//! `cryptox-storage` — Зашифрованный дисковый ACID-движок хранения на базе `redb` (Copy-on-Write B+Tree),
//! составных 48-байтных индексов, слепых крипто-индексов (`Blind Index`) и двухуровневого кэша (L1 RAM + L2 Disk).
//!
//! Архитектурные гарантии (OWASP ASVS v5.0 L3 / NSA CNSA 2.0 / 152-ФЗ):
//! 1. **Storage-at-Rest Envelope Encryption:** каждая запись перед попаданием на физический диск
//!    шифруется уникальным для организации ключом `StorageTenantKey` (`AES-256-GCM`) с привязкой
//!    первичного ключа таблицы в `AAD` (защита от подмены строк в файле БД админом или хакером).
//! 2. **Слепые Индексы (`Cryptographic Blind Indexing`):** точный поиск по `@username` на диске
//!    выполняется по 48-байтному ключу `[16B TenantId || 32B BLAKE3_Keyed(BlindKey, username)]`.
//!    В файле БД на диске нет открытых строк `@username` или имен сотрудников (`0%` утечки при краже SSD).
//! 3. **Составной 48-байтный индекс сообщений (`[16B TenantId || 16B ChannelId || 16B MessageId (UUIDv7)]`):**
//!    все сообщения одного чата физически лежат рядом в B+Tree на диске в хронологическом порядке.
//!    Курсорная выборка `before_cursor` выполняется одним `table.range()` за O(log N) без `OFFSET` и `COUNT(*)`.
//! 4. **L1 Hot Cache + Group Commit Batcher:** горячие данные отдаются из L1 RAM за микросекунды
//!    с контролем потолка памяти (`max_l1_capacity`), а пакетная запись (`Group Commit`) сбрасывает
//!    тысячи зашифрованных записей за одну ACID-транзакцию диска.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use cryptox_proto::{
    ChannelHistoryPageProto, ChannelId, DirectoryEntryProto, EncryptedEnvelope, EncryptedVaultBlob,
    MessageId, PersistedUserAccountProto, ProtoError, ReadReceiptWatermarkProto, TenantId, UserId,
};
use dashmap::DashMap;
use prost::Message;
use rand_core::{OsRng, RngCore};
use redb::{Database, TableDefinition};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Таблица 1: 48-байтный составной индекс истории чатов `[16B TenantId || 16B ChannelId || 16B MessageId] -> SealedRecord`.
const MESSAGES_TIMELINE_TABLE: TableDefinition<[u8; 48], &[u8]> =
    TableDefinition::new("messages_timeline_v1");

/// Таблица 2: 48-байтный слепой индекс `@username` `[16B TenantId || 32B BlindHash(username)] -> SealedRecord`.
const BLIND_USERNAME_TABLE: TableDefinition<[u8; 48], &[u8]> =
    TableDefinition::new("blind_username_idx_v1");

/// Таблица 3: 32-байтный индекс зашифрованных облачных сейфов `[16B TenantId || 16B UserId] -> SealedRecord`.
const VAULT_BLOBS_TABLE: TableDefinition<[u8; 32], &[u8]> =
    TableDefinition::new("vault_blobs_v1");

/// Таблица 4: 48-байтный индекс схлопнутых статусов прочтения `[16B TenantId || 16B ChannelId || 16B UserId] -> SealedRecord`.
const READ_WATERMARKS_TABLE: TableDefinition<[u8; 48], &[u8]> =
    TableDefinition::new("read_watermarks_v1");

/// Таблица 5: 48-байтный слепой индекс постоянных аккаунтов `[16B TenantId || 32B BlindHash(username)] -> SealedRecord`.
const ACCOUNTS_TABLE: TableDefinition<[u8; 48], &[u8]> =
    TableDefinition::new("accounts_v1");

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("ошибка бинарного протокола: {0}")]
    Proto(#[from] ProtoError),

    #[error("ошибка дискового движка redb: {0}")]
    Redb(String),

    #[error("ОБНАРУЖЕНА ПОДМЕНА ИЛИ ПОВРЕЖДЕНИЕ ДАННЫХ НА ДИСКЕ (Disk Tamper / AEAD AAD Failure)")]
    DiskTamperDetected,

    #[error("некорректный поисковый ключ: {0}")]
    InvalidKey(&'static str),
}

/// Статистика работы двухуровневого кэша (L1 RAM vs L2 Encrypted Disk).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageMetricsSnapshot {
    pub l1_cache_hits: u64,
    pub l2_disk_reads: u64,
    pub disk_group_commits: u64,
    pub disk_records_written: u64,
}

/// Зашифрованный дисковый движок хранения `EncryptedStorageEngine`.
pub struct EncryptedStorageEngine {
    db: Database,
    /// 256-битный корневой мастер-ключ хранилища (в проде загружается из KMS / HSM / TPM сервера).
    /// Обернут в `Zeroizing`, поэтому автоматически затирается нулями в RAM при остановке сервера.
    storage_root_key: Zeroizing<[u8; 32]>,
    max_l1_entries: usize,
    /// L1 Hot Cache для карточек сотрудников по слепому ключу `[u8; 48]`.
    l1_directory_cache: DashMap<[u8; 48], Arc<DirectoryEntryProto>>,
    /// L1 Hot Cache для облачных сейфов по `[u8; 32]`.
    l1_vault_cache: DashMap<[u8; 32], Arc<EncryptedVaultBlob>>,
    /// L1 Hot Cache для водоразделов прочтения по `[u8; 48]`.
    l1_watermark_cache: DashMap<[u8; 48], ReadReceiptWatermarkProto>,
    /// Метрики попаданий в L1 и чтений с L2 диска.
    l1_hits: AtomicU64,
    l2_reads: AtomicU64,
    group_commits: AtomicU64,
    records_written: AtomicU64,
}

impl EncryptedStorageEngine {
    /// Открывает или создает зашифрованный файл базы данных `redb` на диске
    /// и инициализирует все 4 B+Tree таблицы.
    pub fn open_or_create(
        path: impl AsRef<Path>,
        storage_root_key: [u8; 32],
        max_l1_entries: usize,
    ) -> Result<Self, StorageError> {
        let db = Database::create(path).map_err(|e| StorageError::Redb(e.to_string()))?;

        // Гарантируем создание таблиц в первом write-транзакционном блоке
        let write_txn = db
            .begin_write()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        {
            let _ = write_txn
                .open_table(MESSAGES_TIMELINE_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;
            let _ = write_txn
                .open_table(BLIND_USERNAME_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;
            let _ = write_txn
                .open_table(VAULT_BLOBS_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;
            let _ = write_txn
                .open_table(READ_WATERMARKS_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;
            let _ = write_txn
                .open_table(ACCOUNTS_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        let cap = max_l1_entries.clamp(64, 1_000_000);
        Ok(Self {
            db,
            storage_root_key: Zeroizing::new(storage_root_key),
            max_l1_entries: cap,
            l1_directory_cache: DashMap::with_capacity(cap.min(16_384)),
            l1_vault_cache: DashMap::with_capacity(cap.min(16_384)),
            l1_watermark_cache: DashMap::with_capacity(cap.min(16_384)),
            l1_hits: AtomicU64::new(0),
            l2_reads: AtomicU64::new(0),
            group_commits: AtomicU64::new(0),
            records_written: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn metrics(&self) -> StorageMetricsSnapshot {
        StorageMetricsSnapshot {
            l1_cache_hits: self.l1_hits.load(Ordering::Relaxed),
            l2_disk_reads: self.l2_reads.load(Ordering::Relaxed),
            disk_group_commits: self.group_commits.load(Ordering::Relaxed),
            disk_records_written: self.records_written.load(Ordering::Relaxed),
        }
    }

    /// Принудительно очищает весь горячий L1 RAM-кэш (для тестирования вытеснения памяти
    /// и проверки того, что L2 диск прозрачно восстанавливает любые данные).
    pub fn evict_all_l1_caches(&self) {
        self.l1_directory_cache.clear();
        self.l1_vault_cache.clear();
        self.l1_watermark_cache.clear();
    }

    /// Выводит изолированный 256-битный ключ шифрования диска `StorageTenantKey` для конкретной компании (`TenantId`).
    fn derive_tenant_disk_key(&self, tenant_id: TenantId) -> Zeroizing<[u8; 32]> {
        let mut kdf = blake3::Hasher::new_keyed(&self.storage_root_key);
        kdf.update(b"cryptox.storage.at-rest.aead-key.v1:");
        kdf.update(tenant_id.as_bytes());
        Zeroizing::new(*kdf.finalize().as_bytes())
    }

    /// Выводит изолированный 256-битный ключ для построения Слепых Индексов (`Blind Index Key`) компании.
    fn derive_tenant_blind_index_key(&self, tenant_id: TenantId) -> Zeroizing<[u8; 32]> {
        let mut kdf = blake3::Hasher::new_keyed(&self.storage_root_key);
        kdf.update(b"cryptox.storage.blind-index-prf.v1:");
        kdf.update(tenant_id.as_bytes());
        Zeroizing::new(*kdf.finalize().as_bytes())
    }

    /// Вычисляет 48-байтный слепой ключ поиска `@username` на диске:
    /// `[16B TenantId || 32B BLAKE3_Keyed(TenantBlindIndexKey, normalized_username)]`.
    pub fn compute_blind_username_key(
        &self,
        tenant_id: TenantId,
        raw_username: &str,
    ) -> Result<[u8; 48], StorageError> {
        let norm = raw_username
            .trim()
            .trim_start_matches('@')
            .to_ascii_lowercase();
        if norm.len() < 3 || norm.len() > 32 {
            return Err(StorageError::InvalidKey("invalid username length"));
        }

        let blind_key = self.derive_tenant_blind_index_key(tenant_id);
        let mut prf = blake3::Hasher::new_keyed(&blind_key);
        prf.update(b"cryptox.blind.username.v1:");
        prf.update(norm.as_bytes());
        let blind_hash = prf.finalize();

        let mut composite = [0u8; 48];
        composite[..16].copy_from_slice(tenant_id.as_bytes());
        composite[16..48].copy_from_slice(blind_hash.as_bytes());
        Ok(composite)
    }

    /// Формирует 48-байтный составной ключ сообщения для B+Tree индекса на диске:
    /// `[16B TenantId || 16B ChannelId || 16B MessageId (UUIDv7)]`.
    #[must_use]
    pub fn compute_composite_timeline_key(
        tenant_id: TenantId,
        channel_id: ChannelId,
        message_id: MessageId,
    ) -> [u8; 48] {
        let mut key = [0u8; 48];
        key[..16].copy_from_slice(tenant_id.as_bytes());
        key[16..32].copy_from_slice(channel_id.as_bytes());
        key[32..48].copy_from_slice(message_id.as_bytes());
        key
    }

    /// Запечатывает произвольную запись перед записью на диск (`AES-256-GCM` + `AAD = table_tag || primary_key`).
    /// Формат на диске: `[12 байт Nonce] || [Ciphertext + 16 байт GCM Tag]`.
    fn seal_disk_record(
        &self,
        tenant_id: TenantId,
        table_tag: &[u8],
        primary_key_bytes: &[u8],
        plaintext_record: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        let disk_key = self.derive_tenant_disk_key(tenant_id);
        let cipher = Aes256Gcm::new((&*disk_key).into());

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = AesNonce::from_slice(&nonce_bytes);

        let mut aad = Vec::with_capacity(table_tag.len() + primary_key_bytes.len());
        aad.extend_from_slice(table_tag);
        aad.extend_from_slice(primary_key_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext_record,
                    aad: &aad,
                },
            )
            .map_err(|_| StorageError::DiskTamperDetected)?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Расшифровывает и проверяет целостность записи с диска (`AES-256-GCM` + `AAD`).
    /// Если в файле БД изменен хотя бы 1 бит или запись переставлена под другой ключ — возвращает `DiskTamperDetected`!
    fn open_disk_record(
        &self,
        tenant_id: TenantId,
        table_tag: &[u8],
        primary_key_bytes: &[u8],
        sealed_record: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        if sealed_record.len() < 12 + 16 {
            return Err(StorageError::DiskTamperDetected);
        }
        let disk_key = self.derive_tenant_disk_key(tenant_id);
        let cipher = Aes256Gcm::new((&*disk_key).into());

        let nonce = AesNonce::from_slice(&sealed_record[..12]);
        let ciphertext = &sealed_record[12..];

        let mut aad = Vec::with_capacity(table_tag.len() + primary_key_bytes.len());
        aad.extend_from_slice(table_tag);
        aad.extend_from_slice(primary_key_bytes);

        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| StorageError::DiskTamperDetected)
    }

    // =========================================================================
    // 1. ХРАНЕНИЕ И СЛЕПОЙ ИНДЕКС СПРАВОЧНИКА СОТРУДНИКОВ (Blind Username Index)
    // =========================================================================

    /// Пакетно сохраняет карточки сотрудников на диск под **Слепым Индексом (`BlindUsernameIndex`)**
    /// и обновляет горячий L1-кэш.
    pub fn put_directory_entries_batch(
        &self,
        entries: &[DirectoryEntryProto],
    ) -> Result<(), StorageError> {
        if entries.is_empty() {
            return Ok(());
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(BLIND_USERNAME_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;

            for entry in entries {
                let tenant_id = TenantId::from_slice(&entry.tenant_id)?;
                let blind_key = self.compute_blind_username_key(tenant_id, &entry.username)?;
                let raw_proto = Zeroizing::new(entry.encode_to_vec());
                let sealed = self.seal_disk_record(
                    tenant_id,
                    b"table:blind_username_idx_v1:",
                    &blind_key,
                    &raw_proto,
                )?;

                table
                    .insert(blind_key, sealed.as_slice())
                    .map_err(|e| StorageError::Redb(e.to_string()))?;

                if self.l1_directory_cache.len() >= self.max_l1_entries {
                    // ВАЖНО: выносим `victim_key` в отдельный `let ...;`, чтобы read-lock шарда `DashMap::iter()`
                    // гарантированно освободился ДО вызова `.remove()` (иначе в Rust 2024 `if let` держит временный guard -> Deadlock!).
                    let victim_key = self.l1_directory_cache.iter().next().map(|r| *r.key());
                    if let Some(k) = victim_key {
                        self.l1_directory_cache.remove(&k);
                    }
                }
                self.l1_directory_cache
                    .insert(blind_key, Arc::new(entry.clone()));
            }
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        self.group_commits.fetch_add(1, Ordering::Relaxed);
        self.records_written
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Ищет карточку сотрудника по `@username`:
    /// 1) Сначала за O(1) проверяет горячий L1 RAM-кэш по 48-байтному слепому ключу;
    /// 2) При промахе (`Cache Miss`) читает с диска `redb`, проверяет тег `AES-256-GCM + AAD`,
    ///    расшифровывает и прогревает L1-кэш!
    pub fn get_directory_entry_by_username(
        &self,
        tenant_id: TenantId,
        username: &str,
    ) -> Result<Option<Arc<DirectoryEntryProto>>, StorageError> {
        let blind_key = self.compute_blind_username_key(tenant_id, username)?;

        // Fast-path: L1 RAM Cache
        if let Some(hit) = self.l1_directory_cache.get(&blind_key) {
            self.l1_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(hit.value().clone()));
        }

        // Slow-path: L2 Encrypted Disk B+Tree
        self.l2_reads.fetch_add(1, Ordering::Relaxed);
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        let table = read_txn
            .open_table(BLIND_USERNAME_TABLE)
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        let Some(guard) = table
            .get(blind_key)
            .map_err(|e| StorageError::Redb(e.to_string()))?
        else {
            return Ok(None);
        };

        let decrypted = Zeroizing::new(self.open_disk_record(
            tenant_id,
            b"table:blind_username_idx_v1:",
            &blind_key,
            guard.value(),
        )?);
        let entry = DirectoryEntryProto::decode(decrypted.as_slice())
            .map_err(|_| StorageError::DiskTamperDetected)?;
        let arc_entry = Arc::new(entry);

        if self.l1_directory_cache.len() < self.max_l1_entries {
            self.l1_directory_cache.insert(blind_key, arc_entry.clone());
        }
        Ok(Some(arc_entry))
    }

    // =========================================================================
    // 2. ХРАНЕНИЕ ОБЛАЧНЫХ СЕЙФОВ КЛЮЧЕЙ (`EncryptedVaultBlob`)
    // =========================================================================

    pub fn put_vault_blob(&self, blob: &EncryptedVaultBlob) -> Result<(), StorageError> {
        let tenant_id = TenantId::from_slice(&blob.tenant_id)?;
        let user_id = UserId::from_slice(&blob.user_id)?;

        let mut key = [0u8; 32];
        key[..16].copy_from_slice(tenant_id.as_bytes());
        key[16..32].copy_from_slice(user_id.as_bytes());

        let raw = blob.encode_to_vec();
        let sealed = self.seal_disk_record(tenant_id, b"table:vault_blobs_v1:", &key, &raw)?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(VAULT_BLOBS_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;
            table
                .insert(key, sealed.as_slice())
                .map_err(|e| StorageError::Redb(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        if self.l1_vault_cache.len() >= self.max_l1_entries {
            let victim_key = self.l1_vault_cache.iter().next().map(|r| *r.key());
            if let Some(k) = victim_key {
                self.l1_vault_cache.remove(&k);
            }
        }
        self.l1_vault_cache.insert(key, Arc::new(blob.clone()));
        self.group_commits.fetch_add(1, Ordering::Relaxed);
        self.records_written.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn get_vault_blob(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<Arc<EncryptedVaultBlob>>, StorageError> {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(tenant_id.as_bytes());
        key[16..32].copy_from_slice(user_id.as_bytes());

        if let Some(hit) = self.l1_vault_cache.get(&key) {
            self.l1_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(hit.value().clone()));
        }

        self.l2_reads.fetch_add(1, Ordering::Relaxed);
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        let table = read_txn
            .open_table(VAULT_BLOBS_TABLE)
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        let Some(guard) = table
            .get(key)
            .map_err(|e| StorageError::Redb(e.to_string()))?
        else {
            return Ok(None);
        };

        let decrypted =
            self.open_disk_record(tenant_id, b"table:vault_blobs_v1:", &key, guard.value())?;
        let blob = EncryptedVaultBlob::decode(decrypted.as_slice())
            .map_err(|_| StorageError::DiskTamperDetected)?;
        let arc_blob = Arc::new(blob);
        self.l1_vault_cache.insert(key, arc_blob.clone());
        Ok(Some(arc_blob))
    }

    // =========================================================================
    // 3. 48-БАЙТНЫЙ СОСТАВНОЙ ИНДЕКС ИСТОРИИ ЧАТОВ + GROUP COMMIT НА ДИСК
    // =========================================================================

    /// Пакетно записывает пачку сообщений в 48-байтный составной B+Tree индекс на диске
    /// за ОДНУ ACID-транзакцию (`Group Commit Batching`).
    pub fn commit_messages_batch(
        &self,
        envelopes: &[EncryptedEnvelope],
    ) -> Result<(), StorageError> {
        if envelopes.is_empty() {
            return Ok(());
        }

        // Предварительно шифруем записи в памяти до открытия дисковой транзакции
        let mut prepared: Vec<([u8; 48], Vec<u8>)> = Vec::with_capacity(envelopes.len());
        for env in envelopes {
            let tenant_id = TenantId::from_slice(&env.tenant_id)?;
            let channel_id = ChannelId::from_slice(&env.channel_id)?;
            let message_id = MessageId::from_slice(&env.message_id)?;

            let key_48 = Self::compute_composite_timeline_key(tenant_id, channel_id, message_id);
            let raw_bytes = env.to_wire_bytes();
            let sealed = self.seal_disk_record(
                tenant_id,
                b"table:messages_timeline_v1:",
                &key_48,
                &raw_bytes,
            )?;
            prepared.push((key_48, sealed));
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(MESSAGES_TIMELINE_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;
            for (k, v) in &prepared {
                table
                    .insert(*k, v.as_slice())
                    .map_err(|e| StorageError::Redb(e.to_string()))?;
            }
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        self.group_commits.fetch_add(1, Ordering::Relaxed);
        self.records_written
            .fetch_add(prepared.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Курсорная выборка страницы истории чата напрямую из 48-байтного дискового B+Tree индекса
    /// (`[16B TenantId || 16B ChannelId || 16B MessageId (UUIDv7)]`) за O(log N + limit) **без `OFFSET` и `COUNT(*)`**.
    pub fn fetch_channel_history_from_disk(
        &self,
        tenant_id: TenantId,
        channel_id: ChannelId,
        before_cursor: Option<MessageId>,
        limit: usize,
    ) -> Result<ChannelHistoryPageProto, StorageError> {
        let capped_limit = limit.clamp(1, 100);
        self.l2_reads.fetch_add(1, Ordering::Relaxed);

        let mut lower_bound = [0u8; 48];
        lower_bound[..16].copy_from_slice(tenant_id.as_bytes());
        lower_bound[16..32].copy_from_slice(channel_id.as_bytes());
        // lower_bound[32..48] = 0x00..00 (начало истории этого канала)

        let mut upper_bound = [0u8; 48];
        upper_bound[..16].copy_from_slice(tenant_id.as_bytes());
        upper_bound[16..32].copy_from_slice(channel_id.as_bytes());

        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        let table = read_txn
            .open_table(MESSAGES_TIMELINE_TABLE)
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        let mut envelopes_desc = Vec::with_capacity(capped_limit);
        let mut has_more = false;

        match before_cursor {
            Some(cursor) => {
                upper_bound[32..48].copy_from_slice(cursor.as_bytes());
                // Строго ДО курсора: `lower_bound .. upper_bound`
                let range_iter = table
                    .range(lower_bound..upper_bound)
                    .map_err(|e| StorageError::Redb(e.to_string()))?;

                for (idx, item) in range_iter.rev().enumerate() {
                    if idx == capped_limit {
                        has_more = true;
                        break;
                    }
                    let (k_guard, v_guard) = item.map_err(|e| StorageError::Redb(e.to_string()))?;
                    let k_val = k_guard.value();
                    let raw = self.open_disk_record(
                        tenant_id,
                        b"table:messages_timeline_v1:",
                        &k_val,
                        v_guard.value(),
                    )?;
                    let env = EncryptedEnvelope::from_wire_bytes(&raw)?;
                    envelopes_desc.push(env);
                }
            }
            None => {
                upper_bound[32..48].fill(0xFF);
                // Включая самое последнее сообщение: `lower_bound ..= upper_bound`
                let range_iter = table
                    .range(lower_bound..=upper_bound)
                    .map_err(|e| StorageError::Redb(e.to_string()))?;

                for (idx, item) in range_iter.rev().enumerate() {
                    if idx == capped_limit {
                        has_more = true;
                        break;
                    }
                    let (k_guard, v_guard) = item.map_err(|e| StorageError::Redb(e.to_string()))?;
                    let k_val = k_guard.value();
                    let raw = self.open_disk_record(
                        tenant_id,
                        b"table:messages_timeline_v1:",
                        &k_val,
                        v_guard.value(),
                    )?;
                    let env = EncryptedEnvelope::from_wire_bytes(&raw)?;
                    envelopes_desc.push(env);
                }
            }
        }

        envelopes_desc.reverse();
        let next_before_cursor = if has_more {
            envelopes_desc
                .first()
                .map(|first| first.message_id.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        Ok(ChannelHistoryPageProto {
            channel_id: channel_id.to_vec(),
            envelopes: envelopes_desc,
            next_before_cursor,
            has_more,
        })
    }

    // =========================================================================
    // 4. WRITE-BEHIND FLUSH СХЛОПНУТЫХ СТАТУСОВ ПРОЧТЕНИЯ (Read Watermarks)
    // =========================================================================

    pub fn flush_watermarks_batch(
        &self,
        watermarks: &[ReadReceiptWatermarkProto],
    ) -> Result<(), StorageError> {
        if watermarks.is_empty() {
            return Ok(());
        }

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(READ_WATERMARKS_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;

            for wm in watermarks {
                let tenant_id = TenantId::from_slice(&wm.tenant_id)?;
                let channel_id = ChannelId::from_slice(&wm.channel_id)?;
                let user_id = UserId::from_slice(&wm.user_id)?;

                let mut key = [0u8; 48];
                key[..16].copy_from_slice(tenant_id.as_bytes());
                key[16..32].copy_from_slice(channel_id.as_bytes());
                key[32..48].copy_from_slice(user_id.as_bytes());

                let raw = wm.encode_to_vec();
                let sealed =
                    self.seal_disk_record(tenant_id, b"table:read_watermarks_v1:", &key, &raw)?;
                table
                    .insert(key, sealed.as_slice())
                    .map_err(|e| StorageError::Redb(e.to_string()))?;

                if self.l1_watermark_cache.len() >= self.max_l1_entries {
                    let victim_key = self.l1_watermark_cache.iter().next().map(|r| *r.key());
                    if let Some(k) = victim_key {
                        self.l1_watermark_cache.remove(&k);
                    }
                }
                self.l1_watermark_cache.insert(key, wm.clone());
            }
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        self.group_commits.fetch_add(1, Ordering::Relaxed);
        self.records_written
            .fetch_add(watermarks.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub fn get_read_watermark(
        &self,
        tenant_id: TenantId,
        channel_id: ChannelId,
        user_id: UserId,
    ) -> Result<Option<ReadReceiptWatermarkProto>, StorageError> {
        let mut key = [0u8; 48];
        key[..16].copy_from_slice(tenant_id.as_bytes());
        key[16..32].copy_from_slice(channel_id.as_bytes());
        key[32..48].copy_from_slice(user_id.as_bytes());

        if let Some(hit) = self.l1_watermark_cache.get(&key) {
            self.l1_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(hit.value().clone()));
        }

        self.l2_reads.fetch_add(1, Ordering::Relaxed);
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        let table = read_txn
            .open_table(READ_WATERMARKS_TABLE)
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        let Some(guard) = table
            .get(key)
            .map_err(|e| StorageError::Redb(e.to_string()))?
        else {
            return Ok(None);
        };

        let raw =
            self.open_disk_record(tenant_id, b"table:read_watermarks_v1:", &key, guard.value())?;
        let wm = ReadReceiptWatermarkProto::decode(raw.as_slice())
            .map_err(|_| StorageError::DiskTamperDetected)?;
        self.l1_watermark_cache.insert(key, wm.clone());
        Ok(Some(wm))
    }

    // =========================================================================
    // 5. ПОСТОЯННОЕ ХРАНЕНИЕ АККАУНТОВ И КЛЮЧЕЙ (`accounts_v1`, AES-256-GCM + Blind Index)
    // =========================================================================

    pub fn put_user_account(
        &self,
        account: &PersistedUserAccountProto,
    ) -> Result<(), StorageError> {
        let tenant_id = TenantId::from_slice(&account.tenant_id)?;
        let blind_key = self.compute_blind_username_key(tenant_id, &account.username)?;
        let raw_proto = Zeroizing::new(account.encode_to_vec());
        let sealed = self.seal_disk_record(
            tenant_id,
            b"table:accounts_v1:",
            &blind_key,
            &raw_proto,
        )?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(ACCOUNTS_TABLE)
                .map_err(|e| StorageError::Redb(e.to_string()))?;
            table
                .insert(blind_key, sealed.as_slice())
                .map_err(|e| StorageError::Redb(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        self.group_commits.fetch_add(1, Ordering::Relaxed);
        self.records_written.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn load_all_user_accounts(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<PersistedUserAccountProto>, StorageError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StorageError::Redb(e.to_string()))?;
        let table = read_txn
            .open_table(ACCOUNTS_TABLE)
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        let mut lower_bound = [0u8; 48];
        lower_bound[..16].copy_from_slice(tenant_id.as_bytes());
        let mut upper_bound = [0xFFu8; 48];
        upper_bound[..16].copy_from_slice(tenant_id.as_bytes());

        let mut accounts = Vec::new();
        let range_iter = table
            .range(lower_bound..=upper_bound)
            .map_err(|e| StorageError::Redb(e.to_string()))?;

        for item in range_iter {
            let (k_guard, v_guard) = item.map_err(|e| StorageError::Redb(e.to_string()))?;
            let k_val = k_guard.value();
            let raw = self.open_disk_record(
                tenant_id,
                b"table:accounts_v1:",
                &k_val,
                v_guard.value(),
            )?;
            let acc = PersistedUserAccountProto::decode(raw.as_slice())
                .map_err(|_| StorageError::DiskTamperDetected)?;
            accounts.push(acc);
        }
        self.l2_reads.fetch_add(accounts.len() as u64, Ordering::Relaxed);
        Ok(accounts)
    }
}
