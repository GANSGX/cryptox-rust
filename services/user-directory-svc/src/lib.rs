//! `user-directory-svc` — Изолированный микросервис поиска сотрудников по `@username`
//! и криптографического реестра публичных ключей (Key Transparency Log, IETF RFC 9750).
//!
//! Архитектурные гарантии на масштабе 100 000+ сотрудников:
//! 1. **Точный поиск за O(1)** через шардированный `DashMap` и **префиксный поиск за O(log N + K)**
//!    через изолированное по `TenantId` префиксное B-дерево (`BTreeMap::range`).
//! 2. **Строгая мульти-арендная изоляция (`Tenant Isolation`):** область поиска жестко берется
//!    из криптографически проверенного `SignedSessionToken` вызывающего сотрудника. Сотрудник Компании А
//!    физически не может найти или перечислить сотрудников Компании Б.
//! 3. **Защита от MITM и подмены ключей (Key Transparency Log):**
//!    - Каждый публикуемый `PublicKeyBundle` проверяется на корректность самоподписи `Ed25519`.
//!    - При ротации ключа сотрудника версия `key_version` обязана строго возрастать (`old + 1`),
//!      блокируя атаки отката ключей (`Key Downgrade Attack`).
//!    - Каждая запись связывается в криптографическую цепочку `BLAKE3` (`transparency_log_hash`).
//! 4. **Bulkhead-автономность:** проверка токенов выполняется локально через `AutonomousTokenVerifier`
//!    (работает со 100% скоростью даже при полном падении `auth-vault-svc`).

use auth_vault_svc::{AuthVaultError, AutonomousTokenVerifier};
use cryptox_core::{CryptoError, UserIdentity};
use cryptox_proto::{
    DirectoryEntryProto, ProtoError, PublicKeyBundle, SearchUsersResponse, SignedSessionToken,
    TenantId, UserId,
};
use dashmap::DashMap;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Максимальное число результатов за один поисковый запрос (защита от скрейпинга и OOM).
pub const MAX_DIRECTORY_SEARCH_LIMIT: usize = 50;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DirectoryError {
    #[error("ошибка протокола: {0}")]
    Proto(#[from] ProtoError),

    #[error("криптографическая ошибка пакета ключей: {0}")]
    Crypto(#[from] CryptoError),

    #[error("ошибка авторизации токена: {0}")]
    Auth(#[from] AuthVaultError),

    #[error("сервис user-directory-svc временно недоступен (Simulated Outage)")]
    ServiceUnavailable,

    #[error("некорректный формат @username или поискового префикса")]
    InvalidUsername,

    #[error("конфликт @username: данный юзернейм уже занят другим сотрудником организации")]
    UsernameConflict,

    #[error("сотрудник не найден в каталоге организации")]
    UserNotFound,

    #[error("нарушение изоляции организации или владельца ключа (Unauthorized)")]
    UnauthorizedKeyPublish,

    #[error("атака отката версии ключа (Key Downgrade Attack): текущая версия {current}, попытка {attempted}")]
    KeyVersionRollback { current: u64, attempted: u64 },

    #[error("попытка подмены корневого ключа подписи Ed25519 без авторизованной ротации (MITM Blocked)")]
    IdentitySigningKeySubstitution,
}

/// Внутреннее состояние префиксного индекса и цепочки Key Transparency для одной компании (`TenantId`).
#[derive(Default)]
struct TenantDirectoryPartition {
    /// Отсортированный индекс `username_lowercase -> UserId` для мгновенного префиксного поиска `BTreeMap::range`.
    prefix_tree: BTreeMap<String, UserId>,
    /// Текущий номер записи в журнале прозрачности ключей компании.
    transparency_seq: u64,
    /// Текущая вершина хеш-цепочки `BLAKE3` (`Key Transparency Head`).
    transparency_head: [u8; 32],
}

pub struct UserDirectoryService {
    verifier: AutonomousTokenVerifier,
    /// Быстрый O(1) доступ к карточке сотрудника по `(TenantId, UserId)`.
    entries_by_id: DashMap<(TenantId, UserId), Arc<DirectoryEntryProto>>,
    /// Быстрый O(1) доступ к карточке сотрудника по точному `(TenantId, username_lowercase)`.
    entries_by_username: DashMap<(TenantId, String), Arc<DirectoryEntryProto>>,
    /// Изолированные партиции компаний для префиксного поиска и цепочки Key Transparency.
    tenant_partitions: DashMap<TenantId, Arc<RwLock<TenantDirectoryPartition>>>,
    /// Флаг симуляции падения `user-directory-svc` для Chaos/Bulkhead тестов.
    simulated_outage: AtomicBool,
}

impl UserDirectoryService {
    #[must_use]
    pub fn new(verifier: AutonomousTokenVerifier) -> Self {
        Self {
            verifier,
            entries_by_id: DashMap::with_capacity(65_536),
            entries_by_username: DashMap::with_capacity(65_536),
            tenant_partitions: DashMap::new(),
            simulated_outage: AtomicBool::new(false),
        }
    }

    /// Включает или выключает симуляцию аварии сервиса (`Chaos / Bulkhead Test`).
    pub fn set_simulated_outage(&self, is_down: bool) {
        self.simulated_outage.store(is_down, Ordering::SeqCst);
    }

    #[inline]
    fn check_available(&self) -> Result<(), DirectoryError> {
        if self.simulated_outage.load(Ordering::Relaxed) {
            return Err(DirectoryError::ServiceUnavailable);
        }
        Ok(())
    }

    fn normalize_username(raw: &str) -> Result<String, DirectoryError> {
        let trimmed = raw.trim().trim_start_matches('@').to_ascii_lowercase();
        if trimmed.len() < 3 || trimmed.len() > 32 {
            return Err(DirectoryError::InvalidUsername);
        }
        if !trimmed
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(DirectoryError::InvalidUsername);
        }
        Ok(trimmed)
    }

    fn normalize_prefix(raw: &str) -> Result<String, DirectoryError> {
        let trimmed = raw.trim().trim_start_matches('@').to_ascii_lowercase();
        if trimmed.is_empty() || trimmed.len() > 32 {
            return Err(DirectoryError::InvalidUsername);
        }
        if !trimmed
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(DirectoryError::InvalidUsername);
        }
        Ok(trimmed)
    }

    /// Вычисляет очередное звено криптографической цепочки Key Transparency (`BLAKE3`).
    fn compute_transparency_leaf_hash(
        prev_head: &[u8; 32],
        seq: u64,
        tenant_id: TenantId,
        user_id: UserId,
        username: &str,
        bundle: &PublicKeyBundle,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("cryptox.key-transparency-chain.v1");
        hasher.update(prev_head);
        hasher.update(&seq.to_le_bytes());
        hasher.update(tenant_id.as_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(username.as_bytes());
        hasher.update(&bundle.key_version.to_le_bytes());
        hasher.update(&bundle.ed25519_verifying_key);
        hasher.update(&bundle.x25519_public_key);
        hasher.update(&bundle.self_signature);
        *hasher.finalize().as_bytes()
    }

    /// Публикует или обновляет (ротирует) карточку и публичный пакет ключей `PublicKeyBundle` сотрудника.
    ///
    /// Проверяет:
    /// 1. Подлинность сессионного токена (или прямую системную синхронизацию при регистрации);
    /// 2. Самоподпись `Ed25519` внутри `PublicKeyBundle` (`UserIdentity::verify_peer_bundle`);
    /// 3. Защиту от отката версии ключа (`KeyVersionRollback`) и подмены корневого ключа (`MITM`).
    pub fn publish_or_rotate_entry(
        &self,
        token: &SignedSessionToken,
        username: &str,
        display_name: &str,
        bundle: PublicKeyBundle,
        now_ms: u64,
    ) -> Result<Arc<DirectoryEntryProto>, DirectoryError> {
        self.check_available()?;

        let claims = self.verifier.verify_token(token, now_ms)?;
        self.upsert_verified_entry(
            claims.tenant_id,
            claims.user_id,
            username,
            display_name,
            bundle,
        )
    }

    /// Внутренняя верифицированная публикация/ротация записи (используется как при RPC с токеном,
    /// так и при пакетной загрузке оргструктуры компании).
    pub fn upsert_verified_entry(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        username: &str,
        display_name: &str,
        bundle: PublicKeyBundle,
    ) -> Result<Arc<DirectoryEntryProto>, DirectoryError> {
        self.check_available()?;

        let norm_username = Self::normalize_username(username)?;

        // 1. Криптографическая проверка самоподписи `PublicKeyBundle` (защита от MITM)
        let (bundle_user_id, _, _) = UserIdentity::verify_peer_bundle(tenant_id, &bundle)?;
        if bundle_user_id != user_id {
            return Err(DirectoryError::UnauthorizedKeyPublish);
        }

        // 2. Проверка конфликта @username и защита от отката версии ключа (Key Version Rollback)
        if let Some(existing_by_uname) = self
            .entries_by_username
            .get(&(tenant_id, norm_username.clone()))
            && existing_by_uname.user_id != user_id.to_vec()
        {
            return Err(DirectoryError::UsernameConflict);
        }

        if let Some(existing_by_id) = self.entries_by_id.get(&(tenant_id, user_id)) {
            if let Some(old_bundle) = &existing_by_id.public_key_bundle {
                // Корневой ключ цифровой подписи Ed25519 сравнивается за константное время (`subtle::ConstantTimeEq`)
                let keys_match: bool = old_bundle
                    .ed25519_verifying_key
                    .as_slice()
                    .ct_eq(bundle.ed25519_verifying_key.as_slice())
                    .into();
                if !keys_match {
                    return Err(DirectoryError::IdentitySigningKeySubstitution);
                }
                // Версия ключа при ротации обязана строго увеличиться на 1
                if bundle.key_version != old_bundle.key_version.saturating_add(1) {
                    return Err(DirectoryError::KeyVersionRollback {
                        current: old_bundle.key_version,
                        attempted: bundle.key_version,
                    });
                }
            }
        } else if bundle.key_version != 1 {
            return Err(DirectoryError::KeyVersionRollback {
                current: 0,
                attempted: bundle.key_version,
            });
        }

        // 3. Обновляем префиксное дерево и цепочку Key Transparency компании
        let partition_lock = self
            .tenant_partitions
            .entry(tenant_id)
            .or_insert_with(|| Arc::new(RwLock::new(TenantDirectoryPartition::default())))
            .clone();

        let (seq, new_head) = {
            let mut part = partition_lock
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            part.transparency_seq = part.transparency_seq.saturating_add(1);
            let seq = part.transparency_seq;
            let new_head = Self::compute_transparency_leaf_hash(
                &part.transparency_head,
                seq,
                tenant_id,
                user_id,
                &norm_username,
                &bundle,
            );
            part.transparency_head = new_head;
            part.prefix_tree.insert(norm_username.clone(), user_id);
            (seq, new_head)
        };

        let entry = Arc::new(DirectoryEntryProto {
            tenant_id: tenant_id.to_vec(),
            user_id: user_id.to_vec(),
            username: norm_username.clone(),
            display_name: display_name.trim().to_string(),
            public_key_bundle: Some(bundle),
            transparency_log_hash: new_head.to_vec(),
            transparency_seq: seq,
        });

        self.entries_by_id.insert((tenant_id, user_id), entry.clone());
        self.entries_by_username
            .insert((tenant_id, norm_username), entry.clone());

        Ok(entry)
    }

    /// Точный поиск сотрудника по `@username` за O(1) (для мгновенного входа в личный чат).
    /// Строго изолирован внутри `claims.tenant_id` вызывающего сотрудника.
    pub fn get_by_username(
        &self,
        token: &SignedSessionToken,
        username: &str,
        now_ms: u64,
    ) -> Result<Arc<DirectoryEntryProto>, DirectoryError> {
        self.check_available()?;

        let claims = self.verifier.verify_token(token, now_ms)?;
        let norm_username = Self::normalize_username(username)?;

        let entry = self
            .entries_by_username
            .get(&(claims.tenant_id, norm_username))
            .ok_or(DirectoryError::UserNotFound)?;

        Ok(entry.value().clone())
    }

    /// Точный поиск карточки и ключей сотрудника по `UserId` за O(1).
    pub fn get_by_user_id(
        &self,
        token: &SignedSessionToken,
        target_user_id: UserId,
        now_ms: u64,
    ) -> Result<Arc<DirectoryEntryProto>, DirectoryError> {
        self.check_available()?;

        let claims = self.verifier.verify_token(token, now_ms)?;
        let entry = self
            .entries_by_id
            .get(&(claims.tenant_id, target_user_id))
            .ok_or(DirectoryError::UserNotFound)?;

        Ok(entry.value().clone())
    }

    /// Префиксный поиск сотрудников по первым буквам `@username` (например, `@al` -> `alice`, `alex`...)
    /// по базе в 100 000+ сотрудников компании за O(log N + K).
    pub fn search_by_prefix(
        &self,
        token: &SignedSessionToken,
        prefix: &str,
        limit: usize,
        now_ms: u64,
    ) -> Result<SearchUsersResponse, DirectoryError> {
        self.check_available()?;

        let claims = self.verifier.verify_token(token, now_ms)?;
        let norm_prefix = Self::normalize_prefix(prefix)?;
        let capped_limit = limit.clamp(1, MAX_DIRECTORY_SEARCH_LIMIT);

        let Some(partition_ref) = self.tenant_partitions.get(&claims.tenant_id) else {
            return Ok(SearchUsersResponse {
                entries: Vec::new(),
                tenant_transparency_head: vec![0u8; 32],
            });
        };

        let (matched_ids, head) = {
            let part = partition_ref
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ids: Vec<UserId> = part
                .prefix_tree
                .range(norm_prefix.clone()..)
                .take_while(|(uname, _)| uname.starts_with(&norm_prefix))
                .take(capped_limit)
                .map(|(_, uid)| *uid)
                .collect();
            (ids, part.transparency_head)
        };

        let mut results = Vec::with_capacity(matched_ids.len());
        for uid in matched_ids {
            if let Some(entry) = self.entries_by_id.get(&(claims.tenant_id, uid)) {
                results.push((**entry.value()).clone());
            }
        }

        Ok(SearchUsersResponse {
            entries: results,
            tenant_transparency_head: head.to_vec(),
        })
    }

    /// Клиентская проверка полученной из `user-directory-svc` карточки `DirectoryEntryProto`:
    /// гарантирует, что сервер каталога не подменил `PublicKeyBundle` сотрудника на MITM-ключ.
    pub fn verify_client_received_entry(
        expected_tenant: TenantId,
        entry: &DirectoryEntryProto,
    ) -> Result<PublicKeyBundle, DirectoryError> {
        let entry_tenant = TenantId::from_slice(&entry.tenant_id)?;
        if entry_tenant != expected_tenant {
            return Err(DirectoryError::UnauthorizedKeyPublish);
        }
        let entry_user = UserId::from_slice(&entry.user_id)?;
        let bundle = entry
            .public_key_bundle
            .as_ref()
            .ok_or(DirectoryError::UserNotFound)?
            .clone();

        let (verified_uid, _, _) = UserIdentity::verify_peer_bundle(expected_tenant, &bundle)?;
        if verified_uid != entry_user || entry.transparency_log_hash.len() != 32 {
            return Err(DirectoryError::UnauthorizedKeyPublish);
        }
        Ok(bundle)
    }
}
