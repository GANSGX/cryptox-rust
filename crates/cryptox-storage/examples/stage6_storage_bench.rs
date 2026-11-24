//! Нагрузочный стенд Этапа 6 (`stage6_storage_bench.rs`).
//!
//! Замеряет реальную производительность зашифрованного дискового движка `cryptox-storage` (`redb` + `AES-256-GCM` + `AAD`):
//! 1. Пакетная запись с шифрованием на физический SSD (`Group Commit`: 50 000 сообщений пачками по 2 500).
//! 2. Курсорное чтение истории из 48-байтного составного B+Tree индекса на диске (`fetch_channel_history_from_disk`).
//! 3. Скорость поиска по Слепому Индексу `@username` (L1 RAM Cache Hit vs L2 Encrypted Disk Read).

use cryptox_core::{ChatSession, UserIdentity, XChaCha20Poly1305Provider};
use cryptox_proto::{
    CipherSuiteId, DeviceId, DirectoryEntryProto, EncryptionPolicy, MessageId, TenantId, UserId,
};
use cryptox_storage::EncryptedStorageEngine;
use std::time::Instant;
use tempfile::tempdir;

#[allow(clippy::expect_used)]
fn main() {
    println!("==================================================================");
    println!("🚀 CRYPTOX-RUST: НАГРУЗОЧНЫЙ СТЕНД ЭТАПА 6 (ENCRYPTED DISK + L1/L2 CACHE)");
    println!("==================================================================");

    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("bench_storage.redb");
    let storage_root_key = [0x55_u8; 32];

    let engine = EncryptedStorageEngine::open_or_create(&db_path, storage_root_key, 100_000)
        .expect("open storage");

    let tenant = TenantId::new_v7();
    let alice = UserIdentity::generate(
        tenant,
        UserId::new_v7(),
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let bob = UserIdentity::generate(
        tenant,
        UserId::new_v7(),
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let bob_bundle = bob.export_public_bundle().expect("b bundle");

    let mut chat = ChatSession::establish_direct(
        &alice,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("chat");
    let channel_id = chat.channel_id();

    let template_env = chat
        .encrypt_message(
            &alice,
            &XChaCha20Poly1305Provider,
            b"Persistent double-encrypted enterprise message stored in 48-byte B+Tree index",
        )
        .expect("encrypt");

    // ------------------------------------------------------------------
    // ТЕСТ 1: Group Commit запись 50 000 зашифрованных сообщений на физический диск
    // (каждая запись дополнительно шифруется AES-256-GCM с 48-байтным ключом в AAD!)
    // ------------------------------------------------------------------
    let total_msgs: usize = 50_000;
    let batch_size: usize = 2_500;
    let mut all_ids: Vec<MessageId> = Vec::with_capacity(total_msgs);
    for _ in 0..total_msgs {
        all_ids.push(MessageId::new_v7());
    }

    let start_write = Instant::now();
    for chunk_ids in all_ids.chunks(batch_size) {
        let mut batch = Vec::with_capacity(chunk_ids.len());
        for mid in chunk_ids {
            let mut env = template_env.clone();
            env.message_id = mid.to_vec();
            batch.push(env);
        }
        engine
            .commit_messages_batch(&batch)
            .expect("commit disk batch");
    }
    let elapsed_write = start_write.elapsed();
    let write_rps = (total_msgs as f64) / elapsed_write.as_secs_f64();
    let file_size_mb = (std::fs::metadata(&db_path).expect("meta").len() as f64) / (1024.0 * 1024.0);

    println!("\n[1] Дисковый ACID Group Commit (50 000 сообщений + AES-256-GCM At-Rest + redb B+Tree fsync):");
    println!("    • Записано на SSD:         {total_msgs} сообщений (пачками по {batch_size})");
    println!("    • Размер файла БД на SSD:  {:.2} МБ", file_size_mb);
    println!("    • Скорость записи на диск: {:.0} зашифрованных записей/сек", write_rps);

    // ------------------------------------------------------------------
    // ТЕСТ 2: Курсорное чтение и дешифрование истории напрямую с диска (48-байтный B+Tree Range)
    // ------------------------------------------------------------------
    let page_reads: usize = 10_000;
    let mid_cursor = all_ids[total_msgs / 2];
    let start_disk_read = Instant::now();
    for _ in 0..page_reads {
        let page = engine
            .fetch_channel_history_from_disk(tenant, channel_id, Some(mid_cursor), 20)
            .expect("disk range read");
        std::hint::black_box(page);
    }
    let elapsed_disk_read = start_disk_read.elapsed();
    let pages_sec = (page_reads as f64) / elapsed_disk_read.as_secs_f64();
    let msgs_read_sec = ((page_reads * 20) as f64) / elapsed_disk_read.as_secs_f64();
    let page_us = (elapsed_disk_read.as_micros() as f64) / (page_reads as f64);

    println!("\n[2] Курсорное чтение истории с диска по 48-байтному ключу [Tenant||Channel||UUIDv7] (20 сообщ/стр):");
    println!("    • Прочитано с диска:       {page_reads} страниц ({} расшифрованных с диска конвертов)", page_reads * 20);
    println!("    • Скорость чтения с диска: {:.0} страниц/сек ({:.0} конвертов/сек!)", pages_sec, msgs_read_sec);
    println!("    • Задержка на страницу:    {:.2} мкс (0 OFFSET, O(log N) B+Tree seek)", page_us);

    // ------------------------------------------------------------------
    // ТЕСТ 3: Поиск по Слепому Индексу `@username` (L1 Cache vs L2 Disk после Eviction)
    // ------------------------------------------------------------------
    let sample_entry = DirectoryEntryProto {
        tenant_id: tenant.to_vec(),
        user_id: bob.user_id().to_vec(),
        username: "bob_blind_indexed".to_string(),
        display_name: "Bob Blind Indexed".to_string(),
        public_key_bundle: Some(bob_bundle),
        transparency_log_hash: vec![0x22; 32],
        transparency_seq: 1,
    };
    engine
        .put_directory_entries_batch(&[sample_entry])
        .expect("put blind entry");

    let l1_iters: usize = 500_000;
    let start_l1 = Instant::now();
    for _ in 0..l1_iters {
        let hit = engine
            .get_directory_entry_by_username(tenant, "@bob_blind_indexed")
            .expect("l1 hit");
        std::hint::black_box(hit);
    }
    let elapsed_l1 = start_l1.elapsed();
    let l1_rps = (l1_iters as f64) / elapsed_l1.as_secs_f64();

    // Теперь принудительно вытесняем L1 кэш и замеряем холодное чтение слепого индекса с L2 диска
    let l2_iters: usize = 20_000;
    let start_l2 = Instant::now();
    for _ in 0..l2_iters {
        engine.evict_all_l1_caches();
        let disk_hit = engine
            .get_directory_entry_by_username(tenant, "@bob_blind_indexed")
            .expect("l2 disk hit");
        std::hint::black_box(disk_hit);
    }
    let elapsed_l2 = start_l2.elapsed();
    let l2_rps = (l2_iters as f64) / elapsed_l2.as_secs_f64();

    println!("\n[3] Поиск по Слепому Крипто-Индексу `BLAKE3(BlindKey, @username)`:");
    println!("    • Скорость из L1 RAM-кэша: {:.0} поисков/сек", l1_rps);
    println!("    • Скорость холодного чтения с L2 диска + AES-256-GCM: {:.0} поисков/сек", l2_rps);
    println!("==================================================================");
}
