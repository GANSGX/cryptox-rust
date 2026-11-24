//! Боевые тесты Этапа 6 (`crates/cryptox-storage`):
//! 1. **Raw Disk Forensics Test (Криминалистический дамп SSD):** проверяем, что при чтении сырых байтов
//!    файла `.redb` с физического диска в нем НЕТ ни открытых `@username`, ни `display_name`, ни текста сообщений.
//! 2. **Cold Server Reboot & L1/L2 Cache Tiering:** записываем данные, полностью уничтожаем движок в RAM (`drop`),
//!    открываем файл заново и проверяем 48-байтную курсорную пагинацию `UUIDv7` с диска и прогрев L1-кэша.
//! 3. **Disk Theft / Tamper Detection:** попытка открыть украденный файл БД без корневого ключа KMS/HSM
//!    гарантированно возвращает `Err(StorageError::DiskTamperDetected)`.

use cryptox_core::{
    Argon2Profile, ChatSession, CloudKeyVault, UserIdentity, XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    CipherSuiteId, DeviceId, DirectoryEntryProto, EncryptionPolicy, MessageId,
    ReadReceiptWatermarkProto, TenantId, UserId,
};
use cryptox_storage::{EncryptedStorageEngine, StorageError};
use tempfile::tempdir;

#[test]
fn test_raw_disk_forensics_zero_plaintext_usernames_or_messages_on_ssd() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("forensics_test.redb");
    let storage_root_key = [0x77_u8; 32];

    let tenant = TenantId::new_v7();
    let alice_uid = UserId::new_v7();
    let bob_uid = UserId::new_v7();

    let alice = UserIdentity::generate(
        tenant,
        alice_uid,
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let bob = UserIdentity::generate(
        tenant,
        bob_uid,
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );

    let alice_bundle = alice.export_public_bundle().expect("a bundle");
    let bob_bundle = bob.export_public_bundle().expect("b bundle");

    let secret_username = "alice_top_secret_president";
    let secret_display_name = "Alice SuperConfidential CEO";
    let secret_chat_text = "LAUNCH_CODE_NUCLEAR_DEAL_2026_DO_NOT_LEAK";

    {
        let engine =
            EncryptedStorageEngine::open_or_create(&db_path, storage_root_key, 1024).expect("open");

        let entry = DirectoryEntryProto {
            tenant_id: tenant.to_vec(),
            user_id: alice_uid.to_vec(),
            username: secret_username.to_string(),
            display_name: secret_display_name.to_string(),
            public_key_bundle: Some(alice_bundle),
            transparency_log_hash: vec![0xAA; 32],
            transparency_seq: 1,
        };
        engine
            .put_directory_entries_batch(&[entry])
            .expect("put directory");

        let mut chat = ChatSession::establish_direct(
            &alice,
            &bob_bundle,
            EncryptionPolicy::StrictZeroKnowledge,
            None,
        )
        .expect("chat");
        let env = chat
            .encrypt_message(
                &alice,
                &XChaCha20Poly1305Provider,
                secret_chat_text.as_bytes(),
            )
            .expect("encrypt");

        engine
            .commit_messages_batch(&[env])
            .expect("commit message");
    }

    // 🔍 КРИМИНАЛИСТИЧЕСКАЯ АТАКА: Хакер или сисадмин украл физический файл `forensics_test.redb` с SSD
    // и сканирует все сырые байты файла на диске:
    let raw_disk_bytes = std::fs::read(&db_path).expect("read raw db file from disk");
    assert!(raw_disk_bytes.len() > 4096);

    assert!(
        !raw_disk_bytes
            .windows(secret_username.len())
            .any(|w| w == secret_username.as_bytes()),
        "УТЕЧКА НА ДИСКЕ: @username найден в открытом виде в файле БД!"
    );
    assert!(
        !raw_disk_bytes
            .windows(secret_display_name.len())
            .any(|w| w == secret_display_name.as_bytes()),
        "УТЕЧКА НА ДИСКЕ: display_name найден в открытом виде в файле БД!"
    );
    assert!(
        !raw_disk_bytes
            .windows(secret_chat_text.len())
            .any(|w| w == secret_chat_text.as_bytes()),
        "УТЕЧКА НА ДИСКЕ: текст сообщения найден в файле БД!"
    );
}

#[test]
fn test_cold_reboot_persistence_and_48_byte_composite_cursor_pagination() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("reboot_test.redb");
    let storage_root_key = [0x42_u8; 32];

    let tenant = TenantId::new_v7();
    let alice_uid = UserId::new_v7();
    let bob_uid = UserId::new_v7();

    let alice = UserIdentity::generate(
        tenant,
        alice_uid,
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let bob = UserIdentity::generate(
        tenant,
        bob_uid,
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );

    let alice_bundle = alice.export_public_bundle().expect("a bundle");
    let bob_bundle = bob.export_public_bundle().expect("b bundle");

    let mut alice_chat = ChatSession::establish_direct(
        &alice,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("alice chat");
    let bob_chat = ChatSession::establish_direct(
        &bob,
        &alice_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("bob chat");
    let channel_id = alice_chat.channel_id();

    let fast_argon = Argon2Profile {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    // ФАЗА 1: Записываем данные на диск и выключаем сервер (drop(engine))
    {
        let engine =
            EncryptedStorageEngine::open_or_create(&db_path, storage_root_key, 1024).expect("open");

        let entry = DirectoryEntryProto {
            tenant_id: tenant.to_vec(),
            user_id: alice_uid.to_vec(),
            username: "alice_persistent".to_string(),
            display_name: "Alice Persistent".to_string(),
            public_key_bundle: Some(alice_bundle.clone()),
            transparency_log_hash: vec![0x11; 32],
            transparency_seq: 1,
        };
        engine
            .put_directory_entries_batch(&[entry])
            .expect("put dir");

        let mut batch = Vec::with_capacity(15);
        for i in 1..=15_usize {
            let msg = format!("Persistent disk message #{i:02}");
            let env = alice_chat
                .encrypt_message(&alice, &XChaCha20Poly1305Provider, msg.as_bytes())
                .expect("enc");
            batch.push(env);
        }
        engine
            .commit_messages_batch(&batch)
            .expect("group commit 15 messages");

        let vault = CloudKeyVault::seal_to_cloud_blob(
            &alice,
            &[&alice_chat],
            b"RebootPass",
            1,
            fast_argon,
        )
        .expect("vault");
        engine.put_vault_blob(&vault).expect("put vault");

        let wm = ReadReceiptWatermarkProto {
            tenant_id: tenant.to_vec(),
            channel_id: channel_id.to_vec(),
            user_id: bob_uid.to_vec(),
            last_read_message_id: batch[14].message_id.clone(),
            updated_at_ms: 1_700_000_000_999,
        };
        engine.flush_watermarks_batch(&[wm]).expect("flush wm");
    } // <-- ЗДЕСЬ СЕРВЕР ПОЛНОСТЬЮ ВЫКЛЮЧАЕТСЯ (100% RAM очищено!)

    // ФАЗА 2: Холодный старт сервера с диска (`Cold Boot`)
    let rebooted_engine =
        EncryptedStorageEngine::open_or_create(&db_path, storage_root_key, 1024).expect("reopen");

    // 1. Первое чтение `@alice_persistent` идет с L2 диска (Cache Miss) и прогревает L1 кэш
    let found_l2 = rebooted_engine
        .get_directory_entry_by_username(tenant, "@ALICE_PERSISTENT")
        .expect("l2 lookup")
        .expect("exists");
    assert_eq!(found_l2.display_name, "Alice Persistent");
    assert_eq!(rebooted_engine.metrics().l2_disk_reads, 1);
    assert_eq!(rebooted_engine.metrics().l1_cache_hits, 0);

    // Второе чтение того же `@alice_persistent` мгновенно бьет в L1 RAM-кэш!
    let _found_l1 = rebooted_engine
        .get_directory_entry_by_username(tenant, "alice_persistent")
        .expect("l1 lookup")
        .expect("exists");
    assert_eq!(rebooted_engine.metrics().l1_cache_hits, 1);

    // 2. Проверяем восстановление облачного сейфа и водораздела прочтения с диска
    let disk_vault = rebooted_engine
        .get_vault_blob(tenant, alice_uid)
        .expect("get vault")
        .expect("vault exists");
    assert_eq!(disk_vault.vault_version, 1);

    let disk_wm = rebooted_engine
        .get_read_watermark(tenant, channel_id, bob_uid)
        .expect("get wm")
        .expect("wm exists");
    assert_eq!(disk_wm.updated_at_ms, 1_700_000_000_999);

    // 3. Проверяем курсорную пагинацию из 48-байтного дискового индекса (по 6 сообщений на страницу, без OFFSET!)
    let page_1 = rebooted_engine
        .fetch_channel_history_from_disk(tenant, channel_id, None, 6)
        .expect("disk page 1");
    assert_eq!(page_1.envelopes.len(), 6);
    assert!(page_1.has_more);

    // Самое последнее сообщение на странице 1 — это сообщение #15
    let last_dec = bob_chat
        .decrypt_message(&bob, &XChaCha20Poly1305Provider, &page_1.envelopes[5])
        .expect("dec 15");
    assert_eq!(last_dec.as_slice(), b"Persistent disk message #15");

    let cursor_1 = MessageId::from_slice(&page_1.next_before_cursor).expect("cursor 1");
    let page_2 = rebooted_engine
        .fetch_channel_history_from_disk(tenant, channel_id, Some(cursor_1), 6)
        .expect("disk page 2");
    assert_eq!(page_2.envelopes.len(), 6);
    assert!(page_2.has_more);

    let cursor_2 = MessageId::from_slice(&page_2.next_before_cursor).expect("cursor 2");
    let page_3 = rebooted_engine
        .fetch_channel_history_from_disk(tenant, channel_id, Some(cursor_2), 6)
        .expect("disk page 3");
    assert_eq!(page_3.envelopes.len(), 3); // Сообщения #01, #02, #03
    assert!(!page_3.has_more);

    let first_dec = bob_chat
        .decrypt_message(&bob, &XChaCha20Poly1305Provider, &page_3.envelopes[0])
        .expect("dec 01");
    assert_eq!(first_dec.as_slice(), b"Persistent disk message #01");

    // ФАЗА 3: Атака с чужим ключом хранилища (украли диск без доступа к KMS/TPM ключу сервера)
    drop(rebooted_engine);
    let attacker_wrong_key = [0x99_u8; 32];
    let attacker_engine =
        EncryptedStorageEngine::open_or_create(&db_path, attacker_wrong_key, 1024)
            .expect("open with wrong key");

    // 1) Слепой индекс с чужим ключом даже не совпадет по хешу (возвращает None):
    assert!(attacker_engine
        .get_directory_entry_by_username(tenant, "alice_persistent")
        .expect("blind lookup")
        .is_none());

    // 2) А прямое чтение таблицы сообщений или сейфа по TenantId мгновенно ловит `DiskTamperDetected`!
    let tamper_err = attacker_engine
        .fetch_channel_history_from_disk(tenant, channel_id, None, 10)
        .err();
    assert!(matches!(tamper_err, Some(StorageError::DiskTamperDetected)));
}
