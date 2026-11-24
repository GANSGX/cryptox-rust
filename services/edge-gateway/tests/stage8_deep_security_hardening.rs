//! Полигон глубокой проверки безопасности всех 7 модулей (`stage8_deep_security_hardening.rs`)
//! по стандарту OWASP ASVS v5.0 Level 3 и Правилу 06 (`06-deep-module-hardening-first.md`).
//!
//! Проверяет закрытие всех 15 векторов атак:
//! 1. `cryptox-proto` + `messaging-svc` + `presence-receipts-svc`: Блокировка `UUIDv7` из 2099 года (`Future Timestamp Poisoning`);
//! 2. `cryptox-core`: 64-шаговое скользящее окно `ReplaySlidingWindow` (блокировка повтора `ratchet_step` + поддержка out-of-order пакетов);
//! 3. `cryptox-storage`: Защита L1-кэша от `Cache Stampede DoS` (точечное вытеснение вместо полного `.clear()`);
//! 4. `auth-vault-svc`: Блокировка брутфорса пароля после 5 попыток (`AccountTemporarilyLocked`) + GC протухших челленджей;
//! 5. `messaging-svc`: Блокировка подмены устройства отправителя (`Device ID Spoofing`);
//! 6. `edge-gateway`: Изолированный `TokenBucketRateLimiter` (блокировка DDoS-спамера без влияния на соседних сотрудников).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use auth_vault_svc::{
    AuthVaultError, AuthVaultService, ACCOUNT_LOCKOUT_DURATION_MS, LOGIN_CHALLENGE_TTL_MS,
};
use cryptox_core::{
    Argon2Profile, ChatSession, CloudKeyVault, CryptoError, UserIdentity,
    XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    CipherSuiteId, DeviceId, DirectoryEntryProto, EncryptionPolicy, MessageId, ProtoError,
    RegisterUserRequest, SignedSessionToken, TenantId, UserId,
};
use cryptox_storage::EncryptedStorageEngine;
use edge_gateway::{EdgeGateway, GatewayError};
use messaging_svc::{MessagingError, MessagingService};
use presence_receipts_svc::{PresenceError, PresenceReceiptsService};
use std::sync::Arc;
use tempfile::tempdir;
use user_directory_svc::UserDirectoryService;

fn build_hardened_cluster() -> Arc<EdgeGateway> {
    let auth_svc = Arc::new(AuthVaultService::new());
    let verifier = auth_svc.export_autonomous_verifier();
    let dir_svc = Arc::new(UserDirectoryService::new(verifier.clone()));
    let presence_svc = Arc::new(PresenceReceiptsService::new(verifier.clone()));
    let msg_svc = Arc::new(MessagingService::new(verifier));
    Arc::new(EdgeGateway::new(auth_svc, dir_svc, presence_svc, msg_svc))
}

fn onboard_user(
    gw: &EdgeGateway,
    tenant: TenantId,
    username: &str,
    password: &[u8],
    now_ms: u64,
) -> (UserId, DeviceId, UserIdentity, SignedSessionToken) {
    let uid = UserId::new_v7();
    let dev = DeviceId::new_v7();
    let profile = Argon2Profile {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let identity = UserIdentity::generate(
        tenant,
        uid,
        dev,
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let bundle = identity.export_public_bundle().expect("bundle");
    let vault =
        CloudKeyVault::seal_to_cloud_blob(&identity, &[], password, 1, profile).expect("vault");
    let auth_vk =
        CloudKeyVault::derive_auth_verifying_key(password, &vault.argon2_salt, profile)
            .expect("vk");

    gw.auth_service()
        .register_user(RegisterUserRequest {
            tenant_id: tenant.to_vec(),
            user_id: uid.to_vec(),
            username: username.to_string(),
            auth_verifying_key: auth_vk.to_vec(),
            public_key_bundle: Some(bundle.clone()),
            initial_vault_blob: Some(vault),
        })
        .expect("reg");

    let ch = gw
        .auth_service()
        .issue_login_challenge(tenant, username, now_ms)
        .expect("ch");
    let req = CloudKeyVault::sign_login_challenge(&ch, password, dev).expect("sign");
    let (token, _) = gw
        .auth_service()
        .verify_login_and_fetch_vault(&req, now_ms + 1)
        .expect("login");

    gw.directory_service()
        .publish_or_rotate_entry(&token, username, username, bundle, now_ms + 2)
        .expect("dir");

    (uid, dev, identity, token)
}

#[test]
fn test_1_core_ratchet_sliding_window_replay_and_out_of_order_protection() {
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

    let mut alice_chat = ChatSession::establish_direct(
        &alice,
        &bob.export_public_bundle().expect("b"),
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("chat a");
    let bob_chat = ChatSession::establish_direct(
        &bob,
        &alice.export_public_bundle().expect("a"),
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("chat b");

    let env_1 = alice_chat
        .encrypt_message(&alice, &XChaCha20Poly1305Provider, b"Transfer 500,000 RUB #1")
        .expect("e1");
    let env_2 = alice_chat
        .encrypt_message(&alice, &XChaCha20Poly1305Provider, b"Msg #2 (delayed in network)")
        .expect("e2");
    let env_3 = alice_chat
        .encrypt_message(&alice, &XChaCha20Poly1305Provider, b"Msg #3 (arrives before #2)")
        .expect("e3");

    // 1. Пакет #1 приходит штатно
    assert!(bob_chat
        .decrypt_message(&bob, &XChaCha20Poly1305Provider, &env_1)
        .is_ok());

    // 2. АТАКА REPLAY НА ПАКЕТ #1: Хакер пересылает пакет #1 второй раз -> БЛОКИРОВКА!
    assert_eq!(
        bob_chat
            .decrypt_message(&bob, &XChaCha20Poly1305Provider, &env_1)
            .err(),
        Some(CryptoError::ReplayAttackDetected(1))
    );

    // 3. Проверка Out-of-Order доставки: пакет #3 приходит РАНЬШЕ пакета #2
    assert!(bob_chat
        .decrypt_message(&bob, &XChaCha20Poly1305Provider, &env_3)
        .is_ok());
    // Запоздавший пакет #2 попадает внутрь 64-шагового скользящего окна и успешно расшифровывается 1 раз:
    assert!(bob_chat
        .decrypt_message(&bob, &XChaCha20Poly1305Provider, &env_2)
        .is_ok());
    // Но повторная отправка #2 или #3 мгновенно блокируется битовой маской окна!
    assert_eq!(
        bob_chat
            .decrypt_message(&bob, &XChaCha20Poly1305Provider, &env_2)
            .err(),
        Some(CryptoError::ReplayAttackDetected(2))
    );
    assert_eq!(
        bob_chat
            .decrypt_message(&bob, &XChaCha20Poly1305Provider, &env_3)
            .err(),
        Some(CryptoError::ReplayAttackDetected(3))
    );
}

#[test]
fn test_2_future_2099_uuidv7_timestamp_poisoning_blocked_in_messaging_and_presence() {
    let gw = build_hardened_cluster();
    let tenant = TenantId::new_v7();
    let now_ms = 1_795_518_000_000;

    let (_, _, alice_id, alice_token) =
        onboard_user(&gw, tenant, "alice_time", b"Pass1", now_ms);
    let (_, _, bob_id, _) = onboard_user(&gw, tenant, "bob_time", b"Pass2", now_ms);

    let mut chat = ChatSession::establish_direct(
        &alice_id,
        &bob_id.export_public_bundle().expect("b"),
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("chat");

    // Хакер кует `MessageId` с таймстемпом из 2099 года (0xFFFF_FFFF_FFFF в первых 6 байтах),
    // чтобы отравить водораздел прочтения `read_watermarks` или прибить сообщение навечно в топ чата!
    let forged_2099_bytes: [u8; 16] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    let forged_2099_mid = MessageId::from_slice(&forged_2099_bytes).expect("mid");

    // 1. Попытка отравить `presence-receipts-svc` будущим `MessageId` -> БЛОКИРОВКА!
    let poison_presence = gw.presence_service().record_read_receipt(
        &alice_token,
        chat.channel_id(),
        forged_2099_mid,
        now_ms,
    );
    assert!(matches!(
        poison_presence.err(),
        Some(PresenceError::Proto(
            ProtoError::InvalidUuidV7OrTimestamp(_)
        ))
    ));

    // 2. Попытка отправить конверт с `message_id` из 2099 года в `messaging-svc` -> БЛОКИРОВКА!
    let mut env = chat
        .encrypt_message(&alice_id, &XChaCha20Poly1305Provider, b"Hello from 2099")
        .expect("enc");
    env.message_id = forged_2099_mid.to_vec();

    let poison_msg = gw
        .messaging_service()
        .route_and_persist_envelope(&alice_token, env, now_ms);
    assert!(matches!(
        poison_msg.err(),
        Some(MessagingError::Proto(
            ProtoError::InvalidUuidV7OrTimestamp(_)
        ))
    ));
}

#[test]
fn test_3_auth_brute_force_lockout_and_challenge_garbage_collection() {
    let gw = build_hardened_cluster();
    let tenant = TenantId::new_v7();
    let now_ms = 1_795_518_000_000;

    let _ = onboard_user(&gw, tenant, "victim_cfo", b"RealCfoPassword#2026", now_ms);

    // 1. Хакер делает 5 неудачных попыток угадать пароль подряд
    for attempt in 1..=5_u32 {
        let ch = gw
            .auth_service()
            .issue_login_challenge(tenant, "victim_cfo", now_ms + (attempt as u64) * 10)
            .expect("issue ch");
        let bad_req = CloudKeyVault::sign_login_challenge(
            &ch,
            format!("WrongPass#{attempt}").as_bytes(),
            DeviceId::new_v7(),
        )
        .expect("sign");

        let res = gw
            .auth_service()
            .verify_login_and_fetch_vault(&bad_req, now_ms + (attempt as u64) * 10 + 1);

        if attempt < 5 {
            assert_eq!(res.err(), Some(AuthVaultError::InvalidCredentials));
        } else {
            // На 5-й ошибке срабатывает автоматическая блокировка аккаунта на 5 минут!
            assert!(matches!(
                res.err(),
                Some(AuthVaultError::AccountTemporarilyLocked { .. })
            ));
        }
    }

    // 2. Пока действует 5-минутная блокировка, даже запрос нового челленджа отклоняется!
    assert!(matches!(
        gw.auth_service()
            .issue_login_challenge(tenant, "victim_cfo", now_ms + 1_000)
            .err(),
        Some(AuthVaultError::AccountTemporarilyLocked { .. })
    ));

    // 3. После окончания окна блокировки (`now_ms + ACCOUNT_LOCKOUT_DURATION_MS + 1000`)
    // легитимный CFO входит со своим настоящим паролем!
    let unlock_time = now_ms + ACCOUNT_LOCKOUT_DURATION_MS + 1_000;
    let ch_valid = gw
        .auth_service()
        .issue_login_challenge(tenant, "victim_cfo", unlock_time)
        .expect("challenge after lockout expired");
    let valid_req = CloudKeyVault::sign_login_challenge(
        &ch_valid,
        b"RealCfoPassword#2026",
        DeviceId::new_v7(),
    )
    .expect("sign valid");
    assert!(gw
        .auth_service()
        .verify_login_and_fetch_vault(&valid_req, unlock_time + 1)
        .is_ok());

    // 4. Проверяем сборщик мусора протухших челленджей (`prune_expired_challenges`)
    let _ = gw
        .auth_service()
        .issue_login_challenge(tenant, "victim_cfo", unlock_time + 10);
    let pruned = gw
        .auth_service()
        .prune_expired_challenges(unlock_time + LOGIN_CHALLENGE_TTL_MS + 100);
    assert_eq!(pruned, 1);
}

#[test]
fn test_4_device_id_spoofing_and_gateway_rate_limiter_ddos_shield() {
    let gw = build_hardened_cluster();
    let tenant = TenantId::new_v7();
    let now_ms = 1_795_518_000_000;

    let (_, _alice_dev1, alice_id, alice_token) =
        onboard_user(&gw, tenant, "alice_dev_check", b"Pass1", now_ms);
    let (_, _, bob_id, bob_token) =
        onboard_user(&gw, tenant, "bob_normal_user", b"Pass2", now_ms);

    let mut alice_chat = ChatSession::establish_direct(
        &alice_id,
        &bob_id.export_public_bundle().expect("b"),
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("chat");
    let mut bob_chat = ChatSession::establish_direct(
        &bob_id,
        &alice_id.export_public_bundle().expect("a"),
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("chat b");

    // 1. АТАКА ПОДМЕНЫ УСТРОЙСТВА (`Device ID Spoofing`):
    // У Алисы токен выдан на `Device 1`, но в заголовке конверта подставлен `Device 2`
    let mut spoofed_dev_env = alice_chat
        .encrypt_message(&alice_id, &XChaCha20Poly1305Provider, b"Spoofed device")
        .expect("enc");
    spoofed_dev_env.sender_device_id = DeviceId::new_v7().to_vec();

    let spoof_res = gw.handle_send_message_wire(
        &alice_token.to_wire_bytes(),
        &spoofed_dev_env.to_wire_bytes(),
        now_ms + 10,
    );
    assert_eq!(
        spoof_res.err(),
        Some(GatewayError::Messaging(
            MessagingError::SenderOrTenantSpoofing
        ))
    );

    // 2. ЗАЩИТА ОТ DDOS И СПАМА (`TokenBucketRateLimiter` на `edge-gateway`):
    // Устанавливаем лимит: не более 5 запросов в секунду на одного пользователя
    gw.configure_rate_limit(5, 1_000);

    for i in 1..=8_usize {
        let env = alice_chat
            .encrypt_message(
                &alice_id,
                &XChaCha20Poly1305Provider,
                format!("Spam #{i}").as_bytes(),
            )
            .expect("enc");
        let res = gw.handle_send_message_wire(
            &alice_token.to_wire_bytes(),
            &env.to_wire_bytes(),
            now_ms + 50,
        );
        if i <= 5 {
            assert!(res.is_ok(), "Запрос #{i} в пределах квоты должен пройти");
        } else {
            assert_eq!(
                res.err(),
                Some(GatewayError::RateLimitExceeded),
                "Спам-запрос #{i} сверх квоты обязан отсекаться на шлюзе!"
            );
        }
    }

    // При этом соседний сотрудник Боб в ту же миллисекунду отправляет сообщение без малейших ограничений!
    let bob_env = bob_chat
        .encrypt_message(&bob_id, &XChaCha20Poly1305Provider, b"Bob is unaffected by Alice spam")
        .expect("bob enc");
    assert!(gw
        .handle_send_message_wire(&bob_token.to_wire_bytes(), &bob_env.to_wire_bytes(), now_ms + 50)
        .is_ok());
}

#[test]
fn test_5_storage_l1_targeted_eviction_prevents_cache_stampede() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("stampede_test.redb");
    let engine =
        EncryptedStorageEngine::open_or_create(&db_path, [0x33; 32], 64).expect("open max 64");

    let tenant = TenantId::new_v7();
    let mut entries = Vec::with_capacity(70);
    for i in 0..70_usize {
        entries.push(DirectoryEntryProto {
            tenant_id: tenant.to_vec(),
            user_id: UserId::new_v7().to_vec(),
            username: format!("user_{i:04}"),
            display_name: format!("User {i}"),
            public_key_bundle: None,
            transparency_log_hash: vec![0xAA; 32],
            transparency_seq: (i + 1) as u64,
        });
    }
    engine
        .put_directory_entries_batch(&entries)
        .expect("put 70 entries into L1 max 64");

    // Проверяем последние 50 записей: благодаря точечному вытеснению (вместо полного .clear())
    // они все остались в горячем L1 RAM-кэше!
    let before_l1 = engine.metrics().l1_cache_hits;
    for i in 20..70_usize {
        let found = engine
            .get_directory_entry_by_username(tenant, &format!("user_{i:04}"))
            .expect("lookup")
            .expect("exists");
        assert_eq!(found.username, format!("user_{i:04}"));
    }
    let l1_delta = engine.metrics().l1_cache_hits - before_l1;
    assert!(
        l1_delta >= 45,
        "Ожидалось сохранение горячего L1 кэша (>=45 хитов), получено {l1_delta}"
    );
}
