//! Боевые интеграционные, хакерские и Triple-Chaos тесты Этапа 4 (`edge-gateway` + `messaging-svc` + `presence-receipts-svc`).
//!
//! Проверяет:
//! 1. **Тройной Chaos / Bulkhead («Апокалипсис второстепенных сервисов»):**
//!    Одновременно падают `auth-vault-svc`, `user-directory-svc` И `presence-receipts-svc`.
//!    Доказываем, что риалтайм-переписка и курсорная облачная история через `edge-gateway <-> messaging-svc`
//!    продолжают работать со 100% доставкой!
//! 2. **Идемпотентная дедупликация («Ехал в лифте, отправил пакет 7 раз»):** в чате сохраняется строго 1 сообщение.
//! 3. **Защита от спуфинга отправителя (`Sender Spoofing Attack`):** попытка подставить чужой `sender_user_id` блокируется.
//! 4. **Полный сквозной сценарий облачной синхронизации истории на новом ноутбуке** (`CloudKeyVault` + `UUIDv7` Cursor History).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use auth_vault_svc::AuthVaultService;
use cryptox_core::{
    Argon2Profile, ChatSession, CloudKeyVault, UserIdentity, XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    CipherSuiteId, DeviceId, EncryptionPolicy, MessageId, RegisterUserRequest, SendMessageAckProto,
    SignedSessionToken, TenantId, UserId,
};
use edge_gateway::{EdgeGateway, GatewayError};
use messaging_svc::{MessagingError, MessagingService};
use presence_receipts_svc::PresenceReceiptsService;
use prost::Message;
use std::sync::Arc;
use user_directory_svc::UserDirectoryService;

fn setup_cluster() -> Arc<EdgeGateway> {
    let auth_svc = Arc::new(AuthVaultService::new());
    let verifier = auth_svc.export_autonomous_verifier();
    let dir_svc = Arc::new(UserDirectoryService::new(verifier.clone()));
    let presence_svc = Arc::new(PresenceReceiptsService::new(verifier.clone()));
    let msg_svc = Arc::new(MessagingService::new(verifier));

    Arc::new(EdgeGateway::new(auth_svc, dir_svc, presence_svc, msg_svc))
}

fn register_and_login(
    gw: &EdgeGateway,
    tenant: TenantId,
    username: &str,
    password: &[u8],
    now_ms: u64,
) -> (UserId, UserIdentity, SignedSessionToken) {
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
        .expect("register");

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
        .expect("publish dir");

    (uid, identity, token)
}

#[test]
fn test_triple_service_apocalypse_chaos_bulkhead_survival() {
    let gw = setup_cluster();
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;

    let (_, alice_id, alice_token) =
        register_and_login(&gw, tenant, "alice_lead", b"PassA", now_ms);
    let (_, bob_id, bob_token) = register_and_login(&gw, tenant, "bob_senior", b"PassB", now_ms);

    // Алиса и Боб находят друг друга по @username и открывают личный чат
    let bob_search = gw
        .handle_search_users(&alice_token, "@bob_sen", 5, now_ms + 10)
        .expect("search bob");
    let bob_bundle =
        UserDirectoryService::verify_client_received_entry(tenant, &bob_search.entries[0])
            .expect("verify bob");

    let alice_search = gw
        .handle_search_users(&bob_token, "@alice_l", 5, now_ms + 10)
        .expect("search alice");
    let alice_bundle =
        UserDirectoryService::verify_client_received_entry(tenant, &alice_search.entries[0])
            .expect("verify alice");

    let mut alice_chat = ChatSession::establish_direct(
        &alice_id,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("alice chat");
    let bob_chat = ChatSession::establish_direct(
        &bob_id,
        &alice_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("bob chat");

    let channel_id = alice_chat.channel_id();

    // Боб подписывается на риалтайм-поток сообщений чата
    let mut bob_realtime_rx = gw
        .subscribe_channel_realtime(&bob_token, channel_id, now_ms + 20)
        .expect("subscribe realtime");

    // Прогреваем токен Алисы и Боба на шлюзе (как у активного соединения)
    let alice_token_wire = alice_token.to_wire_bytes();

    // 💥💥💥 TRIPLE CHAOS APOCALYPSE: ОДНОВРЕМЕННО ПАДАЮТ ВСЕ 3 ВТОРОСТЕПЕННЫХ МИКРОСЕРВИСА!
    gw.auth_service().set_simulated_outage(true);
    gw.directory_service().set_simulated_outage(true);
    gw.presence_service().set_simulated_outage(true);

    // 🛡️ Доказываем, что во время полного отказа `auth`, `directory` и `presence`
    // Алиса отправляет 10 зашифрованных сообщений подряд через `edge-gateway`,
    // Боб мгновенно получает их в риалтайме и читает историю по курсору `UUIDv7`!
    for i in 1..=10_usize {
        let text = format!("Сообщение №{i} во время падения 3 сервисов!");
        let env = alice_chat
            .encrypt_message(&alice_id, &XChaCha20Poly1305Provider, text.as_bytes())
            .expect("encrypt");

        let ack_bytes = gw
            .handle_send_message_wire(
                &alice_token_wire,
                &env.to_wire_bytes(),
                now_ms + 100 + (i as u64),
            )
            .expect("send message succeeds while 3 sidecar services are DOWN!");

        let ack = SendMessageAckProto::decode(ack_bytes.as_slice()).expect("decode ack");
        assert!(!ack.was_deduplicated);

        // Боб мгновенно получает пакет из риалтайм-канала и расшифровывает
        let rt_env = bob_realtime_rx.try_recv().expect("realtime push received");
        let decrypted = bob_chat
            .decrypt_message(&bob_id, &XChaCha20Poly1305Provider, &rt_env)
            .expect("bob decrypt realtime");
        assert_eq!(decrypted.as_slice(), text.as_bytes());
    }

    // Проверяем, что Circuit Breaker на шлюзе аккуратно поглотил все 10 ошибок упавшего `presence-receipts-svc`
    assert_eq!(gw.absorbed_sidecar_failures(), 10);

    // Проверяем курсорную пагинацию истории чата по `UUIDv7` (лимит по 4 сообщения на страницу, без OFFSET!)
    let page_1 = gw
        .handle_fetch_history(&bob_token, channel_id, None, 4, now_ms + 500)
        .expect("fetch page 1");
    assert_eq!(page_1.envelopes.len(), 4);
    assert!(page_1.has_more);

    let cursor_1 = MessageId::from_slice(&page_1.next_before_cursor).expect("cursor 1");
    let page_2 = gw
        .handle_fetch_history(&bob_token, channel_id, Some(cursor_1), 4, now_ms + 501)
        .expect("fetch page 2");
    assert_eq!(page_2.envelopes.len(), 4);
    assert!(page_2.has_more);

    let cursor_2 = MessageId::from_slice(&page_2.next_before_cursor).expect("cursor 2");
    let page_3 = gw
        .handle_fetch_history(&bob_token, channel_id, Some(cursor_2), 4, now_ms + 502)
        .expect("fetch page 3");
    assert_eq!(page_3.envelopes.len(), 2); // Оставшиеся самые старые сообщения №1 и №2
    assert!(!page_3.has_more);
}

#[test]
fn test_idempotent_deduplication_elevator_bad_lte_and_sender_spoofing_blocked() {
    let gw = setup_cluster();
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;

    let (_, alice_id, alice_token) =
        register_and_login(&gw, tenant, "alice_lte", b"PassA", now_ms);
    let (_, bob_id, _bob_token) = register_and_login(&gw, tenant, "bob_lte", b"PassB", now_ms);
    let (_, _mallory_id, mallory_token) =
        register_and_login(&gw, tenant, "mallory_spoof", b"PassM", now_ms);

    let bob_bundle = bob_id.export_public_bundle().expect("bob bundle");
    let mut alice_chat = ChatSession::establish_direct(
        &alice_id,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("chat");

    let env = alice_chat
        .encrypt_message(
            &alice_id,
            &XChaCha20Poly1305Provider,
            b"Message sent from elevator with bad LTE",
        )
        .expect("encrypt");
    let env_wire = env.to_wire_bytes();
    let alice_tok_wire = alice_token.to_wire_bytes();

    // 1. МИНА №2 (Ехал в лифте — клиент отправил один и тот же пакет 7 раз подряд):
    for attempt in 1..=7_usize {
        let ack_wire = gw
            .handle_send_message_wire(&alice_tok_wire, &env_wire, now_ms + (attempt as u64))
            .expect("send");
        let ack = SendMessageAckProto::decode(ack_wire.as_slice()).expect("decode ack");
        if attempt == 1 {
            assert!(!ack.was_deduplicated);
        } else {
            assert!(
                ack.was_deduplicated,
                "Повторная отправка пакета #{attempt} обязана быть дедуплицирована!"
            );
        }
    }

    // В истории чата должно быть СТРОГО 1 сообщение, а не 7 дублей!
    let history = gw
        .handle_fetch_history(&alice_token, alice_chat.channel_id(), None, 50, now_ms + 100)
        .expect("history");
    assert_eq!(history.envelopes.len(), 1);

    // 2. АТАКА СПУФИНГА ОТПРАВИТЕЛЯ: Мэллори со своим токеном пытается отправить конверт от имени Алисы
    let spoof_attempt =
        gw.handle_send_message_wire(&mallory_token.to_wire_bytes(), &env_wire, now_ms + 200);
    assert_eq!(
        spoof_attempt.err(),
        Some(GatewayError::Messaging(
            MessagingError::SenderOrTenantSpoofing
        ))
    );
}

#[test]
fn test_new_laptop_cloud_vault_and_cursor_history_full_sync() {
    let gw = setup_cluster();
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;
    let alice_pass = b"MyCloudSyncPassword#2026";
    let fast_profile = Argon2Profile {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    let (_, alice_laptop1, alice_token1) =
        register_and_login(&gw, tenant, "alice_sync", alice_pass, now_ms);
    let (_, bob_phone, bob_token) =
        register_and_login(&gw, tenant, "bob_sync", b"BobPass", now_ms);

    let bob_bundle = bob_phone.export_public_bundle().expect("bob bundle");
    let alice_bundle = alice_laptop1.export_public_bundle().expect("alice bundle");

    let mut alice_chat_laptop1 = ChatSession::establish_direct(
        &alice_laptop1,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("alice chat");
    let mut bob_chat_phone = ChatSession::establish_direct(
        &bob_phone,
        &alice_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("bob chat");

    // Алиса и Боб переписываются через `edge-gateway`
    let msg1 = alice_chat_laptop1
        .encrypt_message(&alice_laptop1, &XChaCha20Poly1305Provider, b"Hello Bob from Laptop 1")
        .expect("m1");
    let _ = gw
        .handle_send_message_wire(&alice_token1.to_wire_bytes(), &msg1.to_wire_bytes(), now_ms + 10)
        .expect("send m1");

    let msg2 = bob_chat_phone
        .encrypt_message(&bob_phone, &XChaCha20Poly1305Provider, b"Hi Alice from Bob Phone")
        .expect("m2");
    let _ = gw
        .handle_send_message_wire(&bob_token.to_wire_bytes(), &msg2.to_wire_bytes(), now_ms + 20)
        .expect("send m2");

    // Ноутбук №1 Алисы сохраняет обновленный сейф с ключом чата Боба (версия 2) в облако `auth-vault-svc`
    let updated_vault = CloudKeyVault::seal_to_cloud_blob(
        &alice_laptop1,
        &[&alice_chat_laptop1],
        alice_pass,
        2,
        fast_profile,
    )
    .expect("seal v2");
    gw.auth_service()
        .push_vault_update(&alice_token1, updated_vault, now_ms + 30)
        .expect("push v2");

    // --- АЛИСА ОТКРЫВАЕТ НОВЫЙ НОУТБУК №2 (0 общей памяти с Ноутбуком №1!) ---
    let laptop2_dev = DeviceId::new_v7();
    let ch = gw
        .auth_service()
        .issue_login_challenge(tenant, "alice_sync", now_ms + 100)
        .expect("ch2");
    let login_req = CloudKeyVault::sign_login_challenge(&ch, alice_pass, laptop2_dev).expect("sign2");
    let (token_laptop2, cloud_vault_blob) = gw
        .auth_service()
        .verify_login_and_fetch_vault(&login_req, now_ms + 101)
        .expect("login laptop 2");

    let (restored_alice, restored_sessions) = CloudKeyVault::unlock_from_cloud_blob(
        &cloud_vault_blob,
        alice_pass,
        laptop2_dev,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("unlock on laptop 2");
    let laptop2_chat = &restored_sessions[0];

    // Новый ноутбук №2 запрашивает облачную историю у `edge-gateway` и мгновенно расшифровывает весь диалог!
    let cloud_history = gw
        .handle_fetch_history(&token_laptop2, laptop2_chat.channel_id(), None, 50, now_ms + 105)
        .expect("fetch cloud history on laptop 2");
    assert_eq!(cloud_history.envelopes.len(), 2);

    let dec1 = laptop2_chat
        .decrypt_message(&restored_alice, &XChaCha20Poly1305Provider, &cloud_history.envelopes[0])
        .expect("dec1");
    let dec2 = laptop2_chat
        .decrypt_message(&restored_alice, &XChaCha20Poly1305Provider, &cloud_history.envelopes[1])
        .expect("dec2");

    assert_eq!(dec1.as_slice(), b"Hello Bob from Laptop 1");
    assert_eq!(dec2.as_slice(), b"Hi Alice from Bob Phone");
}
