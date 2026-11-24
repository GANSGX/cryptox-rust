//! Боевые тесты Этапа 3 (`services/user-directory-svc`):
//! 1. Полный флоу MVP: Поиск коллеги по префиксу `@username` -> проверка `DirectoryEntryProto` -> мгновенный старт E2EE-чата;
//! 2. Отражение атаки перечисления сотрудников чужой компании (`Cross-Tenant Enumeration`);
//! 3. Отражение MITM-подмены ключа `X25519`, подмены корневого `Ed25519` и отката версии `key_version`;
//! 4. **Chaos / Bulkhead Test**: работа поиска при упавшем `auth-vault-svc` и работа открытых чатов при упавшем `user-directory-svc`.

use auth_vault_svc::AuthVaultService;
use cryptox_core::{
    Argon2Profile, ChatSession, CloudKeyVault, CryptoError, UserIdentity,
    XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    CipherSuiteId, DeviceId, EncryptionPolicy, RegisterUserRequest, SignedSessionToken, TenantId,
    UserId,
};
use user_directory_svc::{DirectoryError, UserDirectoryService};

fn onboard_employee(
    auth_svc: &AuthVaultService,
    dir_svc: &UserDirectoryService,
    tenant_id: TenantId,
    username: &str,
    display_name: &str,
    now_ms: u64,
) -> (UserId, UserIdentity, SignedSessionToken) {
    let user_id = UserId::new_v7();
    let device_id = DeviceId::new_v7();
    let password = b"CorpPass#2026";
    let profile = Argon2Profile {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    let identity = UserIdentity::generate(
        tenant_id,
        user_id,
        device_id,
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let bundle = identity.export_public_bundle().expect("bundle");
    let vault =
        CloudKeyVault::seal_to_cloud_blob(&identity, &[], password, 1, profile).expect("vault");
    let auth_vk =
        CloudKeyVault::derive_auth_verifying_key(password, &vault.argon2_salt, profile)
            .expect("auth vk");

    auth_svc
        .register_user(RegisterUserRequest {
            tenant_id: tenant_id.to_vec(),
            user_id: user_id.to_vec(),
            username: username.to_string(),
            auth_verifying_key: auth_vk.to_vec(),
            public_key_bundle: Some(bundle.clone()),
            initial_vault_blob: Some(vault),
        })
        .expect("register auth");

    let ch = auth_svc
        .issue_login_challenge(tenant_id, username, now_ms)
        .expect("challenge");
    let req = CloudKeyVault::sign_login_challenge(&ch, password, device_id).expect("sign");
    let (token, _) = auth_svc
        .verify_login_and_fetch_vault(&req, now_ms + 1)
        .expect("login");

    dir_svc
        .publish_or_rotate_entry(&token, username, display_name, bundle, now_ms + 2)
        .expect("publish directory");

    (user_id, identity, token)
}

#[test]
fn test_search_username_and_instant_e2ee_chat_establishment() {
    let auth_svc = AuthVaultService::new();
    let dir_svc = UserDirectoryService::new(auth_svc.export_autonomous_verifier());
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;

    let (_alice_id, alice_identity, alice_token) = onboard_employee(
        &auth_svc,
        &dir_svc,
        tenant,
        "alice_product",
        "Alice Product Manager",
        now_ms,
    );
    let (bob_id, bob_identity, bob_token) = onboard_employee(
        &auth_svc,
        &dir_svc,
        tenant,
        "bob_architect",
        "Bob Principal Architect",
        now_ms,
    );
    let _ = onboard_employee(
        &auth_svc,
        &dir_svc,
        tenant,
        "boris_devops",
        "Boris DevOps",
        now_ms,
    );

    // 1. Алиса вводит в поиск префикс `@bo` и находит Боба и Бориса
    let search_res = dir_svc
        .search_by_prefix(&alice_token, "@bo", 10, now_ms + 100)
        .expect("search @bo");
    assert_eq!(search_res.entries.len(), 2);
    assert_eq!(search_res.entries[0].username, "bob_architect");
    assert_eq!(search_res.entries[1].username, "boris_devops");

    // 2. Алиса кликает на `bob_architect`, клиент проверяет подпись карточки и открывает личный E2EE-чат
    let bob_verified_bundle =
        UserDirectoryService::verify_client_received_entry(tenant, &search_res.entries[0])
            .expect("verify bob entry");

    let mut alice_chat = ChatSession::establish_direct(
        &alice_identity,
        &bob_verified_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("alice establish chat");

    let env = alice_chat
        .encrypt_message(
            &alice_identity,
            &XChaCha20Poly1305Provider,
            "Привет, Боб! Нашла тебя через поиск @bob_architect".as_bytes(),
        )
        .expect("encrypt");

    // 3. Боб получает пакет, запрашивает ключ Алисы по ее `UserId` из `user-directory-svc` и расшифровывает
    let alice_entry = dir_svc
        .get_by_user_id(&bob_token, alice_identity.user_id(), now_ms + 110)
        .expect("bob lookup alice");
    let alice_verified_bundle =
        UserDirectoryService::verify_client_received_entry(tenant, &alice_entry)
            .expect("verify alice entry");

    let bob_chat = ChatSession::establish_direct(
        &bob_identity,
        &alice_verified_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("bob establish chat");

    assert_eq!(bob_chat.peer_user_id(), alice_identity.user_id());
    assert_eq!(alice_chat.peer_user_id(), bob_id);

    let decrypted = bob_chat
        .decrypt_message(&bob_identity, &XChaCha20Poly1305Provider, &env)
        .expect("bob decrypt");
    assert_eq!(
        decrypted.as_slice(),
        "Привет, Боб! Нашла тебя через поиск @bob_architect".as_bytes()
    );
}

#[test]
fn test_cross_tenant_enumeration_and_isolation_strictly_blocked() {
    let auth_svc = AuthVaultService::new();
    let dir_svc = UserDirectoryService::new(auth_svc.export_autonomous_verifier());
    let now_ms = 1_700_000_000_000;

    let tenant_bank = TenantId::new_v7();
    let tenant_competitor = TenantId::new_v7();

    let (bank_ceo_id, _, _) = onboard_employee(
        &auth_svc,
        &dir_svc,
        tenant_bank,
        "ceo_alpha_bank",
        "CEO Alpha Bank",
        now_ms,
    );
    let (_, _, competitor_token) = onboard_employee(
        &auth_svc,
        &dir_svc,
        tenant_competitor,
        "spy_competitor",
        "Competitor Agent",
        now_ms,
    );

    // Попытка №1: Поиск по префиксу `@ceo` из токена чужой компании возвращает 0 записей
    let prefix_attempt = dir_svc
        .search_by_prefix(&competitor_token, "@ceo", 50, now_ms + 50)
        .expect("search");
    assert!(
        prefix_attempt.entries.is_empty(),
        "Сотрудник чужой компании не должен видеть людей из другой организации!"
    );

    // Попытка №2: Точный запрос `@ceo_alpha_bank` из чужой компании -> UserNotFound
    assert_eq!(
        dir_svc
            .get_by_username(&competitor_token, "@ceo_alpha_bank", now_ms + 50)
            .err(),
        Some(DirectoryError::UserNotFound)
    );

    // Попытка №3: Запрос напрямую по угаданному `UserId` из чужой компании -> UserNotFound
    assert_eq!(
        dir_svc
            .get_by_user_id(&competitor_token, bank_ceo_id, now_ms + 50)
            .err(),
        Some(DirectoryError::UserNotFound)
    );
}

#[test]
fn test_mitm_forged_key_bundle_and_key_version_downgrade_attacks_blocked() {
    let auth_svc = AuthVaultService::new();
    let dir_svc = UserDirectoryService::new(auth_svc.export_autonomous_verifier());
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;

    let (alice_id, _alice_identity, alice_token) = onboard_employee(
        &auth_svc,
        &dir_svc,
        tenant,
        "alice_sec",
        "Alice Security",
        now_ms,
    );

    // АТАКА №1 (Key Version Downgrade / Rollback): Попытка повторно загрузить версию `key_version = 1`
    let entry_v1 = dir_svc
        .get_by_username(&alice_token, "alice_sec", now_ms + 10)
        .expect("get v1");
    let bundle_v1 = entry_v1.public_key_bundle.clone().expect("bundle v1");

    let rollback_attempt = dir_svc.publish_or_rotate_entry(
        &alice_token,
        "alice_sec",
        "Alice Security",
        bundle_v1.clone(),
        now_ms + 20,
    );
    assert_eq!(
        rollback_attempt.err(),
        Some(DirectoryError::KeyVersionRollback {
            current: 1,
            attempted: 1
        })
    );

    // АТАКА №2 (MITM подмена X25519 ключа в пакете без приватного ключа Ed25519):
    let mut mitm_bundle = bundle_v1;
    mitm_bundle.key_version = 2;
    mitm_bundle.x25519_public_key = vec![99u8; 32];
    let mitm_attempt = dir_svc.publish_or_rotate_entry(
        &alice_token,
        "alice_sec",
        "Alice Security",
        mitm_bundle,
        now_ms + 30,
    );
    assert_eq!(
        mitm_attempt.err(),
        Some(DirectoryError::Crypto(
            CryptoError::SignatureVerificationFailed
        ))
    );

    // АТАКА №3 (Попытка подменить корневой ключ личности Ed25519 новым сгенерированным ключом):
    let impostor_identity = UserIdentity::generate(
        tenant,
        alice_id,
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        2,
    );
    let impostor_bundle = impostor_identity.export_public_bundle().expect("impostor");
    let root_swap_attempt = dir_svc.publish_or_rotate_entry(
        &alice_token,
        "alice_sec",
        "Alice Impostor",
        impostor_bundle,
        now_ms + 40,
    );
    assert_eq!(
        root_swap_attempt.err(),
        Some(DirectoryError::IdentitySigningKeySubstitution)
    );
}

#[test]
fn test_chaos_bulkhead_directory_works_when_auth_is_down_and_chats_survive_directory_crash() {
    let auth_svc = AuthVaultService::new();
    let dir_svc = UserDirectoryService::new(auth_svc.export_autonomous_verifier());
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;

    let (_, alice_id_core, alice_token) =
        onboard_employee(&auth_svc, &dir_svc, tenant, "alice_core", "Alice", now_ms);
    let (_, bob_id_core, bob_token) =
        onboard_employee(&auth_svc, &dir_svc, tenant, "bob_core", "Bob", now_ms);

    // 💥 CHAOS 1: Падает `auth-vault-svc`!
    auth_svc.set_simulated_outage(true);

    // 🛡️ Поиск по `@username` в `user-directory-svc` продолжает работать без единого сбоя!
    let found_bob = dir_svc
        .get_by_username(&alice_token, "@bob_core", now_ms + 500)
        .expect("directory works while auth-svc is DOWN");
    let bob_bundle =
        UserDirectoryService::verify_client_received_entry(tenant, &found_bob).expect("verify");

    let found_alice = dir_svc
        .get_by_username(&bob_token, "@alice_core", now_ms + 500)
        .expect("directory works while auth-svc is DOWN");
    let alice_bundle =
        UserDirectoryService::verify_client_received_entry(tenant, &found_alice).expect("verify");

    let mut alice_chat = ChatSession::establish_direct(
        &alice_id_core,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("alice chat");
    let bob_chat = ChatSession::establish_direct(
        &bob_id_core,
        &alice_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("bob chat");

    // 💥 CHAOS 2: Теперь падает еще и `user-directory-svc`!
    dir_svc.set_simulated_outage(true);
    assert_eq!(
        dir_svc
            .get_by_username(&alice_token, "@bob_core", now_ms + 600)
            .err(),
        Some(DirectoryError::ServiceUnavailable)
    );

    // 🛡️ BULKHEAD PROOF: Хотя лежат ОБА сервиса (`auth-vault-svc` И `user-directory-svc`),
    // уже открытый чат между Алисой и Бобом продолжает шифровать и доставлять сообщения со 100% успехом!
    let msg = alice_chat
        .encrypt_message(
            &alice_id_core,
            &XChaCha20Poly1305Provider,
            b"Both auth and directory are DOWN, but our chat still works!",
        )
        .expect("encrypt while services down");
    let decrypted = bob_chat
        .decrypt_message(&bob_id_core, &XChaCha20Poly1305Provider, &msg)
        .expect("decrypt while services down");
    assert_eq!(
        decrypted.as_slice(),
        b"Both auth and directory are DOWN, but our chat still works!"
    );
}
