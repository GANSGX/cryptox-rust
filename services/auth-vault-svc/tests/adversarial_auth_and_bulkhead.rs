//! Боевые тесты Этапа 2 (`services/auth-vault-svc`):
//! - Zero-Knowledge регистрация и вход по одноразовому челленджу;
//! - Отражение Replay-атаки (повторная отправка перехваченного пакета входа);
//! - Отражение атаки отката версии сейфа (`Vault Rollback Attack`) и попытки перезаписи чужого сейфа;
//! - **Chaos / Bulkhead Isolation Test**: при полном отключении `auth-vault-svc` шлюз (`AutonomousTokenVerifier`)
//!   продолжает проверять токены активных сотрудников со 100% успехом;
//! - `proptest` фаззинг сессионных токенов.

use auth_vault_svc::{AuthVaultError, AuthVaultService};
use cryptox_core::{Argon2Profile, CloudKeyVault, UserIdentity};
use cryptox_proto::{
    CipherSuiteId, DeviceId, EncryptionPolicy, RegisterUserRequest, TenantId, UserId,
};
use proptest::prelude::*;

fn register_test_employee(
    svc: &AuthVaultService,
    tenant_id: TenantId,
    username: &str,
    password: &[u8],
) -> (UserId, UserIdentity) {
    let user_id = UserId::new_v7();
    let device_id = DeviceId::new_v7();
    let profile = Argon2Profile::interactive_fast();

    let identity = UserIdentity::generate(
        tenant_id,
        user_id,
        device_id,
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let public_bundle = identity.export_public_bundle().expect("bundle");
    let initial_vault =
        CloudKeyVault::seal_to_cloud_blob(&identity, &[], password, 1, profile).expect("vault");

    let auth_vk = CloudKeyVault::derive_auth_verifying_key(
        password,
        &initial_vault.argon2_salt,
        profile,
    )
    .expect("auth vk");

    svc.register_user(RegisterUserRequest {
        tenant_id: tenant_id.to_vec(),
        user_id: user_id.to_vec(),
        username: username.to_string(),
        auth_verifying_key: auth_vk.to_vec(),
        public_key_bundle: Some(public_bundle),
        initial_vault_blob: Some(initial_vault),
    })
    .expect("register user");

    (user_id, identity)
}

#[test]
fn test_zero_knowledge_register_login_and_replay_attack_blocked() {
    let svc = AuthVaultService::new();
    let tenant = TenantId::new_v7();
    let password = b"UltraSecretCorpPass!2026";
    let now_ms = 1_700_000_000_000;

    let (alice_id, _alice_laptop1) = register_test_employee(&svc, tenant, "alice_ceo", password);

    // Повторная регистрация того же @username внутри одной компании блокируется
    let dup_challenge = svc.register_user(RegisterUserRequest {
        tenant_id: tenant.to_vec(),
        user_id: UserId::new_v7().to_vec(),
        username: "ALICE_CEO".to_string(),
        auth_verifying_key: vec![0u8; 32],
        public_key_bundle: None,
        initial_vault_blob: None,
    });
    assert!(dup_challenge.is_err());

    // 1. Вход с нового устройства (Macbook #2): запрашиваем одноразовый челлендж
    let challenge = svc
        .issue_login_challenge(tenant, "alice_ceo", now_ms)
        .expect("issue challenge");

    // 2. Атака подбора пароля: хакер подписывает челлендж неверным паролем
    let bad_verify_req =
        CloudKeyVault::sign_login_challenge(&challenge, b"WrongPassword", DeviceId::new_v7())
            .expect("sign bad");
    assert_eq!(
        svc.verify_login_and_fetch_vault(&bad_verify_req, now_ms + 100)
            .err(),
        Some(AuthVaultError::InvalidCredentials)
    );

    // Поскольку одноразовый челлендж сгорел при первой попытке, запрашиваем новый для легитимного входа
    let challenge_2 = svc
        .issue_login_challenge(tenant, "alice_ceo", now_ms + 200)
        .expect("issue challenge 2");
    let macbook_2 = DeviceId::new_v7();
    let valid_verify_req =
        CloudKeyVault::sign_login_challenge(&challenge_2, password, macbook_2).expect("sign valid");

    let (token, fetched_vault) = svc
        .verify_login_and_fetch_vault(&valid_verify_req, now_ms + 300)
        .expect("valid login");

    // 3. АТАКА ПОВТОРА (REPLAY ATTACK): Хакер перехватил `valid_verify_req` в сети и шлет его повторно
    let replay_attempt = svc.verify_login_and_fetch_vault(&valid_verify_req, now_ms + 301);
    assert_eq!(
        replay_attempt.err(),
        Some(AuthVaultError::ChallengeNotFoundOrReplayed),
        "Повторное использование одноразового челленджа обязано блокироваться!"
    );

    // 4. Проверяем, что скачанный сейф открывается на Macbook #2
    let (restored_alice, _) = CloudKeyVault::unlock_from_cloud_blob(
        &fetched_vault,
        password,
        macbook_2,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("unlock fetched vault");
    assert_eq!(restored_alice.user_id(), alice_id);

    // Проверяем выданный сессионный токен
    let verifier = svc.export_autonomous_verifier();
    let claims = verifier
        .verify_token(&token, now_ms + 500)
        .expect("verify token");
    assert_eq!(claims.user_id, alice_id);
    assert_eq!(claims.tenant_id, tenant);
}

#[test]
fn test_vault_version_rollback_and_cross_user_overwrite_attacks_blocked() {
    let svc = AuthVaultService::new();
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;
    let profile = Argon2Profile::interactive_fast();

    let (_alice_id, alice_identity) =
        register_test_employee(&svc, tenant, "alice_fin", b"AlicePass#1");
    let (_mallory_id, mallory_identity) =
        register_test_employee(&svc, tenant, "mallory_insider", b"MalloryPass#2");

    // Логиним Алису и Мэллори
    let ch_a = svc
        .issue_login_challenge(tenant, "alice_fin", now_ms)
        .expect("ch a");
    let req_a = CloudKeyVault::sign_login_challenge(&ch_a, b"AlicePass#1", DeviceId::new_v7())
        .expect("sign a");
    let (alice_token, _) = svc
        .verify_login_and_fetch_vault(&req_a, now_ms + 10)
        .expect("login a");

    let ch_m = svc
        .issue_login_challenge(tenant, "mallory_insider", now_ms)
        .expect("ch m");
    let req_m = CloudKeyVault::sign_login_challenge(&ch_m, b"MalloryPass#2", DeviceId::new_v7())
        .expect("sign m");
    let (mallory_token, _) = svc
        .verify_login_and_fetch_vault(&req_m, now_ms + 10)
        .expect("login m");

    // 1. Легитимное обновление сейфа Алисы до версии 2
    let vault_v2 = CloudKeyVault::seal_to_cloud_blob(
        &alice_identity,
        &[],
        b"AlicePass#1",
        2,
        profile,
    )
    .expect("seal v2");
    assert_eq!(
        svc.push_vault_update(&alice_token, vault_v2.clone(), now_ms + 20),
        Ok(2)
    );

    // 2. АТАКА ОТКАТА ВЕРСИИ (Vault Rollback Attack): попытка залить старую версию v1 или повторно v2
    let vault_v1 = CloudKeyVault::seal_to_cloud_blob(
        &alice_identity,
        &[],
        b"AlicePass#1",
        1,
        profile,
    )
    .expect("seal v1");
    assert_eq!(
        svc.push_vault_update(&alice_token, vault_v1, now_ms + 30)
            .err(),
        Some(AuthVaultError::VaultVersionRollback {
            current: 2,
            attempted: 1
        })
    );
    assert_eq!(
        svc.push_vault_update(&alice_token, vault_v2, now_ms + 35)
            .err(),
        Some(AuthVaultError::VaultVersionRollback {
            current: 2,
            attempted: 2
        })
    );

    // 3. АТАКА ПЕРЕЗАПИСИ ЧУЖОГО СЕЙФА: Мэллори со своим токеном пытается перезаписать сейф Алисы (версией 3)
    let mut forged_alice_v3 = CloudKeyVault::seal_to_cloud_blob(
        &mallory_identity,
        &[],
        b"MalloryPass#2",
        3,
        profile,
    )
    .expect("seal v3");
    forged_alice_v3.user_id = alice_identity.user_id().to_vec();

    assert_eq!(
        svc.push_vault_update(&mallory_token, forged_alice_v3, now_ms + 40)
            .err(),
        Some(AuthVaultError::UnauthorizedAccess)
    );
}

#[test]
fn test_chaos_bulkhead_auth_service_crash_does_not_drop_active_chat_sessions() {
    let svc = AuthVaultService::new();
    // Экспортируем автономный верификатор на наш сетевой шлюз `edge-gateway`
    let gateway_verifier = svc.export_autonomous_verifier();

    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;

    let (alice_id, _) = register_test_employee(&svc, tenant, "alice_dev", b"Pass12345!");
    let (bob_id, _) = register_test_employee(&svc, tenant, "bob_sre", b"Pass67890!");

    let ch_a = svc
        .issue_login_challenge(tenant, "alice_dev", now_ms)
        .expect("ch a");
    let (alice_token, _) = svc
        .verify_login_and_fetch_vault(
            &CloudKeyVault::sign_login_challenge(&ch_a, b"Pass12345!", DeviceId::new_v7())
                .expect("sign"),
            now_ms + 5,
        )
        .expect("login a");

    let ch_b = svc
        .issue_login_challenge(tenant, "bob_sre", now_ms)
        .expect("ch b");
    let (bob_token, _) = svc
        .verify_login_and_fetch_vault(
            &CloudKeyVault::sign_login_challenge(&ch_b, b"Pass67890!", DeviceId::new_v7())
                .expect("sign"),
            now_ms + 5,
        )
        .expect("login b");

    // 💥 CHAOS INJECTION: Микросервис `auth-vault-svc` ПАДАЕТ!
    svc.set_simulated_outage(true);

    // Новые логины во время аварии `auth-vault-svc` ожидаемо возвращают ServiceUnavailable:
    assert_eq!(
        svc.issue_login_challenge(tenant, "alice_dev", now_ms + 100)
            .err(),
        Some(AuthVaultError::ServiceUnavailable)
    );

    // 🛡️ BULKHEAD PROOF: Несмотря на то, что `auth-vault-svc` мертв, шлюз `edge-gateway`
    // через `AutonomousTokenVerifier` продолжает проверять токены Алисы и Боба со 100% успехом!
    let verified_a = gateway_verifier
        .verify_token(&alice_token, now_ms + 1000)
        .expect("gateway verifies alice while auth-svc is DOWN");
    let verified_b = gateway_verifier
        .verify_token(&bob_token, now_ms + 1000)
        .expect("gateway verifies bob while auth-svc is DOWN");

    assert_eq!(verified_a.user_id, alice_id);
    assert_eq!(verified_b.user_id, bob_id);

    // И даже во время падения `auth-vault-svc` команда мгновенного увольнения Боба на шлюзе
    // моментально отсекает его сессию:
    gateway_verifier.revoke_user(tenant, bob_id);
    assert_eq!(
        gateway_verifier
            .verify_token(&bob_token, now_ms + 1001)
            .err(),
        Some(AuthVaultError::SessionRevoked)
    );
    // А Алиса продолжает работать без единого сбоя:
    assert!(gateway_verifier
        .verify_token(&alice_token, now_ms + 1001)
        .is_ok());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn proptest_any_token_tampering_is_rejected_by_autonomous_verifier(
        flip_idx in 0..64_usize,
        flip_mask in 1..=255_u8,
        time_extension_ms in 1..1_000_000_u64,
    ) {
        let svc = AuthVaultService::new();
        let verifier = svc.export_autonomous_verifier();
        let tenant = TenantId::new_v7();
        let now_ms = 1_700_000_000_000;

        let _ = register_test_employee(&svc, tenant, "prop_user", b"SecretPass");
        let ch = svc.issue_login_challenge(tenant, "prop_user", now_ms).expect("ch");
        let (valid_token, _) = svc.verify_login_and_fetch_vault(
            &CloudKeyVault::sign_login_challenge(&ch, b"SecretPass", DeviceId::new_v7()).expect("sign"),
            now_ms + 1,
        ).expect("login");

        // 1. Оригинальный токен валиден
        prop_assert!(verifier.verify_token(&valid_token, now_ms + 10).is_ok());

        // 2. Попытка продлить срок действия токена (`expires_at_ms`) без приватного ключа сервера -> ОТКАЗ!
        let mut forged_expiry = valid_token.clone();
        forged_expiry.expires_at_ms += time_extension_ms;
        prop_assert_eq!(
            verifier.verify_token(&forged_expiry, now_ms + 10).err(),
            Some(AuthVaultError::InvalidCredentials)
        );

        // 3. Мутация 1 байта подписи Ed25519 -> ОТКАЗ!
        let mut forged_sig = valid_token;
        let idx = flip_idx % forged_sig.ed25519_signature.len();
        forged_sig.ed25519_signature[idx] ^= flip_mask;
        prop_assert_eq!(
            verifier.verify_token(&forged_sig, now_ms + 10).err(),
            Some(AuthVaultError::InvalidCredentials)
        );
    }
}
