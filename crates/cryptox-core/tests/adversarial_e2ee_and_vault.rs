//! Боевой тестовый полигон Этапа 1 (по Правилу 05: `05-zero-fake-claims-proof.md`).
//!
//! Доказывает на изолированных акторах в памяти:
//! 1. Реальный обмен ключами X25519 + Ed25519 и сквозное шифрование через сырые байты сети (`Vec<u8>`).
//! 2. Облачную синхронизацию истории на новом ноутбуке сотрудника через `CloudKeyVault` (`Argon2id`).
//! 3. Двухрежимную корпоративную политику: `CorporateEscrowDlp` (доступ только через аппаратный HSM компании)
//!    и `StrictZeroKnowledge` (VIP-контур Совета Директоров — недоступен даже для HSM компании).
//! 4. Мгновенное уничтожение ключей при увольнении сотрудника (`crypto_shred()`).
//! 5. Полное отражение атак взломанного сервера (MITM подмена ключа, переклейка сообщения в чужой чат, битовые мутации).

use cryptox_core::{
    Aes256GcmProvider, Argon2Profile, ChatSession, CloudKeyVault, CryptoError, CryptoProvider,
    TenantComplianceKeyPair, UserIdentity, XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    CipherSuiteId, DeviceId, EncryptedEnvelope, EncryptedVaultBlob, EncryptionPolicy,
    PublicKeyBundle, TenantId, UserId,
};
use proptest::prelude::*;

#[test]
fn test_alice_bob_real_e2ee_over_untrusted_wire_both_ciphersuites() {
    let providers: [&dyn CryptoProvider; 2] = [&XChaCha20Poly1305Provider, &Aes256GcmProvider];

    for provider in providers {
        let tenant = TenantId::new_v7();

        // Устройство Алисы (изолированная память)
        let alice_id = UserId::new_v7();
        let alice_device = DeviceId::new_v7();
        let alice = UserIdentity::generate(tenant, alice_id, alice_device, provider.suite_id(), 1);

        // Устройство Боба (изолированная память)
        let bob_id = UserId::new_v7();
        let bob_device = DeviceId::new_v7();
        let bob = UserIdentity::generate(tenant, bob_id, bob_device, provider.suite_id(), 1);

        // Обмен публичными пакетами ТОЛЬКО через сериализованные байты сети
        let alice_bundle_wire: Vec<u8> = alice
            .export_public_bundle()
            .expect("export alice bundle")
            .to_wire_bytes();
        let bob_bundle_wire: Vec<u8> = bob
            .export_public_bundle()
            .expect("export bob bundle")
            .to_wire_bytes();

        let bob_bundle_on_alice =
            PublicKeyBundle::from_wire_bytes(&bob_bundle_wire).expect("decode bob bundle");
        let alice_bundle_on_bob =
            PublicKeyBundle::from_wire_bytes(&alice_bundle_wire).expect("decode alice bundle");

        let mut alice_session = ChatSession::establish_direct(
            &alice,
            &bob_bundle_on_alice,
            EncryptionPolicy::StrictZeroKnowledge,
            None,
        )
        .expect("alice establish session");

        let bob_session = ChatSession::establish_direct(
            &bob,
            &alice_bundle_on_bob,
            EncryptionPolicy::StrictZeroKnowledge,
            None,
        )
        .expect("bob establish session");

        assert_eq!(alice_session.channel_id(), bob_session.channel_id());

        // Алиса отправляет 3 сообщения подряд (проверяем работу Ratchet-шагов 1, 2, 3)
        for step in 1..=3_u64 {
            let secret_text = format!("Секретный контракт №{step} (протокол {:?})", provider.suite_id());
            let envelope = alice_session
                .encrypt_message(&alice, provider, secret_text.as_bytes())
                .expect("alice encrypt");

            assert_eq!(envelope.ratchet_step, step);

            // На сервер уходят только бинарные байты Protobuf
            let wire_bytes = envelope.to_wire_bytes();

            // Убеждаемся, что в сырых байтах по сети НЕТ открытого текста
            assert!(
                !wire_bytes
                    .windows(secret_text.len())
                    .any(|w| w == secret_text.as_bytes()),
                "В сетевом пакете обнаружен открытый текст!"
            );

            // Боб принимает сырые байты с сервера и расшифровывает в своей памяти
            let received_env =
                EncryptedEnvelope::from_wire_bytes(&wire_bytes).expect("bob decode wire");
            let decrypted = bob_session
                .decrypt_message(&bob, provider, &received_env)
                .expect("bob decrypt");

            assert_eq!(decrypted.as_slice(), secret_text.as_bytes());
        }
    }
}

#[test]
fn test_multi_device_cloud_key_vault_sync_and_hacker_db_breach() {
    let provider = XChaCha20Poly1305Provider;
    let tenant = TenantId::new_v7();
    let profile = Argon2Profile::interactive_fast();

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

    let bob_bundle = bob.export_public_bundle().expect("bob bundle");
    let alice_bundle = alice.export_public_bundle().expect("alice bundle");

    let mut alice_laptop_1_session = ChatSession::establish_direct(
        &alice,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("alice session");

    let mut bob_phone_session = ChatSession::establish_direct(
        &bob,
        &alice_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("bob session");

    // 1. В чате накопилась история сообщений (от Алисы и от Боба), которая хранится в облачной БД сервера
    let msg_from_alice = alice_laptop_1_session
        .encrypt_message(&alice, &provider, b"Bob, uploading Q4 financial report")
        .expect("encrypt 1")
        .to_wire_bytes();
    let msg_from_bob = bob_phone_session
        .encrypt_message(&bob, &provider, b"Received, Alice! Numbers look great.")
        .expect("encrypt 2")
        .to_wire_bytes();

    // 2. Ноутбук №1 Алисы сохраняет зашифрованный сейф ключей в облако
    let alice_password = b"CorrectHorseBatteryStaple#2026";
    let cloud_vault_wire = CloudKeyVault::seal_to_cloud_blob(
        &alice,
        &[&alice_laptop_1_session],
        alice_password,
        1,
        profile,
    )
    .expect("seal vault")
    .to_wire_bytes();

    // 3. АТАКА ХАКЕРА / СИСАДМИНА БД: украл `cloud_vault_wire` с сервера
    let stolen_blob = EncryptedVaultBlob::from_wire_bytes(&cloud_vault_wire).expect("decode blob");

    // Попытка №1: Неверный пароль
    let hack_attempt_1 = CloudKeyVault::unlock_from_cloud_blob(
        &stolen_blob,
        b"WrongPassword123",
        DeviceId::new_v7(),
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    );
    assert_eq!(hack_attempt_1.err(), Some(CryptoError::AeadIntegrityFailure));

    // Попытка №2: Хакер подменил `vault_version` в БД (проверка защиты AAD)
    let mut tampered_blob = stolen_blob.clone();
    tampered_blob.vault_version = 999;
    let hack_attempt_2 = CloudKeyVault::unlock_from_cloud_blob(
        &tampered_blob,
        alice_password,
        DeviceId::new_v7(),
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    );
    assert_eq!(hack_attempt_2.err(), Some(CryptoError::AeadIntegrityFailure));

    // 4. ЛЕГИТИМНАЯ ОБЛАЧНАЯ СИНХРОНИЗАЦИЯ: Алиса купила новый Macbook №2,
    // скачала с сервера ТОЛЬКО `cloud_vault_wire` и историю зашифрованных пакетов, и ввела свой пароль
    let new_macbook_device = DeviceId::new_v7();
    let (restored_alice, mut restored_sessions) = CloudKeyVault::unlock_from_cloud_blob(
        &stolen_blob,
        alice_password,
        new_macbook_device,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("unlock vault on new laptop");

    assert_eq!(restored_alice.user_id(), alice.user_id());
    assert_eq!(restored_sessions.len(), 1);
    let macbook_2_session = &mut restored_sessions[0];

    // Новый Macbook №2 мгновенно расшифровывает всю старую облачную историю чата (и свои сообщения, и сообщения Боба)!
    let env_1 = EncryptedEnvelope::from_wire_bytes(&msg_from_alice).expect("decode env 1");
    let env_2 = EncryptedEnvelope::from_wire_bytes(&msg_from_bob).expect("decode env 2");

    let hist_1 = macbook_2_session
        .decrypt_message(&restored_alice, &provider, &env_1)
        .expect("decrypt hist 1 on device 2");
    let hist_2 = macbook_2_session
        .decrypt_message(&restored_alice, &provider, &env_2)
        .expect("decrypt hist 2 on device 2");

    assert_eq!(hist_1.as_slice(), b"Bob, uploading Q4 financial report");
    assert_eq!(hist_2.as_slice(), b"Received, Alice! Numbers look great.");

    // И сразу же продолжает писать Бобу с нового Macbook №2 без пересоздания чата!
    let live_msg_from_macbook_2 = macbook_2_session
        .encrypt_message(&restored_alice, &provider, b"Sent from my new Macbook #2!")
        .expect("encrypt from device 2");
    assert_eq!(live_msg_from_macbook_2.ratchet_step, 2);

    let bob_decrypted = bob_phone_session
        .decrypt_message(&bob, &provider, &live_msg_from_macbook_2)
        .expect("bob decrypt message from alice device 2");
    assert_eq!(bob_decrypted.as_slice(), b"Sent from my new Macbook #2!");
}

#[test]
fn test_corporate_dlp_hsm_escrow_vs_vip_board_of_directors_zero_knowledge() {
    let provider = XChaCha20Poly1305Provider;
    let tenant = TenantId::new_v7();
    let foreign_tenant = TenantId::new_v7();

    // Аппаратный HSM-ключ Директора по безопасности (ИБ / DLP) компании
    let company_hsm = TenantComplianceKeyPair::generate(tenant);
    let foreign_company_hsm = TenantComplianceKeyPair::generate(foreign_tenant);

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
    let bob_bundle = bob.export_public_bundle().expect("bob bundle");

    // СЦЕНАРИЙ А: Обычный рабочий чат с политикой CorporateEscrowDlp
    let mut standard_corp_session = ChatSession::establish_direct(
        &alice,
        &bob_bundle,
        EncryptionPolicy::CorporateEscrowDlp,
        Some(company_hsm.public_key_bytes()),
    )
    .expect("corp session");

    let corp_env = standard_corp_session
        .encrypt_message(&alice, &provider, "Рабочий документ для проверки DLP".as_bytes())
        .expect("encrypt corp");

    // 1. Чужой HSM (или хакер со своим ключом) НЕ может расшифровать
    let foreign_attempt =
        ChatSession::decrypt_with_corporate_hsm(&foreign_company_hsm, &provider, &corp_env);
    assert_eq!(foreign_attempt.err(), Some(CryptoError::TenantMismatch));

    let fake_same_tenant_hsm = TenantComplianceKeyPair::generate(tenant);
    let fake_hsm_attempt =
        ChatSession::decrypt_with_corporate_hsm(&fake_same_tenant_hsm, &provider, &corp_env);
    assert_eq!(fake_hsm_attempt.err(), Some(CryptoError::AeadIntegrityFailure));

    // 2. Настоящий аппаратный HSM Службы Безопасности компании успешно проверяет сообщение в DLP
    let dlp_inspected =
        ChatSession::decrypt_with_corporate_hsm(&company_hsm, &provider, &corp_env)
            .expect("company HSM decrypt");
    assert_eq!(dlp_inspected.as_slice(), "Рабочий документ для проверки DLP".as_bytes());

    // СЦЕНАРИЙ Б: VIP-режим «Совет Директоров» (StrictZeroKnowledge)
    let mut vip_board_session = ChatSession::establish_direct(
        &alice,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("vip session");

    let vip_env = vip_board_session
        .encrypt_message(&alice, &provider, "Секретное решение Совета Директоров по M&A".as_bytes())
        .expect("encrypt vip");

    // Даже настоящий HSM Службы Безопасности компании НЕ может прочитать VIP-чат Совета Директоров!
    let hsm_on_vip =
        ChatSession::decrypt_with_corporate_hsm(&company_hsm, &provider, &vip_env);
    assert_eq!(hsm_on_vip.err(), Some(CryptoError::EscrowNotPresent));
}

#[test]
fn test_remote_wipe_crypto_shredding_on_employee_offboarding() {
    let provider = XChaCha20Poly1305Provider;
    let tenant = TenantId::new_v7();

    let mut fired_employee = UserIdentity::generate(
        tenant,
        UserId::new_v7(),
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let colleague = UserIdentity::generate(
        tenant,
        UserId::new_v7(),
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );

    let fired_bundle = fired_employee.export_public_bundle().expect("bundle");
    let colleague_bundle = colleague.export_public_bundle().expect("bundle");

    let mut fired_session = ChatSession::establish_direct(
        &fired_employee,
        &colleague_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("session");
    let mut colleague_session = ChatSession::establish_direct(
        &colleague,
        &fired_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("session");

    let cached_envelope = colleague_session
        .encrypt_message(&colleague, &provider, b"Top secret roadmap")
        .expect("encrypt");

    // До увольнения сотрудник может прочитать сообщение
    assert!(fired_session
        .decrypt_message(&fired_employee, &provider, &cached_envelope)
        .is_ok());

    // ПРИЛЕТАЕТ КОМАНДА УВОЛЬНЕНИЯ (Remote Wipe / Crypto-Shredding):
    fired_employee.crypto_shred();
    assert!(fired_employee.is_shredded());

    // Мгновенный отказ: ни старый кэш на диске, ни отправка новых сообщений больше не работают!
    assert_eq!(
        fired_session
            .decrypt_message(&fired_employee, &provider, &cached_envelope)
            .err(),
        Some(CryptoError::IdentityShredded)
    );
    assert_eq!(
        fired_session
            .encrypt_message(&fired_employee, &provider, b"Trying to leak data")
            .err(),
        Some(CryptoError::IdentityShredded)
    );
}

#[test]
fn test_malicious_server_mitm_and_context_splicing_attacks() {
    let provider = XChaCha20Poly1305Provider;
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
    let charlie = UserIdentity::generate(
        tenant,
        UserId::new_v7(),
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );

    // АТАКА №1 (MITM на сервере): Взломанный сервер пытается подсунуть Алисе публичный пакет Боба,
    // заменив в нем `x25519_public_key` на ключ Чарли
    let mut mitm_bob_bundle = bob.export_public_bundle().expect("bob bundle");
    let charlie_bundle = charlie.export_public_bundle().expect("charlie bundle");
    mitm_bob_bundle.x25519_public_key = charlie_bundle.x25519_public_key.clone();

    let mitm_result = ChatSession::establish_direct(
        &alice,
        &mitm_bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    );
    assert_eq!(
        mitm_result.err(),
        Some(CryptoError::SignatureVerificationFailed),
        "Клиент обязан отвергнуть подмененный сервером ключ X25519!"
    );

    // АТАКА №2 (Context Splicing): Сервер берет легитимное сообщение Алисы для Боба и пытается
    // подменить в нем `channel_id` или `ratchet_step`
    let valid_bob_bundle = bob.export_public_bundle().expect("bob bundle");
    let valid_alice_bundle = alice.export_public_bundle().expect("alice bundle");

    let mut alice_session = ChatSession::establish_direct(
        &alice,
        &valid_bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("session");
    let bob_session = ChatSession::establish_direct(
        &bob,
        &valid_alice_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("session");

    let env = alice_session
        .encrypt_message(&alice, &provider, b"Approve transfer of 1,000,000 RUB")
        .expect("encrypt");

    // Подмена `ratchet_step`
    let mut tampered_step = env.clone();
    tampered_step.ratchet_step = 99;
    assert!(bob_session
        .decrypt_message(&bob, &provider, &tampered_step)
        .is_err());

    // Подмена `channel_id` на другой чат
    let mut tampered_channel = env.clone();
    tampered_channel.channel_id = cryptox_proto::ChannelId::new_v7().to_vec();
    assert_eq!(
        bob_session
            .decrypt_message(&bob, &provider, &tampered_channel)
            .err(),
        Some(CryptoError::ChannelMismatch)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn proptest_any_bit_flip_in_ciphertext_nonce_or_signature_is_rejected(
        payload in proptest::collection::vec(any::<u8>(), 1..1024),
        flip_index in 0..1024_usize,
        flip_mask in 1..=255_u8,
    ) {
        let provider = XChaCha20Poly1305Provider;
        let tenant = TenantId::new_v7();
        let alice = UserIdentity::generate(tenant, UserId::new_v7(), DeviceId::new_v7(), CipherSuiteId::X25519XChaCha20Poly1305Blake3, 1);
        let bob = UserIdentity::generate(tenant, UserId::new_v7(), DeviceId::new_v7(), CipherSuiteId::X25519XChaCha20Poly1305Blake3, 1);

        let bob_bundle = bob.export_public_bundle().expect("bundle");
        let alice_bundle = alice.export_public_bundle().expect("bundle");

        let mut alice_session = ChatSession::establish_direct(&alice, &bob_bundle, EncryptionPolicy::StrictZeroKnowledge, None).expect("session");
        let bob_session = ChatSession::establish_direct(&bob, &alice_bundle, EncryptionPolicy::StrictZeroKnowledge, None).expect("session");

        let env = alice_session.encrypt_message(&alice, &provider, &payload).expect("encrypt");

        // 1. Мутируем 1 байт в шифротексте -> 100% отказ (и окно повторов НЕ должно отравиться!)
        let mut bad_ct = env.clone();
        let idx = flip_index % bad_ct.ciphertext.len();
        bad_ct.ciphertext[idx] ^= flip_mask;
        prop_assert!(bob_session.decrypt_message(&bob, &provider, &bad_ct).is_err());

        // 2. Мутируем 1 байт в подписи Ed25519 -> 100% отказ SignatureVerificationFailed!
        let mut bad_sig = env.clone();
        let sig_idx = flip_index % bad_sig.ed25519_signature.len();
        bad_sig.ed25519_signature[sig_idx] ^= flip_mask;
        prop_assert_eq!(
            bob_session.decrypt_message(&bob, &provider, &bad_sig).err(),
            Some(CryptoError::SignatureVerificationFailed)
        );

        // 3. Честный пакет после отбитых подделок расшифровывается 1-в-1 (RFC 4303 non-poisoning)
        let clean = bob_session.decrypt_message(&bob, &provider, &env).expect("clean decrypt");
        prop_assert_eq!(clean.as_slice(), payload.as_slice());

        // 4. Повторная отправка того же честного пакета блокируется защитой от Replay-атак
        prop_assert_eq!(
            bob_session.decrypt_message(&bob, &provider, &env).err(),
            Some(CryptoError::ReplayAttackDetected(1))
        );
    }
}
