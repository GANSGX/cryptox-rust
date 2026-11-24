//! Нагрузочный стенд Этапа 1 (`stage1_load_bench.rs`).
//!
//! Замеряет реальную производительность на текущем железе в `--release` режиме:
//! 1. Бинарная сериализация/десериализация `EncryptedEnvelope` (`prost` Protobuf vs JSON).
//! 2. Чистая скорость AEAD + Ratchet KDF (`XChaCha20-Poly1305` и `AES-256-GCM` с проверкой `AAD`).
//! 3. Полный цикл `ChatSession::encrypt_message` + `decrypt_message` (включая `Ed25519` подпись).
//! 4. Упаковка и распаковка `CloudKeyVault` (`Argon2id`).

use cryptox_core::{
    Aes256GcmProvider, Argon2Profile, ChatSession, CloudKeyVault, CryptoProvider, UserIdentity,
    XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    CipherSuiteId, DeviceId, EncryptedEnvelope, EncryptionPolicy, TenantId, UserId,
};
use std::time::Instant;

#[allow(clippy::expect_used)]
fn main() {
    println!("==================================================================");
    println!("🚀 CRYPTOX-RUST: НАГРУЗОЧНЫЙ СТЕНД ЭТАПА 1 (RELEASE BENCHMARK)");
    println!("==================================================================");

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

    let bob_bundle = bob.export_public_bundle().expect("bob bundle");
    let alice_bundle = alice.export_public_bundle().expect("alice bundle");

    let mut alice_session = ChatSession::establish_direct(
        &alice,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("alice session");
    let bob_session = ChatSession::establish_direct(
        &bob,
        &alice_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("bob session");

    let sample_payload =
        b"Hello from CryptoX Enterprise! This is a typical 128-byte corporate chat message with E2EE and AAD protection.";

    // ------------------------------------------------------------------
    // ТЕСТ 1: Бинарная сериализация Protobuf (encode + decode + validate)
    // ------------------------------------------------------------------
    let sample_env = alice_session
        .encrypt_message(&alice, &XChaCha20Poly1305Provider, sample_payload)
        .expect("sample encrypt");
    let wire_len = sample_env.to_wire_bytes().len();

    let proto_iters: u64 = 500_000;
    let start_proto = Instant::now();
    for _ in 0..proto_iters {
        let bytes = sample_env.to_wire_bytes();
        let decoded = EncryptedEnvelope::from_wire_bytes(&bytes).expect("decode");
        std::hint::black_box(decoded);
    }
    let elapsed_proto = start_proto.elapsed();
    let proto_ops_sec = (proto_iters as f64) / elapsed_proto.as_secs_f64();
    let proto_ns_op = elapsed_proto.as_nanos() as f64 / (proto_iters as f64);

    println!("\n[1] Бинарная сериализация + валидация конверта (cryptox-proto):");
    println!("    • Размер пакета в сети: {wire_len} байт (для 110 байт текста + все UUIDv7 + подпись Ed25519)");
    println!("    • Итераций:             {proto_iters}");
    println!("    • Пропускная способность: {:.0} пакетов/сек", proto_ops_sec);
    println!("    • Средняя задержка:       {:.0} нс ({:.3} мкс)", proto_ns_op, proto_ns_op / 1000.0);

    // ------------------------------------------------------------------
    // ТЕСТ 2: Скорость AEAD шифрования + дешифрования с AAD (XChaCha20-Poly1305)
    // ------------------------------------------------------------------
    let aead_iters: u64 = 250_000;
    let key = [42u8; 32];
    let nonce_x = [7u8; 24];
    let aad = sample_env.canonical_aad();

    let start_xchacha = Instant::now();
    for _ in 0..aead_iters {
        let ct = XChaCha20Poly1305Provider
            .seal(&key, &nonce_x, &aad, sample_payload)
            .expect("seal");
        let pt = XChaCha20Poly1305Provider
            .open(&key, &nonce_x, &aad, &ct)
            .expect("open");
        std::hint::black_box(pt);
    }
    let elapsed_xchacha = start_xchacha.elapsed();
    // Каждая итерация = 1 шифрование + 1 дешифрование (2 крипто-операции)
    let xchacha_ops_sec = ((aead_iters * 2) as f64) / elapsed_xchacha.as_secs_f64();
    let xchacha_us_op = (elapsed_xchacha.as_micros() as f64) / ((aead_iters * 2) as f64);

    println!("\n[2] Конвейер AEAD XChaCha20-Poly1305 + AAD (cryptox-core):");
    println!("    • Операций (Seal+Open): {}", aead_iters * 2);
    println!("    • Скорость на 1 ядро:   {:.0} сообщений/сек", xchacha_ops_sec);
    println!("    • Задержка на операцию: {:.2} мкс", xchacha_us_op);

    // ------------------------------------------------------------------
    // ТЕСТ 3: Скорость AEAD шифрования + дешифрования с AAD (AES-256-GCM)
    // ------------------------------------------------------------------
    let nonce_aes = [9u8; 12];
    let start_aes = Instant::now();
    for _ in 0..aead_iters {
        let ct = Aes256GcmProvider
            .seal(&key, &nonce_aes, &aad, sample_payload)
            .expect("seal");
        let pt = Aes256GcmProvider
            .open(&key, &nonce_aes, &aad, &ct)
            .expect("open");
        std::hint::black_box(pt);
    }
    let elapsed_aes = start_aes.elapsed();
    let aes_ops_sec = ((aead_iters * 2) as f64) / elapsed_aes.as_secs_f64();
    let aes_us_op = (elapsed_aes.as_micros() as f64) / ((aead_iters * 2) as f64);

    println!("\n[3] Конвейер AEAD AES-256-GCM (CNSA 2.0) + AAD (cryptox-core):");
    println!("    • Операций (Seal+Open): {}", aead_iters * 2);
    println!("    • Скорость на 1 ядро:   {:.0} сообщений/сек", aes_ops_sec);
    println!("    • Задержка на операцию: {:.2} мкс", aes_us_op);

    // ------------------------------------------------------------------
    // ТЕСТ 4: Полный цикл с криптографической подписью Ed25519 каждого пакета
    // ------------------------------------------------------------------
    let full_iters: u64 = 20_000;
    let start_full = Instant::now();
    for _ in 0..full_iters {
        let env = alice_session
            .encrypt_message(&alice, &XChaCha20Poly1305Provider, sample_payload)
            .expect("encrypt");
        let pt = bob_session
            .decrypt_message(&bob, &XChaCha20Poly1305Provider, &env)
            .expect("decrypt");
        std::hint::black_box(pt);
    }
    let elapsed_full = start_full.elapsed();
    let full_ops_sec = ((full_iters * 2) as f64) / elapsed_full.as_secs_f64();

    println!("\n[4] Полный E2EE цикл (UUIDv7 + BLAKE3 Ratchet + AEAD + Ed25519 Sign & Verify):");
    println!("    • Полных циклов:        {full_iters} ({} крипто-операций с Ed25519)", full_iters * 2);
    println!("    • Скорость на 1 ядро:   {:.0} подписанных операций/сек", full_ops_sec);

    // ------------------------------------------------------------------
    // ТЕСТ 5: CloudKeyVault (Argon2id OWASP L3 64MB RAM)
    // ------------------------------------------------------------------
    let start_vault = Instant::now();
    let blob = CloudKeyVault::seal_to_cloud_blob(
        &alice,
        &[&alice_session],
        b"CorporateMasterPassword#2026",
        1,
        Argon2Profile::production_owasp_l3(),
    )
    .expect("vault seal");
    let seal_ms = start_vault.elapsed().as_millis();

    let start_unlock = Instant::now();
    let (_restored_id, _restored_sess) = CloudKeyVault::unlock_from_cloud_blob(
        &blob,
        b"CorporateMasterPassword#2026",
        DeviceId::new_v7(),
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("vault unlock");
    let unlock_ms = start_unlock.elapsed().as_millis();

    println!("\n[5] Облачный Сейф Ключей (CloudKeyVault — Argon2id 64 МБ RAM, OWASP ASVS L3):");
    println!("    • Размер сейфа в облаке: {} байт", blob.to_wire_bytes().len());
    println!("    • Время запечатывания:   {seal_ms} мс");
    println!("    • Время открытия на новом ноутбуке: {unlock_ms} мс");
    println!("==================================================================");
}
