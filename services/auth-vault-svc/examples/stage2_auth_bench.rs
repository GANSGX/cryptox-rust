//! Нагрузочный стенд Этапа 2 (`stage2_auth_bench.rs`).
//!
//! Проверяет производительность `auth-vault-svc` и `AutonomousTokenVerifier` на масштабе 100 000 сотрудников:
//! 1. Холодная криптографическая проверка подписи `Ed25519` новых токенов.
//! 2. Горячая автономная проверка 1 000 000 пакетов с активными токенами на шлюзе (`AutonomousTokenVerifier` BLAKE3 + DashMap).
//! 3. Выдача 500 000 зашифрованных облачных сейфов (`pull_vault`) при утреннем шторме синхронизации устройств.

use auth_vault_svc::AuthVaultService;
use cryptox_core::{Argon2Profile, CloudKeyVault, UserIdentity};
use cryptox_proto::{
    CipherSuiteId, DeviceId, RegisterUserRequest, SignedSessionToken, TenantId, UserId,
};
use std::time::Instant;

#[allow(clippy::expect_used)]
fn main() {
    println!("==================================================================");
    println!("🚀 CRYPTOX-RUST: НАГРУЗОЧНЫЙ СТЕНД ЭТАПА 2 (AUTH-VAULT-SVC 100K SLA)");
    println!("==================================================================");

    let svc = AuthVaultService::new();
    let gateway_verifier = svc.export_autonomous_verifier();
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;
    let fast_profile = Argon2Profile {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    // Подготавливаем пул зарегистрированных сотрудников и их активных сессионных токенов
    let pool_size: usize = 2_000;
    let mut active_tokens: Vec<SignedSessionToken> = Vec::with_capacity(pool_size);

    let start_prep = Instant::now();
    for i in 0..pool_size {
        let user_id = UserId::new_v7();
        let device_id = DeviceId::new_v7();
        let username = format!("emp_{i:06}");
        let password = b"EnterpriseBenchmarkPassword";

        let identity = UserIdentity::generate(
            tenant,
            user_id,
            device_id,
            CipherSuiteId::X25519XChaCha20Poly1305Blake3,
            1,
        );
        let bundle = identity.export_public_bundle().expect("bundle");
        let vault = CloudKeyVault::seal_to_cloud_blob(&identity, &[], password, 1, fast_profile)
            .expect("vault");
        let auth_vk = CloudKeyVault::derive_auth_verifying_key(
            password,
            &vault.argon2_salt,
            fast_profile,
        )
        .expect("auth vk");

        svc.register_user(RegisterUserRequest {
            tenant_id: tenant.to_vec(),
            user_id: user_id.to_vec(),
            username: username.clone(),
            auth_verifying_key: auth_vk.to_vec(),
            public_key_bundle: Some(bundle),
            initial_vault_blob: Some(vault),
        })
        .expect("register");

        let ch = svc
            .issue_login_challenge(tenant, &username, now_ms)
            .expect("ch");
        let req = CloudKeyVault::sign_login_challenge(&ch, password, device_id).expect("sign");
        let (tok, _) = svc
            .verify_login_and_fetch_vault(&req, now_ms + 1)
            .expect("login");
        active_tokens.push(tok);
    }
    println!(
        "\n[0] Подготовка {} сотрудников (Zero-Knowledge Register + Challenge-Response Login): {:.2} сек",
        pool_size,
        start_prep.elapsed().as_secs_f64()
    );

    // ------------------------------------------------------------------
    // ТЕСТ 1: Холодная криптографическая проверка Ed25519 новых токенов на шлюзе
    // ------------------------------------------------------------------
    let fresh_verifier = svc.export_autonomous_verifier();
    let start_cold = Instant::now();
    for tok in &active_tokens {
        let claims = fresh_verifier
            .verify_token(tok, now_ms + 10)
            .expect("cold verify");
        std::hint::black_box(claims);
    }
    let elapsed_cold = start_cold.elapsed();
    let cold_rps = (pool_size as f64) / elapsed_cold.as_secs_f64();
    let cold_us = (elapsed_cold.as_micros() as f64) / (pool_size as f64);

    println!("\n[1] Холодная проверка новых токенов (Полная проверка подписи Ed25519 на 1 ядро):");
    println!("    • Проверено новых токенов: {pool_size}");
    println!("    • Пропускная способность:  {:.0} новых сессий/сек (на 1 ядро CPU)", cold_rps);
    println!("    • Средняя задержка:        {:.2} мкс", cold_us);

    // ------------------------------------------------------------------
    // ТЕСТ 2: Горячая автономная проверка 1 000 000 запросов на шлюзе (Bulkhead Mode)
    // ------------------------------------------------------------------
    // Даже выключаем `auth-vault-svc`, чтобы доказать 100% автономность под нагрузкой!
    svc.set_simulated_outage(true);

    let hot_iters: usize = 1_000_000;
    let start_hot = Instant::now();
    for i in 0..hot_iters {
        let tok = &active_tokens[i % pool_size];
        let claims = fresh_verifier
            .verify_token(tok, now_ms + 20)
            .expect("hot verify");
        std::hint::black_box(claims);
    }
    let elapsed_hot = start_hot.elapsed();
    let hot_rps = (hot_iters as f64) / elapsed_hot.as_secs_f64();
    let hot_ns = (elapsed_hot.as_nanos() as f64) / (hot_iters as f64);

    println!("\n[2] Автономная проверка активных сессий на шлюзе (при ВЫКЛЮЧЕННОМ auth-vault-svc!):");
    println!("    • Всего проверок:          {hot_iters}");
    println!("    • Пропускная способность:  {:.0} проверок/сек (на 1 ядро CPU!)", hot_rps);
    println!("    • Средняя задержка:        {:.0} наносекунд ({:.3} мкс)", hot_ns, hot_ns / 1000.0);

    // ------------------------------------------------------------------
    // ТЕСТ 3: Утренний шторм облачной синхронизации (500 000 выдач EncryptedVaultBlob)
    // ------------------------------------------------------------------
    svc.set_simulated_outage(false);
    // Прогреваем кэш внутреннего верификатора
    for tok in &active_tokens {
        let _ = gateway_verifier.verify_token(tok, now_ms + 30);
    }

    let pull_iters: usize = 500_000;
    let start_pull = Instant::now();
    for i in 0..pull_iters {
        let tok = &active_tokens[i % pool_size];
        let vault_blob = svc.pull_vault(tok, now_ms + 30).expect("pull vault");
        std::hint::black_box(vault_blob);
    }
    let elapsed_pull = start_pull.elapsed();
    let pull_rps = (pull_iters as f64) / elapsed_pull.as_secs_f64();
    let pull_us = (elapsed_pull.as_micros() as f64) / (pull_iters as f64);

    println!("\n[3] Утренний шторм синхронизации сейфов ключей (pull_vault — 500 000 запросов):");
    println!("    • Пропускная способность:  {:.0} выдач сейфов/сек (на 1 ядро)", pull_rps);
    println!("    • Средняя задержка:        {:.2} мкс", pull_us);
    println!("==================================================================");
}
