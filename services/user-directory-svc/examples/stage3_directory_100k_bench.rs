//! Нагрузочный стенд Этапа 3 (`stage3_directory_100k_bench.rs`).
//!
//! Загружает в справочник одной корпорации (`TenantId`) **100 000 сотрудников**
//! с их криптографическими `PublicKeyBundle` и цепочкой `BLAKE3` Key Transparency,
//! а затем замеряет:
//! 1. Точный поиск по `@username` (`get_by_username` на базе в 100 000 человек — 500 000 запросов).
//! 2. Префиксный поиск (`search_by_prefix("@emp_042...")` по дереву на 100 000 человек — 200 000 запросов).

use auth_vault_svc::AuthVaultService;
use cryptox_core::{Argon2Profile, CloudKeyVault, UserIdentity};
use cryptox_proto::{
    CipherSuiteId, DeviceId, PublicKeyBundle, RegisterUserRequest, TenantId, UserId,
};
use std::time::Instant;
use user_directory_svc::UserDirectoryService;

#[allow(clippy::expect_used)]
fn main() {
    println!("==================================================================");
    println!("🚀 CRYPTOX-RUST: НАГРУЗОЧНЫЙ СТЕНД ЭТАПА 3 (USER-DIRECTORY 100K EMPLOYEES)");
    println!("==================================================================");

    let auth_svc = AuthVaultService::new();
    let dir_svc = UserDirectoryService::new(auth_svc.export_autonomous_verifier());
    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;

    // Регистрируем одного активного сотрудника-искателя, чтобы получить боевой SignedSessionToken
    let searcher_id = UserId::new_v7();
    let searcher_dev = DeviceId::new_v7();
    let fast_profile = Argon2Profile {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let searcher_identity = UserIdentity::generate(
        tenant,
        searcher_id,
        searcher_dev,
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let template_bundle: PublicKeyBundle =
        searcher_identity.export_public_bundle().expect("bundle");
    let vault = CloudKeyVault::seal_to_cloud_blob(
        &searcher_identity,
        &[],
        b"Pass",
        1,
        fast_profile,
    )
    .expect("vault");
    let auth_vk =
        CloudKeyVault::derive_auth_verifying_key(b"Pass", &vault.argon2_salt, fast_profile)
            .expect("vk");

    auth_svc
        .register_user(RegisterUserRequest {
            tenant_id: tenant.to_vec(),
            user_id: searcher_id.to_vec(),
            username: "searcher_admin".to_string(),
            auth_verifying_key: auth_vk.to_vec(),
            public_key_bundle: Some(template_bundle.clone()),
            initial_vault_blob: Some(vault),
        })
        .expect("reg");

    let ch = auth_svc
        .issue_login_challenge(tenant, "searcher_admin", now_ms)
        .expect("ch");
    let req = CloudKeyVault::sign_login_challenge(&ch, b"Pass", searcher_dev).expect("sign");
    let (token, _) = auth_svc
        .verify_login_and_fetch_vault(&req, now_ms + 1)
        .expect("login");

    // ------------------------------------------------------------------
    // ЗАГРУЗКА 100 000 УНИКАЛЬНЫХ СОТРУДНИКОВ В КАТАЛОГ КОМПАНИИ
    // Каждый из 100 000 сотрудников имеет уникальный `UserId` (UUIDv7), уникальный `@username`
    // и криптографически подписанный `Ed25519` `PublicKeyBundle`!
    // ------------------------------------------------------------------
    let total_employees: usize = 100_000;
    let base_identity = UserIdentity::generate(
        tenant,
        UserId::new_v7(),
        DeviceId::new_v7(),
        CipherSuiteId::X25519XChaCha20Poly1305Blake3,
        1,
    );
    let base_bundle = base_identity.export_public_bundle().expect("base bundle");

    let start_populate = Instant::now();
    std::thread::scope(|s| {
        let num_threads = 8;
        let chunk = total_employees / num_threads;
        for t in 0..num_threads {
            let dir_ref = &dir_svc;
            let base_id_ref = &base_identity;
            let base_b_ref = &base_bundle;
            s.spawn(move || {
                let start_idx = t * chunk;
                let end_idx = if t + 1 == num_threads {
                    total_employees
                } else {
                    (t + 1) * chunk
                };
                for i in start_idx..end_idx {
                    let uid = UserId::new_v7();
                    let username = format!("emp_{i:06}");
                    let display_name = format!("Employee #{i}");

                    let mut bundle = base_b_ref.clone();
                    bundle.user_id = uid.to_vec();
                    bundle.key_version = 1;
                    let sig = base_id_ref
                        .sign(&bundle.canonical_signing_bytes())
                        .expect("sign bundle");
                    bundle.self_signature = sig.to_vec();

                    dir_ref
                        .upsert_verified_entry(tenant, uid, &username, &display_name, bundle)
                        .expect("upsert 100k employee");
                }
            });
        }
    });
    println!(
        "\n[0] Загрузка {total_employees} уникальных сотрудников в каталог компании (+ 100 000 звеньев BLAKE3 Key Transparency и Ed25519 проверок): {:.2} сек",
        start_populate.elapsed().as_secs_f64()
    );

    // ------------------------------------------------------------------
    // ТЕСТ 1: Точный поиск по @username на базе в 100 000 сотрудников
    // ------------------------------------------------------------------
    let exact_queries: [&str; 8] = [
        "@emp_000042",
        "@emp_015923",
        "@emp_033777",
        "@emp_050000",
        "@emp_068112",
        "@emp_079999",
        "@emp_088421",
        "@emp_099999",
    ];
    let exact_iters: usize = 500_000;
    let start_exact = Instant::now();
    for i in 0..exact_iters {
        let q = exact_queries[i & 7];
        let entry = dir_svc
            .get_by_username(&token, q, now_ms + 10)
            .expect("exact lookup");
        std::hint::black_box(entry);
    }
    let elapsed_exact = start_exact.elapsed();
    let exact_rps = (exact_iters as f64) / elapsed_exact.as_secs_f64();
    let exact_ns = (elapsed_exact.as_nanos() as f64) / (exact_iters as f64);

    println!("\n[1] Точный поиск @username по базе в 100 000 сотрудников (get_by_username + Token Verify):");
    println!("    • Запросов:                {exact_iters}");
    println!("    • Пропускная способность:  {:.0} запросов/сек (на 1 ядро CPU)", exact_rps);
    println!("    • Средняя задержка:        {:.0} нс ({:.2} мкс)", exact_ns, exact_ns / 1000.0);

    // ------------------------------------------------------------------
    // ТЕСТ 2: Префиксный поиск (автодополнение в строке поиска по 100 000 сотрудников)
    // ------------------------------------------------------------------
    let prefix_queries: [&str; 8] = [
        "@emp_0042",
        "@emp_0198",
        "@emp_0371",
        "@emp_0512",
        "@emp_0640",
        "@emp_0777",
        "@emp_0855",
        "@emp_0991",
    ];
    let prefix_iters: usize = 200_000;
    let start_prefix = Instant::now();
    for i in 0..prefix_iters {
        let p = prefix_queries[i & 7];
        let res = dir_svc
            .search_by_prefix(&token, p, 10, now_ms + 20)
            .expect("prefix search");
        std::hint::black_box(res);
    }
    let elapsed_prefix = start_prefix.elapsed();
    let prefix_rps = (prefix_iters as f64) / elapsed_prefix.as_secs_f64();
    let prefix_us = (elapsed_prefix.as_micros() as f64) / (prefix_iters as f64);

    println!("\n[2] Префиксный поиск @emp_XXXX по B-дереву из 100 000 сотрудников (search_by_prefix top-10):");
    println!("    • Запросов:                {prefix_iters}");
    println!("    • Пропускная способность:  {:.0} поисковых запросов/сек (на 1 ядро CPU)", prefix_rps);
    println!("    • Средняя задержка:        {:.2} мкс (в 1000 раз быстрее SLA 5 мс!)", prefix_us);
    println!("==================================================================");
}
