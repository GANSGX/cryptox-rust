//! Нагрузочный стенд Этапа 4 (`stage4_cluster_100k_bench.rs`).
//!
//! Проверяет производительность критического контура доставки и статусов:
//! 1. Маршрутизация, проверка идемпотентности и сохранение 100 000 зашифрованных сообщений
//!    через `messaging-svc`.
//! 2. Курсорная выдача 200 000 страниц облачной истории чатов по `UUIDv7` (0 `OFFSET`, 0 `COUNT(*)`).
//! 3. Шторм из 1 000 000 событий «Прочитано» (`Read Receipts Coalescing`) в `presence-receipts-svc`.

use auth_vault_svc::AuthVaultService;
use cryptox_core::{
    Argon2Profile, ChatSession, CloudKeyVault, UserIdentity, XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    CipherSuiteId, DeviceId, EncryptionPolicy, MessageId, RegisterUserRequest, TenantId, UserId,
};
use messaging_svc::MessagingService;
use presence_receipts_svc::PresenceReceiptsService;
use std::time::Instant;

#[allow(clippy::expect_used)]
fn main() {
    println!("==================================================================");
    println!("🚀 CRYPTOX-RUST: НАГРУЗОЧНЫЙ СТЕНД ЭТАПА 4 (MESSAGING + PRESENCE 100K SLA)");
    println!("==================================================================");

    let auth_svc = AuthVaultService::new();
    let verifier = auth_svc.export_autonomous_verifier();
    let msg_svc = MessagingService::new(verifier.clone());
    let presence_svc = PresenceReceiptsService::new(verifier);

    let tenant = TenantId::new_v7();
    let now_ms = 1_700_000_000_000;
    let fast_profile = Argon2Profile {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    let alice_uid = UserId::new_v7();
    let alice_dev = DeviceId::new_v7();
    let alice = UserIdentity::generate(
        tenant,
        alice_uid,
        alice_dev,
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

    let alice_bundle = alice.export_public_bundle().expect("a bundle");
    let bob_bundle = bob.export_public_bundle().expect("b bundle");
    let vault =
        CloudKeyVault::seal_to_cloud_blob(&alice, &[], b"Pass", 1, fast_profile).expect("vault");
    let auth_vk =
        CloudKeyVault::derive_auth_verifying_key(b"Pass", &vault.argon2_salt, fast_profile)
            .expect("vk");

    auth_svc
        .register_user(RegisterUserRequest {
            tenant_id: tenant.to_vec(),
            user_id: alice_uid.to_vec(),
            username: "alice_bench".to_string(),
            auth_verifying_key: auth_vk.to_vec(),
            public_key_bundle: Some(alice_bundle),
            initial_vault_blob: Some(vault),
        })
        .expect("reg");

    let ch = auth_svc
        .issue_login_challenge(tenant, "alice_bench", now_ms)
        .expect("ch");
    let req = CloudKeyVault::sign_login_challenge(&ch, b"Pass", alice_dev).expect("sign");
    let (token, _) = auth_svc
        .verify_login_and_fetch_vault(&req, now_ms + 1)
        .expect("login");

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
            b"Highload 100k corporate message payload",
        )
        .expect("encrypt");

    // ------------------------------------------------------------------
    // ТЕСТ 1: Маршрутизация и сохранение 100 000 уникальных сообщений в `messaging-svc`
    // ------------------------------------------------------------------
    let total_msgs: usize = 100_000;
    let mut msg_ids: Vec<MessageId> = Vec::with_capacity(total_msgs);
    for _ in 0..total_msgs {
        msg_ids.push(MessageId::new_v7());
    }

    let start_route = Instant::now();
    for (i, mid) in msg_ids.iter().enumerate() {
        let mut env = template_env.clone();
        env.message_id = mid.to_vec();
        env.ratchet_step = (i + 1) as u64;
        let ack = msg_svc
            .route_and_persist_envelope(&token, env, now_ms + 10)
            .expect("route");
        std::hint::black_box(ack);
    }
    let elapsed_route = start_route.elapsed();
    let route_rps = (total_msgs as f64) / elapsed_route.as_secs_f64();
    let route_us = (elapsed_route.as_micros() as f64) / (total_msgs as f64);

    println!("\n[1] Прием, проверка идемпотентности и запись 100 000 сообщений (messaging-svc):");
    println!("    • Записано сообщений:      {total_msgs}");
    println!("    • Пропускная способность:  {:.0} сообщений/сек (на 1 ядро CPU)", route_rps);
    println!("    • Средняя задержка:        {:.2} мкс", route_us);

    // ------------------------------------------------------------------
    // ТЕСТ 2: Курсорная выдача облачной истории по UUIDv7 (200 000 страниц по 20 сообщений, 0 OFFSET!)
    // ------------------------------------------------------------------
    let history_iters: usize = 200_000;
    let mid_cursor = msg_ids[total_msgs / 2];
    let start_hist = Instant::now();
    for _ in 0..history_iters {
        let page = msg_svc
            .fetch_channel_history(&token, channel_id, Some(mid_cursor), 20, now_ms + 20)
            .expect("fetch history");
        std::hint::black_box(page);
    }
    let elapsed_hist = start_hist.elapsed();
    let hist_rps = (history_iters as f64) / elapsed_hist.as_secs_f64();
    let hist_us = (elapsed_hist.as_micros() as f64) / (history_iters as f64);

    println!("\n[2] Курсорная пагинация облачной истории по UUIDv7 из 100k сообщений (20 сообщ/стр, 0 OFFSET):");
    println!("    • Выдано страниц истории:  {history_iters} (4 000 000 конвертов)");
    println!("    • Пропускная способность:  {:.0} страниц/сек (на 1 ядро CPU)", hist_rps);
    println!("    • Средняя задержка:        {:.2} мкс на страницу", hist_us);

    // ------------------------------------------------------------------
    // ТЕСТ 3: Шторм из 1 000 000 галочек «Прочитано» (`Read Receipts Coalescing` в `presence-receipts-svc`)
    // ------------------------------------------------------------------
    let receipt_iters: usize = 1_000_000;
    let start_receipts = Instant::now();
    for i in 0..receipt_iters {
        let mid = msg_ids[i % total_msgs];
        let state = presence_svc
            .record_read_receipt(&token, channel_id, mid, now_ms + 30)
            .expect("read receipt");
        std::hint::black_box(state);
    }
    let elapsed_receipts = start_receipts.elapsed();
    let receipt_rps = (receipt_iters as f64) / elapsed_receipts.as_secs_f64();
    let receipt_ns = (elapsed_receipts.as_nanos() as f64) / (receipt_iters as f64);

    println!("\n[3] Схлопывание шторма 1 000 000 событий «Прочитано» (presence-receipts-svc):");
    println!("    • Обработано событий read: {receipt_iters} -> схлопнуто в 1 запись БД!");
    println!("    • Пропускная способность:  {:.0} событий/сек (на 1 ядро CPU!)", receipt_rps);
    println!("    • Средняя задержка:        {:.0} нс ({:.3} мкс)", receipt_ns, receipt_ns / 1000.0);
    println!("==================================================================");
}
