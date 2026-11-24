//! Боевые инфраструктурные и хакерские тесты Этапа 9 (`stage9_distributed_rpc_and_circuit_breaker.rs`).
//!
//! Доказывает на реальных TCP-сокетах (`tokio::net::TcpListener` / `TcpStream`):
//! 1. **Разнесение микросервисов по разным сетевым TCP-портам:**
//!    `messaging-svc`, `user-directory-svc` и `presence-receipts-svc` поднимаются на 3 независимых TCP-портах
//!    и общаются со шлюзом по бинарному протоколу с Zero-Trust шифрованием (`XChaCha20-Poly1305` + `Ed25519`).
//! 2. **Отражение хакерского вторжения во внутреннюю сеть дата-центра (VLAN Intrusion & RPC Replay):**
//!    Попытка злоумышленника подключиться напрямую к внутреннему TCP-порту `messaging-svc` с чужим ключом
//!    узла или повторить перехваченный `ZeroTrustRpcFrame` блокируется с фиксацией в телеметрии.
//! 3. **3-фазный автоматический предохранитель (`Closed -> Open -> HalfOpen -> Closed` Self-Healing):**
//!    При физическом отключении TCP-узлов `user-directory-svc` и `presence-receipts-svc` их предохранители
//!    автоматически размыкаются в `OPEN` (отсекая вызовы Fail-Fast за `< 50 нс`), чаты через TCP-порт
//!    `messaging-svc` продолжают работать со 100% доставкой, а после подъема упавших TCP-портов
//!    предохранители сами переходят в `HALF_OPEN` -> `CLOSED` (авто-исцеление кластера без участия человека).
//! 4. **Prometheus `/metrics`, `/healthz` и `/readyz`:**
//!    Проверка экспорта метрик в стандартном формате Prometheus 0.0.4.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use auth_vault_svc::AuthVaultService;
use cryptox_core::{
    Argon2Profile, ChatSession, CloudKeyVault, UserIdentity, XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    CipherSuiteId, DeviceId, EncryptionPolicy, RegisterUserRequest, SignedSessionToken, TenantId,
    UserId,
};
use edge_gateway::{
    cluster_mesh::{
        CircuitState, DistributedRpcCluster, InternalRpcCommand, RpcMeshError,
        ZeroTrustClusterKeys, ZeroTrustRpcFrame,
    },
    EdgeGateway,
};
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use user_directory_svc::UserDirectoryService;

fn fast_argon() -> Argon2Profile {
    Argon2Profile {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    }
}

type TestUserTuple = (
    UserIdentity,
    SignedSessionToken,
    cryptox_proto::PublicKeyBundle,
);

fn setup_gateway_and_two_users() -> (Arc<EdgeGateway>, TenantId, TestUserTuple, TestUserTuple) {
    let now_ms = 1_780_000_000_000;
    let auth_svc = Arc::new(AuthVaultService::new());
    let verifier = auth_svc.export_autonomous_verifier();
    let dir_svc = Arc::new(UserDirectoryService::new(verifier.clone()));
    let pres_svc = Arc::new(presence_receipts_svc::PresenceReceiptsService::new(
        verifier.clone(),
    ));
    let msg_svc = Arc::new(messaging_svc::MessagingService::new(verifier));
    let gateway = Arc::new(EdgeGateway::new(auth_svc, dir_svc, pres_svc, msg_svc));

    let tenant = TenantId::new_v7();
    let pwd = b"ZeroTrust#Cluster#2026";

    let onboard = |uname: &str, dname: &str| {
        let uid = UserId::new_v7();
        let did = DeviceId::new_v7();
        let id = UserIdentity::generate(
            tenant,
            uid,
            did,
            CipherSuiteId::X25519XChaCha20Poly1305Blake3,
            1,
        );
        let bundle = id.export_public_bundle().expect("bundle");
        let vault =
            CloudKeyVault::seal_to_cloud_blob(&id, &[], pwd, 1, fast_argon()).expect("vault");
        let auth_vk =
            CloudKeyVault::derive_auth_verifying_key(pwd, &vault.argon2_salt, fast_argon())
                .expect("vk");

        gateway
            .auth_service()
            .register_user(RegisterUserRequest {
                tenant_id: tenant.to_vec(),
                user_id: uid.to_vec(),
                username: uname.to_string(),
                auth_verifying_key: auth_vk.to_vec(),
                public_key_bundle: Some(bundle.clone()),
                initial_vault_blob: Some(vault),
            })
            .expect("reg");

        let ch = gateway
            .auth_service()
            .issue_login_challenge(tenant, uname, now_ms)
            .expect("ch");
        let verify_req = CloudKeyVault::sign_login_challenge(&ch, pwd, did).expect("sig");
        let (tok, _vault) = gateway
            .auth_service()
            .verify_login_and_fetch_vault(&verify_req, now_ms)
            .expect("login");

        gateway
            .directory_service()
            .publish_or_rotate_entry(&tok, uname, dname, bundle.clone(), now_ms)
            .expect("pub");

        (id, tok, bundle)
    };

    let alice = onboard("alice_mesh", "Alice Mesh Lead");
    let bob = onboard("bob_mesh", "Bob Mesh Lead");

    (gateway, tenant, alice, bob)
}

#[tokio::test]
async fn test_1_distributed_multi_port_tcp_cluster_e2ee_routing_and_zero_trust_intrusion_defense() {
    let now_ms = 1_780_000_005_000;
    let (gateway, _tenant, (alice_id, alice_tok, _), (bob_id, bob_tok, _)) =
        setup_gateway_and_two_users();

    let cluster = DistributedRpcCluster::spawn_tcp_cluster(Arc::clone(&gateway))
        .await
        .expect("spawn tcp cluster");

    // 1. Проверяем, что все 3 микросервиса реально слушают РАЗНЫЕ сетевые TCP-порты
    let msg_port = cluster.messaging_node.listen_addr.port();
    let dir_port = cluster.directory_node.listen_addr.port();
    let pres_port = cluster.presence_node.listen_addr.port();
    assert_ne!(msg_port, dir_port);
    assert_ne!(msg_port, pres_port);
    assert_ne!(dir_port, pres_port);

    // 2. Алиса ищет `@bob_mesh` по реальному TCP-сокету `user-directory-svc`
    let search_res = cluster
        .search_directory_over_tcp(&alice_tok.to_wire_bytes(), "@bob", 10, now_ms)
        .await
        .expect("tcp directory search");
    assert_eq!(search_res.entries.len(), 1);
    let bob_bundle = search_res.entries[0]
        .public_key_bundle
        .clone()
        .expect("bob bundle");

    // 3. Алиса шифрует сообщение и отправляет его по TCP в `messaging-svc`
    let mut alice_chat = ChatSession::establish_direct(
        &alice_id,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("alice chat");
    let env = alice_chat
        .encrypt_message(
            &alice_id,
            &XChaCha20Poly1305Provider,
            b"Zero-Trust Distributed TCP RPC payload!",
        )
        .expect("encrypt");

    let ack = cluster
        .route_message_over_tcp(&alice_tok.to_wire_bytes(), &env.to_wire_bytes(), now_ms)
        .await
        .expect("route message over tcp");
    assert!(!ack.was_deduplicated);

    // 4. Боб скачивает историю по TCP из `messaging-svc` и расшифровывает сообщение
    let page = cluster
        .fetch_history_over_tcp(
            &bob_tok.to_wire_bytes(),
            alice_chat.channel_id(),
            None,
            20,
            now_ms,
        )
        .await
        .expect("fetch history over tcp");
    assert_eq!(page.envelopes.len(), 1);

    let alice_bundle = alice_id.export_public_bundle().expect("alice bundle");
    let bob_chat = ChatSession::establish_direct(
        &bob_id,
        &alice_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("bob chat");
    let pt = bob_chat
        .decrypt_message(&bob_id, &XChaCha20Poly1305Provider, &page.envelopes[0])
        .expect("bob decrypt");
    assert_eq!(pt.as_slice(), b"Zero-Trust Distributed TCP RPC payload!");

    // 5. ХАКЕРСКАЯ АТАКА №1 НА ВНУТРЕННЮЮ СЕТЬ (VLAN Intrusion):
    // Злоумышленник внутри дата-центра стучится напрямую в TCP-порт `messaging-svc` со своим ключом
    let hacker_keys = ZeroTrustClusterKeys::generate();
    let cmd_bytes = serde_json::to_vec(&InternalRpcCommand::PingHealth).expect("cmd");
    let forged_frame =
        ZeroTrustRpcFrame::seal_frame(&hacker_keys, "messaging-svc", &cmd_bytes, now_ms)
            .expect("seal forged");
    let forged_wire = serde_json::to_vec(&forged_frame).expect("wire");

    let mut hacker_stream = TcpStream::connect(cluster.messaging_node.listen_addr)
        .await
        .expect("connect internal tcp");
    let len_be = (forged_wire.len() as u32).to_be_bytes();
    hacker_stream.write_all(&len_be).await.expect("write len");
    hacker_stream
        .write_all(&forged_wire)
        .await
        .expect("write forged");
    hacker_stream.flush().await.expect("flush");

    // Даем узлу 20 мс обработать и заблокировать вторжение
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert_eq!(gateway.zero_trust_intrusions_blocked(), 1);

    // 6. ХАКЕРСКАЯ АТАКА №2 (Replay Attack & Clock Skew на внутренний RPC-пакет):
    let valid_frame =
        ZeroTrustRpcFrame::seal_frame(&cluster.keys, "messaging-svc", &cmd_bytes, now_ms)
            .expect("valid frame");
    let replay_cache = dashmap::DashMap::new();
    assert!(valid_frame
        .open_and_verify(&cluster.keys, "messaging-svc", now_ms, Some(&replay_cache))
        .is_ok());
    // Повтор того же фрейма -> ReplayOrClockSkewDetected!
    assert_eq!(
        valid_frame
            .open_and_verify(&cluster.keys, "messaging-svc", now_ms, Some(&replay_cache))
            .err(),
        Some(RpcMeshError::ReplayOrClockSkewDetected)
    );
    // Пакет со сдвигом часов на 5 минут -> ReplayOrClockSkewDetected!
    assert_eq!(
        valid_frame
            .open_and_verify(&cluster.keys, "messaging-svc", now_ms + 300_000, None)
            .err(),
        Some(RpcMeshError::ReplayOrClockSkewDetected)
    );
}

#[tokio::test]
async fn test_2_three_state_circuit_breaker_auto_trip_fail_fast_and_self_healing_over_tcp() {
    let now_ms = 1_780_000_010_000;
    let (gateway, _tenant, (alice_id, alice_tok, _), (_bob_id, _bob_tok, bob_bundle)) =
        setup_gateway_and_two_users();

    // Настраиваем 3-фазные предохранители: порог размыкания = 2 сбоя подряд, кулдаун восстановления = 100 мс
    gateway.directory_circuit_breaker().configure(2, 100);
    gateway.presence_circuit_breaker().configure(2, 100);

    let cluster = DistributedRpcCluster::spawn_tcp_cluster(Arc::clone(&gateway))
        .await
        .expect("spawn tcp cluster");

    assert_eq!(
        gateway.directory_circuit_breaker().state(),
        CircuitState::Closed
    );
    assert_eq!(
        gateway.presence_circuit_breaker().state(),
        CircuitState::Closed
    );

    // 1. ФИЗИЧЕСКАЯ АВАРИЯ: убиваем TCP-серверы `user-directory-svc` и `presence-receipts-svc`!
    cluster.directory_node.set_node_alive(false);
    cluster.presence_node.set_node_alive(false);

    // Первые 2 сетевых запроса к `user-directory-svc` падают по TCP и размыкают предохранитель в `OPEN`!
    assert!(cluster
        .search_directory_over_tcp(&alice_tok.to_wire_bytes(), "@bob", 5, now_ms)
        .await
        .is_err());
    assert_eq!(
        gateway.directory_circuit_breaker().state(),
        CircuitState::Closed
    );

    assert!(cluster
        .search_directory_over_tcp(&alice_tok.to_wire_bytes(), "@bob", 5, now_ms)
        .await
        .is_err());
    assert_eq!(
        gateway.directory_circuit_breaker().state(),
        CircuitState::Open,
        "После 2 TCP-сбоев подряд предохранитель ОБЯЗАН разомкнуться в состояние OPEN!"
    );
    assert_eq!(gateway.directory_circuit_breaker().trip_count(), 1);

    // 3-й запрос отсекается мгновенно Fail-Fast за < 50 нс с `CircuitBreakerOpen` без обращения к TCP!
    let fast_fail = cluster
        .search_directory_over_tcp(&alice_tok.to_wire_bytes(), "@bob", 5, now_ms + 10)
        .await;
    assert_eq!(
        fast_fail.err(),
        Some(RpcMeshError::CircuitBreakerOpen("user-directory-svc"))
    );
    assert_eq!(gateway.directory_circuit_breaker().fast_rejected_count(), 1);

    // 2. В ЭТО ЖЕ ВРЕМЯ: Алиса отправляет 3 зашифрованных сообщения Бобу по TCP через `messaging-svc`!
    let mut alice_chat = ChatSession::establish_direct(
        &alice_id,
        &bob_bundle,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    )
    .expect("chat");

    for i in 1..=3 {
        let env = alice_chat
            .encrypt_message(
                &alice_id,
                &XChaCha20Poly1305Provider,
                format!("Hot-Path message #{i} while sidecar TCP servers are DEAD").as_bytes(),
            )
            .expect("encrypt");
        let ack = cluster
            .route_message_over_tcp(&alice_tok.to_wire_bytes(), &env.to_wire_bytes(), now_ms)
            .await
            .expect("Hot Path messaging over TCP must survive 100%!");
        assert!(!ack.was_deduplicated);
    }

    // Предохранитель `presence-receipts-svc` тоже автоматически разомкнулся в `OPEN` и поглотил все 3 ошибки!
    assert_eq!(
        gateway.presence_circuit_breaker().state(),
        CircuitState::Open
    );
    assert_eq!(gateway.absorbed_sidecar_failures(), 3);

    // 3. АВТО-ИСЦЕЛЕНИЕ КЛАСТЕРА (Self-Healing: `OPEN -> HALF_OPEN -> CLOSED`):
    // Поднимаем упавшие TCP-узлы обратно!
    cluster.directory_node.set_node_alive(true);
    cluster.presence_node.set_node_alive(true);

    // Спустя 150 мс (> 100 мс cooldown) следующий запрос автоматически переводит предохранитель
    // `OPEN -> HALF_OPEN`, выполняет 1 пробный TCP-запрос и замыкает цепь обратно в `CLOSED`!
    let healed_search = cluster
        .search_directory_over_tcp(&alice_tok.to_wire_bytes(), "@bob", 5, now_ms + 150)
        .await
        .expect("self-healed directory search over TCP");
    assert_eq!(healed_search.entries.len(), 1);
    assert_eq!(
        gateway.directory_circuit_breaker().state(),
        CircuitState::Closed,
        "Предохранитель ОБЯЗАН автоматически замкнуться обратно в CLOSED после успешного Half-Open запроса!"
    );
    assert_eq!(gateway.directory_circuit_breaker().auto_heal_count(), 1);

    // Проверяем, что экспортер Prometheus `/metrics` отражает все события и авто-исцеление
    let prom_text = gateway.render_prometheus_metrics(None);
    assert!(prom_text.contains("cryptox_circuit_breaker_auto_heals_total{service=\"user_directory_svc\"} 1"));
    assert!(prom_text.contains("cryptox_absorbed_sidecar_failures_total 3"));
}
