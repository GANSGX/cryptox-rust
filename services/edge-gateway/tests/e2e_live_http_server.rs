//! Сквозной сетевой E2E-тест Этапов 5–7 (`e2e_live_http_server.rs`).
//!
//! Поднимает реальный `TcpListener` с роутером `Axum 0.8` (`build_app_router`)
//! и зашифрованным дисковым движком `cryptox-storage` (`redb` + `AES-256-GCM` + `Blind Index`)
//! и по живому TCP-сокету проверяет:
//! 1. Загрузку продуктового веб-интерфейса (`GET /`);
//! 2. Живое WebSocket-рукопожатие (`GET /ws` -> `HTTP/1.1 101 Switching Protocols`);
//! 3. Поиск сотрудника по `@username` (`GET /api/search?caller=alice_ceo&q=@bo`);
//! 4. Отправку зашифрованного сообщения (`POST /api/chat/send`), запись на SSD и статус прочтения `✓✓` (`POST /api/chat/mark-read`);
//! 5. Облачную синхронизацию на Новом Ноутбуке #2 (`POST /api/cloud-sync-new-device`);
//! 6. Отключение всех 3 второстепенных сервисов (`POST /api/chaos/toggle`) и успешную отправку сообщения
//!    в открытый чат во время аварии.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use auth_vault_svc::AuthVaultService;
use edge_gateway::{
    http_server::{build_app_router, LivePrototypeState},
    EdgeGateway,
};
use messaging_svc::MessagingService;
use presence_receipts_svc::PresenceReceiptsService;
use std::{net::SocketAddr, sync::Arc};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use user_directory_svc::UserDirectoryService;

async fn raw_http_request(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect tcp");

    let req_str = match body {
        Some(b) => format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        ),
        None => format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        ),
    };

    stream
        .write_all(req_str.as_bytes())
        .await
        .expect("write http");

    let mut resp_buf = Vec::new();
    stream
        .read_to_end(&mut resp_buf)
        .await
        .expect("read http");

    String::from_utf8_lossy(&resp_buf).to_string()
}

#[tokio::test]
async fn test_live_axum_server_e2e_ws_disk_search_chat_cloud_sync_and_chaos() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("e2e_enterprise.redb");

    let auth_svc = Arc::new(AuthVaultService::new());
    let verifier = auth_svc.export_autonomous_verifier();
    let dir_svc = Arc::new(UserDirectoryService::new(verifier.clone()));
    let presence_svc = Arc::new(PresenceReceiptsService::new(verifier.clone()));
    let msg_svc = Arc::new(MessagingService::new(verifier));

    let gateway = Arc::new(EdgeGateway::new(auth_svc, dir_svc, presence_svc, msg_svc));
    let state =
        LivePrototypeState::new_with_disk_storage(gateway, &db_path).expect("init disk storage");
    let app = build_app_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // 1. Проверяем отдачу нового продуктового React + Protobuf SPA (`/`, `/auth`) и NOC Status Dashboard (`/status`)
    let html_resp = raw_http_request(addr, "GET", "/", None).await;
    assert!(html_resp.contains("HTTP/1.1 200 OK"));
    assert!(html_resp.contains("Вход в CryptoX"));

    let status_html = raw_http_request(addr, "GET", "/status", None).await;
    assert!(status_html.contains("HTTP/1.1 200 OK"));
    assert!(status_html.contains("Статус сервисов"));

    let auth_html = raw_http_request(addr, "GET", "/auth", None).await;
    assert!(auth_html.contains("HTTP/1.1 200 OK"));
    assert!(auth_html.contains("Вход и регистрация"));

    let status_json = raw_http_request(addr, "GET", "/api/status/overview", None).await;
    assert!(status_json.contains("HTTP/1.1 200 OK"));
    assert!(status_json.contains("\"overall_status\":\"OPERATIONAL\""));

    let metrics_resp = raw_http_request(addr, "GET", "/metrics", None).await;
    assert!(metrics_resp.contains("HTTP/1.1 200 OK"));
    assert!(metrics_resp.contains("cryptox_circuit_breaker_state"));

    // 2. Проверяем живое WebSocket-рукопожатие (`GET /ws` -> `101 Switching Protocols`)
    {
        let mut ws_stream = tokio::net::TcpStream::connect(addr).await.expect("ws tcp");
        let ws_handshake = concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: 127.0.0.1\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n\r\n"
        );
        ws_stream
            .write_all(ws_handshake.as_bytes())
            .await
            .expect("write ws handshake");
        let mut buf = [0u8; 256];
        let n = ws_stream.read(&mut buf).await.expect("read ws response");
        let header_str = String::from_utf8_lossy(&buf[..n]);
        assert!(
            header_str.contains("101 Switching Protocols"),
            "Ожидался ответ 101 Switching Protocols, получено: {header_str}"
        );
    }

    // 3. Поиск `@bo` от лица `alice_ceo` (заодно прогревает слепой индекс в `cryptox-storage`)
    let search_resp =
        raw_http_request(addr, "GET", "/api/search?caller=alice_ceo&q=%40bo", None).await;
    assert!(search_resp.contains("HTTP/1.1 200 OK"));
    assert!(search_resp.contains("bob_architect"));

    // 4. Отправка первого зашифрованного сообщения от `alice_ceo` к `bob_architect`
    let send_1 = raw_http_request(
        addr,
        "POST",
        "/api/chat/send",
        Some(r#"{"sender_username":"alice_ceo","recipient_username":"bob_architect","plaintext":"First E2EE message persisted to redb SSD!"}"#),
    )
    .await;
    assert!(send_1.contains("HTTP/1.1 200 OK"));

    // 5. Боб открывает чат и помечает сообщение как прочитанное (`POST /api/chat/mark-read`) -> `✓✓`
    let mark_read = raw_http_request(
        addr,
        "POST",
        "/api/chat/mark-read",
        Some(r#"{"reader_username":"bob_architect","peer_username":"alice_ceo"}"#),
    )
    .await;
    assert!(mark_read.contains("HTTP/1.1 200 OK"));

    // 6. Облачная синхронизация на Новом Ноутбуке #2 для `alice_ceo`
    let sync_resp = raw_http_request(
        addr,
        "POST",
        "/api/cloud-sync-new-device",
        Some(r#"{"username":"alice_ceo"}"#),
    )
    .await;
    assert!(sync_resp.contains("HTTP/1.1 200 OK"));
    assert!(sync_resp.contains(r#""device_number":2"#));

    // 7. ТРОЙНОЙ CHAOS ЧЕРЕЗ HTTP API: выключаем `auth`, `directory` и `presence`
    for svc in ["auth", "directory", "presence"] {
        let chaos = raw_http_request(
            addr,
            "POST",
            "/api/chaos/toggle",
            Some(&format!(r#"{{"service":"{svc}","outage":true}}"#)),
        )
        .await;
        assert!(chaos.contains("HTTP/1.1 200 OK"));
    }

    // 8. Во время падения всех 3 сервисов Ноутбук #2 Алисы отправляет второе сообщение в открытый чат!
    let send_2 = raw_http_request(
        addr,
        "POST",
        "/api/chat/send",
        Some(r#"{"sender_username":"alice_ceo","recipient_username":"bob_architect","plaintext":"Second message while 3 services are DOWN!"}"#),
    )
    .await;
    assert!(send_2.contains("HTTP/1.1 200 OK"));

    // 9. Проверяем историю чата от лица Алисы: первое сообщение имеет `"is_read_by_peer":true` (галочки `✓✓`)!
    let hist_resp = raw_http_request(
        addr,
        "GET",
        "/api/chat/history?caller=alice_ceo&peer=bob_architect",
        None,
    )
    .await;
    assert!(hist_resp.contains("HTTP/1.1 200 OK"));
    assert!(hist_resp.contains("First E2EE message persisted to redb SSD!"));
    assert!(hist_resp.contains("Second message while 3 services are DOWN!"));
    assert!(hist_resp.contains(r#""is_read_by_peer":true"#));

    // 10. Проверяем метрики зашифрованного диска в `/api/state`
    let state_resp = raw_http_request(addr, "GET", "/api/state", None).await;
    assert!(state_resp.contains("HTTP/1.1 200 OK"));
    assert!(!state_resp.contains(r#""storage_records_written":0"#));

    // 11. Проверяем 100% бинарный Protobuf RPC шлюза (`POST /rpc/v1/client-wire`, `application/x-protobuf`)
    {
        use cryptox_proto::{ClientWireOp, ClientWireRequestProto, ClientWireResponseProto};
        use prost::Message;

        let proto_req = ClientWireRequestProto {
            op: ClientWireOp::SendChatMessage as i32,
            caller_username: "alice_ceo".to_string(),
            peer_username: "bob_architect".to_string(),
            plaintext_message: "Binary Protobuf Client-to-Gateway Wire Packet!".to_string(),
            ..ClientWireRequestProto::default()
        };
        let req_bytes = proto_req.encode_to_vec();

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect proto tcp");
        let header = format!(
            "POST /rpc/v1/client-wire HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            req_bytes.len()
        );
        stream.write_all(header.as_bytes()).await.expect("write header");
        stream.write_all(&req_bytes).await.expect("write proto body");

        let mut resp_buf = Vec::new();
        stream.read_to_end(&mut resp_buf).await.expect("read proto resp");

        let split_pos = resp_buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("http header separator")
            + 4;
        let headers_str = String::from_utf8_lossy(&resp_buf[..split_pos]);
        assert!(headers_str.contains("HTTP/1.1 200 OK"));
        assert!(headers_str.to_lowercase().contains("content-type: application/x-protobuf"));

        let proto_resp =
            ClientWireResponseProto::decode(&resp_buf[split_pos..]).expect("decode binary protobuf");
        assert!(proto_resp.ok, "Protobuf response must be ok");
        assert!(proto_resp.wire_bytes_len > 100, "Must return encrypted envelope wire length");
    }
}
