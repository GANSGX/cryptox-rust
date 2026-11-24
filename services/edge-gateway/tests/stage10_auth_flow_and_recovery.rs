//! Боевой тест Этапа 10: реальный флоу `/auth` (регистрация с паролем, вход, неверный пароль,
//! восстановление по Ключу Восстановления с перешифрованием сейфа) по живому TCP-сокету.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use auth_vault_svc::AuthVaultService;
use edge_gateway::{
    http_server::{build_app_router, LivePrototypeState},
    EdgeGateway,
};
use messaging_svc::MessagingService;
use presence_receipts_svc::PresenceReceiptsService;
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use user_directory_svc::UserDirectoryService;

async fn http(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = match body {
        Some(b) => format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        ),
        None => format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    };
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    String::from_utf8_lossy(&buf).to_string()
}

fn extract_json_field(resp: &str, field: &str) -> String {
    let needle = format!("\"{field}\":\"");
    let start = resp.find(&needle).expect("field present") + needle.len();
    let rest = &resp[start..];
    rest[..rest.find('"').expect("closing quote")].to_string()
}

#[tokio::test]
async fn test_auth_register_login_wrong_password_and_recovery_key_reset() {
    let auth_svc = Arc::new(AuthVaultService::new());
    let verifier = auth_svc.export_autonomous_verifier();
    let dir_svc = Arc::new(UserDirectoryService::new(verifier.clone()));
    let presence_svc = Arc::new(PresenceReceiptsService::new(verifier.clone()));
    let msg_svc = Arc::new(MessagingService::new(verifier));
    let gateway = Arc::new(EdgeGateway::new(auth_svc, dir_svc, presence_svc, msg_svc));
    let state = LivePrototypeState::new_with_seeded_company(gateway);
    let app = build_app_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // 1. Регистрация с собственным паролем -> выдан Ключ Восстановления формата CX-XXXX-XXXX-XXXX-XXXX
    let reg = http(
        addr,
        "POST",
        "/api/register",
        Some(r#"{"username":"@vadim","display_name":"Вадим","password":"OldPass#2026"}"#),
    )
    .await;
    assert!(reg.contains("201 Created"), "регистрация: {reg}");
    let recovery_key = extract_json_field(&reg, "recovery_key");
    assert!(recovery_key.starts_with("CX-"));
    assert_eq!(recovery_key.len(), 22);

    // 2. Вход с верным паролем проходит
    let ok = http(
        addr,
        "POST",
        "/api/auth/login",
        Some(r#"{"username":"vadim","password":"OldPass#2026"}"#),
    )
    .await;
    assert!(ok.contains("200 OK"), "вход: {ok}");

    // 3. Вход с неверным паролем отклоняется (сервер не пускает без знания пароля)
    let bad = http(
        addr,
        "POST",
        "/api/auth/login",
        Some(r#"{"username":"vadim","password":"WrongPass"}"#),
    )
    .await;
    assert!(bad.contains("401"), "неверный пароль обязан давать 401: {bad}");

    // 4. Восстановление с НЕВЕРНЫМ ключом отклоняется
    let bad_rec = http(
        addr,
        "POST",
        "/api/auth/recover-password",
        Some(r#"{"username":"vadim","recovery_key":"CX-AAAA-BBBB-CCCC-DDDD","new_password":"NewPass#2026"}"#),
    )
    .await;
    assert!(bad_rec.contains("401"), "чужой ключ обязан давать 401: {bad_rec}");

    // 5. Восстановление с верным ключом перешифровывает сейф под новый пароль
    let rec_body = format!(
        r#"{{"username":"vadim","recovery_key":"{recovery_key}","new_password":"NewPass#2026"}}"#
    );
    let rec = http(addr, "POST", "/api/auth/recover-password", Some(&rec_body)).await;
    assert!(rec.contains("200 OK"), "восстановление: {rec}");

    // 6. Старый пароль больше не работает, новый работает
    let old_now_bad = http(
        addr,
        "POST",
        "/api/auth/login",
        Some(r#"{"username":"vadim","password":"OldPass#2026"}"#),
    )
    .await;
    assert!(old_now_bad.contains("401"), "старый пароль обязан быть отозван");

    let new_ok = http(
        addr,
        "POST",
        "/api/auth/login",
        Some(r#"{"username":"vadim","password":"NewPass#2026"}"#),
    )
    .await;
    assert!(new_ok.contains("200 OK"), "новый пароль обязан работать: {new_ok}");
}
