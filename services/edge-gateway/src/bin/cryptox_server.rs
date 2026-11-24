//! Исполняемый бинарный сервер `cryptox_server` (`Axum 0.8` HTTP + WebSocket + Зашифрованный Диск `cryptox-storage`).
//!
//! Запускает на `http://127.0.0.1:8080` весь модульный кластер (`edge-gateway`, `auth-vault-svc`,
//! `user-directory-svc`, `presence-receipts-svc`, `messaging-svc`), зашифрованный дисковый движок
//! `cryptox_enterprise.redb` и продуктовый веб-интерфейс мессенджера.

use auth_vault_svc::AuthVaultService;
use edge_gateway::{
    http_server::{build_app_router, LivePrototypeState},
    EdgeGateway,
};
use messaging_svc::MessagingService;
use presence_receipts_svc::PresenceReceiptsService;
use std::sync::Arc;
use user_directory_svc::UserDirectoryService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_svc = Arc::new(AuthVaultService::new());
    let verifier = auth_svc.export_autonomous_verifier();
    let dir_svc = Arc::new(UserDirectoryService::new(verifier.clone()));
    let presence_svc = Arc::new(PresenceReceiptsService::new(verifier.clone()));
    let msg_svc = Arc::new(MessagingService::new(verifier));

    let gateway = Arc::new(EdgeGateway::new(auth_svc, dir_svc, presence_svc, msg_svc));
    let state =
        LivePrototypeState::new_with_disk_storage(gateway, "cryptox_enterprise.redb")?;
    let app = build_app_router(state);

    let addr = "127.0.0.1:8080";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("==================================================================");
    println!("🛡️ CRYPTOX-RUST 2026: СЕРВЕР ЗАПУЩЕН НА http://{addr}");
    println!("💾 Зашифрованное хранилище: cryptox_enterprise.redb (AES-256-GCM + Blind Index)");
    println!("⚡ Живой WebSocket: ws://{addr}/ws");
    println!("==================================================================");
    axum::serve(listener, app).await?;
    Ok(())
}
