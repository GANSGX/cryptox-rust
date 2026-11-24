//! Живой HTTP + WebSocket сервер на `Axum 0.8` (`http_server.rs`), соединяющий
//! продуктовый UI мессенджера с реальными Rust-сервисами (`edge-gateway`, `auth-vault-svc`,
//! `user-directory-svc`, `presence-receipts-svc`, `messaging-svc`), клиентскими крипто-анклавами `cryptox-core`
//! и зашифрованным дисковым хранилищем `cryptox-storage` (`redb` + `AES-256-GCM` + `Blind Index`).

use crate::EdgeGateway;
use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use cryptox_core::{
    Argon2Profile, ChatSession, CloudKeyVault, UserIdentity, XChaCha20Poly1305Provider,
};
use cryptox_proto::{
    ChannelId, CipherSuiteId, DeviceId, DirectoryEntryProto, EncryptionPolicy, MessageId,
    PublicKeyBundle, ReadReceiptWatermarkProto, RegisterUserRequest, SignedSessionToken, TenantId,
    UserId,
};
use cryptox_storage::EncryptedStorageEngine;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;
use user_directory_svc::UserDirectoryService;

const UI_HTML: &str = include_str!("ui.html");
const DEMO_PASSWORD: &[u8] = b"CryptoX#Enterprise#2026";
const DEFAULT_STORAGE_ROOT_KEY: [u8; 32] = [0x6A_u8; 32];

/// Локальный клиентский крипто-анклав сотрудника (имитирует память Rust-ядра на устройстве в Tauri v2).
pub struct ClientDeviceEnclave {
    pub username: String,
    pub display_name: String,
    pub identity: UserIdentity,
    pub active_token: SignedSessionToken,
    pub device_number: u32,
    pub vault_version: AtomicU64,
    /// Кэш установленных E2EE сессий чатов `peer_username -> ChatSession`.
    pub sessions: DashMap<String, ChatSession>,
    /// Кэш проверенных публичных ключей собеседников `peer_username -> PublicKeyBundle`.
    pub peer_bundles: DashMap<String, PublicKeyBundle>,
}

pub struct LivePrototypeState {
    pub tenant_id: TenantId,
    pub gateway: Arc<EdgeGateway>,
    pub disk_storage: Option<Arc<EncryptedStorageEngine>>,
    pub client_enclaves: DashMap<String, Arc<ClientDeviceEnclave>>,
    /// Шина мгновенных WebSocket-событий для всех открытых вкладок/клиентов (`new_message`, `read_receipt`, `typing`).
    pub ws_event_bus: broadcast::Sender<String>,
    pub auth_down: AtomicBool,
    pub directory_down: AtomicBool,
    pub presence_down: AtomicBool,
}

impl LivePrototypeState {
    #[must_use]
    pub fn new_with_seeded_company(gateway: Arc<EdgeGateway>) -> Arc<Self> {
        Self::build_internal(gateway, None)
    }

    pub fn new_with_disk_storage(
        gateway: Arc<EdgeGateway>,
        db_path: impl AsRef<Path>,
    ) -> Result<Arc<Self>, String> {
        let engine = EncryptedStorageEngine::open_or_create(
            db_path,
            DEFAULT_STORAGE_ROOT_KEY,
            100_000,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self::build_internal(gateway, Some(Arc::new(engine))))
    }

    fn build_internal(
        gateway: Arc<EdgeGateway>,
        disk_storage: Option<Arc<EncryptedStorageEngine>>,
    ) -> Arc<Self> {
        let tenant_id = TenantId::new_v7();
        let (ws_event_bus, _) = broadcast::channel(4096);

        let state = Arc::new(Self {
            tenant_id,
            gateway,
            disk_storage,
            client_enclaves: DashMap::new(),
            ws_event_bus,
            auth_down: AtomicBool::new(false),
            directory_down: AtomicBool::new(false),
            presence_down: AtomicBool::new(false),
        });

        let seed_employees = [
            ("alice_ceo", "Алиса (CEO / Генеральный директор)"),
            ("bob_architect", "Боб (Principal System Architect)"),
            ("charlie_sec", "Чарли (Директор ИБ / CISO)"),
            ("dmitry_backend", "Дмитрий (Lead Rust Engineer)"),
        ];

        for (uname, dname) in seed_employees {
            let _ = state.onboard_employee_enclave(uname, dname);
        }

        state
    }

    #[must_use]
    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1_700_000_000_000)
    }

    fn fast_argon_profile() -> Argon2Profile {
        Argon2Profile {
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// Полный цикл Zero-Knowledge регистрации, челлендж-входа, публикации ключей в `user-directory-svc`
    /// и сохранения на зашифрованный диск `cryptox-storage` (под слепым индексом `BLAKE3`).
    pub fn onboard_employee_enclave(
        &self,
        raw_username: &str,
        display_name: &str,
    ) -> Result<String, String> {
        let now_ms = Self::now_ms();
        let norm_uname = raw_username
            .trim()
            .trim_start_matches('@')
            .to_ascii_lowercase();

        let user_id = UserId::new_v7();
        let device_id = DeviceId::new_v7();
        let profile = Self::fast_argon_profile();

        let identity = UserIdentity::generate(
            self.tenant_id,
            user_id,
            device_id,
            CipherSuiteId::X25519XChaCha20Poly1305Blake3,
            1,
        );
        let bundle = identity
            .export_public_bundle()
            .map_err(|e| e.to_string())?;
        let vault_blob = CloudKeyVault::seal_to_cloud_blob(
            &identity,
            &[],
            DEMO_PASSWORD,
            1,
            profile,
        )
        .map_err(|e| e.to_string())?;
        let auth_vk = CloudKeyVault::derive_auth_verifying_key(
            DEMO_PASSWORD,
            &vault_blob.argon2_salt,
            profile,
        )
        .map_err(|e| e.to_string())?;

        self.gateway
            .auth_service()
            .register_user(RegisterUserRequest {
                tenant_id: self.tenant_id.to_vec(),
                user_id: user_id.to_vec(),
                username: norm_uname.clone(),
                auth_verifying_key: auth_vk.to_vec(),
                public_key_bundle: Some(bundle.clone()),
                initial_vault_blob: Some(vault_blob.clone()),
            })
            .map_err(|e| e.to_string())?;

        let ch = self
            .gateway
            .auth_service()
            .issue_login_challenge(self.tenant_id, &norm_uname, now_ms)
            .map_err(|e| e.to_string())?;
        let verify_req = CloudKeyVault::sign_login_challenge(&ch, DEMO_PASSWORD, device_id)
            .map_err(|e| e.to_string())?;
        let (token, _) = self
            .gateway
            .auth_service()
            .verify_login_and_fetch_vault(&verify_req, now_ms + 1)
            .map_err(|e| e.to_string())?;

        let dir_entry: Arc<DirectoryEntryProto> = self
            .gateway
            .directory_service()
            .publish_or_rotate_entry(&token, &norm_uname, display_name, bundle, now_ms + 2)
            .map_err(|e| e.to_string())?;

        // Синхронно сохраняем в зашифрованное дисковое хранилище `cryptox-storage` (Blind Index + AES-256-GCM)
        if let Some(storage) = &self.disk_storage {
            let _ = storage.put_directory_entries_batch(&[(*dir_entry).clone()]);
            let _ = storage.put_vault_blob(&vault_blob);
        }

        self.client_enclaves.insert(
            norm_uname.clone(),
            Arc::new(ClientDeviceEnclave {
                username: norm_uname.clone(),
                display_name: display_name.to_string(),
                identity,
                active_token: token,
                device_number: 1,
                vault_version: AtomicU64::new(1),
                sessions: DashMap::new(),
                peer_bundles: DashMap::new(),
            }),
        );

        let _ = self.ws_event_bus.send(
            serde_json::json!({
                "type": "directory_updated",
                "username": norm_uname,
            })
            .to_string(),
        );

        Ok(norm_uname)
    }
}

pub fn build_app_router(state: Arc<LivePrototypeState>) -> Router {
    Router::new()
        .route("/", get(serve_ui))
        .route("/ws", get(ws_upgrade_handler))
        .route("/api/state", get(api_get_state))
        .route("/api/register", post(api_register_user))
        .route("/api/cloud-sync-new-device", post(api_cloud_sync_new_device))
        .route("/api/search", get(api_search_users))
        .route("/api/chat/send", post(api_send_message))
        .route("/api/chat/history", get(api_chat_history))
        .route("/api/chat/mark-read", post(api_mark_chat_read))
        .route("/api/chaos/toggle", post(api_chaos_toggle))
        .with_state(state)
}

async fn serve_ui() -> Html<&'static str> {
    Html(UI_HTML)
}

/// Живой WebSocket-актор на `Axum 0.8` (по паттерну `/tokio-rs/axum` из Context7 MCP:
/// единый таск владеет `WebSocket` и через `tokio::select!` мультиплексирует `socket.recv()` и `broadcast::Receiver`).
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<LivePrototypeState>>,
) -> impl IntoResponse {
    ws.max_message_size(64 * 1024)
        .on_upgrade(move |socket| handle_ws_connection(socket, state))
}

async fn handle_ws_connection(mut socket: WebSocket, state: Arc<LivePrototypeState>) {
    let mut rx = state.ws_event_bus.subscribe();

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(WsMessage::Text(text))) => {
                        // Клиент может прислать событие `{"type":"typing","from":"alice_ceo","to":"bob_architect"}`
                        if text.len() <= 512 && text.contains(r#""type":"typing""#) {
                            let _ = state.ws_event_bus.send(text.to_string());
                        }
                    }
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => {}
                    _ => break,
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Ok(json_event) => {
                        if socket.send(WsMessage::Text(json_event.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

#[derive(Serialize)]
pub struct LocalUserDto {
    pub username: String,
    pub display_name: String,
    pub device_number: u32,
    pub vault_version: u64,
}

#[derive(Serialize)]
pub struct ServicesHealthDto {
    pub auth_down: bool,
    pub directory_down: bool,
    pub presence_down: bool,
    pub absorbed_sidecar_failures: u64,
    pub storage_l1_hits: u64,
    pub storage_l2_reads: u64,
    pub storage_disk_commits: u64,
    pub storage_records_written: u64,
}

#[derive(Serialize)]
pub struct StateResponseDto {
    pub local_users: Vec<LocalUserDto>,
    pub services: ServicesHealthDto,
}

async fn api_get_state(State(state): State<Arc<LivePrototypeState>>) -> Json<StateResponseDto> {
    let mut local_users: Vec<LocalUserDto> = state
        .client_enclaves
        .iter()
        .map(|entry| {
            let e = entry.value();
            LocalUserDto {
                username: e.username.clone(),
                display_name: e.display_name.clone(),
                device_number: e.device_number,
                vault_version: e.vault_version.load(Ordering::Relaxed),
            }
        })
        .collect();
    local_users.sort_by(|a, b| a.username.cmp(&b.username));

    let (l1_hits, l2_reads, disk_commits, records_written) = match &state.disk_storage {
        Some(s) => {
            let m = s.metrics();
            (
                m.l1_cache_hits,
                m.l2_disk_reads,
                m.disk_group_commits,
                m.disk_records_written,
            )
        }
        None => (0, 0, 0, 0),
    };

    Json(StateResponseDto {
        local_users,
        services: ServicesHealthDto {
            auth_down: state.auth_down.load(Ordering::Relaxed),
            directory_down: state.directory_down.load(Ordering::Relaxed),
            presence_down: state.presence_down.load(Ordering::Relaxed),
            absorbed_sidecar_failures: state.gateway.absorbed_sidecar_failures(),
            storage_l1_hits: l1_hits,
            storage_l2_reads: l2_reads,
            storage_disk_commits: disk_commits,
            storage_records_written: records_written,
        },
    })
}

#[derive(Deserialize)]
pub struct RegisterReqDto {
    pub username: String,
    pub display_name: String,
}

async fn api_register_user(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<RegisterReqDto>,
) -> impl IntoResponse {
    match state.onboard_employee_enclave(&req.username, &req.display_name) {
        Ok(uname) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "username": uname })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

#[derive(Deserialize)]
pub struct CloudSyncReqDto {
    pub username: String,
}

async fn api_cloud_sync_new_device(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<CloudSyncReqDto>,
) -> impl IntoResponse {
    let now_ms = LivePrototypeState::now_ms();
    let norm = req.username.trim().trim_start_matches('@').to_ascii_lowercase();

    let Some(old_enclave_ref) = state.client_enclaves.get(&norm) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Сотрудник не найден" })),
        );
    };
    let old_enclave = old_enclave_ref.value().clone();
    drop(old_enclave_ref);

    let ch = match state
        .gateway
        .auth_service()
        .issue_login_challenge(state.tenant_id, &norm, now_ms)
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        }
    };

    let new_device_id = DeviceId::new_v7();
    let Ok(verify_req) =
        CloudKeyVault::sign_login_challenge(&ch, DEMO_PASSWORD, new_device_id)
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Ошибка подписи челленджа" })),
        );
    };

    let (new_token, vault_blob) = match state
        .gateway
        .auth_service()
        .verify_login_and_fetch_vault(&verify_req, now_ms + 1)
    {
        Ok(res) => res,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        }
    };

    let vault_bytes = vault_blob.to_wire_bytes().len();
    let Ok((restored_identity, restored_sessions_vec)) = CloudKeyVault::unlock_from_cloud_blob(
        &vault_blob,
        DEMO_PASSWORD,
        new_device_id,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Не удалось расшифровать CloudKeyVault" })),
        );
    };

    let restored_count = restored_sessions_vec.len();
    let new_sessions_map = DashMap::new();
    for s in restored_sessions_vec {
        for item in &old_enclave.sessions {
            if item.value().channel_id() == s.channel_id() {
                new_sessions_map.insert(item.key().clone(), s);
                break;
            }
        }
    }

    let new_device_number = old_enclave.device_number.saturating_add(1);
    let new_enclave = Arc::new(ClientDeviceEnclave {
        username: old_enclave.username.clone(),
        display_name: old_enclave.display_name.clone(),
        identity: restored_identity,
        active_token: new_token,
        device_number: new_device_number,
        vault_version: AtomicU64::new(vault_blob.vault_version),
        sessions: new_sessions_map,
        peer_bundles: old_enclave.peer_bundles.clone(),
    });

    state.client_enclaves.insert(norm, new_enclave);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "device_number": new_device_number,
            "vault_bytes": vault_bytes,
            "restored_sessions": restored_count,
        })),
    )
}

#[derive(Deserialize)]
pub struct SearchQueryDto {
    pub caller: String,
    pub q: Option<String>,
}

async fn api_search_users(
    State(state): State<Arc<LivePrototypeState>>,
    Query(query): Query<SearchQueryDto>,
) -> impl IntoResponse {
    let now_ms = LivePrototypeState::now_ms();
    let Some(caller_enclave) = state.client_enclaves.get(&query.caller) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Активный профиль не найден" })),
        );
    };

    let prefix = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("a");

    let prefixes_to_scan: Vec<&str> = if query.q.as_deref().unwrap_or("").trim().is_empty() {
        vec!["a", "b", "c", "d", "e", "f", "g", "i", "k", "l", "m", "n", "o", "p", "r", "s", "t", "u", "v", "z"]
    } else {
        vec![prefix]
    };

    let mut entries_dto = Vec::new();
    for p in prefixes_to_scan {
        match state.gateway.handle_search_users(
            &caller_enclave.active_token,
            p,
            25,
            now_ms,
        ) {
            Ok(resp) => {
                for e in resp.entries {
                    if let Ok(bundle) =
                        UserDirectoryService::verify_client_received_entry(state.tenant_id, &e)
                    {
                        caller_enclave
                            .peer_bundles
                            .insert(e.username.clone(), bundle);
                    }
                    // Заодно прогреваем слепой индекс в `cryptox-storage` (L1/L2)
                    if let Some(storage) = &state.disk_storage {
                        let _ = storage.get_directory_entry_by_username(state.tenant_id, &e.username);
                    }
                    let kt_hex = bytes_to_hex(&e.transparency_log_hash);
                    entries_dto.push(serde_json::json!({
                        "username": e.username,
                        "display_name": e.display_name,
                        "transparency_seq": e.transparency_seq,
                        "transparency_hash_short": &kt_hex[..16.min(kt_hex.len())],
                    }));
                }
            }
            Err(err) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({ "error": err.to_string() })),
                );
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "entries": entries_dto })),
    )
}

#[derive(Deserialize)]
pub struct SendMessageReqDto {
    pub sender_username: String,
    pub recipient_username: String,
    pub plaintext: String,
}

async fn api_send_message(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<SendMessageReqDto>,
) -> impl IntoResponse {
    let now_ms = LivePrototypeState::now_ms();
    let Some(sender_ref) = state.client_enclaves.get(&req.sender_username) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Отправитель не найден" })),
        );
    };
    let sender = sender_ref.value().clone();
    drop(sender_ref);

    // 1. Получаем или устанавливаем E2EE ChatSession с получателем
    if !sender.sessions.contains_key(&req.recipient_username) {
        let peer_bundle = if let Some(cached) = sender.peer_bundles.get(&req.recipient_username) {
            cached.value().clone()
        } else {
            // Пробуем сначала `user-directory-svc`, а если он отключен — читаем по Слепому Индексу из `cryptox-storage`!
            let entry_res = state
                .gateway
                .directory_service()
                .get_by_username(&sender.active_token, &req.recipient_username, now_ms)
                .ok()
                .or_else(|| {
                    state.disk_storage.as_ref().and_then(|s| {
                        s.get_directory_entry_by_username(state.tenant_id, &req.recipient_username)
                            .ok()
                            .flatten()
                    })
                });

            match entry_res {
                Some(entry) => match UserDirectoryService::verify_client_received_entry(
                    state.tenant_id,
                    &entry,
                ) {
                    Ok(b) => {
                        sender
                            .peer_bundles
                            .insert(req.recipient_username.clone(), b.clone());
                        b
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": e.to_string() })),
                        )
                    }
                },
                None => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({ "error": "Собеседник не найден или каталог отключен" })),
                    )
                }
            }
        };

        let Ok(session) = ChatSession::establish_direct(
            &sender.identity,
            &peer_bundle,
            EncryptionPolicy::StrictZeroKnowledge,
            None,
        ) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Не удалось установить E2EE сессию" })),
            );
        };
        sender
            .sessions
            .insert(req.recipient_username.clone(), session);
    }

    let envelope = {
        let Some(mut sess_mut) = sender.sessions.get_mut(&req.recipient_username) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Сессия не найдена" })),
            );
        };
        match sess_mut.encrypt_message(
            &sender.identity,
            &XChaCha20Poly1305Provider,
            req.plaintext.as_bytes(),
        ) {
            Ok(env) => env,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
            }
        }
    };

    // 2. Отправляем ТОЛЬКО бинарные байты конверта через `edge-gateway` (Hot Path!)
    let token_wire = sender.active_token.to_wire_bytes();
    let env_wire = envelope.to_wire_bytes();
    if let Err(e) = state
        .gateway
        .handle_send_message_wire(&token_wire, &env_wire, now_ms)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        );
    }

    // 2b. Записываем конверт на зашифрованный диск `cryptox-storage` (48-байтный B+Tree индекс `[Tenant||Channel||UUIDv7]`)
    if let Some(storage) = &state.disk_storage {
        let _ = storage.commit_messages_batch(std::slice::from_ref(&envelope));
    }

    // 2c. Аналог X3DH PreKey / MLS Welcome: передаем получателю самоподписанный `PublicKeyBundle`
    if let Some(recipient_enclave) = state.client_enclaves.get(&req.recipient_username)
        && !recipient_enclave
            .peer_bundles
            .contains_key(&sender.username)
        && let Ok(sender_bundle) = sender.identity.export_public_bundle()
        && UserIdentity::verify_peer_bundle(state.tenant_id, &sender_bundle).is_ok()
    {
        recipient_enclave
            .peer_bundles
            .insert(sender.username.clone(), sender_bundle);
    }

    // 3. Автоматическая синхронизация сейфа `CloudKeyVault` (если `auth-vault-svc` онлайн)
    if let Some(sess_ref) = sender.sessions.get(&req.recipient_username) {
        let next_ver = sender.vault_version.load(Ordering::Relaxed).saturating_add(1);
        if let Ok(new_vault) = CloudKeyVault::seal_to_cloud_blob(
            &sender.identity,
            &[sess_ref.value()],
            DEMO_PASSWORD,
            next_ver,
            LivePrototypeState::fast_argon_profile(),
        ) && state
            .gateway
            .auth_service()
            .push_vault_update(&sender.active_token, new_vault.clone(), now_ms)
            .is_ok()
        {
            sender.vault_version.store(next_ver, Ordering::Relaxed);
            if let Some(storage) = &state.disk_storage {
                let _ = storage.put_vault_blob(&new_vault);
            }
        }
    }

    // 4. Мгновенный пуш по WebSocket во все открытые вкладки браузера (< 1 мс)!
    let _ = state.ws_event_bus.send(
        serde_json::json!({
            "type": "new_message",
            "sender": req.sender_username,
            "recipient": req.recipient_username,
        })
        .to_string(),
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "sent" })),
    )
}

#[derive(Deserialize)]
pub struct MarkReadReqDto {
    pub reader_username: String,
    pub peer_username: String,
}

async fn api_mark_chat_read(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<MarkReadReqDto>,
) -> impl IntoResponse {
    let now_ms = LivePrototypeState::now_ms();
    let Some(reader_ref) = state.client_enclaves.get(&req.reader_username) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Пользователь не найден" })),
        );
    };
    let reader = reader_ref.value().clone();
    drop(reader_ref);

    if !reader.sessions.contains_key(&req.peer_username)
        && let Some(peer_bundle) = reader
            .peer_bundles
            .get(&req.peer_username)
            .map(|b| b.value().clone())
            .or_else(|| {
                state
                    .gateway
                    .directory_service()
                    .get_by_username(&reader.active_token, &req.peer_username, now_ms)
                    .ok()
                    .or_else(|| {
                        state.disk_storage.as_ref().and_then(|s| {
                            s.get_directory_entry_by_username(state.tenant_id, &req.peer_username)
                                .ok()
                                .flatten()
                        })
                    })
                    .and_then(|entry| {
                        UserDirectoryService::verify_client_received_entry(state.tenant_id, &entry)
                            .ok()
                    })
            })
        && let Ok(sess) = ChatSession::establish_direct(
            &reader.identity,
            &peer_bundle,
            EncryptionPolicy::StrictZeroKnowledge,
            None,
        )
    {
        reader
            .peer_bundles
            .insert(req.peer_username.clone(), peer_bundle);
        reader.sessions.insert(req.peer_username.clone(), sess);
    }

    let Some(sess_ref) = reader.sessions.get(&req.peer_username) else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "no_session" })),
        );
    };
    let channel_id = sess_ref.channel_id();

    if let Ok(hist) = state.gateway.handle_fetch_history(
        &reader.active_token,
        channel_id,
        None,
        1,
        now_ms,
    ) && let Some(last_env) = hist.envelopes.last()
        && let Ok(last_mid) = MessageId::from_slice(&last_env.message_id)
        && state
            .gateway
            .presence_service()
            .record_read_receipt(&reader.active_token, channel_id, last_mid, now_ms)
            .is_ok()
    {
        if let Some(storage) = &state.disk_storage {
            let wm = ReadReceiptWatermarkProto {
                tenant_id: state.tenant_id.to_vec(),
                channel_id: channel_id.to_vec(),
                user_id: reader.identity.user_id().to_vec(),
                last_read_message_id: last_mid.to_vec(),
                updated_at_ms: now_ms,
            };
            let _ = storage.flush_watermarks_batch(&[wm]);
        }
        let _ = state.ws_event_bus.send(
            serde_json::json!({
                "type": "read_receipt",
                "reader": req.reader_username,
                "peer": req.peer_username,
            })
            .to_string(),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "ok" })),
    )
}

#[derive(Deserialize)]
pub struct HistoryQueryDto {
    pub caller: String,
    pub peer: String,
}

async fn api_chat_history(
    State(state): State<Arc<LivePrototypeState>>,
    Query(q): Query<HistoryQueryDto>,
) -> impl IntoResponse {
    let now_ms = LivePrototypeState::now_ms();
    let Some(caller_ref) = state.client_enclaves.get(&q.caller) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Профиль не найден" })),
        );
    };
    let caller = caller_ref.value().clone();
    drop(caller_ref);

    if !caller.sessions.contains_key(&q.peer) {
        let peer_bundle_opt = caller
            .peer_bundles
            .get(&q.peer)
            .map(|b| b.value().clone())
            .or_else(|| {
                state
                    .gateway
                    .directory_service()
                    .get_by_username(&caller.active_token, &q.peer, now_ms)
                    .ok()
                    .or_else(|| {
                        state.disk_storage.as_ref().and_then(|s| {
                            s.get_directory_entry_by_username(state.tenant_id, &q.peer)
                                .ok()
                                .flatten()
                        })
                    })
                    .and_then(|entry| {
                        UserDirectoryService::verify_client_received_entry(state.tenant_id, &entry)
                            .ok()
                    })
            });

        if let Some(peer_bundle) = peer_bundle_opt {
            caller.peer_bundles.insert(q.peer.clone(), peer_bundle.clone());
            if let Ok(sess) = ChatSession::establish_direct(
                &caller.identity,
                &peer_bundle,
                EncryptionPolicy::StrictZeroKnowledge,
                None,
            ) {
                caller.sessions.insert(q.peer.clone(), sess);
            }
        }
    }

    let Some(session_ref) = caller.sessions.get(&q.peer) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Сессия чата еще не создана, а user-directory-svc сейчас отключен"
            })),
        );
    };
    let channel_id: ChannelId = session_ref.channel_id();
    let peer_user_id: UserId = session_ref.peer_user_id();

    // Читаем историю из `messaging-svc`, а также проверяем 48-байтный дисковый индекс `cryptox-storage`
    let mut history_page = match state.gateway.handle_fetch_history(
        &caller.active_token,
        channel_id,
        None,
        50,
        now_ms,
    ) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
        }
    };

    if history_page.envelopes.is_empty()
        && let Some(storage) = &state.disk_storage
        && let Ok(disk_page) =
            storage.fetch_channel_history_from_disk(state.tenant_id, channel_id, None, 50)
    {
        history_page = disk_page;
    }

    // Проверяем водораздел прочтения собеседником (`peer_read_up_to`) для отображения двойных галочек `✓✓`
    let peer_read_watermark_bytes: Option<Vec<u8>> = state
        .gateway
        .presence_service()
        .get_read_watermark(&caller.active_token, channel_id, peer_user_id, now_ms)
        .ok()
        .flatten()
        .or_else(|| {
            state.disk_storage.as_ref().and_then(|s| {
                s.get_read_watermark(state.tenant_id, channel_id, peer_user_id)
                    .ok()
                    .flatten()
            })
        })
        .map(|wm| wm.last_read_message_id);

    let mut msgs_dto = Vec::with_capacity(history_page.envelopes.len());
    for env in &history_page.envelopes {
        let decrypted_text = session_ref
            .decrypt_historical_message(&caller.identity, &XChaCha20Poly1305Provider, env)
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            .unwrap_or_else(|e| format!("[Ошибка дешифрования: {e}]"));

        let sender_uid =
            UserId::from_slice(&env.sender_user_id).unwrap_or_else(|_| UserId::new_v7());
        let is_mine = sender_uid == caller.identity.user_id();
        let sender_uname = if is_mine {
            caller.username.clone()
        } else {
            q.peer.clone()
        };

        let msg_ts_ms = MessageId::from_slice(&env.message_id)
            .map(|m| m.timestamp_ms())
            .unwrap_or(now_ms);

        let is_read_by_peer = is_mine
            && peer_read_watermark_bytes
                .as_ref()
                .is_some_and(|wm_bytes| wm_bytes.as_slice() >= env.message_id.as_slice());

        let mid_hex = bytes_to_hex(&env.message_id);
        let ct_hex = bytes_to_hex(&env.ciphertext);
        let sig_hex = bytes_to_hex(&env.ed25519_signature);

        msgs_dto.push(serde_json::json!({
            "sender_username": sender_uname,
            "ratchet_step": env.ratchet_step,
            "message_id_short": &mid_hex[..12.min(mid_hex.len())],
            "timestamp_ms": msg_ts_ms,
            "is_read_by_peer": is_read_by_peer,
            "decrypted_text": decrypted_text,
            "wire_bytes_len": env.to_wire_bytes().len(),
            "nonce_hex": bytes_to_hex(&env.nonce),
            "ciphertext_hex": ct_hex,
            "signature_hex_short": &sig_hex[..24.min(sig_hex.len())],
        }));
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "channel_id": bytes_to_hex(channel_id.as_bytes()),
            "messages": msgs_dto,
        })),
    )
}

#[derive(Deserialize)]
pub struct ChaosToggleReqDto {
    pub service: String,
    pub outage: bool,
}

async fn api_chaos_toggle(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<ChaosToggleReqDto>,
) -> impl IntoResponse {
    match req.service.as_str() {
        "auth" => {
            state.auth_down.store(req.outage, Ordering::SeqCst);
            state.gateway.auth_service().set_simulated_outage(req.outage);
        }
        "directory" => {
            state.directory_down.store(req.outage, Ordering::SeqCst);
            state
                .gateway
                .directory_service()
                .set_simulated_outage(req.outage);
        }
        "presence" => {
            state.presence_down.store(req.outage, Ordering::SeqCst);
            state
                .gateway
                .presence_service()
                .set_simulated_outage(req.outage);
        }
        _ => {}
    }

    let _ = state.ws_event_bus.send(
        serde_json::json!({
            "type": "chaos_updated",
            "service": req.service,
            "outage": req.outage,
        })
        .to_string(),
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({ "service": req.service, "outage": req.outage })),
    )
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
