//! Живой HTTP + WebSocket сервер на `Axum 0.8` (`http_server.rs`), соединяющий
//! продуктовый UI мессенджера с реальными Rust-сервисами (`edge-gateway`, `auth-vault-svc`,
//! `user-directory-svc`, `presence-receipts-svc`, `messaging-svc`), клиентскими крипто-анклавами `cryptox-core`
//! и зашифрованным дисковым хранилищем `cryptox-storage` (`redb` + `AES-256-GCM` + `Blind Index`).

use crate::{
    cluster_mesh::{InternalRpcCommand, InternalRpcResponse},
    EdgeGateway,
};
use axum::{
    body::Bytes,
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
    ChannelId, CipherSuiteId, ClientDecryptedMessageItemProto, ClientDirectoryPeerProto,
    ClientWireOp, ClientWireRequestProto, ClientWireResponseProto, ClientWireWsEventProto,
    DeviceId, DirectoryEntryProto, EncryptedVaultBlob, EncryptionPolicy, MessageId,
    PublicKeyBundle, ReadReceiptWatermarkProto, RegisterUserRequest, SignedSessionToken, TenantId,
    UserId,
};
use cryptox_storage::EncryptedStorageEngine;
use dashmap::DashMap;
use prost::Message;
use rand_core::{OsRng, RngCore};
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
const STATUS_UI_HTML: &str = include_str!("status_ui.html");
const AUTH_UI_HTML: &str = include_str!("auth_ui.html");
const DEMO_PASSWORD: &[u8] = b"CryptoX#Enterprise#2026";
const DEFAULT_STORAGE_ROOT_KEY: [u8; 32] = [0x6A_u8; 32];

fn generate_recovery_key() -> String {
    const CHARSET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut rnd = [0u8; 16];
    OsRng.fill_bytes(&mut rnd);
    let mut segs = Vec::with_capacity(4);
    for chunk in rnd.chunks(4) {
        let mut s = String::with_capacity(4);
        for &b in chunk {
            s.push(CHARSET[(b as usize) % CHARSET.len()] as char);
        }
        segs.push(s);
    }
    format!("CX-{}-{}-{}-{}", segs[0], segs[1], segs[2], segs[3])
}

/// Локальный клиентский крипто-анклав сотрудника (имитирует память Rust-ядра на устройстве в Tauri v2).
pub struct ClientDeviceEnclave {
    pub username: String,
    pub display_name: String,
    pub identity: UserIdentity,
    pub active_token: SignedSessionToken,
    pub device_number: u32,
    pub vault_version: AtomicU64,
    pub recovery_key: String,
    pub recovery_vault_blob: EncryptedVaultBlob,
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
    pub email_to_username: DashMap<String, String>,
    /// Шина мгновенных WebSocket-событий для всех открытых вкладок/клиентов (`new_message`, `read_receipt`, `typing`).
    pub ws_event_bus: broadcast::Sender<String>,
    /// Бинарная Protobuf шина мгновенных WebSocket-событий (`ClientWireWsEventProto`).
    pub ws_proto_bus: broadcast::Sender<Vec<u8>>,
    pub auth_down: AtomicBool,
    pub directory_down: AtomicBool,
    pub presence_down: AtomicBool,
}

impl LivePrototypeState {
    pub fn broadcast_proto_ws_event(
        &self,
        event_type: &str,
        sender: &str,
        recipient: &str,
        wire_bytes_len: u32,
    ) {
        let ev = ClientWireWsEventProto {
            event_type: event_type.to_string(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            wire_bytes_len,
            timestamp_ms: Self::now_ms(),
        };
        let _ = self.ws_proto_bus.send(ev.encode_to_vec());
    }
    #[must_use]
    pub fn resolve_identifier(&self, raw: &str) -> String {
        let trimmed = raw.trim().to_ascii_lowercase();
        if let Some(mapped) = self.email_to_username.get(&trimmed) {
            return mapped.value().clone();
        }
        trimmed.trim_start_matches('@').to_string()
    }

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
        let (ws_proto_bus, _) = broadcast::channel(4096);

        let state = Arc::new(Self {
            tenant_id,
            gateway,
            disk_storage,
            client_enclaves: DashMap::new(),
            email_to_username: DashMap::new(),
            ws_event_bus,
            ws_proto_bus,
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
        let (uname, _rec) =
            self.onboard_employee_enclave_with_password(raw_username, display_name, DEMO_PASSWORD)?;
        Ok(uname)
    }

    pub fn onboard_employee_enclave_with_password(
        &self,
        raw_username: &str,
        display_name: &str,
        password_bytes: &[u8],
    ) -> Result<(String, String), String> {
        let now_ms = Self::now_ms();
        let norm_uname = raw_username
            .trim()
            .trim_start_matches('@')
            .to_ascii_lowercase();
        let effective_pwd = if password_bytes.is_empty() {
            DEMO_PASSWORD
        } else {
            password_bytes
        };

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
            effective_pwd,
            1,
            profile,
        )
        .map_err(|e| e.to_string())?;
        let auth_vk = CloudKeyVault::derive_auth_verifying_key(
            effective_pwd,
            &vault_blob.argon2_salt,
            profile,
        )
        .map_err(|e| e.to_string())?;

        // Генерируем резервный Ключ Восстановления (`Recovery Key`) и запечатываем им резервную копию сейфа
        let recovery_key = generate_recovery_key();
        let recovery_vault_blob = CloudKeyVault::seal_to_cloud_blob(
            &identity,
            &[],
            recovery_key.as_bytes(),
            1,
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
        let verify_req = CloudKeyVault::sign_login_challenge(&ch, effective_pwd, device_id)
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
                recovery_key: recovery_key.clone(),
                recovery_vault_blob,
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

        Ok((norm_uname, recovery_key))
    }
}

pub fn build_app_router(state: Arc<LivePrototypeState>) -> Router {
    Router::new()
        .route("/", get(serve_ui))
        .route("/auth", get(serve_auth_ui))
        .route("/status", get(serve_status_ui))
        .route("/ws", get(ws_upgrade_handler))
        .route("/healthz", get(api_healthz))
        .route("/readyz", get(api_readyz))
        .route("/metrics", get(api_prometheus_metrics))
        .route("/rpc/v1/protobuf", post(api_protobuf_rpc))
        .route("/rpc/v1/client-wire", post(api_client_wire_protobuf))
        .route("/api/status/overview", get(api_status_overview))
        .route("/api/status/probe-hotpath", post(api_status_probe_hotpath))
        .route(
            "/api/status/simulate-attack",
            post(api_status_simulate_attack),
        )
        .route("/api/state", get(api_get_state))
        .route("/api/register", post(api_register_user))
        .route("/api/auth/login", post(api_auth_login))
        .route("/api/auth/sso", post(api_auth_sso))
        .route("/api/auth/recover-password", post(api_auth_recover_password))
        .route("/api/cloud-sync-new-device", post(api_cloud_sync_new_device))
        .route("/api/search", get(api_search_users))
        .route("/api/chat/send", post(api_send_message))
        .route("/api/chat/history", get(api_chat_history))
        .route("/api/chat/mark-read", post(api_mark_chat_read))
        .route("/api/chaos/toggle", post(api_chaos_toggle))
        .with_state(state)
}

async fn serve_auth_ui() -> Html<&'static str> {
    Html(AUTH_UI_HTML)
}

async fn serve_status_ui() -> Html<&'static str> {
    Html(STATUS_UI_HTML)
}

async fn api_healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "node": "cryptox-edge-gateway",
            "zero_trust_mesh": "XChaCha20-Poly1305+Ed25519",
        })),
    )
}

async fn api_readyz(State(state): State<Arc<LivePrototypeState>>) -> impl IntoResponse {
    let gw = &state.gateway;
    let msg_cb = gw.messaging_circuit_breaker().state();
    let dir_cb = gw.directory_circuit_breaker().state();
    let pres_cb = gw.presence_circuit_breaker().state();
    let auth_cb = gw.auth_circuit_breaker().state();

    let code = if msg_cb == crate::cluster_mesh::CircuitState::Open {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    (
        code,
        Json(serde_json::json!({
            "hotpath_ready": msg_cb != crate::cluster_mesh::CircuitState::Open,
            "circuits": {
                "messaging_svc": msg_cb.as_str(),
                "auth_vault_svc": auth_cb.as_str(),
                "user_directory_svc": dir_cb.as_str(),
                "presence_receipts_svc": pres_cb.as_str(),
            },
            "absorbed_sidecar_failures": gw.absorbed_sidecar_failures(),
            "zero_trust_intrusions_blocked": gw.zero_trust_intrusions_blocked(),
        })),
    )
}

async fn api_prometheus_metrics(State(state): State<Arc<LivePrototypeState>>) -> impl IntoResponse {
    let body = state
        .gateway
        .render_prometheus_metrics(state.disk_storage.as_deref());
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
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

async fn execute_binary_protobuf_rpc(state: &LivePrototypeState, raw_req_bytes: &[u8]) -> Vec<u8> {
    let Ok(cmd) = InternalRpcCommand::from_protobuf_wire(raw_req_bytes) else {
        return InternalRpcResponse::ServiceErr("invalid binary protobuf RPC frame".into())
            .to_protobuf_wire();
    };

    let resp = match cmd {
        InternalRpcCommand::PingHealth => InternalRpcResponse::Pong,
        InternalRpcCommand::RouteMessage {
            token_wire,
            envelope_wire,
            now_ms,
        } => match state
            .gateway
            .handle_send_message_wire(&token_wire, &envelope_wire, now_ms)
        {
            Ok(ack_wire) => InternalRpcResponse::OkBytes(ack_wire),
            Err(e) => InternalRpcResponse::ServiceErr(e.to_string()),
        },
        InternalRpcCommand::FetchHistory {
            token_wire,
            channel_id_bytes,
            before_cursor_bytes,
            limit,
            now_ms,
        } => {
            let Ok(tok) = SignedSessionToken::from_wire_bytes(&token_wire) else {
                return InternalRpcResponse::ServiceErr("invalid token wire".into())
                    .to_protobuf_wire();
            };
            let Ok(cid) = ChannelId::from_slice(&channel_id_bytes) else {
                return InternalRpcResponse::ServiceErr("invalid channel_id".into())
                    .to_protobuf_wire();
            };
            let cursor = before_cursor_bytes
                .as_ref()
                .and_then(|b| MessageId::from_slice(b).ok());
            match state
                .gateway
                .handle_fetch_history(&tok, cid, cursor, limit, now_ms)
            {
                Ok(page) => InternalRpcResponse::OkBytes(page.encode_to_vec()),
                Err(e) => InternalRpcResponse::ServiceErr(e.to_string()),
            }
        }
        InternalRpcCommand::SearchDirectory {
            token_wire,
            prefix,
            limit,
            now_ms,
        } => {
            let Ok(tok) = SignedSessionToken::from_wire_bytes(&token_wire) else {
                return InternalRpcResponse::ServiceErr("invalid token wire".into())
                    .to_protobuf_wire();
            };
            match state
                .gateway
                .handle_search_users(&tok, &prefix, limit, now_ms)
            {
                Ok(res) => InternalRpcResponse::OkBytes(res.encode_to_vec()),
                Err(e) => InternalRpcResponse::ServiceErr(e.to_string()),
            }
        }
        InternalRpcCommand::PresenceAndReadReceipt {
            token_wire,
            channel_id_bytes,
            message_id_bytes,
            now_ms,
        } => {
            let Ok(tok) = SignedSessionToken::from_wire_bytes(&token_wire) else {
                return InternalRpcResponse::ServiceErr("invalid token wire".into())
                    .to_protobuf_wire();
            };
            let Ok(cid) = ChannelId::from_slice(&channel_id_bytes) else {
                return InternalRpcResponse::ServiceErr("invalid channel_id".into())
                    .to_protobuf_wire();
            };
            let Ok(mid) = MessageId::from_slice(&message_id_bytes) else {
                return InternalRpcResponse::ServiceErr("invalid message_id".into())
                    .to_protobuf_wire();
            };
            let _ = state.gateway.presence_service().heartbeat_online(&tok, now_ms);
            match state
                .gateway
                .presence_service()
                .record_read_receipt(&tok, cid, mid, now_ms)
            {
                Ok(wm) => InternalRpcResponse::OkBytes(wm.last_read_message_id.to_vec()),
                Err(e) => InternalRpcResponse::ServiceErr(e.to_string()),
            }
        }
    };

    resp.to_protobuf_wire()
}

/// Нативный бинарный Protobuf RPC эндпоинт (`POST /rpc/v1/protobuf`, `Content-Type: application/x-protobuf`).
async fn api_protobuf_rpc(
    State(state): State<Arc<LivePrototypeState>>,
    body: Bytes,
) -> impl IntoResponse {
    let resp_wire = execute_binary_protobuf_rpc(&state, &body).await;
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/x-protobuf")],
        resp_wire,
    )
}

async fn handle_ws_connection(mut socket: WebSocket, state: Arc<LivePrototypeState>) {
    let mut rx = state.ws_event_bus.subscribe();
    let mut rx_proto = state.ws_proto_bus.subscribe();

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(WsMessage::Binary(bin_frame))) => {
                        if let Ok(ws_ev) = ClientWireWsEventProto::decode(bin_frame.as_ref())
                            && ws_ev.event_type == "typing"
                        {
                            let _ = state.ws_proto_bus.send(bin_frame.to_vec());
                            continue;
                        }
                        let resp_wire = execute_binary_protobuf_rpc(&state, &bin_frame).await;
                        if socket.send(WsMessage::Binary(resp_wire.into())).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(WsMessage::Text(text))) => {
                        if text.len() <= 512 && text.contains(r#""type":"typing""#) {
                            let _ = state.ws_event_bus.send(text.to_string());
                        }
                    }
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => {}
                    _ => break,
                }
            }
            outbound_proto = rx_proto.recv() => {
                match outbound_proto {
                    Ok(proto_bytes) => {
                        if socket.send(WsMessage::Binary(proto_bytes.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
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

/// Единый бинарный Protobuf RPC-интерфейс Клиент <-> Шлюз (`POST /rpc/v1/client-wire`, `Content-Type: application/x-protobuf`).
async fn api_client_wire_protobuf(
    State(state): State<Arc<LivePrototypeState>>,
    body: Bytes,
) -> impl IntoResponse {
    let resp = handle_client_wire_proto_inner(&state, &body);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/x-protobuf")],
        resp.encode_to_vec(),
    )
}

fn proto_err_resp(msg: impl Into<String>) -> ClientWireResponseProto {
    ClientWireResponseProto {
        ok: false,
        error_message: msg.into(),
        ..ClientWireResponseProto::default()
    }
}

fn validate_strict_password(pwd: &str) -> Result<(), &'static str> {
    if pwd.chars().count() < 8 {
        return Err("Пароль должен содержать минимум 8 символов");
    }
    if !pwd.chars().any(char::is_uppercase) || !pwd.chars().any(char::is_lowercase) {
        return Err("Пароль должен содержать заглавные и строчные буквы");
    }
    if !pwd.chars().any(|c| c.is_ascii_digit()) {
        return Err("Пароль должен содержать хотя бы одну цифру");
    }
    if !pwd.chars().any(|c| !c.is_alphanumeric() && !c.is_whitespace()) {
        return Err("Пароль должен содержать хотя бы один спецсимвол (!@#$%^&* и др.)");
    }
    let bytes = pwd.as_bytes();
    for w in bytes.windows(2) {
        if w[0].is_ascii_digit() && w[1].is_ascii_digit() && w[0] == w[1] {
            return Err("Запрещены одинаковые цифры подряд (например, 11, 00)");
        }
    }
    for w in bytes.windows(3) {
        if w[0].is_ascii_digit() && w[1].is_ascii_digit() && w[2].is_ascii_digit() {
            let a = i16::from(w[0]);
            let b = i16::from(w[1]);
            let c = i16::from(w[2]);
            if (b - a == 1 && c - b == 1) || (a - b == 1 && b - c == 1) {
                return Err("Запрещены идущие подряд цифры (например, 123, 321)");
            }
        }
    }
    Ok(())
}

fn handle_client_wire_proto_inner(
    state: &LivePrototypeState,
    raw_bytes: &[u8],
) -> ClientWireResponseProto {
    let Ok(req) = ClientWireRequestProto::decode(raw_bytes) else {
        return proto_err_resp("Ошибка декодирования бинарного Protobuf пакета");
    };
    let now_ms = LivePrototypeState::now_ms();

    match ClientWireOp::try_from_proto(req.op) {
        Some(ClientWireOp::Login) => {
            if req.password.is_empty() {
                return proto_err_resp("Введите пароль от аккаунта");
            }
            let norm = state.resolve_identifier(&req.caller_username);
            let Some(enclave_ref) = state.client_enclaves.get(&norm) else {
                return proto_err_resp("Аккаунт с таким логином или почтой не найден");
            };
            let display_name = enclave_ref.display_name.clone();
            let dev_num = enclave_ref.device_number;
            let v_ver = enclave_ref.vault_version.load(Ordering::Relaxed);
            drop(enclave_ref);

            let Ok(ch) = state
                .gateway
                .auth_service()
                .issue_login_challenge(state.tenant_id, &norm, now_ms)
            else {
                return proto_err_resp("Ошибка выпуска крипто-вызова входа");
            };
            let Ok(verify_req) = CloudKeyVault::sign_login_challenge(
                &ch,
                req.password.as_bytes(),
                DeviceId::new_v7(),
            ) else {
                return proto_err_resp("Ошибка крипто-подписи вызова входа");
            };
            match state
                .gateway
                .auth_service()
                .verify_login_and_fetch_vault(&verify_req, now_ms + 1)
            {
                Ok(_) => ClientWireResponseProto {
                    ok: true,
                    username: norm,
                    display_name,
                    device_number: dev_num,
                    vault_version: v_ver,
                    ..ClientWireResponseProto::default()
                },
                Err(e) => proto_err_resp(format!("Неверный пароль или аккаунт заблокирован: {e}")),
            }
        }
        Some(ClientWireOp::Register) => {
            let clean_email = req.email.trim().to_ascii_lowercase();
            if !clean_email.is_empty() && (!clean_email.contains('@') || !clean_email.contains('.'))
            {
                return proto_err_resp("Укажите корректный адрес электронной почты");
            }
            if !clean_email.is_empty() && state.email_to_username.contains_key(&clean_email) {
                return proto_err_resp("Аккаунт с такой электронной почтой уже зарегистрирован");
            }
            if let Err(msg) = validate_strict_password(&req.password) {
                return proto_err_resp(msg);
            }
            match state.onboard_employee_enclave_with_password(
                &req.caller_username,
                &req.display_name,
                req.password.as_bytes(),
            ) {
                Ok((uname, recovery_key)) => {
                    if !clean_email.is_empty() {
                        state.email_to_username.insert(clean_email, uname.clone());
                    }
                    state.broadcast_proto_ws_event("directory_updated", &uname, "", 0);
                    ClientWireResponseProto {
                        ok: true,
                        username: uname,
                        display_name: req.display_name,
                        recovery_key,
                        device_number: 1,
                        vault_version: 1,
                        ..ClientWireResponseProto::default()
                    }
                }
                Err(e) => proto_err_resp(e),
            }
        }
        Some(ClientWireOp::SsoLogin) => {
            let clean_domain = req.domain.trim().to_ascii_lowercase();
            let clean_email = req.email.trim().to_ascii_lowercase();
            if clean_domain.len() < 4 || !clean_domain.contains('.') {
                return proto_err_resp("Укажите корпоративный домен (например, company.ru)");
            }
            if clean_email.len() < 3 {
                return proto_err_resp("Укажите рабочую почту или корпоративный логин");
            }
            let resolved = state.resolve_identifier(&clean_email);
            let candidate_uname = resolved
                .split('@')
                .next()
                .unwrap_or(&resolved)
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>();

            if let Some(existing) = state.client_enclaves.get(&candidate_uname) {
                return ClientWireResponseProto {
                    ok: true,
                    username: existing.username.clone(),
                    display_name: existing.display_name.clone(),
                    device_number: existing.device_number,
                    vault_version: existing.vault_version.load(Ordering::Relaxed),
                    ..ClientWireResponseProto::default()
                };
            }

            let display = format!("{candidate_uname} ({clean_domain})");
            match state.onboard_employee_enclave_with_password(
                &candidate_uname,
                &display,
                DEMO_PASSWORD,
            ) {
                Ok((uname, recovery_key)) => {
                    if clean_email.contains('@') {
                        state.email_to_username.insert(clean_email, uname.clone());
                    }
                    state.broadcast_proto_ws_event("directory_updated", &uname, "", 0);
                    ClientWireResponseProto {
                        ok: true,
                        username: uname,
                        display_name: display,
                        recovery_key,
                        device_number: 1,
                        vault_version: 1,
                        ..ClientWireResponseProto::default()
                    }
                }
                Err(e) => proto_err_resp(e),
            }
        }
        Some(ClientWireOp::RecoverPassword) => {
            let norm = state.resolve_identifier(&req.caller_username);
            let clean_rec = req.recovery_key.trim().to_ascii_uppercase();
            if req.password.trim().len() < 6 {
                return proto_err_resp("Новый пароль должен содержать минимум 6 символов");
            }
            let Some(old_ref) = state.client_enclaves.get(&norm) else {
                return proto_err_resp("Аккаунт с таким логином или почтой не найден");
            };
            let old_enclave = Arc::clone(old_ref.value());
            drop(old_ref);

            let Ok((recovered_identity, _)) = CloudKeyVault::unlock_from_cloud_blob(
                &old_enclave.recovery_vault_blob,
                clean_rec.as_bytes(),
                DeviceId::new_v7(),
                EncryptionPolicy::StrictZeroKnowledge,
                None,
            ) else {
                return proto_err_resp(
                    "Неверный ключ восстановления (отказ дешифрования резервного сейфа)",
                );
            };

            let next_ver = old_enclave
                .vault_version
                .load(Ordering::SeqCst)
                .saturating_add(1);
            let profile = LivePrototypeState::fast_argon_profile();
            let Ok(new_vault_blob) = CloudKeyVault::seal_to_cloud_blob(
                &recovered_identity,
                &[],
                req.password.as_bytes(),
                next_ver,
                profile,
            ) else {
                return proto_err_resp("Ошибка перешифрования сейфа");
            };
            let Ok(new_auth_vk) = CloudKeyVault::derive_auth_verifying_key(
                req.password.as_bytes(),
                &new_vault_blob.argon2_salt,
                profile,
            ) else {
                return proto_err_resp("Ошибка генерации ключа входа");
            };
            if let Err(e) = state.gateway.auth_service().rotate_password_and_vault(
                state.tenant_id,
                &norm,
                &new_auth_vk,
                new_vault_blob.clone(),
            ) {
                return proto_err_resp(e.to_string());
            }
            if let Some(storage) = &state.disk_storage {
                let _ = storage.put_vault_blob(&new_vault_blob);
            }
            old_enclave.vault_version.store(next_ver, Ordering::SeqCst);
            ClientWireResponseProto {
                ok: true,
                username: norm,
                display_name: old_enclave.display_name.clone(),
                device_number: old_enclave.device_number,
                vault_version: next_ver,
                ..ClientWireResponseProto::default()
            }
        }
        Some(ClientWireOp::GetState) => {
            let norm = state.resolve_identifier(&req.caller_username);
            let mut peers: Vec<ClientDirectoryPeerProto> = state
                .client_enclaves
                .iter()
                .map(|r| ClientDirectoryPeerProto {
                    username: r.username.clone(),
                    display_name: r.display_name.clone(),
                    key_version: 1,
                    transparency_seq: 1,
                    ed25519_pub_hex_short: String::new(),
                    x25519_pub_hex_short: String::new(),
                    device_number: r.device_number,
                    vault_version: r.vault_version.load(Ordering::Relaxed),
                })
                .collect();
            peers.sort_by(|a, b| a.username.cmp(&b.username));

            let (dname, dev_num, v_ver) = state
                .client_enclaves
                .get(&norm)
                .map_or((String::new(), 1, 1), |e| {
                    (
                        e.display_name.clone(),
                        e.device_number,
                        e.vault_version.load(Ordering::Relaxed),
                    )
                });

            let (l1_hits, l2_reads, disk_commits, records_written) =
                state.disk_storage.as_ref().map_or((0, 0, 0, 0), |s| {
                    let m = s.metrics();
                    (
                        m.l1_cache_hits,
                        m.l2_disk_reads,
                        m.disk_group_commits,
                        m.disk_records_written,
                    )
                });

            ClientWireResponseProto {
                ok: true,
                username: norm,
                display_name: dname,
                device_number: dev_num,
                vault_version: v_ver,
                storage_l1_hits: l1_hits,
                storage_l2_reads: l2_reads,
                storage_disk_commits: disk_commits,
                storage_records_written: records_written,
                absorbed_sidecar_failures: state.gateway.absorbed_sidecar_failures(),
                peers,
                ..ClientWireResponseProto::default()
            }
        }
        Some(ClientWireOp::SearchDirectory) => {
            let caller_norm = state.resolve_identifier(&req.caller_username);
            let Some(caller) = state.client_enclaves.get(&caller_norm).map(|r| Arc::clone(&*r))
            else {
                return proto_err_resp("Актор не найден");
            };
            let prefix = req
                .search_query
                .trim()
                .trim_start_matches('@')
                .to_ascii_lowercase();

            if !prefix.is_empty()
                && let Some(storage) = &state.disk_storage
            {
                let _ = storage.get_directory_entry_by_username(state.tenant_id, &prefix);
            }

            let mut peers = Vec::new();
            let search_prefix = if prefix.is_empty() { "a" } else { &prefix };
            if prefix.is_empty() {
                for l in 'a'..='z' {
                    let s = l.to_string();
                    if let Ok(resp) = state.gateway.handle_search_users(
                        &caller.active_token,
                        &s,
                        50,
                        now_ms,
                    ) {
                        for entry in resp.entries {
                            if let Some(bundle) = &entry.public_key_bundle {
                                caller
                                    .peer_bundles
                                    .insert(entry.username.clone(), bundle.clone());
                                let ed_hex = bytes_to_hex(&bundle.ed25519_verifying_key);
                                let x_hex = bytes_to_hex(&bundle.x25519_public_key);
                                peers.push(ClientDirectoryPeerProto {
                                    username: entry.username,
                                    display_name: entry.display_name,
                                    key_version: bundle.key_version,
                                    transparency_seq: entry.transparency_seq,
                                    ed25519_pub_hex_short: ed_hex[..16.min(ed_hex.len())]
                                        .to_string(),
                                    x25519_pub_hex_short: x_hex[..16.min(x_hex.len())].to_string(),
                                    device_number: 1,
                                    vault_version: 1,
                                });
                            }
                        }
                    }
                }
            } else {
                match state.gateway.handle_search_users(
                    &caller.active_token,
                    search_prefix,
                    50,
                    now_ms,
                ) {
                    Ok(resp) => {
                        for entry in resp.entries {
                            if let Some(bundle) = &entry.public_key_bundle {
                                caller
                                    .peer_bundles
                                    .insert(entry.username.clone(), bundle.clone());
                                let ed_hex = bytes_to_hex(&bundle.ed25519_verifying_key);
                                let x_hex = bytes_to_hex(&bundle.x25519_public_key);
                                peers.push(ClientDirectoryPeerProto {
                                    username: entry.username,
                                    display_name: entry.display_name,
                                    key_version: bundle.key_version,
                                    transparency_seq: entry.transparency_seq,
                                    ed25519_pub_hex_short: ed_hex[..16.min(ed_hex.len())]
                                        .to_string(),
                                    x25519_pub_hex_short: x_hex[..16.min(x_hex.len())].to_string(),
                                    device_number: 1,
                                    vault_version: 1,
                                });
                            }
                        }
                    }
                    Err(e) => return proto_err_resp(e.to_string()),
                }
            }

            ClientWireResponseProto {
                ok: true,
                peers,
                ..ClientWireResponseProto::default()
            }
        }
        Some(ClientWireOp::SendChatMessage) => {
            let sender_norm = state.resolve_identifier(&req.caller_username);
            let recipient_norm = state.resolve_identifier(&req.peer_username);

            let Some(sender) = state.client_enclaves.get(&sender_norm).map(|r| Arc::clone(&*r))
            else {
                return proto_err_resp("Отправитель не найден");
            };

            let peer_bundle = if let Some(b) = sender.peer_bundles.get(&recipient_norm) {
                b.value().clone()
            } else if let Some(storage) = &state.disk_storage
                && let Ok(Some(entry)) =
                    storage.get_directory_entry_by_username(state.tenant_id, &recipient_norm)
                && let Some(b) = &entry.public_key_bundle
            {
                sender
                    .peer_bundles
                    .insert(recipient_norm.clone(), b.clone());
                b.clone()
            } else if let Some(recip_enclave) = state.client_enclaves.get(&recipient_norm) {
                let Ok(b) = recip_enclave.identity.export_public_bundle() else {
                    return proto_err_resp("Ошибка экспорта ключей получателя");
                };
                sender
                    .peer_bundles
                    .insert(recipient_norm.clone(), b.clone());
                b
            } else {
                return proto_err_resp("Получатель не найден");
            };

            if !sender.sessions.contains_key(&recipient_norm) {
                let Ok(new_session) = ChatSession::establish_direct(
                    &sender.identity,
                    &peer_bundle,
                    EncryptionPolicy::StrictZeroKnowledge,
                    None,
                ) else {
                    return proto_err_resp("Не удалось установить X25519 E2EE сессию");
                };
                sender.sessions.insert(recipient_norm.clone(), new_session);
            }

            let Some(mut session_ref) = sender.sessions.get_mut(&recipient_norm) else {
                return proto_err_resp("Сессия чата не найдена");
            };
            let Ok(envelope) = session_ref.encrypt_message(
                &sender.identity,
                &XChaCha20Poly1305Provider,
                req.plaintext_message.as_bytes(),
            ) else {
                return proto_err_resp("Ошибка шифрования XChaCha20-Poly1305");
            };
            drop(session_ref);

            let token_wire = sender.active_token.to_wire_bytes();
            let env_wire = envelope.to_wire_bytes();
            let wire_len = env_wire.len() as u32;

            if let Err(e) = state
                .gateway
                .handle_send_message_wire(&token_wire, &env_wire, now_ms)
            {
                return proto_err_resp(e.to_string());
            }

            if let Some(storage) = &state.disk_storage {
                let _ = storage.commit_messages_batch(std::slice::from_ref(&envelope));
            }

            // Авто-обновление облачного сейфа ключей
            if let Some(sess_ref) = sender.sessions.get(&recipient_norm) {
                let next_ver = sender
                    .vault_version
                    .fetch_add(1, Ordering::SeqCst)
                    .saturating_add(1);
                if let Ok(updated_blob) = CloudKeyVault::seal_to_cloud_blob(
                    &sender.identity,
                    &[sess_ref.value()],
                    DEMO_PASSWORD,
                    next_ver,
                    LivePrototypeState::fast_argon_profile(),
                ) {
                    if !state.auth_down.load(Ordering::Relaxed) {
                        let _ = state.gateway.auth_service().push_vault_update(
                            &sender.active_token,
                            updated_blob.clone(),
                            now_ms + 1,
                        );
                    }
                    if let Some(storage) = &state.disk_storage {
                        let _ = storage.put_vault_blob(&updated_blob);
                    }
                }
            }

            state.broadcast_proto_ws_event("new_message", &sender_norm, &recipient_norm, wire_len);
            let _ = state.ws_event_bus.send(
                serde_json::json!({
                    "type": "new_message",
                    "sender": sender_norm,
                    "recipient": recipient_norm,
                    "wire_bytes": wire_len,
                })
                .to_string(),
            );

            ClientWireResponseProto {
                ok: true,
                wire_bytes_len: wire_len,
                ratchet_step: envelope.ratchet_step,
                ..ClientWireResponseProto::default()
            }
        }
        Some(ClientWireOp::FetchChatHistory) => {
            let caller_norm = state.resolve_identifier(&req.caller_username);
            let peer_norm = state.resolve_identifier(&req.peer_username);

            let Some(caller) = state.client_enclaves.get(&caller_norm).map(|r| Arc::clone(&*r))
            else {
                return proto_err_resp("Актор не найден");
            };

            let peer_bundle = if let Some(b) = caller.peer_bundles.get(&peer_norm) {
                b.value().clone()
            } else if let Some(storage) = &state.disk_storage
                && let Ok(Some(entry)) =
                    storage.get_directory_entry_by_username(state.tenant_id, &peer_norm)
                && let Some(b) = &entry.public_key_bundle
            {
                caller.peer_bundles.insert(peer_norm.clone(), b.clone());
                b.clone()
            } else if let Some(peer_enclave) = state.client_enclaves.get(&peer_norm) {
                let Ok(b) = peer_enclave.identity.export_public_bundle() else {
                    return proto_err_resp("Ошибка экспорта ключей собеседника");
                };
                caller.peer_bundles.insert(peer_norm.clone(), b.clone());
                b
            } else {
                return proto_err_resp("Собеседник не найден");
            };

            if !caller.sessions.contains_key(&peer_norm)
                && let Ok(new_session) = ChatSession::establish_direct(
                    &caller.identity,
                    &peer_bundle,
                    EncryptionPolicy::StrictZeroKnowledge,
                    None,
                )
            {
                caller.sessions.insert(peer_norm.clone(), new_session);
            }

            let Some(session_ref) = caller.sessions.get(&peer_norm) else {
                return proto_err_resp("Не удалось инициализировать E2EE сессию");
            };
            let channel_id = session_ref.channel_id();
            let peer_user_id = session_ref.peer_user_id();

            let Ok(mut history_page) = state.gateway.handle_fetch_history(
                &caller.active_token,
                channel_id,
                None,
                50,
                now_ms,
            ) else {
                return proto_err_resp("Ошибка чтения истории чата");
            };

            if history_page.envelopes.is_empty()
                && let Some(storage) = &state.disk_storage
                && let Ok(disk_page) =
                    storage.fetch_channel_history_from_disk(state.tenant_id, channel_id, None, 50)
            {
                history_page = disk_page;
            }

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

            let mut messages = Vec::with_capacity(history_page.envelopes.len());
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
                    peer_norm.clone()
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

                messages.push(ClientDecryptedMessageItemProto {
                    sender_username: sender_uname,
                    ratchet_step: env.ratchet_step,
                    message_id_short: mid_hex[..12.min(mid_hex.len())].to_string(),
                    timestamp_ms: msg_ts_ms,
                    is_read_by_peer,
                    decrypted_text,
                    wire_bytes_len: env.to_wire_bytes().len() as u32,
                    nonce_hex: bytes_to_hex(&env.nonce),
                    ciphertext_hex: ct_hex,
                    signature_hex_short: sig_hex[..24.min(sig_hex.len())].to_string(),
                });
            }

            ClientWireResponseProto {
                ok: true,
                channel_id_hex: bytes_to_hex(channel_id.as_bytes()),
                messages,
                ..ClientWireResponseProto::default()
            }
        }
        Some(ClientWireOp::MarkChatRead) => {
            let caller_norm = state.resolve_identifier(&req.caller_username);
            let peer_norm = state.resolve_identifier(&req.peer_username);

            let Some(caller) = state.client_enclaves.get(&caller_norm).map(|r| Arc::clone(&*r))
            else {
                return proto_err_resp("Актор не найден");
            };
            let Some(peer_enclave) = state.client_enclaves.get(&peer_norm).map(|r| Arc::clone(&*r))
            else {
                return proto_err_resp("Собеседник не найден");
            };

            let channel_id = ChannelId::deterministic_direct(
                state.tenant_id,
                caller.identity.user_id(),
                peer_enclave.identity.user_id(),
            );

            let mut history_page = state
                .gateway
                .handle_fetch_history(&caller.active_token, channel_id, None, 10, now_ms)
                .unwrap_or(cryptox_proto::ChannelHistoryPageProto {
                    channel_id: channel_id.to_vec(),
                    envelopes: Vec::new(),
                    next_before_cursor: Vec::new(),
                    has_more: false,
                });

            if history_page.envelopes.is_empty()
                && let Some(storage) = &state.disk_storage
                && let Ok(disk_page) =
                    storage.fetch_channel_history_from_disk(state.tenant_id, channel_id, None, 10)
            {
                history_page = disk_page;
            }

            if let Some(last_env) = history_page.envelopes.last()
                && let Ok(last_msg_id) = MessageId::from_slice(&last_env.message_id)
            {
                let _ = state.gateway.presence_service().record_read_receipt(
                    &caller.active_token,
                    channel_id,
                    last_msg_id,
                    now_ms,
                );
                if let Some(storage) = &state.disk_storage {
                    let wm = ReadReceiptWatermarkProto {
                        tenant_id: state.tenant_id.to_vec(),
                        channel_id: channel_id.to_vec(),
                        user_id: caller.identity.user_id().to_vec(),
                        last_read_message_id: last_msg_id.to_vec(),
                        updated_at_ms: now_ms,
                    };
                    let _ = storage.flush_watermarks_batch(&[wm]);
                }
                state.broadcast_proto_ws_event("read_receipt", &caller_norm, &peer_norm, 0);
            }

            ClientWireResponseProto {
                ok: true,
                ..ClientWireResponseProto::default()
            }
        }
        Some(ClientWireOp::CloudSyncNewDevice) => {
            let norm = state.resolve_identifier(&req.caller_username);
            let Some(old_ref) = state.client_enclaves.get(&norm) else {
                return proto_err_resp("Сотрудник не найден");
            };
            let old_enclave = Arc::clone(old_ref.value());
            drop(old_ref);

            let Ok((restored_identity, restored_sessions_vec)) =
                CloudKeyVault::unlock_from_cloud_blob(
                    &old_enclave.recovery_vault_blob,
                    old_enclave.recovery_key.as_bytes(),
                    DeviceId::new_v7(),
                    EncryptionPolicy::StrictZeroKnowledge,
                    None,
                )
            else {
                return proto_err_resp("Не удалось расшифровать CloudKeyVault для нового устройства");
            };

            let new_sessions_map = DashMap::new();
            for s in restored_sessions_vec {
                for item in &old_enclave.sessions {
                    if item.value().channel_id() == s.channel_id() {
                        new_sessions_map.insert(item.key().clone(), s);
                        break;
                    }
                }
            }

            let new_dev_num = old_enclave.device_number.saturating_add(1);
            let v_ver = old_enclave.vault_version.load(Ordering::Relaxed);
            let new_enclave = Arc::new(ClientDeviceEnclave {
                username: old_enclave.username.clone(),
                display_name: old_enclave.display_name.clone(),
                identity: restored_identity,
                active_token: old_enclave.active_token.clone(),
                device_number: new_dev_num,
                vault_version: AtomicU64::new(v_ver),
                recovery_key: old_enclave.recovery_key.clone(),
                recovery_vault_blob: old_enclave.recovery_vault_blob.clone(),
                sessions: new_sessions_map,
                peer_bundles: old_enclave.peer_bundles.clone(),
            });
            state.client_enclaves.insert(norm.clone(), new_enclave);

            ClientWireResponseProto {
                ok: true,
                username: norm,
                device_number: new_dev_num,
                vault_version: v_ver,
                wire_bytes_len: old_enclave.recovery_vault_blob.to_wire_bytes().len() as u32,
                ..ClientWireResponseProto::default()
            }
        }
        Some(ClientWireOp::CheckUsername) => {
            let norm = req
                .caller_username
                .trim()
                .trim_start_matches('@')
                .to_lowercase();
            if norm.len() < 3 {
                return proto_err_resp("Минимум 3 символа");
            }
            if norm.len() > 32
                || !norm
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
            {
                return proto_err_resp("Только латиница, цифры и _ . -");
            }
            if state.client_enclaves.contains_key(&norm) {
                return proto_err_resp("Имя пользователя уже занято");
            }
            ClientWireResponseProto {
                ok: true,
                username: norm,
                ..ClientWireResponseProto::default()
            }
        }
        None | Some(ClientWireOp::Unspecified) => proto_err_resp("Неизвестный код операции Protobuf"),
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
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
}

async fn api_register_user(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<RegisterReqDto>,
) -> impl IntoResponse {
    let clean_email = req.email.trim().to_ascii_lowercase();
    if !clean_email.is_empty() && (!clean_email.contains('@') || !clean_email.contains('.')) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Укажите корректный адрес электронной почты" })),
        );
    }
    if !clean_email.is_empty() && state.email_to_username.contains_key(&clean_email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Аккаунт с такой электронной почтой уже зарегистрирован" })),
        );
    }

    match state.onboard_employee_enclave_with_password(
        &req.username,
        &req.display_name,
        req.password.as_bytes(),
    ) {
        Ok((uname, recovery_key)) => {
            if !clean_email.is_empty() {
                state.email_to_username.insert(clean_email.clone(), uname.clone());
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "username": uname,
                    "email": clean_email,
                    "display_name": req.display_name,
                    "recovery_key": recovery_key,
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

#[derive(Deserialize)]
pub struct AuthLoginReqDto {
    pub username: String,
    #[serde(default)]
    pub password: String,
}

async fn api_auth_login(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<AuthLoginReqDto>,
) -> impl IntoResponse {
    let now_ms = LivePrototypeState::now_ms();
    if req.password.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Введите пароль от аккаунта" })),
        );
    }
    let norm = state.resolve_identifier(&req.username);

    let Some(enclave_ref) = state.client_enclaves.get(&norm) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Аккаунт с таким логином или почтой не найден" })),
        );
    };
    let display_name = enclave_ref.display_name.clone();
    drop(enclave_ref);

    let effective_pwd = req.password.as_bytes();

    let ch = match state
        .gateway
        .auth_service()
        .issue_login_challenge(state.tenant_id, &norm, now_ms)
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": e.to_string() })),
            );
        }
    };

    let device_id = DeviceId::new_v7();
    let Ok(verify_req) = CloudKeyVault::sign_login_challenge(&ch, effective_pwd, device_id) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Ошибка крипто-подписи вызова входа" })),
        );
    };

    match state
        .gateway
        .auth_service()
        .verify_login_and_fetch_vault(&verify_req, now_ms + 1)
    {
        Ok((_tok, _vault)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "username": norm,
                "display_name": display_name,
            })),
        ),
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": format!("Неверный пароль или аккаунт заблокирован: {e}") })),
        ),
    }
}

#[derive(Deserialize)]
pub struct AuthSsoReqDto {
    pub domain: String,
    pub email: String,
}

async fn api_auth_sso(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<AuthSsoReqDto>,
) -> impl IntoResponse {
    let clean_domain = req.domain.trim().to_ascii_lowercase();
    let clean_email = req.email.trim().to_ascii_lowercase();
    if clean_domain.len() < 4 || !clean_domain.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Укажите корпоративный домен (например, company.ru)" })),
        );
    }
    if clean_email.len() < 3 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Укажите рабочую почту или корпоративный логин" })),
        );
    }

    let resolved = state.resolve_identifier(&clean_email);
    let candidate_uname = resolved
        .split('@')
        .next()
        .unwrap_or(&resolved)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();

    if let Some(existing) = state.client_enclaves.get(&candidate_uname) {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "username": existing.username,
                "display_name": existing.display_name,
                "domain": clean_domain,
            })),
        );
    }

    // JIT-провижининг нового корпоративного сотрудника через SSO контур организации
    let display = format!("{candidate_uname} ({clean_domain})");
    match state.onboard_employee_enclave_with_password(&candidate_uname, &display, DEMO_PASSWORD) {
        Ok((uname, recovery_key)) => {
            if clean_email.contains('@') {
                state.email_to_username.insert(clean_email, uname.clone());
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "username": uname,
                    "display_name": display,
                    "domain": clean_domain,
                    "recovery_key": recovery_key,
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

#[derive(Deserialize)]
pub struct AuthRecoverPasswordReqDto {
    pub username: String,
    pub recovery_key: String,
    pub new_password: String,
}

async fn api_auth_recover_password(
    State(state): State<Arc<LivePrototypeState>>,
    Json(req): Json<AuthRecoverPasswordReqDto>,
) -> impl IntoResponse {
    let norm = state.resolve_identifier(&req.username);
    let clean_rec = req.recovery_key.trim().to_ascii_uppercase();
    if req.new_password.trim().len() < 6 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Новый пароль должен содержать минимум 6 символов" })),
        );
    }

    let Some(old_ref) = state.client_enclaves.get(&norm) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Аккаунт с таким @username не найден" })),
        );
    };
    let old_enclave = Arc::clone(old_ref.value());
    drop(old_ref);

    // Zero-Knowledge проверка Ключа Восстановления: пытаемся расшифровать резервный сейф `recovery_vault_blob`!
    let new_device_id = DeviceId::new_v7();
    let Ok((recovered_identity, _)) = CloudKeyVault::unlock_from_cloud_blob(
        &old_enclave.recovery_vault_blob,
        clean_rec.as_bytes(),
        new_device_id,
        EncryptionPolicy::StrictZeroKnowledge,
        None,
    ) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Неверный ключ восстановления (не удалось расшифровать резервный крипто-сейф)"
            })),
        );
    };

    let next_ver = old_enclave
        .vault_version
        .load(Ordering::SeqCst)
        .saturating_add(1);
    let profile = LivePrototypeState::fast_argon_profile();

    let Ok(new_vault_blob) = CloudKeyVault::seal_to_cloud_blob(
        &recovered_identity,
        &[],
        req.new_password.as_bytes(),
        next_ver,
        profile,
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Ошибка перешифрования сейфа" })),
        );
    };

    let Ok(new_auth_vk) = CloudKeyVault::derive_auth_verifying_key(
        req.new_password.as_bytes(),
        &new_vault_blob.argon2_salt,
        profile,
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Ошибка генерации нового ключа входа" })),
        );
    };

    if let Err(e) = state.gateway.auth_service().rotate_password_and_vault(
        state.tenant_id,
        &norm,
        &new_auth_vk,
        new_vault_blob.clone(),
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        );
    }

    if let Some(storage) = &state.disk_storage {
        let _ = storage.put_vault_blob(&new_vault_blob);
    }
    old_enclave.vault_version.store(next_ver, Ordering::SeqCst);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "username": norm,
            "vault_version": next_ver,
            "message": "Пароль успешно сброшен, облачный сейф перешифрован без потери чатов!"
        })),
    )
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
        recovery_key: old_enclave.recovery_key.clone(),
        recovery_vault_blob: old_enclave.recovery_vault_blob.clone(),
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
    let now_ms = LivePrototypeState::now_ms();
    match req.service.as_str() {
        "auth" => {
            state.auth_down.store(req.outage, Ordering::SeqCst);
            state.gateway.auth_service().set_simulated_outage(req.outage);
            if req.outage {
                state.gateway.auth_circuit_breaker().force_trip_open(now_ms);
            } else {
                state
                    .gateway
                    .auth_circuit_breaker()
                    .force_auto_heal_closed();
            }
        }
        "directory" => {
            state.directory_down.store(req.outage, Ordering::SeqCst);
            state
                .gateway
                .directory_service()
                .set_simulated_outage(req.outage);
            if req.outage {
                state
                    .gateway
                    .directory_circuit_breaker()
                    .force_trip_open(now_ms);
            } else {
                state
                    .gateway
                    .directory_circuit_breaker()
                    .force_auto_heal_closed();
            }
        }
        "presence" => {
            state.presence_down.store(req.outage, Ordering::SeqCst);
            state
                .gateway
                .presence_service()
                .set_simulated_outage(req.outage);
            if req.outage {
                state
                    .gateway
                    .presence_circuit_breaker()
                    .force_trip_open(now_ms);
            } else {
                state
                    .gateway
                    .presence_circuit_breaker()
                    .force_auto_heal_closed();
            }
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

async fn api_status_overview(State(state): State<Arc<LivePrototypeState>>) -> impl IntoResponse {
    let gw = &state.gateway;
    let auth_down = state.auth_down.load(Ordering::Relaxed);
    let dir_down = state.directory_down.load(Ordering::Relaxed);
    let pres_down = state.presence_down.load(Ordering::Relaxed);

    let msg_cb = gw.messaging_circuit_breaker();
    let auth_cb = gw.auth_circuit_breaker();
    let dir_cb = gw.directory_circuit_breaker();
    let pres_cb = gw.presence_circuit_breaker();

    let (l1_hits, l2_reads, disk_commits, records_written) =
        state.disk_storage.as_ref().map_or((0, 0, 0, 0), |s| {
            let m = s.metrics();
            (
                m.l1_cache_hits,
                m.l2_disk_reads,
                m.disk_group_commits,
                m.disk_records_written,
            )
        });

    let total_auto_heals = msg_cb.auto_heal_count()
        + auth_cb.auto_heal_count()
        + dir_cb.auto_heal_count()
        + pres_cb.auto_heal_count();

    let overall_status = if auth_down || dir_down || pres_down {
        "PARTIAL_SIDECAR_OUTAGE_HOTPATH_OK"
    } else {
        "OPERATIONAL"
    };

    let services = serde_json::json!([
        {
            "id": "edge-gateway",
            "name": "edge-gateway (:8080)",
            "tier_label": "CRITICAL ENTRY",
            "is_critical_hotpath": true,
            "description": "Периметровый шлюз, WebSocket-мультиплексор, AutonomousTokenVerifier и Rate-Limiter",
            "protocol": "Axum HTTP/1.1 + WebSocket /ws",
            "operational": true,
            "circuit_state": "CLOSED",
            "circuit_trips": 0,
            "circuit_heals": 0,
            "can_toggle_chaos": false,
            "chaos_key": ""
        },
        {
            "id": "messaging-svc",
            "name": "messaging-svc (:50051)",
            "tier_label": "HOT-PATH CORE",
            "is_critical_hotpath": true,
            "description": "Маршрутизация E2EE конвертов, идемпотентная дедупликация и курсорная история UUIDv7",
            "protocol": "Zero-Trust TCP RPC (XChaCha20-Poly1305 + Ed25519)",
            "operational": msg_cb.state() != crate::cluster_mesh::CircuitState::Open,
            "circuit_state": msg_cb.state().as_str(),
            "circuit_trips": msg_cb.trip_count(),
            "circuit_heals": msg_cb.auto_heal_count(),
            "can_toggle_chaos": false,
            "chaos_key": ""
        },
        {
            "id": "cryptox-storage",
            "name": "cryptox-storage (redb SSD)",
            "tier_label": "ENCRYPTED STORAGE",
            "is_critical_hotpath": true,
            "description": "ACID B+Tree хранилище с шифрованием AES-256-GCM и слепым индексом BLAKE3",
            "protocol": "L1 DashMap RAM + L2 redb AES-256-GCM",
            "operational": true,
            "circuit_state": "CLOSED",
            "circuit_trips": 0,
            "circuit_heals": 0,
            "can_toggle_chaos": false,
            "chaos_key": ""
        },
        {
            "id": "auth-vault-svc",
            "name": "auth-vault-svc (:50052)",
            "tier_label": "BULKHEAD SIDECAR",
            "is_critical_hotpath": false,
            "description": "Zero-Knowledge регистрация, одноразовые челленджи входа и облачный сейф ключей Argon2id",
            "protocol": "Zero-Trust TCP RPC • Isolated Bulkhead",
            "operational": !auth_down,
            "circuit_state": auth_cb.state().as_str(),
            "circuit_trips": auth_cb.trip_count(),
            "circuit_heals": auth_cb.auto_heal_count(),
            "can_toggle_chaos": true,
            "chaos_key": "auth"
        },
        {
            "id": "user-directory-svc",
            "name": "user-directory-svc (:50053)",
            "tier_label": "BULKHEAD SIDECAR",
            "is_critical_hotpath": false,
            "description": "Поиск коллег по @username на 100 000 сотрудников и цепочка Key Transparency BLAKE3",
            "protocol": "Zero-Trust TCP RPC • Isolated Bulkhead",
            "operational": !dir_down,
            "circuit_state": dir_cb.state().as_str(),
            "circuit_trips": dir_cb.trip_count(),
            "circuit_heals": dir_cb.auto_heal_count(),
            "can_toggle_chaos": true,
            "chaos_key": "directory"
        },
        {
            "id": "presence-receipts-svc",
            "name": "presence-receipts-svc (:50054)",
            "tier_label": "BULKHEAD SIDECAR",
            "is_critical_hotpath": false,
            "description": "Онлайн-статусы и коалесцирующие галочки прочтения (Discord Read States Architecture)",
            "protocol": "Zero-Trust TCP RPC • Isolated Bulkhead",
            "operational": !pres_down,
            "circuit_state": pres_cb.state().as_str(),
            "circuit_trips": pres_cb.trip_count(),
            "circuit_heals": pres_cb.auto_heal_count(),
            "can_toggle_chaos": true,
            "chaos_key": "presence"
        }
    ]);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "overall_status": overall_status,
            "services": services,
            "metrics": {
                "hotpath_messages_routed": gw.hotpath_messages_routed(),
                "absorbed_sidecar_failures": gw.absorbed_sidecar_failures(),
                "zero_trust_intrusions_blocked": gw.zero_trust_intrusions_blocked(),
                "rate_limited_requests_blocked": gw.rate_limited_requests_blocked(),
                "total_circuit_auto_heals": total_auto_heals,
                "storage_l1_hits": l1_hits,
                "storage_l2_reads": l2_reads,
                "storage_disk_commits": disk_commits,
                "storage_records_written": records_written,
            }
        })),
    )
}

async fn api_status_probe_hotpath(
    State(state): State<Arc<LivePrototypeState>>,
) -> impl IntoResponse {
    let now_ms = LivePrototypeState::now_ms();
    let Some(alice) = state.client_enclaves.get("alice_ceo").map(|r| Arc::clone(&*r)) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "alice_ceo enclave not found" })),
        );
    };
    let Some(bob) = state
        .client_enclaves
        .get("bob_architect")
        .map(|r| Arc::clone(&*r))
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "bob_architect enclave not found" })),
        );
    };

    let Ok(bob_bundle) = bob.identity.export_public_bundle() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "bob bundle export failed" })),
        );
    };

    if !alice.sessions.contains_key("bob_architect")
        && let Ok(sess) = ChatSession::establish_direct(
            &alice.identity,
            &bob_bundle,
            EncryptionPolicy::StrictZeroKnowledge,
            None,
        )
    {
        alice.sessions.insert("bob_architect".to_string(), sess);
    }

    let Some(mut sess) = alice.sessions.get_mut("bob_architect") else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "session missing" })),
        );
    };

    let Ok(env) = sess.encrypt_message(
        &alice.identity,
        &XChaCha20Poly1305Provider,
        b"[NOC Status Probe] Hot-Path E2EE packet verified!",
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "encrypt failed" })),
        );
    };

    let wire = env.to_wire_bytes();
    let wire_len = wire.len();
    match state
        .gateway
        .handle_send_message_wire(&alice.active_token.to_wire_bytes(), &wire, now_ms)
    {
        Ok(_) => {
            if let Some(storage) = &state.disk_storage {
                let _ = storage.commit_messages_batch(&[env]);
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "wire_bytes": wire_len,
                    "absorbed_sidecar_failures": state.gateway.absorbed_sidecar_failures(),
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn api_status_simulate_attack(
    State(state): State<Arc<LivePrototypeState>>,
) -> impl IntoResponse {
    state.gateway.record_zero_trust_intrusion_blocked();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "intrusions_blocked": state.gateway.zero_trust_intrusions_blocked(),
        })),
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
