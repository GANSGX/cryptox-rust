//! `edge-gateway` — Сетевой щит и точка входа клиентов с жесткой изоляцией отказов (Bulkhead Pattern).
//!
//! Главный архитектурный инвариант (Правило 02: `02-rust-microservices-bulkhead.md`):
//! - **Hot Path (Критический контур чатов):** `send_wire_envelope`, `fetch_history_wire`, `subscribe_realtime`
//!   идут напрямую через `AutonomousTokenVerifier` и `MessagingService`.
//! - Второстепенные сервисы (`auth-vault-svc`, `user-directory-svc`, `presence-receipts-svc`)
//!   изолированы предохранителями (`Circuit Breaker / Non-Blocking Sidecar`).
//! - Даже если одновременно упадут **ВСЕ ТРИ** второстепенных сервиса (`auth-vault-svc` DOWN,
//!   `user-directory-svc` DOWN, `presence-receipts-svc` DOWN), все активные сотрудники продолжают
//!   обмениваться сообщениями в риалтайме и синхронизировать историю чатов через `edge-gateway`!

pub mod http_server;

use auth_vault_svc::{AuthVaultError, AuthVaultService, AutonomousTokenVerifier};
use cryptox_proto::{
    ChannelHistoryPageProto, ChannelId, EncryptedEnvelope, MessageId, ProtoError,
    SearchUsersResponse, SendMessageAckProto, SignedSessionToken, TenantId, UserId,
};
use dashmap::DashMap;
use messaging_svc::{MessagingError, MessagingService};
use presence_receipts_svc::{PresenceError, PresenceReceiptsService};
use prost::Message;
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc,
};
use thiserror::Error;
use tokio::sync::broadcast;
use user_directory_svc::{DirectoryError, UserDirectoryService};

/// Лимит запросов по умолчанию на одного сотрудника в секунду (защита от спама и DoS по OWASP ASVS V4/V13).
pub const DEFAULT_RATE_LIMIT_PER_WINDOW: u32 = 1_000;
pub const DEFAULT_RATE_LIMIT_WINDOW_MS: u64 = 1_000;
pub const MAX_RATE_LIMIT_TRACKED_USERS: usize = 131_072;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatewayError {
    #[error("ошибка бинарного протокола: {0}")]
    Proto(#[from] ProtoError),

    #[error("ошибка авторизации: {0}")]
    Auth(#[from] AuthVaultError),

    #[error("ошибка каталога пользователей: {0}")]
    Directory(#[from] DirectoryError),

    #[error("ошибка сервиса статусов: {0}")]
    Presence(#[from] PresenceError),

    #[error("ошибка контура доставки сообщений: {0}")]
    Messaging(#[from] MessagingError),

    #[error("превышен лимит частоты запросов сотрудника на шлюзе (Rate-Limit / Anti-DDoS Shield)")]
    RateLimitExceeded,
}

#[derive(Clone, Copy, Debug)]
struct UserRateWindow {
    window_start_ms: u64,
    count_in_window: u32,
}

pub struct EdgeGateway {
    verifier: AutonomousTokenVerifier,
    /// Критический контур (Hot Path).
    messaging_svc: Arc<MessagingService>,
    /// Изолированные Bulkhead-отсеки (Sidecars).
    auth_svc: Arc<AuthVaultService>,
    directory_svc: Arc<UserDirectoryService>,
    presence_svc: Arc<PresenceReceiptsService>,
    /// Счетчик поглощенных ошибок второстепенных сервисов (когда sidecar упал, но чат не прервался).
    absorbed_sidecar_failures: AtomicU64,
    /// Шардированный Rate-Limiter по `(TenantId, UserId)`.
    rate_limiter: DashMap<(TenantId, UserId), UserRateWindow>,
    rate_limit_max_per_window: AtomicU32,
    rate_limit_window_ms: AtomicU64,
}

impl EdgeGateway {
    #[must_use]
    pub fn new(
        auth_svc: Arc<AuthVaultService>,
        directory_svc: Arc<UserDirectoryService>,
        presence_svc: Arc<PresenceReceiptsService>,
        messaging_svc: Arc<MessagingService>,
    ) -> Self {
        let verifier = auth_svc.export_autonomous_verifier();
        Self {
            verifier,
            messaging_svc,
            auth_svc,
            directory_svc,
            presence_svc,
            absorbed_sidecar_failures: AtomicU64::new(0),
            rate_limiter: DashMap::with_capacity(16_384),
            rate_limit_max_per_window: AtomicU32::new(DEFAULT_RATE_LIMIT_PER_WINDOW),
            rate_limit_window_ms: AtomicU64::new(DEFAULT_RATE_LIMIT_WINDOW_MS),
        }
    }

    /// Настраивает квоту `Rate-Limiter` на одного сотрудника (`max_requests` за `window_ms`).
    pub fn configure_rate_limit(&self, max_requests: u32, window_ms: u64) {
        self.rate_limit_max_per_window
            .store(max_requests.max(1), Ordering::SeqCst);
        self.rate_limit_window_ms
            .store(window_ms.max(1), Ordering::SeqCst);
        self.rate_limiter.clear();
    }

    /// Проверяет квоту частоты запросов сотрудника за O(1) в шардированном `DashMap` (< 200 нс).
    pub fn enforce_rate_limit(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        now_ms: u64,
    ) -> Result<(), GatewayError> {
        let max_reqs = self.rate_limit_max_per_window.load(Ordering::Relaxed);
        let win_ms = self.rate_limit_window_ms.load(Ordering::Relaxed);

        if self.rate_limiter.len() >= MAX_RATE_LIMIT_TRACKED_USERS {
            self.rate_limiter
                .retain(|_, w| now_ms.saturating_sub(w.window_start_ms) < win_ms);
        }

        let mut entry = self
            .rate_limiter
            .entry((tenant_id, user_id))
            .or_insert(UserRateWindow {
                window_start_ms: now_ms,
                count_in_window: 0,
            });

        let w = entry.value_mut();
        if now_ms.saturating_sub(w.window_start_ms) >= win_ms {
            w.window_start_ms = now_ms;
            w.count_in_window = 1;
            return Ok(());
        }

        if w.count_in_window >= max_reqs {
            return Err(GatewayError::RateLimitExceeded);
        }

        w.count_in_window = w.count_in_window.saturating_add(1);
        Ok(())
    }

    #[must_use]
    pub fn absorbed_sidecar_failures(&self) -> u64 {
        self.absorbed_sidecar_failures.load(Ordering::Relaxed)
    }

    #[must_use]
    pub const fn auth_service(&self) -> &Arc<AuthVaultService> {
        &self.auth_svc
    }

    #[must_use]
    pub const fn directory_service(&self) -> &Arc<UserDirectoryService> {
        &self.directory_svc
    }

    #[must_use]
    pub const fn presence_service(&self) -> &Arc<PresenceReceiptsService> {
        &self.presence_svc
    }

    #[must_use]
    pub const fn messaging_service(&self) -> &Arc<MessagingService> {
        &self.messaging_svc
    }

    /// **HOT PATH №1:** Принимает сырые бинарные фреймы `SignedSessionToken` и `EncryptedEnvelope`
    /// из WebSocket / QUIC сокета, маршрутизирует сообщение в `messaging-svc` и возвращает бинарный `SendMessageAckProto`.
    ///
    /// При этом попытка обновить онлайн-хартбит и водораздел прочтения в `presence-receipts-svc`
    /// выполняется через **Bulkhead Circuit Breaker**: если `presence-receipts-svc` упал, ошибка
    /// поглощается без влияния на отправку сообщения!
    pub fn handle_send_message_wire(
        &self,
        token_wire: &[u8],
        envelope_wire: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>, GatewayError> {
        let token = SignedSessionToken::from_wire_bytes(token_wire)?;
        let claims = self.verifier.verify_token(&token, now_ms)?;
        self.enforce_rate_limit(claims.tenant_id, claims.user_id, now_ms)?;

        let envelope = EncryptedEnvelope::from_wire_bytes(envelope_wire)?;

        let channel_id = ChannelId::from_slice(&envelope.channel_id)?;
        let message_id = MessageId::from_slice(&envelope.message_id)?;

        // 1. Критический путь доставки сообщения (0 зависимостей от auth/directory/presence)
        let ack: SendMessageAckProto =
            self.messaging_svc
                .route_and_persist_envelope(&token, envelope, now_ms)?;

        // 2. Изолированный вызов sidecar-сервиса `presence-receipts-svc` (Circuit Breaker):
        // даже если он мертв, пользователь получает успешный ACK доставки сообщения!
        if self.presence_svc.heartbeat_online(&token, now_ms).is_err()
            || self
                .presence_svc
                .record_read_receipt(&token, channel_id, message_id, now_ms)
                .is_err()
        {
            self.absorbed_sidecar_failures
                .fetch_add(1, Ordering::Relaxed);
        }

        Ok(ack.encode_to_vec())
    }

    /// **HOT PATH №2:** Подписка клиентского соединения на риалтайм-поток зашифрованных конвертов канала.
    pub fn subscribe_channel_realtime(
        &self,
        token: &SignedSessionToken,
        channel_id: ChannelId,
        now_ms: u64,
    ) -> Result<broadcast::Receiver<Arc<EncryptedEnvelope>>, GatewayError> {
        Ok(self
            .messaging_svc
            .subscribe_channel_realtime(token, channel_id, now_ms)?)
    }

    /// **HOT PATH №3:** Курсорная подгрузка зашифрованной облачной истории чата (`UUIDv7` без `OFFSET`).
    pub fn handle_fetch_history(
        &self,
        token: &SignedSessionToken,
        channel_id: ChannelId,
        before_cursor: Option<MessageId>,
        limit: usize,
        now_ms: u64,
    ) -> Result<ChannelHistoryPageProto, GatewayError> {
        let _ = self.verifier.verify_token(token, now_ms)?;
        Ok(self.messaging_svc.fetch_channel_history(
            token,
            channel_id,
            before_cursor,
            limit,
            now_ms,
        )?)
    }

    /// **ISOLATED SIDECAR PATH:** Поиск коллег по префиксу `@username` через `user-directory-svc`.
    pub fn handle_search_users(
        &self,
        token: &SignedSessionToken,
        prefix: &str,
        limit: usize,
        now_ms: u64,
    ) -> Result<SearchUsersResponse, GatewayError> {
        let claims = self.verifier.verify_token(token, now_ms)?;
        self.enforce_rate_limit(claims.tenant_id, claims.user_id, now_ms)?;
        Ok(self
            .directory_svc
            .search_by_prefix(token, prefix, limit, now_ms)?)
    }
}
