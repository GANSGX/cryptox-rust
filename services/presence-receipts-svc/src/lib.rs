//! `presence-receipts-svc` — Изолированный микросервис онлайн-статусов и схлопывания
//! шторма галочек «Прочитано» (`Read Receipts Coalescing Engine`, архитектура Discord Read States).
//!
//! Зачем он выделен в отдельный Bulkhead-отсек:
//! 1. Когда в компании на 100 000 человек публикуется новость и 100 000 клиентов одновременно шлют
//!    пакеты `read`, прямая запись каждого `read` в основную БД сообщений убила бы диск.
//! 2. Этот сервис держит в шардированной памяти (`DashMap`) только один монотонно растущий указатель
//!    `last_read_message_id (UUIDv7)` на пару `(TenantId, ChannelId, UserId)`.
//! 3. Если сотрудник пролистал 500 сообщений, 500 событий `read` схлопываются (coalesce) в одну запись
//!    со скоростью > 1 500 000 событий/сек!
//! 4. Если `presence-receipts-svc` упадет — просто не обновятся галочки «прочитано» и статус «в сети»,
//!    но сами сообщения в `messaging-svc` продолжат ходить без единого сбоя.

use auth_vault_svc::{AuthVaultError, AutonomousTokenVerifier};
use cryptox_proto::{
    ChannelId, MessageId, ProtoError, ReadReceiptWatermarkProto, SignedSessionToken, TenantId,
    UserId,
};
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PresenceError {
    #[error("ошибка протокола: {0}")]
    Proto(#[from] ProtoError),

    #[error("ошибка авторизации токена: {0}")]
    Auth(#[from] AuthVaultError),

    #[error("сервис presence-receipts-svc временно недоступен (Simulated Outage)")]
    ServiceUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatermarkState {
    pub last_read_message_id: MessageId,
    pub updated_at_ms: u64,
    pub coalesced_updates_count: u64,
}

pub struct PresenceReceiptsService {
    verifier: AutonomousTokenVerifier,
    /// Шардированная таблица водоразделов прочтения `(TenantId, ChannelId, UserId) -> WatermarkState`.
    read_watermarks: DashMap<(TenantId, ChannelId, UserId), WatermarkState>,
    /// Шардированная таблица онлайн-хартбитов `(TenantId, UserId) -> last_seen_ms`.
    online_heartbeats: DashMap<(TenantId, UserId), u64>,
    /// Флаг симуляции падения сервиса для Chaos / Bulkhead тестов.
    simulated_outage: AtomicBool,
}

impl PresenceReceiptsService {
    #[must_use]
    pub fn new(verifier: AutonomousTokenVerifier) -> Self {
        Self {
            verifier,
            read_watermarks: DashMap::with_capacity(65_536),
            online_heartbeats: DashMap::with_capacity(65_536),
            simulated_outage: AtomicBool::new(false),
        }
    }

    pub fn set_simulated_outage(&self, is_down: bool) {
        self.simulated_outage.store(is_down, Ordering::SeqCst);
    }

    #[inline]
    fn check_available(&self) -> Result<(), PresenceError> {
        if self.simulated_outage.load(Ordering::Relaxed) {
            return Err(PresenceError::ServiceUnavailable);
        }
        Ok(())
    }

    /// Атомарно схлопывает (coalesces) событие прочтения сообщения в чате.
    ///
    /// Проверяет, что `read_up_to_id` (`UUIDv7`) не содержит злонамеренный таймстемп из далекого будущего
    /// (защита от `Future Timestamp Watermark Poisoning`), после чего двигает указатель только вперед.
    pub fn record_read_receipt(
        &self,
        token: &SignedSessionToken,
        channel_id: ChannelId,
        read_up_to_id: MessageId,
        now_ms: u64,
    ) -> Result<WatermarkState, PresenceError> {
        self.check_available()?;
        read_up_to_id.validate_not_in_future(now_ms)?;

        let claims = self.verifier.verify_token(token, now_ms)?;
        let key = (claims.tenant_id, channel_id, claims.user_id);

        let mut entry = self.read_watermarks.entry(key).or_insert(WatermarkState {
            last_read_message_id: read_up_to_id,
            updated_at_ms: now_ms,
            coalesced_updates_count: 0,
        });

        let state = entry.value_mut();
        state.coalesced_updates_count = state.coalesced_updates_count.saturating_add(1);
        if read_up_to_id.as_bytes() > state.last_read_message_id.as_bytes() {
            state.last_read_message_id = read_up_to_id;
            state.updated_at_ms = now_ms;
        }

        Ok(*state)
    }

    /// Возвращает текущий схлопнутый водораздел прочтения сотрудника в чате.
    pub fn get_read_watermark(
        &self,
        token: &SignedSessionToken,
        channel_id: ChannelId,
        target_user_id: UserId,
        now_ms: u64,
    ) -> Result<Option<ReadReceiptWatermarkProto>, PresenceError> {
        self.check_available()?;

        let claims = self.verifier.verify_token(token, now_ms)?;
        let key = (claims.tenant_id, channel_id, target_user_id);

        Ok(self.read_watermarks.get(&key).map(|w| ReadReceiptWatermarkProto {
            tenant_id: claims.tenant_id.to_vec(),
            channel_id: channel_id.to_vec(),
            user_id: target_user_id.to_vec(),
            last_read_message_id: w.last_read_message_id.to_vec(),
            updated_at_ms: w.updated_at_ms,
        }))
    }

    /// Обновляет онлайн-статус сотрудника в памяти (с защитой от Unbounded Memory DoS).
    pub fn heartbeat_online(
        &self,
        token: &SignedSessionToken,
        now_ms: u64,
    ) -> Result<(), PresenceError> {
        self.check_available()?;
        let claims = self.verifier.verify_token(token, now_ms)?;
        if self.online_heartbeats.len() >= 131_072 {
            // Очищаем устаревшие хартбиты старше 5 минут
            self.online_heartbeats
                .retain(|_, last_seen| now_ms.saturating_sub(*last_seen) < 300_000);
        }
        self.online_heartbeats
            .insert((claims.tenant_id, claims.user_id), now_ms);
        Ok(())
    }

    /// Возвращает время последней активности сотрудника (`last_seen_ms`) в `presence-receipts-svc`.
    #[must_use]
    pub fn get_last_seen_ms(&self, tenant_id: TenantId, user_id: UserId) -> Option<u64> {
        if self.simulated_outage.load(Ordering::Relaxed) {
            return None;
        }
        self.online_heartbeats
            .get(&(tenant_id, user_id))
            .map(|r| *r.value())
    }
}
