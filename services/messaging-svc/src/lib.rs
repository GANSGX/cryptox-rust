//! `messaging-svc` — Критический контур слепой маршрутизации и облачного хранения истории чатов
//! (`Blind Delivery & Storage Service` по стандарту IETF RFC 9750).
//!
//! Ключевые свойства:
//! 1. **Zero-Knowledge (Слепой Сервер):** принимает, маршрутизирует и хранит только бинарные
//!    конверты `EncryptedEnvelope`, не имея доступа к открытому тексту или ключам чата.
//! 2. **Защита от спуфинга отправителя (`Sender Spoofing Protection`):** сверяет `envelope.tenant_id`
//!    и `envelope.sender_user_id` с криптографически проверенным токеном `SignedSessionToken`.
//! 3. **Идемпотентная дедупликация (`Idempotent Delivery`, Мина №2):** если из-за моргания сети в лифте
//!    клиент прислал пакет с одним и тем же `message_id` (`UUIDv7`) 10 раз подряд, сообщение сохраняется
//!    и рассылается строго 1 раз (`was_deduplicated = true`).
//! 4. **Курсорная пагинация облачной истории по `UUIDv7` без `OFFSET` и без `COUNT(*)`:**
//!    сообщения в канале хранятся в упорядоченном по `MessageId` индексе `BTreeMap`. Выборка любой
//!    страницы истории (`before_cursor`) работает за O(log N + limit) (микросекунды на миллионах сообщений).
//! 5. **Риалтайм Fan-out (`tokio::sync::broadcast`):** мгновенная рассылка конверта всем активным
//!    подписчикам канала в памяти без блокировки записи.

use auth_vault_svc::{AuthVaultError, AutonomousTokenVerifier};
use cryptox_proto::{
    ChannelHistoryPageProto, ChannelId, DeviceId, EncryptedEnvelope, MessageId, ProtoError,
    SendMessageAckProto, SignedSessionToken, TenantId, UserId,
};
use dashmap::DashMap;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};
use thiserror::Error;
use tokio::sync::broadcast;

/// Максимальный размер страницы истории за один запрос.
pub const MAX_HISTORY_PAGE_LIMIT: usize = 100;

/// Размер кольцевого буфера риалтайм-канала (`tokio::sync::broadcast`).
pub const REALTIME_CHANNEL_CAPACITY: usize = 4096;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessagingError {
    #[error("ошибка протокола конверта: {0}")]
    Proto(#[from] ProtoError),

    #[error("ошибка авторизации токена: {0}")]
    Auth(#[from] AuthVaultError),

    #[error("попытка подделки отправителя или организации в конверте (Sender/Tenant Spoofing Blocked)")]
    SenderOrTenantSpoofing,
}

/// Внутренний партиционированный журнал одного чата/канала (`(TenantId, ChannelId)`).
struct ChannelTimelinePartition {
    /// Упорядоченный по времени (`UUIDv7 MessageId`) журнал слепых конвертов для O(log N) курсорной пагинации.
    timeline: RwLock<BTreeMap<MessageId, Arc<EncryptedEnvelope>>>,
    /// Неблокирующий риалтайм-канал `tokio::sync::broadcast` для мгновенной доставки онлайн-собеседникам.
    realtime_tx: broadcast::Sender<Arc<EncryptedEnvelope>>,
}

impl ChannelTimelinePartition {
    fn new() -> Self {
        let (realtime_tx, _) = broadcast::channel(REALTIME_CHANNEL_CAPACITY);
        Self {
            timeline: RwLock::new(BTreeMap::new()),
            realtime_tx,
        }
    }
}

pub struct MessagingService {
    verifier: AutonomousTokenVerifier,
    /// Шардированный индекс идемпотентности `(TenantId, ChannelId, MessageId) -> server_received_at_ms`.
    dedup_index: DashMap<(TenantId, ChannelId, MessageId), u64>,
    /// Шардированная таблица каналов `(TenantId, ChannelId) -> Arc<ChannelTimelinePartition>`.
    channels: DashMap<(TenantId, ChannelId), Arc<ChannelTimelinePartition>>,
}

impl MessagingService {
    #[must_use]
    pub fn new(verifier: AutonomousTokenVerifier) -> Self {
        Self {
            verifier,
            dedup_index: DashMap::with_capacity(65_536),
            channels: DashMap::with_capacity(16_384),
        }
    }

    fn get_or_create_channel(
        &self,
        tenant_id: TenantId,
        channel_id: ChannelId,
    ) -> Arc<ChannelTimelinePartition> {
        self.channels
            .entry((tenant_id, channel_id))
            .or_insert_with(|| Arc::new(ChannelTimelinePartition::new()))
            .clone()
    }

    /// Подписывает подключенное клиентское устройство на риалтайм-поток зашифрованных конвертов канала.
    pub fn subscribe_channel_realtime(
        &self,
        token: &SignedSessionToken,
        channel_id: ChannelId,
        now_ms: u64,
    ) -> Result<broadcast::Receiver<Arc<EncryptedEnvelope>>, MessagingError> {
        let claims = self.verifier.verify_token(token, now_ms)?;
        let part = self.get_or_create_channel(claims.tenant_id, channel_id);
        Ok(part.realtime_tx.subscribe())
    }

    /// Принимает, дедуплицирует, сохраняет в облачную историю и мгновенно рассылает в риалтайме
    /// слепой зашифрованный конверт `EncryptedEnvelope`.
    ///
    /// **Не имеет ни одной зависимости от `auth-vault-svc`, `user-directory-svc` или `presence-receipts-svc`!**
    pub fn route_and_persist_envelope(
        &self,
        token: &SignedSessionToken,
        envelope: EncryptedEnvelope,
        now_ms: u64,
    ) -> Result<SendMessageAckProto, MessagingError> {
        let claims = self.verifier.verify_token(token, now_ms)?;
        envelope.validate_structure()?;

        let env_tenant = TenantId::from_slice(&envelope.tenant_id)?;
        let env_channel = ChannelId::from_slice(&envelope.channel_id)?;
        let env_msg_id = MessageId::from_slice(&envelope.message_id)?;
        let env_sender = UserId::from_slice(&envelope.sender_user_id)?;
        let env_device = DeviceId::from_slice(&envelope.sender_device_id)?;

        // 1. Защита от отравления таймлайна чата датой из 2099 года (`UUIDv7 Future Timestamp Poisoning`)
        env_msg_id.validate_not_in_future(now_ms)?;

        // 2. Жесткая проверка Zero-Trust за константное время (`ct_eq_id`):
        // отправитель не может подставить чужой `user_id`, чужой `tenant_id` ИЛИ чужой `device_id`!
        if !env_tenant.ct_eq_id(&claims.tenant_id)
            || !env_sender.ct_eq_id(&claims.user_id)
            || !env_device.ct_eq_id(&claims.device_id)
        {
            return Err(MessagingError::SenderOrTenantSpoofing);
        }

        // 3. Защита от переполнения памяти индекса дедупликации (`Unbounded Memory Defense`)
        if self.dedup_index.len() >= 262_144 {
            self.dedup_index
                .retain(|_, ts| now_ms.saturating_sub(*ts) < 3_600_000);
        }

        // Атомарная проверка идемпотентности (Мина №2: защита от дублей при плохом интернете)
        let dedup_key = (env_tenant, env_channel, env_msg_id);
        match self.dedup_index.entry(dedup_key) {
            dashmap::mapref::entry::Entry::Occupied(existing) => {
                return Ok(SendMessageAckProto {
                    channel_id: env_channel.to_vec(),
                    message_id: env_msg_id.to_vec(),
                    server_received_at_ms: *existing.get(),
                    was_deduplicated: true,
                });
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(now_ms);
            }
        }

        let arc_env = Arc::new(envelope);
        let partition = self.get_or_create_channel(env_tenant, env_channel);

        // 1. Записываем в упорядоченный UUIDv7 журнал облачной истории канала
        {
            let mut timeline = partition
                .timeline
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            timeline.insert(env_msg_id, arc_env.clone());
        }

        // 2. Мгновенный неблокирующий fan-out всем онлайн-участникам чата
        // (если онлайн-слушателей сейчас 0, ошибка SendError игнорируется — сообщение уже в истории)
        let _ = partition.realtime_tx.send(arc_env);

        Ok(SendMessageAckProto {
            channel_id: env_channel.to_vec(),
            message_id: env_msg_id.to_vec(),
            server_received_at_ms: now_ms,
            was_deduplicated: false,
        })
    }

    /// Заменяет конверт сообщения на месте в RAM-журнале канала (при редактировании автором)
    /// со строгой проверкой Zero-Trust владения (`sender_user_id == claims.user_id`).
    pub fn update_envelope_in_place(
        &self,
        token: &SignedSessionToken,
        updated_envelope: EncryptedEnvelope,
        now_ms: u64,
    ) -> Result<(), MessagingError> {
        let claims = self.verifier.verify_token(token, now_ms)?;
        updated_envelope.validate_structure()?;

        let env_tenant = TenantId::from_slice(&updated_envelope.tenant_id)?;
        let env_channel = ChannelId::from_slice(&updated_envelope.channel_id)?;
        let env_msg_id = MessageId::from_slice(&updated_envelope.message_id)?;
        let env_sender = UserId::from_slice(&updated_envelope.sender_user_id)?;

        if !env_tenant.ct_eq_id(&claims.tenant_id) || !env_sender.ct_eq_id(&claims.user_id) {
            return Err(MessagingError::SenderOrTenantSpoofing);
        }

        let partition = self.get_or_create_channel(env_tenant, env_channel);
        let arc_env = Arc::new(updated_envelope);
        {
            let mut timeline = partition
                .timeline
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            timeline.insert(env_msg_id, arc_env);
        }
        Ok(())
    }

    /// Удаляет сообщение из RAM-журнала канала и индекса дедупликации.
    pub fn delete_envelope(
        &self,
        token: &SignedSessionToken,
        channel_id: ChannelId,
        message_id: MessageId,
        now_ms: u64,
    ) -> Result<bool, MessagingError> {
        let claims = self.verifier.verify_token(token, now_ms)?;
        self.dedup_index
            .remove(&(claims.tenant_id, channel_id, message_id));

        let Some(partition) = self.channels.get(&(claims.tenant_id, channel_id)) else {
            return Ok(false);
        };
        let mut timeline = partition
            .timeline
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(timeline.remove(&message_id).is_some())
    }

    /// Курсорная выдача зашифрованной облачной истории чата по `UUIDv7` (`before_cursor`)
    /// за O(log N + limit) **без `OFFSET` и без `SELECT COUNT(*)`**.
    ///
    /// Позволяет сотруднику, зашедшему с нового ноутбука (и открывшему `CloudKeyVault`),
    /// за доли миллисекунды подгрузить и расшифровать всю историю переписки.
    pub fn fetch_channel_history(
        &self,
        token: &SignedSessionToken,
        channel_id: ChannelId,
        before_cursor: Option<MessageId>,
        limit: usize,
        now_ms: u64,
    ) -> Result<ChannelHistoryPageProto, MessagingError> {
        let claims = self.verifier.verify_token(token, now_ms)?;
        let capped_limit = limit.clamp(1, MAX_HISTORY_PAGE_LIMIT);

        let Some(partition) = self.channels.get(&(claims.tenant_id, channel_id)) else {
            return Ok(ChannelHistoryPageProto {
                channel_id: channel_id.to_vec(),
                envelopes: Vec::new(),
                next_before_cursor: Vec::new(),
                has_more: false,
            });
        };

        let timeline = partition
            .timeline
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Берем `capped_limit + 1` записей в обратном хронологическом порядке строго ДО курсора `before_cursor`
        let mut page_descending: Vec<EncryptedEnvelope> = Vec::with_capacity(capped_limit);
        let mut has_more = false;

        let iter: Box<dyn Iterator<Item = (&MessageId, &Arc<EncryptedEnvelope>)>> =
            match before_cursor {
                Some(cursor) => Box::new(timeline.range(..cursor).rev()),
                None => Box::new(timeline.iter().rev()),
            };

        for (idx, (_, env)) in iter.enumerate() {
            if idx == capped_limit {
                has_more = true;
                break;
            }
            page_descending.push((**env).clone());
        }

        // Разворачиваем страницу в естественный хронологический порядок (от старых к новым)
        page_descending.reverse();

        let next_before_cursor = if has_more {
            page_descending
                .first()
                .map(|first_env| first_env.message_id.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        Ok(ChannelHistoryPageProto {
            channel_id: channel_id.to_vec(),
            envelopes: page_descending,
            next_before_cursor,
            has_more,
        })
    }
}
