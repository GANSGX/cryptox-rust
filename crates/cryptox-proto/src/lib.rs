//! `cryptox-proto` — Бинарные контракты и типизированные идентификаторы (IETF RFC 9562 / RFC 9750).
//!
//! Никакого текстового JSON + Base64 для сообщений: все сетевые пакеты кодируются
//! в компактный бинарный Protobuf (`prost`) с жесткой привязкой метаданных к AEAD AAD.

use prost::Message;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

/// Максимальный допустимый размер одного бинарного конверта сообщения (1 МБ).
/// Защита от OOM DDoS по стандарту OWASP ASVS v5.0 Level 3 (V5).
pub const MAX_ENVELOPE_WIRE_BYTES: usize = 1024 * 1024;

/// Максимальный размер запечатанного корпоративного ключа эскроу (256 байт).
pub const MAX_ESCROW_SEALED_KEY_BYTES: usize = 256;

/// Максимально допустимое расхождение часов клиента в будущее относительно сервера (60 секунд).
/// Защита от атаки «Сообщение из 2099 года» (`Future Timestamp Poisoning`).
pub const MAX_FUTURE_CLOCK_SKEW_MS: u64 = 60_000;

/// Текущая версия бинарного протокола CryptoX.
pub const PROTOCOL_VERSION_V1: u32 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("некорректная длина UUID байтов: ожидалось 16, получено {0}")]
    InvalidUuidLength(usize),

    #[error("нарушен стандарт RFC 9562 UUIDv7 или таймстемп из будущего (Future Timestamp Poisoning): {0}")]
    InvalidUuidV7OrTimestamp(&'static str),

    #[error("превышен максимальный размер бинарного пакета: {size} > {max}")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("ошибка декодирования Protobuf: {0}")]
    DecodeError(String),

    #[error("неизвестный или неподдерживаемый криптонабор (CipherSuite): {0}")]
    UnsupportedCipherSuite(i32),

    #[error("некорректные метаданные конверта: {0}")]
    InvalidEnvelopeMetadata(&'static str),
}

/// Макрос для создания строго типизированных 16-байтных идентификаторов (Newtype Pattern),
/// чтобы компилятор Rust физически не позволил перепутать `UserId`, `ChannelId` и `TenantId`.
macro_rules! define_typed_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Создает новый монотонно возрастающий по времени идентификатор `UUIDv7` (IETF RFC 9562).
            #[must_use]
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            /// Возвращает сырые 16 байт идентификатора для бинарной передачи по сети.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// Преобразует в `Vec<u8>` (16 байт) для записи в Protobuf-поле.
            #[must_use]
            pub fn to_vec(self) -> Vec<u8> {
                self.0.as_bytes().to_vec()
            }

            /// Восстанавливает типизированный ID из байтового среза (ровно 16 байт).
            pub fn from_slice(bytes: &[u8]) -> Result<Self, ProtoError> {
                let arr: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| ProtoError::InvalidUuidLength(bytes.len()))?;
                Ok(Self(Uuid::from_bytes(arr)))
            }

            /// Извлекает встроенный Unix-таймстемп в миллисекундах напрямую из первых 48 бит UUIDv7 за O(1).
            #[must_use]
            pub const fn timestamp_ms(&self) -> u64 {
                let b = self.0.as_bytes();
                ((b[0] as u64) << 40)
                    | ((b[1] as u64) << 32)
                    | ((b[2] as u64) << 24)
                    | ((b[3] as u64) << 16)
                    | ((b[4] as u64) << 8)
                    | (b[5] as u64)
            }

            /// Сравнение за константное время (`subtle::ConstantTimeEq`) для защиты от Timing Attacks.
            #[must_use]
            pub fn ct_eq_id(&self, other: &Self) -> bool {
                self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
            }

            /// Проверяет, что идентификатор не сгенерирован со злонамеренным таймстемпом из далекого будущего
            /// (защита от `UUIDv7 Future Timestamp Poisoning`).
            pub fn validate_not_in_future(&self, now_ms: u64) -> Result<(), ProtoError> {
                let os_now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(now_ms);
                let effective_now = now_ms.max(os_now_ms);
                let ts = self.timestamp_ms();
                if ts > effective_now.saturating_add(MAX_FUTURE_CLOCK_SKEW_MS) {
                    return Err(ProtoError::InvalidUuidV7OrTimestamp(
                        "UUIDv7 timestamp exceeds allowed future clock skew window",
                    ));
                }
                Ok(())
            }
        }
    };
}

define_typed_id!(TenantId, "Идентификатор компании-арендатора (Multi-Tenancy Isolation).");
define_typed_id!(UserId, "Неизменяемый идентификатор сотрудника (вместо мутабельного @username).");
define_typed_id!(DeviceId, "Идентификатор конкретного клиентского устройства сотрудника.");
define_typed_id!(ChannelId, "Идентификатор личного диалога или корпоративного канала.");
define_typed_id!(MessageId, "Идентификатор сообщения UUIDv7 (используется для идемпотентности и курсорной пагинации без OFFSET).");
define_typed_id!(TokenId, "Уникальный идентификатор сессионного токена (UUIDv7) для мгновенного точечного отзыва при увольнении.");
define_typed_id!(ChallengeId, "Одноразовый идентификатор криптографического челленджа входа (защита от Replay-атак).");

impl ChannelId {
    /// Детерминированно вычисляет неизменяемый 16-байтный `ChannelId` для личного чата (1-на-1)
    /// между двумя сотрудниками внутри одной организации (`tenant_id`).
    ///
    /// В отличие от старого `cryptox` (`alice_bob`), этот ID не ломается при смене `@username`
    /// и криптографически изолирован между разными компаниями (`tenant_id`).
    #[must_use]
    pub fn deterministic_direct(tenant_id: TenantId, user_a: UserId, user_b: UserId) -> Self {
        let (first, second) = if user_a.as_bytes() <= user_b.as_bytes() {
            (user_a, user_b)
        } else {
            (user_b, user_a)
        };

        let mut hasher = blake3::Hasher::new_derive_key("cryptox.direct-channel-id.v1");
        hasher.update(tenant_id.as_bytes());
        hasher.update(first.as_bytes());
        hasher.update(second.as_bytes());
        let hash = hasher.finalize();

        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash.as_bytes()[..16]);
        Self(Uuid::from_bytes(bytes))
    }
}

/// Поддерживаемые криптонаборы (Crypto-Agility по стандартам CNSA 2.0 и ПП РФ № 313).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, prost::Enumeration)]
#[repr(i32)]
pub enum CipherSuiteId {
    /// Базовый высокоскоростной стек: X25519 + XChaCha20-Poly1305 (256 бит) + BLAKE3 + Ed25519.
    X25519XChaCha20Poly1305Blake3 = 1,
    /// Стек аппаратного ускорения AES-NI: X25519 + AES-256-GCM + SHA-512 + Ed25519.
    X25519Aes256GcmSha512 = 2,
    /// Слот для подключения внешнего сертифицированного СКЗИ заказчика (ГОСТ Р 34.12-2018 «Кузнечик»).
    GostR3412KuznyechikExternalSkzi = 3,
}

impl CipherSuiteId {
    pub fn try_from_proto(value: i32) -> Result<Self, ProtoError> {
        match value {
            1 => Ok(Self::X25519XChaCha20Poly1305Blake3),
            2 => Ok(Self::X25519Aes256GcmSha512),
            3 => Ok(Self::GostR3412KuznyechikExternalSkzi),
            other => Err(ProtoError::UnsupportedCipherSuite(other)),
        }
    }
}

/// Политика шифрования чата в корпорации (`RU_ENTERPRISE_COMPLIANCE_AND_DLP.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, prost::Enumeration)]
#[repr(i32)]
pub enum EncryptionPolicy {
    /// Абсолютный Zero-Knowledge («Совет Директоров» / VIP): ключи только у участников чата.
    StrictZeroKnowledge = 1,
    /// Стандартный корпоративный чат: БД мессенджера слепая для админов/хакеров,
    /// но ключ дублируется на аппаратный HSM-ключ Службы Безопасности (DLP) компании.
    CorporateEscrowDlp = 2,
}

/// Публичный пакет ключей пользователя (`KeyPackage`), выдаваемый сервисом `user-directory-svc`
/// при поиске коллеги по `@username`.
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    #[prost(bytes = "vec", tag = "1")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub device_id: Vec<u8>,
    #[prost(int32, tag = "4")]
    pub cipher_suite: i32,
    /// Публичный ключ цифровой подписи Ed25519 (32 байта).
    #[prost(bytes = "vec", tag = "5")]
    pub ed25519_verifying_key: Vec<u8>,
    /// Публичный ключ согласования Диффи-Хеллмана X25519 (32 байта).
    #[prost(bytes = "vec", tag = "6")]
    pub x25519_public_key: Vec<u8>,
    /// Монотонно растущая версия ключа для дерева Key Transparency (защита от MITM).
    #[prost(uint64, tag = "7")]
    pub key_version: u64,
    /// Самоподпись Ed25519 (64 байта) над всеми полями пакета: гарантирует, что сервер
    /// не может подменить `x25519_public_key` без владения приватным ключом `Ed25519`.
    #[prost(bytes = "vec", tag = "8")]
    pub self_signature: Vec<u8>,
}

impl PublicKeyBundle {
    /// Формирует канонический байтовый массив для проверки цифровой подписи `self_signature`.
    #[must_use]
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(140);
        buf.extend_from_slice(b"cryptox.keybundle.v1:");
        buf.extend_from_slice(&self.tenant_id);
        buf.extend_from_slice(&self.user_id);
        buf.extend_from_slice(&self.device_id);
        buf.extend_from_slice(&self.cipher_suite.to_le_bytes());
        buf.extend_from_slice(&self.ed25519_verifying_key);
        buf.extend_from_slice(&self.x25519_public_key);
        buf.extend_from_slice(&self.key_version.to_le_bytes());
        buf
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_ENVELOPE_WIRE_BYTES {
            return Err(ProtoError::PayloadTooLarge {
                size: bytes.len(),
                max: MAX_ENVELOPE_WIRE_BYTES,
            });
        }
        Self::decode(bytes).map_err(|e| ProtoError::DecodeError(e.to_string()))
    }
}

/// Слепой зашифрованный конверт сообщения (`EncryptedEnvelope`, IETF RFC 9750).
///
/// Сервер доставки (`edge-gateway` + `messaging-svc`) маршрутизирует и сохраняет этот конверт
/// в БД по `tenant_id`, `channel_id` и `message_id` (UUIDv7), не имея возможности прочитать `ciphertext`.
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(int32, tag = "2")]
    pub cipher_suite: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub channel_id: Vec<u8>,
    /// Клиентский `UUIDv7`: гарантирует идемпотентность (защиту от дублей при плохом интернете)
    /// и мгновенную курсорную пагинацию в БД.
    #[prost(bytes = "vec", tag = "5")]
    pub message_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub sender_user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub sender_device_id: Vec<u8>,
    /// Номер шага Ratchet-цепочки (Forward Secrecy: каждое сообщение шифруется новым одноразовым ключом).
    #[prost(uint64, tag = "8")]
    pub ratchet_step: u64,
    /// Уникальный Nonce (24 байта для XChaCha20-Poly1305 или 12 байт для AES-256-GCM).
    #[prost(bytes = "vec", tag = "9")]
    pub nonce: Vec<u8>,
    /// Шифротекст сообщения + 16-байтный тег аутентификации Poly1305 / GCM.
    #[prost(bytes = "vec", tag = "10")]
    pub ciphertext: Vec<u8>,
    /// Опциональный запечатанный ключ для аппаратного HSM Службы Безопасности (DLP) компании.
    /// В режиме `StrictZeroKnowledge` поле пустое (`Vec::new()`).
    #[prost(bytes = "vec", tag = "11")]
    pub corporate_escrow_sealed_key: Vec<u8>,
    /// Цифровая подпись отправителя `Ed25519` (64 байта) над заголовком и шифротекстом.
    #[prost(bytes = "vec", tag = "12")]
    pub ed25519_signature: Vec<u8>,
}

impl EncryptedEnvelope {
    /// Вычисляет канонический вектор AAD (Associated Authenticated Data), который подается
    /// внутрь AEAD-шифра (`XChaCha20-Poly1305` / `AES-256-GCM`).
    ///
    /// Если взломанный сервер или хакер попытается изменить хотя бы 1 бит в `tenant_id`,
    /// `channel_id`, `message_id`, `sender_user_id`, `ratchet_step` или `corporate_escrow_sealed_key`,
    /// математическая проверка Poly1305/GCM мгновенно отвергнет пакет!
    #[must_use]
    pub fn canonical_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(128 + self.corporate_escrow_sealed_key.len());
        aad.extend_from_slice(b"cryptox.envelope.aad.v1:");
        aad.extend_from_slice(&self.protocol_version.to_le_bytes());
        aad.extend_from_slice(&self.cipher_suite.to_le_bytes());
        aad.extend_from_slice(&self.tenant_id);
        aad.extend_from_slice(&self.channel_id);
        aad.extend_from_slice(&self.message_id);
        aad.extend_from_slice(&self.sender_user_id);
        aad.extend_from_slice(&self.sender_device_id);
        aad.extend_from_slice(&self.ratchet_step.to_le_bytes());
        aad.extend_from_slice(&(self.corporate_escrow_sealed_key.len() as u32).to_le_bytes());
        aad.extend_from_slice(&self.corporate_escrow_sealed_key);
        aad
    }

    /// Байты для цифровой подписи `Ed25519` (включают весь `canonical_aad` + `nonce` + `ciphertext`).
    #[must_use]
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut buf = self.canonical_aad();
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Проверяет структурную корректность идентификаторов конверта (Fast validation на `edge-gateway`).
    pub fn validate_structure(&self) -> Result<(), ProtoError> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ProtoError::InvalidEnvelopeMetadata("unsupported protocol_version"));
        }
        let suite = CipherSuiteId::try_from_proto(self.cipher_suite)?;
        let expected_nonce_len = match suite {
            CipherSuiteId::X25519XChaCha20Poly1305Blake3 => 24,
            CipherSuiteId::X25519Aes256GcmSha512 | CipherSuiteId::GostR3412KuznyechikExternalSkzi => 12,
        };
        if self.nonce.len() != expected_nonce_len {
            return Err(ProtoError::InvalidEnvelopeMetadata("invalid nonce length for cipher suite"));
        }
        if self.ratchet_step == 0 {
            return Err(ProtoError::InvalidEnvelopeMetadata("ratchet_step must be >= 1"));
        }
        if self.corporate_escrow_sealed_key.len() > MAX_ESCROW_SEALED_KEY_BYTES {
            return Err(ProtoError::InvalidEnvelopeMetadata("corporate_escrow_sealed_key exceeds max bound"));
        }
        let _ = TenantId::from_slice(&self.tenant_id)?;
        let _ = ChannelId::from_slice(&self.channel_id)?;
        let _ = MessageId::from_slice(&self.message_id)?;
        let _ = UserId::from_slice(&self.sender_user_id)?;
        let _ = DeviceId::from_slice(&self.sender_device_id)?;
        if self.ciphertext.len() <= 16 {
            return Err(ProtoError::InvalidEnvelopeMetadata("ciphertext shorter than AEAD tag"));
        }
        if self.ed25519_signature.len() != 64 {
            return Err(ProtoError::InvalidEnvelopeMetadata("invalid ed25519 signature length"));
        }
        Ok(())
    }

    /// Кодирует конверт в бинарный буфер Protobuf для отправки по WebSocket / QUIC / gRPC.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Декодирует конверт из бинарного буфера с защитой от превышения лимита размера.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_ENVELOPE_WIRE_BYTES {
            return Err(ProtoError::PayloadTooLarge {
                size: bytes.len(),
                max: MAX_ENVELOPE_WIRE_BYTES,
            });
        }
        let env = Self::decode(bytes).map_err(|e| ProtoError::DecodeError(e.to_string()))?;
        env.validate_structure()?;
        Ok(env)
    }
}

/// Зашифрованный Облачный Сейф Ключей (`EncryptedVaultBlob`).
///
/// Хранится в облаке (`auth-vault-svc`) для мгновенной синхронизации всей истории чатов
/// при входе сотрудника с нового ноутбука или телефона (как в Яндекс.Мессенджере / Telegram),
/// но зашифрован ключом, выведенным через `Argon2id` на клиенте. Сервер открыть его не может.
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct EncryptedVaultBlob {
    #[prost(bytes = "vec", tag = "1")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub user_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub vault_version: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub argon2_salt: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub argon2_m_cost_kib: u32,
    #[prost(uint32, tag = "6")]
    pub argon2_t_cost: u32,
    #[prost(uint32, tag = "7")]
    pub argon2_p_cost: u32,
    #[prost(bytes = "vec", tag = "8")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub encrypted_payload: Vec<u8>,
}

impl EncryptedVaultBlob {
    /// Канонический AAD облачного сейфа (привязывает шифротекст сейфа к `tenant_id`, `user_id` и `vault_version`).
    #[must_use]
    pub fn canonical_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(b"cryptox.cloud-vault.aad.v1:");
        aad.extend_from_slice(&self.tenant_id);
        aad.extend_from_slice(&self.user_id);
        aad.extend_from_slice(&self.vault_version.to_le_bytes());
        aad.extend_from_slice(&self.argon2_m_cost_kib.to_le_bytes());
        aad.extend_from_slice(&self.argon2_t_cost.to_le_bytes());
        aad.extend_from_slice(&self.argon2_p_cost.to_le_bytes());
        aad
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_ENVELOPE_WIRE_BYTES {
            return Err(ProtoError::PayloadTooLarge {
                size: bytes.len(),
                max: MAX_ENVELOPE_WIRE_BYTES,
            });
        }
        Self::decode(bytes).map_err(|e| ProtoError::DecodeError(e.to_string()))
    }
}

/// Бинарный криптографический сессионный токен (`SignedSessionToken`, модель PASETO v4 Public / Ed25519).
///
/// Выпускается сервисом `auth-vault-svc` и проверяется шлюзом `edge-gateway` автономно в памяти
/// по публичному ключу `Ed25519` без единого сетевого запроса к БД или сервису авторизации (Bulkhead Pattern).
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct SignedSessionToken {
    #[prost(bytes = "vec", tag = "1")]
    pub token_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub device_id: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub issued_at_ms: u64,
    #[prost(uint64, tag = "6")]
    pub expires_at_ms: u64,
    /// Цифровая подпись `Ed25519` (64 байта) сервиса `auth-vault-svc`.
    #[prost(bytes = "vec", tag = "7")]
    pub ed25519_signature: Vec<u8>,
}

impl SignedSessionToken {
    /// Канонический байтовый буфер для подписи и верификации токена.
    #[must_use]
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(112);
        buf.extend_from_slice(b"cryptox.session-token.v1:");
        buf.extend_from_slice(&self.token_id);
        buf.extend_from_slice(&self.tenant_id);
        buf.extend_from_slice(&self.user_id);
        buf.extend_from_slice(&self.device_id);
        buf.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        buf.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        buf
    }

    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > 2048 {
            return Err(ProtoError::PayloadTooLarge {
                size: bytes.len(),
                max: 2048,
            });
        }
        Self::decode(bytes).map_err(|e| ProtoError::DecodeError(e.to_string()))
    }
}

/// Запрос Zero-Knowledge регистрации сотрудника в `auth-vault-svc`.
///
/// Сервер получает ТОЛЬКО публичный ключ аутентификации `auth_verifying_key` (Ed25519),
/// самоподписанный `PublicKeyBundle` и зашифрованный `EncryptedVaultBlob`.
/// Пароль и ключ расшифровки сейфа никогда не покидают клиент!
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct RegisterUserRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub user_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub username: String,
    /// Публичный ключ Ed25519 (32 байта), выведенный клиентом из пароля через Argon2id + BLAKE3 domain separation.
    #[prost(bytes = "vec", tag = "4")]
    pub auth_verifying_key: Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub public_key_bundle: Option<PublicKeyBundle>,
    #[prost(message, optional, tag = "6")]
    pub initial_vault_blob: Option<EncryptedVaultBlob>,
}

/// Одноразовый криптографический вызов (Challenge) от сервера при входе с нового устройства.
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct LoginChallengeResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub challenge_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub argon2_salt: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub argon2_m_cost_kib: u32,
    #[prost(uint32, tag = "6")]
    pub argon2_t_cost: u32,
    #[prost(uint32, tag = "7")]
    pub argon2_p_cost: u32,
    /// Случайные 32 байта (`OsRng`) одноразового челленджа.
    #[prost(bytes = "vec", tag = "8")]
    pub challenge_nonce: Vec<u8>,
    #[prost(uint64, tag = "9")]
    pub expires_at_ms: u64,
}

impl LoginChallengeResponse {
    /// Канонические байты, которые клиент подписывает своим `AuthSigningKey` при входе на устройстве `device_id`.
    #[must_use]
    pub fn canonical_challenge_transcript(&self, device_id: DeviceId) -> Vec<u8> {
        let mut buf = Vec::with_capacity(144);
        buf.extend_from_slice(b"cryptox.auth-challenge.v1:");
        buf.extend_from_slice(&self.challenge_id);
        buf.extend_from_slice(&self.tenant_id);
        buf.extend_from_slice(&self.user_id);
        buf.extend_from_slice(device_id.as_bytes());
        buf.extend_from_slice(&self.challenge_nonce);
        buf.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        buf
    }
}

/// Ответ клиента на одноразовый челлендж входа (Zero-Knowledge Proof of Password).
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct LoginVerifyRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub challenge_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub device_id: Vec<u8>,
    /// Подпись Ed25519 (64 байта) над `canonical_challenge_transcript`.
    #[prost(bytes = "vec", tag = "5")]
    pub challenge_signature: Vec<u8>,
}

/// Карточка сотрудника в корпоративном справочнике (`user-directory-svc`), возвращаемая
/// при поиске по `@username`. Содержит проверенный `PublicKeyBundle` для мгновенного старта E2EE-чата
/// и 32-байтный хеш журнала прозрачности ключей (`transparency_log_hash`, IETF Key Transparency).
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct DirectoryEntryProto {
    #[prost(bytes = "vec", tag = "1")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub user_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub username: String,
    #[prost(string, tag = "4")]
    pub display_name: String,
    #[prost(message, optional, tag = "5")]
    pub public_key_bundle: Option<PublicKeyBundle>,
    /// Криптографический хеш записи в цепочке Key Transparency организации (32 байта BLAKE3).
    #[prost(bytes = "vec", tag = "6")]
    pub transparency_log_hash: Vec<u8>,
    /// Порядковый номер записи в аудит-реестре ключей организации.
    #[prost(uint64, tag = "7")]
    pub transparency_seq: u64,
}

/// Бинарный ответ поиска сотрудников по префиксу `@username` (`SearchUsersResponse`).
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct SearchUsersResponse {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<DirectoryEntryProto>,
    /// Текущая вершина (Root Hash) дерева/цепочки Key Transparency организации.
    #[prost(bytes = "vec", tag = "2")]
    pub tenant_transparency_head: Vec<u8>,
}

/// Подтверждение доставки/сохранения слепого конверта от `messaging-svc` (`SendMessageAckProto`).
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct SendMessageAckProto {
    #[prost(bytes = "vec", tag = "1")]
    pub channel_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub message_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub server_received_at_ms: u64,
    /// `true`, если пакет с таким `message_id` уже был сохранен ранее (идемпотентная дедупликация).
    #[prost(bool, tag = "4")]
    pub was_deduplicated: bool,
}

/// Страница курсорной облачной истории чата (`ChannelHistoryPageProto`).
///
/// Пагинация выполняется строго по `UUIDv7` курсору `next_before_message_id` за O(log N) без `OFFSET` и `COUNT(*)`.
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct ChannelHistoryPageProto {
    #[prost(bytes = "vec", tag = "1")]
    pub channel_id: Vec<u8>,
    /// Зашифрованные конверты сообщений (в хронологическом порядке или обратном от курсора).
    #[prost(message, repeated, tag = "2")]
    pub envelopes: Vec<EncryptedEnvelope>,
    /// Курсор `MessageId` (UUIDv7) для запроса следующей более старой страницы истории (пустой, если достигнуто начало чата).
    #[prost(bytes = "vec", tag = "3")]
    pub next_before_cursor: Vec<u8>,
    #[prost(bool, tag = "4")]
    pub has_more: bool,
}

/// Событие обновления водораздела прочтения чата (`ReadReceiptWatermarkProto`, архитектура Discord Read States).
///
/// Вместо хранения статуса каждого сообщения по отдельности хранит только один монотонно растущий
/// указатель `last_read_message_id` (`UUIDv7`) для пары `(channel_id, user_id)`.
#[derive(Clone, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct ReadReceiptWatermarkProto {
    #[prost(bytes = "vec", tag = "1")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub channel_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub last_read_message_id: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub updated_at_ms: u64,
}

// ============================================================================
// БИНАРНЫЙ ПРОТОКОЛ МЕЖСЕРВИСНОГО И КЛИЕНТСКОГО RPC (100% PROTOBUF / PROST)
// ============================================================================

/// Код операции бинарного Protobuf RPC между шлюзом, клиентом и микросервисами.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum RpcMethodId {
    Unspecified = 0,
    PingHealth = 1,
    RouteMessage = 2,
    FetchHistory = 3,
    SearchDirectory = 4,
    PresenceAndReadReceipt = 5,
}

impl RpcMethodId {
    #[must_use]
    pub const fn try_from_proto(val: i32) -> Option<Self> {
        match val {
            1 => Some(Self::PingHealth),
            2 => Some(Self::RouteMessage),
            3 => Some(Self::FetchHistory),
            4 => Some(Self::SearchDirectory),
            5 => Some(Self::PresenceAndReadReceipt),
            _ => None,
        }
    }
}

/// Зашифрованный и подписанный бинарный Protobuf-фрейм Zero-Trust RPC между узлами кластера.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ZeroTrustRpcFrameProto {
    #[prost(bytes = "vec", tag = "1")]
    pub request_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub timestamp_ms: u64,
    #[prost(string, tag = "3")]
    pub target_service: String,
    #[prost(bytes = "vec", tag = "4")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub ciphertext: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub ed25519_signature: Vec<u8>,
}

/// Бинарный Protobuf-запрос RPC (`InternalRpcRequestProto`).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct InternalRpcRequestProto {
    #[prost(enumeration = "RpcMethodId", tag = "1")]
    pub method: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub token_wire: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub envelope_wire: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub channel_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub message_id_or_cursor: Vec<u8>,
    #[prost(string, tag = "6")]
    pub search_prefix: String,
    #[prost(uint32, tag = "7")]
    pub limit: u32,
    #[prost(uint64, tag = "8")]
    pub now_ms: u64,
}

/// Бинарный Protobuf-ответ RPC (`InternalRpcResponseProto`).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct InternalRpcResponseProto {
    #[prost(bool, tag = "1")]
    pub ok: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub payload_wire: Vec<u8>,
    #[prost(string, tag = "3")]
    pub error_message: String,
}

// ============================================================================
// БИНАРНЫЙ ПРОТОКОЛ КЛИЕНТ <-> ШЛЮЗ (WEB / DESKTOP PROTOBUF WIRE PROTOCOL)
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ClientWireOp {
    Unspecified = 0,
    Login = 1,
    Register = 2,
    SsoLogin = 3,
    RecoverPassword = 4,
    GetState = 5,
    SearchDirectory = 6,
    SendChatMessage = 7,
    FetchChatHistory = 8,
    MarkChatRead = 9,
    CloudSyncNewDevice = 10,
    CheckUsername = 11,
    EditChatMessage = 12,
    DeleteChatMessage = 13,
}

impl ClientWireOp {
    #[must_use]
    pub const fn try_from_proto(val: i32) -> Option<Self> {
        match val {
            1 => Some(Self::Login),
            2 => Some(Self::Register),
            3 => Some(Self::SsoLogin),
            4 => Some(Self::RecoverPassword),
            5 => Some(Self::GetState),
            6 => Some(Self::SearchDirectory),
            7 => Some(Self::SendChatMessage),
            8 => Some(Self::FetchChatHistory),
            9 => Some(Self::MarkChatRead),
            10 => Some(Self::CloudSyncNewDevice),
            11 => Some(Self::CheckUsername),
            12 => Some(Self::EditChatMessage),
            13 => Some(Self::DeleteChatMessage),
            _ => None,
        }
    }
}

/// Внутренняя E2EE-полезная нагрузка сообщения (текст + цитата Reply + флаг редактирования),
/// шифруемая ВНУТРИ `EncryptedEnvelope.ciphertext` (`XChaCha20-Poly1305`) с магическим префиксом `CXR1`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct E2eeRichMessagePayloadProto {
    #[prost(string, tag = "1")]
    pub text: String,
    #[prost(string, tag = "2")]
    pub reply_to_message_id_short: String,
    #[prost(string, tag = "3")]
    pub reply_to_sender: String,
    #[prost(string, tag = "4")]
    pub reply_to_text: String,
    #[prost(bool, tag = "5")]
    pub is_edited: bool,
}

impl E2eeRichMessagePayloadProto {
    pub const MAGIC_PREFIX: &'static [u8; 4] = b"CXR1";

    #[must_use]
    pub fn encode_prefixed(&self) -> Vec<u8> {
        if self.reply_to_message_id_short.is_empty()
            && self.reply_to_sender.is_empty()
            && self.reply_to_text.is_empty()
            && !self.is_edited
        {
            return self.text.as_bytes().to_vec();
        }
        let body = self.encode_to_vec();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(Self::MAGIC_PREFIX);
        out.extend_from_slice(&body);
        out
    }

    #[must_use]
    pub fn decode_or_plain_utf8(raw_decrypted: &[u8]) -> Self {
        if raw_decrypted.starts_with(Self::MAGIC_PREFIX)
            && let Ok(parsed) = Self::decode(&raw_decrypted[4..])
        {
            return parsed;
        }
        Self {
            text: String::from_utf8_lossy(raw_decrypted).to_string(),
            reply_to_message_id_short: String::new(),
            reply_to_sender: String::new(),
            reply_to_text: String::new(),
            is_edited: false,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct ClientWireRequestProto {
    #[prost(enumeration = "ClientWireOp", tag = "1")]
    pub op: i32,
    #[prost(string, tag = "2")]
    pub caller_username: String,
    #[prost(string, tag = "3")]
    pub peer_username: String,
    #[prost(string, tag = "4")]
    pub email: String,
    #[prost(string, tag = "5")]
    pub display_name: String,
    #[prost(string, tag = "6")]
    pub password: String,
    #[prost(string, tag = "7")]
    pub recovery_key: String,
    #[prost(string, tag = "8")]
    pub domain: String,
    #[prost(string, tag = "9")]
    pub search_query: String,
    #[prost(string, tag = "10")]
    pub plaintext_message: String,
    #[prost(string, tag = "11")]
    pub target_message_id_short: String,
    #[prost(string, tag = "12")]
    pub reply_to_message_id_short: String,
    #[prost(string, tag = "13")]
    pub reply_to_sender: String,
    #[prost(string, tag = "14")]
    pub reply_to_text: String,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct ClientDirectoryPeerProto {
    #[prost(string, tag = "1")]
    pub username: String,
    #[prost(string, tag = "2")]
    pub display_name: String,
    #[prost(uint64, tag = "3")]
    pub key_version: u64,
    #[prost(uint64, tag = "4")]
    pub transparency_seq: u64,
    #[prost(string, tag = "5")]
    pub ed25519_pub_hex_short: String,
    #[prost(string, tag = "6")]
    pub x25519_pub_hex_short: String,
    #[prost(uint32, tag = "7")]
    pub device_number: u32,
    #[prost(uint64, tag = "8")]
    pub vault_version: u64,
    #[prost(bool, tag = "9")]
    pub is_online: bool,
    #[prost(uint64, tag = "10")]
    pub last_seen_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct ClientDecryptedMessageItemProto {
    #[prost(string, tag = "1")]
    pub sender_username: String,
    #[prost(uint64, tag = "2")]
    pub ratchet_step: u64,
    #[prost(string, tag = "3")]
    pub message_id_short: String,
    #[prost(uint64, tag = "4")]
    pub timestamp_ms: u64,
    #[prost(bool, tag = "5")]
    pub is_read_by_peer: bool,
    #[prost(string, tag = "6")]
    pub decrypted_text: String,
    #[prost(uint32, tag = "7")]
    pub wire_bytes_len: u32,
    #[prost(string, tag = "8")]
    pub nonce_hex: String,
    #[prost(string, tag = "9")]
    pub ciphertext_hex: String,
    #[prost(string, tag = "10")]
    pub signature_hex_short: String,
    #[prost(string, tag = "11")]
    pub reply_to_message_id_short: String,
    #[prost(string, tag = "12")]
    pub reply_to_sender: String,
    #[prost(string, tag = "13")]
    pub reply_to_text: String,
    #[prost(bool, tag = "14")]
    pub is_edited: bool,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct ClientWireResponseProto {
    #[prost(bool, tag = "1")]
    pub ok: bool,
    #[prost(string, tag = "2")]
    pub error_message: String,
    #[prost(string, tag = "3")]
    pub username: String,
    #[prost(string, tag = "4")]
    pub display_name: String,
    #[prost(string, tag = "5")]
    pub recovery_key: String,
    #[prost(string, tag = "6")]
    pub channel_id_hex: String,
    #[prost(uint32, tag = "7")]
    pub wire_bytes_len: u32,
    #[prost(uint64, tag = "8")]
    pub ratchet_step: u64,
    #[prost(uint32, tag = "9")]
    pub device_number: u32,
    #[prost(uint64, tag = "10")]
    pub vault_version: u64,
    #[prost(uint64, tag = "11")]
    pub storage_l1_hits: u64,
    #[prost(uint64, tag = "12")]
    pub storage_l2_reads: u64,
    #[prost(uint64, tag = "13")]
    pub storage_disk_commits: u64,
    #[prost(uint64, tag = "14")]
    pub storage_records_written: u64,
    #[prost(uint64, tag = "15")]
    pub absorbed_sidecar_failures: u64,
    #[prost(message, repeated, tag = "16")]
    pub peers: Vec<ClientDirectoryPeerProto>,
    #[prost(message, repeated, tag = "17")]
    pub messages: Vec<ClientDecryptedMessageItemProto>,
}

#[derive(Clone, PartialEq, Eq, Message)]
pub struct ClientWireWsEventProto {
    #[prost(string, tag = "1")]
    pub event_type: String,
    #[prost(string, tag = "2")]
    pub sender: String,
    #[prost(string, tag = "3")]
    pub recipient: String,
    #[prost(uint32, tag = "4")]
    pub wire_bytes_len: u32,
    #[prost(uint64, tag = "5")]
    pub timestamp_ms: u64,
}

/// Запись зарегистрированного аккаунта для постоянного зашифрованного хранения в `cryptox-storage` (`redb`).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PersistedUserAccountProto {
    #[prost(bytes = "vec", tag = "1")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub user_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub username: String,
    #[prost(string, tag = "4")]
    pub display_name: String,
    #[prost(string, tag = "5")]
    pub email: String,
    #[prost(bytes = "vec", tag = "6")]
    pub auth_verifying_key: Vec<u8>,
    #[prost(message, optional, tag = "7")]
    pub public_key_bundle: Option<PublicKeyBundle>,
    #[prost(message, optional, tag = "8")]
    pub password_vault_blob: Option<EncryptedVaultBlob>,
    #[prost(string, tag = "9")]
    pub recovery_key: String,
    #[prost(message, optional, tag = "10")]
    pub recovery_vault_blob: Option<EncryptedVaultBlob>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_uuid_v7_monotonic_and_timestamp() {
        let id1 = MessageId::new_v7();
        let id2 = MessageId::new_v7();
        assert!(id2.timestamp_ms() >= id1.timestamp_ms());
        assert_eq!(MessageId::from_slice(&id1.to_vec()), Ok(id1));
    }

    #[test]
    fn test_deterministic_direct_channel_id_is_symmetric_and_tenant_isolated() {
        let tenant_a = TenantId::new_v7();
        let tenant_b = TenantId::new_v7();
        let alice = UserId::new_v7();
        let bob = UserId::new_v7();

        let chat_ab = ChannelId::deterministic_direct(tenant_a, alice, bob);
        let chat_ba = ChannelId::deterministic_direct(tenant_a, bob, alice);
        assert_eq!(chat_ab, chat_ba, "ChannelId должен совпадать независимо от порядка (Alice, Bob)");

        let chat_other_tenant = ChannelId::deterministic_direct(tenant_b, alice, bob);
        assert_ne!(chat_ab, chat_other_tenant, "Разные компании должны иметь строго изолированные ChannelId");
    }

    proptest! {
        #[test]
        fn proptest_arbitrary_corrupted_bytes_never_panic_on_decode(random_bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            // Любой мусор из сети должен безопасно возвращать Result, никогда не вызывая panic!
            let _ = EncryptedEnvelope::from_wire_bytes(&random_bytes);
            let _ = PublicKeyBundle::from_wire_bytes(&random_bytes);
            let _ = EncryptedVaultBlob::from_wire_bytes(&random_bytes);
        }
    }
}
