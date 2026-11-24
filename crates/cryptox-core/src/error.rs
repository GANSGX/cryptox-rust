use cryptox_proto::ProtoError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("ошибка бинарного протокола: {0}")]
    Proto(#[from] ProtoError),

    #[error("криптографическое ядро уничтожено (Crypto-Shredded / Remote Wipe выполнен)")]
    IdentityShredded,

    #[error("нарушение изоляции организаций (Tenant Mismatch): сообщение/ключ из чужой компании")]
    TenantMismatch,

    #[error("нарушение привязки канала (Channel Mismatch): попытка подставить сообщение в чужой чат")]
    ChannelMismatch,

    #[error("недействительная цифровая подпись Ed25519 (попытка подмены ключа или отправителя)")]
    SignatureVerificationFailed,

    #[error("ошибка аутентифицированного шифрования/дешифрования AEAD (нарушена целостность шифротекста или AAD)")]
    AeadIntegrityFailure,

    #[error("ошибка деривации ключа Argon2id: {0}")]
    KeyDerivationError(String),

    #[error("некорректная длина ключа или криптографического параметра: {0}")]
    InvalidKeyMaterial(&'static str),

    #[error("в конверте отсутствует корпоративный DLP/Escrow ключ или политика чата StrictZeroKnowledge")]
    EscrowNotPresent,

    #[error("атака повторной доставки сообщения заблокирована (Ratchet Replay Attack на шаге {0})")]
    ReplayAttackDetected(u64),
}
