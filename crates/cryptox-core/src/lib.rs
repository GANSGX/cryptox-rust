//! `cryptox-core` — Клиентское криптографическое ядро мессенджера CryptoX.
//!
//! Реализует:
//! 1. Модульный трейт `CryptoProvider` (XChaCha20-Poly1305 / AES-256-GCM / слот под ГОСТ СКЗИ по ПП РФ № 313).
//! 2. `UserIdentity` с самоподписанным `PublicKeyBundle` и мгновенным затиранием памяти `crypto_shred()`.
//! 3. Сквозное шифрование чатов (`ChatSession`) с привязкой метаданных `AAD`, одноразовыми ключами сообщений
//!    и двухрежимной корпоративной политикой (`StrictZeroKnowledge` VIP vs `CorporateEscrowDlp` на HSM компании).
//! 4. `CloudKeyVault` (`Argon2id` + `XChaCha20-Poly1305`) для мгновенной облачной синхронизации истории
//!    на новых устройствах сотрудника без раскрытия ключей серверу.

pub mod error;
pub mod identity;
pub mod provider;
pub mod session;
pub mod vault;

pub use error::CryptoError;
pub use identity::{TenantComplianceKeyPair, UserIdentity};
pub use provider::{Aes256GcmProvider, CryptoProvider, XChaCha20Poly1305Provider};
pub use session::ChatSession;
pub use vault::{Argon2Profile, CloudKeyVault};
