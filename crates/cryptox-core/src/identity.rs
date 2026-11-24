//! Модуль криптографической личности сотрудника (`UserIdentity`) и корпоративного HSM-ключа (`TenantComplianceKeyPair`).
//!
//! Гарантирует:
//! - Все приватные ключи в памяти затираются нулями при удалении (`Zeroize`) или по команде `crypto_shred()` (Remote Wipe).
//! - Публичный пакет ключей `PublicKeyBundle` криптографически самоподписан `Ed25519` (защита от подмены `X25519` ключа сервером).

use crate::error::CryptoError;
use cryptox_proto::{CipherSuiteId, DeviceId, PublicKeyBundle, TenantId, UserId};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Сериализуемый снимок секретных ключей сотрудника для помещения внутрь `Encrypted Cloud Key Vault`.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct IdentitySecretSnapshot {
    pub tenant_id_bytes: [u8; 16],
    pub user_id_bytes: [u8; 16],
    pub device_id_bytes: [u8; 16],
    pub cipher_suite: i32,
    pub key_version: u64,
    pub ed25519_secret_bytes: [u8; 32],
    pub x25519_secret_bytes: [u8; 32],
}

/// Криптографическая личность сотрудника на устройстве.
pub struct UserIdentity {
    tenant_id: TenantId,
    user_id: UserId,
    device_id: DeviceId,
    cipher_suite: CipherSuiteId,
    key_version: u64,
    ed25519_signing: Option<SigningKey>,
    x25519_secret: Option<X25519StaticSecret>,
    shredded: bool,
}

impl UserIdentity {
    /// Генерирует новую криптографическую личность сотрудника с использованием системного `OsRng`.
    #[must_use]
    pub fn generate(
        tenant_id: TenantId,
        user_id: UserId,
        device_id: DeviceId,
        cipher_suite: CipherSuiteId,
        key_version: u64,
    ) -> Self {
        let ed25519_signing = SigningKey::generate(&mut OsRng);
        let x25519_secret = X25519StaticSecret::random_from_rng(OsRng);

        Self {
            tenant_id,
            user_id,
            device_id,
            cipher_suite,
            key_version,
            ed25519_signing: Some(ed25519_signing),
            x25519_secret: Some(x25519_secret),
            shredded: false,
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub const fn is_shredded(&self) -> bool {
        self.shredded
    }

    /// **Мина №1 (Remote Wipe / Crypto-Shredding):**
    /// При увольнении сотрудника или отзыве сессии мгновенно затирает все приватные ключи
    /// в оперативной памяти устройства. После вызова любые попытки расшифровать кэш или
    /// подписать пакет возвращают `Err(CryptoError::IdentityShredded)`.
    pub fn crypto_shred(&mut self) {
        self.ed25519_signing = None;
        self.x25519_secret = None;
        self.shredded = true;
    }

    /// Экспортирует самоподписанный `PublicKeyBundle` для загрузки в `user-directory-svc` (поиск по `@username`).
    pub fn export_public_bundle(&self) -> Result<PublicKeyBundle, CryptoError> {
        if self.shredded {
            return Err(CryptoError::IdentityShredded);
        }
        let signing = self
            .ed25519_signing
            .as_ref()
            .ok_or(CryptoError::IdentityShredded)?;
        let x25519 = self
            .x25519_secret
            .as_ref()
            .ok_or(CryptoError::IdentityShredded)?;

        let x25519_pub = X25519PublicKey::from(x25519);

        let mut bundle = PublicKeyBundle {
            tenant_id: self.tenant_id.to_vec(),
            user_id: self.user_id.to_vec(),
            device_id: self.device_id.to_vec(),
            cipher_suite: self.cipher_suite as i32,
            ed25519_verifying_key: signing.verifying_key().to_bytes().to_vec(),
            x25519_public_key: x25519_pub.as_bytes().to_vec(),
            key_version: self.key_version,
            self_signature: Vec::new(),
        };

        let msg = bundle.canonical_signing_bytes();
        let sig: Signature = signing.sign(&msg);
        bundle.self_signature = sig.to_bytes().to_vec();

        Ok(bundle)
    }

    /// Проверяет подлинность и целостность `PublicKeyBundle` собеседника (защита от подмены ключа взломанным сервером).
    pub fn verify_peer_bundle(
        expected_tenant: TenantId,
        bundle: &PublicKeyBundle,
    ) -> Result<(UserId, VerifyingKey, X25519PublicKey), CryptoError> {
        let peer_tenant = TenantId::from_slice(&bundle.tenant_id)?;
        if peer_tenant != expected_tenant {
            return Err(CryptoError::TenantMismatch);
        }
        let peer_user = UserId::from_slice(&bundle.user_id)?;
        let _ = DeviceId::from_slice(&bundle.device_id)?;
        let _ = CipherSuiteId::try_from_proto(bundle.cipher_suite)?;

        let vk_bytes: [u8; 32] = bundle
            .ed25519_verifying_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial("invalid ed25519 verifying key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        let x_bytes: [u8; 32] = bundle
            .x25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial("invalid x25519 public key length"))?;
        let x25519_pub = X25519PublicKey::from(x_bytes);

        let sig_bytes: [u8; 64] = bundle
            .self_signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        let signature = Signature::from_bytes(&sig_bytes);

        let signing_payload = bundle.canonical_signing_bytes();
        verifying_key
            .verify(&signing_payload, &signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        Ok((peer_user, verifying_key, x25519_pub))
    }

    /// Подписывает произвольные байты ключом `Ed25519` сотрудника.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        if self.shredded {
            return Err(CryptoError::IdentityShredded);
        }
        let signing = self
            .ed25519_signing
            .as_ref()
            .ok_or(CryptoError::IdentityShredded)?;
        Ok(signing.sign(message).to_bytes())
    }

    /// Вычисляет общий секрет Диффи-Хеллмана `X25519` с проверенным публичным ключом собеседника.
    pub fn diffie_hellman(
        &self,
        peer_public: &X25519PublicKey,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        if self.shredded {
            return Err(CryptoError::IdentityShredded);
        }
        let secret = self
            .x25519_secret
            .as_ref()
            .ok_or(CryptoError::IdentityShredded)?;
        let shared = secret.diffie_hellman(peer_public);
        Ok(Zeroizing::new(shared.to_bytes()))
    }

    /// Экспортирует секретный снимок для упаковки в `CloudKeyVault`.
    pub fn to_secret_snapshot(&self) -> Result<IdentitySecretSnapshot, CryptoError> {
        if self.shredded {
            return Err(CryptoError::IdentityShredded);
        }
        let signing = self
            .ed25519_signing
            .as_ref()
            .ok_or(CryptoError::IdentityShredded)?;
        let x25519 = self
            .x25519_secret
            .as_ref()
            .ok_or(CryptoError::IdentityShredded)?;

        Ok(IdentitySecretSnapshot {
            tenant_id_bytes: *self.tenant_id.as_bytes(),
            user_id_bytes: *self.user_id.as_bytes(),
            device_id_bytes: *self.device_id.as_bytes(),
            cipher_suite: self.cipher_suite as i32,
            key_version: self.key_version,
            ed25519_secret_bytes: signing.to_bytes(),
            x25519_secret_bytes: x25519.to_bytes(),
        })
    }

    /// Восстанавливает `UserIdentity` на новом устройстве сотрудника из расшифрованного `CloudKeyVault`.
    pub fn from_secret_snapshot(
        snapshot: &IdentitySecretSnapshot,
        new_device_id: Option<DeviceId>,
    ) -> Result<Self, CryptoError> {
        let tenant_id = TenantId::from_slice(&snapshot.tenant_id_bytes)?;
        let user_id = UserId::from_slice(&snapshot.user_id_bytes)?;
        let device_id = match new_device_id {
            Some(d) => d,
            None => DeviceId::from_slice(&snapshot.device_id_bytes)?,
        };
        let cipher_suite = CipherSuiteId::try_from_proto(snapshot.cipher_suite)?;

        let ed25519_signing = SigningKey::from_bytes(&snapshot.ed25519_secret_bytes);
        let x25519_secret = X25519StaticSecret::from(snapshot.x25519_secret_bytes);

        Ok(Self {
            tenant_id,
            user_id,
            device_id,
            cipher_suite,
            key_version: snapshot.key_version,
            ed25519_signing: Some(ed25519_signing),
            x25519_secret: Some(x25519_secret),
            shredded: false,
        })
    }
}

/// Аппаратная ключевая пара Службы Безопасности (HSM / Рутокен / DLP-шлюз) компании-заказчика.
///
/// Приватный ключ живет ТОЛЬКО в HSM безопасника компании (вне БД мессенджера),
/// а публичный ключ раздается клиентам компании для режима `EncryptionPolicy::CorporateEscrowDlp`.
pub struct TenantComplianceKeyPair {
    tenant_id: TenantId,
    secret_key: X25519StaticSecret,
    public_key: X25519PublicKey,
}

impl TenantComplianceKeyPair {
    #[must_use]
    pub fn generate(tenant_id: TenantId) -> Self {
        let secret_key = X25519StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&secret_key);
        Self {
            tenant_id,
            secret_key,
            public_key,
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    #[must_use]
    pub(crate) fn diffie_hellman(&self, ephemeral_pub: &X25519PublicKey) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret_key.diffie_hellman(ephemeral_pub).to_bytes())
    }
}
