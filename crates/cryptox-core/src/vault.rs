//! Модуль Зашифрованного Облачного Сейфа Ключей (`CloudKeyVault`).
//!
//! Обеспечивает UX уровня Яндекс.Мессенджера / Telegram (мгновенная синхронизация истории чатов
//! при входе с нового ноутбука или телефона) при сохранении Zero-Knowledge на сервере:
//! - Сервер (`auth-vault-svc`) хранит только бинарный `EncryptedVaultBlob`.
//! - Ключ расшифровки выводится исключительно в памяти клиента через `Argon2id` (NIST SP 800-63B / OWASP ASVS L3).
//! - Любое изменение `tenant_id`, `user_id`, `vault_version` или параметров Argon2id на сервере
//!   детектируется через привязку к AEAD `AAD`.

use crate::{
    error::CryptoError,
    identity::{IdentitySecretSnapshot, UserIdentity},
    provider::{CryptoProvider, XChaCha20Poly1305Provider},
    session::{ChatSession, SessionVaultRecord},
};
use argon2::{Algorithm, Argon2, Params, Version};
use cryptox_proto::{
    DeviceId, EncryptedVaultBlob, EncryptionPolicy, LoginChallengeResponse, LoginVerifyRequest,
};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Профиль параметров `Argon2id` для вывода мастер-ключа облачного сейфа.
#[derive(Clone, Copy, Debug)]
pub struct Argon2Profile {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Profile {
    /// Боевой профиль по стандарту OWASP ASVS v5.0 Level 3 (64 МБ RAM, 3 итерации, 2 потока).
    #[must_use]
    pub const fn production_owasp_l3() -> Self {
        Self {
            m_cost_kib: 65_536, // 64 MiB
            t_cost: 3,
            p_cost: 2,
        }
    }

    /// Интерактивный профиль для быстрых прогонов `proptest` (4 МБ RAM, 1 итерация).
    #[must_use]
    pub const fn interactive_fast() -> Self {
        Self {
            m_cost_kib: 4_096, // 4 MiB
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// Внутренняя бинарная Protobuf-структура содержимого сейфа до шифрования.
#[derive(Clone, PartialEq, Eq, Message)]
struct VaultInnerProto {
    #[prost(bytes = "vec", tag = "1")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub device_id: Vec<u8>,
    #[prost(int32, tag = "4")]
    pub cipher_suite: i32,
    #[prost(uint64, tag = "5")]
    pub key_version: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub ed25519_secret: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub x25519_secret: Vec<u8>,
    #[prost(message, repeated, tag = "8")]
    pub sessions: Vec<VaultSessionEntryProto>,
}

#[derive(Clone, PartialEq, Eq, Message)]
struct VaultSessionEntryProto {
    #[prost(bytes = "vec", tag = "1")]
    pub tenant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub channel_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub peer_user_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub peer_verifying_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub master_channel_seed: Vec<u8>,
    #[prost(uint64, tag = "6")]
    pub next_outbound_step: u64,
}

pub struct CloudKeyVault;

impl CloudKeyVault {
    /// Выводит базовый 256-битный секрет из пароля сотрудника и 16-байтной соли через `Argon2id`,
    /// а затем через односторонний `BLAKE3 KDF` разделяет его на два независимых домена:
    /// 1. `VaultMasterKey` (остается строго на клиенте для шифрования `EncryptedVaultBlob`);
    /// 2. `AuthSigningKey` (используется для подписи одноразовых челленджей входа без раскрытия пароля серверу).
    fn derive_root_argon2(
        password: &[u8],
        salt: &[u8],
        profile: Argon2Profile,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let params = Params::new(
            profile.m_cost_kib,
            profile.t_cost,
            profile.p_cost,
            Some(32),
        )
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut derived = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, salt, &mut *derived)
            .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

        Ok(derived)
    }

    fn derive_vault_key(
        password: &[u8],
        salt: &[u8],
        profile: Argon2Profile,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let root = Self::derive_root_argon2(password, salt, profile)?;
        let mut kdf = blake3::Hasher::new_derive_key("cryptox.domain.cloud-vault-encryption-key.v1");
        kdf.update(&*root);
        Ok(Zeroizing::new(*kdf.finalize().as_bytes()))
    }

    /// Выводит пару ключей `Ed25519` для Zero-Knowledge аутентификации по паролю и соли `argon2_salt` из `EncryptedVaultBlob`.
    /// Сервер получает только публичный 32-байтный `verifying_key` и физически не может вычислить из него `VaultMasterKey`!
    pub fn derive_auth_verifying_key(
        password: &[u8],
        salt: &[u8],
        profile: Argon2Profile,
    ) -> Result<[u8; 32], CryptoError> {
        let signing = Self::derive_auth_signing_key(password, salt, profile)?;
        Ok(signing.verifying_key().to_bytes())
    }

    fn derive_auth_signing_key(
        password: &[u8],
        salt: &[u8],
        profile: Argon2Profile,
    ) -> Result<SigningKey, CryptoError> {
        let root = Self::derive_root_argon2(password, salt, profile)?;
        let mut kdf = blake3::Hasher::new_derive_key("cryptox.domain.zero-knowledge-auth-login.v1");
        kdf.update(&*root);
        let auth_seed = Zeroizing::new(*kdf.finalize().as_bytes());
        Ok(SigningKey::from_bytes(&auth_seed))
    }

    /// Формирует криптографический ответ `LoginVerifyRequest` на одноразовый челлендж сервера `LoginChallengeResponse`
    /// без передачи пароля или хеша пароля по сети (защита от Pass-the-Hash и перехвата трафика).
    pub fn sign_login_challenge(
        challenge: &LoginChallengeResponse,
        password: &[u8],
        device_id: DeviceId,
    ) -> Result<LoginVerifyRequest, CryptoError> {
        let profile = Argon2Profile {
            m_cost_kib: challenge.argon2_m_cost_kib,
            t_cost: challenge.argon2_t_cost,
            p_cost: challenge.argon2_p_cost,
        };
        let signing_key = Self::derive_auth_signing_key(password, &challenge.argon2_salt, profile)?;
        let transcript = challenge.canonical_challenge_transcript(device_id);
        let signature = signing_key.sign(&transcript);

        Ok(LoginVerifyRequest {
            challenge_id: challenge.challenge_id.clone(),
            tenant_id: challenge.tenant_id.clone(),
            user_id: challenge.user_id.clone(),
            device_id: device_id.to_vec(),
            challenge_signature: signature.to_bytes().to_vec(),
        })
    }

    /// Запечатывает личность сотрудника (`UserIdentity`) и все ключи его активных чатов (`ChatSession`)
    /// в зашифрованный облачный контейнер `EncryptedVaultBlob` для загрузки на сервер `auth-vault-svc`.
    pub fn seal_to_cloud_blob(
        identity: &UserIdentity,
        sessions: &[&ChatSession],
        password: &[u8],
        vault_version: u64,
        profile: Argon2Profile,
    ) -> Result<EncryptedVaultBlob, CryptoError> {
        let snap = identity.to_secret_snapshot()?;

        let mut session_protos = Vec::with_capacity(sessions.len());
        for s in sessions {
            let rec = s.to_vault_record();
            session_protos.push(VaultSessionEntryProto {
                tenant_id: rec.tenant_id_bytes.to_vec(),
                channel_id: rec.channel_id_bytes.to_vec(),
                peer_user_id: rec.peer_user_id_bytes.to_vec(),
                peer_verifying_key: rec.peer_verifying_key_bytes.to_vec(),
                master_channel_seed: rec.master_channel_seed.to_vec(),
                next_outbound_step: rec.next_outbound_step,
            });
        }

        let inner = VaultInnerProto {
            tenant_id: snap.tenant_id_bytes.to_vec(),
            user_id: snap.user_id_bytes.to_vec(),
            device_id: snap.device_id_bytes.to_vec(),
            cipher_suite: snap.cipher_suite,
            key_version: snap.key_version,
            ed25519_secret: snap.ed25519_secret_bytes.to_vec(),
            x25519_secret: snap.x25519_secret_bytes.to_vec(),
            sessions: session_protos,
        };

        let serialized_inner = Zeroizing::new(inner.encode_to_vec());

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let vault_key = Self::derive_vault_key(password, &salt, profile)?;
        let provider = XChaCha20Poly1305Provider;
        let nonce = provider.generate_nonce();

        let mut blob = EncryptedVaultBlob {
            tenant_id: identity.tenant_id().to_vec(),
            user_id: identity.user_id().to_vec(),
            vault_version,
            argon2_salt: salt.to_vec(),
            argon2_m_cost_kib: profile.m_cost_kib,
            argon2_t_cost: profile.t_cost,
            argon2_p_cost: profile.p_cost,
            nonce,
            encrypted_payload: Vec::new(),
        };

        let aad = blob.canonical_aad();
        blob.encrypted_payload =
            provider.seal(&vault_key, &blob.nonce, &aad, &serialized_inner)?;

        Ok(blob)
    }

    /// Открывает скачанный с сервера `EncryptedVaultBlob` на новом устройстве сотрудника
    /// и полностью восстанавливает его `UserIdentity` и все ключи чатов (`Vec<ChatSession>`).
    pub fn unlock_from_cloud_blob(
        blob: &EncryptedVaultBlob,
        password: &[u8],
        new_device_id: DeviceId,
        default_policy: EncryptionPolicy,
        tenant_compliance_pub_bytes: Option<[u8; 32]>,
    ) -> Result<(UserIdentity, Vec<ChatSession>), CryptoError> {
        let profile = Argon2Profile {
            m_cost_kib: blob.argon2_m_cost_kib,
            t_cost: blob.argon2_t_cost,
            p_cost: blob.argon2_p_cost,
        };

        let vault_key = Self::derive_vault_key(password, &blob.argon2_salt, profile)?;
        let provider = XChaCha20Poly1305Provider;
        let aad = blob.canonical_aad();

        let decrypted_bytes = Zeroizing::new(provider.open(
            &vault_key,
            &blob.nonce,
            &aad,
            &blob.encrypted_payload,
        )?);

        let inner = VaultInnerProto::decode(decrypted_bytes.as_slice())
            .map_err(|_| CryptoError::AeadIntegrityFailure)?;

        let snap = IdentitySecretSnapshot {
            tenant_id_bytes: inner
                .tenant_id
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial("invalid vault tenant_id"))?,
            user_id_bytes: inner
                .user_id
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial("invalid vault user_id"))?,
            device_id_bytes: inner
                .device_id
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial("invalid vault device_id"))?,
            cipher_suite: inner.cipher_suite,
            key_version: inner.key_version,
            ed25519_secret_bytes: inner
                .ed25519_secret
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial("invalid vault ed25519 key"))?,
            x25519_secret_bytes: inner
                .x25519_secret
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyMaterial("invalid vault x25519 key"))?,
        };

        let restored_identity = UserIdentity::from_secret_snapshot(&snap, Some(new_device_id))?;

        let mut restored_sessions = Vec::with_capacity(inner.sessions.len());
        for s in &inner.sessions {
            let rec = SessionVaultRecord {
                tenant_id_bytes: s
                    .tenant_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyMaterial("invalid session tenant_id"))?,
                channel_id_bytes: s
                    .channel_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyMaterial("invalid session channel_id"))?,
                peer_user_id_bytes: s
                    .peer_user_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyMaterial("invalid session peer_user_id"))?,
                peer_verifying_key_bytes: s
                    .peer_verifying_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyMaterial("invalid session peer vk"))?,
                master_channel_seed: s
                    .master_channel_seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyMaterial("invalid session seed"))?,
                next_outbound_step: s.next_outbound_step,
            };
            restored_sessions.push(ChatSession::from_vault_record(
                &rec,
                default_policy,
                tenant_compliance_pub_bytes,
            )?);
        }

        Ok((restored_identity, restored_sessions))
    }
}
