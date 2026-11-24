//! Модуль защищенной сессии чата (`ChatSession`).
//!
//! Реализует:
//! - Установку общего секрета `X25519` между Алисой и Бобом с верификацией подписи `PublicKeyBundle`.
//! - Детерминированный `BLAKE3` Key-Derivation Ratchet: каждое сообщение (`ratchet_step`) шифруется
//!   уникальным одноразовым 256-битным ключом (`MessageKey`), при этом новое устройство сотрудника
//!   при облачной синхронизации может мгновенно вычислить ключ для любого исторического сообщения за O(1).
//! - Жесткую привязку контекста `AAD` (`tenant_id`, `channel_id`, `message_id`, `sender_id`, `ratchet_step`).
//! - Поддержку как `StrictZeroKnowledge` (VIP-контур Совета Директоров), так и `CorporateEscrowDlp`
//!   (запечатывание копии ключа сообщения на аппаратный HSM-ключ Службы Безопасности компании).

use crate::{
    error::CryptoError,
    identity::{TenantComplianceKeyPair, UserIdentity},
    provider::CryptoProvider,
};
use cryptox_proto::{
    ChannelId, EncryptedEnvelope, EncryptionPolicy, MessageId, PublicKeyBundle, TenantId, UserId,
    PROTOCOL_VERSION_V1,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// 64-шаговое скользящее окно защиты от Replay-атак (по стандарту IPsec ESP RFC 4303 / WireGuard).
#[derive(Clone, Copy, Debug, Default)]
struct ReplaySlidingWindow {
    max_step: u64,
    bitmap: u64,
}

impl ReplaySlidingWindow {
    /// Проверяет, не был ли шаг `step` уже принят ранее или вытеснен за пределы 64-шагового окна.
    fn check_not_replayed(&self, step: u64) -> Result<(), CryptoError> {
        if step == 0 {
            return Err(CryptoError::ReplayAttackDetected(0));
        }
        if step > self.max_step {
            return Ok(());
        }
        let diff = self.max_step - step;
        if diff >= 64 {
            return Err(CryptoError::ReplayAttackDetected(step));
        }
        if (self.bitmap & (1u64 << diff)) != 0 {
            return Err(CryptoError::ReplayAttackDetected(step));
        }
        Ok(())
    }

    /// Фиксирует успешно расшифрованный и аутентифицированный шаг `step` в битовой маске окна.
    fn record_step(&mut self, step: u64) {
        if step > self.max_step {
            let shift = step - self.max_step;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.max_step = step;
        } else {
            let diff = self.max_step - step;
            if diff < 64 {
                self.bitmap |= 1u64 << diff;
            }
        }
    }
}

/// Снимок состояния сессии чата для сохранения в `CloudKeyVault` (облачная синхронизация между устройствами).
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SessionVaultRecord {
    pub tenant_id_bytes: [u8; 16],
    pub channel_id_bytes: [u8; 16],
    pub peer_user_id_bytes: [u8; 16],
    pub peer_verifying_key_bytes: [u8; 32],
    pub master_channel_seed: [u8; 32],
    pub next_outbound_step: u64,
}

pub struct ChatSession {
    tenant_id: TenantId,
    channel_id: ChannelId,
    peer_user_id: UserId,
    peer_verifying_key: VerifyingKey,
    master_channel_seed: Zeroizing<[u8; 32]>,
    next_outbound_step: u64,
    policy: EncryptionPolicy,
    tenant_compliance_pub: Option<X25519PublicKey>,
    inbound_replay_window: Mutex<ReplaySlidingWindow>,
}

impl ChatSession {
    /// Устанавливает защищенную сессию личного чата (1-на-1) с найденным по `@username` собеседником.
    pub fn establish_direct(
        my_identity: &UserIdentity,
        peer_bundle: &PublicKeyBundle,
        policy: EncryptionPolicy,
        tenant_compliance_pub_bytes: Option<[u8; 32]>,
    ) -> Result<Self, CryptoError> {
        let (peer_user_id, peer_verifying_key, peer_x25519_pub) =
            UserIdentity::verify_peer_bundle(my_identity.tenant_id(), peer_bundle)?;

        let channel_id = ChannelId::deterministic_direct(
            my_identity.tenant_id(),
            my_identity.user_id(),
            peer_user_id,
        );

        let raw_dh = my_identity.diffie_hellman(&peer_x25519_pub)?;

        // Выводим 256-битный корневой сид канала с привязкой к tenant_id и channel_id
        let mut kdf = blake3::Hasher::new_derive_key("cryptox.channel-master-seed.v1");
        kdf.update(my_identity.tenant_id().as_bytes());
        kdf.update(channel_id.as_bytes());
        kdf.update(&*raw_dh);
        let master_channel_seed = Zeroizing::new(*kdf.finalize().as_bytes());

        let tenant_compliance_pub = tenant_compliance_pub_bytes.map(X25519PublicKey::from);

        Ok(Self {
            tenant_id: my_identity.tenant_id(),
            channel_id,
            peer_user_id,
            peer_verifying_key,
            master_channel_seed,
            next_outbound_step: 1,
            policy,
            tenant_compliance_pub,
            inbound_replay_window: Mutex::new(ReplaySlidingWindow::default()),
        })
    }

    #[must_use]
    pub const fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    #[must_use]
    pub const fn peer_user_id(&self) -> UserId {
        self.peer_user_id
    }

    /// Выводит одноразовый 256-битный ключ сообщения для конкретного шага `ratchet_step` и отправителя.
    fn derive_message_key(&self, sender_id: UserId, ratchet_step: u64) -> Zeroizing<[u8; 32]> {
        let mut hasher = blake3::Hasher::new_keyed(&self.master_channel_seed);
        hasher.update(b"cryptox.msg-ratchet-key.v1:");
        hasher.update(self.tenant_id.as_bytes());
        hasher.update(self.channel_id.as_bytes());
        hasher.update(sender_id.as_bytes());
        hasher.update(&ratchet_step.to_le_bytes());
        Zeroizing::new(*hasher.finalize().as_bytes())
    }

    /// Шифрует сообщение и упаковывает его в подписанный бинарный конверт `EncryptedEnvelope`.
    pub fn encrypt_message(
        &mut self,
        my_identity: &UserIdentity,
        provider: &dyn CryptoProvider,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError> {
        if my_identity.is_shredded() {
            return Err(CryptoError::IdentityShredded);
        }
        if my_identity.tenant_id() != self.tenant_id {
            return Err(CryptoError::TenantMismatch);
        }

        let step = self.next_outbound_step;
        self.next_outbound_step = self.next_outbound_step.saturating_add(1);

        let message_id = MessageId::new_v7();
        let message_key = self.derive_message_key(my_identity.user_id(), step);
        let nonce = provider.generate_nonce();

        // Если включен стандартный корпоративный режим с DLP/HSM эскроу, запечатываем копию
        // одноразового ключа сообщения на публичный HSM-ключ компании
        let corporate_escrow_sealed_key = match (self.policy, &self.tenant_compliance_pub) {
            (EncryptionPolicy::CorporateEscrowDlp, Some(compliance_pub)) => {
                Self::seal_escrow_key(
                    provider,
                    self.tenant_id,
                    self.channel_id,
                    message_id,
                    compliance_pub,
                    &message_key,
                )?
            }
            _ => Vec::new(),
        };

        let mut envelope = EncryptedEnvelope {
            protocol_version: PROTOCOL_VERSION_V1,
            cipher_suite: provider.suite_id() as i32,
            tenant_id: self.tenant_id.to_vec(),
            channel_id: self.channel_id.to_vec(),
            message_id: message_id.to_vec(),
            sender_user_id: my_identity.user_id().to_vec(),
            sender_device_id: my_identity.device_id().to_vec(),
            ratchet_step: step,
            nonce,
            ciphertext: Vec::new(),
            corporate_escrow_sealed_key,
            ed25519_signature: Vec::new(),
        };

        // Вычисляем AAD (привязываем все заголовки маршрутизации к тегу Poly1305/GCM)
        let aad = envelope.canonical_aad();
        envelope.ciphertext = provider.seal(&message_key, &envelope.nonce, &aad, plaintext)?;

        // Подписываем весь конверт ключом Ed25519 отправителя
        let signing_bytes = envelope.canonical_signing_bytes();
        let sig = my_identity.sign(&signing_bytes)?;
        envelope.ed25519_signature = sig.to_vec();

        Ok(envelope)
    }

    /// Расшифровывает входящий конверт `EncryptedEnvelope` в живом потоке с защитой от **Replay-атак**
    /// (повторный пакет с тем же `ratchet_step` блокируется с `Err(CryptoError::ReplayAttackDetected)`).
    pub fn decrypt_message(
        &self,
        my_identity: &UserIdentity,
        provider: &dyn CryptoProvider,
        envelope: &EncryptedEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.decrypt_internal(my_identity, provider, envelope, true)
    }

    /// Расшифровывает сообщение из облачного архива истории (без сдвига live-окна повторов,
    /// чтобы историю можно было перечитывать при прокрутке чата).
    pub fn decrypt_historical_message(
        &self,
        my_identity: &UserIdentity,
        provider: &dyn CryptoProvider,
        envelope: &EncryptedEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.decrypt_internal(my_identity, provider, envelope, false)
    }

    fn decrypt_internal(
        &self,
        my_identity: &UserIdentity,
        provider: &dyn CryptoProvider,
        envelope: &EncryptedEnvelope,
        enforce_replay_window: bool,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if my_identity.is_shredded() {
            return Err(CryptoError::IdentityShredded);
        }
        envelope.validate_structure()?;

        let env_tenant = TenantId::from_slice(&envelope.tenant_id)?;
        if !env_tenant.ct_eq_id(&self.tenant_id) {
            return Err(CryptoError::TenantMismatch);
        }

        let env_channel = ChannelId::from_slice(&envelope.channel_id)?;
        if !env_channel.ct_eq_id(&self.channel_id) {
            return Err(CryptoError::ChannelMismatch);
        }

        let sender_id = UserId::from_slice(&envelope.sender_user_id)?;

        // Проверяем окно защиты от Replay-атак для входящих сообщений собеседника
        if enforce_replay_window && sender_id.ct_eq_id(&self.peer_user_id) {
            let win = self
                .inbound_replay_window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            win.check_not_replayed(envelope.ratchet_step)?;
        }

        // Выбираем ключ проверки подписи за константное время: либо собеседника, либо наш собственный
        let verifying_key = if sender_id.ct_eq_id(&self.peer_user_id) {
            self.peer_verifying_key
        } else if sender_id.ct_eq_id(&my_identity.user_id()) {
            let my_bundle = my_identity.export_public_bundle()?;
            let vk_bytes: [u8; 32] = my_bundle
                .ed25519_verifying_key
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::SignatureVerificationFailed)?;
            VerifyingKey::from_bytes(&vk_bytes)
                .map_err(|_| CryptoError::SignatureVerificationFailed)?
        } else {
            return Err(CryptoError::SignatureVerificationFailed);
        };

        let sig_bytes: [u8; 64] = envelope
            .ed25519_signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;
        let signature = Signature::from_bytes(&sig_bytes);

        let signing_bytes = envelope.canonical_signing_bytes();
        verifying_key
            .verify(&signing_bytes, &signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)?;

        let message_key = self.derive_message_key(sender_id, envelope.ratchet_step);
        let aad = envelope.canonical_aad();
        let plaintext = provider.open(&message_key, &envelope.nonce, &aad, &envelope.ciphertext)?;

        if enforce_replay_window && sender_id.ct_eq_id(&self.peer_user_id) {
            let mut win = self
                .inbound_replay_window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            win.record_step(envelope.ratchet_step);
        }

        Ok(Zeroizing::new(plaintext))
    }

    /// Запечатывает одноразовый ключ сообщения на публичный аппаратный ключ комплаенса/DLP компании.
    fn seal_escrow_key(
        provider: &dyn CryptoProvider,
        tenant_id: TenantId,
        channel_id: ChannelId,
        message_id: MessageId,
        compliance_pub: &X25519PublicKey,
        message_key: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
        let shared = Zeroizing::new(ephemeral_secret.diffie_hellman(compliance_pub).to_bytes());

        let mut kdf = blake3::Hasher::new_derive_key("cryptox.corporate-escrow-wrap.v1");
        kdf.update(tenant_id.as_bytes());
        kdf.update(channel_id.as_bytes());
        kdf.update(message_id.as_bytes());
        kdf.update(&*shared);
        let wrap_key = Zeroizing::new(*kdf.finalize().as_bytes());

        let nonce = provider.generate_nonce();
        let mut escrow_aad = Vec::with_capacity(48);
        escrow_aad.extend_from_slice(tenant_id.as_bytes());
        escrow_aad.extend_from_slice(channel_id.as_bytes());
        escrow_aad.extend_from_slice(message_id.as_bytes());

        let sealed = provider.seal(&wrap_key, &nonce, &escrow_aad, message_key)?;

        // Формат: [32 байта ephemeral_pub] || [1 байт nonce_len] || [nonce] || [sealed_key]
        let mut out = Vec::with_capacity(33 + nonce.len() + sealed.len());
        out.extend_from_slice(ephemeral_pub.as_bytes());
        out.push(nonce.len() as u8);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Позволяет аппаратному HSM-шлюзу Службы Безопасности (DLP) компании расшифровать сообщение
    /// в режиме `CorporateEscrowDlp`. В режиме `StrictZeroKnowledge` (VIP) возвращает `Err(EscrowNotPresent)`.
    pub fn decrypt_with_corporate_hsm(
        compliance_hsm: &TenantComplianceKeyPair,
        provider: &dyn CryptoProvider,
        envelope: &EncryptedEnvelope,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        envelope.validate_structure()?;
        let env_tenant = TenantId::from_slice(&envelope.tenant_id)?;
        if env_tenant != compliance_hsm.tenant_id() {
            return Err(CryptoError::TenantMismatch);
        }
        if envelope.corporate_escrow_sealed_key.len() < 34 {
            return Err(CryptoError::EscrowNotPresent);
        }

        let eph_bytes: [u8; 32] = envelope.corporate_escrow_sealed_key[..32]
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial("invalid escrow ephemeral key"))?;
        let ephemeral_pub = X25519PublicKey::from(eph_bytes);
        let nonce_len = envelope.corporate_escrow_sealed_key[32] as usize;
        if envelope.corporate_escrow_sealed_key.len() < 33 + nonce_len {
            return Err(CryptoError::AeadIntegrityFailure);
        }

        let nonce = &envelope.corporate_escrow_sealed_key[33..33 + nonce_len];
        let sealed_key = &envelope.corporate_escrow_sealed_key[33 + nonce_len..];

        let channel_id = ChannelId::from_slice(&envelope.channel_id)?;
        let message_id = MessageId::from_slice(&envelope.message_id)?;
        let shared = compliance_hsm.diffie_hellman(&ephemeral_pub);

        let mut kdf = blake3::Hasher::new_derive_key("cryptox.corporate-escrow-wrap.v1");
        kdf.update(env_tenant.as_bytes());
        kdf.update(channel_id.as_bytes());
        kdf.update(message_id.as_bytes());
        kdf.update(&*shared);
        let wrap_key = Zeroizing::new(*kdf.finalize().as_bytes());

        let mut escrow_aad = Vec::with_capacity(48);
        escrow_aad.extend_from_slice(env_tenant.as_bytes());
        escrow_aad.extend_from_slice(channel_id.as_bytes());
        escrow_aad.extend_from_slice(message_id.as_bytes());

        let raw_msg_key = Zeroizing::new(provider.open(&wrap_key, nonce, &escrow_aad, sealed_key)?);
        let msg_key: [u8; 32] = raw_msg_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::AeadIntegrityFailure)?;

        let aad = envelope.canonical_aad();
        let plaintext = provider.open(&msg_key, &envelope.nonce, &aad, &envelope.ciphertext)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Экспортирует запись сессии для сохранения в облачном сейфе `CloudKeyVault`.
    #[must_use]
    pub fn to_vault_record(&self) -> SessionVaultRecord {
        SessionVaultRecord {
            tenant_id_bytes: *self.tenant_id.as_bytes(),
            channel_id_bytes: *self.channel_id.as_bytes(),
            peer_user_id_bytes: *self.peer_user_id.as_bytes(),
            peer_verifying_key_bytes: self.peer_verifying_key.to_bytes(),
            master_channel_seed: *self.master_channel_seed,
            next_outbound_step: self.next_outbound_step,
        }
    }

    /// Восстанавливает сессию чата на новом устройстве сотрудника из `CloudKeyVault`.
    pub fn from_vault_record(
        record: &SessionVaultRecord,
        policy: EncryptionPolicy,
        tenant_compliance_pub_bytes: Option<[u8; 32]>,
    ) -> Result<Self, CryptoError> {
        let tenant_id = TenantId::from_slice(&record.tenant_id_bytes)?;
        let channel_id = ChannelId::from_slice(&record.channel_id_bytes)?;
        let peer_user_id = UserId::from_slice(&record.peer_user_id_bytes)?;
        let peer_verifying_key = VerifyingKey::from_bytes(&record.peer_verifying_key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial("invalid peer verifying key in vault"))?;

        Ok(Self {
            tenant_id,
            channel_id,
            peer_user_id,
            peer_verifying_key,
            master_channel_seed: Zeroizing::new(record.master_channel_seed),
            next_outbound_step: record.next_outbound_step,
            policy,
            tenant_compliance_pub: tenant_compliance_pub_bytes.map(X25519PublicKey::from),
            inbound_replay_window: Mutex::new(ReplaySlidingWindow::default()),
        })
    }
}
