//! Сменный интерфейс криптопровайдера (`trait CryptoProvider`).
//!
//! Обеспечивает:
//! - **Crypto-Agility** (NSA CNSA 2.0 / NIST): мгновенное переключение между `XChaCha20-Poly1305` и `AES-256-GCM`.
//! - **Соответствие ПП РФ № 313**: возможность подключения внешнего сертифицированного СКЗИ заказчика
//!   (КриптоПро CSP / ГОСТ Р 34.12-2018 «Кузнечик») без изменения бизнес-логики мессенджера.

use crate::error::CryptoError;
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use cryptox_proto::CipherSuiteId;
use rand_core::{OsRng, RngCore};

pub trait CryptoProvider: Send + Sync {
    /// Идентификатор криптонабора в бинарном протоколе.
    fn suite_id(&self) -> CipherSuiteId;

    /// Длина одноразового вектора инициализации (Nonce) в байтах.
    fn nonce_len(&self) -> usize;

    /// Генерирует криптостойкий случайный Nonce через системный `OsRng`.
    fn generate_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; self.nonce_len()];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Аутентифицированное шифрование с привязкой контекста (`AAD` — Associated Authenticated Data).
    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Аутентифицированное дешифрование с проверкой тега целостности и `AAD`.
    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Провайдер №1: `XChaCha20-Poly1305` (256-битный ключ, 192-битный расширенный Nonce, RFC 8439).
#[derive(Clone, Copy, Debug, Default)]
pub struct XChaCha20Poly1305Provider;

impl CryptoProvider for XChaCha20Poly1305Provider {
    fn suite_id(&self) -> CipherSuiteId {
        CipherSuiteId::X25519XChaCha20Poly1305Blake3
    }

    fn nonce_len(&self) -> usize {
        24
    }

    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 24 {
            return Err(CryptoError::InvalidKeyMaterial("XChaCha20-Poly1305 requires 24-byte nonce"));
        }
        let cipher = XChaCha20Poly1305::new(key.into());
        let xnonce = XNonce::from_slice(nonce);
        cipher
            .encrypt(
                xnonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AeadIntegrityFailure)
    }

    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 24 {
            return Err(CryptoError::InvalidKeyMaterial("XChaCha20-Poly1305 requires 24-byte nonce"));
        }
        let cipher = XChaCha20Poly1305::new(key.into());
        let xnonce = XNonce::from_slice(nonce);
        cipher
            .decrypt(
                xnonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AeadIntegrityFailure)
    }
}

/// Провайдер №2: `AES-256-GCM` (256-битный ключ, 96-битный Nonce, стандарт NSA CNSA 2.0 / NIST).
#[derive(Clone, Copy, Debug, Default)]
pub struct Aes256GcmProvider;

impl CryptoProvider for Aes256GcmProvider {
    fn suite_id(&self) -> CipherSuiteId {
        CipherSuiteId::X25519Aes256GcmSha512
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidKeyMaterial("AES-256-GCM requires 12-byte nonce"));
        }
        let cipher = Aes256Gcm::new(key.into());
        let gcm_nonce = AesNonce::from_slice(nonce);
        cipher
            .encrypt(
                gcm_nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AeadIntegrityFailure)
    }

    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidKeyMaterial("AES-256-GCM requires 12-byte nonce"));
        }
        let cipher = Aes256Gcm::new(key.into());
        let gcm_nonce = AesNonce::from_slice(nonce);
        cipher
            .decrypt(
                gcm_nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::AeadIntegrityFailure)
    }
}
