# Правило 01: Стандарты Безопасности (Gov / Intelligence / Enterprise Grade)

Все криптографические и аутентификационные механизмы проекта `cryptox-rust` обязаны строго следовать международным стандартам:

## 1. Обязательные RFC и стандарты шифрования
- **IETF RFC 9420 (MLS Protocol) & RFC 9750 (MLS Architecture):**
  - Строгое разделение ролей между **Authentication Service (AS)** (`auth-vault-svc` + `key-directory-svc`) и **Delivery Service (DS)** (`edge-gateway` + `messaging-svc`).
  - Delivery Service является криптографически «слепым» и не имеет доступа к ключам шифрования контента.
- **IETF RFC 9807 (OPAQUE PAKE):**
  - Пароль пользователя никогда не передается по сети в открытом или просто хешированном виде. Используется протокол OPAQUE (`opaque-ke`).
- **NSA CNSA 2.0 (Commercial National Security Algorithm Suite 2.0) & Post-Quantum Readiness:**
  - Архитектура выбора криптонаборов (Cipher Suites) обязана быть крипто-агностичной (Crypto-Agility) с поддержкой гибридных постквантовых алгоритмов (`X25519MLKEM768` / FIPS 203 ML-KEM и FIPS 204 ML-DSA).
  - Симметричное шифрование: минимум 256-битные ключи (`AES-256-GCM` или `ChaCha20-Poly1305` / `XChaCha20-Poly1305`).
  - Хеширование: `SHA-384` / `SHA-512` или `BLAKE3`.
- **OWASP ASVS v5.0 Level 3 & MASVS:**
  - Никаких секретов, приватных ключей или мастер-токенов в `localStorage`/`sessionStorage`.
  - В десктопном/мобильном клиенте (`Tauri v2` / `cryptox-core`) все ключи живут исключительно в памяти Rust (`zeroize::Zeroizing`) и локальной БД `SQLCipher`, ключ к которой защищен аппаратным хранилищем ОС (Windows DPAPI/TPM, macOS Keychain/Secure Enclave, Linux Secret Service).
  - Использование строго криптографически стойкого ГСЧ (`rand::rngs::OsRng`).

## 2. Запрещенные практики (Anti-Patterns)
- Запрещено использовать `Math.random()` или некриптографические PRNG.
- Запрещено выводить ключи простым `SHA256(password + salt)` без `Argon2id`.
- Запрещено логировать тела запросов авторизации, токены, ключи, IP-адреса без маскирования или открытый текст сообщений (`tracing::Instrument` должен пропускать секретные поля через `#[instrument(skip_all)]`).
