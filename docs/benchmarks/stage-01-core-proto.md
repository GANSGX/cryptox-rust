# Отчет Нагрузочных Испытаний и Верификации: Этап 1 (`cryptox-proto` + `cryptox-core`)

- **Дата прогона:** 2026-11-23
- **Компилятор:** `rustc 1.100.0 (0ef1bc386 2026-11-09)`, профиль `--release` (`optimized`)
- **Статус линтеров безопасности:** `unsafe_code = "forbid"`, `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"` — **0 ошибок, 0 предупреждений**.

---

## 1. Результаты Хакерских (Adversarial) и Property-Based (`proptest`) Тестов

Команда запуска:
```powershell
cargo test --workspace
```

| Тестовый сценарий | Что проверялось | Результат |
| :--- | :--- | :--- |
| `test_alice_bob_real_e2ee_over_untrusted_wire_both_ciphersuites` | Изолированные в памяти устройства Алисы и Боба обмениваются ключами `X25519 + Ed25519` и сообщениями только через сырые байты сети (`Vec<u8>`) на обоих криптопровайдерах (`XChaCha20-Poly1305` и `AES-256-GCM`). Проверка отсутствия открытого текста в сетевом буфере. | **PASSED** |
| `test_multi_device_cloud_key_vault_sync_and_hacker_db_breach` | Алиса сохраняет `EncryptedVaultBlob` в облаке. Хакер пытается взломать дамп с неверным паролем и с подменой `vault_version` (`AAD`) — получает `Err(AeadIntegrityFailure)`. Затем новый `Macbook #2` Алисы скачивает блоб, открывает его паролем, расшифровывает всю старую историю чата и продолжает переписку с Бобом. | **PASSED** |
| `test_corporate_dlp_hsm_escrow_vs_vip_board_of_directors_zero_knowledge` | В режиме `CorporateEscrowDlp` аппаратный HSM Службы Безопасности компании расшифровывает рабочий чат для DLP, а чужой HSM / хакер получает отказ. В VIP-режиме `StrictZeroKnowledge` («Совет Директоров») даже HSM компании получает `Err(EscrowNotPresent)`. | **PASSED** |
| `test_remote_wipe_crypto_shredding_on_employee_offboarding` | Вызов `crypto_shred()` при увольнении сотрудника мгновенно уничтожает приватные ключи в RAM и блокирует чтение локального кэша (`Err(IdentityShredded)`). | **PASSED** |
| `test_malicious_server_mitm_and_context_splicing_attacks` | Отражение атаки MITM (попытка сервера подменить публичный ключ `X25519` Боба блокируется проверкой подписи `Ed25519`) и отражение Context Splicing (попытка переклеить сообщение в другой `channel_id` или изменить `ratchet_step`). | **PASSED** |
| `proptest_any_bit_flip_in_ciphertext_nonce_or_signature_is_rejected` | 256 случайных фаззинг-сценариев с мутацией случайных битов в `ciphertext` и `ed25519_signature`. | **PASSED (100% атак отбито)** |
| `proptest_arbitrary_corrupted_bytes_never_panic_on_decode` | Подача 256 случайных бинарных мусорных массивов в декодеры `EncryptedEnvelope`, `PublicKeyBundle`, `EncryptedVaultBlob` (0 паник). | **PASSED** |

---

## 2. Результаты Нагрузочного Стенда (`stage1_load_bench.rs`)

Команда запуска:
```powershell
cargo run --release --package cryptox-core --example stage1_load_bench
```

| Узел / Операция | Целевой SLA Этапа 1 | Фактический результат на железе | Статус |
| :--- | :--- | :--- | :--- |
| **AEAD `AES-256-GCM` (CNSA 2.0) + `AAD`** (Seal / Open на 1 ядро) | $\ge 150\,000$ сообщ/сек | **1 224 521 сообщ/сек** (`0.82 мкс` на операцию) | **Превышен в 8.1 раза** |
| **AEAD `XChaCha20-Poly1305` + `AAD`** (Seal / Open на 1 ядро) | $\ge 150\,000$ сообщ/сек | **462 518 сообщ/сек** (`2.16 мкс` на операцию) | **Превышен в 3.1 раза** |
| **Бинарный Protobuf (`cryptox-proto`)** (Полный цикл Encode + Decode + Validate) | $\ge 250\,000$ циклов/сек | **389 582 полных циклов/сек** (~`779 164 ops/sec`, `1.28 мкс` на операцию) | **PASSED** |
| **Полный E2EE с подписью `Ed25519` каждого пакета** (UUIDv7 + BLAKE3 Ratchet + AEAD + Ed25519 Sign/Verify) | $\ge 15\,000$ на 1 ядро | **22 420 операций/сек на 1 ядро** (~358 000/сек на 16 ядрах) | **PASSED** |
| **Облачный Сейф Ключей (`CloudKeyVault`)** (`Argon2id` 64 МБ RAM, 3 итерации, OWASP ASVS L3) | $< 300$ мс на клиенте | **155 мс** открытие сейфа (размер блоба всего **363 байта**) | **PASSED** |
