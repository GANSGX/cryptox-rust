# Отчет Нагрузочных Испытаний и Верификации: Этап 2 (`services/auth-vault-svc`)

- **Дата прогона:** 2026-11-23
- **Компилятор:** `rustc 1.100.0`, профиль `--release` (`optimized`)
- **Статус линтеров безопасности:** `unsafe_code = "forbid"`, `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"` — **0 ошибок, 0 предупреждений**.

---

## 1. Результаты Хакерских (Adversarial), Chaos/Bulkhead и `proptest` Тестов

Команда запуска:
```powershell
cargo test --package auth-vault-svc
```

| Тестовый сценарий | Что проверялось | Результат |
| :--- | :--- | :--- |
| `test_zero_knowledge_register_login_and_replay_attack_blocked` | Регистрация без передачи пароля, вход со второго ноутбука по одноразовому челленджу `Ed25519`. Отражение подбора пароля (`Err(InvalidCredentials)`) и **отражение Replay-атаки** при повторной отправке перехваченного пакета входа (`Err(ChallengeNotFoundOrReplayed)`). | **PASSED** |
| `test_vault_version_rollback_and_cross_user_overwrite_attacks_blocked` | Обновление сейфа до `v2`, блокировка атаки отката сейфа до старой версии `v1` (`Err(VaultVersionRollback)`) и блокировка попытки инсайдера перезаписать чужой сейф своим токеном (`Err(UnauthorizedAccess)`). | **PASSED** |
| `test_chaos_bulkhead_auth_service_crash_does_not_drop_active_chat_sessions` | **Chaos / Bulkhead Proof:** принудительное отключение `auth-vault-svc` (`set_simulated_outage(true)`). Новые логины блокируются, НО шлюз через `AutonomousTokenVerifier` продолжает со 100% успехом проверять токены активных сотрудников и мгновенно отрабатывать увольнение (`revoke_user`). | **PASSED** |
| `proptest_any_token_tampering_is_rejected_by_autonomous_verifier` | 256 фаззинг-атак на `SignedSessionToken` (попытка продлить `expires_at_ms` и побитовая мутация подписи `Ed25519`). | **PASSED (100% атак отбито)** |

---

## 2. Результаты Нагрузочного Стенда (`stage2_auth_bench.rs`)

Команда запуска:
```powershell
cargo run --release --package auth-vault-svc --example stage2_auth_bench
```

| Узел / Операция | Целевой SLA Этапа 2 | Фактический результат на железе | Статус |
| :--- | :--- | :--- | :--- |
| **Автономная проверка активных сессий на шлюзе (`AutonomousTokenVerifier`)** (при **ВЫКЛЮЧЕННОМ** `auth-vault-svc`, 1 000 000 запросов) | $\ge 100\,000$ проверок/сек | **1 528 564 проверок/сек на 1 ядро** (`654 наносекунды` на токен!) | **Превышен в 15.2 раза** |
| **Холодная проверка новых токенов** (полная математическая проверка `Ed25519` при первом пакете) | $\ge 15\,000$ сессий/сек на 1 ядро | **19 832 новых сессий/сек на 1 ядро** (~317 000/сек на 16 ядрах, `50.42 мкс`) | **PASSED** |
| **Утренний шторм синхронизации облачных сейфов (`pull_vault`)** (500 000 запросов выдачи `EncryptedVaultBlob`) | $\ge 50\,000$ RPS | **647 406 выдач сейфов/сек на 1 ядро** (`1.54 мкс` на запрос) | **Превышен в 12.9 раза** |
