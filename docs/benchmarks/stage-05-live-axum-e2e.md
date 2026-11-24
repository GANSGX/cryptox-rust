# Отчет Верификации и Сквозного E2E Тестирования: Этап 5 (`cryptox_server` на `Axum 0.8`)

- **Дата прогона:** 2026-11-23
- **Компилятор:** `rustc 1.100.0`, `axum 0.8.9`, `tokio 1.54.1`
- **Всего тестов по всем крейтам и микросервисам воркспейса:** **21 тест (Unit + Proptest + Adversarial + Triple-Chaos + Live TCP E2E) — 21 PASSED, 0 FAILED, 0 WARNINGS**.

---

## 1. Что проверяет сквозной сетевой тест `e2e_live_http_server.rs`

Команда запуска:
```powershell
cargo test --package edge-gateway --test e2e_live_http_server
```

1. **Поднятие реального TCP-сервера `Axum 0.8`** со всеми 4 микросервисами (`auth-vault-svc`, `user-directory-svc`, `presence-receipts-svc`, `messaging-svc`) и шлюзом `edge-gateway`.
2. **`GET /`** — отдача интерактивного UI-прототипа.
3. **`GET /api/search?caller=alice_ceo&q=@bo`** — поиск сотрудника по `@username` через `user-directory-svc` с проверкой `Ed25519` самоподписи и `Key Transparency` хеша.
4. **`POST /api/chat/send`** — установка E2EE-сессии (`X25519` + `XChaCha20-Poly1305` + `AAD`), передача начального `PublicKeyBundle` (по модели X3DH PreKey / MLS Welcome) и отправка бинарного `EncryptedEnvelope`.
5. **`POST /api/cloud-sync-new-device`** — симуляция входа с нового Ноутбука №2 сотрудника: скачивание `EncryptedVaultBlob` из `auth-vault-svc`, расшифровка через `Argon2id` и восстановление всех ключей чатов.
6. **`POST /api/chaos/toggle` (Тройной отказ по HTTP):** отключение `auth-vault-svc`, `user-directory-svc` и `presence-receipts-svc`.
7. **Доказательство выживаемости чата:** отправка второго зашифрованного сообщения с Ноутбука №2 Алисы во время падения всех 3 сервисов и успешное чтение/расшифровка истории Бобом (`GET /api/chat/history`).

---

## 2. Запуск живого сервера прототипа

```powershell
cargo run --release --package edge-gateway --bin cryptox_server
```
Доступен в браузере по адресу: `http://127.0.0.1:8080`
