# CryptoX (`cryptox-rust`)

Модульный корпоративный и публичный мессенджер со сквозным шифрованием (E2EE), построенный на микросервисной архитектуре на базе **Rust (Edition 2024)** и клиентском приложении **React 19 + TypeScript + Protobuf v3**.

---

## 1. Структура репозитория и модули

Проект организован как Cargo Workspace из 7 Rust-крейтов и фронтенд-приложения в `apps/web`:

```text
cryptox-rust/
├── crates/
│   ├── cryptox-proto/          # Бинарные схемы Protobuf v3 (prost), типы UUIDv7 и валидация wire-кадров
│   ├── cryptox-core/           # Криптографическое ядро: X25519, Ed25519, XChaCha20-Poly1305, AES-256-GCM, Argon2id, Ratchet, CloudKeyVault
│   └── cryptox-storage/        # Двухуровневый движок хранения: L1 DashMap RAM + L2 redb B+Tree с шифрованием AES-256-GCM и Blind Index
├── services/
│   ├── auth-vault-svc/         # Zero-Knowledge аутентификация (Ed25519 challenge-response), выдача SignedSessionToken и хранение EncryptedVaultBlob
│   ├── user-directory-svc/     # Каталог публичных ключей сотрудников с криптографическим журналом прозрачности (Key Transparency Log на BLAKE3)
│   ├── presence-receipts-svc/  # Онлайн-статусы (TTL) и коалесцирующие водоразделы прочтения (Read States / last_read_message_id)
│   ├── messaging-svc/          # Горячий контур маршрутизации E2EE-конвертов, идемпотентная дедупликация и курсорная история по UUIDv7
│   └── edge-gateway/           # Периметровый HTTP/WebSocket шлюз (Axum 0.8), AutonomousTokenVerifier, Rate Limiter, Zero-Trust TCP RPC Mesh и Circuit Breakers
└── apps/
    └── web/                    # Клиентское SPA (React 19, TypeScript, Tailwind CSS v4, Framer Motion, protobufjs)
```

---

## 2. Технологический стек

### Бэкенд (Rust 2024, `#![forbid(unsafe_code)]`)
* **Асинхронный рантайм и сеть:** `tokio 1.44` (multi-thread), `axum 0.8` (HTTP/1.1, WebSocket `/ws`), нативный TCP RPC-транспорт с length-delimited фреймингом (`[u32 big-endian length || payload]`).
* **Бинарная сериализация:** `prost 0.13` (Protocol Buffers v3) — используется во всём межсервисном взаимодействии и в клиент-серверном протоколе (`POST /rpc/v1/client-wire` с `Content-Type: application/x-protobuf` и бинарных WebSocket-фреймах `WsMessage::Binary`).
* **Криптографические примитивы:**
  * `ed25519-dalek 2.1` — цифровые подписи профилей ключей (`PublicKeyBundle`), сессионных токенов (`SignedSessionToken`), E2EE-конвертов (`EncryptedEnvelope`) и межсервисных RPC-фреймов.
  * `x25519-dalek 2.0` — согласование общих секретов Диффи-Хеллмана (ECDH).
  * `chacha20poly1305 0.10` (`XChaCha20-Poly1305`, 192-битный nonce) — основной AEAD-шифр сообщений, облачного сейфа ключей и внутреннего Zero-Trust RPC-канала.
  * `aes-gcm 0.10` (`AES-256-GCM`, 96-битный nonce) — шифрование данных на диске (`cryptox-storage`) и альтернативный AEAD-сьют.
  * `argon2 0.5` (`Argon2id`) — вывод мастер-ключа облачного сейфа (`CloudKeyVault`) из пароля или резервного ключа восстановления (`Recovery Key`).
  * `blake3 1.6` — KDF для цепочки симметричного рэтчета (`derive_key`), ключевые хеши слепых индексов (`keyed_hash`), детерминированный расчёт `ChannelId` и хеш-цепочка `Key Transparency`.
  * `zeroize 1.8` (`ZeroizeOnDrop`) — принудительное затирание приватных ключей и промежуточных ключей цепочки в оперативной памяти сразу после использования.
  * `subtle 2.6` — константное по времени сравнение идентификаторов, тегов и хешей (`ConstantTimeEq`).
* **Хранение данных и структуры в памяти:**
  * `redb 2.4` — встраиваемое транзакционное ACID B+Tree хранилище.
  * `dashmap 6.1` — шардированные конкурентные хэш-таблицы для L1-кэша, сессий и лимитеров.

### Фронтенд (`apps/web`)
* **Ядро:** `React 19`, `TypeScript 5.8`, сборщик `Vite 6` + `vite-plugin-singlefile`.
* **Протокол:** `protobufjs 7.5` — клиентское кодирование и декодирование бинарных пакетов `ClientWireRequestProto`, `ClientWireResponseProto` и `ClientWireWsEventProto` (`Uint8Array` / `ArrayBuffer`).
* **Интерфейс и анимации:** `Tailwind CSS v4`, `lucide-react`, `framer-motion 12` (`layoutId`, пружинная анимация), `View Transitions API` (переключение светлой и тёмной темы).

---

## 3. Реализованная функциональность (по подсистемам)

### 3.1. Протокольный слой (`crates/cryptox-proto`)
* **Типизированные 128-битные идентификаторы `UUIDv7`:** `TenantId`, `UserId`, `DeviceId`, `ChannelId`, `MessageId`. Верхние 48 бит содержат миллисекундную метку времени Unix, что обеспечивает лексикографическую сортировку по времени создания.
* **Детерминированный `ChannelId` для личных чатов:** вычисляется симметрично из `TenantId` и упорядоченной пары `(min(UserA, UserB), max(UserA, UserB))` через `BLAKE3`, исключая дублирование каналов и изолируя разных арендаторов (`TenantId`).
* **Канонический AAD (`Associated Authenticated Data`):** для каждого `EncryptedEnvelope` формируется детерминированный буфер метаданных (`tenant_id`, `channel_id`, `message_id`, `sender_user_id`, `sender_device_id`, `ratchet_step`, `ciphersuite`, `encryption_policy`), передаваемый в AEAD. Любая модификация заголовков конверта на пути следования приводит к ошибке аутентификации тега Poly1305 / GCM.
* **Защита от некорректных пакетов:** жёсткие лимиты размера (`MAX_ENVELOPE_WIRE_BYTES = 64 KiB`, `MAX_CIPHERTEXT_BYTES = 48 KiB`), валидация длины подписей (64 байта) и nonce (12 или 24 байта). Покрыто property-based фаззингом (`proptest`).

### 3.2. Криптографическое ядро (`crates/cryptox-core`)
* **Идентичность и пакеты ключей (`UserIdentity`, `PublicKeyBundle`):** генерация долгосрочной пары `Ed25519` и предключей `X25519` с самоподписью, привязанной к `TenantId`, `UserId`, `DeviceId` и монотонной версии ключа `key_version` (защита от downgrade-атак).
* **Симметричный KDF-рэтчет (`ChatSession`):**
  * На каждом шаге отправки/приёма `chain_key` односторонне продвигается через `BLAKE3::derive_key` с генерацией одноразового `message_key` и немедленной очисткой предыдущего состояния (`Forward Secrecy`).
  * Встроено 64-битное скользящее окно `ReplaySlidingWindow` (алгоритм RFC 4303 IPsec ESP), пропускающее пакеты, пришедшие не по порядку (в пределах окна `MAX_SKIPPED_RATCHET_STEPS = 64`), и мгновенно блокирующее повторную доставку (`Replay Attack`) за $O(1)$ через битовую маску.
  * Поддержка расшифровки исторических сообщений при синхронизации с диска или облачного сейфа по сохранённому `initial_root_key`.
* **Опциональное корпоративное депонирование (`CorporateDlpEscrow`):**
  * В режиме `StrictZeroKnowledge` поле `corporate_escrow_sealed_key` остаётся пустым (0 байт).
  * В режиме `CorporateDlpEscrow` клиент запечатывает одноразовый 32-байтный `message_key` конкретного сообщения на публичный ключ `X25519` аппаратного кластера компании (`CorporateHsmCluster`), не раскрывая приватные ключи сотрудника.
* **Облачный сейф ключей (`CloudKeyVault`):**
  * Сериализует приватные ключи и активные сессии в бинарный `EncryptedVaultBlob`, зашифрованный ключом из `Argon2id(password, salt, m_cost, t_cost, p_cost)` через `XChaCha20-Poly1305`.
  * Поддерживает резервное перешифрование сейфа по 128-битному ключу восстановления (`Recovery Key` вида `CX-XXXX-XXXX-XXXX-XXXX`) без знания старого пароля на стороне сервера.
* **Криптографическое уничтожение (`Crypto-Shredding`):** метод `remote_wipe_zeroize()` принудительно обнуляет все ключевые буферы в памяти устройства при отзыве доступа.

### 3.3. Зашифрованное дисковое хранилище (`crates/cryptox-storage`)
* **Двухуровневое чтение/запись:**
  * **L1 (RAM):** шардированный кэш `DashMap` с частичным вытеснением (`evict_partial`, удаляет 12.5% записей при достижении лимита `max_l1_entries` вместо полного сброса кэша, предотвращая Cache Stampede).
  * **L2 (SSD):** транзакционная БД `redb` с групповой фиксацией батчей (`commit_messages_batch`).
* **Шифрование на диске (`AES-256-GCM`):** все значения перед записью в таблицы `redb` шифруются мастер-ключом диска со случайным 96-битным nonce и привязкой ключа таблицы в качестве AAD.
* **48-байтный составной ключ истории сообщений:** `[TenantId (16B) || ChannelId (16B) || MessageId UUIDv7 (16B)]`. Позволяет выполнять курсорную пагинацию истории чата (`fetch_channel_history_from_disk`) прямым диапазонным чтением B+Tree за $O(\log N + K)$.
* **Слепой индекс каталога (`Blind Index`):** поиск пользователей по `@username` на диске выполняется по 32-байтному ключу `BLAKE3::keyed_hash(blind_index_key, tenant_id || normalized_username)`. На диске не хранятся открытые логины или тексты сообщений (проверено тестом бинарной криминалистики файла БД).

### 3.4. Микросервисы и изоляция отказов (Bulkhead Architecture)
* **`auth-vault-svc`:**
  * Регистрация и вход по схеме Zero-Knowledge (`Ed25519` challenge-response с одноразовым 32-байтным `challenge_nonce` и TTL 60 с).
  * Защита от перебора: блокировка после превышения лимита ошибок аутентификации и фоновая сборка мусора просроченных челленджей.
  * Выпуск криптографических токенов `SignedSessionToken` (подписанных `Ed25519`) и контроль монотонной версии `vault_version` при обновлении `EncryptedVaultBlob` (защита от rollback-атак).
  * Ротация ключа аутентификации и облачного сейфа (`rotate_password_and_vault`) при восстановлении доступа по `Recovery Key`.
* **`user-directory-svc`:**
  * Хранение и поиск `DirectoryEntryProto` по префиксу `@username` в рамках `TenantId`.
  * Ведение журнала прозрачности ключей (`Key Transparency Log`): каждая публикация или ротация ключа связывается хешем `BLAKE3` с предыдущей записью (`prev_transparency_hash -> current_hash`), предотвращая скрытую подмену ключа сервером (MITM).
* **`presence-receipts-svc`:**
  * Хранение онлайн-статусов с проверкой TTL и фиксация прочтения чатов через одиночный указатель `last_read_message_id` (`ReadReceiptWatermarkProto`), когда один `UUIDv7` подтверждает прочтение всех предшествующих сообщений в канале.
* **`messaging-svc`:**
  * Приём и валидация `EncryptedEnvelope`, проверка временного дрейфа `UUIDv7` (блокировка пакетов с таймстампом из будущего `> MAX_FUTURE_DRIFT_MS = 30s`).
  * Идемпотентная дедупликация по `MessageId` при повторных отправках в условиях нестабильной сети.
* **`edge-gateway`:**
  * **Автономная верификация токенов (`AutonomousTokenVerifier`):** проверяет подпись `Ed25519` и срок действия `SignedSessionToken` локально в памяти шлюза за ~15 мкс без обращения к `auth-vault-svc`.
  * **Распределённый Zero-Trust TCP RPC Mesh (`cluster_mesh.rs`):** поднимает микросервисы на отдельных TCP-портах; каждый внутренний RPC-пакет упаковывается в `ZeroTrustRpcFrameProto`, шифруется ключом кластера (`XChaCha20-Poly1305`), подписывается `Ed25519` и проверяется по анти-реплей кэшу `frame_id`.
  * **3-состоянийные автоматические выключатели (`CircuitBreaker`):** для каждого микросервиса работает lock-free автомат `CLOSED -> OPEN -> HALF_OPEN -> CLOSED`. При сбое второстепенных сервисов (`auth-vault-svc`, `user-directory-svc`, `presence-receipts-svc`) шлюз размыкает цепь (Fail-Fast за `< 1 мкс`) и продолжает маршрутизировать сообщения активных чатов через `messaging-svc` и `cryptox-storage`.
  * **Ограничитель скорости (`TokenBucketRateLimiter`):** защита от флуда по ключу `(TenantId, UserId, DeviceId)`.
  * **Наблюдаемость (Observability):** эндпоинты `/healthz`, `/readyz`, `/metrics` (текстовый формат Prometheus `0.0.4`) и веб-дашборд состояния узлов `/status`.

### 3.5. Клиент-серверный протокол и веб-интерфейс (`apps/web`)
* **Бинарный Protobuf RPC (`POST /rpc/v1/client-wire`):**
  * Клиент кодирует `ClientWireRequestProto` через `protobufjs` и отправляет бинарный `Uint8Array` (`Content-Type: application/x-protobuf`).
  * Поддерживаемые коды операций (`ClientWireOp`):
    1. `Login` — вход по `@username` или `mail` + паролю;
    2. `Register` — регистрация с генерацией ключей, `CloudKeyVault` и выдачей резервного ключа `CX-XXXX-XXXX-XXXX-XXXX`;
    3. `SsoLogin` — вход через корпоративный домен;
    4. `RecoverPassword` — расшифровка сейфа резервным ключом и перешифрование под новый пароль;
    5. `GetState` — получение списка локальных анклавов и метрик хранилища (`L1 hits`, `L2 SSD reads`, `Group commits`);
    6. `SearchDirectory` — поиск сотрудников в `user-directory-svc` с верификацией `Key Transparency`;
    7. `SendChatMessage` — E2EE-шифрование и отправка сообщения + автообновление `CloudKeyVault`;
    8. `FetchChatHistory` — загрузка и расшифровка истории канала + проверка статуса прочтения собеседником;
    9. `MarkChatRead` — сдвиг указателя `last_read_message_id`;
    10. `CloudSyncNewDevice` — подключение нового устройства с восстановлением идентичности и сессий из `CloudKeyVault`;
    11. `CheckUsername` — $O(1)$ проверка уникальности и формата `@username` в реальном времени.
* **Бинарный WebSocket (`GET /ws`, `binaryType = "arraybuffer"`):**
  * Рассылка и приём бинарных кадров `ClientWireWsEventProto` (`new_message`, `read_receipt`, `typing`, `directory_updated`).
* **Интерфейс авторизации (`/auth`) и мессенджера (`/`):**
  * Бесшовный статичный векторный фон (математика, физика, космос и астрономия), мемоизированный через `React.memo` и CSS-переменные.
  * Плавное переключение светлой/тёмной темы через `View Transitions API` (`clip-path: circle(...)` из правого верхнего угла в левый нижний за `1650 мс`).
  * Валидация пароля в реальном времени (появляется только при вводе): минимум 8 символов, заглавные и строчные буквы, цифры, спецсимволы, запрет одинаковых (`11`, `00`) и последовательных (`123`, `321`) цифр, 3-секционный градиентный индикатор заполнения.
  * Рабочее пространство мессенджера со списком защищённых каналов, индикатором набора текста, двойными галочками прочтения, переключением активного устройства/профиля и выдвижным инспектором пакетов Protobuf (`UUIDv7`, `192-bit Nonce`, `Ciphertext`, `Ed25519 Signature`) и метрик `redb`.

---

## 4. Сборка, запуск и тестирование

### Требования
* **Rust:** `1.85+` (Edition 2024)
* **Node.js & pnpm:** `Node 20+`, `pnpm 9+` (для пересборки `apps/web`)

### Сборка фронтенда (при изменении `apps/web`)
```powershell
cd apps/web
pnpm install
pnpm exec tsc --noEmit
pnpm build
Copy-Item -Force dist/index.html ../../services/edge-gateway/src/auth_ui.html
Copy-Item -Force dist/index.html ../../services/edge-gateway/src/ui.html
```

### Запуск сервера
```powershell
cargo run --bin cryptox_server
```
После запуска доступны:
* `http://127.0.0.1:8080/auth` — экран входа, регистрации и восстановления пароля по `Recovery Key`;
* `http://127.0.0.1:8080/` — интерфейс мессенджера и инспектор пакетов Protobuf;
* `http://127.0.0.1:8080/status` — панель состояния микросервисов, Circuit Breakers и симуляции отказов;
* `http://127.0.0.1:8080/metrics` — метрики в формате Prometheus;
* `http://127.0.0.1:8080/healthz` и `http://127.0.0.1:8080/readyz` — liveness/readiness пробы.

### Статический анализ и тесты
```powershell
# Проверка линтером Clippy со строгим запретом предупреждений
cargo clippy --workspace --all-targets -- -D warnings

# Запуск всех 31 модульных, криптографических, фаззинг- и E2E-тестов
cargo test --workspace
```
