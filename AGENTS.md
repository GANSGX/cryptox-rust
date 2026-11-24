# AGENTS.md — Глобальная Конституция ИИ-Агентов Проекта `cryptox-rust`

Этот документ является **обязательным глобальным правилом** для всех ИИ-агентов, работающих в репозитории `C:\cryptox-rust` и любых его поддиректориях. Ни одно архитектурное решение или строчка кода не должны нарушать описанные ниже принципы.

---

## 1. Главный принцип: «Не изобретать велосипеды» (Zero Custom Crypto & Reinvention)

1. **Никакой самописной криптографии и протоколов:** Запрещено придумывать собственные схемы обмена ключами, кастомные алгоритмы шифрования, самодельные форматы токенов или хранения паролей.
2. **Только стандартизированные протоколы и проверенные Rust-крейты:**
   - **E2EE и групповой обмен ключами:** IETF MLS (**RFC 9420** / **RFC 9750**) через `openmls` или Signal Protocol (PQXDH + Double Ratchet) через `libsignal`.
   - **Аутентификация без передачи пароля (Zero-Knowledge PAKE):** IETF OPAQUE (**RFC 9807**) через `opaque-ke` + аппаратные ключи WebAuthn/Passkeys (`webauthn-rs`).
   - **Хеширование паролей и KDF:** `argon2` (`Argon2id` с параметрами не ниже OWASP ASVS L3) и `hkdf` / `blake3`.
   - **AEAD-шифрование:** `chacha20poly1305` (`ChaCha20-Poly1305` / `XChaCha20-Poly1305`) или `aes-gcm` (`AES-256-GCM`) из `aws-lc-rs` / `RustCrypto`.
   - **Сессионные токены:** `PASETO v4` (`Ed25519` public / `BLAKE2b` local) вместо устаревших и подверженных ошибкам конфигурации JWT.
   - **Очистка памяти:** все секретные ключи, пароли и plaintext-буферы в памяти обязаны быть обернуты в `zeroize::Zeroizing`.

---

## 2. Обязательный Research-протокол перед написанием кода (Context7 MCP + Web Search)

ИИ-агенту **строго запрещено** писать код по устаревшим знаниям из памяти модели:

1. **Context7 MCP на каждый технический шаг:**
   - Перед добавлением или использованием любого крейта (`axum`, `tonic`, `quinn`, `sqlx`, `openmls`, `tauri`, `tokio`, `scylla`, `async-nats`) агент обязан вызвать `resolve-library-id` и `query-docs` в MCP-сервере `context7_context7`, чтобы получить актуальную документацию и паттерны 2026 года.
2. **Проверка международных стандартов и базы уязвимостей (`search_web`):**
   - При проектировании любого узла безопасности агент обязан сверяться с актуальными ревизиями **OWASP ASVS v5.0 (Level 3)**, **IETF RFC**, **NIST SP 800-63B / 800-207** и **NSA CNSA 2.0**, а также проверять `cargo audit` / RustSec Advisory Database.
   - Детальная матрица стандартов проекта находится в файле `[docs/standards/COMPLIANCE_MATRIX.md](docs/standards/COMPLIANCE_MATRIX.md)`.

---

## 3. Архитектурные инварианты (Enterprise 100k+ Scale & Bulkhead Isolation)

1. **Принцип изолированных отсеков (Bulkhead Pattern):**
   - Каждый сервис в `services/*` является полностью автономным процессом со своей зоной ответственности.
   - **Критический контур (Hot Path)** доставки сообщений (`edge-gateway` $\leftrightarrow$ `messaging-svc` $\leftrightarrow$ `NATS JetStream / Storage`) **не имеет права** делать синхронные RPC-вызовы во второстепенные сервисы (`auth-vault-svc`, `user-directory-svc`, `presence-receipts-svc`).
   - Падение или перезагрузка любого второстепенного модуля (`auth`, `directory`, `presence`, `media`) **не должно** прерывать доставку сообщений в уже открытых чатах.
2. **Облачная синхронизация без потери Zero-Knowledge (Encrypted Cloud Key Vault):**
   - Сервер хранит всю историю чатов в зашифрованном виде (`Blind Delivery & Storage Service` согласно **RFC 9750**).
   - Ключи от чатов синхронизируются между устройствами пользователя через **Encrypted Key Vault**, который расшифровывается исключительно на клиенте (`crates/cryptox-core`). Сервер технически не может расшифровать ни сообщения, ни сейф ключей.
3. **Мульти-арендность с первого дня (B2B Multi-Tenancy):**
   - Каждая сущность БД, токен, ключ и сетевой конверт обязаны содержать `tenant_id` (UUID организации) и неизменяемый `user_id` (`UUIDv7`). Использовать мутабельный `@username` в качестве первичного или внешнего ключа строго запрещено.
4. **Бинарный транспорт:**
   - Никакого текстового JSON + Base64 для передачи сообщений по сети. Используется строго бинарный **Protobuf (`prost` / `tonic`)** или zero-copy **`rkyv`** поверх WebSocket (`axum 0.8`) и QUIC (`quinn`).

---

## 4. Четырехступенчатая приемка каждого модуля (Verification & Load SLA)

Модуль считается **неготовым**, если для него не выполнены все 4 пункта:

1. **Unit & Property-Based Testing (`proptest`):** покрытие криптографии, парсеров и стейт-машин тысячами случайных и битых входных пакетов.
2. **Integration Testing (`testcontainers`):** проверка с реальными контейнерами БД и брокеров.
3. **Chaos / Fault-Isolation Test:** автоматический тест, доказывающий, что принудительное отключение соседних микросервисов не вызывает каскадного падения (`Cascading Failure`).
4. **Load Benchmark (`crates/cryptox-loadgen`):** замер пропускной способности (RPS), латентности (`p50`, `p99`, `p99.9`) и потребления RAM под целевой нагрузкой корпорации на **100 000 сотрудников** с записью отчета в `docs/benchmarks/`.

---

## 5. Автоматический Протокол Этапов (Auto Stage-Gate Protocol)

Даже если пользователь НЕ просит об этом явно в промпте, на **каждой** задаче и **каждом** этапе ИИ-агент обязан автоматически выдавать:
1. **Перед этапом (Pre-Flight Briefing):**
   - Что именно строим и какие границы модуля;
   - Какие международные стандарты (RFC / NIST / CNSA 2.0 / OWASP) и доки из Context7 MCP применяем;
   - **Что нам это дает** (архитектурный и продуктовый смысл на масштабе компании в 100 000+ сотрудников);
   - **Какие жесткие требования, тесты и цифры нагрузки (SLA)** мы ожидаем получить на выходе.
2. **После этапа (Post-Flight Verification):**
   - Фактические результаты тестов (`Unit`, `Proptest`, `Chaos`), цифры нагрузочного бенчмарка (`RPS`, `p99`, `RAM`), проверка `clippy` / `SonarQube` / `CodeRabbit` и автоматический брифинг следующего этапа.
- Подробный регламент: `[.agents/rules/04-stage-gate-protocol.md](.agents/rules/04-stage-gate-protocol.md)`.

---

## 6. Навигация по базе знаний ИИ-агентов в репозитории

- **Обязательные правила (`.agents/rules/`):**
  - `[.agents/rules/01-security-standards.md](.agents/rules/01-security-standards.md)` — Криптографические и государственные/корпоративные стандарты защиты.
  - `[.agents/rules/02-rust-microservices-bulkhead.md](.agents/rules/02-rust-microservices-bulkhead.md)` — Правила проектирования микросервисов и изоляции отказов.
  - `[.agents/rules/03-verification-and-benchmarks.md](.agents/rules/03-verification-and-benchmarks.md)` — Требования к тестам и нагрузочному стенду.
  - `[.agents/rules/04-stage-gate-protocol.md](.agents/rules/04-stage-gate-protocol.md)` — Автоматический протокол брифинга и приемки каждого этапа (требования, ожидания, польза, SLA).
  - `[.agents/rules/05-zero-fake-claims-proof.md](.agents/rules/05-zero-fake-claims-proof.md)` — Запрет крипто-заглушек/симуляций и обязательный тест «Алиса — Боб — Взломанный Сервер».
  - `[.agents/rules/06-deep-module-hardening-first.md](.agents/rules/06-deep-module-hardening-first.md)` — Запрет перехода к новым модулям до полного аудита и закалки всех существующих модулей по 7 векторам атак OWASP ASVS L3.
- **Скиллы для агентов (`.agents/skills/`):**
  - `standards-compliance-check` — Аудит кода и архитектуры на соответствие RFC 9420/9750, CNSA 2.0, OWASP ASVS L3.
  - `module-verification-bench` — Ранбук полного цикла тестирования и нагрузочного прогона модуля.
  - `adr-architect` — Создание Architectural Decision Records (ADR) перед разработкой нового модуля.
- **Проектная документация (`docs/`):**
  - `[docs/standards/COMPLIANCE_MATRIX.md](docs/standards/COMPLIANCE_MATRIX.md)` — Справочник международных стандартов (Гос / Спецслужбы / Энтерпрайз).
  - `[docs/architecture/SYSTEM_BLUEPRINT.md](docs/architecture/SYSTEM_BLUEPRINT.md)` — Генеральный план архитектуры мессенджера на 100k+ сотрудников.
  - `docs/architecture/adr/` — Журнал архитектурных решений.
  - `docs/benchmarks/` — Результаты нагрузочных испытаний каждого модуля.
