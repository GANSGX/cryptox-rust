---
name: standards-compliance-check
description: >-
  Аудит архитектуры, криптографии и кода модуля на соответствие международным
  стандартам безопасности мессенджеров (IETF RFC 9420/9750 MLS, RFC 9807 OPAQUE,
  NSA CNSA 2.0, NIST SP 800-63B/207, OWASP ASVS v5.0 Level 3). Используй этот скилл
  перед проектированием любого модуля и перед сдачей этапа.
---

# Скилл: Аудит соответствия международным стандартам безопасности

Перед проектированием или приемкой любого крейта/микросервиса выполни следующие шаги:

## Шаг 1. Сверка с актуальной документацией (Context7 MCP + Web Search)
1. Вызови `resolve-library-id` и `query-docs` в `context7_context7` для используемых библиотек (`openmls`, `axum`, `tonic`, `sqlx`, `tauri` и др.).
2. При необходимости проверь актуальные рекомендации OWASP / NIST / IETF через `search_web`.

## Шаг 2. Прогон по чек-листу стандартов
Открой матрицу `[docs/standards/COMPLIANCE_MATRIX.md](../../../docs/standards/COMPLIANCE_MATRIX.md)` и детальный чек-лист `[references/standards-checklist.md](./references/standards-checklist.md)` и проверь:
1. **RFC 9420 / RFC 9750 (MLS):** Не утекают ли ключи шифрования контента на Delivery Service (`edge-gateway`, `messaging-svc`)?
2. **RFC 9807 (OPAQUE) & NIST SP 800-63B:** Не передается ли пароль или сырой секрет на сервер при регистрации/входе?
3. **NSA CNSA 2.0 / FIPS 140-3:** Используются ли алгоритмы с длиной ключа >= 256 бит для симметричного шифрования (`AES-256-GCM` / `ChaCha20-Poly1305`) и `SHA-384/512` или `BLAKE3` для хеширования?
4. **OWASP ASVS v5.0 Level 3:** Обернуты ли все ключи в памяти в `zeroize::Zeroizing`? Отсутствуют ли секреты в логах и `localStorage`?
5. **RFC 9562 (UUIDv7) & Multi-Tenancy:** Присутствует ли `tenant_id` во всех запросах и таблицах?
