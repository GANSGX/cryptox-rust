# Stage 08 — Deep Security Hardening & Penetration Audit Report

**Date:** 2026-11-24  
**Scope:** All 7 existing Rust crates/microservices (`cryptox-proto`, `cryptox-core`, `cryptox-storage`, `auth-vault-svc`, `user-directory-svc`, `presence-receipts-svc`, `messaging-svc` + `edge-gateway`)  
**Standard:** OWASP ASVS v5.0 Level 3 / IETF RFC 9420 / RFC 9750 / NIST SP 800-63B / Zero-Fake-Claims Rule (`05-zero-fake-claims-proof.md`, `06-deep-module-hardening-first.md`)

---

## 1. Root Cause of the Line 65 Hang (`DashMap` Shard Read/Write Deadlock in Rust 2024)

During initial execution of `test_5_storage_targeted_l1_eviction_and_presence_ttl_pruning` (`services/edge-gateway/tests/stage8_deep_security_hardening.rs:64-66`), the test hung inside `EncryptedStorageEngine::put_directory_entries_batch`.

### Technical Cause
In Rust 2024 edition (`edition = "2024"`), temporary values produced in the scrutinee of an `if let` expression remain alive until the end of the `if let` block if bound via iterator guards:
```rust
// DEADLOCK BUG:
// `.iter().next()` acquires a read-lock on a DashMap shard.
// While that temporary guard is still in scope, `.remove(&first_key)` tries to
// acquire a write-lock on the SAME DashMap shard -> instant self-deadlock!
if let Some(first_key) = self.l1_directory_cache.iter().next().map(|r| *r.key()) {
    self.l1_directory_cache.remove(&first_key);
}
```

### Fix Applied
Extracted the key copy into a standalone `let victim_key = ...;` statement ending with a semicolon so the `DashMap` shard read-lock guard is dropped **before** `.remove(&k)` acquires the write-lock:
- Fixed in `crates/cryptox-storage/src/lib.rs` (`l1_directory_cache` eviction)
- Fixed in `services/auth-vault-svc/src/lib.rs` (`revoked_tokens` bounded cache eviction)

---

## 2. Summary of All 15 Security Vulnerabilities Closed in Stage 8

| # | Module | Vulnerability / Vector (Pre-Stage 8) | Hardening Patch Applied (Stage 8) |
|---|---|---|---|
| **1** | `cryptox-proto` | Future-dated `UUIDv7` (`year 2099`) allowed timeline & read-watermark poisoning | Added `MAX_FUTURE_CLOCK_SKEW_MS = 60_000` and `validate_not_in_future(now_ms)` on all 7 typed `UUIDv7` identifiers |
| **2** | `cryptox-proto` | Non-constant-time UUID byte comparison leaked prefix timing side-channels | Added `ct_eq_id(&self)` using `subtle::ConstantTimeEq` (`ct_eq`) across all 7 typed `UUIDv7` structs |
| **3** | `cryptox-proto` | `EncryptedEnvelope::validate_structure` accepted arbitrary nonce sizes, `ratchet_step == 0`, and oversized DLP escrow blobs | Enforced strict cipher-suite nonce length (`12B` for AES-256-GCM, `24B` for XChaCha20-Poly1305), `ratchet_step >= 1`, `ciphertext.len() > 16`, and `corporate_escrow_sealed_key.len() <= 256` |
| **4** | `cryptox-core` | `ChatSession::decrypt_message` derived any key for arbitrary `ratchet_step` without replay tracking, allowing duplicate replay of captured packets and DoS via `ratchet_step = u64::MAX` | Implemented a **64-step WireGuard/IPsec-style `ReplaySlidingWindow`** (`last_highest_step` + 64-bit `window_bitmap`, `MAX_RATCHET_JUMP = 10_000`) returning `CryptoError::ReplayAttackDetected(step)` on replay, plus `decrypt_historical_message` for archive pagination |
| **5** | `cryptox-core` | `ChatSession::decrypt_message` compared `tenant_id`, `channel_id`, `sender_user_id`, and `sender_device_id` with non-constant-time `!=` | Replaced all 4 checks with constant-time `.ct_eq_id(...)` |
| **6** | `cryptox-storage` | `l1_directory_cache.clear()` upon hitting `max_l1_cache_entries` caused full L1 Cache Stampede DoS | Replaced full `.clear()` with targeted single-key eviction (`let victim_key = ...; remove(&k)`) |
| **7** | `auth-vault-svc` | Unlimited login challenge attempts allowed online password/key brute-forcing | Added `FailedAttemptTracker` (`MAX_FAILED_LOGIN_ATTEMPTS = 5`, `ACCOUNT_LOCKOUT_DURATION_MS = 300_000`) returning `AuthVaultError::AccountTemporarilyLocked` |
| **8** | `auth-vault-svc` | Unbounded `active_challenges` map allowed unauthenticated memory exhaustion DoS | Added `MAX_ACTIVE_CHALLENGES = 100_000` capacity cap + `prune_expired_challenges()` garbage collection |
| **9** | `auth-vault-svc` | `AutonomousTokenVerifier::revoked_tokens` could grow unboundedly | Added `MAX_REVOKED_TOKENS_CACHE = 200_000` bound with safe single-entry eviction |
| **10** | `user-directory-svc` | `tenant_compliance_roots` compared root public keys with non-constant-time `!=` | Replaced with `bool::from(existing.ct_eq(&root.public_key_x25519))` (`subtle::ConstantTimeEq`) |
| **11** | `presence-receipts-svc` | Malicious client could send a year-2099 `MessageId` as `read_up_to_id`, permanently freezing the user's unread watermark | Enforced `read_up_to_id.validate_not_in_future(now_ms)` -> `PresenceError::FutureTimestampRejected` |
| **12** | `presence-receipts-svc` | `online_heartbeats` map grew forever for disconnected devices | Added `MAX_TRACKED_HEARTBEATS = 250_000` and automatic `prune_stale_heartbeats(now_ms)` (`PRESENCE_TTL_MS = 300_000`) |
| **13** | `messaging-svc` | Authenticated token verified `tenant_id` and `user_id`, but did NOT verify `sender_device_id == claims.device_id`, allowing device spoofing across a user's laptops/phones | Added mandatory constant-time device binding check `!env_device.ct_eq_id(&claims.device_id)` -> `MessagingError::SenderOrTenantSpoofing` |
| **14** | `messaging-svc` | `dedup_index` grew unboundedly and accepted future-dated `MessageId` (`year 2099`) | Added `msg_id.validate_not_in_future(now_ms)` (`FutureTimestampRejected`) and `MAX_DEDUP_INDEX_ENTRIES = 500_000` bound |
| **15** | `edge-gateway` | No per-user rate limiting on the hot path | Added lock-free sharded `TokenBucketRateLimiter` (`DashMap<UserId, (u64, u32)>`, configurable `max_requests_per_window` / `window_ms`) returning `GatewayError::RateLimitExceeded` |

---

## 3. Stage 8 Adversarial Penetration Test Suite (`stage8_deep_security_hardening.rs`)

Executed via:
```powershell
cargo test --package edge-gateway --test stage8_deep_security_hardening
```

| Test Case | Attack Vector Simulated | Expected & Verified Result |
|---|---|---|
| `test_1_anti_replay_sliding_window_and_out_of_order_delivery` | Attacker replays captured `env1` (`step=1`), replays out-of-order `env2`/`env3`, or forges `ratchet_step = 999_999` | Exact `CryptoError::ReplayAttackDetected(1/2/3)` and `InvalidEnvelopeStructure`; historical archive reader still works |
| `test_2_future_uuidv7_timestamp_poisoning_blocked_everywhere` | Attacker injects `MessageId::from_raw_bytes(0xFFFF...)` (Year 10889) into `messaging-svc` and `presence-receipts-svc` | Blocked with `MessagingError::FutureTimestampRejected` and `PresenceError::FutureTimestampRejected` |
| `test_3_auth_brute_force_account_lockout_and_challenge_gc` | Attacker sends 5 invalid Ed25519 challenge signatures, then attempts 6th login with valid signature | Account locked for 5 minutes with `AuthVaultError::AccountTemporarilyLocked`; `issue_login_challenge` also blocked during lockout |
| `test_4_device_id_spoofing_and_gateway_rate_limiting` | Laptop A (`claims.device_id = A`) sends envelope claiming `sender_device_id = B`; user floods gateway beyond 5 req/sec | Blocked with `MessagingError::SenderOrTenantSpoofing` and `GatewayError::RateLimitExceeded` |
| `test_5_storage_targeted_l1_eviction_and_presence_ttl_pruning` | Attacker triggers L1 cache overflow (`cap = 4`) to cause Cache Stampede; stale heartbeats accumulate past 5-min TTL | Only 1 entry evicted (`l1_cached_directory_entries() == 4`, not `0`); stale presence pruned while active user stays online |

---

## 4. Static Security Lints & SonarQube CLI Audit Results

1. **Strict All-Targets Rust Clippy Security & Correctness Audit:**
   ```powershell
   cargo clippy --workspace --all-targets -- -D warnings -D clippy::suspicious -D clippy::correctness -D clippy::perf -D clippy::complexity
   ```
   - **Result:** `0 errors, 0 warnings` across all 7 workspace crates, binaries, benchmark examples, and all 28 adversarial/property-based integration tests (`unsafe_code = "forbid"`, `unwrap_used = "deny"`, `expect_used = "deny"`).
2. **SonarQube CLI (`v1.13.0` / `sonar-secrets v2.55.0.13968`):**
   - Connected to `https://sonarcloud.io` (Organization: `gansgx`).
   - Executed deterministic secrets & credential leak scan across `crates/`, `services/`, `docs/`, `.agents/`, `AGENTS.md`, `Cargo.toml`:
     ```text
     ✓ crates
     ✓ services
     ✓ docs
     ✓ .agents
     ✓ AGENTS.md
     ✓ Cargo.toml
     ✅ No secrets found · 1566ms
     ```
