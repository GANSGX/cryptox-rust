# Stage 09 — Distributed Zero-Trust TCP RPC Mesh, 3-State Auto-Healing Circuit Breakers & Prometheus Observability

**Date:** 2026-11-24  
**Scope:** `services/edge-gateway/src/cluster_mesh.rs`, `services/edge-gateway/src/lib.rs`, `services/edge-gateway/src/http_server.rs`, `services/edge-gateway/tests/stage9_distributed_rpc_and_circuit_breaker.rs`  
**Standards:** NIST SP 800-207 (Zero-Trust Architecture), IETF RFC 4303 (2-Phase Anti-Replay), Bulkhead & 3-State Circuit Breaker Pattern (`02-rust-microservices-bulkhead.md`), OpenTelemetry / Prometheus Exposition Format `0.0.4`

---

## 1. Architectural Upgrades Delivered in Stage 9

### A. Real Multi-Port TCP Microservice Separation (`DistributedRpcCluster` & `MicroserviceTcpNode`)
- Backend microservices (`messaging-svc`, `user-directory-svc`, `presence-receipts-svc`) now bind real, independent `tokio::net::TcpListener` sockets on distinct network ports.
- `edge-gateway` communicates with each node over length-prefixed binary frames (`MAX_RPC_FRAME_BYTES = 131_072` to prevent OOM DoS) with strict `tokio::time::timeout` enforcement.

### B. Zero-Trust Internal Mesh Encryption & Node Authentication (`ZeroTrustRpcFrame`)
- Every internal TCP RPC packet inside the data center is encrypted with **`XChaCha20-Poly1305`** (bound via `AAD` to `request_id`, `timestamp_ms`, and `target_service`) and signed with the cluster node's **`Ed25519`** key (`ZeroTrustClusterKeys`).
- **Internal VLAN Intrusion Defense:** Any connection to an internal microservice TCP port without a valid cluster `Ed25519` signature and `XChaCha20-Poly1305` key is rejected before command deserialization and increments `cryptox_zero_trust_intrusions_blocked_total`.
- **Internal RPC Anti-Replay & Clock-Skew Shield:** Rejects replayed `request_id` (`UUIDv7`) via a bounded sharded replay cache (`MAX_RPC_REPLAY_CACHE_ENTRIES = 100_000`) and blocks packets outside `MAX_RPC_CLOCK_SKEW_MS = 60_000`.

### C. Lock-Free 3-State Auto-Healing Circuit Breakers (`Closed -> Open -> HalfOpen -> Closed`)
- Each microservice compartment has an atomic 3-state `CircuitBreaker`:
  1. **`CLOSED` (0):** Normal operation. Resets `consecutive_failures = 0` on success.
  2. **`OPEN` (2):** Trips automatically after `failure_threshold` consecutive TCP timeouts/errors. Rejects subsequent calls Fail-Fast in `< 50 ns` (`RpcMeshError::CircuitBreakerOpen`) without blocking threads on dead sockets.
  3. **`HALF_OPEN` (1):** Once `recovery_cooldown_ms` elapses, atomically (`compare_exchange`) allows **1 probe request** through over TCP. If the remote TCP node has recovered, the breaker **automatically self-heals back to `CLOSED`** and increments `cryptox_circuit_breaker_auto_heals_total`.

### D. Enterprise Kubernetes / Prometheus Observability (`GET /healthz`, `GET /readyz`, `GET /metrics`)
- `GET /healthz`: Liveness probe returning node identity and Zero-Trust mesh cipher suite.
- `GET /readyz`: Readiness probe returning all 4 circuit breaker states (`CLOSED` / `HALF_OPEN` / `OPEN`) and `HTTP 503` only if the critical hot-path (`messaging_svc`) circuit is `OPEN`.
- `GET /metrics`: Prometheus `0.0.4` exposition endpoint exporting hot-path throughput, absorbed sidecar failures, blocked Zero-Trust intrusions, rate-limiter drops, circuit breaker states/trips/auto-heals, and L1/L2 storage metrics.

---

## 2. Verification & Penetration Test Results (`stage9_distributed_rpc_and_circuit_breaker.rs`)

| Test Case | Scenario & Adversarial Vector | Result |
|---|---|---|
| `test_1_distributed_multi_port_tcp_cluster_e2ee_routing_and_zero_trust_intrusion_defense` | 3 distinct TCP ports spawned; full E2EE `@username` search, message routing, and cursor history over real TCP; internal VLAN hacker intrusion with rogue `Ed25519/AEAD` key + RPC frame replay + 5-min clock skew | **PASSED** (`zero_trust_intrusions_blocked == 1`, `ReplayOrClockSkewDetected`) |
| `test_2_three_state_circuit_breaker_auto_trip_fail_fast_and_self_healing_over_tcp` | TCP nodes for `user-directory-svc` and `presence-receipts-svc` killed -> breakers auto-trip `CLOSED -> OPEN` after 2 failures -> 3rd call fast-fails in `< 50 ns` -> 3 E2EE chat messages route 100% over `messaging-svc` TCP port -> killed TCP nodes restarted -> after 150ms cooldown, breaker transitions `OPEN -> HALF_OPEN -> CLOSED` automatically | **PASSED** (`auto_heal_count == 1`, `absorbed_sidecar_failures == 3`) |
