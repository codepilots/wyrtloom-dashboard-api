# Wyrtloom Dashboard — HTTP API Reference

Complete reference for the [`wyrtloom-dashboard-api`](https://github.com/codepilots/wyrtloom-dashboard-api)
HTTP API. The API is a secure, frontend-agnostic [axum](https://github.com/tokio-rs/axum)
service that composes the Wyrtloom sibling crates (kanban board, argon2 user
directory, TOFU client-auth scheme, SQLite persistence, config loader, call
logger) behind a **default-deny, typed router**.

This reference is verified against the source (`src/routes.rs`, `src/auth.rs`,
`src/session.rs`, `src/main.rs`). Every endpoint below is registered in the
single `route_table()` source of truth; there is no path that bypasses it.

For how a client produces the request signature, see
[`client-authoring.md`](./client-authoring.md). For the ecosystem-wide security
model, see [`security-overview.md`](https://github.com/codepilots/wyrtloom/blob/main/docs/security-overview.md).

---

## Base URL, content type, and conventions

- Default bind is `http://127.0.0.1:7878` (loopback). Loopback is a deployment
  rail, **not** an authentication boundary — every endpoint is authenticated
  regardless of bind address. Terminate TLS in a reverse proxy in front.
- All request and response bodies are `application/json`, except `PUT /api/config`,
  whose request body is raw TOML text.
- Every error response has the shape `{ "error": "<generic message>" }`. Error
  messages are deliberately generic and never leak which internal step failed.
- All non-`enroll` routes require the client-signature headers (see
  [Request authentication](#request-authentication)). All `Role(...)` routes
  additionally require a session bearer token.

---

## Authentication tiers (`RequiredAuth`)

Every route declares exactly one of three tiers (`src/auth.rs`):

| Tier | Meaning |
|------|---------|
| `PublicBootstrap` | No client signature, no session. Rate-limited. **Only** `POST /api/enroll`. |
| `ClientOnly` | Client signature required, but no user session. **Only** `POST /api/login`. Rate-limited. |
| `Role(Viewer\|Operator\|Admin)` | Client signature **and** a verified user session **and** the exact role. |

Roles are **non-hierarchical**: `Admin` does not imply `Operator` does not imply
`Viewer`. A user must hold the exact role the route requires. (A bootstrap admin
is therefore granted all three roles explicitly at provisioning time.)

A startup assertion (`assert_all_routes_gated`) plus a test guarantee that **only**
`/api/enroll` may be `PublicBootstrap` and **only** `/api/login` may be
`ClientOnly`; any mis-gated route panics the server at boot.

---

## Endpoint summary

| Method | Path | Required auth |
|--------|------|---------------|
| POST | `/api/enroll` | `PublicBootstrap` (rate-limited) |
| POST | `/api/login` | `ClientOnly` (rate-limited) |
| POST | `/api/logout` | `Role(Viewer)` |
| GET | `/api/board` | `Role(Viewer)` |
| GET | `/api/tasks/:id` | `Role(Viewer)` |
| POST | `/api/tasks` | `Role(Operator)` |
| POST | `/api/tasks/:id/transition` | `Role(Operator)` |
| POST | `/api/tasks/:id/claim` | `Role(Operator)` |
| POST | `/api/tasks/:id/block` | `Role(Operator)` |
| GET | `/api/config` | `Role(Admin)` |
| PUT | `/api/config` | `Role(Admin)` |
| GET | `/api/plugins` | `Role(Viewer)` |
| GET | `/api/logs` | `Role(Admin)` |
| GET | `/api/audit` | `Role(Admin)` |

---

## Endpoints

### POST `/api/enroll`

Trust-on-first-use enrollment of a client application. The **only** route reachable
without a client signature. Pins the client's public key against a single-use
bootstrap key.

- **Auth:** `PublicBootstrap` (rate-limited per source IP). No signature headers, no session.
- **Request body:**
  ```json
  {
    "api_key": "<single-use bootstrap key (hex), printed by --issue-bootstrap-key>",
    "client_name": "<human-readable client name>",
    "public_key_b64": "<base64 of the client's public key>"
  }
  ```
  `public_key_b64` is the raw public key, base64 (standard alphabet). It is either
  a 32-byte ed25519 key or a 65-byte SEC1-uncompressed P-256 point (`0x04 ‖ X ‖ Y`);
  the algorithm is auto-detected by length.
- **Success — `200 OK`:** the enrollment credential returned by the TOFU scheme
  (carrying the assigned `client_id`, which equals `SHA-256(public_key)`).
- **Errors:**
  - `400 Bad Request` — `public_key_b64` is not valid base64.
  - `401 Unauthorized` — enrollment rejected (bad/spent bootstrap key, bad name,
    or pin mismatch — collapsed to one generic message; the failing step is never disclosed).
  - `429 Too Many Requests` — rate limited.
  - `413 Payload Too Large` — body over 64 KiB.

### POST `/api/login`

Authenticate a human user and mint a session token. Requires a valid client
signature but no existing session.

- **Auth:** `ClientOnly` (rate-limited per source IP). Client-signature headers required.
- **Request body:**
  ```json
  { "username": "<string>", "password": "<string>" }
  ```
- **Success — `200 OK`:**
  ```json
  { "token": "<base64(payload_json).hex(stamp)>", "exp_unix": 1700000000 }
  ```
  `token` is the session bearer to send on `Role(...)` routes. `exp_unix` is the
  absolute expiry (Unix seconds); default TTL is 30 minutes.
- **Errors:**
  - `401 Unauthorized` — invalid credentials (also returned for unknown, disabled,
    or locked-out accounts — all timing-uniform; a per-account lockout arms after 5
    failures for 300 s).
  - `429 Too Many Requests` — rate limited (token bucket, before argon2 work).
  - `413 Payload Too Large` — body over 64 KiB.
  - `500 Internal Server Error` — auth task failed (internal).

Password verification is argon2id, run on a blocking thread under a concurrency
semaphore so a login burst cannot exhaust CPU.

### POST `/api/logout`

Revoke the current session. Requires a valid session (any role ≥ Viewer).

- **Auth:** `Role(Viewer)` (client signature + session).
- **Request body:** none.
- **Success — `200 OK`:** `{ "ok": true }`
- **Behavior:** adds the session's exact nonce to the durable `revoked_sessions`
  denylist until `exp_unix` (the authoritative, cross-restart revocation), and
  best-effort invalidates the in-process stamp.
- **Errors:**
  - `401 Unauthorized` — missing/invalid session, or no session present.
  - `500 Internal Server Error` — revocation write failed.

### GET `/api/board`

List kanban tasks grouped by state into board columns.

- **Auth:** `Role(Viewer)`.
- **Query parameters:**
  - `states` (optional) — comma-separated state names. Valid names:
    `Backlog`, `Todo`, `Ready`, `Running`, `Blocked`, `Done`, `Archived`.
    Omitted or empty ⇒ all states. Query string is integrity-protected by the
    client signature.
- **Success — `200 OK`:**
  ```json
  { "columns": { "Todo": [ <task>, ... ], "Running": [ ... ] } }
  ```
  Keys are state names; values are arrays of task objects.
- **Errors:**
  - `400 Bad Request` — unknown state name in `states`.
  - `401 Unauthorized` / `403 Forbidden` — auth / role failure.
  - `500 Internal Server Error` — board listing failed.

### GET `/api/tasks/:id`

Fetch a single task by UUID.

- **Auth:** `Role(Viewer)`.
- **Path parameter:** `:id` — task UUID.
- **Success — `200 OK`:** the full task object.
- **Errors:**
  - `404 Not Found` — task not found (also returned for a malformed UUID path).
  - `401` / `403` — auth / role failure.

### POST `/api/tasks`

Create a new task. The actor is derived from the verified session user
(`human:<user_id>`), never from the body.

- **Auth:** `Role(Operator)`.
- **Request body:**
  ```json
  { "title": "<string>", "depends_on": ["<uuid>", "..."] }
  ```
  `depends_on` is optional (defaults to `[]`).
- **Success — `201 Created`:** `{ "id": "<uuid>" }`
- **Errors:**
  - `400 Bad Request` — task creation failed (e.g. invalid dependency).
  - `401` / `403` — auth / role failure.

### POST `/api/tasks/:id/transition`

Transition a task to a new state.

- **Auth:** `Role(Operator)`.
- **Path parameter:** `:id` — task UUID.
- **Request body:**
  ```json
  { "to": "<TaskState>", "reason": "<optional string>" }
  ```
  `to` is one of the valid state names listed under [`/api/board`](#get-apiboard).
- **Success — `200 OK`:** `{ "ok": true }`
- **Errors:**
  - `400 Bad Request` — transition rejected (illegal transition / unknown task).
  - `401` / `403` — auth / role failure.

### POST `/api/tasks/:id/claim`

Claim a task for the current actor.

- **Auth:** `Role(Operator)`.
- **Path parameter:** `:id` — task UUID.
- **Request body:** none.
- **Success — `200 OK`:** `{ "ok": true }`
- **Errors:**
  - `409 Conflict` — claim rejected (already claimed).
  - `401` / `403` — auth / role failure.

### POST `/api/tasks/:id/block`

Mark a task blocked with a human-supplied reason. `blocked_by` is recorded as the
verified human actor.

- **Auth:** `Role(Operator)`.
- **Path parameter:** `:id` — task UUID.
- **Request body:**
  ```json
  { "reason": "<string>" }
  ```
- **Success — `200 OK`:** `{ "ok": true }`
- **Errors:**
  - `400 Bad Request` — block rejected.
  - `401` / `403` — auth / role failure.

### GET `/api/config`

Read the server's `wyrtloom.toml`. Reads only the fixed server-side `--config`
path — never a caller-supplied path (no traversal).

- **Auth:** `Role(Admin)`.
- **Success — `200 OK`:**
  ```json
  {
    "toml": "<the on-disk TOML, round-trippable back via PUT>",
    "security": {
      "file_read_prefixes": ["..."],
      "file_write_prefixes": ["..."],
      "network_allowlist": ["..."],
      "allow_shell": false,
      "allow_git": false
    }
  }
  ```
- **Errors:**
  - `500 Internal Server Error` — config load or serialise failed.
  - `401` / `403` — auth / role failure.

### PUT `/api/config`

Replace the server's `wyrtloom.toml`. The submitted TOML is parsed **and**
validated before saving to the fixed server path.

- **Auth:** `Role(Admin)`.
- **Request body:** raw TOML text (not JSON).
- **Success — `200 OK`:** `{ "ok": true }`
- **Errors:**
  - `400 Bad Request` — invalid configuration (parse or validation failure).
    The internal parser/validator detail is recorded server-side (audit chain)
    but never echoed to the client.
  - `500 Internal Server Error` — config save failed.
  - `401` / `403` — auth / role failure.
  - `413 Payload Too Large` — body over 64 KiB.

Validation rejects path-traversal (`..`) in file capabilities and prefixes,
SAFE-class plugins that declare capabilities, unknown TOML keys, and bad SemVer.

### GET `/api/plugins`

List the configured plugin manifests (from the same fixed config path).

- **Auth:** `Role(Viewer)`.
- **Success — `200 OK`:**
  ```json
  {
    "plugins": [
      {
        "name": "<string>",
        "version": "1.2.3",
        "class": "<Safe|Unsafe>",
        "enabled": true,
        "capabilities": "<debug-formatted capability set>"
      }
    ]
  }
  ```
- **Errors:**
  - `500 Internal Server Error` — config load failed.
  - `401` / `403` — auth / role failure.

### GET `/api/logs`

Return all call-logger entries (if a logger DB was configured).

- **Auth:** `Role(Admin)`.
- **Success — `200 OK`:** `{ "logs": [ <entry>, ... ] }`. If no logger DB is
  configured, returns `{ "logs": [] }`.
- **Errors:**
  - `500 Internal Server Error` — log read failed.
  - `401` / `403` — auth / role failure.

### GET `/api/audit`

Return the tamper-evident audit-chain snapshot plus a freshly-computed chain
verification flag.

- **Auth:** `Role(Admin)`.
- **Success — `200 OK`:**
  ```json
  { "chain_verified": true, "anchor_verified": true, "entries": [ <audit entry>, ... ] }
  ```
  `anchor_verified` is the result of `SecurityModule::verify_anchor()` at request
  time: the store's signed high-water mark is present, genuine, and exactly in
  step with the chain. `false` means the anchor record was lost or altered, the
  store could not be read, or an anchor update failed and the newest entries are
  not yet protected against truncation.
  `chain_verified` is the result of `SecurityModule::verify_chain()` at request
  time (detects in-place tampering, reordering, mid-chain deletion). `entries`
  carry only public identifiers — never tokens, passwords, or keys.
- **Errors:**
  - `401` / `403` — auth / role failure.

---

## Request authentication

Two independent layers gate requests. The verification order is security-audit
mandated and implemented in `src/auth.rs::enforce_inner`.

### Layer 1 — client-application signature (all non-`enroll` routes)

Trust-on-first-use asymmetric signing (`wyrtloom-clientauth-tofu`). The client
signs the **canonical request bytes** and sends four headers:

| Header | Value |
|--------|-------|
| `x-wyrtloom-client` | the enrolled `client_id` |
| `x-wyrtloom-timestamp` | Unix seconds (server enforces a ±skew window; default ±300 s) |
| `x-wyrtloom-nonce` | a fresh per-request nonce (server replay-checks) |
| `x-wyrtloom-signature` | lowercase hex of the signature over the canonical bytes |

**The server rebuilds the canonical bytes; it never trusts client-supplied
canonical bytes.** It takes the real request method and the full `path_and_query`
string (so query parameters are integrity-protected, not just the path), buffers
the body under the 64 KiB limit, computes `SHA-256(body)`, and reconstructs the
canonical via the shared `canonical_request(method, path, body_sha256, client_id,
timestamp, nonce)` encoder. This length-prefixes every field under a domain tag
(`wyrtloom-client-auth-v1`), so a signature binds unambiguously to
method/path/body/client/time/nonce with no field-boundary confusion. The same
encoder is used by every signer and verifier, so signed bytes are byte-identical
everywhere. On success the canonical bytes are stamped into the tamper-evident
audit chain.

- ed25519 signatures are 64-byte raw; P-256 signatures are raw `r ‖ s` and **must
  be low-s normalized** by the client (the verifier rejects high-s to remove ECDSA
  malleability).
- Failure → `401 Unauthorized` (`missing client auth` / `bad client auth` /
  `client auth failed` — all generic).

See [`client-authoring.md`](./client-authoring.md) for a step-by-step recipe to
construct these headers (including SEC1 key export, the canonical encoding, and
low-s normalization).

### Layer 2 — user session bearer (all `Role(...)` routes)

```
Authorization: Bearer <base64(payload_json)>.<hex(stamp)>
payload_json = { "user_id", "roles", "exp_unix", "nonce" }
```

The `stamp` is the `SecurityModule` HMAC over the exact `payload_json` bytes. The
embedded `roles` are **advisory only** — they are never trusted on verify.

**Verification order is load-bearing** (`verify_session`):

1. **`exp` is checked BEFORE any MAC work.** The clock is read fail-closed: a
   pre-epoch / rolled-back clock is treated as expired, never as time 0. `now >
   exp_unix` → `401 session expired`.
2. **MAC stamp validity** (constant-time compare) is checked **before** the
   revocation lookup, so distinct error responses cannot be used to probe which
   nonces are on the denylist. Invalid → `401 session invalid`.
3. **Durable revocation denylist, fail-closed.** `Revoked` → `401 session
   invalid`; a transient/uncertain store read (`Unknown`) → `503 revocation
   status unavailable` (never let a revoked token through during a store hiccup).
4. **Role re-fetch.** The user is re-fetched from the directory and its **current**
   roles + `active` flag are authoritative. Unknown user → `401`; `!active` →
   `401 user disabled`. A role change or account disable takes effect on the very
   next request.

Then **RBAC** compares the user's current roles to the route's required role.
Mismatch → `403 forbidden`.

### Rate limiting (login / enroll)

A per-source-IP token bucket (5-token burst, refilling 1 token/sec) guards
`POST /api/login` and `POST /api/enroll`. The check runs at the top of the auth
middleware — **before** body buffering, signature verification, and argon2 — so a
credential burst is cheaply shed. Over-limit → `429 Too Many Requests`.

### Body size limit

All request bodies are capped at **64 KiB** (`MAX_BODY_BYTES`), enforced both by a
`tower_http::RequestBodyLimitLayer` and by the same bound on the in-middleware
body buffering used for the signed body. Over-limit → `413 Payload Too Large`.

### CORS

Exact-origin only. `--cors-origin` is repeatable and matched **exactly** via
`AllowOrigin::list`; the server never uses `Any` or request-mirroring. With no
configured origin, cross-origin access is denied (same-origin SPAs still work);
credentials are enabled **only** alongside an explicit origin list. Allowed
methods are `GET`, `POST`, `PUT`; allowed headers include `Authorization`,
`Content-Type`, and the four `x-wyrtloom-*` headers.

Every response also carries defence-in-depth security headers:
`Content-Security-Policy` (`default-src 'self'; script-src 'self'; object-src
'none'; base-uri 'none'; frame-ancestors 'none'`), `X-Content-Type-Options:
nosniff`, and `Referrer-Policy: no-referrer`, set `overriding` so handlers cannot
weaken them.

### Standard error model

| Status | Meaning |
|--------|---------|
| `400 Bad Request` | malformed body / unknown query value / invalid config |
| `401 Unauthorized` | client-signature or session auth failure (generic) |
| `403 Forbidden` | authenticated but lacking the required role |
| `404 Not Found` | task not found / unparseable id path |
| `409 Conflict` | claim rejected (already claimed) |
| `413 Payload Too Large` | body over 64 KiB |
| `429 Too Many Requests` | rate limited (login / enroll) |
| `500 Internal Server Error` | internal failure (store, serialise, save) |
| `503 Service Unavailable` | revocation status uncertain (fail-closed) |

All error bodies are `{ "error": "<generic message>" }`. Messages are intentionally
generic — credential and config internals are recorded server-side in the audit
chain (no secrets) but never echoed to the client.
