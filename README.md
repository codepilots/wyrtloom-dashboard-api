# wyrtloom-dashboard-api

A secure, frontend-agnostic [axum](https://github.com/tokio-rs/axum) HTTP API for
the Wyrtloom dashboard. It is the **integration / wiring** crate: it composes the
already-built sibling crates (kanban board, argon2 user directory, TOFU
client-auth scheme, SQLite persistence, config loader, call logger) behind a
default-deny, typed router with layered authentication and RBAC.

This crate ships no UI. Any frontend (SPA, mobile, CLI) talks to it over the
header scheme below.

## Build & run

Cargo/rustc are not on the default PATH in this environment:

```sh
export PATH="/home/autumn/.hermes/profiles/coder/home/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
cargo build && cargo test && cargo clippy --all-targets
```

Run (loopback only, audit file mandatory):

```sh
cargo run -- \
  --bind 127.0.0.1:7878 \
  --kanban-db kanban.db \
  --store store.db \
  --config wyrtloom.toml \
  --session-key-file session.key \
  --audit-file audit.jsonl \
  --cors-origin https://dashboard.example
```

* `--audit-file` is **required** — the server fails closed if it is absent or
  cannot be opened.
* `--session-key-file` is generated (32 random bytes, `0600`) if missing and
  reused thereafter, so sessions and the audit hash-chain survive a restart.
* Binding a non-loopback address over plain HTTP is **refused** unless
  `--insecure-allow-remote-http` is passed. Loopback is a deployment rail, *not*
  an authentication boundary (see below) — put TLS termination in front and keep
  this on loopback.
* `--cors-origin` is repeatable and matched **exactly**. With no origins,
  cross-origin access is denied; credentials are only enabled alongside an
  explicit origin list (never `Any` / request-mirroring).

## Authentication header scheme

Two independent layers gate requests:

### 1. Client-application auth (every route except `POST /api/enroll`)

Trust-on-first-use ed25519 (`wyrtloom-clientauth-tofu`). The client signs the
canonical request bytes and sends:

| Header                  | Value                                                        |
|-------------------------|-------------------------------------------------------------|
| `X-Wyrtloom-Client`     | enrolled `client_id`                                         |
| `X-Wyrtloom-Timestamp`  | Unix seconds (±skew window enforced server-side)            |
| `X-Wyrtloom-Nonce`      | per-request nonce (replay-checked)                          |
| `X-Wyrtloom-Signature`  | hex(ed25519 signature over the canonical bytes)            |

The server buffers the body (under the 64 KiB limit), computes its SHA-256, and
rebuilds the canonical bytes via
`TofuClientAuth::canonicalize(method, path, body_sha256, client_id, ts, nonce)`
before verifying. A verified request appends a tamper-evident stamp to the audit
chain. Failure → `401`.

### 2. User session (every route except `enroll` + `login`)

```
Authorization: Bearer <base64(payload_json)>.<hex(stamp)>
payload_json = { "user_id", "roles", "exp_unix", "nonce" }
```

The `stamp` is the `SecurityModule` HMAC over the exact `payload_json` bytes.
Verification order (load-bearing):

1. reject if `now > exp_unix` (before any MAC work);
2. reject if `nonce` is in the durable `revoked_sessions` denylist;
3. verify the stamp;
4. **re-fetch the user** from the directory and use its *current* roles +
   reject if `!active` — the token's embedded `roles` are advisory only.

Then RBAC compares the user's current roles to the route's required `Role`.
Failure → `401` (auth) / `403` (RBAC).

## Endpoints

| Method | Path                          | Required auth        |
|--------|-------------------------------|----------------------|
| POST   | `/api/enroll`                 | PublicBootstrap (rate-limited) |
| POST   | `/api/login`                  | ClientOnly (rate-limited)      |
| POST   | `/api/logout`                 | Role: Viewer         |
| GET    | `/api/board?states=...`       | Role: Viewer         |
| GET    | `/api/tasks/:id`              | Role: Viewer         |
| POST   | `/api/tasks`                  | Role: Operator       |
| POST   | `/api/tasks/:id/transition`   | Role: Operator       |
| POST   | `/api/tasks/:id/claim`        | Role: Operator       |
| POST   | `/api/tasks/:id/block`        | Role: Operator       |
| GET    | `/api/config`                 | Role: Admin          |
| PUT    | `/api/config`                 | Role: Admin          |
| GET    | `/api/plugins`                | Role: Viewer         |
| GET    | `/api/logs`                   | Role: Admin          |
| GET    | `/api/audit`                  | Role: Admin          |

`POST /api/login` returns `{ "token", "exp_unix" }`. `GET /api/audit` returns the
audit snapshot plus a `chain_verified` flag from `SecurityModule::verify_chain`.

## Security posture

* **Default-deny typed router** — every route declares exactly one
  `RequiredAuth`; a startup assertion and a test (`route_gate_enumeration_*`)
  fail if any non-bootstrap route is reachable without client + session auth.
* **Loopback is not an auth boundary.** Any local process (or a browser-driven
  SSRF/CSRF pivot) can reach a loopback socket, so every endpoint except
  `/api/enroll` is client-signature gated and every endpoint except `enroll` +
  `login` is session gated. The transport guard only prevents accidental remote
  plain-HTTP exposure.
* **Session expiry enforced before MAC verification**; short default TTL (30 min).
* **Durable revocation denylist** (`revoked_sessions` collection), pruned past
  expiry; logout adds the session nonce and invalidates the stamp.
* **Per-request role re-fetch** — disabling a user or changing roles takes effect
  on the very next request, regardless of an outstanding token.
* **Rate limiting** — a per-IP token bucket guards `/login` and `/enroll`.
* **argon2 concurrency cap** — a Tokio `Semaphore` bounds concurrent password
  verifications so a login burst cannot exhaust CPU/memory.
* **Body limit** — `tower_http::RequestBodyLimitLayer` at 64 KiB.
* **Exact-origin CORS** — `AllowOrigin::list` only; never `Any` or mirror;
  credentials only with the explicit list.
* **Mandatory audit file** — fail closed if `--audit-file` is missing.
* **No secrets in audit detail** — only public identifiers (client id, user id,
  method, path) are recorded; tokens, passwords, and keys never are.
* **Config path is fixed server-side** — `/api/config` reads/writes only the
  `--config` path and validates submitted TOML (traversal rejected by the loader).
* **Security response headers** — every response carries
  `Content-Security-Policy` (`default-src 'self'; script-src 'self'; object-src
  'none'; base-uri 'none'; frame-ancestors 'none'`), `X-Content-Type-Options:
  nosniff`, and `Referrer-Policy: no-referrer` as defence-in-depth against XSS
  (which could otherwise *use* the non-extractable client key) and clickjacking.

## Deployment: single-instance assumption

This API is designed to run as a **single instance / single writer**. Two pieces
of security-critical state are process-local rather than shared:

* the **client-auth nonce replay cache** (per-process; a replayed request is only
  rejected if the original was seen by the *same* process), and
* the **enroll / bootstrap lock** (a per-process lock serialises enrollment so a
  single-use bootstrap key cannot be redeemed twice concurrently).

Running multiple instances behind a load balancer would split this state: a nonce
replayed against a *different* instance would not be caught, and concurrent
enrollments could race on the bootstrap key. **Do not horizontally scale this API
as-is.** Horizontal scaling would require moving the replay cache and the
bootstrap/enroll state into the shared persistence store with a **compare-and-set**
(atomic insert-if-absent) operation so the check-and-record is atomic across
writers. This is documented, not implemented — HA is out of scope for v0.1.

## License

Apache-2.0. See [LICENSE](LICENSE).
