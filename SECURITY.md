# Security model — `wyrtloom-dashboard-api`

This document describes the security model of the secure, frontend-agnostic axum
API. It is verified against the code as of writing; file/line citations point at
the load-bearing implementation so the model can be re-audited against reality.

The crate ships no UI. It is the integration/wiring layer that composes the
sibling Wyrtloom crates (kanban board, argon2 user directory, TOFU client-auth
scheme, SQLite persistence, config loader, call logger) behind a default-deny,
typed router with two independent authentication layers and RBAC.

---

## Threat model & scope

**What this protects.** A local-first dashboard backend whose every endpoint is
reachable by any frontend (SPA, native, CLI) that holds an enrolled client key
plus a user session. The design assumes the socket is reachable by hostile local
software and by browser-driven SSRF/CSRF pivots, and that tokens may be stolen,
replayed, or outlive a role change.

**In scope / defended:**

- Forged or replayed client requests (per-request signature over server-rebuilt
  canonical bytes + nonce replay cache).
- Forged, tampered, expired, or revoked user sessions (MAC stamp + `exp` +
  durable denylist).
- Privilege retention after a role change or account disable (per-request role
  re-fetch + `active` check).
- Credential brute-force / CPU exhaustion via `/login` + `/enroll` (per-IP rate
  limit + argon2 concurrency semaphore + body limit).
- Accidental remote plain-HTTP exposure (loopback transport guard).
- Audit tampering detection (hash-chained, 0600 audit file; `verify_chain`).
- Cross-origin abuse from a browser (exact-origin CORS; CSP / nosniff /
  referrer-policy response headers).

**Out of scope / NOT defended (see Gotchas):**

- Confidentiality/integrity of the transport itself — TLS is expected to be
  terminated by a reverse proxy in front; the server binds loopback plain HTTP.
- Local-process isolation — loopback is **not** an auth boundary; any local
  process can connect, which is exactly why auth is mandatory on every endpoint.
- Horizontal scale / HA — single-instance / single-writer is assumed.
- Compromise of the one key file (root of trust for both signing and audit).
- Audit-log *truncation* (an attacker who can rewrite the whole file from the
  start can produce a self-consistent shorter chain) — inherited from core,
  roadmapped to external anchoring.

---

## Authentication & authorization

Two independent layers gate requests. The verification order is security-audit
mandated and implemented in `src/auth.rs::enforce_inner` (lines 104-184).

### Layer 1 — client-application signature (every route except `POST /api/enroll`)

Trust-on-first-use (`wyrtloom-clientauth-tofu`). The client sends four headers
(`src/auth.rs:51-54`):

| Header                 | Value                                            |
|------------------------|--------------------------------------------------|
| `X-Wyrtloom-Client`    | enrolled `client_id`                             |
| `X-Wyrtloom-Timestamp` | Unix seconds (skew window enforced in the scheme)|
| `X-Wyrtloom-Nonce`     | per-request nonce (replay-checked)               |
| `X-Wyrtloom-Signature` | hex signature over the canonical bytes           |

**The canonical bytes are rebuilt by the server, never trusted from the client.**
`verify_client` (`src/auth.rs:187-234`) takes the **real** request method
(`request.method()`, captured at line 136) and the **`path_and_query`** string
(line 139-143, so query parameters are integrity-protected, not just the path),
computes `SHA-256(body)` over the buffered body (line 209), and reconstructs the
canonical via `canonical_request(method, path, body_sha256, client_id, ts, nonce)`
(line 210). The client never supplies canonical bytes that are fed to the
verifier — only the signature, headers, and body are taken from the wire. On
success the **canonical bytes are stamped into the tamper-evident audit chain**
(`security.stamp(&canonical)`, line 229). Failure → `401`.

### Layer 2 — user session (every route except `enroll` + `login`)

Bearer token format (`src/session.rs:1-7`): `base64(payload_json) . hex(stamp)`,
where the stamp is a `SecurityModule` MAC over the **exact** `payload_json` bytes
and the payload is `{ user_id, roles, exp_unix, nonce }`.

`verify_session` (`src/auth.rs:238-294`) enforces this order — and the order is
load-bearing:

1. **`exp` is enforced BEFORE any MAC work** (lines 254-258). The clock is read
   via `now_unix_checked`; a pre-epoch / rolled-back clock returns `None` and is
   treated as **fail-closed** ("session expired"), never as time 0.
2. **MAC stamp validity** (`is_valid`, lines 264-266), checked *before* the
   revocation lookup specifically so distinct error responses cannot be used by
   an unauthenticated caller to probe which nonces are on the denylist.
3. **Durable revocation denylist, fail-closed** (lines 271-282). `revocation_status`
   (`src/state.rs:94-100`) returns `Revoked` / `NotRevoked` / `Unknown`, where
   `Unknown` is any store error other than `NotFound`. `Revoked` → `401`;
   `Unknown` → `503` (never let a revoked token through during a store hiccup).
4. **Roles are re-fetched from the user directory every request** (lines 285-289).
   The token's embedded `roles` are advisory only (`src/session.rs:8-12`); the
   *current* directory roles are authoritative. `active == false` is rejected
   (lines 290-292). A role change or account disable therefore takes effect on
   the very next request, regardless of an outstanding token.

**Logout** (`src/routes.rs:276-296`) adds the exact session nonce to the durable
`revoked_sessions` denylist until `exp_unix` (`state.revoke`, `src/state.rs:106-115`)
and additionally `invalidate`s the precise stamp using the exact payload bytes
the middleware verified (threaded through `AuthContext.session_bytes`, never
re-serialised — re-serialisation could drift). The durable denylist is the
authoritative, cross-restart revocation; the in-process `invalidate` is
belt-and-braces.

### RBAC — non-hierarchical, per-endpoint

`authorize` (`src/auth.rs:300-311`) requires the user to hold the **exact**
required role via `user.has_role(required)`. **Roles are NOT hierarchical** —
Admin does not imply Operator does not imply Viewer. A bootstrap admin is
therefore granted all three roles explicitly (`src/main.rs:171`). Mapping
(`src/routes.rs::route_table`, lines 37-124):

- **Reads → Viewer**: `/api/board`, `/api/tasks/:id`, `/api/plugins`, plus
  `/api/logout`.
- **Writes → Operator**: `POST /api/tasks`, `/transition`, `/claim`, `/block`.
- **Config / audit / logs → Admin**: `GET`+`PUT /api/config`, `/api/logs`,
  `/api/audit`.

### Default-deny typed router

Every route declares exactly one `RequiredAuth` — `PublicBootstrap`,
`ClientOnly`, or `Role(_)` (`src/auth.rs:39-48`). The single route table
(`src/routes.rs:37-124`) is the only source of truth, and `build_router`
(`src/routes.rs:156-170`) attaches the matching middleware per route, so there is
no path that bypasses the table — the default is deny. `assert_all_routes_gated`
(`src/routes.rs:129-151`) enforces that **only** `/api/enroll` may be
`PublicBootstrap` and **only** `/api/login` may be `ClientOnly`; it runs **both at
startup** (called from `build_router`, line 157) **and in a test**. An ungated /
mis-gated route panics the server at boot.

---

## Other controls (hardening)

All in `src/main.rs` unless noted.

- **Loopback-only transport guard** (lines 105-117). A non-loopback bind over
  plain HTTP is refused unless `--insecure-allow-remote-http` is passed.
  `is_loopback` covers `127.0.0.0/8` and `::1` (lines 249-254).
- **Exact-origin CORS** (`build_cors`, lines 259-284). `AllowOrigin::list` only —
  never `Any` and never request-mirroring. With no `--cors-origin`, cross-origin
  access is denied; `allow_credentials(true)` is set **only** alongside an
  explicit origin list.
- **Per-IP rate limit on `/login` + `/enroll`** before any expensive work. The
  limiter check happens at the top of `enforce_inner` (`src/auth.rs:113-121`),
  i.e. **before body buffering, signature verify, and argon2**. Token bucket: 5
  burst, 1 token/sec/IP (`src/main.rs:193`, `src/state.rs:176-218`).
- **argon2 concurrency semaphore** (`src/routes.rs:239`) caps concurrent password
  verifications at the CPU count (`src/main.rs:191`, `num_cpus`), and argon2 runs
  on a blocking thread (`spawn_blocking`, `src/routes.rs:245-246`) so it cannot
  stall the reactor.
- **64 KiB body limit** — `RequestBodyLimitLayer` (`src/main.rs:211`) plus the
  same `MAX_BODY_BYTES` bound on the in-middleware `to_bytes` buffering used for
  the signed body (`src/auth.rs:148`, `src/state.rs:43`).
- **Mandatory 0600 audit file, fail-closed** (`src/main.rs:126-131`). The server
  refuses to start if `--audit-file` cannot be opened. A `self_check` runs after.
- **Session key file generated 0600 with `O_EXCL`** (`load_or_create_key`,
  `src/main.rs:288-325`): `create_new(true)` (O_EXCL), `mode(0o600)`, then a
  defensive `set_permissions(0o600)` against a permissive umask. An all-zero or
  wrong-length key file is rejected.
- **Constant-time MAC** — stamp verification uses the core `SecurityModule`'s
  constant-time `is_valid`; the API never byte-compares MACs itself.
- **Security response headers on every response** (`src/main.rs:217-231`, set
  `overriding` so handlers cannot weaken them): `Content-Security-Policy`
  (`default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';
  frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`.
- **No secrets in audit detail** — recorded decisions carry only public
  identifiers (client id, user id, method, path, denied role); never tokens,
  passwords, keys, or bodies (`src/auth.rs:163-169, 304-307`;
  `src/routes.rs:259-271, 405-419`).
- **Fixed server-side config path** — `/api/config` and `/api/plugins` read/write
  only `config_path` (`src/state.rs:73-75`); no caller-supplied path, no
  traversal. Submitted TOML is parsed **and** validated before save
  (`src/routes.rs:400-425`); parser/validator detail is audited server-side but
  never echoed to the client.

### Provisioning

Two one-shot subcommands perform their action and exit (`src/main.rs:151-180`):

- **`--issue-bootstrap-key`** — issues a **single-use** enrollment key, prints it
  to stdout **once**, and only its hash is stored by the scheme. Give it to one
  client for `POST /api/enroll`.
- **`--create-admin <username>`** — reads the password from
  `$WYRTLOOM_ADMIN_PASSWORD` and creates a user granted **all three roles**
  (Viewer + Operator + Admin) because roles are non-hierarchical.

---

## Key decisions & rationale

- **Server rebuilds the canonical request; client-supplied canonical bytes are
  never trusted.** Signing the real method + `path_and_query` + `SHA-256(body)`
  binds the signature to exactly what the server will act on, closing the gap
  where a client could sign benign bytes and send different ones.
- **`exp` checked before the MAC, and the MAC before the revocation lookup.**
  Cheap freshness rejection first avoids spending crypto on stale tokens; doing
  the MAC before the denylist read prevents an unauthenticated caller from using
  response differences to enumerate revoked nonces.
- **Roles re-fetched every request; token roles advisory.** A long-lived or
  stolen token cannot retain privileges after a directory change; disable/role
  change is effective on the next request without token revocation infrastructure.
- **Revocation fails closed on uncertainty.** A transient store error is `Unknown`
  → `503`, never silently "not revoked".
- **Default-deny typed router with a boot-time + test assertion.** Forgetting to
  gate a route is a startup panic, not a silent open endpoint.
- **Non-hierarchical roles.** Explicit grants avoid the "Admin silently gets read
  access it was never reviewed for" class of surprise; the cost is that admins
  must be granted lower roles explicitly (handled in provisioning).
- **Loopback bind + mandatory auth.** Transport is delegated to a fronting TLS
  proxy; the API never relies on network position for authentication.

---

## Gotchas / watch-outs

- **Loopback is NOT an authentication boundary.** Any local process can connect
  to the loopback socket (and a browser SSRF/CSRF pivot can too). Auth applies to
  **every** endpoint regardless of bind address; the transport guard
  (`--insecure-allow-remote-http`) is only a deployment safety rail
  (`src/state.rs:3-9`, `src/main.rs:9-11`).
- **Single-instance / single-writer assumption.** The client-auth **nonce replay
  cache** and the **enroll/bootstrap lock** are **process-local**
  (`src/state.rs:57-63`, `src/auth.rs:220-224`). A nonce replayed against a
  *different* process would not be caught, and concurrent enrollments could race
  on the single-use bootstrap key. **Do not horizontally scale this API as-is** —
  HA needs the replay cache and bootstrap state moved into shared store state
  behind a compare-and-set (atomic insert-if-absent).
- **One key file is the root of trust for BOTH session signing and audit
  anchoring.** The same `--session-key-file` keys the session stamps and anchors
  the audit hash-chain (`src/main.rs:120-128`). Its compromise lets an attacker
  forge sessions **and** rewrite the audit log. Protect this file (0600, restricted
  host, backups treated as secrets).
- **`$WYRTLOOM_ADMIN_PASSWORD` lives in the provisioning process env.** It is read
  by `--create-admin` (`src/main.rs:164`). Set it **inline** for the one-shot
  invocation; do not `export` it into a long-lived shell or shared environment.
- **Browser clients cannot hold a signing key like native clients can.** A web
  SPA must use a **non-extractable WebCrypto** P-256 key and **low-s normalize**
  its signatures so they match the scheme's expected encoding. (The CSP / nosniff
  / referrer-policy headers blunt the residual that XSS could *use* the
  non-extractable key even though it cannot exfiltrate it.)
- **Audit-truncation limitation inherited from core.** The chain detects in-place
  tampering, but an attacker able to rewrite the entire file from the start can
  produce a shorter, self-consistent chain. External anchoring is roadmapped.

---

## Operational requirements

- **Run a single instance only.** See the single-writer gotcha above.
- **Provide `--audit-file`.** The server fails closed without a writable audit
  file. Keep it `0600` and on durable storage.
- **Protect `--session-key-file` (0600).** It is the root of trust for sessions
  and audit; back it up as a secret. It is auto-generated `0600`/`O_EXCL` if
  missing and must be reused across restarts for sessions and the chain to survive.
- **Terminate TLS in front; keep the bind on loopback.** Only use
  `--insecure-allow-remote-http` if you fully understand it exposes plain HTTP.
- **Set exact `--cors-origin` values** for any cross-origin SPA; omit entirely to
  deny cross-origin access. Never expect `Any`/mirror behaviour.
- **Provision out-of-band:** issue a single-use bootstrap key
  (`--issue-bootstrap-key`, printed once) for the first client enrollment, and
  create the first admin with `--create-admin` supplying
  `$WYRTLOOM_ADMIN_PASSWORD` **inline** (not exported).
- **Default session TTL is 30 minutes** (`SESSION_TTL_SECS`, `src/state.rs:46`);
  the revocation denylist is pruned past expiry to stay bounded.
- **Keep the host clock sane.** Freshness gates fail closed on a pre-epoch /
  rolled-back clock (`now_unix_checked`, `src/state.rs:149-155`).
