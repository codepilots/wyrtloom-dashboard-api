# Changelog

All notable changes to `wyrtloom-dashboard-api` are documented here.

## [0.1.0] — initial release

First implementation of the secure, frontend-agnostic dashboard API.

### Added
- Default-deny **typed router**: every route declares a `RequiredAuth`
  (`PublicBootstrap` / `ClientOnly` / `Role`); a startup assertion plus the
  `route_gate_enumeration_no_default_open` test guarantee no route is reachable
  without the appropriate auth.
- Two-layer auth middleware:
  - **Client-signature layer** (TOFU ed25519 over canonicalised request bytes,
    body SHA-256 included); verified requests are stamped into the tamper-evident
    audit chain.
  - **User-session layer**: `base64(payload).hex(stamp)` bearer tokens with
    `exp` enforced before MAC verification, durable nonce revocation denylist,
    stamp validity, and per-request user/role/active re-fetch.
  - **RBAC** against the route's required `Role`, recording grant/deny decisions.
- Endpoints: enroll, login, logout, board, task get/create/transition/claim/block,
  config get/put, plugins, logs, audit (with `verify_chain` status).
- Startup wiring: `SqliteStore` shared as `Arc<dyn PersistenceProvider>` into the
  user directory and client-auth scheme; SQLite kanban board; keyed
  `SecurityModule` with a mandatory audit file.

### Security hardening (from the integration security audit)
- Loopback-only transport guard (`--insecure-allow-remote-http` to override),
  with a documented note that loopback is **not** an auth boundary.
- Mandatory audit file — fail closed if absent.
- Persisted 32-byte session/audit key file, created with `0600` if missing.
- Per-IP token-bucket rate limiting on `/login` and `/enroll`.
- Tokio `Semaphore` capping concurrent argon2 verifications; argon2 run on a
  blocking task.
- `RequestBodyLimitLayer` at 64 KiB; the auth layer buffers the signed body under
  the same limit.
- Exact-origin CORS via `AllowOrigin::list` (never `Any`/mirror); credentials
  only with an explicit origin list.
- Durable `revoked_sessions` collection, pruned past expiry.
- No secrets/tokens in audit `detail` — only public identifiers.

### Code-review fixes
- **Revocation fails closed**: `revocation_status` distinguishes a definite
  "not revoked" (store `NotFound`) from an uncertain store error; the latter
  rejects the request (`503`) instead of silently admitting a revoked token.
- **Clock failure fails closed**: session-expiry uses `now_unix_checked`; a
  pre-epoch/rolled-back clock rejects rather than treating "now" as 0 (which
  would accept every expired token).
- **No denylist-membership oracle**: the stamp MAC is verified *before* the
  revocation lookup, and a revoked token returns the same `session invalid` body
  as a bad MAC, so an unauthenticated caller cannot probe the denylist.
- **Precise logout invalidation**: the verified payload bytes are threaded
  through to `logout`, which invalidates the exact stamp instead of
  re-serialising (avoiding a stamp-drift / empty-payload fallback bug).
- Shared a single hex decoder across the session and client-auth paths.

### Second-pass security-audit fixes
- **Provisioning decoupled from the audit file**: the `--issue-bootstrap-key` /
  `--create-admin` subcommands now build the `SecurityModule` *without*
  `with_audit_file`, so they never open a second appender on the audit JSONL or
  re-anchor the chain. Previously they did, risking an audit-chain fork/corruption
  when run against a live server. `--audit-file` is now optional (server-only).
- **Audit chain verified at startup (fail closed)**: the server path explicitly
  calls `verify_chain()` after attaching the audit file and aborts startup with a
  clear error on failure, logging `audit chain verified, N entries` on success.
- **Documented single-writer provisioning**: README + a code comment note that
  provisioning is a second process sharing `store.db` and must run only while the
  server is stopped.
