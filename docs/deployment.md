# Deploying the Wyrtloom dashboard (operator guide)

This guide is for **operators** standing up the Wyrtloom dashboard: the
`wyrtloom-dashboard-api` HTTP service and the `wyrtloom-dashboard-web` SPA. It
covers building, provisioning initial state, the API's CLI flags, the security
posture you must respect, and serving the web app.

See also: [getting-started.md](https://github.com/codepilots/wyrtloom/blob/main/docs/getting-started.md) for the repo map,
[configuration.md](https://github.com/codepilots/wyrtloom-config/blob/main/docs/configuration.md) for the `wyrtloom.toml` the API reads/writes,
and [dashboard-user-guide.md](https://github.com/codepilots/wyrtloom-dashboard-web/blob/main/docs/dashboard-user-guide.md) for the end-user view.

## Building

The Rust toolchain is not on the default `PATH`; export it first:

```sh
export PATH="/home/autumn/.hermes/profiles/coder/home/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
```

### API (`wyrtloom-dashboard-api`)

```sh
cargo build && cargo test && cargo clippy --all-targets
```

### Web (`wyrtloom-dashboard-web`)

Node 22 + npm:

```sh
npm install
npm run build      # type-check + production build → dist/
```

The production build emits a static `dist/` directory to be served by a reverse
proxy / static host (see "Serving the web SPA" below).

## Provisioning (run only while the server is stopped)

Two one-shot subcommands provision initial state. **Each performs its action and
exits immediately — it does not start the server.** They write only to the
persistence store (`store.db`); they deliberately build the security module
**without** the audit file, so they never open a second appender on the audit
JSONL.

> **Run provisioning only while the server is stopped.** Provisioning is a second
> process opening the same `store.db`. The single-use bootstrap guarantee (a
> per-process enroll lock) and the audit hash-chain both assume a **single
> writer**; a concurrent provisioning process would split that state.

### Create the first admin

The password is read from the `WYRTLOOM_ADMIN_PASSWORD` environment variable. Set
it **inline** for the one invocation — do not `export` it into a long-lived or
shared shell:

```sh
WYRTLOOM_ADMIN_PASSWORD='choose-a-strong-password' \
  cargo run -- --store store.db --create-admin alice
```

Because roles are **non-hierarchical** (Admin does not imply Operator does not
imply Viewer), the created admin is granted **all three roles** (Viewer +
Operator + Admin) so the account is fully operational.

### Issue a single-use bootstrap enrollment key

The key is printed to stdout **once**; only its hash is stored. Give it to the one
client (e.g. the first browser) that will call `POST /api/enroll`:

```sh
cargo run -- --store store.db --issue-bootstrap-key
```

Each first-run client needs its own single-use bootstrap key. Issue another when
you enroll another device.

## Running the API

Loopback bind, with the audit file mandatory:

```sh
cargo run -- \
  --bind 127.0.0.1:7878 \
  --kanban-db kanban.db \
  --store store.db \
  --config wyrtloom.toml \
  --session-key-file session.key \
  --audit-file audit.jsonl \
  --logger-db logger.db \
  --cors-origin https://dashboard.example
```

### CLI flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--bind <ADDR>` | `127.0.0.1:7878` | Listen address. Must be loopback unless `--insecure-allow-remote-http`. |
| `--kanban-db <PATH>` | `kanban.db` | SQLite DB for the Kanban board. |
| `--store <PATH>` | `store.db` | SQLite persistence DB (users, clients, session revocations). |
| `--config <PATH>` | `wyrtloom.toml` | The **only** config file the API reads/writes (`GET`/`PUT /api/config`). |
| `--session-key-file <PATH>` | `session.key` | 32-byte session/audit key file. Generated `0600` if missing, reused thereafter. |
| `--audit-file <PATH>` | (none) | Tamper-evident audit JSONL. **Required to serve** — the server fails closed if absent or unopenable. Not used by the one-shot provisioning subcommands. |
| `--logger-db <PATH>` | (none) | Optional SQLite DB for the call logger. With none, `GET /api/logs` returns an empty list. |
| `--cors-origin <ORIGIN>` | (none) | Exact allowed CORS origin. **Repeatable.** Empty ⇒ no cross-origin access. |
| `--insecure-allow-remote-http` | off | Allow binding a non-loopback address over plain HTTP. **Dangerous.** |
| `--issue-bootstrap-key` | — | Provisioning: issue a single-use bootstrap key, print it, exit. |
| `--create-admin <USERNAME>` | — | Provisioning: create an admin (password from `$WYRTLOOM_ADMIN_PASSWORD`), exit. |

## Security posture

The dashboard API is a **local-first** backend whose threat model assumes the
socket is reachable by hostile local software and by browser-driven SSRF/CSRF
pivots, and that tokens may be stolen, replayed, or outlive a role change. The
following operator-facing rules follow from that.

### Loopback is NOT an authentication boundary

By default the API binds loopback only. **This is a deployment rail, not an auth
boundary** — any local process (or a browser SSRF/CSRF pivot) can reach a loopback
socket. Authentication therefore applies on **every** endpoint regardless of bind
address: every route except `POST /api/enroll` is client-signature gated, and
every route except `enroll` + `login` is session gated. The transport guard
(`--insecure-allow-remote-http`) only prevents *accidental* remote plain-HTTP
exposure.

### Remote use needs a TLS-terminating reverse proxy

The API binds **plain HTTP**; it does not terminate TLS. A non-loopback bind over
plain HTTP is **refused** unless you pass `--insecure-allow-remote-http`. For any
remote access, put a **TLS-terminating reverse proxy** in front and keep the API
on loopback. Confidentiality/integrity of the transport is delegated to that
proxy.

### Security response headers at the serving layer

Every API response already carries, as defence-in-depth against XSS and
clickjacking:

- `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src
  'none'; base-uri 'none'; frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`

The serving layer that fronts the **SPA** should send the **same** CSP and
`X-Content-Type-Options: nosniff` as real HTTP response headers. The SPA's
`index.html` ships a CSP `<meta>` tag as a fallback, but `frame-ancestors` is
**only** honoured when delivered as a response header — so the header is required
to actually deny framing.

### Key management — the session key is the root of trust

`--session-key-file` is the **single root of trust for both session signing and
audit anchoring**. The same key signs session stamps and anchors the audit
hash-chain. Its compromise lets an attacker forge sessions **and** rewrite the
audit log. Therefore:

- Protect the file (`0600`, restricted host, backups treated as secrets). It is
  auto-generated with `0600` / `O_EXCL` if missing (an all-zero or wrong-length
  file is rejected).
- **Reuse the same key file across restarts** — sessions and the audit chain only
  survive a restart if the key is the same one that created them.

### Single-instance assumption

The API is designed to run as a **single instance / single writer**. Two pieces of
security-critical state are process-local, not shared:

- the client-auth **nonce replay cache** (a replayed request is only caught if the
  original was seen by the *same* process), and
- the **enroll / bootstrap lock** (serialises enrollment so a single-use bootstrap
  key cannot be redeemed twice concurrently).

**Do not horizontally scale this API as-is.** Running multiple instances behind a
load balancer would split this state. HA is out of scope for v0.1.

### Mandatory, verified audit file

`--audit-file` is **required** to serve; the server fails closed if it is missing
or cannot be opened. The hash-chained, `0600` audit file is **verified at startup**
(`verify_chain`) — a tampered or forked chain aborts the server rather than
serving silently. Keep the audit file `0600` and on durable storage. (The chain
detects in-place tampering; full-file truncation is a documented limitation,
roadmapped to external anchoring.)

### Other built-in controls (no operator action needed)

- Sessions are short-lived (default TTL 30 min); `exp` is enforced **before** any
  MAC work; a durable revocation denylist backs logout.
- User roles are **re-fetched every request** — disabling a user or changing roles
  takes effect on the very next request, regardless of an outstanding token.
- Per-IP rate limiting on `/login` + `/enroll`; an argon2 concurrency cap; a
  64 KiB body limit.
- Exact-origin CORS only (`--cors-origin`); never `Any` or request-mirroring.
  Credentials are enabled **only** alongside an explicit origin list.

## Serving the web SPA

Build the SPA (`npm run build` → `dist/`) and serve the static files behind the
same reverse proxy that fronts the API. Recommended layout:

- Serve the SPA's `dist/` and the API under the **same origin** (the proxy fronts
  the loopback API and serves the static assets at the same host).
- Add that exact origin to the API's `--cors-origin` allowlist so credentialed
  session requests are accepted. With the same-origin layout this is mainly
  belt-and-braces.
- Send the CSP + `X-Content-Type-Options: nosniff` response headers from the
  serving layer (see above).

`VITE_API_BASE` controls the base URL the SPA calls; it **defaults to `/api`**
(same-origin). Point it elsewhere only if that origin is on the API's CORS
allowlist. (`VITE_DEV_API_TARGET` is a dev-only proxy target, e.g.
`http://127.0.0.1:7878`.)

The SPA enrolls its **own** non-extractable WebCrypto P-256 key in the browser and
signs every request itself — no edge signing component is needed and no signing
key is shipped in the bundle. You only need to hand the first-run user a
single-use bootstrap key (issued above) to complete enrollment.
