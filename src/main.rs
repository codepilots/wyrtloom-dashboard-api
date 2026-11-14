//! `wyrtloom-dashboard-api` — a secure, frontend-agnostic axum HTTP API that
//! wires the Wyrtloom sibling crates (kanban board, user directory, client-auth
//! scheme, persistence, config, logger) behind a default-deny, typed router.
//!
//! SECURITY POSTURE (summary; see README.md for detail):
//!   * Default-deny typed router — every route declares a `RequiredAuth`; a
//!     startup assertion + a test fail if any non-bootstrap route is reachable
//!     without client+session auth.
//!   * Loopback binding is NOT an auth boundary; the transport guard only
//!     prevents accidental remote exposure over plain HTTP. Auth applies to
//!     every endpoint regardless of bind address.
//!   * Mandatory audit file (fail closed); short-lived sessions with `exp`
//!     enforced before MAC verification; durable revocation denylist; per-request
//!     role re-fetch; rate-limited `/login`+`/enroll`; argon2 concurrency cap;
//!     64 KiB body limit; exact-origin CORS (never `Any`/mirror).

use wyrtloom_dashboard_api::{routes, state};

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::http::{header, HeaderValue, Method};
use clap::Parser;
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use wyrtloom_core::client_auth::ClientAuthScheme;
use wyrtloom_core::kanban::KanbanBoard;
use wyrtloom_core::logger::CallLogger;
use wyrtloom_core::persistence::PersistenceProvider;
use wyrtloom_core::profile::TaskProfile;
use wyrtloom_core::provider::LlmProvider;
use wyrtloom_core::audit_anchor::PersistenceAuditAnchor;
use wyrtloom_core::security::{AnchorEnrollment, SecurityModule, SecurityPolicy};
use wyrtloom_core::users::{AuthError, NewUser, Role, UserDirectory};

use plugin_kanban_sqlite::SqliteKanbanBoard;
use plugin_logger_sqlite::SqliteCallLogger;
use plugin_provider_ollama::OllamaProvider;
use tokio::sync::Semaphore;
use wyrtloom_clientauth_tofu::TofuClientAuth;
use wyrtloom_store_sqlite::SqliteStore;
use wyrtloom_users::UserStore;

use wyrtloom_dashboard_api::state::{AppState, Inner, RateLimiter, MAX_BODY_BYTES};

#[derive(Parser, Debug)]
#[command(name = "wyrtloom-dashboard-api", version, about = "Secure dashboard API for Wyrtloom")]
struct Cli {
    /// Address to bind. Must be loopback unless --insecure-allow-remote-http.
    #[arg(long, default_value = "127.0.0.1:7878")]
    bind: String,

    /// SQLite database for the kanban board.
    #[arg(long, default_value = "kanban.db")]
    kanban_db: String,

    /// SQLite persistence DB (users, clients, revocations).
    #[arg(long, default_value = "store.db")]
    store: String,

    /// Optional SQLite DB for the call logger.
    #[arg(long)]
    logger_db: Option<String>,

    /// Path to wyrtloom.toml (the only config file the API reads/writes).
    #[arg(long, default_value = "wyrtloom.toml")]
    config: String,

    /// 32-byte session/audit key file. Generated with 0600 perms if missing.
    #[arg(long, default_value = "session.key")]
    session_key_file: String,

    /// Tamper-evident audit JSONL file. REQUIRED to serve — the server fails
    /// closed if this is not provided. Not needed for one-shot provisioning
    /// subcommands, which write no audit entries.
    #[arg(long)]
    audit_file: Option<String>,

    /// One-time adoption of audit anchoring: accept an EXISTING, non-empty audit
    /// file that has no anchor in the store yet, and anchor it as it stands.
    /// Without this flag such a start is refused, because a missing anchor is
    /// what an attacker who deleted it would present. Pass it for one start
    /// only, then remove it.
    #[arg(long)]
    audit_anchor_enroll: bool,

    /// Exact allowed CORS origin (repeatable). Empty => no cross-origin access.
    #[arg(long = "cors-origin")]
    cors_origin: Vec<String>,

    /// Allow binding a non-loopback address over plain HTTP. DANGEROUS.
    #[arg(long)]
    insecure_allow_remote_http: bool,

    /// Provisioning: issue a single-use bootstrap enrollment key, print it to
    /// stdout, and exit (give it to one client for POST /api/enroll).
    #[arg(long)]
    issue_bootstrap_key: bool,

    /// Provisioning: create an Admin user with this username (password read from
    /// $WYRTLOOM_ADMIN_PASSWORD), then exit.
    #[arg(long)]
    create_admin: Option<String>,
}

/// Id of this server's audit-anchor record in the persistence store.
const AUDIT_ANCHOR_ID: &str = "dashboard-api";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    // ── Transport guard: refuse non-loopback bind over plain HTTP. ─────────
    let addr: SocketAddr = cli
        .bind
        .parse()
        .with_context(|| format!("invalid --bind address '{}'", cli.bind))?;
    if !is_loopback(addr.ip()) && !cli.insecure_allow_remote_http {
        bail!(
            "refusing to bind non-loopback address {} over plain HTTP. \
             Put a TLS-terminating reverse proxy in front and keep this on loopback, \
             or pass --insecure-allow-remote-http to override (NOT recommended).",
            addr
        );
    }

    // ── Session/audit key: load or generate-and-persist with 0600. ─────────
    let key = load_or_create_key(&cli.session_key_file)?;

    let policy: SecurityPolicy = wyrtloom_config::load(&cli.config)
        .map(|c| c.security_policy())
        .unwrap_or_else(|_| SecurityPolicy::deny_all());

    // ── Provider + task profile for the /execute route, from [provider]. ───
    // Built from the same wyrtloom.toml [provider] table the serial circuit
    // uses: base_url (validated at construction, SSRF-guarded) and model. A
    // missing/unusable provider disables execution (503) rather than falling
    // back silently.
    let (provider, profile): (Option<Arc<dyn LlmProvider>>, Option<TaskProfile>) =
        match wyrtloom_config::load(&cli.config) {
            Ok(cfg) if !cfg.provider.base_url.trim().is_empty() => {
                let base_url = cfg.provider.base_url.clone();
                let model = cfg.provider.model.clone();
                match OllamaProvider::new(base_url) {
                    Ok(provider) => {
                        let mut profile = TaskProfile::default_v01();
                        profile.model = model.clone();
                        profile.provider = cfg.provider.name.clone();
                        (
                            Some(Arc::new(provider) as Arc<dyn LlmProvider>),
                            Some(profile),
                        )
                    }
                    Err(e) => {
                        eprintln!("[boot] provider not usable, execution disabled: {e}");
                        (None, None)
                    }
                }
            }
            _ => (None, None),
        };
    // ── Persistence + plugins. ─────────────────────────────────────────────
    let store: Arc<dyn PersistenceProvider> =
        Arc::new(SqliteStore::open(&cli.store).context("opening persistence store")?);
    let users: Arc<dyn UserDirectory> =
        Arc::new(UserStore::new(store.clone()).context("initialising user directory")?);

    // ── One-shot provisioning subcommands (perform, then exit). ────────────
    //
    // Provisioning is a SECOND, short-lived process that writes only to the
    // persistence store (`store.db`); it emits no audit entries. It therefore
    // deliberately builds the `SecurityModule` WITHOUT an audit file: attaching
    // the audit file here would open a second appender on the same JSONL (and
    // re-read/re-anchor the whole chain) while a server might be running,
    // risking an audit-chain fork. Run provisioning only while the server is
    // STOPPED — the bootstrap single-use guarantee and the audit chain assume a
    // single writer to `store.db` / the audit file.
    if cli.issue_bootstrap_key || cli.create_admin.is_some() {
        // Keyed but audit-file-less: self_check still validates key entropy and
        // structure, but no second appender is opened on the audit JSONL.
        let security = SecurityModule::with_key(key, policy);
        security
            .self_check()
            .map_err(|e| anyhow::anyhow!("security self-check failed: {e}"))?;
        return run_provisioning(&cli, store, users).await;
    }

    // ── Server path only: keyed + mandatory audit file (fail closed). ──────
    let audit_file = cli
        .audit_file
        .as_deref()
        .context("--audit-file is required to serve (the audit log is mandatory and fails closed)")?;
    // The audit chain's high-water mark (signed entry count + chain head) is
    // kept in the persistence store — a different file from the audit JSONL —
    // so a log whose newest entries were dropped is refused at startup.
    let anchor = PersistenceAuditAnchor::new(store.clone(), AUDIT_ANCHOR_ID)
        .map_err(|e| anyhow::anyhow!("initialising audit anchor: {e}"))?;
    let enrollment = if cli.audit_anchor_enroll {
        AnchorEnrollment::EnrollExisting
    } else {
        AnchorEnrollment::Strict
    };
    let security = SecurityModule::with_key(key, policy)
        .with_audit_file(audit_file)
        .map_err(|e| anyhow::anyhow!("audit file is mandatory and could not be opened: {e}"))?
        .with_audit_anchor(Arc::new(anchor), enrollment)
        .map_err(|e| {
            anyhow::anyhow!(
                "audit anchor check failed, refusing to serve: {e}. \
                 If this audit file predates anchoring, start once with --audit-anchor-enroll."
            )
        })?;
    security
        .self_check()
        .map_err(|e| anyhow::anyhow!("security self-check failed: {e}"))?;
    // Defence-in-depth: `with_audit_file` already verifies the chain on load and
    // fails closed, but verify again explicitly at startup so a tampered/forked
    // audit file aborts the server rather than silently continuing.
    security
        .verify_chain()
        .map_err(|e| anyhow::anyhow!("audit chain verification failed at startup, refusing to serve: {e}"))?;
    security
        .verify_anchor()
        .map_err(|e| anyhow::anyhow!("audit anchor verification failed at startup, refusing to serve: {e}"))?;
    let audit_len = security.audit_log_snapshot().len();
    eprintln!("audit chain and anchor verified, {audit_len} entries");

    let clients: Arc<dyn ClientAuthScheme> =
        Arc::new(TofuClientAuth::new(store.clone()).context("initialising client auth")?);
    let board: Arc<dyn KanbanBoard> =
        Arc::new(SqliteKanbanBoard::open(&cli.kanban_db).context("opening kanban board")?);
    // The composition root is the only place that names the concrete logger
    // plugin; the rest of the app holds it behind the `CallLogger` trait.
    let logger: Option<Arc<dyn CallLogger>> = match &cli.logger_db {
        Some(p) => Some(Arc::new(
            SqliteCallLogger::open(p).context("opening logger db")?,
        )),
        None => None,
    };

    let app_state = AppState {
        inner: Arc::new(Inner {
            store,
            users,
            clients,
            board,
            provider,
            profile: match &profile {
                Some(p) => p.clone(),
                // Unreachable in practice: `provider` and `profile` are always
                // Some together. Defensive default so the field is never unset.
                None => TaskProfile::default_v01(),
            },
            exec_semaphore: Arc::new(Semaphore::new(2)),
            security: Arc::new(security),
            logger,
            // Cap concurrent argon2 verifications to the CPU count (min 1).
            auth_semaphore: Arc::new(Semaphore::new(num_cpus())),
            // 5-token burst, refilling 1 token/sec per IP for /login + /enroll.
            rate_limiter: Arc::new(RateLimiter::new(5.0, 1.0)),
            config_path: cli.config.clone(),
        }),
    };
    app_state
        .ensure_collections()
        .map_err(|e| anyhow::anyhow!("ensuring revocation collection: {e}"))?;

    // ── Build the typed, default-deny router (asserts gating at startup). ──
    let table = routes::route_table();
    let router = routes::build_router(app_state.clone(), table);

    // ── Exact-origin CORS (never Any/mirror). ──────────────────────────────
    let cors = build_cors(&cli.cors_origin)?;

    let app = router.layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
            // Defence-in-depth security response headers on EVERY response. These
            // blunt the documented residual ("XSS could USE the non-extractable
            // key") and clickjacking, even though this crate ships no UI of its
            // own — any SPA/client served alongside it inherits the protection.
            // `overriding` so these win over anything a handler might set.
            .layer(SetResponseHeaderLayer::overriding(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    "default-src 'self'; script-src 'self'; object-src 'none'; \
                     base-uri 'none'; frame-ancestors 'none'",
                ),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ))
            .layer(cors),
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    eprintln!("wyrtloom-dashboard-api listening on http://{addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")?;
    Ok(())
}

/// Execute a one-shot provisioning subcommand (`--issue-bootstrap-key` or
/// `--create-admin`) against the persistence store, then return so the process
/// exits. Provisioning writes no audit entries and must run only while the
/// server is stopped (single-writer assumption — see `run`).
async fn run_provisioning(
    cli: &Cli,
    store: Arc<dyn PersistenceProvider>,
    users: Arc<dyn UserDirectory>,
) -> Result<()> {
    if cli.issue_bootstrap_key {
        // issue_bootstrap_key is a concrete TofuClientAuth capability, not part of
        // the ClientAuthScheme contract; the composition root may name the type.
        let scheme = TofuClientAuth::new(store.clone()).context("client auth")?;
        let key = scheme
            .issue_bootstrap_key()
            .map_err(|e| anyhow::anyhow!("issuing bootstrap key: {e}"))?;
        println!("{key}");
        eprintln!("[provision] single-use bootstrap key issued — give it to one client for /api/enroll");
        return Ok(());
    }
    if let Some(username) = &cli.create_admin {
        let password = std::env::var("WYRTLOOM_ADMIN_PASSWORD")
            .context("set WYRTLOOM_ADMIN_PASSWORD to the new admin's password")?;
        // Roles are explicit with NO hierarchy (Admin does not imply Viewer), so a
        // bootstrap admin is granted all three roles to be fully operational.
        match users.create(NewUser {
            username: username.clone(),
            password,
            roles: vec![Role::Viewer, Role::Operator, Role::Admin],
        }) {
            Ok(_) => eprintln!("[provision] admin user '{username}' created"),
            Err(AuthError::AlreadyExists) => {
                eprintln!("[provision] admin user '{username}' already exists")
            }
            Err(e) => return Err(anyhow::anyhow!("creating admin: {e}")),
        }
        return Ok(());
    }
    Ok(())
}

/// 127.0.0.0/8 or ::1 are treated as loopback.
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 127,
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Build an exact-origin CORS layer. With no origins, cross-origin requests are
/// denied entirely. Credentials are enabled only alongside an explicit list —
/// never with a wildcard or request-mirroring origin.
fn build_cors(origins: &[String]) -> Result<CorsLayer> {
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            "x-wyrtloom-client".parse().unwrap(),
            "x-wyrtloom-timestamp".parse().unwrap(),
            "x-wyrtloom-nonce".parse().unwrap(),
            "x-wyrtloom-signature".parse().unwrap(),
        ]);
    if origins.is_empty() {
        // No cross-origin access. (Same-origin SPAs still work.)
        return Ok(base.allow_origin(AllowOrigin::list([])));
    }
    let mut parsed = Vec::with_capacity(origins.len());
    for o in origins {
        let hv: HeaderValue = o
            .parse()
            .with_context(|| format!("invalid --cors-origin '{o}'"))?;
        parsed.push(hv);
    }
    Ok(base
        .allow_origin(AllowOrigin::list(parsed))
        .allow_credentials(true))
}

/// Load a 32-byte key from `path`, or generate one and persist it with 0600
/// permissions if the file does not yet exist.
fn load_or_create_key(path: &str) -> Result<[u8; 32]> {
    use std::io::Write;
    match std::fs::read(path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("session key file must be exactly 32 bytes"))?;
            if key == [0u8; 32] {
                bail!("session key file is all-zero (invalid)");
            }
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = state::random_bytes::<32>();
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(path)
                .with_context(|| format!("creating session key file '{path}'"))?;
            f.write_all(&key)
                .with_context(|| format!("writing session key file '{path}'"))?;
            // Defensively re-apply 0600 in case of a permissive umask on create.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(key)
        }
        Err(e) => Err(anyhow::Error::new(e).context("reading session key file")),
    }
}

/// Available parallelism, clamped to at least 1.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}
