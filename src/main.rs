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
use axum::http::{HeaderValue, Method};
use clap::Parser;
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use wyrtloom_core::client_auth::ClientAuthScheme;
use wyrtloom_core::kanban::KanbanBoard;
use wyrtloom_core::logger::CallLogger;
use wyrtloom_core::persistence::PersistenceProvider;
use wyrtloom_core::security::{SecurityModule, SecurityPolicy};
use wyrtloom_core::users::UserDirectory;

use plugin_kanban_sqlite::SqliteKanbanBoard;
use plugin_logger_sqlite::SqliteCallLogger;
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

    /// Tamper-evident audit JSONL file. REQUIRED — the server fails closed if
    /// this is not provided.
    #[arg(long)]
    audit_file: String,

    /// Exact allowed CORS origin (repeatable). Empty => no cross-origin access.
    #[arg(long = "cors-origin")]
    cors_origin: Vec<String>,

    /// Allow binding a non-loopback address over plain HTTP. DANGEROUS.
    #[arg(long)]
    insecure_allow_remote_http: bool,
}

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

    // ── Security module: keyed + mandatory audit file (fail closed). ───────
    let policy: SecurityPolicy = wyrtloom_config::load(&cli.config)
        .map(|c| c.security_policy())
        .unwrap_or_else(|_| SecurityPolicy::deny_all());
    let security = SecurityModule::with_key(key, policy)
        .with_audit_file(&cli.audit_file)
        .map_err(|e| anyhow::anyhow!("audit file is mandatory and could not be opened: {e}"))?;
    security
        .self_check()
        .map_err(|e| anyhow::anyhow!("security self-check failed: {e}"))?;

    // ── Persistence + plugins. ─────────────────────────────────────────────
    let store: Arc<dyn PersistenceProvider> =
        Arc::new(SqliteStore::open(&cli.store).context("opening persistence store")?);
    let users: Arc<dyn UserDirectory> =
        Arc::new(UserStore::new(store.clone()).context("initialising user directory")?);
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
