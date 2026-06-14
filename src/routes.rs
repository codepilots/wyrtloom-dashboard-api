//! Endpoint handlers and the typed, default-deny router.
//!
//! Every route is declared in [`route_table`] with its method, path, and
//! [`RequiredAuth`]. [`build_router`] consumes that single table to attach the
//! correct auth middleware to each route — there is no path that bypasses the
//! table, so the default is deny. [`assert_all_routes_gated`] (called at
//! startup and in tests) fails if any route is left without an explicit gate
//! other than the bootstrap enroll endpoint.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put, MethodRouter};
use axum::{Extension, Json, Router};

use serde::{Deserialize, Serialize};
use serde_json::json;

use wyrtloom_core::client_auth::EnrollmentRequest;
use wyrtloom_core::kanban::{BlockReason, BlockedBy, NewTask, TaskQuery, TaskState};
use wyrtloom_core::users::Role;

use crate::auth::{enforce, AuthContext, RequiredAuth};
use crate::session::{self, SessionPayload};
use crate::state::{now_unix, AppState, SESSION_TTL_SECS};

/// One row of the route table: method, path, required auth, and the bare
/// handler wrapped as a `MethodRouter`.
pub struct RouteSpec {
    pub method: &'static str,
    pub path: &'static str,
    pub auth: RequiredAuth,
    pub handler: MethodRouter<AppState>,
}

/// The single source of truth for every registered route and its auth gate.
pub fn route_table() -> Vec<RouteSpec> {
    vec![
        RouteSpec {
            method: "POST",
            path: "/api/enroll",
            auth: RequiredAuth::PublicBootstrap,
            handler: post(enroll),
        },
        RouteSpec {
            method: "POST",
            path: "/api/login",
            auth: RequiredAuth::ClientOnly,
            handler: post(login),
        },
        RouteSpec {
            method: "POST",
            path: "/api/logout",
            auth: RequiredAuth::Role(Role::Viewer),
            handler: post(logout),
        },
        RouteSpec {
            method: "GET",
            path: "/api/board",
            auth: RequiredAuth::Role(Role::Viewer),
            handler: get(board),
        },
        RouteSpec {
            method: "GET",
            path: "/api/tasks/:id",
            auth: RequiredAuth::Role(Role::Viewer),
            handler: get(get_task),
        },
        RouteSpec {
            method: "POST",
            path: "/api/tasks",
            auth: RequiredAuth::Role(Role::Operator),
            handler: post(create_task),
        },
        RouteSpec {
            method: "POST",
            path: "/api/tasks/:id/transition",
            auth: RequiredAuth::Role(Role::Operator),
            handler: post(transition_task),
        },
        RouteSpec {
            method: "POST",
            path: "/api/tasks/:id/claim",
            auth: RequiredAuth::Role(Role::Operator),
            handler: post(claim_task),
        },
        RouteSpec {
            method: "POST",
            path: "/api/tasks/:id/block",
            auth: RequiredAuth::Role(Role::Operator),
            handler: post(block_task),
        },
        RouteSpec {
            method: "GET",
            path: "/api/config",
            auth: RequiredAuth::Role(Role::Admin),
            handler: get(get_config),
        },
        RouteSpec {
            method: "PUT",
            path: "/api/config",
            auth: RequiredAuth::Role(Role::Admin),
            handler: put(put_config),
        },
        RouteSpec {
            method: "GET",
            path: "/api/plugins",
            auth: RequiredAuth::Role(Role::Viewer),
            handler: get(plugins),
        },
        RouteSpec {
            method: "GET",
            path: "/api/logs",
            auth: RequiredAuth::Role(Role::Admin),
            handler: get(logs),
        },
        RouteSpec {
            method: "GET",
            path: "/api/audit",
            auth: RequiredAuth::Role(Role::Admin),
            handler: get(audit),
        },
    ]
}

/// Assert that every route carries an explicit auth gate and that the ONLY
/// route reachable without a verified client+session is the bootstrap enroll
/// endpoint. Panics on violation (called at startup; also exercised by a test).
pub fn assert_all_routes_gated(table: &[RouteSpec]) {
    for spec in table {
        match spec.auth {
            RequiredAuth::PublicBootstrap => {
                assert_eq!(
                    spec.path, "/api/enroll",
                    "only /api/enroll may be PublicBootstrap; {} {} is not",
                    spec.method, spec.path
                );
            }
            RequiredAuth::ClientOnly => {
                assert_eq!(
                    spec.path, "/api/login",
                    "only /api/login may be ClientOnly; {} {} is not",
                    spec.method, spec.path
                );
            }
            RequiredAuth::Role(_) => {
                // Role routes require both client + session auth — acceptable.
            }
        }
    }
}

/// Build the typed, default-deny router from the route table, attaching the
/// per-route auth middleware. Each path's routes are merged so axum sees a
/// single method-router per path.
pub fn build_router(state: AppState, table: Vec<RouteSpec>) -> Router {
    assert_all_routes_gated(&table);

    let mut router: Router<AppState> = Router::new();
    for spec in table {
        let auth = spec.auth;
        // Per-route middleware capturing this route's RequiredAuth.
        let gated = spec.handler.route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            move |st, headers, request, next| enforce(auth, st, headers, request, next),
        ));
        router = router.route(spec.path, gated);
    }
    router.with_state(state)
}

// ---------------------------------------------------------------------------
// Request/response DTOs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EnrollBody {
    pub api_key: String,
    pub client_name: String,
    pub public_key_b64: String,
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateTaskBody {
    pub title: String,
    #[serde(default)]
    pub depends_on: Vec<uuid::Uuid>,
}

#[derive(Deserialize)]
pub struct TransitionBody {
    pub to: TaskState,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct BlockBody {
    pub reason: String,
}

#[derive(Deserialize)]
pub struct BoardParams {
    /// Comma-separated state names, e.g. `Todo,Running`.
    pub states: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn enroll(State(state): State<AppState>, Json(body): Json<EnrollBody>) -> Response {
    use base64::Engine;
    let public_key = match base64::engine::general_purpose::STANDARD.decode(&body.public_key_b64) {
        Ok(b) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "public_key_b64 is not valid base64"),
    };
    let req = EnrollmentRequest {
        api_key: body.api_key,
        client_name: body.client_name,
        public_key,
    };
    match state.inner.clients.enroll(req) {
        Ok(cred) => (StatusCode::OK, Json(cred)).into_response(),
        // Do not leak which step failed (bad key vs. bad name vs. pin) beyond a
        // generic 401/400 — credential errors are 401.
        Err(_) => err(StatusCode::UNAUTHORIZED, "enrollment rejected"),
    }
}

async fn login(State(state): State<AppState>, Json(body): Json<LoginBody>) -> Response {
    // Cap concurrent argon2 work so a login burst cannot exhaust CPU.
    let _permit = state.inner.auth_semaphore.clone().acquire_owned().await;

    let users = state.inner.users.clone();
    let username = body.username.clone();
    let password = body.password.clone();
    // argon2 verify is blocking/CPU-bound — run it off the async reactor.
    let result =
        tokio::task::spawn_blocking(move || users.authenticate(&username, &password)).await;

    match result {
        Ok(Ok(user)) => {
            let nonce = mint_nonce();
            let exp_unix = now_unix() + SESSION_TTL_SECS;
            let payload = SessionPayload {
                user_id: user.id.clone(),
                roles: user.roles.clone(),
                exp_unix,
                nonce,
            };
            let token = session::mint(&state.inner.security, &payload);
            state
                .inner
                .security
                .record_decision(true, format!("login ok user={}", user.id));
            (StatusCode::OK, Json(json!({ "token": token, "exp_unix": exp_unix }))).into_response()
        }
        Ok(Err(_)) => {
            state
                .inner
                .security
                .record_decision(false, "login failed".to_string());
            err(StatusCode::UNAUTHORIZED, "invalid credentials")
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "auth task failed"),
    }
}

async fn logout(State(state): State<AppState>, Extension(ctx): Extension<AuthContext>) -> Response {
    // The middleware already verified the session and threaded the payload, so we
    // have the exact nonce + expiry to revoke. Adding the nonce to the durable
    // denylist makes the token unusable on every future request; we also
    // `invalidate` the stamp so the SecurityModule's in-process revocation set
    // short-circuits it too. The denylist record is pruned once `exp_unix`
    // passes, keeping the collection bounded.
    let (Some(payload), Some(payload_bytes)) = (ctx.session, ctx.session_bytes) else {
        return err(StatusCode::UNAUTHORIZED, "no session");
    };
    if state.revoke(&payload.nonce, payload.exp_unix).is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "revocation failed");
    }
    // Best-effort in-process belt-and-braces: invalidate the exact stamp using
    // the precise payload bytes the middleware verified (not a re-serialisation,
    // which could drift). The durable denylist above is the authoritative,
    // cross-restart revocation; this only short-circuits the in-process MAC path.
    let stamp = state.inner.security.stamp(&payload_bytes);
    state.inner.security.invalidate(stamp);
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

async fn board(
    State(state): State<AppState>,
    Query(params): Query<BoardParams>,
) -> Response {
    let states = match parse_states(params.states.as_deref()) {
        Ok(s) => s,
        Err(msg) => return err(StatusCode::BAD_REQUEST, &msg),
    };
    let query = TaskQuery {
        states,
        ..Default::default()
    };
    match state.inner.board.list(&query) {
        Ok(tasks) => {
            // Group by state for a frontend-agnostic board shape.
            let mut grouped: std::collections::BTreeMap<String, Vec<_>> = Default::default();
            for t in tasks {
                grouped.entry(t.state.to_string()).or_default().push(t);
            }
            (StatusCode::OK, Json(json!({ "columns": grouped }))).into_response()
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "board listing failed"),
    }
}

async fn get_task(State(state): State<AppState>, Path(id): Path<uuid::Uuid>) -> Response {
    match state.inner.board.get(id) {
        Ok(task) => (StatusCode::OK, Json(task)).into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "task not found"),
    }
}

async fn create_task(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<CreateTaskBody>,
) -> Response {
    let actor = actor_of(&ctx);
    let new = NewTask {
        title: body.title,
        actor,
        depends_on: body.depends_on,
    };
    match state.inner.board.create(new) {
        Ok(id) => (StatusCode::CREATED, Json(json!({ "id": id }))).into_response(),
        Err(_) => err(StatusCode::BAD_REQUEST, "task creation failed"),
    }
}

async fn transition_task(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<TransitionBody>,
) -> Response {
    let actor = actor_of(&ctx);
    match state.inner.board.transition(id, body.to, actor, body.reason) {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(_) => err(StatusCode::BAD_REQUEST, "transition rejected"),
    }
}

async fn claim_task(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    let actor = actor_of(&ctx);
    match state.inner.board.claim(id, actor) {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(_) => err(StatusCode::CONFLICT, "claim rejected"),
    }
}

async fn block_task(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    Extension(ctx): Extension<AuthContext>,
    Json(body): Json<BlockBody>,
) -> Response {
    let actor = actor_of(&ctx);
    let reason = BlockReason {
        reason: body.reason,
        blocked_by: BlockedBy::Human(actor.clone()),
    };
    match state.inner.board.block(id, actor, reason) {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(_) => err(StatusCode::BAD_REQUEST, "block rejected"),
    }
}

async fn get_config(State(state): State<AppState>) -> Response {
    // Server-config path only — never a caller-supplied path (no traversal).
    match wyrtloom_config::load(&state.inner.config_path) {
        Ok(cfg) => match config_to_json(&cfg) {
            Ok(v) => (StatusCode::OK, Json(v)).into_response(),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "config serialise failed"),
        },
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "config load failed"),
    }
}

async fn put_config(State(state): State<AppState>, body: String) -> Response {
    // Parse + validate the submitted TOML, then save to the fixed server path.
    // Internal parser/validator detail is logged server-side (audit log) but
    // never echoed to the client — the response stays generic.
    let cfg = match wyrtloom_config::from_str(&body) {
        Ok(c) => c,
        Err(e) => {
            state
                .inner
                .security
                .record_decision(false, format!("config parse rejected: {e}"));
            return err(StatusCode::BAD_REQUEST, "invalid configuration");
        }
    };
    if let Err(e) = wyrtloom_config::validate(&cfg) {
        state
            .inner
            .security
            .record_decision(false, format!("config validation rejected: {e}"));
        return err(StatusCode::BAD_REQUEST, "invalid configuration");
    }
    match wyrtloom_config::save(&state.inner.config_path, &cfg) {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "config save failed"),
    }
}

async fn plugins(State(state): State<AppState>) -> Response {
    match wyrtloom_config::load(&state.inner.config_path) {
        Ok(cfg) => {
            let manifests: Vec<_> = cfg
                .plugins
                .iter()
                .map(|p| {
                    json!({
                        "name": p.manifest.name,
                        "version": p.manifest.version.to_string(),
                        "class": format!("{:?}", p.manifest.class),
                        "enabled": p.enabled,
                        "capabilities": format!("{:?}", p.manifest.capabilities),
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "plugins": manifests }))).into_response()
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "config load failed"),
    }
}

async fn logs(State(state): State<AppState>) -> Response {
    match &state.inner.logger {
        Some(logger) => match logger.all_logs() {
            Ok(entries) => (StatusCode::OK, Json(json!({ "logs": entries }))).into_response(),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "log read failed"),
        },
        None => (StatusCode::OK, Json(json!({ "logs": [] }))).into_response(),
    }
}

async fn audit(State(state): State<AppState>) -> Response {
    let snapshot = state.inner.security.audit_log_snapshot();
    let chain_ok = state.inner.security.verify_chain().is_ok();
    (
        StatusCode::OK,
        Json(json!({ "chain_verified": chain_ok, "entries": snapshot })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ConfigView {
    file_read_prefixes: Vec<String>,
    file_write_prefixes: Vec<String>,
    network_allowlist: Vec<String>,
    allow_shell: bool,
    allow_git: bool,
}

fn config_to_json(cfg: &wyrtloom_config::Config) -> Result<serde_json::Value, serde_json::Error> {
    // Re-serialise to the on-disk TOML form so the client can round-trip it back
    // through PUT, plus a structured security view.
    let toml = wyrtloom_config::to_string(cfg).unwrap_or_default();
    let view = ConfigView {
        file_read_prefixes: cfg.security.file_read_prefixes.clone(),
        file_write_prefixes: cfg.security.file_write_prefixes.clone(),
        network_allowlist: cfg.security.network_allowlist.clone(),
        allow_shell: cfg.security.allow_shell,
        allow_git: cfg.security.allow_git,
    };
    Ok(json!({ "toml": toml, "security": serde_json::to_value(view)? }))
}

fn parse_states(raw: Option<&str>) -> Result<Option<Vec<TaskState>>, String> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let mut out = Vec::new();
    for tok in raw.split(',') {
        let tok = tok.trim();
        let state = match tok {
            "Backlog" => TaskState::Backlog,
            "Todo" => TaskState::Todo,
            "Ready" => TaskState::Ready,
            "Running" => TaskState::Running,
            "Blocked" => TaskState::Blocked,
            "Done" => TaskState::Done,
            "Archived" => TaskState::Archived,
            other => return Err(format!("unknown state '{other}'")),
        };
        out.push(state);
    }
    Ok(Some(out))
}

/// Derive a kanban actor id from the verified user.
fn actor_of(ctx: &AuthContext) -> String {
    match &ctx.user {
        Some(u) => format!("human:{}", u.id),
        None => "human:unknown".to_string(),
    }
}

/// Generate a per-session nonce from the OS CSPRNG.
fn mint_nonce() -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::state::random_bytes::<16>())
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}
