//! Security middleware: client-signature auth, user-session auth, and RBAC.
//!
//! The router is **default-deny and typed**: every route is registered with an
//! explicit [`RequiredAuth`]. There is no "open" tier — a route is either
//! [`RequiredAuth::PublicBootstrap`] (enroll only, still rate-limited),
//! [`RequiredAuth::ClientOnly`] (client signature but no user session — login
//! only), or [`RequiredAuth::Role`] (client signature AND a verified user
//! session AND a role check). A startup assertion + a test guarantee no route
//! escapes this classification.
//!
//! Verification order for a `Role` route (security-audit mandated):
//!   1. client signature (X-Wyrtloom-* headers) over canonical request bytes,
//!      then stamp the canonical bytes into the tamper-evident audit chain;
//!   2. session: parse bearer token, reject if `now > exp` BEFORE any MAC work,
//!      reject if the nonce is revoked, verify the stamp, then RE-FETCH the user
//!      and use its *current* roles + reject if `!active`;
//!   3. RBAC: compare current roles to the route's required role.

use std::net::SocketAddr;

use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use sha2::{Digest, Sha256};

use wyrtloom_core::client_auth::PresentedClientAuth;
use wyrtloom_core::users::{Role, User};

// Build the signed request bytes from the core contract, not a concrete scheme
// plugin — the canonical encoding is shared agreement, so it lives in core.
use wyrtloom_core::client_auth::canonical_request as canonicalize;

use crate::session::{self, SessionPayload};
use crate::state::{now_unix_checked, AppState, RevocationStatus, MAX_BODY_BYTES};

/// Per-route authentication requirement. Every route declares exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredAuth {
    /// First-contact enrollment. No client signature, no session. Rate-limited.
    PublicBootstrap,
    /// Client signature required, but no user session yet (the login endpoint).
    ClientOnly,
    /// Client signature + verified user session + this role.
    Role(Role),
}

/// Header names for the client-auth scheme.
const H_CLIENT: &str = "x-wyrtloom-client";
const H_TIMESTAMP: &str = "x-wyrtloom-timestamp";
const H_NONCE: &str = "x-wyrtloom-nonce";
const H_SIGNATURE: &str = "x-wyrtloom-signature";

/// The verified identity threaded into handlers via request extensions for
/// `Role` routes. For `ClientOnly` routes only `client_id` is set.
#[derive(Clone)]
pub struct AuthContext {
    pub client_id: String,
    /// Present only after a successful session verification.
    pub user: Option<User>,
    /// The verified session payload (carries the nonce + exp needed for logout
    /// revocation). Present only for `Role` routes with a valid session.
    pub session: Option<SessionPayload>,
    /// The exact payload bytes the session stamp was verified against. Threaded
    /// so logout can invalidate the precise stamp without re-deriving (and thus
    /// risking) the serialisation. Present alongside `session`.
    pub session_bytes: Option<Vec<u8>>,
}

/// Axum middleware factory: returns a layer enforcing `required` auth.
///
/// Because axum's `from_fn_with_state` needs a plain async fn, we capture
/// `required` by building one closure per route via `from_fn`.
pub async fn enforce(
    required: RequiredAuth,
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    match enforce_inner(required, &state, headers, request).await {
        Ok(req) => next.run(req).await,
        Err(resp) => *resp,
    }
}

/// Boxed rejection response. Boxing keeps the `Result` `Err` variant small (the
/// happy path threads a full `Request`), satisfying `clippy::result_large_err`.
type Reject = Box<Response>;

/// Best-effort client IP for rate-limiting. Falls back to a constant bucket key
/// when no connect-info is available (e.g. some test harnesses), which simply
/// shares one bucket — still bounded, never a bypass.
fn peer_ip(request: &Request) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn enforce_inner(
    required: RequiredAuth,
    state: &AppState,
    headers: HeaderMap,
    request: Request,
) -> Result<Request, Reject> {
    // Rate-limit the sensitive credential endpoints per source IP, BEFORE doing
    // any expensive work (argon2, signature verify). Applies to both the
    // bootstrap (enroll) and client-only (login) tiers.
    if matches!(
        required,
        RequiredAuth::PublicBootstrap | RequiredAuth::ClientOnly
    ) {
        let ip = peer_ip(&request);
        if !state.inner.rate_limiter.check(&ip).await {
            return Err(status(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
        }
    }

    // ── Bootstrap tier: no client signature, no session. ──────────────────
    if matches!(required, RequiredAuth::PublicBootstrap) {
        // Re-attach an empty AuthContext so handlers can rely on the extension.
        let mut request = request;
        request.extensions_mut().insert(AuthContext {
            client_id: String::new(),
            user: None,
            session: None,
            session_bytes: None,
        });
        return Ok(request);
    }

    let method = request.method().to_string();
    // Sign over path AND query so query parameters are integrity-protected, not
    // just the path. The client signs the identical path+query string it sends.
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    // Split into parts + body so we can buffer/measure the body under the limit
    // and rebuild the request for downstream handlers.
    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| status(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"))?;

    // ── 1. Client-signature layer (all non-bootstrap routes). ─────────────
    let client_id = verify_client(state, &headers, &method, &path, &body_bytes)?;

    // ── 2/3. Session + RBAC (only for Role routes). ───────────────────────
    let (user, session, session_bytes) = match required {
        RequiredAuth::ClientOnly => (None, None, None),
        RequiredAuth::Role(role) => {
            let (user, payload, payload_bytes) = verify_session(state, &headers)?;
            authorize(state, &user, role)?;
            // Record the granted access — public identifiers only (client id,
            // user id, method+path); never the token, body, or any secret.
            state.inner.security.record_decision(
                true,
                format!(
                    "grant client={} user={} {} {}",
                    client_id, user.id, method, path
                ),
            );
            (Some(user), Some(payload), Some(payload_bytes))
        }
        RequiredAuth::PublicBootstrap => unreachable!("handled above"),
    };

    // Rebuild the request with the buffered body and the verified identity.
    let mut request = Request::from_parts(parts, Body::from(body_bytes));
    request.extensions_mut().insert(AuthContext {
        client_id,
        user,
        session,
        session_bytes,
    });
    Ok(request)
}

/// Layer 1: verify the client signature and stamp the canonical bytes.
fn verify_client(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, Reject> {
    let client_id = header(headers, H_CLIENT)
        .ok_or_else(|| status(StatusCode::UNAUTHORIZED, "missing client auth"))?;
    let ts_str = header(headers, H_TIMESTAMP)
        .ok_or_else(|| status(StatusCode::UNAUTHORIZED, "missing client auth"))?;
    let nonce = header(headers, H_NONCE)
        .ok_or_else(|| status(StatusCode::UNAUTHORIZED, "missing client auth"))?;
    let sig_hex = header(headers, H_SIGNATURE)
        .ok_or_else(|| status(StatusCode::UNAUTHORIZED, "missing client auth"))?;

    let timestamp: i64 = ts_str
        .parse()
        .map_err(|_| status(StatusCode::UNAUTHORIZED, "bad client auth"))?;
    let signature = hex_decode(&sig_hex)
        .ok_or_else(|| status(StatusCode::UNAUTHORIZED, "bad client auth"))?;

    let body_sha256 = Sha256::digest(body);
    let canonical = canonicalize(method, path, &body_sha256, &client_id, timestamp, &nonce);

    let presented = PresentedClientAuth {
        client_id: client_id.clone(),
        canonical_request: canonical.clone(),
        signature,
        timestamp,
        nonce,
    };

    // SINGLE-INSTANCE ASSUMPTION: `verify` consults a process-local nonce replay
    // cache. A replay is only rejected if the original request hit THIS process,
    // so the API must run as a single instance / single writer. Horizontal
    // scaling would require moving the replay cache into the shared store behind a
    // compare-and-set (insert-if-absent). See README "single-instance assumption".
    match state.inner.clients.verify(&presented) {
        Ok(identity) => {
            // Stamp the canonical bytes into the tamper-evident audit chain.
            // Detail carries no secrets — only the public client id and path.
            state.inner.security.stamp(&canonical);
            Ok(identity.client_id)
        }
        Err(_) => Err(status(StatusCode::UNAUTHORIZED, "client auth failed")),
    }
}

/// Layers 2: verify the bearer session token. Order is load-bearing:
/// expiry → revocation → stamp validity → role re-fetch + active check.
fn verify_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(User, SessionPayload, Vec<u8>), Reject> {
    let bearer = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| status(StatusCode::UNAUTHORIZED, "missing session"))?;

    let (payload, payload_bytes, stamp) =
        session::parse(bearer).map_err(|_| status(StatusCode::UNAUTHORIZED, "bad session"))?;

    // Reject expired tokens BEFORE spending MAC work or hitting the store
    // (audit-mandated ordering: exp before is_valid). A broken/rolled-back clock
    // fails closed — we cannot prove freshness, so we reject.
    let now = now_unix_checked()
        .ok_or_else(|| status(StatusCode::UNAUTHORIZED, "session expired"))?;
    if now > payload.exp_unix {
        return Err(status(StatusCode::UNAUTHORIZED, "session expired"));
    }

    // Cryptographic validity of the stamp over the exact payload bytes. This is
    // checked BEFORE the revocation lookup so an unauthenticated caller (who can
    // forge the base64 payload but not the HMAC) cannot use distinct error
    // responses to probe which nonces are on the durable denylist.
    if !state.inner.security.is_valid(&stamp, &payload_bytes) {
        return Err(status(StatusCode::UNAUTHORIZED, "session invalid"));
    }

    // Durable revocation denylist (logout / forced invalidation). FAIL CLOSED on
    // an uncertain store read — a transient error must not let a revoked token
    // through.
    match state.revocation_status(&payload.nonce) {
        RevocationStatus::NotRevoked => {}
        RevocationStatus::Revoked => {
            return Err(status(StatusCode::UNAUTHORIZED, "session invalid"));
        }
        RevocationStatus::Unknown => {
            return Err(status(
                StatusCode::SERVICE_UNAVAILABLE,
                "revocation status unavailable",
            ));
        }
    }

    // Re-fetch the user and trust its CURRENT roles/active — NEVER the token's.
    let user = state
        .inner
        .users
        .get(&payload.user_id)
        .map_err(|_| status(StatusCode::UNAUTHORIZED, "unknown user"))?;
    if !user.active {
        return Err(status(StatusCode::UNAUTHORIZED, "user disabled"));
    }
    Ok((user, payload, payload_bytes))
}

/// Layer 3: RBAC. Admin implies Operator implies Viewer is NOT assumed — the
/// directory stores explicit roles, so a user must hold the exact required role.
/// (Login mints whatever roles the directory returns; operators grant Viewer
/// alongside Operator/Admin as needed.)
fn authorize(state: &AppState, user: &User, required: Role) -> Result<(), Reject> {
    if user.has_role(required) {
        Ok(())
    } else {
        // No secrets in detail — only the public user id and the denied role.
        state.inner.security.record_decision(
            false,
            format!("rbac deny user={} role={:?}", user.id, required),
        );
        Err(status(StatusCode::FORBIDDEN, "forbidden"))
    }
}

// ---- helpers ---------------------------------------------------------------

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn status(code: StatusCode, msg: &str) -> Reject {
    let body = serde_json::json!({ "error": msg }).to_string();
    Box::new(
        Response::builder()
            .status(code)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("static response builds"),
    )
}

// hex decoding is shared from the `session` module to keep a single decoder for
// all security-sensitive paths (signature + stamp).
use crate::session::hex_decode;
