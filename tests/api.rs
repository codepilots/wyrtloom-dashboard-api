//! Integration tests for the dashboard API security middleware and endpoints.
//!
//! All offline: in-memory `SqliteStore` / `SqliteKanbanBoard`, an in-test
//! enrolled client (ed25519) and minted sessions, driven through axum's tower
//! `oneshot` harness — no real network.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use wyrtloom_clientauth_tofu::{canonicalize, TofuClientAuth};
use wyrtloom_core::client_auth::{ClientAuthScheme, EnrollmentRequest};
use wyrtloom_core::kanban::KanbanBoard;
use wyrtloom_core::persistence::PersistenceProvider;
use wyrtloom_core::security::{SecurityModule, SecurityPolicy};
use wyrtloom_core::users::{NewUser, Role, UserDirectory};

use plugin_kanban_sqlite::SqliteKanbanBoard;
use wyrtloom_store_sqlite::SqliteStore;
use wyrtloom_users::UserStore;

use wyrtloom_dashboard_api::{auth, routes, session, state};

use auth::RequiredAuth;
use state::{AppState, Inner, RateLimiter};

const TEST_KEY: [u8; 32] = [9u8; 32];

struct Harness {
    state: AppState,
    security: Arc<SecurityModule>,
    client_sk: SigningKey,
    client_id: String,
}

fn build_state() -> (AppState, Arc<SecurityModule>) {
    let store: Arc<dyn PersistenceProvider> = Arc::new(SqliteStore::in_memory().unwrap());
    let users: Arc<dyn UserDirectory> = Arc::new(UserStore::new(store.clone()).unwrap());
    let clients: Arc<dyn ClientAuthScheme> = Arc::new(TofuClientAuth::new(store.clone()).unwrap());
    let board: Arc<dyn KanbanBoard> = Arc::new(SqliteKanbanBoard::in_memory().unwrap());
    let security = Arc::new(SecurityModule::with_key(TEST_KEY, SecurityPolicy::permissive()));

    let inner = Inner {
        store,
        users,
        clients,
        board,
        security: security.clone(),
        logger: None,
        auth_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
        // Generous limiter so functional tests are not throttled.
        rate_limiter: Arc::new(RateLimiter::new(1000.0, 1000.0)),
        config_path: "wyrtloom.toml".to_string(),
    };
    let app_state = AppState {
        inner: Arc::new(inner),
    };
    app_state.ensure_collections().unwrap();
    (app_state, security)
}

impl Harness {
    fn new() -> Self {
        let (state, security) = build_state();

        // Enroll an in-test client via the scheme directly.
        let tofu = TofuClientAuth::new(state.inner.store.clone()).unwrap();
        let key = tofu.issue_bootstrap_key().unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        // Enroll through the SAME scheme instance the state uses so the pin lands
        // in the shared store.
        let cred = state
            .inner
            .clients
            .enroll(EnrollmentRequest {
                api_key: key,
                client_name: "test-spa".into(),
                public_key: sk.verifying_key().to_bytes().to_vec(),
            })
            .unwrap();

        Harness {
            state,
            security,
            client_sk: sk,
            client_id: cred.client_id,
        }
    }

    fn router(&self) -> axum::Router {
        routes::build_router(self.state.clone(), routes::route_table())
    }

    fn create_user(&self, username: &str, password: &str, roles: Vec<Role>) {
        self.state
            .inner
            .users
            .create(NewUser {
                username: username.into(),
                password: password.into(),
                roles,
            })
            .unwrap();
    }

    /// Build a request with valid client-signature headers over `body`.
    fn signed_request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        bearer: Option<&str>,
    ) -> Request<Body> {
        let ts = state::now_unix();
        let nonce = format!("n-{}-{}", path, rand::random::<u64>());
        let body_sha = Sha256::digest(body);
        let canonical = canonicalize(method, path, &body_sha, &self.client_id, ts, &nonce);
        let sig = self.client_sk.sign(&canonical);

        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("x-wyrtloom-client", &self.client_id)
            .header("x-wyrtloom-timestamp", ts.to_string())
            .header("x-wyrtloom-nonce", nonce)
            .header("x-wyrtloom-signature", hex(&sig.to_bytes()))
            .header("content-type", "application/json");
        if let Some(b) = bearer {
            builder = builder.header("authorization", format!("Bearer {b}"));
        }
        builder.body(Body::from(body.to_vec())).unwrap()
    }

    /// Mint a session token for `username` with the given roles + ttl.
    fn mint_token(&self, username: &str, roles: Vec<Role>, exp_unix: i64, nonce: &str) -> String {
        let payload = session::SessionPayload {
            user_id: username.into(),
            roles,
            exp_unix,
            nonce: nonce.into(),
        };
        session::mint(&self.security, &payload)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

async fn status_of(router: axum::Router, req: Request<Body>) -> StatusCode {
    router.oneshot(req).await.unwrap().status()
}

async fn body_json(router: axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_then_board_succeeds() {
    let h = Harness::new();
    h.create_user("alice", "pw-correct", vec![Role::Viewer]);

    // Login (ClientOnly): signed request, no bearer.
    let login_body = serde_json::to_vec(&serde_json::json!({
        "username": "alice", "password": "pw-correct"
    }))
    .unwrap();
    let req = h.signed_request("POST", "/api/login", &login_body, None);
    let (status, json) = body_json(h.router(), req).await;
    assert_eq!(status, StatusCode::OK, "login should succeed: {json:?}");
    let token = json["token"].as_str().unwrap().to_string();

    // Board (Role::Viewer): signed + bearer.
    let req = h.signed_request("GET", "/api/board", b"", Some(&token));
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn missing_token_is_401() {
    let h = Harness::new();
    // Signed client request but NO session bearer to a Role route.
    let req = h.signed_request("GET", "/api/board", b"", None);
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_client_signature_is_401() {
    let h = Harness::new();
    h.create_user("alice", "pw", vec![Role::Viewer]);
    let token = h.mint_token("alice", vec![Role::Viewer], state::now_unix() + 600, "nonce1");

    // Tamper the signature header.
    let mut req = h.signed_request("GET", "/api/board", b"", Some(&token));
    req.headers_mut()
        .insert("x-wyrtloom-signature", "00ff".parse().unwrap());
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn absent_client_signature_is_401() {
    let h = Harness::new();
    h.create_user("alice", "pw", vec![Role::Viewer]);
    let token = h.mint_token("alice", vec![Role::Viewer], state::now_unix() + 600, "nonce1");

    // Build a request with NO client headers at all.
    let req = Request::builder()
        .method("GET")
        .uri("/api/board")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn viewer_hitting_operator_route_is_403() {
    let h = Harness::new();
    h.create_user("vic", "pw", vec![Role::Viewer]);
    let login_body = serde_json::to_vec(&serde_json::json!({
        "username": "vic", "password": "pw"
    }))
    .unwrap();
    let req = h.signed_request("POST", "/api/login", &login_body, None);
    let (_, json) = body_json(h.router(), req).await;
    let token = json["token"].as_str().unwrap().to_string();

    // POST /api/tasks requires Operator.
    let task_body = serde_json::to_vec(&serde_json::json!({ "title": "t" })).unwrap();
    let req = h.signed_request("POST", "/api/tasks", &task_body, Some(&token));
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn viewer_hitting_admin_route_is_403() {
    let h = Harness::new();
    h.create_user("vic", "pw", vec![Role::Viewer]);
    let token = h.mint_token("vic", vec![Role::Viewer], state::now_unix() + 600, "n");
    let req = h.signed_request("GET", "/api/audit", b"", Some(&token));
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_token_is_401() {
    let h = Harness::new();
    h.create_user("alice", "pw", vec![Role::Viewer]);
    // exp in the past.
    let token = h.mint_token("alice", vec![Role::Viewer], state::now_unix() - 10, "expired-n");
    let req = h.signed_request("GET", "/api/board", b"", Some(&token));
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_then_reuse_is_401() {
    let h = Harness::new();
    h.create_user("alice", "pw", vec![Role::Viewer]);
    let exp = state::now_unix() + 600;
    let token = h.mint_token("alice", vec![Role::Viewer], exp, "logout-n");

    // Logout (Role::Viewer) revokes the nonce.
    let req = h.signed_request("POST", "/api/logout", b"", Some(&token));
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::OK);

    // Reuse the same token → revoked → 401.
    let req = h.signed_request("GET", "/api/board", b"", Some(&token));
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabled_user_next_request_denied() {
    let h = Harness::new();
    h.create_user("alice", "pw", vec![Role::Viewer]);
    let token = h.mint_token("alice", vec![Role::Viewer], state::now_unix() + 600, "n");

    // Works first.
    let req = h.signed_request("GET", "/api/board", b"", Some(&token));
    assert_eq!(status_of(h.router(), req).await, StatusCode::OK);

    // Disable the user directly in the store.
    let mut rec = h.state.inner.store.get("users", "alice").unwrap();
    rec.doc["active"] = serde_json::json!(false);
    h.state.inner.store.put("users", rec).unwrap();

    // Next request denied (role/active re-fetched per request).
    let req = h.signed_request("GET", "/api/board", b"", Some(&token));
    assert_eq!(
        status_of(h.router(), req).await,
        StatusCode::UNAUTHORIZED,
        "disabled user must be rejected on the next request"
    );
}

#[tokio::test]
async fn role_change_demotion_denied_on_next_request() {
    let h = Harness::new();
    h.create_user("op", "pw", vec![Role::Operator, Role::Viewer]);
    // Token still claims Operator, but we will demote the stored user.
    let token = h.mint_token(
        "op",
        vec![Role::Operator, Role::Viewer],
        state::now_unix() + 600,
        "n",
    );

    // Demote to Viewer-only in the store.
    let mut rec = h.state.inner.store.get("users", "op").unwrap();
    rec.doc["roles"] = serde_json::json!(["Viewer"]);
    h.state.inner.store.put("users", rec).unwrap();

    // Operator route now denied despite the token's stale Operator claim.
    let task_body = serde_json::to_vec(&serde_json::json!({ "title": "t" })).unwrap();
    let req = h.signed_request("POST", "/api/tasks", &task_body, Some(&token));
    assert_eq!(status_of(h.router(), req).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn enroll_happy_path() {
    let h = Harness::new();
    // Mint a fresh bootstrap key via a scheme over the same store.
    let tofu = TofuClientAuth::new(h.state.inner.store.clone()).unwrap();
    let key = tofu.issue_bootstrap_key().unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());

    let body = serde_json::to_vec(&serde_json::json!({
        "api_key": key,
        "client_name": "another-client",
        "public_key_b64": pk_b64,
    }))
    .unwrap();
    // Enroll is PublicBootstrap — no client signature needed.
    let req = Request::builder()
        .method("POST")
        .uri("/api/enroll")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = body_json(h.router(), req).await;
    assert_eq!(status, StatusCode::OK, "enroll should succeed: {json:?}");
    assert!(json["client_id"].is_string());
}

#[tokio::test]
async fn enroll_with_bad_key_is_rejected() {
    let h = Harness::new();
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    let body = serde_json::to_vec(&serde_json::json!({
        "api_key": "not-a-real-bootstrap-key",
        "client_name": "x",
        "public_key_b64": pk_b64,
    }))
    .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/api/enroll")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let status = status_of(h.router(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[test]
fn route_gate_enumeration_no_default_open() {
    // Every registered route must declare a RequiredAuth, and only the bootstrap
    // enroll endpoint (plus the client-only login) may skip session/role gating.
    let table = routes::route_table();
    assert!(!table.is_empty());
    routes::assert_all_routes_gated(&table);

    let public: Vec<_> = table
        .iter()
        .filter(|r| matches!(r.auth, RequiredAuth::PublicBootstrap))
        .map(|r| r.path)
        .collect();
    assert_eq!(public, vec!["/api/enroll"], "only enroll may be public");

    let client_only: Vec<_> = table
        .iter()
        .filter(|r| matches!(r.auth, RequiredAuth::ClientOnly))
        .map(|r| r.path)
        .collect();
    assert_eq!(client_only, vec!["/api/login"], "only login may be client-only");
}

#[tokio::test]
async fn revoked_nonce_with_invalid_stamp_does_not_leak_via_distinct_body() {
    // An attacker-forged token (arbitrary nonce, junk stamp) must yield the SAME
    // 401 "session invalid" whether or not the nonce is on the denylist — the MAC
    // is checked before the revocation lookup, so the denylist is not probeable.
    let h = Harness::new();
    h.create_user("alice", "pw", vec![Role::Viewer]);

    // Put a known nonce on the durable denylist directly.
    h.state
        .inner
        .store
        .put(
            state::REVOKED_SESSIONS,
            wyrtloom_core::persistence::Record {
                id: "known-revoked".into(),
                doc: serde_json::json!({ "nonce": "known-revoked", "exp_unix": state::now_unix() + 600 }),
            },
        )
        .unwrap();

    // Forge a token: valid base64 payload referencing the revoked nonce, junk stamp.
    let payload = serde_json::json!({
        "user_id": "alice",
        "roles": ["Viewer"],
        "exp_unix": state::now_unix() + 600,
        "nonce": "known-revoked",
    });
    let b64 = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payload).unwrap());
    let forged = format!("{b64}.{}", hex(&[0u8; 32]));

    let req = h.signed_request("GET", "/api/board", b"", Some(&forged));
    let resp = h.router().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Forged stamp must be rejected as "session invalid" (MAC failed) — NOT
    // "session revoked", which would reveal denylist membership.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "session invalid");
}

#[tokio::test]
async fn verified_request_produces_audit_entry_and_chain_verifies() {
    let h = Harness::new();
    h.create_user("alice", "pw", vec![Role::Viewer]);
    let token = h.mint_token("alice", vec![Role::Viewer], state::now_unix() + 600, "n-audit");

    let before = h.security.audit_log_snapshot().len();
    let req = h.signed_request("GET", "/api/board", b"", Some(&token));
    assert_eq!(status_of(h.router(), req).await, StatusCode::OK);

    let after = h.security.audit_log_snapshot();
    assert!(
        after.len() > before,
        "a verified request must append at least one audit entry"
    );
    assert!(
        h.security.verify_chain().is_ok(),
        "audit hash-chain must verify after a real request"
    );
}
