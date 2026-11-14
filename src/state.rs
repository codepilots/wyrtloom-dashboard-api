//! Shared application state, the concurrency limiter, the per-IP rate limiter,
//! and the durable session-revocation denylist.
//!
//! SECURITY: loopback binding is NOT an authentication boundary. Any process on
//! the host (or a CSRF/SSRF pivot through a browser) can reach a loopback
//! socket, so every endpoint except `/api/enroll` is gated by client-signature
//! auth, and every endpoint except `/api/enroll` and `/api/login` is gated by a
//! verified user session. The `--insecure-allow-remote-http` transport guard is
//! a deployment safety rail, not the security perimeter.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, Semaphore};

use wyrtloom_core::kanban::KanbanBoard;
use wyrtloom_core::persistence::{
    CollectionSpec, PersistenceProvider, Query, Record, StoreError,
};
use wyrtloom_core::provider::LlmProvider;
use wyrtloom_core::profile::TaskProfile;
use wyrtloom_core::security::SecurityModule;
use wyrtloom_core::users::UserDirectory;
use wyrtloom_core::client_auth::ClientAuthScheme;
use wyrtloom_core::logger::CallLogger;
use wyrtloom_core::escalation::{Escalation, EscalationError, HumanEscalation, HumanResponse};

/// Collection holding revoked session nonces (durable across restarts).
pub const REVOKED_SESSIONS: &str = "revoked_sessions";

/// Indexed field used to prune expired revocation records.
const REVOKED_EXP_FIELD: &str = "exp_unix";

/// Result of a revocation-denylist lookup. `Unknown` (a store error other than
/// NotFound) must be treated as a denial by callers — fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    Revoked,
    NotRevoked,
    Unknown,
}

/// Maximum request body size accepted by the API (defence against memory DoS
/// and oversized signed-body buffering). 64 KiB.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Default session lifetime in seconds (30 minutes).
pub const SESSION_TTL_SECS: i64 = 30 * 60;

/// Shared, cloneable application state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<Inner>,
}

pub struct Inner {
    pub store: Arc<dyn PersistenceProvider>,
    pub users: Arc<dyn UserDirectory>,
    /// Client-auth scheme. SINGLE-INSTANCE ASSUMPTION: this holds a process-local
    /// nonce replay cache and a per-process enroll/bootstrap lock, so the API must
    /// run as a single instance / single writer — a nonce replayed against a
    /// *different* process would not be caught, and concurrent enrollments could
    /// race on the single-use bootstrap key. Horizontal scaling would require
    /// moving the replay/bootstrap state into the shared store behind a
    /// compare-and-set. See README "single-instance assumption".
    pub clients: Arc<dyn ClientAuthScheme>,
    pub board: Arc<dyn KanbanBoard>,
    /// The configured LLM provider built from `[provider]` in wyrtloom.toml.
    /// `None` when no provider is usable — the `/api/tasks/:id/execute` route
    /// then returns 503 (execution unavailable) rather than running unverified.
    pub provider: Option<Arc<dyn LlmProvider>>,
    /// The task profile (model, output budget, escalation threshold) selected
    /// for execution. Built from `[provider]` alongside `provider`.
    pub profile: TaskProfile,
    /// Caps concurrent task executions. Execution is CPU/IO bound
    /// (provider call + kanban writes); a semaphore keeps a burst of execute
    /// requests from denting the async reactor and the single-writer store.
    pub exec_semaphore: Arc<Semaphore>,
    pub security: Arc<SecurityModule>,
    pub logger: Option<Arc<dyn CallLogger>>,
    /// Caps concurrent argon2 verifications so a burst of `/login` requests
    /// cannot exhaust CPU/memory (argon2 is deliberately expensive).
    pub auth_semaphore: Arc<Semaphore>,
    /// Per-IP token bucket for `/login` and `/enroll`.
    pub rate_limiter: Arc<RateLimiter>,
    /// Path to the server-side `wyrtloom.toml` (the only config path the API
    /// will read/write — no caller-supplied paths, no traversal).
    pub config_path: String,
}

impl AppState {
    /// Ensure the durable revocation collection exists.
    pub fn ensure_collections(&self) -> Result<(), StoreError> {
        self.inner.store.ensure_collection(&CollectionSpec {
            name: REVOKED_SESSIONS.to_string(),
            indexed_fields: vec![REVOKED_EXP_FIELD.to_string()],
        })
    }

    /// Revocation status of a session nonce.
    ///
    /// Distinguishes a definite "not revoked" (the store said NotFound) from an
    /// *uncertain* read (any other store error). A revocation/denylist check
    /// must FAIL CLOSED on uncertainty — treating a transient store error as
    /// "not revoked" would let a logged-out/forcibly-revoked token slip through
    /// during a store hiccup.
    pub fn revocation_status(&self, nonce: &str) -> RevocationStatus {
        match self.inner.store.get(REVOKED_SESSIONS, nonce) {
            Ok(_) => RevocationStatus::Revoked,
            Err(StoreError::NotFound(_)) => RevocationStatus::NotRevoked,
            Err(_) => RevocationStatus::Unknown,
        }
    }

    /// Revoke a session nonce until `exp_unix`, and opportunistically prune any
    /// revocation records whose own expiry has already passed (so the denylist
    /// stays bounded — a revoked entry is only useful until the token it covers
    /// would have expired anyway).
    pub fn revoke(&self, nonce: &str, exp_unix: i64) -> Result<(), StoreError> {
        self.prune_revocations();
        self.inner.store.put(
            REVOKED_SESSIONS,
            Record {
                id: nonce.to_string(),
                doc: serde_json::json!({ "nonce": nonce, REVOKED_EXP_FIELD: exp_unix }),
            },
        )
    }

    /// Delete revocation records whose covered token has already expired.
    fn prune_revocations(&self) {
        let now = now_unix();
        if let Ok(recs) = self.inner.store.query(REVOKED_SESSIONS, &Query::All) {
            for rec in recs {
                let exp = rec
                    .doc
                    .get(REVOKED_EXP_FIELD)
                    .and_then(|v| v.as_i64())
                    .unwrap_or(i64::MAX);
                if exp < now {
                    let _ = self.inner.store.delete(REVOKED_SESSIONS, &rec.id);
                }
            }
        }
    }
}

/// Read `N` bytes from the OS CSPRNG (`/dev/urandom`). Panics only if the OS
/// entropy source is unavailable, which on a supported host indicates a broken
/// environment — failing loudly is safer than returning weak randomness.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use std::io::Read;
    let mut buf = [0u8; N];
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom for CSPRNG");
    f.read_exact(&mut buf).expect("read CSPRNG bytes");
    buf
}

/// Current Unix-seconds time, or `None` if the system clock is set before the
/// Unix epoch (a broken/rolled-back clock). Security gates MUST treat `None` as
/// a failure (fail closed), never as "time = 0".
pub fn now_unix_checked() -> Option<i64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

/// Current Unix-seconds time for non-security-gating uses (token TTL math,
/// pruning). Saturates to 0 on a pre-epoch clock; callers that gate on freshness
/// must use [`now_unix_checked`] instead so they can fail closed.
pub fn now_unix() -> i64 {
    now_unix_checked().unwrap_or(0)
}

/// Headless escalation used when the API executes a task and the agent blocks.
///
/// The API has no interactive terminal to ask *which* way to proceed, so when
/// the agent reports blocked, the task is recorded as **Blocked with the agent's
/// reason** (the `record_blocked` path) rather than prompting a human. This
/// keeps execution deterministic and non-blocking for the operator. A future
/// UI can map this to a real interactive escalation.
pub struct HeadlessEscalation;

impl HumanEscalation for HeadlessEscalation {
    fn escalate(&self, _e: Escalation) -> Result<HumanResponse, EscalationError> {
        // Any non-"skip" choice routes the pipeline into `record_blocked`,
        // leaving the task Blocked with the agent's reason. We choose a
        // deliberately meaningless id so no one mistakes it for a real action.
        Ok(HumanResponse::Chose("headless-block".into()))
    }
}

// ---------------------------------------------------------------------------
// Per-IP token-bucket rate limiter
// ---------------------------------------------------------------------------

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Simple per-key token-bucket limiter. Keyed by client IP for the sensitive
/// `/login` and `/enroll` endpoints so a single source cannot brute-force
/// credentials or spam enrollment.
pub struct RateLimiter {
    buckets: AsyncMutex<HashMap<String, Bucket>>,
    capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    /// `capacity` burst tokens, refilled at `refill_per_sec` tokens/second.
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            buckets: AsyncMutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
        }
    }

    /// Attempt to spend one token for `key`. Returns `true` if allowed.
    pub async fn check(&self, key: &str) -> bool {
        let mut map = self.buckets.lock().await;
        let now = Instant::now();

        // Opportunistically evict idle buckets to keep the map bounded.
        if map.len() > 10_000 {
            map.retain(|_, b| now.duration_since(b.last) < Duration::from_secs(3600));
        }

        let bucket = map.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last);
        bucket.tokens =
            (bucket.tokens + elapsed.as_secs_f64() * self.refill_per_sec).min(self.capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
