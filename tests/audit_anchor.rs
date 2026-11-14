//! Subprocess tests for audit-chain anchoring at server startup.
//!
//! These run the real binary so they exercise `run()`'s wiring: the anchor
//! lives in the persistence store (`store.db`), and a server must refuse to
//! start on an audit file that is shorter than its anchor, or that has no
//! anchor at all unless `--audit-anchor-enroll` is passed.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use wyrtloom_core::audit_anchor::PersistenceAuditAnchor;
use wyrtloom_core::persistence::PersistenceProvider;
use wyrtloom_core::security::{AnchorEnrollment, SecurityModule, SecurityPolicy};
use wyrtloom_store_sqlite::SqliteStore;

const BIN: &str = env!("CARGO_BIN_EXE_wyrtloom-dashboard-api");
const KEY: [u8; 32] = [21u8; 32];

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "wyrtloom-anchor-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("session.key"), KEY).unwrap();
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Write `n` audit entries the way a server would leave them: under the
    /// same key, anchored in `store.db` when `anchored` is true.
    fn write_log(&self, n: usize, anchored: bool) {
        let audit = self.path("audit.jsonl");
        let mut security = SecurityModule::with_key(KEY, SecurityPolicy::deny_all())
            .with_audit_file(audit.to_str().unwrap())
            .unwrap();
        if anchored {
            let store: Arc<dyn PersistenceProvider> =
                Arc::new(SqliteStore::open(self.path("store.db").to_str().unwrap()).unwrap());
            let anchor = PersistenceAuditAnchor::new(store, "dashboard-api").unwrap();
            security = security
                .with_audit_anchor(Arc::new(anchor), AnchorEnrollment::Strict)
                .unwrap();
        }
        for i in 0..n {
            security.record_decision(true, format!("entry {i}"));
        }
    }

    fn server(&self, extra: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.arg("--bind")
            .arg("127.0.0.1:0")
            .arg("--store")
            .arg(self.path("store.db"))
            .arg("--kanban-db")
            .arg(self.path("kanban.db"))
            .arg("--audit-file")
            .arg(self.path("audit.jsonl"))
            .arg("--session-key-file")
            .arg(self.path("session.key"))
            .arg("--config")
            .arg(self.path("wyrtloom.toml"))
            .args(extra);
        cmd
    }

    /// Run the server expecting it to refuse to start; return its stderr.
    fn expect_refusal(&self, extra: &[&str]) -> String {
        let out = self.server(extra).output().expect("run server binary");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(!out.status.success(), "server must refuse to start: {stderr}");
        stderr
    }

    /// Run the server expecting it to come up; kill it once it is listening.
    fn expect_start(&self, extra: &[&str]) {
        let mut child = self
            .server(extra)
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn server binary");
        let mut seen = String::new();
        let mut listening = false;
        for line in BufReader::new(child.stderr.take().unwrap()).lines() {
            let line = line.unwrap();
            seen.push_str(&line);
            seen.push('\n');
            if line.contains("listening on") {
                listening = true;
                break;
            }
        }
        child.kill().ok();
        child.wait().ok();
        assert!(listening, "server did not start: {seen}");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).ok();
    }
}

fn keep_first_lines(path: &Path, n: usize) {
    let contents = fs::read_to_string(path).unwrap();
    let mut out = contents.lines().take(n).collect::<Vec<_>>().join("\n");
    out.push('\n');
    fs::write(path, out).unwrap();
}

#[test]
fn fresh_install_starts_and_is_anchored() {
    let f = Fixture::new("fresh");
    f.expect_start(&[]);
    // A second start finds the anchor it wrote and accepts the log.
    f.expect_start(&[]);
}

#[test]
fn truncated_audit_file_refuses_to_start() {
    let f = Fixture::new("trunc");
    f.write_log(4, true);
    keep_first_lines(&f.path("audit.jsonl"), 2);
    let stderr = f.expect_refusal(&[]);
    assert!(stderr.contains("truncated"), "stderr: {stderr}");
    // The enrolment flag must not be a way round an existing anchor.
    let stderr = f.expect_refusal(&["--audit-anchor-enroll"]);
    assert!(stderr.contains("truncated"), "stderr: {stderr}");
}

#[test]
fn intact_anchored_audit_file_starts() {
    let f = Fixture::new("intact");
    f.write_log(3, true);
    f.expect_start(&[]);
}

#[test]
fn existing_unanchored_audit_file_needs_the_enroll_flag_once() {
    let f = Fixture::new("enroll");
    f.write_log(3, false);
    let stderr = f.expect_refusal(&[]);
    assert!(stderr.contains("anchor missing"), "stderr: {stderr}");
    assert!(stderr.contains("--audit-anchor-enroll"), "stderr: {stderr}");

    f.expect_start(&["--audit-anchor-enroll"]);
    // Once enrolled, the flag is no longer needed.
    f.expect_start(&[]);
}
