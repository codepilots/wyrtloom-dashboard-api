//! Subprocess tests for the one-shot provisioning subcommands.
//!
//! These run the real binary (`CARGO_BIN_EXE_wyrtloom-dashboard-api`) so they
//! exercise `run()`'s mode selection end-to-end. The security-critical
//! invariant under test: provisioning mode must NOT open or grow the audit file
//! (it builds the `SecurityModule` without `with_audit_file`), so it cannot
//! fork the tamper-evident chain a running server is appending to.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_wyrtloom-dashboard-api");

/// Unique temp dir per test (under the system temp dir) to avoid cross-test
/// interference; cleaned up at the end.
fn temp_dir(tag: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!(
        "wyrtloom-prov-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn issue_bootstrap_key_does_not_create_audit_file() {
    let dir = temp_dir("bootstrap");
    let store = dir.join("store.db");
    let audit = dir.join("audit.jsonl");
    let session_key = dir.join("session.key");
    let config = dir.join("wyrtloom.toml");

    // Audit file must not exist beforehand.
    assert!(!audit.exists());

    let out = Command::new(BIN)
        .arg("--store")
        .arg(&store)
        .arg("--audit-file")
        .arg(&audit)
        .arg("--session-key-file")
        .arg(&session_key)
        .arg("--config")
        .arg(&config)
        .arg("--issue-bootstrap-key")
        .output()
        .expect("run provisioning binary");

    assert!(
        out.status.success(),
        "provisioning failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // A bootstrap key is printed to stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty(), "expected a bootstrap key on stdout");

    // The load-bearing assertion: provisioning never touched the audit file.
    assert!(
        !audit.exists(),
        "provisioning must NOT open/create the audit file"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn provisioning_works_without_audit_file_flag() {
    // The audit file is server-only; provisioning must not require --audit-file.
    let dir = temp_dir("noaudit");
    let store = dir.join("store.db");

    let out = Command::new(BIN)
        .arg("--store")
        .arg(&store)
        .arg("--issue-bootstrap-key")
        .output()
        .expect("run provisioning binary");

    assert!(
        out.status.success(),
        "provisioning without --audit-file failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).trim().is_empty());

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn create_admin_does_not_grow_audit_file() {
    let dir = temp_dir("admin");
    let store = dir.join("store.db");
    let audit = dir.join("audit.jsonl");
    let session_key = dir.join("session.key");
    let config = dir.join("wyrtloom.toml");

    // Pre-seed a non-empty audit file (as a running server would leave behind).
    let seeded = "{\"pre-existing\":\"entry\"}\n";
    fs::write(&audit, seeded).unwrap();
    let before = fs::metadata(&audit).unwrap().len();

    let out = Command::new(BIN)
        .arg("--store")
        .arg(&store)
        .arg("--audit-file")
        .arg(&audit)
        .arg("--session-key-file")
        .arg(&session_key)
        .arg("--config")
        .arg(&config)
        .arg("--create-admin")
        .arg("alice")
        .env("WYRTLOOM_ADMIN_PASSWORD", "correct-horse-battery-staple")
        .output()
        .expect("run provisioning binary");

    assert!(
        out.status.success(),
        "provisioning failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Audit file untouched: same size, same bytes — no second appender opened.
    let after = fs::metadata(&audit).unwrap().len();
    assert_eq!(before, after, "provisioning must not grow the audit file");
    assert_eq!(fs::read_to_string(&audit).unwrap(), seeded);

    fs::remove_dir_all(&dir).ok();
}
