//! CLI-level tests for `kip metadata`.
//!
//! All cases are offline: they only exercise validation and refusal paths that
//! fail before any connection is made.

use std::process::Command;

fn kip_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kip"))
}

#[test]
fn metadata_refuses_local_targets_with_nonzero_exit() {
    for url in [
        "http://127.0.0.1:9/",
        "http://localhost:9/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
    ] {
        let output = kip_command()
            .args(["metadata", url, "--json"])
            .output()
            .expect("run kip");
        assert!(!output.status.success(), "{url} should fail");
        assert!(
            output.stdout.is_empty(),
            "{url}: stdout must stay empty on failure, got {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Refusing"), "{url}: {stderr}");
    }
}

#[test]
fn metadata_rejects_invalid_urls_with_nonzero_exit() {
    for (url, needle) in [
        ("not a url", "Invalid URL"),
        ("ftp://example.com/x", "HTTP(S)"),
        ("http://user:pass@example.com/", "credentials"),
    ] {
        let output = kip_command()
            .args(["metadata", url, "--json"])
            .output()
            .expect("run kip");
        assert!(!output.status.success(), "{url} should fail");
        assert!(
            output.stdout.is_empty(),
            "{url}: stdout must stay empty on failure, got {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(needle), "{url}: {stderr}");
    }
}

#[test]
fn metadata_requires_no_session_and_writes_nothing() {
    let home = std::env::temp_dir().join(format!("kip-cli-no-session-{}", std::process::id()));
    std::fs::remove_dir_all(&home).ok();
    std::fs::create_dir_all(&home).expect("create temp HOME");

    let output = kip_command()
        .env("HOME", &home)
        .args(["metadata", "http://127.0.0.1:9/", "--json"])
        .output()
        .expect("run kip");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "refused URL should fail");
    assert!(
        stderr.contains("Refusing"),
        "should fail at the fetch, not at auth: {stderr}"
    );
    assert!(
        !stderr.contains("login"),
        "must not ask for a login: {stderr}"
    );

    let entries: Vec<_> = std::fs::read_dir(&home).expect("read temp HOME").collect();
    assert!(
        entries.is_empty(),
        "command must not write session or config files"
    );

    std::fs::remove_dir_all(&home).ok();
}
