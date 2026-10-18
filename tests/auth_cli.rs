//! Offline auth-error contract tests. Every subprocess uses a disposable HOME;
//! fixtures fail before OAuth restoration, browser launch, or any PDS request.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    home: PathBuf,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!(
            "kip-auth-cli-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&home).expect("create disposable HOME");
        let config_root = if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            home.join("config")
        };
        let config = config_root.join("kipclip");
        std::fs::create_dir_all(&config).expect("create fixture config");
        Self { home, config }
    }

    fn list(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_kip"))
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join("config"))
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .args(["list", "--json"])
            .output()
            .expect("run fixture CLI")
    }

    fn assert_error(&self, marker: &str, login_hint: bool) {
        let output = self.list();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            output.stdout.is_empty(),
            "failed list must print no records"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(marker), "{stderr}");
        assert_eq!(stderr.contains("kip login"), login_hint, "{stderr}");
        assert!(!stderr.contains("fixture-private-detail"), "{stderr}");
        assert!(
            !self.config.join("session.json").exists(),
            "failure must precede opening/creating the OAuth store"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.home).expect("remove only this disposable fixture");
    }
}

#[test]
fn missing_session_requires_manual_login_without_opening_oauth() {
    let fixture = Fixture::new();
    fixture.assert_error("KIP_AUTH_REQUIRED", true);
    let stderr = String::from_utf8(fixture.list().stderr).unwrap();
    assert!(stderr.contains("browser approval on this computer"));
}

#[test]
fn unreadable_malformed_or_invalid_cached_info_is_not_expiry() {
    for data in [
        // A missing field must not echo any of the cached data.
        r#"{"did":"fixture-private-detail"}"#,
        // Valid JSON, invalid DID: must stop before constructing OAuth/store.
        r#"{"did":"fixture-private-detail","handle":"fixture.test","session_id":"fixture-only"}"#,
    ] {
        let fixture = Fixture::new();
        std::fs::write(fixture.config.join("whoami.json"), data).unwrap();
        fixture.assert_error("KIP_RESTORE_FAILED", false);
    }
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.config.join("whoami.json")).unwrap();
    fixture.assert_error("KIP_RESTORE_FAILED", false);
}
