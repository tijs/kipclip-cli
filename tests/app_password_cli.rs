//! Offline CLI preflight tests: valid passwords never reach a real resolver or
//! PDS. Each child has an empty environment and a disposable HOME.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};

const SENTINEL: &str = "fixture-private-detail";
const KEY: &str = "BLUESKY_PASSWD";

struct Fixture {
    home: tempfile::TempDir,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let config = if cfg!(target_os = "macos") {
            home.path().join("Library/Application Support/kipclip")
        } else {
            home.path().join("config/kipclip")
        };
        Self { home, config }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kip"));
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join("config"))
            .env("APPDATA", self.home.path().join("config"));
        command
    }

    fn login(&self, name: &str, value: Option<OsString>) -> Output {
        let mut command = self.command();
        command.args(["login", "tijs.org", "--app-password-env", name]);
        if let Some(value) = value {
            command.env(KEY, value);
        }
        // Credentials are provided only in the child's environment, never argv.
        let argv: Vec<_> = command.get_args().collect();
        assert_eq!(argv, ["login", "tijs.org", "--app-password-env", name]);
        let output = command.output().expect("run isolated preflight");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty(), "preflight must emit no output");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("KIP_APP_PASSWORD_ENV"));
        assert!(
            !stderr.contains(SENTINEL) && !stderr.contains(KEY),
            "must not echo input"
        );
        assert!(!self.config.exists(), "preflight must not create a store");
        output
    }
}

#[test]
fn login_missing_empty_whitespace_and_invalid_environment_values_fail_before_network() {
    let fixture = Fixture::new();
    fixture.login(KEY, None);
    for value in [
        "",
        " ",
        "\n",
        "fixture-private-detail\n",
        "fixture-private-detail\t",
    ] {
        fixture.login(KEY, Some(value.into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        fixture.login(KEY, Some(OsString::from_vec(vec![0xff])));
    }
}

#[test]
fn generic_name_is_selected_and_missing_is_distinct_from_empty() {
    let fixture = Fixture::new();
    let name = "CUSTOM_LOGIN_SECRET";
    for (selected_value, expected) in [
        (None, "not set in this login process"),
        (Some(""), "is empty"),
        (
            Some("fixture-private-detail\n"),
            "invalid app-password value",
        ),
    ] {
        let mut command = fixture.command();
        command.args(["login", "tijs.org", "--app-password-env", name]);
        // Deliberately different invalid state: accidentally reading a built-in
        // key would produce a different error, still without risking network.
        command.env(KEY, "\n");
        if let Some(value) = selected_value {
            command.env(name, value);
        }
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["login", "tijs.org", "--app-password-env", name]
        );
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Miette wraps diagnostics across terminal-width lines with a gutter.
        let diagnostic = stderr
            .replace('│', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(diagnostic.contains("KIP_APP_PASSWORD_ENV") && diagnostic.contains(expected));
        assert!(!stderr.contains(SENTINEL) && !stderr.contains(name) && !stderr.contains(KEY));
        assert!(!fixture.config.exists());
    }
}

#[test]
fn invalid_environment_names_are_not_echoed_or_read() {
    let fixture = Fixture::new();
    for name in [
        "",
        "1BAD",
        "fixture-private-detail",
        "BAD=fixture-private-detail",
        "BAD\nfixture-private-detail",
    ] {
        fixture.login(name, Some(SENTINEL.into()));
    }
}

#[test]
fn only_explicit_login_reads_the_environment_and_no_cross_process_fallback_exists() {
    let fixture = Fixture::new();
    // This is a valid opaque synthetic password. With no explicit login it must
    // be ignored, not silently used to create a session, even on auth failure.
    let output = fixture
        .command()
        .env(KEY, SENTINEL)
        .args(["whoami", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("KIP_AUTH_REQUIRED"));
    assert!(!stderr.contains(SENTINEL) && !stderr.contains("KIP_APP_PASSWORD_ENV"));
    assert!(!fixture.config.exists());
    // An earlier process having the key does not supply it to this invocation.
    fixture.login(KEY, None);
}

#[test]
fn password_option_is_login_only_and_conflicts_with_headless_oauth() {
    let fixture = Fixture::new();
    let conflict = fixture
        .command()
        .args(["login", "tijs.org", "--headless", "--app-password-env", KEY])
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(2));
    for command in ["metadata", "whoami", "list", "add"] {
        let output = fixture
            .command()
            .args([command, "--app-password-env", KEY])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument"));
    }
    assert!(!fixture.config.exists());
}

#[test]
fn metadata_ignores_injected_key_and_never_reads_or_writes_a_session() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env(KEY, SENTINEL)
        .args(["metadata", "http://127.0.0.1:9/", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Refusing"));
    assert!(!stderr.contains(SENTINEL) && !stderr.contains("login"));
    assert!(!fixture.config.exists());
}

#[test]
fn whoami_never_prints_app_tokens_or_extra_cached_private_material() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(&fixture.config).unwrap();
    let path = fixture.config.join("whoami.json");
    let data = serde_json::json!({
        "did":"did:plc:fixtureaccount", "handle":"fixture.test", "session_id":"app-password",
        "auth_method":"app-password", "pds":"https://pds.test",
        "access_jwt":format!("{SENTINEL}.access.signature"),
        "refresh_jwt":format!("{SENTINEL}.refresh.signature"), "private":SENTINEL
    });
    std::fs::write(path, serde_json::to_vec(&data).unwrap()).unwrap();
    for args in [vec!["whoami"], vec!["whoami", "--json"]] {
        let output = fixture
            .command()
            .env(KEY, SENTINEL)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            !stdout.contains(SENTINEL)
                && !stdout.contains("access_jwt")
                && !stdout.contains("refresh_jwt")
        );
    }
    assert!(
        !fixture.config.join("session.json").exists(),
        "must not open OAuth store"
    );
}
