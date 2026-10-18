# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo fmt -- --check          # check formatting
cargo clippy --all-targets -- -D warnings  # lint
cargo test --locked --offline  # full offline suite (including mocked auth flows)
cargo test refs::tests        # run tests in a specific module
cargo build --release         # release build
```

CI runs all four checks on push/PR to main (.github/workflows/ci.yml).

## Architecture

Rust CLI (`kip`) for kipclip.com, an AT Protocol bookmark manager. Uses `jacquard` for default OAuth (PKCE + DPoP) and typed XRPC calls to the user's PDS. Explicit `login --app-password-env NAME` is the only app-password entry point; never retrieve credentials or run live auth in tests.

```
main.rs → clap parsing + command dispatch
commands/*  → thin handlers, each receives a PdsClient
kipclip/*   → core library (auth, pds, types, enrich, refs, display, config)
```

**Data flow**: CLI parses args → command handler gets `PdsClient` → `pds.rs` builds typed jacquard requests → PDS returns records → command formats output.

**Sidecar pattern**: Bookmarks (`community.lexicon.bookmarks.bookmark`) and annotations (`com.kipclip.annotation`) share the same rkey. Annotations hold enrichment metadata (title, description, favicon, image). Both are created/deleted together.

**Ref resolution** (`refs.rs`): Users address bookmarks by rkey prefix (min 4 chars). Fetches all bookmarks and matches prefix, errors on ambiguous matches.

**Enrichment** (`enrich.rs`): Client-side HTML parsing via regex-lite. Extracts og:title, og:description, og:image, twitter:image, favicon. 10s timeout, 512KB body limit. Falls back gracefully on failure.

## Key Jacquard Patterns

- `auth::Session` dispatches to `OAuthSession<JacquardResolver, OAuthStore>` or the app-session typed XRPC adapter. `OAuthStore` delegates the unchanged JSON format to Jacquard's `FileAuthStore`, retaining one lifecycle-wide `SessionTransaction` through all Arc-owned clients/sessions/store handles, plus an in-process mutex for SDK read/modify/write calls.
- Restore session: `OAuthClient::restore(&did, &session_id)`
- OAuth login: both default and `--headless` use the same `start_auth` → hidden pasted callback → `parse_callback_url` → `callback` → identity activation path. Default also tries `open::that`; headless never opens a browser. Always print the authorization URL and continue to paste if browser opening fails. Never call `login_with_local_server` or start a callback listener: Jacquard's helper binds all interfaces. Keep redirect metadata `http://127.0.0.1:4000/oauth/callback` and scopes exactly `atproto transition:generic`; the browser's connection-refused page is expected and the user copies its complete URL. Keep the one transaction alive across approval, parsing, token writes and activation.
- `app_session.rs`: resolve handle/DID/PDS bidirectionally and validate original unnormalized identity strings before persisting. Require exactly one `#atproto_pds` service with type `AtprotoPersonalDataServer`, not the first service by type. Typed `createSession`/`refreshSession`, refresh-token bearer auth, one retry for exact HTTP 400/401 `ExpiredToken`. The raw-layer adapter recognizes that body before Jacquard can discard it for `WWW-Authenticate`; every other challenge retains SDK handling. Do not substitute Jacquard's credential helpers, which persist before caller identity validation.
- `app_session/discovery.rs` uses Jacquard only for DNS TXT; bounded HTTP discovery handles statuses directly (avoiding Jacquard 0.9's non-200 `unwrap_err` panic), preserves raw DID documents, and follows at most three credential-free HTTPS redirects. Every GET (well-known, did:web, PLC, public resolveHandle, and each redirect) resolves and rejects the entire DNS answer if any address is forbidden, then pins all approved addresses on a fresh direct/no-proxy client with the original TLS hostname. Never forward caller headers or bodies. Offline discovery tests use injected DNS/executors plus a loopback-only wire fixture for real reqwest pins and hostile proxy settings. `transport.rs` streams authentication/discovery bodies with a 256 KiB limit; credential POSTs are redirect-denied. Other app-session XRPC responses allow 8 MiB.
- `SessionHttp` validates every PDS destination before sending any credential: reuse `fetch`'s literal/DNS address checks, reject the entire mixed answer if any IP is forbidden, disable proxies, and apply `resolve_to_addrs` to a fresh client per request. Keep the original TLS/SNI/Host name and no redirects. Local/private/reserved PDS endpoints are intentionally unsupported in app-password mode; do not add an unsafe override. Routing tests inject public DNS answers and a mock executor, plus a loopback-only wire fixture to verify actual reqwest pins/proxy/redirect behavior without public network.
- Rkey conversion: `RecordKey(Rkey::new(rkey)?)`
- Cursor for pagination: `CowStr::from(cursor_string)`
- Record values: use `.to_data()` for conversion

## Config & Session Storage

Under `dirs::config_dir()/kipclip/` (macOS: `~/Library/Application Support/kipclip/`; Linux: XDG, normally `~/.config/kipclip/`):
- `session.json` — OAuth tokens (via jacquard's FileAuthStore)
- `whoami.json` — cached DID, handle, session_id for OAuth; for app-password mode an explicit discriminator plus access/refresh tokens and verified PDS. `whoami` serializes only `SessionInfo`, never the token-bearing representation.
- No app password or environment-variable name is saved. Reads never initiate login or read password env vars. No app-password support belongs in metadata or other read-only command handlers.
- App-session/identity writes are atomic with 0600 permissions and a 0700 directory (Unix); symlinks/hardlinks/non-regular files are refused. The original OAuth JSON map is retained and its permissions hardened before Jacquard opens it.
- Every active-session writer, OAuth identity activation, refresh CAS, and logout shares `config::SessionTransaction` and a persistent no-follow 0600 `.session.lock` inode using `flock`. Never unlink that lock on logout. App refresh holds it across the disk recheck and rename, comparing the login generation as well as tokens. `RwLock` protects only in-process state, not other CLIs. Never nest transaction acquisitions; use the guard's `write` method when already locked.
- OAuth MUST acquire once before `FileAuthStore::new`, retain the guard through the full SDK lifecycle (including async I/O/user approval/implicit refresh), and activate `whoami` using that already-held guard. No store method may reacquire flock. Restore rechecks the pointer and refuses missing tokens under the lock before constructing the SDK store; only explicit login initializes it. Logout/other writers wait for every surviving OAuth handle. Keep acquisition waits off the async executor. Lifecycle regressions use bounded child-process pipe barriers and real FileAuthStore mutations with a synthetic OAuth server, never real OAuth/PDS HTTP.
- Auth/PDS errors must discard raw sources/bodies/headers and cached account data, including in Debug diagnostics.

## Testing

Tests are colocated (`#[cfg(test)]` blocks) plus CLI integration tests under `tests/`. Auth tests use in-memory HTTP/identity mocks, synthetic sentinels, and private disposable stores; CLI env tests use an empty environment and disposable HOME and fail before networking. Manual OAuth tests inject browser/hidden-prompt I/O and a synthetic resolver to exercise the real SDK callback/token store in both modes, including browser-open failure and invalid callbacks, without a callback listener. Never use real credentials or a real PDS. Other test helpers build fake `EnrichedBookmark` instances; fetch tests use loopback-only mock servers. Set TMPDIR to the prescribed scratch root when running the suite.

## Style

- Rust edition 2024, max line width 100, field init shorthand enabled
- MSRV: 1.85 (clippy.toml)
- Errors via `miette::Result` with contextual `miette!()` wrapping
- Module name is `kipclip` (not `lib`) to avoid `special_module_name` warning
