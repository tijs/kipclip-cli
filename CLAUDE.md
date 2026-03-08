# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo fmt -- --check          # check formatting
cargo clippy --all-targets -- -D warnings  # lint
cargo test                    # run all 39 tests
cargo test refs::tests        # run tests in a specific module
cargo build --release         # release build
```

CI runs all four checks on push/PR to main (.github/workflows/ci.yml).

## Architecture

Rust CLI (`kip`) for kipclip.com, an AT Protocol bookmark manager. Uses `jacquard` for OAuth (PKCE + DPoP) and typed XRPC calls to the user's PDS.

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

- Session type: `OAuthSession<JacquardResolver, FileAuthStore>`
- Restore session: `OAuthClient::restore(&did, &session_id)`
- Rkey conversion: `RecordKey(Rkey::new(rkey)?)`
- Cursor for pagination: `CowStr::from(cursor_string)`
- Record values: use `.to_data()` for conversion

## Config & Session Storage

All under `~/.config/kipclip/`:
- `session.json` — OAuth tokens (via jacquard's FileAuthStore)
- `whoami.json` — cached DID, handle, session_id
- Files written atomically with 0600 permissions (Unix)

## Testing

Tests are colocated (`#[cfg(test)]` blocks). No external services or env vars — test helpers build fake `EnrichedBookmark` instances with known data. Tests cover filtering, parsing, ref matching, and display logic.

## Style

- Rust edition 2024, max line width 100, field init shorthand enabled
- MSRV: 1.85 (clippy.toml)
- Errors via `miette::Result` with contextual `miette!()` wrapping
- Module name is `kipclip` (not `lib`) to avoid `special_module_name` warning
