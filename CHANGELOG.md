# Changelog

## 0.1.4

### Added

- `kip metadata <url> [--json]` — fetch page metadata (title, description, favicon, image) without a session. Read-only: no PDS calls and no records are written. Fetches are hardened: bounded timeouts and body size, every redirect hop validated, and local/private/reserved destinations refused.
- Explicit app-password login via `kip login <handle> --app-password-env <ENV_NAME>`. Reads only the caller-chosen variable in the login process, verifies the identity-discovered PDS and returned account before saving, and never persists the password. OAuth remains the default; `--headless` remains OAuth-only. Documents a narrowly scoped, single-entry secret-injection boundary, not shared-project BWS injection.
- Secure app-session persistence and refresh for authenticated commands: atomic `0600` files in a `0700` directory, identity-validated token rotation, and one retry on an explicit expired access token. Existing OAuth sessions remain compatible.

### Fixed

- Default OAuth login opens the browser but now uses the same hidden pasted-callback flow as `--headless`, without starting Jacquard's LAN-reachable callback server or any listener. Browser-open failure keeps the printed URL and paste prompt available. The `http://127.0.0.1:4000/oauth/callback` redirect and `atproto transition:generic` scopes are unchanged; the browser's connection-refused page is expected.
- Sanitize authentication and PDS transport/response diagnostics without upstream bodies, tokens, passwords, or cached account data. Harden legacy OAuth store permissions without changing its JSON format.
- Require an exact original DID document ID and one canonical `#atproto_pds` service of the correct type; refuse ambiguous services before sending credentials. Bound authentication/discovery bodies to 256 KiB and handle discovery redirects/non-200 responses without resolver panics.
- Recognize only the exact HTTP 400/401 XRPC `ExpiredToken` code before Jacquard's auth-header conversion, retaining once-only refresh/retry and normal handling for unrelated challenges.
- Serialize active-session activation, refresh compare-and-swap and logout across processes with a secure persistent OS lock. Reject stale refreshes even when a newer login returns identical tokens.

## 0.1.3

### Fixed

- Request the current AT Protocol OAuth `transition:generic` scope so write commands such as `kip add` can create PDS records.

## 0.1.2

### Added

- `kip login <handle> --headless` for SSH and remote machines: authorize in a local browser, then paste the hidden loopback callback URL into the CLI.

### Fixed

- Reject malformed empty OAuth callback parameters before they consume an authorization attempt.

## 0.1.1

### Fixed

- Fix OAuth token refresh so sessions last up to 2 weeks instead of expiring after ~2 hours. The client_id used during token refresh now matches the one from login, allowing the PDS to accept refresh token requests.
- Show a clear "Session expired" message with re-login instructions when session restore fails.

## 0.1.0

First release of `kip`, the CLI for [kipclip.com](https://kipclip.com).

### Commands

- `kip login <handle>` — AT Protocol OAuth login (PKCE + DPoP)
- `kip logout` — clear stored session
- `kip whoami` — show current user (DID, handle)
- `kip add <url> [-t tag ...]` — bookmark a URL with optional tags
- `kip list [-t tag] [-n limit] [--search query] [--json]` — list bookmarks with filtering and search
- `kip search <query>` — search bookmarks by title, URL, or description
- `kip open <ref>` — open a bookmark in the browser
- `kip delete <ref> [--force]` — delete a bookmark and its annotation
- `kip note <ref> [text]` — set or clear a note on a bookmark
- `kip tag <ref> <tag...>` — add tags to a bookmark
- `kip untag <ref> <tag...>` — remove tags from a bookmark
- `kip tags [--json]` — list all tags with counts

### Features

- Client-side URL enrichment — extracts title, description, favicon, and image from bookmarked URLs
- Ref-based bookmark resolution — address bookmarks by rkey prefix (min 4 chars)
- Terminal-aware display with unicode width handling
- JSON output mode for scripting
- Session persistence via `~/.config/kipclip/`
