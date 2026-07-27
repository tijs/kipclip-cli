# Changelog

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
