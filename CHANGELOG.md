# Changelog

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
