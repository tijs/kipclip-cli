# kip

Command-line tool for managing your AT Protocol bookmarks. Works with [kipclip.com](https://kipclip.com) and any app that uses the same record format.

Read, add, tag, and manage your bookmarks from the terminal. Bookmarks are stored on your personal PDS using AT Protocol, so they stay yours.

kip talks directly to your PDS — it doesn't go through kipclip.com or any other server. The website and CLI read and write the same data, but neither depends on the other. You can use kip without ever visiting the website, and your bookmarks will still show up there if you do.

## Install

### From source

```sh
cargo install --git https://github.com/tijs/kipclip-cli
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/tijs/kipclip-cli/releases).

## Usage

### Authentication

```sh
kip login tijs.org              # Opens browser for AT Protocol OAuth
kip login tijs.org --headless   # SSH/headless login (paste callback URL)
kip whoami                      # Show current user
kip logout                      # Clear session
```

### SSH and headless login

Run `kip login <handle> --headless` on the remote machine, open the printed URL
in a local browser, and approve access. The browser will then fail to load its
`127.0.0.1:4000` callback; copy that complete URL from the address bar and paste
it at kip's hidden terminal prompt. The short-lived authorization code is bound
to the remote CLI's PKCE verifier and DPoP key, so no tunnel, password, or token
transfer is needed.

### Bookmarks

```sh
kip add https://example.com -t reading -t rust
kip list
kip list -t reading -n 10
kip search "rust"
kip list --json | jq .
kip open <ref>           # Open URL in browser
kip delete <ref> --force
```

### Tags

```sh
kip tag <ref> reading    # Add tag to bookmark
kip untag <ref> reading  # Remove tag
kip tags                 # List all tags with counts
```

### Notes

```sh
kip note <ref> "Read this later"  # Set note
kip note <ref>                     # Clear note
```

Bookmark refs are short rkey prefixes (min 4 chars) shown next to each bookmark in list output.

## How it works

On [AT Protocol](https://atproto.com), your data lives in your Personal Data Server (PDS) — a repository of records that you own. Apps don't store your data in their own databases; they read and write records in your PDS. This means any app that understands the same record format can work with the same data.

kip authenticates via AT Protocol OAuth (PKCE + DPoP) using the [jacquard](https://crates.io/crates/jacquard) Rust SDK, then talks to your PDS directly. URL metadata (title, description, favicon, image) is extracted client-side by fetching and parsing the bookmarked page — no server involved.

### Records

Your bookmarks are stored as records in these AT Protocol collections:

- **`community.lexicon.bookmarks.bookmark`** — the bookmark itself (URL, creation date, tags). This is a shared lexicon, so other AT Protocol apps can read your bookmarks too.
- **`com.kipclip.annotation`** — enrichment sidecar (page title, description, favicon, image, notes). Shares the same rkey as its bookmark so they stay paired.
- **`com.kipclip.tag`** — tag records for organizing bookmarks.

Because these are just records in your PDS, you can inspect them with any AT Protocol tool, export them, or build your own app on top of them.

## License

MIT
