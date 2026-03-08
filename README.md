# kip

Command-line interface for [kipclip.com](https://kipclip.com) — an AT Protocol bookmark manager.

Read, add, tag, and manage your bookmarks from the terminal. Bookmarks are stored on your personal PDS using AT Protocol, so they stay yours.

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
kip login tijs.org       # Opens browser for AT Protocol OAuth
kip whoami               # Show current user
kip logout               # Clear session
```

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

kip authenticates via AT Protocol OAuth (PKCE + DPoP) using the [jacquard](https://crates.io/crates/jacquard) Rust SDK. Bookmarks are read from and written to your PDS directly. URL metadata (title, description, favicon) is fetched from the kipclip.com enrichment endpoint.

AT Protocol collections used:
- `community.lexicon.bookmarks.bookmark` — bookmark records
- `com.kipclip.annotation` — enrichment + notes sidecar
- `com.kipclip.tag` — tag records

## License

MIT
