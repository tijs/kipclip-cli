# kip

Command-line tool for managing your AT Protocol bookmarks. Works with [kipclip.com](https://kipclip.com) and any app that uses the same record format.

Read, add, tag, and manage your bookmarks from the terminal. Bookmarks are stored on your personal PDS using AT Protocol, so they stay yours.

kip talks directly to your PDS — it doesn't go through kipclip.com or any other server. The website and CLI read and write the same data, but neither depends on the other. You can use kip without ever visiting the website, and your bookmarks will still show up there if you do.

## Install

### Homebrew (macOS)

```sh
brew install tijs/tap/kipclip
```

This installs the `kip` command.

### From source

```sh
cargo install --git https://github.com/tijs/kipclip-cli
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/tijs/kipclip-cli/releases).

## Usage

### Authentication

```sh
kip login tijs.org              # Opens browser for OAuth, then paste callback URL
kip login tijs.org --headless   # Print URL without opening browser; paste callback URL
kip whoami                      # Show current user
kip logout                      # Clear session
```

Both OAuth modes use the same hidden pasted-callback prompt; **kip never starts
a callback server or opens a listening port**. With a normal login, kip opens
your browser and also prints the authorization URL. If opening the browser fails,
open that printed URL manually; login still waits for your pasted callback.

After approving access, a connection-refused page at
`http://127.0.0.1:4000/oauth/callback` is expected. Copy the **complete URL,
including its query parameters**, from the browser's address bar and paste it at
kip's hidden `Callback URL:` prompt. Keep that URL private; it contains the
short-lived authorization code. The redirect metadata remains unchanged, as do
the `atproto transition:generic` scopes and PKCE + DPoP protections.

### SSH and headless login

Run `kip login <handle> --headless` on the remote machine. This skips opening a
browser but still prints the URL. Open it in a local browser and approve access,
then paste the complete callback URL from the expected connection-refused page
at the same hidden terminal prompt. The short-lived authorization code is bound
to the remote CLI's PKCE verifier and DPoP key, so no tunnel, password, or token
transfer is needed.

### Explicit app-password login

OAuth remains the default and is recommended. If browser authorization is not an
option, kip can read an app password from an environment variable **in the same
kip process**, only during an explicit login:

```sh
kip login tijs.org --app-password-env BLUESKY_PASSWD
```

Have your trusted secret injector supply `BLUESKY_PASSWD` to that invocation.
The flag is generic: choose any existing environment-variable name, not
necessarily `BLUESKY_PASSWD` and not necessarily from Bitwarden. Names must match
`[A-Za-z_][A-Za-z0-9_]*` and be at most 128 characters. Omitting the flag always
selects OAuth; kip does not search for well-known password keys.

For Bitwarden Secrets Manager, use a trusted **single-entry** injector: it should
fetch only the selected existing BWS entry in memory, launch the command above
with only that password variable added to the child's environment, and avoid
forwarding BWS access tokens or unrelated secrets. Do not use `bws run` against
a shared project: it injects **every** project secret, not just the named key.
In particular, a Hermes project can contain unrelated API credentials. This is
not a safe single-entry handoff. Kip itself never retrieves a BWS entry.
Never print fetched values, include them in arguments/files, or enable shell tracing.

Only the variable **name** belongs in the command. Never put its value in argv,
shell history, a shell assignment, a `.env`/other file, logs, or diagnostic output.
kip does not run a vault command or child process to fetch it. Injecting a key into
a different process does not make it available to kip. Missing, empty, non-UTF-8,
or whitespace/control-containing values fail before discovery or file writes.
This option cannot be combined with `--headless`.

kip resolves the bare handle's DID and PDS, checks the DID document's reverse
handle binding and exact original document ID. Only one `#atproto_pds` service
with type `AtprotoPersonalDataServer` may authorize the PDS. Discovery uses
credential-free HTTPS GETs with at most three validated HTTPS redirects; PDS
credential POSTs never follow redirects. Authentication and discovery bodies are
streamed with a 256 KiB limit (other app-session XRPC responses allow 8 MiB).
Before every app-session request (including password creation and token refresh),
kip resolves the PDS host and refuses the entire destination if **any** result is
local, private, link-local, CGNAT, reserved or multicast. IPv4, IPv6, mapped IPv4
and numeric IP literals are checked. All approved DNS addresses are pinned for
that request; environment/system proxies are disabled so neither DNS rebinding
nor a proxy can reroute credentials. TLS still verifies the original hostname.
**Local/private PDS endpoints are intentionally unsupported in app-password mode**;
there is no unsafe-address or proxy override.
Both the returned DID and handle must match
the requested account exactly, and inactive accounts are refused, before any
session is saved. A rejected/mismatched PDS response leaves the previous session intact.

Only access/refresh tokens and the verified identity/PDS routing are persisted;
no app password, injector key name, email, DID document, or raw response is saved.
The active app-password session is in `whoami.json`, atomically replaced with
`0600` permissions in a `0700` directory. This requires Unix file permissions;
unsafe storage is refused. The directory is `~/Library/Application Support/kipclip/`
on macOS, or `$XDG_CONFIG_HOME/kipclip/` (normally `~/.config/kipclip/`) on Linux.
`kip whoami` never prints tokens. Existing OAuth `session.json` stores and legacy
`whoami.json` files remain compatible; a normal login still uses OAuth.
Active-session activation, refresh compare-and-swap and logout share an OS-level
interprocess transaction via a no-follow `0600` `.session.lock` file. That empty
lock file remains after logout so concurrent processes cannot split the lock.
Refresh rechecks the active session under the lock and cannot overwrite a newer
login or recreate a logged-out session.
OAuth retains this same transaction from before opening Jacquard's token store
through login/callback, identity activation, restoration and every implicit token
refresh, until the final client/session/store handle is dropped. Consequently,
another authenticated OAuth command or logout waits for the running OAuth command
to finish, including a pending browser/headless approval. Cancel a stuck command
before logging out. Restoration rechecks both active identity and existing token
store under the lock and never initializes a missing store after logout. This
deliberately serializes OAuth lifecycles rather than trying to lock only SDK writes;
the OAuth JSON map, DPoP material and legacy session identity format are unchanged.

Kip zeroizes its owned password string, but this is not a complete memory-erasure
guarantee: the process environment and HTTP/serialization/library buffers may
retain copies. Use a short-lived, narrowly scoped injector and process.

Later authenticated commands use the saved session, not the app password. An
explicit PDS `ExpiredToken` response triggers `com.atproto.server.refreshSession`
with the refresh token, validates the same account, securely saves rotated tokens,
and retries the original request once. Failed refresh does not trigger a password
login, browser, vault lookup, or credential reset. `kip logout` clears the local
session files; it does not revoke the app password at its provider.

No other command accepts this option or automatically reads an injected app
password. In particular, `kip metadata` remains unauthenticated and read-only.

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

For integrations, `kip bookmark-records` outputs bookmark JSON without fetching
annotations. After checking these live records for canonical URL duplicates,
an integration can pipe cached metadata JSON to
`kip save-verified <url> -t toread --duplicate-checked`. Metadata is limited to
16 KiB with optional `title`, `description`, `favicon`, and `image` fields.
This command does not fetch the article or scan bookmarks again. It writes both
records, reads each one back by its exact key, and returns
`{"verified":true,"bookmark":...}` only after checking the URL, tags, and annotation.
On failure, check live duplicates again before retrying; a partial write may exist.
Use ordinary `kip add` when the caller has not performed duplicate checking.

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

### Metadata

```sh
kip metadata https://example.com          # print title, description, favicon, image
kip metadata https://example.com --json   # {"title":"…","description":"…","favicon":"…","image":"…"}
```

Fetch a page's metadata without logging in. Read-only: no PDS calls and no records are
written. Only public HTTP(S) destinations are fetched; local, private, and reserved
addresses are refused, redirects are limited and validated, and the response body read
is capped.

## How it works

On [AT Protocol](https://atproto.com), your data lives in your Personal Data Server (PDS) — a repository of records that you own. Apps don't store your data in their own databases; they read and write records in your PDS. This means any app that understands the same record format can work with the same data.

kip authenticates via AT Protocol OAuth (PKCE + DPoP) by default, with an explicit app-password alternative, using the [jacquard](https://crates.io/crates/jacquard) Rust SDK's typed APIs. It then talks to your PDS directly. URL metadata (title, description, favicon, image) is extracted client-side by fetching and parsing the bookmarked page — no server involved.

### Records

Your bookmarks are stored as records in these AT Protocol collections:

- **`community.lexicon.bookmarks.bookmark`** — the bookmark itself (URL, creation date, tags). This is a shared lexicon, so other AT Protocol apps can read your bookmarks too.
- **`com.kipclip.annotation`** — enrichment sidecar (page title, description, favicon, image, notes). Shares the same rkey as its bookmark so they stay paired.
- **`com.kipclip.tag`** — tag records for organizing bookmarks.

Because these are just records in your PDS, you can inspect them with any AT Protocol tool, export them, or build your own app on top of them.

## License

MIT
