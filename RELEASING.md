# Releasing kip

Releases are built locally: bump `Cargo.toml` and `CHANGELOG.md`, commit, and tag the matching `vX.Y.Z` release. Build artifacts on matching Apple Silicon and Intel Macs (or a Mac that can build both targets), then collect their `target/distrib/` contents in one checkout:

```sh
cargo install cargo-dist --version 0.32.0 --locked
VERSION=0.1.6

# Write each manifest outside target/distrib first: dist reads manifests there.
dist build --tag "v$VERSION" --artifacts=local --target aarch64-apple-darwin --output-format=json > /tmp/kip-arm-manifest.json
mv /tmp/kip-arm-manifest.json target/distrib/aarch64-apple-darwin-dist-manifest.json

dist build --tag "v$VERSION" --artifacts=local --target x86_64-apple-darwin --output-format=json > /tmp/kip-intel-manifest.json
mv /tmp/kip-intel-manifest.json target/distrib/x86_64-apple-darwin-dist-manifest.json

dist build --tag "v$VERSION" --artifacts=global
```

Before publishing, inspect the two `.tar.xz` archives and their `.sha256` files in `target/distrib/`. Run the Apple Silicon package's version/help smoke checks and run Intel smoke checks on an Intel Mac or with Rosetta when available; record when cross-compiled Intel runtime checks are unavailable.

Retain the tap's existing minimal formula and `test do` block, updating only the versioned download URLs and the two archive hashes. The generated cargo-dist formula currently fails strict Homebrew audit. Put the audited formula in `target/distrib/kipclip.rb` before uploading it.

This local-only dist configuration can make `dist host` exit successfully without creating a release. Publish explicitly with the authenticated GitHub CLI after pushing the verified tag and preparing release notes:

```sh
git push origin "v$VERSION"
gh release create "v$VERSION" --verify-tag --title "v$VERSION" --notes-file /tmp/kip-release-notes.md \
  target/distrib/kipclip-aarch64-apple-darwin.tar.xz \
  target/distrib/kipclip-aarch64-apple-darwin.tar.xz.sha256 \
  target/distrib/kipclip-x86_64-apple-darwin.tar.xz \
  target/distrib/kipclip-x86_64-apple-darwin.tar.xz.sha256 \
  target/distrib/kipclip.rb target/distrib/sha256.sum \
  target/distrib/source.tar.gz target/distrib/source.tar.gz.sha256
gh release view "v$VERSION" --json url,isDraft,assets
```

Then publish the tap update. The formula must not be pushed until both archives are present in the published release. Audit using a tap/name (current Homebrew no longer accepts file paths):

```sh
git clone git@github.com:tijs/homebrew-tap.git
cp target/distrib/kipclip.rb homebrew-tap/Formula/kipclip.rb
cd homebrew-tap
brew audit --new --strict tijs/tap/kipclip
git add Formula/kipclip.rb
git commit -m "kipclip $VERSION"
git push
```

Finally, install from the tap on each architecture and confirm `kip --version` matches `$VERSION`.
