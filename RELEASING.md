# Releasing kip

Releases are built locally: bump `Cargo.toml` and `CHANGELOG.md`, commit, and tag the matching `vX.Y.Z` release. Build artifacts on matching Apple Silicon and Intel Macs (or a Mac that can build both targets), then collect their `target/distrib/` contents in one checkout:

```sh
cargo install cargo-dist --version 0.32.0 --locked
VERSION=0.1.3

# Write each manifest outside target/distrib first: dist reads manifests there.
dist build --tag "v$VERSION" --artifacts=local --target aarch64-apple-darwin --output-format=json > /tmp/kip-arm-manifest.json
mv /tmp/kip-arm-manifest.json target/distrib/aarch64-apple-darwin-dist-manifest.json

dist build --tag "v$VERSION" --artifacts=local --target x86_64-apple-darwin --output-format=json > /tmp/kip-intel-manifest.json
mv /tmp/kip-intel-manifest.json target/distrib/x86_64-apple-darwin-dist-manifest.json

dist build --tag "v$VERSION" --artifacts=global
```

Before publishing, inspect the two `.tar.xz` archives and their `.sha256` files in `target/distrib/`. With a GitHub token that can create releases:

```sh
GH_TOKEN="$(gh auth token)" dist host --tag "v$VERSION" --steps=create --steps=upload --steps=release
```

Then update the tap with the generated formula. The formula must not be published until both archives are present:

```sh
git clone git@github.com:tijs/homebrew-tap.git
cp target/distrib/kipclip.rb homebrew-tap/Formula/kipclip.rb
cd homebrew-tap
brew audit --new --strict Formula/kipclip.rb
git add Formula/kipclip.rb
git commit -m "kipclip $VERSION"
git push
```

Finally, install from the tap on each architecture and confirm `kip --version` matches `$VERSION`.
