# Contributing

Thanks for contributing to `pq-objectstore`.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo package --allow-dirty
```

## Guidelines

* Prefer small, reviewable PRs.
* Do not introduce `unsafe` code without a compelling, documented reason.
* Do not add casually configurable crypto algorithm feature flags.
* Never log private keys, DEKs, shared secrets, plaintext, or credentials.
* Keep the dependency tree intentionally small.

## Release process

Use the helper script (bumps `Cargo.toml` + `CHANGELOG.md`, tags, pushes):

```bash
./scripts/release.sh           # asks: major? → minor? → else patch
./scripts/release.sh patch     # 0.1.0 -> 0.1.1
./scripts/release.sh minor     # 0.1.0 -> 0.2.0
./scripts/release.sh major     # 0.1.0 -> 1.0.0
```

Pushing tag `vX.Y.Z` runs `.github/workflows/release.yml`, which publishes to
crates.io (requires the `CARGO_REGISTRY_TOKEN` repo secret) and creates a
GitHub Release.

Manual checklist if not using the script:

1. Update `CHANGELOG.md` and `Cargo.toml` version.
2. Tag `vX.Y.Z` matching the Cargo version.
3. Push the tag; the release workflow publishes to crates.io.
