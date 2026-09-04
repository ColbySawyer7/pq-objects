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

1. Update `CHANGELOG.md` and `Cargo.toml` version.
2. Tag `vX.Y.Z` matching the Cargo version.
3. Push the tag; the release workflow publishes to crates.io.
