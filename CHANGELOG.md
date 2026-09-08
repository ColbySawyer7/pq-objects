# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-08

### Added

- Sync `seal` / `open` / `peek_header` byte API (no object backend)
- `store` feature gating Tokio / backends (disable for wasm)
- `wasm` feature with `wasm-bindgen` exports for Workers / Next.js
- TypeScript + Cloudflare Worker + R2 cookbook in README and rustdoc
- `examples/seal_bytes.rs` and wasm CI check
- `scripts/release.sh` for tagged crates.io publishes

## [0.1.0] - 2026-09-04

### Added

- ML-KEM-768 envelope encryption for per-object data keys
- AES-256-GCM STREAM object encryption (64 KiB chunks)
- Versioned `PQOS` object header format
- `KeyProvider` trait and `LocalKeyProvider`
- Key IDs for write/read rotation
- S3-compatible backend (Cloudflare R2, AWS S3, MinIO, RustFS)
- In-memory backend for tests and embedding
- Builder-style `PqObjectStore` API with streaming `AsyncRead` put/get
- Convenience helpers: `put_bytes`, `get_bytes`, `put_file`, `get_file`, `exists`
- Examples for local keys, R2, and MinIO
- GitHub Actions CI and crates.io release workflow
