# pq-objectstore

**Post-quantum encrypted object storage for Rust** — encrypt locally with
ML-KEM-768 + AES-256-GCM, then store ciphertext on any S3-compatible backend.

Cloudflare R2, AWS S3, MinIO, RustFS, and in-process memory are all fair game.
The bucket is treated as an untrusted ciphertext store.

```text
Application / Celld
        │
        ▼
┌───────────────────────┐
│    pq-objectstore     │
│  ML-KEM-768 + AES-GCM │
└──────────┬────────────┘
           │ ciphertext
           ▼
     S3-compatible API  →  R2 · S3 · MinIO · RustFS
```

## Performance

Crypto on this crate is fast enough that **network and disk dominate** real
deployments. Measured on this machine with `cargo run --release --example bench`
(in-memory backend — no S3/network):

### Streaming throughput

| Object size | Encrypt + put | Decrypt + get |
| ----------- | ------------- | ------------- |
| 1 KiB       | 3.5 MiB/s     | 9.0 MiB/s     |
| 64 KiB      | 82 MiB/s      | 184 MiB/s     |
| 1 MiB       | **136 MiB/s** | **260 MiB/s** |
| 10 MiB      | **136 MiB/s** | **240 MiB/s** |
| 100 MiB     | **126 MiB/s** | **250 MiB/s** |

Large objects settle around **~130 MiB/s encrypt** and **~250 MiB/s decrypt**
once STREAM chunks amortize the per-object ML-KEM wrap.

### Small-object latency (18-byte payload, p50)

| Path      | Latency  |
| --------- | -------- |
| `put`     | 232 µs   |
| `get`     | 92 µs    |
| round-trip | **328 µs** |

### ML-KEM-768 microbenchmarks

| Operation     | Mean latency |
| ------------- | ------------ |
| Key generation | 44 µs       |
| Encapsulation  | 43 µs       |
| Decapsulation  | 85 µs       |

<details>
<summary>Benchmark environment</summary>

| | |
| --- | --- |
| Date | 2026-09-04 |
| Host | Ubuntu 24.04.4 LTS, Linux 6.8 |
| CPU | QEMU Virtual CPU 2.5+ · 20 vCPUs |
| RAM | 31 GiB |
| Rust | `rustc 1.97.1` · `--release` |
| Suite | ML-KEM-768 + AES-256-GCM STREAM (64 KiB chunks) |
| Backend | `MemoryBackend` (crypto + PQOS framing only) |

Reproduce:

```bash
cargo run --release --example bench
```

</details>

## Why pq-objectstore?

- **Post-quantum** — ML-KEM-768 (FIPS 203) protects every object's data key
- **Fast enough to forget** — hundred-plus MiB/s bulk crypto on commodity CPUs
- **Transparent API** — `put` / `get` instead of hand-rolled envelope encryption
- **Key rotation** — each object records a `key_id`; old keys stay readable
- **Embeddable** — small surface area for Celld, agents, and services

## Installation

```toml
[dependencies]
pq-objectstore = "0.1"
```

## Quick Start

```rust
use pq_objectstore::{
    PqObjectStore,
    backend::MemoryBackend,
    key::{KeyId, LocalKeyProvider},
};

#[tokio::main]
async fn main() -> pq_objectstore::Result<()> {
    let key_id = KeyId::new("workspace-a-v1")?;
    let keys = LocalKeyProvider::generate(key_id.clone())?;

    let store = PqObjectStore::builder()
        .backend(MemoryBackend::new())
        .key_provider(keys)
        .key_id_validated(key_id)
        .build()?;

    store.put_bytes("agents/123/memory.bin", b"secret").await?;
    let plaintext = store.get_bytes("agents/123/memory.bin").await?;
    assert_eq!(plaintext, b"secret");
    Ok(())
}
```

## Cloudflare R2

```bash
export R2_ENDPOINT=https://<accountid>.r2.cloudflarestorage.com
export R2_ACCESS_KEY_ID=...
export R2_SECRET_ACCESS_KEY=...
export R2_BUCKET=celld-data
export PQ_KEY_FILE=./workspace-a-v1.key

cargo run --example r2
```

Credentials belong in the environment — never in source or docs.

## Security Model

| Protected | Not necessarily protected |
| --- | --- |
| Object payload contents | Bucket names |
| Data encryption keys | Object keys / paths |
| Integrity of ciphertext | Object sizes, timing, account metadata |

Paths like `/cells/acme-secret-project/memory` still leak metadata. Prefer opaque
object IDs when that matters. See [SECURITY.md](SECURITY.md).

## Key Management

Long-lived private keys live in a `KeyProvider`, never inside object storage.
Writes use the configured active `key_id`; reads honor the ID in each header.

```text
Generate v2 → publish public key → set v2 active
    → new writes use v2 → v1 remains for reads → retire v1
```

## Supported Backends

| Backend | Feature | Notes |
| --- | --- | --- |
| Cloudflare R2 | `s3` | `region = "auto"` |
| AWS S3 | `s3` | Standard AWS endpoints |
| MinIO / RustFS | `s3` | Path-style friendly |
| `MemoryBackend` | always | Tests and local embedding |

## Object Format

Encrypted objects start with a versioned `PQOS` header:

```text
magic · version · suite · key_id · ML-KEM ct · wrapped DEK · STREAM nonce
                    ↓
            AES-256-GCM STREAM chunks (64 KiB plaintext)
```

## MSRV

Rust **1.94** or newer.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

