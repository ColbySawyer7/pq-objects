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
- **Wasm-ready** — sync `seal` / `open` for Next.js Cloudflare Workers (JS owns R2)

## Installation

```toml
[dependencies]
pq-objectstore = "0.2"
```

For Workers / wasm only (no Tokio / AWS SDK):

```toml
[dependencies]
pq-objectstore = { version = "0.2", default-features = false, features = ["wasm", "local-keys"] }
```

## Quick Start

### Rust store

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

### Cookbook: TypeScript + Cloudflare Worker + R2

Rust/WASM seals bytes; your Worker owns R2:

```text
TS Worker                         pq-objectstore (wasm)
─────────                         ────────────────────
plaintext ── seal() ────────────► PQOS ciphertext
     │
     └── await env.MY_BUCKET.put(key, ct)

ct = await env.MY_BUCKET.get(key)
plaintext ◄── open(ct, secretSeed)
```

**1. Build the package**

```bash
rustup target add wasm32-unknown-unknown
wasm-pack build --target web --out-dir pkg \
  -- --no-default-features --features "wasm,local-keys"
```

**2. Worker example**

```ts
import init, {
  PqosKeypair,
  seal,
  open,
  peekKeyId,
} from "../pkg/pq_objectstore.js";

export interface Env {
  MY_BUCKET: R2Bucket;
  /** 64-byte ML-KEM seed, base64 — set via `wrangler secret` */
  PQ_SECRET_SEED_B64: string;
}

let wasmReady: Promise<void> | undefined;

function ensureWasm() {
  wasmReady ??= init().then(() => undefined);
  return wasmReady;
}

function loadKeys(env: Env): PqosKeypair {
  const seed = Uint8Array.from(atob(env.PQ_SECRET_SEED_B64), (c) =>
    c.charCodeAt(0),
  );
  return PqosKeypair.fromSecretSeed(seed);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    await ensureWasm();
    const keys = loadKeys(env);
    const keyId = "workspace-a-v1";
    const objectKey = new URL(req.url).pathname.replace(/^\//, "") || "demo.bin";

    if (req.method === "PUT") {
      const plaintext = new Uint8Array(await req.arrayBuffer());
      const ciphertext = seal(plaintext, keys.publicKey, keyId);
      await env.MY_BUCKET.put(objectKey, ciphertext);
      return new Response(null, { status: 204 });
    }

    if (req.method === "GET") {
      const obj = await env.MY_BUCKET.get(objectKey);
      if (!obj) return new Response("not found", { status: 404 });
      const ct = new Uint8Array(await obj.arrayBuffer());
      const _whichKey = peekKeyId(ct); // use after rotation
      const plaintext = open(ct, keys.secretSeed);
      return new Response(plaintext);
    }

    return new Response("method not allowed", { status: 405 });
  },
};
```

**3. Next.js on Cloudflare**

Same module from a Cloudflare-hosted route / OpenNext Worker: `await init()`,
then `seal` / `open` before `env.MY_BUCKET.put` / `.get`. Keep `secretSeed` in
Worker secrets — never ship it to the browser.

**4. Native Rust seal (no WASM)**

```rust
use pq_objectstore::crypto::generate_keypair;
use pq_objectstore::key::KeyId;
use pq_objectstore::seal::{open, seal};

let (secret, public) = generate_keypair();
let key_id = KeyId::new("workspace-a-v1")?;
let ct = seal(b"secret", &public, &key_id)?;
assert_eq!(open(&ct, &secret)?, b"secret");
```

The same cookbook lives on the [docs.rs crate page](https://docs.rs/pq-objectstore)
under **Quick starts → Cookbook: TypeScript + Cloudflare Worker + R2**.

## Large objects

`put` / `put_file` encrypt STREAM chunks and hand ciphertext to the backend as
it is produced. There is no second full ciphertext file on disk. The S3
backend uploads that stream as multipart parts of 8 MiB (the last part may be
shorter), at most 10,000 parts, and aborts the upload if a part fails.

`PutResult::content_length` is the ciphertext size. A later `head` returns the
same number when the upload finished. `list` pages keys under a prefix, with
each object's ciphertext size, using continuation tokens.

`get` / `get_file` decrypt one chunk at a time and can write plaintext straight
to a restore path.

A backup host can encrypt with a recipient file (public key only). The 64-byte
seed stays on the machine that decrypts:

```rust
keys.save_recipient(&id, "backup.pk")?;

let backup_host = LocalKeyProvider::new();
let key_id = backup_host.load_recipient("backup.pk")?;
```

Cloudflare R2 needs `region("auto")`, the account endpoint, and checksums only
when the operation requires them. `S3Backend` sets that checksum mode so R2
does not see `x-amz-checksum-algorithm`. `force_path_style` is on the builder.

## Cloudflare R2 (Rust S3 backend)

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
`save_recipient` writes the public key for hosts that only encrypt.

```text
Generate v2 → publish public key → set v2 active
    → new writes use v2 → v1 remains for reads → retire v1
```

## Features / Backends

| Feature | Default | Purpose |
| --- | --- | --- |
| `store` | yes | Async `PqObjectStore` + backends |
| `s3` | yes | R2 / S3 / MinIO / RustFS |
| `local-keys` | yes | `LocalKeyProvider` |
| `wasm` | no | `wasm-bindgen` `seal` / `open` / `PqosKeypair` |

| Backend | Feature | Notes |
| --- | --- | --- |
| Cloudflare R2 | `s3` | `region = "auto"` |
| AWS S3 | `s3` | Standard AWS endpoints |
| MinIO / RustFS | `s3` | Path-style friendly |
| `MemoryBackend` | `store` | Tests and local embedding |
| Byte `seal` / `open` | always | JS/Worker owns storage |

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
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

