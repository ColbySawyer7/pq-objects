//! # pq-objectstore
//!
//! Post-quantum encrypted object storage for Rust **and** TypeScript.
//!
//! Encrypt locally with ML-KEM-768 + AES-256-GCM, then store ciphertext on any
//! S3-compatible backend — or seal bytes in WASM and let a Cloudflare Worker /
//! Next.js route write them to R2.
//!
//! ```text
//! Application / Celld / Next.js Worker
//!         │
//!         ▼
//! ┌───────────────────────┐
//! │    pq-objectstore     │
//! │  ML-KEM-768 + AES-GCM │
//! └──────────┬────────────┘
//!            │ ciphertext (PQOS)
//!            ▼
//!      S3 / R2 / MinIO / RustFS
//! ```
//!
//! # Quick starts
//!
//! ## 1. Rust store (Tokio + S3/R2)
//!
//! ```no_run
//! # #[cfg(all(feature = "store", feature = "local-keys"))]
//! # {
//! use pq_objectstore::{
//!     PqObjectStore,
//!     backend::MemoryBackend,
//!     key::{KeyId, LocalKeyProvider},
//! };
//!
//! # async fn example() -> pq_objectstore::Result<()> {
//! let key_id = KeyId::new("workspace-a-v1")?;
//! let keys = LocalKeyProvider::generate(key_id.clone())?;
//!
//! let store = PqObjectStore::builder()
//!     .backend(MemoryBackend::new())
//!     .key_provider(keys)
//!     .key_id_validated(key_id)
//!     .build()?;
//!
//! store.put_bytes("agents/123/memory.bin", b"secret").await?;
//! let plaintext = store.get_bytes("agents/123/memory.bin").await?;
//! assert_eq!(plaintext, b"secret");
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## 2. Rust seal bytes (no backend)
//!
//! ```
//! use pq_objectstore::crypto::generate_keypair;
//! use pq_objectstore::key::KeyId;
//! use pq_objectstore::seal::{open, seal};
//!
//! let (secret, public) = generate_keypair();
//! let key_id = KeyId::new("workspace-a-v1").unwrap();
//! let ciphertext = seal(b"secret", &public, &key_id).unwrap();
//! assert_eq!(open(&ciphertext, &secret).unwrap(), b"secret");
//! ```
//!
//! ## 3. Cookbook: TypeScript + Cloudflare Worker + R2
//!
//! Build the WASM package once (no Tokio / AWS SDK):
//!
//! ```bash
//! rustup target add wasm32-unknown-unknown
//! wasm-pack build --target web --out-dir pkg \
//!   -- --no-default-features --features "wasm,local-keys"
//! ```
//!
//! Cargo dependency equivalent:
//!
//! ```toml
//! pq-objectstore = { version = "0.1", default-features = false, features = ["wasm", "local-keys"] }
//! ```
//!
//! ### Worker flow
//!
//! ```text
//! TS Worker                         pq-objectstore (wasm)
//! ─────────                         ────────────────────
//! plaintext ── seal() ────────────► PQOS ciphertext
//!      │
//!      └── await env.MY_BUCKET.put(key, ct)
//!
//! ct = await env.MY_BUCKET.get(key)
//! plaintext ◄── open(ct, secretSeed)
//! ```
//!
//! ### Example Worker (TypeScript)
//!
//! ```ts
//! import init, {
//!   PqosKeypair,
//!   seal,
//!   open,
//!   peekKeyId,
//! } from "../pkg/pq_objectstore.js";
//!
//! export interface Env {
//!   MY_BUCKET: R2Bucket;
//!   // 64-byte ML-KEM seed, base64 — never commit real secrets
//!   PQ_SECRET_SEED_B64: string;
//! }
//!
//! let wasmReady: Promise<void> | undefined;
//!
//! function ensureWasm() {
//!   wasmReady ??= init().then(() => undefined);
//!   return wasmReady;
//! }
//!
//! function loadKeys(env: Env): PqosKeypair {
//!   const seed = Uint8Array.from(atob(env.PQ_SECRET_SEED_B64), (c) =>
//!     c.charCodeAt(0),
//!   );
//!   return PqosKeypair.fromSecretSeed(seed);
//! }
//!
//! export default {
//!   async fetch(req: Request, env: Env): Promise<Response> {
//!     await ensureWasm();
//!     const keys = loadKeys(env);
//!     const keyId = "workspace-a-v1";
//!     const url = new URL(req.url);
//!     const objectKey = url.pathname.replace(/^\//, "") || "demo.bin";
//!
//!     if (req.method === "PUT") {
//!       const plaintext = new Uint8Array(await req.arrayBuffer());
//!       const ciphertext = seal(plaintext, keys.publicKey, keyId);
//!       await env.MY_BUCKET.put(objectKey, ciphertext);
//!       return new Response(null, { status: 204 });
//!     }
//!
//!     if (req.method === "GET") {
//!       const obj = await env.MY_BUCKET.get(objectKey);
//!       if (!obj) return new Response("not found", { status: 404 });
//!       const ct = new Uint8Array(await obj.arrayBuffer());
//!       // peekKeyId(ct) selects which seed to use after rotation
//!       const _which = peekKeyId(ct);
//!       const plaintext = open(ct, keys.secretSeed);
//!       return new Response(plaintext, {
//!         headers: { "content-type": "application/octet-stream" },
//!       });
//!     }
//!
//!     return new Response("method not allowed", { status: 405 });
//!   },
//! };
//! ```
//!
//! ### Next.js note
//!
//! Same WASM module works from a Cloudflare-hosted Next.js route or OpenNext
//! Worker: import `pkg/pq_objectstore.js`, `await init()`, then `seal` /
//! `open` before `env.MY_BUCKET.put` / `.get`. Keep the 64-byte secret seed in
//! Worker secrets (`wrangler secret`), not in the client bundle.
//!
//! See also [`mod@wasm`] (feature `wasm`) and [`mod@seal`].
//!
//! # Architecture
//!
//! Each object receives a unique AES-256-GCM data-encryption key (DEK). That DEK
//! is wrapped using an ML-KEM-768 shared secret derived from a long-lived key.
//! Object payloads use a chunked STREAM construction.
//!
//! # Security model
//!
//! The storage backend is untrusted. Payload contents and DEKs are protected;
//! object keys/paths and sizes are not. Prefer opaque object IDs when metadata
//! confidentiality matters.
//!
//! # Features
//!
//! - `store` (default): async [`PqObjectStore`] + backends
//! - `s3` (default): Cloudflare R2 / AWS S3 / MinIO / RustFS backend
//! - `local-keys` (default): [`key::LocalKeyProvider`]
//! - `wasm`: `wasm-bindgen` exports (`PqosKeypair`, `seal`, `open`, `peekKeyId`)
//! - `tracing`: optional structured logging (never logs secrets)

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod crypto;
pub mod error;
pub mod format;
pub mod key;
pub mod seal;

#[cfg(feature = "store")]
pub mod backend;
#[cfg(feature = "store")]
pub mod store;

#[cfg(feature = "wasm")]
#[cfg_attr(docsrs, doc(cfg(feature = "wasm")))]
pub mod wasm;

pub use error::{Error, Result};
pub use key::KeyId;
pub use seal::{SealInfo, open, peek_header, seal, seal_with_info};

#[cfg(feature = "store")]
pub use key::KeyProvider;
#[cfg(feature = "store")]
pub use store::{
    EncryptedObjectStore, EncryptedReader, ObjectMetadata, PqObjectStore, PqObjectStoreBuilder,
    PutResult,
};

#[cfg(feature = "local-keys")]
pub use key::LocalKeyProvider;
