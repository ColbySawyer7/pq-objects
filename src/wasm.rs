//! `wasm-bindgen` exports for Cloudflare Workers / Next.js.
//!
//! # Build
//!
//! ```bash
//! rustup target add wasm32-unknown-unknown
//! wasm-pack build --target web --out-dir pkg \
//!   -- --no-default-features --features "wasm,local-keys"
//! ```
//!
//! # TypeScript quick start
//!
//! ```ts
//! import init, { PqosKeypair, seal, open, peekKeyId } from "./pkg/pq_objectstore.js";
//!
//! await init();
//!
//! // Generate once; persist secretSeed (64 bytes) in a Worker secret.
//! const keys = new PqosKeypair();
//! // const keys = PqosKeypair.fromSecretSeed(seedBytes);
//!
//! const keyId = "workspace-a-v1";
//! const ciphertext = seal(plaintextBytes, keys.publicKey, keyId);
//! await env.MY_BUCKET.put(objectKey, ciphertext);
//!
//! const obj = await env.MY_BUCKET.get(objectKey);
//! const ct = new Uint8Array(await obj.arrayBuffer());
//! const whichKey = peekKeyId(ct); // rotation
//! const plaintext = open(ct, keys.secretSeed);
//! ```
//!
//! JS owns R2 (or any store). This module only seals / opens PQOS bytes.
//!
//! Full Worker cookbook: crate-level docs on [docs.rs/pq-objectstore](https://docs.rs/pq-objectstore).

use wasm_bindgen::prelude::*;

use crate::crypto::{PublicKey, SecretKey, generate_keypair};
use crate::key::KeyId;
use crate::seal::{open as seal_open, peek_header, seal as seal_bytes};

fn js_err(err: impl core::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}

/// ML-KEM-768 keypair for JS (public key + 64-byte secret seed).
#[wasm_bindgen(js_name = PqosKeypair)]
pub struct PqosKeypair {
    public_key: Vec<u8>,
    secret_seed: Vec<u8>,
}

#[wasm_bindgen(js_class = PqosKeypair)]
impl PqosKeypair {
    /// Generate a fresh keypair using the Web Crypto CSPRNG.
    #[wasm_bindgen(constructor)]
    pub fn generate() -> PqosKeypair {
        let (secret, public) = generate_keypair();
        Self {
            public_key: public.as_bytes().to_vec(),
            secret_seed: secret.as_bytes().to_vec(),
        }
    }

    /// Restore from a 64-byte secret seed.
    #[wasm_bindgen(js_name = fromSecretSeed)]
    pub fn from_secret_seed(secret_seed: &[u8]) -> Result<PqosKeypair, JsError> {
        let secret = SecretKey::from_seed(secret_seed).map_err(js_err)?;
        let (_, public) = crate::crypto::kem::keypair_from_seed(&secret);
        Ok(Self {
            public_key: public.as_bytes().to_vec(),
            secret_seed: secret.as_bytes().to_vec(),
        })
    }

    /// ML-KEM-768 public key bytes (1184).
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// 64-byte secret seed (private).
    #[wasm_bindgen(getter, js_name = secretSeed)]
    pub fn secret_seed(&self) -> Vec<u8> {
        self.secret_seed.clone()
    }
}

/// Encrypt `plaintext` to PQOS ciphertext bytes.
///
/// `public_key` is the 1184-byte ML-KEM-768 encapsulation key.
/// `key_id` is recorded in the object header for rotation.
#[wasm_bindgen(js_name = seal)]
pub fn wasm_seal(plaintext: &[u8], public_key: &[u8], key_id: &str) -> Result<Vec<u8>, JsError> {
    let pk = PublicKey::from_bytes(public_key).map_err(js_err)?;
    let id = KeyId::new(key_id).map_err(js_err)?;
    seal_bytes(plaintext, &pk, &id).map_err(js_err)
}

/// Decrypt PQOS ciphertext with a 64-byte ML-KEM secret seed.
#[wasm_bindgen(js_name = open)]
pub fn wasm_open(ciphertext: &[u8], secret_seed: &[u8]) -> Result<Vec<u8>, JsError> {
    let sk = SecretKey::from_seed(secret_seed).map_err(js_err)?;
    seal_open(ciphertext, &sk).map_err(js_err)
}

/// Return the `key_id` from a PQOS object header (no decryption).
#[wasm_bindgen(js_name = peekKeyId)]
pub fn wasm_peek_key_id(ciphertext: &[u8]) -> Result<String, JsError> {
    let header = peek_header(ciphertext).map_err(js_err)?;
    Ok(header.key_id.as_str().to_string())
}
