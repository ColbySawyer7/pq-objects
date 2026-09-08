//! Seal bytes without an object backend — JS/Worker owns R2.
//!
//! ```bash
//! cargo run --example seal_bytes --no-default-features --features local-keys
//! ```

use pq_objectstore::crypto::generate_keypair;
use pq_objectstore::key::KeyId;
use pq_objectstore::seal::{open, peek_header, seal};

fn main() -> pq_objectstore::Result<()> {
    let (secret, public) = generate_keypair();
    let key_id = KeyId::new("workspace-a-v1")?;

    let plaintext = b"cell memory for worker";
    let ciphertext = seal(plaintext, &public, &key_id)?;
    println!(
        "sealed {} plaintext bytes -> {} PQOS bytes (key_id={})",
        plaintext.len(),
        ciphertext.len(),
        peek_header(&ciphertext)?.key_id
    );

    // Hand `ciphertext` to R2 from TS, e.g.:
    //   await env.BUCKET.put(objectKey, ciphertext)
    let recovered = open(&ciphertext, &secret)?;
    assert_eq!(recovered, plaintext);
    println!("open ok");
    Ok(())
}
