//! Encrypt an object to Cloudflare R2.
//!
//! Required environment variables:
//!
//! - `R2_ENDPOINT`
//! - `R2_ACCESS_KEY_ID`
//! - `R2_SECRET_ACCESS_KEY`
//! - `R2_BUCKET`
//! - `PQ_KEY_FILE` — path to a key file created with this example or `local_key`
//!
//! ```bash
//! cargo run --example r2
//! ```

use std::env;
use std::path::PathBuf;

use pq_objectstore::PqObjectStore;
use pq_objectstore::backend::S3Backend;
use pq_objectstore::key::LocalKeyProvider;

#[tokio::main]
async fn main() -> pq_objectstore::Result<()> {
    let endpoint = env::var("R2_ENDPOINT").expect("R2_ENDPOINT");
    let access_key = env::var("R2_ACCESS_KEY_ID").expect("R2_ACCESS_KEY_ID");
    let secret_key = env::var("R2_SECRET_ACCESS_KEY").expect("R2_SECRET_ACCESS_KEY");
    let bucket = env::var("R2_BUCKET").expect("R2_BUCKET");
    let key_file = PathBuf::from(env::var("PQ_KEY_FILE").expect("PQ_KEY_FILE"));

    let keys = LocalKeyProvider::new();
    let key_id = if key_file.exists() {
        keys.load_key(&key_file)?
    } else {
        let id = pq_objectstore::KeyId::new("workspace-a-v1")?;
        keys.insert_generated(id.clone())?;
        keys.save_key(&id, &key_file)?;
        println!("wrote new key to {}", key_file.display());
        id
    };

    // R2: region "auto", the account endpoint, and checksums only when the
    // operation requires them (the backend disables x-amz-checksum-algorithm).
    // force_path_style is available on the builder for path-style gateways.
    let backend = S3Backend::builder()
        .endpoint(endpoint)
        .bucket(bucket)
        .region("auto")
        .credentials(access_key, secret_key)
        .build()
        .await?;

    let store = PqObjectStore::builder()
        .backend(backend)
        .key_provider(keys)
        .key_id_validated(key_id)
        .build()?;

    let object_key = "examples/r2/demo.bin";
    let payload = b"cloudflare r2 encrypted payload";
    let put = store.put_bytes(object_key, payload).await?;
    println!("stored {} ciphertext bytes", put.content_length);
    let recovered = store.get_bytes(object_key).await?;
    assert_eq!(recovered, payload);
    println!("r2 round-trip ok for {object_key}");
    Ok(())
}
