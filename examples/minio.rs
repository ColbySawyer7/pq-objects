//! Encrypt an object against a local MinIO / RustFS endpoint.
//!
//! Required environment variables:
//!
//! - `S3_ENDPOINT` (e.g. `http://127.0.0.1:9000`)
//! - `S3_ACCESS_KEY_ID`
//! - `S3_SECRET_ACCESS_KEY`
//! - `S3_BUCKET`
//! - `PQ_KEY_FILE`
//!
//! ```bash
//! cargo run --example minio
//! ```

use std::env;
use std::path::PathBuf;

use pq_objectstore::PqObjectStore;
use pq_objectstore::backend::S3Backend;
use pq_objectstore::key::LocalKeyProvider;

#[tokio::main]
async fn main() -> pq_objectstore::Result<()> {
    let endpoint = env::var("S3_ENDPOINT").expect("S3_ENDPOINT");
    let access_key = env::var("S3_ACCESS_KEY_ID").expect("S3_ACCESS_KEY_ID");
    let secret_key = env::var("S3_SECRET_ACCESS_KEY").expect("S3_SECRET_ACCESS_KEY");
    let bucket = env::var("S3_BUCKET").expect("S3_BUCKET");
    let key_file = PathBuf::from(env::var("PQ_KEY_FILE").expect("PQ_KEY_FILE"));
    let region = env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());

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

    let backend = S3Backend::builder()
        .endpoint(endpoint)
        .bucket(bucket)
        .region(region)
        .credentials(access_key, secret_key)
        .force_path_style(true)
        .build()
        .await?;

    let store = PqObjectStore::builder()
        .backend(backend)
        .key_provider(keys)
        .key_id_validated(key_id)
        .build()?;

    let object_key = "examples/minio/demo.bin";
    let payload = b"minio encrypted payload";
    store.put_bytes(object_key, payload).await?;
    let recovered = store.get_bytes(object_key).await?;
    assert_eq!(recovered, payload);
    println!("minio round-trip ok for {object_key}");
    Ok(())
}
