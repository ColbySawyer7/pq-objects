//! Generate a local ML-KEM key and round-trip an encrypted object in memory.
//!
//! ```bash
//! cargo run --example local_key
//! ```

use pq_objectstore::PqObjectStore;
use pq_objectstore::backend::MemoryBackend;
use pq_objectstore::key::{KeyId, LocalKeyProvider};

#[tokio::main]
async fn main() -> pq_objectstore::Result<()> {
    let key_id = KeyId::new("workspace-a-v1")?;
    let keys = LocalKeyProvider::generate(key_id.clone())?;

    let store = PqObjectStore::builder()
        .backend(MemoryBackend::new())
        .key_provider(keys)
        .key_id_validated(key_id)
        .build()?;

    store
        .put_bytes("agents/123/memory.bin", b"hello from local_key example")
        .await?;
    let out = store.get_bytes("agents/123/memory.bin").await?;
    println!("recovered: {}", String::from_utf8_lossy(&out));
    Ok(())
}
