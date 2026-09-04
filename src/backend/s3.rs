//! S3-compatible object backend (AWS S3, Cloudflare R2, MinIO, RustFS).

use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Region};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use futures::StreamExt;

use super::{BackendMetadata, BackendReader, ObjectBackend};
use crate::error::{Error, Result};

/// S3-compatible object store backend.
///
/// Construct with [`S3Backend::builder`]. The same backend works with
/// Cloudflare R2, AWS S3, MinIO, and RustFS when given an appropriate endpoint.
#[derive(Clone)]
pub struct S3Backend {
    client: Client,
    bucket: String,
}

impl std::fmt::Debug for S3Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Backend")
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

impl S3Backend {
    /// Start building an [`S3Backend`].
    #[must_use]
    pub fn builder() -> S3BackendBuilder {
        S3BackendBuilder::default()
    }

    /// Borrow the configured bucket name.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}

/// Builder for [`S3Backend`].
#[derive(Debug, Default)]
pub struct S3BackendBuilder {
    endpoint: Option<String>,
    bucket: Option<String>,
    region: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    force_path_style: bool,
}

impl S3BackendBuilder {
    /// S3 API endpoint URL (required for R2 / MinIO / RustFS).
    #[must_use]
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Target bucket name.
    #[must_use]
    pub fn bucket(mut self, bucket: impl Into<String>) -> Self {
        self.bucket = Some(bucket.into());
        self
    }

    /// AWS region, or `"auto"` for Cloudflare R2.
    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Static access key credentials.
    #[must_use]
    pub fn credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self.secret_access_key = Some(secret_access_key.into());
        self
    }

    /// Force path-style addressing (recommended for MinIO / some gateways).
    #[must_use]
    pub fn force_path_style(mut self, enabled: bool) -> Self {
        self.force_path_style = enabled;
        self
    }

    /// Build the backend client.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when required fields are missing.
    pub async fn build(self) -> Result<S3Backend> {
        let bucket = self
            .bucket
            .ok_or_else(|| Error::config("bucket is required"))?;
        let region = self.region.unwrap_or_else(|| "us-east-1".to_string());
        let endpoint = self.endpoint;

        let mut config_loader =
            aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region));

        if let (Some(access_key_id), Some(secret_access_key)) =
            (self.access_key_id, self.secret_access_key)
        {
            let creds = Credentials::new(
                access_key_id,
                secret_access_key,
                None,
                None,
                "pq-objectstore",
            );
            config_loader = config_loader.credentials_provider(creds);
        }

        let shared = config_loader.load().await;
        let mut s3_config = aws_sdk_s3::config::Builder::from(&shared);
        if let Some(endpoint) = endpoint {
            s3_config = s3_config.endpoint_url(endpoint);
        }
        if self.force_path_style {
            s3_config = s3_config.force_path_style(true);
        }

        let client = Client::from_conf(s3_config.build());
        Ok(S3Backend { client, bucket })
    }
}

#[async_trait]
impl ObjectBackend for S3Backend {
    async fn put(&self, key: &str, mut body: BackendReader) -> Result<()> {
        // Buffer the (already encrypted) body so Content-Length is known.
        // Memory usage tracks ciphertext size; callers stream plaintext through
        // the encrypting layer which can spill via chunk framing. For multi-GB
        // objects prefer multipart in a future release.
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(Error::from)?;
            buf.extend_from_slice(&chunk);
        }
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(buf))
            .send()
            .await
            .map_err(Error::backend)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<BackendReader> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::backend)?;
        let aggregated = resp
            .body
            .collect()
            .await
            .map_err(|e| Error::backend(e.to_string()))?;
        let bytes = aggregated.into_bytes();
        let stream = futures::stream::once(async move { Ok::<Bytes, std::io::Error>(bytes) });
        Ok(Box::pin(stream))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::backend)?;
        Ok(())
    }

    async fn head(&self, key: &str) -> Result<BackendMetadata> {
        let resp = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::backend)?;
        Ok(BackendMetadata {
            content_length: resp.content_length().map(|v| v as u64),
            etag: resp.e_tag().map(str::to_string),
        })
    }
}
