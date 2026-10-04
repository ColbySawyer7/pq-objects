//! S3-compatible object backend (AWS S3, Cloudflare R2, MinIO, RustFS).

use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{
    BehaviorVersion, Region, RequestChecksumCalculation, ResponseChecksumValidation,
};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use bytes::Bytes;
use futures::StreamExt;

use super::{BackendBody, BackendMetadata, BackendReader, ListPage, ListedObject, ObjectBackend};
use crate::error::{Error, Result};

/// Every part except the last is this size.
///
/// S3 and R2 require that size to be at least 5 MiB. 8 MiB keeps a 25 GiB
/// object near 3,200 parts, under the 10,000 part cap (about 80 GiB total).
const PART_SIZE: usize = 8 * 1024 * 1024;

/// S3 multipart uploads accept at most this many parts.
const MAX_PARTS: i32 = 10_000;

const _: () = {
    assert!(PART_SIZE >= 5 * 1024 * 1024);
    assert!(MAX_PARTS == 10_000);
};

/// S3-compatible object store backend.
///
/// Construct with [`S3Backend::builder`]. The same backend works with
/// Cloudflare R2, AWS S3, MinIO, and RustFS when given an appropriate endpoint.
///
/// Puts stream ciphertext into a multipart upload. Each part has a known
/// `Content-Length`. A failed part aborts the upload. Checksums are calculated
/// only when the operation requires them, because Cloudflare R2 rejects
/// `x-amz-checksum-algorithm`.
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

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<CompletedPart> {
        check_part_number(part_number)?;
        let content_length = i64::try_from(body.len())
            .map_err(|_| Error::backend("multipart part exceeds Content-Length range"))?;
        let output = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .content_length(content_length)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(Error::backend)?;
        let etag = output
            .e_tag()
            .ok_or_else(|| Error::backend("upload part response missing e_tag"))?;
        Ok(CompletedPart::builder()
            .part_number(part_number)
            .e_tag(etag)
            .build())
    }

    async fn abort_upload(&self, key: &str, upload_id: &str) -> Result<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(Error::backend)?;
        Ok(())
    }
}

/// Builder for [`S3Backend`].
///
/// Cloudflare R2 needs `region("auto")`, the account endpoint, and
/// `force_path_style` when the gateway requires path-style keys. The built
/// client sends checksum headers only for operations that require them.
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
        let mut s3_config = aws_sdk_s3::config::Builder::from(&shared)
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired);
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
    async fn put(&self, key: &str, body: BackendReader<'_>) -> Result<u64> {
        let mut parts_src = PartReader::new(body);
        let Some(first) = parts_src.next_part(PART_SIZE).await? else {
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .content_length(0)
                .body(ByteStream::from(Bytes::new()))
                .send()
                .await
                .map_err(Error::backend)?;
            return Ok(0);
        };

        let created = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::backend)?;
        let upload_id = created
            .upload_id()
            .ok_or_else(|| Error::backend("multipart upload id missing"))?
            .to_string();

        match self
            .upload_parts(key, &upload_id, first, &mut parts_src)
            .await
        {
            Ok(total) => Ok(total),
            Err(err) => Err(self.fail_upload(key, &upload_id, err).await),
        }
    }

    async fn get(&self, key: &str) -> Result<BackendBody> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(Error::backend)?;
        Ok(Box::new(resp.body.into_async_read()))
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

    async fn list(&self, prefix: &str, continuation_token: Option<&str>) -> Result<ListPage> {
        let mut req = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix);
        if let Some(token) = continuation_token {
            req = req.continuation_token(token);
        }
        let resp = req.send().await.map_err(Error::backend)?;
        let mut objects = Vec::new();
        for object in resp.contents() {
            let Some(key) = object.key() else {
                continue;
            };
            let size = u64::try_from(object.size().unwrap_or(0)).unwrap_or(0);
            objects.push(ListedObject {
                key: key.to_string(),
                size,
            });
        }
        let continuation_token = if resp.is_truncated().unwrap_or(false) {
            Some(
                resp.next_continuation_token()
                    .ok_or_else(|| Error::backend("truncated list missing continuation token"))?
                    .to_string(),
            )
        } else {
            None
        };
        Ok(ListPage {
            objects,
            continuation_token,
        })
    }
}

impl S3Backend {
    async fn upload_parts(
        &self,
        key: &str,
        upload_id: &str,
        first: Bytes,
        parts_src: &mut PartReader<'_>,
    ) -> Result<u64> {
        let mut completed = Vec::new();
        let mut total = 0u64;
        let mut part_number = 1i32;
        let mut next = Some(first);
        while let Some(part) = next {
            let n = part.len() as u64;
            completed.push(self.upload_part(key, upload_id, part_number, part).await?);
            total += n;
            part_number = part_number
                .checked_add(1)
                .ok_or_else(|| Error::backend("multipart part number overflow"))?;
            next = parts_src.next_part(PART_SIZE).await?;
        }

        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(upload)
            .send()
            .await
            .map_err(Error::backend)?;

        #[cfg(feature = "tracing")]
        tracing::debug!(
            object_key = %key,
            bytes = total,
            "multipart put complete"
        );
        Ok(total)
    }

    async fn fail_upload(&self, key: &str, upload_id: &str, err: Error) -> Error {
        match self.abort_upload(key, upload_id).await {
            Ok(()) => err,
            Err(abort_err) => Error::backend(format!(
                "{err}; failed to abort multipart upload: {abort_err}"
            )),
        }
    }
}

fn check_part_number(part_number: i32) -> Result<()> {
    if !(1..=MAX_PARTS).contains(&part_number) {
        return Err(Error::backend(format!(
            "multipart upload exceeds {MAX_PARTS} parts"
        )));
    }
    Ok(())
}

struct PartReader<'a> {
    body: BackendReader<'a>,
    carry: Bytes,
}

impl<'a> PartReader<'a> {
    fn new(body: BackendReader<'a>) -> Self {
        Self {
            body,
            carry: Bytes::new(),
        }
    }

    /// Read the next part. Full parts are exactly `part_size` bytes. The final
    /// part is shorter when the stream ends first. `None` means the stream is
    /// exhausted.
    async fn next_part(&mut self, part_size: usize) -> Result<Option<Bytes>> {
        if part_size == 0 {
            return Err(Error::backend("multipart part size must be non-zero"));
        }
        let mut buf = Vec::new();
        while buf.len() < part_size {
            if self.carry.is_empty() {
                match self.body.next().await {
                    None => break,
                    Some(Err(err)) => return Err(crate::error::error_from_io(err)),
                    Some(Ok(chunk)) if chunk.is_empty() => continue,
                    Some(Ok(chunk)) => self.carry = chunk,
                }
            }
            let need = part_size - buf.len();
            if self.carry.len() <= need {
                buf.extend_from_slice(&self.carry);
                self.carry = Bytes::new();
            } else {
                buf.extend_from_slice(&self.carry[..need]);
                self.carry = self.carry.slice(need..);
            }
        }
        if buf.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Bytes::from(buf)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_numbers_start_at_one_and_stop_at_the_cap() {
        assert!(check_part_number(1).is_ok());
        assert!(check_part_number(MAX_PARTS).is_ok());
        assert!(check_part_number(0).is_err());
        assert!(check_part_number(MAX_PARTS + 1).is_err());
    }

    #[tokio::test]
    async fn parts_are_equal_until_the_last() {
        let data = vec![7u8; 100];
        let stream = futures::stream::iter(vec![
            Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(&data[..30])),
            Ok(Bytes::copy_from_slice(&data[30..])),
        ]);
        let mut reader = PartReader::new(Box::pin(stream));
        let p1 = reader.next_part(40).await.unwrap().unwrap();
        let p2 = reader.next_part(40).await.unwrap().unwrap();
        let p3 = reader.next_part(40).await.unwrap().unwrap();
        assert!(reader.next_part(40).await.unwrap().is_none());
        assert_eq!(p1.len(), 40);
        assert_eq!(p2.len(), 40);
        assert_eq!(p3.len(), 20);
        let mut all = Vec::new();
        all.extend_from_slice(&p1);
        all.extend_from_slice(&p2);
        all.extend_from_slice(&p3);
        assert_eq!(all, data);
    }
}
