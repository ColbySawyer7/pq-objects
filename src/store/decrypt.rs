//! Streaming PQOS decryption.
//!
//! Ciphertext is read one STREAM frame at a time and plaintext is produced as
//! [`AsyncRead`] pulls it. The ciphertext and the plaintext are not both held
//! in full.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use crate::backend::BackendBody;
use crate::crypto::cipher::{DataEncryptionKey, unwrap_dek};
use crate::crypto::kem::CIPHERTEXT_LEN;
use crate::crypto::stream::{STREAM_NONCE_PREFIX_LEN, decrypt_chunk};
use crate::error::{Error, Result};
use crate::format::ObjectHeader;
use crate::format::header::{MAGIC, MAX_KEY_ID_LEN, chunk_len_in_range};
use crate::key::KeyProvider;

/// Decrypting reader returned by [`crate::store::EncryptedObjectStore::get`].
///
/// Reads ciphertext in STREAM frames and yields plaintext as the caller reads.
/// Suitable for writing a large restore directly to a file.
pub struct EncryptedReader {
    header: ObjectHeader,
    inner: DecryptReader<BackendBody>,
}

impl EncryptedReader {
    pub(crate) fn from_body(
        header: ObjectHeader,
        body: BackendBody,
        dek: DataEncryptionKey,
        aad: Vec<u8>,
    ) -> Self {
        let prefix = header.stream_nonce_prefix;
        Self {
            inner: DecryptReader::new(body, dek, aad, prefix),
            header,
        }
    }

    /// Object header parsed from the ciphertext.
    #[must_use]
    pub fn header(&self) -> Option<&ObjectHeader> {
        Some(&self.header)
    }
}

impl AsyncRead for EncryptedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

pub(crate) async fn open_body(
    keys: &dyn KeyProvider,
    mut body: BackendBody,
) -> Result<EncryptedReader> {
    let header = read_header(&mut body).await?;
    let shared = keys
        .decapsulate(&header.key_id, &header.kem_ciphertext)
        .await?;
    let aad = header.aad();
    let dek = unwrap_dek(&shared, &header.wrap_nonce, &header.wrapped_dek, &aad)?;
    Ok(EncryptedReader::from_body(header, body, dek, aad))
}

pub(crate) async fn read_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<ObjectHeader> {
    let mut prefix = [0u8; 10];
    read_exact(reader, &mut prefix).await?;
    if &prefix[..4] != MAGIC {
        return Err(Error::invalid_header("missing PQOS magic"));
    }
    let key_id_len = u16::from_be_bytes([prefix[8], prefix[9]]) as usize;
    if key_id_len == 0 || key_id_len > MAX_KEY_ID_LEN {
        return Err(Error::invalid_header("invalid key id length"));
    }
    let rest_len = key_id_len
        + 2
        + CIPHERTEXT_LEN
        + crate::crypto::cipher::WRAP_NONCE_LEN
        + crate::crypto::cipher::WRAPPED_DEK_LEN
        + STREAM_NONCE_PREFIX_LEN;
    let mut rest = vec![0u8; rest_len];
    read_exact(reader, &mut rest).await?;
    let mut encoded = Vec::with_capacity(prefix.len() + rest.len());
    encoded.extend_from_slice(&prefix);
    encoded.extend_from_slice(&rest);
    let (header, leftover) = ObjectHeader::decode(&encoded)?;
    if !leftover.is_empty() {
        return Err(Error::invalid_header("trailing bytes in object header"));
    }
    Ok(header)
}

async fn read_exact<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    reader.read_exact(buf).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::invalid_header("truncated object header")
        } else {
            Error::Io(err)
        }
    })?;
    Ok(())
}

struct DecryptReader<R> {
    reader: R,
    dek: DataEncryptionKey,
    aad: Vec<u8>,
    prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    counter: u32,
    pending: Vec<u8>,
    pending_off: usize,
    acc: Vec<u8>,
    acc_filled: usize,
    acc_need: usize,
    held: Option<Vec<u8>>,
    phase: Phase,
}

#[derive(Clone, Copy)]
enum Phase {
    Len,
    Body { len: usize },
    Lookahead,
    Done,
}

enum Drive {
    Continue,
    Plaintext(Vec<u8>),
}

enum AccStatus {
    Partial,
    Full,
    Eof,
    UnexpectedEof,
}

impl<R> DecryptReader<R> {
    fn new(
        reader: R,
        dek: DataEncryptionKey,
        aad: Vec<u8>,
        prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    ) -> Self {
        Self {
            reader,
            dek,
            aad,
            prefix,
            counter: 0,
            pending: Vec::new(),
            pending_off: 0,
            acc: vec![0u8; 4],
            acc_filled: 0,
            acc_need: 4,
            held: None,
            phase: Phase::Len,
        }
    }

    fn reset_acc(&mut self, need: usize) {
        self.acc_need = need;
        self.acc_filled = 0;
        if self.acc.len() < need {
            self.acc.resize(need, 0);
        }
    }
}

impl<R: AsyncRead + Unpin> DecryptReader<R> {
    fn poll_acc(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<AccStatus>> {
        if self.acc_filled >= self.acc_need {
            return Poll::Ready(Ok(AccStatus::Full));
        }
        if self.acc.len() < self.acc_need {
            self.acc.resize(self.acc_need, 0);
        }
        let mut read_buf = ReadBuf::new(&mut self.acc[self.acc_filled..self.acc_need]);
        match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(if self.acc_filled == 0 {
                        AccStatus::Eof
                    } else {
                        AccStatus::UnexpectedEof
                    }));
                }
                self.acc_filled += n;
                if self.acc_filled >= self.acc_need {
                    Poll::Ready(Ok(AccStatus::Full))
                } else {
                    Poll::Ready(Ok(AccStatus::Partial))
                }
            }
        }
    }

    fn take_len(&self) -> std::io::Result<usize> {
        let raw = u32::from_be_bytes(self.acc[..4].try_into().expect("length is 4 bytes")) as usize;
        if !chunk_len_in_range(raw) {
            return Err(crate::error::io_error(Error::invalid_header(
                "invalid chunk length",
            )));
        }
        Ok(raw)
    }

    fn decrypt_held(&mut self, is_final: bool) -> std::io::Result<Vec<u8>> {
        let frame = self
            .held
            .take()
            .ok_or_else(|| crate::error::io_error(Error::invalid_header("missing stream chunk")))?;
        decrypt_chunk(
            &self.dek,
            &self.prefix,
            self.counter,
            is_final,
            &frame,
            &self.aad,
        )
        .map_err(crate::error::io_error)
    }

    fn drive(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Drive>> {
        match self.phase {
            Phase::Done => Poll::Ready(Ok(Drive::Continue)),
            Phase::Len => self.drive_len(cx),
            Phase::Body { len } => self.drive_body(cx, len),
            Phase::Lookahead => self.drive_lookahead(cx),
        }
    }

    fn drive_len(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Drive>> {
        match self.poll_acc(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(AccStatus::Partial)) => Poll::Ready(Ok(Drive::Continue)),
            Poll::Ready(Ok(AccStatus::Full)) => {
                let len = match self.take_len() {
                    Ok(len) => len,
                    Err(err) => return Poll::Ready(Err(err)),
                };
                self.reset_acc(len);
                self.phase = Phase::Body { len };
                Poll::Ready(Ok(Drive::Continue))
            }
            Poll::Ready(Ok(AccStatus::Eof | AccStatus::UnexpectedEof)) => Poll::Ready(Err(
                crate::error::io_error(Error::invalid_header("missing final stream chunk")),
            )),
        }
    }

    fn drive_body(&mut self, cx: &mut Context<'_>, len: usize) -> Poll<std::io::Result<Drive>> {
        match self.poll_acc(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(AccStatus::Partial)) => Poll::Ready(Ok(Drive::Continue)),
            Poll::Ready(Ok(AccStatus::Full)) => {
                self.held = Some(self.acc[..len].to_vec());
                self.reset_acc(4);
                self.phase = Phase::Lookahead;
                Poll::Ready(Ok(Drive::Continue))
            }
            Poll::Ready(Ok(AccStatus::Eof | AccStatus::UnexpectedEof)) => Poll::Ready(Err(
                crate::error::io_error(Error::invalid_header("truncated stream chunk")),
            )),
        }
    }

    fn drive_lookahead(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Drive>> {
        match self.poll_acc(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(AccStatus::Partial)) => Poll::Ready(Ok(Drive::Continue)),
            Poll::Ready(Ok(AccStatus::UnexpectedEof)) => Poll::Ready(Err(crate::error::io_error(
                Error::invalid_header("truncated chunk length"),
            ))),
            Poll::Ready(Ok(AccStatus::Eof)) => {
                let plain = match self.decrypt_held(true) {
                    Ok(plain) => plain,
                    Err(err) => return Poll::Ready(Err(err)),
                };
                self.phase = Phase::Done;
                Poll::Ready(Ok(Drive::Plaintext(plain)))
            }
            Poll::Ready(Ok(AccStatus::Full)) => {
                let next_len = match self.take_len() {
                    Ok(len) => len,
                    Err(err) => return Poll::Ready(Err(err)),
                };
                let plain = match self.decrypt_held(false) {
                    Ok(plain) => plain,
                    Err(err) => return Poll::Ready(Err(err)),
                };
                self.counter = match self.counter.checked_add(1) {
                    Some(counter) => counter,
                    None => {
                        return Poll::Ready(Err(crate::error::io_error(Error::crypto(
                            "chunk counter overflow",
                        ))));
                    }
                };
                self.reset_acc(next_len);
                self.phase = Phase::Body { len: next_len };
                Poll::Ready(Ok(Drive::Plaintext(plain)))
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DecryptReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut wrote = false;
        loop {
            if this.pending_off < this.pending.len() {
                let n = (this.pending.len() - this.pending_off).min(buf.remaining());
                buf.put_slice(&this.pending[this.pending_off..this.pending_off + n]);
                this.pending_off += n;
                wrote = true;
                if this.pending_off == this.pending.len() {
                    this.pending.clear();
                    this.pending_off = 0;
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }
            if matches!(this.phase, Phase::Done) {
                return Poll::Ready(Ok(()));
            }
            match this.drive(cx) {
                Poll::Pending => {
                    return if wrote {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    };
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(Drive::Continue)) => {}
                Poll::Ready(Ok(Drive::Plaintext(plain))) => {
                    this.pending = plain;
                    this.pending_off = 0;
                }
            }
        }
    }
}
