//! Streaming PQOS encryption.
//!
//! Plaintext is read in [`CHUNK_PLAINTEXT_SIZE`] windows and each ciphertext
//! frame is yielded as soon as it is sealed. Nothing writes a full ciphertext
//! file first.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::Stream;
use tokio::io::{AsyncRead, ReadBuf};

use crate::crypto::cipher::{DataEncryptionKey, wrap_dek};
use crate::crypto::stream::{CHUNK_PLAINTEXT_SIZE, encrypt_chunk, generate_stream_nonce_prefix};
use crate::crypto::{CipherSuite, PublicKey, encapsulate};
use crate::error::{Error, Result};
use crate::format::{ObjectHeader, encode_chunk_frame};
use crate::key::KeyId;

pub(crate) struct CiphertextStream<R> {
    reader: R,
    dek: DataEncryptionKey,
    aad: Vec<u8>,
    prefix: [u8; STREAM_PREFIX],
    header: Bytes,
    header_off: usize,
    plain: Vec<u8>,
    filled: usize,
    counter: u32,
    done: bool,
    key_id: KeyId,
    suite: CipherSuite,
}

const STREAM_PREFIX: usize = crate::crypto::stream::STREAM_NONCE_PREFIX_LEN;

impl<R> CiphertextStream<R> {
    pub(crate) fn start(key_id: &KeyId, public: &PublicKey, reader: R) -> Result<Self> {
        let (kem_ct, shared) = encapsulate(public)?;
        let dek = DataEncryptionKey::generate();
        let header_for_aad = ObjectHeader::new_v1(
            key_id.clone(),
            kem_ct.clone(),
            [0u8; 12],
            [0u8; 48],
            [0u8; STREAM_PREFIX],
        );
        let aad = header_for_aad.aad();
        let (wrap_nonce, wrapped_dek) = wrap_dek(&shared, &dek, &aad)?;
        let prefix = generate_stream_nonce_prefix();
        let header = ObjectHeader::new_v1(key_id.clone(), kem_ct, wrap_nonce, wrapped_dek, prefix);
        debug_assert_eq!(header.aad(), aad);
        Ok(Self {
            reader,
            dek,
            aad,
            prefix,
            header: Bytes::from(header.encode()),
            header_off: 0,
            plain: vec![0u8; CHUNK_PLAINTEXT_SIZE],
            filled: 0,
            counter: 0,
            done: false,
            key_id: header.key_id.clone(),
            suite: header.suite,
        })
    }

    pub(crate) fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub(crate) fn suite(&self) -> CipherSuite {
        self.suite
    }

    fn emit_chunk(&mut self, is_final: bool) -> std::io::Result<Bytes> {
        let ct = encrypt_chunk(
            &self.dek,
            &self.prefix,
            self.counter,
            is_final,
            &self.plain[..self.filled],
            &self.aad,
        )
        .map_err(crate::error::io_error)?;
        let frame = encode_chunk_frame(&ct).map_err(crate::error::io_error)?;
        if !is_final {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| crate::error::io_error(Error::crypto("chunk counter overflow")))?;
            self.filled = 0;
        }
        Ok(Bytes::from(frame))
    }
}

impl<R> Stream for CiphertextStream<R>
where
    R: AsyncRead + Unpin,
{
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.header_off < this.header.len() {
            let rest = this.header.slice(this.header_off..);
            this.header_off = this.header.len();
            return Poll::Ready(Some(Ok(rest)));
        }
        if this.done {
            return Poll::Ready(None);
        }

        loop {
            if this.filled == CHUNK_PLAINTEXT_SIZE {
                return Poll::Ready(Some(this.emit_chunk(false)));
            }
            let n = {
                let mut read_buf = ReadBuf::new(&mut this.plain[this.filled..]);
                match Pin::new(&mut this.reader).poll_read(cx, &mut read_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                    Poll::Ready(Ok(())) => read_buf.filled().len(),
                }
            };
            if n == 0 {
                match this.emit_chunk(true) {
                    Ok(frame) => {
                        this.done = true;
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    Err(err) => return Poll::Ready(Some(Err(err))),
                }
            }
            this.filled += n;
        }
    }
}
