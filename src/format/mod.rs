//! Versioned encrypted object binary format.

pub(crate) mod header;

pub use header::{
    FORMAT_VERSION, ObjectHeader, encode_chunk_frame, read_chunk_frame, write_header,
};
