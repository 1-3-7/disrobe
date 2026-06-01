#![deny(unsafe_code)]

pub mod envelope;
pub mod error;
pub mod io;
pub mod payload;
pub mod sidecar;
pub mod transcode;

pub use envelope::{Envelope, HEADER_SIZE, compute_root_hash};
pub use error::{EnvelopeError, Result};
pub use io::{MmapView, mmap_envelope_view};
pub use payload::{
    ArchivedDisasmPayload, ArchivedRawPayload, DisasmInstruction, DisasmPayload, DisasmSymbol,
    DisasmSymbolKind, RawPayload, decode_disasm, decode_raw, encode_disasm, encode_raw,
};
pub use sidecar::Sidecar;
pub use transcode::{EnvelopeVersion, TranscodeFn, TranscodeKey, TranscodeRegistry, TranscodeStep};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const ENVELOPE_MAGIC: &[u8; 8] = b"DISROBE\0";
pub const ENVELOPE_FORMAT_VERSION: u16 = 1;

pub use disrobe_core::{Capability, Rung};
