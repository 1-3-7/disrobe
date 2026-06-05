#![forbid(unsafe_code)]

mod cache;
#[cfg(feature = "chain")]
pub mod chain_detector;
mod codec;
mod decorator;
mod envelope;
mod error;
mod inlined;
mod kdf;
pub mod pass;
mod provenance_header;
mod source_recover;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use cache::{KeyCache, KeyCacheStats};
pub use codec::{
    ascii85_decode, base85_decode_rfc1924, basename_of, decode_armored_line, hex_encode,
    strip_extension,
};
pub use decorator::{DecoratorStripReport, strip_sourcedefender_decorators};
pub use envelope::{
    DecryptedPye, PYE_BEGIN_MARKER, PYE_END_MARKER, PyeCodePayload, PyeEnvelope, PyeFrame,
    apply_aes_ctr, decrypt_frame, decrypt_pye, decrypt_pye_with_key, parse_msgpack_envelope,
    parse_pye_frame,
};
pub use error::{Error, Result};
pub use inlined::{
    InlinedBlock, InlinedExtractOptions, InlinedExtraction, InlinedFailure, extract_inlined,
    locate_inlined_blocks,
};
pub use kdf::{AES_IV_LEN, AES_KEY_LEN, DerivedKey, derive_aes_key};
pub use provenance_header::{python_decoded_header, render_decoded_with_header};
pub use source_recover::{
    CodeObjectSummary as SourceRecoverCodeObjectSummary, ParsedPyeArrayEnvelope, SourceRecoverOpts,
    SourceRecoverOutput, decrypt_pye_to_source, parse_array_envelope, recover_from_marshal_bytes,
    recover_from_plaintext,
};
