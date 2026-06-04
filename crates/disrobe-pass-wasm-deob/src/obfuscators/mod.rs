mod cryptic_bytes;
mod jscrambler;
mod name_obfuscator;
mod tigress;
mod wasmixer;
mod wobfuscator;

pub use cryptic_bytes::{
    CrypticBytesDetection, CrypticBytesPeel, detect as detect_cryptic_bytes,
    peel_xor_layer as peel_cryptic_bytes,
};
pub use jscrambler::{
    IntegrityStripStats, OpaquePredStats, kill_opaque_predicates, strip_integrity_imports,
};
pub use name_obfuscator::{NameStrategy, classify_export_strategy};
pub use tigress::{
    DispatcherInfo, UnflattenStats, detect_dispatcher, unflatten, unflatten_to_fixed_point,
};
pub use wasmixer::{
    DefragStats, StubInfo, UnwrappedSegment, defragment, detect_decrypt_stubs, unwrap_decryption,
};
pub use wobfuscator::{WobfuscatorTable, extract_optable, lift_op_to_rust_fn};
