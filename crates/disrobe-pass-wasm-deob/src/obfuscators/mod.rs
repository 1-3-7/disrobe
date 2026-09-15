mod cryptic_bytes;
mod jscrambler;
mod mba;
mod name_obfuscator;
mod reverse;
mod tigress;
mod wasmixer;
mod wobfuscator;

pub use cryptic_bytes::{
    CrypticBytesDetection, CrypticBytesPeel, detect as detect_cryptic_bytes,
    peel_xor_layer as peel_cryptic_bytes,
};
pub use jscrambler::{
    IntegrityCfgStats, IntegrityStripStats, OpaquePredStats, eliminate_integrity_guards,
    kill_opaque_predicates, strip_integrity_imports,
};
pub use mba::{MbaSsaStats, simplify_mba};
pub use name_obfuscator::{NameStrategy, classify_export_strategy};
pub use reverse::{
    CanonicalizeStats, DataDecryptStats, DeadFunctionStats, DemangleStats,
    canonicalize_substitutions, decrypt_data_sections, demangle_names, demangle_symbol,
    strip_dead_functions,
};
pub use tigress::{
    DispatcherInfo, UnflattenStats, detect_dispatcher, unflatten, unflatten_to_fixed_point,
};
pub use wasmixer::{
    DefragStats, HeapRegion, ProbeSource, StubInfo, UnresolvedReason, UnresolvedStub, UnwrapReport,
    UnwrappedSegment, defragment, detect_decrypt_stubs, recover_heap_regions, unwrap_decryption,
};
pub use wobfuscator::{
    ReinlineStats, WobfuscatorTable, extract_optable, lift_op_to_rust_fn, reinline_imported_ops,
};
