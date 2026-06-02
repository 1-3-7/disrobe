pub mod asar_listing;
pub mod bytecode_disasm;
pub mod bytecode_lift;
pub mod bytecode_opcodes;
pub mod bytenode;
pub mod nexe;
pub mod nwjs;
pub mod pkg;
pub mod sea;
pub mod tauri;

pub use asar_listing::{AsarListing, AsarListingEntry, list_asar};
pub use bytecode_disasm::{
    DecodedInstruction, DecodedOperand, Disassembly, OperandScale, disassemble,
    disassemble_with_table, encode_instruction,
};
pub use bytecode_lift::{LiftFidelity, LiftedFunction, LiftedLine, lift_disassembly};
pub use bytecode_opcodes::{AccumulatorUse, OpcodeTable, OperandKind, V8OpcodeSpec};
#[allow(deprecated)]
pub use bytenode::V8_CACHED_DATA_MAGIC;
pub use bytenode::{
    ByteVersion, BytenodeCacheBody, BytenodeCacheHeader, HeaderLayout, NodeVersion,
    ScrapedConstantPool, SnapshotDeserializeStatus, V8_HEADER_SIZE_V11, V8_HEADER_SIZE_V12,
    V8_MAGIC_HIGH_BITS, V8_MAGIC_MARKER_MASK, V8_MAGIC_NODE_18, V8_MAGIC_NODE_20, V8_MAGIC_NODE_22,
    V8_MAGIC_NODE_24, V8_MAX_PAYLOAD_BYTES, parse_bytenode_full, parse_bytenode_header,
    scrape_payload_strings, snapshot_deserialize_status,
};
pub use nexe::{NEXE_FOOTER_MAGIC, NexeLocation, detect_nexe_suffix};
pub use nwjs::{NwjsLocation, detect_nwjs_zip_suffix};
pub use pkg::{PkgLocation, detect_pkg_payload};
pub use sea::{
    SEA_MAGIC, SEA_MAX_STRING_BYTES, SeaBlob, SeaBlobLocation, SeaFlags, carve_sea_main_code,
    detect_node_sea_blob, find_sea_magic_offsets, parse_sea_blob, parse_sea_blob_at,
};
#[allow(deprecated)]
pub use sea::{SEA_MAGIC_LEGACY_LABEL, SEA_RESOURCE_TAG_V1};
pub use tauri::{TauriBinaryClass, classify_tauri_binary};
