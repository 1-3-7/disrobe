pub mod asar_listing;
pub mod bytecode_opcodes;
pub mod bytenode;
pub mod code_serializer;
pub mod flat_bytecode_disasm;
pub mod flat_bytecode_lift;
pub mod nexe;
pub mod nwjs;
pub mod pkg;
mod root_names;
pub mod sea;
pub mod serialized_code;
pub mod tauri;

pub use asar_listing::{AsarListing, AsarListingEntry, carve_entry as carve_asar_entry, list_asar};
pub use bytecode_opcodes::{AccumulatorUse, OpcodeTable, OperandKind, V8OpcodeSpec};
#[allow(deprecated)]
pub use bytenode::{
    ByteVersion, BytenodeCacheBody, BytenodeCacheHeader, HeaderLayout, NodeVersion,
    ScrapedConstantPool, SnapshotDeserializeStatus, V8_HEADER_SIZE_V11, V8_HEADER_SIZE_V12,
    V8_MAGIC_HIGH_BITS, V8_MAGIC_MARKER_MASK, V8_MAGIC_NODE_18, V8_MAGIC_NODE_20, V8_MAGIC_NODE_22,
    V8_MAGIC_NODE_24, V8_MAX_PAYLOAD_BYTES, parse_bytenode_full, parse_bytenode_header,
    scrape_payload_strings, snapshot_deserialize_status,
};
pub use code_serializer::{
    BYTECODE_ARRAY_SCALAR_HEADER, BytecodeArrayLayout, CodeSerializerGraph, ConstantPoolEntry,
    RETURN_OPCODE_NODE24, RawBytecodeView, RecoveredBytecodeArray, SerializerBuild,
    parse_code_serializer_graph, recover_bytecode_array_from_run,
    recover_bytecode_array_with_layout, return_opcode_for,
};
pub use flat_bytecode_disasm::{
    DecodedInstruction, DecodedOperand, Disassembly, OperandScale, disassemble,
    disassemble_with_table, encode_instruction,
};
pub use flat_bytecode_lift::{
    LiftFidelity, LiftedFunction, LiftedLine, lift_disassembly, lift_disassembly_with_pool,
};
pub use nexe::{
    NEXE_FOOTER_MAGIC, NexeLocation, carve_payload as carve_nexe_payload, detect_nexe_suffix,
};
pub use nwjs::{NwjsLocation, detect_nwjs_zip_suffix};
pub use pkg::{PkgLocation, detect_pkg_payload};
pub use sea::{
    SEA_MAGIC, SEA_MAX_STRING_BYTES, SeaBlob, SeaBlobLocation, SeaFlags, carve_sea_main_code,
    detect_node_sea_blob, find_sea_magic_offsets, parse_sea_blob, parse_sea_blob_at,
};
pub use serialized_code::{
    FramedString, SFI_MARKER, STRING_MAP_INTERNALIZED, STRING_MAP_SEQ_ONE_BYTE, STRING_RECORD_TAG,
    StringClass, StructuralRecovery, count_sfi_markers, extract_framed_strings, recover_structure,
};
pub use tauri::{TauriBinaryClass, classify_tauri_binary};
