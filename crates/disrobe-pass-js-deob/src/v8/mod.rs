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
pub use bytenode::{
    BYTENODE_PREFIX_BYTES, ByteVersion, BytenodeCacheBody, BytenodeCacheHeader, NodeVersion,
    V8_CACHED_DATA_MAGIC, parse_bytenode_full, parse_bytenode_header,
};
pub use nexe::{NexeLocation, detect_nexe_suffix};
pub use nwjs::{NwjsLocation, detect_nwjs_zip_suffix};
pub use pkg::{PkgLocation, detect_pkg_payload};
pub use sea::{SeaBlobLocation, detect_node_sea_blob};
pub use tauri::{TauriBinaryClass, classify_tauri_binary};
