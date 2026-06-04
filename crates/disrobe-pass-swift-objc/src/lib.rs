#![forbid(unsafe_code)]

#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod demangle;
pub mod error;
pub mod fairplay;
pub mod ipa;
pub mod macho;
pub mod objc;
pub mod objc_records;
pub mod pass;
pub mod plist_decode;
pub mod provenance_header;
pub mod swift;
pub mod swift_reflect;

pub use error::{Error, Result};
pub use fairplay::{FairPlayStatus, detect as detect_fairplay};
pub use ipa::{
    IpaEntry, IpaExtract, IpaInventory, extract as extract_ipa, inventory as ipa_inventory,
};
pub use macho::{
    Bitness, CpuKind, EncryptionInfo, Endian, FatArchEntry, LoadCommand, MachoKind, ParsedSlice,
    Section, Segment, SliceHeader, SymtabInfo, detect_magic, find_section, parse_slice,
    section_bytes, slice_bytes, symbol_names, walk_fat,
};
pub use objc::{
    ObjcClassDump, ObjcPointerList, ObjcStringTable, SelectorIndex, class_dump as objc_class_dump,
    index_selectors,
};
pub use objc_records::{
    ObjcInterface, ObjcIvar, ObjcMethod, ObjcProperty,
    recover_interfaces as recover_objc_interfaces,
};
pub use pass::{ContainerKind, PASS_ID, SliceReport, SwiftObjcPass, SwiftObjcReport, analyze};
pub use plist_decode::{
    EntitlementValue, EntitlementsDecode, InfoPlistSummary,
    decode_entitlements_from_code_signature, decode_entitlements_xml, parse_info_plist,
};
pub use provenance_header::{
    objc_class_dump_header, render_objc_with_header, render_swift_with_header,
    swift_class_dump_header,
};
pub use swift::{
    ConfidentialDecryptResult, SwiftClassDump, SwiftReflectionStrings, SwiftSectionPointers,
    SwiftShieldUndoMap, class_dump as swift_class_dump, confidential_recover_strings,
    confidential_xor_decrypt, demangle as swift_demangle, looks_like_swift_mangled,
    swiftshield_undo_from_dsym_text,
};
pub use swift_reflect::{
    FieldDescriptorKind, SwiftField, SwiftTypeReflection,
    parse_field_descriptors as parse_swift_field_descriptors,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
