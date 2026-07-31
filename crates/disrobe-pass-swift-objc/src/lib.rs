#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod code_signature;
pub(crate) mod debug;
pub mod demangle;
pub mod dyld_cache;
pub mod error;
pub mod fairplay;
pub mod ipa;
pub mod macho;
pub mod native_bodies;
pub mod objc;
pub mod objc_dispatch;
pub mod objc_records;
pub mod pass;
pub mod plist_decode;
pub mod provenance_header;
pub mod swift;
pub mod swift_reflect;
pub mod swift_symbolic;
pub mod swift_typedump;
pub mod swiftinterface;
pub mod swiftmodule;
pub mod toolchain;

pub use code_signature::{
    BlobSlot, CodeDirectory, CodeSignature, HashKind, PageHashAudit, PageHashVerdict,
    SignatureCoverage, SlotKind, parse as parse_code_signature,
};
pub use dyld_cache::{
    DyldImage, DyldMapping, DyldSharedCache, ReconstructedDylib, is_dyld_shared_cache,
    parse as parse_dyld_cache, reconstruct_all as reconstruct_dyld_images,
    reconstruct_by_name as reconstruct_dyld_image_by_name,
    reconstruct_image as reconstruct_dyld_image,
};
pub use error::{Error, Result};
pub use fairplay::{
    EncryptedTextNotice, FairPlayStatus, detect as detect_fairplay, encrypted_text_notice,
};
pub use ipa::{
    EmbeddedImage, EmbeddedImageRole, IpaEntry, IpaExtract, IpaInventory,
    embedded_images as ipa_embedded_images, extract as extract_ipa, inventory as ipa_inventory,
};
pub use macho::{
    Bitness, CpuKind, DylibKind, DylibReference, DysymtabInfo, EncryptedRegion, EncryptionInfo,
    Endian, EntryPoint, ExportKind, ExportedSymbol, FatArchEntry, FunctionSymbol, ImportThunk,
    LinkeditData, LoadCommand, MachoKind, PackedVersion, ParsedSlice, PlatformVersion, Section,
    Segment, SliceHeader, SymtabInfo, detect_magic, encrypted_region, exported_symbols,
    find_section, function_starts, function_symbols, import_thunks, parse_slice,
    readable_section_bytes, section_bytes, section_is_encrypted_at_rest, slice_bytes, symbol_names,
    walk_fat,
};
pub use native_bodies::{
    DisasmInstruction, FunctionBody, NativeBodyReport, ReconstructedMember,
    ReconstructedTypeReport, SourceGrade, SourceLine, recover_native_bodies,
};
pub use objc::{
    ObjcClassDump, ObjcPointerList, ObjcStringTable, SelectorIndex, class_dump as objc_class_dump,
    index_selectors,
};
pub use objc_dispatch::{
    ChainedPointerFormat, DispatchArch, DispatchMaps, ObjcMessageSend, ObjcSend,
    annotate_instructions, bound_symbols_by_slot, build_dispatch_maps, chained_pointer_formats,
};
pub use objc_records::{
    OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES, ObjcCategory, ObjcInterface, ObjcIvar, ObjcMethod,
    ObjcProperty, ObjcProtocol, recover_categories as recover_objc_categories,
    recover_interfaces as recover_objc_interfaces, recover_protocols as recover_objc_protocols,
};
pub use pass::{
    ContainerKind, EmbeddedImageReport, MetadataSummary, SliceReport, SwiftObjcReport,
    UnanalyzedEmbeddedImage, analyze,
};
pub use plist_decode::{
    EntitlementValue, EntitlementsDecode, InfoPlistSummary,
    decode_entitlements_from_code_signature, decode_entitlements_xml, parse_info_plist,
};
pub use provenance_header::{
    objc_class_dump_header, render_objc_with_header, render_swift_with_header,
    swift_class_dump_header,
};
pub use swift::{
    ConfidentialDecryptResult, ConfidentialKeyRecovery, MIN_RECOVERABLE_CIPHERTEXT_LEN,
    SwiftClassDump, SwiftReflectionStrings, SwiftSectionPointers, SwiftShieldUndoMap,
    class_dump as swift_class_dump, confidential_recover, confidential_recover_key,
    confidential_recover_strings, confidential_xor_decrypt, demangle as swift_demangle,
    looks_like_swift_mangled, swiftshield_undo_from_dsym_text,
};
pub use swift_reflect::{
    FieldDescriptorKind, SwiftField, SwiftTypeReflection,
    parse_field_descriptors as parse_swift_field_descriptors, read_field_list,
};
pub use swift_typedump::{
    ConformanceProtocolKind, NominalKind, ProtocolRequirementKind, SwiftAssociatedTypeRecord,
    SwiftAssociatedTypeWitness, SwiftNominalType, SwiftProtocolConformance,
    SwiftProtocolDescriptor, SwiftProtocolRequirement, SwiftTypeDump, nominal_kind_for,
    parse_type_dump,
};
pub use swiftinterface::{
    InterfaceCase, InterfaceDecl, InterfaceDeclKind, InterfaceMethod, InterfaceProperty,
    ParsedInterface, looks_like_swiftinterface, merge_elided_field_names,
    parse as parse_swiftinterface,
};
pub use swiftmodule::{
    MODULE_SIGNATURE, SwiftModuleDecls, is_swift_module, read as read_swift_module,
};
pub use toolchain::{SymbolState, ToolchainReport, file_type_label, report as toolchain_report};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
