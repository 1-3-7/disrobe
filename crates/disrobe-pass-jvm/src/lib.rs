#![forbid(unsafe_code)]
#![allow(
    clippy::redundant_pub_crate,
    clippy::too_many_lines,
    clippy::naive_bytecount,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::option_if_let_else,
    clippy::single_match_else,
    clippy::single_char_pattern,
    clippy::unreadable_literal,
    clippy::no_effect_underscore_binding,
    clippy::needless_type_cast,
    clippy::match_same_arms,
    clippy::map_unwrap_or
)]

pub mod arsc;
pub mod attributes;
pub mod axml;
pub mod backends;
pub mod bytecode;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod classfile;
pub mod dalvik;
pub mod dalvik_cfg;
pub mod dalvik_decompile;
pub mod dalvik_lift;
pub mod decompile;
pub mod decompile_struct;
pub mod descriptor;
pub mod dex;
pub mod error;
pub mod format_wire;
pub mod jar;
pub mod kotlin;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod oat;
pub mod obfuscators;
pub mod pass;
pub mod proguard;
pub mod protectors;
pub mod provenance_header;
pub mod scala;
pub mod smali;
pub mod stub_emulator;

pub use arsc::{
    RES_STRING_POOL_TYPE, RES_TABLE_PACKAGE_TYPE, RES_TABLE_TYPE, ResChunkHeader, ResStringPool,
    ResTablePackage, ResourceTable, parse_arsc,
};
pub use attributes::{
    BootstrapMethod, ClassStructure, RecordComponent, analyze as analyze_class_structure,
};
pub use axml::{AxmlAttribute, AxmlNode, AxmlTree, parse as parse_axml};
pub use backends::{
    AndroidBackend, BackendCapability, BackendInvocation, JvmBackend, detect_available,
    invoke_android, invoke_jvm,
};
pub use bytecode::{
    CodeAttribute, ExceptionEntry, Instruction, OpcodeInfo, OperandShape, Operands, branch_target,
    disassemble, opcode_info, parse_code_attribute, resolve_ref,
};
pub use classfile::{
    Attribute, CLASS_MAGIC, ClassFile, ConstantPoolEntry, FieldInfo, JavaVersion, MAX_MAJOR,
    MIN_MAJOR, MethodInfo, parse as parse_classfile,
};
pub use dalvik::{
    DalvikInsn, DalvikOp, InsnFormat, SwitchPayload, dalvik_format, decode_method,
    disassemble_units as disassemble_dalvik, opcode as dalvik_opcode, parse_packed_switch,
    parse_sparse_switch,
};
pub use dalvik_cfg::{DalvikMethodCfg, build_dalvik_cfg, build_dalvik_cfg_from_code_item};
pub use dalvik_decompile::{
    DecompiledDex, decompile_dex, decompile_dex_bytes as decompile_dex_from_bytes,
};
pub use decompile::{
    DecompiledClass, class_access_keywords, decompile_class, decompile_classfile_bytes,
    member_access_keywords,
};
pub use decompile_struct::{
    BasicBlock, BlockId, Cfg, Dominators, Edge, EdgeKind, ExceptionRegion, NaturalLoop,
    PrecomputedSwitch, Region, Structurer, SwitchKey, compute_dominators, find_natural_loops,
};
pub use descriptor::{
    JavaType, MethodDescriptor, binary_to_source, parse_field as parse_field_descriptor,
    parse_method as parse_method_descriptor,
};
pub use dex::{
    CodeItem, DEX_ENDIAN_TAG, DEX_MAGIC_PREFIX, DexFile, DexHeader, DexVersion, FieldId, MethodId,
    MultiDex, ProtoId, TryItem, parse as parse_dex, parse_code_items,
    parse_header as parse_dex_header, parse_multi_dex,
};
pub use error::{Error, Result};
pub use format_wire::{format_java, format_kotlin, format_scala};
pub use jar::{
    AabExtract, AabModule, ApkExtract, JIMAGE_MAGIC, JMOD_MAGIC, JarEntry, JarExtract, Jimage,
    JimageHeader, JimageResource, JmodExtract, extract as extract_jar, extract_aab, extract_apk,
    extract_jmod, parse_jimage, parse_jimage_header,
};
pub use kotlin::{KotlinKind, KotlinMetadata, recover_metadata as recover_kotlin_metadata};
#[cfg(feature = "llm-metadata")]
pub use llm::{JvmInstr, JvmLlmInput, METADATA_CAPABILITY as JVM_METADATA_CAPABILITY};
pub use oat::{
    DexOptHeader, InstructionSet, OAT_MAGIC, ODEX_MAGIC, OatFile, OatHeader, OatVersion, OdexFile,
    parse_oat, parse_oat_header, parse_odex, parse_odex_header,
};
pub use obfuscators::{
    CffUndoStats, Detection, Protector, StringStrip, WatermarkFinding, detect_all,
    detect_allatori_watermarks, strip_encrypted_strings, undo_control_flow,
};
pub use pass::JvmPass;
pub use proguard::{
    AppliedNames, ClassMapping, Mapping as ProguardMapping, UnmappedHeuristics,
    apply_to_classfile as apply_proguard_mapping, heuristic_recover,
    parse as parse_proguard_mapping,
};
pub use protectors::{
    PeelStatus, ProtectorFamily as ProtectorFamilyKind, ProtectorPeelReport,
    allatori as allatori_protector, dasho as dasho_protector, dexguard as dexguard_protector,
    stringer as stringer_protector, zelix as zelix_protector,
};
pub use provenance_header::{
    java_decompiled_header, kotlin_decompiled_header, render_java_with_header,
    render_kotlin_with_header, render_scala_with_header, render_smali_with_header,
    scala_decompiled_header, smali_disasm_header,
};
pub use scala::{Demangled as ScalaDemangled, demangle as demangle_scala};
pub use smali::{SmaliEmission, emit as emit_smali, emit_method_body, emit_method_body_from_insns};
pub use stub_emulator::{
    DecryptStub, EmulationError, decrypt_constant, emulate_char_array, find_char_array_decrypt,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
