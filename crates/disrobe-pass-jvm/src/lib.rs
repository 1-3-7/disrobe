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

pub mod axml;
pub mod backends;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod classfile;
pub mod dex;
pub mod error;
pub mod format_wire;
pub mod jar;
pub mod kotlin;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod obfuscators;
pub mod pass;
pub mod proguard;
pub mod protectors;
pub mod provenance_header;
pub mod scala;
pub mod smali;

pub use axml::{AxmlAttribute, AxmlNode, AxmlTree, parse as parse_axml};
pub use backends::{
    AndroidBackend, BackendCapability, BackendInvocation, JvmBackend, detect_available,
    invoke_android, invoke_jvm,
};
pub use classfile::{
    Attribute, CLASS_MAGIC, ClassFile, ConstantPoolEntry, FieldInfo, JavaVersion, MAX_MAJOR,
    MIN_MAJOR, MethodInfo, parse as parse_classfile,
};
pub use dex::{
    DEX_ENDIAN_TAG, DEX_MAGIC_PREFIX, DexFile, DexHeader, DexVersion, MultiDex, parse as parse_dex,
    parse_header as parse_dex_header, parse_multi_dex,
};
pub use error::{Error, Result};
pub use format_wire::{format_java, format_kotlin, format_scala};
pub use jar::{
    ApkExtract, JIMAGE_MAGIC, JarEntry, JarExtract, JimageHeader, JmodExtract,
    extract as extract_jar, extract_apk, extract_jmod, parse_jimage_header,
};
pub use kotlin::{KotlinKind, KotlinMetadata, recover_metadata as recover_kotlin_metadata};
#[cfg(feature = "llm-metadata")]
pub use llm::{JvmInstr, JvmLlmInput, METADATA_CAPABILITY as JVM_METADATA_CAPABILITY};
pub use obfuscators::{
    CffUndoStats, Detection, Protector, StringStrip, WatermarkFinding, detect_all,
    detect_allatori_watermarks, strip_encrypted_strings, undo_control_flow,
};
pub use pass::JvmPass;
pub use proguard::{
    ClassMapping, Mapping as ProguardMapping, UnmappedHeuristics, heuristic_recover,
    parse as parse_proguard_mapping,
};
pub use protectors::{
    ProtectorFamily as ProtectorFamilyKind, ProtectorPeelReport, allatori as allatori_protector,
    dasho as dasho_protector, dexguard as dexguard_protector, stringer as stringer_protector,
    zelix as zelix_protector,
};
pub use provenance_header::{
    java_decompiled_header, kotlin_decompiled_header, render_java_with_header,
    render_kotlin_with_header, render_scala_with_header, render_smali_with_header,
    scala_decompiled_header, smali_disasm_header,
};
pub use scala::{Demangled as ScalaDemangled, demangle as demangle_scala};
pub use smali::{SmaliEmission, emit as emit_smali};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
