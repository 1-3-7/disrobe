#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
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

pub mod android_attrs;
pub mod android_backend;
pub mod apk_resources;
pub mod apk_sig;
pub mod arsc;
pub mod attributes;
pub mod axml;
pub mod backends;
pub mod bytecode;
pub mod bytecode_eval;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod classfile;
pub mod const_fold;
pub mod dalvik;
pub mod dalvik_blackobf;
pub mod dalvik_cfg;
mod dalvik_core_library;
pub mod dalvik_decompile;
pub(crate) mod dalvik_desugar;
pub mod dalvik_dexguard;
pub(crate) mod dalvik_interp;
pub mod dalvik_lift;
pub mod dalvik_pack_recover;
pub mod dalvik_pack_stub_loader;
pub mod dalvik_r8_inline;
pub(crate) mod dalvik_split;
pub mod dalvik_strdec;
pub mod dalvik_strdec_generic;
pub mod dalvik_to_jvm;
pub(crate) mod dalvik_typestate;
pub(crate) mod debug;
pub mod decompile;
pub mod decompile_struct;
pub mod descriptor;
pub mod dex;
pub mod dex2jar;
pub mod dex_builder;
pub mod error;
pub mod format_wire;
pub mod frame_infer;
pub mod hierarchy;
pub mod jar;
pub mod jni;
pub mod jsr_inline;
pub mod kotlin;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod name_disambig;
pub mod oat;
pub mod obfuscators;
pub mod pass;
pub mod proguard;
pub mod proguard_fingerprint;
pub mod protectors;
pub mod provenance_header;
pub mod rasp;
#[cfg(feature = "semantic-reach")]
pub mod reach;
pub mod scala;
pub mod sccp;
pub(crate) mod signature;
pub mod smali;
pub mod stackmap;
pub mod string_recovery;
pub mod stub_emulator;

pub use android_backend::{
    AndroidDecompileOutput, AndroidDecompiler, BackendPreference, JadxOutcome, JadxRefusal,
    decompile_dex as android_decompile_dex, run_jadx_on_bytes, run_jadx_on_bytes_detailed,
};
pub use apk_resources::{
    ApkReconstruction, ApkResourceReport, ResourceEntrySummary,
    analyze_apk as analyze_apk_resources, analyze_manifest_bytes as decode_manifest_bytes,
    decode_manifest,
};
pub use apk_sig::{
    APK_SIG_BLOCK_MAGIC, APK_SIGNATURE_SCHEME_V2_BLOCK_ID, APK_SIGNATURE_SCHEME_V3_1_BLOCK_ID,
    APK_SIGNATURE_SCHEME_V3_BLOCK_ID, ApkSignatureReport, CertificateInfo, SchemeReport,
    SignatureAlgorithm, SignatureScheme, SignerDigest, V4Report, verify as verify_apk_signatures,
    verify_v4 as verify_apk_v4_idsig,
};
pub use arsc::{
    RES_STRING_POOL_TYPE, RES_TABLE_PACKAGE_TYPE, RES_TABLE_TYPE, RES_TABLE_TYPE_SPEC_TYPE,
    RES_TABLE_TYPE_TYPE, ResBagItem, ResChunkHeader, ResEntry, ResEntryValue, ResStringPool,
    ResTablePackage, ResTypeConfig, ResValue, ResourceTable, parse_arsc,
};
pub use attributes::{
    BootstrapMethod, ClassStructure, RecordComponent, analyze as analyze_class_structure,
};
pub use axml::{
    AxmlAttribute, AxmlNode, AxmlTree, ResourceIdResolver, format_res_value, parse as parse_axml,
};
pub use backends::{
    AndroidBackend, BackendCapability, BackendInvocation, JvmBackend, detect_available,
    invoke_android, invoke_jvm,
};
pub use bytecode::{
    CodeAttribute, ExceptionEntry, Instruction, OpcodeInfo, OperandShape, Operands, branch_target,
    class_internal_name_at, disassemble, escape_java_string, field_descriptor_at,
    method_name_descriptor_at, opcode_info, parse_code_attribute, resolve_ref,
    validate_code_attribute,
};
pub use bytecode_eval::{
    CallerContext, CallerKeyedReport, DecryptMethod, EvalError, evaluate_decrypt,
    find_decrypt_methods, java_string_hash, recover_caller_keyed_strings,
    recover_reflective_self_hash_empty_fold,
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
pub use dalvik_blackobf::{
    BlackObfDeflatten, BlackObfReport, deflatten_blackobfuscator, detect_blackobfuscator,
    java_string_hashcode,
};
pub use dalvik_cfg::{DalvikMethodCfg, build_dalvik_cfg, build_dalvik_cfg_from_code_item};
pub use dalvik_decompile::{
    DecompiledDex, decompile_dex, decompile_dex_bytes as decompile_dex_from_bytes,
};
pub use dalvik_dexguard::{
    DalvikCffReport, DalvikMethodCff, unflatten_code_item, unflatten_dex_methods,
};
pub use dalvik_pack_recover::{
    LocatedPayload, PackageRecoveryReport, PackingScheme, PackingSchemeKind, RecoveryOutcome,
    SchemeCandidate, VerificationSignals, recover_packed_dex,
};
pub use dalvik_pack_stub_loader::{
    StubLoaderKeystreamScheme, encode_container as encode_stub_loader_container,
};
pub use dalvik_strdec::{
    DecryptedString, DexStringRecovery, DexStringRecoveryReport, NativeIntKey, ReflectiveCallSite,
    recover as recover_dex_reflection_strings, recover_report as recover_dex_reflection_report,
    recover_with_native_keys as recover_dex_reflection_strings_with_native_keys,
    recover_with_native_keys_report as recover_dex_reflection_report_with_native_keys,
};
pub use dalvik_strdec_generic::{
    CallSiteOutcome, CallSiteRecovery, GenericStringRecovery, SkipReason as DexInterpSkipReason,
    recover as recover_dex_strings_generic,
};
#[cfg(feature = "opcode-census")]
pub use decompile::drain_unhandled_census;
pub use decompile::{
    DecompiledClass, class_access_keywords, decompile_class, decompile_class_with_inners,
    decompile_classfile_bytes, member_access_keywords,
};
pub use decompile_struct::{
    BasicBlock, BlockId, Cfg, Dominators, Edge, EdgeKind, ExceptionRegion, NaturalLoop,
    PrecomputedSwitch, Region, Structurer, SwitchKey, compute_dominators, find_natural_loops,
};
pub use descriptor::{
    JavaType, MethodDescriptor, binary_to_source, java_writable_identifier,
    parse_field as parse_field_descriptor, parse_method as parse_method_descriptor,
};
pub use dex::{
    ACC_ABSTRACT, ACC_NATIVE, CodeItem, CodeItemsReport, DEX_ENDIAN_TAG, DEX_MAGIC_PREFIX,
    DexCodeState, DexCodeTail, DexFile, DexHeader, DexMethodCode, DexVersion, FieldId, MethodId,
    MultiDex, NativeMethod, ProtoId, TryItem, extract_native_methods, parse as parse_dex,
    parse_code_items, parse_header as parse_dex_header, parse_multi_dex,
};
pub use dex2jar::{
    Dex2JarLimits, Dex2JarResult, TranslatedClass, TranslatedField, TranslatedMethod, assemble_jar,
    assemble_jar_with_limit, build_class_model, translate as translate_dex_to_jar,
    translate_dex_bytes, translate_with_limits,
};
pub use error::{Error, Result};
pub use format_wire::{format_java, format_kotlin, format_scala};
pub use frame_infer::{FrameInferOutcome, FrameInferReport, FrameState, infer_frames};
pub use hierarchy::{HierarchyKind, HierarchyNode, classfile_hierarchy_node, dex_hierarchy_nodes};
pub use jar::{
    AabExtract, AabModule, AarExtract, ApkExtract, ApksExtract, JIMAGE_MAGIC, JMOD_MAGIC, JarEntry,
    JarExtract, Jimage, JimageHeader, JimageResource, JmodExtract, extract as extract_jar,
    extract_aab, extract_aar, extract_apk, extract_apks, extract_jmod, parse_jimage,
    parse_jimage_header,
};
pub use jni::{
    JniPrototype, JniSurfaceReport, NativeLibrary, RegisteredNative, ResolvedNative,
    analyze as analyze_jni_surface, analyze_native_methods as analyze_jni_native_methods,
    emit_prototypes as emit_jni_prototypes, native_methods_from_class, recover_register_natives,
};
pub use jsr_inline::{JsrInlineReport, contains_jsr, inline_jsr_subroutines};
pub use kotlin::{KotlinKind, KotlinMetadata, recover_metadata as recover_kotlin_metadata};
#[cfg(feature = "llm-metadata")]
pub use llm::{JvmInstr, JvmLlmInput, METADATA_CAPABILITY as JVM_METADATA_CAPABILITY};
pub use name_disambig::{
    CollisionReport, NameDisambiguator, classify as classify_name_collisions,
    remap_class_bytes as remap_renamed_class_bytes, rewrite_active, with_rename_scope,
    with_self_rename_scope,
};
pub use oat::{
    DexOptHeader, InstructionSet, OAT_MAGIC, ODEX_MAGIC, OatEmbeddedDex, OatFile, OatHeader,
    OatVersion, OdexFile, extract_oat_dex, parse_oat, parse_oat_header, parse_odex,
    parse_odex_header,
};
pub use obfuscators::{
    CffUndoStats, Detection, Protector, StringStrip, UpstreamStatus, WatermarkFinding, detect_all,
    detect_allatori_watermarks, strip_encrypted_strings, undo_control_flow, upstream_status,
};
pub use proguard::{
    AppliedNames, ClassHierarchy, ClassMapping, FieldMapping, InheritedField, InheritedMethod,
    LineRange, Mapping as ProguardMapping, MethodLineRecord, MethodMapping, RetracedFrame,
    UnmappedHeuristics, apply_to_classfile as apply_proguard_mapping,
    apply_to_classfile_with_hierarchy as apply_proguard_mapping_with_hierarchy, heuristic_recover,
    parse as parse_proguard_mapping, remap_descriptor as remap_proguard_descriptor,
    source_params_to_descriptor, source_type_to_descriptor,
};
pub use proguard_fingerprint::{
    ClassSignature, FieldSignature, FingerprintReport, LibrarySignatureSet, MethodSignature,
    ReidentifiedClass, ReidentifiedField, ReidentifiedMethod,
    fingerprint as fingerprint_library_symbols, is_stable_type,
};
pub use protectors::name_keyed::{NameKeyedCipher, NameKeyedRecovery, recover_name_keyed};
pub use protectors::{
    PeelStatus, PeeledClass, ProtectorFamily as ProtectorFamilyKind, ProtectorPeelReport,
    allatori as allatori_protector, dasho as dasho_protector,
    detect_family as detect_protector_family, dexguard as dexguard_protector,
    name_keyed as name_keyed_protector, peel_and_decompile as peel_and_decompile_classfile,
    peel_classfile, peel_for_family, stringer as stringer_protector, substitute_recovered_strings,
    zelix as zelix_protector,
};
pub use provenance_header::{
    java_decompiled_header, kotlin_decompiled_header, render_java_with_header,
    render_kotlin_with_header, render_scala_with_header, render_smali_with_header,
    scala_decompiled_header, smali_disasm_header,
};
pub use rasp::{RaspReport, RaspSignal, RaspVendor, detect_in_apk as detect_rasp_in_apk};
#[cfg(feature = "semantic-reach")]
pub use reach::{
    CaptureError, Captured, Observation, ObservationPhase, SemanticEntryPoint, SemanticSurface,
    capture_observations,
};
pub use scala::{Demangled as ScalaDemangled, demangle as demangle_scala};
pub use sccp::{SccpReport, simplify_flattened_cfg};
pub use smali::{SmaliEmission, emit as emit_smali, emit_method_body, emit_method_body_from_insns};
pub use stackmap::{
    StackMapReport, VerificationType, analyze_stack_map, analyze_stack_map_with_entry_frame,
    entry_frame_locals, required_frame_offsets,
};
pub use string_recovery::{
    RecoveryError, StringDecryptStub, StringRecoveryReport, emulate_string_decrypt,
    find_string_decrypt_methods, recover_strings,
};
pub use stub_emulator::{
    DecryptStub, EmulationError, decrypt_constant, emulate_char_array, find_char_array_decrypt,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
