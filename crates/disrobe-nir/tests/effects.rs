#![allow(clippy::expect_used)]

use disrobe_core::recovery::ConfidenceTier;
use disrobe_nir::{
    Avm2Effect, BehaviorAnnotation, BehaviorAnnotations, BehaviorKind, CallOtherEffect,
    CallOtherKey, CallOtherModel, CilEffect, DalvikEffect, DialectEffect, EffectContext,
    EffectProvenance, EffectRow, EffectRowError, EffectTable, EffectTableError, FileSourceOffset,
    HardEffect, HardEffects, ImportEffectModel, ImportKey, JvmEffect, LuaEffect, NativeEffect,
    NirArtifact, NirFunction, NirInstr, NirModule, NirOp, PythonEffect, SourceBytes,
    SourceEncoding, SourceLang, SourceOffset, SourceOffsetUnavailable, SourceRef, SourceUnit,
    SyscallNumber, SyscallResolution, SyscallSite, WasmEffect, YarvEffect, derive_behaviors,
    derive_effect_row,
};

fn instr(lang: SourceLang, op: NirOp, mnemonic: &str) -> NirInstr {
    NirInstr {
        address: 0x1000,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: Vec::new(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(lang, 0x1000),
    }
}

const fn empty_context() -> EffectContext {
    EffectContext::new()
}

#[test]
fn every_hard_effect_is_representable_under_every_provenance() {
    const PROVENANCES: [EffectProvenance; 4] = [
        EffectProvenance::Encoding,
        EffectProvenance::ResolvedImport,
        EffectProvenance::ResolvedSyscall,
        EffectProvenance::Unknown,
    ];
    for effect in HardEffect::ALL {
        for provenance in PROVENANCES {
            let row: EffectRow = EffectRow::builder(SourceLang::NativeX86)
                .effect(effect, provenance)
                .build();
            assert!(row.contains(effect), "{} not representable", effect.label());
            assert_eq!(
                row.provenance_of(effect),
                Some(provenance),
                "{} lost its provenance",
                effect.label()
            );
            row.validate().expect("single effect row is valid");
        }
    }
    assert_eq!(HardEffect::ALL.len(), 18);
}

#[test]
fn unknown_is_a_distinct_value_from_none() {
    let none: EffectRow = EffectRow::none(SourceLang::Jvm);
    let unknown: EffectRow = EffectRow::unknown(SourceLang::Jvm);

    assert!(none.is_effect_free());
    assert!(!none.is_unknown());
    assert!(unknown.is_unknown());
    assert!(!unknown.is_effect_free());
    assert_ne!(none, unknown);
    assert_eq!(
        unknown.provenance_of(HardEffect::Unmodelled),
        Some(EffectProvenance::Unknown)
    );
    assert_eq!(none.provenance_of(HardEffect::Unmodelled), None);
}

#[test]
fn an_unresolved_import_is_unknown_rather_than_effect_free() {
    let call: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::ExternCall {
            symbol: "CreateFileW".to_owned(),
        },
        "CALL",
    );
    let row: EffectRow = derive_effect_row(&call, &empty_context());

    assert_eq!(
        row.provenance_of(HardEffect::ImportCall),
        Some(EffectProvenance::Encoding)
    );
    assert_eq!(
        row.provenance_of(HardEffect::Unmodelled),
        Some(EffectProvenance::Unknown)
    );
    assert!(!row.is_effect_free());
    assert_eq!(
        row.dialect(),
        DialectEffect::Native(NativeEffect::ImportCall)
    );
}

#[test]
fn a_resolved_import_carries_import_provenance_and_drops_the_unknown_effect() {
    let mut context: EffectContext = EffectContext::new();
    context
        .insert_import(
            ImportKey::new("NtCreateFile"),
            ImportEffectModel::new(
                HardEffects::empty()
                    .with(HardEffect::MemoryWrite)
                    .with(HardEffect::Syscall),
            )
            .with_behavior(BehaviorAnnotation::new(
                BehaviorKind::FileAccess,
                ConfidenceTier::Semantic,
            )),
        )
        .expect("import model fits the model budget");

    let call: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::ExternCall {
            symbol: "NtCreateFile".to_owned(),
        },
        "CALL",
    );
    let row: EffectRow = derive_effect_row(&call, &context);

    assert_eq!(
        row.provenance_of(HardEffect::MemoryWrite),
        Some(EffectProvenance::ResolvedImport)
    );
    assert_eq!(
        row.provenance_of(HardEffect::Syscall),
        Some(EffectProvenance::ResolvedImport)
    );
    assert!(!row.is_unknown());

    let behaviors: BehaviorAnnotations = derive_behaviors(&call, &context);
    assert_eq!(
        behaviors.tier_of(BehaviorKind::FileAccess),
        Some(ConfidenceTier::Semantic)
    );
    assert_eq!(behaviors.tier_of(BehaviorKind::NetworkAccess), None);
}

#[test]
fn import_resolution_is_exact_and_never_matches_a_longer_name() {
    let mut context: EffectContext = EffectContext::new();
    context
        .insert_import(
            ImportKey::new("NtCreateFile"),
            ImportEffectModel::new(HardEffects::empty().with(HardEffect::MemoryWrite)),
        )
        .expect("import model fits the model budget");

    for symbol in [
        "NtCreateFileX",
        "ntcreatefile",
        "tCreateFile",
        "NtCreateFil",
    ] {
        let call: NirInstr = instr(
            SourceLang::NativeX86,
            NirOp::ExternCall {
                symbol: symbol.to_owned(),
            },
            "CALL",
        );
        let row: EffectRow = derive_effect_row(&call, &context);
        assert!(row.is_unknown(), "{symbol} inherited a foreign model");
        assert!(!row.contains(HardEffect::MemoryWrite));
    }
}

#[test]
fn an_unmodelled_call_other_sets_the_unmodelled_effect() {
    let userop: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::CallOther {
            effect: CallOtherEffect {
                name: "vendor_specific_userop".to_owned(),
                reads: Vec::new(),
                writes: Vec::new(),
                reads_memory: false,
                writes_memory: false,
                unknown_registers: false,
            },
        },
        "CALLOTHER",
    );
    let row: EffectRow = derive_effect_row(&userop, &empty_context());

    assert_eq!(
        row.provenance_of(HardEffect::Unmodelled),
        Some(EffectProvenance::Unknown)
    );
    assert_eq!(
        row.dialect(),
        DialectEffect::Native(NativeEffect::UserOperation)
    );
}

#[test]
fn an_atomic_operation_is_one_effect_not_a_separate_read_and_write() {
    let mut context: EffectContext = EffectContext::new();
    context
        .insert_call_other(
            CallOtherKey::new("LOCK"),
            CallOtherModel::new(
                HardEffects::empty().with(HardEffect::AtomicReadModifyWrite),
                NativeEffect::AtomicReadModifyWrite,
            ),
        )
        .expect("userop model fits the model budget");

    let userop: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::CallOther {
            effect: CallOtherEffect {
                name: "LOCK".to_owned(),
                reads: Vec::new(),
                writes: Vec::new(),
                reads_memory: true,
                writes_memory: true,
                unknown_registers: false,
            },
        },
        "CALLOTHER",
    );
    let row: EffectRow = derive_effect_row(&userop, &context);

    assert!(row.contains(HardEffect::AtomicReadModifyWrite));
    assert!(!row.contains(HardEffect::MemoryRead));
    assert!(!row.contains(HardEffect::MemoryWrite));
    row.validate().expect("normalized atomic row is valid");

    let split: Result<EffectRow, EffectRowError> = EffectRow::from_parts(
        SourceLang::NativeX86,
        [
            (
                EffectProvenance::Encoding,
                HardEffects::empty()
                    .with(HardEffect::AtomicReadModifyWrite)
                    .with(HardEffect::MemoryRead),
            ),
            (EffectProvenance::ResolvedImport, HardEffects::empty()),
            (EffectProvenance::ResolvedSyscall, HardEffects::empty()),
            (EffectProvenance::Unknown, HardEffects::empty()),
        ],
        HardEffects::empty(),
        DialectEffect::Native(NativeEffect::AtomicReadModifyWrite),
        SourceEncoding::Present,
    );
    assert_eq!(split, Err(EffectRowError::AtomicSplit));
}

#[test]
fn the_same_nir_op_does_not_flatten_across_source_languages() {
    let native_allocation: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::ExternCall {
            symbol: "malloc".to_owned(),
        },
        "CALL",
    );
    let managed_allocation: NirInstr =
        instr(SourceLang::Cil, NirOp::Call { target: None }, "newobj");
    let jvm_allocation: NirInstr = instr(SourceLang::Jvm, NirOp::Call { target: None }, "new");

    let native_row: EffectRow = derive_effect_row(&native_allocation, &empty_context());
    let managed_row: EffectRow = derive_effect_row(&managed_allocation, &empty_context());
    let jvm_row: EffectRow = derive_effect_row(&jvm_allocation, &empty_context());

    assert_eq!(
        native_row.dialect(),
        DialectEffect::Native(NativeEffect::ImportCall)
    );
    assert_eq!(
        managed_row.dialect(),
        DialectEffect::Cil(CilEffect::NewObject)
    );
    assert_eq!(jvm_row.dialect(), DialectEffect::Jvm(JvmEffect::NewObject));
    assert_ne!(native_row.dialect(), managed_row.dialect());
    assert_ne!(managed_row.dialect(), jvm_row.dialect());
}

#[test]
fn the_interrupt_op_means_a_syscall_in_native_code_and_a_raise_in_script_code() {
    let native: NirInstr = instr(SourceLang::NativeX86, NirOp::Interrupt, "SYSCALL");
    let python: NirInstr = instr(SourceLang::Python, NirOp::Interrupt, "raise");
    let ruby: NirInstr = instr(SourceLang::Yarv, NirOp::Interrupt, "throw");

    let native_row: EffectRow = derive_effect_row(&native, &empty_context());
    let python_row: EffectRow = derive_effect_row(&python, &empty_context());
    let ruby_row: EffectRow = derive_effect_row(&ruby, &empty_context());

    assert!(native_row.contains(HardEffect::Syscall));
    assert!(!native_row.contains(HardEffect::ExceptionRaise));
    assert!(python_row.contains(HardEffect::ExceptionRaise));
    assert!(!python_row.contains(HardEffect::Syscall));
    assert!(ruby_row.contains(HardEffect::ExceptionRaise));
    assert_eq!(
        python_row.dialect(),
        DialectEffect::Python(PythonEffect::RaiseException)
    );
    assert_eq!(ruby_row.dialect(), DialectEffect::Yarv(YarvEffect::Throw));
}

#[test]
fn every_source_language_populates_its_own_dialect_vocabulary() {
    let cases: [(SourceLang, NirOp, &str, DialectEffect); 10] = [
        (
            SourceLang::NativeX86,
            NirOp::Return,
            "RETURN",
            DialectEffect::Native(NativeEffect::Return),
        ),
        (
            SourceLang::NativeArm,
            NirOp::Return,
            "RETURN",
            DialectEffect::Native(NativeEffect::Return),
        ),
        (
            SourceLang::Cil,
            NirOp::Nop,
            "stfld",
            DialectEffect::Cil(CilEffect::StoreField),
        ),
        (
            SourceLang::Jvm,
            NirOp::Nop,
            "monitorenter",
            DialectEffect::Jvm(JvmEffect::MonitorEnter),
        ),
        (
            SourceLang::Dalvik,
            NirOp::Nop,
            "move-exception",
            DialectEffect::Dalvik(DalvikEffect::MoveException),
        ),
        (
            SourceLang::Wasm,
            NirOp::Nop,
            "memory.grow",
            DialectEffect::Wasm(WasmEffect::MemoryGrow),
        ),
        (
            SourceLang::Avm2,
            NirOp::Nop,
            "getproperty",
            DialectEffect::Avm2(Avm2Effect::GetProperty),
        ),
        (
            SourceLang::Lua,
            NirOp::Nop,
            "SETTABUP",
            DialectEffect::Lua(LuaEffect::TableSet),
        ),
        (
            SourceLang::Python,
            NirOp::Load,
            "load",
            DialectEffect::Python(PythonEffect::LoadSubscript),
        ),
        (
            SourceLang::Yarv,
            NirOp::Nop,
            "setinstancevariable",
            DialectEffect::Yarv(YarvEffect::InstanceVariableSet),
        ),
    ];

    for (lang, op, mnemonic, expected) in cases {
        let row: EffectRow = derive_effect_row(&instr(lang, op, mnemonic), &empty_context());
        assert_eq!(row.dialect(), expected, "{} lost its dialect", lang.label());
        assert_eq!(row.lang(), lang);
        row.validate().expect("derived row is valid");
    }

    let beam: EffectRow = derive_effect_row(
        &instr(SourceLang::Beam, NirOp::Nop, "send"),
        &empty_context(),
    );
    assert!(matches!(beam.dialect(), DialectEffect::Beam(_)));

    let unknown: EffectRow = derive_effect_row(
        &instr(SourceLang::Unknown, NirOp::Nop, "?"),
        &empty_context(),
    );
    assert!(unknown.is_unknown());
    assert_eq!(unknown.dialect(), DialectEffect::None);
}

#[test]
fn a_dialect_effect_cannot_be_attached_to_a_foreign_language() {
    let mismatched: Result<EffectRow, EffectRowError> = EffectRow::from_parts(
        SourceLang::Jvm,
        [
            (EffectProvenance::Encoding, HardEffects::empty()),
            (EffectProvenance::ResolvedImport, HardEffects::empty()),
            (EffectProvenance::ResolvedSyscall, HardEffects::empty()),
            (EffectProvenance::Unknown, HardEffects::empty()),
        ],
        HardEffects::empty(),
        DialectEffect::Cil(CilEffect::NewObject),
        SourceEncoding::Present,
    );
    assert_eq!(
        mismatched,
        Err(EffectRowError::DialectLangMismatch {
            lang: SourceLang::Jvm
        })
    );
}

#[test]
fn lifter_memory_facts_are_never_lost_by_the_row() {
    const LANGS: [SourceLang; 11] = [
        SourceLang::NativeX86,
        SourceLang::NativeArm,
        SourceLang::Wasm,
        SourceLang::Jvm,
        SourceLang::Dalvik,
        SourceLang::Cil,
        SourceLang::Python,
        SourceLang::Lua,
        SourceLang::Avm2,
        SourceLang::Yarv,
        SourceLang::Beam,
    ];
    for lang in LANGS {
        let mut reader: NirInstr = instr(lang, NirOp::Nop, "opaque");
        reader.reads_memory = true;
        let mut writer: NirInstr = instr(lang, NirOp::Nop, "opaque");
        writer.writes_memory = true;

        let read_row: EffectRow = derive_effect_row(&reader, &empty_context());
        let write_row: EffectRow = derive_effect_row(&writer, &empty_context());

        assert!(
            read_row.contains(HardEffect::MemoryRead),
            "{} dropped a lifted memory read",
            lang.label()
        );
        assert_eq!(
            read_row.provenance_of(HardEffect::MemoryRead),
            Some(EffectProvenance::Encoding)
        );
        assert!(
            write_row.contains(HardEffect::MemoryWrite),
            "{} dropped a lifted memory write",
            lang.label()
        );
    }
}

#[test]
fn syscall_number_resolution_moves_effects_out_of_the_unknown_set() {
    let site: NirInstr = instr(SourceLang::NativeX86, NirOp::Interrupt, "SYSCALL");

    let unresolved: EffectRow = derive_effect_row(&site, &empty_context());
    assert_eq!(
        unresolved.dialect(),
        DialectEffect::Native(NativeEffect::Syscall(SyscallNumber::Unresolved))
    );
    assert!(unresolved.is_unknown());

    let mut ambiguous_context: EffectContext = EffectContext::new();
    ambiguous_context
        .insert_syscall(
            0x1000,
            SyscallSite::new(SyscallResolution::Ambiguous, HardEffects::empty()),
        )
        .expect("syscall site fits the model budget");
    let ambiguous: EffectRow = derive_effect_row(&site, &ambiguous_context);
    assert_eq!(
        ambiguous.dialect(),
        DialectEffect::Native(NativeEffect::Syscall(SyscallNumber::ArchitectureAmbiguous))
    );
    assert!(ambiguous.is_unknown());

    let mut resolved_context: EffectContext = EffectContext::new();
    resolved_context
        .insert_syscall(
            0x1000,
            SyscallSite::new(
                SyscallResolution::Number(1),
                HardEffects::empty().with(HardEffect::MemoryRead),
            ),
        )
        .expect("syscall site fits the model budget");
    let resolved: EffectRow = derive_effect_row(&site, &resolved_context);
    assert_eq!(
        resolved.dialect(),
        DialectEffect::Native(NativeEffect::Syscall(SyscallNumber::Resolved(1)))
    );
    assert_eq!(
        resolved.provenance_of(HardEffect::MemoryRead),
        Some(EffectProvenance::ResolvedSyscall)
    );
    assert_eq!(
        resolved.provenance_of(HardEffect::Syscall),
        Some(EffectProvenance::Encoding)
    );
    assert!(!resolved.is_unknown());
}

#[test]
fn an_unresolved_indirect_call_is_control_and_unknown_at_once() {
    let indirect: NirInstr = instr(SourceLang::NativeX86, NirOp::IndirectCall, "CALLIND");
    let row: EffectRow = derive_effect_row(&indirect, &empty_context());

    assert_eq!(
        row.provenance_of(HardEffect::IndirectCall),
        Some(EffectProvenance::Encoding)
    );
    assert_eq!(
        row.provenance_of(HardEffect::Unmodelled),
        Some(EffectProvenance::Unknown)
    );
}

#[test]
fn a_conditional_effect_is_marked_and_must_be_derived() {
    let conditional: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::CondBranch { target: None },
        "CBRANCH",
    );
    let row: EffectRow = derive_effect_row(&conditional, &empty_context());
    assert!(row.contains(HardEffect::IndirectJump));
    assert!(row.is_conditional(HardEffect::IndirectJump));
    row.validate().expect("conditional row is valid");

    let unconditional: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::Branch { target: None },
        "BRANCH",
    );
    let plain: EffectRow = derive_effect_row(&unconditional, &empty_context());
    assert!(plain.contains(HardEffect::IndirectJump));
    assert!(!plain.is_conditional(HardEffect::IndirectJump));

    let dangling: Result<EffectRow, EffectRowError> = EffectRow::from_parts(
        SourceLang::NativeX86,
        [
            (EffectProvenance::Encoding, HardEffects::empty()),
            (EffectProvenance::ResolvedImport, HardEffects::empty()),
            (EffectProvenance::ResolvedSyscall, HardEffects::empty()),
            (EffectProvenance::Unknown, HardEffects::empty()),
        ],
        HardEffects::empty().with(HardEffect::MemoryWrite),
        DialectEffect::None,
        SourceEncoding::Present,
    );
    assert_eq!(
        dangling,
        Err(EffectRowError::ConditionalNotDerived {
            effect: HardEffect::MemoryWrite
        })
    );
}

#[test]
fn provenance_sets_stay_disjoint_across_a_whole_derived_function() {
    let module: NirModule = mixed_module();
    let table: EffectTable =
        EffectTable::for_module(&module, &empty_context()).expect("table fits its budget");

    for row in table.function_rows(0).expect("function zero has rows") {
        row.validate().expect("derived row is valid");
        let mut seen: HardEffects = HardEffects::empty();
        for provenance in [
            EffectProvenance::Encoding,
            EffectProvenance::ResolvedImport,
            EffectProvenance::ResolvedSyscall,
            EffectProvenance::Unknown,
        ] {
            let set: HardEffects = row.provenance_set(provenance);
            assert!(seen.intersection(set).is_empty(), "provenance sets overlap");
            seen = seen.union(set);
        }
        assert_eq!(seen, row.effects());
    }
}

fn mixed_module() -> NirModule {
    NirModule {
        source_hash: [0x11; 32],
        lang: SourceLang::NativeX86,
        functions: vec![NirFunction {
            name: "mixed".to_owned(),
            address: 0x1000,
            end: 0x1010,
            is_export: false,
            instructions: vec![
                instr(SourceLang::NativeX86, NirOp::Interrupt, "SYSCALL"),
                instr(
                    SourceLang::NativeX86,
                    NirOp::ExternCall {
                        symbol: "unknown_import".to_owned(),
                    },
                    "CALL",
                ),
                instr(SourceLang::NativeX86, NirOp::IndirectCall, "CALLIND"),
                instr(SourceLang::NativeX86, NirOp::Return, "RETURN"),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0x1000),
        }],
        symbols: Vec::new(),
    }
}

#[test]
fn rows_are_keyed_per_operation_not_per_address() {
    let mut store: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::RawStore {
            addr: "rbx".to_owned(),
            value: "rax".to_owned(),
            size: 8,
        },
        "STORE",
    );
    store.writes_memory = true;
    let flag: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::Copy {
            src: "rax".to_owned(),
            size: 1,
        },
        "COPY",
    );
    let mut flag: NirInstr = flag;
    flag.operands = vec!["zf".to_owned()];

    let module: NirModule = NirModule {
        source_hash: [0x22; 32],
        lang: SourceLang::NativeX86,
        functions: vec![NirFunction {
            name: "lowered".to_owned(),
            address: 0x1000,
            end: 0x1001,
            is_export: false,
            instructions: vec![store, flag],
            source: SourceRef::new(SourceLang::NativeX86, 0x1000),
        }],
        symbols: Vec::new(),
    };

    let table: EffectTable =
        EffectTable::for_module(&module, &empty_context()).expect("table fits its budget");
    let first: EffectRow = table.row(0, 0).expect("first row exists");
    let second: EffectRow = table.row(0, 1).expect("second row exists");

    assert!(first.contains(HardEffect::MemoryWrite));
    assert!(!second.contains(HardEffect::MemoryWrite));
    assert!(second.contains(HardEffect::FlagWrite));
    assert_ne!(first, second);
    assert_eq!(table.len(), 2);
}

#[test]
fn a_synthesized_instruction_reports_that_it_has_no_source_encoding() {
    let module: NirModule = mixed_module();
    let units: Vec<SourceUnit> = vec![
        SourceUnit::new(
            0,
            0..3,
            SourceBytes::Original(vec![0x0f, 0x05, 0x90]),
            SourceOffset::File(FileSourceOffset::new(0, 3).expect("bounded file offset")),
        )
        .expect("valid source unit"),
        SourceUnit::new(
            0,
            3..4,
            SourceBytes::Synthesized,
            SourceOffset::Unavailable(SourceOffsetUnavailable::Synthesized),
        )
        .expect("valid synthesized unit"),
    ];
    let artifact: NirArtifact = NirArtifact::new(module, units).expect("valid provenance");
    let table: EffectTable =
        EffectTable::for_artifact(&artifact, &empty_context()).expect("table fits its budget");

    assert_eq!(
        table.row(0, 0).expect("row zero").source_encoding(),
        SourceEncoding::Present
    );
    assert_eq!(
        table.row(0, 3).expect("row three").source_encoding(),
        SourceEncoding::Synthesized
    );

    let module_only: EffectTable = EffectTable::for_module(artifact.module(), &empty_context())
        .expect("table fits its budget");
    assert_eq!(
        module_only.row(0, 3).expect("row three").source_encoding(),
        SourceEncoding::Unknown
    );
}

#[test]
fn behavioral_annotations_are_confidence_tagged_and_never_hard_effects() {
    let mut context: EffectContext = EffectContext::new();
    context
        .insert_import(
            ImportKey::new("connect"),
            ImportEffectModel::new(HardEffects::empty().with(HardEffect::MemoryRead))
                .with_behavior(BehaviorAnnotation::new(
                    BehaviorKind::NetworkAccess,
                    ConfidenceTier::Partial,
                ))
                .with_behavior(BehaviorAnnotation::new(
                    BehaviorKind::NetworkAccess,
                    ConfidenceTier::Semantic,
                )),
        )
        .expect("import model fits the model budget");

    let call: NirInstr = instr(
        SourceLang::NativeX86,
        NirOp::ExternCall {
            symbol: "connect".to_owned(),
        },
        "CALL",
    );
    let row: EffectRow = derive_effect_row(&call, &context);
    let behaviors: BehaviorAnnotations = derive_behaviors(&call, &context);

    assert_eq!(behaviors.len(), 1);
    assert_eq!(
        behaviors.tier_of(BehaviorKind::NetworkAccess),
        Some(ConfidenceTier::Semantic)
    );
    assert_eq!(
        row.effects(),
        HardEffects::empty()
            .with(HardEffect::ImportCall)
            .with(HardEffect::MemoryRead)
            .with(HardEffect::RegisterWrite)
    );
    assert_eq!(
        row.provenance_of(HardEffect::MemoryRead),
        Some(EffectProvenance::ResolvedImport)
    );
    assert!(!row.is_unknown());
}

#[test]
fn the_row_stays_compact_enough_to_attach_to_every_instruction() {
    assert!(
        EffectTable::row_byte_size() <= 32,
        "effect row grew to {} bytes",
        EffectTable::row_byte_size()
    );
    let module: NirModule = mixed_module();
    let table: EffectTable =
        EffectTable::for_module(&module, &empty_context()).expect("table fits its budget");
    assert_eq!(
        table.byte_size(),
        EffectTable::row_byte_size() * 4 + size_of::<u32>() * 2
    );
}

#[test]
fn a_table_rejects_a_module_it_was_not_derived_from() {
    let module: NirModule = mixed_module();
    let table: EffectTable =
        EffectTable::for_module(&module, &empty_context()).expect("table fits its budget");
    table
        .validate_against(&module)
        .expect("table matches its module");

    let mut shortened: NirModule = module;
    shortened.functions[0].instructions.truncate(2);
    assert_eq!(
        table.validate_against(&shortened),
        Err(EffectTableError::InstructionCount {
            function_index: 0,
            rows: 4,
            instructions: 2,
        })
    );
}

#[test]
fn reconstructed_tables_and_rows_reject_corrupted_wire_values() {
    assert_eq!(
        HardEffects::from_bits(1 << 31),
        Err(EffectRowError::UndefinedEffectBits { bits: 1 << 31 })
    );
    assert_eq!(
        HardEffects::from_bits(0b11),
        Ok(HardEffects::empty()
            .with(HardEffect::MemoryRead)
            .with(HardEffect::MemoryWrite))
    );

    let module: NirModule = mixed_module();
    let table: EffectTable =
        EffectTable::for_module(&module, &empty_context()).expect("table fits its budget");
    let rebuilt: EffectTable =
        EffectTable::from_parts(table.rows().to_vec(), table.function_starts().to_vec())
            .expect("round trip through the checked constructor");
    assert_eq!(rebuilt, table);

    assert_eq!(
        EffectTable::from_parts(table.rows().to_vec(), vec![0, 9]),
        Err(EffectTableError::RowCount {
            declared: 9,
            rows: 4,
        })
    );
    assert_eq!(
        EffectTable::from_parts(table.rows().to_vec(), vec![3, 4]),
        Err(EffectTableError::UnorderedFunctionStart { index: 0 })
    );
    assert_eq!(
        EffectTable::from_parts(table.rows().to_vec(), vec![0, 3, 1, 4]),
        Err(EffectTableError::UnorderedFunctionStart { index: 2 })
    );
    assert_eq!(
        EffectTable::from_parts(table.rows().to_vec(), Vec::new()),
        Err(EffectTableError::MissingFunctionStarts)
    );
}
