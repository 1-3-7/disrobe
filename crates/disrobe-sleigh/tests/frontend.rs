use disrobe_sleigh::SleighError;
use disrobe_sleigh::compiler::{
    CompiledSpec, ConflictPolicy, ContextState, DecodeOutcome, compile_spec_with_policy,
};
use disrobe_sleigh::syntax::{
    AttachmentKind, Endian, PatternAtom, PatternExpr, SleighSpec, parse_spec,
};
use disrobe_sleigh::vendor::{
    preprocessed_aarch64_source, preprocessed_arm32_source, preprocessed_mips32be_source,
    preprocessed_mips32le_source,
};

#[test]
fn parses_declarations_attachments_context_and_constructor_sections() {
    let source: &str = r#"
define endian=little;
define space ram type=ram_space size=8 default;
define space register type=register_space size=4;
define register offset=0 size=8 [ x0 x1 ];
define register offset=0 size=4 [ w0 w1 ];
define register offset=0x100 size=4 contextreg;
define context contextreg
  mode=(0,0) noflow
;
define token instruction(16) endian=little
  opcode=(12,15)
  rd=(0,3)
;
attach variables rd [ w0 w1 ];
attach names opcode [ "copy" "add" ];
attach values mode [ 0 1 ];
define pcodeop system_op;
operand: rd is rd { export rd; }
:copy operand is opcode=0 & operand [ mode=1; ] { operand = operand; }
:next operand is opcode=1 ; operand { system_op(operand); }
"#;

    let result: Result<SleighSpec, SleighError> = parse_spec(source);
    assert!(result.is_ok(), "{result:?}");
    let Ok(spec) = result else {
        return;
    };
    assert_eq!(spec.endian, Some(Endian::Little));
    assert_eq!(spec.spaces.len(), 2);
    assert_eq!(spec.registers.len(), 5);
    assert_eq!(spec.contexts.len(), 1);
    assert_eq!(spec.tokens.len(), 1);
    assert_eq!(spec.tokens[0].fields.len(), 2);
    assert_eq!(spec.attachments.len(), 3);
    assert_eq!(spec.attachments[0].kind, AttachmentKind::Variables);
    assert!(spec.pcodeops.contains("system_op"));
    assert_eq!(spec.constructors.len(), 3);
    assert_eq!(spec.constructors[0].table, "operand");
    assert_eq!(spec.constructors[1].table, "instruction");
    assert!(matches!(spec.constructors[1].pattern, PatternExpr::All(_)));
    assert!(matches!(
        spec.constructors[2].pattern,
        PatternExpr::Next(_, _)
    ));
    assert!(!spec.constructors[1].context_tokens.is_empty());
    assert!(!spec.constructors[1].semantic_tokens.is_empty());
}

#[test]
fn parses_vendored_scalar_aarch64_spec() {
    let source_result: Result<String, SleighError> = preprocessed_aarch64_source();
    assert!(source_result.is_ok(), "{source_result:?}");
    let Ok(source) = source_result else {
        return;
    };
    let result: Result<SleighSpec, SleighError> = parse_spec(&source);
    assert!(result.is_ok(), "{result:?}");
    let Ok(spec) = result else {
        return;
    };
    assert_eq!(spec.alignment, Some(4));
    assert_eq!(spec.endian, Some(Endian::Little));
    assert!(
        spec.bitranges
            .iter()
            .any(|definition| definition.name == "gcr_el1.exclude")
    );
    assert!(spec.spaces.len() >= 2);
    assert!(spec.tokens.iter().any(|token| token.name == "instrAARCH64"));
    assert!(spec.registers.iter().any(|register| register.name == "x0"));
    assert!(
        spec.contexts
            .iter()
            .any(|context| context.name == "ShowPAC")
    );
    assert!(spec.pcodeops.contains("CallSupervisor"));
    assert!(spec.constructors.len() > 1_000);
    let residual_count: usize = spec
        .constructors
        .iter()
        .filter(|constructor| has_residual(&constructor.pattern))
        .count();
    assert_eq!(residual_count, 0);
    for mnemonic in ["add", "sub", "ldr", "str", "ret", "csel"] {
        assert!(spec.constructors.iter().any(|constructor| {
            constructor.table == "instruction" && constructor.mnemonic == mnemonic
        }));
    }
}

#[test]
fn parses_vendored_arm32_and_thumb_spec() {
    let source_result: Result<String, SleighError> = preprocessed_arm32_source();
    assert!(source_result.is_ok(), "{source_result:?}");
    let result: Result<SleighSpec, SleighError> = source_result
        .as_deref()
        .map_err(Clone::clone)
        .and_then(parse_spec);
    assert!(result.is_ok(), "{result:?}");
    let Ok(spec) = result else {
        return;
    };
    assert_eq!(spec.endian, Some(Endian::Little));
    assert!(spec.contexts.iter().any(|context| context.name == "TMode"));
    assert!(spec.tokens.iter().any(|token| token.bits == 16));
    assert!(spec.tokens.iter().any(|token| token.bits == 32));
    for mnemonic in ["add", "ldr", "stm", "bl", "bx", "push", "pop"] {
        assert!(spec.constructors.iter().any(|constructor| {
            constructor.table == "instruction" && constructor.mnemonic == mnemonic
        }));
    }
}

#[test]
fn parses_vendored_mips32_specs_in_both_byte_orders() {
    for source_result in [
        preprocessed_mips32le_source(),
        preprocessed_mips32be_source(),
    ] {
        assert!(source_result.is_ok(), "{source_result:?}");
        let result: Result<SleighSpec, SleighError> = source_result
            .as_deref()
            .map_err(Clone::clone)
            .and_then(parse_spec);
        assert!(result.is_ok(), "{result:?}");
        let Ok(spec) = result else {
            continue;
        };
        assert!(
            spec.contexts
                .iter()
                .any(|context| context.name == "ISA_MODE")
        );
        assert!(spec.constructors.iter().any(|constructor| {
            constructor.table == "instruction"
                && constructor
                    .semantic_tokens
                    .iter()
                    .any(|token| token == "delayslot")
        }));
        for mnemonic in ["addiu", "lw", "sw", "beq", "jal", "jr", "mult"] {
            assert!(spec.constructors.iter().any(|constructor| {
                constructor.table == "instruction" && constructor.mnemonic == mnemonic
            }));
        }
    }
}

#[test]
fn compiles_vendored_multiarch_decision_trees() {
    for source_result in [
        preprocessed_arm32_source(),
        preprocessed_mips32le_source(),
        preprocessed_mips32be_source(),
    ] {
        assert!(source_result.is_ok(), "{source_result:?}");
        let parsed: Result<SleighSpec, SleighError> = source_result
            .as_deref()
            .map_err(Clone::clone)
            .and_then(parse_spec);
        assert!(parsed.is_ok(), "{parsed:?}");
        let compiled: Result<CompiledSpec, SleighError> =
            parsed.and_then(|spec| compile_spec_with_policy(spec, ConflictPolicy::FirstDefined));
        assert!(compiled.is_ok(), "{compiled:?}");
        assert!(!compiled.map_or(true, |spec| spec.decision_nodes().is_empty()));
    }
}

#[test]
fn arm_decision_tree_selects_a32_and_thumb_constructors() {
    let source: String = preprocessed_arm32_source().unwrap_or_default();
    let spec: SleighSpec = parse_spec(&source).unwrap_or_default();
    let compiled: Result<CompiledSpec, SleighError> =
        compile_spec_with_policy(spec, ConflictPolicy::FirstDefined);
    assert!(compiled.is_ok(), "{compiled:?}");
    let Ok(compiled) = compiled else {
        return;
    };
    let mut a32_context: ContextState = ContextState::new();
    a32_context.insert("TMode".to_owned(), 0);
    a32_context.insert("ARMcond".to_owned(), 1);
    a32_context.insert("ARMcondCk".to_owned(), 1);
    let a32: DecodeOutcome = compiled.decode(&0xe081_0182_u32.to_le_bytes(), 0, &a32_context);
    assert!(matches!(a32, DecodeOutcome::Matched(_)), "{a32:?}");

    let mut thumb_context: ContextState = ContextState::new();
    thumb_context.insert("TMode".to_owned(), 1);
    thumb_context.insert("ARMcondCk".to_owned(), 1);
    let thumb: DecodeOutcome = compiled.decode(&[0x88, 0x18, 0x2a, 0x20], 0, &thumb_context);
    let thumb_adds: Vec<_> = compiled
        .source()
        .constructors
        .iter()
        .filter(|constructor| constructor.mnemonic == "add")
        .take(12)
        .collect();
    assert!(
        matches!(thumb, DecodeOutcome::Matched(_)),
        "{thumb:?} {thumb_adds:#?}"
    );
}

fn has_residual(pattern: &PatternExpr) -> bool {
    match pattern {
        PatternExpr::All(parts) | PatternExpr::Any(parts) => parts.iter().any(has_residual),
        PatternExpr::Atom(PatternAtom::Residual(_)) => true,
        PatternExpr::Next(left, right) => has_residual(left) || has_residual(right),
        PatternExpr::Atom(_) | PatternExpr::True => false,
    }
}

#[test]
fn rejects_non_ascii_and_out_of_range_fields() {
    let non_ascii: Result<SleighSpec, SleighError> = parse_spec("define endian=little; é");
    assert!(non_ascii.is_err());
    let invalid_field: Result<SleighSpec, SleighError> =
        parse_spec("define endian=little; define token instruction(8) oversized=(0,8);");
    assert!(invalid_field.is_err());
}

#[test]
fn rejects_unknown_and_malformed_declarations() {
    for source in [
        "bogus; define endian=little;",
        "define mystery=1;",
        "define endian=middle;",
        "define space ram type=ram_space;",
        "define register offset=oops size=4 r0;",
        "define register size=4 r0;",
        "define endian=little garbage;",
        "define endian=little; define token instruction(8) endian=middle op=(0,7);",
        "define endian=little; define token instruction op=(0,7) (8);",
        "define endian=little; define token instruction(8) op=(0,7) garbage;",
        "define endian=little; define token instruction(8) op=(0,7) signedd;",
        "define endian=little; define token instruction(8) bad=(x,7) op=(0,7);",
        "define endian=little; define token instruction(8) op=(0,;",
    ] {
        let result: Result<SleighSpec, SleighError> = parse_spec(source);
        assert!(result.is_err(), "{source}: {result:?}");
    }
}

#[test]
fn rejects_excessive_with_nesting() {
    let mut source: String =
        "define endian=little; define token instruction(8) op=(0,7);".to_owned();
    for _ in 0..80 {
        source.push_str("with : op=0 {");
    }
    source.push_str(":nested is op=0 { export op; }");
    for _ in 0..80 {
        source.push('}');
    }
    let result: Result<SleighSpec, SleighError> = parse_spec(&source);
    assert!(result.is_err());
}

#[test]
fn token_concatenation_has_lower_precedence_than_alternatives() {
    let source: &str = r"
define endian=little;
define token first(8) head=(0,7);
define token second(8) tail=(0,7);
:choice is head=1 ; tail=2 | tail=3 { export tail; }
";
    let parsed: Result<SleighSpec, SleighError> = parse_spec(source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return;
    };
    let Some(constructor) = spec.constructors.first() else {
        return;
    };
    assert!(matches!(
        constructor.pattern,
        PatternExpr::Next(_, ref right) if matches!(right.as_ref(), PatternExpr::Any(parts) if parts.len() == 2)
    ));
}
