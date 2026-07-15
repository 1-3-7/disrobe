use std::collections::BTreeMap;
use std::fmt::{self, Write};

use disrobe_sleigh::SleighError;
use disrobe_sleigh::compiler::{
    CompiledSpec, ConflictPolicy, ContextState, DecodeMatch, DecodeOutcome, compile_spec,
    compile_spec_with_policy,
};
use disrobe_sleigh::syntax::{SleighSpec, parse_spec};
use disrobe_sleigh::vendor::preprocessed_aarch64_source;

fn compile_source(source: &str) -> Option<disrobe_sleigh::compiler::CompiledSpec> {
    let parsed: Result<SleighSpec, SleighError> = parse_spec(source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return None;
    };
    let compiled: Result<CompiledSpec, SleighError> = compile_spec(spec);
    assert!(compiled.is_ok(), "{compiled:?}");
    compiled.ok()
}

#[test]
fn decision_tree_resolves_fields_alternatives_and_subtables() {
    let source: &str = r#"
define endian=little;
define token first(8)
  op=(6,7)
  reg=(0,1)
;
define token second(8)
  tail=(0,7)
;
register_name: "r0" is reg=0 { export 0; }
register_name: "r1" is reg=1 { export 1; }
:copy register_name is (op=0 | op=1) & register_name { register_name = register_name; }
:short is op=2 { export op; }
:wide is op=2 ; tail=0xaa { export tail; }
"#;
    let Some(compiled) = compile_source(source) else {
        return;
    };
    assert!(compiled.decision_nodes().len() >= 2);
    let context: ContextState = BTreeMap::new();
    let first: DecodeOutcome = compiled.decode(&[0x01], 0, &context);
    assert!(matches!(
        first,
        DecodeOutcome::Matched(DecodeMatch { ref mnemonic, length: 1, .. }) if mnemonic == "copy"
    ));
    let next: DecodeOutcome = compiled.decode(&[0x80, 0xaa], 0, &context);
    assert!(
        matches!(
            next,
            DecodeOutcome::Matched(DecodeMatch { ref mnemonic, length: 2, .. }) if mnemonic == "wide"
        ),
        "{next:?}"
    );
    let truncated: DecodeOutcome = compiled.decode(&[0x80], 0, &context);
    assert!(matches!(
        truncated,
        DecodeOutcome::Truncated {
            available: 1,
            needed: 2,
        }
    ));
}

#[test]
fn equal_specificity_overlap_is_ambiguous() {
    let source: &str = r"
define endian=little;
define token instruction(8) op=(0,7);
:first is op=0b00000001 { export op; }
:second is op=0b00000001 { export op; }
";
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let outcome: DecodeOutcome = compiled.decode(&[1], 0, &BTreeMap::new());
    assert!(matches!(outcome, DecodeOutcome::Ambiguous { .. }));
}

#[test]
fn partial_unequal_specificity_overlap_is_ambiguous() {
    let source: &str = r"
define endian=little;
define token instruction(8) high=(4,7) low_six=(0,5);
:first is high=1 { export high; }
:second is low_six=0x12 { export low_six; }
";
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let outcome: DecodeOutcome = compiled.decode(&[0x12], 0, &BTreeMap::new());
    assert!(matches!(outcome, DecodeOutcome::Ambiguous { .. }));
}

#[test]
fn first_defined_policy_resolves_partial_overlap_by_source_order() {
    let source: &str = r"
define endian=little;
define token instruction(8) high=(4,7) low_six=(0,5);
:first is high=1 { export high; }
:second is low_six=0x12 { export low_six; }
";
    let parsed: Result<SleighSpec, SleighError> = parse_spec(source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return;
    };
    let compiled: Result<CompiledSpec, SleighError> =
        compile_spec_with_policy(spec, ConflictPolicy::FirstDefined);
    assert!(compiled.is_ok(), "{compiled:?}");
    let Ok(compiled) = compiled else {
        return;
    };
    let outcome: DecodeOutcome = compiled.decode(&[0x12], 0, &BTreeMap::new());
    assert!(matches!(
        outcome,
        DecodeOutcome::Matched(DecodeMatch { ref mnemonic, .. }) if mnemonic == "first"
    ));
}

#[test]
fn proper_pattern_containment_selects_the_special_case() {
    let source: &str = r"
define endian=little;
define token instruction(8) high=(4,7) low=(0,3);
:general is high=1 { export high; }
:special is high=1 & low=2 { export low; }
";
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let outcome: DecodeOutcome = compiled.decode(&[0x12], 0, &BTreeMap::new());
    assert!(matches!(
        outcome,
        DecodeOutcome::Matched(DecodeMatch { ref mnemonic, .. }) if mnemonic == "special"
    ));
}

#[test]
fn equal_specificity_subtable_overlap_is_ambiguous() {
    let source: &str = r#"
define endian=little;
define token instruction(8) op=(0,7);
choice: "first" is op=1 { export op; }
choice: "second" is op=1 { export op; }
:root choice is choice { export choice; }
"#;
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let context: ContextState = BTreeMap::new();
    let outcome: DecodeOutcome = compiled.decode(&[1], 0, &context);
    assert!(matches!(outcome, DecodeOutcome::Ambiguous { .. }));
}

#[test]
fn subtable_maximal_munch_reports_truncated_longer_alternative() {
    let source: &str = r#"
define endian=little;
define token first(8) op=(0,7);
define token second(8) tail=(0,7);
choice: "short" is op=1 { export op; }
choice: "wide" is op=1 ; tail=2 { export tail; }
:root choice is choice { export choice; }
"#;
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let outcome: DecodeOutcome = compiled.decode(&[1], 0, &BTreeMap::new());
    assert!(matches!(
        outcome,
        DecodeOutcome::Truncated {
            available: 1,
            needed: 2,
        }
    ));
}

#[test]
fn compiler_rejects_tokens_wider_than_runtime_reads() {
    let source: &str = r"
define endian=little;
define token instruction(72) op=(0,7);
:wide is op=0 { export op; }
";
    let parsed: Result<SleighSpec, SleighError> = parse_spec(source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return;
    };
    let compiled: Result<CompiledSpec, SleighError> = compile_spec(spec);
    assert!(compiled.is_err());
}

#[test]
fn compiler_rejects_tokens_without_effective_endian() {
    let source: &str = r"
define token instruction(8) op=(0,7);
:one is op=1 { export op; }
";
    let parsed: Result<SleighSpec, SleighError> = parse_spec(source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return;
    };
    let compiled: Result<CompiledSpec, SleighError> = compile_spec(spec);
    assert!(compiled.is_err());
}

#[test]
fn register_symbols_are_zero_width_pattern_operands() {
    let source: &str = r"
define endian=little;
define space register type=register_space size=4;
define register offset=0 size=4 r0;
define token instruction(8) op=(0,7);
:root is op=1 & r0 { export r0; }
";
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let outcome: DecodeOutcome = compiled.decode(&[1], 0, &BTreeMap::new());
    assert!(matches!(outcome, DecodeOutcome::Matched(_)));
}

#[test]
fn compiler_rejects_residual_and_undefined_patterns() {
    for pattern in ["op=1 trailing", "missing"] {
        let source: String = format!(
            "define endian=little; define token instruction(8) op=(0,7); :bad is {pattern} {{ export op; }}"
        );
        let parsed: Result<SleighSpec, SleighError> = parse_spec(&source);
        assert!(parsed.is_ok(), "{parsed:?}");
        let Ok(spec) = parsed else {
            return;
        };
        let compiled: Result<CompiledSpec, SleighError> = compile_spec(spec);
        assert!(compiled.is_err());
    }
}

#[test]
fn compiler_rejects_zero_width_instruction_patterns() {
    let source: &str = r"
define endian=little;
:zero is { export 0; }
";
    let parsed: Result<SleighSpec, SleighError> = parse_spec(source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return;
    };
    let compiled: Result<CompiledSpec, SleighError> = compile_spec(spec);
    assert!(compiled.is_err());
}

#[test]
fn decision_tree_maps_big_endian_token_bits_to_stream_bytes() {
    let source: &str = r"
define endian=big;
define token instruction(16) op=(8,15) tail=(0,7);
:first is op=0x12 & tail=0x34 { export op; }
:second is op=0x56 & tail=0x34 { export op; }
";
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let context: ContextState = BTreeMap::new();
    let outcome: DecodeOutcome = compiled.decode(&[0x12, 0x34], 0, &context);
    assert!(matches!(
        outcome,
        DecodeOutcome::Matched(DecodeMatch { ref mnemonic, .. }) if mnemonic == "first"
    ));
}

#[test]
fn right_hand_token_fields_contribute_to_next_token_length() {
    let source: &str = r"
define endian=little;
define register offset=0 size=4 contextreg;
define context contextreg mode=(0,7);
define token first(8) head=(0,7);
define token second(8) tail=(0,7);
:ctxnext is head=1 ; mode=tail { export tail; }
";
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let context: ContextState = BTreeMap::from([("mode".to_owned(), 7)]);
    let outcome: DecodeOutcome = compiled.decode(&[1, 7], 0, &context);
    assert!(matches!(
        outcome,
        DecodeOutcome::Matched(DecodeMatch { length: 2, .. })
    ));
}

#[test]
fn decoding_uses_the_token_referenced_by_each_constructor() {
    let source: &str = r"
define endian=little;
define token wide(16) unused=(0,15);
define token instruction(8) op=(0,7);
:one is op=1 { export op; }
";
    let Some(compiled) = compile_source(source) else {
        return;
    };
    let outcome: DecodeOutcome = compiled.decode(&[1], 0, &BTreeMap::new());
    assert!(matches!(
        outcome,
        DecodeOutcome::Matched(DecodeMatch { length: 1, .. })
    ));
}

#[test]
fn decision_tree_selects_real_aarch64_scalar_constructors() {
    let source_result: Result<String, SleighError> = preprocessed_aarch64_source();
    assert!(source_result.is_ok(), "{source_result:?}");
    let Ok(source) = source_result else {
        return;
    };
    let parsed: Result<SleighSpec, SleighError> = parse_spec(&source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return;
    };
    let compiled_result: Result<CompiledSpec, SleighError> = compile_spec(spec);
    assert!(compiled_result.is_ok(), "{compiled_result:?}");
    let Ok(compiled) = compiled_result else {
        return;
    };
    let context: ContextState = BTreeMap::from([("ImmS_ImmR_TestSet".to_owned(), 1)]);
    let cases: [(u32, &str); 6] = [
        (0x8b01_0000, "add"),
        (0xd65f_03c0, "ret"),
        (0xf940_0000, "ldr"),
        (0xf900_0041, "str"),
        (0xd503_201f, "nop"),
        (0xaa00_03e2, "mov"),
    ];
    for (word, expected) in cases {
        let bytes: [u8; 4] = word.to_le_bytes();
        let outcome: DecodeOutcome = compiled.decode(&bytes, 0x1000, &context);
        assert!(
            matches!(outcome, DecodeOutcome::Matched(DecodeMatch { ref mnemonic, .. }) if mnemonic == expected),
            "{word:08x}: expected {expected}, got {outcome:?}"
        );
    }
}

#[test]
fn compiler_rejects_oversized_constructor_tables() {
    let mut source: String = r"
define endian=little;
define token instruction(8)
  opcode=(0,7)
;
"
    .to_owned();
    for index in 0_usize..2049 {
        let write_result: fmt::Result = writeln!(source, ":op{index} is opcode=0 {{}}");
        assert!(write_result.is_ok(), "{write_result:?}");
    }
    let parsed: Result<SleighSpec, SleighError> = parse_spec(&source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return;
    };
    let compiled: Result<CompiledSpec, SleighError> =
        compile_spec_with_policy(spec, ConflictPolicy::FirstDefined);
    assert!(matches!(
        compiled,
        Err(SleighError::Parse { message, .. }) if message.contains("constructor count")
    ));
}

#[test]
fn decoding_reports_constructor_attempt_exhaustion() {
    let mut source: String = r"
define endian=little;
define token first(8)
  root=(0,0)
;
define token second(8)
  value=(0,0)
;
"
    .to_owned();
    for index in 0_usize..2048 {
        let write_result: fmt::Result = writeln!(
            source,
            "choice: \"choice{index}\" is value=1 {{ export value; }}"
        );
        assert!(write_result.is_ok(), "{write_result:?}");
    }
    for index in 0_usize..33 {
        let write_result: fmt::Result = writeln!(
            source,
            ":root{index} choice is root=0 ; choice {{ export choice; }}"
        );
        assert!(write_result.is_ok(), "{write_result:?}");
    }
    let parsed: Result<SleighSpec, SleighError> = parse_spec(&source);
    assert!(parsed.is_ok(), "{parsed:?}");
    let Ok(spec) = parsed else {
        return;
    };
    let compiled: Result<CompiledSpec, SleighError> =
        compile_spec_with_policy(spec, ConflictPolicy::FirstDefined);
    assert!(compiled.is_ok(), "{compiled:?}");
    let Ok(compiled) = compiled else {
        return;
    };
    let outcome: DecodeOutcome = compiled.decode(&[0, 0], 0, &BTreeMap::new());
    assert!(matches!(
        outcome,
        DecodeOutcome::ResourceLimit { attempts: 65_536 }
    ));
}
