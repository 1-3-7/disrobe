#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_nir::{NirModule, NirOp};
use disrobe_nir_lift::lift_dotnet_pe;
use disrobe_pass_dotnet::{
    ClrHeader, Instruction, MetadataRoot, MethodBody, OperandValue, PeImage, Resolver,
    parse as parse_pe, parse_clr_header, parse_metadata_root, parse_method_body,
};

const CONST_PROBE: &[u8] = include_bytes!("fixtures/ConstProbe.dll");

fn expected_render(operand: &OperandValue) -> Option<String> {
    match operand {
        OperandValue::I32(v) => Some(v.to_string()),
        OperandValue::I64(v) => Some(v.to_string()),
        OperandValue::U8(v) => Some(i32::from(v.cast_signed()).to_string()),
        OperandValue::F32Bits(bits) => Some(f32::from_bits(*bits).to_string()),
        OperandValue::F64Bits(bits) => Some(f64::from_bits(*bits).to_string()),
        _ => None,
    }
}

fn is_numeric_const(name: &str) -> bool {
    matches!(name, "ldc.i4" | "ldc.i4.s" | "ldc.i8" | "ldc.r4" | "ldc.r8")
}

fn independent_const_pairs() -> Vec<(String, String)> {
    let pe: PeImage = parse_pe(CONST_PROBE).expect("pe");
    let clr: ClrHeader = parse_clr_header(CONST_PROBE, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(CONST_PROBE, &pe, &clr).expect("root");
    let resolver: Resolver = Resolver::build(CONST_PROBE, &pe, &clr, &root).expect("resolver");

    let mut pairs: Vec<(String, String)> = Vec::new();
    for (_, _, rva) in resolver.methods_with_bodies() {
        let slice: &[u8] = pe.slice_at_rva_to_end(CONST_PROBE, rva).expect("body");
        let body: MethodBody = match parse_method_body(slice) {
            Ok(body) => body,
            Err(_) => continue,
        };
        for insn in &body.instructions {
            let i: &Instruction = insn;
            if is_numeric_const(i.name.as_str())
                && let Some(value) = expected_render(&i.operand)
            {
                pairs.push((i.name.clone(), value));
            }
        }
    }
    pairs.sort();
    pairs
}

fn lifted_const_pairs(nir: &NirModule) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if ins.op == NirOp::Const
                && is_numeric_const(ins.mnemonic.as_str())
                && let Some(value) = ins.operands.first()
            {
                pairs.push((ins.mnemonic.clone(), value.clone()));
            }
        }
    }
    pairs.sort();
    pairs
}

#[test]
fn lifted_numeric_constants_match_the_independent_il_decode() {
    let oracle: Vec<(String, String)> = independent_const_pairs();
    let nir: NirModule = lift_dotnet_pe(CONST_PROBE).expect("lift ConstProbe.dll");
    let lifted: Vec<(String, String)> = lifted_const_pairs(&nir);

    assert!(
        !oracle.is_empty(),
        "the fixture must carry inline numeric constants"
    );
    assert_eq!(
        lifted, oracle,
        "each lifted numeric const must equal the value decoded straight from the IL bytes"
    );
}

#[test]
fn float_and_signed_short_constants_are_not_dropped_or_unsigned() {
    let oracle: Vec<(String, String)> = independent_const_pairs();

    let has_float: bool = oracle
        .iter()
        .any(|(name, _): &(String, String)| name == "ldc.r4" || name == "ldc.r8");
    assert!(
        has_float,
        "the fixture must exercise ldc.r4 and ldc.r8 so a dropped float would fail the test"
    );
    let has_signed_short: bool = oracle
        .iter()
        .any(|(name, value): &(String, String)| name == "ldc.i4.s" && value.starts_with('-'));
    assert!(
        has_signed_short,
        "the fixture must exercise a negative ldc.i4.s so an unsigned render would fail the test"
    );

    let nir: NirModule = lift_dotnet_pe(CONST_PROBE).expect("lift ConstProbe.dll");
    let values: BTreeSet<String> = lifted_const_pairs(&nir)
        .into_iter()
        .map(|(_, value): (String, String)| value)
        .collect();

    for expected in [
        "-0",
        "inf",
        "-inf",
        "2.5",
        "1.5",
        "-5",
        "-100",
        "1000000",
        "5000000000",
    ] {
        assert!(
            values.contains(expected),
            "source declares the constant {expected}; lifted numeric consts were {values:?}"
        );
    }
}
