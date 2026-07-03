#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::signature::{TypeSig, element_type, parse_local_sig};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

fn baseline() -> DecompiledAssembly {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    decompile_assembly(&bytes).expect("decompile baseline")
}

fn method_by_signature<'a>(
    asm: &'a DecompiledAssembly,
    needle: &str,
) -> Option<&'a StructuredMethod> {
    asm.methods.iter().find(|m: &&StructuredMethod| {
        m.signature
            .lines()
            .next_back()
            .is_some_and(|l: &str| l.contains(needle))
    })
}

#[test]
fn local_var_sig_parses_count_and_types() {
    let blob: [u8; 6] = [
        0x07,
        0x03,
        element_type::I4,
        element_type::SZARRAY,
        element_type::STRING,
        element_type::R8,
    ];
    let locals: Vec<TypeSig> = parse_local_sig(&blob).expect("local sig parses");
    assert_eq!(locals.len(), 3, "header declares three locals");
    assert_eq!(locals[0], TypeSig::I4);
    assert_eq!(locals[1], TypeSig::SzArray(Box::new(TypeSig::String)));
    assert_eq!(locals[2], TypeSig::R8);
}

#[test]
fn non_local_calling_convention_rejected() {
    assert!(parse_local_sig(&[0x06, element_type::I4]).is_err());
    assert!(parse_local_sig(&[]).is_err());
}

#[test]
fn recovered_locals_are_never_untyped_var() {
    let asm: DecompiledAssembly = baseline();
    let offenders: Vec<&str> = asm
        .methods
        .iter()
        .filter(|m: &&StructuredMethod| m.body.contains("var local"))
        .map(|m: &StructuredMethod| m.signature.as_str())
        .collect();
    assert!(
        offenders.is_empty(),
        "every recovered local must carry a declared type from the local-var signature; \
         {} method(s) still emit `var local`, first: {:?}",
        offenders.len(),
        offenders.first()
    );
}

#[test]
fn create_range_recovers_param_names_and_local_types() {
    let asm: DecompiledAssembly = baseline();
    let m: &StructuredMethod =
        method_by_signature(&asm, "CreateRange").expect("CreateRange present in baseline");
    assert!(
        m.signature.contains("CreateRange(int start, int count)"),
        "params must carry recovered names start/count and int types; got: {}",
        m.signature.lines().next_back().unwrap_or("")
    );
    assert!(
        m.body.contains("int[] local0"),
        "the int[] array local must be declared with its type; got:\n{}",
        m.body
    );
    assert!(
        m.body.contains("int local1"),
        "the loop counter local must be declared int; got:\n{}",
        m.body
    );
    assert!(
        m.body.contains("local1 < count") && m.body.contains("start + local1"),
        "body must reference the recovered parameter names start/count, not argN; got:\n{}",
        m.body
    );
    assert!(
        !m.body.contains("arg1") && !m.body.contains("arg2"),
        "no positional argN may remain when names were recovered; got:\n{}",
        m.body
    );
    assert!(m.named_params >= 2, "two params resolved a real name");
    assert!(m.typed_locals >= 2, "at least two locals carry a type");
}

#[test]
fn distance_to_recovers_typed_local_and_named_param() {
    let asm: DecompiledAssembly = baseline();
    let m: &StructuredMethod =
        method_by_signature(&asm, "DistanceTo").expect("DistanceTo present in baseline");
    assert!(
        m.signature
            .contains("DistanceTo(EdgeCases.Coordinate other)"),
        "the Coordinate parameter must resolve its type token and keep the name `other`; got: {}",
        m.signature.lines().next_back().unwrap_or("")
    );
    assert!(
        m.body.contains("double local0"),
        "the dx/dy local must be declared double from the local-var signature; got:\n{}",
        m.body
    );
    assert!(
        m.body.contains("other"),
        "body must reference parameter `other`; got:\n{}",
        m.body
    );
}

#[test]
fn shift_resolves_ldarga_to_named_param_not_positional() {
    let asm: DecompiledAssembly = baseline();
    let m: &StructuredMethod =
        method_by_signature(&asm, "Coordinate Shift(").expect("Shift present in baseline");
    assert!(
        m.signature
            .contains("Shift(EdgeCases.Coordinate c, double dx, double dy)"),
        "all three params resolve names c/dx/dy and the Coordinate type; got: {}",
        m.signature.lines().next_back().unwrap_or("")
    );
    assert!(
        m.body.contains("c.Latitude") && !m.body.contains("(&arg0)") && !m.body.contains("arg0."),
        "ldarga on the first static parameter must resolve to the named param `c`, not positional arg0; got:\n{}",
        m.body
    );
    assert!(
        !m.body.contains("(&c)"),
        "an instance access on a struct parameter renders as `c`, not the invalid address-of receiver `(&c)`; got:\n{}",
        m.body
    );
}

#[test]
fn typed_local_rate_is_total_on_clean_baseline() {
    let asm: DecompiledAssembly = baseline();
    let untyped_methods: usize = asm
        .methods
        .iter()
        .filter(|m: &&StructuredMethod| m.body.contains("var local"))
        .count();
    let positional_methods: usize = asm
        .methods
        .iter()
        .filter(|m: &&StructuredMethod| {
            m.body.match_indices("arg").any(|(i, _): (usize, &str)| {
                m.body[i + 3..]
                    .chars()
                    .next()
                    .is_some_and(|c: char| c.is_ascii_digit())
            })
        })
        .count();
    assert_eq!(
        untyped_methods, 0,
        "no method on the clean baseline may carry an untyped `var` local"
    );
    assert!(
        positional_methods <= 8,
        "only genuinely-unnamed compiler-generated params may keep argN; got {positional_methods} methods"
    );
}
