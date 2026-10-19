#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const SOURCE: &str = "../../corpus/dotnet/megafile/EdgeCases.cs";

fn manifest(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    path
}

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = std::fs::read(manifest(DLL)).expect("read EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile")
}

fn body_of(asm: &DecompiledAssembly, declaring: &str, method: &str) -> String {
    asm.methods
        .iter()
        .find(|m: &&StructuredMethod| {
            m.body
                .lines()
                .next()
                .is_some_and(|first: &str| first.trim() == format!("// EdgeCases.{declaring}"))
                && (m.signature.contains(&format!(" {method}("))
                    || m.signature.contains(&format!(" {method}<")))
        })
        .map_or_else(
            || panic!("no recovered body for EdgeCases.{declaring}::{method}"),
            |m: &StructuredMethod| m.body.clone(),
        )
}

fn initializer_elements(body: &str, element_type: &str) -> Vec<String> {
    let needle: String = format!("new {element_type}[");
    let start: usize = body.find(&needle).unwrap_or_else(|| {
        panic!("recovered body creates no {element_type} array:\n{body}");
    });
    let open: usize = body[start..].find('{').map_or_else(
        || panic!("array creation carries no initializer:\n{body}"),
        |offset: usize| start + offset + 1,
    );
    let close: usize = body[open..].find('}').map_or_else(
        || panic!("array initializer is unterminated:\n{body}"),
        |offset: usize| open + offset,
    );
    body[open..close]
        .split(',')
        .map(|element: &str| element.trim().to_owned())
        .collect()
}

fn interpolation_holes(source: &str, method: &str) -> Vec<String> {
    let line: &str = source
        .lines()
        .find(|l: &&str| l.contains(method) && l.contains("=> $\""))
        .unwrap_or_else(|| panic!("original source has no interpolated {method}"));
    let mut holes: Vec<String> = Vec::new();
    let mut rest: &str = line;
    while let Some(open) = rest.find('{') {
        let after: &str = &rest[open + 1..];
        let Some(close): Option<usize> = after.find('}') else {
            break;
        };
        holes.push(after[..close].to_owned());
        rest = &after[close + 1..];
    }
    holes
}

#[test]
fn interpolated_concat_recovers_one_array_initializer_in_source_order() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "AnimalBase", "Describe");
    let source: String = std::fs::read_to_string(manifest(SOURCE)).expect("read EdgeCases.cs");
    let holes: Vec<String> = interpolation_holes(&source, "Describe");

    let recovered: Vec<String> = initializer_elements(&body, "System.String");
    let expected: Vec<String> = vec![
        format!("this.{}", holes.first().cloned().unwrap_or_default()),
        "\":\"".to_owned(),
        format!("this.{}", holes.get(1).cloned().unwrap_or_default()),
        "\":\"".to_owned(),
        format!("this.{}", holes.get(2).cloned().unwrap_or_default()),
    ];
    assert_eq!(
        recovered, expected,
        "the concat argument must carry every interpolation hole of the original in order:\n{body}"
    );
    assert!(
        !body.contains("])["),
        "no element store may survive outside the initializer:\n{body}"
    );
}

#[test]
fn element_order_check_rejects_a_permuted_initializer() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "AnimalBase", "Describe");
    let recovered: Vec<String> = initializer_elements(&body, "System.String");
    let permuted: String = body.replacen(
        "{ this.GetType().Name, \":\"",
        "{ \":\", this.GetType().Name",
        1,
    );
    assert_ne!(
        permuted, body,
        "the mutation must actually change the source it grades"
    );
    assert_ne!(
        initializer_elements(&permuted, "System.String"),
        recovered,
        "an initializer whose elements are swapped must not compare equal, otherwise this check cannot separate a faithful argument list from a reordered one"
    );
}

#[test]
fn array_creation_names_an_element_type_a_compiler_can_resolve() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "ExpressionPlayground", "SquareExpr");
    assert!(
        body.contains("new System.Linq.Expressions.ParameterExpression[1] {"),
        "an array element type outside the recovered namespace must stay fully qualified:\n{body}"
    );
}

#[test]
fn boxed_boolean_constant_recovers_as_a_boolean_literal() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "ExpressionPlayground", "AlwaysTrue");
    assert!(
        body.contains("Expression.Constant(true)"),
        "a bool boxed into an object parameter must render as a boolean literal, not as its integer encoding:\n{body}"
    );
}

#[test]
fn collection_expression_recovers_the_two_field_rva_integer_literals() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "CollectionPlayground", "CollectionExpression");
    assert!(
        body.contains("new System.Int32[3] { 1, 2, 3 }")
            && body.contains("new System.Int32[3] { 9, 10, 11 }"),
        "the compiled FieldRVA blocks must recover their little-endian Int32 values:\n{body}"
    );
    assert!(
        !body.contains("__unreconstructed_runtime_handle"),
        "the authenticated collection initializers must not retain a runtime-handle refusal:\n{body}"
    );
}

#[test]
fn utf8_literal_recovers_the_field_rva_bytes_as_a_span_literal() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "StringPlayground", "get_Utf8Literal");
    assert!(
        body.contains("return \"edge-cases-utf8\"u8;"),
        "the FieldRVA-backed RuntimeHelpers.CreateSpan<byte> shape must preserve its bytes as a C# UTF-8 literal:\n{body}"
    );
    assert!(
        !body.contains("__unreconstructed_runtime_handle"),
        "the recovered UTF-8 span must not retain its FieldRVA handle refusal:\n{body}"
    );
}

#[test]
fn span_conversion_operator_renders_as_a_csharp_cast() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "StringPlayground", "MakeUtf8Snapshot");
    assert!(
        body.contains("CopyTo((System.Span<byte>)local1)"),
        "the conversion operator must be rendered in C# syntax:\n{body}"
    );
    assert!(
        !body.contains("op_Implicit"),
        "invalid metadata name:\n{body}"
    );
}

#[test]
fn framework_try_parse_member_ref_uses_the_out_keyword() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "RefPlayground", "OutTryParse");
    assert!(
        body.contains("System.Int32.TryParse(input, out result)"),
        "the framework MemberRef must preserve the known out contract:\n{body}"
    );
}

#[test]
fn static_framework_field_keeps_its_declaring_type() {
    let asm: DecompiledAssembly = decompile();
    let body: String = body_of(&asm, "PinvokePlayground", "ReadEnvVar");
    assert!(
        body.contains("return System.String.Empty;"),
        "the static field owner must survive lifting:\n{body}"
    );
}

fn contract_body(method: &str) -> StructuredMethod {
    let bytes: Vec<u8> = std::fs::read(manifest(
        "../../corpus/dotnet/csharp-contracts/CsharpContracts.dll",
    ))
    .expect("read compiler-authored C# contract fixture");
    let assembly: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile C# contracts");
    assembly
        .methods
        .into_iter()
        .find(|candidate: &StructuredMethod| candidate.signature.contains(&format!(" {method}(")))
        .unwrap_or_else(|| panic!("missing recovered contract method {method}"))
}

#[test]
fn fake_system_try_parse_method_definition_retains_ref() {
    let method: StructuredMethod = contract_body("FakeSystemTryParse");
    assert!(
        method
            .body
            .contains("System.Fake.Contracts.TryParse(input, ref "),
        "the authored TryParse declaration takes ref, despite its System namespace:\n{}",
        method.body
    );
    assert!(!method.body.contains("TryParse(input, out "));
}

#[test]
fn integer_span_field_rva_is_not_reinterpreted_as_utf8() {
    let method: StructuredMethod = contract_body("get_IntSpan");
    assert!(
        method.signature.contains("System.ReadOnlySpan<int>"),
        "{}",
        method.signature
    );
    assert!(
        !method.body.contains("u8"),
        "the compiler's CreateSpan<int> uses element counts and must retain integer semantics:\n{}",
        method.body
    );
    assert!(method.body.contains("return "), "{}", method.body);
}
