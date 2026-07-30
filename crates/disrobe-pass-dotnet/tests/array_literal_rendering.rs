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
