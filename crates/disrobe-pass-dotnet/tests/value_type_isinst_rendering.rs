#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

fn edgecases() -> DecompiledAssembly {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read fixture: {error}"));
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

fn money_equals_object(assembly: &DecompiledAssembly) -> String {
    assembly
        .methods
        .iter()
        .find(|method: &&StructuredMethod| {
            method
                .body
                .lines()
                .next()
                .is_some_and(|first: &str| first.contains("EdgeCases.Money"))
                && method.signature.contains("Equals(object")
        })
        .map_or_else(
            || panic!("EdgeCases.Money::Equals(object) not found"),
            |method: &StructuredMethod| method.body.clone(),
        )
}

#[test]
fn value_type_isinst_and_unbox_any_render_as_valid_csharp() {
    let assembly: DecompiledAssembly = edgecases();
    let body: String = money_equals_object(&assembly);
    assert!(
        body.contains("((object)obj) is Money"),
        "a branch over isinst Money must retain the CLR object boundary in a valid C# type predicate, got:\n{body}"
    );
    assert!(
        body.contains("local0 = (Money)((object)obj);"),
        "unbox.any Money must preserve its object boundary and value-type cast, got:\n{body}"
    );
    assert!(
        !body.contains("obj as Money") && !body.contains("local0 = obj;"),
        "value-type isinst and unbox.any must not survive as invalid or missing casts, got:\n{body}"
    );
}
