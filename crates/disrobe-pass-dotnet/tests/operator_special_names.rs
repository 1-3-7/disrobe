#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/constructs/Constructs.dll");
    decompile_assembly(&bytes).expect("decompile Constructs.dll")
}

fn method_body(asm: &DecompiledAssembly, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| m.signature.contains(needle))
        .map_or_else(
            || panic!("method containing `{needle}` not found"),
            |m| m.body.clone(),
        )
}

#[test]
fn string_equality_operator_renders_as_operator_not_op_equality_call() {
    let asm: DecompiledAssembly = decompile();
    let classify: String = method_body(&asm, "Classify");
    assert!(
        !classify.contains("op_Equality("),
        "string switch must render structurally, not a raw op_Equality call; got:\n{classify}"
    );
    assert!(
        !classify.contains("op_Inequality("),
        "no raw op_Inequality call may survive; got:\n{classify}"
    );
    assert!(
        classify.contains("kind switch"),
        "the switch-on-string must recover as a C# switch expression; got:\n{classify}"
    );
    for arm in [
        "\"alpha\" => \"first\"",
        "\"beta\" => \"second\"",
        "\"gamma\" => \"third\"",
    ] {
        assert!(
            classify.contains(arm),
            "switch arm `{arm}` must be reconstructed; got:\n{classify}"
        );
    }
    assert!(
        classify.contains("_ => \"unknown\""),
        "the default arm must be reconstructed; got:\n{classify}"
    );
}

#[test]
fn whole_assembly_has_no_raw_operator_special_name_calls() {
    let asm: DecompiledAssembly = decompile();
    for m in &asm.methods {
        let statements: String = m
            .body
            .lines()
            .filter(|line: &&str| {
                let trimmed: &str = line.trim_start();
                let is_comment: bool = trimmed.starts_with("//");
                let is_operator_decl: bool = trimmed.contains(" op_") && trimmed.ends_with(')');
                !is_comment && !is_operator_decl
            })
            .collect::<Vec<&str>>()
            .join("\n");
        for op in [
            "op_Equality(",
            "op_Inequality(",
            "op_Addition(",
            "op_Subtraction(",
            "op_Multiply(",
            "op_Division(",
            "op_LessThan(",
            "op_GreaterThan(",
            "op_UnaryNegation(",
            "op_LogicalNot(",
        ] {
            assert!(
                !statements.contains(op),
                "operator special-name call `{op}` must be lowered to a C# operator in {}; got:\n{}",
                m.signature,
                m.body
            );
        }
    }
}

#[test]
fn decompile_is_lossless_on_construct_corpus() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method body may fail to decompile; got {} failures",
        asm.methods_failed
    );
    assert!(
        asm.methods_decompiled >= 10,
        "the construct corpus exercises records, async, iterators, closures, switch-on-string, and tuples; at least 10 method bodies must decompile, got {}",
        asm.methods_decompiled
    );
}
