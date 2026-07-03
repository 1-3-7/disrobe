#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::cil::{MethodBody, disassemble};
use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly_in};
use disrobe_pass_dotnet::structurize::{
    HexNamer, StructuredMethod, TargetLang, decompile_method_in,
};

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

#[test]
fn native_decompile_real_helloapp_fsharp() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/HelloApp.dll");
    let asm: DecompiledAssembly =
        decompile_assembly_in(&bytes, TargetLang::FSharp).expect("decompile helloapp fsharp");
    assert!(
        asm.methods_decompiled >= 1,
        "must natively decompile at least one method body; got {asm:?}"
    );
    let joined: String = asm
        .methods
        .iter()
        .map(|m: &StructuredMethod| m.body.as_str())
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        joined.contains("let") || joined.contains("member"),
        "emits F# let bindings or member headers; got:\n{joined}"
    );
    assert!(
        joined.contains("<-") || joined.contains("// goto") || joined.contains("()"),
        "emits F# statements; got:\n{joined}"
    );
}

#[test]
fn native_decompile_real_megafile_fsharp() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let asm: DecompiledAssembly =
        decompile_assembly_in(&bytes, TargetLang::FSharp).expect("decompile megafile fsharp");
    assert!(
        asm.methods_decompiled > 20,
        "megafile has many method bodies; decompiled {}",
        asm.methods_decompiled
    );
    let any_named_sig: bool = asm.methods.iter().any(|m: &StructuredMethod| {
        m.signature.contains('(')
            && m.signature.contains(')')
            && (m.signature.contains(':') || m.signature.contains("member"))
    });
    assert!(
        any_named_sig,
        "rendered F# member signatures with parameter lists"
    );
}

#[test]
fn native_decompile_confused_fsharp_does_not_panic() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/HelloAppLegacy.confuserex2.dll");
    let asm: DecompiledAssembly =
        decompile_assembly_in(&bytes, TargetLang::FSharp).expect("decompile obfuscated fsharp");
    assert!(
        asm.methods_decompiled + asm.methods_failed + asm.methods_bodyless > 0,
        "accounts for every method even under obfuscation; got {asm:?}"
    );
}

#[test]
fn hand_encoded_local_store_renders_fsharp_let_and_no_fabricated_goto() {
    let code: [u8; 4] = [0x1B, 0x0A, 0x06, 0x2A];
    let body: MethodBody = MethodBody {
        max_stack: 8,
        code_size: code.len() as u32,
        local_var_sig_tok: 0,
        init_locals: false,
        instructions: disassemble(&code).expect("disasm"),
        exception_clauses: Vec::new(),
    };
    let out: StructuredMethod =
        decompile_method_in("member M() : int", &body, &HexNamer, TargetLang::FSharp);
    assert!(out.body.contains("local0 <- 5"), "got:\n{}", out.body);
    assert!(
        out.body.contains("let mutable local0"),
        "got:\n{}",
        out.body
    );
    assert!(
        out.body
            .contains("// note: unstructured CIL jumps preserved as comments; F# has no goto"),
        "F# must carry the honest goto barrier banner; got:\n{}",
        out.body
    );
    assert!(
        !out.body
            .lines()
            .any(|l: &str| l.trim_start().starts_with("goto ")),
        "F# must never fabricate a bare goto; got:\n{}",
        out.body
    );
}
