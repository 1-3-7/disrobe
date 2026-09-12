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
fn native_decompile_real_helloapp_vbnet() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/HelloApp.dll");
    let asm: DecompiledAssembly =
        decompile_assembly_in(&bytes, TargetLang::VbNet).expect("decompile helloapp vbnet");
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
        joined.contains("End Sub") || joined.contains("End Function"),
        "emits VB method blocks; got:\n{joined}"
    );
    assert!(
        joined.contains("Return") || joined.contains("GoTo") || joined.contains('='),
        "emits VB statements; got:\n{joined}"
    );
}

#[test]
fn native_decompile_real_megafile_vbnet() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let asm: DecompiledAssembly =
        decompile_assembly_in(&bytes, TargetLang::VbNet).expect("decompile megafile vbnet");
    assert!(
        asm.methods_decompiled > 20,
        "megafile has many method bodies; decompiled {}",
        asm.methods_decompiled
    );
    let any_named_sig: bool = asm.methods.iter().any(|m: &StructuredMethod| {
        m.signature.contains('(')
            && m.signature.contains(')')
            && (m.signature.contains("As ") || m.signature.contains("Sub "))
    });
    assert!(
        any_named_sig,
        "rendered VB method signatures with parameter lists"
    );
}

#[test]
fn native_decompile_confused_vbnet_does_not_panic() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/HelloAppLegacy.confuserex2.dll");
    let asm: DecompiledAssembly =
        decompile_assembly_in(&bytes, TargetLang::VbNet).expect("decompile obfuscated vbnet");
    assert!(
        asm.methods_decompiled + asm.methods_failed + asm.methods_bodyless > 0,
        "accounts for every method even under obfuscation; got {asm:?}"
    );
}

#[test]
fn hand_encoded_add_renders_vbnet_return() {
    let code: [u8; 4] = [0x03, 0x04, 0x58, 0x2A];
    let body: MethodBody = MethodBody {
        max_stack: 8,
        code_size: code.len() as u32,
        local_var_sig_tok: 0,
        init_locals: false,
        instructions: disassemble(&code).expect("disasm"),
        exception_clauses: Vec::new(),
    };
    let out: StructuredMethod = decompile_method_in(
        "Public Function Add(arg1 As Integer, arg2 As Integer) As Integer",
        &body,
        &HexNamer,
        TargetLang::VbNet,
    );
    assert!(
        out.body.contains("Return arg1 + arg2"),
        "got:\n{}",
        out.body
    );
    assert!(
        out.body.contains("End Sub") || out.body.contains("End Function"),
        "got:\n{}",
        out.body
    );
}
