#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::cil::{Instruction, MethodBody, disassemble};
use disrobe_pass_dotnet::decompile::{
    CSharpPseudo, DecompiledAssembly, decompile_assembly, emit_csharp,
};

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

#[test]
fn pseudo_csharp_emits_method_skeleton() {
    let code: [u8; 4] = [0x16, 0x17, 0x58, 0x2A];
    let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
    let body: MethodBody = MethodBody {
        max_stack: 2,
        code_size: 4,
        local_var_sig_tok: 0,
        init_locals: false,
        instructions,
        exception_clauses: Vec::new(),
    };
    let out: CSharpPseudo = emit_csharp("Sum", &body);
    assert!(out.body.contains("void Sum()"));
    assert!(out.body.contains("ldc.i4.0"));
    assert!(out.body.contains("ldc.i4.1"));
    assert!(out.body.contains("add"));
    assert!(out.body.contains("ret"));
    assert_eq!(out.flow_summary.returns, 1);
}

#[test]
fn pseudo_csharp_counts_branches_and_calls() {
    let code: [u8; 9] = [0x16, 0x2C, 0x02, 0x28, 0x00, 0x00, 0x00, 0x00, 0x2A];
    let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
    let body: MethodBody = MethodBody {
        max_stack: 1,
        code_size: 9,
        local_var_sig_tok: 0,
        init_locals: false,
        instructions,
        exception_clauses: Vec::new(),
    };
    let out: CSharpPseudo = emit_csharp("M", &body);
    assert_eq!(out.flow_summary.branches, 1);
    assert_eq!(out.flow_summary.calls, 1);
    assert_eq!(out.flow_summary.returns, 1);
}

#[test]
fn native_decompile_real_helloapp_assembly() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/HelloApp.dll");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile helloapp");
    assert!(
        asm.methods_decompiled >= 1,
        "must natively decompile at least one method body; got {asm:?}"
    );
    let joined: String = asm
        .methods
        .iter()
        .map(|m| m.body.as_str())
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        joined.contains('{') && joined.contains('}'),
        "emits C# blocks"
    );
    assert!(
        joined.contains("return") || joined.contains("goto") || joined.contains(';'),
        "emits statements"
    );
}

#[test]
fn native_decompile_real_megafile_resolves_signatures() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile megafile");
    assert!(
        asm.methods_decompiled > 20,
        "megafile has many method bodies; decompiled {}",
        asm.methods_decompiled
    );
    let any_named_sig: bool = asm
        .methods
        .iter()
        .any(|m| m.signature.contains('(') && m.signature.contains(')'));
    assert!(
        any_named_sig,
        "rendered method signatures with parameter lists"
    );
}

#[test]
#[ignore = "inspection-only: prints native decompiler output; run with --ignored --nocapture"]
fn dump_helloapp_decomp() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/HelloApp.dll");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    eprintln!(
        "module={} decompiled={} bodyless={} failed={}",
        asm.module_name, asm.methods_decompiled, asm.methods_bodyless, asm.methods_failed
    );
    for m in asm.methods.iter().take(4) {
        eprintln!("======\n{}", m.body);
    }
}

#[test]
fn native_decompile_confused_assembly_does_not_panic() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/HelloAppLegacy.confuserex2.dll");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile obfuscated");
    assert!(
        asm.methods_decompiled + asm.methods_failed + asm.methods_bodyless > 0,
        "accounts for every method even under obfuscation; got {asm:?}"
    );
}

#[test]
fn recovers_exception_filter_when_clause_from_real_assembly() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile megafile");
    let safe_divide: &str = asm
        .methods
        .iter()
        .find(|m| m.signature.contains("SafeDivide"))
        .map(|m| m.body.as_str())
        .expect("SafeDivide method present");
    assert!(
        safe_divide.contains("when ("),
        "filter clause must render a real when(...) guard; got:\n{safe_divide}"
    );
    assert!(
        !safe_divide.contains("/* filter */"),
        "no filter placeholder comment remains; got:\n{safe_divide}"
    );
    assert!(
        safe_divide.contains("catch (OverflowException ex) when ("),
        "filter recovers the typed exception and a guard; got:\n{safe_divide}"
    );
    assert!(
        !safe_divide.contains("when (/* filter */ true)"),
        "fabricated always-true filter must be gone; got:\n{safe_divide}"
    );
    let when_line: &str = safe_divide
        .lines()
        .find(|l| l.contains("when ("))
        .expect("when line");
    assert!(
        when_line.contains("==") && when_line.contains("&&"),
        "recovered guard preserves the real comparison structure; got: {when_line}"
    );
    assert!(
        when_line.contains("-2147483648") && when_line.contains("-1"),
        "guard preserves both comparison constants (int.MinValue and -1); got: {when_line}"
    );
    assert!(
        safe_divide.contains("catch (DivideByZeroException ex)"),
        "the sibling typed catch on the same protected region still renders; got:\n{safe_divide}"
    );
    assert!(
        safe_divide.contains("finally"),
        "the finally handler overlapping the same try still renders; got:\n{safe_divide}"
    );
    let catch_count: usize = safe_divide.matches("catch (").count();
    assert!(
        catch_count >= 2,
        "both the typed catch and the filtered catch over the overlapping region render; got {catch_count} in:\n{safe_divide}"
    );
}

fn movenext_body<'a>(asm: &'a DecompiledAssembly, needle: &str) -> &'a str {
    asm.methods
        .iter()
        .find(|m| m.signature.contains("MoveNext") && m.signature.contains(needle))
        .map_or_else(
            || panic!("MoveNext for {needle} present"),
            |m| m.body.as_str(),
        )
}

#[test]
fn linearizes_single_await_async_state_machine() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let body: &str = movenext_body(&asm, "AboveThresholdAsync");
    assert!(
        body.contains("await "),
        "the await surface is recovered; got:\n{body}"
    );
    assert!(
        !body.contains("get_IsCompleted"),
        "the await-completion suspend scaffolding is removed; got:\n{body}"
    );
    assert!(
        !body.contains("<>u__"),
        "the hoisted awaiter restore/save plumbing is removed; got:\n{body}"
    );
    assert!(
        !body.contains("= this.<>1__state"),
        "the state dispatch mirror load is removed; got:\n{body}"
    );
    assert!(
        !body.contains("this.<>1__state ="),
        "no residual state writes remain; got:\n{body}"
    );
    assert!(
        !body.contains("if (!local0)") && !body.contains("if (local0 =="),
        "the state-resume dispatch guards are collapsed; got:\n{body}"
    );
}

#[test]
fn iterator_state_machine_recovers_yields_without_state_dispatch() {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile");
    let body: &str = movenext_body(&asm, "Counting");
    assert!(
        body.contains("yield return"),
        "iterator yields are recovered; got:\n{body}"
    );
    assert!(
        body.contains("yield break"),
        "iterator termination is recovered; got:\n{body}"
    );
    assert!(
        !body.contains("= this.<>1__state"),
        "the iterator state mirror load is removed; got:\n{body}"
    );
    assert!(
        !body.contains("return true;") && !body.contains("return false;"),
        "the MoveNext bool returns are folded into yields; got:\n{body}"
    );
}

#[test]
fn resolves_generic_typespec_names_in_body() {
    let bytes: Vec<u8> = load("tests/fixtures/GenVerify.dll");
    let asm: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile generics");
    let joined: String = asm
        .methods
        .iter()
        .map(|m| m.body.as_str())
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        joined.contains("Dictionary<string, int>"),
        "generic instance resolves to a real name (not TypeSpec[N]); got:\n{joined}"
    );
    assert!(
        !joined.contains("TypeSpec["),
        "no unresolved TypeSpec placeholders remain; got:\n{joined}"
    );
    assert!(
        !joined.contains("`2"),
        "generic arity suffix stripped; got:\n{joined}"
    );
}
