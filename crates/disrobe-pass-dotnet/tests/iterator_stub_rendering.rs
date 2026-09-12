#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::{Command, Output};

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

fn outer_body(asm: &DecompiledAssembly, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| {
            m.signature.contains(needle)
                && !m.body.lines().next().unwrap_or_default().contains(">d__")
        })
        .map_or_else(|| panic!("method {needle} not found"), |m| m.body.clone())
}

#[test]
fn iterator_factory_stub_reconstructs_to_the_yield_body() {
    let asm: DecompiledAssembly = decompile();
    let evens: String = outer_body(&asm, "IEnumerable<int> Evens");
    assert!(
        !evens.contains(">d__") && !evens.contains("new <Evens>"),
        "the Evens iterator factory stub must not leak the compiler state-machine construction; got:\n{evens}"
    );
    assert!(
        evens.contains("yield return i"),
        "the reconstructed Evens body must carry the yield from the recovered MoveNext; got:\n{evens}"
    );
    assert!(
        evens.contains("int i;"),
        "the hoisted loop variable must get a local declaration with its real type; got:\n{evens}"
    );
    assert!(
        !evens.contains("this.n"),
        "the hoisted parameter field this.n must resolve to the method parameter n; got:\n{evens}"
    );
    assert!(
        !evens.contains("if (i & 1)"),
        "an integer-as-bool condition must be normalized to a comparison, not left as `if (i & 1)`; got:\n{evens}"
    );
}

fn edgecases() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

fn kickoff_body(asm: &DecompiledAssembly, declaring: &str, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| {
            m.body
                .lines()
                .next()
                .unwrap_or_default()
                .contains(declaring)
                && m.signature.contains(needle)
        })
        .map_or_else(|| panic!("method {needle} not found"), |m| m.body.clone())
}

#[test]
fn an_unreversible_state_machine_states_the_refusal_instead_of_emitting_builder_plumbing() {
    let asm: DecompiledAssembly = edgecases();
    let body: String = kickoff_body(&asm, "EdgeCases.IteratorPlayground", " WithEarlyExit(");
    assert!(
        body.contains(disrobe_pass_dotnet::iterator_reverse::UNRECONSTRUCTED_STATE_MACHINE_MARKER),
        "a state machine the pass cannot reverse must say so; got:\n{body}"
    );
    for line in body.lines() {
        let statement: &str = line.trim();
        if statement.starts_with("//") {
            continue;
        }
        assert!(
            !statement.contains(">d__") && !statement.contains("<>"),
            "the refusal must not leave compiler plumbing as a live statement; got:\n{body}"
        );
    }
}

#[test]
fn an_async_kickoff_reverses_to_its_await_body_with_hoisted_locals_declared() {
    let asm: DecompiledAssembly = edgecases();
    let body: String = kickoff_body(&asm, "EdgeCases.AsyncPlayground", " SumAsync(");
    let has_bare_await: bool = body
        .lines()
        .any(|line: &str| line.trim() == "await System.Threading.Tasks.Task.Yield();");
    assert!(
        body.contains(" async "),
        "the reversed kickoff must carry the async modifier; got:\n{body}"
    );
    assert!(
        !body.contains("<>t__builder") && !body.contains(">d__"),
        "the reversed kickoff must not leak builder plumbing; got:\n{body}"
    );
    assert!(
        has_bare_await,
        "the await from MoveNext must survive into the kickoff; got:\n{body}"
    );
    assert!(
        body.contains("System.Collections.Generic.IEnumerator<int> wrap2;"),
        "the compiler-hoisted enumerator field must come back as a typed local; got:\n{body}"
    );
    assert!(
        body.contains("wrap2 = source.GetEnumerator();"),
        "the hoisted parameter field must resolve to the method parameter; got:\n{body}"
    );
    assert!(
        body.contains("return local1;"),
        "the result register must still be returned; got:\n{body}"
    );
}

#[test]
fn recovered_async_kickoff_compiles_with_real_csc() {
    let asm: DecompiledAssembly = edgecases();
    let body: String = kickoff_body(&asm, "EdgeCases.AsyncPlayground", " SumAsync(");
    let source: String = format!(
        "namespace EdgeCases\n{{\n    public static class AsyncPlayground\n    {{\n{body}\n    }}\n}}\n"
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_async_kickoff_recompile")
            .expect("create compiler scratch directory");
    let project: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n  </PropertyGroup>\n  <ItemGroup>\n    <Compile Include=\"AsyncPlayground.cs\" />\n  </ItemGroup>\n</Project>\n";
    std::fs::write(scratch.path().join("compile.csproj"), project).expect("write project");
    std::fs::write(scratch.path().join("AsyncPlayground.cs"), &source)
        .expect("write recovered source");
    let compiled: Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(scratch.path())
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("the real dotnet SDK is required for this regression: {error}")
        });
    assert!(
        compiled.status.success(),
        "real csc rejected recovered AsyncPlayground.SumAsync\nsource:\n{source}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
}

#[test]
fn dispose_async_preserves_the_configured_void_await() {
    let asm: DecompiledAssembly = edgecases();
    let body: String = kickoff_body(&asm, "EdgeCases.AsyncDisposableScope", " DisposeAsync(");
    let configured_await: bool = body.lines().any(|line: &str| {
        let statement: &str = line.trim();
        statement.starts_with("await ") && statement.ends_with(".ConfigureAwait(false);")
    });
    assert!(
        configured_await,
        "AsyncDisposableScope.DisposeAsync must preserve its configured void await:\n{body}"
    );
    assert!(
        !body.lines().any(|line: &str| {
            let declaration: &str = line.trim();
            declaration.contains("ConfiguredValueTaskAwaiter") && declaration.ends_with(';')
        }),
        "the configured void await must not retain an unused result or awaiter declaration:\n{body}"
    );
}

#[test]
fn decompile_remains_lossless_after_iterator_reconstruction() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after iterator-stub reconstruction; got {} failures",
        asm.methods_failed
    );
}
