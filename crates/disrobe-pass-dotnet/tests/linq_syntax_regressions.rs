#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const EDGECASES_DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const EXPECTED_PROJECTION: &str = "new { x = x, sq = x * x }";

enum CompileOutcome {
    Accepted,
    RejectedByCsc(String),
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(EDGECASES_DLL)
}

fn recovered_even_squares() -> String {
    let bytes: Vec<u8> = std::fs::read(fixture_path()).expect("read EdgeCases.baseline.dll");
    let assembly: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile EdgeCases");
    let matches: Vec<&StructuredMethod> = assembly
        .methods
        .iter()
        .filter(|method: &&StructuredMethod| {
            method.signature.contains(" EvenSquares(")
                && method
                    .body
                    .lines()
                    .next()
                    .is_some_and(|line: &str| line.contains("EdgeCases.LinqPlayground"))
        })
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one recovered EdgeCases.LinqPlayground.EvenSquares method, found {}",
        matches.len()
    );
    matches[0].body.clone()
}

fn require_dotnet() {
    let version: Output = Command::new("dotnet")
        .arg("--version")
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("the real dotnet SDK is required for this regression: {error}")
        });
    assert!(
        version.status.success(),
        "dotnet --version failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    );
}

fn source_for(even_squares: &str) -> String {
    format!(
        "using System.Collections.Generic;\nusing System.Linq;\n\nnamespace EdgeCases\n{{\n    public static class LinqPlayground\n    {{\n{even_squares}\n    }}\n}}\n"
    )
}

fn recovered_source() -> String {
    let source: String = source_for(&recovered_even_squares());
    assert_eq!(
        source.matches(EXPECTED_PROJECTION).count(),
        1,
        "EvenSquares must retain exactly one recovered anonymous projection:\n{source}"
    );
    source
}

fn compile_with_real_csc(source: &str, purpose: &str) -> CompileOutcome {
    require_dotnet();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(purpose)
            .expect("create compiler scratch directory");
    let project: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>\n  </PropertyGroup>\n  <ItemGroup>\n    <Compile Include=\"EvenSquares.cs\" />\n  </ItemGroup>\n</Project>\n";
    std::fs::write(scratch.path().join("compile.csproj"), project).expect("write project");
    std::fs::write(scratch.path().join("EvenSquares.cs"), source).expect("write recovered source");
    let compiled: Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(scratch.path())
        .output()
        .expect("run dotnet build");
    if compiled.status.success() {
        return CompileOutcome::Accepted;
    }
    let output: String = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        output.contains(": error CS"),
        "dotnet build failed before csc produced a diagnostic:\n{output}"
    );
    CompileOutcome::RejectedByCsc(output)
}

#[test]
fn recovered_even_squares_compiles_with_real_csc() {
    let source: String = recovered_source();
    match compile_with_real_csc(&source, "disrobe_linq_even_squares_syntax") {
        CompileOutcome::Accepted => {}
        CompileOutcome::RejectedByCsc(output) => {
            panic!("real csc rejected recovered EvenSquares\nsource:\n{source}\n{output}");
        }
    }
}

#[test]
fn real_csc_rejects_corrupted_anonymous_projection() {
    let source: String = recovered_source();
    let corrupted: String = source.replacen(EXPECTED_PROJECTION, "new", 1);
    match compile_with_real_csc(&corrupted, "disrobe_linq_even_squares_cs1526_mutation") {
        CompileOutcome::Accepted => panic!("csc accepted the deliberately corrupted projection"),
        CompileOutcome::RejectedByCsc(output) => assert!(
            output.contains("error CS1526"),
            "the corrupted projection must produce CS1526:\n{output}"
        ),
    }
}
