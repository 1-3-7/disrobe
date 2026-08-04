#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const EDGECASES_DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(EDGECASES_DLL)
}

fn recovered_stats() -> String {
    let bytes: Vec<u8> = std::fs::read(fixture_path()).expect("read EdgeCases.baseline.dll");
    let assembly: DecompiledAssembly = decompile_assembly(&bytes).expect("decompile EdgeCases");
    assembly
        .methods
        .iter()
        .find(|method: &&StructuredMethod| {
            method.signature.contains(" Stats(")
                && method
                    .body
                    .lines()
                    .next()
                    .is_some_and(|line: &str| line.contains("EdgeCases.DeconstructPlayground"))
        })
        .map_or_else(
            || panic!("DeconstructPlayground.Stats was not recovered"),
            |method: &StructuredMethod| method.body.clone(),
        )
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

fn source_for(stats: &str) -> String {
    format!(
        "using System;\nusing System.Collections.Generic;\n\nnamespace EdgeCases\n{{\n    public static class DeconstructPlayground\n    {{\n{stats}\n    }}\n}}\n"
    )
}

#[test]
fn deconstruct_stats_has_no_out_of_scope_goto_diagnostic() {
    require_dotnet();
    let source: String = source_for(&recovered_stats());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_deconstruct_stats_syntax")
            .expect("create compiler scratch directory");
    let project: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n  </PropertyGroup>\n</Project>\n";
    std::fs::write(scratch.path().join("oracle.csproj"), project).expect("write project");
    std::fs::write(scratch.path().join("Stats.cs"), &source).expect("write recovered source");
    let compiled: Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(scratch.path())
        .output()
        .expect("run dotnet build");
    let compiler_output: String = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(
        compiled.status.success() || compiler_output.contains(": error CS"),
        "dotnet build failed before csc produced a diagnostic\nsource:\n{source}\n{compiler_output}"
    );
    assert!(
        !compiler_output.contains("error CS0159:"),
        "real csc found an out-of-scope goto in recovered DeconstructPlayground.Stats\nsource:\n{source}\n{compiler_output}"
    );
}
