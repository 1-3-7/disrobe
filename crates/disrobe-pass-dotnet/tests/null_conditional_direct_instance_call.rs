#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net9.0</TargetFramework><Nullable>disable</Nullable><ImplicitUsings>disable</ImplicitUsings><GenerateAssemblyInfo>false</GenerateAssemblyInfo></PropertyGroup></Project>";

const SOURCE: &str = "namespace Sample;\n\npublic sealed class Money\n{\n    public void Reset() { }\n}\n\npublic static class Extensions\n{\n    public static void Announce(this Money value) { }\n}\n\npublic class Caller\n{\n    private Money _money;\n\n    public void Poke()\n    {\n        _money?.Reset();\n    }\n\n    public void PokeStatic()\n    {\n        _money?.Announce();\n    }\n}\n";

#[cfg(windows)]
fn dotnet_path() -> PathBuf {
    if Command::new("dotnet")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status: std::process::ExitStatus| status.success())
    {
        return PathBuf::from("dotnet");
    }
    let known_install: PathBuf = PathBuf::from(r"C:\Program Files\dotnet\dotnet.exe");
    assert!(
        known_install.is_file(),
        "dotnet SDK was not found on PATH or at {}; install the .NET SDK before running this oracle",
        known_install.display()
    );
    known_install
}

#[cfg(not(windows))]
fn dotnet_path() -> PathBuf {
    PathBuf::from("dotnet")
}

fn build(dotnet: &Path, project: &Path, out_dir: &Path, configuration: &str) -> PathBuf {
    let args: Vec<String> = vec![
        "build".to_owned(),
        project.to_string_lossy().into_owned(),
        "-c".to_owned(),
        configuration.to_owned(),
        "-o".to_owned(),
        out_dir.to_string_lossy().into_owned(),
        "-v".to_owned(),
        "q".to_owned(),
        "-nologo".to_owned(),
    ];
    let captured: CapturedOutput =
        run_captured(dotnet, &args, Duration::from_mins(3), 8 * 1024 * 1024)
            .unwrap_or_else(|error: std::io::Error| {
                panic!("spawn dotnet build ({configuration}): {error}")
            })
            .unwrap_or_else(|| panic!("dotnet build ({configuration}) timed out"));
    assert_eq!(
        captured.exit_code,
        Some(0),
        "dotnet build ({configuration}) failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&captured.stdout),
        String::from_utf8_lossy(&captured.stderr)
    );
    out_dir.join("Fixture.dll")
}

fn method_named<'a>(
    assembly: &'a DecompiledAssembly,
    signature_fragment: &str,
) -> &'a StructuredMethod {
    assembly
        .methods
        .iter()
        .find(|method: &&StructuredMethod| method.signature.contains(signature_fragment))
        .unwrap_or_else(|| {
            panic!("no recovered method with signature containing {signature_fragment:?}")
        })
}

#[test]
fn direct_instance_call_folds_and_static_extension_call_declines() {
    let dotnet: PathBuf = dotnet_path();
    let scratch: ScratchDir = ScratchDir::create("disrobe_null_conditional_direct_instance_call")
        .expect("create scratch directory");
    let dir: &Path = scratch.path();
    let project: PathBuf = dir.join("Fixture.csproj");
    std::fs::write(&project, CSPROJ).expect("write csproj");
    std::fs::write(dir.join("Fixture.cs"), SOURCE).expect("write source");

    for configuration in ["Debug", "Release"] {
        let out_dir: PathBuf = dir.join("out").join(configuration);
        let dll_path: PathBuf = build(&dotnet, &project, &out_dir, configuration);
        let bytes: Vec<u8> = std::fs::read(&dll_path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", dll_path.display()));
        let assembly: DecompiledAssembly = decompile_assembly(&bytes)
            .unwrap_or_else(|error| panic!("decompile the {configuration} fixture: {error}"));

        let poke: &StructuredMethod = method_named(&assembly, "void Poke()");
        assert!(
            poke.body.contains("_money?.Reset();"),
            "{configuration}: a direct-instance call on a sealed type must fold to null-conditional form; got:\n{}",
            poke.body
        );
        assert!(
            !poke.body.contains("__stack_underflow"),
            "{configuration}: Poke() must not fabricate a stack-underflow expression; got:\n{}",
            poke.body
        );

        let poke_static: &StructuredMethod = method_named(&assembly, "void PokeStatic()");
        assert!(
            !poke_static.body.contains("?."),
            "{configuration}: a static extension call consuming the guarded value must not render with \
             null-conditional syntax; got:\n{}",
            poke_static.body
        );
        assert!(
            poke_static.body.contains("Announce"),
            "{configuration}: PokeStatic() must still recover the guarded call to Announce; got:\n{}",
            poke_static.body
        );
    }
}
