#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

fn source_for(body: &str) -> String {
    format!(
        "namespace EdgeCases\n{{\n    public readonly struct Money\n    {{\n        public long Pennies {{ get; }}\n\n        public Money(long pennies)\n        {{\n            Pennies = pennies;\n        }}\n\n        public bool Equals(Money other)\n        {{\n            return Pennies == other.Pennies;\n        }}\n\n        public override int GetHashCode()\n        {{\n            return Pennies.GetHashCode();\n        }}\n\n{body}\n    }}\n}}\n\npublic static class Program\n{{\n    public static int Main()\n    {{\n        object matching = new EdgeCases.Money(37);\n        if (!matching.Equals(new EdgeCases.Money(37)))\n        {{\n            return 1;\n        }}\n        if (matching.Equals(new EdgeCases.Money(38)))\n        {{\n            return 2;\n        }}\n        return matching.Equals(new object()) ? 3 : 0;\n    }}\n}}\n"
    )
}

fn write_probe_source(directory: &Path, source: &str) {
    std::fs::write(
        directory.join("ValueTypeIsInstProbe.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework><Nullable>disable</Nullable><ImplicitUsings>disable</ImplicitUsings><GenerateAssemblyInfo>false</GenerateAssemblyInfo><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup></Project>",
    )
    .expect("write value-type isinst compiler project");
    std::fs::write(directory.join("ValueTypeIsInstProbe.cs"), source)
        .expect("write value-type isinst compiler source");
}

fn build_probe(directory: &Path) -> Output {
    Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "-nologo"])
        .current_dir(directory)
        .output()
        .expect("build value-type isinst compiler")
}

fn run_built_probe(directory: &Path) -> Output {
    Command::new("dotnet")
        .args(["run", "-c", "Release", "-v", "q", "-nologo", "--no-build"])
        .current_dir(directory)
        .output()
        .expect("run built value-type isinst compiler")
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
    let source: String = source_for(&body);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_value_type_isinst_rendering")
            .expect("create value-type isinst compiler scratch directory");
    write_probe_source(scratch.path(), &source);
    let build_output: Output = build_probe(scratch.path());
    assert!(
        build_output.status.success(),
        "the real EdgeCases Money output must compile with warnings as errors:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );
    let output: Output = run_built_probe(scratch.path());
    assert!(
        output.status.success(),
        "the real EdgeCases Money output must preserve equality semantics:\nstdout:\n{}\nstderr:\n{}\nsource:\n{source}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mutated: String = source.replacen("local0 = (Money)((object)obj);", "local0 = default;", 1);
    assert_ne!(mutated, source, "the unbox.any mutation must apply");
    write_probe_source(scratch.path(), &mutated);
    let mutated_build_output: Output = build_probe(scratch.path());
    assert!(
        mutated_build_output.status.success(),
        "the unbox.any mutation must compile so its runtime result is observable:\nstdout:\n{}\nstderr:\n{}\nsource:\n{mutated}",
        String::from_utf8_lossy(&mutated_build_output.stdout),
        String::from_utf8_lossy(&mutated_build_output.stderr)
    );
    let mutated_output: Output = run_built_probe(scratch.path());
    assert_eq!(
        mutated_output.status.code(),
        Some(1),
        "the mutated real-metadata output must fail the equality probe:\nstdout:\n{}\nstderr:\n{}\nsource:\n{mutated}",
        String::from_utf8_lossy(&mutated_output.stdout),
        String::from_utf8_lossy(&mutated_output.stderr)
    );
}
