#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_dotnet::model::{MethodModel, ParamModel};
use disrobe_pass_dotnet::signature::{MethodSig, TypeSig, TypeSigOrVoid};

fn dotnet_available() -> bool {
    Command::new("dotnet")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Library</OutputType>\n    <TargetFramework>net9.0</TargetFramework>\n    <Nullable>disable</Nullable>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n    <AssemblyName>kwparamoracle</AssemblyName>\n  </PropertyGroup>\n</Project>\n";

fn method_with_param_named(name: &str) -> MethodModel {
    MethodModel {
        token: 0x0600_0001,
        name: "Sample.K::M".to_owned(),
        flags: 0x0006 | 0x0010,
        impl_flags: 0,
        rva: 0,
        signature: MethodSig {
            calling_convention: 0,
            has_this: false,
            explicit_this: false,
            generic_param_count: 0,
            return_type: TypeSigOrVoid::Void,
            params: vec![TypeSig::I4],
        },
        parameters: vec![ParamModel {
            sequence: 1,
            name: name.to_owned(),
        }],
    }
}

fn compiles(header: &str, subdir: &str) -> (bool, String) {
    let source: String = format!("public class W\n{{\n    {header} {{ }}\n}}\n");
    let tmp: PathBuf = std::env::temp_dir().join(subdir);
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mk tmp");
    std::fs::write(tmp.join("kwparamoracle.csproj"), CSPROJ).expect("write csproj");
    std::fs::write(tmp.join("Lib.cs"), &source).expect("write source");
    let out: std::process::Output = Command::new("dotnet")
        .args(["build", "-c", "Release", "-v", "q", "--nologo"])
        .current_dir(&tmp)
        .output()
        .expect("dotnet build");
    let combined: String = format!(
        "SOURCE:\n{source}\nSTDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), combined)
}

#[test]
fn emitted_signature_with_keyword_parameter_recompiles() {
    let escaped: MethodModel = method_with_param_named("object");
    let header: String = escaped.csharp_signature();
    assert!(
        header.ends_with("M(int @object)"),
        "emitter must @-escape the keyword parameter; got: {header}"
    );

    if !dotnet_available() {
        eprintln!("SKIP keyword-parameter recompile oracle: no dotnet SDK on PATH");
        return;
    }

    let (ok, report): (bool, String) = compiles(&header, "disrobe_kwparam_escaped");
    assert!(ok, "escaped signature failed to compile:\n{report}");

    let raw: String = header.replace("@object", "object");
    let (raw_ok, raw_report): (bool, String) = compiles(&raw, "disrobe_kwparam_raw");
    assert!(
        !raw_ok,
        "unescaped keyword parameter must not compile, so the @-escape is what recovers a valid program:\n{raw_report}"
    );
}
