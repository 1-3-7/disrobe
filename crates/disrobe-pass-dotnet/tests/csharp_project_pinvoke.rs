#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_dotnet::csharp_project::{CSharpProject, emit_csharp_project};

const EDGECASES_DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";
const INTEROP_DLL: &str = "../../corpus/dotnet/interop/Interop.dll";
const PRESERVE_SIG_DLL: &str = "../../corpus/dotnet/pinvoke-preserve/PreserveSigFixture.dll";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(EDGECASES_DLL)
}

#[test]
fn csharp_project_emits_impl_map_pinvoke_declarations() {
    let bytes: Vec<u8> = std::fs::read(fixture_path()).expect("read EdgeCases.baseline.dll");
    let project: CSharpProject = emit_csharp_project(&bytes).expect("emit C# project");
    let source: &str = project
        .files
        .values()
        .find(|source: &&String| source.contains("class PinvokePlayground"))
        .expect("PinvokePlayground source");
    assert!(
        source.contains(
            "[System.Runtime.InteropServices.DllImport(\"kernel32.dll\", EntryPoint = \"GetEnvironmentVariableW\", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true, CallingConvention = System.Runtime.InteropServices.CallingConvention.Winapi)]"
        ),
        "the ImplMap and ModuleRef metadata must become a C# DllImport attribute:\n{source}"
    );
    assert!(
        source.contains(
            "public static extern int GetEnvironmentVariableW(string name, System.Text.StringBuilder buffer, int size);"
        ),
        "the P/Invoke declaration must retain its C# signature and extern modifier:\n{source}"
    );
    assert!(
        !project.refusals.iter().any(|refusal| {
            refusal.type_name == "PinvokePlayground" && refusal.member == "GetEnvironmentVariableW"
        }),
        "GetEnvironmentVariableW must not be refused when ImplMap metadata is present: {:?}",
        project.refusals
    );
}

#[test]
fn csharp_project_preserves_impl_map_calling_convention() {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(INTEROP_DLL);
    let bytes: Vec<u8> = std::fs::read(path).expect("read Interop.dll");
    let project: CSharpProject = emit_csharp_project(&bytes).expect("emit C# project");
    let source: String = project.files.values().cloned().collect();
    assert!(
        source.contains(
            "[System.Runtime.InteropServices.DllImport(\"kernel32.dll\", EntryPoint = \"CreateFileW\", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true, CallingConvention = System.Runtime.InteropServices.CallingConvention.Winapi, ExactSpelling = true)]"
        ),
        "the C# attribute must preserve the ImplMap calling convention and flags:\n{source}"
    );
    assert!(
        source.contains(
            "[System.Runtime.InteropServices.DllImport(\"msvcrt.dll\", EntryPoint = \"printf\", CallingConvention = System.Runtime.InteropServices.CallingConvention.Cdecl)]"
        ),
        "the C# attribute must preserve a non-default ImplMap calling convention:\n{source}"
    );
}

#[test]
fn csharp_project_preserves_explicit_false_pinvoke_preserve_sig() {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PRESERVE_SIG_DLL);
    let bytes: Vec<u8> = std::fs::read(path).expect("read PreserveSigFixture.dll");
    let project: CSharpProject = emit_csharp_project(&bytes).expect("emit C# project");
    let source: String = project.files.values().cloned().collect();
    let source: String = source
        .lines()
        .map(str::trim)
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        source.contains(
            "[System.Runtime.InteropServices.DllImport(\"kernel32.dll\", EntryPoint = \"GetCurrentProcessId\", CallingConvention = System.Runtime.InteropServices.CallingConvention.Winapi)]\npublic static extern uint DefaultPreserveSig();"
        ),
        "the default PreserveSig metadata must not add a non-default C# argument:\n{source}"
    );
    assert!(
        source.contains(
            "[System.Runtime.InteropServices.DllImport(\"kernel32.dll\", EntryPoint = \"GetCurrentProcessId\", PreserveSig = false, CallingConvention = System.Runtime.InteropServices.CallingConvention.Winapi)]\npublic static extern uint ExplicitNoPreserveSig();"
        ),
        "an explicit false PreserveSig metadata bit must survive C# project emission:\n{source}"
    );
}
