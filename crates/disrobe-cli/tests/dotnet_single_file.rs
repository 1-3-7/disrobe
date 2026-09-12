#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

fn workspace_root() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn corpus_path(relative: &str) -> PathBuf {
    workspace_root().join("corpus").join(relative)
}

fn run_dotnet_decompile(input: &Path, out: &Path) -> disrobe_core::subprocess::CapturedOutput {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_disrobe"));
    command
        .arg("dotnet")
        .arg("decompile")
        .arg(input)
        .arg("--out")
        .arg(out)
        .arg("--backend")
        .arg("auto")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child: std::process::Child = command
        .spawn()
        .unwrap_or_else(|error: std::io::Error| panic!("failed to spawn disrobe: {error}"));
    disrobe_core::subprocess::wait_with_direct_process_output_timeout(
        child,
        Duration::from_secs(30),
        1 << 20,
    )
    .expect("dotnet bundle decompile must complete within 30 seconds with bounded output")
}

#[test]
fn dotnet_decompile_routes_every_managed_bundle_member() {
    let fixture: PathBuf = corpus_path("binfmt/dotnet-single-file/probe.v6.all-types.exe");
    let expected_assembly: Vec<u8> =
        std::fs::read(corpus_path("binfmt/dotnet-single-file/expected/probe.dll"))
            .expect("tracked expected assembly must be readable");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-dotnet-bundle-cli")
            .expect("create scratch directory");
    let output: disrobe_core::subprocess::CapturedOutput =
        run_dotnet_decompile(&fixture, scratch.path());
    assert_eq!(
        output.exit_code,
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let extracted: Vec<u8> = std::fs::read(scratch.path().join("members/probe.dll"))
        .expect("bundle assembly must be extracted");
    assert_eq!(extracted, expected_assembly);
    for member in [
        "libcustom.dll",
        "probe.deps.json",
        "probe.dll",
        "probe.pdb",
        "probe.runtimeconfig.json",
    ] {
        assert!(
            scratch.path().join("members").join(member).is_file(),
            "missing extracted member {member}"
        );
    }
    assert!(
        scratch
            .path()
            .join("assemblies/probe.dll/manifest.json")
            .is_file()
    );
    let nested_manifest_bytes: Vec<u8> =
        std::fs::read(scratch.path().join("assemblies/probe.dll/manifest.json"))
            .expect("nested manifest must be readable");
    let nested_manifest: serde_json::Value =
        serde_json::from_slice(&nested_manifest_bytes).expect("nested manifest must be valid JSON");
    assert_eq!(nested_manifest["input"], "members/probe.dll");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(!stdout.contains("disrobe-dotnet-bundle-stage"));
    let source: String =
        std::fs::read_to_string(scratch.path().join("assemblies/probe.dll/probe.native.cs"))
            .expect("managed bundle assembly must produce C# output");
    assert!(
        source.contains("<Main>") && source.contains("Hello, World!"),
        "unexpected native source: {source}"
    );
    assert!(scratch.path().join("bundle.manifest.json").is_file());
}

#[test]
fn dotnet_decompile_accepts_every_defined_bundle_manifest_version() {
    for (fixture_name, expected_version) in [
        ("probe.v1.win-x64.exe", "1.0"),
        ("probe.v2.win-x64.exe", "2.0"),
        ("probe.v6.all-types.exe", "6.0"),
        ("probe.v6.linux-x64", "6.0"),
        ("probe.v6.osx-x64", "6.0"),
        ("probe.v6.win-x64.exe", "6.0"),
    ] {
        let fixture: PathBuf = corpus_path(&format!("binfmt/dotnet-single-file/{fixture_name}"));
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-dotnet-bundle-version")
                .expect("create scratch directory");
        let output: disrobe_core::subprocess::CapturedOutput =
            run_dotnet_decompile(&fixture, scratch.path());
        assert_eq!(
            output.exit_code,
            Some(0),
            "{fixture_name} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let manifest_bytes: Vec<u8> = std::fs::read(scratch.path().join("bundle.manifest.json"))
            .expect("bundle manifest must be readable");
        let manifest: serde_json::Value =
            serde_json::from_slice(&manifest_bytes).expect("bundle manifest must be valid JSON");
        assert_eq!(
            manifest["bundle_version"],
            serde_json::Value::String(expected_version.to_owned())
        );
        assert_eq!(manifest["managed_assembly_count"], 1);
    }
}

#[test]
fn dotnet_decompile_preserves_direct_assembly_layout() {
    let fixture: PathBuf = corpus_path("binfmt/dotnet-single-file/expected/probe.dll");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-dotnet-direct-cli")
            .expect("create scratch directory");
    let output: disrobe_core::subprocess::CapturedOutput =
        run_dotnet_decompile(&fixture, scratch.path());
    assert_eq!(
        output.exit_code,
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(scratch.path().join("manifest.json").is_file());
    assert!(scratch.path().join("probe.native.cs").is_file());
    assert!(!scratch.path().join("bundle.manifest.json").exists());
    assert!(!scratch.path().join("members").exists());
}

#[test]
fn dotnet_bundle_decompile_does_not_replace_nonempty_output() {
    let fixture: PathBuf = corpus_path("binfmt/dotnet-single-file/probe.v6.all-types.exe");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-dotnet-bundle-existing")
            .expect("create scratch directory");
    let output_dir: PathBuf = scratch.path().join("output");
    std::fs::create_dir(&output_dir).expect("create existing output directory");
    let sentinel_path: PathBuf = output_dir.join("sentinel.bin");
    std::fs::write(&sentinel_path, b"preserve-me").expect("write sentinel");
    let output: disrobe_core::subprocess::CapturedOutput =
        run_dotnet_decompile(&fixture, &output_dir);
    assert_eq!(output.exit_code, Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("DR-CLI-0468"));
    let sentinel: Vec<u8> = std::fs::read(&sentinel_path).expect("sentinel must remain readable");
    assert_eq!(sentinel, b"preserve-me");
    assert!(!output_dir.join("bundle.manifest.json").exists());
}

#[test]
fn dotnet_bundle_decompile_refuses_invalid_declared_assembly_transactionally() {
    let fixture: PathBuf = corpus_path("binfmt/dotnet-single-file/probe.v6.all-types.exe");
    let mut bytes: Vec<u8> = std::fs::read(&fixture).expect("tracked bundle must be readable");
    let path: &[u8] = b"libcustom.dll";
    let path_offset: usize = bytes
        .windows(path.len())
        .rposition(|window: &[u8]| window == path)
        .expect("tracked manifest must name libcustom.dll");
    assert_eq!(bytes[path_offset - 1], path.len() as u8);
    assert_eq!(bytes[path_offset - 2], 2);
    bytes[path_offset - 2] = 1;
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-dotnet-bundle-invalid-assembly")
            .expect("create scratch directory");
    let input_path: PathBuf = scratch.path().join("invalid-declared-assembly.exe");
    std::fs::write(&input_path, bytes).expect("write malformed bundle");
    let output_dir: PathBuf = scratch.path().join("output");
    let output: disrobe_core::subprocess::CapturedOutput =
        run_dotnet_decompile(&input_path, &output_dir);
    assert_eq!(output.exit_code, Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("DR-CLI-0483"));
    assert!(!output_dir.exists());
    let residual_stages: usize = std::fs::read_dir(scratch.path())
        .expect("scratch root must be readable")
        .filter_map(Result::ok)
        .filter(|entry: &std::fs::DirEntry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("disrobe-dotnet-bundle-stage")
        })
        .count();
    assert_eq!(residual_stages, 0);
}
