use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;

fn temporary_consumer() -> core::result::Result<ScratchDir, Box<dyn std::error::Error>> {
    let scratch: ScratchDir = ScratchDir::create("disrobe-dotnet-default-consumer")?;
    let root: &Path = scratch.path();
    fs::create_dir_all(root.join("src"))?;
    let crate_path: String = env!("CARGO_MANIFEST_DIR").replace('\\', "/");
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"dotnet-default-consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\ndisrobe-pass-dotnet = {{ path = \"{crate_path}\" }}\n"
        ),
    )?;
    Ok(scratch)
}

fn cargo_check(root: &Path) -> core::result::Result<Output, Box<dyn std::error::Error>> {
    let output: Output = Command::new(env!("CARGO"))
        .args(["check", "--quiet"])
        .current_dir(root)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TARGET_DIR", root.join("target"))
        .output()?;
    Ok(output)
}

#[test]
fn default_feature_consumer_has_parser_api_without_reach_api()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let scratch: ScratchDir = temporary_consumer()?;
    let root: &Path = scratch.path();
    fs::write(
        root.join("src").join("main.rs"),
        "fn main() { let _ = disrobe_pass_dotnet::parse(&[]); }\n",
    )?;
    let parser_output: Output = cargo_check(root)?;
    if !parser_output.status.success() {
        return Err(String::from_utf8(parser_output.stderr)?.into());
    }
    let reach_symbols: [&str; 8] = [
        "capture_observations",
        "without_observations",
        "CaptureError",
        "Captured",
        "Observation",
        "ObservationPhase",
        "SemanticEntryPoint",
        "SemanticSurface",
    ];
    for symbol in reach_symbols {
        fs::write(
            root.join("src").join("main.rs"),
            format!("use disrobe_pass_dotnet::{symbol};\nfn main() {{}}\n"),
        )?;
        let reach_output: Output = cargo_check(root)?;
        assert!(
            !reach_output.status.success(),
            "default consumer imported {symbol}"
        );
        let stderr: String = String::from_utf8(reach_output.stderr)?;
        assert!(stderr.contains(symbol));
        assert!(stderr.contains("unresolved import"));
    }
    scratch.close()?;
    Ok(())
}
