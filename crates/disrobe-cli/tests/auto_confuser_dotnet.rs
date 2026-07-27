#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

#[allow(clippy::disallowed_methods)]
fn tmp_out(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-chain-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn run_chain_cli_capture(input: &Path, out: &Path, chain_arg: &str) -> std::process::Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    Command::new(&bin)
        .arg("chain")
        .arg(input)
        .arg("--out")
        .arg(out)
        .arg("--chain")
        .arg(chain_arg)
        .arg("--capture-stages")
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

fn read_chain_json(out_dir: &Path) -> String {
    let p: PathBuf = out_dir.join("chain.json");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read chain.json at {p:?}: {e}"))
}

fn stage_output_contains(out_dir: &Path, needle: &[u8]) -> bool {
    let final_dir: PathBuf = out_dir.join("final");
    for base in [out_dir, final_dir.as_path()] {
        let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            let stage: PathBuf = entry.path().join("output.bin");
            let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&stage) else {
                continue;
            };
            if bytes.windows(needle.len()).any(|w: &[u8]| w == needle) {
                return true;
            }
        }
    }
    false
}

#[test]
fn auto_confuser_dotnet_recovers_constant_and_csharp_node() {
    const KNOWN_PLAINTEXT: &[u8] = b"DISROBE_CONFUSER_CONSTANT_PROOF_8842";

    let fixture: PathBuf = corpus_path("dotnet/SampleConstants.confuserex2.dll");
    if !fixture.exists() {
        eprintln!("SKIP: fixture missing: {fixture:?}");
        return;
    }
    if !cargo_bin().exists() {
        eprintln!("SKIP: disrobe binary missing: {:?}", cargo_bin());
        return;
    }

    let raw: Vec<u8> = std::fs::read(&fixture)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read fixture {fixture:?}: {e}"));
    assert!(
        !raw.windows(KNOWN_PLAINTEXT.len())
            .any(|w: &[u8]| w == KNOWN_PLAINTEXT),
        "plaintext must NOT appear in the obfuscated fixture; otherwise the chain assertion is a \
         trivial string scan, not a real ConfuserEx2 decrypt"
    );

    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("confuser-dotnet");

    let out: PathBuf = out_scratch.path().to_path_buf();
    let proc_out: std::process::Output = run_chain_cli_capture(&fixture, &out, "auto:8");
    assert!(
        proc_out.status.success(),
        "chain failed: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let json: String = read_chain_json(&out);
    assert!(
        json.contains("dotnet.classify"),
        "expected dotnet.classify pass in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );
    assert!(
        json.contains("\"kind\": \"source\"") && json.contains("\"language\": \"C#\""),
        "expected a C# source decompile node in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );
    assert!(
        json.contains("\"verdict\": \"complete\""),
        "expected the dotnet node to complete; got prefix: {prefix}",
        prefix = &json[..json.len().min(600)]
    );

    assert!(
        stage_output_contains(&out, KNOWN_PLAINTEXT),
        "in-house ConfuserEx2 constants decryptor must surface {plaintext:?} in a captured stage \
         output under {out:?}; chain.json: {prefix}",
        plaintext = std::str::from_utf8(KNOWN_PLAINTEXT).unwrap_or("<utf8>"),
        prefix = &json[..json.len().min(600)]
    );

    let _ = std::fs::remove_dir_all(&out);
}
