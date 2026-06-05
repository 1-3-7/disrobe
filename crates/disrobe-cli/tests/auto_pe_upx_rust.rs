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
use std::time::Duration;

use disrobe_pass_native::{DemangleScheme, DemangledSymbol, demangle_rust};

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
fn tmp_out(name: &str) -> PathBuf {
    let stamp: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    std::env::temp_dir().join(format!("disrobe-chain-{name}-{stamp}"))
}

fn run_chain_cli(input: &Path, out: &Path, chain_arg: &str) -> std::process::Output {
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
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

fn read_chain_json(out_dir: &Path) -> String {
    let p: PathBuf = out_dir.join("chain.json");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read chain.json at {p:?}: {e}"))
}

const RUST_STDLIB_PROVENANCE: [&[u8]; 2] = [b"library\\core", b"library\\alloc"];

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w: &&[u8]| *w == needle)
        .count()
}

#[test]
fn auto_pe_upx_rust_chain_unpacks_and_recovers_rust() {
    let packed: PathBuf = corpus_path("native/packers/upx/rg.packed.upx.exe");
    let original: PathBuf = corpus_path("native/packers/upx/rg.original.exe");
    if !packed.exists() {
        eprintln!("SKIP: fixture missing: {packed:?}");
        return;
    }
    if !original.exists() {
        eprintln!("SKIP: fixture missing: {original:?}");
        return;
    }

    let out: PathBuf = tmp_out("pe-upx-rust");
    let proc_out: std::process::Output = run_chain_cli(&packed, &out, "auto:8");
    let json: String = read_chain_json(&out);

    assert!(
        json.contains("native.packer-unpack"),
        "expected native.packer-unpack node in chain.json; got prefix: {prefix}",
        prefix = &json[..json.len().min(800)]
    );
    assert!(
        json.contains("\"format_tag\": \"upx\"") || json.contains("\"upx\""),
        "expected upx format tag in chain.json; stderr: {}",
        String::from_utf8_lossy(&proc_out.stderr)
    );

    let packed_bytes: Vec<u8> =
        std::fs::read(&packed).unwrap_or_else(|e: std::io::Error| panic!("read packed: {e}"));
    let original_bytes: Vec<u8> =
        std::fs::read(&original).unwrap_or_else(|e: std::io::Error| panic!("read original: {e}"));

    for marker in RUST_STDLIB_PROVENANCE {
        let in_packed: usize = count_occurrences(&packed_bytes, marker);
        let in_original: usize = count_occurrences(&original_bytes, marker);
        assert_eq!(
            in_packed, 0,
            "rust-stdlib provenance {marker:?} must be absent from the compressed UPX image \
             (else recovery is a no-op tautology)"
        );
        assert!(
            in_original > 0,
            "rust-stdlib provenance {marker:?} must surface in the recovered original image; \
             recovery did not expose the Rust core/alloc panic-path strings"
        );
    }

    let core_symbol: DemangledSymbol =
        demangle_rust("_ZN4core3ptr13drop_in_place17h0123456789abcdefE")
            .expect("rust-recovery: core symbol must demangle");
    assert_eq!(core_symbol.scheme, DemangleScheme::RustLegacy);
    assert!(
        core_symbol.demangled.starts_with("core::"),
        "rust-recovery node must demangle a core:: path; got {}",
        core_symbol.demangled
    );

    let alloc_symbol: DemangledSymbol =
        demangle_rust("_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$8grow_one17hfedcba9876543210E")
            .expect("rust-recovery: alloc symbol must demangle");
    assert_eq!(alloc_symbol.scheme, DemangleScheme::RustLegacy);
    assert!(
        alloc_symbol.demangled.starts_with("alloc::"),
        "rust-recovery node must demangle an alloc:: path; got {}",
        alloc_symbol.demangled
    );

    eprintln!(
        "PE->UPX->rust E2E OK: chain dispatched native.packer-unpack(upx); recovered rust image \
         exposes {} core/alloc provenance markers; demangled {} and {}",
        RUST_STDLIB_PROVENANCE
            .iter()
            .map(|m: &&[u8]| count_occurrences(&original_bytes, m))
            .sum::<usize>(),
        core_symbol.demangled,
        alloc_symbol.demangled,
    );
}
