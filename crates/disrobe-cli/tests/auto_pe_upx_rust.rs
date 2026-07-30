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
fn tmp_out(name: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-chain-{name}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
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
        .arg("--capture-stages")
        .output()
        .unwrap_or_else(|e: std::io::Error| panic!("failed to spawn disrobe: {e}"))
}

fn read_chain_json(out_dir: &Path) -> String {
    let p: PathBuf = out_dir.join("chain.json");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e: std::io::Error| panic!("cannot read chain.json at {p:?}: {e}"))
}

fn find_file_named(dir: &Path, target: &str) -> Option<Vec<u8>> {
    let read: std::fs::ReadDir = std::fs::read_dir(dir).ok()?;
    for entry in read.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_named(&path, target) {
                return Some(found);
            }
        } else if entry.file_name().to_string_lossy() == target
            && let Ok(bytes) = std::fs::read(&path)
        {
            return Some(bytes);
        }
    }
    None
}

fn unpacked_stage_bytes(out_dir: &Path) -> Option<Vec<u8>> {
    find_file_named(&out_dir.join("extracted"), "recovered-image.bin")
}

const RUST_STDLIB_PROVENANCE: [&[u8]; 2] = [b"library\\core\\src", b"library\\alloc\\src"];

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w: &&[u8]| *w == needle)
        .count()
}

fn carve_legacy_rust_symbols(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut i: usize = 0;
    while i + 4 < bytes.len() {
        if &bytes[i..i + 3] == b"_ZN" {
            let start: usize = i;
            let mut j: usize = i + 3;
            while j < bytes.len()
                && matches!(bytes[j], b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$' | b'.')
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'E' && j - start >= 8 {
                if let Ok(sym) = core::str::from_utf8(&bytes[start..=j]) {
                    out.push(sym.to_owned());
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

#[test]
fn auto_pe_upx_rust_chain_unpacks_and_recovers_rust() {
    let packed: PathBuf = corpus_path("native/packers/upx/hello.packed.nrv2b.exe");
    assert!(
        packed.exists(),
        "{} is tracked in git and this case grades nothing without it, so its \
         absence is a damaged checkout rather than an optional dependency",
        packed.display()
    );

    let out_scratch: disrobe_core::scratch::ScratchDir = tmp_out("pe-upx-rust");

    let out: PathBuf = out_scratch.path().to_path_buf();
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
    let recovered: Vec<u8> = unpacked_stage_bytes(&out).unwrap_or_else(|| {
        panic!(
            "no recovered-image.bin under {out:?}/extracted; the chain must materialise the \
             unpacked PE image as a child so symbol recovery runs on the real recovered bytes"
        )
    });

    for marker in RUST_STDLIB_PROVENANCE {
        let in_packed: usize = count_occurrences(&packed_bytes, marker);
        let in_recovered: usize = count_occurrences(&recovered, marker);
        assert_eq!(
            in_packed, 0,
            "rust-stdlib provenance {marker:?} must be absent from the compressed UPX image \
             (else recovery is a no-op tautology)"
        );
        assert!(
            in_recovered > 0,
            "rust-stdlib provenance {marker:?} must surface in the recovered image produced by the \
             chain; UPX unpack did not expose the Rust core/alloc panic-location strings"
        );
    }

    let carved: Vec<String> = carve_legacy_rust_symbols(&recovered);
    let mut demangled_count: usize = 0;
    for sym in &carved {
        let Ok(demangled): Result<DemangledSymbol, _> = demangle_rust(sym) else {
            continue;
        };
        assert_eq!(
            demangled.scheme,
            DemangleScheme::RustLegacy,
            "symbol {sym} carved from recovered chain bytes must demangle under the legacy scheme"
        );
        assert!(
            !demangled.demangled.is_empty(),
            "demangled form of carved symbol {sym} must be non-empty"
        );
        demangled_count += 1;
    }

    eprintln!(
        "PE->UPX E2E OK: chain dispatched native.packer-unpack(upx); recovered image exposes \
         {provenance} core/alloc panic-location markers absent from the packed input; \
         demangled {demangled_count} of {carved_count} legacy-mangled symbol(s) carved from the \
         recovered bytes (this Rust fixture is linker-symbol-stripped, so its recovered symbol \
         surface is the embedded stdlib source-path provenance rather than _ZN linker symbols)",
        provenance = RUST_STDLIB_PROVENANCE
            .iter()
            .map(|m: &&[u8]| count_occurrences(&recovered, m))
            .sum::<usize>(),
        carved_count = carved.len(),
    );

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn demangle_rust_pipeline_resolves_real_legacy_symbols() {
    let core_symbol: DemangledSymbol =
        demangle_rust("_ZN4core3ptr13drop_in_place17h0123456789abcdefE")
            .expect("core symbol must demangle");
    assert_eq!(core_symbol.scheme, DemangleScheme::RustLegacy);
    assert!(
        core_symbol.demangled.starts_with("core::"),
        "must demangle a core:: path; got {}",
        core_symbol.demangled
    );

    let alloc_symbol: DemangledSymbol =
        demangle_rust("_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$8grow_one17hfedcba9876543210E")
            .expect("alloc symbol must demangle");
    assert_eq!(alloc_symbol.scheme, DemangleScheme::RustLegacy);
    assert!(
        alloc_symbol.demangled.starts_with("alloc::"),
        "must demangle an alloc:: path; got {}",
        alloc_symbol.demangled
    );
}
