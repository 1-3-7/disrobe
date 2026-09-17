#![cfg(feature = "native")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const FIXTURES: [&str; 3] = ["thumb_forms", "arm32_mixed_modes", "arm32_forms"];

const DISASM_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_CAPTURED_BYTES: usize = 1 << 20;

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn arch_corpus(stem: &str, extension: &str) -> PathBuf {
    workspace_root()
        .join("corpus")
        .join("native")
        .join("arch")
        .join(format!("{stem}.{extension}"))
}

fn read_reference(stem: &str) -> String {
    let path: PathBuf = arch_corpus(stem, "objdump");
    std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is the committed llvm-objdump reference this case grades against, and without it \
             the case would assert nothing, so its absence is a damaged checkout rather than an \
             optional dependency: {error}",
            path.display()
        )
    })
}

fn cargo_bin() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

#[allow(clippy::disallowed_methods)]
fn run_disasm(input: &Path, out: &Path) {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {bin:?}; run `cargo build -p disrobe-cli` first"
    );
    let mut command: Command = Command::new(&bin);
    command
        .arg("native")
        .arg("disasm")
        .arg(input)
        .arg("--out")
        .arg(out)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child: std::process::Child = command
        .spawn()
        .unwrap_or_else(|error: std::io::Error| panic!("failed to spawn disrobe: {error}"));
    let captured: disrobe_core::subprocess::CapturedOutput =
        disrobe_core::subprocess::wait_with_direct_process_output_timeout(
            child,
            DISASM_TIMEOUT,
            MAX_CAPTURED_BYTES,
        )
        .expect("disrobe native disasm must complete within its bound with bounded output");
    assert_eq!(
        captured.exit_code,
        Some(0),
        "disrobe native disasm on {input:?} did not exit zero\n--stdout--\n{}\n--stderr--\n{}",
        String::from_utf8_lossy(&captured.stdout),
        String::from_utf8_lossy(&captured.stderr)
    );
}

fn parse_hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

fn reference_addresses(objdump: &str) -> BTreeMap<String, BTreeSet<u64>> {
    let mut out: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in objdump.lines() {
        if let Some(open) = line.find(" <")
            && let Some(close) = line.rfind(">:")
            && close > open
            && parse_hex(&line[..open]).is_some()
        {
            current = Some(line[open + 2..close].to_owned());
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            continue;
        }
        let trimmed: &str = line.trim_start();
        let Some(colon) = trimmed.find(':') else {
            continue;
        };
        let Some(address) = parse_hex(&trimmed[..colon]) else {
            continue;
        };
        if let Some(name) = current.as_ref() {
            out.entry(name.clone()).or_default().insert(address);
        }
    }
    out
}

fn recovered_addresses(asm: &str) -> BTreeMap<String, BTreeSet<u64>> {
    let mut out: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in asm.lines() {
        if !line.starts_with(char::is_whitespace) {
            if let Some(at) = line.find(" @ 0x") {
                current = Some(line[..at].trim().to_owned());
            }
            continue;
        }
        let trimmed: &str = line.trim_start();
        if !trimmed.starts_with("0x") {
            continue;
        }
        let Some(colon) = trimmed.find(':') else {
            continue;
        };
        let Some(address) = parse_hex(&trimmed[..colon]) else {
            continue;
        };
        if let Some(name) = current.as_ref() {
            out.entry(name.clone()).or_default().insert(address);
        }
    }
    out
}

#[allow(clippy::disallowed_methods)]
fn recovered_for(stem: &str) -> BTreeMap<String, BTreeSet<u64>> {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&format!("disrobe-arm-boundary-{stem}"))
            .expect("create scratch directory");
    let out: PathBuf = scratch.path().join(format!("{stem}.asm"));
    run_disasm(&arch_corpus(stem, "elf"), &out);
    let asm: String = std::fs::read_to_string(&out)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", out.display()));
    recovered_addresses(&asm)
}

#[test]
fn every_arm_fixture_decodes_at_the_reference_instruction_boundaries() {
    let mut graded: usize = 0;
    let mut agreed: usize = 0;
    for stem in FIXTURES {
        let reference: BTreeMap<String, BTreeSet<u64>> = reference_addresses(&read_reference(stem));
        assert!(
            !reference.is_empty(),
            "{stem}.objdump parsed to no function, so this case would grade nothing"
        );
        let recovered: BTreeMap<String, BTreeSet<u64>> = recovered_for(stem);
        for (function, want) in &reference {
            let Some(got) = recovered.get(function) else {
                panic!(
                    "{stem}: llvm-objdump reports {} instructions in `{function}` and disrobe \
                     recovered no such function; recovered functions were {:?}",
                    want.len(),
                    recovered.keys().collect::<Vec<&String>>()
                );
            };
            graded += want.len();
            agreed += want.intersection(got).count();
            let missing: Vec<u64> = want.difference(got).copied().collect();
            let extra: Vec<u64> = got.difference(want).copied().collect();
            assert!(
                missing.is_empty() && extra.is_empty(),
                "{stem}:{function}: decoded boundaries diverge from llvm-objdump. A wrong ARM \
                 decode mode lands mid-instruction, so a divergent boundary set is the mis-decode \
                 signature. missing={missing:#x?} extra={extra:#x?}"
            );
        }
    }
    assert_eq!(
        agreed, graded,
        "ARM DECODE BOUNDARY REFERENCE: {agreed}/{graded} addresses agree with llvm-objdump"
    );
    assert!(
        graded >= 80,
        "the three committed ARM fixtures hold more than 80 instructions between them, so a \
         denominator of {graded} means the reference stopped parsing early"
    );
    println!("ARM DECODE BOUNDARY REFERENCE: {agreed}/{graded} addresses agree with llvm-objdump");
}

#[test]
fn the_thumb_fixture_is_decoded_as_thumb_rather_than_a32() {
    let recovered: BTreeMap<String, BTreeSet<u64>> = recovered_for("thumb_forms");
    let addresses: Vec<u64> = recovered
        .values()
        .flat_map(|set: &BTreeSet<u64>| set.iter().copied())
        .collect();
    assert!(
        !addresses.is_empty(),
        "thumb_forms recovered no instruction at all"
    );
    let two_byte_steps: usize = addresses
        .windows(2)
        .filter(|pair: &&[u64]| pair[1].saturating_sub(pair[0]) == 2)
        .count();
    assert!(
        two_byte_steps > 0,
        "every recovered instruction in thumb_forms is four bytes wide, which is what reading a \
         Thumb region through the A32 decoder produces; addresses were {addresses:#x?}"
    );
}

#[test]
fn the_mixed_fixture_recovers_both_a32_and_thumb_regions() {
    let recovered: BTreeMap<String, BTreeSet<u64>> = recovered_for("arm32_mixed_modes");
    let names: Vec<&String> = recovered.keys().collect();
    for expected in ["arm_pick", "thumb_scale"] {
        assert!(
            recovered.contains_key(expected),
            "the mixed image holds an A32 region and a Thumb region, so `{expected}` must be \
             recovered in the same run; recovered {names:?}"
        );
    }
}
