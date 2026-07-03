#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_binfmt::native::{NativeFile, SymbolInfo, parse_native};
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, encode_disasm,
};
use disrobe_ir::{Envelope, Rung};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter as _, Instruction, NasmFormatter, OpKind,
};
use object::write::{
    Object as WriteObject, StandardSection, Symbol as WriteSymbol, SymbolFlags as WriteSymbolFlags,
    SymbolKind as WriteSymbolKind, SymbolScope, SymbolSection,
};
use object::{Architecture, BinaryFormat, Endianness};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn cli_binary() -> PathBuf {
    let mut p: PathBuf = env_target_dir();
    p.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    p
}

fn env_target_dir() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn temp_path(stem: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("disrobe-query-e2e-{stem}-{pid}-{seq}.dr"))
}

fn run_disrobe(args: &[&str]) -> (i32, String, String) {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {}",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin).args(args).output().expect("spawn");
    let code: i32 = output.status.code().unwrap_or(-1);
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    (code, stdout, stderr)
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

fn call_rel32(buf: &mut [u8], at: usize, target: usize) {
    let rel: i32 = i32::try_from(target as i64 - (at as i64 + 5)).expect("rel32");
    buf[at] = 0xE8;
    buf[at + 1..at + 5].copy_from_slice(&rel.to_le_bytes());
}

fn build_text() -> Vec<u8> {
    let mut t: Vec<u8> = vec![0xCC; 0x80];
    put(&mut t, 0x00, &[0x8A, 0x07, 0xC3]);
    put(&mut t, 0x10, &[0x53, 0x31, 0xDB]);
    call_rel32(&mut t, 0x13, 0x00);
    put(&mut t, 0x18, &[0x34, 0x5A]);
    put(&mut t, 0x1A, &[0x88, 0x04, 0x1F]);
    put(&mut t, 0x1D, &[0x43]);
    put(&mut t, 0x1E, &[0x83, 0xFB, 0x10]);
    put(&mut t, 0x21, &[0x7C, 0xF0]);
    put(&mut t, 0x23, &[0x5B, 0xC3]);
    call_rel32(&mut t, 0x30, 0x70);
    put(&mut t, 0x35, &[0xC3]);
    call_rel32(&mut t, 0x40, 0x74);
    call_rel32(&mut t, 0x45, 0x78);
    put(&mut t, 0x4A, &[0xC3]);
    call_rel32(&mut t, 0x50, 0x10);
    call_rel32(&mut t, 0x55, 0x30);
    call_rel32(&mut t, 0x5A, 0x40);
    put(&mut t, 0x5F, &[0x31, 0xC0, 0xC3]);
    put(&mut t, 0x70, &[0xC3]);
    put(&mut t, 0x74, &[0xC3]);
    put(&mut t, 0x78, &[0xC3]);
    t
}

fn fixture_symbols() -> Vec<(&'static str, u64, u64)> {
    vec![
        ("read_byte", 0x00, 0x03),
        ("decode", 0x10, 0x15),
        ("crypto_init", 0x30, 0x06),
        ("net_send", 0x40, 0x0B),
        ("main", 0x50, 0x12),
        ("CryptEncrypt", 0x70, 0x01),
        ("connect", 0x74, 0x01),
        ("send", 0x78, 0x01),
    ]
}

fn build_elf() -> Vec<u8> {
    let mut obj: WriteObject<'_> =
        WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text: object::write::SectionId = obj.section_id(StandardSection::Text);
    let _ = obj.append_section_data(text, &build_text(), 16);
    for (name, off, size) in fixture_symbols() {
        let sym: WriteSymbol = WriteSymbol {
            name: name.as_bytes().to_vec(),
            value: off,
            size,
            kind: WriteSymbolKind::Text,
            scope: if name == "main" {
                SymbolScope::Dynamic
            } else {
                SymbolScope::Linkage
            },
            weak: false,
            section: SymbolSection::Section(text),
            flags: WriteSymbolFlags::None,
        };
        let _ = obj.add_symbol(sym);
    }
    obj.write().expect("elf write")
}

fn lift_to_dr() -> Vec<u8> {
    let elf: Vec<u8> = build_elf();
    let nf: NativeFile = parse_native(&elf).expect("parse native");
    let text_addr: u64 = nf
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| s.address)
        .expect("text");

    let file: object::read::File<'_> = object::read::File::parse(elf.as_slice()).expect("object");
    let text_bytes: Vec<u8> = {
        use object::Object as _;
        use object::ObjectSection as _;
        file.sections()
            .find(|s| s.name().is_ok_and(|n| n == ".text"))
            .and_then(|s| s.data().ok().map(<[u8]>::to_vec))
            .expect("text data")
    };

    let mut decoder: Decoder<'_> =
        Decoder::with_ip(64, &text_bytes, text_addr, DecoderOptions::NONE);
    let mut formatter: NasmFormatter = NasmFormatter::new();
    let mut insn: Instruction = Instruction::default();
    let mut instructions: Vec<DisasmInstruction> = Vec::new();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        let start: usize = (insn.ip().saturating_sub(text_addr)) as usize;
        let raw: Vec<u8> = text_bytes
            .get(start..start + insn.len())
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let mut text: String = String::new();
        formatter.format(&insn, &mut text);
        let (mnemonic, operands): (String, Vec<String>) = match text.split_once(' ') {
            Some((m, ops)) => (
                m.to_owned(),
                ops.split(',').map(|s: &str| s.trim().to_owned()).collect(),
            ),
            None => (text.clone(), Vec::new()),
        };
        let (flow, branch_target): (InsnFlow, Option<u64>) = flow_of(&insn);
        instructions.push(DisasmInstruction {
            offset: insn.ip(),
            bytes: raw,
            mnemonic,
            operands,
            flow,
            branch_target,
            ..DisasmInstruction::default()
        });
    }

    let known: Vec<&str> = fixture_symbols().into_iter().map(|(n, _, _)| n).collect();
    let symbol_table: Vec<DisasmSymbol> = nf
        .symbols
        .iter()
        .filter(|s: &&SymbolInfo| known.contains(&s.name.as_str()))
        .map(|s: &SymbolInfo| DisasmSymbol {
            address: s.address,
            name: s.name.clone(),
            kind: match s.name.as_str() {
                "main" => DisasmSymbolKind::Export,
                "CryptEncrypt" | "connect" | "send" => DisasmSymbolKind::Import,
                _ => DisasmSymbolKind::Function,
            },
        })
        .collect();

    let payload: DisasmPayload = DisasmPayload {
        source_hash: [0u8; 32],
        instructions,
        symbol_table,
    };
    let hot: Vec<u8> = encode_disasm(&payload).expect("encode");
    Envelope::new(Rung::Disasm, hot, Vec::new())
        .encode()
        .expect("encode envelope")
}

fn flow_of(insn: &Instruction) -> (InsnFlow, Option<u64>) {
    let direct: bool = matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    match insn.flow_control() {
        FlowControl::Call if direct => (InsnFlow::Call, Some(insn.near_branch_target())),
        FlowControl::Call | FlowControl::IndirectCall => (InsnFlow::IndirectCall, None),
        FlowControl::ConditionalBranch => {
            (InsnFlow::ConditionalBranch, Some(insn.near_branch_target()))
        }
        FlowControl::UnconditionalBranch if direct => (
            InsnFlow::UnconditionalBranch,
            Some(insn.near_branch_target()),
        ),
        FlowControl::UnconditionalBranch => (InsnFlow::UnconditionalBranch, None),
        FlowControl::IndirectBranch => (InsnFlow::IndirectBranch, None),
        FlowControl::Return => (InsnFlow::Return, None),
        FlowControl::Interrupt => (InsnFlow::Interrupt, None),
        FlowControl::Next | FlowControl::XbeginXabortXend | FlowControl::Exception => {
            (InsnFlow::Sequential, None)
        }
    }
}

fn write_dr(stem: &str) -> PathBuf {
    let path: PathBuf = temp_path(stem);
    std::fs::write(&path, lift_to_dr()).expect("write dr");
    path
}

fn corpus_discovery(rel: &str) -> Option<PathBuf> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("native")
        .join("discovery")
        .join(rel);
    path.is_file().then_some(path)
}

#[test]
fn query_calls_to_json_lists_the_real_site() {
    let dr: PathBuf = write_dr("calls");
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "query",
        &dr.display().to_string(),
        "calls-to",
        "read_byte",
        "--json",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["query"], "calls-to");
    let matches: &Vec<serde_json::Value> = v["matches"].as_array().expect("matches");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["caller"], "decode");
    let _ = std::fs::remove_file(&dr);
}

#[test]
fn query_functions_text_lists_local_functions() {
    let dr: PathBuf = write_dr("funcs");
    let (code, stdout, stderr): (i32, String, String) =
        run_disrobe(&["query", &dr.display().to_string(), "functions"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for name in ["read_byte", "decode", "crypto_init", "net_send", "main"] {
        assert!(stdout.contains(name), "missing {name} in: {stdout}");
    }
    assert!(stdout.contains("[export]"), "main should be tagged export");
    let _ = std::fs::remove_file(&dr);
}

#[test]
fn query_capability_network_json_finds_connect_and_send() {
    let dr: PathBuf = write_dr("cap");
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "query",
        &dr.display().to_string(),
        "capability",
        "network",
        "--json",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let symbols: Vec<String> = v["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|m| m["symbol"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(symbols, vec!["connect", "send"]);
    let _ = std::fs::remove_file(&dr);
}

#[test]
fn query_rejects_non_disasm_envelope() {
    let raw: Vec<u8> = Envelope::new(Rung::Raw, vec![1, 2, 3], Vec::new())
        .encode()
        .expect("encode raw");
    let path: PathBuf = temp_path("raw");
    std::fs::write(&path, raw).expect("write raw");
    let (code, _stdout, stderr): (i32, String, String) =
        run_disrobe(&["query", &path.display().to_string(), "functions"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("DR-CLI-0831"), "stderr: {stderr}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn query_rejects_bad_expression() {
    let dr: PathBuf = write_dr("badexpr");
    let (code, _stdout, stderr): (i32, String, String) =
        run_disrobe(&["query", &dr.display().to_string(), "telepathy"]);
    assert_ne!(code, 0);
    assert!(stderr.contains("DR-CLI-0832"), "stderr: {stderr}");
    let _ = std::fs::remove_file(&dr);
}

fn write_raw_binary(stem: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path: PathBuf =
        std::env::temp_dir().join(format!("disrobe-query-bin-{stem}-{pid}-{seq}.elf"));
    std::fs::write(&path, build_elf()).expect("write elf");
    path
}

#[test]
fn query_runs_directly_on_a_raw_native_binary() {
    let bin: PathBuf = write_raw_binary("funcs");
    let (code, stdout, stderr): (i32, String, String) =
        run_disrobe(&["query", &bin.display().to_string(), "functions"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for name in ["read_byte", "decode", "main"] {
        assert!(stdout.contains(name), "missing {name} in: {stdout}");
    }
    let _ = std::fs::remove_file(&bin);
}

#[test]
fn query_calls_to_on_raw_binary_finds_real_site() {
    let bin: PathBuf = write_raw_binary("calls");
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "query",
        &bin.display().to_string(),
        "calls-to",
        "read_byte",
        "--json",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let matches: &Vec<serde_json::Value> = v["matches"].as_array().expect("matches");
    assert_eq!(matches.len(), 1, "one call to read_byte: {matches:?}");
    assert_eq!(matches[0]["caller"], "decode");
    let _ = std::fs::remove_file(&bin);
}

#[test]
fn query_functions_on_stripped_binary_is_nonempty() {
    let Some(stripped): Option<PathBuf> = corpus_discovery("disc.stripped.elf") else {
        return;
    };
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "query",
        &stripped.display().to_string(),
        "functions",
        "--json",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let matches: &Vec<serde_json::Value> = v["matches"].as_array().expect("matches");
    assert!(
        !matches.is_empty(),
        "G1 closed: stripped binary now yields functions over the CLI: {stdout}"
    );
}

#[test]
fn native_disasm_cfg_dot_on_stripped_binary_is_valid_graphviz() {
    let Some(stripped): Option<PathBuf> = corpus_discovery("disc.stripped.elf") else {
        return;
    };
    let out: PathBuf = {
        let pid: u32 = std::process::id();
        let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("disrobe-disasm-cfg-{pid}-{seq}.dot"))
    };
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "native",
        "disasm",
        &stripped.display().to_string(),
        "--emit",
        "cfg-dot",
        "-o",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    let dot: String = std::fs::read_to_string(&out).expect("dot output");
    assert!(dot.starts_with("digraph cfg {"), "not graphviz: {dot}");
    assert!(dot.contains("->"), "no CFG edges: {dot}");
    assert!(dot.trim_end().ends_with('}'));
    let _ = std::fs::remove_file(&out);
}

#[test]
fn native_disasm_raw_blob_emits_asm() {
    let out: PathBuf = {
        let pid: u32 = std::process::id();
        let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("disrobe-disasm-raw-{pid}-{seq}.asm"))
    };
    let blob: PathBuf = {
        let pid: u32 = std::process::id();
        let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p: PathBuf = std::env::temp_dir().join(format!("disrobe-rawblob-{pid}-{seq}.bin"));
        std::fs::write(&p, [0x90u8, 0x90, 0xC3]).expect("write blob");
        p
    };
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "native",
        "disasm",
        &blob.display().to_string(),
        "--raw",
        "--base",
        "0x1000",
        "--bits",
        "bits64",
        "-o",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    let asm: String = std::fs::read_to_string(&out).expect("asm output");
    assert!(asm.contains("nop"), "raw asm missing nop: {asm}");
    assert!(asm.contains("ret"), "raw asm missing ret: {asm}");
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&blob);
}

#[test]
fn native_callgraph_json_on_stripped_binary_has_real_edges() {
    let Some(stripped): Option<PathBuf> = corpus_discovery("disc.stripped.elf") else {
        return;
    };
    let out: PathBuf = {
        let pid: u32 = std::process::id();
        let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("disrobe-callgraph-{pid}-{seq}.json"))
    };
    let (code, stdout, stderr): (i32, String, String) = run_disrobe(&[
        "native",
        "callgraph",
        &stripped.display().to_string(),
        "--emit",
        "json",
        "-o",
        &out.display().to_string(),
    ]);
    assert_eq!(code, 0, "stdout: {stdout} stderr: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("cg json")).expect("json");
    let nodes: &Vec<serde_json::Value> = v["nodes"].as_array().expect("nodes");
    let edges: &Vec<serde_json::Value> = v["edges"].as_array().expect("edges");
    assert!(!nodes.is_empty(), "stripped binary yields call-graph nodes");
    assert!(
        !edges.is_empty(),
        "the _start -> compute -> dispatch chain produces real call edges: {edges:?}"
    );
    let _ = std::fs::remove_file(&out);
}
