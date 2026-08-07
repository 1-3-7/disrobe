#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::disallowed_methods,
    clippy::missing_panics_doc
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::anti_analysis::{AntiAnalysisReport, Technique, scan};
use disrobe_core::scratch::ScratchDir;

fn scratch_dir() -> ScratchDir {
    ScratchDir::create("disrobe-aa-corpus").expect("create scratch dir")
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn first_c_compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"]
        .into_iter()
        .find(|c: &&'static str| tool_available(c))
}

fn exe_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

fn compile_c(cc: &str, dir: &std::path::Path, stem: &str, src: &str, opt: &str) -> Option<Vec<u8>> {
    let src_path: PathBuf = dir.join(format!("{stem}.c"));
    std::fs::write(&src_path, src).expect("write c source");
    let out_path: PathBuf = dir.join(exe_name(stem));
    let status: std::process::ExitStatus = Command::new(cc)
        .arg(opt)
        .arg(&src_path)
        .arg("-o")
        .arg(&out_path)
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    std::fs::read(&out_path).ok()
}

const TINY_C: &str = "int main(void){return 0;}\n";
const MEDIUM_C: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int fib(int n){ if(n<2) return n; return fib(n-1)+fib(n-2); }
int main(int argc,char**argv){
    int total=0; char buf[64];
    for(int i=0;i<argc+10;i++){
        total+=fib(i%12);
        snprintf(buf,sizeof buf,"iter %d total %d",i,total);
        if(strlen(buf)>3) total^=(int)buf[0];
    }
    char*p=(char*)malloc(128);
    if(p){ memset(p,total&0xff,128); total+=p[7]; free(p); }
    printf("result %d\n",total);
    return total&0x7f;
}
"#;

fn assert_zero_anti_analysis_verdicts(label: &str, bytes: &[u8]) {
    let report: AntiAnalysisReport = scan(bytes, Some(label));
    let verdicts: Vec<&Technique> = report
        .findings
        .iter()
        .filter(|f| f.detected)
        .map(|f| &f.technique)
        .collect();
    assert!(
        verdicts.is_empty(),
        "benign artifact {label} must yield ZERO anti-analysis verdicts; got {verdicts:?} \
         (full findings: {:?})",
        report.findings
    );
}

#[test]
fn benign_c_binaries_yield_zero_verdicts() {
    let Some(cc): Option<&'static str> = first_c_compiler() else {
        eprintln!("SKIP: no C compiler (cc/gcc/clang) available");
        return;
    };
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let mut compiled_any: bool = false;
    for (stem, src) in [("aa_tiny", TINY_C), ("aa_medium", MEDIUM_C)] {
        for opt in ["-O0", "-O2"] {
            let unique: String = format!("{stem}{}", opt.replace('-', "_"));
            let Some(bytes): Option<Vec<u8>> = compile_c(cc, &dir, &unique, src, opt) else {
                eprintln!("SKIP: {cc} {opt} failed to build {stem}");
                continue;
            };
            compiled_any = true;
            assert_zero_anti_analysis_verdicts(&format!("{cc}{opt}/{stem}"), &bytes);
        }
    }
    assert!(
        compiled_any,
        "at least one benign C build must succeed to exercise the precision corpus"
    );
}

#[test]
fn benign_rust_binary_yields_zero_verdicts() {
    if !tool_available("rustc") {
        eprintln!("SKIP: rustc unavailable");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("aa_rust.rs");
    std::fs::write(
        &src_path,
        "fn main(){ let mut s:u64=0; for i in 0..1000u64 { s=s.wrapping_add(i*i^s); } \
         println!(\"{}\", s); }\n",
    )
    .expect("write rust source");
    let mut compiled_any: bool = false;
    for (label, opt) in [("debug", "0"), ("release", "2")] {
        let out_path: PathBuf = dir.join(exe_name(&format!("aa_rust_{label}")));
        let ok: bool = Command::new("rustc")
            .arg(format!("-Copt-level={opt}"))
            .arg(&src_path)
            .arg("-o")
            .arg(&out_path)
            .status()
            .is_ok_and(|s: std::process::ExitStatus| s.success());
        if !ok {
            eprintln!("SKIP: rustc {label} build failed");
            continue;
        }
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&out_path) else {
            continue;
        };
        compiled_any = true;
        assert_zero_anti_analysis_verdicts(&format!("rust/{label}"), &bytes);
    }
    if !compiled_any {
        eprintln!("SKIP: no rust build succeeded");
    }
}

#[test]
fn positive_recall_real_binary_calling_two_debugger_checks() {
    if !tool_available("rustc") {
        eprintln!("SKIP: rustc unavailable");
        return;
    }
    if !cfg!(windows) {
        eprintln!("SKIP: IsDebuggerPresent/CheckRemoteDebuggerPresent are win32-only");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("aa_two_debug_checks.rs");
    std::fs::write(
        &src_path,
        "unsafe extern \"system\" { \
             fn IsDebuggerPresent() -> i32; \
             fn CheckRemoteDebuggerPresent(h_process: isize, pb_debugger_present: *mut i32) -> i32; \
         } \
         fn main(){ unsafe { \
             let a: i32 = IsDebuggerPresent(); \
             let mut b: i32 = 0; \
             CheckRemoteDebuggerPresent(-1isize, std::ptr::addr_of_mut!(b)); \
             println!(\"{a} {b}\"); \
         } }\n",
    )
    .expect("write rust source");
    let out_path: PathBuf = dir.join(exe_name("aa_two_debug_checks"));
    let ok: bool = Command::new("rustc")
        .arg("-Copt-level=0")
        .arg(&src_path)
        .arg("-o")
        .arg(&out_path)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success());
    if !ok {
        eprintln!("SKIP: rustc build of the two-debugger-check probe failed");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&out_path).expect("read compiled probe");
    let report: AntiAnalysisReport = scan(&bytes, Some("rust/two-debugger-checks"));
    assert!(
        detects(&report, Technique::AntiDebug),
        "a real binary that calls two distinct high-confidence anti-debug apis must still \
         reach an AntiDebug verdict; got {:?}",
        report.findings
    );
}

#[test]
fn disrobe_own_release_binary_yields_zero_verdicts() {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    let bin: PathBuf = root
        .join("target")
        .join("release")
        .join(exe_name("disrobe"));
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&bin) else {
        eprintln!(
            "SKIP: disrobe release binary not built at {}",
            bin.display()
        );
        return;
    };
    assert_zero_anti_analysis_verdicts("disrobe-own-release", &bytes);
}

#[test]
fn upx_packed_benign_reports_only_packing() {
    let Some(cc): Option<&'static str> = first_c_compiler() else {
        eprintln!("SKIP: no C compiler for upx corpus");
        return;
    };
    if !tool_available("upx") {
        eprintln!("SKIP: upx unavailable");
        return;
    }
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let Some(_): Option<Vec<u8>> = compile_c(cc, &dir, "aa_upx", MEDIUM_C, "-O2") else {
        eprintln!("SKIP: could not build upx input");
        return;
    };
    let input: PathBuf = dir.join(exe_name("aa_upx"));
    let packed: PathBuf = dir.join(exe_name("aa_upx_packed"));
    let ok: bool = Command::new("upx")
        .arg("--best")
        .arg("-q")
        .arg("-o")
        .arg(&packed)
        .arg(&input)
        .status()
        .is_ok_and(|s: std::process::ExitStatus| s.success());
    if !ok {
        eprintln!("SKIP: upx packing failed");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&packed).expect("read packed");
    let report: AntiAnalysisReport = scan(&bytes, Some("upx-packed"));
    let verdicts: Vec<Technique> = report
        .findings
        .iter()
        .filter(|f| f.detected)
        .map(|f| f.technique)
        .collect();
    assert_eq!(
        verdicts,
        vec![Technique::Packing],
        "a upx-packed benign must report exactly one verdict, Packing; got {:?}",
        report.findings
    );
}

fn pe_with_code(payload: &[u8], bits64: bool) -> Vec<u8> {
    let pe_off: usize = 0x80;
    let opt_size: usize = if bits64 { 0xF0 } else { 0xE0 };
    let sect_start: usize = pe_off + 24 + opt_size;
    let raw_ptr: usize = 0x200;
    let total: usize = (raw_ptr + payload.len().max(1)).max(sect_start + 40);
    let mut img: Vec<u8> = vec![0u8; total];
    img[0] = b'M';
    img[1] = b'Z';
    img[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    img[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let machine: u16 = if bits64 { 0x8664 } else { 0x014C };
    img[pe_off + 4..pe_off + 6].copy_from_slice(&machine.to_le_bytes());
    img[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
    img[pe_off + 20..pe_off + 22].copy_from_slice(&u16::try_from(opt_size).unwrap().to_le_bytes());
    let opt_start: usize = pe_off + 24;
    let magic: u16 = if bits64 { 0x020B } else { 0x010B };
    img[opt_start..opt_start + 2].copy_from_slice(&magic.to_le_bytes());
    let base: usize = sect_start;
    img[base..base + 8].copy_from_slice(b".text\0\0\0");
    let plen: u32 = u32::try_from(payload.len()).unwrap();
    img[base + 8..base + 12].copy_from_slice(&plen.to_le_bytes());
    img[base + 12..base + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    img[base + 16..base + 20].copy_from_slice(&plen.to_le_bytes());
    img[base + 20..base + 24].copy_from_slice(&u32::try_from(raw_ptr).unwrap().to_le_bytes());
    img[base + 36..base + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    img[raw_ptr..raw_ptr + payload.len()].copy_from_slice(payload);
    img
}

fn detects(report: &AntiAnalysisReport, technique: Technique) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.technique == technique && f.detected)
}

fn surfaced(report: &AntiAnalysisReport, technique: Technique) -> bool {
    report.findings.iter().any(|f| f.technique == technique)
}

#[test]
fn positive_recall_peb_being_debugged_32bit() {
    let mut payload: Vec<u8> = vec![0x64, 0xA1, 0x30, 0x00, 0x00, 0x00];
    payload.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02, 0x84, 0xC0]);
    let report: AntiAnalysisReport =
        scan(&pe_with_code(&payload, false), Some("peb-beingdebugged"));
    assert!(
        detects(&report, Technique::AntiDebug),
        "peb beingdebugged read must reach a verdict: {:?}",
        report.findings
    );
}

#[test]
fn positive_recall_peb_ntglobalflag_64bit() {
    let mut payload: Vec<u8> = vec![0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
    payload.extend_from_slice(&[0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00]);
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("peb-ntglobalflag"));
    assert!(
        detects(&report, Technique::AntiDebug),
        "{:?}",
        report.findings
    );
}

#[test]
fn positive_recall_rdtsc_sandwich() {
    let payload: Vec<u8> = vec![0x0F, 0x31, 0x50, 0x0F, 0xA2, 0x58, 0x0F, 0x31, 0x2B, 0xC1];
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("rdtsc-sandwich"));
    assert!(
        detects(&report, Technique::TimingEvasion),
        "{:?}",
        report.findings
    );
}

#[test]
fn positive_recall_sidt_red_pill_surfaced() {
    let payload: Vec<u8> = vec![0x0F, 0x01, 0x4C, 0x24, 0xFE, 0x3C, 0xFF];
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("sidt-compare"));
    assert!(
        surfaced(&report, Technique::AntiVm),
        "an instruction-boundary sidt red-pill store is surfaced for triage (informational): {:?}",
        report.findings
    );
}

#[test]
fn positive_recall_icebp_int_cluster() {
    let payload: Vec<u8> = vec![0x90, 0xCD, 0x2D, 0x90, 0x48, 0xF1, 0x90];
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("icebp-cluster"));
    assert!(
        detects(&report, Technique::AntiDebug),
        "{:?}",
        report.findings
    );
}

#[test]
fn positive_recall_hardware_breakpoint_surfaced() {
    let mut payload: Vec<u8> = vec![0xB8, 0x10, 0x00, 0x01, 0x00];
    payload.extend_from_slice(b"GetThreadContext\x00");
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, true), Some("hwbp"));
    assert!(
        surfaced(&report, Technique::AntiDebug),
        "a context-debug-registers flag immediate is surfaced for triage (informational): {:?}",
        report.findings
    );
}

#[test]
fn positive_recall_anti_disasm_cluster() {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&[0xEB, 0x01, 0xE8]);
    payload.extend_from_slice(&[0xEB, 0x01, 0xE9]);
    payload.extend_from_slice(&[0xEB, 0x01, 0x0F]);
    payload.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]);
    let report: AntiAnalysisReport = scan(&pe_with_code(&payload, false), Some("desync-cluster"));
    assert!(
        detects(&report, Technique::AntiDisassembly),
        "a dense jump-into-instruction desync cluster is verdict-grade: {:?}",
        report.findings
    );
}
