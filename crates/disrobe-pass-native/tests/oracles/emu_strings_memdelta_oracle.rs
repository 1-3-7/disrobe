#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

#[cfg(windows)]
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::{EmulatedString, emulate_string_decoders};

use crate::prerequisite;

const KEY: u8 = 0x5A;
const PLAINTEXT_DEC: &str = "recovered0from0emulated0scratch0AAAA";
const BLOCK1: &str = "transient0temp0block0one0";
const BLOCK2: &str = "surviving0final0block0two";
const COPY_SRC: &str = "benign0static0copysource0CCCC";
const GEN_FILL: &str = "01234567890123456789012345678901";
const WIDE_PLAINTEXT: &str = "wide0secret0url0payload0token0DDDD";
#[cfg(windows)]
const TEST_GCC_ENV: &str = "DISROBE_TEST_GCC";

fn has_tool(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn scratch_dir() -> ScratchDir {
    ScratchDir::create("disrobe-emu-memdelta").expect("create scratch directory")
}

fn c_array(name: &str, plain: &str) -> String {
    let bytes: Vec<String> = plain
        .bytes()
        .map(|b: u8| format!("0x{:02x}", b ^ KEY))
        .collect();
    format!(
        "static const unsigned char {name}[] = {{ {} }};\n",
        bytes.join(", ")
    )
}

fn c_array_wide(name: &str, plain: &str) -> String {
    let mut bytes: Vec<String> = Vec::with_capacity(plain.len() * 2);
    for b in plain.bytes() {
        bytes.push(format!("0x{:02x}", b ^ KEY));
        bytes.push(format!("0x{KEY:02x}"));
    }
    format!(
        "static const unsigned char {name}[] = {{ {} }};\n",
        bytes.join(", ")
    )
}

fn corpus_source() -> String {
    let mut src: String = String::new();
    src.push_str("#include <stddef.h>\n");
    src.push_str("#if defined(_WIN32)\n#define API __declspec(dllexport)\n");
    src.push_str("#else\n#define API __attribute__((visibility(\"default\")))\n#endif\n");
    src.push_str(&c_array("ENC_DEC", PLAINTEXT_DEC));
    src.push_str(&c_array("ENC_B1", BLOCK1));
    src.push_str(&c_array("ENC_B2", BLOCK2));
    src.push_str(&c_array_wide("ENC_WIDE", WIDE_PLAINTEXT));
    src.push_str("static const unsigned char XKEY = 0x5a;\n");
    let _ = writeln!(src, "static const char COPY_SRC[] = \"{COPY_SRC}\";");
    src.push_str(
        "API void dec(char *out){ for(unsigned i=0;i<(unsigned)sizeof(ENC_DEC);i++) \
         out[i]=(char)((unsigned char)ENC_DEC[i]^XKEY); }\n",
    );
    src.push_str(
        "API void dec_wide(char *out){ for(unsigned i=0;i<(unsigned)sizeof(ENC_WIDE);i++) \
         out[i]=(char)((unsigned char)ENC_WIDE[i]^XKEY); }\n",
    );
    src.push_str(
        "API int dec_transient(char *tmp){ int acc=0; \
         for(unsigned i=0;i<(unsigned)sizeof(ENC_B1);i++) tmp[i]=(char)((unsigned char)ENC_B1[i]^XKEY); \
         for(unsigned i=0;i<(unsigned)sizeof(ENC_B1);i++) acc+=(unsigned char)tmp[i]; \
         for(unsigned i=0;i<(unsigned)sizeof(ENC_B2);i++) tmp[i]=(char)((unsigned char)ENC_B2[i]^XKEY); \
         return acc; }\n",
    );
    src.push_str(
        "API void copy_static(char *out){ for(unsigned i=0;i<(unsigned)sizeof(COPY_SRC);i++) \
         out[i]=COPY_SRC[i]; }\n",
    );
    src.push_str(
        "API void gen_fill(char *out){ for(unsigned i=0;i<32u;i++) out[i]=(char)(0x30+(i%10)); }\n",
    );
    src
}

fn values(recovered: &[EmulatedString]) -> Vec<String> {
    recovered
        .iter()
        .map(|s: &EmulatedString| s.value.clone())
        .collect()
}

fn assert_recovery(image: &[u8], tag: &str) {
    let recovered: Vec<EmulatedString> = emulate_string_decoders(image);
    let got: Vec<String> = values(&recovered);

    let plaintext_recovered: bool = recovered
        .iter()
        .any(|s: &EmulatedString| s.value == PLAINTEXT_DEC);
    assert!(
        plaintext_recovered,
        "{tag}: scratch-buffer decoder plaintext {PLAINTEXT_DEC:?} not recovered from written \
         memory; harvested {got:?}"
    );

    let block1_hit: Option<&EmulatedString> = recovered
        .iter()
        .find(|s: &&EmulatedString| s.value == BLOCK1);
    assert!(
        block1_hit.is_some(),
        "{tag}: transient block {BLOCK1:?} (decoded into a temp then OVERWRITTEN before the routine \
         returned) must be captured by the write-log; a final-state scan loses it. harvested {got:?}"
    );
    assert!(
        recovered.iter().any(|s: &EmulatedString| s.value == BLOCK2),
        "{tag}: surviving block {BLOCK2:?} not recovered; harvested {got:?}"
    );

    let block1: &EmulatedString = block1_hit.expect("checked present");
    assert!(
        block1.decoder_address != 0,
        "{tag}: recovered string must carry its decoder call-site address"
    );

    let wide_hit: Option<&EmulatedString> = recovered
        .iter()
        .find(|s: &&EmulatedString| s.value == WIDE_PLAINTEXT);
    assert!(
        wide_hit.is_some(),
        "{tag}: UTF-16LE decoder plaintext {WIDE_PLAINTEXT:?} not recovered from written memory; \
         the plaintext is laid out as printable/0x00 cells so the ASCII path CANNOT produce it \
         (no run reaches the {MIN_LEN}-byte floor), proving the wide extractor is doing the work. \
         harvested {got:?}",
        MIN_LEN = 4
    );
    assert!(
        wide_hit.is_some_and(|s: &EmulatedString| s.decoder_address != 0),
        "{tag}: the recovered UTF-16 string must carry its decoder call-site address"
    );

    let wide_misread: String = PLAINTEXT_DEC.chars().step_by(2).collect();
    assert!(
        !recovered
            .iter()
            .any(|s: &EmulatedString| s.value == wide_misread),
        "{tag}: an ASCII-only decoder must NOT be misread as UTF-16 (the every-other-char artifact \
         {wide_misread:?} must be absent). harvested {got:?}"
    );

    assert!(
        !recovered
            .iter()
            .any(|s: &EmulatedString| s.value == COPY_SRC),
        "{tag}: precision: a pure byte-copy of a pre-existing static string must NOT be reported as \
         a decoded string (static dedup). harvested {got:?}"
    );
    assert!(
        !recovered
            .iter()
            .any(|s: &EmulatedString| s.value == GEN_FILL),
        "{tag}: precision: a runtime-built printable string with no ciphertext input is not a \
         decoder and must not be harvested. harvested {got:?}"
    );

    println!(
        "{tag}: recall+precision PASSED; harvested {} strings",
        got.len()
    );
}

#[test]
#[cfg(windows)]
fn gcc_dll_decoders_recovered_from_written_memory() {
    let gcc_override: Option<OsString> = std::env::var_os(TEST_GCC_ENV);
    assert!(
        gcc_override.is_some() || has_tool("gcc"),
        "gcc is required on PATH (or named by {TEST_GCC_ENV}); every Windows CI runner provisions MinGW gcc"
    );
    let gcc: OsString = gcc_override.unwrap_or_else(|| OsString::from("gcc"));
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("corpus.c");
    std::fs::write(&src_path, corpus_source().as_bytes()).expect("write corpus.c");
    let dll: PathBuf = dir.join("corpus_gcc.dll");
    let build: std::process::Output = Command::new(&gcc)
        .args([
            "-O0",
            "-fno-stack-protector",
            "-fno-builtin",
            "-shared",
            "-nostdlib",
            "-Wl,--image-base,0x10000000",
            "-o",
        ])
        .arg(&dll)
        .arg(&src_path)
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "host gcc toolchain could not start before Disrobe recovery ran: compiler \
                 {gcc:?}; output {dll:?}; error {error}"
            )
        });
    assert!(
        build.status.success(),
        "host gcc toolchain failed before Disrobe recovery ran: compiler {gcc:?}; status {}; \
         output {dll:?}; stdout: {}; stderr: {}",
        build.status,
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    let image: Vec<u8> = std::fs::read(&dll).expect("read corpus_gcc.dll");
    assert_recovery(&image, "gcc-dll");
}

#[test]
#[cfg(windows)]
fn gcc_failure_is_identified_as_host_toolchain_error() {
    let current_exe: PathBuf = std::env::current_exe().expect("resolve current test executable");
    let child: std::process::Output = Command::new(&current_exe)
        .args([
            "--exact",
            "emu_strings_memdelta_oracle::gcc_dll_decoders_recovered_from_written_memory",
            "--nocapture",
        ])
        .env(TEST_GCC_ENV, &current_exe)
        .output()
        .expect("run gcc oracle with failing compiler process");
    let diagnostic: String = format!(
        "{}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );

    assert!(
        !child.status.success(),
        "injected compiler unexpectedly passed"
    );
    assert!(
        diagnostic.contains("host gcc toolchain failed before Disrobe recovery ran"),
        "toolchain failure was not classified: {diagnostic}"
    );
}

#[test]
fn sysv_clang_decoders_recovered_from_written_memory() {
    assert!(
        has_tool("clang"),
        "clang is required on PATH; every CI test runner provisions it"
    );
    let scratch: ScratchDir = scratch_dir();
    let dir: PathBuf = scratch.path().to_path_buf();
    let src_path: PathBuf = dir.join("corpus_sysv.c");
    std::fs::write(&src_path, corpus_source().as_bytes()).expect("write corpus_sysv.c");
    let so: PathBuf = dir.join("corpus_clang.so");
    let build: std::process::Output = Command::new("clang")
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-O0",
            "-fno-stack-protector",
            "-fno-builtin",
            "-fcf-protection=none",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
            "-o",
        ])
        .arg(&so)
        .arg(&src_path)
        .output()
        .expect("invoke clang");
    if !build.status.success() {
        prerequisite::toolchain_capability_absent(
            "the SysV clang string-decoder oracle",
            &format!(
                "clang cannot link a linux/SysV shared object with lld on this host: {}",
                String::from_utf8_lossy(&build.stderr)
            ),
        );
        return;
    }
    let image: Vec<u8> = std::fs::read(&so).expect("read corpus_clang.so");
    assert_recovery(&image, "clang-sysv-so");
}
