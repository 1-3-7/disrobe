#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_native::{LeafRecovery, PseudoAbi, recover_leaf_function_abi};
use disrobe_typerec::{CIntType, TypedFunction, recover_function};

use crate::common::{COMPILE_TIMEOUT, MAX_CAPTURE_BYTES, require_cc, scratch_dir};

const RUN_TIMEOUT: Duration = Duration::from_mins(1);

const SIGNED_AND_UNKNOWN: [u8; 29] = [
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b, 0x45, 0xf8,
    0x48, 0xc1, 0xf8, 0x03, 0x48, 0x8b, 0x4d, 0xf0, 0x48, 0x01, 0xc8, 0x5d, 0xc3,
];

const ADDRESS_TAKEN: [u8; 18] = [
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x45, 0xf8, 0x48, 0x89, 0x4d, 0xf8, 0x48, 0x8b, 0x45, 0xf8,
    0x5d, 0xc3,
];

#[test]
fn signed_slot_is_typed_and_unknown_sign_slot_falls_back_to_word() {
    let base: u64 = 0x1000;
    let typed: TypedFunction = recover_function(&SIGNED_AND_UNKNOWN, base);
    assert_eq!(
        typed.typed_slot(-8),
        Some(CIntType::I64),
        "the arithmetic shift proves slot -8 is a signed qword; typerec must surface it",
    );
    assert_eq!(
        typed.typed_slot(-16),
        None,
        "slot -16 only feeds a sign-agnostic add; sign is undetermined and must abstain",
    );

    let rec: LeafRecovery = recover_leaf_function_abi(&SIGNED_AND_UNKNOWN, base, PseudoAbi::SysV)
        .expect("the rbp-frame spill/shift/add leaf must lift");
    let source: &str = &rec.source;
    assert!(
        source.contains("(struct __attribute__((packed, may_alias)) { int64_t value; }*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-8LL)"),
        "the soundly-typed signed slot must render with its recovered int64_t type: {source}",
    );
    assert!(
        source.contains("(struct __attribute__((packed, may_alias)) { uint64_t value; }*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-16LL)"),
        "the undetermined-sign slot must keep the uint64_t word type: {source}",
    );
    assert!(
        !source.contains("(struct __attribute__((packed, may_alias)) { int64_t value; }*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-16LL)"),
        "the undetermined-sign slot must never be emitted as a signed type: {source}",
    );
}

fn address_taken_harness(source: &str) -> String {
    let code: String = ADDRESS_TAKEN
        .iter()
        .map(|byte: &u8| format!("{byte:#04x}"))
        .collect::<Vec<String>>()
        .join(", ");
    let renamed: String = source.replacen("recovered(", "rec_fn(", 1);
    format!(
        r#"#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
__declspec(dllimport) void *__stdcall VirtualAlloc(void *, size_t, unsigned long, unsigned long);
static void *executable(size_t size) {{ return VirtualAlloc(0, size, 0x3000ul, 0x40ul); }}
#else
#include <sys/mman.h>
static void *executable(size_t size) {{
    void *at = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return at == MAP_FAILED ? 0 : at;
}}
#endif
{renamed}
static const unsigned char code[] = {{ {code} }};
typedef uint64_t (__attribute__((sysv_abi)) *original_fn)(uint64_t, uint64_t, uint64_t, uint64_t);
int main(void) {{
    unsigned char *page = executable(4096);
    if (!page) return 2;
    memcpy(page, code, sizeof code);
    original_fn original = (original_fn)(void *)page;
    uint64_t state = 0x9e3779b97f4a7c15ULL;
    unsigned equal = 0, differ = 0;
    for (int i = 0; i < 1000; i++) {{
        uint64_t v[4];
        for (int k = 0; k < 4; k++) {{ state ^= state << 13; state ^= state >> 7; state ^= state << 17; v[k] = state; }}
        uint64_t a = original(v[0], v[1], v[2], v[3]);
        uint64_t b = rec_fn(v[0], v[1], v[2], v[3]);
        if (a == b) equal++; else differ++;
    }}
    printf("result equal=%u differ=%u\n", equal, differ);
    return 0;
}}
"#
    )
}

fn address_taken_grade(source: &str, tag: &str) -> (u32, u32) {
    let compiler: String = require_cc();
    let scratch: ScratchDir = scratch_dir("disrobe-native-typed-locals-address-taken");
    let c_path: PathBuf = scratch.path().join(format!("{tag}.c"));
    let exe_path: PathBuf = scratch.path().join(if cfg!(windows) {
        format!("{tag}.exe")
    } else {
        tag.to_owned()
    });
    std::fs::write(&c_path, address_taken_harness(source)).expect("write the harness");
    let args: Vec<OsString> = vec![
        "-O1".into(),
        "-w".into(),
        "-o".into(),
        exe_path.clone().into_os_string(),
        c_path.into_os_string(),
    ];
    let compiled: CapturedOutput = run_captured(
        Path::new(&compiler),
        &args,
        COMPILE_TIMEOUT,
        MAX_CAPTURE_BYTES,
    )
    .expect("spawn the compiler")
    .expect("the compiler finishes within its timeout");
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "{tag}: the harness must compile: {}\n{source}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let no_args: [&str; 0] = [];
    let ran: CapturedOutput = run_captured(&exe_path, &no_args, RUN_TIMEOUT, MAX_CAPTURE_BYTES)
        .expect("spawn the harness")
        .expect("the harness finishes within its timeout");
    let stdout: String = String::from_utf8_lossy(&ran.stdout).into_owned();
    assert_eq!(
        ran.exit_code,
        Some(0),
        "{tag}: the harness failed: {stdout}"
    );
    let line: &str = stdout
        .lines()
        .find(|line: &&str| line.starts_with("result "))
        .unwrap_or_else(|| panic!("{tag}: no result line: {stdout}"));
    let field = |key: &str| -> u32 {
        line.split_whitespace()
            .find_map(|item: &str| item.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
            .unwrap_or_else(|| panic!("{tag}: missing {key} in {line}"))
    };
    (field("equal"), field("differ"))
}

#[test]
fn address_taken_slot_is_never_typed() {
    let typed: TypedFunction = recover_function(&ADDRESS_TAKEN, 0x2000);
    assert_eq!(
        typed.typed_slot(-8),
        None,
        "an address-taken slot escapes the single-object model and must not be typed",
    );
    assert!(
        typed.typed_slots().is_empty(),
        "no slot in the escaped function is soundly typeable",
    );
    match recover_leaf_function_abi(&ADDRESS_TAKEN, 0x2000, PseudoAbi::SysV) {
        Ok(recovery) => assert_address_taken_recovery_is_sound(&recovery),
        Err(error) => {
            let reason: String = error.to_string();
            assert!(
                reason.contains("address") || reason.contains("escape"),
                "a refusal must name the escaping slot address: {reason}"
            );
        }
    }
}

fn assert_address_taken_recovery_is_sound(recovery: &LeafRecovery) {
    let source: &str = &recovery.source;
    assert!(
        !source.contains("{ int64_t value; }*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-8LL)"),
        "the escaped slot must never be emitted as a typed local: {source}",
    );
    assert_eq!(
        address_taken_grade(source, "address_taken_recovered"),
        (1000, 0),
        "the recovered C must behave like the authored machine code on every input: {source}",
    );
    let mutated: String = source.replacen("    return ", "    return 1 + ", 1);
    assert_ne!(
        mutated, source,
        "the mutation control must change the source"
    );
    let (_, differ): (u32, u32) = address_taken_grade(&mutated, "address_taken_mutated");
    assert!(
        differ > 0,
        "the mutation control must turn the grade red: {mutated}"
    );
}
