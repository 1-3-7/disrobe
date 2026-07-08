#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::{EbpfRecovery, recover_ebpf_program};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

fn clang_supports_bpf(path: &Path) -> bool {
    let Ok(output) = Command::new(path).arg("-print-targets").output() else {
        return false;
    };
    output.status.success() && String::from_utf8_lossy(&output.stdout).contains("bpf")
}

fn find_bpf_clang() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = vec![PathBuf::from("clang")];
    if let Ok(program_files) = std::env::var("ProgramFiles") {
        candidates.push(
            PathBuf::from(program_files)
                .join("LLVM")
                .join("bin")
                .join("clang.exe"),
        );
    }
    candidates.push(PathBuf::from(r"C:\Program Files\LLVM\bin\clang.exe"));
    for minor in (13..=25).rev() {
        candidates.push(PathBuf::from(format!("clang-{minor}")));
        candidates.push(PathBuf::from(format!("/usr/lib/llvm-{minor}/bin/clang")));
    }
    candidates.push(PathBuf::from("/usr/bin/clang"));
    candidates
        .into_iter()
        .find(|c: &PathBuf| clang_supports_bpf(c))
}

fn compile_bpf(clang: &Path, dir: &Path, name: &str, opt: &str, source: &str) -> PathBuf {
    let c_path: PathBuf = dir.join(format!("{name}.c"));
    std::fs::write(&c_path, source).expect("write fixture source");
    let o_path: PathBuf = dir.join(format!("{name}.o"));
    let status = Command::new(clang)
        .args(["--target=bpf", opt, "-c"])
        .arg(&c_path)
        .arg("-o")
        .arg(&o_path)
        .status()
        .expect("invoke clang");
    assert!(status.success(), "clang --target=bpf failed for {name}");
    o_path
}

fn extract_text(o_path: &Path) -> Vec<u8> {
    let data: Vec<u8> = std::fs::read(o_path).expect("read compiled object");
    let file: object::File<'_> = object::File::parse(&*data).expect("parse elf object");
    let section = file
        .section_by_name(".text")
        .expect(".text section present");
    section.data().expect("read .text data").to_vec()
}

const FAKE_MAP_FD: u32 = 3;

fn extract_text_with_map_fd_relocation(o_path: &Path) -> Vec<u8> {
    let data: Vec<u8> = std::fs::read(o_path).expect("read compiled object");
    let file: object::File<'_> = object::File::parse(&*data).expect("parse elf object");
    let text_section = file
        .section_by_name(".text")
        .expect(".text section present");
    let mut text: Vec<u8> = text_section.data().expect("read .text data").to_vec();
    let maps_index: Option<object::SectionIndex> = file
        .section_by_name(".maps")
        .map(|s: object::Section<'_, '_>| s.index());
    for (offset, reloc) in text_section.relocations() {
        if let RelocationTarget::Symbol(sym_idx) = reloc.target() {
            let symbol = file.symbol_by_index(sym_idx).expect("resolve reloc symbol");
            if symbol.section_index() == maps_index && maps_index.is_some() {
                let slot: usize = offset as usize;
                text[slot + 1] = (text[slot + 1] & 0x0f) | (1u8 << 4);
                text[slot + 4..slot + 8].copy_from_slice(&FAKE_MAP_FD.to_le_bytes());
            }
        }
    }
    text
}

fn compile_host_and_run(
    clang: &Path,
    dir: &Path,
    name: &str,
    recovered_source: &str,
    harness: &str,
) -> Vec<i64> {
    let prog_c: PathBuf = dir.join(format!("{name}_prog.c"));
    std::fs::write(&prog_c, recovered_source).expect("write recovered source");
    let main_c: PathBuf = dir.join(format!("{name}_main.c"));
    std::fs::write(&main_c, harness).expect("write harness source");
    let exe: PathBuf = dir.join(format!("{name}_native.exe"));
    let status = Command::new(clang)
        .arg(&prog_c)
        .arg(&main_c)
        .arg("-O0")
        .arg("-o")
        .arg(&exe)
        .status()
        .expect("invoke host clang");
    assert!(status.success(), "native recompile failed for {name}");
    let output = Command::new(&exe).output().expect("run native harness");
    assert!(
        output.status.success(),
        "native harness exited nonzero for {name}"
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l: &&str| !l.trim().is_empty())
        .map(|l: &str| {
            l.trim()
                .parse::<i64>()
                .expect("parse native harness output")
        })
        .collect()
}

fn run_rbpf(bytecode: &[u8], mem: &mut [u8]) -> i64 {
    let vm = rbpf::EbpfVmRaw::new(Some(bytecode)).expect("construct rbpf vm");
    vm.execute_program(mem)
        .expect("interpret original bytecode") as i64
}

fn le_pair(a: i64, b: i64) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(16);
    out.extend_from_slice(&a.to_le_bytes());
    out.extend_from_slice(&b.to_le_bytes());
    out
}

fn le_single(a: i64) -> Vec<u8> {
    a.to_le_bytes().to_vec()
}

const ARITH_SRC: &str = r"
struct ctx { long a; long b; };
long prog(struct ctx *ctx) {
    long a = ctx->a;
    long b = ctx->b;
    long r = a + b;
    r = r * 3;
    return r;
}
";

const COND_SRC: &str = r"
struct ctx { long a; long b; };
long prog(struct ctx *ctx) {
    long a = ctx->a;
    long b = ctx->b;
    long r;
    if (a > b) {
        r = a - b;
    } else {
        r = b - a;
    }
    return r;
}
";

const LOOP_SRC: &str = r"
struct ctx { long n; };
long prog(struct ctx *ctx) {
    long n = ctx->n;
    long sum = 0;
    long i = 0;
    while (i < n) {
        sum += i;
        i += 1;
    }
    return sum;
}
";

const HELPER_SRC: &str = r"
static unsigned long (*bpf_get_prandom_u32)(void) = (void *) 7;
long prog(void *ctx) {
    unsigned long v = bpf_get_prandom_u32();
    return (long)(v + 1);
}
";

const MAPLOOKUP_SRC: &str = r#"
struct map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
};
struct map_def counters __attribute__((section(".maps"))) = {
    .type = 2,
    .key_size = 4,
    .value_size = 8,
    .max_entries = 1,
};
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
long prog(void *ctx) {
    unsigned int key = 0;
    long *value = bpf_map_lookup_elem(&counters, &key);
    if (value) {
        return *value;
    }
    return 0;
}
"#;

fn arith_harness() -> String {
    r#"
#include <stdint.h>
#include <stdio.h>
extern int64_t prog(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
int main(void) {
    long long pairs[5][2] = { {1,2}, {100,-5}, {0,0}, {-7,3}, {123456789LL,2} };
    for (int i = 0; i < 5; i++) {
        long long buf[2];
        buf[0] = pairs[i][0];
        buf[1] = pairs[i][1];
        int64_t r = prog((uint64_t)(uintptr_t)buf, 0, 0, 0, 0);
        printf("%lld\n", (long long)r);
    }
    return 0;
}
"#
    .to_owned()
}

fn cond_harness() -> String {
    r#"
#include <stdint.h>
#include <stdio.h>
extern int64_t prog(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
int main(void) {
    long long pairs[5][2] = { {1,2}, {100,-5}, {0,0}, {-7,3}, {50,50} };
    for (int i = 0; i < 5; i++) {
        long long buf[2];
        buf[0] = pairs[i][0];
        buf[1] = pairs[i][1];
        int64_t r = prog((uint64_t)(uintptr_t)buf, 0, 0, 0, 0);
        printf("%lld\n", (long long)r);
    }
    return 0;
}
"#
    .to_owned()
}

fn loop_harness() -> String {
    r#"
#include <stdint.h>
#include <stdio.h>
extern int64_t prog(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);
int main(void) {
    long long ns[4] = { 0, 1, 5, 1000 };
    for (int i = 0; i < 4; i++) {
        long long buf[1];
        buf[0] = ns[i];
        int64_t r = prog((uint64_t)(uintptr_t)buf, 0, 0, 0, 0);
        printf("%lld\n", (long long)r);
    }
    return 0;
}
"#
    .to_owned()
}

#[test]
fn ebpf_oracle_battery() {
    let Some(clang) = find_bpf_clang() else {
        eprintln!(
            "skipping ebpf oracle: no clang with a bpf target backend was found on this machine"
        );
        return;
    };
    let dir = tempfile::tempdir().expect("scratch dir");

    let arith_o: PathBuf = compile_bpf(&clang, dir.path(), "arith", "-O2", ARITH_SRC);
    let cond_o: PathBuf = compile_bpf(&clang, dir.path(), "cond", "-O0", COND_SRC);
    let loop_o: PathBuf = compile_bpf(&clang, dir.path(), "loop", "-O0", LOOP_SRC);
    let helper_o: PathBuf = compile_bpf(&clang, dir.path(), "helper", "-O2", HELPER_SRC);
    let maplookup_o: PathBuf = compile_bpf(&clang, dir.path(), "maplookup", "-O2", MAPLOOKUP_SRC);

    let arith_bytes: Vec<u8> = extract_text(&arith_o);
    let cond_bytes: Vec<u8> = extract_text(&cond_o);
    let loop_bytes: Vec<u8> = extract_text(&loop_o);
    let helper_bytes: Vec<u8> = extract_text(&helper_o);
    let maplookup_bytes: Vec<u8> = extract_text_with_map_fd_relocation(&maplookup_o);

    let arith_rec: EbpfRecovery =
        recover_ebpf_program(&arith_bytes, "prog").expect("arith recover");
    let cond_rec: EbpfRecovery = recover_ebpf_program(&cond_bytes, "prog").expect("cond recover");
    let loop_rec: EbpfRecovery = recover_ebpf_program(&loop_bytes, "prog").expect("loop recover");
    let helper_rec: EbpfRecovery =
        recover_ebpf_program(&helper_bytes, "prog").expect("helper recover");
    let maplookup_rec: EbpfRecovery =
        recover_ebpf_program(&maplookup_bytes, "prog").expect("maplookup recover");

    assert!(arith_rec.structured, "arith should structure cleanly");
    assert!(
        !arith_rec.source.contains("if ("),
        "arith recovers no control flow: {}",
        arith_rec.source
    );
    assert!(
        !arith_rec.source.contains("while ("),
        "arith recovers no loop: {}",
        arith_rec.source
    );
    assert!(arith_rec.unknown_opcodes.is_empty());

    assert!(
        cond_rec.structured,
        "cond should structure cleanly:\n{}",
        cond_rec.source
    );
    assert!(
        cond_rec.source.contains("if ("),
        "cond recovers an if: {}",
        cond_rec.source
    );
    assert!(
        cond_rec.source.contains("else"),
        "cond recovers an else arm: {}",
        cond_rec.source
    );
    assert!(
        !cond_rec.source.contains("while ("),
        "cond has no loop: {}",
        cond_rec.source
    );
    assert!(cond_rec.unknown_opcodes.is_empty());

    assert!(
        loop_rec.structured,
        "loop should structure cleanly:\n{}",
        loop_rec.source
    );
    assert!(
        loop_rec.source.contains("while ("),
        "loop recovers a loop: {}",
        loop_rec.source
    );
    assert!(loop_rec.unknown_opcodes.is_empty());

    assert!(
        helper_rec.source.contains("bpf_get_prandom_u32("),
        "helper call rendered by real name: {}",
        helper_rec.source
    );
    assert!(helper_rec.unresolved_helper_ids.is_empty());
    assert!(helper_rec.unknown_opcodes.is_empty());

    assert!(
        maplookup_rec.source.contains("bpf_map_lookup_elem("),
        "map lookup helper rendered by real name: {}",
        maplookup_rec.source
    );
    assert!(
        maplookup_rec
            .source
            .contains(&format!("map_fd_{FAKE_MAP_FD}")),
        "map fd rendered as a typed handle: {}",
        maplookup_rec.source
    );
    assert_eq!(maplookup_rec.map_fds, vec![FAKE_MAP_FD]);
    assert!(maplookup_rec.unknown_opcodes.is_empty());

    let arith_inputs: [(i64, i64); 5] = [(1, 2), (100, -5), (0, 0), (-7, 3), (123_456_789, 2)];
    let arith_expected: Vec<i64> = arith_inputs
        .iter()
        .map(|&(a, b): &(i64, i64)| run_rbpf(&arith_bytes, &mut le_pair(a, b)))
        .collect();
    let arith_native: Vec<i64> = compile_host_and_run(
        &clang,
        dir.path(),
        "arith",
        &arith_rec.source,
        &arith_harness(),
    );
    assert_eq!(
        arith_expected, arith_native,
        "arithmetic differential execution must match the interpreted original bytecode"
    );

    let cond_inputs: [(i64, i64); 5] = [(1, 2), (100, -5), (0, 0), (-7, 3), (50, 50)];
    let cond_expected: Vec<i64> = cond_inputs
        .iter()
        .map(|&(a, b): &(i64, i64)| run_rbpf(&cond_bytes, &mut le_pair(a, b)))
        .collect();
    let cond_native: Vec<i64> = compile_host_and_run(
        &clang,
        dir.path(),
        "cond",
        &cond_rec.source,
        &cond_harness(),
    );
    assert_eq!(
        cond_expected, cond_native,
        "conditional differential execution must match the interpreted original bytecode"
    );

    let loop_inputs: [i64; 4] = [0, 1, 5, 1000];
    let loop_expected: Vec<i64> = loop_inputs
        .iter()
        .map(|&n: &i64| run_rbpf(&loop_bytes, &mut le_single(n)))
        .collect();
    let loop_native: Vec<i64> = compile_host_and_run(
        &clang,
        dir.path(),
        "loop",
        &loop_rec.source,
        &loop_harness(),
    );
    assert_eq!(
        loop_expected, loop_native,
        "bounded-loop differential execution must match the interpreted original bytecode"
    );
}
