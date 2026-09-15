#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_native::{ApiHashHit, HashFamily, resolve_imports_by_hash};

const REFERENCE_C: &str = r#"
#include <stdio.h>
#include <stdint.h>

static uint32_t ror(uint32_t v, uint32_t n) { return (v >> n) | (v << (32 - n)); }
static uint32_t rol(uint32_t v, uint32_t n) { return (v << n) | (v >> (32 - n)); }

static uint32_t ror13_add(const char *s) {
    uint32_t h = 0;
    for (; *s; ++s) h = ror(h, 13) + (uint8_t)*s;
    return h;
}
static uint32_t ror7_add(const char *s) {
    uint32_t h = 0;
    for (; *s; ++s) h = ror(h, 7) + (uint8_t)*s;
    return h;
}
static uint32_t rol5_add(const char *s) {
    uint32_t h = 0;
    for (; *s; ++s) h = rol(h, 5) + (uint8_t)*s;
    return h;
}
static uint32_t djb2(const char *s) {
    uint32_t h = 5381;
    for (; *s; ++s) h = h * 33 + (uint8_t)*s;
    return h;
}
static uint32_t sdbm(const char *s) {
    uint32_t h = 0;
    for (; *s; ++s) h = (uint8_t)*s + (h << 6) + (h << 16) - h;
    return h;
}
static uint32_t crc32_hash(const char *s) {
    uint32_t h = 0xFFFFFFFFu;
    for (; *s; ++s) {
        h ^= (uint8_t)*s;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = -(h & 1u);
            h = (h >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~h;
}
static uint32_t fnv1a(const char *s) {
    uint32_t h = 0x811C9DC5u;
    for (; *s; ++s) {
        h ^= (uint8_t)*s;
        h *= 0x01000193u;
    }
    return h;
}

static const char *NAMES[] = {
    "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "CreateThread",
    "WriteProcessMemory", "NtAllocateVirtualMemory", "connect", "InternetOpenA"
};

int main(void) {
    for (unsigned i = 0; i < sizeof(NAMES)/sizeof(NAMES[0]); ++i) {
        const char *n = NAMES[i];
        printf("%s %08x %08x %08x %08x %08x %08x %08x\n", n,
            ror13_add(n), ror7_add(n), rol5_add(n),
            djb2(n), sdbm(n), crc32_hash(n), fnv1a(n));
    }
    return 0;
}
"#;

fn gcc_available() -> bool {
    Command::new("gcc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

#[test]
fn rust_hashes_match_an_independent_c_reference_compiled_by_gcc() {
    if !gcc_available() {
        println!("SKIP: gcc not on PATH; cannot grade against an independent C reference");
        return;
    }
    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let src: PathBuf = dir.path().join("ref.c");
    let exe: PathBuf = dir.path().join("ref.exe");
    std::fs::write(&src, REFERENCE_C).expect("write reference C");

    let build: std::process::Output = Command::new("gcc")
        .arg("-O2")
        .arg("-o")
        .arg(&exe)
        .arg(&src)
        .output()
        .expect("invoke gcc");
    assert!(
        build.status.success(),
        "gcc must compile the reference: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run: std::process::Output = Command::new(&exe).output().expect("run reference");
    assert!(run.status.success(), "reference binary must run");
    let stdout: String = String::from_utf8_lossy(&run.stdout).into_owned();

    let families: [HashFamily; 7] = [
        HashFamily::Ror13Add,
        HashFamily::Ror7Add,
        HashFamily::Rol5Add,
        HashFamily::Djb2,
        HashFamily::Sdbm,
        HashFamily::Crc32,
        HashFamily::Fnv1a32,
    ];

    let mut lines: usize = 0;
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            1 + families.len(),
            "each reference line is name + 7 hashes: {line}"
        );
        let name: &str = fields[0];
        for (index, family) in families.iter().copied().enumerate() {
            let reference: u32 =
                u32::from_str_radix(fields[1 + index], 16).expect("hex hash from reference");
            let ours: u32 = family.hash(name.as_bytes(), false);
            assert_eq!(
                ours,
                reference,
                "{} hash of {name}: disrobe 0x{ours:08x} != gcc-C reference 0x{reference:08x}",
                family.label()
            );
        }
        lines += 1;
    }
    assert_eq!(lines, 8, "all eight reference names must be graded");
}

#[test]
fn resolver_recovers_names_from_a_gcc_compiled_peb_walk_resolver() {
    if !gcc_available() {
        println!("SKIP: gcc not on PATH");
        return;
    }
    let target: u32 = HashFamily::Ror13Add.hash(b"LoadLibraryA", false);
    let resolver_c: String = format!(
        r#"
#include <stdint.h>
static uint32_t ror(uint32_t v, uint32_t n) {{ return (v >> n) | (v << (32 - n)); }}
__attribute__((noinline))
int resolve_one(const char *name) {{
    uint32_t h = 0;
    for (const char *s = name; *s; ++s) h = ror(h, 13) + (uint8_t)*s;
    if (h == 0x{target:08x}u) return 1;
    return 0;
}}
int main(void) {{ return resolve_one("x"); }}
"#
    );

    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let src: PathBuf = dir.path().join("resolver.c");
    let obj: PathBuf = dir.path().join("resolver.o");
    std::fs::write(&src, &resolver_c).expect("write resolver C");

    let build: std::process::Output = Command::new("gcc")
        .arg("-O1")
        .arg("-c")
        .arg("-o")
        .arg(&obj)
        .arg(&src)
        .output()
        .expect("invoke gcc");
    assert!(
        build.status.success(),
        "gcc must compile the resolver object: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let object_bytes: Vec<u8> = std::fs::read(&obj).expect("read resolver object");
    let Some(text): Option<Vec<u8>> = extract_text_section(&object_bytes) else {
        eprintln!(
            "skipping resolver_recovers_names_from_a_gcc_compiled_peb_walk_resolver: \
             object is not an ELF with a .text section (e.g. a macos Mach-O object)"
        );
        return;
    };

    let hits: Vec<ApiHashHit> = resolve_imports_by_hash(64, 0, &text);
    assert!(
        hits.iter().any(|h: &ApiHashHit| {
            h.family == HashFamily::Ror13Add
                && h.hash == target
                && h.resolved_name.as_deref() == Some("LoadLibraryA")
        }),
        "the ror13(LoadLibraryA) constant the compiler embedded as a cmp immediate must be \
         harvested and reversed back to the API name: target=0x{target:08x} hits={hits:?}"
    );
}

fn extract_text_section(object: &[u8]) -> Option<Vec<u8>> {
    use object::{Object, ObjectSection};
    let parsed: object::File<'_> = object::File::parse(object).ok()?;
    for section in parsed.sections() {
        let name: &str = section.name().unwrap_or("");
        if (name == ".text" || name == "text")
            && let Ok(data) = section.data()
            && !data.is_empty()
        {
            return Some(data.to_vec());
        }
    }
    None
}
