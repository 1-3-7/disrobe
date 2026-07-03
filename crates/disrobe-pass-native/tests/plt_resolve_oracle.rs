#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::{
    ImportStub, TailCall, TailCallKind, classify_tail_calls, resolve_elf_plt_imports,
    resolve_pe_iat_imports,
};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

const PLT_C: &str = r#"
extern int ext_printf(const char*);
extern long ext_write(int, const void*, unsigned long);
extern void *ext_malloc(unsigned long);

__attribute__((noinline)) int leaf(int x) { return x * 3 + 1; }

__attribute__((noinline)) int caller(int x) {
    ext_printf("hi");
    ext_write(1, "ab", 2);
    void *p = ext_malloc(16);
    int y = leaf(x);
    return p ? y : x;
}

__attribute__((noinline)) int tailer(int x) {
    return caller(x + 1);
}
"#;

fn clang_lld_available() -> bool {
    let clang: bool = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success());
    let lld: bool = Command::new("ld.lld")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        || Command::new("lld")
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success());
    clang && lld
}

fn build_so(src: &Path, out: &Path, strip: bool) -> bool {
    let mut cmd: Command = Command::new("clang");
    cmd.arg("--target=x86_64-unknown-linux-gnu")
        .arg("-O1")
        .arg("-fuse-ld=lld")
        .arg("-shared")
        .arg("-nostdlib")
        .arg("-fPIC")
        .arg("-o")
        .arg(out)
        .arg(src);
    if strip {
        cmd.arg("-Wl,--strip-all");
    }
    cmd.output()
        .is_ok_and(|o: std::process::Output| o.status.success())
}

fn ground_truth_jump_slots(bytes: &[u8]) -> BTreeMap<u64, String> {
    let parsed: object::File<'_> = object::File::parse(bytes).expect("parse so");
    let mut out: BTreeMap<u64, String> = BTreeMap::new();
    for section in parsed.sections() {
        let name: &str = section.name().unwrap_or("");
        if name != ".rela.plt" && name != ".rel.plt" {
            continue;
        }
        for (offset, reloc) in section.relocations() {
            let RelocationTarget::Symbol(idx) = reloc.target() else {
                continue;
            };
            let Ok(symbol) = parsed.symbol_by_index(idx) else {
                continue;
            };
            let Ok(sym_name) = symbol.name() else {
                continue;
            };
            if sym_name.is_empty() {
                continue;
            }
            out.insert(offset, sym_name.to_owned());
        }
    }
    out
}

fn ground_truth_func_starts(bytes: &[u8]) -> BTreeSet<u64> {
    let parsed: object::File<'_> = object::File::parse(bytes).expect("parse so");
    let mut out: BTreeSet<u64> = BTreeSet::new();
    for sym in parsed.symbols() {
        if !matches!(sym.kind(), object::SymbolKind::Text) {
            continue;
        }
        if sym.address() == 0 || sym.is_undefined() {
            continue;
        }
        let Ok(name) = sym.name() else {
            continue;
        };
        if matches!(name, "leaf" | "caller" | "tailer") {
            out.insert(sym.address());
        }
    }
    out
}

fn text_window(bytes: &[u8]) -> (u64, Vec<u8>) {
    let parsed: object::File<'_> = object::File::parse(bytes).expect("parse so");
    let text: object::Section<'_, '_> = parsed
        .sections()
        .find(|s: &object::Section<'_, '_>| s.name().is_ok_and(|n: &str| n == ".text"))
        .expect(".text present");
    (text.address(), text.data().expect("text data").to_vec())
}

const REAL_PE64: &[u8] = include_bytes!("../../../corpus/native/formats/hello.pe64.exe");

#[test]
fn pe_iat_slots_resolve_to_import_directory_names() {
    let truth: BTreeSet<String> = {
        let parsed: object::File<'_> = object::File::parse(REAL_PE64).expect("parse pe");
        let table = parsed.imports().expect("imports");
        table
            .iter()
            .map(|i: &object::Import<'_>| String::from_utf8_lossy(i.name()).into_owned())
            .filter(|n: &String| !n.is_empty())
            .collect()
    };
    assert!(
        truth.len() >= 3,
        "a real PE must import several functions: {truth:?}"
    );

    let stubs: Vec<ImportStub> = resolve_pe_iat_imports(REAL_PE64);
    assert!(
        !stubs.is_empty(),
        "disrobe must map IAT slots to import names for a real PE"
    );

    let image_base: u64 = object::File::parse(REAL_PE64)
        .expect("parse")
        .relative_address_base();
    let image_end: u64 = image_base + REAL_PE64.len() as u64 * 4;
    let resolved: BTreeSet<String> = stubs.iter().map(|s: &ImportStub| s.name.clone()).collect();
    for stub in &stubs {
        assert!(
            stub.slot_address > image_base && stub.slot_address < image_end,
            "IAT slot {:#x} must sit inside the mapped image (base {:#x})",
            stub.slot_address,
            image_base
        );
    }
    let common: usize = truth.intersection(&resolved).count();
    assert!(
        common >= 3,
        "disrobe's IAT names must agree with the import directory parsed independently; \
         truth={truth:?} resolved={resolved:?}"
    );
}

#[test]
fn elf_plt_stubs_resolve_to_jmprel_symbol_names() {
    if !clang_lld_available() {
        println!("SKIP: clang+lld not on PATH; cannot link a real ELF with a PLT");
        return;
    }
    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let src: PathBuf = dir.path().join("plt.c");
    std::fs::write(&src, PLT_C).expect("write C");
    let so: PathBuf = dir.path().join("plt.so");
    if !build_so(&src, &so, false) {
        println!("SKIP: clang failed to link the shared object");
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&so).expect("read so");
    if bytes.get(..4) != Some(&[0x7F, b'E', b'L', b'F']) {
        println!("SKIP: linker produced no ELF");
        return;
    }

    let truth: BTreeMap<u64, String> = ground_truth_jump_slots(&bytes);
    assert!(
        truth.len() >= 3,
        "the JUMP_SLOT table must bind ext_printf/ext_write/ext_malloc: {truth:?}"
    );

    let stubs: Vec<ImportStub> = resolve_elf_plt_imports(&bytes);
    assert!(
        !stubs.is_empty(),
        "disrobe must decode .plt stubs and name them from JMPREL"
    );

    for stub in &stubs {
        let expected: &String = truth.get(&stub.slot_address).unwrap_or_else(|| {
            panic!(
                "stub at {:#x} points at GOT slot {:#x} which is not in the linker's JUMP_SLOT table {:?}",
                stub.stub_address, stub.slot_address, truth
            )
        });
        assert_eq!(
            &stub.name, expected,
            "stub {:#x} -> slot {:#x} must be named exactly as the linker's reloc symbol",
            stub.stub_address, stub.slot_address
        );
    }

    let resolved_names: BTreeSet<&str> =
        stubs.iter().map(|s: &ImportStub| s.name.as_str()).collect();
    for want in ["ext_printf", "ext_write", "ext_malloc"] {
        assert!(
            resolved_names.contains(want),
            "every imported call target must be resolved to its name; missing {want}: {resolved_names:?}"
        );
    }
}

#[test]
fn tail_call_to_plt_thunk_and_function_start_classified_on_real_elf() {
    if !clang_lld_available() {
        println!("SKIP: clang+lld not on PATH");
        return;
    }
    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let src: PathBuf = dir.path().join("plt.c");
    std::fs::write(&src, PLT_C).expect("write C");

    let unstripped: PathBuf = dir.path().join("plt.so");
    let stripped: PathBuf = dir.path().join("plt.stripped.so");
    if !build_so(&src, &unstripped, false) || !build_so(&src, &stripped, true) {
        println!("SKIP: link failed");
        return;
    }
    let un_bytes: Vec<u8> = std::fs::read(&unstripped).expect("read unstripped");
    let st_bytes: Vec<u8> = std::fs::read(&stripped).expect("read stripped");
    if un_bytes.get(..4) != Some(&[0x7F, b'E', b'L', b'F']) {
        println!("SKIP: no ELF");
        return;
    }

    let truth_starts: BTreeSet<u64> = ground_truth_func_starts(&un_bytes);
    assert!(
        truth_starts.len() >= 2,
        "ground-truth symtab must carry the helper functions: {truth_starts:?}"
    );

    let stubs: Vec<ImportStub> = resolve_elf_plt_imports(&un_bytes);
    let (text_addr, text): (u64, Vec<u8>) = text_window(&un_bytes);

    let tails: Vec<TailCall> = classify_tail_calls(64, text_addr, &text, &truth_starts, &stubs);
    assert!(
        tails
            .iter()
            .any(|t: &TailCall| t.kind == TailCallKind::FunctionStart),
        "tailer's `return caller(x+1)` lowers to a jmp to caller's start; that is a tail call: {tails:?}"
    );

    let stripped_tails: Vec<TailCall> = {
        let (st_text_addr, st_text): (u64, Vec<u8>) = text_window(&st_bytes);
        let st_stubs: Vec<ImportStub> = resolve_elf_plt_imports(&st_bytes);
        classify_tail_calls(64, st_text_addr, &st_text, &truth_starts, &st_stubs)
    };

    let un_targets: BTreeSet<u64> = tails.iter().map(|t: &TailCall| t.target).collect();
    let st_targets: BTreeSet<u64> = stripped_tails.iter().map(|t: &TailCall| t.target).collect();
    assert_eq!(
        un_targets, st_targets,
        "the recovered tail-call target set must be identical before and after stripping the symbol table"
    );
}
