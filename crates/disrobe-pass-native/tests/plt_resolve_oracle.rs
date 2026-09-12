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
use object::{
    Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, RelocationFlags, RelocationTarget,
};

const PLT_C: &str = r#"
extern int ext_printf(const char*);
extern long ext_write(int, const void*, unsigned long);
extern void *ext_malloc(unsigned long);

__attribute__((noinline)) int leaf(int x) { return x * 3 + 1; }

__attribute__((noinline, visibility("hidden"))) int caller(int x) {
    ext_printf("hi");
    ext_write(1, "ab", 2);
    void *p = ext_malloc(16);
    int y = leaf(x);
    return p ? y : x;
}

__attribute__((noinline)) int tailer(int x) {
    return caller(x + 1);
}

__attribute__((noinline)) int tail_import(const char *text) {
    return ext_printf(text);
}
"#;

fn clang_lld_available() -> bool {
    let clang: bool = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success());
    let linker: &str = if cfg!(windows) {
        "ld.lld.exe"
    } else {
        "ld.lld"
    };
    let lld: bool = Command::new(linker)
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
        .arg("-fplt")
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
    let symbols: object::SymbolTable<'_, '_> =
        parsed.dynamic_symbol_table().expect("ELF dynamic symbols");
    for (offset, reloc) in parsed
        .dynamic_relocations()
        .expect("ELF dynamic relocations")
    {
        if reloc.flags()
            != (RelocationFlags::Elf {
                r_type: object::elf::R_X86_64_JUMP_SLOT,
            })
        {
            continue;
        }
        let RelocationTarget::Symbol(idx) = reloc.target() else {
            continue;
        };
        let Ok(symbol) = symbols.symbol_by_index(idx) else {
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
        if matches!(name, "leaf" | "caller" | "tailer" | "tail_import") {
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
    assert!(
        clang_lld_available(),
        "clang+lld are required to link the real ELF PLT fixture"
    );
    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let src: PathBuf = dir.path().join("plt.c");
    std::fs::write(&src, PLT_C).expect("write C");
    let so: PathBuf = dir.path().join("plt.so");
    assert!(
        build_so(&src, &so, false),
        "clang must link the PLT fixture"
    );
    let bytes: Vec<u8> = std::fs::read(&so).expect("read so");
    let payload: disrobe_ir::payload::DisasmPayload =
        disrobe_pass_native::build_disasm_payload(&bytes).expect("lift real ELF fixture");
    let imports: Vec<ImportStub> = resolve_elf_plt_imports(&bytes);
    assert!(
        !imports.is_empty(),
        "real ELF fixture must have import stubs"
    );
    for import in &imports {
        assert!(
            payload.symbol_table.iter().any(|symbol| {
                (symbol.address, symbol.name.as_str())
                    == (import.stub_address, import.name.as_str())
                    && symbol.kind == disrobe_ir::payload::DisasmSymbolKind::Import
            }),
            "disassembly must preserve import {} at {:#x}",
            import.name,
            import.stub_address
        );
    }
    assert!(
        bytes.get(..4) == Some(&[0x7F, b'E', b'L', b'F']),
        "the PLT fixture linker must produce an ELF"
    );

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
    assert!(
        clang_lld_available(),
        "clang+lld are required to link the real ELF PLT fixture"
    );
    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let src: PathBuf = dir.path().join("plt.c");
    std::fs::write(&src, PLT_C).expect("write C");

    let unstripped: PathBuf = dir.path().join("plt.so");
    let stripped: PathBuf = dir.path().join("plt.stripped.so");
    assert!(
        build_so(&src, &unstripped, false) && build_so(&src, &stripped, true),
        "clang must link both real ELF PLT fixtures"
    );
    let un_bytes: Vec<u8> = std::fs::read(&unstripped).expect("read unstripped");
    let st_bytes: Vec<u8> = std::fs::read(&stripped).expect("read stripped");
    assert!(
        un_bytes.get(..4) == Some(&[0x7F, b'E', b'L', b'F']),
        "the PLT fixture linker must produce an ELF"
    );

    let truth_starts: BTreeSet<u64> = ground_truth_func_starts(&un_bytes);
    assert!(
        truth_starts.len() >= 2,
        "ground-truth symtab must carry the helper functions: {truth_starts:?}"
    );

    let stubs: Vec<ImportStub> = resolve_elf_plt_imports(&un_bytes);
    let (text_addr, text): (u64, Vec<u8>) = text_window(&un_bytes);
    let caller_address: u64 = object::File::parse(&*un_bytes)
        .expect("parse unstripped ELF")
        .symbols()
        .find(|symbol| {
            !symbol.is_undefined() && symbol.name().is_ok_and(|name: &str| name == "caller")
        })
        .expect("reference ELF defines caller")
        .address();

    let tails: Vec<TailCall> = classify_tail_calls(64, text_addr, &text, &truth_starts, &stubs);
    assert!(
        tails.iter().any(|tail: &TailCall| {
            tail.kind == TailCallKind::ImportThunk && tail.name.as_deref() == Some("ext_printf")
        }),
        "the external tail call must retain its PLT import identity: {tails:?}"
    );
    assert!(
        tails
            .iter()
            .any(|t: &TailCall| t.kind == TailCallKind::FunctionStart && t.target == caller_address),
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
