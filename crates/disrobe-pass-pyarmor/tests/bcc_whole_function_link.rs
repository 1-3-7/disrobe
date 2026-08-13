#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_pyarmor::{
    BccArch, FunctionNameSource, PseudoCFunction, UnpackOptions, lift_bcc_code_region,
    lift_bcc_native, unpack_wrapper_text_with_options,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

const SIBLING_SOURCE: &str = "static long long sib_callee(long long a, long long b) { return a * 3 + b; }\n\
static long long sib_caller(long long a, long long b) { return sib_callee(a, b) + 7; }\n\
long long sib_entry(long long a, long long b) { return sib_caller(a, b); }\n";

const ABSOLUTE_COMPILER_PROBES: &[&str] = &[
    "C:/msys64/ucrt64/bin/gcc.exe",
    "C:/msys64/mingw64/bin/gcc.exe",
    "C:/Program Files/LLVM/bin/clang.exe",
    "/usr/bin/gcc",
    "/usr/bin/clang",
    "/usr/bin/cc",
];

fn compiler() -> String {
    for candidate in ["gcc", "clang", "cc"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|out: std::process::Output| out.status.success())
        {
            return candidate.to_owned();
        }
    }
    for candidate in ABSOLUTE_COMPILER_PROBES {
        if Path::new(candidate).is_file() {
            return (*candidate).to_owned();
        }
    }
    panic!(
        "no C compiler resolved on PATH (gcc/clang/cc) or at {ABSOLUTE_COMPILER_PROBES:?}; this grade needs a real compiler as its reference and must not be skipped"
    );
}

const fn host_arch() -> BccArch {
    if cfg!(windows) {
        BccArch::WinX64
    } else {
        BccArch::LinuxX64
    }
}

fn scratch() -> ScratchDir {
    ScratchDir::create("pyarmor-bcc-sibling").expect("scratch dir")
}

fn compile_siblings(cc: &str, dir: &Path) -> Vec<u8> {
    let source: PathBuf = dir.join("siblings.c");
    std::fs::write(&source, SIBLING_SOURCE.as_bytes()).expect("write siblings.c");
    let object: PathBuf = dir.join("siblings.o");
    let out: std::process::Output = Command::new(cc)
        .args(["-O1", "-fno-inline", "-fno-stack-protector", "-c", "-o"])
        .arg(&object)
        .arg(&source)
        .output()
        .expect("invoke the reference compiler");
    assert!(
        out.status.success(),
        "reference compile failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&object).expect("read siblings.o")
}

fn text_section(object_bytes: &[u8]) -> (u64, Vec<u8>) {
    let file: object::File<'_> = object::File::parse(object_bytes).expect("parse object");
    let section: object::Section<'_, '_> = file
        .sections()
        .find(|s: &object::Section<'_, '_>| s.kind() == object::SectionKind::Text)
        .expect("the reference object carries a text section");
    let data: &[u8] = section.data().expect("text data");
    (section.address(), data.to_vec())
}

fn symbol_address(object_bytes: &[u8], name: &str) -> u64 {
    let file: object::File<'_> = object::File::parse(object_bytes).expect("parse object");
    let candidates: [String; 2] = [name.to_owned(), format!("_{name}")];
    let symbol: object::Symbol<'_, '_> = file
        .symbols()
        .find(|s: &object::Symbol<'_, '_>| {
            s.name()
                .is_ok_and(|n: &str| candidates.iter().any(|c: &String| c == n))
        })
        .unwrap_or_else(|| panic!("the reference object must name {name} in its symbol table"));
    symbol.address()
}

fn find_function(functions: &[PseudoCFunction], entry_va: u64) -> &PseudoCFunction {
    functions
        .iter()
        .find(|f: &&PseudoCFunction| f.id.entry_va == entry_va)
        .unwrap_or_else(|| {
            panic!(
                "no lifted function at {entry_va:#x}; lifted entries are {:?}",
                functions
                    .iter()
                    .map(|f: &PseudoCFunction| f.id.entry_va)
                    .collect::<Vec<u64>>()
            )
        })
}

fn declared_parameters(pseudo_c: &str, callee: &str) -> Vec<String> {
    let needle: String = format!("{callee}(");
    let line: &str = pseudo_c
        .lines()
        .find(|l: &&str| l.trim_start().starts_with("extern") && l.contains(needle.as_str()))
        .unwrap_or_else(|| panic!("no extern declaration of {callee} in:\n{pseudo_c}"));
    parameter_list(line, &needle)
}

fn call_arguments(pseudo_c: &str, callee: &str) -> Vec<String> {
    let needle: String = format!("{callee}(");
    let line: &str = pseudo_c
        .lines()
        .find(|l: &&str| !l.trim_start().starts_with("extern") && l.contains(needle.as_str()))
        .unwrap_or_else(|| panic!("no call site for {callee} in:\n{pseudo_c}"));
    parameter_list(line, &needle)
}

fn parameter_list(line: &str, needle: &str) -> Vec<String> {
    let start: usize = line.find(needle).expect("needle present") + needle.len();
    let rest: &str = line.get(start..).expect("text after the open paren");
    let close: usize = rest.find(')').expect("a closing paren on the same line");
    let inside: &str = rest.get(..close).expect("argument text").trim();
    if inside.is_empty() || inside == "void" {
        return Vec::new();
    }
    inside
        .split(',')
        .map(|part: &str| part.trim().to_owned())
        .collect()
}

fn definition_body(function: &PseudoCFunction) -> String {
    function
        .pseudo_c
        .lines()
        .filter(|l: &&str| !l.trim_start().starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn a_sibling_call_recovers_the_callee_name_and_its_real_arity() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!(
            "skipping: the reference compiler on this host emits non-x86-64 code and the BCC lift models x86-64 only"
        );
        return;
    }
    let cc: String = compiler();
    let holder: ScratchDir = scratch();
    let object_bytes: Vec<u8> = compile_siblings(&cc, holder.path());
    let (base, code): (u64, Vec<u8>) = text_section(&object_bytes);
    let callee_va: u64 = symbol_address(&object_bytes, "sib_callee");
    let caller_va: u64 = symbol_address(&object_bytes, "sib_caller");

    let functions: Vec<PseudoCFunction> = lift_bcc_code_region(&code, base, host_arch());
    let callee: &PseudoCFunction = find_function(&functions, callee_va);
    let caller: &PseudoCFunction = find_function(&functions, caller_va);

    assert!(
        callee.modeled,
        "the leaf callee must lift; note {:?}",
        callee.note
    );
    assert!(
        caller.modeled,
        "the calling sibling must lift; note {:?}",
        caller.note
    );
    assert_eq!(
        callee.parameter_count, 2,
        "the authored callee takes two parameters"
    );
    assert_eq!(
        caller.resolved_callees,
        vec![callee.id.name.clone()],
        "the carved caller must resolve its sibling by name"
    );

    let declared: Vec<String> = declared_parameters(&caller.pseudo_c, &callee.id.name);
    assert_eq!(
        declared.len(),
        2,
        "the sibling is declared with the two parameters the authored source gives it, not the whole ABI argument bank: {declared:?}\n{}",
        caller.pseudo_c
    );
    let passed: Vec<String> = call_arguments(&caller.pseudo_c, &callee.id.name);
    assert_eq!(
        passed.len(),
        2,
        "the call site passes exactly the sibling's arguments: {passed:?}\n{}",
        caller.pseudo_c
    );
    assert_eq!(
        caller.parameter_count, 2,
        "resolving the sibling narrows the caller's own signature to the authored two parameters"
    );
    println!(
        "sibling link: {} calls {} with {}/{} arguments, caller arity {}",
        caller.id.name,
        callee.id.name,
        passed.len(),
        declared.len(),
        caller.parameter_count
    );
}

#[test]
fn the_recovered_sibling_pair_recompiles_and_matches_the_reference_object() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!(
            "skipping: the reference compiler on this host emits non-x86-64 code and the BCC lift models x86-64 only"
        );
        return;
    }
    let cc: String = compiler();
    let holder: ScratchDir = scratch();
    let dir: &Path = holder.path();
    let object_bytes: Vec<u8> = compile_siblings(&cc, dir);
    let (base, code): (u64, Vec<u8>) = text_section(&object_bytes);
    let callee_va: u64 = symbol_address(&object_bytes, "sib_callee");
    let caller_va: u64 = symbol_address(&object_bytes, "sib_caller");

    let functions: Vec<PseudoCFunction> = lift_bcc_code_region(&code, base, host_arch());
    let callee: &PseudoCFunction = find_function(&functions, callee_va);
    let caller: &PseudoCFunction = find_function(&functions, caller_va);
    assert!(callee.modeled && caller.modeled, "both bodies must lift");

    let arity: usize = call_arguments(&caller.pseudo_c, &callee.id.name).len();
    let forwarded: Vec<String> = (0..arity)
        .map(|i: usize| format!("(uint64_t)in[{i}]"))
        .collect();
    let program: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n\
         extern long long sib_entry(long long, long long);\n\
         {callee_body}\n{caller_body}\n\
         int main(void) {{\n\
         \x20   long long inputs[][2] = {{ {{0,0}},{{1,1}},{{-1,-1}},{{7,3}},{{-7,3}},\n\
         \x20       {{123456,-654321}},{{2147483647,1}},{{-2147483648,-1}},{{9,4}},{{100,200}},\n\
         \x20       {{-100,50}},{{1<<20,1<<10}},{{42,42}},{{5,2}} }};\n\
         \x20   size_t n = sizeof(inputs)/sizeof(inputs[0]);\n\
         \x20   for (size_t k = 0; k < n; k++) {{\n\
         \x20       long long in[6] = {{ inputs[k][0], inputs[k][1], 0, 0, 0, 0 }};\n\
         \x20       unsigned long long want = (unsigned long long)sib_entry(in[0], in[1]);\n\
         \x20       unsigned long long got = {caller_name}({args});\n\
         \x20       if (want != got) {{ printf(\"MISMATCH in=%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], want, got); return 1; }}\n\
         \x20   }}\n\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n",
        callee_body = definition_body(callee),
        caller_body = definition_body(caller),
        caller_name = caller.id.name,
        args = forwarded.join(", "),
    );

    let driver: PathBuf = dir.join("driver.c");
    std::fs::write(&driver, program.as_bytes()).expect("write driver.c");
    let harness: PathBuf = dir.join(if cfg!(windows) {
        "harness.exe"
    } else {
        "harness"
    });
    let link: std::process::Output = Command::new(&cc)
        .args(["-O1", "-o"])
        .arg(&harness)
        .arg(&driver)
        .arg(dir.join("siblings.o"))
        .output()
        .expect("invoke the reference compiler to link the differential harness");
    assert!(
        link.status.success(),
        "the recovered sibling pair did not recompile against the reference callee prototype: {}\n--- driver.c ---\n{program}",
        String::from_utf8_lossy(&link.stderr)
    );

    let run: std::process::Output = Command::new(&harness).output().expect("run the harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "recovered sibling pair diverged from the reference object: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!("recovered sibling pair matched the reference object over 14 input vectors");
}

const RECORD_STRIDE: usize = 32;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

fn descriptor_object(text: &[u8], entries: &[(u64, &str)]) -> Vec<u8> {
    let text_addr: u64 = 0x1000;
    let names_addr: u64 = 0x8000;
    let table_addr: u64 = 0x9000;

    let mut names: Vec<u8> = Vec::new();
    let mut name_ptrs: Vec<u64> = Vec::with_capacity(entries.len());
    for (_, name) in entries {
        name_ptrs.push(names_addr + u64::try_from(names.len()).expect("name table fits u64"));
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }

    let mut table: Vec<u8> = Vec::new();
    for (index, (offset, _)) in entries.iter().enumerate() {
        table.extend_from_slice(&name_ptrs[index].to_le_bytes());
        table.extend_from_slice(&(text_addr + offset).to_le_bytes());
        table.extend_from_slice(&1u64.to_le_bytes());
        table.extend_from_slice(&0u64.to_le_bytes());
    }
    table.resize(table.len() + RECORD_STRIDE, 0);

    let header_len: usize = 64;
    let shentsize: usize = 64;
    let sections: [(u64, u64, &[u8]); 3] = [
        (text_addr, SHF_ALLOC | SHF_EXECINSTR, text),
        (names_addr, 0, names.as_slice()),
        (table_addr, 0, table.as_slice()),
    ];

    let mut body: Vec<u8> = Vec::new();
    let mut placed: Vec<(u64, u64, usize, usize)> = Vec::new();
    for (addr, flags, data) in &sections {
        let offset: usize = header_len + body.len();
        body.extend_from_slice(data);
        placed.push((*addr, *flags, offset, data.len()));
    }
    let shoff: usize = header_len + body.len();

    let mut blob: Vec<u8> = vec![0u8; header_len];
    blob[..4].copy_from_slice(&ELF_MAGIC);
    blob[4] = 2;
    blob[5] = 1;
    blob[0x28..0x30].copy_from_slice(&u64::try_from(shoff).expect("shoff fits").to_le_bytes());
    blob[0x3a..0x3c].copy_from_slice(&u16::try_from(shentsize).expect("shentsize").to_le_bytes());
    blob[0x3c..0x3e].copy_from_slice(&u16::try_from(placed.len()).expect("shnum").to_le_bytes());
    blob[0x3e..0x40].copy_from_slice(&259u16.to_le_bytes());
    blob.extend_from_slice(&body);
    for (addr, flags, offset, size) in placed {
        let mut hdr: Vec<u8> = vec![0u8; shentsize];
        hdr[4..8].copy_from_slice(&1u32.to_le_bytes());
        hdr[8..16].copy_from_slice(&flags.to_le_bytes());
        hdr[16..24].copy_from_slice(&addr.to_le_bytes());
        hdr[24..32].copy_from_slice(&u64::try_from(offset).expect("offset").to_le_bytes());
        hdr[32..40].copy_from_slice(&u64::try_from(size).expect("size").to_le_bytes());
        blob.extend_from_slice(&hdr);
    }
    blob
}

#[test]
fn the_dispatch_descriptor_names_the_carved_functions_and_links_the_sibling() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!(
            "skipping: the reference compiler on this host emits non-x86-64 code and the BCC lift models x86-64 only"
        );
        return;
    }
    let cc: String = compiler();
    let holder: ScratchDir = scratch();
    let object_bytes: Vec<u8> = compile_siblings(&cc, holder.path());
    let (base, text): (u64, Vec<u8>) = text_section(&object_bytes);
    let callee_offset: u64 = symbol_address(&object_bytes, "sib_callee") - base;
    let caller_offset: u64 = symbol_address(&object_bytes, "sib_caller") - base;
    let entry_offset: u64 = symbol_address(&object_bytes, "sib_entry") - base;

    let blob: Vec<u8> = descriptor_object(
        &text,
        &[
            (callee_offset, "bcc_11"),
            (caller_offset, "bcc_22"),
            (entry_offset, "bcc_33"),
        ],
    );
    let lift: disrobe_pass_pyarmor::BccLiftOutput =
        lift_bcc_native(&blob, host_arch()).expect("the descriptor object lifts");

    assert_eq!(
        lift.modeled_count + lift.unmodeled_count,
        lift.functions.len(),
        "every surfaced function is counted exactly once"
    );
    let names: Vec<String> = lift
        .functions
        .values()
        .map(|f: &PseudoCFunction| f.id.name.clone())
        .collect();
    for wanted in ["bcc_11", "bcc_22", "bcc_33"] {
        assert!(
            names.iter().any(|n: &String| n == wanted),
            "the descriptor table must name the carved function {wanted}; got {names:?}"
        );
    }
    for name in ["bcc_11", "bcc_22", "bcc_33"] {
        let function: &PseudoCFunction = lift
            .functions
            .values()
            .find(|f: &&PseudoCFunction| f.id.name == name)
            .expect("named function present");
        assert_eq!(
            function.name_source,
            FunctionNameSource::DispatchDescriptor,
            "{name} takes its name from the descriptor table, not from its entry address"
        );
    }

    let caller: &PseudoCFunction = lift
        .functions
        .values()
        .find(|f: &&PseudoCFunction| f.id.name == "bcc_22")
        .expect("the calling sibling is surfaced");
    assert_eq!(
        caller.resolved_callees,
        vec!["bcc_11".to_owned()],
        "the descriptor name reaches the call site: {}",
        caller.pseudo_c
    );
    assert!(
        caller.pseudo_c.contains("bcc_11("),
        "the recovered body calls the sibling by its descriptor name: {}",
        caller.pseudo_c
    );
    assert_eq!(
        declared_parameters(&caller.pseudo_c, "bcc_11").len(),
        2,
        "the descriptor-named sibling keeps the authored two-parameter arity: {}",
        caller.pseudo_c
    );
}

fn corpus_default_dir() -> Option<PathBuf> {
    let dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .join("corpus/python/pyarmor/v9-bcc/default");
    dir.is_dir().then_some(dir)
}

#[test]
fn the_real_bcc_object_counts_every_carved_function_exactly_once() {
    let Some(dir): Option<PathBuf> = corpus_default_dir() else {
        eprintln!("v9-bcc corpus absent; skipping the real-object counting check");
        return;
    };
    let wrapper_path: PathBuf = dir.join("known_plaintext.py");
    let wrapper_text: String = std::fs::read_to_string(&wrapper_path).expect("read wrapper");
    let options: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let out = unpack_wrapper_text_with_options(&wrapper_text, &wrapper_path, &options)
        .expect("the real v9 BCC wrapper unpacks");
    assert_eq!(out.bcc_lifts.len(), 1, "one carved BCC object");
    let lift = &out.bcc_lifts[0];
    assert_eq!(
        lift.modeled_count + lift.unmodeled_count,
        lift.functions.len(),
        "modeled plus unmodeled must equal the carved function count"
    );
    let descriptor_named: usize = lift
        .functions
        .values()
        .filter(|f: &&PseudoCFunction| f.name_source == FunctionNameSource::DispatchDescriptor)
        .count();
    let linked: usize = lift
        .functions
        .values()
        .filter(|f: &&PseudoCFunction| !f.resolved_callees.is_empty())
        .count();
    let extents: Vec<String> = lift
        .functions
        .values()
        .map(|f: &PseudoCFunction| format!("{}@{:#x}+{:#x}", f.id.name, f.id.entry_va, f.size))
        .collect();
    println!(
        "real BCC object: {}/{} functions named from the dispatch descriptor, {}/{} carry a resolved sibling call, {} modeled, extents {extents:?}",
        descriptor_named,
        lift.functions.len(),
        linked,
        lift.functions.len(),
        lift.modeled_count
    );
    assert!(
        descriptor_named > 0,
        "the real BCC object carries a dispatch descriptor table, so at least one carved function must take its name from it rather than from its entry address"
    );
    let mut previous_end: Option<(String, u64)> = None;
    for function in lift.functions.values() {
        if function.name_source == FunctionNameSource::EntryAddress {
            assert_eq!(
                function.id.name,
                format!("sub_{:x}", function.id.entry_va),
                "a function outside the descriptor table records the address fallback"
            );
        }
        assert!(
            function.id.entry_va >= lift.text_base,
            "{} starts before the lifted text base {:#x}",
            function.id.name,
            lift.text_base
        );
        if let Some((earlier, end)) = previous_end.as_ref() {
            assert!(
                function.id.entry_va >= *end,
                "{} at {:#x} overlaps {earlier}, which runs to {end:#x}; a carved extent must not swallow a sibling",
                function.id.name,
                function.id.entry_va
            );
        }
        previous_end = Some((
            function.id.name.clone(),
            function.id.entry_va + u64::from(function.size),
        ));
        for callee in &function.resolved_callees {
            assert!(
                lift.functions
                    .values()
                    .any(|f: &PseudoCFunction| f.id.name == *callee),
                "a resolved callee must be one of the carved siblings, got {callee}"
            );
        }
    }
}
