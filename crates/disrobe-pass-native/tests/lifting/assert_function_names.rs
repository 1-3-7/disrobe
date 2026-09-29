#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::missing_docs_in_private_items
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_native::backend_export::{
    render_ghidra_postscript, render_idapython, render_symbol_map_json,
};
use disrobe_pass_native::lang::{FunctionNameConfidence, FunctionNameEvidenceSource};
use disrobe_pass_native::plt_resolve::resolve_elf_plt_imports;
use disrobe_pass_native::pseudo_c::{
    Abi, NamedRecoveredProgram, ProgramFunction, recover_program_with_naming,
};
use disrobe_pass_native::sig_engine::{FunctionNameSubject, assert_fail_function_names};
use object::{Object, ObjectSection, ObjectSymbol};
use tempfile::TempDir;

const SOURCE: &str = r#"
extern void __assert_fail(const char *, const char *, unsigned int, const char *);

__attribute__((used)) static int recovered_target(int value) {
    if (!(value > 0)) {
        __assert_fail("value > 0", "fixture.c", 6, __func__);
    }
    return value;
}

__attribute__((used)) static int decoy_target(int value) {
    static const char decoy[] = "recovered_target";
    return value + decoy[0] - decoy[0];
}

__attribute__((used)) static void collision_left(void) {
    __assert_fail("left", "fixture.c", 17, "shared_assert_name");
}

__attribute__((used)) static void collision_right(void) {
    __assert_fail("right", "fixture.c", 18, "shared_assert_name");
}
"#;

fn compile_fixture(directory: &TempDir) -> (Vec<u8>, Vec<u8>) {
    let source: PathBuf = directory.path().join("fixture.c");
    let unstripped: PathBuf = directory.path().join("fixture.unstripped");
    let stripped: PathBuf = directory.path().join("fixture.stripped");
    std::fs::write(&source, SOURCE).expect("write fixture source");
    let compile: std::process::Output = Command::new("clang")
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-O0",
            "-g",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&unstripped)
        .output()
        .expect("invoke clang for assert fixture");
    assert!(
        compile.status.success(),
        "clang must compile the assert fixture: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let strip: std::process::Output = Command::new("llvm-strip")
        .args(["--strip-all", "-o"])
        .arg(&stripped)
        .arg(&unstripped)
        .output()
        .expect("invoke llvm-strip for assert fixture");
    assert!(
        strip.status.success(),
        "llvm-strip must remove symbols from the assert fixture: {}",
        String::from_utf8_lossy(&strip.stderr)
    );
    (
        std::fs::read(&unstripped).expect("read unstripped fixture"),
        std::fs::read(&stripped).expect("read stripped fixture"),
    )
}

fn code_at(image: &[u8], address: u64, size: u64) -> Vec<u8> {
    let file: object::File<'_> = object::File::parse(image).expect("parse fixture");
    let section = file
        .sections()
        .find(|section| {
            let end: u64 = section.address().saturating_add(section.size());
            address >= section.address() && address.saturating_add(size) <= end
        })
        .expect("function must lie in a mapped section");
    let (file_start, _): (u64, u64) = section.file_range().expect("mapped section file range");
    let offset: u64 = file_start.saturating_add(address.saturating_sub(section.address()));
    let start: usize = usize::try_from(offset).expect("function file offset");
    let end: usize = start.saturating_add(usize::try_from(size).expect("function size"));
    image[start..end].to_vec()
}

fn stripped_subjects(unstripped: &[u8], stripped: &[u8]) -> BTreeMap<String, ProgramFunction> {
    let file: object::File<'_> = object::File::parse(unstripped).expect("parse unstripped fixture");
    file.symbols()
        .filter_map(|symbol| {
            let name: &str = symbol.name().ok()?;
            let required: bool = matches!(
                name,
                "recovered_target" | "decoy_target" | "collision_left" | "collision_right"
            );
            (required && symbol.kind() == object::SymbolKind::Text && symbol.size() != 0).then(
                || {
                    (
                        name.to_owned(),
                        ProgramFunction {
                            name: format!("sub_{:x}", symbol.address()),
                            address: symbol.address(),
                            code: code_at(stripped, symbol.address(), symbol.size()),
                        },
                    )
                },
            )
        })
        .collect()
}

#[test]
fn direct_assert_fail_function_argument_recovers_only_the_cited_stripped_function_name() {
    let directory: TempDir = TempDir::new().expect("temporary fixture directory");
    let (unstripped, stripped): (Vec<u8>, Vec<u8>) = compile_fixture(&directory);
    let stripped_file: object::File<'_> =
        object::File::parse(stripped.as_slice()).expect("parse stripped fixture");
    assert!(
        stripped_file.symbols().next().is_none(),
        "strip must remove static symbols"
    );
    let functions: BTreeMap<String, ProgramFunction> = stripped_subjects(&unstripped, &stripped);
    assert!(
        resolve_elf_plt_imports(&stripped)
            .iter()
            .any(|entry| entry.name == "__assert_fail"),
        "fixture must retain a resolved __assert_fail PLT stub: {:?}",
        resolve_elf_plt_imports(&stripped)
    );
    let subjects: Vec<FunctionNameSubject<'_>> =
        functions.values().map(FunctionNameSubject::from).collect();

    let first = assert_fail_function_names(&stripped, &subjects);
    let second = assert_fail_function_names(&stripped, &subjects);

    assert_eq!(first, second, "assert-derived names must be deterministic");
    assert_eq!(
        first.len(),
        1,
        "the shared string and non-call decoy must abstain"
    );
    let recovered = &first[0];
    assert_eq!(
        recovered.function_address,
        functions["recovered_target"].address
    );
    assert_eq!(recovered.name, "recovered_target");
    assert_eq!(recovered.evidence.confidence, FunctionNameConfidence::High);
    assert_eq!(
        recovered.evidence.source,
        FunctionNameEvidenceSource::AssertFailFunction
    );
    let span = usize::try_from(recovered.evidence.input_bytes.start).expect("span start");
    let end = usize::try_from(recovered.evidence.input_bytes.end).expect("span end");
    assert_eq!(&stripped[span..end], b"recovered_target");
    assert_eq!(recovered.evidence.identity, "recovered_target");

    let ordered_functions: Vec<ProgramFunction> = functions.values().cloned().collect();
    let named: NamedRecoveredProgram =
        recover_program_with_naming(&stripped, &ordered_functions, Abi::SysV);
    assert_eq!(named.names, first);
    let json: String = render_symbol_map_json(&named).expect("render JSON export");
    let ghidra: String = render_ghidra_postscript(&named).expect("render Ghidra export");
    let ida: String = render_idapython(&named).expect("render IDA export");
    assert!(json.contains("recovered_target"));
    assert!(json.contains("assert-fail-function"));
    assert!(ghidra.contains("recovered_target"));
    assert!(ida.contains("recovered_target"));

    let mut named_subject: ProgramFunction = functions["recovered_target"].clone();
    named_subject.name = "ground_truth_name".to_owned();
    let existing: FunctionNameSubject<'_> = FunctionNameSubject::from(&named_subject);
    assert!(assert_fail_function_names(&stripped, &[existing]).is_empty());
}

#[test]
fn malformed_assert_function_pointer_abstains() {
    let directory: TempDir = TempDir::new().expect("temporary fixture directory");
    let (unstripped, mut stripped): (Vec<u8>, Vec<u8>) = compile_fixture(&directory);
    let functions: BTreeMap<String, ProgramFunction> = stripped_subjects(&unstripped, &stripped);
    let mut target: ProgramFunction = functions["recovered_target"].clone();
    let code_start: usize = stripped
        .windows(target.code.len())
        .position(|window| window == target.code)
        .expect("fixture function bytes");
    let lea_offset: usize = target
        .code
        .windows(3)
        .position(|window| window == [0x48, 0x8d, 0x0d])
        .expect("RCX function-name pointer load");
    stripped[code_start + lea_offset + 3..code_start + lea_offset + 7]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    target.code = stripped[code_start..code_start + target.code.len()].to_vec();
    let subject = FunctionNameSubject::from(&target);
    assert!(assert_fail_function_names(&stripped, &[subject]).is_empty());
}
