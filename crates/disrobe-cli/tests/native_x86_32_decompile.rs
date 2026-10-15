#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use object::{Object as _, ObjectSymbol as _};
use serde_json::Value;

const DECOMPILE_TIMEOUT: Duration = Duration::from_mins(2);
const COMPILE_TIMEOUT: Duration = Duration::from_mins(1);
const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const COMPILE_TARGET: &str = "--target=i686-unknown-linux-gnu";

struct Fixture {
    path: &'static str,
    total: u64,
    recovered: u64,
    conventions: &'static [(&'static str, &'static str)],
}

const MSVC_O2: Fixture = Fixture {
    path: "corpus/native/decompile32/conventions/conventions_msvc_o2.dll",
    total: 19,
    recovered: 17,
    conventions: &[("stdcall", "_sc_sub_8"), ("fastcall", "_fc_lin_12")],
};

const ELF_PIC_O2: Fixture = Fixture {
    path: "corpus/native/decompile32/conventions/conventions_elf_o2.so",
    total: 23,
    recovered: 20,
    conventions: &[
        ("stdcall", "sc_sub"),
        ("fastcall", "fc_lin"),
        ("thiscall", "tc_get"),
    ],
};

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn disrobe_bin() -> PathBuf {
    let bin: PathBuf = PathBuf::from(std::env::var_os("DISROBE_BIN").expect(
        "DISROBE_BIN must name the disrobe binary built by `cargo build -p disrobe-cli --bin disrobe` for this caller test",
    ));
    assert!(
        bin.is_file(),
        "DISROBE_BIN does not name a file: {}",
        bin.display()
    );
    bin
}

fn run(program: &Path, args: &[OsString], timeout: Duration) -> CapturedOutput {
    run_captured(program, args, timeout, MAX_CAPTURE_BYTES)
        .unwrap_or_else(|e| panic!("cannot start {}: {e}", program.display()))
        .unwrap_or_else(|| panic!("{} exceeded its timeout", program.display()))
}

fn compile_i386(source: &Path, object_path: &Path) -> CapturedOutput {
    let args: Vec<OsString> = vec![
        COMPILE_TARGET.into(),
        "-ffreestanding".into(),
        "-c".into(),
        "-o".into(),
        object_path.as_os_str().to_owned(),
        source.as_os_str().to_owned(),
    ];
    run(Path::new("clang"), &args, COMPILE_TIMEOUT)
}

fn defined_symbols(object_bytes: &[u8]) -> BTreeSet<String> {
    let file: object::File<'_> =
        object::File::parse(object_bytes).expect("clang writes an object file");
    assert_eq!(
        file.architecture(),
        object::Architecture::I386,
        "the recovered C must compile for x86-32"
    );
    file.symbols()
        .filter(|symbol: &object::Symbol<'_, '_>| symbol.is_definition())
        .filter_map(|symbol: object::Symbol<'_, '_>| symbol.name().ok().map(str::to_owned))
        .collect()
}

fn assert_decompiles_and_compiles(fixture: &Fixture) {
    let input: PathBuf = workspace_root().join(fixture.path);
    assert!(
        input.is_file(),
        "committed x86-32 fixture missing at {}",
        input.display()
    );
    let scratch: ScratchDir =
        ScratchDir::create("native-x86-32-decompile").expect("create scratch directory");
    let out: PathBuf = scratch.path().join("decompiled");
    let args: Vec<OsString> = vec![
        "native".into(),
        "decompile".into(),
        input.as_os_str().to_owned(),
        "--out".into(),
        out.as_os_str().to_owned(),
    ];
    let decompiled: CapturedOutput = run(&disrobe_bin(), &args, DECOMPILE_TIMEOUT);
    assert_eq!(
        decompiled.exit_code,
        Some(0),
        "native decompile {} failed: {}",
        fixture.path,
        String::from_utf8_lossy(&decompiled.stderr)
    );
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(out.join("manifest.json")).expect("native decompile writes manifest.json"),
    )
    .expect("manifest.json is JSON");
    assert_eq!(manifest["backend"], "native-in-tree-x86", "{manifest}");
    assert_eq!(manifest["abi"], "I386", "{manifest}");
    assert_eq!(manifest["language"], "C", "{manifest}");
    assert_eq!(
        (
            manifest["functions_total"].as_u64(),
            manifest["functions_recovered"].as_u64()
        ),
        (Some(fixture.total), Some(fixture.recovered)),
        "{manifest}"
    );
    for refused in ["fp_half", "fp_scale"] {
        let reason: &str = manifest["unrecovered"]
            .as_array()
            .expect("an unrecovered list")
            .iter()
            .find(|entry: &&Value| entry["name"] == refused)
            .and_then(|entry: &Value| entry["reason"].as_str())
            .unwrap_or_else(|| {
                panic!("{refused} returns in st(0) and must be refused: {manifest}")
            });
        assert!(
            reason.contains("x87"),
            "{refused} must be refused by naming x87: {reason}"
        );
    }
    let emitted: Vec<String> = manifest["recovered"]
        .as_array()
        .expect("a recovered list")
        .iter()
        .map(|entry: &Value| {
            entry["emitted_as"]
                .as_str()
                .expect("every recovered function names its emitted symbol")
                .to_owned()
        })
        .collect();
    let source_path: PathBuf = PathBuf::from(
        manifest["source"]
            .as_str()
            .expect("the manifest names its emitted source"),
    );
    let source: String = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|e| panic!("emitted source at {}: {e}", source_path.display()));
    for (convention, name) in fixture.conventions {
        assert!(
            source.contains(&format!("__attribute__(({convention})) {name}(")),
            "{name} must be emitted with its {convention} convention: {source}"
        );
    }

    let object_path: PathBuf = scratch.path().join("recovered.o");
    let compiled: CapturedOutput = compile_i386(&source_path, &object_path);
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "the recovered C of {} must compile for x86-32: {}",
        fixture.path,
        String::from_utf8_lossy(&compiled.stderr)
    );
    let defined: BTreeSet<String> =
        defined_symbols(&std::fs::read(&object_path).expect("read the compiled object"));
    for name in &emitted {
        assert!(
            defined.contains(name),
            "the compiled recovered C must define {name}; it defines {defined:?}"
        );
    }

    let broken_source: String = source.replacen("#include <stdint.h>", "", 1);
    assert_ne!(
        broken_source, source,
        "the control needs the stdint include to remove"
    );
    let broken_path: PathBuf = scratch.path().join("broken.c");
    std::fs::write(&broken_path, broken_source).expect("write the control source");
    let broken: CapturedOutput = compile_i386(&broken_path, &scratch.path().join("broken.o"));
    assert_ne!(
        broken.exit_code,
        Some(0),
        "the compile check must reject C whose integer types are undeclared"
    );
}

#[test]
fn an_msvc_x86_32_dll_decompiles_to_c_that_compiles_for_x86_32() {
    assert_decompiles_and_compiles(&MSVC_O2);
}

#[test]
fn a_pic_x86_32_elf_shared_object_decompiles_to_c_that_compiles_for_x86_32() {
    assert_decompiles_and_compiles(&ELF_PIC_O2);
}
