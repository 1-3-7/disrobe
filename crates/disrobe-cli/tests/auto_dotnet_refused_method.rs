#![cfg(feature = "dotnet")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assembly_with_one_invalid_body() -> (Vec<u8>, String, String) {
    let path: PathBuf = workspace_root().join("corpus/dotnet/HelloAppLegacy.dll");
    let mut bytes: Vec<u8> = std::fs::read(&path).expect("committed HelloAppLegacy.dll");
    let pe: PeImage = parse(&bytes).expect("pe");
    let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr header");
    let root: MetadataRoot = parse_metadata_root(&bytes, &pe, &clr).expect("metadata root");
    let model: AssemblyModel = Resolver::build(&bytes, &pe, &clr, &root)
        .expect("resolver")
        .model();
    let (type_name, method_name, rva): (String, String, u32) = model
        .types
        .iter()
        .flat_map(|ty: &TypeModel| {
            ty.methods
                .iter()
                .filter(|m: &&MethodModel| m.rva != 0)
                .map(|m: &MethodModel| (ty.full_name.clone(), m.name.clone(), m.rva))
        })
        .next()
        .expect("a method with a body");
    let offset: usize = pe.rva_to_offset(rva).expect("body offset");
    bytes[offset] = 0x00;
    (bytes, type_name, method_name)
}

#[test]
fn auto_prints_a_refusal_stub_for_a_method_it_cannot_decompile() {
    let (bytes, type_name, method_name): (Vec<u8>, String, String) =
        assembly_with_one_invalid_body();
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-dotnet-refused-input").expect("input dir");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-dotnet-refused-output")
            .expect("output dir");
    let input_path: PathBuf = input.path().join("HelloAppLegacy.dll");
    std::fs::write(&input_path, &bytes).expect("write input");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&input_path)
        .arg("--out")
        .arg(output.path())
        .arg("--capture-stages")
        .output()
        .expect("run disrobe auto");
    assert!(
        process.status.success(),
        "disrobe auto failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let mut rendered: String = String::new();
    for entry in std::fs::read_dir(output.path()).expect("output dir") {
        let stage: PathBuf = entry.expect("entry").path().join("output.bin");
        if let Ok(text) = std::fs::read_to_string(&stage) {
            rendered.push_str(&text);
        }
    }
    assert!(
        rendered.contains(&format!("DR-DOTNET-0930: {type_name}::{method_name} ")),
        "the refused method must be printed as a named refusal stub:\n{rendered}"
    );
    assert!(
        rendered.contains(", 1 refused"),
        "the header must count the refused method:\n{rendered}"
    );
}
