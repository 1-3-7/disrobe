#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::indirect_metadata::{ParamPtrShape, build_param_ptr_image};
use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::{AssemblyModel, MethodModel, ParamModel, Resolver, TypeModel};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::structurize::StructuredMethod;
use disrobe_pass_dotnet::tables::{TableId, Tables, parse_tables};

fn param_ptr_rows(image: &[u8]) -> usize {
    let pe: PeImage = parse(image).expect("parse the image");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("read the CLR header");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("read the metadata root");
    let metadata: &[u8] = disrobe_pass_dotnet::metadata::metadata_slice(image, &pe, &clr, &root)
        .expect("slice the metadata");
    let header: disrobe_pass_dotnet::metadata::StreamHeader = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .copied()
        .expect("a table stream");
    let tables: Tables = parse_tables(metadata, header).expect("parse the tables");
    tables.indirection(TableId::Param).map_or(0, <[u32]>::len)
}

const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

fn baseline_bytes() -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(EDGECASES_BASELINE_REL);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read the clean baseline at {}: {e}", path.display())
    })
}

fn parameter_names(image: &[u8]) -> BTreeMap<u32, Vec<(u16, String)>> {
    let pe: PeImage = parse(image).expect("parse the image");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("read the CLR header");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("read the metadata root");
    let model: AssemblyModel = Resolver::build(image, &pe, &clr, &root)
        .expect("build a resolver")
        .model();
    model
        .types
        .iter()
        .flat_map(|t: &TypeModel| t.methods.iter())
        .map(|m: &MethodModel| {
            (
                m.token,
                m.parameters
                    .iter()
                    .map(|p: &ParamModel| (p.sequence, p.name.clone()))
                    .collect::<Vec<(u16, String)>>(),
            )
        })
        .collect()
}

fn rendered_signatures(image: &[u8]) -> BTreeMap<u32, String> {
    let asm: DecompiledAssembly = decompile_assembly(image).expect("decompile the image");
    asm.methods
        .iter()
        .map(|m: &StructuredMethod| {
            (
                m.token,
                m.signature.lines().next_back().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_param_ptr_table_reaches_the_same_names_as_the_direct_param_table() {
    let original: Vec<u8> = baseline_bytes();
    let indirect: Vec<u8> = build_param_ptr_image(&original, ParamPtrShape::Faithful)
        .expect("build a ParamPtr carrying variant of the clean baseline");

    assert_eq!(
        param_ptr_rows(&original),
        0,
        "the clean baseline is the direct layout, so it must carry no ParamPtr table"
    );
    let indirect_rows: usize = param_ptr_rows(&indirect);
    assert!(
        indirect_rows > 0,
        "the variant has to actually carry a ParamPtr table, otherwise this check compares the \
         direct layout with itself and proves nothing"
    );

    let expected: BTreeMap<u32, Vec<(u16, String)>> = parameter_names(&original);
    let actual: BTreeMap<u32, Vec<(u16, String)>> = parameter_names(&indirect);

    let named: usize = expected
        .values()
        .flatten()
        .filter(|(sequence, name): &&(u16, String)| *sequence != 0 && !name.is_empty())
        .count();
    assert!(
        named > 100,
        "the clean baseline has to carry a real body of parameter names for this to prove \
         anything; saw {named}"
    );
    assert_eq!(
        actual.len(),
        expected.len(),
        "the indirection must not change how many methods are reachable"
    );

    let mut wrong: Vec<String> = Vec::new();
    for (token, want) in &expected {
        let Some(got): Option<&Vec<(u16, String)>> = actual.get(token) else {
            wrong.push(format!(
                "  0x{token:08x} is missing from the indirect image"
            ));
            continue;
        };
        if got != want {
            wrong.push(format!(
                "  0x{token:08x} reads {got:?} through ParamPtr but {want:?} directly"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "MethodDef.ParamList indexes ParamPtr when that table is present, so every method has to \
         resolve to the same Param rows the direct layout gives; {} do not:\n{}",
        wrong.len(),
        wrong
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<String>>()
            .join("\n")
    );

    assert_eq!(
        rendered_signatures(&indirect),
        rendered_signatures(&original),
        "every recovered signature has to render identically through the indirection"
    );
}

#[test]
fn ignoring_the_indirection_is_detected() {
    let original: Vec<u8> = baseline_bytes();
    let scrambled: Vec<u8> =
        build_param_ptr_image(&original, ParamPtrShape::IdentityPointerOverPermutedRows)
            .expect("build a variant whose ParamPtr rows do not undo the permutation");

    let expected: BTreeMap<u32, Vec<(u16, String)>> = parameter_names(&original);
    let actual: BTreeMap<u32, Vec<(u16, String)>> = parameter_names(&scrambled);

    assert_ne!(
        actual, expected,
        "this control permutes the Param rows and points ParamPtr straight at them, so a reader \
         that resolves the indirection has to see different names. Reading the same names back \
         would mean the check cannot fail and proves nothing about the faithful case."
    );
}
