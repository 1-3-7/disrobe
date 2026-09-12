#![allow(clippy::expect_used, clippy::panic)]

mod common;

use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
use std::path::{Path, PathBuf};

fn symbol_bytes<'image>(file: &object::File<'image>, name: &str) -> &'image [u8] {
    let symbol: object::Symbol<'_, '_> = file
        .symbols()
        .find(|symbol: &object::Symbol<'_, '_>| symbol.name() == Ok(name))
        .expect("linked AArch64 fixture symbol");
    let section: object::Section<'_, '_> = file
        .section_by_index(symbol.section_index().expect("fixture symbol section"))
        .expect("fixture text section");
    let data: &[u8] = section.data().expect("fixture text bytes");
    let offset: usize = usize::try_from(
        symbol
            .address()
            .checked_sub(section.address())
            .expect("fixture symbol lies in its section"),
    )
    .expect("fixture symbol offset fits usize");
    let size: usize = usize::try_from(symbol.size()).expect("fixture symbol size fits usize");
    data.get(offset..offset + size)
        .expect("fixture symbol bytes lie in section")
}

fn collect_c_sources(directory: &Path) -> String {
    let mut pending: Vec<PathBuf> = vec![directory.to_owned()];
    let mut sources: Vec<(PathBuf, String)> = Vec::new();
    while let Some(current) = pending.pop() {
        let entries: std::fs::ReadDir =
            std::fs::read_dir(&current).expect("inspect native output directory");
        for entry in entries {
            let path: PathBuf = entry.expect("inspect native output entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "c") {
                let source: String =
                    std::fs::read_to_string(&path).expect("read recovered native C source");
                sources.push((path, source));
            }
        }
    }
    sources.sort_by(|left: &(PathBuf, String), right: &(PathBuf, String)| left.0.cmp(&right.0));
    assert!(!sources.is_empty(), "native decompile emitted no C source");
    sources
        .into_iter()
        .map(|(_, source): (PathBuf, String)| source)
        .collect::<Vec<String>>()
        .join("\n")
}

#[test]
fn native_decompile_routes_linked_aarch64_scalar_post_index_through_fp_state() {
    let fixture: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/native_aarch64_scalar_post_index.elf");
    let image: Vec<u8> = std::fs::read(&fixture).expect("read linked AArch64 fixture");
    let file: object::File<'_> = object::File::parse(image.as_slice()).expect("parse AArch64 ELF");
    assert_eq!(
        symbol_bytes(&file, "scalar_take"),
        [
            0x08, 0x00, 0x40, 0xf9, 0x00, 0x85, 0x40, 0xfc, 0x08, 0x00, 0x00, 0xf9, 0xc0, 0x03,
            0x5f, 0xd6,
        ]
    );
    assert_eq!(
        symbol_bytes(&file, "scalar_put"),
        [
            0x28, 0x00, 0x40, 0xf9, 0x00, 0x85, 0x00, 0xfc, 0x28, 0x00, 0x00, 0xf9, 0xc0, 0x03,
            0x5f, 0xd6,
        ]
    );
    let scratch: tempfile::TempDir =
        tempfile::tempdir().expect("create native AArch64 CLI output directory");
    let output: PathBuf = scratch.path().join("out");
    let run: common::Run = common::run_disrobe(&[
        "native",
        "decompile",
        &fixture.display().to_string(),
        "--backend",
        "native",
        "--format",
        "c",
        "--out",
        &output.display().to_string(),
    ]);
    assert_eq!(
        run.code, 0,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );

    let source: String = collect_c_sources(&output);
    assert!(source.contains("scalar_take"), "{source}");
    assert!(source.contains("scalar_put"), "{source}");
    assert!(source.contains("x_xmm0"), "{source}");
    assert!(!source.contains("recovered_i8x8"), "{source}");
}
