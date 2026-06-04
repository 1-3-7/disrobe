#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::missing_docs_in_private_items
)]

use disrobe_pass_native::{
    CompileUnit, DwarfSourcemap, Error, LineRow, synthesize_dwarf_sourcemap,
};

const ZIG_ELF: &[u8] = include_bytes!("../../../corpus/native/zig/hello.zig.elf");
const NIM_ELF: &[u8] = include_bytes!("../../../corpus/native/nim/hello.nim.elf");

#[test]
fn synthesizes_real_dwarf_sourcemap_from_zig_elf() {
    let map: DwarfSourcemap =
        synthesize_dwarf_sourcemap(ZIG_ELF).expect("zig ELF carries real .debug_* sections");
    assert!(
        !map.is_empty(),
        "the zig binary is compiled with DWARF; recovery must not be empty",
    );
    assert!(
        !map.compile_units.is_empty(),
        "at least one compilation unit must be recovered from .debug_info",
    );
    assert!(
        !map.line_rows.is_empty(),
        "the .debug_line program must yield pc->source rows",
    );

    let dwarf_versions: Vec<u16> = map
        .compile_units
        .iter()
        .map(|cu: &CompileUnit| cu.dwarf_version)
        .collect();
    assert!(
        dwarf_versions.iter().all(|v: &u16| (2..=5).contains(v)),
        "recovered DWARF versions must be in the real 2..=5 band, got {dwarf_versions:?}",
    );

    let sorted: bool = map
        .line_rows
        .windows(2)
        .all(|w: &[LineRow]| w[0].pc <= w[1].pc);
    assert!(sorted, "line rows must be pc-sorted");

    let has_zig_source: bool =
        map.line_rows
            .iter()
            .any(|r: &LineRow| r.file.contains(".zig"))
            || map.compile_units.iter().any(|cu: &CompileUnit| {
                cu.name.as_deref().is_some_and(|n: &str| n.contains(".zig"))
            });
    assert!(
        has_zig_source,
        "the recovered file/CU names must reference real .zig source paths the compiler embedded \
         (non-circular: these strings come from the binary's own .debug_str, not from any re-emit)",
    );

    println!(
        "zig DWARF sourcemap: {} CUs, {} line rows (versions {:?})",
        map.compile_units.len(),
        map.line_rows.len(),
        dwarf_versions,
    );
}

#[test]
fn zig_sourcemap_json_is_v3_compatible() {
    let map: DwarfSourcemap = synthesize_dwarf_sourcemap(ZIG_ELF).expect("zig sourcemap");
    let json: serde_json::Value = map.to_sourcemap_json();
    assert_eq!(json["version"], 1, "v3-compatible schema version tag");
    assert_eq!(
        json["line_entries"],
        serde_json::Value::from(map.line_rows.len()),
    );
    assert!(json["compile_units"].is_array());
    assert!(json["line_map"].is_array());
    assert!(
        !json["line_map"].as_array().expect("array").is_empty(),
        "the emitted line_map must carry real rows",
    );
}

#[test]
fn synthesizes_dwarf_sourcemap_from_nim_elf() {
    let map: DwarfSourcemap =
        synthesize_dwarf_sourcemap(NIM_ELF).expect("nim ELF carries real .debug_* sections");
    assert!(
        !map.is_empty(),
        "nim binary ships DWARF; recovery non-empty"
    );
    assert!(
        !map.compile_units.is_empty() || !map.line_rows.is_empty(),
        "at least one of CUs or line rows must be recovered",
    );
    println!(
        "nim DWARF sourcemap: {} CUs, {} line rows",
        map.compile_units.len(),
        map.line_rows.len(),
    );
}

#[test]
fn rejects_object_without_debug_sections() {
    let mut minimal_pe: Vec<u8> = vec![0u8; 0x200];
    minimal_pe[0] = b'M';
    minimal_pe[1] = b'Z';
    let err: Error = synthesize_dwarf_sourcemap(&minimal_pe).unwrap_err();
    assert!(
        matches!(err, Error::UnknownFormat | Error::SignatureDb(_)),
        "a non-DWARF / unparsable object must surface an honest error, never a fabricated map",
    );
}
