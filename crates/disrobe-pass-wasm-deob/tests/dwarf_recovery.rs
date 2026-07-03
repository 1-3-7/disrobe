#![cfg(feature = "dwarf")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeMap;

use disrobe_pass_wasm_deob::dwarf::{
    BaseEncoding, FunctionInfo, RecoveredDwarfType, SourceLocation, WasmDwarfRecovery,
    function_banner, line_for_pc, recover_source_map,
};
use gimli::write::{
    Address, AttributeValue, DwarfUnit, EndianVec, LineProgram, LineString, Range, RangeList,
    Sections, StringTable,
};
use gimli::{Encoding, Format, LineEncoding};

const EMPTY_WASM_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

fn write_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte: u8 = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn embed_custom_section(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut name_bytes: Vec<u8> = Vec::new();
    write_uleb128(&mut name_bytes, name.len() as u64);
    name_bytes.extend_from_slice(name.as_bytes());

    let mut body: Vec<u8> = Vec::with_capacity(name_bytes.len() + data.len());
    body.extend_from_slice(&name_bytes);
    body.extend_from_slice(data);

    out.push(0x00);
    write_uleb128(out, body.len() as u64);
    out.extend_from_slice(&body);
}

struct SynthDwarf {
    sections: BTreeMap<gimli::SectionId, Vec<u8>>,
}

fn make_line_program(encoding: Encoding) -> LineProgram {
    let mut program: LineProgram = LineProgram::new(
        encoding,
        LineEncoding::default(),
        LineString::String(b"/src".to_vec()),
        None,
        LineString::String(b"hello.c".to_vec()),
        None,
    );
    let dir_id = program.default_directory();
    let file_id = program.add_file(LineString::String(b"hello.c".to_vec()), dir_id, None);

    program.begin_sequence(Some(Address::Constant(0x100)));
    for (offset, line) in [(0u64, 1u64), (0x10, 2), (0x20, 3)] {
        program.row().file = file_id;
        program.row().address_offset = offset;
        program.row().line = line;
        program.row().column = 1;
        program.generate_row();
    }
    program.end_sequence(0x40);
    program
}

struct Strings {
    producer: gimli::write::StringId,
    name: gimli::write::StringId,
    comp_dir: gimli::write::StringId,
    main: gimli::write::StringId,
    add: gimli::write::StringId,
    int_: gimli::write::StringId,
    point: gimli::write::StringId,
    x: gimli::write::StringId,
    y: gimli::write::StringId,
}

fn populate_strings(dwarf: &mut DwarfUnit) -> Strings {
    Strings {
        producer: dwarf.strings.add(b"disrobe-synth-clang"[..].to_vec()),
        name: dwarf.strings.add(b"hello.c"[..].to_vec()),
        comp_dir: dwarf.strings.add(b"/src"[..].to_vec()),
        main: dwarf.strings.add(b"main"[..].to_vec()),
        add: dwarf.strings.add(b"add"[..].to_vec()),
        int_: dwarf.strings.add(b"int"[..].to_vec()),
        point: dwarf.strings.add(b"Point"[..].to_vec()),
        x: dwarf.strings.add(b"x"[..].to_vec()),
        y: dwarf.strings.add(b"y"[..].to_vec()),
    }
}

fn add_subprogram(
    dwarf: &mut DwarfUnit,
    name_id: gimli::write::StringId,
    int_ref: gimli::write::UnitEntryId,
    low_pc: u64,
    decl_line: u8,
) -> gimli::write::UnitEntryId {
    let root = dwarf.unit.root();
    let sub_id = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
    let die = dwarf.unit.get_mut(sub_id);
    die.set(gimli::DW_AT_name, AttributeValue::StringRef(name_id));
    die.set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(low_pc)),
    );
    die.set(gimli::DW_AT_high_pc, AttributeValue::Udata(0x20));
    die.set(gimli::DW_AT_decl_file, AttributeValue::Data1(1));
    die.set(gimli::DW_AT_decl_line, AttributeValue::Data1(decl_line));
    die.set(gimli::DW_AT_type, AttributeValue::UnitRef(int_ref));
    sub_id
}

fn add_point_struct(dwarf: &mut DwarfUnit, strings: &Strings, int_ref: gimli::write::UnitEntryId) {
    let root = dwarf.unit.root();
    let point_id = dwarf.unit.add(root, gimli::DW_TAG_structure_type);
    {
        let pd = dwarf.unit.get_mut(point_id);
        pd.set(gimli::DW_AT_name, AttributeValue::StringRef(strings.point));
        pd.set(gimli::DW_AT_byte_size, AttributeValue::Data1(8));
    }
    let x_member = dwarf.unit.add(point_id, gimli::DW_TAG_member);
    {
        let m = dwarf.unit.get_mut(x_member);
        m.set(gimli::DW_AT_name, AttributeValue::StringRef(strings.x));
        m.set(gimli::DW_AT_type, AttributeValue::UnitRef(int_ref));
        m.set(gimli::DW_AT_data_member_location, AttributeValue::Data1(0));
    }
    let y_member = dwarf.unit.add(point_id, gimli::DW_TAG_member);
    {
        let m = dwarf.unit.get_mut(y_member);
        m.set(gimli::DW_AT_name, AttributeValue::StringRef(strings.y));
        m.set(gimli::DW_AT_type, AttributeValue::UnitRef(int_ref));
        m.set(gimli::DW_AT_data_member_location, AttributeValue::Data1(4));
    }
}

fn serialize_dwarf(dwarf: &mut DwarfUnit) -> BTreeMap<gimli::SectionId, Vec<u8>> {
    let mut sections: Sections<EndianVec<gimli::LittleEndian>> =
        Sections::new(EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections).expect("dwarf write succeeds");
    let mut out: BTreeMap<gimli::SectionId, Vec<u8>> = BTreeMap::new();
    sections
        .for_each(
            |id: gimli::SectionId,
             data: &EndianVec<gimli::LittleEndian>|
             -> gimli::write::Result<()> {
                let bytes: Vec<u8> = data.clone().into_vec();
                if !bytes.is_empty() {
                    out.insert(id, bytes);
                }
                Ok(())
            },
        )
        .expect("for_each succeeds");
    out
}

fn synthesize_minimal_dwarf() -> SynthDwarf {
    let encoding: Encoding = Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: 4,
    };
    let mut dwarf: DwarfUnit = DwarfUnit::new(encoding);
    dwarf.unit.line_program = make_line_program(encoding);
    let strings: Strings = populate_strings(&mut dwarf);

    let range_list_id = dwarf.unit.ranges.add(RangeList(vec![Range::StartLength {
        begin: Address::Constant(0x100),
        length: 0x100,
    }]));

    let root = dwarf.unit.root();
    {
        let cu = dwarf.unit.get_mut(root);
        cu.set(
            gimli::DW_AT_producer,
            AttributeValue::StringRef(strings.producer),
        );
        cu.set(gimli::DW_AT_name, AttributeValue::StringRef(strings.name));
        cu.set(
            gimli::DW_AT_comp_dir,
            AttributeValue::StringRef(strings.comp_dir),
        );
        cu.set(
            gimli::DW_AT_language,
            AttributeValue::Language(gimli::DW_LANG_C99),
        );
        cu.set(
            gimli::DW_AT_ranges,
            AttributeValue::RangeListRef(range_list_id),
        );
    }

    let int_id = dwarf.unit.add(root, gimli::DW_TAG_base_type);
    {
        let die = dwarf.unit.get_mut(int_id);
        die.set(gimli::DW_AT_name, AttributeValue::StringRef(strings.int_));
        die.set(
            gimli::DW_AT_encoding,
            AttributeValue::Encoding(gimli::DW_ATE_signed),
        );
        die.set(gimli::DW_AT_byte_size, AttributeValue::Data1(4));
    }

    add_point_struct(&mut dwarf, &strings, int_id);
    let _ = add_subprogram(&mut dwarf, strings.add, int_id, 0x100, 1);
    let _ = add_subprogram(&mut dwarf, strings.main, int_id, 0x120, 3);
    let _ = StringTable::default();

    SynthDwarf {
        sections: serialize_dwarf(&mut dwarf),
    }
}

fn build_wasm_with_dwarf(dwarf: &SynthDwarf) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(4096);
    bytes.extend_from_slice(&EMPTY_WASM_HEADER);
    for (id, data) in &dwarf.sections {
        embed_custom_section(&mut bytes, id.name(), data);
    }
    bytes
}

#[test]
fn dwarf_recovers_function_names_from_synth_wasm() {
    let synth: SynthDwarf = synthesize_minimal_dwarf();
    let wasm: Vec<u8> = build_wasm_with_dwarf(&synth);

    let recovery: WasmDwarfRecovery = recover_source_map(&wasm).expect("recover");
    assert!(!recovery.is_empty(), "expected non-empty recovery");
    assert!(
        recovery.section_bytes > 0,
        "expected positive section bytes"
    );

    let names: Vec<&str> = recovery
        .functions
        .values()
        .filter_map(|f: &FunctionInfo| f.name.as_deref())
        .collect::<Vec<_>>();
    assert!(names.contains(&"main"), "expected main, got {names:?}");
    assert!(names.contains(&"add"), "expected add, got {names:?}");

    let saw_hello_cu: bool = recovery
        .compile_units
        .iter()
        .filter_map(|cu| cu.name.as_deref())
        .any(|n: &str| n == "hello.c");
    assert!(saw_hello_cu, "expected compile-unit named hello.c");
}

#[test]
fn dwarf_recovers_line_table() {
    let synth: SynthDwarf = synthesize_minimal_dwarf();
    let wasm: Vec<u8> = build_wasm_with_dwarf(&synth);

    let recovery: WasmDwarfRecovery = recover_source_map(&wasm).expect("recover");
    assert!(
        recovery.line_entry_count() >= 3,
        "expected at least 3 line entries, got {}",
        recovery.line_entry_count()
    );

    let row_at_100: &SourceLocation = recovery.resolve_pc(0x100).expect("resolve 0x100");
    assert_eq!(row_at_100.line, 1, "first row at pc 0x100 is line 1");
    assert!(
        row_at_100.file.ends_with("hello.c"),
        "file should end with hello.c, got {}",
        row_at_100.file
    );

    let row_at_110: &SourceLocation = recovery.resolve_pc(0x110).expect("resolve 0x110");
    assert_eq!(row_at_110.line, 2);

    let row_at_120: &SourceLocation = recovery.resolve_pc(0x120).expect("resolve 0x120");
    assert_eq!(row_at_120.line, 3);
}

#[test]
fn dwarf_recovers_type_graph() {
    let synth: SynthDwarf = synthesize_minimal_dwarf();
    let wasm: Vec<u8> = build_wasm_with_dwarf(&synth);

    let recovery: WasmDwarfRecovery = recover_source_map(&wasm).expect("recover");
    assert!(recovery.type_count() >= 2, "base int + Point struct");

    let has_signed_int_base: bool = recovery.types.types.values().any(|t: &RecoveredDwarfType| {
        matches!(
            t,
            RecoveredDwarfType::Base {
                encoding: BaseEncoding::SignedInt,
                ..
            }
        )
    });
    assert!(has_signed_int_base, "expected a signed int base type");

    let point_struct: &RecoveredDwarfType = recovery
        .types
        .types
        .values()
        .find(|t: &&RecoveredDwarfType| {
            matches!(
                t,
                RecoveredDwarfType::Structure {
                    name: Some(n),
                    ..
                } if n == "Point"
            )
        })
        .expect("expected Point struct");
    if let RecoveredDwarfType::Structure {
        members, byte_size, ..
    } = point_struct
    {
        assert_eq!(*byte_size, Some(8));
        assert_eq!(members.len(), 2, "Point has two fields");
        let field_names: Vec<&str> = members
            .iter()
            .filter_map(|m| m.name.as_deref())
            .collect::<Vec<_>>();
        assert!(field_names.contains(&"x"));
        assert!(field_names.contains(&"y"));
    } else {
        panic!("expected Structure variant");
    }
}

#[test]
fn dwarf_sourcemap_json_includes_functions_and_lines() {
    let synth: SynthDwarf = synthesize_minimal_dwarf();
    let wasm: Vec<u8> = build_wasm_with_dwarf(&synth);

    let recovery: WasmDwarfRecovery = recover_source_map(&wasm).expect("recover");
    let json: serde_json::Value = recovery.to_sourcemap_json();
    assert_eq!(json["version"], 1);
    assert!(json["function_count"].as_u64().unwrap() >= 2);
    assert!(json["line_entries"].as_u64().unwrap() >= 3);

    let function_for_pc: &FunctionInfo =
        recovery.function_for_pc(0x108).expect("function at 0x108");
    assert_eq!(function_for_pc.name.as_deref(), Some("add"));
}

#[test]
fn recover_handles_module_with_no_dwarf() {
    let recovery: WasmDwarfRecovery =
        recover_source_map(&EMPTY_WASM_HEADER).expect("empty recovery");
    assert!(recovery.is_empty());
    assert_eq!(recovery.function_count(), 0);
}

#[test]
fn function_banner_and_line_helpers_resolve_recovered_info() {
    let synth: SynthDwarf = synthesize_minimal_dwarf();
    let wasm: Vec<u8> = build_wasm_with_dwarf(&synth);
    let recovery: WasmDwarfRecovery = recover_source_map(&wasm).expect("recover");

    let banner: String = function_banner(&recovery, 0x108).expect("banner for add");
    assert!(
        banner.starts_with("add "),
        "banner should start with add: {banner}"
    );
    assert!(banner.contains("hello.c"));

    let loc: SourceLocation = line_for_pc(&recovery, 0x110).expect("line for 0x110");
    assert_eq!(loc.line, 2);
    assert!(loc.file.ends_with("hello.c"));

    assert!(function_banner(&recovery, 0xDEAD_BEEF).is_none());
    assert!(line_for_pc(&recovery, 0).is_none());
}
