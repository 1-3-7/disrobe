#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{
    DelphiClass, DelphiEra, DelphiForm, DelphiInitTable, DelphiOrigin, DelphiReport,
    DelphiSignalKind, DelphiString, DelphiStringKind, DelphiTypeInfo, DelphiVersionSignal, analyze,
    classify_unit, detect_delphi, recover_delphi_classes, recover_delphi_strings,
    recover_dfm_resources,
};

const FORM1_HEX: &str = "545046300654466F726D3105466F726D31044C65667403C80003546F7002640557696474680340010648656967687403F0000743617074696F6E060C4C6F67696E2057696E646F7705436F6C6F720709636C42746E4661636507456E61626C6564090756697369626C650803546167022A0B426F7264657249636F6E730B0C626953797374656D4D656E750A62694D696E696D697A65000B426F726465725374796C65070862734469616C6F6700055445646974054564697431044C656674021003546F70021005576964746802790454657874060975736572206E616D6508526561644F6E6C790800000754427574746F6E07427574746F6E31044C656674021003546F70023C0743617074696F6E06034F274B0744656661756C74090B4D6F64616C526573756C740201000000";

const FORM1_EXPECTED: &str = "object Form1: TForm1
  Left = 200
  Top = 100
  Width = 320
  Height = 240
  Caption = 'Login Window'
  Color = clBtnFace
  Enabled = True
  Visible = False
  Tag = 42
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsDialog
  object Edit1: TEdit
    Left = 16
    Top = 16
    Width = 121
    Text = 'user name'
    ReadOnly = False
  end
  object Button1: TButton
    Left = 16
    Top = 60
    Caption = 'O''K'
    Default = True
    ModalResult = 1
  end
end
";

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 2);
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        let hi: u8 = (bytes[i] as char).to_digit(16).unwrap() as u8;
        let lo: u8 = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn form1_bin() -> Vec<u8> {
    hex_to_bytes(FORM1_HEX)
}

fn form2_bin() -> Vec<u8> {
    let prefix: &str = "54504630095444617461466F726D0844617461466F726D044C65667404A086010003546F7002FB035461670478FDFF7F054974656D7301020A0214021E00054E6F7465730C11010000";
    let full: String = format!("{prefix}{}5A0000", "61".repeat(272));
    hex_to_bytes(&full)
}

fn form2_expected() -> String {
    let long: String = format!("{}Z", "a".repeat(272));
    format!(
        "object DataForm: TDataForm\n  Left = 100000\n  Top = -5\n  Tag = 2147483000\n  Items = (\n    10\n    20\n    30\n  )\n  Notes = '{long}'\nend\n"
    )
}

#[test]
fn dfm_decode_form1_matches_the_pinned_expectation() {
    let forms: Vec<DelphiForm> = vec![decode_standalone(&form1_bin())];
    assert_eq!(forms[0].text, FORM1_EXPECTED);
    assert_eq!(forms[0].root_class, "TForm1");
    assert_eq!(forms[0].object_count, 3);
    assert!(!forms[0].truncated);
}

#[test]
fn dfm_decode_form2_matches_the_pinned_expectation() {
    let decoded: DelphiForm = decode_standalone(&form2_bin());
    assert_eq!(decoded.text, form2_expected());
    assert_eq!(decoded.root_class, "TDataForm");
    assert!(!decoded.truncated);
}

fn decode_standalone(dfm: &[u8]) -> DelphiForm {
    let pe: Vec<u8> = pe_with_dfm_resource("TFORM1", dfm);
    let forms: Vec<DelphiForm> = recover_dfm_resources(&pe);
    assert_eq!(forms.len(), 1, "expected exactly one TPF0 resource");
    forms.into_iter().next().unwrap()
}

#[test]
fn resource_walk_reports_resource_name() {
    let pe: Vec<u8> = pe_with_dfm_resource("TFORM1", &form1_bin());
    let forms: Vec<DelphiForm> = recover_dfm_resources(&pe);
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0].resource_name, "TFORM1");
    assert!(detect_delphi(&pe));
}

#[test]
fn dfm_decode_partial_on_unknown_value_type() {
    let mut dfm: Vec<u8> = b"TPF0".to_vec();
    dfm.extend([2]);
    dfm.extend(b"TX");
    dfm.extend([0]);
    dfm.extend([1]);
    dfm.extend(b"P");
    dfm.extend([0xEE]);
    let decoded: super::dfm::DfmDecoded = super::dfm::decode(&dfm).expect("still a TPF0 stream");
    assert!(decoded.truncated);
    assert!(!decoded.notes.is_empty());
    assert!(decoded.text.contains("P = "));
}

#[test]
fn recover_modern32_classes_with_props_methods_inheritance() {
    let (blob, _base): (Vec<u8>, u64) = build_modern32_blob();
    let pe: Vec<u8> = pe_with_code_and_data(blob);
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    assert_eq!(classes.len(), 2, "expected TBase and TChild");

    let base: &DelphiClass = find_class(&classes, "TBase");
    assert_eq!(base.era, DelphiEra::Modern32);
    assert_eq!(base.parent, None);
    assert_eq!(base.unit_name.as_deref(), Some("Unit1"));
    assert!(
        base.properties
            .iter()
            .any(|p: &super::DelphiProperty| p.name == "Caption"
                && p.type_name.as_deref() == Some("AnsiString")
                && p.inherited_from.is_none())
    );

    let child: &DelphiClass = find_class(&classes, "TChild");
    assert_eq!(child.parent.as_deref(), Some("TBase"));
    assert!(
        child
            .properties
            .iter()
            .any(|p: &super::DelphiProperty| p.name == "Value"
                && p.type_name.as_deref() == Some("Integer")
                && p.inherited_from.is_none())
    );
    assert!(
        child
            .properties
            .iter()
            .any(|p: &super::DelphiProperty| p.name == "Caption"
                && p.inherited_from.as_deref() == Some("TBase"))
    );
    assert!(
        child
            .methods
            .iter()
            .any(|m: &super::DelphiMethod| m.name == "DoIt")
    );
}

#[test]
fn detect_legacy32_variant() {
    let blob: Vec<u8> = build_single_class_blob(T_LEGACY32, "TLegacy", data_va());
    let pe: Vec<u8> = pe_with_code_and_data(blob);
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    assert_eq!(classes.len(), 1);
    assert_eq!(classes[0].name, "TLegacy");
    assert_eq!(classes[0].era, DelphiEra::Legacy32);
}

#[test]
fn detect_modern64_variant() {
    let base: u64 = 0x1_4000_0000;
    let blob: Vec<u8> = build_single_class_blob(T_MODERN64, "TWin64", base + 0x2000);
    let pe: Vec<u8> = build_pe(true, base, &[(".data".to_owned(), 0x2000, blob)], None);
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    assert_eq!(classes.len(), 1);
    assert_eq!(classes[0].name, "TWin64");
    assert_eq!(classes[0].era, DelphiEra::Modern64);
}

#[test]
fn analyze_reports_no_rtti_when_absent() {
    let junk: Vec<u8> = (0..0x800u16)
        .map(|i: u16| (i.wrapping_mul(37) & 0xFF) as u8)
        .collect();
    let pe: Vec<u8> = pe_with_code_and_data(junk);
    let report: DelphiReport = analyze(&pe);
    assert!(!report.rtti_present);
    assert!(report.classes.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("no Delphi RTTI"))
    );
}

#[cfg(windows)]
const SYSTEM_DLLS: [&str; 4] = [
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\shell32.dll",
];

#[test]
#[cfg(windows)]
fn no_validated_classes_on_real_system_dlls() {
    let mut checked: usize = 0;
    for path in SYSTEM_DLLS {
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(path) else {
            continue;
        };
        checked += 1;
        let report: DelphiReport = analyze(&bytes);
        assert!(
            report.classes.is_empty(),
            "{path} unexpectedly produced validated Delphi classes: {}",
            report.classes.len()
        );
        assert!(!report.rtti_present, "{path} unexpectedly reported RTTI");
        assert!(
            report.types.is_empty(),
            "{path} unexpectedly produced recovered type records"
        );
        assert_eq!(report.library_class_count, 0);
        assert_eq!(report.author_class_count, 0);
        assert!(
            report.version.product.is_none(),
            "{path} must not be named as a Delphi release"
        );
    }
    assert!(checked > 0, "no real system DLL was readable for the check");
}

#[test]
#[cfg(windows)]
fn no_published_tables_recovered_from_real_system_dlls() {
    let mut checked: usize = 0;
    for path in SYSTEM_DLLS {
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(path) else {
            continue;
        };
        checked += 1;
        for class in recover_delphi_classes(&bytes) {
            assert!(
                class.fields.is_empty(),
                "{path} produced published fields on {}",
                class.name
            );
            assert!(
                class.dynamic_methods.is_empty(),
                "{path} produced dynamic methods on {}",
                class.name
            );
            assert!(
                class.interfaces.is_empty(),
                "{path} produced interface entries on {}",
                class.name
            );
        }
    }
    assert!(checked > 0, "no real system DLL was readable for the check");
}

#[test]
fn detect_delphi_marker_in_bytes() {
    let mut buf: Vec<u8> = b"MZ".to_vec();
    buf.extend(std::iter::repeat_n(0u8, 128));
    buf.extend_from_slice(b"compiled with Embarcadero Delphi 12");
    assert!(detect_delphi(&buf));
}

#[test]
fn dfm_deep_value_nesting_is_bounded_not_stack_overflow() {
    let mut dfm: Vec<u8> = b"TPF0".to_vec();
    dfm.extend([1]);
    dfm.extend(b"T");
    dfm.extend([0]);
    dfm.extend([1]);
    dfm.extend(b"p");
    dfm.extend(std::iter::repeat_n(1u8, 200_000));
    let decoded: super::dfm::DfmDecoded = super::dfm::decode(&dfm).expect("still a TPF0 stream");
    assert!(decoded.truncated);
    assert!(
        decoded
            .notes
            .iter()
            .any(|n: &String| n.contains("nesting exceeded the depth cap"))
    );
}

fn build_deep_property_bomb(levels: usize, props_at_leaf: usize) -> Vec<u8> {
    let mut dfm: Vec<u8> = b"TPF0".to_vec();
    for _ in 0..levels {
        dfm.extend([1u8, b'T', 0u8, 0u8]);
    }
    dfm.extend([1u8, b'T', 0u8]);
    for _ in 0..props_at_leaf {
        dfm.extend([1u8, b'p', 8u8]);
    }
    dfm.extend([0u8, 0u8]);
    dfm.extend(std::iter::repeat_n(0u8, levels));
    dfm
}

#[test]
fn dfm_deep_nesting_output_is_capped_not_gigabytes() {
    let dfm: Vec<u8> = build_deep_property_bomb(300, 40_000);
    assert!(
        dfm.len() < 256 * 1024,
        "crafted input stays small: {} bytes",
        dfm.len()
    );
    let decoded: super::dfm::DfmDecoded = super::dfm::decode(&dfm).expect("still a TPF0 stream");
    assert!(decoded.truncated);
    assert!(decoded.text.len() <= super::dfm::MAX_OUTPUT_BYTES);
    assert!(decoded.text.len() > 1024 * 1024);
    assert!(
        decoded
            .notes
            .iter()
            .any(|n: &String| n.contains("output size"))
    );
}

#[test]
fn hardening_never_panics_on_garbage() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8],
        b"MZ".to_vec(),
        b"TPF0".to_vec(),
        b"TPF0\x01".to_vec(),
        vec![0xFFu8; 64],
        (0..4096u16)
            .map(|i: u16| (i.wrapping_mul(101) & 0xFF) as u8)
            .collect(),
    ];
    for input in &inputs {
        let _ = analyze(input);
        let _ = recover_delphi_classes(input);
        let _ = recover_dfm_resources(input);
        let _ = detect_delphi(input);
        let _ = super::dfm::decode(input);
    }
    let mut truncated_pe: Vec<u8> = pe_with_code_and_data(build_modern32_blob().0);
    truncated_pe.truncate(truncated_pe.len() / 2);
    let _ = analyze(&truncated_pe);
}

#[test]
fn library_unit_table_stays_sorted_and_lowercase() {
    let names: Vec<&str> = super::units::library_unit_names().to_vec();
    assert!(!names.is_empty());
    let mut sorted: Vec<&str> = names.clone();
    sorted.sort_unstable();
    assert_eq!(
        names, sorted,
        "the runtime library unit table must stay sorted because lookup uses a binary search"
    );
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        names.len(),
        "duplicate unit name in the table"
    );
    for name in &names {
        assert_eq!(
            *name,
            name.to_ascii_lowercase(),
            "unit table entries are compared lowercased"
        );
    }
}

#[test]
fn unit_classification_splits_author_code_from_the_runtime_library() {
    assert_eq!(
        classify_unit(Some("SysUtils")),
        DelphiOrigin::RuntimeLibrary
    );
    assert_eq!(
        classify_unit(Some("System.Classes")),
        DelphiOrigin::RuntimeLibrary
    );
    assert_eq!(
        classify_unit(Some("Vcl.Forms")),
        DelphiOrigin::RuntimeLibrary
    );
    assert_eq!(classify_unit(Some("uPayloadDropper")), DelphiOrigin::Author);
    assert_eq!(classify_unit(None), DelphiOrigin::Unattributed);
}

#[test]
fn field_table_recovers_names_offsets_and_class_types() {
    let pe: Vec<u8> = pe_with_code_and_data(build_field_table_blob(false));
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    let form: &DelphiClass = find_class(&classes, "TMainForm");

    assert_eq!(form.fields.len(), 2, "both published fields recovered");
    assert_eq!(form.fields[0].name, "Edit1");
    assert_eq!(form.fields[0].offset, 0x10);
    assert_eq!(form.fields[0].type_name.as_deref(), Some("TEdit"));
    assert_eq!(form.fields[1].name, "Button1");
    assert_eq!(form.fields[1].offset, 0x14);
    assert_eq!(form.fields[1].type_name.as_deref(), Some("TEdit"));
}

#[test]
fn field_table_is_rejected_whole_when_an_offset_escapes_the_instance() {
    let pe: Vec<u8> = pe_with_code_and_data(build_field_table_blob(true));
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    let form: &DelphiClass = find_class(&classes, "TMainForm");
    assert!(
        form.fields.is_empty(),
        "one out-of-range field offset must reject the whole table, got {:?}",
        form.fields
    );
}

#[test]
fn dynamic_method_table_recovers_message_handlers() {
    let pe: Vec<u8> = pe_with_code_and_data(build_dynamic_table_blob(code_va()));
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    let cls: &DelphiClass = find_class(&classes, "TWinControl");
    assert_eq!(cls.dynamic_methods.len(), 2);
    assert_eq!(cls.dynamic_methods[0].index, 0x0F);
    assert_eq!(cls.dynamic_methods[0].address, code_va());
    assert_eq!(cls.dynamic_methods[1].index, -3);
    assert_eq!(cls.dynamic_methods[1].address, code_va() + 0x20);
}

#[test]
fn dynamic_method_table_is_rejected_when_an_address_is_not_code() {
    let pe: Vec<u8> = pe_with_code_and_data(build_dynamic_table_blob(data_va()));
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    let cls: &DelphiClass = find_class(&classes, "TWinControl");
    assert!(
        cls.dynamic_methods.is_empty(),
        "an address outside an executable section must reject the whole table"
    );
}

#[test]
fn interface_table_recovers_the_interface_identifier() {
    let pe: Vec<u8> = pe_with_code_and_data(build_interface_table_blob());
    let classes: Vec<DelphiClass> = recover_delphi_classes(&pe);
    let cls: &DelphiClass = find_class(&classes, "TComObject");
    assert_eq!(cls.interfaces.len(), 1);
    assert_eq!(
        cls.interfaces[0].iid,
        "{00000000-0000-0000-C000-000000000046}"
    );
}

#[test]
fn enumeration_property_recovers_every_member_name() {
    let pe: Vec<u8> = pe_with_code_and_data(build_enum_blob());
    let report: DelphiReport = analyze(&pe);
    let align: &DelphiTypeInfo = report
        .types
        .iter()
        .find(|t: &&DelphiTypeInfo| t.name == "TAlign")
        .expect("TAlign type recovered");
    assert_eq!(align.kind, "enumeration");
    assert_eq!(align.min_value, Some(0));
    assert_eq!(align.max_value, Some(3));
    assert_eq!(
        align.members,
        vec![
            "alNone".to_owned(),
            "alTop".to_owned(),
            "alBottom".to_owned(),
            "alClient".to_owned()
        ]
    );
    assert_eq!(align.unit_name.as_deref(), Some("Controls"));
}

#[test]
fn version_resolves_from_a_linked_runtime_package_name() {
    let mut pe: Vec<u8> = pe_with_code_and_data(build_modern32_blob().0);
    pe.extend_from_slice(b"rtl250.bpl\x00");
    let report: DelphiReport = analyze(&pe);
    assert_eq!(report.version.product.as_deref(), Some("Delphi 10.2 Tokyo"));
    assert_eq!(report.version.package_version, Some(250));
    assert_eq!(report.version.ver_symbol.as_deref(), Some("VER320"));
    assert!(report.version.conflicts.is_empty());
    assert!(
        report
            .version
            .signals
            .iter()
            .any(|s: &DelphiVersionSignal| s.evidence == "rtl250.bpl")
    );
}

#[test]
fn version_reports_a_conflict_instead_of_picking_a_winner() {
    let blob: Vec<u8> = build_single_class_blob(T_LEGACY32, "TLegacy", data_va());
    let mut pe: Vec<u8> = pe_with_code_and_data(blob);
    pe.extend_from_slice(b"rtl280.bpl\x00");
    let report: DelphiReport = analyze(&pe);
    assert_eq!(report.era, Some(DelphiEra::Legacy32));
    assert!(
        report.version.product.is_none(),
        "a pre-2009 table layout cannot hold with a Delphi 11 runtime package"
    );
    assert!(!report.version.conflicts.is_empty());
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("signals disagree"))
    );
}

#[test]
fn version_stays_silent_when_nothing_bounds_it() {
    let junk: Vec<u8> = (0..0x800u16)
        .map(|i: u16| (i.wrapping_mul(37) & 0xFF) as u8)
        .collect();
    let pe: Vec<u8> = pe_with_code_and_data(junk);
    let report: DelphiReport = analyze(&pe);
    assert!(report.version.product.is_none());
    assert!(report.version.candidates.is_empty());
    assert!(report.version.conflicts.is_empty());
}

#[test]
fn dotted_unit_scope_names_bound_the_release_from_below_only() {
    let pe: Vec<u8> = pe_with_code_and_data(build_scoped_unit_blob());
    let report: DelphiReport = analyze(&pe);
    let signal: &DelphiVersionSignal = report
        .version
        .signals
        .iter()
        .find(|s: &&DelphiVersionSignal| s.kind == DelphiSignalKind::UnitScopeNames)
        .expect("dotted unit scope signal present");
    assert_eq!(signal.min_package, Some(160));
    assert_eq!(signal.max_package, None);
}

#[test]
fn undotted_unit_names_assert_no_version_bound() {
    let pe: Vec<u8> = pe_with_code_and_data(build_modern32_blob().0);
    let report: DelphiReport = analyze(&pe);
    assert!(
        !report
            .version
            .signals
            .iter()
            .any(|s: &DelphiVersionSignal| s.kind == DelphiSignalKind::UnitScopeNames),
        "an undotted unit name proves nothing because unit scope names can be switched off"
    );
}

#[test]
fn author_classes_are_counted_apart_from_runtime_library_classes() {
    let pe: Vec<u8> = pe_with_code_and_data(build_mixed_origin_blob());
    let report: DelphiReport = analyze(&pe);
    assert_eq!(report.library_class_count, 1);
    assert_eq!(report.author_class_count, 1);
    let dropper: &DelphiClass = find_class(&report.classes, "TDropper");
    assert_eq!(dropper.origin, DelphiOrigin::Author);
    let control: &DelphiClass = find_class(&report.classes, "TControl");
    assert_eq!(control.origin, DelphiOrigin::RuntimeLibrary);
}

fn build_string_pool_blob() -> Vec<u8> {
    let mut b: Blob = Blob::new(data_va(), 4);
    let _legacy: u64 = b.put_legacy_string("legacy literal", 0xFFFF_FFFF);
    let _ansi: u64 = b.put_ansi_string(1252, "ansi literal");
    let _unicode: u64 = b.put_unicode_string("unicode literal");
    let _live: u64 = b.put_legacy_string("runtime allocated", 3);
    let _cut: u64 = b.put_unterminated_string("no terminator here");
    let _padding: u64 = {
        b.align(4);
        b.put_u32(0xFFFF_FFFF);
        b.put_u32(5);
        let at: u64 = b.va(b.buf.len());
        b.put_bytes(&[0xFF, 0xFF, 0xFF, 0xFF, 0x50]);
        b.put_u8(0);
        at
    };
    b.buf
}

#[test]
fn string_pool_recovers_each_literal_shape() {
    let pe: Vec<u8> = pe_with_code_and_data(build_string_pool_blob());
    let found: Vec<DelphiString> = recover_delphi_strings(&pe);
    let texts: Vec<&str> = found
        .iter()
        .map(|s: &DelphiString| s.text.as_str())
        .collect();

    assert!(
        texts.contains(&"legacy literal"),
        "pre-2009 header not recovered, got {texts:?}"
    );
    assert!(
        texts.contains(&"ansi literal"),
        "code page header not recovered, got {texts:?}"
    );
    assert!(
        texts.contains(&"unicode literal"),
        "UTF-16 header not recovered, got {texts:?}"
    );

    let unicode: &DelphiString = found
        .iter()
        .find(|s: &&DelphiString| s.text == "unicode literal")
        .expect("UTF-16 literal present");
    assert_eq!(unicode.kind, DelphiStringKind::Unicode);
    assert_eq!(unicode.code_page, Some(1200));

    let ansi: &DelphiString = found
        .iter()
        .find(|s: &&DelphiString| s.text == "ansi literal")
        .expect("code page literal present");
    assert_eq!(ansi.kind, DelphiStringKind::Ansi);
    assert_eq!(ansi.code_page, Some(1252));
}

#[test]
fn string_pool_refuses_a_live_reference_count_a_missing_terminator_and_filler() {
    let pe: Vec<u8> = pe_with_code_and_data(build_string_pool_blob());
    let found: Vec<DelphiString> = recover_delphi_strings(&pe);
    let texts: Vec<&str> = found
        .iter()
        .map(|s: &DelphiString| s.text.as_str())
        .collect();

    assert!(
        !texts.contains(&"runtime allocated"),
        "a positive reference count is not a compiled-in literal"
    );
    assert!(
        !texts.iter().any(|t: &&str| t.starts_with("no terminator")),
        "a length that does not land on a null must be refused"
    );
    assert!(
        !texts.iter().any(|t: &&str| t.contains('\u{00FF}')),
        "a run of filler bytes must not read as a literal, got {texts:?}"
    );
}

#[test]
#[cfg(windows)]
fn string_pool_finds_nothing_in_real_system_dlls() {
    let mut checked: usize = 0;
    for path in SYSTEM_DLLS {
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(path) else {
            continue;
        };
        checked += 1;
        let found: Vec<DelphiString> = recover_delphi_strings(&bytes);
        assert!(
            found.is_empty(),
            "{path} produced {} string literals, first {:?}",
            found.len(),
            found.first().map(|s: &DelphiString| s.text.clone())
        );
    }
    assert!(checked > 0, "no real system DLL was readable for the check");
}

fn delphi_entry_stub(table_va: u64) -> Vec<u8> {
    let mut stub: Vec<u8> = vec![0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xF0, 0xB8];
    stub.extend_from_slice(&(table_va as u32).to_le_bytes());
    stub.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3]);
    stub
}

fn pe_with_stub_and_data(stub: &[u8], blob: Vec<u8>) -> Vec<u8> {
    let mut text: Vec<u8> = vec![0x90u8; 0x200];
    text[..stub.len()].copy_from_slice(stub);
    build_pe_sections(
        false,
        FLAT_BASE32,
        &[
            Section {
                name: ".text".to_owned(),
                rva: TEXT_RVA,
                data: text,
                characteristics: SCN_CODE_EXEC_READ,
            },
            Section {
                name: ".data".to_owned(),
                rva: DATA_RVA,
                data: blob,
                characteristics: SCN_DATA_READ,
            },
        ],
        None,
    )
}

fn build_init_table_blob(units: &[(u64, u64)]) -> (Vec<u8>, u64) {
    let mut b: Blob = Blob::new(data_va(), 4);
    let table_va: u64 = b.va(0);
    b.put_u32(units.len() as u32);
    let (slot, _placeholder): (usize, u64) = b.reserve_ptr();
    let unit_table_va: u64 = b.va(b.buf.len());
    for (init, finalize) in units {
        b.put_ptr(*init);
        b.put_ptr(*finalize);
    }
    b.patch_ptr(slot, unit_table_va);
    (b.buf, table_va)
}

fn init_table_pe(units: &[(u64, u64)]) -> Vec<u8> {
    let (blob, table_va): (Vec<u8>, u64) = build_init_table_blob(units);
    pe_with_stub_and_data(&delphi_entry_stub(table_va), blob)
}

#[test]
fn entry_point_stub_leads_to_the_unit_initialization_table() {
    let units: [(u64, u64); 3] = [
        (code_va() + 0x40, code_va() + 0x60),
        (code_va() + 0x80, code_va() + 0xA0),
        (code_va() + 0xC0, 0),
    ];
    let report: DelphiReport = analyze(&init_table_pe(&units));
    let table: &DelphiInitTable = report
        .init_table
        .as_ref()
        .expect("the entry stub names a unit initialization table");

    assert_eq!(table.unit_count, 3);
    assert_eq!(table.initialized_units, 3);
    assert_eq!(table.finalized_units, 2);
    assert_eq!(table.units[0].init, code_va() + 0x40);
    assert_eq!(table.units[0].finalize, code_va() + 0x60);
    assert_eq!(table.units[2].init, code_va() + 0xC0);
    assert_eq!(table.units[2].finalize, 0);
}

#[test]
fn init_table_is_rejected_whole_when_a_unit_entry_leaves_the_code_sections() {
    let units: [(u64, u64); 3] = [
        (code_va() + 0x40, code_va() + 0x60),
        (data_va(), code_va() + 0xA0),
        (code_va() + 0xC0, 0),
    ];
    let report: DelphiReport = analyze(&init_table_pe(&units));
    assert!(
        report.init_table.is_none(),
        "one entry pointing outside an executable section must reject the whole table"
    );
}

#[test]
fn init_table_is_rejected_when_the_stub_names_nothing_parseable() {
    let junk: Vec<u8> = (0..0x400u16)
        .map(|i: u16| (i.wrapping_mul(37) & 0xFF) as u8)
        .collect();
    let pe: Vec<u8> = pe_with_stub_and_data(&delphi_entry_stub(data_va()), junk);
    let report: DelphiReport = analyze(&pe);
    assert!(report.init_table.is_none());
}

#[test]
#[cfg(windows)]
fn no_init_table_recovered_from_real_system_dlls() {
    let mut checked: usize = 0;
    for path in SYSTEM_DLLS {
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(path) else {
            continue;
        };
        checked += 1;
        let report: DelphiReport = analyze(&bytes);
        assert!(
            report.init_table.is_none(),
            "{path} produced a unit initialization table with {} units",
            report
                .init_table
                .as_ref()
                .map_or(0, |t: &DelphiInitTable| t.unit_count)
        );
    }
    assert!(checked > 0, "no real system DLL was readable for the check");
}

fn find_class<'a>(classes: &'a [DelphiClass], name: &str) -> &'a DelphiClass {
    classes
        .iter()
        .find(|c: &&DelphiClass| c.name == name)
        .unwrap_or_else(|| panic!("class {name} was not recovered"))
}

fn w16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn w32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn w64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

#[derive(Debug, Clone, Copy)]
struct TestLayout {
    ptr: usize,
    self_abs: usize,
    intf_table: i64,
    type_info: i64,
    field_table: i64,
    method_table: i64,
    dynamic_table: i64,
    class_name: i64,
    instance_size: i64,
    parent: i64,
}

const T_LEGACY32: TestLayout = TestLayout {
    ptr: 4,
    self_abs: 76,
    intf_table: -72,
    type_info: -60,
    field_table: -56,
    method_table: -52,
    dynamic_table: -48,
    class_name: -44,
    instance_size: -40,
    parent: -36,
};

const T_MODERN32: TestLayout = TestLayout {
    ptr: 4,
    self_abs: 88,
    intf_table: -84,
    type_info: -72,
    field_table: -68,
    method_table: -64,
    dynamic_table: -60,
    class_name: -56,
    instance_size: -52,
    parent: -48,
};

const T_MODERN64: TestLayout = TestLayout {
    ptr: 8,
    self_abs: 176,
    intf_table: -168,
    type_info: -144,
    field_table: -136,
    method_table: -128,
    dynamic_table: -120,
    class_name: -112,
    instance_size: -104,
    parent: -96,
};

#[derive(Debug, Clone, Copy, Default)]
struct VmtSpec {
    class_name_va: u64,
    type_info_va: u64,
    method_table_va: u64,
    field_table_va: u64,
    dynamic_table_va: u64,
    intf_table_va: u64,
    instance_size: u32,
    parent_va: u64,
}

const TEXT_RVA: u32 = 0x1000;
const DATA_RVA: u32 = 0x2000;
const FLAT_BASE32: u64 = 0x0040_0000;
const SCN_CODE_EXEC_READ: u32 = 0x6000_0020;
const SCN_DATA_READ: u32 = 0x4000_0040;

const fn code_va() -> u64 {
    FLAT_BASE32 + TEXT_RVA as u64
}

const fn data_va() -> u64 {
    FLAT_BASE32 + DATA_RVA as u64
}

struct Section {
    name: String,
    rva: u32,
    data: Vec<u8>,
    characteristics: u32,
}

fn pe_with_code_and_data(blob: Vec<u8>) -> Vec<u8> {
    build_pe_sections(
        false,
        FLAT_BASE32,
        &[
            Section {
                name: ".text".to_owned(),
                rva: TEXT_RVA,
                data: vec![0x90u8; 0x200],
                characteristics: SCN_CODE_EXEC_READ,
            },
            Section {
                name: ".data".to_owned(),
                rva: DATA_RVA,
                data: blob,
                characteristics: SCN_DATA_READ,
            },
        ],
        None,
    )
}

fn build_pe_sections(
    plus: bool,
    image_base: u64,
    sections: &[Section],
    resource: Option<(u32, u32)>,
) -> Vec<u8> {
    let file_align: usize = 0x200;
    let sect_align: u32 = 0x1000;
    let opt_size: usize = if plus { 0xF0 } else { 0xE0 };
    let coff_off: usize = 0x84;
    let opt_off: usize = coff_off + 20;
    let sec_table_off: usize = opt_off + opt_size;
    let num: usize = sections.len();
    let raw_start: usize = align_up(sec_table_off + num * 40, file_align);

    let mut recs: Vec<(usize, usize)> = Vec::with_capacity(num);
    let mut cur: usize = raw_start;
    for section in sections {
        let rsize: usize = align_up(section.data.len().max(1), file_align);
        recs.push((cur, rsize));
        cur += rsize;
    }
    let file_size: usize = cur.max(raw_start + file_align);
    let mut buf: Vec<u8> = vec![0u8; file_size];

    buf[0] = b'M';
    buf[1] = b'Z';
    w32(&mut buf, 0x3C, 0x80);
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    let machine: u16 = if plus { 0x8664 } else { 0x014C };
    w16(&mut buf, coff_off, machine);
    w16(&mut buf, coff_off + 2, num as u16);
    w16(&mut buf, coff_off + 16, opt_size as u16);

    let magic: u16 = if plus { 0x020B } else { 0x010B };
    w16(&mut buf, opt_off, magic);
    w32(&mut buf, opt_off + 16, 0x1000);
    if plus {
        w64(&mut buf, opt_off + 24, image_base);
    } else {
        w32(&mut buf, opt_off + 28, image_base as u32);
    }
    w32(&mut buf, opt_off + 32, sect_align);
    w32(&mut buf, opt_off + 36, file_align as u32);
    let max_end: u32 = sections
        .iter()
        .map(|s: &Section| {
            let end: u32 = s.rva.saturating_add(s.data.len() as u32);
            end.div_ceil(sect_align) * sect_align
        })
        .max()
        .unwrap_or(0x2000);
    w32(&mut buf, opt_off + 56, max_end);

    let dir_count_off: usize = if plus { opt_off + 108 } else { opt_off + 92 };
    w32(&mut buf, dir_count_off, 16);
    let dir_table: usize = dir_count_off + 4;
    if let Some((rva, size)) = resource {
        w32(&mut buf, dir_table + 2 * 8, rva);
        w32(&mut buf, dir_table + 2 * 8 + 4, size);
    }

    for (i, section) in sections.iter().enumerate() {
        let (off, rsize): (usize, usize) = recs[i];
        let so: usize = sec_table_off + i * 40;
        let mut nm: [u8; 8] = [0u8; 8];
        let nb: &[u8] = section.name.as_bytes();
        let n: usize = nb.len().min(8);
        nm[..n].copy_from_slice(&nb[..n]);
        buf[so..so + 8].copy_from_slice(&nm);
        w32(&mut buf, so + 8, section.data.len() as u32);
        w32(&mut buf, so + 12, section.rva);
        w32(&mut buf, so + 16, rsize as u32);
        w32(&mut buf, so + 20, off as u32);
        w32(&mut buf, so + 36, section.characteristics);
        buf[off..off + section.data.len()].copy_from_slice(&section.data);
    }

    buf
}

fn build_pe(
    plus: bool,
    image_base: u64,
    sections: &[(String, u32, Vec<u8>)],
    resource: Option<(u32, u32)>,
) -> Vec<u8> {
    let mapped: Vec<Section> = sections
        .iter()
        .map(|(name, rva, data): &(String, u32, Vec<u8>)| Section {
            name: name.clone(),
            rva: *rva,
            data: data.clone(),
            characteristics: SCN_DATA_READ,
        })
        .collect();
    build_pe_sections(plus, image_base, &mapped, resource)
}

fn pe_with_dfm_resource(res_name: &str, dfm: &[u8]) -> Vec<u8> {
    let res_base_rva: u32 = 0x4000;
    let (rsrc, size): (Vec<u8>, u32) = build_rsrc(res_base_rva, res_name, dfm);
    build_pe(
        false,
        FLAT_BASE32,
        &[(".rsrc".to_owned(), res_base_rva, rsrc)],
        Some((res_base_rva, size)),
    )
}

fn build_rsrc(res_base_rva: u32, res_name: &str, dfm: &[u8]) -> (Vec<u8>, u32) {
    let dir1_off: usize = 0;
    let dir2_off: usize = 24;
    let dir3_off: usize = 48;
    let name_off: usize = 72;
    let name_bytes: usize = 2 + res_name.len() * 2;
    let data_entry_off: usize = align_up(name_off + name_bytes, 4);
    let dfm_off: usize = align_up(data_entry_off + 16, 4);
    let total: usize = dfm_off + dfm.len();
    let mut buf: Vec<u8> = vec![0u8; total];

    w16(&mut buf, dir1_off + 12, 0);
    w16(&mut buf, dir1_off + 14, 1);
    w32(&mut buf, dir1_off + 16, 10);
    w32(&mut buf, dir1_off + 20, 0x8000_0000 | dir2_off as u32);

    w16(&mut buf, dir2_off + 12, 1);
    w16(&mut buf, dir2_off + 14, 0);
    w32(&mut buf, dir2_off + 16, 0x8000_0000 | name_off as u32);
    w32(&mut buf, dir2_off + 20, 0x8000_0000 | dir3_off as u32);

    w16(&mut buf, dir3_off + 12, 0);
    w16(&mut buf, dir3_off + 14, 1);
    w32(&mut buf, dir3_off + 16, 0x0409);
    w32(&mut buf, dir3_off + 20, data_entry_off as u32);

    w16(&mut buf, name_off, res_name.len() as u16);
    for (i, ch) in res_name.encode_utf16().enumerate() {
        w16(&mut buf, name_off + 2 + i * 2, ch);
    }

    w32(&mut buf, data_entry_off, res_base_rva + dfm_off as u32);
    w32(&mut buf, data_entry_off + 4, dfm.len() as u32);

    buf[dfm_off..dfm_off + dfm.len()].copy_from_slice(dfm);
    (buf, total as u32)
}

fn short_string(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = vec![s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

struct Blob {
    buf: Vec<u8>,
    base_va: u64,
    ptr: usize,
}

impl Blob {
    fn new(base_va: u64, ptr: usize) -> Self {
        Self {
            buf: Vec::new(),
            base_va,
            ptr,
        }
    }

    fn va(&self, off: usize) -> u64 {
        self.base_va + off as u64
    }

    fn align(&mut self, a: usize) {
        while self.buf.len() % a != 0 {
            self.buf.push(0);
        }
    }

    fn put_bytes(&mut self, b: &[u8]) -> usize {
        let at: usize = self.buf.len();
        self.buf.extend_from_slice(b);
        at
    }

    fn put_ss(&mut self, s: &str) -> u64 {
        let at: usize = self.put_bytes(&short_string(s));
        self.va(at)
    }

    fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn put_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn put_ptr(&mut self, v: u64) {
        if self.ptr == 8 {
            self.buf.extend_from_slice(&v.to_le_bytes());
        } else {
            self.buf.extend_from_slice(&(v as u32).to_le_bytes());
        }
    }

    fn reserve_ptr(&mut self) -> (usize, u64) {
        self.align(self.ptr);
        let at: usize = self.buf.len();
        let va: u64 = self.va(at);
        self.buf.extend(std::iter::repeat_n(0u8, self.ptr));
        (at, va)
    }

    fn patch_ptr(&mut self, at: usize, value: u64) {
        if self.ptr == 8 {
            self.buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
        } else {
            self.buf[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
    }

    fn put_simple_typeinfo(&mut self, kind: u8, name: &str) -> u64 {
        self.align(4);
        let at: u64 = self.va(self.buf.len());
        self.put_u8(kind);
        self.put_bytes(&short_string(name));
        at
    }

    fn put_enum_typeinfo(
        &mut self,
        name: &str,
        min: i32,
        max: i32,
        members: &[&str],
        unit: &str,
    ) -> u64 {
        self.align(4);
        let at: u64 = self.va(self.buf.len());
        self.put_u8(3);
        self.put_bytes(&short_string(name));
        self.put_u8(1);
        self.put_u32(min as u32);
        self.put_u32(max as u32);
        self.put_ptr(0);
        for member in members {
            self.put_bytes(&short_string(member));
        }
        self.put_bytes(&short_string(unit));
        at
    }

    fn put_class_typeinfo(&mut self, name: &str, unit: &str, props: &[(&str, u64)]) -> u64 {
        self.align(4);
        let at: u64 = self.va(self.buf.len());
        self.put_u8(7);
        self.put_bytes(&short_string(name));
        self.put_ptr(0);
        self.put_ptr(0);
        self.put_u16(props.len() as u16);
        self.put_bytes(&short_string(unit));
        self.put_u16(props.len() as u16);
        for (pname, ptype) in props {
            self.put_ptr(*ptype);
            self.put_ptr(0);
            self.put_ptr(0);
            self.put_ptr(0);
            self.put_u32(0);
            self.put_u32(0);
            self.put_u16(0);
            self.put_bytes(&short_string(pname));
        }
        at
    }

    fn put_method_table(&mut self, methods: &[(&str, u64)]) -> u64 {
        self.align(4);
        let at: u64 = self.va(self.buf.len());
        self.put_u16(methods.len() as u16);
        for (name, addr) in methods {
            let size: u16 = (2 + self.ptr + 1 + name.len()) as u16;
            self.put_u16(size);
            self.put_ptr(*addr);
            self.put_bytes(&short_string(name));
        }
        at
    }

    fn put_field_class_table(&mut self, count: u16) -> (u64, Vec<usize>) {
        self.align(self.ptr);
        let at: u64 = self.va(self.buf.len());
        self.put_u16(count);
        let mut slots: Vec<usize> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let start: usize = self.buf.len();
            self.buf.extend(std::iter::repeat_n(0u8, self.ptr));
            slots.push(start);
        }
        (at, slots)
    }

    fn put_field_table(&mut self, class_tab_va: u64, entries: &[(&str, u32, u16)]) -> u64 {
        self.align(self.ptr);
        let at: u64 = self.va(self.buf.len());
        self.put_u16(entries.len() as u16);
        self.put_ptr(class_tab_va);
        for (name, offset, type_index) in entries {
            self.put_u32(*offset);
            self.put_u16(*type_index);
            self.put_bytes(&short_string(name));
        }
        at
    }

    fn put_dynamic_table(&mut self, entries: &[(i16, u64)]) -> u64 {
        self.align(self.ptr);
        let at: u64 = self.va(self.buf.len());
        self.put_u16(entries.len() as u16);
        for (index, _addr) in entries {
            self.put_u16(*index as u16);
        }
        for (_index, addr) in entries {
            self.put_ptr(*addr);
        }
        at
    }

    fn put_interface_table(&mut self, entries: &[([u8; 16], u64, i32)]) -> u64 {
        self.align(self.ptr);
        let at: u64 = self.va(self.buf.len());
        self.put_u32(entries.len() as u32);
        for (iid, vtable, instance_offset) in entries {
            self.put_bytes(iid);
            self.put_ptr(*vtable);
            self.put_u32(*instance_offset as u32);
            self.put_u32(0);
        }
        at
    }

    fn put_legacy_string(&mut self, text: &str, refcount: u32) -> u64 {
        self.align(4);
        self.put_u32(refcount);
        self.put_u32(text.len() as u32);
        let at: u64 = self.va(self.buf.len());
        self.put_bytes(text.as_bytes());
        self.put_u8(0);
        at
    }

    fn put_ansi_string(&mut self, code_page: u16, text: &str) -> u64 {
        self.align(4);
        self.put_u16(code_page);
        self.put_u16(1);
        self.put_u32(0xFFFF_FFFF);
        self.put_u32(text.len() as u32);
        let at: u64 = self.va(self.buf.len());
        self.put_bytes(text.as_bytes());
        self.put_u8(0);
        at
    }

    fn put_unicode_string(&mut self, text: &str) -> u64 {
        let units: Vec<u16> = text.encode_utf16().collect();
        self.align(4);
        self.put_u16(1200);
        self.put_u16(2);
        self.put_u32(0xFFFF_FFFF);
        self.put_u32(units.len() as u32);
        let at: u64 = self.va(self.buf.len());
        for unit in units {
            self.put_u16(unit);
        }
        self.put_u16(0);
        at
    }

    fn put_unterminated_string(&mut self, text: &str) -> u64 {
        self.align(4);
        self.put_u32(0xFFFF_FFFF);
        self.put_u32(text.len() as u32);
        let at: u64 = self.va(self.buf.len());
        self.put_bytes(text.as_bytes());
        self.put_u8(b'!');
        at
    }

    fn write_slot(&mut self, anchor: i64, slot: i64, value: u64, ptr: usize) {
        let at: usize = (anchor + slot) as usize;
        if ptr == 8 {
            self.buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
        } else {
            self.buf[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
    }

    fn put_vmt(&mut self, layout: TestLayout, spec: &VmtSpec) -> u64 {
        self.align(layout.ptr);
        let region_off: usize = self.buf.len();
        let class_va: u64 = self.va(region_off + layout.self_abs);
        self.buf
            .extend(std::iter::repeat_n(0u8, layout.self_abs + 4 * layout.ptr));

        let anchor: i64 = region_off as i64 + layout.self_abs as i64;
        self.write_slot(anchor, -(layout.self_abs as i64), class_va, layout.ptr);
        self.write_slot(anchor, layout.intf_table, spec.intf_table_va, layout.ptr);
        self.write_slot(anchor, layout.type_info, spec.type_info_va, layout.ptr);
        self.write_slot(anchor, layout.field_table, spec.field_table_va, layout.ptr);
        self.write_slot(
            anchor,
            layout.method_table,
            spec.method_table_va,
            layout.ptr,
        );
        self.write_slot(
            anchor,
            layout.dynamic_table,
            spec.dynamic_table_va,
            layout.ptr,
        );
        self.write_slot(anchor, layout.class_name, spec.class_name_va, layout.ptr);
        self.write_slot(anchor, layout.parent, spec.parent_va, layout.ptr);

        let size_at: usize = (anchor + layout.instance_size) as usize;
        self.buf[size_at..size_at + 4].copy_from_slice(&spec.instance_size.to_le_bytes());
        class_va
    }
}

fn build_modern32_blob() -> (Vec<u8>, u64) {
    let base_va: u64 = data_va();
    let mut b: Blob = Blob::new(base_va, 4);
    let cn_base: u64 = b.put_ss("TBase");
    let cn_child: u64 = b.put_ss("TChild");
    let ti_int: u64 = b.put_simple_typeinfo(1, "Integer");
    let ti_astr: u64 = b.put_simple_typeinfo(10, "AnsiString");
    let ti_base: u64 = b.put_class_typeinfo("TBase", "Unit1", &[("Caption", ti_astr)]);
    let ti_child: u64 = b.put_class_typeinfo("TChild", "Unit1", &[("Value", ti_int)]);
    let mt_child: u64 = b.put_method_table(&[("DoIt", code_va())]);
    let c_base: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn_base,
            type_info_va: ti_base,
            instance_size: 20,
            ..VmtSpec::default()
        },
    );
    let _c_child: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn_child,
            type_info_va: ti_child,
            method_table_va: mt_child,
            instance_size: 24,
            parent_va: c_base,
            ..VmtSpec::default()
        },
    );
    (b.buf, base_va)
}

fn build_single_class_blob(layout: TestLayout, name: &str, base_va: u64) -> Vec<u8> {
    let mut b: Blob = Blob::new(base_va, layout.ptr);
    let cn_va: u64 = b.put_ss(name);
    let _c: u64 = b.put_vmt(
        layout,
        &VmtSpec {
            class_name_va: cn_va,
            instance_size: if layout.ptr == 8 { 32 } else { 16 },
            ..VmtSpec::default()
        },
    );
    b.buf
}

fn build_field_table_blob(escape_instance: bool) -> Vec<u8> {
    let mut b: Blob = Blob::new(data_va(), 4);
    let cn_edit: u64 = b.put_ss("TEdit");
    let cn_form: u64 = b.put_ss("TMainForm");

    let (cell_at, cell_va): (usize, u64) = b.reserve_ptr();
    let (class_tab_va, class_slots): (u64, Vec<usize>) = b.put_field_class_table(1);

    let first_offset: u32 = if escape_instance { 0x400 } else { 0x10 };
    let field_table_va: u64 = b.put_field_table(
        class_tab_va,
        &[("Edit1", first_offset, 0), ("Button1", 0x14, 0)],
    );

    let edit_va: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn_edit,
            instance_size: 0x20,
            ..VmtSpec::default()
        },
    );
    let _form_va: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn_form,
            field_table_va,
            instance_size: 0x40,
            ..VmtSpec::default()
        },
    );

    b.patch_ptr(cell_at, edit_va);
    b.patch_ptr(class_slots[0], cell_va);
    b.buf
}

fn build_dynamic_table_blob(address_base: u64) -> Vec<u8> {
    let mut b: Blob = Blob::new(data_va(), 4);
    let cn: u64 = b.put_ss("TWinControl");
    let dynamic_table_va: u64 =
        b.put_dynamic_table(&[(0x0F, address_base), (-3, address_base + 0x20)]);
    let _va: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn,
            dynamic_table_va,
            instance_size: 0x30,
            ..VmtSpec::default()
        },
    );
    b.buf
}

fn build_interface_table_blob() -> Vec<u8> {
    const IUNKNOWN: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    let mut b: Blob = Blob::new(data_va(), 4);
    let cn: u64 = b.put_ss("TComObject");
    let intf_table_va: u64 = b.put_interface_table(&[(IUNKNOWN, code_va(), 0)]);
    let _va: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn,
            intf_table_va,
            instance_size: 0x28,
            ..VmtSpec::default()
        },
    );
    b.buf
}

fn build_enum_blob() -> Vec<u8> {
    let mut b: Blob = Blob::new(data_va(), 4);
    let cn: u64 = b.put_ss("TPanel");
    let ti_align: u64 = b.put_enum_typeinfo(
        "TAlign",
        0,
        3,
        &["alNone", "alTop", "alBottom", "alClient"],
        "Controls",
    );
    let ti_panel: u64 = b.put_class_typeinfo("TPanel", "ExtCtrls", &[("Align", ti_align)]);
    let _va: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn,
            type_info_va: ti_panel,
            instance_size: 0x30,
            ..VmtSpec::default()
        },
    );
    b.buf
}

fn build_scoped_unit_blob() -> Vec<u8> {
    let mut b: Blob = Blob::new(data_va(), 4);
    let cn: u64 = b.put_ss("TCustomForm");
    let ti: u64 = b.put_class_typeinfo("TCustomForm", "Vcl.Forms", &[]);
    let _va: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn,
            type_info_va: ti,
            instance_size: 0x40,
            ..VmtSpec::default()
        },
    );
    b.buf
}

fn build_mixed_origin_blob() -> Vec<u8> {
    let mut b: Blob = Blob::new(data_va(), 4);
    let cn_control: u64 = b.put_ss("TControl");
    let cn_dropper: u64 = b.put_ss("TDropper");
    let ti_control: u64 = b.put_class_typeinfo("TControl", "Controls", &[]);
    let ti_dropper: u64 = b.put_class_typeinfo("TDropper", "uPayload", &[]);
    let _c: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn_control,
            type_info_va: ti_control,
            instance_size: 0x20,
            ..VmtSpec::default()
        },
    );
    let _d: u64 = b.put_vmt(
        T_MODERN32,
        &VmtSpec {
            class_name_va: cn_dropper,
            type_info_va: ti_dropper,
            instance_size: 0x24,
            ..VmtSpec::default()
        },
    );
    b.buf
}
