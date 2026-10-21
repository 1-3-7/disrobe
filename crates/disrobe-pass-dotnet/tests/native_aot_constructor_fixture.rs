#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::OnceLock;

use disrobe_pass_dotnet::aot::{
    AotMetadataStatus, AotObjectConstant, AotObjectFieldInitializer, AotObjectMethodEvidence,
    AotObjectModel, AotObjectModelStatus, AotReport, detect, recover_object_model,
};

const FIXTURE: &str = "corpus/dotnet/aot/aot_ctor_net10_x86_64";
const NAMESPACE: &str = "Tidewater.Moorings";
const BERTH_CTOR_SYMBOL: &str = "aot_ctor_net10_x86_64_Tidewater_Moorings_Berth___ctor";
const BUOY_CTOR_SYMBOL: &str = "aot_ctor_net10_x86_64_Tidewater_Moorings_Buoy___ctor";
const REFERENCE_FIELDS: [&str; 1] = ["_name"];

fn fixture(name: &str) -> Vec<u8> {
    let path: String = format!("{FIXTURE}/{name}");
    disrobe_testkit::load_fixture(&path, 4 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("fixture {path} is missing or unreadable: {error}"))
}

fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| fixture("aot_ctor_net10_x86_64.exe"))
}

fn report() -> &'static AotReport {
    static REPORT: OnceLock<AotReport> = OnceLock::new();
    REPORT.get_or_init(|| detect(image()))
}

fn managed_symbols() -> &'static [(String, u32)] {
    static SYMBOLS: OnceLock<Vec<(String, u32)>> = OnceLock::new();
    SYMBOLS.get_or_init(|| {
        let compressed: Vec<u8> = fixture("aot_ctor_net10_x86_64.link-map-managed.txt.gz");
        let mut text: String = String::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .take(16 * 1024 * 1024)
            .read_to_string(&mut text)
            .unwrap_or_else(|error| panic!("link map decompresses: {error}"));
        let base: u64 = text
            .lines()
            .find_map(|line| line.split_once("Preferred load address is "))
            .map(|(_, value)| u64::from_str_radix(value.trim(), 16))
            .transpose()
            .unwrap_or_else(|error| panic!("link map load address is hexadecimal: {error}"))
            .unwrap_or_else(|| panic!("link map names its load address"));
        text.lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let [section, symbol, address, object] = fields.as_slice() else {
                    return None;
                };
                if !section.starts_with("0001:") || *object != "aot_ctor_net10_x86_64.obj" {
                    return None;
                }
                let address: u64 = u64::from_str_radix(address, 16).ok()?;
                let rva: u32 = u32::try_from(address.checked_sub(base)?).ok()?;
                Some(((*symbol).to_owned(), rva))
            })
            .collect()
    })
}

fn constructor_evidence(
    report: &AotReport,
    symbol: &str,
    type_name: &str,
) -> AotObjectMethodEvidence {
    let symbols: &[(String, u32)] = managed_symbols();
    let index: usize = symbols
        .iter()
        .position(|(candidate, _)| candidate == symbol)
        .unwrap_or_else(|| panic!("link map names {symbol}"));
    let start_rva: u32 = symbols[index].1;
    let end_rva: u32 = symbols
        .get(index.saturating_add(1))
        .map_or_else(|| panic!("link map bounds {symbol}"), |(_, rva)| *rva);
    let owner = report
        .metadata_attribution
        .types
        .iter()
        .find(|type_record| {
            type_record.name == type_name && type_record.namespace.as_deref() == Some(NAMESPACE)
        })
        .unwrap_or_else(|| panic!("{type_name} type is attributed"));
    let method_record_offset: u32 = owner
        .method_record_offsets
        .iter()
        .copied()
        .find(|record_offset| {
            report
                .metadata_attribution
                .methods
                .iter()
                .any(|method| method.record_offset == *record_offset && method.name == ".ctor")
        })
        .unwrap_or_else(|| panic!("{type_name}..ctor metadata record is attributed"));
    AotObjectMethodEvidence {
        type_record_offset: owner.record_offset,
        method_record_offset,
        start_rva,
        end_rva,
    }
}

fn evidence(report: &AotReport) -> [AotObjectMethodEvidence; 2] {
    [
        constructor_evidence(report, BERTH_CTOR_SYMBOL, "Berth"),
        constructor_evidence(report, BUOY_CTOR_SYMBOL, "Buoy"),
    ]
}

fn recover(image: &[u8]) -> AotObjectModel {
    let report: &AotReport = report();
    recover_object_model(
        image,
        &report.metadata_attribution,
        report.object_model.type_layouts.clone(),
        &evidence(report),
        &[],
    )
}

fn parse_integer(literal: &str) -> i128 {
    let (negative, digits): (bool, &str) = literal
        .strip_prefix('-')
        .map_or((false, literal), |rest| (true, rest));
    let magnitude: i128 = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .map_or_else(
            || digits.parse::<i128>(),
            |hex| i128::from_str_radix(hex, 16),
        )
        .unwrap_or_else(|error| panic!("integer literal {literal} parses: {error}"));
    if negative { -magnitude } else { magnitude }
}

fn expected_constant(
    field_type: &str,
    literal: &str,
    enums: &BTreeMap<String, BTreeMap<String, i128>>,
) -> Option<AotObjectConstant> {
    let constant: AotObjectConstant = match field_type {
        "bool" => AotObjectConstant::Byte(u8::from(literal == "true")),
        "byte" => AotObjectConstant::Byte(u8::try_from(parse_integer(literal)).expect("byte")),
        "sbyte" => {
            AotObjectConstant::Byte(i8::try_from(parse_integer(literal)).expect("sbyte") as u8)
        }
        "short" => {
            AotObjectConstant::Word(i16::try_from(parse_integer(literal)).expect("short") as u16)
        }
        "ushort" => AotObjectConstant::Word(u16::try_from(parse_integer(literal)).expect("ushort")),
        "char" => {
            let character: char = literal
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
                .and_then(|inner| inner.chars().next())
                .unwrap_or_else(|| panic!("char literal {literal} is quoted"));
            AotObjectConstant::Word(u16::try_from(u32::from(character)).expect("BMP char"))
        }
        "int" => {
            AotObjectConstant::Dword(i32::try_from(parse_integer(literal)).expect("int") as u32)
        }
        "uint" => AotObjectConstant::Dword(u32::try_from(parse_integer(literal)).expect("uint")),
        "long" => {
            AotObjectConstant::Qword(i64::try_from(parse_integer(literal)).expect("long") as u64)
        }
        "ulong" => AotObjectConstant::Qword(u64::try_from(parse_integer(literal)).expect("ulong")),
        "float" => AotObjectConstant::Dword(
            literal
                .strip_suffix('f')
                .unwrap_or(literal)
                .parse::<f32>()
                .unwrap_or_else(|error| panic!("float literal {literal} parses: {error}"))
                .to_bits(),
        ),
        "double" => AotObjectConstant::Qword(
            literal
                .parse::<f64>()
                .unwrap_or_else(|error| panic!("double literal {literal} parses: {error}"))
                .to_bits(),
        ),
        "string" => return None,
        other => {
            let (enum_name, member): (&str, &str) = literal
                .split_once('.')
                .unwrap_or_else(|| panic!("enum literal {literal} names its member"));
            assert_eq!(
                enum_name, other,
                "enum literal {literal} matches the field type"
            );
            let value: i128 = *enums
                .get(enum_name)
                .and_then(|members| members.get(member))
                .unwrap_or_else(|| panic!("enum member {literal} is declared"));
            AotObjectConstant::Dword(i32::try_from(value).expect("enum int") as u32)
        }
    };
    Some(constant)
}

type Expectations = BTreeMap<String, Option<AotObjectConstant>>;

fn source_expectations(source: &str) -> Expectations {
    let mut enums: BTreeMap<String, BTreeMap<String, i128>> = BTreeMap::new();
    let mut current_enum: Option<String> = None;
    let mut field_types: BTreeMap<String, String> = BTreeMap::new();
    let mut assignments: BTreeMap<String, String> = BTreeMap::new();
    for raw in source.lines() {
        let line: &str = raw.trim();
        if let Some(rest) = line.strip_prefix("internal enum ") {
            let name: &str = rest.split([' ', ':']).next().expect("enum name");
            current_enum = Some(name.to_owned());
            continue;
        }
        if let Some(name) = current_enum.as_deref() {
            if line == "}" {
                current_enum = None;
                continue;
            }
            if let Some((member, value)) = line.trim_end_matches(',').split_once(" = ") {
                enums
                    .entry(name.to_owned())
                    .or_default()
                    .insert(member.trim().to_owned(), parse_integer(value.trim()));
            }
            continue;
        }
        if let Some(declaration) = line.strip_prefix("private readonly ") {
            let (field_type, name): (&str, &str) = declaration
                .trim_end_matches(';')
                .split_once(' ')
                .expect("field declaration has a type and a name");
            assert!(
                field_types
                    .insert(name.to_owned(), field_type.to_owned())
                    .is_none(),
                "field {name} is declared once"
            );
            continue;
        }
        if line.starts_with('_')
            && let Some((name, literal)) = line.trim_end_matches(';').split_once(" = ")
        {
            assert!(
                assignments
                    .insert(name.to_owned(), literal.to_owned())
                    .is_none(),
                "field {name} is assigned once"
            );
        }
    }
    assert_eq!(
        field_types.len(),
        assignments.len(),
        "every declared field is assigned"
    );
    assignments
        .iter()
        .map(|(name, literal)| {
            let field_type: &str = field_types
                .get(name)
                .unwrap_or_else(|| panic!("assigned field {name} is declared"));
            (name.clone(), expected_constant(field_type, literal, &enums))
        })
        .collect()
}

fn expectations() -> &'static Expectations {
    static EXPECTATIONS: OnceLock<Expectations> = OnceLock::new();
    EXPECTATIONS.get_or_init(|| {
        let source: Vec<u8> = fixture("Program.cs");
        source_expectations(
            std::str::from_utf8(&source)
                .unwrap_or_else(|error| panic!("Program.cs is UTF-8: {error}")),
        )
    })
}

fn named_initializers(model: &AotObjectModel) -> BTreeMap<String, AotObjectConstant> {
    let mut named: BTreeMap<String, AotObjectConstant> = BTreeMap::new();
    for initializer in &model.field_initializers {
        let name: &str = initializer.field_name.as_deref().unwrap_or_else(|| {
            panic!(
                "initializer at 0x{:x} names its field",
                initializer.store_rva
            )
        });
        assert!(
            named.insert(name.to_owned(), initializer.value).is_none(),
            "field {name} has one initializer"
        );
    }
    named
}

fn compare(named: &BTreeMap<String, AotObjectConstant>, expected: &Expectations) -> Vec<String> {
    let mut mismatches: Vec<String> = Vec::new();
    for (name, constant) in expected {
        match (constant, named.get(name)) {
            (Some(expected), Some(recovered)) if expected == recovered => {}
            (Some(expected), recovered) => {
                mismatches.push(format!(
                    "{name}: expected {expected:?}, recovered {recovered:?}"
                ));
            }
            (None, Some(recovered)) => {
                mismatches.push(format!(
                    "{name}: reference field recovered as {recovered:?}"
                ));
            }
            (None, None) => {}
        }
    }
    for name in named.keys() {
        if !expected.contains_key(name) {
            mismatches.push(format!("{name}: initializer without a source assignment"));
        }
    }
    mismatches
}

#[test]
fn compiler_built_constructors_recover_every_constant_initializer_from_the_source() {
    let report: &AotReport = report();
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    let expected: &Expectations = expectations();
    assert_eq!(expected.len(), 52);
    let reference_fields: Vec<&str> = expected
        .iter()
        .filter_map(|(name, constant)| constant.is_none().then_some(name.as_str()))
        .collect();
    assert_eq!(reference_fields, REFERENCE_FIELDS);
    let model: AotObjectModel = recover(image());
    assert_eq!(model.status, AotObjectModelStatus::Recovered);
    let named: BTreeMap<String, AotObjectConstant> = named_initializers(&model);
    let mismatches: Vec<String> = compare(&named, expected);
    assert!(
        mismatches.is_empty(),
        "initializers disagree with the source:\n{}",
        mismatches.join("\n")
    );
    assert_eq!(named.len(), expected.len() - REFERENCE_FIELDS.len());
}

#[test]
fn a_mutated_source_expectation_turns_the_comparison_red() {
    let model: AotObjectModel = recover(image());
    let named: BTreeMap<String, AotObjectConstant> = named_initializers(&model);
    let mut expected: Expectations = expectations().clone();
    let slot = expected.get_mut("_depth").expect("_depth is expected");
    assert_eq!(*slot, Some(AotObjectConstant::Dword(123_456_789)));
    *slot = Some(AotObjectConstant::Dword(123_456_788));
    let mismatches: Vec<String> = compare(&named, &expected);
    assert_eq!(mismatches.len(), 1);
    assert!(mismatches[0].starts_with("_depth:"));
}

fn initializer_for<'a>(model: &'a AotObjectModel, name: &str) -> &'a AotObjectFieldInitializer {
    model
        .field_initializers
        .iter()
        .find(|initializer| initializer.field_name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("{name} initializer is recovered"))
}

fn file_offset(rva: u32) -> usize {
    disrobe_pass_dotnet::pe::parse(image())
        .unwrap_or_else(|error| panic!("fixture PE parses: {error}"))
        .rva_to_offset(rva)
        .unwrap_or_else(|| panic!("RVA 0x{rva:x} is file backed"))
}

#[test]
fn a_coalesced_store_names_each_field_it_covers_and_its_mutation_removes_both() {
    let baseline: AotObjectModel = recover(image());
    let lit: &AotObjectFieldInitializer = initializer_for(&baseline, "_lit");
    let lane: &AotObjectFieldInitializer = initializer_for(&baseline, "_lane");
    assert_eq!(lit.store_rva, lane.store_rva);
    assert_eq!(lane.field_offset, lit.field_offset + 1);
    assert_eq!(lit.value, AotObjectConstant::Byte(1));
    assert_eq!(lane.value, AotObjectConstant::Byte(200));
    let fender0: &AotObjectFieldInitializer = initializer_for(&baseline, "_fender0");
    let fender1: &AotObjectFieldInitializer = initializer_for(&baseline, "_fender1");
    assert_eq!(fender0.store_rva, fender1.store_rva);
    assert_eq!(fender1.field_offset, fender0.field_offset + 4);
    let mut mutated: Vec<u8> = image().to_vec();
    let at: usize = file_offset(lit.store_rva);
    assert_eq!(&mutated[at..at + 3], &[0x66, 0xc7, 0x81]);
    mutated[at..at + 9].copy_from_slice(&[0x90; 9]);
    let model: AotObjectModel = recover(mutated.as_slice());
    assert_eq!(model.status, AotObjectModelStatus::Recovered);
    assert!(model.field_initializers.iter().all(|initializer| {
        initializer.field_name.as_deref() != Some("_lit")
            && initializer.field_name.as_deref() != Some("_lane")
    }));
    assert_eq!(
        model.field_initializers.len(),
        baseline.field_initializers.len() - 2
    );
}

#[test]
fn a_register_materialized_constant_needs_its_adjacent_load() {
    let baseline: AotObjectModel = recover(image());
    let serial: &AotObjectFieldInitializer = initializer_for(&baseline, "_serial");
    assert_eq!(
        serial.value,
        AotObjectConstant::Qword(0x1122_3344_5566_7788)
    );
    let store_at: usize = file_offset(serial.store_rva);
    assert_eq!(&image()[store_at..store_at + 2], &[0x48, 0x89]);
    let load_at: usize = store_at - 10;
    assert_eq!(&image()[load_at..load_at + 2], &[0x48, 0xb8]);
    let mut mutated: Vec<u8> = image().to_vec();
    mutated[load_at..load_at + 10].copy_from_slice(&[0x90; 10]);
    let model: AotObjectModel = recover(mutated.as_slice());
    assert_eq!(model.status, AotObjectModelStatus::Recovered);
    assert!(
        model
            .field_initializers
            .iter()
            .all(|initializer| initializer.field_name.as_deref() != Some("_serial"))
    );
    assert_eq!(
        model.field_initializers.len(),
        baseline.field_initializers.len() - 1
    );
}
