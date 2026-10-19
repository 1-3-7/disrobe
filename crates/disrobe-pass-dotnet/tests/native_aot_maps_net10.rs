#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::sync::OnceLock;

use disrobe_pass_dotnet::aot::{
    AotManifestResource, AotMetadataStatus, AotMethod, AotReport, AotResourceStatus,
    AotStackTraceMethod, AotStackTraceName, AotStackTraceStatus, AotType, ReadyToRunHeader, detect,
    manifest_resource_data,
};

const FIXTURE: &str = "corpus/dotnet/aot/aot_maps_net10_x86_64";
const MODULE_PREFIX: &str = "aot_maps_net10_x86_64_";
const PROGRAM_NAMESPACE: &str = "Tidewater.Gauges";
const LINKER_OBJECT: &str = "aot_maps_net10_x86_64.obj";

fn fixture(name: &str, max_bytes: u64) -> Vec<u8> {
    let path: String = format!("{FIXTURE}/{name}");
    disrobe_testkit::load_fixture(&path, max_bytes)
        .unwrap_or_else(|error| panic!("fixture {path} is missing or unreadable: {error}"))
}

fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| fixture("aot_maps_net10_x86_64.exe", 4 * 1024 * 1024))
}

fn report() -> &'static AotReport {
    static REPORT: OnceLock<AotReport> = OnceLock::new();
    REPORT.get_or_init(|| detect(image()))
}

struct LinkMap {
    symbols: BTreeMap<u32, Vec<String>>,
}

fn link_map() -> &'static LinkMap {
    static MAP: OnceLock<LinkMap> = OnceLock::new();
    MAP.get_or_init(|| {
        let compressed: Vec<u8> =
            fixture("aot_maps_net10_x86_64.link-map-managed.txt.gz", 1024 * 1024);
        let mut text: String = String::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .take(16 * 1024 * 1024)
            .read_to_string(&mut text)
            .expect("the linker map excerpt decompresses");
        let base: u64 = text
            .lines()
            .find_map(|line: &str| line.split_once("Preferred load address is "))
            .map(|(_, value): (&str, &str)| {
                u64::from_str_radix(value.trim(), 16).expect("load address is hexadecimal")
            })
            .expect("the linker map names its load address");
        let mut symbols: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [section, name, address, object] = fields.as_slice() else {
                continue;
            };
            if !section.starts_with("0001:") || *object != LINKER_OBJECT {
                continue;
            }
            let address: u64 = u64::from_str_radix(address, 16).expect("symbol address is hex");
            let rva: u32 = u32::try_from(address - base).expect("symbol RVA fits u32");
            symbols.entry(rva).or_default().push((*name).to_owned());
        }
        assert!(
            symbols.len() > 1_000,
            "the linker map excerpt lost its symbols"
        );
        LinkMap { symbols }
    })
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|character: char| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn strip_instantiations(symbol: &str) -> String {
    let mut depth: usize = 0;
    let mut stripped: String = String::with_capacity(symbol.len());
    for character in symbol.chars() {
        match character {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => stripped.push(character),
            _ => {}
        }
    }
    stripped
}

fn method_suffix_matches(stripped: &str, method_name: &str) -> bool {
    let needle: String = format!("__{}", sanitize(method_name));
    let Some(position): Option<usize> = stripped.rfind(&needle) else {
        return false;
    };
    let rest: &str = &stripped[position + needle.len()..];
    rest.is_empty()
        || rest.strip_prefix('_').is_some_and(|digits: &str| {
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        })
}

fn well_known_symbol_name(type_name: &str) -> &str {
    match type_name {
        "Boolean" => "Bool",
        "Byte" => "UInt8",
        "SByte" => "Int8",
        other => other,
    }
}

fn symbol_names_method(symbol: &str, name: &AotStackTraceName) -> bool {
    let stripped: String = strip_instantiations(symbol);
    let qualified: String = name.namespace.as_ref().map_or_else(
        || name.type_name.clone(),
        |namespace: &String| format!("{namespace}.{}", name.type_name),
    );
    let qualified_owner: bool = stripped.contains(&format!("{}__", sanitize(&qualified)));
    let well_known_owner: bool = name.namespace.as_deref() == Some("System")
        && stripped.starts_with(&format!("{}__", well_known_symbol_name(&name.type_name)));
    (qualified_owner || well_known_owner) && method_suffix_matches(&stripped, &name.method_name)
}

fn is_program_method(symbol: &str) -> bool {
    let program: String = format!("{MODULE_PREFIX}{}_", sanitize(PROGRAM_NAMESPACE));
    symbol.starts_with(&program) && !symbol.contains("____GetFieldHelper")
}

fn stub_target(symbol: &str) -> Option<String> {
    if let Some(target) = symbol.strip_prefix("unbox_") {
        return Some(target.to_owned());
    }
    let (owner, unboxed): (&str, &str) = symbol.strip_prefix("<Boxed>")?.split_once("__<unbox>")?;
    let (_, method): (&str, &str) = unboxed.rsplit_once("__")?;
    Some(format!("{owner}__{method}"))
}

fn reflection_named_bodies(report: &AotReport, map: &LinkMap) -> BTreeSet<String> {
    let mut named: BTreeSet<String> = BTreeSet::new();
    for method in &report.metadata_attribution.methods {
        for rva in method
            .entrypoint_rva
            .iter()
            .chain(method.instantiation_entrypoint_rvas.iter())
        {
            for symbol in map.symbols.get(rva).into_iter().flatten() {
                named.insert(symbol.clone());
                named.extend(stub_target(symbol));
            }
        }
    }
    named
}

fn grade_stack_trace(
    methods: &[AotStackTraceMethod],
    reflection_named: &BTreeSet<String>,
    map: &LinkMap,
) -> Vec<String> {
    let mut failures: Vec<String> = Vec::new();
    let mut recovered: BTreeMap<u32, &AotStackTraceMethod> = BTreeMap::new();
    for method in methods {
        recovered.insert(method.rva, method);
        let Some(symbols): Option<&Vec<String>> = map.symbols.get(&method.rva) else {
            failures.push(format!("0x{:x} is not a linker symbol start", method.rva));
            continue;
        };
        let Some(name): Option<&AotStackTraceName> = method.name.as_ref() else {
            continue;
        };
        if !symbols
            .iter()
            .any(|symbol: &String| symbol_names_method(symbol, name))
        {
            failures.push(format!(
                "0x{:x} {:?}.{} {} matches none of {symbols:?}",
                method.rva, name.namespace, name.type_name, name.method_name
            ));
        }
    }
    for (rva, symbols) in &map.symbols {
        let expected: bool = symbols
            .iter()
            .any(|symbol: &String| is_program_method(symbol))
            && !symbols
                .iter()
                .any(|symbol: &String| reflection_named.contains(symbol));
        if !expected {
            continue;
        }
        match recovered.get(rva).and_then(|method| method.name.as_ref()) {
            Some(name) if name.namespace.as_deref() == Some(PROGRAM_NAMESPACE) => {}
            _ => failures.push(format!(
                "program method {symbols:?} at 0x{rva:x} is named by neither map"
            )),
        }
    }
    failures
}

fn program_type<'a>(types: &'a [AotType], name: &str) -> &'a AotType {
    types
        .iter()
        .find(|candidate: &&AotType| {
            candidate.name == name && candidate.namespace.as_deref() == Some(PROGRAM_NAMESPACE)
        })
        .unwrap_or_else(|| panic!("{PROGRAM_NAMESPACE}.{name} is attributed"))
}

fn grade_invoke_entrypoints(report: &AotReport, map: &LinkMap) -> (usize, Vec<String>) {
    let attribution = &report.metadata_attribution;
    let mut graded: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for type_name in ["Readings", "Station`1", "Sample`1"] {
        let owner: &AotType = program_type(&attribution.types, type_name);
        let owner_symbol: String = format!(
            "{MODULE_PREFIX}{}_{}",
            sanitize(PROGRAM_NAMESPACE),
            sanitize(type_name)
        );
        for method in attribution.methods.iter().filter(|method: &&AotMethod| {
            owner.method_record_offsets.contains(&method.record_offset)
        }) {
            for rva in method
                .entrypoint_rva
                .iter()
                .chain(method.instantiation_entrypoint_rvas.iter())
            {
                graded += 1;
                let matches: bool = map.symbols.get(rva).is_some_and(|symbols: &Vec<String>| {
                    symbols.iter().any(|symbol: &String| {
                        let stripped: String = strip_instantiations(symbol);
                        stripped.contains(&owner_symbol)
                            && method_suffix_matches(&stripped, &method.name)
                    })
                });
                if !matches {
                    failures.push(format!(
                        "{type_name}.{} entrypoint 0x{rva:x} matches no linker symbol {:?}",
                        method.name,
                        map.symbols.get(rva)
                    ));
                }
            }
        }
    }
    (graded, failures)
}

#[test]
fn generic_invoke_map_entrypoints_match_the_linker_map() {
    let report: &AotReport = report();
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    assert!(
        report.invoke_map_refusals.is_empty(),
        "{:?}",
        report.invoke_map_refusals
    );
    let (graded, failures): (usize, Vec<String>) = grade_invoke_entrypoints(report, link_map());
    assert!(failures.is_empty(), "{failures:#?}");
    assert!(
        graded >= 12,
        "only {graded} program entrypoints were graded"
    );
}

#[test]
fn invoke_map_grader_rejects_a_shifted_entrypoint() {
    let mut mutated: AotReport = report().clone();
    let echo: &mut AotMethod = mutated
        .metadata_attribution
        .methods
        .iter_mut()
        .find(|method: &&mut AotMethod| method.name == "Echo")
        .expect("Echo is attributed");
    let first: &mut u32 = echo
        .instantiation_entrypoint_rvas
        .first_mut()
        .expect("Echo has instantiation entrypoints");
    *first += 0x10;
    let (_graded, failures): (usize, Vec<String>) = grade_invoke_entrypoints(&mutated, link_map());
    assert_eq!(failures.len(), 1, "{failures:#?}");
}

#[test]
fn stack_trace_map_names_every_method_at_its_linker_address() {
    let report: &AotReport = report();
    let map = &report.stack_trace_map;
    assert_eq!(map.status, AotStackTraceStatus::Recovered);
    assert!(map.refusals.is_empty(), "{:?}", map.refusals);
    assert!(map.methods.len() > 3_000, "{} methods", map.methods.len());
    let reflection_named: BTreeSet<String> = reflection_named_bodies(report, link_map());
    let failures: Vec<String> = grade_stack_trace(&map.methods, &reflection_named, link_map());
    assert!(
        failures.is_empty(),
        "{} failures: {failures:#?}",
        failures.len()
    );
    let with_range: usize = map
        .methods
        .iter()
        .filter(|method: &&AotStackTraceMethod| {
            method
                .code_range
                .is_some_and(|range| range.start_rva == method.rva && range.end_rva > method.rva)
        })
        .count();
    assert_eq!(with_range, map.methods.len());
}

#[test]
fn stack_trace_map_names_program_methods_exactly() {
    let mut named: Vec<(String, String, Vec<String>, bool)> = report()
        .stack_trace_map
        .methods
        .iter()
        .filter_map(|method: &AotStackTraceMethod| {
            let name: &AotStackTraceName = method.name.as_ref()?;
            (name.namespace.as_deref() == Some(PROGRAM_NAMESPACE)).then(|| {
                (
                    name.type_name.clone(),
                    name.method_name.clone(),
                    name.method_generic_arguments.clone(),
                    method.stack_trace_hidden,
                )
            })
        })
        .collect();
    named.sort();
    let owned = |type_name: &str, method: &str, arguments: &[&str], hidden: bool| {
        (
            type_name.to_owned(),
            method.to_owned(),
            arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect::<Vec<String>>(),
            hidden,
        )
    };
    let mut expected: Vec<(String, String, Vec<String>, bool)> = vec![
        owned("Ring`1", "Peek", &[], false),
        owned("Ring`1", "Peek", &[], false),
        owned("Ring`1", "Push", &[], false),
        owned("Ring`1", "Push", &[], false),
        owned("Smoothing", "Average", &[], false),
        owned("Smoothing", "Clamp", &[], true),
        owned("Smoothing", "Pick", &["T"], false),
        owned("Smoothing", "Pick", &["T"], false),
        owned("Smoothing+Window", "Span", &[], false),
    ];
    expected.sort();
    assert_eq!(named, expected);
}

#[test]
fn stack_trace_grader_rejects_swapped_names_and_shifted_addresses() {
    let report: &AotReport = report();
    let methods: &[AotStackTraceMethod] = &report.stack_trace_map.methods;
    let reflection_named: BTreeSet<String> = reflection_named_bodies(report, link_map());
    let positions: Vec<usize> = methods
        .iter()
        .enumerate()
        .filter(|(_, method)| {
            method.name.as_ref().is_some_and(|name| {
                name.namespace.as_deref() == Some(PROGRAM_NAMESPACE)
                    && name.type_name == "Smoothing"
            })
        })
        .map(|(index, _)| index)
        .collect();
    let (first, second): (usize, usize) = positions
        .iter()
        .copied()
        .find_map(|first: usize| {
            positions
                .iter()
                .copied()
                .find(|second: &usize| {
                    methods[first].name.as_ref().map(|name| &name.method_name)
                        != methods[*second].name.as_ref().map(|name| &name.method_name)
                })
                .map(|second: usize| (first, second))
        })
        .expect("two differently named Smoothing methods are recovered");
    let mut swapped: Vec<AotStackTraceMethod> = methods.to_vec();
    let first_name: Option<AotStackTraceName> = swapped[first].name.clone();
    swapped[first].name = swapped[second].name.clone();
    swapped[second].name = first_name;
    assert_eq!(
        grade_stack_trace(&swapped, &reflection_named, link_map()).len(),
        2
    );

    let mut shifted: Vec<AotStackTraceMethod> = methods.to_vec();
    shifted[first].rva += 1;
    assert!(!grade_stack_trace(&shifted, &reflection_named, link_map()).is_empty());

    let mut dropped: Vec<AotStackTraceMethod> = methods.to_vec();
    dropped.remove(first);
    assert_eq!(
        grade_stack_trace(&dropped, &reflection_named, link_map()).len(),
        1
    );
}

#[test]
fn stack_trace_names_survive_without_the_invoke_map() {
    let original: &AotReport = report();
    let mut header: ReadyToRunHeader = original
        .ready_to_run
        .clone()
        .expect("the image has a NativeAOT header");
    header.sections.retain(|section| section.id != 306);
    let without_invoke_map = disrobe_pass_dotnet::aot::recover_stack_trace_map(image(), &header);
    assert_eq!(without_invoke_map, original.stack_trace_map);
}

#[test]
fn manifest_resources_match_their_source_files() {
    let report: &AotReport = report();
    let index = &report.manifest_resources;
    assert_eq!(index.status, AotResourceStatus::Recovered);
    assert!(index.refusals.is_empty(), "{:?}", index.refusals);
    let header: &ReadyToRunHeader = report.ready_to_run.as_ref().expect("NativeAOT header");
    for (logical, file) in [
        (
            "Tidewater.Gauges.tide_table.json",
            "resources/tide_table.json",
        ),
        (
            "Tidewater.Gauges.gauge_curve.bin",
            "resources/gauge_curve.bin",
        ),
    ] {
        let resource: &AotManifestResource = index
            .resources
            .iter()
            .find(|resource: &&AotManifestResource| resource.name == logical)
            .unwrap_or_else(|| panic!("{logical} is indexed: {:?}", index.resources));
        assert!(
            resource.assembly.starts_with("aot_maps_net10_x86_64,"),
            "{}",
            resource.assembly
        );
        let recovered: &[u8] =
            manifest_resource_data(image(), header, resource).expect("resource data is in range");
        assert_eq!(
            recovered,
            fixture(file, 1024 * 1024).as_slice(),
            "{logical}"
        );
    }
}

#[test]
fn manifest_resource_grader_rejects_a_shifted_range() {
    let report: &AotReport = report();
    let header: &ReadyToRunHeader = report.ready_to_run.as_ref().expect("NativeAOT header");
    let mut resource: AotManifestResource = report
        .manifest_resources
        .resources
        .iter()
        .find(|resource: &&AotManifestResource| resource.name == "Tidewater.Gauges.gauge_curve.bin")
        .expect("gauge_curve.bin is indexed")
        .clone();
    resource.data_offset = match resource.data_offset.checked_sub(1) {
        Some(earlier) => earlier,
        None => resource.data_offset + 1,
    };
    let shifted: &[u8] =
        manifest_resource_data(image(), header, &resource).expect("shifted range stays in bounds");
    assert_ne!(
        shifted,
        fixture("resources/gauge_curve.bin", 1024 * 1024).as_slice()
    );
}

fn section(id: i32) -> disrobe_pass_dotnet::aot::AotSection {
    *report()
        .ready_to_run
        .as_ref()
        .and_then(|header: &ReadyToRunHeader| header.section(id))
        .unwrap_or_else(|| panic!("section {id} is present"))
}

fn file_offset(rva: u32) -> usize {
    use object::{Object as _, ObjectSection as _};
    let file: object::File<'_, &[u8]> = object::File::parse(image()).expect("fixture parses");
    let address: u64 = file.relative_address_base() + u64::from(rva);
    file.sections()
        .find_map(|candidate| {
            let (start, size): (u64, u64) = candidate.file_range()?;
            let begin: u64 = candidate.address();
            (address >= begin && address < begin + size)
                .then(|| usize::try_from(start + (address - begin)).expect("offset fits usize"))
        })
        .unwrap_or_else(|| panic!("RVA 0x{rva:x} is file backed"))
}

fn patched(section_id: i32, offset: u32, bytes: &[u8]) -> Vec<u8> {
    let mut image: Vec<u8> = image().to_vec();
    let at: usize = file_offset(section(section_id).start_rva + offset);
    image[at..at + bytes.len()].copy_from_slice(bytes);
    image
}

const STACK_TRACE_MAP: i32 = 327;

#[test]
fn stack_trace_command_with_unknown_bits_refuses_the_map_by_name() {
    let report: AotReport = detect(&patched(STACK_TRACE_MAP, 4, &[0x20]));
    let AotStackTraceStatus::Rejected { reason, .. } = &report.stack_trace_map.status else {
        panic!("unknown command bits were accepted");
    };
    assert!(reason.contains("DR-DOTNET-0036"), "{reason}");
    assert!(reason.contains("unknown bits"), "{reason}");
    assert!(report.stack_trace_map.methods.is_empty());
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
}

#[test]
fn stack_trace_entry_count_beyond_the_stream_refuses_the_map() {
    let declared: i32 = i32::try_from(report().stack_trace_map.methods.len()).expect("count fits");
    let report: AotReport = detect(&patched(STACK_TRACE_MAP, 0, &(declared + 1).to_le_bytes()));
    let AotStackTraceStatus::Rejected { reason, .. } = &report.stack_trace_map.status else {
        panic!("a header count beyond the stream was accepted");
    };
    assert!(reason.contains("fewer entries"), "{reason}");
}

#[test]
fn stack_trace_pointer_outside_code_refuses_only_that_entry() {
    let original: &AotReport = report();
    let map_rva: u32 = section(STACK_TRACE_MAP).start_rva;
    let first_command: u8 = {
        let at: usize = file_offset(map_rva + 4);
        image()[at]
    };
    assert_eq!(
        first_command, 0x10,
        "the first entry is a hidden startup method"
    );
    let delta: i32 = -i32::try_from(map_rva + 5).expect("map RVA fits i32");
    let report: AotReport = detect(&patched(STACK_TRACE_MAP, 5, &delta.to_le_bytes()));
    let map = &report.stack_trace_map;
    assert_eq!(map.status, AotStackTraceStatus::Recovered);
    assert_eq!(
        map.methods.len() + 1,
        original.stack_trace_map.methods.len()
    );
    assert_eq!(map.refusals.len(), 1, "{:?}", map.refusals);
    assert_eq!(map.refusals[0].entry_offset, 4);
    assert!(
        map.refusals[0].reason.contains("executable code"),
        "{}",
        map.refusals[0].reason
    );
}

#[test]
fn resource_outside_a_truncated_data_blob_is_refused_by_name() {
    let mut header: ReadyToRunHeader = report().ready_to_run.clone().expect("NativeAOT header");
    let resources: &[AotManifestResource] = &report().manifest_resources.resources;
    let last: &AotManifestResource = resources
        .iter()
        .max_by_key(|resource: &&AotManifestResource| resource.data_offset)
        .expect("resources are indexed");
    let data: &mut disrobe_pass_dotnet::aot::AotSection = header
        .sections
        .iter_mut()
        .find(|candidate| candidate.id == 325)
        .expect("resource data section");
    data.end_rva = data.start_rva + last.data_offset;
    let index = disrobe_pass_dotnet::aot::recover_manifest_resources(image(), &header);
    assert_eq!(index.status, AotResourceStatus::Recovered);
    assert_eq!(index.resources.len() + 1, resources.len());
    assert_eq!(index.refusals.len(), 1, "{:?}", index.refusals);
    assert_eq!(index.refusals[0].name.as_deref(), Some(last.name.as_str()));
    assert!(
        index.refusals[0].reason.contains("outside the data blob"),
        "{}",
        index.refusals[0].reason
    );
}

#[test]
fn mutated_maps_never_panic() {
    let mut state: u64 = 0x5eed_0fa0_7a11_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let targets: Vec<disrobe_pass_dotnet::aot::AotSection> = [306, 308, 313, 324, 325, 327]
        .into_iter()
        .map(section)
        .collect();
    for _ in 0..96 {
        let mut image: Vec<u8> = image().to_vec();
        for _ in 0..=(next() % 8) {
            let target = targets[usize::try_from(next() % 6).expect("index fits")];
            let span: u64 = u64::from(target.end_rva - target.start_rva).max(1);
            let rva: u32 = target.start_rva + u32::try_from(next() % span).expect("offset fits");
            let at: usize = file_offset(rva);
            image[at] = u8::try_from(next() & 0xff).expect("byte fits");
        }
        let report: AotReport = detect(&image);
        let methods: &[AotStackTraceMethod] = &report.stack_trace_map.methods;
        assert!(methods.windows(2).all(|pair| pair[0].rva <= pair[1].rva));
    }
}

#[test]
fn stack_trace_names_survive_a_refused_exception_directory() {
    let mut image: Vec<u8> = image().to_vec();
    let pe: usize = usize::try_from(u32::from_le_bytes(
        image[0x3c..0x40].try_into().expect("PE offset"),
    ))
    .expect("PE offset fits usize");
    let size_at: usize = pe + 24 + 112 + 3 * 8 + 4;
    let size: u32 = u32::from_le_bytes(image[size_at..size_at + 4].try_into().expect("size"));
    image[size_at..size_at + 4].copy_from_slice(&(size - 1).to_le_bytes());
    let report: AotReport = detect(&image);
    assert!(matches!(
        report.metadata_attribution.status,
        AotMetadataStatus::Rejected { .. }
    ));
    let map = &report.stack_trace_map;
    assert_eq!(map.status, AotStackTraceStatus::Recovered);
    assert_eq!(map.methods, report_methods_without_ranges());
    let refusal: &str = map
        .code_range_refusal
        .as_deref()
        .expect("the exception directory refusal is named");
    assert!(refusal.contains("DR-DOTNET-0038"), "{refusal}");
}

fn report_methods_without_ranges() -> Vec<AotStackTraceMethod> {
    report()
        .stack_trace_map
        .methods
        .iter()
        .cloned()
        .map(|mut method: AotStackTraceMethod| {
            method.code_range = None;
            method
        })
        .collect()
}
