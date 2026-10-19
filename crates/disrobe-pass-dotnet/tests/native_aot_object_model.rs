#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::io::Read as _;
use std::sync::OnceLock;

use disrobe_pass_dotnet::aot::{
    AotFieldLayout, AotMetadataStatus, AotObjectHelperEvidence, AotObjectHelperKind,
    AotObjectMethodEvidence, AotObjectModel, AotObjectModelRefusal, AotObjectModelStatus,
    AotObjectStoreWidth, AotReport, AotRuntimeFieldLayout, AotTypeSignature, AotTypeSignatureKind,
    detect, recover_object_model,
};
use sha2::{Digest as _, Sha256};

const FIXTURE: &str = "corpus/dotnet/aot/aot_maps_net10_x86_64";
const STATION_TYPE: &str = "Station`1";
const STATION_SWAP_SYMBOL: &str = "aot_maps_net10_x86_64_Tidewater_Gauges_Station_1<Int32>__Swap";
const STATION_REF_SWAP_SYMBOL: &str =
    "aot_maps_net10_x86_64_Tidewater_Gauges_Station_1<System___Canon>__Swap";
const ASSIGN_REF_RVA: u32 = 0xB04E0;
const PROGRAM_MAIN_SYMBOL: &str = "aot_maps_net10_x86_64_Tidewater_Gauges_Program__Main";
const NEW_FAST_RVA: u32 = 0xB0280;

fn fixture(name: &str) -> Vec<u8> {
    let path: String = format!("{FIXTURE}/{name}");
    disrobe_testkit::load_fixture(&path, 4 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("fixture {path} is missing or unreadable: {error}"))
}

fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| fixture("aot_maps_net10_x86_64.exe"))
}

fn report() -> &'static AotReport {
    static REPORT: OnceLock<AotReport> = OnceLock::new();
    REPORT.get_or_init(|| detect(image()))
}

fn method_evidence(
    report: &AotReport,
    symbol: &str,
    namespace: &str,
    type_name: &str,
    method_name: &str,
) -> AotObjectMethodEvidence {
    let compressed: Vec<u8> = fixture("aot_maps_net10_x86_64.link-map-managed.txt.gz");
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
    let symbols: Vec<(String, u32)> = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [section, symbol, address, object] = fields.as_slice() else {
                return None;
            };
            if !section.starts_with("0001:") || *object != "aot_maps_net10_x86_64.obj" {
                return None;
            }
            let address: u64 = u64::from_str_radix(address, 16).ok()?;
            let rva: u32 = u32::try_from(address.checked_sub(base)?).ok()?;
            Some(((*symbol).to_owned(), rva))
        })
        .collect();
    let index: usize = symbols
        .iter()
        .position(|(candidate, _)| candidate == symbol)
        .unwrap_or_else(|| panic!("link map names {symbol}"));
    let (_, start_rva): &(String, u32) = symbols
        .get(index)
        .unwrap_or_else(|| panic!("station swap symbol remains indexed"));
    let (_, end_rva): &(String, u32) = symbols
        .get(index.saturating_add(1))
        .unwrap_or_else(|| panic!("link map bounds station swap"));
    let owner = report
        .metadata_attribution
        .types
        .iter()
        .find(|type_record| {
            type_record.name == type_name && type_record.namespace.as_deref() == Some(namespace)
        })
        .unwrap_or_else(|| panic!("{type_name} type is attributed"));
    let method_record_offset: u32 =
        owner
            .method_record_offsets
            .iter()
            .copied()
            .find(|record_offset| {
                report.metadata_attribution.methods.iter().any(|method| {
                    method.record_offset == *record_offset && method.name == method_name
                })
            })
            .unwrap_or_else(|| panic!("{type_name}.{method_name} metadata record is attributed"));
    AotObjectMethodEvidence {
        type_record_offset: owner.record_offset,
        method_record_offset,
        start_rva: *start_rva,
        end_rva: *end_rva,
    }
}

fn station_swap_evidence(report: &AotReport, symbol: &str) -> AotObjectMethodEvidence {
    method_evidence(report, symbol, "Tidewater.Gauges", STATION_TYPE, "Swap")
}

fn program_main_evidence(report: &AotReport) -> AotObjectMethodEvidence {
    method_evidence(
        report,
        PROGRAM_MAIN_SYMBOL,
        "Tidewater.Gauges",
        "Program",
        "Main",
    )
}

fn recover_station(report: &AotReport, image: &[u8]) -> AotObjectModel {
    recover_object_model(
        image,
        &report.metadata_attribution,
        report.object_model.type_layouts.clone(),
        &[station_swap_evidence(report, STATION_SWAP_SYMBOL)],
        &[],
    )
}

fn recover_station_reference_write(report: &AotReport, image: &[u8]) -> AotObjectModel {
    let pe = disrobe_pass_dotnet::pe::parse(image)
        .unwrap_or_else(|error| panic!("fixture PE parses: {error}"));
    let helper_bytes: &[u8] = pe
        .slice_exact_file_backed_rva(image, ASSIGN_REF_RVA, 0x61)
        .unwrap_or_else(|| panic!("RhpAssignRef reference body is file backed"));
    assert_eq!(
        format!("{:x}", Sha256::digest(helper_bytes)),
        "31e6a1f513121c857e2a2fd214e9aec33c1194d16d4978b389b8fb1804116e85"
    );
    recover_object_model(
        image,
        &report.metadata_attribution,
        report.object_model.type_layouts.clone(),
        &[station_swap_evidence(report, STATION_REF_SWAP_SYMBOL)],
        &[AotObjectHelperEvidence {
            rva: ASSIGN_REF_RVA,
            name: "RhpAssignRef".to_owned(),
            kind: AotObjectHelperKind::WriteBarrier,
        }],
    )
}

fn recover_program_allocation(report: &AotReport, image: &[u8]) -> AotObjectModel {
    let pe = disrobe_pass_dotnet::pe::parse(image)
        .unwrap_or_else(|error| panic!("fixture PE parses: {error}"));
    let helper_bytes: &[u8] = pe
        .slice_exact_file_backed_rva(image, NEW_FAST_RVA, 0x40)
        .unwrap_or_else(|| panic!("RhpNewFast reference body is file backed"));
    assert_eq!(
        format!("{:x}", Sha256::digest(helper_bytes)),
        "17c584aed4a975d8939ddf0c9c840daa74dfa337bc3c77bb504a68219fbf28a8"
    );
    recover_object_model(
        image,
        &report.metadata_attribution,
        report.object_model.type_layouts.clone(),
        &[program_main_evidence(report)],
        &[AotObjectHelperEvidence {
            rva: NEW_FAST_RVA,
            name: "RhpNewFast".to_owned(),
            kind: AotObjectHelperKind::Allocation,
        }],
    )
}

#[test]
fn native_aot_station_field_layout_requires_linker_map_ownership_evidence() {
    let report: &AotReport = report();
    assert_eq!(
        report.metadata_attribution.status,
        AotMetadataStatus::Recovered
    );
    assert_eq!(report.object_model.status, AotObjectModelStatus::NotPresent);
    assert!(report.object_model.field_stores.is_empty());
    assert!(report.object_model.type_references.is_empty());
    let recovered: AotObjectModel = recover_station(report, image());
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    let store = recovered
        .field_stores
        .iter()
        .find(|store| {
            store.store_rva == 0x87DA3
                && store.field_offset == 8
                && store.width == AotObjectStoreWidth::Dword
                && store.source_register == 2
        })
        .unwrap_or_else(|| panic!("map-owned Station<int>.Swap store is recovered"));
    assert!(store.field_name.is_none());
    assert!(store.field_type.is_none());
}

#[test]
fn native_aot_object_model_mutation_removes_the_map_owned_store() {
    let report: &AotReport = report();
    let evidence: AotObjectMethodEvidence = station_swap_evidence(report, STATION_SWAP_SYMBOL);
    let baseline: AotObjectModel = recover_station(report, image());
    let mut mutated: Vec<u8> = image().to_vec();
    let pe = disrobe_pass_dotnet::pe::parse(mutated.as_slice())
        .unwrap_or_else(|error| panic!("fixture PE parses: {error}"));
    let store_rva: u32 = baseline
        .field_stores
        .iter()
        .find(|store| store.store_rva == 0x87DA3)
        .map_or_else(
            || panic!("baseline store is recovered"),
            |store| store.store_rva,
        );
    let offset: usize = pe
        .rva_to_offset(store_rva)
        .unwrap_or_else(|| panic!("store RVA 0x{store_rva:x} is file backed"));
    *mutated
        .get_mut(offset)
        .unwrap_or_else(|| panic!("store file offset {offset} exists")) = 0x90;
    let recovered: AotObjectModel = recover_object_model(
        mutated.as_slice(),
        &report.metadata_attribution,
        report.object_model.type_layouts.clone(),
        &[evidence],
        &[],
    );
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    assert!(recovered.field_stores.is_empty());
}

#[test]
fn native_aot_runtime_field_layout_names_the_exact_store() {
    let report: &AotReport = report();
    let evidence: AotObjectMethodEvidence = station_swap_evidence(report, STATION_SWAP_SYMBOL);
    let field_type = AotTypeSignature {
        kind: AotTypeSignatureKind::Definition,
        record_offset: evidence.type_record_offset,
    };
    let field_record_offset: u32 = u32::MAX;
    let mut attribution = report.metadata_attribution.clone();
    attribution
        .runtime_field_layouts
        .push(AotRuntimeFieldLayout {
            type_record_offset: evidence.type_record_offset,
            field_record_offset,
            method_table_rva: None,
            field_offset: 8,
        });
    let mut layouts = report.object_model.type_layouts.clone();
    layouts
        .iter_mut()
        .find(|layout| layout.record_offset == evidence.type_record_offset)
        .unwrap_or_else(|| panic!("Station<T> layout is recovered"))
        .instance_fields
        .push(AotFieldLayout {
            record_offset: field_record_offset,
            name: "_last".to_owned(),
            field_type,
        });
    let recovered: AotObjectModel =
        recover_object_model(image(), &attribution, layouts.clone(), &[evidence], &[]);
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    let store = recovered
        .field_stores
        .iter()
        .find(|store| store.store_rva == 0x87DA3)
        .unwrap_or_else(|| panic!("Station<int>.Swap store is recovered"));
    assert_eq!(store.field_name.as_deref(), Some("_last"));
    assert_eq!(store.field_type, Some(field_type));
    let conflicting_record_offset: u32 = u32::MAX - 1;
    layouts
        .iter_mut()
        .find(|layout| layout.record_offset == evidence.type_record_offset)
        .unwrap_or_else(|| panic!("Station<T> layout remains recovered"))
        .instance_fields
        .push(AotFieldLayout {
            record_offset: conflicting_record_offset,
            name: "_other".to_owned(),
            field_type,
        });
    attribution
        .runtime_field_layouts
        .push(AotRuntimeFieldLayout {
            type_record_offset: evidence.type_record_offset,
            field_record_offset: conflicting_record_offset,
            method_table_rva: None,
            field_offset: 8,
        });
    let refused: AotObjectModel =
        recover_object_model(image(), &attribution, layouts, &[evidence], &[]);
    assert_eq!(
        refused.status,
        AotObjectModelStatus::Refused {
            reason: AotObjectModelRefusal::RuntimeFieldLayoutAmbiguous,
        }
    );
}

#[test]
fn native_aot_object_model_refuses_overlapping_method_evidence() {
    let report: &AotReport = report();
    let evidence: AotObjectMethodEvidence = station_swap_evidence(report, STATION_SWAP_SYMBOL);
    let overlapping: AotObjectMethodEvidence = AotObjectMethodEvidence {
        start_rva: evidence.start_rva.saturating_add(1),
        ..evidence
    };
    let recovered: AotObjectModel = recover_object_model(
        image(),
        &report.metadata_attribution,
        report.object_model.type_layouts.clone(),
        &[evidence, overlapping],
        &[],
    );
    assert_eq!(
        recovered.status,
        AotObjectModelStatus::Refused {
            reason: AotObjectModelRefusal::MethodEvidenceAmbiguous,
        }
    );
}

#[test]
fn native_aot_object_model_refuses_ambiguous_method_table_evidence() {
    let report: &AotReport = report();
    let mut attribution = report.metadata_attribution.clone();
    let mut conflict = *attribution
        .method_table_references
        .first()
        .unwrap_or_else(|| panic!("fixture has a MethodTable reference"));
    conflict.type_record_offset = attribution
        .types
        .iter()
        .map(|type_record| type_record.record_offset)
        .find(|record_offset| *record_offset != conflict.type_record_offset)
        .unwrap_or_else(|| panic!("fixture has a second metadata type"));
    attribution.method_table_references.push(conflict);
    let recovered: AotObjectModel = recover_object_model(
        image(),
        &attribution,
        report.object_model.type_layouts.clone(),
        &[station_swap_evidence(report, STATION_SWAP_SYMBOL)],
        &[],
    );
    assert_eq!(
        recovered.status,
        AotObjectModelStatus::Refused {
            reason: AotObjectModelRefusal::MethodTableEvidenceAmbiguous,
        }
    );
    assert!(recovered.type_references.is_empty());
}

#[test]
fn native_aot_station_reference_swap_recovers_write_barrier_call() {
    let report: &AotReport = report();
    let recovered: AotObjectModel = recover_station_reference_write(report, image());
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    let call = recovered
        .helper_calls
        .iter()
        .find(|call| call.call_rva == 0x94519)
        .unwrap_or_else(|| panic!("Station<string>.Swap write barrier call is recovered"));
    assert_eq!(call.helper.rva, ASSIGN_REF_RVA);
    assert_eq!(call.helper.name, "RhpAssignRef");
    assert_eq!(call.helper.kind, AotObjectHelperKind::WriteBarrier);
}

#[test]
fn native_aot_station_reference_swap_mutation_removes_write_barrier_call() {
    let report: &AotReport = report();
    let mut mutated: Vec<u8> = image().to_vec();
    let pe = disrobe_pass_dotnet::pe::parse(mutated.as_slice())
        .unwrap_or_else(|error| panic!("fixture PE parses: {error}"));
    let offset: usize = pe
        .rva_to_offset(0x94519)
        .unwrap_or_else(|| panic!("write barrier call RVA is file backed"));
    *mutated
        .get_mut(offset)
        .unwrap_or_else(|| panic!("write barrier call file offset exists")) = 0x90;
    let recovered: AotObjectModel = recover_station_reference_write(report, mutated.as_slice());
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    assert!(recovered.helper_calls.is_empty());
}

#[test]
fn native_aot_program_main_recovers_allocation_call() {
    let report: &AotReport = report();
    let recovered: AotObjectModel = recover_program_allocation(report, image());
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    let call = recovered
        .helper_calls
        .iter()
        .find(|call| call.call_rva == 0x833B7)
        .unwrap_or_else(|| panic!("Program.Main allocation call is recovered"));
    assert_eq!(call.helper.rva, NEW_FAST_RVA);
    assert_eq!(call.helper.name, "RhpNewFast");
    assert_eq!(call.helper.kind, AotObjectHelperKind::Allocation);
}

fn program_with_evidenced_method_table(report: &AotReport) -> (Vec<u8>, u32, u32) {
    let reference = report
        .metadata_attribution
        .method_table_references
        .first()
        .unwrap_or_else(|| panic!("fixture has an invoke-map MethodTable reference"));
    let instruction_rva: u32 = 0x833B0;
    let displacement: i32 =
        i32::try_from(i64::from(reference.method_table_rva) - i64::from(instruction_rva + 7))
            .unwrap_or_else(|_| panic!("fixture MethodTable is RIP-relative reachable"));
    let mut patched: Vec<u8> = image().to_vec();
    let pe = disrobe_pass_dotnet::pe::parse(patched.as_slice())
        .unwrap_or_else(|error| panic!("fixture PE parses: {error}"));
    let offset: usize = pe
        .rva_to_offset(instruction_rva)
        .unwrap_or_else(|| panic!("MethodTable instruction RVA is file backed"));
    assert_eq!(&patched[offset..offset + 3], &[0x48, 0x8d, 0x0d]);
    patched[offset + 3..offset + 7].copy_from_slice(&displacement.to_le_bytes());
    (
        patched,
        reference.type_record_offset,
        reference.method_table_rva,
    )
}

#[test]
fn native_aot_method_table_reference_matches_in_bounded_method() {
    let report: &AotReport = report();
    let (patched, type_record_offset, method_table_rva): (Vec<u8>, u32, u32) =
        program_with_evidenced_method_table(report);
    let recovered: AotObjectModel = recover_program_allocation(report, patched.as_slice());
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    let reference = recovered
        .type_references
        .iter()
        .find(|reference| reference.instruction_rva == 0x833B0)
        .unwrap_or_else(|| panic!("evidenced MethodTable reference is recovered"));
    assert_eq!(reference.type_record_offset, type_record_offset);
    assert_eq!(reference.method_table_rva, method_table_rva);
    assert_eq!(
        reference.method_record_offset,
        program_main_evidence(report).method_record_offset
    );
}

#[test]
fn native_aot_method_table_opcode_mutation_removes_the_match() {
    let report: &AotReport = report();
    let (mutated, _type_record_offset, _method_table_rva): (Vec<u8>, u32, u32) =
        program_with_evidenced_method_table(report);
    let baseline: AotObjectModel = recover_program_allocation(report, mutated.as_slice());
    let instruction_rva: u32 = baseline
        .type_references
        .iter()
        .find(|reference| reference.instruction_rva == 0x833B0)
        .map_or_else(
            || panic!("baseline MethodTable reference is recovered"),
            |reference| reference.instruction_rva,
        );
    let mut mutated: Vec<u8> = mutated;
    let pe = disrobe_pass_dotnet::pe::parse(mutated.as_slice())
        .unwrap_or_else(|error| panic!("fixture PE parses: {error}"));
    let offset: usize = pe
        .rva_to_offset(instruction_rva)
        .unwrap_or_else(|| panic!("MethodTable instruction RVA is file backed"));
    *mutated
        .get_mut(offset + 1)
        .unwrap_or_else(|| panic!("MethodTable instruction opcode is file backed")) = 0x8b;
    let recovered: AotObjectModel = recover_program_allocation(report, mutated.as_slice());
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    assert!(
        recovered
            .type_references
            .iter()
            .all(|reference| reference.instruction_rva != instruction_rva)
    );
}

#[test]
fn native_aot_program_main_mutation_removes_allocation_call() {
    let report: &AotReport = report();
    let mut mutated: Vec<u8> = image().to_vec();
    let pe = disrobe_pass_dotnet::pe::parse(mutated.as_slice())
        .unwrap_or_else(|error| panic!("fixture PE parses: {error}"));
    let offset: usize = pe
        .rva_to_offset(0x833B7)
        .unwrap_or_else(|| panic!("allocation call RVA is file backed"));
    *mutated
        .get_mut(offset)
        .unwrap_or_else(|| panic!("allocation call file offset exists")) = 0x90;
    let recovered: AotObjectModel = recover_program_allocation(report, mutated.as_slice());
    assert_eq!(recovered.status, AotObjectModelStatus::Recovered);
    assert!(
        recovered
            .helper_calls
            .iter()
            .all(|call| call.call_rva != 0x833B7)
    );
}
