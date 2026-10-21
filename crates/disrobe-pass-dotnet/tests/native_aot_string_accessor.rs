#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::io::Read as _;
use std::sync::OnceLock;

use disrobe_pass_dotnet::aot::{
    AotCodeRange, AotReport, AotStringAccessor, detect, recover_string_accessors,
};

const FIXTURE: &str = "corpus/dotnet/aot/aot_strings_net10_x86_64";
const GET_SYMBOL: &str = "aot_strings_net10_x86_64_Tidewater_Signals_Lexicon__Get";
const MAIN_SYMBOL: &str = "aot_strings_net10_x86_64_Tidewater_Signals_Program__Main";
const CALLED_INDEXES: [u32; 6] = [0, 1, 3, 5, 6, 7];

fn fixture(name: &str) -> Vec<u8> {
    let path: String = format!("{FIXTURE}/{name}");
    disrobe_testkit::load_fixture(&path, 4 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("fixture {path} is missing or unreadable: {error}"))
}

fn image() -> &'static [u8] {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| fixture("aot_strings_net10_x86_64.exe"))
}

fn report() -> &'static AotReport {
    static REPORT: OnceLock<AotReport> = OnceLock::new();
    REPORT.get_or_init(|| detect(image()))
}

fn symbol_rva(symbol: &str) -> u32 {
    let compressed: Vec<u8> = fixture("aot_strings_net10_x86_64.link-map-managed.txt.gz");
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
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [section, name, address, object] = fields.as_slice() else {
                return None;
            };
            if !section.starts_with("0001:")
                || *object != "aot_strings_net10_x86_64.obj"
                || *name != symbol
            {
                return None;
            }
            let address: u64 = u64::from_str_radix(address, 16).ok()?;
            u32::try_from(address.checked_sub(base)?).ok()
        })
        .unwrap_or_else(|| panic!("link map names {symbol}"))
}

fn frozen_region() -> Option<AotCodeRange> {
    report()
        .ready_to_run
        .as_ref()
        .and_then(|header| header.section(206))
        .map(|section| AotCodeRange {
            start_rva: section.start_rva,
            end_rva: section.end_rva,
        })
}

fn the_accessor(accessors: &[AotStringAccessor]) -> &AotStringAccessor {
    let [accessor] = accessors else {
        panic!(
            "exactly one string accessor is recovered, got {}",
            accessors.len()
        );
    };
    accessor
}

#[test]
fn the_accessor_and_its_immediate_call_sites_match_the_link_map() {
    let report: &AotReport = report();
    let accessor: &AotStringAccessor = the_accessor(&report.string_accessors);
    assert_eq!(accessor.accessor_rva, symbol_rva(GET_SYMBOL));
    assert!(accessor.end_rva > accessor.accessor_rva);
    let main_rva: u32 = symbol_rva(MAIN_SYMBOL);
    assert!(
        accessor
            .call_sites
            .iter()
            .all(|site| site.caller_start_rva == main_rva)
    );
    let indexes: BTreeSet<u32> = accessor.call_sites.iter().map(|site| site.index).collect();
    assert_eq!(
        indexes,
        CALLED_INDEXES.into_iter().collect::<BTreeSet<u32>>()
    );
    assert_eq!(accessor.call_sites.len(), CALLED_INDEXES.len());
    let region: AotCodeRange =
        frozen_region().expect("fixture carries a FrozenObjectRegion section");
    assert_eq!(accessor.tables.len(), 2);
    let sizes: BTreeSet<(u16, u32)> = accessor
        .tables
        .iter()
        .map(|table| (table.component_size, table.length))
        .collect();
    assert_eq!(sizes, BTreeSet::from([(4, 9), (1, 77)]));
    assert!(
        accessor
            .tables
            .iter()
            .all(|table| table.object_rva >= region.start_rva && table.object_rva < region.end_rva)
    );
}

#[test]
fn a_blanked_index_load_removes_its_call_site_and_a_blanked_table_load_removes_the_accessor() {
    let report: &AotReport = report();
    let accessor: &AotStringAccessor = the_accessor(&report.string_accessors);
    let pe = disrobe_pass_dotnet::pe::parse(image()).expect("fixture PE parses");
    let site = accessor
        .call_sites
        .iter()
        .find(|site| site.index == 3)
        .expect("index 3 call site");
    let load_at: usize = pe
        .rva_to_offset(site.call_rva - 5)
        .expect("index load is file backed");
    let mut no_load: Vec<u8> = image().to_vec();
    assert_eq!(no_load[load_at], 0xb9);
    no_load[load_at..load_at + 5].copy_from_slice(&[0x90; 5]);
    let fewer: Vec<AotStringAccessor> = recover_string_accessors(
        &no_load,
        &report.metadata_attribution,
        &report.stack_trace_map,
        frozen_region(),
    );
    assert_eq!(
        the_accessor(&fewer).call_sites.len(),
        CALLED_INDEXES.len() - 1
    );
    assert!(
        the_accessor(&fewer)
            .call_sites
            .iter()
            .all(|site| site.index != 3)
    );
    let body_at: usize = pe
        .rva_to_offset(accessor.accessor_rva)
        .expect("accessor body is file backed");
    let body_len: usize =
        usize::try_from(accessor.end_rva - accessor.accessor_rva).expect("length");
    let mut no_tables: Vec<u8> = image().to_vec();
    for at in body_at..body_at + body_len - 6 {
        if no_tables[at] == 0x48 && no_tables[at + 1] == 0x8d && no_tables[at + 2] & 0xC7 == 0x05 {
            no_tables[at..at + 7].copy_from_slice(&[0x90; 7]);
        }
    }
    let none: Vec<AotStringAccessor> = recover_string_accessors(
        &no_tables,
        &report.metadata_attribution,
        &report.stack_trace_map,
        frozen_region(),
    );
    assert!(none.is_empty());
}

fn plaintexts() -> Vec<String> {
    let text: Vec<u8> = fixture("plain.txt");
    std::str::from_utf8(&text)
        .expect("plain.txt is UTF-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_called_index_decodes_to_its_plaintext_reference() {
    let report: &AotReport = report();
    let accessor: &AotStringAccessor = the_accessor(&report.string_accessors);
    let plain: Vec<String> = plaintexts();
    assert_eq!(plain.len(), 8);
    assert!(
        accessor.decode_refusals.is_empty(),
        "no index is refused: {:?}",
        accessor.decode_refusals
    );
    assert_eq!(accessor.literals.len(), CALLED_INDEXES.len());
    for literal in &accessor.literals {
        let expected: &str = plain
            .get(usize::try_from(literal.index).expect("index"))
            .expect("index names a plaintext");
        assert_eq!(literal.value, expected, "index {}", literal.index);
        assert!(!literal.call_rvas.is_empty());
    }
}

#[test]
fn a_corrupted_table_byte_changes_exactly_one_decoded_literal() {
    let report: &AotReport = report();
    let accessor: &AotStringAccessor = the_accessor(&report.string_accessors);
    let blob = accessor
        .tables
        .iter()
        .find(|table| table.component_size == 1)
        .expect("byte table");
    let pe = disrobe_pass_dotnet::pe::parse(image()).expect("fixture PE parses");
    let data_at: usize = pe
        .rva_to_offset(blob.object_rva + 0x10)
        .expect("table data is file backed");
    let mut corrupted: Vec<u8> = image().to_vec();
    corrupted[data_at] ^= 0xFF;
    let mut accessors: Vec<AotStringAccessor> = recover_string_accessors(
        &corrupted,
        &report.metadata_attribution,
        &report.stack_trace_map,
        frozen_region(),
    );
    disrobe_pass_dotnet::aot::decode_string_accessors(&corrupted, &mut accessors);
    let decoded: &AotStringAccessor = the_accessor(&accessors);
    let plain: Vec<String> = plaintexts();
    let changed: Vec<u32> = decoded
        .literals
        .iter()
        .filter(|literal| literal.value != plain[usize::try_from(literal.index).expect("index")])
        .map(|literal| literal.index)
        .collect();
    let refused: Vec<u32> = decoded
        .decode_refusals
        .iter()
        .map(|refusal| refusal.index)
        .collect();
    assert_eq!(
        (
            changed.len() + refused.len(),
            changed.first().or_else(|| refused.first()).copied()
        ),
        (1, Some(0)),
        "only the literal whose first byte was corrupted changes or is refused: {changed:?} {refused:?}"
    );
}
