#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use disrobe_capabilities::{
    CapabilitiesReport, CapabilityMatch, Evidence, FeatureHit, FeatureValue, ImportMap,
    ScopedFeatures,
};
use disrobe_ir::payload::{DisasmInstruction, DisasmPayload};
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::Module;

const REFERENCE: &str = "crates/disrobe-capabilities/tests/fixtures/elf_plt_reference.txt";
const NIM: &str = "corpus/native/nim/hello.nim.elf";
const PYARMOR: &str =
    "corpus/python/pyarmor/v9/platform_linux/pyarmor_runtime_000000/pyarmor_runtime.so";
const FREESTANDING: &str = "corpus/native/discovery/disc.unstripped.elf";
const AARCH64: &[&str] = &[
    "corpus/python/pyarmor/v8/platform_linux_aarch64/pyarmor_runtime_000000/pyarmor_runtime.so",
    "corpus/python/pyarmor/v9/platform_linux_aarch64/pyarmor_runtime_000000/pyarmor_runtime.so",
];
const MAX_REFERENCE_LINES: usize = 8192;
const PLT_ENTRY_SIZE: u64 = 0x10;

type Reference = BTreeMap<String, Vec<(u64, String)>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("repository root resolves from the crate manifest directory")
}

fn read_required(relative: &str) -> Vec<u8> {
    let path: PathBuf = repo_root().join(relative);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "required reference input {} is unreadable: {error}",
            path.display()
        )
    })
}

fn load_reference() -> Reference {
    let raw: Vec<u8> = read_required(REFERENCE);
    let text: String = String::from_utf8(raw).expect("the reference file is utf-8");
    let mut out: Reference = Reference::new();
    let mut current: Option<String> = None;
    for (index, line) in text.lines().enumerate() {
        assert!(
            index < MAX_REFERENCE_LINES,
            "the reference file exceeds its {MAX_REFERENCE_LINES}-line bound"
        );
        let trimmed: &str = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(fixture) = trimmed
            .strip_prefix('[')
            .and_then(|v: &str| v.strip_suffix(']'))
        {
            current = Some(fixture.to_owned());
            out.entry(fixture.to_owned()).or_default();
            continue;
        }
        let fixture: &String = current
            .as_ref()
            .expect("every reference entry follows a bracketed fixture path");
        let (address, symbol): (&str, &str) = trimmed
            .split_once(' ')
            .unwrap_or_else(|| panic!("malformed reference entry: {trimmed}"));
        let hex: &str = address
            .strip_prefix("0x")
            .unwrap_or_else(|| panic!("reference address must be hexadecimal: {address}"));
        let parsed: u64 = u64::from_str_radix(hex, 16)
            .unwrap_or_else(|error| panic!("reference address {address} is invalid: {error}"));
        out.entry(fixture.clone())
            .or_default()
            .push((parsed, symbol.to_owned()));
    }
    assert!(
        !out.is_empty(),
        "the reference file names no fixture, so nothing can be graded"
    );
    for (fixture, entries) in &out {
        assert!(
            !entries.is_empty(),
            "the reference file records no stub for {fixture}, so nothing can be graded"
        );
    }
    out
}

fn scoped_features(bytes: &[u8]) -> (DisasmPayload, ScopedFeatures) {
    let payload: DisasmPayload =
        build_disasm_payload(bytes).expect("the fixture disassembles into a payload");
    let module: Module = Module::from_disasm(&payload);
    let imports: ImportMap = ImportMap::from_bytes(bytes);
    let scoped: ScopedFeatures = disrobe_capabilities::extract(&module, bytes, &imports);
    (payload, scoped)
}

fn api_names(scoped: &ScopedFeatures) -> BTreeSet<String> {
    scoped
        .file
        .hits()
        .iter()
        .filter_map(|hit: &FeatureHit| match &hit.value {
            FeatureValue::Api(name) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn call_sites_targeting(payload: &DisasmPayload, stub: u64) -> BTreeSet<u64> {
    payload
        .instructions
        .iter()
        .filter(|insn: &&DisasmInstruction| insn.branch_target == Some(stub))
        .map(|insn: &DisasmInstruction| insn.offset)
        .collect()
}

#[test]
fn every_reference_stub_resolves_to_its_reference_symbol() {
    let reference: Reference = load_reference();
    let mut graded: usize = 0;
    for (fixture, entries) in &reference {
        let bytes: Vec<u8> = read_required(fixture);
        let map: ImportMap = ImportMap::from_bytes(&bytes);
        let mut matched: usize = 0;
        for (address, symbol) in entries {
            let resolved: Option<&str> = map.name_at_thunk(*address);
            assert_eq!(
                resolved,
                Some(symbol.as_str()),
                "{fixture}: stub {address:#x} must resolve to {symbol}"
            );
            matched += 1;
        }
        assert_eq!(
            matched,
            entries.len(),
            "{fixture}: {matched} of {} reference stubs resolved",
            entries.len()
        );
        let distinct: BTreeSet<&String> = entries
            .iter()
            .map(|(_, symbol): &(u64, String)| symbol)
            .collect();
        assert_eq!(
            map.names().len(),
            distinct.len(),
            "{fixture}: the import map reports {} names against {} reference symbols, so it \
             invented or dropped an entry",
            map.names().len(),
            distinct.len()
        );
        graded += entries.len();
    }
    assert!(graded > 0, "no reference stub was graded");
}

#[test]
fn resolution_stops_at_the_edges_of_the_table() {
    let reference: Reference = load_reference();
    for (fixture, entries) in &reference {
        let bytes: Vec<u8> = read_required(fixture);
        let map: ImportMap = ImportMap::from_bytes(&bytes);
        let lowest: u64 = entries
            .iter()
            .map(|(address, _): &(u64, String)| *address)
            .min()
            .expect("the reference names at least one stub");
        let highest: u64 = entries
            .iter()
            .map(|(address, _): &(u64, String)| *address)
            .max()
            .expect("the reference names at least one stub");
        let header: u64 = lowest
            .checked_sub(PLT_ENTRY_SIZE)
            .expect("the table header precedes the first stub");
        assert_eq!(
            map.name_at_thunk(header),
            None,
            "{fixture}: the table header at {header:#x} is not an import stub"
        );
        let past_end: u64 = highest.saturating_add(PLT_ENTRY_SIZE);
        assert_eq!(
            map.name_at_thunk(past_end),
            None,
            "{fixture}: {past_end:#x} lies past the last stub and is not an import stub"
        );
    }
}

#[test]
fn a_branch_into_a_stub_reaches_the_same_import_as_its_entry_point() {
    let reference: Reference = load_reference();
    for (fixture, entries) in &reference {
        let bytes: Vec<u8> = read_required(fixture);
        let map: ImportMap = ImportMap::from_bytes(&bytes);
        for (address, symbol) in entries {
            for skew in [0u64, 1, 4, 8] {
                let inside: u64 = address.saturating_add(skew);
                assert_eq!(
                    map.name_at_thunk(inside),
                    Some(symbol.as_str()),
                    "{fixture}: {inside:#x} lies inside the {symbol} stub at {address:#x}"
                );
            }
        }
    }
}

#[test]
fn elf_call_sites_resolve_only_to_reference_symbols() {
    let reference: Reference = load_reference();
    let entries: &Vec<(u64, String)> = reference
        .get(PYARMOR)
        .expect("the reference covers the shared object");
    let expected: BTreeSet<&str> = entries
        .iter()
        .map(|(_, symbol): &(u64, String)| symbol.as_str())
        .collect();

    let bytes: Vec<u8> = read_required(PYARMOR);
    let (_, scoped): (DisasmPayload, ScopedFeatures) = scoped_features(&bytes);
    let resolved: BTreeSet<String> = api_names(&scoped);
    assert!(
        !resolved.is_empty(),
        "the shared object resolves no call site to an imported symbol"
    );
    for name in &resolved {
        assert!(
            expected.contains(name.as_str()),
            "{name} is not an imported symbol of the fixture, so the call site was misresolved"
        );
    }
    let sites: usize = scoped
        .file
        .hits()
        .iter()
        .filter(|hit: &&FeatureHit| matches!(hit.value, FeatureValue::Api(_)))
        .count();
    let reached: usize = resolved.len();
    println!(
        "reached {reached} of {} reference symbols across {sites} resolved call sites",
        expected.len()
    );
    assert!(
        sites >= reached,
        "{sites} call sites cannot cover {reached} distinct symbols"
    );
    assert!(
        reached >= 200,
        "{reached} of {} reference symbols were reached from a call site",
        expected.len()
    );
}

#[test]
fn an_aarch64_table_yields_no_stub_from_the_x86_64_decoder() {
    for fixture in AARCH64 {
        let bytes: Vec<u8> = read_required(fixture);
        let map: ImportMap = ImportMap::from_bytes(&bytes);
        assert!(
            map.is_empty(),
            "{fixture}: an aarch64 table is not decodable as x86-64, so it must yield no stub, \
             got {:?}",
            map.names()
        );
    }
}

#[test]
fn a_network_capability_anchors_at_a_reference_call_site() {
    let reference: Reference = load_reference();
    let entries: &Vec<(u64, String)> = reference
        .get(PYARMOR)
        .expect("the reference covers the shared object");
    let socket_stub: u64 = entries
        .iter()
        .find(|(_, symbol): &&(u64, String)| symbol == "socket")
        .map(|(address, _): &(u64, String)| *address)
        .expect("the reference records a socket stub");

    let bytes: Vec<u8> = read_required(PYARMOR);
    let payload: DisasmPayload =
        build_disasm_payload(&bytes).expect("the fixture disassembles into a payload");
    let sites: BTreeSet<u64> = call_sites_targeting(&payload, socket_stub);
    assert!(
        !sites.is_empty(),
        "the fixture contains no branch to the socket stub at {socket_stub:#x}"
    );

    let report: CapabilitiesReport =
        disrobe_capabilities::analyze(&bytes).expect("the fixture analyzes");
    let hit: &CapabilityMatch = report
        .capabilities
        .iter()
        .find(|c: &&CapabilityMatch| c.rule == "open network socket")
        .expect("the socket import must raise the socket capability");
    let cited: Vec<u64> = hit
        .evidence
        .iter()
        .filter(|e: &&Evidence| e.feature == "api(socket)")
        .map(|e: &Evidence| e.address)
        .collect();
    assert!(
        !cited.is_empty(),
        "the socket capability cites no api(socket) evidence: {:?}",
        hit.evidence
    );
    for address in &cited {
        assert!(
            sites.contains(address),
            "evidence address {address:#x} is not a branch to the socket stub {socket_stub:#x}"
        );
    }
    assert!(
        report
            .capabilities
            .iter()
            .any(|c: &CapabilityMatch| c.rule == "connect to network resource"),
        "the connect import must raise the connect capability"
    );
}

#[test]
fn a_freestanding_elf_resolves_no_imported_call() {
    let bytes: Vec<u8> = read_required(FREESTANDING);
    let map: ImportMap = ImportMap::from_bytes(&bytes);
    assert!(
        map.is_empty(),
        "a freestanding executable has no dynamic import: {:?}",
        map.names()
    );
    let (_, scoped): (DisasmPayload, ScopedFeatures) = scoped_features(&bytes);
    assert!(
        api_names(&scoped).is_empty(),
        "a freestanding executable must resolve no call site to an imported symbol"
    );
}

#[test]
fn a_damaged_elf_never_reports_a_symbol_the_whole_image_lacks() {
    let bytes: Vec<u8> = read_required(NIM);
    let whole: BTreeSet<String> = ImportMap::from_bytes(&bytes)
        .names()
        .iter()
        .cloned()
        .collect();
    assert!(!whole.is_empty(), "the intact fixture must resolve stubs");

    let mut damaged: Vec<Vec<u8>> = Vec::new();
    for keep in [
        0usize,
        1,
        4,
        16,
        64,
        0x40,
        0x1000,
        bytes.len() / 3,
        bytes.len() / 2,
    ] {
        damaged.push(bytes[..keep.min(bytes.len())].to_vec());
    }
    for stride in [1usize, 7, 97, 1021] {
        let mut mutated: Vec<u8> = bytes.clone();
        let mut at: usize = 0;
        while at < mutated.len() {
            mutated[at] ^= 0xff;
            at = at.saturating_add(stride.saturating_mul(1024));
        }
        damaged.push(mutated);
    }

    for candidate in &damaged {
        let map: ImportMap = ImportMap::from_bytes(candidate);
        for name in map.names() {
            assert!(
                whole.contains(name),
                "a damaged image reported {name}, which the intact image does not import"
            );
        }
    }
}

#[test]
fn the_import_map_is_deterministic_across_repeated_builds() {
    let reference: Reference = load_reference();
    let bytes: Vec<u8> = read_required(NIM);
    let first: ImportMap = ImportMap::from_bytes(&bytes);
    let second: ImportMap = ImportMap::from_bytes(&bytes);
    assert_eq!(first.names(), second.names());
    for (address, symbol) in &reference[NIM] {
        assert_eq!(
            first.name_at_thunk(*address),
            second.name_at_thunk(*address)
        );
        assert_eq!(first.name_at_thunk(*address), Some(symbol.as_str()));
    }
}
