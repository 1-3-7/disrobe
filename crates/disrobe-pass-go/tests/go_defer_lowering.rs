#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_go::{
    DeferCallKind, DeferCallSupport, DeferFunc, DeferLowering, DeferReport, DeferSupport,
    GoAnalysis, RuntimeDeferHook, analyze,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fixture {
    binary: &'static str,
    go_toolchain: &'static str,
    pclntab_band: &'static str,
    container: &'static str,
    arch: &'static str,
}

const FIXTURES: [Fixture; 4] = [
    Fixture {
        binary: "defer_go126_windows_amd64",
        go_toolchain: "go1.26.5",
        pclntab_band: "go1.20+",
        container: "pe",
        arch: "amd64",
    },
    Fixture {
        binary: "defer_go118_linux_amd64",
        go_toolchain: "go1.18.10",
        pclntab_band: "go1.18..go1.19",
        container: "elf",
        arch: "amd64",
    },
    Fixture {
        binary: "defer_go117_linux_arm64",
        go_toolchain: "go1.17.13",
        pclntab_band: "go1.16..go1.17",
        container: "elf",
        arch: "arm64",
    },
    Fixture {
        binary: "defer_go115_windows_386",
        go_toolchain: "go1.15.15",
        pclntab_band: "go1.2..go1.15",
        container: "pe",
        arch: "386",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjdumpFunc {
    span: (u32, u32),
    deferreturn_pcs: Vec<u64>,
    defer_setup_lines: Vec<u32>,
    deferreturn_bytes: Vec<(u64, Vec<u8>)>,
    runtime_calls: Vec<(DeferCallKind, u64)>,
}

impl ObjdumpFunc {
    fn expected_lowering(&self) -> Option<DeferLowering> {
        if !self.defer_setup_lines.is_empty() {
            return Some(DeferLowering::CallBased);
        }
        (!self.deferreturn_pcs.is_empty()).then_some(DeferLowering::OpenCoded)
    }
}

fn parse_objdump_reference(text: &str) -> BTreeMap<String, ObjdumpFunc> {
    let mut out: BTreeMap<String, ObjdumpFunc> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["FUNC", name, lo, hi] => {
                let span: (u32, u32) = (
                    lo.parse().expect("objdump span low bound"),
                    hi.parse().expect("objdump span high bound"),
                );
                out.insert(
                    (*name).to_owned(),
                    ObjdumpFunc {
                        span,
                        deferreturn_pcs: Vec::new(),
                        defer_setup_lines: Vec::new(),
                        deferreturn_bytes: Vec::new(),
                        runtime_calls: Vec::new(),
                    },
                );
            }
            ["CALL", name, target, pc, src_line, bytes] => {
                let entry: &mut ObjdumpFunc = out
                    .get_mut(*name)
                    .unwrap_or_else(|| panic!("CALL before FUNC for {name}"));
                let pc: u64 = u64::from_str_radix(pc.trim_start_matches("0x"), 16)
                    .expect("objdump program counter");
                let src_line: u32 = src_line.parse().expect("objdump source line");
                match *target {
                    "runtime.deferreturn" => {
                        entry.deferreturn_pcs.push(pc);
                        entry.deferreturn_bytes.push((pc, decode_hex(bytes)));
                        entry.runtime_calls.push((DeferCallKind::Return, pc));
                    }
                    "runtime.deferproc" => {
                        entry.defer_setup_lines.push(src_line);
                        entry.runtime_calls.push((DeferCallKind::Proc, pc));
                    }
                    "runtime.deferprocStack" => {
                        entry.defer_setup_lines.push(src_line);
                        entry.runtime_calls.push((DeferCallKind::ProcStack, pc));
                    }
                    "runtime.deferprocat" => {
                        entry.defer_setup_lines.push(src_line);
                    }
                    _ => {}
                }
            }
            [] => {}
            _ => panic!("unrecognized objdump reference line: {line}"),
        }
    }
    assert!(
        !out.is_empty(),
        "objdump reference carries no function records"
    );
    out
}

#[test]
fn x86_call_sites_match_the_real_toolchain_disassembly() {
    let mut graded: usize = 0;
    for fixture in FIXTURES
        .into_iter()
        .filter(|fixture: &Fixture| fixture.arch != "arm64")
    {
        let (analysis, objdump, _compiler): (
            GoAnalysis,
            BTreeMap<String, ObjdumpFunc>,
            Vec<(u32, CompilerKind)>,
        ) = load(fixture);
        assert_eq!(
            analysis.defers.call_support,
            if fixture.arch == "386" {
                DeferCallSupport::X86
            } else {
                DeferCallSupport::X86_64
            },
            "{} call-site architecture support differs",
            fixture.binary
        );
        let recovered: BTreeMap<&str, &DeferFunc> = analysis
            .defers
            .functions
            .iter()
            .map(|function: &DeferFunc| (function.name.as_str(), function))
            .collect();
        for (name, reference) in &objdump {
            if reference.runtime_calls.is_empty() {
                continue;
            }
            let function: &&DeferFunc = recovered
                .get(name.as_str())
                .unwrap_or_else(|| panic!("{}: missing defer function {name}", fixture.binary));
            let actual: Vec<(DeferCallKind, u64)> = function
                .call_sites
                .iter()
                .map(|call| (call.kind, call.va))
                .collect();
            assert_eq!(
                actual, reference.runtime_calls,
                "{}: {name} runtime defer calls differ from go tool objdump",
                fixture.binary
            );
            graded += actual.len();
        }
    }
    assert!(
        graded >= 100,
        "graded only {graded} runtime defer call sites"
    );
}

#[test]
fn arm64_call_site_exclusion_is_explicit_and_emits_no_shape_matches() {
    let (analysis, _objdump, _compiler): (
        GoAnalysis,
        BTreeMap<String, ObjdumpFunc>,
        Vec<(u32, CompilerKind)>,
    ) = load(FIXTURES[2]);
    assert_eq!(
        analysis.defers.call_support,
        DeferCallSupport::UnsupportedImage
    );
    assert!(
        analysis
            .defers
            .functions
            .iter()
            .all(|function: &DeferFunc| function.call_sites.is_empty()),
        "unsupported ARM64 instructions must not be decoded as x86 call shapes"
    );
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(
        text.len().is_multiple_of(2),
        "odd instruction byte run: {text}"
    );
    (0..text.len() / 2)
        .map(|i: usize| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("instruction byte run")
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompilerKind {
    OpenCoded,
    CallBased,
}

fn parse_defer_reference(text: &str) -> Vec<(u32, CompilerKind)> {
    let mut out: Vec<(u32, CompilerKind)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let rest: &str = line
            .strip_prefix("main.go:")
            .unwrap_or_else(|| panic!("unrecognized compiler defer record: {line}"));
        let (src_line, tail): (&str, &str) = rest
            .split_once(':')
            .unwrap_or_else(|| panic!("unrecognized compiler defer record: {line}"));
        let (_column, kind): (&str, &str) = tail
            .split_once(": ")
            .unwrap_or_else(|| panic!("unrecognized compiler defer record: {line}"));
        let kind: CompilerKind = match kind {
            "open-coded defer" => CompilerKind::OpenCoded,
            "stack-allocated defer" | "heap-allocated defer" => CompilerKind::CallBased,
            other => panic!("unrecognized compiler defer class: {other}"),
        };
        out.push((src_line.parse().expect("compiler defer record line"), kind));
    }
    assert!(
        !out.is_empty(),
        "compiler defer reference carries no records"
    );
    out
}

fn recovered_main_lowerings(report: &DeferReport) -> BTreeMap<String, DeferLowering> {
    report
        .functions
        .iter()
        .filter(|f: &&DeferFunc| f.name.starts_with("main."))
        .map(|f: &DeferFunc| (f.name.clone(), f.lowering))
        .collect()
}

fn expected_main_lowerings(
    reference: &BTreeMap<String, ObjdumpFunc>,
) -> BTreeMap<String, DeferLowering> {
    reference
        .iter()
        .filter_map(|(name, func): (&String, &ObjdumpFunc)| {
            func.expected_lowering()
                .map(|lowering: DeferLowering| (name.clone(), lowering))
        })
        .collect()
}

fn load(
    fixture: Fixture,
) -> (
    GoAnalysis,
    BTreeMap<String, ObjdumpFunc>,
    Vec<(u32, CompilerKind)>,
) {
    let bytes: Vec<u8> = common::required_fixture(fixture.binary);
    let analysis: GoAnalysis =
        analyze(&bytes).unwrap_or_else(|e| panic!("analyze {} failed: {e}", fixture.binary));
    let objdump: String = String::from_utf8(common::required_fixture(&format!(
        "{}.objdump.txt",
        fixture.binary
    )))
    .expect("objdump reference is utf-8");
    let defers: String = String::from_utf8(common::required_fixture(&format!(
        "{}.defer.txt",
        fixture.binary
    )))
    .expect("compiler defer reference is utf-8");
    (
        analysis,
        parse_objdump_reference(&objdump),
        parse_defer_reference(&defers),
    )
}

#[test]
fn defer_lowering_matches_the_disassembled_call_sites_across_four_go_bands() {
    let mut graded: usize = 0;
    let mut matched: usize = 0;
    for fixture in FIXTURES {
        let (analysis, objdump, _compiler): (
            GoAnalysis,
            BTreeMap<String, ObjdumpFunc>,
            Vec<(u32, CompilerKind)>,
        ) = load(fixture);
        assert_eq!(
            analysis.defers.support,
            DeferSupport::Recovered,
            "{} ({}) did not reach a recovered defer report",
            fixture.binary,
            fixture.go_toolchain
        );
        assert_eq!(
            analysis.image_kind, fixture.container,
            "{} landed in an unexpected container",
            fixture.binary
        );
        let expected_ptr_size: u8 = if fixture.arch == "386" { 4 } else { 8 };
        assert_eq!(
            analysis.ptr_size, expected_ptr_size,
            "{} landed on an unexpected pointer width",
            fixture.binary
        );
        assert_eq!(
            analysis.pclntab_version, fixture.pclntab_band,
            "{} landed in an unexpected pclntab band",
            fixture.binary
        );
        let expected: BTreeMap<String, DeferLowering> = expected_main_lowerings(&objdump);
        assert!(
            expected.len() >= 8,
            "{} reference only carries {} defer-bearing functions",
            fixture.binary,
            expected.len()
        );
        let actual: BTreeMap<String, DeferLowering> = recovered_main_lowerings(&analysis.defers);
        for (name, want) in &expected {
            graded += 1;
            if actual.get(name) == Some(want) {
                matched += 1;
            }
        }
        assert_eq!(
            actual, expected,
            "{} ({}): recovered defer lowering differs from the disassembled call sites",
            fixture.binary, fixture.go_toolchain
        );
        let open_coded: usize = expected
            .values()
            .filter(|l: &&DeferLowering| **l == DeferLowering::OpenCoded)
            .count();
        let call_based: usize = expected.len() - open_coded;
        assert!(
            open_coded >= 4 && call_based >= 4,
            "{} reference must span both lowerings, saw open-coded={open_coded} call-based={call_based}",
            fixture.binary
        );
    }
    assert_eq!(
        matched,
        graded,
        "defer lowering agreement {matched}/{graded} across {} fixtures",
        FIXTURES.len()
    );
    assert!(
        graded >= 40,
        "graded only {graded} function classifications"
    );
}

#[test]
fn defer_lowering_matches_the_go_compiler_own_classification() {
    let mut graded: usize = 0;
    for fixture in FIXTURES {
        let (analysis, objdump, compiler): (
            GoAnalysis,
            BTreeMap<String, ObjdumpFunc>,
            Vec<(u32, CompilerKind)>,
        ) = load(fixture);
        let recovered: BTreeMap<String, DeferLowering> = recovered_main_lowerings(&analysis.defers);
        let mut from_compiler: BTreeMap<String, DeferLowering> = BTreeMap::new();
        for (src_line, kind) in &compiler {
            let owner: String = match kind {
                CompilerKind::CallBased => {
                    let owners: Vec<&String> = objdump
                        .iter()
                        .filter(|(_, f): &(&String, &ObjdumpFunc)| {
                            f.defer_setup_lines.contains(src_line)
                        })
                        .map(|(name, _): (&String, &ObjdumpFunc)| name)
                        .collect();
                    assert_eq!(
                        owners.len(),
                        1,
                        "{}: call-based defer at line {src_line} has {} owning functions",
                        fixture.binary,
                        owners.len()
                    );
                    owners[0].clone()
                }
                CompilerKind::OpenCoded => {
                    let owners: Vec<&String> = objdump
                        .iter()
                        .filter(|(_, f): &(&String, &ObjdumpFunc)| {
                            f.expected_lowering() == Some(DeferLowering::OpenCoded)
                                && f.span.0 <= *src_line
                                && *src_line <= f.span.1
                        })
                        .map(|(name, _): (&String, &ObjdumpFunc)| name)
                        .collect();
                    assert_eq!(
                        owners.len(),
                        1,
                        "{}: open-coded defer at line {src_line} has {} owning functions",
                        fixture.binary,
                        owners.len()
                    );
                    owners[0].clone()
                }
            };
            let lowering: DeferLowering = match kind {
                CompilerKind::OpenCoded => DeferLowering::OpenCoded,
                CompilerKind::CallBased => DeferLowering::CallBased,
            };
            if let Some(previous) = from_compiler.insert(owner.clone(), lowering) {
                assert_eq!(
                    previous, lowering,
                    "{}: {owner} carries conflicting compiler defer classes",
                    fixture.binary
                );
            }
            graded += 1;
        }
        assert_eq!(
            recovered, from_compiler,
            "{} ({}): recovered defer lowering differs from the go compiler's own -d=defer classification",
            fixture.binary, fixture.go_toolchain
        );
    }
    assert_eq!(
        graded,
        24 * FIXTURES.len(),
        "expected every committed compiler defer record to be graded"
    );
}

#[test]
fn deferreturn_offset_lands_on_a_real_deferreturn_call_site() {
    let mut graded: usize = 0;
    for fixture in FIXTURES {
        let (analysis, objdump, _compiler): (
            GoAnalysis,
            BTreeMap<String, ObjdumpFunc>,
            Vec<(u32, CompilerKind)>,
        ) = load(fixture);
        for func in &analysis.defers.functions {
            let func: &DeferFunc = func;
            let Some(reference): Option<&ObjdumpFunc> = objdump.get(&func.name) else {
                continue;
            };
            let va: u64 = func.va.unwrap_or_else(|| {
                panic!("{}: {} has no absolute address", fixture.binary, func.name)
            });
            let deferreturn_va: u64 = va + u64::from(func.deferreturn_offset);
            assert_eq!(
                func.deferreturn_va,
                Some(deferreturn_va),
                "{}: {} reported an inconsistent deferreturn address",
                fixture.binary,
                func.name
            );
            let first: u64 = *reference.deferreturn_pcs.iter().min().unwrap_or_else(|| {
                panic!("{}: {} has no deferreturn call", fixture.binary, func.name)
            });
            assert_eq!(
                deferreturn_va, first,
                "{}: {} deferreturn offset {:#x} resolves to {deferreturn_va:#x}, disassembly says {first:#x}",
                fixture.binary, func.name, func.deferreturn_offset
            );
            graded += 1;
        }
    }
    assert!(
        graded >= 40,
        "graded only {graded} deferreturn call-site addresses"
    );
}

#[test]
fn runtime_defer_hooks_match_the_disassembled_call_targets() {
    let fixture: Fixture = FIXTURES[0];
    let (analysis, objdump, _compiler): (
        GoAnalysis,
        BTreeMap<String, ObjdumpFunc>,
        Vec<(u32, CompilerKind)>,
    ) = load(fixture);
    let hooks: BTreeMap<&str, u64> = analysis
        .defers
        .runtime_hooks
        .iter()
        .map(|h: &RuntimeDeferHook| {
            (
                h.name.as_str(),
                h.va.unwrap_or_else(|| panic!("{} has no address", h.name)),
            )
        })
        .collect();
    for expected in [
        "runtime.deferproc",
        "runtime.deferprocStack",
        "runtime.deferreturn",
        "runtime.gopanic",
        "runtime.gorecover",
    ] {
        assert!(
            hooks.contains_key(expected),
            "{expected} is absent from the recovered runtime defer hooks"
        );
    }
    let deferreturn: u64 = hooks["runtime.deferreturn"];
    let mut graded: usize = 0;
    for func in objdump.values() {
        for (pc, bytes) in &func.deferreturn_bytes {
            assert_eq!(
                bytes.first(),
                Some(&0xe8u8),
                "expected a near call at {pc:#x}"
            );
            let rel: i32 = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let target: u64 = pc
                .wrapping_add(bytes.len() as u64)
                .wrapping_add(rel as i64 as u64);
            assert_eq!(
                target, deferreturn,
                "call at {pc:#x} targets {target:#x}, recovered runtime.deferreturn is {deferreturn:#x}"
            );
            graded += 1;
        }
    }
    assert!(
        graded >= 10,
        "graded only {graded} deferreturn call targets"
    );
}

#[test]
fn stripping_the_symbol_table_does_not_change_the_defer_report() {
    let plain: Vec<u8> = common::required_fixture("defer_go126_windows_amd64");
    let stripped: Vec<u8> = common::required_fixture("defer_go126_windows_amd64_stripped");
    let plain_report: DeferReport = analyze(&plain).expect("plain analyze").defers;
    let stripped_report: DeferReport = analyze(&stripped).expect("stripped analyze").defers;
    let names = |report: &DeferReport| -> BTreeMap<String, DeferLowering> {
        report
            .functions
            .iter()
            .filter(|f: &&DeferFunc| f.name.starts_with("main."))
            .map(|f: &DeferFunc| (f.name.clone(), f.lowering))
            .collect()
    };
    assert_eq!(
        stripped_report.support,
        DeferSupport::Recovered,
        "stripped build lost defer recovery"
    );
    assert_eq!(
        names(&stripped_report),
        names(&plain_report),
        "stripping -s -w changed the recovered defer lowering"
    );
    let offsets = |report: &DeferReport| -> BTreeMap<String, u32> {
        report
            .functions
            .iter()
            .filter(|f: &&DeferFunc| f.name.starts_with("main."))
            .map(|f: &DeferFunc| (f.name.clone(), f.deferreturn_offset))
            .collect()
    };
    assert_eq!(
        offsets(&stripped_report),
        offsets(&plain_report),
        "stripping -s -w changed the recovered deferreturn offsets"
    );
}

#[test]
fn functions_without_a_defer_gain_no_defer_record() {
    for fixture in FIXTURES {
        let (analysis, objdump, _compiler): (
            GoAnalysis,
            BTreeMap<String, ObjdumpFunc>,
            Vec<(u32, CompilerKind)>,
        ) = load(fixture);
        let reported: BTreeSet<&str> = analysis
            .defers
            .functions
            .iter()
            .map(|f: &DeferFunc| f.name.as_str())
            .collect();
        let mut clean: usize = 0;
        for (name, func) in &objdump {
            if func.expected_lowering().is_some() {
                continue;
            }
            clean += 1;
            assert!(
                !reported.contains(name.as_str()),
                "{}: {name} has no defer in the disassembly but carries a defer record",
                fixture.binary
            );
        }
        assert!(
            clean >= 3,
            "{} reference carries only {clean} defer-free functions",
            fixture.binary
        );
    }
}

#[test]
fn every_band_recovers_the_exact_main_package_function_set_the_disassembler_reports() {
    let mut graded: usize = 0;
    for fixture in FIXTURES {
        let (analysis, objdump, _compiler): (
            GoAnalysis,
            BTreeMap<String, ObjdumpFunc>,
            Vec<(u32, CompilerKind)>,
        ) = load(fixture);
        let expected: BTreeSet<&str> = objdump.keys().map(String::as_str).collect();
        let recovered: BTreeSet<&str> = analysis
            .symbols
            .funcs
            .iter()
            .map(|f: &disrobe_pass_go::GoFunc| f.name.as_str())
            .filter(|name: &&str| name.starts_with("main."))
            .collect();
        assert_eq!(
            recovered, expected,
            "{} ({}): recovered main-package function set differs from the disassembler",
            fixture.binary, fixture.go_toolchain
        );
        graded += expected.len();
    }
    assert!(
        graded >= 60,
        "graded only {graded} main-package function names"
    );
}

#[test]
fn a_binary_without_a_pclntab_reports_the_absent_state() {
    let report: DeferReport = DeferReport::pclntab_absent();
    assert_eq!(report.support, DeferSupport::PclntabAbsent);
    assert!(report.functions.is_empty());
}

#[test]
fn every_real_go_fixture_keeps_the_defer_report_bounded_and_deterministic() {
    for fixture in FIXTURES {
        let bytes: Vec<u8> = common::required_fixture(fixture.binary);
        let first: DeferReport = analyze(&bytes).expect("analyze").defers;
        let second: DeferReport = analyze(&bytes).expect("analyze").defers;
        assert_eq!(
            first, second,
            "{} defer report is not deterministic",
            fixture.binary
        );
        assert!(
            !first.truncated,
            "{} tripped the listing cap",
            fixture.binary
        );
        assert_eq!(
            first.unreadable_functions, 0,
            "{} left {} function records unreadable",
            fixture.binary, first.unreadable_functions
        );
        assert_eq!(
            first.open_coded_functions + first.call_based_functions,
            first.functions.len(),
            "{} defer counts disagree with the listing",
            fixture.binary
        );
        assert!(
            first.scanned_functions > first.functions.len(),
            "{} scanned {} functions but listed {}",
            fixture.binary,
            first.scanned_functions,
            first.functions.len()
        );
    }
}

#[test]
fn truncated_and_corrupted_go_images_never_panic_in_defer_recovery() {
    let bytes: Vec<u8> = common::required_fixture("defer_go126_windows_amd64");
    for cut in [0usize, 1, 64, 4096, bytes.len() / 3, bytes.len() / 2] {
        let slice: &[u8] = &bytes[..cut.min(bytes.len())];
        let _ignored: Option<DeferReport> = analyze(slice).ok().map(|a: GoAnalysis| a.defers);
    }
    let mut corrupted: Vec<u8> = bytes;
    for (index, byte) in corrupted.iter_mut().enumerate() {
        if index % 4099 == 0 {
            *byte = byte.wrapping_add(0x5b);
        }
    }
    let _ignored: Option<DeferReport> = analyze(&corrupted).ok().map(|a: GoAnalysis| a.defers);
}
