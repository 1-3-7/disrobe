#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, GoFunc, analyze};

const BENCH_SOURCE: &str = include_str!("fixtures/benchsrc/main.go");

fn unique_recovered_vas(analysis: &GoAnalysis) -> BTreeMap<String, u64> {
    let mut seen_twice: BTreeSet<String> = BTreeSet::new();
    let mut recovered: BTreeMap<String, u64> = BTreeMap::new();
    for function in &analysis.symbols.funcs {
        let Some(va): Option<u64> = function.va else {
            continue;
        };
        if recovered.insert(function.name.clone(), va).is_some() {
            seen_twice.insert(function.name.clone());
        }
    }
    for name in &seen_twice {
        recovered.remove(name);
    }
    recovered
}

fn unique_nm_vas(text: &str) -> BTreeMap<String, u64> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for line in text.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() >= 3 && matches!(columns[columns.len() - 2], "T" | "t") {
            let name: String = columns[columns.len() - 1].to_owned();
            let count: &mut usize = counts.entry(name).or_insert(0);
            *count += 1;
        }
    }
    let parsed: BTreeMap<String, u64> = common::parse_nm_text_symbol_vas(text);
    parsed
        .into_iter()
        .filter(|(name, _): &(String, u64)| counts.get(name).copied() == Some(1))
        .collect()
}

struct Target {
    goos: &'static str,
    goarch: &'static str,
    kind: &'static str,
    ptr_size: u8,
    normal_floor: common::FunctionRecoveryFloor,
    stripped_floor: common::FunctionRecoveryFloor,
}

fn assert_analysis_metadata(analysis: &GoAnalysis, target: &Target, flavor: &str, stripped: bool) {
    assert_eq!(
        analysis.stripped.stripped,
        stripped,
        "{}/{target_arch} {flavor}: stripped classification must be {stripped}",
        target.goos,
        target_arch = target.goarch
    );
    assert_eq!(
        analysis.image_kind,
        target.kind,
        "{}/{target_arch} {flavor}: image kind must be {}",
        target.goos,
        target.kind,
        target_arch = target.goarch
    );
    assert_eq!(
        analysis.ptr_size,
        target.ptr_size,
        "{}/{target_arch} {flavor}: pointer size must be {}",
        target.goos,
        target.ptr_size,
        target_arch = target.goarch
    );
    assert_eq!(
        analysis.pclntab_version,
        "go1.20+",
        "{}/{target_arch} {flavor}: Go 1.26 must emit the go1.20+ pclntab",
        target.goos,
        target_arch = target.goarch
    );
}

fn assert_target(target: &Target) {
    let tag: String = format!("crossgrade_{}_{}", target.goos, target.goarch);
    let scratch: common::GoBuildScratch = common::new_scratch(&tag);
    common::write_module(&scratch, "crossgrademod", BENCH_SOURCE);
    let extension: &str = if target.goos == "windows" { ".exe" } else { "" };
    let normal: PathBuf = common::go_build_cross_required(
        &scratch,
        &format!("normal{extension}"),
        target.goos,
        target.goarch,
        &[],
    )
    .unwrap_or_else(|error: String| panic!("{error}"));
    let stripped: PathBuf = common::go_build_cross_required(
        &scratch,
        &format!("stripped{extension}"),
        target.goos,
        target.goarch,
        &["-ldflags", "-s -w"],
    )
    .unwrap_or_else(|error: String| panic!("{error}"));
    let nm_output: String =
        common::go_tool_nm_output(&normal).unwrap_or_else(|error: String| panic!("{error}"));
    let truth: BTreeSet<String> = common::parse_nm_text_symbols(&nm_output);
    assert!(
        truth.len() > 1000,
        "{}/{}: go tool nm truth is implausibly small: {} text symbols",
        target.goos,
        target.goarch,
        truth.len()
    );
    let normal_bytes: Vec<u8> = std::fs::read(&normal)
        .unwrap_or_else(|error: std::io::Error| panic!("read normal: {error}"));
    let stripped_bytes: Vec<u8> = std::fs::read(&stripped)
        .unwrap_or_else(|error: std::io::Error| panic!("read stripped: {error}"));
    let normal_analysis: GoAnalysis =
        analyze(&normal_bytes).unwrap_or_else(|error| panic!("analyze normal: {error}"));
    let stripped_analysis: GoAnalysis =
        analyze(&stripped_bytes).unwrap_or_else(|error| panic!("analyze stripped: {error}"));
    assert_analysis_metadata(&normal_analysis, target, "normal", false);
    assert_analysis_metadata(&stripped_analysis, target, "stripped", true);

    let normal_grade: common::FunctionRecoveryGrade =
        common::grade_analyzed_function_names(&normal_analysis, &truth);
    let stripped_grade: common::FunctionRecoveryGrade =
        common::grade_analyzed_function_names(&stripped_analysis, &truth);
    eprintln!(
        "{}/{} live ({} normal): function-name recovery {}/{} = {}; floor={}/{}; missing={:?}",
        target.goos,
        target.goarch,
        target.kind,
        normal_grade.hit,
        normal_grade.total,
        normal_grade.percentage_display(),
        target.normal_floor.numerator,
        target.normal_floor.denominator,
        normal_grade.missing
    );
    eprintln!(
        "{}/{} live ({} stripped): function-name recovery {}/{} = {}; floor={}/{}; missing={:?}",
        target.goos,
        target.goarch,
        target.kind,
        stripped_grade.hit,
        stripped_grade.total,
        stripped_grade.percentage_display(),
        target.stripped_floor.numerator,
        target.stripped_floor.denominator,
        stripped_grade.missing
    );
    assert!(
        normal_grade.meets_floor(target.normal_floor),
        "{}/{} normal: function-name recovery {}/{} = {} fell below floor {}/{}; missing={:?}",
        target.goos,
        target.goarch,
        normal_grade.hit,
        normal_grade.total,
        normal_grade.percentage_display(),
        target.normal_floor.numerator,
        target.normal_floor.denominator,
        normal_grade.missing
    );
    assert!(
        stripped_grade.meets_floor(target.stripped_floor),
        "{}/{} stripped: function-name recovery {}/{} = {} fell below floor {}/{}; missing={:?}",
        target.goos,
        target.goarch,
        stripped_grade.hit,
        stripped_grade.total,
        stripped_grade.percentage_display(),
        target.stripped_floor.numerator,
        target.stripped_floor.denominator,
        stripped_grade.missing
    );

    let truth_vas: BTreeMap<String, u64> = unique_nm_vas(&nm_output);
    assert!(
        truth_vas.len() > 800,
        "{}/{}: go tool nm VA truth is implausibly small: {} text symbols",
        target.goos,
        target.goarch,
        truth_vas.len()
    );
    let with_va: usize = stripped_analysis
        .symbols
        .funcs
        .iter()
        .filter(|function: &&GoFunc| function.va.is_some())
        .count();
    let total: usize = stripped_analysis.symbols.funcs.len();
    assert_eq!(
        with_va, total,
        "{}/{}: every stripped function must carry an absolute VA: {with_va}/{total}",
        target.goos, target.goarch
    );
    let recovered_vas: BTreeMap<String, u64> = unique_recovered_vas(&stripped_analysis);
    let mut matched: usize = 0;
    let mut mismatched: Vec<(String, u64, u64)> = Vec::new();
    for (name, expected) in &truth_vas {
        let Some(actual): Option<&u64> = recovered_vas.get(name) else {
            continue;
        };
        if actual == expected {
            matched += 1;
        } else if !common::FUNCTION_NAME_ANCHORS.contains(&name.as_str()) {
            mismatched.push((name.clone(), *expected, *actual));
        }
    }
    assert!(
        mismatched.is_empty(),
        "{}/{}: recovered stripped VAs must equal go tool nm exactly: {mismatched:?}",
        target.goos,
        target.goarch
    );
    assert!(
        matched > 400,
        "{}/{}: recovered-vs-nm VA intersection is too small: {matched}",
        target.goos,
        target.goarch
    );
    let probes: [&str; 3] = [
        "main.(*Tree[go.shape.int]).Insert",
        "main.main",
        "main.process",
    ];
    for probe in probes {
        let expected: u64 = *truth_vas.get(probe).unwrap_or_else(|| {
            panic!(
                "{}/{}: go tool nm lacks {probe}",
                target.goos, target.goarch
            )
        });
        let actual: u64 = *recovered_vas.get(probe).unwrap_or_else(|| {
            panic!(
                "{}/{}: recovery dropped {probe}",
                target.goos, target.goarch
            )
        });
        assert_eq!(
            actual, expected,
            "{}/{}: {probe} VA must equal go tool nm",
            target.goos, target.goarch
        );
    }
    let discriminating: usize = truth_vas
        .iter()
        .filter(|(name, expected): &(&String, &u64)| {
            recovered_vas
                .get(*name)
                .is_some_and(|actual: &u64| actual.wrapping_add(0x1000) != **expected)
        })
        .count();
    assert!(
        discriminating > 200,
        "{}/{}: exact-VA equality lacks discrimination: {discriminating}",
        target.goos,
        target.goarch
    );
}

#[test]
fn function_names_and_vas_match_nm_across_arch_and_container() -> Result<(), String> {
    let go_version: Option<String> = common::require_go_1_26_3_for_grading()?;
    let Some(go_version): Option<String> = go_version else {
        return Ok(());
    };
    eprintln!("live Go toolchain: {go_version}");
    let targets: [Target; 7] = [
        Target {
            goos: "windows",
            goarch: "amd64",
            kind: "pe",
            ptr_size: 8,
            normal_floor: common::FunctionRecoveryFloor::new(85, 100),
            stripped_floor: common::FunctionRecoveryFloor::new(94, 100),
        },
        Target {
            goos: "windows",
            goarch: "386",
            kind: "pe",
            ptr_size: 4,
            normal_floor: common::FunctionRecoveryFloor::new(99, 100),
            stripped_floor: common::FunctionRecoveryFloor::new(99, 100),
        },
        Target {
            goos: "linux",
            goarch: "amd64",
            kind: "elf",
            ptr_size: 8,
            normal_floor: common::FunctionRecoveryFloor::new(99, 100),
            stripped_floor: common::FunctionRecoveryFloor::new(93, 100),
        },
        Target {
            goos: "linux",
            goarch: "386",
            kind: "elf",
            ptr_size: 4,
            normal_floor: common::FunctionRecoveryFloor::new(99, 100),
            stripped_floor: common::FunctionRecoveryFloor::new(99, 100),
        },
        Target {
            goos: "linux",
            goarch: "arm64",
            kind: "elf",
            ptr_size: 8,
            normal_floor: common::FunctionRecoveryFloor::new(99, 100),
            stripped_floor: common::FunctionRecoveryFloor::new(94, 100),
        },
        Target {
            goos: "darwin",
            goarch: "amd64",
            kind: "macho",
            ptr_size: 8,
            normal_floor: common::FunctionRecoveryFloor::new(99, 100),
            stripped_floor: common::FunctionRecoveryFloor::new(88, 100),
        },
        Target {
            goos: "darwin",
            goarch: "arm64",
            kind: "macho",
            ptr_size: 8,
            normal_floor: common::FunctionRecoveryFloor::new(99, 100),
            stripped_floor: common::FunctionRecoveryFloor::new(90, 100),
        },
    ];
    for target in &targets {
        assert_target(target);
    }
    Ok(())
}
