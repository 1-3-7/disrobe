#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::any::Any;
use std::collections::BTreeSet;
use std::panic::UnwindSafe;

use disrobe_pass_go::{GoAnalysis, analyze};

const PUBLISHED_HEADING: &str = "Go function-name recovery from a stripped binary";
const PUBLISHED_VALUE_TOLERANCE: f64 = 0.05;

#[derive(Debug)]
struct PublishedPlatform {
    label: &'static str,
    image_kind: &'static str,
    ptr_size: u8,
    normal: &'static str,
    stripped: &'static str,
    truth: &'static str,
}

const PUBLISHED_PLATFORMS: [PublishedPlatform; 7] = [
    PublishedPlatform {
        label: "windows/amd64",
        image_kind: "pe",
        ptr_size: 8,
        normal: common::BENCH_GENERICS,
        stripped: common::BENCH_GENERICS_STRIPPED,
        truth: common::BENCH_GENERICS_NM,
    },
    PublishedPlatform {
        label: "windows/386",
        image_kind: "pe",
        ptr_size: 4,
        normal: common::BENCH_WINDOWS_386,
        stripped: common::BENCH_WINDOWS_386_STRIPPED,
        truth: common::BENCH_WINDOWS_386_NM,
    },
    PublishedPlatform {
        label: "linux/amd64",
        image_kind: "elf",
        ptr_size: 8,
        normal: common::BENCH_LINUX_AMD64,
        stripped: common::BENCH_LINUX_AMD64_STRIPPED,
        truth: common::BENCH_LINUX_AMD64_NM,
    },
    PublishedPlatform {
        label: "linux/386",
        image_kind: "elf",
        ptr_size: 4,
        normal: common::BENCH_LINUX_386,
        stripped: common::BENCH_LINUX_386_STRIPPED,
        truth: common::BENCH_LINUX_386_NM,
    },
    PublishedPlatform {
        label: "linux/arm64",
        image_kind: "elf",
        ptr_size: 8,
        normal: common::BENCH_LINUX_ARM64,
        stripped: common::BENCH_LINUX_ARM64_STRIPPED,
        truth: common::BENCH_LINUX_ARM64_NM,
    },
    PublishedPlatform {
        label: "darwin/amd64",
        image_kind: "macho",
        ptr_size: 8,
        normal: common::BENCH_DARWIN_AMD64,
        stripped: common::BENCH_DARWIN_AMD64_STRIPPED,
        truth: common::BENCH_DARWIN_AMD64_NM,
    },
    PublishedPlatform {
        label: "darwin/arm64",
        image_kind: "macho",
        ptr_size: 8,
        normal: common::BENCH_DARWIN_ARM64,
        stripped: common::BENCH_DARWIN_ARM64_STRIPPED,
        truth: common::BENCH_DARWIN_ARM64_NM,
    },
];

#[derive(Debug, Clone, Copy)]
struct PinnedBar {
    num: u64,
    den: u64,
    value: f64,
}

fn pinned_bar(label: &str) -> PinnedBar {
    let bar: serde_json::Value = common::published_bar(PUBLISHED_HEADING, label);
    let num: u64 = bar["num"]
        .as_u64()
        .unwrap_or_else(|| panic!("the {label} bar must publish a numerator"));
    let den: u64 = bar["den"]
        .as_u64()
        .unwrap_or_else(|| panic!("the {label} bar must publish a denominator"));
    let value: f64 = bar["value"]
        .as_f64()
        .unwrap_or_else(|| panic!("the {label} bar must publish the percentage it plots"));
    PinnedBar { num, den, value }
}

fn assert_bar_pinned(label: &str, hit: usize, total: usize, bar: PinnedBar) {
    let measured_total: u64 = u64::try_from(total).expect("the truth total fits u64");
    let measured_hit: u64 = u64::try_from(hit).expect("the recovered count fits u64");
    assert_eq!(
        measured_total, bar.den,
        "{label}: xtask/data/recovery.json publishes a denominator of {} function names on this \
         build and every document renders that number, but `go tool nm` on the committed \
         unstripped image yields {measured_total}. A recovery that inspects fewer functions must \
         score worse, never shrink what it is measured against",
        bar.den
    );
    assert!(
        measured_hit >= bar.num,
        "{label}: recovery.json publishes {} of {} function names recovered from the stripped \
         build; this run recovered {measured_hit}. Raise the recovery or correct the published \
         figure, never the reverse",
        bar.num,
        bar.den
    );
    let derived: f64 = 100.0 * bar.num as f64 / bar.den as f64;
    assert!(
        (derived - bar.value).abs() < PUBLISHED_VALUE_TOLERANCE,
        "{label}: the plotted value {} must equal its own {}/{} = {derived:.4}",
        bar.value,
        bar.num,
        bar.den
    );
}

#[derive(Debug)]
struct PlatformMeasurement {
    stripped: common::FunctionRecoveryGrade,
    normal_hit: usize,
}

fn measure_platform(platform: &PublishedPlatform) -> PlatformMeasurement {
    let truth_bytes: Vec<u8> = common::required_fixture(platform.truth);
    let truth: BTreeSet<String> =
        common::parse_nm_text_symbols(&String::from_utf8_lossy(&truth_bytes));
    assert!(
        truth.len() > 1_000,
        "{}: the committed `go tool nm` truth is implausibly small ({} text symbols); rebuild it \
         with crates/disrobe-pass-go/tests/fixtures/regen.ps1",
        platform.label,
        truth.len()
    );

    let normal_bytes: Vec<u8> = common::required_fixture(platform.normal);
    let normal: GoAnalysis = analyze(&normal_bytes)
        .unwrap_or_else(|error| panic!("{}: analyze {}: {error}", platform.label, platform.normal));
    let stripped_bytes: Vec<u8> = common::required_fixture(platform.stripped);
    let stripped: GoAnalysis = analyze(&stripped_bytes).unwrap_or_else(|error| {
        panic!("{}: analyze {}: {error}", platform.label, platform.stripped)
    });

    for (analysis, fixture, expect_stripped) in [
        (&normal, platform.normal, false),
        (&stripped, platform.stripped, true),
    ] {
        assert_eq!(
            analysis.image_kind, platform.image_kind,
            "{}: {fixture} must parse as {}",
            platform.label, platform.image_kind
        );
        assert_eq!(
            analysis.ptr_size, platform.ptr_size,
            "{}: {fixture} must report a {}-byte pointer size",
            platform.label, platform.ptr_size
        );
        assert_eq!(
            analysis.stripped.stripped, expect_stripped,
            "{}: {fixture} must classify as stripped={expect_stripped}, so a swapped fixture \
             cannot let the stripped figure be measured on an image that kept its symbol table",
            platform.label
        );
    }

    PlatformMeasurement {
        stripped: common::grade_analyzed_function_names(&stripped, &truth),
        normal_hit: common::grade_analyzed_function_names(&normal, &truth).hit,
    }
}

#[test]
fn published_go_function_name_bars_are_pinned_per_platform() {
    for platform in &PUBLISHED_PLATFORMS {
        let bar: PinnedBar = pinned_bar(platform.label);
        let measured: PlatformMeasurement = measure_platform(platform);
        eprintln!(
            "{} committed ({} stripped): function-name recovery {}/{} = {}; published {}/{} = {}; \
             unstripped recovered {}; missing={:?}",
            platform.label,
            platform.image_kind,
            measured.stripped.hit,
            measured.stripped.total,
            measured.stripped.percentage_display(),
            bar.num,
            bar.den,
            bar.value,
            measured.normal_hit,
            measured.stripped.missing
        );
        assert_bar_pinned(
            platform.label,
            measured.stripped.hit,
            measured.stripped.total,
            bar,
        );
        assert_eq!(
            u64::try_from(measured.normal_hit).expect("the unstripped recovered count fits u64"),
            bar.den,
            "{}: the published detail states the unstripped build of the same source recovers all \
             {} names, so the unstripped image must yield every one of them; it yielded {}",
            platform.label,
            bar.den,
            measured.normal_hit
        );
    }
}

fn message_from_seeded_defect(what: &str, check: impl FnOnce() + UnwindSafe) -> String {
    eprintln!("seeding a defect ({what}); the failure below is the expected outcome");
    let outcome: std::thread::Result<()> = std::panic::catch_unwind(check);
    let payload: Box<dyn Any + Send> = outcome.expect_err(
        "a seeded defect must make this gate fail; a check that accepts a perturbed measurement \
         pins nothing",
    );
    let owned: Option<String> = payload.downcast_ref::<String>().cloned();
    owned
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message: &&str| (*message).to_owned())
        })
        .unwrap_or_else(|| panic!("the failure must carry a message naming what regressed"))
}

#[test]
fn the_pinned_bar_check_rejects_a_dropped_name_and_a_shrunken_denominator() {
    let label: &str = "windows/amd64";
    let bar: PinnedBar = pinned_bar(label);
    let hit: usize = usize::try_from(bar.num).expect("the published numerator fits usize");
    let total: usize = usize::try_from(bar.den).expect("the published denominator fits usize");

    assert_bar_pinned(label, hit, total, bar);

    let dropped: String = message_from_seeded_defect("one fewer recovered name", move || {
        assert_bar_pinned(label, hit - 1, total, bar);
    });
    eprintln!("rejected: {dropped}");
    assert!(
        dropped.contains("this run recovered"),
        "losing one recovered name must be reported as a shortfall against the published \
         numerator, got: {dropped}"
    );

    let shrunk: String =
        message_from_seeded_defect("the denominator shrunk to hide that loss", move || {
            assert_bar_pinned(label, hit - 1, total - 1, bar);
        });
    eprintln!("rejected: {shrunk}");
    assert!(
        shrunk.contains("never shrink what it is measured against"),
        "dropping a function from the graded population must be rejected on the denominator \
         rather than absorbed as a better ratio, got: {shrunk}"
    );
}
