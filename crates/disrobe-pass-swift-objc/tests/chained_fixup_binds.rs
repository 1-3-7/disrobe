#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use std::collections::BTreeSet;

use disrobe_pass_swift_objc::macho::{CpuKind, ParsedSlice};
use disrobe_pass_swift_objc::objc_dispatch::{
    ChainedPointerFormat, bound_symbols_by_slot, chained_pointer_formats,
};

use macho_corpus::{CorpusFixture, macos_system_binary, read_host_sourced, slice_preferring};

struct SliceImports {
    formats: Vec<ChainedPointerFormat>,
    slots: usize,
    names: BTreeSet<String>,
}

fn imports_of(fixture: CorpusFixture, bytes: &[u8], cpu: CpuKind) -> Option<SliceImports> {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = slice_preferring(fixture, bytes, cpu);
    if parsed.header.cpu != cpu {
        return None;
    }
    let bound: std::collections::BTreeMap<u64, String> = bound_symbols_by_slot(&slice, &parsed);
    Some(SliceImports {
        formats: chained_pointer_formats(&slice, &parsed),
        slots: bound.len(),
        names: bound.into_values().collect(),
    })
}

fn normalized(symbol: &str) -> String {
    symbol
        .strip_suffix("$INODE64")
        .unwrap_or(symbol)
        .trim_start_matches('_')
        .to_owned()
}

fn normalized_set(names: &BTreeSet<String>) -> BTreeSet<String> {
    names.iter().map(|name: &String| normalized(name)).collect()
}

fn assert_names_are_well_formed(label: &str, imports: &SliceImports) {
    let malformed: Vec<&String> = imports
        .names
        .iter()
        .filter(|name: &&String| {
            name.is_empty() || !name.starts_with(['_', '$']) || name.contains(char::is_whitespace)
        })
        .collect();
    assert!(
        malformed.is_empty(),
        "{label} resolved {} import names that are not shaped like linker symbols: {malformed:?}. \
         A chain walked with the wrong stride or the wrong bind bit lands mid-record and reads a \
         fragment of one, so a malformed name is the shape a misread chain takes",
        malformed.len()
    );
}

const CROSS_ARCH_TWINS: [&str; 5] = ["grep", "sqlite3", "awk", "sed", "otool"];

#[test]
fn an_authenticated_arm64e_chain_names_the_same_imports_as_its_intel_twin() {
    let mut graded: Vec<&str> = Vec::new();
    for name in CROSS_ARCH_TWINS {
        let fixture: CorpusFixture = macos_system_binary(name);
        let Some(bytes): Option<Vec<u8>> = read_host_sourced(fixture) else {
            continue;
        };
        let (Some(arm), Some(intel)): (Option<SliceImports>, Option<SliceImports>) = (
            imports_of(fixture, &bytes, CpuKind::Arm64),
            imports_of(fixture, &bytes, CpuKind::X86_64),
        ) else {
            continue;
        };
        if !arm
            .formats
            .iter()
            .any(|format: &ChainedPointerFormat| format.is_authenticated())
        {
            continue;
        }
        graded.push(name);

        assert!(
            !intel
                .formats
                .iter()
                .any(|format: &ChainedPointerFormat| format.is_authenticated()),
            "{name}: the intel slice is the control here, so it must be the unauthenticated \
             encoding, got {:?}",
            intel.formats
        );
        assert_names_are_well_formed(&format!("{name}[arm64e]"), &arm);
        assert_names_are_well_formed(&format!("{name}[x86_64]"), &intel);
        assert!(arm.slots > 0 && intel.slots > 0);

        assert_eq!(
            normalized_set(&arm.names),
            normalized_set(&intel.names),
            "{name}: these two slices are the same program compiled twice, so they import the \
             same symbols. The arm64e slice encodes its chain with authentication bits, a 24 bit \
             ordinal and an 8 byte stride, and the intel slice encodes the same imports with no \
             authentication, a 12 bit next field and a 4 byte stride. Reading either encoding \
             wrong shifts the ordinals and names a different set, so agreement here is what says \
             the authenticated decode landed on the right fields rather than on plausible ones. \
             The comparison folds the two documented per-architecture spellings, the $INODE64 \
             suffix and the extra leading underscore, and nothing else."
        );
    }
    assert!(
        !graded.is_empty()
            || CROSS_ARCH_TWINS
                .iter()
                .all(|name: &&str| { read_host_sourced(macos_system_binary(name)).is_none() }),
        "every fixture this case could read was present, yet none of them carried an \
         authenticated arm64e chain, so this case measured nothing while reporting success"
    );
}

#[test]
fn a_large_authenticated_image_resolves_nearly_all_of_its_twins_imports() {
    let fixture: CorpusFixture = macos_system_binary("codesign");
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(fixture) else {
        return;
    };
    let (Some(arm), Some(intel)): (Option<SliceImports>, Option<SliceImports>) = (
        imports_of(fixture, &bytes, CpuKind::Arm64),
        imports_of(fixture, &bytes, CpuKind::X86_64),
    ) else {
        return;
    };
    if !arm
        .formats
        .iter()
        .any(|format: &ChainedPointerFormat| format.is_authenticated())
    {
        return;
    }
    assert_names_are_well_formed("codesign[arm64e]", &arm);

    let arm_names: BTreeSet<String> = normalized_set(&arm.names);
    let intel_names: BTreeSet<String> = normalized_set(&intel.names);
    let shared: usize = arm_names.intersection(&intel_names).count();
    let floor: usize = arm_names.len() * 95 / 100;
    assert!(
        shared >= floor,
        "codesign carries some architecture specific code, so its two slices do not import \
         exactly the same set, but a decode that landed on the wrong fields would not agree with \
         its twin at all: {shared} of {} arm64e imports are also imported by the intel slice, \
         below the {floor} this requires",
        arm_names.len()
    );
    assert!(
        arm.slots >= 100,
        "codesign binds hundreds of slots through its chain, so a run that resolves {} has \
         stopped walking early",
        arm.slots
    );
}

#[test]
fn every_authenticated_format_seen_in_the_corpus_is_one_this_pass_decodes() {
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for name in [
        "codesign",
        "sqlite3",
        "grep",
        "awk",
        "sed",
        "otool",
        "lipo",
        "ls",
        "python3",
        "dyld",
        "file",
        "swift-driver",
    ] {
        let fixture: CorpusFixture = macos_system_binary(name);
        let Some(bytes): Option<Vec<u8>> = read_host_sourced(fixture) else {
            continue;
        };
        for cpu in [CpuKind::Arm64, CpuKind::X86_64] {
            let Some(imports): Option<SliceImports> = imports_of(fixture, &bytes, cpu) else {
                continue;
            };
            for format in &imports.formats {
                assert!(
                    !matches!(format, ChainedPointerFormat::Unsupported(_)),
                    "{name}[{cpu:?}] uses chained fixup pointer format {format:?}, which this \
                     pass does not decode. An undecoded format is reported as unsupported rather \
                     than guessed at, but every format the corpus actually contains should be one \
                     the walker handles"
                );
                seen.insert(format.label());
            }
        }
    }
    if !seen.is_empty() {
        assert!(
            seen.contains("arm64e-userland24") || seen.contains("arm64e"),
            "the corpus is expected to contain at least one authenticated arm64e image, and \
             without one the authenticated decode is never exercised against a real binary; saw \
             {seen:?}"
        );
    }
}
