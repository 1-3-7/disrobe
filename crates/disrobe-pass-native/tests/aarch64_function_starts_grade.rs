#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_ir::payload::{DisasmPayload, DisasmSymbol, DisasmSymbolKind};
use disrobe_pass_native::build_disasm_payload;
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind as ObjSymbolKind};

const STATIC_STRIPPED: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64.stripped.elf");

const STATIC_REFERENCE: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64.unstripped.elf");

const SHARED_STRIPPED: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_shared.stripped.elf");

const SHARED_REFERENCE: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_shared.unstripped.elf");

const PLAIN_STRIPPED: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_nounwind.stripped.elf");

const PLAIN_REFERENCE: &[u8] =
    include_bytes!("../../../corpus/native/discovery/disc_aarch64_nounwind.unstripped.elf");

const PE_GUARD_CF_STRIPPED: &[u8] = include_bytes!("fixtures/pe_arm64_guard_cf.exe");

const PE_GUARD_CF_REFERENCE: &[u8] = include_bytes!("fixtures/pe_arm64_guard_cf.reference.exe");

const UNWOUND_RECALL_FLOOR_PERMILLE: u64 = 1000;

const PLAIN_RECALL_FLOOR_PERMILLE: u64 = 962;

const PRECISION_FLOOR_PERMILLE: u64 = 1000;

const STATIC_REFERENCE_STARTS: usize = 27;

const SHARED_REFERENCE_STARTS: usize = 25;

const PE_GUARD_CF_REFERENCE_STARTS: usize = 4;

const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

const TOOL_CAPTURE_LIMIT: usize = 1 << 20;

const ELF_PLT_SOURCE: &str = r#"
extern long external_alpha(long);
extern long external_beta(long);

__attribute__((noinline, visibility("hidden"))) long plt_caller(long value) {
    return external_alpha(value) + external_beta(value + 1);
}
"#;

const ELF_EH_FRAME_HDR_SOURCE: &str = r#"
__attribute__((noinline, visibility("hidden"))) long header_alpha(long value) {
    return value + 3;
}

__attribute__((noinline, visibility("hidden"))) long header_beta(long value) {
    return value * 5;
}

__attribute__((noinline, visibility("hidden"))) long header_gamma(long value) {
    return value ^ 7;
}
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tally {
    truth: usize,
    recovered: usize,
    hits: usize,
    strays: usize,
}

impl Tally {
    const fn recall_permille(self) -> u64 {
        if self.truth == 0 {
            return 0;
        }
        (self.hits as u64).saturating_mul(1000) / self.truth as u64
    }

    const fn precision_permille(self) -> u64 {
        if self.recovered == 0 {
            return 0;
        }
        ((self.recovered - self.strays) as u64).saturating_mul(1000) / self.recovered as u64
    }
}

fn reference_starts(unstripped: &[u8]) -> BTreeMap<u64, String> {
    let file: object::File<'_> =
        object::File::parse(unstripped).expect("the reference twin must parse");
    let text_sections: BTreeSet<usize> = file
        .sections()
        .filter(|section: &object::Section<'_, '_>| {
            matches!(section.kind(), object::SectionKind::Text)
        })
        .map(|section: object::Section<'_, '_>| section.index().0)
        .collect();
    assert!(
        !text_sections.is_empty(),
        "the reference twin must carry an executable section"
    );
    let mut starts: BTreeMap<u64, String> = BTreeMap::new();
    for symbol in file.symbols() {
        if !matches!(symbol.kind(), ObjSymbolKind::Text) {
            continue;
        }
        let object::SymbolSection::Section(index) = symbol.section() else {
            continue;
        };
        if !text_sections.contains(&index.0) {
            continue;
        }
        let name: String = symbol.name().unwrap_or("<unnamed>").to_owned();
        starts.entry(symbol.address()).or_insert(name);
    }
    starts
}

fn recovered_starts(stripped: &[u8]) -> BTreeSet<u64> {
    let payload: DisasmPayload =
        build_disasm_payload(stripped).expect("the stripped image must disassemble");
    payload
        .symbol_table
        .iter()
        .filter(|symbol: &&DisasmSymbol| {
            matches!(
                symbol.kind,
                DisasmSymbolKind::Function | DisasmSymbolKind::Export
            )
        })
        .map(|symbol: &DisasmSymbol| symbol.address)
        .collect()
}

fn stripped_aarch64_plt_image() -> Vec<u8> {
    let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary directory");
    let source: PathBuf = directory.path().join("plt.c");
    let output: PathBuf = directory.path().join("plt.so");
    fs::write(&source, ELF_PLT_SOURCE).expect("write fixture source");
    let arguments: Vec<OsString> = vec![
        OsString::from("--target=aarch64-unknown-linux-gnu"),
        OsString::from("-O1"),
        OsString::from("-fPIC"),
        OsString::from("-fuse-ld=lld"),
        OsString::from("-nostdlib"),
        OsString::from("-shared"),
        OsString::from("-Wl,--strip-all"),
        OsString::from("-o"),
        output.as_os_str().to_os_string(),
        source.as_os_str().to_os_string(),
    ];
    let compiled: CapturedOutput = run_captured(
        Path::new("clang"),
        &arguments,
        TOOL_TIMEOUT,
        TOOL_CAPTURE_LIMIT,
    )
    .expect("start the AArch64 PLT fixture compiler")
    .expect("the AArch64 PLT fixture compiler exceeded its timeout");
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "clang failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    fs::read(output).expect("read linked fixture")
}

fn aarch64_eh_frame_hdr_images() -> (Vec<u8>, Vec<u8>) {
    let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary directory");
    let source: PathBuf = directory.path().join("eh_frame_hdr.c");
    let reference: PathBuf = directory.path().join("eh_frame_hdr.reference.so");
    let stripped: PathBuf = directory.path().join("eh_frame_hdr.stripped.so");
    fs::write(&source, ELF_EH_FRAME_HDR_SOURCE).expect("write fixture source");
    let arguments: Vec<OsString> = vec![
        OsString::from("--target=aarch64-unknown-linux-gnu"),
        OsString::from("-O1"),
        OsString::from("-fPIC"),
        OsString::from("-fuse-ld=lld"),
        OsString::from("-nostdlib"),
        OsString::from("-shared"),
        OsString::from("-Wl,--eh-frame-hdr"),
        OsString::from("-o"),
        reference.as_os_str().to_os_string(),
        source.as_os_str().to_os_string(),
    ];
    let compiled: CapturedOutput = run_captured(
        Path::new("clang"),
        &arguments,
        TOOL_TIMEOUT,
        TOOL_CAPTURE_LIMIT,
    )
    .expect("start the AArch64 eh-frame-header fixture compiler")
    .expect("the AArch64 eh-frame-header fixture compiler exceeded its timeout");
    assert_eq!(
        compiled.exit_code,
        Some(0),
        "clang failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compiled.stdout),
        String::from_utf8_lossy(&compiled.stderr)
    );
    let strip_arguments: Vec<OsString> = vec![
        OsString::from("--strip-all"),
        OsString::from("-o"),
        stripped.as_os_str().to_os_string(),
        reference.as_os_str().to_os_string(),
    ];
    let stripped_output: CapturedOutput = run_captured(
        Path::new("llvm-strip"),
        &strip_arguments,
        TOOL_TIMEOUT,
        TOOL_CAPTURE_LIMIT,
    )
    .expect("start the AArch64 fixture stripper")
    .expect("the AArch64 fixture stripper exceeded its timeout");
    assert_eq!(
        stripped_output.exit_code,
        Some(0),
        "llvm-strip failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stripped_output.stdout),
        String::from_utf8_lossy(&stripped_output.stderr)
    );
    (
        fs::read(reference).expect("read unstripped eh-frame-header fixture"),
        fs::read(stripped).expect("read stripped eh-frame-header fixture"),
    )
}

fn aarch64_plt_starts(bytes: &[u8]) -> BTreeSet<u64> {
    let file: object::File<'_> = object::File::parse(bytes).expect("parse linked fixture");
    let plt: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            section.name().is_ok_and(|name: &str| name == ".plt")
        })
        .expect("linked fixture must contain .plt");
    let plt_end: u64 = plt.address().checked_add(plt.size()).expect("PLT extent");
    let text: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            section.name().is_ok_and(|name: &str| name == ".text")
        })
        .expect("linked fixture must contain .text");
    text.data()
        .expect("text data")
        .chunks_exact(4)
        .enumerate()
        .filter_map(|(index, word): (usize, &[u8])| {
            let word: [u8; 4] = word.try_into().ok()?;
            let instruction: u32 = u32::from_le_bytes(word);
            if instruction & 0xFC00_0000 != 0x9400_0000 {
                return None;
            }
            let offset: u64 = u64::try_from(index).ok()?.checked_mul(4)?;
            let site: u64 = text.address().checked_add(offset)?;
            let immediate: i64 = ((i64::from(instruction & 0x03FF_FFFF)) << 38) >> 36;
            let target: u64 = site.checked_add_signed(immediate)?;
            (target >= plt.address() && target < plt_end).then_some(target)
        })
        .collect()
}

fn erase_got_plt_contents(bytes: &mut [u8]) {
    let file: object::File<'_> = object::File::parse(&*bytes).expect("parse linked fixture");
    let section: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            section.name().is_ok_and(|name: &str| name == ".got.plt")
        })
        .expect("linked fixture must contain .got.plt");
    let (offset, size): (u64, u64) = section.file_range().expect(".got.plt has file range");
    let start: usize = usize::try_from(offset).expect(".got.plt offset fits usize");
    let length: usize = usize::try_from(size).expect(".got.plt size fits usize");
    let end: usize = start
        .checked_add(length)
        .expect(".got.plt extent fits usize");
    bytes
        .get_mut(start..end)
        .expect(".got.plt range lies inside linked fixture")
        .fill(0);
}

fn erase_section_contents(bytes: &mut [u8], name: &str) {
    let file: object::File<'_> = object::File::parse(&*bytes).expect("parse linked fixture");
    let section: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            section
                .name()
                .is_ok_and(|candidate: &str| candidate == name)
        })
        .expect("linked fixture must contain requested section");
    let (offset, size): (u64, u64) = section.file_range().expect("section has file range");
    let start: usize = usize::try_from(offset).expect("section offset fits usize");
    let length: usize = usize::try_from(size).expect("section size fits usize");
    let end: usize = start
        .checked_add(length)
        .expect("section extent fits usize");
    bytes
        .get_mut(start..end)
        .expect("section range lies inside linked fixture")
        .fill(0);
}

fn grade(
    label: &str,
    stripped: &[u8],
    unstripped: &[u8],
    expected_starts: usize,
    recall_floor: u64,
) -> Tally {
    let truth: BTreeMap<u64, String> = reference_starts(unstripped);
    assert_eq!(
        truth.len(),
        expected_starts,
        "{label}: the committed reference twin changed shape"
    );
    let recovered: BTreeSet<u64> = recovered_starts(stripped);
    let hits: usize = truth
        .keys()
        .filter(|address: &&u64| recovered.contains(address))
        .count();
    let strays: usize = recovered
        .iter()
        .filter(|address: &&u64| !truth.contains_key(address))
        .count();
    let tally: Tally = Tally {
        truth: truth.len(),
        recovered: recovered.len(),
        hits,
        strays,
    };
    let missed: Vec<&str> = truth
        .iter()
        .filter(|(address, _): &(&u64, &String)| !recovered.contains(address))
        .map(|(_, name): (&u64, &String)| name.as_str())
        .collect();
    println!(
        "{label}: recall {}/{} at {} permille, precision {}/{} at {} permille, missed {missed:?}",
        tally.hits,
        tally.truth,
        tally.recall_permille(),
        tally.recovered - tally.strays,
        tally.recovered,
        tally.precision_permille()
    );
    assert!(
        tally.recall_permille() >= recall_floor,
        "{label}: recall {}/{} is below the floor, missed {missed:?}",
        tally.hits,
        tally.truth
    );
    assert!(
        tally.precision_permille() >= PRECISION_FLOOR_PERMILLE,
        "{label}: {} of {} recovered starts are absent from the reference twin",
        tally.strays,
        tally.recovered
    );
    tally
}

fn recovered_names(stripped: &[u8], unstripped: &[u8]) -> BTreeSet<String> {
    let truth: BTreeMap<u64, String> = reference_starts(unstripped);
    let recovered: BTreeSet<u64> = recovered_starts(stripped);
    truth
        .into_iter()
        .filter(|(address, _): &(u64, String)| recovered.contains(address))
        .map(|(_, name): (u64, String)| name)
        .collect()
}

#[test]
fn a_stripped_static_image_recovers_every_reference_start() {
    let tally: Tally = grade(
        "static",
        STATIC_STRIPPED,
        STATIC_REFERENCE,
        STATIC_REFERENCE_STARTS,
        UNWOUND_RECALL_FLOOR_PERMILLE,
    );
    assert_eq!(tally.strays, 0, "no start outside the reference twin");
}

#[test]
fn a_stripped_shared_object_recovers_every_reference_start() {
    let tally: Tally = grade(
        "shared",
        SHARED_STRIPPED,
        SHARED_REFERENCE,
        SHARED_REFERENCE_STARTS,
        UNWOUND_RECALL_FLOOR_PERMILLE,
    );
    assert_eq!(tally.strays, 0, "no start outside the reference twin");
}

#[test]
fn a_stripped_pe_arm64_image_recovers_every_guard_cf_function_start() {
    let tally: Tally = grade(
        "pe-guard-cf",
        PE_GUARD_CF_STRIPPED,
        PE_GUARD_CF_REFERENCE,
        PE_GUARD_CF_REFERENCE_STARTS,
        1000,
    );
    assert_eq!(tally.strays, 0, "no start outside the reference twin");
}

#[test]
fn an_image_without_unwind_tables_recovers_all_but_its_tail_called_start() {
    let tally: Tally = grade(
        "no-unwind",
        PLAIN_STRIPPED,
        PLAIN_REFERENCE,
        STATIC_REFERENCE_STARTS,
        PLAIN_RECALL_FLOOR_PERMILLE,
    );
    assert_eq!(tally.strays, 0, "no start outside the reference twin");
    let names: BTreeSet<String> = recovered_names(PLAIN_STRIPPED, PLAIN_REFERENCE);
    assert!(
        !names.contains("clamp_high"),
        "a tail-called start with no unwind entry is the recorded residual, not a pass"
    );
}

#[test]
fn starts_with_no_incoming_call_are_recovered_from_their_evidence() {
    for (label, stripped, unstripped) in [
        ("static", STATIC_STRIPPED, STATIC_REFERENCE),
        ("shared", SHARED_STRIPPED, SHARED_REFERENCE),
        ("no-unwind", PLAIN_STRIPPED, PLAIN_REFERENCE),
    ] {
        let names: BTreeSet<String> = recovered_names(stripped, unstripped);
        for required in [
            "only_from_data",
            "also_only_from_data",
            "discovery_ctor",
            "discovery_dtor",
        ] {
            assert!(
                names.contains(required),
                "{label}: {required} has no incoming call and must come from its own evidence, recovered {names:?}"
            );
        }
    }
    for (label, stripped, unstripped) in [
        ("static", STATIC_STRIPPED, STATIC_REFERENCE),
        ("shared", SHARED_STRIPPED, SHARED_REFERENCE),
    ] {
        let names: BTreeSet<String> = recovered_names(stripped, unstripped);
        assert!(
            names.contains("clamp_high"),
            "{label}: a tail-called start comes from the unwind table, recovered {names:?}"
        );
    }
}

#[test]
fn discovery_repeats_byte_for_byte() {
    for stripped in [STATIC_STRIPPED, SHARED_STRIPPED, PLAIN_STRIPPED] {
        let first: BTreeSet<u64> = recovered_starts(stripped);
        let second: BTreeSet<u64> = recovered_starts(stripped);
        assert_eq!(first, second, "discovery must repeat exactly");
    }
}

#[test]
fn stripped_elf_jump_slots_seed_each_aarch64_plt_entry() {
    let mut image: Vec<u8> = stripped_aarch64_plt_image();
    let expected: BTreeSet<u64> = aarch64_plt_starts(&image);
    assert_eq!(
        expected.len(),
        2,
        "the caller must have two direct PLT calls"
    );
    erase_got_plt_contents(&mut image);
    erase_section_contents(&mut image, ".eh_frame");
    let recovered: BTreeSet<u64> = recovered_starts(&image);
    let file: object::File<'_> = object::File::parse(&*image).expect("parse stripped fixture");
    let plt: object::Section<'_, '_> = file
        .sections()
        .find(|section: &object::Section<'_, '_>| {
            section.name().is_ok_and(|name: &str| name == ".plt")
        })
        .expect("PLT section");
    let plt_end: u64 = plt.address().checked_add(plt.size()).expect("PLT extent");
    let recovered_plt: BTreeSet<u64> = recovered
        .iter()
        .copied()
        .filter(|address: &u64| *address >= plt.address() && *address < plt_end)
        .collect();
    assert_eq!(
        recovered_plt, expected,
        "only called PLT stubs may be discovered; PLT0 and trailing bytes are not starts"
    );
    assert!(
        expected.is_subset(&recovered),
        "every .rela.plt JUMP_SLOT must seed its corresponding PLT entry; expected {expected:?}, recovered {recovered:?}"
    );
}

fn eh_frame_header_reference_starts(reference: &[u8]) -> BTreeMap<u64, String> {
    reference_starts(reference)
        .into_iter()
        .filter(|(_, name): &(u64, String)| name.starts_with("header_"))
        .collect()
}

#[test]
fn stripped_elf_eh_frame_header_is_load_bearing_for_disassembly() {
    let (reference, stripped): (Vec<u8>, Vec<u8>) = aarch64_eh_frame_hdr_images();
    let expected: BTreeMap<u64, String> = eh_frame_header_reference_starts(&reference);
    assert_eq!(
        expected.len(),
        3,
        "the compiler reference must retain the three hidden functions"
    );
    let expected_addresses: BTreeSet<u64> = expected.keys().copied().collect();
    let mut without_unwind_sources: Vec<u8> = stripped.clone();
    erase_section_contents(&mut without_unwind_sources, ".eh_frame");
    erase_section_contents(&mut without_unwind_sources, ".eh_frame_hdr");
    let negative: BTreeSet<u64> = recovered_starts(&without_unwind_sources)
        .intersection(&expected_addresses)
        .copied()
        .collect();
    assert!(
        negative.is_empty(),
        "the three hidden starts must disappear when both unwind sources are erased, found {negative:?}"
    );
    let mut header_only: Vec<u8> = stripped;
    erase_section_contents(&mut header_only, ".eh_frame");
    let recovered: BTreeSet<u64> = recovered_starts(&header_only);
    assert!(
        expected_addresses.is_subset(&recovered),
        "the stripped .eh_frame_hdr must seed all 3 independently named functions; expected {expected_addresses:?}, recovered {recovered:?}"
    );
}
