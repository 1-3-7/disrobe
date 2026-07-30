#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod packer_fixture;

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::packers::emulated_unpack::{
    EmulatedUnpack, EmulationConfig, emulate_unpack_stub,
};
use disrobe_pass_native::packers::pe_sections::{PeImage, PeSection, parse_pe_image};
use disrobe_pass_native::packers::section_recovery::{
    GranuleRecovery, SectionRecoveryReport, SectionRole, section_recovery_report,
};
use disrobe_pass_native::packers::stub_pack_oracle::{
    PackedImage, SectionSpec, StubKind, build_packed,
};
use packer_fixture::{CommittedFixture, PackerFixture, declared_byte_defect, load_fixture};

#[derive(Debug, Clone, Copy)]
struct ContentFloor {
    matching: usize,
    compared: usize,
}

#[derive(Debug, Clone, Copy)]
struct SectionFloor {
    name: &'static str,
    matching: usize,
    compared: usize,
}

const CONSTRUCTED_FAMILY: &str = "stub_pack";

const MULTI_ORIGINAL: &str = "multi.original.exe";
const MULTI_PACKED: &str = "multi.packed.lz.exe";
const SINGLE_ORIGINAL: &str = "single.original.exe";
const SINGLE_PACKED_STREAM: &str = "single.packed.stream.exe";

const POLY_SHAPES: usize = 4;

const POLY_PACKED: &[&str] = &[
    "single.packed.poly0.exe",
    "single.packed.poly1.exe",
    "single.packed.poly2.exe",
    "single.packed.poly3.exe",
];

const COMMITTED_STUB_PACK: &[CommittedFixture] = &[
    CommittedFixture {
        family: CONSTRUCTED_FAMILY,
        name: MULTI_ORIGINAL,
        size_bytes: 4_608,
        crc32: 0x37c9_4740,
    },
    CommittedFixture {
        family: CONSTRUCTED_FAMILY,
        name: MULTI_PACKED,
        size_bytes: 6_656,
        crc32: 0x0026_af25,
    },
    CommittedFixture {
        family: CONSTRUCTED_FAMILY,
        name: SINGLE_ORIGINAL,
        size_bytes: 3_072,
        crc32: 0x5d46_d26f,
    },
    CommittedFixture {
        family: CONSTRUCTED_FAMILY,
        name: SINGLE_PACKED_STREAM,
        size_bytes: 3_584,
        crc32: 0xe4d1_0e64,
    },
    CommittedFixture {
        family: CONSTRUCTED_FAMILY,
        name: "single.packed.poly0.exe",
        size_bytes: 3_584,
        crc32: 0x6f38_b664,
    },
    CommittedFixture {
        family: CONSTRUCTED_FAMILY,
        name: "single.packed.poly1.exe",
        size_bytes: 3_584,
        crc32: 0x3063_df15,
    },
    CommittedFixture {
        family: CONSTRUCTED_FAMILY,
        name: "single.packed.poly2.exe",
        size_bytes: 3_584,
        crc32: 0x3845_5a1f,
    },
    CommittedFixture {
        family: CONSTRUCTED_FAMILY,
        name: "single.packed.poly3.exe",
        size_bytes: 3_584,
        crc32: 0xb590_54bf,
    },
];

const OEP_RVA: u32 = 0x1000;
const STEP_CAP: u64 = 50_000_000;
const LZ_STUB_SECTION: &[u8] = b".nPack";
const STREAM_STUB_SECTION: &[u8] = b".aspr";
const STUB_CODE_PAD: u32 = 0x400;
const STREAM_KEY0: u8 = 0x5A;
const STREAM_KEY_STEP: u8 = 0x13;
const PLAINTEXT_NEEDLE: &[u8] = b"the quick brown fox jumps over the lazy dog";

const TEXT_LEN: usize = 2048;
const RDATA_LEN: usize = 1024;
const DATA_LEN: usize = 512;
const MULTI_CONTENT_BYTES: usize = TEXT_LEN + RDATA_LEN + DATA_LEN;

const MULTI_CONTENT: ContentFloor = ContentFloor {
    matching: 3_584,
    compared: 3_584,
};

const MULTI_SECTIONS: &[SectionFloor] = &[
    SectionFloor {
        name: ".text",
        matching: 2_048,
        compared: 2_048,
    },
    SectionFloor {
        name: ".rdata",
        matching: 1_024,
        compared: 1_024,
    },
    SectionFloor {
        name: ".data",
        matching: 512,
        compared: 512,
    },
];

const MULTI_IDENTICAL: &[&str] = &[".text", ".rdata", ".data"];

const SINGLE_CONTENT: ContentFloor = ContentFloor {
    matching: 2_048,
    compared: 2_048,
};

const SINGLE_SECTIONS: &[SectionFloor] = &[SectionFloor {
    name: ".text",
    matching: 2_048,
    compared: 2_048,
}];

const SINGLE_IDENTICAL: &[&str] = &[".text"];

const MULTI_STUB_WRITES: usize = 3_584;
const SINGLE_STUB_WRITES: usize = 2_040;

const CORRUPT_RVA: usize = 0x1400;
const CORRUPT_TEXT_OFFSET: u32 = 0x400;

const VENDOR_DECODER: &str = "stub-emulator generic entry";
const VENDOR_FAMILY: &str = "aspack";
const VENDOR_PACKED: &str = "AccessEnum.packed.aspack.exe";
const VENDOR_ORIGINAL: &str = "AccessEnum.original.exe";
const VENDOR_STUB_SECTIONS: &[&[u8]] = &[b".aspack", b".adata"];

const VENDOR_CONTENT: ContentFloor = ContentFloor {
    matching: 13_469,
    compared: 164_194,
};

const VENDOR_SECTIONS: &[SectionFloor] = &[
    SectionFloor {
        name: ".text",
        matching: 1_501,
        compared: 28_440,
    },
    SectionFloor {
        name: ".rdata",
        matching: 2_027,
        compared: 10_638,
    },
    SectionFloor {
        name: ".data",
        matching: 4_430,
        compared: 113_204,
    },
    SectionFloor {
        name: ".rsrc",
        matching: 5_511,
        compared: 11_912,
    },
];

fn fixture_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("tests");
    root.push("fixtures");
    root.push("stub_pack");
    root
}

fn declared(name: &str) -> &'static CommittedFixture {
    COMMITTED_STUB_PACK
        .iter()
        .find(|f: &&CommittedFixture| f.name == name)
        .unwrap_or_else(|| {
            panic!(
                "{name} carries pinned figures in this file but is absent from COMMITTED_STUB_PACK, \
                 so nothing checks that the bytes graded are the bytes those figures were measured \
                 from"
            )
        })
}

fn committed(name: &str) -> Vec<u8> {
    let entry: &CommittedFixture = declared(name);
    let path: PathBuf = fixture_root().join(name);
    let bytes: Vec<u8> = fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "the pre-pack pair this file grades against is committed at {}, so an absent or \
             unreadable fixture is never a skip: {err}",
            path.display()
        )
    });
    let defect: Option<String> = declared_byte_defect(entry, &bytes);
    assert!(
        defect.is_none(),
        "a pinned figure only means something against the exact fixture bytes it was measured \
         from, so {} must reject bytes that have moved: {defect:?}",
        path.display()
    );
    bytes
}

fn filled(line: &[u8], len: usize) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(len + line.len());
    while body.len() < len {
        body.extend_from_slice(line);
    }
    body.truncate(len);
    body
}

fn text_body() -> Vec<u8> {
    filled(
        b"the quick brown fox jumps over the lazy dog; pack me and recover me byte-exact. ",
        TEXT_LEN,
    )
}

fn rdata_body() -> Vec<u8> {
    filled(
        b"read-only literal pool row; recovered from the compressed payload. ",
        RDATA_LEN,
    )
}

fn data_body() -> Vec<u8> {
    filled(
        b"writable initialized data row; recovered from the same payload. ",
        DATA_LEN,
    )
}

fn build_multi() -> PackedImage {
    let secs: Vec<SectionSpec<'_>> = vec![
        SectionSpec {
            name: b".text",
            rva: 0x1000,
            body: text_body(),
        },
        SectionSpec {
            name: b".rdata",
            rva: 0x2000,
            body: rdata_body(),
        },
        SectionSpec {
            name: b".data",
            rva: 0x3000,
            body: data_body(),
        },
    ];
    build_packed(&secs, OEP_RVA, LZ_STUB_SECTION, StubKind::LzDecompress)
}

fn build_single(kind: StubKind) -> PackedImage {
    let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: text_body(),
    }];
    build_packed(&secs, OEP_RVA, STREAM_STUB_SECTION, kind)
}

const fn poly_kind(seed: u8) -> StubKind {
    StubKind::StreamDecryptPoly {
        key0: STREAM_KEY0.wrapping_add(seed.wrapping_mul(7)),
        key_step: STREAM_KEY_STEP.wrapping_add(seed.wrapping_mul(11)),
        seed,
    }
}

fn emulated(packed: &[u8], original: &[u8], stub_names: &[&[u8]], stub_rva: u32) -> EmulatedUnpack {
    let img: PeImage = parse_pe_image(packed)
        .unwrap_or_else(|err| panic!("the committed packed image must parse as a PE: {err}"));
    let config: EmulationConfig<'_> = EmulationConfig {
        stub_section_names: stub_names,
        content_exclude: &[],
        step_cap: STEP_CAP,
    };
    emulate_unpack_stub(packed, &img, stub_rva, Some(original), &config)
        .unwrap_or_else(|err| panic!("emulation of the committed packed image must run: {err}"))
}

fn stub_rva_of(packed: &[u8], stub_name: &[u8]) -> u32 {
    let img: PeImage = parse_pe_image(packed)
        .unwrap_or_else(|err| panic!("the committed packed image must parse as a PE: {err}"));
    let stub: &PeSection = img.section_by_name(stub_name).unwrap_or_else(|| {
        panic!(
            "the stub section {} must be located in the committed packed image by name, because \
             the emulator is given only the packed bytes",
            String::from_utf8_lossy(stub_name)
        )
    });
    stub.virtual_address
}

fn report_of(out: &EmulatedUnpack) -> &SectionRecoveryReport {
    out.section_report.as_ref().unwrap_or_else(|| {
        panic!("a per-section report against the committed original is what this file grades")
    })
}

fn row<'a>(report: &'a SectionRecoveryReport, name: &str) -> &'a GranuleRecovery {
    report
        .sections
        .iter()
        .find(|s: &&GranuleRecovery| s.name == name)
        .unwrap_or_else(|| panic!("section {name} must appear in the recovery report"))
}

fn assert_pinned(
    label: &str,
    report: &SectionRecoveryReport,
    content: ContentFloor,
    sections: &[SectionFloor],
) {
    print!("{}", report.render());
    assert_eq!(
        report.content_compared, content.compared,
        "{label}: the content denominator is the committed original's own section span, so it must \
         stay {} bytes; a recovery that emits fewer bytes must score worse, never shrink its own \
         denominator",
        content.compared
    );
    assert!(
        report.content_matching >= content.matching,
        "{label}: content byte-recovery against the committed original must hold at or above the \
         measured {}/{} ({:.2}%); got {}/{} ({:.2}%)",
        content.matching,
        content.compared,
        100.0 * content.matching as f64 / content.compared as f64,
        report.content_matching,
        report.content_compared,
        report.content_recovery_pct(),
    );
    for floor in sections {
        let granule: &GranuleRecovery = row(report, floor.name);
        assert_eq!(
            granule.compared, floor.compared,
            "{label} {}: compared span must stay {} bytes",
            floor.name, floor.compared
        );
        assert!(
            granule.matching >= floor.matching,
            "{label} {}: must hold at or above the measured {}/{}; got {}/{}",
            floor.name,
            floor.matching,
            floor.compared,
            granule.matching,
            granule.compared
        );
    }
}

fn assert_byte_identical_membership(
    label: &str,
    report: &SectionRecoveryReport,
    expected: &[&str],
) {
    let identical: Vec<&str> = report
        .sections
        .iter()
        .filter(|s: &&GranuleRecovery| s.role == SectionRole::Content && s.is_byte_identical())
        .map(|s: &GranuleRecovery| s.name.as_str())
        .collect();
    assert_eq!(
        identical, expected,
        "{label}: the byte-identical content sections are a membership list, not a count; a \
         section that stops recovering exactly must drop out of it"
    );
}

fn assert_reached_oep(label: &str, out: &EmulatedUnpack, stub_writes: usize) {
    assert_eq!(
        out.oep_rva,
        Some(OEP_RVA),
        "{label}: the stub must transfer control to the committed original's entry point",
    );
    assert!(
        out.reached_oep(),
        "{label}: reaching the entry point without writing a content byte is not an unpack",
    );
    assert!(
        out.content_bytes_mutated_by_stub >= stub_writes,
        "{label}: the stub must write at least the measured {stub_writes} content bytes; got {}",
        out.content_bytes_mutated_by_stub,
    );
}

#[test]
fn every_pinned_figure_is_bound_to_committed_and_intact_fixture_bytes() {
    let mut defects: Vec<String> = Vec::new();
    for entry in COMMITTED_STUB_PACK {
        let path: PathBuf = fixture_root().join(entry.name);
        match fs::read(&path) {
            Ok(bytes) => defects.extend(declared_byte_defect(entry, &bytes)),
            Err(err) => defects.push(format!(
                "{}/{} is committed in this crate but unreadable at {} ({err})",
                entry.family,
                entry.name,
                path.display()
            )),
        }
    }
    assert!(
        defects.is_empty(),
        "every figure in this file was measured against these exact committed bytes, so a fixture \
         whose bytes have moved must fail here instead of being regraded silently: {}",
        defects.join("; ")
    );

    let mut present: Vec<String> = Vec::new();
    for entry in fs::read_dir(fixture_root())
        .unwrap_or_else(|err| panic!("the committed fixture directory must be readable: {err}"))
    {
        let entry: fs::DirEntry = entry
            .unwrap_or_else(|err| panic!("every fixture directory entry must be readable: {err}"));
        present.push(entry.file_name().to_string_lossy().into_owned());
    }
    present.sort();
    let mut registered: Vec<String> = COMMITTED_STUB_PACK
        .iter()
        .map(|f: &CommittedFixture| f.name.to_owned())
        .collect();
    registered.sort();
    assert_eq!(
        present, registered,
        "the committed pairs are a membership list, not a count: a fixture added to the directory \
         without a pinned size and crc32, or removed while its figures stay in this file, must fail \
         here"
    );
}

#[test]
fn committed_lz_pair_recovers_every_content_section_against_the_committed_original() {
    let packed: Vec<u8> = committed(MULTI_PACKED);
    let original: Vec<u8> = committed(MULTI_ORIGINAL);
    let stub_rva: u32 = stub_rva_of(&packed, LZ_STUB_SECTION);
    let out: EmulatedUnpack = emulated(&packed, &original, &[LZ_STUB_SECTION], stub_rva);
    println!(
        "LZ multi: oep={:?} stub_writes={} steps={} whole={:?}",
        out.oep_rva,
        out.content_bytes_mutated_by_stub,
        out.steps_executed,
        out.whole_image_recovery_pct
    );
    assert_reached_oep("LZ multi", &out, MULTI_STUB_WRITES);
    let report: &SectionRecoveryReport = report_of(&out);
    assert_pinned("LZ multi", report, MULTI_CONTENT, MULTI_SECTIONS);
    assert_byte_identical_membership("LZ multi", report, MULTI_IDENTICAL);
}

#[test]
fn committed_lz_packed_image_holds_no_copy_of_the_original_content() {
    let packed: Vec<u8> = committed(MULTI_PACKED);
    let img: PeImage = parse_pe_image(&packed).expect("committed packed image parses");
    let mut spanned: usize = 0;
    let mut nonzero: usize = 0;
    for sec in &img.sections {
        if sec.name_is(LZ_STUB_SECTION) {
            continue;
        }
        let (start, end): (usize, usize) = sec
            .raw_range(packed.len())
            .unwrap_or_else(|| panic!("content section raw range must be in file"));
        spanned += end - start;
        nonzero += packed[start..end].iter().filter(|b: &&u8| **b != 0).count();
    }
    assert_eq!(
        spanned, MULTI_CONTENT_BYTES,
        "all {MULTI_CONTENT_BYTES} content bytes of the packed image must be inspected here",
    );
    assert_eq!(
        nonzero, 0,
        "every content byte of the committed packed image is zero, so a recovered content byte can \
         only come from the emulated decompressor and never from a copy already present in the \
         input",
    );
    let stub: &PeSection = img
        .section_by_name(LZ_STUB_SECTION)
        .expect("stub section present");
    let payload: u32 = stub.virtual_size.saturating_sub(STUB_CODE_PAD);
    println!("LZ payload bytes: {payload}");
    assert!(
        payload > 0 && (payload as usize) < MULTI_CONTENT_BYTES,
        "the compressed payload must be non-empty and smaller than the {MULTI_CONTENT_BYTES} \
         content bytes it reconstructs; got {payload}",
    );
}

#[test]
fn committed_stream_pair_recovers_text_against_the_committed_original() {
    let packed: Vec<u8> = committed(SINGLE_PACKED_STREAM);
    let original: Vec<u8> = committed(SINGLE_ORIGINAL);
    assert!(
        !contains(&packed, PLAINTEXT_NEEDLE),
        "the committed encrypted image must not carry the plaintext, else recovery could be a copy",
    );
    let stub_rva: u32 = stub_rva_of(&packed, STREAM_STUB_SECTION);
    let out: EmulatedUnpack = emulated(&packed, &original, &[STREAM_STUB_SECTION], stub_rva);
    println!(
        "stream: oep={:?} stub_writes={} steps={}",
        out.oep_rva, out.content_bytes_mutated_by_stub, out.steps_executed
    );
    assert_reached_oep("stream", &out, SINGLE_STUB_WRITES);
    let report: &SectionRecoveryReport = report_of(&out);
    assert_pinned("stream", report, SINGLE_CONTENT, SINGLE_SECTIONS);
    assert_byte_identical_membership("stream", report, SINGLE_IDENTICAL);
}

#[test]
fn committed_polymorphic_pairs_recover_text_against_one_committed_original() {
    assert_eq!(
        POLY_PACKED.len(),
        POLY_SHAPES,
        "all {POLY_SHAPES} committed stub shapes must be graded here, so dropping one cannot pass \
         as a smaller run",
    );
    let original: Vec<u8> = committed(SINGLE_ORIGINAL);
    let mut shapes: Vec<Vec<u8>> = Vec::with_capacity(POLY_PACKED.len());
    for (seed, name) in POLY_PACKED.iter().enumerate() {
        let packed: Vec<u8> = committed(name);
        assert!(
            !contains(&packed, PLAINTEXT_NEEDLE),
            "{name}: the committed encrypted image must not carry the plaintext",
        );
        let stub_rva: u32 = stub_rva_of(&packed, STREAM_STUB_SECTION);
        let out: EmulatedUnpack = emulated(&packed, &original, &[STREAM_STUB_SECTION], stub_rva);
        println!(
            "poly seed {seed}: oep={:?} stub_writes={} steps={}",
            out.oep_rva, out.content_bytes_mutated_by_stub, out.steps_executed
        );
        let label: String = format!("poly seed {seed}");
        assert_reached_oep(&label, &out, SINGLE_STUB_WRITES);
        let report: &SectionRecoveryReport = report_of(&out);
        assert_pinned(&label, report, SINGLE_CONTENT, SINGLE_SECTIONS);
        assert_byte_identical_membership(&label, report, SINGLE_IDENTICAL);
        shapes.push(packed);
    }
    for (i, a) in shapes.iter().enumerate() {
        for (j, b) in shapes.iter().enumerate().skip(i + 1) {
            assert!(
                a != b,
                "seeds {i} and {j} must be different stub shapes, else the per-seed cases grade one \
                 layout four times",
            );
        }
    }
}

#[test]
fn one_corrupted_byte_is_named_by_offset_and_drops_the_pinned_figure() {
    let packed: Vec<u8> = committed(MULTI_PACKED);
    let original: Vec<u8> = committed(MULTI_ORIGINAL);
    let stub_rva: u32 = stub_rva_of(&packed, LZ_STUB_SECTION);
    let out: EmulatedUnpack = emulated(&packed, &original, &[LZ_STUB_SECTION], stub_rva);
    let clean: &SectionRecoveryReport = report_of(&out);
    let clean_text: &GranuleRecovery = row(clean, ".text");
    assert!(
        clean_text.is_byte_identical(),
        "the control needs a byte-identical section to corrupt",
    );

    let mut tampered: Vec<u8> = out.recovered_memory_image.clone();
    tampered[CORRUPT_RVA] ^= 0xFF;
    let report: SectionRecoveryReport =
        section_recovery_report(&original, &tampered, &[LZ_STUB_SECTION])
            .expect("tampered section report");
    let text: &GranuleRecovery = row(&report, ".text");
    assert!(
        !text.is_byte_identical(),
        "flipping one byte inside .text must break byte identity, else the comparison is measuring \
         nothing",
    );
    assert_eq!(
        text.first_mismatch_rel,
        Some(CORRUPT_TEXT_OFFSET),
        "the report must name the corrupted offset relative to the section start",
    );
    assert_eq!(
        text.matching,
        clean_text.matching - 1,
        "exactly one byte must stop matching",
    );
    assert_eq!(
        report.content_matching,
        clean.content_matching - 1,
        "the content figure must fall by exactly one byte",
    );
    assert!(
        report.content_matching < MULTI_CONTENT.matching,
        "the pinned figure must reject the corrupted image",
    );
}

#[test]
fn the_in_tree_packer_reproduces_every_committed_fixture_byte_for_byte() {
    let multi: PackedImage = build_multi();
    assert_same(MULTI_ORIGINAL, &multi.original, &committed(MULTI_ORIGINAL));
    assert_same(MULTI_PACKED, &multi.bytes, &committed(MULTI_PACKED));

    let stream: PackedImage = build_single(StubKind::StreamDecrypt {
        key0: STREAM_KEY0,
        key_step: STREAM_KEY_STEP,
    });
    assert_same(
        SINGLE_ORIGINAL,
        &stream.original,
        &committed(SINGLE_ORIGINAL),
    );
    assert_same(
        SINGLE_PACKED_STREAM,
        &stream.bytes,
        &committed(SINGLE_PACKED_STREAM),
    );

    for (seed, name) in POLY_PACKED.iter().enumerate() {
        let poly: PackedImage = build_single(poly_kind(seed as u8));
        assert_same(SINGLE_ORIGINAL, &poly.original, &committed(SINGLE_ORIGINAL));
        assert_same(name, &poly.bytes, &committed(name));
    }
}

#[test]
fn the_same_generic_entry_on_a_committed_vendor_pair_is_measured_not_assumed() {
    let packed: Vec<u8> = vendor(VENDOR_PACKED);
    let original: Vec<u8> = vendor(VENDOR_ORIGINAL);
    let stub_rva: u32 = stub_rva_of(&packed, VENDOR_STUB_SECTIONS[0]);
    let out: EmulatedUnpack = emulated(&packed, &original, VENDOR_STUB_SECTIONS, stub_rva);
    println!(
        "vendor ASPack through the generic entry: oep={:?} stub_writes={} steps={} exit={}",
        out.oep_rva, out.content_bytes_mutated_by_stub, out.steps_executed, out.exit_reason
    );
    let report: &SectionRecoveryReport = report_of(&out);
    assert_pinned("vendor ASPack", report, VENDOR_CONTENT, VENDOR_SECTIONS);
    assert_eq!(
        out.content_bytes_mutated_by_stub, 0,
        "the generic entry drives {} instructions of a real ASPack stub and writes no content \
         byte, so the {}/{} above is byte coincidence between the still-packed image and the \
         original, not recovery: a vendor ASPack figure comes from the dedicated phase-two path in \
         aspack_pecompact_phase2.rs, never from this entry. If this ever writes content, remeasure \
         this case and rewrite what the published row claims",
        out.steps_executed, report.content_matching, report.content_compared,
    );
    assert!(
        report
            .sections
            .iter()
            .filter(|s: &&GranuleRecovery| s.role == SectionRole::Content)
            .all(|s: &GranuleRecovery| !s.is_byte_identical()),
        "no content section of a real ASPack image is recovered byte-identical by the generic \
         entry, so none may report byte identity here",
    );
}

fn vendor(name: &'static str) -> Vec<u8> {
    load_fixture(PackerFixture {
        decoder: VENDOR_DECODER,
        family: VENDOR_FAMILY,
        name,
    })
    .unwrap_or_else(|| {
        panic!(
            "corpus/native/packers/{VENDOR_FAMILY}/{name} is tracked in the repository, so its \
             absence is never a skip: this case exists to measure what the generic stub-emulator \
             entry does on a real vendor pair"
        )
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

fn digest(bytes: &[u8]) -> (usize, u32) {
    let mut hasher: crc32fast::Hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    (bytes.len(), hasher.finalize())
}

fn assert_same(name: &str, built: &[u8], committed_bytes: &[u8]) {
    assert!(
        built == committed_bytes,
        "the in-tree packer must still emit {name} exactly as committed, so a reader can regenerate \
         the graded pair; built {:?} committed {:?}",
        digest(built),
        digest(committed_bytes),
    );
}
