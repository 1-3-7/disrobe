#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod packer_fixture;

use disrobe_pass_native::packers::section_recovery::{
    GranuleRecovery, SectionRecoveryReport, SectionRole, section_recovery_report,
};
use disrobe_pass_native::packers::{
    FsgBlock, FsgUnpackOutput, NspackEmulatedReport, NspackLayout, NspackSection, PeImage,
    PeSection, PetitePhase2EmulatedOutput, parse_nspack_layout, parse_pe_image, unpack_fsg,
    unpack_nspack_emulated_with_baseline, unpack_petite_phase2_emulated,
};
use packer_fixture::{
    CommittedFixture, PackerFixture, committed_fixture_defect, declared_fixture, load_fixture,
};

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

const FSG_HASH_CONTENT: ContentFloor = ContentFloor {
    matching: 55080,
    compared: 60060,
};

const FSG_HASH_SECTIONS: &[SectionFloor] = &[
    SectionFloor {
        name: ".text",
        matching: 18188,
        compared: 18188,
    },
    SectionFloor {
        name: ".rdata",
        matching: 2311,
        compared: 3988,
    },
    SectionFloor {
        name: ".data",
        matching: 33212,
        compared: 33212,
    },
    SectionFloor {
        name: ".rsrc",
        matching: 1369,
        compared: 4672,
    },
];

const FSG_FTP_CONTENT: ContentFloor = ContentFloor {
    matching: 52808,
    compared: 56742,
};

const FSG_FTP_SECTIONS: &[SectionFloor] = &[
    SectionFloor {
        name: ".text",
        matching: 31171,
        compared: 33870,
    },
    SectionFloor {
        name: ".data",
        matching: 20888,
        compared: 20888,
    },
    SectionFloor {
        name: ".rsrc",
        matching: 749,
        compared: 1984,
    },
];

const NSPACK_HASH_CONTENT: ContentFloor = ContentFloor {
    matching: 56967,
    compared: 60060,
};

const NSPACK_HASH_SECTIONS: &[SectionFloor] = &[
    SectionFloor {
        name: ".text",
        matching: 18188,
        compared: 18188,
    },
    SectionFloor {
        name: ".rdata",
        matching: 3635,
        compared: 3988,
    },
    SectionFloor {
        name: ".data",
        matching: 33212,
        compared: 33212,
    },
    SectionFloor {
        name: ".rsrc",
        matching: 1932,
        compared: 4672,
    },
];

const PETITE_HELLO_CONTENT: ContentFloor = ContentFloor {
    matching: 86986,
    compared: 89648,
};

const PETITE_HELLO_SECTIONS: &[SectionFloor] = &[
    SectionFloor {
        name: ".text",
        matching: 70796,
        compared: 70796,
    },
    SectionFloor {
        name: ".rdata",
        matching: 15734,
        compared: 18396,
    },
    SectionFloor {
        name: ".data",
        matching: 456,
        compared: 456,
    },
];

const CORRUPT_RVA: usize = 0x3000;

const CORRUPT_TEXT_OFFSET: u32 = 0x2000;

const TEXT_AND_DATA: &[&str] = &[".text", ".data"];

const DATA_ONLY: &[&str] = &[".data"];

const FLOORS_PINNED_AGAINST: &[(&str, &str)] = &[
    ("fsg", "Hash.packed.fsg.exe"),
    ("fsg", "Hash.original.exe"),
    ("nspack", "hash.packed.nspack.exe"),
    ("nspack", "hash.original.exe"),
    ("petite", "hello.exe"),
    ("petite", "hello.original.exe"),
];

fn fixture(decoder: &str, family: &str, name: &str) -> Option<Vec<u8>> {
    load_fixture(PackerFixture {
        decoder,
        family,
        name,
    })
}

#[test]
fn every_pinned_floor_is_bound_to_declared_and_intact_fixture_bytes() {
    let mut defects: Vec<String> = Vec::new();
    for (family, name) in FLOORS_PINNED_AGAINST {
        let Some(declared): Option<&CommittedFixture> = declared_fixture(family, name) else {
            defects.push(format!(
                "{family}/{name} carries pinned floors in this file but is absent from the fixture \
                 registry, so nothing checks that the bytes graded are the bytes those floors were \
                 measured from"
            ));
            continue;
        };
        defects.extend(committed_fixture_defect(declared));
    }
    assert!(
        defects.is_empty(),
        "a pinned floor only means something against the exact fixture bytes it was measured \
         from, so this file must reject a fixture whose bytes have moved: {}",
        defects.join("; ")
    );
}

fn loaded_span(original: &[u8]) -> usize {
    let image: PeImage = parse_pe_image(original).expect("original PE parses");
    let last: u64 = image
        .sections
        .iter()
        .map(|s: &PeSection| {
            u64::from(s.virtual_address) + u64::from(s.virtual_size.max(s.raw_size))
        })
        .max()
        .unwrap_or(0);
    u64::from(image.size_of_image).max(last) as usize
}

fn to_full_span(recovered: Vec<u8>, original: &[u8]) -> Vec<u8> {
    let mut image: Vec<u8> = recovered;
    let span: usize = loaded_span(original);
    if image.len() < span {
        image.resize(span, 0u8);
    }
    image
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
    byte_identical: &[&str],
) {
    print!("{}", report.render());
    assert_eq!(
        report.content_compared, content.compared,
        "{label}: the content denominator is the original's own section span, so it must stay \
         {} bytes; a recovery that emits fewer bytes must score worse, never shrink its own \
         denominator",
        content.compared
    );
    assert!(
        report.content_matching >= content.matching,
        "{label}: content byte-recovery must hold at or above the measured {}/{} ({:.2}%); got \
         {}/{} ({:.2}%)",
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
    let identical: Vec<&str> = report
        .sections
        .iter()
        .filter(|s: &&GranuleRecovery| s.role == SectionRole::Content && s.is_byte_identical())
        .map(|s: &GranuleRecovery| s.name.as_str())
        .collect();
    assert_eq!(
        identical, byte_identical,
        "{label}: the byte-identical content sections are a membership list, not a count; a \
         section that stops recovering exactly must drop out of it"
    );
}

fn fsg_recovery(packed: &[u8], original: &[u8]) -> SectionRecoveryReport {
    let out: FsgUnpackOutput = unpack_fsg(packed).expect("FSG unpack must succeed");
    let recovered: Vec<u8> = to_full_span(out.raw_image, original);
    section_recovery_report(original, &recovered, &[]).expect("FSG section report")
}

fn nspack_recovery(packed: &[u8], original: &[u8]) -> SectionRecoveryReport {
    let report: NspackEmulatedReport = unpack_nspack_emulated_with_baseline(packed, Some(original))
        .expect("NSPack emulation must succeed");
    let layout: NspackLayout<'_> = parse_nspack_layout(packed).expect("packed NSPack layout");
    let nsp0: &NspackSection<'_> = layout
        .sections
        .iter()
        .find(|s: &&NspackSection<'_>| s.name.starts_with(b"nsp0"))
        .expect("nsp0 section must exist in an NSPack image");
    let mut recovered: Vec<u8> = vec![0u8; nsp0.virtual_address as usize];
    recovered.extend_from_slice(&report.decompressed_image);
    let recovered: Vec<u8> = to_full_span(recovered, original);
    section_recovery_report(original, &recovered, &[b"nsp0", b"nsp1"])
        .expect("NSPack section report")
}

fn petite_recovery(packed: &[u8], original: &[u8]) -> SectionRecoveryReport {
    let out: PetitePhase2EmulatedOutput =
        unpack_petite_phase2_emulated(packed).expect("Petite phase two must succeed");
    let recovered: Vec<u8> = to_full_span(out.recovered_memory_image, original);
    section_recovery_report(original, &recovered, &[b"petite"]).expect("Petite section report")
}

#[test]
fn fsg_hash_content_byte_recovery_is_pinned() {
    let Some(packed): Option<Vec<u8>> = fixture("FSG", "fsg", "Hash.packed.fsg.exe") else {
        return;
    };
    let Some(original): Option<Vec<u8>> = fixture("FSG", "fsg", "Hash.original.exe") else {
        return;
    };
    let report: SectionRecoveryReport = fsg_recovery(&packed, &original);
    assert_pinned(
        "FSG Hash",
        &report,
        FSG_HASH_CONTENT,
        FSG_HASH_SECTIONS,
        TEXT_AND_DATA,
    );
}

#[test]
fn fsg_ftp_content_byte_recovery_is_pinned() {
    let Some(packed): Option<Vec<u8>> = fixture("FSG", "fsg", "ftp.packed.fsg.exe") else {
        return;
    };
    let Some(original): Option<Vec<u8>> = fixture("FSG", "fsg", "ftp.original.exe") else {
        return;
    };
    let report: SectionRecoveryReport = fsg_recovery(&packed, &original);
    assert_pinned(
        "FSG ftp",
        &report,
        FSG_FTP_CONTENT,
        FSG_FTP_SECTIONS,
        DATA_ONLY,
    );
}

#[test]
fn fsg_hash_decodes_every_block_the_stub_table_names() {
    let Some(packed): Option<Vec<u8>> = fixture("FSG", "fsg", "Hash.packed.fsg.exe") else {
        return;
    };
    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    let payload: Vec<u32> = out
        .blocks
        .iter()
        .filter(|b: &&FsgBlock| !b.stub_metadata)
        .map(|b: &FsgBlock| b.dest_rva)
        .collect();
    assert_eq!(
        payload,
        vec![0x1000, 0x6000, 0x7000, 0x1_0000],
        "the stub's block-destination table names one aPLib stream per original section, and all \
         four must be decoded, not just the one the entry-point prologue points at"
    );
    assert_eq!(
        out.import_descriptor_va,
        Some(0x0040_6B76),
        "the absolute-destination entry names the stub's own import descriptor block"
    );
    assert!(
        !out.import_descriptor_block.is_empty(),
        "the import descriptor block must be decoded and kept out of the recovered image, because \
         the stub writes it over original .rdata content at run time"
    );
}

#[test]
fn nspack_hash_content_byte_recovery_is_pinned() {
    let Some(packed): Option<Vec<u8>> = fixture("NSPack", "nspack", "hash.packed.nspack.exe")
    else {
        return;
    };
    let Some(original): Option<Vec<u8>> = fixture("NSPack", "nspack", "hash.original.exe") else {
        return;
    };
    let report: SectionRecoveryReport = nspack_recovery(&packed, &original);
    assert_pinned(
        "NSPack hash",
        &report,
        NSPACK_HASH_CONTENT,
        NSPACK_HASH_SECTIONS,
        TEXT_AND_DATA,
    );
}

#[test]
fn petite_hello_content_byte_recovery_is_pinned() {
    let Some(packed): Option<Vec<u8>> = fixture("Petite", "petite", "hello.exe") else {
        return;
    };
    let Some(original): Option<Vec<u8>> = fixture("Petite", "petite", "hello.original.exe") else {
        return;
    };
    let report: SectionRecoveryReport = petite_recovery(&packed, &original);
    assert_pinned(
        "Petite hello",
        &report,
        PETITE_HELLO_CONTENT,
        PETITE_HELLO_SECTIONS,
        TEXT_AND_DATA,
    );
}

#[test]
fn one_corrupted_byte_is_named_by_offset_and_drops_the_pinned_figure() {
    let Some(packed): Option<Vec<u8>> = fixture("FSG", "fsg", "Hash.packed.fsg.exe") else {
        return;
    };
    let Some(original): Option<Vec<u8>> = fixture("FSG", "fsg", "Hash.original.exe") else {
        return;
    };
    let clean: SectionRecoveryReport = fsg_recovery(&packed, &original);
    let clean_text: &GranuleRecovery = row(&clean, ".text");
    assert!(
        clean_text.is_byte_identical(),
        "the control needs a byte-identical section to corrupt"
    );

    let out: FsgUnpackOutput = unpack_fsg(&packed).expect("FSG unpack must succeed");
    let mut tampered: Vec<u8> = to_full_span(out.raw_image, &original);
    tampered[CORRUPT_RVA] ^= 0xFF;
    let report: SectionRecoveryReport =
        section_recovery_report(&original, &tampered, &[]).expect("tampered section report");
    let text: &GranuleRecovery = row(&report, ".text");
    assert!(
        !text.is_byte_identical(),
        "flipping one byte inside .text must break byte identity, else the comparison is \
         measuring nothing"
    );
    assert_eq!(
        text.first_mismatch_rel,
        Some(CORRUPT_TEXT_OFFSET),
        "the report must name the corrupted offset relative to the section start"
    );
    assert_eq!(
        text.matching,
        clean_text.matching - 1,
        "exactly one byte must stop matching"
    );
    assert_eq!(
        report.content_matching,
        clean.content_matching - 1,
        "the content figure must fall by exactly one byte"
    );
    assert!(
        report.content_matching < FSG_HASH_CONTENT.matching,
        "the pinned floor must reject the corrupted image"
    );
}
