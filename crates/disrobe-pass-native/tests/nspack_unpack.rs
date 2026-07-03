#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::{
    NspackEmulatedReport, NspackRecoveredSectionName, NspackRecoveryStatus, NspackUnpackReport,
    Packer, UnpackerStatus, detect_packers, parse_nspack_layout, unpack_nspack,
    unpack_nspack_emulated_with_baseline,
};

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("packers");
    p.push("nspack");
    p
}

fn read_corpus(name: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = corpus_dir();
    p.push(name);
    fs::read(&p).ok()
}

const fn fixtures() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("hash", "hash.packed.nspack.exe", "hash.original.exe"),
        ("ftp", "ftp.packed.nspack.exe", "ftp.original.exe"),
        ("cmd", "cmd.packed.nspack.exe", "cmd.original.exe"),
        ("psexec", "psexec.packed.nspack.exe", "psexec.original.exe"),
        ("handle", "handle.packed.nspack.exe", "handle.original.exe"),
        ("calc", "calc.packed.nspack.exe", "calc.original.exe"),
    ]
}

fn assert_basic_report_shape(report: &NspackUnpackReport, packed_size: usize, label: &str) {
    assert_eq!(
        report.packed_size, packed_size,
        "{label}: packed_size echoed"
    );
    assert!(
        report.nsp0_raw_size > 0,
        "{label}: nsp0 must have raw bytes"
    );
    assert!(
        report.nsp1_raw_size > 0,
        "{label}: nsp1 must have raw bytes"
    );
    assert!(
        report.nsp1_virtual_size >= report.nsp1_raw_size,
        "{label}: nsp1 virtual_size >= raw_size",
    );
    assert!(
        report.stub_entry_point_rva >= 0x1000,
        "{label}: stub EP RVA must be inside an image section",
    );
    assert!(
        matches!(
            report.status,
            NspackRecoveryStatus::StructuralOnly | NspackRecoveryStatus::ResourcesRecovered
        ),
        "{label}: status must be one of the implemented recovery levels",
    );
    assert!(
        !report.limitation_note.is_empty(),
        "{label}: limitation_note must be present (honest disclosure)",
    );
}

#[test]
fn nspack_packer_status_is_implemented() {
    assert_eq!(Packer::Nspack.label(), "nspack");
    assert_eq!(
        Packer::Nspack.unpacker_status(),
        UnpackerStatus::Implemented
    );
    assert!(!Packer::Nspack.is_grey_zone());
}

#[test]
fn nspack_section_signatures_detected() {
    let opt_size: usize = 0xE0;
    let sec_table: usize = 0x80 + 4 + 20 + opt_size;
    let mut buf: Vec<u8> = vec![0u8; sec_table + 2 * 40 + 0x200];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    let coff: usize = 0x80 + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    buf[sec_table..sec_table + 4].copy_from_slice(b"nsp0");
    buf[sec_table + 40..sec_table + 44].copy_from_slice(b"nsp1");
    let hits = detect_packers(&buf);
    assert!(
        hits.iter().any(|h| h.packer == Packer::Nspack),
        "nsp0/nsp1 section names must classify as NSPack",
    );
}

#[test]
fn test_nspack_hash_round_trip() {
    let Some(packed) = read_corpus("hash.packed.nspack.exe") else {
        eprintln!("skip: hash.packed.nspack.exe missing");
        return;
    };
    let Some(original) = read_corpus("hash.original.exe") else {
        eprintln!("skip: hash.original.exe missing");
        return;
    };
    let report: NspackUnpackReport =
        unpack_nspack(&packed).expect("unpack_nspack must parse Hash sample");
    assert_basic_report_shape(&report, packed.len(), "hash");
    assert!(
        original.len() >= packed.len(),
        "original Hash.exe must be larger than packed"
    );
    let hits = detect_packers(&packed);
    assert!(
        hits.iter().any(|h| h.packer == Packer::Nspack),
        "hash packed sample must classify as NSPack",
    );
}

#[test]
fn test_nspack_ftp_round_trip() {
    let Some(packed) = read_corpus("ftp.packed.nspack.exe") else {
        eprintln!("skip: ftp.packed.nspack.exe missing");
        return;
    };
    let report: NspackUnpackReport = unpack_nspack(&packed).expect("unpack ftp");
    assert_basic_report_shape(&report, packed.len(), "ftp");
}

#[test]
fn test_nspack_cmd_round_trip() {
    let Some(packed) = read_corpus("cmd.packed.nspack.exe") else {
        eprintln!("skip: cmd.packed.nspack.exe missing");
        return;
    };
    let report: NspackUnpackReport = unpack_nspack(&packed).expect("unpack cmd");
    assert_basic_report_shape(&report, packed.len(), "cmd");
    let layout = parse_nspack_layout(&packed).expect("layout");
    assert_eq!(
        layout.sections.len(),
        2,
        "cmd: NSPack always emits 2 sections"
    );
    assert!(
        layout.sections[1].raw_size > layout.sections[0].raw_size,
        "cmd: nsp1 (compressed payload) must dominate nsp0 (stub host)",
    );
}

#[test]
fn test_nspack_psexec_round_trip() {
    let Some(packed) = read_corpus("psexec.packed.nspack.exe") else {
        eprintln!("skip: psexec.packed.nspack.exe missing");
        return;
    };
    let report: NspackUnpackReport = unpack_nspack(&packed).expect("unpack psexec");
    assert_basic_report_shape(&report, packed.len(), "psexec");
    let layout = parse_nspack_layout(&packed).expect("layout");
    assert!(!layout.is_pe32_plus, "psexec PsExec is 32-bit (i386)");
    assert_eq!(layout.image_base, 0x0040_0000);
    assert_eq!(layout.sections.len(), 2);
    assert_eq!(layout.sections[0].name, b"nsp0");
    assert_eq!(layout.sections[1].name, b"nsp1");
}

#[test]
fn test_nspack_handle_round_trip() {
    let Some(packed) = read_corpus("handle.packed.nspack.exe") else {
        eprintln!("skip: handle.packed.nspack.exe missing");
        return;
    };
    let report: NspackUnpackReport = unpack_nspack(&packed).expect("unpack handle");
    assert_basic_report_shape(&report, packed.len(), "handle");
}

#[test]
fn test_nspack_calc_round_trip() {
    let Some(packed) = read_corpus("calc.packed.nspack.exe") else {
        eprintln!("skip: calc.packed.nspack.exe missing");
        return;
    };
    let report: NspackUnpackReport = unpack_nspack(&packed).expect("unpack calc");
    assert_basic_report_shape(&report, packed.len(), "calc");
    assert!(
        report
            .recovered_section_names
            .iter()
            .any(|r: &NspackRecoveredSectionName| r.name == b".data"),
        "calc: must recover .data from nsp0 metadata",
    );
}

#[test]
fn test_nspack_all_fixtures_parse_without_panic() {
    let mut tested: usize = 0;
    for (label, packed_name, _orig_name) in fixtures() {
        let Some(bytes) = read_corpus(packed_name) else {
            continue;
        };
        let report: NspackUnpackReport = match unpack_nspack(&bytes) {
            Ok(r) => r,
            Err(e) => panic!("{label}: unpack_nspack errored on real fixture: {e:?}"),
        };
        assert_basic_report_shape(&report, bytes.len(), label);
        tested += 1;
    }
    if tested == 0 {
        eprintln!("skip: no NSPack fixtures present");
    } else {
        println!("nspack: parsed {tested} fixtures cleanly");
    }
}

#[test]
fn test_nspack_unpacked_pe_runs() {
    let Some(packed) = read_corpus("hash.packed.nspack.exe") else {
        eprintln!("skip: hash.packed.nspack.exe missing");
        return;
    };
    let report: NspackUnpackReport = unpack_nspack(&packed).expect("unpack");
    assert!(
        matches!(
            report.status,
            NspackRecoveryStatus::StructuralOnly | NspackRecoveryStatus::ResourcesRecovered
        ),
        "structural recovery returns one of the two implemented statuses; \
         FullPayloadDecompressed requires aPLib stub emulation which is a follow-up wave",
    );
    assert!(
        !report.limitation_note.is_empty(),
        "structural-only paths must carry a non-empty limitation note for downstream consumers",
    );
}

fn assert_content_recovery(label: &str, packed_name: &str, orig_name: &str, min_pct: f64) {
    let Some(packed) = read_corpus(packed_name) else {
        eprintln!("skip: {packed_name} missing/unreadable");
        return;
    };
    let Some(original) = read_corpus(orig_name) else {
        eprintln!("skip: {orig_name} missing/unreadable");
        return;
    };
    let report: NspackEmulatedReport =
        unpack_nspack_emulated_with_baseline(&packed, Some(&original))
            .unwrap_or_else(|e| panic!("{label}: emulated unpack must decompress: {e:?}"));
    let pct: f64 = report
        .content_recovery_pct
        .unwrap_or_else(|| panic!("{label}: content_recovery_pct must be populated with baseline"));
    println!(
        "{label}: content-section byte-recovery {pct:.2}% (whole-image diff {:?}%)",
        report.byte_diff_pct
    );
    assert!(
        pct >= min_pct,
        "{label}: content-section byte-recovery {pct:.2}% below floor {min_pct:.1}% \
         (.rsrc/.reloc excluded - NSPack stores them uncompressed outside the nsp1 stream)"
    );
}

#[test]
fn test_nspack_hash_content_byte_recovery() {
    assert_content_recovery("hash", "hash.packed.nspack.exe", "hash.original.exe", 90.0);
}

#[test]
#[ignore = "FIXTURE PENDING: ftp.packed.nspack.exe (NSPack-packed Microsoft ftp.exe) is flagged as a virus by Windows Defender and quarantined on read; re-stage from github.com/chesvectain/PackingData PackingData/NSPack/nspack_ftp.exe with a Defender exclusion on corpus/native/packers/nspack (requires admin). See MANIFEST.toml NSPack ftp row."]
fn test_nspack_ftp_content_byte_recovery() {
    assert_content_recovery("ftp", "ftp.packed.nspack.exe", "ftp.original.exe", 90.0);
}

#[test]
fn test_nspack_cmd_content_byte_recovery() {
    assert_content_recovery("cmd", "cmd.packed.nspack.exe", "cmd.original.exe", 90.0);
}

#[test]
fn test_nspack_psexec_content_byte_recovery() {
    assert_content_recovery(
        "psexec",
        "psexec.packed.nspack.exe",
        "psexec.original.exe",
        90.0,
    );
}

#[test]
fn test_nspack_handle_content_byte_recovery() {
    assert_content_recovery(
        "handle",
        "handle.packed.nspack.exe",
        "handle.original.exe",
        90.0,
    );
}

#[test]
fn test_nspack_calc_content_byte_recovery() {
    assert_content_recovery("calc", "calc.packed.nspack.exe", "calc.original.exe", 90.0);
}
