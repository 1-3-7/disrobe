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
    NspackEmulatedReport, NspackRecoveryStatus, unpack_nspack_emulated_with_baseline,
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

fn run_one_fixture(label: &str, packed_name: &str, orig_name: &str) -> Option<(f64, f64)> {
    let Some(packed): Option<Vec<u8>> = read_corpus(packed_name) else {
        eprintln!("skip: {packed_name} missing");
        return None;
    };
    let Some(original): Option<Vec<u8>> = read_corpus(orig_name) else {
        eprintln!("skip: {orig_name} missing");
        return None;
    };
    let report: NspackEmulatedReport =
        match unpack_nspack_emulated_with_baseline(&packed, Some(&original)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{label}: unpack_nspack_emulated FAILED: {e:?}");
                panic!("nspack emulation must succeed on {label}");
            }
        };
    assert_eq!(report.status, NspackRecoveryStatus::FullPayloadDecompressed);
    assert_eq!(
        report.decompressed_image.len(),
        report.decompressed_size_bytes
    );
    let content_pct: f64 = report.content_recovery_pct.unwrap_or(0.0);
    let whole_pct: f64 = report.whole_file_recovery_pct.unwrap_or(0.0);
    println!(
        "{label}: dsize={} ssize={} start_of_stuff={:#x} whole_file_recovery={:.2}% content_recovery={:.2}%",
        report.decompressed_size_bytes,
        report.stream_size_bytes,
        report.start_of_stuff_file_offset,
        whole_pct,
        content_pct,
    );
    Some((whole_pct, content_pct))
}

fn assert_recovery(label: &str, packed: &str, orig: &str, whole_floor: f64, content_floor: f64) {
    let Some((whole_pct, content_pct)): Option<(f64, f64)> = run_one_fixture(label, packed, orig)
    else {
        return;
    };
    assert!(
        whole_pct >= whole_floor,
        "{label}: HONEST whole-image byte-recovery must be >= {whole_floor:.1}%; got {whole_pct:.2}%",
    );
    assert!(
        content_pct >= content_floor,
        "{label}: content-section (.text/.rdata/.data) byte-recovery must be >= {content_floor:.1}%; \
         got {content_pct:.2}%",
    );
}

#[test]
fn nspack_byte_recovery_hash() {
    assert_recovery(
        "hash",
        "hash.packed.nspack.exe",
        "hash.original.exe",
        93.5,
        99.0,
    );
}

#[test]
#[ignore = "FIXTURE PENDING: ftp.packed.nspack.exe (NSPack-packed Microsoft ftp.exe) is flagged as a virus by Windows Defender and quarantined on read; re-stage from github.com/chesvectain/PackingData PackingData/NSPack/nspack_ftp.exe with a Defender exclusion on corpus/native/packers/nspack (requires admin). See MANIFEST.toml NSPack ftp row."]
fn nspack_byte_recovery_ftp() {
    assert_recovery(
        "ftp",
        "ftp.packed.nspack.exe",
        "ftp.original.exe",
        80.0,
        90.0,
    );
}

#[test]
fn nspack_byte_recovery_cmd() {
    assert_recovery(
        "cmd",
        "cmd.packed.nspack.exe",
        "cmd.original.exe",
        92.0,
        99.0,
    );
}

#[test]
fn nspack_byte_recovery_psexec() {
    assert_recovery(
        "psexec",
        "psexec.packed.nspack.exe",
        "psexec.original.exe",
        73.5,
        98.0,
    );
}

#[test]
fn nspack_byte_recovery_handle() {
    assert_recovery(
        "handle",
        "handle.packed.nspack.exe",
        "handle.original.exe",
        49.5,
        98.0,
    );
}

#[test]
fn nspack_byte_recovery_calc() {
    assert_recovery(
        "calc",
        "calc.packed.nspack.exe",
        "calc.original.exe",
        89.0,
        98.0,
    );
}

#[test]
fn nspack_content_recovery_all_present_fixtures_pass() {
    let fixtures: &[(&str, &str, &str)] = &[
        ("hash", "hash.packed.nspack.exe", "hash.original.exe"),
        ("ftp", "ftp.packed.nspack.exe", "ftp.original.exe"),
        ("cmd", "cmd.packed.nspack.exe", "cmd.original.exe"),
        ("psexec", "psexec.packed.nspack.exe", "psexec.original.exe"),
        ("handle", "handle.packed.nspack.exe", "handle.original.exe"),
        ("calc", "calc.packed.nspack.exe", "calc.original.exe"),
    ];
    let mut passed: usize = 0;
    let mut tested: usize = 0;
    for (label, p, o) in fixtures {
        let Some((_whole, content)): Option<(f64, f64)> = run_one_fixture(label, p, o) else {
            continue;
        };
        tested += 1;
        if content >= 90.0 {
            passed += 1;
        }
    }
    if tested == 0 {
        eprintln!("no fixtures present; content-recovery check skipped");
        return;
    }
    println!("nspack content-recovery: {passed}/{tested} fixtures at or above 90%");
    assert_eq!(
        passed, tested,
        "every present fixture must reach >= 90% content-section byte-recovery; got {passed}/{tested}",
    );
}
