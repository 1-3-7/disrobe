#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use disrobe_pass_pyfreeze::ExtractionQuota;
use disrobe_pass_pyfreeze::briefcase::layout::walk_python_sources;
use disrobe_pass_pyfreeze::error::Error;
use disrobe_pass_pyfreeze::shiv::{
    ShivExtraction, detect_and_extract, detect_and_extract_with_quota,
};

struct StoredEntry {
    name: &'static str,
    body: Vec<u8>,
    declared_uncompressed: u32,
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask: u32 = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn build_stored_zip(entries: &[StoredEntry]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();

    for entry in entries {
        let local_offset: u32 = out.len() as u32;
        let crc: u32 = crc32(&entry.body);
        let compressed: u32 = entry.body.len() as u32;
        let name_bytes: &[u8] = entry.name.as_bytes();

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&compressed.to_le_bytes());
        out.extend_from_slice(&entry.declared_uncompressed.to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&entry.body);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&compressed.to_le_bytes());
        central.extend_from_slice(&entry.declared_uncompressed.to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let central_offset: u32 = out.len() as u32;
    let central_size: u32 = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn out_dir(tag: &str) -> PathBuf {
    let mut p: PathBuf = std::env::temp_dir();
    p.push(format!(
        "disrobe-pyfreeze-ressafe-{tag}-{pid}-{nonce}",
        pid = std::process::id(),
        nonce = next_nonce()
    ));
    p
}

fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xC0FF_EE00);
    N.fetch_add(1, Ordering::Relaxed)
}

#[test]
fn shiv_manifest_with_lying_4gib_uncompressed_size_does_not_oom() {
    let env_json: Vec<u8> = br#"{"entry_point":"hello:main"}"#.to_vec();
    let entries: [StoredEntry; 2] = [
        StoredEntry {
            name: "_bootstrap/environment.json",
            declared_uncompressed: u32::MAX,
            body: env_json,
        },
        StoredEntry {
            name: "_bootstrap/_bootstrap.py",
            declared_uncompressed: 5,
            body: b"pass\n".to_vec(),
        },
    ];
    let archive: Vec<u8> = build_stored_zip(&entries);
    let src: PathBuf = PathBuf::from("forged.pyz");
    let out: PathBuf = out_dir("shiv-lie");

    let start: Instant = Instant::now();
    let result: Result<ShivExtraction, Error> = detect_and_extract(&archive, &src, &out);
    let elapsed: Duration = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "extraction of a 4 GiB-declared manifest must stay bounded; took {elapsed:?}"
    );
    let err: Error =
        result.expect_err("a manifest declaring 4 GiB must be rejected, not allocated");
    assert!(
        matches!(
            &err,
            Error::ZipEntry(name, _) | Error::QuotaExceeded { entry: name, .. }
                if name == "_bootstrap/environment.json"
        ),
        "the oversized manifest must surface a bounded structured error, got {err:?}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn shiv_manifest_read_is_bounded_when_only_manifest_lies() {
    let env_json: Vec<u8> = br#"{"entry_point":"hello:main"}"#.to_vec();
    let entries: [StoredEntry; 2] = [
        StoredEntry {
            name: "_bootstrap/environment.json",
            declared_uncompressed: u32::MAX,
            body: env_json,
        },
        StoredEntry {
            name: "_bootstrap/_bootstrap.py",
            declared_uncompressed: 5,
            body: b"pass\n".to_vec(),
        },
    ];
    let archive: Vec<u8> = build_stored_zip(&entries);
    let src: PathBuf = PathBuf::from("forged-manifest-lie.pyz");
    let out: PathBuf = out_dir("shiv-manifest-lie");
    let quota: ExtractionQuota = ExtractionQuota {
        max_per_entry_uncompressed: 4096,
        ..ExtractionQuota::default_safe()
    };

    let start: Instant = Instant::now();
    let result: Result<ShivExtraction, Error> =
        detect_and_extract_with_quota(&archive, &src, &out, quota);
    let elapsed: Duration = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "the manifest read must not eagerly allocate the declared 4 GiB; took {elapsed:?}"
    );
    let err: Error =
        result.expect_err("the lying manifest entry must be rejected by the loop guard");
    assert!(
        matches!(&err, Error::QuotaExceeded { entry, .. } if entry == "_bootstrap/environment.json"),
        "manifest parsing succeeded (read_entry stayed bounded) but the loop guard must reject the inflated declaration, got {err:?}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn shiv_valid_small_manifest_still_extracts() {
    let entries: [StoredEntry; 2] = [
        StoredEntry {
            name: "_bootstrap/environment.json",
            declared_uncompressed: 28,
            body: br#"{"entry_point":"hello:main"}"#.to_vec(),
        },
        StoredEntry {
            name: "_bootstrap/_bootstrap.py",
            declared_uncompressed: 5,
            body: b"pass\n".to_vec(),
        },
    ];
    let archive: Vec<u8> = build_stored_zip(&entries);
    let src: PathBuf = PathBuf::from("valid.pyz");
    let out: PathBuf = out_dir("shiv-ok");

    let extraction: ShivExtraction =
        detect_and_extract(&archive, &src, &out).expect("a valid shiv archive must still extract");
    assert_eq!(
        extraction.environment.entry_point.as_deref(),
        Some("hello:main"),
        "the manifest entry_point must be recovered from a valid archive"
    );
    assert!(
        extraction
            .extracted
            .iter()
            .any(|e| e.name == "_bootstrap/_bootstrap.py"),
        "the bootstrap member must be extracted: {:?}",
        extraction.extracted
    );
    let _ = std::fs::remove_dir_all(&out);
}

fn make_dir(path: &std::path::Path) {
    std::fs::create_dir_all(path).expect("create dir");
}

fn write_file(path: &std::path::Path, body: &[u8]) {
    if let Some(parent) = path.parent() {
        make_dir(parent);
    }
    std::fs::write(path, body).expect("write file");
}

#[test]
fn briefcase_walk_rejects_pathologically_deep_tree() {
    let root: PathBuf = out_dir("bc-deep");
    make_dir(&root);
    let mut cursor: PathBuf = root.clone();
    for _ in 0..70u32 {
        cursor = cursor.join("d");
    }
    make_dir(&cursor);
    write_file(&cursor.join("leaf.py"), b"x = 1\n");

    let start: Instant = Instant::now();
    let result: Result<_, Error> = walk_python_sources(&root);
    let elapsed: Duration = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "a deep tree walk must stay bounded; took {elapsed:?}"
    );
    let err: Error = result.expect_err("a 70-deep tree must trip the depth bound");
    assert!(
        matches!(err, Error::BriefcaseWalkBounded { .. }),
        "deep nesting must surface a bounded walk error, got {err:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn briefcase_walk_collects_valid_shallow_sources() {
    let root: PathBuf = out_dir("bc-ok");
    make_dir(&root);
    write_file(&root.join("main.py"), b"print('hi')\n");
    write_file(&root.join("pkg").join("mod.py"), b"y = 2\n");

    let entries: Vec<_> = walk_python_sources(&root).expect("valid shallow tree walks");
    assert_eq!(
        entries.len(),
        2,
        "both source files must be indexed: {entries:?}"
    );
    assert!(entries.iter().any(|e| e.relative_name == "main.py"));
    assert!(entries.iter().any(|e| e.relative_name == "pkg/mod.py"));
    let _ = std::fs::remove_dir_all(&root);
}
