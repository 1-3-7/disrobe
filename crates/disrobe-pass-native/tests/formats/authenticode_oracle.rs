#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::{AuthenticodeReport, AuthenticodeVerdict, verify_authenticode};

use crate::prerequisite;

const NOW_SECS: u64 = 1_798_761_600;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("authenticode")
}

fn read_fixture(name: &str) -> Option<Vec<u8>> {
    fs::read(fixture_dir().join(name)).ok()
}

#[test]
fn committed_corpus_verdicts_are_correct() {
    let unsigned: Vec<u8> = read_fixture("unsigned.exe").expect("unsigned fixture present");
    let unsigned_report: AuthenticodeReport = verify_authenticode(&unsigned, NOW_SECS);
    assert_eq!(unsigned_report.verdict, AuthenticodeVerdict::NoSignature);

    let mismatch: Vec<u8> = read_fixture("hash_mismatch.exe").expect("byte-flip fixture present");
    let mismatch_report: AuthenticodeReport = verify_authenticode(&mismatch, NOW_SECS);
    assert_eq!(mismatch_report.verdict, AuthenticodeVerdict::HashMismatch);
    assert_ne!(
        mismatch_report.computed_hash, mismatch_report.claimed_hash,
        "byte-flipped .text must yield a different Authenticode hash"
    );
    assert!(!mismatch_report.claimed_hash.is_empty());

    let expired: Vec<u8> = read_fixture("expired_leaf.exe").expect("expired fixture present");
    let expired_report: AuthenticodeReport = verify_authenticode(&expired, NOW_SECS);
    assert_eq!(expired_report.verdict, AuthenticodeVerdict::Expired);
    assert_eq!(
        expired_report.computed_hash, expired_report.claimed_hash,
        "expired sample has an intact hash; only the cert validity fails"
    );

    let self_signed: Vec<u8> =
        read_fixture("self_signed.exe").expect("self-signed fixture present");
    let self_report: AuthenticodeReport = verify_authenticode(&self_signed, NOW_SECS);
    assert_eq!(self_report.verdict, AuthenticodeVerdict::SelfSigned);
    assert_eq!(self_report.computed_hash, self_report.claimed_hash);
    assert_eq!(self_report.chain.len(), 1);
    assert!(self_report.chain[0].self_signed);

    let valid_untrusted: Vec<u8> =
        read_fixture("valid_untrusted.exe").expect("valid-untrusted fixture present");
    let vu_report: AuthenticodeReport = verify_authenticode(&valid_untrusted, NOW_SECS);
    assert_eq!(vu_report.verdict, AuthenticodeVerdict::UntrustedChain);
    assert_eq!(
        vu_report.computed_hash, vu_report.claimed_hash,
        "the intact signed sample must reproduce the embedded Authenticode hash"
    );
    assert_eq!(vu_report.chain.len(), 2, "leaf plus self-signed test CA");
    assert!(!vu_report.chain[0].self_signed, "the leaf is CA-issued");
    assert!(vu_report.chain[1].is_ca, "the anchor of the chain is a CA");
}

#[test]
fn wrong_eku_leaf_never_reaches_valid() {
    let bytes: Vec<u8> = read_fixture("wrong_eku.exe").expect("wrong-eku fixture present");
    let report: AuthenticodeReport = verify_authenticode(&bytes, NOW_SECS);
    assert_ne!(
        report.verdict,
        AuthenticodeVerdict::Valid,
        "a leaf whose ExtendedKeyUsage lacks codeSigning must never be trusted"
    );
    assert_eq!(
        report.verdict,
        AuthenticodeVerdict::WrongKeyUsage,
        "a present EKU without codeSigning or anyExtendedKeyUsage is a key-usage failure"
    );
    assert_eq!(
        report.computed_hash, report.claimed_hash,
        "the sample's Authenticode hash is intact; only the key usage disqualifies it"
    );
}

fn tlv_parts(bytes: &[u8]) -> (usize, usize) {
    let first: u8 = bytes[1];
    if first & 0x80 == 0 {
        return (2, usize::from(first));
    }
    let count: usize = usize::from(first & 0x7F);
    let length: usize = bytes[2..2 + count]
        .iter()
        .fold(0usize, |acc: usize, &b: &u8| (acc << 8) | usize::from(b));
    (2 + count, length)
}

fn tlv_with(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![tag];
    let length: usize = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let be: [u8; 4] = (length as u32).to_be_bytes();
        let skip: usize = be.iter().take_while(|&&b: &&u8| b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn children(content: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = Vec::new();
    let mut pos: usize = 0;
    while pos < content.len() {
        let (header, length): (usize, usize) = tlv_parts(&content[pos..]);
        out.push(&content[pos..pos + header + length]);
        pos += header + length;
    }
    out
}

fn content_of(tlv: &[u8]) -> &[u8] {
    let (header, length): (usize, usize) = tlv_parts(tlv);
    &tlv[header..header + length]
}

fn with_first_certificate_repeated(pe: &[u8]) -> Vec<u8> {
    let e_lfanew: usize = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    let opt: usize = e_lfanew + 24;
    let directory: usize = opt
        + if u16::from_le_bytes([pe[opt], pe[opt + 1]]) == 0x020B {
            144
        } else {
            128
        };
    let table: usize =
        u32::from_le_bytes(pe[directory..directory + 4].try_into().unwrap()) as usize;
    let table_len: usize =
        u32::from_le_bytes(pe[directory + 4..directory + 8].try_into().unwrap()) as usize;
    assert_eq!(
        table + table_len,
        pe.len(),
        "the certificate table ends the fixture"
    );
    let entry_len: usize = u32::from_le_bytes(pe[table..table + 4].try_into().unwrap()) as usize;
    let pkcs7: &[u8] = &pe[table + 8..table + entry_len];
    let (header, length): (usize, usize) = tlv_parts(pkcs7);
    let content_info: Vec<&[u8]> = children(&pkcs7[header..header + length]);
    let signed_data: &[u8] = content_of(content_info[1]);
    let fields: Vec<&[u8]> = children(content_of(signed_data));
    let mut rebuilt_fields: Vec<u8> = Vec::new();
    let mut repeated: bool = false;
    for field in fields {
        if field[0] == 0xA0 {
            let certificates: Vec<&[u8]> = children(content_of(field));
            let mut set: Vec<u8> = Vec::new();
            for (index, certificate) in certificates.iter().enumerate() {
                set.extend_from_slice(certificate);
                if index == 0 {
                    set.extend_from_slice(certificate);
                    repeated = true;
                }
            }
            rebuilt_fields.extend_from_slice(&tlv_with(0xA0, &set));
        } else {
            rebuilt_fields.extend_from_slice(field);
        }
    }
    assert!(repeated, "the fixture carries a certificate set");
    let signed: Vec<u8> = tlv_with(0x30, &rebuilt_fields);
    let mut info: Vec<u8> = content_info[0].to_vec();
    info.extend_from_slice(&tlv_with(0xA0, &signed));
    let der: Vec<u8> = tlv_with(0x30, &info);
    let mut entry: Vec<u8> = Vec::new();
    entry.extend_from_slice(&((8 + der.len()) as u32).to_le_bytes());
    entry.extend_from_slice(&pe[table + 4..table + 8]);
    entry.extend_from_slice(&der);
    while !entry.len().is_multiple_of(8) {
        entry.push(0);
    }
    let mut out: Vec<u8> = pe[..table].to_vec();
    out.extend_from_slice(&entry);
    out[directory + 4..directory + 8].copy_from_slice(&(entry.len() as u32).to_le_bytes());
    out
}

#[test]
fn a_repeated_certificate_in_the_signed_data_set_keeps_the_verdict() {
    let original: Vec<u8> =
        read_fixture("valid_untrusted.exe").expect("valid-untrusted fixture present");
    let repeated: Vec<u8> = with_first_certificate_repeated(&original);
    assert_ne!(repeated, original);
    let report: AuthenticodeReport = verify_authenticode(&repeated, NOW_SECS);
    assert_eq!(
        report.verdict,
        AuthenticodeVerdict::UntrustedChain,
        "signers that repeat a certificate in the SET OF still carry a well-formed signature"
    );
    assert_eq!(report.computed_hash, report.claimed_hash);
    assert_eq!(report.chain.len(), 2, "leaf plus self-signed test CA");
}

#[test]
fn injected_timestamp_cannot_unexpire_a_signature() {
    let bytes: Vec<u8> =
        read_fixture("timestamp_forged_expired.exe").expect("forged-timestamp fixture present");
    let report: AuthenticodeReport = verify_authenticode(&bytes, NOW_SECS);
    assert_ne!(
        report.verdict,
        AuthenticodeVerdict::Valid,
        "an unverifiable RFC3161 genTime must never flip a verdict to Valid"
    );
    assert_eq!(
        report.verdict,
        AuthenticodeVerdict::Expired,
        "the injected in-window genTime must not override the expired signing certificate"
    );
    assert_eq!(
        report.computed_hash, report.claimed_hash,
        "the file hash is untouched; the injected genTime lives in the certificate table"
    );
}

#[test]
#[cfg(windows)]
fn real_binary_rfc3161_timestamp_is_extracted() {
    let candidates: &[&str] = &[
        "advapi32.dll",
        "kernel32.dll",
        "crypt32.dll",
        "user32.dll",
        "ntdll.dll",
        "gdi32.dll",
        "ole32.dll",
        "shell32.dll",
        "wintrust.dll",
    ];
    let system_root: String = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let system32: PathBuf = Path::new(&system_root).join("System32");
    assert!(
        system32.is_dir(),
        "a Windows host carries {}",
        system32.display()
    );
    for name in candidates {
        let Ok(bytes): Result<Vec<u8>, _> = fs::read(system32.join(name)) else {
            continue;
        };
        let report: AuthenticodeReport = verify_authenticode(
            &bytes,
            disrobe_core::time::now_secs().expect("SOURCE_DATE_EPOCH is unset or whole seconds"),
        );
        if let Some(ts) = report.timestamp.as_ref() {
            eprintln!(
                "TIMESTAMP via {name}: signing_time={}, hash={}, tsa={}",
                ts.signing_time, ts.hash_algorithm, ts.tsa_subject
            );
            assert!(
                ts.signing_time.ends_with('Z') && ts.signing_time.len() >= 20,
                "{name}: RFC3161 signing time must be an ISO UTC timestamp, got {}",
                ts.signing_time
            );
            assert!(
                !ts.hash_algorithm.is_empty(),
                "{name}: timestamp hash algorithm must be identified"
            );
            return;
        }
    }
    eprintln!("SKIP rfc3161_timestamp: no timestamped System32 DLL found on this host");
}

fn find_osslsigncode() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("DISROBE_OSSLSIGNCODE") {
        let path: PathBuf = PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }
    if Command::new("osslsigncode")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
    {
        return Some(PathBuf::from("osslsigncode"));
    }
    let local: String = env::var("LOCALAPPDATA").ok()?;
    let base: PathBuf = Path::new(&local)
        .join("Microsoft")
        .join("WinGet")
        .join("Packages");
    let entries = fs::read_dir(&base).ok()?;
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("osslsigncode")
        {
            let candidate: PathBuf = entry.path().join("bin").join("osslsigncode.exe");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn ossl_calculated_digest(tool: &Path, sample: &Path) -> Option<(String, bool, bool)> {
    let output = Command::new(tool).arg("verify").arg(sample).output().ok()?;
    let mut text: String = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let mut digest: Option<String> = None;
    let mut mismatch: bool = false;
    let mut no_signature: bool = false;
    for line in text.lines() {
        if line.contains("No signature found") {
            no_signature = true;
        }
        if line.contains("Calculated message digest") {
            mismatch |= line.contains("MISMATCH");
            if let Some((_, rhs)) = line.split_once(':')
                && let Some(token) = rhs.split_whitespace().next()
            {
                digest = Some(token.to_ascii_uppercase());
            }
        }
    }
    Some((digest.unwrap_or_default(), mismatch, no_signature))
}

#[test]
fn osslsigncode_cross_check_of_hash_and_verdict() {
    let Some(tool): Option<PathBuf> = find_osslsigncode() else {
        prerequisite::tool_unavailable(
            "disrobe-pass-native::osslsigncode",
            "the osslsigncode Authenticode cross-check",
            "osslsigncode is not on PATH, in %LOCALAPPDATA%\\Microsoft\\WinGet\\Packages, or named by DISROBE_OSSLSIGNCODE",
        );
        return;
    };

    let signed_samples: &[&str] = &[
        "valid_untrusted.exe",
        "hash_mismatch.exe",
        "expired_leaf.exe",
        "self_signed.exe",
    ];
    for name in signed_samples {
        let path: PathBuf = fixture_dir().join(name);
        let bytes: Vec<u8> = fs::read(&path).expect("fixture present");
        let report: AuthenticodeReport = verify_authenticode(&bytes, NOW_SECS);
        let Some((digest, mismatch, no_sig)): Option<(String, bool, bool)> =
            ossl_calculated_digest(&tool, &path)
        else {
            panic!("osslsigncode produced no parseable output for {name}");
        };
        assert!(!no_sig, "{name} should carry a signature");
        assert_eq!(
            report.computed_hash, digest,
            "{name}: disrobe Authenticode hash must equal osslsigncode's calculated digest"
        );
        let disrobe_mismatch: bool = report.verdict == AuthenticodeVerdict::HashMismatch;
        assert_eq!(
            disrobe_mismatch, mismatch,
            "{name}: disrobe and osslsigncode must agree on hash-mismatch"
        );
    }

    let unsigned_path: PathBuf = fixture_dir().join("unsigned.exe");
    let (_digest, _mismatch, no_sig): (String, bool, bool) =
        ossl_calculated_digest(&tool, &unsigned_path).expect("osslsigncode output");
    assert!(
        no_sig,
        "osslsigncode must report the unsigned sample as unsigned"
    );
    let unsigned: Vec<u8> = fs::read(&unsigned_path).expect("unsigned fixture");
    assert_eq!(
        verify_authenticode(&unsigned, NOW_SECS).verdict,
        AuthenticodeVerdict::NoSignature
    );
}

#[test]
#[cfg(windows)]
fn real_trusted_binary_reaches_valid() {
    let candidates: &[&str] = &[
        "advapi32.dll",
        "crypt32.dll",
        "kernel32.dll",
        "user32.dll",
        "ntdll.dll",
        "shell32.dll",
    ];
    let system_root: String = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let system32: PathBuf = Path::new(&system_root).join("System32");
    assert!(
        system32.is_dir(),
        "a Windows host carries {}",
        system32.display()
    );
    for name in candidates {
        let Ok(bytes): Result<Vec<u8>, _> = fs::read(system32.join(name)) else {
            continue;
        };
        let report: AuthenticodeReport = verify_authenticode(
            &bytes,
            disrobe_core::time::now_secs().expect("SOURCE_DATE_EPOCH is unset or whole seconds"),
        );
        if report.verdict == AuthenticodeVerdict::Valid {
            eprintln!(
                "VALID via {name}: digest={}, chain len={}, timestamp={}",
                report.digest_algorithm,
                report.chain.len(),
                report.timestamp.is_some()
            );
            assert_eq!(
                report.computed_hash, report.claimed_hash,
                "{name}: a Valid verdict requires the computed hash to match the embedded hash"
            );
            assert!(
                report.chain.len() >= 2,
                "{name}: a trusted chain has a leaf and at least one issuer"
            );
            assert!(
                !report.chain[0].self_signed,
                "{name}: the signing leaf must be CA-issued"
            );
            return;
        }
    }
    eprintln!(
        "SKIP real_trusted_binary: no embedded-signed System32 DLL anchored to the bundled roots on this host"
    );
}
