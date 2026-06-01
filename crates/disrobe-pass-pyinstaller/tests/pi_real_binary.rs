#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unreadable_literal,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_pyinstaller::{
    Cookie, EntryType, ExtractOutput, ExtractedEntry, TocEntry, extract_archive, find_cookie,
    walk_toc,
};

const HELLO_SOURCE_FILENAME: &str = "hello.py";
const HELLO_SOURCE_BODY: &str =
    "def main():\n    print('disrobe-pyinstaller-hello')\nif __name__ == '__main__':\n    main()\n";
const ENV_FORCE_REGEN: &str = "DISROBE_PYINSTALLER_REGEN";
const MIN_PYINSTALLER_MAJOR: u32 = 6;
const MIN_PYINSTALLER_MINOR: u32 = 20;

#[derive(Debug)]
struct PyInstallerArtifact {
    binary_path: PathBuf,
    bytes: Vec<u8>,
}

fn locate_pyinstaller() -> Option<PathBuf> {
    let candidate: &str = if cfg!(windows) {
        "pyinstaller.exe"
    } else {
        "pyinstaller"
    };
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let full: PathBuf = dir.join(candidate);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

fn pyinstaller_version(exe: &Path) -> Option<(u32, u32)> {
    let out: std::process::Output = Command::new(exe).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&out.stdout).into_owned();
    parse_version_string(text.trim())
}

fn parse_version_string(text: &str) -> Option<(u32, u32)> {
    let first_line: &str = text.lines().next().unwrap_or(text);
    let trimmed: &str = first_line.trim();
    let mut parts: std::str::Split<'_, char> = trimmed.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_raw: &str = parts.next()?;
    let mut minor_digits: String = String::with_capacity(minor_raw.len());
    for c in minor_raw.chars() {
        if c.is_ascii_digit() {
            minor_digits.push(c);
        } else {
            break;
        }
    }
    let minor: u32 = minor_digits.parse().ok()?;
    Some((major, minor))
}

fn fixtures_root() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("target");
    p.push("test-fixtures");
    p.push("pyinst-built");
    p
}

fn source_root() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("target");
    p.push("test-fixtures");
    p.push("pyinst-src");
    p
}

fn source_hash() -> String {
    let mut acc: u64 = 0xCAFE_FEED_BAAD_F00Du64;
    for b in HELLO_SOURCE_BODY.bytes() {
        acc = acc.wrapping_mul(1_000_003).wrapping_add(u64::from(b));
    }
    for b in HELLO_SOURCE_FILENAME.bytes() {
        acc = acc.wrapping_mul(1_000_003).wrapping_add(u64::from(b));
    }
    format!("{acc:016x}")
}

fn ensure_artifact() -> Option<PyInstallerArtifact> {
    let Some(pyinst) = locate_pyinstaller() else {
        eprintln!(
            "[disrobe-pyinstaller] pyinstaller not on PATH; install via `pip install pyinstaller>={MIN_PYINSTALLER_MAJOR}.{MIN_PYINSTALLER_MINOR}` to enable real-binary E2E tests"
        );
        return None;
    };
    let Some((maj, min)) = pyinstaller_version(&pyinst) else {
        eprintln!(
            "[disrobe-pyinstaller] could not determine pyinstaller version; require >= {MIN_PYINSTALLER_MAJOR}.{MIN_PYINSTALLER_MINOR}"
        );
        return None;
    };
    if maj < MIN_PYINSTALLER_MAJOR || (maj == MIN_PYINSTALLER_MAJOR && min < MIN_PYINSTALLER_MINOR)
    {
        eprintln!(
            "[disrobe-pyinstaller] pyinstaller {maj}.{min} too old; require >= {MIN_PYINSTALLER_MAJOR}.{MIN_PYINSTALLER_MINOR}; upgrade via `pip install --upgrade pyinstaller>={MIN_PYINSTALLER_MAJOR}.{MIN_PYINSTALLER_MINOR}`"
        );
        return None;
    }
    let hash: String = source_hash();
    let target_dir: PathBuf = fixtures_root().join(&hash);
    let candidate: PathBuf = pick_built_binary(&target_dir);
    let force: bool = std::env::var(ENV_FORCE_REGEN).is_ok();
    if !force && candidate.is_file() {
        let bytes: Vec<u8> = std::fs::read(&candidate).ok()?;
        return Some(PyInstallerArtifact {
            binary_path: candidate,
            bytes,
        });
    }
    std::fs::create_dir_all(&target_dir).ok()?;
    let src_dir: PathBuf = source_root().join(&hash);
    std::fs::create_dir_all(&src_dir).ok()?;
    let src_file: PathBuf = src_dir.join(HELLO_SOURCE_FILENAME);
    std::fs::write(&src_file, HELLO_SOURCE_BODY).ok()?;
    let work_dir: PathBuf = src_dir.join("work");
    let dist_dir: PathBuf = src_dir.join("dist");
    let spec_dir: &Path = src_dir.as_path();
    let status: std::process::ExitStatus = Command::new(&pyinst)
        .arg("--onefile")
        .arg("--noconfirm")
        .arg("--clean")
        .arg("--name")
        .arg("disrobe_hello_pyinst")
        .arg("--distpath")
        .arg(&dist_dir)
        .arg("--workpath")
        .arg(&work_dir)
        .arg("--specpath")
        .arg(spec_dir)
        .arg(&src_file)
        .status()
        .ok()?;
    if !status.success() {
        eprintln!(
            "[disrobe-pyinstaller] pyinstaller build exited non-zero (status={status:?}); aborting"
        );
        return None;
    }
    let produced: PathBuf = pick_built_binary(&dist_dir);
    if !produced.is_file() {
        eprintln!(
            "[disrobe-pyinstaller] expected onefile binary at {p} not found after build",
            p = produced.display()
        );
        return None;
    }
    std::fs::copy(&produced, &candidate).ok()?;
    let bytes: Vec<u8> = std::fs::read(&candidate).ok()?;
    Some(PyInstallerArtifact {
        binary_path: candidate,
        bytes,
    })
}

fn pick_built_binary(dist_dir: &Path) -> PathBuf {
    let candidate_name: &str = if cfg!(windows) {
        "disrobe_hello_pyinst.exe"
    } else {
        "disrobe_hello_pyinst"
    };
    dist_dir.join(candidate_name)
}

#[test]
fn pi_620_real_binary_extract_round_trip() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let cookie: Cookie =
        find_cookie(&artifact.bytes).expect("real pyinstaller binary must expose a MEI cookie");
    assert!(
        (2..=3).contains(&cookie.python_major),
        "python major out of range: {}",
        cookie.python_major
    );
    let toc: Vec<TocEntry> = walk_toc(&artifact.bytes, &cookie).expect("toc walks");
    assert!(!toc.is_empty(), "real binary must produce non-empty TOC");
    let output: ExtractOutput =
        extract_archive(&artifact.bytes).expect("extract real pyinstaller binary");
    assert!(
        !output.entries.is_empty(),
        "extracted entries must be non-empty for binary at {:?}",
        artifact.binary_path
    );
}

#[test]
fn pi_620_real_binary_toc_entries_match_expected() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let output: ExtractOutput = extract_archive(&artifact.bytes).expect("extract");
    let names: Vec<String> = output
        .entries
        .iter()
        .map(|e: &ExtractedEntry| e.toc.name.clone())
        .collect();
    let has_hello: bool = names
        .iter()
        .any(|n: &String| n == "hello" || n.contains("hello"));
    assert!(
        has_hello,
        "expected `hello` script in pyinstaller TOC; got {names:?}"
    );
    let pyc_carriers: usize = output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| e.toc.entry_type.is_pyc_carrier())
        .count();
    assert!(
        pyc_carriers > 0,
        "expected at least one pyc-carrier entry; got 0"
    );
    let script_count: usize = output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| e.toc.entry_type == EntryType::Script)
        .count();
    assert!(
        script_count > 0,
        "expected at least one script entry in TOC; got {script_count}"
    );
}

#[test]
fn pi_620_real_binary_aes_ctr_decryption_when_keyed() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let output: ExtractOutput = extract_archive(&artifact.bytes).expect("extract");
    let has_key_entry: bool = output
        .entries
        .iter()
        .any(|e: &ExtractedEntry| e.toc.name == "pyimod00_crypto_key");
    if !has_key_entry {
        assert!(
            output.encryption_key.is_none(),
            "no pyimod00_crypto_key entry but encryption_key materialized: {:?}",
            output.encryption_key
        );
        let decrypted_count: usize = output
            .entries
            .iter()
            .filter(|e: &&ExtractedEntry| e.decrypted)
            .count();
        assert_eq!(
            decrypted_count, 0,
            "unkeyed archive must not mark any entry as decrypted"
        );
        return;
    }
    assert!(
        output.encryption_key.is_some(),
        "keyed archive must produce an encryption key"
    );
    let any_decrypted: bool = output.entries.iter().any(|e: &ExtractedEntry| e.decrypted);
    assert!(
        any_decrypted,
        "keyed archive should have at least one successfully-decrypted entry"
    );
}
