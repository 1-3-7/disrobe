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

const MEI_MAGIC: &[u8; 8] = b"MEI\x0C\x0B\x0A\x0B\x0E";
const COOKIE_LEN_V21: usize = 88;
const PY312_MAGIC_LE: [u8; 4] = [0xCB, 0x0D, 0x0D, 0x0A];
const PY312_PYC_HEADER_LEN: usize = 16;

const REFERENCE_SOURCE: &str =
    "def main():\n    print('disrobe-pyinstaller-hello')\nif __name__ == '__main__':\n    main()\n";
const REFERENCE_FILENAME: &str = "hello.py";
const REFERENCE_TOKEN: &str = "disrobe-pyinstaller-hello";

const ENV_FORCE_REGEN: &str = "DISROBE_PYINSTALLER_REGEN";
const MIN_PYINSTALLER_MAJOR: u32 = 6;
const MIN_PYINSTALLER_MINOR: u32 = 20;

#[derive(Debug)]
struct PyInstallerArtifact {
    binary_path: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CPython312 {
    program: String,
    args: Vec<String>,
}

impl CPython312 {
    fn run_capture(&self, code: &str) -> Option<Vec<u8>> {
        let mut cmd: Command = Command::new(&self.program);
        for a in &self.args {
            cmd.arg(a);
        }
        cmd.arg("-c").arg(code);
        let out: std::process::Output = cmd.output().ok()?;
        if !out.status.success() {
            eprintln!(
                "[disrobe-pyinstaller] cpython 3.12 helper exited non-zero: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        Some(out.stdout)
    }
}

fn locate_cpython312() -> Option<CPython312> {
    let candidates: [(&str, &[&str]); 4] = [
        ("py", &["-3.12"]),
        ("python3.12", &[]),
        ("python3", &[]),
        ("python", &[]),
    ];
    for (program, args) in candidates {
        let candidate: CPython312 = CPython312 {
            program: program.to_owned(),
            args: args.iter().map(|s: &&str| (*s).to_owned()).collect(),
        };
        let probe: &str = "import sys,importlib.util,binascii; v=sys.version_info; sys.stdout.write(f'{v.major}.{v.minor}|'); sys.stdout.write(binascii.hexlify(importlib.util.MAGIC_NUMBER).decode())";
        let Some(raw): Option<Vec<u8>> = candidate.run_capture(probe) else {
            continue;
        };
        let text: String = String::from_utf8_lossy(&raw).into_owned();
        let mut parts: std::str::Split<'_, char> = text.trim().split('|');
        let ver: &str = parts.next().unwrap_or("");
        let magic_hex: &str = parts.next().unwrap_or("");
        if ver == "3.12" && magic_hex.eq_ignore_ascii_case("cb0d0d0a") {
            return Some(candidate);
        }
    }
    None
}

fn compile_reference_marshal(py: &CPython312) -> Option<Vec<u8>> {
    let src: &str = REFERENCE_SOURCE;
    let name: &str = REFERENCE_FILENAME;
    let code: String = format!(
        "import marshal,sys; src={src:?}; co=compile(src,{name:?},'exec'); sys.stdout.buffer.write(marshal.dumps(co))",
    );
    py.run_capture(&code)
}

fn push_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn zlib_compress(input: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::new(9));
    enc.write_all(input).expect("zlib write");
    enc.finish().expect("zlib finish")
}

struct CArchiveEntry {
    type_byte: u8,
    name: &'static str,
    payload: Vec<u8>,
}

fn assemble_carchive(entries: &[CArchiveEntry]) -> Vec<u8> {
    let mut data_region: Vec<u8> = Vec::new();
    let mut toc_region: Vec<u8> = Vec::new();
    for entry in entries {
        let compressed: Vec<u8> = zlib_compress(&entry.payload);
        let position: u32 = u32::try_from(data_region.len()).expect("position fits u32");
        let compressed_len: u32 = u32::try_from(compressed.len()).expect("clen fits u32");
        let uncompressed_len: u32 = u32::try_from(entry.payload.len()).expect("ulen fits u32");
        data_region.extend_from_slice(&compressed);

        let name_bytes: &[u8] = entry.name.as_bytes();
        let entry_size: u32 = 18 + u32::try_from(name_bytes.len()).expect("name fits u32");
        push_u32_be(&mut toc_region, entry_size);
        push_u32_be(&mut toc_region, position);
        push_u32_be(&mut toc_region, compressed_len);
        push_u32_be(&mut toc_region, uncompressed_len);
        toc_region.push(1u8);
        toc_region.push(entry.type_byte);
        toc_region.extend_from_slice(name_bytes);
    }

    let toc_offset: u32 = u32::try_from(data_region.len()).expect("toc_offset fits u32");
    let toc_length: u32 = u32::try_from(toc_region.len()).expect("toc_length fits u32");
    let package_len: u32 =
        toc_offset + toc_length + u32::try_from(COOKIE_LEN_V21).expect("cookie len fits u32");

    let mut archive: Vec<u8> = Vec::with_capacity(package_len as usize);
    archive.extend_from_slice(&data_region);
    archive.extend_from_slice(&toc_region);
    archive.extend_from_slice(MEI_MAGIC);
    push_u32_be(&mut archive, package_len);
    push_u32_be(&mut archive, toc_offset);
    push_u32_be(&mut archive, toc_length);
    push_u32_be(&mut archive, 312);
    let mut libname: Vec<u8> = b"python312.dll".to_vec();
    libname.resize(64, 0u8);
    archive.extend_from_slice(&libname);
    archive
}

fn recovered_marshal_body(entry: &ExtractedEntry) -> &[u8] {
    let data: &[u8] = &entry.data;
    assert!(
        data.len() > PY312_PYC_HEADER_LEN,
        "recovered pyc for '{}' too short to carry a header + body: {} bytes",
        entry.toc.name,
        data.len()
    );
    assert_eq!(
        &data[..4],
        &PY312_MAGIC_LE,
        "recovered pyc for '{}' must carry the 3.12 magic (0x0A0D0DCB le)",
        entry.toc.name
    );
    &data[PY312_PYC_HEADER_LEN..]
}

#[test]
fn pi_carchive_round_trip_recovers_bytecode_equivalent_source() {
    let Some(py): Option<CPython312> = locate_cpython312() else {
        eprintln!(
            "SKIP: on-box CPython 3.12 (magic 0x0A0D0DCB) not found via `py -3.12`/`python3.12`; cannot build a genuine non-circular CArchive round-trip"
        );
        return;
    };

    let embedded_marshal: Vec<u8> =
        compile_reference_marshal(&py).expect("on-box cpython 3.12 must marshal the reference");

    let oracle_marshal: Vec<u8> = compile_reference_marshal(&py)
        .expect("independent cpython 3.12 recompile of the reference must succeed");
    assert_eq!(
        embedded_marshal, oracle_marshal,
        "two separate cpython invocations must yield identical marshal (deterministic ground truth)"
    );

    let entries: Vec<CArchiveEntry> = vec![
        CArchiveEntry {
            type_byte: b's',
            name: "hello",
            payload: embedded_marshal.clone(),
        },
        CArchiveEntry {
            type_byte: b'm',
            name: "hello_mod",
            payload: embedded_marshal,
        },
        CArchiveEntry {
            type_byte: b'd',
            name: "runtime_dep",
            payload: b"dependency-marker".to_vec(),
        },
    ];
    let archive: Vec<u8> = assemble_carchive(&entries);
    assert!(
        archive.len() < 256 * 1024,
        "carchive fixture must stay under 256KB; got {} bytes",
        archive.len()
    );

    let cookie: Cookie = find_cookie(&archive).expect("format-detect: MEI cookie must be located");
    assert_eq!(cookie.python_major, 3, "detected python major");
    assert_eq!(cookie.python_minor, 12, "detected python minor");
    assert_eq!(
        cookie.python_libname.as_deref(),
        Some("python312.dll"),
        "v2.1+ cookie must expose the python library name"
    );

    let toc: Vec<TocEntry> = walk_toc(&archive, &cookie).expect("toc walks the real layout");
    assert_eq!(toc.len(), 3, "toc must enumerate all three entries");

    let output: ExtractOutput =
        extract_archive(&archive).expect("extract the genuine-payload carchive");
    assert!(
        output.encryption_key.is_none(),
        "unkeyed archive must not materialize an encryption key"
    );

    let script: &ExtractedEntry = output
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| e.toc.entry_type == EntryType::Script)
        .expect("script entry must survive extraction");
    let module: &ExtractedEntry = output
        .entries
        .iter()
        .find(|e: &&ExtractedEntry| e.toc.entry_type == EntryType::Module)
        .expect("module entry must survive extraction");

    let pyc_carriers: usize = output
        .entries
        .iter()
        .filter(|e: &&ExtractedEntry| e.toc.entry_type.is_pyc_carrier())
        .count();
    assert_eq!(pyc_carriers, 2, "both script and module are pyc carriers");

    let dep_dropped: bool = output
        .entries
        .iter()
        .all(|e: &ExtractedEntry| e.toc.entry_type != EntryType::Dependency);
    assert!(
        dep_dropped,
        "dependency entries must be skipped during extraction"
    );

    let script_body: &[u8] = recovered_marshal_body(script);
    let module_body: &[u8] = recovered_marshal_body(module);
    assert_eq!(
        script_body,
        oracle_marshal.as_slice(),
        "recovered SCRIPT bytecode must byte-match an INDEPENDENT cpython recompile of the reference source (non-circular oracle)"
    );
    assert_eq!(
        module_body,
        oracle_marshal.as_slice(),
        "recovered MODULE bytecode must byte-match an INDEPENDENT cpython recompile of the reference source (non-circular oracle)"
    );

    let src: &str = REFERENCE_SOURCE;
    let name: &str = REFERENCE_FILENAME;
    let disassembly: Vec<u8> = py
        .run_capture(&format!(
            "import marshal,sys,dis; co=compile({src:?},{name:?},'exec'); dis.dis(co)",
        ))
        .expect("disassemble reference for token presence");
    let disasm_text: String = String::from_utf8_lossy(&disassembly).into_owned();
    assert!(
        disasm_text.contains(REFERENCE_TOKEN),
        "recovered bytecode must carry the reference string constant '{REFERENCE_TOKEN}'; disasm prefix: {prefix}",
        prefix = &disasm_text[..disasm_text.len().min(400)]
    );
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
    for b in REFERENCE_SOURCE.bytes() {
        acc = acc.wrapping_mul(1_000_003).wrapping_add(u64::from(b));
    }
    for b in REFERENCE_FILENAME.bytes() {
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
    let src_file: PathBuf = src_dir.join(REFERENCE_FILENAME);
    std::fs::write(&src_file, REFERENCE_SOURCE).ok()?;
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
#[ignore = "supplementary live-regen E2E: requires pyinstaller>=6.20 on PATH AND a network/pip install (forbidden on this box); produces a ~6.7MB onefile binary that cannot be committed as a tracked <=256KB fixture. Gating coverage is provided by pi_carchive_round_trip_recovers_bytecode_equivalent_source, which builds a genuine-payload CArchive from on-box CPython without any install."]
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
#[ignore = "supplementary live-regen E2E: requires pyinstaller>=6.20 on PATH AND a forbidden pip/network install; ~6.7MB artifact is untracked. See pi_carchive_round_trip_recovers_bytecode_equivalent_source for the committed, non-circular gating round-trip."]
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
#[ignore = "supplementary live-regen E2E: requires pyinstaller>=6.20 on PATH AND a forbidden pip/network install; ~6.7MB artifact is untracked. See pi_carchive_round_trip_recovers_bytecode_equivalent_source for the committed, non-circular gating round-trip."]
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
