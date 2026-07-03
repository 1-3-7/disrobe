#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    dead_code,
    clippy::print_stdout,
    clippy::redundant_pub_crate,
    clippy::std_instead_of_alloc,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

use disrobe_pass_php::{
    Decompilation, Error, OPARRAY_MAX_VERSION, OPARRAY_MIN_VERSION, decompile_oparray,
    parse_oparray,
};
use std::path::{Path, PathBuf};
use std::process::Command;

fn oparray_dir() -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut root: PathBuf = manifest;
    root.pop();
    root.pop();
    root.push("corpus");
    root.push("php");
    root.push("oparray");
    root
}

fn find_php() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("DISROBE_PHP_BIN") {
        let p: PathBuf = PathBuf::from(explicit);
        if p.exists() {
            return Some(p);
        }
    }
    let probe: std::io::Result<std::process::Output> =
        Command::new("php").arg("--version").output();
    match probe {
        Ok(out) if out.status.success() => Some(PathBuf::from("php")),
        _ => None,
    }
}

fn opcache_dll(php: &Path) -> Option<String> {
    if let Ok(explicit) = std::env::var("DZOA_OPCACHE_DLL")
        && Path::new(&explicit).exists()
    {
        return Some(explicit);
    }
    let resolved: PathBuf = if php == Path::new("php") {
        let which: std::io::Result<std::process::Output> = Command::new("php")
            .args(["-r", "echo PHP_BINARY;"])
            .output();
        match which {
            Ok(out) if out.status.success() => {
                PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_owned())
            }
            _ => return None,
        }
    } else {
        php.to_path_buf()
    };
    let dir: &Path = resolved.parent()?;
    for rel in ["ext/php_opcache.dll", "php_opcache.dll", "ext/opcache.so"] {
        let candidate: PathBuf = dir.join(rel);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn run_php(php: &Path, script: &Path) -> Option<String> {
    let out: std::process::Output = Command::new(php).arg(script).output().ok()?;
    if !out.status.success() {
        eprintln!(
            "php run of {} failed: {}",
            script.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(normalize(&String::from_utf8_lossy(&out.stdout)))
}

static RECOVERED_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn run_php_source(php: &Path, source: &str) -> Option<String> {
    let seq: u64 = RECOVERED_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp: PathBuf = std::env::temp_dir().join(format!(
        "disrobe_recovered_{}_{}.php",
        std::process::id(),
        seq
    ));
    std::fs::write(&tmp, source).ok()?;
    let result: Option<String> = run_php(php, &tmp);
    let _ = std::fs::remove_file(&tmp);
    result
}

fn emit_dzoa(php: &Path, dll: &str, src: &Path, out: &Path) -> Result<(), String> {
    emit_dzoa_versioned(php, dll, src, out, None)
}

fn emit_dzoa_versioned(
    php: &Path,
    dll: &str,
    src: &Path,
    out: &Path,
    force_version: Option<u8>,
) -> Result<(), String> {
    let emitter: PathBuf = oparray_dir().join("emit_dzoa.php");
    let mut command: Command = Command::new(php);
    command.env("DZOA_OPCACHE_DLL", dll);
    if let Some(v) = force_version {
        command.env("DZOA_FORCE_VERSION", v.to_string());
    }
    let output: std::process::Output = command
        .arg(&emitter)
        .arg(src)
        .arg(out)
        .output()
        .map_err(|e: std::io::Error| format!("could not spawn emit_dzoa.php: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "emit_dzoa.php exit={:?}\n--- emitter stdout ---\n{}\n--- emitter stderr ---\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn environment_diagnostics(php: &Path) -> String {
    let version: String = Command::new(php).arg("-v").output().map_or_else(
        |e: std::io::Error| format!("php -v failed: {e}"),
        |o: std::process::Output| String::from_utf8_lossy(&o.stdout).trim().to_owned(),
    );
    let info: String = Command::new(php).arg("-i").output().map_or_else(
        |e: std::io::Error| format!("php -i failed: {e}"),
        |o: std::process::Output| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|line: &&str| line.to_ascii_lowercase().contains("opcache"))
                .collect::<Vec<&str>>()
                .join("\n")
        },
    );
    format!("php -v:\n{version}\n\nphp -i | grep -i opcache:\n{info}")
}

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn behavioral_roundtrip(sample: &str) {
    let Some(php): Option<PathBuf> = find_php() else {
        eprintln!("skip: php not on PATH (set DISROBE_PHP_BIN)");
        return;
    };
    let Some(dll): Option<String> = opcache_dll(&php) else {
        eprintln!("skip: php_opcache extension not found next to the php binary");
        return;
    };
    let src: PathBuf = oparray_dir().join("src").join(format!("{sample}.php"));
    if !src.exists() {
        eprintln!("skip: sample {sample} absent");
        return;
    }

    let Some(original): Option<String> = run_php(&php, &src) else {
        panic!("could not run original {sample}.php");
    };

    let out_dir: PathBuf = std::env::temp_dir().join("disrobe_oparray_oracle");
    std::fs::create_dir_all(&out_dir).expect("mkdir oracle tmp");
    let dzoa: PathBuf = out_dir.join(format!("{sample}.dzoa"));
    let emitted: Result<(), String> = emit_dzoa(&php, &dll, &src, &dzoa);
    if let Err(diag) = emitted {
        eprintln!(
            "skip: this php/opcache build emits no op_array dump for {sample}; the path is exercised on builds whose opcache honors opt_debug_level.\n{diag}\n\n{}",
            environment_diagnostics(&php)
        );
        return;
    }

    let bytes: Vec<u8> = std::fs::read(&dzoa).expect("read dzoa");
    let parsed = parse_oparray(&bytes).expect("disrobe parse real op_array");
    let decomp: Decompilation = decompile_oparray(&parsed);
    let recovered_source: &str = &decomp.php_skeleton;

    let Some(recovered_output): Option<String> = run_php_source(&php, recovered_source) else {
        panic!("recovered {sample}.php did not execute; source:\n{recovered_source}");
    };

    assert_eq!(
        original, recovered_output,
        "behavioral mismatch for {sample}\n--- recovered source ---\n{recovered_source}\n--- original stdout ---\n{original}\n--- recovered stdout ---\n{recovered_output}"
    );
}

#[test]
fn arithmetic_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("arithmetic");
}

#[test]
fn control_flow_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("control_flow");
}

#[test]
fn functions_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("functions");
}

#[test]
fn do_while_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("do_while");
}

#[test]
fn keyed_foreach_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("keyed_foreach");
}

#[test]
fn variable_variable_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("variable_variable");
}

struct RealDump {
    php: PathBuf,
    original_stdout: String,
    bytes: Vec<u8>,
}

fn emit_real_dump(sample: &str) -> Option<RealDump> {
    emit_real_dump_versioned(sample, None)
}

fn emit_real_dump_versioned(sample: &str, force_version: Option<u8>) -> Option<RealDump> {
    let php: PathBuf = find_php()?;
    let dll: String = opcache_dll(&php)?;
    let canonical_src: PathBuf = oparray_dir().join("src").join(format!("{sample}.php"));
    if !canonical_src.exists() {
        eprintln!("skip: sample {sample} absent");
        return None;
    }
    let out_dir: PathBuf = std::env::temp_dir().join("disrobe_oparray_oracle");
    std::fs::create_dir_all(&out_dir).expect("mkdir oracle tmp");
    let seq: u64 = RECOVERED_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid: u32 = std::process::id();
    let src: PathBuf = out_dir.join(format!("{sample}_{pid}_{seq}.php"));
    std::fs::copy(&canonical_src, &src).expect("copy sample to unique path");
    let original_stdout: String = run_php(&php, &src)?;
    let dzoa: PathBuf = out_dir.join(format!("{sample}_{pid}_{seq}.dzoa"));
    let emitted: Result<(), String> = emit_dzoa_versioned(&php, &dll, &src, &dzoa, force_version);
    if let Err(diag) = emitted {
        eprintln!(
            "skip: this php/opcache build emits no op_array dump for {sample}; the path is exercised on builds whose opcache honors opt_debug_level.\n{diag}\n\n{}",
            environment_diagnostics(&php)
        );
        let _ = std::fs::remove_file(&src);
        return None;
    }
    let bytes: Vec<u8> = std::fs::read(&dzoa).expect("read dzoa");
    let _ = std::fs::remove_file(&dzoa);
    let _ = std::fs::remove_file(&src);
    Some(RealDump {
        php,
        original_stdout,
        bytes,
    })
}

fn restamp_version(bytes: &[u8], version: u8) -> Vec<u8> {
    let mut out: Vec<u8> = bytes.to_vec();
    out[4] = version;
    out
}

#[test]
fn real_opcache_dump_stamps_a_version_inside_the_accepted_range() {
    let Some(dump): Option<RealDump> = emit_real_dump("versioned") else {
        eprintln!("skip: php_opcache unavailable (set DISROBE_PHP_BIN)");
        return;
    };
    let stamped: u8 = dump.bytes[4];
    assert!(
        (OPARRAY_MIN_VERSION..=OPARRAY_MAX_VERSION).contains(&stamped),
        "emitter stamped schema version {stamped} outside parser range {OPARRAY_MIN_VERSION}..={OPARRAY_MAX_VERSION}"
    );
    parse_oparray(&dump.bytes).expect("parser accepts the emitter's own schema version");
}

#[test]
fn every_in_range_schema_version_parses_and_roundtrips_through_real_php() {
    for version in OPARRAY_MIN_VERSION..=OPARRAY_MAX_VERSION {
        let Some(dump): Option<RealDump> = emit_real_dump_versioned("versioned", Some(version))
        else {
            eprintln!("skip: php_opcache unavailable (set DISROBE_PHP_BIN)");
            return;
        };
        assert_eq!(
            dump.bytes[4], version,
            "emitter honored DZOA_FORCE_VERSION and stamped {version}"
        );
        let parsed = parse_oparray(&dump.bytes)
            .unwrap_or_else(|e| panic!("in-range schema version {version} rejected: {e}"));
        let decomp: Decompilation = decompile_oparray(&parsed);
        let recovered: String = run_php_source(&dump.php, &decomp.php_skeleton)
            .unwrap_or_else(|| panic!("recovered source for version {version} did not run"));
        assert_eq!(
            dump.original_stdout, recovered,
            "behavioral mismatch at schema version {version}\n--- recovered ---\n{}",
            decomp.php_skeleton
        );
    }
}

#[test]
fn out_of_range_schema_versions_are_rejected_naming_the_exact_version() {
    let Some(dump): Option<RealDump> = emit_real_dump("versioned") else {
        eprintln!("skip: php_opcache unavailable (set DISROBE_PHP_BIN)");
        return;
    };
    for bad in [
        OPARRAY_MIN_VERSION.wrapping_sub(1),
        OPARRAY_MAX_VERSION.wrapping_add(1),
        0xff,
    ] {
        if (OPARRAY_MIN_VERSION..=OPARRAY_MAX_VERSION).contains(&bad) {
            continue;
        }
        let bytes: Vec<u8> = restamp_version(&dump.bytes, bad);
        let err: Error =
            parse_oparray(&bytes).expect_err(&format!("schema version {bad} must be rejected"));
        assert!(
            matches!(err, Error::OpArrayUnsupportedVersion { version, .. } if version == bad),
            "expected DR-PHP-0091 naming version {bad}, got {err}"
        );
        let rendered: String = format!("{err}");
        assert!(
            rendered.contains("DR-PHP-0091") && rendered.contains(&bad.to_string()),
            "message must name code and version {bad}: {rendered}"
        );
    }
}
