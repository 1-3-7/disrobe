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

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use disrobe_pass_php::{
    Decompilation, Error, OPARRAY_MAX_VERSION, OPARRAY_MIN_VERSION, decompile_oparray,
    parse_oparray,
};
use php_toolchain::{PHP_OPCACHE, PhpRuntime, require_php, unmeasured};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const GRADED: &str = "the op_array decompile differential over the committed oparray samples";

const PINNED_SAMPLES: [&str; 7] = [
    "arithmetic",
    "control_flow",
    "do_while",
    "functions",
    "keyed_foreach",
    "variable_variable",
    "versioned",
];

const BEHAVIORALLY_GRADED_SAMPLES: [&str; 6] = [
    "arithmetic",
    "control_flow",
    "do_while",
    "functions",
    "keyed_foreach",
    "variable_variable",
];

fn required_sample(sample: &str) -> PathBuf {
    let path: PathBuf = oparray_dir().join("src").join(format!("{sample}.php"));
    assert!(
        path.is_file(),
        "corpus/php/oparray/src/{sample}.php is tracked in this repository and graded here, so a \
         run that cannot read it must fail rather than measure nothing; {} is absent",
        path.display()
    );
    path
}

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

fn find_php(graded: &str) -> Option<PathBuf> {
    let runtime: PhpRuntime = require_php(graded)?;
    Some(runtime.binary)
}

fn find_opcache(php: &Path, graded: &str) -> Option<String> {
    let dll: Option<String> = opcache_dll(php);
    if dll.is_none() {
        unmeasured(
            &PHP_OPCACHE,
            graded,
            "the opcache extension was not found beside the php binary",
        );
    }
    dll
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
    let purpose: String = format!("disrobe_recovered_{}_{}", std::process::id(), seq);
    let (scratch, mut file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create(&purpose, "php").ok()?;
    let tmp: PathBuf = scratch.path().to_path_buf();
    std::io::Write::write_all(&mut file, source.as_bytes()).ok()?;
    drop(file);
    let result: Option<String> = run_php(php, &tmp);
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
    let graded: String = format!("the {sample} op_array decompile differential");
    let Some(php): Option<PathBuf> = find_php(&graded) else {
        return;
    };
    let Some(dll): Option<String> = find_opcache(&php, &graded) else {
        return;
    };
    let src: PathBuf = required_sample(sample);

    let Some(original): Option<String> = run_php(&php, &src) else {
        panic!("could not run original {sample}.php");
    };
    assert!(
        !original.is_empty(),
        "{sample}.php prints nothing, so comparing the recovered source against its output would \
         accept a recovery that also prints nothing"
    );

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_oparray_oracle")
            .expect("mkdir oracle tmp");
    let out_dir: PathBuf = scratch.path().to_path_buf();
    let dzoa: PathBuf = out_dir.join(format!("{sample}.dzoa"));
    let emitted: Result<(), String> = emit_dzoa(&php, &dll, &src, &dzoa);
    if let Err(diag) = emitted {
        unmeasured(
            &PHP_OPCACHE,
            &graded,
            &format!(
                "this php and opcache build emits no op_array dump for {sample}, so the path is \
                 exercised only on builds whose opcache honors opt_debug_level\n{diag}\n\n{}",
                environment_diagnostics(&php)
            ),
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
fn every_committed_oparray_sample_is_pinned_by_name() {
    let dir: PathBuf = oparray_dir().join("src");
    let entries: std::fs::ReadDir = std::fs::read_dir(&dir).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "corpus/php/oparray/src is tracked in this repository and {GRADED} runs over it, so a \
             run that cannot enumerate it must fail rather than grade an empty set: {e} at {}",
            dir.display()
        )
    });
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let entry: std::fs::DirEntry =
            entry.unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", dir.display()));
        let name: String = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".php") {
            on_disk.insert(stem.to_owned());
        }
    }
    let pinned: BTreeSet<String> = PINNED_SAMPLES
        .iter()
        .map(|s: &&str| (*s).to_owned())
        .collect();
    assert_eq!(
        pinned.len(),
        PINNED_SAMPLES.len(),
        "a sample is pinned twice, so one entry grades nothing"
    );
    let ungraded: Vec<&String> = on_disk.difference(&pinned).collect();
    assert!(
        ungraded.is_empty(),
        "these op_array samples are committed but named by no test: {ungraded:?}. A sample that is \
         added without a case leaves a php construct compiled and never checked."
    );
    let missing: Vec<&String> = pinned.difference(&on_disk).collect();
    assert!(
        missing.is_empty(),
        "these samples are pinned but absent: {missing:?}. Deleting an input must fail rather than \
         quietly shrink what the differential covers."
    );
    assert_eq!(
        on_disk.len(),
        PINNED_SAMPLES.len(),
        "corpus/php/oparray/src holds {} samples and {} are pinned; the total is asserted apart \
         from the names so trading one sample for another cannot keep the count right",
        on_disk.len(),
        PINNED_SAMPLES.len()
    );
    let behavioral: BTreeSet<String> = BEHAVIORALLY_GRADED_SAMPLES
        .iter()
        .map(|s: &&str| (*s).to_owned())
        .collect();
    let not_behavioral: Vec<&String> = pinned.difference(&behavioral).collect();
    assert_eq!(
        not_behavioral,
        vec!["versioned"],
        "every pinned sample except `versioned`, which carries the schema-version cases, must have \
         a behavioral roundtrip; these do not: {not_behavioral:?}"
    );
    for sample in PINNED_SAMPLES {
        required_sample(sample);
    }
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
    let graded: String = format!("the {sample} op_array schema-version differential");
    let php: PathBuf = find_php(&graded)?;
    let dll: String = find_opcache(&php, &graded)?;
    let canonical_src: PathBuf = required_sample(sample);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_oparray_oracle")
            .expect("mkdir oracle tmp");
    let out_dir: PathBuf = scratch.path().to_path_buf();
    let seq: u64 = RECOVERED_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid: u32 = std::process::id();
    let src: PathBuf = out_dir.join(format!("{sample}_{pid}_{seq}.php"));
    std::fs::copy(&canonical_src, &src).expect("copy sample to unique path");
    let original_stdout: String = run_php(&php, &src)?;
    let dzoa: PathBuf = out_dir.join(format!("{sample}_{pid}_{seq}.dzoa"));
    let emitted: Result<(), String> = emit_dzoa_versioned(&php, &dll, &src, &dzoa, force_version);
    if let Err(diag) = emitted {
        unmeasured(
            &PHP_OPCACHE,
            &graded,
            &format!(
                "this php and opcache build emits no op_array dump for {sample}, so the path is \
                 exercised only on builds whose opcache honors opt_debug_level\n{diag}\n\n{}",
                environment_diagnostics(&php)
            ),
        );
        return None;
    }
    let bytes: Vec<u8> = std::fs::read(&dzoa).expect("read dzoa");
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
