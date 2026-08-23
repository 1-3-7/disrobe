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

use disrobe_pass_php::decompile::op;
use disrobe_pass_php::{
    Decompilation, Error, OPARRAY_MAX_VERSION, OPARRAY_MIN_VERSION, Op, OpArray, UnrecoveredOp,
    decompile_oparray, opcode_name, parse_oparray,
};
use php_toolchain::{PHP_OPCACHE, PhpRuntime, require_php, unmeasured, write_opcache_source};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

const GRADED: &str = "the op_array decompile differential over the committed oparray samples";
const FETCH_IS_DZOA: &[u8] = include_bytes!("fixtures/oparray_fetch_is/fetch_is.dzoa");

const PINNED_SAMPLES: [&str; 25] = [
    "arithmetic",
    "closure_bodies",
    "closures",
    "control_flow",
    "do_while",
    "dynamic_members",
    "functions",
    "generators",
    "goto_forward",
    "goto_shapes",
    "interpolation",
    "keyed_foreach",
    "match_optimized",
    "members",
    "nullsafe",
    "nullsafe_calls",
    "objects",
    "references",
    "spaceship",
    "switch_linear",
    "switch_optimized",
    "type_checks",
    "unset_cv",
    "variable_variable",
    "versioned",
];

const BEHAVIORALLY_GRADED_SAMPLES: [&str; 22] = [
    "arithmetic",
    "closure_bodies",
    "control_flow",
    "do_while",
    "dynamic_members",
    "functions",
    "generators",
    "goto_forward",
    "goto_shapes",
    "interpolation",
    "keyed_foreach",
    "match_optimized",
    "nullsafe",
    "nullsafe_calls",
    "objects",
    "references",
    "spaceship",
    "switch_linear",
    "switch_optimized",
    "type_checks",
    "unset_cv",
    "variable_variable",
];

const OPCODE_NAMING_SAMPLES: [&str; 25] = [
    "arithmetic",
    "closure_bodies",
    "closures",
    "control_flow",
    "do_while",
    "dynamic_members",
    "functions",
    "generators",
    "goto_forward",
    "goto_shapes",
    "interpolation",
    "keyed_foreach",
    "match_optimized",
    "members",
    "nullsafe",
    "nullsafe_calls",
    "objects",
    "references",
    "spaceship",
    "switch_linear",
    "switch_optimized",
    "type_checks",
    "unset_cv",
    "variable_variable",
    "versioned",
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
    let explicit: Option<OsString> = std::env::var_os("DZOA_OPCACHE_DLL");
    opcache_dll_with_explicit(php, explicit)
}

const WINDOWS_VERBATIM_PREFIX: &str = r"\\?\";
const WINDOWS_VERBATIM_UNC_PREFIX: &str = r"\\?\UNC\";

fn loadable_extension_path(canonical: &Path) -> Option<String> {
    let text: String = canonical.to_str()?.to_owned();
    if let Some(share) = text.strip_prefix(WINDOWS_VERBATIM_UNC_PREFIX) {
        return Some(format!(r"\\{share}"));
    }
    let Some(drive) = text.strip_prefix(WINDOWS_VERBATIM_PREFIX) else {
        return Some(text);
    };
    let mut bytes: std::str::Bytes<'_> = drive.bytes();
    let letter: bool = bytes
        .next()
        .is_some_and(|byte: u8| byte.is_ascii_alphabetic());
    let colon: bool = bytes.next() == Some(b':');
    let separator: bool = bytes.next() == Some(b'\\');
    if letter && colon && separator {
        return Some(drive.to_owned());
    }
    Some(text)
}

fn opcache_dll_with_explicit(php: &Path, explicit: Option<OsString>) -> Option<String> {
    if let Some(explicit) = explicit {
        let canonical: PathBuf = PathBuf::from(explicit).canonicalize().ok()?;
        if !canonical.is_file() {
            return None;
        }
        return loadable_extension_path(&canonical);
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
    emit_dzoa_versioned(php, dll, src, out, None, None)
}

fn emit_dzoa_with_dump(
    php: &Path,
    dll: &str,
    src: &Path,
    out: &Path,
    dump: &Path,
) -> Result<(), String> {
    emit_dzoa_versioned(php, dll, src, out, None, Some(dump))
}

fn emit_dzoa_versioned(
    php: &Path,
    dll: &str,
    src: &Path,
    out: &Path,
    force_version: Option<u8>,
    dump: Option<&Path>,
) -> Result<(), String> {
    let emitter: PathBuf = oparray_dir().join("emit_dzoa.php");
    let mut command: Command = Command::new(php);
    command.env("DZOA_OPCACHE_DLL", dll);
    if let Some(v) = force_version {
        command.env("DZOA_FORCE_VERSION", v.to_string());
    }
    command.arg(&emitter).arg(src).arg(out);
    if let Some(path) = dump {
        command.arg(path);
    }
    let output: std::process::Output = command
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

const SLOT_FALLBACK_PREFIXES: [&str; 3] = ["$tmp", "$var", "$slot"];

fn leaked_slot_names(source: &str) -> Vec<String> {
    let bytes: &[u8] = source.as_bytes();
    let mut found: BTreeSet<String> = BTreeSet::new();
    for prefix in SLOT_FALLBACK_PREFIXES {
        let mut from: usize = 0;
        while let Some(hit) = source[from..].find(prefix) {
            let start: usize = from + hit;
            let mut end: usize = start + prefix.len();
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            let digits: usize = end - start - prefix.len();
            let boundary: bool = bytes
                .get(end)
                .is_none_or(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_');
            if digits > 0 && boundary {
                found.insert(source[start..end].to_owned());
            }
            from = start + prefix.len();
        }
    }
    found.into_iter().collect()
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
    if sample == "generators" {
        assert_eq!(
            bytes,
            include_bytes!("fixtures/oparray_generator/generators.dzoa"),
            "the committed generator op array must reproduce byte-for-byte from its tracked PHP source and emitter"
        );
    }
    let parsed = parse_oparray(&bytes).expect("disrobe parse real op_array");
    let decomp: Decompilation = decompile_oparray(&parsed);
    let recovered_source: &str = &decomp.php_skeleton;
    assert!(
        decomp.unrecovered.is_empty(),
        "{sample} is graded as a recovered sample, so every opcode in it must be modelled; these \
         were refused: {:?}\n--- recovered source ---\n{recovered_source}",
        decomp.unrecovered
    );
    let leaked: Vec<String> = leaked_slot_names(recovered_source);
    assert!(
        leaked.is_empty(),
        "{sample} recovered with generated slot names still in the source, which means data flow \
         did not reach those values: {leaked:?}\n--- recovered source \
         ---\n{recovered_source}"
    );

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
        vec!["closures", "members", "versioned"],
        "every pinned sample except `closures`, which grades anonymous closure opcode blocks, \
         `goto_shapes`, whose jumps the structurer refuses by name, `members`, whose user class \
         declaration and static methods are not carried in this container, and `versioned`, \
         which carries the schema-version cases, must have a behavioral roundtrip; these do \
         not: {not_behavioral:?}"
    );
    let opcode_naming: BTreeSet<String> = OPCODE_NAMING_SAMPLES
        .iter()
        .map(|sample: &&str| (*sample).to_owned())
        .collect();
    assert_eq!(
        opcode_naming, pinned,
        "every pinned sample must compare its opcodes against the raw opcache dump"
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
fn generator_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("generators");
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
fn unset_cv_recovers_the_compiled_variable_and_preserves_runtime_state() {
    let graded: &str = "the php 8.4 UNSET_CV recovery";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let original: String = run_php(&php, &required_sample("unset_cv"))
        .unwrap_or_else(|| panic!("the tracked unset_cv source must execute"));
    let parsed: OpArray = parse_sample(&php, &dll, "unset_cv");
    let first: Decompilation = decompile_oparray(&parsed);
    let second: Decompilation = decompile_oparray(&parsed);
    assert_eq!(
        first.php_skeleton, second.php_skeleton,
        "one op array must recover byte-identical source on repeated runs"
    );
    assert!(
        first.unrecovered.is_empty(),
        "the real php 8.4 UNSET_CV must recover without a refusal: {:?}\n--- recovered ---\n{}",
        first.unrecovered,
        first.php_skeleton
    );
    assert!(
        first.php_skeleton.contains("unset($removed);"),
        "the recovered unset must name the CV php compiled: {}",
        first.php_skeleton
    );
    assert!(
        !first.php_skeleton.contains("unset($kept);"),
        "the adjacent CV must remain live: {}",
        first.php_skeleton
    );
    let recovered: String = run_php_source(&php, &first.php_skeleton)
        .unwrap_or_else(|| panic!("the recovered unset_cv source must execute"));
    assert_eq!(
        original, recovered,
        "UNSET_CV recovery must preserve observable variable state\n--- recovered ---\n{}",
        first.php_skeleton
    );

    let mut wrong_cv: OpArray = parsed.clone();
    let body: &mut OpArray = wrong_cv
        .children
        .iter_mut()
        .find(|child: &&mut OpArray| child.name.as_deref() == Some("remove_first"))
        .unwrap_or_else(|| panic!("the tracked sample declares remove_first"));
    let unset: &mut Op = body
        .ops
        .iter_mut()
        .find(|candidate: &&mut Op| candidate.opcode == op::UNSET_CV)
        .unwrap_or_else(|| panic!("php 8.4 must compile unset($removed) as UNSET_CV"));
    assert_eq!(unset.op1, 0, "php must encode $removed as the first CV");
    unset.op1 = 1;
    let wrong: Decompilation = decompile_oparray(&wrong_cv);
    let wrong_output: String = run_php_source(&php, &wrong.php_skeleton)
        .unwrap_or_else(|| panic!("the deliberately wrong-CV recovery must still execute"));
    assert_ne!(
        original, wrong_output,
        "the runtime differential must fail if recovery unsets the adjacent CV"
    );
}

#[test]
fn fetch_is_recovers_local_coalesce_reads_under_php_84() {
    let graded: &str = "the PHP 8.4 FETCH_IS recovery differential";
    let php: PathBuf = required_php(graded);
    let banner: String = String::from_utf8_lossy(
        &Command::new(&php)
            .arg("-v")
            .output()
            .expect("read the PHP 8.4 banner")
            .stdout,
    )
    .into_owned();
    assert!(
        banner.starts_with("PHP 8.4."),
        "expected PHP 8.4, found {banner}"
    );
    let dll: String = required_opcache(&php, graded);
    let fixture: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("oparray_fetch_is");
    let source: PathBuf = fixture.join("fetch_is.php");
    let original: String =
        run_php(&php, &source).expect("the tracked FETCH_IS source must execute");
    assert_eq!(original, "present\nmissing\n");

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_fetch_is")
            .expect("create FETCH_IS scratch directory");
    let emitted: PathBuf = scratch.path().join("fetch_is.dzoa");
    emit_dzoa(&php, &dll, &source, &emitted).expect("emit tracked FETCH_IS source");
    let fresh: Vec<u8> = std::fs::read(&emitted).expect("read regenerated FETCH_IS DZOA");
    assert_eq!(
        fresh, FETCH_IS_DZOA,
        "the tracked FETCH_IS DZOA must reproduce byte-for-byte"
    );

    let parsed: OpArray = parse_oparray(&fresh).expect("parse FETCH_IS DZOA");
    let first: Decompilation = decompile_oparray(&parsed);
    let second: Decompilation = decompile_oparray(&parsed);
    assert_eq!(
        first.php_skeleton, second.php_skeleton,
        "FETCH_IS recovery must be byte-identical"
    );
    assert!(first.unrecovered.is_empty(), "{:?}", first.unrecovered);
    assert!(
        first.php_skeleton.contains("return $$name ?? 'missing';"),
        "{}",
        first.php_skeleton
    );
    let recovered: String =
        run_php_source(&php, &first.php_skeleton).expect("recovered FETCH_IS source must execute");
    assert_eq!(recovered, original, "behavioral grade: 2/2 calls");

    let mutant: String = first
        .php_skeleton
        .replacen("$$name ?? 'missing'", "$$name", 1);
    assert_ne!(mutant, first.php_skeleton, "FETCH_IS mutation must apply");
    let perturbed: Option<String> = run_php_source(&php, &mutant);
    assert_ne!(
        perturbed.as_deref(),
        Some(original.as_str()),
        "the missing-value mutation must fail"
    );
}

#[test]
fn malformed_unset_cv_operands_are_refused_by_name() {
    #[derive(Clone, Copy)]
    enum Mutation {
        OperandType,
        Index,
        MissingName,
        InvalidName,
        SecondOperand,
        Result,
        ExtendedValue,
    }

    let graded: &str = "the php 8.4 UNSET_CV operand boundary";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let parsed: OpArray = parse_sample(&php, &dll, "unset_cv");

    for (label, mutation) in [
        ("a non-CV operand", Mutation::OperandType),
        (
            "a CV index outside the declared variable table",
            Mutation::Index,
        ),
        ("a CV slot without a declared name", Mutation::MissingName),
        ("an invalid PHP variable name", Mutation::InvalidName),
        ("a second operand", Mutation::SecondOperand),
        ("a result operand", Mutation::Result),
        ("an extended-value payload", Mutation::ExtendedValue),
    ] {
        let mut malformed: OpArray = parsed.clone();
        let body: &mut OpArray = malformed
            .children
            .iter_mut()
            .find(|child: &&mut OpArray| child.name.as_deref() == Some("remove_first"))
            .unwrap_or_else(|| panic!("the tracked sample declares remove_first"));
        let unset: &mut Op = body
            .ops
            .iter_mut()
            .find(|candidate: &&mut Op| candidate.opcode == op::UNSET_CV)
            .unwrap_or_else(|| panic!("php 8.4 must compile unset($removed) as UNSET_CV"));
        match mutation {
            Mutation::OperandType => unset.op1_type = disrobe_pass_php::OperandType::Var,
            Mutation::Index => {
                unset.op1 = u32::try_from(body.var_names.len())
                    .unwrap_or_else(|_| panic!("the tracked CV table length fits in u32"));
            }
            Mutation::MissingName => body.var_names[unset.op1 as usize] = None,
            Mutation::InvalidName => {
                body.var_names[unset.op1 as usize] = Some("invalid-name".to_owned());
            }
            Mutation::SecondOperand => unset.op2_type = disrobe_pass_php::OperandType::Cv,
            Mutation::Result => unset.result_type = disrobe_pass_php::OperandType::TmpVar,
            Mutation::ExtendedValue => unset.extended_value = 1,
        }
        let recovered: Decompilation = decompile_oparray(&malformed);
        assert!(
            recovered.unrecovered.iter().any(|entry: &UnrecoveredOp| {
                entry.opcode == op::UNSET_CV && entry.reason.contains("compiled variable")
            }),
            "{label} must produce the existing typed refusal record: {:?}\n--- recovered ---\n{}",
            recovered.unrecovered,
            recovered.php_skeleton
        );
    }
}

#[test]
fn variable_variable_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("variable_variable");
}

#[test]
fn objects_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("objects");
}

#[test]
fn php_84_linear_switch_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("switch_linear");
}

#[test]
fn php_84_optimized_switch_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("switch_optimized");
}

#[test]
fn php_84_optimized_match_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("match_optimized");
}

#[test]
fn dynamic_members_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("dynamic_members");
}

#[test]
fn references_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("references");
}

#[test]
fn nullsafe_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("nullsafe");
}

#[test]
fn nullsafe_calls_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("nullsafe_calls");
}

#[test]
fn spaceship_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("spaceship");
}

#[test]
fn closure_bodies_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("closure_bodies");
}

#[test]
fn goto_forward_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("goto_forward");
}

#[test]
fn interpolation_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("interpolation");
}

#[test]
fn goto_shapes_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("goto_shapes");
}

#[test]
fn type_checks_oparray_roundtrips_behaviorally() {
    behavioral_roundtrip("type_checks");
}

const GOTO_RECOVERED_SITES: [(&str, &str); 2] = [("out_of_loop", "goto "), ("backward", "goto ")];

#[test]
fn a_jump_the_structurer_cannot_shape_recovers_as_the_goto_the_source_had() {
    let graded: &str = "the php 8.4 goto shapes the structurer cannot fold";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let recovered: Decompilation = recover_sample(&php, &dll, "goto_shapes");
    let source: &str = &recovered.php_skeleton;
    assert!(
        recovered.unrecovered.is_empty(),
        "a jump the structurer cannot fold is recovered as the goto the source had, not refused; \
         these were refused: {:?}\n--- recovered ---\n{source}",
        recovered.unrecovered
    );
    let gotos: usize = source.matches("goto ").count();
    assert_eq!(
        gotos,
        GOTO_RECOVERED_SITES.len(),
        "goto_shapes writes exactly {} gotos the structurer cannot fold, so the recovery must \
         emit that many and no more\n--- recovered ---\n{source}",
        GOTO_RECOVERED_SITES.len()
    );
    for line in source.lines() {
        let trimmed: &str = line.trim();
        let Some(label) = trimmed.strip_suffix(':') else {
            continue;
        };
        if !label.starts_with("disrobe_label_") {
            continue;
        }
        assert!(
            source.contains(&format!("goto {label};")),
            "a label may only be placed where a jump targets it; `{label}` is unreferenced\n--- \
             recovered ---\n{source}"
        );
    }
    for target in source.match_indices("goto ") {
        let rest: &str = &source[target.0 + "goto ".len()..];
        let Some(name) = rest.split(';').next() else {
            continue;
        };
        assert!(
            source.contains(&format!("{name}:")),
            "every goto must land on a label that was placed; `{name}` has none\n--- recovered \
             ---\n{source}"
        );
    }
}

#[test]
fn a_goto_that_already_structures_does_not_regress_into_a_jump() {
    let graded: &str = "the php 8.4 forward goto shapes that already structure";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let recovered: Decompilation = recover_sample(&php, &dll, "goto_forward");
    assert!(
        !recovered.php_skeleton.contains("goto "),
        "a forward goto at the same nesting level compiles to the same opcodes as an if/else and \
         must keep recovering as one; emitting a goto here is the soup this capability \
         forbids\n--- recovered ---\n{}",
        recovered.php_skeleton
    );
}

#[test]
fn a_lexical_bind_that_does_not_target_its_declared_closure_is_refused_rather_than_captured() {
    let graded: &str = "the php 8.4 closure use-list binding boundary";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let clean: Decompilation = decompile_oparray(&parse_sample(&php, &dll, "closure_bodies"));
    assert!(
        clean.unrecovered.is_empty(),
        "the unmutated sample must recover fully before a mutation can mean anything: {:?}",
        clean.unrecovered
    );
    let captured: usize = clean.php_skeleton.matches("use ($base)").count();
    assert!(
        captured >= 2,
        "pick declares two closures that each capture $base, so the clean recovery must show at \
         least two; the sample changed\n--- recovered ---\n{}",
        clean.php_skeleton
    );

    let mut parsed: OpArray = parse_sample(&php, &dll, "closure_bodies");
    {
        let ops: &mut Vec<Op> = nullsafe_body(&mut parsed, "pick");
        let bind: &mut Op = ops
            .iter_mut()
            .find(|op: &&mut Op| op.opcode == 182)
            .expect("pick binds a lexical into its first closure");
        bind.op1 = bind.op1.wrapping_add(64);
    }
    let recovered: Decompilation = decompile_oparray(&parsed);
    assert!(
        recovered
            .unrecovered
            .iter()
            .any(|entry: &UnrecoveredOp| entry.mnemonic == "ZEND_DECLARE_LAMBDA_FUNCTION"),
        "a lexical bind whose target is not the closure just declared is not a php 8 use list, so \
         the declaration must be refused rather than given a capture it does not have; got \
         {:?}\n--- recovered ---\n{}",
        recovered.unrecovered,
        recovered.php_skeleton
    );
    assert_eq!(
        recovered.php_skeleton.matches("use ($base)").count(),
        captured - 1,
        "exactly the closure whose bind was broken must lose its use list; the others must keep \
         theirs\n--- recovered ---\n{}",
        recovered.php_skeleton
    );
}

const NULLSAFE_CHAINS: [(&str, &str); 4] = [
    ("read_one", "return (string) ($box?->label ?? 'none');"),
    (
        "read_chain",
        "return (string) ($box?->inner?->label ?? 'none');",
    ),
    (
        "read_deep",
        "return (string) ($box?->inner?->inner?->label ?? 'none');",
    ),
    ("read_plain", "return (string) ($box?->label ?? '');"),
];

const NULLSAFE_LINKS: usize = 7;

fn nullsafe_body<'a>(parsed: &'a mut OpArray, function: &str) -> &'a mut Vec<Op> {
    &mut parsed
        .children
        .iter_mut()
        .find(|child: &&mut OpArray| child.name.as_deref() == Some(function))
        .unwrap_or_else(|| panic!("the nullsafe sample declares {function}"))
        .ops
}

#[test]
fn a_nullsafe_chain_whose_guards_do_not_form_one_php_8_chain_is_refused_rather_than_folded() {
    let graded: &str = "the php 8.4 nullsafe chain shape boundary";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);

    for (label, mutate) in [
        ("guards that jump to different joins", 0_u8),
        (
            "a chain whose last fetch does not land in the guarded slot",
            1_u8,
        ),
    ] {
        let mut parsed: OpArray = parse_sample(&php, &dll, "nullsafe");
        {
            let ops: &mut Vec<Op> = nullsafe_body(&mut parsed, "read_chain");
            let guards: Vec<usize> = ops
                .iter()
                .enumerate()
                .filter(|(_, op): &(usize, &Op)| op.opcode == 198)
                .map(|(index, _): (usize, &Op)| index)
                .collect();
            assert_eq!(
                guards.len(),
                2,
                "read_chain is pinned as a two-link nullsafe chain; the sample changed"
            );
            if mutate == 0 {
                let second: usize = guards[1];
                ops[second].op2 = ops[second].op2.saturating_sub(1);
            } else {
                let last: usize = ops.len() - 1;
                let fetch: usize = guards[1] + 1;
                assert_eq!(
                    ops[fetch].opcode, 91,
                    "the guard is followed by FETCH_OBJ_IS"
                );
                ops[fetch].result = ops[fetch].result.wrapping_add(64);
                let _ = last;
            }
        }
        let recovered: Decompilation = decompile_oparray(&parsed);
        assert!(
            recovered
                .unrecovered
                .iter()
                .any(|entry: &UnrecoveredOp| entry.mnemonic == "ZEND_JMP_NULL"),
            "{label} is not a php 8 nullsafe chain, so it must be refused by name rather than \
             folded into an operator that short-circuits differently; got {:?}\n--- recovered \
             ---\n{}",
            recovered.unrecovered,
            recovered.php_skeleton
        );
        assert!(
            !recovered.php_skeleton.contains("$box?->inner?->label"),
            "{label} must not still render the two-link chain it no longer describes\n--- \
             recovered ---\n{}",
            recovered.php_skeleton
        );
    }
}

#[test]
fn every_nullsafe_chain_keeps_the_operator_that_short_circuits_it() {
    let graded: &str = "the php 8.4 nullsafe property chain recovery";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let recovered: Decompilation = recover_sample(&php, &dll, "nullsafe");
    assert!(
        recovered.unrecovered.is_empty(),
        "nullsafe is graded as a fully recovered sample: {:?}\n--- recovered ---\n{}",
        recovered.unrecovered,
        recovered.php_skeleton
    );
    let source: &str = &recovered.php_skeleton;
    let mut lost: Vec<&str> = Vec::new();
    let mut restored: usize = 0;
    for (site, statement) in NULLSAFE_CHAINS {
        if source.contains(statement) {
            restored += 1;
        } else {
            lost.push(site);
        }
    }
    assert!(
        lost.is_empty(),
        "{restored}/{} nullsafe chains recovered their operator; these did not: {lost:?}\n--- \
         recovered ---\n{source}",
        NULLSAFE_CHAINS.len()
    );
    assert_eq!(
        source.matches("?->").count(),
        NULLSAFE_LINKS,
        "the sample writes exactly {NULLSAFE_LINKS} nullsafe links, so the recovery must not \
         invent or drop one\n--- recovered ---\n{source}"
    );
}

fn required_php(graded: &str) -> PathBuf {
    find_php(graded).unwrap_or_else(|| {
        panic!(
            "{graded} is graded only by running php, so this case must not report success \
             without it. Missing prerequisite: a php 8.4 interpreter on PATH or at \
             DISROBE_PHP_BIN."
        )
    })
}

fn required_opcache(php: &Path, graded: &str) -> String {
    find_opcache(php, graded).unwrap_or_else(|| {
        panic!(
            "{graded} is graded only by compiling php source into an op array, so this case \
             must not report success without the compiler that makes them. Missing \
             prerequisite: the php 8.4 opcache extension beside the php binary or at \
             DZOA_OPCACHE_DLL."
        )
    })
}

fn parse_sample(php: &Path, dll: &str, sample: &str) -> OpArray {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_parse_probe")
            .expect("create the parse scratch directory");
    let dzoa: PathBuf = scratch.path().join(format!("{sample}.dzoa"));
    emit_dzoa(php, dll, &required_sample(sample), &dzoa)
        .unwrap_or_else(|diagnosis: String| panic!("emit {sample}: {diagnosis}"));
    let bytes: Vec<u8> = std::fs::read(&dzoa).expect("read the op array");
    parse_oparray(&bytes).expect("parse the op array")
}

fn recover_sample(php: &Path, dll: &str, sample: &str) -> Decompilation {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_limitation_probe")
            .expect("create the limitation scratch directory");
    let dzoa: PathBuf = scratch.path().join(format!("{sample}.dzoa"));
    emit_dzoa(php, dll, &required_sample(sample), &dzoa)
        .unwrap_or_else(|diagnosis: String| panic!("emit {sample}: {diagnosis}"));
    let bytes: Vec<u8> = std::fs::read(&dzoa).expect("read the op array");
    let parsed: OpArray = parse_oparray(&bytes).expect("parse the op array");
    decompile_oparray(&parsed)
}

#[test]
fn a_constant_array_literal_is_published_with_a_named_limitation_rather_than_refused() {
    let graded: &str =
        "the named limitation on a constant array literal this container cannot carry";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);

    let carried: Decompilation = recover_sample(&php, &dll, "keyed_foreach");
    assert!(
        carried.unrecovered.is_empty(),
        "a constant array literal must NOT refuse the body; `array()` is right whenever the \
         literal was empty, and keyed_foreach's is. It reported: {:?}",
        carried.unrecovered
    );
    assert!(
        !carried.limitations.is_empty(),
        "keyed_foreach assigns `[]`, whose elements this container does not carry, so the \
         recovery must say so rather than let `array()` pass as verified\n--- recovered ---\n{}",
        carried.php_skeleton
    );
    for limitation in &carried.limitations {
        assert!(
            limitation.note.contains("not carried in this op array"),
            "a limitation must name what cannot be vouched for, got {limitation:?}"
        );
        assert!(
            !limitation.mnemonic.is_empty() && !limitation.container.is_empty(),
            "a limitation must name the op and the container it sits in, got {limitation:?}"
        );
    }
    let markers: usize = carried
        .php_skeleton
        .matches("// disrobe: unverified")
        .count();
    assert_eq!(
        markers,
        carried.limitations.len(),
        "every limitation must be visible at its site in the recovered source, and every visible \
         marker must be in the machine-readable record; the two disagree\n--- recovered ---\n{}",
        carried.php_skeleton
    );
    assert!(
        carried.php_skeleton.contains("array()"),
        "the body is published, not refused, so the array must still be emitted\n--- recovered \
         ---\n{}",
        carried.php_skeleton
    );
    assert_eq!(
        carried.limitations_total,
        carried.limitations.len(),
        "the limitation total must match the records this sample produced"
    );
}

#[test]
fn a_sample_with_nothing_unverifiable_carries_no_limitation() {
    let graded: &str = "the limitation mechanism's silence on a sample with nothing to qualify";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let clean: Decompilation = recover_sample(&php, &dll, "arithmetic");
    assert!(
        clean.limitations.is_empty() && clean.limitations_total == 0,
        "arithmetic builds no constant array literal, so a limitation there would mean the \
         mechanism fires on everything and therefore vouches for nothing: {:?}",
        clean.limitations
    );
    assert!(
        !clean.php_skeleton.contains("// disrobe: unverified"),
        "a sample with nothing unverifiable must carry no marker\n--- recovered ---\n{}",
        clean.php_skeleton
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenDisposition {
    Deferred,
    Discarded,
    Failed,
}

const OPERAND_TOKEN_SHAPES: [(&str, &str, TokenDisposition, &str); 4] = [
    (
        "a bare number",
        "<?php $n = 0; while ($n < 3) { $n = $n + 1; } echo $n, \"\\n\";\n",
        TokenDisposition::Deferred,
        "a jump target, an argument count or a closure index; the jump-target pass resolves it",
    ),
    (
        "loop-end(+N)",
        "<?php $rows = [1, 2]; $cols = [3, 4]; $t = 0; foreach ($rows as $r) { foreach ($cols \
         as $c) { if ($c === 4) { continue 2; } $t = $t + $c; } } echo $t, \"\\n\";\n",
        TokenDisposition::Discarded,
        "a live-range annotation on the iterator a multi-level loop exit frees; it names no \
         operand",
    ),
    (
        "(unqualified-in-namespace)",
        "<?php namespace A\\B; echo PHP_EOL;\n",
        TokenDisposition::Discarded,
        "a constant fetch mode; the name is carried by the literal, and the token holds the op1 \
         slot so the name stays in op2",
    ),
    (
        "(ref)",
        "<?php $b = 1; $a = [&$b]; echo count($a), \"\\n\";\n",
        TokenDisposition::Failed,
        "a by-reference array element; nothing else in the stream carries it",
    ),
];

#[test]
fn every_operand_token_shape_the_emitter_sees_is_parsed_deferred_discarded_or_failed() {
    let graded: &str = "the op_array emitter's disposition of every operand token shape it sees";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_token_shapes")
            .expect("create the token shape scratch directory");

    for (index, (shape, source, disposition, reason)) in OPERAND_TOKEN_SHAPES.iter().enumerate() {
        let staged: PathBuf = scratch.path().join(format!("shape{index}.php"));
        write_opcache_source(&staged, source.as_bytes()).expect("stage the token shape source");
        let produced: PathBuf = scratch.path().join(format!("shape{index}.dzoa"));
        let outcome: Result<(), String> = emit_dzoa(&php, &dll, &staged, &produced);
        match disposition {
            TokenDisposition::Deferred | TokenDisposition::Discarded => {
                outcome.unwrap_or_else(|diagnosis: String| {
                    panic!(
                        "`{shape}` is classified as {disposition:?} because {reason}, so a source \
                         carrying it must still emit. It did not: {diagnosis}"
                    )
                });
            }
            TokenDisposition::Failed => {
                let diagnosis: String = outcome.err().unwrap_or_else(|| {
                    panic!(
                        "`{shape}` is classified as Failed because {reason}, so a source carrying \
                         it must be refused rather than encoded with the token dropped and every \
                         operand after it shifted"
                    )
                });
                assert!(
                    diagnosis.contains(shape),
                    "a refused token must name itself so the next author knows what to handle; \
                     `{shape}` reported: {diagnosis}"
                );
            }
        }
    }
}

const UNHANDLED_FLAG_SOURCE: &str =
    "<?php\n$b = 1;\n$c = 2;\n$byref = [&$b, 'k' => &$c];\n$b = 9;\necho $byref[0], \"\\n\";\n";

#[test]
fn an_operand_flag_the_emitter_cannot_encode_fails_it_and_the_tracked_op_arrays_still_reproduce() {
    let graded: &str =
        "the op_array emitter's refusal to drop an operand flag it would otherwise shift past";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_emitter_flag_guard")
            .expect("create the emitter guard scratch directory");

    let flagged: PathBuf = scratch.path().join("by_reference_element.php");
    write_opcache_source(&flagged, UNHANDLED_FLAG_SOURCE.as_bytes())
        .expect("stage the by-reference array element source");
    let refused: PathBuf = scratch.path().join("by_reference_element.dzoa");
    let outcome: Result<(), String> = emit_dzoa(&php, &dll, &flagged, &refused);
    let diagnosis: String = match outcome {
        Ok(()) => panic!(
            "a by-reference array element carries a `(ref)` operand flag this container cannot \
             encode. The emitter consumed it as op1 and shifted the real value into the key slot, \
             which is a silently corrupt op array rather than a refusal. It must fail instead. It \
             wrote {}",
            refused.display()
        ),
        Err(diagnosis) => diagnosis,
    };
    assert!(
        diagnosis.contains("(ref)"),
        "the emitter must name the flag it could not encode, so the next author knows what to \
         handle; it reported: {diagnosis}"
    );
    assert!(
        !refused.exists(),
        "a refused emission must leave no op array behind for a grader to read as real evidence"
    );

    let handled: PathBuf = scratch.path().join("members.dzoa");
    emit_dzoa(&php, &dll, &required_sample("members"), &handled).unwrap_or_else(
        |diagnosis: String| {
            panic!(
                "the guard must reject only the flags the emitter cannot encode. `members` \
                 carries `(self)`, `(static)` and `(exception)`, which it can, and bare numeric \
                 jump targets, which a later pass resolves; none of those may fail: {diagnosis}"
            )
        },
    );

    let reproduced: PathBuf = scratch.path().join("generators.dzoa");
    emit_dzoa(&php, &dll, &required_sample("generators"), &reproduced)
        .expect("re-emit the tracked generator op array");
    let fresh: Vec<u8> =
        std::fs::read(&reproduced).expect("read the re-emitted generator op array");
    assert_eq!(
        fresh,
        include_bytes!("fixtures/oparray_generator/generators.dzoa"),
        "the guard must not change any op array the emitter already produced, or every tracked \
         fixture and the grades built on them move at once"
    );
}

const MEMBERS_STATIC_STATEMENTS: [&str; 9] = [
    "Ledger::$total += $by;",
    "++Ledger::$total;",
    "--Ledger::$total;",
    "return self::$total;",
    "Ledger::$tag = $suffix;",
    "Ledger::$tag .= '!';",
    "return static::$tag;",
    "$this->bag[$key] += 10;",
    "Ledger::$tag = &$local;",
];

#[test]
fn members_recovers_every_static_member_form_and_refuses_only_its_class_declaration() {
    let graded: &str = "the php 8.4 static property, class constant and member step recovery";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let src: PathBuf = required_sample("members");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_members_recover")
            .expect("create the member recovery scratch directory");
    let dzoa: PathBuf = scratch.path().join("members.dzoa");
    emit_dzoa(&php, &dll, &src, &dzoa).unwrap_or_else(|diag: String| {
        panic!(
            "{graded} is graded only against an op array the php 8.4 compiler produced, so a \
             run that emits none must not report success. Missing prerequisite: an opcache \
             build that honours opt_debug_level, beside the php binary or at \
             DZOA_OPCACHE_DLL.\n{diag}"
        )
    });
    let bytes: Vec<u8> = std::fs::read(&dzoa).expect("read the member op array");
    let parsed: OpArray = parse_oparray(&bytes).expect("parse the member op array");
    let first: Decompilation = decompile_oparray(&parsed);
    let second: Decompilation = decompile_oparray(&parsed);
    assert_eq!(
        first.php_skeleton, second.php_skeleton,
        "members recovered two different sources from one op array"
    );
    let source: &str = &first.php_skeleton;
    let refused: Vec<&str> = first
        .unrecovered
        .iter()
        .map(|entry: &UnrecoveredOp| entry.mnemonic.as_str())
        .collect();
    assert_eq!(
        refused,
        vec!["ZEND_DECLARE_CLASS_DELAYED"],
        "members is pinned to refuse exactly the class declaration this container does not carry; \
         every member access in it must recover\n--- recovered ---\n{source}"
    );
    let mut lost: Vec<&str> = Vec::new();
    let mut restored: usize = 0;
    for statement in MEMBERS_STATIC_STATEMENTS {
        if source.contains(statement) {
            restored += 1;
        } else {
            lost.push(statement);
        }
    }
    assert!(
        lost.is_empty(),
        "{restored}/{} static member statements recovered; these did not: {lost:?}\n--- recovered \
         ---\n{source}",
        MEMBERS_STATIC_STATEMENTS.len()
    );
    assert!(
        !source.contains("Ledger::total"),
        "a static property must keep its sigil, or the recovered source reads a class constant \
         instead\n--- recovered ---\n{source}"
    );
    assert_eq!(
        source.matches("class Ledger").count(),
        1,
        "php fatals on a duplicate class declaration, so every method must land in one class \
         block\n--- recovered ---\n{source}"
    );
}

#[test]
fn optimized_switch_emitter_refuses_schemas_without_table_payloads() {
    let graded: &str = "the PHP 8.4 optimized switch DZOA schema boundary";
    let php: PathBuf = required_php(graded);
    let dll: String = required_opcache(&php, graded);
    let source: PathBuf = required_sample("switch_optimized");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_switch_schema")
            .expect("create switch schema scratch directory");
    for version in [1u8, 2u8] {
        let output: PathBuf = scratch.path().join(format!("switch-v{version}.dzoa"));
        let error: String = emit_dzoa_versioned(&php, &dll, &source, &output, Some(version), None)
            .expect_err("schemas without typed switch literals must be refused");
        assert!(
            !error.contains("no opcache configuration produced"),
            "{graded} is proven only by the emitter refusing schema version {version} for the \
             stated reason. This run failed for a different reason, so it checked no refusal at \
             all and must not report success. Missing prerequisite: an opcache build that honours \
             opt_debug_level, beside the php binary or at DZOA_OPCACHE_DLL.\n{error}"
        );
        assert!(
            error.contains(&format!(
                "DZOA schema version {version} cannot encode SWITCH_"
            )),
            "{error}"
        );
    }
}

#[test]
fn optimized_match_emitter_refuses_schemas_without_table_payloads() {
    let graded: &str = "the PHP 8.4 optimized match DZOA schema boundary";
    let Some(php): Option<PathBuf> = find_php(graded) else {
        return;
    };
    let Some(dll): Option<String> = find_opcache(&php, graded) else {
        return;
    };
    let source: PathBuf = required_sample("match_optimized");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_match_schema")
            .expect("create match schema scratch directory");
    for version in [1u8, 2u8] {
        let output: PathBuf = scratch.path().join(format!("match-v{version}.dzoa"));
        let error: String = emit_dzoa_versioned(&php, &dll, &source, &output, Some(version), None)
            .expect_err("schemas without typed match literals must be refused");
        if error.contains("no opcache configuration produced") {
            unmeasured(&PHP_OPCACHE, graded, &error);
            return;
        }
        assert!(
            error.contains(&format!(
                "DZOA schema version {version} cannot encode SWITCH_"
            )),
            "{error}"
        );
    }
}

const EMITTER_SEND_FAMILY_TARGET: &str = "ZEND_SEND_VAL";

const EMITTER_ASSIGN_OP_TARGET: &str = "ZEND_ASSIGN_OP";

const EMITTER_ASSIGN_OP_BINOPS: [&str; 12] = [
    "ADD", "SUB", "MUL", "DIV", "MOD", "CONCAT", "POW", "SL", "SR", "BW_OR", "BW_AND", "BW_XOR",
];

fn mnemonic_of(line: &str) -> Option<String> {
    let (address, rest): (&str, &str) = line.split_once(' ')?;
    if address.len() != 4 || !address.bytes().all(|byte: u8| byte.is_ascii_digit()) {
        return None;
    }
    let body: &str = rest.trim_start();
    let after_result: &str = match body.split_once(" = ") {
        Some((head, tail)) if !head.contains(' ') => tail.trim_start(),
        _ => body,
    };
    let token: &str = after_result.split_whitespace().next()?;
    if !token
        .bytes()
        .all(|byte: u8| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
    {
        return None;
    }
    Some(token.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum OpcodeBlockId {
    Main,
    Named(String),
    Closure { path: Vec<u32> },
}

fn opcode_block_label(id: &OpcodeBlockId) -> String {
    match id {
        OpcodeBlockId::Main => "$_main".to_owned(),
        OpcodeBlockId::Named(name) => name.clone(),
        OpcodeBlockId::Closure { path } => format!("{{closure}}#{path:?}"),
    }
}

fn opcode_block_name(line: &str) -> Option<&str> {
    let name: &str = line.strip_suffix(':')?;
    if name.is_empty()
        || (name.len() == 4 && name.bytes().all(|byte: u8| byte.is_ascii_digit()))
        || name.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some(name)
}

fn raw_opcode_block_id(name: &str, closure_ordinal: &mut u32) -> Result<OpcodeBlockId, String> {
    if name == "$_main" {
        return Ok(OpcodeBlockId::Main);
    }
    if name.starts_with("{closure") {
        let ordinal: u32 = *closure_ordinal;
        *closure_ordinal = closure_ordinal
            .checked_add(1)
            .ok_or_else(|| "raw opcache dump has too many closure blocks".to_owned())?;
        return Ok(OpcodeBlockId::Closure {
            path: vec![ordinal],
        });
    }
    Ok(OpcodeBlockId::Named(name.to_owned()))
}

fn flush_raw_opcode_block(
    blocks: &mut BTreeMap<OpcodeBlockId, Vec<String>>,
    id: OpcodeBlockId,
    mnemonics: Vec<String>,
) -> Result<(), String> {
    if mnemonics.is_empty() {
        return Err(format!(
            "raw opcache dump block `{}` is empty",
            opcode_block_label(&id)
        ));
    }
    if blocks.insert(id.clone(), mnemonics).is_some() {
        return Err(format!(
            "raw opcache dump has duplicate block `{}`",
            opcode_block_label(&id)
        ));
    }
    Ok(())
}

fn raw_opcache_dump_blocks(text: &str) -> Result<BTreeMap<OpcodeBlockId, Vec<String>>, String> {
    let mut current: Option<OpcodeBlockId> = None;
    let mut mnemonics: Vec<String> = Vec::new();
    let mut blocks: BTreeMap<OpcodeBlockId, Vec<String>> = BTreeMap::new();
    let mut closure_ordinal: u32 = 0;
    for raw in text.lines() {
        let line: &str = raw.trim_end();
        if line.starts_with("LIVE RANGES") || line.starts_with("EXCEPTION TABLE") {
            continue;
        }
        if let Some(name) = opcode_block_name(line) {
            let next: OpcodeBlockId = raw_opcode_block_id(name, &mut closure_ordinal)?;
            if let Some(previous) = current.replace(next) {
                flush_raw_opcode_block(&mut blocks, previous, std::mem::take(&mut mnemonics))?;
            }
            continue;
        }
        if current.is_none() {
            continue;
        }
        if let Some(mnemonic) = mnemonic_of(line.trim()) {
            mnemonics.push(mnemonic);
        }
    }
    let Some(name) = current else {
        return Err("raw opcache dump has no named blocks".to_owned());
    };
    flush_raw_opcode_block(&mut blocks, name, mnemonics)?;
    if !blocks.contains_key(&OpcodeBlockId::Main) {
        return Err("raw opcache dump has no $_main block".to_owned());
    }
    Ok(blocks)
}

fn expected_zend_name(mnemonic: &str) -> String {
    if mnemonic.starts_with("SEND_") {
        return EMITTER_SEND_FAMILY_TARGET.to_owned();
    }
    if mnemonic == "FAST_CONCAT" {
        return "ZEND_CONCAT".to_owned();
    }
    if let Some(rest) = mnemonic.strip_prefix("ASSIGN_")
        && EMITTER_ASSIGN_OP_BINOPS.contains(&rest)
    {
        return EMITTER_ASSIGN_OP_TARGET.to_owned();
    }
    format!("ZEND_{mnemonic}")
}

fn parsed_opcode_blocks(array: &OpArray) -> Result<BTreeMap<OpcodeBlockId, Vec<String>>, String> {
    fn collect(
        array: &OpArray,
        blocks: &mut BTreeMap<OpcodeBlockId, Vec<String>>,
        id: OpcodeBlockId,
        closure_ordinal: &mut u32,
    ) -> Result<(), String> {
        let mnemonics: Vec<String> = array
            .ops
            .iter()
            .map(|op: &Op| opcode_name(op.opcode).to_owned())
            .collect();
        if mnemonics.is_empty() {
            return Err(format!("DZOA block `{}` is empty", opcode_block_label(&id)));
        }
        if blocks.insert(id.clone(), mnemonics).is_some() {
            return Err(format!(
                "DZOA has duplicate block `{}`",
                opcode_block_label(&id)
            ));
        }
        for child in &array.children {
            let child_id: OpcodeBlockId = match (&child.class_name, &child.name) {
                (Some(class_name), Some(name)) => {
                    OpcodeBlockId::Named(format!("{class_name}::{name}"))
                }
                (None, Some(name)) => OpcodeBlockId::Named(name.clone()),
                (None, None) => {
                    let ordinal: u32 = *closure_ordinal;
                    *closure_ordinal = closure_ordinal
                        .checked_add(1)
                        .ok_or_else(|| "DZOA has too many closure blocks".to_owned())?;
                    OpcodeBlockId::Closure {
                        path: vec![ordinal],
                    }
                }
                (Some(_), None) => {
                    return Err("DZOA contains a method block without a method name".to_owned());
                }
            };
            collect(child, blocks, child_id, closure_ordinal)?;
        }
        Ok(())
    }

    let mut blocks: BTreeMap<OpcodeBlockId, Vec<String>> = BTreeMap::new();
    let mut closure_ordinal: u32 = 0;
    collect(
        array,
        &mut blocks,
        OpcodeBlockId::Main,
        &mut closure_ordinal,
    )?;
    Ok(blocks)
}

fn expected_opcode_blocks(
    raw: &BTreeMap<OpcodeBlockId, Vec<String>>,
) -> BTreeMap<OpcodeBlockId, Vec<String>> {
    raw.iter()
        .map(|(id, mnemonics): (&OpcodeBlockId, &Vec<String>)| {
            let expected: Vec<String> = mnemonics
                .iter()
                .map(|mnemonic: &String| expected_zend_name(mnemonic))
                .collect();
            (id.clone(), expected)
        })
        .collect()
}

fn require_closure_opcode_blocks(
    raw: &BTreeMap<OpcodeBlockId, Vec<String>>,
    parsed: &BTreeMap<OpcodeBlockId, Vec<String>>,
) -> Result<(), String> {
    for ordinal in [0u32, 1] {
        let id: OpcodeBlockId = OpcodeBlockId::Closure {
            path: vec![ordinal],
        };
        if !raw.contains_key(&id) {
            return Err(format!(
                "raw opcache dump is missing required closure path [{ordinal}]"
            ));
        }
        if !parsed.contains_key(&id) {
            return Err(format!("DZOA is missing required closure path [{ordinal}]"));
        }
    }
    Ok(())
}

fn compare_opcode_blocks(
    raw: &BTreeMap<OpcodeBlockId, Vec<String>>,
    parsed: &BTreeMap<OpcodeBlockId, Vec<String>>,
    sample: &str,
) -> Result<(), String> {
    let expected: BTreeMap<OpcodeBlockId, Vec<String>> = expected_opcode_blocks(raw);
    for id in expected.keys() {
        if !parsed.contains_key(id) {
            return Err(format!(
                "{sample}: raw opcache dump block `{}` has no matching DZOA block",
                opcode_block_label(id)
            ));
        }
    }
    for id in parsed.keys() {
        if !expected.contains_key(id) {
            return Err(format!(
                "{sample}: DZOA block `{}` is absent from the raw opcache dump",
                opcode_block_label(id)
            ));
        }
    }
    for (id, expected_mnemonics) in &expected {
        let Some(parsed_mnemonics): Option<&Vec<String>> = parsed.get(id) else {
            return Err(format!(
                "{sample}: DZOA block `{}` is absent",
                opcode_block_label(id)
            ));
        };
        if parsed_mnemonics.len() != expected_mnemonics.len() {
            return Err(format!(
                "{sample}: block `{}` has {} raw opcache dump opcodes but {} DZOA opcodes; raw={expected_mnemonics:?}; dzoa={parsed_mnemonics:?}",
                opcode_block_label(id),
                expected_mnemonics.len(),
                parsed_mnemonics.len()
            ));
        }
        if parsed_mnemonics != expected_mnemonics {
            return Err(format!(
                "{sample}: block `{}` differs; raw={expected_mnemonics:?}; dzoa={parsed_mnemonics:?}",
                opcode_block_label(id)
            ));
        }
    }
    Ok(())
}

fn opcode_naming_agrees_with_real_php(sample: &str) {
    let graded: String =
        format!("the {sample} op_array opcode names against the mnemonics real php prints");
    let Some(php): Option<PathBuf> = find_php(&graded) else {
        return;
    };
    let Some(dll): Option<String> = find_opcache(&php, &graded) else {
        return;
    };
    let src: PathBuf = required_sample(sample);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_oparray_mnemonics")
            .expect("mkdir mnemonic scratch");
    let dzoa: PathBuf = scratch.path().join(format!("{sample}.dzoa"));
    let dump: PathBuf = scratch.path().join(format!("{sample}.opcache"));
    if let Err(diag) = emit_dzoa_with_dump(&php, &dll, &src, &dzoa, &dump) {
        unmeasured(
            &PHP_OPCACHE,
            &graded,
            &format!(
                "this php and opcache build emits no op_array dump for {sample}\n{diag}\n\n{}",
                environment_diagnostics(&php)
            ),
        );
        return;
    }
    let text: String = std::fs::read_to_string(&dump).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the selected emitter run did not leave its raw opcache dump at {}: {error}",
            dump.display()
        )
    });
    let reference: BTreeMap<OpcodeBlockId, Vec<String>> = raw_opcache_dump_blocks(&text)
        .unwrap_or_else(|error: String| {
            panic!("the raw opcache dump for {sample} is invalid: {error}\n{text}")
        });

    let bytes: Vec<u8> = std::fs::read(&dzoa).expect("read dzoa");
    let parsed: OpArray = parse_oparray(&bytes).expect("disrobe parse real op_array");
    let ours: BTreeMap<OpcodeBlockId, Vec<String>> =
        parsed_opcode_blocks(&parsed).unwrap_or_else(|error: String| {
            panic!("DZOA for {sample} has invalid block names: {error}")
        });
    if sample == "closures" {
        require_closure_opcode_blocks(&reference, &ours)
            .unwrap_or_else(|error: String| panic!("closure opcode differential failed: {error}"));
    }
    compare_opcode_blocks(&reference, &ours, sample)
        .unwrap_or_else(|error: String| panic!("opcode differential failed: {error}"));

    let raw_count: usize = reference.values().map(Vec::len).sum();
    let passthrough: usize = reference
        .values()
        .flatten()
        .filter(|mnemonic: &&String| expected_zend_name(mnemonic) == format!("ZEND_{mnemonic}"))
        .count();
    assert!(
        passthrough * 2 > raw_count,
        "{sample}: {passthrough} of {raw_count} opcodes survive the emitter unrenamed. Below half, the \
         comparison is mostly checking the rename table rather than the opcode names",
    );
}

#[test]
fn opcode_names_are_the_mnemonics_real_php_prints() {
    for sample in OPCODE_NAMING_SAMPLES {
        opcode_naming_agrees_with_real_php(sample);
    }
}

#[test]
fn the_mnemonic_reader_takes_the_opcode_and_not_the_result_slot() {
    assert_eq!(
        mnemonic_of("0000 ASSIGN CV0($a) int(6)").as_deref(),
        Some("ASSIGN")
    );
    assert_eq!(
        mnemonic_of("0002 T11 = ADD CV0($a) CV1($b)").as_deref(),
        Some("ADD")
    );
    assert_eq!(mnemonic_of("  ; (lines=39, args=0)"), None);
    assert_eq!(mnemonic_of("LIVE RANGES (1):"), None);
    assert_eq!(mnemonic_of("\")"), None);
    assert_eq!(
        expected_zend_name("SEND_VAR"),
        EMITTER_SEND_FAMILY_TARGET,
        "the emitter folds the whole SEND family into one opcode, so the comparison must expect \
         that rather than report a mismatch the container cannot carry"
    );
    assert_eq!(expected_zend_name("ASSIGN_ADD"), EMITTER_ASSIGN_OP_TARGET);
    assert_eq!(expected_zend_name("ASSIGN_DIM"), "ZEND_ASSIGN_DIM");
    assert_eq!(expected_zend_name("ECHO"), "ZEND_ECHO");
}

#[test]
fn opcode_dump_blocks_keep_main_and_named_function_mnemonics_in_order() {
    let text: &str = "$_main:\n0000 INIT_FCALL 2 112 string(\"add\")\n0001 SEND_VAL int(40) 1\n0002 DO_UCALL\n\nadd:\n; (lines=3, args=2)\n0000 RECV 1\n0001 T2 = ADD CV0($a) CV1($b)\n0002 RETURN T2\n";
    let blocks: BTreeMap<OpcodeBlockId, Vec<String>> =
        raw_opcache_dump_blocks(text).expect("parse blocks");
    assert_eq!(
        blocks.get(&OpcodeBlockId::Main),
        Some(&vec![
            "INIT_FCALL".to_owned(),
            "SEND_VAL".to_owned(),
            "DO_UCALL".to_owned(),
        ])
    );
    assert_eq!(
        blocks.get(&OpcodeBlockId::Named("add".to_owned())),
        Some(&vec![
            "RECV".to_owned(),
            "ADD".to_owned(),
            "RETURN".to_owned()
        ])
    );
}

#[test]
fn opcode_dump_blocks_reject_missing_empty_and_duplicate_names() {
    let missing: Result<BTreeMap<OpcodeBlockId, Vec<String>>, String> =
        raw_opcache_dump_blocks("add:\n0000 RETURN int(1)\n");
    assert!(
        missing
            .expect_err("missing main must fail")
            .contains("$_main")
    );
    let empty: Result<BTreeMap<OpcodeBlockId, Vec<String>>, String> =
        raw_opcache_dump_blocks("$_main:\n\nadd:\n0000 RETURN int(1)\n");
    assert!(empty.expect_err("empty block must fail").contains("empty"));
    let duplicate: Result<BTreeMap<OpcodeBlockId, Vec<String>>, String> =
        raw_opcache_dump_blocks("$_main:\n0000 RETURN int(1)\n\n$_main:\n0000 RETURN int(2)\n");
    assert!(
        duplicate
            .expect_err("duplicate block must fail")
            .contains("duplicate")
    );
}

#[test]
fn opcode_dump_blocks_ignore_live_ranges_between_named_blocks() {
    let blocks: BTreeMap<OpcodeBlockId, Vec<String>> = raw_opcache_dump_blocks(
        "$_main:\n0000 RETURN int(1)\nLIVE RANGES:\n     4: 0000 - 0000 (tmp/var)\n\nadd:\n0000 RETURN int(2)\n",
    )
    .expect("live ranges are not blocks");
    assert_eq!(blocks.len(), 2);
    assert_eq!(
        blocks.get(&OpcodeBlockId::Main),
        Some(&vec!["RETURN".to_owned()])
    );
    assert_eq!(
        blocks.get(&OpcodeBlockId::Named("add".to_owned())),
        Some(&vec!["RETURN".to_owned()])
    );
}

#[test]
fn opcode_dump_headers_match_the_php_producer_grammar() {
    assert_eq!(opcode_block_name("$_main:"), Some("$_main"));
    assert_eq!(opcode_block_name("Worker::run:"), Some("Worker::run"));
    assert_eq!(opcode_block_name("0000:"), None);
    assert_eq!(opcode_block_name("JIT tracing header:"), None);
    let blocks: BTreeMap<OpcodeBlockId, Vec<String>> =
        raw_opcache_dump_blocks("$_main:\n0000 RETURN int(1)\n  add:\n0001 RETURN int(2)\n")
            .expect("indented heading is not a block");
    assert!(!blocks.contains_key(&OpcodeBlockId::Named("add".to_owned())));
}

#[test]
fn opcode_block_comparison_rejects_unknown_missing_and_wrong_mnemonics() {
    let raw: BTreeMap<OpcodeBlockId, Vec<String>> = BTreeMap::from([
        (OpcodeBlockId::Main, vec!["ECHO".to_owned()]),
        (
            OpcodeBlockId::Named("add".to_owned()),
            vec!["RETURN".to_owned()],
        ),
    ]);
    let unknown: BTreeMap<OpcodeBlockId, Vec<String>> = BTreeMap::from([
        (OpcodeBlockId::Main, vec!["ZEND_ECHO".to_owned()]),
        (
            OpcodeBlockId::Named("other".to_owned()),
            vec!["ZEND_RETURN".to_owned()],
        ),
    ]);
    assert!(
        compare_opcode_blocks(&raw, &unknown, "fixture")
            .expect_err("unknown raw block must fail")
            .contains("matching DZOA")
    );
    let missing: BTreeMap<OpcodeBlockId, Vec<String>> = BTreeMap::from([
        (OpcodeBlockId::Main, vec!["ZEND_ECHO".to_owned()]),
        (
            OpcodeBlockId::Named("add".to_owned()),
            vec!["ZEND_RETURN".to_owned()],
        ),
        (
            OpcodeBlockId::Named("extra".to_owned()),
            vec!["ZEND_RETURN".to_owned()],
        ),
    ]);
    assert!(
        compare_opcode_blocks(&raw, &missing, "fixture")
            .expect_err("missing raw block must fail")
            .contains("absent from the raw opcache dump")
    );
    let wrong: BTreeMap<OpcodeBlockId, Vec<String>> = BTreeMap::from([
        (OpcodeBlockId::Main, vec!["ZEND_PRINT".to_owned()]),
        (
            OpcodeBlockId::Named("add".to_owned()),
            vec!["ZEND_RETURN".to_owned()],
        ),
    ]);
    assert!(
        compare_opcode_blocks(&raw, &wrong, "fixture")
            .expect_err("wrong mnemonic must fail")
            .contains("differs")
    );
}

#[test]
fn raw_opcache_dump_closures_receive_stable_ordinals() {
    let blocks: BTreeMap<OpcodeBlockId, Vec<String>> = raw_opcache_dump_blocks(
        "$_main:\n0000 DECLARE_LAMBDA_FUNCTION 0\n\n{closure}:\n0000 RECV 1\n0001 RETURN CV0($value)\n\n{closure}:\n0000 RECV 1\n0001 RETURN CV0($value)\n",
    )
    .expect("parse closure blocks");
    assert!(blocks.contains_key(&OpcodeBlockId::Main));
    assert!(blocks.contains_key(&OpcodeBlockId::Closure { path: vec![0] }));
    assert!(blocks.contains_key(&OpcodeBlockId::Closure { path: vec![1] }));
}

#[test]
fn supplied_opcache_path_wins_over_php_sibling_discovery() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_oparray_explicit_opcache")
            .expect("create explicit opcache scratch");
    let php: PathBuf = scratch.path().join("php-bin").join("php");
    let supplied: PathBuf = scratch.path().join("provided").join(".").join("opcache.so");
    std::fs::create_dir_all(supplied.parent().expect("provided parent"))
        .expect("create supplied parent");
    std::fs::write(&supplied, b"provided opcache").expect("write supplied opcache");
    let expected: PathBuf = supplied
        .canonicalize()
        .expect("canonicalize supplied opcache");
    let actual: String = opcache_dll_with_explicit(&php, Some(supplied.into_os_string()))
        .expect("use supplied opcache");
    assert!(
        !actual.starts_with(WINDOWS_VERBATIM_PREFIX),
        "php rejects a zend_extension path in the windows verbatim form, so a resolver that hands \
         one back silently disarms every opcache-backed grader: {actual}"
    );
    assert!(
        !actual.contains(r"\.\") && !actual.contains("/./"),
        "the resolved opcache path still carries an unnormalised component: {actual}"
    );
    assert_eq!(
        PathBuf::from(&actual)
            .canonicalize()
            .expect("resolved opcache path must still name the supplied file"),
        expected
    );
}

#[test]
fn nonexistent_supplied_opcache_path_does_not_fall_back_to_php_sibling() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_oparray_missing_opcache")
            .expect("create missing opcache scratch");
    let php: PathBuf = scratch.path().join("php-bin").join("php");
    let sibling: PathBuf = scratch
        .path()
        .join("php-bin")
        .join("ext")
        .join("opcache.so");
    std::fs::create_dir_all(sibling.parent().expect("sibling parent"))
        .expect("create sibling parent");
    std::fs::write(&sibling, b"sibling opcache").expect("write sibling opcache");
    let missing: PathBuf = scratch.path().join("missing").join("opcache.so");
    assert!(opcache_dll_with_explicit(&php, Some(missing.into_os_string())).is_none());
}

#[test]
fn emitter_rejects_identical_and_aliased_output_paths() {
    let graded: &str = "the raw opcache dump output path check";
    let Some(php): Option<PathBuf> = find_php(graded) else {
        return;
    };
    let Some(dll): Option<String> = find_opcache(&php, graded) else {
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_oparray_output_paths")
            .expect("create output-path scratch");
    let src: PathBuf = required_sample("arithmetic");
    let same: PathBuf = scratch.path().join("same.dzoa");
    let same_error: String = emit_dzoa_with_dump(&php, &dll, &src, &same, &same)
        .expect_err("identical output paths must fail");
    assert!(same_error.contains("raw opcache dump"));
    let alias: PathBuf = scratch.path().join(".").join("same.dzoa");
    let alias_error: String = emit_dzoa_with_dump(&php, &dll, &src, &same, &alias)
        .expect_err("aliased output paths must fail");
    assert!(alias_error.contains("raw opcache dump"));
}

#[test]
fn emitter_rejects_hard_linked_output_paths() {
    let graded: &str = "the raw opcache dump hard-link output path check";
    let Some(php): Option<PathBuf> = find_php(graded) else {
        return;
    };
    let Some(dll): Option<String> = find_opcache(&php, graded) else {
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_oparray_hard_links")
            .expect("create hard-link scratch");
    let src: PathBuf = required_sample("arithmetic");
    let dzoa: PathBuf = scratch.path().join("same.dzoa");
    let dump: PathBuf = scratch.path().join("same.opcache");
    std::fs::write(&dzoa, b"seed").expect("create DZOA hard-link source");
    std::fs::hard_link(&dzoa, &dump).expect("create hard-linked raw opcache dump path");
    let error: String = emit_dzoa_with_dump(&php, &dll, &src, &dzoa, &dump)
        .expect_err("hard-linked output paths must fail");
    assert!(error.contains("raw opcache dump"));
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[test]
fn emitter_rejects_dangling_raw_opcache_dump_symlink() {
    let graded: &str = "the raw opcache dump dangling symlink output path check";
    let Some(php): Option<PathBuf> = find_php(graded) else {
        return;
    };
    let Some(dll): Option<String> = find_opcache(&php, graded) else {
        return;
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_oparray_dangling_symlink")
            .expect("create dangling-symlink scratch");
    let src: PathBuf = required_sample("arithmetic");
    let dzoa: PathBuf = scratch.path().join("out.dzoa");
    let dump: PathBuf = scratch.path().join("out.dump");
    create_file_symlink(&dzoa, &dump).expect("create dangling raw opcache dump symlink");
    let error: String = emit_dzoa_with_dump(&php, &dll, &src, &dzoa, &dump)
        .expect_err("dangling raw opcache dump symlink must fail");
    assert!(error.contains("raw opcache dump"));
    assert!(!dzoa.exists());
}

#[test]
fn closure_opcode_blocks_require_each_raw_and_dzoa_ordinal() {
    let raw: BTreeMap<OpcodeBlockId, Vec<String>> = BTreeMap::from([
        (
            OpcodeBlockId::Main,
            vec!["DECLARE_LAMBDA_FUNCTION".to_owned()],
        ),
        (
            OpcodeBlockId::Closure { path: vec![0] },
            vec!["RETURN".to_owned()],
        ),
        (
            OpcodeBlockId::Closure { path: vec![1] },
            vec!["RETURN".to_owned()],
        ),
    ]);
    let parsed: BTreeMap<OpcodeBlockId, Vec<String>> = BTreeMap::from([
        (
            OpcodeBlockId::Main,
            vec!["ZEND_DECLARE_LAMBDA_FUNCTION".to_owned()],
        ),
        (
            OpcodeBlockId::Closure { path: vec![0] },
            vec!["ZEND_RETURN".to_owned()],
        ),
    ]);
    assert!(
        require_closure_opcode_blocks(&raw, &parsed)
            .expect_err("missing closure ordinal must fail")
            .contains("path [1]")
    );
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
    let emitted: Result<(), String> =
        emit_dzoa_versioned(&php, &dll, &src, &dzoa, force_version, None);
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
