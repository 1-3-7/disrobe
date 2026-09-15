#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_pyarmor::{
    BccArch, BccLinkOutput, FunctionRecord, UnpackOptions, UnpackOutput, link_bcc_from_unpack,
    unpack_wrapper_text_with_options,
};

fn corpus_dir() -> PathBuf {
    let dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory must have a crates parent")
        .parent()
        .expect("workspace directory must have a parent")
        .join("corpus/python/pyarmor/v9-bcc/default");
    assert!(
        dir.join("known_plaintext.py").is_file(),
        "tracked BCC corpus must be available at {}",
        dir.display()
    );
    dir
}

fn python() -> Option<String> {
    for candidate in ["python", "python3", "py"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
        {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn link_corpus(dir: &Path) -> BccLinkOutput {
    let (unpacked, wrapper_text, wrapper_path): (UnpackOutput, String, PathBuf) =
        unpack_corpus(dir);
    link_bcc_from_unpack(&unpacked, &wrapper_text, &wrapper_path).expect("link")
}

fn unpack_corpus(dir: &Path) -> (UnpackOutput, String, PathBuf) {
    let wrapper_path: PathBuf = dir.join("known_plaintext.py");
    let wrapper_text: String = std::fs::read_to_string(&wrapper_path).expect("read wrapper");
    let opts: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let unpacked: UnpackOutput =
        unpack_wrapper_text_with_options(&wrapper_text, &wrapper_path, &opts)
            .expect("unpack committed BCC wrapper");
    (unpacked, wrapper_text, wrapper_path)
}

fn record<'a>(output: &'a BccLinkOutput, qualname: &str) -> &'a FunctionRecord {
    output
        .map
        .records
        .iter()
        .find(|r: &&FunctionRecord| r.source.qualname == qualname)
        .unwrap_or_else(|| panic!("missing record for {qualname}"))
}

fn def_params(recovered: &str) -> Vec<String> {
    let header: &str = recovered.lines().next().unwrap_or_default();
    let inner: &str = header
        .split_once('(')
        .and_then(|(_, rest): (&str, &str)| rest.split_once(')'))
        .map_or("", |(inside, _): (&str, &str)| inside);
    inner
        .split(',')
        .map(|part: &str| part.trim().to_owned())
        .filter(|part: &String| !part.is_empty())
        .collect()
}

#[test]
fn bcc_pass_output_carries_recovered_bodies() {
    let dir: PathBuf = corpus_dir();
    let output: BccLinkOutput = link_corpus(&dir);

    let mix: &FunctionRecord = record(&output, "mix_add");
    let mix_body: &str = mix
        .recovered_body
        .as_deref()
        .expect("mix_add body reconstructed from native code");
    println!("mix_add recovered body:\n{mix_body}");
    let mix_params: Vec<String> = def_params(mix_body);
    assert_eq!(mix_params.len(), 2, "mix_add takes two positional params");
    let expected_mix: String = format!(
        "def mix_add({a}, {b}):\n    return ({a} + {b}) * 3 - ({a} ^ {b})\n",
        a = mix_params[0],
        b = mix_params[1]
    );
    assert_eq!(
        mix_body, expected_mix,
        "mix_add recovers (a + b) * 3 - (a ^ b)"
    );

    let poly: &FunctionRecord = record(&output, "poly");
    let poly_body: &str = poly
        .recovered_body
        .as_deref()
        .expect("poly body reconstructed from native code");
    println!("poly recovered body:\n{poly_body}");
    assert!(
        poly_body.starts_with("def poly("),
        "poly body is a def for poly"
    );
    assert!(
        poly_body.contains("return "),
        "poly body reduces to a return expression"
    );

    let clamp: &FunctionRecord = record(&output, "clamp");
    let clamp_body: &str = clamp
        .recovered_body
        .as_deref()
        .expect("clamp body reconstructed from the guarded native result-local chain");
    println!("clamp recovered body:\n{clamp_body}");
    assert!(
        clamp_body.starts_with("def clamp(")
            && clamp_body.matches("if result").count() == 2
            && clamp_body.contains("result < ")
            && clamp_body.contains("result > ")
            && clamp_body.trim_end().ends_with("return result"),
        "clamp recovers the two-guard result-local shape: {clamp_body}"
    );
    let main: &FunctionRecord = record(&output, "main");
    assert!(
        main.recovered_body.is_none(),
        "main loops and calls helpers; it degrades honestly"
    );

    assert!(
        output.skeleton.contains("@bcc_recovered"),
        "skeleton marks recovered native bodies"
    );
    assert!(
        output.skeleton.contains("@native_wall"),
        "skeleton still marks native functions as a native wall"
    );
    for expected_line in [
        expected_mix.lines().nth(1).unwrap(),
        "def mix_add(",
        "def poly(",
    ] {
        assert!(
            output.skeleton.contains(expected_line.trim_end()),
            "skeleton carries {expected_line:?}\n---\n{}",
            output.skeleton
        );
    }

    let Some(py): Option<String> = python() else {
        eprintln!(
            "no python interpreter; recovered bodies asserted structurally, skipping behavior"
        );
        return;
    };
    behavioral_match(&py, &dir, mix_body, poly_body, clamp_body);
    println!("recovered mix_add, poly, and clamp match the original CPython semantics end-to-end");
}

#[test]
fn unsupported_bcc_architecture_cannot_populate_recovered_body() {
    let dir: PathBuf = corpus_dir();
    let (mut unpacked, wrapper_text, wrapper_path): (UnpackOutput, String, PathBuf) =
        unpack_corpus(&dir);
    let cases: [(BccArch, &str); 2] = [
        (BccArch::DarwinArm64, "darwin-arm64"),
        (BccArch::Other(0xdead), "other"),
    ];
    for (architecture, expected_arch) in cases {
        for blob in &mut unpacked.bcc_blobs {
            blob.architecture = architecture;
        }
        let output: BccLinkOutput = link_bcc_from_unpack(&unpacked, &wrapper_text, &wrapper_path)
            .expect("unsupported BCC architecture must retain the native link");
        let native_records: Vec<&FunctionRecord> = output
            .map
            .records
            .iter()
            .filter(|record: &&FunctionRecord| record.native.is_some())
            .collect();
        assert!(
            !native_records.is_empty(),
            "unsupported BCC architecture must retain native records"
        );
        for record in native_records {
            let native = record
                .native
                .as_ref()
                .expect("filtered record must retain native metadata");
            assert_eq!(native.arch, expected_arch);
            assert!(
                record.recovered_body.is_none(),
                "unsupported {expected_arch} body must not be interpreted as x86-64"
            );
        }
        assert!(
            !output
                .skeleton
                .lines()
                .any(|line: &str| line.trim() == "@bcc_recovered"),
            "unsupported {expected_arch} skeleton must not mark a recovered body"
        );
    }
}

fn behavioral_match(py: &str, dir: &Path, mix_body: &str, poly_body: &str, clamp_body: &str) {
    let reference_dir: PathBuf = dir.parent().expect("corpus parent").to_owned();
    let script: String = format!(
        "import sys, itertools\n\
         sys.path.insert(0, {ref_dir:?})\n\
         import bench_mod_original as ref\n\
         ns = {{}}\n\
         exec({mix:?}, ns)\n\
         exec({poly:?}, ns)\n\
         exec({clamp:?}, ns)\n\
         mix = ns['mix_add']\n\
         poly = ns['poly']\n\
         clamp = ns['clamp']\n\
         vals = [-7, -3, -1, 0, 1, 2, 5, 11, 123, -456, 1000]\n\
         for a, b in itertools.product(vals, repeat=2):\n\
         \x20   if mix(a, b) != ref.mix_add(a, b):\n\
         \x20       print('MIX MISMATCH', a, b); sys.exit(1)\n\
         for x in vals:\n\
         \x20   if poly(x) != ref.poly(x):\n\
         \x20       print('POLY MISMATCH', x); sys.exit(1)\n\
         for a, b, c in itertools.product(vals, repeat=3):\n\
         \x20   if clamp(a, b, c) != ref.clamp(a, b, c):\n\
         \x20       print('CLAMP MISMATCH', a, b, c); sys.exit(1)\n\
         print('OK')\n",
        ref_dir = reference_dir.to_string_lossy(),
        mix = mix_body,
        poly = poly_body,
        clamp = clamp_body,
    );
    let scratch: ScratchDir = ScratchDir::create("pyarmor-bcc-e2e").expect("scratch dir");
    let script_path: PathBuf = scratch.path().join("check.py");
    std::fs::write(&script_path, script).expect("write script");
    let out: std::process::Output = Command::new(py)
        .arg(&script_path)
        .output()
        .expect("run python");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "behavioral equivalence FAILED: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
