#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_binfmt::chain_detector::{CONTAINER_PASS, ContainerDetector};
use disrobe_binfmt::containers::{DenoCompileLayout, DenoCompilePayload, parse_deno_compile};
use disrobe_core::chain::{ChildArtifact, DetectContext, DetectVerdict, Detector as _, Pass as _};
use disrobe_core::{Artifact, Rung};
use sha2::{Digest as _, Sha256};

const DENO_VAR: &str = "DISROBE_DENO";

const MAIN_JS: &[u8] = include_bytes!("../../../corpus/javascript/deno/app/main.js");
const GREET_JS: &[u8] = include_bytes!("../../../corpus/javascript/deno/app/lib/greet.js");
const MATH_TS: &[u8] = include_bytes!("../../../corpus/javascript/deno/app/lib/math.ts");
const NAMES_JSON: &[u8] = include_bytes!("../../../corpus/javascript/deno/app/lib/names.json");
const MATH_EMIT_1_46: &[u8] =
    include_bytes!("../../../corpus/javascript/deno/expected/deno-1.46.3-emit-math.ts.js");
const PAYLOAD_2_9: &[u8] = include_bytes!(
    "../../../corpus/javascript/deno/compiled/deno-2.9.7-x86_64-pc-windows-msvc.payload"
);
const PAYLOAD_1_46: &[u8] = include_bytes!(
    "../../../corpus/javascript/deno/compiled/deno-1.46.3-x86_64-pc-windows-msvc.payload"
);
const ESZIP_1_46: &[u8] =
    include_bytes!("../../../corpus/javascript/deno/compiled/deno-1.46.3.eszip");

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug)]
struct Reference {
    path: &'static str,
    sha256: String,
}

fn reference(path: &'static str, bytes: &[u8]) -> Reference {
    Reference {
        path,
        sha256: hex_sha256(bytes),
    }
}

fn authored_sources() -> Vec<Reference> {
    vec![
        reference("main.js", MAIN_JS),
        reference("lib/greet.js", GREET_JS),
        reference("lib/math.ts", MATH_TS),
        reference("lib/names.json", NAMES_JSON),
    ]
}

fn chain_members(bytes: &[u8], expected_tag: &str) -> BTreeMap<String, Vec<u8>> {
    let ctx: DetectContext<'_> = DetectContext {
        bytes,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let verdict: DetectVerdict = ContainerDetector
        .detect(&ctx)
        .expect("the container detector must tag the input");
    assert_eq!(verdict.format_tag, expected_tag);
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
    let children: Vec<ChildArtifact> = CONTAINER_PASS
        .extract_children(&artifact)
        .expect("the container pass must extract the modules");
    let mut members: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for child in children {
        let previous: Option<Vec<u8>> =
            members.insert(child.handle.relative_path.clone(), child.bytes);
        assert!(
            previous.is_none(),
            "duplicate member {}",
            child.handle.relative_path
        );
    }
    members
}

fn grade(members: &BTreeMap<String, Vec<u8>>, references: &[Reference]) -> Result<(), String> {
    let mut problems: Vec<String> = Vec::new();
    for expected in references {
        match members.get(expected.path) {
            None => problems.push(format!("{} is missing", expected.path)),
            Some(bytes) if hex_sha256(bytes) != expected.sha256 => problems.push(format!(
                "{} has sha256 {} but the reference is {}",
                expected.path,
                hex_sha256(bytes),
                expected.sha256
            )),
            Some(_) => {}
        }
    }
    for path in members.keys() {
        if !references
            .iter()
            .any(|expected: &Reference| expected.path == path)
        {
            problems.push(format!("{path} is not a module of the authored program"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

fn source_map_original(map: &[u8]) -> Vec<u8> {
    let parsed: serde_json::Value = serde_json::from_slice(map).expect("source map is JSON");
    let contents: &Vec<serde_json::Value> = parsed["sourcesContent"]
        .as_array()
        .expect("source map carries sourcesContent");
    assert_eq!(contents.len(), 1);
    contents[0]
        .as_str()
        .expect("sourcesContent entry is a string")
        .as_bytes()
        .to_vec()
}

fn grade_eszip_modules(mut members: BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    let map: Vec<u8> = members
        .remove("app/lib/math.ts.map")
        .ok_or_else(|| "app/lib/math.ts.map is missing".to_owned())?;
    if hex_sha256(&source_map_original(&map)) != hex_sha256(MATH_TS) {
        return Err("the math.ts source map does not carry the authored TypeScript".to_owned());
    }
    let references: [Reference; 4] = [
        reference("app/main.js", MAIN_JS),
        reference("app/lib/greet.js", GREET_JS),
        reference("app/lib/math.ts", MATH_EMIT_1_46),
        reference("app/lib/names.json", NAMES_JSON),
    ];
    grade(&members, &references)
}

#[test]
fn a_deno_2_payload_yields_every_authored_module_through_the_chain() {
    let payload: DenoCompilePayload = parse_deno_compile(PAYLOAD_2_9).expect("parse payload");
    assert_eq!(payload.layout, DenoCompileLayout::ModuleStore);
    assert_eq!(payload.base_offset, 0);
    assert_eq!(payload.len, PAYLOAD_2_9.len());
    assert_eq!(payload.entrypoint, "main.js");
    let members: BTreeMap<String, Vec<u8>> = chain_members(PAYLOAD_2_9, "deno-compile");
    grade(&members, &authored_sources()).unwrap_or_else(|problems: String| panic!("{problems}"));

    let artifact: Artifact = Artifact::new(Rung::Raw, PAYLOAD_2_9.to_vec(), [0u8; 32]);
    let manifest: Artifact = CONTAINER_PASS.run(&artifact).expect("container manifest");
    let text: &str = std::str::from_utf8(manifest.envelope.as_slice()).expect("utf8 manifest");
    assert!(text.contains("format=deno-compile"), "{text}");
    assert!(text.contains("entries=4 listing=read-only"), "{text}");
    assert!(text.contains("lib/math.ts	bytes=166"), "{text}");
    assert!(
        CONTAINER_PASS
            .chain_refusals(&artifact)
            .expect("refusals")
            .is_empty()
    );
}

#[test]
fn a_deno_1_payload_with_npm_packages_records_that_they_were_not_read() {
    let mut mutated: Vec<u8> = PAYLOAD_1_46.to_vec();
    let npm_directory: usize = mutated.len() - 4;
    assert_eq!(&mutated[npm_directory..], b"null");
    mutated[npm_directory..].copy_from_slice(b"[{}]");
    let payload: DenoCompilePayload = parse_deno_compile(&mutated).expect("parse payload");
    assert!(payload.unread_npm_files);
    let artifact: Artifact = Artifact::new(Rung::Raw, mutated, [0u8; 32]);
    let refusals: Vec<String> = CONTAINER_PASS.chain_refusals(&artifact).expect("refusals");
    assert_eq!(refusals.len(), 1);
    assert!(
        refusals[0].contains("npm package directory"),
        "{refusals:?}"
    );
}

#[test]
fn a_deno_1_payload_yields_its_eszip_modules_through_the_chain() {
    let payload: DenoCompilePayload = parse_deno_compile(PAYLOAD_1_46).expect("parse payload");
    assert_eq!(payload.layout, DenoCompileLayout::EszipTrailer);
    assert_eq!(payload.entrypoint, "app/main.js");
    assert!(!payload.unread_npm_files);
    let members: BTreeMap<String, Vec<u8>> = chain_members(PAYLOAD_1_46, "deno-compile");
    grade_eszip_modules(members).unwrap_or_else(|problems: String| panic!("{problems}"));
}

#[test]
fn a_bare_eszip_yields_every_module_through_the_chain() {
    let members: BTreeMap<String, Vec<u8>> = chain_members(ESZIP_1_46, "eszip");
    grade_eszip_modules(members).unwrap_or_else(|problems: String| panic!("{problems}"));
}

fn flip_first_byte_of(bytes: &[u8], needle: &[u8]) -> Vec<u8> {
    let at: usize = bytes
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
        .expect("the embedded source is present");
    let mut mutated: Vec<u8> = bytes.to_vec();
    mutated[at] ^= 0x20;
    mutated
}

#[test]
fn the_grade_turns_red_when_one_embedded_source_byte_changes() {
    let mutated: Vec<u8> = flip_first_byte_of(PAYLOAD_2_9, GREET_JS);
    let members: BTreeMap<String, Vec<u8>> = chain_members(&mutated, "deno-compile");
    let verdict: Result<(), String> = grade(&members, &authored_sources());
    let problems: String = verdict.expect_err("a changed greet.js byte must fail the grade");
    assert!(problems.contains("lib/greet.js has sha256"), "{problems}");

    let mutated: Vec<u8> = flip_first_byte_of(ESZIP_1_46, MAIN_JS);
    let members: BTreeMap<String, Vec<u8>> = chain_members(&mutated, "eszip");
    let problems: String =
        grade_eszip_modules(members).expect_err("a changed main.js byte must fail the grade");
    assert!(problems.contains("app/main.js has sha256"), "{problems}");

    let mutated: Vec<u8> =
        flip_first_byte_of(ESZIP_1_46, b"export function checksum(text: string)");
    let members: BTreeMap<String, Vec<u8>> = chain_members(&mutated, "eszip");
    let problems: String = grade_eszip_modules(members)
        .expect_err("a changed byte of the embedded TypeScript must fail the grade");
    assert!(
        problems.contains("does not carry the authored TypeScript"),
        "{problems}"
    );
}

#[test]
fn the_grade_turns_red_when_a_module_is_missing_or_extra() {
    let mut members: BTreeMap<String, Vec<u8>> = chain_members(PAYLOAD_2_9, "deno-compile");
    members.remove("lib/names.json");
    members.insert("lib/extra.js".to_owned(), Vec::new());
    let problems: String =
        grade(&members, &authored_sources()).expect_err("a changed member set must fail");
    assert!(problems.contains("lib/names.json is missing"), "{problems}");
    assert!(
        problems.contains("lib/extra.js is not a module"),
        "{problems}"
    );
}

fn required_deno() -> (PathBuf, PathBuf) {
    let Some(value) = std::env::var_os(DENO_VAR) else {
        panic!(
            "{DENO_VAR} is not set: point it at a Deno 2.x `deno` executable whose directory also \
             holds the matching `denort` runtime, both from the Deno 2.9.7 GitHub release"
        );
    };
    let deno: PathBuf = PathBuf::from(value);
    assert!(
        deno.is_file(),
        "{DENO_VAR}={} does not name a file",
        deno.display()
    );
    let directory: &Path = deno.parent().expect("deno has a parent directory");
    let runtime_name: &str = if cfg!(windows) {
        "denort.exe"
    } else {
        "denort"
    };
    let denort: PathBuf = directory.join(runtime_name);
    assert!(
        denort.is_file(),
        "{DENO_VAR} names {} but {} is missing beside it, and deno compile would download it",
        deno.display(),
        denort.display()
    );
    (deno, denort)
}

fn write_program(root: &Path) {
    std::fs::create_dir_all(root.join("lib")).expect("create program directory");
    let files: [(&str, &[u8]); 4] = [
        ("main.js", MAIN_JS),
        ("lib/greet.js", GREET_JS),
        ("lib/math.ts", MATH_TS),
        ("lib/names.json", NAMES_JSON),
    ];
    for (path, bytes) in files {
        std::fs::write(root.join(path), bytes).expect("write program source");
    }
}

#[test]
fn a_fresh_deno_compile_binary_yields_every_authored_module_through_the_chain() {
    let (deno, denort): (PathBuf, PathBuf) = required_deno();
    let work: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR")).join("deno_compile");
    if work.exists() {
        std::fs::remove_dir_all(&work).expect("clear previous deno work directory");
    }
    let program: PathBuf = work.join("app");
    write_program(&program);
    let output_stem: PathBuf = work.join("out").join("app");
    let output: Output = Command::new(&deno)
        .args(["compile", "--no-check", "--output"])
        .arg(&output_stem)
        .arg("./main.js")
        .current_dir(&program)
        .env("DENO_DIR", work.join("deno_dir"))
        .env("DENORT_BIN", &denort)
        .env("DENO_NO_UPDATE_CHECK", "1")
        .env("NO_COLOR", "1")
        .env_remove("FORCE_COLOR")
        .output()
        .expect("run deno compile");
    assert!(
        output.status.success(),
        "deno compile failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let binary_path: PathBuf = if cfg!(windows) {
        output_stem.with_extension("exe")
    } else {
        output_stem
    };
    let binary: Vec<u8> = std::fs::read(&binary_path).expect("read compiled binary");
    std::fs::remove_dir_all(&work).expect("remove deno work directory");

    let payload: DenoCompilePayload = parse_deno_compile(&binary).expect("parse compiled binary");
    assert_eq!(
        payload.layout,
        DenoCompileLayout::ModuleStore,
        "{DENO_VAR} must name a Deno 2.x release"
    );
    assert_eq!(payload.entrypoint, "main.js");
    let members: BTreeMap<String, Vec<u8>> = chain_members(&binary, "deno-compile");
    grade(&members, &authored_sources()).unwrap_or_else(|problems: String| panic!("{problems}"));
}
