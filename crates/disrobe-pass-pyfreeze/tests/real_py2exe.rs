#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_pyfreeze::py2exe::pe::extract_pythonscript_resource;
use disrobe_pass_pyfreeze::py2exe::scriptinfo::{self, PY2EXE_MAGIC_TAG};
use disrobe_pass_pyfreeze::py2exe::{Py2exeExtraction, ScriptInfo, detect_and_extract};
use disrobe_pass_pyfreeze::{Detection, FreezerKind, detect_bytes};
use serde_json::Value;

const BANDS: &[&str] = &[
    "edge_cases_3_6",
    "edge_cases_3_8",
    "edge_cases_3_9",
    "edge_cases_3_10",
    "edge_cases_3_11",
    "edge_cases_3_12",
];

const CPYTHON_DIGEST: &str = r#"
import hashlib, json, marshal, sys, types
resource = open(sys.argv[1], "rb").read()
script = open(sys.argv[2], "rb").read()
loaded = marshal.loads(script)
codes = loaded if isinstance(loaded, list) else [loaded]
json.dump({
    "size": len(resource),
    "sha256": hashlib.sha256(resource).hexdigest(),
    "script_data_sha256": hashlib.sha256(script).hexdigest(),
    "marshal_loads": {
        "python": "%d.%d" % sys.version_info[:2],
        "type": type(loaded).__name__,
        "code_objects": [
            {"co_filename": code.co_filename, "co_name": code.co_name}
            for code in codes if isinstance(code, types.CodeType)
        ],
    },
}, sys.stdout, sort_keys=True)
"#;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
        .join("freezers")
        .join("py2exe")
}

fn committed(name: &str) -> PathBuf {
    let path: PathBuf = fixture_dir().join(name);
    assert!(
        path.is_file(),
        "the committed py2exe fixture {} is missing; restore it from git, because this test never rebuilds fixtures",
        path.display()
    );
    path
}

fn reference() -> Value {
    let text: String =
        std::fs::read_to_string(committed("hello.expected.json")).expect("read reference");
    serde_json::from_str(&text).expect("parse reference")
}

fn out_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0x1234_5678);
    let purpose: String = format!(
        "disrobe-real-py2exe-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
}

fn cpython_digest(dir: &Path, resource: &[u8], script: &[u8], python: &str) -> Value {
    let program: PathBuf = dir.join("digest.py");
    let resource_path: PathBuf = dir.join("pythonscript.bin");
    let script_path: PathBuf = dir.join("script_data.marshal");
    std::fs::write(&program, CPYTHON_DIGEST).expect("write digest program");
    std::fs::write(&resource_path, resource).expect("write resource");
    std::fs::write(&script_path, script).expect("write script data");
    let versioned: String = format!("python{python}{}", std::env::consts::EXE_SUFFIX);
    let launchers: [(String, Vec<String>); 2] = [
        (versioned, Vec::new()),
        ("py".to_owned(), vec![format!("-{python}")]),
    ];
    let mut failures: Vec<String> = Vec::new();
    for (launcher, prefix) in &launchers {
        let output: Output = match Command::new(launcher)
            .args(prefix)
            .arg(&program)
            .arg(&resource_path)
            .arg(&script_path)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                failures.push(format!("{launcher}: {error}"));
                continue;
            }
        };
        if !output.status.success() {
            failures.push(format!(
                "{launcher}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
            continue;
        }
        let digest: Value = serde_json::from_slice(&output.stdout).expect("digest is JSON");
        if digest["marshal_loads"]["python"] == python {
            return digest;
        }
        failures.push(format!(
            "{launcher}: runs CPython {}",
            digest["marshal_loads"]["python"]
        ));
    }
    panic!(
        "CPython {python} is required to marshal.loads the PYTHONSCRIPT script data the fixture was \
         built with; tried {failures:?}"
    );
}

#[test]
fn py2exe_real_fixture_detects_as_py2exe() {
    let path: PathBuf = committed("hello.exe");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let det: Detection = detect_bytes(&bytes, Some(&path));
    assert_eq!(
        det.kind,
        FreezerKind::Py2exe,
        "real py2exe binary must be detected; got {det:?}"
    );
    assert!(
        det.confidence > 0.5,
        "py2exe detection confidence too low: {}",
        det.confidence
    );
}

#[test]
fn pythonscript_resource_matches_the_pefile_reference_and_loads_in_cpython() {
    let reference: Value = reference();
    let expected: &Value = &reference["pythonscript"];
    let path: PathBuf = committed("hello.exe");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");

    let resource: Vec<u8> =
        extract_pythonscript_resource(&bytes).expect("PYTHONSCRIPT from the resource directory");
    let info: ScriptInfo = scriptinfo::parse(&resource).expect("parse PYTHONSCRIPT header");
    assert_eq!(info.magic_tag, PY2EXE_MAGIC_TAG);
    assert_eq!(u64::from(info.optimize_level), expected["optimize"]);
    assert_eq!(u64::from(info.unbuffered_flag), expected["unbuffered"]);
    assert_eq!(u64::from(info.script_data_len), expected["script_data_len"]);
    assert_eq!(info.zip_archive_name, expected["zip_archive_name"]);

    let scratch: disrobe_core::scratch::ScratchDir = out_dir("digest");
    let python: &str = expected["marshal_loads"]["python"]
        .as_str()
        .expect("reference names the CPython version");
    let digest: Value = cpython_digest(scratch.path(), &resource, &info.marshalled_code, python);
    for key in ["size", "sha256", "script_data_sha256", "marshal_loads"] {
        assert_eq!(
            digest[key], expected[key],
            "the recovered PYTHONSCRIPT `{key}` differs from what pefile read out of the py2exe build"
        );
    }

    let extraction: Py2exeExtraction =
        detect_and_extract(&bytes, &path, scratch.path()).expect("py2exe extraction");
    assert_eq!(extraction.script_resource_bytes, resource);
    assert_eq!(
        std::fs::read(&extraction.embedded_pyc_path).expect("read embedded script data"),
        info.marshalled_code
    );
}

#[test]
fn a_decoy_tag_ahead_of_the_resource_is_not_taken_for_the_script() {
    let path: PathBuf = committed("hello.exe");
    let original: Vec<u8> = std::fs::read(&path).expect("read fixture");
    let genuine: Vec<u8> =
        extract_pythonscript_resource(&original).expect("the fixture carries PYTHONSCRIPT");

    let mut decoy: Vec<u8> = Vec::new();
    decoy.extend_from_slice(&PY2EXE_MAGIC_TAG.to_le_bytes());
    decoy.extend_from_slice(&0u32.to_le_bytes());
    decoy.extend_from_slice(&0u32.to_le_bytes());
    decoy.extend_from_slice(&1u32.to_le_bytes());
    decoy.extend_from_slice(b"decoy.zip\0N\0");
    let e_lfanew: usize = usize::try_from(u32::from_le_bytes(
        original[0x3C..0x40].try_into().expect("four bytes"),
    ))
    .expect("fits");
    let decoy_at: usize = 0x40;
    assert!(
        e_lfanew >= decoy_at + decoy.len(),
        "the DOS stub must leave room for the decoy script header"
    );
    let mut decoyed: Vec<u8> = original;
    decoyed[decoy_at..decoy_at + decoy.len()].copy_from_slice(&decoy);

    let recovered: Vec<u8> =
        extract_pythonscript_resource(&decoyed).expect("the decoy does not hide the resource");
    assert_eq!(recovered, genuine);
    let info: ScriptInfo = scriptinfo::parse(&recovered).expect("parse PYTHONSCRIPT header");
    assert_eq!(info.zip_archive_name, "library.zip");
}

#[test]
fn py2exe_sibling_library_zip_contains_all_edge_case_bands() {
    let path: PathBuf = committed("library.zip");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read library.zip");
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(std::io::Cursor::new(bytes.as_slice())).expect("zip parse");
    let mut names: BTreeSet<String> = BTreeSet::new();
    for i in 0..archive.len() {
        let mut file: zip::read::ZipFile<'_> = archive.by_index(i).expect("zip entry");
        names.insert(file.name().to_owned());
        let _ = file.read(&mut [0u8; 0]);
    }
    for band in BANDS {
        let pyc: String = format!("{band}.pyc");
        assert!(
            names.contains(&pyc),
            "edge_cases band `{band}` missing from py2exe library.zip; sample={:?}",
            names.iter().take(10).collect::<Vec<&String>>()
        );
    }
}
