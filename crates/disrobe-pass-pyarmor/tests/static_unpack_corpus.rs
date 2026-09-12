#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/pyarmor_corpus_manifest.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod pyarmor_corpus_manifest;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use disrobe_pass_pyarmor::{
    PyarmorVersion, SerialKind, StaticDecryptStatus, StaticRuntimeInfoSummary, StaticUnpackConfig,
    StaticUnpackOutput, WrapperMagic, classify_serial, detect_from_wrapper, marshal_stream_start,
    unpack_static, unpack_static_with_config,
};
use disrobe_py_marshal::{Object, PyVersion, RefTableDump, load_with_reftable};
use pyarmor_corpus_manifest::{
    CorpusManifest, CorpusVersion, ResolvedFixture, read_manifest, verified_fixtures,
};

const STRUCTURAL_CODE_OBJECT_FLOOR: usize = 72;
const DEFAULT_TRIAL_SERIAL: &str = "000000";
const PY312: PyVersion = PyVersion::new(3, 12);

const PUBLISHED_HEADING: &str = "PyArmor structural marshal coverage";
const PUBLISHED_BAR: &str = "v8/v9 default-trial wrappers";

fn published_bar(heading_needle: &str, label: &str) -> serde_json::Value {
    let path: PathBuf = workspace_root()
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error: serde_json::Error| panic!("parse {}: {error}", path.display()));
    let mut found: Vec<serde_json::Value> = Vec::new();
    for group in doc["groups"].as_array().expect("groups array") {
        let heading_matches: bool = group["heading"]
            .as_str()
            .is_some_and(|heading: &str| heading.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        let bars: &Vec<serde_json::Value> = group["bars"]
            .as_array()
            .expect("each recovery group must carry a bars array");
        for bar in bars {
            if bar["label"].as_str() == Some(label) {
                found.push(bar.clone());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labelled `{label}` under a heading containing `{heading_needle}`, found {}",
        found.len()
    );
    found.remove(0)
}

#[test]
fn rejects_zero_bytes() {
    let err: bool = unpack_static(&[]).is_err();
    assert!(err);
}

#[test]
fn rejects_garbage_bytes() {
    let err: bool = unpack_static(&[0xffu8; 64]).is_err();
    assert!(err);
}

#[test]
fn detect_only_v8_without_runtime() {
    let mut bytes: Vec<u8> = vec![0u8; 64];
    bytes[..8].copy_from_slice(b"PY008106");
    bytes[9] = 3;
    bytes[10] = 11;
    bytes[20] = 0x08;
    let output: StaticUnpackOutput =
        unpack_static(&bytes).expect("v8 detect-only succeeds with no runtime");
    assert_eq!(output.header_metadata.magic, WrapperMagic::Py8Or9);
    assert_eq!(output.header_metadata.serial.as_deref(), Some("008106"));
    assert_eq!(output.python_version, Some((3, 11)));
}

#[test]
fn detect_only_v9_bcc_without_runtime() {
    let mut bytes: Vec<u8> = vec![0u8; 64];
    bytes[..8].copy_from_slice(b"PY009070");
    bytes[9] = 3;
    bytes[10] = 13;
    bytes[20] = 0x09;
    let output: StaticUnpackOutput = unpack_static(&bytes).expect("v9 detect-only");
    assert_eq!(output.header_metadata.protection_type, Some(0x09));
}

#[test]
fn corpus_pyc_smoke_does_not_panic() {
    let corpus_dir: PathBuf = workspace_root().join("corpus/python/pyarmor");
    assert!(
        corpus_dir.is_dir(),
        "the pyarmor corpus is tracked in git and is what this case sweeps, so its absence is a damaged checkout rather than an optional dependency: {}",
        corpus_dir.display()
    );
    let mut swept: usize = 0;
    walk_files(&corpus_dir, &mut |path: &Path| {
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("pyc") {
            return;
        }
        let bytes: Vec<u8> = std::fs::read(path).unwrap_or_else(|error: std::io::Error| {
            panic!("{} is unreadable: {error}", path.display())
        });
        let cfg: StaticUnpackConfig = StaticUnpackConfig {
            emit_llm_metadata: true,
            ..StaticUnpackConfig::default()
        };
        let _ = unpack_static_with_config(&bytes, &cfg);
        swept += 1;
    });
    assert!(
        swept > 0,
        "{} carries no .pyc, so this case swept nothing and would report success without running the unpacker over a single sample",
        corpus_dir.display()
    );
}

#[test]
fn named_v8_v9_default_trial_wrappers_decode_complete_root_code_objects() {
    let fixtures: &Vec<ResolvedFixture> = verified_corpus();
    assert_eq!(
        fixtures.len(),
        STRUCTURAL_CODE_OBJECT_FLOOR,
        "the structural corpus floor must remain pinned to the validated named wrapper population"
    );

    let mut decoded: usize = 0;
    for fixture in fixtures {
        let output: StaticUnpackOutput = decrypt_fixture(fixture);
        let Some(header_serial): Option<&str> = output.header_metadata.serial.as_deref() else {
            panic!(
                "{}: the static-unpack header must carry a serial so the trial classification is bound to decrypted inputs",
                fixture.relative_id
            )
        };
        assert_eq!(
            header_serial, DEFAULT_TRIAL_SERIAL,
            "{}: the static-unpack header must carry the default-trial serial claimed by the named corpus",
            fixture.relative_id
        );
        assert_eq!(
            output.serial.as_deref(),
            Some(header_serial),
            "{}: the static-unpack output serial must agree with the parsed header serial",
            fixture.relative_id
        );
        assert_eq!(
            classify_serial(header_serial).kind,
            SerialKind::DefaultTrial,
            "{}: the canonical serial classifier must recognize the static-unpack header serial as default-trial",
            fixture.relative_id
        );
        let runtime: &StaticRuntimeInfoSummary =
            output.runtime_info.as_ref().unwrap_or_else(|| {
                panic!(
                    "{}: strict static unpack must retain the runtime summary used for decryption",
                    fixture.relative_id
                )
            });
        assert_eq!(
            runtime.serial.as_str(),
            header_serial,
            "{}: the runtime serial must agree with the static-unpack header serial",
            fixture.relative_id
        );
        assert_eq!(
            runtime.descriptor_version,
            Some(expected_version(fixture.pyarmor_version)),
            "{}: the runtime descriptor must agree with the manifest's v8/v9 corpus label",
            fixture.relative_id
        );
        assert_eq!(
            output.pyarmor_version,
            expected_version(fixture.pyarmor_version),
            "{}: runtime-descriptor discrimination must agree with the manifest's v8/v9 corpus label",
            fixture.relative_id
        );
        assert_eq!(
            output.status,
            StaticDecryptStatus::Functional,
            "{}: static decryption must finish functionally",
            fixture.relative_id
        );
        assert_eq!(
            output.plaintext.first(),
            Some(&0x20u8),
            "{}: decrypted body must start with the v8/v9 plaintext structural header",
            fixture.relative_id
        );
        let version: PyVersion = python_version(&output, fixture);
        grade_anchored_marshaled_code_object(&output.plaintext, version).unwrap_or_else(
            |error: String| {
                panic!(
                    "{}: the header-anchored marshal stream must decode as one complete root CodeObject: {error}",
                    fixture.relative_id
                )
            },
        );
        decoded += 1;
    }

    let bar: serde_json::Value = published_bar(PUBLISHED_HEADING, PUBLISHED_BAR);
    let detected: u64 = bar["detected"]
        .as_u64()
        .expect("the structural PyArmor bar must carry a detected count");
    let delivered: u64 = bar["delivered"]
        .as_u64()
        .expect("the structural PyArmor bar must carry a delivered count");
    let total: u64 = u64::try_from(fixtures.len()).expect("fixture count fits u64");
    let successful: u64 = u64::try_from(decoded).expect("decoded count fits u64");
    assert_eq!(
        total, detected,
        "xtask/data/recovery.json must publish the complete named v8/v9 wrapper population"
    );
    assert_eq!(
        successful, delivered,
        "xtask/data/recovery.json must publish exactly the fixtures whose anchored marshal streams decoded"
    );
}

#[test]
fn non_code_anchored_marshaled_root_is_rejected() {
    let fixtures: &Vec<ResolvedFixture> = verified_corpus();
    let fixture: &ResolvedFixture = fixtures
        .first()
        .expect("the pinned PyArmor corpus contains at least one fixture");
    let output: StaticUnpackOutput = decrypt_fixture(fixture);
    let baseline_version: PyVersion = python_version(&output, fixture);
    grade_anchored_marshaled_code_object(&output.plaintext, baseline_version)
        .expect("the unmodified real fixture must satisfy the complete root-CodeObject grader");
    let version: PyVersion = python_version(&output, fixture);
    let start: usize = declared_marshaled_start(&output.plaintext)
        .expect("the unmodified fixture carries a bounded plaintext marshal offset");
    let end: usize = start
        .checked_add(1)
        .expect("the marshal root type tag has an addressable byte after the header");
    let mut non_code: Vec<u8> = output.plaintext;
    non_code[start] = b'N';
    non_code.truncate(end);
    assert!(
        grade_anchored_marshaled_code_object(&non_code, version).is_err(),
        "the structural grader must reject a complete header-anchored marshal value whose root is not a CodeObject"
    );
}

fn decrypt_fixture(fixture: &ResolvedFixture) -> StaticUnpackOutput {
    let text: &str = std::str::from_utf8(&fixture.wrapper.bytes).unwrap_or_else(|error| {
        panic!(
            "{} is not valid UTF-8 after manifest identity verification: {error}",
            fixture.relative_id
        )
    });
    let (_detection, payload): (_, Vec<u8>) = detect_from_wrapper(text).unwrap_or_else(|error| {
        panic!(
            "{} has no extractable payload literal: {error}",
            fixture.relative_id
        )
    });
    let cfg: StaticUnpackConfig = StaticUnpackConfig {
        runtime_bytes: Some(fixture.runtime.bytes.to_vec()),
        strict: true,
        ..StaticUnpackConfig::default()
    };
    unpack_static_with_config(&payload, &cfg)
        .unwrap_or_else(|error| panic!("{} static decrypt failed: {error}", fixture.relative_id))
}

fn verified_corpus() -> &'static Vec<ResolvedFixture> {
    static FIXTURES: OnceLock<Vec<ResolvedFixture>> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let manifest: CorpusManifest = read_manifest();
        verified_fixtures(&manifest)
    })
}

const fn expected_version(version: CorpusVersion) -> PyarmorVersion {
    match version {
        CorpusVersion::V8 => PyarmorVersion::V8,
        CorpusVersion::V9 => PyarmorVersion::V9,
    }
}

fn python_version(output: &StaticUnpackOutput, fixture: &ResolvedFixture) -> PyVersion {
    let Some((major, minor)): Option<(u8, u8)> = output.python_version else {
        panic!(
            "{} has no declared Python version after static decrypt",
            fixture.relative_id
        )
    };
    assert_eq!(
        (major, minor),
        (PY312.major, PY312.minor),
        "{} must remain pinned to the Python 3.12 marshal format declared by the committed corpus",
        fixture.relative_id
    );
    PyVersion::new(major, minor)
}

fn declared_marshaled_start(plaintext: &[u8]) -> Result<usize, String> {
    let code_object_offset: usize = usize::try_from(read_u32_le(plaintext, 0)?)
        .map_err(|error| format!("code-object offset does not fit usize: {error}"))?;
    let xor_procedure_len: usize = usize::try_from(read_u32_le(plaintext, 4)?)
        .map_err(|error| format!("xor procedure length does not fit usize: {error}"))?;
    let start: usize = code_object_offset
        .checked_add(xor_procedure_len)
        .ok_or_else(|| "plaintext header marshal offset overflows usize".to_owned())?;
    if start > plaintext.len() {
        return Err(format!(
            "plaintext header declares marshal start {start} beyond {} decrypted bytes",
            plaintext.len()
        ));
    }
    Ok(start)
}

fn read_u32_le(plaintext: &[u8], offset: usize) -> Result<u32, String> {
    let end: usize = offset
        .checked_add(4)
        .ok_or_else(|| "plaintext header field end overflows usize".to_owned())?;
    let bytes: &[u8] = plaintext
        .get(offset..end)
        .ok_or_else(|| format!("plaintext header omits bytes {offset}..{end}"))?;
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| format!("plaintext header field {offset}..{end} is not four bytes"))?;
    Ok(u32::from_le_bytes(array))
}

fn grade_anchored_marshaled_code_object(
    plaintext: &[u8],
    version: PyVersion,
) -> Result<usize, String> {
    let declared_start: usize = declared_marshaled_start(plaintext)?;
    let start: usize = marshal_stream_start(plaintext)
        .map_err(|error| format!("plaintext header has no bounded marshal start: {error}"))?;
    if start != declared_start {
        return Err(format!(
            "public marshal-start helper returned {start}, but the plaintext header declares {declared_start}"
        ));
    }
    let stream: &[u8] = plaintext
        .get(start..)
        .filter(|stream: &&[u8]| !stream.is_empty())
        .ok_or_else(|| "plaintext header points to an empty marshal stream".to_owned())?;
    let (object, trace): (Object, RefTableDump) = load_with_reftable(stream, version)
        .map_err(|error| format!("marshal reader rejected the header-anchored stream: {error}"))?;
    if !matches!(object, Object::Code(_)) {
        return Err("header-anchored marshal root is not a CodeObject".to_owned());
    }
    if trace.total_bytes != stream.len() {
        return Err(format!(
            "marshal reader consumed {} of {} bytes from the header-anchored stream",
            trace.total_bytes,
            stream.len()
        ));
    }
    Ok(trace.total_bytes)
}

fn workspace_root() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn walk_files(dir: &Path, visitor: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            walk_files(&path, visitor);
        } else {
            visitor(&path);
        }
    }
}
