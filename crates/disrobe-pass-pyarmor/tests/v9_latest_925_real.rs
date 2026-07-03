#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{
    BootstrapImport, Detection, ModeClassification, PyarmorVersion, RecoveryDisposition,
    ScriptType, StaticDecryptStatus, StaticUnpackConfig, StaticUnpackOutput, classify_modes,
    detect_from_wrapper, unpack_static_with_config,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion};

const SAMPLE_ROOT: &str = "corpus/python/pyarmor/v9_latest_925";

const KNOWN_IDENTIFIERS: &[&str] = &["add", "classify", "Counter", "increment", "main"];
const KNOWN_SECRET: &[u8] = b"disrobe-vmc-oracle-12345";

fn workspace_root() -> PathBuf {
    let mut dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !dir.join("Cargo.lock").is_file() {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn sample_dir(name: &str) -> Option<PathBuf> {
    let root: PathBuf = workspace_root().join(SAMPLE_ROOT).join(name);
    root.is_dir().then_some(root)
}

fn load_wrapper_and_runtime(dir: &Path) -> Option<(String, Vec<u8>)> {
    let wrapper: String = std::fs::read_to_string(dir.join("known_plaintext.py")).ok()?;
    let runtime: PathBuf = dir
        .join("pyarmor_runtime_000000")
        .join("pyarmor_runtime.pyd");
    let runtime_bytes: Vec<u8> = std::fs::read(runtime).ok()?;
    Some((wrapper, runtime_bytes))
}

fn co_names(code: &CodeObject) -> Vec<String> {
    code.names
        .iter()
        .filter_map(|n: &Object| match n {
            Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.clone()),
            _ => None,
        })
        .collect()
}

fn collect_co_names_recursive(code: &CodeObject, out: &mut Vec<String>) {
    out.extend(co_names(code));
    for c in &code.consts {
        if let Object::Code(inner) = c {
            collect_co_names_recursive(inner, out);
        }
    }
}

fn locate_real_code_object(plaintext: &[u8]) -> Option<(usize, Box<CodeObject>)> {
    let py: PyVersion = PyVersion::new(3, 14);
    for start in 0x10..plaintext.len().saturating_sub(4) {
        if plaintext[start] != 0xE3 {
            continue;
        }
        if let Ok(Object::Code(code)) = disrobe_py_marshal::load(&plaintext[start..], py)
            && (!code.names.is_empty() || !code.consts.is_empty())
        {
            return Some((start, code));
        }
    }
    None
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn recovers_known_plaintext_from_real_925_default_sample() {
    let Some(dir): Option<PathBuf> = sample_dir("default") else {
        eprintln!("real 9.2.5 default sample absent; skipping");
        return;
    };
    let (wrapper, runtime_bytes): (String, Vec<u8>) =
        load_wrapper_and_runtime(&dir).expect("default sample readable");

    let (detection, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&wrapper).expect("real wrapper carries an extractable payload literal");
    assert_eq!(
        detection.python_minor,
        Some(14),
        "real 9.2.5 trial sample was built on Python 3.14"
    );

    let cfg: StaticUnpackConfig = StaticUnpackConfig {
        runtime_bytes: Some(runtime_bytes),
        strict: true,
        ..StaticUnpackConfig::default()
    };
    let out: StaticUnpackOutput = unpack_static_with_config(&payload, &cfg)
        .expect("in-house decrypt of the real 9.2.5 runtime key succeeds");

    assert_eq!(out.pyarmor_version, PyarmorVersion::V9);
    assert_eq!(
        out.status,
        StaticDecryptStatus::Functional,
        "real 9.2.5 AES body must fully decrypt"
    );
    assert_eq!(
        out.plaintext.first(),
        Some(&0x20u8),
        "decrypted body starts with the PyArmor 0x20 structural header"
    );

    for ident in KNOWN_IDENTIFIERS {
        assert!(
            contains_subslice(&out.plaintext, ident.as_bytes()),
            "pre-obfuscation identifier `{ident}` survives in the decrypted bytes"
        );
    }
    assert!(
        contains_subslice(&out.plaintext, KNOWN_SECRET),
        "the known SECRET_TOKEN string survives decryption"
    );

    let (_offset, code): (usize, Box<CodeObject>) =
        locate_real_code_object(&out.plaintext).expect("a genuine marshalled module code object");
    let mut all_names: Vec<String> = Vec::new();
    collect_co_names_recursive(&code, &mut all_names);
    for ident in KNOWN_IDENTIFIERS {
        assert!(
            all_names.iter().any(|n: &String| n == ident),
            "recovered co_names carry the original identifier `{ident}` (grade vs the pre-obfuscation source, not the tool's own output)"
        );
    }
}

#[test]
fn recovers_known_plaintext_from_real_925_nowrap_sample() {
    let Some(dir): Option<PathBuf> = sample_dir("nowrap") else {
        eprintln!("real 9.2.5 nowrap sample absent; skipping");
        return;
    };
    let (wrapper, runtime_bytes): (String, Vec<u8>) =
        load_wrapper_and_runtime(&dir).expect("nowrap sample readable");
    let (_detection, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&wrapper).expect("nowrap wrapper payload literal");

    let cfg: StaticUnpackConfig = StaticUnpackConfig {
        runtime_bytes: Some(runtime_bytes),
        strict: true,
        ..StaticUnpackConfig::default()
    };
    let out: StaticUnpackOutput =
        unpack_static_with_config(&payload, &cfg).expect("nowrap real decrypt succeeds");
    assert_eq!(out.status, StaticDecryptStatus::Functional);
    for ident in KNOWN_IDENTIFIERS {
        assert!(
            contains_subslice(&out.plaintext, ident.as_bytes()),
            "nowrap: identifier `{ident}` recovered"
        );
    }
}

#[test]
fn real_925_default_classified_as_normal_static_recoverable() {
    let Some(dir): Option<PathBuf> = sample_dir("default") else {
        return;
    };
    let (wrapper, _runtime): (String, Vec<u8>) = load_wrapper_and_runtime(&dir).unwrap();
    let (_detection, payload): (Detection, Vec<u8>) = detect_from_wrapper(&wrapper).unwrap();
    let class: ModeClassification = classify_modes(&wrapper, &payload);
    assert_eq!(class.script_type, ScriptType::Normal);
    assert_eq!(class.bootstrap_import, BootstrapImport::RuntimePackage);
    assert_eq!(class.disposition, RecoveryDisposition::StaticRecoverable);
    assert!(!class.ecc_enabled);
}

#[test]
fn real_925_header_is_python_314_magic() {
    let Some(dir): Option<PathBuf> = sample_dir("default") else {
        return;
    };
    let (wrapper, _runtime): (String, Vec<u8>) = load_wrapper_and_runtime(&dir).unwrap();
    let (detection, _payload): (Detection, Vec<u8>) = detect_from_wrapper(&wrapper).unwrap();
    assert_eq!(detection.python_major, Some(3));
    assert_eq!(detection.python_minor, Some(14));
    assert_eq!(
        detection.pyc_magic,
        Some(0x0E2B),
        "real 9.2.5 Python 3.14 sample carries the 3.14 pyc magic 0x0E2B"
    );
}

#[cfg(feature = "chain")]
#[test]
fn chain_detect_paths_classify_925_serial_as_v9_not_v8_super() {
    use disrobe_core::chain::{DetectContext, Detector, DetectorOutput, ObfuscatorCatalog};
    use disrobe_pass_pyarmor::chain_detector::PyarmorDetector;

    let Some(dir): Option<PathBuf> = sample_dir("default") else {
        eprintln!("real 9.2.5 default sample absent; skipping");
        return;
    };
    let wrapper: String =
        std::fs::read_to_string(dir.join("known_plaintext.py")).expect("wrapper readable");
    let ctx: DetectContext<'_> = DetectContext {
        bytes: wrapper.as_bytes(),
        path_hint: Some("known_plaintext.py"),
        parent_hint: None,
        depth: 0,
    };

    let verdict: disrobe_core::chain::DetectVerdict =
        Detector::detect(&PyarmorDetector, &ctx).expect("chain pipeline detector must fire");
    assert_eq!(
        verdict.format_tag, "pyarmor-v9",
        "a 9.2.x license-id serial decodes to v9, not the v8-super-mode tag the old serial-prefix heuristic produced; got {}",
        verdict.format_tag
    );

    let output: DetectorOutput = ObfuscatorCatalog::detect(&PyarmorDetector, &ctx)
        .expect("`disrobe detect` catalog path must fire");
    assert_eq!(
        output.entry_id, "pyarmor-v9",
        "the catalog/`disrobe detect` path must also report v9 for a 9.2.x sample; got {}",
        output.entry_id
    );
}

#[cfg(feature = "chain")]
#[test]
fn chain_run_with_path_recovers_real_pyc_via_sibling_runtime() {
    use disrobe_core::Artifact;
    use disrobe_core::Rung;
    use disrobe_core::chain::Pass;
    use disrobe_pass_pyarmor::chain_detector::PYARMOR_PASS;

    let Some(dir): Option<PathBuf> = sample_dir("default") else {
        eprintln!("real 9.2.5 default sample absent; skipping");
        return;
    };
    let wrapper_path: PathBuf = dir.join("known_plaintext.py");
    let wrapper: Vec<u8> = std::fs::read(&wrapper_path).expect("wrapper readable");
    let artifact: Artifact = Artifact::new(Rung::Raw, wrapper, [0u8; 32]);

    let path_str: String = wrapper_path.display().to_string();
    let out: Artifact = PYARMOR_PASS
        .run_with_path(&artifact, Some(&path_str))
        .expect("v9 auto-route must locate the sibling runtime and decrypt to a real pyc");
    let pyc: &[u8] = out.envelope.as_slice();
    assert!(
        pyc.len() > 16 && pyc[..4] == [0x2b, 0x0e, 0x0d, 0x0a],
        "auto-route output must be a real CPython 3.14 .pyc (magic 0x0A0D0E2B le) that feeds straight into py-decompile, not the raw 0x20 structural blob; got head {:?}",
        &pyc[..pyc.len().min(4)]
    );

    let byte_only: Artifact = PYARMOR_PASS
        .run(&artifact)
        .expect("byte-only run now emits the static manifest + wall instead of a bare failure");
    let manifest_bytes: &[u8] = byte_only.envelope.as_slice();
    assert!(
        !(manifest_bytes.len() > 4 && manifest_bytes[..4] == [0x2b, 0x0e, 0x0d, 0x0a]),
        "without the sibling runtime key the byte-only run must NOT emit a partial/fake pyc; it emits the json manifest wall"
    );
    let parsed: serde_json::Value = serde_json::from_slice(manifest_bytes)
        .expect("byte-only run output is the json wall manifest");
    assert_eq!(parsed["schema"], "disrobe.pyarmor.manifest/v0");
    let limitations: &Vec<serde_json::Value> = parsed["limitations"]
        .as_array()
        .expect("wall manifest carries limitations");
    assert!(
        limitations
            .iter()
            .any(|l: &serde_json::Value| l.as_str().is_some_and(|s| s.contains("v8/v9 AES key"))),
        "the runtime-key wall must be recorded in the chain manifest, not dropped as a bare error"
    );
}
