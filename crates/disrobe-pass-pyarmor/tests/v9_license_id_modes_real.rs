#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{
    Detection, DetectionConfidence, HeaderModeFlags, PyarmorVersion, RuntimeKeyClass,
    RuntimeKeyClassification, SerialKind, StaticDecryptStatus, StaticUnpackConfig,
    StaticUnpackOutput, classify_runtime_key, classify_serial, detect_from_wrapper,
    unpack_static_with_config,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion};

const SAMPLE_ROOT: &str = "corpus/python/pyarmor/v9_license_id_015009";
const RUNTIME_DIR: &str = "pyarmor_runtime_015009";
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

fn sample_dir(mode: &str) -> Option<PathBuf> {
    let root: PathBuf = workspace_root().join(SAMPLE_ROOT).join(mode);
    root.is_dir().then_some(root)
}

fn load_wrapper_and_runtime(dir: &Path) -> Option<(String, Vec<u8>)> {
    let wrapper: String = std::fs::read_to_string(dir.join("known_plaintext.py")).ok()?;
    let runtime: PathBuf = dir.join(RUNTIME_DIR).join("pyarmor_runtime.pyd");
    let runtime_bytes: Vec<u8> = std::fs::read(runtime).ok()?;
    Some((wrapper, runtime_bytes))
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
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

fn locate_real_code_object(plaintext: &[u8]) -> Option<Box<CodeObject>> {
    let py: PyVersion = PyVersion::new(3, 14);
    for start in 0x10..plaintext.len().saturating_sub(4) {
        if plaintext[start] != 0xE3 {
            continue;
        }
        if let Ok(Object::Code(code)) = disrobe_py_marshal::load(&plaintext[start..], py)
            && (!code.names.is_empty() || !code.consts.is_empty())
        {
            return Some(code);
        }
    }
    None
}

fn unpack_mode(mode: &str) -> Option<StaticUnpackOutput> {
    let dir: PathBuf = sample_dir(mode)?;
    let (wrapper, runtime_bytes): (String, Vec<u8>) =
        load_wrapper_and_runtime(&dir).expect("license-id sample readable");
    let (_detection, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&wrapper).expect("wrapper carries an extractable payload literal");
    let cfg: StaticUnpackConfig = StaticUnpackConfig {
        runtime_bytes: Some(runtime_bytes),
        strict: true,
        ..StaticUnpackConfig::default()
    };
    Some(
        unpack_static_with_config(&payload, &cfg)
            .expect("in-house decrypt of the license-id runtime"),
    )
}

#[test]
fn license_id_serial_resolves_v9_via_runtime_descriptor() {
    let Some(dir): Option<PathBuf> = sample_dir("default") else {
        eprintln!("license-id default sample absent; skipping");
        return;
    };
    let wrapper: String =
        std::fs::read_to_string(dir.join("known_plaintext.py")).expect("wrapper readable");
    let (detection, _payload): (Detection, Vec<u8>) = detect_from_wrapper(&wrapper).unwrap();
    assert_eq!(
        detection.serial.as_deref(),
        Some("015009"),
        "the real pro build carries a license-id-derived serial, not the trial 000000/009xxx"
    );
    assert_eq!(
        detection.confidence,
        DetectionConfidence::Medium,
        "from the wrapper header alone a license-id serial cannot prove the format version (the same 015009 ships from 8.x and 9.x), so the serial-only verdict is honestly Medium"
    );

    let out: StaticUnpackOutput =
        unpack_mode("default").expect("license-id default sample present");
    assert_eq!(
        out.pyarmor_version,
        PyarmorVersion::V9,
        "the runtime descriptor word resolves the version to V9"
    );
    assert_eq!(
        out.confidence,
        DetectionConfidence::High,
        "once the runtime descriptor confirms the version the verdict is upgraded to High"
    );
}

#[test]
fn license_id_serial_classification_is_license_id_kind() {
    let class: disrobe_pass_pyarmor::SerialClassification = classify_serial("015009");
    assert_eq!(class.kind, SerialKind::LicenseId);
    assert_eq!(class.license_id.as_deref(), Some("015"));
    assert_eq!(
        class.format_version, None,
        "the serial alone does not encode the format version"
    );
    assert!(!class.format_version_high_confidence);
}

#[test]
fn default_mode_recovers_known_plaintext() {
    let Some(out): Option<StaticUnpackOutput> = unpack_mode("default") else {
        eprintln!("license-id default sample absent; skipping");
        return;
    };
    assert_eq!(out.pyarmor_version, PyarmorVersion::V9);
    assert_eq!(out.status, StaticDecryptStatus::Functional);
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

    let code: Box<CodeObject> = locate_real_code_object(&out.plaintext)
        .expect("a genuine marshalled module code object inside the decrypted blob");
    let mut all_names: Vec<String> = Vec::new();
    collect_co_names_recursive(&code, &mut all_names);
    for ident in KNOWN_IDENTIFIERS {
        assert!(
            all_names.iter().any(|n: &String| n == ident),
            "recovered co_names carry the original identifier `{ident}`, graded against the pre-obfuscation source not the tool's own output"
        );
    }
}

#[test]
fn default_mode_key_classification_is_embedded() {
    let Some(out): Option<StaticUnpackOutput> = unpack_mode("default") else {
        return;
    };
    let class: RuntimeKeyClassification = out
        .key_classification
        .expect("a v9 sample with a serial carries a key classification");
    assert_eq!(class.serial.kind, SerialKind::LicenseId);
    assert_eq!(class.runtime_key_class, RuntimeKeyClass::Embedded);
    let flags: HeaderModeFlags = class.mode_flags.expect("64-byte header decodes mode flags");
    assert!(flags.obf_module, "default build obfuscates the module");
    assert!(flags.obf_code, "default build obfuscates code");
    assert!(!flags.restrict_mode, "default build is not restrict");
    assert!(!flags.outer_runtime_key, "default build embeds the key");
}

#[test]
fn restrict_mode_flag_is_decoded_and_still_recovers() {
    let Some(out): Option<StaticUnpackOutput> = unpack_mode("restrict") else {
        eprintln!("license-id restrict sample absent; skipping");
        return;
    };
    let class: RuntimeKeyClassification = out.key_classification.expect("classification");
    let flags: HeaderModeFlags = class.mode_flags.expect("flags");
    assert!(
        flags.restrict_mode,
        "the --restrict build must set the restrict mode flag in the header"
    );
    assert_eq!(
        out.status,
        StaticDecryptStatus::Functional,
        "restrict mode is a runtime import guard, not a static wall; recovery still succeeds"
    );
    for ident in KNOWN_IDENTIFIERS {
        assert!(
            contains_subslice(&out.plaintext, ident.as_bytes()),
            "restrict: identifier `{ident}` recovered"
        );
    }
}

#[test]
fn obf_module_disabled_flag_is_decoded() {
    let Some(out): Option<StaticUnpackOutput> = unpack_mode("obfmod0") else {
        eprintln!("license-id obfmod0 sample absent; skipping");
        return;
    };
    let class: RuntimeKeyClassification = out.key_classification.expect("classification");
    let flags: HeaderModeFlags = class.mode_flags.expect("flags");
    assert!(
        !flags.obf_module,
        "the --obf-module 0 build must clear the obf-module flag"
    );
    assert!(flags.obf_code, "function bodies are still obfuscated");
}

#[test]
fn outer_runtime_key_flag_is_decoded() {
    let Some(dir): Option<PathBuf> = sample_dir("outer") else {
        eprintln!("license-id outer sample absent; skipping");
        return;
    };
    let (wrapper, _runtime): (String, Vec<u8>) = load_wrapper_and_runtime(&dir).unwrap();
    let (detection, _payload): (Detection, Vec<u8>) = detect_from_wrapper(&wrapper).unwrap();
    let serial: &str = detection.serial.as_deref().expect("serial");
    let class: RuntimeKeyClassification = classify_runtime_key(serial, &detection.raw_header);
    assert_eq!(
        class.runtime_key_class,
        RuntimeKeyClass::Outer,
        "the --outer build must classify the runtime key as outer"
    );
    let flags: HeaderModeFlags = class.mode_flags.expect("flags");
    assert!(flags.outer_runtime_key);
    assert!(
        class.notes.iter().any(|n: &String| n.contains("outer")),
        "outer key surfaces a diagnostic note"
    );
}

#[test]
fn mix_str_mode_recovers_module_structure() {
    let Some(out): Option<StaticUnpackOutput> = unpack_mode("mixstr") else {
        eprintln!("license-id mixstr sample absent; skipping");
        return;
    };
    assert_eq!(out.status, StaticDecryptStatus::Functional);
    for ident in KNOWN_IDENTIFIERS {
        assert!(
            contains_subslice(&out.plaintext, ident.as_bytes()),
            "mix-str: identifier `{ident}` recovered (names are not string-mixed)"
        );
    }
}

#[test]
fn clean_control_yields_nothing() {
    let clean: PathBuf = workspace_root()
        .join(SAMPLE_ROOT)
        .join("known_plaintext_original.py");
    let Ok(src): std::io::Result<String> = std::fs::read_to_string(&clean) else {
        eprintln!("clean control absent; skipping");
        return;
    };
    assert!(
        detect_from_wrapper(&src).is_err(),
        "the original un-obfuscated source must not be detected as a pyarmor wrapper"
    );
}
