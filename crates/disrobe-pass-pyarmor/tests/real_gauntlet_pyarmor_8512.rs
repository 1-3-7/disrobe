#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{
    BootstrapImport, Detection, ModeClassification, PyarmorVersion, RecoveryDisposition,
    ScriptType, StaticDecryptStatus, StaticUnpackConfig, StaticUnpackOutput, classify_modes,
    detect_from_wrapper, unpack_static_with_config,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion};

const GAUNTLET_ROOT: &str = "corpus/python/pyarmor/gauntlet";

const EXPECTED_PYARMOR_VERSION: &str = "8.5.12";
const EXPECTED_PYTHON_MAJOR: u8 = 3;
const EXPECTED_PYTHON_MINOR: u8 = 12;
const EXPECTED_SERIAL: &str = "015009";
const EXPECTED_PYC_MAGIC: u16 = 0x0DCB;

const KNOWN_IDENTIFIERS: &[&str] = &[
    "Item",
    "Inventory",
    "summarize",
    "WAREHOUSE_ID",
    "LOW_STOCK_THRESHOLD",
    "UNIT_TAX_RATE",
    "total_value",
    "is_low_stock",
    "discounted_price",
    "low_stock_report",
    "reorder_candidates",
    "search_by_tag",
    "taxed_value",
];

const KNOWN_STRINGS: &[&[u8]] = &[b"WH-BOSTON-42", b"discount must be in [0, 1], got "];

fn workspace_root() -> PathBuf {
    let mut dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !dir.join("Cargo.lock").is_file() {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn gauntlet_dir() -> Option<PathBuf> {
    let root: PathBuf = workspace_root().join(GAUNTLET_ROOT);
    root.is_dir().then_some(root)
}

fn load_wrapper_and_runtime(gauntlet: &Path) -> (String, Vec<u8>) {
    let wrapper_path: PathBuf = gauntlet.join("dist").join("inventory.py");
    let runtime_path: PathBuf = gauntlet
        .join("dist")
        .join("pyarmor_runtime_015009")
        .join("pyarmor_runtime.pyd");

    let wrapper: String = std::fs::read_to_string(&wrapper_path).unwrap_or_else(|e| {
        panic!(
            "gauntlet wrapper not readable at {}: {e}",
            wrapper_path.display()
        )
    });
    let runtime: Vec<u8> = std::fs::read(&runtime_path).unwrap_or_else(|e| {
        panic!(
            "gauntlet runtime not readable at {}: {e}",
            runtime_path.display()
        )
    });
    (wrapper, runtime)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

fn locate_first_code_object(plaintext: &[u8]) -> Option<Box<CodeObject>> {
    let py: PyVersion = PyVersion::new(3, 12);
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

fn collect_co_names_recursive(code: &CodeObject, out: &mut Vec<String>) {
    for n in &code.names {
        match n {
            Object::String { value, .. }
            | Object::ShortAscii { value, .. }
            | Object::Unicode { value, .. } => out.push(value.clone()),
            _ => {}
        }
    }
    for c in &code.consts {
        if let Object::Code(inner) = c {
            collect_co_names_recursive(inner, out);
        }
    }
}

#[test]
fn gauntlet_real_8512_wrapper_detection() {
    let Some(gauntlet): Option<PathBuf> = gauntlet_dir() else {
        eprintln!("gauntlet corpus absent; skipping");
        return;
    };

    let (wrapper, _runtime): (String, Vec<u8>) = load_wrapper_and_runtime(&gauntlet);

    assert!(
        wrapper.contains("from pyarmor_runtime_015009 import __pyarmor__"),
        "real 8.5.12 wrapper must import from pyarmor_runtime_015009"
    );
    assert!(
        wrapper.contains(&format!("Pyarmor {EXPECTED_PYARMOR_VERSION}")),
        "wrapper comment must carry the generator version {EXPECTED_PYARMOR_VERSION}"
    );

    let (detection, _payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&wrapper).expect("real 8.5.12 wrapper carries an extractable payload");

    assert_eq!(
        detection.python_major,
        Some(EXPECTED_PYTHON_MAJOR),
        "real 8.5.12 wrapper was built on Python {EXPECTED_PYTHON_MAJOR}.{EXPECTED_PYTHON_MINOR}"
    );
    assert_eq!(
        detection.python_minor,
        Some(EXPECTED_PYTHON_MINOR),
        "real 8.5.12 wrapper was built on Python {EXPECTED_PYTHON_MAJOR}.{EXPECTED_PYTHON_MINOR}"
    );
    assert_eq!(
        detection.serial.as_deref(),
        Some(EXPECTED_SERIAL),
        "payload serial must match the installed license serial"
    );
    assert_eq!(
        detection.pyc_magic,
        Some(EXPECTED_PYC_MAGIC),
        "Python 3.12 pyc magic must be 0x{EXPECTED_PYC_MAGIC:04X}"
    );
}

#[test]
fn gauntlet_real_8512_mode_classified_normal_static_recoverable() {
    let Some(gauntlet): Option<PathBuf> = gauntlet_dir() else {
        return;
    };

    let (wrapper, _runtime): (String, Vec<u8>) = load_wrapper_and_runtime(&gauntlet);
    let (_detection, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&wrapper).expect("payload extractable");

    let mode: ModeClassification = classify_modes(&wrapper, &payload);
    assert_eq!(
        mode.script_type,
        ScriptType::Normal,
        "default pyarmor gen without --enable flags produces a Normal script type"
    );
    assert_eq!(
        mode.bootstrap_import,
        BootstrapImport::RuntimePackage,
        "default gen uses the runtime-package bootstrap import path"
    );
    assert_eq!(
        mode.disposition,
        RecoveryDisposition::StaticRecoverable,
        "default gen (no BCC, no RFT, no ECC) must classify as StaticRecoverable"
    );
    assert!(
        !mode.ecc_enabled,
        "default gen does not enable ECC (BCC-class wall)"
    );
    assert!(
        !mode.rft_enabled,
        "default gen does not enable RFT (rename-from-table)"
    );
}

#[test]
fn gauntlet_real_8512_static_unpack_recovers_module_structure() {
    let Some(gauntlet): Option<PathBuf> = gauntlet_dir() else {
        eprintln!("gauntlet corpus absent; skipping");
        return;
    };

    let (wrapper, runtime_bytes): (String, Vec<u8>) = load_wrapper_and_runtime(&gauntlet);

    let (detection, payload): (Detection, Vec<u8>) = detect_from_wrapper(&wrapper)
        .expect("payload literal extractable from real 8.5.12 wrapper");

    let cfg: StaticUnpackConfig = StaticUnpackConfig {
        runtime_bytes: Some(runtime_bytes),
        strict: true,
        ..StaticUnpackConfig::default()
    };

    let out: StaticUnpackOutput = unpack_static_with_config(&payload, &cfg)
        .expect("in-house key extraction + AES-CTR decrypt of real 8.5.12 runtime succeeds");

    assert_eq!(
        out.pyarmor_version,
        PyarmorVersion::V8,
        "runtime descriptor must resolve the 015009 serial to V8 (pyarmor 8.x product)"
    );
    assert_eq!(
        out.status,
        StaticDecryptStatus::Functional,
        "real 8.5.12 default-mode body must fully decrypt (Functional, not DetectOnly)"
    );
    assert_eq!(
        out.python_version,
        Some((3, 12)),
        "decrypted header agrees with the Python 3.12 builder"
    );
    assert_eq!(
        detection.serial.as_deref(),
        Some(EXPECTED_SERIAL),
        "serial from wrapper matches the installed license"
    );

    assert_eq!(
        out.plaintext.first(),
        Some(&0x20u8),
        "decrypted body starts with the PyArmor 0x20 structural header byte"
    );

    for ident in KNOWN_IDENTIFIERS {
        assert!(
            contains_subslice(&out.plaintext, ident.as_bytes()),
            "pre-obfuscation identifier `{ident}` survives in the decrypted bytes (graded vs inventory_original.py)"
        );
    }

    for string in KNOWN_STRINGS {
        assert!(
            contains_subslice(&out.plaintext, string),
            "known string constant `{}` survives decryption",
            core::str::from_utf8(string).unwrap_or("<non-utf8>")
        );
    }

    let code: Box<CodeObject> = locate_first_code_object(&out.plaintext).expect(
        "decrypted body must contain a genuine Python 3.12 marshalled CodeObject (0xE3 header)",
    );

    let mut all_names: Vec<String> = Vec::new();
    collect_co_names_recursive(&code, &mut all_names);

    for ident in KNOWN_IDENTIFIERS {
        assert!(
            all_names.iter().any(|n: &String| n == ident),
            "recovered co_names carry original identifier `{ident}` from inventory_original.py"
        );
    }
}

#[test]
fn gauntlet_real_8512_detect_only_without_runtime() {
    let Some(gauntlet): Option<PathBuf> = gauntlet_dir() else {
        return;
    };

    let (wrapper, _runtime): (String, Vec<u8>) = load_wrapper_and_runtime(&gauntlet);
    let (_detection, payload): (Detection, Vec<u8>) =
        detect_from_wrapper(&wrapper).expect("payload extractable");

    let cfg: StaticUnpackConfig = StaticUnpackConfig::default();
    let out: StaticUnpackOutput = unpack_static_with_config(&payload, &cfg)
        .expect("detect-only succeeds without runtime (non-strict)");

    assert_eq!(
        out.status,
        StaticDecryptStatus::DetectOnly,
        "without runtime bytes, status must be DetectOnly (AES key is in the runtime, not the payload)"
    );
    assert!(
        out.plaintext.is_empty(),
        "no plaintext is produced without the runtime binary"
    );
    assert!(
        out.diagnostics
            .iter()
            .any(|d: &String| d.contains("pyarmor_runtime") || d.contains("runtime")),
        "detect-only diagnostic must mention that the runtime is needed"
    );
}
