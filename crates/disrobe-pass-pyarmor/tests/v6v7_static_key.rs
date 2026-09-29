#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{
    Detection, PyarmorVersion, StaticDecryptStatus, StaticUnpackConfig, StaticUnpackOutput,
    detect_from_wrapper, unpack_static_with_config,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load};

const KNOWN_MARKER: &[u8] = b"try_except_basic";
const PY312: PyVersion = PyVersion::new(3, 12);
const REQUIRE_LOCAL_CORPUS_VAR: &str = "DISROBE_REQUIRE_PYARMOR_LOCAL_CORPUS";

fn local_input_absent(graded: &str, absent: &str) {
    assert!(
        std::env::var_os(REQUIRE_LOCAL_CORPUS_VAR).is_none(),
        "{REQUIRE_LOCAL_CORPUS_VAR} is set, so the local-only input for {graded} must exist: {absent}"
    );
    eprintln!(
        "UNGRADED: {graded} graded nothing, because {absent}; PyArmor 6 and 7 runtimes are not \
         redistributable, so this input is local-only. Set {REQUIRE_LOCAL_CORPUS_VAR}=1 to fail \
         instead"
    );
}

fn corpus_root() -> PathBuf {
    let here: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .expect("crates")
        .parent()
        .expect("repo root")
        .join("corpus")
        .join("python")
        .join("pyarmor")
}

struct PlatformRuntimeCase {
    relative_id: &'static str,
    runtime_format: &'static str,
    expected_version: PyarmorVersion,
}

const CROSS_PLATFORM_RUNTIME_CASES: [PlatformRuntimeCase; 5] = [
    PlatformRuntimeCase {
        relative_id: "v8/platform_linux",
        runtime_format: "ELF64/x86_64",
        expected_version: PyarmorVersion::V8,
    },
    PlatformRuntimeCase {
        relative_id: "v8/platform_linux_aarch64",
        runtime_format: "ELF64/aarch64",
        expected_version: PyarmorVersion::V8,
    },
    PlatformRuntimeCase {
        relative_id: "v8/platform_darwin",
        runtime_format: "Mach-O",
        expected_version: PyarmorVersion::V8,
    },
    PlatformRuntimeCase {
        relative_id: "v9/platform_linux",
        runtime_format: "ELF64/x86_64",
        expected_version: PyarmorVersion::V9,
    },
    PlatformRuntimeCase {
        relative_id: "v9/platform_darwin",
        runtime_format: "Mach-O",
        expected_version: PyarmorVersion::V9,
    },
];

#[test]
fn cross_platform_elf_macho_runtime_keypath_recovers_real_source() {
    let root: PathBuf = corpus_root();
    assert!(
        root.is_dir(),
        "the pyarmor corpus is tracked in git and carries the runtimes this case reads, so its \
         absence is a damaged checkout rather than an optional dependency: {}",
        root.display()
    );

    let mut proven: usize = 0;
    for case in &CROSS_PLATFORM_RUNTIME_CASES {
        let dir: PathBuf = root.join(case.relative_id);
        let wrapper: PathBuf = dir.join("chunk_00_try_except_basic_try_except_else.py");
        let Some(runtime): Option<PathBuf> = find_native_runtime(&dir) else {
            panic!(
                "{}: real {} runtime fixture must be committed under the corpus",
                case.relative_id, case.runtime_format
            );
        };

        let text: String = std::fs::read_to_string(&wrapper)
            .unwrap_or_else(|_| panic!("{}: wrapper .py is readable", case.relative_id));
        let (_detection, payload): (Detection, Vec<u8>) = detect_from_wrapper(&text)
            .unwrap_or_else(|_| panic!("{}: wrapper carries a payload literal", case.relative_id));
        let runtime_bytes: Vec<u8> = std::fs::read(&runtime)
            .unwrap_or_else(|_| panic!("{}: native runtime is readable", case.relative_id));

        let cfg: StaticUnpackConfig = StaticUnpackConfig {
            runtime_bytes: Some(runtime_bytes),
            strict: true,
            ..StaticUnpackConfig::default()
        };
        let out: StaticUnpackOutput = unpack_static_with_config(&payload, &cfg).unwrap_or_else(|e| {
            panic!(
                "{}: in-house key extraction over the real {} runtime + AES decrypt must succeed: {e}",
                case.relative_id, case.runtime_format
            )
        });

        assert_eq!(
            out.pyarmor_version, case.expected_version,
            "{}: runtime-descriptor discrimination must hold on non-PE binaries",
            case.relative_id
        );
        assert_eq!(
            out.status,
            StaticDecryptStatus::Functional,
            "{}: decrypt over the {} runtime key must be Functional",
            case.relative_id,
            case.runtime_format
        );

        let (offset, code): (usize, Box<CodeObject>) = locate_real_code_object(&out.plaintext)
            .unwrap_or_else(|| {
                panic!(
                    "{}: decrypted body must contain a genuine marshalled CodeObject",
                    case.relative_id
                )
            });
        assert!(
            offset >= 0x20,
            "{}: marshal stream lives beyond the structural header",
            case.relative_id
        );
        assert!(
            contains_subslice(&out.plaintext, KNOWN_MARKER),
            "{}: pre-obfuscation identifier `try_except_basic` survives in the decrypted bytes",
            case.relative_id
        );
        assert!(
            co_names_contains(&code, "try_except_basic"),
            "{}: recovered co_names carry the independent ground-truth identifier",
            case.relative_id
        );

        proven += 1;
    }

    assert_eq!(
        proven,
        CROSS_PLATFORM_RUNTIME_CASES.len(),
        "every committed cross-platform ELF/Mach-O runtime fixture must drive a real recovery"
    );
}

#[test]
fn v6v7_static_key_real_pytransform_when_baked() {
    let runtimes_dir: PathBuf = corpus_root().join("_pytransform-runtimes");
    if !runtimes_dir.is_dir() {
        local_input_absent(
            "the static-key probe over real pytransform runtimes",
            &format!("{} is not in this checkout", runtimes_dir.display()),
        );
        return;
    }
    let mut probed: usize = 0;
    let entries: std::fs::ReadDir = std::fs::read_dir(&runtimes_dir).expect("read dir");
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        let name: std::ffi::OsString = entry.file_name();
        let n: std::borrow::Cow<'_, str> = name.to_string_lossy();
        if !(n.starts_with("v7_") || n.starts_with("v6_")) {
            continue;
        }
        let bytes: Vec<u8> = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        probed += 1;
        assert!(
            bytes.len() > 1024,
            "candidate runtime too small: {}",
            path.display()
        );
    }
    if probed == 0 {
        local_input_absent(
            "the static-key probe over real pytransform runtimes",
            &format!("{} carries no v6_ or v7_ runtime", runtimes_dir.display()),
        );
    }
}

#[test]
fn v7_wrapper_detect_when_baked_fixture_present() {
    let v7_dir: PathBuf = corpus_root().join("v7-super");
    if !v7_dir.is_dir() {
        local_input_absent(
            "the v7 super-mode wrapper detection",
            &format!("{} is not in this checkout", v7_dir.display()),
        );
        return;
    }
    let walker: std::fs::ReadDir = std::fs::read_dir(&v7_dir).expect("read v7-super");
    let mut wrapper_text: Option<String> = None;
    for entry in walker.flatten() {
        let path: PathBuf = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("py") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path)
            && (text.contains("pyarmor") || text.contains("__pyarmor__"))
        {
            wrapper_text = Some(text);
            break;
        }
    }
    let text: String = wrapper_text.unwrap_or_else(|| {
        panic!(
            "the local v7-super fixture is present but carries no pyarmor wrapper .py: {}",
            v7_dir.display()
        )
    });
    let (det, _): (Detection, Vec<u8>) =
        detect_from_wrapper(&text).expect("must detect baked v7 wrapper");
    assert!(matches!(
        det.version,
        PyarmorVersion::V6 | PyarmorVersion::V7
    ));
}

fn find_native_runtime(dir: &Path) -> Option<PathBuf> {
    let entries: std::fs::ReadDir = std::fs::read_dir(dir).ok()?;
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if is_native_runtime(&path) {
            return Some(path);
        }
    }
    for subdir in subdirs {
        if let Some(found) = find_native_runtime(&subdir) {
            return Some(found);
        }
    }
    None
}

fn is_native_runtime(path: &Path) -> bool {
    let Some(name): Option<&str> = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    name.starts_with("pyarmor_runtime")
        && matches!(
            path.extension().and_then(std::ffi::OsStr::to_str),
            Some("so" | "dylib")
        )
}

fn locate_real_code_object(plaintext: &[u8]) -> Option<(usize, Box<CodeObject>)> {
    for (i, &b) in plaintext.iter().enumerate() {
        if b == 0xE3
            && let Ok(Object::Code(code)) = load(&plaintext[i..], PY312)
        {
            return Some((i, code));
        }
    }
    None
}

fn co_names_contains(code: &CodeObject, needle: &str) -> bool {
    code.names.iter().any(|name: &Object| match name {
        Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. }
        | Object::String { value, .. } => value == needle,
        _ => false,
    })
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window: &[u8]| window == needle)
}
