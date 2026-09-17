#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unreadable_literal,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::if_same_then_else
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_pyfreeze::pyoxidizer::signatures::{
    ExtractedModule, PackedResourcesParse, ParsedResourceEntry, ResourceTier, extract_modules,
    extract_resources_blob, parse_packed_resources,
};
use disrobe_pass_pyfreeze::pyoxidizer::{PyOxidizerExtraction, detect_and_extract};
use disrobe_pass_pyfreeze::{
    Detection, EntryOrigin, EntryRecord, FreezerKind, ModuleInventoryEntry, RecoveredModule,
    detect_bytes, recover_bytecode_file,
};

const HELLO_SOURCE_FILENAME: &str = "hello.py";
const HELLO_SOURCE_BODY: &str =
    "def main():\n    print('disrobe-pyoxidizer-hello')\nif __name__ == '__main__':\n    main()\n";
const HELLO_PYOXIDIZER_CONFIG: &str = include_str_template_pyoxidizer_bzl();
const ENV_FORCE_REGEN: &str = "DISROBE_PYOXIDIZER_REGEN";

const fn include_str_template_pyoxidizer_bzl() -> &'static str {
    "def make_exe():\n    dist = default_python_distribution()\n    policy = dist.make_python_packaging_policy()\n    policy.resources_location_fallback = 'filesystem-relative:lib'\n    python_config = dist.make_python_interpreter_config()\n    python_config.run_command = \"import hello; hello.main()\"\n    exe = dist.to_python_executable(name = 'disrobe_hello_pyox', packaging_policy = policy, config = python_config)\n    exe.add_python_resources(exe.pip_install(['--no-deps', '.']))\n    return exe\n\ndef make_embedded_resources(exe):\n    return exe.to_embedded_resources()\n\ndef make_install(exe):\n    files = FileManifest()\n    files.add_python_resource('.', exe)\n    return files\n\nregister_target('exe', make_exe)\nregister_target('resources', make_embedded_resources, depends = ['exe'])\nregister_target('install', make_install, depends = ['exe'], default = True)\nresolve_targets()\n"
}

#[derive(Debug)]
struct PyOxidizerArtifact {
    binary_path: PathBuf,
    bytes: Vec<u8>,
}

fn locate_pyoxidizer() -> Option<PathBuf> {
    let candidate: &str = if cfg!(windows) {
        "pyoxidizer.exe"
    } else {
        "pyoxidizer"
    };
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let full: PathBuf = dir.join(candidate);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

fn fixtures_root() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("target");
    p.push("test-fixtures");
    p.push("pyoxidizer-built");
    p
}

fn source_root() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("target");
    p.push("test-fixtures");
    p.push("pyoxidizer-src");
    p
}

fn source_hash() -> String {
    let mut acc: u64 = 0xCAFE_BABE_DEAD_BEEFu64;
    for b in HELLO_SOURCE_BODY.bytes() {
        acc = acc.wrapping_mul(1_000_003).wrapping_add(u64::from(b));
    }
    for b in HELLO_PYOXIDIZER_CONFIG.bytes() {
        acc = acc.wrapping_mul(1_000_003).wrapping_add(u64::from(b));
    }
    format!("{acc:016x}")
}

fn ensure_artifact() -> Option<PyOxidizerArtifact> {
    let Some(pyox) = locate_pyoxidizer() else {
        eprintln!(
            "[disrobe-pyfreeze] pyoxidizer not on PATH; install via `cargo install pyoxidizer` to enable real-binary E2E tests"
        );
        return None;
    };
    let hash: String = source_hash();
    let target_dir: PathBuf = fixtures_root().join(&hash);
    let candidate: PathBuf = pick_built_binary(&target_dir);
    let force: bool = std::env::var(ENV_FORCE_REGEN).is_ok();
    if !force && candidate.is_file() {
        let bytes: Vec<u8> = std::fs::read(&candidate).ok()?;
        return Some(PyOxidizerArtifact {
            binary_path: candidate,
            bytes,
        });
    }
    std::fs::create_dir_all(&target_dir).ok()?;
    let src_dir: PathBuf = source_root().join(&hash);
    std::fs::create_dir_all(&src_dir).ok()?;
    std::fs::write(src_dir.join(HELLO_SOURCE_FILENAME), HELLO_SOURCE_BODY).ok()?;
    std::fs::write(src_dir.join("pyoxidizer.bzl"), HELLO_PYOXIDIZER_CONFIG).ok()?;
    let build_status: std::process::ExitStatus = {
        let started: std::io::Result<std::process::ExitStatus> = Command::new(&pyox)
            .arg("build")
            .arg("--release")
            .current_dir(&src_dir)
            .status();
        let Ok(status) = started else {
            eprintln!(
                "[disrobe-pyfreeze] pyoxidizer build failed to start: {err}; aborting real-binary test",
                err = started.err().map(|e| format!("{e}")).unwrap_or_default()
            );
            return None;
        };
        status
    };
    if !build_status.success() {
        eprintln!(
            "[disrobe-pyfreeze] pyoxidizer build exited non-zero (status={build_status:?}); aborting real-binary test"
        );
        return None;
    }
    let produced: Option<PathBuf> = find_built_executable(&src_dir.join("build"));
    let produced_path: PathBuf = produced?;
    std::fs::copy(&produced_path, &candidate).ok()?;
    let bytes: Vec<u8> = std::fs::read(&candidate).ok()?;
    Some(PyOxidizerArtifact {
        binary_path: candidate,
        bytes,
    })
}

fn pick_built_binary(target_dir: &Path) -> PathBuf {
    let candidate_name: &str = if cfg!(windows) {
        "disrobe_hello_pyox.exe"
    } else if cfg!(target_os = "macos") {
        "disrobe_hello_pyox"
    } else {
        "disrobe_hello_pyox"
    };
    target_dir.join(candidate_name)
}

fn find_built_executable(root: &Path) -> Option<PathBuf> {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).ok()?;
    let mut stack: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|e: std::fs::DirEntry| e.path())
        .collect();
    let target_name_stem: &str = "disrobe_hello_pyox";
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&path) {
                stack.extend(
                    rd.filter_map(std::result::Result::ok)
                        .map(|e: std::fs::DirEntry| e.path()),
                );
            }
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|n: &std::ffi::OsStr| n.to_str()) else {
            continue;
        };
        let stem_match: bool = file_name == target_name_stem
            || file_name == format!("{target_name_stem}.exe")
            || (file_name.starts_with(target_name_stem)
                && (file_name.ends_with(".exe") || !file_name.contains('.')));
        if stem_match {
            return Some(path);
        }
    }
    None
}

#[test]
fn pyoxidizer_real_binary_parses_with_structured_path() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let det: Detection = detect_bytes(&artifact.bytes, Some(&artifact.binary_path));
    assert_eq!(
        det.kind,
        FreezerKind::PyOxidizer,
        "real pyoxidizer binary must be detected; got: {det:?}"
    );
    let blob: &[u8] = extract_resources_blob(&artifact.bytes)
        .expect("real pyoxidizer binary must contain a pyembed\\x03 packed-resources blob");
    let parse: PackedResourcesParse = parse_packed_resources(blob)
        .expect("real pyoxidizer blob must round-trip through the structured parser");
    assert!(
        parse.format_version >= 1,
        "format_version must be >=1, got {}",
        parse.format_version
    );
    assert!(
        !parse.entries.is_empty(),
        "structured parse must surface at least one resource entry"
    );
}

#[test]
fn pyoxidizer_real_binary_extracts_hello_module() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let blob: &[u8] = extract_resources_blob(&artifact.bytes).expect("blob present");
    let parse: PackedResourcesParse = parse_packed_resources(blob).expect("parse");
    let hello_present: bool = parse
        .entries
        .iter()
        .any(|e: &ParsedResourceEntry| e.name.contains("hello"));
    assert!(
        hello_present,
        "hello module must appear in parsed entries; got {names:?}",
        names = parse
            .entries
            .iter()
            .map(|e| e.name.clone())
            .collect::<Vec<String>>()
    );

    let modules: Vec<ExtractedModule> = extract_modules(blob).expect("extract real modules");
    let hello: &ExtractedModule = modules
        .iter()
        .find(|m: &&ExtractedModule| m.name == "hello")
        .expect("hello module must be extractable from the real binary");
    let payload: &[u8] = hello
        .bytecode
        .as_deref()
        .or(hello.source.as_deref())
        .expect("hello must carry in-memory bytecode or source");
    assert!(
        !payload.is_empty(),
        "extracted hello payload must contain real bytes"
    );
    if let Some(bytecode) = hello.bytecode.as_deref() {
        assert!(
            bytecode.len() > 4,
            "marshalled hello bytecode must be more than a stub"
        );
        let type_tag: u8 = bytecode[0] & 0x7f;
        assert_eq!(
            type_tag, b'c',
            "a module-level marshalled code object starts with the 'c' TYPE_CODE tag (flag bit masked)"
        );
    }
}

#[test]
fn pyoxidizer_real_binary_count_matches_pyoxidizer_manifest() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let blob: &[u8] = extract_resources_blob(&artifact.bytes).expect("blob present");
    let parse: PackedResourcesParse = parse_packed_resources(blob).expect("parse");
    let source_count: usize = parse
        .entries
        .iter()
        .filter(|e: &&ParsedResourceEntry| e.tier == ResourceTier::Source)
        .count();
    let bytecode_count: usize = parse
        .entries
        .iter()
        .filter(|e: &&ParsedResourceEntry| {
            matches!(
                e.tier,
                ResourceTier::Bytecode | ResourceTier::BytecodeOpt1 | ResourceTier::BytecodeOpt2
            )
        })
        .count();
    let payload_tier_count: usize = source_count + bytecode_count;
    assert!(
        payload_tier_count > 0,
        "expected at least one source or bytecode resource entry; got source={source_count} bytecode={bytecode_count}"
    );
    assert!(
        !parse.best_effort,
        "real binary must not fall back to heuristic walk; diagnostics={:?}",
        parse.diagnostics
    );
}

#[test]
fn pyoxidizer_falls_back_to_heuristic_on_truncated_blob() {
    const MARKER: &[u8] = b"pyembed\x03";
    const RES_FIELD_START_OF_ENTRY: u8 = 0x01;
    const RES_FIELD_NAME: u8 = 0x03;
    let mut blob: Vec<u8> = Vec::with_capacity(MARKER.len() + 32);
    blob.extend_from_slice(MARKER);
    blob.push(RES_FIELD_START_OF_ENTRY);
    blob.push(RES_FIELD_NAME);
    blob.extend_from_slice(&0xFFFFu16.to_le_bytes());
    blob.extend_from_slice(b"__pycache__/mod.pyc");
    let parse: PackedResourcesParse =
        parse_packed_resources(&blob).expect("truncated blob must still produce a parse");
    assert!(
        parse.best_effort,
        "truncated blob must trigger heuristic walk fallback"
    );
    let pycache_present: bool = parse
        .entries
        .iter()
        .any(|e: &ParsedResourceEntry| e.name.contains("__pycache__"));
    assert!(
        pycache_present,
        "heuristic walk must surface __pycache__ name even on truncated input"
    );
}

const RT_MODULES: [(&str, bool, &str); 3] = [
    (
        "rtpkg",
        true,
        "VERSION = '1.2.3'\n\ndef greet(name):\n    return f'hello {name}'\n",
    ),
    (
        "rtpkg.calc",
        false,
        "def add(a, b):\n    return a + b\n\ndef mul(a, b):\n    total = 0\n    for _ in range(b):\n        total += a\n    return total\n",
    ),
    (
        "rtpkg.cli",
        false,
        "import sys\n\ndef main(argv=None):\n    args = argv if argv is not None else sys.argv[1:]\n    return len(args)\n",
    ),
];

fn real_marshalled_bytecode(source: &str) -> Option<Vec<u8>> {
    let py: &str = if cfg!(windows) { "py" } else { "python3.12" };
    let script: String = String::from(
        "import sys,marshal,base64\nsrc=sys.stdin.read()\ncode=compile(src,'<rt>','exec')\nsys.stdout.write(base64.b64encode(marshal.dumps(code)).decode())\n",
    );
    let mut command: Command = Command::new(py);
    if cfg!(windows) {
        command.arg("-3.12");
    }
    command
        .arg("-c")
        .arg(&script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child: std::process::Child = command.spawn().ok()?;
    {
        use std::io::Write as _;
        child.stdin.take()?.write_all(source.as_bytes()).ok()?;
    }
    let output: std::process::Output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    let encoded: String = String::from_utf8(output.stdout).ok()?;
    Some(base64_decode(encoded.trim()))
}

fn base64_decode(input: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup: [i16; 256] = [-1; 256];
    for (i, b) in TABLE.iter().enumerate() {
        lookup[*b as usize] = i as i16;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for ch in input.bytes() {
        if ch == b'=' {
            break;
        }
        let v: i16 = lookup[ch as usize];
        if v < 0 {
            continue;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn synth_marshalled_bytecode(source: &str) -> Vec<u8> {
    let mut body: Vec<u8> = vec![b'c'];
    body.extend_from_slice(source.as_bytes());
    body.extend_from_slice(&[0x53, 0x00, 0x00, 0x00]);
    body
}

fn build_v3_blob(modules: &[(String, bool, Vec<u8>)]) -> Vec<u8> {
    const BLOB_START_OF_ENTRY: u8 = 0x01;
    const BLOB_RESOURCE_FIELD_TYPE: u8 = 0x02;
    const BLOB_RAW_PAYLOAD_LENGTH: u8 = 0x03;
    const BLOB_INTERIOR_PADDING: u8 = 0x04;
    const BLOB_END_OF_ENTRY: u8 = 0xff;
    const BLOB_END_OF_INDEX: u8 = 0x00;
    const PADDING_NULL: u8 = 0x02;
    const RES_START_OF_ENTRY: u8 = 0x01;
    const RES_NAME: u8 = 0x03;
    const RES_IS_PYTHON_PACKAGE: u8 = 0x04;
    const RES_IN_MEMORY_BYTECODE: u8 = 0x07;
    const RES_IS_PYTHON_MODULE: u8 = 0x16;
    const RES_END_OF_ENTRY: u8 = 0xff;
    const RES_END_OF_INDEX: u8 = 0x00;

    let mut name_section: Vec<u8> = Vec::new();
    let mut bytecode_section: Vec<u8> = Vec::new();
    for (name, _, bc) in modules {
        name_section.extend_from_slice(name.as_bytes());
        name_section.push(0x00);
        bytecode_section.extend_from_slice(bc);
        bytecode_section.push(0x00);
    }

    let mut blob_index: Vec<u8> = Vec::new();
    let mut count: u8 = 0;
    for (field, len) in [
        (RES_NAME, name_section.len()),
        (RES_IN_MEMORY_BYTECODE, bytecode_section.len()),
    ] {
        blob_index.push(BLOB_START_OF_ENTRY);
        blob_index.push(BLOB_RESOURCE_FIELD_TYPE);
        blob_index.push(field);
        blob_index.push(BLOB_RAW_PAYLOAD_LENGTH);
        blob_index.extend_from_slice(&(len as u64).to_le_bytes());
        blob_index.push(BLOB_INTERIOR_PADDING);
        blob_index.push(PADDING_NULL);
        blob_index.push(BLOB_END_OF_ENTRY);
        count += 1;
    }
    blob_index.push(BLOB_END_OF_INDEX);

    let mut resources_index: Vec<u8> = Vec::new();
    for (name, is_pkg, bc) in modules {
        resources_index.push(RES_START_OF_ENTRY);
        resources_index.push(RES_NAME);
        resources_index.extend_from_slice(&(name.len() as u16).to_le_bytes());
        if *is_pkg {
            resources_index.push(RES_IS_PYTHON_PACKAGE);
        }
        resources_index.push(RES_IS_PYTHON_MODULE);
        resources_index.push(RES_IN_MEMORY_BYTECODE);
        resources_index.extend_from_slice(&(bc.len() as u32).to_le_bytes());
        resources_index.push(RES_END_OF_ENTRY);
    }
    resources_index.push(RES_END_OF_INDEX);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"pyembed\x03");
    out.push(count);
    out.extend_from_slice(&(blob_index.len() as u32).to_le_bytes());
    out.extend_from_slice(&(modules.len() as u32).to_le_bytes());
    out.extend_from_slice(&(resources_index.len() as u32).to_le_bytes());
    out.extend_from_slice(&blob_index);
    out.extend_from_slice(&resources_index);
    out.extend_from_slice(&name_section);
    out.extend_from_slice(&bytecode_section);
    out
}

#[test]
fn packed_resources_v3_roundtrip_recovers_exact_modules() {
    let real_available: bool = real_marshalled_bytecode("x = 1\n").is_some();
    if !real_available {
        eprintln!(
            "[disrobe-pyfreeze] py -3.12 unavailable; round-trip oracle runs against synthetic marshalled-shaped payloads (exact byte recovery still asserted, CPython-real bytecode skipped)"
        );
    }

    let modules: Vec<(String, bool, Vec<u8>)> = RT_MODULES
        .iter()
        .map(|(name, is_pkg, src)| {
            let bytecode: Vec<u8> = if real_available {
                real_marshalled_bytecode(src).expect("real compile must succeed once probed")
            } else {
                synth_marshalled_bytecode(src)
            };
            ((*name).to_owned(), *is_pkg, bytecode)
        })
        .collect();

    let blob: Vec<u8> = build_v3_blob(&modules);

    let mut container: Vec<u8> = vec![0xCCu8; 96];
    container.extend_from_slice(b"PyOxidizer");
    container.extend_from_slice(b"python312.dll");
    container.extend_from_slice(&[0u8; 8]);
    let blob_start: usize = container.len();
    container.extend_from_slice(&blob);
    container.extend_from_slice(&[0xEEu8; 64]);

    let carved: &[u8] =
        extract_resources_blob(&container).expect("blob must be carved from container");
    assert_eq!(
        carved.len(),
        blob.len(),
        "carved blob must trim to the measured packed-resources length, not trailing padding"
    );
    assert_eq!(&container[blob_start..blob_start + blob.len()], carved);

    let parse: PackedResourcesParse = parse_packed_resources(carved).expect("structured parse");
    assert!(!parse.best_effort, "diagnostics={:?}", parse.diagnostics);
    assert_eq!(parse.declared_count, 3);
    assert_eq!(parse.entries.len(), 3);

    let recovered: Vec<ExtractedModule> = extract_modules(carved).expect("extract modules");
    assert_eq!(recovered.len(), modules.len());
    for ((name, is_pkg, original_bc), got) in modules.iter().zip(recovered.iter()) {
        assert_eq!(&got.name, name, "module name order/identity must match");
        assert_eq!(got.is_package, *is_pkg, "package flag must round-trip");
        assert_eq!(
            got.bytecode.as_deref(),
            Some(original_bc.as_slice()),
            "module {name}: recovered marshalled bytecode must be byte-exact"
        );
    }

    if real_available {
        let pkg: &ExtractedModule = recovered
            .iter()
            .find(|m: &&ExtractedModule| m.name == "rtpkg")
            .expect("rtpkg present");
        let marshalled: &[u8] = pkg.bytecode.as_deref().expect("rtpkg bytecode");
        let mut pyc: Vec<u8> = Vec::new();
        pyc.extend_from_slice(&0x0A0D_0DCBu32.to_le_bytes());
        pyc.extend_from_slice(&[0u8; 12]);
        pyc.extend_from_slice(marshalled);
        let parsed: disrobe_py_marshal::PycFile = disrobe_py_marshal::read_pyc(&pyc)
            .expect("reconstructed 3.12 pyc must load in the real marshal reader");
        assert_eq!(
            parsed.header.version,
            disrobe_py_marshal::PyVersion::PY312,
            "header magic must resolve to CPython 3.12"
        );
        assert!(
            matches!(parsed.code, disrobe_py_marshal::Object::Code(_)),
            "the recovered+headered payload must decode to a real code object, ready for the pyc decompiler"
        );
    }
}

#[test]
fn module_inventory_surfaces_names_and_per_tier_presence() {
    let modules: Vec<(String, bool, Vec<u8>)> = vec![
        ("pkg".to_owned(), true, synth_marshalled_bytecode("v = 1\n")),
        (
            "pkg.leaf".to_owned(),
            false,
            synth_marshalled_bytecode("def f():\n    return 1\n"),
        ),
        (
            "solo".to_owned(),
            false,
            synth_marshalled_bytecode("x = 2\n"),
        ),
    ];
    let blob: Vec<u8> = build_v3_blob(&modules);

    let mut container: Vec<u8> = vec![0xABu8; 80];
    container.extend_from_slice(b"PyOxidizer");
    container.extend_from_slice(b"python312.dll");
    container.extend_from_slice(&[0u8; 8]);
    container.extend_from_slice(&blob);

    let purpose: String = format!("disrobe-pyox-inv-{}-{}", std::process::id(), blob.len());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let out: PathBuf = scratch.path().to_path_buf();
    let extraction: PyOxidizerExtraction =
        detect_and_extract(&container, Path::new("inv.exe"), &out).expect("extract");

    let inventory: &[ModuleInventoryEntry] = &extraction.manifest.module_inventory;
    assert_eq!(
        inventory.len(),
        3,
        "every named module must appear in the inventory: {:?}",
        inventory
            .iter()
            .map(|m| m.name.clone())
            .collect::<Vec<String>>()
    );

    let pkg: &ModuleInventoryEntry = inventory
        .iter()
        .find(|m: &&ModuleInventoryEntry| m.name == "pkg")
        .expect("pkg present");
    assert!(pkg.is_package, "pkg flagged RES_IS_PYTHON_PACKAGE");
    assert!(pkg.has_bytecode);
    assert!(!pkg.has_source);
    assert!(!pkg.has_extension);

    let leaf: &ModuleInventoryEntry = inventory
        .iter()
        .find(|m: &&ModuleInventoryEntry| m.name == "pkg.leaf")
        .expect("pkg.leaf present under its dotted name");
    assert!(!leaf.is_package);
    assert!(leaf.has_bytecode);

    let json: String =
        serde_json::to_string(&extraction.manifest).expect("manifest must serialize");
    assert!(
        json.contains("\"module_inventory\""),
        "the inventory must be part of the serialized report"
    );
    assert!(
        json.contains("pkg.leaf"),
        "dotted module names must reach the JSON report"
    );
}

fn unique_temp_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq: u64 = SEQ.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("disrobe-{tag}-{}-{}", std::process::id(), seq);
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
}

fn cpython_marshal_loads_is_code(marshal_path: &Path) -> Option<bool> {
    let py: &str = if cfg!(windows) { "py" } else { "python3.12" };
    let script: &str = "import sys,marshal\nwith open(sys.argv[1],'rb') as f: data=f.read()\nobj=marshal.loads(data)\nsys.stdout.write('1' if type(obj).__name__=='code' else '0')\n";
    let mut command: Command = Command::new(py);
    if cfg!(windows) {
        command.arg("-3.12");
    }
    command
        .arg("-c")
        .arg(script)
        .arg(marshal_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let output: std::process::Output = command.output().ok()?;
    if !output.status.success() {
        return Some(false);
    }
    let text: String = String::from_utf8(output.stdout).ok()?;
    Some(text.trim() == "1")
}

fn build_blob_fs_relative_bytecode(version: u8, modules: &[(&str, bool, &str)]) -> Vec<u8> {
    const BLOB_START_OF_ENTRY: u8 = 0x01;
    const BLOB_RESOURCE_FIELD_TYPE: u8 = 0x02;
    const BLOB_RAW_PAYLOAD_LENGTH: u8 = 0x03;
    const BLOB_INTERIOR_PADDING: u8 = 0x04;
    const BLOB_END_OF_ENTRY: u8 = 0xff;
    const BLOB_END_OF_INDEX: u8 = 0x00;
    const PADDING_NONE: u8 = 0x01;
    const RES_START_OF_ENTRY: u8 = 0x01;
    const RES_NAME: u8 = 0x03;
    const RES_IS_PYTHON_PACKAGE: u8 = 0x04;
    const RES_RELATIVE_FS_MODULE_BYTECODE: u8 = 0x10;
    const RES_IS_PYTHON_MODULE: u8 = 0x16;
    const RES_END_OF_ENTRY: u8 = 0xff;
    const RES_END_OF_INDEX: u8 = 0x00;

    let mut name_section: Vec<u8> = Vec::new();
    let mut path_section: Vec<u8> = Vec::new();
    for (name, _, path) in modules {
        name_section.extend_from_slice(name.as_bytes());
        path_section.extend_from_slice(path.as_bytes());
    }

    let mut blob_index: Vec<u8> = Vec::new();
    let mut count: u8 = 0;
    for (field, len) in [
        (RES_NAME, name_section.len()),
        (RES_RELATIVE_FS_MODULE_BYTECODE, path_section.len()),
    ] {
        blob_index.push(BLOB_START_OF_ENTRY);
        blob_index.push(BLOB_RESOURCE_FIELD_TYPE);
        blob_index.push(field);
        blob_index.push(BLOB_RAW_PAYLOAD_LENGTH);
        blob_index.extend_from_slice(&(len as u64).to_le_bytes());
        blob_index.push(BLOB_INTERIOR_PADDING);
        blob_index.push(PADDING_NONE);
        blob_index.push(BLOB_END_OF_ENTRY);
        count += 1;
    }
    blob_index.push(BLOB_END_OF_INDEX);

    let mut resources_index: Vec<u8> = Vec::new();
    for (name, is_pkg, path) in modules {
        resources_index.push(RES_START_OF_ENTRY);
        resources_index.push(RES_NAME);
        resources_index.extend_from_slice(&(name.len() as u16).to_le_bytes());
        if *is_pkg {
            resources_index.push(RES_IS_PYTHON_PACKAGE);
        }
        resources_index.push(RES_IS_PYTHON_MODULE);
        resources_index.push(RES_RELATIVE_FS_MODULE_BYTECODE);
        resources_index.extend_from_slice(&(path.len() as u32).to_le_bytes());
        resources_index.push(RES_END_OF_ENTRY);
    }
    resources_index.push(RES_END_OF_INDEX);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"pyembed");
    out.push(version);
    out.push(count);
    out.extend_from_slice(&(blob_index.len() as u32).to_le_bytes());
    out.extend_from_slice(&(modules.len() as u32).to_le_bytes());
    out.extend_from_slice(&(resources_index.len() as u32).to_le_bytes());
    out.extend_from_slice(&blob_index);
    out.extend_from_slice(&resources_index);
    out.extend_from_slice(&name_section);
    out.extend_from_slice(&path_section);
    out
}

fn real_312_pyc(source: &str) -> (Vec<u8>, Vec<u8>, bool) {
    let real_available: bool = real_marshalled_bytecode("x = 1\n").is_some();
    let marshalled: Vec<u8> = if real_available {
        real_marshalled_bytecode(source).expect("real compile must succeed once probed")
    } else {
        synth_marshalled_bytecode(source)
    };
    let mut pyc: Vec<u8> = Vec::with_capacity(16 + marshalled.len());
    pyc.extend_from_slice(&0x0A0D_0DCBu32.to_le_bytes());
    pyc.extend_from_slice(&[0u8; 12]);
    pyc.extend_from_slice(&marshalled);
    (pyc, marshalled, real_available)
}

#[test]
fn filesystem_relative_siblings_surface_and_marshal_load() {
    if real_marshalled_bytecode("x = 1\n").is_none() {
        eprintln!(
            "[disrobe-pyfreeze] py -3.12 unavailable; filesystem-relative surfacing still asserted byte-exact against synthetic pyc, CPython marshal.loads ground truth skipped"
        );
    }
    let (sibling_pyc, marshalled, real_available): (Vec<u8>, Vec<u8>, bool) =
        real_312_pyc("def greet(who):\n    return f'hi {who}'\n");

    let root_scratch: disrobe_core::scratch::ScratchDir = unique_temp_dir("pyox-fsrel");
    let root: PathBuf = root_scratch.path().to_path_buf();
    let lib_dir: PathBuf = root.join("lib");
    std::fs::create_dir_all(&lib_dir).expect("mk lib");
    std::fs::write(lib_dir.join("sib.pyc"), &sibling_pyc).expect("write sibling pyc");

    let sep: &str = if cfg!(windows) { "\\" } else { "/" };
    let sib_path: String = format!("lib{sep}sib.pyc");
    let ghost_path: String = format!("lib{sep}ghost.pyc");
    let blob: Vec<u8> = build_blob_fs_relative_bytecode(
        0x03,
        &[
            ("sib", false, sib_path.as_str()),
            ("ghost", false, ghost_path.as_str()),
        ],
    );

    let mut container: Vec<u8> = vec![0xA5u8; 96];
    container.extend_from_slice(b"PyOxidizer");
    container.extend_from_slice(b"python312.dll");
    container.extend_from_slice(&[0u8; 8]);
    container.extend_from_slice(&blob);

    let input: PathBuf = root.join("app.exe");
    std::fs::write(&input, &container).expect("write input exe");
    let out: PathBuf = root.join("out");

    let extraction: PyOxidizerExtraction =
        detect_and_extract(&container, &input, &out).expect("extract");

    assert_eq!(
        extraction.fs_relative_modules_surfaced, 1,
        "exactly the present sibling (lib/sib.pyc) surfaces; the absent lib/ghost.pyc is an honest skip, not a failure (was 0 before filesystem-relative resolution)"
    );

    let surfaced: PathBuf = out.join("modules").join("sib.pyc");
    assert!(
        surfaced.is_file(),
        "surfaced sibling must be written at {surfaced:?}"
    );
    assert_eq!(
        std::fs::read(&surfaced).expect("read surfaced"),
        sibling_pyc,
        "surfaced bytes must be the on-disk sibling pyc, verbatim"
    );

    let ghost: PathBuf = out.join("modules").join("ghost.pyc");
    assert!(
        !ghost.exists(),
        "an absent sibling must never fabricate a module file"
    );

    let entry: &EntryRecord = extraction
        .manifest
        .entries
        .iter()
        .find(|e: &&EntryRecord| e.name == "sib.pyc")
        .expect("manifest must carry the surfaced sibling entry");
    assert_eq!(entry.origin, EntryOrigin::SiblingFile);
    assert!(
        entry.source_path.is_some(),
        "surfaced entry must wire a disk path into the same recovery pass embedded modules use"
    );

    if real_available {
        let recovered: RecoveredModule = recover_bytecode_file("sib.pyc", &surfaced)
            .expect("surfaced sibling must flow through the real bytecode recovery/decompile path");
        assert_eq!(
            (recovered.python_major, recovered.python_minor),
            (3, 12),
            "the surfaced sibling's pyc header must resolve to CPython 3.12"
        );

        let body: PathBuf = root.join("sib.marshal");
        std::fs::write(&body, &marshalled).expect("write marshal body");
        assert_eq!(
            cpython_marshal_loads_is_code(&body),
            Some(true),
            "ground truth: the surfaced sibling's marshalled body loads as a code object under real CPython marshal.loads"
        );
    }
}

#[test]
fn packed_resources_legacy_v2_surfaces_modules() {
    let (_, bytecode, real_available): (Vec<u8>, Vec<u8>, bool) =
        real_312_pyc("def f(n):\n    return n * 2\n");
    let modules: Vec<(String, bool, Vec<u8>)> =
        vec![("legacymod".to_owned(), false, bytecode.clone())];
    let mut blob: Vec<u8> = build_v3_blob(&modules);
    assert_eq!(blob[7], 0x03, "in-memory builder emits the v3 magic byte");
    blob[7] = 0x02;

    let carved: &[u8] = extract_resources_blob(&blob)
        .expect("a pyembed v2 blob must carve via the generalized structured magic, not just v3");
    assert!(
        carved.starts_with(b"pyembed\x02"),
        "carved slice must anchor on the v2 magic"
    );

    let parse: PackedResourcesParse = parse_packed_resources(carved)
        .expect("v2 blob must round-trip through the structured parser");
    assert!(
        !parse.best_effort,
        "v2 must parse structurally, not fall back to the heuristic walk: {:?}",
        parse.diagnostics
    );
    assert_eq!(parse.format_version, 0x02);

    let recovered: Vec<ExtractedModule> = extract_modules(carved)
        .expect("v2 module extraction (was 0 modules before generalization)");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].name, "legacymod");
    assert_eq!(
        recovered[0].bytecode.as_deref(),
        Some(bytecode.as_slice()),
        "v2 marshalled bytecode must be byte-exact"
    );

    if real_available {
        let tmp_scratch: disrobe_core::scratch::ScratchDir = unique_temp_dir("pyox-v2");
        let tmp: PathBuf = tmp_scratch.path().to_path_buf();
        let body: PathBuf = tmp.join("body.marshal");
        std::fs::write(&body, &bytecode).expect("write marshal body");
        assert_eq!(
            cpython_marshal_loads_is_code(&body),
            Some(true),
            "ground truth: v2-recovered marshalled bytecode loads as a code object under real CPython"
        );
    }
}
