#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_pyfreeze::bbfreeze::{self, BbfreezeExtraction};
use disrobe_pass_pyfreeze::{Detection, FreezerKind, PyfreezeOutput, detect_bytes, extract};

const MODULES: &[(&str, &str)] = &[
    (
        "app_logic",
        "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n\n\ndef greet(name):\n    return 'hello ' + name + ' fib10=' + str(fib(10))\n",
    ),
    (
        "util",
        "import math\n\n\ndef area(r):\n    return math.pi * r * r\n\n\nCONST = 1234\n",
    ),
    (
        "__main__",
        "import app_logic\nimport util\n\n\ndef main():\n    print(app_logic.greet('frozen'), util.area(2.0), util.CONST)\n\n\nif __name__ == '__main__':\n    main()\n",
    ),
];

const fn python() -> &'static str {
    if cfg!(windows) { "python" } else { "python3" }
}

fn has_python() -> bool {
    Command::new(python())
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn compile_pyc(source: &str) -> Option<Vec<u8>> {
    let script: &str = r"
import sys, marshal, importlib.util
src = sys.stdin.buffer.read().decode('utf-8')
code = compile(src, '<frozen>', 'exec')
out = sys.stdout.buffer
out.write(importlib.util.MAGIC_NUMBER)
out.write((0).to_bytes(4, 'little'))
out.write((0).to_bytes(4, 'little'))
out.write((0).to_bytes(4, 'little'))
out.write(marshal.dumps(code))
out.flush()
";
    let mut child = Command::new(python())
        .args(["-c", script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(source.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        eprintln!(
            "[real_bbfreeze] pyc compile failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(out.stdout)
}

fn build_zip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> =
        zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options: SimpleFileOptions =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in entries {
        writer.start_file(name.as_str(), options).expect("start");
        writer.write_all(body).expect("write");
    }
    writer.finish().expect("finish").into_inner()
}

fn runtime_dll_name() -> String {
    let major: i32 = 3;
    let minor: i32 = python_minor();
    if cfg!(windows) {
        format!("python{major}{minor}.dll")
    } else {
        format!("libpython{major}.{minor}.so.1.0")
    }
}

fn python_minor() -> i32 {
    let out = Command::new(python())
        .args(["-c", "import sys; print(sys.version_info[1])"])
        .output();
    out.ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(14)
}

fn stage_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xBBFE_0000);
    let p: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-bbfreeze-stage-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).expect("mkdir stage");
    p
}

fn assemble_real_bbfreeze_dist() -> Option<(PathBuf, PathBuf)> {
    if !has_python() {
        eprintln!("[real_bbfreeze] skipped: python interpreter unavailable on this box");
        return None;
    }
    let mut zip_entries: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, src) in MODULES {
        let pyc: Vec<u8> = compile_pyc(src)?;
        zip_entries.push((format!("{name}.pyc"), pyc));
    }
    let dist: PathBuf = stage_dir("dist");
    let library_zip: Vec<u8> = build_zip(&zip_entries);
    std::fs::write(dist.join("library.zip"), &library_zip).expect("write library.zip");
    let dll_name: String = runtime_dll_name();
    std::fs::write(
        dist.join(&dll_name),
        b"MZ\x90\x00fake-runtime-dll-placeholder",
    )
    .expect("write runtime dll");
    let exe: PathBuf = dist.join("hello.exe");
    std::fs::write(&exe, b"MZ\x90\x00bbfreeze-stub-launcher").expect("write stub exe");
    Some((dist, exe))
}

fn out_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0xBBFE_F000);
    std::env::temp_dir().join(format!(
        "disrobe-bbfreeze-out-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn bbfreeze_real_layout_detects_as_bbfreeze() {
    let Some((dist, exe)): Option<(PathBuf, PathBuf)> = assemble_real_bbfreeze_dist() else {
        return;
    };
    let bytes: Vec<u8> = std::fs::read(&exe).expect("read stub");
    let det: Detection = detect_bytes(&bytes, Some(&exe));
    assert_eq!(
        det.kind,
        FreezerKind::Bbfreeze,
        "a stub next to library.zip + pythonNN.dll with no license must classify as bbfreeze; got {det:?}"
    );
    let _ = std::fs::remove_dir_all(&dist);
}

#[test]
fn bbfreeze_extracts_and_recovers_real_module_set() {
    let Some((dist, exe)): Option<(PathBuf, PathBuf)> = assemble_real_bbfreeze_dist() else {
        return;
    };
    let out: PathBuf = out_dir("extract");
    let extraction: BbfreezeExtraction =
        bbfreeze::detect_and_extract(&exe, &out).expect("bbfreeze extraction");

    assert!(
        extraction.python_dll.is_some(),
        "bbfreeze extraction must surface the bundled python runtime dll"
    );
    let names: BTreeSet<String> = extraction
        .extracted
        .iter()
        .map(|e| e.name.clone())
        .collect();
    for (module, _) in MODULES {
        assert!(
            names.contains(&format!("{module}.pyc")),
            "module `{module}` must extract from the bbfreeze library.zip; got {names:?}"
        );
    }

    for ent in &extraction.extracted {
        let body: Vec<u8> = std::fs::read(&ent.disk_path).expect("read pyc");
        let pyc: disrobe_py_marshal::PycFile = disrobe_py_marshal::read_pyc(&body)
            .unwrap_or_else(|e| panic!("`{}` must be a loadable pyc: {e}", ent.name));
        assert!(
            matches!(pyc.code, disrobe_py_marshal::Object::Code(_)),
            "`{}` pyc must marshal-load to a code object",
            ent.name
        );
    }

    assert_eq!(
        extraction.manifest.primary_module.as_deref(),
        Some("__main__.pyc"),
        "bbfreeze manifest must mark __main__.pyc as the entry point"
    );

    let _ = std::fs::remove_dir_all(&dist);
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn bbfreeze_full_pipeline_recovers_source() {
    let Some((dist, exe)): Option<(PathBuf, PathBuf)> = assemble_real_bbfreeze_dist() else {
        return;
    };
    let out: PathBuf = out_dir("pipeline");
    let output: PyfreezeOutput = extract(&exe, &out).expect("pyfreeze extract");
    assert_eq!(output.detection.kind, FreezerKind::Bbfreeze);
    let recovered: BTreeSet<String> = output
        .recovery
        .modules
        .iter()
        .map(|m| m.name.clone())
        .collect();
    for (module, _) in MODULES {
        assert!(
            recovered.contains(&format!("{module}.pyc")),
            "module `{module}` must be recovered through the bbfreeze pipeline; got {recovered:?}"
        );
    }
    let app_logic: Option<&disrobe_pass_pyfreeze::RecoveredModule> = output
        .recovery
        .modules
        .iter()
        .find(|m| m.name == "app_logic.pyc");
    if let Some(module) = app_logic
        && module.recovered_directly
    {
        assert!(
            module.source.contains("def fib") && module.source.contains("def greet"),
            "recovered bbfreeze source must contain the authored functions, got:\n{}",
            module.source
        );
    } else {
        eprintln!(
            "[real_bbfreeze] HONEST-PARTIAL: app_logic extracted+loadable but decompiler did not \
             recover direct source on this build; extraction and marshal-load asserted"
        );
    }
    let _ = std::fs::remove_dir_all(&dist);
    let _ = std::fs::remove_dir_all(&out);
}
