#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest dir has a parent")
        .to_path_buf()
}

fn python_program() -> Option<String> {
    for candidate in ["python", "python3", "py"] {
        let ok: bool = Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|o: Output| o.status.success());
        if ok {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn build_extension_artifact() -> PathBuf {
    let output: Output = Command::new(env!("CARGO"))
        .arg("build")
        .arg("-p")
        .arg("disrobe-python")
        .arg("--message-format=json-render-diagnostics")
        .env("CARGO_INCREMENTAL", "0")
        .current_dir(workspace_root())
        .output()
        .expect("spawning cargo build for disrobe-python");
    assert!(
        output.status.success(),
        "cargo build -p disrobe-python failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout: String = String::from_utf8(output.stdout).expect("cargo json stdout is utf-8");
    let mut artifact: Option<PathBuf> = None;
    for line in stdout.lines() {
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let is_target: bool = value
            .get("target")
            .and_then(|t: &serde_json::Value| t.get("name"))
            .and_then(serde_json::Value::as_str)
            == Some("disrobe");
        if !is_target {
            continue;
        }
        let Some(filenames): Option<&Vec<serde_json::Value>> =
            value.get("filenames").and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for name in filenames {
            let Some(path): Option<&str> = name.as_str() else {
                continue;
            };
            let candidate: PathBuf = PathBuf::from(path);
            if is_dynamic_library(&candidate) {
                artifact = Some(candidate);
            }
        }
    }
    artifact.expect("cargo did not report a cdylib artifact for disrobe-python")
}

fn is_dynamic_library(path: &Path) -> bool {
    path.extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        .is_some_and(|ext: &str| {
            ext.eq_ignore_ascii_case("dll")
                || ext.eq_ignore_ascii_case("so")
                || ext.eq_ignore_ascii_case("dylib")
        })
}

fn import_name(artifact: &Path) -> &'static str {
    match artifact
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
    {
        Some("dll" | "pyd") => "disrobe.pyd",
        _ => "disrobe.so",
    }
}

fn run_python(program: &str, module_dir: &Path, script: &str) -> Output {
    Command::new(program)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", module_dir)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("spawning python")
}

#[test]
fn python_module_imports_and_returns_correct_analysis() {
    let Some(python): Option<String> = python_program() else {
        eprintln!("SKIP: no python interpreter on PATH; cannot exercise the disrobe Python module");
        return;
    };

    let artifact: PathBuf = build_extension_artifact();
    let module_dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let dest: PathBuf = module_dir.path().join(import_name(&artifact));
    std::fs::copy(&artifact, &dest).unwrap_or_else(|e: std::io::Error| {
        panic!("copy {} -> {}: {e}", artifact.display(), dest.display())
    });

    let script: &str = r#"
import pickle, sys

import disrobe

assert isinstance(disrobe.__version__, str) and disrobe.__version__, "module must expose __version__"

# Non-circular oracle: CPython itself produces the pickle stream; disrobe must recover it.
value = {"a": 1, "b": [2, 3], "c": "hi"}
blob = pickle.dumps(value, protocol=4)

dis = disrobe.pickle_disasm(blob)
assert isinstance(dis, str), f"pickle_disasm must return str, got {type(dis)}"
assert "STOP" in dis, f"disasm must end with the STOP opcode:\n{dis}"
assert "EMPTY_DICT" in dis, f"a dict pickle must disassemble with EMPTY_DICT:\n{dis}"

report = disrobe.pickle_decompile(blob)
assert isinstance(report, disrobe.PickleDecompilation), f"pickle_decompile must return a PickleDecompilation, got {type(report)}"
src = report.source
assert isinstance(src, str) and src, "PickleDecompilation.source must be non-empty"
recovered = {}
exec(src, {}, recovered)
assert recovered["result"] == value, f"decompiled source must reconstruct the original value: {src!r} -> {recovered.get('result')!r}"

# A flat list through a different protocol, to prove it is not a fixed fixture.
blob2 = pickle.dumps([10, 20, 30], protocol=2)
report2 = disrobe.pickle_decompile(blob2)
recovered2 = {}
exec(report2.source, {}, recovered2)
assert recovered2["result"] == [10, 20, 30], f"list round-trip failed: {report2.source!r}"

print("PYBIND_OK")
"#;

    let out: Output = run_python(&python, module_dir.path(), script);
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success() && stdout.contains("PYBIND_OK"),
        "python could not import/exercise the disrobe module:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn stage_module() -> (tempfile::TempDir, PathBuf) {
    let artifact: PathBuf = build_extension_artifact();
    let module_dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let dest: PathBuf = module_dir.path().join(import_name(&artifact));
    std::fs::copy(&artifact, &dest).unwrap_or_else(|e: std::io::Error| {
        panic!("copy {} -> {}: {e}", artifact.display(), dest.display())
    });
    let dir: PathBuf = module_dir.path().to_path_buf();
    (module_dir, dir)
}

fn require_fixture(rel: &str) -> Option<PathBuf> {
    let path: PathBuf = workspace_root().join(rel);
    if path.is_file() {
        Some(path)
    } else {
        eprintln!("SKIP: committed fixture absent: {}", path.display());
        None
    }
}

fn run_python_with_root(program: &str, module_dir: &Path, root: &Path, script: &str) -> Output {
    Command::new(program)
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", module_dir)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("DISROBE_TEST_ROOT", root)
        .output()
        .expect("spawning python")
}

fn exercise_binding(rel_fixture: Option<&str>, script_body: &str) {
    let Some(python): Option<String> = python_program() else {
        eprintln!("SKIP: no python interpreter on PATH; cannot exercise the disrobe module");
        return;
    };
    if let Some(rel) = rel_fixture
        && require_fixture(rel).is_none()
    {
        return;
    }
    let (_keep, module_dir): (tempfile::TempDir, PathBuf) = stage_module();
    let root: PathBuf = workspace_root();
    let preamble: &str = "import os\nimport disrobe\nROOT = os.environ[\"DISROBE_TEST_ROOT\"]\n";
    let script: String = String::from(preamble) + script_body;
    let out: Output = run_python_with_root(&python, &module_dir, &root, &script);
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success() && stdout.contains("BIND_OK"),
        "binding script failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn lua_decompile_recovers_print_call_from_real_luac() {
    exercise_binding(
        Some("corpus/lua/luac/hello.5_1.luac"),
        r#"
blob = open(ROOT + "/corpus/lua/luac/hello.5_1.luac", "rb").read()
det = disrobe.lua_detect(blob)
assert det.format == "lua-5.1", det
out = disrobe.lua_decompile(blob)
src = out.source
assert isinstance(src, str) and src, "lua_decompile must return non-empty source"
assert 'print("hello world")' in src, f"expected recovered print call, got:\n{src}"
print("BIND_OK")
"#,
    );
}

#[test]
fn lua_deobfuscate_detects_and_peels_prometheus() {
    exercise_binding(
        Some("corpus/lua/obfuscators/hello.prometheus.lua"),
        r#"
src = open(ROOT + "/corpus/lua/obfuscators/hello.prometheus.lua", "r", encoding="utf-8", errors="replace").read()
rep = disrobe.lua_deobfuscate(src)
assert rep.obfuscator == "prometheus", rep.obfuscator
detection = rep.raw["detection"]
assert detection is not None, "prometheus sample must be detected"
assert detection["confidence"] > 0, detection
assert isinstance(rep.deobfuscated, str)
print("BIND_OK")
"#,
    );
}

#[test]
fn go_analyze_recovers_main_and_runtime_symbols() {
    exercise_binding(
        Some("crates/disrobe-pass-go/tests/fixtures/hello_normal.exe"),
        r#"
blob = open(ROOT + "/crates/disrobe-pass-go/tests/fixtures/hello_normal.exe", "rb").read()
a = disrobe.go_analyze(blob)
funcs = a.raw["symbols"]["funcs"]
assert len(funcs) > 100, f"expected many funcs, got {len(funcs)}"
names = {f["name"] for f in funcs}
assert "main.main" in names, "missing main.main"
assert any(n.startswith("runtime.") for n in names), "missing runtime.* funcs"
bv = a.buildversion or ""
assert bv.startswith("go1."), f"buildversion not recovered: {bv}"
pcl = disrobe.go_pclntab(blob)
assert pcl.ptr_size == 8, pcl
assert pcl.func_count > 100, pcl
assert pcl.version.startswith("go1."), pcl
print("BIND_OK")
"#,
    );
}

#[test]
fn go_garble_recovers_names_on_garbled_binary() {
    exercise_binding(
        Some("crates/disrobe-pass-go/tests/fixtures/hello_garble.exe"),
        r#"
blob = open(ROOT + "/crates/disrobe-pass-go/tests/fixtures/hello_garble.exe", "rb").read()
g = disrobe.go_garble(blob)
assert isinstance(g.quality, str) and g.quality, g.quality
assert isinstance(g.detection_score, int), g.detection_score
raw = g.raw
assert "total_funcs" in raw["name_recovery"], raw["name_recovery"]
assert "plain_ascii" in raw["literal_recovery"], raw["literal_recovery"]
print("BIND_OK")
"#,
    );
}

#[test]
fn ruby_decompile_parses_real_yarv_iseq() {
    exercise_binding(
        Some("corpus/ruby/mri/yarv/hello.rb.yarvc"),
        r#"
blob = open(ROOT + "/corpus/ruby/mri/yarv/hello.rb.yarvc", "rb").read()
det = disrobe.ruby_detect(blob)
assert det.flavor == "yarv-binary", det
a = disrobe.ruby_decompile(blob)
assert a.flavor == "yarv-binary", a
yarv = a.raw["yarv"]
assert yarv is not None, "yarv analysis must be present"
assert yarv["header"]["major"] == 3 and yarv["header"]["minor"] == 4, yarv["header"]
assert "ruby 3.4" in yarv["disasm_text"], yarv["disasm_text"][:200]
assert isinstance(yarv["decompiled"]["source"], str)
print("BIND_OK")
"#,
    );
}

#[test]
fn php_detect_classifies_real_phar_and_source() {
    exercise_binding(
        Some("corpus/php/phar/hello.phar"),
        r#"
phar = open(ROOT + "/corpus/php/phar/hello.phar", "rb").read()
det = disrobe.php_detect(phar)
assert det.kind in ("PharArchive", "PharStub"), det
assert det.has_halt_compiler is True, det
src = open(ROOT + "/corpus/php/baseline/hello.php", "rb").read()
det2 = disrobe.php_detect(src)
assert det2.kind == "Source", det2
print("BIND_OK")
"#,
    );
}

#[test]
fn php_decode_peels_base64_eval_chain() {
    exercise_binding(
        None,
        r#"
import base64
payload = b"echo 'recovered php payload';"
inner = base64.b64encode(payload).decode("ascii")
loader = ("<?php eval(base64_decode('" + inner + "'));").encode("ascii")
rep = disrobe.php_decode(loader)
assert "recovered php payload" in rep.source, rep.source
layers = rep.raw["layers"]
assert any(l["layer"] == "Base64Decode" for l in layers), layers
print("BIND_OK")
"#,
    );
}

#[test]
fn shell_batch_deobfuscates_real_caret_fixture() {
    exercise_binding(
        Some("corpus/shell/batch/caret/hello.bat"),
        r#"
src = open(ROOT + "/corpus/shell/batch/caret/hello.bat", "r", encoding="utf-8", errors="replace").read()
rep = disrobe.batch_deobfuscate(src)
out = rep.output
assert rep.raw["caret_escapes_removed"] > 0, rep
norm = " ".join(out.split())
assert "echo hello world" in norm, f"caret recovery failed: {out!r}"
print("BIND_OK")
"#,
    );
}

#[test]
fn shell_powershell_detects_and_recovers_iex() {
    exercise_binding(
        Some("corpus/shell/powershell/invoke-obfuscation/token/hello.ps1"),
        r#"
src = open(ROOT + "/corpus/shell/powershell/invoke-obfuscation/token/hello.ps1", "r", encoding="utf-8", errors="replace").read()
det = disrobe.powershell_detect(src)
assert isinstance(det.obfuscator, str) and det.obfuscator, det
assert isinstance(det.confidence, float), det
rev = disrobe.powershell_deobfuscate(".( \"{1}{0}\" -f 'X','IE' )")
assert "IEX" in rev.output, rev.output
print("BIND_OK")
"#,
    );
}

#[test]
fn container_detect_and_lists_members_in_memory() {
    exercise_binding(
        Some("corpus/jvm/r8/Hello-r8.jar"),
        r#"
blob = open(ROOT + "/corpus/jvm/r8/Hello-r8.jar", "rb").read()
det = disrobe.container_detect(blob)
assert det.detected is True, det
assert det.kind == "zip", det
assert det.is_zip_family is True, det
mem = disrobe.container_members(blob)
assert mem.format == "zip", mem
assert mem.listing == "enumerated", mem
names = {e["name"] for e in mem.raw["entries"]}
assert any(n.endswith(".class") for n in names) or "META-INF/MANIFEST.MF" in names, sorted(names)
print("BIND_OK")
"#,
    );
}

#[test]
fn apk_resources_decodes_manifest_arsc_and_certificate() {
    exercise_binding(
        Some("corpus/apk/fixture-v2v3-signed.apk"),
        r#"
blob = open(ROOT + "/corpus/apk/fixture-v2v3-signed.apk", "rb").read()
rep = disrobe.apk_resources(blob)
assert rep.package == "com.disrobe.fixture", rep.package
assert rep.resource_entry_count == 1, rep
raw = rep.raw
assert raw["resource_table_present"] is True, raw
assert raw["package_count"] == 1, raw
ids = {(r["id"], r["name"]) for r in raw["resources"]}
assert (0x7f010000, "com.disrobe.fixture.string.app_name") in ids, sorted(ids)
xml = rep.manifest_xml
assert isinstance(xml, str) and 'package="com.disrobe.fixture"' in xml, xml[:200]
fps = {c["sha256_fingerprint"] for c in raw["certificates"]}
assert "F8:B7:66:4F:AD:A9:B0:F3:9D:7A:97:2A:BB:28:C1:37:09:5C:65:32:09:1E:98:DF:4F:11:3B:31:BF:23:D4:9C" in fps, fps
print("BIND_OK")
"#,
    );
}

#[test]
fn swift_analyze_recovers_objc_classes_and_demangled_swift_symbols() {
    exercise_binding(
        Some("corpus/mobile/macho-mac/SwiftHello.original"),
        r#"
blob = open(ROOT + "/corpus/mobile/macho-mac/SwiftHello.original", "rb").read()
rep = disrobe.swift_analyze(blob)
assert rep.container == "MachO", rep.container
slices = rep.raw["slices"]
assert len(slices) == 1, rep
assert rep.slice_count == 1, rep
slice0 = slices[0]
assert slice0["cpu_label"] == "arm64", slice0["cpu_label"]
s = slice0["metadata_summary"]
assert s["swift_reflected_types"] >= 1, s
assert s["swift_mangled_symbols"] >= 30, s
assert 1 <= s["swift_demangled_symbols"] <= s["swift_mangled_symbols"], s
objc_names = {c["name"] for c in slice0["objc"]["interfaces"]}
assert "_TtC10SwiftHello19LoginViewController" in objc_names, sorted(objc_names)
print("BIND_OK")
"#,
    );
}

#[test]
fn macho_dump_rejects_fat64_slice_range_overflow() {
    exercise_binding(
        None,
        r#"
fat = bytearray()
fat.extend((0xCAFE_BABF).to_bytes(4, "big"))
fat.extend((1).to_bytes(4, "big"))
fat.extend((0x01000007).to_bytes(4, "big"))
fat.extend((3).to_bytes(4, "big"))
fat.extend(((1 << 64) - 16).to_bytes(8, "big"))
fat.extend((32).to_bytes(8, "big"))
fat.extend((0).to_bytes(4, "big"))
fat.extend((0).to_bytes(4, "big"))
try:
    disrobe.macho_dump(bytes(fat))
except disrobe.DisrobeError as exc:
    msg = str(exc)
    assert "overflows" in msg, msg
else:
    raise AssertionError("macho_dump accepted overflowing fat64 slice")
print("BIND_OK")
"#,
    );
}

#[test]
fn pyarmor_classify_marks_real_925_default_as_normal_static_recoverable() {
    exercise_binding(
        Some("corpus/python/pyarmor/v9_latest_925/default/known_plaintext.py"),
        r#"
src = open(ROOT + "/corpus/python/pyarmor/v9_latest_925/default/known_plaintext.py", "r", encoding="utf-8", errors="replace").read()
rep = disrobe.pyarmor_classify(src, b"")
assert rep.script_type == "normal", rep
assert rep.bootstrap_import == "pyarmor_runtime_NNNNNN", rep
assert rep.disposition == "static-recoverable", rep
assert rep.ecc_enabled is False, rep
print("BIND_OK")
"#,
    );
}

fn build_disasm_envelope() -> Vec<u8> {
    use disrobe_core::Rung;
    use disrobe_ir::Envelope;
    use disrobe_ir::payload::{
        DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, encode_disasm,
    };

    let payload: DisasmPayload = DisasmPayload {
        source_hash: [7u8; 32],
        instructions: vec![
            DisasmInstruction {
                offset: 0x0,
                bytes: vec![0xe8, 0, 0, 0, 0],
                mnemonic: "call".to_owned(),
                operands: vec!["0x10".to_owned()],
                flow: InsnFlow::Call,
                branch_target: Some(0x10),
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x5,
                bytes: vec![0xc3],
                mnemonic: "ret".to_owned(),
                operands: vec![],
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x10,
                bytes: vec![0xc3],
                mnemonic: "ret".to_owned(),
                operands: vec![],
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
        ],
        symbol_table: vec![
            DisasmSymbol {
                address: 0x0,
                name: "main".to_owned(),
                kind: DisasmSymbolKind::Export,
            },
            DisasmSymbol {
                address: 0x10,
                name: "helper".to_owned(),
                kind: DisasmSymbolKind::Function,
            },
        ],
    };
    let hot: Vec<u8> = encode_disasm(&payload).expect("encode disasm payload");
    let env: Envelope = Envelope::new(Rung::Disasm, hot, Vec::new());
    env.encode().expect("encode envelope")
}

#[test]
fn query_runs_function_and_call_queries_over_disasm_envelope() {
    let Some(python): Option<String> = python_program() else {
        eprintln!("SKIP: no python interpreter on PATH; cannot exercise the disrobe module");
        return;
    };
    let (_keep, module_dir): (tempfile::TempDir, PathBuf) = stage_module();
    let envelope: Vec<u8> = build_disasm_envelope();
    let dr_path: PathBuf = module_dir.join("module.dr");
    std::fs::write(&dr_path, &envelope).expect("write dr envelope");
    let dr_literal: String = dr_path.display().to_string().replace('\\', "/");
    let script: String = format!(
        r#"
import disrobe
blob = open(r"{dr_literal}", "rb").read()
fns = disrobe.query_functions(blob).raw
assert fns["query"] == "functions", fns
names = {{m["name"] for m in fns["matches"]}}
assert names == {{"main", "helper"}}, names
calls = disrobe.query_calls_to(blob, "helper").raw
assert calls["query"] == "calls-to", calls
assert calls["target"] == "helper", calls
assert len(calls["matches"]) == 1, calls
assert calls["matches"][0]["caller"] == "main", calls
xref = disrobe.query_xrefs_to(blob, "helper").raw
assert xref["query"] == "xrefs-to", xref
assert len(xref["matches"]) == 1, xref
dec = disrobe.query_string_decoders(blob).raw
assert dec["query"] == "string-decoders", dec
try:
    disrobe.query_functions(b"not a dr envelope")
    raise SystemExit("query must reject non-envelope input")
except disrobe.DisrobeError:
    pass
print("BIND_OK")
"#
    );
    let out: Output = run_python(&python, &module_dir, &script);
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success() && stdout.contains("BIND_OK"),
        "query binding script failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

fn flattened_function_bytes() -> Vec<u8> {
    use iced_x86::code_asm::{CodeAssembler, CodeLabel, dword_ptr, eax, rbp};

    const BASE: u64 = 0x1000;
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    let mut dispatcher: CodeLabel = asm.create_label();
    let mut case_a: CodeLabel = asm.create_label();
    let mut case_b: CodeLabel = asm.create_label();
    let mut case_c: CodeLabel = asm.create_label();

    asm.mov(dword_ptr(rbp - 4), 0i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut dispatcher).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 0i32).unwrap();
    asm.je(case_a).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 1i32).unwrap();
    asm.je(case_b).unwrap();
    asm.cmp(dword_ptr(rbp - 4), 2i32).unwrap();
    asm.je(case_c).unwrap();
    asm.ret().unwrap();
    asm.set_label(&mut case_a).unwrap();
    asm.mov(eax, 1i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), 1i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut case_b).unwrap();
    asm.add(eax, 7i32).unwrap();
    asm.mov(dword_ptr(rbp - 4), 2i32).unwrap();
    asm.jmp(dispatcher).unwrap();
    asm.set_label(&mut case_c).unwrap();
    asm.ret().unwrap();
    asm.assemble(BASE).expect("assemble")
}

#[test]
fn native_deobfuscate_unflattens_ollvm_cff_into_linear_order() {
    let Some(python): Option<String> = python_program() else {
        eprintln!("SKIP: no python interpreter on PATH; cannot exercise the disrobe module");
        return;
    };
    let (_keep, module_dir): (tempfile::TempDir, PathBuf) = stage_module();
    let code: Vec<u8> = flattened_function_bytes();
    let code_path: PathBuf = module_dir.join("flattened.bin");
    std::fs::write(&code_path, &code).expect("write flattened code");
    let code_literal: String = code_path.display().to_string().replace('\\', "/");
    let script: String = format!(
        r#"
import disrobe
code = open(r"{code_literal}", "rb").read()
rep = disrobe.native_deobfuscate(code, bits=64, base=0x1000, entry=0x1000)
assert rep.bits == 64, rep
assert rep.fully_recovered is True, rep
assert rep.recovered_blocks == 3, rep
raw = rep.raw
assert raw["base"] == 0x1000 and raw["entry"] == 0x1000, raw
cff = raw["cff"]
assert cff["fully_recovered"] is True, cff
assert cff["recovered_blocks"] == 3, cff
assert cff["dispatcher_address"] is not None, cff
order = cff["linear_order"]
assert order == sorted(order) and len(order) == 3, order
print("BIND_OK")
"#
    );
    let out: Output = run_python(&python, &module_dir, &script);
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success() && stdout.contains("BIND_OK"),
        "native_deobfuscate binding script failed:\nstdout: {stdout}\nstderr: {stderr}"
    );
}
