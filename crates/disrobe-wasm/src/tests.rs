#![allow(clippy::expect_used)]
use serde_json::Value;

#[test]
fn phar_selected_bzip2_members_match_original_files() {
    let archive: &[u8] = include_bytes!("../../../corpus/php/phar/bzip2.phar");
    let listing: Value = run(super::phar_list, archive);
    assert_eq!(listing["ok"], true);
    assert_eq!(listing["entries"].as_array().expect("members").len(), 3);
    for (index, name, source) in [
        (
            0_u32,
            "index.php",
            &include_bytes!("../../../corpus/php/phar-bz2/src/index.php")[..],
        ),
        (
            1_u32,
            "lib/greeter.php",
            &include_bytes!("../../../corpus/php/phar-bz2/src/lib/greeter.php")[..],
        ),
        (
            2_u32,
            "lib/math.php",
            &include_bytes!("../../../corpus/php/phar-bz2/src/lib/math.php")[..],
        ),
    ] {
        assert_eq!(listing["entries"][index as usize]["name"], name);
        assert_eq!(
            extract_phar_payload(archive, index),
            [&[0][..], source].concat()
        );
    }
    let route: Value = run(super::auto_route, archive);
    assert_eq!(route["primary"]["mode"], "phar_list");
}

#[test]
fn phar_binary_frame_preserves_empty_and_non_utf8_members() {
    let archive: Vec<u8> = phar_fixture(&[("empty.bin", &[]), ("raw.bin", &[0, 255, 128, 13, 10])]);
    assert_eq!(extract_phar_payload(&archive, 0), [0]);
    assert_eq!(extract_phar_payload(&archive, 1), [0, 0, 255, 128, 13, 10]);
    let error: Value =
        serde_json::from_slice(&extract_phar_payload(&archive, 2)).expect("JSON error");
    assert_eq!(error["ok"], false);
    assert!(
        error["error"]
            .as_str()
            .expect("message")
            .contains("out of range")
    );
}

#[test]
fn phar_rejects_colliding_names_and_excessive_browser_lists() {
    let duplicate: Vec<u8> = phar_fixture(&[("same.php", b"first"), ("same.php", b"second")]);
    let result: Value = run(super::phar_list, &duplicate);
    assert_eq!(result["ok"], false);
    assert!(
        result["error"]
            .as_str()
            .expect("message")
            .contains("colliding")
    );
    let names: Vec<String> = (0..4097)
        .map(|index: usize| format!("file-{index}"))
        .collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|name: &String| (name.as_str(), &[][..]))
        .collect();
    let result: Value = run(super::phar_list, &phar_fixture(&entries));
    assert_eq!(result["ok"], false);
    assert!(result["error"].as_str().expect("message").contains("4096"));
}

#[test]
fn phar_lists_oversized_members_but_refuses_their_extraction() {
    let oversized: Vec<u8> = vec![42; 32 * 1024 * 1024 + 1];
    let archive: Vec<u8> = phar_fixture(&[("large.bin", &oversized)]);
    let result: Value = run(super::phar_list, &archive);
    assert_eq!(result["ok"], true);
    assert_eq!(result["entries"][0]["extractable"], false);
    let error: Value =
        serde_json::from_slice(&extract_phar_payload(&archive, 0)).expect("JSON error");
    assert_eq!(error["ok"], false);
    assert!(error["error"].as_str().expect("message").contains("32 MiB"));
}

fn extract_phar_payload(bytes: &[u8], index: u32) -> Vec<u8> {
    let input: *mut u8 = write_input(bytes);
    let result: *mut u8 = unsafe { super::phar_extract(input, bytes.len(), index) };
    assert!(!result.is_null());
    let len: usize = unsafe { super::disrobe_result_len(result) } as usize;
    let output: Vec<u8> =
        unsafe { core::slice::from_raw_parts(result.add(super::RESULT_HEADER_LEN), len) }.to_vec();
    unsafe {
        super::disrobe_result_free(result);
        super::disrobe_free(input, bytes.len());
    }
    output
}

fn phar_fixture(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut manifest: Vec<u8> = Vec::new();
    push_le_u32(
        &mut manifest,
        u32::try_from(entries.len()).expect("member count"),
    );
    manifest.extend_from_slice(&0x0011_u16.to_be_bytes());
    manifest.extend_from_slice(&[0; 12]);
    for &(name, bytes) in entries {
        push_le_u32(
            &mut manifest,
            u32::try_from(name.len()).expect("name length"),
        );
        manifest.extend_from_slice(name.as_bytes());
        let size: u32 = u32::try_from(bytes.len()).expect("member size");
        for value in [size, 0, size, 0, 0, 0] {
            push_le_u32(&mut manifest, value);
        }
    }
    let mut output: Vec<u8> = b"<?php __HALT_COMPILER(); ?>\n".to_vec();
    push_le_u32(
        &mut output,
        u32::try_from(manifest.len()).expect("manifest length"),
    );
    output.extend_from_slice(&manifest);
    for &(_, bytes) in entries {
        output.extend_from_slice(bytes);
    }
    output
}

#[test]
fn dart_kernel_preserves_the_compiled_source_record() {
    let bytes: &[u8] = include_bytes!(
        "../../disrobe-pass-mobile/tests/fixtures/flutter_symbol_dart_3_12_2/symbol_probe.app.dill"
    );
    let source: &str = include_str!(
        "../../disrobe-pass-mobile/tests/fixtures/flutter_symbol_dart_3_12_2/symbol_probe.dart"
    );
    let result: Value = run(super::dart_kernel, bytes);
    assert_eq!(result["ok"], true);
    assert_eq!(result["kernel"]["format_version"], 130);
    assert_eq!(
        result["kernel"]["sources"]
            .as_array()
            .expect("source records")
            .len(),
        1
    );
    assert_eq!(
        result["kernel"]["sources"][0]["uri"],
        "disrobe-fixture:///symbol_probe.dart"
    );
    assert_eq!(result["kernel"]["sources"][0]["text"], source);
    let route: Value = run(super::auto_route, bytes);
    assert_eq!(route["primary"]["mode"], "dart_kernel");
}

#[test]
fn dart_kernel_rejects_missing_component_sections() {
    for bytes in [
        &b"ordinary input"[..],
        &[0x90, 0xab, 0xcd, 0xef, 0, 0, 0, 130][..],
    ] {
        let result: Value = run(super::dart_kernel, bytes);
        assert_eq!(result["ok"], false);
        assert!(
            result["error"]
                .as_str()
                .expect("error")
                .contains("Dart Kernel")
        );
    }
}

#[test]
fn resource_only_apk_routes_to_manifest_and_resource_inspection() {
    let bytes: &[u8] = include_bytes!("../../../corpus/apk/fixture-res.apk");
    let result: Value = run(super::auto_route, bytes);
    assert_eq!(result["primary"]["mode"], "apk_analyze");
}

#[test]
fn apk_inspection_recovers_manifest_and_signing_metadata() {
    let bytes: &[u8] = include_bytes!("../../../corpus/apk/fixture-v2v3-signed.apk");
    let result: Value = run(super::apk_analyze, bytes);
    assert_eq!(result["ok"], true);
    assert_eq!(result["entry_count"], 6);
    assert_eq!(result["decoded_bytes"], 5132);
    assert_eq!(
        result["report"]["manifest"]["package"],
        "com.disrobe.fixture"
    );
    assert_eq!(result["report"]["manifest"]["version_name"], "1.0");
    assert_eq!(result["report"]["signing"]["signing_block_present"], true);
    assert_eq!(
        result["report"]["signing"]["schemes"]
            .as_array()
            .expect("schemes")
            .len(),
        2
    );
    assert_eq!(result["resource_table_status"], "decoded");
}

#[test]
fn apk_resource_recovery_does_not_require_dex() {
    let bytes: &[u8] = include_bytes!("../../../corpus/apk/fixture-res.apk");
    let result: Value = run(super::apk_analyze, bytes);
    assert_eq!(result["ok"], true);
    assert_eq!(result["entry_count"], 4);
    assert_eq!(result["decoded_bytes"], 3984);
    assert_eq!(result["resource_xml_entries"], 2);
    assert_eq!(
        result["report"]["resources_decoded"]["decoded_xml"]
            .as_array()
            .expect("resource XML")
            .len(),
        2
    );
}

#[test]
fn apk_inspection_rejects_oversized_entries_before_decompression() {
    let result: Value = run(super::apk_analyze, &apk_with_oversized_classes_dex());
    assert_eq!(result["ok"], false);
    assert!(
        result["error"]
            .as_str()
            .expect("error")
            .contains("32 MiB decoded limit")
    );
}

#[test]
fn apk_inspection_rejects_an_ordinary_zip_and_invalid_manifest() {
    for (name, data, error) in [
        (
            "README.txt",
            b"hello".as_slice(),
            "root AndroidManifest.xml",
        ),
        (
            "AndroidManifest.xml",
            b"not Android XML".as_slice(),
            "APK manifest:",
        ),
    ] {
        let result: Value = run(super::apk_analyze, &zip_bytes(&[(name, data)]));
        assert_eq!(result["ok"], false);
        assert!(result["error"].as_str().expect("error").contains(error));
    }
}

#[test]
fn apk_inspection_preserves_missing_and_undecoded_resource_status() {
    use std::io::Read;
    let fixture: &[u8] = include_bytes!("../../../corpus/apk/fixture-v2v3-signed.apk");
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(std::io::Cursor::new(fixture)).expect("fixture archive");
    let mut manifest: Vec<u8> = Vec::new();
    archive
        .by_name("AndroidManifest.xml")
        .expect("fixture manifest")
        .read_to_end(&mut manifest)
        .expect("manifest bytes");
    for (table, status) in [
        (None, "missing"),
        (Some(b"invalid resource table".as_slice()), "undecoded"),
    ] {
        let mut files: Vec<(&str, &[u8])> = vec![("AndroidManifest.xml", &manifest)];
        if let Some(bytes) = table {
            files.push(("resources.arsc", bytes));
        }
        let result: Value = run(super::apk_analyze, &zip_bytes(&files));
        assert_eq!(result["ok"], true);
        assert_eq!(result["resource_table_status"], status);
        assert_eq!(
            result["report"]["manifest"]["package"],
            "com.disrobe.fixture"
        );
    }
}

#[test]
fn apk_directory_rejects_duplicate_names_and_aggregate_overflow() {
    let duplicate: Vec<u8> = zip_headers(&[("AndroidManifest.xml", 0), ("AndroidManifest.xml", 0)]);
    let result: Value = run(super::apk_analyze, &duplicate);
    assert_eq!(result["ok"], false);
    assert!(
        result["error"]
            .as_str()
            .expect("error")
            .contains("duplicate entry names")
    );
    let entries: [(&str, u32); 5] = [
        ("AndroidManifest.xml", 32 << 20),
        ("a", 32 << 20),
        ("b", 32 << 20),
        ("c", 32 << 20),
        ("d", 32 << 20),
    ];
    let result: Value = run(super::apk_analyze, &zip_headers(&entries));
    assert_eq!(result["ok"], false);
    assert!(
        result["error"]
            .as_str()
            .expect("error")
            .contains("128 MiB decoded archive limit")
    );
}

fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut archive: zip::ZipWriter<std::io::Cursor<Vec<u8>>> =
        zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for &(name, bytes) in files {
        archive
            .start_file(name, zip::write::SimpleFileOptions::default())
            .expect("ZIP entry");
        archive.write_all(bytes).expect("ZIP bytes");
    }
    archive.finish().expect("complete ZIP").into_inner()
}

const SAMPLE_PYC: &[u8] = include_bytes!("../tests/fixtures/sample.pyc");
const BENIGN_PICKLE: &[u8] = include_bytes!("../tests/fixtures/benign_list.pkl");
const MALICIOUS_PICKLE: &[u8] = include_bytes!("../tests/fixtures/reduce_os_system.pkl");
const UNSAFE_ATOMIC_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00, 0x05, 0x04, 0x01, 0x03, 0x01, 0x02, 0x07, 0x08, 0x01, 0x04, 0x6c, 0x6f,
    0x61, 0x64, 0x00, 0x00, 0x0a, 0x0a, 0x01, 0x08, 0x00, 0x20, 0x00, 0xfe, 0x10, 0x02, 0x00, 0x0b,
];
const SHARED_ATOMIC_WAT: &str = r#"
(module
  (memory (export "memory") 1 1 shared)
  (func (export "notify") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    memory.atomic.notify))
"#;

fn write_input(bytes: &[u8]) -> *mut u8 {
    let ptr: *mut u8 = super::disrobe_alloc(bytes.len());
    assert!(!ptr.is_null());
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    }
    ptr
}

fn read_result_json(result: *mut u8) -> Value {
    assert!(!result.is_null());
    let payload_len: usize = unsafe { super::disrobe_result_len(result) } as usize;
    let json_bytes: &[u8] =
        unsafe { core::slice::from_raw_parts(result.add(super::RESULT_HEADER_LEN), payload_len) };
    let parsed: Value = serde_json::from_slice(json_bytes).expect("result payload is valid JSON");
    unsafe { super::disrobe_result_free(result) };
    parsed
}

fn run(entry: unsafe extern "C" fn(*const u8, usize) -> *mut u8, bytes: &[u8]) -> Value {
    let input: *mut u8 = write_input(bytes);
    let result: *mut u8 = unsafe { entry(input, bytes.len()) };
    unsafe { super::disrobe_free(input, bytes.len()) };
    read_result_json(result)
}

#[test]
fn alloc_zero_yields_freeable_pointer() {
    let ptr: *mut u8 = super::disrobe_alloc(0);
    assert!(!ptr.is_null());
    unsafe { super::disrobe_free(ptr, 0) };
}

#[test]
fn alloc_over_cap_returns_null() {
    let ptr: *mut u8 = super::disrobe_alloc(super::MAX_GUEST_ALLOC + 1);
    assert!(ptr.is_null());
}

#[test]
fn result_header_encodes_payload_length() {
    let payload: &[u8] = br#"{"ok":true}"#;
    let result: *mut u8 = super::pack_result(payload);
    let len: u32 = unsafe { super::disrobe_result_len(result) };
    assert_eq!(len as usize, payload.len());
    let body: &[u8] =
        unsafe { core::slice::from_raw_parts(result.add(super::RESULT_HEADER_LEN), len as usize) };
    assert_eq!(body, payload);
    unsafe { super::disrobe_result_free(result) };
}

#[test]
fn result_over_cap_returns_error_payload() {
    let payload: &[u8] = b"abcdef";
    let result: *mut u8 = super::pack_result_with_cap(payload, 3);
    let json: Value = read_result_json(result);
    assert_eq!(json["ok"], Value::Bool(false));
    assert!(
        json["error"]
            .as_str()
            .expect("error")
            .contains("output cap")
    );
}

#[test]
fn over_cap_input_len_is_reported() {
    let ptr: *mut u8 = super::disrobe_alloc(1);
    assert!(!ptr.is_null());
    let result: *mut u8 = unsafe { super::detect(ptr, super::MAX_INPUT_BYTES + 1) };
    unsafe { super::disrobe_free(ptr, 1) };
    let json: Value = read_result_json(result);
    assert_eq!(json["ok"], Value::Bool(false));
    assert!(json["error"].as_str().expect("error").contains("input cap"));
}

#[test]
fn py_disasm_roundtrip_emits_instructions() {
    let json: Value = run(super::py_disasm, SAMPLE_PYC);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["format"], "pyc");
    assert!(
        json["instruction_count"].as_u64().expect("count") > 0,
        "expected a non-empty instruction stream"
    );
    assert!(
        json["listing"]
            .as_str()
            .expect("listing")
            .contains("RESUME")
            || !json["listing"].as_str().expect("listing").is_empty()
    );
}

#[test]
fn py_decompile_roundtrip_emits_source() {
    let json: Value = run(super::py_decompile, SAMPLE_PYC);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["format"], "pyc");
    assert!(
        json["python_version"]
            .as_str()
            .expect("version")
            .starts_with("3.")
    );
    assert!(!json["source"].as_str().expect("source").is_empty());
}

#[test]
fn pickle_disasm_roundtrip_reports_protocol() {
    let json: Value = run(super::pickle_disasm, BENIGN_PICKLE);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["format"], "pickle");
    assert!(json["opcode_count"].as_u64().expect("count") > 0);
}

#[test]
fn pickle_safety_flags_reduce_os_system() {
    let json: Value = run(super::pickle_safety, MALICIOUS_PICKLE);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(
        json["severity"], "overtly_malicious",
        "reduce/os.system must be overtly malicious"
    );
    assert!(json["finding_count"].as_u64().expect("findings") > 0);
}

#[test]
fn pickle_safety_benign_is_not_malicious() {
    let json: Value = run(super::pickle_safety, BENIGN_PICKLE);
    assert_ne!(
        json["severity"], "overtly_malicious",
        "a plain list pickle must not be flagged overtly malicious"
    );
}

#[test]
fn detect_classifies_pyc() {
    let json: Value = run(super::detect, SAMPLE_PYC);
    assert_eq!(json["format"], "pyc");
    assert!(
        json["suggested_command"]
            .as_str()
            .expect("cmd")
            .contains("py decompile")
    );
}

#[test]
fn detect_classifies_pickle() {
    let json: Value = run(super::detect, MALICIOUS_PICKLE);
    assert_eq!(json["format"], "pickle");
}

#[test]
fn detect_classifies_wasm() {
    let module: &[u8] = b"\0asm\x01\x00\x00\x00";
    let json: Value = run(super::detect, module);
    assert_eq!(json["format"], "wasm");
}

#[test]
fn detect_unknown_for_garbage() {
    let json: Value = run(super::detect, b"not a known format at all");
    assert_eq!(json["format"], "unknown");
}

#[test]
fn wasm_analyze_reports_on_minimal_module() {
    let module: &[u8] = b"\0asm\x01\x00\x00\x00";
    let json: Value = run(super::wasm_analyze, module);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["format"], "wasm");
}

#[test]
fn wasm_signatures_carries_the_validated_boundary_links_document() {
    let module: Vec<u8> = wat::parse_str(
        r#"(module
            (import "host" "call" (func (param i32)))
            (import "host" "memory" (memory 1))
            (import "host" "table" (table 1 funcref))
            (import "host" "global" (global i32))
            (export "call_out" (func 0))
            (export "memory_out" (memory 0))
            (export "table_out" (table 0))
            (export "global_out" (global 0)))"#,
    )
    .expect("boundary module assembles");
    let json: Value = run(super::wasm_signatures, &module);
    assert_eq!(json["ok"], Value::Bool(true), "wasm signatures: {json}");
    let boundary_links: Value = json
        .get("boundary_links")
        .expect("wasm signatures includes boundary links")
        .clone();
    let encoded: Vec<u8> = serde_json::to_vec(&boundary_links).expect("encode boundary links");
    let expected: Vec<u8> = disrobe_pass_wasm_deob::extract_signatures(&module)
        .expect("extract boundary links")
        .boundary_links()
        .to_json()
        .expect("serialize boundary links");
    let decoded: disrobe_pass_wasm_deob::BoundaryLinks =
        disrobe_pass_wasm_deob::BoundaryLinks::from_json(&encoded).expect("validated links");

    let reserialized: Vec<u8> = decoded.to_json().expect("re-serialize boundary links");
    assert_eq!(reserialized, expected);
    assert_eq!(decoded.schema_version(), 1);
    assert_eq!(decoded.links().len(), 8);
    assert_eq!(
        json["boundary_link_collection_status"]["status"],
        "complete"
    );
}

#[test]
fn wasm_signatures_keeps_an_empty_boundary_links_document() {
    let json: Value = run(super::wasm_signatures, b"\0asm\x01\x00\x00\x00");
    let boundary_links: Value = json
        .get("boundary_links")
        .expect("wasm signatures includes empty boundary links")
        .clone();
    let encoded: Vec<u8> = serde_json::to_vec(&boundary_links).expect("encode boundary links");
    let decoded: disrobe_pass_wasm_deob::BoundaryLinks =
        disrobe_pass_wasm_deob::BoundaryLinks::from_json(&encoded).expect("validated empty links");

    assert_eq!(decoded.schema_version(), 1);
    assert!(decoded.links().is_empty());
}

#[test]
fn wasm_signatures_reports_truncated_boundary_links_without_losing_exports() {
    let maximum: usize = disrobe_pass_wasm_deob::MAX_BOUNDARY_LINKS;
    let count: usize = maximum + 1;
    let mut source: String = "(module (func $body)".to_owned();
    for index in 0..count {
        source.push_str("(export \"call_");
        source.push_str(&index.to_string());
        source.push_str("\" (func $body))");
    }
    source.push(')');
    let module: Vec<u8> = wat::parse_str(&source).expect("export module assembles");
    let json: Value = run(super::wasm_signatures, &module);
    assert_eq!(json["ok"], true, "wasm signatures: {json}");
    assert_eq!(
        json["boundary_link_collection_status"],
        serde_json::json!({"status": "truncated", "link_count": count, "retained_link_count": maximum}),
    );
    assert_eq!(json["defined_function_count"], 1);
    assert_eq!(
        json["summary"]["exports"]
            .as_array()
            .expect("exports")
            .len(),
        count
    );
    let encoded: Vec<u8> =
        serde_json::to_vec(&json["boundary_links"]).expect("encode boundary links");
    let links: disrobe_pass_wasm_deob::BoundaryLinks =
        disrobe_pass_wasm_deob::BoundaryLinks::from_json(&encoded)
            .expect("strict boundary-links schema remains valid");
    assert_eq!(links.links().len(), maximum);
}

#[test]
fn wasm_lift_rust_reports_unsafe_atomic_state() {
    let json: Value = run(super::wasm_lift_rust, UNSAFE_ATOMIC_WASM);
    assert_eq!(json["ok"], Value::Bool(false));
    let error: &str = json["error"].as_str().expect("error");
    assert!(
        error.contains("DR-WASMDEOB-0003"),
        "unsafe atomic state returned the wrong diagnostic: {error}"
    );
    assert!(
        json.get("source").is_none(),
        "unsafe atomic state returned a stub"
    );
}

#[test]
fn wasm_lift_ts_uses_the_shared_memory_module_surface() {
    let module: Vec<u8> = wat::parse_str(SHARED_ATOMIC_WAT).expect("shared module assembles");
    let json: Value = run(super::wasm_lift_ts, &module);
    assert_eq!(json["ok"], Value::Bool(true));
    let source: &str = json["source"].as_str().expect("source");
    assert!(source.contains("export const instantiate"));
    assert!(source.contains("Atomics.notify"));
}

#[test]
fn malformed_pyc_yields_error_not_trap() {
    let json: Value = run(super::py_disasm, b"\x00\x01\x02");
    assert_eq!(json["ok"], Value::Bool(false));
    assert!(json["error"].as_str().expect("error").contains("pyc"));
}

#[test]
fn as3_analyze_reports_malformed_doabc_tag() {
    let swf: Vec<u8> = malformed_doabc_swf();
    let json: Value = run(super::as3_analyze, &swf);
    assert_eq!(json["ok"], Value::Bool(false));
    let error: &str = json["error"].as_str().expect("error");
    assert!(error.contains("DoABC tag parse"), "got {error}");
    assert!(error.contains("not null-terminated"), "got {error}");
}

#[test]
fn empty_pickle_yields_error_not_trap() {
    let json: Value = run(super::pickle_disasm, b"");
    assert_eq!(json["ok"], Value::Bool(false));
    assert!(json.get("error").is_some());
}

#[test]
fn null_pointer_nonzero_len_is_reported() {
    let result: *mut u8 = unsafe { super::detect(core::ptr::null(), 8) };
    let json: Value = read_result_json(result);
    assert_eq!(json["ok"], Value::Bool(false));
}

#[test]
fn pickle_decompile_recovers_python_literal() {
    let json: Value = run(super::pickle_decompile, BENIGN_PICKLE);
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(!json["source"].as_str().expect("source").is_empty());
}

#[test]
fn pickle_trace_reports_reduce_on_malicious() {
    let json: Value = run(super::pickle_trace, MALICIOUS_PICKLE);
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["reduce_count"].as_u64().expect("reduce_count") > 0);
}

#[test]
fn pickle_polyglot_marks_pickle() {
    let json: Value = run(super::pickle_polyglot, BENIGN_PICKLE);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["report"]["is_pickle"], Value::Bool(true));
}

#[test]
fn wasm_detect_runs_on_minimal_module() {
    let module: &[u8] = b"\0asm\x01\x00\x00\x00";
    let json: Value = run(super::wasm_detect, module);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["format"], "wasm");
}

#[test]
fn wasm_index_rejects_usize_overflow() {
    let err: String =
        super::entry::wasm_index(usize::MAX, "wasm function").expect_err("overflow must reject");
    assert!(err.contains("wasm function"));
}

#[test]
fn mobile_detect_unknown_keeps_empty_children() {
    let json: Value = run(super::mobile_detect, b"not a mobile artifact");
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["kind"], "Unknown");
    assert_eq!(json["child_count"], Value::from(0));
}

#[test]
fn mobile_detect_reports_child_extraction_error() {
    let apk: Vec<u8> = apk_with_oversized_classes_dex();
    let json: Value = run(super::mobile_detect, &apk);
    assert_eq!(json["ok"], Value::Bool(false));
    assert!(
        json["error"]
            .as_str()
            .expect("error")
            .contains("android dex extract")
    );
}

#[test]
fn strings_extracts_ascii_runs() {
    let json: Value = run(
        super::strings,
        b"\x00\x01hello world this is a string\x00\x02",
    );
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["report"]["total"].as_u64().expect("total") > 0);
}

#[test]
fn ioc_extracts_url() {
    let json: Value = run(
        super::ioc,
        b"connect to http://malware.example.com/payload now",
    );
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["report"]["total"].as_u64().expect("total") > 0);
}

#[test]
fn entropy_reports_blocks() {
    let json: Value = run(super::entropy, MALICIOUS_PICKLE);
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["overall"].as_f64().expect("overall") >= 0.0);
    assert!(!json["blocks"].as_array().expect("blocks").is_empty());
}

#[test]
fn entropy_caps_reported_blocks() {
    let byte_len: usize = (super::entry::MAX_ENTROPY_BLOCKS + 1) * super::entry::ENTROPY_WINDOW;
    let bytes: Vec<u8> = vec![0xff; byte_len];
    let json: Value = run(super::entropy, &bytes);
    let expected: u64 = u64::try_from(super::entry::MAX_ENTROPY_BLOCKS).expect("cap fits");
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["block_count"].as_u64().expect("block_count"), expected);
    assert_eq!(json["truncated"], Value::Bool(true));
    assert_eq!(
        json["blocks"].as_array().expect("blocks").len(),
        super::entry::MAX_ENTROPY_BLOCKS
    );
}

#[test]
fn secrets_scan_runs() {
    let json: Value = run(
        super::secrets,
        b"AKIAIOSFODNN7EXAMPLE plus some filler bytes here",
    );
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["report"].is_object());
}

#[test]
fn behavior_scan_runs() {
    let json: Value = run(
        super::behavior,
        b"CreateProcessW VirtualAllocEx WriteProcessMemory",
    );
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["report"].is_object());
}

#[test]
fn anti_analysis_scan_runs() {
    let json: Value = run(
        super::anti_analysis,
        b"IsDebuggerPresent CheckRemoteDebuggerPresent",
    );
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["report"].is_object());
}

#[test]
fn yara_gen_emits_rule() {
    let json: Value = run(super::yara_gen, MALICIOUS_PICKLE);
    assert_eq!(json["ok"], Value::Bool(true));
    assert!(json["rule"].is_object());
}

#[test]
fn auto_route_points_at_pickle() {
    let json: Value = run(super::auto_route, MALICIOUS_PICKLE);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["primary"]["ecosystem"], "pickle");
}

#[test]
fn auto_route_points_at_python_for_pyc() {
    let json: Value = run(super::auto_route, SAMPLE_PYC);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["primary"]["ecosystem"], "python");
}

#[test]
fn auto_route_points_at_swift_for_macho() {
    let bytes: &[u8] = include_bytes!("../../../corpus/mobile/macho-mac/SwiftHello.original");
    let json: Value = run(super::auto_route, bytes);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["primary"]["mode"], "swift_objc");
    let candidates: &[Value] = json["candidates"].as_array().expect("route candidates");
    assert!(
        candidates
            .iter()
            .all(|candidate: &Value| candidate["mode"] != "shell_deob")
    );
}

#[test]
fn auto_route_does_not_treat_unknown_input_as_shell() {
    for bytes in [
        b"\xff\x00\xfe\x01".as_slice(),
        b"ordinary text without a script signature".as_slice(),
    ] {
        let json: Value = run(super::auto_route, bytes);
        assert_eq!(json["ok"], Value::Bool(true));
        let candidates: &[Value] = json["candidates"].as_array().expect("route candidates");
        assert!(
            candidates
                .iter()
                .all(|candidate: &Value| candidate["mode"] != "shell_deob")
        );
    }
}

#[test]
fn auto_route_retains_recognized_batch_scripts() {
    let json: Value = run(
        super::auto_route,
        b"@echo off\nset name=hello\necho %name%\n",
    );
    assert_eq!(json["ok"], Value::Bool(true));
    let candidates: &[Value] = json["candidates"].as_array().expect("route candidates");
    assert!(
        candidates
            .iter()
            .any(|candidate: &Value| candidate["mode"] == "shell_deob")
    );
}

#[test]
fn auto_route_points_at_hermes_for_bytecode() {
    let bytes: &[u8] = include_bytes!("../../disrobe-pass-mobile/tests/fixtures/hermes/shapes.hbc");
    let json: Value = run(super::auto_route, bytes);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["primary"]["mode"], "hermes_analyze");
}

#[test]
fn hermes_analyze_exposes_source_instructions_and_tables() {
    let bytes: &[u8] = include_bytes!("../../disrobe-pass-mobile/tests/fixtures/hermes/shapes.hbc");
    let reference: &str =
        include_str!("../../disrobe-pass-mobile/tests/fixtures/hermes/shapes.hbcdump.txt");
    let reference_functions: usize = reference
        .lines()
        .filter(|line: &&str| line.contains(" <_") && line.ends_with(">:"))
        .count();
    let json: Value = run(super::hermes_analyze, bytes);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["header"]["version"], 96);
    assert_eq!(json["header"]["function_count"], reference_functions);
    assert_eq!(json["report"]["function_count"], reference_functions);
    assert_eq!(
        json["disassembly"]
            .as_array()
            .expect("function bytecode")
            .len(),
        reference_functions
    );
    assert!(
        json["disassembly"][0]["listing"]
            .as_str()
            .expect("global instructions")
            .contains("DeclareGlobalVar")
    );
    assert!(
        json["report"]["functions"]
            .as_array()
            .expect("functions")
            .iter()
            .any(|function: &Value| function["name"] == "bigText"
                && function["source"]
                    .as_str()
                    .is_some_and(|source: &str| source.contains("123456789012345678901234567890")))
    );
    assert!(
        json["string_table"]
            .as_array()
            .expect("string table")
            .iter()
            .any(|entry: &Value| entry["index"] == 31
                && entry["kind"] == "identifier"
                && entry["value"] == "makeBox")
    );
    assert_eq!(
        json["string_table"].as_array().expect("string table").len(),
        38
    );
    assert_eq!(json["header"]["identifier_count"], 27);
}

#[test]
fn hermes_analyze_rejects_invalid_bytecode() {
    for bytes in [
        b"".as_slice(),
        b"ordinary text".as_slice(),
        &include_bytes!("../../disrobe-pass-mobile/tests/fixtures/hermes/shapes.hbc")[..32],
    ] {
        let json: Value = run(super::hermes_analyze, bytes);
        assert_eq!(json["ok"], Value::Bool(false));
        assert!(
            json["error"]
                .as_str()
                .is_some_and(|message: &str| message.contains("Hermes bytecode"))
        );
    }
}

#[test]
fn go_metadata_recovers_fixture_build_and_function_information() {
    let bytes: &[u8] =
        include_bytes!("../../disrobe-pass-go/tests/fixtures/goembed/goembed_elf32_le");
    let json: Value = run(super::go_metadata, bytes);
    assert_eq!(json["ok"], true);
    assert_eq!(json["container"], "ELF");
    assert_eq!(json["pointer_width"], 32);
    assert_eq!(json["build_info"]["go_version"], "go1.26.5");
    assert_eq!(json["build_info"]["path"], "embedwide");
    assert_eq!(json["build_info"]["settings"]["GOOS"], "linux");
    assert_eq!(json["build_info"]["settings"]["GOARCH"], "386");
    assert_eq!(json["build_info"]["settings"]["CGO_ENABLED"], "0");
    let functions: &[Value] = json["symbols"]["functions"]
        .as_array()
        .expect("function records");
    let main: &Value = functions
        .iter()
        .find(|function: &&Value| function["name"] == "main.main")
        .expect("main.main");
    assert!(
        main["address"]
            .as_str()
            .is_some_and(|address: &str| address.starts_with("0x") && address != "0x0")
    );
    assert!(
        !json["types"]["types"]
            .as_array()
            .expect("runtime types")
            .is_empty()
    );
    let routed: Value = run(super::auto_route, bytes);
    assert!(
        routed["candidates"]
            .as_array()
            .expect("routes")
            .iter()
            .any(|route: &Value| route["mode"] == "go_metadata")
    );
}

#[test]
fn go_metadata_rejects_non_go_and_truncated_inputs() {
    for bytes in [
        b"not a Go executable".as_slice(),
        b"\x7fELF".as_slice(),
        b"MZ".as_slice(),
    ] {
        let json: Value = run(super::go_metadata, bytes);
        assert_eq!(json["ok"], false);
        assert!(
            json["error"]
                .as_str()
                .is_some_and(|error: &str| error.starts_with("Go metadata:"))
        );
    }
}

#[test]
fn lua_detect_classifies_luac() {
    let mut module: Vec<u8> = vec![0x1b, b'L', b'u', b'a', 0x53];
    module.extend_from_slice(&[0u8; 16]);
    let json: Value = run(super::lua_detect, &module);
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["dialect"], "lua 5.3");
}

#[test]
fn php_detect_classifies_source() {
    let json: Value = run(super::php_detect, b"<?php echo 'hi'; ?>");
    assert_eq!(json["ok"], Value::Bool(true));
    assert_eq!(json["detection"]["kind"], "Source");
}

fn apk_with_oversized_classes_dex() -> Vec<u8> {
    let declared_dex_size: u32 =
        u32::try_from(disrobe_pass_mobile::ZIP_ENTRY_READ_CAP + 1).expect("dex size");
    zip_headers(&[
        ("AndroidManifest.xml", 0),
        ("classes.dex", declared_dex_size),
    ])
}

fn zip_headers(entries: &[(&str, u32)]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(entries.len());
    for &(name, size) in entries {
        offsets.push(u32::try_from(out.len()).expect("ZIP local offset"));
        push_zip_local_header(&mut out, name, size);
    }
    let central_offset: u32 = u32::try_from(out.len()).expect("central offset");
    for (&(name, size), &offset) in entries.iter().zip(&offsets) {
        push_zip_central_header(&mut out, name, size, offset);
    }
    let central_size: u32 = u32::try_from(out.len())
        .expect("central end")
        .saturating_sub(central_offset);
    push_le_u32(&mut out, 0x0605_4b50);
    push_le_u16(&mut out, 0);
    push_le_u16(&mut out, 0);
    let count: u16 = u16::try_from(entries.len()).expect("ZIP entry count");
    push_le_u16(&mut out, count);
    push_le_u16(&mut out, count);
    push_le_u32(&mut out, central_size);
    push_le_u32(&mut out, central_offset);
    push_le_u16(&mut out, 0);
    out
}

fn malformed_doabc_swf() -> Vec<u8> {
    let mut doabc_payload: Vec<u8> = Vec::new();
    push_le_u32(&mut doabc_payload, 0);
    doabc_payload.extend_from_slice(b"unterminated");
    let mut body: Vec<u8> = Vec::new();
    body.push(0);
    push_le_u16(&mut body, 24);
    push_le_u16(&mut body, 1);
    push_swf_tag(&mut body, 82, &doabc_payload);
    push_swf_tag(&mut body, 0, &[]);

    let mut swf: Vec<u8> = Vec::new();
    swf.extend_from_slice(b"FWS");
    swf.push(10);
    let file_length: u32 = u32::try_from(8 + body.len()).expect("swf size");
    push_le_u32(&mut swf, file_length);
    swf.extend_from_slice(&body);
    swf
}

fn push_swf_tag(out: &mut Vec<u8>, code: u16, payload: &[u8]) {
    let len: u16 = u16::try_from(payload.len()).expect("swf tag len");
    let header: u16 = (code << 6) | len;
    push_le_u16(out, header);
    out.extend_from_slice(payload);
}

fn push_zip_local_header(out: &mut Vec<u8>, name: &str, size: u32) {
    push_le_u32(out, 0x0403_4b50);
    push_le_u16(out, 20);
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u32(out, 0);
    push_le_u32(out, size);
    push_le_u32(out, size);
    push_le_u16(out, u16::try_from(name.len()).expect("name len"));
    push_le_u16(out, 0);
    out.extend_from_slice(name.as_bytes());
}

fn push_zip_central_header(out: &mut Vec<u8>, name: &str, size: u32, local_offset: u32) {
    push_le_u32(out, 0x0201_4b50);
    push_le_u16(out, 20);
    push_le_u16(out, 20);
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u32(out, 0);
    push_le_u32(out, size);
    push_le_u32(out, size);
    push_le_u16(out, u16::try_from(name.len()).expect("name len"));
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u16(out, 0);
    push_le_u32(out, 0);
    push_le_u32(out, local_offset);
    out.extend_from_slice(name.as_bytes());
}

fn push_le_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_le_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
