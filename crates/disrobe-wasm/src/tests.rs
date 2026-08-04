#![allow(clippy::expect_used)]
use serde_json::Value;

const SAMPLE_PYC: &[u8] = include_bytes!("../tests/fixtures/sample.pyc");
const BENIGN_PICKLE: &[u8] = include_bytes!("../tests/fixtures/benign_list.pkl");
const MALICIOUS_PICKLE: &[u8] = include_bytes!("../tests/fixtures/reduce_os_system.pkl");
const UNSAFE_ATOMIC_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00, 0x05, 0x04, 0x01, 0x03, 0x01, 0x02, 0x07, 0x08, 0x01, 0x04, 0x6c, 0x6f,
    0x61, 0x64, 0x00, 0x00, 0x0a, 0x0a, 0x01, 0x08, 0x00, 0x20, 0x00, 0xfe, 0x10, 0x02, 0x00, 0x0b,
];

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
    let mut out: Vec<u8> = Vec::new();
    let manifest_offset: u32 = u32::try_from(out.len()).expect("manifest offset");
    push_zip_local_header(&mut out, "AndroidManifest.xml", 0);
    let declared_dex_size: u32 =
        u32::try_from(disrobe_pass_mobile::ZIP_ENTRY_READ_CAP + 1).expect("dex size");
    let dex_offset: u32 = u32::try_from(out.len()).expect("dex offset");
    push_zip_local_header(&mut out, "classes.dex", declared_dex_size);
    let central_offset: u32 = u32::try_from(out.len()).expect("central offset");
    push_zip_central_header(&mut out, "AndroidManifest.xml", 0, manifest_offset);
    push_zip_central_header(&mut out, "classes.dex", declared_dex_size, dex_offset);
    let central_size: u32 = u32::try_from(out.len())
        .expect("central end")
        .saturating_sub(central_offset);
    push_le_u32(&mut out, 0x0605_4b50);
    push_le_u16(&mut out, 0);
    push_le_u16(&mut out, 0);
    push_le_u16(&mut out, 2);
    push_le_u16(&mut out, 2);
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
