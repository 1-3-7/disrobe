#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use disrobe_pass_native::{AuditableSbom, Error, parse_auditable_section};

const REAL_AUDITABLE: &[u8] = include_bytes!("../../../corpus/native/formats/hello.auditable.exe");
const MAX_COMPRESSED_BYTES: usize = 4 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;
const MAX_PACKAGES: usize = 16_384;
const MAX_PACKAGE_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_CONTAINER_ENTRIES: usize = 65_536;
const MAX_JSON_WORK_ITEMS: usize = 1_048_576;
const MAX_JSON_STRING_BYTES: usize = 9 * 1024 * 1024;
const MAX_JSON_ESCAPED_STRING_BYTES: usize = 64 * 1024;
const MAX_PREFLIGHT_ALLOCATION: usize = 128 * 1024;

struct TrackingAllocator;

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;
static TRACK_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static LARGEST_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn record_allocation(size: usize) {
    if TRACK_ALLOCATIONS.load(Ordering::Relaxed) {
        LARGEST_ALLOCATION.fetch_max(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer: *mut u8 = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer: *mut u8 = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let replacement: *mut u8 = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            record_allocation(new_size);
        }
        replacement
    }
}

fn package_array_json(count: usize, name: &str, source: Option<&str>) -> Vec<u8> {
    let source_field: String =
        source.map_or_else(String::new, |value: &str| format!(r#","source":"{value}""#));
    let package: String = format!(r#"{{"name":"{name}","version":"1"{source_field}}}"#);
    let mut json: String = String::from(r#"{"packages":["#);
    for index in 0..count {
        if index != 0 {
            json.push(',');
        }
        json.push_str(&package);
    }
    json.push_str("]}");
    json.into_bytes()
}

fn parse_with_largest_allocation(
    bytes: &[u8],
) -> (disrobe_pass_native::Result<AuditableSbom>, usize) {
    LARGEST_ALLOCATION.store(0, Ordering::Relaxed);
    TRACK_ALLOCATIONS.store(true, Ordering::SeqCst);
    let result: disrobe_pass_native::Result<AuditableSbom> = parse_auditable_section(bytes);
    TRACK_ALLOCATIONS.store(false, Ordering::SeqCst);
    let largest: usize = LARGEST_ALLOCATION.load(Ordering::Relaxed);
    (result, largest)
}

#[test]
fn auditable_section_parses_minimal_json_payload() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let blob: &[u8] = br#"{"packages":[{"name":"tokio","version":"1.40.0","source":"crates.io"}]}"#;
    let sbom: AuditableSbom = parse_auditable_section(blob).expect("parse");
    assert_eq!(sbom.crates.len(), 1);
    assert_eq!(sbom.crates[0].name, "tokio");
}

#[test]
fn auditable_format_version_is_typed_when_present() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    assert!(matches!(
        parse_auditable_section(br#"{"format":"1","packages":[]}"#),
        Err(Error::SignatureDb(message)) if message.contains("format version")
    ));
}

#[test]
fn invalid_format_is_rejected_before_package_conversion() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    assert!(matches!(
        parse_auditable_section(br#"{"format":"invalid","packages":[{}]}"#),
        Err(Error::SignatureDb(message)) if message.contains("format version")
    ));
}

#[test]
fn duplicate_auditable_fields_are_rejected() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let cases: [(&[u8], &str); 5] = [
        (br#"{"format":0,"format":1,"packages":[]}"#, "format"),
        (br#"{"packages":[],"packages":[]}"#, "packages"),
        (
            br#"{"packages":[{"name":"a","name":"b","version":"1"}]}"#,
            "name",
        ),
        (
            br#"{"packages":[{"name":"a","version":"1","version":"2"}]}"#,
            "version",
        ),
        (
            br#"{"packages":[{"name":"a","version":"1","source":"local","source":"git"}]}"#,
            "source",
        ),
    ];
    for (json, field) in cases {
        assert!(matches!(
            parse_auditable_section(json),
            Err(Error::SignatureDb(message))
                if message.contains("duplicate") && message.contains(field)
        ));
    }
}

#[test]
fn raw_json_obeys_the_decompressed_byte_limit() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let oversized: Vec<u8> = vec![b' '; MAX_DECOMPRESSED_BYTES + 1];
    assert!(matches!(
        parse_auditable_section(&oversized),
        Err(Error::SignatureDb(message)) if message.contains("decompressed") && message.contains("limit")
    ));
}

#[test]
fn package_count_is_rejected_before_result_allocation() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let json: Vec<u8> = package_array_json(MAX_PACKAGES + 1, "a", None);
    let (result, largest): (disrobe_pass_native::Result<AuditableSbom>, usize) =
        parse_with_largest_allocation(&json);
    assert!(matches!(
        result,
        Err(Error::SignatureDb(message)) if message.contains("package count") && message.contains("limit")
    ));
    assert!(
        largest <= MAX_PREFLIGHT_ALLOCATION,
        "preflight requested a {largest}-byte allocation"
    );
}

#[test]
fn aggregate_package_text_is_bounded() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let source: String = "s".repeat(MAX_PACKAGE_TEXT_BYTES + 1);
    let json: Vec<u8> = package_array_json(1, "a", Some(&source));
    let (result, largest): (disrobe_pass_native::Result<AuditableSbom>, usize) =
        parse_with_largest_allocation(&json);
    assert!(matches!(
        result,
        Err(Error::SignatureDb(message)) if message.contains("package text") && message.contains("limit")
    ));
    assert!(
        largest <= MAX_PREFLIGHT_ALLOCATION,
        "preflight requested a {largest}-byte allocation"
    );
}

#[test]
fn deep_unknown_json_is_rejected_at_the_declared_depth() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let mut json: String = String::from(r#"{"unknown":"#);
    json.push_str(&"[".repeat(MAX_JSON_DEPTH));
    json.push('0');
    json.push_str(&"]".repeat(MAX_JSON_DEPTH));
    json.push_str(r#", "packages":[]}"#);

    assert!(matches!(
        parse_auditable_section(json.as_bytes()),
        Err(Error::SignatureDb(message))
            if message.contains("nesting depth")
                && message.contains(&(MAX_JSON_DEPTH + 1).to_string())
                && message.contains(&MAX_JSON_DEPTH.to_string())
    ));
}

#[test]
fn irrelevant_array_amplification_is_bounded() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let mut json: String = String::from(r#"{"unknown":["#);
    for index in 0..=MAX_JSON_CONTAINER_ENTRIES {
        if index != 0 {
            json.push(',');
        }
        json.push('0');
    }
    json.push_str(r#"],"packages":[]}"#);

    assert!(matches!(
        parse_auditable_section(json.as_bytes()),
        Err(Error::SignatureDb(message))
            if message.contains("array entry count")
                && message.contains(&(MAX_JSON_CONTAINER_ENTRIES + 1).to_string())
                && message.contains(&MAX_JSON_CONTAINER_ENTRIES.to_string())
    ));
}

#[test]
fn irrelevant_object_amplification_is_bounded() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let mut json: String = String::from(r#"{"unknown":{"#);
    for index in 0..=MAX_JSON_CONTAINER_ENTRIES {
        if index != 0 {
            json.push(',');
        }
        write!(json, r#""key_{index}":0"#).expect("write object member");
    }
    json.push_str(r#"},"packages":[]}"#);

    assert!(matches!(
        parse_auditable_section(json.as_bytes()),
        Err(Error::SignatureDb(message))
            if message.contains("object member count")
                && message.contains(&(MAX_JSON_CONTAINER_ENTRIES + 1).to_string())
                && message.contains(&MAX_JSON_CONTAINER_ENTRIES.to_string())
    ));
}

#[test]
fn aggregate_unknown_json_work_is_bounded() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let inner: &str = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
    let mut json: String = String::from(r#"{"unknown":["#);
    for index in 0..MAX_JSON_CONTAINER_ENTRIES {
        if index != 0 {
            json.push(',');
        }
        json.push_str(inner);
    }
    json.push_str(r#"],"packages":[]}"#);

    assert!(matches!(
        parse_auditable_section(json.as_bytes()),
        Err(Error::SignatureDb(message))
            if message.contains("JSON work")
                && message.contains(&(MAX_JSON_WORK_ITEMS + 1).to_string())
                && message.contains(&MAX_JSON_WORK_ITEMS.to_string())
    ));
}

#[test]
fn aggregate_work_cap_is_order_independent() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let inner: &str = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
    let mut json: String = String::from(r#"{"packages":[],"unknown":["#);
    for index in 0..MAX_JSON_CONTAINER_ENTRIES {
        if index != 0 {
            json.push(',');
        }
        json.push_str(inner);
    }
    json.push_str("]}");

    assert!(matches!(
        parse_auditable_section(json.as_bytes()),
        Err(Error::SignatureDb(message)) if message.contains("JSON work")
    ));
}

#[test]
fn aggregate_unknown_json_string_bytes_are_bounded() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let unknown: String = "s".repeat(MAX_JSON_STRING_BYTES + 1 - "unknown".len());
    let json: String = format!(r#"{{"unknown":"{unknown}","packages":[]}}"#);

    assert!(matches!(
        parse_auditable_section(json.as_bytes()),
        Err(Error::SignatureDb(message))
            if message.contains("JSON string bytes")
                && message.contains(&(MAX_JSON_STRING_BYTES + 1).to_string())
                && message.contains(&MAX_JSON_STRING_BYTES.to_string())
    ));
}

#[test]
fn escaped_unknown_json_keys_remain_compatible() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let sbom: AuditableSbom =
        parse_auditable_section(br#"{"unknown":{"escaped\u005fkey":0},"packages":[]}"#)
            .expect("parse escaped unknown key");
    assert!(sbom.crates.is_empty());
}

#[test]
fn escaped_quote_and_backslash_preserve_later_string_boundaries() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let json: &[u8] = br#"{"unknown":[0,true,null,{"text":"quoted: \" and slash: \\\""}],"packages":[{"name":"serde","version":"1"}]}"#;

    let sbom: AuditableSbom = parse_auditable_section(json).expect("parse escaped punctuation");

    assert_eq!(sbom.crates.len(), 1);
    assert_eq!(sbom.crates[0].name, "serde");
}

#[test]
fn escaped_string_boundary_accepts_exact_decoded_byte_limit() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let prefix: String = "é".repeat((MAX_JSON_ESCAPED_STRING_BYTES - 2) / 2);
    let json: String = format!(r#"{{"unknown":"{prefix}a\n","packages":[]}}"#);

    let (result, largest): (disrobe_pass_native::Result<AuditableSbom>, usize) =
        parse_with_largest_allocation(json.as_bytes());

    assert!(matches!(result, Ok(AuditableSbom { crates, .. }) if crates.is_empty()));
    assert!(
        largest <= MAX_PREFLIGHT_ALLOCATION,
        "boundary escaped string requested a {largest}-byte allocation"
    );
}

#[test]
fn surrogate_pair_boundary_accepts_exact_decoded_byte_limit() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let escaped: String = r"\uD83D\uDE00".repeat(MAX_JSON_ESCAPED_STRING_BYTES / 4);
    let json: String = format!(r#"{{"unknown":"{escaped}","packages":[]}}"#);

    let (result, largest): (disrobe_pass_native::Result<AuditableSbom>, usize) =
        parse_with_largest_allocation(json.as_bytes());

    assert!(matches!(result, Ok(AuditableSbom { crates, .. }) if crates.is_empty()));
    assert!(
        largest <= MAX_PREFLIGHT_ALLOCATION,
        "surrogate-pair boundary requested a {largest}-byte allocation"
    );
}

#[test]
fn late_escape_after_oversized_raw_prefix_is_rejected_before_scratch_allocation() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let prefix: String = "a".repeat(MAX_JSON_ESCAPED_STRING_BYTES + 1);
    let json: String = format!(r#"{{"unknown":"{prefix}\n","packages":[]}}"#);

    let (result, largest): (disrobe_pass_native::Result<AuditableSbom>, usize) =
        parse_with_largest_allocation(json.as_bytes());

    assert!(matches!(
        result,
        Err(Error::SignatureDb(message))
            if message.contains("escaped JSON string")
                && message.contains(&(MAX_JSON_ESCAPED_STRING_BYTES + 2).to_string())
    ));
    assert!(
        largest <= MAX_PREFLIGHT_ALLOCATION,
        "late-escape preflight requested a {largest}-byte allocation"
    );
}

#[test]
fn malformed_and_truncated_escapes_are_rejected_by_json_validation() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    for json in [
        br#"{"unknown":"\q","packages":[]}"#.as_slice(),
        br#"{"unknown":"\u12","packages":[]}"#.as_slice(),
        br#"{"unknown":"\uD83D","packages":[]}"#.as_slice(),
        br#"{"unknown":"truncated\"#.as_slice(),
    ] {
        assert!(matches!(
            parse_auditable_section(json),
            Err(Error::SignatureDb(_))
        ));
    }
}

#[test]
fn oversized_escaped_string_is_rejected_before_scratch_allocation() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let escaped: String = r"\u0061".repeat(MAX_JSON_ESCAPED_STRING_BYTES * 4);
    let json: String = format!(r#"{{"unknown":"{escaped}","packages":[]}}"#);

    let (result, largest): (disrobe_pass_native::Result<AuditableSbom>, usize) =
        parse_with_largest_allocation(json.as_bytes());

    assert!(
        largest <= MAX_PREFLIGHT_ALLOCATION,
        "escaped-string preflight requested a {largest}-byte allocation"
    );
    assert!(matches!(
        result,
        Err(Error::SignatureDb(message))
            if message.contains("escaped JSON string")
                && message.contains(&(MAX_JSON_ESCAPED_STRING_BYTES + 1).to_string())
                && message.contains(&MAX_JSON_ESCAPED_STRING_BYTES.to_string())
    ));
}

#[test]
fn aggregate_unknown_json_key_bytes_are_bounded() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let unknown: String = "k".repeat(MAX_JSON_STRING_BYTES + 1);
    let json: String = format!(r#"{{"{unknown}":0,"packages":[]}}"#);

    assert!(matches!(
        parse_auditable_section(json.as_bytes()),
        Err(Error::SignatureDb(message))
            if message.contains("JSON string bytes")
                && message.contains(&(MAX_JSON_STRING_BYTES + 1).to_string())
                && message.contains(&MAX_JSON_STRING_BYTES.to_string())
    ));
}

#[test]
fn real_auditable_embedded_binary_round_trip() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let sbom: AuditableSbom = parse_auditable_section(REAL_AUDITABLE).expect("parse real PE");
    assert_eq!(sbom.format_version, 1);
    assert_eq!(sbom.crates.len(), 2);
    let adler: &disrobe_pass_native::AuditableCrate = sbom
        .crates
        .iter()
        .find(|krate: &&disrobe_pass_native::AuditableCrate| krate.name == "adler2")
        .expect("adler2 present");
    assert_eq!(adler.version, "2.0.1");
    assert_eq!(adler.source.as_deref(), Some("crates.io"));
    assert!(
        sbom.crates
            .iter()
            .any(|krate: &disrobe_pass_native::AuditableCrate| {
                krate.name == "disrobe_audit_fixture"
            })
    );
    assert!(REAL_AUDITABLE.len() < 256 * 1024);
}

#[test]
fn binary_parser_rejects_missing_or_corrupt_auditable_sections() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let mut missing: Vec<u8> = REAL_AUDITABLE.to_vec();
    let header: usize = dep_section_header_offset(&missing);
    missing[header..header + 7].copy_from_slice(b".absent");
    assert!(matches!(
        parse_auditable_section(&missing),
        Err(Error::SignatureDb(message)) if message.contains(".dep-v0 section")
    ));

    let corrupt: Vec<u8> = replace_dep_section(b"not a zlib stream");
    assert!(matches!(
        parse_auditable_section(&corrupt),
        Err(Error::SignatureDb(message)) if message.contains("zlib decode")
    ));
}

#[test]
fn binary_parser_bounds_compressed_and_decompressed_payloads() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let compressed_too_large: Vec<u8> = vec![0; MAX_COMPRESSED_BYTES + 1];
    let oversized_section: Vec<u8> = replace_dep_section(&compressed_too_large);
    assert!(matches!(
        parse_auditable_section(&oversized_section),
        Err(Error::SignatureDb(message)) if message.contains("compressed") && message.contains("limit")
    ));

    let decompressed_too_large: Vec<u8> = vec![b' '; MAX_DECOMPRESSED_BYTES + 1];
    let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(&decompressed_too_large)
        .expect("compress oversized output");
    let compressed: Vec<u8> = encoder.finish().expect("finish zlib stream");
    assert!(compressed.len() < MAX_COMPRESSED_BYTES);
    let oversized_output: Vec<u8> = replace_dep_section(&compressed);
    assert!(matches!(
        parse_auditable_section(&oversized_output),
        Err(Error::SignatureDb(message)) if message.contains("decompressed") && message.contains("limit")
    ));
}

#[test]
fn decompression_never_requests_an_allocation_above_the_logical_limit() {
    let _guard: std::sync::MutexGuard<'static, ()> = TEST_LOCK.lock().expect("test lock");
    let decompressed_too_large: Vec<u8> = vec![b' '; MAX_DECOMPRESSED_BYTES + 1];
    let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(&decompressed_too_large)
        .expect("compress oversized output");
    let compressed: Vec<u8> = encoder.finish().expect("finish zlib stream");
    let oversized_output: Vec<u8> = replace_dep_section(&compressed);

    let (result, largest): (disrobe_pass_native::Result<AuditableSbom>, usize) =
        parse_with_largest_allocation(&oversized_output);

    assert!(matches!(
        result,
        Err(Error::SignatureDb(message)) if message.contains("decompressed") && message.contains("limit")
    ));
    assert!(
        largest <= MAX_DECOMPRESSED_BYTES + 1,
        "largest allocation request was {largest} bytes"
    );
}

fn dep_section_header_offset(bytes: &[u8]) -> usize {
    bytes
        .windows(8)
        .position(|window: &[u8]| window == b".dep-v0\0")
        .expect("committed PE has .dep-v0 section header")
}

fn replace_dep_section(payload: &[u8]) -> Vec<u8> {
    let mut image: Vec<u8> = REAL_AUDITABLE.to_vec();
    let header: usize = dep_section_header_offset(&image);
    let raw_pointer: u32 = u32::try_from(image.len()).expect("fixture length fits u32");
    let raw_size: u32 = u32::try_from(payload.len()).expect("test payload length fits u32");
    image[header + 8..header + 12].copy_from_slice(&raw_size.to_le_bytes());
    image[header + 16..header + 20].copy_from_slice(&raw_size.to_le_bytes());
    image[header + 20..header + 24].copy_from_slice(&raw_pointer.to_le_bytes());
    image.extend_from_slice(payload);
    image
}
