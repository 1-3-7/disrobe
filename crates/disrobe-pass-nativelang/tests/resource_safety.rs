#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::time::{Duration, Instant};

use disrobe_pass_nativelang::demangle_nim;
use disrobe_pass_nativelang::image::{MAX_STRING_COUNT, MAX_STRING_SCAN_BYTES, ascii_strings};

#[test]
fn ascii_strings_caps_string_count_on_adversarial_runs() {
    let unit: &[u8] = b"abc\x00";
    let mut buf: Vec<u8> = Vec::with_capacity(unit.len() * (MAX_STRING_COUNT + 4096));
    for _ in 0..(MAX_STRING_COUNT + 4096) {
        buf.extend_from_slice(unit);
    }
    let start: Instant = Instant::now();
    let strings: Vec<String> = ascii_strings(&buf, 3);
    let elapsed: Duration = start.elapsed();
    assert!(
        strings.len() <= MAX_STRING_COUNT,
        "string count {} exceeded cap {}",
        strings.len(),
        MAX_STRING_COUNT
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "scan took {elapsed:?}, expected bounded time"
    );
    assert!(strings.iter().all(|s: &String| s == "abc"));
}

#[test]
fn ascii_strings_caps_scan_window_on_huge_input() {
    let mut buf: Vec<u8> = vec![b'A'; MAX_STRING_SCAN_BYTES];
    buf.extend(std::iter::repeat_n(0u8, 8));
    buf.extend_from_slice(b"PASTWINDOWMARKER");
    let strings: Vec<String> = ascii_strings(&buf, 4);
    assert!(
        !strings
            .iter()
            .any(|s: &String| s.contains("PASTWINDOWMARKER")),
        "bytes past the scan window must not be scanned"
    );
}

#[test]
fn ascii_strings_recovers_valid_strings() {
    let buf: &[u8] = b"\x00hello\x00\x00world\x00ab\x00goodbye\x00";
    let strings: Vec<String> = ascii_strings(buf, 3);
    assert!(strings.contains(&"hello".to_owned()));
    assert!(strings.contains(&"world".to_owned()));
    assert!(strings.contains(&"goodbye".to_owned()));
    assert!(!strings.contains(&"ab".to_owned()));
}

#[test]
fn demangle_nim_bounds_deep_template_nesting() {
    let mut mangled: String = String::from("_ZN1aE");
    for _ in 0..200_000 {
        mangled.push_str("1aI");
    }
    let start: Instant = Instant::now();
    let result: Option<_> = demangle_nim(&mangled);
    let elapsed: Duration = start.elapsed();
    let _ = result;
    assert!(
        elapsed < Duration::from_secs(10),
        "deeply nested nim demangle took {elapsed:?}, expected bounded time"
    );
}

#[test]
fn demangle_nim_recovers_valid_symbol() {
    let demangled = demangle_nim("_ZN5mymod4funcE").expect("valid nim symbol must demangle");
    assert_eq!(demangled.name, "func");
    assert_eq!(demangled.module.as_deref(), Some("mymod"));
}
