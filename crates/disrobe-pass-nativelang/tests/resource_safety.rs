#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_nativelang::image::{
    MAX_STRING_COUNT, MAX_STRING_SCAN_BYTES, ascii_strings, ascii_strings_capped,
};
use disrobe_pass_nativelang::{
    CodeArch, ImageKind, NativeImage, NativeLang, Recovery, TypeReport, recover,
};
use disrobe_pass_nativelang::{DemangledSymbol, demangle_nim};

fn over_cap_string_pool() -> Vec<u8> {
    let unit: &[u8] = b"Foo::Bar\x00";
    let count: usize = MAX_STRING_COUNT + 4096;
    let mut buf: Vec<u8> = Vec::with_capacity(unit.len() * count);
    for _ in 0..count {
        buf.extend_from_slice(unit);
    }
    buf
}

const fn stripped_image(raw: &[u8]) -> NativeImage<'_> {
    NativeImage {
        kind: ImageKind::Elf,
        relocatable: false,
        arch: CodeArch::X86_64,
        ptr_size: 8,
        entry: 0,
        raw,
        sections: Vec::new(),
        symbols: Vec::new(),
        func_symbols: Vec::new(),
        function_starts: Vec::new(),
    }
}

fn recover_stripped(raw: &[u8], lang: NativeLang) -> Recovery {
    let img: NativeImage<'_> = stripped_image(raw);
    let types: TypeReport = TypeReport::absent(false);
    recover(&img, lang, &types)
}

#[test]
fn ascii_strings_caps_string_count_on_adversarial_runs() {
    let unit: &[u8] = b"abc\x00";
    let mut buf: Vec<u8> = Vec::with_capacity(unit.len() * (MAX_STRING_COUNT + 4096));
    for _ in 0..(MAX_STRING_COUNT + 4096) {
        buf.extend_from_slice(unit);
    }
    let strings: Vec<String> = ascii_strings(&buf, 3);
    assert!(
        strings.len() <= MAX_STRING_COUNT,
        "string count {} exceeded cap {}",
        strings.len(),
        MAX_STRING_COUNT
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
fn ascii_strings_capped_flags_count_truncation() {
    let buf: Vec<u8> = over_cap_string_pool();
    let (strings, truncated): (Vec<String>, bool) = ascii_strings_capped(&buf, 3);
    assert!(
        truncated,
        "cap binding on {} strings must report truncation",
        strings.len()
    );
    assert!(strings.len() <= MAX_STRING_COUNT);
}

#[test]
fn ascii_strings_capped_flags_window_truncation() {
    let mut buf: Vec<u8> = vec![b'A'; MAX_STRING_SCAN_BYTES];
    buf.extend_from_slice(b"\x00tail\x00");
    let (_strings, truncated): (Vec<String>, bool) = ascii_strings_capped(&buf, 4);
    assert!(
        truncated,
        "input past the scan window must report truncation"
    );
}

#[test]
fn ascii_strings_capped_untruncated_on_small_input() {
    let buf: &[u8] = b"\x00hello\x00world\x00goodbye\x00";
    let (strings, truncated): (Vec<String>, bool) = ascii_strings_capped(buf, 3);
    assert!(!truncated, "small input must not report truncation");
    assert!(strings.contains(&"hello".to_owned()));
}

#[test]
fn crystal_stripped_fallback_signals_truncation_and_stays_bounded() {
    let buf: Vec<u8> = over_cap_string_pool();
    let rec: Recovery = recover_stripped(&buf, NativeLang::Crystal);
    assert!(
        rec.strings_truncated,
        "crystal fallback over the cap must surface truncation instead of silently dropping"
    );
    assert!(rec.strings_sampled <= MAX_STRING_COUNT);
}

#[test]
fn d_stripped_fallback_signals_truncation_and_stays_bounded() {
    let buf: Vec<u8> = over_cap_string_pool();
    let rec: Recovery = recover_stripped(&buf, NativeLang::D);
    assert!(
        rec.strings_truncated,
        "d fallback over the cap must surface truncation instead of silently dropping"
    );
    assert!(rec.strings_sampled <= MAX_STRING_COUNT);
}

#[test]
fn small_stripped_input_not_truncated() {
    let buf: &[u8] = b"\x00Foo::Bar\x00Baz::Qux\x00__crystal_main\x00";
    let rec: Recovery = recover_stripped(buf, NativeLang::Crystal);
    assert!(
        !rec.strings_truncated,
        "a small input must report strings_truncated=false"
    );
}

#[test]
fn demangle_nim_bounds_deep_template_nesting() {
    let mut mangled: String = String::from("_ZN1aE");
    for _ in 0..200_000 {
        mangled.push_str("1aI");
    }
    let symbol: DemangledSymbol =
        demangle_nim(&mangled).expect("the leading component still demangles");
    assert_eq!(symbol.demangled, "a");
    assert!(
        symbol.params.is_empty(),
        "template nesting past the depth cap is refused, not rendered: {:?}",
        symbol.params.len()
    );
}

#[test]
fn demangle_nim_recovers_valid_symbol() {
    let demangled = demangle_nim("_ZN5mymod4funcE").expect("valid nim symbol must demangle");
    assert_eq!(demangled.name, "func");
    assert_eq!(demangled.module.as_deref(), Some("mymod"));
}
