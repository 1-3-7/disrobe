#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

use disrobe_pass_jvm::{
    JniSurfaceReport, RegisteredNative, analyze_jni_surface, recover_register_natives,
};

const X64_SO: &[u8] = include_bytes!("fixtures/jni_register/libjnireg_x64.so");
const A64_SO: &[u8] = include_bytes!("fixtures/jni_register/libjnireg_a64.so");
const X64_SYMS: &str = include_str!("fixtures/jni_register/libjnireg_x64.readelf-syms.txt");
const A64_SYMS: &str = include_str!("fixtures/jni_register/libjnireg_a64.readelf-syms.txt");

fn func_addresses(readelf_dump: &str) -> BTreeMap<String, u64> {
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    for line in readelf_dump.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 8 && cols[3] == "FUNC" {
            let value: u64 = u64::from_str_radix(cols[1], 16).expect("hex symbol value");
            let name: &str = cols[cols.len() - 1];
            out.entry(name.to_owned()).or_insert(value);
        }
    }
    out
}

fn expected_triples() -> Vec<(&'static str, &'static str)> {
    vec![
        ("nativeAdd", "(II)I"),
        ("nativeLen", "(Ljava/lang/String;)J"),
        ("nativeNoop", "()V"),
        ("hiddenMul", "(II)I"),
    ]
}

fn assert_recovery_matches_binutils(label: &str, so_bytes: &[u8], readelf_dump: &str) {
    let symbol_addresses: BTreeMap<String, u64> = func_addresses(readelf_dump);
    let recovered: Vec<RegisteredNative> = recover_register_natives(label, so_bytes);

    assert_eq!(
        recovered.len(),
        4,
        "{label}: four JNINativeMethod entries recovered, no spurious ones from the GOT/keep_methods relocations"
    );

    let by_name: BTreeMap<String, &RegisteredNative> = recovered
        .iter()
        .map(|entry: &RegisteredNative| (entry.name.clone(), entry))
        .collect();
    assert_eq!(by_name.len(), 4, "{label}: recovered names are distinct");

    for (name, signature) in expected_triples() {
        let entry: &RegisteredNative = by_name
            .get(name)
            .unwrap_or_else(|| panic!("{label}: missing recovered method {name}"));
        assert_eq!(
            entry.signature, signature,
            "{label}: {name} recovers its JVM signature from the relocated string pointer"
        );
        assert_eq!(
            entry.fn_symbol.as_deref(),
            Some(name),
            "{label}: {name} fnPtr resolves to its function symbol"
        );
        let truth: u64 = *symbol_addresses
            .get(name)
            .unwrap_or_else(|| panic!("{label}: {name} absent from readelf symbol table"));
        assert_eq!(
            entry.fn_addr, truth,
            "{label}: {name} fnPtr address equals the binutils symbol value"
        );
        assert_eq!(
            entry.library, label,
            "{label}: recovered entry carries its source library"
        );
    }
}

#[test]
fn x64_register_natives_triples_match_binutils() {
    assert_recovery_matches_binutils("lib/x86_64/libjnireg_x64.so", X64_SO, X64_SYMS);
}

#[test]
fn aarch64_register_natives_triples_match_binutils() {
    assert_recovery_matches_binutils("lib/arm64-v8a/libjnireg_a64.so", A64_SO, A64_SYMS);
}

#[test]
fn relative_reloc_function_pointer_recovers_local_symbol() {
    let recovered: Vec<RegisteredNative> = recover_register_natives("libjnireg_x64.so", X64_SO);
    let hidden: &RegisteredNative = recovered
        .iter()
        .find(|entry: &&RegisteredNative| entry.name == "hiddenMul")
        .expect("hiddenMul entry present");
    let truth: BTreeMap<String, u64> = func_addresses(X64_SYMS);
    assert_eq!(
        hidden.fn_symbol.as_deref(),
        Some("hiddenMul"),
        "R_X86_64_RELATIVE fnPtr resolves to the local .symtab function name"
    );
    assert_eq!(
        hidden.fn_addr, truth["hiddenMul"],
        "the RELATIVE addend equals the local hiddenMul address in binutils"
    );
}

#[test]
fn analyze_surface_reports_register_natives() {
    let report: JniSurfaceReport =
        analyze_jni_surface(&[], &[("lib/x86_64/libjnireg_x64.so", X64_SO)]);
    assert_eq!(report.registered_natives.len(), 4);
    let addrs: Vec<u64> = report
        .registered_natives
        .iter()
        .map(|entry: &RegisteredNative| entry.fn_addr)
        .collect();
    let mut sorted: Vec<u64> = addrs.clone();
    sorted.sort_unstable();
    assert_eq!(
        addrs, sorted,
        "registered natives are sorted deterministically"
    );
}

#[test]
fn non_elf_input_yields_no_triples() {
    let garbage: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    assert!(recover_register_natives("garbage.bin", &garbage).is_empty());
    assert!(recover_register_natives("empty", &[]).is_empty());
}
