#![cfg(feature = "lifter-diag")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stderr)]
use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_jvm::dex2jar::{diagnose_dex_bytes, diagnose_dex_methods};
use disrobe_pass_jvm::{ApkExtract, extract_apk};

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    for part in parts {
        p.push(part);
    }
    p
}

#[test]
fn cluster_stub_reasons_committed_corpus() {
    let dexes: &[&str] = &["EdgeCases.dex", "EdgeCasesKt.dex", "Hello.dex"];
    let mut total: BTreeMap<String, usize> = BTreeMap::new();
    for name in dexes {
        let path: PathBuf = corpus(&["jvm", "dex", name]);
        let bytes: Vec<u8> = std::fs::read(&path).expect("read committed dex");
        let per: BTreeMap<String, usize> = diagnose_dex_bytes(&bytes).expect("diag");
        let stubs: usize = per.values().sum();
        eprintln!("=== {name}: {stubs} stubbed methods ===");
        let mut sorted: Vec<(String, usize)> = per.into_iter().collect();
        sorted.sort_by_key(|e: &(String, usize)| std::cmp::Reverse(e.1));
        for (k, v) in &sorted {
            eprintln!("  {v:>6}  {k}");
            *total.entry(k.clone()).or_default() += v;
        }
    }
    eprintln!("=== COMMITTED TOTAL ===");
    let grand: usize = total.values().sum();
    eprintln!("grand total stubs: {grand}");
    let mut sorted: Vec<(String, usize)> = total.into_iter().collect();
    sorted.sort_by_key(|e: &(String, usize)| std::cmp::Reverse(e.1));
    for (k, v) in &sorted {
        eprintln!("  {v:>6}  {k}");
    }
}

#[test]
fn dump_stub_methods_committed_corpus() {
    let dexes: &[&str] = &["EdgeCases.dex", "EdgeCasesKt.dex", "Hello.dex"];
    for name in dexes {
        let path: PathBuf = corpus(&["jvm", "dex", name]);
        let bytes: Vec<u8> = std::fs::read(&path).expect("read committed dex");
        let methods: Vec<(String, String, String, String)> =
            diagnose_dex_methods(&bytes).expect("diag");
        eprintln!("=== {name}: {} stubbed methods ===", methods.len());
        for (class, mname, reason, desc) in &methods {
            eprintln!("  {class}#{mname}{desc}\n      {reason}");
        }
    }
}

#[test]
fn cluster_stub_reasons_across_real_apks() {
    if std::env::var_os("DISROBE_RUN_REAL_APK_TESTS").is_none() {
        eprintln!("skip real apk diagnostics: set DISROBE_RUN_REAL_APK_TESTS=1");
        return;
    }
    let apks: &[&str] = &[
        "transmissionic-ionic.apk",
        "rustdesk-flutter.apk",
        "enrecipes-nativescript.apk",
    ];
    let mut total: BTreeMap<String, usize> = BTreeMap::new();
    for apk in apks {
        let path: PathBuf = corpus(&["mobile", "apk", "inbox", apk]);
        if !path.is_file() {
            eprintln!("skip {apk}: not present");
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(&path).expect("read apk");
        let extract: ApkExtract = extract_apk(&bytes).expect("extract");
        let mut per: BTreeMap<String, usize> = BTreeMap::new();
        for (name, dex) in &extract.dex_files {
            if !std::path::Path::new(name)
                .extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("dex"))
            {
                continue;
            }
            for (k, v) in diagnose_dex_bytes(dex).expect("diag") {
                *per.entry(k.clone()).or_default() += v;
                *total.entry(k).or_default() += v;
            }
        }
        let stubs: usize = per.values().sum();
        eprintln!("=== {apk}: {stubs} stubbed methods ===");
        let mut sorted: Vec<(String, usize)> = per.into_iter().collect();
        sorted.sort_by_key(|e: &(String, usize)| std::cmp::Reverse(e.1));
        for (k, v) in sorted.iter().take(25) {
            eprintln!("  {v:>6}  {k}");
        }
    }
    eprintln!("=== TOTAL across apks ===");
    let mut sorted: Vec<(String, usize)> = total.into_iter().collect();
    sorted.sort_by_key(|e: &(String, usize)| std::cmp::Reverse(e.1));
    let grand: usize = sorted.iter().map(|(_, v): &(String, usize)| *v).sum();
    eprintln!("grand total stubs: {grand}");
    for (k, v) in sorted.iter().take(40) {
        let pct: f64 = *v as f64 * 100.0 / grand.max(1) as f64;
        eprintln!("  {v:>6}  ({pct:>5.1}%)  {k}");
    }
}
