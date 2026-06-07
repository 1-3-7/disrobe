#![allow(clippy::expect_used, clippy::case_sensitive_file_extension_comparisons)]

use std::path::PathBuf;

use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
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

struct RealApk {
    file: &'static str,
    min_bodies_pct: f64,
    min_method_total: usize,
}

const REAL_APKS: &[RealApk] = &[
    RealApk {
        file: "transmissionic-ionic.apk",
        min_bodies_pct: 85.5,
        min_method_total: 20_000,
    },
    RealApk {
        file: "rustdesk-flutter.apk",
        min_bodies_pct: 87.0,
        min_method_total: 20_000,
    },
    RealApk {
        file: "enrecipes-nativescript.apk",
        min_bodies_pct: 83.0,
        min_method_total: 20_000,
    },
];

/// Honest arbitrary-recovery floor on real FOSS apps. The apks live under the gitignored
/// `corpus/mobile/apk/inbox/` (multi-megabyte, local-only — `discord.apkm` exceeds GitHub's
/// 100 MB limit and is proprietary, so it is excluded entirely). When the fixtures are absent
/// (CI), the measurement is skipped; where present (local), it extracts every `classes*.dex`,
/// lifts it, and asserts the share of methods whose REAL Dalvik body was lowered (vs the
/// verifiable `UnsupportedOperationException` stub) stays above a ratcheting floor.
#[test]
fn realworld_apk_bodies_recovered_above_floor() {
    let mut measured: usize = 0;
    for apk in REAL_APKS {
        let path: PathBuf = corpus(&["mobile", "apk", "inbox", apk.file]);
        if !path.is_file() {
            eprintln!(
                "skipping {} (local-only fixture not present at {})",
                apk.file,
                path.display()
            );
            continue;
        }
        measured += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read apk");
        let extract: ApkExtract = extract_apk(&bytes).expect("extract apk");

        let mut method_total: usize = 0;
        let mut bodies_recovered: usize = 0;
        let mut dex_count: usize = 0;
        for (name, dex_bytes) in &extract.dex_files {
            if !name.ends_with(".dex") {
                continue;
            }
            dex_count += 1;
            let result: Dex2JarResult =
                translate_dex_bytes(dex_bytes).expect("translate classes.dex");
            method_total += result.method_total;
            bodies_recovered += result.bodies_recovered;
        }

        assert!(
            dex_count >= 1,
            "{}: apk must contain at least one classes.dex",
            apk.file
        );
        assert!(
            method_total >= apk.min_method_total,
            "{}: expected >= {} defined methods, got {method_total}",
            apk.file,
            apk.min_method_total
        );
        let pct: f64 = bodies_recovered as f64 * 100.0 / method_total.max(1) as f64;
        eprintln!(
            "REALWORLD {}: dex_files={dex_count} method_total={method_total} \
             bodies_recovered={bodies_recovered} ({pct:.1}%)",
            apk.file
        );
        assert!(
            pct >= apk.min_bodies_pct,
            "{}: honest body-recovery {pct:.1}% fell below floor {:.1}% (lifter regression)",
            apk.file,
            apk.min_bodies_pct
        );
    }
    if measured == 0 {
        eprintln!("realworld apk measurement skipped: no local fixtures present (expected in CI)");
    }
}
