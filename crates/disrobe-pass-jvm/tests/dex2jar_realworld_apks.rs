#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

pub mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{
    JvmVerifier, REAL_APKS, RealApk, VerifyScope, assert_permille, lines_with_prefix, parse_metric,
    real_apk_inbox, real_apk_path, real_apks_absent,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ApkExtract, assemble_jar, extract_apk};

const CLASS_SCOPE_APK: &str = "transmissionic-ionic.apk";

const CLASS_SCOPE_DEX: &str = "classes.dex";

const CLASS_SCOPE_PERMILLE: u32 = 0;

const CLASS_SCOPE_GOLDEN: &str = "transmissionic-ionic.txt";

const CLASS_SCOPE_CLASSES: usize = 3_835;

const CLASS_SCOPE_GRADED_FLOOR: usize = 3_223;

const CLASS_SCOPE_REPEAT_RUNS: usize = 8;

const CLASS_SCOPE_CLEAN: usize = 2_986;

const CLASS_SCOPE_CLEAN_METHODS: usize = 13_819;

const CLASS_SCOPE_REJECTABLE: usize = 253;

const CLASS_SCOPE_JAR_SHA256: &str =
    "72eeec49158b731e29d5ef328efaefc6559acc25fade786d4c1182fe5a850e64";

fn class_verify_golden() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("golden");
    path.push("dalvik_class_verify");
    path.push(CLASS_SCOPE_GOLDEN);
    path
}

fn verdict_names(stdout: &str, verdict: &str) -> Vec<String> {
    let tag: String = format!("CLASSVERDICT {verdict} ");
    let mut names: Vec<String> = lines_with_prefix(stdout, &tag)
        .into_iter()
        .map(|line: String| {
            line.strip_prefix(tag.as_str())
                .unwrap_or_else(|| panic!("{line} carries the {tag} prefix it was selected by"))
                .trim()
                .to_string()
        })
        .collect();
    names.sort();
    names
}

fn rejected_types(line: &str) -> impl Iterator<Item = String> + '_ {
    let reason: &str = match line.split_once("Reason:") {
        Some((_, rest)) => rest.split("Current Frame").next().unwrap_or(rest),
        None => "",
    };
    reason.split('\'').skip(1).step_by(2).map(str::to_owned)
}

fn golden_section(recorded: &str, tag: &str) -> Vec<String> {
    let mut names: Vec<String> = recorded
        .lines()
        .filter_map(|line: &str| line.strip_prefix(tag))
        .map(|rest: &str| rest.trim().to_string())
        .collect();
    names.sort();
    names
}

fn assert_verdict_membership(clean: &[String], rejected: &[String]) {
    let golden: PathBuf = class_verify_golden();
    if std::env::var_os("DISROBE_WRITE_CLASS_VERIFY_MEMBERSHIP").is_some() {
        let mut lines: Vec<String> = clean
            .iter()
            .map(|name: &String| format!("CLEAN {name}"))
            .collect();
        lines.extend(
            rejected
                .iter()
                .map(|name: &String| format!("REJECTABLE {name}")),
        );
        std::fs::create_dir_all(golden.parent().expect("golden parent"))
            .expect("create the class-verify golden directory");
        std::fs::write(&golden, format!("{}\n", lines.join("\n")).as_bytes())
            .expect("write the class-verify golden");
        eprintln!(
            "wrote {} verifier-clean and {} rejectable class names to {}. A single run cannot \
             record the rejectable set on its own, because which boundary class the jvm rejects \
             varies between runs; union this file's REJECTABLE section with the previous one rather \
             than replacing it",
            clean.len(),
            rejected.len(),
            golden.display()
        );
        return;
    }
    let recorded: String = std::fs::read_to_string(&golden)
        .unwrap_or_else(|e: std::io::Error| {
            panic!(
                "{} is absent ({e}), so one class could start failing the real jvm verifier while \
                 another started passing and the count would not move; re-run with \
                 DISROBE_WRITE_CLASS_VERIFY_MEMBERSHIP=1 to record the {} clean classes and the \
                 rejectable set beside them",
                golden.display(),
                clean.len()
            )
        })
        .replace("\r\n", "\n");
    let pinned_clean: Vec<String> = golden_section(&recorded, "CLEAN ");
    let rejectable: Vec<String> = golden_section(&recorded, "REJECTABLE ");
    assert_eq!(
        rejectable.len(),
        CLASS_SCOPE_REJECTABLE,
        "the golden pins {} rejectable classes but this gate expects {CLASS_SCOPE_REJECTABLE}. That \
         section is a work queue rather than a bound: it lists classes the real jvm has been seen \
         to reject over {CLASS_SCOPE_REPEAT_RUNS} runs, it grows as reach varies, and it is not \
         asserted against a run because a class reaching the verifier for the first time is not a \
         regression. The family that used to dominate it, a dalvik zero constant materialized as an \
         int on one path and a null on another so that the frame at their join described neither, \
         is gone; what is left is led by assignability checks the harness cannot decide because it \
         stubs the android framework, which the attribution line above sizes. Change this number \
         only when you have added or fixed entries by hand",
        rejectable.len()
    );
    assert!(
        !rejectable
            .iter()
            .any(|name: &String| pinned_clean.binary_search(name).is_ok()),
        "a class cannot be pinned both verifier-clean and rejectable; the golden contradicts itself"
    );
    let unexpected: Vec<&String> = rejected
        .iter()
        .filter(|name: &&String| rejectable.binary_search(name).is_err())
        .collect();
    eprintln!(
        "MEMBERSHIP {}: pinned_clean={} measured_clean={} pinned_rejectable={} measured_rejected={} \
         outside_rejectable={}",
        golden.display(),
        pinned_clean.len(),
        clean.len(),
        rejectable.len(),
        rejected.len(),
        unexpected.len()
    );
    for name in &unexpected {
        eprintln!(
            "  NOTE {name} is rejected by the jvm but absent from the known-bad list. It reached \
             the verifier for the first time rather than regressed, since a class that stops \
             verifying clean is caught by name below; read its VERIFY line above and add it to the \
             golden's REJECTABLE section"
        );
    }
    let gained: Vec<&String> = clean
        .iter()
        .filter(|name: &&String| pinned_clean.binary_search(name).is_err())
        .collect();
    let lost: Vec<&String> = pinned_clean
        .iter()
        .filter(|name: &&String| clean.binary_search(name).is_err())
        .collect();
    let mut drift: Vec<String> = Vec::new();
    drift.extend(lost.iter().map(|name: &&String| format!("lost {name}")));
    drift.extend(gained.iter().map(|name: &&String| format!("gained {name}")));
    assert!(
        drift.is_empty(),
        "{} of the pinned verifier-clean classes changed. A lost entry is a class that no longer \
         passes -Xverify:all and a gained entry is one that now does; either can happen while the \
         counts beside it stay flat, which is why the clean set is pinned by name. First \
         changes:\n{}",
        drift.len(),
        drift
            .iter()
            .take(40)
            .fold(String::new(), |mut acc: String, entry: &String| {
                acc.push_str(entry);
                acc.push('\n');
                acc
            })
    );
}

fn recovered_bodies(apk: &RealApk) -> (usize, usize, usize) {
    let bytes: Vec<u8> = std::fs::read(real_apk_path(apk.file)).expect("read apk");
    let extract: ApkExtract = extract_apk(&bytes).expect("extract apk");
    let mut method_total: usize = 0;
    let mut bodies_recovered: usize = 0;
    let mut dex_count: usize = 0;
    for (name, dex_bytes) in &extract.dex_files {
        if !name.ends_with(".dex") {
            continue;
        }
        dex_count += 1;
        let result: Dex2JarResult = translate_dex_bytes(dex_bytes).expect("translate dex");
        method_total += result.method_total;
        bodies_recovered += result.bodies_recovered;
    }
    (dex_count, bodies_recovered, method_total)
}

#[test]
fn realworld_apk_bodies_recovered_match_their_pinned_counts() {
    if std::env::var_os("DISROBE_RUN_REAL_APK_TESTS").is_none() {
        eprintln!(
            "SKIP: set DISROBE_RUN_REAL_APK_TESTS=1 to re-measure the local real apk corpus. This \
             counts methods the lifter lowered a body for rather than a throw-stub, which is the \
             lifter counting its own output; the verifier-attested figure is \
             dalvik_realworld_body_attest.rs"
        );
        return;
    }
    let absent: Vec<&'static str> = real_apks_absent();
    assert!(
        absent.is_empty(),
        "DISROBE_RUN_REAL_APK_TESTS=1 demands the whole real-apk corpus, because each published \
         per-apk figure is a numerator over that apk's own pinned method count; absent from {}: {}",
        real_apk_inbox().display(),
        absent.join(", ")
    );
    for apk in REAL_APKS {
        let (dex_count, bodies_recovered, method_total): (usize, usize, usize) =
            recovered_bodies(apk);
        eprintln!(
            "REALWORLD {}: dex_files={dex_count} self_reported_bodies={bodies_recovered}/{method_total} \
             (pinned {}/{})",
            apk.file, apk.self_reported_bodies_pinned, apk.method_total
        );
        assert!(
            dex_count >= 1,
            "{}: the apk must carry at least one classes.dex",
            apk.file
        );
        assert_eq!(
            method_total, apk.method_total,
            "{}: the apk defines {method_total} methods but the published denominator is pinned at \
             {}; a run that inspects a different population must not report against the published \
             figure",
            apk.file, apk.method_total
        );
        assert_eq!(
            bodies_recovered, apk.self_reported_bodies_pinned,
            "{}: the lifter lowered {bodies_recovered}/{method_total} bodies against the pinned \
             {}/{}. The apk is a fixed file and the translation is deterministic, so this count \
             cannot drift on its own, and dalvik_realworld_body_attest.rs pins the same per-apk \
             number by equality; a floor here would let one of the two disagree in silence",
            apk.file, apk.self_reported_bodies_pinned, apk.method_total
        );
    }
}

#[test]
fn realworld_apk_translated_classes_verify() {
    if std::env::var_os("DISROBE_RUN_REAL_APK_TESTS").is_none() {
        eprintln!(
            "SKIP: set DISROBE_RUN_REAL_APK_TESTS=1 to link the recovered classes of a real apk \
             under the real jvm verifier"
        );
        return;
    }
    let path: PathBuf = real_apk_path(CLASS_SCOPE_APK);
    assert!(
        path.is_file(),
        "the class-scope attestation needs {}",
        path.display()
    );
    let verifier: JvmVerifier = JvmVerifier::prepare(&format!(
        "disrobe_realworld_class_verify_{}",
        std::process::id()
    ))
    .expect("a JDK 24+ exposing java.lang.classfile is required to link recovered classes");

    let bytes: Vec<u8> = std::fs::read(&path).expect("read apk");
    let extract: ApkExtract = extract_apk(&bytes).expect("extract apk");
    let dex: &Vec<u8> = extract
        .dex_files
        .get(CLASS_SCOPE_DEX)
        .expect("the class-scope apk must carry classes.dex");
    let result: Dex2JarResult = translate_dex_bytes(dex).expect("translate");
    let jar: Vec<u8> = assemble_jar(&result).expect("assemble jar");
    let second: Dex2JarResult = translate_dex_bytes(dex).expect("translate");
    let second_jar: Vec<u8> = assemble_jar(&second).expect("assemble jar");
    assert_eq!(
        jar, second_jar,
        "translating the same dex twice in one process produced different jars, so the recovered \
         bytecode is not a function of the input alone and no verdict measured over it can be \
         reproducible"
    );
    let digest: String = format!(
        "{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(jar.as_slice())
    );
    eprintln!("CLASS SCOPE JAR sha256={digest} bytes={}", jar.len());
    assert_eq!(
        digest, CLASS_SCOPE_JAR_SHA256,
        "the jar this gate measures is not the one its verdicts were recorded against; the pinned \
         clean set and the known-bad list below describe a different build of the same apk"
    );
    let jar_path: PathBuf = verifier.write_jar("realworld-classes", &jar);
    let stdout: String = verifier.run(
        VerifyScope::Classes {
            permille: CLASS_SCOPE_PERMILLE,
        },
        jar_path.as_path(),
    );
    assert_permille(&stdout, CLASS_SCOPE_PERMILLE);

    let clean: usize = parse_metric(&stdout, "verify_clean_classes=");
    let failed: usize = parse_metric(&stdout, "lifter_verify_fail_classes=");
    let link_skipped: usize = parse_metric(&stdout, "link_skipped_classes=");
    let link_unstable: usize = parse_metric(&stdout, "link_unstable_classes=");
    let methods: usize = parse_metric(&stdout, "methods_clean=");
    let reported: Vec<String> = lines_with_prefix(&stdout, "VERIFY ");
    eprintln!(
        "REALWORLD CLASS VERIFY {CLASS_SCOPE_APK} {CLASS_SCOPE_DEX}: verify_clean_classes={clean} \
         lifter_verify_fail_classes={failed} link_skipped_classes={link_skipped} \
         link_unstable_classes={link_unstable} methods_in_clean_classes={methods} \
         recovered_classes={}",
        result.classes.len()
    );
    for line in &reported {
        eprintln!("  {line}");
    }
    let stubbed: BTreeSet<String> = lines_with_prefix(&stdout, "STUB ")
        .into_iter()
        .filter_map(|line: String| {
            line.strip_prefix("STUB ")
                .map(|name: &str| name.trim().replace('.', "/"))
        })
        .collect();
    let stub_named: usize = reported
        .iter()
        .filter(|line: &&String| rejected_types(line).any(|name: String| stubbed.contains(&name)))
        .count();
    eprintln!(
        "REALWORLD CLASS VERIFY STUB ATTRIBUTION: {stub_named} of {} rejected classes name, in the \
         Reason clause of the verifier's own message, one of the {} classes the apk does not \
         define and the harness had to stub. A stub is a bare subclass of RuntimeException, so it \
         has no supertypes and no subtypes: nothing is assignable to it and it is assignable to \
         nothing. Whatever assignability the original program got from the android framework \
         hierarchy is unavailable here whatever bytecode the lifter emits, so a check that failed \
         on a stubbed type is not evidence of a lifter defect. Putting android.jar on the \
         verification classpath is what would settle those; until then they are excluded from \
         neither the rejection count nor the clean count, and this figure is reported and never \
         asserted on",
        reported.len(),
        stubbed.len()
    );
    assert_eq!(
        reported.len(),
        failed,
        "the jvm reported {failed} rejected classes but named {}, so the rejection count is not \
         backed by the class names behind it",
        reported.len()
    );
    let clean_names: Vec<String> = verdict_names(&stdout, "CLEAN");
    let rejected_names: Vec<String> = verdict_names(&stdout, "REJECT");
    assert_eq!(
        clean_names.len(),
        clean,
        "the jvm reported {clean} verifier-clean classes but named {}, so the figure is not backed \
         by the class names behind it",
        clean_names.len()
    );
    assert_eq!(
        rejected_names.len(),
        failed,
        "the jvm reported {failed} rejected classes but named {} in its verdict list",
        rejected_names.len()
    );
    assert_verdict_membership(&clean_names, &rejected_names);
    assert_eq!(
        clean + failed + link_skipped + link_unstable,
        CLASS_SCOPE_CLASSES,
        "{CLASS_SCOPE_DEX} accounted for {} classes but the pinned population is \
         {CLASS_SCOPE_CLASSES}; a smaller run must score worse rather than shrink what it is \
         measured against",
        clean + failed + link_skipped + link_unstable
    );
    assert_eq!(
        link_unstable, 0,
        "{link_unstable} classes ended in a jvm resource error rather than a verdict, so this run \
         measured the lifter through a degraded jvm and its clean set is smaller than the lifter \
         earns. The bucket exists to keep such a class out of the rejection count, where it would \
         read as a lifter defect, and it is asserted empty so that an always-zero counter states a \
         precondition of the measurement instead of standing as unearned coverage"
    );
    assert!(
        clean + failed >= CLASS_SCOPE_GRADED_FLOOR,
        "only {} of {CLASS_SCOPE_CLASSES} recovered classes reached the verifier at all, below the \
         pinned {CLASS_SCOPE_GRADED_FLOOR}; {link_skipped} were link-skipped, and moving classes \
         into that bucket must not shrink the population the pass is graded over. The clean set \
         below is reproducible and pinned by name, so this bound guards the other side, which is \
         reach. It is empirical, set at the pinned clean count plus the rejections that recurred in \
         every one of {CLASS_SCOPE_REPEAT_RUNS} runs rather than at any single run's total, because \
         a bound pinned to one run's figure fails on the next",
        clean + failed
    );
    assert_eq!(
        clean, CLASS_SCOPE_CLEAN,
        "{clean} of {CLASS_SCOPE_CLASSES} recovered classes linked and verified under -Xverify:all \
         against the pinned {CLASS_SCOPE_CLEAN}. This is the number to trust: across \
         {CLASS_SCOPE_REPEAT_RUNS} runs of this test on the same apk, including two under compile \
         load from other work, this set came back byte-identical every time with nothing lost and \
         nothing gained, while which classes the jvm rejected rather than never loaded kept moving \
         around it. A change here is the lifter moving and not the harness, and the membership \
         assertion above names the classes that moved"
    );
    assert_eq!(
        methods, CLASS_SCOPE_CLEAN_METHODS,
        "the verifier-clean classes hold {methods} methods with code against the pinned \
         {CLASS_SCOPE_CLEAN_METHODS}"
    );
}
