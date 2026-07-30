#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

pub mod common;

use std::path::{Path, PathBuf};

use common::{
    JvmVerifier, REAL_APKS, RealApk, VerifyScope, assert_permille, lines_with_prefix, parse_metric,
    real_apk_inbox, real_apk_path, real_apks_absent,
};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ApkExtract, assemble_jar, extract_apk};

const PUBLISHED_BAR_LABEL: &str = "body-lowering (real apks, local)";

const PUBLISHED_GROUP_HEADING: &str = "Dalvik recovered bodies";

const SAMPLE_PERMILLE: u32 = 100;

const WHOLE_BODY_POPULATION_PERMILLE: u32 = 1000;

const REAL_APK_METHOD_TOTAL: usize = 89_516;

const SELF_REPORTED_BODY_FLOOR: usize = 82_788;

const CANDIDATE_BODY_FLOOR: usize = 82_756;

const SAMPLED_BODY_FLOOR: usize = 8_343;

const ATTESTED_PRESENTED: usize = 2_994;

const ATTESTED_CLEAN_FLOOR: usize = 2_960;

const ATTESTED_FAIL_CEILING: usize = 34;

struct BodyAttest {
    self_reported_bodies: usize,
    method_total: usize,
    candidate_bodies: usize,
    sampled_bodies: usize,
    presented: usize,
    clean: usize,
    fail: usize,
    excl_ctor: usize,
    excl_invokespecial: usize,
    excl_unresolved: usize,
    excl_other: usize,
    membership: Vec<String>,
    failures: Vec<String>,
}

fn golden_path(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("golden");
    path.push("dalvik_body_attest");
    path.push(name);
    path
}

fn attest_apk(verifier: &JvmVerifier, apk: &RealApk, path: &Path) -> BodyAttest {
    let bytes: Vec<u8> = std::fs::read(path).expect("read apk");
    let extract: ApkExtract = extract_apk(&bytes).expect("extract apk");
    let mut out: BodyAttest = BodyAttest {
        self_reported_bodies: 0,
        method_total: 0,
        candidate_bodies: 0,
        sampled_bodies: 0,
        presented: 0,
        clean: 0,
        fail: 0,
        excl_ctor: 0,
        excl_invokespecial: 0,
        excl_unresolved: 0,
        excl_other: 0,
        membership: Vec::new(),
        failures: Vec::new(),
    };
    for (name, dex_bytes) in &extract.dex_files {
        if !name.ends_with(".dex") {
            continue;
        }
        let result: Dex2JarResult = translate_dex_bytes(dex_bytes).expect("translate dex");
        out.method_total += result.method_total;
        out.self_reported_bodies += result.bodies_recovered;
        let jar: Vec<u8> = assemble_jar(&result).expect("assemble jar");
        let label: String = format!("{}-{name}", apk.file);
        let jar_path: PathBuf = verifier.write_jar(&label, &jar);
        let stdout: String = verifier.run(
            VerifyScope::Bodies {
                permille: SAMPLE_PERMILLE,
            },
            jar_path.as_path(),
        );
        assert_permille(&stdout, SAMPLE_PERMILLE);
        out.candidate_bodies += parse_metric(&stdout, "candidate_bodies=");
        out.sampled_bodies += parse_metric(&stdout, "sampled_bodies=");
        out.presented += parse_metric(&stdout, "presented=");
        out.clean += parse_metric(&stdout, "body_clean=");
        out.fail += parse_metric(&stdout, "body_fail=");
        out.excl_ctor += parse_metric(&stdout, "excl_ctor=");
        out.excl_invokespecial += parse_metric(&stdout, "excl_invokespecial=");
        out.excl_unresolved += parse_metric(&stdout, "excl_unresolved=");
        out.excl_other += parse_metric(&stdout, "excl_other=");
        out.membership.extend(lines_with_prefix(&stdout, "ATTEST "));
        out.failures
            .extend(lines_with_prefix(&stdout, "BODYVERIFY "));
    }
    out.membership.extend(out.failures.iter().map(|f: &String| {
        let key: &str = f
            .trim_start_matches("BODYVERIFY ")
            .split(':')
            .next()
            .unwrap_or_default();
        format!("REJECT {key}")
    }));
    out.membership.sort();
    out.failures.sort();
    out
}

#[test]
fn realworld_dalvik_body_lowering_is_verifier_attested() {
    if std::env::var_os("DISROBE_RUN_REAL_APK_TESTS").is_none() {
        eprintln!(
            "SKIP {PUBLISHED_BAR_LABEL}: set DISROBE_RUN_REAL_APK_TESTS=1 to re-measure the local \
             real-apk corpus. The apks are gitignored, so CI cannot re-derive either figure; what \
             runs there is dalvik_body_attest_bar_matches_the_pins_this_gate_enforces, which holds \
             the published ratios to the counts pinned in this file."
        );
        return;
    }
    let absent: Vec<&'static str> = real_apks_absent();
    assert!(
        absent.is_empty(),
        "DISROBE_RUN_REAL_APK_TESTS=1 demands the whole real-apk corpus, because the published \
         denominators are pinned across all three apks and a partial run would measure a smaller \
         population under the same published figure; absent from {}: {}",
        real_apk_inbox().display(),
        absent.join(", ")
    );
    let verifier: JvmVerifier = JvmVerifier::prepare(&format!(
        "disrobe_dalvik_body_attest_{}",
        std::process::id()
    ))
    .expect("a JDK 24+ exposing java.lang.classfile is required to attest recovered bodies");

    let mut total_clean: usize = 0;
    let mut total_fail: usize = 0;
    let mut total_self: usize = 0;
    let mut total_methods: usize = 0;
    let mut total_candidates: usize = 0;
    let mut total_sampled: usize = 0;
    let mut total_presented: usize = 0;
    let mut membership: Vec<(&'static str, BodyAttest)> = Vec::new();
    for apk in REAL_APKS {
        let path: PathBuf = real_apk_path(apk.file);
        let attest: BodyAttest = attest_apk(&verifier, apk, path.as_path());
        eprintln!(
            "BODY ATTEST {} [{PUBLISHED_BAR_LABEL}]: self_reported={}/{} candidate_bodies={} \
             sampled={} presented={} attested_clean={}/{} attested_fail={} excl_ctor={} \
             excl_invokespecial={} excl_unresolved={} excl_other={}",
            apk.file,
            attest.self_reported_bodies,
            attest.method_total,
            attest.candidate_bodies,
            attest.sampled_bodies,
            attest.presented,
            attest.clean,
            attest.presented,
            attest.fail,
            attest.excl_ctor,
            attest.excl_invokespecial,
            attest.excl_unresolved,
            attest.excl_other
        );
        for failure in attest.failures.iter().take(40) {
            eprintln!("  {failure}");
        }
        assert_eq!(
            attest.method_total, apk.method_total,
            "{}: the apk defines {} methods but the published self-reported denominator is pinned \
             at {}; a different input is being measured under the published figure",
            apk.file, attest.method_total, apk.method_total
        );
        assert!(
            attest.self_reported_bodies >= apk.self_reported_bodies_floor,
            "{}: the lifter self-reports {}/{} lowered bodies, below the pinned {}/{}",
            apk.file,
            attest.self_reported_bodies,
            attest.method_total,
            apk.self_reported_bodies_floor,
            apk.method_total
        );
        assert!(
            attest.candidate_bodies >= apk.candidate_bodies_floor,
            "{}: {} non-stub candidate bodies reached the sampler, below the pinned {}",
            apk.file,
            attest.candidate_bodies,
            apk.candidate_bodies_floor
        );
        assert!(
            attest.sampled_bodies >= apk.sampled_bodies_floor,
            "{}: the {SAMPLE_PERMILLE}-permille sample selected {} bodies, below the pinned {}",
            apk.file,
            attest.sampled_bodies,
            apk.sampled_bodies_floor
        );
        assert_eq!(
            attest.presented,
            attest.clean + attest.fail,
            "{}: {} bodies were presented to the jvm but only {} clean plus {} rejected came back, \
             so the attested ratio is being computed over a population the harness did not grade",
            apk.file,
            attest.presented,
            attest.clean,
            attest.fail
        );
        assert_eq!(
            attest.presented, apk.presented_bodies,
            "{}: {} recovered bodies reached the real jvm verifier but the published attested \
             denominator is pinned at {}; re-measure and republish the attested ratio rather than \
             leaving the old one beside a different population",
            apk.file, attest.presented, apk.presented_bodies
        );
        assert!(
            attest.clean >= apk.attested_clean_floor,
            "{}: the real jvm verifier accepted {}/{} re-hosted bodies, below the pinned {}/{}",
            apk.file,
            attest.clean,
            attest.presented,
            apk.attested_clean_floor,
            apk.presented_bodies
        );
        assert!(
            attest.fail <= apk.attested_fail_ceiling,
            "{}: the real jvm verifier rejected {} re-hosted bodies, above the pinned ceiling {}",
            apk.file,
            attest.fail,
            apk.attested_fail_ceiling
        );
        total_clean += attest.clean;
        total_fail += attest.fail;
        total_self += attest.self_reported_bodies;
        total_methods += attest.method_total;
        total_candidates += attest.candidate_bodies;
        total_sampled += attest.sampled_bodies;
        total_presented += attest.presented;
        membership.push((apk.golden, attest));
    }

    let attested_pct: f64 = total_clean as f64 * 100.0 / total_presented.max(1) as f64;
    let self_pct: f64 = total_self as f64 * 100.0 / total_methods.max(1) as f64;
    eprintln!(
        "BODY ATTEST TOTAL [{PUBLISHED_BAR_LABEL}]: verifier_attested={total_clean}/{total_presented} \
         ({attested_pct:.1}%) from a {SAMPLE_PERMILLE}-permille deterministic sample that selected \
         {total_sampled} of {total_candidates} non-stub bodies; self_reported_bodies={total_self}/{total_methods} \
         ({self_pct:.1}%). The two denominators are different populations and neither figure implies the other."
    );
    check_membership(&membership);
    assert_eq!(
        total_methods, REAL_APK_METHOD_TOTAL,
        "the real apks define {total_methods} methods but the published self-reported denominator \
         is pinned at {REAL_APK_METHOD_TOTAL}"
    );
    assert_eq!(
        total_presented, ATTESTED_PRESENTED,
        "{total_presented} recovered bodies reached the real jvm verifier but the published \
         attested denominator is pinned at {ATTESTED_PRESENTED}"
    );
    assert!(
        total_candidates >= CANDIDATE_BODY_FLOOR,
        "{total_candidates} non-stub candidate bodies reached the sampler, below the pinned \
         {CANDIDATE_BODY_FLOOR}"
    );
    assert!(
        total_sampled >= SAMPLED_BODY_FLOOR,
        "the deterministic sample selected {total_sampled} bodies, below the pinned \
         {SAMPLED_BODY_FLOOR}"
    );
    assert!(
        total_fail <= ATTESTED_FAIL_CEILING,
        "the real jvm verifier rejected {total_fail} re-hosted real-apk bodies, above the pinned \
         ceiling {ATTESTED_FAIL_CEILING}"
    );
    assert!(
        total_clean >= ATTESTED_CLEAN_FLOOR,
        "verifier-attested real-apk bodies {total_clean}/{total_presented} fell below the pinned \
         {ATTESTED_CLEAN_FLOOR}/{ATTESTED_PRESENTED}"
    );
    assert!(
        total_self >= SELF_REPORTED_BODY_FLOOR,
        "self-reported recovered bodies {total_self}/{total_methods} fell below the pinned \
         {SELF_REPORTED_BODY_FLOOR}/{REAL_APK_METHOD_TOTAL}"
    );
}

fn recovery_json() -> serde_json::Value {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("xtask");
    path.push("data");
    path.push("recovery.json");
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {} ({e})", path.display()));
    serde_json::from_str(&raw).expect("parse recovery.json")
}

fn published_bar(doc: &serde_json::Value) -> &serde_json::Value {
    doc["groups"]
        .as_array()
        .expect("recovery.json groups")
        .iter()
        .filter(|group: &&serde_json::Value| {
            group["heading"]
                .as_str()
                .is_some_and(|heading: &str| heading.starts_with(PUBLISHED_GROUP_HEADING))
        })
        .flat_map(|group: &serde_json::Value| group["bars"].as_array().expect("bars").iter())
        .find(|bar: &&serde_json::Value| bar["label"].as_str() == Some(PUBLISHED_BAR_LABEL))
        .unwrap_or_else(|| {
            panic!(
                "recovery.json carries no `{PUBLISHED_BAR_LABEL}` bar under a \
                 `{PUBLISHED_GROUP_HEADING}` heading, so the real-apk figure every document \
                 renders is sourced from nothing"
            )
        })
}

fn required_count(bar: &serde_json::Value, key: &str) -> u64 {
    bar[key].as_u64().unwrap_or_else(|| {
        panic!(
            "the `{PUBLISHED_BAR_LABEL}` bar carries no `{key}`, so the published real-apk figure \
             is a percentage with no counts behind it. Record `num`/`den` for the self-reported \
             lowered-body count and `attested_num`/`attested_den` for the count the real jvm \
             verifier accepted, because they are separate populations with different denominators"
        )
    })
}

#[test]
fn dalvik_body_attest_bar_matches_the_pins_this_gate_enforces() {
    let methods: usize = REAL_APKS.iter().map(|apk: &RealApk| apk.method_total).sum();
    let bodies: usize = REAL_APKS
        .iter()
        .map(|apk: &RealApk| apk.self_reported_bodies_floor)
        .sum();
    let candidates: usize = REAL_APKS
        .iter()
        .map(|apk: &RealApk| apk.candidate_bodies_floor)
        .sum();
    let sampled: usize = REAL_APKS
        .iter()
        .map(|apk: &RealApk| apk.sampled_bodies_floor)
        .sum();
    let presented: usize = REAL_APKS
        .iter()
        .map(|apk: &RealApk| apk.presented_bodies)
        .sum();
    let clean: usize = REAL_APKS
        .iter()
        .map(|apk: &RealApk| apk.attested_clean_floor)
        .sum();
    let rejected: usize = REAL_APKS
        .iter()
        .map(|apk: &RealApk| apk.attested_fail_ceiling)
        .sum();
    assert_eq!(
        (methods, bodies, candidates, sampled),
        (
            REAL_APK_METHOD_TOTAL,
            SELF_REPORTED_BODY_FLOOR,
            CANDIDATE_BODY_FLOOR,
            SAMPLED_BODY_FLOOR
        ),
        "the per-apk pins in common::REAL_APKS no longer sum to the corpus totals this file \
         publishes, so one apk could regress while the total held"
    );
    assert_eq!(
        (presented, clean, rejected),
        (
            ATTESTED_PRESENTED,
            ATTESTED_CLEAN_FLOOR,
            ATTESTED_FAIL_CEILING
        ),
        "the per-apk verifier-attested pins no longer sum to the corpus totals this file publishes"
    );
    assert!(
        presented < sampled && sampled < candidates && candidates <= bodies,
        "the attested population must stay a strict subset of the sampled bodies and the sample a \
         subset of the candidates: presented={presented} sampled={sampled} candidates={candidates} \
         self_reported={bodies}"
    );

    let doc: serde_json::Value = recovery_json();
    let bar: &serde_json::Value = published_bar(&doc);
    let num: u64 = required_count(bar, "num");
    let den: u64 = required_count(bar, "den");
    let attested_num: u64 = required_count(bar, "attested_num");
    let attested_den: u64 = required_count(bar, "attested_den");
    assert_eq!(
        (num, den),
        (
            SELF_REPORTED_BODY_FLOOR as u64,
            REAL_APK_METHOD_TOTAL as u64
        ),
        "recovery.json publishes {num}/{den} self-reported lowered bodies but this gate pins \
         {SELF_REPORTED_BODY_FLOOR}/{REAL_APK_METHOD_TOTAL}"
    );
    assert_eq!(
        (attested_num, attested_den),
        (ATTESTED_CLEAN_FLOOR as u64, ATTESTED_PRESENTED as u64),
        "recovery.json publishes {attested_num}/{attested_den} verifier-attested bodies but this \
         gate pins {ATTESTED_CLEAN_FLOOR}/{ATTESTED_PRESENTED}"
    );
    assert_ne!(
        (attested_num, attested_den),
        (num, den),
        "the verifier-attested count and the self-reported count are separate populations; \
         publishing one as the other is the defect this bar exists to keep out"
    );

    let value: f64 = bar["value"]
        .as_f64()
        .unwrap_or_else(|| panic!("the `{PUBLISHED_BAR_LABEL}` bar records no plotted percentage"));
    let plotted: f64 = (num as f64 * 1000.0 / den as f64).round() / 10.0;
    assert!(
        (value - plotted).abs() < f64::EPSILON,
        "recovery.json plots {value} for {PUBLISHED_BAR_LABEL} while {num}/{den} is {plotted}"
    );

    let detail: &str = bar["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("the `{PUBLISHED_BAR_LABEL}` bar records no detail prose"));
    let mut unstated: Vec<String> = Vec::new();
    for apk in REAL_APKS {
        unstated.extend(
            [
                format!(
                    "{} {} of {}",
                    apk.short, apk.self_reported_bodies_floor, apk.method_total
                ),
                format!(
                    "{} {} of {}",
                    apk.short, apk.attested_clean_floor, apk.presented_bodies
                ),
            ]
            .into_iter()
            .filter(|phrase: &String| !detail.contains(phrase.as_str())),
        );
    }
    unstated.extend(
        [
            format!("{SELF_REPORTED_BODY_FLOOR} of {REAL_APK_METHOD_TOTAL}"),
            format!("{ATTESTED_CLEAN_FLOOR} of {ATTESTED_PRESENTED}"),
            format!("{CANDIDATE_BODY_FLOOR} non-stub candidate bodies"),
            SAMPLED_BODY_FLOOR.to_string(),
            (SAMPLED_BODY_FLOOR - ATTESTED_PRESENTED).to_string(),
            "ungraded".to_string(),
        ]
        .into_iter()
        .filter(|phrase: &String| !detail.contains(phrase.as_str())),
    );
    assert!(
        unstated.is_empty(),
        "the `{PUBLISHED_BAR_LABEL}` detail is what every document renders beside the chart, and \
         it does not state: {}. Each apk needs its own numerator over its own denominator so one \
         apk's figure cannot be published against another apk's population, and the excluded \
         bodies must be named as ungraded rather than counted as passing",
        unstated.join(" | ")
    );
}

fn check_membership(membership: &[(&'static str, BodyAttest)]) {
    let refresh: bool = std::env::var_os("DISROBE_WRITE_BODY_ATTEST_MEMBERSHIP").is_some();
    let mut missing: Vec<String> = Vec::new();
    for (name, attest) in membership {
        let golden: PathBuf = golden_path(name);
        let rendered: String = format!("{}\n", attest.membership.join("\n"));
        if refresh {
            std::fs::create_dir_all(golden.parent().expect("golden parent"))
                .expect("create membership dir");
            std::fs::write(&golden, rendered.as_bytes()).expect("write membership list");
            eprintln!(
                "wrote {} membership entries to {}",
                attest.membership.len(),
                golden.display()
            );
            continue;
        }
        let Ok(recorded): Result<String, _> = std::fs::read_to_string(&golden) else {
            missing.push(format!(
                "{} ({} membership entries measured)",
                golden.display(),
                attest.membership.len()
            ));
            continue;
        };
        let recorded: String = recorded.replace("\r\n", "\n");
        let recorded_set: Vec<&str> = recorded.lines().filter(|l: &&str| !l.is_empty()).collect();
        let measured_set: Vec<&str> = rendered.lines().filter(|l: &&str| !l.is_empty()).collect();
        let lost: Vec<&&str> = recorded_set
            .iter()
            .filter(|l: &&&str| !measured_set.contains(*l))
            .collect();
        let gained: usize = measured_set
            .iter()
            .filter(|l: &&&str| !recorded_set.contains(*l))
            .count();
        eprintln!(
            "MEMBERSHIP {}: pinned={} measured={} lost={} gained={}",
            golden.display(),
            recorded_set.len(),
            measured_set.len(),
            lost.len(),
            gained
        );
        assert!(
            lost.is_empty(),
            "{}: {} pinned entries changed outcome (an ATTEST line here means that body no longer \
             verifies, a REJECT line means it now does); first losses:\n{}",
            golden.display(),
            lost.len(),
            lost.iter()
                .take(20)
                .fold(String::new(), |mut acc: String, l: &&&str| {
                    acc.push_str(l);
                    acc.push('\n');
                    acc
                })
        );
        assert_eq!(
            gained,
            0,
            "{}: {gained} membership entries are new; re-run with \
             DISROBE_WRITE_BODY_ATTEST_MEMBERSHIP=1 to record them",
            golden.display()
        );
    }
    assert!(
        missing.is_empty(),
        "membership lists absent, so a body could regress while a count stays flat; re-run with \
         DISROBE_WRITE_BODY_ATTEST_MEMBERSHIP=1 to record: {}",
        missing.join(", ")
    );
}

const MUTATION_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");

#[test]
fn body_attest_rejects_a_corrupted_recovered_body() {
    let verifier: JvmVerifier = match JvmVerifier::prepare(&format!(
        "disrobe_dalvik_body_attest_mutation_{}",
        std::process::id()
    )) {
        Ok(v) => v,
        Err(why) => {
            eprintln!("SKIP body-attest mutation control: {why}");
            return;
        }
    };
    let result: Dex2JarResult = translate_dex_bytes(MUTATION_DEX).expect("translate dex");
    let clean_jar: Vec<u8> = assemble_jar(&result).expect("assemble jar");
    let clean_path: PathBuf = verifier.write_jar("mutation-clean", &clean_jar);
    let clean_classes: String = verifier.run(
        VerifyScope::Classes {
            permille: WHOLE_BODY_POPULATION_PERMILLE,
        },
        clean_path.as_path(),
    );
    let clean_bodies: String = verifier.run(
        VerifyScope::Bodies {
            permille: WHOLE_BODY_POPULATION_PERMILLE,
        },
        clean_path.as_path(),
    );
    assert_permille(&clean_classes, WHOLE_BODY_POPULATION_PERMILLE);
    assert_permille(&clean_bodies, WHOLE_BODY_POPULATION_PERMILLE);
    let clean_class_fail: usize = parse_metric(&clean_classes, "lifter_verify_fail_classes=");
    let clean_ok: usize = parse_metric(&clean_bodies, "body_clean=");
    let clean_fail: usize = parse_metric(&clean_bodies, "body_fail=");
    assert!(
        clean_class_fail == 0 && clean_ok > 0 && clean_fail == 0,
        "the committed dex must attest cleanly before the corruption control means anything: \
         class_fail={clean_class_fail} body_clean={clean_ok} body_fail={clean_fail}"
    );
    let attested: Vec<String> = lines_with_prefix(&clean_bodies, "ATTEST ")
        .into_iter()
        .map(|l: String| l.trim_start_matches("ATTEST ").to_string())
        .collect();

    let mut corrupted: Dex2JarResult = result;
    let victim: String = corrupt_one_primitive_load(&mut corrupted, &attested);
    let victim_class: &str = victim.split('#').next().expect("victim class");
    let bad_jar: Vec<u8> = assemble_jar(&corrupted).expect("assemble corrupted jar");
    let bad_path: PathBuf = verifier.write_jar("mutation-corrupt", &bad_jar);
    let bad_classes: String = verifier.run(
        VerifyScope::Classes {
            permille: WHOLE_BODY_POPULATION_PERMILLE,
        },
        bad_path.as_path(),
    );
    let bad_bodies: String = verifier.run(
        VerifyScope::Bodies {
            permille: WHOLE_BODY_POPULATION_PERMILLE,
        },
        bad_path.as_path(),
    );
    assert_permille(&bad_classes, WHOLE_BODY_POPULATION_PERMILLE);
    assert_permille(&bad_bodies, WHOLE_BODY_POPULATION_PERMILLE);
    let bad_class_fail: usize = parse_metric(&bad_classes, "lifter_verify_fail_classes=");
    let class_errors: Vec<String> = lines_with_prefix(&bad_classes, "VERIFY ");
    let body_reports: Vec<String> = lines_with_prefix(&bad_bodies, "BODYVERIFY ")
        .into_iter()
        .chain(lines_with_prefix(&bad_bodies, "BODYREJECT "))
        .collect();
    let still_attested: bool = lines_with_prefix(&bad_bodies, "ATTEST ")
        .iter()
        .any(|l: &String| l.trim_start_matches("ATTEST ") == victim);
    eprintln!(
        "BODY ATTEST MUTATION: corrupted {victim}; lifter_verify_fail_classes={bad_class_fail} \
         still_attested={still_attested}"
    );
    for line in class_errors
        .iter()
        .chain(body_reports.iter())
        .filter(|l: &&String| l.contains(victim_class))
        .take(4)
    {
        eprintln!("  {line}");
    }
    assert!(
        bad_class_fail >= 1
            && class_errors
                .iter()
                .any(|l: &String| l.starts_with(&format!("VERIFY {victim_class}:"))),
        "the real JVM verifier accepted knowingly malformed bytecode in {victim}, so this gate \
         measures nothing:\n{bad_classes}"
    );
    assert!(
        !still_attested && body_reports.iter().any(|l: &String| l.contains(&victim)),
        "the body-attest scope must drop {victim} from the attested set and name it as rejected; \
         still_attested={still_attested}, reports:\n{}",
        body_reports.join("\n")
    );
}

fn corrupt_one_primitive_load(result: &mut Dex2JarResult, attested: &[String]) -> String {
    use disrobe_pass_jvm::bytecode::{
        CodeAttribute, Instruction, disassemble, parse_code_attribute,
    };
    use disrobe_pass_jvm::classfile::{Attribute, ClassFile, MethodInfo};
    use disrobe_pass_jvm::parse_classfile;

    const ALOAD_0: u8 = 0x2A;

    for (entry, bytes) in &mut result.jar_entries {
        if !entry.ends_with(".class") {
            continue;
        }
        let cf: ClassFile = match parse_classfile(bytes) {
            Ok(cf) => cf,
            Err(_) => continue,
        };
        let class: String = entry.trim_end_matches(".class").replace('/', ".");
        for method in &cf.methods {
            let method: &MethodInfo = method;
            let Ok(name): Result<&str, _> = cf.utf8_at(method.name_index) else {
                continue;
            };
            let Ok(descriptor): Result<&str, _> = cf.utf8_at(method.descriptor_index) else {
                continue;
            };
            let key: String = format!("{class}#{name}{descriptor}");
            if method.access_flags & 0x0008 == 0 {
                continue;
            }
            if !attested.contains(&key) {
                continue;
            }
            let Some(code): Option<CodeAttribute> = method
                .attributes
                .iter()
                .filter(|a: &&Attribute| cf.utf8_at(a.name_index).is_ok_and(|n: &str| n == "Code"))
                .find_map(|a: &Attribute| parse_code_attribute(&a.info).ok())
            else {
                continue;
            };
            let Ok(insns): Result<Vec<Instruction>, _> = disassemble(&code.code) else {
                continue;
            };
            if insns
                .iter()
                .any(|i: &Instruction| i.mnemonic == "invokespecial")
            {
                continue;
            }
            let first: Option<&'static str> = insns.first().map(|i: &Instruction| i.mnemonic);
            if code.code.len() < 8 || !matches!(first, Some("iload_0" | "fload_0")) {
                continue;
            }
            let occurrences: usize = bytes
                .windows(code.code.len())
                .filter(|w: &&[u8]| *w == code.code.as_slice())
                .count();
            if occurrences != 1 {
                continue;
            }
            let at: usize = bytes
                .windows(code.code.len())
                .position(|w: &[u8]| w == code.code.as_slice())
                .expect("code slice located");
            bytes[at] = ALOAD_0;
            return key;
        }
    }
    panic!("no attested static void body with a trailing return was available to corrupt");
}
