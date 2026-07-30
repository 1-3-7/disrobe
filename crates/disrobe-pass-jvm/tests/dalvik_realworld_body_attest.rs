#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

pub mod common;

use std::path::PathBuf;

use common::{JvmVerifier, VerifyScope, lines_with_prefix, parse_metric};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{ApkExtract, assemble_jar, extract_apk};

const PUBLISHED_BAR_LABEL: &str = "body-lowering (real apks, local)";

const SAMPLE_PERMILLE: u32 = 100;

struct AttestTarget {
    file: &'static str,
    golden: &'static str,
}

const TARGETS: &[AttestTarget] = &[
    AttestTarget {
        file: "transmissionic-ionic.apk",
        golden: "transmissionic-ionic.txt",
    },
    AttestTarget {
        file: "rustdesk-flutter.apk",
        golden: "rustdesk-flutter.txt",
    },
    AttestTarget {
        file: "enrecipes-nativescript.apk",
        golden: "enrecipes-nativescript.txt",
    },
];

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

fn golden_path(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("golden");
    p.push("dalvik_body_attest");
    p.push(name);
    p
}

fn attest_apk(verifier: &JvmVerifier, target: &AttestTarget, path: &PathBuf) -> BodyAttest {
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
        let label: String = format!("{}-{name}", target.file);
        let jar_path: PathBuf = verifier.write_jar(&label, &jar);
        let stdout: String = verifier.run(
            VerifyScope::Bodies {
                permille: SAMPLE_PERMILLE,
            },
            jar_path.as_path(),
        );
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
            "SKIP {PUBLISHED_BAR_LABEL}: set DISROBE_RUN_REAL_APK_TESTS=1 to re-measure the \
             local real-apk corpus (the apks are gitignored, so this bar cannot be attested in CI; \
             the committed-corpus bar is the CI-enforced attestation)"
        );
        return;
    }
    let present: Vec<(&AttestTarget, PathBuf)> = TARGETS
        .iter()
        .map(|t: &AttestTarget| (t, corpus(&["mobile", "apk", "inbox", t.file])))
        .filter(|(_, p): &(&AttestTarget, PathBuf)| p.is_file())
        .collect();
    assert!(
        !present.is_empty(),
        "DISROBE_RUN_REAL_APK_TESTS=1 was set but none of the real apks are present under {}",
        corpus(&["mobile", "apk", "inbox"]).display()
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
    let mut membership: Vec<(&'static str, BodyAttest)> = Vec::new();
    for (target, path) in &present {
        let a: BodyAttest = attest_apk(&verifier, target, path);
        let self_pct: f64 = a.self_reported_bodies as f64 * 100.0 / a.method_total.max(1) as f64;
        let attested_pct: f64 = a.clean as f64 * 100.0 / (a.clean + a.fail).max(1) as f64;
        eprintln!(
            "BODY ATTEST {} [{PUBLISHED_BAR_LABEL}]: self_reported={}/{} ({self_pct:.1}%) \
             candidate_bodies={} sampled={} presented={} attested_clean={} attested_fail={} \
             ({attested_pct:.1}% of presented) excl_ctor={} excl_invokespecial={} \
             excl_unresolved={} excl_other={}",
            target.file,
            a.self_reported_bodies,
            a.method_total,
            a.candidate_bodies,
            a.sampled_bodies,
            a.presented,
            a.clean,
            a.fail,
            a.excl_ctor,
            a.excl_invokespecial,
            a.excl_unresolved,
            a.excl_other
        );
        for f in a.failures.iter().take(40) {
            eprintln!("  {f}");
        }
        total_clean += a.clean;
        total_fail += a.fail;
        total_self += a.self_reported_bodies;
        total_methods += a.method_total;
        membership.push((target.golden, a));
    }

    let presented: usize = total_clean + total_fail;
    let attested_pct: f64 = total_clean as f64 * 100.0 / presented.max(1) as f64;
    let self_pct: f64 = total_self as f64 * 100.0 / total_methods.max(1) as f64;
    eprintln!(
        "BODY ATTEST TOTAL [{PUBLISHED_BAR_LABEL}]: verifier_attested={total_clean}/{presented} \
         ({attested_pct:.1}%) at a {SAMPLE_PERMILLE}-permille deterministic sample of non-stub bodies; \
         self_reported_bodies={total_self}/{total_methods} ({self_pct:.1}%)"
    );
    check_membership(&membership);
    assert!(
        total_fail <= ATTESTED_FAIL_CEILING,
        "the real JVM verifier rejected {total_fail} re-hosted real-apk bodies, above the pinned \
         ceiling {ATTESTED_FAIL_CEILING}"
    );
    assert!(
        total_clean >= ATTESTED_CLEAN_FLOOR,
        "verifier-attested real-apk bodies {total_clean} fell below floor {ATTESTED_CLEAN_FLOOR}"
    );
    assert!(
        total_self >= SELF_REPORTED_BODY_FLOOR,
        "self-reported recovered bodies {total_self} fell below floor {SELF_REPORTED_BODY_FLOOR}"
    );
    assert!(
        total_methods >= METHOD_TOTAL_FLOOR,
        "defined methods across the real apks {total_methods} fell below floor {METHOD_TOTAL_FLOOR}"
    );
    assert_published_bar(total_self, total_methods, total_clean, presented);
}

fn assert_published_bar(
    self_reported: usize,
    method_total: usize,
    attested_clean: usize,
    presented: usize,
) {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("xtask");
    path.push("data");
    path.push("recovery.json");
    let raw: String =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {} ({e})", path.display()));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse recovery.json");
    let bar: &serde_json::Value = doc["groups"]
        .as_array()
        .expect("recovery.json groups")
        .iter()
        .filter(|g: &&serde_json::Value| {
            g["heading"]
                .as_str()
                .is_some_and(|h: &str| h.starts_with("Dalvik recovered bodies"))
        })
        .flat_map(|g: &serde_json::Value| g["bars"].as_array().expect("bars").iter())
        .find(|b: &&serde_json::Value| b["label"].as_str() == Some(PUBLISHED_BAR_LABEL))
        .unwrap_or_else(|| panic!("no {PUBLISHED_BAR_LABEL} bar in {}", path.display()));

    let published: f64 = bar["value"].as_f64().expect("bar value");
    let measured: f64 = (self_reported as f64 * 1000.0 / method_total.max(1) as f64).round() / 10.0;
    assert!(
        (published - measured).abs() < f64::EPSILON,
        "recovery.json publishes {published} for {PUBLISHED_BAR_LABEL} but the lifter self-reports \
         {self_reported}/{method_total} = {measured} on the local real-apk corpus"
    );
    if let Some(num) = bar["num"].as_u64() {
        let den: u64 = bar["den"].as_u64().expect("a num must carry its den");
        assert_eq!(
            (num, den),
            (self_reported as u64, method_total as u64),
            "recovery.json publishes {num}/{den} for {PUBLISHED_BAR_LABEL}; measured \
             {self_reported}/{method_total}"
        );
    }
    if let Some(attested) = bar["attested_num"].as_u64() {
        let den: u64 = bar["attested_den"]
            .as_u64()
            .expect("attested_num needs its den");
        assert_eq!(
            (attested, den),
            (attested_clean as u64, presented as u64),
            "recovery.json publishes {attested}/{den} verifier-attested bodies; measured \
             {attested_clean}/{presented}"
        );
    }
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

const ATTESTED_CLEAN_FLOOR: usize = 2_960;

const ATTESTED_FAIL_CEILING: usize = 34;

const SELF_REPORTED_BODY_FLOOR: usize = 82_788;

const METHOD_TOTAL_FLOOR: usize = 89_516;

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
    let clean_classes: String = verifier.run(VerifyScope::Classes, clean_path.as_path());
    let clean_bodies: String =
        verifier.run(VerifyScope::Bodies { permille: 1000 }, clean_path.as_path());
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
    let bad_classes: String = verifier.run(VerifyScope::Classes, bad_path.as_path());
    let bad_bodies: String =
        verifier.run(VerifyScope::Bodies { permille: 1000 }, bad_path.as_path());
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
