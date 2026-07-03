#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{
    CallerKeyedReport, ClassFile, ProtectorPeelReport, allatori_protector, parse_classfile,
    recover_caller_keyed_strings,
};

const CALLER_KEYED: &[u8] = include_bytes!("../../../corpus/jvm/callerkeyed/CallerKeyed.class");
const ENV_KEYED: &[u8] = include_bytes!("../../../corpus/jvm/callerkeyed/EnvKeyed.class");

const ORACLE: &[&str] = &[
    "jdbc:postgresql://db.internal:5432/orders",
    "SELECT token FROM sessions WHERE id = ?",
    "Authorization: Bearer token",
    "X-Api-Key",
    "feature.rollout.enabled=true",
];

#[test]
fn recovers_caller_keyed_plaintext_from_real_javac_bytecode() {
    let cf: ClassFile = parse_classfile(CALLER_KEYED).expect("real CallerKeyed.class parses");
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);

    assert_eq!(
        report.decrypt_methods, 1,
        "the private static decrypt(String) is the lone decrypt method"
    );
    assert_eq!(
        report.call_sites, 5,
        "runConnect (2) + runAuth (2) + emitConfig (1) call sites"
    );

    let recovered: Vec<String> = report.recovered.values().cloned().collect();
    for want in ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "caller-context evaluator must recover {want:?} from real javac bytecode; got \
             {recovered:?}"
        );
    }
    assert_eq!(
        report.recovered.len(),
        ORACLE.len(),
        "every encrypted constant resolves and nothing extra is fabricated"
    );
    assert!(
        !report.runtime_key_wall,
        "the caller-derived key is fully static; no runtime wall here"
    );
}

#[test]
fn env_keyed_real_bytecode_walls_with_reason() {
    let cf: ClassFile = parse_classfile(ENV_KEYED).expect("real EnvKeyed.class parses");
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);

    assert!(
        report.recovered.is_empty(),
        "an environment/clock-keyed decrypt must fabricate no plaintext, got {:?}",
        report.recovered
    );
    assert!(
        report.runtime_key_wall,
        "System.getProperty + currentTimeMillis key is runtime-only; the pass must wall"
    );
    assert!(
        report
            .runtime_key_wall_reason
            .as_deref()
            .is_some_and(|r: &str| r.contains("runtime-only state")),
        "the wall must state the concrete runtime-key reason"
    );
}

#[test]
fn wired_protector_path_recovers_caller_keyed_strings() {
    let cf: ClassFile = parse_classfile(CALLER_KEYED).expect("real CallerKeyed.class parses");
    let report: ProtectorPeelReport =
        allatori_protector::peel(&cf, "com/disrobe/bench/CallerKeyed", "decrypt");
    let recovered: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in ORACLE {
        assert!(
            recovered.iter().any(|r: &String| r == want),
            "the wired protector peel must surface {want:?} via the caller-context evaluator; got \
             {recovered:?}"
        );
    }
    assert!(
        report
            .notes
            .iter()
            .any(|n: &String| n.contains("call-site bytecode evaluation")),
        "the recovery note must credit the call-site bytecode evaluator"
    );
}
