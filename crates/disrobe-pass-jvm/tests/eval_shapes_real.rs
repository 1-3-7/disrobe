#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{
    CallerKeyedReport, ClassFile, PeelStatus, ProtectorPeelReport, allatori_protector,
    parse_classfile, recover_caller_keyed_strings, zelix_protector,
};

const LONG_ACCUM: &[u8] = include_bytes!("../../../corpus/jvm/evalshapes/LongAccumCrypt.class");
const INSTANCE: &[u8] = include_bytes!("../../../corpus/jvm/evalshapes/InstanceFieldKeyed.class");
const SWITCHD: &[u8] = include_bytes!("../../../corpus/jvm/evalshapes/SwitchDispatch.class");
const NAME_REFLECT: &[u8] = include_bytes!("../../../corpus/jvm/evalshapes/NameReflectKeyed.class");

const LONG_ACCUM_ORACLE: &[&str] = &[
    "jdbc:sqlserver://db.corp:1433;db=ledger",
    "X-Tenant-Signature: a91c0ffe",
    "https://vault.internal/v1/secret/data",
];

const INSTANCE_ORACLE: &[&str] = &[
    "amqp://broker.internal:5672/events",
    "ROLE_PLATFORM_ADMIN",
    "/var/run/secrets/token",
];

const SWITCH_ORACLE: &[&str] = &[
    "kafka://stream.internal:9092/audit",
    "Bearer eyJhbGciOiJIUzI1NiJ9",
    "s3://artifacts-prod/keys/master",
];

const NAME_REFLECT_ORACLE: &[&str] = &[
    "registry.internal:8443/v2",
    "svc-payments-prod",
    "whsec_3f9a2b7c1d8e4056",
];

fn recovered_set(cf: &ClassFile) -> Vec<String> {
    let report: CallerKeyedReport = recover_caller_keyed_strings(cf);
    report.recovered.values().cloned().collect()
}

#[test]
fn long_accumulator_decrypt_recovers_via_long_arithmetic_and_wide_locals() {
    let cf: ClassFile = parse_classfile(LONG_ACCUM).expect("LongAccumCrypt.class parses");
    let got: Vec<String> = recovered_set(&cf);
    for want in LONG_ACCUM_ORACLE {
        assert!(
            got.iter().any(|s: &String| s == want),
            "the evaluator must run the class's own long-accumulator decrypt (lstore/lload wide \
             slots, lmul/ladd/lxor/lushr, ldc2_w, a long-returning mix helper) and recover \
             {want:?}; got {got:?}"
        );
    }
    assert_eq!(got.len(), LONG_ACCUM_ORACLE.len());
}

#[test]
fn instance_field_keyed_decrypt_recovers_via_constructor_and_getfield() {
    let cf: ClassFile = parse_classfile(INSTANCE).expect("InstanceFieldKeyed.class parses");
    let got: Vec<String> = recovered_set(&cf);
    for want in INSTANCE_ORACLE {
        assert!(
            got.iter().any(|s: &String| s == want),
            "the evaluator must construct the receiver, run its <init> to populate the key field, \
             then read this.base via getfield inside the instance decrypt and recover {want:?}; \
             got {got:?}"
        );
    }
    assert_eq!(got.len(), INSTANCE_ORACLE.len());
}

#[test]
fn switch_dispatched_decrypt_recovers_via_tableswitch() {
    let cf: ClassFile = parse_classfile(SWITCHD).expect("SwitchDispatch.class parses");
    let got: Vec<String> = recovered_set(&cf);
    for want in SWITCH_ORACLE {
        assert!(
            got.iter().any(|s: &String| s == want),
            "the evaluator must follow the per-position tableswitch key selector and recover \
             {want:?}; got {got:?}"
        );
    }
    assert_eq!(got.len(), SWITCH_ORACLE.len());
}

#[test]
fn name_reflect_keyed_decrypt_recovers_via_static_class_name_reflection() {
    let cf: ClassFile = parse_classfile(NAME_REFLECT).expect("NameReflectKeyed.class parses");
    let got: Vec<String> = recovered_set(&cf);
    for want in NAME_REFLECT_ORACLE {
        assert!(
            got.iter().any(|s: &String| s == want),
            "the evaluator must resolve NameReflectKeyed.class.getName() to the static class name, \
             seed the per-class key from it, and recover {want:?}; got {got:?}"
        );
    }
    assert_eq!(got.len(), NAME_REFLECT_ORACLE.len());
}

#[test]
fn name_reflect_keyed_is_not_walled_as_runtime() {
    let cf: ClassFile = parse_classfile(NAME_REFLECT).expect("parses");
    let report: CallerKeyedReport = recover_caller_keyed_strings(&cf);
    assert!(
        !report.runtime_key_wall,
        "a key seeded on the class's own name via reflection is fully static; the class name is \
         present in the artifact, so this must not be flagged a runtime-key wall"
    );
}

#[test]
fn wired_peel_flips_name_reflect_to_recovered() {
    let cf: ClassFile = parse_classfile(NAME_REFLECT).expect("parses");
    let report: ProtectorPeelReport = zelix_protector::peel(&cf);
    assert_eq!(report.status, PeelStatus::StubRecovered);
    let got: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in NAME_REFLECT_ORACLE {
        assert!(got.iter().any(|s: &String| s == want), "missing {want:?}");
    }
}

#[test]
fn wired_peel_flips_long_accumulator_to_recovered() {
    let cf: ClassFile = parse_classfile(LONG_ACCUM).expect("parses");
    let report: ProtectorPeelReport =
        allatori_protector::peel(&cf, "com/disrobe/bench/LongAccumCrypt", "decrypt");
    assert_eq!(
        report.status,
        PeelStatus::StubRecovered,
        "with the long-accumulator decrypt now executable, the peel reports a real recovery"
    );
    let got: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in LONG_ACCUM_ORACLE {
        assert!(got.iter().any(|s: &String| s == want), "missing {want:?}");
    }
}

#[test]
fn wired_peel_flips_instance_field_to_recovered() {
    let cf: ClassFile = parse_classfile(INSTANCE).expect("parses");
    let report: ProtectorPeelReport = zelix_protector::peel(&cf);
    assert_eq!(report.status, PeelStatus::StubRecovered);
    let got: Vec<String> = report.strings_recovered.values().cloned().collect();
    for want in INSTANCE_ORACLE {
        assert!(got.iter().any(|s: &String| s == want), "missing {want:?}");
    }
}
