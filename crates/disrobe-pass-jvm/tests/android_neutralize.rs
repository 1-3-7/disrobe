#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_core::neutralize::{Applied, Refusal, RuntimeCheck, Selection, apply};
use disrobe_pass_jvm::dex::{parse as parse_dex, parse_code_items};
use disrobe_pass_jvm::{
    AndroidAuditReport, AuditFinding, DexNeutralization, audit_android_apk, plan_apk_neutralization,
};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/recon/android-audit")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn wrap_dex(dex: &[u8]) -> Vec<u8> {
    let mut apk: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
    {
        let mut writer: zip::ZipWriter<&mut std::io::Cursor<Vec<u8>>> =
            zip::ZipWriter::new(&mut apk);
        writer
            .start_file("classes.dex", zip::write::SimpleFileOptions::default())
            .expect("start classes.dex");
        std::io::Write::write_all(&mut writer, dex).expect("write classes.dex");
        writer.finish().expect("finish zip");
    }
    apk.into_inner()
}

#[test]
fn the_plant_apk_yields_one_patch_per_neutralizable_check_and_refuses_the_su_launch() {
    let plans: Vec<DexNeutralization> =
        plan_apk_neutralization(&fixture("audit-plants.apk")).expect("plan the plant apk");
    assert_eq!(plans.len(), 1);
    let dex: &DexNeutralization = &plans[0];
    assert_eq!(dex.entry, "classes.dex");
    assert_eq!(dex.audited_sites, 4, "{:#?}", dex.plan);
    assert_eq!(
        dex.plan.checks(),
        BTreeSet::from([
            RuntimeCheck::AndroidDebuggerConnected,
            RuntimeCheck::AndroidEmulatorFingerprint,
            RuntimeCheck::AndroidRootBinary,
        ]),
        "{:#?}",
        dex.plan
    );
    assert_eq!(dex.plan.patches.len(), 3, "{:#?}", dex.plan.patches);
    for patch in &dex.plan.patches {
        assert_eq!(patch.original.len(), 8);
        assert_eq!(patch.replacement.len(), 8);
        assert_eq!(patch.replacement[0], 0x12, "const/4 opens the replacement");
        assert!(
            patch.replacement[2..].iter().all(|b: &u8| *b == 0),
            "nops pad the site"
        );
        assert!(
            patch
                .anchor
                .instruction
                .contains("Lcom/planted/audit/Plants;->"),
            "{patch:?}"
        );
        assert!(patch.risk.contains("re-signed"));
    }
    let refused: Vec<&Refusal> = dex.plan.refusals.iter().collect();
    assert_eq!(refused.len(), 1, "{refused:#?}");
    assert_eq!(refused[0].check, RuntimeCheck::AndroidSuExecution);
    assert!(refused[0].anchor.instruction.contains("rootSuCommand"));
}

#[test]
fn applying_every_patch_removes_the_checks_and_keeps_the_dex_decodable() {
    let plans: Vec<DexNeutralization> =
        plan_apk_neutralization(&fixture("audit-plants.apk")).expect("plan the plant apk");
    let dex: &DexNeutralization = &plans[0];
    let applied: Applied = apply(&dex.bytes, &dex.plan, &Selection::All).expect("apply the plan");
    assert_eq!(applied.report.applied.len(), 3, "{:#?}", applied.report);
    assert!(applied.report.declined.is_empty());
    assert_ne!(applied.bytes, dex.bytes);
    assert_eq!(applied.bytes.len(), dex.bytes.len());
    let parsed = parse_dex(&applied.bytes).expect("the patched dex still parses");
    let code = parse_code_items(&parsed, &applied.bytes);
    assert!(
        code.unrecovered_tail().is_none(),
        "every method of the patched dex still decodes"
    );
    let before: AndroidAuditReport =
        audit_android_apk(&fixture("audit-plants.apk")).expect("audit before");
    let after: AndroidAuditReport =
        audit_android_apk(&wrap_dex(&applied.bytes)).expect("audit the patched dex");
    let rules = |report: &AndroidAuditReport| -> BTreeSet<String> {
        report
            .findings
            .iter()
            .map(|f: &AuditFinding| f.rule_id.clone())
            .collect()
    };
    assert!(rules(&before).contains("DR-APK-DEBUGGER-CHECK"));
    assert!(
        !rules(&after).contains("DR-APK-DEBUGGER-CHECK"),
        "the debugger call is gone: {:#?}",
        after.findings
    );
    assert_eq!(
        before.findings.len() - after.findings.len(),
        1,
        "only the debugger call site disappears; the emulator and root literals stay in the string pool: {:#?}",
        after.findings
    );
}

#[test]
fn the_control_apk_yields_no_patch_and_no_refusal() {
    let plans: Vec<DexNeutralization> =
        plan_apk_neutralization(&fixture("audit-control.apk")).expect("plan the control apk");
    assert_eq!(plans.len(), 1);
    assert!(plans[0].plan.is_empty(), "{:#?}", plans[0].plan);
    assert!(plans[0].plan.refusals.is_empty());
    assert_eq!(plans[0].audited_sites, 0);
}
