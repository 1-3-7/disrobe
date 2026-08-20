#![allow(clippy::expect_used, clippy::panic, clippy::print_stderr)]

pub mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{JvmVerifier, VerifyScope, lines_with_prefix, parse_metric};
use disrobe_pass_jvm::dalvik::{DalvikInsn, decode_method};
use disrobe_pass_jvm::dex::{CodeItem, CodeItemsReport, DexFile, parse_code_items};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::{assemble_jar, parse_dex};
use sha2::{Digest, Sha256};

const DEX: &[u8] = include_bytes!("fixtures/handler_branch_entry/HandlerBranchProbe-r8-min21.dex");
const AUTHORED: &str = include_str!("fixtures/handler_branch_entry/HandlerBranchProbe.java");
const PROVENANCE: &str = include_str!("fixtures/handler_branch_entry/provenance.toml");

const DEX_SHA256: &str = "aa2e0cf233242f6fff412b9a4b85e105e91dcab2b28de7e1558e9f527e4b9faf";
const AUTHORED_SHA256: &str = "62f97af5b81166f58bf08a5e017162800ffbe74c9a7d99a6e2bf0c9cff864ce1";

const PROGRAM_CLASS: &str = "LHandlerBranchProbe;";
const COLLIDING_ENTRIES: usize = 1;
const MOVE_EXCEPTION: u8 = 0x0D;

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn program_items(report: &CodeItemsReport) -> Vec<&CodeItem> {
    report
        .decoded()
        .iter()
        .filter(|item: &&CodeItem| item.class == PROGRAM_CLASS)
        .collect()
}

fn branch_targets(insns: &[DalvikInsn]) -> BTreeSet<u32> {
    insns
        .iter()
        .filter_map(DalvikInsn::branch_target_pc)
        .collect()
}

fn handler_pcs(item: &CodeItem) -> BTreeSet<u32> {
    let mut out: BTreeSet<u32> = BTreeSet::new();
    for entry in &item.tries {
        for (_ty, hpc) in &entry.handlers {
            out.insert(*hpc);
        }
        if let Some(hpc) = entry.catch_all {
            out.insert(hpc);
        }
    }
    out
}

fn colliding_handler_entries(item: &CodeItem) -> Vec<(String, u32)> {
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    let targets: BTreeSet<u32> = branch_targets(&insns);
    let moves: BTreeSet<u32> = insns
        .iter()
        .filter(|insn: &&DalvikInsn| insn.op == MOVE_EXCEPTION)
        .map(|insn: &DalvikInsn| insn.pc)
        .collect();
    handler_pcs(item)
        .into_iter()
        .filter(|hpc: &u32| targets.contains(hpc) && !moves.contains(hpc))
        .map(|hpc: u32| (item.method_name.clone(), hpc))
        .collect()
}

#[test]
fn the_fixture_carries_a_handler_entry_that_normal_control_flow_also_branches_to() {
    assert_eq!(sha256_hex(DEX), DEX_SHA256);
    assert_eq!(sha256_hex(AUTHORED.as_bytes()), AUTHORED_SHA256);
    assert!(PROVENANCE.contains(DEX_SHA256));
    assert!(PROVENANCE.contains(AUTHORED_SHA256));
    assert!(PROVENANCE.contains("version = \"9.1.31\""));
    assert_eq!(DEX.get(..8), Some(b"dex\n035\0".as_slice()));

    let dex: DexFile = parse_dex(DEX).expect("parse the real R8 artifact");
    assert!(
        dex.strings
            .iter()
            .any(|value: &String| value.contains("~~R8{")),
        "the artifact must carry its own R8 marker"
    );
    let report: CodeItemsReport = parse_code_items(&dex, DEX);
    let items: Vec<&CodeItem> = program_items(&report);
    assert!(
        !items.is_empty(),
        "the artifact must define the probe class"
    );

    let mut colliding: Vec<(String, u32)> = Vec::new();
    for item in &items {
        assert!(
            !item.tries.is_empty() || item.method_name == "<init>",
            "{} must carry the try region the authored program declares",
            item.method_name
        );
        colliding.extend(colliding_handler_entries(item));
    }
    assert_eq!(
        colliding.len(),
        COLLIDING_ENTRIES,
        "the artifact must carry {COLLIDING_ENTRIES} handler entries that carry no \
         move-exception and that normal control flow also branches to, which is the shape this \
         gate grades; saw {colliding:?}"
    );
    eprintln!(
        "handler-entry collision fixture: {}/{COLLIDING_ENTRIES} handler entries are also normal \
         branch targets and carry no move-exception: {colliding:?}",
        colliding.len()
    );
}

#[test]
fn a_handler_entry_that_is_also_a_branch_target_verifies_under_the_real_jvm() {
    let dex: DexFile = parse_dex(DEX).expect("parse the real R8 artifact");
    let result: Dex2JarResult = translate_dex_bytes(DEX).expect("translate the dex");
    assert_eq!(
        result.classes.len(),
        1,
        "the artifact defines one class, so one recovered class must reach the verifier"
    );
    assert_eq!(
        result.bodies_recovered, result.method_total,
        "every method of the probe must recover a body rather than a throw stub, or this gate \
         would grade a stub as clean"
    );
    let _: &DexFile = &dex;

    let jar: Vec<u8> = assemble_jar(&result).expect("assemble the jar");
    let verifier: JvmVerifier =
        JvmVerifier::prepare(&format!("handler_entry_branch_{}", std::process::id()))
            .expect("a JDK 24+ exposing java.lang.classfile is required to link recovered classes");
    let jar_path: PathBuf = verifier.write_jar("handler-entry-branch", &jar);
    let stdout: String = verifier.run(VerifyScope::Classes { permille: 1000 }, jar_path.as_path());

    let clean: usize = parse_metric(&stdout, "verify_clean_classes=");
    let failed: usize = parse_metric(&stdout, "lifter_verify_fail_classes=");
    let link_skipped: usize = parse_metric(&stdout, "link_skipped_classes=");
    let reported: Vec<String> = lines_with_prefix(&stdout, "VERIFY ");
    for line in &reported {
        eprintln!("  {line}");
    }
    assert_eq!(
        link_skipped, 0,
        "the probe depends on nothing the harness has to stub, so no class may be link-skipped; a \
         skipped class would leave this gate grading an empty population"
    );
    assert_eq!(
        failed, 0,
        "a handler entry that normal control flow also branches to needs its own dispatch entry, \
         or the one offset has to carry both an empty stack and a thrown exception and the real \
         jvm rejects it: {reported:?}"
    );
    assert_eq!(
        clean, 1,
        "the recovered class must link and verify under -Xverify:all"
    );
    eprintln!(
        "handler-entry collision recovery: {clean}/1 recovered classes verify clean under \
         -Xverify:all, graded against \
         tests/fixtures/handler_branch_entry/HandlerBranchProbe.java built by R8 9.1.31 at \
         min-api 21"
    );
}
