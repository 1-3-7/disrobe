#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

#[path = "support/vba_source_grade.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_source_grade;

#[path = "support/vba_stomp_harness.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_stomp_harness;

use std::collections::BTreeSet;

use disrobe_pass_shell::{
    Error, PCodeWall, PCodeWallDetail, RealModuleDisasm, RealPCodeLine, RealPCodeReport,
    UNKNOWN_OPCODE_MNEMONIC_PREFIX, disassemble_pcode_real, opcode_table, opcode_table_slots,
    vba_project_bin_from_bytes,
};

use vba_source_grade::read_corpus;
use vba_stomp_harness::patch_module_stream;

const OPCODE_TABLE_SLOTS: usize = 264;

const CORPUS: [&str; 5] = [
    "vba/hello.docm",
    "vba/megafile.docm",
    "vba/sourceprobe.docm",
    "vba/sourceprobe.xlsm",
    "vba/vbaProject.bin",
];

fn reached_mnemonics() -> BTreeSet<String> {
    let mut reached: BTreeSet<String> = BTreeSet::new();
    for relative in CORPUS {
        let container: Vec<u8> = read_corpus(relative);
        let project: Vec<u8> = vba_project_bin_from_bytes(&container)
            .unwrap_or_else(|e: Error| panic!("{relative}: locate vbaProject.bin: {e}"));
        let report: RealPCodeReport = disassemble_pcode_real(&project)
            .unwrap_or_else(|e: Error| panic!("{relative}: disassemble: {e}"));
        for module in &report.modules {
            for line in &module.lines {
                for instruction in &line.instructions {
                    reached.insert(instruction.mnemonic.clone());
                }
            }
        }
    }
    reached
}

const REACHED_MNEMONICS: usize = 99;

const UNREACHED_MNEMONICS: [&str; 165] = [
    "ArgsDictLd",
    "ArgsDictLdWith",
    "ArgsDictSet",
    "ArgsDictSetWith",
    "ArgsDictSt",
    "ArgsDictStWith",
    "ArgsMemCallWith",
    "ArgsMemLdWith",
    "ArgsMemRaiseEvent",
    "ArgsMemRaiseEventWith",
    "ArgsMemSet",
    "ArgsMemSetWith",
    "ArgsMemSt",
    "ArgsMemStWith",
    "ArgsSet",
    "Assert",
    "BoL",
    "CaseEq",
    "CaseGe",
    "CaseGt",
    "CaseLe",
    "CaseNe",
    "CaseTo",
    "Circle",
    "CloseAll",
    "CoerceVar",
    "ConstFuncExpr",
    "Context",
    "DefType",
    "DictLd",
    "DictLdWith",
    "DictSetWith",
    "DictSt",
    "DictStWith",
    "Dictset",
    "Do",
    "DoEvents",
    "Else",
    "ElseIfTypeBlock",
    "Empty0",
    "Empty1",
    "EndContext",
    "EndImmediate",
    "EndWith",
    "Eqv",
    "Error",
    "EventDecl",
    "ExitDo",
    "ExitFor",
    "ExitProp",
    "FnCurDir",
    "FnDir",
    "FnError",
    "FnFix",
    "FnFormat",
    "FnFreeFile",
    "FnInStr",
    "FnInStr3",
    "FnInStr4",
    "FnInStrB",
    "FnInStrB3",
    "FnInStrB4",
    "FnInt",
    "FnLenB",
    "FnMid",
    "FnMidB",
    "FnSgn",
    "FnStrComp",
    "FnStrComp3",
    "FnStringStr",
    "FnStringVar",
    "ForEachAs",
    "FuncDefnSave",
    "GoSub",
    "GoTo",
    "IDiv",
    "IfTypeBlock",
    "Illegal",
    "Imp",
    "Implements",
    "IndexLd",
    "IndexSt",
    "Indexset",
    "Input",
    "InputDone",
    "InputItem",
    "LSet",
    "LbConst",
    "LbElse",
    "LbElseIf",
    "LbEndIf",
    "LbIf",
    "LbMark",
    "LdAddressOf",
    "LdLHS",
    "Let",
    "Like",
    "Line",
    "LineInput",
    "LineNum",
    "LitDI4",
    "LitDI8",
    "LitDate",
    "LitHI2",
    "LitHI4",
    "LitHI8",
    "LitOI2",
    "LitOI4",
    "LitOI8",
    "LitR4",
    "LitSmallI2",
    "Lock",
    "LoopUntil",
    "LoopWhile",
    "Me",
    "MeImplicit",
    "MemAddressOf",
    "MemLdWith",
    "MemRedim",
    "MemRedimAs",
    "MemRedimAsWith",
    "MemRedimWith",
    "MemSetWith",
    "MemStWith",
    "Memset",
    "Mid",
    "MidB",
    "Mod",
    "Name",
    "NewRedim",
    "Next",
    "OnGosub",
    "OnGoto",
    "PSet",
    "ParamByVal",
    "ParamNamed",
    "ParamOmitted",
    "PrintChan",
    "PrintComma",
    "PrintEoS",
    "PrintItemComma",
    "PrintNL",
    "PrintSemi",
    "PrintSpc",
    "PrintTab",
    "PrintTabComma",
    "Pwr",
    "RSet",
    "RaiseEvent",
    "RedimAs",
    "Rem",
    "Resume",
    "Return",
    "Scale",
    "Seek",
    "SelectIs",
    "SelectType",
    "SetOrSt",
    "Stack",
    "StartWithExpr",
    "Stop",
    "TypeOf",
    "Unlock",
    "With",
    "WriteChan",
];

const GOLDEN_DUMPS: [&str; 3] = [
    "hello.pcodedmp.txt",
    "megafile.pcodedmp.txt",
    "sourceprobe.pcodedmp.txt",
];

fn golden_mnemonics() -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for name in GOLDEN_DUMPS {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("golden")
            .join(name);
        let text: String = std::fs::read_to_string(&path)
            .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
        for raw in text.lines() {
            let Some(body) = raw.strip_prefix('\t') else {
                continue;
            };
            let mnemonic: &str = body.split_whitespace().next().unwrap_or_default();
            if !mnemonic.is_empty()
                && mnemonic
                    .chars()
                    .all(|c: char| c.is_alphanumeric() || c == '_')
            {
                out.insert(mnemonic.to_owned());
            }
        }
    }
    out
}

#[test]
fn the_reached_roster_equals_what_the_reference_dumps_name() {
    let reached: BTreeSet<String> = reached_mnemonics();
    let golden: BTreeSet<String> = golden_mnemonics();
    assert_eq!(
        reached,
        golden,
        "the reached-opcode roster is graded against the committed pcodedmp 1.2.6 dumps, not \
         against disrobe's own table walk; only in disrobe={:?}, only in pcodedmp={:?}",
        reached.difference(&golden).collect::<Vec<&String>>(),
        golden.difference(&reached).collect::<Vec<&String>>()
    );
    assert_eq!(
        golden.len(),
        REACHED_MNEMONICS,
        "the reference dumps name a pinned number of distinct opcodes"
    );
}

#[test]
fn every_table_opcode_is_reached_by_a_fixture_or_listed_as_unreached() {
    let table: Vec<(u16, &'static str)> = opcode_table();
    assert_eq!(
        opcode_table_slots(),
        OPCODE_TABLE_SLOTS,
        "the published opcode-table size is pinned"
    );
    let named: BTreeSet<&'static str> = table
        .iter()
        .map(|(_, mnem): &(u16, &'static str)| *mnem)
        .collect();
    let reached: BTreeSet<String> = reached_mnemonics();
    let stray: Vec<&String> = reached
        .iter()
        .filter(|m: &&String| !named.contains(m.as_str()))
        .collect();
    assert!(
        stray.is_empty(),
        "the corpus decoded mnemonics that the published table does not name: {stray:?}"
    );
    let unreached: Vec<&str> = named
        .iter()
        .filter(|m: &&&str| !reached.contains(**m))
        .copied()
        .collect();
    let expected: BTreeSet<&str> = UNREACHED_MNEMONICS.iter().copied().collect();
    let actual: BTreeSet<&str> = unreached.iter().copied().collect();
    assert_eq!(
        actual,
        expected,
        "the unreached-opcode roster moved.\nreached {} of {} named entries\nactual unreached \
         list ({} entries):\n{}",
        reached.len(),
        named.len(),
        unreached.len(),
        unreached
            .iter()
            .map(|m: &&str| format!("    \"{m}\","))
            .collect::<Vec<String>>()
            .join("\n")
    );
    assert_eq!(
        UNREACHED_MNEMONICS.len(),
        unreached.len(),
        "the unreached list length is pinned so an entry cannot quietly leave the roster"
    );
    assert_eq!(
        reached.len() + unreached.len(),
        named.len(),
        "every named table entry is either reached by a fixture or on the unreached roster"
    );
    assert_eq!(reached.len(), REACHED_MNEMONICS);
}

const UNKNOWN_LOW_OPCODE: u16 = 0x03FE;
const SOLO_NO_ARG_MNEMONIC: &str = "EndSub";

fn solo_no_arg_site(report: &RealPCodeReport) -> (String, usize) {
    for module in &report.modules {
        for line in &module.lines {
            let only: Option<&disrobe_pass_shell::PCodeInstruction> =
                match line.instructions.as_slice() {
                    [single] => Some(single),
                    _ => None,
                };
            if let Some(instruction) = only
                && instruction.mnemonic == SOLO_NO_ARG_MNEMONIC
            {
                return (module.name.clone(), instruction.offset - 2);
            }
        }
    }
    panic!("the corpus module must carry a line holding only {SOLO_NO_ARG_MNEMONIC} to patch")
}

#[test]
fn an_opcode_outside_the_table_is_refused_by_name_rather_than_skipped() {
    let project: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let clean: RealPCodeReport = disassemble_pcode_real(&project).expect("disassemble the corpus");
    assert!(
        clean
            .walls
            .iter()
            .all(|w: &PCodeWallDetail| w.kind != PCodeWall::UnknownOpcode),
        "the unpatched corpus must raise no unknown-opcode wall; walls={:?}",
        clean.walls
    );
    let (module_name, at): (String, usize) = solo_no_arg_site(&clean);
    let patched: Vec<u8> = patch_module_stream(
        &project,
        &module_name,
        at,
        &UNKNOWN_LOW_OPCODE.to_le_bytes(),
    );
    let report: RealPCodeReport =
        disassemble_pcode_real(&patched).expect("a single bad opcode must not fail the project");
    let unknown: Vec<&PCodeWallDetail> = report
        .walls
        .iter()
        .filter(|w: &&PCodeWallDetail| w.kind == PCodeWall::UnknownOpcode)
        .collect();
    assert_eq!(
        unknown.len(),
        1,
        "one opcode outside the table must raise exactly one wall; walls={:?}",
        report.walls
    );
    let reason: &str = unknown[0].reason.as_str();
    for needle in [
        module_name.as_str(),
        UNKNOWN_OPCODE_MNEMONIC_PREFIX,
        "0x03fe",
    ] {
        assert!(
            reason
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
            "the refusal must name {needle:?}; got {reason:?}"
        );
    }
    let patched_module: &RealModuleDisasm = report
        .modules
        .iter()
        .find(|m: &&RealModuleDisasm| m.name == module_name)
        .expect("the patched module must still be reported");
    let carries_marker: bool = patched_module.lines.iter().any(|l: &RealPCodeLine| {
        l.instructions
            .iter()
            .any(|i: &disrobe_pass_shell::PCodeInstruction| {
                i.mnemonic.starts_with(UNKNOWN_OPCODE_MNEMONIC_PREFIX)
            })
    });
    assert!(
        carries_marker,
        "the unknown opcode must survive into the instruction stream as a named marker, never as \
         a silently dropped instruction"
    );
}

#[test]
fn the_corpus_raises_no_unknown_opcode_wall() {
    for relative in CORPUS {
        let container: Vec<u8> = read_corpus(relative);
        let project: Vec<u8> =
            vba_project_bin_from_bytes(&container).expect("locate vbaProject.bin");
        let report: RealPCodeReport = disassemble_pcode_real(&project).expect("disassemble");
        let unknown: Vec<&PCodeWallDetail> = report
            .walls
            .iter()
            .filter(|w: &&PCodeWallDetail| w.kind == PCodeWall::UnknownOpcode)
            .collect();
        assert!(
            unknown.is_empty(),
            "{relative}: every opcode in a committed document must be in the table; got {unknown:?}"
        );
    }
}
