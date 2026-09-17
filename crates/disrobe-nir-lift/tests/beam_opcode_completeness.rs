#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::lift_beam_module;

const EFFECT_FREE_NAMES: [&str; 5] = [
    "label",
    "line",
    "func_info",
    "executable_line",
    "debug_line",
];

const FIXTURES: [(&str, &str); 2] = [
    ("probe.beam", "probe.beam_disasm.txt"),
    ("probe2.beam", "probe2.beam_disasm.txt"),
];

fn corpus_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam")
        .join("disasm_oracle")
        .join(name)
}

#[derive(Debug, Default)]
struct Coverage {
    total: usize,
    modelled: usize,
    declined: BTreeSet<String>,
    effect_free: BTreeSet<String>,
}

fn reference_functions(listing: &str) -> Vec<(String, Vec<String>)> {
    let mut functions: Vec<(String, Vec<String>)> = Vec::new();
    for line in listing.lines() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("module ") {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("function ") {
            let mut fields: std::str::SplitWhitespace<'_> = rest.split_whitespace();
            let name: &str = fields.next().unwrap_or("?").trim_matches('\'');
            let arity: &str = fields.next().unwrap_or("?");
            functions.push((format!("{name}/{arity}"), Vec::new()));
            continue;
        }
        let Some(current): Option<&mut (String, Vec<String>)> = functions.last_mut() else {
            continue;
        };
        current.1.push(reference_term_name(trimmed));
    }
    functions
}

fn reference_term_name(term: &str) -> String {
    let Some(inner): Option<&str> = term.strip_prefix('{') else {
        return term.trim_matches('\'').to_owned();
    };
    let head: &str = inner.split(',').next().unwrap_or(inner).trim_matches('\'');
    if head != "test" && head != "bif" {
        return head.to_owned();
    }
    inner.split(',').nth(1).map_or_else(
        || head.to_owned(),
        |named: &str| named.trim_matches('\'').to_owned(),
    )
}

fn lifted_family(mnemonic: &str) -> String {
    if let Some(suffix) = mnemonic.strip_prefix("gc_bif")
        && !suffix.is_empty()
        && suffix
            .chars()
            .all(|character: char| character.is_ascii_digit())
    {
        return "gc_bif".to_owned();
    }
    mnemonic.to_owned()
}

#[test]
fn beam_lift_matches_the_reference_disassembly_and_names_every_decline() {
    let mut coverage: Coverage = Coverage::default();
    for (module_name, listing_name) in FIXTURES {
        let bytes: Vec<u8> =
            std::fs::read(corpus_path(module_name)).expect("committed BEAM fixture present");
        let listing: String = std::fs::read_to_string(corpus_path(listing_name))
            .expect("committed reference disassembly present");
        let reference: Vec<(String, Vec<String>)> = reference_functions(&listing);
        assert!(
            !reference.is_empty(),
            "{listing_name} must describe at least one function"
        );

        let module: NirModule = lift_beam_module(&bytes).expect("lift BEAM module to NIR");
        let lifted: BTreeMap<String, &NirFunction> = module
            .functions
            .iter()
            .map(|function: &NirFunction| (function.name.clone(), function))
            .collect();

        for (name, terms) in &reference {
            let function: &NirFunction = lifted
                .get(name)
                .copied()
                .unwrap_or_else(|| panic!("{module_name} must lift {name}"));
            assert_eq!(
                function.instructions.len(),
                terms.len(),
                "{module_name} {name} must lift one instruction per reference term, reference {terms:?}"
            );
            let expected: Vec<String> = terms.clone();
            let observed: Vec<String> = function
                .instructions
                .iter()
                .map(|instruction: &NirInstr| lifted_family(&instruction.mnemonic))
                .collect();
            assert_eq!(
                observed, expected,
                "{module_name} {name} instruction names must agree with the reference disassembly"
            );

            let mut declined_offsets: BTreeSet<u32> = BTreeSet::new();
            let mut declined_count: usize = 0;
            for instruction in &function.instructions {
                let instruction: &NirInstr = instruction;
                coverage.total = coverage.total.saturating_add(1);
                match &instruction.op {
                    NirOp::Nop => {
                        assert!(
                            EFFECT_FREE_NAMES.contains(&instruction.mnemonic.as_str()),
                            "only an effect-free BEAM instruction may lift to Nop, saw {} in {name}",
                            instruction.mnemonic
                        );
                        coverage.effect_free.insert(instruction.mnemonic.clone());
                    }
                    NirOp::Unmodeled { opcode, offset } => {
                        assert!(
                            *opcode > 0,
                            "an unmodelled BEAM instruction must carry its real opcode, saw {} in {name}",
                            instruction.mnemonic
                        );
                        declined_offsets.insert(*offset);
                        declined_count = declined_count.saturating_add(1);
                        coverage.declined.insert(instruction.mnemonic.clone());
                    }
                    _ => coverage.modelled = coverage.modelled.saturating_add(1),
                }
            }
            assert_eq!(
                declined_offsets.len(),
                declined_count,
                "each declined instruction in {name} must carry its own code-chunk offset"
            );
        }
    }

    assert!(
        coverage.total >= 40,
        "the graded BEAM corpus must be non-vacuous: {} instructions",
        coverage.total
    );
    assert!(
        coverage.modelled > 0,
        "the graded BEAM corpus must exercise modelled instructions: {coverage:?}"
    );
    assert_eq!(
        coverage.declined,
        BTreeSet::from([
            "allocate".to_owned(),
            "bs_create_bin".to_owned(),
            "bs_match".to_owned(),
            "bs_start_match3".to_owned(),
            "catch".to_owned(),
            "catch_end".to_owned(),
            "deallocate".to_owned(),
            "fconv".to_owned(),
            "init_yregs".to_owned(),
            "send".to_owned(),
            "test_heap".to_owned(),
            "try".to_owned(),
            "try_case".to_owned(),
            "try_end".to_owned(),
        ]),
        "the declined BEAM instruction set is pinned; growing it silently widens what the IR omits"
    );
}

#[test]
fn a_declined_beam_instruction_carries_its_opcode_and_never_collapses_to_nop() {
    let bytes: Vec<u8> =
        std::fs::read(corpus_path("probe.beam")).expect("committed BEAM fixture present");
    let module: NirModule = lift_beam_module(&bytes).expect("lift BEAM module to NIR");
    let declined: Vec<(String, u8)> = module
        .functions
        .iter()
        .flat_map(|function: &NirFunction| function.instructions.iter())
        .filter_map(|instruction: &NirInstr| match instruction.op {
            NirOp::Unmodeled { opcode, .. } => Some((instruction.mnemonic.clone(), opcode)),
            _ => None,
        })
        .collect();
    assert!(
        !declined.is_empty(),
        "the graded module must exercise at least one instruction the lifter declines"
    );
    for (mnemonic, opcode) in &declined {
        assert!(
            !EFFECT_FREE_NAMES.contains(&mnemonic.as_str()),
            "an effect-free instruction must not be reported as a decline: {mnemonic}"
        );
        assert!(
            *opcode > 0,
            "the decline for {mnemonic} must carry a real BEAM opcode"
        );
    }
}
