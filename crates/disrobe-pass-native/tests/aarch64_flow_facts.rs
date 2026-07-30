#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_ir::payload::{DisasmInstruction, DisasmPayload, InsnFlow};
use disrobe_pass_native::disasm_ir::build_disasm_payload;
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

const REFERENCE: &str =
    "python/pyarmor/v8/platform_linux_aarch64/pyarmor_runtime_000000/pyarmor_runtime.so";

const RELA_ENTRY_BYTES: usize = 24;
const PLT_HEADER_BYTES: u64 = 32;
const PLT_ENTRY_BYTES: u64 = 16;

fn reference_image() -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(REFERENCE);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the aarch64 reference image is required at {}: {error}",
            path.display()
        )
    })
}

fn section<'a>(file: &'a object::File<'a>, name: &str) -> object::Section<'a, 'a> {
    file.sections()
        .find(|s: &object::Section<'a, 'a>| s.name().unwrap_or_default() == name)
        .unwrap_or_else(|| panic!("the reference image must carry a {name} section"))
}

fn plt_stub_names(file: &object::File<'_>) -> BTreeMap<u64, String> {
    let plt: object::Section<'_, '_> = section(file, ".plt");
    let relocations: Vec<u8> = section(file, ".rela.plt")
        .data()
        .expect("relocation table is readable")
        .to_vec();
    let names: BTreeMap<usize, String> = file
        .dynamic_symbols()
        .map(|symbol: object::Symbol<'_, '_>| {
            (
                symbol.index().0,
                symbol.name().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let mut stubs: BTreeMap<u64, String> = BTreeMap::new();
    for (index, entry) in relocations.chunks_exact(RELA_ENTRY_BYTES).enumerate() {
        let info: u64 = u64::from_le_bytes(
            entry[8..16]
                .try_into()
                .expect("a relocation carries an info word"),
        );
        let symbol: usize = usize::try_from(info >> 32).expect("symbol index fits");
        let Some(name): Option<&String> = names.get(&symbol) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let stub: u64 = plt.address() + PLT_HEADER_BYTES + (index as u64) * PLT_ENTRY_BYTES;
        stubs.insert(stub, name.clone());
    }
    assert!(
        stubs.len() > 200,
        "the reference image must import many symbols, saw {}",
        stubs.len()
    );
    stubs
}

fn payload() -> DisasmPayload {
    build_disasm_payload(&reference_image()).expect("the reference image disassembles")
}

#[test]
fn an_aarch64_image_reports_call_flow_instead_of_silence() {
    let payload: DisasmPayload = payload();
    let mut population: BTreeMap<String, usize> = BTreeMap::new();
    for insn in &payload.instructions {
        *population.entry(format!("{:?}", insn.flow)).or_default() += 1;
    }
    for kind in [
        "Call",
        "IndirectCall",
        "Return",
        "ConditionalBranch",
        "UnconditionalBranch",
        "IndirectBranch",
    ] {
        assert!(
            population.get(kind).copied().unwrap_or_default() > 0,
            "an aarch64 image must report {kind} flow, saw {population:?}"
        );
    }
    let calls: usize = population.get("Call").copied().unwrap_or_default();
    assert!(
        calls > 1000,
        "a real shared object makes many direct calls, saw {calls}"
    );
}

#[test]
fn every_direct_call_target_resolves_to_a_named_import_or_executable_code() {
    let image: Vec<u8> = reference_image();
    let file: object::File<'_> = object::File::parse(image.as_slice()).expect("elf parses");
    let executable: Vec<(u64, u64)> = file
        .sections()
        .filter(|s: &object::Section<'_, '_>| matches!(s.kind(), object::SectionKind::Text))
        .map(|s: object::Section<'_, '_>| (s.address(), s.address() + s.size()))
        .collect();
    assert!(!executable.is_empty(), "the image must carry text sections");

    let payload: DisasmPayload = payload();
    let mut stray: Vec<(u64, u64)> = Vec::new();
    let mut targets: usize = 0;
    for insn in &payload.instructions {
        let Some(target): Option<u64> = (match insn.flow {
            InsnFlow::Call | InsnFlow::ConditionalBranch | InsnFlow::UnconditionalBranch => {
                insn.branch_target
            }
            _ => None,
        }) else {
            continue;
        };
        targets += 1;
        if !executable
            .iter()
            .any(|range: &(u64, u64)| (range.0..range.1).contains(&target))
        {
            stray.push((insn.offset, target));
        }
    }
    assert!(
        targets > 10_000,
        "expected many direct transfers, saw {targets}"
    );
    assert!(
        stray.is_empty(),
        "every direct transfer must land in executable code, {} did not: {:x?}",
        stray.len(),
        &stray[..stray.len().min(8)]
    );
}

#[test]
fn direct_calls_reach_the_import_stubs_named_by_the_relocation_table() {
    let image: Vec<u8> = reference_image();
    let file: object::File<'_> = object::File::parse(image.as_slice()).expect("elf parses");
    let stubs: BTreeMap<u64, String> = plt_stub_names(&file);

    let payload: DisasmPayload = payload();
    let reached: BTreeSet<u64> = payload
        .instructions
        .iter()
        .filter(|insn: &&DisasmInstruction| matches!(insn.flow, InsnFlow::Call))
        .filter_map(|insn: &DisasmInstruction| insn.branch_target)
        .filter(|target: &u64| stubs.contains_key(target))
        .collect();

    for required in ["memcpy", "strlen", "PyList_New", "PyDict_SetItemString"] {
        let stub: u64 = stubs
            .iter()
            .find(|(_, name): &(&u64, &String)| name.as_str() == required)
            .map_or_else(
                || panic!("the reference image must import {required}"),
                |(address, _): (&u64, &String)| *address,
            );
        assert!(
            reached.contains(&stub),
            "no reported call reaches the {required} stub at {stub:#x}"
        );
        let sites: Vec<u64> = payload
            .instructions
            .iter()
            .filter(|insn: &&DisasmInstruction| {
                matches!(insn.flow, InsnFlow::Call) && insn.branch_target == Some(stub)
            })
            .map(|insn: &DisasmInstruction| insn.offset)
            .collect();
        assert!(!sites.is_empty(), "{required} must have call sites");
        for site in &sites {
            let insn: &DisasmInstruction = payload
                .instructions
                .iter()
                .find(|candidate: &&DisasmInstruction| candidate.offset == *site)
                .expect("the call site is in the payload");
            assert_eq!(
                insn.mnemonic, "bl",
                "a reported call at {site:#x} must be a branch-with-link"
            );
        }
    }

    assert!(
        reached.len() * 100 >= stubs.len() * 90,
        "reported calls reach {} of {} import stubs",
        reached.len(),
        stubs.len()
    );
}

#[test]
fn reported_flow_agrees_with_the_disassembler_mnemonic_on_every_instruction() {
    let payload: DisasmPayload = payload();
    let mut disagreements: Vec<(u64, String, String)> = Vec::new();
    let mut checked: usize = 0;
    for insn in &payload.instructions {
        let expected: &str = match insn.mnemonic.as_str() {
            "bl" => "Call",
            "blr" | "blraa" | "blrab" | "blraaz" | "blrabz" => "IndirectCall",
            "ret" | "retaa" | "retab" | "eret" | "eretaa" | "eretab" | "drps" => "Return",
            "br" | "braa" | "brab" | "braaz" | "brabz" => "IndirectBranch",
            "b" => "UnconditionalBranch",
            "cbz" | "cbnz" | "tbz" | "tbnz" => "ConditionalBranch",
            "svc" | "hvc" | "smc" | "brk" | "hlt" | "udf" => "Interrupt",
            other if other.starts_with("b.") => "ConditionalBranch",
            _ => continue,
        };
        checked += 1;
        let actual: String = format!("{:?}", insn.flow);
        if actual != expected {
            disagreements.push((insn.offset, insn.mnemonic.clone(), actual));
        }
    }
    assert!(
        checked > 10_000,
        "expected to cross-check many transfers, saw {checked}"
    );
    assert!(
        disagreements.is_empty(),
        "{} instructions disagree with their mnemonic: {:x?}",
        disagreements.len(),
        &disagreements[..disagreements.len().min(8)]
    );
}

#[test]
fn a_direct_transfer_never_reports_a_missing_target() {
    let payload: DisasmPayload = payload();
    let direct: Vec<&DisasmInstruction> = payload
        .instructions
        .iter()
        .filter(|insn: &&DisasmInstruction| {
            matches!(
                insn.flow,
                InsnFlow::Call | InsnFlow::ConditionalBranch | InsnFlow::UnconditionalBranch
            )
        })
        .collect();
    assert!(
        direct.len() > 10_000,
        "the reference image must report many direct transfers, saw {}",
        direct.len()
    );
    let blind: Vec<u64> = direct
        .iter()
        .filter(|insn: &&&DisasmInstruction| insn.branch_target.is_none())
        .map(|insn: &&DisasmInstruction| insn.offset)
        .collect();
    assert!(
        blind.is_empty(),
        "{} direct transfers carry no target: {:x?}",
        blind.len(),
        &blind[..blind.len().min(8)]
    );
}
