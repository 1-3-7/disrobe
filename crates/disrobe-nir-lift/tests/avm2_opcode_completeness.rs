#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::{LiftError, lift_abc, lift_swf_abc};
use disrobe_pass_as3::abc::{self, AbcFile, DisasmLine, MethodBody};
use disrobe_pass_as3::swf::{self, DoAbc, Swf};

const INSTRUCTION_SET_FILE: &str = "avm2_instruction_set.txt";
const INSTRUCTION_SET_HASH: &str =
    "3ce6c5e862a5b9429bcf737760896be4396c75f893ef18bb660b9c1474faeec2";

struct Fixture {
    program: &'static str,
    program_hash: &'static str,
    listing: &'static str,
    listing_hash: &'static str,
    reference_bodies: usize,
    reference_instructions: usize,
    lifted_bodies: usize,
    lifted_instructions: usize,
}

const FIXTURES: [Fixture; 2] = [
    Fixture {
        program: "opcode_breadth.swf",
        program_hash: "020365997d501cf5a7472a625a81b539adbb9944f95a17b9b0db6646bc2e0e3d",
        listing: "opcode_breadth.pcode.txt",
        listing_hash: "eb6b96d50cb81bee12b020510322bb061d6a483e1b43fb15c8b67210f427ec1d",
        reference_bodies: 96,
        reference_instructions: 2369,
        lifted_bodies: 115,
        lifted_instructions: 2821,
    },
    Fixture {
        program: "control_shapes.swf",
        program_hash: "ff26a1cc1648d3082de5e5f8c8e2d6a2fff5cf1c4af21dbd964741d8b63b0d72",
        listing: "control_shapes.pcode.txt",
        listing_hash: "4ad73afaab8694bcdb07a899e9731e4d762e98e5b55c0469babedb5410f03641",
        reference_bodies: 101,
        reference_instructions: 2519,
        lifted_bodies: 119,
        lifted_instructions: 2964,
    },
];

const REFERENCE_SLOTS: usize = 256;
const REFERENCE_DEFINED: usize = 206;
const REFERENCE_UNALLOCATED: usize = 50;
const LOCAL_ACCESSOR_ALIASES: usize = 8;
const CORPUS_REACHED: usize = 115;
const CORPUS_INSTRUCTIONS: usize = 5785;
const CORPUS_MODELLED: usize = 4389;
const CORPUS_DECLINED: usize = 1366;
const CORPUS_EFFECT_FREE: usize = 30;
const UNKNOWN_MNEMONIC: &str = "<unknown>";

const EFFECT_FREE_NAMES: [&str; 7] = [
    "nop",
    "label",
    "debug",
    "debugline",
    "debugfile",
    "bkptline",
    "timestamp",
];

const BINARY_FAMILIES: [(&str, &str); 18] = [
    ("add", "add"),
    ("add_i", "add"),
    ("bitand", "and"),
    ("bitnot", "not"),
    ("bitor", "or"),
    ("bitxor", "xor"),
    ("divide", "div"),
    ("lshift", "shl"),
    ("modulo", "rem"),
    ("multiply", "mul"),
    ("multiply_i", "mul"),
    ("negate", "neg"),
    ("negate_i", "neg"),
    ("not", "not"),
    ("rshift", "shr"),
    ("subtract", "sub"),
    ("subtract_i", "sub"),
    ("urshift", "shr"),
];

const UNNAMED_BY_DISROBE: [&str; 32] = [
    "abs_jump",
    "add_d",
    "add_p",
    "alloc",
    "callinterface",
    "callsuperid",
    "codegenop",
    "concat",
    "decode",
    "declocal_p",
    "decrement_p",
    "deldescendants",
    "deletepropertylate",
    "divide_p",
    "doubletoatom",
    "inclocal_p",
    "increment_p",
    "invalid",
    "mark",
    "modulo_p",
    "multiply_p",
    "negate_p",
    "prologue",
    "pushdecimal",
    "pushdnan",
    "sendenter",
    "setpropertylate",
    "subtract_p",
    "sweep",
    "verifyop",
    "verifypass",
    "wb",
];

const DECLINED_BY_LIFTER: [&str; 45] = [
    "applytype",
    "astype",
    "astypelate",
    "coerce",
    "coerce_a",
    "convert_b",
    "convert_d",
    "convert_i",
    "convert_u",
    "declocal_i",
    "decrement",
    "decrement_i",
    "deleteproperty",
    "dup",
    "equals",
    "greaterthan",
    "hasnext2",
    "in",
    "inclocal_i",
    "increment",
    "increment_i",
    "istypelate",
    "lessthan",
    "lf32",
    "lf64",
    "li16",
    "li32",
    "li8",
    "newactivation",
    "newarray",
    "newclass",
    "newobject",
    "nextname",
    "pop",
    "popscope",
    "pushscope",
    "sf32",
    "sf64",
    "si16",
    "si32",
    "si8",
    "sxi1",
    "sxi16",
    "sxi8",
    "typeof",
];

fn corpus_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("avm2_disasm_oracle")
        .join(name)
}

fn pinned_bytes(name: &str, expected_hash: &str) -> Vec<u8> {
    let raw: Vec<u8> = std::fs::read(corpus_path(name))
        .unwrap_or_else(|error| panic!("committed fixture {name} must be readable: {error}"));
    let observed: String = blake3::hash(&raw).to_hex().to_string();
    assert_eq!(
        observed, expected_hash,
        "{name} changed; the graded corpus is hash-pinned so a rescored run cannot pass silently"
    );
    raw
}

fn pinned_text(name: &str, expected_hash: &str) -> String {
    let raw: Vec<u8> = pinned_bytes(name, expected_hash);
    String::from_utf8(raw).unwrap_or_else(|error| panic!("{name} must be UTF-8: {error}"))
}

fn canonical_mnemonic(name: &str) -> String {
    let bytes: &[u8] = name.as_bytes();
    let length: usize = bytes.len();
    if length >= 3
        && bytes[length - 1].is_ascii_digit()
        && bytes[length - 2] == b'_'
        && bytes[length - 3].is_ascii_alphabetic()
    {
        let mut folded: String = String::with_capacity(length - 1);
        folded.push_str(&name[..length - 2]);
        folded.push_str(&name[length - 1..]);
        return folded;
    }
    name.to_owned()
}

fn binary_family(name: &str) -> Option<&'static str> {
    BINARY_FAMILIES
        .iter()
        .find(|(reference, _): &&(&str, &str)| *reference == name)
        .map(|(_, family): &(&str, &str)| *family)
}

fn graded_name(reference: &str) -> String {
    binary_family(reference).map_or_else(|| canonical_mnemonic(reference), str::to_owned)
}

struct ReferenceSet {
    defined: BTreeMap<u8, String>,
    unallocated: BTreeSet<u8>,
}

fn reference_instruction_set(text: &str) -> ReferenceSet {
    let mut defined: BTreeMap<u8, String> = BTreeMap::new();
    let mut unallocated: BTreeSet<u8> = BTreeSet::new();
    let mut rows: usize = 0;
    for line in text.lines() {
        let trimmed: &str = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let mut fields: std::str::Split<'_, char> = trimmed.split('\t');
        let opcode_text: &str = fields
            .next()
            .unwrap_or_else(|| panic!("instruction set row {rows} has no opcode field"));
        let name: &str = fields
            .next()
            .unwrap_or_else(|| panic!("instruction set row {rows} has no name field"));
        assert!(
            fields.next().is_none(),
            "instruction set row {rows} has more than two fields"
        );
        let opcode: u8 = u8::from_str_radix(opcode_text, 16)
            .unwrap_or_else(|error| panic!("instruction set row {rows} opcode: {error}"));
        assert_eq!(
            usize::from(opcode),
            rows,
            "the reference instruction set must list every slot in order"
        );
        if name == "-" {
            unallocated.insert(opcode);
        } else {
            defined.insert(opcode, name.to_owned());
        }
        rows = rows.saturating_add(1);
    }
    assert_eq!(
        rows, REFERENCE_SLOTS,
        "the reference instruction set must describe the whole one-byte opcode space"
    );
    ReferenceSet {
        defined,
        unallocated,
    }
}

fn is_offset_label(line: &str) -> bool {
    let Some(stem): Option<&str> = line.strip_suffix(':') else {
        return false;
    };
    let Some(digits): Option<&str> = stem.strip_prefix("ofs") else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
}

fn instruction_head(line: &str) -> &str {
    line.split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_end_matches(',')
}

fn reference_bodies(listing: &str, known: &BTreeSet<&str>) -> Vec<Vec<String>> {
    let mut bodies: Vec<Vec<String>> = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for (ordinal, line) in listing.lines().enumerate() {
        let trimmed: &str = line.trim();
        let Some(body): Option<&mut Vec<String>> = current.as_mut() else {
            if trimmed == "code" {
                current = Some(Vec::new());
            }
            continue;
        };
        if trimmed.starts_with("end ; code") {
            bodies.push(current.take().unwrap_or_default());
            continue;
        }
        if trimmed.is_empty() || is_offset_label(trimmed) {
            continue;
        }
        let head: &str = instruction_head(trimmed);
        assert!(
            known.contains(head),
            "line {} of the reference listing sits in a code block but names no reference instruction: {trimmed}",
            ordinal.saturating_add(1)
        );
        body.push(graded_name(head));
    }
    assert!(
        current.is_none(),
        "the reference listing ends inside an unterminated code block"
    );
    bodies
}

fn reached_opcodes(listing: &str, known: &BTreeSet<&str>, into: &mut BTreeSet<String>) {
    let mut inside: bool = false;
    for line in listing.lines() {
        let trimmed: &str = line.trim();
        if trimmed == "code" {
            inside = true;
            continue;
        }
        if trimmed.starts_with("end ; code") {
            inside = false;
            continue;
        }
        if !inside || trimmed.is_empty() || is_offset_label(trimmed) {
            continue;
        }
        let head: &str = instruction_head(trimmed);
        if known.contains(head) {
            into.insert(head.to_owned());
        }
    }
}

fn lifted_bodies(module: &NirModule) -> Vec<Vec<String>> {
    module
        .functions
        .iter()
        .map(|function: &NirFunction| {
            function
                .instructions
                .iter()
                .map(|instruction: &NirInstr| canonical_mnemonic(&instruction.mnemonic))
                .collect()
        })
        .collect()
}

fn multiset(bodies: &[Vec<String>]) -> BTreeMap<&[String], usize> {
    let mut counts: BTreeMap<&[String], usize> = BTreeMap::new();
    for body in bodies {
        *counts.entry(body.as_slice()).or_insert(0) += 1;
    }
    counts
}

fn pinned_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name: &&str| (*name).to_owned()).collect()
}

fn abc_blobs(bytes: &[u8], program: &str) -> Vec<Vec<u8>> {
    let parsed: Swf = swf::parse(bytes).unwrap_or_else(|error| panic!("parse {program}: {error}"));
    let blobs: Vec<DoAbc> = parsed.collect_do_abc();
    assert!(!blobs.is_empty(), "{program} must carry a DoABC tag");
    blobs
        .into_iter()
        .map(|blob: DoAbc| blob.abc_bytes)
        .collect()
}

#[derive(Debug, Default)]
struct Coverage {
    instructions: usize,
    modelled: usize,
    effect_free_instructions: usize,
    declined_instructions: usize,
    effect_free: BTreeSet<String>,
    declined: BTreeSet<String>,
    reached: BTreeSet<String>,
}

#[test]
fn the_avm2_opcode_table_agrees_with_the_reference_instruction_set() {
    let text: String = pinned_text(INSTRUCTION_SET_FILE, INSTRUCTION_SET_HASH);
    let reference: ReferenceSet = reference_instruction_set(&text);
    assert_eq!(
        reference.defined.len(),
        REFERENCE_DEFINED,
        "the reference defines {REFERENCE_DEFINED} of {REFERENCE_SLOTS} one-byte AVM2 opcodes"
    );
    assert_eq!(
        reference.unallocated.len(),
        REFERENCE_UNALLOCATED,
        "the reference leaves {REFERENCE_UNALLOCATED} of {REFERENCE_SLOTS} slots unallocated"
    );

    let mut renamed: usize = 0;
    let mut unnamed: BTreeSet<String> = BTreeSet::new();
    for (opcode, name) in &reference.defined {
        let observed: &str = abc::opcode_mnemonic(*opcode);
        if observed == UNKNOWN_MNEMONIC {
            unnamed.insert(name.clone());
            continue;
        }
        let folded: String = canonical_mnemonic(observed);
        if folded != observed {
            renamed = renamed.saturating_add(1);
        }
        assert_eq!(
            &folded, name,
            "opcode 0x{opcode:02x} is named {observed} but the reference names it {name}"
        );
    }
    assert_eq!(
        renamed, LOCAL_ACCESSOR_ALIASES,
        "only the eight indexed local accessors may differ from the reference by an underscore"
    );
    assert_eq!(
        unnamed,
        pinned_set(&UNNAMED_BY_DISROBE),
        "the reference opcodes this lifter does not name are pinned at {} of {REFERENCE_DEFINED}; every method body containing one is rejected whole",
        UNNAMED_BY_DISROBE.len()
    );

    for opcode in &reference.unallocated {
        assert_eq!(
            abc::opcode_mnemonic(*opcode),
            UNKNOWN_MNEMONIC,
            "opcode 0x{opcode:02x} is unallocated in the reference and must be rejected, not named"
        );
    }
}

#[test]
fn avm2_lift_matches_the_reference_disassembly_and_names_every_decline() {
    let set_text: String = pinned_text(INSTRUCTION_SET_FILE, INSTRUCTION_SET_HASH);
    let reference: ReferenceSet = reference_instruction_set(&set_text);
    let known: BTreeSet<&str> = reference.defined.values().map(String::as_str).collect();

    let mut coverage: Coverage = Coverage::default();
    for fixture in &FIXTURES {
        let bytes: Vec<u8> = pinned_bytes(fixture.program, fixture.program_hash);
        let listing: String = pinned_text(fixture.listing, fixture.listing_hash);
        let expected: Vec<Vec<String>> = reference_bodies(&listing, &known);
        assert_eq!(
            expected.len(),
            fixture.reference_bodies,
            "{} must describe {} reference method bodies",
            fixture.listing,
            fixture.reference_bodies
        );
        assert_eq!(
            expected.iter().map(Vec::len).sum::<usize>(),
            fixture.reference_instructions,
            "{} must carry {} reference instructions",
            fixture.listing,
            fixture.reference_instructions
        );
        reached_opcodes(&listing, &known, &mut coverage.reached);

        let module: NirModule = lift_swf_abc(&bytes)
            .unwrap_or_else(|error| panic!("lift {}: {error}", fixture.program));
        let observed: Vec<Vec<String>> = lifted_bodies(&module);
        assert_eq!(
            observed.len(),
            fixture.lifted_bodies,
            "{} carries {} method bodies",
            fixture.program,
            fixture.lifted_bodies
        );
        assert_eq!(
            observed.iter().map(Vec::len).sum::<usize>(),
            fixture.lifted_instructions,
            "{} must lift {} instructions",
            fixture.program,
            fixture.lifted_instructions
        );
        let observed_counts: BTreeMap<&[String], usize> = multiset(&observed);
        for (body, count) in multiset(&expected) {
            let seen: usize = observed_counts.get(body).copied().unwrap_or_default();
            assert!(
                seen >= count,
                "{} lifts {seen} of the {count} bodies whose reference instruction stream is {body:?}",
                fixture.program
            );
        }

        for function in &module.functions {
            let function: &NirFunction = function;
            for instruction in &function.instructions {
                let instruction: &NirInstr = instruction;
                coverage.instructions = coverage.instructions.saturating_add(1);
                match &instruction.op {
                    NirOp::Nop => {
                        coverage.effect_free_instructions =
                            coverage.effect_free_instructions.saturating_add(1);
                        coverage.effect_free.insert(instruction.mnemonic.clone());
                    }
                    NirOp::Unmodeled { opcode, .. } => {
                        assert_eq!(
                            canonical_mnemonic(abc::opcode_mnemonic(*opcode)),
                            canonical_mnemonic(&instruction.mnemonic),
                            "a declined instruction must carry the opcode its mnemonic names"
                        );
                        coverage.declined_instructions =
                            coverage.declined_instructions.saturating_add(1);
                        coverage.declined.insert(instruction.mnemonic.clone());
                    }
                    _ => coverage.modelled = coverage.modelled.saturating_add(1),
                }
            }
        }
    }

    assert_eq!(
        coverage.instructions, CORPUS_INSTRUCTIONS,
        "the graded AVM2 corpus size is pinned so a shrinking denominator cannot raise coverage"
    );
    assert_eq!(
        coverage.modelled, CORPUS_MODELLED,
        "{CORPUS_MODELLED} of {CORPUS_INSTRUCTIONS} lifted AVM2 instructions carry a modelled operation"
    );
    assert_eq!(
        coverage.declined_instructions, CORPUS_DECLINED,
        "{CORPUS_DECLINED} of {CORPUS_INSTRUCTIONS} lifted AVM2 instructions are named declines"
    );
    assert_eq!(
        coverage.effect_free_instructions, CORPUS_EFFECT_FREE,
        "{CORPUS_EFFECT_FREE} of {CORPUS_INSTRUCTIONS} lifted AVM2 instructions are effect-free"
    );
    assert_eq!(
        coverage.modelled + coverage.declined_instructions + coverage.effect_free_instructions,
        coverage.instructions,
        "every lifted AVM2 instruction is modelled, effect-free, or a named decline"
    );
    assert_eq!(
        coverage.reached.len(),
        CORPUS_REACHED,
        "the reference reaches {CORPUS_REACHED} of the {REFERENCE_DEFINED} defined AVM2 opcodes over this corpus"
    );
    let corpus_absent: BTreeSet<&str> = known
        .iter()
        .filter(|name: &&&str| !coverage.reached.contains(**name))
        .copied()
        .collect();
    assert_eq!(
        corpus_absent.len(),
        REFERENCE_DEFINED - CORPUS_REACHED,
        "a defined opcode this corpus never reaches is reported as corpus-absent, never as covered"
    );

    let effect_free_names: BTreeSet<&str> = EFFECT_FREE_NAMES.iter().copied().collect();
    for name in &coverage.effect_free {
        assert!(
            effect_free_names.contains(canonical_mnemonic(name).as_str()),
            "only an effect-free AVM2 instruction may lift to Nop, saw {name}"
        );
    }
    assert_eq!(
        coverage.effect_free,
        pinned_set(&["label"]),
        "the effect-free AVM2 instruction set this corpus reaches is pinned"
    );
    assert_eq!(
        coverage.declined,
        pinned_set(&DECLINED_BY_LIFTER),
        "the declined AVM2 instruction set is pinned at {} of the {CORPUS_REACHED} reached opcodes; growing it silently widens what the IR omits",
        DECLINED_BY_LIFTER.len()
    );
}

#[test]
fn a_declined_avm2_instruction_carries_its_opcode_and_never_collapses_to_nop() {
    let effect_free_names: BTreeSet<&str> = EFFECT_FREE_NAMES.iter().copied().collect();
    let mut declines: usize = 0;
    for fixture in &FIXTURES {
        let bytes: Vec<u8> = pinned_bytes(fixture.program, fixture.program_hash);
        let module: NirModule = lift_swf_abc(&bytes)
            .unwrap_or_else(|error| panic!("lift {}: {error}", fixture.program));
        for function in &module.functions {
            let function: &NirFunction = function;
            for instruction in &function.instructions {
                let instruction: &NirInstr = instruction;
                let NirOp::Unmodeled { opcode, offset } = instruction.op else {
                    continue;
                };
                declines = declines.saturating_add(1);
                assert!(
                    !effect_free_names.contains(instruction.mnemonic.as_str()),
                    "an effect-free instruction must not be reported as a decline: {}",
                    instruction.mnemonic
                );
                assert_ne!(
                    abc::opcode_mnemonic(opcode),
                    UNKNOWN_MNEMONIC,
                    "a decline must carry an allocated AVM2 opcode, saw 0x{opcode:02x} at {offset}"
                );
            }
        }
    }
    assert_eq!(
        declines, CORPUS_DECLINED,
        "the graded corpus exercises {CORPUS_DECLINED} instructions the lifter declines"
    );
}

#[test]
fn a_truncated_abc_refuses_instead_of_lifting_a_short_program() {
    for fixture in &FIXTURES {
        let bytes: Vec<u8> = pinned_bytes(fixture.program, fixture.program_hash);
        for blob in abc_blobs(&bytes, fixture.program) {
            let full: usize = blob.len();
            assert!(full > 64, "{} must carry a real ABC", fixture.program);
            let cuts: [usize; 9] = [
                0,
                1,
                2,
                4,
                8,
                full / 8,
                full / 4,
                full / 2,
                full.saturating_sub(1),
            ];
            for cut in cuts {
                let outcome: Result<NirModule, LiftError> = lift_abc(&blob[..cut]);
                assert!(
                    outcome.is_err(),
                    "an ABC truncated to {cut} of {full} bytes must refuse, not lift a short program"
                );
            }
        }
    }
}

#[test]
fn a_branch_past_the_end_of_a_body_is_still_refused() {
    let fixture: &Fixture = &FIXTURES[0];
    let bytes: Vec<u8> = pinned_bytes(fixture.program, fixture.program_hash);
    let mut mutations: usize = 0;
    for blob in abc_blobs(&bytes, fixture.program) {
        let parsed: AbcFile =
            abc::parse(&blob).unwrap_or_else(|error| panic!("parse abc: {error}"));
        for body in &parsed.method_bodies {
            let body: &MethodBody = body;
            let Ok(lines): Result<Vec<DisasmLine>, _> = abc::disasm(&body.code) else {
                continue;
            };
            let Some(edge): Option<usize> = branch_to_end_of_body(&lines, body.code.len()) else {
                continue;
            };
            let displacement_low: u8 = body.code[edge.saturating_add(1)];
            if displacement_low == u8::MAX {
                continue;
            }
            let start: usize = locate_unique(&blob, &body.code);
            let mut damaged: Vec<u8> = blob.clone();
            damaged[start.saturating_add(edge).saturating_add(1)] =
                displacement_low.saturating_add(1);
            let outcome: Result<NirModule, LiftError> = lift_abc(&damaged);
            assert!(
                outcome.is_err(),
                "a branch one byte past the end of a method body must be refused"
            );
            mutations = mutations.saturating_add(1);
        }
    }
    assert!(
        mutations > 0,
        "the graded corpus must contain a branch that lands on the end of its body"
    );
}

fn branch_to_end_of_body(lines: &[DisasmLine], code_len: usize) -> Option<usize> {
    for (ordinal, line) in lines.iter().enumerate() {
        if !matches!(line.opcode, 0x0C..=0x1A) || line.opcode == 0x1B {
            continue;
        }
        let next: usize = lines
            .get(ordinal.saturating_add(1))
            .map_or(code_len, |following: &DisasmLine| following.offset);
        let relative: i64 = line.operands.first().copied()?;
        let target: i64 = i64::try_from(next).ok()?.checked_add(relative)?;
        if usize::try_from(target).ok() == Some(code_len) {
            return Some(line.offset);
        }
    }
    None
}

fn locate_unique(haystack: &[u8], needle: &[u8]) -> usize {
    let mut found: Option<usize> = None;
    let mut index: usize = 0;
    while index + needle.len() <= haystack.len() {
        if &haystack[index..index + needle.len()] == needle {
            assert!(
                found.is_none(),
                "the graded method body must occur once in the ABC so the mutation is unambiguous"
            );
            found = Some(index);
        }
        index = index.saturating_add(1);
    }
    found.unwrap_or_else(|| panic!("the graded method body must occur in the ABC it came from"))
}
