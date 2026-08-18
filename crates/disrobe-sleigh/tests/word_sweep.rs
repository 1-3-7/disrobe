use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_sleigh::decode_block;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space};

const SWEEP_SEED: u64 = 0x5150_2024_0612_7a11;
const RANDOM_WORDS_PER_GROUP: usize = 192;
const MAX_SWEEP_WORDS: usize = 8192;
const SWEEP_TIME_BUDGET: Duration = Duration::from_mins(5);
const REFERENCE_TOOL: &str = "llvm-objdump";
const REFERENCE_VERSION: &str = "19.1.7";
const REFERENCE_TRIPLE: &str = "aarch64-none-elf";
const ASSEMBLER_TOOL: &str = "clang";
const TOOL_TIMEOUT: Duration = Duration::from_mins(3);
const TOOL_CAPTURE_LIMIT: usize = 32 * 1024 * 1024;
const REFERENCE_FILE: &str = "aarch64_word_sweep.llvm";
const UNKNOWN: &str = "<unknown>";
const SWEEP_WORDS: usize = 2830;
const ACCEPTED_WORDS: usize = 1381;
const AGREEING_WORDS: usize = 1372;
const TARGET_COMPARISONS: usize = 206;
const CORPUS_MNEMONIC_COMPARISONS: usize = 203;
const CORPUS_NAMES: [&str; 3] = ["aarch64_forms", "aarch64_oracle_o0", "aarch64_oracle_o2"];

const GROUP_OP0: [(&str, &[u32]); 9] = [
    ("reserved", &[0b0000]),
    ("unallocated_0001", &[0b0001]),
    ("sve", &[0b0010]),
    ("unallocated_0011", &[0b0011]),
    ("dp_immediate", &[0b1000, 0b1001]),
    ("branch_system", &[0b1010, 0b1011]),
    ("load_store", &[0b0100, 0b0110, 0b1100, 0b1110]),
    ("dp_register", &[0b0101, 0b1101]),
    ("dp_simd_fp", &[0b0111, 0b1111]),
];

const BOUNDARY_FIELDS: [(u32, u32); 7] =
    [(0, 5), (5, 5), (16, 5), (10, 6), (16, 6), (10, 12), (22, 2)];

const TARGET_MNEMONICS: [&str; 6] = ["adr", "adrp", "b", "bl", "cbnz", "cbz"];

#[derive(Clone, Copy, Debug)]
struct AliasEquivalence {
    decoded: &'static str,
    reference: &'static str,
    mask: u32,
    value: u32,
    applies: fn(u32) -> bool,
    reason: &'static str,
}

const ALIAS_EQUIVALENCES: [AliasEquivalence; 1] = [AliasEquivalence {
    decoded: "bfm",
    reference: "bfi",
    mask: 0x7f80_0000,
    value: 0x3300_0000,
    applies: bitfield_insert_alias,
    reason: "BFI is the preferred disassembly of BFM when imms is below immr and Rn is not the zero register",
}];

const MNEMONIC_DIVERGENCES: [(&str, &str, usize, &str); 1] = [(
    "mov",
    "orr",
    5,
    "the decoder applies the MOV alias to ORR with a shifted or rotated second source, where the alias needs LSL #0; the emitted P-code still applies the shift",
)];

const OVER_ACCEPTED_WORDS: [(u32, &str, &str); 4] = [
    (
        0x5d93_4e86,
        "cpyewtwn",
        "memory-copy encoding that LLVM 19.1.7 leaves unallocated",
    ),
    (
        0x9208_f4ab,
        "and",
        "64-bit AND immediate whose imms field is all ones for its element size, which DecodeBitMasks leaves unallocated",
    ),
    (
        0x9d54_84fb,
        "cpymrn",
        "memory-copy encoding that LLVM 19.1.7 leaves unallocated",
    ),
    (
        0xdd10_8e68,
        "cpypwtrn",
        "memory-copy encoding that LLVM 19.1.7 leaves unallocated",
    ),
];

const GROUP_EXPECTATION: [(&str, GroupCounts); 9] = [
    (
        "branch_system",
        GroupCounts {
            seen: 307,
            accepted: 193,
            agreeing: 193,
            disagreeing: 0,
            accepted_reference_rejects: 0,
            declined_reference_accepts: 1,
            both_reject: 113,
        },
    ),
    (
        "dp_immediate",
        GroupCounts {
            seen: 581,
            accepted: 455,
            agreeing: 454,
            disagreeing: 0,
            accepted_reference_rejects: 1,
            declined_reference_accepts: 1,
            both_reject: 125,
        },
    ),
    (
        "dp_register",
        GroupCounts {
            seen: 515,
            accepted: 346,
            agreeing: 341,
            disagreeing: 5,
            accepted_reference_rejects: 0,
            declined_reference_accepts: 0,
            both_reject: 169,
        },
    ),
    (
        "dp_simd_fp",
        GroupCounts {
            seen: 192,
            accepted: 18,
            agreeing: 18,
            disagreeing: 0,
            accepted_reference_rejects: 0,
            declined_reference_accepts: 2,
            both_reject: 172,
        },
    ),
    (
        "load_store",
        GroupCounts {
            seen: 467,
            accepted: 369,
            agreeing: 366,
            disagreeing: 0,
            accepted_reference_rejects: 3,
            declined_reference_accepts: 1,
            both_reject: 97,
        },
    ),
    (
        "reserved",
        GroupCounts {
            seen: 192,
            accepted: 0,
            agreeing: 0,
            disagreeing: 0,
            accepted_reference_rejects: 0,
            declined_reference_accepts: 35,
            both_reject: 157,
        },
    ),
    (
        "sve",
        GroupCounts {
            seen: 192,
            accepted: 0,
            agreeing: 0,
            disagreeing: 0,
            accepted_reference_rejects: 0,
            declined_reference_accepts: 129,
            both_reject: 63,
        },
    ),
    (
        "unallocated_0001",
        GroupCounts {
            seen: 192,
            accepted: 0,
            agreeing: 0,
            disagreeing: 0,
            accepted_reference_rejects: 0,
            declined_reference_accepts: 0,
            both_reject: 192,
        },
    ),
    (
        "unallocated_0011",
        GroupCounts {
            seen: 192,
            accepted: 0,
            agreeing: 0,
            disagreeing: 0,
            accepted_reference_rejects: 0,
            declined_reference_accepts: 0,
            both_reject: 192,
        },
    ),
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GroupCounts {
    seen: usize,
    accepted: usize,
    agreeing: usize,
    disagreeing: usize,
    accepted_reference_rejects: usize,
    declined_reference_accepts: usize,
    both_reject: usize,
}

#[derive(Clone, Debug, Default)]
struct Grade {
    groups: BTreeMap<&'static str, GroupCounts>,
    alias_uses: BTreeMap<(String, String), usize>,
    divergences: BTreeMap<(String, String), Vec<u32>>,
    over_accepted: Vec<(u32, String)>,
    target_agreeing: usize,
    target_compared: usize,
    target_misses: Vec<String>,
}

#[derive(Clone, Debug)]
struct Reference {
    banner: String,
    entries: Vec<(u32, String)>,
}

#[derive(Clone, Debug)]
struct Tools {
    assembler: PathBuf,
    disassembler: PathBuf,
}

#[derive(Clone, Copy, Debug)]
struct SplitMix {
    state: u64,
}

impl SplitMix {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_value(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value: u64 = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

const fn field(word: u32, shift: u32, width: u32) -> u32 {
    (word >> shift) & ((1_u32 << width) - 1)
}

const fn bitfield_insert_alias(word: u32) -> bool {
    field(word, 10, 6) < field(word, 16, 6) && field(word, 5, 5) != 31
}

fn corpus_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
}

fn read_words(path: &Path) -> Vec<u32> {
    let bytes_result: io::Result<Vec<u8>> = fs::read(path);
    assert!(bytes_result.is_ok(), "{}: {bytes_result:?}", path.display());
    let bytes: Vec<u8> = bytes_result.unwrap_or_default();
    assert!(!bytes.is_empty(), "{} is empty", path.display());
    bytes
        .chunks_exact(4)
        .map(|chunk: &[u8]| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

fn corpus_words() -> Vec<u32> {
    let directory: PathBuf = corpus_directory();
    let mut words: Vec<u32> = Vec::new();
    for name in CORPUS_NAMES {
        words.extend(read_words(&directory.join(format!("{name}.text"))));
    }
    words
}

fn boundary_variants(words: &[u32]) -> Vec<u32> {
    let mut distinct: Vec<u32> = words.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    let mut variants: Vec<u32> = Vec::new();
    for word in distinct {
        for (shift, width) in BOUNDARY_FIELDS {
            let mask: u32 = ((1_u32 << width) - 1) << shift;
            variants.push(word & !mask);
            variants.push(word | mask);
        }
    }
    variants
}

fn random_words() -> Vec<u32> {
    let mut generator: SplitMix = SplitMix::new(SWEEP_SEED);
    let mut words: Vec<u32> = Vec::new();
    for (_, op0_values) in GROUP_OP0 {
        for _ in 0..RANDOM_WORDS_PER_GROUP {
            let draw: u64 = generator.next_value();
            let index: usize = usize::try_from(draw >> 40).unwrap_or(0) % op0_values.len();
            let selected: u32 = op0_values.get(index).copied().unwrap_or_default();
            words.push(((draw as u32) & !(0xf << 25)) | (selected << 25));
        }
    }
    words
}

fn sweep_words() -> Vec<u32> {
    let base: Vec<u32> = corpus_words();
    let mut words: Vec<u32> = base.clone();
    words.extend(boundary_variants(&base));
    words.extend(random_words());
    words.sort_unstable();
    words.dedup();
    assert!(
        words.len() <= MAX_SWEEP_WORDS,
        "sweep word count {} exceeds the {MAX_SWEEP_WORDS} cap at seed 0x{SWEEP_SEED:016x}",
        words.len()
    );
    words
}

fn group_of(word: u32) -> &'static str {
    let op0: u32 = field(word, 25, 4);
    for (name, values) in GROUP_OP0 {
        if values.contains(&op0) {
            return name;
        }
    }
    "unclassified"
}

fn normalize_reference(body: &str) -> String {
    let trimmed: &str = body.trim();
    if trimmed.starts_with(UNKNOWN) {
        return UNKNOWN.to_owned();
    }
    let without_comment: &str = trimmed.split("//").next().unwrap_or(trimmed);
    let mut visible: String = String::new();
    let mut depth: usize = 0;
    for character in without_comment.chars() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' if depth > 0 => depth = depth.saturating_sub(1),
            _ if depth == 0 => visible.push(character),
            _ => {}
        }
    }
    visible.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn load_reference() -> Reference {
    let path: PathBuf = corpus_directory().join(REFERENCE_FILE);
    let text_result: io::Result<String> = fs::read_to_string(&path);
    assert!(
        text_result.is_ok(),
        "the committed {REFERENCE_TOOL} reference {} is unreadable: {text_result:?}",
        path.display()
    );
    let text: String = text_result.unwrap_or_default();
    let mut lines: std::str::Lines<'_> = text.lines();
    let banner: String = lines.next().unwrap_or_default().to_owned();
    let mut entries: Vec<(u32, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let mut parts: std::str::SplitN<'_, char> = line.splitn(2, '\t');
        let word_text: &str = parts.next().unwrap_or_default();
        let rendered: &str = parts.next().unwrap_or_default();
        let parsed: Result<u32, std::num::ParseIntError> = u32::from_str_radix(word_text, 16);
        assert!(parsed.is_ok(), "malformed reference line {line:?}");
        assert!(!rendered.is_empty(), "empty reference line {line:?}");
        entries.push((parsed.unwrap_or_default(), rendered.to_owned()));
    }
    Reference { banner, entries }
}

fn reference_mnemonic(rendered: &str) -> Option<&str> {
    (rendered != UNKNOWN).then(|| rendered.split_whitespace().next().unwrap_or(rendered))
}

fn reference_target(rendered: &str) -> Option<u64> {
    let (_, operands): (&str, &str) = rendered.split_once(char::is_whitespace)?;
    let mut found: Option<u64> = None;
    for operand in operands.split(',') {
        let Some(digits) = operand.trim().strip_prefix("0x") else {
            continue;
        };
        let Ok(value) = u64::from_str_radix(digits, 16) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some(value);
    }
    found
}

fn decoded_target(instruction: &PcodeInstr) -> Option<u64> {
    let is_address_form: bool = matches!(instruction.mnemonic.as_str(), "adr" | "adrp");
    for operation in &instruction.ops {
        match operation {
            PcodeOp::Branch { target }
            | PcodeOp::Call { target }
            | PcodeOp::CBranch { target, .. } => return Some(target.offset),
            PcodeOp::Copy { input, .. } if is_address_form && input.space == Space::Constant => {
                return Some(input.offset);
            }
            _ => {}
        }
    }
    None
}

const fn accepted(status: DecodeStatus) -> bool {
    matches!(
        status,
        DecodeStatus::Supported | DecodeStatus::CallOther | DecodeStatus::Unsupported
    )
}

fn alias_equivalent(word: u32, decoded: &str, reference: &str) -> bool {
    ALIAS_EQUIVALENCES.iter().any(|alias: &AliasEquivalence| {
        alias.decoded == decoded
            && alias.reference == reference
            && word & alias.mask == alias.value
            && (alias.applies)(word)
    })
}

fn carries_target(mnemonic: &str) -> bool {
    TARGET_MNEMONICS.contains(&mnemonic) || mnemonic.starts_with("b.")
}

fn decode_sweep(words: &[u32]) -> Vec<PcodeInstr> {
    let started: Instant = Instant::now();
    let mut decoded: Vec<PcodeInstr> = Vec::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let address: u64 = (index as u64).saturating_mul(4);
        let mut instructions: Vec<PcodeInstr> = decode_block(&word.to_le_bytes(), address);
        assert_eq!(
            instructions.len(),
            1,
            "word 0x{word:08x} produced {instructions:#?}"
        );
        decoded.push(instructions.remove(0));
    }
    let elapsed: Duration = started.elapsed();
    assert!(
        elapsed <= SWEEP_TIME_BUDGET,
        "decoding {} words took {elapsed:?} against the {SWEEP_TIME_BUDGET:?} budget at seed 0x{SWEEP_SEED:016x}",
        words.len()
    );
    decoded
}

fn grade(words: &[u32], reference: &Reference) -> Grade {
    assert_eq!(
        reference.entries.len(),
        words.len(),
        "the committed reference does not cover every sweep word"
    );
    let decoded: Vec<PcodeInstr> = decode_sweep(words);
    let mut grade: Grade = Grade::default();
    for (name, _) in GROUP_OP0 {
        grade.groups.insert(name, GroupCounts::default());
    }
    for ((word, rendered), instruction) in reference.entries.iter().zip(&decoded) {
        let group: &'static str = group_of(*word);
        let counts: &mut GroupCounts = grade.groups.entry(group).or_default();
        counts.seen = counts.seen.saturating_add(1);
        let expected: Option<&str> = reference_mnemonic(rendered);
        if accepted(instruction.status) {
            counts.accepted = counts.accepted.saturating_add(1);
            match expected {
                None => {
                    counts.accepted_reference_rejects =
                        counts.accepted_reference_rejects.saturating_add(1);
                    grade
                        .over_accepted
                        .push((*word, instruction.mnemonic.clone()));
                }
                Some(name) if name == instruction.mnemonic => {
                    counts.agreeing = counts.agreeing.saturating_add(1);
                }
                Some(name) if alias_equivalent(*word, &instruction.mnemonic, name) => {
                    counts.agreeing = counts.agreeing.saturating_add(1);
                    let slot: &mut usize = grade
                        .alias_uses
                        .entry((instruction.mnemonic.clone(), name.to_owned()))
                        .or_default();
                    *slot = slot.saturating_add(1);
                }
                Some(name) => {
                    counts.disagreeing = counts.disagreeing.saturating_add(1);
                    grade
                        .divergences
                        .entry((instruction.mnemonic.clone(), name.to_owned()))
                        .or_default()
                        .push(*word);
                }
            }
        } else if expected.is_some() {
            counts.declined_reference_accepts = counts.declined_reference_accepts.saturating_add(1);
        } else {
            counts.both_reject = counts.both_reject.saturating_add(1);
        }
        if instruction.status == DecodeStatus::Supported
            && carries_target(&instruction.mnemonic)
            && let Some(expected_target) = reference_target(rendered)
            && let Some(actual_target) = decoded_target(instruction)
        {
            grade.target_compared = grade.target_compared.saturating_add(1);
            if expected_target == actual_target {
                grade.target_agreeing = grade.target_agreeing.saturating_add(1);
            } else {
                grade.target_misses.push(format!(
                    "0x{word:08x} {} expected 0x{expected_target:x} decoded 0x{actual_target:x}",
                    instruction.mnemonic
                ));
            }
        }
    }
    grade
}

fn report(grade: &Grade) {
    println!(
        "aarch64 word sweep graded against {REFERENCE_TOOL} {REFERENCE_VERSION} {REFERENCE_TRIPLE}, seed 0x{SWEEP_SEED:016x}"
    );
    println!(
        "group seen accepted agreeing disagreeing accepted_reference_rejects declined_reference_accepts both_reject"
    );
    for (name, counts) in &grade.groups {
        println!(
            "{name} {} {} {} {} {} {} {}",
            counts.seen,
            counts.accepted,
            counts.agreeing,
            counts.disagreeing,
            counts.accepted_reference_rejects,
            counts.declined_reference_accepts,
            counts.both_reject
        );
    }
    let accepted_total: usize = grade
        .groups
        .values()
        .map(|counts: &GroupCounts| counts.accepted)
        .sum();
    let agreeing_total: usize = grade
        .groups
        .values()
        .map(|counts: &GroupCounts| counts.agreeing)
        .sum();
    let percent: f64 = if accepted_total == 0 {
        0.0
    } else {
        agreeing_total as f64 * 100.0 / accepted_total as f64
    };
    println!("mnemonic agreement {agreeing_total}/{accepted_total} ({percent:.2} percent)");
    for ((decoded, expected), words) in &grade.divergences {
        let listed: Vec<String> = words
            .iter()
            .map(|word: &u32| format!("0x{word:08x}"))
            .collect();
        println!(
            "divergence {decoded} against {expected} {} words {}",
            words.len(),
            listed.join(" ")
        );
    }
    for (word, mnemonic) in &grade.over_accepted {
        println!("accepted encoding the reference rejects 0x{word:08x} {mnemonic}");
    }
    println!(
        "branch and address targets {}/{}",
        grade.target_agreeing, grade.target_compared
    );
}

#[test]
fn sweep_word_index_matches_the_committed_reference() {
    let words: Vec<u32> = sweep_words();
    let reference: Reference = load_reference();
    assert_eq!(
        reference.banner,
        format!("{REFERENCE_TOOL} {REFERENCE_VERSION} {REFERENCE_TRIPLE}"),
        "the committed reference is not the pinned tool"
    );
    assert_eq!(words.len(), SWEEP_WORDS);
    let indexed: Vec<u32> = reference
        .entries
        .iter()
        .map(|(word, _): &(u32, String)| *word)
        .collect();
    assert_eq!(
        indexed, words,
        "the committed reference does not cover exactly the generated sweep words"
    );
    for word in &words {
        assert_ne!(
            group_of(*word),
            "unclassified",
            "0x{word:08x} has no encoding group"
        );
    }
}

#[test]
fn accepted_words_agree_with_the_llvm_reference_mnemonic() {
    let words: Vec<u32> = sweep_words();
    let reference: Reference = load_reference();
    let graded: Grade = grade(&words, &reference);
    report(&graded);
    let expected_groups: BTreeMap<&'static str, GroupCounts> =
        GROUP_EXPECTATION.into_iter().collect();
    assert_eq!(graded.groups.len(), GROUP_OP0.len());
    for (name, counts) in &graded.groups {
        assert!(counts.seen > 0, "encoding group {name} saw no words");
        assert_eq!(
            counts.seen,
            counts
                .accepted
                .saturating_add(counts.declined_reference_accepts)
                .saturating_add(counts.both_reject),
            "group {name} does not account for every word"
        );
    }
    assert_eq!(graded.groups, expected_groups);
    let observed: BTreeMap<(String, String), usize> = graded
        .divergences
        .iter()
        .map(
            |((decoded, expected), words): (&(String, String), &Vec<u32>)| {
                ((decoded.clone(), expected.clone()), words.len())
            },
        )
        .collect();
    let declared: BTreeMap<(String, String), usize> = MNEMONIC_DIVERGENCES
        .into_iter()
        .map(
            |(decoded, expected, count, reason): (&str, &str, usize, &str)| {
                assert!(
                    !reason.is_empty(),
                    "{decoded} against {expected} has no reason"
                );
                ((decoded.to_owned(), expected.to_owned()), count)
            },
        )
        .collect();
    assert_eq!(observed, declared);
    let accepted_total: usize = graded
        .groups
        .values()
        .map(|counts: &GroupCounts| counts.accepted)
        .sum();
    let agreeing_total: usize = graded
        .groups
        .values()
        .map(|counts: &GroupCounts| counts.agreeing)
        .sum();
    assert_eq!(accepted_total, ACCEPTED_WORDS);
    assert_eq!(agreeing_total, AGREEING_WORDS);
}

#[test]
fn every_declared_alias_equivalence_is_exercised_and_explained() {
    let words: Vec<u32> = sweep_words();
    let reference: Reference = load_reference();
    let graded: Grade = grade(&words, &reference);
    let declared: Vec<(String, String)> = ALIAS_EQUIVALENCES
        .iter()
        .map(|alias: &AliasEquivalence| {
            assert!(
                !alias.reason.is_empty(),
                "{} against {} has no recorded reason",
                alias.decoded,
                alias.reference
            );
            assert_ne!(alias.decoded, alias.reference);
            (alias.decoded.to_owned(), alias.reference.to_owned())
        })
        .collect();
    for pair in &declared {
        assert!(
            graded.alias_uses.contains_key(pair),
            "alias equivalence {pair:?} is never exercised by the sweep"
        );
    }
    println!("alias equivalences exercised {:?}", graded.alias_uses);
}

#[test]
fn only_the_recorded_encodings_are_accepted_where_the_reference_rejects() {
    let words: Vec<u32> = sweep_words();
    let reference: Reference = load_reference();
    let graded: Grade = grade(&words, &reference);
    let observed: Vec<String> = graded
        .over_accepted
        .iter()
        .map(|(word, mnemonic): &(u32, String)| format!("0x{word:08x} {mnemonic}"))
        .collect();
    let declared: Vec<String> = OVER_ACCEPTED_WORDS
        .into_iter()
        .map(|(word, mnemonic, reason): (u32, &str, &str)| {
            assert!(!reason.is_empty(), "0x{word:08x} has no reason");
            format!("0x{word:08x} {mnemonic}")
        })
        .collect();
    assert_eq!(observed, declared);
}

#[test]
fn branch_and_address_targets_match_the_llvm_reference() {
    let words: Vec<u32> = sweep_words();
    let reference: Reference = load_reference();
    let graded: Grade = grade(&words, &reference);
    assert_eq!(graded.target_compared, TARGET_COMPARISONS);
    assert_eq!(graded.target_misses, Vec::<String>::new());
    assert_eq!(graded.target_agreeing, TARGET_COMPARISONS);
}

#[test]
fn the_llvm_reference_agrees_with_the_committed_gnu_objdump_listings() {
    let directory: PathBuf = corpus_directory();
    let reference: Reference = load_reference();
    let rendered: BTreeMap<u32, String> = reference.entries.into_iter().collect();
    let mut compared: usize = 0;
    for name in CORPUS_NAMES {
        let words: Vec<u32> = read_words(&directory.join(format!("{name}.text")));
        let listing_path: PathBuf = directory.join(format!("{name}.mnemonics"));
        let listing_result: io::Result<String> = fs::read_to_string(&listing_path);
        assert!(
            listing_result.is_ok(),
            "{listing_path:?}: {listing_result:?}"
        );
        let listing: String = listing_result.unwrap_or_default();
        let expected: Vec<&str> = listing.split_whitespace().collect();
        assert_eq!(expected.len(), words.len(), "{name} listing length");
        for (word, gnu) in words.iter().zip(expected) {
            let text: Option<&String> = rendered.get(word);
            assert!(
                text.is_some(),
                "0x{word:08x} is missing from the committed reference"
            );
            let llvm: Option<&str> = text.map(String::as_str).and_then(reference_mnemonic);
            assert_eq!(
                llvm,
                Some(gnu),
                "0x{word:08x} in {name}: GNU objdump and {REFERENCE_TOOL} {REFERENCE_VERSION} disagree"
            );
            compared = compared.saturating_add(1);
        }
    }
    assert_eq!(compared, CORPUS_MNEMONIC_COMPARISONS);
}

#[test]
fn live_llvm_disassembly_reproduces_the_committed_reference() {
    let Some(tools) = find_tools() else {
        println!(
            "skipping live re-derivation: {ASSEMBLER_TOOL} or {REFERENCE_TOOL} {REFERENCE_VERSION} for {REFERENCE_TRIPLE} is not installed"
        );
        return;
    };
    let words: Vec<u32> = sweep_words();
    let reference: Reference = load_reference();
    let produced: Vec<String> = disassemble(&tools, &words);
    assert_eq!(produced.len(), reference.entries.len());
    let mismatches: Vec<String> = reference
        .entries
        .iter()
        .zip(&produced)
        .filter(|((_, committed), fresh): &(&(u32, String), &String)| committed != *fresh)
        .map(|((word, committed), fresh): (&(u32, String), &String)| {
            format!("0x{word:08x} committed [{committed}] fresh [{fresh}]")
        })
        .collect();
    assert_eq!(mismatches, Vec::<String>::new());
}

fn find_tools() -> Option<Tools> {
    let assembler: PathBuf = find_tool("DISROBE_CLANG", ASSEMBLER_TOOL)?;
    let disassembler: PathBuf = find_tool("DISROBE_LLVM_OBJDUMP", REFERENCE_TOOL)?;
    let version_output: CapturedOutput = run(&disassembler, &[OsString::from("--version")])?;
    let banner: String = String::from_utf8_lossy(&version_output.stdout).into_owned();
    let pinned: bool = banner
        .lines()
        .any(|line: &str| line.trim() == format!("LLVM version {REFERENCE_VERSION}"));
    if !pinned {
        println!("{REFERENCE_TOOL} is installed but is not the pinned {REFERENCE_VERSION}");
        return None;
    }
    Some(Tools {
        assembler,
        disassembler,
    })
}

fn find_tool(variable: &str, name: &str) -> Option<PathBuf> {
    if let Some(value) = env::var_os(variable) {
        let path: PathBuf = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    let path_value: OsString = env::var_os("PATH")?;
    for directory in env::split_paths(&path_value) {
        for suffix in ["", ".exe"] {
            let candidate: PathBuf = directory.join(format!("{name}{suffix}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn run(program: &Path, arguments: &[OsString]) -> Option<CapturedOutput> {
    let result: io::Result<Option<CapturedOutput>> =
        run_captured(program, arguments, TOOL_TIMEOUT, TOOL_CAPTURE_LIMIT);
    assert!(result.is_ok(), "{}: {result:?}", program.display());
    let output: Option<CapturedOutput> = result.ok().flatten();
    assert!(output.is_some(), "{} timed out", program.display());
    let captured: CapturedOutput = output?;
    assert!(
        captured.exit_code == Some(0),
        "{} failed: {}",
        program.display(),
        String::from_utf8_lossy(&captured.stderr)
    );
    Some(captured)
}

fn disassemble(tools: &Tools, words: &[u32]) -> Vec<String> {
    let scratch_result: io::Result<ScratchDir> = ScratchDir::create("disrobe-sleigh-word-sweep");
    assert!(scratch_result.is_ok(), "{scratch_result:?}");
    let Ok(scratch) = scratch_result else {
        return Vec::new();
    };
    let source: PathBuf = scratch.path().join("sweep.s");
    let object: PathBuf = scratch.path().join("sweep.o");
    let listing_source: String = std::iter::once(".text\n".to_owned())
        .chain(
            words
                .iter()
                .map(|word: &u32| format!(".inst 0x{word:08x}\n")),
        )
        .collect();
    let write_result: io::Result<()> = fs::write(&source, listing_source.as_bytes());
    assert!(write_result.is_ok(), "{write_result:?}");
    let assembled: Option<CapturedOutput> = run(
        &tools.assembler,
        &[
            OsString::from(format!("--target={REFERENCE_TRIPLE}")),
            OsString::from("-c"),
            OsString::from("-o"),
            object.as_os_str().to_owned(),
            source.as_os_str().to_owned(),
        ],
    );
    assert!(assembled.is_some());
    let disassembled: Option<CapturedOutput> = run(
        &tools.disassembler,
        &[OsString::from("-d"), object.as_os_str().to_owned()],
    );
    let listing: String = disassembled.map_or_else(String::new, |output: CapturedOutput| {
        String::from_utf8_lossy(&output.stdout).into_owned()
    });
    let mut encodings: Vec<u32> = Vec::new();
    let mut rendered: Vec<String> = Vec::new();
    for line in listing.lines() {
        let mut columns: std::str::SplitWhitespace<'_> = line.split_whitespace();
        let Some(address) = columns.next() else {
            continue;
        };
        let Some(encoding) = columns.next() else {
            continue;
        };
        let valid_address: bool = address.ends_with(':')
            && address
                .trim_end_matches(':')
                .chars()
                .all(|character: char| character.is_ascii_hexdigit());
        if !valid_address || encoding.len() != 8 {
            continue;
        }
        let Ok(word) = u32::from_str_radix(encoding, 16) else {
            continue;
        };
        let body: &str = line.split_once(encoding).map_or("", |(_, rest)| rest);
        encodings.push(word);
        rendered.push(normalize_reference(body));
    }
    assert_eq!(
        encodings, words,
        "the live listing does not cover every sweep word in order"
    );
    let close_result: io::Result<()> = scratch.close();
    assert!(close_result.is_ok(), "{close_result:?}");
    rendered
}
