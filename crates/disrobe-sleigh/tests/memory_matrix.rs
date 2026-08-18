#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use disrobe_sleigh::coverage::{DecodeReport, decode_block_with_coverage};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use disrobe_sleigh::syntax::{RegisterDef, SleighSpec, parse_spec};
use disrobe_sleigh::vendor::preprocessed_aarch64_source;

const REFERENCE_FILE: &str = "aarch64_memory_matrix.llvm";
const MATRIX_WORDS: usize = 206;
const VECTOR_BYTES: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexMode {
    Offset,
    Post,
    Pre,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Extend {
    None,
    Sign,
    Zero,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Address {
    Immediate {
        base: String,
        displacement: i64,
        mode: IndexMode,
    },
    Literal {
        target: u64,
    },
    Register {
        base: String,
        extend: Extend,
        index: String,
        shift: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceForm {
    address: Address,
    mnemonic: String,
    transfers: Vec<String>,
}

#[test]
fn every_declared_memory_form_matches_the_llvm_reference() {
    let (words, listings): (Vec<u32>, Vec<String>) = committed_reference();
    assert_eq!(words.len(), MATRIX_WORDS);
    let registers: BTreeMap<(u64, u32), String> = register_names();
    let mut families: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (index, (word, listing)) in words.iter().zip(&listings).enumerate() {
        assert_ne!(
            listing, "<unknown>",
            "{word:08x} is rejected by the reference"
        );
        let address: u64 = (index as u64).saturating_mul(4);
        let form: ReferenceForm = parse_reference(listing, *word);
        let family: &'static str = grade_word(*word, address, &form, &registers);
        let slot: &mut usize = families.entry(family).or_default();
        *slot = slot.saturating_add(1);
    }
    assert_eq!(
        families,
        BTreeMap::from([
            ("immediate", 66),
            ("literal", 6),
            ("pair", 54),
            ("register", 80),
        ]),
        "every declared family must be represented in the graded matrix"
    );
}

#[test]
fn no_declared_memory_form_is_left_unmatched_or_unlifted() {
    let (words, _): (Vec<u32>, Vec<String>) = committed_reference();
    let mut bytes: Vec<u8> = Vec::with_capacity(words.len().saturating_mul(4));
    for word in &words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0);
    assert_eq!(report.instructions.len(), MATRIX_WORDS);
    assert_eq!(report.coverage.status.no_match, 0);
    assert_eq!(report.coverage.status.unsupported, 0);
    assert_eq!(report.coverage.status.callother, 0);
    assert_eq!(report.coverage.status.supported, MATRIX_WORDS);
    assert_eq!(report.unlifted, BTreeMap::new());
}

fn grade_word(
    word: u32,
    address: u64,
    form: &ReferenceForm,
    registers: &BTreeMap<(u64, u32), String>,
) -> &'static str {
    let bytes: [u8; 4] = word.to_le_bytes();
    let report: DecodeReport = decode_block_with_coverage(&bytes, address);
    assert_eq!(report.instructions.len(), 1, "{word:08x}");
    let instruction: &PcodeInstr = &report.instructions[0];
    assert_eq!(
        instruction.status,
        DecodeStatus::Supported,
        "{word:08x} {} decoded as {:?}",
        form.mnemonic,
        instruction.status
    );
    assert_eq!(instruction.mnemonic, form.mnemonic, "{word:08x}");
    let is_load: bool = form.mnemonic.starts_with("ld");
    let expected_bytes: u32 = form
        .transfers
        .iter()
        .map(|register: &String| transfer_width(register))
        .sum();
    assert_eq!(
        moved_bytes(&instruction.ops, is_load, word),
        expected_bytes,
        "{word:08x} moved the wrong number of bytes for {:?}",
        form.transfers
    );
    grade_transfers(&instruction.ops, form, is_load, registers, word);
    match form.address {
        Address::Immediate {
            ref base,
            displacement,
            mode,
        } => {
            grade_immediate(&instruction.ops, base, displacement, mode, registers, word);
            if form.transfers.len() == 2 {
                let width: u32 = transfer_width(&form.transfers[0]);
                grade_pair_spacing(&instruction.ops, width, is_load, word);
                "pair"
            } else {
                "immediate"
            }
        }
        Address::Literal { target } => {
            grade_literal(&instruction.ops, target, word);
            "literal"
        }
        Address::Register {
            ref base,
            extend,
            ref index,
            shift,
        } => {
            grade_register(
                &instruction.ops,
                base,
                index,
                extend,
                shift,
                registers,
                word,
            );
            "register"
        }
    }
}

fn grade_transfers(
    ops: &[PcodeOp],
    form: &ReferenceForm,
    is_load: bool,
    registers: &BTreeMap<(u64, u32), String>,
    word: u32,
) {
    for transfer in &form.transfers {
        let width: u32 = transfer_width(transfer);
        if general_register(transfer) {
            grade_general_transfer(ops, transfer, width, is_load, registers, word);
            continue;
        }
        let index: u32 = transfer_index(transfer);
        let vector: Varnode = named(registers, &format!("q{index}"), VECTOR_BYTES, word);
        if width == VECTOR_BYTES {
            for half in [0, 8] {
                let slice: Varnode = register_slice(vector, half);
                assert!(
                    touches(ops, slice, is_load),
                    "{word:08x} {transfer} half at {half} is never transferred"
                );
            }
            continue;
        }
        if is_load {
            let scalar: Varnode = named(registers, &format!("d{index}"), 8, word);
            assert!(
                ops.iter().any(|operation: &PcodeOp| matches!(
                    *operation,
                    PcodeOp::Copy { output, .. } | PcodeOp::IntZext { output, .. }
                        if output == scalar
                )),
                "{word:08x} {transfer} must land in d{index}"
            );
            let cleared: Varnode = register_slice(vector, 8);
            assert!(
                ops.iter().any(|operation: &PcodeOp| matches!(
                    *operation,
                    PcodeOp::Copy { output, input }
                        if output == cleared
                            && input.space == Space::Constant
                            && input.offset == 0
                )),
                "{word:08x} {transfer} must zero the upper half of q{index}"
            );
        } else {
            let source: Varnode = named(registers, transfer, width, word);
            assert!(
                ops.iter().any(|operation: &PcodeOp| matches!(
                    *operation,
                    PcodeOp::Store { value, .. } if value == source
                )),
                "{word:08x} {transfer} must be the stored value"
            );
        }
    }
}

fn grade_general_transfer(
    ops: &[PcodeOp],
    transfer: &str,
    width: u32,
    is_load: bool,
    registers: &BTreeMap<(u64, u32), String>,
    word: u32,
) {
    if matches!(transfer, "xzr" | "wzr") {
        if is_load {
            assert!(
                !ops.iter().any(|operation: &PcodeOp| matches!(
                    *operation,
                    PcodeOp::Load { output, .. } if output.space == Space::Register
                )),
                "{word:08x} a load into the zero register must not write an architectural register"
            );
        } else {
            assert!(
                ops.iter().any(|operation: &PcodeOp| matches!(
                    *operation,
                    PcodeOp::Store { value, .. }
                        if value.space == Space::Constant && value.offset == 0
                )),
                "{word:08x} a store from the zero register must store zero"
            );
        }
        return;
    }
    let index: u32 = transfer_index(transfer);
    let wide: Varnode = named(registers, &format!("x{index}"), 8, word);
    if is_load {
        let landed: bool = if width == 8 {
            ops.iter().any(|operation: &PcodeOp| {
                matches!(*operation, PcodeOp::Load { output, .. } if output == wide)
            })
        } else {
            ops.iter().any(|operation: &PcodeOp| {
                matches!(*operation, PcodeOp::IntZext { output, .. } if output == wide)
            })
        };
        assert!(
            landed,
            "{word:08x} {transfer} must land in x{index}, zero extended when it is a w register"
        );
    } else {
        let source: Varnode = named(registers, transfer, width, word);
        assert!(
            ops.iter().any(|operation: &PcodeOp| matches!(
                *operation,
                PcodeOp::Store { value, .. } if value == source
            )),
            "{word:08x} {transfer} must be the stored value"
        );
    }
}

fn grade_immediate(
    ops: &[PcodeOp],
    base: &str,
    displacement: i64,
    mode: IndexMode,
    registers: &BTreeMap<(u64, u32), String>,
    word: u32,
) {
    let base_node: Varnode = named(registers, base, 8, word);
    let writebacks: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter_map(
            |(position, operation): (usize, &PcodeOp)| match *operation {
                PcodeOp::Copy { output, .. } if output == base_node => Some(position),
                _ => None,
            },
        )
        .collect();
    let first_access: usize = first_access(ops, word);
    match mode {
        IndexMode::Offset => assert!(
            writebacks.is_empty(),
            "{word:08x} an offset form must not write the base register"
        ),
        IndexMode::Post => {
            assert_eq!(writebacks.len(), 1, "{word:08x} post-index writeback count");
            assert!(
                writebacks[0] > first_access,
                "{word:08x} post-index must access before it writes the base register"
            );
        }
        IndexMode::Pre => {
            assert_eq!(writebacks.len(), 1, "{word:08x} pre-index writeback count");
            assert!(
                writebacks[0] < first_access,
                "{word:08x} pre-index must write the base register before it accesses"
            );
        }
    }
    if displacement != 0 {
        assert!(
            ops.iter().any(|operation: &PcodeOp| matches!(
                *operation,
                PcodeOp::IntAdd { left, right, .. }
                    if left == base_node && is_constant(right, displacement)
            )),
            "{word:08x} no base plus {displacement} address"
        );
    }
}

fn grade_pair_spacing(ops: &[PcodeOp], width: u32, is_load: bool, word: u32) {
    let pointers: Vec<Varnode> = ops
        .iter()
        .filter_map(|operation: &PcodeOp| match *operation {
            PcodeOp::Load { pointer, .. } if is_load => Some(pointer),
            PcodeOp::Store { pointer, .. } if !is_load => Some(pointer),
            _ => None,
        })
        .collect();
    let per_element: usize = if width == VECTOR_BYTES { 2 } else { 1 };
    assert_eq!(
        pointers.len(),
        per_element.saturating_mul(2),
        "{word:08x} a pair must access memory once per element half"
    );
    let first: Varnode = pointers[0];
    let second: Varnode = pointers[per_element];
    assert_ne!(
        first, second,
        "{word:08x} the two elements of a pair must not share one address"
    );
    assert!(
        ops.iter().any(|operation: &PcodeOp| matches!(
            *operation,
            PcodeOp::IntAdd { output, left, right }
                if output == second && left == first && is_constant(right, i64::from(width))
        )),
        "{word:08x} the second element of a pair must sit exactly {width} bytes after the first"
    );
}

fn grade_literal(ops: &[PcodeOp], target: u64, word: u32) {
    let loaded: bool = ops.iter().any(|operation: &PcodeOp| match *operation {
        PcodeOp::Load { pointer, .. } => {
            pointer.space == Space::Constant && pointer.offset == target
        }
        _ => false,
    });
    assert!(
        loaded,
        "{word:08x} a literal load must read the address {target:#x} the reference resolves"
    );
}

fn grade_register(
    ops: &[PcodeOp],
    base: &str,
    index: &str,
    extend: Extend,
    shift: u32,
    registers: &BTreeMap<(u64, u32), String>,
    word: u32,
) {
    let base_node: Varnode = named(registers, base, 8, word);
    assert!(
        !ops.iter().any(|operation: &PcodeOp| matches!(
            *operation,
            PcodeOp::Copy { output, .. } if output == base_node
        )),
        "{word:08x} a register-offset form must not write the base register"
    );
    let index_node: Option<Varnode> = (index != "xzr" && index != "wzr").then(|| {
        named(
            registers,
            index,
            if extend == Extend::None { 8 } else { 4 },
            word,
        )
    });
    match extend {
        Extend::None => {}
        Extend::Sign => assert!(
            ops.iter().any(|operation: &PcodeOp| matches!(
                *operation,
                PcodeOp::IntSext { input, .. } if Some(input) == index_node
            )),
            "{word:08x} an sxtw index must be sign extended"
        ),
        Extend::Zero => assert!(
            ops.iter().any(|operation: &PcodeOp| matches!(
                *operation,
                PcodeOp::IntZext { input, .. } if Some(input) == index_node
            )),
            "{word:08x} a uxtw index must be zero extended"
        ),
    }
    let shifted: bool = ops.iter().any(|operation: &PcodeOp| {
        matches!(
            *operation,
            PcodeOp::IntLeft { amount, .. }
                if amount.space == Space::Constant && amount.offset == u64::from(shift)
        )
    });
    assert_eq!(
        shifted,
        shift != 0,
        "{word:08x} the index shift of {shift} must appear exactly when it is nonzero"
    );
    if extend == Extend::None && shift == 0 && index_node.is_some() {
        assert!(
            ops.iter().any(|operation: &PcodeOp| matches!(
                *operation,
                PcodeOp::IntAdd { left, right, .. }
                    if left == base_node && Some(right) == index_node
            )),
            "{word:08x} an unextended unshifted address must add the index register to the base"
        );
    }
}

fn touches(ops: &[PcodeOp], slot: Varnode, is_load: bool) -> bool {
    ops.iter().any(|operation: &PcodeOp| match *operation {
        PcodeOp::Load { output, .. } if is_load => output == slot,
        PcodeOp::Store { value, .. } if !is_load => value == slot,
        _ => false,
    })
}

fn moved_bytes(ops: &[PcodeOp], is_load: bool, word: u32) -> u32 {
    let mut total: u32 = 0;
    for operation in ops {
        match *operation {
            PcodeOp::Load { output, .. } if is_load => {
                total = total.saturating_add(output.size_bytes);
            }
            PcodeOp::Store { value, .. } if !is_load => {
                total = total.saturating_add(value.size_bytes);
            }
            PcodeOp::Load { .. } | PcodeOp::Store { .. } => {
                panic!("{word:08x} emitted the wrong memory direction")
            }
            _ => {}
        }
    }
    total
}

fn first_access(ops: &[PcodeOp], word: u32) -> usize {
    ops.iter()
        .position(|operation: &PcodeOp| {
            matches!(*operation, PcodeOp::Load { .. } | PcodeOp::Store { .. })
        })
        .unwrap_or_else(|| panic!("{word:08x} emitted no memory access"))
}

fn is_constant(varnode: Varnode, value: i64) -> bool {
    varnode.space == Space::Constant
        && varnode.size_bytes == 8
        && varnode.offset == u64::from_ne_bytes(value.to_ne_bytes())
}

const fn register_slice(vector: Varnode, byte_offset: u64) -> Varnode {
    Varnode {
        offset: vector.offset.saturating_add(byte_offset),
        size_bytes: 8,
        space: Space::Register,
    }
}

fn named(registers: &BTreeMap<(u64, u32), String>, name: &str, size: u32, word: u32) -> Varnode {
    let found: Option<(&(u64, u32), &String)> = registers
        .iter()
        .find(|(key, value): &(&(u64, u32), &String)| value.as_str() == name && key.1 == size);
    let ((offset, size_bytes), _) =
        found.unwrap_or_else(|| panic!("{word:08x} the specification has no register {name}"));
    Varnode {
        offset: *offset,
        size_bytes: *size_bytes,
        space: Space::Register,
    }
}

fn register_names() -> BTreeMap<(u64, u32), String> {
    let source: String = preprocessed_aarch64_source().expect("preprocess the aarch64 sources");
    let spec: SleighSpec = parse_spec(&source).expect("parse the aarch64 specification");
    spec.registers
        .iter()
        .map(|register: &RegisterDef| {
            (
                (register.offset, register.size_bytes),
                register.name.clone(),
            )
        })
        .collect()
}

fn general_register(register: &str) -> bool {
    matches!(register.chars().next(), Some('w' | 'x'))
}

fn transfer_width(register: &str) -> u32 {
    match register.chars().next() {
        Some('b') => 1,
        Some('h') => 2,
        Some('s' | 'w') => 4,
        Some('d' | 'x') => 8,
        Some('q') => VECTOR_BYTES,
        _ => panic!("{register} is not a transfer register"),
    }
}

fn transfer_index(register: &str) -> u32 {
    register[1..]
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("{register} has no register index"))
}

fn parse_reference(listing: &str, word: u32) -> ReferenceForm {
    let (mnemonic, operands) = listing
        .split_once(' ')
        .unwrap_or_else(|| panic!("{word:08x} reference line has no operands"));
    let bracket: Option<usize> = operands.find('[');
    let Some(bracket) = bracket else {
        let (transfer, target) = operands
            .split_once(", ")
            .unwrap_or_else(|| panic!("{word:08x} literal line has no target"));
        let text: &str = target.trim().trim_start_matches("0x");
        let resolved: u64 = u64::from_str_radix(text, 16)
            .unwrap_or_else(|_| panic!("{word:08x} literal target {target} is not hexadecimal"));
        return ReferenceForm {
            address: Address::Literal { target: resolved },
            mnemonic: mnemonic.to_owned(),
            transfers: vec![transfer.to_owned()],
        };
    };
    let transfers: Vec<String> = operands[..bracket]
        .split(',')
        .map(|piece: &str| piece.trim().to_owned())
        .filter(|piece: &String| !piece.is_empty())
        .collect();
    let memory: &str = &operands[bracket..];
    ReferenceForm {
        address: parse_address(memory, word),
        mnemonic: mnemonic.to_owned(),
        transfers,
    }
}

fn parse_address(memory: &str, word: u32) -> Address {
    if let Some(stripped) = memory.strip_suffix("]!") {
        let (base, displacement): (String, i64) = split_memory(stripped, word);
        return Address::Immediate {
            base,
            displacement,
            mode: IndexMode::Pre,
        };
    }
    if let Some((bracketed, trailing)) = memory.split_once("], ") {
        let (base, _): (String, i64) = split_memory(bracketed, word);
        return Address::Immediate {
            base,
            displacement: parse_immediate(trailing, word),
            mode: IndexMode::Post,
        };
    }
    let inner: &str = memory
        .strip_suffix(']')
        .unwrap_or_else(|| panic!("{word:08x} memory operand is not bracketed"))
        .trim_start_matches('[');
    let pieces: Vec<&str> = inner.split(", ").collect();
    match pieces.as_slice() {
        [base] => Address::Immediate {
            base: (*base).to_owned(),
            displacement: 0,
            mode: IndexMode::Offset,
        },
        [base, second] if second.starts_with('#') => Address::Immediate {
            base: (*base).to_owned(),
            displacement: parse_immediate(second, word),
            mode: IndexMode::Offset,
        },
        [base, index] => Address::Register {
            base: (*base).to_owned(),
            extend: Extend::None,
            index: (*index).to_owned(),
            shift: 0,
        },
        [base, index, qualifier] => {
            let mut parts: std::str::SplitWhitespace<'_> = qualifier.split_whitespace();
            let kind: &str = parts.next().unwrap_or_default();
            let amount: u32 = parts.next().map_or(0, |text: &str| {
                u32::try_from(parse_immediate(text, word)).unwrap_or_default()
            });
            Address::Register {
                base: (*base).to_owned(),
                extend: extend_kind(kind),
                index: (*index).to_owned(),
                shift: amount,
            }
        }
        _ => panic!("{word:08x} memory operand {memory} is not a recognised shape"),
    }
}

fn extend_kind(text: &str) -> Extend {
    match text {
        "sxtw" => Extend::Sign,
        "uxtw" => Extend::Zero,
        _ => Extend::None,
    }
}

fn split_memory(bracketed: &str, word: u32) -> (String, i64) {
    let inner: &str = bracketed.trim_start_matches('[');
    match inner.split_once(", ") {
        Some((base, immediate)) => (base.to_owned(), parse_immediate(immediate, word)),
        None => (inner.to_owned(), 0),
    }
}

fn parse_immediate(text: &str, word: u32) -> i64 {
    let trimmed: &str = text
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .trim_start_matches('#');
    let (negative, digits): (bool, &str) = trimmed
        .strip_prefix('-')
        .map_or((false, trimmed), |rest: &str| (true, rest));
    let hexadecimal: &str = digits.strip_prefix("0x").unwrap_or(digits);
    let magnitude: i64 = i64::from_str_radix(hexadecimal, 16)
        .unwrap_or_else(|_| panic!("{word:08x} immediate {text} is not hexadecimal"));
    if negative { -magnitude } else { magnitude }
}

fn committed_reference() -> (Vec<u32>, Vec<String>) {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(REFERENCE_FILE);
    let text: String = fs::read_to_string(&path).expect("read the committed memory reference");
    let mut words: Vec<u32> = Vec::with_capacity(MATRIX_WORDS);
    let mut listings: Vec<String> = Vec::with_capacity(MATRIX_WORDS);
    for line in text.lines().skip(1) {
        let (encoding, body) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("reference line {line} has no listing"));
        words.push(
            u32::from_str_radix(encoding, 16)
                .unwrap_or_else(|_| panic!("reference line {line} has no encoding")),
        );
        listings.push(body.to_owned());
    }
    (words, listings)
}
