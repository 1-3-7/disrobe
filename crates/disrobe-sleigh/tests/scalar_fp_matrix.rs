#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_sleigh::coverage::{DecodeReport, decode_block_with_coverage};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use disrobe_sleigh::syntax::{RegisterDef, SleighSpec, parse_spec};
use disrobe_sleigh::vendor::preprocessed_aarch64_source;

const REFERENCE_FILE: &str = "aarch64_scalar_fp_matrix.llvm";
const REFERENCE_TRIPLE: &str = "aarch64-none-elf";
const TOOL_TIMEOUT: Duration = Duration::from_mins(3);
const TOOL_CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
const MATRIX_WORDS: usize = 75;
const VECTOR_BYTES: u32 = 16;

const WIDTHS: [(u32, u32, u32, u32); 5] = [
    (1, 0b00, 0b01, 0b00),
    (2, 0b01, 0b01, 0b00),
    (4, 0b10, 0b01, 0b00),
    (8, 0b11, 0b01, 0b00),
    (16, 0b00, 0b11, 0b10),
];

const FORMS: [(IndexMode, i64); 6] = [
    (IndexMode::Post, 8),
    (IndexMode::Post, -8),
    (IndexMode::Pre, 8),
    (IndexMode::Pre, -8),
    (IndexMode::Offset, 3),
    (IndexMode::Offset, 0),
];

const RELEASE_OFFSETS: [i64; 3] = [-256, 0, 255];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexMode {
    Offset,
    Post,
    Pre,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceForm {
    base: String,
    displacement: i64,
    mnemonic: String,
    mode: IndexMode,
    transfer: String,
}

#[derive(Clone, Debug)]
struct ReferenceFile {
    header: String,
    words: Vec<u32>,
    listings: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
struct AccessFacts {
    bytes_moved: u32,
    first_pointer: Varnode,
    first_access: usize,
}

#[test]
fn every_declared_scalar_fp_form_matches_the_llvm_reference() {
    let reference: ReferenceFile = committed_reference();
    let words: Vec<u32> = matrix_words();
    assert_eq!(words.len(), MATRIX_WORDS);
    assert_eq!(
        words, reference.words,
        "the committed reference must cover exactly the declared matrix in order"
    );
    let registers: BTreeMap<(u64, u32), String> = register_names();
    let mut graded: usize = 0;
    for (word, listing) in words.iter().zip(&reference.listings) {
        assert_ne!(
            listing, "<unknown>",
            "{word:08x} is declared in the matrix but the reference rejects it"
        );
        let form: ReferenceForm = parse_reference(listing, *word);
        grade_word(*word, &form, &registers);
        graded = graded.saturating_add(1);
    }
    assert_eq!(graded, MATRIX_WORDS);
}

#[test]
fn no_declared_scalar_fp_form_is_left_unmatched_or_unlifted() {
    let words: Vec<u32> = matrix_words();
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

#[test]
fn live_llvm_disassembly_reproduces_the_committed_scalar_fp_reference() {
    let Some(tools) = find_tools() else {
        return;
    };
    let committed: ReferenceFile = committed_reference();
    let words: Vec<u32> = matrix_words();
    let live: Vec<String> = disassemble(&tools, &words);
    assert_eq!(live, committed.listings);
    assert!(committed.header.starts_with("llvm-objdump "));
    assert!(committed.header.ends_with(REFERENCE_TRIPLE));
}

fn matrix_words() -> Vec<u32> {
    let mut words: Vec<u32> = Vec::with_capacity(MATRIX_WORDS);
    let mut index: u32 = 0;
    for (_, size, load_opc, store_opc) in WIDTHS {
        for (mode, immediate) in FORMS {
            for opcode in [load_opc, store_opc] {
                let rt: u32 = index.wrapping_mul(7) % 32;
                let rn: u32 = index.wrapping_mul(11).wrapping_add(3) % 32;
                words.push(match mode {
                    IndexMode::Post => indexed_word(size, opcode, immediate, 0b01, rn, rt),
                    IndexMode::Pre => indexed_word(size, opcode, immediate, 0b11, rn, rt),
                    IndexMode::Offset => unsigned_word(size, opcode, immediate, rn, rt),
                });
                index = index.saturating_add(1);
            }
        }
    }
    for (_, size, _, store_opc) in WIDTHS {
        for immediate in RELEASE_OFFSETS {
            let rt: u32 = index.wrapping_mul(7) % 32;
            let rn: u32 = index.wrapping_mul(11).wrapping_add(3) % 32;
            words.push(release_word(size, store_opc, immediate, rn, rt));
            index = index.saturating_add(1);
        }
    }
    words
}

fn indexed_word(size: u32, opcode: u32, immediate: i64, mode: u32, rn: u32, rt: u32) -> u32 {
    let encoded: u32 = u32::try_from(immediate & 0x1ff).unwrap_or(0);
    (size << 30)
        | (0b111 << 27)
        | (1 << 26)
        | (opcode << 22)
        | (encoded << 12)
        | (mode << 10)
        | (rn << 5)
        | rt
}

fn unsigned_word(size: u32, opcode: u32, immediate: i64, rn: u32, rt: u32) -> u32 {
    let encoded: u32 = u32::try_from(immediate & 0xfff).unwrap_or(0);
    (size << 30)
        | (0b111 << 27)
        | (1 << 26)
        | (0b01 << 24)
        | (opcode << 22)
        | (encoded << 10)
        | (rn << 5)
        | rt
}

fn release_word(size: u32, opcode: u32, immediate: i64, rn: u32, rt: u32) -> u32 {
    let encoded: u32 = u32::try_from(immediate & 0x1ff).unwrap_or(0);
    (size << 30)
        | (0b11101 << 24)
        | (opcode << 22)
        | (encoded << 12)
        | (0b10 << 10)
        | (rn << 5)
        | rt
}

fn grade_word(word: u32, form: &ReferenceForm, registers: &BTreeMap<(u64, u32), String>) {
    let bytes: [u8; 4] = word.to_le_bytes();
    let report: DecodeReport = decode_block_with_coverage(&bytes, 0);
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
    let width: u32 = transfer_width(&form.transfer);
    let index: u32 = transfer_index(&form.transfer);
    let base: Varnode = named(registers, &form.base, 8, word);
    let vector: Varnode = named(registers, &format!("q{index}"), VECTOR_BYTES, word);
    let is_load: bool = form.mnemonic == "ldr";
    let facts: AccessFacts = access_facts(&instruction.ops, is_load, word);
    assert_eq!(
        facts.bytes_moved, width,
        "{word:08x} moved {} bytes for {}",
        facts.bytes_moved, form.transfer
    );
    if is_load {
        grade_load_destination(
            &instruction.ops,
            form,
            index,
            width,
            vector,
            registers,
            word,
        );
    } else {
        grade_store_source(&instruction.ops, form, width, vector, registers, word);
    }
    grade_addressing(&instruction.ops, form, base, facts, word);
}

fn grade_load_destination(
    ops: &[PcodeOp],
    form: &ReferenceForm,
    index: u32,
    width: u32,
    vector: Varnode,
    registers: &BTreeMap<(u64, u32), String>,
    word: u32,
) {
    if width == VECTOR_BYTES {
        let low: Varnode = register_slice(vector, 0);
        let high: Varnode = register_slice(vector, 8);
        let outputs: Vec<Varnode> = ops
            .iter()
            .filter_map(|operation: &PcodeOp| match *operation {
                PcodeOp::Load { output, .. } => Some(output),
                _ => None,
            })
            .collect();
        assert_eq!(outputs, vec![low, high], "{word:08x} {}", form.transfer);
        return;
    }
    let scalar: Varnode = named(registers, &format!("d{index}"), 8, word);
    let widened: Option<Varnode> = ops.iter().find_map(|operation: &PcodeOp| match *operation {
        PcodeOp::Copy { output, .. } | PcodeOp::IntZext { output, .. } if output == scalar => {
            Some(output)
        }
        _ => None,
    });
    assert_eq!(
        widened,
        Some(scalar),
        "{word:08x} {} must land in d{index}",
        form.transfer
    );
    let cleared: Varnode = register_slice(vector, 8);
    let zeroed: bool = ops.iter().any(|operation: &PcodeOp| {
        matches!(
            *operation,
            PcodeOp::Copy { output, input }
                if output == cleared && input.space == Space::Constant && input.offset == 0
        )
    });
    assert!(
        zeroed,
        "{word:08x} {} must zero the upper half of q{index}",
        form.transfer
    );
}

fn grade_store_source(
    ops: &[PcodeOp],
    form: &ReferenceForm,
    width: u32,
    vector: Varnode,
    registers: &BTreeMap<(u64, u32), String>,
    word: u32,
) {
    let values: Vec<Varnode> = ops
        .iter()
        .filter_map(|operation: &PcodeOp| match *operation {
            PcodeOp::Store { value, .. } => Some(value),
            _ => None,
        })
        .collect();
    if width == VECTOR_BYTES {
        let expected: Vec<Varnode> = vec![register_slice(vector, 0), register_slice(vector, 8)];
        assert_eq!(values, expected, "{word:08x} {}", form.transfer);
        return;
    }
    let source: Varnode = named(registers, &form.transfer, width, word);
    assert_eq!(values, vec![source], "{word:08x} {}", form.transfer);
    let vector_end: u64 = vector.offset.saturating_add(u64::from(vector.size_bytes));
    assert!(
        !ops.iter().any(|operation: &PcodeOp| matches!(
            *operation,
            PcodeOp::Copy { output, .. } | PcodeOp::IntZext { output, .. }
                if output.space == Space::Register
                    && output.offset >= vector.offset
                    && output.offset < vector_end
        )),
        "{word:08x} a store must not write the vector register it reads"
    );
}

fn grade_addressing(
    ops: &[PcodeOp],
    form: &ReferenceForm,
    base: Varnode,
    facts: AccessFacts,
    word: u32,
) {
    let writebacks: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter_map(
            |(position, operation): (usize, &PcodeOp)| match *operation {
                PcodeOp::Copy { output, .. } if output == base => Some(position),
                _ => None,
            },
        )
        .collect();
    match form.mode {
        IndexMode::Offset => {
            assert!(
                writebacks.is_empty(),
                "{word:08x} an offset form must not write the base register"
            );
            let expected: Varnode = offset_pointer(ops, base, form.displacement, word);
            assert_eq!(facts.first_pointer, expected, "{word:08x} access pointer");
        }
        IndexMode::Post => {
            assert_eq!(writebacks.len(), 1, "{word:08x} post-index writeback count");
            assert!(
                writebacks[0] > facts.first_access,
                "{word:08x} post-index must access before it writes the base register"
            );
            assert_eq!(
                facts.first_pointer, base,
                "{word:08x} post-index accesses the unmodified base"
            );
            assert_writeback(ops, base, form.displacement, writebacks[0], word);
        }
        IndexMode::Pre => {
            assert_eq!(writebacks.len(), 1, "{word:08x} pre-index writeback count");
            assert!(
                writebacks[0] < facts.first_access,
                "{word:08x} pre-index must write the base register before it accesses"
            );
            let updated: Varnode =
                assert_writeback(ops, base, form.displacement, writebacks[0], word);
            assert_eq!(
                facts.first_pointer, updated,
                "{word:08x} pre-index accesses the updated base"
            );
        }
    }
}

fn assert_writeback(
    ops: &[PcodeOp],
    base: Varnode,
    displacement: i64,
    position: usize,
    word: u32,
) -> Varnode {
    let PcodeOp::Copy { input, .. } = ops[position] else {
        panic!("{word:08x} writeback is not a copy");
    };
    if displacement == 0 {
        assert_eq!(input, base, "{word:08x} zero displacement writeback");
        return input;
    }
    let produced: bool = ops.iter().any(|operation: &PcodeOp| {
        matches!(
            *operation,
            PcodeOp::IntAdd { output, left, right }
                if output == input && left == base && is_constant(right, displacement)
        )
    });
    assert!(
        produced,
        "{word:08x} writeback value is not base plus {displacement}"
    );
    input
}

fn offset_pointer(ops: &[PcodeOp], base: Varnode, displacement: i64, word: u32) -> Varnode {
    if displacement == 0 {
        return base;
    }
    let produced: Option<Varnode> = ops.iter().find_map(|operation: &PcodeOp| match *operation {
        PcodeOp::IntAdd {
            output,
            left,
            right,
        } if left == base && is_constant(right, displacement) => Some(output),
        _ => None,
    });
    produced.unwrap_or_else(|| panic!("{word:08x} no base plus {displacement} address"))
}

fn is_constant(varnode: Varnode, value: i64) -> bool {
    varnode.space == Space::Constant
        && varnode.size_bytes == 8
        && varnode.offset == u64::from_ne_bytes(value.to_ne_bytes())
}

fn access_facts(ops: &[PcodeOp], is_load: bool, word: u32) -> AccessFacts {
    let mut bytes_moved: u32 = 0;
    let mut first_pointer: Option<Varnode> = None;
    let mut first_access: Option<usize> = None;
    for (position, operation) in ops.iter().enumerate() {
        let (pointer, size): (Varnode, u32) = match *operation {
            PcodeOp::Load {
                output, pointer, ..
            } if is_load => (pointer, output.size_bytes),
            PcodeOp::Store { pointer, value, .. } if !is_load => (pointer, value.size_bytes),
            PcodeOp::Load { .. } | PcodeOp::Store { .. } => {
                panic!("{word:08x} emitted the wrong memory direction")
            }
            _ => continue,
        };
        bytes_moved = bytes_moved.saturating_add(size);
        if first_access.is_none() {
            first_access = Some(position);
            first_pointer = Some(pointer);
        }
    }
    AccessFacts {
        bytes_moved,
        first_pointer: first_pointer
            .unwrap_or_else(|| panic!("{word:08x} emitted no memory access")),
        first_access: first_access.unwrap_or_default(),
    }
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

fn transfer_width(register: &str) -> u32 {
    match register.chars().next() {
        Some('b') => 1,
        Some('h') => 2,
        Some('s') => 4,
        Some('d') => 8,
        Some('q') => VECTOR_BYTES,
        _ => panic!("{register} is not a scalar floating-point register"),
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
    let (transfer, memory) = operands
        .split_once(", ")
        .unwrap_or_else(|| panic!("{word:08x} reference line has no memory operand"));
    let (mode, inner): (IndexMode, &str) = if let Some(stripped) = memory.strip_suffix("]!") {
        (IndexMode::Pre, stripped.trim_start_matches('['))
    } else if let Some((bracketed, trailing)) = memory.split_once("], ") {
        let displacement: i64 = parse_immediate(trailing, word);
        return ReferenceForm {
            base: bracketed.trim_start_matches('[').to_owned(),
            displacement,
            mnemonic: mnemonic.to_owned(),
            mode: IndexMode::Post,
            transfer: transfer.to_owned(),
        };
    } else {
        (
            IndexMode::Offset,
            memory
                .strip_suffix(']')
                .unwrap_or_else(|| panic!("{word:08x} memory operand is not bracketed"))
                .trim_start_matches('['),
        )
    };
    let (base, displacement): (&str, i64) = match inner.split_once(", ") {
        Some((register, immediate)) => (register, parse_immediate(immediate, word)),
        None => (inner, 0),
    };
    ReferenceForm {
        base: base.to_owned(),
        displacement,
        mnemonic: mnemonic.to_owned(),
        mode,
        transfer: transfer.to_owned(),
    }
}

fn parse_immediate(text: &str, word: u32) -> i64 {
    let trimmed: &str = text.trim().trim_start_matches('#');
    let (negative, digits): (bool, &str) = trimmed
        .strip_prefix('-')
        .map_or((false, trimmed), |rest: &str| (true, rest));
    let hexadecimal: &str = digits.strip_prefix("0x").unwrap_or(digits);
    let magnitude: i64 = i64::from_str_radix(hexadecimal, 16)
        .unwrap_or_else(|_| panic!("{word:08x} immediate {text} is not hexadecimal"));
    if negative { -magnitude } else { magnitude }
}

fn committed_reference() -> ReferenceFile {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(REFERENCE_FILE);
    let text: String = fs::read_to_string(&path).expect("read the committed scalar fp reference");
    let mut lines: std::str::Lines<'_> = text.lines();
    let header: String = lines
        .next()
        .expect("the reference records its disassembler")
        .to_owned();
    let mut words: Vec<u32> = Vec::with_capacity(MATRIX_WORDS);
    let mut listings: Vec<String> = Vec::with_capacity(MATRIX_WORDS);
    for line in lines {
        let (encoding, body) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("reference line {line} has no listing"));
        words.push(
            u32::from_str_radix(encoding, 16)
                .unwrap_or_else(|_| panic!("reference line {line} has no encoding")),
        );
        listings.push(body.to_owned());
    }
    ReferenceFile {
        header,
        words,
        listings,
    }
}

#[derive(Clone, Debug)]
struct Tools {
    clang: PathBuf,
    objdump: PathBuf,
}

fn disassemble(tools: &Tools, words: &[u32]) -> Vec<String> {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-sleigh-scalar-fp-matrix").expect("create scratch directory");
    let directory: PathBuf = scratch.path().to_path_buf();
    let source: PathBuf = directory.join("matrix.s");
    let object: PathBuf = directory.join("matrix.o");
    let mut assembly: String = String::from(".text\n.arch_extension rcpc3\n");
    for word in words {
        writeln!(assembly, ".inst 0x{word:08x}").expect("append an instruction word");
    }
    fs::write(&source, assembly).expect("write the matrix assembly");
    let assembled: Option<CapturedOutput> = run(
        &tools.clang,
        &[
            OsString::from(format!("--target={REFERENCE_TRIPLE}")),
            OsString::from("-c"),
            OsString::from("-o"),
            object.as_os_str().to_owned(),
            source.as_os_str().to_owned(),
        ],
    );
    assert!(assembled.is_some());
    let listing: Option<CapturedOutput> = run(
        &tools.objdump,
        &[OsString::from("-d"), object.as_os_str().to_owned()],
    );
    let rendered: String = listing
        .map(|output: CapturedOutput| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    let parsed: Vec<(u32, String)> = parse_listing(&rendered);
    let close_result: io::Result<()> = scratch.close();
    assert!(close_result.is_ok(), "{close_result:?}");
    let encodings: Vec<u32> = parsed.iter().map(|(word, _)| *word).collect();
    assert_eq!(encodings, words, "the live listing must cover every word");
    parsed.into_iter().map(|(_, body)| body).collect()
}

fn parse_listing(rendered: &str) -> Vec<(u32, String)> {
    rendered
        .lines()
        .filter_map(|line: &str| {
            let trimmed: &str = line.trim_start();
            let (address, rest) = trimmed.split_once(':')?;
            if address.is_empty() || !address.chars().all(|c: char| c.is_ascii_hexdigit()) {
                return None;
            }
            let rest: &str = rest.trim_start();
            let (encoding, body) = rest.split_once(char::is_whitespace)?;
            if encoding.len() != 8 || !encoding.chars().all(|c: char| c.is_ascii_hexdigit()) {
                return None;
            }
            let word: u32 = u32::from_str_radix(encoding, 16).ok()?;
            Some((word, normalize(body)))
        })
        .collect()
}

fn normalize(body: &str) -> String {
    let without_comment: &str = body.split("//").next().unwrap_or(body);
    let mut cleaned: String = String::with_capacity(without_comment.len());
    let mut depth: usize = 0;
    for character in without_comment.chars() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' if depth > 0 => depth = depth.saturating_sub(1),
            _ if depth == 0 => cleaned.push(character),
            _ => {}
        }
    }
    if cleaned.trim().is_empty() {
        return "<unknown>".to_owned();
    }
    cleaned.split_whitespace().collect::<Vec<&str>>().join(" ")
}

fn run(program: &Path, arguments: &[OsString]) -> Option<CapturedOutput> {
    let result: io::Result<Option<CapturedOutput>> =
        run_captured(program, arguments, TOOL_TIMEOUT, TOOL_CAPTURE_LIMIT);
    assert!(result.is_ok(), "{result:?}");
    let output: CapturedOutput = result.ok().flatten()?;
    assert!(
        output.exit_code == Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output)
}

fn find_tools() -> Option<Tools> {
    Some(Tools {
        clang: find_tool("DISROBE_CLANG", "clang")?,
        objdump: find_tool("DISROBE_LLVM_OBJDUMP", "llvm-objdump")?,
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
