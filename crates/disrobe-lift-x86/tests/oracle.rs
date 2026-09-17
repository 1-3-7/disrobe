#[cfg(target_arch = "x86_64")]
use std::arch::asm;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_lift_x86::decode_block_x86;
use disrobe_sleigh::lifter::DecodedBlock;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

#[allow(clippy::redundant_pub_crate)]
#[path = "oracle/differential.rs"]
mod differential;
#[allow(clippy::redundant_pub_crate)]
#[path = "oracle/evaluator.rs"]
mod evaluator;
#[allow(clippy::redundant_pub_crate)]
#[path = "oracle/generator.rs"]
mod generator;
#[allow(clippy::redundant_pub_crate)]
#[path = "oracle/machine.rs"]
mod machine;

const EXPECTED_INSTRUCTIONS: usize = 281;
const EXPECTED_MODELED: usize = 223;
const EXPECTED_CALLOTHER: usize = 58;
const LEGACY_INSTRUCTIONS: usize = 95;
const EXPECTED_ADDED_MODELED: usize = 130;
const EXPECTED_ADDED_CALLOTHER: usize = 56;
#[derive(Clone, Debug, Eq, PartialEq)]
struct Boundary {
    address: u64,
    length: usize,
    mnemonic: String,
}

#[derive(Clone, Debug)]
struct Toolchain {
    gcc: PathBuf,
    objcopy: PathBuf,
    objdump: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Expression {
    Binary {
        name: &'static str,
        left: Box<Self>,
        right: Box<Self>,
    },
    Load {
        pointer: Box<Self>,
        size_bytes: u32,
        space: Space,
    },
    Node(Varnode),
    Select {
        condition: Box<Self>,
        when_true: Box<Self>,
        when_false: Box<Self>,
    },
    Unary {
        name: &'static str,
        input: Box<Self>,
    },
}

impl Display for Expression {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binary { name, left, right } => write!(formatter, "{name}({left},{right})"),
            Self::Load {
                pointer,
                size_bytes,
                space,
            } => write!(formatter, "load({space},{pointer},{size_bytes})"),
            Self::Node(node) => write!(formatter, "{node}"),
            Self::Select {
                condition,
                when_true,
                when_false,
            } => write!(formatter, "select({condition},{when_true},{when_false})"),
            Self::Unary { name, input } => write!(formatter, "{name}({input})"),
        }
    }
}

#[test]
fn committed_gcc_text_matches_gnu_objdump_boundaries_and_mnemonics() {
    let bytes: Vec<u8> = fs::read(corpus_path("x86_64_oracle_o2.text")).unwrap_or_default();
    let expected: Vec<Boundary> = committed_boundaries();
    let names: Vec<String> = fs::read_to_string(corpus_path("x86_64_oracle_o2.mnemonics"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    assert_eq!(expected.len(), EXPECTED_INSTRUCTIONS);
    assert_eq!(names.len(), expected.len());
    assert_eq!(
        names,
        expected
            .iter()
            .map(|record: &Boundary| record.mnemonic.clone())
            .collect::<Vec<String>>()
    );
    let block: DecodedBlock = decode_block_x86(&bytes, 0, 64);
    assert_block_matches("committed", &block, &expected, bytes.len());
    let modeled: usize = block
        .instructions
        .iter()
        .filter(|instruction: &&PcodeInstr| instruction.status == DecodeStatus::Supported)
        .count();
    let call_other: usize = block
        .instructions
        .iter()
        .filter(|instruction: &&PcodeInstr| instruction.status == DecodeStatus::CallOther)
        .count();
    assert_eq!(modeled, EXPECTED_MODELED);
    assert_eq!(call_other, EXPECTED_CALLOTHER);
    assert_eq!(modeled.saturating_add(call_other), EXPECTED_INSTRUCTIONS);
    let added_modeled: usize = block
        .instructions
        .iter()
        .skip(LEGACY_INSTRUCTIONS)
        .filter(|instruction: &&PcodeInstr| instruction.status == DecodeStatus::Supported)
        .count();
    let added_call_other: usize = block
        .instructions
        .iter()
        .skip(LEGACY_INSTRUCTIONS)
        .filter(|instruction: &&PcodeInstr| instruction.status == DecodeStatus::CallOther)
        .count();
    assert_eq!(added_modeled, EXPECTED_ADDED_MODELED);
    assert_eq!(added_call_other, EXPECTED_ADDED_CALLOTHER);
    let covered: usize = modeled.saturating_add(call_other);
    println!(
        "x86-64 committed corpus: decode {covered}/{EXPECTED_INSTRUCTIONS}, modeled {modeled}, CALLOTHER {call_other}, added modeled {added_modeled}, added CALLOTHER {added_call_other}"
    );
}

#[test]
fn live_gcc_text_matches_live_gnu_objdump() {
    let Some(toolchain): Option<Toolchain> = find_toolchain() else {
        eprintln!("x86-64 live GNU validation skipped because the toolchain is unavailable");
        return;
    };
    let (scratch, directory): (ScratchDir, PathBuf) = temporary_directory();
    let create_result: std::io::Result<()> = fs::create_dir(&directory);
    assert!(create_result.is_ok(), "{create_result:?}");
    let object: PathBuf = directory.join("x86_64_oracle_o2.o");
    let text: PathBuf = directory.join("x86_64_oracle_o2.text");
    let source: PathBuf = fixture_path("x86_64_oracle.c");
    let mut compiler: Command = Command::new(&toolchain.gcc);
    compiler.args([
        OsString::from("-std=c11"),
        OsString::from("-O2"),
        OsString::from("-m64"),
        OsString::from("-march=x86-64-v2"),
        OsString::from("-mno-avx"),
        OsString::from("-fcf-protection=branch"),
        OsString::from("-fno-if-conversion"),
        OsString::from("-fno-if-conversion2"),
        OsString::from("-fno-asynchronous-unwind-tables"),
        OsString::from("-fno-stack-protector"),
        OsString::from("-fno-unwind-tables"),
        OsString::from("-fno-optimize-sibling-calls"),
        OsString::from("-c"),
        source.as_os_str().to_owned(),
        OsString::from("-o"),
        object.as_os_str().to_owned(),
    ]);
    let compile_output: Option<Output> = run(compiler);
    assert!(compile_output.is_some(), "gcc failed");
    let mut copier: Command = Command::new(&toolchain.objcopy);
    copier.args([
        OsString::from("-O"),
        OsString::from("binary"),
        OsString::from("-j"),
        OsString::from(".text"),
        object.as_os_str().to_owned(),
        text.as_os_str().to_owned(),
    ]);
    let copy_output: Option<Output> = run(copier);
    assert!(copy_output.is_some(), "objcopy failed");
    let bytes: Vec<u8> = fs::read(&text).unwrap_or_default();
    let mut dumper: Command = Command::new(&toolchain.objdump);
    dumper.args([
        OsString::from("-d"),
        OsString::from("-z"),
        OsString::from("-M"),
        OsString::from("intel-mnemonic,intel"),
        object.as_os_str().to_owned(),
    ]);
    let dump_output: Option<Output> = run(dumper);
    assert!(dump_output.is_some(), "objdump failed");
    let disassembly: String = dump_output.map_or_else(String::new, |output: Output| {
        String::from_utf8_lossy(&output.stdout).into_owned()
    });
    let expected: Vec<Boundary> = objdump_boundaries(&disassembly, bytes.len());
    let block: DecodedBlock = decode_block_x86(&bytes, 0, 64);
    let close_result: std::io::Result<()> = scratch.close();
    assert!(close_result.is_ok(), "{close_result:?}");
    assert!(!expected.is_empty());
    assert_block_matches("live", &block, &expected, bytes.len());
}

#[test]
fn live_pypcode_reproduces_committed_effects() {
    let Some(python): Option<PathBuf> = find_python_with_pypcode() else {
        eprintln!("x86-64 live pypcode validation skipped because pypcode 4.0.0 is unavailable");
        return;
    };
    let (scratch, directory): (ScratchDir, PathBuf) = temporary_directory();
    let create_result: std::io::Result<()> = fs::create_dir(&directory);
    assert!(create_result.is_ok(), "{create_result:?}");
    let script: PathBuf = fixture_path("../pypcode_oracle.py");
    let corpus: PathBuf = corpus_path("");
    let mut verifier: Command = Command::new(python);
    verifier.args([
        script.as_os_str().to_owned(),
        corpus.as_os_str().to_owned(),
        directory.as_os_str().to_owned(),
    ]);
    let verification: Option<Output> = run(verifier);
    assert!(verification.is_some(), "pypcode oracle regeneration failed");
    for name in ["x86_64_pypcode.raw", "x86_64_pypcode.tsv"] {
        let regenerated: Vec<u8> = fs::read(directory.join(name)).unwrap_or_default();
        let committed: Vec<u8> = fs::read(corpus_path(name)).unwrap_or_default();
        assert!(!regenerated.is_empty(), "{name}");
        assert_eq!(regenerated, committed, "{name}");
    }
    let close_result: std::io::Result<()> = scratch.close();
    assert!(close_result.is_ok(), "{close_result:?}");
}

#[test]
fn normalized_effects_match_ghidra_pypcode() {
    let records: &str = include_str!("corpus/x86_64_pypcode.tsv");
    let raw: &str = include_str!("corpus/x86_64_pypcode.raw");
    let mut banner: std::str::Lines<'_> = raw.lines();
    assert_eq!(banner.next(), Some("pypcode 4.0.0"));
    assert_eq!(banner.next(), Some("x86:LE:64:default"));
    let mut headers: BTreeSet<String> = BTreeSet::new();
    let mut checked: usize = 0;
    let mut added_checked: usize = 0;
    let mut call_other: usize = 0;
    let mut rows: usize = 0;
    for line in records
        .lines()
        .skip(1)
        .filter(|line: &&str| !line.is_empty())
    {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "{line}");
        let address: u64 = u64::from_str_radix(fields[0], 16).unwrap_or(u64::MAX);
        let bytes: Vec<u8> = decode_hex(fields[1]);
        assert!(!bytes.is_empty(), "{line}");
        let header: String = format!("{} {} {}", fields[0], fields[1], fields[2]);
        assert!(
            raw.lines().any(|raw_line: &str| raw_line == header),
            "{line}"
        );
        headers.insert(header);
        let block: DecodedBlock = decode_block_x86(&bytes, address, 64);
        assert_eq!(block.instructions.len(), 1, "{line}");
        let Some(instruction): Option<&PcodeInstr> = block.instructions.first() else {
            continue;
        };
        assert_eq!(instruction.length, bytes.len(), "{line}");
        assert_eq!(instruction.mnemonic, fields[2], "{line}");
        if instruction.status == DecodeStatus::CallOther {
            call_other = call_other.saturating_add(1);
        } else {
            assert_eq!(instruction.status, DecodeStatus::Supported, "{line}");
            let facts: Vec<String> = architectural_facts(&instruction.ops);
            let actual: String = if facts.is_empty() {
                "none".to_owned()
            } else {
                facts.join("|")
            };
            assert_eq!(actual, fields[3], "{line}");
            checked = checked.saturating_add(1);
            if rows >= LEGACY_INSTRUCTIONS {
                added_checked = added_checked.saturating_add(1);
            }
        }
        rows = rows.saturating_add(1);
    }
    assert_eq!(rows, EXPECTED_INSTRUCTIONS);
    assert_eq!(headers.len(), rows);
    assert_eq!(checked, EXPECTED_MODELED);
    assert_eq!(added_checked, EXPECTED_ADDED_MODELED);
    assert_eq!(call_other, EXPECTED_CALLOTHER);
    println!(
        "x86-64 pypcode effects: {checked}/{EXPECTED_MODELED} modeled instructions agree, added {added_checked}/{EXPECTED_ADDED_MODELED}"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn native_xadd_results_and_flags_match_lifted_pcode() {
    let block: DecodedBlock = decode_block_x86(&[0x48, 0x0f, 0xc1, 0xd8], 0x4000, 64);
    assert_eq!(block.instructions.len(), 1);
    let Some(instruction): Option<&PcodeInstr> = block.instructions.first() else {
        return;
    };
    assert_eq!(instruction.status, DecodeStatus::Supported);
    let cases: [(u64, u64); 8] = [
        (0, 0),
        (u64::MAX, 1),
        (0x7fff_ffff_ffff_ffff, 1),
        (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
        (0x0f, 1),
        (0x7f, 1),
        (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3211),
        (0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555),
    ];
    for case in cases {
        let left_input: u64 = case.0;
        let right_input: u64 = case.1;
        let (native_left, native_right, native_flags): (u64, u64, u64) =
            native_xadd(left_input, right_input);
        let evaluated: Option<BTreeMap<Varnode, u64>> =
            evaluate_xadd(&instruction.ops, left_input, right_input);
        assert!(evaluated.is_some());
        let Some(values): Option<BTreeMap<Varnode, u64>> = evaluated else {
            continue;
        };
        assert_eq!(read_value(register_node(0, 8), &values), native_left);
        assert_eq!(read_value(register_node(0x18, 8), &values), native_right);
        for flag in [
            (0x200_u64, 0_u32),
            (0x202, 2),
            (0x204, 4),
            (0x206, 6),
            (0x207, 7),
            (0x20b, 11),
        ] {
            let expected: u64 = native_flags.checked_shr(flag.1).unwrap_or(0) & 1;
            assert_eq!(
                read_value(register_node(flag.0, 1), &values),
                expected,
                "left={left_input:#x} right={right_input:#x} flag={:#x}",
                flag.0
            );
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn native_xadd(mut left: u64, mut right: u64) -> (u64, u64, u64) {
    let flags: u64;
    unsafe {
        asm!(
            "xadd {left}, {right}",
            "pushfq",
            "pop {flags}",
            left = inout(reg) left,
            right = inout(reg) right,
            flags = lateout(reg) flags,
        );
    }
    (left, right, flags)
}

#[cfg(target_arch = "x86_64")]
fn evaluate_xadd(operations: &[PcodeOp], left: u64, right: u64) -> Option<BTreeMap<Varnode, u64>> {
    let mut values: BTreeMap<Varnode, u64> =
        BTreeMap::from([(register_node(0, 8), left), (register_node(0x18, 8), right)]);
    for operation in operations {
        let assignment: Option<(Varnode, u64)> = match operation {
            PcodeOp::Copy { output, input } => Some((*output, read_value(*input, &values))),
            PcodeOp::IntAdd {
                output,
                left,
                right,
            } => Some((
                *output,
                read_value(*left, &values).wrapping_add(read_value(*right, &values))
                    & width_mask(output.size_bytes),
            )),
            PcodeOp::IntAnd {
                output,
                left,
                right,
            } => Some((
                *output,
                read_value(*left, &values) & read_value(*right, &values),
            )),
            PcodeOp::IntCarry {
                output,
                left,
                right,
            } => {
                let sum: u128 = u128::from(read_value(*left, &values))
                    + u128::from(read_value(*right, &values));
                Some((
                    *output,
                    u64::from(sum > u128::from(width_mask(left.size_bytes))),
                ))
            }
            PcodeOp::IntEqual {
                output,
                left,
                right,
            } => Some((
                *output,
                u64::from(read_value(*left, &values) == read_value(*right, &values)),
            )),
            PcodeOp::IntNotEqual {
                output,
                left,
                right,
            } => Some((
                *output,
                u64::from(read_value(*left, &values) != read_value(*right, &values)),
            )),
            PcodeOp::IntSignedCarry {
                output,
                left,
                right,
            } => {
                let bits: u32 = left.size_bytes.checked_mul(8).unwrap_or(0);
                let sign_position: u32 = bits.checked_sub(1)?;
                let sum: i128 = signed_value(read_value(*left, &values), bits)
                    .checked_add(signed_value(read_value(*right, &values), bits))
                    .unwrap_or(i128::MAX);
                let boundary: i128 = 1_i128.checked_shl(sign_position).unwrap_or(0);
                Some((*output, u64::from(sum < -boundary || sum >= boundary)))
            }
            PcodeOp::IntSignedLess {
                output,
                left,
                right,
            } => {
                let bits: u32 = left.size_bytes.checked_mul(8).unwrap_or(0);
                Some((
                    *output,
                    u64::from(
                        signed_value(read_value(*left, &values), bits)
                            < signed_value(read_value(*right, &values), bits),
                    ),
                ))
            }
            PcodeOp::IntXor {
                output,
                left,
                right,
            } => Some((
                *output,
                read_value(*left, &values) ^ read_value(*right, &values),
            )),
            PcodeOp::CallOther {
                name,
                output: Some(output),
                inputs,
            } if name == "x86_parity8_pure_v1" => {
                let input: u64 = inputs
                    .first()
                    .map_or(0, |node: &Varnode| read_value(*node, &values));
                Some((
                    *output,
                    u64::from((input & 0xff).count_ones().is_multiple_of(2)),
                ))
            }
            _ => return None,
        };
        let Some((output, value)): Option<(Varnode, u64)> = assignment else {
            continue;
        };
        let _: Option<u64> = values.insert(output, value & width_mask(output.size_bytes));
    }
    Some(values)
}

#[cfg(target_arch = "x86_64")]
fn read_value(node: Varnode, values: &BTreeMap<Varnode, u64>) -> u64 {
    if node.space == Space::Constant {
        node.offset & width_mask(node.size_bytes)
    } else {
        values.get(&node).copied().unwrap_or(0)
    }
}

#[cfg(target_arch = "x86_64")]
const fn register_node(offset: u64, size_bytes: u32) -> Varnode {
    Varnode {
        offset,
        size_bytes,
        space: Space::Register,
    }
}

#[cfg(target_arch = "x86_64")]
const fn width_mask(size_bytes: u32) -> u64 {
    let bits: u32 = match size_bytes.checked_mul(8) {
        Some(value) => value,
        None => return 0,
    };
    if bits >= 64 {
        u64::MAX
    } else {
        match 1_u64.checked_shl(bits) {
            Some(value) => match value.checked_sub(1) {
                Some(mask) => mask,
                None => 0,
            },
            None => 0,
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn signed_value(value: u64, bits: u32) -> i128 {
    if bits == 0 || bits > 64 {
        return 0;
    }
    let Some(sign_position): Option<u32> = bits.checked_sub(1) else {
        return 0;
    };
    let boundary: u64 = 1_u64.checked_shl(sign_position).unwrap_or(0);
    let masked: u64 = value & width_mask(bits / 8);
    if masked & boundary == 0 {
        i128::from(masked)
    } else {
        i128::from(masked) - 1_i128.checked_shl(bits).unwrap_or(0)
    }
}

fn assert_block_matches(
    label: &str,
    block: &DecodedBlock,
    expected: &[Boundary],
    byte_length: usize,
) {
    assert_eq!(block.consumed, byte_length, "{label}");
    assert_eq!(block.instructions.len(), expected.len(), "{label}");
    for (instruction, reference) in block.instructions.iter().zip(expected) {
        assert_eq!(instruction.address, reference.address, "{label}");
        assert_eq!(instruction.length, reference.length, "{label}");
        assert_eq!(instruction.mnemonic, reference.mnemonic, "{label}");
        assert!(
            matches!(
                instruction.status,
                DecodeStatus::Supported | DecodeStatus::CallOther
            ),
            "{label}: {instruction:#?}"
        );
    }
}

fn committed_boundaries() -> Vec<Boundary> {
    include_str!("corpus/x86_64_oracle_o2.boundaries")
        .lines()
        .skip(1)
        .filter_map(|line: &str| {
            let mut fields: std::str::Split<'_, char> = line.split('\t');
            let address: u64 = u64::from_str_radix(fields.next()?, 16).ok()?;
            let length: usize = fields.next()?.parse().ok()?;
            let mnemonic: String = fields.next()?.to_owned();
            Some(Boundary {
                address,
                length,
                mnemonic,
            })
        })
        .collect()
}

fn objdump_boundaries(disassembly: &str, text_length: usize) -> Vec<Boundary> {
    let mut starts: Vec<(u64, String)> = Vec::new();
    for line in disassembly.lines() {
        let columns: Vec<&str> = line.split('\t').collect();
        if columns.len() < 3 {
            continue;
        }
        let address_text: &str = columns[0].trim().trim_end_matches(':');
        if address_text.is_empty()
            || !address_text
                .chars()
                .all(|character: char| character.is_ascii_hexdigit())
        {
            continue;
        }
        let address: u64 = u64::from_str_radix(address_text, 16).unwrap_or(u64::MAX);
        let instruction_text: &str = columns[2];
        let mnemonic: Option<&str> = instruction_text
            .split_whitespace()
            .find(|token: &&str| !is_objdump_prefix(token));
        if let Some(name) = mnemonic {
            starts.push((address, normalized_objdump_mnemonic(name, instruction_text)));
        }
    }
    let text_end: u64 = u64::try_from(text_length).unwrap_or(u64::MAX);
    starts
        .iter()
        .enumerate()
        .filter_map(|(index, (address, mnemonic)): (usize, &(u64, String))| {
            let end: u64 = starts
                .get(index.saturating_add(1))
                .map_or(text_end, |(next, _): &(u64, String)| *next);
            let length: usize = usize::try_from(end.checked_sub(*address)?).ok()?;
            Some(Boundary {
                address: *address,
                length,
                mnemonic: mnemonic.clone(),
            })
        })
        .collect()
}

fn normalized_objdump_mnemonic(name: &str, instruction_text: &str) -> String {
    if !matches!(name, "movs" | "stos" | "lods" | "cmps" | "scas") {
        return name.to_owned();
    }
    let suffix: Option<char> = if instruction_text.contains("QWORD PTR") {
        Some('q')
    } else if instruction_text.contains("DWORD PTR") {
        Some('d')
    } else if instruction_text.contains("WORD PTR") {
        Some('w')
    } else if instruction_text.contains("BYTE PTR") {
        Some('b')
    } else {
        None
    };
    suffix.map_or_else(|| name.to_owned(), |width: char| format!("{name}{width}"))
}

fn is_objdump_prefix(token: &str) -> bool {
    matches!(
        token,
        "addr16"
            | "addr32"
            | "cs"
            | "data16"
            | "ds"
            | "es"
            | "fs"
            | "gs"
            | "lock"
            | "rep"
            | "repe"
            | "repne"
            | "repnz"
            | "repz"
            | "rex.W"
            | "ss"
    )
}

fn find_toolchain() -> Option<Toolchain> {
    Some(Toolchain {
        gcc: find_tool("gcc")?,
        objcopy: find_tool("objcopy")?,
        objdump: find_tool("objdump")?,
    })
}

fn find_tool(name: &str) -> Option<PathBuf> {
    let executable: String = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let mut directories: Vec<PathBuf> = Vec::new();
    if let Some(configured) = env::var_os("DISROBE_X86_GNU_BIN") {
        directories.push(PathBuf::from(configured));
    }
    if cfg!(windows) {
        directories.push(PathBuf::from("C:/Strawberry/c/bin"));
    }
    if let Some(path) = env::var_os("PATH") {
        directories.extend(env::split_paths(&path));
    }
    directories
        .into_iter()
        .map(|directory: PathBuf| directory.join(&executable))
        .find(|candidate: &PathBuf| candidate.is_file())
}

fn find_python_with_pypcode() -> Option<PathBuf> {
    let names: [&str; 2] = if cfg!(windows) {
        ["python", "python3"]
    } else {
        ["python3", "python"]
    };
    for name in names {
        let Some(candidate): Option<PathBuf> = find_tool(name) else {
            continue;
        };
        let mut command: Command = Command::new(&candidate);
        command.args([
            OsString::from("-c"),
            OsString::from(
                "import pypcode; raise SystemExit(0 if pypcode.__version__ == '4.0.0' else 1)",
            ),
        ]);
        let output: std::io::Result<Output> = command.output();
        if matches!(output, Ok(result) if result.status.success()) {
            return Some(candidate);
        }
    }
    None
}

fn run(mut command: Command) -> Option<Output> {
    let output: Output = command.output().ok()?;
    if output.status.success() {
        Some(output)
    } else {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        None
    }
}

#[allow(clippy::expect_used)]
fn temporary_directory() -> (ScratchDir, PathBuf) {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-lift-x86").expect("create scratch directory");
    let directory: PathBuf = scratch.path().join("payload");
    (scratch, directory)
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn corpus_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(name)
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    if !encoded.len().is_multiple_of(2) {
        return Vec::new();
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .filter_map(|pair: &[u8]| {
            let digits: &str = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

fn architectural_facts(operations: &[PcodeOp]) -> Vec<String> {
    let mut values: BTreeMap<Varnode, Expression> = BTreeMap::new();
    let mut pending: Vec<String> = Vec::new();
    let mut ordered: Vec<String> = Vec::new();
    for operation in operations {
        match operation {
            PcodeOp::BoolAnd {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "booland",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::BoolNegate { output, input } => {
                record_unary(*output, "boolnot", *input, &mut values, &mut pending);
            }
            PcodeOp::BoolOr {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "boolor",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::BoolXor {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "boolxor",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::Branch { target } => push_ordered(
                format!("branch({})", resolve(*target, &values)),
                &mut pending,
                &mut ordered,
            ),
            PcodeOp::BranchIndirect { target } => push_ordered(
                format!("branchind({})", resolve(*target, &values)),
                &mut pending,
                &mut ordered,
            ),
            PcodeOp::CBranch { target, condition } => push_ordered(
                format!(
                    "cbranch({},{})",
                    resolve(*target, &values),
                    resolve(*condition, &values)
                ),
                &mut pending,
                &mut ordered,
            ),
            PcodeOp::Call { target } => push_ordered(
                format!("call({})", resolve(*target, &values)),
                &mut pending,
                &mut ordered,
            ),
            PcodeOp::CallIndirect { target } => push_ordered(
                format!("callind({})", resolve(*target, &values)),
                &mut pending,
                &mut ordered,
            ),
            PcodeOp::CallOther {
                name,
                output: Some(output),
                inputs,
            } if name == "x86_parity8_pure_v1" => {
                let expression: Expression = inputs
                    .first()
                    .map_or(Expression::Node(*output), |input: &Varnode| {
                        resolve(*input, &values)
                    });
                record(*output, expression, &mut values, &mut pending);
            }
            PcodeOp::CallOther { name, .. } if name == "x86_undefined_flag_pure_v1" => {}
            PcodeOp::CallOther { name, .. } => {
                push_ordered(format!("callother({name})"), &mut pending, &mut ordered);
            }
            PcodeOp::Copy { output, input } => {
                let expression: Expression = resolve(*input, &values);
                record(*output, expression, &mut values, &mut pending);
            }
            PcodeOp::FloatAdd {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "fadd",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::FloatDiv {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "fdiv",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::FloatEqual {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "feq",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::FloatLess {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "flt",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::FloatLessEqual {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "fle",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::FloatMult {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "fmul",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::FloatSqrt { output, input } => {
                record_unary(*output, "fsqrt", *input, &mut values, &mut pending);
            }
            PcodeOp::FloatSub {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "fsub",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::FloatToFloat { output, input } => {
                record_unary(*output, "float2float", *input, &mut values, &mut pending);
            }
            PcodeOp::FloatTrunc { output, input } => {
                record_unary(*output, "trunc", *input, &mut values, &mut pending);
            }
            PcodeOp::IntToFloat { output, input } => {
                record_unary(*output, "int2float", *input, &mut values, &mut pending);
            }
            PcodeOp::IntAdd {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "add",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntAnd {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "and",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntCarry {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "carry",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntDiv {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "udiv",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntEqual {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "eq",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntLeft {
                output,
                input,
                amount,
            } => record_binary(
                *output,
                "shl",
                *input,
                *amount,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntLess {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "ult",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntLessEqual {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "ule",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntMult {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "mul",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntNegate { output, input } => {
                record_unary(*output, "not", *input, &mut values, &mut pending);
            }
            PcodeOp::IntNotEqual {
                output,
                left,
                right,
            } => {
                let name: &'static str =
                    if flag_name(*left).is_some() && flag_name(*right).is_some() {
                        "boolxor"
                    } else {
                        "ne"
                    };
                record_binary(
                    *output,
                    name,
                    *left,
                    *right,
                    true,
                    &mut values,
                    &mut pending,
                );
            }
            PcodeOp::IntOr {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "or",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntRem {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "urem",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntRight {
                output,
                input,
                amount,
            } => record_binary(
                *output,
                "lshr",
                *input,
                *amount,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSignedBorrow {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "sborrow",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSignedCarry {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "scarry",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSignedDiv {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "sdiv",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSignedLess {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "slt",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSignedLessEqual {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "sle",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSignedRem {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "srem",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSignedRight {
                output,
                input,
                amount,
            } => record_binary(
                *output,
                "ashr",
                *input,
                *amount,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSub {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "sub",
                *left,
                *right,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntXor {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "xor",
                *left,
                *right,
                true,
                &mut values,
                &mut pending,
            ),
            PcodeOp::IntSext { output, input } => {
                record_unary(*output, "sext", *input, &mut values, &mut pending);
            }
            PcodeOp::IntZext { output, input } => {
                record_unary(*output, "zext", *input, &mut values, &mut pending);
            }
            PcodeOp::Load {
                output,
                space,
                pointer,
            } => {
                let expression: Expression = Expression::Load {
                    pointer: Box::new(resolve(*pointer, &values)),
                    size_bytes: output.size_bytes,
                    space: *space,
                };
                record(*output, expression, &mut values, &mut pending);
            }
            PcodeOp::Piece { output, high, low } => record_binary(
                *output,
                "piece",
                *high,
                *low,
                false,
                &mut values,
                &mut pending,
            ),
            PcodeOp::Return { target } => {
                let rendered: String = target.map_or_else(
                    || "none".to_owned(),
                    |node: Varnode| resolve(node, &values).to_string(),
                );
                push_ordered(format!("return({rendered})"), &mut pending, &mut ordered);
            }
            PcodeOp::Store {
                space,
                pointer,
                value,
            } => pending.push(format!(
                "store({},{},{})",
                space,
                resolve(*pointer, &values),
                resolve(*value, &values)
            )),
            PcodeOp::Subpiece {
                output,
                input,
                byte_offset,
            } => record_subpiece(*output, *input, *byte_offset, &mut values, &mut pending),
        }
    }
    pending.sort();
    ordered.append(&mut pending);
    ordered
}

fn push_ordered(fact: String, pending: &mut Vec<String>, ordered: &mut Vec<String>) {
    pending.sort();
    ordered.append(pending);
    ordered.push(fact);
}

fn record_binary(
    output: Varnode,
    name: &'static str,
    left: Varnode,
    right: Varnode,
    commutative: bool,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let expression: Expression = binary(
        name,
        resolve(left, values),
        resolve(right, values),
        commutative,
        output.size_bytes,
    );
    record(output, expression, values, facts);
}

fn record_unary(
    output: Varnode,
    name: &'static str,
    input: Varnode,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let resolved: Expression = resolve(input, values);
    let expression: Expression = if name == "zext" {
        match resolved {
            Expression::Node(node) if node.space == Space::Constant => Expression::Node(Varnode {
                offset: node.offset,
                size_bytes: output.size_bytes,
                space: Space::Constant,
            }),
            other => Expression::Unary {
                name,
                input: Box::new(other),
            },
        }
    } else if name == "boolnot" {
        match resolved {
            Expression::Unary {
                name: "boolnot",
                input,
            } => *input,
            other => Expression::Unary {
                name,
                input: Box::new(other),
            },
        }
    } else {
        Expression::Unary {
            name,
            input: Box::new(resolved),
        }
    };
    record(output, expression, values, facts);
}

fn record_subpiece(
    output: Varnode,
    input: Varnode,
    byte_offset: Varnode,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let resolved_input: Expression = resolve(input, values);
    let resolved_offset: Expression = resolve(byte_offset, values);
    let expression: Expression =
        register_subpiece(&resolved_input, &resolved_offset, output.size_bytes)
            .or_else(|| low_signed_product(&resolved_input, &resolved_offset, output.size_bytes))
            .unwrap_or_else(|| Expression::Binary {
                name: "subpiece",
                left: Box::new(resolved_input),
                right: Box::new(resolved_offset),
            });
    record(output, expression, values, facts);
}

fn register_subpiece(
    input: &Expression,
    offset: &Expression,
    output_size: u32,
) -> Option<Expression> {
    let Expression::Node(input_node) = input else {
        return None;
    };
    let Expression::Node(offset_node) = offset else {
        return None;
    };
    if input_node.space != Space::Register || offset_node.space != Space::Constant {
        return None;
    }
    let byte_offset: u64 = offset_node.offset;
    let end: u64 = byte_offset.checked_add(u64::from(output_size))?;
    if end > u64::from(input_node.size_bytes) {
        return None;
    }
    let selected: Varnode = Varnode {
        offset: input_node.offset.checked_add(byte_offset)?,
        size_bytes: output_size,
        space: Space::Register,
    };
    Some(Expression::Node(selected))
}

fn low_signed_product(
    input: &Expression,
    offset: &Expression,
    output_size: u32,
) -> Option<Expression> {
    if !matches!(offset, Expression::Node(node) if node.space == Space::Constant && node.offset == 0)
    {
        return None;
    }
    let Expression::Binary {
        name: "mul",
        left,
        right,
    } = input
    else {
        return None;
    };
    let Expression::Unary {
        name: "sext",
        input: original_left,
    } = left.as_ref()
    else {
        return None;
    };
    let Expression::Unary {
        name: "sext",
        input: original_right,
    } = right.as_ref()
    else {
        return None;
    };
    Some(binary(
        "mul",
        original_left.as_ref().clone(),
        original_right.as_ref().clone(),
        true,
        output_size,
    ))
}

fn record(
    output: Varnode,
    expression: Expression,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let previous: Option<Expression> = values.insert(output, expression.clone());
    drop(previous);
    if let Some(name) = flag_name(output) {
        if name != "AF" {
            let marker: String = format!("write_flag({name})");
            facts.retain(|fact: &String| fact != &marker);
            facts.push(marker);
        }
        return;
    }
    if let Some(base) = gpr_base(output) {
        if output.size_bytes == 8 {
            for size_bytes in [1_u32, 2, 4] {
                let prefix: String = format!("write(register:0x{base:x}:{size_bytes},");
                facts.retain(|fact: &String| !fact.starts_with(&prefix));
            }
        }
        let prefix: String = format!("write({output},");
        facts.retain(|fact: &String| !fact.starts_with(&prefix));
        facts.push(format!("{prefix}{expression})"));
        return;
    }
    let Some(base): Option<u64> = xmm_base(output) else {
        return;
    };
    if output.size_bytes == 16 {
        for byte_offset in 0_u64..16 {
            for size_bytes in [1_u32, 2, 4, 8] {
                let Some(end): Option<u64> = byte_offset.checked_add(u64::from(size_bytes)) else {
                    continue;
                };
                if end > 16 {
                    continue;
                }
                let Some(offset): Option<u64> = base.checked_add(byte_offset) else {
                    continue;
                };
                let prefix: String = format!("write(register:0x{offset:x}:{size_bytes},");
                facts.retain(|fact: &String| !fact.starts_with(&prefix));
            }
        }
    }
    let prefix: String = format!("write({output},");
    facts.retain(|fact: &String| !fact.starts_with(&prefix));
    facts.push(format!("{prefix}{expression})"));
}

fn resolve(node: Varnode, values: &BTreeMap<Varnode, Expression>) -> Expression {
    values.get(&node).cloned().unwrap_or(Expression::Node(node))
}

fn binary(
    name: &'static str,
    left: Expression,
    right: Expression,
    commutative: bool,
    output_size: u32,
) -> Expression {
    if name == "add" {
        return canonical_add(left, right, output_size);
    }
    if name == "or"
        && let Some(selection) = masked_select(&left, &right)
    {
        return selection;
    }
    if name == "booland"
        && let (
            Expression::Unary {
                name: "boolnot",
                input: left_input,
            },
            Expression::Unary {
                name: "boolnot",
                input: right_input,
            },
        ) = (&left, &right)
    {
        let disjunction: Expression = binary(
            "boolor",
            left_input.as_ref().clone(),
            right_input.as_ref().clone(),
            true,
            output_size,
        );
        return Expression::Unary {
            name: "boolnot",
            input: Box::new(disjunction),
        };
    }
    if left == right {
        if matches!(name, "and" | "or") {
            return left;
        }
        if matches!(name, "boolxor" | "ne" | "sub" | "xor") {
            return Expression::Node(Varnode {
                offset: 0,
                size_bytes: output_size,
                space: Space::Constant,
            });
        }
        if name == "eq" {
            return Expression::Node(Varnode {
                offset: 1,
                size_bytes: output_size,
                space: Space::Constant,
            });
        }
    }
    if name == "mul" {
        if is_constant(&left, 1) {
            return right;
        }
        if is_constant(&right, 1) {
            return left;
        }
    }
    let (canonical_left, canonical_right): (Expression, Expression) =
        if commutative && left.to_string() > right.to_string() {
            (right, left)
        } else {
            (left, right)
        };
    Expression::Binary {
        name,
        left: Box::new(canonical_left),
        right: Box::new(canonical_right),
    }
}

fn masked_select(left: &Expression, right: &Expression) -> Option<Expression> {
    let left_term: (bool, &Expression, &Expression) = masked_term(left)?;
    let right_term: (bool, &Expression, &Expression) = masked_term(right)?;
    if left_term.0 == right_term.0 || left_term.2 != right_term.2 {
        return None;
    }
    let (when_true, when_false): (&Expression, &Expression) = if left_term.0 {
        (left_term.1, right_term.1)
    } else {
        (right_term.1, left_term.1)
    };
    Some(select_expression(
        left_term.2.clone(),
        when_true.clone(),
        when_false.clone(),
    ))
}

fn masked_term(expression: &Expression) -> Option<(bool, &Expression, &Expression)> {
    let Expression::Binary {
        name: "and",
        left,
        right,
    } = expression
    else {
        return None;
    };
    if let Some(condition) = mask_condition(left) {
        return Some((true, right, condition));
    }
    if let Some(condition) = mask_condition(right) {
        return Some((true, left, condition));
    }
    if let Expression::Unary { name: "not", input } = left.as_ref()
        && let Some(condition) = mask_condition(input)
    {
        return Some((false, right, condition));
    }
    if let Expression::Unary { name: "not", input } = right.as_ref()
        && let Some(condition) = mask_condition(input)
    {
        return Some((false, left, condition));
    }
    None
}

fn mask_condition(expression: &Expression) -> Option<&Expression> {
    let Expression::Binary {
        name: "sub",
        left,
        right,
    } = expression
    else {
        return None;
    };
    if !matches!(left.as_ref(), Expression::Node(node) if node.space == Space::Constant && node.offset == 0)
    {
        return None;
    }
    let Expression::Unary {
        name: "zext",
        input,
    } = right.as_ref()
    else {
        return None;
    };
    Some(input)
}

fn select_expression(
    condition: Expression,
    when_true: Expression,
    when_false: Expression,
) -> Expression {
    if let Expression::Unary {
        name: "boolnot",
        input,
    } = condition
    {
        return Expression::Select {
            condition: input,
            when_true: Box::new(when_false),
            when_false: Box::new(when_true),
        };
    }
    Expression::Select {
        condition: Box::new(condition),
        when_true: Box::new(when_true),
        when_false: Box::new(when_false),
    }
}

fn canonical_add(left: Expression, right: Expression, output_size: u32) -> Expression {
    let mut terms: Vec<Expression> = Vec::new();
    let mut constant_total: u64 = 0;
    let mut saw_constant: bool = false;
    collect_add_terms(
        left,
        output_size,
        &mut terms,
        &mut constant_total,
        &mut saw_constant,
    );
    collect_add_terms(
        right,
        output_size,
        &mut terms,
        &mut constant_total,
        &mut saw_constant,
    );
    let bit_width: u32 = output_size.saturating_mul(8);
    let mask: u64 = if bit_width >= 64 {
        u64::MAX
    } else {
        1_u64.checked_shl(bit_width).unwrap_or(0).saturating_sub(1)
    };
    constant_total &= mask;
    if saw_constant && (constant_total != 0 || terms.is_empty()) {
        terms.push(Expression::Node(Varnode {
            offset: constant_total,
            size_bytes: output_size,
            space: Space::Constant,
        }));
    }
    terms.sort_by_key(ToString::to_string);
    let mut iterator: std::vec::IntoIter<Expression> = terms.into_iter();
    let Some(first): Option<Expression> = iterator.next() else {
        return Expression::Node(Varnode {
            offset: 0,
            size_bytes: output_size,
            space: Space::Constant,
        });
    };
    iterator.fold(first, |accumulator: Expression, term: Expression| {
        Expression::Binary {
            name: "add",
            left: Box::new(accumulator),
            right: Box::new(term),
        }
    })
}

fn collect_add_terms(
    expression: Expression,
    output_size: u32,
    terms: &mut Vec<Expression>,
    constant_total: &mut u64,
    saw_constant: &mut bool,
) {
    match expression {
        Expression::Node(node) if node.space == Space::Constant => {
            let bits: u32 = output_size.saturating_mul(8);
            let mask: u64 = if bits >= 64 {
                u64::MAX
            } else {
                1_u64.checked_shl(bits).unwrap_or(0).saturating_sub(1)
            };
            *constant_total = constant_total.wrapping_add(node.offset) & mask;
            *saw_constant = true;
        }
        Expression::Binary {
            name: "add",
            left,
            right,
        } => {
            collect_add_terms(*left, output_size, terms, constant_total, saw_constant);
            collect_add_terms(*right, output_size, terms, constant_total, saw_constant);
        }
        other => terms.push(other),
    }
}

fn is_constant(expression: &Expression, value: u64) -> bool {
    matches!(expression, Expression::Node(node) if node.space == Space::Constant && node.offset == value)
}

fn flag_name(node: Varnode) -> Option<&'static str> {
    if node.space != Space::Register || node.size_bytes != 1 {
        return None;
    }
    match node.offset {
        0x200 => Some("CF"),
        0x202 => Some("PF"),
        0x204 => Some("AF"),
        0x206 => Some("ZF"),
        0x207 => Some("SF"),
        0x20b => Some("OF"),
        _ => None,
    }
}

fn xmm_base(node: Varnode) -> Option<u64> {
    if node.space != Space::Register {
        return None;
    }
    let relative: u64 = node.offset.checked_sub(0x1200)?;
    let index: u64 = relative / 0x40;
    if index >= 16 {
        return None;
    }
    let base: u64 = 0x1200_u64.checked_add(index.checked_mul(0x40)?)?;
    let within: u64 = node.offset.checked_sub(base)?;
    let end: u64 = within.checked_add(u64::from(node.size_bytes))?;
    (end <= 16).then_some(base)
}

fn gpr_base(node: Varnode) -> Option<u64> {
    if node.space != Space::Register || !matches!(node.size_bytes, 1 | 2 | 4 | 8) {
        return None;
    }
    let base: u64 = if node.size_bytes == 1 && matches!(node.offset, 1 | 9 | 0x11 | 0x19) {
        node.offset.checked_sub(1)?
    } else {
        node.offset
    };
    matches!(
        base,
        0x00 | 0x08
            | 0x10
            | 0x18
            | 0x20
            | 0x28
            | 0x30
            | 0x38
            | 0x80
            | 0x88
            | 0x90
            | 0x98
            | 0xa0
            | 0xa8
            | 0xb0
            | 0xb8
    )
    .then_some(base)
}
