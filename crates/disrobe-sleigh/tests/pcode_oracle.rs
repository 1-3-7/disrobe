use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use disrobe_sleigh::decode_block;
use disrobe_sleigh::lifter::{
    ArmMode, DecodedBlock, Language, RiscVWidth, decode_block_for_language,
};
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};
use disrobe_sleigh::syntax::Endian;

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
        when_false: Box<Self>,
        when_true: Box<Self>,
    },
    Unary {
        input: Box<Self>,
        name: &'static str,
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
                when_false,
                when_true,
            } => write!(formatter, "select({condition},{when_true},{when_false})"),
            Self::Unary { input, name } => write!(formatter, "{name}({input})"),
        }
    }
}

#[test]
fn normalized_architectural_effects_match_ghidra_pypcode() {
    let records: &str = include_str!("corpus/aarch64_pypcode.tsv");
    let raw: String = include_str!("corpus/aarch64_pypcode.raw").replace('\r', "");
    assert!(raw.starts_with("pypcode 4.0.0\nAARCH64:LE:64:v8A\n"));
    let raw_headers: Vec<&str> = raw
        .lines()
        .filter(|line: &&str| is_raw_header(line))
        .collect();
    let mut checked: usize = 0;
    for line in records
        .lines()
        .skip(1)
        .filter(|line: &&str| !line.is_empty())
    {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "{line}");
        let raw_header: String = format!("{:0>4} {} {}", fields[0], fields[1], fields[2]);
        assert!(raw_headers.contains(&raw_header.as_str()), "{line}");
        let address: u64 = u64::from_str_radix(fields[0], 16).unwrap_or(u64::MAX);
        let word: u32 = u32::from_str_radix(fields[1], 16).unwrap_or(u32::MAX);
        let instructions: Vec<PcodeInstr> = decode_block(&word.to_le_bytes(), address);
        assert_eq!(instructions.len(), 1, "{line}");
        let Some(instruction) = instructions.first() else {
            continue;
        };
        assert_eq!(instruction.status, DecodeStatus::Supported, "{line}");
        assert_eq!(instruction.mnemonic, fields[2], "{line}");
        let joined: String = architectural_facts(&instruction.ops).join("|");
        let actual: String = if joined.is_empty() {
            "none".to_owned()
        } else {
            joined
        };
        assert_eq!(actual, fields[3], "{line}");
        checked = checked.saturating_add(1);
    }
    assert_eq!(checked, 64);
    assert_eq!(raw_headers.len(), checked);
}

#[test]
fn multiarch_architectural_effects_match_ghidra_pypcode() {
    let records: &str = include_str!("corpus/multiarch_pypcode.tsv");
    let raw: String = include_str!("corpus/multiarch_pypcode.raw").replace('\r', "");
    assert!(raw.starts_with("pypcode 4.0.0\n"));
    let raw_headers: Vec<&str> = raw
        .lines()
        .filter(|line: &&str| is_multiarch_raw_header(line))
        .collect();
    let mut checked: usize = 0;
    for line in records
        .lines()
        .skip(1)
        .filter(|line: &&str| !line.is_empty())
    {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 5, "{line}");
        let language: Option<Language> = match fields[0] {
            "arm32-a32" => Some(Language::Arm32(ArmMode::A32)),
            "arm32-thumb" => Some(Language::Arm32(ArmMode::Thumb)),
            "mips32le" => Some(Language::Mips32(Endian::Little)),
            "mips32be" => Some(Language::Mips32(Endian::Big)),
            "powerpc32" => Some(Language::PowerPc32Be),
            "powerpc64" => Some(Language::PowerPc64Be),
            "riscv32" => Some(Language::RiscV(RiscVWidth::Rv32)),
            "riscv64" => Some(Language::RiscV(RiscVWidth::Rv64)),
            "riscv32a" | "riscv32c" | "riscv32fd" => {
                Some(Language::RiscVCompressed(RiscVWidth::Rv32))
            }
            "riscv64a" | "riscv64c" | "riscv64fd" => {
                Some(Language::RiscVCompressed(RiscVWidth::Rv64))
            }
            _ => None,
        };
        assert!(language.is_some(), "{line}");
        let Some(language) = language else {
            continue;
        };
        let address: u64 = u64::from_str_radix(fields[1], 16).unwrap_or(u64::MAX);
        let bytes: Vec<u8> = decode_hex(fields[2]);
        assert!(!bytes.is_empty(), "{line}");
        let raw_header: String = format!("{} {} {} {}", fields[0], fields[1], fields[2], fields[3]);
        assert!(raw_headers.contains(&raw_header.as_str()), "{line}");
        let block: DecodedBlock = decode_block_for_language(language, &bytes, address);
        assert!(!block.instructions.is_empty(), "{line}");
        assert_eq!(block.instructions[0].mnemonic, fields[3], "{line}");
        let atomic_record: bool = matches!(fields[0], "riscv32a" | "riscv64a");
        let float_record: bool = matches!(fields[0], "riscv32fd" | "riscv64fd");
        let division_record: bool = matches!(fields[0], "riscv32" | "riscv64")
            && matches!(fields[3], "div" | "divu" | "rem" | "remu");
        let float_contract: bool =
            float_record && !matches!(fields[3], "flw" | "fsw" | "fld" | "fsd" | "fmv.w.x");
        let alignment_marker: bool =
            matches!(fields[0], "riscv32" | "riscv64") && matches!(fields[3], "jalr" | "ret");
        let expected_status: DecodeStatus = if atomic_record || alignment_marker || float_contract {
            DecodeStatus::CallOther
        } else {
            DecodeStatus::Supported
        };
        assert!(
            block
                .instructions
                .iter()
                .all(|instruction: &PcodeInstr| { instruction.status == expected_status }),
            "{line}: {:#?}",
            block.instructions
        );
        let joined: String = if division_record {
            riscv_division_core_facts(&block.instructions[0]).unwrap_or_default()
        } else {
            architectural_facts(&block.ordered_ops).join("|")
        };
        let actual: String = if joined.is_empty() {
            "none".to_owned()
        } else {
            joined
        };
        if atomic_record {
            assert_atomic_reference(&block.instructions[0], &bytes, fields[4]);
        } else {
            if alignment_marker {
                assert!(block.instructions[0].ops.iter().any(|op: &PcodeOp| {
                    matches!(
                        op,
                        PcodeOp::CallOther { name, .. }
                            if name == "riscv_instruction_address_alignment"
                    )
                }));
            }
            let compressed_indirect: bool =
                fields[0].ends_with('c') && matches!(fields[3], "jr" | "jalr");
            let powerpc_indirect: bool = matches!(fields[0], "powerpc32" | "powerpc64")
                && matches!(fields[3], "bclr" | "blr" | "bctr");
            let expected: String = if compressed_indirect {
                let corrected: Option<String> =
                    corrected_compressed_indirect_facts(fields[0], fields[3], fields[4]);
                assert!(corrected.is_some(), "{line}");
                corrected.unwrap_or_default()
            } else if powerpc_indirect {
                let corrected: Option<String> =
                    corrected_powerpc_indirect_facts(fields[0], fields[3], fields[4]);
                assert!(corrected.is_some(), "{line}");
                corrected.unwrap_or_default()
            } else if float_record {
                corrected_riscv_float_facts(fields[4])
            } else {
                fields[4].to_owned()
            };
            assert_eq!(actual, expected, "{line}");
        }
        checked = checked.saturating_add(1);
    }
    assert_eq!(checked, 265);
    assert_eq!(raw_headers.len(), checked);
}

fn assert_atomic_reference(instruction: &PcodeInstr, bytes: &[u8], pypcode_facts: &str) {
    let extracted: Option<(&String, &Option<Varnode>, &Vec<Varnode>)> =
        match instruction.ops.as_slice() {
            [
                PcodeOp::CallOther {
                    name,
                    output,
                    inputs,
                },
            ] => Some((name, output, inputs)),
            _ => None,
        };
    assert!(extracted.is_some(), "{instruction:#?}");
    let Some((name, output, inputs)): Option<(&String, &Option<Varnode>, &Vec<Varnode>)> =
        extracted
    else {
        return;
    };
    assert_eq!(name, "riscv_atomic_memory_v1");
    assert_eq!(inputs.len(), 6);
    assert_eq!(bytes.len(), 4, "{instruction:#?}");
    let encoded_result: Result<[u8; 4], std::array::TryFromSliceError> = <[u8; 4]>::try_from(bytes);
    assert!(encoded_result.is_ok(), "{instruction:#?}");
    let Ok(encoded_bytes): Result<[u8; 4], std::array::TryFromSliceError> = encoded_result else {
        return;
    };
    let encoded: u32 = u32::from_le_bytes(encoded_bytes);
    let operation_code: u64 = match instruction.mnemonic.split('.').next() {
        Some("lr") => 0,
        Some("sc") => 1,
        Some("amoswap") => 2,
        Some("amoadd") => 3,
        Some("amoand") => 4,
        Some("amoor") => 5,
        Some("amoxor") => 6,
        Some("amomin") => 7,
        Some("amomax") => 8,
        _ => u64::MAX,
    };
    assert_eq!(inputs[2].offset, operation_code);
    let access_size: u64 = if instruction.mnemonic.split('.').nth(1) == Some("d") {
        8
    } else {
        4
    };
    assert_eq!(inputs[3].offset, access_size);
    let ordering: Option<&str> = instruction.mnemonic.rsplit('.').next();
    let acquire: u64 = u64::from(matches!(ordering, Some("aq" | "aqrl")));
    let release: u64 = u64::from(matches!(ordering, Some("rl" | "aqrl")));
    assert_eq!(inputs[4].offset, acquire);
    assert_eq!(inputs[5].offset, release);
    let register_size: u32 = inputs[0].size_bytes;
    let source_address_index: u32 = (encoded >> 15) & 0x1f;
    let source_operand_index: u32 = (encoded >> 20) & 0x1f;
    let destination_index: u32 = (encoded >> 7) & 0x1f;
    assert_ne!(source_address_index, 0);
    assert_eq!(inputs[0].space, Space::Register);
    assert_eq!(
        inputs[0].offset,
        0x2000_u64 + u64::from(source_address_index) * u64::from(register_size)
    );
    if operation_code == 0 {
        assert_eq!(inputs[1].space, Space::Constant);
        assert_eq!(inputs[1].offset, 0);
    } else {
        assert_ne!(source_operand_index, 0);
        assert_eq!(inputs[1].space, Space::Register);
        assert_eq!(
            inputs[1].offset,
            0x2000_u64 + u64::from(source_operand_index) * u64::from(register_size)
        );
    }
    let address_fact: String =
        format!("register:0x{:x}:{}", inputs[0].offset, inputs[0].size_bytes);
    let load_fact: String = format!("load(ram,{address_fact},{access_size})");
    assert!(output.is_some(), "{instruction:#?}");
    let Some(output_node): Option<Varnode> = *output else {
        return;
    };
    assert_ne!(destination_index, 0);
    assert_eq!(output_node.space, Space::Register);
    assert_eq!(output_node.size_bytes, register_size);
    assert_eq!(
        output_node.offset,
        0x2000_u64 + u64::from(destination_index) * u64::from(register_size)
    );
    let output_fact: String = format!(
        "write(register:0x{:x}:{}",
        output_node.offset, output_node.size_bytes
    );
    assert!(pypcode_facts.contains(&output_fact), "{instruction:#?}");
    if operation_code == 0 {
        assert!(pypcode_facts.contains(&load_fact), "{instruction:#?}");
        assert!(!pypcode_facts.contains("store(ram,"), "{instruction:#?}");
    } else if operation_code == 1 {
        let operand_fact: String =
            format!("register:0x{:x}:{}", inputs[1].offset, inputs[1].size_bytes);
        let store_fact: String = format!("store(ram,{address_fact},{operand_fact})");
        assert!(pypcode_facts.contains("cbranch("), "{instruction:#?}");
        assert!(pypcode_facts.contains(&store_fact), "{instruction:#?}");
    } else {
        let operand_fact: String =
            format!("register:0x{:x}:{}", inputs[1].offset, inputs[1].size_bytes);
        assert!(pypcode_facts.contains(&operand_fact), "{instruction:#?}");
        assert!(pypcode_facts.contains(&load_fact), "{instruction:#?}");
        assert!(
            pypcode_facts.contains(&format!("store(ram,{address_fact},")),
            "{instruction:#?}"
        );
    }
}

fn riscv_division_core_facts(instruction: &PcodeInstr) -> Option<String> {
    if instruction.status != DecodeStatus::Supported
        || instruction.ops.iter().any(PcodeOp::is_callother)
    {
        return None;
    }
    let (left_snapshot, left_input): (Varnode, Varnode) = match instruction.ops.first()? {
        PcodeOp::Copy { output, input } => (*output, *input),
        _ => return None,
    };
    let (right_snapshot, right_input): (Varnode, Varnode) = match instruction.ops.get(1)? {
        PcodeOp::Copy { output, input } => (*output, *input),
        _ => return None,
    };
    let mut arithmetic: Option<(&str, Varnode)> = None;
    for operation in &instruction.ops {
        let candidate: Option<(&str, Varnode, Varnode, Varnode)> = match operation {
            PcodeOp::IntSignedDiv {
                output,
                left,
                right,
            } => Some(("sdiv", *output, *left, *right)),
            PcodeOp::IntDiv {
                output,
                left,
                right,
            } => Some(("udiv", *output, *left, *right)),
            PcodeOp::IntSignedRem {
                output,
                left,
                right,
            } => Some(("srem", *output, *left, *right)),
            PcodeOp::IntRem {
                output,
                left,
                right,
            } => Some(("urem", *output, *left, *right)),
            _ => None,
        };
        if let Some((name, output, left, right)) = candidate {
            if arithmetic.is_some() || left != left_snapshot || right == right_snapshot {
                return None;
            }
            arithmetic = Some((name, output));
        }
    }
    let (name, arithmetic_output): (&str, Varnode) = arithmetic?;
    if !instruction.ops.iter().any(|operation: &PcodeOp| {
        matches!(operation, PcodeOp::IntAnd { left, .. } if *left == arithmetic_output)
    }) {
        return None;
    }
    let destination: Varnode = match instruction.ops.last()? {
        PcodeOp::IntOr { output, .. } => *output,
        _ => return None,
    };
    Some(format!(
        "write({destination},{name}({left_input},{right_input}))"
    ))
}

fn corrected_compressed_indirect_facts(
    language: &str,
    mnemonic: &str,
    pypcode_facts: &str,
) -> Option<String> {
    let (mask, size): (&str, u32) = match language {
        "riscv32c" => ("0xfffffffe", 4),
        "riscv64c" => ("0xfffffffffffffffe", 8),
        _ => return None,
    };
    let operation: &str = match mnemonic {
        "jr" => "branchind(",
        "jalr" => "callind(",
        _ => return None,
    };
    let (prefix, target_with_close): (&str, &str) = pypcode_facts.rsplit_once(operation)?;
    let target: &str = target_with_close.strip_suffix(')')?;
    let corrected_operation: &str = if mnemonic == "jalr" {
        "branchind("
    } else {
        operation
    };
    Some(format!(
        "{prefix}{corrected_operation}and(const:{mask}:{size},{target}))"
    ))
}

fn corrected_powerpc_indirect_facts(
    language: &str,
    mnemonic: &str,
    pypcode_facts: &str,
) -> Option<String> {
    let (mask, size): (&str, u32) = match language {
        "powerpc32" => ("0xfffffffc", 4),
        "powerpc64" => ("0xfffffffffffffffc", 8),
        _ => return None,
    };
    let operation: &str = if mnemonic == "blr" {
        "return("
    } else {
        "branchind("
    };
    let (prefix, target_with_close): (&str, &str) = pypcode_facts.rsplit_once(operation)?;
    let target: &str = target_with_close.strip_suffix(')')?;
    Some(format!(
        "{prefix}{operation}and(const:{mask}:{size},{target}))"
    ))
}

fn corrected_riscv_float_facts(pypcode_facts: &str) -> String {
    pypcode_facts
        .split('|')
        .map(|fact: &str| {
            let floating_write: bool = fact
                .strip_prefix("write(register:0x")
                .and_then(|rest: &str| rest.split_once(':'))
                .and_then(|(offset, rest): (&str, &str)| {
                    let parsed: u64 = u64::from_str_radix(offset, 16).ok()?;
                    Some((0x3000..0x3100).contains(&parsed) && rest.starts_with("8,zext("))
                })
                .unwrap_or(false);
            if floating_write {
                fact.replacen(",zext(", ",piece(const:0xffffffff:4,", 1)
            } else {
                fact.to_owned()
            }
        })
        .collect::<Vec<String>>()
        .join("|")
}

#[test]
fn architectural_facts_preserve_effect_order() {
    let register: Varnode = Varnode {
        offset: 4,
        size_bytes: 4,
        space: Space::Register,
    };
    let value: Varnode = Varnode {
        offset: 1,
        size_bytes: 4,
        space: Space::Constant,
    };
    let target: Varnode = Varnode {
        offset: 0x1000,
        size_bytes: 4,
        space: Space::Ram,
    };
    let operations: [PcodeOp; 2] = [
        PcodeOp::Copy {
            output: register,
            input: value,
        },
        PcodeOp::Branch { target },
    ];
    let facts: Vec<String> = architectural_facts(&operations);
    assert!(facts[0].starts_with("write("), "{facts:?}");
    assert!(facts[1].starts_with("branch("), "{facts:?}");

    let reversed: [PcodeOp; 2] = [
        PcodeOp::Branch { target },
        PcodeOp::Copy {
            output: register,
            input: value,
        },
    ];
    let reversed_facts: Vec<String> = architectural_facts(&reversed);
    assert!(
        reversed_facts[0].starts_with("branch("),
        "{reversed_facts:?}"
    );
    assert!(
        reversed_facts[1].starts_with("write("),
        "{reversed_facts:?}"
    );
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .filter_map(|pair: &[u8]| {
            let text: &str = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

fn is_raw_header(line: &str) -> bool {
    let fields: Vec<&str> = line.split_whitespace().collect();
    fields.len() == 3
        && fields[0].len() == 4
        && fields[1].len() == 8
        && fields[0]
            .chars()
            .chain(fields[1].chars())
            .all(|character: char| character.is_ascii_hexdigit())
}

fn is_multiarch_raw_header(line: &str) -> bool {
    let fields: Vec<&str> = line.split_whitespace().collect();
    fields.len() == 4
        && matches!(
            fields[0],
            "arm32-a32"
                | "arm32-thumb"
                | "mips32le"
                | "mips32be"
                | "powerpc32"
                | "powerpc64"
                | "riscv32"
                | "riscv64"
                | "riscv32a"
                | "riscv64a"
                | "riscv32c"
                | "riscv64c"
                | "riscv32fd"
                | "riscv64fd"
        )
        && fields[1]
            .chars()
            .all(|character: char| character.is_ascii_hexdigit())
        && fields[2].len().is_multiple_of(2)
        && fields[2]
            .chars()
            .all(|character: char| character.is_ascii_hexdigit())
}

fn architectural_facts(operations: &[PcodeOp]) -> Vec<String> {
    let mut values: BTreeMap<Varnode, Expression> = BTreeMap::new();
    let mut facts: Vec<String> = Vec::new();
    let mut ordered_facts: Vec<String> = Vec::new();
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
                &mut facts,
            ),
            PcodeOp::BoolNegate { output, input } => {
                record_unary(*output, "boolnot", *input, &mut values, &mut facts);
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
                &mut facts,
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
                &mut facts,
            ),
            PcodeOp::Branch { target } => {
                push_ordered_fact(
                    format!("branch({})", resolve(*target, &values)),
                    &mut facts,
                    &mut ordered_facts,
                );
            }
            PcodeOp::BranchIndirect { target } => {
                push_ordered_fact(
                    format!("branchind({})", resolve(*target, &values)),
                    &mut facts,
                    &mut ordered_facts,
                );
            }
            PcodeOp::CBranch { target, condition } => push_ordered_fact(
                format!(
                    "cbranch({},{})",
                    resolve(*target, &values),
                    resolve(*condition, &values)
                ),
                &mut facts,
                &mut ordered_facts,
            ),
            PcodeOp::Call { target } => {
                push_ordered_fact(
                    format!("call({})", resolve(*target, &values)),
                    &mut facts,
                    &mut ordered_facts,
                );
            }
            PcodeOp::CallIndirect { target } => {
                push_ordered_fact(
                    format!("callind({})", resolve(*target, &values)),
                    &mut facts,
                    &mut ordered_facts,
                );
            }
            PcodeOp::CallOther {
                name,
                output: Some(output),
                inputs,
            } if matches!(
                name.as_str(),
                "riscv_fp_binary_v1"
                    | "riscv_fp_unary_v1"
                    | "riscv_fp_convert_v1"
                    | "riscv_fp_compare_v1"
            ) =>
            {
                let input: Option<Varnode> = inputs.last().copied();
                if let Some(value) = input {
                    let expression: Expression = resolve(value, &values);
                    record(*output, expression, &mut values, &mut facts);
                }
            }
            PcodeOp::CallOther { name, .. } if name == "riscv_instruction_address_alignment" => {}
            PcodeOp::CallOther { name, .. } => {
                push_ordered_fact(format!("callother({name})"), &mut facts, &mut ordered_facts);
            }
            PcodeOp::Copy { output, input } => {
                let expression: Expression = resolve(*input, &values);
                record(*output, expression, &mut values, &mut facts);
            }
            PcodeOp::FloatAdd {
                output,
                left,
                right,
            } => record_float_binary(
                *output,
                "fadd",
                *left,
                *right,
                true,
                &mut values,
                &mut facts,
            ),
            PcodeOp::FloatDiv {
                output,
                left,
                right,
            } => record_float_binary(
                *output,
                "fdiv",
                *left,
                *right,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::FloatEqual {
                output,
                left,
                right,
            } => record_float_binary(*output, "feq", *left, *right, true, &mut values, &mut facts),
            PcodeOp::FloatLess {
                output,
                left,
                right,
            } => record_float_binary(
                *output,
                "flt",
                *left,
                *right,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::FloatLessEqual {
                output,
                left,
                right,
            } => record_float_binary(
                *output,
                "fle",
                *left,
                *right,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::FloatMult {
                output,
                left,
                right,
            } => record_float_binary(
                *output,
                "fmul",
                *left,
                *right,
                true,
                &mut values,
                &mut facts,
            ),
            PcodeOp::FloatSqrt { output, input } => {
                record_float_unary(*output, "fsqrt", *input, &mut values, &mut facts);
            }
            PcodeOp::FloatSub {
                output,
                left,
                right,
            } => record_float_binary(
                *output,
                "fsub",
                *left,
                *right,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::FloatToFloat { output, input } => {
                record_float_unary(*output, "float2float", *input, &mut values, &mut facts);
            }
            PcodeOp::FloatTrunc { output, input } => {
                record_float_unary(*output, "trunc", *input, &mut values, &mut facts);
            }
            PcodeOp::IntToFloat { output, input } => {
                record_unary(*output, "int2float", *input, &mut values, &mut facts);
            }
            PcodeOp::IntAdd {
                output,
                left,
                right,
            } => {
                let left_expression: Expression = resolve(*left, &values);
                let right_expression: Expression = resolve(*right, &values);
                let expression: Expression = select_expression(&left_expression, &right_expression)
                    .unwrap_or_else(|| {
                        binary(
                            "add",
                            left_expression,
                            right_expression,
                            true,
                            output.size_bytes,
                        )
                    });
                record(*output, expression, &mut values, &mut facts);
            }
            PcodeOp::IntAnd {
                output,
                left,
                right,
            } => record_binary(*output, "and", *left, *right, true, &mut values, &mut facts),
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
                &mut facts,
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
                &mut facts,
            ),
            PcodeOp::IntEqual {
                output,
                left,
                right,
            } => record_binary(*output, "eq", *left, *right, true, &mut values, &mut facts),
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
                &mut facts,
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
                &mut facts,
            ),
            PcodeOp::IntLessEqual {
                output,
                left,
                right,
            } => record_less_equal(*output, "ult", *left, *right, &mut values, &mut facts),
            PcodeOp::IntMult {
                output,
                left,
                right,
            } => record_binary(*output, "mul", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntNegate { output, input } => {
                record_unary(*output, "not", *input, &mut values, &mut facts);
            }
            PcodeOp::IntNotEqual {
                output,
                left,
                right,
            } => record_binary(*output, "ne", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntOr {
                output,
                left,
                right,
            } => record_binary(*output, "or", *left, *right, true, &mut values, &mut facts),
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
                &mut facts,
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
                &mut facts,
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
                &mut facts,
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
                &mut facts,
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
                &mut facts,
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
                &mut facts,
            ),
            PcodeOp::IntSignedLessEqual {
                output,
                left,
                right,
            } => record_less_equal(*output, "slt", *left, *right, &mut values, &mut facts),
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
                &mut facts,
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
                &mut facts,
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
                &mut facts,
            ),
            PcodeOp::IntXor {
                output,
                left,
                right,
            } => record_binary(*output, "xor", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntSext { output, input } => {
                record_unary(*output, "sext", *input, &mut values, &mut facts);
            }
            PcodeOp::IntZext { output, input } => {
                record_unary(*output, "zext", *input, &mut values, &mut facts);
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
                record(*output, expression, &mut values, &mut facts);
            }
            PcodeOp::Piece { output, high, low } => record_binary(
                *output,
                "piece",
                *high,
                *low,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::Return { target } => {
                let rendered: String = target.map_or_else(
                    || "none".to_owned(),
                    |node: Varnode| resolve(node, &values).to_string(),
                );
                push_ordered_fact(
                    format!("return({rendered})"),
                    &mut facts,
                    &mut ordered_facts,
                );
            }
            PcodeOp::Store {
                space,
                pointer,
                value,
            } => facts.push(format!(
                "store({},{},{})",
                space,
                resolve(*pointer, &values),
                resolve(*value, &values)
            )),
            PcodeOp::Subpiece {
                output,
                input,
                byte_offset,
            } => record_binary(
                *output,
                "subpiece",
                *input,
                *byte_offset,
                false,
                &mut values,
                &mut facts,
            ),
        }
    }
    facts.sort();
    ordered_facts.append(&mut facts);
    ordered_facts
}

fn push_ordered_fact(fact: String, pending: &mut Vec<String>, ordered: &mut Vec<String>) {
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

fn record_float_binary(
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
        resolve_float_input(left, values),
        resolve_float_input(right, values),
        commutative,
        output.size_bytes,
    );
    record(output, expression, values, facts);
}

fn record_float_unary(
    output: Varnode,
    name: &'static str,
    input: Varnode,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let expression: Expression = Expression::Unary {
        input: Box::new(resolve_float_input(input, values)),
        name,
    };
    record(output, expression, values, facts);
}

fn resolve_float_input(node: Varnode, values: &BTreeMap<Varnode, Expression>) -> Expression {
    let resolved: Expression = resolve(node, values);
    let selected: Expression = match resolved {
        Expression::Select { when_true, .. } => *when_true,
        other => other,
    };
    match selected {
        Expression::Binary {
            name: "subpiece",
            left,
            right,
        } if matches!(right.as_ref(), Expression::Node(offset)
            if offset.space == Space::Constant && offset.offset == 0) =>
        {
            match *left {
                Expression::Node(register) if register.space == Space::Register => {
                    Expression::Node(Varnode {
                        offset: register.offset,
                        size_bytes: node.size_bytes,
                        space: Space::Register,
                    })
                }
                other => Expression::Binary {
                    name: "subpiece",
                    left: Box::new(other),
                    right,
                },
            }
        }
        other => other,
    }
}

fn record_unary(
    output: Varnode,
    name: &'static str,
    input: Varnode,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let resolved: Expression = resolve(input, values);
    let expression: Expression = match (&resolved, name) {
        (Expression::Node(node), "zext") if node.space == Space::Constant => {
            Expression::Node(Varnode {
                offset: node.offset,
                size_bytes: output.size_bytes,
                space: Space::Constant,
            })
        }
        _ => Expression::Unary {
            input: Box::new(resolved),
            name,
        },
    };
    record(output, expression, values, facts);
}

fn record_less_equal(
    output: Varnode,
    comparison_name: &'static str,
    left: Varnode,
    right: Varnode,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let comparison: Expression = binary(
        comparison_name,
        resolve(right, values),
        resolve(left, values),
        false,
        output.size_bytes,
    );
    let expression: Expression = Expression::Unary {
        input: Box::new(comparison),
        name: "boolnot",
    };
    record(output, expression, values, facts);
}

fn record(
    output: Varnode,
    expression: Expression,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let previous: Option<Expression> = values.insert(output, expression.clone());
    drop(previous);
    if output.space == Space::Register {
        let prefix: String = format!("write({output},");
        facts.retain(|fact: &String| !fact.starts_with(&prefix));
        facts.push(format!("{prefix}{expression})"));
    }
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
    let Some(first) = iterator.next() else {
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
            let bit_width: u32 = output_size.saturating_mul(8);
            let mask: u64 = if bit_width >= 64 {
                u64::MAX
            } else {
                1_u64.checked_shl(bit_width).unwrap_or(0).saturating_sub(1)
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

fn select_expression(left: &Expression, right: &Expression) -> Option<Expression> {
    select_order(left, right).or_else(|| select_order(right, left))
}

fn select_order(true_term: &Expression, false_term: &Expression) -> Option<Expression> {
    let (condition, when_true): (&Expression, &Expression) = select_term(true_term, false)?;
    let (inverted, when_false): (&Expression, &Expression) = select_term(false_term, true)?;
    if condition != inverted {
        return None;
    }
    Some(Expression::Select {
        condition: Box::new(condition.clone()),
        when_false: Box::new(when_false.clone()),
        when_true: Box::new(when_true.clone()),
    })
}

fn select_term(expression: &Expression, inverted: bool) -> Option<(&Expression, &Expression)> {
    let Expression::Binary {
        name: "mul",
        left,
        right,
    } = expression
    else {
        return None;
    };
    select_factor(left, right, inverted).or_else(|| select_factor(right, left, inverted))
}

fn select_factor<'a>(
    mask: &'a Expression,
    value: &'a Expression,
    inverted: bool,
) -> Option<(&'a Expression, &'a Expression)> {
    let Expression::Unary {
        input,
        name: "zext",
    } = mask
    else {
        return None;
    };
    if !inverted {
        return Some((input, value));
    }
    let Expression::Unary {
        input: condition,
        name: "boolnot",
    } = input.as_ref()
    else {
        return None;
    };
    Some((condition, value))
}
