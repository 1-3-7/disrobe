use std::collections::BTreeMap;

use disrobe_nir::{NirBlock, NirClass, NirFunction, NirInstr, NirOp, ValueOp, basic_blocks};

const IMMORTAL_GUARD_CONST: &str = "0xbfffffff";
const ZERO_CONST: &str = "0x0";
const ONE_CONST: &str = "0x1";
const REFCOUNT_FIELD_SIZE: u32 = 4;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DiamondReport {
    pub(crate) inspected: usize,
    pub(crate) collapsed: usize,
}

type ValueDefs = BTreeMap<String, (ValueOp, Vec<String>)>;

pub(crate) fn collapse_refcount_diamonds(nir: &NirFunction) -> (NirFunction, DiamondReport) {
    let blocks: Vec<NirBlock> = basic_blocks(nir);
    let by_start: BTreeMap<u64, &NirBlock> = blocks
        .iter()
        .map(|block: &NirBlock| (block.start, block))
        .collect();
    let mut guard_addresses: Vec<u64> = Vec::new();
    let mut report: DiamondReport = DiamondReport::default();
    for block in &blocks {
        let Some(branch): Option<&NirInstr> = block.instructions.last() else {
            continue;
        };
        if !matches!(branch.op, NirOp::CondBranch { .. }) {
            continue;
        }
        report.inspected = report.inspected.saturating_add(1);
        if is_incref_guard(block, branch, &by_start) {
            guard_addresses.push(branch.address);
        }
    }

    let mut out: NirFunction = nir.clone();
    for instruction in &mut out.instructions {
        if matches!(instruction.op, NirOp::CondBranch { .. })
            && guard_addresses.contains(&instruction.address)
        {
            instruction.op = NirOp::Nop;
            instruction.operands.clear();
            "nop".clone_into(&mut instruction.mnemonic);
            report.collapsed = report.collapsed.saturating_add(1);
        }
    }
    (out, report)
}

fn is_incref_guard(
    guard: &NirBlock,
    branch: &NirInstr,
    by_start: &BTreeMap<u64, &NirBlock>,
) -> bool {
    let Some(predicate): Option<&String> = branch.operands.first() else {
        return false;
    };
    let Some(taken): Option<u64> = branch.direct_target() else {
        return false;
    };
    let defs: ValueDefs = value_defs(guard);
    if !matches_immortal_chain(predicate, &defs) {
        return false;
    }
    if !guard
        .instructions
        .iter()
        .any(|instruction: &NirInstr| is_refcount_load(instruction))
    {
        return false;
    }
    let Some(fallthrough): Option<u64> = guard
        .successors
        .iter()
        .copied()
        .find(|successor: &u64| *successor != taken)
    else {
        return false;
    };
    let Some(fast): Option<&&NirBlock> = by_start.get(&fallthrough) else {
        return false;
    };
    is_incref_fast_block(fast, taken)
}

fn value_defs(block: &NirBlock) -> ValueDefs {
    let mut defs: ValueDefs = BTreeMap::new();
    for instruction in &block.instructions {
        if let NirOp::Value { op, inputs, .. } = &instruction.op
            && let Some(dest) = instruction.operands.first()
        {
            defs.insert(dest.clone(), (*op, inputs.clone()));
        }
    }
    defs
}

fn value_def<'a>(defs: &'a ValueDefs, name: &str) -> Option<(ValueOp, &'a [String])> {
    defs.get(name)
        .map(|(op, inputs): &(ValueOp, Vec<String>)| (*op, inputs.as_slice()))
}

fn matches_immortal_chain(predicate: &str, defs: &ValueDefs) -> bool {
    let Some((ValueOp::BoolNegate, negate_inputs)): Option<(ValueOp, &[String])> =
        value_def(defs, predicate)
    else {
        return false;
    };
    let Some(disjunction): Option<&String> = negate_inputs.first() else {
        return false;
    };
    let Some((ValueOp::BoolOr, or_inputs)): Option<(ValueOp, &[String])> =
        value_def(defs, disjunction)
    else {
        return false;
    };
    let (Some(left), Some(right)): (Option<&String>, Option<&String>) =
        (or_inputs.first(), or_inputs.get(1))
    else {
        return false;
    };
    (is_unsigned_below_guard(left, defs) && is_equal_boundary_guard(right, defs))
        || (is_unsigned_below_guard(right, defs) && is_equal_boundary_guard(left, defs))
}

fn is_unsigned_below_guard(name: &str, defs: &ValueDefs) -> bool {
    matches!(
        value_def(defs, name),
        Some((ValueOp::IntLess, inputs))
            if inputs.get(1).map(String::as_str) == Some(IMMORTAL_GUARD_CONST)
    )
}

fn is_equal_boundary_guard(name: &str, defs: &ValueDefs) -> bool {
    let Some((ValueOp::IntEqual, equal_inputs)): Option<(ValueOp, &[String])> =
        value_def(defs, name)
    else {
        return false;
    };
    if equal_inputs.get(1).map(String::as_str) != Some(ZERO_CONST) {
        return false;
    }
    let Some(difference): Option<&String> = equal_inputs.first() else {
        return false;
    };
    matches!(
        value_def(defs, difference),
        Some((ValueOp::IntSub, inputs))
            if inputs.get(1).map(String::as_str) == Some(IMMORTAL_GUARD_CONST)
    )
}

const fn is_refcount_load(instruction: &NirInstr) -> bool {
    matches!(&instruction.op, NirOp::RawLoad { size, .. } if *size == REFCOUNT_FIELD_SIZE)
}

fn is_incref_fast_block(fast: &NirBlock, join: u64) -> bool {
    if fast.successors.as_slice() != [join] {
        return false;
    }
    let mut increments: bool = false;
    let mut stores_refcount: bool = false;
    let count: usize = fast.instructions.len();
    for (index, instruction) in fast.instructions.iter().enumerate() {
        let is_last: bool = index + 1 == count;
        match instruction.class() {
            NirClass::Call | NirClass::Return | NirClass::ConditionalJump => return false,
            NirClass::UnconditionalJump => {
                if !is_last || instruction.direct_target() != Some(join) {
                    return false;
                }
            }
            NirClass::Other => {
                if is_increment_by_one(instruction) {
                    increments = true;
                }
                if matches!(&instruction.op, NirOp::RawStore { size, .. } if *size == REFCOUNT_FIELD_SIZE)
                {
                    stores_refcount = true;
                }
            }
        }
    }
    increments && stores_refcount
}

fn is_increment_by_one(instruction: &NirInstr) -> bool {
    matches!(
        &instruction.op,
        NirOp::Value { op: ValueOp::IntAdd, inputs, .. }
            if inputs.get(1).map(String::as_str) == Some(ONE_CONST)
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::vec_init_then_push
)]
mod tests {
    use disrobe_nir::{SourceLang, SourceRef};

    use super::*;

    fn instr(address: u64, op: NirOp, operands: &[&str]) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: String::new(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn value(address: u64, dest: &str, op: ValueOp, inputs: &[&str]) -> NirInstr {
        let mut operands: Vec<&str> = vec![dest];
        operands.extend_from_slice(inputs);
        instr(
            address,
            NirOp::Value {
                op,
                inputs: inputs.iter().map(|s: &&str| (*s).to_owned()).collect(),
                input_sizes: inputs.iter().map(|_| 4_u32).collect(),
                size: 4,
            },
            &operands,
        )
    }

    fn raw_load(address: u64, dest: &str, addr: &str, size: u32) -> NirInstr {
        instr(
            address,
            NirOp::RawLoad {
                addr: addr.to_owned(),
                size,
            },
            &[dest, addr],
        )
    }

    fn raw_store(address: u64, addr: &str, val: &str, size: u32) -> NirInstr {
        instr(
            address,
            NirOp::RawStore {
                addr: addr.to_owned(),
                value: val.to_owned(),
                size,
            },
            &[addr, val],
        )
    }

    fn cond(address: u64, target: u64, flag: &str) -> NirInstr {
        instr(
            address,
            NirOp::CondBranch {
                target: Some(target),
            },
            &[flag],
        )
    }

    fn incref_body(join: u64) -> NirFunction {
        let mut instructions: Vec<NirInstr> = Vec::new();
        instructions.push(raw_load(0x00, "q", "rsi", REFCOUNT_FIELD_SIZE));
        instructions.push(value(
            0x02,
            "sub",
            ValueOp::IntSub,
            &["q", IMMORTAL_GUARD_CONST],
        ));
        instructions.push(value(
            0x02,
            "cf",
            ValueOp::IntLess,
            &["q", IMMORTAL_GUARD_CONST],
        ));
        instructions.push(value(0x02, "zf", ValueOp::IntEqual, &["sub", ZERO_CONST]));
        instructions.push(value(0x08, "orv", ValueOp::BoolOr, &["cf", "zf"]));
        instructions.push(value(0x08, "neg", ValueOp::BoolNegate, &["orv"]));
        instructions.push(cond(0x08, join, "neg"));
        instructions.push(value(0x0e, "inc", ValueOp::IntAdd, &["q", ONE_CONST]));
        instructions.push(raw_store(0x10, "rsi", "inc", REFCOUNT_FIELD_SIZE));
        instructions.push(raw_load(join, "after", "rsi", 8));
        instructions.push(instr(join + 2, NirOp::Return, &["after"]));
        NirFunction {
            name: "f".to_owned(),
            address: 0,
            end: join + 4,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        }
    }

    #[test]
    fn incref_guard_is_collapsed_to_straight_line() {
        let function: NirFunction = incref_body(0x14);
        let before: usize = basic_blocks(&function).len();
        let (out, report): (NirFunction, DiamondReport) = collapse_refcount_diamonds(&function);
        assert_eq!(report.collapsed, 1, "the single incref guard collapses");
        assert!(
            !out.instructions
                .iter()
                .any(|i: &NirInstr| matches!(i.op, NirOp::CondBranch { .. })),
            "the guard branch is neutralized"
        );
        let after: usize = basic_blocks(&out).len();
        assert!(
            after < before,
            "collapsing removes at least one block boundary"
        );
    }

    #[test]
    fn decref_shaped_guard_is_left_intact() {
        let mut instructions: Vec<NirInstr> = Vec::new();
        instructions.push(raw_load(0x00, "q", "rcx", REFCOUNT_FIELD_SIZE));
        instructions.push(value(0x04, "and", ValueOp::IntAnd, &["q", "q"]));
        instructions.push(value(
            0x04,
            "sf",
            ValueOp::IntSignedLess,
            &["and", ZERO_CONST],
        ));
        instructions.push(cond(0x06, 0x20, "sf"));
        instructions.push(value(0x08, "dec", ValueOp::IntSub, &["q", ONE_CONST]));
        instructions.push(raw_store(0x0a, "rcx", "dec", REFCOUNT_FIELD_SIZE));
        instructions.push(instr(0x20, NirOp::Return, &["q"]));
        let function: NirFunction = NirFunction {
            name: "decref".to_owned(),
            address: 0,
            end: 0x24,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let (out, report): (NirFunction, DiamondReport) = collapse_refcount_diamonds(&function);
        assert_eq!(
            report.collapsed, 0,
            "a signed-immortality decref guard is not collapsed"
        );
        assert!(
            out.instructions
                .iter()
                .any(|i: &NirInstr| matches!(i.op, NirOp::CondBranch { .. })),
            "the decref branch survives"
        );
    }

    #[test]
    fn arithmetic_branch_is_left_intact() {
        let mut instructions: Vec<NirInstr> = Vec::new();
        instructions.push(value(0x00, "eq", ValueOp::IntEqual, &["rsi", ZERO_CONST]));
        instructions.push(cond(0x04, 0x10, "eq"));
        instructions.push(instr(0x08, NirOp::Return, &["rsi"]));
        instructions.push(instr(0x10, NirOp::Return, &["rsi"]));
        let function: NirFunction = NirFunction {
            name: "plain".to_owned(),
            address: 0,
            end: 0x14,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let (_, report): (NirFunction, DiamondReport) = collapse_refcount_diamonds(&function);
        assert_eq!(
            report.collapsed, 0,
            "a plain null-check branch is not a refcount guard"
        );
    }

    #[test]
    fn straight_line_function_is_unchanged() {
        let function: NirFunction = NirFunction {
            name: "s".to_owned(),
            address: 0,
            end: 0x4,
            is_export: false,
            instructions: vec![
                value(0x00, "t", ValueOp::IntAdd, &["rcx", "rdx"]),
                instr(0x02, NirOp::Return, &["t"]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let (out, report): (NirFunction, DiamondReport) = collapse_refcount_diamonds(&function);
        assert_eq!(report.collapsed, 0);
        assert_eq!(out.instructions, function.instructions);
    }
}
