use std::collections::BTreeMap;

use disrobe_py_marshal::{CodeObject, PyVersion as MarshalVersion};

use disrobe_pass_py_disasm::{Instruction, disassemble};

use crate::bytecode::flow::{ExceptionTableEntry, parse_exception_table};
use crate::bytecode::version::PyVersion as DecompileVersion;

const PUSH_EXC_INFO: &str = "PUSH_EXC_INFO";

#[derive(Debug, Clone)]
pub(crate) struct InputFacts {
    pub(crate) handler_order: Option<Vec<usize>>,
    pub(crate) loop_inner_return: bool,
}

#[must_use]
pub(crate) fn extract(code: &CodeObject, version: &DecompileVersion) -> InputFacts {
    let marshal: MarshalVersion = MarshalVersion {
        major: version.major(),
        minor: version.minor(),
    };
    let instructions: Vec<Instruction> = disassemble(code, marshal);
    let offset_to_index: BTreeMap<usize, usize> = build_offset_index(&instructions);
    let handler_order: Option<Vec<usize>> =
        except_handler_order(code, &instructions, &offset_to_index);
    let loop_inner_return: bool = loop_body_has_return(&instructions, marshal);
    InputFacts {
        handler_order,
        loop_inner_return,
    }
}

#[must_use]
fn build_offset_index(instructions: &[Instruction]) -> BTreeMap<usize, usize> {
    let mut map: BTreeMap<usize, usize> = BTreeMap::new();
    for (idx, ins) in instructions.iter().enumerate() {
        map.entry(ins.offset).or_insert(idx);
    }
    map
}

#[must_use]
fn except_handler_order(
    code: &CodeObject,
    instructions: &[Instruction],
    offset_to_index: &BTreeMap<usize, usize>,
) -> Option<Vec<usize>> {
    if code.exceptiontable.is_empty() {
        return Some(Vec::new());
    }
    let entries: Vec<ExceptionTableEntry> = parse_exception_table(&code.exceptiontable).ok()?;
    let mut bodies: Vec<(u32, u32)> = Vec::new();
    for entry in &entries {
        if entry.lasti {
            continue;
        }
        let handler_idx: usize = *offset_to_index.get(&(entry.target as usize))?;
        let handler_op: &str = instructions.get(handler_idx)?.opname.as_str();
        if handler_op != PUSH_EXC_INFO {
            return None;
        }
        bodies.push((entry.start, entry.target));
    }
    if bodies.is_empty() {
        return Some(Vec::new());
    }
    let mut by_start: Vec<usize> = (0..bodies.len()).collect();
    by_start.sort_by_key(|&i: &usize| bodies[i].0);
    let mut source_id: BTreeMap<usize, usize> = BTreeMap::new();
    for (rank, &region) in by_start.iter().enumerate() {
        source_id.insert(region, rank);
    }
    let mut by_handler: Vec<usize> = (0..bodies.len()).collect();
    by_handler.sort_by_key(|&i: &usize| bodies[i].1);
    let order: Vec<usize> = by_handler
        .into_iter()
        .map(|region: usize| source_id[&region])
        .collect();
    Some(order)
}

#[must_use]
fn loop_body_has_return(instructions: &[Instruction], version: MarshalVersion) -> bool {
    let wordcode: bool = version.is_wordcode();
    let return_offsets: Vec<usize> = instructions
        .iter()
        .filter(|ins: &&Instruction| is_return_op(ins.opname.as_str()))
        .map(|ins: &Instruction| ins.offset)
        .collect();
    if return_offsets.is_empty() {
        return false;
    }
    let mut primary_edge: BTreeMap<usize, usize> = BTreeMap::new();
    for ins in instructions {
        if !is_backward_jump(ins.opname.as_str()) {
            continue;
        }
        let Some(arg): Option<u32> = ins.arg else {
            continue;
        };
        let Some(target): Option<usize> = backward_target(ins.offset, arg, wordcode) else {
            continue;
        };
        primary_edge
            .entry(target)
            .and_modify(|edge: &mut usize| *edge = (*edge).min(ins.offset))
            .or_insert(ins.offset);
    }
    primary_edge
        .iter()
        .any(|(&header, &edge): (&usize, &usize)| {
            return_offsets
                .iter()
                .any(|&r: &usize| r > header && r < edge)
        })
}

#[must_use]
const fn is_return_op(name: &str) -> bool {
    matches!(name.as_bytes(), b"RETURN_VALUE" | b"RETURN_CONST")
}

#[must_use]
const fn is_backward_jump(name: &str) -> bool {
    matches!(
        name.as_bytes(),
        b"JUMP_BACKWARD" | b"JUMP_BACKWARD_QUICK" | b"JUMP_BACKWARD_NO_INTERRUPT"
    )
}

#[must_use]
fn backward_target(source_offset: usize, arg: u32, wordcode: bool) -> Option<usize> {
    let step: usize = if wordcode { 2 } else { 3 };
    let arg_bytes: usize = if wordcode {
        (arg as usize).checked_mul(2)?
    } else {
        arg as usize
    };
    let base: usize = source_offset.checked_add(step)?;
    base.checked_sub(arg_bytes)
}
