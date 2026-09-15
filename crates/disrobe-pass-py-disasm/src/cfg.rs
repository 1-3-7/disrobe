use crate::Instruction;
use disrobe_py_marshal::PyVersion;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const BYTECODE_UNIT_BYTES: usize = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BlockId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum EdgeKind {
    Fallthrough,
    Branch,
    Conditional,
    Backward,
    ExceptionCleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum TerminatorKind {
    Return,
    ReturnConst,
    Raise,
    Reraise,
    Jump,
    JumpBackward,
    ConditionalJump,
    Throw,
    Resume,
    Yield,
    Fallthrough,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Block {
    pub id: BlockId,
    pub start_offset: usize,
    pub end_offset: usize,
    pub instruction_count: u32,
    pub terminator: Option<TerminatorKind>,
    pub successors: Vec<(BlockId, EdgeKind)>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Cfg {
    pub entry: BlockId,
    pub blocks: Vec<Block>,
    pub offset_to_block: BTreeMap<usize, BlockId>,
}

#[must_use]
pub fn build_cfg(instructions: &[Instruction], version: PyVersion) -> Cfg {
    if instructions.is_empty() {
        return Cfg::default();
    }
    let offset_to_index: BTreeMap<usize, usize> = index_offsets(instructions);
    let leaders: BTreeSet<usize> = compute_leaders(instructions, version, &offset_to_index);
    let block_ranges: Vec<(usize, usize)> = build_block_ranges(instructions, &leaders);
    let offset_to_block: BTreeMap<usize, BlockId> = block_first_offset(instructions, &block_ranges);
    let blocks: Vec<Block> = build_blocks(instructions, version, &block_ranges, &offset_to_block);
    Cfg {
        entry: BlockId(0),
        blocks,
        offset_to_block,
    }
}

fn index_offsets(instructions: &[Instruction]) -> BTreeMap<usize, usize> {
    let mut out: BTreeMap<usize, usize> = BTreeMap::new();
    for (i, ins) in instructions.iter().enumerate() {
        out.insert(ins.offset, i);
    }
    out
}

fn compute_leaders(
    instructions: &[Instruction],
    version: PyVersion,
    offset_to_index: &BTreeMap<usize, usize>,
) -> BTreeSet<usize> {
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    let Some(first): Option<&Instruction> = instructions.first() else {
        return leaders;
    };
    leaders.insert(first.offset);
    for (idx, ins) in instructions.iter().enumerate() {
        let class: JumpClass = classify(&ins.opname, version);
        if matches!(class, JumpClass::None) {
            continue;
        }
        if let Some(target) = resolve_target(ins, class, instructions, offset_to_index) {
            leaders.insert(target);
        }
        if class_introduces_leader(class)
            && let Some(next) = instructions.get(idx + 1)
        {
            leaders.insert(next.offset);
        }
    }
    leaders
}

const fn class_introduces_leader(class: JumpClass) -> bool {
    matches!(
        class,
        JumpClass::ConditionalForward
            | JumpClass::ConditionalBackward
            | JumpClass::UnconditionalForward
            | JumpClass::UnconditionalBackward
            | JumpClass::AbsoluteJump
            | JumpClass::Terminator
    )
}

fn build_block_ranges(
    instructions: &[Instruction],
    leaders: &BTreeSet<usize>,
) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(leaders.len());
    let mut current_start: Option<usize> = None;
    for (idx, ins) in instructions.iter().enumerate() {
        let is_leader: bool = leaders.contains(&ins.offset);
        match (current_start, is_leader) {
            (Some(start), true) if start != idx => {
                ranges.push((start, idx));
                current_start = Some(idx);
            }
            (None, _) => {
                current_start = Some(idx);
            }
            _ => {}
        }
    }
    if let Some(start) = current_start {
        ranges.push((start, instructions.len()));
    }
    ranges
}

fn block_first_offset(
    instructions: &[Instruction],
    ranges: &[(usize, usize)],
) -> BTreeMap<usize, BlockId> {
    let mut out: BTreeMap<usize, BlockId> = BTreeMap::new();
    for (block_idx, &(start, _end)) in ranges.iter().enumerate() {
        let offset: usize = instructions[start].offset;
        let id: BlockId = BlockId(u32::try_from(block_idx).unwrap_or(u32::MAX));
        out.insert(offset, id);
    }
    out
}

fn build_blocks(
    instructions: &[Instruction],
    version: PyVersion,
    ranges: &[(usize, usize)],
    offset_to_block: &BTreeMap<usize, BlockId>,
) -> Vec<Block> {
    let offset_to_index: BTreeMap<usize, usize> = index_offsets(instructions);
    let mut blocks: Vec<Block> = Vec::with_capacity(ranges.len());
    for (block_idx, &(start, end)) in ranges.iter().enumerate() {
        let id: BlockId = BlockId(u32::try_from(block_idx).unwrap_or(u32::MAX));
        let first: &Instruction = &instructions[start];
        let last: &Instruction = &instructions[end - 1];
        let class: JumpClass = classify(&last.opname, version);
        let terminator: Option<TerminatorKind> = terminator_for(class, &last.opname);
        let mut successors: Vec<(BlockId, EdgeKind)> = Vec::with_capacity(2);
        if let Some(target_off) = resolve_target(last, class, instructions, &offset_to_index)
            && let Some(&succ) = offset_to_block.get(&target_off)
        {
            successors.push((succ, jump_edge_kind(class)));
        }
        if has_fallthrough(class)
            && end < instructions.len()
            && let Some(&succ) = offset_to_block.get(&instructions[end].offset)
        {
            successors.push((succ, fallthrough_edge_kind(class)));
        }
        blocks.push(Block {
            id,
            start_offset: first.offset,
            end_offset: last.offset,
            instruction_count: u32::try_from(end - start).unwrap_or(u32::MAX),
            terminator,
            successors,
        });
    }
    blocks
}

const fn jump_edge_kind(class: JumpClass) -> EdgeKind {
    match class {
        JumpClass::UnconditionalBackward | JumpClass::ConditionalBackward => EdgeKind::Backward,
        JumpClass::ConditionalForward => EdgeKind::Conditional,
        _ => EdgeKind::Branch,
    }
}

const fn fallthrough_edge_kind(class: JumpClass) -> EdgeKind {
    match class {
        JumpClass::ConditionalForward | JumpClass::ConditionalBackward => EdgeKind::Conditional,
        _ => EdgeKind::Fallthrough,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JumpClass {
    None,
    UnconditionalForward,
    UnconditionalBackward,
    ConditionalForward,
    ConditionalBackward,
    AbsoluteJump,
    Terminator,
}

fn classify(name: &str, _version: PyVersion) -> JumpClass {
    match name {
        "RETURN_VALUE" | "RETURN_CONST" | "RAISE_VARARGS" | "RERAISE" | "INTERPRETER_EXIT" => {
            JumpClass::Terminator
        }
        "JUMP_FORWARD" => JumpClass::UnconditionalForward,
        "JUMP_BACKWARD" | "JUMP_BACKWARD_NO_INTERRUPT" => JumpClass::UnconditionalBackward,
        "JUMP_ABSOLUTE" => JumpClass::AbsoluteJump,
        "POP_JUMP_FORWARD_IF_TRUE"
        | "POP_JUMP_FORWARD_IF_FALSE"
        | "POP_JUMP_FORWARD_IF_NONE"
        | "POP_JUMP_FORWARD_IF_NOT_NONE"
        | "POP_JUMP_IF_TRUE"
        | "POP_JUMP_IF_FALSE"
        | "POP_JUMP_IF_NONE"
        | "POP_JUMP_IF_NOT_NONE"
        | "JUMP_IF_TRUE_OR_POP"
        | "JUMP_IF_FALSE_OR_POP"
        | "FOR_ITER" => JumpClass::ConditionalForward,
        "POP_JUMP_BACKWARD_IF_TRUE"
        | "POP_JUMP_BACKWARD_IF_FALSE"
        | "POP_JUMP_BACKWARD_IF_NONE"
        | "POP_JUMP_BACKWARD_IF_NOT_NONE" => JumpClass::ConditionalBackward,
        _ => JumpClass::None,
    }
}

fn terminator_for(class: JumpClass, name: &str) -> Option<TerminatorKind> {
    match (class, name) {
        (JumpClass::Terminator, "RETURN_CONST") => Some(TerminatorKind::ReturnConst),
        (JumpClass::Terminator, "RAISE_VARARGS") => Some(TerminatorKind::Raise),
        (JumpClass::Terminator, "RERAISE") => Some(TerminatorKind::Reraise),
        (JumpClass::Terminator, _) => Some(TerminatorKind::Return),
        (JumpClass::UnconditionalForward | JumpClass::AbsoluteJump, _) => {
            Some(TerminatorKind::Jump)
        }
        (JumpClass::UnconditionalBackward, _) => Some(TerminatorKind::JumpBackward),
        (JumpClass::ConditionalForward | JumpClass::ConditionalBackward, _) => {
            Some(TerminatorKind::ConditionalJump)
        }
        (JumpClass::None, "YIELD_VALUE") => Some(TerminatorKind::Yield),
        (JumpClass::None, "RESUME") => Some(TerminatorKind::Resume),
        (JumpClass::None, "THROW") => Some(TerminatorKind::Throw),
        (JumpClass::None, _) => None,
    }
}

const fn has_fallthrough(class: JumpClass) -> bool {
    !matches!(
        class,
        JumpClass::Terminator
            | JumpClass::UnconditionalForward
            | JumpClass::UnconditionalBackward
            | JumpClass::AbsoluteJump
    )
}

fn resolve_target(
    ins: &Instruction,
    class: JumpClass,
    instructions: &[Instruction],
    offset_to_index: &BTreeMap<usize, usize>,
) -> Option<usize> {
    if matches!(class, JumpClass::None | JumpClass::Terminator) {
        return None;
    }
    let arg: u32 = ins.arg?;
    let arg_units: usize = arg as usize;
    let delta: usize = arg_units.checked_mul(BYTECODE_UNIT_BYTES)?;
    let next_offset: usize = next_offset_of(ins, instructions, offset_to_index)?;
    match class {
        JumpClass::UnconditionalForward | JumpClass::ConditionalForward => {
            next_offset.checked_add(delta)
        }
        JumpClass::UnconditionalBackward | JumpClass::ConditionalBackward => {
            next_offset.checked_sub(delta)
        }
        JumpClass::AbsoluteJump => Some(delta),
        JumpClass::None | JumpClass::Terminator => None,
    }
}

fn next_offset_of(
    ins: &Instruction,
    instructions: &[Instruction],
    offset_to_index: &BTreeMap<usize, usize>,
) -> Option<usize> {
    if let Some(&idx) = offset_to_index.get(&ins.offset)
        && let Some(next) = instructions.get(idx + 1)
    {
        return Some(next.offset);
    }
    ins.offset.checked_add(BYTECODE_UNIT_BYTES)
}

#[must_use]
pub fn render_dot(cfg: &Cfg) -> String {
    let mut out: String = String::with_capacity(cfg.blocks.len() * 64);
    out.push_str("digraph cfg {\n  rankdir=TB;\n  node [shape=box,fontname=monospace];\n");
    for block in &cfg.blocks {
        let term: String = block
            .terminator
            .map_or_else(|| "fall".to_owned(), |t| format!("{t:?}"));
        crate::push_string_fmt(
            &mut out,
            format_args!(
                "  b{} [label=\"b{}\\n0x{:x}..0x{:x}\\n{} ins\\n{}\"];\n",
                block.id.0,
                block.id.0,
                block.start_offset,
                block.end_offset,
                block.instruction_count,
                term
            ),
        );
        for (succ, kind) in &block.successors {
            let style: &'static str = match kind {
                EdgeKind::Fallthrough => "style=solid",
                EdgeKind::Conditional => "style=dashed,color=blue",
                EdgeKind::Backward => "style=solid,color=red",
                EdgeKind::Branch => "style=solid,color=darkgreen",
                EdgeKind::ExceptionCleanup => "style=dotted,color=orange",
            };
            crate::push_string_fmt(
                &mut out,
                format_args!("  b{} -> b{} [{}];\n", block.id.0, succ.0, style),
            );
        }
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::Instruction;

    fn ins(offset: usize, name: &str, arg: Option<u32>) -> Instruction {
        Instruction {
            offset,
            opcode: 0,
            opname: name.to_owned(),
            arg,
            argrepr: None,
            line: None,
            is_jump_target: false,
        }
    }

    #[test]
    fn empty_program_yields_empty_cfg() {
        let cfg: Cfg = build_cfg(&[], PyVersion::PY312);
        assert!(cfg.blocks.is_empty());
    }

    #[test]
    fn straight_line_collapses_to_one_block() {
        let prog: Vec<Instruction> = vec![
            ins(0, "LOAD_FAST", Some(0)),
            ins(2, "LOAD_FAST", Some(1)),
            ins(4, "BINARY_OP", Some(0)),
            ins(6, "RETURN_VALUE", None),
        ];
        let cfg: Cfg = build_cfg(&prog, PyVersion::PY312);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.blocks[0].instruction_count, 4);
        assert_eq!(cfg.blocks[0].terminator, Some(TerminatorKind::Return));
    }

    #[test]
    fn conditional_branch_splits_into_three_blocks() {
        let prog: Vec<Instruction> = vec![
            ins(0, "LOAD_FAST", Some(0)),
            ins(2, "POP_JUMP_IF_FALSE", Some(2)),
            ins(4, "LOAD_CONST", Some(0)),
            ins(6, "RETURN_VALUE", None),
            ins(8, "LOAD_CONST", Some(1)),
            ins(10, "RETURN_VALUE", None),
        ];
        let cfg: Cfg = build_cfg(&prog, PyVersion::PY312);
        assert_eq!(cfg.blocks.len(), 3);
        let head: &Block = &cfg.blocks[0];
        assert_eq!(head.terminator, Some(TerminatorKind::ConditionalJump));
        assert_eq!(head.successors.len(), 2);
        let kinds: BTreeSet<EdgeKind> = head.successors.iter().map(|(_, k)| *k).collect();
        assert!(kinds.contains(&EdgeKind::Conditional));
    }

    #[test]
    fn backward_jump_marked_as_backward_edge() {
        let prog: Vec<Instruction> = vec![
            ins(0, "RESUME", Some(0)),
            ins(2, "LOAD_FAST", Some(0)),
            ins(4, "POP_JUMP_IF_FALSE", Some(3)),
            ins(6, "LOAD_CONST", Some(0)),
            ins(8, "JUMP_BACKWARD", Some(3)),
            ins(10, "RETURN_VALUE", None),
        ];
        let cfg: Cfg = build_cfg(&prog, PyVersion::PY312);
        let has_backward: bool = cfg
            .blocks
            .iter()
            .flat_map(|b| b.successors.iter())
            .any(|(_, kind)| matches!(kind, EdgeKind::Backward));
        assert!(has_backward, "expected a backward edge");
    }

    #[test]
    fn dot_render_produces_directed_graph_header() {
        let prog: Vec<Instruction> = vec![ins(0, "RETURN_VALUE", None)];
        let cfg: Cfg = build_cfg(&prog, PyVersion::PY312);
        let dot: String = render_dot(&cfg);
        assert!(dot.starts_with("digraph cfg"));
        assert!(dot.contains("b0"));
    }

    #[test]
    fn jump_absolute_starts_a_new_block_after_it() {
        let prog: Vec<Instruction> = vec![
            ins(0, "LOAD_FAST", Some(0)),
            ins(2, "POP_JUMP_IF_FALSE", Some(4)),
            ins(4, "JUMP_ABSOLUTE", Some(5)),
            ins(6, "LOAD_CONST", Some(0)),
            ins(8, "RETURN_VALUE", None),
            ins(10, "LOAD_CONST", Some(1)),
            ins(12, "RETURN_VALUE", None),
        ];
        let cfg: Cfg = build_cfg(&prog, PyVersion::PY310);
        let absolute_block: &Block = cfg
            .blocks
            .iter()
            .find(|b| b.terminator == Some(TerminatorKind::Jump))
            .expect("JUMP_ABSOLUTE block present");
        assert_eq!(
            absolute_block.start_offset, 4,
            "the JUMP_ABSOLUTE must terminate its own block"
        );
        assert_eq!(absolute_block.end_offset, 4);
        assert!(
            cfg.offset_to_block.contains_key(&6),
            "the instruction after JUMP_ABSOLUTE must be a block leader"
        );
    }

    #[test]
    fn unreachable_offset_does_not_panic() {
        let prog: Vec<Instruction> = vec![
            ins(0, "LOAD_FAST", Some(0)),
            ins(2, "POP_JUMP_IF_FALSE", Some(500)),
            ins(4, "RETURN_VALUE", None),
        ];
        let cfg: Cfg = build_cfg(&prog, PyVersion::PY312);
        assert!(!cfg.blocks.is_empty());
    }
}
