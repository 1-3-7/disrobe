use serde::Serialize;
use wasmparser::{FunctionBody, Operator};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct BlockId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EdgeKind {
    Fallthrough,
    Branch,
    BrIf,
    BrTable,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockEdge {
    pub from: BlockId,
    pub to: BlockId,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FunctionCfg {
    pub blocks: Vec<CfgBlock>,
    pub edges: Vec<BlockEdge>,
    pub entry: BlockId,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CfgBlock {
    pub id: BlockId,
    pub start_offset: usize,
    pub end_offset: usize,
    pub op_count: u32,
    pub terminator: Option<TerminatorKind>,
    pub successors: Vec<BlockId>,
    pub depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TerminatorKind {
    Return,
    Unreachable,
    Br,
    BrIf,
    BrTable,
    End,
}

pub fn build_function_cfg(body: &FunctionBody<'_>) -> Result<FunctionCfg> {
    let operators_reader: wasmparser::OperatorsReader<'_> = body
        .get_operators_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;

    let mut blocks: Vec<CfgBlock> = Vec::new();
    let mut current: CfgBlock = CfgBlock {
        id: BlockId(0),
        start_offset: 0,
        ..Default::default()
    };
    let mut depth: u32 = 0;
    let mut op_offset: usize = 0;

    for op_result in operators_reader.into_iter_with_offsets() {
        let (op, offset): (Operator<'_>, usize) =
            op_result.map_err(|e| Error::Parse(e.to_string()))?;
        op_offset = offset;
        current.op_count += 1;
        match op {
            Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                depth = depth.saturating_add(1);
            }
            Operator::End => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    seal_block(
                        &mut blocks,
                        &mut current,
                        op_offset,
                        TerminatorKind::End,
                        depth,
                    );
                }
            }
            _ => {
                if let Some(kind) = terminator_for(&op) {
                    seal_block(&mut blocks, &mut current, op_offset, kind, depth);
                }
            }
        }
    }
    if current.op_count > 0 {
        current.end_offset = op_offset;
        blocks.push(current);
    }

    let mut edges: Vec<BlockEdge> = Vec::with_capacity(blocks.len());
    for window in blocks.windows(2) {
        let prev: &CfgBlock = &window[0];
        let next: &CfgBlock = &window[1];
        let kind: EdgeKind = match prev.terminator {
            Some(TerminatorKind::Br) => EdgeKind::Branch,
            Some(TerminatorKind::BrIf) => EdgeKind::BrIf,
            Some(TerminatorKind::BrTable) => EdgeKind::BrTable,
            Some(TerminatorKind::Return | TerminatorKind::Unreachable) => EdgeKind::Return,
            _ => EdgeKind::Fallthrough,
        };
        edges.push(BlockEdge {
            from: prev.id,
            to: next.id,
            kind,
        });
    }
    let mut successors: Vec<Vec<BlockId>> = vec![Vec::new(); blocks.len()];
    for edge in &edges {
        if let Some(list) = successors.get_mut(edge.from.0 as usize) {
            list.push(edge.to);
        }
    }
    for (block, list) in blocks.iter_mut().zip(successors) {
        block.successors = list;
    }

    Ok(FunctionCfg {
        blocks,
        edges,
        entry: BlockId(0),
    })
}

const fn terminator_for(op: &Operator<'_>) -> Option<TerminatorKind> {
    Some(match op {
        Operator::Return => TerminatorKind::Return,
        Operator::Unreachable => TerminatorKind::Unreachable,
        Operator::Br { .. } => TerminatorKind::Br,
        Operator::BrIf { .. } => TerminatorKind::BrIf,
        Operator::BrTable { .. } => TerminatorKind::BrTable,
        _ => return None,
    })
}

fn seal_block(
    blocks: &mut Vec<CfgBlock>,
    current: &mut CfgBlock,
    offset: usize,
    term: TerminatorKind,
    depth: u32,
) {
    current.terminator = Some(term);
    current.end_offset = offset;
    blocks.push(core::mem::take(current));
    *current = CfgBlock {
        id: BlockId(u32::try_from(blocks.len()).unwrap_or(u32::MAX)),
        start_offset: offset,
        depth,
        ..Default::default()
    };
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wasmparser::Parser;

    fn synthetic_module_with_one_fn() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
        buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        buf.extend_from_slice(&[0x0a, 0x05, 0x01, 0x03, 0x00, 0x01, 0x0b]);
        buf
    }

    #[test]
    fn edge_population_yields_per_block_successors_and_fallthrough_kind() {
        let bytes: Vec<u8> = synthetic_module_with_one_fn();
        let parser: Parser = Parser::new(0);
        for payload in parser.parse_all(&bytes) {
            if let Ok(wasmparser::Payload::CodeSectionEntry(body)) = payload {
                let cfg: FunctionCfg = build_function_cfg(&body).expect("cfg build");
                assert_eq!(
                    cfg.edges.len(),
                    cfg.blocks.len().saturating_sub(1),
                    "edges should connect every adjacent block pair"
                );
                for edge in &cfg.edges {
                    let from_block: &CfgBlock =
                        cfg.blocks.iter().find(|b| b.id == edge.from).expect("from");
                    assert!(
                        from_block.successors.contains(&edge.to),
                        "successor list must mirror edges"
                    );
                }
            }
        }
    }

    #[test]
    fn parses_single_block_fn() {
        let bytes: Vec<u8> = synthetic_module_with_one_fn();
        let parser: Parser = Parser::new(0);
        let mut found_one: bool = false;
        for payload in parser.parse_all(&bytes) {
            if let Ok(wasmparser::Payload::CodeSectionEntry(body)) = payload {
                let cfg: FunctionCfg = build_function_cfg(&body).expect("cfg build");
                assert!(!cfg.blocks.is_empty(), "must produce at least one block");
                found_one = true;
            }
        }
        assert!(found_one, "synthetic module must contain a code body");
    }

    fn many_block_module(pairs: usize) -> Vec<u8> {
        let mut body: String = String::with_capacity(pairs * 20);
        for _ in 0..pairs {
            body.push_str("i32.const 0 br_if 0 ");
        }
        let source: String = format!("(module (func {body}))");
        wat::parse_str(&source).expect("many-block module parses")
    }

    fn only_cfg(bytes: &[u8]) -> FunctionCfg {
        for payload in Parser::new(0).parse_all(bytes) {
            if let Ok(wasmparser::Payload::CodeSectionEntry(body)) = payload {
                return build_function_cfg(&body).expect("cfg build");
            }
        }
        panic!("module must contain a code body");
    }

    #[test]
    fn successors_match_edge_filter_oracle_for_many_blocks() {
        let cfg: FunctionCfg = only_cfg(&many_block_module(1500));
        assert!(cfg.blocks.len() > 1000, "expected many blocks");
        for block in &cfg.blocks {
            let expected: Vec<BlockId> = cfg
                .edges
                .iter()
                .filter(|e| e.from == block.id)
                .map(|e| e.to)
                .collect();
            assert_eq!(block.successors, expected, "successors for {:?}", block.id);
        }
    }

    #[test]
    fn many_block_cfg_builds_with_contiguous_successors_within_bound() {
        let pairs: usize = 8000;
        let bytes: Vec<u8> = many_block_module(pairs);
        let start: std::time::Instant = std::time::Instant::now();
        let cfg: FunctionCfg = only_cfg(&bytes);
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            cfg.blocks.len() >= pairs,
            "expected at least one block per branch"
        );
        let last: usize = cfg.blocks.len() - 1;
        for (idx, block) in cfg.blocks.iter().enumerate() {
            if idx == last {
                assert!(
                    block.successors.is_empty(),
                    "terminal block has no successor"
                );
            } else {
                let next: u32 = u32::try_from(idx + 1).expect("index fits u32");
                assert_eq!(
                    block.successors,
                    vec![BlockId(next)],
                    "block {idx} must fall through to its neighbour"
                );
            }
        }
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "cfg build must scale linearly, took {elapsed:?}"
        );
    }
}
