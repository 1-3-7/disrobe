use serde::Serialize;

use crate::cfg::{BlockId, CfgBlock, FunctionCfg, TerminatorKind};

#[derive(Debug, Clone, Serialize)]
pub enum StructuredNode {
    Sequence(Vec<Self>),
    Block(BlockId),
    If {
        condition_block: BlockId,
        then_branch: Box<Self>,
        else_branch: Option<Box<Self>>,
    },
    While {
        header: BlockId,
        body: Box<Self>,
    },
    Return(BlockId),
}

#[derive(Debug, Clone, Serialize)]
pub struct StructuredFunction {
    pub root: StructuredNode,
    pub block_count: usize,
}

pub fn reloop_inverse(cfg: &FunctionCfg) -> StructuredFunction {
    let mut seq: Vec<StructuredNode> = Vec::with_capacity(cfg.blocks.len());
    let mut i: usize = 0;
    while i < cfg.blocks.len() {
        let block: &CfgBlock = &cfg.blocks[i];
        if is_back_edge_target(cfg, block.id) {
            let (loop_body, consumed): (Vec<StructuredNode>, usize) = collect_loop_body(cfg, i);
            seq.push(StructuredNode::While {
                header: block.id,
                body: Box::new(StructuredNode::Sequence(loop_body)),
            });
            i += consumed;
            continue;
        }
        if matches!(block.terminator, Some(TerminatorKind::BrIf)) {
            let (then_branch, consumed): (StructuredNode, usize) = collect_then_branch(cfg, i);
            seq.push(StructuredNode::If {
                condition_block: block.id,
                then_branch: Box::new(then_branch),
                else_branch: None,
            });
            i += consumed;
            continue;
        }
        seq.push(classify_block(block));
        i += 1;
    }
    let root: StructuredNode = if seq.len() == 1 {
        seq.into_iter()
            .next()
            .unwrap_or(StructuredNode::Sequence(Vec::new()))
    } else {
        StructuredNode::Sequence(seq)
    };
    StructuredFunction {
        root,
        block_count: cfg.blocks.len(),
    }
}

fn is_back_edge_target(cfg: &FunctionCfg, target: BlockId) -> bool {
    cfg.edges
        .iter()
        .any(|edge| edge.to == target && edge.from.0 > target.0)
}

fn collect_loop_body(cfg: &FunctionCfg, start: usize) -> (Vec<StructuredNode>, usize) {
    let mut body: Vec<StructuredNode> = Vec::new();
    let mut consumed: usize = 1usize;
    let header_id: BlockId = cfg.blocks[start].id;
    body.push(classify_block(&cfg.blocks[start]));
    for j in (start + 1)..cfg.blocks.len() {
        let back: bool = cfg
            .edges
            .iter()
            .any(|e| e.from == cfg.blocks[j].id && e.to == header_id);
        body.push(classify_block(&cfg.blocks[j]));
        consumed += 1;
        if back {
            break;
        }
    }
    (body, consumed)
}

fn collect_then_branch(cfg: &FunctionCfg, cond_idx: usize) -> (StructuredNode, usize) {
    if cond_idx + 1 < cfg.blocks.len() {
        let then_block: &CfgBlock = &cfg.blocks[cond_idx + 1];
        return (classify_block(then_block), 2);
    }
    (StructuredNode::Sequence(Vec::new()), 1)
}

const fn classify_block(block: &CfgBlock) -> StructuredNode {
    match block.terminator {
        Some(TerminatorKind::Return) => StructuredNode::Return(block.id),
        _ => StructuredNode::Block(block.id),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_cfg_yields_empty_sequence() {
        let cfg: FunctionCfg = FunctionCfg::default();
        let structured: StructuredFunction = reloop_inverse(&cfg);
        assert_eq!(structured.block_count, 0);
        assert!(matches!(structured.root, StructuredNode::Sequence(_)));
    }

    #[test]
    fn single_block_yields_block_node() {
        let cfg: FunctionCfg = FunctionCfg {
            blocks: vec![CfgBlock {
                id: BlockId(0),
                ..Default::default()
            }],
            edges: Vec::new(),
            entry: BlockId(0),
        };
        let structured: StructuredFunction = reloop_inverse(&cfg);
        assert_eq!(structured.block_count, 1);
        assert!(matches!(structured.root, StructuredNode::Block(BlockId(0))));
    }

    #[test]
    fn backedge_target_promotes_to_while_node() {
        use crate::cfg::{BlockEdge, EdgeKind};
        let cfg: FunctionCfg = FunctionCfg {
            blocks: vec![
                CfgBlock {
                    id: BlockId(0),
                    terminator: Some(TerminatorKind::BrIf),
                    ..Default::default()
                },
                CfgBlock {
                    id: BlockId(1),
                    terminator: Some(TerminatorKind::Br),
                    ..Default::default()
                },
            ],
            edges: vec![
                BlockEdge {
                    from: BlockId(0),
                    to: BlockId(1),
                    kind: EdgeKind::BrIf,
                },
                BlockEdge {
                    from: BlockId(1),
                    to: BlockId(0),
                    kind: EdgeKind::Branch,
                },
            ],
            entry: BlockId(0),
        };
        let structured: StructuredFunction = reloop_inverse(&cfg);
        assert!(matches!(structured.root, StructuredNode::While { .. }));
    }

    #[test]
    fn br_if_promotes_to_if_node() {
        let cfg: FunctionCfg = FunctionCfg {
            blocks: vec![
                CfgBlock {
                    id: BlockId(0),
                    terminator: Some(TerminatorKind::BrIf),
                    ..Default::default()
                },
                CfgBlock {
                    id: BlockId(1),
                    ..Default::default()
                },
            ],
            edges: Vec::new(),
            entry: BlockId(0),
        };
        let structured: StructuredFunction = reloop_inverse(&cfg);
        match structured.root {
            StructuredNode::Sequence(ref children) => {
                assert!(matches!(children.first(), Some(StructuredNode::If { .. })));
            }
            StructuredNode::If { .. } => {}
            other => panic!("expected If node, got {other:?}"),
        }
    }

    #[test]
    fn return_terminator_yields_return_node() {
        let cfg: FunctionCfg = FunctionCfg {
            blocks: vec![CfgBlock {
                id: BlockId(0),
                terminator: Some(TerminatorKind::Return),
                ..Default::default()
            }],
            edges: Vec::new(),
            entry: BlockId(0),
        };
        let structured: StructuredFunction = reloop_inverse(&cfg);
        assert!(matches!(
            structured.root,
            StructuredNode::Return(BlockId(0))
        ));
    }
}
