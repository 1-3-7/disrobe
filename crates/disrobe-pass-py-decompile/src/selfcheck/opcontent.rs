use std::collections::BTreeSet;

use disrobe_py_marshal::{CodeObject, PyVersion as MarshalVersion};

use crate::ast::node::Stmt;
use crate::bytecode::version::PyVersion as DecompileVersion;
use crate::roundtrip::{
    NormToken, NormalizedOp, NormalizedSequence, compare_normalized, normalize_sequence,
};

use super::relower::{Relowered, ScopeCtx, relower_function_body};

const MAX_CANDIDATES: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verified {
    Equal,
    NotEqual,
    Uncovered,
}

#[derive(Debug)]
struct BasicBlock {
    ops: Vec<NormalizedOp>,
}

#[derive(Debug)]
struct BlockCfg {
    blocks: Vec<BasicBlock>,
}

#[must_use]
fn is_jump_token(op: &NormalizedOp) -> bool {
    matches!(&op.token, NormToken::Op(name) if is_jump_name(name.as_str()))
}

#[must_use]
fn is_jump_name(name: &str) -> bool {
    name.starts_with("JUMP") || matches!(name, "FOR_ITER" | "SEND")
}

#[must_use]
fn is_terminator(op: &NormalizedOp) -> bool {
    if is_jump_token(op) || op.jump_target_index.is_some() {
        return true;
    }
    matches!(&op.token, NormToken::Op(name) if matches!(name.as_str(), "RETURN_VALUE" | "RAISE_VARARGS" | "RERAISE"))
}

#[must_use]
fn build_cfg(ops: &[NormalizedOp]) -> BlockCfg {
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(0);
    for (idx, op) in ops.iter().enumerate() {
        if let Some(target) = op.jump_target_index {
            leaders.insert(target as usize);
        }
        if is_terminator(op) {
            leaders.insert(idx + 1);
        }
    }
    let mut ordered: Vec<usize> = leaders
        .into_iter()
        .filter(|&l: &usize| l <= ops.len())
        .collect();
    ordered.sort_unstable();
    let mut blocks: Vec<BasicBlock> = Vec::new();
    for window in ordered.windows(2) {
        let (start, end): (usize, usize) = (window[0], window[1]);
        if start >= end {
            continue;
        }
        blocks.push(BasicBlock {
            ops: ops[start..end].to_vec(),
        });
    }
    if let Some(&last) = ordered.last()
        && last < ops.len()
    {
        blocks.push(BasicBlock {
            ops: ops[last..].to_vec(),
        });
    }
    BlockCfg { blocks }
}

#[must_use]
fn cfg_equal(input: &BlockCfg, relowered: &BlockCfg) -> bool {
    if input.blocks.len() != relowered.blocks.len() {
        return false;
    }
    for (a, b) in input.blocks.iter().zip(relowered.blocks.iter()) {
        let sa: NormalizedSequence = NormalizedSequence { ops: a.ops.clone() };
        let sb: NormalizedSequence = NormalizedSequence { ops: b.ops.clone() };
        if compare_normalized(&sa, &sb, String::new()).is_some() {
            return false;
        }
    }
    true
}

#[must_use]
fn canonicalize_back_jumps(ops: Vec<NormalizedOp>) -> Vec<NormalizedOp> {
    ops.into_iter()
        .map(|mut op: NormalizedOp| {
            if matches!(&op.token, NormToken::Op(name) if name == "JUMP_BACKWARD_NO_INTERRUPT") {
                op.token = NormToken::Op("JUMP".to_owned());
                op.jump_target_index = None;
                op.raw_arg = None;
            }
            op
        })
        .collect()
}

#[must_use]
fn input_ops(code: &CodeObject, version: &DecompileVersion) -> Vec<NormalizedOp> {
    let marshal: MarshalVersion = MarshalVersion {
        major: version.major(),
        minor: version.minor(),
    };
    canonicalize_back_jumps(normalize_sequence(code, marshal).ops)
}

#[must_use]
fn verified_equal_core(body: &[Stmt], ctx: &ScopeCtx, input_cfg: &BlockCfg) -> Verified {
    let relowered: Vec<NormalizedOp> = match relower_function_body(body, ctx) {
        Relowered::Ops(ops) => canonicalize_back_jumps(ops),
        Relowered::Uncovered => return Verified::Uncovered,
    };
    let relowered_cfg: BlockCfg = build_cfg(&relowered);
    if cfg_equal(input_cfg, &relowered_cfg) {
        Verified::Equal
    } else {
        Verified::NotEqual
    }
}

#[must_use]
fn accept_reordering_core(
    body: &[Stmt],
    ctx: &ScopeCtx,
    input_cfg: &BlockCfg,
) -> Option<Vec<Stmt>> {
    if verified_equal_core(body, ctx, input_cfg) != Verified::NotEqual {
        return None;
    }
    adjacent_transpositions(body)
        .take(MAX_CANDIDATES)
        .find(|candidate: &Vec<Stmt>| {
            verified_equal_core(candidate, ctx, input_cfg) == Verified::Equal
        })
}

#[must_use]
pub(crate) fn accept_reordering(
    body: &[Stmt],
    code: &CodeObject,
    version: &DecompileVersion,
    module_imports: &BTreeSet<String>,
) -> Option<Vec<Stmt>> {
    let ctx: ScopeCtx = ScopeCtx::from_code(code, module_imports);
    let input_cfg: BlockCfg = build_cfg(&input_ops(code, version));
    accept_reordering_core(body, &ctx, &input_cfg)
}

fn adjacent_transpositions(body: &[Stmt]) -> impl Iterator<Item = Vec<Stmt>> + '_ {
    (0..body.len().saturating_sub(1)).map(move |i: usize| {
        let mut next: Vec<Stmt> = body.to_vec();
        next.swap(i, i + 1);
        next
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unreachable)]
mod tests {
    use super::*;
    use crate::ast::node::{Expr, ExprCtx};

    fn load(id: &str) -> Expr {
        Expr::Name {
            id: id.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }
    }

    fn assign(target: &str, value: Expr) -> Stmt {
        Stmt::Assign {
            targets: vec![Expr::Name {
                id: target.to_owned(),
                ctx: ExprCtx::Store,
                line: None,
            }],
            value,
            type_comment: None,
            line: None,
        }
    }

    fn cfg_of(body: &[Stmt], ctx: &ScopeCtx) -> BlockCfg {
        match relower_function_body(body, ctx) {
            Relowered::Ops(ops) => build_cfg(&ops),
            Relowered::Uncovered => unreachable!("test body must be covered"),
        }
    }

    #[test]
    fn accepts_the_reordering_that_matches_input_op_content() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b", "x", "y"], &[], true);
        let correct: Vec<Stmt> = vec![assign("x", load("a")), assign("y", load("b"))];
        let input_cfg: BlockCfg = cfg_of(&correct, &ctx);

        let misordered: Vec<Stmt> = vec![assign("y", load("b")), assign("x", load("a"))];
        assert_eq!(
            verified_equal_core(&misordered, &ctx, &input_cfg),
            Verified::NotEqual
        );
        let fixed: Vec<Stmt> = accept_reordering_core(&misordered, &ctx, &input_cfg)
            .expect("a transposition should match the input op-content");
        assert_eq!(fixed, correct);
        assert_eq!(
            verified_equal_core(&fixed, &ctx, &input_cfg),
            Verified::Equal
        );
    }

    #[test]
    fn already_correct_body_is_left_unchanged() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b", "x", "y"], &[], true);
        let correct: Vec<Stmt> = vec![assign("x", load("a")), assign("y", load("b"))];
        let input_cfg: BlockCfg = cfg_of(&correct, &ctx);
        assert!(accept_reordering_core(&correct, &ctx, &input_cfg).is_none());
    }

    #[test]
    fn uncovered_body_is_left_unchanged() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a"], &[], false);
        let body: Vec<Stmt> = vec![assign("a", load("a"))];
        let input_cfg: BlockCfg = BlockCfg { blocks: Vec::new() };
        assert_eq!(
            verified_equal_core(&body, &ctx, &input_cfg),
            Verified::Uncovered
        );
        assert!(accept_reordering_core(&body, &ctx, &input_cfg).is_none());
    }
}
