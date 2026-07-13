use std::collections::{BTreeMap, BTreeSet};

use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::rewrite::canonicalize;
use crate::verify::{Equivalence, verify_equivalent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynthConfig {
    pub max_arity: u32,
    pub min_residual_nodes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub fit_samples: usize,
    pub val_samples: usize,
    pub eval_budget: u64,
    pub proof_budget: u32,
    pub restart_stall: u32,
    pub mdl_constant_penalty: usize,
}

impl SynthConfig {
    #[must_use]
    pub const fn bounded_default() -> Self {
        Self {
            max_arity: 3,
            min_residual_nodes: 4,
            max_depth: 6,
            max_nodes: 24,
            fit_samples: 48,
            val_samples: 96,
            eval_budget: 60_000,
            proof_budget: 48,
            restart_stall: 60,
            mdl_constant_penalty: 1,
        }
    }
}

impl Default for SynthConfig {
    fn default() -> Self {
        Self::bounded_default()
    }
}

#[must_use]
pub fn synthesize(residual: &Expr, width: Width) -> Option<Expr> {
    synthesize_with(residual, width, &SynthConfig::bounded_default())
}

#[must_use]
pub fn synthesize_with(residual: &Expr, width: Width, config: &SynthConfig) -> Option<Expr> {
    if residual.depth() > crate::expr::MAX_MBA_DEPTH {
        return None;
    }
    let residual_nodes: usize = residual.node_count();
    if residual_nodes < config.min_residual_nodes {
        return None;
    }
    let vars: Vec<u32> = residual.vars().into_iter().collect();
    let arity: u32 = u32::try_from(vars.len()).ok()?;
    if arity > config.max_arity {
        return None;
    }
    let mut to_dense: BTreeMap<u32, u32> = BTreeMap::new();
    let mut to_original: BTreeMap<u32, u32> = BTreeMap::new();
    for (dense, original) in vars.iter().copied().enumerate() {
        let dense: u32 = u32::try_from(dense).ok()?;
        to_dense.insert(original, dense);
        to_original.insert(dense, original);
    }
    let residual_dense: Expr = residual.remap_vars(&to_dense);
    let max_nodes: usize = config.max_nodes.min(residual_nodes);

    let mut rng: SplitMix64 = SplitMix64::new(structural_seed(residual, width));
    let grammar: Grammar = Grammar::new(arity, width);
    let fit: Samples = build_fit(&grammar, &residual_dense, config.fit_samples, &mut rng);
    let val: Samples = build_val(
        &grammar,
        &residual_dense,
        &fit,
        config.val_samples,
        &mut rng,
    );

    let mut search: Search<'_> = Search {
        grammar,
        rng,
        width,
        fit,
        val,
        residual,
        residual_dense,
        vars,
        to_original,
        cfg: *config,
        max_nodes,
        tried: BTreeSet::new(),
    };
    search.run()
}

struct Search<'a> {
    grammar: Grammar,
    rng: SplitMix64,
    width: Width,
    fit: Samples,
    val: Samples,
    residual: &'a Expr,
    residual_dense: Expr,
    vars: Vec<u32>,
    to_original: BTreeMap<u32, u32>,
    cfg: SynthConfig,
    max_nodes: usize,
    tried: BTreeSet<String>,
}

impl Search<'_> {
    fn run(&mut self) -> Option<Expr> {
        let mut current: Expr = self.fresh();
        let mut current_dist: u64 = self.fit.dist(&current, self.width);
        let mut best: Expr = current.clone();
        let mut best_dist: u64 = current_dist;
        let mut best_mdl: usize = mdl(&best, self.cfg.mdl_constant_penalty);
        let mut no_improve: u32 = 0;
        let mut evals: u64 = 0;
        let mut proofs: u32 = 0;

        while evals < self.cfg.eval_budget && proofs < self.cfg.proof_budget {
            let candidate: Expr = self.propose(&current, &best);
            evals += 1;
            let candidate_dist: u64 = self.fit.dist(&candidate, self.width);

            if candidate_dist == 0 && self.val.dist(&candidate, self.width) == 0 {
                let key: String = format!("{candidate}");
                if self.tried.insert(key) {
                    proofs += 1;
                    let restored: Expr = candidate.remap_vars(&self.to_original);
                    match verify_equivalent(self.residual, &restored, self.width) {
                        Equivalence::Proven => return Some(self.finalize(restored)),
                        Equivalence::Disproven { counterexample } => {
                            self.absorb_counterexample(&counterexample);
                            current = self.fresh();
                            current_dist = self.fit.dist(&current, self.width);
                            no_improve = 0;
                            continue;
                        }
                        Equivalence::Unknown => {
                            current = self.fresh();
                            current_dist = self.fit.dist(&current, self.width);
                            no_improve = 0;
                            continue;
                        }
                    }
                }
            }

            if candidate_dist <= current_dist {
                if candidate_dist < current_dist {
                    no_improve = 0;
                } else {
                    no_improve += 1;
                }
                current = candidate;
                current_dist = candidate_dist;
            } else {
                no_improve += 1;
            }

            let current_mdl: usize = mdl(&current, self.cfg.mdl_constant_penalty);
            if current_dist < best_dist || (current_dist == best_dist && current_mdl < best_mdl) {
                best = current.clone();
                best_dist = current_dist;
                best_mdl = current_mdl;
            }

            if no_improve >= self.cfg.restart_stall {
                current = self.fresh();
                current_dist = self.fit.dist(&current, self.width);
                no_improve = 0;
            }
        }
        None
    }

    fn finalize(&self, restored: Expr) -> Expr {
        let canonical: Expr = canonicalize(&restored, self.width);
        if canonical.node_count() <= restored.node_count()
            && verify_equivalent(self.residual, &canonical, self.width).is_proven()
        {
            canonical
        } else {
            restored
        }
    }

    fn absorb_counterexample(&mut self, counterexample: &[u64]) {
        let mask: u64 = self.width.mask();
        let tuple: Vec<u64> = self
            .vars
            .iter()
            .map(|original: &u32| {
                counterexample.get(*original as usize).copied().unwrap_or(0) & mask
            })
            .collect();
        let output: u64 = self.residual_dense.eval(&tuple, self.width);
        self.fit.inputs.push(tuple);
        self.fit.outputs.push(output);
    }

    fn fresh(&mut self) -> Expr {
        let depth: usize = self.cfg.max_depth.min(3);
        for _ in 0..16 {
            let candidate: Expr = self.grammar.random_expr(&mut self.rng, depth);
            if candidate.node_count() <= self.max_nodes && candidate.depth() <= self.cfg.max_depth {
                return candidate;
            }
        }
        self.grammar.random_terminal(&mut self.rng)
    }

    fn propose(&mut self, current: &Expr, best: &Expr) -> Expr {
        for _ in 0..8 {
            let candidate: Expr = self.mutate_once(current, best);
            if candidate.node_count() <= self.max_nodes && candidate.depth() <= self.cfg.max_depth {
                return candidate;
            }
        }
        current.clone()
    }

    fn mutate_once(&mut self, current: &Expr, best: &Expr) -> Expr {
        let node_total: usize = current.node_count();
        match self.rng.below(6) {
            0 => {
                let target: usize = self.rng.below(node_total);
                let replacement: Expr = self.grammar.random_expr(&mut self.rng, 2);
                transform_at(current, target, &mut |_node: &Expr| replacement.clone())
            }
            1 => {
                let indices: Vec<usize> =
                    matching_indices(current, &|node: &Expr| is_operator(node));
                if indices.is_empty() {
                    return self.grammar.random_expr(&mut self.rng, 2);
                }
                let target: usize = indices[self.rng.below(indices.len())];
                let new_binop: BinOp = random_binop(&mut self.rng);
                let new_unop: UnOp = random_unop(&mut self.rng);
                transform_at(current, target, &mut |node: &Expr| match node {
                    Expr::Binary(_, left, right) => {
                        Expr::Binary(new_binop, left.clone(), right.clone())
                    }
                    Expr::Unary(_, inner) => Expr::Unary(new_unop, inner.clone()),
                    other => other.clone(),
                })
            }
            2 => {
                let target: usize = self.rng.below(node_total);
                let as_unary: bool = self.rng.below(2) == 0;
                let new_unop: UnOp = random_unop(&mut self.rng);
                let new_binop: BinOp = random_binop(&mut self.rng);
                let sibling: Expr = self.grammar.random_expr(&mut self.rng, 1);
                let sibling_left: bool = self.rng.below(2) == 0;
                transform_at(current, target, &mut |node: &Expr| {
                    if as_unary {
                        Expr::Unary(new_unop, Box::new(node.clone()))
                    } else if sibling_left {
                        Expr::Binary(new_binop, Box::new(sibling.clone()), Box::new(node.clone()))
                    } else {
                        Expr::Binary(new_binop, Box::new(node.clone()), Box::new(sibling.clone()))
                    }
                })
            }
            3 => {
                let indices: Vec<usize> =
                    matching_indices(current, &|node: &Expr| is_operator(node));
                if indices.is_empty() {
                    return self.grammar.random_expr(&mut self.rng, 2);
                }
                let target: usize = indices[self.rng.below(indices.len())];
                let take_right: bool = self.rng.below(2) == 0;
                transform_at(current, target, &mut |node: &Expr| match node {
                    Expr::Unary(_, inner) => (**inner).clone(),
                    Expr::Binary(_, left, right) => {
                        if take_right {
                            (**right).clone()
                        } else {
                            (**left).clone()
                        }
                    }
                    other => other.clone(),
                })
            }
            4 => {
                let indices: Vec<usize> =
                    matching_indices(current, &|node: &Expr| matches!(node, Expr::Const(_)));
                if indices.is_empty() {
                    let target: usize = self.rng.below(node_total);
                    let replacement: Expr = self.grammar.random_terminal(&mut self.rng);
                    return transform_at(current, target, &mut |_node: &Expr| replacement.clone());
                }
                let target: usize = indices[self.rng.below(indices.len())];
                let kind: usize = self.rng.below(4);
                let bit: u32 = self.rng.below(self.width.bits() as usize) as u32;
                let mask: u64 = self.width.mask();
                transform_at(current, target, &mut |node: &Expr| match node {
                    Expr::Const(value) => {
                        let perturbed: u64 = match kind {
                            0 => value.wrapping_add(1),
                            1 => value.wrapping_sub(1),
                            2 => value ^ (1u64 << bit),
                            _ => value.wrapping_mul(2),
                        };
                        Expr::Const(perturbed & mask)
                    }
                    other => other.clone(),
                })
            }
            _ => {
                let best_total: usize = best.node_count();
                let source: usize = self.rng.below(best_total);
                let donor: Expr = subtree_at(best, source)
                    .unwrap_or_else(|| self.grammar.random_terminal(&mut self.rng));
                let target: usize = self.rng.below(node_total);
                transform_at(current, target, &mut |_node: &Expr| donor.clone())
            }
        }
    }
}

#[derive(Debug)]
struct Grammar {
    arity: u32,
    width: Width,
    consts: Vec<u64>,
}

impl Grammar {
    fn new(arity: u32, width: Width) -> Self {
        let mask: u64 = width.mask();
        let bits: u32 = width.bits();
        let sign_bit: u64 = 1u64 << (bits - 1);
        let mut consts: Vec<u64> = vec![0, 1, 2, 3, mask, sign_bit];
        consts.sort_unstable();
        consts.dedup();
        Self {
            arity,
            width,
            consts,
        }
    }

    fn random_terminal(&self, rng: &mut SplitMix64) -> Expr {
        if self.arity > 0 && rng.below(4) != 0 {
            Expr::Var(rng.below(self.arity as usize) as u32)
        } else {
            Expr::Const(self.random_const(rng))
        }
    }

    fn random_const(&self, rng: &mut SplitMix64) -> u64 {
        let mask: u64 = self.width.mask();
        let bits: u32 = self.width.bits();
        match rng.below(4) {
            0 => self.consts[rng.below(self.consts.len())],
            1 => (rng.below(16) as u64) & mask,
            2 => {
                if rng.below(2) == 0 {
                    mask
                } else {
                    1u64 << (bits - 1)
                }
            }
            _ => rng.next_u64() & mask,
        }
    }

    const fn random_shift_amount(&self, rng: &mut SplitMix64) -> u64 {
        let bits: u32 = self.width.bits();
        if bits <= 1 {
            1
        } else {
            1 + rng.below((bits - 1) as usize) as u64
        }
    }

    fn random_expr(&self, rng: &mut SplitMix64, depth: usize) -> Expr {
        if depth == 0 || rng.below(3) == 0 {
            return self.random_terminal(rng);
        }
        match rng.below(9) {
            0 => Expr::Unary(UnOp::Neg, Box::new(self.random_expr(rng, depth - 1))),
            1 => Expr::Unary(UnOp::Not, Box::new(self.random_expr(rng, depth - 1))),
            8 => {
                let op: BinOp = if rng.below(2) == 0 {
                    BinOp::Shl
                } else {
                    BinOp::Shr
                };
                Expr::Binary(
                    op,
                    Box::new(self.random_expr(rng, depth - 1)),
                    Box::new(Expr::Const(self.random_shift_amount(rng))),
                )
            }
            slot => {
                let op: BinOp = match slot {
                    2 => BinOp::Add,
                    3 => BinOp::Sub,
                    4 => BinOp::Mul,
                    5 => BinOp::And,
                    6 => BinOp::Or,
                    _ => BinOp::Xor,
                };
                Expr::Binary(
                    op,
                    Box::new(self.random_expr(rng, depth - 1)),
                    Box::new(self.random_expr(rng, depth - 1)),
                )
            }
        }
    }
}

#[derive(Debug)]
struct Samples {
    inputs: Vec<Vec<u64>>,
    outputs: Vec<u64>,
}

impl Samples {
    fn dist(&self, candidate: &Expr, width: Width) -> u64 {
        let mask: u64 = width.mask();
        let mut total: u64 = 0;
        for (input, output) in self.inputs.iter().zip(self.outputs.iter()) {
            let got: u64 = candidate.eval(input, width);
            total += u64::from(((got ^ output) & mask).count_ones());
        }
        total
    }
}

fn corner_values(width: Width) -> Vec<u64> {
    let mask: u64 = width.mask();
    let bits: u32 = width.bits();
    let mut values: Vec<u64> = vec![
        0,
        1,
        mask,
        1u64 << (bits - 1),
        u64::from(bits.saturating_sub(1)),
    ];
    let mut shift: u32 = 0;
    while shift < bits {
        values.push((1u64 << shift) & mask);
        shift += 1;
    }
    values.sort_unstable();
    values.dedup();
    values
}

fn random_tuple(grammar: &Grammar, corners: &[u64], rng: &mut SplitMix64) -> Vec<u64> {
    let mask: u64 = grammar.width.mask();
    (0..grammar.arity)
        .map(|_| {
            if rng.below(2) == 0 {
                corners[rng.below(corners.len())]
            } else {
                rng.next_u64() & mask
            }
        })
        .collect()
}

fn build_fit(
    grammar: &Grammar,
    residual_dense: &Expr,
    target: usize,
    rng: &mut SplitMix64,
) -> Samples {
    let width: Width = grammar.width;
    let corners: Vec<u64> = corner_values(width);
    let mut inputs: Vec<Vec<u64>> = Vec::new();
    let mut seen: BTreeSet<Vec<u64>> = BTreeSet::new();
    for corner in corners.iter().copied() {
        let tuple: Vec<u64> = vec![corner; grammar.arity as usize];
        if seen.insert(tuple.clone()) {
            inputs.push(tuple);
        }
    }
    let mut attempts: usize = 0;
    let attempt_cap: usize = target.saturating_mul(32).max(1024);
    while inputs.len() < target && attempts < attempt_cap {
        attempts += 1;
        let tuple: Vec<u64> = random_tuple(grammar, &corners, rng);
        if seen.insert(tuple.clone()) {
            inputs.push(tuple);
        }
    }
    finish_samples(inputs, residual_dense, width)
}

fn build_val(
    grammar: &Grammar,
    residual_dense: &Expr,
    fit: &Samples,
    target: usize,
    rng: &mut SplitMix64,
) -> Samples {
    let width: Width = grammar.width;
    let corners: Vec<u64> = corner_values(width);
    let mut seen: BTreeSet<Vec<u64>> = fit.inputs.iter().cloned().collect();
    let mut inputs: Vec<Vec<u64>> = Vec::new();
    let mut attempts: usize = 0;
    let attempt_cap: usize = target.saturating_mul(32).max(2048);
    while inputs.len() < target && attempts < attempt_cap {
        attempts += 1;
        let tuple: Vec<u64> = random_tuple(grammar, &corners, rng);
        if seen.insert(tuple.clone()) {
            inputs.push(tuple);
        }
    }
    finish_samples(inputs, residual_dense, width)
}

fn finish_samples(inputs: Vec<Vec<u64>>, residual_dense: &Expr, width: Width) -> Samples {
    let outputs: Vec<u64> = inputs
        .iter()
        .map(|input: &Vec<u64>| residual_dense.eval(input, width))
        .collect();
    Samples { inputs, outputs }
}

const fn is_operator(node: &Expr) -> bool {
    matches!(node, Expr::Binary(..) | Expr::Unary(..))
}

const fn random_binop(rng: &mut SplitMix64) -> BinOp {
    match rng.below(8) {
        0 => BinOp::Add,
        1 => BinOp::Sub,
        2 => BinOp::Mul,
        3 => BinOp::And,
        4 => BinOp::Or,
        5 => BinOp::Xor,
        6 => BinOp::Shl,
        _ => BinOp::Shr,
    }
}

const fn random_unop(rng: &mut SplitMix64) -> UnOp {
    if rng.below(2) == 0 {
        UnOp::Neg
    } else {
        UnOp::Not
    }
}

fn mdl(expr: &Expr, constant_penalty: usize) -> usize {
    expr.node_count() + constant_penalty * distinct_consts(expr).len()
}

fn distinct_consts(expr: &Expr) -> BTreeSet<u64> {
    let mut out: BTreeSet<u64> = BTreeSet::new();
    let mut stack: Vec<&Expr> = vec![expr];
    while let Some(node) = stack.pop() {
        if let Expr::Const(value) = node {
            out.insert(*value);
        }
        stack.extend(tree_children(node));
    }
    out
}

fn tree_children(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::Const(_) | Expr::Var(_) => Vec::new(),
        Expr::Unary(_, inner) | Expr::Slice(inner, _, _) | Expr::Mem(inner, _) => vec![inner],
        Expr::Binary(_, left, right) | Expr::Compose(left, right, _) => vec![left, right],
        Expr::Ite(cond, then, otherwise) => vec![cond, then, otherwise],
    }
}

fn tree_rebuild(expr: &Expr, kids: &[Expr]) -> Expr {
    match (expr, kids) {
        (Expr::Unary(op, _), [inner]) => Expr::Unary(*op, Box::new(inner.clone())),
        (Expr::Binary(op, _, _), [left, right]) => {
            Expr::Binary(*op, Box::new(left.clone()), Box::new(right.clone()))
        }
        (Expr::Slice(_, lo, hi), [inner]) => Expr::Slice(Box::new(inner.clone()), *lo, *hi),
        (Expr::Mem(_, load_width), [inner]) => Expr::Mem(Box::new(inner.clone()), *load_width),
        (Expr::Compose(_, _, low_bits), [left, right]) => {
            Expr::Compose(Box::new(left.clone()), Box::new(right.clone()), *low_bits)
        }
        (Expr::Ite(_, _, _), [cond, then, otherwise]) => Expr::Ite(
            Box::new(cond.clone()),
            Box::new(then.clone()),
            Box::new(otherwise.clone()),
        ),
        _ => expr.clone(),
    }
}

fn transform_at(expr: &Expr, target: usize, f: &mut dyn FnMut(&Expr) -> Expr) -> Expr {
    let mut counter: usize = 0;
    transform_inner(expr, target, &mut counter, f)
}

fn transform_inner(
    expr: &Expr,
    target: usize,
    counter: &mut usize,
    f: &mut dyn FnMut(&Expr) -> Expr,
) -> Expr {
    let here: usize = *counter;
    *counter += 1;
    if here == target {
        return f(expr);
    }
    let children: Vec<&Expr> = tree_children(expr);
    if children.is_empty() {
        return expr.clone();
    }
    let rebuilt: Vec<Expr> = children
        .into_iter()
        .map(|child: &Expr| transform_inner(child, target, counter, f))
        .collect();
    tree_rebuild(expr, &rebuilt)
}

fn matching_indices(expr: &Expr, pred: &dyn Fn(&Expr) -> bool) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    let mut counter: usize = 0;
    collect_inner(expr, &mut counter, pred, &mut out);
    out
}

fn collect_inner(
    expr: &Expr,
    counter: &mut usize,
    pred: &dyn Fn(&Expr) -> bool,
    out: &mut Vec<usize>,
) {
    let here: usize = *counter;
    *counter += 1;
    if pred(expr) {
        out.push(here);
    }
    for child in tree_children(expr) {
        collect_inner(child, counter, pred, out);
    }
}

fn subtree_at(expr: &Expr, target: usize) -> Option<Expr> {
    let mut counter: usize = 0;
    subtree_inner(expr, target, &mut counter)
}

fn subtree_inner(expr: &Expr, target: usize, counter: &mut usize) -> Option<Expr> {
    let here: usize = *counter;
    *counter += 1;
    if here == target {
        return Some(expr.clone());
    }
    for child in tree_children(expr) {
        if let Some(found) = subtree_inner(child, target, counter) {
            return Some(found);
        }
    }
    None
}

fn structural_seed(expr: &Expr, width: Width) -> u64 {
    let encoded: String = format!("{expr}|w{}", width.bits());
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in encoded.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

#[derive(Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z: u64 = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    const fn below(&mut self, bound: usize) -> usize {
        if bound <= 1 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn v(index: u32) -> Expr {
        Expr::var(index)
    }

    fn xor_carry_add() -> Expr {
        Expr::add(
            Expr::xor(v(0), v(1)),
            Expr::mul(Expr::konst(2), Expr::and(v(0), v(1))),
        )
    }

    #[test]
    fn synthesizes_xor_carry_add_and_proves_against_clean_form() {
        let residual: Expr = xor_carry_add();
        let clean: Expr = Expr::add(v(0), v(1));
        for width in [Width::W8, Width::W16, Width::W32, Width::W64] {
            let got: Expr =
                synthesize(&residual, width).unwrap_or_else(|| panic!("synth failed at {width:?}"));
            assert!(
                verify_equivalent(&got, &clean, width).is_proven(),
                "{got} not proven equal to x+y at {width:?}"
            );
            assert!(
                verify_equivalent(&got, &residual, width).is_proven(),
                "{got} not proven equal to residual at {width:?}"
            );
            assert!(
                got.node_count() <= residual.node_count(),
                "{got} ({} nodes) not simpler than residual ({} nodes)",
                got.node_count(),
                residual.node_count()
            );
        }
    }

    #[test]
    fn synthesizes_and_plus_xor_as_or() {
        let residual: Expr = Expr::add(Expr::and(v(0), v(1)), Expr::xor(v(0), v(1)));
        let clean: Expr = Expr::or(v(0), v(1));
        let width: Width = Width::W32;
        let got: Expr = synthesize(&residual, width).expect("synth failed");
        assert!(verify_equivalent(&got, &clean, width).is_proven());
        assert!(got.node_count() <= residual.node_count());
    }

    #[test]
    fn synthesizes_bitwise_xor_decomposition() {
        let residual: Expr = Expr::or(
            Expr::and(v(0), Expr::not(v(1))),
            Expr::and(Expr::not(v(0)), v(1)),
        );
        let clean: Expr = Expr::xor(v(0), v(1));
        let width: Width = Width::W16;
        let got: Expr = synthesize(&residual, width).expect("synth failed");
        assert!(verify_equivalent(&got, &clean, width).is_proven());
        assert!(got.node_count() <= residual.node_count());
    }

    #[test]
    fn rejects_hard_residual_under_tiny_budget() {
        let residual: Expr = Expr::xor(Expr::mul(v(0), v(1)), Expr::mul(v(2), v(2)));
        let config: SynthConfig = SynthConfig {
            eval_budget: 200,
            proof_budget: 2,
            ..SynthConfig::bounded_default()
        };
        assert!(synthesize_with(&residual, Width::W32, &config).is_none());
    }

    #[test]
    fn any_returned_form_is_proven_equivalent_and_not_larger() {
        let cases: [Expr; 4] = [
            xor_carry_add(),
            Expr::add(Expr::and(v(0), v(1)), Expr::xor(v(0), v(1))),
            Expr::xor(Expr::mul(v(0), v(1)), Expr::mul(v(2), v(2))),
            Expr::sub(Expr::or(v(0), v(1)), Expr::and(v(0), v(1))),
        ];
        for residual in &cases {
            for width in [Width::W8, Width::W32] {
                if let Some(got) = synthesize(residual, width) {
                    assert!(
                        verify_equivalent(residual, &got, width).is_proven(),
                        "returned {got} is not proven equal to {residual} at {width:?}"
                    );
                    assert!(got.node_count() <= residual.node_count());
                }
            }
        }
    }

    #[test]
    fn deterministic_across_repeated_runs() {
        let residual: Expr = xor_carry_add();
        let first: Option<Expr> = synthesize(&residual, Width::W32);
        let second: Option<Expr> = synthesize(&residual, Width::W32);
        assert_eq!(first, second);
        assert!(first.is_some());
    }

    #[test]
    fn respects_arity_and_node_floor() {
        let tiny: Expr = Expr::add(v(0), v(1));
        assert!(
            synthesize(&tiny, Width::W32).is_none(),
            "residual below the node floor must not be synthesized"
        );
        let wide: Expr = Expr::add(
            Expr::add(Expr::add(v(0), v(1)), Expr::add(v(2), v(3))),
            v(4),
        );
        assert!(
            synthesize(&wide, Width::W32).is_none(),
            "residual above the arity cap must not be synthesized"
        );
    }

    #[test]
    fn proof_gate_rejects_a_form_that_fits_every_sample() {
        let f: Expr = Expr::var(0);
        let g: Expr = Expr::and(Expr::var(0), Expr::konst(0x7F));
        let width: Width = Width::W8;
        let samples: Vec<u64> = (0..=0x7F).collect();
        assert!(
            samples
                .iter()
                .all(|value: &u64| f.eval(&[*value], width) == g.eval(&[*value], width)),
            "the crafted form must agree with the identity on every sampled input"
        );
        let verdict: Equivalence = verify_equivalent(&f, &g, width);
        assert!(
            verdict.is_disproven(),
            "sampling alone would accept a globally-wrong form; the proof gate must reject it, got {verdict:?}"
        );
    }

    #[test]
    fn structural_seed_is_stable_and_width_sensitive() {
        let residual: Expr = xor_carry_add();
        assert_eq!(
            structural_seed(&residual, Width::W32),
            structural_seed(&residual, Width::W32)
        );
        assert_ne!(
            structural_seed(&residual, Width::W32),
            structural_seed(&residual, Width::W64)
        );
    }
}
