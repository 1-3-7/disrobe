use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::opaque::{CmpOp, OpaqueVerdict, Predicate};
use std::collections::{BTreeMap, BTreeSet};

const MEM_VAR_BASE: u32 = 1u32 << 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Equivalence {
    Proven,
    Disproven { counterexample: Vec<u64> },
    Unknown,
}

impl Equivalence {
    #[must_use]
    pub const fn is_proven(&self) -> bool {
        matches!(self, Self::Proven)
    }

    #[must_use]
    pub const fn is_disproven(&self) -> bool {
        matches!(self, Self::Disproven { .. })
    }
}

const DEFAULT_NODE_BUDGET: usize = 1usize << 20;
const MAX_INPUT_BITS: usize = 512;
const MAX_COUNTEREXAMPLE_SLOTS: usize = 1024;

#[must_use]
pub fn verify_equivalent(lhs: &Expr, rhs: &Expr, width: Width) -> Equivalence {
    verify_equivalent_budgeted(lhs, rhs, width, DEFAULT_NODE_BUDGET)
}

#[must_use]
pub fn verify_equivalent_budgeted(
    lhs: &Expr,
    rhs: &Expr,
    width: Width,
    node_budget: usize,
) -> Equivalence {
    if lhs.depth() > crate::expr::MAX_MBA_DEPTH || rhs.depth() > crate::expr::MAX_MBA_DEPTH {
        return Equivalence::Unknown;
    }
    let bits: usize = width.bits() as usize;
    let mut vars: BTreeSet<u32> = BTreeSet::new();
    lhs.collect_vars(&mut vars);
    rhs.collect_vars(&mut vars);
    let var_count: usize = vars.len();
    let original_vars: Vec<u32> = vars.iter().copied().collect();
    let Some(input_bits): Option<usize> = var_count.checked_mul(bits) else {
        return Equivalence::Unknown;
    };
    if input_bits > MAX_INPUT_BITS || input_bits.saturating_add(2) > node_budget {
        return Equivalence::Unknown;
    }
    let mut remap: BTreeMap<u32, u32> = BTreeMap::new();
    for (dense, original) in original_vars.iter().copied().enumerate() {
        let Ok(dense): Result<u32, _> = u32::try_from(dense) else {
            return Equivalence::Unknown;
        };
        remap.insert(original, dense);
    }
    let lhs: Expr = lhs.remap_vars(&remap);
    let rhs: Expr = rhs.remap_vars(&remap);

    let mut bdd: Bdd = Bdd::new(node_budget);
    let inputs: Vec<Vec<NodeId>> = match bdd.fresh_inputs(var_count, bits) {
        Some(inputs) => inputs,
        None => return Equivalence::Unknown,
    };

    let lhs_bits: Vec<NodeId> = match blast(&mut bdd, &lhs, &inputs, bits) {
        Some(bits) => bits,
        None => return Equivalence::Unknown,
    };
    let rhs_bits: Vec<NodeId> = match blast(&mut bdd, &rhs, &inputs, bits) {
        Some(bits) => bits,
        None => return Equivalence::Unknown,
    };

    let mut difference: NodeId = ZERO;
    for (left, right) in lhs_bits.iter().copied().zip(rhs_bits.iter().copied()) {
        let bit_diff: NodeId = match bdd.xor(left, right) {
            Some(node) => node,
            None => return Equivalence::Unknown,
        };
        difference = match bdd.or(difference, bit_diff) {
            Some(node) => node,
            None => return Equivalence::Unknown,
        };
    }

    if difference == ZERO {
        return Equivalence::Proven;
    }
    let assignment: BTreeMap<u32, bool> = bdd.witness(difference);
    let dense_counterexample: Vec<u64> = decode_witness(&assignment, var_count, bits);
    let counterexample: Vec<u64> =
        match expand_counterexample(&dense_counterexample, &original_vars) {
            Some(counterexample) => counterexample,
            None => return Equivalence::Unknown,
        };
    Equivalence::Disproven { counterexample }
}

#[must_use]
pub fn classify_predicate(predicate: &Predicate, width: Width) -> OpaqueVerdict {
    classify_predicate_budgeted(predicate, width, DEFAULT_NODE_BUDGET)
}

#[must_use]
pub fn classify_predicate_budgeted(
    predicate: &Predicate,
    width: Width,
    node_budget: usize,
) -> OpaqueVerdict {
    if predicate.depth() > crate::expr::MAX_MBA_DEPTH {
        return OpaqueVerdict::OutOfBudget;
    }
    let compact: Predicate = predicate.compact();
    let bits: usize = width.bits() as usize;
    let mut vars: BTreeSet<u32> = BTreeSet::new();
    collect_predicate_vars(&compact, &mut vars);
    let var_count: usize = vars.len();
    let Some(input_bits): Option<usize> = var_count.checked_mul(bits) else {
        return OpaqueVerdict::OutOfBudget;
    };
    if input_bits > MAX_INPUT_BITS || input_bits.saturating_add(2) > node_budget {
        return OpaqueVerdict::OutOfBudget;
    }
    let mut bdd: Bdd = Bdd::new(node_budget);
    let inputs: Vec<Vec<NodeId>> = match bdd.fresh_inputs(var_count, bits) {
        Some(inputs) => inputs,
        None => return OpaqueVerdict::OutOfBudget,
    };
    let root: NodeId = match blast_predicate(&mut bdd, &compact, &inputs, bits) {
        Some(root) => root,
        None => return OpaqueVerdict::OutOfBudget,
    };
    match root {
        ONE => OpaqueVerdict::AlwaysTrue {
            verified_width: width,
            lifted: false,
        },
        ZERO => OpaqueVerdict::AlwaysFalse {
            verified_width: width,
            lifted: false,
        },
        _ => OpaqueVerdict::DataDependent,
    }
}

fn collect_predicate_vars(predicate: &Predicate, into: &mut BTreeSet<u32>) {
    match predicate {
        Predicate::Nonzero(inner) => inner.collect_vars(into),
        Predicate::Compare { left, right, .. } => {
            left.collect_vars(into);
            right.collect_vars(into);
        }
        Predicate::Or(left, right) | Predicate::And(left, right) => {
            collect_predicate_vars(left, into);
            collect_predicate_vars(right, into);
        }
    }
}

fn decode_witness(assignment: &BTreeMap<u32, bool>, var_count: usize, bits: usize) -> Vec<u64> {
    let mut values: Vec<u64> = vec![0; var_count];
    for (var_index, value) in values.iter_mut().enumerate() {
        let mut word: u64 = 0;
        for bit in 0..bits {
            let label: u32 = bdd_var_label(var_index, bit, var_count);
            if matches!(assignment.get(&label), Some(true)) {
                word |= 1u64 << bit;
            }
        }
        *value = word;
    }
    values
}

fn expand_counterexample(dense_values: &[u64], original_vars: &[u32]) -> Option<Vec<u64>> {
    let Some(max_original): Option<u32> = original_vars.last().copied() else {
        return Some(Vec::new());
    };
    let slot_count: usize = usize::try_from(max_original).ok()?.checked_add(1)?;
    if slot_count > MAX_COUNTEREXAMPLE_SLOTS {
        return None;
    }
    let mut out: Vec<u64> = vec![0; slot_count];
    for (dense, original) in original_vars.iter().copied().enumerate() {
        let value: u64 = dense_values.get(dense).copied()?;
        let slot: usize = usize::try_from(original).ok()?;
        *out.get_mut(slot)? = value;
    }
    Some(out)
}

const fn bdd_var_label(var_index: usize, bit: usize, var_count: usize) -> u32 {
    (bit * var_count + var_index) as u32
}

type NodeId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Node {
    var: u32,
    low: NodeId,
    high: NodeId,
}

#[derive(Debug)]
struct Bdd {
    nodes: Vec<Node>,
    unique: BTreeMap<Node, NodeId>,
    and_cache: BTreeMap<(NodeId, NodeId), NodeId>,
    xor_cache: BTreeMap<(NodeId, NodeId), NodeId>,
    or_cache: BTreeMap<(NodeId, NodeId), NodeId>,
    not_cache: BTreeMap<NodeId, NodeId>,
    mem_vars: BTreeMap<(String, Width), Vec<NodeId>>,
    mem_next_label: u32,
    node_budget: usize,
    op_budget: usize,
    ops: usize,
}

const ZERO: NodeId = 0;
const ONE: NodeId = 1;

impl Bdd {
    fn new(node_budget: usize) -> Self {
        let terminal: Node = Node {
            var: u32::MAX,
            low: 0,
            high: 0,
        };
        Self {
            nodes: vec![terminal, terminal],
            unique: BTreeMap::new(),
            and_cache: BTreeMap::new(),
            xor_cache: BTreeMap::new(),
            or_cache: BTreeMap::new(),
            not_cache: BTreeMap::new(),
            mem_vars: BTreeMap::new(),
            mem_next_label: MEM_VAR_BASE,
            node_budget,
            op_budget: node_budget.saturating_mul(8),
            ops: 0,
        }
    }

    fn mem_opaque_bits(&mut self, key: (String, Width), bits: usize) -> Option<Vec<NodeId>> {
        if let Some(existing) = self.mem_vars.get(&key) {
            return Some(existing.clone());
        }
        let mut word: Vec<NodeId> = Vec::with_capacity(bits);
        for _ in 0..bits {
            let label: u32 = self.mem_next_label;
            self.mem_next_label = self.mem_next_label.checked_add(1)?;
            word.push(self.make_var(label)?);
        }
        self.mem_vars.insert(key, word.clone());
        Some(word)
    }

    fn charge_op(&mut self) -> Option<()> {
        self.ops += 1;
        (self.ops <= self.op_budget).then_some(())
    }

    fn fresh_inputs(&mut self, var_count: usize, bits: usize) -> Option<Vec<Vec<NodeId>>> {
        let mut out: Vec<Vec<NodeId>> = Vec::with_capacity(var_count);
        for var_index in 0..var_count {
            let mut word: Vec<NodeId> = Vec::with_capacity(bits);
            for bit in 0..bits {
                let label: u32 = bdd_var_label(var_index, bit, var_count);
                word.push(self.make_var(label)?);
            }
            out.push(word);
        }
        Some(out)
    }

    fn make_var(&mut self, var: u32) -> Option<NodeId> {
        self.make_node(var, ZERO, ONE)
    }

    fn make_node(&mut self, var: u32, low: NodeId, high: NodeId) -> Option<NodeId> {
        if low == high {
            return Some(low);
        }
        let node: Node = Node { var, low, high };
        if let Some(existing) = self.unique.get(&node) {
            return Some(*existing);
        }
        if self.nodes.len() >= self.node_budget {
            return None;
        }
        let id: NodeId = u32::try_from(self.nodes.len()).ok()?;
        self.nodes.push(node);
        self.unique.insert(node, id);
        Some(id)
    }

    const fn is_terminal(id: NodeId) -> bool {
        id == ZERO || id == ONE
    }

    fn not(&mut self, id: NodeId) -> Option<NodeId> {
        match id {
            ZERO => Some(ONE),
            ONE => Some(ZERO),
            _ => {
                if let Some(cached) = self.not_cache.get(&id) {
                    return Some(*cached);
                }
                self.charge_op()?;
                let node: Node = self.nodes[id as usize];
                let low: NodeId = self.not(node.low)?;
                let high: NodeId = self.not(node.high)?;
                let result: NodeId = self.make_node(node.var, low, high)?;
                self.not_cache.insert(id, result);
                Some(result)
            }
        }
    }

    fn and(&mut self, a: NodeId, b: NodeId) -> Option<NodeId> {
        if a == ZERO || b == ZERO {
            return Some(ZERO);
        }
        if a == ONE {
            return Some(b);
        }
        if b == ONE {
            return Some(a);
        }
        if a == b {
            return Some(a);
        }
        let key: (NodeId, NodeId) = if a <= b { (a, b) } else { (b, a) };
        if let Some(cached) = self.and_cache.get(&key) {
            return Some(*cached);
        }
        self.charge_op()?;
        let na: Node = self.nodes[a as usize];
        let nb: Node = self.nodes[b as usize];
        let top: u32 = na.var.min(nb.var);
        let (a_low, a_high): (NodeId, NodeId) = cofactor(na, a, top);
        let (b_low, b_high): (NodeId, NodeId) = cofactor(nb, b, top);
        let low: NodeId = self.and(a_low, b_low)?;
        let high: NodeId = self.and(a_high, b_high)?;
        let result: NodeId = self.make_node(top, low, high)?;
        self.and_cache.insert(key, result);
        Some(result)
    }

    fn xor(&mut self, a: NodeId, b: NodeId) -> Option<NodeId> {
        if a == ZERO {
            return Some(b);
        }
        if b == ZERO {
            return Some(a);
        }
        if a == b {
            return Some(ZERO);
        }
        if a == ONE {
            return self.not(b);
        }
        if b == ONE {
            return self.not(a);
        }
        let key: (NodeId, NodeId) = if a <= b { (a, b) } else { (b, a) };
        if let Some(cached) = self.xor_cache.get(&key) {
            return Some(*cached);
        }
        self.charge_op()?;
        let na: Node = self.nodes[a as usize];
        let nb: Node = self.nodes[b as usize];
        let top: u32 = na.var.min(nb.var);
        let (a_low, a_high): (NodeId, NodeId) = cofactor(na, a, top);
        let (b_low, b_high): (NodeId, NodeId) = cofactor(nb, b, top);
        let low: NodeId = self.xor(a_low, b_low)?;
        let high: NodeId = self.xor(a_high, b_high)?;
        let result: NodeId = self.make_node(top, low, high)?;
        self.xor_cache.insert(key, result);
        Some(result)
    }

    fn or(&mut self, a: NodeId, b: NodeId) -> Option<NodeId> {
        if a == ONE || b == ONE {
            return Some(ONE);
        }
        if a == ZERO {
            return Some(b);
        }
        if b == ZERO {
            return Some(a);
        }
        if a == b {
            return Some(a);
        }
        let key: (NodeId, NodeId) = if a <= b { (a, b) } else { (b, a) };
        if let Some(cached) = self.or_cache.get(&key) {
            return Some(*cached);
        }
        self.charge_op()?;
        let na: Node = self.nodes[a as usize];
        let nb: Node = self.nodes[b as usize];
        let top: u32 = na.var.min(nb.var);
        let (a_low, a_high): (NodeId, NodeId) = cofactor(na, a, top);
        let (b_low, b_high): (NodeId, NodeId) = cofactor(nb, b, top);
        let low: NodeId = self.or(a_low, b_low)?;
        let high: NodeId = self.or(a_high, b_high)?;
        let result: NodeId = self.make_node(top, low, high)?;
        self.or_cache.insert(key, result);
        Some(result)
    }

    fn witness(&self, root: NodeId) -> BTreeMap<u32, bool> {
        let mut assignment: BTreeMap<u32, bool> = BTreeMap::new();
        let mut current: NodeId = root;
        while !Self::is_terminal(current) {
            let node: Node = self.nodes[current as usize];
            let take_high: bool = node.high != ZERO;
            assignment.insert(node.var, take_high);
            current = if take_high { node.high } else { node.low };
        }
        assignment
    }
}

const fn cofactor(node: Node, id: NodeId, top: u32) -> (NodeId, NodeId) {
    if node.var == top {
        (node.low, node.high)
    } else {
        (id, id)
    }
}

fn blast(bdd: &mut Bdd, expr: &Expr, inputs: &[Vec<NodeId>], bits: usize) -> Option<Vec<NodeId>> {
    match expr {
        Expr::Const(value) => Some(const_bits(*value, bits)),
        Expr::Var(index) => Some(
            inputs
                .get(*index as usize)
                .map_or_else(|| const_bits(0, bits), Clone::clone),
        ),
        Expr::Unary(op, inner) => {
            let value: Vec<NodeId> = blast(bdd, inner, inputs, bits)?;
            match op {
                UnOp::Not => bit_not(bdd, &value),
                UnOp::Neg => negate(bdd, &value),
            }
        }
        Expr::Binary(op, left, right) => {
            let lhs: Vec<NodeId> = blast(bdd, left, inputs, bits)?;
            let rhs: Vec<NodeId> = blast(bdd, right, inputs, bits)?;
            match op {
                BinOp::And => bit_and(bdd, &lhs, &rhs),
                BinOp::Or => bit_or(bdd, &lhs, &rhs),
                BinOp::Xor => bit_xor(bdd, &lhs, &rhs),
                BinOp::Add => ripple_add(bdd, &lhs, &rhs).map(|(sum, _)| sum),
                BinOp::Sub => ripple_sub(bdd, &lhs, &rhs),
                BinOp::Mul => multiply(bdd, &lhs, &rhs),
                BinOp::Shl => shift_left(bdd, &lhs, &rhs, bits),
                BinOp::Shr => shift_right(bdd, &lhs, &rhs, bits),
            }
        }
        Expr::Ite(cond, then, otherwise) => {
            let cond_bits: Vec<NodeId> = blast(bdd, cond, inputs, bits)?;
            let then_bits: Vec<NodeId> = blast(bdd, then, inputs, bits)?;
            let else_bits: Vec<NodeId> = blast(bdd, otherwise, inputs, bits)?;
            let selector: NodeId = nonzero(bdd, &cond_bits)?;
            select_word(bdd, selector, &then_bits, &else_bits)
        }
        Expr::Slice(inner, lo, hi) => {
            let value: Vec<NodeId> = blast(bdd, inner, inputs, bits)?;
            Some(slice_bits(&value, *lo as usize, *hi as usize, bits))
        }
        Expr::Compose(low, high, low_bits) => {
            let low_word: Vec<NodeId> = blast(bdd, low, inputs, bits)?;
            let high_word: Vec<NodeId> = blast(bdd, high, inputs, bits)?;
            Some(compose_bits(
                &low_word,
                &high_word,
                *low_bits as usize,
                bits,
            ))
        }
        Expr::Mem(addr, load_width) => {
            let key: (String, Width) = (format!("{addr}"), *load_width);
            let opaque: Vec<NodeId> = bdd.mem_opaque_bits(key, bits)?;
            Some(mem_zero_extend(&opaque, load_width.bits() as usize, bits))
        }
    }
}

fn blast_predicate(
    bdd: &mut Bdd,
    predicate: &Predicate,
    inputs: &[Vec<NodeId>],
    bits: usize,
) -> Option<NodeId> {
    match predicate {
        Predicate::Nonzero(inner) => {
            let value: Vec<NodeId> = blast(bdd, inner, inputs, bits)?;
            nonzero(bdd, &value)
        }
        Predicate::Compare { op, left, right } => {
            let lhs: Vec<NodeId> = blast(bdd, left, inputs, bits)?;
            let rhs: Vec<NodeId> = blast(bdd, right, inputs, bits)?;
            compare_word(bdd, *op, &lhs, &rhs)
        }
        Predicate::Or(left, right) => {
            let lhs: NodeId = blast_predicate(bdd, left, inputs, bits)?;
            let rhs: NodeId = blast_predicate(bdd, right, inputs, bits)?;
            bdd.or(lhs, rhs)
        }
        Predicate::And(left, right) => {
            let lhs: NodeId = blast_predicate(bdd, left, inputs, bits)?;
            let rhs: NodeId = blast_predicate(bdd, right, inputs, bits)?;
            bdd.and(lhs, rhs)
        }
    }
}

fn compare_word(bdd: &mut Bdd, op: CmpOp, lhs: &[NodeId], rhs: &[NodeId]) -> Option<NodeId> {
    match op {
        CmpOp::Eq => word_eq(bdd, lhs, rhs),
        CmpOp::Ne => {
            let equal: NodeId = word_eq(bdd, lhs, rhs)?;
            bdd.not(equal)
        }
        CmpOp::UnsignedLt => unsigned_lt(bdd, lhs, rhs),
        CmpOp::UnsignedLe => {
            let greater: NodeId = unsigned_lt(bdd, rhs, lhs)?;
            bdd.not(greater)
        }
        CmpOp::UnsignedGt => unsigned_lt(bdd, rhs, lhs),
        CmpOp::UnsignedGe => {
            let less: NodeId = unsigned_lt(bdd, lhs, rhs)?;
            bdd.not(less)
        }
        CmpOp::SignedLt => signed_lt(bdd, lhs, rhs),
        CmpOp::SignedLe => {
            let greater: NodeId = signed_lt(bdd, rhs, lhs)?;
            bdd.not(greater)
        }
        CmpOp::SignedGt => signed_lt(bdd, rhs, lhs),
        CmpOp::SignedGe => {
            let less: NodeId = signed_lt(bdd, lhs, rhs)?;
            bdd.not(less)
        }
    }
}

fn word_eq(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<NodeId> {
    let mut equal: NodeId = ONE;
    for (&left, &right) in lhs.iter().zip(rhs.iter()) {
        let diff: NodeId = bdd.xor(left, right)?;
        let same: NodeId = bdd.not(diff)?;
        equal = bdd.and(equal, same)?;
    }
    Some(equal)
}

fn unsigned_lt(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<NodeId> {
    let mut less: NodeId = ZERO;
    let mut equal: NodeId = ONE;
    for (&left, &right) in lhs.iter().zip(rhs.iter()).rev() {
        let not_left: NodeId = bdd.not(left)?;
        let bit_less: NodeId = bdd.and(not_left, right)?;
        let gated_less: NodeId = bdd.and(equal, bit_less)?;
        less = bdd.or(less, gated_less)?;
        let diff: NodeId = bdd.xor(left, right)?;
        let same: NodeId = bdd.not(diff)?;
        equal = bdd.and(equal, same)?;
    }
    Some(less)
}

fn signed_lt(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<NodeId> {
    let lhs_sign: NodeId = lhs.last().copied()?;
    let rhs_sign: NodeId = rhs.last().copied()?;
    let lhs_neg_rhs_pos: NodeId = {
        let rhs_nonneg: NodeId = bdd.not(rhs_sign)?;
        bdd.and(lhs_sign, rhs_nonneg)?
    };
    let sign_diff: NodeId = bdd.xor(lhs_sign, rhs_sign)?;
    let same_sign: NodeId = bdd.not(sign_diff)?;
    let unsigned_less: NodeId = unsigned_lt(bdd, lhs, rhs)?;
    let same_sign_less: NodeId = bdd.and(same_sign, unsigned_less)?;
    bdd.or(lhs_neg_rhs_pos, same_sign_less)
}

fn mem_zero_extend(value: &[NodeId], load_bits: usize, bits: usize) -> Vec<NodeId> {
    (0..bits)
        .map(|out_bit: usize| {
            if out_bit < load_bits {
                node_at_or_zero(value, out_bit)
            } else {
                ZERO
            }
        })
        .collect()
}

fn nonzero(bdd: &mut Bdd, word: &[NodeId]) -> Option<NodeId> {
    let mut acc: NodeId = ZERO;
    for &bit in word {
        acc = bdd.or(acc, bit)?;
    }
    Some(acc)
}

fn slice_bits(value: &[NodeId], lo: usize, hi: usize, bits: usize) -> Vec<NodeId> {
    let width: usize = hi.saturating_sub(lo);
    (0..bits)
        .map(|out_bit: usize| {
            if out_bit < width {
                node_at_or_zero(value, lo + out_bit)
            } else {
                ZERO
            }
        })
        .collect()
}

fn compose_bits(low: &[NodeId], high: &[NodeId], low_bits: usize, bits: usize) -> Vec<NodeId> {
    (0..bits)
        .map(|out_bit: usize| {
            if out_bit < low_bits {
                node_at_or_zero(low, out_bit)
            } else {
                node_at_or_zero(high, out_bit - low_bits)
            }
        })
        .collect()
}

fn const_bits(value: u64, bits: usize) -> Vec<NodeId> {
    (0..bits)
        .map(|bit: usize| if (value >> bit) & 1 == 1 { ONE } else { ZERO })
        .collect()
}

fn bit_not(bdd: &mut Bdd, value: &[NodeId]) -> Option<Vec<NodeId>> {
    let mut out: Vec<NodeId> = Vec::with_capacity(value.len());
    for &bit in value {
        out.push(bdd.not(bit)?);
    }
    Some(out)
}

fn bit_and(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<Vec<NodeId>> {
    zip_map(bdd, lhs, rhs, Bdd::and)
}

fn bit_or(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<Vec<NodeId>> {
    zip_map(bdd, lhs, rhs, Bdd::or)
}

fn bit_xor(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<Vec<NodeId>> {
    zip_map(bdd, lhs, rhs, Bdd::xor)
}

fn zip_map(
    bdd: &mut Bdd,
    lhs: &[NodeId],
    rhs: &[NodeId],
    op: fn(&mut Bdd, NodeId, NodeId) -> Option<NodeId>,
) -> Option<Vec<NodeId>> {
    let mut out: Vec<NodeId> = Vec::with_capacity(lhs.len());
    for (&left, &right) in lhs.iter().zip(rhs.iter()) {
        out.push(op(bdd, left, right)?);
    }
    Some(out)
}

fn full_adder(bdd: &mut Bdd, a: NodeId, b: NodeId, carry: NodeId) -> Option<(NodeId, NodeId)> {
    let a_xor_b: NodeId = bdd.xor(a, b)?;
    let sum: NodeId = bdd.xor(a_xor_b, carry)?;
    let a_and_b: NodeId = bdd.and(a, b)?;
    let carry_and_axb: NodeId = bdd.and(a_xor_b, carry)?;
    let carry_out: NodeId = bdd.or(a_and_b, carry_and_axb)?;
    Some((sum, carry_out))
}

fn ripple_add(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<(Vec<NodeId>, NodeId)> {
    let mut carry: NodeId = ZERO;
    let mut out: Vec<NodeId> = Vec::with_capacity(lhs.len());
    for (&a, &b) in lhs.iter().zip(rhs.iter()) {
        let (sum, carry_out): (NodeId, NodeId) = full_adder(bdd, a, b, carry)?;
        out.push(sum);
        carry = carry_out;
    }
    Some((out, carry))
}

fn negate(bdd: &mut Bdd, value: &[NodeId]) -> Option<Vec<NodeId>> {
    let inverted: Vec<NodeId> = bit_not(bdd, value)?;
    let one: Vec<NodeId> = const_bits(1, value.len());
    ripple_add(bdd, &inverted, &one).map(|(sum, _)| sum)
}

fn ripple_sub(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<Vec<NodeId>> {
    let negated: Vec<NodeId> = negate(bdd, rhs)?;
    ripple_add(bdd, lhs, &negated).map(|(sum, _)| sum)
}

fn multiply(bdd: &mut Bdd, lhs: &[NodeId], rhs: &[NodeId]) -> Option<Vec<NodeId>> {
    let bits: usize = lhs.len();
    let mut acc: Vec<NodeId> = const_bits(0, bits);
    for (shift, &rhs_bit) in rhs.iter().enumerate() {
        let mut partial: Vec<NodeId> = Vec::with_capacity(bits);
        for index in 0..bits {
            if index < shift {
                partial.push(ZERO);
            } else {
                let source: NodeId = lhs[index - shift];
                partial.push(bdd.and(source, rhs_bit)?);
            }
        }
        acc = ripple_add(bdd, &acc, &partial).map(|(sum, _)| sum)?;
    }
    Some(acc)
}

fn mux(bdd: &mut Bdd, selector: NodeId, on_true: NodeId, on_false: NodeId) -> Option<NodeId> {
    let not_sel: NodeId = bdd.not(selector)?;
    let when_true: NodeId = bdd.and(selector, on_true)?;
    let when_false: NodeId = bdd.and(not_sel, on_false)?;
    bdd.or(when_true, when_false)
}

fn select_word(
    bdd: &mut Bdd,
    selector: NodeId,
    on_true: &[NodeId],
    on_false: &[NodeId],
) -> Option<Vec<NodeId>> {
    let mut out: Vec<NodeId> = Vec::with_capacity(on_true.len());
    for (&t, &f) in on_true.iter().zip(on_false.iter()) {
        out.push(mux(bdd, selector, t, f)?);
    }
    Some(out)
}

fn shift_left(
    bdd: &mut Bdd,
    value: &[NodeId],
    amount: &[NodeId],
    bits: usize,
) -> Option<Vec<NodeId>> {
    barrel_shift(bdd, value, amount, bits, ShiftDir::Left)
}

fn shift_right(
    bdd: &mut Bdd,
    value: &[NodeId],
    amount: &[NodeId],
    bits: usize,
) -> Option<Vec<NodeId>> {
    barrel_shift(bdd, value, amount, bits, ShiftDir::Right)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShiftDir {
    Left,
    Right,
}

fn barrel_shift(
    bdd: &mut Bdd,
    value: &[NodeId],
    amount: &[NodeId],
    bits: usize,
    dir: ShiftDir,
) -> Option<Vec<NodeId>> {
    let zero_word: Vec<NodeId> = const_bits(0, bits);
    let stages: u32 = stage_count(bits);
    let in_range: NodeId = amount_in_range(bdd, amount, stages, bits)?;
    let mut current: Vec<NodeId> = value.to_vec();
    for stage in 0..stages {
        let distance: usize = 1usize << stage;
        let shifted: Vec<NodeId> = static_shift(&current, distance, dir);
        let selector: NodeId = node_at_or_zero(amount, stage as usize);
        current = select_word(bdd, selector, &shifted, &current)?;
    }
    select_word(bdd, in_range, &current, &zero_word)
}

fn node_at_or_zero(nodes: &[NodeId], index: usize) -> NodeId {
    if index < nodes.len() {
        nodes[index]
    } else {
        ZERO
    }
}

const fn stage_count(bits: usize) -> u32 {
    let mut stages: u32 = 0;
    let mut span: usize = 1;
    while span < bits {
        span <<= 1;
        stages += 1;
    }
    stages
}

fn amount_in_range(bdd: &mut Bdd, amount: &[NodeId], stages: u32, bits: usize) -> Option<NodeId> {
    let mut in_range: NodeId = ONE;
    for (index, &bit) in amount.iter().enumerate() {
        if index >= stages as usize || (1usize << index) >= bits {
            let not_bit: NodeId = bdd.not(bit)?;
            in_range = bdd.and(in_range, not_bit)?;
        }
    }
    Some(in_range)
}

fn static_shift(value: &[NodeId], distance: usize, dir: ShiftDir) -> Vec<NodeId> {
    let bits: usize = value.len();
    let mut out: Vec<NodeId> = vec![ZERO; bits];
    for index in 0..bits {
        match dir {
            ShiftDir::Left => {
                if index >= distance {
                    out[index] = value[index - distance];
                }
            }
            ShiftDir::Right => {
                if index + distance < bits {
                    out[index] = value[index + distance];
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;

    fn small_widths() -> [Width; 5] {
        [Width::W1, Width::W2, Width::W4, Width::W8, Width::W16]
    }

    fn assert_agrees(lhs: &Expr, rhs: &Expr, width: Width, var_count: u32) {
        let exhaustive: bool = equivalent_exhaustive(lhs, rhs, width, var_count);
        let verdict: Equivalence = verify_equivalent(lhs, rhs, width);
        match verdict {
            Equivalence::Proven => assert!(
                exhaustive,
                "verifier proved `{lhs}` == `{rhs}` at {width:?} but exhaustive disagrees"
            ),
            Equivalence::Disproven { ref counterexample } => {
                assert!(
                    !exhaustive,
                    "verifier disproved `{lhs}` == `{rhs}` at {width:?} but exhaustive says equal"
                );
                let mut env: Vec<u64> =
                    vec![0; var_count.max(counterexample.len() as u32) as usize];
                for (slot, value) in env.iter_mut().zip(counterexample.iter()) {
                    *slot = *value;
                }
                assert_ne!(
                    lhs.eval(&env, width),
                    rhs.eval(&env, width),
                    "counterexample {counterexample:?} does not distinguish `{lhs}` and `{rhs}` at {width:?}"
                );
            }
            Equivalence::Unknown => {}
        }
    }

    fn corpus() -> Vec<Expr> {
        let x: Expr = Expr::var(0);
        let y: Expr = Expr::var(1);
        let z: Expr = Expr::var(2);
        vec![
            Expr::konst(0),
            Expr::konst(1),
            Expr::konst(0xFF),
            x.clone(),
            y.clone(),
            z.clone(),
            Expr::not(x.clone()),
            Expr::neg(x.clone()),
            Expr::add(x.clone(), y.clone()),
            Expr::sub(x.clone(), y.clone()),
            Expr::mul(x.clone(), y.clone()),
            Expr::and(x.clone(), y.clone()),
            Expr::or(x.clone(), y.clone()),
            Expr::xor(x.clone(), y.clone()),
            Expr::add(
                Expr::xor(x.clone(), y.clone()),
                Expr::mul(Expr::konst(2), Expr::and(x.clone(), y.clone())),
            ),
            Expr::add(
                Expr::and(x.clone(), y.clone()),
                Expr::xor(x.clone(), y.clone()),
            ),
            Expr::shl(x.clone(), Expr::konst(1)),
            Expr::shr(x.clone(), Expr::konst(2)),
            Expr::shl(x.clone(), y.clone()),
            Expr::add(x.clone(), Expr::add(y.clone(), z)),
            Expr::or(
                Expr::and(x.clone(), Expr::not(y.clone())),
                Expr::and(Expr::not(x), y),
            ),
        ]
    }

    #[test]
    fn differential_against_exhaustive_le_16_bits_3_vars() {
        let exprs: Vec<Expr> = corpus();
        for width in small_widths() {
            for (i, lhs) in exprs.iter().enumerate() {
                for rhs in exprs.iter().skip(i) {
                    let var_count: u32 = lhs
                        .max_var()
                        .map_or(0, |v: u32| v + 1)
                        .max(rhs.max_var().map_or(0, |v: u32| v + 1));
                    if var_count > 3 {
                        continue;
                    }
                    if !crate::expr::equivalent_exhaustive_runnable(width, var_count) {
                        continue;
                    }
                    assert_agrees(lhs, rhs, width, var_count);
                }
            }
        }
    }

    #[test]
    fn proves_xor_carry_addition_identity_at_32_bits() {
        let lhs: Expr = Expr::add(
            Expr::xor(Expr::var(0), Expr::var(1)),
            Expr::mul(Expr::konst(2), Expr::and(Expr::var(0), Expr::var(1))),
        );
        let rhs: Expr = Expr::add(Expr::var(0), Expr::var(1));
        assert_eq!(
            verify_equivalent(&lhs, &rhs, Width::W32),
            Equivalence::Proven
        );
    }

    #[test]
    fn compacts_sparse_variable_indices_before_blasting() {
        let lhs: Expr = Expr::add(Expr::var(1_000_000), Expr::konst(7));
        let rhs: Expr = Expr::add(Expr::konst(7), Expr::var(1_000_000));
        assert_eq!(
            verify_equivalent(&lhs, &rhs, Width::W64),
            Equivalence::Proven
        );
    }

    #[test]
    fn refuses_input_vectors_above_bit_budget() {
        let mut lhs: Expr = Expr::konst(0);
        for index in 0..9u32 {
            lhs = Expr::add(lhs, Expr::var(index));
        }
        let mut rhs: Expr = Expr::konst(0);
        for index in (0..9u32).rev() {
            rhs = Expr::add(rhs, Expr::var(index));
        }
        assert_eq!(
            verify_equivalent_budgeted(&lhs, &rhs, Width::W64, DEFAULT_NODE_BUDGET),
            Equivalence::Unknown
        );
    }

    #[test]
    fn proves_or_as_and_plus_xor_at_64_bits() {
        let lhs: Expr = Expr::add(
            Expr::and(Expr::var(0), Expr::var(1)),
            Expr::xor(Expr::var(0), Expr::var(1)),
        );
        let rhs: Expr = Expr::or(Expr::var(0), Expr::var(1));
        assert_eq!(
            verify_equivalent(&lhs, &rhs, Width::W64),
            Equivalence::Proven
        );
    }

    #[test]
    fn proves_neg_is_not_plus_one_at_64_bits() {
        let lhs: Expr = Expr::neg(Expr::var(0));
        let rhs: Expr = Expr::add(Expr::not(Expr::var(0)), Expr::konst(1));
        assert_eq!(
            verify_equivalent(&lhs, &rhs, Width::W64),
            Equivalence::Proven
        );
    }

    #[test]
    fn proves_xor_decomposition_at_64_bits() {
        let lhs: Expr = Expr::xor(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::or(
            Expr::and(Expr::var(0), Expr::not(Expr::var(1))),
            Expr::and(Expr::not(Expr::var(0)), Expr::var(1)),
        );
        assert_eq!(
            verify_equivalent(&lhs, &rhs, Width::W64),
            Equivalence::Proven
        );
    }

    #[test]
    fn proves_sub_via_complement_at_64_bits() {
        let lhs: Expr = Expr::sub(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::add(Expr::var(0), Expr::neg(Expr::var(1)));
        assert_eq!(
            verify_equivalent(&lhs, &rhs, Width::W64),
            Equivalence::Proven
        );
    }

    #[test]
    fn disproves_add_versus_sub_at_64_bits() {
        let lhs: Expr = Expr::add(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::sub(Expr::var(0), Expr::var(1));
        let verdict: Equivalence = verify_equivalent(&lhs, &rhs, Width::W64);
        match verdict {
            Equivalence::Disproven { counterexample } => {
                let mut env: Vec<u64> = vec![0; 2];
                for (slot, value) in env.iter_mut().zip(counterexample.iter()) {
                    *slot = *value;
                }
                assert_ne!(lhs.eval(&env, Width::W64), rhs.eval(&env, Width::W64));
            }
            other => panic!("expected disproven, got {other:?}"),
        }
    }

    #[test]
    fn disproves_or_versus_xor_at_64_bits() {
        let lhs: Expr = Expr::or(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::xor(Expr::var(0), Expr::var(1));
        assert!(verify_equivalent(&lhs, &rhs, Width::W64).is_disproven());
    }

    #[test]
    fn never_proves_a_real_difference_under_tiny_budget() {
        let lhs: Expr = Expr::mul(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::mul(Expr::var(1), Expr::var(0));
        let verdict: Equivalence = verify_equivalent_budgeted(&lhs, &rhs, Width::W64, 8);
        assert!(matches!(
            verdict,
            Equivalence::Unknown | Equivalence::Proven
        ));
    }

    #[test]
    fn proves_mul_commutativity_at_narrow_width() {
        let lhs: Expr = Expr::mul(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::mul(Expr::var(1), Expr::var(0));
        assert_eq!(
            verify_equivalent(&lhs, &rhs, Width::W4),
            Equivalence::Proven
        );
    }

    #[test]
    fn wide_symbolic_multiplier_never_falsely_proven() {
        let lhs: Expr = Expr::mul(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::mul(Expr::var(1), Expr::konst(3));
        let verdict: Equivalence = verify_equivalent(&lhs, &rhs, Width::W64);
        assert!(
            !verdict.is_proven(),
            "non-equivalent wide multiplier must never be Proven, got {verdict:?}"
        );
    }

    #[test]
    fn symbolic_shift_left_matches_eval_disproof() {
        let lhs: Expr = Expr::shl(Expr::var(0), Expr::var(1));
        let rhs: Expr = Expr::mul(Expr::var(0), Expr::konst(4));
        assert!(verify_equivalent(&lhs, &rhs, Width::W8).is_disproven());
    }

    #[test]
    fn proves_compose_of_slices_is_identity() {
        let split: Expr = Expr::compose(
            Expr::slice(Expr::var(0), 0, 4),
            Expr::slice(Expr::var(0), 4, 8),
            4,
        );
        assert_eq!(
            verify_equivalent(&split, &Expr::var(0), Width::W8),
            Equivalence::Proven
        );
    }

    #[test]
    fn proves_ite_true_branch_via_const_one() {
        let lhs: Expr = Expr::ite(Expr::konst(1), Expr::var(0), Expr::var(1));
        assert_eq!(
            verify_equivalent(&lhs, &Expr::var(0), Width::W8),
            Equivalence::Proven
        );
    }

    #[test]
    fn proves_ite_false_branch_via_const_zero() {
        let lhs: Expr = Expr::ite(Expr::konst(0), Expr::var(0), Expr::var(1));
        assert_eq!(
            verify_equivalent(&lhs, &Expr::var(1), Width::W8),
            Equivalence::Proven
        );
    }

    #[test]
    fn ite_as_bitwise_select_matches_mask_form() {
        let selected: Expr = Expr::ite(Expr::var(0), Expr::var(1), Expr::var(2));
        let mask_form: Expr = Expr::or(
            Expr::and(Expr::var(1), Expr::var(0)),
            Expr::and(Expr::var(2), Expr::not(Expr::var(0))),
        );
        assert!(
            verify_equivalent(&selected, &mask_form, Width::W8).is_disproven(),
            "word-level ite differs from per-bit mask select when cond is not 0/all-ones"
        );
    }

    #[test]
    fn slice_then_compose_zero_extends_disproves_against_full() {
        let low_nibble: Expr = Expr::slice(Expr::var(0), 0, 4);
        assert!(verify_equivalent(&low_nibble, &Expr::var(0), Width::W8).is_disproven());
    }

    #[test]
    fn structurally_equal_mem_reads_prove_equal() {
        let read: Expr = Expr::mem(Expr::var(0), Width::W32);
        assert_eq!(
            verify_equivalent(&read, &read.clone(), Width::W32),
            Equivalence::Proven
        );
    }

    #[test]
    fn distinct_address_mem_reads_are_never_proven_equal() {
        let read_a: Expr = Expr::mem(Expr::var(0), Width::W32);
        let read_b: Expr = Expr::mem(Expr::add(Expr::var(0), Expr::konst(4)), Width::W32);
        assert!(
            !verify_equivalent(&read_a, &read_b, Width::W32).is_proven(),
            "two reads from structurally-distinct addresses must never collapse"
        );
    }

    #[test]
    fn same_address_different_width_mem_reads_are_independent() {
        let byte_read: Expr = Expr::mem(Expr::var(0), Width::W8);
        let word_read: Expr = Expr::mem(Expr::var(0), Width::W32);
        assert!(
            !verify_equivalent(&byte_read, &word_read, Width::W32).is_proven(),
            "reads at the same address but different widths are distinct opaque terms"
        );
    }

    #[test]
    fn new_node_verifier_agrees_with_exhaustive() {
        let cases: [(Expr, Expr); 4] = [
            (
                Expr::compose(
                    Expr::slice(Expr::var(0), 0, 4),
                    Expr::slice(Expr::var(0), 4, 8),
                    4,
                ),
                Expr::var(0),
            ),
            (
                Expr::ite(Expr::konst(1), Expr::var(0), Expr::var(1)),
                Expr::var(0),
            ),
            (
                Expr::ite(Expr::konst(0), Expr::var(0), Expr::var(1)),
                Expr::var(1),
            ),
            (
                Expr::slice(Expr::var(0), 0, 4),
                Expr::and(Expr::var(0), Expr::konst(0x0F)),
            ),
        ];
        for (lhs, rhs) in &cases {
            let var_count: u32 = lhs
                .max_var()
                .map_or(0, |v: u32| v + 1)
                .max(rhs.max_var().map_or(0, |v: u32| v + 1));
            assert_agrees(lhs, rhs, Width::W8, var_count);
        }
    }

    #[test]
    fn predicate_bdd_handles_signed_compare() {
        let predicate: Predicate = Predicate::Compare {
            op: CmpOp::SignedLt,
            left: Expr::konst(0xFF),
            right: Expr::konst(0),
        };
        assert_eq!(
            classify_predicate(&predicate, Width::W8),
            OpaqueVerdict::AlwaysTrue {
                verified_width: Width::W8,
                lifted: false
            }
        );
    }
}
