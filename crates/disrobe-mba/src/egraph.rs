use crate::expr::{BinOp, Expr, MAX_MBA_DEPTH, UnOp, Width, shift_left, shift_right};
use crate::rewrite::canonicalize;
use crate::rules::egraph_rules::{EgraphRule, Term, egraph_rules};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const MAX_INPUT_NODES: usize = 48;
const MAX_LEAVES: usize = 32;
const MAX_CLASSES: usize = 2000;
const MAX_ITERATIONS: u32 = 10;
const MAX_APPLICATIONS: usize = 12_000;
const MIXING_PENALTY: u64 = 2;

type Id = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum RingOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

impl RingOp {
    pub(crate) fn from_symbol(symbol: &str) -> Option<Self> {
        match symbol {
            "add" => Some(Self::Add),
            "sub" => Some(Self::Sub),
            "mul" => Some(Self::Mul),
            "and" => Some(Self::And),
            "or" => Some(Self::Or),
            "xor" => Some(Self::Xor),
            "shl" => Some(Self::Shl),
            "shr" => Some(Self::Shr),
            _ => None,
        }
    }

    const fn from_bin_op(op: BinOp) -> Self {
        match op {
            BinOp::Add => Self::Add,
            BinOp::Sub => Self::Sub,
            BinOp::Mul => Self::Mul,
            BinOp::And => Self::And,
            BinOp::Or => Self::Or,
            BinOp::Xor => Self::Xor,
            BinOp::Shl => Self::Shl,
            BinOp::Shr => Self::Shr,
        }
    }

    const fn to_bin_op(self) -> BinOp {
        match self {
            Self::Add => BinOp::Add,
            Self::Sub => BinOp::Sub,
            Self::Mul => BinOp::Mul,
            Self::And => BinOp::And,
            Self::Or => BinOp::Or,
            Self::Xor => BinOp::Xor,
            Self::Shl => BinOp::Shl,
            Self::Shr => BinOp::Shr,
        }
    }

    const fn node(self, left: Id, right: Id) -> ENode {
        match self {
            Self::Add => ENode::Add(left, right),
            Self::Sub => ENode::Sub(left, right),
            Self::Mul => ENode::Mul(left, right),
            Self::And => ENode::And(left, right),
            Self::Or => ENode::Or(left, right),
            Self::Xor => ENode::Xor(left, right),
            Self::Shl => ENode::Shl(left, right),
            Self::Shr => ENode::Shr(left, right),
        }
    }

    const fn is_commutative(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Mul | Self::And | Self::Or | Self::Xor
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ENode {
    Const(u64),
    Leaf(u32),
    Neg(Id),
    Not(Id),
    Add(Id, Id),
    Sub(Id, Id),
    Mul(Id, Id),
    And(Id, Id),
    Or(Id, Id),
    Xor(Id, Id),
    Shl(Id, Id),
    Shr(Id, Id),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pat {
    Var(u8),
    Lit(u64),
    AllOnes,
    Un(UnOp, Box<Self>),
    Bin(RingOp, Box<Self>, Box<Self>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopReason {
    Saturated,
    IterationLimit,
    ClassLimit,
    ApplicationLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    DepthAboveCap { depth: usize, max: usize },
    NodesAboveCap { nodes: usize, max: usize },
    LeafBudgetExhausted { max: usize },
    ClassBudgetExhausted { max: usize },
    NoExtraction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) stop: StopReason,
    pub(crate) iterations: u32,
    pub(crate) classes: usize,
    pub(crate) applications: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Saturation {
    Rewritten { expr: Expr, report: Report },
    Unchanged { report: Report },
    Refused(Refusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildStop {
    LeafBudget,
    ClassBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Neutral,
    Arithmetic,
    Bitwise,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Choice {
    cost: u64,
    shape: Shape,
    node: ENode,
}

fn compile_term(term: &Term, captures: &[String]) -> Option<Pat> {
    match term {
        Term::Capture(name) => {
            let index: usize = captures.iter().position(|known: &String| known == name)?;
            u8::try_from(index).ok().map(Pat::Var)
        }
        Term::Const(value) => Some(Pat::Lit(*value)),
        Term::AllOnes => Some(Pat::AllOnes),
        Term::Unary(op, inner) => {
            let inner: Pat = compile_term(inner, captures)?;
            Some(Pat::Un(*op, Box::new(inner)))
        }
        Term::Binary(op, left, right) => {
            let left: Pat = compile_term(left, captures)?;
            let right: Pat = compile_term(right, captures)?;
            Some(Pat::Bin(*op, Box::new(left), Box::new(right)))
        }
    }
}

static COMPILED_RULES: OnceLock<Vec<(Pat, Pat)>> = OnceLock::new();

#[allow(
    clippy::panic,
    reason = "the e-graph rule table is a compile-time include_str! const whose loader guarantees every capture used by either side is recorded on the rule; an unresolvable capture here is a build-integrity bug, and failing loud beats silently running saturation on a truncated rule table"
)]
fn directed_rules() -> &'static [(Pat, Pat)] {
    COMPILED_RULES.get_or_init(|| {
        let mut compiled: Vec<(Pat, Pat)> = Vec::new();
        for (rule, pattern, rewrite) in egraph_rules().directed_pairs() {
            let named: &EgraphRule = rule;
            let (Some(pattern), Some(rewrite)): (Option<Pat>, Option<Pat>) = (
                compile_term(pattern, &named.captures),
                compile_term(rewrite, &named.captures),
            ) else {
                panic!(
                    "e-graph rule {} uses a capture the loader never recorded",
                    named.name
                );
            };
            compiled.push((pattern, rewrite));
        }
        compiled
    })
}

const fn enode_weight(node: &ENode) -> u64 {
    match node {
        ENode::Const(_) | ENode::Leaf(_) => 1,
        ENode::Add(_, _) | ENode::Sub(_, _) | ENode::Neg(_) | ENode::Not(_) => 2,
        ENode::And(_, _)
        | ENode::Or(_, _)
        | ENode::Xor(_, _)
        | ENode::Shl(_, _)
        | ENode::Shr(_, _) => 3,
        ENode::Mul(_, _) => 5,
    }
}

const fn enode_family(node: &ENode) -> Shape {
    match node {
        ENode::Const(_) | ENode::Leaf(_) | ENode::Shl(_, _) | ENode::Shr(_, _) => Shape::Neutral,
        ENode::Add(_, _) | ENode::Sub(_, _) | ENode::Mul(_, _) | ENode::Neg(_) => Shape::Arithmetic,
        ENode::And(_, _) | ENode::Or(_, _) | ENode::Xor(_, _) | ENode::Not(_) => Shape::Bitwise,
    }
}

const fn join_shape(left: Shape, right: Shape) -> Shape {
    match (left, right) {
        (Shape::Neutral, other) | (other, Shape::Neutral) => other,
        (Shape::Arithmetic, Shape::Arithmetic) => Shape::Arithmetic,
        (Shape::Bitwise, Shape::Bitwise) => Shape::Bitwise,
        _ => Shape::Mixed,
    }
}

fn combine_shape(family: Shape, children: &[Shape]) -> Shape {
    match family {
        Shape::Neutral => children
            .iter()
            .copied()
            .fold(Shape::Neutral, |carried: Shape, child: Shape| {
                join_shape(carried, child)
            }),
        Shape::Mixed => Shape::Mixed,
        Shape::Arithmetic => {
            if children
                .iter()
                .any(|shape: &Shape| matches!(shape, Shape::Bitwise | Shape::Mixed))
            {
                Shape::Mixed
            } else {
                Shape::Arithmetic
            }
        }
        Shape::Bitwise => {
            if children
                .iter()
                .any(|shape: &Shape| matches!(shape, Shape::Arithmetic | Shape::Mixed))
            {
                Shape::Mixed
            } else {
                Shape::Bitwise
            }
        }
    }
}

fn enode_children(node: &ENode) -> Vec<Id> {
    match node {
        ENode::Const(_) | ENode::Leaf(_) => Vec::new(),
        ENode::Neg(a) | ENode::Not(a) => vec![*a],
        ENode::Add(a, b)
        | ENode::Sub(a, b)
        | ENode::Mul(a, b)
        | ENode::And(a, b)
        | ENode::Or(a, b)
        | ENode::Xor(a, b)
        | ENode::Shl(a, b)
        | ENode::Shr(a, b) => vec![*a, *b],
    }
}

const fn bin_children(op: RingOp, node: &ENode) -> Option<(Id, Id)> {
    match (op, node) {
        (RingOp::Add, ENode::Add(a, b))
        | (RingOp::Sub, ENode::Sub(a, b))
        | (RingOp::Mul, ENode::Mul(a, b))
        | (RingOp::And, ENode::And(a, b))
        | (RingOp::Or, ENode::Or(a, b))
        | (RingOp::Xor, ENode::Xor(a, b))
        | (RingOp::Shl, ENode::Shl(a, b))
        | (RingOp::Shr, ENode::Shr(a, b)) => Some((*a, *b)),
        _ => None,
    }
}

#[derive(Debug)]
struct EGraph {
    width: Width,
    mask: u64,
    parents: Vec<Id>,
    class_nodes: Vec<BTreeSet<ENode>>,
    const_val: Vec<Option<u64>>,
    memo: BTreeMap<ENode, Id>,
    leaves: Vec<Expr>,
    applications: usize,
}

impl EGraph {
    const fn new(width: Width) -> Self {
        Self {
            width,
            mask: width.mask(),
            parents: Vec::new(),
            class_nodes: Vec::new(),
            const_val: Vec::new(),
            memo: BTreeMap::new(),
            leaves: Vec::new(),
            applications: 0,
        }
    }

    fn root(&self, id: Id) -> Id {
        let mut current: Id = id;
        while self.parents[current as usize] != current {
            current = self.parents[current as usize];
        }
        current
    }

    fn const_of(&self, id: Id) -> Option<u64> {
        self.const_val[self.root(id) as usize]
    }

    fn canonicalize_enode(&self, node: &ENode) -> ENode {
        match *node {
            ENode::Const(value) => ENode::Const(value & self.mask),
            ENode::Leaf(index) => ENode::Leaf(index),
            ENode::Neg(a) => ENode::Neg(self.root(a)),
            ENode::Not(a) => ENode::Not(self.root(a)),
            ENode::Sub(a, b) => ENode::Sub(self.root(a), self.root(b)),
            ENode::Add(a, b) => {
                let (x, y): (Id, Id) = sorted(self.root(a), self.root(b));
                ENode::Add(x, y)
            }
            ENode::Mul(a, b) => {
                let (x, y): (Id, Id) = sorted(self.root(a), self.root(b));
                ENode::Mul(x, y)
            }
            ENode::And(a, b) => {
                let (x, y): (Id, Id) = sorted(self.root(a), self.root(b));
                ENode::And(x, y)
            }
            ENode::Or(a, b) => {
                let (x, y): (Id, Id) = sorted(self.root(a), self.root(b));
                ENode::Or(x, y)
            }
            ENode::Xor(a, b) => {
                let (x, y): (Id, Id) = sorted(self.root(a), self.root(b));
                ENode::Xor(x, y)
            }
            ENode::Shl(a, b) => ENode::Shl(self.root(a), self.root(b)),
            ENode::Shr(a, b) => ENode::Shr(self.root(a), self.root(b)),
        }
    }

    fn fold_const(&self, node: &ENode) -> ENode {
        let mask: u64 = self.mask;
        match *node {
            ENode::Const(value) => ENode::Const(value & mask),
            ENode::Neg(a) => self.const_of(a).map_or(*node, |value: u64| {
                ENode::Const(value.wrapping_neg() & mask)
            }),
            ENode::Not(a) => self
                .const_of(a)
                .map_or(*node, |value: u64| ENode::Const(!value & mask)),
            ENode::Add(a, b) => self.fold_binary(node, a, b, u64::wrapping_add),
            ENode::Sub(a, b) => self.fold_binary(node, a, b, u64::wrapping_sub),
            ENode::Mul(a, b) => self.fold_binary(node, a, b, u64::wrapping_mul),
            ENode::And(a, b) => self.fold_binary(node, a, b, |x, y| x & y),
            ENode::Or(a, b) => self.fold_binary(node, a, b, |x, y| x | y),
            ENode::Xor(a, b) => self.fold_binary(node, a, b, |x, y| x ^ y),
            ENode::Shl(a, b) => self.fold_shift_left(node, a, b),
            ENode::Shr(a, b) => self.fold_shift_right(node, a, b),
            ENode::Leaf(_) => *node,
        }
    }

    fn fold_binary(&self, node: &ENode, a: Id, b: Id, combine: fn(u64, u64) -> u64) -> ENode {
        match (self.const_of(a), self.const_of(b)) {
            (Some(left), Some(right)) => ENode::Const(combine(left, right) & self.mask),
            _ => *node,
        }
    }

    fn fold_shift_right(&self, node: &ENode, value: Id, amount: Id) -> ENode {
        if self.const_of(value) == Some(0) {
            return ENode::Const(0);
        }
        let Some(shift): Option<u64> = self.const_of(amount) else {
            return *node;
        };
        if shift >= u64::from(self.width.bits()) {
            return ENode::Const(0);
        }
        self.const_of(value).map_or(*node, |base: u64| {
            ENode::Const(shift_right(base, shift, self.width) & self.mask)
        })
    }

    fn fold_shift_left(&self, node: &ENode, value: Id, amount: Id) -> ENode {
        if self.const_of(value) == Some(0) {
            return ENode::Const(0);
        }
        let Some(shift): Option<u64> = self.const_of(amount) else {
            return *node;
        };
        if shift >= u64::from(self.width.bits()) {
            return ENode::Const(0);
        }
        self.const_of(value).map_or(*node, |base: u64| {
            ENode::Const(shift_left(base, shift, self.width) & self.mask)
        })
    }

    fn add(&mut self, raw: ENode) -> Option<Id> {
        let canonical: ENode = self.canonicalize_enode(&raw);
        let folded: ENode = self.canonicalize_enode(&self.fold_const(&canonical));
        if let Some(&existing) = self.memo.get(&folded) {
            return Some(self.root(existing));
        }
        if self.parents.len() >= MAX_CLASSES {
            return None;
        }
        let id: Id = u32::try_from(self.parents.len()).ok()?;
        self.parents.push(id);
        let mut set: BTreeSet<ENode> = BTreeSet::new();
        set.insert(folded);
        self.class_nodes.push(set);
        let value: Option<u64> = match folded {
            ENode::Const(value) => Some(value & self.mask),
            _ => None,
        };
        self.const_val.push(value);
        self.memo.insert(folded, id);
        Some(id)
    }

    fn union(&mut self, a: Id, b: Id) -> bool {
        let root_a: Id = self.root(a);
        let root_b: Id = self.root(b);
        if root_a == root_b {
            return false;
        }
        let (keep, gone): (Id, Id) = sorted(root_a, root_b);
        self.parents[gone as usize] = keep;
        if self.const_val[keep as usize].is_none() {
            self.const_val[keep as usize] = self.const_val[gone as usize];
        }
        self.const_val[gone as usize] = None;
        let gone_nodes: BTreeSet<ENode> = std::mem::take(&mut self.class_nodes[gone as usize]);
        for node in gone_nodes {
            self.class_nodes[keep as usize].insert(node);
        }
        true
    }

    fn rebuild(&mut self) {
        loop {
            let mut entries: Vec<(ENode, Id)> = Vec::new();
            for id in 0..self.parents.len() {
                let index: Id = u32::try_from(id).unwrap_or(Id::MAX);
                if self.root(index) != index {
                    continue;
                }
                for node in &self.class_nodes[id] {
                    entries.push((*node, index));
                }
            }
            let mut memo: BTreeMap<ENode, Id> = BTreeMap::new();
            let mut changed: bool = false;
            for (node, owner) in &entries {
                let canonical: ENode = self.canonicalize_enode(node);
                let owner_root: Id = self.root(*owner);
                if let Some(&existing) = memo.get(&canonical) {
                    if self.union(existing, owner_root) {
                        changed = true;
                    }
                } else {
                    memo.insert(canonical, owner_root);
                }
            }
            if changed {
                continue;
            }
            let mut fresh: Vec<BTreeSet<ENode>> = vec![BTreeSet::new(); self.parents.len()];
            for (node, owner) in &memo {
                let owner_root: Id = self.root(*owner);
                fresh[owner_root as usize].insert(*node);
            }
            self.class_nodes = fresh;
            self.memo = memo;
            return;
        }
    }

    fn ematch(&self, pat: &Pat, class: Id, binding: &BTreeMap<u8, Id>) -> Vec<BTreeMap<u8, Id>> {
        let class: Id = self.root(class);
        match pat {
            Pat::Var(key) => {
                if let Some(&bound) = binding.get(key) {
                    if self.root(bound) == class {
                        vec![binding.clone()]
                    } else {
                        Vec::new()
                    }
                } else {
                    let mut extended: BTreeMap<u8, Id> = binding.clone();
                    extended.insert(*key, class);
                    vec![extended]
                }
            }
            Pat::Lit(value) => {
                if self.const_of(class) == Some(*value & self.mask) {
                    vec![binding.clone()]
                } else {
                    Vec::new()
                }
            }
            Pat::AllOnes => {
                if self.const_of(class) == Some(self.mask) {
                    vec![binding.clone()]
                } else {
                    Vec::new()
                }
            }
            Pat::Un(op, inner) => self.ematch_unary(class, binding, inner, *op),
            Pat::Bin(op, left, right) => {
                let mut out: Vec<BTreeMap<u8, Id>> = Vec::new();
                for node in &self.class_nodes[class as usize] {
                    let Some((child_a, child_b)): Option<(Id, Id)> = bin_children(*op, node) else {
                        continue;
                    };
                    for first in self.ematch(left, child_a, binding) {
                        for complete in self.ematch(right, child_b, &first) {
                            out.push(complete);
                        }
                    }
                    if op.is_commutative() {
                        for first in self.ematch(left, child_b, binding) {
                            for complete in self.ematch(right, child_a, &first) {
                                out.push(complete);
                            }
                        }
                    }
                }
                out
            }
        }
    }

    fn ematch_unary(
        &self,
        class: Id,
        binding: &BTreeMap<u8, Id>,
        inner: &Pat,
        op: UnOp,
    ) -> Vec<BTreeMap<u8, Id>> {
        let mut out: Vec<BTreeMap<u8, Id>> = Vec::new();
        for node in &self.class_nodes[class as usize] {
            let child: Option<Id> = match (op, node) {
                (UnOp::Neg, ENode::Neg(a)) | (UnOp::Not, ENode::Not(a)) => Some(*a),
                _ => None,
            };
            if let Some(child) = child {
                for completed in self.ematch(inner, child, binding) {
                    out.push(completed);
                }
            }
        }
        out
    }

    fn collect_matches<'rules>(
        &self,
        rules: &'rules [(Pat, Pat)],
    ) -> Vec<(Id, &'rules Pat, BTreeMap<u8, Id>)> {
        let mut seen: BTreeSet<(Id, usize, BTreeMap<u8, Id>)> = BTreeSet::new();
        let mut out: Vec<(Id, &'rules Pat, BTreeMap<u8, Id>)> = Vec::new();
        let empty: BTreeMap<u8, Id> = BTreeMap::new();
        for id in 0..self.parents.len() {
            let index: Id = u32::try_from(id).unwrap_or(Id::MAX);
            if self.root(index) != index {
                continue;
            }
            for (rule_index, (pattern, rewrite)) in rules.iter().enumerate() {
                for binding in self.ematch(pattern, index, &empty) {
                    if seen.insert((index, rule_index, binding.clone())) {
                        out.push((index, rewrite, binding));
                    }
                }
            }
        }
        out
    }

    fn instantiate(&mut self, pat: &Pat, binding: &BTreeMap<u8, Id>) -> Option<Id> {
        match pat {
            Pat::Var(key) => binding.get(key).map(|&id| self.root(id)),
            Pat::Lit(value) => self.add(ENode::Const(*value & self.mask)),
            Pat::AllOnes => self.add(ENode::Const(self.mask)),
            Pat::Un(op, inner) => {
                let child: Id = self.instantiate(inner, binding)?;
                self.add(match op {
                    UnOp::Neg => ENode::Neg(child),
                    UnOp::Not => ENode::Not(child),
                })
            }
            Pat::Bin(op, left, right) => {
                let child_a: Id = self.instantiate(left, binding)?;
                let child_b: Id = self.instantiate(right, binding)?;
                self.add(op.node(child_a, child_b))
            }
        }
    }

    fn saturate(&mut self, rules: &[(Pat, Pat)]) -> Report {
        let mut iterations: u32 = 0;
        let mut stop: StopReason = StopReason::Saturated;
        while iterations < MAX_ITERATIONS {
            self.rebuild();
            if let Some(reason) = self.exhausted() {
                stop = reason;
                break;
            }
            iterations += 1;
            let matches: Vec<(Id, &Pat, BTreeMap<u8, Id>)> = self.collect_matches(rules);
            let mut changed: bool = false;
            let mut halted: Option<StopReason> = None;
            for (owner, rewrite, binding) in matches {
                if let Some(reason) = self.exhausted() {
                    halted = Some(reason);
                    break;
                }
                self.applications += 1;
                if let Some(instantiated) = self.instantiate(rewrite, &binding)
                    && self.union(owner, instantiated)
                {
                    changed = true;
                }
            }
            if let Some(reason) = halted {
                stop = reason;
                break;
            }
            if !changed {
                stop = StopReason::Saturated;
                break;
            }
            if iterations == MAX_ITERATIONS {
                stop = StopReason::IterationLimit;
            }
        }
        self.rebuild();
        Report {
            stop,
            iterations,
            classes: self.parents.len(),
            applications: self.applications,
        }
    }

    const fn exhausted(&self) -> Option<StopReason> {
        if self.parents.len() >= MAX_CLASSES {
            return Some(StopReason::ClassLimit);
        }
        if self.applications >= MAX_APPLICATIONS {
            return Some(StopReason::ApplicationLimit);
        }
        None
    }

    fn build_from_expr(&mut self, expr: &Expr) -> Result<Id, BuildStop> {
        match expr {
            Expr::Const(value) => self
                .add(ENode::Const(*value & self.mask))
                .ok_or(BuildStop::ClassBudget),
            Expr::Unary(op, inner) => {
                let child: Id = self.build_from_expr(inner)?;
                self.add(match op {
                    UnOp::Neg => ENode::Neg(child),
                    UnOp::Not => ENode::Not(child),
                })
                .ok_or(BuildStop::ClassBudget)
            }
            Expr::Binary(BinOp::Shl, left, right) => self.build_shl(left, right),
            Expr::Binary(op, left, right) => {
                let ring: RingOp = RingOp::from_bin_op(*op);
                let child_a: Id = self.build_from_expr(left)?;
                let child_b: Id = self.build_from_expr(right)?;
                self.add(ring.node(child_a, child_b))
                    .ok_or(BuildStop::ClassBudget)
            }
            Expr::Var(_)
            | Expr::Ite(_, _, _)
            | Expr::Slice(_, _, _)
            | Expr::Compose(_, _, _)
            | Expr::Mem(_, _) => self.leaf(expr),
        }
    }

    fn build_shl(&mut self, left: &Expr, right: &Expr) -> Result<Id, BuildStop> {
        if let Expr::Const(amount) = right
            && *amount < u64::from(self.width.bits())
        {
            let factor: u64 = (1u64 << amount) & self.mask;
            let child: Id = self.build_from_expr(left)?;
            let constant: Id = self
                .add(ENode::Const(factor))
                .ok_or(BuildStop::ClassBudget)?;
            return self
                .add(ENode::Mul(constant, child))
                .ok_or(BuildStop::ClassBudget);
        }
        let child_a: Id = self.build_from_expr(left)?;
        let child_b: Id = self.build_from_expr(right)?;
        self.add(ENode::Shl(child_a, child_b))
            .ok_or(BuildStop::ClassBudget)
    }

    fn leaf(&mut self, expr: &Expr) -> Result<Id, BuildStop> {
        let index: usize =
            if let Some(existing) = self.leaves.iter().position(|known: &Expr| known == expr) {
                existing
            } else {
                if self.leaves.len() >= MAX_LEAVES {
                    return Err(BuildStop::LeafBudget);
                }
                self.leaves.push(expr.clone());
                self.leaves.len() - 1
            };
        let key: u32 = u32::try_from(index).map_err(|_| BuildStop::LeafBudget)?;
        self.add(ENode::Leaf(key)).ok_or(BuildStop::ClassBudget)
    }

    fn best_choices(&self) -> BTreeMap<Id, Choice> {
        let mut best: BTreeMap<Id, Choice> = BTreeMap::new();
        loop {
            let mut changed: bool = false;
            for id in 0..self.parents.len() {
                let index: Id = u32::try_from(id).unwrap_or(Id::MAX);
                if self.root(index) != index {
                    continue;
                }
                for node in &self.class_nodes[id] {
                    let Some(candidate): Option<Choice> = self.evaluate(node, &best) else {
                        continue;
                    };
                    let better: bool = best.get(&index).is_none_or(|current: &Choice| {
                        candidate.cost < current.cost
                            || (candidate.cost == current.cost && *node < current.node)
                    });
                    if better {
                        best.insert(index, candidate);
                        changed = true;
                    }
                }
            }
            if !changed {
                return best;
            }
        }
    }

    fn extract(&self, root: Id) -> Option<Expr> {
        let root: Id = self.root(root);
        let best: BTreeMap<Id, Choice> = self.best_choices();
        let mut cache: BTreeMap<Id, Expr> = BTreeMap::new();
        self.build_expr(root, &best, &mut cache, 0)
    }

    fn evaluate(&self, node: &ENode, best: &BTreeMap<Id, Choice>) -> Option<Choice> {
        let mut cost: u64 = enode_weight(node);
        let mut shapes: Vec<Shape> = Vec::new();
        for child in enode_children(node) {
            let choice: &Choice = best.get(&self.root(child))?;
            cost = cost.saturating_add(choice.cost);
            shapes.push(choice.shape);
        }
        let shape: Shape = combine_shape(enode_family(node), &shapes);
        if shape == Shape::Mixed {
            cost = cost.saturating_add(MIXING_PENALTY);
        }
        Some(Choice {
            cost,
            shape,
            node: *node,
        })
    }

    fn build_expr(
        &self,
        id: Id,
        best: &BTreeMap<Id, Choice>,
        cache: &mut BTreeMap<Id, Expr>,
        depth: usize,
    ) -> Option<Expr> {
        if depth > MAX_MBA_DEPTH {
            return None;
        }
        let id: Id = self.root(id);
        if let Some(existing) = cache.get(&id) {
            return Some(existing.clone());
        }
        let choice: &Choice = best.get(&id)?;
        let built: Expr = match choice.node {
            ENode::Const(value) => Expr::konst(value & self.mask),
            ENode::Leaf(index) => self.leaves.get(index as usize)?.clone(),
            ENode::Neg(a) => Expr::neg(self.build_expr(a, best, cache, depth + 1)?),
            ENode::Not(a) => Expr::not(self.build_expr(a, best, cache, depth + 1)?),
            ENode::Add(a, b) => self.build_binary(RingOp::Add, a, b, best, cache, depth)?,
            ENode::Sub(a, b) => self.build_binary(RingOp::Sub, a, b, best, cache, depth)?,
            ENode::Mul(a, b) => self.build_binary(RingOp::Mul, a, b, best, cache, depth)?,
            ENode::And(a, b) => self.build_binary(RingOp::And, a, b, best, cache, depth)?,
            ENode::Or(a, b) => self.build_binary(RingOp::Or, a, b, best, cache, depth)?,
            ENode::Xor(a, b) => self.build_binary(RingOp::Xor, a, b, best, cache, depth)?,
            ENode::Shl(a, b) => self.build_binary(RingOp::Shl, a, b, best, cache, depth)?,
            ENode::Shr(a, b) => self.build_binary(RingOp::Shr, a, b, best, cache, depth)?,
        };
        cache.insert(id, built.clone());
        Some(built)
    }

    fn build_binary(
        &self,
        op: RingOp,
        left: Id,
        right: Id,
        best: &BTreeMap<Id, Choice>,
        cache: &mut BTreeMap<Id, Expr>,
        depth: usize,
    ) -> Option<Expr> {
        let left: Expr = self.build_expr(left, best, cache, depth + 1)?;
        let right: Expr = self.build_expr(right, best, cache, depth + 1)?;
        Some(Expr::Binary(
            op.to_bin_op(),
            Box::new(left),
            Box::new(right),
        ))
    }
}

const fn sorted(a: Id, b: Id) -> (Id, Id) {
    if a <= b { (a, b) } else { (b, a) }
}

fn saturate_with(expr: &Expr, width: Width, rules: &[(Pat, Pat)]) -> Saturation {
    let depth: usize = expr.depth();
    if depth > MAX_MBA_DEPTH {
        return Saturation::Refused(Refusal::DepthAboveCap {
            depth,
            max: MAX_MBA_DEPTH,
        });
    }
    let normalized: Expr = canonicalize(expr, width);
    let nodes: usize = normalized.node_count();
    if nodes > MAX_INPUT_NODES {
        return Saturation::Refused(Refusal::NodesAboveCap {
            nodes,
            max: MAX_INPUT_NODES,
        });
    }
    let mut graph: EGraph = EGraph::new(width);
    let root: Id = match graph.build_from_expr(&normalized) {
        Ok(root) => root,
        Err(BuildStop::LeafBudget) => {
            return Saturation::Refused(Refusal::LeafBudgetExhausted { max: MAX_LEAVES });
        }
        Err(BuildStop::ClassBudget) => {
            return Saturation::Refused(Refusal::ClassBudgetExhausted { max: MAX_CLASSES });
        }
    };
    let report: Report = graph.saturate(rules);
    let Some(extracted): Option<Expr> = graph.extract(root) else {
        return Saturation::Refused(Refusal::NoExtraction);
    };
    let cleaned: Expr = canonicalize(&extracted, width);
    if cleaned == normalized || cleaned == *expr {
        Saturation::Unchanged { report }
    } else {
        Saturation::Rewritten {
            expr: cleaned,
            report,
        }
    }
}

pub(crate) fn saturate(expr: &Expr, width: Width) -> Saturation {
    saturate_with(expr, width, directed_rules())
}

#[must_use]
pub(crate) fn saturate_simplify(expr: &Expr, width: Width) -> Option<Expr> {
    match saturate(expr, width) {
        Saturation::Rewritten { expr, report: _ } => Some(expr),
        Saturation::Unchanged { report: _ } | Saturation::Refused(_) => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;
    use crate::rules::egraph_rules::load_egraph_rules;

    fn pat_to_expr(pat: &Pat, width: Width) -> Expr {
        match pat {
            Pat::Var(index) => Expr::var(u32::from(*index)),
            Pat::Lit(value) => Expr::konst(*value & width.mask()),
            Pat::AllOnes => Expr::konst(width.mask()),
            Pat::Un(op, inner) => Expr::Unary(*op, Box::new(pat_to_expr(inner, width))),
            Pat::Bin(op, left, right) => Expr::Binary(
                op.to_bin_op(),
                Box::new(pat_to_expr(left, width)),
                Box::new(pat_to_expr(right, width)),
            ),
        }
    }

    fn pat_vars(pat: &Pat, seen: &mut BTreeSet<u8>) {
        match pat {
            Pat::Var(index) => {
                seen.insert(*index);
            }
            Pat::Lit(_) | Pat::AllOnes => {}
            Pat::Un(_, inner) => pat_vars(inner, seen),
            Pat::Bin(_, left, right) => {
                pat_vars(left, seen);
                pat_vars(right, seen);
            }
        }
    }

    #[test]
    fn every_shipped_rule_is_a_proven_equivalence_at_every_exhaustible_narrow_width() {
        let rules: &[(Pat, Pat)] = directed_rules();
        assert!(
            rules.len() >= 40,
            "compiled rule table is unexpectedly small"
        );
        for (pattern, rewrite) in rules {
            let mut seen: BTreeSet<u8> = BTreeSet::new();
            pat_vars(pattern, &mut seen);
            pat_vars(rewrite, &mut seen);
            let var_count: u32 = seen
                .iter()
                .next_back()
                .map_or(0, |highest: &u8| u32::from(*highest) + 1);
            for width in [Width::W1, Width::W2, Width::W4, Width::W8] {
                let left: Expr = pat_to_expr(pattern, width);
                let right: Expr = pat_to_expr(rewrite, width);
                assert!(
                    equivalent_exhaustive(&left, &right, width, var_count),
                    "rule `{left}` == `{right}` fails at {width:?}"
                );
            }
        }
    }

    #[test]
    fn the_rule_table_is_data_not_code() {
        let set = egraph_rules();
        assert!(set.rules.len() >= 30);
        let compiled: usize = directed_rules().len();
        assert_eq!(compiled, set.directed_pairs().len());
        let names: BTreeSet<&str> = set
            .rules
            .iter()
            .map(|rule: &EgraphRule| rule.name.as_str())
            .collect();
        assert!(names.contains("add_from_xor_and_carry"));
        assert!(names.contains("or_from_xor_plus_and"));
    }

    struct Rng {
        state: u64,
    }

    impl Rng {
        const fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        const fn next(&mut self) -> u64 {
            self.state = self
                .state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.state >> 17
        }

        const fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    fn random_expr(rng: &mut Rng, depth: u32, vars: u32) -> Expr {
        if depth == 0 || rng.below(100) < 30 {
            return match rng.below(4) {
                0 => Expr::konst(rng.next()),
                1 => opaque_leaf(rng, vars),
                _ => Expr::var(rng.below(u64::from(vars)) as u32),
            };
        }
        match rng.below(11) {
            0 => Expr::add(
                random_expr(rng, depth - 1, vars),
                random_expr(rng, depth - 1, vars),
            ),
            1 => Expr::sub(
                random_expr(rng, depth - 1, vars),
                random_expr(rng, depth - 1, vars),
            ),
            2 => Expr::and(
                random_expr(rng, depth - 1, vars),
                random_expr(rng, depth - 1, vars),
            ),
            3 => Expr::or(
                random_expr(rng, depth - 1, vars),
                random_expr(rng, depth - 1, vars),
            ),
            4 => Expr::xor(
                random_expr(rng, depth - 1, vars),
                random_expr(rng, depth - 1, vars),
            ),
            5 => Expr::not(random_expr(rng, depth - 1, vars)),
            6 => Expr::neg(random_expr(rng, depth - 1, vars)),
            7 => Expr::mul(
                random_expr(rng, depth - 1, vars),
                random_expr(rng, depth - 1, vars),
            ),
            8 => Expr::shr(
                random_expr(rng, depth - 1, vars),
                Expr::konst(rng.below(10)),
            ),
            9 => Expr::shr(
                random_expr(rng, depth - 1, vars),
                Expr::var(rng.below(u64::from(vars)) as u32),
            ),
            _ => Expr::mul(Expr::konst(rng.next()), random_expr(rng, depth - 1, vars)),
        }
    }

    fn opaque_leaf(rng: &mut Rng, vars: u32) -> Expr {
        let base: u32 = rng.below(u64::from(vars)) as u32;
        match rng.below(2) {
            0 => Expr::mul(Expr::var(base), Expr::var((base + 1) % vars)),
            _ => Expr::shr(Expr::var(base), Expr::konst(1 + rng.below(2))),
        }
    }

    #[test]
    fn saturation_never_emits_a_non_equivalent_rewrite() {
        let mut rng: Rng = Rng::new(0x51ED_2A17_C0FF_EE01);
        let mut fired: u32 = 0;
        let mut non_equivalent: u32 = 0;
        let iterations: u32 = 2000;
        for _ in 0..iterations {
            let vars: u32 = 1 + rng.below(3) as u32;
            let depth: u32 = 2 + rng.below(3) as u32;
            let expr: Expr = random_expr(&mut rng, depth, vars);
            for width in [Width::W4, Width::W8] {
                if width == Width::W8 && vars > 2 {
                    continue;
                }
                if !crate::expr::equivalent_exhaustive_runnable(width, vars) {
                    continue;
                }
                let Some(candidate): Option<Expr> = saturate_simplify(&expr, width) else {
                    continue;
                };
                fired += 1;
                if !equivalent_exhaustive(&expr, &candidate, width, vars) {
                    non_equivalent += 1;
                }
                let repeat: Option<Expr> = saturate_simplify(&expr, width);
                assert_eq!(
                    repeat.as_ref(),
                    Some(&candidate),
                    "non-deterministic output"
                );
            }
        }
        assert_eq!(non_equivalent, 0, "L5 emitted a non-equivalent rewrite");
        assert!(
            fired > 0,
            "expected L5 to fire on at least one random input"
        );
    }

    #[test]
    fn every_saturation_run_respects_its_declared_caps() {
        let mut rng: Rng = Rng::new(0x0E64_2A17_5AFE_0001);
        let mut ran: u32 = 0;
        for _ in 0..400 {
            let vars: u32 = 1 + rng.below(4) as u32;
            let depth: u32 = 2 + rng.below(4) as u32;
            let expr: Expr = random_expr(&mut rng, depth, vars);
            for width in [Width::W4, Width::W8, Width::W32, Width::W64] {
                let report: Report = match saturate(&expr, width) {
                    Saturation::Rewritten { report, .. } | Saturation::Unchanged { report } => {
                        report
                    }
                    Saturation::Refused(_) => continue,
                };
                ran += 1;
                assert!(
                    report.iterations <= MAX_ITERATIONS,
                    "saturation ran {} iterations, above the {MAX_ITERATIONS} cap",
                    report.iterations
                );
                assert!(
                    report.classes <= MAX_CLASSES,
                    "saturation held {} classes, above the {MAX_CLASSES} cap",
                    report.classes
                );
                assert!(
                    report.applications <= MAX_APPLICATIONS,
                    "saturation applied {} rewrites, above the {MAX_APPLICATIONS} cap",
                    report.applications
                );
            }
        }
        assert!(ran > 0, "no saturation run reached the cap assertions");
    }

    #[test]
    fn a_wide_associative_sum_stops_at_the_class_cap() {
        let mut expr: Expr = Expr::var(0);
        for index in 1..14u32 {
            expr = Expr::add(expr, Expr::var(index));
        }
        let report: Report = match saturate(&expr, Width::W32) {
            Saturation::Rewritten { report, .. } | Saturation::Unchanged { report } => report,
            Saturation::Refused(refusal) => panic!("expected saturation to run, got {refusal:?}"),
        };
        assert_eq!(
            report.stop,
            StopReason::ClassLimit,
            "a 14 term associative sum must exhaust the class cap, got {report:?}"
        );
        assert!(report.classes >= MAX_CLASSES);
    }

    #[test]
    fn a_small_input_saturates_instead_of_hitting_a_cap() {
        let expr: Expr = Expr::add(
            Expr::xor(Expr::var(0), Expr::var(1)),
            Expr::mul(Expr::konst(2), Expr::and(Expr::var(0), Expr::var(1))),
        );
        let report: Report = match saturate(&expr, Width::W8) {
            Saturation::Rewritten { report, .. } | Saturation::Unchanged { report } => report,
            Saturation::Refused(refusal) => panic!("expected saturation to run, got {refusal:?}"),
        };
        assert_eq!(report.stop, StopReason::Saturated);
        assert!(report.iterations >= 1);
    }

    #[test]
    fn every_expression_node_kind_is_interpreted_or_interned_as_an_opaque_leaf() {
        let kinds: Vec<(&str, Expr)> = vec![
            ("const", Expr::konst(7)),
            ("var", Expr::var(0)),
            ("unary", Expr::not(Expr::var(0))),
            ("binary", Expr::add(Expr::var(0), Expr::var(1))),
            ("ite", Expr::ite(Expr::var(0), Expr::var(1), Expr::var(2))),
            ("slice", Expr::slice(Expr::var(0), 0, 4)),
            ("compose", Expr::compose(Expr::var(0), Expr::var(1), 4)),
            ("mem", Expr::mem(Expr::var(0), Width::W8)),
            ("shift_right", Expr::shr(Expr::var(0), Expr::konst(1))),
            ("zero_width_slice", Expr::slice(Expr::var(0), 4, 4)),
            (
                "overlong_compose",
                Expr::compose(Expr::var(0), Expr::var(1), 64),
            ),
        ];
        for width in [
            Width::W1,
            Width::W2,
            Width::W4,
            Width::W8,
            Width::W16,
            Width::W32,
            Width::W64,
        ] {
            for (name, kind) in &kinds {
                let doubled: Expr = Expr::sub(kind.clone(), kind.clone());
                assert_eq!(
                    settled(&doubled, width),
                    Expr::konst(0),
                    "{name} at {width:?}: `{doubled}` must cancel to zero"
                );
                let complemented: Expr = Expr::and(kind.clone(), Expr::not(kind.clone()));
                assert_eq!(
                    settled(&complemented, width),
                    Expr::konst(0),
                    "{name} at {width:?}: `{complemented}` must cancel to zero"
                );
            }
        }
    }

    fn settled(expr: &Expr, width: Width) -> Expr {
        match saturate(expr, width) {
            Saturation::Rewritten { expr, report: _ } => expr,
            Saturation::Unchanged { report: _ } => canonicalize(expr, width),
            Saturation::Refused(refusal) => {
                panic!("`{expr}` at {width:?} was refused: {refusal:?}")
            }
        }
    }

    #[test]
    fn a_memory_load_stays_an_opaque_leaf() {
        let cell: Expr = Expr::mem(Expr::var(0), Width::W8);
        assert!(
            matches!(saturate(&cell, Width::W8), Saturation::Unchanged { .. }),
            "a bare load has no smaller equal form"
        );
        let distinct: Expr = Expr::sub(
            Expr::mem(Expr::var(0), Width::W8),
            Expr::mem(Expr::var(0), Width::W16),
        );
        assert!(
            matches!(
                saturate(&distinct, Width::W32),
                Saturation::Unchanged { .. }
            ),
            "loads of two different widths are two leaves and must not cancel"
        );
        let addressed: Expr = Expr::sub(
            Expr::mem(Expr::var(0), Width::W8),
            Expr::mem(Expr::var(1), Width::W8),
        );
        assert!(
            matches!(
                saturate(&addressed, Width::W32),
                Saturation::Unchanged { .. }
            ),
            "loads of two different addresses are two leaves and must not cancel"
        );
    }

    #[test]
    fn an_expression_at_the_depth_cap_yields_a_typed_outcome() {
        let mut expr: Expr = Expr::var(0);
        for _ in 1..MAX_MBA_DEPTH {
            expr = Expr::not(expr);
        }
        assert_eq!(expr.depth(), MAX_MBA_DEPTH);
        let outcome: Saturation = saturate(&expr, Width::W8);
        assert!(
            matches!(
                outcome,
                Saturation::Refused(Refusal::NodesAboveCap { .. })
                    | Saturation::Rewritten { .. }
                    | Saturation::Unchanged { .. }
            ),
            "a depth capped input must produce a typed outcome, got {outcome:?}"
        );
        let settled: crate::simplify::Simplification = crate::simplify::simplify(&expr, Width::W8);
        assert!(
            settled.verification.is_proven() || !settled.changed(),
            "a depth capped input must leave the pipeline with a proof or unchanged"
        );
        let mut inner: Expr = Expr::var(0);
        for _ in 2..MAX_MBA_DEPTH {
            inner = Expr::not(inner);
        }
        let predicate: crate::opaque::Predicate =
            crate::opaque::Predicate::eq(inner, Expr::konst(0));
        assert_eq!(predicate.depth(), MAX_MBA_DEPTH);
        let folded: crate::simplify::PredicateSimplification =
            crate::simplify::simplify_predicate(&predicate, Width::W8);
        assert!(
            folded.verification.is_proven() || !folded.changed(),
            "a depth capped predicate must leave the pipeline with a proof or unchanged"
        );

        let mut deeper: Expr = Expr::var(0);
        for _ in 0..MAX_MBA_DEPTH {
            deeper = Expr::not(deeper);
        }
        assert_eq!(
            saturate(&deeper, Width::W8),
            Saturation::Refused(Refusal::DepthAboveCap {
                depth: MAX_MBA_DEPTH + 1,
                max: MAX_MBA_DEPTH,
            })
        );
        let refused: crate::simplify::Simplification =
            crate::simplify::simplify(&deeper, Width::W8);
        assert!(!refused.changed());
    }

    #[test]
    fn an_oversized_input_is_refused_with_its_measured_node_count() {
        let mut expr: Expr = Expr::var(0);
        for index in 1..25u32 {
            expr = Expr::xor(expr, Expr::var(index));
        }
        assert!(expr.node_count() > MAX_INPUT_NODES);
        let outcome: Saturation = saturate(&expr, Width::W8);
        assert!(
            matches!(
                outcome,
                Saturation::Refused(Refusal::NodesAboveCap {
                    max: MAX_INPUT_NODES,
                    ..
                })
            ),
            "got {outcome:?}"
        );
        let mut collapsible: Expr = Expr::var(0);
        for _ in 0..MAX_INPUT_NODES {
            collapsible = Expr::add(collapsible, Expr::var(1));
        }
        assert!(
            matches!(
                saturate(&collapsible, Width::W8),
                Saturation::Rewritten { .. } | Saturation::Unchanged { .. }
            ),
            "a large input that canonicalization collapses must still reach saturation"
        );
    }

    #[test]
    fn a_leaf_flood_is_refused_by_the_leaf_budget() {
        let mut expr: Expr = Expr::mem(Expr::var(0), Width::W8);
        for index in 1..=u32::try_from(MAX_LEAVES).unwrap_or(u32::MAX) {
            expr = Expr::add(expr, Expr::mem(Expr::var(index), Width::W8));
        }
        assert!(expr.node_count() > MAX_INPUT_NODES);
        let outcome: Saturation = saturate(&expr, Width::W8);
        assert!(
            matches!(
                outcome,
                Saturation::Refused(
                    Refusal::LeafBudgetExhausted { .. } | Refusal::NodesAboveCap { .. }
                )
            ),
            "got {outcome:?}"
        );
    }

    #[test]
    fn opaque_leaf_or_and_sum_collapses_where_linear_layers_cannot() {
        let width: Width = Width::W8;
        let opaque: Expr = Expr::mul(Expr::var(0), Expr::var(1));
        let other: Expr = Expr::var(2);
        let obfuscated: Expr = Expr::add(
            Expr::or(opaque.clone(), other.clone()),
            Expr::and(opaque.clone(), other.clone()),
        );
        let Some(candidate): Option<Expr> = saturate_simplify(&obfuscated, width) else {
            panic!("L5 must collapse (a|b)+(a&b) with an opaque leaf");
        };
        assert!(equivalent_exhaustive(&obfuscated, &candidate, width, 3));
        assert!(candidate.node_count() < obfuscated.node_count());
        let expected: Expr = Expr::add(opaque, other);
        assert!(equivalent_exhaustive(&candidate, &expected, width, 3));
    }

    #[test]
    fn irreducible_product_is_left_untouched() {
        let genuine: Expr = Expr::mul(Expr::var(0), Expr::var(1));
        assert!(saturate_simplify(&genuine, Width::W8).is_none());
    }

    fn probe_rules(name: &str, pattern: &str, rewrite: &str) -> Vec<(Pat, Pat)> {
        let text: String = format!(
            "[[rules]]\nname = \"{name}\"\nprovenance = \"saturation probe\"\ndirection = \"contract\"\npattern = \"{pattern}\"\nrewrite = \"{rewrite}\"\n"
        );
        let set: crate::rules::egraph_rules::EgraphRuleSet = match load_egraph_rules(&text) {
            Ok(set) => set,
            Err(error) => panic!("probe rule must load: {error}"),
        };
        let mut compiled: Vec<(Pat, Pat)> = Vec::new();
        for (rule, pattern, rewrite) in set.directed_pairs() {
            let (Some(pattern), Some(rewrite)): (Option<Pat>, Option<Pat>) = (
                compile_term(pattern, &rule.captures),
                compile_term(rewrite, &rule.captures),
            ) else {
                panic!("probe rule must compile");
            };
            compiled.push((pattern, rewrite));
        }
        compiled
    }

    fn poisoned_rules() -> Vec<(Pat, Pat)> {
        probe_rules("poison_or_drops_an_operand", "(or ?x ?y)", "?x")
    }

    #[test]
    fn saturation_stops_at_the_iteration_cap() {
        let width: Width = Width::W32;
        let mut chain: Expr = Expr::add(Expr::var(14), Expr::var(15));
        for index in (0..14u32).rev() {
            chain = Expr::add(Expr::var(index), chain);
        }
        let expr: Expr = Expr::neg(chain);
        let rules: Vec<(Pat, Pat)> = probe_rules(
            "negation_distributes_over_addition",
            "(neg (add ?x ?y))",
            "(add (neg ?x) (neg ?y))",
        );
        for (pattern, rewrite) in &rules {
            let left: Expr = pat_to_expr(pattern, Width::W4);
            let right: Expr = pat_to_expr(rewrite, Width::W4);
            assert!(
                equivalent_exhaustive(&left, &right, Width::W4, 2),
                "the probe rule must be a real identity"
            );
        }
        let mut graph: EGraph = EGraph::new(width);
        let Ok(root): Result<Id, BuildStop> = graph.build_from_expr(&expr) else {
            panic!("the chain must build");
        };
        let report: Report = graph.saturate(&rules);
        assert_eq!(
            report.stop,
            StopReason::IterationLimit,
            "a sixteen term chain under one descending rule must exhaust the iteration cap, got {report:?}"
        );
        assert_eq!(report.iterations, MAX_ITERATIONS);
        assert!(
            report.classes < MAX_CLASSES,
            "the iteration cap must bind before the class cap, got {report:?}"
        );
        let Some(extracted): Option<Expr> = graph.extract(root) else {
            panic!("a capped run must still extract a term");
        };
        assert!(
            agrees_on_samples(&expr, &extracted, width, 16),
            "a capped run extracted `{extracted}`, which is not equal to its input"
        );
    }

    fn agrees_on_samples(lhs: &Expr, rhs: &Expr, width: Width, vars: u32) -> bool {
        let mut rng: Rng = Rng::new(0x5A17_0BEE_1234_9911);
        let mask: u64 = width.mask();
        for _ in 0..512u32 {
            let env: Vec<u64> = (0..vars).map(|_| rng.next() & mask).collect();
            if lhs.eval(&env, width) != rhs.eval(&env, width) {
                return false;
            }
        }
        true
    }

    #[test]
    fn a_deliberately_unsound_rule_produces_a_wrong_term_that_the_gate_refuses() {
        let width: Width = Width::W8;
        let original: Expr = Expr::add(
            Expr::or(Expr::var(0), Expr::var(1)),
            Expr::mul(Expr::var(0), Expr::var(1)),
        );
        let poisoned: Saturation = saturate_with(&original, width, &poisoned_rules());
        let Saturation::Rewritten { expr: wrong, .. } = poisoned else {
            panic!("the poisoned rule must produce a rewrite, otherwise the gate is untested");
        };
        assert!(
            !equivalent_exhaustive(&original, &wrong, width, 2),
            "the poisoned rewrite `{wrong}` is equivalent, so it cannot probe the gate"
        );
        assert_eq!(
            crate::simplify::accept_verified(&original, &wrong, width, 2),
            None,
            "the acceptance gate admitted a non-equivalent saturation result"
        );
        for gate_width in [Width::W16, Width::W32, Width::W64] {
            assert_eq!(
                crate::simplify::accept_verified(&original, &wrong, gate_width, 2),
                None,
                "{gate_width:?}: the acceptance gate admitted a non-equivalent saturation result"
            );
        }
        let clean: Expr = Expr::add(Expr::var(0), Expr::var(1));
        let source: Expr = Expr::add(
            Expr::xor(Expr::var(0), Expr::var(1)),
            Expr::mul(Expr::konst(2), Expr::and(Expr::var(0), Expr::var(1))),
        );
        assert!(
            crate::simplify::accept_verified(&source, &clean, width, 2).is_some(),
            "the same gate must admit a correct rewrite, otherwise the refusal above proves nothing"
        );
        for pipeline_width in [Width::W8, Width::W16, Width::W32, Width::W64] {
            let shipped: crate::simplify::Simplification =
                crate::simplify::simplify(&original, pipeline_width);
            assert_ne!(
                shipped.simplified, wrong,
                "{pipeline_width:?}: the shipping pipeline emitted the poisoned term"
            );
            assert!(
                shipped.verification.is_proven() || !shipped.changed(),
                "{pipeline_width:?}: the shipping pipeline changed the input without a proof"
            );
        }
    }

    #[test]
    fn extraction_prefers_the_unmixed_term_at_equal_size() {
        let width: Width = Width::W8;
        let mixed: Expr = Expr::add(Expr::var(0), Expr::not(Expr::var(1)));
        let unmixed: Expr = Expr::sub(Expr::var(0), Expr::add(Expr::var(1), Expr::konst(1)));
        assert!(
            equivalent_exhaustive(&mixed, &unmixed, width, 2),
            "the probe pair must be a real identity"
        );
        let mut graph: EGraph = EGraph::new(width);
        let (Ok(left), Ok(right)): (Result<Id, BuildStop>, Result<Id, BuildStop>) = (
            graph.build_from_expr(&mixed),
            graph.build_from_expr(&unmixed),
        ) else {
            panic!("probe terms must build");
        };
        graph.union(left, right);
        graph.rebuild();
        let Some(extracted): Option<Expr> = graph.extract(left) else {
            panic!("probe class must extract");
        };
        assert_eq!(
            extracted, unmixed,
            "extraction kept the mixed arithmetic and bitwise term `{extracted}`"
        );
    }

    #[test]
    fn the_shape_analysis_separates_mixed_terms_from_pure_ones() {
        let width: Width = Width::W8;
        let cases: Vec<(&str, Expr, Shape)> = vec![
            (
                "pure_arithmetic",
                Expr::add(Expr::var(0), Expr::var(1)),
                Shape::Arithmetic,
            ),
            (
                "pure_bitwise",
                Expr::and(Expr::var(0), Expr::var(1)),
                Shape::Bitwise,
            ),
            (
                "arithmetic_over_bitwise",
                Expr::add(Expr::var(0), Expr::and(Expr::var(0), Expr::var(1))),
                Shape::Mixed,
            ),
            (
                "bitwise_over_arithmetic",
                Expr::not(Expr::add(Expr::var(0), Expr::var(1))),
                Shape::Mixed,
            ),
            ("leaf", Expr::var(0), Shape::Neutral),
            (
                "shift_of_arithmetic",
                Expr::shr(Expr::add(Expr::var(0), Expr::var(1)), Expr::konst(1)),
                Shape::Arithmetic,
            ),
            (
                "shift_of_bitwise",
                Expr::shr(Expr::and(Expr::var(0), Expr::var(1)), Expr::konst(1)),
                Shape::Bitwise,
            ),
            (
                "arithmetic_over_shifted_bitwise",
                Expr::add(
                    Expr::var(2),
                    Expr::shr(Expr::and(Expr::var(0), Expr::var(1)), Expr::konst(1)),
                ),
                Shape::Mixed,
            ),
        ];
        for (name, expr, expected) in cases {
            let mut graph: EGraph = EGraph::new(width);
            let Ok(root): Result<Id, BuildStop> = graph.build_from_expr(&expr) else {
                panic!("{name} must build");
            };
            graph.rebuild();
            let best: BTreeMap<Id, Choice> = graph.best_choices();
            let Some(choice): Option<&Choice> = best.get(&graph.root(root)) else {
                panic!("{name} must have an extraction choice");
            };
            assert_eq!(choice.shape, expected, "{name} classified wrongly");
        }
    }
}
