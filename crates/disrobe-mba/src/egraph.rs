use crate::expr::{BinOp, Expr, UnOp, Width};
use crate::rewrite::canonicalize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_INPUT_NODES: usize = 48;
const MAX_LEAVES: usize = 32;
const MAX_ENODES: usize = 2000;
const MAX_ITERS: u32 = 10;
const MAX_APPLICATIONS: usize = 12_000;
const MAX_BUILD_DEPTH: u32 = 4096;

type Id = u32;

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
}

#[derive(Debug, Clone)]
enum Pat {
    Var(u8),
    Lit(u64),
    AllOnes,
    Neg(Box<Self>),
    Not(Box<Self>),
    Bin(BinOp, Box<Self>, Box<Self>),
}

const fn pvar(index: u8) -> Pat {
    Pat::Var(index)
}

fn pbin(op: BinOp, left: Pat, right: Pat) -> Pat {
    Pat::Bin(op, Box::new(left), Box::new(right))
}

fn pneg(inner: Pat) -> Pat {
    Pat::Neg(Box::new(inner))
}

fn pnot(inner: Pat) -> Pat {
    Pat::Not(Box::new(inner))
}

fn padd(left: Pat, right: Pat) -> Pat {
    pbin(BinOp::Add, left, right)
}

fn psub(left: Pat, right: Pat) -> Pat {
    pbin(BinOp::Sub, left, right)
}

fn pmul(left: Pat, right: Pat) -> Pat {
    pbin(BinOp::Mul, left, right)
}

fn pand(left: Pat, right: Pat) -> Pat {
    pbin(BinOp::And, left, right)
}

fn por(left: Pat, right: Pat) -> Pat {
    pbin(BinOp::Or, left, right)
}

fn pxor(left: Pat, right: Pat) -> Pat {
    pbin(BinOp::Xor, left, right)
}

fn contracting_identities() -> Vec<(Pat, Pat)> {
    vec![
        (
            padd(
                pxor(pvar(0), pvar(1)),
                pmul(Pat::Lit(2), pand(pvar(0), pvar(1))),
            ),
            padd(pvar(0), pvar(1)),
        ),
        (
            psub(
                pxor(pvar(0), pvar(1)),
                pmul(Pat::Lit(2), pand(pnot(pvar(0)), pvar(1))),
            ),
            psub(pvar(0), pvar(1)),
        ),
        (
            psub(padd(pvar(0), pvar(1)), pand(pvar(0), pvar(1))),
            por(pvar(0), pvar(1)),
        ),
        (
            padd(pxor(pvar(0), pvar(1)), pand(pvar(0), pvar(1))),
            por(pvar(0), pvar(1)),
        ),
        (
            psub(por(pvar(0), pvar(1)), pand(pvar(0), pvar(1))),
            pxor(pvar(0), pvar(1)),
        ),
        (
            psub(padd(pvar(0), pvar(1)), por(pvar(0), pvar(1))),
            pand(pvar(0), pvar(1)),
        ),
        (
            padd(por(pvar(0), pvar(1)), pand(pvar(0), pvar(1))),
            padd(pvar(0), pvar(1)),
        ),
        (padd(pvar(0), pneg(pvar(1))), psub(pvar(0), pvar(1))),
        (padd(pnot(pvar(0)), Pat::Lit(1)), pneg(pvar(0))),
        (psub(pneg(pvar(0)), Pat::Lit(1)), pnot(pvar(0))),
        (
            por(pnot(pvar(0)), pnot(pvar(1))),
            pnot(pand(pvar(0), pvar(1))),
        ),
        (
            pand(pnot(pvar(0)), pnot(pvar(1))),
            pnot(por(pvar(0), pvar(1))),
        ),
        (pxor(pnot(pvar(0)), pnot(pvar(1))), pxor(pvar(0), pvar(1))),
    ]
}

fn associativity() -> Vec<(Pat, Pat)> {
    vec![
        (
            padd(padd(pvar(0), pvar(1)), pvar(2)),
            padd(pvar(0), padd(pvar(1), pvar(2))),
        ),
        (
            pand(pand(pvar(0), pvar(1)), pvar(2)),
            pand(pvar(0), pand(pvar(1), pvar(2))),
        ),
        (
            por(por(pvar(0), pvar(1)), pvar(2)),
            por(pvar(0), por(pvar(1), pvar(2))),
        ),
        (
            pxor(pxor(pvar(0), pvar(1)), pvar(2)),
            pxor(pvar(0), pxor(pvar(1), pvar(2))),
        ),
    ]
}

fn directed_simplifiers() -> Vec<(Pat, Pat)> {
    vec![
        (pnot(pnot(pvar(0))), pvar(0)),
        (pneg(pneg(pvar(0))), pvar(0)),
        (pand(pvar(0), pvar(0)), pvar(0)),
        (por(pvar(0), pvar(0)), pvar(0)),
        (pxor(pvar(0), pvar(0)), Pat::Lit(0)),
        (psub(pvar(0), pvar(0)), Pat::Lit(0)),
        (pand(pvar(0), pnot(pvar(0))), Pat::Lit(0)),
        (por(pvar(0), pnot(pvar(0))), Pat::AllOnes),
        (pxor(pvar(0), pnot(pvar(0))), Pat::AllOnes),
        (pand(pvar(0), por(pvar(0), pvar(1))), pvar(0)),
        (por(pvar(0), pand(pvar(0), pvar(1))), pvar(0)),
        (padd(pvar(0), Pat::Lit(0)), pvar(0)),
        (psub(pvar(0), Pat::Lit(0)), pvar(0)),
        (pmul(pvar(0), Pat::Lit(1)), pvar(0)),
        (pmul(pvar(0), Pat::Lit(0)), Pat::Lit(0)),
        (pand(pvar(0), Pat::Lit(0)), Pat::Lit(0)),
        (pand(pvar(0), Pat::AllOnes), pvar(0)),
        (por(pvar(0), Pat::Lit(0)), pvar(0)),
        (por(pvar(0), Pat::AllOnes), Pat::AllOnes),
        (pxor(pvar(0), Pat::Lit(0)), pvar(0)),
    ]
}

fn directed_rules() -> Vec<(Pat, Pat)> {
    let mut rules: Vec<(Pat, Pat)> = contracting_identities();
    for (lhs, rhs) in associativity() {
        rules.push((lhs.clone(), rhs.clone()));
        rules.push((rhs, lhs));
    }
    rules.extend(directed_simplifiers());
    rules
}

const fn is_commutative(op: BinOp) -> bool {
    matches!(
        op,
        BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
    )
}

const fn enode_weight(node: &ENode) -> u64 {
    match node {
        ENode::Const(_) | ENode::Leaf(_) => 1,
        ENode::Add(_, _) | ENode::Sub(_, _) | ENode::Neg(_) | ENode::Not(_) => 2,
        ENode::And(_, _) | ENode::Or(_, _) | ENode::Xor(_, _) => 3,
        ENode::Mul(_, _) => 5,
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
        | ENode::Xor(a, b) => vec![*a, *b],
    }
}

const fn bin_children(op: BinOp, node: &ENode) -> Option<(Id, Id)> {
    match (op, node) {
        (BinOp::Add, ENode::Add(a, b))
        | (BinOp::Sub, ENode::Sub(a, b))
        | (BinOp::Mul, ENode::Mul(a, b))
        | (BinOp::And, ENode::And(a, b))
        | (BinOp::Or, ENode::Or(a, b))
        | (BinOp::Xor, ENode::Xor(a, b)) => Some((*a, *b)),
        _ => None,
    }
}

const fn bin_enode(op: BinOp, left: Id, right: Id) -> ENode {
    match op {
        BinOp::Add => ENode::Add(left, right),
        BinOp::Sub | BinOp::Shl | BinOp::Shr => ENode::Sub(left, right),
        BinOp::Mul => ENode::Mul(left, right),
        BinOp::And => ENode::And(left, right),
        BinOp::Or => ENode::Or(left, right),
        BinOp::Xor => ENode::Xor(left, right),
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
            ENode::Leaf(_) => *node,
        }
    }

    fn fold_binary(&self, node: &ENode, a: Id, b: Id, combine: fn(u64, u64) -> u64) -> ENode {
        match (self.const_of(a), self.const_of(b)) {
            (Some(left), Some(right)) => ENode::Const(combine(left, right) & self.mask),
            _ => *node,
        }
    }

    fn add(&mut self, raw: ENode) -> Option<Id> {
        let canonical: ENode = self.canonicalize_enode(&raw);
        let folded: ENode = self.canonicalize_enode(&self.fold_const(&canonical));
        if let Some(&existing) = self.memo.get(&folded) {
            return Some(self.root(existing));
        }
        if self.parents.len() >= MAX_ENODES {
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
            Pat::Neg(inner) => self.ematch_unary(class, binding, inner, true),
            Pat::Not(inner) => self.ematch_unary(class, binding, inner, false),
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
                    if is_commutative(*op) {
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
        is_neg: bool,
    ) -> Vec<BTreeMap<u8, Id>> {
        let mut out: Vec<BTreeMap<u8, Id>> = Vec::new();
        for node in &self.class_nodes[class as usize] {
            let child: Option<Id> = match (is_neg, node) {
                (true, ENode::Neg(a)) | (false, ENode::Not(a)) => Some(*a),
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

    fn collect_matches(&self, rules: &[(Pat, Pat)]) -> Vec<(Id, usize, BTreeMap<u8, Id>)> {
        let mut seen: BTreeSet<(Id, usize, BTreeMap<u8, Id>)> = BTreeSet::new();
        let mut out: Vec<(Id, usize, BTreeMap<u8, Id>)> = Vec::new();
        let empty: BTreeMap<u8, Id> = BTreeMap::new();
        for id in 0..self.parents.len() {
            let index: Id = u32::try_from(id).unwrap_or(Id::MAX);
            if self.root(index) != index {
                continue;
            }
            for (rule_index, (lhs, _rhs)) in rules.iter().enumerate() {
                for binding in self.ematch(lhs, index, &empty) {
                    let key: (Id, usize, BTreeMap<u8, Id>) = (index, rule_index, binding);
                    if seen.insert(key.clone()) {
                        out.push(key);
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
            Pat::Neg(inner) => {
                let child: Id = self.instantiate(inner, binding)?;
                self.add(ENode::Neg(child))
            }
            Pat::Not(inner) => {
                let child: Id = self.instantiate(inner, binding)?;
                self.add(ENode::Not(child))
            }
            Pat::Bin(op, left, right) => {
                let child_a: Id = self.instantiate(left, binding)?;
                let child_b: Id = self.instantiate(right, binding)?;
                self.add(bin_enode(*op, child_a, child_b))
            }
        }
    }

    fn saturate(&mut self, rules: &[(Pat, Pat)]) {
        for _ in 0..MAX_ITERS {
            self.rebuild();
            if self.parents.len() >= MAX_ENODES || self.applications >= MAX_APPLICATIONS {
                break;
            }
            let matches: Vec<(Id, usize, BTreeMap<u8, Id>)> = self.collect_matches(rules);
            let mut changed: bool = false;
            for (owner, rule_index, binding) in matches {
                if self.parents.len() >= MAX_ENODES || self.applications >= MAX_APPLICATIONS {
                    break;
                }
                self.applications += 1;
                let rhs: Pat = rules[rule_index].1.clone();
                if let Some(instantiated) = self.instantiate(&rhs, &binding)
                    && self.union(owner, instantiated)
                {
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        self.rebuild();
    }

    fn build_from_expr(&mut self, expr: &Expr) -> Option<Id> {
        match expr {
            Expr::Const(value) => self.add(ENode::Const(*value & self.mask)),
            Expr::Unary(UnOp::Neg, inner) => {
                let child: Id = self.build_from_expr(inner)?;
                self.add(ENode::Neg(child))
            }
            Expr::Unary(UnOp::Not, inner) => {
                let child: Id = self.build_from_expr(inner)?;
                self.add(ENode::Not(child))
            }
            Expr::Binary(BinOp::Shl, left, right) => self.build_shl(expr, left, right),
            Expr::Binary(
                op @ (BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor),
                left,
                right,
            ) => {
                let child_a: Id = self.build_from_expr(left)?;
                let child_b: Id = self.build_from_expr(right)?;
                self.add(bin_enode(*op, child_a, child_b))
            }
            Expr::Var(_)
            | Expr::Binary(BinOp::Shr, _, _)
            | Expr::Ite(_, _, _)
            | Expr::Slice(_, _, _)
            | Expr::Compose(_, _, _)
            | Expr::Mem(_, _) => self.leaf(expr),
        }
    }

    fn build_shl(&mut self, expr: &Expr, left: &Expr, right: &Expr) -> Option<Id> {
        if let Expr::Const(amount) = right
            && *amount < u64::from(self.width.bits())
        {
            let factor: u64 = (1u64 << amount) & self.mask;
            let child: Id = self.build_from_expr(left)?;
            let constant: Id = self.add(ENode::Const(factor))?;
            return self.add(ENode::Mul(constant, child));
        }
        self.leaf(expr)
    }

    fn leaf(&mut self, expr: &Expr) -> Option<Id> {
        let index: usize =
            if let Some(existing) = self.leaves.iter().position(|known: &Expr| known == expr) {
                existing
            } else {
                if self.leaves.len() >= MAX_LEAVES {
                    return None;
                }
                self.leaves.push(expr.clone());
                self.leaves.len() - 1
            };
        let key: u32 = u32::try_from(index).ok()?;
        self.add(ENode::Leaf(key))
    }

    fn extract(&self, root: Id) -> Option<Expr> {
        let root: Id = self.root(root);
        let mut best: BTreeMap<Id, (u64, ENode)> = BTreeMap::new();
        loop {
            let mut changed: bool = false;
            for id in 0..self.parents.len() {
                let index: Id = u32::try_from(id).unwrap_or(Id::MAX);
                if self.root(index) != index {
                    continue;
                }
                for node in &self.class_nodes[id] {
                    let Some(cost): Option<u64> = self.node_cost(node, &best) else {
                        continue;
                    };
                    let better: bool = match best.get(&index) {
                        None => true,
                        Some((current, current_node)) => {
                            cost < *current || (cost == *current && *node < *current_node)
                        }
                    };
                    if better {
                        best.insert(index, (cost, *node));
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let mut cache: BTreeMap<Id, Expr> = BTreeMap::new();
        self.build_expr(root, &best, &mut cache, 0)
    }

    fn node_cost(&self, node: &ENode, best: &BTreeMap<Id, (u64, ENode)>) -> Option<u64> {
        let mut total: u64 = enode_weight(node);
        for child in enode_children(node) {
            let (child_cost, _): &(u64, ENode) = best.get(&self.root(child))?;
            total = total.saturating_add(*child_cost);
        }
        Some(total)
    }

    fn build_expr(
        &self,
        id: Id,
        best: &BTreeMap<Id, (u64, ENode)>,
        cache: &mut BTreeMap<Id, Expr>,
        depth: u32,
    ) -> Option<Expr> {
        if depth > MAX_BUILD_DEPTH {
            return None;
        }
        let id: Id = self.root(id);
        if let Some(existing) = cache.get(&id) {
            return Some(existing.clone());
        }
        let (_, node): &(u64, ENode) = best.get(&id)?;
        let built: Expr = match *node {
            ENode::Const(value) => Expr::konst(value & self.mask),
            ENode::Leaf(index) => self.leaves.get(index as usize)?.clone(),
            ENode::Neg(a) => Expr::neg(self.build_expr(a, best, cache, depth + 1)?),
            ENode::Not(a) => Expr::not(self.build_expr(a, best, cache, depth + 1)?),
            ENode::Add(a, b) => Expr::add(
                self.build_expr(a, best, cache, depth + 1)?,
                self.build_expr(b, best, cache, depth + 1)?,
            ),
            ENode::Sub(a, b) => Expr::sub(
                self.build_expr(a, best, cache, depth + 1)?,
                self.build_expr(b, best, cache, depth + 1)?,
            ),
            ENode::Mul(a, b) => Expr::mul(
                self.build_expr(a, best, cache, depth + 1)?,
                self.build_expr(b, best, cache, depth + 1)?,
            ),
            ENode::And(a, b) => Expr::and(
                self.build_expr(a, best, cache, depth + 1)?,
                self.build_expr(b, best, cache, depth + 1)?,
            ),
            ENode::Or(a, b) => Expr::or(
                self.build_expr(a, best, cache, depth + 1)?,
                self.build_expr(b, best, cache, depth + 1)?,
            ),
            ENode::Xor(a, b) => Expr::xor(
                self.build_expr(a, best, cache, depth + 1)?,
                self.build_expr(b, best, cache, depth + 1)?,
            ),
        };
        cache.insert(id, built.clone());
        Some(built)
    }
}

const fn sorted(a: Id, b: Id) -> (Id, Id) {
    if a <= b { (a, b) } else { (b, a) }
}

#[must_use]
pub(crate) fn saturate_simplify(expr: &Expr, width: Width) -> Option<Expr> {
    if expr.depth() > crate::expr::MAX_MBA_DEPTH {
        return None;
    }
    let normalized: Expr = canonicalize(expr, width);
    if normalized.node_count() > MAX_INPUT_NODES {
        return None;
    }
    let mut graph: EGraph = EGraph::new(width);
    let root: Id = graph.build_from_expr(&normalized)?;
    graph.saturate(&directed_rules());
    let extracted: Expr = graph.extract(root)?;
    let cleaned: Expr = canonicalize(&extracted, width);
    if cleaned == normalized || cleaned == *expr {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::expr::equivalent_exhaustive;

    fn pat_to_expr(pat: &Pat, width: Width) -> Expr {
        match pat {
            Pat::Var(index) => Expr::var(u32::from(*index)),
            Pat::Lit(value) => Expr::konst(*value & width.mask()),
            Pat::AllOnes => Expr::konst(width.mask()),
            Pat::Neg(inner) => Expr::neg(pat_to_expr(inner, width)),
            Pat::Not(inner) => Expr::not(pat_to_expr(inner, width)),
            Pat::Bin(op, left, right) => Expr::Binary(
                *op,
                Box::new(pat_to_expr(left, width)),
                Box::new(pat_to_expr(right, width)),
            ),
        }
    }

    fn pat_var_count(pat: &Pat, seen: &mut BTreeSet<u8>) {
        match pat {
            Pat::Var(index) => {
                seen.insert(*index);
            }
            Pat::Lit(_) | Pat::AllOnes => {}
            Pat::Neg(inner) | Pat::Not(inner) => pat_var_count(inner, seen),
            Pat::Bin(_, left, right) => {
                pat_var_count(left, seen);
                pat_var_count(right, seen);
            }
        }
    }

    #[test]
    fn every_curated_rule_is_a_proven_equivalence() {
        let rules: Vec<(Pat, Pat)> = directed_rules();
        assert!(!rules.is_empty());
        for (lhs, rhs) in &rules {
            let mut seen: BTreeSet<u8> = BTreeSet::new();
            pat_var_count(lhs, &mut seen);
            pat_var_count(rhs, &mut seen);
            let var_count: u32 = seen
                .iter()
                .next_back()
                .map_or(0, |m: &u8| u32::from(*m) + 1);
            for width in [Width::W4, Width::W8] {
                let left: Expr = pat_to_expr(lhs, width);
                let right: Expr = pat_to_expr(rhs, width);
                assert!(
                    equivalent_exhaustive(&left, &right, width, var_count),
                    "rule `{left}` == `{right}` fails at {width:?}"
                );
            }
        }
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
        match rng.below(9) {
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
    fn oversized_input_abstains() {
        let mut expr: Expr = Expr::var(0);
        for _ in 0..MAX_INPUT_NODES {
            expr = Expr::add(expr, Expr::var(1));
        }
        assert!(saturate_simplify(&expr, Width::W8).is_none());
    }

    #[test]
    fn irreducible_product_is_left_untouched() {
        let genuine: Expr = Expr::mul(Expr::var(0), Expr::var(1));
        assert!(saturate_simplify(&genuine, Width::W8).is_none());
    }
}
