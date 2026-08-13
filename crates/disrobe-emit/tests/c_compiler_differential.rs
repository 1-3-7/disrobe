#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use disrobe_core::scratch::splitmix64;
use disrobe_emit::c::ast::{
    AssignOp, BinaryOp, CBaseType, CDecl, CExpr, CTypeSpec, DeclaratorChain, IntSuffix, LongSuffix,
    PostfixOp, Radix, TypeName, UnaryOp,
};
use disrobe_emit::c::print::{render_declaration, render_expr};
use disrobe_emit::{Interner, Symbol};

use common::{
    Compiler, WIDE, build_and_run, int_param, required_compilers, syntax_check, walk_assertions,
};

const NARROW: usize = 40;

const ALL_BINARY: [BinaryOp; 18] = [
    BinaryOp::Mul,
    BinaryOp::Div,
    BinaryOp::Rem,
    BinaryOp::Add,
    BinaryOp::Sub,
    BinaryOp::Shl,
    BinaryOp::Shr,
    BinaryOp::Lt,
    BinaryOp::Gt,
    BinaryOp::Le,
    BinaryOp::Ge,
    BinaryOp::Eq,
    BinaryOp::Ne,
    BinaryOp::BitAnd,
    BinaryOp::BitXor,
    BinaryOp::BitOr,
    BinaryOp::LogAnd,
    BinaryOp::LogOr,
];

const fn binary_index(op: BinaryOp) -> usize {
    match op {
        BinaryOp::Mul => 0,
        BinaryOp::Div => 1,
        BinaryOp::Rem => 2,
        BinaryOp::Add => 3,
        BinaryOp::Sub => 4,
        BinaryOp::Shl => 5,
        BinaryOp::Shr => 6,
        BinaryOp::Lt => 7,
        BinaryOp::Gt => 8,
        BinaryOp::Le => 9,
        BinaryOp::Ge => 10,
        BinaryOp::Eq => 11,
        BinaryOp::Ne => 12,
        BinaryOp::BitAnd => 13,
        BinaryOp::BitXor => 14,
        BinaryOp::BitOr => 15,
        BinaryOp::LogAnd => 16,
        BinaryOp::LogOr => 17,
    }
}

const ALL_UNARY: [UnaryOp; 8] = [
    UnaryOp::Neg,
    UnaryOp::Pos,
    UnaryOp::Not,
    UnaryOp::BitNot,
    UnaryOp::Deref,
    UnaryOp::AddrOf,
    UnaryOp::PreInc,
    UnaryOp::PreDec,
];

const fn unary_index(op: UnaryOp) -> usize {
    match op {
        UnaryOp::Neg => 0,
        UnaryOp::Pos => 1,
        UnaryOp::Not => 2,
        UnaryOp::BitNot => 3,
        UnaryOp::Deref => 4,
        UnaryOp::AddrOf => 5,
        UnaryOp::PreInc => 6,
        UnaryOp::PreDec => 7,
    }
}

const VALUE_UNARY: [UnaryOp; 4] = [UnaryOp::Neg, UnaryOp::Pos, UnaryOp::Not, UnaryOp::BitNot];

const ALL_ASSIGN: [AssignOp; 11] = [
    AssignOp::Assign,
    AssignOp::Add,
    AssignOp::Sub,
    AssignOp::Mul,
    AssignOp::Div,
    AssignOp::Rem,
    AssignOp::Shl,
    AssignOp::Shr,
    AssignOp::And,
    AssignOp::Xor,
    AssignOp::Or,
];

const fn assign_index(op: AssignOp) -> usize {
    match op {
        AssignOp::Assign => 0,
        AssignOp::Add => 1,
        AssignOp::Sub => 2,
        AssignOp::Mul => 3,
        AssignOp::Div => 4,
        AssignOp::Rem => 5,
        AssignOp::Shl => 6,
        AssignOp::Shr => 7,
        AssignOp::And => 8,
        AssignOp::Xor => 9,
        AssignOp::Or => 10,
    }
}

const ALL_POSTFIX: [PostfixOp; 2] = [PostfixOp::PostInc, PostfixOp::PostDec];

const fn postfix_index(op: PostfixOp) -> usize {
    match op {
        PostfixOp::PostInc => 0,
        PostfixOp::PostDec => 1,
    }
}

struct Rng {
    state: u64,
}

impl Rng {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        splitmix64(self.state)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

fn unsigned_suffix() -> IntSuffix {
    IntSuffix {
        unsigned: true,
        long: LongSuffix::None,
    }
}

fn unsigned_literal(value: u32, radix: Radix) -> CExpr {
    CExpr::Int {
        value: u64::from(value),
        radix,
        suffix: unsigned_suffix(),
    }
}

fn unsigned_type() -> TypeName {
    TypeName::plain(CTypeSpec::UnsignedInt)
}

fn to_unsigned(operand: CExpr) -> CExpr {
    CExpr::Cast {
        ty: unsigned_type(),
        operand: Box::new(operand),
    }
}

const fn yields_signed_int(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Lt
            | BinaryOp::Gt
            | BinaryOp::Le
            | BinaryOp::Ge
            | BinaryOp::Eq
            | BinaryOp::Ne
            | BinaryOp::LogAnd
            | BinaryOp::LogOr
    )
}

fn guarded_binary(op: BinaryOp, lhs: CExpr, rhs: CExpr) -> CExpr {
    let safe_rhs: CExpr = match op {
        BinaryOp::Div | BinaryOp::Rem => CExpr::Binary {
            op: BinaryOp::BitOr,
            lhs: Box::new(rhs),
            rhs: Box::new(unsigned_literal(1, Radix::Dec)),
        },
        BinaryOp::Shl | BinaryOp::Shr => CExpr::Binary {
            op: BinaryOp::BitAnd,
            lhs: Box::new(rhs),
            rhs: Box::new(unsigned_literal(31, Radix::Dec)),
        },
        _ => rhs,
    };
    let node: CExpr = CExpr::Binary {
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(safe_rhs),
    };
    if yields_signed_int(op) {
        to_unsigned(node)
    } else {
        node
    }
}

fn guarded_unary(op: UnaryOp, operand: CExpr) -> CExpr {
    let node: CExpr = CExpr::Unary {
        op,
        operand: Box::new(operand),
    };
    if matches!(op, UnaryOp::Not) {
        to_unsigned(node)
    } else {
        node
    }
}

const LEAF_VALUES: [u32; 12] = [
    0,
    1,
    2,
    3,
    5,
    7,
    31,
    255,
    65_535,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
];

const RADICES: [Radix; 3] = [Radix::Dec, Radix::Hex, Radix::Oct];

#[derive(Default)]
struct Census {
    binary: [u32; ALL_BINARY.len()],
    unary: [u32; ALL_UNARY.len()],
    assign: [u32; ALL_ASSIGN.len()],
    postfix: [u32; ALL_POSTFIX.len()],
    ternary: u32,
    comma: u32,
    cast: u32,
    call: u32,
    index: u32,
    member: u32,
    sizeof_expr: u32,
    sizeof_type: u32,
}

impl Census {
    fn record(&mut self, expr: &CExpr) {
        match expr {
            CExpr::Int { .. }
            | CExpr::Float(_)
            | CExpr::Char(_)
            | CExpr::Str(_)
            | CExpr::Ident(_) => {}
            CExpr::SizeofType(_) => self.sizeof_type += 1,
            CExpr::Unary { op, operand } => {
                self.unary[unary_index(*op)] += 1;
                self.record(operand);
            }
            CExpr::Postfix { op, operand } => {
                self.postfix[postfix_index(*op)] += 1;
                self.record(operand);
            }
            CExpr::Binary { op, lhs, rhs } => {
                self.binary[binary_index(*op)] += 1;
                self.record(lhs);
                self.record(rhs);
            }
            CExpr::Assign { op, lhs, rhs } => {
                self.assign[assign_index(*op)] += 1;
                self.record(lhs);
                self.record(rhs);
            }
            CExpr::Ternary { cond, then, els } => {
                self.ternary += 1;
                self.record(cond);
                self.record(then);
                self.record(els);
            }
            CExpr::Comma { lhs, rhs } => {
                self.comma += 1;
                self.record(lhs);
                self.record(rhs);
            }
            CExpr::Call { callee, args } => {
                self.call += 1;
                self.record(callee);
                for arg in args {
                    self.record(arg);
                }
            }
            CExpr::Index { base, index } => {
                self.index += 1;
                self.record(base);
                self.record(index);
            }
            CExpr::Member { base, .. } => {
                self.member += 1;
                self.record(base);
            }
            CExpr::Cast { operand, .. } => {
                self.cast += 1;
                self.record(operand);
            }
            CExpr::SizeofExpr(operand) => {
                self.sizeof_expr += 1;
                self.record(operand);
            }
        }
    }

    fn absorb(&mut self, other: &Self) {
        for (slot, hits) in other.binary.iter().enumerate() {
            self.binary[slot] += hits;
        }
        for (slot, hits) in other.unary.iter().enumerate() {
            self.unary[slot] += hits;
        }
        for (slot, hits) in other.assign.iter().enumerate() {
            self.assign[slot] += hits;
        }
        for (slot, hits) in other.postfix.iter().enumerate() {
            self.postfix[slot] += hits;
        }
        self.ternary += other.ternary;
        self.comma += other.comma;
        self.cast += other.cast;
        self.call += other.call;
        self.index += other.index;
        self.member += other.member;
        self.sizeof_expr += other.sizeof_expr;
        self.sizeof_type += other.sizeof_type;
    }

    fn of(corpus: &[CExpr]) -> Self {
        let mut census: Self = Self::default();
        for expr in corpus {
            census.record(expr);
        }
        census
    }

    fn covered(hits: &[u32]) -> usize {
        hits.iter().filter(|count: &&u32| **count > 0).count()
    }
}

fn leaf(rng: &mut Rng) -> CExpr {
    let value: u32 = LEAF_VALUES[rng.below(LEAF_VALUES.len())];
    let radix: Radix = RADICES[rng.below(RADICES.len())];
    unsigned_literal(value, radix)
}

fn value_expr(rng: &mut Rng, depth: u32) -> CExpr {
    if depth == 0 {
        return leaf(rng);
    }
    match rng.below(8) {
        0..=3 => {
            let op: BinaryOp = ALL_BINARY[rng.below(ALL_BINARY.len())];
            let lhs: CExpr = value_expr(rng, depth - 1);
            let rhs: CExpr = value_expr(rng, depth - 1);
            guarded_binary(op, lhs, rhs)
        }
        4 | 5 => {
            let op: UnaryOp = VALUE_UNARY[rng.below(VALUE_UNARY.len())];
            let operand: CExpr = value_expr(rng, depth - 1);
            guarded_unary(op, operand)
        }
        6 => {
            let cond: CExpr = value_expr(rng, depth - 1);
            let then: CExpr = value_expr(rng, depth - 1);
            let els: CExpr = value_expr(rng, depth - 1);
            CExpr::Ternary {
                cond: Box::new(cond),
                then: Box::new(then),
                els: Box::new(els),
            }
        }
        _ => {
            let operand: CExpr = value_expr(rng, depth - 1);
            to_unsigned(operand)
        }
    }
}

fn eval_u32(expr: &CExpr) -> u32 {
    match expr {
        CExpr::Int { value, .. } => *value as u32,
        CExpr::Cast { operand, .. } => eval_u32(operand),
        CExpr::Unary { op, operand } => {
            let value: u32 = eval_u32(operand);
            match op {
                UnaryOp::Neg => value.wrapping_neg(),
                UnaryOp::Pos => value,
                UnaryOp::Not => u32::from(value == 0),
                UnaryOp::BitNot => !value,
                UnaryOp::Deref | UnaryOp::AddrOf | UnaryOp::PreInc | UnaryOp::PreDec => {
                    panic!("the constant generator never emits {op:?}")
                }
            }
        }
        CExpr::Binary { op, lhs, rhs } => {
            let left: u32 = eval_u32(lhs);
            let right: u32 = eval_u32(rhs);
            apply_binary(*op, left, right)
        }
        CExpr::Ternary { cond, then, els } => {
            if eval_u32(cond) == 0 {
                eval_u32(els)
            } else {
                eval_u32(then)
            }
        }
        other => panic!("the constant generator never emits {other:?}"),
    }
}

fn apply_binary(op: BinaryOp, left: u32, right: u32) -> u32 {
    match op {
        BinaryOp::Mul => left.wrapping_mul(right),
        BinaryOp::Div => left / right,
        BinaryOp::Rem => left % right,
        BinaryOp::Add => left.wrapping_add(right),
        BinaryOp::Sub => left.wrapping_sub(right),
        BinaryOp::Shl => left.wrapping_shl(right),
        BinaryOp::Shr => left.wrapping_shr(right),
        BinaryOp::Lt => u32::from(left < right),
        BinaryOp::Gt => u32::from(left > right),
        BinaryOp::Le => u32::from(left <= right),
        BinaryOp::Ge => u32::from(left >= right),
        BinaryOp::Eq => u32::from(left == right),
        BinaryOp::Ne => u32::from(left != right),
        BinaryOp::BitAnd => left & right,
        BinaryOp::BitXor => left ^ right,
        BinaryOp::BitOr => left | right,
        BinaryOp::LogAnd => u32::from(left != 0 && right != 0),
        BinaryOp::LogOr => u32::from(left != 0 || right != 0),
    }
}

fn value_corpus() -> Vec<CExpr> {
    let mut rng: Rng = Rng::new(0x5f37_2c19_a4b8_0d61);
    let mut corpus: Vec<CExpr> = Vec::new();
    for op in ALL_BINARY {
        for _ in 0..4 {
            let lhs: CExpr = value_expr(&mut rng, 3);
            let rhs: CExpr = value_expr(&mut rng, 3);
            corpus.push(guarded_binary(op, lhs, rhs));
        }
    }
    for op in VALUE_UNARY {
        for _ in 0..4 {
            let operand: CExpr = value_expr(&mut rng, 3);
            corpus.push(guarded_unary(op, operand));
        }
    }
    for _ in 0..160 {
        corpus.push(value_expr(&mut rng, 4));
    }
    corpus
}

const SUFFIX_PROBE_VALUE: u32 = 63;

fn suffix_matrix() -> Vec<(IntSuffix, &'static str)> {
    vec![
        (
            IntSuffix {
                unsigned: false,
                long: LongSuffix::None,
            },
            "int",
        ),
        (
            IntSuffix {
                unsigned: true,
                long: LongSuffix::None,
            },
            "unsigned int",
        ),
        (
            IntSuffix {
                unsigned: false,
                long: LongSuffix::Long,
            },
            "long",
        ),
        (
            IntSuffix {
                unsigned: true,
                long: LongSuffix::Long,
            },
            "unsigned long",
        ),
        (
            IntSuffix {
                unsigned: false,
                long: LongSuffix::LongLong,
            },
            "long long",
        ),
        (
            IntSuffix {
                unsigned: true,
                long: LongSuffix::LongLong,
            },
            "unsigned long long",
        ),
    ]
}

#[test]
fn constant_expressions_evaluate_the_same_in_every_host_compiler() {
    let compilers: &[Compiler] = required_compilers();
    let corpus: Vec<CExpr> = value_corpus();
    let census: Census = Census::of(&corpus);
    let interner: Interner = Interner::new();

    let mut source: String = String::new();
    source.push_str("_Static_assert(sizeof(unsigned int) == 4, \"abi unsigned int width\");\n");
    for (index, expr) in corpus.iter().enumerate() {
        let expected: u32 = eval_u32(expr);
        let width: usize = if index % 2 == 0 { WIDE } else { NARROW };
        let rendered: String = render_expr(expr, &interner, width);
        writeln!(
            source,
            "_Static_assert(({rendered}) == {expected}u, \"expression {index}\");"
        )
        .expect("format probe");
    }

    let mut literal_cases: usize = 0;
    for (suffix_index, (suffix, ctype)) in suffix_matrix().into_iter().enumerate() {
        for (radix_index, radix) in RADICES.into_iter().enumerate() {
            let expr: CExpr = CExpr::Int {
                value: u64::from(SUFFIX_PROBE_VALUE),
                radix,
                suffix,
            };
            let rendered: String = render_expr(&expr, &interner, WIDE);
            let label: String = format!("literal {suffix_index} radix {radix_index}");
            writeln!(
                source,
                "_Static_assert(({rendered}) == {SUFFIX_PROBE_VALUE}, \"{label} value\");"
            )
            .expect("format probe");
            writeln!(
                source,
                "_Static_assert(sizeof({rendered}) == sizeof({ctype}), \"{label} width\");"
            )
            .expect("format probe");
            let signedness: &str = if suffix.unsigned { ">" } else { "<" };
            writeln!(
                source,
                "_Static_assert(({rendered}) * 0 - 1 {signedness} 0, \"{label} signedness\");"
            )
            .expect("format probe");
            literal_cases += 1;
        }
    }

    for compiler in compilers {
        syntax_check(compiler, &source, "constant expression");
    }

    println!(
        "constant expressions: {}/{} cases, binary operators {}/{}, value unary operators {}/{}, \
         literal suffix and radix combinations {literal_cases}/18, compilers {}/{}",
        corpus.len(),
        corpus.len(),
        Census::covered(&census.binary),
        ALL_BINARY.len(),
        VALUE_UNARY
            .iter()
            .filter(|op: &&UnaryOp| census.unary[unary_index(**op)] > 0)
            .count(),
        VALUE_UNARY.len(),
        compilers.len(),
        compilers.len()
    );
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Any,
    ArrayElement,
    FunctionReturn,
}

const fn allows_array(role: Role) -> bool {
    matches!(role, Role::Any | Role::ArrayElement)
}

const fn allows_function(role: Role) -> bool {
    matches!(role, Role::Any)
}

fn enumerate_chains(depth: u32, role: Role) -> Vec<DeclaratorChain> {
    let mut out: Vec<DeclaratorChain> = vec![DeclaratorChain::Terminal];
    if depth == 0 {
        return out;
    }
    for inner in enumerate_chains(depth - 1, Role::Any) {
        out.push(inner.pointer_to());
    }
    if allows_array(role) {
        let extent: u32 = 2 + depth;
        for inner in enumerate_chains(depth - 1, Role::ArrayElement) {
            out.push(inner.array_of(Some(CExpr::int(u64::from(extent)))));
        }
    }
    if allows_function(role) {
        for inner in enumerate_chains(depth - 1, Role::FunctionReturn) {
            out.push(inner.returning(vec![int_param()], false));
        }
    }
    out
}

#[test]
fn declarator_chains_have_the_type_the_chain_declares() {
    let compilers: &[Compiler] = required_compilers();
    let chains: Vec<DeclaratorChain> = enumerate_chains(5, Role::Any);
    let mut interner: Interner = Interner::new();

    let mut source: String = String::new();
    source.push_str("_Static_assert(sizeof(int) == 4, \"abi int width\");\n");
    source.push_str("_Static_assert(sizeof(void *) == 8, \"abi pointer width\");\n");
    let mut assertions: usize = 0;
    for (index, chain) in chains.iter().enumerate() {
        let name: String = format!("d{index}");
        let decl: CDecl = CDecl {
            storage: None,
            base: CBaseType::plain(CTypeSpec::Int),
            name: Some(interner.intern(&name)),
            declarator: chain.clone(),
            init: None,
        };
        let rendered: String = render_declaration(&decl, &interner, WIDE);
        source.push_str(&rendered);
        source.push('\n');
        let mut walk: Vec<String> = Vec::new();
        walk_assertions(chain, &name, &format!("chain {index}"), &mut walk);
        assertions += walk.len();
        for line in walk {
            source.push_str(&line);
            source.push('\n');
        }
    }

    for compiler in compilers {
        syntax_check(compiler, &source, "declarator chain");
    }

    assert_eq!(
        chains.len(),
        125,
        "the depth five declarator enumeration changed shape"
    );
    assert!(
        assertions >= chains.len(),
        "every chain must contribute at least one type assertion"
    );
    println!(
        "declarator chains: {}/{} shapes, {assertions} type assertions, compilers {}/{}",
        chains.len(),
        chains.len(),
        compilers.len(),
        compilers.len()
    );
}

const POINTER_PREAMBLE: &str = "\
unsigned int arr[4] = { 10u, 20u, 30u, 40u };
unsigned int *ptr = arr;
struct pair { unsigned int lo; unsigned int hi; };
struct pair pr = { 5u, 9u };
struct pair *prp = &pr;
unsigned int twice(unsigned int x) { return x * 2u; }
unsigned int (*fnp)(unsigned int) = twice;
_Static_assert(sizeof(arr) == 16, \"abi array width\");
";

struct PointerCase {
    expr: CExpr,
    expected: u32,
    label: &'static str,
}

fn pointer_corpus(interner: &mut Interner) -> Vec<PointerCase> {
    let arr: CExpr = CExpr::ident(interner, "arr");
    let ptr: CExpr = CExpr::ident(interner, "ptr");
    let pr: CExpr = CExpr::ident(interner, "pr");
    let prp: CExpr = CExpr::ident(interner, "prp");
    let fnp: CExpr = CExpr::ident(interner, "fnp");
    let twice: CExpr = CExpr::ident(interner, "twice");
    let lo: Symbol = interner.intern("lo");
    let hi: Symbol = interner.intern("hi");
    let deref = |operand: CExpr| CExpr::Unary {
        op: UnaryOp::Deref,
        operand: Box::new(operand),
    };
    let addr_of = |operand: CExpr| CExpr::Unary {
        op: UnaryOp::AddrOf,
        operand: Box::new(operand),
    };
    let index = |base: CExpr, at: u32| CExpr::Index {
        base: Box::new(base),
        index: Box::new(unsigned_literal(at, Radix::Dec)),
    };
    let add = |lhs: CExpr, rhs: u32| CExpr::Binary {
        op: BinaryOp::Add,
        lhs: Box::new(lhs),
        rhs: Box::new(unsigned_literal(rhs, Radix::Dec)),
    };
    let member = |base: CExpr, arrow: bool, field: Symbol| CExpr::Member {
        base: Box::new(base),
        arrow,
        field,
    };
    let call = |callee: CExpr, arg: CExpr| CExpr::Call {
        callee: Box::new(callee),
        args: vec![arg],
    };

    vec![
        PointerCase {
            expr: deref(add(ptr.clone(), 1)),
            expected: 20,
            label: "dereference of a pointer sum",
        },
        PointerCase {
            expr: add(deref(ptr.clone()), 1),
            expected: 11,
            label: "sum of a dereference",
        },
        PointerCase {
            expr: deref(add(arr.clone(), 3)),
            expected: 40,
            label: "dereference of an array sum",
        },
        PointerCase {
            expr: deref(addr_of(index(arr.clone(), 3))),
            expected: 40,
            label: "dereference of an address of a subscript",
        },
        PointerCase {
            expr: CExpr::Binary {
                op: BinaryOp::Sub,
                lhs: Box::new(addr_of(index(arr.clone(), 2))),
                rhs: Box::new(arr.clone()),
            },
            expected: 2,
            label: "difference between an address and an array",
        },
        PointerCase {
            expr: index(arr.clone(), 1),
            expected: 20,
            label: "plain subscript",
        },
        PointerCase {
            expr: deref(add(addr_of(index(arr.clone(), 0)), 2)),
            expected: 30,
            label: "dereference of an address plus an offset",
        },
        PointerCase {
            expr: member(prp.clone(), true, hi),
            expected: 9,
            label: "arrow member access",
        },
        PointerCase {
            expr: member(pr.clone(), false, lo),
            expected: 5,
            label: "dot member access",
        },
        PointerCase {
            expr: member(deref(prp.clone()), false, hi),
            expected: 9,
            label: "dot member access through a dereference",
        },
        PointerCase {
            expr: call(twice.clone(), index(arr.clone(), 1)),
            expected: 40,
            label: "call with a subscript argument",
        },
        PointerCase {
            expr: call(deref(fnp.clone()), unsigned_literal(3, Radix::Dec)),
            expected: 6,
            label: "call through a dereferenced function pointer",
        },
        PointerCase {
            expr: call(fnp.clone(), unsigned_literal(4, Radix::Dec)),
            expected: 8,
            label: "call through a function pointer",
        },
        PointerCase {
            expr: CExpr::SizeofExpr(Box::new(arr.clone())),
            expected: 16,
            label: "sizeof an array expression",
        },
        PointerCase {
            expr: CExpr::SizeofExpr(Box::new(index(arr.clone(), 0))),
            expected: 4,
            label: "sizeof a subscript expression",
        },
        PointerCase {
            expr: CExpr::SizeofType(TypeName {
                base: CBaseType::plain(CTypeSpec::UnsignedInt),
                declarator: DeclaratorChain::Terminal.pointer_to(),
            }),
            expected: 8,
            label: "sizeof a pointer type name",
        },
        PointerCase {
            expr: CExpr::Binary {
                op: BinaryOp::Mul,
                lhs: Box::new(CExpr::SizeofExpr(Box::new(index(arr.clone(), 0)))),
                rhs: Box::new(unsigned_literal(3, Radix::Dec)),
            },
            expected: 12,
            label: "product of a sizeof and a literal",
        },
    ]
}

#[test]
fn pointer_and_postfix_operators_read_the_memory_the_tree_names() {
    let compilers: &[Compiler] = required_compilers();
    let mut interner: Interner = Interner::new();
    let cases: Vec<PointerCase> = pointer_corpus(&mut interner);

    let mut source: String = String::from(POINTER_PREAMBLE);
    for (index, case) in cases.iter().enumerate() {
        let rendered: String = render_expr(&case.expr, &interner, WIDE);
        writeln!(
            source,
            "unsigned int ptr_case{index}(void) {{ return (unsigned int)({rendered}); }}"
        )
        .expect("format probe");
    }
    source.push_str("int main(void) {\n");
    for (index, case) in cases.iter().enumerate() {
        writeln!(
            source,
            "    if (ptr_case{index}() != {}u) return {};",
            case.expected,
            index + 1
        )
        .expect("format probe");
    }
    source.push_str("    return 0;\n}\n");

    let roster: String = cases
        .iter()
        .enumerate()
        .map(|(index, case): (usize, &PointerCase)| format!("{}={}", index + 1, case.label))
        .collect::<Vec<String>>()
        .join(", ");
    for compiler in compilers {
        build_and_run(compiler, &source, &format!("pointer operator ({roster})"));
    }

    let corpus: Vec<CExpr> = cases
        .iter()
        .map(|case: &PointerCase| case.expr.clone())
        .collect();
    let census: Census = Census::of(&corpus);
    assert!(
        census.unary[unary_index(UnaryOp::Deref)] > 0,
        "no dereference reached the compiler"
    );
    assert!(
        census.unary[unary_index(UnaryOp::AddrOf)] > 0,
        "no address-of reached the compiler"
    );
    println!(
        "pointer operators: {}/{} cases, {} dereferences, {} address-of, {} calls, {} subscripts, \
         {} member accesses, {} sizeof expressions, {} sizeof type names, compilers {}/{}",
        cases.len(),
        cases.len(),
        census.unary[unary_index(UnaryOp::Deref)],
        census.unary[unary_index(UnaryOp::AddrOf)],
        census.call,
        census.index,
        census.member,
        census.sizeof_expr,
        census.sizeof_type,
        compilers.len(),
        compilers.len()
    );
}

#[test]
fn every_expression_operator_reaches_a_compiler_graded_corpus() {
    let mut interner: Interner = Interner::new();
    let mut total: Census = Census::default();
    total.absorb(&Census::of(&value_corpus()));
    total.absorb(&Census::of(
        &pointer_corpus(&mut interner)
            .iter()
            .map(|case: &PointerCase| case.expr.clone())
            .collect::<Vec<CExpr>>(),
    ));
    total.absorb(&Census::of(
        &seq_corpus(&mut interner)
            .iter()
            .map(|case: &SeqCase| case.expr.clone())
            .collect::<Vec<CExpr>>(),
    ));

    for (slot, hits) in total.binary.iter().enumerate() {
        assert!(
            *hits > 0,
            "binary operator {:?} is ungraded",
            ALL_BINARY[slot]
        );
    }
    for (slot, hits) in total.unary.iter().enumerate() {
        assert!(
            *hits > 0,
            "unary operator {:?} is ungraded",
            ALL_UNARY[slot]
        );
    }
    for (slot, hits) in total.assign.iter().enumerate() {
        assert!(
            *hits > 0,
            "assignment operator {:?} is ungraded",
            ALL_ASSIGN[slot]
        );
    }
    for (slot, hits) in total.postfix.iter().enumerate() {
        assert!(
            *hits > 0,
            "postfix operator {:?} is ungraded",
            ALL_POSTFIX[slot]
        );
    }
    for (count, name) in [
        (total.ternary, "conditional"),
        (total.comma, "comma"),
        (total.cast, "cast"),
        (total.call, "call"),
        (total.index, "subscript"),
        (total.member, "member access"),
        (total.sizeof_expr, "sizeof expression"),
        (total.sizeof_type, "sizeof type name"),
    ] {
        assert!(count > 0, "{name} is ungraded");
    }
    println!(
        "operator census: binary {}/{}, unary {}/{}, assignment {}/{}, postfix {}/{}, and every \
         one of conditional, comma, cast, call, subscript, member access, sizeof expression and \
         sizeof type name",
        Census::covered(&total.binary),
        ALL_BINARY.len(),
        Census::covered(&total.unary),
        ALL_UNARY.len(),
        Census::covered(&total.assign),
        ALL_ASSIGN.len(),
        Census::covered(&total.postfix),
        ALL_POSTFIX.len()
    );
}

fn string_cases() -> Vec<String> {
    let all_low: String = (0u32..=0xffu32)
        .filter_map(char::from_u32)
        .collect::<String>();
    let wide: String = ['\u{100}', '\u{7ff}', '\u{800}', '\u{fffd}', '\u{10000}']
        .iter()
        .collect::<String>();
    vec![
        String::new(),
        "plain".to_owned(),
        "a\nb\"c\\d".to_owned(),
        "\u{ff}A".to_owned(),
        "\u{ff}0".to_owned(),
        "\u{0}1".to_owned(),
        "\u{0}\u{0}\u{0}".to_owned(),
        "??/".to_owned(),
        "??>".to_owned(),
        "???".to_owned(),
        "why? because.".to_owned(),
        "tab\there\r\n".to_owned(),
        "\u{7f}\u{1}\u{1f}".to_owned(),
        "'single' and \"double\"".to_owned(),
        "percent %s and %n".to_owned(),
        all_low,
        wide,
        "\u{1f600}\u{10ffff}".to_owned(),
    ]
}

fn char_cases() -> Vec<char> {
    let mut cases: Vec<char> = (0u32..=0xffu32).filter_map(char::from_u32).collect();
    for point in [
        0x100u32, 0x7ff, 0x800, 0xfffd, 0x1_0000, 0x1_f600, 0x10_ffff,
    ] {
        if let Some(value) = char::from_u32(point) {
            cases.push(value);
        }
    }
    cases
}

#[test]
fn string_and_char_literals_denote_their_own_bytes() {
    let compilers: &[Compiler] = required_compilers();
    let interner: Interner = Interner::new();
    let strings: Vec<String> = string_cases();
    let chars: Vec<char> = char_cases();

    let mut source: String = String::new();
    source.push_str("_Static_assert(sizeof(unsigned int) == 4, \"abi unsigned int width\");\n");

    for (index, case) in strings.iter().enumerate() {
        let expr: CExpr = CExpr::Str(Box::from(case.as_str()));
        let rendered: String = render_expr(&expr, &interner, WIDE);
        let bytes: &[u8] = case.as_bytes();
        let listed: String = bytes
            .iter()
            .map(|byte: &u8| byte.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        writeln!(source, "static const char lit{index}[] = {rendered};").expect("format probe");
        writeln!(
            source,
            "static const unsigned char exp{index}[] = {{ {}0 }};",
            if listed.is_empty() {
                String::new()
            } else {
                format!("{listed}, ")
            }
        )
        .expect("format probe");
        writeln!(
            source,
            "_Static_assert(sizeof(lit{index}) == {}, \"string {index} length\");",
            bytes.len() + 1
        )
        .expect("format probe");
    }

    for (index, case) in chars.iter().enumerate() {
        let expr: CExpr = CExpr::Char(*case);
        let rendered: String = render_expr(&expr, &interner, WIDE);
        let point: u32 = *case as u32;
        if point <= 0xff {
            writeln!(
                source,
                "_Static_assert((unsigned char){rendered} == {point}, \"char {index}\");"
            )
            .expect("format probe");
        } else {
            writeln!(
                source,
                "_Static_assert({rendered} == {point}u, \"wide char {index}\");"
            )
            .expect("format probe");
        }
    }

    source.push_str("int main(void) {\n");
    for (index, case) in strings.iter().enumerate() {
        let length: usize = case.len();
        writeln!(
            source,
            "    for (unsigned int i = 0; i < {length}u; i++) {{ if ((unsigned char)lit{index}[i] \
             != exp{index}[i]) return {}; }}",
            index + 1
        )
        .expect("format probe");
    }
    source.push_str("    return 0;\n}\n");

    for compiler in compilers {
        build_and_run(compiler, &source, "literal byte fidelity");
    }

    let total_bytes: usize = strings.iter().map(String::len).sum();
    println!(
        "literals: {}/{} strings covering {total_bytes} bytes, {}/{} character constants, \
         compilers {}/{}",
        strings.len(),
        strings.len(),
        chars.len(),
        chars.len(),
        compilers.len(),
        compilers.len()
    );
}

const SEQ_VARS: [&str; 4] = ["v0", "v1", "v2", "v3"];
const SEQ_INITIAL: [u32; 4] = [11, 3, 7, 2];

struct SeqCase {
    expr: CExpr,
    label: String,
}

fn seq_corpus(interner: &mut Interner) -> Vec<SeqCase> {
    let vars: Vec<Symbol> = SEQ_VARS
        .iter()
        .map(|name: &&str| interner.intern(name))
        .collect();
    let var = |index: usize| CExpr::Ident(vars[index]);
    let lit = |value: u32| unsigned_literal(value, Radix::Dec);
    let mut cases: Vec<SeqCase> = Vec::new();

    for op in ALL_ASSIGN {
        let rhs: CExpr = CExpr::Binary {
            op: BinaryOp::Add,
            lhs: Box::new(lit(2)),
            rhs: Box::new(CExpr::Binary {
                op: BinaryOp::Mul,
                lhs: Box::new(lit(3)),
                rhs: Box::new(lit(1)),
            }),
        };
        cases.push(SeqCase {
            expr: CExpr::Assign {
                op,
                lhs: Box::new(var(0)),
                rhs: Box::new(rhs),
            },
            label: format!("assign {op:?}"),
        });
    }

    for op in ALL_POSTFIX {
        cases.push(SeqCase {
            expr: CExpr::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(CExpr::Postfix {
                    op,
                    operand: Box::new(var(0)),
                }),
                rhs: Box::new(lit(1)),
            },
            label: format!("postfix {op:?} in a sum"),
        });
        cases.push(SeqCase {
            expr: CExpr::Unary {
                op: UnaryOp::Neg,
                operand: Box::new(CExpr::Postfix {
                    op,
                    operand: Box::new(var(1)),
                }),
            },
            label: format!("postfix {op:?} under negation"),
        });
    }

    for op in [UnaryOp::PreInc, UnaryOp::PreDec] {
        cases.push(SeqCase {
            expr: CExpr::Binary {
                op: BinaryOp::Mul,
                lhs: Box::new(CExpr::Unary {
                    op,
                    operand: Box::new(var(2)),
                }),
                rhs: Box::new(lit(3)),
            },
            label: format!("prefix {op:?} in a product"),
        });
    }

    cases.push(SeqCase {
        expr: CExpr::Assign {
            op: AssignOp::Assign,
            lhs: Box::new(var(0)),
            rhs: Box::new(CExpr::Assign {
                op: AssignOp::Add,
                lhs: Box::new(var(1)),
                rhs: Box::new(lit(9)),
            }),
        },
        label: "assignment chains to the right".to_owned(),
    });
    cases.push(SeqCase {
        expr: CExpr::Assign {
            op: AssignOp::Assign,
            lhs: Box::new(var(0)),
            rhs: Box::new(CExpr::Ternary {
                cond: Box::new(lit(1)),
                then: Box::new(lit(4)),
                els: Box::new(lit(5)),
            }),
        },
        label: "assignment takes a conditional right operand".to_owned(),
    });
    cases.push(SeqCase {
        expr: CExpr::Ternary {
            cond: Box::new(CExpr::Assign {
                op: AssignOp::Assign,
                lhs: Box::new(var(0)),
                rhs: Box::new(lit(0)),
            }),
            then: Box::new(lit(4)),
            els: Box::new(lit(5)),
        },
        label: "assignment as a conditional condition".to_owned(),
    });
    cases.push(SeqCase {
        expr: CExpr::Ternary {
            cond: Box::new(lit(0)),
            then: Box::new(CExpr::Assign {
                op: AssignOp::Assign,
                lhs: Box::new(var(0)),
                rhs: Box::new(lit(41)),
            }),
            els: Box::new(CExpr::Assign {
                op: AssignOp::Assign,
                lhs: Box::new(var(1)),
                rhs: Box::new(lit(42)),
            }),
        },
        label: "only the taken conditional branch assigns".to_owned(),
    });
    cases.push(SeqCase {
        expr: CExpr::Comma {
            lhs: Box::new(CExpr::Assign {
                op: AssignOp::Assign,
                lhs: Box::new(var(0)),
                rhs: Box::new(lit(6)),
            }),
            rhs: Box::new(CExpr::Assign {
                op: AssignOp::Assign,
                lhs: Box::new(var(1)),
                rhs: Box::new(lit(8)),
            }),
        },
        label: "comma sequences two assignments".to_owned(),
    });
    cases.push(SeqCase {
        expr: CExpr::Assign {
            op: AssignOp::Assign,
            lhs: Box::new(var(0)),
            rhs: Box::new(CExpr::Comma {
                lhs: Box::new(CExpr::Assign {
                    op: AssignOp::Assign,
                    lhs: Box::new(var(1)),
                    rhs: Box::new(lit(6)),
                }),
                rhs: Box::new(lit(8)),
            }),
        },
        label: "comma inside an assignment right operand".to_owned(),
    });
    cases.push(SeqCase {
        expr: CExpr::Comma {
            lhs: Box::new(CExpr::Unary {
                op: UnaryOp::PreInc,
                operand: Box::new(var(2)),
            }),
            rhs: Box::new(CExpr::Postfix {
                op: PostfixOp::PostDec,
                operand: Box::new(var(3)),
            }),
        },
        label: "comma sequences a prefix and a postfix".to_owned(),
    });

    cases
}

fn eval_env(expr: &CExpr, env: &mut BTreeMap<Symbol, u32>) -> u32 {
    match expr {
        CExpr::Int { value, .. } => *value as u32,
        CExpr::Ident(symbol) => *env
            .get(symbol)
            .expect("sequencing cases only read declared variables"),
        CExpr::Cast { operand, .. } => eval_env(operand, env),
        CExpr::Comma { lhs, rhs } => {
            let _: u32 = eval_env(lhs, env);
            eval_env(rhs, env)
        }
        CExpr::Ternary { cond, then, els } => {
            if eval_env(cond, env) == 0 {
                eval_env(els, env)
            } else {
                eval_env(then, env)
            }
        }
        CExpr::Binary { op, lhs, rhs } => {
            let left: u32 = eval_env(lhs, env);
            let right: u32 = eval_env(rhs, env);
            apply_binary(*op, left, right)
        }
        CExpr::Assign { op, lhs, rhs } => {
            let target: Symbol = target_symbol(lhs);
            let value: u32 = eval_env(rhs, env);
            let current: u32 = *env.get(&target).expect("assign target is declared");
            let updated: u32 = apply_assign(*op, current, value);
            env.insert(target, updated);
            updated
        }
        CExpr::Postfix { op, operand } => {
            let target: Symbol = target_symbol(operand);
            let current: u32 = *env.get(&target).expect("postfix target is declared");
            let updated: u32 = match op {
                PostfixOp::PostInc => current.wrapping_add(1),
                PostfixOp::PostDec => current.wrapping_sub(1),
            };
            env.insert(target, updated);
            current
        }
        CExpr::Unary { op, operand } => match op {
            UnaryOp::PreInc | UnaryOp::PreDec => {
                let target: Symbol = target_symbol(operand);
                let current: u32 = *env.get(&target).expect("prefix target is declared");
                let updated: u32 = if matches!(op, UnaryOp::PreInc) {
                    current.wrapping_add(1)
                } else {
                    current.wrapping_sub(1)
                };
                env.insert(target, updated);
                updated
            }
            UnaryOp::Neg => eval_env(operand, env).wrapping_neg(),
            UnaryOp::Pos => eval_env(operand, env),
            UnaryOp::Not => u32::from(eval_env(operand, env) == 0),
            UnaryOp::BitNot => !eval_env(operand, env),
            UnaryOp::Deref | UnaryOp::AddrOf => {
                panic!("sequencing cases never dereference or take an address")
            }
        },
        other => panic!("sequencing cases never build {other:?}"),
    }
}

fn target_symbol(expr: &CExpr) -> Symbol {
    match expr {
        CExpr::Ident(symbol) => *symbol,
        other => panic!("sequencing cases only modify plain variables, not {other:?}"),
    }
}

const fn apply_assign(op: AssignOp, current: u32, value: u32) -> u32 {
    match op {
        AssignOp::Assign => value,
        AssignOp::Add => current.wrapping_add(value),
        AssignOp::Sub => current.wrapping_sub(value),
        AssignOp::Mul => current.wrapping_mul(value),
        AssignOp::Div => current / value,
        AssignOp::Rem => current % value,
        AssignOp::Shl => current.wrapping_shl(value),
        AssignOp::Shr => current.wrapping_shr(value),
        AssignOp::And => current & value,
        AssignOp::Xor => current ^ value,
        AssignOp::Or => current | value,
    }
}

#[test]
fn sequencing_operators_evaluate_as_the_tree_says() {
    let compilers: &[Compiler] = required_compilers();
    let mut interner: Interner = Interner::new();
    let cases: Vec<SeqCase> = seq_corpus(&mut interner);
    let census: Census = Census::of(
        &cases
            .iter()
            .map(|case: &SeqCase| case.expr.clone())
            .collect::<Vec<CExpr>>(),
    );

    let mut source: String = String::new();
    source.push_str("_Static_assert(sizeof(unsigned int) == 4, \"abi unsigned int width\");\n");
    let mut expectations: Vec<[u32; 5]> = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let mut env: BTreeMap<Symbol, u32> = BTreeMap::new();
        for (slot, name) in SEQ_VARS.iter().enumerate() {
            let symbol: Symbol = interner.lookup(name).expect("sequencing variable interned");
            env.insert(symbol, SEQ_INITIAL[slot]);
        }
        let result: u32 = eval_env(&case.expr, &mut env);
        let mut expected: [u32; 5] = [result, 0, 0, 0, 0];
        for (slot, name) in SEQ_VARS.iter().enumerate() {
            let symbol: Symbol = interner.lookup(name).expect("sequencing variable interned");
            expected[slot + 1] = *env.get(&symbol).expect("variable survives evaluation");
        }
        expectations.push(expected);

        let rendered: String = render_expr(&case.expr, &interner, WIDE);
        writeln!(source, "static void seq{index}(unsigned int out[5]) {{").expect("format probe");
        writeln!(
            source,
            "    unsigned int v0 = {}u, v1 = {}u, v2 = {}u, v3 = {}u;",
            SEQ_INITIAL[0], SEQ_INITIAL[1], SEQ_INITIAL[2], SEQ_INITIAL[3]
        )
        .expect("format probe");
        writeln!(source, "    out[0] = ({rendered});").expect("format probe");
        source.push_str("    out[1] = v0; out[2] = v1; out[3] = v2; out[4] = v3;\n}\n");
    }

    source.push_str("int main(void) {\n    unsigned int out[5];\n");
    for (index, expected) in expectations.iter().enumerate() {
        writeln!(source, "    seq{index}(out);").expect("format probe");
        let checks: String = expected
            .iter()
            .enumerate()
            .map(|(slot, value): (usize, &u32)| format!("out[{slot}] != {value}u"))
            .collect::<Vec<String>>()
            .join(" || ");
        writeln!(source, "    if ({checks}) return {};", index + 1).expect("format probe");
    }
    source.push_str("    return 0;\n}\n");

    let labels: BTreeSet<&str> = cases
        .iter()
        .map(|case: &SeqCase| case.label.as_str())
        .collect();
    assert_eq!(
        labels.len(),
        cases.len(),
        "sequencing cases must be distinct; a duplicate label means a case was copied, not added"
    );
    let roster: String = cases
        .iter()
        .enumerate()
        .map(|(index, case): (usize, &SeqCase)| format!("{}={}", index + 1, case.label))
        .collect::<Vec<String>>()
        .join(", ");

    for compiler in compilers {
        build_and_run(
            compiler,
            &source,
            &format!("sequencing operator ({roster})"),
        );
    }

    for (slot, hits) in census.assign.iter().enumerate() {
        assert!(
            *hits > 0,
            "assignment operator {:?} never reached the compiler",
            ALL_ASSIGN[slot]
        );
    }
    for (slot, hits) in census.postfix.iter().enumerate() {
        assert!(
            *hits > 0,
            "postfix operator {:?} never reached the compiler",
            ALL_POSTFIX[slot]
        );
    }
    for op in [UnaryOp::PreInc, UnaryOp::PreDec] {
        assert!(
            census.unary[unary_index(op)] > 0,
            "prefix operator {op:?} never reached the compiler"
        );
    }
    println!(
        "sequencing: {}/{} cases, assignment operators {}/{}, postfix operators {}/{}, prefix \
         increments 2/2, comma expressions {}, compilers {}/{}",
        cases.len(),
        cases.len(),
        Census::covered(&census.assign),
        ALL_ASSIGN.len(),
        Census::covered(&census.postfix),
        ALL_POSTFIX.len(),
        census.comma,
        compilers.len(),
        compilers.len()
    );
}
