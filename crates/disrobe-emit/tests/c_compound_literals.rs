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

use std::fmt::Write as _;

use disrobe_emit::c::Cx;
use disrobe_emit::c::ast::{
    AssignOp, BinaryOp, CBaseType, CExpr, CInit, CInitItem, CTypeSpec, DeclaratorChain, Designator,
    IntSuffix, LongSuffix, PostfixOp, Radix, TypeName, UnaryOp,
};
use disrobe_emit::c::print::render_expr;
use disrobe_emit::{Interner, Symbol};

use common::{Compiler, WIDE, build_and_run, required_compilers, syntax_check};

const NARROW: usize = 40;

const PREAMBLE: &str = "\
struct pair { unsigned int lo; unsigned int hi; };
struct nest { struct pair inner; unsigned int tail; };
unsigned int seed = 7u;
unsigned int table[4] = { 1u, 2u, 3u, 4u };
unsigned int sink = 0u;
unsigned int twice(unsigned int x) { return 2u * x; }
_Static_assert(sizeof(unsigned int) == 4, \"abi unsigned int width\");
_Static_assert(sizeof(struct pair) == 8, \"abi pair width\");
";

fn lit(value: u32) -> CExpr {
    CExpr::Int {
        value: u64::from(value),
        radix: Radix::Dec,
        suffix: IntSuffix {
            unsigned: true,
            long: LongSuffix::None,
        },
    }
}

fn scalar_type() -> TypeName {
    TypeName::plain(CTypeSpec::UnsignedInt)
}

fn array_type(extent: u32) -> TypeName {
    TypeName {
        base: CBaseType::plain(CTypeSpec::UnsignedInt),
        declarator: DeclaratorChain::Terminal.array_of(Some(lit(extent))),
    }
}

fn matrix_type(rows: u32, columns: u32) -> TypeName {
    TypeName {
        base: CBaseType::plain(CTypeSpec::UnsignedInt),
        declarator: DeclaratorChain::Terminal
            .array_of(Some(lit(columns)))
            .array_of(Some(lit(rows))),
    }
}

fn tagged_type(tag: Symbol) -> TypeName {
    TypeName {
        base: CBaseType::plain(CTypeSpec::Struct(Some(tag))),
        declarator: DeclaratorChain::Terminal,
    }
}

fn typeof_type(subject: CExpr) -> TypeName {
    TypeName {
        base: CBaseType::plain(CTypeSpec::typeof_expr(subject)),
        declarator: DeclaratorChain::Terminal,
    }
}

fn index(base: CExpr, at: u32) -> CExpr {
    CExpr::Index {
        base: Box::new(base),
        index: Box::new(lit(at)),
    }
}

fn member(base: CExpr, field: Symbol) -> CExpr {
    CExpr::Member {
        base: Box::new(base),
        arrow: false,
        field,
    }
}

fn unary(op: UnaryOp, operand: CExpr) -> CExpr {
    CExpr::Unary {
        op,
        operand: Box::new(operand),
    }
}

struct Case {
    expr: CExpr,
    expected: u32,
    label: &'static str,
}

#[allow(clippy::too_many_lines)]
fn corpus(cx: &mut Cx<'_>) -> Vec<Case> {
    let pair: Symbol = cx.sym("pair");
    let nest: Symbol = cx.sym("nest");
    let lo: Symbol = cx.sym("lo");
    let hi: Symbol = cx.sym("hi");
    let inner: Symbol = cx.sym("inner");
    let tail: Symbol = cx.sym("tail");
    let seed: CExpr = cx.var("seed");
    let table: CExpr = cx.var("table");
    let sink: CExpr = cx.var("sink");
    let field_lo: Designator = cx.designator("lo");
    let field_hi: Designator = cx.designator("hi");
    let field_inner: Designator = cx.designator("inner");

    let ramp: CExpr = CExpr::compound(
        array_type(4),
        vec![
            CInitItem::expr(lit(10)),
            CInitItem::expr(lit(20)),
            CInitItem::expr(lit(30)),
            CInitItem::expr(lit(40)),
        ],
    );
    let sparse: CExpr = CExpr::compound(
        array_type(4),
        vec![CInitItem::at(
            vec![Designator::Index(lit(3))],
            CInit::Expr(lit(7)),
        )],
    );
    let resumed: CExpr = CExpr::compound(
        array_type(4),
        vec![
            CInitItem::at(vec![Designator::Index(lit(2))], CInit::Expr(lit(5))),
            CInitItem::expr(lit(6)),
        ],
    );
    let computed_index: CExpr = CExpr::compound(
        array_type(4),
        vec![CInitItem::at(
            vec![Designator::Index(CExpr::Binary {
                op: BinaryOp::Add,
                lhs: Box::new(lit(1)),
                rhs: Box::new(lit(2)),
            })],
            CInit::Expr(lit(7)),
        )],
    );
    let both_fields: CExpr = CExpr::compound(
        tagged_type(pair),
        vec![
            CInitItem::at(vec![field_lo.clone()], CInit::Expr(lit(3))),
            CInitItem::at(vec![field_hi.clone()], CInit::Expr(lit(4))),
        ],
    );
    let one_field: CExpr = CExpr::compound(
        tagged_type(pair),
        vec![CInitItem::at(vec![field_hi.clone()], CInit::Expr(lit(4)))],
    );
    let deep_path: CExpr = CExpr::compound(
        tagged_type(nest),
        vec![CInitItem::at(
            vec![field_inner, field_hi.clone()],
            CInit::Expr(lit(9)),
        )],
    );
    let braced: CExpr = CExpr::compound(
        tagged_type(nest),
        vec![
            CInitItem::nested(vec![CInitItem::at(vec![field_hi], CInit::Expr(lit(3)))]),
            CInitItem::expr(lit(4)),
        ],
    );
    let matrix: CExpr = CExpr::compound(
        matrix_type(2, 2),
        vec![
            CInitItem::nested(vec![CInitItem::expr(lit(1)), CInitItem::expr(lit(2))]),
            CInitItem::nested(vec![CInitItem::expr(lit(3)), CInitItem::expr(lit(4))]),
        ],
    );
    let typed_scalar: CExpr =
        CExpr::compound(typeof_type(seed.clone()), vec![CInitItem::expr(lit(9))]);
    let typed_array: CExpr = CExpr::compound(
        typeof_type(table),
        vec![CInitItem::at(
            vec![Designator::Index(lit(1))],
            CInit::Expr(lit(8)),
        )],
    );
    let sequenced: CExpr = CExpr::compound(
        array_type(4),
        vec![
            CInitItem::expr(CExpr::Comma {
                lhs: Box::new(CExpr::Assign {
                    op: AssignOp::Assign,
                    lhs: Box::new(sink),
                    rhs: Box::new(lit(1)),
                }),
                rhs: Box::new(lit(5)),
            }),
            CInitItem::expr(lit(9)),
        ],
    );
    let twelve: CExpr = CExpr::compound(scalar_type(), vec![CInitItem::expr(lit(12))]);
    let twenty_one: CExpr = CExpr::compound(scalar_type(), vec![CInitItem::expr(lit(21))]);
    let five: CExpr = CExpr::compound(scalar_type(), vec![CInitItem::expr(lit(5))]);
    let two: CExpr = CExpr::compound(scalar_type(), vec![CInitItem::expr(lit(2))]);
    let counter: CExpr = CExpr::compound(scalar_type(), vec![CInitItem::expr(lit(41))]);

    vec![
        Case {
            expr: CExpr::compound(scalar_type(), vec![CInitItem::expr(lit(5))]),
            expected: 5,
            label: "scalar compound literal",
        },
        Case {
            expr: index(ramp, 2),
            expected: 30,
            label: "subscript of an array compound literal",
        },
        Case {
            expr: index(sparse.clone(), 3),
            expected: 7,
            label: "index designator writes its slot",
        },
        Case {
            expr: index(sparse, 0),
            expected: 0,
            label: "index designator leaves other slots zero",
        },
        Case {
            expr: index(resumed, 3),
            expected: 6,
            label: "positional item resumes after an index designator",
        },
        Case {
            expr: index(computed_index, 3),
            expected: 7,
            label: "index designator with a computed subscript",
        },
        Case {
            expr: member(both_fields, hi),
            expected: 4,
            label: "field designator writes its member",
        },
        Case {
            expr: member(one_field, lo),
            expected: 0,
            label: "field designator leaves other members zero",
        },
        Case {
            expr: member(member(deep_path, inner), hi),
            expected: 9,
            label: "nested designator path",
        },
        Case {
            expr: member(member(braced.clone(), inner), hi),
            expected: 3,
            label: "brace nested initializer",
        },
        Case {
            expr: member(braced, tail),
            expected: 4,
            label: "member after a brace nested initializer",
        },
        Case {
            expr: index(index(matrix, 1), 0),
            expected: 3,
            label: "two dimensional compound literal",
        },
        Case {
            expr: typed_scalar,
            expected: 9,
            label: "typeof of a scalar variable",
        },
        Case {
            expr: index(typed_array.clone(), 1),
            expected: 8,
            label: "typeof of an array variable with a designator",
        },
        Case {
            expr: index(typed_array, 0),
            expected: 0,
            label: "typeof of an array variable leaves other slots zero",
        },
        Case {
            expr: index(sequenced.clone(), 0),
            expected: 5,
            label: "comma expression inside an initializer stays one element",
        },
        Case {
            expr: index(sequenced, 1),
            expected: 9,
            label: "the element after a comma expression keeps its slot",
        },
        Case {
            expr: unary(UnaryOp::Deref, unary(UnaryOp::AddrOf, twelve)),
            expected: 12,
            label: "address of a compound literal",
        },
        Case {
            expr: CExpr::Call {
                callee: Box::new(cx.var("twice")),
                args: vec![twenty_one],
            },
            expected: 42,
            label: "compound literal as a call argument",
        },
        Case {
            expr: unary(UnaryOp::Neg, five),
            expected: 5u32.wrapping_neg(),
            label: "unary minus on a compound literal",
        },
        Case {
            expr: CExpr::Binary {
                op: BinaryOp::Mul,
                lhs: Box::new(two),
                rhs: Box::new(lit(3)),
            },
            expected: 6,
            label: "compound literal as a binary operand",
        },
        Case {
            expr: CExpr::Ternary {
                cond: Box::new(seed),
                then: Box::new(CExpr::compound(
                    scalar_type(),
                    vec![CInitItem::expr(lit(4))],
                )),
                els: Box::new(CExpr::compound(
                    scalar_type(),
                    vec![CInitItem::expr(lit(5))],
                )),
            },
            expected: 4,
            label: "compound literals in both conditional branches",
        },
        Case {
            expr: CExpr::Postfix {
                op: PostfixOp::PostInc,
                operand: Box::new(counter),
            },
            expected: 41,
            label: "postfix increment of a compound literal",
        },
    ]
}

#[derive(Default)]
struct Census {
    scalar: u32,
    array: u32,
    aggregate: u32,
    typeof_spec: u32,
    field_designator: u32,
    index_designator: u32,
    designator_path: u32,
    nested_list: u32,
    positional_after_designator: u32,
}

impl Census {
    fn record(&mut self, expr: &CExpr) {
        match expr {
            CExpr::Int { .. }
            | CExpr::Float(_)
            | CExpr::Char(_)
            | CExpr::Str(_)
            | CExpr::Ident(_) => {}
            CExpr::Unary { operand, .. }
            | CExpr::Postfix { operand, .. }
            | CExpr::SizeofExpr(operand) => self.record(operand),
            CExpr::Binary { lhs, rhs, .. }
            | CExpr::Assign { lhs, rhs, .. }
            | CExpr::Comma { lhs, rhs } => {
                self.record(lhs);
                self.record(rhs);
            }
            CExpr::Ternary { cond, then, els } => {
                self.record(cond);
                self.record(then);
                self.record(els);
            }
            CExpr::Call { callee, args } => {
                self.record(callee);
                for arg in args {
                    self.record(arg);
                }
            }
            CExpr::Index { base, index } => {
                self.record(base);
                self.record(index);
            }
            CExpr::Member { base, .. } => self.record(base),
            CExpr::Cast { ty, operand } => {
                self.record_type(ty);
                self.record(operand);
            }
            CExpr::SizeofType(ty) => self.record_type(ty),
            CExpr::CompoundLiteral { ty, items } => {
                self.record_kind(ty);
                self.record_type(ty);
                self.record_items(items);
            }
        }
    }

    fn record_kind(&mut self, ty: &TypeName) {
        if matches!(ty.declarator, DeclaratorChain::Array { .. }) {
            self.array += 1;
        }
        match ty.base.spec {
            CTypeSpec::Struct(_) | CTypeSpec::Union(_) => self.aggregate += 1,
            CTypeSpec::TypeofExpr(_) => self.typeof_spec += 1,
            _ if matches!(ty.declarator, DeclaratorChain::Terminal) => self.scalar += 1,
            _ => {}
        }
    }

    fn record_type(&mut self, ty: &TypeName) {
        if let CTypeSpec::TypeofExpr(subject) = &ty.base.spec {
            self.record(subject);
        }
    }

    fn record_items(&mut self, items: &[CInitItem]) {
        let mut seen_designator: bool = false;
        for item in items {
            if item.designators.len() > 1 {
                self.designator_path += 1;
            }
            for designator in &item.designators {
                match designator {
                    Designator::Field(_) => self.field_designator += 1,
                    Designator::Index(expr) => {
                        self.index_designator += 1;
                        self.record(expr);
                    }
                }
            }
            if item.designators.is_empty() && seen_designator {
                self.positional_after_designator += 1;
            }
            seen_designator |= !item.designators.is_empty();
            match &item.value {
                CInit::Expr(expr) => self.record(expr),
                CInit::List(nested) => {
                    self.nested_list += 1;
                    self.record_items(nested);
                }
            }
        }
    }
}

#[test]
fn compound_literals_and_designated_initializers_read_the_values_the_tree_names() {
    let compilers: &[Compiler] = required_compilers();
    let mut interner: Interner = Interner::new();
    let cases: Vec<Case> = {
        let mut cx: Cx<'_> = Cx::new(&mut interner);
        corpus(&mut cx)
    };

    let mut source: String = String::from(PREAMBLE);
    for (position, case) in cases.iter().enumerate() {
        let width: usize = if position % 2 == 0 { WIDE } else { NARROW };
        let rendered: String = render_expr(&case.expr, &interner, width);
        writeln!(
            source,
            "unsigned int lit_case{position}(void) {{ return (unsigned int)({rendered}); }}"
        )
        .expect("format probe");
    }
    source.push_str("int main(void) {\n");
    for (position, case) in cases.iter().enumerate() {
        writeln!(
            source,
            "    if (lit_case{position}() != {}u) return {};",
            case.expected,
            position + 1
        )
        .expect("format probe");
    }
    source.push_str("    return 0;\n}\n");

    let roster: String = cases
        .iter()
        .enumerate()
        .map(|(position, case): (usize, &Case)| format!("{}={}", position + 1, case.label))
        .collect::<Vec<String>>()
        .join(", ");
    for compiler in compilers {
        build_and_run(compiler, &source, &format!("compound literal ({roster})"));
    }
    println!(
        "compound literal values: {}/{} cases, compilers {}/{}",
        cases.len(),
        cases.len(),
        compilers.len(),
        compilers.len()
    );
}

#[test]
fn a_compound_literal_has_the_size_of_its_own_type() {
    let compilers: &[Compiler] = required_compilers();
    let mut interner: Interner = Interner::new();
    let pair: Symbol = interner.intern("pair");
    let probes: Vec<(CExpr, u64, &str)> = vec![
        (
            CExpr::SizeofExpr(Box::new(CExpr::compound(
                scalar_type(),
                vec![CInitItem::expr(lit(0))],
            ))),
            4,
            "scalar",
        ),
        (
            CExpr::SizeofExpr(Box::new(CExpr::compound(
                array_type(4),
                vec![CInitItem::at(
                    vec![Designator::Index(lit(0))],
                    CInit::Expr(lit(0)),
                )],
            ))),
            16,
            "array",
        ),
        (
            CExpr::SizeofExpr(Box::new(CExpr::compound(
                matrix_type(2, 2),
                vec![
                    CInitItem::nested(vec![CInitItem::expr(lit(1)), CInitItem::expr(lit(2))]),
                    CInitItem::nested(vec![CInitItem::expr(lit(3)), CInitItem::expr(lit(4))]),
                ],
            ))),
            16,
            "matrix",
        ),
        (
            CExpr::SizeofExpr(Box::new(CExpr::compound(
                tagged_type(pair),
                vec![CInitItem::expr(lit(1))],
            ))),
            8,
            "aggregate",
        ),
    ];

    let mut source: String = String::from(PREAMBLE);
    for (expr, size, label) in &probes {
        let rendered: String = render_expr(expr, &interner, WIDE);
        writeln!(
            source,
            "_Static_assert(({rendered}) == {size}, \"{label} compound literal width\");"
        )
        .expect("format probe");
    }
    for compiler in compilers {
        syntax_check(compiler, &source, "compound literal width");
    }
    println!(
        "compound literal widths: {}/{} probes, compilers {}/{}",
        probes.len(),
        probes.len(),
        compilers.len(),
        compilers.len()
    );
}

#[test]
fn every_initializer_shape_reaches_a_compiler_graded_corpus() {
    let mut interner: Interner = Interner::new();
    let cases: Vec<Case> = {
        let mut cx: Cx<'_> = Cx::new(&mut interner);
        corpus(&mut cx)
    };
    let mut census: Census = Census::default();
    for case in &cases {
        census.record(&case.expr);
    }

    for (count, name) in [
        (census.scalar, "scalar compound literal"),
        (census.array, "array compound literal"),
        (census.aggregate, "aggregate compound literal"),
        (census.typeof_spec, "typeof type specifier"),
        (census.field_designator, "field designator"),
        (census.index_designator, "index designator"),
        (census.designator_path, "nested designator path"),
        (census.nested_list, "brace nested initializer"),
        (
            census.positional_after_designator,
            "positional item after a designator",
        ),
    ] {
        assert!(count > 0, "{name} is ungraded");
    }
    println!(
        "initializer census: scalar {}, array {}, aggregate {}, typeof {}, field designators {}, \
         index designators {}, designator paths {}, nested lists {}, positional resumes {}",
        census.scalar,
        census.array,
        census.aggregate,
        census.typeof_spec,
        census.field_designator,
        census.index_designator,
        census.designator_path,
        census.nested_list,
        census.positional_after_designator
    );
}
