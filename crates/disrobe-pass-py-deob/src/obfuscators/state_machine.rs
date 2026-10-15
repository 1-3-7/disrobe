use std::collections::BTreeMap;

use ruff_python_ast::visitor::{Visitor, walk_expr, walk_stmt};
use ruff_python_ast::{
    AtomicNodeIndex, CmpOp, ExceptHandler, Expr, ExprCompare, ModModule, Number, Operator, Stmt,
    StmtAssign, StmtAugAssign, StmtIf, StmtPass, StmtWhile, UnaryOp,
};
use ruff_python_codegen::{Generator, Stylist};
use ruff_python_parser::{Parsed, parse_module};
use ruff_text_size::TextRange;

const MAX_STATES: usize = 65_536;

pub(crate) fn unflatten(source: &str) -> Option<(String, usize)> {
    let parsed: Parsed<ModModule> = parse_module(source).ok()?;
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), source);
    let mut module: ModModule = parsed.into_syntax();
    let mut counter: NameCounter = NameCounter::default();
    for stmt in &module.body {
        counter.visit_stmt(stmt);
    }
    let mut rewriter: Rewriter = Rewriter {
        uses: counter.uses,
        machines: 0,
    };
    rewriter.body(&mut module.body, true);
    if rewriter.machines == 0 {
        return None;
    }
    let mut out: String = String::with_capacity(source.len());
    for stmt in &module.body {
        out.push_str(&Generator::from(&stylist).stmt(stmt));
        out.push('\n');
    }
    Some((out, rewriter.machines))
}

struct Rewriter {
    uses: BTreeMap<String, usize>,
    machines: usize,
}

impl Rewriter {
    fn body(&mut self, body: &mut Vec<Stmt>, opens_scope: bool) {
        for stmt in body.iter_mut() {
            self.nested(stmt);
        }
        let mut index: usize = 0;
        let mut changed: bool = false;
        while index + 1 < body.len() {
            let Some(states) = self.machine(&body[index], &body[index + 1]) else {
                index += 1;
                continue;
            };
            let at_scope_start: bool = opens_scope && index == 0;
            let mut sequential: Vec<Stmt> = states;
            if at_scope_start && sequential.first().is_some_and(is_string_statement) {
                sequential.remove(0);
            }
            let count: usize = sequential.len();
            body.splice(index..index + 2, sequential);
            index += count;
            self.machines += 1;
            changed = true;
        }
        if changed && body.is_empty() {
            body.push(Stmt::Pass(StmtPass {
                node_index: AtomicNodeIndex::default(),
                range: TextRange::default(),
            }));
        }
    }

    fn nested(&mut self, stmt: &mut Stmt) {
        match stmt {
            Stmt::FunctionDef(function) => self.body(&mut function.body, true),
            Stmt::ClassDef(class) => self.body(&mut class.body, true),
            Stmt::If(conditional) => {
                self.body(&mut conditional.body, false);
                for clause in &mut conditional.elif_else_clauses {
                    self.body(&mut clause.body, false);
                }
            }
            Stmt::For(loop_) => {
                self.body(&mut loop_.body, false);
                self.body(&mut loop_.orelse, false);
            }
            Stmt::While(loop_) => {
                self.body(&mut loop_.body, false);
                self.body(&mut loop_.orelse, false);
            }
            Stmt::With(with) => self.body(&mut with.body, false),
            Stmt::Try(attempt) => {
                self.body(&mut attempt.body, false);
                for handler in &mut attempt.handlers {
                    let ExceptHandler::ExceptHandler(handler) = handler;
                    self.body(&mut handler.body, false);
                }
                self.body(&mut attempt.orelse, false);
                self.body(&mut attempt.finalbody, false);
            }
            Stmt::Match(matched) => {
                for case in &mut matched.cases {
                    self.body(&mut case.body, false);
                }
            }
            _ => {}
        }
    }

    fn machine(&self, init: &Stmt, run: &Stmt) -> Option<Vec<Stmt>> {
        let Stmt::Assign(StmtAssign { targets, value, .. }) = init else {
            return None;
        };
        let [Expr::Name(state)] = targets.as_slice() else {
            return None;
        };
        if int_literal(value)? != 0 {
            return None;
        }
        let Stmt::While(StmtWhile {
            test, body, orelse, ..
        }) = run
        else {
            return None;
        };
        let state: &str = state.id.as_str();
        let count: usize = compare_to(test, state, CmpOp::Lt)?;
        if !orelse.is_empty() || count == 0 || count > MAX_STATES {
            return None;
        }
        let mut local: NameCounter = NameCounter::default();
        local.visit_stmt(init);
        local.visit_stmt(run);
        if self.uses.get(state) != local.uses.get(state) {
            return None;
        }
        let states: Vec<Vec<Stmt>> = split_states(body, state)?;
        if states.len() != count {
            return None;
        }
        let sequential: Vec<Stmt> = states.into_iter().flatten().collect();
        let mut inner: NameCounter = NameCounter::default();
        for stmt in &sequential {
            inner.visit_stmt(stmt);
        }
        if inner.uses.contains_key(state) || sequential.iter().any(escapes_loop) {
            return None;
        }
        Some(sequential)
    }
}

fn split_states(body: &[Stmt], state: &str) -> Option<Vec<Vec<Stmt>>> {
    let mut states: Vec<Vec<Stmt>> = Vec::new();
    let mut index: usize = 0;
    while index < body.len() {
        let Stmt::If(StmtIf {
            test,
            body: branch,
            elif_else_clauses,
            ..
        }) = &body[index]
        else {
            return None;
        };
        if !elif_else_clauses.is_empty() {
            return None;
        }
        let expected: usize = states.len();
        if compare_to(test, state, CmpOp::Eq) == Some(expected) {
            states.push(state_body(branch, state)?);
            index += 1;
            continue;
        }
        let Expr::UnaryOp(negated) = test.as_ref() else {
            return None;
        };
        if negated.op != UnaryOp::Not
            || compare_to(&negated.operand, state, CmpOp::Eq) != Some(expected)
            || !matches!(branch.as_slice(), [Stmt::Continue(_)])
        {
            return None;
        }
        states.push(state_body(&body[index + 1..], state)?);
        index = body.len();
    }
    Some(states)
}

fn state_body(stmts: &[Stmt], state: &str) -> Option<Vec<Stmt>> {
    match stmts.split_last()? {
        (
            Stmt::AugAssign(StmtAugAssign {
                target, op, value, ..
            }),
            rest,
        ) if *op == Operator::Add
            && matches!(target.as_ref(), Expr::Name(name) if name.id.as_str() == state)
            && int_literal(value) == Some(1) =>
        {
            Some(rest.to_vec())
        }
        (Stmt::Return(_) | Stmt::Raise(_), _) => Some(stmts.to_vec()),
        _ => None,
    }
}

fn compare_to(test: &Expr, state: &str, wanted: CmpOp) -> Option<usize> {
    let Expr::Compare(ExprCompare {
        left,
        ops,
        comparators,
        ..
    }) = test
    else {
        return None;
    };
    let ([op], [bound]) = (ops.as_ref(), comparators.as_ref()) else {
        return None;
    };
    if *op != wanted || !matches!(left.as_ref(), Expr::Name(name) if name.id.as_str() == state) {
        return None;
    }
    usize::try_from(int_literal(bound)?).ok()
}

const fn int_literal(expr: &Expr) -> Option<u64> {
    let Expr::NumberLiteral(number) = expr else {
        return None;
    };
    let Number::Int(int) = &number.value else {
        return None;
    };
    int.as_u64()
}

fn is_string_statement(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Expr(expr) if matches!(expr.value.as_ref(), Expr::StringLiteral(_)))
}

fn escapes_loop(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Break(_) | Stmt::Continue(_) => true,
        Stmt::If(conditional) => {
            conditional.body.iter().any(escapes_loop)
                || conditional
                    .elif_else_clauses
                    .iter()
                    .any(|clause| clause.body.iter().any(escapes_loop))
        }
        Stmt::With(with) => with.body.iter().any(escapes_loop),
        Stmt::Try(attempt) => {
            attempt.body.iter().any(escapes_loop)
                || attempt.handlers.iter().any(|handler| {
                    let ExceptHandler::ExceptHandler(handler) = handler;
                    handler.body.iter().any(escapes_loop)
                })
                || attempt.orelse.iter().any(escapes_loop)
                || attempt.finalbody.iter().any(escapes_loop)
        }
        Stmt::Match(matched) => matched
            .cases
            .iter()
            .any(|case| case.body.iter().any(escapes_loop)),
        Stmt::For(loop_) => loop_.orelse.iter().any(escapes_loop),
        Stmt::While(loop_) => loop_.orelse.iter().any(escapes_loop),
        _ => false,
    }
}

#[derive(Default)]
struct NameCounter {
    uses: BTreeMap<String, usize>,
}

impl<'a> Visitor<'a> for NameCounter {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::Global(global) => {
                for name in &global.names {
                    *self.uses.entry(name.to_string()).or_default() += 1;
                }
            }
            Stmt::Nonlocal(nonlocal) => {
                for name in &nonlocal.names {
                    *self.uses.entry(name.to_string()).or_default() += 1;
                }
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Name(name) = expr {
            *self.uses.entry(name.id.to_string()).or_default() += 1;
        }
        walk_expr(self, expr);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn unflattened(source: &str) -> Option<String> {
        unflatten(source).map(|(text, _): (String, usize)| text)
    }

    #[test]
    fn a_linear_machine_runs_its_states_in_order() {
        let source: &str = "def main():\n    _st_1 = 0\n    while _st_1 < 3:\n        if _st_1 == 0:\n            print('a')\n            _st_1 += 1\n        if _st_1 == 1:\n            x = 2\n            _st_1 += 1\n        if not _st_1 == 2:\n            continue\n        print(x)\n        _st_1 += 1\n";
        assert_eq!(
            unflattened(source).expect("unflattens"),
            "def main():\n    print('a')\n    x = 2\n    print(x)\n"
        );
    }

    #[test]
    fn a_single_state_and_an_empty_state_unflatten() {
        let source: &str = "class C:\n    def __init__(self, v):\n        _st_2 = 0\n        while _st_2 < 1:\n            if not _st_2 == 0:\n                continue\n            self.v = v\n            _st_2 += 1\n\n    def close(self):\n        _st_3 = 0\n        while _st_3 < 1:\n            if not _st_3 == 0:\n                continue\n            _st_3 += 1\n";
        assert_eq!(
            unflattened(source).expect("unflattens"),
            "class C:\n\n    def __init__(self, v):\n        self.v = v\n\n    def close(self):\n        pass\n"
        );
    }

    #[test]
    fn a_demoted_docstring_stays_out_of_docstring_position() {
        let source: &str = "def f(t):\n    _st_4 = 0\n    while _st_4 < 2:\n        if _st_4 == 0:\n            'text'\n            _st_4 += 1\n        if not _st_4 == 1:\n            continue\n        t.close()\n        _st_4 += 1\n";
        assert_eq!(
            unflattened(source).expect("unflattens"),
            "def f(t):\n    t.close()\n"
        );
    }

    #[test]
    fn a_returning_state_ends_the_sequence() {
        let source: &str = "def f():\n    _st_5 = 0\n    while _st_5 < 2:\n        if _st_5 == 0:\n            y = 1\n            _st_5 += 1\n        if _st_5 == 1:\n            return y\n";
        assert_eq!(
            unflattened(source).expect("unflattens"),
            "def f():\n    y = 1\n    return y\n"
        );
    }

    #[test]
    fn machines_that_are_not_linear_stay() {
        for source in [
            "def f():\n    _st_6 = 0\n    while _st_6 < 2:\n        if _st_6 == 1:\n            print(1)\n            _st_6 += 1\n        if _st_6 == 0:\n            print(0)\n            _st_6 += 1\n",
            "def f():\n    _st_7 = 0\n    while _st_7 < 2:\n        if _st_7 == 0:\n            _st_7 = 1\n            _st_7 += 1\n        if _st_7 == 1:\n            print(1)\n            _st_7 += 1\n",
            "def f():\n    _st_8 = 0\n    while _st_8 < 1:\n        if not _st_8 == 0:\n            continue\n        print(_st_8)\n        _st_8 += 1\n",
            "def f():\n    _st_9 = 0\n    while _st_9 < 1:\n        if not _st_9 == 0:\n            continue\n        print(1)\n        _st_9 += 1\n    print(_st_9)\n",
            "def f(xs):\n    _st_10 = 0\n    while _st_10 < 1:\n        if not _st_10 == 0:\n            continue\n        if xs:\n            break\n        _st_10 += 1\n",
            "def f():\n    _st_11 = 0\n    while _st_11 < 3:\n        if _st_11 == 0:\n            print(0)\n            _st_11 += 1\n        if _st_11 == 1:\n            print(1)\n            _st_11 += 1\n",
            "def f():\n    _st_12 = 0\n    while _st_12 < 1:\n        if not _st_12 == 0:\n            continue\n        print(1)\n        _st_12 += 2\n",
        ] {
            assert_eq!(unflattened(source), None, "{source}");
        }
    }

    #[test]
    fn breaks_inside_an_inner_loop_belong_to_it() {
        let source: &str = "def f(xs):\n    _st_13 = 0\n    while _st_13 < 1:\n        if not _st_13 == 0:\n            continue\n        for x in xs:\n            break\n        _st_13 += 1\n";
        assert_eq!(
            unflattened(source).expect("unflattens"),
            "def f(xs):\n    for x in xs:\n        break\n"
        );
    }
}
