use super::ir::{BinaryOp, Expr, Stmt, SwitchCase};
use super::value::Value;

#[derive(Debug, Clone)]
pub(super) struct DispatcherShape<'a> {
    pub state_sum: &'a Expr,
    pub terminal: f64,
    pub with_object: &'a Expr,
    pub cases: &'a [SwitchCase],
}

pub(super) fn match_dispatcher_parts<'a>(
    test: &'a Expr,
    body: &'a [Stmt],
) -> Option<DispatcherShape<'a>> {
    let (state_sum, terminal): (&Expr, f64) = match_terminal_test(test)?;
    let [
        Stmt::With {
            object,
            body: with_body,
        },
    ] = body
    else {
        return None;
    };
    let [
        Stmt::Switch {
            discriminant,
            cases,
        },
    ] = with_body.as_slice()
    else {
        return None;
    };
    if discriminant != state_sum {
        return None;
    }
    Some(DispatcherShape {
        state_sum,
        terminal,
        with_object: object,
        cases,
    })
}

fn match_terminal_test(test: &Expr) -> Option<(&Expr, f64)> {
    let Expr::Binary { op, left, right } = test else {
        return None;
    };
    if !matches!(op, BinaryOp::StrictNeq | BinaryOp::Neq) {
        return None;
    }
    let terminal: f64 = const_number(right)?;
    Some((left.as_ref(), terminal))
}

pub(super) fn const_number(expr: &Expr) -> Option<f64> {
    match expr {
        Expr::Num(n) => Some(*n),
        Expr::Unary {
            op: super::ir::UnaryOp::Neg,
            argument,
        } => const_number(argument).map(|n| -n),
        Expr::Unary {
            op: super::ir::UnaryOp::Pos,
            argument,
        } => const_number(argument),
        _ => None,
    }
}

pub(super) struct BranchEdge {
    pub sum: f64,
    pub scope: super::value::Scope,
    pub with_chain: Option<super::value::WithScope>,
}

pub(super) enum BlockExit {
    Goto(f64),
    Branch {
        test: Expr,
        then_edge: Box<BranchEdge>,
        else_edge: Box<BranchEdge>,
    },
    Return(Value),
    Bail,
}

pub(super) fn split_block_transition(stmts: &[Stmt]) -> (Vec<&Stmt>, Option<&Stmt>) {
    let mut actions: Vec<&Stmt> = Vec::new();
    let mut terminal: Option<&Stmt> = None;
    for stmt in stmts {
        match stmt {
            Stmt::Break(_) => break,
            Stmt::Return(_) | Stmt::If { .. } => {
                terminal = Some(stmt);
                break;
            }
            other => actions.push(other),
        }
    }
    (actions, terminal)
}
