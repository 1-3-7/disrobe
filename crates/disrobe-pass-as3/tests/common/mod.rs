#![allow(dead_code, clippy::redundant_pub_crate)]

use std::collections::BTreeMap;

use disrobe_pass_as3::lifter::{CaseLabel, Expr, Stmt, SwitchCase};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Int(i64),
    Bool(bool),
    Str(String),
    Null,
}

impl Value {
    pub(crate) fn as_int(&self) -> i64 {
        match self {
            Self::Int(value) => *value,
            Self::Bool(true) => 1,
            Self::Bool(false) => 0,
            Self::Str(value) => panic!("a recovered body used string {value:?} as a number"),
            Self::Null => panic!("a recovered body used null as a number"),
        }
    }

    pub(crate) const fn as_bool(&self) -> bool {
        match self {
            Self::Int(value) => *value != 0,
            Self::Bool(value) => *value,
            Self::Str(value) => !value.is_empty(),
            Self::Null => false,
        }
    }

    pub(crate) fn equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Null, _) | (_, Self::Null) => false,
            (Self::Str(left), Self::Str(right)) => left == right,
            (Self::Str(_), _) | (_, Self::Str(_)) => {
                panic!("a recovered body compared a string against a non-string")
            }
            _ => self.as_int() == other.as_int(),
        }
    }

    pub(crate) fn render(&self) -> String {
        match self {
            Self::Int(value) => value.to_string(),
            Self::Bool(value) => value.to_string(),
            Self::Str(value) => value.clone(),
            Self::Null => "null".to_owned(),
        }
    }
}

enum Flow {
    Fell,
    Returned(Value),
    Broke,
    Continued,
}

pub(crate) struct Machine {
    slots: BTreeMap<u32, Value>,
    steps: usize,
    method: String,
}

const MAX_STEPS: usize = 1 << 20;

impl Machine {
    fn new(method: &str, arguments: &[(u32, Value)]) -> Self {
        Self {
            slots: arguments.iter().cloned().collect(),
            steps: 0,
            method: method.to_owned(),
        }
    }

    fn charge(&mut self) {
        self.steps += 1;
        assert!(
            self.steps <= MAX_STEPS,
            "evaluating the recovered {} body exceeded {MAX_STEPS} steps",
            self.method
        );
    }

    fn slot(&self, index: u32) -> Value {
        self.slots.get(&index).cloned().unwrap_or(Value::Null)
    }

    fn eval(&mut self, expr: &Expr) -> Value {
        self.charge();
        match expr {
            Expr::IntLit(value) => Value::Int(*value),
            Expr::UintLit(value) => Value::Int(i64::try_from(*value).unwrap_or(i64::MAX)),
            Expr::BoolLit(value) => Value::Bool(*value),
            Expr::StringLit(value) => Value::Str(value.clone()),
            Expr::Null | Expr::Undefined => Value::Null,
            Expr::Local(index) | Expr::Param(index) => self.slot(*index),
            Expr::Coerce { ty, operand } => {
                let inner: Value = self.eval(operand);
                match ty.as_str() {
                    "int" | "uint" | "Number" => match inner {
                        Value::Null => Value::Null,
                        other => Value::Int(other.as_int()),
                    },
                    "Boolean" => Value::Bool(inner.as_bool()),
                    "String" | "Object" | "*" => inner,
                    other => panic!(
                        "the recovered {} body coerces to unmodelled type {other}",
                        self.method
                    ),
                }
            }
            Expr::Unary { op, operand } => {
                let inner: Value = self.eval(operand);
                match *op {
                    "!" => Value::Bool(!inner.as_bool()),
                    "-" => Value::Int(-inner.as_int()),
                    other => panic!(
                        "the recovered {} body uses unmodelled unary {other}",
                        self.method
                    ),
                }
            }
            Expr::Update {
                op,
                operand,
                postfix,
            } => self.eval_update(op, operand, *postfix),
            Expr::Ternary {
                cond,
                then_value,
                else_value,
            } => {
                if self.eval(cond).as_bool() {
                    self.eval(then_value)
                } else {
                    self.eval(else_value)
                }
            }
            Expr::Binary { op, lhs, rhs } => self.eval_binary(op, lhs, rhs),
            other => panic!(
                "the recovered {} body uses unmodelled expression {other:?}",
                self.method
            ),
        }
    }

    fn eval_update(&mut self, op: &str, operand: &Expr, postfix: bool) -> Value {
        let (Expr::Local(index) | Expr::Param(index)) = operand else {
            panic!(
                "the recovered {} body updates a non-slot operand",
                self.method
            );
        };
        let before: i64 = self.slot(*index).as_int();
        let after: i64 = match op {
            "++" => before + 1,
            "--" => before - 1,
            other => panic!(
                "the recovered {} body uses unmodelled update {other}",
                self.method
            ),
        };
        self.slots.insert(*index, Value::Int(after));
        Value::Int(if postfix { before } else { after })
    }

    fn eval_binary(&mut self, op: &str, lhs: &Expr, rhs: &Expr) -> Value {
        if op == "&&" {
            let left: Value = self.eval(lhs);
            return if left.as_bool() { self.eval(rhs) } else { left };
        }
        if op == "||" {
            let left: Value = self.eval(lhs);
            return if left.as_bool() { left } else { self.eval(rhs) };
        }
        let left: Value = self.eval(lhs);
        let right: Value = self.eval(rhs);
        match op {
            "+" => match (&left, &right) {
                (Value::Str(_), _) | (_, Value::Str(_)) => {
                    Value::Str(format!("{}{}", left.render(), right.render()))
                }
                _ => Value::Int(left.as_int() + right.as_int()),
            },
            "-" => Value::Int(left.as_int() - right.as_int()),
            "*" => Value::Int(left.as_int() * right.as_int()),
            "/" => Value::Int(left.as_int() / right.as_int()),
            "%" => Value::Int(left.as_int() % right.as_int()),
            ">" => Value::Bool(left.as_int() > right.as_int()),
            "<" => Value::Bool(left.as_int() < right.as_int()),
            ">=" => Value::Bool(left.as_int() >= right.as_int()),
            "<=" => Value::Bool(left.as_int() <= right.as_int()),
            "==" | "===" => Value::Bool(left.equals(&right)),
            "!=" | "!==" => Value::Bool(!left.equals(&right)),
            other => panic!(
                "the recovered {} body uses unmodelled operator {other}",
                self.method
            ),
        }
    }

    fn matching_case(&mut self, cases: &[SwitchCase], selector: &Value) -> Option<usize> {
        let mut fallback: Option<usize> = None;
        for (index, case) in cases.iter().enumerate() {
            for label in &case.labels {
                match label {
                    CaseLabel::Default => fallback = Some(index),
                    CaseLabel::Value(value) => {
                        if selector.equals(&Value::Int(*value)) {
                            return Some(index);
                        }
                    }
                    CaseLabel::Expr(expr) => {
                        let expected: Value = self.eval(expr);
                        if selector.equals(&expected) {
                            return Some(index);
                        }
                    }
                }
            }
        }
        fallback
    }

    fn run_switch(&mut self, selector: &Expr, cases: &[SwitchCase]) -> Flow {
        let value: Value = self.eval(selector);
        let Some(start): Option<usize> = self.matching_case(cases, &value) else {
            return Flow::Fell;
        };
        for case in cases.iter().skip(start) {
            match self.run(&case.body) {
                Flow::Returned(returned) => return Flow::Returned(returned),
                Flow::Broke => return Flow::Fell,
                Flow::Continued => return Flow::Continued,
                Flow::Fell => {}
            }
            if case.breaks {
                return Flow::Fell;
            }
        }
        Flow::Fell
    }

    fn run(&mut self, stmts: &[Stmt]) -> Flow {
        for stmt in stmts {
            self.charge();
            match stmt {
                Stmt::Assign {
                    target: Expr::Local(index) | Expr::Param(index),
                    value,
                } => {
                    let evaluated: Value = self.eval(value);
                    self.slots.insert(*index, evaluated);
                }
                Stmt::Expression(value) => {
                    self.eval(value);
                }
                Stmt::Return(Some(value)) => {
                    let evaluated: Value = self.eval(value);
                    return Flow::Returned(evaluated);
                }
                Stmt::Return(None) => return Flow::Returned(Value::Null),
                Stmt::Break => return Flow::Broke,
                Stmt::Continue => return Flow::Continued,
                Stmt::IfBlock { cond, body } => {
                    if self.eval(cond).as_bool() {
                        match self.run(body) {
                            Flow::Fell => {}
                            other => return other,
                        }
                    }
                }
                Stmt::IfElse {
                    cond,
                    then_body,
                    else_body,
                } => {
                    let taken: &Vec<Stmt> = if self.eval(cond).as_bool() {
                        then_body
                    } else {
                        else_body
                    };
                    match self.run(taken) {
                        Flow::Fell => {}
                        other => return other,
                    }
                }
                Stmt::While { cond, body } => loop {
                    self.charge();
                    if !self.eval(cond).as_bool() {
                        break;
                    }
                    match self.run(body) {
                        Flow::Fell | Flow::Continued => {}
                        Flow::Broke => break,
                        Flow::Returned(value) => return Flow::Returned(value),
                    }
                },
                Stmt::DoWhile { cond, body } => loop {
                    self.charge();
                    match self.run(body) {
                        Flow::Fell | Flow::Continued => {}
                        Flow::Broke => break,
                        Flow::Returned(value) => return Flow::Returned(value),
                    }
                    if !self.eval(cond).as_bool() {
                        break;
                    }
                },
                Stmt::StructuredSwitch { selector, cases } => {
                    match self.run_switch(selector, cases) {
                        Flow::Fell => {}
                        other => return other,
                    }
                }
                other => panic!(
                    "the recovered {} body uses unmodelled statement {other:?}",
                    self.method
                ),
            }
        }
        Flow::Fell
    }
}

pub(crate) fn evaluate(stmts: &[Stmt], method: &str, arguments: &[(u32, Value)]) -> Value {
    let mut machine: Machine = Machine::new(method, arguments);
    match machine.run(stmts) {
        Flow::Returned(value) => value,
        Flow::Fell => Value::Null,
        Flow::Broke | Flow::Continued => {
            panic!("the recovered {method} body left a loop from its top level")
        }
    }
}
