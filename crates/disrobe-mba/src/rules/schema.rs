use crate::expr::{BinOp, UnOp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum Binary {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

impl Binary {
    #[must_use]
    pub const fn to_mba(self) -> BinOp {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum Unary {
    Neg,
    Not,
}

impl Unary {
    #[must_use]
    pub const fn to_mba(self) -> UnOp {
        match self {
            Self::Neg => UnOp::Neg,
            Self::Not => UnOp::Not,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Pattern {
    AnyExpr {
        bind: String,
    },
    AnyConst {
        bind: String,
    },
    Const {
        value: u64,
    },
    Var {
        index: u32,
    },
    Unary {
        op: Unary,
        operand: Box<Self>,
    },
    Binary {
        op: Binary,
        left: Box<Self>,
        right: Box<Self>,
    },
    Ite {
        cond: Box<Self>,
        then: Box<Self>,
        otherwise: Box<Self>,
    },
    Slice {
        inner: Box<Self>,
        lo: u32,
        hi: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum Condition {
    IsZero { expr: String },
    IsNonZero { expr: String },
    IsOne { expr: String },
    IsAllOnes { expr: String },
    Equal { left: String, right: String },
    Complement { left: String, right: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "build", rename_all = "snake_case")]
pub enum Template {
    Use {
        expr: String,
    },
    Const {
        value: u64,
    },
    AllOnes,
    Unary {
        op: Unary,
        operand: Box<Self>,
    },
    Binary {
        op: Binary,
        left: Box<Self>,
        right: Box<Self>,
    },
    SliceConst {
        expr: String,
        lo: u32,
        hi: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub widths: Vec<u8>,
    pub proof: String,
    pub source: String,
    pub pattern: Pattern,
    #[serde(default)]
    pub when: Vec<Condition>,
    pub rewrite: Template,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    #[serde(default)]
    pub commutative_match: bool,
    pub rules: Vec<Rule>,
}

impl RuleSet {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
