use serde::{Deserialize, Serialize};

use crate::rules::SourceClass;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FunctionId(String);

impl FunctionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CallSiteId(String);

impl CallSiteId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResolvedCallee {
    pub canonical_name: String,
}

impl ResolvedCallee {
    pub fn new(canonical_name: impl Into<String>) -> Self {
        Self {
            canonical_name: canonical_name.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstractArgument {
    Constant,
    NonConstant,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DirectCall {
    pub id: CallSiteId,
    pub caller: FunctionId,
    pub callee_function: Option<FunctionId>,
    pub resolved_callee: Option<ResolvedCallee>,
    pub arguments: Vec<AbstractArgument>,
}

impl DirectCall {
    pub const fn new(
        id: CallSiteId,
        caller: FunctionId,
        callee_function: Option<FunctionId>,
        resolved_callee: Option<ResolvedCallee>,
        arguments: Vec<AbstractArgument>,
    ) -> Self {
        Self {
            id,
            caller,
            callee_function,
            resolved_callee,
            arguments,
        }
    }
}

pub trait CallGraphView {
    fn functions(&self) -> Vec<FunctionId>;

    fn direct_calls(&self) -> Vec<DirectCall>;

    fn entry_points(&self) -> Vec<FunctionId>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintStatus {
    Unknown,
    Absent,
}

pub trait TaintOracle {
    fn taint_status(&self, source: &SourceClass, site: &DirectCall) -> TaintStatus;
}
