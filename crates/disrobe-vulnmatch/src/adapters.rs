use std::collections::BTreeSet;

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

    pub fn direct_edge(&self) -> CallGraphEdge {
        CallGraphEdge {
            id: self.id.clone(),
            caller: self.caller.clone(),
            kind: EdgeKind::Direct {
                callee: self.callee_function.clone(),
            },
        }
    }
}

pub const MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EdgeKind {
    Direct { callee: Option<FunctionId> },
    ResolvedIndirect { candidates: BTreeSet<FunctionId> },
    UnresolvedIndirect,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallGraphEdge {
    pub id: CallSiteId,
    pub caller: FunctionId,
    pub kind: EdgeKind,
}

pub trait CallGraphView {
    fn functions(&self) -> Vec<FunctionId>;

    fn direct_calls(&self) -> Vec<DirectCall>;

    fn call_edges(&self) -> Vec<CallGraphEdge> {
        let mut edges: Vec<CallGraphEdge> = self
            .direct_calls()
            .into_iter()
            .map(|call: DirectCall| call.direct_edge())
            .collect();
        edges.sort();
        edges
    }

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
