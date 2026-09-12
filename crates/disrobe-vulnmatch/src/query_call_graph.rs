use std::collections::{BTreeMap, BTreeSet};

use disrobe_query::model::{CallGraph, CallGraphEdge as QueryCallGraphEdge, CallGraphNode};

use crate::adapters::{
    CallGraphEdge, CallGraphView, CallSiteId, DirectCall, FunctionId, ResolvedCallee,
};

#[derive(Debug)]
pub struct QueryCallGraphView<'graph> {
    call_graph: &'graph CallGraph,
    node_ids: BTreeMap<(u64, &'graph str), FunctionId>,
}

impl<'graph> QueryCallGraphView<'graph> {
    pub fn new(call_graph: &'graph CallGraph) -> Self {
        let node_ids: BTreeMap<(u64, &'graph str), FunctionId> = call_graph
            .nodes
            .iter()
            .map(|node: &CallGraphNode| {
                (
                    (node.address, node.name.as_str()),
                    Self::function_id(&node.name, node.address),
                )
            })
            .collect();
        Self {
            call_graph,
            node_ids,
        }
    }

    fn function_id(name: &str, address: u64) -> FunctionId {
        FunctionId::new(format!("query:{address:016x}:{name}"))
    }

    fn node_id(&self, name: &str, address: u64) -> Option<FunctionId> {
        self.node_ids.get(&(address, name)).cloned()
    }

    fn caller_id(edge: &QueryCallGraphEdge) -> FunctionId {
        Self::function_id(&edge.caller, edge.caller_address)
    }

    fn callee_id(&self, edge: &QueryCallGraphEdge) -> Option<FunctionId> {
        self.node_id(&edge.callee, edge.callee_address)
    }

    fn call_site_id(edge: &QueryCallGraphEdge) -> CallSiteId {
        CallSiteId::new(format!(
            "query:{:016x}:{:016x}",
            edge.caller_address, edge.call_site
        ))
    }

    fn generated_callee_name(edge: &QueryCallGraphEdge) -> String {
        format!("sub_{:x}", edge.callee_address)
    }

    fn resolved_callee(
        edge: &QueryCallGraphEdge,
        callee_function: Option<&FunctionId>,
    ) -> Option<ResolvedCallee> {
        if callee_function.is_none() && edge.callee == Self::generated_callee_name(edge) {
            return None;
        }
        Some(ResolvedCallee::new(edge.callee.clone()))
    }

    fn direct_call(&self, edge: &QueryCallGraphEdge) -> DirectCall {
        let callee_function: Option<FunctionId> = self.callee_id(edge);
        DirectCall::new(
            Self::call_site_id(edge),
            Self::caller_id(edge),
            callee_function.clone(),
            Self::resolved_callee(edge, callee_function.as_ref()),
            Vec::new(),
        )
    }
}

impl CallGraphView for QueryCallGraphView<'_> {
    fn functions(&self) -> Vec<FunctionId> {
        let functions: BTreeSet<FunctionId> = self.node_ids.values().cloned().collect();
        functions.into_iter().collect()
    }

    fn direct_calls(&self) -> Vec<DirectCall> {
        let mut calls: Vec<DirectCall> = self
            .call_graph
            .edges
            .iter()
            .map(|edge: &QueryCallGraphEdge| self.direct_call(edge))
            .collect();
        calls.sort();
        calls.dedup();
        calls
    }

    fn entry_points_complete(&self) -> bool {
        false
    }

    fn call_edges(&self) -> Vec<CallGraphEdge> {
        let mut edges: Vec<CallGraphEdge> = self
            .call_graph
            .edges
            .iter()
            .map(|edge: &QueryCallGraphEdge| self.direct_call(edge).direct_edge())
            .collect();
        edges.sort();
        edges.dedup();
        edges
    }

    fn entry_points(&self) -> Vec<FunctionId> {
        let exports: BTreeSet<FunctionId> = self
            .call_graph
            .nodes
            .iter()
            .filter(|node: &&CallGraphNode| node.is_export)
            .map(|node: &CallGraphNode| Self::function_id(&node.name, node.address))
            .collect();
        if !exports.is_empty() {
            return exports.into_iter().collect();
        }
        let callees: BTreeSet<FunctionId> = self
            .call_graph
            .edges
            .iter()
            .filter_map(|edge: &QueryCallGraphEdge| self.callee_id(edge))
            .collect();
        let roots: BTreeSet<FunctionId> = self
            .functions()
            .into_iter()
            .filter(|function: &FunctionId| !callees.contains(function))
            .collect();
        if roots.is_empty() {
            return self.functions();
        }
        roots.into_iter().collect()
    }
}
