use std::collections::BTreeMap;

use disrobe_query::{CallGraph, CallGraphEdge, Module};

#[derive(Debug, Clone, Default)]
pub(super) struct CallIndex {
    by_caller: BTreeMap<u64, Vec<CallGraphEdge>>,
    by_callee: BTreeMap<u64, Vec<CallGraphEdge>>,
    all: Vec<CallGraphEdge>,
}

impl CallIndex {
    pub(super) fn build(module: &Module) -> Self {
        let graph: CallGraph = module.call_graph();
        let mut by_caller: BTreeMap<u64, Vec<CallGraphEdge>> = BTreeMap::new();
        let mut by_callee: BTreeMap<u64, Vec<CallGraphEdge>> = BTreeMap::new();
        for edge in &graph.edges {
            by_caller
                .entry(edge.caller_address)
                .or_default()
                .push(edge.clone());
            by_callee
                .entry(edge.callee_address)
                .or_default()
                .push(edge.clone());
        }
        Self {
            by_caller,
            by_callee,
            all: graph.edges,
        }
    }

    pub(super) fn calls_to(
        &self,
        function_address: Option<u64>,
        pattern: &str,
    ) -> Option<(u64, String)> {
        let edges: &[CallGraphEdge] = function_address.map_or(self.all.as_slice(), |fa: u64| {
            self.by_caller.get(&fa).map_or(&[][..], Vec::as_slice)
        });
        edges
            .iter()
            .find(|e: &&CallGraphEdge| tag_substring_matches(pattern, &e.callee))
            .map(|e: &CallGraphEdge| (e.call_site, e.callee.clone()))
    }

    pub(super) fn calls_from(
        &self,
        function_address: Option<u64>,
        pattern: &str,
    ) -> Option<(u64, String)> {
        let edges: &[CallGraphEdge] = function_address.map_or(self.all.as_slice(), |fa: u64| {
            self.by_callee.get(&fa).map_or(&[][..], Vec::as_slice)
        });
        edges
            .iter()
            .find(|e: &&CallGraphEdge| tag_substring_matches(pattern, &e.caller))
            .map(|e: &CallGraphEdge| (e.call_site, e.caller.clone()))
    }
}

fn tag_substring_matches(pattern: &str, have: &str) -> bool {
    have.to_ascii_lowercase()
        .contains(&pattern.to_ascii_lowercase())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_ir::payload::{
        DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow,
    };

    fn payload() -> DisasmPayload {
        DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                DisasmInstruction {
                    offset: 0x10,
                    bytes: vec![0xe8],
                    mnemonic: "call".to_owned(),
                    operands: vec!["0x20".to_owned()],
                    flow: InsnFlow::Call,
                    branch_target: Some(0x20),
                    ..DisasmInstruction::default()
                },
                DisasmInstruction {
                    offset: 0x15,
                    bytes: vec![0xc3],
                    mnemonic: "ret".to_owned(),
                    operands: vec![],
                    flow: InsnFlow::Return,
                    branch_target: None,
                    ..DisasmInstruction::default()
                },
                DisasmInstruction {
                    offset: 0x20,
                    bytes: vec![0xc3],
                    mnemonic: "ret".to_owned(),
                    operands: vec![],
                    flow: InsnFlow::Return,
                    branch_target: None,
                    ..DisasmInstruction::default()
                },
            ],
            symbol_table: vec![
                DisasmSymbol {
                    address: 0x10,
                    name: "caller".to_owned(),
                    kind: DisasmSymbolKind::Function,
                },
                DisasmSymbol {
                    address: 0x20,
                    name: "callee".to_owned(),
                    kind: DisasmSymbolKind::Function,
                },
            ],
        }
    }

    #[test]
    fn calls_to_and_calls_from_resolve_the_real_internal_edge() {
        let module: Module = Module::from_disasm(&payload());
        let index: CallIndex = CallIndex::build(&module);
        let (site, callee): (u64, String) =
            index.calls_to(Some(0x10), "call").expect("calls-to hit");
        assert_eq!(site, 0x10);
        assert_eq!(callee, "callee");
        assert!(index.calls_to(Some(0x20), "call").is_none());

        let (site, caller): (u64, String) = index
            .calls_from(Some(0x20), "call")
            .expect("calls-from hit");
        assert_eq!(site, 0x10);
        assert_eq!(caller, "caller");
        assert!(index.calls_from(Some(0x10), "call").is_none());
    }

    #[test]
    fn file_scope_query_aggregates_across_all_functions() {
        let module: Module = Module::from_disasm(&payload());
        let index: CallIndex = CallIndex::build(&module);
        assert!(index.calls_to(None, "callee").is_some());
        assert!(index.calls_from(None, "caller").is_some());
        assert!(index.calls_to(None, "tag-alpha").is_none());
    }
}
