#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

pub mod eval;
pub mod extract;
pub mod feature;
pub mod imports;
pub mod rule;
pub mod ruleset;
#[cfg(feature = "yaml_rules")]
pub mod yaml_rules;

use std::collections::BTreeSet;

use disrobe_ir::payload::DisasmPayload;
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::Module;
use serde::Serialize;

pub use eval::{CapabilityMatch, evaluate};
pub use extract::{ScopedFeatures, extract};
pub use feature::{
    Characteristic, Feature, FeatureHit, FeatureSet, FeatureValue, OperandFeature, OperandValue,
    Scope,
};
pub use imports::ImportMap;
pub use rule::{CountBound, Evidence, Rule, RuleExpr};
pub use ruleset::builtin_rules;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CAPABILITIES_SCHEMA: &str = "disrobe.capabilities/v0";

#[derive(Debug, thiserror::Error)]
pub enum CapabilitiesError {
    #[error("disassembly failed: {0}")]
    Disasm(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilitiesReport {
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub byte_len: usize,
    pub matched_rules: usize,
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
    pub capabilities: Vec<CapabilityMatch>,
}

pub fn analyze(bytes: &[u8]) -> Result<CapabilitiesReport, CapabilitiesError> {
    analyze_with_uri(bytes, None)
}

pub fn analyze_with_uri(
    bytes: &[u8],
    uri: Option<&str>,
) -> Result<CapabilitiesReport, CapabilitiesError> {
    let payload: DisasmPayload =
        build_disasm_payload(bytes).map_err(|e| CapabilitiesError::Disasm(e.to_string()))?;
    let module: Module = Module::from_disasm(&payload);
    Ok(analyze_module(&module, bytes, uri))
}

#[must_use]
pub fn analyze_module(module: &Module, bytes: &[u8], uri: Option<&str>) -> CapabilitiesReport {
    let imports: ImportMap = ImportMap::from_bytes(bytes);
    let scoped: ScopedFeatures = extract(module, bytes, &imports);
    let rules: Vec<Rule> = builtin_rules();
    let capabilities: Vec<CapabilityMatch> = evaluate(&scoped, &rules);
    finalize(capabilities, bytes.len(), uri)
}

fn finalize(
    capabilities: Vec<CapabilityMatch>,
    byte_len: usize,
    uri: Option<&str>,
) -> CapabilitiesReport {
    let attack: Vec<String> = unique(
        capabilities
            .iter()
            .flat_map(|c: &CapabilityMatch| c.attack.iter().cloned()),
    );
    let mbc: Vec<String> = unique(
        capabilities
            .iter()
            .flat_map(|c: &CapabilityMatch| c.mbc.iter().cloned()),
    );
    let matched: BTreeSet<&str> = capabilities
        .iter()
        .map(|c: &CapabilityMatch| c.rule.as_str())
        .collect();
    CapabilitiesReport {
        schema: CAPABILITIES_SCHEMA,
        uri: uri.map(str::to_owned),
        byte_len,
        matched_rules: matched.len(),
        attack,
        mbc,
        capabilities,
    }
}

fn unique<I: Iterator<Item = String>>(iter: I) -> Vec<String> {
    let set: BTreeSet<String> = iter.collect();
    set.into_iter().collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_ir::payload::{
        DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow,
    };

    fn insn(
        offset: u64,
        mnemonic: &str,
        operands: &[&str],
        flow: InsnFlow,
        branch_target: Option<u64>,
    ) -> DisasmInstruction {
        DisasmInstruction {
            offset,
            bytes: vec![0x90],
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            flow,
            branch_target,
            ..DisasmInstruction::default()
        }
    }

    fn import(address: u64, name: &str) -> DisasmSymbol {
        DisasmSymbol {
            address,
            name: name.to_owned(),
            kind: DisasmSymbolKind::Import,
        }
    }

    fn func(address: u64, name: &str) -> DisasmSymbol {
        DisasmSymbol {
            address,
            name: name.to_owned(),
            kind: DisasmSymbolKind::Function,
        }
    }

    #[test]
    fn connect_call_fires_connect_rule_at_the_call_site() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x0, "call", &["0x200"], InsnFlow::Call, Some(0x200)),
                insn(0x5, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![func(0x0, "beacon"), import(0x200, "connect")],
        };
        let module: Module = Module::from_disasm(&payload);
        let report: CapabilitiesReport = analyze_module(&module, b"", None);
        let hit: &CapabilityMatch = report
            .capabilities
            .iter()
            .find(|c: &&CapabilityMatch| c.rule == "connect to network resource")
            .expect("connect rule fires");
        assert_eq!(hit.function.as_deref(), Some("beacon"));
        assert_eq!(hit.address, 0x0);
        assert!(hit.attack.contains(&"T1071".to_owned()));
        assert!(report.attack.contains(&"T1071".to_owned()));
    }

    #[test]
    fn clean_function_matches_nothing() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x0, "mov", &["eax", "0x1"], InsnFlow::Sequential, None),
                insn(0x5, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![func(0x0, "noop")],
        };
        let module: Module = Module::from_disasm(&payload);
        let report: CapabilitiesReport = analyze_module(&module, b"the quick brown fox", None);
        assert!(report.capabilities.is_empty(), "{report:?}");
        assert_eq!(report.matched_rules, 0);
    }

    #[test]
    fn write_file_rule_requires_both_open_and_write() {
        let only_open: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x0, "call", &["0x200"], InsnFlow::Call, Some(0x200)),
                insn(0x5, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![func(0x0, "dropper"), import(0x200, "CreateFileA")],
        };
        let module: Module = Module::from_disasm(&only_open);
        let report: CapabilitiesReport = analyze_module(&module, b"", None);
        assert!(
            !report
                .capabilities
                .iter()
                .any(|c: &CapabilityMatch| c.rule == "write file"),
            "write file must not fire on open alone"
        );

        let open_and_write: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                insn(0x0, "call", &["0x200"], InsnFlow::Call, Some(0x200)),
                insn(0x5, "call", &["0x208"], InsnFlow::Call, Some(0x208)),
                insn(0xa, "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![
                func(0x0, "dropper"),
                import(0x200, "CreateFileA"),
                import(0x208, "WriteFile"),
            ],
        };
        let module: Module = Module::from_disasm(&open_and_write);
        let report: CapabilitiesReport = analyze_module(&module, b"", None);
        let hit: &CapabilityMatch = report
            .capabilities
            .iter()
            .find(|c: &&CapabilityMatch| c.rule == "write file")
            .expect("write file fires when both present");
        assert_eq!(hit.function.as_deref(), Some("dropper"));
        assert_eq!(hit.address, 0x0);
        let evidence_addrs: Vec<u64> = hit.evidence.iter().map(|e: &Evidence| e.address).collect();
        assert!(evidence_addrs.contains(&0x0));
        assert!(evidence_addrs.contains(&0x5));
    }
}
