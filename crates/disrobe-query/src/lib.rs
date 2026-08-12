#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

pub mod eval;
pub mod lift;
pub mod model;
pub mod navigation;
pub mod parse;
pub mod query;

use disrobe_core::Rung;
use disrobe_ir::payload::{DisasmPayload, decode_disasm};
use disrobe_ir::{Envelope, EnvelopeError};
use disrobe_nir::{NirCodecError, NirModule, decode_nir};

pub use eval::evaluate;
pub use lift::disasm_to_nir;
pub use model::{
    BasicBlock, BlockKind, CallGraph, CallGraphEdge, CallGraphNode, Function, InsnClass,
    InsnSegmentsView, InsnView, IsaView, Module, StackEffectView, SymbolKind, SymbolRef,
};
pub use navigation::{
    CallOutcome, FunctionId, FunctionIdParseError, FunctionIdentity, FunctionLookupError,
    FunctionSummary, NavigationAnalysis, NavigationCall, NavigationLimitError, NavigationLimits,
    NavigationQueryError, NavigationXref, Neighborhood, NeighborhoodDirection, NeighborhoodLimits,
    NeighborhoodNode,
};
pub use parse::{ParseError, parse_query};
pub use query::{
    CallSiteMatch, Capability, CapabilitySiteMatch, DecoderMatch, FunctionMatch, Query,
    QueryResult, XrefMatch,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("envelope codec: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("query layer requires a Disasm- or Mir-rung envelope; got {0:?}")]
    UnsupportedRung(Rung),
    #[error("rkyv decode of disasm hot payload: {0}")]
    Decode(String),
    #[error("rkyv decode of nir hot payload: {0}")]
    DecodeNir(String),
    #[error(transparent)]
    Parse(#[from] ParseError),
}

pub fn module_from_envelope(env: &Envelope) -> Result<Module, QueryError> {
    match env.rung {
        Rung::Disasm => {
            let payload: DisasmPayload = decode_disasm(&env.hot)
                .map_err(|e: EnvelopeError| QueryError::Decode(e.to_string()))?;
            Ok(Module::from_disasm(&payload))
        }
        Rung::Mir => {
            let module: NirModule = decode_nir(&env.hot)
                .map_err(|e: NirCodecError| QueryError::DecodeNir(e.to_string()))?;
            Ok(Module::from_nir(&module))
        }
        other => Err(QueryError::UnsupportedRung(other)),
    }
}

pub fn module_from_bytes(bytes: &[u8]) -> Result<Module, QueryError> {
    let env: Envelope = Envelope::decode(bytes)?;
    module_from_envelope(&env)
}

#[must_use]
pub fn run(module: &Module, query: &Query) -> QueryResult {
    evaluate(module, query)
}

pub fn run_expr(module: &Module, expr: &str) -> Result<QueryResult, QueryError> {
    let query: Query = parse_query(expr)?;
    Ok(evaluate(module, &query))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_ir::payload::{
        DisasmInstruction, DisasmSymbol, DisasmSymbolKind, InsnFlow, encode_disasm,
    };
    use disrobe_nir::{SourceLang, encode_nir};

    fn disasm_envelope() -> Envelope {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [7u8; 32],
            instructions: vec![
                DisasmInstruction {
                    offset: 0x0,
                    bytes: vec![0xe8, 0, 0, 0, 0],
                    mnemonic: "call".to_owned(),
                    operands: vec!["0x10".to_owned()],
                    flow: InsnFlow::Call,
                    branch_target: Some(0x10),
                    ..DisasmInstruction::default()
                },
                DisasmInstruction {
                    offset: 0x5,
                    bytes: vec![0xc3],
                    mnemonic: "ret".to_owned(),
                    operands: vec![],
                    flow: InsnFlow::Return,
                    branch_target: None,
                    ..DisasmInstruction::default()
                },
                DisasmInstruction {
                    offset: 0x10,
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
                    address: 0x0,
                    name: "main".to_owned(),
                    kind: DisasmSymbolKind::Export,
                },
                DisasmSymbol {
                    address: 0x10,
                    name: "helper".to_owned(),
                    kind: DisasmSymbolKind::Function,
                },
            ],
        };
        let hot: Vec<u8> = encode_disasm(&payload).expect("encode disasm");
        Envelope::new(Rung::Disasm, hot, Vec::new())
    }

    fn mir_envelope() -> Envelope {
        let module: NirModule = NirModule::new([9u8; 32], SourceLang::Unknown);
        let hot: Vec<u8> = encode_nir(&module).expect("encode nir");
        Envelope::new(Rung::Mir, hot, Vec::new())
    }

    #[test]
    fn module_from_envelope_round_trips_through_dr() {
        let env: Envelope = disasm_envelope();
        let encoded: Vec<u8> = env.encode().expect("encode envelope");
        let module: Module = module_from_bytes(&encoded).expect("decode module");
        assert_eq!(module.functions().len(), 2);
        let result: QueryResult = run_expr(&module, "calls-to helper").expect("query");
        assert_eq!(result.count(), 1);
    }

    #[test]
    fn unsupported_rung_is_rejected() {
        let env: Envelope = Envelope::new(Rung::Raw, Vec::new(), Vec::new());
        let err: QueryError = module_from_envelope(&env).expect_err("should reject raw");
        assert!(matches!(err, QueryError::UnsupportedRung(Rung::Raw)));
    }

    #[test]
    fn module_from_envelope_accepts_exactly_disasm_and_mir() {
        for rung in [Rung::Raw, Rung::Disasm, Rung::Mir, Rung::Hir, Rung::Surface] {
            let env: Envelope = match rung {
                Rung::Disasm => disasm_envelope(),
                Rung::Mir => mir_envelope(),
                other => Envelope::new(other, Vec::new(), Vec::new()),
            };
            let result: Result<Module, QueryError> = module_from_envelope(&env);
            match rung {
                Rung::Disasm | Rung::Mir => assert!(
                    result.is_ok(),
                    "rung {rung:?} is in the accepted set {{Disasm, Mir}} but was rejected: {:?}",
                    result.err()
                ),
                Rung::Raw | Rung::Hir | Rung::Surface => {
                    let err: QueryError =
                        result.expect_err(&format!("rung {rung:?} must be rejected"));
                    assert!(
                        matches!(err, QueryError::UnsupportedRung(rejected) if rejected == rung),
                        "rung {rung:?} was rejected with the wrong error: {err:?}"
                    );
                }
            }
        }
    }
}
