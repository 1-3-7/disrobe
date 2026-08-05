#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

pub mod cfg;
pub mod codec;
pub mod defuse;
pub mod emit;
pub mod hir;
pub mod reducible;
pub mod surface;
pub mod types;

pub use cfg::{BlockKind, NirBlock, basic_blocks, complexity, control_flow_graph};
pub use codec::{NirCodecError, decode_nir, encode_nir};
pub use defuse::{DefUse, ValueId, def_use};
pub use emit::{EmitError, emit_pseudo_source};
pub use hir::{
    HirCond, HirDispatchCase, HirExpr, HirFunction, HirInstrStmt, HirLeafStmt, HirModule, HirStmt,
    structurize_function, structurize_function_with_budget, structurize_module,
};
pub use reducible::{CnsBudget, HirDecline, SplitBudget, SplitRefusal, StructureFailure};
pub use surface::{
    SurfaceCase, SurfaceCondition, SurfaceExpr, SurfaceFunction, SurfaceLeaf, SurfaceLocal,
    SurfaceModule, SurfaceSignature, SurfaceStatement, SurfaceStmt, SurfaceType,
    surfacify_function, surfacify_module,
};
pub use types::{
    BinaryOp, CallOtherEffect, NirClass, NirFunction, NirInstr, NirModule, NirOp, NirSymbol,
    SourceLang, SourceRef, SymbolKind, ValueOp,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
