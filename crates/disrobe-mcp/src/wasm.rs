use disrobe_pass_wasm_deob::{
    LiftCoverage, LiftTarget, ModuleSourceLift, lift_module_source_with_limit,
};

use super::{WasmLiftCoverageOut, WasmLiftOut, WasmLiftTarget};

#[derive(Debug)]
pub(crate) enum WasmLiftError {
    Lift(disrobe_pass_wasm_deob::Error),
}

impl std::fmt::Display for WasmLiftError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lift(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WasmLiftError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lift(error) => Some(error),
        }
    }
}

impl From<disrobe_pass_wasm_deob::Error> for WasmLiftError {
    fn from(error: disrobe_pass_wasm_deob::Error) -> Self {
        Self::Lift(error)
    }
}

pub(crate) fn lift(
    bytes: &[u8],
    target: WasmLiftTarget,
    max_source_bytes: usize,
) -> Result<WasmLiftOut, WasmLiftError> {
    let lift_target: LiftTarget = match target {
        WasmLiftTarget::Rust => LiftTarget::Rust,
        WasmLiftTarget::TypeScript => LiftTarget::TypeScript,
        WasmLiftTarget::C => LiftTarget::C,
        WasmLiftTarget::Wat => LiftTarget::Wat,
    };
    let lifted: ModuleSourceLift =
        lift_module_source_with_limit(bytes, lift_target, max_source_bytes)?;
    Ok(WasmLiftOut {
        schema: "disrobe.wasm.lift/v1".to_owned(),
        target,
        function_count: lifted.functions_emitted,
        coverage: coverage_out(lifted.coverage),
        source: lifted.source,
    })
}

fn coverage_out(coverage: LiftCoverage) -> WasmLiftCoverageOut {
    WasmLiftCoverageOut {
        total_ops: coverage.total_ops,
        translated_ops: coverage.translated_ops,
        fully_recovered: coverage.fully_recovered(),
        untranslated: coverage.untranslated,
    }
}
