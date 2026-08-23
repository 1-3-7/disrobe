use disrobe_pass_wasm_deob::{
    LiftCoverage, LiftTarget, ModuleSourceLift, lift_module_source_with_limit,
};
use serde::Serialize;

const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WasmSourceTarget {
    Rust,
    TypeScript,
    C,
    Wat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WasmSourceCoverage {
    pub total_ops: usize,
    pub translated_ops: usize,
    pub untranslated: Vec<String>,
}

impl WasmSourceCoverage {
    #[must_use]
    pub const fn fully_recovered(&self) -> bool {
        self.untranslated.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmSourceLift {
    pub target: WasmSourceTarget,
    pub function_count: usize,
    pub coverage: WasmSourceCoverage,
    pub source: String,
}

#[derive(Debug)]
pub enum WasmSourceLiftError {
    Lift(disrobe_pass_wasm_deob::Error),
}

impl std::fmt::Display for WasmSourceLiftError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lift(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WasmSourceLiftError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lift(error) => Some(error),
        }
    }
}

impl From<disrobe_pass_wasm_deob::Error> for WasmSourceLiftError {
    fn from(error: disrobe_pass_wasm_deob::Error) -> Self {
        Self::Lift(error)
    }
}

pub fn lift_wasm_source(
    bytes: &[u8],
    target: WasmSourceTarget,
) -> Result<WasmSourceLift, WasmSourceLiftError> {
    let lift_target: LiftTarget = match target {
        WasmSourceTarget::Rust => LiftTarget::Rust,
        WasmSourceTarget::TypeScript => LiftTarget::TypeScript,
        WasmSourceTarget::C => LiftTarget::C,
        WasmSourceTarget::Wat => LiftTarget::Wat,
    };
    let lifted: ModuleSourceLift =
        lift_module_source_with_limit(bytes, lift_target, MAX_SOURCE_BYTES)?;
    Ok(WasmSourceLift {
        target,
        function_count: lifted.functions_emitted,
        coverage: coverage_out(lifted.coverage),
        source: lifted.source,
    })
}

fn coverage_out(coverage: LiftCoverage) -> WasmSourceCoverage {
    WasmSourceCoverage {
        total_ops: coverage.total_ops,
        translated_ops: coverage.translated_ops,
        untranslated: coverage.untranslated,
    }
}
