pub mod lua51;
pub mod luajit21;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledChunk {
    pub source: String,
    pub fidelity: Fidelity,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Fidelity {
    Lossless,
    Lossy,
    BestEffort,
}
