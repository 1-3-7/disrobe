use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AtomicMemoryRefusal {
    #[error("module context is unavailable")]
    MissingModuleContext,

    #[error("module bytes do not match the prepared lifting context")]
    MismatchedModuleContext,

    #[error("module memory behavior could not be fully decoded")]
    MemoryScanFailed,

    #[error("expected exactly one memory, found {actual}")]
    MemoryCount { actual: usize },

    #[error("atomic memory index {memory_index} is unavailable")]
    MissingMemory { memory_index: u32 },

    #[error("memory {memory_index} is imported and its host state is unavailable")]
    ImportedMemory { memory_index: u32 },

    #[error("module has {actual} imports whose external state is unavailable")]
    Imports { actual: u32 },

    #[error("memory {memory_index} is not shared")]
    UnsharedMemory { memory_index: u32 },

    #[error("memory {memory_index} starts with {actual} pages instead of one")]
    InitialPages { memory_index: u32, actual: u64 },

    #[error("memory {memory_index} has maximum {actual:?} instead of one page")]
    MaximumPages {
        memory_index: u32,
        actual: Option<u64>,
    },

    #[error("memory {memory_index} uses page-size log2 {actual} instead of 16")]
    PageSize { memory_index: u32, actual: u32 },

    #[error("module has {actual} data segments whose contents are not emitted")]
    DataSegments { actual: u32 },

    #[error("module has {actual} globals whose state is not emitted")]
    Globals { actual: u32 },

    #[error("module has {actual} tags whose exception payload state is not emitted")]
    Tags { actual: u32 },

    #[error("module has {actual} tables whose state is not emitted")]
    Tables { actual: u32 },

    #[error("module has {actual} element segments whose contents are not emitted")]
    ElementSegments { actual: u32 },

    #[error("start function {function_index} may initialize memory before lifted functions")]
    StartFunction { function_index: u32 },

    #[error("memory.grow may execute for memory {memory_index}")]
    MemoryGrow { memory_index: u32 },

    #[error("target {target} cannot express {operation} with the required semantics")]
    UnsupportedTarget {
        target: &'static str,
        operation: &'static str,
    },
}

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-WASMDEOB-0001: input is not a valid WebAssembly module: {0}")]
    Parse(String),

    #[error("DR-WASMDEOB-0002: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-WASMDEOB-0003: atomic memory model is unsupported: {0}")]
    AtomicMemoryModel(#[from] AtomicMemoryRefusal),
}
