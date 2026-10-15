mod elf_core;
mod memory;
mod minidump;
mod names;

use std::collections::BTreeMap;

use serde::Serialize;

use memory::{Memory, ModuleMap};

#[derive(Debug, thiserror::Error)]
pub enum CrashError {
    #[error("not a crash record: no ELF core or minidump signature")]
    Unrecognized,
    #[error("malformed ELF core: {0}")]
    ElfCore(String),
    #[error("malformed minidump: {0}")]
    Minidump(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashLimits {
    pub threads: usize,
    pub modules: usize,
    pub segments: usize,
    pub notes: usize,
    pub auxv: usize,
    pub stack_scan_bytes: usize,
    pub stack_candidates: usize,
}

impl Default for CrashLimits {
    fn default() -> Self {
        Self {
            threads: 65_536,
            modules: 65_536,
            segments: 4_000_000,
            notes: 1_000_000,
            auxv: 4_096,
            stack_scan_bytes: 64 * 1024,
            stack_candidates: 32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrashFormat {
    ElfCore,
    Minidump,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Architecture {
    X86,
    #[serde(rename = "x86-64")]
    X86_64,
    Arm,
    Aarch64,
    Riscv64,
    Other,
}

impl Architecture {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86-64",
            Self::Arm => "arm",
            Self::Aarch64 => "aarch64",
            Self::Riscv64 => "riscv64",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SystemInfo {
    pub platform: String,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_pack: Option<String>,
    pub processors: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_unix: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultKind {
    Signal,
    Exception,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location {
    pub module: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Sender {
    pub pid: i32,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fault {
    pub kind: FaultKind,
    pub code: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<Sender>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Register {
    pub name: &'static str,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StackWord {
    pub address: u64,
    pub value: u64,
    pub location: Location,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThreadReport {
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub crashed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_pointer: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_pointer: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_pointer: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    pub registers: Vec<Register>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<Span>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stack_scan: Vec<StackWord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pdb {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleReport {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader_name: Option<String>,
    pub base: u64,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb: Option<Pdb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MemorySummary {
    pub segments: u64,
    pub described_bytes: u64,
    pub captured_bytes: u64,
    pub executable_segments: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuxEntry {
    pub key: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'static str>,
    pub value: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrashReport {
    pub format: CrashFormat,
    pub architecture: Architecture,
    pub machine: u32,
    pub pointer_bytes: u8,
    pub big_endian: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemInfo>,
    pub process: ProcessInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fault: Option<Fault>,
    pub threads: Vec<ThreadReport>,
    pub modules: Vec<ModuleReport>,
    pub memory: MemorySummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub auxv: Vec<AuxEntry>,
    pub records: BTreeMap<String, u64>,
    pub problems: Vec<String>,
}

pub fn inspect(bytes: &[u8], limits: &CrashLimits) -> Result<CrashReport, CrashError> {
    if bytes.starts_with(b"\x7fELF") {
        elf_core::inspect(bytes, limits)
    } else if bytes.starts_with(b"MDMP") {
        minidump::inspect(bytes, limits)
    } else {
        Err(CrashError::Unrecognized)
    }
}

#[must_use]
pub fn looks_like_crash_record(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MDMP") || (bytes.starts_with(b"\x7fELF") && elf_core::is_core_header(bytes))
}

fn scan_stack(
    memory: &Memory<'_>,
    modules: &ModuleMap,
    stack_pointer: u64,
    pointer_bytes: u8,
    big_endian: bool,
    limits: &CrashLimits,
) -> Vec<StackWord> {
    let mut found: Vec<StackWord> = Vec::new();
    let Some(window): Option<&[u8]> = memory.read_up_to(stack_pointer, limits.stack_scan_bytes)
    else {
        return found;
    };
    let step: usize = usize::from(pointer_bytes);
    if step == 0 {
        return found;
    }
    for (index, word) in window.chunks_exact(step).enumerate() {
        if found.len() >= limits.stack_candidates {
            break;
        }
        let value: u64 = memory::word(word, big_endian);
        if !memory.is_executable(value) {
            continue;
        }
        if let Some(location) = modules.locate(value) {
            let offset: u64 = (index * step) as u64;
            found.push(StackWord {
                address: stack_pointer.wrapping_add(offset),
                value,
                location,
            });
        }
    }
    found
}
