#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate, clippy::option_if_let_else)]

pub mod abi;
pub mod cfg;
mod creation;
mod decompile;
pub mod disasm;
mod dispatch;
pub mod error;
mod exec;
mod expr;
mod function;
pub mod input;
mod memory;
pub mod metadata;
pub mod opcode;
pub mod proxy;
mod render;
pub mod signatures;
pub mod u256;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;
use sha2::Sha256;
use sha3::{Digest, Keccak256};

pub use abi::{InferredArg, Mutability, TypeBasis};
pub use cfg::{Block, BlockEnd, Cfg, CfgLimits};
pub use disasm::Instruction;
pub use error::EvmError;
pub use input::{DecodedInput, InputEncoding, InputFormat};
pub use metadata::Metadata;
pub use opcode::Fork;
pub use proxy::Proxy;

use crate::disasm::JumpDests;
use crate::dispatch::Dispatch;
use crate::exec::{CallKind, Halt, Machine, Payload, Stmt};
use crate::function::{End, Trace};
use crate::u256::U256;

pub const MAX_CODE_BYTES: usize = 1 << 20;
const ERROR_STRING: u32 = 0x08c3_79a0;
const PANIC: u32 = 0x4e48_7b71;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_code_bytes: usize,
    pub cfg: CfgLimits,
    pub max_functions: usize,
    pub total_steps: u64,
    pub dispatcher_steps: u64,
    pub function_steps: u64,
    pub function_nodes: usize,
    pub creation_steps: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_code_bytes: MAX_CODE_BYTES,
            cfg: CfgLimits::default(),
            max_functions: 4096,
            total_steps: 40_000_000,
            dispatcher_steps: 4_000_000,
            function_steps: 600_000,
            function_nodes: 20_000,
            creation_steps: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Layout {
    #[default]
    Auto,
    Runtime,
    Creation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    pub limits: Limits,
    pub layout: Layout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayoutReport {
    pub kind: &'static str,
    pub input_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_offset: Option<usize>,
    pub runtime_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailing_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeReport {
    pub bytes: usize,
    pub code_bytes: usize,
    pub keccak256: String,
    pub sha256: String,
    pub instructions: usize,
    pub minimum_fork: Fork,
    pub undefined_opcodes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgSummary {
    pub blocks: usize,
    pub reachable_blocks: usize,
    pub edges: usize,
    pub jumpdests: usize,
    pub unresolved_jumps: BTreeSet<usize>,
    pub invalid_jump_targets: BTreeMap<usize, String>,
    pub stack_underflows: BTreeSet<usize>,
    pub max_stack_height: u32,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DispatcherReport {
    pub functions: usize,
    pub fallback: bool,
    pub receive: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionReport {
    pub selector: String,
    pub entry: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<&'static str>,
    pub inferred: String,
    pub arguments: Vec<InferredArg>,
    pub mutability: Mutability,
    pub mutability_basis: Vec<&'static str>,
    pub storage_reads: BTreeSet<String>,
    pub storage_writes: BTreeSet<String>,
    pub events: BTreeSet<String>,
    pub calls: BTreeSet<String>,
    pub reverts: BTreeSet<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvmReport {
    pub layout: LayoutReport,
    pub runtime: RuntimeReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    pub cfg: CfgSummary,
    pub dispatcher: DispatcherReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Proxy>,
    pub functions: Vec<FunctionReport>,
    pub event_topics: BTreeMap<String, Option<&'static str>>,
    pub error_selectors: BTreeMap<String, Option<&'static str>>,
    pub budget_exhausted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Section {
    pub name: &'static str,
    pub offset: usize,
    pub bytes: usize,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disassembly {
    pub layout: LayoutReport,
    pub sections: Vec<Section>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    pub blocks: Vec<Block>,
}

struct Located<'a> {
    layout: LayoutReport,
    constructor: &'a [u8],
    runtime: &'a [u8],
}

pub(crate) fn hex_digits(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut out: String, byte: &u8| {
            let _ = write!(out, "{byte:02x}");
            out
        },
    )
}

fn hex(bytes: &[u8]) -> String {
    format!("0x{}", hex_digits(bytes))
}

fn locate<'a>(code: &'a [u8], options: &Options) -> Result<Located<'a>, EvmError> {
    if code.is_empty() {
        return Err(EvmError::Empty);
    }
    if code.len() > options.limits.max_code_bytes {
        return Err(EvmError::TooLarge {
            size: code.len(),
            limit: options.limits.max_code_bytes,
        });
    }
    if code.starts_with(&input::EOF_MAGIC) {
        return Err(EvmError::EofContainer {
            version: code.get(2).copied().unwrap_or(0),
        });
    }
    let runtime_layout = |code: &'a [u8]| Located {
        layout: LayoutReport {
            kind: "runtime",
            input_bytes: code.len(),
            runtime_offset: None,
            runtime_bytes: code.len(),
            trailing_bytes: None,
        },
        constructor: &[],
        runtime: code,
    };
    if options.layout == Layout::Runtime {
        return Ok(runtime_layout(code));
    }
    let dests: JumpDests = JumpDests::analyse(code);
    let mut budget: u64 = options.limits.creation_steps;
    match creation::split(code, &dests, &mut budget) {
        Some(split) if split.runtime_offset > 0 => {
            let end: usize = split.runtime_offset + split.runtime_len;
            let runtime: &[u8] = &code[split.runtime_offset..end];
            if runtime.starts_with(&input::EOF_MAGIC) {
                return Err(EvmError::EofContainer {
                    version: runtime.get(2).copied().unwrap_or(0),
                });
            }
            Ok(Located {
                layout: LayoutReport {
                    kind: "creation",
                    input_bytes: code.len(),
                    runtime_offset: Some(split.runtime_offset),
                    runtime_bytes: split.runtime_len,
                    trailing_bytes: Some(code.len() - end),
                },
                constructor: &code[..split.runtime_offset],
                runtime,
            })
        }
        _ if options.layout == Layout::Creation => Err(EvmError::NoRuntimeImage),
        _ => Ok(runtime_layout(code)),
    }
}

fn minimum_fork(code: &[u8], end: usize) -> (Fork, usize, usize) {
    let mut fork: Fork = Fork::Frontier;
    let mut count: usize = 0;
    let mut undefined: usize = 0;
    let mut pc: usize = 0;
    while pc < end {
        let byte: u8 = code[pc];
        count += 1;
        match opcode::info(byte) {
            Some(info) => fork = fork.max(info.fork),
            None => undefined += 1,
        }
        pc += 1 + opcode::immediate_len(byte);
    }
    (fork, count, undefined)
}

fn code_end(runtime: &[u8], metadata: Option<&Metadata>) -> usize {
    metadata
        .filter(|m: &&Metadata| m.section == "runtime")
        .map_or(runtime.len(), |m: &Metadata| m.offset)
}

pub fn decode_input(
    bytes: &[u8],
    format: InputFormat,
    limits: &Limits,
) -> Result<DecodedInput, EvmError> {
    input::decode(bytes, format, limits.max_code_bytes)
}

pub fn disassemble(code: &[u8], options: &Options) -> Result<Disassembly, EvmError> {
    let analysis: Analysis = analyse(code, options)?;
    let located: Located<'_> = locate(code, options)?;
    let end: usize = analysis.report.runtime.code_bytes;
    let mut sections: Vec<Section> = Vec::new();
    if !located.constructor.is_empty() {
        sections.push(Section {
            name: "constructor",
            offset: 0,
            bytes: located.constructor.len(),
            instructions: disasm::decode(located.constructor),
        });
    }
    sections.push(Section {
        name: "runtime",
        offset: located.layout.runtime_offset.unwrap_or(0),
        bytes: end,
        instructions: disasm::decode(&located.runtime[..end]),
    });
    Ok(Disassembly {
        layout: analysis.report.layout,
        sections,
        metadata: analysis.report.metadata,
        blocks: analysis.blocks,
    })
}

pub(crate) struct Analysis {
    pub(crate) report: EvmReport,
    pub(crate) traces: BTreeMap<u32, Trace>,
    pub(crate) blocks: Vec<Block>,
}

const SOLC_PROLOGUES: [[u8; 5]; 2] = [
    [0x60, 0x80, 0x60, 0x40, 0x52],
    [0x60, 0x60, 0x60, 0x40, 0x52],
];

fn trailer(code: &[u8], located: &Located<'_>) -> Option<Metadata> {
    if let Some(metadata) = metadata::parse_trailer(located.runtime) {
        return Some(metadata);
    }
    let runtime_end: usize = located.layout.runtime_offset? + located.layout.runtime_bytes;
    metadata::parse_trailer(code)
        .filter(|metadata: &Metadata| metadata.offset >= runtime_end)
        .map(|metadata: Metadata| Metadata {
            section: "creation",
            ..metadata
        })
}

pub(crate) fn decode_revert_text(data: &Payload) -> String {
    let Some(selector) = data.selector else {
        return match data.size {
            Some(0) => "revert()".to_owned(),
            _ => "revert(<data>)".to_owned(),
        };
    };
    if selector == ERROR_STRING
        && let Some(text) = data.bytes.as_deref().and_then(error_string)
    {
        return format!("Error({text:?})");
    }
    if selector == PANIC
        && let Some(code) = data.words.first().and_then(expr::as_const)
    {
        return format!("Panic({})", panic_reason(code));
    }
    match signatures::error(selector) {
        Some(signature) => signature.to_owned(),
        None => format!("error 0x{selector:08x}"),
    }
}

pub(crate) fn panic_reason(code: U256) -> String {
    let reason: &str = match code.to_u64() {
        Some(0x01) => "assertion failed",
        Some(0x11) => "arithmetic overflow or underflow",
        Some(0x12) => "division or modulo by zero",
        Some(0x21) => "invalid enum value",
        Some(0x22) => "corrupt storage byte array",
        Some(0x31) => "pop on empty array",
        Some(0x32) => "array index out of bounds",
        Some(0x41) => "memory allocation too large",
        Some(0x51) => "call to zero-initialised function",
        _ => "unknown code",
    };
    format!("{code}: {reason}")
}

pub(crate) fn error_string(bytes: &[u8]) -> Option<String> {
    let body: &[u8] = bytes.get(4..)?;
    let offset: usize = U256::from_be_slice(body.get(..32)?).to_usize()?;
    let len_word: &[u8] = body.get(offset..offset.checked_add(32)?)?;
    let len: usize = U256::from_be_slice(len_word).to_usize()?;
    let start: usize = offset + 32;
    let text: &[u8] = body.get(start..start.checked_add(len)?)?;
    String::from_utf8(text.to_vec()).ok()
}

fn call_text(kind: CallKind, address: &expr::Val, input: &Payload) -> String {
    let verb: &str = match kind {
        CallKind::Call => "call",
        CallKind::CallCode => "callcode",
        CallKind::DelegateCall => "delegatecall",
        CallKind::StaticCall => "staticcall",
    };
    let target: String = render::expr(address);
    match input.selector {
        Some(selector) => match signatures::function(selector) {
            Some(known) => format!("{verb} {target}.{}", known.signature),
            None => format!("{verb} {target}.0x{selector:08x}"),
        },
        None => format!("{verb} {target}"),
    }
}

fn topic_name(topic: &expr::Val) -> Option<(String, Option<&'static str>)> {
    let value: U256 = expr::as_const(topic)?;
    let bytes: [u8; 32] = value.to_be_bytes();
    Some((hex(&bytes), signatures::event(&bytes)))
}

fn summarise(
    selector: u32,
    entry: usize,
    trace: &Trace,
    range_checks: bool,
    topics: &mut BTreeMap<String, Option<&'static str>>,
    errors: &mut BTreeMap<String, Option<&'static str>>,
) -> FunctionReport {
    let arguments: Vec<InferredArg> = abi::arguments(trace, range_checks);
    let (mutability, basis) = abi::mutability(trace);
    let known: Option<signatures::KnownFunction> = signatures::function(selector);
    let types: Vec<&str> = arguments
        .iter()
        .map(|arg: &InferredArg| arg.ty.as_str())
        .collect();
    let mut report: FunctionReport = FunctionReport {
        selector: format!("0x{selector:08x}"),
        entry,
        signature: known.map(|k| k.signature),
        interface: known.map(|k| k.interface),
        inferred: format!("0x{selector:08x}({})", types.join(",")),
        arguments,
        mutability,
        mutability_basis: basis,
        storage_reads: BTreeSet::new(),
        storage_writes: BTreeSet::new(),
        events: BTreeSet::new(),
        calls: BTreeSet::new(),
        reverts: BTreeSet::new(),
        complete: trace.complete,
    };
    for node in &trace.nodes {
        for stmt in &node.stmts {
            match stmt {
                Stmt::Sstore { slot, .. } | Stmt::Tstore { slot, .. } => {
                    report.storage_writes.insert(render::slot(slot));
                }
                Stmt::Log {
                    topics: event_topics,
                    ..
                } => {
                    let name: String = match event_topics.first().and_then(topic_name) {
                        Some((topic, Some(signature))) => {
                            topics.insert(topic, Some(signature));
                            signature.to_owned()
                        }
                        Some((topic, None)) => {
                            topics.insert(topic.clone(), None);
                            topic
                        }
                        None => format!("log{}", event_topics.len()),
                    };
                    report.events.insert(name);
                }
                Stmt::Call {
                    kind,
                    address,
                    input,
                    ..
                } => {
                    report.calls.insert(call_text(*kind, address, input));
                }
                Stmt::Create { kind, .. } => {
                    report.calls.insert(match kind {
                        exec::CreateKind::Create => "create".to_owned(),
                        exec::CreateKind::Create2 => "create2".to_owned(),
                    });
                }
                Stmt::CallValueGuard => {}
            }
        }
        if let End::Halt(Halt::Revert(data)) = &node.end {
            if let Some(selector) = data.selector
                && selector != ERROR_STRING
                && selector != PANIC
            {
                errors.insert(format!("0x{selector:08x}"), signatures::error(selector));
            }
            report.reverts.insert(decode_revert_text(data));
        }
    }
    collect_reads(trace, &mut report.storage_reads);
    report
}

fn collect_reads(trace: &Trace, out: &mut BTreeSet<String>) {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut visit = |value: &expr::Val, out: &mut BTreeSet<String>| {
        let mut budget: u32 = 512;
        let mut found: Vec<expr::Val> = Vec::new();
        walk(value, &mut budget, &mut found);
        for slot in found {
            if seen.insert(slot.hash) && out.len() < 256 {
                out.insert(render::slot(&slot));
            }
        }
    };
    for node in &trace.nodes {
        for stmt in &node.stmts {
            match stmt {
                Stmt::Sstore { slot, value } | Stmt::Tstore { slot, value } => {
                    visit(slot, out);
                    visit(value, out);
                }
                Stmt::Log { topics, data } => {
                    for value in topics.iter().chain(data.words.iter()) {
                        visit(value, out);
                    }
                }
                Stmt::Call { address, input, .. } => {
                    visit(address, out);
                    for value in &input.words {
                        visit(value, out);
                    }
                }
                Stmt::Create { value, .. } => visit(value, out),
                Stmt::CallValueGuard => {}
            }
        }
        match &node.end {
            End::Branch { cond, .. } => visit(cond, out),
            End::Halt(Halt::Return(data) | Halt::Revert(data)) => {
                for value in &data.words {
                    visit(value, out);
                }
            }
            _ => {}
        }
    }
}

fn walk(value: &expr::Val, budget: &mut u32, found: &mut Vec<expr::Val>) {
    if *budget == 0 {
        return;
    }
    *budget -= 1;
    match &value.expr {
        expr::Expr::Sload(slot) => {
            found.push(slot.clone());
            walk(slot, budget, found);
        }
        expr::Expr::CdRaw(a) | expr::Expr::Un(_, a) | expr::Expr::Tload(a) => {
            walk(a, budget, found);
        }
        expr::Expr::Bin(_, a, b) => {
            walk(a, budget, found);
            walk(b, budget, found);
        }
        expr::Expr::Tern(_, a, b, c) => {
            walk(a, budget, found);
            walk(b, budget, found);
            walk(c, budget, found);
        }
        expr::Expr::Keccak(words) => {
            for word in words {
                walk(word, budget, found);
            }
        }
        _ => {}
    }
}

pub(crate) fn analyse(code: &[u8], options: &Options) -> Result<Analysis, EvmError> {
    let located: Located<'_> = locate(code, options)?;
    let runtime: &[u8] = located.runtime;
    let metadata: Option<Metadata> = trailer(code, &located);
    let end: usize = code_end(runtime, metadata.as_ref());
    let range_checks: bool = match metadata
        .as_ref()
        .and_then(|m: &Metadata| m.compiler.as_ref())
    {
        Some(compiler) => compiler.name == "vyper",
        None => !SOLC_PROLOGUES
            .iter()
            .any(|prologue: &[u8; 5]| runtime.starts_with(prologue)),
    };
    let dests: JumpDests = JumpDests::analyse(runtime);
    let (fork, instructions, undefined) = minimum_fork(runtime, end);
    let machine: Machine<'_> = Machine {
        code: runtime,
        dests: &dests,
        codesize_known: true,
        fork_selector_buckets: false,
    };
    let dispatcher: Machine<'_> = Machine {
        fork_selector_buckets: true,
        ..machine
    };
    let mut total: u64 = options.limits.total_steps;
    let mut dispatcher_budget: u64 = options.limits.dispatcher_steps.min(total);
    let dispatch: Dispatch = dispatch::discover(
        &dispatcher,
        &mut dispatcher_budget,
        options.limits.max_functions,
    );
    total = total.saturating_sub(options.limits.dispatcher_steps.min(total) - dispatcher_budget);
    let mut traces: BTreeMap<u32, Trace> = BTreeMap::new();
    let mut functions: Vec<FunctionReport> = Vec::new();
    let mut topics: BTreeMap<String, Option<&'static str>> = BTreeMap::new();
    let mut errors: BTreeMap<String, Option<&'static str>> = BTreeMap::new();
    let mut exhausted: bool = !dispatch.complete && dispatcher_budget == 0;
    for (selector, entry) in &dispatch.entries {
        let allowance: u64 = options.limits.function_steps.min(total);
        let mut budget: u64 = allowance;
        let trace: Trace =
            function::explore(&machine, entry, &mut budget, options.limits.function_nodes);
        total = total.saturating_sub(allowance - budget);
        if total == 0 {
            exhausted = true;
        }
        functions.push(summarise(
            *selector,
            entry.pc,
            &trace,
            range_checks,
            &mut topics,
            &mut errors,
        ));
        traces.insert(*selector, trace);
    }
    let mut observed: exec::Jumps = dispatch.jumps.clone();
    for trace in traces.values() {
        for (pc, targets) in &trace.jumps {
            for target in targets {
                exec::record_jump(&mut observed, *pc, *target);
            }
        }
    }
    let graph: Cfg = cfg::build(runtime, end, &dests, options.limits.cfg, &observed);
    let proxy: Option<Proxy> = proxy::minimal_proxy(runtime)
        .or_else(|| dispatch.delegate_targets.first().map(proxy::from_delegate));
    let runtime_report: RuntimeReport = RuntimeReport {
        bytes: runtime.len(),
        code_bytes: end,
        keccak256: hex(&Keccak256::digest(runtime)),
        sha256: hex(&Sha256::digest(runtime)),
        instructions,
        minimum_fork: fork,
        undefined_opcodes: undefined,
    };
    let report: EvmReport = EvmReport {
        layout: located.layout,
        runtime: runtime_report,
        metadata,
        cfg: CfgSummary {
            blocks: graph.blocks.len(),
            reachable_blocks: graph.reachable_blocks,
            edges: graph.edges,
            jumpdests: graph.jumpdests,
            unresolved_jumps: graph.unresolved_jumps,
            invalid_jump_targets: graph.invalid_jump_targets,
            stack_underflows: graph.stack_underflows,
            max_stack_height: graph.max_stack_height,
            complete: graph.complete,
        },
        dispatcher: DispatcherReport {
            functions: dispatch.entries.len(),
            fallback: dispatch.fallback,
            receive: dispatch.receive,
            complete: dispatch.complete && !dispatch.truncated_functions,
        },
        proxy,
        functions,
        event_topics: topics,
        error_selectors: errors,
        budget_exhausted: exhausted,
    };
    Ok(Analysis {
        report,
        traces,
        blocks: graph.blocks,
    })
}

pub fn analyze(code: &[u8], options: &Options) -> Result<EvmReport, EvmError> {
    analyse(code, options).map(|analysis: Analysis| analysis.report)
}

pub fn decompile(code: &[u8], options: &Options) -> Result<String, EvmError> {
    let analysis: Analysis = analyse(code, options)?;
    Ok(decompile::render(&analysis))
}
