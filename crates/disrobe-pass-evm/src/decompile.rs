use std::collections::{BTreeSet, VecDeque};
use std::fmt::Write as _;

use crate::exec::{CallKind, CreateKind, Halt, Payload, Stmt};
use crate::expr::{BinOp, Expr, UnOp, Val, as_const};
use crate::function::{End, Trace};
use crate::render::{self, expr, is_boolean};
use crate::{Analysis, ERROR_STRING, FunctionReport, Mutability, PANIC, error_string, signatures};

const MAX_FUNCTION_TEXT: usize = 256 * 1024;
const MAX_TOTAL_TEXT: usize = 4 * 1024 * 1024;
const MAX_NESTING: usize = 48;
const FAILURE_CHAIN: usize = 64;

fn negate(cond: &Val) -> String {
    match &cond.expr {
        Expr::Un(UnOp::IsZero, inner) => {
            if is_boolean(inner) {
                expr(inner)
            } else {
                format!("{} != 0", expr(inner))
            }
        }
        Expr::Bin(BinOp::Eq, a, b) => format!("{} != {}", expr(a), expr(b)),
        Expr::Bin(BinOp::Lt, a, b) => format!("{} >= {}", expr(a), expr(b)),
        Expr::Bin(BinOp::Gt, a, b) => format!("{} <= {}", expr(a), expr(b)),
        _ if is_boolean(cond) => format!("!({})", expr(cond)),
        _ => format!("{} == 0", expr(cond)),
    }
}

fn truth(cond: &Val) -> String {
    if is_boolean(cond) {
        expr(cond)
    } else {
        format!("{} != 0", expr(cond))
    }
}

fn args(values: &[Val]) -> String {
    values.iter().map(expr).collect::<Vec<String>>().join(", ")
}

fn payload_args(data: &Payload) -> String {
    if data.words.is_empty() {
        return match data.size {
            Some(0) => String::new(),
            _ => "<memory>".to_owned(),
        };
    }
    args(&data.words)
}

fn event_label(topics: &[Val]) -> (String, &[Val]) {
    let Some((first, rest)) = topics.split_first() else {
        return ("log0".to_owned(), topics);
    };
    let Some(topic) = as_const(first) else {
        return (format!("log{}", topics.len()), topics);
    };
    let bytes: [u8; 32] = topic.to_be_bytes();
    if let Some(signature) = signatures::event(&bytes) {
        return (
            signature.split('(').next().unwrap_or(signature).to_owned(),
            rest,
        );
    }
    (format!("Event_{}", crate::hex_digits(&bytes[..4])), rest)
}

fn stmt_text(stmt: &Stmt) -> String {
    match stmt {
        Stmt::CallValueGuard => "require(msg.value == 0);".to_owned(),
        Stmt::Sstore { slot, value } => format!("{} = {};", render::slot(slot), expr(value)),
        Stmt::Tstore { slot, value } => format!("transient[{}] = {};", expr(slot), expr(value)),
        Stmt::Log { topics, data } => {
            let (name, rest): (String, &[Val]) = event_label(topics);
            let mut parts: Vec<String> = rest.iter().map(expr).collect();
            let data_text: String = payload_args(data);
            if !data_text.is_empty() {
                parts.push(data_text);
            }
            format!("emit {name}({});", parts.join(", "))
        }
        Stmt::Call {
            pc,
            kind,
            address,
            value,
            input,
        } => {
            let verb: &str = match kind {
                CallKind::Call => "call",
                CallKind::CallCode => "callcode",
                CallKind::DelegateCall => "delegatecall",
                CallKind::StaticCall => "staticcall",
            };
            let value_text: String = value
                .as_ref()
                .filter(|v: &&Val| as_const(v).is_none_or(|c| !c.is_zero()))
                .map(|v: &Val| format!("{{value: {}}}", expr(v)))
                .unwrap_or_default();
            let callee: String = match input.selector {
                Some(selector) => {
                    let name: String = signatures::function(selector).map_or_else(
                        || format!("0x{selector:08x}"),
                        |known| {
                            known
                                .signature
                                .split('(')
                                .next()
                                .unwrap_or(known.signature)
                                .to_owned()
                        },
                    );
                    format!("{name}({})", payload_args(input))
                }
                None => payload_args(input),
            };
            let target: String = match as_const(address) {
                Some(constant) => format!("address({constant})"),
                None => render::expr(address),
            };
            format!("success_{pc:x} = {target}.{verb}{value_text}({callee});")
        }
        Stmt::Create { pc, kind, value } => {
            let verb: &str = match kind {
                CreateKind::Create => "create",
                CreateKind::Create2 => "create2",
            };
            format!("created_{pc:x} = {verb}(value: {});", expr(value))
        }
    }
}

fn halt_text(halt: &Halt) -> String {
    match halt {
        Halt::Stop => "return;".to_owned(),
        Halt::Return(data) => {
            if data.size == Some(0) {
                "return;".to_owned()
            } else {
                format!("return abi.encode({});", payload_args(data))
            }
        }
        Halt::Revert(data) => match revert_call(data) {
            None => "revert();".to_owned(),
            Some(reason) if reason.starts_with('"') => format!("revert({reason});"),
            Some(reason) => format!("revert {reason};"),
        },
        Halt::Invalid => "invalid();".to_owned(),
        Halt::SelfDestruct(target) => format!("selfdestruct({});", expr(target)),
        Halt::Undefined(byte) => format!("invalid(); // undefined opcode 0x{byte:02x}"),
        Halt::StackUnderflow => "invalid(); // stack underflow".to_owned(),
        Halt::StackOverflow => "invalid(); // stack overflow".to_owned(),
        Halt::BadJump(target) => format!("invalid(); // jump to non-JUMPDEST {target}"),
        Halt::UnresolvedJump => {
            "goto <computed>; // jump target depends on runtime data".to_owned()
        }
        Halt::LoopLimit => "// loop: explored twice, later iterations not expanded".to_owned(),
        Halt::StepLimit => "// exploration budget reached".to_owned(),
    }
}

enum Failure {
    Revert(Option<String>),
    Invalid,
}

fn revert_call(data: &Payload) -> Option<String> {
    let Some(selector) = data.selector else {
        return (data.size != Some(0)).then(|| "returndata".to_owned());
    };
    if selector == ERROR_STRING
        && let Some(text) = data.bytes.as_deref().and_then(error_string)
    {
        return Some(format!("{text:?}"));
    }
    if selector == PANIC
        && let Some(code) = data.words.first().and_then(as_const)
    {
        return Some(format!("Panic({code})"));
    }
    let name: String = signatures::error(selector).map_or_else(
        || format!("error_{selector:08x}"),
        |signature: &str| signature.split('(').next().unwrap_or(signature).to_owned(),
    );
    Some(format!("{name}({})", args(&data.words)))
}

fn failure(trace: &Trace, node: usize, targets: &BTreeSet<usize>) -> Option<Failure> {
    let mut current: usize = node;
    for _ in 0..FAILURE_CHAIN {
        if targets.contains(&current) {
            return None;
        }
        let item = &trace.nodes[current];
        if !item.stmts.is_empty() {
            return None;
        }
        match &item.end {
            End::Next(next) => current = *next,
            End::Halt(Halt::Revert(data)) => return Some(Failure::Revert(revert_call(data))),
            End::Halt(Halt::Invalid) => return Some(Failure::Invalid),
            _ => return None,
        }
    }
    None
}

fn require(cond: &str, failure: &Failure) -> String {
    match failure {
        Failure::Revert(None) => format!("require({cond});"),
        Failure::Revert(Some(reason)) => format!("require({cond}, {reason});"),
        Failure::Invalid => format!("assert({cond});"),
    }
}

fn mark(emitted: &mut BTreeSet<usize>, trace: &Trace, node: usize) {
    let mut current: usize = node;
    for _ in 0..FAILURE_CHAIN {
        emitted.insert(current);
        match trace.nodes[current].end {
            End::Next(next) => current = next,
            _ => return,
        }
    }
}

struct Writer<'a> {
    trace: &'a Trace,
    out: String,
    targets: BTreeSet<usize>,
    pending: VecDeque<usize>,
    emitted: BTreeSet<usize>,
    full: bool,
}

impl Writer<'_> {
    fn line(&mut self, indent: usize, text: &str) {
        if self.out.len() > MAX_FUNCTION_TEXT {
            if !self.full {
                self.out.push_str("        // output truncated\n");
                self.full = true;
            }
            return;
        }
        for _ in 0..indent {
            self.out.push_str("    ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn block(&mut self, start: usize, indent: usize, depth: usize) {
        let mut current: usize = start;
        loop {
            if self.full {
                return;
            }
            if !self.emitted.insert(current) {
                self.line(indent, &format!("goto label_{current};"));
                return;
            }
            if self.targets.contains(&current) {
                self.line(
                    indent.saturating_sub(1),
                    &format!("label_{current}: // pc {:#x}", self.trace.nodes[current].pc),
                );
            }
            let node = &self.trace.nodes[current];
            for stmt in &node.stmts {
                let text: String = stmt_text(stmt);
                self.line(indent, &text);
            }
            match &node.end {
                End::Next(next) => current = *next,
                End::Goto(target) => {
                    self.line(indent, &format!("goto label_{target};"));
                    return;
                }
                End::Halt(halt) => {
                    self.line(indent, &halt_text(halt));
                    return;
                }
                End::Cut => {
                    self.line(indent, "// exploration stopped here (fork or node limit)");
                    return;
                }
                End::Open => return,
                End::Branch { cond, taken, fall } => {
                    let (cond, taken, fall) = (cond.clone(), *taken, *fall);
                    if let Some(failed) = failure(self.trace, taken, &self.targets) {
                        mark(&mut self.emitted, self.trace, taken);
                        self.line(indent, &require(&negate(&cond), &failed));
                        current = fall;
                        continue;
                    }
                    if let Some(failed) = failure(self.trace, fall, &self.targets) {
                        mark(&mut self.emitted, self.trace, fall);
                        self.line(indent, &require(&truth(&cond), &failed));
                        current = taken;
                        continue;
                    }
                    if depth >= MAX_NESTING {
                        self.targets.insert(taken);
                        self.pending.push_back(taken);
                        self.line(
                            indent,
                            &format!("if ({}) goto label_{taken};", truth(&cond)),
                        );
                        current = fall;
                        continue;
                    }
                    self.line(indent, &format!("if ({}) {{", truth(&cond)));
                    self.block(taken, indent + 1, depth + 1);
                    self.line(indent, "} else {");
                    self.block(fall, indent + 1, depth + 1);
                    self.line(indent, "}");
                    return;
                }
            }
        }
    }
}

fn header(function: &FunctionReport) -> String {
    let (name, types): (String, Vec<String>) = match function.signature {
        Some(signature) => {
            let name: &str = signature.split('(').next().unwrap_or(signature);
            let inner: &str = signature
                .get(name.len() + 1..signature.len().saturating_sub(1))
                .unwrap_or("");
            let types: Vec<String> = if inner.is_empty() {
                Vec::new()
            } else {
                inner.split(',').map(str::to_owned).collect()
            };
            (name.to_owned(), types)
        }
        None => (
            format!("function_{}", &function.selector[2..]),
            function
                .arguments
                .iter()
                .map(|arg| arg.ty.clone())
                .collect(),
        ),
    };
    let params: Vec<String> = types
        .iter()
        .enumerate()
        .map(|(index, ty): (usize, &String)| {
            let location: &str = if ty.ends_with(']') || ty == "bytes" || ty == "string" {
                " calldata"
            } else {
                ""
            };
            format!("{ty}{location} arg{index}")
        })
        .collect();
    let modifier: &str = match function.mutability {
        Mutability::Pure => " pure",
        Mutability::View => " view",
        Mutability::NonPayable => "",
        Mutability::Payable => " payable",
    };
    format!(
        "function {name}({}) external{modifier} {{",
        params.join(", ")
    )
}

pub(crate) fn render(analysis: &Analysis) -> String {
    let report = &analysis.report;
    let mut out: String = String::new();
    let _ = writeln!(
        out,
        "// {} bytecode, runtime {} bytes, keccak256 {}",
        report.layout.kind, report.runtime.bytes, report.runtime.keccak256
    );
    if let Some(metadata) = &report.metadata
        && let Some(compiler) = &metadata.compiler
    {
        let _ = writeln!(out, "// metadata: {} {}", compiler.name, compiler.version);
    }
    if let Some(proxy) = &report.proxy {
        let _ = writeln!(out, "// proxy: {proxy:?}");
    }
    out.push_str("contract Recovered {\n");
    for function in &report.functions {
        if out.len() > MAX_TOTAL_TEXT {
            out.push_str("    // output truncated\n");
            break;
        }
        let Some(selector) = u32::from_str_radix(&function.selector[2..], 16).ok() else {
            continue;
        };
        let Some(trace) = analysis.traces.get(&selector) else {
            continue;
        };
        let signature: &str = function.signature.unwrap_or("unknown signature");
        let _ = writeln!(
            out,
            "\n    // selector {} ({signature}), entry pc {:#x}",
            function.selector, function.entry
        );
        let _ = writeln!(out, "    {}", header(function));
        let mut targets: BTreeSet<usize> = BTreeSet::new();
        for node in &trace.nodes {
            if let End::Goto(target) = node.end {
                targets.insert(target);
            }
        }
        let mut writer: Writer<'_> = Writer {
            trace,
            out: String::new(),
            targets,
            pending: VecDeque::new(),
            emitted: BTreeSet::new(),
            full: false,
        };
        writer.block(0, 2, 0);
        while let Some(next) = writer.pending.pop_front() {
            if !writer.emitted.contains(&next) {
                writer.block(next, 2, 0);
            }
        }
        out.push_str(&writer.out);
        out.push_str("    }\n");
    }
    out.push_str("}\n");
    out
}
