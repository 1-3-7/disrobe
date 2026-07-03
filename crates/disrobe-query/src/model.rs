use disrobe_core::{Cfg, cyclomatic_complexity};
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnEncoding, InsnFlow,
};
use disrobe_nir::{
    NirClass, NirFunction, NirInstr, NirModule, NirSymbol, SymbolKind as NirSymbolKind,
};
use indexmap::IndexMap;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FunctionSymbol<'a> {
    address: u64,
    name: &'a str,
    is_export: bool,
}

fn disasm_function_symbols(symbol_table: &[DisasmSymbol]) -> Vec<FunctionSymbol<'_>> {
    let mut symbols: Vec<FunctionSymbol<'_>> = symbol_table
        .iter()
        .filter_map(|s: &DisasmSymbol| match s.kind {
            DisasmSymbolKind::Function | DisasmSymbolKind::Export => Some(FunctionSymbol {
                address: s.address,
                name: s.name.as_str(),
                is_export: matches!(s.kind, DisasmSymbolKind::Export),
            }),
            DisasmSymbolKind::Data | DisasmSymbolKind::Label | DisasmSymbolKind::Import => None,
        })
        .collect();
    symbols.sort_by_key(|s: &FunctionSymbol<'_>| s.address);
    let mut grouped: Vec<FunctionSymbol<'_>> = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        match grouped.last_mut() {
            Some(existing) if existing.address == symbol.address => {
                existing.is_export |= symbol.is_export;
            }
            _ => grouped.push(symbol),
        }
    }
    grouped
}

fn instruction_end(offset: u64, byte_len: usize) -> u64 {
    u64::try_from(byte_len)
        .ok()
        .and_then(|len: u64| offset.checked_add(len))
        .unwrap_or(offset)
}

const fn address_is_before_end(address: u64, end: u64) -> bool {
    address < end
}

const fn address_in_range(address: u64, start: u64, end: u64) -> bool {
    address >= start && address_is_before_end(address, end)
}

const fn address_in_block(address: u64, leader: u64, next_leader: Option<u64>, end: u64) -> bool {
    if address < leader {
        return false;
    }
    if address == leader {
        return true;
    }
    match next_leader {
        Some(next) => address < next,
        None => address_is_before_end(address, end),
    }
}

const fn instruction_in_function(offset: u64, start: u64, end: u64) -> bool {
    address_in_range(offset, start, end) || offset == start
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymbolRef {
    pub name: String,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolKind {
    Function,
    Data,
    Label,
    Export,
    Import,
}

impl SymbolKind {
    const fn from_disasm(kind: DisasmSymbolKind) -> Self {
        match kind {
            DisasmSymbolKind::Function => Self::Function,
            DisasmSymbolKind::Data => Self::Data,
            DisasmSymbolKind::Label => Self::Label,
            DisasmSymbolKind::Export => Self::Export,
            DisasmSymbolKind::Import => Self::Import,
        }
    }

    const fn from_nir(kind: NirSymbolKind) -> Self {
        match kind {
            NirSymbolKind::Function => Self::Function,
            NirSymbolKind::Data => Self::Data,
            NirSymbolKind::Label => Self::Label,
            NirSymbolKind::Export => Self::Export,
            NirSymbolKind::Import => Self::Import,
        }
    }

    #[must_use]
    pub const fn is_external(self) -> bool {
        matches!(self, Self::Import)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InsnClass {
    Call,
    UnconditionalJump,
    ConditionalJump,
    Return,
    Other,
}

impl InsnClass {
    const fn from_flow(flow: InsnFlow) -> Self {
        match flow {
            InsnFlow::Call | InsnFlow::IndirectCall => Self::Call,
            InsnFlow::UnconditionalBranch | InsnFlow::IndirectBranch => Self::UnconditionalJump,
            InsnFlow::ConditionalBranch => Self::ConditionalJump,
            InsnFlow::Return => Self::Return,
            InsnFlow::Sequential | InsnFlow::Interrupt => Self::Other,
        }
    }

    const fn from_nir(class: NirClass) -> Self {
        match class {
            NirClass::Call => Self::Call,
            NirClass::UnconditionalJump => Self::UnconditionalJump,
            NirClass::ConditionalJump => Self::ConditionalJump,
            NirClass::Return => Self::Return,
            NirClass::Other => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InsnView {
    pub offset: u64,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub class: InsnClass,
    pub branch_target: Option<u64>,
    #[serde(skip_serializing_if = "IsaView::is_empty")]
    pub isa: IsaView,
    #[serde(skip_serializing_if = "StackEffectView::is_neutral")]
    pub stack_effect: StackEffectView,
    #[serde(skip_serializing_if = "InsnSegmentsView::is_empty")]
    pub segments: InsnSegmentsView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct IsaView {
    pub encoding: &'static str,
    pub cpuid_features: Vec<String>,
}

impl IsaView {
    fn from_disasm(insn: &DisasmInstruction) -> Self {
        Self {
            encoding: insn.isa.encoding.label(),
            cpuid_features: insn.isa.cpuid_features.clone(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cpuid_features.is_empty() && self.encoding == InsnEncoding::Unknown.label()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct StackEffectView {
    pub sp_delta: i32,
    pub is_stack: bool,
    pub fpu_increment: i8,
    pub fpu_writes_top: bool,
}

impl StackEffectView {
    const fn from_disasm(insn: &DisasmInstruction) -> Self {
        Self {
            sp_delta: insn.stack_effect.sp_delta,
            is_stack: insn.stack_effect.is_stack,
            fpu_increment: insn.stack_effect.fpu_increment,
            fpu_writes_top: insn.stack_effect.fpu_writes_top,
        }
    }

    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub const fn is_neutral(&self) -> bool {
        self.sp_delta == 0 && !self.is_stack && !self.fpu_writes_top
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct InsnSegmentsView {
    pub legacy_prefix: u8,
    pub opcode: u8,
    pub modrm: u8,
    pub sib: u8,
    pub displacement: u8,
    pub immediate: u8,
}

impl InsnSegmentsView {
    const fn from_disasm(insn: &DisasmInstruction) -> Self {
        Self {
            legacy_prefix: insn.segments.legacy_prefix,
            opcode: insn.segments.opcode,
            modrm: insn.segments.modrm,
            sib: insn.segments.sib,
            displacement: insn.segments.displacement,
            immediate: insn.segments.immediate,
        }
    }

    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub const fn total(&self) -> usize {
        self.legacy_prefix as usize
            + self.opcode as usize
            + self.modrm as usize
            + self.sib as usize
            + self.displacement as usize
            + self.immediate as usize
    }

    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

impl InsnView {
    fn from_disasm(insn: &DisasmInstruction) -> Self {
        Self {
            offset: insn.offset,
            mnemonic: insn.mnemonic.clone(),
            operands: insn.operands.clone(),
            class: InsnClass::from_flow(insn.flow),
            branch_target: insn.branch_target,
            isa: IsaView::from_disasm(insn),
            stack_effect: StackEffectView::from_disasm(insn),
            segments: InsnSegmentsView::from_disasm(insn),
        }
    }

    fn from_nir(insn: &NirInstr) -> Self {
        Self {
            offset: insn.address,
            mnemonic: insn.mnemonic.clone(),
            operands: insn.operands.clone(),
            class: InsnClass::from_nir(insn.class()),
            branch_target: insn.direct_target(),
            isa: IsaView::default(),
            stack_effect: StackEffectView::default(),
            segments: InsnSegmentsView::default(),
        }
    }

    #[must_use]
    pub const fn is_direct_call(&self) -> bool {
        matches!(self.class, InsnClass::Call) && self.branch_target.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub end: u64,
    pub is_export: bool,
    pub instructions: Vec<InsnView>,
}

impl Function {
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    #[must_use]
    pub fn contains_offset(&self, offset: u64) -> bool {
        address_in_range(offset, self.address, self.end)
            || self
                .instructions
                .iter()
                .any(|insn: &InsnView| insn.offset == offset)
    }

    #[must_use]
    pub fn cfg(&self) -> Cfg {
        let blocks: Vec<BasicBlock> = self.basic_blocks();
        let starts: Vec<u64> = blocks.iter().map(|b: &BasicBlock| b.start).collect();
        let nodes: u32 = u32::try_from(blocks.len().max(1)).map_or(u32::MAX, |value: u32| value);
        let mut edges: u32 = 0;
        for block in &blocks {
            for succ in &block.successors {
                if starts.binary_search(succ).is_ok() {
                    edges = edges.saturating_add(1);
                }
            }
        }
        Cfg::from_counts(nodes, edges)
    }

    #[must_use]
    pub fn cyclomatic_complexity(&self) -> u32 {
        cyclomatic_complexity(&self.cfg())
    }

    fn effective_end(&self) -> u64 {
        let last_offset: u64 = self
            .instructions
            .last()
            .map_or(self.end, |i: &InsnView| i.offset);
        self.end.max(last_offset.saturating_add(1))
    }

    #[must_use]
    pub fn basic_blocks(&self) -> Vec<BasicBlock> {
        if self.instructions.is_empty() {
            return Vec::new();
        }
        let end: u64 = self.effective_end();
        let leaders: Vec<u64> = self.block_leaders();
        let mut blocks: Vec<BasicBlock> = Vec::with_capacity(leaders.len());
        for (idx, leader) in leaders.iter().enumerate() {
            let next_leader: Option<u64> = leaders.get(idx + 1).copied();
            let block_end: u64 = next_leader.unwrap_or(end);
            let insns: Vec<InsnView> = self
                .instructions
                .iter()
                .filter(|i: &&InsnView| address_in_block(i.offset, *leader, next_leader, end))
                .cloned()
                .collect();
            let Some(last): Option<&InsnView> = insns.last() else {
                continue;
            };
            let fallthrough: Option<u64> = match next_leader {
                Some(_) => self
                    .instructions
                    .iter()
                    .find(|i: &&InsnView| i.offset >= block_end)
                    .map(|i: &InsnView| i.offset),
                None => None,
            };
            let (kind, successors): (BlockKind, Vec<u64>) =
                terminator_edges(last, fallthrough, &leaders);
            blocks.push(BasicBlock {
                start: *leader,
                end: block_end,
                instructions: insns,
                successors,
                kind,
            });
        }
        blocks
    }

    fn block_leaders(&self) -> Vec<u64> {
        let end: u64 = self.effective_end();
        let in_function = |offset: u64| {
            address_in_range(offset, self.address, end)
                || self
                    .instructions
                    .iter()
                    .any(|insn: &InsnView| insn.offset == offset)
        };
        let mut starts: Vec<u64> = Vec::new();
        if let Some(first) = self.instructions.first() {
            starts.push(first.offset);
        }
        for (idx, insn) in self.instructions.iter().enumerate() {
            match insn.class {
                InsnClass::ConditionalJump => {
                    if let Some(target) = insn.branch_target
                        && in_function(target)
                    {
                        starts.push(target);
                    }
                    if let Some(next) = self.instructions.get(idx + 1) {
                        starts.push(next.offset);
                    }
                }
                InsnClass::UnconditionalJump => {
                    if let Some(target) = insn.branch_target
                        && in_function(target)
                    {
                        starts.push(target);
                    }
                }
                InsnClass::Return | InsnClass::Call | InsnClass::Other => {}
            }
        }
        starts.retain(|s: &u64| in_function(*s));
        starts.sort_unstable();
        starts.dedup();
        starts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockKind {
    FallThrough,
    Conditional,
    Jump,
    Return,
    Indirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BasicBlock {
    pub start: u64,
    pub end: u64,
    pub instructions: Vec<InsnView>,
    pub successors: Vec<u64>,
    pub kind: BlockKind,
}

fn terminator_edges(
    last: &InsnView,
    fallthrough: Option<u64>,
    leaders: &[u64],
) -> (BlockKind, Vec<u64>) {
    let in_function = |addr: u64| leaders.binary_search(&addr).is_ok();
    match last.class {
        InsnClass::ConditionalJump => {
            let mut succ: Vec<u64> = Vec::new();
            if let Some(target) = last.branch_target.filter(|t: &u64| in_function(*t)) {
                succ.push(target);
            }
            if let Some(next) = fallthrough.filter(|n: &u64| in_function(*n)) {
                succ.push(next);
            }
            succ.sort_unstable();
            succ.dedup();
            (BlockKind::Conditional, succ)
        }
        InsnClass::UnconditionalJump => match last.branch_target {
            Some(target) if in_function(target) => (BlockKind::Jump, vec![target]),
            Some(_) => (BlockKind::Jump, Vec::new()),
            None => (BlockKind::Indirect, Vec::new()),
        },
        InsnClass::Return => (BlockKind::Return, Vec::new()),
        InsnClass::Call | InsnClass::Other => {
            let succ: Vec<u64> = fallthrough
                .filter(|n: &u64| in_function(*n))
                .map_or_else(Vec::new, |next: u64| vec![next]);
            (BlockKind::FallThrough, succ)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Module {
    pub source_hash: [u8; 32],
    functions: Vec<Function>,
    symbols_by_addr: IndexMap<u64, SymbolRef>,
}

impl Module {
    #[must_use]
    pub fn from_disasm(payload: &DisasmPayload) -> Self {
        let function_symbols: Vec<FunctionSymbol<'_>> =
            disasm_function_symbols(&payload.symbol_table);

        let mut sorted_insns: Vec<&DisasmInstruction> = payload.instructions.iter().collect();
        sorted_insns.sort_by_key(|i: &&DisasmInstruction| i.offset);

        let last_end: u64 = sorted_insns.last().map_or(0, |i: &&DisasmInstruction| {
            instruction_end(i.offset, i.bytes.len())
        });

        let functions: Vec<Function> = function_symbols
            .iter()
            .enumerate()
            .map(|(idx, sym): (usize, &FunctionSymbol<'_>)| {
                let start: u64 = sym.address;
                let end: u64 = function_symbols
                    .get(idx + 1)
                    .map_or(last_end, |next: &FunctionSymbol<'_>| next.address);
                let instructions: Vec<InsnView> = sorted_insns
                    .iter()
                    .filter(|i: &&&DisasmInstruction| instruction_in_function(i.offset, start, end))
                    .map(|i: &&DisasmInstruction| InsnView::from_disasm(i))
                    .collect();
                Function {
                    name: sym.name.to_owned(),
                    address: start,
                    end,
                    is_export: sym.is_export,
                    instructions,
                }
            })
            .collect();

        let symbols_by_addr: IndexMap<u64, SymbolRef> = payload
            .symbol_table
            .iter()
            .map(|s: &DisasmSymbol| {
                (
                    s.address,
                    SymbolRef {
                        name: s.name.clone(),
                        kind: SymbolKind::from_disasm(s.kind),
                    },
                )
            })
            .collect();

        Self {
            source_hash: payload.source_hash,
            functions,
            symbols_by_addr,
        }
    }

    #[must_use]
    pub fn from_nir(module: &NirModule) -> Self {
        let functions: Vec<Function> = module
            .functions
            .iter()
            .map(|f: &NirFunction| Function {
                name: f.name.clone(),
                address: f.address,
                end: f.end,
                is_export: f.is_export,
                instructions: f.instructions.iter().map(InsnView::from_nir).collect(),
            })
            .collect();

        let symbols_by_addr: IndexMap<u64, SymbolRef> = module
            .symbols
            .iter()
            .map(|s: &NirSymbol| {
                (
                    s.address,
                    SymbolRef {
                        name: s.name.clone(),
                        kind: SymbolKind::from_nir(s.kind),
                    },
                )
            })
            .collect();

        Self {
            source_hash: module.source_hash,
            functions,
            symbols_by_addr,
        }
    }

    #[must_use]
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    #[must_use]
    pub fn function_by_name(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|f: &&Function| f.name == name)
    }

    #[must_use]
    pub fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols_by_addr
            .iter()
            .find(|(_, sym): &(&u64, &SymbolRef)| sym.name.as_str() == name)
            .map(|(addr, _): (&u64, &SymbolRef)| *addr)
    }

    #[must_use]
    pub fn symbol_name(&self, address: u64) -> Option<&str> {
        self.symbols_by_addr
            .get(&address)
            .map(|sym: &SymbolRef| sym.name.as_str())
    }

    #[must_use]
    pub fn symbol_ref(&self, address: u64) -> Option<&SymbolRef> {
        self.symbols_by_addr.get(&address)
    }

    #[must_use]
    pub fn function_containing(&self, offset: u64) -> Option<&Function> {
        self.functions
            .iter()
            .find(|f: &&Function| f.contains_offset(offset))
    }

    #[must_use]
    pub fn call_graph(&self) -> CallGraph {
        let nodes: Vec<CallGraphNode> = self
            .functions
            .iter()
            .map(|f: &Function| CallGraphNode {
                name: f.name.clone(),
                address: f.address,
                is_export: f.is_export,
            })
            .collect();

        let mut edges: Vec<CallGraphEdge> = Vec::new();
        for caller in &self.functions {
            for insn in &caller.instructions {
                if insn.class != InsnClass::Call {
                    continue;
                }
                let Some(target): Option<u64> = insn.branch_target else {
                    continue;
                };
                let callee_name: String = self
                    .function_containing(target)
                    .filter(|callee: &&Function| callee.address == target)
                    .map(|callee: &Function| callee.name.clone())
                    .or_else(|| {
                        self.symbols_by_addr
                            .get(&target)
                            .map(|sym: &SymbolRef| sym.name.clone())
                    })
                    .unwrap_or_else(|| format!("sub_{target:x}"));
                edges.push(CallGraphEdge {
                    caller: caller.name.clone(),
                    caller_address: caller.address,
                    call_site: insn.offset,
                    callee: callee_name,
                    callee_address: target,
                });
            }
        }
        edges.sort_by(|a: &CallGraphEdge, b: &CallGraphEdge| {
            a.call_site
                .cmp(&b.call_site)
                .then(a.callee_address.cmp(&b.callee_address))
        });

        CallGraph { nodes, edges }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallGraphNode {
    pub name: String,
    pub address: u64,
    pub is_export: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallGraphEdge {
    pub caller: String,
    pub caller_address: u64,
    pub call_site: u64,
    pub callee: String,
    pub callee_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
}

impl CallGraph {
    #[must_use]
    pub fn to_dot(&self) -> String {
        let mut out: String = String::new();
        out.push_str("digraph callgraph {\n");
        out.push_str("  rankdir=LR;\n");
        out.push_str("  node [shape=box, fontname=\"monospace\"];\n");
        for node in &self.nodes {
            let shape: &str = if node.is_export {
                "doubleoctagon"
            } else {
                "box"
            };
            let line: String = format!(
                "  \"{}\" [shape={shape}, label=\"{}\\n{:#x}\"];",
                escape_dot(&node.name),
                escape_dot(&node.name),
                node.address
            );
            push_line(&mut out, &line);
        }
        for edge in &self.edges {
            let line: String = format!(
                "  \"{}\" -> \"{}\" [label=\"{:#x}\"];",
                escape_dot(&edge.caller),
                escape_dot(&edge.callee),
                edge.call_site
            );
            push_line(&mut out, &line);
        }
        out.push_str("}\n");
        out
    }
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn escape_dot(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len().saturating_mul(2usize));
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn seq(offset: u64, bytes: Vec<u8>, mnemonic: &str, operands: &[&str]) -> DisasmInstruction {
        flowed(
            offset,
            bytes,
            mnemonic,
            operands,
            InsnFlow::Sequential,
            None,
        )
    }

    fn flowed(
        offset: u64,
        bytes: Vec<u8>,
        mnemonic: &str,
        operands: &[&str],
        flow: InsnFlow,
        branch_target: Option<u64>,
    ) -> DisasmInstruction {
        DisasmInstruction {
            offset,
            bytes,
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            flow,
            branch_target,
            ..DisasmInstruction::default()
        }
    }

    fn func_sym(address: u64, name: &str) -> DisasmSymbol {
        DisasmSymbol {
            address,
            name: name.to_owned(),
            kind: DisasmSymbolKind::Function,
        }
    }

    fn export_sym(address: u64, name: &str) -> DisasmSymbol {
        DisasmSymbol {
            address,
            name: name.to_owned(),
            kind: DisasmSymbolKind::Export,
        }
    }

    #[test]
    fn dot_escape_handles_quotes_and_backslashes_in_one_pass() {
        let escaped: String = escape_dot(r#"a\b"c"#);
        assert_eq!(escaped, r#"a\\b\"c"#);
    }

    #[test]
    fn class_maps_from_structured_flow() {
        assert_eq!(InsnClass::from_flow(InsnFlow::Call), InsnClass::Call);
        assert_eq!(
            InsnClass::from_flow(InsnFlow::IndirectCall),
            InsnClass::Call
        );
        assert_eq!(
            InsnClass::from_flow(InsnFlow::ConditionalBranch),
            InsnClass::ConditionalJump
        );
        assert_eq!(
            InsnClass::from_flow(InsnFlow::UnconditionalBranch),
            InsnClass::UnconditionalJump
        );
        assert_eq!(InsnClass::from_flow(InsnFlow::Return), InsnClass::Return);
        assert_eq!(InsnClass::from_flow(InsnFlow::Sequential), InsnClass::Other);
    }

    #[test]
    fn module_partitions_instructions_into_functions_by_symbol() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                seq(0x10, vec![0x55], "push", &["rbp"]),
                flowed(
                    0x11,
                    vec![0xe8, 0, 0, 0, 0],
                    "call",
                    &["0x20"],
                    InsnFlow::Call,
                    Some(0x20),
                ),
                flowed(0x16, vec![0xc3], "ret", &[], InsnFlow::Return, None),
                seq(0x20, vec![0x90], "nop", &[]),
                flowed(0x21, vec![0xc3], "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![func_sym(0x10, "caller"), func_sym(0x20, "callee")],
        };
        let module: Module = Module::from_disasm(&payload);
        assert_eq!(module.functions().len(), 2);
        let caller: &Function = module.function_by_name("caller").expect("caller");
        assert_eq!(caller.instruction_count(), 3);
        assert_eq!(caller.address, 0x10);
        assert_eq!(caller.end, 0x20);
        let call: &InsnView = caller
            .instructions
            .iter()
            .find(|i: &&InsnView| i.class == InsnClass::Call)
            .expect("a call");
        assert_eq!(call.branch_target, Some(0x20));
        let callee: &Function = module.function_by_name("callee").expect("callee");
        assert_eq!(callee.instruction_count(), 2);
    }

    #[test]
    fn same_address_function_and_export_preserve_export_status() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![flowed(0x10, vec![0xc3], "ret", &[], InsnFlow::Return, None)],
            symbol_table: vec![func_sym(0x10, "internal"), export_sym(0x10, "public")],
        };
        let module: Module = Module::from_disasm(&payload);
        assert_eq!(module.functions().len(), 1);
        let f: &Function = module.function_by_name("internal").expect("internal");
        assert!(f.is_export);
        assert_eq!(f.instruction_count(), 1);
    }

    #[test]
    fn straight_line_function_has_complexity_one() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                seq(0x0, vec![0x90], "nop", &[]),
                seq(0x1, vec![0x90], "nop", &[]),
                flowed(0x2, vec![0xc3], "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![func_sym(0x0, "f")],
        };
        let module: Module = Module::from_disasm(&payload);
        let f: &Function = module.function_by_name("f").expect("f");
        assert_eq!(f.cyclomatic_complexity(), 1);
        let blocks: Vec<BasicBlock> = f.basic_blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].kind, BlockKind::Return);
        assert!(blocks[0].successors.is_empty());
    }

    #[test]
    fn top_address_instruction_stays_in_last_function() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![flowed(
                u64::MAX,
                vec![0xc3],
                "ret",
                &[],
                InsnFlow::Return,
                None,
            )],
            symbol_table: vec![func_sym(u64::MAX, "top")],
        };
        let module: Module = Module::from_disasm(&payload);
        let f: &Function = module.function_by_name("top").expect("top");
        assert_eq!(f.instruction_count(), 1);
        assert!(f.contains_offset(u64::MAX));
        let blocks: Vec<BasicBlock> = f.basic_blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start, u64::MAX);
        assert_eq!(blocks[0].kind, BlockKind::Return);
    }

    #[test]
    fn overflowing_instruction_length_does_not_cover_top_address() {
        let start: u64 = u64::MAX - 1;
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![seq(start, vec![0x90, 0x90, 0x90, 0x90], "nop4", &[])],
            symbol_table: vec![func_sym(start, "edge")],
        };
        let module: Module = Module::from_disasm(&payload);
        let f: &Function = module.function_by_name("edge").expect("edge");
        assert_eq!(f.instruction_count(), 1);
        assert!(f.contains_offset(start));
        assert!(!f.contains_offset(u64::MAX));
        let blocks: Vec<BasicBlock> = f.basic_blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start, start);
        assert_eq!(blocks[0].end, u64::MAX);
        assert_eq!(blocks[0].instructions.len(), 1);
        assert_eq!(blocks[0].instructions[0].offset, start);
    }

    #[test]
    fn single_branch_function_has_complexity_two() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                seq(0x0, vec![0x85, 0xc0], "test", &["eax", "eax"]),
                flowed(
                    0x2,
                    vec![0x74, 0x02],
                    "je",
                    &["0x6"],
                    InsnFlow::ConditionalBranch,
                    Some(0x6),
                ),
                seq(0x4, vec![0x31, 0xc0], "xor", &["eax", "eax"]),
                flowed(0x6, vec![0xc3], "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![func_sym(0x0, "branchy")],
        };
        let module: Module = Module::from_disasm(&payload);
        let f: &Function = module.function_by_name("branchy").expect("branchy");
        assert_eq!(f.cyclomatic_complexity(), 2);
    }

    fn branchy_module() -> Module {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                seq(0x0, vec![0x85, 0xc0], "test", &["eax", "eax"]),
                flowed(
                    0x2,
                    vec![0x74, 0x02],
                    "je",
                    &["0x6"],
                    InsnFlow::ConditionalBranch,
                    Some(0x6),
                ),
                seq(0x4, vec![0x31, 0xc0], "xor", &["eax", "eax"]),
                flowed(0x6, vec![0xc3], "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![func_sym(0x0, "branchy")],
        };
        Module::from_disasm(&payload)
    }

    #[test]
    fn basic_blocks_reassemble_to_linear_listing() {
        let module: Module = branchy_module();
        let f: &Function = module.function_by_name("branchy").expect("branchy");
        let blocks: Vec<BasicBlock> = f.basic_blocks();
        let reassembled: Vec<u64> = blocks
            .iter()
            .flat_map(|b: &BasicBlock| b.instructions.iter().map(|i: &InsnView| i.offset))
            .collect();
        let linear: Vec<u64> = f.instructions.iter().map(|i: &InsnView| i.offset).collect();
        assert_eq!(
            reassembled, linear,
            "blocks in order must reproduce the linear listing"
        );
    }

    #[test]
    fn basic_blocks_edges_match_hand_verified_fixture() {
        let module: Module = branchy_module();
        let f: &Function = module.function_by_name("branchy").expect("branchy");
        let blocks: Vec<BasicBlock> = f.basic_blocks();
        assert_eq!(blocks.len(), 3, "entry, xor-arm, ret: {blocks:?}");
        let entry: &BasicBlock = &blocks[0];
        assert_eq!(entry.start, 0x0);
        assert_eq!(entry.kind, BlockKind::Conditional);
        assert_eq!(entry.successors, vec![0x4, 0x6]);
        let arm: &BasicBlock = &blocks[1];
        assert_eq!(arm.start, 0x4);
        assert_eq!(arm.successors, vec![0x6]);
        let exit: &BasicBlock = &blocks[2];
        assert_eq!(exit.start, 0x6);
        assert_eq!(exit.kind, BlockKind::Return);
        assert!(exit.successors.is_empty());
    }

    #[test]
    fn call_graph_edges_are_backed_by_real_calls() {
        let payload: DisasmPayload = DisasmPayload {
            source_hash: [0u8; 32],
            instructions: vec![
                flowed(
                    0x10,
                    vec![0xe8, 0, 0, 0, 0],
                    "call",
                    &["0x20"],
                    InsnFlow::Call,
                    Some(0x20),
                ),
                flowed(0x15, vec![0xc3], "ret", &[], InsnFlow::Return, None),
                flowed(0x20, vec![0xc3], "ret", &[], InsnFlow::Return, None),
            ],
            symbol_table: vec![func_sym(0x10, "caller"), func_sym(0x20, "callee")],
        };
        let module: Module = Module::from_disasm(&payload);
        let graph: CallGraph = module.call_graph();
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
        let edge: &CallGraphEdge = &graph.edges[0];
        assert_eq!(edge.caller, "caller");
        assert_eq!(edge.callee, "callee");
        assert_eq!(edge.call_site, 0x10);
        assert_eq!(edge.callee_address, 0x20);

        let caller: &Function = module.function_by_name("caller").expect("caller");
        let backing: &InsnView = caller
            .instructions
            .iter()
            .find(|i: &&InsnView| i.offset == edge.call_site)
            .expect("call site exists in caller");
        assert_eq!(backing.class, InsnClass::Call);
        assert_eq!(backing.branch_target, Some(edge.callee_address));

        let dot: String = graph.to_dot();
        assert!(dot.starts_with("digraph callgraph {"));
        assert!(dot.contains("\"caller\" -> \"callee\""));
        assert!(dot.trim_end().ends_with('}'));
    }
}
