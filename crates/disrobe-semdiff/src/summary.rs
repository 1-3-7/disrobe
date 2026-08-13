use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use disrobe_nir::{
    BinaryOp, DefUse, NirBlock, NirFunction, NirInstr, NirOp, ValueId, ValueOp, basic_blocks,
    def_use,
};

pub const MAX_SUMMARY_INSTRUCTIONS: usize = 4096;
pub const MAX_SUMMARY_BLOCKS: usize = 128;
pub const MAX_SUMMARY_NODES: usize = 4096;
pub const MAX_SUMMARY_DEPTH: u32 = 128;
pub const MAX_SUMMARY_MEMORY_CELLS: usize = 256;
pub const MAX_SUMMARY_OUTPUTS: usize = 64;
pub const MAX_ADDRESS_PEEL_STEPS: u32 = 32;
pub const MIN_SUMMARY_OPERATIONS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SummaryDecline {
    BlockCountExceeded,
    CyclicControlFlow,
    DepthBudgetExhausted,
    InstructionCountExceeded,
    MemoryCellBudgetExhausted,
    NodeBudgetExhausted,
    NoObservableOutput,
    OutputBudgetExhausted,
    TrivialComputation,
    UnmodeledEffect,
    UnresolvedCall,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolicSummary {
    terms: Vec<String>,
    outputs: Vec<String>,
    externs: Vec<String>,
    operations: usize,
}

impl SymbolicSummary {
    #[must_use]
    pub const fn operation_count(&self) -> usize {
        self.operations
    }

    #[must_use]
    pub const fn output_count(&self) -> usize {
        self.outputs.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct NodeId(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpToken {
    Binary(BinaryOp),
    Deposit { offset: u32, size: u32 },
    Merge,
    Piece,
    Subpiece(u32),
    Value(ValueOp),
}

impl Ord for OpToken {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl PartialOrd for OpToken {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl OpToken {
    const fn sort_key(&self) -> (u8, &'static str, u32, u32) {
        match self {
            Self::Binary(op) => (0, op.mnemonic(), 0, 0),
            Self::Deposit { offset, size } => (1, "deposit", *offset, *size),
            Self::Merge => (2, "merge", 0, 0),
            Self::Piece => (3, "piece", 0, 0),
            Self::Subpiece(offset) => (4, "subpiece", *offset, 0),
            Self::Value(op) => (5, op.mnemonic(), 0, 0),
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Binary(op) => format!("bin.{}", op.mnemonic()),
            Self::Deposit { offset, size } => format!("deposit.{offset}.{size}"),
            Self::Merge => "merge".to_owned(),
            Self::Piece => "piece".to_owned(),
            Self::Subpiece(offset) => format!("subpiece.{offset}"),
            Self::Value(op) => format!("val.{}", op.mnemonic()),
        }
    }

    const fn is_commutative(&self) -> bool {
        match self {
            Self::Binary(op) => matches!(
                op,
                BinaryOp::Add | BinaryOp::Mul | BinaryOp::And | BinaryOp::Or | BinaryOp::Xor
            ),
            Self::Merge => true,
            Self::Value(op) => matches!(
                op,
                ValueOp::IntAdd
                    | ValueOp::IntMult
                    | ValueOp::IntAnd
                    | ValueOp::IntOr
                    | ValueOp::IntXor
                    | ValueOp::IntEqual
                    | ValueOp::IntNotEqual
                    | ValueOp::BoolAnd
                    | ValueOp::BoolOr
                    | ValueOp::BoolXor
            ),
            Self::Deposit { .. } | Self::Piece | Self::Subpiece(_) => false,
        }
    }

    const fn truncation_distributes(&self) -> bool {
        match self {
            Self::Binary(op) => matches!(
                op,
                BinaryOp::Add
                    | BinaryOp::Sub
                    | BinaryOp::Mul
                    | BinaryOp::And
                    | BinaryOp::Or
                    | BinaryOp::Xor
                    | BinaryOp::Shl
                    | BinaryOp::Not
                    | BinaryOp::Neg
            ),
            Self::Value(op) => matches!(
                op,
                ValueOp::IntAdd
                    | ValueOp::IntSub
                    | ValueOp::IntMult
                    | ValueOp::IntAnd
                    | ValueOp::IntOr
                    | ValueOp::IntXor
                    | ValueOp::IntLeft
                    | ValueOp::IntNegate
            ),
            Self::Deposit { .. } | Self::Merge | Self::Piece | Self::Subpiece(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Term {
    Constant {
        value: u128,
        size: u32,
    },
    Input(ValueId),
    MemoryRead {
        address: NodeId,
        size: u32,
    },
    Opaque {
        token: String,
        size: u32,
        ordinal: u32,
    },
    Operation {
        token: OpToken,
        size: u32,
        operands: Vec<NodeId>,
    },
}

fn cell_key(cell: &ValueId) -> String {
    match cell {
        ValueId::Register(name) => format!("r:{name}"),
        ValueId::Memory(name) => format!("m:{name}"),
        ValueId::Stack(slot) => format!("s:{slot}"),
    }
}

#[derive(Debug, Default)]
struct Arena {
    terms: Vec<Term>,
    depths: Vec<u32>,
    sizes: Vec<u32>,
    content_keys: Vec<String>,
    digests: Vec<u64>,
    interned: BTreeMap<Term, NodeId>,
    decline: Option<SummaryDecline>,
}

impl Arena {
    fn content_key(&self, term: &Term) -> String {
        match term {
            Term::Constant { value, size } => format!("0|{value:x}|{size}"),
            Term::Input(cell) => format!("1|{}", cell_key(cell)),
            Term::MemoryRead { address, size } => {
                format!("2|{:016x}|{size}", self.digest_of(*address))
            }
            Term::Opaque {
                token,
                size,
                ordinal,
            } => format!("3|{token}|{size}|{ordinal}"),
            Term::Operation {
                token,
                size,
                operands,
            } => {
                let children: Vec<String> = operands
                    .iter()
                    .map(|operand: &NodeId| format!("{:016x}", self.digest_of(*operand)))
                    .collect();
                format!("4|{}|{size}|{}", token.label(), children.join(","))
            }
        }
    }

    fn intern(&mut self, term: Term) -> Option<NodeId> {
        if let Some(&existing) = self.interned.get(&term) {
            return Some(existing);
        }
        if self.terms.len() >= MAX_SUMMARY_NODES {
            self.decline = Some(SummaryDecline::NodeBudgetExhausted);
            return None;
        }
        let depth: u32 = match &term {
            Term::Constant { .. } | Term::Input(_) | Term::Opaque { .. } => 0,
            Term::MemoryRead { address, .. } => self.depth_of(*address).checked_add(1)?,
            Term::Operation { operands, .. } => operands
                .iter()
                .map(|operand: &NodeId| self.depth_of(*operand))
                .max()
                .unwrap_or(0)
                .checked_add(1)?,
        };
        if depth > MAX_SUMMARY_DEPTH {
            self.decline = Some(SummaryDecline::DepthBudgetExhausted);
            return None;
        }
        let size: u32 = match &term {
            Term::Constant { size, .. }
            | Term::MemoryRead { size, .. }
            | Term::Opaque { size, .. }
            | Term::Operation { size, .. } => *size,
            Term::Input(_) => 0,
        };
        let content_key: String = self.content_key(&term);
        let mut hasher: DefaultHasher = DefaultHasher::new();
        content_key.hash(&mut hasher);
        let digest: u64 = hasher.finish();
        let id: NodeId = NodeId(u32::try_from(self.terms.len()).ok()?);
        self.terms.push(term.clone());
        self.depths.push(depth);
        self.sizes.push(size);
        self.content_keys.push(content_key);
        self.digests.push(digest);
        self.interned.insert(term, id);
        Some(id)
    }

    fn term_of(&self, id: NodeId) -> Option<&Term> {
        self.terms.get(id.0 as usize)
    }

    fn depth_of(&self, id: NodeId) -> u32 {
        self.depths.get(id.0 as usize).copied().unwrap_or(0)
    }

    fn size_of(&self, id: NodeId) -> u32 {
        self.sizes.get(id.0 as usize).copied().unwrap_or(0)
    }

    fn digest_of(&self, id: NodeId) -> u64 {
        self.digests.get(id.0 as usize).copied().unwrap_or(0)
    }

    fn canonical_key_of(&self, id: NodeId) -> &str {
        self.content_keys
            .get(id.0 as usize)
            .map_or("", String::as_str)
    }

    fn canonical_order(&self, id: NodeId) -> (u64, String) {
        (self.digest_of(id), self.canonical_key_of(id).to_owned())
    }

    fn constant_of(&self, id: NodeId) -> Option<(u128, u32)> {
        match self.term_of(id) {
            Some(Term::Constant { value, size }) => Some((*value, *size)),
            _ => None,
        }
    }

    fn constant(&mut self, value: u128, size: u32) -> Option<NodeId> {
        self.intern(Term::Constant {
            value: mask_to_size(value, size),
            size,
        })
    }

    fn input(&mut self, cell: &ValueId) -> Option<NodeId> {
        self.intern(Term::Input(cell.clone()))
    }

    fn opaque(&mut self, token: &str, size: u32, ordinal: u32) -> Option<NodeId> {
        self.intern(Term::Opaque {
            token: token.to_owned(),
            size,
            ordinal,
        })
    }

    fn operation(&mut self, token: OpToken, size: u32, operands: Vec<NodeId>) -> Option<NodeId> {
        let mut canonical: Vec<NodeId> = operands;
        if token.is_commutative() {
            canonical.sort_by_cached_key(|operand: &NodeId| self.canonical_order(*operand));
        }
        self.intern(Term::Operation {
            token,
            size,
            operands: canonical,
        })
    }

    fn subpiece(&mut self, source: NodeId, offset: u32, size: u32) -> Option<NodeId> {
        if offset == 0 && size != 0 && self.size_of(source) == size {
            return Some(source);
        }
        if let Some((value, _)) = self.constant_of(source) {
            let shift: u32 = offset.checked_mul(8)?;
            let shifted: u128 = if shift >= 128 { 0 } else { value >> shift };
            return self.constant(shifted, size);
        }
        if offset == 0 {
            match self.term_of(source).cloned() {
                Some(Term::Operation {
                    token: OpToken::Value(ValueOp::IntZext | ValueOp::IntSext),
                    operands,
                    ..
                }) => {
                    if let Some(&inner) = operands.first() {
                        let inner_size: u32 = self.size_of(inner);
                        if inner_size == size {
                            return Some(inner);
                        }
                        if inner_size > size && inner_size != 0 {
                            return self.subpiece(inner, 0, size);
                        }
                    }
                }
                Some(Term::Operation {
                    token: OpToken::Subpiece(inner_offset),
                    operands,
                    ..
                }) => {
                    if let Some(&inner) = operands.first() {
                        return self.subpiece(inner, inner_offset, size);
                    }
                }
                Some(Term::Operation {
                    token,
                    size: operation_size,
                    operands,
                }) if token.truncation_distributes()
                    && size != 0
                    && operation_size > size
                    && !operands.is_empty() =>
                {
                    let mut truncated: Vec<NodeId> = Vec::with_capacity(operands.len());
                    for operand in operands {
                        truncated.push(self.subpiece(operand, 0, size)?);
                    }
                    return self.operation(token, size, truncated);
                }
                _ => {}
            }
        }
        if let Some(Term::Operation {
            token: OpToken::Subpiece(inner_offset),
            operands,
            ..
        }) = self.term_of(source).cloned()
            && let Some(&inner) = operands.first()
        {
            let combined: u32 = inner_offset.checked_add(offset)?;
            return self.subpiece(inner, combined, size);
        }
        self.operation(OpToken::Subpiece(offset), size, vec![source])
    }

    fn zero_extend(&mut self, source: NodeId, size: u32) -> Option<NodeId> {
        if self.size_of(source) == size && size != 0 {
            return Some(source);
        }
        if let Some((value, _)) = self.constant_of(source) {
            return self.constant(value, size);
        }
        if let Some(Term::Operation {
            token: OpToken::Value(ValueOp::IntZext),
            operands,
            ..
        }) = self.term_of(source).cloned()
            && let Some(&inner) = operands.first()
        {
            return self.operation(OpToken::Value(ValueOp::IntZext), size, vec![inner]);
        }
        self.operation(OpToken::Value(ValueOp::IntZext), size, vec![source])
    }

    fn address_form(&self, address: NodeId) -> (NodeId, i128) {
        let mut base: NodeId = address;
        let mut delta: i128 = 0;
        let mut steps: u32 = 0;
        while steps < MAX_ADDRESS_PEEL_STEPS {
            steps += 1;
            let Some(Term::Operation {
                token,
                operands,
                size,
            }) = self.term_of(base)
            else {
                break;
            };
            let additive: bool = matches!(
                token,
                OpToken::Value(ValueOp::IntAdd) | OpToken::Binary(BinaryOp::Add)
            );
            let subtractive: bool = matches!(
                token,
                OpToken::Value(ValueOp::IntSub) | OpToken::Binary(BinaryOp::Sub)
            );
            if !additive && !subtractive {
                break;
            }
            let [first, second]: [NodeId; 2] = match operands.as_slice() {
                [first, second] => [*first, *second],
                _ => break,
            };
            let width: u32 = *size;
            if subtractive {
                let Some((value, constant_size)) = self.constant_of(second) else {
                    break;
                };
                let Some(signed) = signed_value(value, pick_width(constant_size, width)) else {
                    break;
                };
                let Some(next) = delta.checked_sub(signed) else {
                    break;
                };
                delta = next;
                base = first;
                continue;
            }
            let folded: Option<(NodeId, i128)> = self
                .constant_of(second)
                .and_then(|(value, constant_size): (u128, u32)| {
                    signed_value(value, pick_width(constant_size, width))
                        .map(|signed: i128| (first, signed))
                })
                .or_else(|| {
                    self.constant_of(first)
                        .and_then(|(value, constant_size): (u128, u32)| {
                            signed_value(value, pick_width(constant_size, width))
                                .map(|signed: i128| (second, signed))
                        })
                });
            let Some((next_base, signed)) = folded else {
                break;
            };
            let Some(next) = delta.checked_add(signed) else {
                break;
            };
            delta = next;
            base = next_base;
        }
        (base, delta)
    }
}

const fn pick_width(constant_size: u32, operation_size: u32) -> u32 {
    if constant_size == 0 {
        operation_size
    } else {
        constant_size
    }
}

const fn mask_to_size(value: u128, size: u32) -> u128 {
    match size {
        0 | 16.. => value,
        _ => {
            let bits: u32 = size * 8;
            if bits >= 128 {
                value
            } else {
                value & ((1u128 << bits) - 1)
            }
        }
    }
}

fn signed_value(value: u128, size: u32) -> Option<i128> {
    if size == 0 || size > 8 {
        return i128::try_from(value).ok();
    }
    let bits: u32 = size * 8;
    let masked: u128 = mask_to_size(value, size);
    let sign_bit: u128 = 1u128 << (bits - 1);
    if masked & sign_bit == 0 {
        i128::try_from(masked).ok()
    } else {
        let modulus: u128 = 1u128 << bits;
        i128::try_from(modulus - masked)
            .map(|magnitude: i128| -magnitude)
            .ok()
    }
}

fn literal_value(text: &str) -> Option<u128> {
    let trimmed: &str = text.trim();
    let (negative, body): (bool, &str) = trimmed
        .strip_prefix('-')
        .map_or((false, trimmed), |rest: &str| (true, rest));
    let parsed: u128 =
        if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            u128::from_str_radix(hex, 16).ok()?
        } else if let Some(hex) = body.strip_suffix('h').or_else(|| body.strip_suffix('H')) {
            u128::from_str_radix(hex, 16).ok()?
        } else {
            body.parse::<u128>().ok()?
        };
    if negative {
        Some(parsed.wrapping_neg())
    } else {
        Some(parsed)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Environment {
    cells: BTreeMap<ValueId, NodeId>,
    memory: BTreeMap<(NodeId, i128, u32), NodeId>,
}

#[derive(Debug, Default)]
struct Outputs {
    returns: BTreeSet<(String, NodeId)>,
    stores: BTreeSet<(NodeId, i128, u32, NodeId)>,
    externs: BTreeMap<String, usize>,
}

struct Evaluator {
    arena: Arena,
    outputs: Outputs,
    opaque_ordinal: u32,
}

impl Evaluator {
    fn new() -> Self {
        Self {
            arena: Arena::default(),
            outputs: Outputs::default(),
            opaque_ordinal: 0,
        }
    }

    fn read(&mut self, environment: &Environment, cell: &ValueId) -> Option<NodeId> {
        match environment.cells.get(cell) {
            Some(&node) => Some(node),
            None => self.arena.input(cell),
        }
    }

    fn read_operand(&mut self, environment: &Environment, text: &str) -> Option<NodeId> {
        if let Some(value) = literal_value(text) {
            return self.arena.constant(value, 0);
        }
        let cell: ValueId = ValueId::register(text);
        self.read(environment, &cell)
    }

    const fn next_ordinal(&mut self) -> u32 {
        let ordinal: u32 = self.opaque_ordinal;
        self.opaque_ordinal = self.opaque_ordinal.saturating_add(1);
        ordinal
    }

    fn store(
        &mut self,
        environment: &mut Environment,
        address: NodeId,
        value: NodeId,
        size: u32,
    ) -> Option<()> {
        let (base, delta): (NodeId, i128) = self.arena.address_form(address);
        let span: i128 = i128::from(size.max(1));
        let end: i128 = delta.checked_add(span)?;
        environment
            .memory
            .retain(|&(entry_base, entry_delta, entry_size), _: &mut NodeId| {
                if entry_base != base {
                    return false;
                }
                let entry_span: i128 = i128::from(entry_size.max(1));
                entry_delta
                    .checked_add(entry_span)
                    .is_some_and(|entry_end: i128| entry_end <= delta || end <= entry_delta)
            });
        if environment.memory.len() >= MAX_SUMMARY_MEMORY_CELLS {
            self.arena.decline = Some(SummaryDecline::MemoryCellBudgetExhausted);
            return None;
        }
        environment.memory.insert((base, delta, size), value);
        Some(())
    }

    fn load(&mut self, environment: &Environment, address: NodeId, size: u32) -> Option<NodeId> {
        let (base, delta): (NodeId, i128) = self.arena.address_form(address);
        match environment.memory.get(&(base, delta, size)) {
            Some(&value) => Some(value),
            None => self.arena.intern(Term::MemoryRead { address, size }),
        }
    }

    fn invalidate_memory(environment: &mut Environment) {
        environment.memory.clear();
    }

    fn define(environment: &mut Environment, cell: &ValueId, value: NodeId) {
        environment.cells.insert(cell.clone(), value);
    }

    fn clobber(&mut self, environment: &mut Environment, cell: &ValueId, size: u32) -> Option<()> {
        let ordinal: u32 = self.next_ordinal();
        let node: NodeId = self.arena.opaque(cell.label(), size, ordinal)?;
        Self::define(environment, cell, node);
        Some(())
    }

    fn apply(&mut self, environment: &mut Environment, instruction: &NirInstr) -> Option<()> {
        match &instruction.op {
            NirOp::Nop | NirOp::Branch { .. } | NirOp::CondBranch { .. } => Some(()),
            NirOp::Return => self.capture_return(environment, instruction),
            NirOp::Copy { src, size } => {
                let value: NodeId = self.read_operand(environment, src)?;
                let sized: NodeId = self.resize(value, *size)?;
                Self::define_first_operand(environment, instruction, sized)
            }
            NirOp::Subpiece { src, offset, size } => {
                let source: NodeId = self.read_operand(environment, src)?;
                let value: NodeId = self.arena.subpiece(source, *offset, *size)?;
                Self::define_first_operand(environment, instruction, value)
            }
            NirOp::Deposit {
                cell,
                value,
                offset,
                size,
                cell_size,
                zero_upper,
            } => {
                let inserted: NodeId = self.read_operand(environment, value)?;
                let target: ValueId = ValueId::register(cell);
                let combined: NodeId = if *zero_upper && *offset == 0 {
                    self.arena.zero_extend(inserted, *cell_size)?
                } else if *offset == 0 && *size == *cell_size {
                    inserted
                } else {
                    let previous: NodeId = self.read(environment, &target)?;
                    self.arena.operation(
                        OpToken::Deposit {
                            offset: *offset,
                            size: *size,
                        },
                        *cell_size,
                        vec![previous, inserted],
                    )?
                };
                Self::define(environment, &target, combined);
                Some(())
            }
            NirOp::RawLoad { addr, size } => {
                let address: NodeId = self.read_operand(environment, addr)?;
                let value: NodeId = self.load(environment, address, *size)?;
                Self::define_first_operand(environment, instruction, value)
            }
            NirOp::RawStore { addr, value, size } => {
                let address: NodeId = self.read_operand(environment, addr)?;
                let stored: NodeId = self.read_operand(environment, value)?;
                self.record_escaping_store(address, stored, *size)?;
                self.store(environment, address, stored, *size)
            }
            NirOp::Value {
                op,
                inputs,
                input_sizes,
                size,
            } => {
                let mut operands: Vec<NodeId> = Vec::with_capacity(inputs.len());
                for (index, input) in inputs.iter().enumerate() {
                    let declared: u32 = input_sizes.get(index).copied().unwrap_or(0);
                    let node: NodeId = self.read_typed_operand(environment, input, declared)?;
                    operands.push(node);
                }
                let value: NodeId = self.arena.operation(OpToken::Value(*op), *size, operands)?;
                Self::define_first_operand(environment, instruction, value)
            }
            NirOp::Piece {
                high,
                low,
                high_size,
                low_size,
                size,
            } => {
                let high_node: NodeId = self.read_typed_operand(environment, high, *high_size)?;
                let low_node: NodeId = self.read_typed_operand(environment, low, *low_size)?;
                let value: NodeId =
                    self.arena
                        .operation(OpToken::Piece, *size, vec![high_node, low_node])?;
                Self::define_first_operand(environment, instruction, value)
            }
            NirOp::BinOp { op } => self.apply_binary(environment, instruction, *op),
            NirOp::Const => self.apply_constant(environment, instruction),
            NirOp::Load | NirOp::Store => self.apply_opaque_memory(environment, instruction),
            NirOp::ExternCall { symbol } => {
                self.apply_extern_call(environment, instruction, symbol)
            }
            NirOp::CallOther { effect } => {
                for write in &effect.writes {
                    let cell: ValueId = ValueId::register(write);
                    self.clobber(environment, &cell, 0)?;
                }
                if effect.unknown_registers || effect.writes_memory {
                    Self::invalidate_memory(environment);
                }
                Some(())
            }
            NirOp::Call { .. }
            | NirOp::IndirectCall
            | NirOp::NoReturnCall { .. }
            | NirOp::TailCall { .. }
            | NirOp::Interrupt
            | NirOp::Phi
            | NirOp::Unmodeled { .. } => {
                self.arena.decline = Some(SummaryDecline::UnresolvedCall);
                None
            }
        }
    }

    fn resize(&mut self, value: NodeId, size: u32) -> Option<NodeId> {
        let current: u32 = self.arena.size_of(value);
        if size == 0 || current == size {
            return Some(value);
        }
        if current == 0 || current < size {
            return Some(value);
        }
        self.arena.subpiece(value, 0, size)
    }

    fn read_typed_operand(
        &mut self,
        environment: &Environment,
        text: &str,
        size: u32,
    ) -> Option<NodeId> {
        if let Some(value) = literal_value(text) {
            return self.arena.constant(value, size);
        }
        let cell: ValueId = ValueId::register(text);
        self.read(environment, &cell)
    }

    fn define_first_operand(
        environment: &mut Environment,
        instruction: &NirInstr,
        value: NodeId,
    ) -> Option<()> {
        let destination: &String = instruction.operands.first()?;
        let cell: ValueId = ValueId::register(destination);
        Self::define(environment, &cell, value);
        Some(())
    }

    fn apply_binary(
        &mut self,
        environment: &mut Environment,
        instruction: &NirInstr,
        op: BinaryOp,
    ) -> Option<()> {
        let mut operands: Vec<NodeId> = Vec::with_capacity(instruction.operands.len());
        for operand in &instruction.operands {
            operands.push(self.read_operand(environment, operand)?);
        }
        if operands.is_empty() {
            return Some(());
        }
        let value: NodeId = self.arena.operation(OpToken::Binary(op), 0, operands)?;
        Self::define_first_operand(environment, instruction, value)
    }

    fn apply_constant(
        &mut self,
        environment: &mut Environment,
        instruction: &NirInstr,
    ) -> Option<()> {
        let literal: Option<u128> = instruction
            .operands
            .get(1)
            .and_then(|text: &String| literal_value(text));
        let value: NodeId = if let Some(number) = literal {
            self.arena.constant(number, 0)?
        } else {
            let ordinal: u32 = self.next_ordinal();
            self.arena.opaque("const", 0, ordinal)?
        };
        Self::define_first_operand(environment, instruction, value)
    }

    fn apply_opaque_memory(
        &mut self,
        environment: &mut Environment,
        instruction: &NirInstr,
    ) -> Option<()> {
        let effects: DefUse = def_use(instruction);
        let address_cell: Option<ValueId> = effects
            .defs
            .iter()
            .chain(effects.uses.iter())
            .find(|value: &&ValueId| matches!(value, ValueId::Memory(_)))
            .cloned();
        let Some(ValueId::Memory(text)) = address_cell else {
            return Some(());
        };
        let address: NodeId = self.arena.opaque(&text, 0, 0)?;
        if instruction.writes_memory {
            let source: Option<String> = instruction.operands.get(1).cloned();
            let stored: NodeId = if let Some(operand) = source {
                self.read_operand(environment, &operand)?
            } else {
                let ordinal: u32 = self.next_ordinal();
                self.arena.opaque("store", 0, ordinal)?
            };
            self.record_escaping_store(address, stored, 0)?;
            return self.store(environment, address, stored, 0);
        }
        let value: NodeId = self.load(environment, address, 0)?;
        Self::define_first_operand(environment, instruction, value)
    }

    fn apply_extern_call(
        &mut self,
        environment: &mut Environment,
        instruction: &NirInstr,
        symbol: &str,
    ) -> Option<()> {
        let seen: &mut usize = self.outputs.externs.entry(symbol.to_owned()).or_default();
        *seen += 1;
        let ordinal: u32 = u32::try_from(*seen).unwrap_or(u32::MAX);
        let effects: DefUse = def_use(instruction);
        for def in &effects.defs {
            let node: NodeId = self.arena.opaque(symbol, 0, ordinal)?;
            Self::define(environment, def, node);
        }
        Self::invalidate_memory(environment);
        Some(())
    }

    fn record_escaping_store(&mut self, address: NodeId, value: NodeId, size: u32) -> Option<()> {
        let (base, delta): (NodeId, i128) = self.arena.address_form(address);
        let frame_local: bool = matches!(
            self.arena.term_of(base),
            Some(Term::Input(ValueId::Register(name))) if name == "rsp" || name == "rbp"
        );
        if frame_local {
            return Some(());
        }
        if self.outputs.stores.len() >= MAX_SUMMARY_OUTPUTS {
            self.arena.decline = Some(SummaryDecline::OutputBudgetExhausted);
            return None;
        }
        self.outputs.stores.insert((base, delta, size, value));
        Some(())
    }

    fn capture_return(&mut self, environment: &Environment, instruction: &NirInstr) -> Option<()> {
        let declared: Vec<ValueId> = return_cells(instruction);
        for cell in &declared {
            let value: NodeId = self.read(environment, cell)?;
            if self.outputs.returns.len() >= MAX_SUMMARY_OUTPUTS {
                self.arena.decline = Some(SummaryDecline::OutputBudgetExhausted);
                return None;
            }
            self.outputs
                .returns
                .insert((cell.label().to_owned(), value));
        }
        Some(())
    }
}

fn return_cells(instruction: &NirInstr) -> Vec<ValueId> {
    if let Some(text) = instruction.operands.first() {
        return vec![ValueId::register(text)];
    }
    let effects: DefUse = def_use(instruction);
    let unique: BTreeSet<ValueId> = effects.uses.into_iter().collect();
    unique.into_iter().collect()
}

fn has_unmodeled_effect(function: &NirFunction) -> bool {
    function
        .instructions
        .iter()
        .any(|instruction: &NirInstr| match &instruction.op {
            NirOp::Unmodeled { .. } | NirOp::Interrupt | NirOp::Phi => true,
            NirOp::Nop => !instruction.operands.is_empty(),
            _ => false,
        })
}

fn has_unresolved_call(function: &NirFunction) -> bool {
    function.instructions.iter().any(|instruction: &NirInstr| {
        matches!(
            instruction.op,
            NirOp::Call { .. }
                | NirOp::IndirectCall
                | NirOp::NoReturnCall { .. }
                | NirOp::TailCall { .. }
        )
    })
}

fn block_order(blocks: &[NirBlock]) -> Option<Vec<usize>> {
    let index_of: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block): (usize, &NirBlock)| (block.start, index))
        .collect();
    let mut successors: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); blocks.len()];
    let mut predecessors: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        for target in &block.successors {
            if let Some(&successor) = index_of.get(target) {
                successors[index].insert(successor);
                predecessors[successor].insert(index);
            }
        }
    }
    let mut reachable: BTreeSet<usize> = BTreeSet::new();
    let mut frontier: Vec<usize> = vec![0];
    while let Some(current) = frontier.pop() {
        if !reachable.insert(current) {
            continue;
        }
        for &successor in &successors[current] {
            frontier.push(successor);
        }
    }
    let mut pending: BTreeMap<usize, usize> = reachable
        .iter()
        .map(|&index: &usize| {
            let count: usize = predecessors[index]
                .iter()
                .filter(|candidate: &&usize| reachable.contains(candidate))
                .count();
            (index, count)
        })
        .collect();
    let mut ready: BTreeSet<usize> = pending
        .iter()
        .filter_map(|(&index, &count): (&usize, &usize)| (count == 0).then_some(index))
        .collect();
    let mut order: Vec<usize> = Vec::with_capacity(reachable.len());
    while let Some(&next) = ready.iter().next() {
        ready.remove(&next);
        pending.remove(&next);
        order.push(next);
        for &successor in &successors[next] {
            let Some(count) = pending.get_mut(&successor) else {
                continue;
            };
            *count = count.saturating_sub(1);
            if *count == 0 {
                ready.insert(successor);
            }
        }
    }
    (order.len() == reachable.len()).then_some(order)
}

fn merge_environments(evaluator: &mut Evaluator, incoming: &[&Environment]) -> Option<Environment> {
    if let [only] = incoming {
        return Some((*only).clone());
    }
    let mut cells: BTreeMap<ValueId, NodeId> = BTreeMap::new();
    let keys: BTreeSet<ValueId> = incoming
        .iter()
        .flat_map(|environment: &&Environment| environment.cells.keys().cloned())
        .collect();
    for key in keys {
        let mut values: BTreeSet<NodeId> = BTreeSet::new();
        for environment in incoming {
            let value: NodeId = match environment.cells.get(&key) {
                Some(&node) => node,
                None => evaluator.arena.input(&key)?,
            };
            values.insert(value);
        }
        let merged: NodeId = if values.len() == 1 {
            *values.iter().next()?
        } else {
            evaluator.arena.operation(
                OpToken::Merge,
                0,
                values.into_iter().collect::<Vec<NodeId>>(),
            )?
        };
        cells.insert(key, merged);
    }
    let memory: BTreeMap<(NodeId, i128, u32), NodeId> = incoming
        .first()
        .map(|environment: &&Environment| environment.memory.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, value): &((NodeId, i128, u32), NodeId)| {
            incoming
                .iter()
                .all(|environment: &&Environment| environment.memory.get(key) == Some(value))
        })
        .collect();
    Some(Environment { cells, memory })
}

fn render(
    arena: &Arena,
    roots: &[NodeId],
) -> Option<(Vec<String>, BTreeMap<NodeId, usize>, usize)> {
    let mut reachable: BTreeSet<NodeId> = BTreeSet::new();
    let mut frontier: Vec<NodeId> = roots.to_vec();
    while let Some(node) = frontier.pop() {
        if !reachable.insert(node) {
            continue;
        }
        match arena.term_of(node)? {
            Term::MemoryRead { address, .. } => frontier.push(*address),
            Term::Operation { operands, .. } => frontier.extend(operands.iter().copied()),
            Term::Constant { .. } | Term::Input(_) | Term::Opaque { .. } => {}
        }
    }
    let mut ordered: Vec<NodeId> = reachable.into_iter().collect();
    ordered.sort_by_cached_key(|node: &NodeId| {
        (
            arena.depth_of(*node),
            arena.digest_of(*node),
            arena.canonical_key_of(*node).to_owned(),
        )
    });

    let mut assigned: BTreeMap<NodeId, usize> = BTreeMap::new();
    for (position, node) in ordered.iter().enumerate() {
        assigned.insert(*node, position);
    }

    let mut lines: Vec<String> = Vec::with_capacity(ordered.len());
    let mut operations: usize = 0;
    for node in &ordered {
        let line: String = match arena.term_of(*node)? {
            Term::Constant { value, size } => format!("const {value:#x}:{size}"),
            Term::Input(cell) => format!("in {}", cell_key(cell)),
            Term::MemoryRead { address, size } => {
                format!("read #{}:{size}", assigned.get(address).copied()?)
            }
            Term::Opaque {
                token,
                size,
                ordinal,
            } => format!("opaque {token}:{size}#{ordinal}"),
            Term::Operation {
                token,
                size,
                operands,
            } => {
                operations += 1;
                let rendered: Vec<String> = operands
                    .iter()
                    .map(|operand: &NodeId| {
                        assigned
                            .get(operand)
                            .copied()
                            .map(|index: usize| format!("#{index}"))
                    })
                    .collect::<Option<Vec<String>>>()?;
                format!("{}:{size} {}", token.label(), rendered.join(","))
            }
        };
        lines.push(line);
    }
    Some((lines, assigned, operations))
}

pub fn symbolic_summary(function: &NirFunction) -> Result<SymbolicSummary, SummaryDecline> {
    if function.instructions.len() > MAX_SUMMARY_INSTRUCTIONS {
        return Err(SummaryDecline::InstructionCountExceeded);
    }
    if has_unresolved_call(function) {
        return Err(SummaryDecline::UnresolvedCall);
    }
    if has_unmodeled_effect(function) {
        return Err(SummaryDecline::UnmodeledEffect);
    }
    let blocks: Vec<NirBlock> = basic_blocks(function);
    if blocks.is_empty() {
        return Err(SummaryDecline::NoObservableOutput);
    }
    if blocks.len() > MAX_SUMMARY_BLOCKS {
        return Err(SummaryDecline::BlockCountExceeded);
    }
    let order: Vec<usize> = block_order(&blocks).ok_or(SummaryDecline::CyclicControlFlow)?;

    let index_of: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block): (usize, &NirBlock)| (block.start, index))
        .collect();
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        for target in &block.successors {
            if let Some(&successor) = index_of.get(target)
                && successor != index
            {
                predecessors[successor].push(index);
            }
        }
    }

    let mut evaluator: Evaluator = Evaluator::new();
    let mut exits: BTreeMap<usize, Environment> = BTreeMap::new();
    for &index in &order {
        let incoming: Vec<&Environment> = predecessors
            .get(index)
            .map(|list: &Vec<usize>| {
                list.iter()
                    .filter_map(|candidate: &usize| exits.get(candidate))
                    .collect()
            })
            .unwrap_or_default();
        let mut environment: Environment = if incoming.is_empty() {
            Environment::default()
        } else {
            merge_environments(&mut evaluator, &incoming).ok_or_else(|| {
                evaluator
                    .arena
                    .decline
                    .unwrap_or(SummaryDecline::NodeBudgetExhausted)
            })?
        };
        let Some(block): Option<&NirBlock> = blocks.get(index) else {
            return Err(SummaryDecline::NoObservableOutput);
        };
        for instruction in &block.instructions {
            if evaluator.apply(&mut environment, instruction).is_none() {
                return Err(evaluator
                    .arena
                    .decline
                    .unwrap_or(SummaryDecline::UnmodeledEffect));
            }
        }
        exits.insert(index, environment);
    }

    let mut roots: Vec<NodeId> = Vec::new();
    for &(_, node) in &evaluator.outputs.returns {
        roots.push(node);
    }
    for &(base, _, _, value) in &evaluator.outputs.stores {
        roots.push(base);
        roots.push(value);
    }
    if roots.is_empty() {
        return Err(SummaryDecline::NoObservableOutput);
    }

    let (terms, assigned, operations): (Vec<String>, BTreeMap<NodeId, usize>, usize) =
        render(&evaluator.arena, &roots).ok_or(SummaryDecline::NodeBudgetExhausted)?;
    if operations < MIN_SUMMARY_OPERATIONS {
        return Err(SummaryDecline::TrivialComputation);
    }

    let mut outputs: Vec<String> = Vec::new();
    for (cell, node) in &evaluator.outputs.returns {
        let index: usize = assigned
            .get(node)
            .copied()
            .ok_or(SummaryDecline::NoObservableOutput)?;
        outputs.push(format!("ret {cell}=#{index}"));
    }
    for (base, delta, size, value) in &evaluator.outputs.stores {
        let base_index: usize = assigned
            .get(base)
            .copied()
            .ok_or(SummaryDecline::NoObservableOutput)?;
        let value_index: usize = assigned
            .get(value)
            .copied()
            .ok_or(SummaryDecline::NoObservableOutput)?;
        outputs.push(format!(
            "store #{base_index}{delta:+}:{size}=#{value_index}"
        ));
    }
    outputs.sort_unstable();

    let externs: Vec<String> = evaluator
        .outputs
        .externs
        .iter()
        .map(|(symbol, count): (&String, &usize)| format!("{symbol}x{count}"))
        .collect();

    Ok(SymbolicSummary {
        terms,
        outputs,
        externs,
        operations,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::structural::{Indeterminate, MatchTier, StructuralMatchReport, structural_match};
    use disrobe_nir::{NirModule, SourceLang, SourceRef};

    fn pcode(address: u64, op: NirOp, operands: &[&str]) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: String::new(),
            operands: operands
                .iter()
                .map(|text: &&str| (*text).to_owned())
                .collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn value(op: ValueOp, inputs: &[&str], input_sizes: &[u32], size: u32) -> NirOp {
        NirOp::Value {
            op,
            inputs: inputs
                .iter()
                .map(|text: &&str| (*text).to_owned())
                .collect(),
            input_sizes: input_sizes.to_vec(),
            size,
        }
    }

    fn deposit_rax(address: u64, source: &str, size: u32) -> NirInstr {
        pcode(
            address,
            NirOp::Deposit {
                cell: "rax".to_owned(),
                value: source.to_owned(),
                offset: 0,
                size,
                cell_size: 8,
                zero_upper: true,
            },
            &[],
        )
    }

    fn function(name: &str, address: u64, instructions: Vec<NirInstr>) -> NirFunction {
        let end: u64 = address + instructions.len() as u64;
        NirFunction {
            name: name.to_owned(),
            address,
            end,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn module_of(functions: Vec<NirFunction>) -> NirModule {
        NirModule {
            source_hash: [0u8; 32],
            lang: SourceLang::NativeX86,
            functions,
            symbols: Vec::new(),
        }
    }

    fn wide_add_then_truncate(address: u64) -> NirFunction {
        function(
            "wide",
            address,
            vec![
                pcode(
                    address,
                    value(ValueOp::IntAdd, &["rcx", "rdx"], &[8, 8], 8),
                    &["t0"],
                ),
                pcode(
                    address + 1,
                    NirOp::Subpiece {
                        src: "t0".to_owned(),
                        offset: 0,
                        size: 4,
                    },
                    &["t1"],
                ),
                pcode(
                    address + 2,
                    NirOp::Copy {
                        src: "t1".to_owned(),
                        size: 4,
                    },
                    &["t2"],
                ),
                deposit_rax(address + 3, "t2", 4),
                pcode(address + 4, NirOp::Return, &["rax"]),
            ],
        )
    }

    fn narrow_add_through_the_frame(address: u64) -> NirFunction {
        function(
            "narrow",
            address,
            vec![
                pcode(
                    address,
                    value(ValueOp::IntAdd, &["rbp", "0x10"], &[8, 8], 8),
                    &["s0"],
                ),
                pcode(
                    address + 1,
                    NirOp::Subpiece {
                        src: "rcx".to_owned(),
                        offset: 0,
                        size: 4,
                    },
                    &["s1"],
                ),
                pcode(
                    address + 2,
                    NirOp::RawStore {
                        addr: "s0".to_owned(),
                        value: "s1".to_owned(),
                        size: 4,
                    },
                    &[],
                ),
                pcode(
                    address + 3,
                    value(ValueOp::IntAdd, &["rbp", "0x18"], &[8, 8], 8),
                    &["s2"],
                ),
                pcode(
                    address + 4,
                    NirOp::Subpiece {
                        src: "rdx".to_owned(),
                        offset: 0,
                        size: 4,
                    },
                    &["s3"],
                ),
                pcode(
                    address + 5,
                    NirOp::RawStore {
                        addr: "s2".to_owned(),
                        value: "s3".to_owned(),
                        size: 4,
                    },
                    &[],
                ),
                pcode(
                    address + 6,
                    NirOp::RawLoad {
                        addr: "s2".to_owned(),
                        size: 4,
                    },
                    &["s4"],
                ),
                pcode(
                    address + 7,
                    NirOp::RawLoad {
                        addr: "s0".to_owned(),
                        size: 4,
                    },
                    &["s5"],
                ),
                pcode(
                    address + 8,
                    value(ValueOp::IntAdd, &["s4", "s5"], &[4, 4], 4),
                    &["s6"],
                ),
                deposit_rax(address + 9, "s6", 4),
                pcode(address + 10, NirOp::Return, &["rax"]),
            ],
        )
    }

    #[test]
    fn a_wide_add_and_a_frame_spilled_narrow_add_share_one_summary() {
        let wide: SymbolicSummary =
            symbolic_summary(&wide_add_then_truncate(0x1000)).expect("wide summary");
        let narrow: SymbolicSummary =
            symbolic_summary(&narrow_add_through_the_frame(0x2000)).expect("narrow summary");
        assert_eq!(
            wide, narrow,
            "truncation distribution, copy folding, deposit folding and frame memory resolution must converge on one key"
        );
        assert!(wide.operation_count() >= MIN_SUMMARY_OPERATIONS);
    }

    #[test]
    fn commutative_operand_order_does_not_change_the_summary() {
        let forward: NirFunction = wide_add_then_truncate(0x1000);
        let mut reversed: NirFunction = wide_add_then_truncate(0x3000);
        reversed.instructions[0].op = value(ValueOp::IntAdd, &["rdx", "rcx"], &[8, 8], 8);
        assert_eq!(
            symbolic_summary(&forward).expect("forward"),
            symbolic_summary(&reversed).expect("reversed")
        );
    }

    #[test]
    fn a_different_operator_does_not_share_a_summary() {
        let add: NirFunction = wide_add_then_truncate(0x1000);
        let mut subtract: NirFunction = wide_add_then_truncate(0x3000);
        subtract.instructions[0].op = value(ValueOp::IntSub, &["rcx", "rdx"], &[8, 8], 8);
        assert_ne!(
            symbolic_summary(&add).expect("add"),
            symbolic_summary(&subtract).expect("subtract")
        );
    }

    #[test]
    fn truncation_does_not_distribute_through_a_right_shift() {
        let mut wide_shift: NirFunction = wide_add_then_truncate(0x1000);
        wide_shift.instructions[0].op = value(ValueOp::IntRight, &["rcx", "rdx"], &[8, 8], 8);
        let mut narrow_shift: NirFunction = wide_add_then_truncate(0x2000);
        narrow_shift.instructions[0].op = value(ValueOp::IntRight, &["rcx", "rdx"], &[8, 8], 4);
        narrow_shift.instructions[1].op = NirOp::Copy {
            src: "t0".to_owned(),
            size: 4,
        };
        assert_ne!(
            symbolic_summary(&wide_shift).expect("wide shift"),
            symbolic_summary(&narrow_shift).expect("narrow shift"),
            "a right shift is not width homomorphic, so truncation must not be pushed through it"
        );
    }

    #[test]
    fn a_pass_through_function_declines_as_trivial() {
        let trivial: NirFunction = function(
            "passthrough",
            0x1000,
            vec![
                pcode(
                    0x1000,
                    NirOp::Copy {
                        src: "rcx".to_owned(),
                        size: 8,
                    },
                    &["rax"],
                ),
                pcode(0x1001, NirOp::Return, &["rax"]),
            ],
        );
        assert_eq!(
            symbolic_summary(&trivial),
            Err(SummaryDecline::TrivialComputation)
        );
    }

    #[test]
    fn an_instruction_with_an_unmodeled_effect_declines() {
        let mut unmodeled: NirFunction = wide_add_then_truncate(0x1000);
        unmodeled
            .instructions
            .insert(1, pcode(0x1001, NirOp::Nop, &["rax", "rcx"]));
        assert_eq!(
            symbolic_summary(&unmodeled),
            Err(SummaryDecline::UnmodeledEffect)
        );
    }

    #[test]
    fn an_internal_call_declines_rather_than_guessing_a_callee_result() {
        let mut calling: NirFunction = wide_add_then_truncate(0x1000);
        calling.instructions.insert(
            1,
            pcode(
                0x1001,
                NirOp::Call {
                    target: Some(0x9000),
                },
                &[],
            ),
        );
        assert_eq!(
            symbolic_summary(&calling),
            Err(SummaryDecline::UnresolvedCall)
        );
    }

    #[test]
    fn a_loop_declines_as_cyclic_control_flow() {
        let cyclic: NirFunction = function(
            "loop",
            0x1000,
            vec![
                pcode(
                    0x1000,
                    value(ValueOp::IntAdd, &["rcx", "rdx"], &[8, 8], 8),
                    &["t0"],
                ),
                pcode(
                    0x1001,
                    NirOp::CondBranch {
                        target: Some(0x1000),
                    },
                    &["t0"],
                ),
                deposit_rax(0x1002, "t0", 4),
                pcode(0x1003, NirOp::Return, &["rax"]),
            ],
        );
        assert_eq!(
            symbolic_summary(&cyclic),
            Err(SummaryDecline::CyclicControlFlow)
        );
    }

    #[test]
    fn a_function_over_the_instruction_budget_declines_and_the_report_records_the_fallback() {
        let mut instructions: Vec<NirInstr> = Vec::new();
        for index in 0..=MAX_SUMMARY_INSTRUCTIONS {
            instructions.push(pcode(
                0x1000 + index as u64,
                value(ValueOp::IntAdd, &["rcx", "rdx"], &[8, 8], 8),
                &["t0"],
            ));
        }
        let oversized: NirFunction = function("oversized", 0x1000, instructions);
        assert_eq!(
            symbolic_summary(&oversized),
            Err(SummaryDecline::InstructionCountExceeded)
        );
        let base: NirModule = module_of(vec![oversized]);
        let other: NirModule = base.clone();
        let report: StructuralMatchReport = structural_match(&base, &other);
        assert_eq!(
            report.summary_decline_base(0x1000),
            Some(SummaryDecline::InstructionCountExceeded),
            "the report must record why the summary tier declined an over-budget function"
        );
        assert_eq!(
            report.matched_tier(0x1000),
            Some(MatchTier::LeafExact),
            "an over-budget function must still fall back to the structural tier"
        );
    }

    #[test]
    fn a_deep_expression_chain_declines_on_the_depth_budget() {
        let mut instructions: Vec<NirInstr> = vec![pcode(
            0x1000,
            value(ValueOp::IntAdd, &["rcx", "rdx"], &[8, 8], 8),
            &["t0"],
        )];
        let last_step: u32 = MAX_SUMMARY_DEPTH + 40;
        for step in 1..=last_step {
            let previous: String = format!("t{}", step - 1);
            let current: String = format!("t{step}");
            instructions.push(pcode(
                0x1000 + u64::from(step),
                value(ValueOp::IntAdd, &[previous.as_str(), "rsi"], &[8, 8], 8),
                &[current.as_str()],
            ));
        }
        let last: String = format!("t{last_step}");
        instructions.push(deposit_rax(0x8000, last.as_str(), 8));
        instructions.push(pcode(0x8001, NirOp::Return, &["rax"]));
        let deep: NirFunction = function("deep", 0x1000, instructions);
        assert_eq!(
            symbolic_summary(&deep),
            Err(SummaryDecline::DepthBudgetExhausted)
        );
    }

    #[test]
    fn a_wide_expression_declines_on_the_node_budget() {
        let mut instructions: Vec<NirInstr> = Vec::new();
        for index in 0..(MAX_SUMMARY_NODES / 2 + 32) {
            let constant: String = format!("0x{index:x}");
            instructions.push(pcode(
                0x1000 + index as u64,
                value(ValueOp::IntAdd, &["rcx", constant.as_str()], &[8, 8], 8),
                &["t0"],
            ));
        }
        instructions.push(deposit_rax(0x9000, "t0", 8));
        instructions.push(pcode(0x9001, NirOp::Return, &["rax"]));
        let wide: NirFunction = function("wide", 0x1000, instructions);
        assert_eq!(
            symbolic_summary(&wide),
            Err(SummaryDecline::NodeBudgetExhausted)
        );
    }

    #[test]
    fn a_partly_overlapping_frame_store_does_not_resolve_a_stale_value() {
        let overlapping: NirFunction = function(
            "overlap",
            0x1000,
            vec![
                pcode(
                    0x1000,
                    value(ValueOp::IntAdd, &["rbp", "0x10"], &[8, 8], 8),
                    &["s0"],
                ),
                pcode(
                    0x1001,
                    NirOp::RawStore {
                        addr: "s0".to_owned(),
                        value: "rcx".to_owned(),
                        size: 8,
                    },
                    &[],
                ),
                pcode(
                    0x1002,
                    value(ValueOp::IntAdd, &["rbp", "0x14"], &[8, 8], 8),
                    &["s1"],
                ),
                pcode(
                    0x1003,
                    NirOp::RawStore {
                        addr: "s1".to_owned(),
                        value: "rdx".to_owned(),
                        size: 4,
                    },
                    &[],
                ),
                pcode(
                    0x1004,
                    NirOp::RawLoad {
                        addr: "s0".to_owned(),
                        size: 8,
                    },
                    &["s2"],
                ),
                pcode(
                    0x1005,
                    value(ValueOp::IntAdd, &["s2", "rsi"], &[8, 8], 8),
                    &["s3"],
                ),
                deposit_rax(0x1006, "s3", 8),
                pcode(0x1007, NirOp::Return, &["rax"]),
            ],
        );
        let summary: SymbolicSummary = symbolic_summary(&overlapping).expect("overlap summary");
        assert!(
            summary
                .terms
                .iter()
                .any(|term: &String| term.starts_with("read ")),
            "a store that partly overwrites an earlier slot must force a symbolic memory read instead of reusing the stale value: {:?}",
            summary.terms
        );
    }

    #[test]
    fn two_functions_with_one_summary_resolve_to_ambiguous_rather_than_a_guess() {
        let base: NirModule = module_of(vec![
            wide_add_then_truncate(0x1000),
            narrow_add_through_the_frame(0x2000),
        ]);
        let other: NirModule = module_of(vec![
            wide_add_then_truncate(0x8000),
            narrow_add_through_the_frame(0x9000),
        ]);
        let report: StructuralMatchReport = structural_match(&base, &other);
        assert!(
            report
                .matches
                .iter()
                .all(|pair: &crate::StructuralPair| pair.tier != MatchTier::SymbolicSummary),
            "the summary tier must not commit a pair when two candidates share one summary"
        );
        assert!(
            report
                .unmatched_base
                .iter()
                .all(|&(_, reason): &(u64, Indeterminate)| matches!(
                    reason,
                    Indeterminate::Ambiguous { .. }
                )),
            "an indistinguishable summary must be reported ambiguous: {:?}",
            report.unmatched_base
        );
    }

    #[test]
    fn an_escaping_store_is_an_output_and_a_frame_store_is_not() {
        let frame_only: NirFunction = narrow_add_through_the_frame(0x1000);
        let frame_summary: SymbolicSummary = symbolic_summary(&frame_only).expect("frame summary");
        let mut escaping: NirFunction = narrow_add_through_the_frame(0x2000);
        escaping.instructions[0].op = value(ValueOp::IntAdd, &["r9", "0x10"], &[8, 8], 8);
        escaping.instructions[3].op = value(ValueOp::IntAdd, &["r9", "0x18"], &[8, 8], 8);
        let escaping_summary: SymbolicSummary =
            symbolic_summary(&escaping).expect("escaping summary");
        assert_eq!(frame_summary.output_count(), 1);
        assert!(
            escaping_summary.output_count() > frame_summary.output_count(),
            "a store through a non-frame pointer must appear as an observable output"
        );
    }

    #[test]
    fn swapping_two_escaping_store_destinations_changes_the_summary() {
        let mut forward: NirFunction = narrow_add_through_the_frame(0x2000);
        forward.instructions[0].op = value(ValueOp::IntAdd, &["r9", "0x10"], &[8, 8], 8);
        forward.instructions[3].op = value(ValueOp::IntAdd, &["r9", "0x18"], &[8, 8], 8);
        let mut swapped: NirFunction = narrow_add_through_the_frame(0x3000);
        swapped.instructions[0].op = value(ValueOp::IntAdd, &["r9", "0x18"], &[8, 8], 8);
        swapped.instructions[3].op = value(ValueOp::IntAdd, &["r9", "0x10"], &[8, 8], 8);
        assert_ne!(
            symbolic_summary(&forward).expect("forward stores"),
            symbolic_summary(&swapped).expect("swapped stores"),
            "two functions that write the same values to swapped offsets of one pointer must not share a summary"
        );
    }

    #[test]
    fn literal_parsing_covers_both_operand_spellings() {
        assert_eq!(literal_value("0x18"), Some(0x18));
        assert_eq!(literal_value("18h"), Some(0x18));
        assert_eq!(literal_value("24"), Some(24));
        assert_eq!(literal_value("-8"), Some(8u128.wrapping_neg()));
        assert_eq!(literal_value("rax"), None);
        assert_eq!(literal_value("[rbp+10h]"), None);
    }

    #[test]
    fn signed_value_sign_extends_within_the_declared_width() {
        assert_eq!(signed_value(0xffff_fff8, 4), Some(-8));
        assert_eq!(signed_value(0x18, 8), Some(0x18));
        assert_eq!(signed_value(0xf8, 1), Some(-8));
    }
}
