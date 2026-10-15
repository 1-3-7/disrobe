use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::rc::Rc;

use sha3::{Digest, Keccak256};

use crate::disasm::{JumpDests, push_value};
use crate::expr::{
    BinOp, CdLoc, Env, Expr, TernOp, UnOp, Val, affine, as_const, bin, konst, node, tern, un,
};
use crate::memory::Memory;
use crate::opcode::{self, JUMPDEST};
use crate::u256::U256;

const STACK_LIMIT: usize = 1024;
const MAX_HEAD_WORDS: u64 = 4096;
const MAX_JUMPDEST_VISITS: u16 = 256;
const MAX_SYMBOLIC_FORKS: u16 = 2;
const MAX_KECCAK_BYTES: u64 = 4096;
const OFFSET_BOUND: u64 = 0xffff_ffff_ffff_ffff;
const MAX_SELECTOR_BUCKETS: u16 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Evidence {
    Mask(U256),
    SignExtend(u8),
    Bool,
    Signed,
    Offset,
    Dynamic,
    Loaded,
    Stride(U256),
    HighZero(u16),
    LowZero(u16),
    Bound(u64),
    FixedCopy(u64),
    BytesLength,
    NestedDynamic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CallKind {
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CreateKind {
    Create,
    Create2,
}

#[derive(Debug, Clone)]
pub(crate) struct Payload {
    pub(crate) origin: Val,
    pub(crate) selector: Option<u32>,
    pub(crate) words: Vec<Val>,
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) size: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) enum Stmt {
    CallValueGuard,
    Sstore {
        slot: Val,
        value: Val,
    },
    Tstore {
        slot: Val,
        value: Val,
    },
    Log {
        topics: Vec<Val>,
        data: Payload,
    },
    Call {
        pc: u32,
        kind: CallKind,
        address: Val,
        value: Option<Val>,
        input: Payload,
    },
    Create {
        pc: u32,
        kind: CreateKind,
        value: Val,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum Halt {
    Stop,
    Return(Payload),
    Revert(Payload),
    Invalid,
    SelfDestruct(Val),
    Undefined(u8),
    StackUnderflow,
    StackOverflow,
    BadJump(U256),
    UnresolvedJump,
    LoopLimit,
    StepLimit,
}

impl Halt {
    pub(crate) const fn succeeds(&self) -> bool {
        matches!(self, Self::Stop | Self::Return(_) | Self::SelfDestruct(_))
    }
}

pub(crate) enum Stop {
    Branch {
        cond: Val,
        target: Option<usize>,
        fallthrough: usize,
    },
    JumpDest,
    Bucket(u16),
    Halt(Halt),
}

pub(crate) trait Sink {
    fn op(&mut self, pc: usize, opcode: u8);
    fn evidence(&mut self, loc: CdLoc, evidence: Evidence);
    fn stmt(&mut self, stmt: Stmt);
    fn jump(&mut self, _pc: usize, _target: usize) {}
}

pub(crate) type Jumps = BTreeMap<usize, BTreeSet<usize>>;

const MAX_RECORDED_JUMPS: usize = 1 << 16;

pub(crate) fn record_jump(jumps: &mut Jumps, pc: usize, target: usize) {
    if jumps.len() < MAX_RECORDED_JUMPS || jumps.contains_key(&pc) {
        let targets: &mut BTreeSet<usize> = jumps.entry(pc).or_default();
        if targets.len() < 256 {
            targets.insert(target);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct State {
    pub(crate) pc: usize,
    pub(crate) stack: Vec<Val>,
    pub(crate) memory: Memory,
    pub(crate) visits: Rc<BTreeMap<(usize, u64), u16>>,
    pub(crate) forks: Rc<BTreeMap<(usize, u64), u16>>,
    pub(crate) guarded: bool,
    pub(crate) delegate_target: Option<Val>,
    pub(crate) code_copies: Rc<Vec<(Val, u64, u64)>>,
}

impl State {
    pub(crate) fn context(&self, dests: &JumpDests) -> u64 {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        for value in &self.stack {
            if let Some(constant) = as_const(value)
                && dests.valid_target(constant).is_some()
            {
                constant.hash(&mut hasher);
            }
        }
        hasher.finish()
    }

    pub(crate) fn fingerprint(&self) -> u64 {
        let mut hasher: DefaultHasher = DefaultHasher::new();
        self.pc.hash(&mut hasher);
        for value in &self.stack {
            value.hash(&mut hasher);
        }
        self.memory.fingerprint().hash(&mut hasher);
        self.guarded.hash(&mut hasher);
        hasher.finish()
    }

    pub(crate) fn note_fork(&mut self, pc: usize, dests: &JumpDests) -> bool {
        let key: (usize, u64) = (pc, self.context(dests));
        let count: &mut u16 = Rc::make_mut(&mut self.forks).entry(key).or_insert(0);
        *count += 1;
        *count <= MAX_SYMBOLIC_FORKS
    }
}

pub(crate) struct Machine<'a> {
    pub(crate) code: &'a [u8],
    pub(crate) dests: &'a JumpDests,
    pub(crate) codesize_known: bool,
    pub(crate) fork_selector_buckets: bool,
}

fn keccak(bytes: &[u8]) -> U256 {
    let digest = Keccak256::digest(bytes);
    let mut out: [u8; 32] = [0; 32];
    out.copy_from_slice(&digest);
    U256::from_be_bytes(out)
}

pub(crate) fn keccak_bytes(bytes: &[u8]) -> [u8; 32] {
    keccak(bytes).to_be_bytes()
}

fn small_const(value: &Val) -> Option<u64> {
    as_const(value).and_then(U256::to_u64)
}

pub(crate) fn classify_calldata(offset: &Val) -> Option<CdLoc> {
    let form = affine(offset);
    let constant: u64 = form.constant.to_u64()?;
    if form.terms.is_empty() {
        if constant == 0 {
            return Some(CdLoc::Word0);
        }
        if constant >= 4
            && (constant - 4).is_multiple_of(32)
            && (constant - 4) / 32 < MAX_HEAD_WORDS
        {
            return u16::try_from((constant - 4) / 32).ok().map(CdLoc::Head);
        }
        return None;
    }
    let mut head: Option<u16> = None;
    let mut element: Option<u16> = None;
    let mut others: usize = 0;
    for term in &form.terms {
        match term.expr {
            Expr::Cd(CdLoc::Head(index)) if head.is_none() => head = Some(index),
            Expr::Cd(CdLoc::Element(index)) if element.is_none() => element = Some(index),
            _ => others += 1,
        }
    }
    if let Some(index) = element {
        return Some(CdLoc::Nested(index));
    }
    let index: u16 = head?;
    if others == 0 && constant == 4 {
        Some(CdLoc::Length(index))
    } else if constant >= 4 {
        Some(CdLoc::Element(index))
    } else {
        None
    }
}

fn mentions_selector(value: &Val) -> bool {
    let mut budget: u32 = 64;
    crate::expr::mentions(
        value,
        &|expr: &Expr| matches!(expr, Expr::Cd(CdLoc::Word0)),
        &mut budget,
    )
}

fn cd_loc(value: &Val) -> Option<CdLoc> {
    match value.expr {
        Expr::Cd(loc) => Some(loc),
        _ => None,
    }
}

fn evidence_for_bin(op: BinOp, a: &Val, b: &Val, sink: &mut dyn Sink) {
    let pair = |x: &Val, y: &Val| -> Option<(CdLoc, U256)> { cd_loc(x).zip(as_const(y)) };
    match op {
        BinOp::And => {
            if let Some((loc, mask)) = pair(a, b).or_else(|| pair(b, a)) {
                sink.evidence(loc, Evidence::Mask(mask));
            }
        }
        BinOp::SignExtend => {
            if let (Some(index), Some(loc)) = (small_const(a), cd_loc(b))
                && index < 31
            {
                sink.evidence(loc, Evidence::SignExtend(index as u8));
            }
        }
        BinOp::Slt | BinOp::Sgt | BinOp::SDiv | BinOp::SMod => {
            for operand in [a, b] {
                if let Some(loc @ (CdLoc::Head(_) | CdLoc::Element(_))) = cd_loc(operand) {
                    sink.evidence(loc, Evidence::Signed);
                }
            }
        }
        BinOp::Sar => {
            if let Some(loc @ (CdLoc::Head(_) | CdLoc::Element(_))) = cd_loc(b) {
                sink.evidence(loc, Evidence::Signed);
            }
        }
        BinOp::Gt | BinOp::Lt => {
            let (value, bound) = if op == BinOp::Gt { (a, b) } else { (b, a) };
            if let Some(loc @ (CdLoc::Head(_) | CdLoc::Element(_))) = cd_loc(value)
                && as_const(bound) == Some(U256::from_u64(OFFSET_BOUND))
            {
                sink.evidence(loc, Evidence::Offset);
            }
            if let (Some(loc @ CdLoc::Length(_)), Some(limit)) = (cd_loc(value), small_const(bound))
                && limit < OFFSET_BOUND
            {
                sink.evidence(loc, Evidence::Bound(limit));
            }
        }
        BinOp::Mul => {
            if let Some((CdLoc::Length(index), stride)) = pair(a, b).or_else(|| pair(b, a)) {
                sink.evidence(CdLoc::Length(index), Evidence::Stride(stride));
            }
        }
        BinOp::Shr => {
            if let (Some(shift), Some(loc @ (CdLoc::Head(_) | CdLoc::Element(_)))) =
                (small_const(a), cd_loc(b))
                && (1..256).contains(&shift)
            {
                sink.evidence(loc, Evidence::HighZero(shift as u16));
            }
        }
        BinOp::Shl => {
            if let (Some(shift), Some(loc @ (CdLoc::Head(_) | CdLoc::Element(_)))) =
                (small_const(a), cd_loc(b))
                && (1..256).contains(&shift)
            {
                sink.evidence(loc, Evidence::LowZero(shift as u16));
            }
            if let (Some(shift), Some(CdLoc::Length(index))) = (small_const(a), cd_loc(b))
                && shift < 32
            {
                sink.evidence(
                    CdLoc::Length(index),
                    Evidence::Stride(U256::ONE.shift_left(shift as u32)),
                );
            }
        }
        BinOp::Add => {
            for operand in [a, b] {
                if let Some(loc @ CdLoc::Length(_)) = cd_loc(operand) {
                    sink.evidence(loc, Evidence::BytesLength);
                }
            }
        }
        _ => {}
    }
}

fn selector_of(memory: &Memory, offset: &Val, size: Option<u64>) -> Option<u32> {
    if size.is_some_and(|size: u64| size < 4) {
        return None;
    }
    let bytes: Vec<u8> = memory.written_bytes(offset, 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn payload(memory: &Memory, offset: &Val, size: &Val, pc: u32) -> Payload {
    let size_value: Option<u64> = small_const(size);
    let selector: Option<u32> = selector_of(memory, offset, size_value);
    let bytes: Option<Vec<u8>> = memory.known_bytes(offset, size);
    let words: Vec<Val> = match size_value {
        Some(len) if len >= 4 && (len - 4) % 32 == 0 && selector.is_some() => memory
            .words(
                &bin(BinOp::Add, offset.clone(), konst(U256::from_u64(4)), pc),
                &konst(U256::from_u64(len - 4)),
                pc,
            )
            .unwrap_or_default(),
        _ => memory.words(offset, size, pc).unwrap_or_default(),
    };
    Payload {
        origin: offset.clone(),
        selector,
        words,
        bytes,
        size: size_value,
    }
}

impl Machine<'_> {
    fn pop(state: &mut State) -> Val {
        state.stack.pop().unwrap_or_else(|| konst(U256::ZERO))
    }

    fn arrive(&self, state: &mut State, pc: usize) -> bool {
        let key: (usize, u64) = (pc, state.context(self.dests));
        let count: &mut u16 = Rc::make_mut(&mut state.visits).entry(key).or_insert(0);
        *count += 1;
        *count <= MAX_JUMPDEST_VISITS
    }

    pub(crate) fn run(
        &self,
        state: &mut State,
        sink: &mut dyn Sink,
        budget: &mut u64,
        stop_at_jumpdest: bool,
    ) -> Stop {
        let mut first: bool = true;
        loop {
            if *budget == 0 {
                return Stop::Halt(Halt::StepLimit);
            }
            *budget -= 1;
            let pc: usize = state.pc;
            let Some(&byte) = self.code.get(pc) else {
                return Stop::Halt(Halt::Stop);
            };
            let Some(info) = opcode::info(byte) else {
                return Stop::Halt(Halt::Undefined(byte));
            };
            if byte == JUMPDEST {
                if stop_at_jumpdest && !first {
                    return Stop::JumpDest;
                }
                if !self.arrive(state, pc) {
                    return Stop::Halt(Halt::LoopLimit);
                }
            }
            first = false;
            if state.stack.len() < usize::from(info.inputs) {
                return Stop::Halt(Halt::StackUnderflow);
            }
            sink.op(pc, byte);
            let at: u32 = pc as u32;
            let next: usize = pc + 1 + opcode::immediate_len(byte);
            match byte {
                0x00 => return Stop::Halt(Halt::Stop),
                0x01..=0x07 | 0x0a | 0x0b | 0x10..=0x14 | 0x16..=0x18 | 0x1a..=0x1d => {
                    let op: BinOp = match byte {
                        0x01 => BinOp::Add,
                        0x02 => BinOp::Mul,
                        0x03 => BinOp::Sub,
                        0x04 => BinOp::Div,
                        0x05 => BinOp::SDiv,
                        0x06 => BinOp::Mod,
                        0x07 => BinOp::SMod,
                        0x0a => BinOp::Exp,
                        0x0b => BinOp::SignExtend,
                        0x10 => BinOp::Lt,
                        0x11 => BinOp::Gt,
                        0x12 => BinOp::Slt,
                        0x13 => BinOp::Sgt,
                        0x14 => BinOp::Eq,
                        0x16 => BinOp::And,
                        0x17 => BinOp::Or,
                        0x18 => BinOp::Xor,
                        0x1a => BinOp::Byte,
                        0x1b => BinOp::Shl,
                        0x1c => BinOp::Shr,
                        _ => BinOp::Sar,
                    };
                    let a: Val = Self::pop(state);
                    let b: Val = Self::pop(state);
                    if op == BinOp::Mod
                        && self.fork_selector_buckets
                        && let Some(modulus) = small_const(&b)
                            .and_then(|n: u64| u16::try_from(n).ok())
                            .filter(|n: &u16| (2..=MAX_SELECTOR_BUCKETS).contains(n))
                        && mentions_selector(&a)
                    {
                        state.pc = next;
                        return Stop::Bucket(modulus);
                    }
                    evidence_for_bin(op, &a, &b, sink);
                    state.stack.push(bin(op, a, b, at));
                }
                0x08 | 0x09 => {
                    let a: Val = Self::pop(state);
                    let b: Val = Self::pop(state);
                    let c: Val = Self::pop(state);
                    let op: TernOp = if byte == 0x08 {
                        TernOp::AddMod
                    } else {
                        TernOp::MulMod
                    };
                    state.stack.push(tern(op, a, b, c, at));
                }
                0x15 => {
                    let a: Val = Self::pop(state);
                    if let Expr::Un(UnOp::IsZero, inner) = &a.expr
                        && let Some(loc @ (CdLoc::Head(_) | CdLoc::Element(_))) = cd_loc(inner)
                    {
                        sink.evidence(loc, Evidence::Bool);
                    }
                    state.stack.push(un(UnOp::IsZero, a, at));
                }
                0x19 => {
                    let a: Val = Self::pop(state);
                    state.stack.push(un(UnOp::Not, a, at));
                }
                0x1e => {
                    let a: Val = Self::pop(state);
                    state.stack.push(un(UnOp::Clz, a, at));
                }
                0x20 => {
                    let offset: Val = Self::pop(state);
                    let size: Val = Self::pop(state);
                    state.stack.push(self.hash(state, &offset, &size, at));
                }
                0x30 | 0x32 | 0x33 | 0x34 | 0x3a | 0x3d | 0x41..=0x48 | 0x4a | 0x59 | 0x5a => {
                    let env: Env = match byte {
                        0x30 => Env::Address,
                        0x32 => Env::Origin,
                        0x33 => Env::Caller,
                        0x34 => Env::CallValue,
                        0x3a => Env::GasPrice,
                        0x3d => Env::ReturnDataSize,
                        0x41 => Env::Coinbase,
                        0x42 => Env::Timestamp,
                        0x43 => Env::Number,
                        0x44 => Env::PrevRandao,
                        0x45 => Env::GasLimit,
                        0x46 => Env::ChainId,
                        0x47 => Env::SelfBalance,
                        0x48 => Env::BaseFee,
                        0x4a => Env::BlobBaseFee,
                        0x59 => Env::MemorySize,
                        _ => Env::Gas,
                    };
                    state.stack.push(node(Expr::Env(env), at));
                }
                0x31 | 0x3b | 0x3f | 0x40 | 0x49 => {
                    let op: UnOp = match byte {
                        0x31 => UnOp::Balance,
                        0x3b => UnOp::ExtCodeSize,
                        0x3f => UnOp::ExtCodeHash,
                        0x40 => UnOp::BlockHash,
                        _ => UnOp::BlobHash,
                    };
                    let a: Val = Self::pop(state);
                    state.stack.push(un(op, a, at));
                }
                0x35 => {
                    let offset: Val = Self::pop(state);
                    let value: Val = match classify_calldata(&offset) {
                        Some(loc) => {
                            match loc {
                                CdLoc::Length(index) => {
                                    sink.evidence(CdLoc::Head(index), Evidence::Dynamic);
                                }
                                CdLoc::Element(index) => {
                                    sink.evidence(CdLoc::Head(index), Evidence::Dynamic);
                                    sink.evidence(loc, Evidence::Loaded);
                                }
                                CdLoc::Nested(index) => {
                                    sink.evidence(CdLoc::Head(index), Evidence::NestedDynamic);
                                }
                                CdLoc::Head(_) => sink.evidence(loc, Evidence::Loaded),
                                CdLoc::Word0 => {}
                            }
                            node(Expr::Cd(loc), at)
                        }
                        None => node(Expr::CdRaw(offset), at),
                    };
                    state.stack.push(value);
                }
                0x36 => state.stack.push(node(Expr::CdSize, at)),
                0x37 => {
                    let dest: Val = Self::pop(state);
                    let source: Val = Self::pop(state);
                    let len: Val = Self::pop(state);
                    if let Some(loc @ CdLoc::Length(_)) = cd_loc(&len) {
                        sink.evidence(loc, Evidence::BytesLength);
                    }
                    if let (Some(loc @ CdLoc::Length(_)), Some(size)) =
                        (classify_calldata(&source), small_const(&len))
                    {
                        sink.evidence(loc, Evidence::FixedCopy(size));
                    }
                    state.memory.clobber(&dest, &len, at);
                }
                0x38 => {
                    let value: Val = if self.codesize_known {
                        konst(U256::from_u64(self.code.len() as u64))
                    } else {
                        node(Expr::Env(Env::CodeSize), at)
                    };
                    state.stack.push(value);
                }
                0x39 => {
                    let dest: Val = Self::pop(state);
                    let source: Val = Self::pop(state);
                    let len: Val = Self::pop(state);
                    match small_const(&source) {
                        Some(start) => {
                            let from: usize = usize::try_from(start).unwrap_or(usize::MAX);
                            let data: &[u8] = self.code.get(from..).unwrap_or(&[]);
                            state.memory.copy_in(&dest, data, &len, at);
                            if let Some(count) = small_const(&len)
                                && state.code_copies.len() < 64
                            {
                                Rc::make_mut(&mut state.code_copies).push((
                                    dest.clone(),
                                    start,
                                    count,
                                ));
                            }
                        }
                        None => state.memory.clobber(&dest, &len, at),
                    }
                }
                0x3c => {
                    let _address: Val = Self::pop(state);
                    let dest: Val = Self::pop(state);
                    let _source: Val = Self::pop(state);
                    let len: Val = Self::pop(state);
                    state.memory.clobber(&dest, &len, at);
                }
                0x3e => {
                    let dest: Val = Self::pop(state);
                    let _source: Val = Self::pop(state);
                    let len: Val = Self::pop(state);
                    state.memory.clobber(&dest, &len, at);
                }
                0x50 => {
                    Self::pop(state);
                }
                0x51 => {
                    let address: Val = Self::pop(state);
                    let value: Val = state.memory.load(&address, at);
                    state.stack.push(value);
                }
                0x52 => {
                    let address: Val = Self::pop(state);
                    let value: Val = Self::pop(state);
                    state.memory.store(&address, &value);
                }
                0x53 => {
                    let address: Val = Self::pop(state);
                    let value: Val = Self::pop(state);
                    state.memory.store_byte(&address, &value, at);
                }
                0x54 => {
                    let slot: Val = Self::pop(state);
                    state.stack.push(node(Expr::Sload(slot), at));
                }
                0x55 => {
                    let slot: Val = Self::pop(state);
                    let value: Val = Self::pop(state);
                    sink.stmt(Stmt::Sstore { slot, value });
                }
                0x5c => {
                    let slot: Val = Self::pop(state);
                    state.stack.push(node(Expr::Tload(slot), at));
                }
                0x5d => {
                    let slot: Val = Self::pop(state);
                    let value: Val = Self::pop(state);
                    sink.stmt(Stmt::Tstore { slot, value });
                }
                0x5e => {
                    let dest: Val = Self::pop(state);
                    let source: Val = Self::pop(state);
                    let len: Val = Self::pop(state);
                    state.memory.copy_within(&dest, &source, &len, at);
                }
                0x56 => {
                    let target: Val = Self::pop(state);
                    match as_const(&target) {
                        Some(value) => match self.dests.valid_target(value) {
                            Some(dest) => {
                                sink.jump(pc, dest);
                                state.pc = dest;
                                continue;
                            }
                            None => return Stop::Halt(Halt::BadJump(value)),
                        },
                        None => return Stop::Halt(Halt::UnresolvedJump),
                    }
                }
                0x57 => {
                    let target: Val = Self::pop(state);
                    let cond: Val = Self::pop(state);
                    let dest: Option<usize> =
                        as_const(&target).and_then(|t| self.dests.valid_target(t));
                    match as_const(&cond) {
                        Some(value) if value.is_zero() => {}
                        Some(_) => match (dest, as_const(&target)) {
                            (Some(dest), _) => {
                                sink.jump(pc, dest);
                                state.pc = dest;
                                continue;
                            }
                            (None, Some(value)) => return Stop::Halt(Halt::BadJump(value)),
                            (None, None) => return Stop::Halt(Halt::UnresolvedJump),
                        },
                        None => {
                            state.pc = next;
                            return Stop::Branch {
                                cond,
                                target: dest,
                                fallthrough: next,
                            };
                        }
                    }
                }
                0x58 => state.stack.push(konst(U256::from_u64(pc as u64))),
                JUMPDEST => {}
                0x5f..=0x7f => {
                    let value: U256 = if byte == 0x5f {
                        U256::ZERO
                    } else {
                        push_value(self.code, pc).0
                    };
                    state.stack.push(konst(value));
                }
                0x80..=0x8f => {
                    let depth: usize = usize::from(byte - 0x80) + 1;
                    let value: Val = state.stack[state.stack.len() - depth].clone();
                    state.stack.push(value);
                }
                0x90..=0x9f => {
                    let depth: usize = usize::from(byte - 0x90) + 1;
                    let top: usize = state.stack.len() - 1;
                    state.stack.swap(top, top - depth);
                }
                0xa0..=0xa4 => {
                    let offset: Val = Self::pop(state);
                    let size: Val = Self::pop(state);
                    let topics: Vec<Val> = (0..byte - 0xa0).map(|_| Self::pop(state)).collect();
                    let data: Payload = payload(&state.memory, &offset, &size, at);
                    let data: Payload = Payload {
                        selector: None,
                        ..data
                    };
                    sink.stmt(Stmt::Log { topics, data });
                }
                0xf0 | 0xf5 => {
                    let value: Val = Self::pop(state);
                    let _offset: Val = Self::pop(state);
                    let _size: Val = Self::pop(state);
                    if byte == 0xf5 {
                        Self::pop(state);
                    }
                    let kind: CreateKind = if byte == 0xf0 {
                        CreateKind::Create
                    } else {
                        CreateKind::Create2
                    };
                    sink.stmt(Stmt::Create {
                        pc: at,
                        kind,
                        value,
                    });
                    state.stack.push(node(Expr::Created(at), at));
                }
                0xf1 | 0xf2 | 0xf4 | 0xfa => {
                    let _gas: Val = Self::pop(state);
                    let address: Val = Self::pop(state);
                    let value: Option<Val> = matches!(byte, 0xf1 | 0xf2).then(|| Self::pop(state));
                    let in_offset: Val = Self::pop(state);
                    let in_size: Val = Self::pop(state);
                    let out_offset: Val = Self::pop(state);
                    let out_size: Val = Self::pop(state);
                    let kind: CallKind = match byte {
                        0xf1 => CallKind::Call,
                        0xf2 => CallKind::CallCode,
                        0xf4 => CallKind::DelegateCall,
                        _ => CallKind::StaticCall,
                    };
                    if kind == CallKind::DelegateCall {
                        state.delegate_target = Some(address.clone());
                    }
                    let input: Payload = payload(&state.memory, &in_offset, &in_size, at);
                    sink.stmt(Stmt::Call {
                        pc: at,
                        kind,
                        address,
                        value,
                        input,
                    });
                    state.memory.clobber(&out_offset, &out_size, at);
                    state.stack.push(node(Expr::CallResult(at), at));
                }
                0xf3 | 0xfd => {
                    let offset: Val = Self::pop(state);
                    let size: Val = Self::pop(state);
                    let data: Payload = payload(&state.memory, &offset, &size, at);
                    if byte == 0xf3 {
                        return Stop::Halt(Halt::Return(data));
                    }
                    return Stop::Halt(Halt::Revert(data));
                }
                0xfe => return Stop::Halt(Halt::Invalid),
                0xff => {
                    let beneficiary: Val = Self::pop(state);
                    return Stop::Halt(Halt::SelfDestruct(beneficiary));
                }
                _ => return Stop::Halt(Halt::Undefined(byte)),
            }
            if state.stack.len() > STACK_LIMIT {
                return Stop::Halt(Halt::StackOverflow);
            }
            state.pc = next;
        }
    }

    fn hash(&self, state: &State, offset: &Val, size: &Val, pc: u32) -> Val {
        let _ = self;
        let Some(len) = small_const(size).filter(|len: &u64| *len <= MAX_KECCAK_BYTES) else {
            return node(Expr::Opaque(pc), pc);
        };
        if let Some(bytes) = state.memory.known_bytes(offset, size) {
            return konst(keccak(&bytes));
        }
        if len.is_multiple_of(32)
            && len <= 256
            && let Some(words) = state.memory.words(offset, size, pc)
            && words
                .iter()
                .all(|word: &Val| !matches!(word.expr, Expr::Opaque(_)))
        {
            return node(Expr::Keccak(words), pc);
        }
        node(Expr::Opaque(pc), pc)
    }

    pub(crate) fn guard_reverts(&self, state: &State, budget: &mut u64) -> bool {
        let mut probe: State = state.clone();
        let mut sink: NullSink = NullSink;
        let mut steps: u64 = 64.min(*budget);
        let start: u64 = steps;
        let outcome: Stop = self.run(&mut probe, &mut sink, &mut steps, false);
        *budget = budget.saturating_sub(start - steps);
        matches!(outcome, Stop::Halt(Halt::Revert(_)))
    }
}

pub(crate) struct NullSink;

impl Sink for NullSink {
    fn op(&mut self, _pc: usize, _opcode: u8) {}
    fn evidence(&mut self, _loc: CdLoc, _evidence: Evidence) {}
    fn stmt(&mut self, _stmt: Stmt) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallValueCheck {
    JumpWhenNonZero,
    JumpWhenZero,
}

pub(crate) fn callvalue_check(cond: &Val) -> Option<CallValueCheck> {
    match &cond.expr {
        Expr::Env(Env::CallValue) => Some(CallValueCheck::JumpWhenNonZero),
        Expr::Bin(BinOp::Or, a, b)
            if matches!(a.expr, Expr::Env(Env::CallValue))
                || matches!(b.expr, Expr::Env(Env::CallValue)) =>
        {
            Some(CallValueCheck::JumpWhenNonZero)
        }
        Expr::Un(UnOp::IsZero, inner) => match callvalue_check(inner)? {
            CallValueCheck::JumpWhenNonZero => Some(CallValueCheck::JumpWhenZero),
            CallValueCheck::JumpWhenZero => Some(CallValueCheck::JumpWhenNonZero),
        },
        _ => None,
    }
}

pub(crate) fn split_branch(state: &State, target: usize, fallthrough: usize) -> (State, State) {
    let mut taken: State = state.clone();
    taken.pc = target;
    let mut fall: State = state.clone();
    fall.pc = fallthrough;
    (taken, fall)
}
