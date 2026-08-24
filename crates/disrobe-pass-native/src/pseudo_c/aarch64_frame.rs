use super::super::{MemRef, Result, Width};
use super::{
    FrameAnalysis, FrameInfo, MAX_FRAME_BYTES, SwitchDispatch, parse_immediate, parse_memory,
    reject, reject_at, relative_target, split_operands,
};
use crate::arch::DisasmInsn;
use std::collections::{BTreeMap, BTreeSet};

const PRESERVED_GPRS: [u8; 12] = [19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30];
const PRESERVED_VECS: [u8; 8] = [8, 9, 10, 11, 12, 13, 14, 15];
const PRESERVED_COUNT: usize = PRESERVED_GPRS.len() + PRESERVED_VECS.len();
const FRAME_POINTER_SLOT: usize = 10;
const LINK_REGISTER_SLOT: usize = 11;
const STACK_ALIGNMENT: i64 = 16;
const MAX_FIXPOINT_STEPS: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Preserved {
    Entry(usize),
    CallReturn,
    Opaque,
}

const fn preserved_rank(value: Preserved) -> u8 {
    match value {
        Preserved::Entry(_) => 0,
        Preserved::CallReturn => 1,
        Preserved::Opaque => 2,
    }
}

fn join_preserved(left: Preserved, right: Preserved) -> Preserved {
    if left == right {
        return left;
    }
    if preserved_rank(left) == 0 && preserved_rank(right) == 0 {
        return Preserved::Opaque;
    }
    if preserved_rank(left) >= preserved_rank(right) {
        left
    } else {
        right
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FramePointer {
    Absent,
    At(i64),
    Conflicting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StackState {
    sp_to_entry: i64,
    link_signed: bool,
    entry_prologue_open: bool,
    frame_pointer: FramePointer,
    preserved: [Preserved; PRESERVED_COUNT],
    saved: BTreeMap<i64, Preserved>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Body,
    Management,
    AbsorbedWriteback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpEffect {
    Unchanged,
    Delta(i64),
    FromFramePointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityHint {
    BtiC,
    PaciAsp,
    AutiAsp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    Sp,
    FramePointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Access {
    base: Base,
    disp: i64,
    width: i64,
    write: bool,
    after_writeback: bool,
}

#[derive(Debug, Clone)]
struct Facts {
    sp: SpEffect,
    establishes_frame_pointer: Option<i64>,
    accesses: Vec<Access>,
    written: Vec<usize>,
    unknown_writes: bool,
    preserved_transfer: Option<PreservedTransfer>,
    calls: bool,
    reads_frame_register: bool,
    exits: bool,
    security_hint: Option<SecurityHint>,
}

fn security_hint(insn: &DisasmInsn) -> Result<Option<SecurityHint>> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    match (insn.mnemonic.as_str(), operands.as_slice()) {
        ("hint", ["#0x22"]) | ("bti", ["c"]) => Ok(Some(SecurityHint::BtiC)),
        ("hint", ["#0x19"]) | ("paciasp", []) => Ok(Some(SecurityHint::PaciAsp)),
        ("hint", ["#0x1d"]) | ("autiasp", []) => Ok(Some(SecurityHint::AutiAsp)),
        ("hint", _) => Err(reject_at(insn, "unsupported aarch64 hint instruction")),
        _ => Ok(None),
    }
}

#[derive(Debug, Clone)]
struct PreservedTransfer {
    registers: Vec<usize>,
    store: bool,
}

impl StackState {
    fn entry() -> Self {
        let mut preserved: [Preserved; PRESERVED_COUNT] = [Preserved::Opaque; PRESERVED_COUNT];
        for (slot, cell) in preserved.iter_mut().enumerate() {
            *cell = Preserved::Entry(slot);
        }
        Self {
            sp_to_entry: 0,
            link_signed: false,
            entry_prologue_open: true,
            frame_pointer: FramePointer::Absent,
            preserved,
            saved: BTreeMap::new(),
        }
    }

    fn join(&self, other: &Self, insn: &DisasmInsn) -> Result<Self> {
        if self.sp_to_entry != other.sp_to_entry {
            return Err(reject_at(
                insn,
                "stack pointer offsets disagree on the paths reaching this instruction",
            ));
        }
        if self.link_signed != other.link_signed {
            return Err(reject_at(
                insn,
                "pointer-authentication state disagrees on incoming paths",
            ));
        }
        let frame_pointer: FramePointer = if self.frame_pointer == other.frame_pointer {
            self.frame_pointer
        } else {
            FramePointer::Conflicting
        };
        let mut preserved: [Preserved; PRESERVED_COUNT] = self.preserved;
        for (slot, cell) in preserved.iter_mut().enumerate() {
            let incoming: Preserved = other
                .preserved
                .get(slot)
                .copied()
                .unwrap_or(Preserved::Opaque);
            *cell = join_preserved(*cell, incoming);
        }
        let saved: BTreeMap<i64, Preserved> = self
            .saved
            .iter()
            .filter_map(|(offset, value): (&i64, &Preserved)| {
                let incoming: Preserved = other.saved.get(offset).copied()?;
                let merged: Preserved = join_preserved(*value, incoming);
                (merged != Preserved::Opaque).then_some((*offset, merged))
            })
            .collect();
        Ok(Self {
            sp_to_entry: self.sp_to_entry,
            link_signed: self.link_signed,
            entry_prologue_open: self.entry_prologue_open && other.entry_prologue_open,
            frame_pointer,
            preserved,
            saved,
        })
    }

    fn clobber(&mut self, slot: usize) {
        if let Some(cell) = self.preserved.get_mut(slot) {
            *cell = Preserved::Opaque;
        }
    }

    fn invalidate(&mut self, start: i64, width: i64) {
        self.saved.retain(|offset: &i64, _: &mut Preserved| {
            *offset + 8 <= start || *offset >= start + width
        });
    }
}

fn gpr_number(token: &str) -> Option<u8> {
    let trimmed: &str = token.trim();
    let rest: &str = trimmed
        .strip_prefix('x')
        .or_else(|| trimmed.strip_prefix('w'))?;
    rest.parse::<u8>().ok().filter(|value: &u8| *value <= 30)
}

fn vector_number(token: &str) -> Option<u8> {
    let trimmed: &str = token.trim();
    let rest: &str = trimmed
        .strip_prefix('d')
        .or_else(|| trimmed.strip_prefix('s'))
        .or_else(|| trimmed.strip_prefix('q'))
        .or_else(|| trimmed.strip_prefix('h'))
        .or_else(|| trimmed.strip_prefix('b'))
        .or_else(|| trimmed.strip_prefix('v'))?;
    let digits: &str = rest.split('.').next().unwrap_or(rest);
    digits.parse::<u8>().ok().filter(|value: &u8| *value <= 31)
}

fn preserved_slot(token: &str) -> Option<usize> {
    let trimmed: &str = token.trim();
    if let Some(number) = gpr_number(trimmed) {
        return PRESERVED_GPRS
            .iter()
            .position(|candidate: &u8| *candidate == number);
    }
    let number: u8 = vector_number(trimmed)?;
    PRESERVED_VECS
        .iter()
        .position(|candidate: &u8| *candidate == number)
        .map(|index: usize| index + PRESERVED_GPRS.len())
}

fn is_memory_operand(token: &str) -> bool {
    token.trim().starts_with('[')
}

fn is_stack_base(token: &str) -> Option<Base> {
    let body: &str = token
        .trim()
        .trim_end_matches('!')
        .trim()
        .strip_prefix('[')?
        .trim_end_matches(']');
    let head: &str = body.split(',').next().unwrap_or(body).trim();
    match head {
        "sp" => Some(Base::Sp),
        "x29" => Some(Base::FramePointer),
        _ => None,
    }
}

fn scalar_token_width(token: &str) -> Option<i64> {
    let trimmed: &str = token.trim();
    match trimmed {
        "sp" | "xzr" => return Some(8),
        "wzr" => return Some(4),
        _ => {}
    }
    let (head, rest): (char, &str) = {
        let mut chars: std::str::Chars<'_> = trimmed.chars();
        (chars.next()?, chars.as_str())
    };
    if rest
        .split('.')
        .next()
        .unwrap_or(rest)
        .parse::<u8>()
        .is_err()
    {
        return None;
    }
    match head {
        'x' | 'd' => Some(8),
        'w' | 's' => Some(4),
        'q' => Some(16),
        'h' => Some(2),
        'b' => Some(1),
        _ => None,
    }
}

fn access_element_width(mnemonic: &str, value_token: &str) -> Option<i64> {
    match mnemonic {
        "ldrb" | "ldurb" | "ldrsb" | "ldursb" | "strb" | "sturb" => return Some(1),
        "ldrh" | "ldurh" | "ldrsh" | "ldursh" | "strh" | "sturh" => return Some(2),
        "ldrsw" | "ldursw" | "ldpsw" => return Some(4),
        _ => {}
    }
    scalar_token_width(value_token)
}

const fn is_scalar_load(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"ldr"
            | b"ldur"
            | b"ldrb"
            | b"ldurb"
            | b"ldrsb"
            | b"ldursb"
            | b"ldrh"
            | b"ldurh"
            | b"ldrsh"
            | b"ldursh"
            | b"ldrsw"
            | b"ldursw"
    )
}

const fn is_scalar_store(mnemonic: &str) -> bool {
    matches!(
        mnemonic.as_bytes(),
        b"str" | b"stur" | b"strb" | b"sturb" | b"strh" | b"sturh"
    )
}

const fn is_pair_load(mnemonic: &str) -> bool {
    matches!(mnemonic.as_bytes(), b"ldp" | b"ldnp" | b"ldpsw")
}

const fn is_pair_store(mnemonic: &str) -> bool {
    matches!(mnemonic.as_bytes(), b"stp" | b"stnp")
}

fn is_discardable_destination(token: &str) -> bool {
    let trimmed: &str = token.trim();
    matches!(trimmed, "sp" | "wsp" | "xzr" | "wzr")
        || gpr_number(trimmed).is_some()
        || vector_number(trimmed).is_some()
}

fn writes_nothing(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "cmp"
            | "cmn"
            | "tst"
            | "ccmp"
            | "ccmn"
            | "fcmp"
            | "fcmpe"
            | "fccmp"
            | "fccmpe"
            | "b"
            | "br"
            | "ret"
            | "cbz"
            | "cbnz"
            | "tbz"
            | "tbnz"
            | "bl"
            | "blr"
            | "nop"
    ) || mnemonic.starts_with("b.")
        || is_scalar_store(mnemonic)
        || is_pair_store(mnemonic)
        || matches!(mnemonic, "st1" | "st2" | "st3" | "st4")
}

fn stack_facts(insn: &DisasmInsn) -> Result<Facts> {
    let operands: Vec<&str> = split_operands(&insn.operands);
    let security_hint: Option<SecurityHint> = security_hint(insn)?;
    let mut facts: Facts = Facts {
        sp: SpEffect::Unchanged,
        establishes_frame_pointer: None,
        accesses: Vec::new(),
        written: Vec::new(),
        unknown_writes: false,
        preserved_transfer: None,
        calls: matches!(insn.mnemonic.as_str(), "bl" | "blr"),
        reads_frame_register: false,
        exits: insn.mnemonic == "ret",
        security_hint,
    };
    if insn.mnemonic == "ret" && !insn.operands.trim().is_empty() {
        return Err(reject_at(insn, "return uses a non-default link register"));
    }
    let mut writeback: i64 = 0;
    let mut writeback_is_pre: bool = false;
    let mut memory_index: Option<usize> = None;
    for (index, token) in operands.iter().enumerate() {
        if is_memory_operand(token) {
            if memory_index.is_some() {
                return Err(reject_at(insn, "instruction uses two memory operands"));
            }
            memory_index = Some(index);
        }
    }
    if let Some(index) = memory_index
        && let Some(base) = is_stack_base(operands[index])
    {
        let element: i64 = access_element_width(
            &insn.mnemonic,
            operands
                .first()
                .ok_or_else(|| reject_at(insn, "stack access lacks a value operand"))?,
        )
        .ok_or_else(|| reject_at(insn, "stack access has an unmodelled operand width"))?;
        let load: bool = is_scalar_load(&insn.mnemonic) || is_pair_load(&insn.mnemonic);
        let store: bool = is_scalar_store(&insn.mnemonic) || is_pair_store(&insn.mnemonic);
        if !load && !store {
            return Err(reject_at(
                insn,
                "stack access uses an unmodelled instruction",
            ));
        }
        let pair: bool = is_pair_load(&insn.mnemonic) || is_pair_store(&insn.mnemonic);
        let value_count: usize = if pair { 2 } else { 1 };
        if index != value_count {
            return Err(reject_at(
                insn,
                "stack access has an unexpected operand order",
            ));
        }
        let (mem, pre_index): (MemRef, bool) = parse_memory(operands[index], Width::W64)?;
        if mem.index.is_some() {
            return Err(reject_at(insn, "stack access uses a register index"));
        }
        let post_delta: Option<i64> = operands
            .get(index + 1)
            .map(|token: &&str| parse_immediate(token))
            .transpose()?;
        if pre_index && post_delta.is_some() {
            return Err(reject_at(insn, "stack access uses two writeback modes"));
        }
        if pair {
            let second: i64 = access_element_width(
                &insn.mnemonic,
                operands
                    .get(1)
                    .ok_or_else(|| reject_at(insn, "pair access lacks a second value operand"))?,
            )
            .ok_or_else(|| reject_at(insn, "stack access has an unmodelled operand width"))?;
            if second != element {
                return Err(reject_at(insn, "pair access mixes operand widths"));
            }
        }
        let total: i64 = element * i64::try_from(value_count).unwrap_or(2);
        if let Some(delta) = post_delta {
            if mem.disp != 0 {
                return Err(reject_at(
                    insn,
                    "post-indexed stack access carries an inline displacement",
                ));
            }
            writeback = delta;
        } else if pre_index {
            writeback = mem.disp;
            writeback_is_pre = true;
        }
        facts.accesses.push(Access {
            base,
            disp: if writeback_is_pre { 0 } else { mem.disp },
            width: total,
            write: store,
            after_writeback: writeback_is_pre,
        });
        if base == Base::Sp && writeback != 0 {
            facts.sp = SpEffect::Delta(
                writeback
                    .checked_neg()
                    .ok_or_else(|| reject_at(insn, "stack writeback overflow"))?,
            );
        } else if base == Base::FramePointer && writeback != 0 {
            return Err(reject_at(
                insn,
                "frame-pointer access writes back to the frame pointer",
            ));
        }
        let mut registers: Vec<usize> = Vec::new();
        let mut every_preserved: bool = true;
        for token in operands.iter().take(value_count) {
            match preserved_slot(token) {
                Some(slot) => registers.push(slot),
                None => every_preserved = false,
            }
        }
        if every_preserved && !registers.is_empty() {
            facts.preserved_transfer = Some(PreservedTransfer { registers, store });
        }
    }
    if memory_index.is_none() {
        match (insn.mnemonic.as_str(), operands.as_slice()) {
            ("sub", ["sp", "sp", immediate]) if immediate.starts_with('#') => {
                facts.sp = SpEffect::Delta(parse_immediate(immediate)?);
            }
            ("add", ["sp", "sp", immediate]) if immediate.starts_with('#') => {
                facts.sp = SpEffect::Delta(
                    parse_immediate(immediate)?
                        .checked_neg()
                        .ok_or_else(|| reject_at(insn, "stack release overflow"))?,
                );
            }
            ("mov", ["x29", "sp"]) => facts.establishes_frame_pointer = Some(0),
            ("add", ["x29", "sp", immediate]) if immediate.starts_with('#') => {
                facts.establishes_frame_pointer = Some(parse_immediate(immediate)?);
            }
            ("mov", ["sp", "x29"]) => facts.sp = SpEffect::FromFramePointer,
            _ => {}
        }
    }
    let modelled_adjustment: bool =
        !matches!(facts.sp, SpEffect::Unchanged) || facts.establishes_frame_pointer.is_some();
    if !modelled_adjustment
        && operands
            .iter()
            .any(|token: &&str| matches!(token.trim(), "sp" | "wsp"))
    {
        return Err(reject_at(
            insn,
            "stack pointer is used outside a modelled frame adjustment",
        ));
    }
    facts.reads_frame_register = operands
        .iter()
        .any(|token: &&str| matches!(token.trim(), "x29" | "w29"))
        && facts.establishes_frame_pointer.is_none()
        && facts.sp != SpEffect::FromFramePointer
        && !facts
            .preserved_transfer
            .as_ref()
            .is_some_and(|transfer: &PreservedTransfer| {
                transfer.registers.contains(&FRAME_POINTER_SLOT)
            });
    if facts.security_hint.is_none() && !writes_nothing(&insn.mnemonic) {
        let dests: usize = if is_pair_load(&insn.mnemonic) { 2 } else { 1 };
        for token in operands.iter().take(dests) {
            match preserved_slot(token) {
                Some(slot) => facts.written.push(slot),
                None => {
                    if !is_discardable_destination(token) {
                        facts.unknown_writes = true;
                    }
                }
            }
        }
    }
    if facts.establishes_frame_pointer.is_some() {
        facts.written.push(FRAME_POINTER_SLOT);
    }
    Ok(facts)
}

fn is_entry_stub_frame_chain_termination(insn: &DisasmInsn) -> bool {
    let operands: Vec<&str> = split_operands(&insn.operands);
    insn.mnemonic == "mov"
        && operands.first() == Some(&"x29")
        && operands.len() == 2
        && operands.get(1).is_some_and(|immediate: &&str| {
            parse_immediate(immediate).is_ok_and(|value: i64| value == 0)
        })
}

fn is_frame_pair_restore(insn: &DisasmInsn) -> bool {
    let operands: Vec<&str> = split_operands(&insn.operands);
    insn.mnemonic == "ldp"
        && operands.len() >= 3
        && operands.first() == Some(&"x29")
        && operands.get(1) == Some(&"x30")
        && operands
            .get(2)
            .is_some_and(|memory: &&str| memory.trim().starts_with("[sp]"))
}

fn successors(
    insns: &[DisasmInsn],
    index: usize,
    switches: &BTreeMap<usize, SwitchDispatch>,
) -> Result<Vec<usize>> {
    let insn: &DisasmInsn = &insns[index];
    let operands: Vec<&str> = split_operands(&insn.operands);
    let fallthrough: Result<usize> = index
        .checked_add(1)
        .filter(|next: &usize| *next < insns.len())
        .ok_or_else(|| reject_at(insn, "control flow falls off the decoded function"));
    let target: &dyn Fn(Option<&&str>) -> Result<usize> = &|token: Option<&&str>| -> Result<usize> {
        let token: &&str = token.ok_or_else(|| reject_at(insn, "branch lacks a target operand"))?;
        let address: u64 = relative_target(insn, token)?;
        insns
            .binary_search_by_key(&address, |candidate: &DisasmInsn| candidate.address)
            .map_err(|_| reject_at(insn, "branch target is outside the decoded function"))
    };
    if insn.mnemonic == "ret" {
        return Ok(Vec::new());
    }
    if insn.mnemonic == "brk" {
        return Ok(Vec::new());
    }
    if insn.mnemonic == "b" {
        return Ok(vec![target(operands.first())?]);
    }
    if insn.mnemonic.starts_with("b.") {
        return Ok(vec![target(operands.first())?, fallthrough?]);
    }
    if matches!(insn.mnemonic.as_str(), "cbz" | "cbnz") {
        return Ok(vec![target(operands.get(1))?, fallthrough?]);
    }
    if matches!(insn.mnemonic.as_str(), "tbz" | "tbnz") {
        return Ok(vec![target(operands.get(2))?, fallthrough?]);
    }
    if insn.mnemonic == "br" {
        let preceding_frame_restore: bool = index
            .checked_sub(1)
            .and_then(|previous: usize| insns.get(previous))
            .is_some_and(|previous: &DisasmInsn| {
                previous.mnemonic == "ldp" && previous.operands.starts_with("x29, x30, [sp]")
            });
        if preceding_frame_restore {
            return Err(reject_at(
                insn,
                "indirect tail-call epilogue has no recovered target set",
            ));
        }
        let dispatch: &SwitchDispatch = switches
            .get(&index)
            .ok_or_else(|| reject_at(insn, "indirect branch has no recovered target set"))?;
        let mut out: Vec<usize> = Vec::new();
        for address in dispatch
            .cases
            .iter()
            .map(|(_, address): &(i64, u64)| *address)
            .chain(std::iter::once(dispatch.default))
        {
            let resolved: usize = insns
                .binary_search_by_key(&address, |candidate: &DisasmInsn| candidate.address)
                .map_err(|_| reject_at(insn, "switch target is outside the decoded function"))?;
            if !out.contains(&resolved) {
                out.push(resolved);
            }
        }
        return Ok(out);
    }
    Ok(vec![fallthrough?])
}

fn check_stack_offset(value: i64, insn: &DisasmInsn) -> Result<i64> {
    if !(0..=MAX_FRAME_BYTES).contains(&value) || value % STACK_ALIGNMENT != 0 {
        return Err(reject_at(
            insn,
            "stack pointer leaves the bounded aligned frame",
        ));
    }
    Ok(value)
}

fn transfer(state: &StackState, facts: &Facts, insn: &DisasmInsn) -> Result<StackState> {
    let mut next: StackState = state.clone();
    match facts.security_hint {
        Some(SecurityHint::PaciAsp) => {
            if !state.entry_prologue_open || state.sp_to_entry != 0 || state.link_signed {
                return Err(reject_at(insn, "paciasp lies outside the entry prologue"));
            }
            next.link_signed = true;
            next.entry_prologue_open = false;
        }
        Some(SecurityHint::AutiAsp) => {
            if !state.link_signed {
                return Err(reject_at(insn, "autiasp lacks a matching paciasp"));
            }
            next.link_signed = false;
        }
        Some(SecurityHint::BtiC) | None => {}
    }
    if facts.security_hint.is_none() {
        next.entry_prologue_open = false;
    }
    let access_offset: i64 = match facts.sp {
        SpEffect::Delta(delta) if facts.accesses.iter().any(|a: &Access| a.after_writeback) => {
            check_stack_offset(
                state
                    .sp_to_entry
                    .checked_add(delta)
                    .ok_or_else(|| reject_at(insn, "stack pointer overflow"))?,
                insn,
            )?
        }
        _ => state.sp_to_entry,
    };
    for access in &facts.accesses {
        if access.base != Base::Sp {
            continue;
        }
        let start: i64 = access
            .disp
            .checked_sub(access_offset)
            .ok_or_else(|| reject_at(insn, "stack displacement overflow"))?;
        if access.write {
            next.invalidate(start, access.width);
        }
    }
    let mut restored: Vec<usize> = Vec::new();
    if let Some(transfer) = &facts.preserved_transfer {
        let access: &Access = facts
            .accesses
            .first()
            .ok_or_else(|| reject_at(insn, "preserved-register transfer lacks an address"))?;
        if access.base == Base::Sp {
            let start: i64 = access
                .disp
                .checked_sub(access_offset)
                .ok_or_else(|| reject_at(insn, "stack displacement overflow"))?;
            let element: i64 = access.width / i64::try_from(transfer.registers.len()).unwrap_or(1);
            if element == 8 {
                for (position, slot) in transfer.registers.iter().enumerate() {
                    let offset: i64 = start + 8 * i64::try_from(position).unwrap_or(0);
                    if transfer.store {
                        let value: Preserved =
                            *state.preserved.get(*slot).unwrap_or(&Preserved::Opaque);
                        next.saved.insert(offset, value);
                    } else if state.saved.get(&offset) == Some(&Preserved::Entry(*slot)) {
                        restored.push(*slot);
                    }
                }
            }
        }
    }
    for slot in &facts.written {
        if !restored.contains(slot) {
            next.clobber(*slot);
        }
    }
    if facts.unknown_writes {
        for slot in 0..PRESERVED_COUNT {
            next.clobber(slot);
        }
        next.saved.clear();
    }
    for slot in &restored {
        if let Some(cell) = next.preserved.get_mut(*slot) {
            *cell = Preserved::Entry(*slot);
        }
    }
    if facts.calls
        && let Some(cell) = next.preserved.get_mut(LINK_REGISTER_SLOT)
        && *cell != Preserved::Opaque
    {
        *cell = Preserved::CallReturn;
    }
    if let Some(adjustment) = facts.establishes_frame_pointer {
        let offset: i64 = state
            .sp_to_entry
            .checked_sub(adjustment)
            .ok_or_else(|| reject_at(insn, "frame pointer adjustment overflow"))?;
        if !(0..=MAX_FRAME_BYTES).contains(&offset) {
            return Err(reject_at(insn, "frame pointer leaves the bounded frame"));
        }
        next.frame_pointer = FramePointer::At(offset);
    }
    next.sp_to_entry = match facts.sp {
        SpEffect::Unchanged => state.sp_to_entry,
        SpEffect::Delta(delta) => {
            let adjusted: i64 = state
                .sp_to_entry
                .checked_add(delta)
                .ok_or_else(|| reject_at(insn, "stack pointer overflow"))?;
            if is_frame_pair_restore(insn)
                && (!(0..=MAX_FRAME_BYTES).contains(&adjusted) || adjusted % STACK_ALIGNMENT != 0)
            {
                return Err(reject_at(
                    insn,
                    "frame epilogue does not restore the entry stack pointer",
                ));
            }
            check_stack_offset(adjusted, insn)?
        }
        SpEffect::FromFramePointer => match state.frame_pointer {
            FramePointer::At(offset) => check_stack_offset(offset, insn)?,
            FramePointer::Absent | FramePointer::Conflicting => {
                return Err(reject_at(
                    insn,
                    "stack pointer is restored from an unestablished frame pointer",
                ));
            }
        },
    };
    Ok(next)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ByteSpans {
    spans: Vec<(i64, i64)>,
}

impl ByteSpans {
    fn normalize(&mut self) {
        self.spans.sort_unstable();
        let mut merged: Vec<(i64, i64)> = Vec::with_capacity(self.spans.len());
        for span in self.spans.drain(..) {
            match merged.last_mut() {
                Some(last) if span.0 <= last.1 => last.1 = last.1.max(span.1),
                _ => merged.push(span),
            }
        }
        self.spans = merged;
    }

    fn insert(&mut self, start: i64, end: i64) {
        if start >= end {
            return;
        }
        self.spans.push((start, end));
        self.normalize();
    }

    fn intersect(&self, other: &Self) -> Self {
        let mut spans: Vec<(i64, i64)> = Vec::new();
        for left in &self.spans {
            for right in &other.spans {
                let start: i64 = left.0.max(right.0);
                let end: i64 = left.1.min(right.1);
                if start < end {
                    spans.push((start, end));
                }
            }
        }
        let mut out: Self = Self { spans };
        out.normalize();
        out
    }

    fn covers(&self, start: i64, end: i64) -> bool {
        start >= end
            || self
                .spans
                .iter()
                .any(|(low, high): &(i64, i64)| *low <= start && *high >= end)
    }
}

fn definite_writes(
    edges: &[Vec<usize>],
    writes: &BTreeMap<usize, ByteSpans>,
) -> Vec<Option<ByteSpans>> {
    let count: usize = edges.len();
    let mut incoming: Vec<Option<ByteSpans>> = vec![None; count];
    incoming[0] = Some(ByteSpans::default());
    let mut worklist: Vec<usize> = vec![0];
    let mut steps: usize = 0;
    while let Some(index) = worklist.pop() {
        steps += 1;
        if steps > MAX_FIXPOINT_STEPS {
            return vec![None; count];
        }
        let Some(entering): Option<ByteSpans> = incoming[index].clone() else {
            continue;
        };
        let mut leaving: ByteSpans = entering;
        if let Some(spans) = writes.get(&index) {
            for (start, end) in &spans.spans {
                leaving.insert(*start, *end);
            }
        }
        for target in &edges[index] {
            let merged: ByteSpans = incoming[*target].as_ref().map_or_else(
                || leaving.clone(),
                |existing: &ByteSpans| existing.intersect(&leaving),
            );
            if incoming[*target].as_ref() != Some(&merged) {
                incoming[*target] = Some(merged);
                worklist.push(*target);
            }
        }
    }
    incoming
}

pub(super) fn analyze(
    insns: &[DisasmInsn],
    switches: &BTreeMap<usize, SwitchDispatch>,
) -> Result<FrameAnalysis> {
    if insns.iter().any(is_entry_stub_frame_chain_termination)
        && !insns.iter().any(|insn: &DisasmInsn| insn.mnemonic == "ret")
    {
        return Err(reject(
            "entry-stub frame-chain termination has no matching epilogue",
        ));
    }
    let count: usize = insns.len();
    let mut facts: Vec<Facts> = Vec::with_capacity(count);
    for insn in insns {
        facts.push(stack_facts(insn)?);
    }
    for (index, fact) in facts.iter().enumerate() {
        match fact.security_hint {
            Some(SecurityHint::BtiC) if index != 0 => {
                return Err(reject_at(
                    &insns[index],
                    "bti c lies outside the entry landing pad",
                ));
            }
            Some(SecurityHint::PaciAsp)
                if !insns[index + 1..].iter().any(|insn: &DisasmInsn| {
                    insn.mnemonic == "stp" && insn.operands.starts_with("x29, x30, [sp")
                }) =>
            {
                return Err(reject_at(&insns[index], "paciasp lacks a framed prologue"));
            }
            Some(SecurityHint::AutiAsp)
                if insns
                    .get(index + 1)
                    .is_none_or(|insn: &DisasmInsn| insn.mnemonic != "ret") =>
            {
                return Err(reject_at(
                    &insns[index],
                    "autiasp lacks its return epilogue",
                ));
            }
            _ => {}
        }
    }
    let mut edges: Vec<Vec<usize>> = Vec::with_capacity(count);
    for index in 0..count {
        edges.push(successors(insns, index, switches)?);
    }
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (index, targets) in edges.iter().enumerate() {
        for target in targets {
            predecessors[*target].push(index);
        }
    }

    let mut states: Vec<Option<StackState>> = vec![None; count];
    states[0] = Some(StackState::entry());
    let mut worklist: Vec<usize> = vec![0];
    let mut steps: usize = 0;
    while let Some(index) = worklist.pop() {
        steps += 1;
        if steps > MAX_FIXPOINT_STEPS {
            return Err(reject("stack state analysis did not converge"));
        }
        let Some(incoming): Option<StackState> = states[index].clone() else {
            continue;
        };
        let outgoing: StackState = transfer(&incoming, &facts[index], &insns[index])?;
        for target in edges[index].clone() {
            let merged: StackState = match &states[target] {
                None => outgoing.clone(),
                Some(existing) => existing.join(&outgoing, &insns[target])?,
            };
            if states[target].as_ref() != Some(&merged) {
                states[target] = Some(merged);
                worklist.push(target);
            }
        }
    }

    let reachable: BTreeSet<usize> = (0..count)
        .filter(|index: &usize| states[*index].is_some())
        .collect();
    if !reachable.contains(&0) {
        return Err(reject("stack state analysis has no entry state"));
    }
    if let Some(index) = reachable
        .iter()
        .copied()
        .find(|index: &usize| insns[*index].mnemonic == "brk")
    {
        return Err(reject_at(
            &insns[index],
            "non-returning trap has no frame epilogue",
        ));
    }

    let mut management: BTreeSet<usize> = BTreeSet::new();
    let mut absorbed: BTreeSet<usize> = BTreeSet::new();
    let mut writes: BTreeMap<usize, ByteSpans> = BTreeMap::new();
    let mut reads: Vec<(usize, i64, i64)> = Vec::new();
    let mut body_bytes: ByteSpans = ByteSpans::default();
    let mut management_bytes: ByteSpans = ByteSpans::default();
    let mut slot_offsets: BTreeSet<i64> = BTreeSet::new();
    let mut frame_pointer: Option<i64> = None;
    let mut frame_size: i64 = 0;
    let mut saw_return: bool = false;

    for index in reachable.iter().copied() {
        let insn: &DisasmInsn = &insns[index];
        let facts: &Facts = &facts[index];
        let state: &StackState = states[index]
            .as_ref()
            .ok_or_else(|| reject_at(insn, "stack state is missing"))?;
        frame_size = frame_size.max(state.sp_to_entry);
        let access_offset: i64 = match facts.sp {
            SpEffect::Delta(delta) if facts.accesses.iter().any(|a: &Access| a.after_writeback) => {
                state
                    .sp_to_entry
                    .checked_add(delta)
                    .ok_or_else(|| reject_at(insn, "stack pointer overflow"))?
            }
            _ => state.sp_to_entry,
        };
        frame_size = frame_size.max(access_offset);
        if facts.exits {
            saw_return = true;
            if state.link_signed {
                return Err(reject_at(
                    insn,
                    "paciasp has no matching autiasp before the return",
                ));
            }
            if state.sp_to_entry != 0 {
                return Err(reject_at(
                    insn,
                    "stack pointer does not return to its entry value before the return",
                ));
            }
            for slot in 0..PRESERVED_COUNT {
                let value: Preserved = state
                    .preserved
                    .get(slot)
                    .copied()
                    .unwrap_or(Preserved::Opaque);
                let acceptable: bool = value == Preserved::Entry(slot)
                    || (slot == LINK_REGISTER_SLOT && value == Preserved::CallReturn);
                if !acceptable {
                    return Err(reject_at(
                        insn,
                        "a callee-saved register is not provably restored at the return",
                    ));
                }
            }
        }
        if facts.reads_frame_register && matches!(state.frame_pointer, FramePointer::At(_)) {
            return Err(reject_at(
                insn,
                "frame pointer is used outside a modelled frame access",
            ));
        }
        let role: Role = classify_role(state, facts, insn, access_offset, &mut frame_pointer)?;
        match role {
            Role::Management => {
                management.insert(index);
            }
            Role::AbsorbedWriteback => {
                absorbed.insert(index);
            }
            Role::Body => {}
        }
        for access in &facts.accesses {
            let anchor: i64 = match access.base {
                Base::Sp => access_offset,
                Base::FramePointer => match state.frame_pointer {
                    FramePointer::At(offset) => offset,
                    FramePointer::Absent | FramePointer::Conflicting => {
                        return Err(reject_at(
                            insn,
                            "frame-pointer relative access has no established frame pointer",
                        ));
                    }
                },
            };
            let start: i64 = access
                .disp
                .checked_sub(anchor)
                .ok_or_else(|| reject_at(insn, "stack displacement overflow"))?;
            let end: i64 = start
                .checked_add(access.width)
                .ok_or_else(|| reject_at(insn, "stack displacement overflow"))?;
            if start >= 0 {
                if access.write {
                    return Err(reject_at(
                        insn,
                        "a store lands in the incoming-argument area above the entry stack pointer",
                    ));
                }
                if access.base == Base::Sp && matches!(role, Role::Body | Role::AbsorbedWriteback) {
                    slot_offsets.insert(anchor);
                }
                continue;
            }
            if end > 0 {
                return Err(reject_at(
                    insn,
                    "stack access straddles the entry stack pointer",
                ));
            }
            if start < -state.sp_to_entry.max(access_offset) {
                return Err(reject_at(
                    insn,
                    "stack access lands below the allocated frame",
                ));
            }
            if matches!(role, Role::Body | Role::AbsorbedWriteback) {
                if access.base == Base::Sp {
                    slot_offsets.insert(anchor);
                }
                body_bytes.insert(start, end);
                if access.write {
                    writes.entry(index).or_default().insert(start, end);
                } else {
                    reads.push((index, start, end));
                }
            } else {
                management_bytes.insert(start, end);
            }
        }
    }

    if !saw_return {
        return Err(reject("the decoded function never returns"));
    }
    if slot_offsets.len() > 1 {
        return Err(reject(
            "stack slots are accessed at more than one stack-pointer offset",
        ));
    }
    if !body_bytes.intersect(&management_bytes).spans.is_empty() {
        return Err(reject(
            "a data slot overlaps the register-save area the recovery skips",
        ));
    }

    let defined: Vec<Option<ByteSpans>> = definite_writes(&edges, &writes);
    for (index, start, end) in &reads {
        let available: &ByteSpans = defined
            .get(*index)
            .and_then(|entry: &Option<ByteSpans>| entry.as_ref())
            .ok_or_else(|| {
                reject_at(
                    &insns[*index],
                    "a stack slot is read on a path with no definition state",
                )
            })?;
        if !available.covers(*start, *end) {
            return Err(reject_at(
                &insns[*index],
                "a stack slot is read before every path has written it",
            ));
        }
    }

    let canonical: i64 = slot_offsets.iter().copied().next().unwrap_or(frame_size);
    Ok(FrameAnalysis {
        info: FrameInfo {
            sp_to_entry: canonical,
            frame_bytes: frame_size,
            fp_to_entry: frame_pointer,
            sp_writeback_absorbed: false,
        },
        management,
        absorbed,
        reachable,
    })
}

fn classify_role(
    state: &StackState,
    facts: &Facts,
    insn: &DisasmInsn,
    access_offset: i64,
    frame_pointer: &mut Option<i64>,
) -> Result<Role> {
    if facts.establishes_frame_pointer.is_some() || facts.sp == SpEffect::FromFramePointer {
        if let FramePointer::At(offset) = state.frame_pointer
            && facts.sp == SpEffect::FromFramePointer
        {
            record_frame_pointer(frame_pointer, offset, insn)?;
        }
        if let Some(adjustment) = facts.establishes_frame_pointer {
            let offset: i64 = state
                .sp_to_entry
                .checked_sub(adjustment)
                .ok_or_else(|| reject_at(insn, "frame pointer adjustment overflow"))?;
            record_frame_pointer(frame_pointer, offset, insn)?;
        }
        return Ok(Role::Management);
    }
    if let FramePointer::At(offset) = state.frame_pointer
        && facts
            .accesses
            .iter()
            .any(|access: &Access| access.base == Base::FramePointer)
    {
        record_frame_pointer(frame_pointer, offset, insn)?;
    }
    if facts.accesses.is_empty() {
        return Ok(if facts.sp == SpEffect::Unchanged {
            Role::Body
        } else {
            Role::Management
        });
    }
    if let Some(transfer) = &facts.preserved_transfer {
        let access: &Access = facts
            .accesses
            .first()
            .ok_or_else(|| reject_at(insn, "preserved-register transfer lacks an address"))?;
        let element: i64 = access.width / i64::try_from(transfer.registers.len()).unwrap_or(1);
        if access.base == Base::Sp && element == 8 {
            let start: i64 = access
                .disp
                .checked_sub(access_offset)
                .ok_or_else(|| reject_at(insn, "stack displacement overflow"))?;
            let rounds_trip: bool =
                transfer
                    .registers
                    .iter()
                    .enumerate()
                    .all(|(position, slot): (usize, &usize)| {
                        let offset: i64 = start + 8 * i64::try_from(position).unwrap_or(0);
                        if transfer.store {
                            state.preserved.get(*slot) == Some(&Preserved::Entry(*slot))
                        } else {
                            state.saved.get(&offset) == Some(&Preserved::Entry(*slot))
                        }
                    });
            if rounds_trip {
                return Ok(Role::Management);
            }
        }
    }
    Ok(if facts.sp == SpEffect::Unchanged {
        Role::Body
    } else {
        Role::AbsorbedWriteback
    })
}

fn record_frame_pointer(
    frame_pointer: &mut Option<i64>,
    offset: i64,
    insn: &DisasmInsn,
) -> Result<()> {
    match frame_pointer {
        None => {
            *frame_pointer = Some(offset);
            Ok(())
        }
        Some(existing) if *existing == offset => Ok(()),
        Some(_) => Err(reject_at(
            insn,
            "the frame pointer holds more than one offset from the entry stack pointer",
        )),
    }
}
