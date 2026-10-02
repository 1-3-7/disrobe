use std::collections::{BTreeMap, BTreeSet};

use super::{
    Insn, LOP_ADD, LOP_ADDK, LOP_AND, LOP_ANDK, LOP_CALL, LOP_CALLFB, LOP_CAPTURE, LOP_CLOSEUPVALS,
    LOP_CONCAT, LOP_COVERAGE, LOP_DIV, LOP_DIVK, LOP_DIVRK, LOP_DUPCLOSURE, LOP_DUPTABLE,
    LOP_FASTCALL, LOP_FASTCALL1, LOP_FASTCALL2, LOP_FASTCALL2K, LOP_FASTCALL3, LOP_FORGLOOP,
    LOP_FORGPREP, LOP_FORGPREP_INEXT, LOP_FORGPREP_NEXT, LOP_FORNLOOP, LOP_FORNPREP, LOP_GETGLOBAL,
    LOP_GETIMPORT, LOP_GETTABLE, LOP_GETTABLEKS, LOP_GETTABLEN, LOP_GETUPVAL, LOP_GETVARARGS,
    LOP_JUMP, LOP_JUMPBACK, LOP_JUMPIF, LOP_JUMPIFEQ, LOP_JUMPIFLE, LOP_JUMPIFLT, LOP_JUMPIFNOT,
    LOP_JUMPIFNOTEQ, LOP_JUMPIFNOTLE, LOP_JUMPIFNOTLT, LOP_JUMPX, LOP_JUMPXEQKB, LOP_JUMPXEQKN,
    LOP_JUMPXEQKNIL, LOP_JUMPXEQKS, LOP_LENGTH, LOP_LOADB, LOP_LOADK, LOP_LOADKX, LOP_LOADN,
    LOP_LOADNIL, LOP_MINUS, LOP_MOD, LOP_MODK, LOP_MOVE, LOP_MUL, LOP_MULK, LOP_NAMECALL,
    LOP_NATIVECALL, LOP_NEWCLOSURE, LOP_NEWTABLE, LOP_NOP, LOP_NOT, LOP_OR, LOP_ORK, LOP_POW,
    LOP_POWK, LOP_PREPVARARGS, LOP_RETURN, LOP_SETGLOBAL, LOP_SETLIST, LOP_SETTABLE,
    LOP_SETTABLEKS, LOP_SETTABLEN, LOP_SETUPVAL, LOP_SUB, LOP_SUBK, LOP_SUBRK, decode, op_length,
};
use crate::debug::dbg_line;
use crate::reader::common::{LuaConstant, LuaProto, LuaUpvalueName};

const MAX_TRANSLATE_DEPTH: usize = 200;
const MAX_STACK: u32 = 250;
const MAX_RK_INDEX: u32 = 255;
const RK_CONSTANT: u32 = 1 << 8;
const MAX_BX: u32 = (1 << 18) - 1;
const SBX_BIAS: i64 = 0x1FFFF;
const MAX_C: u32 = 511;
const FIELDS_PER_FLUSH: u32 = 50;
const VARARG_ISVARARG: u8 = 2;
const FOR_SCRATCH_WIDTH: u32 = 4;
const FOR_BODY_OFFSET: usize = 4;
const CAPTURE_UPVAL: u8 = 2;
const IMPORT_PATH_MAX: u32 = 3;
const MAX_JUMP_CHAIN: usize = 64;

const MOVE: u32 = 0;
const LOADK: u32 = 1;
const LOADBOOL: u32 = 2;
const LOADNIL: u32 = 3;
const GETUPVAL: u32 = 4;
const GETGLOBAL: u32 = 5;
const GETTABLE: u32 = 6;
const SETGLOBAL: u32 = 7;
const SETUPVAL: u32 = 8;
const SETTABLE: u32 = 9;
const NEWTABLE: u32 = 10;
const SELF: u32 = 11;
const ADD: u32 = 12;
const SUB: u32 = 13;
const MUL: u32 = 14;
const DIV: u32 = 15;
const MOD: u32 = 16;
const POW: u32 = 17;
const UNM: u32 = 18;
const NOT: u32 = 19;
const LEN: u32 = 20;
const CONCAT: u32 = 21;
const JMP: u32 = 22;
const EQ: u32 = 23;
const LT: u32 = 24;
const LE: u32 = 25;
const TEST: u32 = 26;
const TESTSET: u32 = 27;
const CALL: u32 = 28;
const RETURN: u32 = 30;
const FORLOOP: u32 = 31;
const FORPREP: u32 = 32;
const TFORLOOP: u32 = 33;
const SETLIST: u32 = 34;
const CLOSE: u32 = 35;
const CLOSURE: u32 = 36;
const VARARG: u32 = 37;

#[derive(Debug, Clone, Copy)]
struct Target {
    luau_pc: usize,
    offset: usize,
}

#[derive(Debug, Clone, Copy)]
enum Word {
    Ready(u32),
    Jump { op: u32, a: u32, target: Target },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ConstKey {
    Nil,
    Bool(bool),
    Number(u64),
}

struct Item {
    luau_pc: usize,
    words: Vec<Word>,
    skip_bool: Option<(u32, u32, usize)>,
}

struct ProtoTranslation<'p> {
    proto: &'p LuaProto,
    constants: Vec<LuaConstant>,
    known: BTreeMap<ConstKey, u32>,
    scratch: u32,
    next_loop_base: u32,
    open_loops: BTreeMap<usize, (u32, usize)>,
    loop_ends: BTreeMap<usize, usize>,
    rethreaded: BTreeMap<usize, usize>,
    reachable: Vec<bool>,
    flipped: BTreeSet<usize>,
    elided: BTreeSet<usize>,
    captures: BTreeMap<usize, usize>,
}

pub(crate) fn translate(main: &LuaProto) -> Option<LuaProto> {
    translate_proto(main, main.upvalues.len(), 0)
}

fn refuse<T>(pc: usize, why: &str) -> Option<T> {
    dbg_line(|| format!("luau translation refused at pc {pc}: {why}"));
    None
}

#[must_use]
const fn abc(op: u32, a: u32, b: u32, c: u32) -> u32 {
    op | (a << 6) | (c << 14) | (b << 23)
}

#[must_use]
const fn abx(op: u32, a: u32, bx: u32) -> u32 {
    op | (a << 6) | (bx << 14)
}

fn translate_proto(p: &LuaProto, upvalue_count: usize, depth: usize) -> Option<LuaProto> {
    if depth > MAX_TRANSLATE_DEPTH {
        return refuse(0, "prototype nesting too deep");
    }
    let mut known: BTreeMap<ConstKey, u32> = BTreeMap::new();
    for (index, constant) in p.constants.iter().enumerate() {
        let key: Option<ConstKey> = match constant {
            LuaConstant::Nil => Some(ConstKey::Nil),
            LuaConstant::Bool(value) => Some(ConstKey::Bool(*value)),
            LuaConstant::Number(value) => Some(ConstKey::Number(value.to_bits())),
            _ => None,
        };
        if let (Some(key), Ok(index)) = (key, u32::try_from(index)) {
            known.entry(key).or_insert(index);
        }
    }
    let base: u32 = u32::from(p.max_stack_size);
    let mut t: ProtoTranslation<'_> = ProtoTranslation {
        proto: p,
        constants: p.constants.clone(),
        known,
        scratch: base,
        next_loop_base: base + 1,
        open_loops: BTreeMap::new(),
        loop_ends: BTreeMap::new(),
        rethreaded: BTreeMap::new(),
        reachable: Vec::new(),
        flipped: BTreeSet::new(),
        elided: BTreeSet::new(),
        captures: BTreeMap::new(),
    };
    let items: Vec<Item> = t.lower_all()?;
    let code: Vec<u32> = resolve(items, p.code.len())?;
    let mut protos: Vec<LuaProto> = Vec::with_capacity(p.protos.len());
    for (index, child) in p.protos.iter().enumerate() {
        let count: usize = t
            .captures
            .get(&index)
            .copied()
            .unwrap_or(child.upvalues.len());
        protos.push(translate_proto(child, count, depth + 1)?);
    }
    let upvalues: Vec<LuaUpvalueName> = if p.upvalues.len() == upvalue_count {
        p.upvalues.clone()
    } else {
        (0..upvalue_count)
            .map(|_| LuaUpvalueName {
                name: String::new(),
                descriptor: None,
            })
            .collect()
    };
    let max_stack_size: u8 = u8::try_from(t.next_loop_base).ok()?;
    Some(LuaProto {
        source: p.source.clone(),
        line_defined: p.line_defined,
        last_line_defined: p.last_line_defined,
        num_params: p.num_params,
        is_vararg: if p.is_vararg != 0 { VARARG_ISVARARG } else { 0 },
        max_stack_size,
        code,
        constants: t.constants,
        protos,
        source_lines: Vec::new(),
        locals: Vec::new(),
        upvalues,
    })
}

fn resolve(mut items: Vec<Item>, code_len: usize) -> Option<Vec<u32>> {
    for index in (0..items.len()).rev() {
        let Some((a, b, target)) = items[index].skip_bool else {
            continue;
        };
        let after_next: usize = items
            .get(index + 2)
            .map_or(code_len, |item: &Item| item.luau_pc);
        let next_is_one_word: bool = items
            .get(index + 1)
            .is_some_and(|item: &Item| item.words.len() == 1);
        if next_is_one_word && target == after_next {
            items[index].words = vec![Word::Ready(abc(LOADBOOL, a, b, 1))];
        }
    }
    let mut new_pc: Vec<Option<usize>> = vec![None; code_len + 1];
    let mut total: usize = 0;
    for item in &items {
        if let Some(slot) = new_pc.get_mut(item.luau_pc) {
            *slot = Some(total);
        }
        total += item.words.len();
    }
    if let Some(slot) = new_pc.get_mut(code_len) {
        *slot = Some(total);
    }
    let mut code: Vec<u32> = Vec::with_capacity(total);
    for item in &items {
        for word in &item.words {
            let raw: u32 = match *word {
                Word::Ready(raw) => raw,
                Word::Jump { op, a, target } => {
                    let Some(Some(landing)) = new_pc.get(target.luau_pc).copied() else {
                        return refuse(item.luau_pc, "jump into the middle of an instruction");
                    };
                    let landing: i64 = i64::try_from(landing + target.offset).ok()?;
                    let here: i64 = i64::try_from(code.len()).ok()?;
                    let sbx: i64 = landing - (here + 1);
                    if !(-SBX_BIAS..=SBX_BIAS).contains(&sbx) {
                        return refuse(item.luau_pc, "jump distance exceeds the Lua 5.1 range");
                    }
                    let bx: u32 = u32::try_from(sbx + SBX_BIAS).ok()?;
                    abx(op, a, bx)
                }
            };
            code.push(raw);
        }
    }
    Some(code)
}

impl ProtoTranslation<'_> {
    fn lower_all(&mut self) -> Option<Vec<Item>> {
        let code: &[u32] = &self.proto.code;
        let mut pc: usize = 0;
        while pc < code.len() {
            let inst: Insn = decode(code[pc]);
            if inst.op == LOP_FORNLOOP
                && let Some(body) = self.target(pc, inst.d)
                && self.loop_ends.insert(body, pc).is_some()
            {
                return refuse(pc, "two numeric loops share one body");
            }
            pc += op_length(inst.op);
        }
        self.rethread_loop_exits()?;
        self.reachable = self.reachability();
        self.fold_jumps_over_jumps();
        let mut items: Vec<Item> = Vec::new();
        pc = 0;
        let mut consumed_until: usize = 0;
        while pc < code.len() {
            let inst: Insn = decode(code[pc]);
            let length: usize = op_length(inst.op);
            if pc + length > code.len() {
                return refuse(pc, "instruction runs past the end of the code");
            }
            let aux: u32 = if length == 2 { code[pc + 1] } else { 0 };
            let mut item: Item = Item {
                luau_pc: pc,
                words: Vec::new(),
                skip_bool: None,
            };
            if pc >= consumed_until
                && self.reachable.get(pc).copied().unwrap_or(false)
                && !self.elided.contains(&pc)
            {
                let captured: usize = self.lower(pc, inst, aux, &mut item)?;
                consumed_until = pc + length + captured;
            }
            items.push(item);
            pc += length;
        }
        if self.next_loop_base > MAX_STACK {
            return refuse(0, "register frame exceeds the Lua 5.1 limit");
        }
        if !self.open_loops.is_empty() {
            return refuse(0, "numeric loop without its closing instruction");
        }
        Some(items)
    }

    fn successors(&self, pc: usize, inst: Insn) -> Vec<usize> {
        let next: usize = pc + op_length(inst.op);
        let jump: Option<usize> = match inst.op {
            LOP_JUMPX => self.target(pc, inst.e),
            LOP_LOADB if inst.c != 0 => self.target(pc, i32::from(inst.c)),
            _ => self.target(pc, inst.d),
        };
        let jump: Option<usize> = self.rethreaded.get(&pc).copied().or(jump);
        let mut found: Vec<usize> = match inst.op {
            LOP_JUMP | LOP_JUMPBACK | LOP_JUMPX | LOP_FORGPREP | LOP_FORGPREP_INEXT
            | LOP_FORGPREP_NEXT => jump.into_iter().collect(),
            LOP_LOADB if inst.c != 0 => jump.into_iter().collect(),
            LOP_RETURN => Vec::new(),
            LOP_JUMPIF | LOP_JUMPIFNOT | LOP_JUMPIFEQ | LOP_JUMPIFNOTEQ | LOP_JUMPIFLT
            | LOP_JUMPIFNOTLT | LOP_JUMPIFLE | LOP_JUMPIFNOTLE | LOP_JUMPXEQKNIL
            | LOP_JUMPXEQKB | LOP_JUMPXEQKN | LOP_JUMPXEQKS | LOP_FORNLOOP | LOP_FORGLOOP => {
                std::iter::once(next).chain(jump).collect()
            }
            LOP_FORNPREP => std::iter::once(next)
                .chain(jump)
                .chain(self.loop_ends.get(&(pc + 1)).copied())
                .collect(),
            _ => vec![next],
        };
        found.retain(|successor: &usize| *successor < self.proto.code.len());
        found
    }

    fn reachability(&self) -> Vec<bool> {
        let code: &[u32] = &self.proto.code;
        let mut seen: Vec<bool> = vec![false; code.len()];
        let mut work: Vec<usize> = Vec::new();
        if !code.is_empty() {
            work.push(0);
        }
        while let Some(pc) = work.pop() {
            match seen.get_mut(pc) {
                Some(flag) if !*flag => *flag = true,
                _ => continue,
            }
            let inst: Insn = decode(code[pc]);
            work.extend(self.successors(pc, inst));
        }
        seen
    }

    fn next_reachable(&self, pc: usize) -> Option<usize> {
        (pc..self.proto.code.len())
            .find(|at: &usize| self.reachable.get(*at).copied().unwrap_or(false))
    }

    fn effective_target(&self, pc: usize, inst: Insn) -> Option<usize> {
        let offset: i32 = if inst.op == LOP_JUMPX { inst.e } else { inst.d };
        self.rethreaded
            .get(&pc)
            .copied()
            .or_else(|| self.target(pc, offset))
    }

    fn fold_jumps_over_jumps(&mut self) {
        let code: &[u32] = &self.proto.code;
        let mut predecessors: Vec<u32> = vec![0; code.len()];
        for (pc, raw) in code.iter().enumerate() {
            if self.reachable.get(pc).copied().unwrap_or(false) {
                for successor in self.successors(pc, decode(*raw)) {
                    if let Some(count) = predecessors.get_mut(successor) {
                        *count = count.saturating_add(1);
                    }
                }
            }
        }
        let mut folds: Vec<(usize, usize, usize)> = Vec::new();
        for (pc, raw) in code.iter().enumerate() {
            let inst: Insn = decode(*raw);
            let conditional: bool = matches!(
                inst.op,
                LOP_JUMPIF
                    | LOP_JUMPIFNOT
                    | LOP_JUMPIFEQ
                    | LOP_JUMPIFNOTEQ
                    | LOP_JUMPIFLT
                    | LOP_JUMPIFNOTLT
                    | LOP_JUMPIFLE
                    | LOP_JUMPIFNOTLE
                    | LOP_JUMPXEQKNIL
                    | LOP_JUMPXEQKB
                    | LOP_JUMPXEQKN
                    | LOP_JUMPXEQKS
            );
            if !conditional || !self.reachable.get(pc).copied().unwrap_or(false) {
                continue;
            }
            let Some(over) = self.next_reachable(pc + op_length(inst.op)) else {
                continue;
            };
            let skip: Insn = decode(code[over]);
            if !matches!(skip.op, LOP_JUMP | LOP_JUMPX)
                || predecessors.get(over).copied() != Some(1)
            {
                continue;
            }
            let (Some(taken), Some(other)) = (
                self.effective_target(pc, inst),
                self.effective_target(over, skip),
            ) else {
                continue;
            };
            if other > over && Some(taken) == self.next_reachable(over + 1) {
                folds.push((pc, over, other));
            }
        }
        for (pc, over, other) in folds {
            self.rethreaded.insert(pc, other);
            self.flipped.insert(pc);
            self.elided.insert(over);
        }
    }

    fn falls_through_to(&self, pc: usize, landing: usize) -> bool {
        landing > pc
            && (pc + 1..landing)
                .all(|between: usize| !self.reachable.get(between).copied().unwrap_or(false))
    }

    fn jumps(&self) -> Vec<(usize, usize, bool)> {
        let code: &[u32] = &self.proto.code;
        let mut found: Vec<(usize, usize, bool)> = Vec::new();
        let mut pc: usize = 0;
        while pc < code.len() {
            let inst: Insn = decode(code[pc]);
            let offset: Option<i32> = match inst.op {
                LOP_JUMP | LOP_JUMPBACK | LOP_JUMPIF | LOP_JUMPIFNOT | LOP_JUMPIFEQ
                | LOP_JUMPIFNOTEQ | LOP_JUMPIFLT | LOP_JUMPIFNOTLT | LOP_JUMPIFLE
                | LOP_JUMPIFNOTLE | LOP_JUMPXEQKNIL | LOP_JUMPXEQKB | LOP_JUMPXEQKN
                | LOP_JUMPXEQKS | LOP_FORNLOOP | LOP_FORGLOOP => Some(inst.d),
                LOP_JUMPX => Some(inst.e),
                _ => None,
            };
            if let Some(landing) = offset.and_then(|offset: i32| self.target(pc, offset)) {
                let unconditional: bool = matches!(inst.op, LOP_JUMP | LOP_JUMPBACK | LOP_JUMPX);
                found.push((pc, landing, unconditional));
            }
            pc += op_length(inst.op);
        }
        found
    }

    fn rethread_loop_exits(&mut self) -> Option<()> {
        let jumps: Vec<(usize, usize, bool)> = self.jumps();
        let mut loops: BTreeMap<usize, usize> = BTreeMap::new();
        for (pc, landing, _) in &jumps {
            if *landing <= *pc {
                let exit: usize = pc + op_length(decode(self.proto.code[*pc]).op);
                let slot: &mut usize = loops.entry(*landing).or_insert(exit);
                *slot = (*slot).max(exit);
            }
        }
        let unconditional: BTreeMap<usize, usize> = jumps
            .iter()
            .filter(|(_, _, plain): &&(usize, usize, bool)| *plain)
            .map(|(pc, landing, _): &(usize, usize, bool)| (*pc, *landing))
            .collect();
        let mut open: Vec<(usize, usize)> = Vec::new();
        let mut pending: std::iter::Peekable<std::collections::btree_map::IntoIter<usize, usize>> =
            loops.into_iter().peekable();
        for (pc, landing, _) in &jumps {
            while let Some((head, exit)) = pending.next_if(|(head, _): &(usize, usize)| head <= pc)
            {
                while open
                    .last()
                    .is_some_and(|(_, inner): &(usize, usize)| *inner <= head)
                {
                    open.pop();
                }
                if open
                    .last()
                    .is_some_and(|(_, outer): &(usize, usize)| *outer < exit)
                {
                    return refuse(head, "loops overlap without nesting");
                }
                open.push((head, exit));
            }
            while open
                .last()
                .is_some_and(|(_, exit): &(usize, usize)| exit <= pc)
            {
                open.pop();
            }
            let Some(&(head, exit)) = open.last() else {
                continue;
            };
            if *landing >= head && *landing <= exit {
                continue;
            }
            let mut through: usize = exit;
            for _ in 0..MAX_JUMP_CHAIN {
                if through == *landing {
                    self.rethreaded.insert(*pc, exit);
                    break;
                }
                match unconditional.get(&through) {
                    Some(next) => through = *next,
                    None => break,
                }
            }
        }
        Some(())
    }

    fn constant(&mut self, key: ConstKey) -> u32 {
        if let Some(index) = self.known.get(&key) {
            return *index;
        }
        let index: u32 = u32::try_from(self.constants.len()).unwrap_or(u32::MAX);
        self.constants.push(match key {
            ConstKey::Nil => LuaConstant::Nil,
            ConstKey::Bool(value) => LuaConstant::Bool(value),
            ConstKey::Number(bits) => LuaConstant::Number(f64::from_bits(bits)),
        });
        self.known.insert(key, index);
        index
    }

    fn number(&mut self, value: f64) -> u32 {
        self.constant(ConstKey::Number(value.to_bits()))
    }

    fn rk(&self, index: u32, words: &mut Vec<Word>) -> Option<u32> {
        if index <= MAX_RK_INDEX {
            return Some(RK_CONSTANT | index);
        }
        if index > MAX_BX {
            return None;
        }
        words.push(Word::Ready(abx(LOADK, self.scratch, index)));
        Some(self.scratch)
    }

    fn constant_is(&self, index: u32, accept: fn(&LuaConstant) -> bool) -> bool {
        self.proto.constants.get(index as usize).is_some_and(accept)
    }

    fn target(&self, pc: usize, offset: i32) -> Option<usize> {
        let landing: i64 = i64::try_from(pc).ok()? + 1 + i64::from(offset);
        let landing: usize = usize::try_from(landing).ok()?;
        (landing < self.proto.code.len()).then_some(landing)
    }

    fn jump(
        &self,
        pc: usize,
        offset: i32,
        unconditional: bool,
        words: &mut Vec<Word>,
    ) -> Option<()> {
        let Some(landing) = self.target(pc, offset) else {
            return refuse(pc, "jump target outside the function");
        };
        let landing: usize = self.rethreaded.get(&pc).copied().unwrap_or(landing);
        if unconditional && self.falls_through_to(pc, landing) {
            return Some(());
        }
        words.push(Word::Jump {
            op: JMP,
            a: 0,
            target: Target {
                luau_pc: landing,
                offset: 0,
            },
        });
        Some(())
    }

    #[allow(clippy::too_many_lines)]
    fn lower(&mut self, pc: usize, inst: Insn, aux: u32, item: &mut Item) -> Option<usize> {
        let a: u32 = u32::from(inst.a);
        let b: u32 = u32::from(inst.b);
        let c: u32 = u32::from(inst.c);
        let flip: u32 = u32::from(self.flipped.contains(&pc));
        let words: &mut Vec<Word> = &mut item.words;
        match inst.op {
            LOP_NOP | LOP_COVERAGE | LOP_PREPVARARGS | LOP_NATIVECALL | LOP_FASTCALL
            | LOP_FASTCALL1 | LOP_FASTCALL2 | LOP_FASTCALL2K | LOP_FASTCALL3 => {}
            LOP_LOADNIL => words.push(Word::Ready(abc(LOADNIL, a, a, 0))),
            LOP_LOADB => {
                let value: u32 = u32::from(b != 0);
                words.push(Word::Ready(abc(LOADBOOL, a, value, 0)));
                if c != 0 {
                    self.jump(pc, i32::from(inst.c), false, words)?;
                    item.skip_bool = Some((a, value, self.target(pc, i32::from(inst.c))?));
                }
            }
            LOP_LOADN => {
                let k: u32 = self.number(f64::from(inst.d));
                if k > MAX_BX {
                    return refuse(pc, "constant index exceeds the Lua 5.1 range");
                }
                words.push(Word::Ready(abx(LOADK, a, k)));
            }
            LOP_LOADK | LOP_LOADKX => {
                let k: u32 = if inst.op == LOP_LOADK {
                    u32::try_from(inst.d).unwrap_or(u32::MAX)
                } else {
                    aux
                };
                if k > MAX_BX || !self.constant_is(k, is_plain_value) {
                    return refuse(pc, "constant load the Lua 5.1 lifter cannot express");
                }
                words.push(Word::Ready(abx(LOADK, a, k)));
            }
            LOP_MOVE => words.push(Word::Ready(abc(MOVE, a, b, 0))),
            LOP_GETGLOBAL | LOP_SETGLOBAL => {
                if aux > MAX_BX || !self.constant_is(aux, is_string) {
                    return refuse(pc, "global name is not a string constant");
                }
                let op: u32 = if inst.op == LOP_GETGLOBAL {
                    GETGLOBAL
                } else {
                    SETGLOBAL
                };
                words.push(Word::Ready(abx(op, a, aux)));
            }
            LOP_GETUPVAL => words.push(Word::Ready(abc(GETUPVAL, a, b, 0))),
            LOP_SETUPVAL => words.push(Word::Ready(abc(SETUPVAL, a, b, 0))),
            LOP_CLOSEUPVALS => words.push(Word::Ready(abc(CLOSE, a, 0, 0))),
            LOP_GETIMPORT => {
                let count: u32 = aux >> 30;
                if count == 0 || count > IMPORT_PATH_MAX {
                    return refuse(pc, "import path length");
                }
                let ids: [u32; 3] = [(aux >> 20) & 0x3FF, (aux >> 10) & 0x3FF, aux & 0x3FF];
                for (position, id) in ids.iter().take(count as usize).enumerate() {
                    if !self.constant_is(*id, is_string) {
                        return refuse(pc, "import path is not made of string constants");
                    }
                    if position == 0 {
                        words.push(Word::Ready(abx(GETGLOBAL, a, *id)));
                    } else {
                        let key: u32 = self.rk(*id, words)?;
                        words.push(Word::Ready(abc(GETTABLE, a, a, key)));
                    }
                }
            }
            LOP_GETTABLE => words.push(Word::Ready(abc(GETTABLE, a, b, c))),
            LOP_SETTABLE => words.push(Word::Ready(abc(SETTABLE, b, c, a))),
            LOP_GETTABLEKS | LOP_SETTABLEKS | LOP_NAMECALL => {
                if !self.constant_is(aux, is_string) {
                    return refuse(pc, "field name is not a string constant");
                }
                let Some(key) = self.rk(aux, words) else {
                    return refuse(pc, "constant index exceeds the Lua 5.1 range");
                };
                let raw: u32 = match inst.op {
                    LOP_GETTABLEKS => abc(GETTABLE, a, b, key),
                    LOP_SETTABLEKS => abc(SETTABLE, b, key, a),
                    _ => abc(SELF, a, b, key),
                };
                words.push(Word::Ready(raw));
            }
            LOP_GETTABLEN | LOP_SETTABLEN => {
                let k: u32 = self.number(f64::from(c + 1));
                let Some(key) = self.rk(k, words) else {
                    return refuse(pc, "constant index exceeds the Lua 5.1 range");
                };
                let raw: u32 = if inst.op == LOP_GETTABLEN {
                    abc(GETTABLE, a, b, key)
                } else {
                    abc(SETTABLE, b, key, a)
                };
                words.push(Word::Ready(raw));
            }
            LOP_NEWCLOSURE | LOP_DUPCLOSURE => return self.closure(pc, inst, words),
            LOP_CALL | LOP_CALLFB => words.push(Word::Ready(abc(CALL, a, b, c))),
            LOP_RETURN => words.push(Word::Ready(abc(RETURN, a, b, 0))),
            LOP_JUMP | LOP_JUMPBACK => self.jump(pc, inst.d, true, words)?,
            LOP_JUMPX => self.jump(pc, inst.e, true, words)?,
            LOP_JUMPIF | LOP_JUMPIFNOT => {
                let expect: u32 = u32::from(inst.op == LOP_JUMPIF) ^ flip;
                words.push(Word::Ready(abc(TEST, a, 0, expect)));
                self.jump(pc, inst.d, false, words)?;
            }
            LOP_JUMPIFEQ | LOP_JUMPIFNOTEQ | LOP_JUMPIFLT | LOP_JUMPIFNOTLT | LOP_JUMPIFLE
            | LOP_JUMPIFNOTLE => {
                if aux > MAX_RK_INDEX {
                    return refuse(pc, "comparison operand is not a register");
                }
                let (op, expect): (u32, u32) = match inst.op {
                    LOP_JUMPIFEQ => (EQ, 1),
                    LOP_JUMPIFNOTEQ => (EQ, 0),
                    LOP_JUMPIFLT => (LT, 1),
                    LOP_JUMPIFNOTLT => (LT, 0),
                    LOP_JUMPIFLE => (LE, 1),
                    _ => (LE, 0),
                };
                words.push(Word::Ready(abc(op, expect ^ flip, a, aux)));
                self.jump(pc, inst.d, false, words)?;
            }
            LOP_JUMPXEQKNIL | LOP_JUMPXEQKB | LOP_JUMPXEQKN | LOP_JUMPXEQKS => {
                let k: u32 = match inst.op {
                    LOP_JUMPXEQKNIL => self.constant(ConstKey::Nil),
                    LOP_JUMPXEQKB => self.constant(ConstKey::Bool(aux & 1 != 0)),
                    _ => {
                        let index: u32 = aux & 0x00FF_FFFF;
                        let accept: fn(&LuaConstant) -> bool = if inst.op == LOP_JUMPXEQKN {
                            is_number
                        } else {
                            is_string
                        };
                        if !self.constant_is(index, accept) {
                            return refuse(pc, "comparison constant has the wrong type");
                        }
                        index
                    }
                };
                let Some(operand) = self.rk(k, words) else {
                    return refuse(pc, "constant index exceeds the Lua 5.1 range");
                };
                let expect: u32 = u32::from(aux >> 31 == 0) ^ flip;
                words.push(Word::Ready(abc(EQ, expect, a, operand)));
                self.jump(pc, inst.d, false, words)?;
            }
            LOP_ADD | LOP_SUB | LOP_MUL | LOP_DIV | LOP_MOD | LOP_POW => {
                words.push(Word::Ready(abc(arith(inst.op), a, b, c)));
            }
            LOP_ADDK | LOP_SUBK | LOP_MULK | LOP_DIVK | LOP_MODK | LOP_POWK => {
                if !self.constant_is(c, is_number) {
                    return refuse(pc, "arithmetic constant is not a number");
                }
                let operand: u32 = RK_CONSTANT | c;
                words.push(Word::Ready(abc(arith(inst.op), a, b, operand)));
            }
            LOP_SUBRK | LOP_DIVRK => {
                if !self.constant_is(b, is_number) {
                    return refuse(pc, "arithmetic constant is not a number");
                }
                let op: u32 = if inst.op == LOP_SUBRK { SUB } else { DIV };
                words.push(Word::Ready(abc(op, a, RK_CONSTANT | b, c)));
            }
            LOP_AND | LOP_OR | LOP_ANDK | LOP_ORK => {
                let keep_when_truthy: u32 = u32::from(matches!(inst.op, LOP_OR | LOP_ORK));
                let register_operand: bool = matches!(inst.op, LOP_AND | LOP_OR);
                let test: u32 = if a == b {
                    abc(TEST, a, 0, keep_when_truthy)
                } else if register_operand && a == c {
                    abc(TESTSET, a, b, keep_when_truthy)
                } else {
                    words.push(Word::Ready(abc(MOVE, a, b, 0)));
                    abc(TEST, a, 0, keep_when_truthy)
                };
                let second: u32 = if register_operand {
                    abc(MOVE, a, c, 0)
                } else {
                    if !self.constant_is(c, is_plain_value) {
                        return refuse(pc, "logical constant the Lua 5.1 lifter cannot express");
                    }
                    abx(LOADK, a, c)
                };
                words.push(Word::Ready(test));
                words.push(Word::Jump {
                    op: JMP,
                    a: 0,
                    target: Target {
                        luau_pc: pc + 1,
                        offset: 0,
                    },
                });
                words.push(Word::Ready(second));
            }
            LOP_CONCAT => words.push(Word::Ready(abc(CONCAT, a, b, c))),
            LOP_NOT => words.push(Word::Ready(abc(NOT, a, b, 0))),
            LOP_MINUS => words.push(Word::Ready(abc(UNM, a, b, 0))),
            LOP_LENGTH => words.push(Word::Ready(abc(LEN, a, b, 0))),
            LOP_NEWTABLE | LOP_DUPTABLE => words.push(Word::Ready(abc(NEWTABLE, a, 0, 0))),
            LOP_SETLIST => self.set_list(pc, a, b, c, aux, words)?,
            LOP_GETVARARGS => words.push(Word::Ready(abc(VARARG, a, b, 0))),
            LOP_FORNPREP => self.numeric_prep(pc, inst, words)?,
            LOP_FORNLOOP => {
                let Some((scratch, prep)) = self.open_loops.remove(&pc) else {
                    return refuse(pc, "numeric loop end without its opening instruction");
                };
                words.push(Word::Jump {
                    op: FORLOOP,
                    a: scratch,
                    target: Target {
                        luau_pc: prep,
                        offset: FOR_BODY_OFFSET,
                    },
                });
            }
            LOP_FORGPREP | LOP_FORGPREP_INEXT | LOP_FORGPREP_NEXT => {
                let Some(control) = self.target(pc, inst.d) else {
                    return refuse(pc, "generic loop target outside the function");
                };
                let closes: bool = self.proto.code.get(control).is_some_and(|raw: &u32| {
                    let next: Insn = decode(*raw);
                    next.op == LOP_FORGLOOP && next.a == inst.a
                });
                if !closes {
                    return refuse(pc, "generic loop without its closing instruction");
                }
                self.jump(pc, inst.d, false, words)?;
            }
            LOP_FORGLOOP => {
                let vars: u32 = aux & 0xFF;
                if vars == 0 {
                    return refuse(pc, "generic loop without variables");
                }
                words.push(Word::Ready(abc(TFORLOOP, a, 0, vars)));
                self.jump(pc, inst.d, false, words)?;
            }
            LOP_CAPTURE => return refuse(pc, "capture outside a closure"),
            _ => return refuse(pc, "opcode the Lua 5.1 lifter cannot express"),
        }
        Some(0)
    }

    fn set_list(
        &mut self,
        pc: usize,
        a: u32,
        b: u32,
        c: u32,
        aux: u32,
        words: &mut Vec<Word>,
    ) -> Option<()> {
        let count: Option<u32> = c.checked_sub(1);
        let Some(first) = aux.checked_sub(1) else {
            return refuse(pc, "array batch starts before index 1");
        };
        let block: u32 = first / FIELDS_PER_FLUSH + 1;
        if first % FIELDS_PER_FLUSH == 0 && block <= MAX_C {
            match count {
                Some(0) => {}
                None if b == a + 1 => words.push(Word::Ready(abc(SETLIST, a, 0, block))),
                Some(values) if b > a => {
                    for offset in 0..values {
                        if b != a + 1 {
                            words.push(Word::Ready(abc(MOVE, a + 1 + offset, b + offset, 0)));
                        }
                    }
                    words.push(Word::Ready(abc(SETLIST, a, values, block)));
                }
                _ => return refuse(pc, "array batch the Lua 5.1 layout cannot express"),
            }
            return Some(());
        }
        let Some(values) = count else {
            return refuse(pc, "open array batch past the first Lua 5.1 flush");
        };
        for offset in 0..values {
            let Some(index) = aux.checked_add(offset) else {
                return refuse(pc, "array index overflows");
            };
            let k: u32 = self.number(f64::from(index));
            let Some(key) = self.rk(k, words) else {
                return refuse(pc, "constant index exceeds the Lua 5.1 range");
            };
            words.push(Word::Ready(abc(SETTABLE, a, key, b + offset)));
        }
        Some(())
    }

    fn numeric_prep(&mut self, pc: usize, inst: Insn, words: &mut Vec<Word>) -> Option<()> {
        let a: u32 = u32::from(inst.a);
        let Some(exit) = self.target(pc, inst.d) else {
            return refuse(pc, "numeric loop exit outside the function");
        };
        let a_matches: bool = self
            .loop_ends
            .get(&(pc + 1))
            .and_then(|end: &usize| self.proto.code.get(*end))
            .is_some_and(|raw: &u32| decode(*raw).a == inst.a);
        if !a_matches {
            return refuse(pc, "numeric loop closes on another register");
        }
        let closing: Option<usize> = self
            .loop_ends
            .get(&(pc + 1))
            .copied()
            .filter(|end: &usize| *end < exit);
        let Some(closing) = closing else {
            return refuse(pc, "numeric loop without its closing instruction");
        };
        let scratch: u32 = self.next_loop_base;
        self.next_loop_base += FOR_SCRATCH_WIDTH;
        self.open_loops.insert(closing, (scratch, pc));
        words.push(Word::Ready(abc(MOVE, scratch, a + 2, 0)));
        words.push(Word::Ready(abc(MOVE, scratch + 1, a, 0)));
        words.push(Word::Ready(abc(MOVE, scratch + 2, a + 1, 0)));
        words.push(Word::Jump {
            op: FORPREP,
            a: scratch,
            target: Target {
                luau_pc: closing,
                offset: 0,
            },
        });
        words.push(Word::Ready(abc(MOVE, a + 2, scratch + 3, 0)));
        Some(())
    }

    fn closure(&mut self, pc: usize, inst: Insn, words: &mut Vec<Word>) -> Option<usize> {
        let child: usize = if inst.op == LOP_DUPCLOSURE {
            match self.proto.constants.get(usize::try_from(inst.d).ok()?) {
                Some(LuaConstant::ClosureRef(slot)) => usize::try_from(*slot).ok()?,
                _ => return refuse(pc, "closure constant does not name a prototype"),
            }
        } else {
            usize::try_from(inst.d).ok()?
        };
        let index: u32 = u32::try_from(child).ok()?;
        if child >= self.proto.protos.len() || index > MAX_BX {
            return refuse(pc, "closure prototype index out of range");
        }
        words.push(Word::Ready(abx(CLOSURE, u32::from(inst.a), index)));
        let mut count: usize = 0;
        while let Some(raw) = self.proto.code.get(pc + 1 + count) {
            let capture: Insn = decode(*raw);
            if capture.op != LOP_CAPTURE {
                break;
            }
            let op: u32 = if capture.a == CAPTURE_UPVAL {
                GETUPVAL
            } else {
                MOVE
            };
            words.push(Word::Ready(abc(op, 0, u32::from(capture.b), 0)));
            count += 1;
        }
        match self.captures.get(&child) {
            Some(previous) if *previous != count => {
                return refuse(pc, "prototype instantiated with different capture counts");
            }
            _ => {
                self.captures.insert(child, count);
            }
        }
        Some(count)
    }
}

#[must_use]
const fn arith(op: u8) -> u32 {
    match op {
        LOP_ADD | LOP_ADDK => ADD,
        LOP_SUB | LOP_SUBK => SUB,
        LOP_MUL | LOP_MULK => MUL,
        LOP_DIV | LOP_DIVK => DIV,
        LOP_MOD | LOP_MODK => MOD,
        _ => POW,
    }
}

const fn is_plain_value(constant: &LuaConstant) -> bool {
    matches!(
        constant,
        LuaConstant::Nil | LuaConstant::Bool(_) | LuaConstant::Number(_) | LuaConstant::Str(_)
    )
}

const fn is_string(constant: &LuaConstant) -> bool {
    matches!(constant, LuaConstant::Str(_))
}

const fn is_number(constant: &LuaConstant) -> bool {
    matches!(constant, LuaConstant::Number(_))
}
