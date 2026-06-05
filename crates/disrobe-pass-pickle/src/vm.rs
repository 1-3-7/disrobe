use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::disasm::{DecodedArg, Disassembly, Insn};
use crate::error::{Error, Result};

const RECURSION_LIMIT: usize = 2_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PickleValue {
    None,
    Bool(bool),
    Int(i64),
    BigInt(String),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<PickleValue>),
    Tuple(Vec<PickleValue>),
    Set(Vec<PickleValue>),
    FrozenSet(Vec<PickleValue>),
    Dict(Vec<(PickleValue, PickleValue)>),
    Global {
        module: String,
        name: String,
    },
    Ext {
        code: i64,
    },
    PersId {
        id: Box<PickleValue>,
    },
    Reduce {
        callable: Box<PickleValue>,
        args: Box<PickleValue>,
    },
    Object {
        cls: Box<PickleValue>,
        args: Box<PickleValue>,
        state: Option<Box<PickleValue>>,
    },
    MemoRef {
        key: u64,
    },
}

#[derive(Debug, Clone)]
enum Slot {
    Value(PickleValue),
    Mark,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmTrace {
    pub protocol: u8,
    pub result: PickleValue,
    pub memo_count: usize,
    pub max_stack_depth: usize,
    pub global_refs: Vec<GlobalRef>,
    pub reduce_count: usize,
    pub unused_memos: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRef {
    pub module: String,
    pub name: String,
    pub offset: usize,
}

#[derive(Debug)]
struct Machine {
    stack: Vec<Slot>,
    memo: BTreeMap<u64, PickleValue>,
    memo_used: BTreeMap<u64, bool>,
    next_auto_memo: u64,
    max_depth: usize,
    global_refs: Vec<GlobalRef>,
    reduce_count: usize,
}

impl Machine {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            memo: BTreeMap::new(),
            memo_used: BTreeMap::new(),
            next_auto_memo: 0,
            max_depth: 0,
            global_refs: Vec::new(),
            reduce_count: 0,
        }
    }

    fn push(&mut self, v: PickleValue) {
        self.stack.push(Slot::Value(v));
        self.max_depth = self.max_depth.max(self.stack.len());
    }

    fn pop_value(&mut self, op: &'static str, offset: usize) -> Result<PickleValue> {
        match self.stack.pop() {
            Some(Slot::Value(v)) => Ok(v),
            Some(Slot::Mark) => Err(Error::NoMark { op, offset }),
            None => Err(Error::StackUnderflow { op, offset }),
        }
    }

    fn peek_value(&self, op: &'static str, offset: usize) -> Result<&PickleValue> {
        match self.stack.last() {
            Some(Slot::Value(v)) => Ok(v),
            _ => Err(Error::StackUnderflow { op, offset }),
        }
    }

    fn pop_to_mark(&mut self, op: &'static str, offset: usize) -> Result<Vec<PickleValue>> {
        let mark: usize = self
            .stack
            .iter()
            .rposition(|s: &Slot| matches!(s, Slot::Mark))
            .ok_or(Error::NoMark { op, offset })?;
        let items: Vec<PickleValue> = self
            .stack
            .drain(mark + 1..)
            .filter_map(slot_value)
            .collect();
        self.stack.pop();
        Ok(items)
    }

    fn store_memo(&mut self, key: u64, op: &'static str, offset: usize) -> Result<()> {
        let v: PickleValue = self.peek_value(op, offset)?.clone();
        self.memo.insert(key, v);
        self.memo_used.entry(key).or_insert(false);
        Ok(())
    }

    fn get_memo(&mut self, key: u64, offset: usize) -> Result<PickleValue> {
        self.memo_used.insert(key, true);
        self.memo
            .get(&key)
            .cloned()
            .ok_or(Error::MemoMiss { key, offset })
    }
}

#[inline]
fn slot_value(s: Slot) -> Option<PickleValue> {
    match s {
        Slot::Value(v) => Some(v),
        Slot::Mark => None,
    }
}

fn arg_int(arg: &DecodedArg, op: &'static str, offset: usize) -> Result<i64> {
    match arg {
        DecodedArg::Int(v) => Ok(*v),
        _ => Err(Error::StackUnderflow { op, offset }),
    }
}

#[derive(Debug)]
pub struct Session {
    machine: Machine,
}

impl Default for Session {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            machine: Machine::new(),
        }
    }

    pub fn run(&mut self, dis: &Disassembly) -> Result<PickleValue> {
        for insn in &dis.instructions {
            if self.machine.stack.len() > RECURSION_LIMIT {
                return Err(Error::RecursionLimit {
                    depth: self.machine.stack.len(),
                    limit: RECURSION_LIMIT,
                });
            }
            step(&mut self.machine, insn)?;
        }
        self.machine
            .pop_value("STOP", dis.stop_offset.unwrap_or(0))
            .map_err(|e: Error| {
                if matches!(e, Error::StackUnderflow { .. }) {
                    Error::EmptyResult
                } else {
                    e
                }
            })
    }

    #[must_use]
    #[inline]
    pub fn memo_len(&self) -> usize {
        self.machine.memo.len()
    }

    #[must_use]
    #[inline]
    pub fn global_refs(&self) -> &[GlobalRef] {
        &self.machine.global_refs
    }
}

pub fn execute(dis: &Disassembly) -> Result<VmTrace> {
    let mut session: Session = Session::new();
    let result: PickleValue = session.run(dis)?;
    let m: Machine = session.machine;

    let unused_memos: Vec<u64> = m
        .memo_used
        .iter()
        .filter_map(|(&k, &used): (&u64, &bool)| (!used).then_some(k))
        .collect();

    Ok(VmTrace {
        protocol: dis.protocol,
        result,
        memo_count: m.memo.len(),
        max_stack_depth: m.max_depth,
        global_refs: m.global_refs,
        reduce_count: m.reduce_count,
        unused_memos,
    })
}

#[allow(clippy::too_many_lines)]
fn step(m: &mut Machine, insn: &Insn) -> Result<()> {
    let off: usize = insn.offset;
    match insn.name.as_str() {
        "PROTO" | "FRAME" => {}
        "MARK" => m.stack.push(Slot::Mark),
        "POP" => {
            m.stack.pop();
        }
        "POP_MARK" => {
            m.pop_to_mark("POP_MARK", off)?;
        }
        "DUP" => {
            let v: PickleValue = m.peek_value("DUP", off)?.clone();
            m.push(v);
        }
        "NONE" => m.push(PickleValue::None),
        "NEWTRUE" => m.push(PickleValue::Bool(true)),
        "NEWFALSE" => m.push(PickleValue::Bool(false)),
        "INT" | "BININT" | "BININT1" | "BININT2" => match &insn.arg {
            DecodedArg::Int(v) => m.push(PickleValue::Int(*v)),
            DecodedArg::BigInt(s) => m.push(PickleValue::BigInt(s.clone())),
            _ => m.push(PickleValue::None),
        },
        "LONG" | "LONG1" | "LONG4" => match &insn.arg {
            DecodedArg::Int(v) => m.push(PickleValue::Int(*v)),
            DecodedArg::BigInt(s) => m.push(PickleValue::BigInt(s.clone())),
            _ => m.push(PickleValue::Int(0)),
        },
        "FLOAT" | "BINFLOAT" => {
            if let DecodedArg::Float(v) = &insn.arg {
                m.push(PickleValue::Float(*v));
            }
        }
        "STRING" | "BINSTRING" | "SHORT_BINSTRING" => push_str_or_bytes(m, &insn.arg),
        "UNICODE" | "BINUNICODE" | "SHORT_BINUNICODE" | "BINUNICODE8" => match &insn.arg {
            DecodedArg::Str(s) => m.push(PickleValue::Str(s.clone())),
            DecodedArg::Bytes(b) => {
                m.push(PickleValue::Str(String::from_utf8_lossy(b).into_owned()));
            }
            _ => m.push(PickleValue::Str(String::new())),
        },
        "BINBYTES" | "SHORT_BINBYTES" | "BINBYTES8" | "BYTEARRAY8" => {
            if let DecodedArg::Bytes(b) = &insn.arg {
                m.push(PickleValue::Bytes(b.clone()));
            } else {
                m.push(PickleValue::Bytes(Vec::new()));
            }
        }
        "EMPTY_LIST" => m.push(PickleValue::List(Vec::new())),
        "EMPTY_DICT" => m.push(PickleValue::Dict(Vec::new())),
        "EMPTY_TUPLE" => m.push(PickleValue::Tuple(Vec::new())),
        "EMPTY_SET" => m.push(PickleValue::Set(Vec::new())),
        "LIST" => {
            let items: Vec<PickleValue> = m.pop_to_mark("LIST", off)?;
            m.push(PickleValue::List(items));
        }
        "DICT" => {
            let items: Vec<PickleValue> = m.pop_to_mark("DICT", off)?;
            m.push(PickleValue::Dict(pairs(items)));
        }
        "TUPLE" => {
            let items: Vec<PickleValue> = m.pop_to_mark("TUPLE", off)?;
            m.push(PickleValue::Tuple(items));
        }
        "TUPLE1" => {
            let a: PickleValue = m.pop_value("TUPLE1", off)?;
            m.push(PickleValue::Tuple(vec![a]));
        }
        "TUPLE2" => {
            let b: PickleValue = m.pop_value("TUPLE2", off)?;
            let a: PickleValue = m.pop_value("TUPLE2", off)?;
            m.push(PickleValue::Tuple(vec![a, b]));
        }
        "TUPLE3" => {
            let c: PickleValue = m.pop_value("TUPLE3", off)?;
            let b: PickleValue = m.pop_value("TUPLE3", off)?;
            let a: PickleValue = m.pop_value("TUPLE3", off)?;
            m.push(PickleValue::Tuple(vec![a, b, c]));
        }
        "FROZENSET" => {
            let items: Vec<PickleValue> = m.pop_to_mark("FROZENSET", off)?;
            m.push(PickleValue::FrozenSet(items));
        }
        "APPEND" => {
            let v: PickleValue = m.pop_value("APPEND", off)?;
            append_into(m, vec![v], off)?;
        }
        "APPENDS" => {
            let items: Vec<PickleValue> = m.pop_to_mark("APPENDS", off)?;
            append_into(m, items, off)?;
        }
        "ADDITEMS" => {
            let items: Vec<PickleValue> = m.pop_to_mark("ADDITEMS", off)?;
            add_items(m, items, off)?;
        }
        "SETITEM" => {
            let val: PickleValue = m.pop_value("SETITEM", off)?;
            let key: PickleValue = m.pop_value("SETITEM", off)?;
            set_items(m, vec![key, val], off)?;
        }
        "SETITEMS" => {
            let items: Vec<PickleValue> = m.pop_to_mark("SETITEMS", off)?;
            set_items(m, items, off)?;
        }
        "GLOBAL" => {
            if let DecodedArg::GlobalPair { module, name } = &insn.arg {
                m.global_refs.push(GlobalRef {
                    module: module.clone(),
                    name: name.clone(),
                    offset: off,
                });
                m.push(PickleValue::Global {
                    module: module.clone(),
                    name: name.clone(),
                });
            }
        }
        "STACK_GLOBAL" => {
            let name: PickleValue = m.pop_value("STACK_GLOBAL", off)?;
            let module: PickleValue = m.pop_value("STACK_GLOBAL", off)?;
            let (ms, ns): (String, String) = (as_string(&module), as_string(&name));
            m.global_refs.push(GlobalRef {
                module: ms.clone(),
                name: ns.clone(),
                offset: off,
            });
            m.push(PickleValue::Global {
                module: ms,
                name: ns,
            });
        }
        "EXT1" | "EXT2" | "EXT4" => {
            let code: i64 = arg_int(&insn.arg, "EXT", off)?;
            m.push(PickleValue::Ext { code });
        }
        "PERSID" => {
            let id: PickleValue = match &insn.arg {
                DecodedArg::Str(s) => PickleValue::Str(s.clone()),
                _ => PickleValue::None,
            };
            m.push(PickleValue::PersId { id: Box::new(id) });
        }
        "BINPERSID" => {
            let id: PickleValue = m.pop_value("BINPERSID", off)?;
            m.push(PickleValue::PersId { id: Box::new(id) });
        }
        "REDUCE" => {
            let args: PickleValue = m.pop_value("REDUCE", off)?;
            let callable: PickleValue = m.pop_value("REDUCE", off)?;
            m.reduce_count += 1;
            m.push(PickleValue::Reduce {
                callable: Box::new(callable),
                args: Box::new(args),
            });
        }
        "NEWOBJ" => {
            let args: PickleValue = m.pop_value("NEWOBJ", off)?;
            let cls: PickleValue = m.pop_value("NEWOBJ", off)?;
            m.reduce_count += 1;
            m.push(PickleValue::Object {
                cls: Box::new(cls),
                args: Box::new(args),
                state: None,
            });
        }
        "NEWOBJ_EX" => {
            let _kwargs: PickleValue = m.pop_value("NEWOBJ_EX", off)?;
            let args: PickleValue = m.pop_value("NEWOBJ_EX", off)?;
            let cls: PickleValue = m.pop_value("NEWOBJ_EX", off)?;
            m.reduce_count += 1;
            m.push(PickleValue::Object {
                cls: Box::new(cls),
                args: Box::new(args),
                state: None,
            });
        }
        "INST" => {
            let args: Vec<PickleValue> = m.pop_to_mark("INST", off)?;
            let (module, name): (String, String) = match &insn.arg {
                DecodedArg::GlobalPair { module, name } => (module.clone(), name.clone()),
                _ => (String::new(), String::new()),
            };
            m.global_refs.push(GlobalRef {
                module: module.clone(),
                name: name.clone(),
                offset: off,
            });
            m.reduce_count += 1;
            m.push(PickleValue::Object {
                cls: Box::new(PickleValue::Global { module, name }),
                args: Box::new(PickleValue::Tuple(args)),
                state: None,
            });
        }
        "OBJ" => {
            let mut args: Vec<PickleValue> = m.pop_to_mark("OBJ", off)?;
            let cls: PickleValue = if args.is_empty() {
                PickleValue::None
            } else {
                args.remove(0)
            };
            m.reduce_count += 1;
            m.push(PickleValue::Object {
                cls: Box::new(cls),
                args: Box::new(PickleValue::Tuple(args)),
                state: None,
            });
        }
        "BUILD" => {
            let state: PickleValue = m.pop_value("BUILD", off)?;
            let target: PickleValue = m.pop_value("BUILD", off)?;
            m.push(apply_build(target, state));
        }
        "PUT" | "BINPUT" | "LONG_BINPUT" => {
            let key: u64 = arg_int(&insn.arg, "PUT", off)? as u64;
            m.store_memo(key, "PUT", off)?;
        }
        "MEMOIZE" => {
            let key: u64 = m.next_auto_memo;
            m.next_auto_memo += 1;
            m.store_memo(key, "MEMOIZE", off)?;
        }
        "GET" | "BINGET" | "LONG_BINGET" => {
            let key: u64 = arg_int(&insn.arg, "GET", off)? as u64;
            let v: PickleValue = m.get_memo(key, off)?;
            m.push(v);
        }
        "NEXT_BUFFER" => m.push(PickleValue::Bytes(Vec::new())),
        "READONLY_BUFFER" => {}
        "STOP" => {}
        _ => {
            return Err(Error::UnknownOpcode {
                opcode: insn.opcode,
                offset: off,
            });
        }
    }
    if matches!(insn.name.as_str(), "PUT" | "BINPUT" | "LONG_BINPUT")
        && let DecodedArg::Int(k) = &insn.arg
    {
        m.next_auto_memo = m.next_auto_memo.max(*k as u64 + 1);
    }
    Ok(())
}

fn push_str_or_bytes(m: &mut Machine, arg: &DecodedArg) {
    match arg {
        DecodedArg::Str(s) => m.push(PickleValue::Str(s.clone())),
        DecodedArg::Bytes(b) => m.push(PickleValue::Str(String::from_utf8_lossy(b).into_owned())),
        _ => m.push(PickleValue::Str(String::new())),
    }
}

fn pairs(items: Vec<PickleValue>) -> Vec<(PickleValue, PickleValue)> {
    let mut out: Vec<(PickleValue, PickleValue)> = Vec::with_capacity(items.len() / 2);
    let mut it: std::vec::IntoIter<PickleValue> = items.into_iter();
    while let (Some(k), Some(v)) = (it.next(), it.next()) {
        out.push((k, v));
    }
    out
}

fn append_into(m: &mut Machine, mut items: Vec<PickleValue>, off: usize) -> Result<()> {
    match m.stack.last_mut() {
        Some(Slot::Value(PickleValue::List(l))) => {
            l.append(&mut items);
            Ok(())
        }
        Some(Slot::Value(PickleValue::Set(s))) => {
            s.append(&mut items);
            Ok(())
        }
        _ => Err(Error::StackUnderflow {
            op: "APPEND",
            offset: off,
        }),
    }
}

fn add_items(m: &mut Machine, mut items: Vec<PickleValue>, off: usize) -> Result<()> {
    match m.stack.last_mut() {
        Some(Slot::Value(PickleValue::Set(s) | PickleValue::FrozenSet(s))) => {
            s.append(&mut items);
            Ok(())
        }
        _ => Err(Error::StackUnderflow {
            op: "ADDITEMS",
            offset: off,
        }),
    }
}

fn set_items(m: &mut Machine, items: Vec<PickleValue>, off: usize) -> Result<()> {
    let kvs: Vec<(PickleValue, PickleValue)> = pairs(items);
    match m.stack.last_mut() {
        Some(Slot::Value(PickleValue::Dict(d))) => {
            d.extend(kvs);
            Ok(())
        }
        _ => Err(Error::StackUnderflow {
            op: "SETITEMS",
            offset: off,
        }),
    }
}

fn apply_build(target: PickleValue, state: PickleValue) -> PickleValue {
    match target {
        PickleValue::Object { cls, args, .. } => PickleValue::Object {
            cls,
            args,
            state: Some(Box::new(state)),
        },
        PickleValue::Reduce { callable, args } => PickleValue::Object {
            cls: callable,
            args,
            state: Some(Box::new(state)),
        },
        other => PickleValue::Object {
            cls: Box::new(other),
            args: Box::new(PickleValue::Tuple(Vec::new())),
            state: Some(Box::new(state)),
        },
    }
}

fn as_string(v: &PickleValue) -> String {
    match v {
        PickleValue::Str(s) => s.clone(),
        PickleValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::disasm::disassemble;

    fn run(bytes: &[u8]) -> VmTrace {
        execute(&disassemble(bytes).expect("disasm")).expect("vm")
    }

    #[test]
    fn none_value() {
        assert_eq!(run(b"\x80\x02N.").result, PickleValue::None);
    }

    #[test]
    fn true_value() {
        assert_eq!(run(b"\x80\x02\x88.").result, PickleValue::Bool(true));
    }

    #[test]
    fn empty_list_then_appends() {
        let t: VmTrace = run(b"\x80\x02]q\x00(K\x01K\x02e.");
        assert_eq!(
            t.result,
            PickleValue::List(vec![PickleValue::Int(1), PickleValue::Int(2)])
        );
    }

    #[test]
    fn dict_setitems() {
        let t: VmTrace = run(b"\x80\x02}q\x00X\x01\x00\x00\x00aq\x01K\x01s.");
        assert_eq!(
            t.result,
            PickleValue::Dict(vec![(PickleValue::Str("a".into()), PickleValue::Int(1))])
        );
    }

    #[test]
    fn global_ref_recorded() {
        let t: VmTrace =
            run(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x8c\x06system\x93\x94.");
        assert_eq!(t.global_refs.len(), 1);
        assert_eq!(t.global_refs[0].module, "os");
        assert_eq!(t.global_refs[0].name, "system");
    }

    #[test]
    fn session_threads_memo_across_streams() {
        let stream1: &[u8] = b"\x80\x05\x8c\x03str\x94.";
        let stream2: &[u8] = b"\x80\x05h\x00.";

        let dis2_standalone: Disassembly = disassemble(stream2).expect("disasm stream2");
        let standalone: Result<VmTrace> = execute(&dis2_standalone);
        assert!(
            matches!(standalone, Err(Error::MemoMiss { key: 0, .. })),
            "fresh-memo execute must miss the cross-stream back-reference, got {standalone:?}"
        );

        let mut session: Session = Session::new();
        let dis1: Disassembly = disassemble(stream1).expect("disasm stream1");
        let v1: PickleValue = session.run(&dis1).expect("session stream1");
        assert_eq!(v1, PickleValue::Str("str".into()));
        assert_eq!(session.memo_len(), 1);

        let dis2: Disassembly = disassemble(stream2).expect("disasm stream2");
        let v2: PickleValue = session.run(&dis2).expect("session stream2 resolves memo");
        assert_eq!(v2, PickleValue::Str("str".into()));
    }
}
