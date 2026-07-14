use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD as B64_STANDARD, STANDARD_NO_PAD as B64_STANDARD_NO_PAD, URL_SAFE as B64_URL_SAFE,
    URL_SAFE_NO_PAD as B64_URL_SAFE_NO_PAD,
};
use serde::{Deserialize, Serialize};

use crate::disasm::{DecodedArg, Disassembly, Insn};
use crate::error::{Error, Result};

const RECURSION_LIMIT: usize = 2_000;
const NODE_BUDGET: u64 = 8_000_000;
const MAX_VALUE_DEPTH: u32 = 1_000;
const STACK_GLOBAL_CONST_DEPTH: usize = 16;
const STACK_GLOBAL_CONST_NODES: usize = 128;
const STACK_GLOBAL_CONST_BYTES: usize = 4096;

fn value_depth(v: &PickleValue, cap: u32) -> u32 {
    if cap == 0 {
        return 0;
    }
    let child_cap: u32 = cap - 1;
    let deepest_child: u32 = match v {
        PickleValue::List(items)
        | PickleValue::Tuple(items)
        | PickleValue::Set(items)
        | PickleValue::FrozenSet(items) => items
            .iter()
            .map(|item: &PickleValue| value_depth(item, child_cap))
            .max()
            .unwrap_or(0),
        PickleValue::Dict(pairs) => pairs
            .iter()
            .map(|(k, val): &(PickleValue, PickleValue)| {
                value_depth(k, child_cap).max(value_depth(val, child_cap))
            })
            .max()
            .unwrap_or(0),
        PickleValue::PersId { id } => value_depth(id, child_cap),
        PickleValue::Reduce { callable, args } => {
            value_depth(callable, child_cap).max(value_depth(args, child_cap))
        }
        PickleValue::Object {
            cls,
            args,
            kwargs,
            state,
            listitems,
            dictitems,
            ..
        } => {
            let mut base: u32 = value_depth(cls, child_cap).max(value_depth(args, child_cap));
            if let Some(kwargs) = kwargs {
                base = base.max(value_depth(kwargs, child_cap));
            }
            if let Some(state) = state {
                base = base.max(value_depth(state, child_cap));
            }
            for item in listitems {
                base = base.max(value_depth(item, child_cap));
            }
            for (k, val) in dictitems {
                base = base
                    .max(value_depth(k, child_cap))
                    .max(value_depth(val, child_cap));
            }
            base
        }
        PickleValue::None
        | PickleValue::Bool(_)
        | PickleValue::Int(_)
        | PickleValue::BigInt(_)
        | PickleValue::Float(_)
        | PickleValue::Str(_)
        | PickleValue::Bytes(_)
        | PickleValue::Global { .. }
        | PickleValue::Ext { .. }
        | PickleValue::OutOfBandBuffer { .. }
        | PickleValue::MemoRef { .. } => 0,
    };
    1 + deepest_child
}

fn node_count_capped(v: &PickleValue, cap: u64) -> u64 {
    fn walk(v: &PickleValue, cap: u64, acc: &mut u64) {
        if *acc >= cap {
            return;
        }
        *acc += 1;
        match v {
            PickleValue::List(items)
            | PickleValue::Tuple(items)
            | PickleValue::Set(items)
            | PickleValue::FrozenSet(items) => {
                for item in items {
                    if *acc >= cap {
                        return;
                    }
                    walk(item, cap, acc);
                }
            }
            PickleValue::Dict(pairs) => {
                for (k, val) in pairs {
                    if *acc >= cap {
                        return;
                    }
                    walk(k, cap, acc);
                    walk(val, cap, acc);
                }
            }
            PickleValue::PersId { id } => walk(id, cap, acc),
            PickleValue::Reduce { callable, args } => {
                walk(callable, cap, acc);
                walk(args, cap, acc);
            }
            PickleValue::Object {
                cls,
                args,
                kwargs,
                state,
                listitems,
                dictitems,
                ..
            } => {
                walk(cls, cap, acc);
                walk(args, cap, acc);
                if let Some(kwargs) = kwargs {
                    walk(kwargs, cap, acc);
                }
                if let Some(state) = state {
                    walk(state, cap, acc);
                }
                for item in listitems {
                    if *acc >= cap {
                        return;
                    }
                    walk(item, cap, acc);
                }
                for (k, val) in dictitems {
                    if *acc >= cap {
                        return;
                    }
                    walk(k, cap, acc);
                    if *acc >= cap {
                        return;
                    }
                    walk(val, cap, acc);
                }
            }
            PickleValue::None
            | PickleValue::Bool(_)
            | PickleValue::Int(_)
            | PickleValue::BigInt(_)
            | PickleValue::Float(_)
            | PickleValue::Str(_)
            | PickleValue::Bytes(_)
            | PickleValue::Global { .. }
            | PickleValue::Ext { .. }
            | PickleValue::OutOfBandBuffer { .. }
            | PickleValue::MemoRef { .. } => {}
        }
    }
    let mut acc: u64 = 0;
    walk(v, cap, &mut acc);
    acc
}

fn charged_total_after_clone(v: &PickleValue, already: u64) -> Result<u64> {
    let remaining: u64 = NODE_BUDGET.saturating_sub(already);
    let nodes: u64 = node_count_capped(v, remaining.saturating_add(1));
    if nodes > remaining {
        return Err(Error::NodeBudget { limit: NODE_BUDGET });
    }
    Ok(already.saturating_add(nodes))
}

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
    OutOfBandBuffer {
        readonly: bool,
    },
    PersId {
        id: Box<PickleValue>,
    },
    Reduce {
        callable: Box<PickleValue>,
        args: Box<PickleValue>,
    },
    Object {
        ctor: ObjCtor,
        cls: Box<PickleValue>,
        args: Box<PickleValue>,
        kwargs: Option<Box<PickleValue>>,
        state: Option<Box<PickleValue>>,
        listitems: Vec<PickleValue>,
        dictitems: Vec<(PickleValue, PickleValue)>,
    },
    MemoRef {
        key: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCtor {
    NewObj,
    NewObjEx,
    Inst,
    Obj,
    Reduce,
}

#[derive(Debug, Clone)]
enum Slot {
    Value {
        value: PickleValue,
        memo_id: Option<u64>,
        depth: u32,
    },
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
    pub cyclic: bool,
    pub oob_buffer_count: usize,
    pub call_graph: Vec<CallSite>,
    pub root_memo_key: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalRef {
    pub module: String,
    pub name: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Reduce,
    NewObj,
    NewObjEx,
    Inst,
    Obj,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSite {
    pub kind: CallKind,
    pub offset: usize,
    pub callable: CallableRef,
    pub args: Vec<ArgSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallableRef {
    Global { module: String, name: String },
    Ext { code: i64 },
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgSummary {
    None,
    Bool(bool),
    Int(i64),
    BigInt(String),
    Float(String),
    Str(String),
    Bytes(usize),
    Global { module: String, name: String },
    OutOfBandBuffer,
    MemoRef(u64),
    Container(String),
    Other,
}

#[derive(Debug)]
struct Machine {
    stack: Vec<Slot>,
    memo: BTreeMap<u64, PickleValue>,
    memo_indices: BTreeMap<u64, u64>,
    memo_used: BTreeMap<u64, bool>,
    next_memo_id: u64,
    max_depth: usize,
    global_refs: Vec<GlobalRef>,
    reduce_count: usize,
    materialized_nodes: u64,
    oob_buffer_count: usize,
    call_graph: Vec<CallSite>,
}

impl Machine {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            memo: BTreeMap::new(),
            memo_indices: BTreeMap::new(),
            memo_used: BTreeMap::new(),
            next_memo_id: 0,
            max_depth: 0,
            global_refs: Vec::new(),
            reduce_count: 0,
            materialized_nodes: 0,
            oob_buffer_count: 0,
            call_graph: Vec::new(),
        }
    }

    fn charge(&mut self, nodes: u64) -> Result<()> {
        self.materialized_nodes = self.materialized_nodes.saturating_add(nodes);
        if self.materialized_nodes > NODE_BUDGET {
            return Err(Error::NodeBudget { limit: NODE_BUDGET });
        }
        Ok(())
    }

    fn push(&mut self, v: PickleValue) {
        let depth: u32 = value_depth(&v, MAX_VALUE_DEPTH + 1);
        self.stack.push(Slot::Value {
            value: v,
            memo_id: None,
            depth,
        });
        self.max_depth = self.max_depth.max(self.stack.len());
    }

    fn push_from_memo(&mut self, v: PickleValue, memo_id: u64) {
        let depth: u32 = value_depth(&v, MAX_VALUE_DEPTH + 1);
        self.stack.push(Slot::Value {
            value: v,
            memo_id: Some(memo_id),
            depth,
        });
        self.max_depth = self.max_depth.max(self.stack.len());
    }

    fn push_new(&mut self, v: PickleValue) -> Result<()> {
        self.charge(1)?;
        self.push(v);
        self.enforce_top_depth()
    }

    fn enforce_top_depth(&self) -> Result<()> {
        if let Some(Slot::Value { depth, .. }) = self.stack.last()
            && *depth > MAX_VALUE_DEPTH
        {
            return Err(Error::ValueDepth {
                depth: *depth as usize,
                limit: MAX_VALUE_DEPTH as usize,
            });
        }
        Ok(())
    }

    fn push_clone_of_top(&mut self, op: &'static str, offset: usize) -> Result<()> {
        let already: u64 = self.materialized_nodes;
        let top: &PickleValue = self.peek_value(op, offset)?;
        let total: u64 = charged_total_after_clone(top, already)?;
        let v: PickleValue = top.clone();
        let memo_id: Option<u64> = match self.stack.last() {
            Some(Slot::Value { memo_id, .. }) => *memo_id,
            Some(Slot::Mark) | None => return Err(Error::StackUnderflow { op, offset }),
        };
        self.materialized_nodes = total;
        if let Some(memo_id) = memo_id {
            self.memo_used.insert(memo_id, true);
            self.push_from_memo(v, memo_id);
        } else {
            self.push(v);
        }
        Ok(())
    }

    fn pop_value(&mut self, op: &'static str, offset: usize) -> Result<PickleValue> {
        match self.stack.pop() {
            Some(Slot::Value { value, .. }) => Ok(value),
            Some(Slot::Mark) => Err(Error::NoMark { op, offset }),
            None => Err(Error::StackUnderflow { op, offset }),
        }
    }

    fn peek_value(&self, op: &'static str, offset: usize) -> Result<&PickleValue> {
        match self.stack.last() {
            Some(Slot::Value { value, .. }) => Ok(value),
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
        let already: u64 = self.materialized_nodes;
        let top: &PickleValue = self.peek_value(op, offset)?;
        let total: u64 = charged_total_after_clone(top, already)?;
        let v: PickleValue = top.clone();
        let memo_id: u64 = match self.stack.last() {
            Some(Slot::Value {
                memo_id: Some(memo_id),
                ..
            }) => *memo_id,
            Some(Slot::Value { memo_id: None, .. }) => {
                let next: u64 = self
                    .next_memo_id
                    .checked_add(1)
                    .ok_or(Error::InvalidArgument {
                        op,
                        offset,
                        expected: "memo identity below u64::MAX",
                    })?;
                let memo_id: u64 = self.next_memo_id;
                self.next_memo_id = next;
                memo_id
            }
            Some(Slot::Mark) | None => return Err(Error::StackUnderflow { op, offset }),
        };
        self.materialized_nodes = total;
        self.memo.insert(memo_id, v);
        self.memo_indices.insert(key, memo_id);
        self.memo_used.entry(memo_id).or_insert(false);
        if let Some(Slot::Value {
            memo_id: slot_id, ..
        }) = self.stack.last_mut()
        {
            *slot_id = Some(memo_id);
        }
        Ok(())
    }

    fn refresh_open_memos(&mut self) {
        let open: Vec<(usize, u64)> = self
            .stack
            .iter()
            .enumerate()
            .filter_map(|(i, s): (usize, &Slot)| match s {
                Slot::Value {
                    value,
                    memo_id: Some(k),
                    ..
                } if is_container(value) => Some((i, *k)),
                _ => None,
            })
            .collect();
        for (i, k) in open {
            if let Some(Slot::Value { value, .. }) = self.stack.get(i) {
                self.memo.insert(k, value.clone());
            }
        }
    }

    fn pop_placed(&mut self, n: usize, op: &'static str, offset: usize) -> Result<Vec<Placed>> {
        let mut out: Vec<Placed> = Vec::with_capacity(n);
        for _ in 0..n {
            match self.stack.pop() {
                Some(Slot::Value {
                    value,
                    memo_id,
                    depth,
                }) => out.push(Placed {
                    value,
                    memo_id,
                    depth,
                }),
                Some(Slot::Mark) => return Err(Error::NoMark { op, offset }),
                None => return Err(Error::StackUnderflow { op, offset }),
            }
        }
        out.reverse();
        Ok(out)
    }

    fn pop_placed_to_mark(&mut self, op: &'static str, offset: usize) -> Result<Vec<Placed>> {
        let mark: usize = self
            .stack
            .iter()
            .rposition(|s: &Slot| matches!(s, Slot::Mark))
            .ok_or(Error::NoMark { op, offset })?;
        let items: Vec<Placed> = self
            .stack
            .drain(mark + 1..)
            .filter_map(|s: Slot| match s {
                Slot::Value {
                    value,
                    memo_id,
                    depth,
                } => Some(Placed {
                    value,
                    memo_id,
                    depth,
                }),
                Slot::Mark => None,
            })
            .collect();
        self.stack.pop();
        Ok(items)
    }

    fn pop_to_mark_shared(&mut self, op: &'static str, offset: usize) -> Result<Vec<PickleValue>> {
        let mark: usize = self
            .stack
            .iter()
            .rposition(|s: &Slot| matches!(s, Slot::Mark))
            .ok_or(Error::NoMark { op, offset })?;
        let items: Vec<PickleValue> = self
            .stack
            .drain(mark + 1..)
            .filter_map(|s: Slot| match s {
                Slot::Value {
                    value,
                    memo_id,
                    depth,
                } => Some(
                    resolve_shared(Placed {
                        value,
                        memo_id,
                        depth,
                    })
                    .0,
                ),
                Slot::Mark => None,
            })
            .collect();
        self.stack.pop();
        Ok(items)
    }

    fn pop_final(&mut self, op: &'static str, offset: usize) -> Result<(PickleValue, Option<u64>)> {
        match self.stack.pop() {
            Some(Slot::Value { value, memo_id, .. }) => Ok((value, memo_id)),
            Some(Slot::Mark) => Err(Error::NoMark { op, offset }),
            None => Err(Error::StackUnderflow { op, offset }),
        }
    }

    fn record_call(
        &mut self,
        kind: CallKind,
        offset: usize,
        callable: &PickleValue,
        args: &PickleValue,
    ) {
        self.record_call_ex(kind, offset, callable, args, None);
    }

    fn record_call_ex(
        &mut self,
        kind: CallKind,
        offset: usize,
        callable: &PickleValue,
        args: &PickleValue,
        kwargs: Option<&PickleValue>,
    ) {
        let callable_ref: CallableRef = match callable {
            PickleValue::Global { module, name } => CallableRef::Global {
                module: module.clone(),
                name: name.clone(),
            },
            PickleValue::Ext { code } => CallableRef::Ext { code: *code },
            _ => CallableRef::Unresolved,
        };
        let mut arg_summaries: Vec<ArgSummary> = match args {
            PickleValue::Tuple(items) => items.iter().map(summarize_arg).collect(),
            other => vec![summarize_arg(other)],
        };
        if let Some(PickleValue::Dict(pairs)) = kwargs
            && !pairs.is_empty()
        {
            arg_summaries.push(ArgSummary::Container("dict".to_string()));
        }
        self.call_graph.push(CallSite {
            kind,
            offset,
            callable: callable_ref,
            args: arg_summaries,
        });
    }

    fn push_clone_of_memo(&mut self, key: u64, offset: usize) -> Result<()> {
        let memo_id: u64 = *self
            .memo_indices
            .get(&key)
            .ok_or(Error::MemoMiss { key, offset })?;
        self.memo_used.insert(memo_id, true);
        let already: u64 = self.materialized_nodes;
        let entry: &PickleValue = self
            .memo
            .get(&memo_id)
            .ok_or(Error::MemoMiss { key, offset })?;
        let total: u64 = charged_total_after_clone(entry, already)?;
        let v: PickleValue = entry.clone();
        self.materialized_nodes = total;
        self.push_from_memo(v, memo_id);
        Ok(())
    }
}

fn summarize_arg(v: &PickleValue) -> ArgSummary {
    match v {
        PickleValue::None => ArgSummary::None,
        PickleValue::Bool(b) => ArgSummary::Bool(*b),
        PickleValue::Int(i) => ArgSummary::Int(*i),
        PickleValue::BigInt(s) => ArgSummary::BigInt(s.clone()),
        PickleValue::Float(f) => ArgSummary::Float(f.to_string()),
        PickleValue::Str(s) => ArgSummary::Str(s.clone()),
        PickleValue::Bytes(b) => ArgSummary::Bytes(b.len()),
        PickleValue::Global { module, name } => ArgSummary::Global {
            module: module.clone(),
            name: name.clone(),
        },
        PickleValue::OutOfBandBuffer { .. } => ArgSummary::OutOfBandBuffer,
        PickleValue::MemoRef { key } => ArgSummary::MemoRef(*key),
        PickleValue::List(_) => ArgSummary::Container("list".to_string()),
        PickleValue::Tuple(_) => ArgSummary::Container("tuple".to_string()),
        PickleValue::Set(_) => ArgSummary::Container("set".to_string()),
        PickleValue::FrozenSet(_) => ArgSummary::Container("frozenset".to_string()),
        PickleValue::Dict(_) => ArgSummary::Container("dict".to_string()),
        PickleValue::Ext { .. }
        | PickleValue::PersId { .. }
        | PickleValue::Reduce { .. }
        | PickleValue::Object { .. } => ArgSummary::Other,
    }
}

#[derive(Debug)]
struct Placed {
    value: PickleValue,
    memo_id: Option<u64>,
    depth: u32,
}

#[inline]
fn is_container(v: &PickleValue) -> bool {
    matches!(
        v,
        PickleValue::List(_)
            | PickleValue::Tuple(_)
            | PickleValue::Dict(_)
            | PickleValue::Set(_)
            | PickleValue::FrozenSet(_)
            | PickleValue::Object { .. }
            | PickleValue::Reduce { .. }
    )
}

#[inline]
fn slot_value(s: Slot) -> Option<PickleValue> {
    match s {
        Slot::Value { value, .. } => Some(value),
        Slot::Mark => None,
    }
}

fn arg_int(arg: &DecodedArg, op: &'static str, offset: usize) -> Result<i64> {
    match arg {
        DecodedArg::Int(v) => Ok(*v),
        _ => Err(Error::InvalidArgument {
            op,
            offset,
            expected: "integer",
        }),
    }
}

fn arg_memo_key(arg: &DecodedArg, op: &'static str, offset: usize) -> Result<u64> {
    let key: i64 = arg_int(arg, op, offset)?;
    u64::try_from(key).map_err(|_| Error::InvalidArgument {
        op,
        offset,
        expected: "non-negative memo key",
    })
}

fn arg_global_pair(arg: &DecodedArg, op: &'static str, offset: usize) -> Result<(String, String)> {
    match arg {
        DecodedArg::GlobalPair { module, name } => Ok((module.clone(), name.clone())),
        _ => Err(Error::InvalidArgument {
            op,
            offset,
            expected: "global pair",
        }),
    }
}

fn push_int_or_bigint(
    m: &mut Machine,
    arg: &DecodedArg,
    op: &'static str,
    offset: usize,
) -> Result<()> {
    match arg {
        DecodedArg::Int(v) => m.push_new(PickleValue::Int(*v)),
        DecodedArg::BigInt(s) => m.push_new(PickleValue::BigInt(s.clone())),
        DecodedArg::Bool(b) => m.push_new(PickleValue::Bool(*b)),
        _ => Err(Error::InvalidArgument {
            op,
            offset,
            expected: "integer or big integer",
        }),
    }
}

fn push_float(m: &mut Machine, arg: &DecodedArg, op: &'static str, offset: usize) -> Result<()> {
    match arg {
        DecodedArg::Float(v) => m.push_new(PickleValue::Float(*v)),
        _ => Err(Error::InvalidArgument {
            op,
            offset,
            expected: "float",
        }),
    }
}

fn push_bytes(m: &mut Machine, arg: &DecodedArg, op: &'static str, offset: usize) -> Result<()> {
    match arg {
        DecodedArg::Bytes(b) => m.push_new(PickleValue::Bytes(b.clone())),
        _ => Err(Error::InvalidArgument {
            op,
            offset,
            expected: "bytes",
        }),
    }
}

fn push_bytearray(m: &mut Machine, arg: &DecodedArg, offset: usize) -> Result<()> {
    let DecodedArg::Bytes(b) = arg else {
        return Err(Error::InvalidArgument {
            op: "BYTEARRAY8",
            offset,
            expected: "bytes",
        });
    };
    m.push_new(PickleValue::Reduce {
        callable: Box::new(PickleValue::Global {
            module: "builtins".to_owned(),
            name: "bytearray".to_owned(),
        }),
        args: Box::new(PickleValue::Tuple(vec![PickleValue::Bytes(b.clone())])),
    })
}

#[derive(Debug)]
pub struct Session {
    machine: Machine,
    root_memo_key: Option<u64>,
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
            root_memo_key: None,
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
        let (value, key): (PickleValue, Option<u64>) = self
            .machine
            .pop_final("STOP", dis.stop_offset.unwrap_or(0))
            .map_err(|e: Error| {
                if matches!(e, Error::StackUnderflow { .. }) {
                    Error::EmptyResult
                } else {
                    e
                }
            })?;
        let cleaned_memo: BTreeMap<u64, PickleValue> = self
            .machine
            .memo
            .iter()
            .map(|(&k, v): (&u64, &PickleValue)| {
                (
                    k,
                    inline_unused_refs(v, &self.machine.memo, &self.machine.memo_used),
                )
            })
            .collect();
        let value: PickleValue =
            inline_unused_refs(&value, &self.machine.memo, &self.machine.memo_used);
        self.machine.memo = cleaned_memo;
        self.root_memo_key = key.filter(|_| is_container(&value));
        Ok(value)
    }

    #[must_use]
    #[inline]
    pub fn memo_len(&self) -> usize {
        self.machine.memo_indices.len()
    }

    #[must_use]
    #[inline]
    pub fn memo(&self) -> &BTreeMap<u64, PickleValue> {
        &self.machine.memo
    }

    #[must_use]
    #[inline]
    pub fn global_refs(&self) -> &[GlobalRef] {
        &self.machine.global_refs
    }

    #[must_use]
    #[inline]
    pub fn root_memo_key(&self) -> Option<u64> {
        self.root_memo_key
    }
}

pub fn execute(dis: &Disassembly) -> Result<VmTrace> {
    Ok(execute_full(dis)?.0)
}

pub fn execute_full(dis: &Disassembly) -> Result<(VmTrace, BTreeMap<u64, PickleValue>)> {
    crate::debug::dbg_section("pickle vm trace");
    crate::debug::dbg_kv("vm-input", || {
        format!(
            "protocol={} opcodes={}",
            dis.protocol,
            dis.instructions.len()
        )
    });
    let mut session: Session = Session::new();
    let result: PickleValue = session.run(dis)?;
    let root_memo_key: Option<u64> = session.root_memo_key();
    let m: Machine = session.machine;

    let unused_memos: Vec<u64> = m
        .memo_indices
        .iter()
        .filter_map(|(&index, &memo_id): (&u64, &u64)| {
            (!m.memo_used
                .get(&memo_id)
                .copied()
                .is_some_and(|used: bool| used))
            .then_some(index)
        })
        .collect();
    let memo_count: usize = m.memo_indices.len();
    let memo: BTreeMap<u64, PickleValue> = m.memo;
    let cyclic: bool = detect_cycle(&memo);

    crate::debug::dbg_kv("vm-result", || {
        format!(
            "reduce_count={} max_stack_depth={} memo_count={} unused_memos={} cyclic={} oob_buffers={} call_sites={}",
            m.reduce_count,
            m.max_depth,
            memo_count,
            unused_memos.len(),
            cyclic,
            m.oob_buffer_count,
            m.call_graph.len()
        )
    });
    for gref in &m.global_refs {
        crate::debug::dbg_kv("global-import", || {
            format!("{}.{} @ offset {}", gref.module, gref.name, gref.offset)
        });
    }

    let trace: VmTrace = VmTrace {
        protocol: dis.protocol,
        result,
        memo_count,
        max_stack_depth: m.max_depth,
        global_refs: m.global_refs,
        reduce_count: m.reduce_count,
        unused_memos,
        cyclic,
        oob_buffer_count: m.oob_buffer_count,
        call_graph: m.call_graph,
        root_memo_key,
    };
    Ok((trace, memo))
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
            m.push_clone_of_top("DUP", off)?;
        }
        "NONE" => m.push_new(PickleValue::None)?,
        "NEWTRUE" => m.push_new(PickleValue::Bool(true))?,
        "NEWFALSE" => m.push_new(PickleValue::Bool(false))?,
        "INT" | "BININT" | "BININT1" | "BININT2" => {
            push_int_or_bigint(m, &insn.arg, "INT", off)?;
        }
        "LONG" | "LONG1" | "LONG4" => {
            push_int_or_bigint(m, &insn.arg, "LONG", off)?;
        }
        "FLOAT" | "BINFLOAT" => push_float(m, &insn.arg, "FLOAT", off)?,
        "STRING" | "BINSTRING" | "SHORT_BINSTRING" => {
            push_str_or_bytes(m, &insn.arg, "STRING", off)?;
        }
        "UNICODE" | "BINUNICODE" | "SHORT_BINUNICODE" | "BINUNICODE8" => match &insn.arg {
            DecodedArg::Str(s) => m.push_new(PickleValue::Str(s.clone()))?,
            DecodedArg::Bytes(b) => {
                m.push_new(PickleValue::Str(String::from_utf8_lossy(b).into_owned()))?;
            }
            _ => {
                return Err(Error::InvalidArgument {
                    op: "UNICODE",
                    offset: off,
                    expected: "string or bytes",
                });
            }
        },
        "BINBYTES" | "SHORT_BINBYTES" | "BINBYTES8" => {
            push_bytes(m, &insn.arg, "BYTES", off)?;
        }
        "BYTEARRAY8" => {
            push_bytearray(m, &insn.arg, off)?;
        }
        "EMPTY_LIST" => m.push_new(PickleValue::List(Vec::new()))?,
        "EMPTY_DICT" => m.push_new(PickleValue::Dict(Vec::new()))?,
        "EMPTY_TUPLE" => m.push_new(PickleValue::Tuple(Vec::new()))?,
        "EMPTY_SET" => m.push_new(PickleValue::Set(Vec::new()))?,
        "LIST" => {
            let items: Vec<PickleValue> = m.pop_to_mark_shared("LIST", off)?;
            m.push_new(PickleValue::List(items))?;
        }
        "DICT" => {
            let items: Vec<PickleValue> = m.pop_to_mark_shared("DICT", off)?;
            m.push_new(PickleValue::Dict(pairs(items)))?;
        }
        "TUPLE" => {
            let items: Vec<Placed> = m.pop_placed_to_mark("TUPLE", off)?;
            push_tuple(m, items)?;
        }
        "TUPLE1" => {
            let items: Vec<Placed> = m.pop_placed(1, "TUPLE1", off)?;
            push_tuple(m, items)?;
        }
        "TUPLE2" => {
            let items: Vec<Placed> = m.pop_placed(2, "TUPLE2", off)?;
            push_tuple(m, items)?;
        }
        "TUPLE3" => {
            let items: Vec<Placed> = m.pop_placed(3, "TUPLE3", off)?;
            push_tuple(m, items)?;
        }
        "FROZENSET" => {
            let items: Vec<PickleValue> = m.pop_to_mark_shared("FROZENSET", off)?;
            m.push_new(PickleValue::FrozenSet(items))?;
        }
        "APPEND" => {
            let v: Vec<Placed> = m.pop_placed(1, "APPEND", off)?;
            append_into(m, v, off)?;
            m.refresh_open_memos();
        }
        "APPENDS" => {
            let items: Vec<Placed> = m.pop_placed_to_mark("APPENDS", off)?;
            append_into(m, items, off)?;
            m.refresh_open_memos();
        }
        "ADDITEMS" => {
            let items: Vec<Placed> = m.pop_placed_to_mark("ADDITEMS", off)?;
            add_items(m, items, off)?;
            m.refresh_open_memos();
        }
        "SETITEM" => {
            let kv: Vec<Placed> = m.pop_placed(2, "SETITEM", off)?;
            set_items(m, kv, off)?;
            m.refresh_open_memos();
        }
        "SETITEMS" => {
            let items: Vec<Placed> = m.pop_placed_to_mark("SETITEMS", off)?;
            set_items(m, items, off)?;
            m.refresh_open_memos();
        }
        "GLOBAL" => {
            let (module, name): (String, String) = arg_global_pair(&insn.arg, "GLOBAL", off)?;
            m.global_refs.push(GlobalRef {
                module: module.clone(),
                name: name.clone(),
                offset: off,
            });
            m.push_new(PickleValue::Global { module, name })?;
        }
        "STACK_GLOBAL" => {
            let name: PickleValue = m.pop_value("STACK_GLOBAL", off)?;
            let module: PickleValue = m.pop_value("STACK_GLOBAL", off)?;
            let (ms, ns): (String, String) = (as_string(&module), as_string(&name));
            crate::debug::dbg_kv("stack-global", || {
                format!("offset {off}: STACK_GLOBAL resolves import {ms}.{ns} from stack operands")
            });
            m.global_refs.push(GlobalRef {
                module: ms.clone(),
                name: ns.clone(),
                offset: off,
            });
            m.push_new(PickleValue::Global {
                module: ms,
                name: ns,
            })?;
        }
        "EXT1" | "EXT2" | "EXT4" => {
            let code: i64 = arg_int(&insn.arg, "EXT", off)?;
            m.push_new(PickleValue::Ext { code })?;
        }
        "PERSID" => {
            let id: PickleValue = match &insn.arg {
                DecodedArg::Str(s) => PickleValue::Str(s.clone()),
                _ => {
                    return Err(Error::InvalidArgument {
                        op: "PERSID",
                        offset: off,
                        expected: "string",
                    });
                }
            };
            m.push_new(PickleValue::PersId { id: Box::new(id) })?;
        }
        "BINPERSID" => {
            let id: PickleValue = m.pop_value("BINPERSID", off)?;
            m.push_new(PickleValue::PersId { id: Box::new(id) })?;
        }
        "REDUCE" => {
            let args: PickleValue = m.pop_value("REDUCE", off)?;
            let callable: PickleValue = m.pop_value("REDUCE", off)?;
            m.reduce_count += 1;
            crate::debug::dbg_kv("reduce", || {
                format!(
                    "offset {off}: {}(...) materialized on load",
                    describe_callable(&callable)
                )
            });
            m.record_call(CallKind::Reduce, off, &callable, &args);
            m.push_new(PickleValue::Reduce {
                callable: Box::new(callable),
                args: Box::new(args),
            })?;
        }
        "NEWOBJ" => {
            let args: PickleValue = m.pop_value("NEWOBJ", off)?;
            let cls: PickleValue = m.pop_value("NEWOBJ", off)?;
            m.reduce_count += 1;
            m.record_call(CallKind::NewObj, off, &cls, &args);
            m.push_new(PickleValue::Object {
                ctor: ObjCtor::NewObj,
                cls: Box::new(cls),
                args: Box::new(args),
                kwargs: None,
                state: None,
                listitems: Vec::new(),
                dictitems: Vec::new(),
            })?;
        }
        "NEWOBJ_EX" => {
            let kwargs: PickleValue = m.pop_value("NEWOBJ_EX", off)?;
            let args: PickleValue = m.pop_value("NEWOBJ_EX", off)?;
            let cls: PickleValue = m.pop_value("NEWOBJ_EX", off)?;
            m.reduce_count += 1;
            m.record_call_ex(CallKind::NewObjEx, off, &cls, &args, Some(&kwargs));
            m.push_new(PickleValue::Object {
                ctor: ObjCtor::NewObjEx,
                cls: Box::new(cls),
                args: Box::new(args),
                kwargs: Some(Box::new(kwargs)),
                state: None,
                listitems: Vec::new(),
                dictitems: Vec::new(),
            })?;
        }
        "INST" => {
            let args: Vec<PickleValue> = m.pop_to_mark("INST", off)?;
            let (module, name): (String, String) = arg_global_pair(&insn.arg, "INST", off)?;
            m.global_refs.push(GlobalRef {
                module: module.clone(),
                name: name.clone(),
                offset: off,
            });
            m.reduce_count += 1;
            let cls: PickleValue = PickleValue::Global { module, name };
            let arg_tuple: PickleValue = PickleValue::Tuple(args);
            m.record_call(CallKind::Inst, off, &cls, &arg_tuple);
            m.push_new(PickleValue::Object {
                ctor: ObjCtor::Inst,
                cls: Box::new(cls),
                args: Box::new(arg_tuple),
                kwargs: None,
                state: None,
                listitems: Vec::new(),
                dictitems: Vec::new(),
            })?;
        }
        "OBJ" => {
            let mut args: Vec<PickleValue> = m.pop_to_mark("OBJ", off)?;
            let cls: PickleValue = if args.is_empty() {
                PickleValue::None
            } else {
                args.remove(0)
            };
            m.reduce_count += 1;
            let arg_tuple: PickleValue = PickleValue::Tuple(args);
            m.record_call(CallKind::Obj, off, &cls, &arg_tuple);
            m.push_new(PickleValue::Object {
                ctor: ObjCtor::Obj,
                cls: Box::new(cls),
                args: Box::new(arg_tuple),
                kwargs: None,
                state: None,
                listitems: Vec::new(),
                dictitems: Vec::new(),
            })?;
        }
        "BUILD" => {
            let state: PickleValue = m.pop_value("BUILD", off)?;
            let target_memo_id: Option<u64> = match m.stack.last() {
                Some(Slot::Value { memo_id, .. }) => *memo_id,
                _ => None,
            };
            let target: PickleValue = m.pop_value("BUILD", off)?;
            crate::debug::dbg_kv("build-setstate", || {
                format!(
                    "offset {off}: __setstate__/__dict__ on {} populated from state",
                    describe_target(&target)
                )
            });
            m.push_new(apply_build(target, state))?;
            if let Some(memo_id) = target_memo_id
                && let Some(Slot::Value {
                    memo_id: slot_id, ..
                }) = m.stack.last_mut()
            {
                *slot_id = Some(memo_id);
            }
            m.refresh_open_memos();
        }
        "PUT" | "BINPUT" | "LONG_BINPUT" => {
            let key: u64 = arg_memo_key(&insn.arg, "PUT", off)?;
            m.store_memo(key, "PUT", off)?;
        }
        "MEMOIZE" => {
            let key: u64 =
                u64::try_from(m.memo_indices.len()).map_err(|_| Error::InvalidArgument {
                    op: "MEMOIZE",
                    offset: off,
                    expected: "memo entry count below u64::MAX",
                })?;
            m.store_memo(key, "MEMOIZE", off)?;
        }
        "GET" | "BINGET" | "LONG_BINGET" => {
            let key: u64 = arg_memo_key(&insn.arg, "GET", off)?;
            m.push_clone_of_memo(key, off)?;
        }
        "NEXT_BUFFER" => {
            m.oob_buffer_count += 1;
            m.push_new(PickleValue::OutOfBandBuffer { readonly: false })?;
        }
        "READONLY_BUFFER" => {
            if let Some(Slot::Value {
                value: PickleValue::OutOfBandBuffer { readonly },
                ..
            }) = m.stack.last_mut()
            {
                *readonly = true;
            }
        }
        "STOP" => {}
        _ => {
            return Err(Error::UnknownOpcode {
                opcode: insn.opcode,
                offset: off,
            });
        }
    }
    Ok(())
}

fn push_str_or_bytes(
    m: &mut Machine,
    arg: &DecodedArg,
    op: &'static str,
    offset: usize,
) -> Result<()> {
    match arg {
        DecodedArg::Str(s) => m.push_new(PickleValue::Str(s.clone())),
        DecodedArg::Bytes(b) => {
            m.push_new(PickleValue::Str(String::from_utf8_lossy(b).into_owned()))
        }
        _ => Err(Error::InvalidArgument {
            op,
            offset,
            expected: "string or bytes",
        }),
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

fn push_tuple(m: &mut Machine, placed: Vec<Placed>) -> Result<()> {
    let (items, _): (Vec<PickleValue>, u32) = resolve_all(placed);
    m.push_new(PickleValue::Tuple(items))
}

fn resolve_shared(placed: Placed) -> (PickleValue, u32) {
    match placed.memo_id {
        Some(k) if is_container(&placed.value) => (PickleValue::MemoRef { key: k }, 1),
        _ => (placed.value, placed.depth),
    }
}

fn resolve_all(placed: Vec<Placed>) -> (Vec<PickleValue>, u32) {
    let mut items: Vec<PickleValue> = Vec::with_capacity(placed.len());
    let mut deepest_child: u32 = 0;
    for p in placed {
        let (value, depth): (PickleValue, u32) = resolve_shared(p);
        deepest_child = deepest_child.max(depth);
        items.push(value);
    }
    (items, deepest_child)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitMark {
    Visiting,
    Done,
}

fn detect_cycle(memo: &BTreeMap<u64, PickleValue>) -> bool {
    fn reaches(
        value: &PickleValue,
        memo: &BTreeMap<u64, PickleValue>,
        marks: &mut BTreeMap<u64, VisitMark>,
    ) -> bool {
        match value {
            PickleValue::MemoRef { key } => walk(*key, memo, marks),
            PickleValue::List(items)
            | PickleValue::Tuple(items)
            | PickleValue::Set(items)
            | PickleValue::FrozenSet(items) => items
                .iter()
                .any(|item: &PickleValue| reaches(item, memo, marks)),
            PickleValue::Dict(entries) => {
                entries.iter().any(|(k, v): &(PickleValue, PickleValue)| {
                    reaches(k, memo, marks) || reaches(v, memo, marks)
                })
            }
            PickleValue::PersId { id } => reaches(id, memo, marks),
            PickleValue::Reduce { callable, args } => {
                reaches(callable, memo, marks) || reaches(args, memo, marks)
            }
            PickleValue::Object {
                cls,
                args,
                kwargs,
                state,
                listitems,
                dictitems,
                ..
            } => {
                reaches(cls, memo, marks)
                    || reaches(args, memo, marks)
                    || kwargs
                        .as_deref()
                        .is_some_and(|v: &PickleValue| reaches(v, memo, marks))
                    || state
                        .as_deref()
                        .is_some_and(|v: &PickleValue| reaches(v, memo, marks))
                    || listitems
                        .iter()
                        .any(|item: &PickleValue| reaches(item, memo, marks))
                    || dictitems.iter().any(|(k, v): &(PickleValue, PickleValue)| {
                        reaches(k, memo, marks) || reaches(v, memo, marks)
                    })
            }
            _ => false,
        }
    }
    fn walk(
        key: u64,
        memo: &BTreeMap<u64, PickleValue>,
        marks: &mut BTreeMap<u64, VisitMark>,
    ) -> bool {
        match marks.get(&key) {
            Some(VisitMark::Visiting) => return true,
            Some(VisitMark::Done) => return false,
            None => {}
        }
        marks.insert(key, VisitMark::Visiting);
        let hit: bool = memo
            .get(&key)
            .is_some_and(|value: &PickleValue| reaches(value, memo, marks));
        marks.insert(key, VisitMark::Done);
        hit
    }
    let mut marks: BTreeMap<u64, VisitMark> = BTreeMap::new();
    memo.keys().any(|&key: &u64| walk(key, memo, &mut marks))
}

fn inline_unused_refs(
    value: &PickleValue,
    memo: &BTreeMap<u64, PickleValue>,
    memo_used: &BTreeMap<u64, bool>,
) -> PickleValue {
    match value {
        PickleValue::MemoRef { key } => {
            if memo_used.get(key).copied().unwrap_or(false) {
                PickleValue::MemoRef { key: *key }
            } else {
                memo.get(key)
                    .map_or(PickleValue::MemoRef { key: *key }, |v: &PickleValue| {
                        inline_unused_refs(v, memo, memo_used)
                    })
            }
        }
        PickleValue::List(items) => PickleValue::List(
            items
                .iter()
                .map(|v: &PickleValue| inline_unused_refs(v, memo, memo_used))
                .collect(),
        ),
        PickleValue::Tuple(items) => PickleValue::Tuple(
            items
                .iter()
                .map(|v: &PickleValue| inline_unused_refs(v, memo, memo_used))
                .collect(),
        ),
        PickleValue::Set(items) => PickleValue::Set(
            items
                .iter()
                .map(|v: &PickleValue| inline_unused_refs(v, memo, memo_used))
                .collect(),
        ),
        PickleValue::FrozenSet(items) => PickleValue::FrozenSet(
            items
                .iter()
                .map(|v: &PickleValue| inline_unused_refs(v, memo, memo_used))
                .collect(),
        ),
        PickleValue::Dict(entries) => PickleValue::Dict(
            entries
                .iter()
                .map(|(k, v): &(PickleValue, PickleValue)| {
                    (
                        inline_unused_refs(k, memo, memo_used),
                        inline_unused_refs(v, memo, memo_used),
                    )
                })
                .collect(),
        ),
        PickleValue::PersId { id } => PickleValue::PersId {
            id: Box::new(inline_unused_refs(id, memo, memo_used)),
        },
        PickleValue::Reduce { callable, args } => PickleValue::Reduce {
            callable: Box::new(inline_unused_refs(callable, memo, memo_used)),
            args: Box::new(inline_unused_refs(args, memo, memo_used)),
        },
        PickleValue::Object {
            ctor,
            cls,
            args,
            kwargs,
            state,
            listitems,
            dictitems,
        } => PickleValue::Object {
            ctor: *ctor,
            cls: Box::new(inline_unused_refs(cls, memo, memo_used)),
            args: Box::new(inline_unused_refs(args, memo, memo_used)),
            kwargs: kwargs
                .as_deref()
                .map(|v: &PickleValue| Box::new(inline_unused_refs(v, memo, memo_used))),
            state: state
                .as_deref()
                .map(|v: &PickleValue| Box::new(inline_unused_refs(v, memo, memo_used))),
            listitems: listitems
                .iter()
                .map(|v: &PickleValue| inline_unused_refs(v, memo, memo_used))
                .collect(),
            dictitems: dictitems
                .iter()
                .map(|(k, v): &(PickleValue, PickleValue)| {
                    (
                        inline_unused_refs(k, memo, memo_used),
                        inline_unused_refs(v, memo, memo_used),
                    )
                })
                .collect(),
        },
        other => other.clone(),
    }
}

fn deepen_top(depth: &mut u32, deepest_child: u32) -> Result<()> {
    *depth = (*depth).max(deepest_child.saturating_add(1));
    if *depth > MAX_VALUE_DEPTH {
        return Err(Error::ValueDepth {
            depth: *depth as usize,
            limit: MAX_VALUE_DEPTH as usize,
        });
    }
    Ok(())
}

fn container_mutation_error(op: &'static str, top_is_value: bool, off: usize) -> Error {
    if top_is_value {
        Error::Container(format!(
            "{op}: container mutation applied to a reduce-constructed object (listitems/dictitems reduce protocol not modeled)"
        ))
    } else {
        Error::StackUnderflow { op, offset: off }
    }
}

fn ensure_reduce_object(value: &mut PickleValue) -> bool {
    if matches!(value, PickleValue::Reduce { .. }) {
        let PickleValue::Reduce { callable, args } = std::mem::replace(value, PickleValue::None)
        else {
            return false;
        };
        *value = PickleValue::Object {
            ctor: ObjCtor::Reduce,
            cls: callable,
            args,
            kwargs: None,
            state: None,
            listitems: Vec::new(),
            dictitems: Vec::new(),
        };
    }
    matches!(value, PickleValue::Object { .. })
}

fn append_into(m: &mut Machine, placed: Vec<Placed>, off: usize) -> Result<()> {
    let (mut items, deepest_child): (Vec<PickleValue>, u32) = resolve_all(placed);
    match m.stack.last_mut() {
        Some(Slot::Value {
            value: PickleValue::List(l),
            depth,
            ..
        }) => {
            l.append(&mut items);
            deepen_top(depth, deepest_child)
        }
        Some(Slot::Value {
            value: PickleValue::Set(s),
            depth,
            ..
        }) => {
            s.append(&mut items);
            deepen_top(depth, deepest_child)
        }
        Some(Slot::Value { value, depth, .. }) => {
            if ensure_reduce_object(value) {
                if let PickleValue::Object { listitems, .. } = value {
                    listitems.append(&mut items);
                }
                deepen_top(depth, deepest_child)
            } else {
                Err(container_mutation_error("APPEND", true, off))
            }
        }
        _ => Err(container_mutation_error("APPEND", false, off)),
    }
}

fn add_items(m: &mut Machine, placed: Vec<Placed>, off: usize) -> Result<()> {
    let (mut items, deepest_child): (Vec<PickleValue>, u32) = resolve_all(placed);
    let top_is_value: bool = matches!(m.stack.last(), Some(Slot::Value { .. }));
    match m.stack.last_mut() {
        Some(Slot::Value {
            value: PickleValue::Set(s) | PickleValue::FrozenSet(s),
            depth,
            ..
        }) => {
            s.append(&mut items);
            deepen_top(depth, deepest_child)
        }
        _ => Err(container_mutation_error("ADDITEMS", top_is_value, off)),
    }
}

fn set_items(m: &mut Machine, placed: Vec<Placed>, off: usize) -> Result<()> {
    let (values, deepest_child): (Vec<PickleValue>, u32) = resolve_all(placed);
    let mut kvs: Vec<(PickleValue, PickleValue)> = pairs(values);
    match m.stack.last_mut() {
        Some(Slot::Value {
            value: PickleValue::Dict(d),
            depth,
            ..
        }) => {
            d.extend(kvs);
            deepen_top(depth, deepest_child)
        }
        Some(Slot::Value { value, depth, .. }) => {
            if ensure_reduce_object(value) {
                if let PickleValue::Object { dictitems, .. } = value {
                    dictitems.append(&mut kvs);
                }
                deepen_top(depth, deepest_child)
            } else {
                Err(container_mutation_error("SETITEMS", true, off))
            }
        }
        _ => Err(container_mutation_error("SETITEMS", false, off)),
    }
}

fn apply_build(target: PickleValue, state: PickleValue) -> PickleValue {
    match target {
        PickleValue::Object {
            ctor,
            cls,
            args,
            kwargs,
            listitems,
            dictitems,
            ..
        } => PickleValue::Object {
            ctor,
            cls,
            args,
            kwargs,
            state: Some(Box::new(state)),
            listitems,
            dictitems,
        },
        PickleValue::Reduce { callable, args } => PickleValue::Object {
            ctor: ObjCtor::Reduce,
            cls: callable,
            args,
            kwargs: None,
            state: Some(Box::new(state)),
            listitems: Vec::new(),
            dictitems: Vec::new(),
        },
        other => PickleValue::Object {
            ctor: ObjCtor::Reduce,
            cls: Box::new(other),
            args: Box::new(PickleValue::Tuple(Vec::new())),
            kwargs: None,
            state: Some(Box::new(state)),
            listitems: Vec::new(),
            dictitems: Vec::new(),
        },
    }
}

fn as_string(v: &PickleValue) -> String {
    let mut nodes: usize = STACK_GLOBAL_CONST_NODES;
    fold_static_value(v, STACK_GLOBAL_CONST_DEPTH, &mut nodes)
        .and_then(static_value_into_string)
        .unwrap_or_else(|| format!("{v:?}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StaticValue {
    Str(String),
    Bytes(Vec<u8>),
}

fn fold_static_value(value: &PickleValue, depth: usize, nodes: &mut usize) -> Option<StaticValue> {
    if depth == 0 || *nodes == 0 {
        return None;
    }
    *nodes = nodes.saturating_sub(1);
    match value {
        PickleValue::Str(s) if s.len() <= STACK_GLOBAL_CONST_BYTES => {
            Some(StaticValue::Str(s.clone()))
        }
        PickleValue::Bytes(b) if b.len() <= STACK_GLOBAL_CONST_BYTES => {
            Some(StaticValue::Bytes(b.clone()))
        }
        PickleValue::Reduce { callable, args } => fold_static_reduce(callable, args, depth, nodes),
        _ => None,
    }
}

fn fold_static_reduce(
    callable: &PickleValue,
    args: &PickleValue,
    depth: usize,
    nodes: &mut usize,
) -> Option<StaticValue> {
    let PickleValue::Global { module, name } = callable else {
        return None;
    };
    match (module.as_str(), name.as_str()) {
        ("operator" | "_operator", "add" | "concat") => fold_static_concat(args, depth, nodes),
        ("base64", "b64decode" | "standard_b64decode" | "urlsafe_b64decode") => {
            let value: StaticValue = fold_static_value(tuple_arg(args, 0)?, depth - 1, nodes)?;
            let decoded: Vec<u8> = decode_base64_static(&static_value_into_string(value)?)?;
            Some(StaticValue::Bytes(decoded))
        }
        ("codecs", "decode") => fold_codecs_decode(args, depth, nodes),
        _ => None,
    }
}

fn fold_static_concat(args: &PickleValue, depth: usize, nodes: &mut usize) -> Option<StaticValue> {
    let left: StaticValue = fold_static_value(tuple_arg(args, 0)?, depth - 1, nodes)?;
    let right: StaticValue = fold_static_value(tuple_arg(args, 1)?, depth - 1, nodes)?;
    match (left, right) {
        (StaticValue::Str(mut left), StaticValue::Str(right)) => {
            if left.len().saturating_add(right.len()) > STACK_GLOBAL_CONST_BYTES {
                return None;
            }
            left.push_str(&right);
            Some(StaticValue::Str(left))
        }
        (StaticValue::Bytes(mut left), StaticValue::Bytes(right)) => {
            if left.len().saturating_add(right.len()) > STACK_GLOBAL_CONST_BYTES {
                return None;
            }
            left.extend_from_slice(&right);
            Some(StaticValue::Bytes(left))
        }
        _ => None,
    }
}

fn fold_codecs_decode(args: &PickleValue, depth: usize, nodes: &mut usize) -> Option<StaticValue> {
    let value: StaticValue = fold_static_value(tuple_arg(args, 0)?, depth - 1, nodes)?;
    let encoding: String =
        static_value_into_string(fold_static_value(tuple_arg(args, 1)?, depth - 1, nodes)?)?;
    let normalized: String = normalize_codec(&encoding);
    match normalized.as_str() {
        "base64" | "base64codec" => {
            let decoded: Vec<u8> = decode_base64_static(&static_value_into_string(value)?)?;
            Some(StaticValue::Bytes(decoded))
        }
        "utf8" => static_value_into_string(value).map(StaticValue::Str),
        "latin1" | "iso88591" => Some(StaticValue::Str(static_value_into_latin1(value))),
        "rot13" => static_value_into_string(value).map(|s: String| StaticValue::Str(rot13(&s))),
        _ => None,
    }
}

fn tuple_arg(value: &PickleValue, index: usize) -> Option<&PickleValue> {
    match value {
        PickleValue::Tuple(items) => items.get(index),
        _ => None,
    }
}

fn static_value_into_string(value: StaticValue) -> Option<String> {
    match value {
        StaticValue::Str(s) => Some(s),
        StaticValue::Bytes(b) => String::from_utf8(b).ok(),
    }
}

fn static_value_into_latin1(value: StaticValue) -> String {
    match value {
        StaticValue::Str(s) => s,
        StaticValue::Bytes(b) => b.into_iter().map(char::from).collect(),
    }
}

fn decode_base64_static(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c: &char| !c.is_whitespace())
        .collect();
    if cleaned.len() > STACK_GLOBAL_CONST_BYTES {
        return None;
    }
    B64_STANDARD
        .decode(cleaned.as_bytes())
        .or_else(|_| B64_URL_SAFE.decode(cleaned.as_bytes()))
        .or_else(|_| B64_STANDARD_NO_PAD.decode(cleaned.trim_end_matches('=').as_bytes()))
        .or_else(|_| B64_URL_SAFE_NO_PAD.decode(cleaned.trim_end_matches('=').as_bytes()))
        .ok()
        .filter(|decoded: &Vec<u8>| decoded.len() <= STACK_GLOBAL_CONST_BYTES)
}

fn normalize_codec(encoding: &str) -> String {
    encoding
        .chars()
        .filter(|c: &char| !matches!(*c, '-' | '_' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c: char| match c {
            'a'..='m' | 'A'..='M' => char::from_u32(u32::from(c) + 13).unwrap_or(c),
            'n'..='z' | 'N'..='Z' => char::from_u32(u32::from(c) - 13).unwrap_or(c),
            _ => c,
        })
        .collect()
}

fn describe_callable(v: &PickleValue) -> String {
    match v {
        PickleValue::Global { module, name } => format!("{module}.{name}"),
        PickleValue::Ext { code } => format!("<ext copyreg code {code}>"),
        PickleValue::Reduce { callable, .. } => {
            format!("<reduce-derived {}>", describe_callable(callable))
        }
        PickleValue::Object { cls, .. } => format!("<object {}>", describe_callable(cls)),
        _ => "<unresolved callable>".to_owned(),
    }
}

fn describe_target(v: &PickleValue) -> String {
    match v {
        PickleValue::Object { cls, .. } => describe_callable(cls),
        PickleValue::Reduce { callable, .. } => describe_callable(callable),
        other => describe_callable(other),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::disasm::disassemble;
    use crate::opcode::Effect;

    fn run(bytes: &[u8]) -> VmTrace {
        execute(&disassemble(bytes).expect("disasm")).expect("vm")
    }

    fn malformed(name: &'static str, opcode: u8, effect: Effect, arg: DecodedArg) -> Disassembly {
        Disassembly {
            protocol: 5,
            instructions: vec![Insn {
                offset: 0,
                opcode,
                name: name.to_string(),
                effect,
                proto: 5,
                arg,
            }],
            frame_count: 0,
            stop_offset: Some(0),
        }
    }

    #[test]
    fn malformed_int_arg_is_rejected() {
        let dis: Disassembly = malformed("BININT", 0x4a, Effect::PushConst, DecodedArg::None);
        let err: Error = execute(&dis).expect_err("malformed integer arg must fail");
        assert!(matches!(
            err,
            Error::InvalidArgument {
                op: "INT",
                offset: 0,
                expected: "integer or big integer"
            }
        ));
    }

    #[test]
    fn negative_memo_key_is_rejected() {
        let dis: Disassembly = malformed("BINPUT", 0x71, Effect::StoreMemo, DecodedArg::Int(-1));
        let err: Error = execute(&dis).expect_err("negative memo key must fail");
        assert!(matches!(
            err,
            Error::InvalidArgument {
                op: "PUT",
                offset: 0,
                expected: "non-negative memo key"
            }
        ));
    }

    #[test]
    fn malformed_global_arg_is_rejected() {
        let dis: Disassembly = malformed(
            "GLOBAL",
            b'c',
            Effect::Global,
            DecodedArg::Str("os system".to_string()),
        );
        let err: Error = execute(&dis).expect_err("malformed global arg must fail");
        assert!(matches!(
            err,
            Error::InvalidArgument {
                op: "GLOBAL",
                offset: 0,
                expected: "global pair"
            }
        ));
    }

    #[test]
    fn none_value() {
        assert_eq!(run(b"\x80\x02N.").result, PickleValue::None);
    }

    #[test]
    fn rejects_value_depth_bomb() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02, b'N'];
        let wraps: Vec<u8> = vec![0x85u8; MAX_VALUE_DEPTH as usize + 5];
        bytes.extend_from_slice(&wraps);
        bytes.push(b'.');
        let dis: Disassembly = disassemble(&bytes).expect("disasm");
        let err: Error = execute(&dis).expect_err("deep TUPLE1 chain must be rejected");
        assert!(
            matches!(err, Error::ValueDepth { limit, .. } if limit == MAX_VALUE_DEPTH as usize),
            "expected ValueDepth, got {err:?}"
        );
    }

    #[test]
    fn accepts_value_depth_just_under_cap() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02, b'N'];
        let wraps: Vec<u8> = vec![0x85u8; MAX_VALUE_DEPTH as usize - 2];
        bytes.extend_from_slice(&wraps);
        bytes.push(b'.');
        let dis: Disassembly = disassemble(&bytes).expect("disasm");
        assert!(execute(&dis).is_ok(), "a chain under the cap must decode");
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
    fn stack_global_folds_operator_concat_operands() {
        let t: VmTrace = run(
            b"\x80\x04\x8c\x08operator\x8c\x03add\x93\x8c\x01o\x8c\x01s\x86R\x8c\x06system\x93.",
        );
        assert_eq!(
            t.result,
            PickleValue::Global {
                module: "os".into(),
                name: "system".into(),
            }
        );
        let last: &GlobalRef = t.global_refs.last().expect("final stack global");
        assert_eq!(last.module, "os");
        assert_eq!(last.name, "system");
    }

    #[test]
    fn stack_global_folds_base64_module_operand() {
        let t: VmTrace =
            run(b"\x80\x04\x8c\x06base64\x8c\x09b64decode\x93\x8c\x04b3M=\x85R\x8c\x06system\x93.");
        assert_eq!(
            t.result,
            PickleValue::Global {
                module: "os".into(),
                name: "system".into(),
            }
        );
        let last: &GlobalRef = t.global_refs.last().expect("final stack global");
        assert_eq!(last.module, "os");
        assert_eq!(last.name, "system");
    }

    #[test]
    fn stack_global_folds_codecs_name_operand() {
        let t: VmTrace = run(
            b"\x80\x04\x8c\x02os\x8c\x06codecs\x8c\x06decode\x93\x8c\x08c3lzdGVt\x8c\x06base64\x86R\x93.",
        );
        assert_eq!(
            t.result,
            PickleValue::Global {
                module: "os".into(),
                name: "system".into(),
            }
        );
        let last: &GlobalRef = t.global_refs.last().expect("final stack global");
        assert_eq!(last.module, "os");
        assert_eq!(last.name, "system");
    }

    #[test]
    fn dup_tuple2_clone_bomb_stays_bounded() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02, 0x88];
        for _ in 0..60 {
            bytes.push(0x32);
            bytes.push(0x86);
        }
        bytes.push(b'.');
        let dis: Disassembly = disassemble(&bytes).expect("disasm");
        let start: std::time::Instant = std::time::Instant::now();
        let result: Result<VmTrace> = execute(&dis);
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            matches!(result, Err(Error::NodeBudget { .. })),
            "dup+tuple2 clone bomb must hit the node budget, got {result:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "clone bomb must bail fast, took {elapsed:?}"
        );
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

    #[test]
    fn self_referential_list_surfaces_back_edge() {
        let t: VmTrace = run(b"\x80\x02]q\x00h\x00a.");
        assert!(t.cyclic, "self-referential list must flag cyclic");
        assert_eq!(
            t.result,
            PickleValue::List(vec![PickleValue::MemoRef { key: 0 }]),
            "the inner element must be a memo back-edge, not an inlined clone"
        );
    }

    #[test]
    fn shared_reference_stays_acyclic_and_shares_by_reference() {
        let t: VmTrace = run(b"\x80\x02]q\x00(]q\x01(K\x01K\x02K\x03eh\x01e.");
        assert!(!t.cyclic, "shared (non-cyclic) reuse must not flag cyclic");
        assert_eq!(
            t.result,
            PickleValue::List(vec![
                PickleValue::MemoRef { key: 1 },
                PickleValue::MemoRef { key: 1 },
            ]),
            "both occurrences must be memo references into the same shell, or the rebuilt object loses the original's shared identity"
        );
        assert_eq!(
            t.memo_count, 2,
            "the outer list and the shared inner list each keep a memo slot"
        );
    }

    #[test]
    fn three_way_shared_reference_through_a_nested_dict_all_alias_one_shell() {
        let t: VmTrace = run(
            b"\x80\x02]q\x00(]q\x01(K\x07K\x08K\teh\x01}q\x02X\x03\x00\x00\x00refq\x03h\x01se.",
        );
        assert!(!t.cyclic, "acyclic fan-out sharing must not flag cyclic");
        assert_eq!(
            t.result,
            PickleValue::List(vec![
                PickleValue::MemoRef { key: 1 },
                PickleValue::MemoRef { key: 1 },
                PickleValue::Dict(vec![(
                    PickleValue::Str("ref".into()),
                    PickleValue::MemoRef { key: 1 },
                )]),
            ]),
            "all three occurrences (direct, direct, and nested in a dict value) must alias the same memo slot"
        );
    }

    #[test]
    fn out_of_band_buffer_is_distinct_placeholder() {
        let bytes: &[u8] = b"\x80\x05\x95\x00\x00\x00\x00\x00\x00\x00\x00\x97\x98.";
        let t: VmTrace = run(bytes);
        assert_eq!(t.oob_buffer_count, 1);
        assert_eq!(t.result, PickleValue::OutOfBandBuffer { readonly: true });
    }

    #[test]
    fn reduce_records_call_graph_edge() {
        let t: VmTrace =
            run(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R.");
        assert_eq!(t.call_graph.len(), 1);
        let site: &CallSite = &t.call_graph[0];
        assert_eq!(site.kind, CallKind::Reduce);
        assert_eq!(
            site.callable,
            CallableRef::Global {
                module: "os".into(),
                name: "system".into(),
            }
        );
        assert_eq!(site.args, vec![ArgSummary::Str("id".into())]);
    }

    #[test]
    fn ext1_records_unresolved_ext_callable_code() {
        let t: VmTrace = run(b"\x80\x02\x82\x10.");
        assert_eq!(t.result, PickleValue::Ext { code: 16 });
    }

    #[test]
    fn indirect_cycle_a_b_a_surfaces_back_edge() {
        let bytes: &[u8] = b"\x80\x02]q\x00]q\x01h\x00aa.";
        let t: VmTrace = run(bytes);
        assert!(t.cyclic, "a -> b -> a indirect cycle must flag cyclic");
        assert_eq!(
            t.result,
            PickleValue::List(vec![PickleValue::List(vec![PickleValue::MemoRef {
                key: 0
            }])]),
            "the inner list must back-reference the outer via memo key 0"
        );
    }

    #[test]
    fn reduce_listitems_accumulate_on_deque() {
        let t: VmTrace = run(b"\x80\x02ccollections\ndeque\nq\x00)Rq\x01(K\x01K\x02K\x03e.");
        let PickleValue::Object {
            ctor,
            cls,
            listitems,
            dictitems,
            state,
            ..
        } = &t.result
        else {
            panic!("expected reduce-constructed object, got {:?}", t.result);
        };
        assert_eq!(*ctor, ObjCtor::Reduce);
        assert_eq!(
            cls.as_ref(),
            &PickleValue::Global {
                module: "collections".into(),
                name: "deque".into(),
            }
        );
        assert_eq!(
            listitems,
            &vec![
                PickleValue::Int(1),
                PickleValue::Int(2),
                PickleValue::Int(3)
            ],
            "APPENDS after REDUCE must accumulate the deque's listitems"
        );
        assert!(dictitems.is_empty());
        assert!(state.is_none());
    }

    #[test]
    fn reduce_dictitems_accumulate_on_ordered_dict() {
        let t: VmTrace = run(
            b"\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01(X\x01\x00\x00\x00aq\x02K\x01X\x01\x00\x00\x00bq\x03K\x02u.",
        );
        let PickleValue::Object {
            ctor,
            cls,
            listitems,
            dictitems,
            ..
        } = &t.result
        else {
            panic!("expected reduce-constructed object, got {:?}", t.result);
        };
        assert_eq!(*ctor, ObjCtor::Reduce);
        assert_eq!(
            cls.as_ref(),
            &PickleValue::Global {
                module: "collections".into(),
                name: "OrderedDict".into(),
            }
        );
        assert!(listitems.is_empty());
        assert_eq!(
            dictitems,
            &vec![
                (PickleValue::Str("a".into()), PickleValue::Int(1)),
                (PickleValue::Str("b".into()), PickleValue::Int(2)),
            ],
            "SETITEMS after REDUCE must accumulate the dict's dictitems"
        );
    }

    #[test]
    fn append_onto_non_container_int_is_rejected() {
        let dis: Disassembly = disassemble(b"\x80\x02K\x01(K\x02e.").expect("disasm");
        let err: Error = execute(&dis).expect_err("APPENDS onto a bare int must fail, not panic");
        assert!(
            matches!(err, Error::Container(_)),
            "expected a container error, got {err:?}"
        );
    }

    #[test]
    fn acyclic_control_yields_no_cycle() {
        let bytes: &[u8] = b"\x80\x02]q\x00(]q\x01K\x01a]q\x02K\x02ae.";
        let t: VmTrace = run(bytes);
        assert!(!t.cyclic, "plain nested lists must NOT flag cyclic");
        assert_eq!(
            t.result,
            PickleValue::List(vec![
                PickleValue::List(vec![PickleValue::Int(1)]),
                PickleValue::List(vec![PickleValue::Int(2)]),
            ])
        );
    }
}
