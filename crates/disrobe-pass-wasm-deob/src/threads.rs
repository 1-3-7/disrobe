use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{MemArg, Operator, Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum AtomicOpKind {
    Notify,
    Wait32,
    Wait64,
    Fence,
    Load,
    Store,
    Rmw,
    Cmpxchg,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AtomicOpRecord {
    pub kind: AtomicOpKind,
    pub mnemonic: &'static str,
    pub memory: u32,
    pub offset: u64,
    pub align: u8,
    pub rust_lift: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SharedMemoryRecord {
    pub memory_index: u32,
    pub initial: u64,
    pub maximum: Option<u64>,
    pub memory64: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ThreadsReport {
    pub atomic_ops: Vec<AtomicOpRecord>,
    pub shared_memories: BTreeMap<u32, SharedMemoryRecord>,
    pub uses_atomic_fence: bool,
    pub uses_wait_notify: bool,
}

impl ThreadsReport {
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.atomic_ops.is_empty() && self.shared_memories.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn requires_arc_mutex(&self) -> bool {
        !self.shared_memories.is_empty() && self.uses_wait_notify
    }
}

pub fn scan_threads(input: &[u8]) -> Result<ThreadsReport> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-THREADS: not a wasm module".to_owned(),
        ));
    }
    let mut report: ThreadsReport = ThreadsReport::default();
    let mut memory_index: u32 = 0u32;
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        match payload {
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem: wasmparser::MemoryType =
                        mem.map_err(|e| Error::Parse(format!("{e}")))?;
                    if mem.shared {
                        report.shared_memories.insert(
                            memory_index,
                            SharedMemoryRecord {
                                memory_index,
                                initial: mem.initial,
                                maximum: mem.maximum,
                                memory64: mem.memory64,
                            },
                        );
                    }
                    memory_index = memory_index.saturating_add(1);
                }
            }
            Payload::CodeSectionEntry(body) => {
                let reader: wasmparser::OperatorsReader<'_> = body
                    .get_operators_reader()
                    .map_err(|e| Error::Parse(format!("{e}")))?;
                for op in reader {
                    let op: Operator<'_> = op.map_err(|e| Error::Parse(format!("{e}")))?;
                    if let Some(rec) = classify_atomic(&op) {
                        if matches!(rec.kind, AtomicOpKind::Fence) {
                            report.uses_atomic_fence = true;
                        }
                        if matches!(
                            rec.kind,
                            AtomicOpKind::Wait32 | AtomicOpKind::Wait64 | AtomicOpKind::Notify
                        ) {
                            report.uses_wait_notify = true;
                        }
                        report.atomic_ops.push(rec);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(report)
}

fn classify_atomic(op: &Operator<'_>) -> Option<AtomicOpRecord> {
    let (kind, mnemonic, memarg): (AtomicOpKind, &'static str, MemArg) = match op {
        Operator::AtomicFence => {
            return Some(AtomicOpRecord {
                kind: AtomicOpKind::Fence,
                mnemonic: "atomic.fence",
                memory: 0,
                offset: 0,
                align: 0,
                rust_lift: "std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);"
                    .to_owned(),
            });
        }
        Operator::MemoryAtomicNotify { memarg } => {
            (AtomicOpKind::Notify, "memory.atomic.notify", *memarg)
        }
        Operator::MemoryAtomicWait32 { memarg } => {
            (AtomicOpKind::Wait32, "memory.atomic.wait32", *memarg)
        }
        Operator::MemoryAtomicWait64 { memarg } => {
            (AtomicOpKind::Wait64, "memory.atomic.wait64", *memarg)
        }
        Operator::I32AtomicLoad { memarg } => (AtomicOpKind::Load, "i32.atomic.load", *memarg),
        Operator::I64AtomicLoad { memarg } => (AtomicOpKind::Load, "i64.atomic.load", *memarg),
        Operator::I32AtomicLoad8U { memarg } => (AtomicOpKind::Load, "i32.atomic.load8_u", *memarg),
        Operator::I32AtomicLoad16U { memarg } => {
            (AtomicOpKind::Load, "i32.atomic.load16_u", *memarg)
        }
        Operator::I64AtomicLoad8U { memarg } => (AtomicOpKind::Load, "i64.atomic.load8_u", *memarg),
        Operator::I64AtomicLoad16U { memarg } => {
            (AtomicOpKind::Load, "i64.atomic.load16_u", *memarg)
        }
        Operator::I64AtomicLoad32U { memarg } => {
            (AtomicOpKind::Load, "i64.atomic.load32_u", *memarg)
        }
        Operator::I32AtomicStore { memarg } => (AtomicOpKind::Store, "i32.atomic.store", *memarg),
        Operator::I64AtomicStore { memarg } => (AtomicOpKind::Store, "i64.atomic.store", *memarg),
        Operator::I32AtomicStore8 { memarg } => (AtomicOpKind::Store, "i32.atomic.store8", *memarg),
        Operator::I32AtomicStore16 { memarg } => {
            (AtomicOpKind::Store, "i32.atomic.store16", *memarg)
        }
        Operator::I64AtomicStore8 { memarg } => (AtomicOpKind::Store, "i64.atomic.store8", *memarg),
        Operator::I64AtomicStore16 { memarg } => {
            (AtomicOpKind::Store, "i64.atomic.store16", *memarg)
        }
        Operator::I64AtomicStore32 { memarg } => {
            (AtomicOpKind::Store, "i64.atomic.store32", *memarg)
        }
        Operator::I32AtomicRmwAdd { memarg } => (AtomicOpKind::Rmw, "i32.atomic.rmw.add", *memarg),
        Operator::I32AtomicRmwSub { memarg } => (AtomicOpKind::Rmw, "i32.atomic.rmw.sub", *memarg),
        Operator::I32AtomicRmwAnd { memarg } => (AtomicOpKind::Rmw, "i32.atomic.rmw.and", *memarg),
        Operator::I32AtomicRmwOr { memarg } => (AtomicOpKind::Rmw, "i32.atomic.rmw.or", *memarg),
        Operator::I32AtomicRmwXor { memarg } => (AtomicOpKind::Rmw, "i32.atomic.rmw.xor", *memarg),
        Operator::I32AtomicRmwXchg { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw.xchg", *memarg)
        }
        Operator::I64AtomicRmwAdd { memarg } => (AtomicOpKind::Rmw, "i64.atomic.rmw.add", *memarg),
        Operator::I64AtomicRmwSub { memarg } => (AtomicOpKind::Rmw, "i64.atomic.rmw.sub", *memarg),
        Operator::I64AtomicRmwAnd { memarg } => (AtomicOpKind::Rmw, "i64.atomic.rmw.and", *memarg),
        Operator::I64AtomicRmwOr { memarg } => (AtomicOpKind::Rmw, "i64.atomic.rmw.or", *memarg),
        Operator::I64AtomicRmwXor { memarg } => (AtomicOpKind::Rmw, "i64.atomic.rmw.xor", *memarg),
        Operator::I64AtomicRmwXchg { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw.xchg", *memarg)
        }
        Operator::I32AtomicRmwCmpxchg { memarg } => {
            (AtomicOpKind::Cmpxchg, "i32.atomic.rmw.cmpxchg", *memarg)
        }
        Operator::I64AtomicRmwCmpxchg { memarg } => {
            (AtomicOpKind::Cmpxchg, "i64.atomic.rmw.cmpxchg", *memarg)
        }
        _ => return None,
    };
    let rust_lift: String = rust_lift_for(kind, mnemonic, &memarg)?;
    Some(AtomicOpRecord {
        kind,
        mnemonic,
        memory: memarg.memory,
        offset: memarg.offset,
        align: memarg.align,
        rust_lift,
    })
}

fn rust_lift_for(kind: AtomicOpKind, mnemonic: &str, memarg: &MemArg) -> Option<String> {
    let ordering: &str = "std::sync::atomic::Ordering::SeqCst";
    match kind {
        AtomicOpKind::Load => {
            let cell: &str = rust_atomic_cell(mnemonic)?;
            let lift: String = format!(
                "unsafe {{ (&*(ptr.add({}) as *const std::sync::atomic::{cell})).load({ordering}) /* offset={} */ }}",
                memarg.offset, memarg.offset
            );
            match mnemonic {
                "i32.atomic.load8_u" | "i32.atomic.load16_u" => Some(format!("i32::from({lift})")),
                "i64.atomic.load8_u" | "i64.atomic.load16_u" | "i64.atomic.load32_u" => {
                    Some(format!("i64::from({lift})"))
                }
                _ => Some(lift),
            }
        }
        AtomicOpKind::Store => {
            let cell: &str = rust_atomic_cell(mnemonic)?;
            let value: &str = rust_atomic_store_value(mnemonic)?;
            Some(format!(
                "unsafe {{ (&*(ptr.add({}) as *const std::sync::atomic::{cell})).store({value}, {ordering}) /* offset={} */ }}",
                memarg.offset, memarg.offset
            ))
        }
        AtomicOpKind::Rmw => {
            let cell: &str = rust_atomic_cell(mnemonic)?;
            Some(format!(
                "unsafe {{ (&*(ptr.add({}) as *const std::sync::atomic::{cell})).{}(val, {ordering}) /* {mnemonic} offset={} */ }}",
                memarg.offset,
                rust_rmw_method(mnemonic)?,
                memarg.offset
            ))
        }
        AtomicOpKind::Cmpxchg => {
            let cell: &str = rust_atomic_cell(mnemonic)?;
            Some(format!(
                "match unsafe {{ (&*(ptr.add({}) as *const std::sync::atomic::{cell})).compare_exchange(old, new, {ordering}, {ordering}) /* offset={} */ }} {{ Ok(observed) | Err(observed) => observed }}",
                memarg.offset, memarg.offset
            ))
        }
        AtomicOpKind::Wait32 | AtomicOpKind::Wait64 => Some(format!(
            "wait_on_arc_mutex(memory.clone(), addr, expected, timeout_ns) /* {mnemonic} offset={} */",
            memarg.offset
        )),
        AtomicOpKind::Notify => Some(format!(
            "notify_arc_mutex(memory.clone(), addr, count) /* {mnemonic} offset={} */",
            memarg.offset
        )),
        AtomicOpKind::Fence => Some(format!("std::sync::atomic::fence({ordering});")),
    }
}

fn rust_atomic_cell(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "i32.atomic.load8_u" | "i64.atomic.load8_u" | "i32.atomic.store8" | "i64.atomic.store8" => {
            Some("AtomicU8")
        }
        "i32.atomic.load16_u"
        | "i64.atomic.load16_u"
        | "i32.atomic.store16"
        | "i64.atomic.store16" => Some("AtomicU16"),
        "i64.atomic.load32_u" | "i64.atomic.store32" => Some("AtomicU32"),
        value if value.starts_with("i32.atomic.") => Some("AtomicI32"),
        value if value.starts_with("i64.atomic.") => Some("AtomicI64"),
        _ => None,
    }
}

fn rust_atomic_store_value(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "i32.atomic.store" | "i64.atomic.store" => Some("val"),
        "i32.atomic.store8" | "i64.atomic.store8" => Some("val as u8"),
        "i32.atomic.store16" | "i64.atomic.store16" => Some("val as u16"),
        "i64.atomic.store32" => Some("val as u32"),
        _ => None,
    }
}

fn rust_rmw_method(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        "i32.atomic.rmw.add" | "i64.atomic.rmw.add" => Some("fetch_add"),
        "i32.atomic.rmw.sub" | "i64.atomic.rmw.sub" => Some("fetch_sub"),
        "i32.atomic.rmw.and" | "i64.atomic.rmw.and" => Some("fetch_and"),
        "i32.atomic.rmw.or" | "i64.atomic.rmw.or" => Some("fetch_or"),
        "i32.atomic.rmw.xor" | "i64.atomic.rmw.xor" => Some("fetch_xor"),
        "i32.atomic.rmw.xchg" | "i64.atomic.rmw.xchg" => Some("swap"),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const SHARED_MEM_RMW: &str = r#"
        (module
          (memory $m 1 1 shared)
          (func (export "inc") (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.atomic.rmw.add offset=0 align=4))
    "#;

    #[test]
    fn detects_shared_memory_and_rmw() {
        let bytes: Vec<u8> = wat::parse_str(SHARED_MEM_RMW).expect("wat");
        let report: ThreadsReport = scan_threads(&bytes).expect("scan");
        assert!(!report.is_empty());
        assert_eq!(report.shared_memories.len(), 1);
        let mem: &SharedMemoryRecord = report.shared_memories.get(&0).expect("shared");
        assert_eq!(mem.initial, 1);
        assert_eq!(mem.maximum, Some(1));
        let rmw: bool = report
            .atomic_ops
            .iter()
            .any(|o: &AtomicOpRecord| matches!(o.kind, AtomicOpKind::Rmw));
        assert!(rmw);
        let lifted: &AtomicOpRecord = report
            .atomic_ops
            .iter()
            .find(|o: &&AtomicOpRecord| matches!(o.kind, AtomicOpKind::Rmw))
            .expect("rmw record");
        assert!(lifted.rust_lift.contains("AtomicI32"));
        assert!(lifted.rust_lift.contains("SeqCst"));
    }

    #[test]
    fn fence_lifts_to_atomic_fence_call() {
        let wat: &str = r#"(module (func (export "f") atomic.fence))"#;
        let bytes: Vec<u8> = wat::parse_str(wat).expect("wat");
        let report: ThreadsReport = scan_threads(&bytes).expect("scan");
        assert!(report.uses_atomic_fence);
        assert!(
            report
                .atomic_ops
                .iter()
                .any(|o: &AtomicOpRecord| o.rust_lift.contains("fence("))
        );
    }
}
