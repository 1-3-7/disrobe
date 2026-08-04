use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{MemArg, MemoryType, Operator, Parser, Payload, TypeRef};

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
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import: wasmparser::Import<'_> =
                        import.map_err(|e| Error::Parse(format!("{e}")))?;
                    if let TypeRef::Memory(memory) = import.ty {
                        record_memory(&mut report, &mut memory_index, memory);
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem: MemoryType = mem.map_err(|e| Error::Parse(format!("{e}")))?;
                    record_memory(&mut report, &mut memory_index, mem);
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

fn record_memory(report: &mut ThreadsReport, memory_index: &mut u32, memory: MemoryType) {
    if memory.shared {
        report.shared_memories.insert(
            *memory_index,
            SharedMemoryRecord {
                memory_index: *memory_index,
                initial: memory.initial,
                maximum: memory.maximum,
                memory64: memory.memory64,
            },
        );
    }
    *memory_index = memory_index.saturating_add(1);
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
        Operator::I32AtomicRmw8AddU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw8.add_u", *memarg)
        }
        Operator::I32AtomicRmw16AddU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw16.add_u", *memarg)
        }
        Operator::I64AtomicRmw8AddU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw8.add_u", *memarg)
        }
        Operator::I64AtomicRmw16AddU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw16.add_u", *memarg)
        }
        Operator::I64AtomicRmw32AddU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw32.add_u", *memarg)
        }
        Operator::I32AtomicRmw8SubU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw8.sub_u", *memarg)
        }
        Operator::I32AtomicRmw16SubU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw16.sub_u", *memarg)
        }
        Operator::I64AtomicRmw8SubU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw8.sub_u", *memarg)
        }
        Operator::I64AtomicRmw16SubU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw16.sub_u", *memarg)
        }
        Operator::I64AtomicRmw32SubU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw32.sub_u", *memarg)
        }
        Operator::I32AtomicRmw8AndU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw8.and_u", *memarg)
        }
        Operator::I32AtomicRmw16AndU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw16.and_u", *memarg)
        }
        Operator::I64AtomicRmw8AndU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw8.and_u", *memarg)
        }
        Operator::I64AtomicRmw16AndU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw16.and_u", *memarg)
        }
        Operator::I64AtomicRmw32AndU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw32.and_u", *memarg)
        }
        Operator::I32AtomicRmw8OrU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw8.or_u", *memarg)
        }
        Operator::I32AtomicRmw16OrU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw16.or_u", *memarg)
        }
        Operator::I64AtomicRmw8OrU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw8.or_u", *memarg)
        }
        Operator::I64AtomicRmw16OrU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw16.or_u", *memarg)
        }
        Operator::I64AtomicRmw32OrU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw32.or_u", *memarg)
        }
        Operator::I32AtomicRmw8XorU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw8.xor_u", *memarg)
        }
        Operator::I32AtomicRmw16XorU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw16.xor_u", *memarg)
        }
        Operator::I64AtomicRmw8XorU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw8.xor_u", *memarg)
        }
        Operator::I64AtomicRmw16XorU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw16.xor_u", *memarg)
        }
        Operator::I64AtomicRmw32XorU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw32.xor_u", *memarg)
        }
        Operator::I32AtomicRmw8XchgU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw8.xchg_u", *memarg)
        }
        Operator::I32AtomicRmw16XchgU { memarg } => {
            (AtomicOpKind::Rmw, "i32.atomic.rmw16.xchg_u", *memarg)
        }
        Operator::I64AtomicRmw8XchgU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw8.xchg_u", *memarg)
        }
        Operator::I64AtomicRmw16XchgU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw16.xchg_u", *memarg)
        }
        Operator::I64AtomicRmw32XchgU { memarg } => {
            (AtomicOpKind::Rmw, "i64.atomic.rmw32.xchg_u", *memarg)
        }
        Operator::I32AtomicRmwCmpxchg { memarg } => {
            (AtomicOpKind::Cmpxchg, "i32.atomic.rmw.cmpxchg", *memarg)
        }
        Operator::I64AtomicRmwCmpxchg { memarg } => {
            (AtomicOpKind::Cmpxchg, "i64.atomic.rmw.cmpxchg", *memarg)
        }
        Operator::I32AtomicRmw8CmpxchgU { memarg } => {
            (AtomicOpKind::Cmpxchg, "i32.atomic.rmw8.cmpxchg_u", *memarg)
        }
        Operator::I32AtomicRmw16CmpxchgU { memarg } => {
            (AtomicOpKind::Cmpxchg, "i32.atomic.rmw16.cmpxchg_u", *memarg)
        }
        Operator::I64AtomicRmw8CmpxchgU { memarg } => {
            (AtomicOpKind::Cmpxchg, "i64.atomic.rmw8.cmpxchg_u", *memarg)
        }
        Operator::I64AtomicRmw16CmpxchgU { memarg } => {
            (AtomicOpKind::Cmpxchg, "i64.atomic.rmw16.cmpxchg_u", *memarg)
        }
        Operator::I64AtomicRmw32CmpxchgU { memarg } => {
            (AtomicOpKind::Cmpxchg, "i64.atomic.rmw32.cmpxchg_u", *memarg)
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
            let value: String = rust_atomic_operand(mnemonic, "val")?;
            let lift: String = format!(
                "unsafe {{ (&*(ptr.add({}) as *const std::sync::atomic::{cell})).{}({value}, {ordering}) /* {mnemonic} offset={} */ }}",
                memarg.offset,
                rust_rmw_method(mnemonic)?,
                memarg.offset
            );
            rust_atomic_result(mnemonic, lift)
        }
        AtomicOpKind::Cmpxchg => {
            let cell: &str = rust_atomic_cell(mnemonic)?;
            let old: String = rust_atomic_operand(mnemonic, "old")?;
            let new: String = rust_atomic_operand(mnemonic, "new")?;
            let lift: String = format!(
                "match unsafe {{ (&*(ptr.add({}) as *const std::sync::atomic::{cell})).compare_exchange({old}, {new}, {ordering}, {ordering}) /* offset={} */ }} {{ Ok(observed) | Err(observed) => observed }}",
                memarg.offset, memarg.offset
            );
            rust_atomic_result(mnemonic, lift)
        }
        AtomicOpKind::Wait32 | AtomicOpKind::Wait64 => {
            let effective_address: String = rust_effective_address(memarg.offset);
            Some(format!(
                "wait_on_arc_mutex(memory.clone(), {effective_address}, expected, timeout_ns) /* {mnemonic} offset={} */",
                memarg.offset
            ))
        }
        AtomicOpKind::Notify => {
            let effective_address: String = rust_effective_address(memarg.offset);
            Some(format!(
                "notify_arc_mutex(memory.clone(), {effective_address}, count) /* {mnemonic} offset={} */",
                memarg.offset
            ))
        }
        AtomicOpKind::Fence => Some(format!("std::sync::atomic::fence({ordering});")),
    }
}

fn rust_effective_address(offset: u64) -> String {
    format!(
        "match addr.checked_add({offset}) {{ Some(effective_addr) => effective_addr, None => panic!(\"DR-WASMDEOB-THREADS: atomic effective address overflow\") }}"
    )
}

fn rust_atomic_cell(mnemonic: &str) -> Option<&'static str> {
    match mnemonic {
        value if value.starts_with("i32.atomic.rmw8.") || value.starts_with("i64.atomic.rmw8.") => {
            Some("AtomicU8")
        }
        value
            if value.starts_with("i32.atomic.rmw16.") || value.starts_with("i64.atomic.rmw16.") =>
        {
            Some("AtomicU16")
        }
        value if value.starts_with("i64.atomic.rmw32.") => Some("AtomicU32"),
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

fn rust_atomic_operand(mnemonic: &str, operand: &str) -> Option<String> {
    match rust_atomic_cell(mnemonic)? {
        "AtomicU8" => Some(format!("{operand} as u8")),
        "AtomicU16" => Some(format!("{operand} as u16")),
        "AtomicU32" => Some(format!("{operand} as u32")),
        "AtomicI32" | "AtomicI64" => Some(operand.to_owned()),
        _ => None,
    }
}

fn rust_atomic_result(mnemonic: &str, lift: String) -> Option<String> {
    match rust_atomic_cell(mnemonic)? {
        "AtomicU8" | "AtomicU16" if mnemonic.starts_with("i32.") => {
            Some(format!("i32::from({lift})"))
        }
        "AtomicU8" | "AtomicU16" | "AtomicU32" if mnemonic.starts_with("i64.") => {
            Some(format!("i64::from({lift})"))
        }
        "AtomicI32" | "AtomicI64" => Some(lift),
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
    match mnemonic.rsplit('.').next()? {
        "add" | "add_u" => Some("fetch_add"),
        "sub" | "sub_u" => Some("fetch_sub"),
        "and" | "and_u" => Some("fetch_and"),
        "or" | "or_u" => Some("fetch_or"),
        "xor" | "xor_u" => Some("fetch_xor"),
        "xchg" | "xchg_u" => Some("swap"),
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
