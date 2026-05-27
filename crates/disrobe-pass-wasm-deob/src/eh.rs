use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use wasmparser::{Catch, Operator, Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum EhConstruct {
    LegacyTry,
    TryTable,
    Catch,
    CatchAll,
    CatchRef,
    CatchAllRef,
    Throw,
    ThrowRef,
    Rethrow,
    Delegate,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EhTagSummary {
    pub throws: u32,
    pub catches: u32,
    pub catches_ref: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EhFunctionSummary {
    pub function_index: u32,
    pub legacy_try_blocks: u32,
    pub try_table_blocks: u32,
    pub catch_all_arms: u32,
    pub catch_all_ref_arms: u32,
    pub rethrows: u32,
    pub delegates: u32,
    pub throw_refs: u32,
    pub constructs: BTreeSet<EhConstruct>,
    pub per_tag: BTreeMap<u32, EhTagSummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EhModuleSummary {
    pub functions: BTreeMap<u32, EhFunctionSummary>,
    pub tag_section_count: u32,
    pub constructs: BTreeSet<EhConstruct>,
    pub per_tag: BTreeMap<u32, EhTagSummary>,
}

impl EhModuleSummary {
    #[must_use]
    #[inline]
    pub fn uses_exception_handling(&self) -> bool {
        !self.constructs.is_empty() || self.tag_section_count > 0
    }

    #[must_use]
    #[inline]
    pub fn uses_legacy_eh(&self) -> bool {
        self.constructs.contains(&EhConstruct::LegacyTry)
            || self.constructs.contains(&EhConstruct::Delegate)
            || self.constructs.contains(&EhConstruct::Rethrow)
    }

    #[must_use]
    #[inline]
    pub fn uses_modern_eh(&self) -> bool {
        self.constructs.contains(&EhConstruct::TryTable)
            || self.constructs.contains(&EhConstruct::ThrowRef)
    }
}

#[must_use]
#[inline]
pub fn lift_tag_to_rust_result(tag_index: u32, fn_name: &str) -> String {
    format!(
        "pub fn {fn_name}() -> Result<(), Exception{tag_index}> {{ Err(Exception{tag_index}) }}\n"
    )
}

pub fn scan_module(bytes: &[u8]) -> Result<EhModuleSummary> {
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-EH: not a wasm module (missing \\0asm magic)".to_owned(),
        ));
    }
    let mut summary: EhModuleSummary = EhModuleSummary::default();
    let mut function_local_index: u32 = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(parse_err)?;
        match payload {
            Payload::TagSection(reader) => {
                summary.tag_section_count = reader.count();
            }
            Payload::CodeSectionEntry(body) => {
                let func: EhFunctionSummary = scan_body(function_local_index, &body)?;
                for c in &func.constructs {
                    summary.constructs.insert(*c);
                }
                merge_per_tag(&mut summary.per_tag, &func.per_tag);
                summary.functions.insert(function_local_index, func);
                function_local_index = function_local_index.saturating_add(1);
            }
            _ => {}
        }
    }
    Ok(summary)
}

fn scan_body(
    function_index: u32,
    body: &wasmparser::FunctionBody<'_>,
) -> Result<EhFunctionSummary> {
    let mut out: EhFunctionSummary = EhFunctionSummary {
        function_index,
        ..EhFunctionSummary::default()
    };
    let reader: wasmparser::OperatorsReader<'_> = body.get_operators_reader().map_err(parse_err)?;
    for op_result in reader {
        let op: Operator<'_> = op_result.map_err(parse_err)?;
        record_op(&op, &mut out);
    }
    Ok(out)
}

fn record_op(op: &Operator<'_>, out: &mut EhFunctionSummary) {
    match op {
        Operator::Try { .. } => {
            out.legacy_try_blocks = out.legacy_try_blocks.saturating_add(1);
            out.constructs.insert(EhConstruct::LegacyTry);
        }
        Operator::TryTable { try_table } => {
            out.try_table_blocks = out.try_table_blocks.saturating_add(1);
            out.constructs.insert(EhConstruct::TryTable);
            record_try_table(out, &try_table.catches);
        }
        Operator::Catch { tag_index } => {
            out.constructs.insert(EhConstruct::Catch);
            let entry: &mut EhTagSummary = out.per_tag.entry(*tag_index).or_default();
            entry.catches = entry.catches.saturating_add(1);
        }
        Operator::CatchAll => {
            out.catch_all_arms = out.catch_all_arms.saturating_add(1);
            out.constructs.insert(EhConstruct::CatchAll);
        }
        Operator::Throw { tag_index } => {
            out.constructs.insert(EhConstruct::Throw);
            let entry: &mut EhTagSummary = out.per_tag.entry(*tag_index).or_default();
            entry.throws = entry.throws.saturating_add(1);
        }
        Operator::ThrowRef => {
            out.throw_refs = out.throw_refs.saturating_add(1);
            out.constructs.insert(EhConstruct::ThrowRef);
        }
        Operator::Rethrow { .. } => {
            out.rethrows = out.rethrows.saturating_add(1);
            out.constructs.insert(EhConstruct::Rethrow);
        }
        Operator::Delegate { .. } => {
            out.delegates = out.delegates.saturating_add(1);
            out.constructs.insert(EhConstruct::Delegate);
        }
        _ => {}
    }
}

fn record_try_table(out: &mut EhFunctionSummary, catches: &[Catch]) {
    for catch in catches {
        match *catch {
            Catch::One { tag, .. } => {
                out.constructs.insert(EhConstruct::Catch);
                let entry: &mut EhTagSummary = out.per_tag.entry(tag).or_default();
                entry.catches = entry.catches.saturating_add(1);
            }
            Catch::OneRef { tag, .. } => {
                out.constructs.insert(EhConstruct::CatchRef);
                let entry: &mut EhTagSummary = out.per_tag.entry(tag).or_default();
                entry.catches_ref = entry.catches_ref.saturating_add(1);
            }
            Catch::All { .. } => {
                out.catch_all_arms = out.catch_all_arms.saturating_add(1);
                out.constructs.insert(EhConstruct::CatchAll);
            }
            Catch::AllRef { .. } => {
                out.catch_all_ref_arms = out.catch_all_ref_arms.saturating_add(1);
                out.constructs.insert(EhConstruct::CatchAllRef);
            }
        }
    }
}

fn merge_per_tag(dst: &mut BTreeMap<u32, EhTagSummary>, src: &BTreeMap<u32, EhTagSummary>) {
    for (tag, summary) in src {
        let entry: &mut EhTagSummary = dst.entry(*tag).or_default();
        entry.throws = entry.throws.saturating_add(summary.throws);
        entry.catches = entry.catches.saturating_add(summary.catches);
        entry.catches_ref = entry.catches_ref.saturating_add(summary.catches_ref);
    }
}

fn parse_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Parse(format!("DR-WASMDEOB-EH: {e}"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn empty_module() -> Vec<u8> {
        vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    #[test]
    fn rejects_non_wasm_bytes() {
        let Err(err) = scan_module(b"definitely not wasm") else {
            panic!("must reject non-wasm bytes");
        };
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn empty_module_yields_no_eh() {
        let summary: EhModuleSummary = scan_module(&empty_module()).expect("must parse");
        assert!(!summary.uses_exception_handling());
        assert_eq!(summary.tag_section_count, 0);
        assert!(summary.constructs.is_empty());
        assert!(summary.per_tag.is_empty());
    }

    #[test]
    fn lift_tag_to_rust_result_emits_named_exception_type() {
        let rust: String = lift_tag_to_rust_result(7, "may_fail");
        assert!(rust.contains("Result<(), Exception7>"));
        assert!(rust.contains("may_fail"));
    }

    #[test]
    fn merge_per_tag_sums_throws_and_catches() {
        let mut dst: BTreeMap<u32, EhTagSummary> = BTreeMap::new();
        dst.insert(
            0,
            EhTagSummary {
                throws: 1,
                catches: 2,
                catches_ref: 0,
            },
        );
        let mut src: BTreeMap<u32, EhTagSummary> = BTreeMap::new();
        src.insert(
            0,
            EhTagSummary {
                throws: 4,
                catches: 0,
                catches_ref: 1,
            },
        );
        src.insert(
            1,
            EhTagSummary {
                throws: 1,
                catches: 1,
                catches_ref: 0,
            },
        );
        merge_per_tag(&mut dst, &src);
        let tag0: &EhTagSummary = dst.get(&0).expect("tag 0 must exist");
        assert_eq!(tag0.throws, 5);
        assert_eq!(tag0.catches, 2);
        assert_eq!(tag0.catches_ref, 1);
        let tag1: &EhTagSummary = dst.get(&1).expect("tag 1 must exist after merge");
        assert_eq!(tag1.throws, 1);
        assert_eq!(tag1.catches, 1);
    }

    #[test]
    fn modern_classification_reads_try_table_construct() {
        let mut summary: EhModuleSummary = EhModuleSummary::default();
        summary.constructs.insert(EhConstruct::TryTable);
        assert!(summary.uses_modern_eh());
        assert!(!summary.uses_legacy_eh());
    }
}
