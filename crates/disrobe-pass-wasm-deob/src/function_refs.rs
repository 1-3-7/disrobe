use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{Operator, Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum FuncRefOpKind {
    CallRef,
    ReturnCallRef,
    RefAsNonNull,
    BrOnNull,
    BrOnNonNull,
    RefFunc,
}

impl FuncRefOpKind {
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::CallRef => "call_ref",
            Self::ReturnCallRef => "return_call_ref",
            Self::RefAsNonNull => "ref.as_non_null",
            Self::BrOnNull => "br_on_null",
            Self::BrOnNonNull => "br_on_non_null",
            Self::RefFunc => "ref.func",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FuncRefOpRecord {
    pub function_index: u32,
    pub operator_offset: usize,
    pub kind: FuncRefOpKind,
    pub type_index: Option<u32>,
    pub function_target: Option<u32>,
    pub relative_depth: Option<u32>,
    pub rust_lift: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FuncRefReport {
    pub ops: Vec<FuncRefOpRecord>,
    pub kinds: BTreeMap<FuncRefOpKind, usize>,
    pub uses_tail_call_ref: bool,
    pub uses_br_on_null_family: bool,
    pub typed_function_ref_count: usize,
    pub functions_using: BTreeMap<u32, usize>,
}

impl FuncRefReport {
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    #[inline]
    #[must_use]
    pub const fn op_count(&self) -> usize {
        self.ops.len()
    }
}

pub fn scan_function_refs(input: &[u8]) -> Result<FuncRefReport> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-FUNCREF: not a wasm module".to_owned(),
        ));
    }
    let mut report: FuncRefReport = FuncRefReport::default();
    let mut fn_index: u32 = 0u32;
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let mut reader: wasmparser::OperatorsReader<'_> = body
                .get_operators_reader()
                .map_err(|e| Error::Parse(format!("{e}")))?;
            while !reader.eof() {
                let pos: usize = reader.original_position();
                let op: Operator<'_> = reader.read().map_err(|e| Error::Parse(format!("{e}")))?;
                let Some(record): Option<FuncRefOpRecord> = classify(fn_index, pos, &op) else {
                    continue;
                };
                let kind: FuncRefOpKind = record.kind;
                *report.kinds.entry(kind).or_insert(0usize) += 1usize;
                *report.functions_using.entry(fn_index).or_insert(0usize) += 1usize;
                if matches!(kind, FuncRefOpKind::ReturnCallRef) {
                    report.uses_tail_call_ref = true;
                }
                if matches!(kind, FuncRefOpKind::BrOnNull | FuncRefOpKind::BrOnNonNull) {
                    report.uses_br_on_null_family = true;
                }
                if record.type_index.is_some() {
                    report.typed_function_ref_count =
                        report.typed_function_ref_count.saturating_add(1);
                }
                report.ops.push(record);
            }
            fn_index = fn_index.saturating_add(1);
        }
    }
    Ok(report)
}

fn classify(
    function_index: u32,
    operator_offset: usize,
    op: &Operator<'_>,
) -> Option<FuncRefOpRecord> {
    match op {
        Operator::CallRef { type_index } => Some(FuncRefOpRecord {
            function_index,
            operator_offset,
            kind: FuncRefOpKind::CallRef,
            type_index: Some(*type_index),
            function_target: None,
            relative_depth: None,
            rust_lift: format!("let result = (callee_ref as fn_type_{type_index})(args);"),
        }),
        Operator::ReturnCallRef { type_index } => Some(FuncRefOpRecord {
            function_index,
            operator_offset,
            kind: FuncRefOpKind::ReturnCallRef,
            type_index: Some(*type_index),
            function_target: None,
            relative_depth: None,
            rust_lift: format!(
                "return (callee_ref as fn_type_{type_index})(args); /* tail-call */"
            ),
        }),
        Operator::RefAsNonNull => Some(FuncRefOpRecord {
            function_index,
            operator_offset,
            kind: FuncRefOpKind::RefAsNonNull,
            type_index: None,
            function_target: None,
            relative_depth: None,
            rust_lift: "let nn = r.expect(\"DR-WASMDEOB-FUNCREF: null ref unwrap\");".to_owned(),
        }),
        Operator::BrOnNull { relative_depth } => Some(FuncRefOpRecord {
            function_index,
            operator_offset,
            kind: FuncRefOpKind::BrOnNull,
            type_index: None,
            function_target: None,
            relative_depth: Some(*relative_depth),
            rust_lift: format!("if r.is_none() {{ break 'b{relative_depth}; }}"),
        }),
        Operator::BrOnNonNull { relative_depth } => Some(FuncRefOpRecord {
            function_index,
            operator_offset,
            kind: FuncRefOpKind::BrOnNonNull,
            type_index: None,
            function_target: None,
            relative_depth: Some(*relative_depth),
            rust_lift: format!("if let Some(nn) = r {{ /* push nn */ break 'b{relative_depth}; }}"),
        }),
        Operator::RefFunc {
            function_index: target,
        } => Some(FuncRefOpRecord {
            function_index,
            operator_offset,
            kind: FuncRefOpKind::RefFunc,
            type_index: None,
            function_target: Some(*target),
            relative_depth: None,
            rust_lift: format!("let r = Some(fn_{target} as fn(_) -> _);"),
        }),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const WAT_CALL_REF: &str = r#"
        (module
          (type $ft (func (param i32) (result i32)))
          (func $square (param i32) (result i32)
            local.get 0
            local.get 0
            i32.mul)
          (func (export "go") (param i32) (result i32)
            local.get 0
            ref.func $square
            call_ref $ft))
    "#;

    const WAT_BR_ON_NULL: &str = r#"
        (module
          (type $ft (func))
          (func (export "go") (param (ref null $ft))
            block $b (result (ref $ft))
              local.get 0
              br_on_null $b
            end
            call_ref $ft))
    "#;

    fn try_wat(src: &str) -> Option<Vec<u8>> {
        wat::parse_str(src).ok()
    }

    #[test]
    fn detects_call_ref_and_typed_func_ref() {
        let Some(bytes): Option<Vec<u8>> = try_wat(WAT_CALL_REF) else {
            return;
        };
        let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
        assert!(report.kinds.contains_key(&FuncRefOpKind::CallRef));
        assert!(report.kinds.contains_key(&FuncRefOpKind::RefFunc));
        assert!(report.typed_function_ref_count >= 1usize);
    }

    #[test]
    fn detects_br_on_null_family() {
        let Some(bytes): Option<Vec<u8>> = try_wat(WAT_BR_ON_NULL) else {
            return;
        };
        let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
        assert!(report.uses_br_on_null_family);
    }

    #[test]
    fn empty_module_is_empty() {
        let bytes: Vec<u8> = wat::parse_str("(module)").expect("wat");
        let report: FuncRefReport = scan_function_refs(&bytes).expect("scan");
        assert!(report.is_empty());
    }

    #[test]
    fn rejects_non_wasm_input() {
        let err: Error = scan_function_refs(b"not wasm").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }
}
