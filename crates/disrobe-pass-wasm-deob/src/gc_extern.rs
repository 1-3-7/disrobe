use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{Operator, Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ExternConvKind {
    AnyToExtern,
    ExternToAny,
}

impl ExternConvKind {
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::AnyToExtern => "extern.convert_any",
            Self::ExternToAny => "any.convert_extern",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternConvOpRecord {
    pub function_index: u32,
    pub operator_offset: usize,
    pub kind: ExternConvKind,
    pub rust_lift: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GcExternReport {
    pub ops: Vec<ExternConvOpRecord>,
    pub any_to_extern: usize,
    pub extern_to_any: usize,
    pub functions_using: BTreeMap<u32, usize>,
}

impl GcExternReport {
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.any_to_extern == 0 && self.extern_to_any == 0
    }

    #[inline]
    #[must_use]
    pub const fn op_count(&self) -> usize {
        self.ops.len()
    }
}

pub fn scan_gc_extern(input: &[u8]) -> Result<GcExternReport> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-GCEXT: not a wasm module".to_owned(),
        ));
    }
    let mut report: GcExternReport = GcExternReport::default();
    let mut fn_index: u32 = 0u32;
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let mut reader = body
                .get_operators_reader()
                .map_err(|e| Error::Parse(format!("{e}")))?;
            while !reader.eof() {
                let pos: usize = reader.original_position();
                let op: Operator<'_> = reader.read().map_err(|e| Error::Parse(format!("{e}")))?;
                let Some(record): Option<ExternConvOpRecord> = classify(fn_index, pos, &op) else {
                    continue;
                };
                match record.kind {
                    ExternConvKind::AnyToExtern => {
                        report.any_to_extern = report.any_to_extern.saturating_add(1);
                    }
                    ExternConvKind::ExternToAny => {
                        report.extern_to_any = report.extern_to_any.saturating_add(1);
                    }
                }
                *report.functions_using.entry(fn_index).or_insert(0usize) += 1usize;
                report.ops.push(record);
            }
            fn_index = fn_index.saturating_add(1);
        }
    }
    Ok(report)
}

const fn classify(
    function_index: u32,
    operator_offset: usize,
    op: &Operator<'_>,
) -> Option<ExternConvOpRecord> {
    match op {
        Operator::ExternConvertAny => Some(ExternConvOpRecord {
            function_index,
            operator_offset,
            kind: ExternConvKind::AnyToExtern,
            rust_lift: "let externalized: ExternRef = ExternRef::from_anyref(any);",
        }),
        Operator::AnyConvertExtern => Some(ExternConvOpRecord {
            function_index,
            operator_offset,
            kind: ExternConvKind::ExternToAny,
            rust_lift: "let internalized: AnyRef = AnyRef::from_externref(ext);",
        }),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const WAT_EXTERN: &str = r#"
        (module
          (func (export "go") (param externref) (result externref)
            local.get 0
            any.convert_extern
            extern.convert_any))
    "#;

    fn try_wat(src: &str) -> Option<Vec<u8>> {
        wat::parse_str(src).ok()
    }

    #[test]
    fn detects_both_directions_when_supported() {
        let Some(bytes): Option<Vec<u8>> = try_wat(WAT_EXTERN) else {
            return;
        };
        let report: GcExternReport = scan_gc_extern(&bytes).expect("scan");
        assert_eq!(report.any_to_extern, 1usize);
        assert_eq!(report.extern_to_any, 1usize);
    }

    #[test]
    fn empty_module_reports_zero() {
        let bytes: Vec<u8> = wat::parse_str("(module)").expect("wat");
        let report: GcExternReport = scan_gc_extern(&bytes).expect("scan");
        assert!(report.is_empty());
    }

    #[test]
    fn rejects_non_wasm_input() {
        let err: Error = scan_gc_extern(b"not wasm").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }
}
