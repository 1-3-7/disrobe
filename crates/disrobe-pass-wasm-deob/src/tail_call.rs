use serde::Serialize;
use wasmparser::{Operator, Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum TailCallKind {
    Direct,
    Indirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TailCallRecord {
    pub kind: TailCallKind,
    pub function_index: u32,
    pub callee: u32,
    pub rust_form: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TailCallReport {
    pub records: Vec<TailCallRecord>,
}

impl TailCallReport {
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn direct_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r: &&TailCallRecord| matches!(r.kind, TailCallKind::Direct))
            .count()
    }

    #[inline]
    #[must_use]
    pub fn indirect_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r: &&TailCallRecord| matches!(r.kind, TailCallKind::Indirect))
            .count()
    }
}

pub fn scan_tail_calls(input: &[u8]) -> Result<TailCallReport> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-TAILCALL: not a wasm module".to_owned(),
        ));
    }
    let mut report: TailCallReport = TailCallReport::default();
    let mut function_index: u32 = 0u32;
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let reader: wasmparser::OperatorsReader<'_> = body
                .get_operators_reader()
                .map_err(|e| Error::Parse(format!("{e}")))?;
            for op in reader {
                let op: Operator<'_> = op.map_err(|e| Error::Parse(format!("{e}")))?;
                match op {
                    Operator::ReturnCall { function_index: fi } => {
                        report.records.push(TailCallRecord {
                            kind: TailCallKind::Direct,
                            function_index,
                            callee: fi,
                            rust_form: format!(
                                "#[inline(always)] return fn_{fi}(/* tail */ args);"
                            ),
                        });
                    }
                    Operator::ReturnCallIndirect { type_index, .. } => {
                        report.records.push(TailCallRecord {
                            kind: TailCallKind::Indirect,
                            function_index,
                            callee: type_index,
                            rust_form: format!(
                                "#[inline(always)] return (table[idx] as fn(_) -> _)(/* tail-type-{type_index} */ args);"
                            ),
                        });
                    }
                    _ => {}
                }
            }
            function_index = function_index.saturating_add(1);
        }
    }
    Ok(report)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const TAIL_WAT: &str = r#"
        (module
          (func $callee (param i32) (result i32) local.get 0)
          (func (export "tail") (param i32) (result i32)
            local.get 0
            return_call $callee))
    "#;

    #[test]
    fn return_call_records_as_direct_tail() {
        let bytes: Vec<u8> = wat::parse_str(TAIL_WAT).expect("wat");
        let report: TailCallReport = scan_tail_calls(&bytes).expect("scan");
        assert_eq!(report.direct_count(), 1);
        assert_eq!(report.indirect_count(), 0);
        let rec: &TailCallRecord = report.records.first().expect("rec");
        assert!(rec.rust_form.contains("#[inline(always)]"));
        assert!(rec.rust_form.contains("return fn_0"));
    }
}
