use std::collections::BTreeMap;

use wasmparser::{Operator, Parser, Payload, ValType};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct StubInfo {
    pub fn_index: u32,
    pub key: Option<u8>,
    pub op_histogram: BTreeMap<String, u32>,
    pub confidence: f32,
}

pub fn detect_decrypt_stubs(bytes: &[u8]) -> Result<Vec<StubInfo>> {
    let layout: Layout<'_> = scan_layout(bytes)?;
    let mut out: Vec<StubInfo> = Vec::with_capacity(layout.bodies.len());
    for (local_idx, body) in layout.bodies.iter().enumerate() {
        let fn_index: u32 = layout.imported_funcs + u32::try_from(local_idx).unwrap_or(u32::MAX);
        let Some(sig): Option<FuncSig> = layout.signature_for(local_idx) else {
            continue;
        };
        if !is_two_i32_to_i32(&sig) {
            continue;
        }
        let analysis: BodyAnalysis = analyze_body(body)?;
        let confidence: f32 = score(&analysis);
        if confidence <= 0.5 {
            continue;
        }
        out.push(StubInfo {
            fn_index,
            key: analysis.const_key,
            op_histogram: analysis.histogram,
            confidence,
        });
    }
    Ok(out)
}

fn is_two_i32_to_i32(sig: &FuncSig) -> bool {
    sig.params.len() == 2
        && sig.params.iter().all(|p| matches!(p, ValType::I32))
        && sig.results.len() == 1
        && matches!(sig.results.first(), Some(ValType::I32))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct BodyAnalysis {
    histogram: BTreeMap<String, u32>,
    has_loop: bool,
    has_load8_u: bool,
    has_store8: bool,
    has_xor: bool,
    has_sub: bool,
    has_add: bool,
    const_key: Option<u8>,
    distinct_xor_ops: u32,
}

fn analyze_body(body: &wasmparser::FunctionBody<'_>) -> Result<BodyAnalysis> {
    let mut analysis: BodyAnalysis = BodyAnalysis::default();
    let mut last_const: Option<i32> = None;
    let ops_reader: wasmparser::OperatorsReader<'_> = body
        .get_operators_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;
    for op_result in ops_reader {
        let op: Operator<'_> = op_result.map_err(|e| Error::Parse(e.to_string()))?;
        let name: &'static str = mnemonic(&op);
        *analysis.histogram.entry(name.to_owned()).or_default() += 1;
        match op {
            Operator::Loop { .. } => analysis.has_loop = true,
            Operator::I32Load8U { .. } => analysis.has_load8_u = true,
            Operator::I32Store8 { .. } => analysis.has_store8 = true,
            Operator::I32Const { value } => last_const = Some(value),
            Operator::I32Xor => {
                analysis.has_xor = true;
                analysis.distinct_xor_ops += 1;
                if let Some(key) = last_const.take().and_then(narrow_byte_key) {
                    analysis.const_key = Some(key);
                }
            }
            Operator::I32Sub => {
                analysis.has_sub = true;
                if let Some(key) = last_const.take().and_then(narrow_byte_key) {
                    analysis.const_key = analysis.const_key.or(Some(key));
                }
            }
            Operator::I32Add => {
                analysis.has_add = true;
                if let Some(key) = last_const.take().and_then(narrow_byte_key) {
                    analysis.const_key = analysis.const_key.or(Some(key));
                }
            }
            _ => {
                last_const = None;
            }
        }
    }
    Ok(analysis)
}

fn narrow_byte_key(c: i32) -> Option<u8> {
    u8::try_from(c).ok()
}

fn score(a: &BodyAnalysis) -> f32 {
    let loop_byte_walk: bool = a.has_loop && a.has_load8_u && a.has_store8;
    if !loop_byte_walk {
        return 0.0;
    }
    let single_xor: bool = a.has_xor && a.distinct_xor_ops == 1;
    let single_keyed_op: bool = single_xor || ((a.has_sub || a.has_add) && !a.has_xor);
    let mut score: f32 = 0.6;
    if single_keyed_op {
        score += 0.25;
    }
    if a.const_key.is_some() {
        score += 0.1;
    }
    if a.histogram.contains_key("i32.load8_u") && a.histogram.contains_key("i32.store8") {
        score += 0.05;
    }
    score.min(1.0)
}

const fn mnemonic(op: &Operator<'_>) -> &'static str {
    match op {
        Operator::Loop { .. } => "loop",
        Operator::Block { .. } => "block",
        Operator::If { .. } => "if",
        Operator::Else => "else",
        Operator::End => "end",
        Operator::Br { .. } => "br",
        Operator::BrIf { .. } => "br_if",
        Operator::BrTable { .. } => "br_table",
        Operator::Return => "return",
        Operator::Unreachable => "unreachable",
        Operator::Drop => "drop",
        Operator::Select => "select",
        Operator::LocalGet { .. } => "local.get",
        Operator::LocalSet { .. } => "local.set",
        Operator::LocalTee { .. } => "local.tee",
        Operator::I32Const { .. } => "i32.const",
        Operator::I64Const { .. } => "i64.const",
        Operator::I32Load { .. } => "i32.load",
        Operator::I32Load8U { .. } => "i32.load8_u",
        Operator::I32Load8S { .. } => "i32.load8_s",
        Operator::I32Load16U { .. } => "i32.load16_u",
        Operator::I32Load16S { .. } => "i32.load16_s",
        Operator::I32Store { .. } => "i32.store",
        Operator::I32Store8 { .. } => "i32.store8",
        Operator::I32Store16 { .. } => "i32.store16",
        Operator::I32Add => "i32.add",
        Operator::I32Sub => "i32.sub",
        Operator::I32Mul => "i32.mul",
        Operator::I32And => "i32.and",
        Operator::I32Or => "i32.or",
        Operator::I32Xor => "i32.xor",
        Operator::I32Shl => "i32.shl",
        Operator::I32ShrU => "i32.shr_u",
        Operator::I32ShrS => "i32.shr_s",
        Operator::I32Eq => "i32.eq",
        Operator::I32Ne => "i32.ne",
        Operator::I32LtU => "i32.lt_u",
        Operator::I32LtS => "i32.lt_s",
        Operator::I32GeU => "i32.ge_u",
        Operator::I32GeS => "i32.ge_s",
        Operator::I32LeU => "i32.le_u",
        Operator::I32LeS => "i32.le_s",
        Operator::I32GtU => "i32.gt_u",
        Operator::I32GtS => "i32.gt_s",
        Operator::Call { .. } => "call",
        Operator::CallIndirect { .. } => "call_indirect",
        _ => "other",
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FuncSig {
    params: Vec<ValType>,
    results: Vec<ValType>,
}

#[derive(Debug, Default)]
struct Layout<'a> {
    types: Vec<FuncSig>,
    function_type_indices: Vec<u32>,
    imported_funcs: u32,
    bodies: Vec<wasmparser::FunctionBody<'a>>,
}

impl Layout<'_> {
    fn signature_for(&self, local_idx: usize) -> Option<FuncSig> {
        let ty_idx: usize = *self.function_type_indices.get(local_idx)? as usize;
        self.types.get(ty_idx).cloned()
    }
}

fn scan_layout(bytes: &[u8]) -> Result<Layout<'_>> {
    let mut layout: Layout<'_> = Layout::default();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(e.to_string()))?;
        match payload {
            Payload::TypeSection(reader) => {
                for entry in reader.into_iter_with_offsets() {
                    let (_, group): (usize, wasmparser::RecGroup) =
                        entry.map_err(|e| Error::Parse(e.to_string()))?;
                    for sub in group.into_types() {
                        if let wasmparser::CompositeInnerType::Func(ft) = sub.composite_type.inner {
                            layout.types.push(FuncSig {
                                params: ft.params().to_vec(),
                                results: ft.results().to_vec(),
                            });
                        } else {
                            layout.types.push(FuncSig::default());
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for group in reader {
                    let group: wasmparser::Imports<'_> =
                        group.map_err(|e| Error::Parse(e.to_string()))?;
                    if let wasmparser::Imports::Single(_, imp) = group
                        && matches!(imp.ty, wasmparser::TypeRef::Func(_))
                    {
                        layout.imported_funcs = layout.imported_funcs.saturating_add(1);
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for entry in reader {
                    let ty_idx: u32 = entry.map_err(|e| Error::Parse(e.to_string()))?;
                    layout.function_type_indices.push(ty_idx);
                }
            }
            Payload::CodeSectionEntry(body) => {
                layout.bodies.push(body);
            }
            _ => {}
        }
    }
    Ok(layout)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[test]
    fn score_zero_when_no_byte_walk_loop() {
        let a: BodyAnalysis = BodyAnalysis {
            has_xor: true,
            const_key: Some(0x42),
            ..Default::default()
        };
        assert_eq!(score(&a), 0.0);
    }

    #[test]
    fn score_exceeds_threshold_for_xor_loop_with_key() {
        let mut a: BodyAnalysis = BodyAnalysis {
            has_loop: true,
            has_load8_u: true,
            has_store8: true,
            has_xor: true,
            const_key: Some(0x42),
            distinct_xor_ops: 1,
            ..Default::default()
        };
        a.histogram.insert("i32.load8_u".to_owned(), 1);
        a.histogram.insert("i32.store8".to_owned(), 1);
        assert!(score(&a) > 0.9, "score={}", score(&a));
    }

    #[test]
    fn is_two_i32_to_i32_accepts_canonical_decrypt_sig() {
        let sig: FuncSig = FuncSig {
            params: vec![ValType::I32, ValType::I32],
            results: vec![ValType::I32],
        };
        assert!(is_two_i32_to_i32(&sig));
    }

    #[test]
    fn is_two_i32_to_i32_rejects_other_signatures() {
        let sig: FuncSig = FuncSig {
            params: vec![ValType::I64, ValType::I32],
            results: vec![ValType::I32],
        };
        assert!(!is_two_i32_to_i32(&sig));
    }
}
