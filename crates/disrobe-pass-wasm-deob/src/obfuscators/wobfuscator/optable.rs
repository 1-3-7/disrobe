use std::collections::BTreeMap;

use serde::Serialize;
use wasmparser::{ExternalKind, FunctionBody, Parser, Payload, ValType};

use crate::cfg::build_function_cfg;
use crate::error::{Error, Result};
use crate::ssa::{OpKind, SsaFunction, ValueDef, build_ssa};

#[derive(Debug, Clone, Serialize)]
pub struct WobfuscatorTable {
    pub entries: BTreeMap<String, OpKind>,
    pub sidecar_json: String,
}

pub fn extract_optable(wasm_bytes: &[u8]) -> Result<WobfuscatorTable> {
    let layout: ModuleLayout<'_> = scan_module(wasm_bytes)?;
    let mut entries: BTreeMap<String, OpKind> = BTreeMap::new();
    for (name, idx) in &layout.eval_targets {
        let (Some(body), Some(params)): (Option<&FunctionBody<'_>>, Option<&Vec<ValType>>) =
            (layout.bodies.get(*idx), layout.body_param_types.get(*idx))
        else {
            continue;
        };
        if let Some(kind) = first_op_kind(body, params)? {
            entries.insert(name.clone(), kind);
        }
    }
    let sidecar_json: String = serde_json::to_string(&entries).map_err(parse_err)?;
    Ok(WobfuscatorTable {
        entries,
        sidecar_json,
    })
}

#[must_use]
pub fn lift_op_to_rust_fn(export_name: &str, op: OpKind) -> String {
    let body: String =
        op_symbol(op).map_or_else(|| op_expr(op).to_owned(), |sym| format!("a {sym} b"));
    format!("pub fn {export_name}(a: i32, b: i32) -> i32 {{ {body} }}\n")
}

const fn op_symbol(kind: OpKind) -> Option<&'static str> {
    Some(match kind {
        OpKind::I32Add => "+",
        OpKind::I32Sub => "-",
        OpKind::I32Mul => "*",
        OpKind::I32And => "&",
        OpKind::I32Or => "|",
        OpKind::I32Xor => "^",
        OpKind::I32Shl => "<<",
        OpKind::I32ShrU | OpKind::I32ShrS => ">>",
        OpKind::I32Eq => "==",
        OpKind::I32Ne => "!=",
        OpKind::I32LtS | OpKind::I32LtU => "<",
        OpKind::I32GtS | OpKind::I32GtU => ">",
        OpKind::I32LeS | OpKind::I32LeU => "<=",
        OpKind::I32GeS | OpKind::I32GeU => ">=",
        _ => return None,
    })
}

const fn op_expr(kind: OpKind) -> &'static str {
    match kind {
        OpKind::I32DivS => "a.wrapping_div(b)",
        OpKind::I32DivU => "(a as u32).wrapping_div(b as u32) as i32",
        OpKind::I32RemS => "a.wrapping_rem(b)",
        OpKind::I32RemU => "(a as u32).wrapping_rem(b as u32) as i32",
        OpKind::I32Rotl => "a.rotate_left((b as u32) & 31)",
        OpKind::I32Rotr => "a.rotate_right((b as u32) & 31)",
        _ => "a.wrapping_add(b)",
    }
}

fn is_eval_export(name: &str) -> bool {
    let Some(rest): Option<&str> = name.strip_prefix("eval") else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

struct ModuleLayout<'a> {
    bodies: Vec<FunctionBody<'a>>,
    body_param_types: Vec<Vec<ValType>>,
    eval_targets: Vec<(String, usize)>,
}

fn scan_module(wasm_bytes: &[u8]) -> Result<ModuleLayout<'_>> {
    let mut bodies: Vec<FunctionBody<'_>> = Vec::new();
    let mut type_sigs: Vec<Vec<ValType>> = Vec::new();
    let mut func_type_idx: Vec<u32> = Vec::new();
    let mut imported_funcs: u32 = 0;
    let mut exports: Vec<(String, u32)> = Vec::new();

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload: Payload<'_> = payload.map_err(parse_err)?;
        match payload {
            Payload::TypeSection(reader) => {
                for entry in reader.into_iter_with_offsets() {
                    let (_, group): (usize, wasmparser::RecGroup) = entry.map_err(parse_err)?;
                    for sub in group.into_types() {
                        let params: Vec<ValType> = match &sub.composite_type.inner {
                            wasmparser::CompositeInnerType::Func(f) => f.params().to_vec(),
                            _ => Vec::new(),
                        };
                        type_sigs.push(params);
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for group in reader {
                    let group: wasmparser::Imports<'_> = group.map_err(parse_err)?;
                    if let wasmparser::Imports::Single(_, imp) = group
                        && matches!(imp.ty, wasmparser::TypeRef::Func(_))
                    {
                        imported_funcs = imported_funcs.saturating_add(1);
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for f in reader {
                    func_type_idx.push(f.map_err(parse_err)?);
                }
            }
            Payload::ExportSection(reader) => {
                for exp in reader {
                    let exp: wasmparser::Export<'_> = exp.map_err(parse_err)?;
                    if matches!(exp.kind, ExternalKind::Func) && is_eval_export(exp.name) {
                        exports.push((exp.name.to_owned(), exp.index));
                    }
                }
            }
            Payload::CodeSectionEntry(body) => bodies.push(body),
            _ => {}
        }
    }

    let mut eval_targets: Vec<(String, usize)> = Vec::new();
    for (name, abs_idx) in exports {
        if abs_idx < imported_funcs {
            continue;
        }
        let local_idx: usize = (abs_idx - imported_funcs) as usize;
        if local_idx < bodies.len() {
            eval_targets.push((name, local_idx));
        }
    }
    eval_targets.sort_by(|a, b| a.0.cmp(&b.0));

    let body_param_types: Vec<Vec<ValType>> = (0..bodies.len())
        .map(|i| {
            func_type_idx
                .get(i)
                .and_then(|ty_idx| type_sigs.get(*ty_idx as usize).cloned())
                .unwrap_or_default()
        })
        .collect();

    Ok(ModuleLayout {
        bodies,
        body_param_types,
        eval_targets,
    })
}

fn first_op_kind(body: &FunctionBody<'_>, params: &[ValType]) -> Result<Option<OpKind>> {
    let cfg: crate::cfg::FunctionCfg = build_function_cfg(body)?;
    let ssa: SsaFunction = build_ssa(&cfg, body, params)?;
    Ok(scan_first_op(&ssa))
}

fn scan_first_op(ssa: &SsaFunction) -> Option<OpKind> {
    ssa.blocks
        .iter()
        .flat_map(|b| b.instrs.iter())
        .find_map(|vid| match ssa.values.get(vid.0 as usize)? {
            ValueDef::Op { kind, .. } => Some(*kind),
            _ => None,
        })
}

fn parse_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Parse(format!("DR-WASMDEOB-WOBF: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_eval_export_accepts_eval0_eval42() {
        assert!(is_eval_export("eval0"));
        assert!(is_eval_export("eval42"));
    }

    #[test]
    fn is_eval_export_rejects_eval_alone_and_eval_x() {
        assert!(!is_eval_export("eval"));
        assert!(!is_eval_export("evalx"));
        assert!(!is_eval_export("other"));
        assert!(!is_eval_export("eval0x"));
    }

    #[test]
    fn lift_op_to_rust_fn_emits_signature_and_body_for_add() {
        let out: String = lift_op_to_rust_fn("eval0", OpKind::I32Add);
        assert_eq!(out, "pub fn eval0(a: i32, b: i32) -> i32 { a + b }\n");
    }

    #[test]
    fn lift_op_to_rust_fn_emits_correct_symbol_for_sub_and_xor() {
        assert!(lift_op_to_rust_fn("eval1", OpKind::I32Sub).contains("a - b"));
        assert!(lift_op_to_rust_fn("eval2", OpKind::I32Xor).contains("a ^ b"));
    }
}
