use std::collections::BTreeMap;

use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::{AssemblyModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFieldConstants {
    pub by_field_token: BTreeMap<u32, i64>,
    pub all_immediates: Vec<i64>,
}

impl StaticFieldConstants {
    #[must_use]
    pub fn first_u32(&self) -> Option<u32> {
        self.all_immediates
            .iter()
            .copied()
            .find(|&v: &i64| v != 0)
            .map(|v: i64| v as u32)
    }
}

#[must_use]
pub fn fold_cctor_constants(image: &[u8]) -> StaticFieldConstants {
    let Ok(model): Result<AssemblyModel> = build_model(image) else {
        return empty();
    };
    let Ok(pe): Result<PeImage> = parse(image) else {
        return empty();
    };
    let mut by_field: BTreeMap<u32, i64> = BTreeMap::new();
    let mut all: Vec<i64> = Vec::new();
    for ty in &model.types {
        for m in &ty.methods {
            if !m.is_static() || (m.name != ".cctor" && m.name != ".ctor") {
                continue;
            }
            let Some(off): Option<usize> = pe.rva_to_offset(m.rva) else {
                continue;
            };
            if m.rva == 0 || off >= image.len() {
                continue;
            }
            let Ok(body): Result<MethodBody> = parse_method_body(&image[off..]) else {
                continue;
            };
            fold_body(&body, &mut by_field, &mut all);
        }
    }
    StaticFieldConstants {
        by_field_token: by_field,
        all_immediates: all,
    }
}

#[must_use]
pub fn immediates_in_named_method(image: &[u8], name_pred: impl Fn(&str) -> bool) -> Vec<i64> {
    let Ok(model): Result<AssemblyModel> = build_model(image) else {
        return Vec::new();
    };
    let Ok(pe): Result<PeImage> = parse(image) else {
        return Vec::new();
    };
    let mut out: Vec<i64> = Vec::new();
    for ty in &model.types {
        scan_type(image, &pe, ty, &name_pred, &mut out);
    }
    out
}

fn scan_type(
    image: &[u8],
    pe: &PeImage,
    ty: &TypeModel,
    name_pred: &impl Fn(&str) -> bool,
    out: &mut Vec<i64>,
) {
    for m in &ty.methods {
        if !name_pred(&m.name) {
            continue;
        }
        let Some(off): Option<usize> = pe.rva_to_offset(m.rva) else {
            continue;
        };
        if m.rva == 0 || off >= image.len() {
            continue;
        }
        let Ok(body): Result<MethodBody> = parse_method_body(&image[off..]) else {
            continue;
        };
        for ins in &body.instructions {
            if let Some(v) = int_immediate(ins) {
                out.push(v);
            }
        }
    }
}

fn build_model(image: &[u8]) -> Result<AssemblyModel> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)?;
    Ok(resolver.model())
}

fn fold_body(body: &MethodBody, by_field: &mut BTreeMap<u32, i64>, all: &mut Vec<i64>) {
    let mut pending: Option<i64> = None;
    for ins in &body.instructions {
        if let Some(v) = int_immediate(ins) {
            pending = Some(v);
            all.push(v);
            continue;
        }
        match ins.name.as_str() {
            "stsfld" => {
                if let (OperandValue::Token(tok), Some(v)) = (&ins.operand, pending) {
                    by_field.insert(*tok, v);
                }
                pending = None;
            }
            "nop" | "conv.i4" | "conv.u4" | "conv.i8" | "conv.u8" | "dup" => {}
            _ => {
                pending = None;
            }
        }
    }
}

#[must_use]
pub fn int_immediate(ins: &Instruction) -> Option<i64> {
    let name: &str = ins.name.as_str();
    if let Some(rest) = name.strip_prefix("ldc.i4.") {
        return Some(match rest {
            "m1" => -1,
            "s" => match ins.operand {
                OperandValue::U8(b) => i64::from(b.cast_signed()),
                _ => return None,
            },
            d => i64::from(d.parse::<i32>().ok()?),
        });
    }
    match (name, &ins.operand) {
        ("ldc.i4", OperandValue::I32(v)) => Some(i64::from(*v)),
        ("ldc.i8", OperandValue::I64(v)) => Some(*v),
        _ => None,
    }
}

const fn empty() -> StaticFieldConstants {
    StaticFieldConstants {
        by_field_token: BTreeMap::new(),
        all_immediates: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn folds_ldc_i4_stsfld_into_field_constant() {
        let mut code: Vec<u8> = vec![0x20];
        code.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        code.push(0x80);
        code.extend_from_slice(&0x0400_0003u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let mut by_field: BTreeMap<u32, i64> = BTreeMap::new();
        let mut all: Vec<i64> = Vec::new();
        fold_body(&body, &mut by_field, &mut all);
        assert_eq!(by_field.get(&0x0400_0003), Some(&0x1234_5678));
        assert_eq!(all, vec![0x1234_5678]);
    }

    #[test]
    fn short_form_ldc_i4_s_recovered() {
        let body: MethodBody = body_from(&[0x1F, 0x5A, 0x2A]);
        let v: Option<i64> = int_immediate(&body.instructions[0]);
        assert_eq!(v, Some(0x5A));
    }
}
