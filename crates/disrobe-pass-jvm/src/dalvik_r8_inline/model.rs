use std::collections::BTreeMap;

use crate::dalvik::DalvikInsn;
use crate::decompile::Expr;
use crate::descriptor;
use crate::dex::{DexFile, FieldId};

pub(crate) struct HelperModel {
    pub(crate) return_expr: Expr,
    pub(crate) param_count: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum GateStatus {
    Green,
    Rejected(String),
}

fn placeholder(index: usize) -> String {
    format!("$p{index}")
}

const fn is_category_two(descriptor: &str) -> bool {
    matches!(descriptor.as_bytes().first(), Some(b'J' | b'D'))
}

const fn cast_target(op: u8) -> &'static str {
    match op {
        0x81 | 0x88 | 0x8B => "long",
        0x82 | 0x85 | 0x8C => "float",
        0x83 | 0x86 | 0x89 => "double",
        0x84 | 0x87 | 0x8A => "int",
        0x8D => "byte",
        0x8E => "char",
        0x8F => "short",
        _ => "int",
    }
}

const fn arith_op(op: u8) -> &'static str {
    match op {
        0x90 | 0x9B | 0xA6 | 0xAB | 0xB0 | 0xBB | 0xC6 | 0xCB => "+",
        0x91 | 0x9C | 0xA7 | 0xAC | 0xB1 | 0xBC | 0xC7 | 0xCC => "-",
        0x92 | 0x9D | 0xA8 | 0xAD | 0xB2 | 0xBD | 0xC8 | 0xCD => "*",
        0x93 | 0x9E | 0xA9 | 0xAE | 0xB3 | 0xBE | 0xC9 | 0xCE => "/",
        0x94 | 0x9F | 0xAA | 0xAF | 0xB4 | 0xBF | 0xCA | 0xCF => "%",
        0x95 | 0xA0 | 0xB5 | 0xC0 => "&",
        0x96 | 0xA1 | 0xB6 | 0xC1 => "|",
        0x97 | 0xA2 | 0xB7 | 0xC2 => "^",
        0x98 | 0xA3 | 0xB8 | 0xC3 => "<<",
        0x99 | 0xA4 | 0xB9 | 0xC4 => ">>",
        0x9A | 0xA5 | 0xBA | 0xC5 => ">>>",
        _ => "?",
    }
}

const fn arith_lit_op(op: u8) -> &'static str {
    match op {
        0xD0 | 0xD8 => "+",
        0xD1 | 0xD9 => "-",
        0xD2 | 0xDA => "*",
        0xD3 | 0xDB => "/",
        0xD4 | 0xDC => "%",
        0xD5 | 0xDD => "&",
        0xD6 | 0xDE => "|",
        0xD7 | 0xDF => "^",
        0xE0 => "<<",
        0xE1 => ">>",
        0xE2 => ">>>",
        _ => "?",
    }
}

struct Regs {
    slots: BTreeMap<u16, Expr>,
}

impl Regs {
    fn read(&self, reg: u16) -> Expr {
        self.slots
            .get(&reg)
            .cloned()
            .unwrap_or_else(|| Expr::Local(format!("v{reg}")))
    }

    fn write(&mut self, reg: u16, value: Expr) {
        self.slots.insert(reg, value);
    }
}

fn const_literal(op: u8, raw: i64) -> String {
    let value: i64 = match op {
        0x15 => i64::from((raw as i32).wrapping_shl(16)),
        0x19 => raw.wrapping_shl(48),
        _ => raw,
    };
    if matches!(op, 0x16..=0x19) {
        format!("{value}L")
    } else {
        value.to_string()
    }
}

fn resolve_field<'a>(dex: &'a DexFile, insn: &DalvikInsn) -> Option<&'a FieldId> {
    insn.index.and_then(|i| dex.field_ids.get(i as usize))
}

fn resolve_type(dex: &DexFile, insn: &DalvikInsn) -> String {
    insn.index
        .and_then(|i| dex.type_names.get(i as usize))
        .map_or_else(|| "Object".to_string(), |d| descriptor::binary_to_source(d))
}

enum Step {
    Continue,
    Return(Expr),
    Abstain,
}

fn eval_insn(dex: &DexFile, regs: &mut Regs, insn: &DalvikInsn) -> Step {
    let op: u8 = insn.op;
    let r: &[u16] = &insn.regs;
    match op {
        0x00 => Step::Continue,
        0x01..=0x09 => {
            let (Some(&dst), Some(&src)): (Option<&u16>, Option<&u16>) = (r.first(), r.get(1))
            else {
                return Step::Abstain;
            };
            let value: Expr = regs.read(src);
            regs.write(dst, value);
            Step::Continue
        }
        0x0E => Step::Abstain,
        0x0F..=0x11 => {
            let Some(&src): Option<&u16> = r.first() else {
                return Step::Abstain;
            };
            Step::Return(regs.read(src))
        }
        0x12..=0x19 => {
            let Some(&dst): Option<&u16> = r.first() else {
                return Step::Abstain;
            };
            regs.write(
                dst,
                Expr::Const(const_literal(op, insn.literal.unwrap_or(0))),
            );
            Step::Continue
        }
        0x1A | 0x1B => {
            let Some(&dst): Option<&u16> = r.first() else {
                return Step::Abstain;
            };
            let text: String = insn
                .index
                .and_then(|i| dex.strings.get(i as usize))
                .map_or_else(|| "\"\"".to_string(), |s| format!("{s:?}"));
            regs.write(dst, Expr::Const(text));
            Step::Continue
        }
        0x1C => {
            let Some(&dst): Option<&u16> = r.first() else {
                return Step::Abstain;
            };
            regs.write(
                dst,
                Expr::Const(format!("{}.class", resolve_type(dex, insn))),
            );
            Step::Continue
        }
        0x1F => {
            let Some(&dst): Option<&u16> = r.first() else {
                return Step::Abstain;
            };
            let value: Expr = regs.read(dst);
            regs.write(
                dst,
                Expr::Cast {
                    ty: resolve_type(dex, insn),
                    value: Box::new(value),
                },
            );
            Step::Continue
        }
        0x20 => {
            let (Some(&dst), Some(&src)): (Option<&u16>, Option<&u16>) = (r.first(), r.get(1))
            else {
                return Step::Abstain;
            };
            regs.write(
                dst,
                Expr::InstanceOf {
                    value: Box::new(regs.read(src)),
                    ty: resolve_type(dex, insn),
                },
            );
            Step::Continue
        }
        0x21 => {
            let (Some(&dst), Some(&src)): (Option<&u16>, Option<&u16>) = (r.first(), r.get(1))
            else {
                return Step::Abstain;
            };
            regs.write(dst, Expr::ArrayLength(Box::new(regs.read(src))));
            Step::Continue
        }
        0x44..=0x4A => {
            let (Some(&dst), Some(&arr), Some(&idx)): (Option<&u16>, Option<&u16>, Option<&u16>) =
                (r.first(), r.get(1), r.get(2))
            else {
                return Step::Abstain;
            };
            regs.write(
                dst,
                Expr::ArrayLoad {
                    array: Box::new(regs.read(arr)),
                    index: Box::new(regs.read(idx)),
                },
            );
            Step::Continue
        }
        0x52..=0x58 => {
            let (Some(&dst), Some(&obj)): (Option<&u16>, Option<&u16>) = (r.first(), r.get(1))
            else {
                return Step::Abstain;
            };
            let Some(field): Option<&FieldId> = resolve_field(dex, insn) else {
                return Step::Abstain;
            };
            regs.write(
                dst,
                Expr::Field {
                    receiver: Box::new(regs.read(obj)),
                    owner: field.class.clone(),
                    name: field.name.clone(),
                    boolean: field.type_name == "Z",
                },
            );
            Step::Continue
        }
        0x60..=0x66 => {
            let Some(&dst): Option<&u16> = r.first() else {
                return Step::Abstain;
            };
            let Some(field): Option<&FieldId> = resolve_field(dex, insn) else {
                return Step::Abstain;
            };
            regs.write(
                dst,
                Expr::StaticField {
                    owner: descriptor::binary_to_source(&field.class),
                    name: field.name.clone(),
                    boolean: field.type_name == "Z",
                },
            );
            Step::Continue
        }
        0x7B | 0x7D | 0x7F => unary(regs, r, "-"),
        0x7C | 0x7E => unary(regs, r, "~"),
        0x81..=0x8F => {
            let (Some(&dst), Some(&src)): (Option<&u16>, Option<&u16>) = (r.first(), r.get(1))
            else {
                return Step::Abstain;
            };
            regs.write(
                dst,
                Expr::Cast {
                    ty: cast_target(op).to_string(),
                    value: Box::new(regs.read(src)),
                },
            );
            Step::Continue
        }
        0x90..=0xAF => binary_three(regs, r, arith_op(op)),
        0xB0..=0xCF => binary_2addr(regs, r, arith_op(op)),
        0x2D..=0x31 => {
            let (Some(&dst), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
                (r.first(), r.get(1), r.get(2))
            else {
                return Step::Abstain;
            };
            regs.write(
                dst,
                Expr::Cmp {
                    lhs: Box::new(regs.read(lhs)),
                    rhs: Box::new(regs.read(rhs)),
                },
            );
            Step::Continue
        }
        0xD0..=0xE2 => binary_lit(regs, r, insn, arith_lit_op(op)),
        _ => Step::Abstain,
    }
}

fn unary(regs: &mut Regs, r: &[u16], op: &'static str) -> Step {
    let (Some(&dst), Some(&src)): (Option<&u16>, Option<&u16>) = (r.first(), r.get(1)) else {
        return Step::Abstain;
    };
    regs.write(
        dst,
        Expr::Unary {
            op,
            value: Box::new(regs.read(src)),
        },
    );
    Step::Continue
}

fn binary_three(regs: &mut Regs, r: &[u16], op: &'static str) -> Step {
    let (Some(&dst), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (r.first(), r.get(1), r.get(2))
    else {
        return Step::Abstain;
    };
    regs.write(
        dst,
        Expr::Binary {
            op,
            lhs: Box::new(regs.read(lhs)),
            rhs: Box::new(regs.read(rhs)),
        },
    );
    Step::Continue
}

fn binary_2addr(regs: &mut Regs, r: &[u16], op: &'static str) -> Step {
    let (Some(&dst), Some(&rhs)): (Option<&u16>, Option<&u16>) = (r.first(), r.get(1)) else {
        return Step::Abstain;
    };
    let lhs: Expr = regs.read(dst);
    regs.write(
        dst,
        Expr::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(regs.read(rhs)),
        },
    );
    Step::Continue
}

fn binary_lit(regs: &mut Regs, r: &[u16], insn: &DalvikInsn, op: &'static str) -> Step {
    let (Some(&dst), Some(&src)): (Option<&u16>, Option<&u16>) = (r.first(), r.get(1)) else {
        return Step::Abstain;
    };
    let literal: i64 = insn.literal.unwrap_or(0);
    let src_expr: Expr = regs.read(src);
    let result: Expr = if matches!(insn.op, 0xD1 | 0xD9) {
        Expr::Binary {
            op,
            lhs: Box::new(Expr::Const(literal.to_string())),
            rhs: Box::new(src_expr),
        }
    } else {
        Expr::Binary {
            op,
            lhs: Box::new(src_expr),
            rhs: Box::new(Expr::Const(literal.to_string())),
        }
    };
    regs.write(dst, result);
    Step::Continue
}

pub(crate) fn model_pure_helper(
    dex: &DexFile,
    params: &[String],
    registers_size: u16,
    ins_size: u16,
    insns: &[DalvikInsn],
) -> Option<HelperModel> {
    if insns.is_empty() {
        return None;
    }
    let first_param_reg: u16 = registers_size.checked_sub(ins_size)?;
    let mut slots: BTreeMap<u16, Expr> = BTreeMap::new();
    let mut cursor: u16 = first_param_reg;
    for (index, param) in params.iter().enumerate() {
        slots.insert(cursor, Expr::Local(placeholder(index)));
        let step: u16 = if is_category_two(param) { 2 } else { 1 };
        cursor = cursor.checked_add(step)?;
    }
    let mut regs: Regs = Regs { slots };
    for insn in insns {
        match eval_insn(dex, &mut regs, insn) {
            Step::Continue => {}
            Step::Return(expr) => {
                return Some(HelperModel {
                    return_expr: expr,
                    param_count: params.len(),
                });
            }
            Step::Abstain => return None,
        }
    }
    None
}

pub(crate) fn substitute(expr: &Expr, args: &[Expr]) -> Expr {
    match expr {
        Expr::Local(name) => match parse_placeholder(name) {
            Some(index) if index < args.len() => args[index].clone(),
            _ => expr.clone(),
        },
        Expr::Const(_) | Expr::This | Expr::StaticField { .. } | Expr::New(_) | Expr::Opaque(_) => {
            expr.clone()
        }
        Expr::Field {
            receiver,
            owner,
            name,
            boolean,
        } => Expr::Field {
            receiver: Box::new(substitute(receiver, args)),
            owner: owner.clone(),
            name: name.clone(),
            boolean: *boolean,
        },
        Expr::Binary { op, lhs, rhs } => Expr::Binary {
            op,
            lhs: Box::new(substitute(lhs, args)),
            rhs: Box::new(substitute(rhs, args)),
        },
        Expr::Unary { op, value } => Expr::Unary {
            op,
            value: Box::new(substitute(value, args)),
        },
        Expr::Cast { ty, value } => Expr::Cast {
            ty: ty.clone(),
            value: Box::new(substitute(value, args)),
        },
        Expr::InstanceOf { value, ty } => Expr::InstanceOf {
            value: Box::new(substitute(value, args)),
            ty: ty.clone(),
        },
        Expr::Cmp { lhs, rhs } => Expr::Cmp {
            lhs: Box::new(substitute(lhs, args)),
            rhs: Box::new(substitute(rhs, args)),
        },
        Expr::ArrayLength(arr) => Expr::ArrayLength(Box::new(substitute(arr, args))),
        Expr::ArrayLoad { array, index } => Expr::ArrayLoad {
            array: Box::new(substitute(array, args)),
            index: Box::new(substitute(index, args)),
        },
        Expr::NewArray { ty, size } => Expr::NewArray {
            ty: ty.clone(),
            size: Box::new(substitute(size, args)),
        },
        Expr::ArrayInit { ty, elements } => Expr::ArrayInit {
            ty: ty.clone(),
            elements: elements
                .iter()
                .map(|e: &Expr| substitute(e, args))
                .collect(),
        },
        Expr::Invoke {
            receiver,
            owner,
            method,
            args: call_args,
            returns_bool,
        } => Expr::Invoke {
            receiver: receiver
                .as_ref()
                .map(|recv| Box::new(substitute(recv, args))),
            owner: owner.clone(),
            method: method.clone(),
            args: call_args
                .iter()
                .map(|a: &Expr| substitute(a, args))
                .collect(),
            returns_bool: *returns_bool,
        },
    }
}

fn parse_placeholder(name: &str) -> Option<usize> {
    name.strip_prefix("$p")
        .and_then(|rest| rest.parse::<usize>().ok())
}

fn effect_atoms(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Const(_) | Expr::Local(_) | Expr::This | Expr::Opaque(_) => {}
        Expr::Field {
            receiver,
            owner,
            name,
            ..
        } => {
            effect_atoms(receiver, out);
            out.push(format!("iget {owner}.{name}"));
        }
        Expr::StaticField { owner, name, .. } => out.push(format!("sget {owner}.{name}")),
        Expr::Binary { op, lhs, rhs } => {
            effect_atoms(lhs, out);
            effect_atoms(rhs, out);
            if matches!(*op, "/" | "%") {
                out.push("arith-div".to_string());
            }
        }
        Expr::Unary { value, .. } => effect_atoms(value, out),
        Expr::Cast { ty, value } => {
            effect_atoms(value, out);
            out.push(format!("cast {ty}"));
        }
        Expr::InstanceOf { value, .. } => effect_atoms(value, out),
        Expr::Cmp { lhs, rhs } => {
            effect_atoms(lhs, out);
            effect_atoms(rhs, out);
        }
        Expr::ArrayLength(arr) => {
            effect_atoms(arr, out);
            out.push("array-length".to_string());
        }
        Expr::ArrayLoad { array, index } => {
            effect_atoms(array, out);
            effect_atoms(index, out);
            out.push("aget".to_string());
        }
        Expr::New(ty) => out.push(format!("new {ty}")),
        Expr::NewArray { size, .. } => {
            effect_atoms(size, out);
            out.push("new-array".to_string());
        }
        Expr::ArrayInit { elements, .. } => {
            for element in elements {
                effect_atoms(element, out);
            }
            out.push("array-init".to_string());
        }
        Expr::Invoke {
            receiver,
            owner,
            method,
            args,
            ..
        } => {
            if let Some(recv) = receiver {
                effect_atoms(recv, out);
            }
            for arg in args {
                effect_atoms(arg, out);
            }
            out.push(format!("invoke {owner}.{method}"));
        }
    }
}

pub(crate) fn gate_inline(body_return: &Expr, args: &[Expr]) -> GateStatus {
    let mut original: Vec<String> = Vec::new();
    for arg in args {
        effect_atoms(arg, &mut original);
    }
    effect_atoms(body_return, &mut original);

    let substituted: Expr = substitute(body_return, args);
    let mut rewritten: Vec<String> = Vec::new();
    effect_atoms(&substituted, &mut rewritten);

    if original == rewritten {
        GateStatus::Green
    } else {
        GateStatus::Rejected(format!(
            "effect sequence diverges: before={original:?} after={rewritten:?}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{Expr, GateStatus, gate_inline, substitute};

    fn effectful_call() -> Expr {
        Expr::Invoke {
            receiver: None,
            owner: "Foo".to_string(),
            method: "bar".to_string(),
            args: Vec::new(),
            returns_bool: false,
        }
    }

    #[test]
    fn gate_passes_for_leaf_arguments() {
        let body: Expr = Expr::Binary {
            op: "+",
            lhs: Box::new(Expr::Local("$p0".to_string())),
            rhs: Box::new(Expr::Local("$p1".to_string())),
        };
        let args: Vec<Expr> = vec![Expr::Local("v1".to_string()), Expr::Local("v2".to_string())];
        assert!(matches!(gate_inline(&body, &args), GateStatus::Green));
        assert_eq!(substitute(&body, &args).render(), "(v1 + v2)");
    }

    #[test]
    fn gate_rejects_duplicating_an_effectful_argument() {
        let body: Expr = Expr::Binary {
            op: "+",
            lhs: Box::new(Expr::Local("$p0".to_string())),
            rhs: Box::new(Expr::Local("$p0".to_string())),
        };
        let args: Vec<Expr> = vec![effectful_call()];
        assert!(matches!(gate_inline(&body, &args), GateStatus::Rejected(_)));
    }

    #[test]
    fn gate_rejects_reordering_effectful_arguments() {
        let body: Expr = Expr::Binary {
            op: "-",
            lhs: Box::new(Expr::Local("$p1".to_string())),
            rhs: Box::new(Expr::Local("$p0".to_string())),
        };
        let args: Vec<Expr> = vec![
            Expr::Invoke {
                receiver: None,
                owner: "A".to_string(),
                method: "a".to_string(),
                args: Vec::new(),
                returns_bool: false,
            },
            Expr::Invoke {
                receiver: None,
                owner: "B".to_string(),
                method: "b".to_string(),
                args: Vec::new(),
                returns_bool: false,
            },
        ];
        assert!(matches!(gate_inline(&body, &args), GateStatus::Rejected(_)));
    }
}
