use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::DalvikInsn;
use crate::decompile::{Expr, MAX_DUP_EXPR_NODES, expr_node_count_capped};
use crate::descriptor::{self, MethodDescriptor};
use crate::dex::{DexFile, FieldId, MethodId};

pub(crate) struct MethodContext<'a> {
    pub(crate) dex: &'a DexFile,
    pub(crate) desugar: crate::dalvik_desugar::DesugarView<'a>,
    pub(crate) registers_size: u16,
    pub(crate) ins_size: u16,
    pub(crate) is_static: bool,
    pub(crate) inline_temporaries: bool,
    pub(crate) param_regs: BTreeMap<u16, String>,
    pub(crate) this_reg: Option<u16>,
}

impl<'a> MethodContext<'a> {
    pub(crate) fn new(
        dex: &'a DexFile,
        registers_size: u16,
        ins_size: u16,
        descriptor: &str,
        is_static: bool,
        inline_temporaries: bool,
        desugar: crate::dalvik_desugar::DesugarView<'a>,
    ) -> Self {
        let parsed: Option<MethodDescriptor> = descriptor::parse_method(descriptor);
        let first_param_reg: u16 = registers_size.saturating_sub(ins_size);
        let mut param_regs: BTreeMap<u16, String> = BTreeMap::new();
        let mut this_reg: Option<u16> = None;
        let mut cursor: u16 = first_param_reg;
        if !is_static {
            this_reg = Some(cursor);
            cursor = cursor.saturating_add(1);
        }
        if let Some(md) = &parsed {
            for (i, p) in md.params.iter().enumerate() {
                param_regs.insert(cursor, format!("arg{i}"));
                let step: u16 = if p.category_two() { 2 } else { 1 };
                cursor = cursor.saturating_add(step);
            }
        }
        Self {
            dex,
            desugar,
            registers_size,
            ins_size,
            is_static,
            inline_temporaries,
            param_regs,
            this_reg,
        }
    }

    pub(crate) fn register_name(&self, reg: u16) -> Expr {
        if Some(reg) == self.this_reg {
            return Expr::This;
        }
        if let Some(name) = self.param_regs.get(&reg) {
            return Expr::Local(name.clone());
        }
        Expr::Local(format!("var{reg}"))
    }

    pub(crate) fn register_lvalue(&self, reg: u16) -> String {
        if let Some(name) = self.param_regs.get(&reg) {
            return name.clone();
        }
        format!("var{reg}")
    }

    fn method_id(&self, index: u32) -> Option<&MethodId> {
        self.dex.method_ids.get(index as usize)
    }

    fn field_id(&self, index: u32) -> Option<&FieldId> {
        self.dex.field_ids.get(index as usize)
    }

    fn string_at(&self, index: u32) -> Option<&str> {
        self.dex.strings.get(index as usize).map(String::as_str)
    }

    fn type_at(&self, index: u32) -> Option<&str> {
        self.dex.type_names.get(index as usize).map(String::as_str)
    }
}

pub(crate) struct RegisterFile {
    slots: BTreeMap<u16, Expr>,
    pending: BTreeSet<u16>,
}

impl RegisterFile {
    pub(crate) const fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
            pending: BTreeSet::new(),
        }
    }

    fn read(&self, ctx: &MethodContext<'_>, reg: u16) -> Expr {
        match self.slots.get(&reg) {
            Some(expr) if expr_node_count_capped(expr, MAX_DUP_EXPR_NODES) < MAX_DUP_EXPR_NODES => {
                expr.clone()
            }
            Some(_) => Expr::Opaque("?".to_string()),
            None => ctx.register_name(reg),
        }
    }

    fn write(&mut self, reg: u16, expr: Expr) {
        self.slots.insert(reg, expr);
        self.pending.insert(reg);
    }

    fn write_materialized(&mut self, reg: u16, expr: Expr) {
        self.slots.insert(reg, expr);
        self.pending.remove(&reg);
    }

    fn seed_register_with_name(&mut self, ctx: &MethodContext<'_>, reg: u16) {
        self.slots.insert(reg, ctx.register_name(reg));
        self.pending.remove(&reg);
    }

    pub(crate) fn current(&self, ctx: &MethodContext<'_>, reg: u16) -> Expr {
        self.read(ctx, reg)
    }

    pub(crate) fn pending_registers(&self) -> impl Iterator<Item = u16> + '_ {
        self.pending.iter().copied()
    }
}

pub(crate) enum LiftOutcome {
    Statement(String),
    Statements(Vec<String>),
    None,
}

pub(crate) struct PendingResult {
    expr: Expr,
    materialized_in: Option<u16>,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn lift_insn(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
    pending_result: &mut Option<PendingResult>,
) -> LiftOutcome {
    let op: u8 = insn.op;
    let regs: &[u16] = &insn.regs;
    let receiver_consumes_pending: bool = matches!(op, 0x6E..=0x72 | 0x74..=0x78)
        && pending_result
            .as_ref()
            .and_then(|result: &PendingResult| result.materialized_in)
            .is_some_and(|register: u16| regs.first() == Some(&register));
    let discarded: Option<String> = if matches!(op, 0x0A..=0x0C) {
        None
    } else if receiver_consumes_pending {
        let _: Option<PendingResult> = pending_result.take();
        None
    } else {
        pending_result
            .take()
            .and_then(|result: PendingResult| result.expr.discarded_side_effect())
    };
    let outcome: LiftOutcome = match op {
        0x00 | 0x1D | 0x1E => LiftOutcome::None,
        0x01..=0x09 => move_register(ctx, file, regs),
        0x0A..=0x0C => {
            if let (Some(&dest), Some(result)) = (regs.first(), pending_result.take()) {
                file.write(dest, result.expr);
            }
            LiftOutcome::None
        }
        0x0D => {
            if let Some(&dest) = regs.first() {
                file.write(dest, Expr::Local("ex".to_string()));
            }
            LiftOutcome::None
        }
        0x0E => LiftOutcome::Statement("return".to_string()),
        0x0F..=0x11 => {
            let value: Expr = regs
                .first()
                .map_or_else(|| Expr::Opaque("?".to_string()), |&r| file.read(ctx, r));
            LiftOutcome::Statement(format!("return {}", value.render()))
        }
        0x12..=0x19 => const_value(ctx, file, regs, insn),
        0x1A | 0x1B => const_string(ctx, file, regs, insn),
        0x1C => const_class(ctx, file, regs, insn),
        0x1F => check_cast(ctx, file, regs, insn),
        0x20 => instance_of(ctx, file, regs, insn),
        0x21 => array_length(ctx, file, regs),
        0x22 => new_instance(ctx, file, regs, insn),
        0x23 => new_array(ctx, file, regs, insn),
        0x27 => {
            let value: Expr = regs
                .first()
                .map_or_else(|| Expr::Opaque("?".to_string()), |&r| file.read(ctx, r));
            LiftOutcome::Statement(format!("throw {}", value.render()))
        }
        0x44..=0x4A => array_get(ctx, file, regs),
        0x4B..=0x51 => array_put(ctx, file, regs),
        0x52..=0x58 => instance_get(ctx, file, regs, insn),
        0x59..=0x5F => instance_put(ctx, file, regs, insn),
        0x60..=0x66 => static_get(ctx, file, regs, insn),
        0x67..=0x6D => static_put(ctx, file, regs, insn),
        0x6E..=0x72 | 0x74..=0x78 => invoke(ctx, file, insn, pending_result),
        0x7B | 0x7D | 0x7F => unary(ctx, file, regs, "-"),
        0x7C | 0x7E => unary(ctx, file, regs, "~"),
        0x81..=0x8F => numeric_cast(ctx, file, regs, op),
        0x90..=0x97 | 0x9B..=0xA2 | 0xA6..=0xAF => binary_three(ctx, file, regs, arith_op(op)),
        0x98..=0x9A | 0xA3..=0xA5 => binary_three(ctx, file, regs, arith_op(op)),
        0xB0..=0xB7 | 0xBB..=0xC2 | 0xC6..=0xCF => binary_2addr(ctx, file, regs, arith_op(op)),
        0xB8..=0xBA | 0xC3..=0xC5 => binary_2addr(ctx, file, regs, arith_op(op)),
        0x2D..=0x31 => cmp_three(ctx, file, regs),
        0xD0..=0xD7 => binary_lit(ctx, file, regs, insn, arith_lit_op(op)),
        0xD8..=0xE2 => binary_lit(ctx, file, regs, insn, arith_lit_op(op)),
        _ => LiftOutcome::None,
    };
    match (discarded, outcome) {
        (Some(side_effect), LiftOutcome::Statement(statement)) => {
            LiftOutcome::Statements(vec![side_effect, statement])
        }
        (Some(side_effect), LiftOutcome::Statements(mut statements)) => {
            statements.insert(0, side_effect);
            LiftOutcome::Statements(statements)
        }
        (Some(side_effect), LiftOutcome::None) => LiftOutcome::Statement(side_effect),
        (None, outcome) => outcome,
    }
}

fn move_register(ctx: &MethodContext<'_>, file: &mut RegisterFile, regs: &[u16]) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let value: Expr = file.read(ctx, src);
    let rendered: String = value.render();
    file.write_materialized(dest, value);
    if ctx.inline_temporaries {
        LiftOutcome::None
    } else {
        LiftOutcome::Statement(format!("{} = {rendered}", ctx.register_lvalue(dest)))
    }
}

fn const_value(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let raw: i64 = insn.literal.unwrap_or(0);
    let value: i64 = match insn.op {
        0x15 => i64::from((raw as i32).wrapping_shl(16)),
        0x19 => raw.wrapping_shl(48),
        _ => raw,
    };
    let wide: bool = matches!(insn.op, 0x16..=0x19);
    let literal: String = if wide {
        format!("{value}L")
    } else {
        value.to_string()
    };
    file.write_materialized(dest, Expr::Const(literal.clone()));
    if ctx.inline_temporaries {
        LiftOutcome::None
    } else {
        LiftOutcome::Statement(format!("{} = {literal}", lvalue(dest)))
    }
}

fn const_string(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let text: String = insn
        .index
        .and_then(|i| ctx.string_at(i))
        .map_or_else(|| "\"\"".to_string(), |s| format!("{s:?}"));
    file.write_materialized(dest, Expr::Const(text.clone()));
    if ctx.inline_temporaries {
        LiftOutcome::None
    } else {
        LiftOutcome::Statement(format!("{} = {text}", lvalue(dest)))
    }
}

fn const_class(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let ty: String = insn
        .index
        .and_then(|i| ctx.type_at(i))
        .map_or_else(|| "Object".to_string(), descriptor::binary_to_source);
    let text: String = format!("{ty}.class");
    file.write_materialized(dest, Expr::Const(text.clone()));
    LiftOutcome::Statement(format!("{} = {text}", lvalue(dest)))
}

fn check_cast(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let ty: String = insn
        .index
        .and_then(|i| ctx.type_at(i))
        .map_or_else(|| "Object".to_string(), descriptor::binary_to_source);
    let value: Expr = file.read(ctx, dest);
    file.write(
        dest,
        Expr::Cast {
            ty,
            value: Box::new(value),
        },
    );
    LiftOutcome::None
}

fn instance_of(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let ty: String = insn
        .index
        .and_then(|i| ctx.type_at(i))
        .map_or_else(|| "Object".to_string(), descriptor::binary_to_source);
    let value: Expr = file.read(ctx, src);
    file.write(
        dest,
        Expr::InstanceOf {
            value: Box::new(value),
            ty,
        },
    );
    LiftOutcome::None
}

fn array_length(ctx: &MethodContext<'_>, file: &mut RegisterFile, regs: &[u16]) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let array: Expr = file.read(ctx, src);
    file.write(dest, Expr::ArrayLength(Box::new(array)));
    LiftOutcome::None
}

fn new_instance(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let ty: String = insn
        .index
        .and_then(|i| ctx.type_at(i))
        .map_or_else(|| "Object".to_string(), descriptor::binary_to_source);
    file.write(dest, Expr::New(ty));
    LiftOutcome::None
}

fn new_array(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&dest), Some(&size_reg)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let element: String = insn
        .index
        .and_then(|i| ctx.type_at(i))
        .map(|descr| descr.trim_start_matches('[').to_string())
        .map_or_else(
            || "Object".to_string(),
            |inner| descriptor::binary_to_source(&inner),
        );
    let size: Expr = file.read(ctx, size_reg);
    file.write(
        dest,
        Expr::NewArray {
            ty: element,
            size: Box::new(size),
        },
    );
    LiftOutcome::None
}

fn array_get(ctx: &MethodContext<'_>, file: &mut RegisterFile, regs: &[u16]) -> LiftOutcome {
    let (Some(&dest), Some(&array), Some(&index)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (regs.first(), regs.get(1), regs.get(2))
    else {
        return LiftOutcome::None;
    };
    let array_expr: Expr = file.read(ctx, array);
    let index_expr: Expr = file.read(ctx, index);
    file.write(
        dest,
        Expr::ArrayLoad {
            array: Box::new(array_expr),
            index: Box::new(index_expr),
        },
    );
    LiftOutcome::None
}

fn array_put(ctx: &MethodContext<'_>, file: &RegisterFile, regs: &[u16]) -> LiftOutcome {
    let (Some(&value), Some(&array), Some(&index)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (regs.first(), regs.get(1), regs.get(2))
    else {
        return LiftOutcome::None;
    };
    let value_expr: Expr = file.read(ctx, value);
    let array_expr: Expr = file.read(ctx, array);
    let index_expr: Expr = file.read(ctx, index);
    LiftOutcome::Statement(format!(
        "{}[{}] = {}",
        array_expr.render(),
        index_expr.render(),
        value_expr.render()
    ))
}

fn instance_get(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&dest), Some(&obj)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let Some(field): Option<&FieldId> = insn.index.and_then(|i| ctx.field_id(i)) else {
        return LiftOutcome::None;
    };
    let name: String = field.name.clone();
    let owner: String = field.class.clone();
    let boolean: bool = field.type_name == "Z";
    let receiver: Expr = file.read(ctx, obj);
    let expr: Expr = match &receiver {
        Expr::This => Expr::Field {
            receiver: Box::new(Expr::This),
            owner,
            name,
            boolean,
        },
        _ => Expr::Opaque(format!("{}.{name}", receiver.render())),
    };
    file.write(dest, expr);
    LiftOutcome::None
}

fn instance_put(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let (Some(&value), Some(&obj)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let Some(field): Option<&FieldId> = insn.index.and_then(|i| ctx.field_id(i)) else {
        return LiftOutcome::None;
    };
    let value_expr: Expr = file.read(ctx, value);
    let receiver: Expr = file.read(ctx, obj);
    let target: String = match &receiver {
        Expr::This => format!("this.{}", field.name),
        _ => format!("{}.{}", receiver.render(), field.name),
    };
    LiftOutcome::Statement(format!("{target} = {}", value_expr.render()))
}

fn static_get(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&dest): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let Some(field): Option<&FieldId> = insn.index.and_then(|i| ctx.field_id(i)) else {
        return LiftOutcome::None;
    };
    let owner: String = descriptor::binary_to_source(&field.class);
    file.write(
        dest,
        Expr::StaticField {
            owner,
            name: field.name.clone(),
            boolean: field.type_name == "Z",
        },
    );
    LiftOutcome::None
}

fn static_put(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
) -> LiftOutcome {
    let Some(&value): Option<&u16> = regs.first() else {
        return LiftOutcome::None;
    };
    let Some(field): Option<&FieldId> = insn.index.and_then(|i| ctx.field_id(i)) else {
        return LiftOutcome::None;
    };
    let owner: String = descriptor::binary_to_source(&field.class);
    let value_expr: Expr = file.read(ctx, value);
    LiftOutcome::Statement(format!("{owner}.{} = {}", field.name, value_expr.render()))
}

fn invoke(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
    pending_result: &mut Option<PendingResult>,
) -> LiftOutcome {
    let Some(method): Option<&MethodId> = insn.index.and_then(|i| ctx.method_id(i)) else {
        return LiftOutcome::None;
    };
    let is_static: bool = matches!(insn.op, 0x71 | 0x77);
    let is_direct: bool = matches!(insn.op, 0x70 | 0x76);
    let recovered_default: Option<&crate::dalvik_desugar::DefaultInterfaceMethod> = insn
        .index
        .and_then(|index: u32| ctx.desugar.interfaces.rewrites_call(index));
    let owner: String = recovered_default.map_or_else(
        || descriptor::binary_to_source(&method.class),
        |recovered: &crate::dalvik_desugar::DefaultInterfaceMethod| {
            descriptor::binary_to_source(&recovered.interface)
        },
    );
    let name: String =
        recovered_default.map_or_else(|| method.name.clone(), |recovered| recovered.name.clone());
    let returns_void: bool = method.proto.return_type == "V";

    let mut reg_iter: std::slice::Iter<'_, u16> = insn.regs.iter();
    let receiver_register: Option<u16> = if !is_static || recovered_default.is_some() {
        insn.regs.first().copied()
    } else {
        None
    };
    let receiver: Option<Expr> = if !is_static {
        reg_iter.next().map(|&r| file.read(ctx, r))
    } else if recovered_default.is_some() {
        reg_iter.next().map(|&r| file.read(ctx, r))
    } else {
        None
    };
    let parameters: &[String] = if recovered_default.is_some() {
        let Some(parameters): Option<&[String]> = method.proto.parameters.get(1..) else {
            return LiftOutcome::None;
        };
        parameters
    } else {
        &method.proto.parameters
    };
    let mut args: Vec<Expr> = Vec::with_capacity(parameters.len());
    for param in parameters {
        let Some(&r): Option<&u16> = reg_iter.next() else {
            break;
        };
        args.push(file.read(ctx, r));
        if is_category_two(param) {
            let _: Option<&u16> = reg_iter.next();
        }
    }

    if name == "<init>" && is_direct {
        let joined: String = args
            .iter()
            .map(Expr::render)
            .collect::<Vec<String>>()
            .join(", ");
        if let Some(Expr::New(ty)) = &receiver {
            let reference: Option<String> =
                ctx.desugar.method_refs.recovered(&method.class).and_then(
                    |recovered: &crate::dalvik_desugar::RecoveredMethodRef| {
                        render_method_reference(recovered, &args)
                    },
                );
            let constructed: Expr =
                Expr::Opaque(reference.unwrap_or_else(|| format!("new {ty}({joined})")));
            *pending_result = Some(PendingResult {
                expr: constructed.clone(),
                materialized_in: receiver_register,
            });
            if let Some(&recv_reg) = insn.regs.first() {
                file.write(recv_reg, constructed);
            }
            return LiftOutcome::None;
        }
        return LiftOutcome::Statement(format!("super({joined})"));
    }

    let call: Expr = Expr::Invoke {
        receiver: receiver.map(Box::new),
        owner,
        method: name,
        args,
        returns_bool: method.proto.return_type == "Z",
    };
    if returns_void {
        return LiftOutcome::Statement(call.render());
    }
    let materialized_in: Option<u16> = receiver_register.filter(|_| returns_receiver(method));
    if let Some(register) = materialized_in {
        file.write(register, call.clone());
    }
    *pending_result = Some(PendingResult {
        expr: call,
        materialized_in,
    });
    LiftOutcome::None
}

fn render_method_reference(
    recovered: &crate::dalvik_desugar::RecoveredMethodRef,
    args: &[Expr],
) -> Option<String> {
    let name: &str = recovered.name.as_str();
    if recovered.kind == crate::dalvik_desugar::MethodRefKind::BoundInstance {
        if args.len() != 1 {
            return None;
        }
        let rendered: String = args.first()?.render();
        let receiver: String = if is_expression_name(&rendered) {
            rendered
        } else {
            format!("({rendered})")
        };
        return Some(format!("{receiver}::{name}"));
    }
    if !args.is_empty() {
        return None;
    }
    Some(format!(
        "{}::{name}",
        descriptor::binary_to_source(&recovered.owner)
    ))
}

fn is_expression_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .split('.')
            .all(crate::name_disambig::is_java_source_identifier)
}

fn returns_receiver(method: &MethodId) -> bool {
    matches!(
        method.class.as_str(),
        "Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;"
    ) && matches!(
        method.name.as_str(),
        "append" | "appendCodePoint" | "delete" | "deleteCharAt" | "insert" | "replace" | "reverse"
    ) && method.proto.return_type == method.class
}

fn unary(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: &'static str,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let value: Expr = file.read(ctx, src);
    let result: Expr = Expr::Unary {
        op,
        value: Box::new(value),
    };
    let rendered: String = result.render();
    file.write_materialized(dest, result);
    LiftOutcome::Statement(format!("{} = {rendered}", ctx.register_lvalue(dest)))
}

fn numeric_cast(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: u8,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let ty: &str = cast_target(op);
    let value: Expr = file.read(ctx, src);
    let result: Expr = Expr::Cast {
        ty: ty.to_string(),
        value: Box::new(value),
    };
    let rendered: String = result.render();
    file.write_materialized(dest, result);
    LiftOutcome::Statement(format!("{} = {rendered}", ctx.register_lvalue(dest)))
}

fn binary_three(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: &'static str,
) -> LiftOutcome {
    let (Some(&dest), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (regs.first(), regs.get(1), regs.get(2))
    else {
        return LiftOutcome::None;
    };
    let lhs_expr: Expr = file.read(ctx, lhs);
    let rhs_expr: Expr = file.read(ctx, rhs);
    let result: Expr = Expr::Binary {
        op,
        lhs: Box::new(lhs_expr),
        rhs: Box::new(rhs_expr),
    };
    let rendered: String = result.render();
    file.write_materialized(dest, result);
    LiftOutcome::Statement(format!("{} = {rendered}", ctx.register_lvalue(dest)))
}

fn binary_2addr(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    op: &'static str,
) -> LiftOutcome {
    let (Some(&dest), Some(&rhs)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let lhs_expr: Expr = file.read(ctx, dest);
    let rhs_expr: Expr = file.read(ctx, rhs);
    let result: Expr = Expr::Binary {
        op,
        lhs: Box::new(lhs_expr),
        rhs: Box::new(rhs_expr),
    };
    let rendered: String = result.render();
    file.write_materialized(dest, result);
    LiftOutcome::Statement(format!("{} = {rendered}", ctx.register_lvalue(dest)))
}

fn binary_lit(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    regs: &[u16],
    insn: &DalvikInsn,
    op: &'static str,
) -> LiftOutcome {
    let (Some(&dest), Some(&src)): (Option<&u16>, Option<&u16>) = (regs.first(), regs.get(1))
    else {
        return LiftOutcome::None;
    };
    let literal: i64 = insn.literal.unwrap_or(0);
    let lhs_expr: Expr = file.read(ctx, src);
    let result: Expr = if insn.op == 0xD1 || insn.op == 0xD9 {
        Expr::Binary {
            op,
            lhs: Box::new(Expr::Const(literal.to_string())),
            rhs: Box::new(lhs_expr),
        }
    } else {
        Expr::Binary {
            op,
            lhs: Box::new(lhs_expr),
            rhs: Box::new(Expr::Const(literal.to_string())),
        }
    };
    let rendered: String = result.render();
    file.write_materialized(dest, result);
    LiftOutcome::Statement(format!("{} = {rendered}", ctx.register_lvalue(dest)))
}

fn cmp_three(ctx: &MethodContext<'_>, file: &mut RegisterFile, regs: &[u16]) -> LiftOutcome {
    let (Some(&dest), Some(&lhs), Some(&rhs)): (Option<&u16>, Option<&u16>, Option<&u16>) =
        (regs.first(), regs.get(1), regs.get(2))
    else {
        return LiftOutcome::None;
    };
    let lhs_expr: Expr = file.read(ctx, lhs);
    let rhs_expr: Expr = file.read(ctx, rhs);
    file.write(
        dest,
        Expr::Binary {
            op: "/*cmp*/-",
            lhs: Box::new(lhs_expr),
            rhs: Box::new(rhs_expr),
        },
    );
    LiftOutcome::None
}

pub(crate) fn render_branch_condition(
    ctx: &MethodContext<'_>,
    file: &RegisterFile,
    insn: &DalvikInsn,
) -> String {
    let op: u8 = insn.op;
    match op {
        0x32..=0x37 => {
            let (Some(&a), Some(&b)): (Option<&u16>, Option<&u16>) =
                (insn.regs.first(), insn.regs.get(1))
            else {
                return "true".to_string();
            };
            let lhs: Expr = file.read(ctx, a);
            let rhs: Expr = file.read(ctx, b);
            format!("{} {} {}", lhs.render(), compare_op(op), rhs.render())
        }
        0x38..=0x3D => {
            let Some(&a): Option<&u16> = insn.regs.first() else {
                return "true".to_string();
            };
            let value: Expr = file.read(ctx, a);
            match &value {
                Expr::Binary { op: cmp, lhs, rhs } if *cmp == "/*cmp*/-" => {
                    format!("{} {} {}", lhs.render(), comparez_op(op), rhs.render())
                }
                Expr::InstanceOf { .. } if matches!(op, 0x38 | 0x39) => {
                    let inner: String = value.render();
                    if op == 0x38 {
                        format!("!{inner}")
                    } else {
                        inner
                    }
                }
                _ => format!("{} {} 0", value.render(), comparez_op(op)),
            }
        }
        _ => "true".to_string(),
    }
}

pub(crate) fn seed_block_registers(ctx: &MethodContext<'_>, file: &mut RegisterFile) {
    for reg in 0..ctx.registers_size {
        file.seed_register_with_name(ctx, reg);
    }
    let _ = ctx.ins_size;
    let _ = ctx.is_static;
}

const fn is_category_two(descriptor: &str) -> bool {
    matches!(descriptor.as_bytes().first(), Some(b'J' | b'D'))
}

fn lvalue(reg: u16) -> String {
    format!("var{reg}")
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

const fn compare_op(op: u8) -> &'static str {
    match op {
        0x32 => "==",
        0x33 => "!=",
        0x34 => "<",
        0x35 => ">=",
        0x36 => ">",
        0x37 => "<=",
        _ => "?",
    }
}

const fn comparez_op(op: u8) -> &'static str {
    match op {
        0x38 => "==",
        0x39 => "!=",
        0x3A => "<",
        0x3B => ">=",
        0x3C => ">",
        0x3D => "<=",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::returns_receiver;
    use crate::dex::{MethodId, ProtoId};

    fn method(class: &str, name: &str, returns: &str) -> MethodId {
        MethodId {
            class: class.to_string(),
            proto: ProtoId {
                shorty: String::new(),
                return_type: returns.to_string(),
                parameters: Vec::new(),
            },
            name: name.to_string(),
        }
    }

    #[test]
    fn only_mutable_builder_methods_thread_the_receiver_expression() {
        let append: MethodId = method(
            "Ljava/lang/StringBuilder;",
            "append",
            "Ljava/lang/StringBuilder;",
        );
        let concat: MethodId = method("Ljava/lang/String;", "concat", "Ljava/lang/String;");
        let builder_factory: MethodId = method(
            "Ljava/lang/StringBuilder;",
            "newBuilder",
            "Ljava/lang/StringBuilder;",
        );
        assert!(returns_receiver(&append));
        assert!(!returns_receiver(&concat));
        assert!(!returns_receiver(&builder_factory));
    }
}
