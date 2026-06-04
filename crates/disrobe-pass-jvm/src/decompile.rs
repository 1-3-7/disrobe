use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::bytecode::{
    self, CodeAttribute, Instruction, Operands, branch_target, disassemble, parse_code_attribute,
};
use crate::classfile::{ClassFile, FieldInfo, MethodInfo};
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Dominators, EdgeKind, NaturalLoop, Region, Structurer, SwitchKey,
    build_cfg, compute_dominators, find_natural_loops,
};
use crate::descriptor::{self, JavaType, MethodDescriptor};
use crate::error::Result;

pub const ACC_PUBLIC: u16 = 0x0001;
pub const ACC_PRIVATE: u16 = 0x0002;
pub const ACC_PROTECTED: u16 = 0x0004;
pub const ACC_STATIC: u16 = 0x0008;
pub const ACC_FINAL: u16 = 0x0010;
pub const ACC_SYNCHRONIZED: u16 = 0x0020;
pub const ACC_VOLATILE: u16 = 0x0040;
pub const ACC_TRANSIENT: u16 = 0x0080;
pub const ACC_NATIVE: u16 = 0x0100;
pub const ACC_INTERFACE: u16 = 0x0200;
pub const ACC_ABSTRACT: u16 = 0x0400;
pub const ACC_ENUM: u16 = 0x4000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledClass {
    pub source: String,
    pub method_count: usize,
    pub field_count: usize,
    pub fully_lifted_methods: usize,
    pub fallback_methods: usize,
}

#[must_use]
pub fn class_access_keywords(flags: u16) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & ACC_PUBLIC != 0 {
        parts.push("public");
    }
    if flags & ACC_ABSTRACT != 0 && flags & ACC_INTERFACE == 0 {
        parts.push("abstract");
    }
    if flags & ACC_FINAL != 0 {
        parts.push("final");
    }
    parts.join(" ")
}

#[must_use]
pub fn member_access_keywords(flags: u16) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & ACC_PUBLIC != 0 {
        parts.push("public");
    } else if flags & ACC_PRIVATE != 0 {
        parts.push("private");
    } else if flags & ACC_PROTECTED != 0 {
        parts.push("protected");
    }
    if flags & ACC_STATIC != 0 {
        parts.push("static");
    }
    if flags & ACC_FINAL != 0 {
        parts.push("final");
    }
    if flags & ACC_ABSTRACT != 0 {
        parts.push("abstract");
    }
    if flags & ACC_SYNCHRONIZED != 0 {
        parts.push("synchronized");
    }
    if flags & ACC_NATIVE != 0 {
        parts.push("native");
    }
    if flags & ACC_VOLATILE != 0 {
        parts.push("volatile");
    }
    if flags & ACC_TRANSIENT != 0 {
        parts.push("transient");
    }
    parts.join(" ")
}

#[must_use]
pub fn decompile_class(cf: &ClassFile) -> DecompiledClass {
    let mut source: String = String::with_capacity(2048);
    let this_name: String = cf.this_class_name().unwrap_or("UnknownClass").to_string();
    let simple: &str = this_name.rsplit('/').next().unwrap_or(&this_name);
    let package: Option<&str> = this_name.rfind('/').map(|p| &this_name[..p]);

    if let Some(pkg) = package {
        let _ = writeln!(source, "package {};", pkg.replace('/', "."));
        let _ = writeln!(source);
    }

    let structure: crate::attributes::ClassStructure = crate::attributes::analyze(cf);
    let is_interface: bool = cf.access_flags & ACC_INTERFACE != 0;
    let is_enum: bool = cf.access_flags & ACC_ENUM != 0;
    let kw: String = class_access_keywords(cf.access_flags);
    let kind: &str = if is_interface {
        "interface"
    } else if is_enum {
        "enum"
    } else if structure.is_record {
        "record"
    } else {
        "class"
    };
    let sealed_kw: &str = if structure.is_sealed { "sealed " } else { "" };
    if kw.is_empty() {
        let _ = write!(source, "{sealed_kw}{kind} {simple}");
    } else {
        let _ = write!(source, "{kw} {sealed_kw}{kind} {simple}");
    }
    if structure.is_record {
        let components: Vec<String> = structure
            .record_components
            .iter()
            .filter_map(|c| {
                descriptor::parse_field(&c.descriptor).map(|t| format!("{} {}", t.render(), c.name))
            })
            .collect();
        let _ = write!(source, "({})", components.join(", "));
    }

    let super_name: Option<String> = if cf.super_class == 0 {
        None
    } else {
        cf.class_name(cf.super_class).ok().map(str::to_string)
    };
    if let Some(sup) = &super_name
        && sup != "java/lang/Object"
        && !is_interface
    {
        let _ = write!(source, " extends {}", descriptor::binary_to_source(sup));
    }
    if !cf.interfaces.is_empty() {
        let names: Vec<String> = cf
            .interfaces
            .iter()
            .filter_map(|&i| cf.class_name(i).ok().map(descriptor::binary_to_source))
            .collect();
        if !names.is_empty() {
            let verb: &str = if is_interface {
                "extends"
            } else {
                "implements"
            };
            let _ = write!(source, " {verb} {}", names.join(", "));
        }
    }
    if structure.is_sealed && !structure.permitted_subclasses.is_empty() {
        let permitted: Vec<String> = structure
            .permitted_subclasses
            .iter()
            .map(|s| descriptor::binary_to_source(s))
            .collect();
        let _ = write!(source, " permits {}", permitted.join(", "));
    }
    let _ = writeln!(source, " {{");

    let mut field_count: usize = 0;
    for field in &cf.fields {
        if let Some(line) = render_field(cf, field) {
            let _ = writeln!(source, "    {line}");
            field_count += 1;
        }
    }
    if field_count > 0 {
        let _ = writeln!(source);
    }

    let mut method_count: usize = 0;
    let mut fully_lifted: usize = 0;
    let mut fallback: usize = 0;
    for method in &cf.methods {
        let rendered: RenderedMethod = render_method(cf, method, simple, is_interface);
        let _ = writeln!(source, "{}", rendered.text);
        method_count += 1;
        if rendered.fully_lifted {
            fully_lifted += 1;
        } else if rendered.has_body {
            fallback += 1;
        }
    }

    let _ = writeln!(source, "}}");

    DecompiledClass {
        source,
        method_count,
        field_count,
        fully_lifted_methods: fully_lifted,
        fallback_methods: fallback,
    }
}

fn render_field(cf: &ClassFile, field: &FieldInfo) -> Option<String> {
    let name: &str = cf.utf8_at(field.name_index).ok()?;
    let desc: &str = cf.utf8_at(field.descriptor_index).ok()?;
    let ty: JavaType = descriptor::parse_field(desc)?;
    let kw: String = member_access_keywords(field.access_flags);
    let constant: Option<String> = constant_value(cf, field);
    let prefix: String = if kw.is_empty() {
        String::new()
    } else {
        format!("{kw} ")
    };
    match constant {
        Some(value) => Some(format!("{prefix}{} {name} = {value};", ty.render())),
        None => Some(format!("{prefix}{} {name};", ty.render())),
    }
}

fn constant_value(cf: &ClassFile, field: &FieldInfo) -> Option<String> {
    for attr in &field.attributes {
        if cf.utf8_at(attr.name_index).ok()? == "ConstantValue" && attr.info.len() == 2 {
            let idx: u16 = u16::from_be_bytes([attr.info[0], attr.info[1]]);
            return bytecode::resolve_ref(cf, idx);
        }
    }
    None
}

struct RenderedMethod {
    text: String,
    fully_lifted: bool,
    has_body: bool,
}

fn render_method(
    cf: &ClassFile,
    method: &MethodInfo,
    class_simple: &str,
    is_interface: bool,
) -> RenderedMethod {
    let name: &str = cf.utf8_at(method.name_index).unwrap_or("?");
    let desc: &str = cf.utf8_at(method.descriptor_index).unwrap_or("()V");
    let parsed: Option<MethodDescriptor> = descriptor::parse_method(desc);
    let kw: String = member_access_keywords(method.access_flags);
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    let is_abstract: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) != 0;

    let mut signature: String = String::new();
    if kw.is_empty() {
        let _ = write!(signature, "    ");
    } else {
        let _ = write!(signature, "    {kw} ");
    }

    let mut local_index: u16 = u16::from(!is_static);
    let mut param_names: Vec<(u16, String)> = Vec::new();
    let params: String = match &parsed {
        Some(md) => {
            let mut rendered: Vec<String> = Vec::with_capacity(md.params.len());
            for (i, p) in md.params.iter().enumerate() {
                let pname: String = format!("arg{i}");
                rendered.push(format!("{} {pname}", p.render()));
                param_names.push((local_index, pname));
                local_index += if p.category_two() { 2 } else { 1 };
            }
            rendered.join(", ")
        }
        None => String::new(),
    };

    if name == "<init>" {
        let _ = write!(signature, "{class_simple}({params})");
    } else if name == "<clinit>" {
        signature = "    static".to_string();
    } else {
        let ret: String = parsed
            .as_ref()
            .map_or_else(|| "void".to_string(), |md| md.returns.render());
        let _ = write!(signature, "{ret} {name}({params})");
    }

    if is_abstract || is_interface && !has_code(cf, method) {
        let _ = write!(signature, ";");
        return RenderedMethod {
            text: signature,
            fully_lifted: false,
            has_body: false,
        };
    }

    let code_attr: Option<CodeAttribute> = find_code(cf, method);
    let Some(code) = code_attr else {
        let _ = write!(signature, " {{\n    }}");
        return RenderedMethod {
            text: signature,
            fully_lifted: true,
            has_body: true,
        };
    };

    let body: MethodBody = lift_method_body(cf, &code, &param_names, name == "<clinit>");
    let mut text: String = signature;
    let _ = write!(text, " {{\n{}    }}", body.text);
    RenderedMethod {
        text,
        fully_lifted: body.fully_lifted,
        has_body: true,
    }
}

fn has_code(cf: &ClassFile, method: &MethodInfo) -> bool {
    method.attributes.iter().any(|a| {
        cf.utf8_at(a.name_index)
            .map(|n| n == "Code")
            .unwrap_or(false)
    })
}

fn find_code(cf: &ClassFile, method: &MethodInfo) -> Option<CodeAttribute> {
    for attr in &method.attributes {
        if cf.utf8_at(attr.name_index).ok()? == "Code" {
            return parse_code_attribute(&attr.info).ok();
        }
    }
    None
}

struct MethodBody {
    text: String,
    fully_lifted: bool,
}

#[derive(Clone)]
pub(crate) enum Expr {
    Const(String),
    Local(String),
    This,
    Field {
        name: String,
    },
    StaticField {
        owner: String,
        name: String,
    },
    Binary {
        op: &'static str,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Unary {
        op: &'static str,
        value: Box<Self>,
    },
    Cast {
        ty: String,
        value: Box<Self>,
    },
    InstanceOf {
        value: Box<Self>,
        ty: String,
    },
    Cmp {
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    ArrayLength(Box<Self>),
    ArrayLoad {
        array: Box<Self>,
        index: Box<Self>,
    },
    New(String),
    NewArray {
        ty: String,
        size: Box<Self>,
    },
    Invoke {
        receiver: Option<Box<Self>>,
        owner: String,
        method: String,
        args: Vec<Self>,
    },
    Opaque(String),
}

impl Expr {
    pub(crate) fn render(&self) -> String {
        match self {
            Self::Const(s) | Self::Local(s) | Self::Opaque(s) => s.clone(),
            Self::This => "this".to_string(),
            Self::Field { name } => format!("this.{name}"),
            Self::StaticField { owner, name } => format!("{owner}.{name}"),
            Self::Binary { op, lhs, rhs } => {
                format!("({} {op} {})", lhs.render(), rhs.render())
            }
            Self::Unary { op, value } => format!("({op}{})", value.render()),
            Self::Cast { ty, value } => format!("(({ty}) {})", value.render()),
            Self::InstanceOf { value, ty } => {
                format!("({} instanceof {ty})", value.render())
            }
            Self::Cmp { lhs, rhs } => {
                format!("Integer.compare({}, {})", lhs.render(), rhs.render())
            }
            Self::ArrayLength(arr) => format!("{}.length", arr.render()),
            Self::ArrayLoad { array, index } => {
                format!("{}[{}]", array.render(), index.render())
            }
            Self::New(ty) => format!("new {ty}()"),
            Self::NewArray { ty, size } => format!("new {ty}[{}]", size.render()),
            Self::Invoke {
                receiver,
                owner,
                method,
                args,
            } => {
                let rendered_args: Vec<String> = args.iter().map(Self::render).collect();
                let joined: String = rendered_args.join(", ");
                match receiver {
                    Some(r) => format!("{}.{method}({joined})", r.render()),
                    None => format!("{owner}.{method}({joined})"),
                }
            }
        }
    }
}

fn lift_method_body(
    cf: &ClassFile,
    code: &CodeAttribute,
    params: &[(u16, String)],
    is_clinit: bool,
) -> MethodBody {
    let _ = is_clinit;
    let insns: Vec<Instruction> = match disassemble(&code.code) {
        Ok(v) => v,
        Err(_) => {
            return MethodBody {
                text: "        // <decompile: malformed bytecode>\n".to_string(),
                fully_lifted: false,
            };
        }
    };
    if insns.is_empty() {
        return MethodBody {
            text: String::new(),
            fully_lifted: true,
        };
    }
    let bootstraps: Vec<crate::attributes::BootstrapMethod> =
        crate::attributes::analyze(cf).bootstrap_methods;
    if let Some(body) = lift_structured(cf, code, &insns, params, &bootstraps) {
        return body;
    }
    lift_method_body_flat(cf, &insns, params, &bootstraps)
}

fn lift_method_body_flat(
    cf: &ClassFile,
    insns: &[Instruction],
    params: &[(u16, String)],
    bootstraps: &[crate::attributes::BootstrapMethod],
) -> MethodBody {
    let targets: BTreeSet<u32> = branch_targets(insns);
    let mut out: String = String::new();
    let mut stack: Vec<Expr> = Vec::new();
    let mut fully_lifted: bool = true;
    let indent: &str = "        ";

    let _ = writeln!(out, "{indent}/// irreducible CFG (native fallback)");
    for insn in insns {
        if targets.contains(&insn.pc) {
            stack.clear();
            let _ = writeln!(out, "{indent}// :L{}", insn.pc);
        }
        let lifted: LiftResult = lift_one(cf, insn, &mut stack, params, bootstraps);
        match lifted {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{indent}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{indent}{s}");
                fully_lifted = false;
            }
            LiftResult::Pushed => {}
            LiftResult::Unhandled => {
                stack.clear();
                fully_lifted = false;
                let _ = writeln!(out, "{indent}// {} (stack reset)", insn.mnemonic);
            }
        }
    }
    MethodBody {
        text: out,
        fully_lifted,
    }
}

fn lift_structured(
    cf: &ClassFile,
    code: &CodeAttribute,
    insns: &[Instruction],
    params: &[(u16, String)],
    bootstraps: &[crate::attributes::BootstrapMethod],
) -> Option<MethodBody> {
    let cfg: Cfg = build_cfg(insns, code, |idx: u16| {
        cf.class_name(idx).ok().map(str::to_string)
    })
    .ok()?;
    let dom: Dominators = compute_dominators(&cfg).ok()?;
    let loops: Vec<NaturalLoop> = find_natural_loops(&cfg, &dom);
    let mut structurer: Structurer<'_> = Structurer::new(&cfg, &dom, &loops, insns);
    let root: Region = structurer.structure();
    let mut ctx: RenderCtx<'_> = RenderCtx {
        cf,
        cfg: &cfg,
        insns,
        params,
        bootstraps,
        rendered_blocks: BTreeSet::new(),
        fully_lifted: !structurer.had_irreducible,
    };
    let mut out: String = String::new();
    render_region(&mut ctx, &root, &mut out, 2);
    let decls: String = local_declarations(insns, params);
    Some(MethodBody {
        text: format!("{decls}{out}"),
        fully_lifted: ctx.fully_lifted,
    })
}

/// Hoists a `Type varN;` declaration to the top of the method body for every
/// non-parameter local that the bytecode writes, inferring the JVM slot type
/// from the store opcode family (`istore`/`lstore`/`fstore`/`dstore`/`astore`).
/// javac discards local names and only the verifier's slot type survives, so
/// emitting a single widest-fit declaration per written slot is what makes the
/// reconstructed assignments (`varN = ...;`) compile rather than referencing an
/// undeclared symbol.
fn local_declarations(insns: &[Instruction], params: &[(u16, String)]) -> String {
    let param_slots: BTreeSet<u16> = params.iter().map(|(i, _)| *i).collect();
    let mut slot_type: BTreeMap<u16, &'static str> = BTreeMap::new();
    for insn in insns {
        let ty: &'static str = match insn.opcode {
            0x36 | 0x3B..=0x3E => "int",
            0x37 | 0x3F..=0x42 => "long",
            0x38 | 0x43..=0x46 => "float",
            0x39 | 0x47..=0x4A => "double",
            0x3A | 0x4B..=0x4E => "Object",
            _ => continue,
        };
        let slot: u16 = match (insn.opcode, &insn.operands) {
            (0x36..=0x3A, Operands::Local(idx)) => *idx,
            (0x3B..=0x3E, _) => u16::from(insn.opcode - 0x3B),
            (0x3F..=0x42, _) => u16::from(insn.opcode - 0x3F),
            (0x43..=0x46, _) => u16::from(insn.opcode - 0x43),
            (0x47..=0x4A, _) => u16::from(insn.opcode - 0x47),
            (0x4B..=0x4E, _) => u16::from(insn.opcode - 0x4B),
            _ => continue,
        };
        if param_slots.contains(&slot) {
            continue;
        }
        slot_type
            .entry(slot)
            .and_modify(|cur: &mut &'static str| {
                if *cur != ty {
                    *cur = "Object";
                }
            })
            .or_insert(ty);
    }
    let mut out: String = String::new();
    for (slot, ty) in &slot_type {
        let _ = writeln!(out, "        {ty} var{slot};");
    }
    out
}

struct RenderCtx<'a> {
    cf: &'a ClassFile,
    cfg: &'a Cfg,
    insns: &'a [Instruction],
    params: &'a [(u16, String)],
    bootstraps: &'a [crate::attributes::BootstrapMethod],
    rendered_blocks: BTreeSet<BlockId>,
    fully_lifted: bool,
}

fn indent_string(level: usize) -> String {
    "    ".repeat(level)
}

const MAX_RENDER_BYTES: usize = 4 * 1024 * 1024;

fn render_region(ctx: &mut RenderCtx<'_>, region: &Region, out: &mut String, level: usize) {
    if out.len() > MAX_RENDER_BYTES {
        return;
    }
    match region {
        Region::Block(bid) => render_block(ctx, *bid, out, level),
        Region::Sequence(items) => {
            for r in items {
                render_region(ctx, r, out, level);
            }
        }
        Region::IfThen {
            head, then_body, ..
        } => {
            let cond: String = render_if_condition(ctx, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(ctx, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::IfThenElse {
            head,
            then_body,
            else_body,
            ..
        } => {
            let cond: String = render_if_condition(ctx, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(ctx, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}} else {{");
            render_region(ctx, else_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::While { header, body, exit } => {
            let cond: String = render_if_condition(ctx, *header, out, level);
            let negated: bool =
                matches!(exit, Some(e) if header_cond_true_target(ctx.cfg, *header) == Some(*e));
            let displayed_cond: String = if negated { invert(&cond) } else { cond };
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}while ({displayed_cond}) {{");
            render_region(ctx, body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::DoWhile { header, body, .. } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}do {{");
            render_block(ctx, *header, out, level + 1);
            render_region(ctx, body, out, level + 1);
            let _ = writeln!(out, "{pad}}} while (true);");
        }
        Region::Switch {
            head,
            cases,
            default,
            ..
        } => {
            let expr: String = render_switch_subject(ctx, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}switch ({expr}) {{");
            for (i, (key, body)) in cases.iter().enumerate() {
                let label: String = format_switch_key(key, i);
                let _ = writeln!(out, "{pad}    case {label}:");
                render_region(ctx, body, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            if let Some(def) = default {
                let _ = writeln!(out, "{pad}    default:");
                render_region(ctx, def, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Try { try_body, handlers } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try {{");
            render_region(ctx, try_body, out, level + 1);
            for (i, (catch_type, handler_region)) in handlers.iter().enumerate() {
                let ty: String = catch_type
                    .as_deref()
                    .map_or_else(|| "Throwable".to_string(), descriptor::binary_to_source);
                let _ = writeln!(out, "{pad}}} catch ({ty} ex{i}) {{");
                render_region(ctx, handler_region, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Irreducible { blocks } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}/// irreducible region");
            for bid in blocks {
                render_block(ctx, *bid, out, level);
            }
            ctx.fully_lifted = false;
        }
    }
}

fn block_insn_range(ctx: &RenderCtx<'_>, bid: BlockId) -> (usize, usize) {
    let b: &BasicBlock = &ctx.cfg.blocks[bid.0 as usize];
    b.insn_range
}

fn render_block(ctx: &mut RenderCtx<'_>, bid: BlockId, out: &mut String, level: usize) {
    if !ctx.rendered_blocks.insert(bid) {
        return;
    }
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let pad: String = indent_string(level);
    let mut stack: Vec<Expr> = Vec::new();
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(
            op,
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xA7 | 0xC8 | 0xAA | 0xAB | 0xA9
        ) {
            continue;
        }
        let lifted: LiftResult = lift_one(ctx.cf, ins, &mut stack, ctx.params, ctx.bootstraps);
        match lifted {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
                ctx.fully_lifted = false;
            }
            LiftResult::Pushed => {}
            LiftResult::Unhandled => {
                stack.clear();
                ctx.fully_lifted = false;
                let _ = writeln!(out, "{pad}// {} (stack reset)", ins.mnemonic);
            }
        }
    }
}

fn render_if_condition(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    if start == end {
        return "true".to_string();
    }
    let body_end: usize = end - 1;
    let pad: String = indent_string(level);
    let mut stack: Vec<Expr> = Vec::new();
    let already_rendered: bool = !ctx.rendered_blocks.insert(head);
    for ins in &ctx.insns[start..body_end] {
        let lifted: LiftResult = lift_one(ctx.cf, ins, &mut stack, ctx.params, ctx.bootstraps);
        if already_rendered {
            continue;
        }
        match lifted {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
                ctx.fully_lifted = false;
            }
            LiftResult::Pushed => {}
            LiftResult::Unhandled => {
                stack.clear();
                ctx.fully_lifted = false;
                let _ = writeln!(out, "{pad}// {} (stack reset)", ins.mnemonic);
            }
        }
    }
    let term: &Instruction = &ctx.insns[body_end];
    render_branch_condition(term, &mut stack)
}

fn render_branch_condition(insn: &Instruction, stack: &mut Vec<Expr>) -> String {
    match insn.opcode {
        0x99 => unary_or_cmp_cond(stack, "==", "== 0"),
        0x9A => unary_or_cmp_cond(stack, "!=", "!= 0"),
        0x9B => unary_or_cmp_cond(stack, "<", "< 0"),
        0x9C => unary_or_cmp_cond(stack, ">=", ">= 0"),
        0x9D => unary_or_cmp_cond(stack, ">", "> 0"),
        0x9E => unary_or_cmp_cond(stack, "<=", "<= 0"),
        0x9F | 0xA5 => binary_cond_kept(stack, "=="),
        0xA0 | 0xA6 => binary_cond_kept(stack, "!="),
        0xA1 => binary_cond_kept(stack, "<"),
        0xA2 => binary_cond_kept(stack, ">="),
        0xA3 => binary_cond_kept(stack, ">"),
        0xA4 => binary_cond_kept(stack, "<="),
        0xC6 => unary_cond_kept(stack, "== null"),
        0xC7 => unary_cond_kept(stack, "!= null"),
        _ => "true".to_string(),
    }
}

fn unary_cond_kept(stack: &mut Vec<Expr>, suffix: &str) -> String {
    let v: Expr = pop_expr(stack);
    format!("{} {suffix}", v.render())
}

fn unary_or_cmp_cond(stack: &mut Vec<Expr>, rel_op: &str, zero_suffix: &str) -> String {
    let v: Expr = pop_expr(stack);
    match v {
        Expr::Cmp { lhs, rhs } => format!("{} {rel_op} {}", lhs.render(), rhs.render()),
        other => format!("{} {zero_suffix}", other.render()),
    }
}

fn binary_cond_kept(stack: &mut Vec<Expr>, op: &str) -> String {
    let rhs: Expr = pop_expr(stack);
    let lhs: Expr = pop_expr(stack);
    format!("{} {op} {}", lhs.render(), rhs.render())
}

fn render_switch_subject(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    if start == end {
        return "expr".to_string();
    }
    let body_end: usize = end - 1;
    let pad: String = indent_string(level);
    let mut stack: Vec<Expr> = Vec::new();
    let already_rendered: bool = !ctx.rendered_blocks.insert(head);
    for ins in &ctx.insns[start..body_end] {
        let lifted: LiftResult = lift_one(ctx.cf, ins, &mut stack, ctx.params, ctx.bootstraps);
        if already_rendered {
            continue;
        }
        match lifted {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
                ctx.fully_lifted = false;
            }
            LiftResult::Pushed => {}
            LiftResult::Unhandled => {
                stack.clear();
                ctx.fully_lifted = false;
                let _ = writeln!(out, "{pad}// {} (stack reset)", ins.mnemonic);
            }
        }
    }
    pop_expr(&mut stack).render()
}

fn invert(cond: &str) -> String {
    if let Some(rest) = cond.strip_suffix(" == 0") {
        return format!("{rest} != 0");
    }
    if let Some(rest) = cond.strip_suffix(" != 0") {
        return format!("{rest} == 0");
    }
    if let Some(rest) = cond.strip_suffix(" == null") {
        return format!("{rest} != null");
    }
    if let Some(rest) = cond.strip_suffix(" != null") {
        return format!("{rest} == null");
    }
    if cond.contains(" < ") {
        return cond.replacen(" < ", " >= ", 1);
    }
    if cond.contains(" <= ") {
        return cond.replacen(" <= ", " > ", 1);
    }
    if cond.contains(" > ") {
        return cond.replacen(" > ", " <= ", 1);
    }
    if cond.contains(" >= ") {
        return cond.replacen(" >= ", " < ", 1);
    }
    if cond.contains(" == ") {
        return cond.replacen(" == ", " != ", 1);
    }
    if cond.contains(" != ") {
        return cond.replacen(" != ", " == ", 1);
    }
    format!("!({cond})")
}

fn header_cond_true_target(cfg: &Cfg, head: BlockId) -> Option<BlockId> {
    let block: &BasicBlock = &cfg.blocks[head.0 as usize];
    block
        .successors
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::CondTrue))
        .map(|e| e.target)
}

fn format_switch_key(key: &SwitchKey, fallback_idx: usize) -> String {
    match key {
        SwitchKey::Range { low, high } => (*low..=*high)
            .map(|v: i32| v.to_string())
            .collect::<Vec<String>>()
            .join(", "),
        SwitchKey::Values(vs) if !vs.is_empty() => vs
            .iter()
            .map(i32::to_string)
            .collect::<Vec<String>>()
            .join(", "),
        SwitchKey::Values(_) => fallback_idx.to_string(),
    }
}

fn branch_targets(insns: &[Instruction]) -> BTreeSet<u32> {
    let mut targets: BTreeSet<u32> = BTreeSet::new();
    for insn in insns {
        if let Some(t) = branch_target(insn) {
            targets.insert(t);
        }
        match &insn.operands {
            Operands::TableSwitch {
                default, offsets, ..
            } => {
                targets.insert((i64::from(insn.pc) + i64::from(*default)) as u32);
                for off in offsets {
                    targets.insert((i64::from(insn.pc) + i64::from(*off)) as u32);
                }
            }
            Operands::LookupSwitch { default, pairs } => {
                targets.insert((i64::from(insn.pc) + i64::from(*default)) as u32);
                for (_, off) in pairs {
                    targets.insert((i64::from(insn.pc) + i64::from(*off)) as u32);
                }
            }
            _ => {}
        }
    }
    targets
}

enum LiftResult {
    Pushed,
    Statement(String),
    ControlFlow(String),
    Unhandled,
}

fn local_name(index: u16, params: &[(u16, String)]) -> String {
    params
        .iter()
        .find(|(i, _)| *i == index)
        .map_or_else(|| format!("var{index}"), |(_, n)| n.clone())
}

pub(crate) const MAX_DUP_EXPR_NODES: usize = 1024;

pub(crate) fn expr_node_count_capped(e: &Expr, cap: usize) -> usize {
    fn walk(e: &Expr, cap: usize, acc: &mut usize) {
        if *acc >= cap {
            return;
        }
        *acc += 1;
        match e {
            Expr::Binary { lhs, rhs, .. }
            | Expr::Cmp { lhs, rhs }
            | Expr::ArrayLoad {
                array: lhs,
                index: rhs,
            } => {
                walk(lhs, cap, acc);
                walk(rhs, cap, acc);
            }
            Expr::Unary { value, .. }
            | Expr::Cast { value, .. }
            | Expr::InstanceOf { value, .. }
            | Expr::ArrayLength(value)
            | Expr::NewArray { size: value, .. } => walk(value, cap, acc),
            Expr::Invoke { receiver, args, .. } => {
                if let Some(r) = receiver {
                    walk(r, cap, acc);
                }
                for a in args {
                    walk(a, cap, acc);
                }
            }
            Expr::Const(_)
            | Expr::Local(_)
            | Expr::This
            | Expr::Field { .. }
            | Expr::StaticField { .. }
            | Expr::New(_)
            | Expr::Opaque(_) => {}
        }
    }
    let mut acc: usize = 0;
    walk(e, cap, &mut acc);
    acc
}

#[allow(clippy::too_many_lines)]
fn lift_one(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    params: &[(u16, String)],
    bootstraps: &[crate::attributes::BootstrapMethod],
) -> LiftResult {
    let op: u8 = insn.opcode;
    match op {
        0x00 => LiftResult::Pushed,
        0x01 => push(stack, Expr::Const("null".to_string())),
        0x02 => push(stack, Expr::Const("-1".to_string())),
        0x03..=0x08 => push(stack, Expr::Const((i32::from(op) - 3).to_string())),
        0x09 | 0x0A => push(stack, Expr::Const(format!("{}L", op - 9))),
        0x0B..=0x0D => push(stack, Expr::Const(format!("{}.0f", op - 0x0B))),
        0x0E | 0x0F => push(stack, Expr::Const(format!("{}.0", op - 0x0E))),
        0x10 | 0x11 => match &insn.operands {
            Operands::Byte(v) | Operands::Short(v) => push(stack, Expr::Const(v.to_string())),
            _ => LiftResult::Unhandled,
        },
        0x12..=0x14 => match &insn.operands {
            Operands::ConstPool(idx) => {
                let value: String =
                    bytecode::resolve_ref(cf, *idx).unwrap_or_else(|| "/*ldc*/0".to_string());
                push(stack, Expr::Const(value))
            }
            _ => LiftResult::Unhandled,
        },
        0x15..=0x19 => match &insn.operands {
            Operands::Local(idx) => {
                if op == 0x19 && *idx == 0 && !params.iter().any(|(i, _)| *i == 0) {
                    push(stack, Expr::This)
                } else {
                    push(stack, Expr::Local(local_name(*idx, params)))
                }
            }
            _ => LiftResult::Unhandled,
        },
        0x1A..=0x1D => push(stack, Expr::Local(local_name(u16::from(op - 0x1A), params))),
        0x1E..=0x21 => push(stack, Expr::Local(local_name(u16::from(op - 0x1E), params))),
        0x22..=0x25 => push(stack, Expr::Local(local_name(u16::from(op - 0x22), params))),
        0x26..=0x29 => push(stack, Expr::Local(local_name(u16::from(op - 0x26), params))),
        0x2A..=0x2D => {
            let idx: u16 = u16::from(op - 0x2A);
            if idx == 0 && !params.iter().any(|(i, _)| *i == 0) {
                push(stack, Expr::This)
            } else {
                push(stack, Expr::Local(local_name(idx, params)))
            }
        }
        0x2E..=0x35 => binary_array_load(stack),
        0x36..=0x3A => store_local(insn, stack, params),
        0x3B..=0x3E => store_indexed(stack, u16::from(op - 0x3B), params),
        0x3F..=0x42 => store_indexed(stack, u16::from(op - 0x3F), params),
        0x43..=0x46 => store_indexed(stack, u16::from(op - 0x43), params),
        0x47..=0x4A => store_indexed(stack, u16::from(op - 0x47), params),
        0x4B..=0x4E => store_indexed(stack, u16::from(op - 0x4B), params),
        0x4F..=0x56 => array_store(stack),
        0x57 => {
            stack.pop();
            LiftResult::Pushed
        }
        0x58 => {
            stack.pop();
            stack.pop();
            LiftResult::Pushed
        }
        0x59 => {
            if let Some(top) = stack.last() {
                let dup: Expr =
                    if expr_node_count_capped(top, MAX_DUP_EXPR_NODES) >= MAX_DUP_EXPR_NODES {
                        unknown()
                    } else {
                        top.clone()
                    };
                stack.push(dup);
            }
            LiftResult::Pushed
        }
        0x60..=0x63 => binary_op(stack, "+"),
        0x64..=0x67 => binary_op(stack, "-"),
        0x68..=0x6B => binary_op(stack, "*"),
        0x6C..=0x6F => binary_op(stack, "/"),
        0x70..=0x73 => binary_op(stack, "%"),
        0x74..=0x77 => unary_op(stack, "-"),
        0x78 | 0x79 => binary_op(stack, "<<"),
        0x7A | 0x7B => binary_op(stack, ">>"),
        0x7C | 0x7D => binary_op(stack, ">>>"),
        0x7E | 0x7F => binary_op(stack, "&"),
        0x80 | 0x81 => binary_op(stack, "|"),
        0x82 | 0x83 => binary_op(stack, "^"),
        0x84 => iinc(insn, params),
        0x85..=0x93 => cast_numeric(insn, stack),
        0x94..=0x98 => binary_op(stack, "cmp"),
        0x99..=0xA6 => conditional_branch(insn, stack),
        0xA7 | 0xC8 => {
            LiftResult::ControlFlow(format!("// goto L{}", branch_target(insn).unwrap_or(0)))
        }
        0xAC..=0xB0 => {
            let value: Expr = pop_expr(stack);
            LiftResult::Statement(format!("return {}", value.render()))
        }
        0xB1 => LiftResult::Statement("return".to_string()),
        0xB2 | 0xB4 => field_get(cf, insn, stack, op == 0xB2),
        0xB3 | 0xB5 => field_put(cf, insn, stack, op == 0xB3),
        0xB6..=0xB9 => invoke(cf, insn, stack, op),
        0xBA => invoke_dynamic(cf, insn, stack, bootstraps),
        0xBB => new_object(cf, insn, stack),
        0xBC | 0xBD => new_array(cf, insn, stack),
        0xBE => array_length(stack),
        0xBF => {
            let value: Expr = pop_expr(stack);
            LiftResult::Statement(format!("throw {}", value.render()))
        }
        0xC0 => checkcast(cf, insn, stack),
        0xC1 => instance_of(cf, insn, stack),
        0xC2 => {
            stack.pop();
            LiftResult::ControlFlow("// monitorenter (synchronized)".to_string())
        }
        0xC3 => {
            stack.pop();
            LiftResult::ControlFlow("// monitorexit".to_string())
        }
        _ => LiftResult::Unhandled,
    }
}

#[inline]
fn push(stack: &mut Vec<Expr>, e: Expr) -> LiftResult {
    stack.push(e);
    LiftResult::Pushed
}

#[inline]
fn unknown() -> Expr {
    Expr::Opaque("?".to_string())
}

#[inline]
fn pop_expr(stack: &mut Vec<Expr>) -> Expr {
    stack.pop().unwrap_or_else(unknown)
}

fn binary_op(stack: &mut Vec<Expr>, op: &'static str) -> LiftResult {
    let rhs: Expr = pop_expr(stack);
    let lhs: Expr = pop_expr(stack);
    if op == "cmp" {
        stack.push(Expr::Cmp {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        });
    } else {
        stack.push(Expr::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        });
    }
    LiftResult::Pushed
}

fn unary_op(stack: &mut Vec<Expr>, op: &'static str) -> LiftResult {
    let value: Expr = pop_expr(stack);
    stack.push(Expr::Unary {
        op,
        value: Box::new(value),
    });
    LiftResult::Pushed
}

fn binary_array_load(stack: &mut Vec<Expr>) -> LiftResult {
    let index: Expr = pop_expr(stack);
    let array: Expr = pop_expr(stack);
    stack.push(Expr::ArrayLoad {
        array: Box::new(array),
        index: Box::new(index),
    });
    LiftResult::Pushed
}

fn array_store(stack: &mut Vec<Expr>) -> LiftResult {
    let value: Expr = pop_expr(stack);
    let index: Expr = pop_expr(stack);
    let array: Expr = pop_expr(stack);
    LiftResult::Statement(format!(
        "{}[{}] = {}",
        array.render(),
        index.render(),
        value.render()
    ))
}

fn store_local(insn: &Instruction, stack: &mut Vec<Expr>, params: &[(u16, String)]) -> LiftResult {
    match &insn.operands {
        Operands::Local(idx) => store_indexed(stack, *idx, params),
        _ => LiftResult::Unhandled,
    }
}

fn store_indexed(stack: &mut Vec<Expr>, idx: u16, params: &[(u16, String)]) -> LiftResult {
    let value: Expr = pop_expr(stack);
    LiftResult::Statement(format!("{} = {}", local_name(idx, params), value.render()))
}

fn iinc(insn: &Instruction, params: &[(u16, String)]) -> LiftResult {
    match &insn.operands {
        Operands::Iinc { index, delta } => {
            let name: String = local_name(*index, params);
            if *delta == 1 {
                LiftResult::Statement(format!("{name}++"))
            } else if *delta == -1 {
                LiftResult::Statement(format!("{name}--"))
            } else if *delta < 0 {
                LiftResult::Statement(format!("{name} -= {}", -delta))
            } else {
                LiftResult::Statement(format!("{name} += {delta}"))
            }
        }
        _ => LiftResult::Unhandled,
    }
}

fn cast_numeric(insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let ty: &str = match insn.opcode {
        0x85 | 0x8F | 0x91 => "long",
        0x86 | 0x89 | 0x8C => "float",
        0x87 | 0x8A | 0x8D => "double",
        0x88 | 0x8B | 0x8E => "int",
        0x90 => "float",
        0x92 => "char",
        0x93 => "short",
        _ => return LiftResult::Unhandled,
    };
    let value: Expr = pop_expr(stack);
    stack.push(Expr::Cast {
        ty: ty.to_string(),
        value: Box::new(value),
    });
    LiftResult::Pushed
}

fn conditional_branch(insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let target: u32 = branch_target(insn).unwrap_or(0);
    let cond: String = match insn.opcode {
        0x99 => unary_or_cmp_cond(stack, "==", "== 0"),
        0x9A => unary_or_cmp_cond(stack, "!=", "!= 0"),
        0x9B => unary_or_cmp_cond(stack, "<", "< 0"),
        0x9C => unary_or_cmp_cond(stack, ">=", ">= 0"),
        0x9D => unary_or_cmp_cond(stack, ">", "> 0"),
        0x9E => unary_or_cmp_cond(stack, "<=", "<= 0"),
        0x9F | 0xA5 => binary_cond(stack, "=="),
        0xA0 | 0xA6 => binary_cond(stack, "!="),
        0xA1 => binary_cond(stack, "<"),
        0xA2 => binary_cond(stack, ">="),
        0xA3 => binary_cond(stack, ">"),
        0xA4 => binary_cond(stack, "<="),
        _ => "?".to_string(),
    };
    LiftResult::ControlFlow(format!("if ({cond}) goto L{target};"))
}

fn binary_cond(stack: &mut Vec<Expr>, op: &str) -> String {
    let rhs: Expr = pop_expr(stack);
    let lhs: Expr = pop_expr(stack);
    format!("{} {op} {}", lhs.render(), rhs.render())
}

fn split_member(reference: &str) -> Option<(String, String, String)> {
    let (owner_name, desc): (&str, &str) = reference.rsplit_once(':')?;
    let (owner, name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some((owner.to_string(), name.to_string(), desc.to_string()))
}

fn field_get(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    is_static: bool,
) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(cf, *idx) else {
        return LiftResult::Unhandled;
    };
    let Some((owner, name, _desc)): Option<(String, String, String)> = split_member(&reference)
    else {
        return LiftResult::Unhandled;
    };
    if is_static {
        push(
            stack,
            Expr::StaticField {
                owner: descriptor::binary_to_source(&owner),
                name,
            },
        )
    } else {
        let _owner: String = owner;
        let _receiver: Expr = stack.pop().unwrap_or(Expr::This);
        push(stack, Expr::Field { name })
    }
}

fn field_put(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    is_static: bool,
) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(cf, *idx) else {
        return LiftResult::Unhandled;
    };
    let Some((owner, name, _desc)): Option<(String, String, String)> = split_member(&reference)
    else {
        return LiftResult::Unhandled;
    };
    let value: Expr = pop_expr(stack);
    if is_static {
        LiftResult::Statement(format!(
            "{}.{name} = {}",
            descriptor::binary_to_source(&owner),
            value.render()
        ))
    } else {
        let _receiver: Expr = stack.pop().unwrap_or(Expr::This);
        LiftResult::Statement(format!("this.{name} = {}", value.render()))
    }
}

fn invoke(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>, op: u8) -> LiftResult {
    let idx: u16 = match &insn.operands {
        Operands::ConstPool(i) => *i,
        Operands::InvokeInterface { index, .. } => *index,
        _ => return LiftResult::Unhandled,
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(cf, idx) else {
        return LiftResult::Unhandled;
    };
    let Some((owner, name, desc)): Option<(String, String, String)> = split_member(&reference)
    else {
        return LiftResult::Unhandled;
    };
    let Some(parsed): Option<MethodDescriptor> = descriptor::parse_method(&desc) else {
        return LiftResult::Unhandled;
    };
    let argc: usize = parsed.params.len();
    if stack.len() < argc {
        return LiftResult::Unhandled;
    }
    let args: Vec<Expr> = stack.split_off(stack.len() - argc);
    let is_static: bool = op == 0xB8;
    let receiver: Option<Expr> = if is_static {
        None
    } else {
        Some(stack.pop().unwrap_or(Expr::This))
    };

    if name == "<init>" {
        let ctor_args: Vec<String> = args.iter().map(Expr::render).collect();
        let joined: String = ctor_args.join(", ");
        match receiver {
            Some(Expr::New(ty)) => {
                let folded: Expr = Expr::Opaque(format!("new {ty}({joined})"));
                if matches!(stack.last(), Some(Expr::New(under)) if *under == ty) {
                    stack.pop();
                    stack.push(folded);
                    return LiftResult::Pushed;
                }
                return LiftResult::Statement(folded.render());
            }
            Some(Expr::This) | None => {
                return LiftResult::Statement(format!(
                    "super({joined}) /* {} */",
                    descriptor::binary_to_source(&owner)
                ));
            }
            Some(other) => {
                return LiftResult::Statement(format!("{}.<init>({joined})", other.render()));
            }
        }
    }

    let call: Expr = Expr::Invoke {
        receiver: receiver.map(Box::new),
        owner: descriptor::binary_to_source(&owner),
        method: name,
        args,
    };
    if matches!(parsed.returns, JavaType::Void) {
        LiftResult::Statement(call.render())
    } else {
        stack.push(call);
        LiftResult::Pushed
    }
}

fn invoke_dynamic(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    bootstraps: &[crate::attributes::BootstrapMethod],
) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let Some(indy): Option<&crate::classfile::ConstantPoolEntry> =
        cf.constant_pool.get(usize::from(*idx))
    else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let crate::classfile::ConstantPoolEntry::InvokeDynamic {
        bootstrap_method_attr_index,
        name_and_type_index,
    } = indy
    else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let Some((indy_name, indy_desc)): Option<(String, String)> =
        name_and_type_parts(cf, *name_and_type_index)
    else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let Some(parsed): Option<MethodDescriptor> = descriptor::parse_method(&indy_desc) else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let argc: usize = parsed.params.len();
    let popped: usize = argc.min(stack.len());
    let args: Vec<Expr> = stack.split_off(stack.len() - popped);

    let bsm: Option<&crate::attributes::BootstrapMethod> =
        bootstraps.get(usize::from(*bootstrap_method_attr_index));
    let bsm_name: Option<String> = bsm.and_then(|b| method_handle_ref_name(cf, b.method_ref_index));

    if matches!(
        bsm_name.as_deref(),
        Some("makeConcatWithConstants" | "makeConcat")
    ) {
        let recipe: Option<String> = bsm
            .filter(|_| bsm_name.as_deref() == Some("makeConcatWithConstants"))
            .and_then(|b| b.arguments.first())
            .and_then(|&a| bootstrap_string_arg(cf, a));
        let folded: Expr = fold_string_concat(recipe.as_deref(), &args);
        return push(stack, folded);
    }

    if matches!(parsed.returns, JavaType::Object(_)) {
        let impl_ref: Option<String> = bsm
            .and_then(|b| b.arguments.get(1).copied())
            .and_then(|a| method_handle_ref_name(cf, a));
        let target: String =
            impl_ref.map_or_else(|| format!("{indy_name}$lambda"), |m| format!("this::{m}"));
        return push(stack, Expr::Opaque(target));
    }
    push(stack, Expr::Opaque(format!("{indy_name}()")))
}

fn name_and_type_parts(cf: &ClassFile, index: u16) -> Option<(String, String)> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    if let crate::classfile::ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = entry
    {
        let name: String = cf.utf8_at(*name_index).ok()?.to_string();
        let desc: String = cf.utf8_at(*descriptor_index).ok()?.to_string();
        Some((name, desc))
    } else {
        None
    }
}

fn method_handle_ref_name(cf: &ClassFile, index: u16) -> Option<String> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    let crate::classfile::ConstantPoolEntry::MethodHandle {
        reference_index, ..
    } = entry
    else {
        return None;
    };
    let reference: String = bytecode::resolve_ref(cf, *reference_index)?;
    let (owner_name, _desc): (&str, &str) = reference.rsplit_once(':')?;
    let (_owner, name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some(name.to_string())
}

fn bootstrap_string_arg(cf: &ClassFile, index: u16) -> Option<String> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    if let crate::classfile::ConstantPoolEntry::String { utf8_index } = entry {
        cf.utf8_at(*utf8_index).ok().map(str::to_string)
    } else {
        None
    }
}

/// Reconstructs a `String` concatenation desugared into a
/// `StringConcatFactory.makeConcatWithConstants` invokedynamic. The recipe
/// string interleaves literal text with `` (dynamic argument) and
/// `` (constant pool) markers; this walks the recipe, substituting each
/// `` with the next stack argument and emitting literal runs as quoted
/// strings, yielding `"x=" + a + ", y=" + b`. With no recipe (`makeConcat`)
/// the arguments are simply joined with `+`.
fn fold_string_concat(recipe: Option<&str>, args: &[Expr]) -> Expr {
    let mut pieces: Vec<String> = Vec::new();
    match recipe {
        Some(r) => {
            let mut arg_iter: std::slice::Iter<'_, Expr> = args.iter();
            let mut literal: String = String::new();
            for ch in r.chars() {
                match ch {
                    '\u{0001}' => {
                        if !literal.is_empty() {
                            pieces.push(bytecode::escape_java_string(&literal));
                            literal.clear();
                        }
                        if let Some(a) = arg_iter.next() {
                            pieces.push(a.render());
                        }
                    }
                    '\u{0002}' => {}
                    c => literal.push(c),
                }
            }
            if !literal.is_empty() {
                pieces.push(bytecode::escape_java_string(&literal));
            }
        }
        None => pieces.extend(args.iter().map(Expr::render)),
    }
    if pieces.is_empty() {
        return Expr::Const("\"\"".to_string());
    }
    if pieces.first().is_none_or(|p: &String| !p.starts_with('"')) {
        pieces.insert(0, "\"\"".to_string());
    }
    Expr::Opaque(format!("({})", pieces.join(" + ")))
}

fn new_object(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let Some(name): Option<String> = bytecode::resolve_ref(cf, *idx) else {
        return LiftResult::Unhandled;
    };
    push(stack, Expr::New(descriptor::binary_to_source(&name)))
}

fn new_array(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let size: Expr = pop_expr(stack);
    let ty: String = match (&insn.operands, insn.opcode) {
        (Operands::NewArray(code), _) => primitive_array_type(*code).to_string(),
        (Operands::ConstPool(idx), _) => bytecode::resolve_ref(cf, *idx)
            .map(|n| descriptor::binary_to_source(&n))
            .unwrap_or_else(|| "Object".to_string()),
        _ => "Object".to_string(),
    };
    push(
        stack,
        Expr::NewArray {
            ty,
            size: Box::new(size),
        },
    )
}

const fn primitive_array_type(code: u8) -> &'static str {
    match code {
        4 => "boolean",
        5 => "char",
        6 => "float",
        7 => "double",
        8 => "byte",
        9 => "short",
        10 => "int",
        11 => "long",
        _ => "Object",
    }
}

fn array_length(stack: &mut Vec<Expr>) -> LiftResult {
    let arr: Expr = pop_expr(stack);
    push(stack, Expr::ArrayLength(Box::new(arr)))
}

fn checkcast(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let ty: String = bytecode::resolve_ref(cf, *idx)
        .map(|n| descriptor::binary_to_source(&n))
        .unwrap_or_else(|| "Object".to_string());
    let value: Expr = pop_expr(stack);
    stack.push(Expr::Cast {
        ty,
        value: Box::new(value),
    });
    LiftResult::Pushed
}

fn instance_of(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let ty: String = bytecode::resolve_ref(cf, *idx)
        .map(|n| descriptor::binary_to_source(&n))
        .unwrap_or_else(|| "Object".to_string());
    let value: Expr = pop_expr(stack);
    stack.push(Expr::InstanceOf {
        value: Box::new(value),
        ty,
    });
    LiftResult::Pushed
}

pub fn decompile_classfile_bytes(bytes: &[u8]) -> Result<DecompiledClass> {
    let cf: ClassFile = crate::classfile::parse(bytes)?;
    Ok(decompile_class(&cf))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::classfile::{Attribute, ConstantPoolEntry};

    fn cp_utf8(s: &str) -> ConstantPoolEntry {
        ConstantPoolEntry::Utf8(s.to_string())
    }

    #[test]
    fn access_keywords_render() {
        assert_eq!(
            member_access_keywords(ACC_PUBLIC | ACC_STATIC),
            "public static"
        );
        assert_eq!(
            member_access_keywords(ACC_PRIVATE | ACC_FINAL),
            "private final"
        );
    }

    #[test]
    fn decompiles_minimal_class_header() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(d.source.contains("package com.example;"));
        assert!(d.source.contains("public class Foo {"));
    }

    #[test]
    fn lifts_iconst_ireturn_method() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("answer"));
        cp.push(cp_utf8("()I"));
        cp.push(cp_utf8("Code"));
        let code_body: Vec<u8> = vec![0x05, 0xAC];
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
        info.extend_from_slice(&code_body);
        info.extend_from_slice(&0u16.to_be_bytes());
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags: ACC_PUBLIC | ACC_STATIC,
                name_index: 5,
                descriptor_index: 6,
                attributes: vec![Attribute {
                    name_index: 7,
                    info,
                }],
            }],
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(
            d.source.contains("public static int answer()"),
            "{}",
            d.source
        );
        assert!(d.source.contains("return 2"), "{}", d.source);
        assert_eq!(d.fully_lifted_methods, 1);
    }

    #[test]
    fn dup_bomb_method_stays_bounded() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("bomb"));
        cp.push(cp_utf8("()I"));
        cp.push(cp_utf8("Code"));
        let mut code_body: Vec<u8> = vec![0x05];
        for _ in 0..60 {
            code_body.push(0x59);
            code_body.push(0x68);
        }
        code_body.push(0xAC);
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&4u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
        info.extend_from_slice(&code_body);
        info.extend_from_slice(&0u16.to_be_bytes());
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags: ACC_PUBLIC | ACC_STATIC,
                name_index: 5,
                descriptor_index: 6,
                attributes: vec![Attribute {
                    name_index: 7,
                    info,
                }],
            }],
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(
            d.source.len() < 1_000_000,
            "dup-bomb output must stay bounded, got {} bytes",
            d.source.len()
        );
        assert!(
            d.source.contains('?'),
            "dup-bomb cap must emit opaque marker"
        );
    }

    #[test]
    fn lifts_field_and_static_field_access() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("count"));
        cp.push(cp_utf8("I"));
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: vec![FieldInfo {
                access_flags: ACC_PRIVATE,
                name_index: 5,
                descriptor_index: 6,
                attributes: Vec::new(),
            }],
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(d.source.contains("private int count;"), "{}", d.source);
    }

    #[test]
    fn interface_method_renders_abstract() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Service"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("run"));
        cp.push(cp_utf8("()V"));
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags: ACC_PUBLIC | ACC_ABSTRACT,
                name_index: 5,
                descriptor_index: 6,
                attributes: Vec::new(),
            }],
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(d.source.contains("interface Service"), "{}", d.source);
        assert!(d.source.contains("void run();"), "{}", d.source);
    }
}
