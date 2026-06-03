use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::dalvik::DalvikInsn;
use crate::dalvik_cfg::{DalvikMethodCfg, build_dalvik_cfg_from_code_item};
use crate::dalvik_lift::{
    LiftOutcome, MethodContext, RegisterFile, lift_insn, render_branch_condition,
    seed_block_registers,
};
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Dominators, EdgeKind, NaturalLoop, Region, Structurer, SwitchKey,
    compute_dominators, find_natural_loops,
};
use crate::descriptor::{self, MethodDescriptor};
use crate::dex::{CodeItem, DexFile, parse_code_items};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledDex {
    pub source: String,
    pub class_count: usize,
    pub method_count: usize,
    pub fully_lifted_methods: usize,
    pub fallback_methods: usize,
}

const MAX_RENDER_BYTES: usize = 4 * 1024 * 1024;

#[must_use]
pub fn decompile_dex(dex: &DexFile, bytes: &[u8]) -> DecompiledDex {
    let items: Vec<CodeItem> = parse_code_items(dex, bytes);
    let mut by_class: BTreeMap<String, Vec<CodeItem>> = BTreeMap::new();
    for descriptor_name in &dex.class_descriptors {
        by_class.entry(descriptor_name.clone()).or_default();
    }
    for item in items {
        by_class.entry(item.class.clone()).or_default().push(item);
    }

    let mut source: String = String::with_capacity(4096);
    let mut class_count: usize = 0;
    let mut method_count: usize = 0;
    let mut fully_lifted: usize = 0;
    let mut fallback: usize = 0;

    for (class_descriptor, methods) in &by_class {
        let rendered: RenderedClass = render_class(dex, class_descriptor, methods);
        source.push_str(&rendered.text);
        source.push('\n');
        class_count += 1;
        method_count += rendered.method_count;
        fully_lifted += rendered.fully_lifted;
        fallback += rendered.fallback;
    }

    DecompiledDex {
        source,
        class_count,
        method_count,
        fully_lifted_methods: fully_lifted,
        fallback_methods: fallback,
    }
}

struct RenderedClass {
    text: String,
    method_count: usize,
    fully_lifted: usize,
    fallback: usize,
}

fn render_class(dex: &DexFile, class_descriptor: &str, methods: &[CodeItem]) -> RenderedClass {
    let binary: String = descriptor::binary_to_source(class_descriptor);
    let (package, simple): (Option<&str>, &str) = match binary.rfind('.') {
        Some(p) => (Some(&binary[..p]), &binary[p + 1..]),
        None => (None, binary.as_str()),
    };

    let mut text: String = String::with_capacity(1024);
    if let Some(pkg) = package {
        let _ = writeln!(text, "package {pkg};");
        let _ = writeln!(text);
    }
    let _ = writeln!(text, "public class {simple} {{");

    let mut method_count: usize = 0;
    let mut fully_lifted: usize = 0;
    let mut fallback: usize = 0;
    for item in methods {
        let rendered: RenderedMethod = render_method(dex, simple, item);
        let _ = writeln!(text, "{}", rendered.text);
        method_count += 1;
        if rendered.fully_lifted {
            fully_lifted += 1;
        } else {
            fallback += 1;
        }
    }

    let _ = writeln!(text, "}}");
    RenderedClass {
        text,
        method_count,
        fully_lifted,
        fallback,
    }
}

struct RenderedMethod {
    text: String,
    fully_lifted: bool,
}

fn render_method(dex: &DexFile, class_simple: &str, item: &CodeItem) -> RenderedMethod {
    let parsed: Option<MethodDescriptor> = descriptor::parse_method(&item.method_descriptor);
    let footprint: u16 = parsed
        .as_ref()
        .map(|md| {
            md.params
                .iter()
                .map(|p| if p.category_two() { 2u16 } else { 1u16 })
                .sum()
        })
        .unwrap_or(0);
    let is_constructor: bool = item.method_name == "<init>";
    let is_clinit: bool = item.method_name == "<clinit>";
    let is_static: bool = !is_constructor && item.ins_size <= footprint;

    let mut signature: String = String::new();
    let modifier: &str = if is_static {
        "public static "
    } else {
        "public "
    };

    let params: String = match &parsed {
        Some(md) => md
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{} arg{i}", p.render()))
            .collect::<Vec<String>>()
            .join(", "),
        None => String::new(),
    };

    if is_constructor {
        let _ = write!(signature, "    {modifier}{class_simple}({params})");
    } else if is_clinit {
        let _ = write!(signature, "    static");
    } else {
        let ret: String = parsed
            .as_ref()
            .map_or_else(|| "void".to_string(), |md| md.returns.render());
        let _ = write!(
            signature,
            "    {modifier}{ret} {}({params})",
            item.method_name
        );
    }

    let body: MethodBody = lift_method(dex, item, is_static);
    let text: String = format!("{signature} {{\n{}    }}", body.text);
    RenderedMethod {
        text,
        fully_lifted: body.fully_lifted,
    }
}

struct MethodBody {
    text: String,
    fully_lifted: bool,
}

fn lift_method(dex: &DexFile, item: &CodeItem, is_static: bool) -> MethodBody {
    if item.insns.is_empty() {
        return MethodBody {
            text: String::new(),
            fully_lifted: true,
        };
    }
    let Some(built): Option<DalvikMethodCfg> = build_dalvik_cfg_from_code_item(item) else {
        return MethodBody {
            text: "        // <decompile: malformed bytecode>\n".to_string(),
            fully_lifted: false,
        };
    };
    let Ok(dom): Result<Dominators, _> = compute_dominators(&built.cfg) else {
        return flat_fallback(dex, item, is_static, &built);
    };
    let loops: Vec<NaturalLoop> = find_natural_loops(&built.cfg, &dom);
    let mut structurer: Structurer<'_> =
        Structurer::with_switch_map(&built.cfg, &dom, &loops, &[], built.switch_map.clone());
    let root: Region = structurer.structure();

    let ctx: MethodContext<'_> = MethodContext::new(
        dex,
        item.registers_size,
        item.ins_size,
        &item.method_descriptor,
        is_static,
    );
    let mut render: RenderState<'_> = RenderState {
        ctx: &ctx,
        cfg: &built.cfg,
        insns: &built.insns,
        rendered_blocks: std::collections::BTreeSet::new(),
        fully_lifted: !structurer.had_irreducible,
    };
    let mut out: String = String::new();
    render_region(&mut render, &root, &mut out, 2);
    MethodBody {
        text: out,
        fully_lifted: render.fully_lifted,
    }
}

fn flat_fallback(
    dex: &DexFile,
    item: &CodeItem,
    is_static: bool,
    built: &DalvikMethodCfg,
) -> MethodBody {
    let ctx: MethodContext<'_> = MethodContext::new(
        dex,
        item.registers_size,
        item.ins_size,
        &item.method_descriptor,
        is_static,
    );
    let mut file: RegisterFile = RegisterFile::new();
    seed_block_registers(&ctx, &mut file);
    let mut pending: Option<crate::decompile::Expr> = None;
    let mut out: String = String::new();
    let _ = writeln!(out, "        // irreducible CFG (flat fallback)");
    for insn in &built.insns {
        emit_insn(&ctx, &mut file, insn, &mut pending, &mut out, 2);
    }
    MethodBody {
        text: out,
        fully_lifted: false,
    }
}

struct RenderState<'a> {
    ctx: &'a MethodContext<'a>,
    cfg: &'a Cfg,
    insns: &'a [DalvikInsn],
    rendered_blocks: std::collections::BTreeSet<BlockId>,
    fully_lifted: bool,
}

fn indent_string(level: usize) -> String {
    "    ".repeat(level)
}

fn render_region(state: &mut RenderState<'_>, region: &Region, out: &mut String, level: usize) {
    if out.len() > MAX_RENDER_BYTES {
        return;
    }
    match region {
        Region::Block(bid) => render_block(state, *bid, out, level),
        Region::Sequence(items) => {
            for r in items {
                render_region(state, r, out, level);
            }
        }
        Region::IfThen {
            head, then_body, ..
        } => {
            let cond: String = render_head_condition(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(state, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::IfThenElse {
            head,
            then_body,
            else_body,
            ..
        } => {
            let cond: String = render_head_condition(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(state, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}} else {{");
            render_region(state, else_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::While { header, body, exit } => {
            let cond: String = render_head_condition(state, *header, out, level);
            let negated: bool =
                matches!(exit, Some(e) if header_cond_true_target(state.cfg, *header) == Some(*e));
            let displayed: String = if negated { invert(&cond) } else { cond };
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}while ({displayed}) {{");
            render_region(state, body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::DoWhile { header, body, .. } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}do {{");
            render_block(state, *header, out, level + 1);
            render_region(state, body, out, level + 1);
            let _ = writeln!(out, "{pad}}} while (true);");
        }
        Region::Switch {
            head,
            cases,
            default,
            ..
        } => {
            let subject: String = render_switch_subject(state, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}switch ({subject}) {{");
            for (i, (key, body)) in cases.iter().enumerate() {
                let _ = writeln!(out, "{pad}    case {}:", format_switch_key(key, i));
                render_region(state, body, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            if let Some(def) = default {
                let _ = writeln!(out, "{pad}    default:");
                render_region(state, def, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Try { try_body, handlers } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try {{");
            render_region(state, try_body, out, level + 1);
            for (catch_type, handler_region) in handlers {
                let ty: String = catch_type
                    .as_deref()
                    .map_or_else(|| "Throwable".to_string(), descriptor::binary_to_source);
                let _ = writeln!(out, "{pad}}} catch ({ty} ex) {{");
                render_region(state, handler_region, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Irreducible { blocks } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}// irreducible region");
            for bid in blocks {
                render_block(state, *bid, out, level);
            }
            state.fully_lifted = false;
        }
    }
}

fn block_insn_range(state: &RenderState<'_>, bid: BlockId) -> (usize, usize) {
    let block: &BasicBlock = &state.cfg.blocks[bid.0 as usize];
    block.insn_range
}

fn render_block(state: &mut RenderState<'_>, bid: BlockId, out: &mut String, level: usize) {
    if !state.rendered_blocks.insert(bid) {
        return;
    }
    let (start, end): (usize, usize) = block_insn_range(state, bid);
    let mut file: RegisterFile = RegisterFile::new();
    seed_block_registers(state.ctx, &mut file);
    let mut pending: Option<crate::decompile::Expr> = None;
    for insn in &state.insns[start..end] {
        if insn.is_conditional_branch() || insn.is_unconditional_goto() || insn.is_switch() {
            continue;
        }
        emit_insn(state.ctx, &mut file, insn, &mut pending, out, level);
    }
}

fn render_head_condition(
    state: &mut RenderState<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (start, end): (usize, usize) = block_insn_range(state, head);
    if start == end {
        return "true".to_string();
    }
    let body_end: usize = end - 1;
    let already: bool = !state.rendered_blocks.insert(head);
    let mut file: RegisterFile = RegisterFile::new();
    seed_block_registers(state.ctx, &mut file);
    let mut pending: Option<crate::decompile::Expr> = None;
    for insn in &state.insns[start..body_end] {
        if already {
            let _ = lift_insn(state.ctx, &mut file, insn, &mut pending);
        } else {
            emit_insn(state.ctx, &mut file, insn, &mut pending, out, level);
        }
    }
    let term: &DalvikInsn = &state.insns[body_end];
    render_branch_condition(state.ctx, &file, term)
}

fn render_switch_subject(
    state: &mut RenderState<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (start, end): (usize, usize) = block_insn_range(state, head);
    if start == end {
        return "var0".to_string();
    }
    let body_end: usize = end - 1;
    let already: bool = !state.rendered_blocks.insert(head);
    let mut file: RegisterFile = RegisterFile::new();
    seed_block_registers(state.ctx, &mut file);
    let mut pending: Option<crate::decompile::Expr> = None;
    for insn in &state.insns[start..body_end] {
        if already {
            let _ = lift_insn(state.ctx, &mut file, insn, &mut pending);
        } else {
            emit_insn(state.ctx, &mut file, insn, &mut pending, out, level);
        }
    }
    let term: &DalvikInsn = &state.insns[body_end];
    term.regs
        .first()
        .map(|&r| state.ctx.register_name(r).render())
        .unwrap_or_else(|| "var0".to_string())
}

fn emit_insn(
    ctx: &MethodContext<'_>,
    file: &mut RegisterFile,
    insn: &DalvikInsn,
    pending: &mut Option<crate::decompile::Expr>,
    out: &mut String,
    level: usize,
) {
    let pad: String = indent_string(level);
    match lift_insn(ctx, file, insn, pending) {
        LiftOutcome::Statement(s) => {
            let _ = writeln!(out, "{pad}{s};");
        }
        LiftOutcome::None => {}
    }
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

fn invert(cond: &str) -> String {
    if let Some(rest) = cond.strip_prefix('!') {
        return rest.to_string();
    }
    if cond.contains(" == ") {
        return cond.replacen(" == ", " != ", 1);
    }
    if cond.contains(" != ") {
        return cond.replacen(" != ", " == ", 1);
    }
    if cond.contains(" <= ") {
        return cond.replacen(" <= ", " > ", 1);
    }
    if cond.contains(" >= ") {
        return cond.replacen(" >= ", " < ", 1);
    }
    if cond.contains(" < ") {
        return cond.replacen(" < ", " >= ", 1);
    }
    if cond.contains(" > ") {
        return cond.replacen(" > ", " <= ", 1);
    }
    format!("!({cond})")
}

pub fn decompile_dex_bytes(bytes: &[u8]) -> crate::error::Result<DecompiledDex> {
    let dex: DexFile = crate::dex::parse(bytes)?;
    Ok(decompile_dex(&dex, bytes))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
    const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");

    fn decompiled() -> DecompiledDex {
        let dex: DexFile = crate::dex::parse(EDGECASES_DEX).expect("parse edgecases.dex");
        decompile_dex(&dex, EDGECASES_DEX)
    }

    #[test]
    fn gcd_body_has_modulo_and_loop() {
        let out: DecompiledDex = decompiled();
        let src: &str = &out.source;
        let start: usize = src.find("int gcd(").expect("gcd present");
        let slice: &str = &src[start..(start + 400).min(src.len())];
        assert!(slice.contains('%'), "gcd body must contain %: {slice}");
        assert!(
            slice.contains("while"),
            "gcd body must contain a loop: {slice}"
        );
        assert!(
            slice.contains("Math.abs"),
            "gcd body must reference Math.abs: {slice}"
        );
    }

    #[test]
    fn dotint_body_has_array_index_and_loop() {
        let out: DecompiledDex = decompiled();
        let src: &str = &out.source;
        let start: usize = src.find("int dotInt(").expect("dotInt present");
        let slice: &str = &src[start..(start + 500).min(src.len())];
        assert!(slice.contains('['), "dotInt must index arrays: {slice}");
        assert!(slice.contains("while"), "dotInt must loop: {slice}");
    }

    #[test]
    fn kotlin_dex_emits_without_panic() {
        let dex: DexFile = crate::dex::parse(EDGECASES_KT_DEX).expect("parse edgecases kt dex");
        let out: DecompiledDex = decompile_dex(&dex, EDGECASES_KT_DEX);
        assert!(out.class_count > 0, "kotlin dex must yield classes");
    }
}
