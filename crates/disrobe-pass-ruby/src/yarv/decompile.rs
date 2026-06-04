//! Surface decompiler for the YARV stack machine, driven by the decoded IBF iseq stream.
//!
//! Runs a lightweight abstract stack over each iseq body: `putobject`/`putstring`/`putself`/
//! `putnil`/`duparray` push values, `opt_send_without_block`/`send`/`opt_*` arithmetic fold the
//! receiver and arguments into a `recv.method(args)` expression, `branchunless`/`branchif`
//! surface as `if`/`unless` guards, `definemethod`/`defineclass` surface as `def`/`class`, and
//! `leave` returns the stack top. Constructs that are genuinely ambiguous on the stream are
//! rendered as faithful structured expressions rather than fabricated.

use core::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::yarv::ibf::{IbfImage, IbfObjectKind, YarvIbfInstruction, YarvIseqBody, YarvOperand};

const MAX_STACK: usize = 8192;
const MAX_EXPR_LEN: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvDecompiled {
    pub source: String,
    pub statement_count: u32,
    pub fidelity: Fidelity,
    pub recovered_strings: Vec<String>,
    pub recovered_symbols: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fidelity {
    Lossy,
    StructuralOnly,
    LiteralPoolOnly,
}

#[must_use]
pub fn decompile_from_ibf(image: &IbfImage) -> YarvDecompiled {
    let mut recovered_strings: Vec<String> = Vec::new();
    let mut recovered_symbols: Vec<String> = Vec::new();
    for obj in &image.objects {
        match (obj.kind, obj.literal.as_ref()) {
            (IbfObjectKind::String | IbfObjectKind::Regexp, Some(text)) => {
                recovered_strings.push(text.clone());
            }
            (IbfObjectKind::Symbol, Some(text)) => recovered_symbols.push(text.clone()),
            _ => {}
        }
    }

    let mut out: String = String::with_capacity(512);
    out.push_str("# YARV IBF decompile (clean-room iseq opcode-body lifting)\n");

    let mut statement_count: u32 = 0;
    let fidelity: Fidelity = if image.iseqs.iter().any(|b| !b.instructions.is_empty()) {
        for body in &image.iseqs {
            let label: &str = if body.index == 0 { "<main>" } else { "<iseq>" };
            let stmts: Vec<String> = decompile_body(body);
            let _: core::result::Result<(), core::fmt::Error> = writeln!(
                out,
                "# iseq {} ({}): {} instruction(s)",
                body.index,
                label,
                body.instructions.len()
            );
            for stmt in &stmts {
                out.push_str(stmt);
                out.push('\n');
                statement_count = statement_count.saturating_add(1);
            }
        }
        Fidelity::StructuralOnly
    } else {
        out.push_str("# (no iseq bodies decoded; reporting literal pool)\n");
        Fidelity::LiteralPoolOnly
    };

    push_section(&mut out, "string literals", &recovered_strings);
    push_section(&mut out, "symbols", &recovered_symbols);

    YarvDecompiled {
        source: out,
        statement_count,
        fidelity,
        recovered_strings,
        recovered_symbols,
    }
}

/// `VM_ENV_DATA_SIZE` in `vm_core.h`: the fixed environment slots a `getlocal`/`setlocal` operand
/// is biased by before it indexes the local table.
const VM_ENV_DATA_SIZE: u64 = 3;

fn decompile_body(body: &YarvIseqBody) -> Vec<String> {
    let mut stack: Vec<String> = Vec::with_capacity(32);
    let mut stmts: Vec<String> = Vec::new();
    for instr in &body.instructions {
        step(instr, &body.local_table, &mut stack, &mut stmts);
    }
    stmts
}

/// Resolve a `getlocal`/`setlocal` operand to its source name via the body's `local_table`. YARV
/// erases names to environment offsets; when the dump preserved the table (non-hidden locals) the
/// slot index is `local_table_size - (operand - VM_ENV_DATA_SIZE) - 1` (`local_var_name` in
/// `iseq.c`). Falls back to `local{N}` when the table is absent or the slot is hidden.
fn local_name(local_table: &[Option<String>], operand: u64) -> String {
    let size: u64 = local_table.len() as u64;
    let resolved: Option<&str> = operand
        .checked_sub(VM_ENV_DATA_SIZE)
        .and_then(|op| size.checked_sub(op))
        .and_then(|n| n.checked_sub(1))
        .and_then(|idx| usize::try_from(idx).ok())
        .and_then(|idx| local_table.get(idx))
        .and_then(Option::as_deref);
    resolved.map_or_else(|| format!("local{operand}"), str::to_owned)
}

#[allow(clippy::match_same_arms)]
fn step(
    instr: &YarvIbfInstruction,
    local_table: &[Option<String>],
    stack: &mut Vec<String>,
    stmts: &mut Vec<String>,
) {
    let m: &str = instr.mnemonic.as_str();
    match m {
        "putnil" => push(stack, "nil".to_owned()),
        "putself" => push(stack, "self".to_owned()),
        "putobject"
        | "putstring"
        | "putchilledstring"
        | "duparray"
        | "duphash"
        | "opt_getconstant_path" => {
            push(stack, operand_value(instr, 0));
        }
        "putobject_INT2FIX_0_" => push(stack, "0".to_owned()),
        "putobject_INT2FIX_1_" => push(stack, "1".to_owned()),
        "getlocal" | "getlocal_WC_0" | "getlocal_WC_1" => {
            push(stack, local_name(local_table, operand_num(instr, 0)));
        }
        "getinstancevariable" => push(stack, ivar_name(instr, 0)),
        "getglobal" => push(stack, id_or_index(instr, 0)),
        "getconstant" => push(stack, id_or_index(instr, 0)),
        "newarray" => {
            let n: usize = operand_num(instr, 0) as usize;
            let elems: Vec<String> = pop_n(stack, n);
            push(stack, format!("[{}]", elems.join(", ")));
        }
        "newhash" => {
            let n: usize = operand_num(instr, 0) as usize;
            let _ = pop_n(stack, n);
            push(stack, "{...}".to_owned());
        }
        "concatstrings" => {
            let n: usize = operand_num(instr, 0) as usize;
            let parts: Vec<String> = pop_n(stack, n);
            push(stack, render_interpolation(&parts));
        }
        "opt_send_without_block" | "send" | "invokesuper" | "sendforward" => {
            emit_send(instr, stack);
        }
        "opt_str_freeze" | "opt_str_uminus" | "opt_nil_p" => {
            emit_unary_call(instr, stack);
        }
        "objtostring" => {}
        "anytostring" => collapse_interp_coercion(stack),
        "opt_plus" => emit_binop(instr, stack, "+"),
        "opt_minus" => emit_binop(instr, stack, "-"),
        "opt_mult" => emit_binop(instr, stack, "*"),
        "opt_div" => emit_binop(instr, stack, "/"),
        "opt_mod" => emit_binop(instr, stack, "%"),
        "opt_eq" => emit_binop(instr, stack, "=="),
        "opt_neq" => emit_binop(instr, stack, "!="),
        "opt_lt" => emit_binop(instr, stack, "<"),
        "opt_le" => emit_binop(instr, stack, "<="),
        "opt_gt" => emit_binop(instr, stack, ">"),
        "opt_ge" => emit_binop(instr, stack, ">="),
        "opt_ltlt" => emit_binop(instr, stack, "<<"),
        "opt_aref" => {
            let idx: String = pop(stack);
            let recv: String = pop(stack);
            push(stack, format!("{recv}[{idx}]"));
        }
        "setlocal" | "setlocal_WC_0" | "setlocal_WC_1" => {
            let v: String = pop(stack);
            stmts.push(format!(
                "{} = {v}",
                local_name(local_table, operand_num(instr, 0))
            ));
        }
        "setinstancevariable" => {
            let v: String = pop(stack);
            stmts.push(format!("{} = {v}", ivar_name(instr, 0)));
        }
        "setglobal" => {
            let v: String = pop(stack);
            stmts.push(format!("{} = {v}", id_or_index(instr, 0)));
        }
        "setconstant" => {
            let v: String = pop(stack);
            let name: String = id_or_index(instr, 0);
            let _ = pop(stack);
            stmts.push(format!("{name} = {v}"));
        }
        "definemethod" => {
            let name: String = id_or_index(instr, 0);
            stmts.push(format!("def {name}; ...; end"));
            push(stack, format!(":{name}"));
        }
        "definesmethod" => {
            let name: String = id_or_index(instr, 0);
            stmts.push(format!("def self.{name}; ...; end"));
            push(stack, format!(":{name}"));
        }
        "defineclass" => {
            let name: String = id_or_index(instr, 0);
            let keyword: &str = match operand_num(instr, 2) & 7 {
                1 => "class <<",
                2 => "module",
                _ => "class",
            };
            stmts.push(format!("{keyword} {name}; ...; end"));
            push(stack, name);
        }
        "branchunless" => {
            let cond: String = pop(stack);
            stmts.push(format!("if {cond}"));
        }
        "branchif" => {
            let cond: String = pop(stack);
            stmts.push(format!("unless {cond}"));
        }
        "branchnil" => {
            let cond: String = pop(stack);
            stmts.push(format!("{cond}&. ..."));
        }
        "leave" => {
            if let Some(top) = stack.last() {
                stmts.push(format!("return {top}"));
            }
        }
        "pop" => {
            if let Some(top) = stack.pop()
                && is_effecting_call(&top)
            {
                stmts.push(top);
            }
        }
        "dup" => {
            if let Some(top) = stack.last().cloned() {
                push(stack, top);
            }
        }
        "nop" | "putspecialobject" | "intern" | "tostring" => {}
        _ => {}
    }
}

/// Collapse the YARV string-interpolation coercion idiom `dup; objtostring; anytostring`: the `dup`
/// left two copies of the interpolated value and `objtostring` is treated as identity, so
/// `anytostring` discards the spare copy, leaving one expression to feed `concatstrings`.
fn collapse_interp_coercion(stack: &mut Vec<String>) {
    if stack.len() >= 2 {
        let top: String = pop(stack);
        let below: String = pop(stack);
        push(stack, if top == below { top } else { below });
    }
}

/// Reconstruct a `concatstrings` join. When the parts mix quoted string literals with expressions
/// the result is a Ruby interpolation `"text#{expr}text"`; a single part passes through unchanged;
/// an all-expression join (no literal anchor) falls back to a `+` concatenation so nothing is
/// fabricated.
fn render_interpolation(parts: &[String]) -> String {
    match parts {
        [] => "\"\"".to_owned(),
        [single] => single.clone(),
        _ => {
            let has_literal: bool = parts.iter().any(|p| is_string_literal(p));
            if !has_literal {
                return parts.join(" + ");
            }
            let mut out: String = String::with_capacity(MAX_EXPR_LEN.min(128));
            out.push('"');
            for part in parts {
                if let Some(body) = string_literal_body(part) {
                    out.push_str(body);
                } else {
                    out.push_str("#{");
                    out.push_str(part);
                    out.push('}');
                }
            }
            out.push('"');
            out
        }
    }
}

#[inline]
fn is_string_literal(s: &str) -> bool {
    string_literal_body(s).is_some()
}

/// The inner text of a Rust-`Debug`-rendered string literal (`"..."`), or `None` when `s` is not a
/// plain double-quoted literal (e.g. an expression, or a literal containing nested quotes/escapes
/// that would be unsafe to splice verbatim into an interpolation).
fn string_literal_body(s: &str) -> Option<&str> {
    let inner: &str = s.strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('"') || inner.contains('\\') || inner.contains("#{") {
        return None;
    }
    Some(inner)
}

fn emit_send(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let (method, argc): (String, usize) = match instr.operands.first() {
        Some(YarvOperand::Call { method, argc }) => (method.clone(), *argc as usize),
        Some(YarvOperand::Id(name)) => (name.clone(), 0),
        _ => ("call".to_owned(), 0),
    };
    let args: Vec<String> = pop_n(stack, argc);
    let recv: String = pop(stack);
    let call: String = render_method_call(&recv, &method, &args);
    push(stack, call);
}

fn emit_unary_call(instr: &YarvIbfInstruction, stack: &mut Vec<String>) {
    let method: String = match instr.operands.first() {
        Some(YarvOperand::Call { method, .. }) => method.clone(),
        _ => return,
    };
    let recv: String = pop(stack);
    push(stack, render_method_call(&recv, &method, &[]));
}

fn render_method_call(recv: &str, method: &str, args: &[String]) -> String {
    let prefix: String = if recv == "self" {
        String::new()
    } else {
        format!("{recv}.")
    };
    if args.is_empty() {
        format!("{prefix}{method}")
    } else {
        format!("{prefix}{method}({})", args.join(", "))
    }
}

fn emit_binop(_instr: &YarvIbfInstruction, stack: &mut Vec<String>, op: &str) {
    let rhs: String = pop(stack);
    let lhs: String = pop(stack);
    push(stack, format!("{lhs} {op} {rhs}"));
}

fn is_effecting_call(expr: &str) -> bool {
    expr.contains('(') || expr.contains('.')
}

#[inline]
fn push(stack: &mut Vec<String>, v: String) {
    if stack.len() < MAX_STACK {
        let bounded: String = if v.len() > MAX_EXPR_LEN {
            "(...)".to_owned()
        } else {
            v
        };
        stack.push(bounded);
    }
}

#[inline]
fn pop(stack: &mut Vec<String>) -> String {
    stack.pop().unwrap_or_else(|| "_".to_owned())
}

fn pop_n(stack: &mut Vec<String>, n: usize) -> Vec<String> {
    let take: usize = n.min(stack.len());
    let mut out: Vec<String> = stack.split_off(stack.len() - take);
    if out.len() < n {
        let mut pad: Vec<String> = vec!["_".to_owned(); n - out.len()];
        pad.append(&mut out);
        out = pad;
    }
    out
}

fn operand_value(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Literal(s)) => format!("{s:?}"),
        Some(YarvOperand::Id(s)) => format!(":{s}"),
        Some(YarvOperand::ObjectRef(i)) => format!("obj[{i}]"),
        Some(YarvOperand::IseqRef(i)) => format!("iseq[{i}]"),
        Some(YarvOperand::Num(n)) => n.to_string(),
        Some(YarvOperand::Offset(o)) => format!("->{o}"),
        Some(YarvOperand::Builtin(b)) => format!("<builtin {b}>"),
        Some(YarvOperand::Call { method, .. }) => format!(":{method}"),
        None => "_".to_owned(),
    }
}

fn operand_num(instr: &YarvIbfInstruction, idx: usize) -> u64 {
    match instr.operands.get(idx) {
        Some(YarvOperand::Num(n)) => *n,
        Some(YarvOperand::Offset(o)) => u64::from(*o),
        Some(YarvOperand::ObjectRef(i) | YarvOperand::IseqRef(i)) => u64::from(*i),
        _ => 0,
    }
}

fn id_or_index(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) => s.clone(),
        Some(YarvOperand::ObjectRef(i)) => format!("Const{i}"),
        _ => "_".to_owned(),
    }
}

/// Instance-variable name from an operand whose symbol already carries its `@` sigil; falls back
/// to prefixing when an `ObjectRef` index could not resolve.
fn ivar_name(instr: &YarvIbfInstruction, idx: usize) -> String {
    match instr.operands.get(idx) {
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) if s.starts_with('@') => s.clone(),
        Some(YarvOperand::Id(s) | YarvOperand::Literal(s)) => format!("@{s}"),
        _ => "@ivar".to_owned(),
    }
}

fn push_section(out: &mut String, title: &str, items: &[String]) {
    let _: core::result::Result<(), core::fmt::Error> =
        writeln!(out, "# {} ({}):", title, items.len());
    for item in items {
        let _: core::result::Result<(), core::fmt::Error> = writeln!(out, "#   {item:?}");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::yarv::ibf::{
        IbfObject, IbfObjectKind, YarvIbfInstruction, YarvIseqBody, YarvOperand,
    };

    fn obj(index: u32, kind: IbfObjectKind, literal: Option<&str>) -> IbfObject {
        IbfObject {
            index,
            offset: 0,
            kind,
            literal: literal.map(str::to_owned),
            element_count: None,
        }
    }

    fn instr(mnemonic: &str, operands: Vec<YarvOperand>) -> YarvIbfInstruction {
        YarvIbfInstruction {
            pc: 0,
            opcode: 0,
            mnemonic: mnemonic.to_owned(),
            operands,
        }
    }

    #[test]
    fn interpolation_reconstructs_from_mixed_parts() {
        let parts: Vec<String> = vec![
            "\"hello, \"".to_owned(),
            "@who".to_owned(),
            "\"!\"".to_owned(),
        ];
        assert_eq!(render_interpolation(&parts), "\"hello, #{@who}!\"");
    }

    #[test]
    fn interpolation_all_expression_parts_fall_back_to_concat() {
        let parts: Vec<String> = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(render_interpolation(&parts), "a + b");
    }

    #[test]
    fn interpolation_single_part_passes_through() {
        assert_eq!(render_interpolation(&["x".to_owned()]), "x");
    }

    #[test]
    fn interp_coercion_idiom_collapses_to_single_expr() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 7,
            local_table: Vec::new(),
            instructions: vec![
                instr(
                    "putobject",
                    vec![YarvOperand::Literal("hello, ".to_owned())],
                ),
                instr(
                    "getinstancevariable",
                    vec![YarvOperand::Id("@who".to_owned())],
                ),
                instr("dup", vec![]),
                instr(
                    "objtostring",
                    vec![YarvOperand::Call {
                        method: "to_s".to_owned(),
                        argc: 0,
                    }],
                ),
                instr("anytostring", vec![]),
                instr("putobject", vec![YarvOperand::Literal("!".to_owned())]),
                instr("concatstrings", vec![YarvOperand::Num(3)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s == "return \"hello, #{@who}!\""),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn recovers_strings_and_symbols_from_pool() {
        let img: IbfImage = IbfImage {
            iseq_offsets: vec![0],
            objects: vec![
                obj(0, IbfObjectKind::String, Some("hello world")),
                obj(1, IbfObjectKind::Symbol, Some("puts")),
            ],
            iseqs: vec![],
            recovered_literal_count: 2,
            recovered_instruction_count: 0,
        };
        let out: YarvDecompiled = decompile_from_ibf(&img);
        assert!(out.recovered_strings.contains(&"hello world".to_owned()));
        assert!(out.recovered_symbols.contains(&"puts".to_owned()));
        assert_eq!(out.fidelity, Fidelity::LiteralPoolOnly);
    }

    #[test]
    fn surfaces_putself_putstring_send_as_method_call() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 4,
            local_table: Vec::new(),
            instructions: vec![
                instr("putself", vec![]),
                instr(
                    "putstring",
                    vec![YarvOperand::Literal("hello world".to_owned())],
                ),
                instr(
                    "opt_send_without_block",
                    vec![YarvOperand::Call {
                        method: "puts".to_owned(),
                        argc: 1,
                    }],
                ),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s.contains("puts(\"hello world\")")),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn local_name_maps_env_offset_through_local_table() {
        let table: Vec<Option<String>> = vec![Some("a".to_owned()), Some("b".to_owned())];
        assert_eq!(local_name(&table, 4), "a");
        assert_eq!(local_name(&table, 3), "b");
        assert_eq!(local_name(&table, 99), "local99");
        assert_eq!(local_name(&[], 3), "local3");
    }

    #[test]
    fn getlocal_setlocal_use_recovered_names() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 4,
            local_table: vec![Some("total".to_owned())],
            instructions: vec![
                instr("putobject", vec![YarvOperand::Num(0)]),
                instr("setlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("getlocal_WC_0", vec![YarvOperand::Num(3)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(stmts.iter().any(|s| s == "total = 0"), "stmts: {stmts:?}");
        assert!(
            stmts.iter().any(|s| s == "return total"),
            "stmts: {stmts:?}"
        );
    }

    #[test]
    fn surfaces_binary_op() {
        let body: YarvIseqBody = YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 4,
            local_table: Vec::new(),
            instructions: vec![
                instr("putobject", vec![YarvOperand::Num(1)]),
                instr("putobject", vec![YarvOperand::Num(2)]),
                instr("opt_plus", vec![YarvOperand::Num(0)]),
                instr("leave", vec![]),
            ],
        };
        let stmts: Vec<String> = decompile_body(&body);
        assert!(
            stmts.iter().any(|s| s.contains("1 + 2")),
            "stmts: {stmts:?}"
        );
    }
}
