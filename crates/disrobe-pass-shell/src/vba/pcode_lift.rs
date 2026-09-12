use serde::Serialize;

use super::pcode_real::{RealModuleDisasm, RealPCodeLine};

const MAX_CALL_ARGS: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct SemanticLift {
    pub module: String,
    pub pseudocode: String,
    pub lifted_lines: usize,
    pub unlifted_lines: usize,
    pub walls: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Procedure,
    If,
    For,
    ForEach,
    Do,
    While,
    With,
    Select,
    Type,
}

struct OpenBlock {
    kind: BlockKind,
    header_out_index: usize,
    inline: bool,
}

#[derive(Debug, Clone)]
struct DeclHead {
    scope: Option<String>,
    is_const: bool,
}

struct Lifter {
    stack: Vec<String>,
    out: Vec<String>,
    indent: usize,
    blocks: Vec<OpenBlock>,
    lifted: usize,
    unlifted: usize,
    walls: Vec<String>,
    pending_decl: Option<DeclHead>,
    printing: bool,
    print_target: String,
    print_items: Vec<String>,
    join_next: Option<&'static str>,
    dim_group: Option<usize>,
}

impl Lifter {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            out: Vec::new(),
            indent: 0,
            blocks: Vec::new(),
            lifted: 0,
            unlifted: 0,
            walls: Vec::new(),
            pending_decl: None,
            printing: false,
            print_target: String::new(),
            print_items: Vec::new(),
            join_next: None,
            dim_group: None,
        }
    }

    fn pop(&mut self) -> String {
        self.stack.pop().unwrap_or_else(|| "<?>".to_owned())
    }

    fn pop_n(&mut self, n: usize) -> Vec<String> {
        let count: usize = n.min(self.stack.len()).min(MAX_CALL_ARGS);
        let mut args: Vec<String> = Vec::with_capacity(count);
        for _ in 0..count {
            args.push(self.pop());
        }
        args.reverse();
        args
    }

    fn emit(&mut self, stmt: String) {
        if let Some(separator) = self.join_next.take()
            && let Some(previous) = self.out.last_mut()
        {
            previous.push_str(separator);
            previous.push_str(&stmt);
            return;
        }
        let pad: String = "    ".repeat(self.indent);
        self.out.push(format!("{pad}{stmt}"));
    }

    fn open(&mut self, kind: BlockKind, header: String) {
        self.emit(header);
        let header_out_index: usize = self.out.len().saturating_sub(1);
        self.blocks.push(OpenBlock {
            kind,
            header_out_index,
            inline: false,
        });
        self.indent += 1;
    }

    fn close(&mut self, footer: String) {
        if self.indent > 0 {
            self.indent -= 1;
        }
        self.blocks.pop();
        self.emit(footer);
    }

    fn relabel_procedure(&mut self, keyword: &str) {
        let Some(block): Option<&OpenBlock> = self.blocks.last() else {
            return;
        };
        if block.kind != BlockKind::Procedure {
            return;
        }
        let header_index: usize = block.header_out_index;
        if let Some(header) = self.out.get_mut(header_index) {
            *header = header.replacen("Sub ", &format!("{keyword} "), 1);
        }
    }

    fn relabel_block(&mut self, from: &str, to: &str) {
        let Some(block): Option<&OpenBlock> = self.blocks.last() else {
            return;
        };
        let header_index: usize = block.header_out_index;
        if let Some(header) = self.out.get_mut(header_index) {
            *header = header.replacen(from, to, 1);
        }
    }

    fn flush_print(&mut self) {
        if !self.printing {
            return;
        }
        self.printing = false;
        let items: Vec<String> = std::mem::take(&mut self.print_items);
        let target: String = std::mem::take(&mut self.print_target);
        if items.is_empty() {
            self.emit(target);
        } else {
            self.emit(format!("{target} {}", items.join("; ")));
        }
    }
}

#[must_use]
fn parse_mnemonic(text: &str) -> (&str, &str) {
    match text.split_once(char::is_whitespace) {
        Some((head, rest)) => (head, rest.trim()),
        None => (text, ""),
    }
}

#[must_use]
fn first_operand(rest: &str) -> &str {
    rest.split_whitespace().next().unwrap_or("")
}

#[must_use]
fn quoted_payload(rest: &str) -> Option<String> {
    let start: usize = rest.find('"')?;
    let end: usize = rest.rfind('"')?;
    if end > start {
        Some(rest[start..=end].to_owned())
    } else {
        None
    }
}

#[must_use]
fn vba_string_literal(rest: &str) -> String {
    let Some(payload): Option<String> = quoted_payload(rest) else {
        return "\"\"".to_owned();
    };
    let inner: &str = payload
        .strip_prefix('"')
        .and_then(|s: &str| s.strip_suffix('"'))
        .unwrap_or(payload.as_str());
    format!("\"{}\"", inner.replace('"', "\"\""))
}

#[must_use]
fn call_arg_count(rest: &str) -> usize {
    rest.split_whitespace()
        .find_map(|tok: &str| {
            tok.strip_prefix("0x")
                .and_then(|hex: &str| u32::from_str_radix(hex, 16).ok())
        })
        .unwrap_or(0) as usize
}

#[must_use]
fn join_args(args: &[String]) -> String {
    args.join(", ")
}

#[must_use]
fn call_args_text(args: &[String]) -> String {
    format!("({})", join_args(args))
}

#[must_use]
fn member_target(base: String, name: &str, is_with: bool) -> String {
    if is_with {
        format!(".{name}")
    } else {
        format!("{base}.{name}")
    }
}

#[must_use]
fn dict_target(base: String, name: &str, is_with: bool) -> String {
    if is_with {
        format!("!{name}")
    } else {
        format!("{base}!{name}")
    }
}

#[must_use]
fn parse_decl_head(rest: &str) -> DeclHead {
    let inner: &str = rest.trim().trim_start_matches('(').trim_end_matches(')');
    let mut scope: Option<String> = None;
    let mut is_const: bool = false;
    for tok in inner.split_whitespace() {
        match tok {
            "Const" => is_const = true,
            "Public" | "Private" | "Global" | "Static" => scope = Some(tok.to_owned()),
            _ => {}
        }
    }
    DeclHead { scope, is_const }
}

#[must_use]
fn decl_keyword(head: &DeclHead) -> String {
    match (head.scope.as_deref(), head.is_const) {
        (Some(s), true) => format!("{s} Const"),
        (Some(s), false) => s.to_owned(),
        (None, true) => "Const".to_owned(),
        (None, false) => "Dim".to_owned(),
    }
}

#[must_use]
fn vardefn_type_suffix(paren: &str) -> String {
    let outer: &str = paren.trim();
    let inner: &str = outer.strip_prefix('(').unwrap_or(outer);
    let p: &str = inner.strip_suffix(')').unwrap_or(inner).trim();
    if p.is_empty() {
        return String::new();
    }
    if let Some(r) = p.strip_prefix("New As ") {
        return format!(" As New {r}");
    }
    if let Some(r) = p.strip_prefix("New ") {
        return format!(" As New {r}");
    }
    if let Some(r) = p.strip_prefix("As ") {
        return format!(" As {r}");
    }
    format!(" {p}")
}

#[must_use]
fn parse_vardefn(rest: &str) -> (String, String) {
    let trimmed: &str = rest.trim();
    let Some(i): Option<usize> = trimmed.find('(') else {
        return (trimmed.to_owned(), String::new());
    };
    let name: String = trimmed[..i].trim().to_owned();
    let suffix: String = vardefn_type_suffix(&trimmed[i..]);
    match suffix.strip_suffix("()") {
        Some(element) => (format!("{name}()"), element.to_owned()),
        None => (name, suffix),
    }
}

#[must_use]
fn format_redim_bounds(vals: &[String], dims: usize) -> String {
    if dims > 0 && vals.len() == dims.saturating_mul(2) {
        vals.chunks_exact(2)
            .map(|c: &[String]| format!("{} To {}", c[0], c[1]))
            .collect::<Vec<String>>()
            .join(", ")
    } else {
        vals.join(", ")
    }
}

fn emit_assignment(l: &mut Lifter, target: String, value: String, object_set: bool) {
    if object_set {
        l.emit(format!("Set {target} = {value}"));
    } else {
        l.emit(format!("{target} = {value}"));
    }
}

fn indexed_named_target(l: &mut Lifter, name: &str, argc: usize) -> String {
    let args: Vec<String> = l.pop_n(argc);
    format!("{name}{}", call_args_text(&args))
}

fn indexed_member_target(l: &mut Lifter, name: &str, argc: usize, is_with: bool) -> String {
    let base: String = if is_with { String::new() } else { l.pop() };
    let args: Vec<String> = l.pop_n(argc);
    format!(
        "{}{}",
        member_target(base, name, is_with),
        call_args_text(&args)
    )
}

fn indexed_dict_target(l: &mut Lifter, name: &str, argc: usize, is_with: bool) -> String {
    let base: String = if is_with { String::new() } else { l.pop() };
    let args: Vec<String> = l.pop_n(argc);
    format!(
        "{}{}",
        dict_target(base, name, is_with),
        call_args_text(&args)
    )
}

fn binary(l: &mut Lifter, op: &str) {
    let rhs: String = l.pop();
    let lhs: String = l.pop();
    l.stack.push(format!("{lhs} {op} {rhs}"));
}

fn unary_prefix(l: &mut Lifter, op: &str) {
    let v: String = l.pop();
    l.stack.push(format!("{op}{v}"));
}

fn lift_line(l: &mut Lifter, line: &RealPCodeLine) {
    l.pending_decl = None;
    l.join_next = None;
    l.dim_group = None;
    let produced_before: usize = l.out.len();
    let mut saw_known: bool = false;
    for raw in line.text.lines() {
        let (mnem, rest): (&str, &str) = parse_mnemonic(raw.trim());
        if mnem.is_empty() {
            continue;
        }
        saw_known |= apply(l, mnem, rest, line);
    }
    if l.printing {
        l.flush_print();
    }
    let trailing_comment: Option<String> = match l.stack.as_slice() {
        [only] if l.out.len() > produced_before && only.starts_with('\'') => Some(only.clone()),
        _ => None,
    };
    if let Some(comment) = trailing_comment
        && let Some(last) = l.out.last_mut()
        && !last.trim().is_empty()
    {
        last.push_str("  ");
        last.push_str(&comment);
        l.stack.clear();
    }
    if l.stack.len() == 1 && l.out.len() == produced_before {
        let expr: String = l.pop();
        if !expr.is_empty() && expr != "<?>" {
            l.emit(expr);
        }
    }
    if saw_known {
        l.lifted += 1;
    } else if !line.text.trim().is_empty() && !line.text.contains("<empty>") {
        l.unlifted += 1;
    }
    l.stack.clear();
}

fn apply(l: &mut Lifter, mnem: &str, rest: &str, line: &RealPCodeLine) -> bool {
    match mnem {
        "LitStr" | "QuoteRem" | "Rem" => {
            if mnem == "Rem" || mnem == "QuoteRem" {
                let body: String = quoted_payload(rest).unwrap_or_default();
                let inner: &str = body.trim_matches('"');
                l.stack.push(format!("'{inner}"));
            } else {
                l.stack.push(vba_string_literal(rest));
            }
            true
        }
        "LitDI2" | "LitDI4" | "LitDI8" | "LitHI2" | "LitHI4" | "LitHI8" | "LitOI2" | "LitOI4"
        | "LitOI8" | "LitR4" | "LitR8" | "LitCy" | "LitDate" | "LitSmallI2" => {
            l.stack.push(lit_number(mnem, rest));
            true
        }
        "LitVarSpecial" => {
            let inner: &str = rest
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim();
            l.stack.push(if inner.is_empty() {
                "Empty".to_owned()
            } else {
                inner.to_owned()
            });
            true
        }
        "LitNothing" => {
            l.stack.push("Nothing".to_owned());
            true
        }
        "LitDefault" => {
            l.stack.push(String::new());
            true
        }
        "ArgsArray" => {
            let name: &str = first_operand(rest);
            let argc: usize = call_arg_count(rest);
            let args: Vec<String> = l.pop_n(argc);
            l.stack.push(format!("{name}({})", join_args(&args)));
            true
        }
        "New" => {
            l.stack.push(format!("New {}", first_operand(rest)));
            true
        }
        "Sharp" => {
            let v: String = l.pop();
            l.stack.push(format!("#{v}"));
            true
        }
        "Ld" | "LdLHS" | "LdAddressOf" => {
            l.stack.push(first_operand(rest).to_owned());
            true
        }
        "MemLd" | "MemLdWith" | "DictLd" | "DictLdWith" => {
            let name: &str = first_operand(rest);
            let is_with: bool = mnem == "MemLdWith" || mnem == "DictLdWith";
            let base: String = if is_with { String::new() } else { l.pop() };
            let target: String = if mnem == "DictLd" || mnem == "DictLdWith" {
                dict_target(base, name, is_with)
            } else {
                member_target(base, name, is_with)
            };
            l.stack.push(target);
            true
        }
        "Me" | "MeImplicit" => {
            l.stack.push("Me".to_owned());
            true
        }
        "ArgsLd" | "ArgsMemLd" | "ArgsMemLdWith" | "ArgsDictLd" | "ArgsDictLdWith" => {
            let name: &str = first_operand(rest);
            let argc: usize = call_arg_count(rest);
            let target: String = match mnem {
                "ArgsMemLd" => indexed_member_target(l, name, argc, false),
                "ArgsMemLdWith" => indexed_member_target(l, name, argc, true),
                "ArgsDictLd" => indexed_dict_target(l, name, argc, false),
                "ArgsDictLdWith" => indexed_dict_target(l, name, argc, true),
                _ => indexed_named_target(l, name, argc),
            };
            l.stack.push(target);
            true
        }
        "IndexLd" => {
            let argc: usize = call_arg_count(rest).max(1);
            let args: Vec<String> = l.pop_n(argc);
            let base: String = l.pop();
            l.stack.push(format!("{base}({})", join_args(&args)));
            true
        }
        "Add" => {
            binary(l, "+");
            true
        }
        "Sub" => {
            binary(l, "-");
            true
        }
        "Mul" => {
            binary(l, "*");
            true
        }
        "Div" => {
            binary(l, "/");
            true
        }
        "IDiv" => {
            binary(l, "\\");
            true
        }
        "Mod" => {
            binary(l, "Mod");
            true
        }
        "Pwr" => {
            binary(l, "^");
            true
        }
        "Concat" => {
            binary(l, "&");
            true
        }
        "And" => {
            binary(l, "And");
            true
        }
        "Or" => {
            binary(l, "Or");
            true
        }
        "Xor" => {
            binary(l, "Xor");
            true
        }
        "Eqv" => {
            binary(l, "Eqv");
            true
        }
        "Imp" => {
            binary(l, "Imp");
            true
        }
        "Eq" => {
            binary(l, "=");
            true
        }
        "Ne" => {
            binary(l, "<>");
            true
        }
        "Le" => {
            binary(l, "<=");
            true
        }
        "Ge" => {
            binary(l, ">=");
            true
        }
        "Lt" => {
            binary(l, "<");
            true
        }
        "Gt" => {
            binary(l, ">");
            true
        }
        "Like" => {
            binary(l, "Like");
            true
        }
        "Is" => {
            binary(l, "Is");
            true
        }
        "Not" => {
            unary_prefix(l, "Not ");
            true
        }
        "UMi" => {
            unary_prefix(l, "-");
            true
        }
        "Paren" => {
            let v: String = l.pop();
            l.stack.push(format!("({v})"));
            true
        }
        "FnAbs" | "FnFix" | "FnInt" | "FnSgn" | "FnLen" | "FnLenB" => {
            let v: String = l.pop();
            let fname: &str = mnem.strip_prefix("Fn").unwrap_or(mnem);
            l.stack.push(format!("{fname}({v})"));
            true
        }
        "FnLBound" | "FnUBound" => {
            let fname: &str = if mnem == "FnLBound" {
                "LBound"
            } else {
                "UBound"
            };
            if call_arg_count(rest) > 0 {
                let dim: String = l.pop();
                let arr: String = l.pop();
                l.stack.push(format!("{fname}({arr}, {dim})"));
            } else {
                let arr: String = l.pop();
                l.stack.push(format!("{fname}({arr})"));
            }
            true
        }
        "St" | "SetOrSt" => {
            let value: String = l.pop();
            let target: &str = first_operand(rest);
            l.emit(format!("{target} = {value}"));
            true
        }
        "MemSt" | "DictSt" | "MemStWith" | "DictStWith" => {
            let name: &str = first_operand(rest);
            let is_with: bool = mnem == "MemStWith" || mnem == "DictStWith";
            let base: String = if is_with { String::new() } else { l.pop() };
            let value: String = l.pop();
            let target: String = if mnem == "DictSt" || mnem == "DictStWith" {
                dict_target(base, name, is_with)
            } else {
                member_target(base, name, is_with)
            };
            emit_assignment(l, target, value, false);
            true
        }
        "IndexSt" | "Indexset" => {
            let argc: usize = call_arg_count(rest).max(1);
            let args: Vec<String> = l.pop_n(argc);
            let base: String = l.pop();
            let value: String = l.pop();
            let target: String = format!("{base}{}", call_args_text(&args));
            emit_assignment(l, target, value, mnem == "Indexset");
            true
        }
        "Set" => {
            let value: String = l.pop();
            let target: &str = first_operand(rest);
            l.emit(format!("Set {target} = {value}"));
            true
        }
        "Memset" | "Dictset" | "MemSetWith" | "DictSetWith" => {
            let name: &str = first_operand(rest);
            let is_with: bool = mnem == "MemSetWith" || mnem == "DictSetWith";
            let base: String = if is_with { String::new() } else { l.pop() };
            let value: String = l.pop();
            let target: String = if mnem == "Dictset" || mnem == "DictSetWith" {
                dict_target(base, name, is_with)
            } else {
                member_target(base, name, is_with)
            };
            emit_assignment(l, target, value, true);
            true
        }
        "ArgsSt" | "ArgsMemSt" | "ArgsDictSt" | "ArgsMemStWith" | "ArgsDictStWith" | "ArgsSet"
        | "ArgsMemSet" | "ArgsDictSet" | "ArgsMemSetWith" | "ArgsDictSetWith" => {
            let name: &str = first_operand(rest);
            let argc: usize = call_arg_count(rest);
            let target: String = match mnem {
                "ArgsMemSt" | "ArgsMemSet" => indexed_member_target(l, name, argc, false),
                "ArgsMemStWith" | "ArgsMemSetWith" => indexed_member_target(l, name, argc, true),
                "ArgsDictSt" | "ArgsDictSet" => indexed_dict_target(l, name, argc, false),
                "ArgsDictStWith" | "ArgsDictSetWith" => indexed_dict_target(l, name, argc, true),
                _ => indexed_named_target(l, name, argc),
            };
            let value: String = l.pop();
            let object_set: bool = matches!(
                mnem,
                "ArgsSet" | "ArgsMemSet" | "ArgsDictSet" | "ArgsMemSetWith" | "ArgsDictSetWith"
            );
            emit_assignment(l, target, value, object_set);
            true
        }
        "ArgsCall" | "ArgsMemCall" | "ArgsMemCallWith" => {
            let name: &str = first_operand(rest);
            let argc: usize = call_arg_count(rest);
            let base: String = if mnem == "ArgsMemCall" {
                l.pop()
            } else {
                String::new()
            };
            let args: Vec<String> = l.pop_n(argc);
            let prefix: String = match mnem {
                "ArgsMemCallWith" => format!(".{name}"),
                "ArgsMemCall" => format!("{base}.{name}"),
                _ => name.to_owned(),
            };
            if args.is_empty() {
                l.emit(prefix);
            } else {
                l.emit(format!("{prefix} {}", join_args(&args)));
            }
            true
        }
        "FuncDefn" | "FuncDefnSave" => {
            let header: String = signature_header(line);
            l.open(BlockKind::Procedure, header);
            true
        }
        "EndSub" => {
            l.close("End Sub".to_owned());
            true
        }
        "EndFunc" => {
            l.relabel_procedure("Function");
            l.close("End Function".to_owned());
            true
        }
        "EndProp" => {
            l.relabel_procedure("Property");
            l.close("End Property".to_owned());
            true
        }
        "If" | "IfBlock" => {
            let cond: String = l.pop();
            l.open(BlockKind::If, format!("If {cond} Then"));
            true
        }
        "Else" | "ElseBlock" => {
            if l.indent > 0 {
                l.indent -= 1;
            }
            l.emit("Else".to_owned());
            l.indent += 1;
            true
        }
        "ElseIfBlock" => {
            let cond: String = l.pop();
            if l.indent > 0 {
                l.indent -= 1;
            }
            l.emit(format!("ElseIf {cond} Then"));
            l.indent += 1;
            true
        }
        "EndIf" | "EndIfBlock" => {
            if l.blocks
                .last()
                .is_some_and(|b: &OpenBlock| b.kind == BlockKind::If && b.inline)
            {
                l.blocks.pop();
                if l.indent > 0 {
                    l.indent -= 1;
                }
            } else {
                l.close("End If".to_owned());
            }
            true
        }
        "For" | "ForStep" => {
            let step: String = if mnem == "ForStep" {
                let s: String = l.pop();
                format!(" Step {s}")
            } else {
                String::new()
            };
            let limit: String = l.pop();
            let init: String = l.pop();
            let var: String = l.pop();
            l.open(
                BlockKind::For,
                format!("For {var} = {init} To {limit}{step}"),
            );
            true
        }
        "ForEach" | "ForEachAs" => {
            let coll: String = l.pop();
            let var: String = l.pop();
            l.open(BlockKind::ForEach, format!("For Each {var} In {coll}"));
            true
        }
        "Next" => {
            l.close("Next".to_owned());
            true
        }
        "NextVar" => {
            let var: String = l.pop();
            l.close(format!("Next {var}"));
            true
        }
        "Do" => {
            l.open(BlockKind::Do, "Do".to_owned());
            true
        }
        "DoWhile" => {
            let cond: String = l.pop();
            l.open(BlockKind::Do, format!("Do While {cond}"));
            true
        }
        "DoUnitil" => {
            let cond: String = l.pop();
            l.open(BlockKind::Do, format!("Do Until {cond}"));
            true
        }
        "Loop" => {
            l.close("Loop".to_owned());
            true
        }
        "LoopWhile" => {
            let cond: String = l.pop();
            l.close(format!("Loop While {cond}"));
            true
        }
        "LoopUntil" => {
            let cond: String = l.pop();
            l.close(format!("Loop Until {cond}"));
            true
        }
        "While" => {
            let cond: String = l.pop();
            l.open(BlockKind::While, format!("While {cond}"));
            true
        }
        "Wend" => {
            l.close("Wend".to_owned());
            true
        }
        "With" | "StartWithExpr" => {
            let obj: String = l.pop();
            l.open(BlockKind::With, format!("With {obj}"));
            true
        }
        "EndWith" => {
            l.close("End With".to_owned());
            true
        }
        "SelectCase" | "SelectType" => {
            let sel: String = l.pop();
            l.open(BlockKind::Select, format!("Select Case {sel}"));
            true
        }
        "Case" | "CaseEq" => {
            let v: String = l.pop();
            l.emit(format!("Case {v}"));
            true
        }
        "CaseLt" => {
            let v: String = l.pop();
            l.emit(format!("Case Is < {v}"));
            true
        }
        "CaseGt" => {
            let v: String = l.pop();
            l.emit(format!("Case Is > {v}"));
            true
        }
        "CaseLe" => {
            let v: String = l.pop();
            l.emit(format!("Case Is <= {v}"));
            true
        }
        "CaseGe" => {
            let v: String = l.pop();
            l.emit(format!("Case Is >= {v}"));
            true
        }
        "CaseNe" => {
            let v: String = l.pop();
            l.emit(format!("Case Is <> {v}"));
            true
        }
        "CaseTo" => {
            let hi: String = l.pop();
            let lo: String = l.pop();
            l.emit(format!("Case {lo} To {hi}"));
            true
        }
        "CaseElse" => {
            l.emit("Case Else".to_owned());
            true
        }
        "EndSelect" => {
            l.close("End Select".to_owned());
            true
        }
        "ExitSub" => {
            l.emit("Exit Sub".to_owned());
            true
        }
        "ExitFunc" => {
            l.emit("Exit Function".to_owned());
            true
        }
        "ExitFor" => {
            l.emit("Exit For".to_owned());
            true
        }
        "ExitDo" => {
            l.emit("Exit Do".to_owned());
            true
        }
        "ExitProp" => {
            l.emit("Exit Property".to_owned());
            true
        }
        "GoTo" => {
            l.emit(format!("GoTo {}", first_operand(rest)));
            true
        }
        "GoSub" => {
            l.emit(format!("GoSub {}", first_operand(rest)));
            true
        }
        "RaiseEvent" | "ArgsMemRaiseEvent" | "ArgsMemRaiseEventWith" => {
            let name: &str = first_operand(rest);
            let argc: usize = call_arg_count(rest);
            let args: Vec<String> = l.pop_n(argc);
            let target: String = match mnem {
                "ArgsMemRaiseEvent" => {
                    let base: String = l.pop();
                    member_target(base, name, false)
                }
                "ArgsMemRaiseEventWith" => member_target(String::new(), name, true),
                _ => name.to_owned(),
            };
            if args.is_empty() {
                l.emit(format!("RaiseEvent {target}"));
            } else {
                l.emit(format!("RaiseEvent {target}{}", call_args_text(&args)));
            }
            true
        }
        "Label" => {
            l.emit(format!("{}:", first_operand(rest)));
            true
        }
        "OnError" => {
            let r: &str = rest.trim();
            if r.starts_with("(Resume") {
                l.emit("On Error Resume Next".to_owned());
            } else if r.starts_with("(GoTo") {
                l.emit("On Error GoTo 0".to_owned());
            } else {
                l.emit(format!("On Error GoTo {}", first_operand(r)));
            }
            true
        }
        "Resume" => {
            let target: &str = first_operand(rest);
            if target.is_empty() {
                l.emit("Resume".to_owned());
            } else {
                l.emit(format!("Resume {target}"));
            }
            true
        }
        "Return" => {
            l.emit("Return".to_owned());
            true
        }
        "Stop" => {
            l.emit("Stop".to_owned());
            true
        }
        "End" => {
            l.emit("End".to_owned());
            true
        }
        "DoEvents" => {
            l.stack.push("DoEvents".to_owned());
            true
        }
        "Dim" | "DimImplicit" => {
            l.pending_decl = Some(parse_decl_head(rest));
            l.dim_group = None;
            true
        }
        "VarDefn" => {
            let (name, type_suffix): (String, String) = parse_vardefn(rest);
            let inside_type: bool = matches!(
                l.blocks.last().map(|b: &OpenBlock| b.kind),
                Some(BlockKind::Type)
            );
            if inside_type {
                l.emit(format!("{name}{type_suffix}"));
            } else {
                let head: DeclHead = l.pending_decl.clone().unwrap_or(DeclHead {
                    scope: None,
                    is_const: false,
                });
                let keyword: String = decl_keyword(&head);
                let value: String = if head.is_const && !l.stack.is_empty() {
                    format!(" = {}", l.pop())
                } else {
                    String::new()
                };
                let declarator: String = format!("{name}{type_suffix}{value}");
                if let Some(existing) = l.dim_group.and_then(|i: usize| l.out.get_mut(i)) {
                    existing.push_str(", ");
                    existing.push_str(&declarator);
                } else {
                    l.emit(format!("{keyword} {declarator}"));
                    l.dim_group = Some(l.out.len().saturating_sub(1));
                }
            }
            true
        }
        "Type" => {
            let raw: &str = rest.trim();
            let (prefix, name): (&str, &str) = match raw.strip_prefix("(Private)") {
                Some(r) => ("Private ", r.trim()),
                None => ("Public ", raw),
            };
            l.open(BlockKind::Type, format!("{prefix}Type {name}"));
            true
        }
        "EndType" => {
            l.close("End Type".to_owned());
            true
        }
        "EndEnum" => {
            l.relabel_block("Type ", "Enum ");
            l.close("End Enum".to_owned());
            true
        }
        "Redim" | "RedimAs" | "NewRedim" => {
            let name: &str = first_operand(rest);
            let dims: usize = call_arg_count(rest);
            let preserve: bool = rest.contains("(Preserve)");
            let vals: Vec<String> = l.pop_n(l.stack.len());
            let bounds: String = format_redim_bounds(&vals, dims);
            let keyword: &str = if preserve {
                "ReDim Preserve "
            } else {
                "ReDim "
            };
            l.emit(format!("{keyword}{name}({bounds})"));
            true
        }
        "Erase" => {
            let count: usize = call_arg_count(rest).max(1);
            let names: Vec<String> = l.pop_n(count);
            l.emit(format!("Erase {}", names.join(", ")));
            true
        }
        "Open" => {
            let items: Vec<String> = l.pop_n(l.stack.len());
            let mode: &str = rest
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim();
            let fnum: String = items
                .iter()
                .find(|s: &&String| s.starts_with('#'))
                .cloned()
                .unwrap_or_default();
            let path: String = items
                .iter()
                .find(|s: &&String| !s.is_empty() && !s.starts_with('#'))
                .cloned()
                .unwrap_or_default();
            l.emit(format!("Open {path} {mode} As {fnum}"));
            true
        }
        "GetRec" => {
            let items: Vec<String> = l.pop_n(l.stack.len());
            l.emit(format!("Get {}", items.join(", ")));
            true
        }
        "PutRec" => {
            let items: Vec<String> = l.pop_n(l.stack.len());
            l.emit(format!("Put {}", items.join(", ")));
            true
        }
        "Close" => {
            let count: usize = call_arg_count(rest);
            if count == 0 {
                l.emit("Close".to_owned());
            } else {
                let items: Vec<String> = l.pop_n(count);
                l.emit(format!("Close {}", items.join(", ")));
            }
            true
        }
        "CloseAll" => {
            l.emit("Close".to_owned());
            true
        }
        "Debug" => {
            l.printing = true;
            l.print_target = "Debug.Print".to_owned();
            l.print_items.clear();
            true
        }
        "PrintChan" => {
            let chan: String = l.pop();
            l.printing = true;
            l.print_target = format!("Print {chan},");
            l.print_items.clear();
            true
        }
        "PrintObj" => {
            if !l.printing {
                l.printing = true;
                l.print_target = "Print".to_owned();
                l.print_items.clear();
            }
            true
        }
        "PrintItemNL" | "PrintItemSemi" | "PrintItemComma" => {
            if l.printing && !l.stack.is_empty() {
                let item: String = l.pop();
                l.print_items.push(item);
            }
            true
        }
        "Reparse" => {
            if let Some(payload) = quoted_payload(rest) {
                let inner: &str = payload.trim_matches('"').trim();
                if !inner.is_empty() {
                    l.emit(inner.to_owned());
                }
            }
            true
        }
        "Option" => {
            let inner: &str = rest
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .trim();
            if !inner.is_empty() {
                l.emit(format!("Option {inner}"));
            }
            true
        }
        "Coerce" => {
            if let Some(func) = coercion_function(rest)
                && !l.stack.is_empty()
            {
                let value: String = l.pop();
                l.stack.push(format!("{func}({value})"));
            }
            true
        }
        "BoS" => {
            l.join_next = Some(": ");
            true
        }
        "BoSImplicit" => {
            l.join_next = Some(" ");
            if let Some(block) = l.blocks.last_mut()
                && block.kind == BlockKind::If
            {
                block.inline = true;
            }
            true
        }
        "SetStmt" | "CaseDone" | "PrintNL" | "PrintEoS" | "PrintSemi" | "PrintComma"
        | "PrintSpc" | "PrintTab" | "PrintTabComma" | "BoL" | "CoerceVar" | "Paren0"
        | "EndContext" | "Context" | "LineCont" | "ParamByVal" | "ParamOmitted" | "OptionBase"
        | "StartForVariable" | "EndForVariable" => true,
        _ => false,
    }
}

#[must_use]
fn typed_float_literal(rendered: &str, suffix: char) -> String {
    if rendered
        .chars()
        .all(|c: char| c.is_ascii_digit() || c == '-' || c == '+')
    {
        return format!("{rendered}{suffix}");
    }
    rendered.to_owned()
}

const CURRENCY_SCALE: u64 = 10_000;

#[must_use]
fn format_currency(scaled: i64) -> String {
    let sign: &str = if scaled < 0 { "-" } else { "" };
    let magnitude: u64 = scaled.unsigned_abs();
    let units: u64 = magnitude / CURRENCY_SCALE;
    let frac: u64 = magnitude % CURRENCY_SCALE;
    if frac == 0 {
        return format!("{sign}{units}@");
    }
    let mut digits: String = format!("{frac:04}");
    while digits.ends_with('0') {
        digits.pop();
    }
    format!("{sign}{units}.{digits}@")
}

#[must_use]
fn coercion_function(rest: &str) -> Option<&'static str> {
    let outer: &str = rest.trim();
    let inner: &str = outer.strip_prefix('(').unwrap_or(outer);
    match inner.strip_suffix(')').unwrap_or(inner).trim() {
        "Int" => Some("CInt"),
        "Lng" => Some("CLng"),
        "Sng" => Some("CSng"),
        "Dbl" => Some("CDbl"),
        "Cur" => Some("CCur"),
        "Date" => Some("CDate"),
        "Str" => Some("CStr"),
        "Bool" => Some("CBool"),
        "Byte" => Some("CByte"),
        "Var" => Some("CVar"),
        _ => None,
    }
}

#[must_use]
fn lit_number(mnem: &str, rest: &str) -> String {
    let words: Vec<u16> = rest
        .split_whitespace()
        .filter_map(|tok: &str| {
            tok.strip_prefix("0x")
                .and_then(|hex: &str| u16::from_str_radix(hex, 16).ok())
        })
        .collect();
    match mnem {
        "LitDI2" | "LitHI2" | "LitOI2" | "LitSmallI2" => {
            let v: i16 = words.first().copied().unwrap_or(0) as i16;
            v.to_string()
        }
        "LitDI4" | "LitHI4" | "LitOI4" => {
            let lo: u32 = words.first().copied().unwrap_or(0) as u32;
            let hi: u32 = words.get(1).copied().unwrap_or(0) as u32;
            ((hi << 16 | lo) as i32).to_string()
        }
        "LitR4" => {
            let lo: u32 = words.first().copied().unwrap_or(0) as u32;
            let hi: u32 = words.get(1).copied().unwrap_or(0) as u32;
            typed_float_literal(&f32::from_bits(hi << 16 | lo).to_string(), '!')
        }
        "LitR8" => {
            let mut bits: u64 = 0;
            for (i, w) in words.iter().take(4).enumerate() {
                bits |= (*w as u64) << (16 * i);
            }
            typed_float_literal(&f64::from_bits(bits).to_string(), '#')
        }
        "LitCy" => {
            let mut bits: u64 = 0;
            for (i, w) in words.iter().take(4).enumerate() {
                bits |= (*w as u64) << (16 * i);
            }
            format_currency(bits as i64)
        }
        _ => {
            let mut bits: u64 = 0;
            for (i, w) in words.iter().take(4).enumerate() {
                bits |= (*w as u64) << (16 * i);
            }
            (bits as i64).to_string()
        }
    }
}

#[must_use]
fn signature_header(line: &RealPCodeLine) -> String {
    for raw in line.text.lines() {
        let (mnem, rest): (&str, &str) = parse_mnemonic(raw.trim());
        if mnem == "FuncDefn" || mnem == "FuncDefnSave" {
            if let Some(sig) = resolved_signature(rest) {
                return sig;
            }
            let name: &str = first_operand(rest);
            if !name.is_empty() && !name.starts_with("func_") {
                return format!("Sub {name}()");
            }
        }
    }
    for raw in line.text.lines() {
        let (mnem, rest): (&str, &str) = parse_mnemonic(raw.trim());
        if mnem == "ArgsCall" {
            let name: &str = first_operand(rest);
            if !name.is_empty() && !name.starts_with("func_") && name != "(Call)" {
                return format!("Sub {name}()");
            }
        }
    }
    "Sub Main()".to_owned()
}

#[must_use]
fn resolved_signature(rest: &str) -> Option<String> {
    let trimmed: &str = rest.trim();
    let inner: &str = trimmed.strip_prefix('(')?.strip_suffix(')')?;
    let inner: &str = inner.trim();
    if inner.is_empty() {
        return None;
    }
    let has_kind: bool = inner.starts_with("Sub ")
        || inner.starts_with("Function ")
        || inner.contains("Property Get ")
        || inner.contains("Property Let ")
        || inner.contains("Property Set ")
        || inner.contains(" Sub ")
        || inner.contains(" Function ");
    if has_kind {
        Some(inner.to_owned())
    } else {
        None
    }
}

#[must_use]
pub fn semantic_lift(module: &RealModuleDisasm) -> SemanticLift {
    let mut l: Lifter = Lifter::new();
    for line in &module.lines {
        let before_lifted: usize = l.lifted;
        let before_out: usize = l.out.len();
        lift_line(&mut l, line);
        if l.lifted == before_lifted && l.out.len() == before_out {
            let body: &str = line.text.trim();
            if !body.is_empty() && !body.contains("<empty>") {
                let first: &str = body.lines().next().unwrap_or(body);
                l.emit(format!("' [pcode] {first}"));
            }
        }
    }
    while !l.blocks.is_empty() {
        let kind: BlockKind = l.blocks[l.blocks.len() - 1].kind;
        let footer: &str = match kind {
            BlockKind::Procedure => "End Sub",
            BlockKind::If => "End If",
            BlockKind::For | BlockKind::ForEach => "Next",
            BlockKind::Do | BlockKind::While => "Loop",
            BlockKind::With => "End With",
            BlockKind::Select => "End Select",
            BlockKind::Type => "End Type",
        };
        l.walls.push(format!(
            "unterminated {kind:?} block closed synthetically with `{footer}`"
        ));
        l.close(footer.to_owned());
    }
    SemanticLift {
        module: module.name.clone(),
        pseudocode: l.out.join("\n"),
        lifted_lines: l.lifted,
        unlifted_lines: l.unlifted,
        walls: l.walls,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::vba::pcode::PCodeInstruction;

    fn line(idx: usize, text: &str) -> RealPCodeLine {
        RealPCodeLine {
            line_index: idx,
            instructions: Vec::<PCodeInstruction>::new(),
            text: text.to_owned(),
        }
    }

    fn module(name: &str, lines: Vec<RealPCodeLine>) -> RealModuleDisasm {
        RealModuleDisasm {
            name: name.to_owned(),
            pcode_offset_in_stream: 0,
            num_lines: lines.len(),
            lines,
        }
    }

    #[test]
    fn lifts_msgbox_hello_world() {
        let m: RealModuleDisasm = module(
            "Module1",
            vec![
                line(0, "FuncDefn func_00000000"),
                line(1, "LitStr 0x000B \"hello world\"\nArgsCall MsgBox 0x0001"),
                line(2, "EndSub"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("MsgBox \"hello world\""),
            "lift output:\n{}",
            r.pseudocode
        );
        assert!(r.pseudocode.contains("End Sub"));
        assert_eq!(r.unlifted_lines, 0, "lift:\n{}", r.pseudocode);
        assert!(r.walls.is_empty());
    }

    #[test]
    fn lifts_assignment_and_arithmetic() {
        let m: RealModuleDisasm = module(
            "M",
            vec![line(
                0,
                "Ld a\nLitDI2 0x0002\nMul\nLitDI2 0x0003\nAdd\nSt result",
            )],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("result = a * 2 + 3"),
            "lift output:\n{}",
            r.pseudocode
        );
    }

    #[test]
    fn statements_sharing_one_pcode_line_stay_on_one_source_line() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(
                    0,
                    "Ld level\nLd g_LogLevel\nLt\nIf\nBoSImplicit\nExitSub\nEndIf",
                ),
                line(
                    1,
                    "Ld LogLevelDebug\nCase\nCaseDone\nBoS 0x001D\nLitStr 0x0003 \"DBG\"\nSt Prefix",
                ),
                line(2, "Dim\nVarDefn r (As Long)\nVarDefn c (As Long)"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("If level < g_LogLevel Then Exit Sub"),
            "{}",
            r.pseudocode
        );
        assert!(
            !r.pseudocode.contains("End If"),
            "a single-line If must not gain a block terminator:\n{}",
            r.pseudocode
        );
        assert!(
            r.pseudocode
                .contains("Case LogLevelDebug: Prefix = \"DBG\""),
            "{}",
            r.pseudocode
        );
        assert!(
            r.pseudocode.contains("Dim r As Long, c As Long"),
            "{}",
            r.pseudocode
        );
    }

    #[test]
    fn typed_literals_keep_the_suffix_that_produced_them() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "LitCy 0x4000 0x009C 0x0000 0x0000\nSt size"),
                line(1, "LitCy 0x1F40 0x0000 0x0000 0x0000\nSt half"),
                line(2, "LitR8 0x0000 0x0000 0x0000 0x0000\nSt zero"),
                line(3, "Ld raw\nCoerce (Lng)\nSt count"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("size = 1024@"), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("half = 0.8@"), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("zero = 0#"), "{}", r.pseudocode);
        assert!(
            r.pseudocode.contains("count = CLng(raw)"),
            "{}",
            r.pseudocode
        );
    }

    #[test]
    fn lifts_if_then_else_block() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "Ld x\nLitDI2 0x0000\nGt\nIfBlock"),
                line(1, "LitStr 0x0001 \"y\"\nArgsCall Print 0x0001"),
                line(2, "ElseBlock"),
                line(3, "LitStr 0x0001 \"n\"\nArgsCall Print 0x0001"),
                line(4, "EndIfBlock"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("If x > 0 Then"), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("Else"), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("End If"), "{}", r.pseudocode);
    }

    #[test]
    fn lifts_for_loop_with_member_call() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "Ld i\nLitDI2 0x0001\nLitDI2 0x000A\nFor"),
                line(1, "LitStr 0x0001 \"v\"\nLd obj\nArgsMemCall Add 0x0001"),
                line(2, "Next"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("For i = 1 To 10"), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("obj.Add \"v\""), "{}", r.pseudocode);
        assert!(r.pseudocode.contains("Next"), "{}", r.pseudocode);
    }

    #[test]
    fn unterminated_block_records_wall() {
        let m: RealModuleDisasm = module(
            "M",
            vec![line(
                0,
                "FuncDefn func_0\nLitStr 0x01 \"x\"\nArgsCall Print 0x0001",
            )],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("End Sub"), "{}", r.pseudocode);
        assert_eq!(r.walls.len(), 1, "walls={:?}", r.walls);
    }

    #[test]
    fn unknown_mnemonic_preserved_not_fabricated() {
        let m: RealModuleDisasm = module("M", vec![line(0, "Unknown_0F3A (raw=0x1234)")]);
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("' [pcode] Unknown_0F3A"),
            "{}",
            r.pseudocode
        );
        assert_eq!(r.lifted_lines, 0);
    }

    #[test]
    fn crafted_argc_does_not_allocate_billions() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "LitStr 0x0001 \"x\""),
                line(1, "ArgsCall Evil 0xFFFFFFFF"),
                line(2, "ArgsLd Evil2 0xFFFFFFFF"),
                line(3, "IndexLd 0xFFFFFFFF"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.len() < 4096, "bounded output expected");
    }

    #[test]
    fn lifts_indexed_member_and_event_statements() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "LitStr 0x0001 \"x\"\nLd i\nArgsSt arr 0x0001"),
                line(
                    1,
                    "LitStr 0x0001 \"v\"\nLd k\nLd obj\nArgsMemSt Item 0x0001",
                ),
                line(2, "LitStr 0x0001 \"v\"\nLd d\nDictSt key"),
                line(3, "LitStr 0x0001 \"v\"\nLd target\nLd i\nIndexset 0x0001"),
                line(4, "LitStr 0x0001 \"m\"\nRaiseEvent MoodChanged 0x0001"),
                line(5, "LitStr 0x0001 \"w\"\nArgsMemSetWith Child 0x0000"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("arr(i) = \"x\""), "{}", r.pseudocode);
        assert!(
            r.pseudocode.contains("obj.Item(k) = \"v\""),
            "{}",
            r.pseudocode
        );
        assert!(r.pseudocode.contains("d!key = \"v\""), "{}", r.pseudocode);
        assert!(
            r.pseudocode.contains("Set target(i) = \"v\""),
            "{}",
            r.pseudocode
        );
        assert!(
            r.pseudocode.contains("RaiseEvent MoodChanged(\"m\")"),
            "{}",
            r.pseudocode
        );
        assert!(
            r.pseudocode.contains("Set .Child() = \"w\""),
            "{}",
            r.pseudocode
        );
        assert_eq!(r.unlifted_lines, 0, "{}", r.pseudocode);
    }

    #[test]
    fn lifts_declarations_types_enums_and_arrays() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "Option (Explicit)"),
                line(
                    1,
                    "Dim (Public Const)\nLitStr 0x0003 \"hi\"\nVarDefn TAG (As String)",
                ),
                line(2, "Dim (Public)\nVarDefn g_Count (As Long)"),
                line(3, "Type Color"),
                line(4, "LitDI2 0x0000\nSt Red"),
                line(5, "EndEnum"),
                line(6, "Type Pt"),
                line(7, "DimImplicit\nVarDefn X (As Double)"),
                line(8, "EndType"),
                line(9, "FuncDefn (Public Sub Init())"),
                line(
                    10,
                    "LitDI2 0x0001\nLitDI2 0x0004\nRedim arr 0x0001 (As Variant)",
                ),
                line(11, "Ld arr\nErase 0x0001"),
                line(12, "EndSub"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        let pc: &str = &r.pseudocode;
        assert!(pc.contains("Option Explicit"), "{pc}");
        assert!(pc.contains("Public Const TAG As String = \"hi\""), "{pc}");
        assert!(pc.contains("Public g_Count As Long"), "{pc}");
        assert!(pc.contains("Enum Color"), "{pc}");
        assert!(pc.contains("Red = 0"), "{pc}");
        assert!(pc.contains("End Enum"), "{pc}");
        assert!(pc.contains("Type Pt"), "{pc}");
        assert!(pc.contains("X As Double"), "{pc}");
        assert!(pc.contains("End Type"), "{pc}");
        assert!(pc.contains("ReDim arr(1 To 4)"), "{pc}");
        assert!(pc.contains("Erase arr"), "{pc}");
        assert_eq!(r.unlifted_lines, 0, "{pc}");
        assert!(r.walls.is_empty(), "walls={:?}", r.walls);
    }

    #[test]
    fn litstr_embedded_quotes_are_doubled() {
        let m: RealModuleDisasm = module(
            "M",
            vec![
                line(0, "FuncDefn func_00000000"),
                line(1, "LitStr 0x0007 \"Say \"hi\"\"\nArgsCall MsgBox 0x0001"),
                line(2, "EndSub"),
            ],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("MsgBox \"Say \"\"hi\"\"\""),
            "embedded quotes must be doubled for a re-parseable literal:\n{}",
            r.pseudocode
        );
        assert!(
            !r.pseudocode.contains("MsgBox \"Say \"hi\"\""),
            "raw single quotes must not survive:\n{}",
            r.pseudocode
        );
    }

    #[test]
    fn litstr_trailing_quote_char_is_doubled() {
        let m: RealModuleDisasm = module("M", vec![line(0, "LitStr 0x0003 \"ab\"\"\nSt s")]);
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("s = \"ab\"\"\""),
            "string ending in a quote must round-trip:\n{}",
            r.pseudocode
        );
    }

    #[test]
    fn litstr_plain_string_unchanged() {
        let m: RealModuleDisasm = module("M", vec![line(0, "LitStr 0x0005 \"plain\"\nSt s")]);
        let r: SemanticLift = semantic_lift(&m);
        assert!(r.pseudocode.contains("s = \"plain\""), "{}", r.pseudocode);
    }

    #[test]
    fn lifts_member_store_base_on_top() {
        let m: RealModuleDisasm = module(
            "M",
            vec![line(0, "LitStr 0x0005 \"hello\"\nLd greeter\nMemSt Prefix")],
        );
        let r: SemanticLift = semantic_lift(&m);
        assert!(
            r.pseudocode.contains("greeter.Prefix = \"hello\""),
            "{}",
            r.pseudocode
        );
    }
}
