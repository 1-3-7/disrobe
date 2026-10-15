use std::collections::BTreeMap;

use serde::Serialize;
use walrus::ir::BinaryOp;
use wasmparser::{ExternalKind, Operator, Parser, Payload};

use super::reinline::{ReinlineStats, reinline_with};
use crate::error::{Error, Result};

pub const MAX_HOST_SCRIPT_BYTES: usize = 1 << 20;
pub const MAX_HOST_ENTRIES: usize = 4096;
const MAX_TOKENS: usize = 1 << 18;
const MAX_EVAL_DEPTH: usize = 2;

const PUNCTUATORS: [&str; 22] = [
    ">>>=", ">>>", "===", "!==", "=>", ">>", "<<", "==", "!=", "<=", ">=", "&&", "||", "++", "--",
    "+=", "-=", "|=", "&=", "^=", "**", "?.",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostOperator {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    ShrS,
    ShrU,
}

impl HostOperator {
    const fn binary_op(self) -> BinaryOp {
        match self {
            Self::Add => BinaryOp::I32Add,
            Self::Sub => BinaryOp::I32Sub,
            Self::Mul => BinaryOp::I32Mul,
            Self::And => BinaryOp::I32And,
            Self::Or => BinaryOp::I32Or,
            Self::Xor => BinaryOp::I32Xor,
            Self::Shl => BinaryOp::I32Shl,
            Self::ShrS => BinaryOp::I32ShrS,
            Self::ShrU => BinaryOp::I32ShrU,
        }
    }

    const fn commutative(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Mul | Self::And | Self::Or | Self::Xor
        )
    }

    const fn from_wasm(op: &Operator<'_>) -> Option<Self> {
        Some(match op {
            Operator::I32Add => Self::Add,
            Operator::I32Sub => Self::Sub,
            Operator::I32Mul => Self::Mul,
            Operator::I32And => Self::And,
            Operator::I32Or => Self::Or,
            Operator::I32Xor => Self::Xor,
            Operator::I32Shl => Self::Shl,
            Operator::I32ShrS => Self::ShrS,
            Operator::I32ShrU => Self::ShrU,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostBinding {
    Operator(HostOperator),
    EvalExport(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostOpTable {
    pub entries: BTreeMap<String, HostBinding>,
    pub refused: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTableReinline {
    pub bytes: Vec<u8>,
    pub stats: ReinlineStats,
    pub resolved: BTreeMap<String, HostOperator>,
    pub unresolved: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Num(String),
    Str(String),
    Punct(String),
}

impl Tok {
    fn is_punct(&self, text: &str) -> bool {
        matches!(self, Self::Punct(p) if p == text)
    }

    fn ident(&self) -> Option<&str> {
        match self {
            Self::Ident(name) => Some(name),
            _ => None,
        }
    }
}

fn limit_error(what: &str, limit: usize) -> Error {
    Error::Parse(format!(
        "DR-WASMDEOB-WOBF-HOST: the host script has more {what} than the {limit} this reader accepts"
    ))
}

fn tokenize(text: &str) -> Result<Vec<Tok>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<Tok> = Vec::new();
    let mut i: usize = 0;
    while i < chars.len() {
        if out.len() >= MAX_TOKENS {
            return Err(limit_error("tokens", MAX_TOKENS));
        }
        let c: char = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            let (value, next): (String, usize) = read_string(&chars, i);
            out.push(Tok::Str(value));
            i = next;
            continue;
        }
        if c.is_ascii_digit() {
            let start: usize = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            out.push(Tok::Num(chars[start..i].iter().collect()));
            continue;
        }
        if c.is_alphabetic() || c == '_' || c == '$' {
            let start: usize = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '$')
            {
                i += 1;
            }
            out.push(Tok::Ident(chars[start..i].iter().collect()));
            continue;
        }
        let rest: String = chars[i..chars.len().min(i + 4)].iter().collect();
        let punct: String = PUNCTUATORS
            .iter()
            .find(|p: &&&str| rest.starts_with(**p))
            .map_or_else(|| c.to_string(), |p: &&str| (*p).to_owned());
        i += punct.chars().count();
        out.push(Tok::Punct(punct));
    }
    Ok(out)
}

fn read_string(chars: &[char], start: usize) -> (String, usize) {
    let quote: char = chars[start];
    let mut value: String = String::new();
    let mut i: usize = start + 1;
    while i < chars.len() {
        let c: char = chars[i];
        if c == quote {
            return (value, i + 1);
        }
        if c == '\\' {
            let Some(&escaped) = chars.get(i + 1) else {
                break;
            };
            match escaped {
                'n' => value.push('\n'),
                't' => value.push('\t'),
                'r' => value.push('\r'),
                other => value.push(other),
            }
            i += 2;
            continue;
        }
        value.push(c);
        i += 1;
    }
    (value, chars.len())
}

fn strip_parens(mut body: &[Tok]) -> &[Tok] {
    while body.len() >= 2
        && body[0].is_punct("(")
        && body[body.len() - 1].is_punct(")")
        && closes_at_end(body)
    {
        body = &body[1..body.len() - 1];
    }
    body
}

fn closes_at_end(body: &[Tok]) -> bool {
    let mut depth: usize = 0;
    for (index, tok) in body.iter().enumerate() {
        if tok.is_punct("(") {
            depth += 1;
        } else if tok.is_punct(")") {
            depth = depth.saturating_sub(1);
            if depth == 0 && index + 1 != body.len() {
                return false;
            }
        }
    }
    true
}

fn strip_int32_coercion(body: &[Tok]) -> &[Tok] {
    let mut current: &[Tok] = strip_parens(body);
    loop {
        let n: usize = current.len();
        let coerced: bool = n >= 3
            && matches!(&current[n - 1], Tok::Num(num) if num == "0")
            && (current[n - 2].is_punct("|")
                || current[n - 2].is_punct(">>")
                || current[n - 2].is_punct(">>>"));
        if !coerced || !top_level_only(&current[..n - 2]) {
            return current;
        }
        current = strip_parens(&current[..n - 2]);
    }
}

fn top_level_only(body: &[Tok]) -> bool {
    let mut depth: usize = 0;
    let mut operators: usize = 0;
    for tok in body {
        match tok {
            Tok::Punct(p) if p == "(" => depth += 1,
            Tok::Punct(p) if p == ")" => depth = depth.saturating_sub(1),
            Tok::Punct(p) if depth == 0 && p != "." => operators += 1,
            _ => {}
        }
    }
    operators <= 1
}

fn operator_for(punct: &str) -> std::result::Result<HostOperator, String> {
    Ok(match punct {
        "+" => HostOperator::Add,
        "-" => HostOperator::Sub,
        "&" => HostOperator::And,
        "|" => HostOperator::Or,
        "^" => HostOperator::Xor,
        "<<" => HostOperator::Shl,
        ">>" => HostOperator::ShrS,
        ">>>" => HostOperator::ShrU,
        "*" => {
            return Err(
                "JavaScript `*` multiplies doubles and rounds large products, so it is not i32.mul; only Math.imul is exact".to_owned(),
            );
        }
        other => return Err(format!("operator `{other}` has no exact i32 counterpart")),
    })
}

fn classify_body(body: &[Tok], params: &[String; 2]) -> std::result::Result<HostBinding, String> {
    let body: &[Tok] = strip_int32_coercion(body);
    let is_param = |tok: &Tok, index: usize| tok.ident() == Some(params[index].as_str());
    if let [left, Tok::Punct(op), right] = body {
        let operator: HostOperator = operator_for(op)?;
        if is_param(left, 0) && is_param(right, 1) {
            return Ok(HostBinding::Operator(operator));
        }
        if is_param(left, 1) && is_param(right, 0) {
            return if operator.commutative() {
                Ok(HostBinding::Operator(operator))
            } else {
                Err("the operands are swapped and the operator is not commutative".to_owned())
            };
        }
        return Err("the operator does not combine the two parameters directly".to_owned());
    }
    let call_args_match = |args: &[Tok]| -> bool {
        matches!(args, [a, comma, b] if comma.is_punct(",")
            && ((is_param(a, 0) && is_param(b, 1)) || (is_param(a, 1) && is_param(b, 0))))
    };
    if let [
        Tok::Ident(math),
        dot,
        Tok::Ident(imul),
        open,
        args @ ..,
        close,
    ] = body
        && math == "Math"
        && dot.is_punct(".")
        && imul == "imul"
        && open.is_punct("(")
        && close.is_punct(")")
        && call_args_match(args)
    {
        return Ok(HostBinding::Operator(HostOperator::Mul));
    }
    if let Some(open_at) = body.iter().position(|tok: &Tok| tok.is_punct("("))
        && open_at >= 1
        && open_at + 1 < body.len()
        && body[body.len() - 1].is_punct(")")
        && matches!(&body[open_at + 1..body.len() - 1], [a, comma, b]
            if comma.is_punct(",") && is_param(a, 0) && is_param(b, 1))
        && let Some(name) = member_tail(&body[..open_at])
        && is_eval_export(&name)
    {
        return Ok(HostBinding::EvalExport(name));
    }
    Err("the body is not a single i32-exact binary operator over the two parameters".to_owned())
}

fn member_tail(chain: &[Tok]) -> Option<String> {
    match chain {
        [.., dot, Tok::Ident(name)] if dot.is_punct(".") => Some(name.clone()),
        [.., open, Tok::Str(name), close] if open.is_punct("[") && close.is_punct("]") => {
            Some(name.clone())
        }
        _ => None,
    }
}

fn is_eval_export(name: &str) -> bool {
    name.strip_prefix("eval")
        .is_some_and(|rest: &str| !rest.is_empty() && rest.bytes().all(|b: u8| b.is_ascii_digit()))
}

fn two_params(tokens: &[Tok]) -> Option<([String; 2], usize)> {
    match tokens {
        [open, Tok::Ident(a), comma, Tok::Ident(b), close, ..]
            if open.is_punct("(") && comma.is_punct(",") && close.is_punct(")") =>
        {
            Some(([a.clone(), b.clone()], 5))
        }
        _ => None,
    }
}

fn expression_end(tokens: &[Tok]) -> usize {
    let mut depth: usize = 0;
    for (index, tok) in tokens.iter().enumerate() {
        match tok {
            Tok::Punct(p) if p == "(" || p == "[" || p == "{" => depth += 1,
            Tok::Punct(p) if p == ")" || p == "]" || p == "}" => {
                if depth == 0 {
                    return index;
                }
                depth -= 1;
            }
            Tok::Punct(p) if depth == 0 && (p == "," || p == ";") => return index,
            _ => {}
        }
    }
    tokens.len()
}

fn returned_expression(block: &[Tok]) -> std::result::Result<&[Tok], String> {
    let [open, Tok::Ident(ret), rest @ ..] = block else {
        return Err("the function body is not a single return statement".to_owned());
    };
    if !open.is_punct("{") || ret != "return" {
        return Err("the function body is not a single return statement".to_owned());
    }
    let end: usize = expression_end(rest);
    let mut tail: &[Tok] = &rest[end..];
    if tail.first().is_some_and(|tok: &Tok| tok.is_punct(";")) {
        tail = &tail[1..];
    }
    if !tail.first().is_some_and(|tok: &Tok| tok.is_punct("}")) {
        return Err("the function body holds more than one statement".to_owned());
    }
    Ok(&rest[..end])
}

fn classify_function(tokens: &[Tok], depth: usize) -> std::result::Result<HostBinding, String> {
    if let Some((params, used)) = two_params(tokens)
        && tokens.get(used).is_some_and(|tok: &Tok| tok.is_punct("=>"))
    {
        let rest: &[Tok] = &tokens[used + 1..];
        if rest.first().is_some_and(|tok: &Tok| tok.is_punct("{")) {
            return classify_body(returned_expression(rest)?, &params);
        }
        return classify_body(&rest[..expression_end(rest)], &params);
    }
    if tokens.first().and_then(Tok::ident) == Some("function") {
        let after_name: &[Tok] = match tokens.get(1) {
            Some(Tok::Ident(_)) => &tokens[2..],
            _ => &tokens[1..],
        };
        let (params, used): ([String; 2], usize) = two_params(after_name)
            .ok_or_else(|| "the function does not take exactly two parameters".to_owned())?;
        return classify_body(returned_expression(&after_name[used..])?, &params);
    }
    let callee: &[Tok] = if tokens.first().and_then(Tok::ident) == Some("new") {
        &tokens[1..]
    } else {
        tokens
    };
    match callee {
        [Tok::Ident(eval), open, Tok::Str(code), close, ..]
            if eval == "eval" && open.is_punct("(") && close.is_punct(")") =>
        {
            if depth >= MAX_EVAL_DEPTH {
                return Err("eval nesting is deeper than this reader follows".to_owned());
            }
            let inner: Vec<Tok> = tokenize(code).map_err(|e: Error| e.to_string())?;
            classify_function(&inner, depth + 1)
        }
        [
            Tok::Ident(function),
            open,
            Tok::Str(a),
            c1,
            Tok::Str(b),
            c2,
            Tok::Str(code),
            close,
            ..,
        ] if function == "Function"
            && open.is_punct("(")
            && c1.is_punct(",")
            && c2.is_punct(",")
            && close.is_punct(")") =>
        {
            let inner: Vec<Tok> =
                tokenize(&format!("{{{code}}}")).map_err(|e: Error| e.to_string())?;
            let params: [String; 2] = [a.trim().to_owned(), b.trim().to_owned()];
            classify_body(returned_expression(&inner)?, &params)
        }
        _ => Err("the value is not a static two-parameter function".to_owned()),
    }
}

pub fn parse_host_table(script: &str) -> Result<HostOpTable> {
    if script.len() > MAX_HOST_SCRIPT_BYTES {
        return Err(limit_error("bytes", MAX_HOST_SCRIPT_BYTES));
    }
    let tokens: Vec<Tok> = tokenize(script)?;
    let mut table: HostOpTable = HostOpTable::default();
    for index in 1..tokens.len().saturating_sub(1) {
        if !(tokens[index - 1].is_punct("{") || tokens[index - 1].is_punct(","))
            || !tokens[index + 1].is_punct(":")
        {
            continue;
        }
        let key: String = match &tokens[index] {
            Tok::Ident(name) | Tok::Str(name) => name.clone(),
            _ => continue,
        };
        let value: &[Tok] = &tokens[index + 2..];
        let looks_like_function: bool = two_params(value).is_some()
            || matches!(
                value.first().and_then(Tok::ident),
                Some("function" | "eval" | "new" | "Function")
            );
        if !looks_like_function {
            continue;
        }
        if table.entries.len() + table.refused.len() >= MAX_HOST_ENTRIES {
            return Err(limit_error("table entries", MAX_HOST_ENTRIES));
        }
        if table.entries.remove(&key).is_some() || table.refused.contains_key(&key) {
            table
                .refused
                .insert(key, "the import is bound more than once".to_owned());
            continue;
        }
        match classify_function(value, 0) {
            Ok(binding) => {
                table.entries.insert(key, binding);
            }
            Err(reason) => {
                table.refused.insert(key, reason);
            }
        }
    }
    Ok(table)
}

fn exact_eval_exports(wasm: &[u8]) -> Result<BTreeMap<String, HostOperator>> {
    let mut imported_funcs: u32 = 0;
    let mut exports: BTreeMap<u32, String> = BTreeMap::new();
    let mut local_index: u32 = 0;
    let mut out: BTreeMap<String, HostOperator> = BTreeMap::new();
    for payload in Parser::new(0).parse_all(wasm) {
        let payload: Payload<'_> =
            payload.map_err(|e| Error::Parse(format!("DR-WASMDEOB-WOBF-HOST: {e}")))?;
        match payload {
            Payload::ImportSection(reader) => {
                for group in reader {
                    let group: wasmparser::Imports<'_> =
                        group.map_err(|e| Error::Parse(format!("DR-WASMDEOB-WOBF-HOST: {e}")))?;
                    if let wasmparser::Imports::Single(_, import) = group
                        && matches!(import.ty, wasmparser::TypeRef::Func(_))
                    {
                        imported_funcs = imported_funcs.saturating_add(1);
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export: wasmparser::Export<'_> =
                        export.map_err(|e| Error::Parse(format!("DR-WASMDEOB-WOBF-HOST: {e}")))?;
                    if export.kind == ExternalKind::Func && is_eval_export(export.name) {
                        exports.insert(export.index, export.name.to_owned());
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let index: u32 = imported_funcs.saturating_add(local_index);
                local_index = local_index.saturating_add(1);
                let Some(name) = exports.get(&index) else {
                    continue;
                };
                if body
                    .get_locals_reader()
                    .map_err(|e| Error::Parse(format!("DR-WASMDEOB-WOBF-HOST: {e}")))?
                    .get_count()
                    != 0
                {
                    continue;
                }
                let ops: Vec<Operator<'_>> = body
                    .get_operators_reader()
                    .map_err(|e| Error::Parse(format!("DR-WASMDEOB-WOBF-HOST: {e}")))?
                    .into_iter()
                    .take(5)
                    .collect::<std::result::Result<Vec<Operator<'_>>, _>>()
                    .map_err(|e| Error::Parse(format!("DR-WASMDEOB-WOBF-HOST: {e}")))?;
                if let [
                    Operator::LocalGet { local_index: 0 },
                    Operator::LocalGet { local_index: 1 },
                    op,
                    Operator::End,
                ] = ops.as_slice()
                    && let Some(operator) = HostOperator::from_wasm(op)
                {
                    out.insert(name.clone(), operator);
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

pub fn reinline_host_table(wasm: &[u8], table: &HostOpTable) -> Result<HostTableReinline> {
    let evals: BTreeMap<String, HostOperator> = exact_eval_exports(wasm)?;
    let mut resolved: BTreeMap<String, HostOperator> = BTreeMap::new();
    let mut unresolved: BTreeMap<String, String> = table.refused.clone();
    for (import, binding) in &table.entries {
        match binding {
            HostBinding::Operator(operator) => {
                resolved.insert(import.clone(), *operator);
            }
            HostBinding::EvalExport(export) => match evals.get(export) {
                Some(operator) => {
                    resolved.insert(import.clone(), *operator);
                }
                None => {
                    unresolved.insert(
                        import.clone(),
                        format!("export `{export}` is not a two-parameter function whose whole body is one i32 binary operator"),
                    );
                }
            },
        }
    }
    let (bytes, stats): (Vec<u8>, ReinlineStats) = reinline_with(wasm, |name: &str| {
        resolved
            .get(name)
            .map(|operator: &HostOperator| operator.binary_op())
    })?;
    Ok(HostTableReinline {
        bytes,
        stats,
        resolved,
        unresolved,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_static_form_resolves_and_inexact_operators_are_refused() {
        let table: HostOpTable = parse_host_table(
            r#"const env = {
                a: (x, y) => x + y,
                "b": function (x, y) { return (x - y) | 0; },
                c: (x, y) => (y ^ x),
                d: (x, y) => y - x,
                e: (x, y) => Math.imul(y, x),
                f: eval("(l, r) => l >>> r"),
                g: new Function("v", "s", "return v << s;"),
                h: (x, y) => instance.exports.eval4(x, y),
                i: (x, y) => x * y,
                j: (x, y) => x % y,
                k: (x, y) => x + y + 1,
                a: (x, y) => x & y,
            };"#,
        )
        .expect("parse");
        assert_eq!(
            table.entries.get("b"),
            Some(&HostBinding::Operator(HostOperator::Sub))
        );
        assert_eq!(
            table.entries.get("c"),
            Some(&HostBinding::Operator(HostOperator::Xor))
        );
        assert_eq!(
            table.entries.get("e"),
            Some(&HostBinding::Operator(HostOperator::Mul))
        );
        assert_eq!(
            table.entries.get("f"),
            Some(&HostBinding::Operator(HostOperator::ShrU))
        );
        assert_eq!(
            table.entries.get("g"),
            Some(&HostBinding::Operator(HostOperator::Shl))
        );
        assert_eq!(
            table.entries.get("h"),
            Some(&HostBinding::EvalExport("eval4".to_owned()))
        );
        for refused in ["a", "d", "i", "j", "k"] {
            assert!(table.refused.contains_key(refused), "{refused}: {table:?}");
            assert!(!table.entries.contains_key(refused));
        }
    }

    #[test]
    fn hostile_scripts_are_bounded_and_never_panic() {
        let oversized: String = "x".repeat(MAX_HOST_SCRIPT_BYTES + 1);
        assert!(parse_host_table(&oversized).is_err());
        let mut many: String = String::from("{");
        for i in 0..=MAX_HOST_ENTRIES {
            many.push('k');
            many.push_str(&i.to_string());
            many.push_str(": (a, b) => a ^ b,");
        }
        many.push('}');
        assert!(parse_host_table(&many).is_err());
        let nested: String = "{k: eval(\"eval('eval(`(a,b)=>a^b`)')\")}".to_owned();
        let table: HostOpTable = parse_host_table(&nested).expect("parse");
        assert!(table.refused.contains_key("k"), "{table:?}");
        for text in [
            "{",
            "{k:",
            "{k: (",
            "{k: (a, b) =>",
            "\"unterminated",
            "{k: function (a, b) {",
        ] {
            let _: Result<HostOpTable> = parse_host_table(text);
        }
    }
}
