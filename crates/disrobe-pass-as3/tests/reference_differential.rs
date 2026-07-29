#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_as3::abc::{AbcFile, ClassInfo, InstanceInfo, MethodBody, MethodInfo, TraitInfo};
use disrobe_pass_as3::lifter::{
    CaseLabel, CatchClause, Expr, LiftedBody, LocalNames, Stmt, SwitchCase, lift_body,
    local_names_for, render_body,
};
use disrobe_pass_as3::swf::{DoAbc, Swf};
use disrobe_pass_as3::{abc, swf};

const TRAIT_KIND_METHOD: u8 = 1;
const TRAIT_KIND_GETTER: u8 = 2;
const TRAIT_KIND_SETTER: u8 = 3;

const CONTROL_KEYWORDS: [&str; 26] = [
    "if",
    "while",
    "for",
    "switch",
    "catch",
    "do",
    "with",
    "return",
    "each",
    "in",
    "is",
    "as",
    "instanceof",
    "typeof",
    "delete",
    "throw",
    "new",
    "function",
    "case",
    "default",
    "else",
    "var",
    "const",
    "try",
    "finally",
    "package",
];

const REGEX_PREFIX_KEYWORDS: [&str; 12] = [
    "return",
    "typeof",
    "delete",
    "in",
    "is",
    "as",
    "instanceof",
    "new",
    "throw",
    "case",
    "void",
    "else",
];

const UNDECOMPILED_MARKERS: [&str; 5] = ["error", "decompil", "unable", "exception", "timeout"];

const COERCION_NAMES: [&str; 12] = [
    "int", "uint", "Number", "String", "Boolean", "Object", "Array", "Class", "Function", "XML",
    "XMLList", "Vector",
];

const TEMPORARY_PREFIXES: [&str; 4] = ["loc", "arg", "param", "reg"];

const ESCAPE_DELIMITER: char = '\u{A7}';

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Escaped(String),
    Str(String),
    Punct(char),
    Num,
    Regex,
    Comment(String),
}

fn is_identifier(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c: char| c.is_alphanumeric() || c == '_' || c == '$')
}

fn is_temporary_name(name: &str) -> bool {
    let core: &str = name.trim_start_matches('_').trim_end_matches('_');
    TEMPORARY_PREFIXES.iter().any(|prefix: &&str| {
        core.strip_prefix(prefix).is_some_and(|rest: &str| {
            !rest.is_empty() && rest.bytes().all(|b: u8| b.is_ascii_digit())
        })
    })
}

fn is_gradable_call_name(name: &str) -> bool {
    is_identifier(name)
        && !CONTROL_KEYWORDS.contains(&name)
        && !COERCION_NAMES.contains(&name)
        && !is_temporary_name(name)
}

#[derive(Debug, Clone)]
struct Lexed {
    toks: Vec<Token>,
    starts: Vec<usize>,
    ends: Vec<usize>,
    src: Vec<char>,
}

impl Lexed {
    fn text(&self, from: usize, to: usize) -> String {
        if from >= to || from >= self.starts.len() {
            return String::new();
        }
        let a: usize = self.starts[from];
        let b: usize = self.ends[to - 1].min(self.src.len());
        self.src[a..b].iter().collect()
    }

    fn ident_at(&self, i: usize) -> Option<&str> {
        match self.toks.get(i) {
            Some(Token::Ident(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    fn name_at(&self, i: usize) -> Option<&str> {
        match self.toks.get(i) {
            Some(Token::Ident(s) | Token::Escaped(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    fn is_punct(&self, i: usize, c: char) -> bool {
        matches!(self.toks.get(i), Some(Token::Punct(p)) if *p == c)
    }

    fn glued_to_dash(&self, i: usize) -> bool {
        self.starts
            .get(i)
            .is_some_and(|&start: &usize| start > 0 && self.src[start - 1] == '-')
    }
}

fn regex_allowed(prev: Option<&Token>) -> bool {
    match prev {
        None => true,
        Some(Token::Ident(s)) => REGEX_PREFIX_KEYWORDS.contains(&s.as_str()),
        Some(Token::Punct(c)) => !matches!(c, ')' | ']'),
        Some(Token::Escaped(_) | Token::Str(_) | Token::Num | Token::Regex) => false,
        Some(Token::Comment(_)) => true,
    }
}

fn scan_regex(chars: &[char], start: usize) -> Option<usize> {
    let mut i: usize = start + 1;
    let mut in_class: bool = false;
    while i < chars.len() {
        match chars[i] {
            '\n' => return None,
            '\\' => i += 1,
            '[' => in_class = true,
            ']' => in_class = false,
            '/' if !in_class => {
                let mut j: usize = i + 1;
                while j < chars.len() && chars[j].is_ascii_alphabetic() {
                    j += 1;
                }
                return Some(j);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn unescape_hex(chars: &[char], from: usize, width: usize) -> Option<(char, usize)> {
    if from + width > chars.len() {
        return None;
    }
    let mut value: u32 = 0;
    for offset in 0..width {
        value = value * 16 + chars[from + offset].to_digit(16)?;
    }
    char::from_u32(value).map(|c: char| (c, from + width))
}

fn scan_string(chars: &[char], start: usize) -> (String, usize) {
    let quote: char = chars[start];
    let mut value: String = String::new();
    let mut i: usize = start + 1;
    while i < chars.len() {
        let c: char = chars[i];
        if c == quote {
            return (value, i + 1);
        }
        if c != '\\' {
            value.push(c);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&esc) = chars.get(i) else { break };
        i += 1;
        match esc {
            'n' => value.push('\n'),
            'r' => value.push('\r'),
            't' => value.push('\t'),
            'b' => value.push('\u{08}'),
            'f' => value.push('\u{0C}'),
            'v' => value.push('\u{0B}'),
            '0' => value.push('\0'),
            '\n' => {}
            'x' => match unescape_hex(chars, i, 2) {
                Some((c, next)) => {
                    value.push(c);
                    i = next;
                }
                None => value.push('x'),
            },
            'u' => match unescape_hex(chars, i, 4) {
                Some((c, next)) => {
                    value.push(c);
                    i = next;
                }
                None => value.push('u'),
            },
            other => value.push(other),
        }
    }
    (value, chars.len())
}

fn lex(src: &str) -> Lexed {
    let chars: Vec<char> = src.chars().collect();
    let mut toks: Vec<Token> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();
    let mut ends: Vec<usize> = Vec::new();
    let mut i: usize = 0;
    while i < chars.len() {
        let c: char = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let start: usize = i;
        let tok: Token = if c == '/' && chars.get(i + 1) == Some(&'/') {
            let mut j: usize = i + 2;
            while j < chars.len() && chars[j] != '\n' {
                j += 1;
            }
            let text: String = chars[i + 2..j].iter().collect();
            i = j;
            Token::Comment(text)
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut j: usize = i + 2;
            while j + 1 < chars.len() && !(chars[j] == '*' && chars[j + 1] == '/') {
                j += 1;
            }
            let text: String = chars[i + 2..j.min(chars.len())].iter().collect();
            i = (j + 2).min(chars.len());
            Token::Comment(text)
        } else if c == '/'
            && regex_allowed(toks.last())
            && let Some(end) = scan_regex(&chars, i)
        {
            i = end;
            Token::Regex
        } else if c == '"' || c == '\'' {
            let (value, next): (String, usize) = scan_string(&chars, i);
            i = next;
            Token::Str(value)
        } else if c == ESCAPE_DELIMITER {
            let mut j: usize = i + 1;
            while j < chars.len() && chars[j] != ESCAPE_DELIMITER {
                j += 1;
            }
            let name: String = chars[i + 1..j.min(chars.len())].iter().collect();
            i = (j + 1).min(chars.len());
            Token::Escaped(name)
        } else if c.is_alphabetic() || c == '_' || c == '$' {
            let mut j: usize = i;
            while j < chars.len()
                && (chars[j].is_alphanumeric() || chars[j] == '_' || chars[j] == '$')
            {
                j += 1;
            }
            let name: String = chars[i..j].iter().collect();
            i = j;
            Token::Ident(name)
        } else if c.is_ascii_digit() {
            let mut j: usize = i;
            while j < chars.len()
                && (chars[j].is_ascii_alphanumeric() || chars[j] == '.' || chars[j] == '_')
            {
                j += 1;
            }
            i = j;
            Token::Num
        } else {
            i += 1;
            Token::Punct(c)
        };
        toks.push(tok);
        starts.push(start);
        ends.push(i);
    }
    Lexed {
        toks,
        starts,
        ends,
        src: chars,
    }
}

fn match_brace(lx: &Lexed, open: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut i: usize = open;
    while i < lx.toks.len() {
        if lx.is_punct(i, '{') {
            depth += 1;
        } else if lx.is_punct(i, '}') {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn find_brace_open(lx: &Lexed, from: usize) -> Option<usize> {
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut i: usize = from;
    while i < lx.toks.len() {
        match lx.toks.get(i) {
            Some(Token::Punct('(')) => paren += 1,
            Some(Token::Punct(')')) => paren -= 1,
            Some(Token::Punct('[')) => bracket += 1,
            Some(Token::Punct(']')) => bracket -= 1,
            Some(Token::Punct('{')) if paren == 0 && bracket == 0 => return Some(i),
            Some(Token::Punct(';')) if paren == 0 && bracket == 0 => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MethodFacts {
    strings: BTreeMap<String, usize>,
    calls: BTreeMap<String, usize>,
    ifs: usize,
    loops: usize,
    switches: usize,
    tries: usize,
}

impl MethodFacts {
    fn control_shape(&self) -> (usize, usize, usize, usize) {
        (self.ifs, self.loops, self.switches, self.tries)
    }
}

fn facts_of(lx: &Lexed, from: usize, to: usize) -> MethodFacts {
    let mut facts: MethodFacts = MethodFacts::default();
    let mut depth: i32 = 0;
    let mut pending_do: Vec<i32> = Vec::new();
    let mut prev: Option<Token> = None;
    let mut i: usize = from;
    while i < to {
        let Some(tok): Option<&Token> = lx.toks.get(i) else {
            break;
        };
        match tok {
            Token::Comment(_) => {
                i += 1;
                continue;
            }
            Token::Punct('{') => depth += 1,
            Token::Punct('}') => depth -= 1,
            Token::Str(s) => {
                *facts.strings.entry(s.clone()).or_insert(0) += 1;
            }
            Token::Ident(name) | Token::Escaped(name) => {
                let mangled: bool = lx.glued_to_dash(i);
                let keyword: bool = matches!(tok, Token::Ident(_))
                    && !mangled
                    && !matches!(prev, Some(Token::Punct('.')));
                if keyword && name == "function" {
                    if let Some(open) = find_brace_open(lx, i + 1)
                        && open < to
                        && let Some(close) = match_brace(lx, open)
                    {
                        prev = Some(Token::Punct('}'));
                        i = close + 1;
                        continue;
                    }
                } else if keyword {
                    match name.as_str() {
                        "if" => facts.ifs += 1,
                        "for" => facts.loops += 1,
                        "do" => {
                            facts.loops += 1;
                            pending_do.push(depth);
                        }
                        "while" => {
                            let closes_do: bool = matches!(prev, Some(Token::Punct('}')))
                                && pending_do.last() == Some(&depth);
                            if closes_do {
                                pending_do.pop();
                            } else {
                                facts.loops += 1;
                            }
                        }
                        "switch" => facts.switches += 1,
                        "try" => facts.tries += 1,
                        _ => {}
                    }
                }
                if !mangled && is_gradable_call_name(name) && lx.is_punct(i + 1, '(') {
                    *facts.calls.entry(name.clone()).or_insert(0) += 1;
                }
            }
            _ => {}
        }
        prev = lx.toks.get(i).cloned();
        i += 1;
    }
    facts
}

fn body_is_undecompiled(lx: &Lexed, from: usize, to: usize) -> bool {
    lx.toks[from.min(lx.toks.len())..to.min(lx.toks.len())]
        .iter()
        .any(|t: &Token| match t {
            Token::Escaped(name) => name.is_empty(),
            Token::Comment(c) => {
                let lower: String = c.to_lowercase();
                UNDECOMPILED_MARKERS
                    .iter()
                    .any(|m: &&str| lower.contains(m))
            }
            _ => false,
        })
}

#[derive(Debug, Clone)]
struct MethodRecord {
    facts: MethodFacts,
    text: String,
    self_reported_full: bool,
}

#[derive(Debug, Default, Clone)]
struct ClassFacts {
    methods: BTreeMap<String, MethodRecord>,
    undecompiled: BTreeSet<String>,
}

type ClassMap = BTreeMap<String, ClassFacts>;

fn parse_class_body(lx: &Lexed, from: usize, to: usize) -> ClassFacts {
    let mut out: ClassFacts = ClassFacts::default();
    let mut depth: i32 = 0;
    let mut i: usize = from;
    while i < to {
        if lx.is_punct(i, '{') {
            depth += 1;
            i += 1;
            continue;
        }
        if lx.is_punct(i, '}') {
            depth -= 1;
            i += 1;
            continue;
        }
        if depth != 0 || lx.ident_at(i) != Some("function") {
            i += 1;
            continue;
        }
        let mut cursor: usize = i + 1;
        let accessor: Option<&str> = lx
            .ident_at(cursor)
            .filter(|k: &&str| matches!(*k, "get" | "set"))
            .filter(|_| lx.name_at(cursor + 1).is_some());
        let key: String = match accessor {
            Some(kind) => {
                let name: &str = lx.name_at(cursor + 1).unwrap_or("");
                cursor += 2;
                format!("{kind} {name}")
            }
            None => match lx.name_at(cursor) {
                Some(name) => {
                    let owned: String = name.to_owned();
                    cursor += 1;
                    owned
                }
                None => {
                    i += 1;
                    continue;
                }
            },
        };
        let Some(open) = find_brace_open(lx, cursor) else {
            i = cursor;
            continue;
        };
        let Some(close) = match_brace(lx, open) else {
            i = open + 1;
            continue;
        };
        if body_is_undecompiled(lx, open + 1, close) {
            out.undecompiled.insert(key);
        } else {
            out.methods.insert(
                key,
                MethodRecord {
                    facts: facts_of(lx, open + 1, close),
                    text: lx.text(open + 1, close),
                    self_reported_full: false,
                },
            );
        }
        i = close + 1;
    }
    out
}

fn parse_reference_source(src: &str) -> ClassMap {
    let lx: Lexed = lex(src);
    let mut out: ClassMap = ClassMap::new();
    let mut package: Option<String> = None;
    let mut i: usize = 0;
    while i < lx.toks.len() {
        match lx.ident_at(i) {
            Some("package") => {
                let mut j: usize = i + 1;
                let mut name: String = String::new();
                loop {
                    match lx.toks.get(j) {
                        Some(Token::Ident(s) | Token::Escaped(s)) => {
                            name.push_str(s);
                            j += 1;
                        }
                        Some(Token::Punct('.')) => {
                            name.push('.');
                            j += 1;
                        }
                        _ => break,
                    }
                }
                package = Some(name);
                i = j;
            }
            Some("class" | "interface") if package.is_some() => {
                let Some(simple) = lx.name_at(i + 1) else {
                    i += 1;
                    continue;
                };
                let prefix: &str = package.as_deref().unwrap_or_default();
                let fqn: String = if prefix.is_empty() {
                    simple.to_owned()
                } else {
                    format!("{prefix}.{simple}")
                };
                let Some(open) = find_brace_open(&lx, i + 2) else {
                    i += 2;
                    continue;
                };
                let Some(close) = match_brace(&lx, open) else {
                    i = open + 1;
                    continue;
                };
                out.insert(fqn, parse_class_body(&lx, open + 1, close));
                i = close + 1;
            }
            _ => i += 1,
        }
    }
    out
}

fn strip_expr(expr: &Expr) -> Expr {
    match expr {
        Expr::Coerce { operand, .. } => strip_expr(operand),
        Expr::Get { object, property } => Expr::Get {
            object: Box::new(strip_expr(object)),
            property: property.clone(),
        },
        Expr::Index { object, index } => Expr::Index {
            object: Box::new(strip_expr(object)),
            index: Box::new(strip_expr(index)),
        },
        Expr::Call {
            callee,
            property,
            args,
        } => Expr::Call {
            callee: Box::new(strip_expr(callee)),
            property: property.clone(),
            args: strip_args(args),
        },
        Expr::Construct {
            callee,
            property,
            args,
        } => Expr::Construct {
            callee: Box::new(strip_expr(callee)),
            property: property.clone(),
            args: strip_args(args),
        },
        Expr::New { ty, args } => Expr::New {
            ty: Box::new(strip_expr(ty)),
            args: strip_args(args),
        },
        Expr::Array(items) => Expr::Array(strip_args(items)),
        Expr::Object(pairs) => Expr::Object(
            pairs
                .iter()
                .map(|(k, v): &(Expr, Expr)| (strip_expr(k), strip_expr(v)))
                .collect(),
        ),
        Expr::Unary { op, operand } => Expr::Unary {
            op,
            operand: Box::new(strip_expr(operand)),
        },
        Expr::Binary { op, lhs, rhs } => Expr::Binary {
            op,
            lhs: Box::new(strip_expr(lhs)),
            rhs: Box::new(strip_expr(rhs)),
        },
        Expr::Typeof(inner) => Expr::Typeof(Box::new(strip_expr(inner))),
        Expr::Delete { object, property } => Expr::Delete {
            object: Box::new(strip_expr(object)),
            property: property.clone(),
        },
        Expr::Descendants { object, property } => Expr::Descendants {
            object: Box::new(strip_expr(object)),
            property: property.clone(),
        },
        Expr::Applied { base, args } => Expr::Applied {
            base: Box::new(strip_expr(base)),
            args: strip_args(args),
        },
        Expr::IsType { operand, ty } => Expr::IsType {
            operand: Box::new(strip_expr(operand)),
            ty: Box::new(strip_expr(ty)),
        },
        Expr::AsType { operand, ty } => Expr::AsType {
            operand: Box::new(strip_expr(operand)),
            ty: Box::new(strip_expr(ty)),
        },
        other => other.clone(),
    }
}

fn strip_args(args: &[Expr]) -> Vec<Expr> {
    args.iter().map(strip_expr).collect()
}

fn strip_stmts(stmts: &[Stmt]) -> Vec<Stmt> {
    stmts.iter().map(strip_stmt).collect()
}

fn strip_stmt(stmt: &Stmt) -> Stmt {
    match stmt {
        Stmt::Assign { target, value } => Stmt::Assign {
            target: strip_expr(target),
            value: strip_expr(value),
        },
        Stmt::AssignProperty {
            object,
            property,
            value,
        } => Stmt::AssignProperty {
            object: strip_expr(object),
            property: property.clone(),
            value: strip_expr(value),
        },
        Stmt::AssignIndex {
            object,
            index,
            value,
        } => Stmt::AssignIndex {
            object: strip_expr(object),
            index: strip_expr(index),
            value: strip_expr(value),
        },
        Stmt::Expression(e) => Stmt::Expression(strip_expr(e)),
        Stmt::Return(e) => Stmt::Return(e.as_ref().map(strip_expr)),
        Stmt::If { cond, target_label } => Stmt::If {
            cond: strip_expr(cond),
            target_label: *target_label,
        },
        Stmt::Throw(e) => Stmt::Throw(strip_expr(e)),
        Stmt::Switch {
            selector,
            case_labels,
            default_label,
        } => Stmt::Switch {
            selector: strip_expr(selector),
            case_labels: case_labels.clone(),
            default_label: *default_label,
        },
        Stmt::StructuredSwitch { selector, cases } => Stmt::StructuredSwitch {
            selector: strip_expr(selector),
            cases: cases
                .iter()
                .map(|case: &SwitchCase| SwitchCase {
                    labels: case
                        .labels
                        .iter()
                        .map(|label: &CaseLabel| match label {
                            CaseLabel::Expr(e) => CaseLabel::Expr(strip_expr(e)),
                            other => other.clone(),
                        })
                        .collect(),
                    body: strip_stmts(&case.body),
                    breaks: case.breaks,
                })
                .collect(),
        },
        Stmt::IfBlock { cond, body } => Stmt::IfBlock {
            cond: strip_expr(cond),
            body: strip_stmts(body),
        },
        Stmt::IfElse {
            cond,
            then_body,
            else_body,
        } => Stmt::IfElse {
            cond: strip_expr(cond),
            then_body: strip_stmts(then_body),
            else_body: strip_stmts(else_body),
        },
        Stmt::While { cond, body } => Stmt::While {
            cond: strip_expr(cond),
            body: strip_stmts(body),
        },
        Stmt::DoWhile { cond, body } => Stmt::DoWhile {
            cond: strip_expr(cond),
            body: strip_stmts(body),
        },
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => Stmt::For {
            init: Box::new(strip_stmt(init)),
            cond: strip_expr(cond),
            update: Box::new(strip_stmt(update)),
            body: strip_stmts(body),
        },
        Stmt::ForEach {
            var,
            collection,
            body,
        } => Stmt::ForEach {
            var: strip_expr(var),
            collection: strip_expr(collection),
            body: strip_stmts(body),
        },
        Stmt::ForIn {
            var,
            collection,
            body,
        } => Stmt::ForIn {
            var: strip_expr(var),
            collection: strip_expr(collection),
            body: strip_stmts(body),
        },
        Stmt::Try { body, catches } => Stmt::Try {
            body: strip_stmts(body),
            catches: catches
                .iter()
                .map(|catch: &CatchClause| CatchClause {
                    var_name: catch.var_name.clone(),
                    type_name: catch.type_name.clone(),
                    body: strip_stmts(&catch.body),
                })
                .collect(),
        },
        Stmt::With { object, body } => Stmt::With {
            object: strip_expr(object),
            body: strip_stmts(body),
        },
        other => other.clone(),
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct LiftAccounting {
    class_initializers: usize,
    script_initializers: usize,
    unnamed_bodies: usize,
    lift_errors: usize,
}

fn trait_key(abc_file: &AbcFile, info: &TraitInfo) -> Option<String> {
    let name: String = abc_file
        .cpool
        .render_multiname_property(info.name_index)
        .ok()?;
    match info.kind & 0x0F {
        TRAIT_KIND_METHOD => Some(name),
        TRAIT_KIND_GETTER => Some(format!("get {name}")),
        TRAIT_KIND_SETTER => Some(format!("set {name}")),
        _ => None,
    }
}

fn lifted_record(
    abc_file: &AbcFile,
    method_idx: u32,
    bodies: &BTreeMap<u32, usize>,
    account: &mut LiftAccounting,
) -> Option<MethodRecord> {
    let position: usize = *bodies.get(&method_idx)?;
    let body: &MethodBody = abc_file.method_bodies.get(position)?;
    let info: Option<&MethodInfo> = abc_file.methods.get(method_idx as usize);
    let Ok(mut lifted): Result<LiftedBody, _> = lift_body(abc_file, body, info) else {
        account.lift_errors += 1;
        return Some(MethodRecord {
            facts: MethodFacts::default(),
            text: "<disrobe lift returned an error for this body>".to_owned(),
            self_reported_full: false,
        });
    };
    let self_reported_full: bool = lifted.fully_recovered;
    lifted.statements = strip_stmts(&lifted.statements);
    let names: LocalNames = local_names_for(abc_file, info);
    let text: String = render_body(&lifted, &names, "");
    let lx: Lexed = lex(&text);
    let end: usize = lx.toks.len();
    Some(MethodRecord {
        facts: facts_of(&lx, 0, end),
        text,
        self_reported_full,
    })
}

fn disrobe_classes(bytes: &[u8]) -> (ClassMap, LiftAccounting) {
    let mut out: ClassMap = ClassMap::new();
    let mut account: LiftAccounting = LiftAccounting::default();
    let Ok(parsed): Result<Swf, _> = swf::parse(bytes) else {
        return (out, account);
    };
    for blob in parsed.collect_do_abc() {
        let blob: DoAbc = blob;
        let Ok(abc_file): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
            continue;
        };
        let bodies: BTreeMap<u32, usize> = abc_file
            .method_bodies
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &MethodBody)| (b.method, i))
            .collect();
        let mut named: BTreeSet<u32> = BTreeSet::new();
        account.script_initializers += abc_file.scripts.len();
        for script in &abc_file.scripts {
            named.insert(script.init);
        }
        for (idx, instance) in abc_file.instances.iter().enumerate() {
            let instance: &InstanceInfo = instance;
            let Ok(fqn): Result<String, _> = abc_file.cpool.render_multiname(instance.name_index)
            else {
                continue;
            };
            let simple: String = fqn.rsplit('.').next().unwrap_or(fqn.as_str()).to_owned();
            let entry: &mut ClassFacts = out.entry(fqn).or_default();
            named.insert(instance.iinit);
            if let Some(record) = lifted_record(&abc_file, instance.iinit, &bodies, &mut account) {
                entry.methods.insert(simple, record);
            }
            let class_info: Option<&ClassInfo> = abc_file.classes.get(idx);
            if let Some(class_info) = class_info {
                account.class_initializers += 1;
                named.insert(class_info.cinit);
            }
            let instance_traits: std::slice::Iter<'_, TraitInfo> = instance.traits.iter();
            let static_traits: std::slice::Iter<'_, TraitInfo> =
                class_info.map_or_else(|| [].iter(), |c: &ClassInfo| c.traits.iter());
            for info in instance_traits.chain(static_traits) {
                named.insert(info.method_index);
                let Some(key): Option<String> = trait_key(&abc_file, info) else {
                    continue;
                };
                if let Some(record) =
                    lifted_record(&abc_file, info.method_index, &bodies, &mut account)
                {
                    entry.methods.insert(key, record);
                }
            }
        }
        account.unnamed_bodies += abc_file
            .method_bodies
            .iter()
            .filter(|b: &&MethodBody| !named.contains(&b.method))
            .count();
    }
    (out, account)
}

fn reference_jar() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(explicit) = std::env::var("DR_AS3_REF_JAR") {
        candidates.push(PathBuf::from(explicit));
    }
    let roots: Vec<PathBuf> = ["FFDEC_HOME", "USERPROFILE", "HOME"]
        .iter()
        .filter_map(|k: &&str| std::env::var(k).ok())
        .map(PathBuf::from)
        .chain(std::iter::once(PathBuf::from("/opt")))
        .collect();
    for root in roots {
        for tail in [
            PathBuf::from("ffdec-cli.jar"),
            PathBuf::from("ffdec.jar"),
            Path::new("tools").join("ffdec").join("ffdec-cli.jar"),
            Path::new("tools").join("ffdec").join("ffdec.jar"),
            Path::new("ffdec").join("ffdec-cli.jar"),
            Path::new("ffdec").join("ffdec.jar"),
        ] {
            candidates.push(root.join(tail));
        }
    }
    candidates.into_iter().find(|p: &PathBuf| p.is_file())
}

fn java_available() -> bool {
    Command::new("java")
        .arg("-version")
        .output()
        .is_ok_and(|o: Output| o.status.success())
}

fn corpus_root() -> PathBuf {
    if let Ok(over) = std::env::var("DR_AS3_CORPUS") {
        return PathBuf::from(over);
    }
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
}

fn export_reference(jar: &Path, swf_path: &Path, out_dir: &Path, size: u64) -> bool {
    let stamp: PathBuf = out_dir.join(".exported");
    let refresh: bool = std::env::var("DR_AS3_REF_REFRESH").is_ok();
    if !refresh
        && std::fs::read_to_string(&stamp).is_ok_and(|s: String| s.trim() == size.to_string())
    {
        return true;
    }
    let _ = std::fs::remove_dir_all(out_dir);
    if std::fs::create_dir_all(out_dir).is_err() {
        return false;
    }
    let status: Option<Output> = Command::new("java")
        .arg("-jar")
        .arg(jar)
        .arg("-format")
        .arg("script:as")
        .arg("-export")
        .arg("script")
        .arg(out_dir)
        .arg(swf_path)
        .output()
        .ok();
    let ok: bool = status.is_some_and(|o: Output| o.status.success());
    if ok {
        let _ = std::fs::write(&stamp, size.to_string());
    }
    ok
}

fn collect_as_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_as_files(&path, out);
        } else if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) == Some("as") {
            out.push(path);
        }
    }
}

fn reference_classes(dir: &Path) -> ClassMap {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_as_files(dir, &mut files);
    files.sort();
    let mut out: ClassMap = ClassMap::new();
    for file in files {
        let Ok(src): Result<String, _> = std::fs::read_to_string(&file) else {
            continue;
        };
        if !src.contains("package") {
            continue;
        }
        for (fqn, facts) in parse_reference_source(&src) {
            out.entry(fqn).or_default().merge(facts);
        }
    }
    out
}

impl ClassFacts {
    fn merge(&mut self, other: Self) {
        for (k, v) in other.methods {
            self.methods.entry(k).or_insert(v);
        }
        self.undecompiled.extend(other.undecompiled);
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    graded: usize,
    agreed: usize,
    ungraded_reference_failed: usize,
    reference_only_classes: usize,
    disrobe_only_classes: usize,
    shared_classes: usize,
    self_reported_full: usize,
    self_reported_full_agreed: usize,
}

#[derive(Debug, Clone)]
struct Disagreement {
    file: String,
    class: String,
    method: String,
    reason: String,
    reference_text: String,
    disrobe_text: String,
}

fn multiset_delta(a: &BTreeMap<String, usize>, b: &BTreeMap<String, usize>) -> String {
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    let mut parts: Vec<String> = Vec::new();
    for key in keys {
        let left: usize = a.get(key).copied().unwrap_or(0);
        let right: usize = b.get(key).copied().unwrap_or(0);
        if left != right {
            parts.push(format!("{key:?} ref={left} dis={right}"));
        }
    }
    parts.join(", ")
}

fn compare_method(
    reference: &MethodFacts,
    disrobe: &MethodFacts,
    graded_dimensions: &GradedDimensions,
) -> Option<String> {
    let mut reasons: Vec<String> = Vec::new();
    if graded_dimensions.strings && reference.strings != disrobe.strings {
        reasons.push(format!(
            "string literals differ: {}",
            multiset_delta(&reference.strings, &disrobe.strings)
        ));
    }
    if graded_dimensions.calls && reference.calls != disrobe.calls {
        reasons.push(format!(
            "called names differ: {}",
            multiset_delta(&reference.calls, &disrobe.calls)
        ));
    }
    if graded_dimensions.control && reference.control_shape() != disrobe.control_shape() {
        reasons.push(format!(
            "control shape differs: ref(if={},loop={},switch={},try={}) dis(if={},loop={},switch={},try={})",
            reference.ifs,
            reference.loops,
            reference.switches,
            reference.tries,
            disrobe.ifs,
            disrobe.loops,
            disrobe.switches,
            disrobe.tries
        ));
    }
    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join("; "))
    }
}

#[derive(Debug, Clone, Copy)]
struct GradedDimensions {
    strings: bool,
    calls: bool,
    control: bool,
}

impl GradedDimensions {
    const ALL: Self = Self {
        strings: true,
        calls: true,
        control: true,
    };
}

struct Measurement {
    tally: Tally,
    disagreements: Vec<Disagreement>,
    accounting: LiftAccounting,
    files_compared: usize,
    strings_only_failures: usize,
    calls_only_failures: usize,
    control_only_failures: usize,
    missing_methods: usize,
    extra_methods: usize,
}

fn measure(dimensions: GradedDimensions) -> Option<Measurement> {
    if !java_available() {
        eprintln!(
            "SKIP reference differential: `java` is not on PATH. Install a JRE, or run with the reference decompiler available."
        );
        return None;
    }
    let Some(jar): Option<PathBuf> = reference_jar() else {
        eprintln!(
            "SKIP reference differential: no reference decompiler jar found. Set DR_AS3_REF_JAR to an ffdec-cli.jar / ffdec.jar path, or install it under <home>/tools/ffdec/."
        );
        return None;
    };
    let corpus: PathBuf = corpus_root();
    let Ok(entries): Result<std::fs::ReadDir, _> = std::fs::read_dir(&corpus) else {
        eprintln!(
            "SKIP reference differential: corpus directory absent ({})",
            corpus.display()
        );
        return None;
    };
    let mut swfs: Vec<PathBuf> = entries
        .flatten()
        .map(|e: std::fs::DirEntry| e.path())
        .filter(|p: &PathBuf| {
            p.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) == Some("swf")
        })
        .collect();
    swfs.sort();
    if swfs.is_empty() {
        eprintln!(
            "SKIP reference differential: corpus holds no .swf fixtures ({})",
            corpus.display()
        );
        return None;
    }
    let scratch: PathBuf = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("as3-reference-export");
    let _ = std::fs::create_dir_all(&scratch);

    let mut tally: Tally = Tally::default();
    let mut disagreements: Vec<Disagreement> = Vec::new();
    let mut accounting: LiftAccounting = LiftAccounting::default();
    let mut files_compared: usize = 0;
    let mut strings_only_failures: usize = 0;
    let mut calls_only_failures: usize = 0;
    let mut control_only_failures: usize = 0;
    let mut missing_methods: usize = 0;
    let mut extra_methods: usize = 0;

    for swf_path in &swfs {
        let stem: String = swf_path
            .file_stem()
            .and_then(|s: &std::ffi::OsStr| s.to_str())
            .unwrap_or("unknown")
            .to_owned();
        let bytes: Vec<u8> = std::fs::read(swf_path).expect("read swf");
        let (disrobe_map, file_accounting): (ClassMap, LiftAccounting) = disrobe_classes(&bytes);
        let out_dir: PathBuf = scratch.join(&stem);
        let size: u64 = bytes.len() as u64;
        if !export_reference(&jar, swf_path, &out_dir, size) {
            eprintln!("  {stem}: reference decompiler export failed, file not graded");
            continue;
        }
        let reference_map: ClassMap = reference_classes(&out_dir);
        if reference_map.is_empty() && disrobe_map.is_empty() {
            continue;
        }
        files_compared += 1;
        accounting.class_initializers += file_accounting.class_initializers;
        accounting.script_initializers += file_accounting.script_initializers;
        accounting.unnamed_bodies += file_accounting.unnamed_bodies;
        accounting.lift_errors += file_accounting.lift_errors;

        let reference_names: BTreeSet<&String> = reference_map.keys().collect();
        let disrobe_names: BTreeSet<&String> = disrobe_map.keys().collect();
        for only in reference_names.difference(&disrobe_names) {
            tally.reference_only_classes += 1;
            disagreements.push(Disagreement {
                file: stem.clone(),
                class: (*only).clone(),
                method: "<class>".to_owned(),
                reason: "class present in the reference decompilation, absent from disrobe"
                    .to_owned(),
                reference_text: String::new(),
                disrobe_text: String::new(),
            });
        }
        for only in disrobe_names.difference(&reference_names) {
            tally.disrobe_only_classes += 1;
            disagreements.push(Disagreement {
                file: stem.clone(),
                class: (*only).clone(),
                method: "<class>".to_owned(),
                reason: "class present in disrobe, absent from the reference decompilation"
                    .to_owned(),
                reference_text: String::new(),
                disrobe_text: String::new(),
            });
        }
        for class_name in reference_names.intersection(&disrobe_names) {
            tally.shared_classes += 1;
            let reference_class: &ClassFacts = &reference_map[*class_name];
            let disrobe_class: &ClassFacts = &disrobe_map[*class_name];
            tally.ungraded_reference_failed += reference_class.undecompiled.len();
            let keys: BTreeSet<&String> = reference_class
                .methods
                .keys()
                .chain(disrobe_class.methods.keys())
                .filter(|k: &&String| !reference_class.undecompiled.contains(*k))
                .collect();
            for key in keys {
                tally.graded += 1;
                match (
                    reference_class.methods.get(key),
                    disrobe_class.methods.get(key),
                ) {
                    (Some(reference), Some(disrobe)) => {
                        if disrobe.self_reported_full {
                            tally.self_reported_full += 1;
                        }
                        match compare_method(&reference.facts, &disrobe.facts, &dimensions) {
                            None => {
                                tally.agreed += 1;
                                if disrobe.self_reported_full {
                                    tally.self_reported_full_agreed += 1;
                                }
                            }
                            Some(reason) => {
                                let strings_differ: bool =
                                    reference.facts.strings != disrobe.facts.strings;
                                let calls_differ: bool =
                                    reference.facts.calls != disrobe.facts.calls;
                                let control_differ: bool = reference.facts.control_shape()
                                    != disrobe.facts.control_shape();
                                match (strings_differ, calls_differ, control_differ) {
                                    (true, false, false) => strings_only_failures += 1,
                                    (false, true, false) => calls_only_failures += 1,
                                    (false, false, true) => control_only_failures += 1,
                                    _ => {}
                                }
                                let claim: &str = if disrobe.self_reported_full {
                                    " [disrobe self-reports this body fully recovered]"
                                } else {
                                    ""
                                };
                                disagreements.push(Disagreement {
                                    file: stem.clone(),
                                    class: (*class_name).clone(),
                                    method: key.clone(),
                                    reason: format!("{reason}{claim}"),
                                    reference_text: reference.text.clone(),
                                    disrobe_text: disrobe.text.clone(),
                                });
                            }
                        }
                    }
                    (Some(reference), None) => {
                        missing_methods += 1;
                        disagreements.push(Disagreement {
                            file: stem.clone(),
                            class: (*class_name).clone(),
                            method: key.clone(),
                            reason:
                                "method present in the reference decompilation, absent from disrobe"
                                    .to_owned(),
                            reference_text: reference.text.clone(),
                            disrobe_text: String::new(),
                        });
                    }
                    (None, Some(disrobe)) => {
                        extra_methods += 1;
                        disagreements.push(Disagreement {
                            file: stem.clone(),
                            class: (*class_name).clone(),
                            method: key.clone(),
                            reason:
                                "method present in disrobe, absent from the reference decompilation"
                                    .to_owned(),
                            reference_text: String::new(),
                            disrobe_text: disrobe.text.clone(),
                        });
                    }
                    (None, None) => {}
                }
            }
        }
    }
    Some(Measurement {
        tally,
        disagreements,
        accounting,
        files_compared,
        strings_only_failures,
        calls_only_failures,
        control_only_failures,
        missing_methods,
        extra_methods,
    })
}

fn dump_limit() -> usize {
    std::env::var("DR_AS3_REF_DUMP")
        .ok()
        .and_then(|v: String| v.parse::<usize>().ok())
        .unwrap_or(20)
}

fn report(m: &Measurement) -> f64 {
    let rate: f64 = if m.tally.graded == 0 {
        0.0
    } else {
        100.0 * m.tally.agreed as f64 / m.tally.graded as f64
    };
    eprintln!("=== AS3 lift vs independent reference decompiler ===");
    eprintln!("files compared            : {}", m.files_compared);
    eprintln!(
        "classes                   : shared {} | reference-only {} | disrobe-only {}",
        m.tally.shared_classes, m.tally.reference_only_classes, m.tally.disrobe_only_classes
    );
    eprintln!(
        "methods graded            : {} (agreed {} => {rate:.2}%)",
        m.tally.graded, m.tally.agreed
    );
    eprintln!(
        "ungraded, reference failed: {}",
        m.tally.ungraded_reference_failed
    );
    eprintln!(
        "ungraded, no counterpart  : class initializers {} | script initializers {} | anonymous bodies {}",
        m.accounting.class_initializers,
        m.accounting.script_initializers,
        m.accounting.unnamed_bodies
    );
    eprintln!("disrobe lift errors       : {}", m.accounting.lift_errors);
    let claimed: usize = m.tally.self_reported_full;
    let claimed_rate: f64 = if claimed == 0 {
        0.0
    } else {
        100.0 * m.tally.self_reported_full_agreed as f64 / claimed as f64
    };
    eprintln!(
        "bodies disrobe calls fully recovered: {claimed} (agreed {} => {claimed_rate:.2}%, disagreed {})",
        m.tally.self_reported_full_agreed,
        claimed.saturating_sub(m.tally.self_reported_full_agreed)
    );
    eprintln!(
        "disagreement breakdown    : strings-only {} | calls-only {} | control-only {} | mixed {} | missing {} | extra {}",
        m.strings_only_failures,
        m.calls_only_failures,
        m.control_only_failures,
        m.tally
            .graded
            .saturating_sub(m.tally.agreed)
            .saturating_sub(m.strings_only_failures)
            .saturating_sub(m.calls_only_failures)
            .saturating_sub(m.control_only_failures)
            .saturating_sub(m.missing_methods)
            .saturating_sub(m.extra_methods),
        m.missing_methods,
        m.extra_methods
    );
    let limit: usize = dump_limit();
    eprintln!(
        "[{} disagreement(s); first {} shown with both renderings, the rest as one line each (raise DR_AS3_REF_DUMP for more)]",
        m.disagreements.len(),
        limit.min(m.disagreements.len())
    );
    for (i, d) in m.disagreements.iter().enumerate() {
        eprintln!(
            "[{i}] {} :: {} :: {} | {}",
            d.file, d.class, d.method, d.reason
        );
        if i < limit {
            eprintln!(
                "  reference rendering:\n{}",
                indent_block(&d.reference_text)
            );
            eprintln!("  disrobe rendering:\n{}", indent_block(&d.disrobe_text));
        }
    }
    rate
}

fn indent_block(text: &str) -> String {
    if text.trim().is_empty() {
        return "    <empty>".to_owned();
    }
    text.lines()
        .map(|l: &str| format!("    {l}"))
        .collect::<Vec<String>>()
        .join("\n")
}

#[test]
#[ignore = "needs java and an external reference decompiler; run with --ignored"]
fn as3_lift_agrees_with_an_independent_reference_decompiler() {
    let Some(m): Option<Measurement> = measure(GradedDimensions::ALL) else {
        return;
    };
    let rate: f64 = report(&m);
    assert_population(&m);
    assert!(
        m.tally.shared_classes >= 1971,
        "the corpus must keep matching the reference on the bulk of its classes, got {}",
        m.tally.shared_classes
    );
    assert!(
        m.tally.reference_only_classes <= 36,
        "disrobe must not start losing more classes than the 36 whose package survives only in the defining script, got {}",
        m.tally.reference_only_classes
    );
    assert!(
        m.tally.agreed * 1000 >= m.tally.graded * 847,
        "per-method agreement with the independent reference decompiler must hold its measured floor (>=84.7%); got {}/{} = {rate:.2}%",
        m.tally.agreed,
        m.tally.graded
    );
    assert!(
        m.tally.self_reported_full_agreed * 1000 >= m.tally.self_reported_full * 966,
        "bodies disrobe calls fully recovered must hold their measured agreement floor (>=96.6%); got {}/{}",
        m.tally.self_reported_full_agreed,
        m.tally.self_reported_full
    );
}

fn assert_population(m: &Measurement) {
    assert!(
        m.files_compared >= 5,
        "the differential must compare several real files, got {}",
        m.files_compared
    );
    assert!(
        m.tally.graded >= 13000,
        "the graded population must stay large enough to be meaningful, got {}",
        m.tally.graded
    );
    assert!(
        m.tally.ungraded_reference_failed * 10 <= m.tally.graded,
        "no more than a tenth of the population may drop out because the reference decompiler failed; got {} ungraded against {} graded",
        m.tally.ungraded_reference_failed,
        m.tally.graded
    );
}

#[test]
#[ignore = "needs java and an external reference decompiler; run with --ignored"]
fn string_literals_and_call_targets_match_the_reference_almost_everywhere() {
    let dimensions: GradedDimensions = GradedDimensions {
        strings: true,
        calls: true,
        control: false,
    };
    let Some(m): Option<Measurement> = measure(dimensions) else {
        return;
    };
    let rate: f64 = report(&m);
    assert_population(&m);
    assert!(
        m.tally.agreed * 1000 >= m.tally.graded * 950,
        "constant-pool and call-target agreement must hold its measured floor (>=95.0%); got {}/{} = {rate:.2}%",
        m.tally.agreed,
        m.tally.graded
    );
}
