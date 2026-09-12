use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_pickle::{PickleValue, to_python};
use serde::{Deserialize, Serialize};

use crate::body::{
    BodyLift, LiftFidelity, PythonExpr, PythonStmt, c_code_mask_with_nuitka_python_abi,
    extract_c_function_body_by_symbol_with_mask, lift_body_with_source, render_const_token,
    resolve_const_items, resolve_const_token,
};
use crate::c_module::{CCodeObject, CConstReturn, CFunctionWiring, CImplBody, CModuleStructure};
use crate::constants::{ConstantsPool, builtin_type_name, nuitka_bytes_repr, nuitka_value_repr};
use crate::error::Error;
use crate::limits::validate_c_source;
use crate::skeleton::{SkeletonFunction, SkeletonModule, SkeletonParam};
use crate::symbols::SymbolGraph;
use crate::{DemangledFunction, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceFidelity {
    StructuredFromCSource,
    NamesOnly,
}

impl From<SurfaceFidelity> for disrobe_core::RecoverySignal {
    #[inline]
    fn from(fidelity: SurfaceFidelity) -> Self {
        match fidelity {
            SurfaceFidelity::StructuredFromCSource => Self::StructuredNoVerify,
            SurfaceFidelity::NamesOnly => Self::SignaturesOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParamStar {
    None,
    Args,
    Kwargs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceParam {
    pub name: String,
    pub annotation: Option<String>,
    pub default: Option<String>,
    pub star: ParamStar,
    #[serde(default)]
    pub positional_only: bool,
    #[serde(default)]
    pub keyword_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceFunction {
    pub name: String,
    pub source_index: u32,
    pub params: Vec<SurfaceParam>,
    pub return_annotation: Option<String>,
    pub docstring: Option<String>,
    pub body_recovered: bool,
    pub body_stmts: Vec<PythonStmt>,
    pub lift_fidelity: LiftFidelity,
    pub unrecognized_c_lines: Vec<String>,
    pub source_line: Option<u32>,
    pub parent_names: Vec<String>,
    pub nested: Vec<Self>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceModule {
    pub module_name: String,
    pub functions: Vec<SurfaceFunction>,
    pub has_main_guard: bool,
    pub python_source: String,
    pub fidelity: SurfaceFidelity,
    pub notes: Vec<String>,
}

const RETURN_KEY: &str = "return";

#[inline]
fn strip_builtins(rendered: &str) -> String {
    rendered
        .strip_prefix("builtins.")
        .unwrap_or(rendered)
        .to_owned()
}

fn lookup_annotation(pairs: &[(PickleValue, PickleValue)], key: &str) -> Option<String> {
    for (k, v) in pairs {
        if let PickleValue::Str(s) = k
            && s == key
        {
            return render_annotation_value(v);
        }
    }
    None
}

fn annotation_dict_for_wiring<'a>(
    wiring: Option<&CFunctionWiring>,
    pool: &'a ConstantsPool,
) -> Option<&'a [(PickleValue, PickleValue)]> {
    let digest: &str = wiring
        .and_then(|wiring: &CFunctionWiring| wiring.annotations_dict_const.as_deref())?
        .strip_prefix("const_dict_")?;
    (!pool.ambiguous_dict_digests.contains(digest))
        .then(|| pool.dict_pairs_for_digest(digest))
        .flatten()
}

fn render_annotation_value(value: &PickleValue) -> Option<String> {
    if let PickleValue::Global { module, name } = value
        && let Some(name) = builtin_type_name(module, name)
    {
        return Some(name.to_owned());
    }
    if let PickleValue::Str(s) = value
        && is_safe_annotation_expression(s)
    {
        return Some(s.clone());
    }
    render_static_pickle_value(value)
}

fn render_annotation_source(annotation: &str) -> String {
    let value: PickleValue = PickleValue::Str(annotation.to_owned());
    if let Some(rendered) = render_annotation_value(&value) {
        return rendered;
    }
    to_python(&value)
}

const MAX_STATIC_PICKLE_DEPTH: usize = 256;

fn render_static_pickle_value(value: &PickleValue) -> Option<String> {
    if !is_static_pickle_value(value, 0usize) {
        return None;
    }
    if contains_nonfinite_float(value, 0usize) {
        return render_static_pickle_value_with_nonfinite_float(value, 0usize);
    }
    let exact_repr: Option<String> = nuitka_value_repr(value, 0usize);
    if let Some(rendered) = exact_repr {
        return Some(rendered);
    }
    Some(strip_builtins(&to_python(value)))
}

fn render_static_pickle_value_with_nonfinite_float(
    value: &PickleValue,
    depth: usize,
) -> Option<String> {
    if depth >= MAX_STATIC_PICKLE_DEPTH {
        return None;
    }
    let next: usize = depth + 1usize;
    match value {
        PickleValue::Float(value) if !value.is_finite() => Some(render_nonfinite_float(*value)),
        PickleValue::List(values) => render_static_sequence(values, '[', ']', false, next),
        PickleValue::Tuple(values) => render_static_sequence(values, '(', ')', true, next),
        PickleValue::Set(values) => {
            if values.is_empty() {
                Some("set()".to_owned())
            } else {
                render_static_sequence(values, '{', '}', false, next)
            }
        }
        PickleValue::FrozenSet(values) => {
            if values.is_empty() {
                Some("frozenset()".to_owned())
            } else {
                let rendered: String = render_static_sequence(values, '{', '}', false, next)?;
                Some(format!("frozenset({rendered})"))
            }
        }
        PickleValue::Dict(pairs) => render_static_dict(pairs, next),
        _ => nuitka_value_repr(value, depth).or_else(|| Some(strip_builtins(&to_python(value)))),
    }
}

fn render_static_sequence(
    values: &[PickleValue],
    open: char,
    close: char,
    singleton_comma: bool,
    depth: usize,
) -> Option<String> {
    let mut rendered: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        rendered.push(render_static_pickle_value_with_nonfinite_float(
            value, depth,
        )?);
    }
    let mut joined: String = rendered.join(", ");
    if singleton_comma && rendered.len() == 1usize {
        joined.push(',');
    }
    Some(format!("{open}{joined}{close}"))
}

fn render_static_dict(pairs: &[(PickleValue, PickleValue)], depth: usize) -> Option<String> {
    let mut rendered: Vec<String> = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let key: String = render_static_pickle_value_with_nonfinite_float(key, depth)?;
        let value: String = render_static_pickle_value_with_nonfinite_float(value, depth)?;
        rendered.push(format!("{key}: {value}"));
    }
    Some(format!("{{{}}}", rendered.join(", ")))
}

fn render_nonfinite_float(value: f64) -> String {
    if value == f64::INFINITY {
        return "float('inf')".to_owned();
    }
    if value == f64::NEG_INFINITY {
        return "float('-inf')".to_owned();
    }
    let bytes: [u8; 8] = value.to_bits().to_be_bytes();
    let literal: String = nuitka_bytes_repr(&bytes);
    format!("__import__('struct').unpack('>d', {literal})[0]")
}

fn contains_nonfinite_float(value: &PickleValue, depth: usize) -> bool {
    if depth >= MAX_STATIC_PICKLE_DEPTH {
        return true;
    }
    let next: usize = depth + 1usize;
    match value {
        PickleValue::Float(value) => !value.is_finite(),
        PickleValue::List(items)
        | PickleValue::Tuple(items)
        | PickleValue::Set(items)
        | PickleValue::FrozenSet(items) => items
            .iter()
            .any(|item: &PickleValue| contains_nonfinite_float(item, next)),
        PickleValue::Dict(pairs) => pairs
            .iter()
            .any(|(key, item): &(PickleValue, PickleValue)| {
                contains_nonfinite_float(key, next) || contains_nonfinite_float(item, next)
            }),
        PickleValue::None
        | PickleValue::Bool(_)
        | PickleValue::Int(_)
        | PickleValue::BigInt(_)
        | PickleValue::Str(_)
        | PickleValue::Bytes(_)
        | PickleValue::Global { .. }
        | PickleValue::Ext { .. }
        | PickleValue::OutOfBandBuffer { .. }
        | PickleValue::PersId { .. }
        | PickleValue::Reduce { .. }
        | PickleValue::Object { .. }
        | PickleValue::MemoRef { .. } => false,
    }
}

fn is_static_pickle_value(value: &PickleValue, depth: usize) -> bool {
    if depth >= MAX_STATIC_PICKLE_DEPTH {
        return false;
    }
    let next: usize = depth + 1;
    match value {
        PickleValue::None
        | PickleValue::Bool(_)
        | PickleValue::Int(_)
        | PickleValue::Float(_)
        | PickleValue::Str(_)
        | PickleValue::Bytes(_) => true,
        PickleValue::BigInt(value) => is_canonical_decimal_integer(value),
        PickleValue::List(items) | PickleValue::Tuple(items) => items
            .iter()
            .all(|item: &PickleValue| is_static_pickle_value(item, next)),
        PickleValue::Set(items) | PickleValue::FrozenSet(items) => items
            .iter()
            .all(|item: &PickleValue| is_static_pickle_hashable(item, next)),
        PickleValue::Dict(pairs) => pairs
            .iter()
            .all(|(key, item): &(PickleValue, PickleValue)| {
                is_static_pickle_hashable(key, next) && is_static_pickle_value(item, next)
            }),
        PickleValue::Global { .. }
        | PickleValue::Ext { .. }
        | PickleValue::OutOfBandBuffer { .. }
        | PickleValue::PersId { .. }
        | PickleValue::Reduce { .. }
        | PickleValue::Object { .. }
        | PickleValue::MemoRef { .. } => false,
    }
}

fn is_static_pickle_hashable(value: &PickleValue, depth: usize) -> bool {
    if depth >= MAX_STATIC_PICKLE_DEPTH {
        return false;
    }
    let next: usize = depth + 1;
    match value {
        PickleValue::None
        | PickleValue::Bool(_)
        | PickleValue::Int(_)
        | PickleValue::Float(_)
        | PickleValue::Str(_)
        | PickleValue::Bytes(_) => true,
        PickleValue::BigInt(value) => is_canonical_decimal_integer(value),
        PickleValue::Tuple(items) | PickleValue::FrozenSet(items) => items
            .iter()
            .all(|item: &PickleValue| is_static_pickle_hashable(item, next)),
        PickleValue::List(_)
        | PickleValue::Set(_)
        | PickleValue::Dict(_)
        | PickleValue::Global { .. }
        | PickleValue::Ext { .. }
        | PickleValue::OutOfBandBuffer { .. }
        | PickleValue::PersId { .. }
        | PickleValue::Reduce { .. }
        | PickleValue::Object { .. }
        | PickleValue::MemoRef { .. } => false,
    }
}

fn is_canonical_decimal_integer(value: &str) -> bool {
    let digits: &str = value.strip_prefix('-').map_or(value, |digits: &str| digits);
    if digits.is_empty() || !digits.bytes().all(|byte: u8| byte.is_ascii_digit()) {
        return false;
    }
    digits == "0" || !digits.starts_with('0')
}

const MAX_ANNOTATION_EXPRESSION_BYTES: usize = 8_192usize;
const MAX_ANNOTATION_NESTING: usize = 64usize;

#[derive(Clone, Copy)]
enum AnnotationToken<'a> {
    Identifier(&'a str),
    Integer,
    Quoted,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Dot,
    Pipe,
    Star,
    Minus,
    Ellipsis,
}

fn is_safe_annotation_expression(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ANNOTATION_EXPRESSION_BYTES {
        return false;
    }
    let Some(tokens): Option<Vec<AnnotationToken<'_>>> = tokenize_annotation_expression(value)
    else {
        return false;
    };
    let mut parser: AnnotationExpressionParser<'_> = AnnotationExpressionParser {
        tokens: &tokens,
        position: 0usize,
        nesting: 0usize,
    };
    parser.parse_union() && parser.position == tokens.len()
}

fn tokenize_annotation_expression(value: &str) -> Option<Vec<AnnotationToken<'_>>> {
    let bytes: &[u8] = value.as_bytes();
    let mut tokens: Vec<AnnotationToken<'_>> = Vec::new();
    let mut position: usize = 0usize;
    while position < bytes.len() {
        match bytes[position] {
            b' ' | b'\t' => position += 1usize,
            b'[' => {
                tokens.push(AnnotationToken::LBracket);
                position += 1usize;
            }
            b']' => {
                tokens.push(AnnotationToken::RBracket);
                position += 1usize;
            }
            b'(' => {
                tokens.push(AnnotationToken::LParen);
                position += 1usize;
            }
            b')' => {
                tokens.push(AnnotationToken::RParen);
                position += 1usize;
            }
            b',' => {
                tokens.push(AnnotationToken::Comma);
                position += 1usize;
            }
            b'|' => {
                tokens.push(AnnotationToken::Pipe);
                position += 1usize;
            }
            b'*' => {
                tokens.push(AnnotationToken::Star);
                position += 1usize;
            }
            b'-' => {
                tokens.push(AnnotationToken::Minus);
                position += 1usize;
            }
            b'.' if bytes.get(position..position + 3usize) == Some(b"...".as_slice()) => {
                tokens.push(AnnotationToken::Ellipsis);
                position += 3usize;
            }
            b'.' => {
                tokens.push(AnnotationToken::Dot);
                position += 1usize;
            }
            b'\'' | b'"' => {
                position = annotation_quoted_end(bytes, position)?;
                tokens.push(AnnotationToken::Quoted);
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start: usize = position;
                position += 1usize;
                while bytes
                    .get(position)
                    .is_some_and(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    position += 1usize;
                }
                tokens.push(AnnotationToken::Identifier(value.get(start..position)?));
            }
            byte if byte.is_ascii_digit() => {
                let start: usize = position;
                position += 1usize;
                while bytes
                    .get(position)
                    .is_some_and(|byte: &u8| byte.is_ascii_digit() || *byte == b'_')
                {
                    position += 1usize;
                }
                let integer: &str = value.get(start..position)?;
                if !valid_annotation_integer(integer) {
                    return None;
                }
                tokens.push(AnnotationToken::Integer);
            }
            _ => return None,
        }
    }
    (!tokens.is_empty()).then_some(tokens)
}

fn annotation_quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote: u8 = *bytes.get(start)?;
    let mut position: usize = start.checked_add(1usize)?;
    while position < bytes.len() {
        match bytes[position] {
            b'\\' => position = annotation_escape_end(bytes, position)?,
            b'\r' | b'\n' => return None,
            byte if byte == quote => return position.checked_add(1usize),
            byte if annotation_raw_string_byte_is_safe(byte) => position += 1usize,
            _ => return None,
        }
    }
    None
}

const fn annotation_raw_string_byte_is_safe(byte: u8) -> bool {
    matches!(byte, b' '..=b'~') || byte >= 0x80u8
}

fn annotation_escape_end(bytes: &[u8], slash: usize) -> Option<usize> {
    let kind_position: usize = slash.checked_add(1usize)?;
    let kind: u8 = *bytes.get(kind_position)?;
    let after_kind: usize = kind_position.checked_add(1usize)?;
    match kind {
        b'\\' | b'\'' | b'"' | b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v' => Some(after_kind),
        b'0'..=b'7' => {
            let mut position: usize = after_kind;
            let mut digits: usize = 1usize;
            while digits < 3usize
                && bytes
                    .get(position)
                    .is_some_and(|byte: &u8| byte.is_ascii_digit() && *byte <= b'7')
            {
                position += 1usize;
                digits += 1usize;
            }
            Some(position)
        }
        b'x' => annotation_hex_escape_end(bytes, after_kind, 2usize),
        b'u' => annotation_unicode_escape_end(bytes, after_kind, 4usize),
        b'U' => annotation_unicode_escape_end(bytes, after_kind, 8usize),
        _ => None,
    }
}

fn annotation_hex_escape_end(bytes: &[u8], start: usize, width: usize) -> Option<usize> {
    let end: usize = start.checked_add(width)?;
    let digits: &[u8] = bytes.get(start..end)?;
    digits
        .iter()
        .all(|byte: &u8| byte.is_ascii_hexdigit())
        .then_some(end)
}

fn annotation_unicode_escape_end(bytes: &[u8], start: usize, width: usize) -> Option<usize> {
    let end: usize = annotation_hex_escape_end(bytes, start, width)?;
    let digits: &str = core::str::from_utf8(bytes.get(start..end)?).ok()?;
    let scalar: u32 = u32::from_str_radix(digits, 16u32).ok()?;
    char::from_u32(scalar).map(|_: char| end)
}

fn valid_annotation_integer(value: &str) -> bool {
    let mut digits: usize = 0usize;
    let mut first_digit: Option<u8> = None;
    let mut previous_underscore: bool = false;
    for byte in value.bytes() {
        if byte == b'_' {
            if digits == 0usize || previous_underscore {
                return false;
            }
            previous_underscore = true;
        } else {
            first_digit.get_or_insert(byte);
            digits += 1usize;
            previous_underscore = false;
        }
    }
    digits > 0usize && !previous_underscore && !(digits > 1usize && first_digit == Some(b'0'))
}

struct AnnotationExpressionParser<'a> {
    tokens: &'a [AnnotationToken<'a>],
    position: usize,
    nesting: usize,
}

impl<'a> AnnotationExpressionParser<'a> {
    fn parse_union(&mut self) -> bool {
        if !self.parse_primary() {
            return false;
        }
        while self.consume_pipe() {
            if !self.parse_primary() {
                return false;
            }
        }
        true
    }

    fn parse_primary(&mut self) -> bool {
        let negative: bool = self.consume_minus();
        let Some(token): Option<AnnotationToken<'a>> = self.next() else {
            return false;
        };
        let mut attribute_allowed: bool = true;
        match token {
            AnnotationToken::Integer => attribute_allowed = false,
            AnnotationToken::Identifier(identifier)
                if !negative && is_annotation_identifier(identifier) => {}
            AnnotationToken::Quoted | AnnotationToken::Ellipsis if !negative => {}
            AnnotationToken::LParen => {
                if negative {
                    return false;
                }
                if !self.parse_parenthesized() {
                    return false;
                }
            }
            _ => return false,
        }
        loop {
            if self.consume_dot() {
                if !attribute_allowed {
                    return false;
                }
                let Some(AnnotationToken::Identifier(identifier)): Option<AnnotationToken<'a>> =
                    self.next()
                else {
                    return false;
                };
                if !is_annotation_identifier(identifier) {
                    return false;
                }
                continue;
            }
            if !self.consume_lbracket() {
                break;
            }
            if !self.parse_subscript_items() {
                return false;
            }
            attribute_allowed = true;
        }
        true
    }

    fn parse_parenthesized(&mut self) -> bool {
        if !self.enter_nesting() {
            return false;
        }
        if self.consume_rparen() {
            self.leave_nesting();
            return true;
        }
        if !self.parse_argument_list(AnnotationToken::RParen) {
            return false;
        }
        self.leave_nesting();
        true
    }

    fn parse_subscript_items(&mut self) -> bool {
        if !self.enter_nesting() {
            return false;
        }
        let parsed: bool = self.parse_argument_list(AnnotationToken::RBracket);
        if parsed {
            self.leave_nesting();
        }
        parsed
    }

    fn parse_argument_list(&mut self, terminator: AnnotationToken<'a>) -> bool {
        if !self.parse_argument() {
            return false;
        }
        while self.consume_comma() {
            if self.matches(terminator) {
                break;
            }
            if !self.parse_argument() {
                return false;
            }
        }
        self.consume(terminator)
    }

    fn parse_argument(&mut self) -> bool {
        if self.consume_star() {
            return self.parse_union();
        }
        if self.consume_lbracket() {
            if !self.enter_nesting() {
                return false;
            }
            if self.consume_rbracket() {
                self.leave_nesting();
                return true;
            }
            let parsed: bool = self.parse_argument_list(AnnotationToken::RBracket);
            if parsed {
                self.leave_nesting();
            }
            return parsed;
        }
        self.parse_union()
    }

    const fn enter_nesting(&mut self) -> bool {
        let Some(next): Option<usize> = self.nesting.checked_add(1usize) else {
            return false;
        };
        if next > MAX_ANNOTATION_NESTING {
            return false;
        }
        self.nesting = next;
        true
    }

    const fn leave_nesting(&mut self) {
        self.nesting = self.nesting.saturating_sub(1usize);
    }

    fn next(&mut self) -> Option<AnnotationToken<'a>> {
        let token: AnnotationToken<'a> = *self.tokens.get(self.position)?;
        self.position = self.position.checked_add(1usize)?;
        Some(token)
    }

    fn consume(&mut self, token: AnnotationToken<'a>) -> bool {
        if !self.matches(token) {
            return false;
        }
        self.position = self.position.saturating_add(1usize);
        true
    }

    fn matches(&self, token: AnnotationToken<'a>) -> bool {
        matches!(
            (self.tokens.get(self.position), token),
            (Some(AnnotationToken::LBracket), AnnotationToken::LBracket)
                | (Some(AnnotationToken::RBracket), AnnotationToken::RBracket)
                | (Some(AnnotationToken::LParen), AnnotationToken::LParen)
                | (Some(AnnotationToken::RParen), AnnotationToken::RParen)
                | (Some(AnnotationToken::Comma), AnnotationToken::Comma)
                | (Some(AnnotationToken::Dot), AnnotationToken::Dot)
                | (Some(AnnotationToken::Pipe), AnnotationToken::Pipe)
                | (Some(AnnotationToken::Star), AnnotationToken::Star)
                | (Some(AnnotationToken::Minus), AnnotationToken::Minus)
                | (Some(AnnotationToken::Ellipsis), AnnotationToken::Ellipsis)
        )
    }

    fn consume_lbracket(&mut self) -> bool {
        self.consume(AnnotationToken::LBracket)
    }

    fn consume_rbracket(&mut self) -> bool {
        self.consume(AnnotationToken::RBracket)
    }

    fn consume_rparen(&mut self) -> bool {
        self.consume(AnnotationToken::RParen)
    }

    fn consume_comma(&mut self) -> bool {
        self.consume(AnnotationToken::Comma)
    }

    fn consume_dot(&mut self) -> bool {
        self.consume(AnnotationToken::Dot)
    }

    fn consume_pipe(&mut self) -> bool {
        self.consume(AnnotationToken::Pipe)
    }

    fn consume_star(&mut self) -> bool {
        self.consume(AnnotationToken::Star)
    }

    fn consume_minus(&mut self) -> bool {
        self.consume(AnnotationToken::Minus)
    }
}

fn is_annotation_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character: char| character.is_ascii_alphabetic() || character == '_')
        && characters.all(|character: char| character.is_ascii_alphanumeric() || character == '_')
        && (!is_python_keyword(value) || matches!(value, "False" | "None" | "True"))
}

struct DefaultsResult {
    values: Vec<String>,
    unresolved: Option<String>,
}

struct KeywordDefaultsResult {
    values: BTreeMap<String, String>,
    unresolved: Option<String>,
}

fn default_values(wiring: Option<&CFunctionWiring>, pool: &ConstantsPool) -> DefaultsResult {
    let Some(token): Option<String> =
        wiring.and_then(|w: &CFunctionWiring| w.defaults_const.clone())
    else {
        return DefaultsResult {
            values: Vec::new(),
            unresolved: None,
        };
    };
    let rendered: Option<Vec<String>> = resolve_const_items(&token, pool)
        .iter()
        .map(|value: &PythonExpr| render_default_expression(value, pool))
        .collect();
    let Some(rendered): Option<Vec<String>> =
        rendered.filter(|values: &Vec<String>| !values.is_empty())
    else {
        return DefaultsResult {
            values: Vec::new(),
            unresolved: Some(token),
        };
    };
    DefaultsResult {
        values: rendered,
        unresolved: None,
    }
}

fn render_default_expression(value: &PythonExpr, pool: &ConstantsPool) -> Option<String> {
    match value {
        PythonExpr::Const(value) => (!value.starts_with("UNRESOLVED:")).then(|| value.clone()),
        PythonExpr::Name(value) => value
            .strip_prefix("const_dict_")
            .and_then(|digest: &str| render_static_dict_digest(digest, pool)),
        PythonExpr::Tuple(values) => render_default_sequence(values, '(', ')', true, pool),
        PythonExpr::List(values) => render_default_sequence(values, '[', ']', false, pool),
        _ => None,
    }
}

fn render_default_sequence(
    values: &[PythonExpr],
    open: char,
    close: char,
    singleton_comma: bool,
    pool: &ConstantsPool,
) -> Option<String> {
    let rendered: Vec<String> = values
        .iter()
        .map(|value: &PythonExpr| render_default_expression(value, pool))
        .collect::<Option<Vec<String>>>()?;
    let mut out: String = String::new();
    out.push(open);
    out.push_str(&rendered.join(", "));
    if singleton_comma && rendered.len() == 1usize {
        out.push(',');
    }
    out.push(close);
    Some(out)
}

fn render_static_dict_digest(digest: &str, pool: &ConstantsPool) -> Option<String> {
    if digest == "empty" {
        return Some("{}".to_owned());
    }
    if pool.ambiguous_dict_digests.contains(digest) {
        return None;
    }
    render_static_dict_pairs(pool.dict_pairs_for_digest(digest)?)
}

fn render_static_dict_pairs(pairs: &[(PickleValue, PickleValue)]) -> Option<String> {
    let mut rendered: Vec<String> = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        if !is_static_pickle_hashable(key, 0usize) {
            return None;
        }
        let rendered_key: String = render_static_pickle_value(key)?;
        let rendered_value: String = render_static_pickle_value(value)?;
        rendered.push(format!("{rendered_key}: {rendered_value}"));
    }
    Some(format!("{{{}}}", rendered.join(", ")))
}

fn keyword_default_values(
    wiring: Option<&CFunctionWiring>,
    pool: &ConstantsPool,
) -> KeywordDefaultsResult {
    let Some(token): Option<String> =
        wiring.and_then(|wiring: &CFunctionWiring| wiring.kw_defaults_const.clone())
    else {
        return KeywordDefaultsResult {
            values: BTreeMap::new(),
            unresolved: None,
        };
    };
    let Some(digest): Option<&str> = token.strip_prefix("const_dict_") else {
        return KeywordDefaultsResult {
            values: BTreeMap::new(),
            unresolved: Some(token),
        };
    };
    if pool.ambiguous_dict_digests.contains(digest) {
        return KeywordDefaultsResult {
            values: BTreeMap::new(),
            unresolved: Some(token),
        };
    }
    let Some(pairs): Option<&[(PickleValue, PickleValue)]> = pool.dict_pairs_for_digest(digest)
    else {
        return KeywordDefaultsResult {
            values: BTreeMap::new(),
            unresolved: Some(token),
        };
    };
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in pairs {
        let PickleValue::Str(key): &PickleValue = key else {
            return KeywordDefaultsResult {
                values: BTreeMap::new(),
                unresolved: Some(token),
            };
        };
        let Some(rendered): Option<String> = render_static_pickle_value(value) else {
            return KeywordDefaultsResult {
                values: BTreeMap::new(),
                unresolved: Some(token),
            };
        };
        if values.insert(key.clone(), rendered).is_some() {
            return KeywordDefaultsResult {
                values: BTreeMap::new(),
                unresolved: Some(token),
            };
        }
    }
    KeywordDefaultsResult {
        values,
        unresolved: None,
    }
}

fn docstring_value(wiring: Option<&CFunctionWiring>) -> (Option<String>, Option<String>) {
    (
        None,
        wiring.and_then(|w: &CFunctionWiring| w.doc_const.clone()),
    )
}

fn wiring_for_body<'a>(
    c_module: &'a CModuleStructure,
    function_name: &str,
    source_index: u32,
    parent_names: &[String],
) -> Option<&'a CFunctionWiring> {
    let mut exact = c_module.wirings.iter().filter(|wiring: &&CFunctionWiring| {
        wiring.function_name == function_name
            && wiring.source_index == Some(source_index)
            && wiring.parent_names == parent_names
    });
    if let Some(candidate) = exact.next() {
        return exact.next().is_none().then_some(candidate);
    }
    let matching_indices: BTreeSet<u32> = c_module
        .impl_bodies
        .iter()
        .filter(|body: &&CImplBody| {
            body.function_name == function_name && body.parent_names == parent_names
        })
        .map(|body: &CImplBody| body.source_index)
        .chain(
            c_module
                .const_returns
                .iter()
                .filter(|constant: &&CConstReturn| {
                    constant.function_name == function_name && constant.parent_names == parent_names
                })
                .map(|constant: &CConstReturn| constant.source_index),
        )
        .collect();
    if matching_indices.len() != 1 {
        return None;
    }
    let mut legacy = c_module.wirings.iter().filter(|wiring: &&CFunctionWiring| {
        wiring.function_name == function_name
            && wiring.source_index.is_none()
            && wiring.parent_names == parent_names
    });
    let candidate: &CFunctionWiring = legacy.next()?;
    legacy.next().is_none().then_some(candidate)
}

#[derive(Clone, Copy)]
enum SurfaceBody<'a> {
    Impl(&'a CImplBody),
    ConstReturn(&'a CConstReturn),
}

impl<'a> SurfaceBody<'a> {
    fn function_name(self) -> &'a str {
        match self {
            Self::Impl(body) => &body.function_name,
            Self::ConstReturn(body) => &body.function_name,
        }
    }

    const fn source_index(self) -> u32 {
        match self {
            Self::Impl(body) => body.source_index,
            Self::ConstReturn(body) => body.source_index,
        }
    }

    fn parent_names(self) -> &'a [String] {
        match self {
            Self::Impl(body) => &body.parent_names,
            Self::ConstReturn(body) => &body.parent_names,
        }
    }

    fn code_object(self, c_module: &CModuleStructure) -> Option<&CCodeObject> {
        match self {
            Self::Impl(body) => body.code_object_symbol.as_deref().map_or_else(
                || {
                    c_module
                        .code_objects
                        .iter()
                        .all(|code: &CCodeObject| code.symbol.is_empty())
                        .then(|| unique_code_object_by_name(c_module, &body.function_name))
                        .flatten()
                },
                |symbol: &str| {
                    unique_code_object_by_symbol_and_name(c_module, symbol, &body.function_name)
                },
            ),
            Self::ConstReturn(body) => unique_code_object_by_symbol_and_name(
                c_module,
                &body.code_object_symbol,
                &body.function_name,
            ),
        }
    }

    fn params(
        self,
        code_object: Option<&CCodeObject>,
        pool: &ConstantsPool,
    ) -> Option<Vec<String>> {
        match self {
            Self::Impl(body) => Some(body.params.clone()),
            Self::ConstReturn(_) => const_return_params(code_object, pool),
        }
    }

    fn lift(
        self,
        c_source: Option<&str>,
        c_source_mask: Option<&[u8]>,
        pool: &ConstantsPool,
        signature_recovered: bool,
    ) -> BodyLift {
        match self {
            Self::Impl(body) => {
                if !signature_recovered {
                    return BodyLift {
                        stmts: Vec::new(),
                        fidelity: LiftFidelity::Skeleton,
                        unrecognized_lines: vec![
                            "implementation body omitted because its signature was not value-resolved"
                                .to_owned(),
                        ],
                    };
                }
                match (c_source, c_source_mask) {
                    (Some(src), Some(code)) => {
                        extract_c_function_body_by_symbol_with_mask(src, code, &body.impl_symbol)
                            .map(|slice: &str| (src, slice))
                            .map_or_else(
                                || BodyLift {
                                    stmts: Vec::new(),
                                    fidelity: LiftFidelity::Skeleton,
                                    unrecognized_lines: Vec::new(),
                                },
                                |(src, slice): (&str, &str)| {
                                    lift_body_with_source(slice, &body.params, pool, src)
                                },
                            )
                    }
                    _ => BodyLift {
                        stmts: Vec::new(),
                        fidelity: LiftFidelity::Skeleton,
                        unrecognized_lines: Vec::new(),
                    },
                }
            }
            Self::ConstReturn(body) => {
                if !signature_recovered {
                    return BodyLift {
                        stmts: Vec::new(),
                        fidelity: LiftFidelity::Skeleton,
                        unrecognized_lines: vec![
                            "constant-return factory has no exact code-object metadata".to_owned(),
                        ],
                    };
                }
                let value: PythonExpr = resolve_const_token(&body.value_const, pool);
                if !is_static_const_expr(&value) {
                    return BodyLift {
                        stmts: Vec::new(),
                        fidelity: LiftFidelity::Skeleton,
                        unrecognized_lines: vec![format!(
                            "constant return '{}' was not value-resolved",
                            body.value_const
                        )],
                    };
                }
                BodyLift {
                    stmts: vec![PythonStmt::Return(value)],
                    fidelity: LiftFidelity::FullBody,
                    unrecognized_lines: Vec::new(),
                }
            }
        }
    }
}

fn unique_code_object_by_name<'a>(
    c_module: &'a CModuleStructure,
    function_name: &str,
) -> Option<&'a CCodeObject> {
    let mut code_objects = c_module
        .code_objects
        .iter()
        .filter(|code: &&CCodeObject| code.name == function_name);
    let candidate: &CCodeObject = code_objects.next()?;
    code_objects.next().is_none().then_some(candidate)
}

fn unique_code_object_by_symbol_and_name<'a>(
    c_module: &'a CModuleStructure,
    symbol: &str,
    function_name: &str,
) -> Option<&'a CCodeObject> {
    let mut code_objects = c_module
        .code_objects
        .iter()
        .filter(|code: &&CCodeObject| code.symbol == symbol && code.name == function_name);
    let candidate: &CCodeObject = code_objects.next()?;
    code_objects.next().is_none().then_some(candidate)
}

fn const_return_params(
    code_object: Option<&CCodeObject>,
    pool: &ConstantsPool,
) -> Option<Vec<String>> {
    let code_object: &CCodeObject = code_object?;
    let Some(arg_names): Option<&str> = code_object.arg_names_const.as_deref() else {
        return parameter_layout(Some(code_object), 0usize).map(|_: ParameterLayout| Vec::new());
    };
    let names: Option<Vec<String>> = render_const_token(arg_names, pool)
        .into_iter()
        .map(|name: String| {
            name.strip_prefix('\'')
                .and_then(|inner: &str| inner.strip_suffix('\''))
                .map(str::to_owned)
        })
        .collect();
    let names: Vec<String> = names?;
    if !valid_parameter_names(&names) {
        return None;
    }
    parameter_layout(Some(code_object), names.len()).map(|_: ParameterLayout| names)
}

fn valid_parameter_names(names: &[String]) -> bool {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    names
        .iter()
        .all(|name: &String| is_python_parameter_name(name) && seen.insert(name.as_str()))
}

fn valid_function_path(name: &str, parent_names: &[String]) -> bool {
    is_python_parameter_name(name)
        && parent_names
            .iter()
            .all(|parent: &String| is_python_parameter_name(parent))
}

fn is_python_parameter_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|character: char| character.is_ascii_alphabetic() || character == '_')
        && characters.all(|character: char| character.is_ascii_alphanumeric() || character == '_')
        && !is_python_keyword(name)
}

fn is_python_keyword(name: &str) -> bool {
    matches!(
        name,
        "False"
            | "None"
            | "True"
            | "and"
            | "as"
            | "assert"
            | "async"
            | "await"
            | "break"
            | "class"
            | "continue"
            | "def"
            | "del"
            | "elif"
            | "else"
            | "except"
            | "finally"
            | "for"
            | "from"
            | "global"
            | "if"
            | "import"
            | "in"
            | "is"
            | "lambda"
            | "nonlocal"
            | "not"
            | "or"
            | "pass"
            | "raise"
            | "return"
            | "try"
            | "while"
            | "with"
            | "yield"
    )
}

fn is_static_const_expr(expr: &PythonExpr) -> bool {
    match expr {
        PythonExpr::Const(value) => !value.starts_with("UNRESOLVED:"),
        PythonExpr::Tuple(items) | PythonExpr::List(items) => {
            items.iter().all(is_static_const_expr)
        }
        PythonExpr::Dict(items) => items.iter().all(|(key, value): &(PythonExpr, PythonExpr)| {
            is_static_const_expr(key) && is_static_const_expr(value)
        }),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy)]
struct ParameterLayout {
    positional_count: usize,
    positional_only_count: usize,
    keyword_only_start: usize,
    keyword_only_end: usize,
    vararg_index: Option<usize>,
    kwarg_index: Option<usize>,
}

fn parameter_layout(
    code_object: Option<&CCodeObject>,
    parameter_count: usize,
) -> Option<ParameterLayout> {
    let code_object: &CCodeObject = code_object?;
    let positional_count: usize = usize::try_from(code_object.arg_count).ok()?;
    let positional_only_count: usize = usize::try_from(code_object.pos_only_count).ok()?;
    if positional_only_count > positional_count {
        return None;
    }
    let keyword_only_count: usize = usize::try_from(code_object.kw_only_count).ok()?;
    let keyword_only_start: usize = positional_count;
    let keyword_only_end: usize = keyword_only_start.checked_add(keyword_only_count)?;
    let vararg_index: Option<usize> = code_object.has_varargs.then_some(keyword_only_end);
    let kwarg_index: Option<usize> = code_object
        .has_kwargs
        .then(|| keyword_only_end.checked_add(usize::from(code_object.has_varargs)))
        .flatten();
    let expected: usize = keyword_only_end
        .checked_add(usize::from(code_object.has_varargs))?
        .checked_add(usize::from(code_object.has_kwargs))?;
    (parameter_count == expected).then_some(ParameterLayout {
        positional_count,
        positional_only_count,
        keyword_only_start,
        keyword_only_end,
        vararg_index,
        kwarg_index,
    })
}

pub fn build_surface(
    c_module: &CModuleStructure,
    pool: &ConstantsPool,
    c_source: Option<&str>,
) -> Result<SurfaceModule> {
    build_surface_with_optional_python_abi(c_module, pool, c_source, c_module.python_abi)
}

pub fn build_surface_with_python_abi(
    c_module: &CModuleStructure,
    pool: &ConstantsPool,
    c_source: Option<&str>,
    python_abi: (u8, u8),
) -> Result<SurfaceModule> {
    build_surface_with_optional_python_abi(c_module, pool, c_source, Some(python_abi))
}

pub(crate) fn build_surface_with_optional_python_abi(
    c_module: &CModuleStructure,
    pool: &ConstantsPool,
    c_source: Option<&str>,
    python_abi: Option<(u8, u8)>,
) -> Result<SurfaceModule> {
    let python_abi: Option<(u8, u8)> = resolved_python_abi(c_module, python_abi)?;
    if let Some(source) = c_source {
        validate_c_source(source)?;
    }
    let c_source_mask: Option<Vec<u8>> =
        c_source.map(|source: &str| c_code_mask_with_nuitka_python_abi(source, python_abi));
    build_surface_with_c_source_mask(c_module, pool, c_source, c_source_mask)
}

fn resolved_python_abi(
    c_module: &CModuleStructure,
    requested: Option<(u8, u8)>,
) -> Result<Option<(u8, u8)>> {
    if let (Some(parsed), Some(requested)) = (c_module.python_abi, requested)
        && parsed != requested
    {
        return Err(Error::SurfaceBinding(format!(
            "C module was parsed for Python {}.{}, but surface recovery requested Python {}.{}",
            parsed.0, parsed.1, requested.0, requested.1
        )));
    }
    Ok(requested.or(c_module.python_abi))
}

fn build_surface_with_c_source_mask(
    c_module: &CModuleStructure,
    pool: &ConstantsPool,
    c_source: Option<&str>,
    c_source_mask: Option<Vec<u8>>,
) -> Result<SurfaceModule> {
    let mut bodies: Vec<SurfaceBody<'_>> =
        c_module.impl_bodies.iter().map(SurfaceBody::Impl).collect();
    bodies.extend(
        c_module
            .const_returns
            .iter()
            .filter(|constant: &&CConstReturn| {
                !c_module.impl_bodies.iter().any(|body: &CImplBody| {
                    body.function_name == constant.function_name
                        && body.source_index == constant.source_index
                        && body.parent_names == constant.parent_names
                })
            })
            .map(SurfaceBody::ConstReturn),
    );
    bodies.sort_by_key(|body: &SurfaceBody<'_>| body.source_index());

    let mut functions: Vec<SurfaceFunction> = Vec::with_capacity(bodies.len());
    let mut notes: Vec<String> = c_module.notes.clone();
    for body in bodies {
        let function_name: &str = body.function_name();
        let parent_names: &[String] = body.parent_names();
        if !valid_function_path(function_name, parent_names) {
            notes.push(format!(
                "skipped function '{function_name}' because its recovered Python name path was invalid"
            ));
            continue;
        }
        let code_object: Option<&CCodeObject> = body.code_object(c_module);
        let (param_names, signature_recovered): (Vec<String>, bool) = body
            .params(code_object, pool)
            .filter(|params: &Vec<String>| valid_parameter_names(params))
            .map_or_else(|| (Vec::new(), false), |params: Vec<String>| (params, true));
        let wiring: Option<&CFunctionWiring> =
            wiring_for_body(c_module, function_name, body.source_index(), parent_names);

        let annotation_dict: Option<&[(PickleValue, PickleValue)]> =
            annotation_dict_for_wiring(wiring, pool);

        let defaults_result: DefaultsResult = default_values(wiring, pool);
        if let Some(unresolved) = &defaults_result.unresolved {
            notes.push(format!(
                "function '{function_name}' defaults const '{unresolved}' present but not value-resolved (follow-on)"
            ));
        }
        let defaults: Vec<String> = defaults_result.values;
        let keyword_defaults_result: KeywordDefaultsResult = keyword_default_values(wiring, pool);
        if let Some(unresolved) = &keyword_defaults_result.unresolved {
            notes.push(format!(
                "function '{function_name}' keyword-only defaults const '{unresolved}' present but not value-resolved"
            ));
        }
        let keyword_defaults: BTreeMap<String, String> = keyword_defaults_result.values;
        let n_params: usize = param_names.len();
        let layout: Option<ParameterLayout> = parameter_layout(code_object, n_params);
        let fallback_first_defaulted: usize = n_params.saturating_sub(defaults.len());
        let positional_default_start: Option<usize> = layout.and_then(|layout: ParameterLayout| {
            layout.positional_count.checked_sub(defaults.len())
        });

        let mut params: Vec<SurfaceParam> = Vec::with_capacity(n_params);

        for (i, pname) in param_names.iter().enumerate() {
            let annotation: Option<String> =
                annotation_dict.and_then(|pairs| lookup_annotation(pairs, pname));
            let star: ParamStar = if layout
                .is_some_and(|value: ParameterLayout| value.vararg_index == Some(i))
            {
                ParamStar::Args
            } else if layout.is_some_and(|value: ParameterLayout| value.kwarg_index == Some(i)) {
                ParamStar::Kwargs
            } else {
                ParamStar::None
            };
            let keyword_only: bool = layout.is_some_and(|value: ParameterLayout| {
                i >= value.keyword_only_start && i < value.keyword_only_end
            });
            let default: Option<String> = if star != ParamStar::None {
                None
            } else if keyword_only {
                keyword_defaults.get(pname).cloned()
            } else if let (Some(layout), Some(start)) = (layout, positional_default_start) {
                (i >= start && i < layout.positional_count)
                    .then(|| defaults.get(i - start).cloned())
                    .flatten()
            } else if layout.is_none() && i >= fallback_first_defaulted {
                defaults.get(i - fallback_first_defaulted).cloned()
            } else {
                None
            };
            params.push(SurfaceParam {
                name: pname.clone(),
                annotation,
                default,
                star,
                positional_only: layout
                    .is_some_and(|value: ParameterLayout| i < value.positional_only_count),
                keyword_only,
            });
        }

        let return_annotation: Option<String> =
            annotation_dict.and_then(|pairs| lookup_annotation(pairs, RETURN_KEY));

        if wiring.is_none() {
            notes.push(format!(
                "function '{function_name}' has no wiring record; annotations unresolved"
            ));
        }

        let source_line: Option<u32> = code_object.map(|c| c.line);

        let (docstring, doc_unresolved): (Option<String>, Option<String>) = docstring_value(wiring);
        if let Some(unresolved) = &doc_unresolved {
            notes.push(format!(
                "function '{function_name}' doc const '{unresolved}' present but not value-resolved (follow-on)"
            ));
        }

        let lift: BodyLift = body.lift(
            c_source,
            c_source_mask.as_deref(),
            pool,
            signature_recovered,
        );
        let body_recovered: bool = !lift.stmts.is_empty();
        if !lift.unrecognized_lines.is_empty() {
            notes.push(format!(
                "function '{}' dropped {} unrecognized C line(s); fidelity downgraded from full coverage",
                function_name,
                lift.unrecognized_lines.len()
            ));
        }

        functions.push(SurfaceFunction {
            name: function_name.to_owned(),
            source_index: body.source_index(),
            params,
            return_annotation,
            docstring,
            body_recovered,
            body_stmts: lift.stmts,
            lift_fidelity: lift.fidelity,
            unrecognized_c_lines: lift.unrecognized_lines,
            source_line,
            parent_names: parent_names.to_vec(),
            nested: Vec::new(),
        });
    }

    let functions: Vec<SurfaceFunction> = nest_functions(functions);

    let mut module: SurfaceModule = SurfaceModule {
        module_name: c_module.module_name.clone(),
        functions,
        has_main_guard: c_module.has_main_guard,
        python_source: String::new(),
        fidelity: SurfaceFidelity::StructuredFromCSource,
        notes,
    };
    module.python_source = emit_python(&module);
    if module.python_source.is_empty() {
        return Err(Error::SurfaceBinding(
            "emitter produced empty source".to_owned(),
        ));
    }
    Ok(module)
}

fn attach_nested(
    parents: &mut [SurfaceFunction],
    child: SurfaceFunction,
) -> Option<SurfaceFunction> {
    let Some((immediate, ancestors)): Option<(String, Vec<String>)> = child
        .parent_names
        .split_last()
        .map(|(last, rest): (&String, &[String])| (last.clone(), rest.to_vec()))
    else {
        return Some(child);
    };
    let mut pending: Option<SurfaceFunction> = Some(child);
    for parent in parents.iter_mut() {
        let Some(candidate): Option<SurfaceFunction> = pending.take() else {
            break;
        };
        if parent.name == immediate && parent.parent_names == ancestors {
            parent.nested.push(candidate);
            return None;
        }
        pending = attach_nested(&mut parent.nested, candidate);
    }
    pending
}

fn nest_functions(flat: Vec<SurfaceFunction>) -> Vec<SurfaceFunction> {
    let mut ordered: Vec<SurfaceFunction> = flat;
    ordered.sort_by_key(|f: &SurfaceFunction| f.parent_names.len());
    let mut roots: Vec<SurfaceFunction> = Vec::new();
    for func in ordered {
        if func.parent_names.is_empty() {
            roots.push(func);
            continue;
        }
        if let Some(orphan) = attach_nested(&mut roots, func) {
            roots.push(orphan);
        }
    }
    sort_tree(&mut roots);
    roots
}

fn sort_tree(funcs: &mut [SurfaceFunction]) {
    funcs.sort_by_key(|f: &SurfaceFunction| f.source_index);
    for f in funcs.iter_mut() {
        sort_tree(&mut f.nested);
    }
}

#[must_use]
pub fn build_surface_names_only(graph: &SymbolGraph, pool: &ConstantsPool) -> SurfaceModule {
    build_surface_names_only_with_skeleton(graph, pool, None)
}

#[must_use]
pub fn build_surface_names_only_with_skeleton(
    graph: &SymbolGraph,
    pool: &ConstantsPool,
    skeleton: Option<&SkeletonModule>,
) -> SurfaceModule {
    let mut functions: Vec<SurfaceFunction> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut seen_names: BTreeSet<String> = BTreeSet::new();
    let mut module_name: String =
        skeleton.map_or_else(String::new, |m: &SkeletonModule| m.name.clone());
    let mut by_qualname: BTreeMap<String, &SkeletonFunction> = BTreeMap::new();
    let mut by_name: BTreeMap<String, Option<&SkeletonFunction>> = BTreeMap::new();

    if let Some(module) = skeleton {
        for function in &module.functions {
            by_qualname.insert(function.qualname.clone(), function);
            by_name
                .entry(function.name.clone())
                .and_modify(|slot: &mut Option<&SkeletonFunction>| *slot = None)
                .or_insert(Some(function));
        }
    }

    for imp in &graph.impl_functions {
        let Some(demangled): Option<&DemangledFunction> = imp.demangled.as_ref() else {
            continue;
        };
        if !valid_function_path(&demangled.function_name, &demangled.parent_names) {
            continue;
        }
        if module_name.is_empty() {
            module_name.clone_from(&demangled.module_path);
        }
        let qualname: String = demangled_qualname(demangled);
        if !seen.insert(qualname) {
            continue;
        }
        seen_names.insert(demangled.function_name.clone());
        let skeleton_function: Option<&SkeletonFunction> =
            find_skeleton_function(demangled, &by_qualname, &by_name);
        if let Some(function) = skeleton_function {
            seen.insert(function.qualname.clone());
        }
        functions.push(surface_function_from_parts(
            &demangled.function_name,
            demangled.source_index,
            demangled.parent_names.clone(),
            skeleton_function,
        ));
    }

    if let Some(module) = skeleton {
        for (index, function) in module.functions.iter().enumerate() {
            let parent_names: Vec<String> = parent_names_from_qualname(&function.qualname);
            if !valid_function_path(&function.name, &parent_names) {
                continue;
            }
            if !seen.insert(function.qualname.clone()) {
                continue;
            }
            seen_names.insert(function.name.clone());
            functions.push(surface_function_from_parts(
                &function.name,
                skeleton_only_source_index(index),
                parent_names,
                Some(function),
            ));
        }
    }
    let functions: Vec<SurfaceFunction> = nest_functions(functions);

    let has_main: bool = pool.strings.contains("__main__") && seen_names.contains("main");
    let note: String = if skeleton.is_some() {
        "names-only fidelity: no module.<name>.c; signatures sourced from constants metadata where present; bodies not recovered".to_owned()
    } else {
        "names-only fidelity: no module.<name>.c; signatures/annotations not recoverable".to_owned()
    };
    let mut module: SurfaceModule = SurfaceModule {
        module_name,
        functions,
        has_main_guard: has_main,
        python_source: String::new(),
        fidelity: SurfaceFidelity::NamesOnly,
        notes: vec![note],
    };
    module.python_source = emit_python(&module);
    module
}

fn find_skeleton_function<'a>(
    demangled: &DemangledFunction,
    by_qualname: &BTreeMap<String, &'a SkeletonFunction>,
    by_name: &BTreeMap<String, Option<&'a SkeletonFunction>>,
) -> Option<&'a SkeletonFunction> {
    let qualname: String = demangled_qualname(demangled);
    by_qualname
        .get(&qualname)
        .copied()
        .or_else(|| match by_name.get(&demangled.function_name) {
            Some(Some(function)) => Some(*function),
            _ => None,
        })
}

fn demangled_qualname(demangled: &DemangledFunction) -> String {
    if demangled.parent_names.is_empty() {
        return demangled.function_name.clone();
    }
    let mut out: String = String::new();
    for parent in &demangled.parent_names {
        if !out.is_empty() {
            out.push_str(".<locals>.");
        }
        out.push_str(parent);
    }
    out.push_str(".<locals>.");
    out.push_str(&demangled.function_name);
    out
}

fn surface_function_from_parts(
    name: &str,
    source_index: u32,
    parent_names: Vec<String>,
    skeleton: Option<&SkeletonFunction>,
) -> SurfaceFunction {
    SurfaceFunction {
        name: name.to_owned(),
        source_index,
        params: skeleton.map_or_else(Vec::new, |function: &SkeletonFunction| {
            function
                .params
                .iter()
                .map(surface_param_from_skeleton)
                .collect()
        }),
        return_annotation: skeleton
            .and_then(|function: &SkeletonFunction| function.return_annotation.clone()),
        docstring: None,
        body_recovered: false,
        body_stmts: Vec::new(),
        lift_fidelity: LiftFidelity::Skeleton,
        unrecognized_c_lines: Vec::new(),
        source_line: None,
        parent_names,
        nested: Vec::new(),
    }
}

fn surface_param_from_skeleton(param: &SkeletonParam) -> SurfaceParam {
    SurfaceParam {
        name: param.name.clone(),
        annotation: param.annotation.clone(),
        default: None,
        star: ParamStar::None,
        positional_only: false,
        keyword_only: false,
    }
}

fn parent_names_from_qualname(qualname: &str) -> Vec<String> {
    let parts: Vec<&str> = qualname.split(".<locals>.").collect();
    if parts.len() <= 1 {
        return Vec::new();
    }
    parts[..parts.len() - 1]
        .iter()
        .map(|part: &&str| part.rsplit('.').next().unwrap_or(*part).to_owned())
        .collect()
}

fn skeleton_only_source_index(index: usize) -> u32 {
    1_000_000u32.saturating_add(u32::try_from(index).unwrap_or(u32::MAX - 1_000_000))
}

fn sanitize_fn_name(name: &str) -> String {
    name.replace("$$$", "__").replace('$', "_")
}

fn render_signature(function: &SurfaceFunction) -> String {
    let has_parameter_roles: bool = function
        .params
        .iter()
        .any(|param: &SurfaceParam| param.positional_only || param.keyword_only);
    let parameters: Vec<String> = if has_parameter_roles {
        render_role_aware_parameters(&function.params)
    } else {
        function.params.iter().map(render_parameter).collect()
    };
    let mut sig: String = format!(
        "def {}({}",
        sanitize_fn_name(&function.name),
        parameters.join(", ")
    );
    sig.push(')');
    if let Some(ret) = &function.return_annotation {
        sig.push_str(" -> ");
        sig.push_str(&render_annotation_source(ret));
    }
    sig.push(':');
    sig
}

fn render_role_aware_parameters(params: &[SurfaceParam]) -> Vec<String> {
    let positional_only: Vec<&SurfaceParam> = params
        .iter()
        .filter(|param: &&SurfaceParam| {
            param.star == ParamStar::None && param.positional_only && !param.keyword_only
        })
        .collect();
    let mut out: Vec<String> = positional_only
        .iter()
        .copied()
        .map(render_parameter)
        .collect();
    if !positional_only.is_empty() {
        out.push("/".to_owned());
    }
    out.extend(
        params
            .iter()
            .filter(|param: &&SurfaceParam| {
                param.star == ParamStar::None && !param.positional_only && !param.keyword_only
            })
            .map(render_parameter),
    );

    let varargs: Vec<&SurfaceParam> = params
        .iter()
        .filter(|param: &&SurfaceParam| param.star == ParamStar::Args)
        .collect();
    out.extend(varargs.iter().copied().map(render_parameter));

    let keyword_only: Vec<&SurfaceParam> = params
        .iter()
        .filter(|param: &&SurfaceParam| param.star == ParamStar::None && param.keyword_only)
        .collect();
    if !keyword_only.is_empty() && varargs.is_empty() {
        out.push("*".to_owned());
    }
    out.extend(keyword_only.iter().copied().map(render_parameter));

    out.extend(
        params
            .iter()
            .filter(|param: &&SurfaceParam| param.star == ParamStar::Kwargs)
            .map(render_parameter),
    );
    out
}

fn render_parameter(param: &SurfaceParam) -> String {
    let mut rendered: String = String::new();
    match param.star {
        ParamStar::Args => rendered.push('*'),
        ParamStar::Kwargs => rendered.push_str("**"),
        ParamStar::None => {}
    }
    rendered.push_str(&param.name);
    if let Some(annotation) = &param.annotation {
        rendered.push_str(": ");
        rendered.push_str(&render_annotation_source(annotation));
    }
    if let Some(default) = &param.default {
        if param.annotation.is_some() {
            rendered.push_str(" = ");
        } else {
            rendered.push('=');
        }
        rendered.push_str(default);
    }
    rendered
}

fn any_body_lifted(funcs: &[SurfaceFunction]) -> bool {
    funcs
        .iter()
        .any(|f: &SurfaceFunction| !f.body_stmts.is_empty() || any_body_lifted(&f.nested))
}

fn emit_function(function: &SurfaceFunction, indent: usize, out: &mut String) {
    let prefix: String = emit_indent(indent);
    out.push_str(&prefix);
    out.push_str(&render_signature(function));
    out.push('\n');
    if let Some(doc) = &function.docstring {
        out.push_str(&emit_indent(indent + 1));
        out.push_str(&py_docstring(doc));
        out.push('\n');
    }
    let mut body_text: String = String::new();
    for stmt in &function.body_stmts {
        body_text.push_str(&emit_stmt(stmt, indent + 1));
    }
    let body_emittable: bool =
        !function.body_stmts.is_empty() && !body_text.contains("UNRESOLVED:");
    let empty: bool = !body_emittable && function.nested.is_empty();
    if empty {
        out.push_str(&emit_indent(indent + 1));
        out.push_str("...  # disrobe: body not recovered\n");
        return;
    }
    for (i, nested) in function.nested.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        emit_function(nested, indent + 1, out);
    }
    if !function.nested.is_empty() && body_emittable {
        out.push('\n');
    }
    if body_emittable {
        out.push_str(&body_text);
    } else if function.nested.is_empty() {
        out.push_str(&emit_indent(indent + 1));
        out.push_str("...  # disrobe: body not recovered\n");
    }
}

#[must_use]
pub fn emit_python(module: &SurfaceModule) -> String {
    let mut out: String = String::new();
    if any_body_lifted(&module.functions) {
        out.push_str("# Recovered by disrobe (bodies partially lifted from Nuitka-generated C).\n");
    } else {
        out.push_str("# Recovered by disrobe (surface skeleton; bodies not lifted).\n");
    }
    out.push_str("from __future__ import annotations\n\n");
    for (i, function) in module.functions.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        emit_function(function, 0, &mut out);
    }

    let has_main_fn: bool = module
        .functions
        .iter()
        .any(|f: &SurfaceFunction| f.name == "main");
    if module.has_main_guard && has_main_fn {
        if !module.functions.is_empty() {
            out.push('\n');
        }
        out.push_str("\nif __name__ == \"__main__\":\n");
        out.push_str("    raise SystemExit(main())\n");
    }

    out
}

fn py_docstring(doc: &str) -> String {
    let escaped: String = doc.replace('\\', "\\\\").replace("\"\"\"", "\\\"\\\"\\\"");
    format!("\"\"\"{escaped}\"\"\"")
}

fn emit_indent(indent: usize) -> String {
    "    ".repeat(indent)
}

fn emit_expr(expr: &PythonExpr) -> String {
    match expr {
        PythonExpr::Name(s) | PythonExpr::Const(s) => s.clone(),
        PythonExpr::FStringJoin { parts } => format!("''.join({})", emit_tuple_items(parts)),
        PythonExpr::BinOp { op, left, right } => {
            format!(
                "{} {} {}",
                emit_operand(left),
                op.symbol(),
                emit_operand(right)
            )
        }
        PythonExpr::UnaryOp { op, operand } => {
            format!("{}{}", op.symbol(), emit_operand(operand))
        }
        PythonExpr::Compare { op, left, right } => {
            format!(
                "{} {} {}",
                emit_operand(left),
                op.symbol(),
                emit_operand(right)
            )
        }
        PythonExpr::BoolOp { op, left, right } => {
            format!(
                "{} {} {}",
                emit_operand(left),
                op.keyword(),
                emit_operand(right)
            )
        }
        PythonExpr::IfExp { test, body, orelse } => {
            format!(
                "{} if {} else {}",
                emit_operand(body),
                emit_operand(test),
                emit_operand(orelse)
            )
        }
        PythonExpr::Attribute { value, attr } => {
            format!("{}.{attr}", emit_operand(value))
        }
        PythonExpr::Subscript { value, index } => {
            format!("{}[{}]", emit_operand(value), emit_expr(index))
        }
        PythonExpr::Dict(pairs) => {
            let inner: String = pairs
                .iter()
                .map(|(k, v): &(PythonExpr, PythonExpr)| {
                    format!("{}: {}", emit_expr(k), emit_expr(v))
                })
                .collect::<Vec<String>>()
                .join(", ");
            format!("{{{inner}}}")
        }
        PythonExpr::Call { func, args } => {
            let args_str: String = args
                .iter()
                .map(emit_expr)
                .collect::<Vec<String>>()
                .join(", ");
            format!("{}({})", emit_expr(func), args_str)
        }
        PythonExpr::Tuple(items) => emit_tuple_items(items),
        PythonExpr::List(items) => {
            let inner: String = items
                .iter()
                .map(emit_expr)
                .collect::<Vec<String>>()
                .join(", ");
            format!("[{inner}]")
        }
        PythonExpr::ListComp {
            element,
            target,
            iter,
        } => {
            format!(
                "[{} for {target} in {}]",
                emit_expr(element),
                emit_expr(iter)
            )
        }
        PythonExpr::DictComp {
            key,
            value,
            target,
            iter,
        } => {
            format!(
                "{{{}: {} for {target} in {}}}",
                emit_expr(key),
                emit_expr(value),
                emit_expr(iter)
            )
        }
        PythonExpr::SetComp {
            element,
            target,
            iter,
        } => {
            format!(
                "{{{} for {target} in {}}}",
                emit_expr(element),
                emit_expr(iter)
            )
        }
    }
}

fn emit_tuple_items(items: &[PythonExpr]) -> String {
    let inner: String = items
        .iter()
        .map(emit_expr)
        .collect::<Vec<String>>()
        .join(", ");
    if items.len() == 1 {
        format!("({inner},)")
    } else {
        format!("({inner})")
    }
}

fn emit_operand(expr: &PythonExpr) -> String {
    match expr {
        PythonExpr::BinOp { .. }
        | PythonExpr::Compare { .. }
        | PythonExpr::UnaryOp { .. }
        | PythonExpr::BoolOp { .. }
        | PythonExpr::IfExp { .. } => {
            format!("({})", emit_expr(expr))
        }
        other => emit_expr(other),
    }
}

fn emit_expr_unpack(expr: &PythonExpr) -> String {
    match expr {
        PythonExpr::Tuple(items) | PythonExpr::List(items) => items
            .iter()
            .map(emit_expr)
            .collect::<Vec<String>>()
            .join(", "),
        other => emit_expr(other),
    }
}

fn emit_stmt(stmt: &PythonStmt, indent: usize) -> String {
    let prefix: String = emit_indent(indent);
    match stmt {
        PythonStmt::Return(e) => format!("{prefix}return {}\n", emit_expr(e)),
        PythonStmt::Raise(e) => format!("{prefix}raise {}\n", emit_expr(e)),
        PythonStmt::Expr(e) => format!("{prefix}{}\n", emit_expr(e)),
        PythonStmt::Assign { targets, value } => {
            format!("{prefix}{} = {}\n", targets.join(", "), emit_expr(value))
        }
        PythonStmt::TupleUnpackAssign { targets, value } => {
            format!(
                "{prefix}{} = {}\n",
                targets.join(", "),
                emit_expr_unpack(value)
            )
        }
        PythonStmt::If { test, body, orelse } => {
            let mut out: String = format!("{prefix}if {}:\n", emit_expr(test));
            emit_suite(body, indent + 1, &mut out);
            if !orelse.is_empty() {
                out.push_str(prefix.as_str());
                out.push_str("else:\n");
                emit_suite(orelse, indent + 1, &mut out);
            }
            out
        }
        PythonStmt::For { target, iter, body } => {
            let mut out: String = format!("{prefix}for {target} in {}:\n", emit_expr(iter));
            emit_suite(body, indent + 1, &mut out);
            out
        }
        PythonStmt::While { test, body } => {
            let mut out: String = format!("{prefix}while {}:\n", emit_expr(test));
            emit_suite(body, indent + 1, &mut out);
            out
        }
        PythonStmt::Break => format!("{prefix}break\n"),
        PythonStmt::Continue => format!("{prefix}continue\n"),
        PythonStmt::Yield(e) => format!("{prefix}yield {}\n", emit_expr(e)),
        PythonStmt::Try { body, handlers } => {
            if handlers.is_empty() {
                let mut out: String = String::new();
                emit_suite(body, indent, &mut out);
                return out;
            }
            let mut out: String = format!("{prefix}try:\n");
            emit_suite(body, indent + 1, &mut out);
            for handler in handlers {
                out.push_str(&prefix);
                let clause: String = match (&handler.exc_type, &handler.name) {
                    (Some(ty), Some(name)) => format!("except {ty} as {name}:\n"),
                    (Some(ty), None) => format!("except {ty}:\n"),
                    (None, _) => "except:\n".to_owned(),
                };
                out.push_str(&clause);
                emit_suite(&handler.body, indent + 1, &mut out);
            }
            out
        }
    }
}

fn emit_suite(stmts: &[PythonStmt], indent: usize, out: &mut String) {
    if stmts.is_empty() {
        out.push_str(&emit_indent(indent));
        out.push_str("pass\n");
        return;
    }
    for stmt in stmts {
        out.push_str(&emit_stmt(stmt, indent));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::c_module::parse_c_module_with_python_abi;
    use crate::constants::{ConstantEntry, ConstantProvenance, DictLocation, decode_const_file};
    use crate::demangle_function;

    const C_SRC: &str =
        include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
    const CONST: &[u8] =
        include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");

    fn surface() -> SurfaceModule {
        let cmod: CModuleStructure =
            parse_c_module_with_python_abi(C_SRC, (3u8, 12u8)).expect("parse");
        let pool: ConstantsPool =
            decode_const_file(CONST, "module.hello.const", "hello").expect("decode");
        build_surface_with_python_abi(&cmod, &pool, Some(C_SRC), (3u8, 12u8)).expect("surface")
    }

    fn pool_with_dict(pairs: Vec<(PickleValue, PickleValue)>) -> ConstantsPool {
        let mut pool: ConstantsPool = ConstantsPool::default();
        pool.entries.push(ConstantEntry {
            provenance: ConstantProvenance {
                source_file: "test".to_owned(),
                blob_name: "test".to_owned(),
                stream_index: 0usize,
                byte_offset: 0usize,
                byte_len: 0usize,
            },
            value: PickleValue::Dict(pairs),
        });
        pool.digest_to_dict.insert(
            "digest".to_owned(),
            DictLocation {
                entry_index: 0usize,
                path: Vec::new(),
            },
        );
        pool
    }

    #[test]
    fn functions_in_source_order_with_annotations() {
        let s: SurfaceModule = surface();
        let names: Vec<&str> = s.functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["greet", "fib", "main"]);

        let greet: &SurfaceFunction = &s.functions[0];
        assert_eq!(greet.params.len(), 1);
        assert_eq!(greet.params[0].name, "name");
        assert_eq!(greet.params[0].annotation.as_deref(), Some("str"));
        assert_eq!(greet.return_annotation.as_deref(), Some("str"));

        let fib: &SurfaceFunction = &s.functions[1];
        assert_eq!(fib.params[0].name, "n");
        assert_eq!(fib.params[0].annotation.as_deref(), Some("int"));
        assert_eq!(fib.return_annotation.as_deref(), Some("int"));

        let main: &SurfaceFunction = &s.functions[2];
        assert!(main.params.is_empty());
        assert_eq!(main.return_annotation.as_deref(), Some("int"));

        for f in &s.functions {
            assert!(f.docstring.is_none());
            for p in &f.params {
                assert!(p.default.is_none());
            }
        }
    }

    #[test]
    fn emitted_signatures_match_pyi() {
        let s: SurfaceModule = surface();
        let py: String = emit_python(&s);
        assert!(py.contains("def greet(name: str) -> str:"));
        assert!(py.contains("def fib(n: int) -> int:"));
        assert!(py.contains("def main() -> int:"));
        assert!(py.contains("if n < 2:") || py.contains("return"));
    }

    #[test]
    fn emitted_source_defers_recovered_annotation_evaluation() {
        let mut surface: SurfaceModule = surface();
        surface.functions[0].return_annotation = Some("MissingAnnotation".to_owned());
        let python: String = emit_python(&surface);
        assert!(python.starts_with("# Recovered by disrobe"));
        assert!(python.contains("from __future__ import annotations\n\n"));
        assert!(python.contains(" -> MissingAnnotation:"));
    }

    #[test]
    fn emitted_source_preserves_safe_generic_annotations() {
        let mut surface: SurfaceModule = surface();
        surface.functions[0].params[0].annotation = Some("list[int]".to_owned());
        surface.functions[0].return_annotation = Some("dict[str, Model | None]".to_owned());
        let python: String = emit_python(&surface);
        assert!(python.contains("def greet(name: list[int]) -> dict[str, Model | None]:"));
        assert!(!python.contains("'list[int]'"));
    }

    #[test]
    fn keyword_defaults_bind_by_const_dict_digest() {
        let wiring: CFunctionWiring = CFunctionWiring {
            function_name: "f".to_owned(),
            source_index: Some(1),
            annotations_dict_const: None,
            defaults_const: None,
            kw_defaults_const: Some("const_dict_digest".to_owned()),
            doc_const: None,
            parent_names: Vec::new(),
        };
        let pool: ConstantsPool = pool_with_dict(vec![
            (
                PickleValue::Str("enabled".to_owned()),
                PickleValue::Bool(true),
            ),
            (PickleValue::Str("limit".to_owned()), PickleValue::Int(3)),
        ]);
        let result: KeywordDefaultsResult = keyword_default_values(Some(&wiring), &pool);
        assert_eq!(result.unresolved, None);
        assert_eq!(result.values.get("enabled"), Some(&"True".to_owned()));
        assert_eq!(result.values.get("limit"), Some(&"3".to_owned()));
    }

    #[test]
    fn positional_dictionary_defaults_are_rendered_without_c_identifiers() {
        let wiring: CFunctionWiring = CFunctionWiring {
            function_name: "f".to_owned(),
            source_index: Some(1),
            annotations_dict_const: None,
            defaults_const: Some("const_tuple_dict_empty_tuple".to_owned()),
            kw_defaults_const: None,
            doc_const: None,
            parent_names: Vec::new(),
        };
        let values: DefaultsResult = default_values(Some(&wiring), &ConstantsPool::default());
        assert_eq!(values.unresolved, None);
        assert_eq!(values.values, vec!["{}"]);
    }

    #[test]
    fn unsafe_pickle_values_do_not_enter_default_or_annotation_source() {
        let wiring: CFunctionWiring = CFunctionWiring {
            function_name: "f".to_owned(),
            source_index: Some(1),
            annotations_dict_const: None,
            defaults_const: None,
            kw_defaults_const: Some("const_dict_digest".to_owned()),
            doc_const: None,
            parent_names: Vec::new(),
        };
        let pool: ConstantsPool = pool_with_dict(vec![(
            PickleValue::Str("enabled".to_owned()),
            PickleValue::OutOfBandBuffer { readonly: false },
        )]);
        let defaults: KeywordDefaultsResult = keyword_default_values(Some(&wiring), &pool);
        assert!(defaults.values.is_empty());
        assert_eq!(defaults.unresolved.as_deref(), Some("const_dict_digest"));
        assert_eq!(
            render_annotation_value(&PickleValue::OutOfBandBuffer { readonly: true }),
            None
        );
        assert_eq!(
            render_annotation_value(&PickleValue::Str("class".to_owned())).as_deref(),
            Some("'class'")
        );
        assert!(
            render_static_pickle_value(&PickleValue::Dict(vec![(
                PickleValue::List(Vec::new()),
                PickleValue::Int(1)
            ),]))
            .is_none()
        );
    }

    #[test]
    fn nonfinite_static_values_keep_valid_python_source() {
        let value: PickleValue = PickleValue::Dict(vec![(
            PickleValue::Str("value".to_owned()),
            PickleValue::Float(f64::NAN),
        )]);
        assert_eq!(
            render_static_pickle_value(&value).as_deref(),
            Some(
                "{'value': __import__('struct').unpack('>d', b'\\x7f\\xf8\\x00\\x00\\x00\\x00\\x00\\x00')[0]}"
            )
        );
    }

    #[test]
    fn nonfinite_static_values_preserve_nan_sign_and_payload() {
        let value: PickleValue = PickleValue::Float(f64::from_bits(0xfff8_0000_0000_0042));
        assert_eq!(
            render_static_pickle_value(&value).as_deref(),
            Some("__import__('struct').unpack('>d', b'\\xff\\xf8\\x00\\x00\\x00\\x00\\x00B')[0]")
        );
    }

    #[test]
    fn safe_annotation_expressions_remain_annotations() {
        let allowed: [&str; 7] = [
            "list[int]",
            "typing.Annotated[list[int | None], \"metadata\"]",
            "collections.abc.Callable[[str, ...], tuple[int, ...]]",
            "tuple[*Ts]",
            "Literal[-1, \"x\", None]",
            "'Forward'",
            r"Literal['\x41']",
        ];
        for value in allowed {
            assert_eq!(
                render_annotation_value(&PickleValue::Str(value.to_owned())).as_deref(),
                Some(value)
            );
        }
        for value in [
            "__import__('os')",
            "list[int",
            "lambda: int",
            "A; B",
            "T\nother: U",
            "*Ts",
            r"'\x'",
            r"'\u123'",
            "'a\0b'",
            "1.foo",
        ] {
            assert_ne!(
                render_annotation_value(&PickleValue::Str(value.to_owned())).as_deref(),
                Some(value)
            );
        }
    }

    #[test]
    fn parameter_names_require_unique_nonkeyword_python_identifiers() {
        assert!(valid_parameter_names(&[
            "alpha".to_owned(),
            "_beta2".to_owned()
        ]));
        assert!(!valid_parameter_names(&["class".to_owned()]));
        assert!(!valid_parameter_names(&["a-b".to_owned()]));
        assert!(!valid_parameter_names(&[
            "same".to_owned(),
            "same".to_owned()
        ]));
    }

    #[test]
    fn invalid_demangled_function_names_are_not_emitted_as_python_definitions() {
        let module: CModuleStructure = CModuleStructure {
            module_name: "m".to_owned(),
            python_abi: None,
            code_objects: Vec::new(),
            impl_bodies: vec![CImplBody {
                function_name: "class".to_owned(),
                source_index: 1,
                params: Vec::new(),
                parent_names: Vec::new(),
                impl_symbol: "impl_m$$$function__1_class".to_owned(),
                code_object_symbol: None,
            }],
            const_returns: Vec::new(),
            wirings: Vec::new(),
            has_main_guard: false,
            notes: Vec::new(),
        };
        let surface: SurfaceModule =
            build_surface(&module, &ConstantsPool::default(), None).expect("build");
        assert!(surface.functions.is_empty());
        assert!(!surface.python_source.contains("def class("));
    }

    #[test]
    fn profile_selected_impl_body_uses_the_same_c_mask_as_module_parsing() {
        let module: CModuleStructure = CModuleStructure {
            module_name: "m".to_owned(),
            python_abi: None,
            code_objects: Vec::new(),
            impl_bodies: vec![CImplBody {
                function_name: "f".to_owned(),
                source_index: 1,
                params: Vec::new(),
                parent_names: Vec::new(),
                impl_symbol: "impl_m$$$function__1_f".to_owned(),
                code_object_symbol: None,
            }],
            const_returns: Vec::new(),
            wirings: Vec::new(),
            has_main_guard: false,
            notes: Vec::new(),
        };
        let source: &str = r"
#if PYTHON_VERSION >= 0x3e0
static PyObject *impl_m$$$function__1_f(PyThreadState *tstate, PyObject *const *python_pars) {
    tmp_return_value = const_true;
    goto frame_return_exit_1;
}
#endif
";
        let pool: ConstantsPool = ConstantsPool::default();
        let unknown: SurfaceModule =
            build_surface(&module, &pool, Some(source)).expect("build without profile");
        assert!(!unknown.functions[0].body_recovered);
        let profiled: SurfaceModule =
            build_surface_with_python_abi(&module, &pool, Some(source), (3, 14))
                .expect("build with profile");
        assert_eq!(
            profiled.functions[0].body_stmts,
            vec![PythonStmt::Return(PythonExpr::Const("True".to_owned()))]
        );
    }

    #[test]
    fn parsed_abi_is_reused_and_conflicting_surface_profile_is_rejected() {
        let cmod: CModuleStructure =
            parse_c_module_with_python_abi(C_SRC, (3u8, 12u8)).expect("parse");
        let pool: ConstantsPool =
            decode_const_file(CONST, "module.hello.const", "hello").expect("decode");
        let surface: SurfaceModule = build_surface(&cmod, &pool, Some(C_SRC)).expect("surface");
        assert!(surface.functions.iter().any(|function: &SurfaceFunction| {
            function.name == "greet" && function.return_annotation.as_deref() == Some("str")
        }));
        assert!(matches!(
            build_surface_with_python_abi(&cmod, &pool, Some(C_SRC), (3u8, 13u8)),
            Err(Error::SurfaceBinding(_))
        ));
    }

    #[test]
    fn main_guard_emits_systemexit() {
        let s: SurfaceModule = surface();
        assert!(s.has_main_guard);
        let py: String = emit_python(&s);
        assert!(py.contains("if __name__ == \"__main__\":"));
        assert!(py.contains("raise SystemExit(main())"));
    }

    #[test]
    fn names_only_degrades_cleanly() {
        let mut graph: SymbolGraph = SymbolGraph::default();
        graph.impl_functions.push(crate::symbols::ImpFunction {
            identifier: "hello$$$function__1_greet".to_owned(),
            demangled: demangle_function("impl_hello$$$function__1_greet"),
        });
        let pool: ConstantsPool =
            decode_const_file(CONST, "module.hello.const", "hello").expect("decode");
        let s: SurfaceModule = build_surface_names_only(&graph, &pool);
        assert_eq!(s.fidelity, SurfaceFidelity::NamesOnly);
        assert_eq!(s.functions.len(), 1);
        assert_eq!(s.functions[0].name, "greet");
        assert!(s.functions[0].params.is_empty());
    }

    #[test]
    fn names_only_uses_skeleton_signatures_when_available() {
        let mut graph: SymbolGraph = SymbolGraph::default();
        graph.impl_functions.push(crate::symbols::ImpFunction {
            identifier: "hello$$$function__1_greet".to_owned(),
            demangled: demangle_function("impl_hello$$$function__1_greet"),
        });
        let pool: ConstantsPool =
            decode_const_file(CONST, "module.hello.const", "hello").expect("decode");
        let skeleton: SkeletonModule = SkeletonModule {
            name: "hello".to_owned(),
            filename: None,
            docstring: None,
            functions: vec![SkeletonFunction {
                name: "greet".to_owned(),
                qualname: "greet".to_owned(),
                params: vec![SkeletonParam {
                    name: "name".to_owned(),
                    annotation: Some("str".to_owned()),
                }],
                return_annotation: Some("str".to_owned()),
                kind: crate::const_blob::CodeKind::Function,
                nested: false,
                from_annotations: true,
            }],
            constant_names: Vec::new(),
            python: String::new(),
            from_code_objects: true,
        };
        let s: SurfaceModule =
            build_surface_names_only_with_skeleton(&graph, &pool, Some(&skeleton));
        assert_eq!(s.fidelity, SurfaceFidelity::NamesOnly);
        assert_eq!(s.functions.len(), 1);
        let greet: &SurfaceFunction = &s.functions[0];
        assert_eq!(greet.params.len(), 1);
        assert_eq!(greet.params[0].name, "name");
        assert_eq!(greet.params[0].annotation.as_deref(), Some("str"));
        assert_eq!(greet.return_annotation.as_deref(), Some("str"));
        assert!(s.python_source.contains("def greet(name: str) -> str:"));
    }

    #[test]
    fn names_only_uses_skeleton_qualnames_for_nested_functions() {
        let graph: SymbolGraph = SymbolGraph::default();
        let pool: ConstantsPool = ConstantsPool::default();
        let skeleton: SkeletonModule = SkeletonModule {
            name: "nested".to_owned(),
            filename: None,
            docstring: None,
            functions: vec![
                SkeletonFunction {
                    name: "outer".to_owned(),
                    qualname: "outer".to_owned(),
                    params: Vec::new(),
                    return_annotation: None,
                    kind: crate::const_blob::CodeKind::Function,
                    nested: false,
                    from_annotations: false,
                },
                SkeletonFunction {
                    name: "inner".to_owned(),
                    qualname: "outer.<locals>.inner".to_owned(),
                    params: vec![SkeletonParam {
                        name: "x".to_owned(),
                        annotation: Some("int".to_owned()),
                    }],
                    return_annotation: Some("int".to_owned()),
                    kind: crate::const_blob::CodeKind::Function,
                    nested: true,
                    from_annotations: true,
                },
            ],
            constant_names: Vec::new(),
            python: String::new(),
            from_code_objects: true,
        };
        let s: SurfaceModule =
            build_surface_names_only_with_skeleton(&graph, &pool, Some(&skeleton));
        assert_eq!(s.functions.len(), 1);
        assert_eq!(s.functions[0].name, "outer");
        assert_eq!(s.functions[0].nested.len(), 1);
        assert_eq!(s.functions[0].nested[0].name, "inner");
        assert_eq!(
            s.functions[0].nested[0].params[0].annotation.as_deref(),
            Some("int")
        );
        assert!(s.python_source.contains("    def inner(x: int) -> int:"));
    }
}
