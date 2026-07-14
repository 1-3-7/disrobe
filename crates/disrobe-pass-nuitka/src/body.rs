use std::collections::BTreeMap;
use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::constants::{ConstantsPool, nuitka_bytes_repr, nuitka_string_repr};
use crate::limits::{MAX_C_SOURCE_BYTES, validate_c_source};
use crate::version_specific_patterns::{EraPatternPack, guess_era_from_csource, pack_for_era};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiftFidelity {
    FullBody,
    PartialBody,
    Skeleton,
}

impl From<LiftFidelity> for disrobe_core::RecoverySignal {
    #[inline]
    fn from(fidelity: LiftFidelity) -> Self {
        match fidelity {
            LiftFidelity::FullBody => Self::FullBodyLifted,
            LiftFidelity::PartialBody => Self::SomeBodiesLifted,
            LiftFidelity::Skeleton => Self::NoRecovery,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOpKind {
    Add,
    Sub,
    Mult,
    Div,
    FloorDiv,
    Mod,
    Pow,
    BitAnd,
    BitOr,
    BitXor,
    LShift,
    RShift,
    MatMult,
}

impl BinOpKind {
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mult => "*",
            Self::Div => "/",
            Self::FloorDiv => "//",
            Self::Mod => "%",
            Self::Pow => "**",
            Self::BitAnd => "&",
            Self::BitOr => "|",
            Self::BitXor => "^",
            Self::LShift => "<<",
            Self::RShift => ">>",
            Self::MatMult => "@",
        }
    }

    fn from_nuitka(op: &str) -> Option<Self> {
        let kind: Self = match op {
            "ADD" => Self::Add,
            "SUB" => Self::Sub,
            "MULT" => Self::Mult,
            "TRUEDIV" | "DIV" => Self::Div,
            "FLOORDIV" => Self::FloorDiv,
            "MOD" => Self::Mod,
            "POW" => Self::Pow,
            "BITAND" => Self::BitAnd,
            "BITOR" => Self::BitOr,
            "BITXOR" => Self::BitXor,
            "LSHIFT" => Self::LShift,
            "RSHIFT" => Self::RShift,
            "MATMULT" => Self::MatMult,
            _ => return None,
        };
        Some(kind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOpKind {
    Lt,
    Le,
    Eq,
    Ne,
    Gt,
    Ge,
}

impl CmpOpKind {
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }

    fn from_nuitka(op: &str) -> Option<Self> {
        let kind: Self = match op {
            "LT" => Self::Lt,
            "LE" => Self::Le,
            "EQ" => Self::Eq,
            "NE" => Self::Ne,
            "GT" => Self::Gt,
            "GE" => Self::Ge,
            _ => return None,
        };
        Some(kind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOpKind {
    Neg,
    Pos,
    Invert,
    Not,
}

impl UnaryOpKind {
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Neg => "-",
            Self::Pos => "+",
            Self::Invert => "~",
            Self::Not => "not ",
        }
    }

    fn from_nuitka(op: &str) -> Option<Self> {
        let kind: Self = match op.trim() {
            "PyNumber_Negative" => Self::Neg,
            "PyNumber_Positive" => Self::Pos,
            "PyNumber_Invert" => Self::Invert,
            _ => return None,
        };
        Some(kind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoolOpKind {
    And,
    Or,
}

impl BoolOpKind {
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Or => "or",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PythonExpr {
    Name(String),
    Const(String),
    FStringJoin {
        parts: Vec<Self>,
    },
    BinOp {
        op: BinOpKind,
        left: Box<Self>,
        right: Box<Self>,
    },
    UnaryOp {
        op: UnaryOpKind,
        operand: Box<Self>,
    },
    Compare {
        op: CmpOpKind,
        left: Box<Self>,
        right: Box<Self>,
    },
    BoolOp {
        op: BoolOpKind,
        left: Box<Self>,
        right: Box<Self>,
    },
    IfExp {
        test: Box<Self>,
        body: Box<Self>,
        orelse: Box<Self>,
    },
    Attribute {
        value: Box<Self>,
        attr: String,
    },
    Subscript {
        value: Box<Self>,
        index: Box<Self>,
    },
    Call {
        func: Box<Self>,
        args: Vec<Self>,
    },
    Tuple(Vec<Self>),
    List(Vec<Self>),
    Dict(Vec<(Self, Self)>),
    ListComp {
        element: Box<Self>,
        target: String,
        iter: Box<Self>,
    },
    DictComp {
        key: Box<Self>,
        value: Box<Self>,
        target: String,
        iter: Box<Self>,
    },
    SetComp {
        element: Box<Self>,
        target: String,
        iter: Box<Self>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptHandler {
    pub exc_type: Option<String>,
    pub name: Option<String>,
    pub body: Vec<PythonStmt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PythonStmt {
    Return(PythonExpr),
    If {
        test: PythonExpr,
        body: Vec<Self>,
        orelse: Vec<Self>,
    },
    Assign {
        targets: Vec<String>,
        value: PythonExpr,
    },
    TupleUnpackAssign {
        targets: Vec<String>,
        value: PythonExpr,
    },
    For {
        target: String,
        iter: PythonExpr,
        body: Vec<Self>,
    },
    While {
        test: PythonExpr,
        body: Vec<Self>,
    },
    Try {
        body: Vec<Self>,
        handlers: Vec<ExceptHandler>,
    },
    Raise(PythonExpr),
    Break,
    Continue,
    Yield(PythonExpr),
    Expr(PythonExpr),
}

#[must_use]
pub(crate) fn render_const_token(token: &str, pool: &ConstantsPool) -> Vec<String> {
    resolve_const_items(token, pool)
        .iter()
        .map(render_simple_expr)
        .collect()
}

#[must_use]
pub(crate) fn resolve_const_items(token: &str, pool: &ConstantsPool) -> Vec<PythonExpr> {
    match resolve_const_token(token, pool) {
        PythonExpr::Tuple(items) | PythonExpr::List(items) => items,
        other => vec![other],
    }
}

fn render_simple_expr(expr: &PythonExpr) -> String {
    match expr {
        PythonExpr::Const(s) | PythonExpr::Name(s) => s.clone(),
        PythonExpr::Tuple(items) => format!(
            "({})",
            items
                .iter()
                .map(render_simple_expr)
                .collect::<Vec<String>>()
                .join(", ")
        ),
        PythonExpr::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(render_simple_expr)
                .collect::<Vec<String>>()
                .join(", ")
        ),
        _ => "UNRESOLVED".to_owned(),
    }
}

#[must_use]
pub fn extract_impl_body_text<'a>(
    source: &'a str,
    module_name: &str,
    source_index: u32,
    fn_name: &str,
) -> Option<&'a str> {
    let symbol: String = format!("impl_{module_name}$$$function__{source_index}_{fn_name}");
    extract_impl_body_by_symbol(source, &symbol)
}

#[must_use]
pub fn extract_impl_body_by_symbol<'a>(source: &'a str, impl_symbol: &str) -> Option<&'a str> {
    extract_c_function_body_by_symbol(source, impl_symbol)
}

#[must_use]
pub(crate) fn extract_c_function_body_by_symbol<'a>(
    source: &'a str,
    symbol: &str,
) -> Option<&'a str> {
    let code: Vec<u8> = c_code_mask(source);
    extract_c_function_body_by_symbol_with_mask(source, &code, symbol)
}

#[must_use]
pub(crate) fn extract_c_function_body_by_symbol_with_mask<'a>(
    source: &'a str,
    code: &[u8],
    symbol: &str,
) -> Option<&'a str> {
    if source.len() != code.len() {
        return None;
    }
    let needle: String = format!("static PyObject *{symbol}(");
    let mut search: usize = 0usize;

    while let Some(start) = find_code_marker(code, needle.as_bytes(), search) {
        if let Some(body) = extract_c_function_body_at_with_mask(source, code, start) {
            return Some(body);
        }
        search = start + needle.len();
    }
    None
}

#[must_use]
pub(crate) fn extract_c_function_body_at_with_mask<'a>(
    source: &'a str,
    code: &[u8],
    start: usize,
) -> Option<&'a str> {
    let range: Range<usize> = extract_c_function_body_range_at_with_mask(source, code, start)?;
    source.get(range)
}

#[must_use]
pub(crate) fn extract_c_function_body_range_at_with_mask(
    source: &str,
    code: &[u8],
    start: usize,
) -> Option<Range<usize>> {
    if source.len() != code.len() || start >= code.len() {
        return None;
    }
    let search_start: usize = start.checked_add(1)?;
    let next_marker: Option<usize> = find_code_marker(code, b"static ", search_start);
    let declaration_end: usize = next_marker.map_or(code.len(), |next: usize| next);
    let header_open: usize = code
        .get(start..declaration_end)?
        .iter()
        .position(|byte: &u8| *byte == b'(')?
        .checked_add(start)?;
    if code.get(start..header_open)?.contains(&b';') {
        return None;
    }
    let header_close: usize = matching_header_paren_before(code, header_open, declaration_end)?;
    let open: usize = function_body_open_after_header(code, header_close, declaration_end)?;
    let body_start: usize = open.checked_add(1)?;
    let body_end: usize =
        find_code_marker(code, b"static PyObject *", body_start).unwrap_or(code.len());
    let mut depth: i32 = 0i32;
    let mut i: usize = open;
    while i < body_end {
        match code[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start..i.checked_add(1)?);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn matching_header_paren_before(code: &[u8], open: usize, end: usize) -> Option<usize> {
    if open >= end || end > code.len() || code.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth: i32 = 0i32;
    for (position, byte) in code.iter().enumerate().take(end).skip(open) {
        match *byte {
            b'(' => depth += 1i32,
            b')' => {
                depth -= 1i32;
                if depth == 0i32 {
                    return Some(position);
                }
            }
            _ => {}
        }
    }
    None
}

fn function_body_open_after_header(code: &[u8], close: usize, end: usize) -> Option<usize> {
    let mut position: usize = close.checked_add(1usize)?;
    while position < end && code.get(position).is_some_and(u8::is_ascii_whitespace) {
        position += 1usize;
    }
    (code.get(position) == Some(&b'{')).then_some(position)
}

#[must_use]
pub(crate) fn c_code_mask(source: &str) -> Vec<u8> {
    c_code_mask_with_python_version(source, None)
}

#[derive(Clone, Copy)]
enum ScanState {
    Code,
    LineComment,
    BlockComment,
    Quoted { quote: u8, escaped: bool },
}

#[must_use]
pub(crate) fn c_code_mask_with_python_version(
    source: &str,
    python_version: Option<u32>,
) -> Vec<u8> {
    c_code_mask_with_python_version_range(
        source,
        python_version.map(|value: u32| PythonVersionRange {
            minimum: value,
            maximum: Some(value),
        }),
        PreprocessorProfile::Generic,
    )
}

#[must_use]
#[cfg(test)]
pub(crate) fn c_code_mask_with_python_abi(source: &str, python_abi: Option<(u8, u8)>) -> Vec<u8> {
    c_code_mask_with_python_version_range(
        source,
        python_abi.and_then(python_version_range_from_abi),
        PreprocessorProfile::Generic,
    )
}

#[must_use]
pub(crate) fn c_code_mask_with_nuitka_python_abi(
    source: &str,
    python_abi: Option<(u8, u8)>,
) -> Vec<u8> {
    c_code_mask_with_python_version_range(
        source,
        python_abi.and_then(python_version_range_from_abi),
        PreprocessorProfile::Nuitka,
    )
}

#[derive(Clone, Copy)]
struct PythonVersionRange {
    minimum: u32,
    maximum: Option<u32>,
}

#[derive(Clone, Copy)]
enum PreprocessorProfile {
    Generic,
    Nuitka,
}

impl PreprocessorProfile {
    fn defined(self, identifier: &[u8]) -> Option<bool> {
        match self {
            Self::Generic => None,
            Self::Nuitka => {
                (identifier == b"_NUITKA_EXPERIMENTAL_NEW_CODE_OBJECTS").then_some(false)
            }
        }
    }
}

fn python_version_range_from_abi(python_abi: (u8, u8)) -> Option<PythonVersionRange> {
    let (major, minor): (u8, u8) = python_abi;
    let minimum: u32 = u32::from(major)
        .checked_mul(0x100u32)?
        .checked_add(u32::from(minor).checked_mul(0x10u32)?)?;
    Some(PythonVersionRange {
        minimum,
        maximum: Some(minimum.checked_add(0x0fu32)?),
    })
}

fn c_code_mask_with_python_version_range(
    source: &str,
    python_version: Option<PythonVersionRange>,
    profile: PreprocessorProfile,
) -> Vec<u8> {
    if source.len() > MAX_C_SOURCE_BYTES {
        return Vec::new();
    }
    let bytes: &[u8] = source.as_bytes();
    let mut mask: Vec<u8> = bytes.to_vec();
    let mut state: ScanState = ScanState::Code;
    let mut i: usize = 0usize;

    while i < bytes.len() {
        match state {
            ScanState::Code => {
                if let Some(end) = line_splice_end(bytes, i) {
                    mask[i..end].fill(b' ');
                    i = end;
                    continue;
                }
                let next: Option<usize> = next_logical_index(bytes, i + 1);
                match (bytes[i], next) {
                    (b'/', Some(next)) if bytes[next] == b'/' => {
                        mask[i..=next].fill(b' ');
                        i = next + 1;
                        state = ScanState::LineComment;
                    }
                    (b'/', Some(next)) if bytes[next] == b'*' => {
                        mask[i..=next].fill(b' ');
                        i = next + 1;
                        state = ScanState::BlockComment;
                    }
                    (b'\'' | b'"', _) => {
                        let quote: u8 = bytes[i];
                        mask[i] = b' ';
                        i += 1;
                        state = ScanState::Quoted {
                            quote,
                            escaped: false,
                        };
                    }
                    _ => i += 1,
                }
            }
            ScanState::LineComment => {
                if let Some(end) = line_splice_end(bytes, i) {
                    mask[i..end].fill(b' ');
                    i = end;
                } else if bytes[i] == b'\n' {
                    state = ScanState::Code;
                    i += 1;
                } else {
                    mask[i] = b' ';
                    i += 1;
                }
            }
            ScanState::BlockComment => {
                let next: Option<usize> = next_logical_index(bytes, i + 1);
                if let Some(next) = next
                    && bytes[i] == b'*'
                    && bytes[next] == b'/'
                {
                    mask[i..=next].fill(b' ');
                    i = next + 1;
                    state = ScanState::Code;
                } else if let Some(end) = line_splice_end(bytes, i) {
                    mask[i..end].fill(b' ');
                    i = end;
                } else {
                    if !matches!(bytes[i], b'\r' | b'\n') {
                        mask[i] = b' ';
                    }
                    i += 1;
                }
            }
            ScanState::Quoted { quote, escaped } => {
                if let Some(end) = line_splice_end(bytes, i) {
                    mask[i..end].fill(b' ');
                    i = end;
                    continue;
                }
                let byte: u8 = bytes[i];
                mask[i] = b' ';
                if escaped {
                    state = ScanState::Quoted {
                        quote,
                        escaped: false,
                    };
                } else if byte == b'\\' {
                    state = ScanState::Quoted {
                        quote,
                        escaped: true,
                    };
                } else if byte == quote {
                    state = ScanState::Code;
                }
                i += 1;
            }
        }
    }

    mask_inactive_preprocessor(&mut mask, python_version, profile);

    mask
}

fn line_splice_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'\\') {
        return None;
    }
    if bytes.get(start + 1) == Some(&b'\n') {
        return Some(start + 2);
    }
    (bytes.get(start + 1) == Some(&b'\r') && bytes.get(start + 2) == Some(&b'\n'))
        .then_some(start + 3)
}

fn next_logical_index(bytes: &[u8], mut index: usize) -> Option<usize> {
    while let Some(end) = line_splice_end(bytes, index) {
        index = end;
    }
    (index < bytes.len()).then_some(index)
}

fn mask_inactive_preprocessor(
    mask: &mut [u8],
    python_version: Option<PythonVersionRange>,
    profile: PreprocessorProfile,
) {
    #[derive(Clone, Copy)]
    struct ConditionalFrame {
        parent_active: bool,
        known_true: bool,
        saw_unknown: bool,
        branch_active: bool,
        saw_else: bool,
    }

    let mut frames: Vec<ConditionalFrame> = Vec::new();
    let mut defined_macros: BTreeMap<Vec<u8>, bool> = BTreeMap::new();
    let mut line_start: usize = 0usize;

    while line_start < mask.len() {
        let line_end: usize = mask[line_start..]
            .iter()
            .position(|byte: &u8| *byte == b'\n')
            .map_or(mask.len(), |offset: usize| line_start + offset);
        let physical_content_end: usize = if line_end > line_start && mask[line_end - 1] == b'\r' {
            line_end - 1
        } else {
            line_end
        };
        let (content_end, next_line_start): (usize, usize) =
            if preprocessor_line_starts(mask, line_start, physical_content_end) {
                preprocessor_logical_bounds(mask, line_start, line_end)
            } else {
                (physical_content_end, line_end.saturating_add(1))
            };
        let active: bool = frames
            .last()
            .is_none_or(|frame: &ConditionalFrame| frame.branch_active);
        let logical_line: Vec<u8> = preprocessor_logical_line(mask, line_start, content_end);
        let directive: Option<(&[u8], &[u8])> = preprocessor_directive(&logical_line);

        if let Some((kind, expression)) = directive {
            match kind {
                b"if" | b"ifdef" | b"ifndef" => {
                    if !valid_preprocessor_opener(kind, expression) {
                        mask_non_newline(mask);
                        return;
                    }
                    let condition: Option<bool> = preprocessor_opening_condition(
                        kind,
                        expression,
                        python_version,
                        profile,
                        &defined_macros,
                    );
                    let branch_active: bool = active && condition == Some(true);
                    frames.push(ConditionalFrame {
                        parent_active: active,
                        known_true: condition == Some(true),
                        saw_unknown: condition.is_none(),
                        branch_active,
                        saw_else: false,
                    });
                }
                b"elif" => {
                    let Some(frame): Option<&mut ConditionalFrame> = frames.last_mut() else {
                        mask_non_newline(mask);
                        return;
                    };
                    if frame.saw_else || preprocessor_expression_is_empty(expression) {
                        mask_non_newline(mask);
                        return;
                    }
                    let condition: Option<bool> = preprocessor_condition(
                        expression,
                        python_version,
                        profile,
                        &defined_macros,
                    );
                    frame.branch_active = frame.parent_active
                        && !frame.known_true
                        && !frame.saw_unknown
                        && condition == Some(true);
                    frame.known_true |= condition == Some(true);
                    frame.saw_unknown |= condition.is_none();
                }
                b"else" => {
                    let Some(frame): Option<&mut ConditionalFrame> = frames.last_mut() else {
                        mask_non_newline(mask);
                        return;
                    };
                    if frame.saw_else || !preprocessor_expression_is_empty(expression) {
                        mask_non_newline(mask);
                        return;
                    }
                    frame.branch_active =
                        frame.parent_active && !frame.known_true && !frame.saw_unknown;
                    frame.saw_else = true;
                }
                b"endif" => {
                    if !preprocessor_expression_is_empty(expression) || frames.pop().is_none() {
                        mask_non_newline(mask);
                        return;
                    }
                }
                b"define" => {
                    if active {
                        let Some(identifier): Option<Vec<u8>> =
                            preprocessor_define_identifier(expression)
                        else {
                            mask_non_newline(mask);
                            return;
                        };
                        defined_macros.insert(identifier, true);
                    }
                }
                b"undef" => {
                    if active {
                        let Some(identifier): Option<&[u8]> =
                            preprocessor_identifier_token(expression)
                        else {
                            mask_non_newline(mask);
                            return;
                        };
                        defined_macros.insert(identifier.to_vec(), false);
                    }
                }
                _ if conditional_directive_prefix(kind) => {
                    mask_non_newline(mask);
                    return;
                }
                _ => {}
            }
            mask_non_newline_range(mask, line_start, content_end);
        } else if !active {
            mask[line_start..content_end].fill(b' ');
        }

        line_start = next_line_start;
    }

    if !frames.is_empty() {
        mask_non_newline(mask);
    }
}

fn preprocessor_line_starts(mask: &[u8], start: usize, end: usize) -> bool {
    mask.get(start..end)
        .and_then(|line: &[u8]| line.iter().find(|byte: &&u8| !byte.is_ascii_whitespace()))
        == Some(&b'#')
}

fn preprocessor_logical_bounds(mask: &[u8], start: usize, first_line_end: usize) -> (usize, usize) {
    let mut line_start: usize = start;
    let mut line_end: usize = first_line_end;
    loop {
        let content_end: usize = line_content_end(mask, line_start, line_end);
        let next_line_start: usize = line_end.saturating_add(1);
        if !line_ends_with_splice(mask, line_start, content_end) || next_line_start >= mask.len() {
            return (content_end, next_line_start);
        }
        line_start = next_line_start;
        line_end = mask[line_start..]
            .iter()
            .position(|byte: &u8| *byte == b'\n')
            .map_or(mask.len(), |offset: usize| line_start + offset);
    }
}

fn line_content_end(mask: &[u8], start: usize, line_end: usize) -> usize {
    if line_end > start && mask.get(line_end - 1) == Some(&b'\r') {
        line_end - 1
    } else {
        line_end
    }
}

fn line_ends_with_splice(mask: &[u8], start: usize, content_end: usize) -> bool {
    content_end > start && mask.get(content_end - 1) == Some(&b'\\')
}

fn mask_non_newline_range(mask: &mut [u8], start: usize, end: usize) {
    for byte in &mut mask[start..end] {
        if !matches!(*byte, b'\r' | b'\n') {
            *byte = b' ';
        }
    }
}

fn mask_non_newline(mask: &mut [u8]) {
    for byte in mask {
        if !matches!(*byte, b'\r' | b'\n') {
            *byte = b' ';
        }
    }
}

fn preprocessor_expression_is_empty(expression: &[u8]) -> bool {
    expression.iter().all(u8::is_ascii_whitespace)
}

fn valid_preprocessor_opener(kind: &[u8], expression: &[u8]) -> bool {
    match kind {
        b"if" => !preprocessor_expression_is_empty(expression),
        b"ifdef" | b"ifndef" => preprocessor_identifier(expression),
        _ => false,
    }
}

fn preprocessor_identifier(expression: &[u8]) -> bool {
    preprocessor_identifier_token(expression).is_some()
}

fn preprocessor_identifier_token(expression: &[u8]) -> Option<&[u8]> {
    let start: usize = expression
        .iter()
        .position(|byte: &u8| !byte.is_ascii_whitespace())?;
    let end: usize = expression
        .iter()
        .rposition(|byte: &u8| !byte.is_ascii_whitespace())?;
    let identifier: &[u8] = &expression[start..=end];
    (identifier
        .first()
        .is_some_and(|byte: &u8| byte.is_ascii_alphabetic() || *byte == b'_')
        && identifier[1..]
            .iter()
            .all(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_'))
    .then_some(identifier)
}

fn preprocessor_define_identifier(expression: &[u8]) -> Option<Vec<u8>> {
    let start: usize = expression
        .iter()
        .position(|byte: &u8| !byte.is_ascii_whitespace())?;
    let mut end: usize = start;
    while expression
        .get(end)
        .is_some_and(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        end = end.checked_add(1)?;
    }
    let identifier: &[u8] = expression.get(start..end)?;
    identifier
        .first()
        .is_some_and(|byte: &u8| byte.is_ascii_alphabetic() || *byte == b'_')
        .then_some(identifier.to_vec())
}

fn preprocessor_opening_condition(
    kind: &[u8],
    expression: &[u8],
    python_version: Option<PythonVersionRange>,
    profile: PreprocessorProfile,
    defined_macros: &BTreeMap<Vec<u8>, bool>,
) -> Option<bool> {
    match kind {
        b"if" => preprocessor_condition(expression, python_version, profile, defined_macros),
        b"ifdef" => preprocessor_identifier_token(expression)
            .and_then(|identifier: &[u8]| macro_is_defined(defined_macros, profile, identifier)),
        b"ifndef" => preprocessor_identifier_token(expression)
            .and_then(|identifier: &[u8]| macro_is_defined(defined_macros, profile, identifier))
            .map(|defined: bool| !defined),
        _ => None,
    }
}

fn macro_is_defined(
    defined_macros: &BTreeMap<Vec<u8>, bool>,
    profile: PreprocessorProfile,
    identifier: &[u8],
) -> Option<bool> {
    defined_macros
        .get(identifier)
        .copied()
        .or_else(|| profile.defined(identifier))
}

fn preprocessor_logical_line(mask: &[u8], start: usize, end: usize) -> Vec<u8> {
    let mut logical: Vec<u8> = Vec::with_capacity(end.saturating_sub(start));
    let mut position: usize = start;
    while position < end {
        if mask.get(position) == Some(&b'\\')
            && let Some(splice_end) = line_splice_end(mask, position)
        {
            position = splice_end;
            continue;
        }
        let Some(byte): Option<&u8> = mask.get(position) else {
            break;
        };
        logical.push(*byte);
        position += 1;
    }
    logical
}

fn preprocessor_directive(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let start: usize = line
        .iter()
        .position(|byte: &u8| !byte.is_ascii_whitespace())?;
    if line.get(start) != Some(&b'#') {
        return None;
    }
    let mut key_start: usize = start + 1;
    while line
        .get(key_start)
        .is_some_and(|byte: &u8| byte.is_ascii_whitespace())
    {
        key_start += 1;
    }
    let mut key_end: usize = key_start;
    while line
        .get(key_end)
        .is_some_and(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        key_end += 1;
    }
    (key_start < key_end).then_some((&line[key_start..key_end], &line[key_end..]))
}

fn conditional_directive_prefix(kind: &[u8]) -> bool {
    [
        b"if".as_slice(),
        b"ifdef",
        b"ifndef",
        b"elif",
        b"else",
        b"endif",
    ]
    .iter()
    .any(|prefix: &&[u8]| kind.starts_with(prefix))
}

fn preprocessor_condition(
    expression: &[u8],
    python_version: Option<PythonVersionRange>,
    profile: PreprocessorProfile,
    defined_macros: &BTreeMap<Vec<u8>, bool>,
) -> Option<bool> {
    let compact: Vec<u8> = expression
        .iter()
        .copied()
        .filter(|byte: &u8| !byte.is_ascii_whitespace())
        .collect();
    let mut parser: PreprocessorExpressionParser<'_> = PreprocessorExpressionParser {
        expression: &compact,
        position: 0usize,
        nesting: 0usize,
        python_version,
        profile,
        defined_macros,
    };
    let truth: PreprocessorTruth = parser.parse_disjunction()?;
    if parser.position != compact.len() {
        return None;
    }
    truth.value()
}

const MAX_PREPROCESSOR_NESTING: usize = 256usize;

#[derive(Clone, Copy)]
enum PreprocessorTruth {
    Known(bool),
    Unknown,
}

impl PreprocessorTruth {
    const fn value(self) -> Option<bool> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown => None,
        }
    }

    const fn negate(self) -> Self {
        match self {
            Self::Known(value) => Self::Known(!value),
            Self::Unknown => Self::Unknown,
        }
    }

    const fn conjunction(self, other: Self) -> Self {
        match (self, other) {
            (Self::Known(false), _) | (_, Self::Known(false)) => Self::Known(false),
            (Self::Known(true), Self::Known(true)) => Self::Known(true),
            _ => Self::Unknown,
        }
    }

    const fn disjunction(self, other: Self) -> Self {
        match (self, other) {
            (Self::Known(true), _) | (_, Self::Known(true)) => Self::Known(true),
            (Self::Known(false), Self::Known(false)) => Self::Known(false),
            _ => Self::Unknown,
        }
    }
}

struct PreprocessorExpressionParser<'a> {
    expression: &'a [u8],
    position: usize,
    nesting: usize,
    python_version: Option<PythonVersionRange>,
    profile: PreprocessorProfile,
    defined_macros: &'a BTreeMap<Vec<u8>, bool>,
}

impl PreprocessorExpressionParser<'_> {
    fn parse_disjunction(&mut self) -> Option<PreprocessorTruth> {
        let mut result: PreprocessorTruth = self.parse_conjunction()?;
        while self.consume(b"||") {
            result = result.disjunction(self.parse_conjunction()?);
        }
        Some(result)
    }

    fn parse_conjunction(&mut self) -> Option<PreprocessorTruth> {
        let mut result: PreprocessorTruth = self.parse_unary()?;
        while self.consume(b"&&") {
            result = result.conjunction(self.parse_unary()?);
        }
        Some(result)
    }

    fn parse_unary(&mut self) -> Option<PreprocessorTruth> {
        let mut negate: bool = false;
        while self.consume(b"!") {
            negate = !negate;
        }
        let value: PreprocessorTruth = self.parse_primary()?;
        Some(if negate { value.negate() } else { value })
    }

    fn parse_primary(&mut self) -> Option<PreprocessorTruth> {
        if self.consume(b"(") {
            self.nesting = self.nesting.checked_add(1)?;
            if self.nesting > MAX_PREPROCESSOR_NESTING {
                return None;
            }
            let value: PreprocessorTruth = self.parse_disjunction()?;
            if !self.consume(b")") {
                return None;
            }
            self.nesting = self.nesting.checked_sub(1)?;
            return Some(value);
        }
        if self.starts_with(b"defined(") {
            return self.parse_defined();
        }
        let start: usize = self.position;
        while let Some(byte) = self.expression.get(self.position) {
            if *byte == b'(' || *byte == b')' || self.starts_with(b"&&") || self.starts_with(b"||")
            {
                break;
            }
            self.position = self.position.checked_add(1)?;
        }
        let atom: &[u8] = self.expression.get(start..self.position)?;
        if atom.is_empty() {
            return None;
        }
        if let Some((operator, value)) = python_version_comparison(atom) {
            return self
                .python_version
                .and_then(|version: PythonVersionRange| {
                    python_version_comparison_result(version, operator, value)
                })
                .map_or(Some(PreprocessorTruth::Unknown), |value: bool| {
                    Some(PreprocessorTruth::Known(value))
                });
        }
        Some(
            preprocessor_integer(atom).map_or(PreprocessorTruth::Unknown, |value: u32| {
                PreprocessorTruth::Known(value != 0u32)
            }),
        )
    }

    fn parse_defined(&mut self) -> Option<PreprocessorTruth> {
        if !self.consume(b"defined(") {
            return None;
        }
        let start: usize = self.position;
        while self
            .expression
            .get(self.position)
            .is_some_and(|byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.position = self.position.checked_add(1)?;
        }
        let identifier: &[u8] = self.expression.get(start..self.position)?;
        if identifier.is_empty()
            || !identifier
                .first()
                .is_some_and(|byte: &u8| byte.is_ascii_alphabetic() || *byte == b'_')
            || !self.consume(b")")
        {
            return None;
        }
        Some(
            macro_is_defined(self.defined_macros, self.profile, identifier)
                .map_or(PreprocessorTruth::Unknown, PreprocessorTruth::Known),
        )
    }

    fn consume(&mut self, token: &[u8]) -> bool {
        if !self.starts_with(token) {
            return false;
        }
        let Some(next): Option<usize> = self.position.checked_add(token.len()) else {
            return false;
        };
        self.position = next;
        true
    }

    fn starts_with(&self, token: &[u8]) -> bool {
        self.expression
            .get(self.position..)
            .is_some_and(|remaining: &[u8]| remaining.starts_with(token))
    }
}

fn python_version_comparison_result(
    python_version: PythonVersionRange,
    operator: &[u8],
    value: u32,
) -> Option<bool> {
    let minimum: u32 = python_version.minimum;
    let maximum: Option<u32> = python_version.maximum;
    match operator {
        b">=" => {
            if minimum >= value {
                Some(true)
            } else {
                maximum
                    .filter(|maximum: &u32| *maximum < value)
                    .map(|_: u32| false)
            }
        }
        b"<=" => {
            if maximum.is_some_and(|maximum: u32| maximum <= value) {
                Some(true)
            } else if minimum > value {
                Some(false)
            } else {
                None
            }
        }
        b"==" => {
            if maximum == Some(minimum) && minimum == value {
                Some(true)
            } else if minimum > value || maximum.is_some_and(|maximum: u32| maximum < value) {
                Some(false)
            } else {
                None
            }
        }
        b"!=" => {
            python_version_comparison_result(python_version, b"==", value).map(|equal: bool| !equal)
        }
        b">" => {
            if minimum > value {
                Some(true)
            } else {
                maximum
                    .filter(|maximum: &u32| *maximum <= value)
                    .map(|_: u32| false)
            }
        }
        b"<" => {
            if maximum.is_some_and(|maximum: u32| maximum < value) {
                Some(true)
            } else if minimum >= value {
                Some(false)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn python_version_comparison(expression: &[u8]) -> Option<(&[u8], u32)> {
    const OPERATORS: [&[u8]; 6] = [b">=", b"<=", b"==", b"!=", b">", b"<"];
    for operator in OPERATORS {
        let Some(offset): Option<usize> = expression
            .windows(operator.len())
            .position(|candidate: &[u8]| candidate == operator)
        else {
            continue;
        };
        let left: &[u8] = expression.get(..offset)?;
        let right_start: usize = offset.checked_add(operator.len())?;
        let right: &[u8] = expression.get(right_start..)?;
        if left == b"PYTHON_VERSION" {
            return Some((operator, preprocessor_integer(right)?));
        }
    }
    None
}

fn preprocessor_integer(expression: &[u8]) -> Option<u32> {
    let (radix, digits_with_suffix): (u32, &[u8]) =
        if expression.starts_with(b"0x") || expression.starts_with(b"0X") {
            (16u32, &expression[2..])
        } else {
            (10u32, expression)
        };
    let first_non_digit: Option<usize> = digits_with_suffix
        .iter()
        .position(|byte: &u8| !byte.is_ascii_hexdigit());
    let digit_end: usize =
        first_non_digit.map_or(digits_with_suffix.len(), |position: usize| position);
    let digits: &[u8] = &digits_with_suffix[..digit_end];
    let suffix: &[u8] = &digits_with_suffix[digit_end..];
    if digits.is_empty()
        || (radix == 10u32 && digits.iter().any(|byte: &u8| !byte.is_ascii_digit()))
        || suffix
            .iter()
            .any(|byte: &u8| !matches!(*byte, b'u' | b'U' | b'l' | b'L'))
    {
        return None;
    }
    let digits: &str = std::str::from_utf8(digits).ok()?;
    u32::from_str_radix(digits, radix).ok()
}

#[must_use]
pub(crate) fn find_code_marker(code: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    code.get(start..)
        .and_then(|rest: &[u8]| {
            rest.windows(needle.len())
                .position(|item: &[u8]| item == needle)
        })
        .map(|offset: usize| start + offset)
}

fn strip_mod_consts(token: &str) -> &str {
    token.strip_prefix("mod_consts.").unwrap_or(token)
}

pub(crate) fn resolve_const_token(token: &str, pool: &ConstantsPool) -> PythonExpr {
    let t: &str = strip_mod_consts(token.trim().trim_end_matches(';'));
    if let Some(expr) = resolve_singleton_token(t) {
        return expr;
    }
    if let Some(expr) = resolve_numeric_token(t) {
        return expr;
    }
    if let Some(expr) = resolve_string_token(t, pool) {
        return expr;
    }
    if let Some(expr) = resolve_bytes_token(t, pool) {
        return expr;
    }
    if let Some(inner) = t
        .strip_prefix("const_tuple_")
        .and_then(|i: &str| i.strip_suffix("_tuple"))
    {
        return resolve_sequence_inner(inner, pool, false);
    }
    if let Some(inner) = t
        .strip_prefix("const_list_")
        .and_then(|i: &str| i.strip_suffix("_list"))
    {
        return resolve_sequence_inner(inner, pool, true);
    }
    if t == "const_tuple_empty" {
        return PythonExpr::Tuple(Vec::new());
    }
    if t == "const_list_empty" {
        return PythonExpr::List(Vec::new());
    }
    PythonExpr::Name(t.to_owned())
}

fn resolve_singleton_token(t: &str) -> Option<PythonExpr> {
    let lit: &str = match t {
        "const_true" => "True",
        "const_false" => "False",
        "const_none" => "None",
        "const_ellipsis" => "...",
        _ => return None,
    };
    Some(PythonExpr::Const(lit.to_owned()))
}

fn resolve_numeric_token(t: &str) -> Option<PythonExpr> {
    if t == "const_int_0" || t == "const_long_0" || t == "global_constants[2]" {
        return Some(PythonExpr::Const("0".to_owned()));
    }
    for prefix in ["const_int_pos_", "const_long_pos_"] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return decimal_literal(rest);
        }
    }
    for prefix in ["const_int_neg_", "const_long_neg_"] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return decimal_literal(rest).map(|literal: PythonExpr| match literal {
                PythonExpr::Const(value) if value == "0" => PythonExpr::Const(value),
                PythonExpr::Const(value) => PythonExpr::Const(format!("-{value}")),
                _ => literal,
            });
        }
    }
    if let Some(rest) = t
        .strip_prefix("const_int_hex_")
        .or_else(|| t.strip_prefix("const_long_hex_"))
    {
        return (!rest.is_empty() && rest.bytes().all(|byte: u8| byte.is_ascii_hexdigit()))
            .then(|| PythonExpr::Const(format!("0x{rest}")));
    }
    if let Some(rest) = t.strip_prefix("const_float_") {
        return resolve_float_fragment(rest);
    }
    if let Some(rest) = t.strip_prefix("const_complex_") {
        return resolve_complex_fragment(rest);
    }
    None
}

fn decimal_literal(rest: &str) -> Option<PythonExpr> {
    if rest.is_empty() || !rest.bytes().all(|byte: u8| byte.is_ascii_digit()) {
        return None;
    }
    let without_leading_zeroes: &str = rest.trim_start_matches('0');
    let literal: &str = if without_leading_zeroes.is_empty() {
        "0"
    } else {
        without_leading_zeroes
    };
    Some(PythonExpr::Const(literal.to_owned()))
}

fn resolve_float_fragment(fragment: &str) -> Option<PythonExpr> {
    if fragment == "plus_nan" || fragment == "minus_nan" {
        return Some(PythonExpr::Const("float('nan')".to_owned()));
    }
    if fragment == "plus_inf" {
        return Some(PythonExpr::Const("float('inf')".to_owned()));
    }
    if fragment == "minus_inf" {
        return Some(PythonExpr::Const("float('-inf')".to_owned()));
    }
    let restored: String = fragment.replace("minus_", "-").replace('_', ".");
    restored
        .parse::<f64>()
        .ok()
        .map(|_: f64| PythonExpr::Const(restored))
}

fn resolve_complex_fragment(fragment: &str) -> Option<PythonExpr> {
    let (real, imag): (&str, &str) = fragment.split_once("__")?;
    let real: String = decode_complex_component(real)?;
    let imag: String = decode_complex_component(imag)?;
    Some(PythonExpr::Const(format!("complex({real}, {imag})")))
}

fn decode_complex_component(component: &str) -> Option<String> {
    let restored: String = component
        .replace('p', "+")
        .replace('m', "-")
        .replace('_', ".");
    restored.parse::<f64>().ok().map(|_: f64| restored)
}

fn resolve_string_token(t: &str, pool: &ConstantsPool) -> Option<PythonExpr> {
    let body: &str = t.strip_prefix("const_str_")?;
    Some(resolve_string_fragment(body, pool))
}

fn resolve_bytes_token(t: &str, pool: &ConstantsPool) -> Option<PythonExpr> {
    let body: &str = t.strip_prefix("const_bytes_")?;
    Some(resolve_bytes_fragment(body, pool))
}

fn resolve_string_fragment(body: &str, pool: &ConstantsPool) -> PythonExpr {
    if let Some(rest) = body.strip_prefix("plain_") {
        return string_literal(rest);
    }
    if let Some(rest) = body.strip_prefix("chr_")
        && let Ok(code) = rest.parse::<u32>()
        && let Some(ch) = char::from_u32(code)
    {
        let value: String = ch.to_string();
        return string_literal(&value);
    }
    if let Some(rest) = body.strip_prefix("angle_") {
        return string_literal(&format!("<{rest}>"));
    }
    let named: Option<&str> = match body {
        "empty" => Some(""),
        "null" => Some("\0"),
        "space" => Some(" "),
        "dot" => Some("."),
        "newline" => Some("\n"),
        "slash" => Some("/"),
        "backslash" => Some("\\"),
        "underscore" => Some("_"),
        _ => None,
    };
    if let Some(literal) = named {
        return string_literal(literal);
    }
    if let Some(hex) = body.strip_prefix("digest_") {
        if !pool.ambiguous_string_digests.contains(hex)
            && let Some(s) = pool.digest_to_string.get(hex)
        {
            return string_literal(s);
        }
        return PythonExpr::Const(format!("UNRESOLVED:{hex}"));
    }
    PythonExpr::Const(format!("UNRESOLVED:{body}"))
}

fn string_literal(value: &str) -> PythonExpr {
    PythonExpr::Const(nuitka_string_repr(value))
}

fn resolve_bytes_fragment(body: &str, pool: &ConstantsPool) -> PythonExpr {
    if let Some(rest) = body.strip_prefix("plain_") {
        return bytes_literal(rest.as_bytes());
    }
    if let Some(rest) = body.strip_prefix("chr_")
        && let Ok(code) = rest.parse::<u32>()
        && let Ok(byte) = u8::try_from(code)
    {
        return bytes_literal(&[byte]);
    }
    if let Some(rest) = body.strip_prefix("angle_") {
        return bytes_literal(format!("<{rest}>").as_bytes());
    }
    let named: Option<&[u8]> = match body {
        "empty" => Some(b""),
        "null" => Some(b"\0"),
        "space" => Some(b" "),
        "dot" => Some(b"."),
        "newline" => Some(b"\n"),
        "slash" => Some(b"/"),
        "backslash" => Some(b"\\"),
        "underscore" => Some(b"_"),
        _ => None,
    };
    if let Some(bytes) = named {
        return bytes_literal(bytes);
    }
    if let Some(hex) = body.strip_prefix("digest_") {
        if !pool.ambiguous_bytes_digests.contains(hex)
            && let Some(bytes) = pool.digest_to_bytes.get(hex)
        {
            return bytes_literal(bytes);
        }
        return PythonExpr::Const(format!("UNRESOLVED:{hex}"));
    }
    PythonExpr::Const(format!("UNRESOLVED:{body}"))
}

fn bytes_literal(bytes: &[u8]) -> PythonExpr {
    PythonExpr::Const(nuitka_bytes_repr(bytes))
}

fn resolve_sequence_inner(inner: &str, pool: &ConstantsPool, is_list: bool) -> PythonExpr {
    let items: Vec<PythonExpr> = split_tuple_tokens(inner)
        .into_iter()
        .map(|tok: String| resolve_const_token(&tok, pool))
        .collect();
    if is_list {
        PythonExpr::List(items)
    } else {
        PythonExpr::Tuple(items)
    }
}

const SINGLE_SEGMENT_PREFIXES: &[&str] = &[
    "str_plain_",
    "str_digest_",
    "str_chr_",
    "str_angle_",
    "bytes_plain_",
    "bytes_digest_",
    "bytes_chr_",
    "int_pos_",
    "int_neg_",
    "int_hex_",
    "long_pos_",
    "long_neg_",
    "long_hex_",
    "dict_",
];

const ATOMIC_FRAGMENTS: &[&str] = &[
    "true",
    "false",
    "none",
    "ellipsis",
    "int_0",
    "long_0",
    "str_empty",
    "str_null",
    "str_space",
    "str_dot",
    "str_newline",
    "str_slash",
    "str_backslash",
    "str_underscore",
    "tuple_empty",
    "list_empty",
];

fn split_tuple_tokens(inner: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut remaining: &str = inner;
    while !remaining.is_empty() {
        let (fragment, rest): (&str, &str) = next_sequence_fragment(remaining);
        out.push(format!("const_{fragment}"));
        remaining = rest;
    }
    out
}

fn next_sequence_fragment(remaining: &str) -> (&str, &str) {
    for atom in ATOMIC_FRAGMENTS {
        if remaining == *atom {
            return (remaining, "");
        }
        if let Some(rest) = remaining.strip_prefix(atom)
            && rest.starts_with('_')
        {
            return (&remaining[..atom.len()], &rest[1..]);
        }
    }
    for prefix in SINGLE_SEGMENT_PREFIXES {
        if let Some(after) = remaining.strip_prefix(prefix) {
            let seg_end: usize = after.find('_').unwrap_or(after.len());
            let frag_end: usize = prefix.len() + seg_end;
            let next: &str = remaining.get(frag_end + 1..).unwrap_or("");
            return (&remaining[..frag_end], next);
        }
    }
    let end: usize = remaining.find('_').unwrap_or(remaining.len());
    let next: &str = remaining.get(end + 1..).unwrap_or("");
    (&remaining[..end], next)
}

fn contains_unresolved(expr: &PythonExpr) -> bool {
    match expr {
        PythonExpr::Const(s) | PythonExpr::Name(s) => {
            s.starts_with("UNRESOLVED:") || s.contains("UNPACK_") || s.contains("LOOKUP_")
        }
        PythonExpr::FStringJoin { parts } => parts.iter().any(contains_unresolved),
        PythonExpr::BinOp { left, right, .. }
        | PythonExpr::Compare { left, right, .. }
        | PythonExpr::BoolOp { left, right, .. } => {
            contains_unresolved(left) || contains_unresolved(right)
        }
        PythonExpr::IfExp { test, body, orelse } => {
            contains_unresolved(test) || contains_unresolved(body) || contains_unresolved(orelse)
        }
        PythonExpr::UnaryOp { operand, .. } => contains_unresolved(operand),
        PythonExpr::Attribute { value, .. } => contains_unresolved(value),
        PythonExpr::Subscript { value, index } => {
            contains_unresolved(value) || contains_unresolved(index)
        }
        PythonExpr::Call { func, args } => {
            contains_unresolved(func) || args.iter().any(contains_unresolved)
        }
        PythonExpr::Tuple(items) | PythonExpr::List(items) => items.iter().any(contains_unresolved),
        PythonExpr::Dict(pairs) => pairs.iter().any(|(k, v): &(PythonExpr, PythonExpr)| {
            contains_unresolved(k) || contains_unresolved(v)
        }),
        PythonExpr::ListComp { element, iter, .. } | PythonExpr::SetComp { element, iter, .. } => {
            contains_unresolved(element) || contains_unresolved(iter)
        }
        PythonExpr::DictComp {
            key, value, iter, ..
        } => contains_unresolved(key) || contains_unresolved(value) || contains_unresolved(iter),
    }
}

fn stmt_has_unresolved(stmt: &PythonStmt) -> bool {
    match stmt {
        PythonStmt::Return(e)
        | PythonStmt::Expr(e)
        | PythonStmt::Raise(e)
        | PythonStmt::Yield(e) => contains_unresolved(e),
        PythonStmt::If { test, body, orelse } => {
            contains_unresolved(test)
                || body.iter().any(stmt_has_unresolved)
                || orelse.iter().any(stmt_has_unresolved)
        }
        PythonStmt::Assign { value, .. } | PythonStmt::TupleUnpackAssign { value, .. } => {
            contains_unresolved(value)
        }
        PythonStmt::For { iter, body, .. } => {
            contains_unresolved(iter) || body.iter().any(stmt_has_unresolved)
        }
        PythonStmt::While { test, body } => {
            contains_unresolved(test) || body.iter().any(stmt_has_unresolved)
        }
        PythonStmt::Try { body, handlers } => {
            body.iter().any(stmt_has_unresolved)
                || handlers
                    .iter()
                    .any(|h: &ExceptHandler| h.body.iter().any(stmt_has_unresolved))
        }
        PythonStmt::Break | PythonStmt::Continue => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyLift {
    pub stmts: Vec<PythonStmt>,
    pub fidelity: LiftFidelity,
    pub unrecognized_lines: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompKind {
    List,
    Dict,
    Set,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceKind {
    List,
    Tuple,
}

impl SequenceKind {
    fn strip(token: &str) -> Option<(Self, &str)> {
        token
            .strip_prefix("MAKE_LIST")
            .map(|rest: &str| (Self::List, rest))
            .or_else(|| {
                token
                    .strip_prefix("MAKE_TUPLE")
                    .map(|rest: &str| (Self::Tuple, rest))
            })
    }

    const fn build(self, items: Vec<PythonExpr>) -> PythonExpr {
        match self {
            Self::List => PythonExpr::List(items),
            Self::Tuple => PythonExpr::Tuple(items),
        }
    }
}

const MAX_LIFT_DEPTH: usize = 256;

struct Lifter<'a> {
    lines: Vec<&'a str>,
    pool: &'a ConstantsPool,
    pack: EraPatternPack,
    depth: std::cell::Cell<usize>,
    eval_depth: std::cell::Cell<usize>,
}

struct Block {
    stmts: Vec<PythonStmt>,
    unrecognized: Vec<String>,
}

impl<'a> Lifter<'a> {
    fn new(c_body: &'a str, pool: &'a ConstantsPool, pack: EraPatternPack) -> Self {
        let lines: Vec<&'a str> = c_body.lines().map(str::trim).collect();
        Self {
            lines,
            pool,
            pack,
            depth: std::cell::Cell::new(0),
            eval_depth: std::cell::Cell::new(0),
        }
    }

    fn lift_block(&self, from: usize, to: usize, env: &mut BTreeMap<String, PythonExpr>) -> Block {
        if self.depth.get() >= MAX_LIFT_DEPTH {
            return Block {
                stmts: Vec::new(),
                unrecognized: vec!["<nuitka c-lift recursion depth limit>".to_owned()],
            };
        }
        self.depth.set(self.depth.get() + 1);
        let block: Block = self.lift_block_inner(from, to, env);
        self.depth.set(self.depth.get() - 1);
        block
    }

    fn lift_block_inner(
        &self,
        from: usize,
        to: usize,
        env: &mut BTreeMap<String, PythonExpr>,
    ) -> Block {
        let end: usize = to.min(self.lines.len());
        let mut stmts: Vec<PythonStmt> = Vec::new();
        let mut unrecognized: Vec<String> = Vec::new();
        let mut i: usize = from;
        while i < end {
            let line: &str = self.lines[i];
            if let Some(consumed) = self.try_structural(i, end, env, &mut stmts, &mut unrecognized)
            {
                i += consumed.max(1);
                continue;
            }
            if let Some(consumed) = self.try_assignment(i, env, &mut stmts) {
                i += consumed.max(1);
                continue;
            }
            if !should_skip(line) {
                unrecognized.push(line.to_owned());
            }
            i += 1;
        }
        Block {
            stmts,
            unrecognized,
        }
    }

    fn try_structural(
        &self,
        i: usize,
        end: usize,
        env: &mut BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
        unrecognized: &mut Vec<String>,
    ) -> Option<usize> {
        if stmts.is_empty()
            && let Some(consumed) = self.try_try_except(i, end, env, stmts, unrecognized)
        {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_yield(i, end, env, stmts) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_return(i, env, stmts) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_tuple_unpack(i, end, env, stmts) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_comprehension(i, end, env) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_for_loop(i, end, env, stmts, unrecognized) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_while_loop(i, end, env, stmts, unrecognized) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_value_diamond(i, end, env, stmts) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_if_branch(i, end, env, stmts, unrecognized) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_raise(i, env, stmts) {
            return Some(consumed);
        }
        if let Some(consumed) = self.try_break(i) {
            stmts.push(PythonStmt::Break);
            return Some(consumed);
        }
        None
    }

    fn try_break(&self, i: usize) -> Option<usize> {
        let line: &str = self.lines[i];
        let tag: &str = line.strip_prefix("goto loop_end_")?.trim_end_matches(';');
        if tag.chars().all(|c: char| c.is_ascii_digit()) {
            Some(1)
        } else {
            None
        }
    }

    fn try_yield(
        &self,
        i: usize,
        end: usize,
        env: &BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
    ) -> Option<usize> {
        let index_line: &str = self.lines[i];
        let idx_token: &str = index_line
            .strip_prefix("generator->m_yield_return_index = ")?
            .trim_end_matches(';')
            .trim();
        if !idx_token.chars().all(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let ret_idx: usize = (i + 1..end.min(self.lines.len())).find(|&k: &usize| {
            let t: &str = self.lines[k];
            t.starts_with("return ") && !t.starts_with("return NULL")
        })?;
        let value_token: &str = self.lines[ret_idx]
            .strip_prefix("return ")?
            .trim_end_matches(';')
            .trim();
        let value: PythonExpr = env
            .get(value_token)
            .cloned()
            .unwrap_or_else(|| self.eval_value(value_token, env));
        stmts.push(PythonStmt::Yield(value));
        let resume_label: String = format!("yield_return_{idx_token}:");
        let resume: usize = self
            .find_exact_label(ret_idx + 1, end, &resume_label)
            .map_or(ret_idx, |k: usize| k);
        Some(resume.saturating_sub(i) + 1)
    }

    fn try_return(
        &self,
        i: usize,
        env: &BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];
        let rhs: &str = line
            .strip_prefix("tmp_return_value = ")?
            .trim_end_matches(';');
        if rhs.starts_with("PyUnicode_Join(") {
            let expr: PythonExpr = Self::eval_unicode_join(rhs, env)?;
            stmts.push(PythonStmt::Return(expr));
            return Some(1);
        }
        if rhs.starts_with("MAKE_LIST_EMPTY(") {
            let (items, end): (Vec<PythonExpr>, usize) =
                self.collect_list_fills(i, "tmp_return_value", env);
            stmts.push(PythonStmt::Return(PythonExpr::List(items)));
            return Some(end.saturating_sub(i).max(1));
        }
        if rhs.starts_with("MAKE_TUPLE_EMPTY(") {
            let (items, end): (Vec<PythonExpr>, usize) =
                self.collect_tuple_fills(i, "tmp_return_value", env);
            stmts.push(PythonStmt::Return(PythonExpr::Tuple(items)));
            return Some(end.saturating_sub(i).max(1));
        }
        if rhs.starts_with("_PyDict_NewPresized(") || rhs.starts_with("DICT_NEW") {
            let (pairs, end): (Vec<(PythonExpr, PythonExpr)>, usize) =
                self.collect_dict_fills(i, "tmp_return_value", env);
            stmts.push(PythonStmt::Return(PythonExpr::Dict(pairs)));
            return Some(end.saturating_sub(i).max(1));
        }
        let expr: PythonExpr = self.eval_value(rhs, env);
        stmts.push(PythonStmt::Return(expr));
        Some(1)
    }

    fn collect_list_fills(
        &self,
        from: usize,
        target: &str,
        env: &BTreeMap<String, PythonExpr>,
    ) -> (Vec<PythonExpr>, usize) {
        let mut local: BTreeMap<String, PythonExpr> = env.clone();
        let mut indexed: BTreeMap<u32, PythonExpr> = BTreeMap::new();
        let mut last: usize = from;
        let mut i: usize = from + 1;
        while i < self.lines.len() {
            let t: &str = self.lines[i];
            if t.starts_with("goto ") && t.contains("return_exit") {
                last = i;
                break;
            }
            if let Some((name, rhs)) = parse_assignment(t)
                && name.starts_with("tmp_")
                && rhs.trim() != "NULL"
            {
                local.insert(name.to_owned(), self.eval_value(rhs, &local));
            }
            if let Some((idx, value_tok)) = parse_list_set_item(t, target) {
                let value: PythonExpr = local
                    .get(value_tok)
                    .cloned()
                    .unwrap_or_else(|| self.eval_value(value_tok, &local));
                indexed.insert(idx, value);
                last = i;
            }
            i += 1;
        }
        (indexed.into_values().collect(), last + 1)
    }

    fn collect_tuple_fills(
        &self,
        from: usize,
        target: &str,
        env: &BTreeMap<String, PythonExpr>,
    ) -> (Vec<PythonExpr>, usize) {
        let mut local: BTreeMap<String, PythonExpr> = env.clone();
        let mut indexed: BTreeMap<u32, PythonExpr> = BTreeMap::new();
        let mut last: usize = from;
        let mut i: usize = from + 1;
        while i < self.lines.len() {
            let t: &str = self.lines[i];
            if t.starts_with("goto ") && t.contains("return_exit") {
                last = i;
                break;
            }
            if let Some((name, rhs)) = parse_assignment(t)
                && name.starts_with("tmp_")
                && rhs.trim() != "NULL"
            {
                local.insert(name.to_owned(), self.eval_value(rhs, &local));
            }
            if let Some((idx, value_tok)) = parse_set_item(t, target) {
                let value: PythonExpr = local
                    .get(value_tok)
                    .cloned()
                    .unwrap_or_else(|| self.eval_value(value_tok, &local));
                indexed.insert(idx, value);
                last = i;
            }
            i += 1;
        }
        (indexed.into_values().collect(), last + 1)
    }

    fn collect_dict_fills(
        &self,
        from: usize,
        target: &str,
        env: &BTreeMap<String, PythonExpr>,
    ) -> (Vec<(PythonExpr, PythonExpr)>, usize) {
        let mut local: BTreeMap<String, PythonExpr> = env.clone();
        let mut pairs: Vec<(PythonExpr, PythonExpr)> = Vec::new();
        let mut last: usize = from;
        let mut i: usize = from + 1;
        while i < self.lines.len() {
            let t: &str = self.lines[i];
            if t.starts_with("goto ") && t.contains("return_exit") {
                last = i;
                break;
            }
            if let Some((name, rhs)) = parse_assignment(t)
                && name.starts_with("tmp_")
                && rhs.trim() != "NULL"
            {
                local.insert(name.to_owned(), self.eval_value(rhs, &local));
            }
            if let Some((key_tok, value_tok)) = parse_dict_set_item(t, target) {
                let key: PythonExpr = local
                    .get(key_tok)
                    .cloned()
                    .unwrap_or_else(|| self.eval_value(key_tok, &local));
                let value: PythonExpr = local
                    .get(value_tok)
                    .cloned()
                    .unwrap_or_else(|| self.eval_value(value_tok, &local));
                pairs.push((key, value));
                last = i;
            }
            i += 1;
        }
        (pairs, last + 1)
    }

    fn try_raise(
        &self,
        i: usize,
        env: &BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];
        if !line.starts_with("RAISE_EXCEPTION_WITH_VALUE(") {
            return None;
        }
        let value_var: Option<String> = self.find_before(i, 30, |l: &str| {
            l.starts_with("exception_state.exception_value = ")
        });
        let value_tok: String = value_var?
            .strip_prefix("exception_state.exception_value = ")?
            .trim_end_matches(';')
            .to_owned();
        let expr: PythonExpr = env
            .get(value_tok.trim())
            .cloned()
            .unwrap_or_else(|| self.eval_value(value_tok.trim(), env));
        stmts.push(PythonStmt::Raise(expr));
        Some(1)
    }

    fn try_try_except(
        &self,
        i: usize,
        end: usize,
        env: &BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
        unrecognized: &mut Vec<String>,
    ) -> Option<usize> {
        let handler_label: usize = self.try_body_handler(i, end)?;
        let handler_tag: &str = self.lines[handler_label].trim_end_matches(":;");

        let mut body_env: BTreeMap<String, PythonExpr> = env.clone();
        let body: Block = self.lift_block(i, handler_label, &mut body_env);
        unrecognized.extend(body.unrecognized);

        let (handlers, h_end): (Vec<ExceptHandler>, usize) =
            self.lift_except_handlers(handler_label + 1, end, env)?;

        if body.stmts.is_empty() && handlers.iter().all(|h: &ExceptHandler| h.body.is_empty()) {
            return None;
        }
        let _ = handler_tag;
        stmts.push(PythonStmt::Try {
            body: body.stmts,
            handlers,
        });
        Some(h_end.saturating_sub(i).max(1))
    }

    fn try_body_handler(&self, i: usize, end: usize) -> Option<usize> {
        let mut depth_handler: Option<usize> = None;
        let mut saw_goto: bool = false;
        for idx in i..end.min(self.lines.len()) {
            let t: &str = self.lines[idx];
            if t.starts_with("goto try_except_handler_") {
                saw_goto = true;
            }
            if t.starts_with("try_except_handler_") && t.ends_with(":;") {
                depth_handler = Some(idx);
                break;
            }
            if t.starts_with("loop_start_") {
                return None;
            }
        }
        let handler: usize = depth_handler?;
        if !saw_goto {
            return None;
        }
        if !self.lines[handler + 1..end.min(self.lines.len())]
            .iter()
            .take(40)
            .any(|l: &&str| l.contains("EXCEPTION_MATCH_BOOL("))
        {
            return None;
        }
        Some(handler)
    }

    fn lift_except_handlers(
        &self,
        from: usize,
        end: usize,
        env: &BTreeMap<String, PythonExpr>,
    ) -> Option<(Vec<ExceptHandler>, usize)> {
        let mut handlers: Vec<ExceptHandler> = Vec::new();
        let mut cursor: usize = from;
        while cursor < end.min(self.lines.len()) {
            let Some(match_line): Option<usize> =
                self.find_before_reraise(cursor, end, "EXCEPTION_MATCH_BOOL(")
            else {
                break;
            };
            let mut match_env: BTreeMap<String, PythonExpr> = env.clone();
            for idx in cursor..match_line {
                if let Some((name, rhs)) = parse_assignment(self.lines[idx])
                    && name.starts_with("tmp_")
                    && rhs.trim() != "NULL"
                {
                    match_env.insert(name.to_owned(), self.eval_value(rhs, &match_env));
                }
            }
            let exc_type: Option<String> = self.exception_match_type(match_line, &match_env);

            let yes_label: usize = self.find_label(match_line, end, "branch_yes_")?;
            let no_label: usize = self.find_label(match_line, end, "branch_no_")?;
            let (bind_name, body_start): (Option<String>, usize) =
                self.except_as_binding(yes_label + 1, no_label);
            let body_end: usize = no_label.min(
                self.find_after(body_start, no_label, |l: &str| {
                    l.starts_with("goto try_return_handler_")
                        || l.starts_with("goto branch_end_")
                        || l.starts_with("goto try_except_handler_")
                })
                .unwrap_or(no_label),
            );

            let mut handler_env: BTreeMap<String, PythonExpr> = env.clone();
            if let Some(name) = &bind_name {
                handler_env.insert(format!("var_{name}"), PythonExpr::Name(name.clone()));
            }
            let handler_block: Block = self.lift_block(body_start, body_end, &mut handler_env);
            handlers.push(ExceptHandler {
                exc_type,
                name: bind_name,
                body: handler_block.stmts,
            });
            cursor = no_label + 1;
        }

        if handlers.is_empty() {
            return None;
        }
        let region_end: usize = self
            .find_after(cursor.saturating_sub(1), end, |l: &str| {
                l.starts_with("goto function_return_exit")
                    || l.starts_with("goto frame_exception_exit")
            })
            .unwrap_or(end);
        Some((handlers, region_end))
    }

    fn find_before_reraise(&self, from: usize, to: usize, needle: &str) -> Option<usize> {
        let end: usize = to.min(self.lines.len());
        for idx in from..end {
            let t: &str = self.lines[idx];
            if t.starts_with("tmp_result = RERAISE_EXCEPTION(") || t.starts_with("// Re-raise.") {
                return None;
            }
            if t.contains(needle) {
                return Some(idx);
            }
        }
        None
    }

    fn except_as_binding(&self, from: usize, to: usize) -> (Option<String>, usize) {
        let end: usize = to.min(self.lines.len());
        let mut exc_value_temp: Option<&str> = None;
        for idx in from..end {
            let t: &str = self.lines[idx];
            if let Some((name, rhs)) = parse_assignment(t) {
                let rhs_t: &str = rhs.trim();
                if name.starts_with("tmp_") && rhs_t.starts_with("EXC_VALUE(") {
                    exc_value_temp = Some(name);
                    continue;
                }
                if let Some(var) = name.strip_prefix("var_")
                    && exc_value_temp.is_some_and(|tv: &str| rhs_t == tv)
                {
                    return (Some(var.to_owned()), idx + 1);
                }
            }
        }
        (None, from)
    }

    fn exception_match_type(
        &self,
        match_line: usize,
        env: &BTreeMap<String, PythonExpr>,
    ) -> Option<String> {
        let pos: usize = self.lines[match_line].find("EXCEPTION_MATCH_BOOL(")?;
        let after: &str = &self.lines[match_line][pos + "EXCEPTION_MATCH_BOOL(".len()..];
        let inner: &str = trim_matching_paren(after);
        let args: Vec<&str> = split_top_args(inner)?;
        let type_tok: &str = args.last()?.trim();
        match self.eval_operand(type_tok, env) {
            PythonExpr::Name(n) => Some(n),
            _ => None,
        }
    }

    fn try_tuple_unpack(
        &self,
        i: usize,
        end: usize,
        env: &mut BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];
        let (lhs, _): (&str, &str) = parse_assignment(line)?;
        let unpack_id: &str = lhs.strip_suffix("__source_iter")?;

        let mut local: BTreeMap<String, PythonExpr> = env.clone();
        let element_prefix: String = format!("{unpack_id}__element_");
        let mut elem_of: BTreeMap<String, u32> = BTreeMap::new();
        let mut element_value: BTreeMap<u32, PythonExpr> = BTreeMap::new();
        let mut targets: Vec<(u32, String)> = Vec::new();
        let mut last: usize = i;
        let mut idx: usize = i;
        while idx < end {
            let t: &str = self.lines[idx];
            if let Some((unpack_idx, _)) = parse_unpack_next(t)
                && let Some((name, rhs)) = parse_assignment(t)
            {
                let value: PythonExpr = self.eval_value(rhs, &local);
                element_value.entry(unpack_idx).or_insert(value);
                elem_of.insert(name.to_owned(), unpack_idx);
                last = idx;
            }
            if let Some((name, rhs)) = parse_assignment(t) {
                let rhs_tok: &str = rhs.trim();
                if let Some(suffix) = rhs_tok.strip_prefix(&element_prefix) {
                    if let Ok(n) = suffix.parse::<u32>() {
                        elem_of.insert(name.to_owned(), n.saturating_sub(1));
                    }
                } else if let Some(&e) = elem_of.get(rhs_tok) {
                    elem_of.insert(name.to_owned(), e);
                }
                if let Some(elem_idx) = name.strip_prefix(&element_prefix)
                    && let Ok(n) = elem_idx.parse::<u32>()
                {
                    elem_of.insert(name.to_owned(), n.saturating_sub(1));
                }
                if name.starts_with("tmp_") && rhs.trim() != "NULL" {
                    let expr: PythonExpr = self.eval_value(rhs, &local);
                    local.insert(name.to_owned(), expr);
                }
            }
            if let Some(rest) = t.strip_prefix("var_").or_else(|| t.strip_prefix("par_"))
                && let Some((vname, src)) = rest.split_once(" = ")
            {
                let src: &str = src.trim_end_matches(';').trim();
                if let Some(&elem_idx) = elem_of.get(src) {
                    targets.push((elem_idx, vname.to_owned()));
                    last = idx;
                }
            }
            if idx > i {
                let new_unpack: bool = parse_assignment(t).is_some_and(|(lhs, _): (&str, &str)| {
                    lhs.ends_with("__source_iter") && lhs != format!("{unpack_id}__source_iter")
                });
                if t.starts_with("loop_start_") || t.starts_with("tmp_return_value =") || new_unpack
                {
                    break;
                }
            }
            idx += 1;
        }

        if targets.is_empty() {
            return None;
        }
        targets.sort_by_key(|(k, _): &(u32, String)| *k);

        let source: PythonExpr =
            Self::resolve_unpack_source(unpack_id, &element_value, &targets, &local);
        let target_names: Vec<String> =
            targets.into_iter().map(|(_, n): (u32, String)| n).collect();
        for t in &target_names {
            env.insert(format!("var_{t}"), PythonExpr::Name(t.clone()));
            env.insert(format!("par_{t}"), PythonExpr::Name(t.clone()));
        }
        stmts.push(PythonStmt::TupleUnpackAssign {
            targets: target_names,
            value: source,
        });
        Some(last.saturating_sub(i) + 1)
    }

    fn resolve_unpack_source(
        unpack_id: &str,
        element_value: &BTreeMap<u32, PythonExpr>,
        targets: &[(u32, String)],
        local: &BTreeMap<String, PythonExpr>,
    ) -> PythonExpr {
        let iter_token: String = format!("{unpack_id}__source_iter");
        if let Some(PythonExpr::Tuple(items) | PythonExpr::List(items)) = local.get(&iter_token)
            && items.len() == targets.len()
        {
            return PythonExpr::Tuple(items.clone());
        }
        let mut parts: Vec<PythonExpr> = Vec::with_capacity(targets.len());
        for (elem_idx, _) in targets {
            if let Some(expr) = element_value.get(elem_idx) {
                parts.push(expr.clone());
            } else {
                parts.push(PythonExpr::Name(format!("UNRESOLVED:elem_{elem_idx}")));
            }
        }
        PythonExpr::Tuple(parts)
    }

    fn try_comprehension(
        &self,
        i: usize,
        end: usize,
        env: &mut BTreeMap<String, PythonExpr>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];
        let loop_tag: &str = line.strip_prefix("loop_start_")?.trim_end_matches(":;");
        if !loop_tag.chars().all(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let (kind, contraction_var): (CompKind, String) = self.find_comprehension_kind(i)?;
        let iter_token: &str = self.find_before_token(i, 40, "__$0 = ")?;
        let iter_expr: PythonExpr = env
            .get(iter_token)
            .cloned()
            .unwrap_or_else(|| self.eval_value(iter_token, env));
        let loop_end: usize = self.find_label(i + 1, end, "loop_end_")?;

        let mut body_env: BTreeMap<String, PythonExpr> = env.clone();
        let target: String = self.bind_comp_target(i + 1, loop_end, &mut body_env)?;

        let result: PythonExpr = match kind {
            CompKind::List => {
                let element: PythonExpr =
                    self.find_append_value(i + 1, loop_end, &contraction_var, &mut body_env)?;
                PythonExpr::ListComp {
                    element: Box::new(element),
                    target,
                    iter: Box::new(iter_expr),
                }
            }
            CompKind::Dict => {
                let (key, value): (PythonExpr, PythonExpr) =
                    self.find_dict_set(i + 1, loop_end, &contraction_var, &mut body_env)?;
                PythonExpr::DictComp {
                    key: Box::new(key),
                    value: Box::new(value),
                    target,
                    iter: Box::new(iter_expr),
                }
            }
            CompKind::Set => {
                let element: PythonExpr =
                    self.find_set_add_value(i + 1, loop_end, &mut body_env)?;
                PythonExpr::SetComp {
                    element: Box::new(element),
                    target,
                    iter: Box::new(iter_expr),
                }
            }
        };
        env.insert(contraction_var, result);
        Some(loop_end.saturating_sub(i) + 1)
    }

    fn find_comprehension_kind(&self, loop_start: usize) -> Option<(CompKind, String)> {
        let lo: usize = loop_start.saturating_sub(40);
        let mut contraction: Option<String> = None;
        for idx in (lo..loop_start).rev() {
            if let Some((name, _)) = parse_assignment(self.lines[idx])
                && name.ends_with("__contraction")
            {
                contraction = Some(name.to_owned());
                break;
            }
        }
        let contraction: String = contraction?;
        if contraction.contains("listcontraction") || contraction.contains("listcomp") {
            return Some((CompKind::List, contraction));
        }
        if contraction.contains("setcontraction") || contraction.contains("setcomp") {
            return Some((CompKind::Set, contraction));
        }
        if contraction.contains("dictcontraction")
            || contraction.contains("dictcomp")
            || contraction.contains("dict")
        {
            return Some((CompKind::Dict, contraction));
        }
        let hi: usize = (loop_start + 200).min(self.lines.len());
        for l in &self.lines[loop_start..hi] {
            if l.contains("LIST_APPEND1(") {
                return Some((CompKind::List, contraction));
            }
            if l.contains("PySet_Add(") {
                return Some((CompKind::Set, contraction));
            }
            if l.contains("DICT_SET_ITEM(") || l.contains("PyDict_SetItem(") {
                return Some((CompKind::Dict, contraction));
            }
        }
        None
    }

    fn bind_comp_target(
        &self,
        from: usize,
        to: usize,
        env: &mut BTreeMap<String, PythonExpr>,
    ) -> Option<String> {
        for idx in from..to.min(self.lines.len()) {
            let t: &str = self.lines[idx];
            let Some((name, rhs)): Option<(&str, &str)> = parse_assignment(t) else {
                continue;
            };
            let outline_bind: bool = name.starts_with("outline_") && name.contains("_var_");
            let var_bind: bool = name.starts_with("var_") && rhs.contains("__iter_value");
            if outline_bind || var_bind {
                let var: &str = name
                    .rsplit("_var_")
                    .next()
                    .or_else(|| name.strip_prefix("var_"))
                    .unwrap_or(name);
                env.insert(name.to_owned(), PythonExpr::Name(var.to_owned()));
                return Some(var.to_owned());
            }
        }
        None
    }

    fn find_append_value(
        &self,
        from: usize,
        to: usize,
        _contraction: &str,
        env: &mut BTreeMap<String, PythonExpr>,
    ) -> Option<PythonExpr> {
        for idx in from..to.min(self.lines.len()) {
            let t: &str = self.lines[idx];
            if let Some((name, rhs)) = parse_assignment(t)
                && name.starts_with("tmp_")
                && rhs.trim() != "NULL"
            {
                env.insert(name.to_owned(), self.eval_value(rhs, env));
            }
            if let Some(pos) = t.find("LIST_APPEND1(") {
                let after: &str = &t[pos + "LIST_APPEND1(".len()..];
                let inner: &str = trim_matching_paren(after);
                let value_tok: &str = split_top_args(inner)?.last()?.trim();
                return Some(
                    env.get(value_tok)
                        .cloned()
                        .unwrap_or_else(|| self.eval_value(value_tok, env)),
                );
            }
        }
        None
    }

    fn find_dict_set(
        &self,
        from: usize,
        to: usize,
        _contraction: &str,
        env: &mut BTreeMap<String, PythonExpr>,
    ) -> Option<(PythonExpr, PythonExpr)> {
        for idx in from..to.min(self.lines.len()) {
            let t: &str = self.lines[idx];
            if let Some((name, rhs)) = parse_assignment(t)
                && name.starts_with("tmp_")
                && rhs.trim() != "NULL"
            {
                env.insert(name.to_owned(), self.eval_value(rhs, env));
            }
            for marker in ["DICT_SET_ITEM(", "PyDict_SetItem("] {
                if let Some(pos) = t.find(marker) {
                    let after: &str = &t[pos + marker.len()..];
                    let inner: &str = trim_matching_paren(after);
                    let args: Vec<&str> = split_top_args(inner)?;
                    if args.len() == 3 {
                        let key: PythonExpr = env
                            .get(args[1].trim())
                            .cloned()
                            .unwrap_or_else(|| self.eval_value(args[1].trim(), env));
                        let value: PythonExpr = env
                            .get(args[2].trim())
                            .cloned()
                            .unwrap_or_else(|| self.eval_value(args[2].trim(), env));
                        return Some((key, value));
                    }
                }
            }
        }
        None
    }

    fn find_set_add_value(
        &self,
        from: usize,
        to: usize,
        env: &mut BTreeMap<String, PythonExpr>,
    ) -> Option<PythonExpr> {
        for idx in from..to.min(self.lines.len()) {
            let t: &str = self.lines[idx];
            if let Some((name, rhs)) = parse_assignment(t)
                && name.starts_with("tmp_")
                && rhs.trim() != "NULL"
            {
                env.insert(name.to_owned(), self.eval_value(rhs, env));
            }
            if let Some(pos) = t.find("PySet_Add(") {
                let after: &str = &t[pos + "PySet_Add(".len()..];
                let inner: &str = trim_matching_paren(after);
                let value_tok: &str = split_top_args(inner)?.last()?.trim();
                return Some(
                    env.get(value_tok)
                        .cloned()
                        .unwrap_or_else(|| self.eval_value(value_tok, env)),
                );
            }
        }
        None
    }

    fn try_for_loop(
        &self,
        i: usize,
        end: usize,
        env: &BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
        unrecognized: &mut Vec<String>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];
        let loop_tag: &str = line.strip_prefix("loop_start_")?.trim_end_matches(":;");
        if !loop_tag.chars().all(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let iter_var: &str = self.find_before_token(i, 80, "__for_iterator = ")?;
        let iter_expr: PythonExpr = env
            .get(iter_var)
            .cloned()
            .unwrap_or_else(|| self.eval_value(iter_var, env));

        let loop_end: usize = self.find_label(i + 1, end, "loop_end_")?;

        let (target_var, target_bind_idx): (String, usize) =
            self.find_for_target(i + 1, loop_end)?;
        let body_start: usize = target_bind_idx + 1;

        let mut body_env: BTreeMap<String, PythonExpr> = env.clone();
        if target_var != "_" {
            body_env.insert(
                format!("var_{target_var}"),
                PythonExpr::Name(target_var.clone()),
            );
        }
        let body: Block = self.lift_block(body_start, loop_end, &mut body_env);
        unrecognized.extend(body.unrecognized);

        stmts.push(PythonStmt::For {
            target: target_var,
            iter: iter_expr,
            body: body.stmts,
        });
        Some(loop_end.saturating_sub(i) + 1)
    }

    fn find_for_target(&self, from: usize, to: usize) -> Option<(String, usize)> {
        let end: usize = to.min(self.lines.len());
        let iter_value_temp: Option<&str> = self.find_iter_value_temp(from, end);
        for idx in from..end {
            let t: &str = self.lines[idx];
            let Some(rest): Option<&str> = t.strip_prefix("var_") else {
                continue;
            };
            let Some((name, rhs)): Option<(&str, &str)> = rest.split_once(" = ") else {
                continue;
            };
            let rhs: &str = rhs.trim_end_matches(';').trim();
            let binds_iter_value: bool = iter_value_temp.is_some_and(|tv: &str| rhs == tv)
                || rhs.starts_with("tmp_assign_source")
                || rhs.contains("__iter_value");
            if binds_iter_value && !name.is_empty() {
                let target: String = if name == "_" {
                    "_".to_owned()
                } else {
                    name.to_owned()
                };
                return Some((target, idx));
            }
        }
        None
    }

    fn find_iter_value_temp(&self, from: usize, to: usize) -> Option<&str> {
        for l in &self.lines[from..to.min(self.lines.len())] {
            let t: &str = l.trim();
            if let Some(rest) = t.strip_prefix("tmp_assign_source")
                && let Some((_, rhs)) = rest.split_once(" = ")
            {
                let rhs: &str = rhs.trim_end_matches(';').trim();
                if rhs.ends_with("__iter_value") {
                    return Some(rhs);
                }
            }
        }
        None
    }

    fn try_while_loop(
        &self,
        i: usize,
        end: usize,
        env: &mut BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
        unrecognized: &mut Vec<String>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];
        let loop_tag: &str = line.strip_prefix("loop_start_")?.trim_end_matches(":;");
        if !loop_tag.chars().all(|c: char| c.is_ascii_digit()) {
            return None;
        }
        if self.find_before_token(i, 80, "__for_iterator = ").is_some() {
            return None;
        }
        let loop_end: usize = self.find_label(i + 1, end, "loop_end_")?;

        let (test, body_start): (PythonExpr, usize) =
            self.extract_while_condition(i + 1, loop_end, env)?;

        let mut body_env: BTreeMap<String, PythonExpr> = env.clone();
        let body: Block = self.lift_block(body_start, loop_end, &mut body_env);
        unrecognized.extend(body.unrecognized);

        stmts.push(PythonStmt::While {
            test,
            body: body.stmts,
        });
        Some(loop_end.saturating_sub(i) + 1)
    }

    fn extract_while_condition(
        &self,
        from: usize,
        to: usize,
        env: &mut BTreeMap<String, PythonExpr>,
    ) -> Option<(PythonExpr, usize)> {
        let mut local: BTreeMap<String, PythonExpr> = env.clone();
        let mut i: usize = from;
        while i < to {
            let line: &str = self.lines[i];
            if let Some((name, rhs)) = parse_assignment(line)
                && name.starts_with("tmp_")
            {
                let expr: PythonExpr = self.eval_value(rhs, &local);
                local.insert(name.to_owned(), expr);
            }
            if line.starts_with("if (tmp_condition_result_")
                && (line.contains("== NUITKA_BOOL_TRUE") || line.contains("!= false"))
            {
                let cond_var: &str = condition_var_from_if(line)?;
                let raw: PythonExpr = local.get(cond_var)?.clone();
                let break_jumps_out: bool = self.branch_breaks(i, to);
                let test: PythonExpr = if break_jumps_out {
                    negate_condition(raw)
                } else {
                    raw
                };
                let body_start: usize = self.find_label(i, to, "branch_no_")? + 1;
                env.clone_from(&local);
                return Some((test, body_start));
            }
            i += 1;
        }
        None
    }

    fn branch_breaks(&self, if_idx: usize, to: usize) -> bool {
        if let Some(yes_idx) = self.find_label(if_idx, to, "branch_yes_") {
            let lo: usize = yes_idx + 1;
            let hi: usize = (yes_idx + 4).min(to);
            return self.lines[lo..hi]
                .iter()
                .any(|l: &&str| l.starts_with("goto loop_end_"));
        }
        false
    }

    fn try_value_diamond(
        &self,
        i: usize,
        end: usize,
        env: &mut BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];
        if line.starts_with("if (tmp_and_left_truth_") {
            return self.try_bool_diamond(i, end, env, stmts, BoolOpKind::And);
        }
        if line.starts_with("if (tmp_or_left_truth_") {
            return self.try_bool_diamond(i, end, env, stmts, BoolOpKind::Or);
        }
        if line.starts_with("if (tmp_condition_result_")
            && (line.contains("== NUITKA_BOOL_TRUE") || line.contains("!= false"))
        {
            let yes_idx: usize = self.find_after(i, (i + 4).min(end), |l: &str| {
                l.starts_with("goto condexpr_true_")
            })?;
            return self.try_condexpr_diamond(i, yes_idx, end, env, stmts);
        }
        None
    }

    fn try_bool_diamond(
        &self,
        i: usize,
        end: usize,
        env: &mut BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
        op: BoolOpKind,
    ) -> Option<usize> {
        let kw: &str = if matches!(op, BoolOpKind::And) {
            "and"
        } else {
            "or"
        };
        let truth_var: &str = condition_var_from_if(self.lines[i])?;
        let left_value_temp: String = truth_var.replace("_truth_", "_value_");
        let left: PythonExpr = env.get(&left_value_temp)?.clone();

        let end_label: usize = self.find_label(i, end, &format!("{kw}_end_"))?;
        let right_label: usize = self.find_label(i, end, &format!("{kw}_right_"))?;
        let left_label: usize = self.find_label(i, end, &format!("{kw}_left_"))?;
        let (right_from, right_to): (usize, usize) = if right_label < left_label {
            (right_label + 1, left_label)
        } else {
            (right_label + 1, end_label)
        };

        let mut right_env: BTreeMap<String, PythonExpr> = env.clone();
        let mut right: Option<PythonExpr> = None;
        let mut result_temp: Option<String> = None;
        for idx in right_from..right_to {
            let t: &str = self.lines[idx];
            if let Some((name, rhs)) = parse_assignment(t) {
                if name.starts_with("tmp_") && rhs.trim() != "NULL" {
                    right_env.insert(name.to_owned(), self.eval_value(rhs, &right_env));
                }
                if name.starts_with("tmp_return_value") {
                    right = Some(self.eval_value(rhs, &right_env));
                    result_temp = Some(name.to_owned());
                }
            }
        }
        let right_expr: PythonExpr = right?;
        let value: PythonExpr = PythonExpr::BoolOp {
            op,
            left: Box::new(left),
            right: Box::new(right_expr),
        };
        let target: String = result_temp.unwrap_or_else(|| "tmp_return_value".to_owned());
        if target.starts_with("tmp_return_value") {
            stmts.push(PythonStmt::Return(value));
        } else {
            env.insert(target, value);
        }
        Some(end_label.saturating_sub(i) + 1)
    }

    fn try_condexpr_diamond(
        &self,
        i: usize,
        yes_idx: usize,
        end: usize,
        env: &mut BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
    ) -> Option<usize> {
        let cond_var: &str = condition_var_from_if(self.lines[i])?;
        let test: PythonExpr = env.get(cond_var)?.clone();
        let _ = yes_idx;

        let true_label: usize = self.find_label(i, end, "condexpr_true_")?;
        let false_label: usize = self.find_label(i, end, "condexpr_false_")?;
        let end_label: usize = self.find_label(i, end, "condexpr_end_")?;

        let body: PythonExpr = self.diamond_branch_value(true_label + 1, false_label, env)?;
        let orelse: PythonExpr = self.diamond_branch_value(false_label + 1, end_label, env)?;
        let value: PythonExpr = PythonExpr::IfExp {
            test: Box::new(test),
            body: Box::new(body),
            orelse: Box::new(orelse),
        };
        let target: String = self
            .diamond_result_temp(true_label + 1, false_label)
            .unwrap_or_else(|| "tmp_return_value".to_owned());
        if target.starts_with("tmp_return_value") {
            stmts.push(PythonStmt::Return(value));
        } else {
            env.insert(target, value);
        }
        Some(end_label.saturating_sub(i) + 1)
    }

    fn diamond_branch_value(
        &self,
        from: usize,
        to: usize,
        env: &BTreeMap<String, PythonExpr>,
    ) -> Option<PythonExpr> {
        let mut local: BTreeMap<String, PythonExpr> = env.clone();
        let mut result: Option<PythonExpr> = None;
        for idx in from..to.min(self.lines.len()) {
            let t: &str = self.lines[idx];
            if let Some((name, rhs)) = parse_assignment(t) {
                if rhs.trim() == "NULL" {
                    continue;
                }
                let value: PythonExpr = self.eval_value(rhs, &local);
                if name.starts_with("tmp_") {
                    local.insert(name.to_owned(), value.clone());
                }
                let is_return: bool = name.starts_with("tmp_return_value");
                if is_return || result.is_none() {
                    result = Some(value);
                }
            }
        }
        result
    }

    fn diamond_result_temp(&self, from: usize, to: usize) -> Option<String> {
        for idx in from..to.min(self.lines.len()) {
            if let Some((name, _)) = parse_assignment(self.lines[idx])
                && name.starts_with("tmp_return_value")
            {
                return Some(name.to_owned());
            }
        }
        None
    }

    fn try_if_branch(
        &self,
        i: usize,
        end: usize,
        env: &BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
        unrecognized: &mut Vec<String>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];
        if !line.starts_with("if (tmp_condition_result_") {
            return None;
        }
        if !(line.contains("== NUITKA_BOOL_TRUE") || line.contains("!= false")) {
            return None;
        }
        let cond_var: &str = condition_var_from_if(line)?;
        let raw_test: PythonExpr = env.get(cond_var)?.clone();

        let yes_idx: usize = self.find_after(i, (i + 4).min(end), |l: &str| {
            l.starts_with("goto branch_yes_")
        })?;
        let yes_tag: String = format!(
            "branch_yes_{}",
            self.lines[yes_idx]
                .strip_prefix("goto branch_yes_")?
                .trim_end_matches(';')
        );
        let no_tag: String = yes_tag.replacen("yes", "no", 1);

        let yes_start: usize = self.find_exact_label(i, end, &format!("{yes_tag}:;"))? + 1;
        let no_start: usize = self.find_exact_label(i, end, &format!("{no_tag}:;"))? + 1;

        let test: PythonExpr = raw_test;

        let mut yes_env: BTreeMap<String, PythonExpr> = env.clone();
        let yes_body: Block = self.lift_block(yes_start, no_start.saturating_sub(1), &mut yes_env);
        unrecognized.extend(yes_body.unrecognized);

        let yes_terminates: bool = yes_body
            .stmts
            .last()
            .is_some_and(|s: &PythonStmt| matches!(s, PythonStmt::Return(_) | PythonStmt::Break));

        if yes_terminates {
            stmts.push(PythonStmt::If {
                test,
                body: yes_body.stmts,
                orelse: Vec::new(),
            });
            return Some(no_start.saturating_sub(i));
        }

        let no_end: usize = self.find_branch_end(no_start, end);
        let mut no_env: BTreeMap<String, PythonExpr> = env.clone();
        let no_body: Block = self.lift_block(no_start, no_end, &mut no_env);
        unrecognized.extend(no_body.unrecognized);

        stmts.push(PythonStmt::If {
            test,
            body: yes_body.stmts,
            orelse: no_body.stmts,
        });
        Some(no_end.saturating_sub(i).max(1))
    }

    fn find_branch_end(&self, from: usize, end: usize) -> usize {
        for (offset, l) in self.lines[from..end].iter().enumerate() {
            let t: &str = l.trim();
            if t.starts_with("goto frame_return_exit")
                || t.starts_with("goto function_return_exit")
                || t.starts_with("goto frame_no_exception")
                || t.starts_with("tmp_return_value = ")
            {
                return from + offset;
            }
        }
        end
    }

    fn try_assignment(
        &self,
        i: usize,
        env: &mut BTreeMap<String, PythonExpr>,
        stmts: &mut Vec<PythonStmt>,
    ) -> Option<usize> {
        let line: &str = self.lines[i];

        if line.starts_with("PyTuple_SET_ITEM") {
            return self.try_tuple_build(i, env);
        }

        let (name, rhs): (&str, &str) = parse_assignment(line)?;

        if rhs == "NULL" {
            return Some(1);
        }

        if name.starts_with("tmp_call_result_") {
            let expr: PythonExpr = self.eval_value(rhs, env);
            env.insert(name.to_owned(), expr.clone());
            if matches!(expr, PythonExpr::Call { .. }) {
                stmts.push(PythonStmt::Expr(expr));
            }
            return Some(1);
        }

        if name.starts_with("tmp_") {
            let expr: PythonExpr = self.eval_value(rhs, env);
            env.insert(name.to_owned(), expr);
            return Some(1);
        }

        if let Some(local) = name.strip_prefix("var_") {
            if rhs.starts_with("MAKE_FUNCTION_") {
                env.insert(name.to_owned(), PythonExpr::Name(local.to_owned()));
                return Some(1);
            }
            if local == "_" {
                let expr: PythonExpr = self.eval_value(rhs, env);
                env.insert(name.to_owned(), expr.clone());
                stmts.push(PythonStmt::Assign {
                    targets: vec!["_".to_owned()],
                    value: expr,
                });
                return Some(1);
            }
            let expr: PythonExpr = self.eval_value(rhs, env);
            env.insert(name.to_owned(), PythonExpr::Name(local.to_owned()));
            if matches!(&expr, PythonExpr::Name(n) if n == local) {
                return Some(1);
            }
            stmts.push(PythonStmt::Assign {
                targets: vec![local.to_owned()],
                value: expr,
            });
            return Some(1);
        }

        if let Some(param) = name.strip_prefix("par_") {
            let expr: PythonExpr = self.eval_value(rhs, env);
            env.insert(name.to_owned(), PythonExpr::Name(param.to_owned()));
            stmts.push(PythonStmt::Assign {
                targets: vec![param.to_owned()],
                value: expr,
            });
            return Some(1);
        }

        None
    }

    fn try_tuple_build(&self, i: usize, env: &mut BTreeMap<String, PythonExpr>) -> Option<usize> {
        let line: &str = self.lines[i];
        let tuple_var: &str = line
            .trim_start_matches("PyTuple_SET_ITEM0(")
            .trim_start_matches("PyTuple_SET_ITEM(")
            .split(',')
            .next()?
            .trim();
        if env.contains_key(tuple_var) && !is_buildable_tuple_var(tuple_var) {
            return Some(1);
        }
        let (parts, end): (Vec<PythonExpr>, usize) = self.collect_tuple_parts(i, tuple_var, env)?;
        let is_fstring: bool = self.tuple_feeds_unicode_join(end, tuple_var);
        let value: PythonExpr = if is_fstring {
            PythonExpr::FStringJoin { parts }
        } else {
            PythonExpr::Tuple(parts)
        };
        env.insert(tuple_var.to_owned(), value);
        Some(end.saturating_sub(i).max(1))
    }

    fn collect_tuple_parts(
        &self,
        from: usize,
        tuple_var: &str,
        env: &BTreeMap<String, PythonExpr>,
    ) -> Option<(Vec<PythonExpr>, usize)> {
        let scan_start: usize = self.tuple_region_start(from, tuple_var);
        let mut local: BTreeMap<String, PythonExpr> = env.clone();
        let mut indexed: BTreeMap<u32, PythonExpr> = BTreeMap::new();
        let mut i: usize = scan_start;
        let mut last: usize = from;
        while i < self.lines.len() {
            let t: &str = self.lines[i];
            if t.starts_with("tmp_return_value =")
                || t.starts_with("goto tuple_build_no_exception")
                || t.starts_with("MAKE_ITERATOR")
                || t.contains("= MAKE_ITERATOR")
            {
                break;
            }
            if let Some((name, rhs)) = parse_assignment(t)
                && name.starts_with("tmp_")
            {
                let expr: PythonExpr = self.eval_value(rhs, &local);
                local.insert(name.to_owned(), expr);
            }
            if let Some((idx, value_tok)) = parse_set_item(t, tuple_var) {
                let value: PythonExpr = local
                    .get(value_tok)
                    .cloned()
                    .unwrap_or_else(|| self.eval_value(value_tok, &local));
                indexed.insert(idx, value);
                last = i;
            }
            i += 1;
        }
        if indexed.is_empty() {
            return None;
        }
        let parts: Vec<PythonExpr> = indexed.into_values().collect();
        Some((parts, last + 1))
    }

    fn tuple_region_start(&self, from: usize, tuple_var: &str) -> usize {
        let lo: usize = from.saturating_sub(30);
        for idx in (lo..from).rev() {
            let t: &str = self.lines[idx];
            if let Some(rest) = t.strip_prefix(tuple_var)
                && rest.trim_start().starts_with("= MAKE_TUPLE_EMPTY")
            {
                return idx;
            }
        }
        lo
    }

    fn tuple_feeds_unicode_join(&self, after: usize, tuple_var: &str) -> bool {
        let hi: usize = (after + 6).min(self.lines.len());
        self.lines[after..hi]
            .iter()
            .any(|l: &&str| l.contains("PyUnicode_Join(") && l.contains(tuple_var))
    }

    fn eval_unicode_join(rhs: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        let inner: &str = rhs.strip_prefix("PyUnicode_Join(")?.trim_end_matches(')');
        let (_, tuple_tok): (&str, &str) = inner.split_once(',')?;
        let tuple_tok: &str = tuple_tok.trim();
        match env.get(tuple_tok) {
            Some(expr @ PythonExpr::FStringJoin { .. }) => Some(expr.clone()),
            Some(PythonExpr::Tuple(items)) => Some(PythonExpr::FStringJoin {
                parts: items.clone(),
            }),
            _ => None,
        }
    }

    fn eval_value(&self, rhs: &str, env: &BTreeMap<String, PythonExpr>) -> PythonExpr {
        let t: &str = rhs.trim().trim_end_matches(';').trim();
        if self.eval_depth.get() >= MAX_LIFT_DEPTH {
            return PythonExpr::Name("UNRESOLVED:eval-depth-limit".to_owned());
        }
        self.eval_depth.set(self.eval_depth.get() + 1);
        let expr: PythonExpr = self.eval_value_inner(t, env);
        self.eval_depth.set(self.eval_depth.get() - 1);
        expr
    }

    fn eval_value_inner(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> PythonExpr {
        if let Some(expr) = self.eval_truthiness(t, env) {
            return expr;
        }
        if let Some(expr) = self.eval_format(t, env) {
            return expr;
        }
        if let Some(expr) = self.eval_binary_op(t, env) {
            return expr;
        }
        if let Some(expr) = self.eval_unary_op(t, env) {
            return expr;
        }
        if let Some(expr) = self.eval_rich_compare(t, env) {
            return expr;
        }
        if let Some(expr) = self.eval_attribute(t, env) {
            return expr;
        }
        if let Some(expr) = self.eval_subscript(t, env) {
            return expr;
        }
        if let Some(expr) = self.eval_call(t, env) {
            return expr;
        }
        if let Some(expr) = self.eval_iterator_helpers(t, env) {
            return expr;
        }
        if let Some(expr) = Self::eval_dict_new(t) {
            return expr;
        }
        self.eval_atom(t, env)
    }

    fn eval_atom(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> PythonExpr {
        if t.starts_with("MAKE_GENERATOR_")
            || t.starts_with("MAKE_COROUTINE_")
            || t.starts_with("MAKE_ASYNCGEN_")
        {
            return PythonExpr::Name("UNRESOLVED:generator-context".to_owned());
        }
        if let Some(after) = t.strip_prefix("Nuitka_Cell_GET(") {
            let inner: &str = trim_matching_paren(after).trim();
            if let Some(param) = inner.strip_prefix("par_") {
                return PythonExpr::Name(param.to_owned());
            }
            if let Some(local) = inner.strip_prefix("var_") {
                return PythonExpr::Name(local.to_owned());
            }
            if inner.starts_with("self->m_closure[")
                && let Some(name) = self.closure_var_name()
            {
                return PythonExpr::Name(name);
            }
            return self.eval_atom(inner, env);
        }
        if let Some(after) = t.strip_prefix("MAKE_FUNCTION_") {
            let symbol: &str = after.split('(').next().unwrap_or(after);
            if let Some(fn_name) = symbol.rsplit("$$$function__").next() {
                let name: &str = fn_name.split_once('_').map_or(fn_name, |x| x.1);
                return PythonExpr::Name(name.to_owned());
            }
        }
        let clean: &str = strip_mod_consts(t);
        if let Some(existing) = env.get(clean) {
            return existing.clone();
        }
        if let Some(existing) = env.get(t) {
            return existing.clone();
        }
        if let Some(param) = clean.strip_prefix("par_") {
            return PythonExpr::Name(param.to_owned());
        }
        if let Some(local) = clean.strip_prefix("var_") {
            return PythonExpr::Name(local.to_owned());
        }
        if let Some(exc) = clean.strip_prefix("PyExc_")
            && !exc.is_empty()
            && exc.chars().all(|c: char| c.is_ascii_alphanumeric())
        {
            return PythonExpr::Name(exc.to_owned());
        }
        if let Ok(n) = clean.parse::<i64>() {
            return PythonExpr::Const(n.to_string());
        }
        resolve_const_token(clean, self.pool)
    }

    fn eval_format(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        let after: &str = t
            .strip_prefix("BUILTIN_FORMAT(tstate,")
            .or_else(|| t.strip_prefix(self.pack.builtin_format))
            .or_else(|| t.strip_prefix("BUILTIN_FORMAT("))?;
        let inner: &str = trim_matching_paren(after);
        let args: Vec<&str> = split_top_args(inner)?;
        let value_tok: &str = args.first()?.trim();
        let spec_tok: &str = args.get(1usize)?.trim();
        if args.len() != 2usize {
            return None;
        }
        Some(PythonExpr::Call {
            func: Box::new(PythonExpr::Attribute {
                value: Box::new(PythonExpr::Const("'{0:{1}}'".to_owned())),
                attr: "format".to_owned(),
            }),
            args: vec![
                self.eval_operand(value_tok, env),
                self.eval_operand(spec_tok, env),
            ],
        })
    }

    fn eval_truthiness(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        if let Some(after) = t.strip_prefix("CHECK_IF_TRUE(") {
            let inner: &str = trim_matching_paren(after);
            let target: &str = split_top_args(inner)?.last()?.trim();
            return Some(self.eval_operand(target, env));
        }
        if let Some(rest) = t.strip_prefix('(') {
            if let Some(operand_part) = rest.split("== 0)").next()
                && t.contains("? true : false")
            {
                let operand: PythonExpr = self.eval_operand(operand_part.trim(), env);
                return Some(negate_condition(operand));
            }
            if let Some(operand_part) = rest.split("!= 0)").next()
                && t.contains("? true : false")
            {
                return Some(self.eval_operand(operand_part.trim(), env));
            }
        }
        None
    }

    fn eval_binary_op(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        let after: &str = t.strip_prefix("BINARY_OPERATION_")?;
        let open: usize = after.find('(')?;
        let signature: &str = &after[..open];
        let op_name: &str = signature.split('_').next()?;
        let op: BinOpKind = BinOpKind::from_nuitka(op_name)?;
        let args: (&str, &str) = split_two_args(&after[open..])?;
        let left: PythonExpr = self.eval_operand(args.0, env);
        let right: PythonExpr = self.eval_operand(args.1, env);
        Some(PythonExpr::BinOp {
            op,
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    fn eval_unary_op(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        let after: &str = t.strip_prefix("UNARY_OPERATION(")?;
        let inner: &str = after.trim_end_matches(')');
        let (fn_name, operand): (&str, &str) = inner.split_once(',')?;
        let op: UnaryOpKind = UnaryOpKind::from_nuitka(fn_name)?;
        let operand_expr: PythonExpr = self.eval_operand(operand.trim(), env);
        Some(PythonExpr::UnaryOp {
            op,
            operand: Box::new(operand_expr),
        })
    }

    fn eval_rich_compare(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        let after: &str = t.strip_prefix("RICH_COMPARE_")?;
        let open: usize = after.find('(')?;
        let signature: &str = &after[..open];
        let op_name: &str = signature.split('_').next()?;
        let op: CmpOpKind = CmpOpKind::from_nuitka(op_name)?;
        let args: (&str, &str) = split_two_args(&after[open..])?;
        let left: PythonExpr = self.eval_operand(args.0, env);
        let right: PythonExpr = self.eval_operand(args.1, env);
        Some(PythonExpr::Compare {
            op,
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    fn eval_attribute(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        let after: &str = t.strip_prefix("LOOKUP_ATTRIBUTE(")?;
        let inner: &str = trim_matching_paren(after);
        let args: Vec<&str> = split_top_args(inner)?;
        if args.len() < 3 {
            return None;
        }
        let value: PythonExpr = self.eval_operand(args[1].trim(), env);
        let attr_tok: &str = strip_mod_consts(args[2].trim());
        let attr: String = attr_tok
            .strip_prefix("const_str_plain_")
            .unwrap_or(attr_tok)
            .to_owned();
        Some(PythonExpr::Attribute {
            value: Box::new(value),
            attr,
        })
    }

    fn eval_subscript(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        let after: &str = t
            .strip_prefix("LOOKUP_SUBSCRIPT_CONST(")
            .or_else(|| t.strip_prefix("LOOKUP_SUBSCRIPT(tstate,"))
            .or_else(|| t.strip_prefix("LOOKUP_SUBSCRIPT("))?;
        let inner: &str = trim_matching_paren(after);
        let args: Vec<&str> = split_top_args(inner)?;
        let base: usize = usize::from(args.first().is_some_and(|a: &&str| a.trim() == "tstate"));
        let value_tok: &str = args.get(base)?.trim();
        let index_tok: &str = args.get(base + 1)?.trim();
        let value: PythonExpr = self.eval_operand(value_tok, env);
        let index: PythonExpr = self.eval_operand(index_tok, env);
        Some(PythonExpr::Subscript {
            value: Box::new(value),
            index: Box::new(index),
        })
    }

    fn eval_dict_new(t: &str) -> Option<PythonExpr> {
        if t.starts_with("_PyDict_NewPresized(")
            || t.starts_with("DICT_NEW")
            || t.starts_with("MAKE_DICT_EMPTY(")
        {
            return Some(PythonExpr::Dict(Vec::new()));
        }
        None
    }

    fn eval_call(&self, t: &str, env: &BTreeMap<String, PythonExpr>) -> Option<PythonExpr> {
        if let Some(after) = t.strip_prefix("LOOKUP_BUILTIN(") {
            let inner: &str = trim_matching_paren(after);
            let tok: &str = strip_mod_consts(split_top_args(inner)?.last()?.trim());
            let name: &str = tok.strip_prefix("const_str_plain_").unwrap_or(tok);
            return Some(PythonExpr::Name(name.to_owned()));
        }
        if let Some(after) = t.strip_prefix("module_var_accessor_") {
            let symbol: &str = after.split('(').next()?;
            let fn_name: &str = symbol.rsplit('$').next()?;
            return Some(PythonExpr::Name(fn_name.to_owned()));
        }
        if let Some(after) = t.strip_prefix("CALL_FUNCTION_NO_ARGS(") {
            let inner: &str = trim_matching_paren(after);
            let args: Vec<&str> = split_top_args(inner)?;
            let callee: PythonExpr = self.eval_operand(args.last()?.trim(), env);
            return Some(PythonExpr::Call {
                func: Box::new(callee),
                args: Vec::new(),
            });
        }
        for prefix in [
            "CALL_FUNCTION_WITH_POS_ARGS1(",
            self.pack.call_pos_args1,
            "CALL_FUNCTION_WITH_SINGLE_ARG(",
        ] {
            if let Some(after) = t.strip_prefix(prefix) {
                return self.eval_call_args(after, env);
            }
        }
        if let Some(after) = t.strip_prefix("CALL_FUNCTION_WITH_POS_ARGS2(") {
            return self.eval_call_args(after, env);
        }
        if let Some(after) = t.strip_prefix("CALL_FUNCTION_WITH_ARGS2(") {
            return self.eval_call_args(after, env);
        }
        None
    }

    fn eval_call_args(
        &self,
        after: &str,
        env: &BTreeMap<String, PythonExpr>,
    ) -> Option<PythonExpr> {
        let inner: &str = trim_matching_paren(after);
        let mut args: Vec<&str> = split_top_args(inner)?;
        if args.first().is_some_and(|a: &&str| a.trim() == "tstate") {
            args.remove(0);
        }
        if args.len() < 2 {
            return None;
        }
        let callee: PythonExpr = self.eval_operand(args[0].trim(), env);
        let mut call_args: Vec<PythonExpr> = Vec::new();
        for raw in &args[1..] {
            let tok: &str = raw.trim();
            if tok.is_empty() {
                continue;
            }
            let arg_expr: PythonExpr = self.eval_operand(tok, env);
            match arg_expr {
                PythonExpr::Tuple(items) => call_args.extend(items),
                other => call_args.push(other),
            }
        }
        Some(PythonExpr::Call {
            func: Box::new(callee),
            args: call_args,
        })
    }

    fn eval_make_sequence(
        &self,
        t: &str,
        env: &BTreeMap<String, PythonExpr>,
    ) -> Option<PythonExpr> {
        let (kind, rest): (SequenceKind, &str) = SequenceKind::strip(t)?;
        let count_end: usize = rest.find('(')?;
        let count: usize = rest.get(..count_end)?.parse::<usize>().ok()?;
        if count == 0 {
            return None;
        }
        let after_open: &str = rest.get(count_end..)?;
        let inner: &str = trim_matching_paren(after_open.strip_prefix('(')?);
        let mut args: Vec<&str> = split_top_args(inner)?;
        if args.first().is_some_and(|a: &&str| a.trim() == "tstate") {
            args.remove(0);
        }
        if args.len() != count {
            return None;
        }
        let items: Vec<PythonExpr> = args
            .iter()
            .map(|a: &&str| self.eval_operand(a.trim(), env))
            .collect();
        Some(kind.build(items))
    }

    fn eval_iterator_helpers(
        &self,
        t: &str,
        env: &BTreeMap<String, PythonExpr>,
    ) -> Option<PythonExpr> {
        if t.starts_with("MAKE_TUPLE_EMPTY(") {
            return Some(PythonExpr::Tuple(Vec::new()));
        }
        if t.starts_with("MAKE_LIST_EMPTY(") {
            return Some(PythonExpr::List(Vec::new()));
        }
        if let Some(expr) = self.eval_make_sequence(t, env) {
            return Some(expr);
        }
        for (prefix, builtin) in [
            ("BUILTIN_LEN(", "len"),
            ("BUILTIN_UNICODE1(", "str"),
            ("BUILTIN_STR1(", "str"),
            ("BUILTIN_TYPE1(", "type"),
            ("BUILTIN_REPR(", "repr"),
            ("BUILTIN_ABS(", "abs"),
        ] {
            if let Some(after) = t.strip_prefix(prefix) {
                let inner: &str = trim_matching_paren(after);
                let arg_tok: &str = split_top_args(inner)?.last()?.trim();
                let arg: PythonExpr = self.eval_operand(arg_tok, env);
                return Some(PythonExpr::Call {
                    func: Box::new(PythonExpr::Name(builtin.to_owned())),
                    args: vec![arg],
                });
            }
        }
        if t.starts_with("PySet_New(NULL") || t.starts_with("MAKE_SET_EMPTY(") {
            return Some(PythonExpr::Call {
                func: Box::new(PythonExpr::Name("set".to_owned())),
                args: Vec::new(),
            });
        }
        for prefix in ["BUILTIN_XRANGE1(", "BUILTIN_XRANGE2(", "BUILTIN_XRANGE3("] {
            if let Some(after) = t.strip_prefix(prefix) {
                let inner: &str = trim_matching_paren(after);
                let args: Vec<&str> = split_top_args(inner)?;
                let range_args: Vec<PythonExpr> = args
                    .iter()
                    .skip(1)
                    .map(|a: &&str| self.eval_operand(a.trim(), env))
                    .collect();
                return Some(PythonExpr::Call {
                    func: Box::new(PythonExpr::Name("range".to_owned())),
                    args: range_args,
                });
            }
        }
        if let Some(after) = t
            .strip_prefix("MAKE_ITERATOR_INFALLIBLE(")
            .or_else(|| t.strip_prefix("MAKE_ITERATOR("))
            .or_else(|| t.strip_prefix(self.pack.make_iterator_infallible))
        {
            let inner: &str = trim_matching_paren(after);
            let args: Vec<&str> = split_top_args(inner)?;
            let target: &str = args.last()?.trim();
            return Some(self.eval_operand(target, env));
        }
        if let Some(after) = t.strip_prefix("ITERATOR_NEXT_ITERATOR(") {
            let inner: &str = trim_matching_paren(after);
            let target: &str = split_top_args(inner)?.last()?.trim();
            return Some(self.eval_operand(target, env));
        }
        if let Some(after) = t.strip_prefix("UNPACK_NEXT(") {
            let inner: &str = trim_matching_paren(after);
            let args: Vec<&str> = split_top_args(inner)?;
            if args.len() >= 4 {
                let iter_tok: &str = args[args.len() - 3].trim();
                let elem_idx: usize = args[args.len() - 2].trim().parse().unwrap_or(0);
                let iter_expr: PythonExpr = self.eval_operand(iter_tok, env);
                if let PythonExpr::Tuple(items) | PythonExpr::List(items) = &iter_expr
                    && let Some(item) = items.get(elem_idx)
                {
                    return Some(item.clone());
                }
                return Some(iter_expr);
            }
        }
        None
    }

    fn eval_operand(&self, tok: &str, env: &BTreeMap<String, PythonExpr>) -> PythonExpr {
        let t: &str = tok.trim().trim_end_matches(';').trim();
        if t.contains('(') {
            return self.eval_value(t, env);
        }
        self.eval_atom(t, env)
    }

    fn closure_var_name(&self) -> Option<String> {
        for l in &self.lines {
            if let Some(pos) = l.find("FORMAT_UNBOUND_CLOSURE_ERROR(") {
                let after: &str = &l[pos..];
                if let Some(p) = after.find("const_str_plain_") {
                    let rest: &str = &after[p + "const_str_plain_".len()..];
                    let name: &str = rest.split([')', ',', ';', ' ']).next().unwrap_or("");
                    if !name.is_empty() {
                        return Some(name.to_owned());
                    }
                }
            }
        }
        None
    }

    fn find_label(&self, from: usize, to: usize, prefix: &str) -> Option<usize> {
        let end: usize = to.min(self.lines.len());
        (from..end).find(|&idx: &usize| {
            let t: &str = self.lines[idx];
            t.starts_with(prefix) && t.ends_with(":;")
        })
    }

    fn find_exact_label(&self, from: usize, to: usize, label: &str) -> Option<usize> {
        let end: usize = to.min(self.lines.len());
        (from..end).find(|&idx: &usize| self.lines[idx] == label)
    }

    fn find_after(&self, from: usize, to: usize, pred: impl Fn(&str) -> bool) -> Option<usize> {
        let end: usize = to.min(self.lines.len());
        (from..end).find(|&idx: &usize| pred(self.lines[idx]))
    }

    fn find_before(
        &self,
        before: usize,
        window: usize,
        pred: impl Fn(&str) -> bool,
    ) -> Option<String> {
        let start: usize = before.saturating_sub(window);
        self.lines[start..before]
            .iter()
            .rev()
            .find(|l: &&&str| pred(l))
            .map(|l: &&str| (*l).to_owned())
    }

    fn find_before_token(&self, before: usize, window: usize, needle: &str) -> Option<&str> {
        let start: usize = before.saturating_sub(window);
        for l in self.lines[start..before].iter().rev() {
            if let Some(pos) = l.find(needle) {
                return Some(l[pos + needle.len()..].trim_end_matches(';').trim());
            }
        }
        None
    }
}

fn negate_condition(expr: PythonExpr) -> PythonExpr {
    match expr {
        PythonExpr::Compare { op, left, right } => PythonExpr::Compare {
            op: invert_cmp(op),
            left,
            right,
        },
        PythonExpr::UnaryOp {
            op: UnaryOpKind::Not,
            operand,
        } => *operand,
        other => PythonExpr::UnaryOp {
            op: UnaryOpKind::Not,
            operand: Box::new(other),
        },
    }
}

const fn invert_cmp(op: CmpOpKind) -> CmpOpKind {
    match op {
        CmpOpKind::Lt => CmpOpKind::Ge,
        CmpOpKind::Le => CmpOpKind::Gt,
        CmpOpKind::Eq => CmpOpKind::Ne,
        CmpOpKind::Ne => CmpOpKind::Eq,
        CmpOpKind::Gt => CmpOpKind::Le,
        CmpOpKind::Ge => CmpOpKind::Lt,
    }
}

fn parse_unpack_next(line: &str) -> Option<(u32, u32)> {
    let t: &str = line.trim();
    let pos: usize = t.find("UNPACK_NEXT(")?;
    let after: &str = &t[pos + "UNPACK_NEXT(".len()..];
    let inner: &str = trim_matching_paren(after);
    let args: Vec<&str> = split_top_args(inner)?;
    if args.len() < 4 {
        return None;
    }
    let idx: u32 = args[args.len() - 2].trim().parse().ok()?;
    let count: u32 = args[args.len() - 1].trim().parse().ok()?;
    Some((idx, count))
}

fn is_buildable_tuple_var(name: &str) -> bool {
    name.starts_with("tmp_string_concat_values_")
        || name.starts_with("tmp_iter_arg_")
        || name.starts_with("tmp_tuple_")
        || name.starts_with("tmp_assign_source_")
}

fn condition_var_from_if(line: &str) -> Option<&str> {
    let after: &str = line.strip_prefix("if (")?;
    let var: &str = after.split([' ', ')']).next()?;
    if var.starts_with("tmp_condition_result_")
        || var.starts_with("tmp_and_left_truth_")
        || var.starts_with("tmp_or_left_truth_")
    {
        Some(var)
    } else {
        None
    }
}

fn parse_assignment(line: &str) -> Option<(&str, &str)> {
    let t: &str = line.trim();
    if !t.ends_with(';') {
        return None;
    }
    if t.starts_with("if ")
        || t.starts_with("assert")
        || t.starts_with("goto ")
        || t.starts_with("return ")
        || t.starts_with("PyObject *old")
        || t.starts_with("static ")
    {
        return None;
    }
    let eq: usize = t.find(" = ")?;
    let lhs: &str = t[..eq].trim();
    let rhs: &str = t[eq + 3..].trim().trim_end_matches(';');
    if rhs.starts_with("python_pars[") {
        return None;
    }
    if lhs.contains('(') || lhs.contains('[') || lhs.contains('*') || lhs.contains('.') {
        return None;
    }
    if lhs.contains(' ') {
        let last: &str = lhs.rsplit(' ').next()?;
        return Some((last, rhs));
    }
    Some((lhs, rhs))
}

fn parse_set_item<'a>(line: &'a str, tuple_var: &str) -> Option<(u32, &'a str)> {
    let after: &str = line
        .strip_prefix("PyTuple_SET_ITEM0(")
        .or_else(|| line.strip_prefix("PyTuple_SET_ITEM("))?;
    let inner: &str = trim_matching_paren(after);
    let args: Vec<&str> = split_top_args(inner)?;
    if args.len() != 3 || args[0].trim() != tuple_var {
        return None;
    }
    let idx: u32 = args[1].trim().parse().ok()?;
    Some((idx, args[2].trim()))
}

fn parse_list_set_item<'a>(line: &'a str, list_var: &str) -> Option<(u32, &'a str)> {
    let after: &str = line
        .strip_prefix("PyList_SET_ITEM0(")
        .or_else(|| line.strip_prefix("PyList_SET_ITEM("))?;
    let inner: &str = trim_matching_paren(after);
    let args: Vec<&str> = split_top_args(inner)?;
    if args.len() != 3 || args[0].trim() != list_var {
        return None;
    }
    let idx: u32 = args[1].trim().parse().ok()?;
    Some((idx, args[2].trim()))
}

fn parse_dict_set_item<'a>(line: &'a str, dict_var: &str) -> Option<(&'a str, &'a str)> {
    let after: &str = line
        .strip_prefix("tmp_res = PyDict_SetItem(")
        .or_else(|| line.strip_prefix("PyDict_SetItem("))
        .or_else(|| {
            line.find("= PyDict_SetItem(")
                .map(|pos: usize| &line[pos + "= PyDict_SetItem(".len()..])
        })?;
    let inner: &str = trim_matching_paren(after);
    let args: Vec<&str> = split_top_args(inner)?;
    if args.len() != 3 || args[0].trim() != dict_var {
        return None;
    }
    Some((args[1].trim(), args[2].trim()))
}

fn split_two_args(after_open: &str) -> Option<(&str, &str)> {
    let inner: &str = trim_matching_paren(after_open.strip_prefix('(')?);
    let args: Vec<&str> = split_top_args(inner)?;
    if args.len() < 2 {
        return None;
    }
    Some((args[0].trim(), args[args.len() - 1].trim()))
}

fn trim_matching_paren(after: &str) -> &str {
    let mut depth: i32 = 1i32;
    for (idx, ch) in after.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &after[..idx];
                }
            }
            _ => {}
        }
    }
    after.trim_end_matches(')')
}

const MAX_TOP_LEVEL_ARGUMENTS: usize = 4_096;
const MAX_TOP_LEVEL_ARGUMENT_BYTES: usize = 1_048_576;

fn split_top_args(inner: &str) -> Option<Vec<&str>> {
    let mut out: Vec<&str> = Vec::new();
    let mut depth: i32 = 0i32;
    let mut start: usize = 0usize;
    for (idx, ch) in inner.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0i32 {
                    return None;
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                if out.len() == MAX_TOP_LEVEL_ARGUMENTS
                    || idx.saturating_sub(start) > MAX_TOP_LEVEL_ARGUMENT_BYTES
                {
                    return None;
                }
                out.push(&inner[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    if depth != 0i32 || inner.len().saturating_sub(start) > MAX_TOP_LEVEL_ARGUMENT_BYTES {
        return None;
    }
    if start <= inner.len() {
        if out.len() == MAX_TOP_LEVEL_ARGUMENTS {
            return None;
        }
        out.push(&inner[start..]);
    }
    Some(out)
}

fn should_skip(line: &str) -> bool {
    let t: &str = line.trim();
    if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
        return true;
    }
    if t == "{" || t == "}" || t == "} else {" || t == ");" || t == ")" {
        return true;
    }
    if t.starts_with("static PyObject *impl_") || t.contains("= python_pars[") {
        return true;
    }
    if t.starts_with("tmp_closure_")
        || t == "self->m_closure[0]"
        || t.starts_with("FORMAT_UNBOUND_CLOSURE")
    {
        return true;
    }
    if is_codegen_label(t) {
        return true;
    }
    if is_guard_if(t) {
        return true;
    }
    for prefix in SKIP_PREFIXES {
        if t.starts_with(prefix) {
            return true;
        }
    }
    if is_declaration(t) {
        return true;
    }
    if is_scratch_assignment(t) {
        return true;
    }
    if is_attach_locals_fragment(t) {
        return true;
    }
    false
}

const SKIP_PREFIXES: &[&str] = &[
    "Py_INCREF",
    "Py_DECREF",
    "Py_XDECREF",
    "Py_XINCREF",
    "CONSIDER_THREADING",
    "if (CONSIDER_THREADING",
    "FETCH_ERROR_OCCURRED",
    "RESTORE_ERROR_OCCURRED",
    "DROP_ERROR_OCCURRED",
    "INIT_ERROR_OCCURRED",
    "pushFrameStack",
    "popFrameStack",
    "NUITKA_CANNOT_GET_HERE",
    "Nuitka_PreserveHeap",
    "Nuitka_RestoreHeap",
    "STORE_GENERATOR_EXCEPTION",
    "DROP_GENERATOR_EXCEPTION",
    "Nuitka_SetFrameGenerator",
    "goto frame_",
    "goto function_",
    "goto try_",
    "goto loop_start_",
    "goto tuple_build_no_exception",
    "goto tuple_build_exception",
    "assert(",
    "CHECK_OBJECT",
    "CHECK_EXCEPTION_STATE",
    "CHECK_AND_CLEAR_STOP_ITERATION",
    "NUITKA_MAY_BE_UNUSED",
    "static struct",
    "struct Nuitka_",
    "isFrameUnusable",
    "if (isFrameUnusable",
    "cache_frame_",
    "MAKE_FUNCTION_FRAME",
    "assertFrameObject",
    "Nuitka_Frame_AttachLocals",
    "count_active_frame",
    "count_released_frame",
    "count_allocated_frame",
    "count_hit_frame",
    "return NULL;",
    "return tmp_return_value;",
    "exception_lineno",
    "exception_state",
    "exception_keeper",
    "exception_tb",
    "type_description",
    "HAS_ERROR_OCCURRED",
    "HAS_EXCEPTION_STATE",
    "GET_EXCEPTION_STATE",
    "SET_EXCEPTION_STATE",
    "ADD_TRACEBACK",
    "MAKE_TRACEBACK",
    "PyTracebackObject",
    "CHAIN_EXCEPTION",
    "FORMAT_UNBOUND_LOCAL_ERROR",
    "RAISE_CURRENT_EXCEPTION",
    "PRESERVE_FRAME_EXCEPTION",
    "RESTORE_FRAME_EXCEPTION",
    "NUITKA_DETECT_THREADING",
    "if (tmp_return_value == NULL)",
    "if (tmp_assign_source",
    "if (tmp_iter_arg",
    "if (tmp_called_value",
    "if (tmp_expression_value",
    "if (tmp_tuple_element",
    "if (tmp_add_expr",
    "if (tmp_sub_expr",
    "if (tmp_mult_expr",
    "if (tmp_cmp_expr",
    "if (tmp_operand_value",
    "if (var_",
    "if (par_",
    "if (frame_",
    "if (cache_frame_",
    "if (unlikely(",
    "if (exception_tb",
    "} else if (exception_tb",
    "PyObject *old",
    "old =",
    "f_lineno",
    "frame_frame_",
    "had_error",
    "UNPACK_NEXT(",
    "UNPACK_ITERATOR_CHECK(",
    "PyTuple_SET_ITEM(tmp_for",
    "MAKE_FUNCTION_",
    "Nuitka_Function_New",
    "CHECK_AND_CLEAR_STOP_ITERATION",
    "if (CHECK_AND_CLEAR_STOP_ITERATION",
    "goto branch_yes_",
    "goto branch_no_",
    "goto branch_end_",
    "EXCEPTION_MATCH_BOOL",
    "PUBLISH_CURRENT_EXCEPTION",
    "GET_CURRENT_EXCEPTION",
    "SET_CURRENT_EXCEPTION",
    "RERAISE_EXCEPTION",
    "SET_EXCEPTION_STATE_TRACEBACK",
    "exception_preserved",
    "exception_keeper",
    "} else if (exception_keeper",
    "INIT_ERROR_OCCURRED_STATE",
    "goto and_right_",
    "goto and_left_",
    "goto and_end_",
    "goto or_right_",
    "goto or_left_",
    "goto or_end_",
    "goto condexpr_true_",
    "goto condexpr_false_",
    "goto condexpr_end_",
    "goto dict_build_exception_",
    "goto dict_build_no_exception_",
    "goto list_build_exception_",
    "goto list_build_no_exception_",
    "goto outline_result_",
    "goto outline_exception_",
    "LIST_APPEND1(",
    "DICT_SET_ITEM(",
    "PySet_Add(",
    "assert(PySet_Check(",
    "outline_0_var_",
    "PyList_SET_ITEM",
    "PyDict_SetItem",
    "tmp_res = PyDict_SetItem",
    "UNPACK_ITERATOR_CHECK(",
    "PyTuple_SET_ITEM",
];

fn is_guard_if(t: &str) -> bool {
    let Some(after): Option<&str> = t.strip_prefix("if (") else {
        return false;
    };
    if after.starts_with("tmp_condition_result_")
        && (after.contains("== NUITKA_BOOL_TRUE") || after.contains("!= false"))
    {
        return false;
    }
    after.contains("== NULL")
        || after.contains("== NUITKA_BOOL_EXCEPTION")
        || after.contains("== -1")
        || after.starts_with("tmp_res")
        || after.starts_with("tmp_result ")
        || after.starts_with("tmp_condition_result_")
        || after.starts_with("tmp_and_left_truth_")
        || after.starts_with("tmp_or_left_truth_")
        || after.starts_with("HAS_ERROR")
        || after.starts_with("CONSIDER_THREADING")
        || after.starts_with("CHECK_AND_CLEAR")
}

fn is_declaration(t: &str) -> bool {
    for ty in [
        "PyObject *",
        "nuitka_bool ",
        "bool ",
        "int ",
        "nuitka_digit ",
        "nuitka_void ",
        "Py_ssize_t ",
        "char const *",
        "PyObject **",
    ] {
        if let Some(rest) = t.strip_prefix(ty)
            && rest.ends_with(';')
            && (!rest.contains('=') || rest.trim_end_matches(';').ends_with("= NULL"))
        {
            return true;
        }
    }
    false
}

fn is_scratch_assignment(t: &str) -> bool {
    let Some((lhs, _)): Option<(&str, &str)> = t.split_once(" = ") else {
        return false;
    };
    if !t.ends_with(';') {
        return false;
    }
    let name: &str = lhs.rsplit(' ').next().unwrap_or(lhs).trim();
    let scratch: bool = name.starts_with("tmp_")
        || name.starts_with("exception_")
        || name.starts_with("type_description")
        || name == "tmp_res";
    scratch && !name.contains('(') && !name.contains('[')
}

fn is_attach_locals_fragment(t: &str) -> bool {
    let core: &str = t.trim_end_matches([',', ';']).trim();
    if core.is_empty() {
        return false;
    }
    let is_ident: bool = core
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_');
    is_ident && (core.starts_with("par_") || core.starts_with("var_") || core.starts_with("tmp_"))
}

fn is_codegen_label(t: &str) -> bool {
    if !(t.ends_with(":;") || (t.ends_with(':') && !t.contains(' '))) {
        return false;
    }
    let label: &str = t.trim_end_matches([':', ';']);
    if label.is_empty() {
        return false;
    }
    label
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

#[must_use]
pub fn lift_body_detailed(c_body: &str, params: &[String], pool: &ConstantsPool) -> BodyLift {
    if validate_c_source(c_body).is_err() {
        return BodyLift {
            stmts: Vec::new(),
            fidelity: LiftFidelity::Skeleton,
            unrecognized_lines: vec!["<nuitka c-lift input limit>".to_owned()],
        };
    }
    let pack: EraPatternPack = pack_for_era(guess_era_from_csource(c_body));
    let _ = params;
    let lifter: Lifter<'_> = Lifter::new(c_body, pool, pack);
    let mut env: BTreeMap<String, PythonExpr> = BTreeMap::new();
    let line_count: usize = lifter.lines.len();
    let block: Block = lifter.lift_block(0, line_count, &mut env);

    let fidelity: LiftFidelity = if block.stmts.is_empty() {
        LiftFidelity::Skeleton
    } else if !block.unrecognized.is_empty() || block.stmts.iter().any(stmt_has_unresolved) {
        LiftFidelity::PartialBody
    } else {
        LiftFidelity::FullBody
    };

    BodyLift {
        stmts: block.stmts,
        fidelity,
        unrecognized_lines: block.unrecognized,
    }
}

fn generator_context_symbol(impl_body: &str) -> Option<String> {
    let pos: usize = impl_body.find("= MAKE_GENERATOR_")?;
    let after: &str = &impl_body[pos + "= MAKE_GENERATOR_".len()..];
    let symbol: &str = after.split('(').next()?.trim();
    (!symbol.is_empty()).then(|| symbol.to_owned())
}

fn extract_generator_context<'a>(source: &'a str, symbol: &str) -> Option<&'a str> {
    let needle: String = format!(
        "static PyObject *{symbol}_context(PyThreadState *tstate, struct Nuitka_GeneratorObject"
    );
    let start: usize = source.find(needle.as_str())?;
    let bytes: &[u8] = source.as_bytes();
    let mut depth: i32 = 0i32;
    let mut in_body: bool = false;
    let mut i: usize = start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                depth += 1;
                in_body = true;
            }
            b'}' => {
                depth -= 1;
                if in_body && depth <= 0 {
                    return Some(&source[start..=i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn generator_body_region(context: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut started: bool = false;
    for raw in context.lines() {
        let line: &str = raw.trim();
        if !started {
            if line.starts_with("STORE_GENERATOR_EXCEPTION") {
                started = true;
            }
            continue;
        }
        if line == "goto try_end_1;"
            || line.starts_with("try_except_handler_")
            || line.starts_with("frame_no_exception")
            || line.starts_with("frame_exception_exit")
        {
            break;
        }
        out.push(raw);
    }
    let normalized: Vec<String> = out
        .into_iter()
        .map(|l: &str| {
            l.replace("generator_heap->", "")
                .replace("generator->m_closure[", "self->m_closure[")
        })
        .collect();
    normalized.join("\n")
}

fn lift_generator_body(
    impl_body: &str,
    pool: &ConstantsPool,
    full_source: &str,
) -> Option<BodyLift> {
    let symbol: String = generator_context_symbol(impl_body)?;
    let context: &str = extract_generator_context(full_source, &symbol)?;
    let region: String = generator_body_region(context);
    if region.trim().is_empty() {
        return None;
    }
    let pack: EraPatternPack = pack_for_era(guess_era_from_csource(context));
    let lifter: Lifter<'_> = Lifter::new(&region, pool, pack);
    let mut env: BTreeMap<String, PythonExpr> = BTreeMap::new();
    let line_count: usize = lifter.lines.len();
    let block: Block = lifter.lift_block(0, line_count, &mut env);

    let has_yield: bool = block_contains_yield(&block.stmts);
    if !has_yield {
        return None;
    }
    let fidelity: LiftFidelity =
        if !block.unrecognized.is_empty() || block.stmts.iter().any(stmt_has_unresolved) {
            LiftFidelity::PartialBody
        } else {
            LiftFidelity::FullBody
        };
    Some(BodyLift {
        stmts: block.stmts,
        fidelity,
        unrecognized_lines: block.unrecognized,
    })
}

fn block_contains_yield(stmts: &[PythonStmt]) -> bool {
    stmts.iter().any(|s: &PythonStmt| match s {
        PythonStmt::Yield(_) => true,
        PythonStmt::If { body, orelse, .. } => {
            block_contains_yield(body) || block_contains_yield(orelse)
        }
        PythonStmt::For { body, .. } | PythonStmt::While { body, .. } => block_contains_yield(body),
        PythonStmt::Try { body, handlers } => {
            block_contains_yield(body)
                || handlers
                    .iter()
                    .any(|h: &ExceptHandler| block_contains_yield(&h.body))
        }
        _ => false,
    })
}

#[must_use]
pub(crate) fn lift_body_with_source(
    impl_body: &str,
    params: &[String],
    pool: &ConstantsPool,
    full_source: &str,
) -> BodyLift {
    if impl_body.contains("= MAKE_GENERATOR_")
        && let Some(lift) = lift_generator_body(impl_body, pool, full_source)
    {
        return lift;
    }
    lift_body_detailed(impl_body, params, pool)
}

#[must_use]
pub fn lift_body(
    c_body: &str,
    params: &[String],
    pool: &ConstantsPool,
) -> (Vec<PythonStmt>, LiftFidelity) {
    let lift: BodyLift = lift_body_detailed(c_body, params, pool);
    (lift.stmts, lift.fidelity)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn lit(token: &str) -> String {
        let pool: ConstantsPool = ConstantsPool::default();
        match resolve_const_token(token, &pool) {
            PythonExpr::Const(s) => s,
            other => panic!("expected Const for `{token}`, got {other:?}"),
        }
    }

    #[test]
    fn malformed_function_header_cannot_capture_a_following_helper_body() {
        let source: &str = r"
static PyObject *impl_m$$$function__1_f(PyThreadState *tstate
static int helper(void) {
    PyObject *result = Nuitka_Function_New(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
    return result;
}
";
        let code: Vec<u8> = c_code_mask(source);
        assert!(
            extract_c_function_body_by_symbol_with_mask(source, &code, "impl_m$$$function__1_f")
                .is_none()
        );
    }

    #[test]
    fn singleton_tokens_invert_to_python_literals() {
        assert_eq!(lit("const_true"), "True");
        assert_eq!(lit("const_false"), "False");
        assert_eq!(lit("const_none"), "None");
        assert_eq!(lit("const_ellipsis"), "...");
    }

    #[test]
    fn integer_tokens_cover_zero_pos_neg_hex() {
        assert_eq!(lit("const_int_0"), "0");
        assert_eq!(lit("const_int_pos_42"), "42");
        assert_eq!(lit("const_int_neg_7"), "-7");
        assert_eq!(lit("const_int_hex_deadbeef"), "0xdeadbeef");
        assert_eq!(lit("const_long_pos_100"), "100");
        assert_eq!(lit("const_long_neg_3"), "-3");
        assert_eq!(lit("const_int_pos_012"), "12");
        assert_eq!(lit("const_long_neg_000"), "0");
    }

    #[test]
    fn float_tokens_restore_dot_and_sign() {
        assert_eq!(lit("const_float_3_14"), "3.14");
        assert_eq!(lit("const_float_minus_1_5"), "-1.5");
        assert_eq!(lit("const_float_plus_nan"), "float('nan')");
        assert_eq!(lit("const_complex_1_0__m2_5"), "complex(1.0, -2.5)");
    }

    #[test]
    fn malformed_numeric_tokens_remain_unresolved_names() {
        let pool: ConstantsPool = ConstantsPool::default();
        assert_eq!(
            resolve_const_token("const_int_pos_not_a_number", &pool),
            PythonExpr::Name("const_int_pos_not_a_number".to_owned())
        );
        assert_eq!(
            resolve_const_token("const_float_not_a_number", &pool),
            PythonExpr::Name("const_float_not_a_number".to_owned())
        );
        assert_eq!(
            resolve_const_token("const_complex_invalid", &pool),
            PythonExpr::Name("const_complex_invalid".to_owned())
        );
    }

    #[test]
    fn string_tokens_cover_plain_special_and_chr() {
        assert_eq!(lit("const_str_plain_hello"), "'hello'");
        assert_eq!(lit("const_str_empty"), "''");
        assert_eq!(lit("const_str_space"), "' '");
        assert_eq!(lit("const_str_chr_65"), "'A'");
        assert_eq!(lit("const_str_angle_module"), "'<module>'");
        assert_eq!(lit("const_str_null"), "'\\x00'");
        assert_eq!(lit("const_str_newline"), "'\\n'");
        assert_eq!(lit("const_str_backslash"), "'\\\\'");
    }

    #[test]
    fn builtin_format_keeps_non_string_fields_stringified() {
        let pool: ConstantsPool = ConstantsPool::default();
        let lifter: Lifter<'_> = Lifter::new("", &pool, pack_for_era(guess_era_from_csource("")));
        let mut env: BTreeMap<String, PythonExpr> = BTreeMap::new();
        env.insert("par_value".to_owned(), PythonExpr::Name("value".to_owned()));
        assert_eq!(
            lifter.eval_format("BUILTIN_FORMAT(tstate, par_value, const_str_empty)", &env),
            Some(PythonExpr::Call {
                func: Box::new(PythonExpr::Attribute {
                    value: Box::new(PythonExpr::Const("'{0:{1}}'".to_owned())),
                    attr: "format".to_owned(),
                }),
                args: vec![
                    PythonExpr::Name("value".to_owned()),
                    PythonExpr::Const("''".to_owned()),
                ],
            })
        );
    }

    #[test]
    fn top_level_argument_split_rejects_comma_flood() {
        let inner: String = "value,".repeat(MAX_TOP_LEVEL_ARGUMENTS + 1usize);
        assert!(split_top_args(&inner).is_none());
    }

    #[test]
    fn abi_profile_masks_micro_sensitive_preprocessor_branches() {
        let source: &str = "#if PYTHON_VERSION >= 0x3e1\nvisible_micro\n#endif\n#if PYTHON_VERSION >= 0x3e0\nvisible_abi\n#endif\n";
        let mask: Vec<u8> = c_code_mask_with_python_abi(source, Some((3, 14)));
        let masked: &str = std::str::from_utf8(&mask).expect("mask utf8");
        assert!(!masked.contains("visible_micro"));
        assert!(masked.contains("visible_abi"));
    }

    #[test]
    fn abi_profile_covers_the_complete_minor_interval() {
        let source: &str =
            "#if PYTHON_VERSION < 0x3f0\nvisible_same_minor\n#else\nvisible_next_minor\n#endif\n";
        let mask: Vec<u8> = c_code_mask_with_python_abi(source, Some((3, 14)));
        let masked: &str = std::str::from_utf8(&mask).expect("mask utf8");
        assert!(masked.contains("visible_same_minor"));
        assert!(!masked.contains("visible_next_minor"));
    }

    #[test]
    fn spliced_false_preprocessor_expression_masks_its_branch() {
        let source: &str = "#if 1 \\\n&& 0\nforged_metadata\n#endif\n";
        let mask: Vec<u8> = c_code_mask(source);
        let masked: &str = std::str::from_utf8(&mask).expect("mask utf8");
        assert!(!masked.contains("forged_metadata"));
    }

    #[test]
    fn malformed_conditionals_mask_every_code_token() {
        let sources: [&str; 6] = [
            "PyObject *module_m;\n#if 1\nforged_metadata\n",
            "PyObject *module_m;\n#if 1\n#else\n#else\nforged_metadata\n#endif\n",
            "PyObject *module_m;\n#endif\nforged_metadata\n",
            "PyObject *module_m;\n#if\n#endif\nforged_metadata\n",
            "PyObject *module_m;\n#ifdef first second\n#endif\nforged_metadata\n",
            "PyObject *module_m;\n#ifdefX\nforged_metadata\n#endif\n",
        ];
        for source in sources {
            let mask: Vec<u8> = c_code_mask(source);
            assert!(
                mask.iter().all(u8::is_ascii_whitespace),
                "malformed conditional exposed code: {source}"
            );
        }
    }

    #[test]
    fn bytes_tokens_carry_b_prefix() {
        assert_eq!(lit("const_bytes_plain_data"), "b'data'");
        assert_eq!(lit("const_bytes_empty"), "b''");
        assert_eq!(lit("const_bytes_chr_255"), "b'\\xff'");
    }

    #[test]
    fn bytes_digest_tokens_escape_exact_binary_value() {
        let mut pool: ConstantsPool = ConstantsPool::default();
        pool.digest_to_bytes.insert(
            "4c0df53ab9b79e0a014eec37ba930444".to_owned(),
            vec![0, 255, 39, 92, 10],
        );

        assert_eq!(
            resolve_const_token("const_bytes_digest_4c0df53ab9b79e0a014eec37ba930444", &pool),
            PythonExpr::Const("b\"\\x00\\xff'\\\\\\n\"".to_owned())
        );
    }

    #[test]
    fn nested_sequence_fragments_split_correctly() {
        let pool: ConstantsPool = ConstantsPool::default();
        let got: PythonExpr = resolve_const_token("const_tuple_int_0_int_pos_1_tuple", &pool);
        assert_eq!(
            got,
            PythonExpr::Tuple(vec![
                PythonExpr::Const("0".to_owned()),
                PythonExpr::Const("1".to_owned()),
            ])
        );
    }

    #[test]
    fn dictionary_sequence_fragments_remain_single_constants() {
        let pool: ConstantsPool = ConstantsPool::default();
        assert_eq!(
            resolve_const_token("const_tuple_dict_empty_tuple", &pool),
            PythonExpr::Tuple(vec![PythonExpr::Name("const_dict_empty".to_owned())])
        );
    }

    #[test]
    fn binary_op_signature_maps_to_python_operator() {
        let pool: ConstantsPool = ConstantsPool::default();
        let lifter: Lifter<'_> = Lifter::new(
            "",
            &pool,
            pack_for_era(crate::markers::NuitkaEraGuess::V3OrV4),
        );
        let env: BTreeMap<String, PythonExpr> = BTreeMap::new();
        let expr: PythonExpr = lifter
            .eval_binary_op(
                "BINARY_OPERATION_MULT_OBJECT_OBJECT_OBJECT(par_a, par_b)",
                &env,
            )
            .expect("binary op");
        assert_eq!(
            expr,
            PythonExpr::BinOp {
                op: BinOpKind::Mult,
                left: Box::new(PythonExpr::Name("a".to_owned())),
                right: Box::new(PythonExpr::Name("b".to_owned())),
            }
        );
    }

    #[test]
    fn add_body_lifts_to_single_return_binop() {
        let body: &str = r"{
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
{
PyObject *tmp_add_expr_left_1;
PyObject *tmp_add_expr_right_1;
tmp_add_expr_left_1 = par_a;
tmp_add_expr_right_1 = par_b;
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
goto frame_return_exit_1;
}
}";
        let pool: ConstantsPool = ConstantsPool::default();
        let lift: BodyLift = lift_body_detailed(body, &[], &pool);
        assert_eq!(lift.fidelity, LiftFidelity::FullBody);
        assert_eq!(
            lift.stmts,
            vec![PythonStmt::Return(PythonExpr::BinOp {
                op: BinOpKind::Add,
                left: Box::new(PythonExpr::Name("a".to_owned())),
                right: Box::new(PythonExpr::Name("b".to_owned())),
            })]
        );
    }

    #[test]
    fn nested_subexpression_folds_through_temps() {
        let body: &str = r"{
PyObject *par_a = python_pars[0];
PyObject *par_b = python_pars[1];
PyObject *par_c = python_pars[2];
tmp_add_expr_left_1 = par_a;
tmp_mult_expr_left_1 = par_b;
tmp_mult_expr_right_1 = par_c;
tmp_add_expr_right_1 = BINARY_OPERATION_MULT_OBJECT_OBJECT_OBJECT(tmp_mult_expr_left_1, tmp_mult_expr_right_1);
tmp_return_value = BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(tmp_add_expr_left_1, tmp_add_expr_right_1);
goto frame_return_exit_1;
}";
        let pool: ConstantsPool = ConstantsPool::default();
        let lift: BodyLift = lift_body_detailed(body, &[], &pool);
        assert_eq!(
            lift.stmts,
            vec![PythonStmt::Return(PythonExpr::BinOp {
                op: BinOpKind::Add,
                left: Box::new(PythonExpr::Name("a".to_owned())),
                right: Box::new(PythonExpr::BinOp {
                    op: BinOpKind::Mult,
                    left: Box::new(PythonExpr::Name("b".to_owned())),
                    right: Box::new(PythonExpr::Name("c".to_owned())),
                }),
            })]
        );
    }

    #[test]
    fn unary_negative_lifts_to_unaryop() {
        let body: &str = r"{
PyObject *par_a = python_pars[0];
tmp_operand_value_1 = par_a;
tmp_return_value = UNARY_OPERATION(PyNumber_Negative, tmp_operand_value_1);
goto frame_return_exit_1;
}";
        let pool: ConstantsPool = ConstantsPool::default();
        let lift: BodyLift = lift_body_detailed(body, &[], &pool);
        assert_eq!(
            lift.stmts,
            vec![PythonStmt::Return(PythonExpr::UnaryOp {
                op: UnaryOpKind::Neg,
                operand: Box::new(PythonExpr::Name("a".to_owned())),
            })]
        );
    }

    #[test]
    fn method_call_lifts_to_attribute_call() {
        let body: &str = r"{
PyObject *par_s = python_pars[0];
tmp_expression_value_1 = par_s;
tmp_called_value_1 = LOOKUP_ATTRIBUTE(tstate, tmp_expression_value_1, mod_consts.const_str_plain_upper);
tmp_return_value = CALL_FUNCTION_NO_ARGS(tstate, tmp_called_value_1);
goto frame_return_exit_1;
}";
        let pool: ConstantsPool = ConstantsPool::default();
        let lift: BodyLift = lift_body_detailed(body, &[], &pool);
        assert_eq!(
            lift.stmts,
            vec![PythonStmt::Return(PythonExpr::Call {
                func: Box::new(PythonExpr::Attribute {
                    value: Box::new(PythonExpr::Name("s".to_owned())),
                    attr: "upper".to_owned(),
                }),
                args: Vec::new(),
            })]
        );
    }

    #[test]
    fn early_return_if_lifts_to_if_without_else() {
        let body: &str = r"{
PyObject *par_n = python_pars[0];
tmp_cmp_expr_left_1 = par_n;
tmp_cmp_expr_right_1 = const_int_0;
tmp_condition_result_1 = RICH_COMPARE_LT_NBOOL_OBJECT_LONG(tmp_cmp_expr_left_1, tmp_cmp_expr_right_1);
if (tmp_condition_result_1 == NUITKA_BOOL_TRUE) {
goto branch_yes_1;
} else {
goto branch_no_1;
}
branch_yes_1:;
tmp_return_value = const_int_0;
goto frame_return_exit_1;
branch_no_1:;
tmp_return_value = par_n;
goto frame_return_exit_1;
}";
        let pool: ConstantsPool = ConstantsPool::default();
        let lift: BodyLift = lift_body_detailed(body, &[], &pool);
        assert_eq!(
            lift.stmts,
            vec![
                PythonStmt::If {
                    test: PythonExpr::Compare {
                        op: CmpOpKind::Lt,
                        left: Box::new(PythonExpr::Name("n".to_owned())),
                        right: Box::new(PythonExpr::Const("0".to_owned())),
                    },
                    body: vec![PythonStmt::Return(PythonExpr::Const("0".to_owned()))],
                    orelse: Vec::new(),
                },
                PythonStmt::Return(PythonExpr::Name("n".to_owned())),
            ]
        );
    }

    #[test]
    fn unrecognized_semantic_line_downgrades_to_partial() {
        let body: &str = r"{
tmp_return_value = par_n;
SOME_UNMODELED_NUITKA_HELPER(tstate, tmp_x);
goto frame_return_exit_1;
}";
        let pool: ConstantsPool = ConstantsPool::default();
        let lift: BodyLift = lift_body_detailed(body, &[], &pool);
        assert_eq!(lift.fidelity, LiftFidelity::PartialBody);
        assert!(
            lift.unrecognized_lines
                .iter()
                .any(|l: &String| l.contains("SOME_UNMODELED_NUITKA_HELPER"))
        );
    }

    #[test]
    fn raise_idiom_lifts_to_raise_statement() {
        let body: &str = r"{
tmp_raise_type_1 = CALL_FUNCTION_WITH_SINGLE_ARG(tstate, PyExc_ValueError, mod_consts.const_str_plain_boom);
exception_state.exception_value = tmp_raise_type_1;
exception_lineno = 3;
RAISE_EXCEPTION_WITH_VALUE(tstate, &exception_state);
goto frame_exception_exit_1;
}";
        let pool: ConstantsPool = ConstantsPool::default();
        let (stmts, _): (Vec<PythonStmt>, LiftFidelity) = lift_body(body, &[], &pool);
        assert_eq!(
            stmts,
            vec![PythonStmt::Raise(PythonExpr::Call {
                func: Box::new(PythonExpr::Name("ValueError".to_owned())),
                args: vec![PythonExpr::Const("'boom'".to_owned())],
            })]
        );
    }
}
