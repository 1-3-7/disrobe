use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::body::{
    c_code_mask_with_nuitka_python_abi, extract_c_function_body_range_at_with_mask,
    find_code_marker,
};
use crate::demangle::{DemangledFunction, NuitkaSymbolKind, demangle_function};
use crate::error::{Error, Result};
use crate::limits::validate_c_source;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CCodeObject {
    #[serde(default)]
    pub symbol: String,
    pub name: String,
    pub line: u32,
    pub arg_names_const: Option<String>,
    pub arg_count: u32,
    pub kw_only_count: u32,
    pub pos_only_count: u32,
    pub has_varargs: bool,
    pub has_kwargs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CImplBody {
    pub function_name: String,
    pub source_index: u32,
    pub params: Vec<String>,
    pub parent_names: Vec<String>,
    pub impl_symbol: String,
    #[serde(default)]
    pub code_object_symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CFunctionWiring {
    pub function_name: String,
    #[serde(default)]
    pub source_index: Option<u32>,
    pub annotations_dict_const: Option<String>,
    pub defaults_const: Option<String>,
    #[serde(default)]
    pub kw_defaults_const: Option<String>,
    pub doc_const: Option<String>,
    pub parent_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CConstReturn {
    pub function_name: String,
    pub source_index: u32,
    pub parent_names: Vec<String>,
    pub value_const: String,
    #[serde(default)]
    pub code_object_symbol: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CModuleStructure {
    pub module_name: String,
    #[serde(default)]
    pub python_abi: Option<(u8, u8)>,
    pub code_objects: Vec<CCodeObject>,
    pub impl_bodies: Vec<CImplBody>,
    #[serde(default)]
    pub const_returns: Vec<CConstReturn>,
    pub wirings: Vec<CFunctionWiring>,
    pub has_main_guard: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCodeObject {
    code_object: CCodeObject,
    name_token: String,
}

#[derive(Debug, Default)]
struct ParsedCodeObjects {
    code_objects: Vec<CCodeObject>,
    name_tokens: BTreeMap<String, String>,
}

const DIGEST_NAME_PREFIX: &str = "const_str_digest_";
const STR_PLAIN_PREFIX: &str = "const_str_plain_";
const MAKE_CODE_OBJECT_SLOT_COUNT: usize = 10;
const NUITKA_FUNCTION_NEW_SLOT_COUNT: usize = 11;
const MAX_C_MODULE_RECORDS: usize = 65_536;
const MAX_C_FUNCTION_PARAMETERS: usize = 4_096;
const MAX_C_CALL_ARGUMENT_BYTES: usize = 1_048_576;
const MAX_C_DIRECT_STATEMENT_BYTES: usize = 1_048_576;
const MAX_FACTORY_TOP_LEVEL_STATEMENTS: usize = 4_096;
const MAX_TEMPORARY_CONST_SCOPES: usize = 65_536;
const MAX_TEMPORARY_CONST_SCOPE_SEGMENTS: usize = 131_072;
const MAX_TEMPORARY_CONST_ASSIGNMENTS: usize = 65_536;

#[inline]
fn strip_mod_consts(token: &str) -> &str {
    token.strip_prefix("mod_consts.").unwrap_or(token)
}

fn parse_module_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let t: &str = line.trim();
        let Some(body): Option<&str> = t.strip_prefix("PyObject *module_") else {
            continue;
        };
        let Some(name): Option<&str> = body.strip_suffix(';') else {
            continue;
        };
        if !name.is_empty() && name.chars().all(|c: char| c.is_alphanumeric() || c == '_') {
            return Some(name.to_owned());
        }
    }
    None
}

fn parse_code_objects(
    source: &str,
    code: &[u8],
    factory_names: &BTreeMap<String, String>,
) -> Result<ParsedCodeObjects> {
    let marker: &[u8] = b"MAKE_CODE_OBJECT(";
    let mut candidates: BTreeMap<String, Option<ParsedCodeObject>> = BTreeMap::new();
    let mut search: usize = 0usize;

    while let Some(start) = find_code_marker(code, marker, search) {
        let next_search: usize = start.saturating_add(marker.len());
        let scan_end: usize = find_code_marker(code, marker, next_search).unwrap_or(code.len());
        let Some(symbol): Option<String> =
            assignment_target_before_call_from(source, code, search, start)
        else {
            search = next_search;
            continue;
        };
        let open: usize = start + marker.len() - 1;
        let Some(close): Option<usize> = matching_paren_with_mask_before(code, open, scan_end)
        else {
            search = scan_end;
            continue;
        };
        let Some(args): Option<Vec<String>> =
            split_top_level_args_with_mask(code, open + 1, close, MAKE_CODE_OBJECT_SLOT_COUNT)
        else {
            search = close.saturating_add(1usize);
            continue;
        };
        if args.len() != MAKE_CODE_OBJECT_SLOT_COUNT {
            search = close.saturating_add(1usize);
            continue;
        }
        let name_token: String = strip_mod_consts(args[3].trim()).to_owned();
        let name: Option<String> = name_token
            .strip_prefix(STR_PLAIN_PREFIX)
            .filter(|name: &&str| !name.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                name_token
                    .starts_with(DIGEST_NAME_PREFIX)
                    .then(|| factory_names.get(&symbol).cloned())
                    .flatten()
            });
        let Some(name): Option<String> = name else {
            search = close.saturating_add(1usize);
            continue;
        };
        let Ok(line_no): core::result::Result<u32, _> = args[1].trim().parse() else {
            search = close.saturating_add(1usize);
            continue;
        };
        let arg_names_raw: &str = strip_mod_consts(args[5].trim());
        let arg_names_const: Option<String> = if arg_names_raw == "NULL" {
            None
        } else {
            Some(arg_names_raw.to_owned())
        };
        let Ok(arg_count): core::result::Result<u32, _> = args[7].trim().parse() else {
            search = close.saturating_add(1);
            continue;
        };
        let Ok(kw_only_count): core::result::Result<u32, _> = args[8].trim().parse() else {
            search = close.saturating_add(1);
            continue;
        };
        let Ok(pos_only_count): core::result::Result<u32, _> = args[9].trim().parse() else {
            search = close.saturating_add(1);
            continue;
        };
        let flags: &str = args[2].trim();
        let candidate: ParsedCodeObject = ParsedCodeObject {
            code_object: CCodeObject {
                symbol: symbol.clone(),
                name,
                line: line_no,
                arg_names_const,
                arg_count,
                kw_only_count,
                pos_only_count,
                has_varargs: flags.contains("CO_VARARGS"),
                has_kwargs: flags.contains("CO_VARKEYWORDS"),
            },
            name_token,
        };
        if !candidates.contains_key(&symbol) && candidates.len() == MAX_C_MODULE_RECORDS {
            return Err(Error::CSourceComplexityExceeded {
                resource: "code object",
                count: candidates.len().saturating_add(1usize),
                max_count: MAX_C_MODULE_RECORDS,
            });
        }
        match candidates.entry(symbol) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(candidate));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().as_ref() != Some(&candidate) {
                    entry.insert(None);
                }
            }
        }
        search = close.saturating_add(1);
    }

    let mut parsed: ParsedCodeObjects = ParsedCodeObjects::default();
    for candidate in candidates.into_values().flatten() {
        parsed
            .name_tokens
            .insert(candidate.code_object.symbol.clone(), candidate.name_token);
        parsed.code_objects.push(candidate.code_object);
    }
    Ok(parsed)
}

fn parse_impl_bodies(
    lines: &[&str],
    code_object_symbols: &BTreeMap<String, String>,
) -> Result<Vec<CImplBody>> {
    let mut out: Vec<CImplBody> = Vec::new();
    let mut i: usize = 0usize;
    while i < lines.len() {
        let line: &str = lines[i];
        let demangled: Option<DemangledFunction> = impl_decl_demangle(line);
        let Some(demangled): Option<DemangledFunction> = demangled else {
            i += 1;
            continue;
        };
        let (params, end): (Vec<(u32, String)>, usize) = collect_params(lines, i)?;
        if demangled.kind != NuitkaSymbolKind::Function {
            i = end + 1;
            continue;
        }
        let mut ordered: Vec<(u32, String)> = params;
        ordered.sort_by_key(|(idx, _): &(u32, String)| *idx);
        if out.len() == MAX_C_MODULE_RECORDS {
            return Err(Error::CSourceComplexityExceeded {
                resource: "implementation body",
                count: out.len().saturating_add(1usize),
                max_count: MAX_C_MODULE_RECORDS,
            });
        }
        out.push(CImplBody {
            function_name: demangled.function_name,
            source_index: demangled.source_index,
            params: ordered.into_iter().map(|(_, n): (u32, String)| n).collect(),
            parent_names: demangled.parent_names,
            code_object_symbol: code_object_symbols.get(&demangled.raw_symbol).cloned(),
            impl_symbol: demangled.raw_symbol,
        });
        i = end + 1;
    }
    Ok(out)
}

fn impl_decl_demangle(line: &str) -> Option<DemangledFunction> {
    let t: &str = line.trim_start();
    let after: &str = t.strip_prefix("static PyObject *")?;
    let symbol: &str = after.split('(').next()?;
    if !symbol.starts_with("impl_") {
        return None;
    }
    if !line.contains("python_pars") {
        return None;
    }
    demangle_function(symbol)
}

fn collect_params(lines: &[&str], decl: usize) -> Result<(Vec<(u32, String)>, usize)> {
    let mut depth: i32 = 0i32;
    let mut started: bool = false;
    let mut params: Vec<(u32, String)> = Vec::new();
    let mut i: usize = decl;
    while i < lines.len() {
        let line: &str = lines[i];
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        if let Some((idx, name)) = parse_param_line(line) {
            if params.len() == MAX_C_FUNCTION_PARAMETERS {
                return Err(Error::CSourceComplexityExceeded {
                    resource: "function parameter",
                    count: params.len().saturating_add(1usize),
                    max_count: MAX_C_FUNCTION_PARAMETERS,
                });
            }
            params.push((idx, name));
        }
        if started && depth <= 0 {
            return Ok((params, i));
        }
        i += 1;
    }
    Ok((params, lines.len().saturating_sub(1)))
}

fn parse_param_line(line: &str) -> Option<(u32, String)> {
    let t: &str = line.trim();
    if let Some(after) = t.strip_prefix("PyObject *par_") {
        let (name, rest): (&str, &str) = after.split_once(" = python_pars[")?;
        let idx: u32 = rest.split(']').next()?.trim().parse().ok()?;
        if name.is_empty() {
            return None;
        }
        return Some((idx, name.to_owned()));
    }
    if let Some(after) = t.strip_prefix("struct Nuitka_CellObject *par_") {
        let (name, rest): (&str, &str) = after.split_once(" = Nuitka_Cell_New1(python_pars[")?;
        let idx: u32 = rest.split(']').next()?.trim().parse().ok()?;
        if name.is_empty() {
            return None;
        }
        return Some((idx, name.to_owned()));
    }
    None
}

fn parse_wirings(lines: &[&str]) -> Result<Vec<CFunctionWiring>> {
    let mut wirings: Vec<CFunctionWiring> = Vec::new();
    for line in lines {
        if let Some(demangled) = parse_make_function_call(line)
            && demangled.kind == NuitkaSymbolKind::Function
        {
            if wirings.len() == MAX_C_MODULE_RECORDS {
                return Err(Error::CSourceComplexityExceeded {
                    resource: "function wiring",
                    count: wirings.len().saturating_add(1usize),
                    max_count: MAX_C_MODULE_RECORDS,
                });
            }
            wirings.push(CFunctionWiring {
                function_name: demangled.function_name,
                source_index: Some(demangled.source_index),
                annotations_dict_const: None,
                defaults_const: None,
                kw_defaults_const: None,
                doc_const: None,
                parent_names: demangled.parent_names,
            });
        }
    }
    Ok(wirings)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionFactory {
    factory_symbol: String,
    function_name: String,
    source_index: u32,
    parent_names: Vec<String>,
    name_token: String,
    implementation_symbol: Option<String>,
    code_object_symbol: String,
    const_return: Option<String>,
    defaults_const: Option<String>,
    kw_defaults_const: Option<String>,
    doc_const: Option<String>,
    creation_parameters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FunctionIdentity {
    function_name: String,
    source_index: u32,
    parent_names: Vec<String>,
}

impl FunctionFactory {
    fn identity(&self) -> FunctionIdentity {
        FunctionIdentity {
            function_name: self.function_name.clone(),
            source_index: self.source_index,
            parent_names: self.parent_names.clone(),
        }
    }
}

struct FactoryMetadata {
    name_token: String,
    implementation_symbol: Option<String>,
    code_object_symbol: String,
    const_return: Option<String>,
    defaults_const: Option<String>,
    kw_defaults_const: Option<String>,
    doc_const: Option<String>,
    creation_parameters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FactoryCall {
    Absent,
    Single(Vec<String>),
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FactoryCallBindings {
    annotations: Option<String>,
    defaults: Option<String>,
    keyword_defaults: Option<String>,
}

enum FactoryParameterConst {
    Absent,
    Value(String),
    Unresolved,
}

#[derive(Debug, Default)]
struct TemporaryConstBindings {
    scopes: BTreeMap<usize, TemporaryConstScope>,
    scope_segments: Vec<TemporaryConstScopeSegment>,
}

#[derive(Debug)]
struct TemporaryConstScopeSegment {
    start: usize,
    end: usize,
    scope_start: usize,
}

#[derive(Debug, Default)]
struct TemporaryConstScope {
    start: usize,
    depth: usize,
    plain_block: bool,
    values: BTreeMap<String, Vec<(usize, TemporaryConstValue)>>,
    control_flow: TemporaryConstControlFlow,
}

#[derive(Debug, Default)]
enum TemporaryConstControlFlow {
    #[default]
    None,
    Inherited,
    Local(usize),
}

impl TemporaryConstControlFlow {
    fn mark_local(&mut self, position: usize) {
        match self {
            Self::None | Self::Inherited => *self = Self::Local(position),
            Self::Local(existing) => *existing = (*existing).min(position),
        }
    }

    const fn applies_before(&self, position: usize) -> bool {
        match self {
            Self::None | Self::Inherited => false,
            Self::Local(existing) => *existing < position,
        }
    }

    const fn inherits_before(&self, position: usize) -> bool {
        match self {
            Self::None => false,
            Self::Inherited => true,
            Self::Local(existing) => *existing < position,
        }
    }
}

#[derive(Debug)]
enum TemporaryConstValue {
    Value(String),
    Unresolved,
}

struct ReturnedVariable {
    name: String,
    return_start: usize,
}

struct DirectAssignment {
    target: String,
    assignment: usize,
}

struct FunctionConstruction {
    slots: Vec<String>,
    start: usize,
    end: usize,
}

fn parse_factory_metadata(factory: &str, code: &[u8]) -> Option<FactoryMetadata> {
    if factory.len() != code.len() {
        return None;
    }
    let statements: Vec<std::ops::Range<usize>> = factory_top_level_statements(code)?;
    let returned: ReturnedVariable = parse_returned_variable(factory, code, &statements)?;
    let construction: FunctionConstruction =
        parse_function_new_args(factory, code, &returned, &statements)?;
    let slots: &[String] = &construction.slots;
    let name_token: String = slots
        .get(1)
        .map(String::as_str)
        .map(str::trim)
        .map(strip_mod_consts)
        .filter(|token: &&str| {
            token.starts_with(STR_PLAIN_PREFIX) || token.starts_with(DIGEST_NAME_PREFIX)
        })?
        .to_owned();
    let code_object_symbol: String = slots
        .get(3)
        .map(String::as_str)
        .map(str::trim)
        .filter(|symbol: &&str| symbol.starts_with("code_objects_"))?
        .to_owned();
    let implementation_symbol: Option<String> = slots
        .first()
        .map(String::as_str)
        .map(str::trim)
        .filter(|symbol: &&str| symbol.starts_with("impl_"))
        .map(str::to_owned);
    let defaults_const: Option<String> = slots.get(4).map(String::as_str).and_then(non_null_const);
    let kw_defaults_const: Option<String> =
        slots.get(5).map(String::as_str).and_then(non_null_const);
    let doc_const: Option<String> = slots.get(8).map(String::as_str).and_then(non_null_const);
    let creation_parameters: Vec<String> = parse_factory_parameters(code)?;
    let const_return: Option<String> =
        parse_const_return_value(code, &returned, &construction, slots, &statements);
    Some(FactoryMetadata {
        name_token,
        implementation_symbol,
        code_object_symbol,
        const_return,
        defaults_const,
        kw_defaults_const,
        doc_const,
        creation_parameters,
    })
}

fn parse_factory_parameters(code: &[u8]) -> Option<Vec<String>> {
    let open: usize = code.iter().position(|byte: &u8| *byte == b'(')?;
    let close: usize = matching_paren_with_mask(code, open)?;
    let values: Vec<String> =
        split_top_level_args_with_mask(code, open + 1, close, MAX_C_FUNCTION_PARAMETERS)?;
    values
        .iter()
        .map(|value: &String| trailing_c_identifier(value))
        .collect()
}

fn factory_top_level_statements(code: &[u8]) -> Option<Vec<std::ops::Range<usize>>> {
    let body_open: usize = code.iter().position(|byte: &u8| *byte == b'{')?;
    let mut statements: Vec<std::ops::Range<usize>> = Vec::new();
    let mut statement_start: usize = body_open.checked_add(1usize)?;
    let mut brace_depth: i32 = 1i32;
    let mut paren_depth: i32 = 0i32;
    let mut bracket_depth: i32 = 0i32;
    let mut position: usize = statement_start;
    while position < code.len() {
        if code_keyword_at(code, b"return", position) && brace_depth != 1i32 {
            return None;
        }
        match code[position] {
            b'{' => brace_depth = brace_depth.checked_add(1i32)?,
            b'}' => {
                brace_depth = brace_depth.checked_sub(1i32)?;
                if brace_depth == 0i32 {
                    return (paren_depth == 0i32 && bracket_depth == 0i32).then_some(statements);
                }
            }
            b'(' => paren_depth = paren_depth.checked_add(1i32)?,
            b')' => paren_depth = paren_depth.checked_sub(1i32)?,
            b'[' => bracket_depth = bracket_depth.checked_add(1i32)?,
            b']' => bracket_depth = bracket_depth.checked_sub(1i32)?,
            b';' if brace_depth == 1i32 && paren_depth == 0i32 && bracket_depth == 0i32 => {
                if statements.len() == MAX_FACTORY_TOP_LEVEL_STATEMENTS {
                    return None;
                }
                let statement_end: usize = position.checked_add(1usize)?;
                statements.push(statement_start..statement_end);
                statement_start = statement_end;
            }
            _ => {}
        }
        position = position.checked_add(1usize)?;
    }
    None
}

fn code_keyword_at(code: &[u8], marker: &[u8], position: usize) -> bool {
    if marker.is_empty()
        || code.get(position..position.saturating_add(marker.len())) != Some(marker)
    {
        return false;
    }
    let previous: Option<u8> = position
        .checked_sub(1usize)
        .and_then(|index: usize| code.get(index))
        .copied();
    let next: Option<u8> = position
        .checked_add(marker.len())
        .and_then(|index: usize| code.get(index))
        .copied();
    !previous.is_some_and(is_c_identifier_continue) && !next.is_some_and(is_c_identifier_continue)
}

fn trailing_c_identifier(value: &str) -> Option<String> {
    let bytes: &[u8] = value.as_bytes();
    let mut end: usize = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start: usize = end;
    while start > 0 && is_c_identifier_continue(bytes[start - 1]) {
        start -= 1;
    }
    (start < end)
        .then(|| value.get(start..end).map(str::to_owned))
        .flatten()
}

fn parse_const_return_value(
    code: &[u8],
    returned: &ReturnedVariable,
    construction: &FunctionConstruction,
    slots: &[String],
    statements: &[std::ops::Range<usize>],
) -> Option<String> {
    if slots
        .first()
        .is_none_or(|implementation: &String| implementation.trim() != "NULL")
    {
        return None;
    }
    if !factory_constant_return_path_is_linear(code, construction, returned) {
        return None;
    }
    let generic: FactoryCall = find_factory_call_args(
        code,
        b"Nuitka_Function_EnableConstReturnGeneric(",
        returned,
        construction.start,
        statements,
    );
    let truth: FactoryCall = find_factory_call_args(
        code,
        b"Nuitka_Function_EnableConstReturnTrue(",
        returned,
        construction.start,
        statements,
    );
    let falsity: FactoryCall = find_factory_call_args(
        code,
        b"Nuitka_Function_EnableConstReturnFalse(",
        returned,
        construction.start,
        statements,
    );
    match (generic, truth, falsity) {
        (FactoryCall::Single(args), FactoryCall::Absent, FactoryCall::Absent)
            if args.len() == 2 =>
        {
            let value: &str = args.get(1)?.trim();
            let token: &str = strip_mod_consts(value);
            token.starts_with("const_").then(|| token.to_owned())
        }
        (FactoryCall::Absent, FactoryCall::Single(args), FactoryCall::Absent)
            if args.len() == 1 =>
        {
            Some("const_true".to_owned())
        }
        (FactoryCall::Absent, FactoryCall::Absent, FactoryCall::Single(args))
            if args.len() == 1 =>
        {
            Some("const_false".to_owned())
        }
        (FactoryCall::Absent, FactoryCall::Absent, FactoryCall::Absent) => {
            Some("const_none".to_owned())
        }
        _ => None,
    }
}

fn factory_constant_return_path_is_linear(
    code: &[u8],
    construction: &FunctionConstruction,
    returned: &ReturnedVariable,
) -> bool {
    let Some(body_start): Option<usize> = code
        .iter()
        .position(|byte: &u8| *byte == b'{')
        .and_then(|position: usize| position.checked_add(1))
    else {
        return false;
    };
    if construction.start < body_start
        || construction.start >= returned.return_start
        || construction.end >= returned.return_start
    {
        return false;
    }
    !statement_contains_control_flow(code, body_start, returned.return_start)
        && code
            .get(body_start..returned.return_start)
            .is_some_and(|body: &[u8]| !body.contains(&b':'))
        && returned_variable_has_only_const_return_uses(
            code,
            construction.end.saturating_add(1),
            returned.return_start,
            &returned.name,
        )
}

fn returned_variable_has_only_const_return_uses(
    code: &[u8],
    start: usize,
    end: usize,
    returned: &str,
) -> bool {
    let returned: &[u8] = returned.as_bytes();
    let mut statement_start: usize = start;
    while statement_start < end {
        let Some(remaining): Option<&[u8]> = code.get(statement_start..end) else {
            return false;
        };
        if remaining.iter().all(u8::is_ascii_whitespace) {
            return true;
        }
        let Some(semicolon_offset): Option<usize> =
            remaining.iter().position(|byte: &u8| *byte == b';')
        else {
            return false;
        };
        let statement_end: usize = statement_start + semicolon_offset;
        let Some(statement): Option<&[u8]> = code.get(statement_start..statement_end) else {
            return false;
        };
        if code_keyword_in_range(statement, returned, 0usize, statement.len())
            && !is_const_return_enablement_statement(statement, returned)
        {
            return false;
        }
        statement_start = statement_end.saturating_add(1);
    }
    true
}

fn is_const_return_enablement_statement(statement: &[u8], returned: &[u8]) -> bool {
    const MARKERS: [&[u8]; 3] = [
        b"Nuitka_Function_EnableConstReturnGeneric(",
        b"Nuitka_Function_EnableConstReturnTrue(",
        b"Nuitka_Function_EnableConstReturnFalse(",
    ];
    let start: usize = skip_code_whitespace(statement, 0usize);
    let Some(end): Option<usize> = statement
        .iter()
        .rposition(|byte: &u8| !byte.is_ascii_whitespace())
        .map(|position: usize| position.saturating_add(1))
    else {
        return false;
    };
    let trimmed: &[u8] = &statement[start..end];
    MARKERS.iter().any(|marker: &&[u8]| {
        if !trimmed.starts_with(marker) {
            return false;
        }
        let open: usize = marker.len().saturating_sub(1);
        let Some(close): Option<usize> = matching_paren_with_mask(trimmed, open) else {
            return false;
        };
        if skip_code_whitespace(trimmed, close.saturating_add(1)) != trimmed.len() {
            return false;
        }
        let Some(args): Option<Vec<String>> = split_top_level_args_with_mask(
            trimmed,
            open.saturating_add(1),
            close,
            MAX_C_FUNCTION_PARAMETERS,
        ) else {
            return false;
        };
        args.first()
            .is_some_and(|argument: &String| argument.trim().as_bytes() == returned)
    })
}

fn parse_function_new_args(
    factory: &str,
    code: &[u8],
    returned: &ReturnedVariable,
    statements: &[std::ops::Range<usize>],
) -> Option<FunctionConstruction> {
    let marker: &[u8] = b"Nuitka_Function_New(";
    let mut found: Option<FunctionConstruction> = None;
    for statement in statements {
        let Some(start): Option<usize> = find_code_marker(code, marker, statement.start) else {
            continue;
        };
        if start >= statement.end {
            continue;
        }
        let Some(assignment): Option<DirectAssignment> =
            direct_assignment_prefix(factory, code, statement.start, start)
        else {
            continue;
        };
        if assignment.target != returned.name {
            continue;
        }
        if !code
            .get(assignment.assignment + 1usize..start)?
            .iter()
            .all(u8::is_ascii_whitespace)
        {
            return None;
        }
        let open: usize = start + marker.len() - 1usize;
        let close: usize = matching_paren_with_mask_before(code, open, statement.end)?;
        if close >= returned.return_start
            || !direct_statement_suffix_in_range(code, close, statement)
        {
            return None;
        }
        let slots: Vec<String> = split_top_level_args_with_mask(
            code,
            open + 1usize,
            close,
            NUITKA_FUNCTION_NEW_SLOT_COUNT,
        )?;
        if slots.len() != NUITKA_FUNCTION_NEW_SLOT_COUNT {
            return None;
        }
        let construction: FunctionConstruction = FunctionConstruction {
            slots,
            start,
            end: close,
        };
        if found.replace(construction).is_some() {
            return None;
        }
    }
    found
}

fn find_factory_call_args(
    code: &[u8],
    marker: &[u8],
    returned: &ReturnedVariable,
    construction_start: usize,
    statements: &[std::ops::Range<usize>],
) -> FactoryCall {
    let mut found: Option<Vec<String>> = None;
    for statement in statements {
        let Some(start): Option<usize> = find_code_marker(code, marker, statement.start) else {
            continue;
        };
        if start >= statement.end {
            continue;
        }
        let open: usize = start + marker.len() - 1usize;
        let Some(close): Option<usize> = matching_paren_with_mask_before(code, open, statement.end)
        else {
            return FactoryCall::Ambiguous;
        };
        let Some(args): Option<Vec<String>> =
            split_top_level_args_with_mask(code, open + 1usize, close, MAX_C_FUNCTION_PARAMETERS)
        else {
            return FactoryCall::Ambiguous;
        };
        if args
            .first()
            .is_none_or(|argument: &String| argument.trim() != returned.name.as_str())
        {
            continue;
        }
        if start <= construction_start
            || !code
                .get(statement.start..start)
                .is_some_and(|prefix: &[u8]| prefix.iter().all(u8::is_ascii_whitespace))
            || !direct_statement_suffix_in_range(code, close, statement)
            || found.replace(args).is_some()
        {
            return FactoryCall::Ambiguous;
        }
    }
    found.map_or(FactoryCall::Absent, FactoryCall::Single)
}

fn direct_statement_suffix_in_range(
    code: &[u8],
    close: usize,
    statement: &std::ops::Range<usize>,
) -> bool {
    let Some(after_call): Option<usize> = close.checked_add(1usize) else {
        return false;
    };
    let Some(semicolon): Option<usize> = statement.end.checked_sub(1usize) else {
        return false;
    };
    code.get(semicolon) == Some(&b';')
        && after_call <= semicolon
        && code
            .get(after_call..semicolon)
            .is_some_and(|suffix: &[u8]| suffix.iter().all(u8::is_ascii_whitespace))
}

fn direct_statement_suffix(code: &[u8], close: usize, return_start: usize) -> bool {
    let Some(after_call): Option<usize> = close.checked_add(1) else {
        return false;
    };
    let Some(tail_end): Option<usize> = after_call
        .checked_add(MAX_C_DIRECT_STATEMENT_BYTES)
        .map(|end: usize| end.min(return_start))
    else {
        return false;
    };
    let Some(semicolon_offset): Option<usize> = code
        .get(after_call..tail_end)
        .and_then(|remaining: &[u8]| remaining.iter().position(|byte: &u8| *byte == b';'))
    else {
        return false;
    };
    let semicolon: usize = after_call + semicolon_offset;
    semicolon < return_start
        && code[after_call..semicolon]
            .iter()
            .all(u8::is_ascii_whitespace)
}

fn is_plain_assignment_operator(prefix: &[u8], offset: usize) -> bool {
    if prefix.get(offset) != Some(&b'=') {
        return false;
    }
    let previous: Option<u8> = offset
        .checked_sub(1)
        .and_then(|index: usize| prefix.get(index))
        .copied();
    let next: Option<u8> = prefix.get(offset + 1).copied();
    !matches!(previous, Some(b'=' | b'!' | b'<' | b'>')) && !matches!(next, Some(b'='))
}

fn direct_assignment_prefix(
    source: &str,
    code: &[u8],
    statement_start: usize,
    end: usize,
) -> Option<DirectAssignment> {
    let prefix: &[u8] = code.get(statement_start..end)?;
    let mut assignment: Option<usize> = None;
    for (offset, byte) in prefix.iter().enumerate() {
        if *byte != b'=' || !is_plain_assignment_operator(prefix, offset) {
            continue;
        }
        if assignment.replace(statement_start + offset).is_some() {
            return None;
        }
    }
    let assignment: usize = assignment?;
    if statement_contains_control_flow(code, statement_start, end) {
        return None;
    }
    let left: &[u8] = code.get(statement_start..assignment)?;
    if !left.iter().all(|byte: &u8| {
        byte.is_ascii_whitespace() || is_c_identifier_continue(*byte) || *byte == b'*'
    }) {
        return None;
    }
    let target: String = last_code_identifier(source, code, statement_start, assignment)?;
    Some(DirectAssignment { target, assignment })
}

fn parse_function_factories(source: &str, code: &[u8]) -> Result<Vec<FunctionFactory>> {
    let marker: &str = "static PyObject *MAKE_FUNCTION_";
    if source.len() != code.len() {
        return Ok(Vec::new());
    }
    let mut candidates: BTreeMap<String, Option<FunctionFactory>> = BTreeMap::new();
    let mut search: usize = 0usize;

    while let Some(start) = find_code_marker(code, marker.as_bytes(), search) {
        let after_start: usize = start.saturating_add("static PyObject *".len());
        let declaration_end: usize =
            find_code_marker(code, b"static PyObject *", after_start).unwrap_or(code.len());
        let Some(after): Option<&str> = source.get(after_start..declaration_end) else {
            break;
        };
        let Some(symbol): Option<&str> = after.split('(').next() else {
            break;
        };
        let symbol: &str = symbol.trim();
        let Some(demangled): Option<DemangledFunction> = demangle_function(symbol) else {
            search = start + marker.len();
            continue;
        };
        if demangled.kind != NuitkaSymbolKind::Function {
            search = start + marker.len();
            continue;
        }
        let metadata: Option<FactoryMetadata> = extract_c_function_body_range_at_with_mask(
            source, code, start,
        )
        .and_then(|range: std::ops::Range<usize>| {
            let factory: &str = source.get(range.clone())?;
            let factory_code: &[u8] = code.get(range)?;
            parse_factory_metadata(factory, factory_code)
        });
        if let Some(metadata) = metadata {
            let candidate: FunctionFactory = FunctionFactory {
                factory_symbol: symbol.to_owned(),
                function_name: demangled.function_name,
                source_index: demangled.source_index,
                parent_names: demangled.parent_names,
                name_token: metadata.name_token,
                implementation_symbol: metadata.implementation_symbol,
                code_object_symbol: metadata.code_object_symbol,
                const_return: metadata.const_return,
                defaults_const: metadata.defaults_const,
                kw_defaults_const: metadata.kw_defaults_const,
                doc_const: metadata.doc_const,
                creation_parameters: metadata.creation_parameters,
            };
            if !candidates.contains_key(symbol) && candidates.len() == MAX_C_MODULE_RECORDS {
                return Err(Error::CSourceComplexityExceeded {
                    resource: "function factory",
                    count: candidates.len().saturating_add(1usize),
                    max_count: MAX_C_MODULE_RECORDS,
                });
            }
            match candidates.entry(symbol.to_owned()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Some(candidate));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if entry.get().as_ref() != Some(&candidate) {
                        entry.insert(None);
                    }
                }
            }
        }
        search = start + marker.len();
    }

    Ok(candidates
        .into_values()
        .flatten()
        .collect::<Vec<FunctionFactory>>())
}

fn factory_names_by_code_object(factories: &[FunctionFactory]) -> BTreeMap<String, String> {
    let mut candidates: BTreeMap<String, Option<FunctionIdentity>> = BTreeMap::new();
    for factory in factories {
        let candidate: FunctionIdentity = factory.identity();
        match candidates.entry(factory.code_object_symbol.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(candidate));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().as_ref() != Some(&candidate) {
                    entry.insert(None);
                }
            }
        }
    }
    candidates
        .into_iter()
        .filter_map(|(symbol, candidate): (String, Option<FunctionIdentity>)| {
            candidate.map(|identity: FunctionIdentity| (symbol, identity.function_name))
        })
        .collect()
}

fn validated_factories(
    factories: &[FunctionFactory],
    parsed_code_objects: &ParsedCodeObjects,
) -> Vec<FunctionFactory> {
    let by_symbol: BTreeMap<&str, &CCodeObject> = parsed_code_objects
        .code_objects
        .iter()
        .map(|code_object: &CCodeObject| (code_object.symbol.as_str(), code_object))
        .collect();
    factories
        .iter()
        .filter(|factory: &&FunctionFactory| {
            by_symbol
                .get(factory.code_object_symbol.as_str())
                .is_some_and(|code_object: &&CCodeObject| {
                    parsed_code_objects
                        .name_tokens
                        .get(&code_object.symbol)
                        .is_some_and(|name_token: &String| name_token == &factory.name_token)
                        && code_object.name == factory.function_name
                        && factory_name_matches_demangled_name(factory)
                })
        })
        .cloned()
        .collect()
}

fn factory_name_matches_demangled_name(factory: &FunctionFactory) -> bool {
    factory
        .name_token
        .strip_prefix(STR_PLAIN_PREFIX)
        .map_or_else(
            || factory.name_token.starts_with(DIGEST_NAME_PREFIX),
            |name: &str| name == factory.function_name,
        )
}

fn factory_identity_for_wiring(wiring: &CFunctionWiring) -> Option<FunctionIdentity> {
    let source_index: u32 = wiring.source_index?;
    Some(FunctionIdentity {
        function_name: wiring.function_name.clone(),
        source_index,
        parent_names: wiring.parent_names.clone(),
    })
}

fn factories_by_identity(
    factories: &[FunctionFactory],
) -> BTreeMap<FunctionIdentity, Option<&FunctionFactory>> {
    let mut out: BTreeMap<FunctionIdentity, Option<&FunctionFactory>> = BTreeMap::new();
    for factory in factories {
        let identity: FunctionIdentity = factory.identity();
        match out.entry(identity) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(factory));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }
    out
}

fn impl_code_object_symbols(factories: &[FunctionFactory]) -> BTreeMap<String, String> {
    let mut candidates: BTreeMap<String, Option<String>> = BTreeMap::new();
    for factory in factories {
        let Some(implementation_symbol): Option<&String> = factory.implementation_symbol.as_ref()
        else {
            continue;
        };
        let candidate: String = factory.code_object_symbol.clone();
        match candidates.entry(implementation_symbol.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(candidate));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().as_deref() != Some(candidate.as_str()) {
                    entry.insert(None);
                }
            }
        }
    }
    candidates
        .into_iter()
        .filter_map(|(symbol, candidate): (String, Option<String>)| {
            candidate.map(|code_object: String| (symbol, code_object))
        })
        .collect()
}

fn parse_const_returns(factories: &[FunctionFactory]) -> Vec<CConstReturn> {
    factories
        .iter()
        .filter_map(|factory: &FunctionFactory| {
            factory
                .const_return
                .as_ref()
                .map(|value_const: &String| CConstReturn {
                    function_name: factory.function_name.clone(),
                    source_index: factory.source_index,
                    parent_names: factory.parent_names.clone(),
                    value_const: value_const.clone(),
                    code_object_symbol: factory.code_object_symbol.clone(),
                })
        })
        .collect()
}

fn assignment_target_before_call_from(
    source: &str,
    code: &[u8],
    lower_bound: usize,
    call_start: usize,
) -> Option<String> {
    if lower_bound > call_start || call_start > code.len() {
        return None;
    }
    let statement_start: usize = code[lower_bound..call_start]
        .iter()
        .rposition(|byte: &u8| matches!(*byte, b';' | b'{' | b'}'))
        .map_or(lower_bound, |position: usize| {
            lower_bound + position + 1usize
        });
    let assignment: DirectAssignment =
        direct_assignment_prefix(source, code, statement_start, call_start)?;
    code.get(assignment.assignment + 1..call_start)?
        .iter()
        .all(u8::is_ascii_whitespace)
        .then_some(assignment.target)
}

fn parse_returned_variable(
    factory: &str,
    code: &[u8],
    statements: &[std::ops::Range<usize>],
) -> Option<ReturnedVariable> {
    let marker: &[u8] = b"return";
    let mut returned: Option<ReturnedVariable> = None;
    for statement in statements {
        let semicolon: usize = statement.end.checked_sub(1usize)?;
        if code.get(semicolon) != Some(&b';') {
            return None;
        }
        let mut search: usize = statement.start;
        while let Some(start) = find_code_keyword(code, marker, search) {
            if start >= semicolon {
                break;
            }
            if statement_contains_control_flow(code, statement.start, start)
                || code
                    .get(statement.start..start)
                    .is_some_and(|prefix: &[u8]| prefix.contains(&b':'))
            {
                return None;
            }
            let expression_start: usize = start + marker.len();
            let expression: &str = factory.get(expression_start..semicolon)?;
            let expression_code: &[u8] = code.get(expression_start..semicolon)?;
            let variable: String = parse_return_expression(expression, expression_code)?;
            let candidate: ReturnedVariable = ReturnedVariable {
                name: variable,
                return_start: start,
            };
            if returned.replace(candidate).is_some() {
                return None;
            }
            search = expression_start;
        }
    }
    returned
}

fn parse_return_expression(expression: &str, code: &[u8]) -> Option<String> {
    let mut position: usize = skip_code_whitespace(code, 0);
    while code.get(position) == Some(&b'(') {
        let close: usize = matching_paren_with_mask(code, position)?;
        if let Some(identifier) = single_code_identifier(expression, code, position + 1, close) {
            let after: usize = skip_code_whitespace(code, close + 1);
            if after == code.len() {
                return Some(identifier);
            }
        }
        if !is_pointer_cast(&code[position + 1..close]) {
            return None;
        }
        position = skip_code_whitespace(code, close + 1);
    }
    let start: usize = position;
    if !code
        .get(start)
        .is_some_and(|byte: &u8| is_c_identifier_start(*byte))
    {
        return None;
    }
    position += 1;
    while code
        .get(position)
        .is_some_and(|byte: &u8| is_c_identifier_continue(*byte))
    {
        position += 1;
    }
    let end: usize = position;
    (skip_code_whitespace(code, position) == code.len())
        .then(|| expression.get(start..end).map(str::to_owned))
        .flatten()
}

fn find_code_keyword(code: &[u8], marker: &[u8], start: usize) -> Option<usize> {
    let mut search: usize = start;
    while let Some(found) = find_code_marker(code, marker, search) {
        let previous: Option<u8> = found
            .checked_sub(1)
            .and_then(|index: usize| code.get(index))
            .copied();
        let next: Option<u8> = code.get(found + marker.len()).copied();
        if !previous.is_some_and(is_c_identifier_continue)
            && !next.is_some_and(is_c_identifier_continue)
        {
            return Some(found);
        }
        search = found + marker.len();
    }
    None
}

fn last_code_identifier(source: &str, code: &[u8], start: usize, end: usize) -> Option<String> {
    let mut candidate: Option<String> = None;
    let mut position: usize = start;
    while position < end {
        if is_c_identifier_start(code[position]) {
            let token_start: usize = position;
            position += 1;
            while position < end && is_c_identifier_continue(code[position]) {
                position += 1;
            }
            candidate = source.get(token_start..position).map(str::to_owned);
        } else {
            position += 1;
        }
    }
    candidate
}

fn single_code_identifier(source: &str, code: &[u8], start: usize, end: usize) -> Option<String> {
    let token_start: usize = skip_code_whitespace(code, start);
    if token_start >= end || !is_c_identifier_start(code[token_start]) {
        return None;
    }
    let mut token_end: usize = token_start + 1;
    while token_end < end && is_c_identifier_continue(code[token_end]) {
        token_end += 1;
    }
    (skip_code_whitespace(code, token_end) == end)
        .then(|| source.get(token_start..token_end).map(str::to_owned))
        .flatten()
}

fn is_pointer_cast(code: &[u8]) -> bool {
    code.contains(&b'*')
        && code.iter().all(|byte: &u8| {
            byte.is_ascii_whitespace() || is_c_identifier_continue(*byte) || *byte == b'*'
        })
}

fn skip_code_whitespace(code: &[u8], mut position: usize) -> usize {
    while code
        .get(position)
        .is_some_and(|byte: &u8| byte.is_ascii_whitespace())
    {
        position += 1;
    }
    position
}

const fn is_c_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

const fn is_c_identifier_continue(byte: u8) -> bool {
    is_c_identifier_start(byte) || byte.is_ascii_digit()
}

fn parse_dict_copy(line: &str) -> Option<String> {
    const DICT_COPY_CALLEES: [&str; 2] = ["DICT_COPY(", "DEEP_COPY_DICT("];
    let line: &str = line.trim();
    let inner: &str = DICT_COPY_CALLEES
        .iter()
        .find_map(|callee: &&str| line.strip_prefix(callee))?
        .strip_suffix(')')?;
    let mut arguments: std::str::Split<'_, char> = inner.split(',');
    let tstate: &str = arguments.next()?.trim();
    if tstate != "tstate" {
        return None;
    }
    let last_arg: &str = arguments.next()?.trim();
    if arguments.next().is_some() {
        return None;
    }
    let token: &str = strip_mod_consts(last_arg);
    if token.starts_with("const_dict_")
        && token.bytes().all(|byte: u8| is_c_identifier_continue(byte))
    {
        Some(token.to_owned())
    } else {
        None
    }
}

fn parse_make_function_call(line: &str) -> Option<DemangledFunction> {
    let assign: usize = line.find("= MAKE_FUNCTION_")?;
    let after: &str = &line[assign + "= ".len()..];
    let symbol: &str = after.split('(').next()?;
    if !symbol.contains("$$$") {
        return None;
    }
    demangle_function(symbol)
}

fn factory_call_bindings_by_symbol(
    source: &str,
    code: &[u8],
    factories: &[FunctionFactory],
) -> Result<BTreeMap<String, Option<FactoryCallBindings>>> {
    if source.len() != code.len() || factories.is_empty() {
        return Ok(BTreeMap::new());
    }
    let temporary_constants: TemporaryConstBindings = temporary_const_bindings(source, code)?;
    let factory_by_symbol: BTreeMap<&str, &FunctionFactory> = factories
        .iter()
        .map(|factory: &FunctionFactory| (factory.factory_symbol.as_str(), factory))
        .collect();
    let marker: &[u8] = b"MAKE_FUNCTION_";
    let mut out: BTreeMap<String, Option<FactoryCallBindings>> = BTreeMap::new();
    let mut search: usize = 0usize;

    while let Some(start) = find_code_marker(code, marker, search) {
        let next_search: usize = start.saturating_add(marker.len());
        let scan_end: usize = find_code_marker(code, marker, next_search).unwrap_or(code.len());
        let Some(candidate): Option<&[u8]> = code.get(start..scan_end) else {
            break;
        };
        let open: Option<usize> = candidate
            .iter()
            .position(|byte: &u8| *byte == b'(')
            .and_then(|offset: usize| start.checked_add(offset));
        let Some(open): Option<usize> = open else {
            search = scan_end;
            continue;
        };
        let symbol: Option<&str> = source.get(start..open).map(str::trim);
        let Some(symbol): Option<&str> = symbol else {
            search = scan_end;
            continue;
        };
        let Some(factory): Option<&&FunctionFactory> = factory_by_symbol.get(symbol) else {
            search = next_search;
            continue;
        };
        let assignment_target: Option<String> =
            assignment_target_before_call_from(source, code, search, start);
        let Some(close): Option<usize> = matching_paren_with_mask_before(code, open, scan_end)
        else {
            if assignment_target.is_some() {
                record_factory_call_bindings(&mut out, symbol, None);
            }
            search = scan_end;
            continue;
        };
        if assignment_target.is_some() {
            let args: Option<Vec<String>> =
                split_top_level_args_with_mask(code, open + 1, close, MAX_C_FUNCTION_PARAMETERS);
            let candidate: Option<FactoryCallBindings> =
                direct_factory_call_target(source, code, start, close)
                    .and(args)
                    .and_then(|values: Vec<String>| {
                        factory_call_bindings(factory, &values, &temporary_constants, start)
                    });
            record_factory_call_bindings(&mut out, symbol, candidate);
        }
        search = close.saturating_add(1usize);
    }

    Ok(out)
}

fn record_factory_call_bindings(
    out: &mut BTreeMap<String, Option<FactoryCallBindings>>,
    symbol: &str,
    candidate: Option<FactoryCallBindings>,
) {
    match out.entry(symbol.to_owned()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(candidate);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if entry.get().as_ref() != candidate.as_ref() {
                entry.insert(None);
            }
        }
    }
}

fn const_assignment_value(value: &str) -> Option<String> {
    let value: &str = value.trim();
    let token: &str = strip_mod_consts(value);
    if token.starts_with("const_") && token.bytes().all(|byte: u8| is_c_identifier_continue(byte)) {
        return Some(token.to_owned());
    }
    parse_dict_copy(value)
}

fn direct_factory_call_target(
    source: &str,
    code: &[u8],
    start: usize,
    close: usize,
) -> Option<String> {
    let statement_start: usize = code[..start]
        .iter()
        .rposition(|byte: &u8| matches!(*byte, b';' | b'{' | b'}'))
        .map_or(0usize, |position: usize| position + 1);
    let assignment: DirectAssignment =
        direct_assignment_prefix(source, code, statement_start, start)?;
    if !code
        .get(assignment.assignment + 1..start)?
        .iter()
        .all(u8::is_ascii_whitespace)
        || !direct_statement_suffix(code, close, code.len())
    {
        return None;
    }
    Some(assignment.target)
}

fn factory_call_bindings(
    factory: &FunctionFactory,
    args: &[String],
    temporary_constants: &TemporaryConstBindings,
    call_start: usize,
) -> Option<FactoryCallBindings> {
    if !factory_call_is_statically_unconditional(temporary_constants, call_start) {
        return None;
    }
    let annotations_dict_const: Option<String> = match factory_parameter_const(
        factory,
        args,
        "annotations",
        temporary_constants,
        call_start,
    ) {
        FactoryParameterConst::Absent => None,
        FactoryParameterConst::Value(value) if value.starts_with("const_dict_") => Some(value),
        FactoryParameterConst::Value(_) | FactoryParameterConst::Unresolved => return None,
    };
    let defaults_const: Option<String> =
        match factory_parameter_const(factory, args, "defaults", temporary_constants, call_start) {
            FactoryParameterConst::Absent => None,
            FactoryParameterConst::Value(value) => Some(value),
            FactoryParameterConst::Unresolved => return None,
        };
    let kw_defaults_const: Option<String> = match factory_parameter_const(
        factory,
        args,
        "kw_defaults",
        temporary_constants,
        call_start,
    ) {
        FactoryParameterConst::Absent => None,
        FactoryParameterConst::Value(value) => Some(value),
        FactoryParameterConst::Unresolved => return None,
    };
    Some(FactoryCallBindings {
        annotations: annotations_dict_const,
        defaults: defaults_const,
        keyword_defaults: kw_defaults_const,
    })
}

fn factory_parameter_const(
    factory: &FunctionFactory,
    args: &[String],
    parameter: &str,
    temporary_constants: &TemporaryConstBindings,
    call_start: usize,
) -> FactoryParameterConst {
    let Some(index): Option<usize> = factory
        .creation_parameters
        .iter()
        .position(|name: &String| name == parameter)
    else {
        return FactoryParameterConst::Absent;
    };
    let Some(argument): Option<&String> = args.get(index) else {
        return FactoryParameterConst::Unresolved;
    };
    let token: &str = strip_mod_consts(argument.trim());
    if token == "NULL" {
        return FactoryParameterConst::Absent;
    }
    if token.starts_with("const_") && token.bytes().all(|byte: u8| is_c_identifier_continue(byte)) {
        return FactoryParameterConst::Value(token.to_owned());
    }
    temporary_const_before_call(temporary_constants, token, call_start).map_or(
        FactoryParameterConst::Unresolved,
        FactoryParameterConst::Value,
    )
}

fn temporary_const_bindings(source: &str, code: &[u8]) -> Result<TemporaryConstBindings> {
    if source.len() != code.len() {
        return Ok(TemporaryConstBindings::default());
    }
    let mut bindings: TemporaryConstBindings = TemporaryConstBindings {
        scopes: BTreeMap::new(),
        scope_segments: Vec::new(),
    };
    let mut scopes: Vec<TemporaryConstScope> = vec![TemporaryConstScope {
        start: 0usize,
        depth: 0usize,
        plain_block: false,
        values: BTreeMap::new(),
        control_flow: TemporaryConstControlFlow::None,
    }];
    let mut statement_start: usize = 0usize;
    let mut segment_start: usize = 0usize;
    let mut assignment_count: usize = 0usize;

    for (position, byte) in code.iter().enumerate() {
        let Some(scope): Option<&TemporaryConstScope> = scopes.last() else {
            return Ok(TemporaryConstBindings::default());
        };
        match *byte {
            b'{' => {
                append_scope_segment(&mut bindings, segment_start, position + 1usize, scope.start)?;
                if scopes.len() == MAX_TEMPORARY_CONST_SCOPES {
                    return Err(Error::CSourceComplexityExceeded {
                        resource: "temporary scope",
                        count: scopes.len().saturating_add(1usize),
                        max_count: MAX_TEMPORARY_CONST_SCOPES,
                    });
                }
                let control_flow: TemporaryConstControlFlow =
                    if scopes.last().is_some_and(|parent: &TemporaryConstScope| {
                        parent.control_flow.inherits_before(position)
                    }) || opening_brace_is_control_flow(code, position)
                    {
                        TemporaryConstControlFlow::Inherited
                    } else {
                        TemporaryConstControlFlow::None
                    };
                scopes.push(TemporaryConstScope {
                    start: position,
                    depth: scopes.len(),
                    plain_block: opening_brace_is_plain_block(code, position),
                    values: BTreeMap::new(),
                    control_flow,
                });
                statement_start = position.saturating_add(1);
                segment_start = position.saturating_add(1);
            }
            b'}' => {
                if scopes.len() <= 1usize {
                    return Ok(TemporaryConstBindings::default());
                }
                append_scope_segment(&mut bindings, segment_start, position + 1usize, scope.start)?;
                let Some(scope): Option<TemporaryConstScope> = scopes.pop() else {
                    return Ok(TemporaryConstBindings::default());
                };
                if bindings.scopes.len() == MAX_TEMPORARY_CONST_SCOPES {
                    return Err(Error::CSourceComplexityExceeded {
                        resource: "temporary scope",
                        count: bindings.scopes.len().saturating_add(1usize),
                        max_count: MAX_TEMPORARY_CONST_SCOPES,
                    });
                }
                bindings.scopes.insert(scope.start, scope);
                statement_start = position.saturating_add(1);
                segment_start = position.saturating_add(1);
            }
            b':' => {
                let Some(scope): Option<&mut TemporaryConstScope> = scopes.last_mut() else {
                    return Ok(TemporaryConstBindings::default());
                };
                scope.control_flow.mark_local(position);
            }
            b';' => {
                let Some(scope): Option<&mut TemporaryConstScope> = scopes.last_mut() else {
                    return Ok(TemporaryConstBindings::default());
                };
                if statement_contains_control_flow(code, statement_start, position) {
                    scope.control_flow.mark_local(position);
                }
                if let Some((name, value)) =
                    direct_temporary_const_assignment(source, code, statement_start, position)
                {
                    if assignment_count == MAX_TEMPORARY_CONST_ASSIGNMENTS {
                        return Err(Error::CSourceComplexityExceeded {
                            resource: "temporary constant assignment",
                            count: assignment_count.saturating_add(1usize),
                            max_count: MAX_TEMPORARY_CONST_ASSIGNMENTS,
                        });
                    }
                    let value: TemporaryConstValue =
                        value.map_or(TemporaryConstValue::Unresolved, TemporaryConstValue::Value);
                    scope
                        .values
                        .entry(name)
                        .or_default()
                        .push((position, value));
                    assignment_count += 1usize;
                }
                statement_start = position.saturating_add(1);
            }
            _ => {}
        }
    }

    if scopes.len() != 1usize {
        return Ok(TemporaryConstBindings::default());
    }
    if let Some(scope) = scopes.last() {
        append_scope_segment(&mut bindings, segment_start, code.len(), scope.start)?;
    }
    while let Some(scope) = scopes.pop() {
        if bindings.scopes.len() == MAX_TEMPORARY_CONST_SCOPES {
            return Err(Error::CSourceComplexityExceeded {
                resource: "temporary scope",
                count: bindings.scopes.len().saturating_add(1usize),
                max_count: MAX_TEMPORARY_CONST_SCOPES,
            });
        }
        bindings.scopes.insert(scope.start, scope);
    }
    Ok(bindings)
}

fn append_scope_segment(
    bindings: &mut TemporaryConstBindings,
    start: usize,
    end: usize,
    scope_start: usize,
) -> Result<()> {
    if start < end {
        if bindings.scope_segments.len() == MAX_TEMPORARY_CONST_SCOPE_SEGMENTS {
            return Err(Error::CSourceComplexityExceeded {
                resource: "temporary scope segment",
                count: bindings.scope_segments.len().saturating_add(1usize),
                max_count: MAX_TEMPORARY_CONST_SCOPE_SEGMENTS,
            });
        }
        bindings.scope_segments.push(TemporaryConstScopeSegment {
            start,
            end,
            scope_start,
        });
    }
    Ok(())
}

fn opening_brace_is_control_flow(code: &[u8], brace: usize) -> bool {
    let statement_start: usize = code[..brace]
        .iter()
        .rposition(|byte: &u8| matches!(*byte, b';' | b'{' | b'}'))
        .map_or(0usize, |position: usize| position.saturating_add(1));
    statement_contains_control_flow(code, statement_start, brace)
}

fn opening_brace_is_plain_block(code: &[u8], brace: usize) -> bool {
    let statement_start: usize = code[..brace]
        .iter()
        .rposition(|byte: &u8| matches!(*byte, b';' | b'{' | b'}'))
        .map_or(0usize, |position: usize| position.saturating_add(1));
    let prefix: &[u8] = &code[statement_start..brace];
    if prefix.iter().all(u8::is_ascii_whitespace) {
        return true;
    }
    let Some(start): Option<usize> = prefix
        .iter()
        .position(|byte: &u8| !byte.is_ascii_whitespace())
    else {
        return false;
    };
    let Some(end): Option<usize> = prefix
        .iter()
        .rposition(|byte: &u8| !byte.is_ascii_whitespace())
    else {
        return false;
    };
    let label: &[u8] = &prefix[start..=end];
    label.strip_suffix(b":").is_some_and(|name: &[u8]| {
        name.starts_with(b"frame_")
            && name.len() > b"frame_".len()
            && name.iter().all(|byte: &u8| is_c_identifier_continue(*byte))
    })
}

fn statement_contains_control_flow(code: &[u8], start: usize, end: usize) -> bool {
    const CONTROL_FLOW_MARKERS: [&[u8]; 11] = [
        b"if",
        b"else",
        b"switch",
        b"for",
        b"while",
        b"do",
        b"goto",
        b"return",
        b"break",
        b"continue",
        b"case",
    ];
    CONTROL_FLOW_MARKERS
        .iter()
        .any(|marker: &&[u8]| code_keyword_in_range(code, marker, start, end))
}

fn code_keyword_in_range(code: &[u8], marker: &[u8], start: usize, end: usize) -> bool {
    if marker.is_empty() || start > end || end > code.len() || marker.len() > end - start {
        return false;
    }
    let last_start: usize = end - marker.len();
    for position in start..=last_start {
        if code.get(position..position + marker.len()) != Some(marker) {
            continue;
        }
        let previous: Option<u8> = position
            .checked_sub(1)
            .and_then(|index: usize| code.get(index))
            .copied();
        let next: Option<u8> = position
            .checked_add(marker.len())
            .and_then(|index: usize| code.get(index))
            .copied();
        if !previous.is_some_and(is_c_identifier_continue)
            && !next.is_some_and(is_c_identifier_continue)
        {
            return true;
        }
    }
    false
}

fn temporary_const_before_call(
    bindings: &TemporaryConstBindings,
    token: &str,
    call_start: usize,
) -> Option<String> {
    if !factory_call_is_statically_unconditional(bindings, call_start) {
        return None;
    }
    let scope_start: usize = scope_start_at(bindings, call_start)?;
    let scope: &TemporaryConstScope = bindings.scopes.get(&scope_start)?;
    let values: &Vec<(usize, TemporaryConstValue)> = scope.values.get(token)?;
    let insertion: usize = values
        .partition_point(|(position, _): &(usize, TemporaryConstValue)| *position < call_start);
    let previous: usize = insertion.checked_sub(1)?;
    match &values.get(previous)?.1 {
        TemporaryConstValue::Value(value) => Some(value.clone()),
        TemporaryConstValue::Unresolved => None,
    }
}

fn factory_call_is_statically_unconditional(
    bindings: &TemporaryConstBindings,
    call_start: usize,
) -> bool {
    let Some(scope_start): Option<usize> = scope_start_at(bindings, call_start) else {
        return false;
    };
    let Some(scope): Option<&TemporaryConstScope> = bindings.scopes.get(&scope_start) else {
        return false;
    };
    scope.depth == 2usize && scope.plain_block && !scope.control_flow.applies_before(call_start)
}

fn scope_start_at(bindings: &TemporaryConstBindings, position: usize) -> Option<usize> {
    let insertion: usize = bindings
        .scope_segments
        .partition_point(|segment: &TemporaryConstScopeSegment| segment.start <= position);
    let previous: usize = insertion.checked_sub(1usize)?;
    let segment: &TemporaryConstScopeSegment = bindings.scope_segments.get(previous)?;
    (position < segment.end).then_some(segment.scope_start)
}

fn direct_temporary_const_assignment(
    source: &str,
    code: &[u8],
    start: usize,
    semicolon: usize,
) -> Option<(String, Option<String>)> {
    let assignment: DirectAssignment = direct_assignment_prefix(source, code, start, semicolon)?;
    let name: String = assignment.target;
    if !name.starts_with("tmp_") {
        return None;
    }
    let value: &str = source.get(assignment.assignment + 1..semicolon)?.trim();
    Some((name, const_assignment_value(value)))
}

fn matching_paren_with_mask(code: &[u8], open: usize) -> Option<usize> {
    matching_paren_with_mask_before(code, open, code.len())
}

fn matching_paren_with_mask_before(code: &[u8], open: usize, end: usize) -> Option<usize> {
    if end > code.len() || open >= end || code.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth: i32 = 0i32;
    for (i, &b) in code.iter().enumerate().take(end).skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_args_with_mask(
    code: &[u8],
    start: usize,
    end: usize,
    max_args: usize,
) -> Option<Vec<String>> {
    if start > end || end > code.len() || max_args == 0usize {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    let mut depth: i32 = 0i32;
    let mut arg_start: usize = start;
    for position in start..end {
        match code[position] {
            b'(' | b'[' | b'{' => {
                depth += 1;
            }
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
            }
            b',' if depth == 0 => {
                if out.len() == max_args
                    || position.saturating_sub(arg_start) > MAX_C_CALL_ARGUMENT_BYTES
                {
                    return None;
                }
                let value: String = String::from_utf8_lossy(&code[arg_start..position])
                    .trim()
                    .to_owned();
                out.push(value);
                arg_start = position + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    if end.saturating_sub(arg_start) > MAX_C_CALL_ARGUMENT_BYTES {
        return None;
    }
    let value: String = String::from_utf8_lossy(&code[arg_start..end])
        .trim()
        .to_owned();
    if !value.is_empty() {
        if out.len() == max_args {
            return None;
        }
        out.push(value);
    }
    Some(out)
}

fn non_null_const(slot: &str) -> Option<String> {
    let token: &str = strip_mod_consts(slot.trim());
    token.starts_with("const_").then(|| token.to_owned())
}

fn detect_main_guard(lines: &[&str]) -> bool {
    let mut main_temp: Option<&str> = None;
    for line in lines {
        let t: &str = line.trim();
        if let Some((lhs, rhs)) = t.split_once(" = ") {
            let rhs_token: &str = strip_mod_consts(rhs.trim_end_matches(';').trim());
            if rhs_token == "const_str_plain___main__" && lhs.starts_with("tmp_cmp_expr_right") {
                main_temp = Some(lhs.trim());
            }
        }
        if let Some(temp) = main_temp
            && line.contains("RICH_COMPARE_EQ")
            && line.contains(temp)
        {
            return true;
        }
    }
    false
}

pub fn parse_c_module(source: &str) -> Result<CModuleStructure> {
    parse_c_module_with_optional_python_abi(source, None)
}

pub fn parse_c_module_with_python_abi(
    source: &str,
    python_abi: (u8, u8),
) -> Result<CModuleStructure> {
    parse_c_module_with_optional_python_abi(source, Some(python_abi))
}

pub(crate) fn parse_c_module_with_optional_python_abi(
    source: &str,
    python_abi: Option<(u8, u8)>,
) -> Result<CModuleStructure> {
    validate_c_source(source)?;
    let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(source, python_abi);
    parse_c_module_with_mask(source, code, python_abi)
}

fn parse_c_module_with_mask(
    source: &str,
    code: Vec<u8>,
    python_abi: Option<(u8, u8)>,
) -> Result<CModuleStructure> {
    let masked_source: &str = std::str::from_utf8(&code)
        .map_err(|_| Error::SurfaceBinding("C lexical mask was not valid UTF-8".to_owned()))?;
    let lines: Vec<&str> = masked_source.lines().collect();

    let module_name: String = parse_module_name(masked_source).ok_or_else(|| {
        Error::SurfaceBinding(
            "no `PyObject *module_<name>;` declaration found; not a Nuitka module.<name>.c"
                .to_owned(),
        )
    })?;
    let factories: Vec<FunctionFactory> = parse_function_factories(source, &code)?;
    let factory_names: BTreeMap<String, String> = factory_names_by_code_object(&factories);
    let parsed_code_objects: ParsedCodeObjects = parse_code_objects(source, &code, &factory_names)?;
    let factories: Vec<FunctionFactory> = validated_factories(&factories, &parsed_code_objects);
    let code_objects: Vec<CCodeObject> = parsed_code_objects.code_objects;
    let code_object_symbols: BTreeMap<String, String> = impl_code_object_symbols(&factories);
    let impl_bodies: Vec<CImplBody> = parse_impl_bodies(&lines, &code_object_symbols)?;
    let const_returns: Vec<CConstReturn> = parse_const_returns(&factories);
    let mut wirings: Vec<CFunctionWiring> = parse_wirings(&lines)?;
    let factory_bindings: BTreeMap<String, Option<FactoryCallBindings>> =
        factory_call_bindings_by_symbol(source, &code, &factories)?;
    let factory_by_identity: BTreeMap<FunctionIdentity, Option<&FunctionFactory>> =
        factories_by_identity(&factories);

    for wiring in &mut wirings {
        let factory: Option<&FunctionFactory> =
            factory_identity_for_wiring(wiring).and_then(|identity: FunctionIdentity| {
                factory_by_identity.get(&identity).copied().flatten()
            });
        if let Some(factory) = factory {
            if let Some(defaults) = &factory.defaults_const {
                wiring.defaults_const = Some(defaults.clone());
            }
            if let Some(defaults) = &factory.kw_defaults_const {
                wiring.kw_defaults_const = Some(defaults.clone());
            }
            if let Some(doc) = &factory.doc_const {
                wiring.doc_const = Some(doc.clone());
            }
            if let Some(Some(call)) = factory_bindings.get(&factory.factory_symbol) {
                if let Some(annotations) = &call.annotations {
                    wiring.annotations_dict_const = Some(annotations.clone());
                }
                if let Some(defaults) = &call.defaults {
                    wiring.defaults_const = Some(defaults.clone());
                }
                if let Some(defaults) = &call.keyword_defaults {
                    wiring.kw_defaults_const = Some(defaults.clone());
                }
            }
        }
    }

    let has_main_guard: bool = detect_main_guard(&lines);

    let mut notes: Vec<String> = Vec::new();
    let n_recovered: usize = impl_bodies.len() + const_returns.len();
    let n_wire: usize = wirings.len();
    if n_recovered != n_wire {
        notes.push(format!(
            "structure mismatch: {n_recovered} recoverable bodies vs {n_wire} wirings"
        ));
    }

    Ok(CModuleStructure {
        module_name,
        python_abi,
        code_objects,
        impl_bodies,
        const_returns,
        wirings,
        has_main_guard,
        notes,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use crate::limits::{MAX_C_SOURCE_BYTES, MAX_C_SOURCE_LINES, validate_c_source_size};

    use std::fmt::Write as _;
    use std::time::{Duration, Instant};

    use super::*;

    const C_SRC: &str =
        include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");

    fn parse_hello_module() -> CModuleStructure {
        parse_c_module_with_python_abi(C_SRC, (3u8, 12u8)).expect("parse")
    }

    #[test]
    fn parses_module_name() {
        let m: CModuleStructure = parse_hello_module();
        assert_eq!(m.module_name, "hello");
    }

    #[test]
    fn parses_three_impl_bodies_in_order() {
        let m: CModuleStructure = parse_hello_module();
        let names: Vec<&str> = m
            .impl_bodies
            .iter()
            .map(|b: &CImplBody| b.function_name.as_str())
            .collect();
        assert_eq!(names, vec!["greet", "fib", "main"]);
        assert_eq!(m.impl_bodies[0].params, vec!["name"]);
        assert_eq!(m.impl_bodies[1].params, vec!["n"]);
        assert!(m.impl_bodies[2].params.is_empty());
        assert!(
            m.impl_bodies
                .iter()
                .all(|body: &CImplBody| body.code_object_symbol.is_some())
        );
    }

    #[test]
    fn parses_code_objects_excluding_digest() {
        let m: CModuleStructure = parse_hello_module();
        let names: Vec<&str> = m
            .code_objects
            .iter()
            .map(|c: &CCodeObject| c.name.as_str())
            .collect();
        assert!(names.contains(&"greet"));
        assert!(names.contains(&"fib"));
        assert!(names.contains(&"main"));
        assert_eq!(m.code_objects.len(), 3);
        assert!(
            m.code_objects
                .iter()
                .all(|code: &CCodeObject| code.symbol.starts_with("code_objects_"))
        );
    }

    #[test]
    fn malformed_code_object_numbers_are_skipped() {
        let source: &str = r"
PyObject *module_m;
static PyCodeObject *codeobj_bad = MAKE_CODE_OBJECT(module_filename_obj, nope, 0, mod_consts.const_str_plain_bad, NULL, NULL, NULL, xx, yy, zz);
";
        let m: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(m.code_objects.is_empty());
    }

    #[test]
    fn wirings_bind_annotation_dicts() {
        let m: CModuleStructure = parse_hello_module();
        let greet: &CFunctionWiring = m
            .wirings
            .iter()
            .find(|w: &&CFunctionWiring| w.function_name == "greet")
            .expect("greet wiring");
        assert_eq!(
            greet.annotations_dict_const.as_deref(),
            Some("const_dict_0d747635c5b87742d1bd242db31edac3")
        );
        for w in &m.wirings {
            assert_eq!(w.defaults_const, None);
            assert_eq!(w.doc_const, None);
        }
    }

    #[test]
    fn detects_main_guard_from_real_bytes() {
        let m: CModuleStructure = parse_hello_module();
        assert!(m.has_main_guard);
    }

    #[test]
    fn self_consistency_three_each() {
        let m: CModuleStructure = parse_hello_module();
        assert_eq!(m.impl_bodies.len(), 3);
        assert_eq!(m.wirings.len(), 3);
        assert_eq!(m.code_objects.len(), 3);
        assert!(m.notes.is_empty());
    }

    #[test]
    fn ignores_factory_markers_inside_comments_and_strings() {
        let source: &str = r#"
PyObject *module_m;
/*
static PyObject *MAKE_FUNCTION_m$$$function__1_fake(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_fake, NULL, code_objects_fake, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
*/
static const char *factory_text = "static PyObject *MAKE_FUNCTION_m$$$function__2_text(PyThreadState *tstate, PyObject *annotations) { Nuitka_Function_EnableConstReturnTrue(result); }";
"#;
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn ignores_factory_markers_after_escaped_quoted_line_splices() {
        let source: &str = r#"
PyObject *module_m;
code_objects_fake = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_fake, mod_consts.const_str_plain_fake, NULL, NULL, 0, 0, 0);
static const char *text = "\\
" static PyObject *MAKE_FUNCTION_m$$$function__1_fake(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_fake, NULL, code_objects_fake, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}";
"#;
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn ignores_factory_markers_after_spliced_line_comments() {
        let source: &str = r"
PyObject *module_m;
// \
static PyObject *MAKE_FUNCTION_m$$$function__1_fake(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_fake, NULL, code_objects_fake, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn ignores_factory_markers_in_inactive_preprocessor_branches() {
        let source: &str = r"
PyObject *module_m;
#if 0
static PyObject *MAKE_FUNCTION_m$$$function__1_fake(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_fake, NULL, code_objects_fake, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
#endif
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn ignores_factory_markers_in_spliced_inactive_preprocessor_branches() {
        let source: &str = r"
PyObject *module_m;
#if 1 \
    && 0
static PyObject *MAKE_FUNCTION_m$$$function__1_fake(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_fake, NULL, code_objects_fake, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
#endif
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn recognizes_preprocessor_keywords_split_by_splices() {
        let source: &str = r"
PyObject *module_m;
#i\
f 0
static PyObject *MAKE_FUNCTION_m$$$function__1_fake(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_fake, NULL, code_objects_fake, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
#e\
ndif
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn multiline_block_comments_preserve_preprocessor_line_boundaries() {
        let source: &str = r"
PyObject *module_m;
int sentinel; /* first line
second line */#if 0
code_objects_fake = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_fake, mod_consts.const_str_plain_fake, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_fake(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_fake, NULL, code_objects_fake, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
#endif
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn truncated_function_factory_is_not_recovered_as_a_constant_return() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn binds_constant_return_to_the_returned_factory_object() {
        let source: &str = r"
PyObject *module_m;
code_objects_helper = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
code_objects_result = MAKE_CODE_OBJECT(module_filename_obj, 2, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *helper = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_helper, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnGeneric(helper, mod_consts.const_false);
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_result, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnGeneric(result, mod_consts.const_true);
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert_eq!(parsed.const_returns.len(), 1);
        assert_eq!(parsed.const_returns[0].value_const, "const_true");
        assert_eq!(
            parsed.const_returns[0].code_object_symbol,
            "code_objects_result"
        );
    }

    #[test]
    fn rejects_constant_return_factory_when_the_returned_object_is_reassigned() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    result = replacement;
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn rejects_constant_return_factory_when_the_returned_object_is_mutated() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    Py_SETREF(result, replacement);
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn rejects_conditional_factory_construction() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0) ? first : second;
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn rejects_conditional_const_return_enablement() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    if (enabled) Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn rejects_factory_with_only_nested_return() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    if (enabled) {
        return (PyObject *)result;
    }
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn rejects_factory_with_unbraced_conditional_return() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    if (enabled) return (PyObject *)result;
    abort();
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn rejects_factory_with_control_transfer_that_bypasses_const_return_enablement() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    if (enabled) goto returned;
    Nuitka_Function_EnableConstReturnTrue(result);
returned:
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn unresolved_second_factory_call_clears_prior_default_binding() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *defaults, PyObject *kw_defaults, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, defaults, kw_defaults, annotations, module_m, NULL, NULL, 0);
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
    PyObject *tmp_defaults = mod_consts.const_tuple_empty;
    tmp_assign_source_1 = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults, NULL, NULL);
    tmp_assign_source_2 = MAKE_FUNCTION_m$$$function__1_f(tstate, unresolved_defaults, NULL, NULL);
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        let wirings: Vec<&CFunctionWiring> = parsed
            .wirings
            .iter()
            .filter(|wiring: &&CFunctionWiring| wiring.function_name == "f")
            .collect();
        assert_eq!(wirings.len(), 2);
        assert!(
            wirings
                .iter()
                .all(|wiring: &&CFunctionWiring| wiring.defaults_const.is_none())
        );
    }

    #[test]
    fn direct_temporary_defaults_are_bound_within_their_lexical_block() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *defaults, PyObject *kw_defaults, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, defaults, kw_defaults, annotations, module_m, NULL, NULL, 0);
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
    {
        PyObject *tmp_defaults;
        PyObject *tmp_kw_defaults;
        PyObject *tmp_assign_source;
        tmp_defaults = mod_consts.const_tuple_empty;
        tmp_kw_defaults = DICT_COPY(tstate, mod_consts.const_dict_empty);
        tmp_assign_source = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults, tmp_kw_defaults, NULL);
    }
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        let wiring: &CFunctionWiring = parsed
            .wirings
            .iter()
            .find(|wiring: &&CFunctionWiring| wiring.function_name == "f")
            .expect("wiring");
        assert_eq!(wiring.defaults_const.as_deref(), Some("const_tuple_empty"));
        assert_eq!(
            wiring.kw_defaults_const.as_deref(),
            Some("const_dict_empty")
        );
    }

    #[test]
    fn local_keyword_defaults_remain_bound_after_a_nuitka_frame_label() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_enabled_tuple, NULL, 0, 1, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *kw_defaults) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, kw_defaults, NULL, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
    goto frame_no_exception;
frame_no_exception:
    {
        PyObject *tmp_assign_source;
        PyObject *tmp_kw_defaults;
        tmp_kw_defaults = DICT_COPY(tstate, mod_consts.const_dict_empty);
        tmp_assign_source = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_kw_defaults);
    }
}
";
        let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(source, None);
        let call_start: usize = find_code_marker(
            &code,
            b"MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_kw_defaults)",
            0usize,
        )
        .expect("factory call");
        let temporary_constants: TemporaryConstBindings =
            temporary_const_bindings(source, &code).expect("temporary constants");
        assert!(factory_call_is_statically_unconditional(
            &temporary_constants,
            call_start
        ));
        assert_eq!(
            temporary_const_before_call(&temporary_constants, "tmp_kw_defaults", call_start),
            Some("const_dict_empty".to_owned())
        );
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        let wiring: &CFunctionWiring = parsed
            .wirings
            .iter()
            .find(|wiring: &&CFunctionWiring| wiring.function_name == "f")
            .expect("wiring");
        assert_eq!(
            wiring.kw_defaults_const.as_deref(),
            Some("const_dict_empty")
        );
    }

    #[test]
    fn inherited_frame_scope_with_internal_control_flow_does_not_bind_defaults() {
        let source: &str = r"
static void modulecode_m(PyThreadState *tstate) {
    goto frame_no_exception;
frame_no_exception:
    {
        tmp_defaults = mod_consts.const_tuple_empty;
        goto make_function;
make_function:
        tmp_assign_source = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults);
    }
}
";
        let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(source, None);
        let call_start: usize = find_code_marker(
            &code,
            b"MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults)",
            0usize,
        )
        .expect("factory call");
        let bindings: TemporaryConstBindings =
            temporary_const_bindings(source, &code).expect("temporary constants");
        assert!(!factory_call_is_statically_unconditional(
            &bindings, call_start
        ));
        assert!(temporary_const_before_call(&bindings, "tmp_defaults", call_start).is_none());
    }

    #[test]
    fn deep_copy_keyword_defaults_bind_to_the_source_dict() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, mod_consts.const_tuple_str_plain_enabled_tuple, NULL, 0, 1, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *kw_defaults) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, kw_defaults, NULL, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
    {
        PyObject *tmp_assign_source;
        PyObject *tmp_kw_defaults;
        tmp_kw_defaults = DEEP_COPY_DICT(tstate, mod_consts.const_dict_0123456789abcdef0123456789abcdef);
        tmp_assign_source = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_kw_defaults);
    }
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        let wiring: &CFunctionWiring = parsed
            .wirings
            .iter()
            .find(|wiring: &&CFunctionWiring| wiring.function_name == "f")
            .expect("wiring");
        assert_eq!(
            wiring.kw_defaults_const.as_deref(),
            Some("const_dict_0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn dictionary_copy_matcher_requires_exact_nuitka_call_shapes() {
        let digest: &str = "const_dict_0123456789abcdef0123456789abcdef";
        for callee in ["DICT_COPY", "DEEP_COPY_DICT"] {
            assert_eq!(
                parse_dict_copy(&format!("{callee}(tstate, mod_consts.{digest})")),
                Some(digest.to_owned())
            );
        }
        for value in [
            format!("MY_DEEP_COPY_DICT(tstate, mod_consts.{digest})"),
            format!("DEEP_COPY_DICT(other_state, mod_consts.{digest})"),
            "DEEP_COPY_DICT(tstate, mod_consts.const_str_plain_not_a_dict)".to_owned(),
            format!("DEEP_COPY_DICT(tstate, mod_consts.{digest}, extra)"),
            format!("DEEP_COPY_DICT(tstate, mod_consts.{digest}) trailing"),
        ] {
            assert_eq!(
                parse_dict_copy(&value),
                None,
                "unexpected match for {value}"
            );
        }
    }

    #[test]
    fn branch_or_label_bound_temporary_defaults_are_not_bound_at_the_factory_call() {
        let conditional: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *defaults, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, defaults, NULL, annotations, module_m, NULL, NULL, 0);
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
    PyObject *tmp_defaults;
    PyObject *tmp_assign_source;
    if (enabled) {
        enabled = false;
    }
    else tmp_defaults = mod_consts.const_tuple_empty;
    tmp_assign_source = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults, NULL);
}
";
        let label: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *defaults, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, defaults, NULL, annotations, module_m, NULL, NULL, 0);
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
    PyObject *tmp_defaults;
    PyObject *tmp_assign_source;
    tmp_defaults = mod_consts.const_tuple_empty;
    goto make_function;
make_function:
    tmp_assign_source = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults, NULL);
}
";
        let branch_call: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *defaults, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, defaults, NULL, annotations, module_m, NULL, NULL, 0);
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
    if (enabled) {
        PyObject *tmp_assign_source;
        tmp_assign_source = MAKE_FUNCTION_m$$$function__1_f(tstate, mod_consts.const_tuple_empty, NULL);
    }
}
";
        for source in [conditional, label, branch_call] {
            let parsed: CModuleStructure = parse_c_module(source).expect("parse");
            let wiring: &CFunctionWiring = parsed
                .wirings
                .iter()
                .find(|wiring: &&CFunctionWiring| wiring.function_name == "f")
                .expect("wiring");
            assert!(wiring.defaults_const.is_none());
        }
    }

    #[test]
    fn unknown_python_version_branch_is_not_recovered_without_artifact_profile() {
        let source: &str = r"
PyObject *module_m;
#if PYTHON_VERSION >= 0x3e0
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
#endif
";
        let unknown: CModuleStructure = parse_c_module(source).expect("parse without profile");
        assert!(unknown.const_returns.is_empty());
        let profiled: CModuleStructure =
            parse_c_module_with_python_abi(source, (3u8, 14u8)).expect("parse profile");
        assert_eq!(profiled.const_returns.len(), 1);
        assert_eq!(profiled.python_abi, Some((3u8, 14u8)));
    }

    #[test]
    fn profiled_parse_binds_versioned_factory_annotations() {
        let source: &str = r"
PyObject *module_m;
code_objects_f = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_f, mod_consts.const_str_plain_f, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(
        impl_m$$$function__1_f,
        mod_consts.const_str_plain_f,
#if PYTHON_VERSION >= 0x300
        NULL,
#endif
        code_objects_f,
        NULL,
#if PYTHON_VERSION >= 0x300
        NULL,
        annotations,
#endif
        module_m,
        NULL,
        NULL,
        0
    );
    return (PyObject *)result;
}
static void modulecode_m(PyThreadState *tstate) {
{
    PyObject *tmp_annotations;
    PyObject *tmp_assign_source;
    tmp_annotations = DICT_COPY(tstate, mod_consts.const_dict_annotations);
    tmp_assign_source = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_annotations);
}
}
";
        let parsed: CModuleStructure =
            parse_c_module_with_python_abi(source, (3u8, 12u8)).expect("parse");
        let wiring: &CFunctionWiring = parsed
            .wirings
            .iter()
            .find(|wiring: &&CFunctionWiring| wiring.function_name == "f")
            .expect("wiring");
        assert_eq!(
            wiring.annotations_dict_const.as_deref(),
            Some("const_dict_annotations")
        );
    }

    #[test]
    fn ignores_constant_lambda_factory() {
        let source: &str = r"
PyObject *module_m;
code_objects_lambda = MAKE_CODE_OBJECT(module_filename_obj, 1, 0, mod_consts.const_str_plain_lambda, mod_consts.const_str_plain_lambda, NULL, NULL, 0, 0, 0);
static PyObject *MAKE_FUNCTION_m$$$lambda__1_lambda(PyThreadState *tstate, PyObject *annotations) {
    struct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_lambda, NULL, code_objects_lambda, NULL, NULL, annotations, module_m, NULL, NULL, 0);
    Nuitka_Function_EnableConstReturnTrue(result);
    return (PyObject *)result;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn ignores_lambda_factory_wirings() {
        let source: &str = r"
PyObject *module_m;
static void modulecode_m(PyThreadState *tstate) {
    PyObject *tmp_assign_source;
    tmp_assign_source = MAKE_FUNCTION_m$$$lambda__1_lambda(tstate);
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.wirings.is_empty());
    }

    #[test]
    fn ignores_non_function_implementation_bodies() {
        let source: &str = r"
PyObject *module_m;
static PyObject *impl_m$$$lambda__1_lambda(PyThreadState *tstate, PyObject *const *python_pars) {
    return Py_None;
}
";
        let parsed: CModuleStructure = parse_c_module(source).expect("parse");
        assert!(parsed.impl_bodies.is_empty());
    }

    #[test]
    fn factory_prototypes_are_bounded() {
        let mut source: String = String::from("PyObject *module_m;\n");
        for index in 0..10_000usize {
            writeln!(
                source,
                "static PyObject *MAKE_FUNCTION_m$$$function__{index}_f{index}(PyThreadState *tstate, PyObject *annotations);"
            )
            .expect("write prototype");
        }
        let start: Instant = Instant::now();
        let parsed: CModuleStructure = parse_c_module(&source).expect("parse");
        let elapsed: Duration = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "factory prototypes took {elapsed:?}, expected bounded parsing"
        );
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn malformed_factory_markers_are_bounded() {
        let mut source: String = String::from("PyObject *module_m;\n");
        for index in 0..10_000usize {
            writeln!(
                source,
                "static PyObject *MAKE_FUNCTION_m$$$function__{index}_f{index}(PyThreadState *tstate"
            )
            .expect("write malformed marker");
        }
        let start: Instant = Instant::now();
        let parsed: CModuleStructure = parse_c_module(&source).expect("parse");
        let elapsed: Duration = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "malformed factory markers took {elapsed:?}, expected bounded parsing"
        );
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn comma_chained_factory_marker_flood_is_linear() {
        let constructor: &str = "Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0)";
        let mut source: String = String::from(
            "static PyObject *MAKE_FUNCTION_m$$$function__1_f(PyThreadState *tstate, PyObject *annotations) {\nPyObject *noise = ",
        );
        for _ in 0usize..10_000usize {
            source.push_str(constructor);
            source.push_str(", ");
        }
        source.push_str(
            "NULL;\nstruct Nuitka_FunctionObject *result = Nuitka_Function_New(NULL, mod_consts.const_str_plain_f, NULL, code_objects_f, NULL, NULL, annotations, module_m, NULL, NULL, 0);\nreturn (PyObject *)result;\n}",
        );
        let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(&source, None);
        let start: Instant = Instant::now();
        let metadata: FactoryMetadata =
            parse_factory_metadata(&source, &code).expect("recover factory metadata");
        let elapsed: Duration = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(10),
            "comma-chained factory markers took {elapsed:?}, expected linear parsing"
        );
        assert_eq!(metadata.const_return.as_deref(), Some("const_none"));
    }

    #[test]
    fn malformed_code_object_markers_are_bounded() {
        let mut source: String = String::from("PyObject *module_m;\n");
        for index in 0..10_000usize {
            writeln!(source, "code_objects_{index} = MAKE_CODE_OBJECT(")
                .expect("write malformed code object marker");
        }
        let start: Instant = Instant::now();
        let parsed: CModuleStructure = parse_c_module(&source).expect("parse");
        let elapsed: Duration = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "malformed code object markers took {elapsed:?}, expected bounded parsing"
        );
        assert!(parsed.code_objects.is_empty());
    }

    #[test]
    fn unterminated_factory_bodies_are_bounded() {
        let mut source: String = String::from("PyObject *module_m;\n");
        for index in 0..10_000usize {
            writeln!(
                source,
                "static PyObject *MAKE_FUNCTION_m$$$function__{index}_f{index}(PyThreadState *tstate) {{"
            )
            .expect("write unterminated factory body");
        }
        let start: Instant = Instant::now();
        let parsed: CModuleStructure = parse_c_module(&source).expect("parse");
        let elapsed: Duration = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "unterminated factory bodies took {elapsed:?}, expected bounded parsing"
        );
        assert!(parsed.const_returns.is_empty());
    }

    #[test]
    fn temporary_const_scope_segments_are_compact_and_lexical() {
        let padding: String = " ".repeat(2_000_000usize);
        let source: String = format!(
            "static void modulecode_m(PyThreadState *tstate) {{\n{{\n{padding}\ntmp_defaults = mod_consts.const_tuple_empty;\ntmp_first = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults);\n}}\n{{\ntmp_second = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults);\n}}\n}}"
        );
        let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(&source, None);
        let bindings: TemporaryConstBindings =
            temporary_const_bindings(&source, &code).expect("temporary constants");
        let first: usize = find_code_marker(
            &code,
            b"MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults)",
            0usize,
        )
        .expect("first factory call");
        let second: usize = find_code_marker(
            &code,
            b"MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults)",
            first.saturating_add(1usize),
        )
        .expect("second factory call");
        assert!(bindings.scope_segments.len() <= 8usize);
        assert!(bindings.scope_segments.len() * 1_024usize < source.len());
        assert_eq!(
            temporary_const_before_call(&bindings, "tmp_defaults", first).as_deref(),
            Some("const_tuple_empty")
        );
        assert!(temporary_const_before_call(&bindings, "tmp_defaults", second).is_none());
    }

    #[test]
    fn incomplete_scope_metadata_is_not_used() {
        let source: &str = r"
static void modulecode_m(PyThreadState *tstate) {
    {
        tmp_defaults = mod_consts.const_tuple_empty;
        tmp_call = MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults);
";
        let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(source, None);
        let bindings: TemporaryConstBindings =
            temporary_const_bindings(source, &code).expect("temporary constants");
        let call: usize = find_code_marker(
            &code,
            b"MAKE_FUNCTION_m$$$function__1_f(tstate, tmp_defaults)",
            0usize,
        )
        .expect("factory call");
        assert!(bindings.scope_segments.is_empty());
        assert!(temporary_const_before_call(&bindings, "tmp_defaults", call).is_none());
    }

    #[test]
    fn c_source_size_cap_rejects_before_lexical_masking() {
        assert!(validate_c_source_size(MAX_C_SOURCE_BYTES).is_ok());
        assert!(matches!(
            validate_c_source_size(MAX_C_SOURCE_BYTES.saturating_add(1usize)),
            Err(Error::CSourceTooLarge { bytes, max_bytes })
                if bytes == MAX_C_SOURCE_BYTES.saturating_add(1usize)
                    && max_bytes == MAX_C_SOURCE_BYTES
        ));
    }

    #[test]
    fn c_source_line_cap_rejects_before_line_index_allocation() {
        let exact_limit: String = "\n".repeat(MAX_C_SOURCE_LINES);
        assert!(validate_c_source(&exact_limit).is_ok());
        let source: String = "\n".repeat(MAX_C_SOURCE_LINES.saturating_add(1usize));
        assert!(matches!(
            validate_c_source(&source),
            Err(Error::CSourceComplexityExceeded {
                resource: "line",
                count,
                max_count,
            }) if count == MAX_C_SOURCE_LINES.saturating_add(1usize)
                && max_count == MAX_C_SOURCE_LINES
        ));
    }

    #[test]
    fn fixed_arity_call_split_rejects_comma_flood() {
        let code: Vec<u8> = ","
            .repeat(MAKE_CODE_OBJECT_SLOT_COUNT + 1usize)
            .into_bytes();
        assert!(
            split_top_level_args_with_mask(&code, 0usize, code.len(), MAKE_CODE_OBJECT_SLOT_COUNT,)
                .is_none()
        );
    }

    #[test]
    fn temporary_scope_cap_rejects_excessive_brace_scopes() {
        let source: String = format!(
            "{}{}",
            "{".repeat(MAX_TEMPORARY_CONST_SCOPES + 1usize),
            "}".repeat(MAX_TEMPORARY_CONST_SCOPES + 1usize),
        );
        let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(&source, None);
        assert!(matches!(
            temporary_const_bindings(&source, &code),
            Err(Error::CSourceComplexityExceeded {
                resource: "temporary scope",
                count,
                max_count,
            }) if count > max_count && max_count == MAX_TEMPORARY_CONST_SCOPES
        ));
    }

    #[test]
    fn temporary_scope_segment_cap_rejects_repeated_brace_pairs() {
        let source: String = "{}".repeat(MAX_TEMPORARY_CONST_SCOPES + 1usize);
        let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(&source, None);
        assert!(matches!(
            temporary_const_bindings(&source, &code),
            Err(Error::CSourceComplexityExceeded {
                resource: "temporary scope segment",
                count,
                max_count,
            }) if count > max_count && max_count == MAX_TEMPORARY_CONST_SCOPE_SEGMENTS
        ));
    }

    #[test]
    fn factory_binding_scan_skips_scope_analysis_without_factories() {
        let source: String = "{}".repeat(MAX_TEMPORARY_CONST_SCOPES + 1usize);
        let code: Vec<u8> = c_code_mask_with_nuitka_python_abi(&source, None);
        let bindings: BTreeMap<String, Option<FactoryCallBindings>> =
            factory_call_bindings_by_symbol(&source, &code, &[]).expect("empty factory scan");
        assert!(bindings.is_empty());
    }

    #[test]
    fn prior_module_json_without_const_returns_deserializes() {
        let prior: &str = r#"{
            "module_name": "m",
            "code_objects": [],
            "impl_bodies": [],
            "wirings": [],
            "has_main_guard": false,
            "notes": []
        }"#;
        let parsed: CModuleStructure = serde_json::from_str(prior).expect("deserialize");
        assert!(parsed.const_returns.is_empty());
    }
}
