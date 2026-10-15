use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use ruff_python_ast::comparable::ComparableExpr;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{
    Expr, ExprCall, ExprName, ModModule, Number, Parameters, PySourceType, Stmt, StmtAssign,
    StmtClassDef, StmtFor, StmtFunctionDef, StmtIf,
};
use ruff_python_parser::{Mode, Parsed, lexer, parse_module, parse_unchecked_source};
use ruff_text_size::Ranged;

use super::render_str_literal;
use crate::pyint::{IntText, parse_int};

pub(crate) const LOADER_VERSION: &str = "Version: 0.1.1";
const MAX_LAYERS: usize = 8;
const MAX_KEYS: u64 = 100_000;
const MAX_CHUNKS: usize = 65_536;
const MAX_CIPHER_BYTES: usize = 32 * 1024 * 1024;
const ENGINE_CLASS: &str = "Engine";
const ENGINE_METHODS: [&str; 5] = ["__init__", "Intake", "Compression", "Combustion", "Exhaust"];
const PRELUDE_BUILTINS: [&str; 4] = ["enumerate", "globals", "len", "range"];
const TOOL_PREFIX: &str = "pass;";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EngineRefusal {
    #[error(
        "no Manglify {LOADER_VERSION} Engine loader (banner, payload table, key loop, trigger)"
    )]
    NotEngine,
    #[error("the loader runs a top-level statement the Engine model does not cover")]
    OuterStatement,
    #[error("the payload table is malformed: {0}")]
    Table(&'static str),
    #[error("the key loop spans {0} keys, above the {MAX_KEYS} bound")]
    KeyRange(u64),
    #[error(
        "no key in {start}..{end} decodes the payload to Python that passes the loader's integrity check"
    )]
    NoKey { start: u64, end: u64 },
    #[error("keys {0:?} all decode to an integrity-checked payload")]
    AmbiguousKeys(Vec<u64>),
    #[error("key {0} decodes to Python whose first statement may run without raising")]
    UnprovenDecoy(u64),
    #[error("key {0} decodes through a character the decoder model does not cover")]
    Unmodeled(u64),
    #[error("more than {MAX_LAYERS} nested Engine layers")]
    LayerLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnginePeel {
    pub(crate) source: String,
    pub(crate) keys: Vec<u64>,
    pub(crate) decoys: usize,
    pub(crate) uncompilable_layers: usize,
}

pub(crate) fn peel_engine(text: &str) -> Result<EnginePeel, EngineRefusal> {
    let mut current: String = text.to_owned();
    let mut peel: EnginePeel = EnginePeel {
        source: String::new(),
        keys: Vec::new(),
        decoys: 0,
        uncompilable_layers: 0,
    };
    for _ in 0..MAX_LAYERS {
        let loader: Loader = match Loader::read(&current) {
            Ok(loader) => loader,
            Err(EngineRefusal::NotEngine) if !peel.keys.is_empty() => {
                peel.source = current;
                return Ok(peel);
            }
            Err(refusal) => return Err(refusal),
        };
        let layer: Layer = loader.unlock()?;
        peel.keys.push(layer.key);
        peel.decoys += layer.decoys;
        peel.uncompilable_layers += usize::from(loader.syntax_errors);
        current = layer.payload;
    }
    if matches!(Loader::read(&current), Err(EngineRefusal::NotEngine)) {
        peel.source = current;
        return Ok(peel);
    }
    Err(EngineRefusal::LayerLimit)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkMode {
    Hex,
    Decimal,
    Binary,
    Rot13,
    Atbash,
}

impl ChunkMode {
    const fn from_key_digit(digit: u8) -> Option<Self> {
        match digit {
            b'1' => Some(Self::Hex),
            b'2' => Some(Self::Decimal),
            b'3' => Some(Self::Binary),
            b'4' => Some(Self::Rot13),
            b'5' => Some(Self::Atbash),
            _ => None,
        }
    }

    const fn rejects_cheaply(self) -> bool {
        matches!(self, Self::Hex | Self::Decimal | Self::Binary)
    }
}

#[derive(Debug, Clone)]
struct Chunk {
    mode: ChunkMode,
    cipher: Vec<u8>,
}

#[derive(Debug)]
struct Loader {
    banner_name: String,
    banner: Vec<String>,
    chunks: Vec<Chunk>,
    keys: Range<u64>,
    names: BTreeSet<String>,
    imported_modules: BTreeSet<String>,
    syntax_errors: bool,
}

#[derive(Debug)]
struct Layer {
    payload: String,
    key: u64,
    decoys: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Raises,
    Unmodeled,
}

#[derive(Debug)]
enum Candidate {
    Payload(String),
    Decoy(Option<String>),
    Unproven,
}

impl Loader {
    fn read(text: &str) -> Result<Self, EngineRefusal> {
        let parsed: Parsed<ModModule> = parse_unchecked_source(text, PySourceType::Python);
        let body: &[Stmt] = &parsed.syntax().body;
        let (banner_name, banner): (String, Vec<String>) = body
            .first()
            .and_then(banner_assignment)
            .ok_or(EngineRefusal::NotEngine)?;
        if !banner.iter().any(|line: &String| line == LOADER_VERSION) {
            return Err(EngineRefusal::NotEngine);
        }
        let engine: &StmtClassDef = body
            .iter()
            .find_map(|stmt: &Stmt| match stmt {
                Stmt::ClassDef(class) if class.name.as_str() == ENGINE_CLASS => Some(class),
                _ => None,
            })
            .ok_or(EngineRefusal::NotEngine)?;
        let aliases: BTreeMap<&str, &str> = builtin_aliases(body);
        let keys: Range<u64> = intake_range(engine, &aliases).ok_or(EngineRefusal::NotEngine)?;
        if !body.last().is_some_and(instantiates_engine) {
            return Err(EngineRefusal::NotEngine);
        }
        let tables: Vec<&Expr> = body.iter().filter_map(payload_table).collect();
        let [table] = tables.as_slice() else {
            return Err(EngineRefusal::NotEngine);
        };
        let chunks: Vec<Chunk> = read_chunks(table)?;
        let syntax_errors: bool = parsed.has_invalid_syntax();
        let bound: BTreeSet<&str> = module_bindings(body);
        let shadowed: bool = PRELUDE_BUILTINS
            .iter()
            .copied()
            .chain(aliases.values().copied())
            .any(|builtin: &str| bound.contains(builtin));
        let middle: &[Stmt] = body
            .get(1..body.len().saturating_sub(1))
            .unwrap_or_default();
        if shadowed
            || (!syntax_errors
                && !middle
                    .iter()
                    .all(|stmt: &Stmt| loader_statement(stmt, table)))
        {
            return Err(EngineRefusal::OuterStatement);
        }
        if keys.end.saturating_sub(keys.start) > MAX_KEYS {
            return Err(EngineRefusal::KeyRange(keys.end - keys.start));
        }
        Ok(Self {
            banner_name,
            banner,
            chunks,
            keys,
            names: name_tokens(text, &parsed),
            imported_modules: imported_modules(body),
            syntax_errors,
        })
    }

    fn unlock(&self) -> Result<Layer, EngineRefusal> {
        let mut order: Vec<usize> = (0..self.chunks.len()).collect();
        order.sort_by_key(|index: &usize| !self.chunks[*index].mode.rejects_cheaply());
        let mut payloads: Vec<(u64, String)> = Vec::new();
        let mut decoys: Vec<(u64, Option<String>)> = Vec::new();
        for key in self.keys.clone() {
            match self.try_key(key, &order) {
                Ok(Some(Candidate::Payload(payload))) => payloads.push((key, payload)),
                Ok(Some(Candidate::Decoy(name))) => decoys.push((key, name)),
                Ok(Some(Candidate::Unproven)) => return Err(EngineRefusal::UnprovenDecoy(key)),
                Ok(None) | Err(Fault::Raises) => {}
                Err(Fault::Unmodeled) => return Err(EngineRefusal::Unmodeled(key)),
            }
        }
        let (key, payload): (u64, String) = match payloads.len() {
            0 => {
                return Err(EngineRefusal::NoKey {
                    start: self.keys.start,
                    end: self.keys.end,
                });
            }
            1 => payloads.swap_remove(0),
            _ => {
                return Err(EngineRefusal::AmbiguousKeys(
                    payloads
                        .iter()
                        .map(|(key, _): &(u64, String)| *key)
                        .collect(),
                ));
            }
        };
        let payload_names: BTreeSet<String> = parse_module(&payload)
            .map(|parsed: Parsed<ModModule>| name_tokens(&payload, &parsed))
            .unwrap_or_default();
        if let Some((decoy, _)) = decoys.iter().find(|(_, name): &&(u64, Option<String>)| {
            name.as_ref()
                .is_some_and(|name: &String| payload_names.contains(name))
        }) {
            return Err(EngineRefusal::UnprovenDecoy(*decoy));
        }
        if !self.syntax_errors && !self.imports_covered_by(&payload) {
            return Err(EngineRefusal::OuterStatement);
        }
        Ok(Layer {
            payload,
            key,
            decoys: decoys.len(),
        })
    }

    fn imports_covered_by(&self, payload: &str) -> bool {
        let Ok(parsed) = parse_module(payload) else {
            return false;
        };
        let inner: BTreeSet<String> = imported_modules(&parsed.syntax().body);
        self.imported_modules.is_subset(&inner)
    }

    fn try_key(&self, key: u64, order: &[usize]) -> Result<Option<Candidate>, Fault> {
        let key_text: String = key.to_string();
        let mut decoded: Vec<Option<String>> = vec![None; self.chunks.len()];
        for index in order {
            let chunk: &Chunk = &self.chunks[*index];
            decoded[*index] = Some(decode_chunk(chunk, key_text.as_bytes())?);
        }
        let text: String = decoded.into_iter().flatten().collect();
        if text.contains('\0') || !lexes_cleanly(&text) {
            return Ok(None);
        }
        let Ok(parsed) = parse_module(&text) else {
            return Ok(None);
        };
        if let Some(start) = self.integrity_prelude_end(&parsed) {
            let rest: &str = text[start..].trim_start_matches(['\r', '\n']);
            let program: &str = rest.strip_prefix(TOOL_PREFIX).unwrap_or(rest);
            return Ok(Some(Candidate::Payload(program.to_owned())));
        }
        let Some(first) = parsed.syntax().body.first() else {
            return Ok(Some(Candidate::Decoy(None)));
        };
        match first_loaded_name(first) {
            Some(name) if self.provably_unbound(name) => {
                Ok(Some(Candidate::Decoy(Some(name.to_owned()))))
            }
            _ => Ok(Some(Candidate::Unproven)),
        }
    }

    fn provably_unbound(&self, name: &str) -> bool {
        name.bytes().any(|byte: u8| byte.is_ascii_digit()) && !self.names.contains(name)
    }

    fn integrity_prelude_end(&self, parsed: &Parsed<ModModule>) -> Option<usize> {
        let [banner, fetched, length_check, item_check, ..] = parsed.syntax().body.as_slice()
        else {
            return None;
        };
        let (tuple_name, values): (&str, &Expr) = single_assignment(banner)?;
        let Expr::Tuple(tuple) = values else {
            return None;
        };
        let inner: Vec<&str> = tuple
            .elts
            .iter()
            .map(|elt: &Expr| match elt {
                Expr::StringLiteral(literal) => Some(literal.value.to_str()),
                _ => None,
            })
            .collect::<Option<Vec<&str>>>()?;
        if inner
            != self
                .banner
                .iter()
                .map(String::as_str)
                .collect::<Vec<&str>>()
        {
            return None;
        }
        let (fetched_name, fetch): (&str, &Expr) = single_assignment(fetched)?;
        let Stmt::If(StmtIf {
            test: length_test,
            elif_else_clauses,
            ..
        }) = length_check
        else {
            return None;
        };
        let Stmt::For(StmtFor {
            target,
            iter,
            body,
            orelse,
            is_async: false,
            ..
        }) = item_check
        else {
            return None;
        };
        let Expr::Tuple(pair) = target.as_ref() else {
            return None;
        };
        let [Expr::Name(index), Expr::Name(item)] = pair.elts.as_slice() else {
            return None;
        };
        let [
            Stmt::If(StmtIf {
                test: item_test,
                elif_else_clauses: item_else,
                ..
            }),
        ] = body.as_slice()
        else {
            return None;
        };
        if !elif_else_clauses.is_empty() || !item_else.is_empty() || !orelse.is_empty() {
            return None;
        }
        let template_text: String = format!(
            "globals().get({banner}, None)\nnot {fetched_name} or len({fetched_name}) != len({tuple_name})\nenumerate({tuple_name})\n{i} >= len({fetched_name}) or {fetched_name}[{i}] != {v}\n",
            banner = render_str_literal(&self.banner_name),
            i = index.id.as_str(),
            v = item.id.as_str(),
        );
        let template: Parsed<ModModule> = parse_module(&template_text).ok()?;
        let expected: Vec<ComparableExpr<'_>> = template
            .syntax()
            .body
            .iter()
            .map(|stmt: &Stmt| match stmt {
                Stmt::Expr(expr) => Some(ComparableExpr::from(expr.value.as_ref())),
                _ => None,
            })
            .collect::<Option<Vec<ComparableExpr<'_>>>>()?;
        let actual: [ComparableExpr<'_>; 4] = [
            ComparableExpr::from(fetch),
            ComparableExpr::from(length_test.as_ref()),
            ComparableExpr::from(iter.as_ref()),
            ComparableExpr::from(item_test.as_ref()),
        ];
        (expected.as_slice() == actual.as_slice()).then(|| item_check.end().to_usize())
    }
}

fn banner_assignment(stmt: &Stmt) -> Option<(String, Vec<String>)> {
    let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
        return None;
    };
    let [Expr::Subscript(subscript)] = targets.as_slice() else {
        return None;
    };
    let Expr::Call(ExprCall {
        func, arguments, ..
    }) = subscript.value.as_ref()
    else {
        return None;
    };
    if !is_name(func, "globals") || !arguments.is_empty() {
        return None;
    }
    let Expr::StringLiteral(name) = subscript.slice.as_ref() else {
        return None;
    };
    let Expr::Tuple(tuple) = value.as_ref() else {
        return None;
    };
    let lines: Vec<String> = tuple
        .elts
        .iter()
        .map(|elt: &Expr| match elt {
            Expr::StringLiteral(literal) => Some(literal.value.to_str().to_owned()),
            _ => None,
        })
        .collect::<Option<Vec<String>>>()?;
    Some((name.value.to_str().to_owned(), lines))
}

fn single_assignment(stmt: &Stmt) -> Option<(&str, &Expr)> {
    let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
        return None;
    };
    let [Expr::Name(target)] = targets.as_slice() else {
        return None;
    };
    Some((target.id.as_str(), value.as_ref()))
}

fn is_name(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Name(ExprName { id, .. }) if id.as_str() == name)
}

fn builtin_aliases(body: &[Stmt]) -> BTreeMap<&str, &str> {
    body.iter()
        .filter_map(single_assignment)
        .filter_map(|(alias, value): (&str, &Expr)| match value {
            Expr::Name(builtin) => Some((alias, builtin.id.as_str())),
            _ => None,
        })
        .collect()
}

fn intake_range(engine: &StmtClassDef, aliases: &BTreeMap<&str, &str>) -> Option<Range<u64>> {
    let methods: BTreeMap<&str, &StmtFunctionDef> = engine
        .body
        .iter()
        .filter_map(|stmt: &Stmt| match stmt {
            Stmt::FunctionDef(method) => Some((method.name.as_str(), method)),
            _ => None,
        })
        .collect();
    if !ENGINE_METHODS
        .iter()
        .all(|method: &&str| methods.contains_key(method))
    {
        return None;
    }
    let loops: Vec<&StmtFor> = methods["Intake"]
        .body
        .iter()
        .filter_map(|stmt: &Stmt| match stmt {
            Stmt::For(found) => Some(found),
            _ => None,
        })
        .collect();
    let [intake] = loops.as_slice() else {
        return None;
    };
    let Expr::Call(ExprCall {
        func, arguments, ..
    }) = intake.iter.as_ref()
    else {
        return None;
    };
    if !is_name(func, "range") || !arguments.keywords.is_empty() {
        return None;
    }
    let [start, end] = arguments.args.as_ref() else {
        return None;
    };
    let start: u64 = int_bound(start, aliases)?;
    let end: u64 = int_bound(end, aliases)?;
    Some(start..end.max(start))
}

fn int_bound(expr: &Expr, aliases: &BTreeMap<&str, &str>) -> Option<u64> {
    match expr {
        Expr::NumberLiteral(number) => match &number.value {
            Number::Int(int) => int.as_u64(),
            _ => None,
        },
        Expr::Call(ExprCall {
            func, arguments, ..
        }) => {
            let Expr::Name(callee) = func.as_ref() else {
                return None;
            };
            if aliases.get(callee.id.as_str()).copied() != Some("int")
                || !arguments.keywords.is_empty()
            {
                return None;
            }
            let [Expr::Call(strip)] = arguments.args.as_ref() else {
                return None;
            };
            let Expr::Attribute(attribute) = strip.func.as_ref() else {
                return None;
            };
            let Expr::StringLiteral(literal) = attribute.value.as_ref() else {
                return None;
            };
            if attribute.attr.as_str() != "strip" || !strip.arguments.is_empty() {
                return None;
            }
            let digits: &str = literal.value.to_str().trim_matches(is_python_space);
            if digits.is_empty() || !digits.bytes().all(|byte: u8| byte.is_ascii_digit()) {
                return None;
            }
            digits.parse::<u64>().ok()
        }
        _ => None,
    }
}

fn instantiates_engine(stmt: &Stmt) -> bool {
    let Stmt::Expr(statement) = stmt else {
        return false;
    };
    let call: &Expr = match statement.value.as_ref() {
        Expr::Compare(compare) if matches!(compare.left.as_ref(), Expr::Name(_)) => {
            match compare.comparators.as_ref() {
                [call] => call,
                _ => return false,
            }
        }
        other => other,
    };
    let Expr::Call(ExprCall {
        func, arguments, ..
    }) = call
    else {
        return false;
    };
    let literal_args: bool = arguments.keywords.is_empty()
        && arguments
            .args
            .iter()
            .all(|arg: &Expr| matches!(arg, Expr::StringLiteral(_)));
    literal_args && resolves_to_engine(func)
}

fn resolves_to_engine(func: &Expr) -> bool {
    match func {
        Expr::Name(name) => name.id.as_str() == ENGINE_CLASS,
        Expr::Subscript(subscript) => {
            let Expr::Tuple(choices) = subscript.value.as_ref() else {
                return false;
            };
            constant_index(subscript.slice.as_ref())
                .and_then(|index: usize| choices.elts.get(index))
                .is_some_and(|choice: &Expr| is_name(choice, ENGINE_CLASS))
        }
        _ => false,
    }
}

fn constant_index(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::NumberLiteral(number) => match &number.value {
            Number::Int(int) => int.as_usize(),
            _ => None,
        },
        Expr::Subscript(subscript) => {
            let Expr::Tuple(values) = subscript.value.as_ref() else {
                return None;
            };
            let index: usize = constant_index(subscript.slice.as_ref())?;
            constant_index(values.elts.get(index)?)
        }
        _ => None,
    }
}

fn payload_table(stmt: &Stmt) -> Option<&Expr> {
    let (_, value): (&str, &Expr) = single_assignment(stmt)?;
    let Expr::Dict(dict) = value else {
        return None;
    };
    let table: bool = !dict.items.is_empty() && dict.items.iter().all(|item| {
        matches!(&item.key, Some(Expr::NumberLiteral(key)) if matches!(key.value, Number::Int(_)))
            && matches!(item.value, Expr::StringLiteral(_))
    });
    table.then_some(value)
}

fn read_chunks(table: &Expr) -> Result<Vec<Chunk>, EngineRefusal> {
    let Expr::Dict(dict) = table else {
        return Err(EngineRefusal::NotEngine);
    };
    if dict.items.len() > MAX_CHUNKS {
        return Err(EngineRefusal::Table("too many chunks"));
    }
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut chunks: Vec<Chunk> = Vec::with_capacity(dict.items.len());
    let mut total: usize = 0;
    for item in &dict.items {
        let (Some(Expr::NumberLiteral(key)), Expr::StringLiteral(value)) = (&item.key, &item.value)
        else {
            return Err(EngineRefusal::Table(
                "a chunk is not an int key with a str value",
            ));
        };
        let Number::Int(int) = &key.value else {
            return Err(EngineRefusal::Table("a chunk key is not an int"));
        };
        let Some(key) = int.as_u64() else {
            return Err(EngineRefusal::Table("a chunk key is out of range"));
        };
        if !seen.insert(key) {
            return Err(EngineRefusal::Table("a chunk key repeats"));
        }
        let mode: ChunkMode = key
            .to_string()
            .bytes()
            .next()
            .and_then(ChunkMode::from_key_digit)
            .ok_or(EngineRefusal::Table("a chunk key names no decoder"))?;
        let hex: &str = value.value.to_str();
        total = total.saturating_add(hex.len() / 2);
        if total > MAX_CIPHER_BYTES {
            return Err(EngineRefusal::Table("the payload exceeds the size bound"));
        }
        let cipher: Vec<u8> =
            strict_hex(hex).ok_or(EngineRefusal::Table("a chunk is not plain hex"))?;
        chunks.push(Chunk { mode, cipher });
    }
    Ok(chunks)
}

fn strict_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| Some(hex_value(pair[0])? << 4 | hex_value(pair[1])?))
        .collect()
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn module_bindings(body: &[Stmt]) -> BTreeSet<&str> {
    let mut bound: BTreeSet<&str> = BTreeSet::new();
    for stmt in body {
        match stmt {
            Stmt::Assign(StmtAssign { targets, .. }) => {
                bound.extend(targets.iter().filter_map(|target: &Expr| match target {
                    Expr::Name(name) => Some(name.id.as_str()),
                    _ => None,
                }));
            }
            Stmt::FunctionDef(function) => {
                bound.insert(function.name.as_str());
            }
            Stmt::ClassDef(class) => {
                bound.insert(class.name.as_str());
            }
            Stmt::Import(import) => {
                bound.extend(import.names.iter().map(|alias| {
                    alias.asname.as_ref().map_or_else(
                        || alias.name.as_str().split('.').next().unwrap_or_default(),
                        |asname| asname.as_str(),
                    )
                }));
            }
            Stmt::ImportFrom(import) => {
                bound.extend(import.names.iter().map(|alias| {
                    alias
                        .asname
                        .as_ref()
                        .map_or_else(|| alias.name.as_str(), |asname| asname.as_str())
                }));
            }
            _ => {}
        }
    }
    bound
}

fn imported_modules(body: &[Stmt]) -> BTreeSet<String> {
    let mut modules: BTreeSet<String> = BTreeSet::new();
    for stmt in body {
        match stmt {
            Stmt::Import(import) => {
                modules.extend(import.names.iter().map(|alias| alias.name.to_string()));
            }
            Stmt::ImportFrom(import) => {
                let module: &str = import.module.as_ref().map_or("", |module| module.as_str());
                modules.insert(format!("{}{module}", ".".repeat(import.level as usize)));
            }
            _ => {}
        }
    }
    modules
}

fn loader_statement(stmt: &Stmt, table: &Expr) -> bool {
    match stmt {
        Stmt::Import(_) | Stmt::ImportFrom(_) => true,
        Stmt::Expr(expr) => matches!(expr.value.as_ref(), Expr::Name(_)),
        Stmt::Assign(_) => {
            single_assignment(stmt).is_some_and(|(target, value): (&str, &Expr)| {
                target != ENGINE_CLASS
                    && (std::ptr::eq(value, table)
                        || match value {
                            Expr::Name(_)
                            | Expr::NoneLiteral(_)
                            | Expr::BooleanLiteral(_)
                            | Expr::NumberLiteral(_)
                            | Expr::StringLiteral(_) => true,
                            Expr::Lambda(lambda) => lambda
                                .parameters
                                .as_deref()
                                .is_none_or(inert_parameters),
                            Expr::List(list) => list
                                .elts
                                .iter()
                                .all(|elt: &Expr| matches!(elt, Expr::Name(_))),
                            _ => false,
                        })
            })
        }
        Stmt::FunctionDef(function) => inert_definition(function),
        Stmt::ClassDef(class) => {
            class.name.as_str() == ENGINE_CLASS
                && class.decorator_list.is_empty()
                && class.arguments.is_none()
                && class.type_params.is_none()
                && class.body.iter().all(|member: &Stmt| {
                    matches!(member, Stmt::FunctionDef(method) if inert_definition(method))
                })
        }
        _ => false,
    }
}

fn inert_definition(function: &StmtFunctionDef) -> bool {
    function.decorator_list.is_empty()
        && function.returns.is_none()
        && function.type_params.is_none()
        && inert_parameters(&function.parameters)
}

fn inert_parameters(parameters: &Parameters) -> bool {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .all(|parameter| parameter.default.is_none() && parameter.parameter.annotation.is_none())
        && parameters
            .vararg
            .iter()
            .chain(&parameters.kwarg)
            .all(|parameter| parameter.annotation.is_none())
}

fn name_tokens(text: &str, parsed: &Parsed<ModModule>) -> BTreeSet<String> {
    parsed
        .tokens()
        .iter()
        .filter(|token| token.kind() == TokenKind::Name)
        .filter_map(|token| {
            text.get(token.range().start().to_usize()..token.range().end().to_usize())
        })
        .map(str::to_owned)
        .collect()
}

fn lexes_cleanly(text: &str) -> bool {
    let mut lexer = lexer::lex(text, Mode::Module);
    loop {
        match lexer.next_token() {
            TokenKind::EndOfFile => return true,
            TokenKind::Unknown => return false,
            _ => {}
        }
    }
}

fn first_loaded_name(stmt: &Stmt) -> Option<&str> {
    match stmt {
        Stmt::Expr(expr) => first_evaluated_name(&expr.value),
        Stmt::Assign(assign) => first_evaluated_name(&assign.value),
        Stmt::AugAssign(assign) => match assign.target.as_ref() {
            Expr::Name(name) => Some(name.id.as_str()),
            _ => None,
        },
        _ => None,
    }
}

fn first_evaluated_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::BinOp(binary) => first_evaluated_name(&binary.left),
        Expr::BoolOp(boolean) => boolean.values.first().and_then(first_evaluated_name),
        Expr::Compare(compare) => first_evaluated_name(&compare.left),
        Expr::UnaryOp(unary) => first_evaluated_name(&unary.operand),
        Expr::Call(call) => first_evaluated_name(&call.func),
        Expr::Attribute(attribute) => first_evaluated_name(&attribute.value),
        Expr::Subscript(subscript) => first_evaluated_name(&subscript.value),
        Expr::If(conditional) => first_evaluated_name(&conditional.test),
        Expr::Starred(starred) => first_evaluated_name(&starred.value),
        Expr::Tuple(tuple) => tuple.elts.first().and_then(first_evaluated_name),
        Expr::List(list) => list.elts.first().and_then(first_evaluated_name),
        Expr::Set(set) => set.elts.first().and_then(first_evaluated_name),
        _ => None,
    }
}

fn decode_chunk(chunk: &Chunk, key: &[u8]) -> Result<String, Fault> {
    let plain: Vec<u8> = chunk
        .cipher
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, mask): (&u8, &u8)| byte ^ mask)
        .collect();
    let text: String = String::from_utf8(plain).map_err(|_| Fault::Raises)?;
    match chunk.mode {
        ChunkMode::Hex => python_fromhex(&text)
            .and_then(|bytes: Vec<u8>| String::from_utf8(bytes).ok())
            .ok_or(Fault::Raises),
        ChunkMode::Decimal => text
            .split(is_python_space)
            .filter(|token: &&str| !token.is_empty())
            .map(|token: &str| python_chr_of(token, 10))
            .collect(),
        ChunkMode::Binary => {
            let chars: Vec<char> = text.chars().collect();
            chars
                .chunks(8)
                .map(|group: &[char]| {
                    let group: String = group.iter().collect();
                    python_chr_of(&group, 2)
                })
                .collect()
        }
        ChunkMode::Rot13 => Ok(text.chars().map(rot13).collect()),
        ChunkMode::Atbash => Ok(text.chars().map(atbash).collect()),
    }
}

fn python_fromhex(text: &str) -> Option<Vec<u8>> {
    let bytes: &[u8] = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 2);
    let mut index: usize = 0;
    while index < bytes.len() {
        if is_ascii_python_space(bytes[index]) {
            index += 1;
            continue;
        }
        let high: u8 = hex_value(bytes[index])?;
        let low: u8 = hex_value(*bytes.get(index + 1)?)?;
        out.push(high << 4 | low);
        index += 2;
    }
    Some(out)
}

fn python_chr_of(token: &str, radix: u32) -> Result<char, Fault> {
    let code: i128 = parse_int(token, radix).map_err(|error: IntText| match error {
        IntText::NonAscii => Fault::Unmodeled,
        IntText::Invalid | IntText::TooWide => Fault::Raises,
    })?;
    u32::try_from(code)
        .ok()
        .and_then(char::from_u32)
        .ok_or(Fault::Raises)
}

fn rot13(c: char) -> char {
    match c {
        'A'..='Z' => char::from(((c as u8 - b'A' + 13) % 26) + b'A'),
        'a'..='z' => char::from(((c as u8 - b'a' + 13) % 26) + b'a'),
        _ => c,
    }
}

fn atbash(c: char) -> char {
    match c {
        'a'..='z' => char::from(b'a' + b'z' - c as u8),
        'A'..='Z' => char::from(b'A' + b'Z' - c as u8),
        _ => c,
    }
}

const fn is_ascii_python_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

const fn is_python_space(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\u{1c}'..='\u{20}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fmt::Write;

    use super::*;

    const BANNER_NAME: &str = "B0";
    const BANNER: [&str; 4] = [
        "Manglify Obfuscator",
        LOADER_VERSION,
        "Author: ImInTheICU",
        "Github: github.com/ImInTheICU/Manglify",
    ];
    const MIXED: [ChunkMode; 5] = [
        ChunkMode::Hex,
        ChunkMode::Binary,
        ChunkMode::Decimal,
        ChunkMode::Rot13,
        ChunkMode::Atbash,
    ];
    const COMPACT: [ChunkMode; 2] = [ChunkMode::Hex, ChunkMode::Rot13];
    const PROGRAM: &str = "import math\n\ndef fact(n):\n    return 1 if n <= 1 else n * fact(n - 1)\n\nprint(fact(5), math.pi)\n";
    const COMPOUND_FIRST: &str = "def fact(n):\n    return 1\n";

    const fn mode_digit(mode: ChunkMode) -> char {
        match mode {
            ChunkMode::Hex => '1',
            ChunkMode::Decimal => '2',
            ChunkMode::Binary => '3',
            ChunkMode::Rot13 => '4',
            ChunkMode::Atbash => '5',
        }
    }

    fn encode(mode: ChunkMode, text: &str) -> String {
        match mode {
            ChunkMode::Hex => text
                .bytes()
                .fold(String::new(), |mut out: String, byte: u8| {
                    write!(out, "{byte:02x}").expect("write to String");
                    out
                }),
            ChunkMode::Decimal => text
                .chars()
                .map(|c: char| u32::from(c).to_string())
                .collect::<Vec<String>>()
                .join(" "),
            ChunkMode::Binary => text
                .chars()
                .fold(String::new(), |mut out: String, c: char| {
                    write!(out, "{:08b}", u32::from(c)).expect("write to String");
                    out
                }),
            ChunkMode::Rot13 => text.chars().map(rot13).collect(),
            ChunkMode::Atbash => text.chars().map(atbash).collect(),
        }
    }

    fn seal(plain: &str, key: u64) -> String {
        let key: String = key.to_string();
        plain.bytes().zip(key.bytes().cycle()).fold(
            String::new(),
            |mut out: String, (byte, mask): (u8, u8)| {
                write!(out, "{:02x}", byte ^ mask).expect("write to String");
                out
            },
        )
    }

    fn banner_tuple() -> String {
        BANNER
            .iter()
            .map(|line: &&str| render_str_literal(line))
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn payload(program: &str) -> String {
        format!(
            "T0 = ({banner})\n\nG0 = globals().get({name}, None)\n\nif not G0 or len(G0) != len(T0):\n    __import__('os')._exit(0)\n\nfor i0, v0 in enumerate(T0):\n    if i0 >= len(G0) or G0[i0] != v0:\n        __import__('os')._exit(0)\n\n{TOOL_PREFIX}{program}",
            banner = banner_tuple(),
            name = render_str_literal(BANNER_NAME),
        )
    }

    fn table(text: &str, key: u64, modes: &[ChunkMode]) -> String {
        let chars: Vec<char> = text.chars().collect();
        let head: usize = chars.len().min(96);
        let rest: &[char] = &chars[head..];
        let tail_size: usize = rest
            .len()
            .div_ceil(modes.len().saturating_sub(1).max(1))
            .max(1);
        std::iter::once(&chars[..head])
            .chain(rest.chunks(tail_size))
            .enumerate()
            .map(|(index, piece): (usize, &[char])| {
                let mode: ChunkMode = modes[index.min(modes.len() - 1)];
                let plain: String = piece.iter().collect();
                format!(
                    "{}{index:06}: '{}'",
                    mode_digit(mode),
                    seal(&encode(mode, &plain), key)
                )
            })
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn engine_file(
        program: &str,
        key: u64,
        keys: Range<u64>,
        modes: &[ChunkMode],
        extra: &str,
    ) -> String {
        format!(
            "globals()[{name}] = ({banner})\n\nI0 = int;T1 = {{{table}}};E0 = exec\n{extra}\nclass Engine:\n    def __init__(self, kwargs):\n        self.Intake(kwargs)\n\n    def Intake(self, spark):\n        for k in range(I0('{start}  '.strip()), I0(' {end}'.strip())):\n            try: self.Compression(k)\n            except: pass\n\n    def Compression(self, spark):\n        pass\n\n    def Combustion(self, spark):\n        pass\n\n    def Exhaust(self, spark):\n        pass\n\n(print)==(Engine, ...)[(0,1,2)[0]]('ab')\n",
            name = render_str_literal(BANNER_NAME),
            banner = banner_tuple(),
            table = table(&payload(program), key, modes),
            start = keys.start,
            end = keys.end,
        )
    }

    #[test]
    fn an_engine_file_unlocks_to_the_program_it_carries() {
        let file: String = engine_file(PROGRAM, 4721, 1000..9999, &MIXED, "");
        let peel: EnginePeel = peel_engine(&file).expect("the authored loader unlocks");
        assert_eq!(peel.source, PROGRAM);
        assert_eq!(peel.keys, vec![4721]);
        assert_eq!(peel.uncompilable_layers, 0);
    }

    #[test]
    fn nested_engine_layers_unlock_in_turn() {
        let inner: String = engine_file(PROGRAM, 1234, 1200..1300, &COMPACT, "");
        let outer: String = engine_file(&inner, 1250, 1200..1300, &COMPACT, "");
        let peel: EnginePeel = peel_engine(&outer).expect("both layers unlock");
        assert_eq!(peel.keys, vec![1250, 1234]);
        assert_eq!(peel.source, PROGRAM);
    }

    #[test]
    fn nesting_beyond_the_layer_bound_is_refused() {
        let mut file: String = PROGRAM.to_owned();
        for layer in 0..=MAX_LAYERS as u64 {
            file = engine_file(&file, 1000 + layer, 1000..1010, &COMPACT, "");
        }
        assert_eq!(peel_engine(&file), Err(EngineRefusal::LayerLimit));
    }

    #[test]
    fn a_key_loop_beyond_the_bound_is_refused() {
        let file: String = engine_file(PROGRAM, 4721, 0..MAX_KEYS + 1, &COMPACT, "");
        assert_eq!(
            peel_engine(&file),
            Err(EngineRefusal::KeyRange(MAX_KEYS + 1))
        );
    }

    #[test]
    fn a_key_outside_the_loop_never_unlocks() {
        let file: String = engine_file(PROGRAM, 4721, 1000..4721, &MIXED, "");
        assert_eq!(
            peel_engine(&file),
            Err(EngineRefusal::NoKey {
                start: 1000,
                end: 4721
            })
        );
    }

    #[test]
    fn loader_statements_with_effects_are_refused() {
        for extra in [
            "print('side effect')\n",
            "len = 1\n",
            "Engine = print\n",
            "F0 = lambda x=print(): x\n",
        ] {
            let file: String = engine_file(PROGRAM, 4721, 4700..4800, &MIXED, extra);
            assert_eq!(
                peel_engine(&file),
                Err(EngineRefusal::OuterStatement),
                "{extra}"
            );
        }
    }

    #[test]
    fn another_loader_version_is_not_modelled() {
        let file: String = engine_file(PROGRAM, 4721, 4700..4800, &MIXED, "")
            .replace(LOADER_VERSION, "Version: 0.2.0");
        assert_eq!(peel_engine(&file), Err(EngineRefusal::NotEngine));
    }

    #[test]
    fn a_payload_that_fails_the_integrity_check_never_unlocks() {
        let file: String = engine_file(PROGRAM, 4721, 4700..4800, &MIXED, "").replacen(
            "globals()['B0']",
            "globals()['B1']",
            1,
        );
        assert_eq!(peel_engine(&file), Err(EngineRefusal::UnprovenDecoy(4721)));
    }

    #[test]
    fn malformed_tables_are_refused() {
        let file: String = engine_file(PROGRAM, 4721, 4700..4800, &MIXED, "");
        let odd: String = file.replacen(": '", ": 'z", 1);
        assert_eq!(
            peel_engine(&odd),
            Err(EngineRefusal::Table("a chunk is not plain hex"))
        );
        let no_decoder: String = file.replacen("{1000000:", "{9000000:", 1);
        assert_eq!(
            peel_engine(&no_decoder),
            Err(EngineRefusal::Table("a chunk key names no decoder"))
        );
    }

    #[test]
    fn a_changed_cipher_byte_never_recovers_the_program() {
        let file: String = engine_file(PROGRAM, 4721, 4700..4800, &MIXED, "");
        let start: usize = file.find("5000004: '").expect("the atbash chunk") + 12;
        let mut bytes: Vec<u8> = file.into_bytes();
        bytes[start] = if bytes[start] == b'0' { b'1' } else { b'0' };
        let tampered: String = String::from_utf8(bytes).expect("ascii");
        assert_ne!(
            peel_engine(&tampered).map(|peel: EnginePeel| peel.source),
            Ok(PROGRAM.to_owned())
        );
    }

    #[test]
    fn a_payload_the_pass_prefix_breaks_never_unlocks() {
        let file: String = engine_file(COMPOUND_FIRST, 4721, 4700..4800, &MIXED, "");
        assert_eq!(
            peel_engine(&file),
            Err(EngineRefusal::NoKey {
                start: 4700,
                end: 4800
            })
        );
    }

    #[test]
    fn the_decoders_follow_cpython_int_and_fromhex() {
        for (token, radix, expected) in [
            ("0b_1000001", 2, Ok('A')),
            ("-0b1", 2, Err(Fault::Raises)),
            ("-0", 10, Ok('\0')),
            ("1\u{1c}", 2, Err(Fault::Raises)),
            ("0_65", 10, Ok('A')),
            ("1114112", 10, Err(Fault::Raises)),
            ("55296", 10, Err(Fault::Raises)),
            (
                "99999999999999999999999999999999999999999",
                10,
                Err(Fault::Raises),
            ),
            ("\u{661}", 10, Err(Fault::Unmodeled)),
        ] {
            assert_eq!(python_chr_of(token, radix), expected, "{token:?}");
        }
        assert_eq!(python_fromhex(" 41 42 "), Some(b"AB".to_vec()));
        assert_eq!(python_fromhex("41\u{b}42"), Some(b"AB".to_vec()));
        assert_eq!(python_fromhex("4 1"), None);
        assert_eq!(python_fromhex("41\u{1c}42"), None);
        let decimal: Chunk = Chunk {
            mode: ChunkMode::Decimal,
            cipher: b"65\x1c66".to_vec(),
        };
        assert_eq!(decode_chunk(&decimal, b"\0"), Ok("AB".to_owned()));
        let surrogate: Chunk = Chunk {
            mode: ChunkMode::Decimal,
            cipher: b"55296".to_vec(),
        };
        assert_eq!(decode_chunk(&surrogate, b"\0"), Err(Fault::Raises));
    }
}
