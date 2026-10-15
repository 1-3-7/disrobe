use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use ruff_python_ast::comparable::ComparableStmt;
use ruff_python_ast::name::Name;
use ruff_python_ast::visitor::transformer::{Transformer, walk_expr};
use ruff_python_ast::visitor::{Visitor, walk_expr as walk_ref, walk_stmt};
use ruff_python_ast::{
    AtomicNodeIndex, Expr, ExprAttribute, ExprCall, ExprContext, ExprName, Identifier, ModModule,
    Number, Operator, Stmt, StmtAssign,
};
use ruff_python_codegen::{Generator, Stylist};
use ruff_python_parser::{Parsed, parse_module};
use ruff_text_size::{Ranged, TextRange};

use crate::ast_eval::{Value, fold_constant_expr, value_to_expr};
use crate::bindings::{binding_counts, bindings};

const MAX_ROUNDS: usize = 8;
const MODULE_STATE: [&str; 9] = [
    "__annotations__",
    "__builtins__",
    "__cached__",
    "__doc__",
    "__file__",
    "__loader__",
    "__name__",
    "__package__",
    "__spec__",
];
const PYTHON_KEYWORDS: [&str; 35] = [
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PayloadFold {
    pub(crate) source: String,
    pub(crate) aliases: usize,
    pub(crate) decoded: usize,
    pub(crate) attributes: usize,
    pub(crate) helpers_dropped: usize,
    pub(crate) imports: usize,
    pub(crate) binds_names: bool,
}

pub(crate) fn fold_payload(source: &str) -> Option<PayloadFold> {
    let (mut current, aliases): (String, usize) = substitute_aliases(source)?;
    let mut decoded: usize = 0;
    let mut attributes: usize = 0;
    let mut helpers_dropped: usize = 0;
    let mut imports: usize = 0;
    for _ in 0..MAX_ROUNDS {
        let round: Round = fold_round(&current)?;
        decoded += round.decoded;
        attributes += round.attributes;
        helpers_dropped += round.dropped;
        current = round.source;
        imports += round.imports;
        if round.constants + round.decoded + round.attributes + round.dropped + round.imports == 0 {
            break;
        }
    }
    let parsed: Parsed<ModModule> = parse_module(&current).ok()?;
    let binds_names: bool = !bindings(&parsed.syntax().body).is_empty();
    Some(PayloadFold {
        source: current,
        aliases,
        decoded,
        attributes,
        helpers_dropped,
        imports,
        binds_names,
    })
}

struct Round {
    source: String,
    imports: usize,
    constants: usize,
    decoded: usize,
    attributes: usize,
    dropped: usize,
}

fn render(module: &ModModule, stylist: &Stylist<'_>) -> String {
    let mut out: String = String::new();
    for stmt in &module.body {
        out.push_str(&Generator::from(stylist).stmt(stmt));
        out.push('\n');
    }
    out
}

fn substitute_aliases(source: &str) -> Option<(String, usize)> {
    let parsed: Parsed<ModModule> = parse_module(source).ok()?;
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), source);
    let mut module: ModModule = parsed.into_syntax();
    let table: BTreeMap<String, Expr> = alias_table(module.body.first()?)?;
    let rest: &[Stmt] = &module.body[1..];
    let bound: BTreeSet<String> = bindings(rest);
    if star_import(rest) {
        return None;
    }
    let substitutable: BTreeMap<String, Expr> = table
        .iter()
        .filter(|(alias, value): &(&String, &Expr)| {
            !bound.contains(*alias)
                && match value {
                    Expr::Name(builtin) => {
                        let name: &str = builtin.id.as_str();
                        !(bound.contains(name) || MODULE_STATE.contains(&name))
                    }
                    _ => true,
                }
        })
        .map(|(alias, value): (&String, &Expr)| (alias.clone(), value.clone()))
        .collect();
    let substituter: AliasSubstituter<'_> = AliasSubstituter {
        table: &substitutable,
        replaced: Cell::new(0),
    };
    for stmt in &mut module.body[1..] {
        substituter.visit_stmt(stmt);
    }
    let still_loaded: BTreeSet<String> = loaded_names(&module.body[1..]);
    let kept: Vec<(String, Expr)> = table
        .into_iter()
        .filter(|(alias, _): &(String, Expr)| still_loaded.contains(alias))
        .collect();
    if kept.is_empty() {
        module.body.remove(0);
    } else {
        module.body[0] = alias_statement(kept, module.body[0].range());
    }
    Some((render(&module, &stylist), substituter.replaced.get()))
}

fn alias_table(stmt: &Stmt) -> Option<BTreeMap<String, Expr>> {
    let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
        return None;
    };
    let [Expr::Tuple(names)] = targets.as_slice() else {
        return None;
    };
    let Expr::Tuple(values) = value.as_ref() else {
        return None;
    };
    if names.elts.len() != values.elts.len() || names.elts.len() < 8 {
        return None;
    }
    let mut table: BTreeMap<String, Expr> = BTreeMap::new();
    for (name, value) in names.elts.iter().zip(&values.elts) {
        let Expr::Name(alias) = name else {
            return None;
        };
        if !matches!(
            value,
            Expr::Name(_)
                | Expr::NoneLiteral(_)
                | Expr::BooleanLiteral(_)
                | Expr::EllipsisLiteral(_)
        ) {
            return None;
        }
        table.insert(alias.id.to_string(), value.clone());
    }
    Some(table)
}

fn alias_statement(kept: Vec<(String, Expr)>, range: TextRange) -> Stmt {
    let (names, values): (Vec<Expr>, Vec<Expr>) = kept
        .into_iter()
        .map(|(alias, value): (String, Expr)| (name_expr(&alias, ExprContext::Store, range), value))
        .unzip();
    Stmt::Assign(StmtAssign {
        node_index: AtomicNodeIndex::default(),
        range,
        targets: vec![tuple_expr(names, ExprContext::Store, range)],
        value: Box::new(tuple_expr(values, ExprContext::Load, range)),
    })
}

fn name_expr(id: &str, ctx: ExprContext, range: TextRange) -> Expr {
    Expr::Name(ExprName {
        node_index: AtomicNodeIndex::default(),
        range,
        id: Name::new(id),
        ctx,
    })
}

fn tuple_expr(elts: Vec<Expr>, ctx: ExprContext, range: TextRange) -> Expr {
    Expr::Tuple(ruff_python_ast::ExprTuple {
        node_index: AtomicNodeIndex::default(),
        range,
        elts,
        ctx,
        parenthesized: false,
    })
}

struct AliasSubstituter<'a> {
    table: &'a BTreeMap<String, Expr>,
    replaced: Cell<usize>,
}

impl Transformer for AliasSubstituter<'_> {
    fn visit_expr(&self, expr: &mut Expr) {
        if let Expr::Name(ExprName {
            id,
            ctx: ExprContext::Load,
            range,
            ..
        }) = expr
            && let Some(value) = self.table.get(id.as_str())
        {
            let range: TextRange = *range;
            let mut replacement: Expr = value.clone();
            set_range(&mut replacement, range);
            *expr = replacement;
            self.replaced.set(self.replaced.get() + 1);
            return;
        }
        walk_expr(self, expr);
    }
}

const fn set_range(expr: &mut Expr, range: TextRange) {
    match expr {
        Expr::Name(name) => name.range = range,
        Expr::NoneLiteral(literal) => literal.range = range,
        Expr::BooleanLiteral(literal) => literal.range = range,
        Expr::EllipsisLiteral(literal) => literal.range = range,
        _ => {}
    }
}

fn fold_round(source: &str) -> Option<Round> {
    let parsed: Parsed<ModModule> = parse_module(source).ok()?;
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), source);
    let mut module: ModModule = parsed.into_syntax();
    let counts: BTreeMap<String, usize> = binding_counts(&module.body);
    let builtin = |name: &str| !counts.contains_key(name);
    let constants: ConstantFolder<'_> = ConstantFolder {
        bound: &counts,
        folded: Cell::new(0),
    };
    for stmt in &mut module.body {
        constants.visit_stmt(stmt);
    }
    let decoders: BTreeMap<String, Vec<i128>> = module
        .body
        .iter()
        .filter_map(xor_decoder)
        .filter(|(name, _): &(String, Vec<i128>)| {
            counts.get(name) == Some(&1) && builtin("bytes") && builtin("enumerate")
        })
        .collect();
    let folder: CallFolder<'_> = CallFolder {
        decoders: &decoders,
        getattr_is_builtin: builtin("getattr"),
        decoded: Cell::new(0),
        attributes: Cell::new(0),
    };
    for stmt in &mut module.body {
        folder.visit_stmt(stmt);
    }
    let helper: Option<String> = module
        .body
        .iter()
        .filter_map(import_helper)
        .find(|name: &&str| counts.get(*name) == Some(&1) && builtin("ImportError"))
        .map(str::to_owned);
    let mut imports: usize = 0;
    if builtin("__import__") {
        let mut body: Vec<Stmt> = Vec::with_capacity(module.body.len());
        for stmt in std::mem::take(&mut module.body) {
            match import_statements(&stmt, helper.as_deref()) {
                Some(statements) => {
                    imports += 1;
                    body.extend(statements);
                }
                None => body.push(stmt),
            }
        }
        module.body = body;
    }
    let loaded: BTreeSet<String> = loaded_names(&module.body);
    let before: usize = module.body.len();
    module.body.retain(|stmt: &Stmt| {
        let dead_decoder: bool = xor_decoder(stmt).is_some_and(|(name, _): (String, Vec<i128>)| {
            decoders.contains_key(&name) && !loaded.contains(&name)
        });
        let dead_helper: bool = import_helper(stmt).is_some_and(|name: &str| {
            !loaded.contains(name) && builtin("__import__") && builtin("ImportError")
        });
        !(dead_decoder || dead_helper)
    });
    Some(Round {
        source: render(&module, &stylist),
        constants: constants.folded.get(),
        decoded: folder.decoded.get(),
        attributes: folder.attributes.get(),
        dropped: before.saturating_sub(module.body.len()),
        imports,
    })
}

fn xor_decoder(stmt: &Stmt) -> Option<(String, Vec<i128>)> {
    let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
        return None;
    };
    let [Expr::Name(target)] = targets.as_slice() else {
        return None;
    };
    let Expr::Lambda(lambda) = value.as_ref() else {
        return None;
    };
    let parameters = lambda.parameters.as_deref()?;
    let [parameter] = parameters.args.as_slice() else {
        return None;
    };
    if !parameters.posonlyargs.is_empty()
        || !parameters.kwonlyargs.is_empty()
        || parameters.vararg.is_some()
        || parameters.kwarg.is_some()
        || parameter.default.is_some()
    {
        return None;
    }
    let input: &str = parameter.parameter.name.as_str();
    let call: &ExprCall = lambda.body.as_call_expr()?;
    if !is_name(&call.func, "bytes") || !call.arguments.keywords.is_empty() {
        return None;
    }
    let [Expr::ListComp(comprehension)] = call.arguments.args.as_ref() else {
        return None;
    };
    let [generator] = comprehension.generators.as_slice() else {
        return None;
    };
    if generator.is_async || !generator.ifs.is_empty() {
        return None;
    }
    let Expr::Tuple(pair) = &generator.target else {
        return None;
    };
    let [Expr::Name(index), Expr::Name(byte)] = pair.elts.as_slice() else {
        return None;
    };
    let enumerated: &ExprCall = generator.iter.as_call_expr()?;
    let [Expr::Name(enumerated_input)] = enumerated.arguments.args.as_ref() else {
        return None;
    };
    if !is_name(&enumerated.func, "enumerate")
        || !enumerated.arguments.keywords.is_empty()
        || enumerated_input.id.as_str() != input
        || index.id.as_str() == byte.id.as_str()
        || [index.id.as_str(), byte.id.as_str()].contains(&input)
    {
        return None;
    }
    let Expr::BinOp(xor) = comprehension.elt.as_ref() else {
        return None;
    };
    if xor.op != Operator::BitXor || !is_name(&xor.left, byte.id.as_str()) {
        return None;
    }
    let Expr::Subscript(lookup) = xor.right.as_ref() else {
        return None;
    };
    let Expr::List(keys) = lookup.value.as_ref() else {
        return None;
    };
    let Expr::BinOp(modulo) = lookup.slice.as_ref() else {
        return None;
    };
    if modulo.op != Operator::Mod || !is_name(&modulo.left, index.id.as_str()) {
        return None;
    }
    let period: i128 = int_literal(&modulo.right)?;
    let keys: Vec<i128> = keys
        .elts
        .iter()
        .map(int_literal)
        .collect::<Option<Vec<i128>>>()?;
    if period <= 0 || usize::try_from(period).ok()? != keys.len() {
        return None;
    }
    Some((target.id.to_string(), keys))
}

fn int_literal(expr: &Expr) -> Option<i128> {
    let Expr::NumberLiteral(number) = expr else {
        return None;
    };
    let Number::Int(int) = &number.value else {
        return None;
    };
    int.as_u64().map(i128::from)
}

fn import_helper(stmt: &Stmt) -> Option<&str> {
    let Stmt::FunctionDef(function) = stmt else {
        return None;
    };
    let parameters = &function.parameters;
    let ([module, member], Some(rest), Some(options)) = (
        parameters.args.as_slice(),
        parameters.vararg.as_deref(),
        parameters.kwarg.as_deref(),
    ) else {
        return None;
    };
    let template: String = format!(
        "def {name}({module}, {member}, *{rest}, **{options}):\n    try:\n        return __import__({module} + '.' + {member}, *{rest}, **{options})\n    except ImportError:\n        return __import__({module}, *{rest}, **{options})\n",
        name = function.name.as_str(),
        module = module.parameter.name.as_str(),
        member = member.parameter.name.as_str(),
        rest = rest.name.as_str(),
        options = options.name.as_str(),
    );
    let parsed: Parsed<ModModule> = parse_module(&template).ok()?;
    let [expected] = parsed.syntax().body.as_slice() else {
        return None;
    };
    (ComparableStmt::from(stmt) == ComparableStmt::from(expected)).then(|| function.name.as_str())
}

fn import_statements(stmt: &Stmt, helper: Option<&str>) -> Option<Vec<Stmt>> {
    let Stmt::Assign(StmtAssign {
        targets,
        value,
        range,
        ..
    }) = stmt
    else {
        return None;
    };
    let [target] = targets.as_slice() else {
        return None;
    };
    let pairs: Vec<(&Expr, &Expr)> = match (target, value.as_ref()) {
        (Expr::Tuple(names), Expr::Tuple(values)) if names.elts.len() == values.elts.len() => {
            names.elts.iter().zip(&values.elts).collect()
        }
        (Expr::Name(_), single) => vec![(target, single)],
        _ => return None,
    };
    let mut statements: Vec<Stmt> = Vec::with_capacity(pairs.len());
    for (name, imported) in pairs {
        let Expr::Name(bound) = name else {
            return None;
        };
        let statement: Stmt = import_statement(bound.id.as_str(), imported, helper, *range)?;
        match (statements.last_mut(), statement) {
            (Some(Stmt::ImportFrom(previous)), Stmt::ImportFrom(next))
                if previous.module.as_ref().map(Identifier::as_str)
                    == next.module.as_ref().map(Identifier::as_str) =>
            {
                previous.names.extend(next.names);
            }
            (_, statement) => statements.push(statement),
        }
    }
    Some(statements)
}

fn import_statement(
    bound: &str,
    imported: &Expr,
    helper: Option<&str>,
    range: TextRange,
) -> Option<Stmt> {
    let alias = |name: &str| ruff_python_ast::Alias {
        range,
        node_index: AtomicNodeIndex::default(),
        name: Identifier::new(name, range),
        asname: (name != bound).then(|| Identifier::new(bound, range)),
    };
    match imported {
        Expr::Call(call) if is_name(&call.func, "__import__") => {
            let module: &str = plain_module(call, 1)?.first().copied()?;
            Some(Stmt::Import(ruff_python_ast::StmtImport {
                node_index: AtomicNodeIndex::default(),
                range,
                names: vec![alias(module)],
                is_lazy: false,
            }))
        }
        Expr::Attribute(ExprAttribute { value, attr, .. }) => {
            let call: &ExprCall = value.as_call_expr()?;
            if !helper.is_some_and(|helper: &str| is_name(&call.func, helper)) {
                return None;
            }
            let [module, member]: [&str; 2] = plain_module(call, 2)?.try_into().ok()?;
            if member != attr.as_str() {
                return None;
            }
            Some(Stmt::ImportFrom(ruff_python_ast::StmtImportFrom {
                node_index: AtomicNodeIndex::default(),
                range,
                module: Some(Identifier::new(module, range)),
                names: vec![alias(member)],
                level: 0,
                is_lazy: false,
            }))
        }
        _ => None,
    }
}

fn plain_module(call: &ExprCall, arity: usize) -> Option<Vec<&str>> {
    let absolute_defaults: bool = call.arguments.keywords.iter().all(|keyword| {
        match keyword.arg.as_ref().map(Identifier::as_str) {
            Some("globals" | "locals") => matches!(keyword.value, Expr::NoneLiteral(_)),
            Some("level") => matches!(
                &keyword.value,
                Expr::NumberLiteral(number) if matches!(&number.value, Number::Int(level) if level.as_u64() == Some(0))
            ),
            _ => false,
        }
    });
    if !absolute_defaults || call.arguments.args.len() != arity {
        return None;
    }
    call.arguments
        .args
        .iter()
        .map(|arg: &Expr| match arg {
            Expr::StringLiteral(literal) if is_identifier(literal.value.to_str()) => {
                Some(literal.value.to_str())
            }
            _ => None,
        })
        .collect()
}

fn is_identifier(text: &str) -> bool {
    text.chars()
        .next()
        .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
        && text
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && !PYTHON_KEYWORDS.contains(&text)
}

fn is_name(expr: &Expr, wanted: &str) -> bool {
    matches!(expr, Expr::Name(ExprName { id, .. }) if id.as_str() == wanted)
}

struct CallFolder<'a> {
    decoders: &'a BTreeMap<String, Vec<i128>>,
    getattr_is_builtin: bool,
    decoded: Cell<usize>,
    attributes: Cell<usize>,
}

impl CallFolder<'_> {
    fn xor_call(&self, call: &ExprCall) -> Option<Vec<u8>> {
        let Expr::Name(callee) = call.func.as_ref() else {
            return None;
        };
        let keys: &Vec<i128> = self.decoders.get(callee.id.as_str())?;
        let [Expr::BytesLiteral(data)] = call.arguments.args.as_ref() else {
            return None;
        };
        if !call.arguments.keywords.is_empty() {
            return None;
        }
        data.value
            .bytes()
            .enumerate()
            .map(|(index, byte): (usize, u8)| {
                let mixed: i128 = i128::from(byte) ^ keys[index % keys.len()];
                u8::try_from(mixed).ok()
            })
            .collect()
    }

    fn decode_call(&self, call: &ExprCall) -> Option<String> {
        let [Expr::StringLiteral(encoding)] = call.arguments.args.as_ref() else {
            return None;
        };
        if !call.arguments.keywords.is_empty() || encoding.value.to_str() != "utf-8" {
            return None;
        }
        let data: Vec<u8> = match call.func.as_ref() {
            Expr::Attribute(ExprAttribute { value, attr, .. }) if attr.as_str() == "decode" => {
                bytes_of(value)?
            }
            Expr::Call(lookup) if self.getattr_is_builtin => {
                let [target, Expr::StringLiteral(method)] = lookup.arguments.args.as_ref() else {
                    return None;
                };
                if !is_name(&lookup.func, "getattr")
                    || !lookup.arguments.keywords.is_empty()
                    || method.value.to_str() != "decode"
                {
                    return None;
                }
                bytes_of(target)?
            }
            _ => return None,
        };
        String::from_utf8(data).ok()
    }

    fn attribute_of(&self, call: &ExprCall) -> Option<(Expr, Identifier)> {
        if !self.getattr_is_builtin
            || !is_name(&call.func, "getattr")
            || !call.arguments.keywords.is_empty()
        {
            return None;
        }
        let [target, Expr::StringLiteral(attribute)] = call.arguments.args.as_ref() else {
            return None;
        };
        let attribute: &str = attribute.value.to_str();
        let identifier: bool = attribute
            .chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
            && attribute
                .chars()
                .all(|c: char| c.is_ascii_alphanumeric() || c == '_');
        let mangled: bool = attribute.starts_with("__") && !attribute.ends_with("__");
        if !identifier || mangled || PYTHON_KEYWORDS.contains(&attribute) {
            return None;
        }
        Some((target.clone(), Identifier::new(attribute, call.range)))
    }
}

fn bytes_of(expr: &Expr) -> Option<Vec<u8>> {
    match expr {
        Expr::BytesLiteral(literal) => Some(literal.value.bytes().collect()),
        _ => None,
    }
}

impl Transformer for CallFolder<'_> {
    fn visit_expr(&self, expr: &mut Expr) {
        walk_expr(self, expr);
        let Expr::Call(call) = expr else {
            return;
        };
        let range: TextRange = call.range;
        if let Some(plain) = self.xor_call(call)
            && let Some(literal) = value_to_expr(Value::Bytes(plain), range)
        {
            *expr = literal;
            self.decoded.set(self.decoded.get() + 1);
            return;
        }
        if let Some(text) = self.decode_call(call)
            && let Some(literal) = value_to_expr(Value::Str(text), range)
        {
            *expr = literal;
            self.decoded.set(self.decoded.get() + 1);
            return;
        }
        if let Some((target, attr)) = self.attribute_of(call) {
            *expr = Expr::Attribute(ExprAttribute {
                node_index: AtomicNodeIndex::default(),
                range,
                value: Box::new(target),
                attr,
                ctx: ExprContext::Load,
            });
            self.attributes.set(self.attributes.get() + 1);
        }
    }
}

struct ConstantFolder<'a> {
    bound: &'a BTreeMap<String, usize>,
    folded: Cell<usize>,
}

impl Transformer for ConstantFolder<'_> {
    fn visit_expr(&self, expr: &mut Expr) {
        walk_expr(self, expr);
        if matches!(expr, Expr::Call(_) | Expr::BinOp(_) | Expr::UnaryOp(_))
            && loaded_names_of(expr)
                .iter()
                .all(|name: &String| !self.bound.contains_key(name))
            && fold_constant_expr(expr)
        {
            self.folded.set(self.folded.get() + 1);
        }
    }
}

fn loaded_names_of(expr: &Expr) -> BTreeSet<String> {
    struct Loads {
        names: BTreeSet<String>,
    }
    impl<'a> Visitor<'a> for Loads {
        fn visit_expr(&mut self, expr: &'a Expr) {
            if let Expr::Name(name) = expr {
                self.names.insert(name.id.to_string());
            }
            walk_ref(self, expr);
        }
    }
    let mut loads: Loads = Loads {
        names: BTreeSet::new(),
    };
    loads.visit_expr(expr);
    loads.names
}

fn star_import(body: &[Stmt]) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'a> Visitor<'a> for Finder {
        fn visit_stmt(&mut self, stmt: &'a Stmt) {
            if let Stmt::ImportFrom(import) = stmt
                && import.names.iter().any(|alias| alias.name.as_str() == "*")
            {
                self.found = true;
            }
            walk_stmt(self, stmt);
        }
    }
    let mut finder: Finder = Finder { found: false };
    for stmt in body {
        finder.visit_stmt(stmt);
    }
    finder.found
}

fn loaded_names(body: &[Stmt]) -> BTreeSet<String> {
    struct Loads {
        names: BTreeSet<String>,
    }
    impl<'a> Visitor<'a> for Loads {
        fn visit_expr(&mut self, expr: &'a Expr) {
            if let Expr::Name(name) = expr
                && name.ctx == ExprContext::Load
            {
                self.names.insert(name.id.to_string());
            }
            walk_ref(self, expr);
        }
    }
    let mut loads: Loads = Loads {
        names: BTreeSet::new(),
    };
    for stmt in body {
        loads.visit_stmt(stmt);
    }
    loads.names
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const ALIASES: &str = "a1, a2, a3, a4, a5, a6, a7, a8, a9 = print, int, chr, bytes, enumerate, getattr, __import__, ImportError, None\n";
    const HELPER: &str = "def H(m, n, *r, **k):\n    try:\n        return a7(m + '.' + n, *r, **k)\n    except a8:\n        return a7(m, *r, **k)\n";

    fn payload(keys: &str, body: &str) -> String {
        format!(
            "{ALIASES}D = lambda d: a4([b ^ [{keys}][i % 2] for i, b in a5(d)])\n{HELPER}{body}"
        )
    }

    #[test]
    fn the_alias_table_decoder_and_helper_fold_away() {
        let folded: PayloadFold = fold_payload(&payload(
            "a2(a3(48) + 'o7', 8), 3",
            "a1(a6(D(b'oj'), a3(100) + 'ecode')('utf-8'))\n",
        ))
        .expect("folds");
        assert_eq!(folded.source, "print('hi')\n");
        assert!(!folded.binds_names);
        assert_eq!(folded.helpers_dropped, 2);
    }

    #[test]
    fn an_alias_whose_builtin_is_rebound_is_kept() {
        let folded: PayloadFold = fold_payload(&payload(
            "a2('0o7', 8), 3",
            "def f(int):\n    return int\na1(a6(D(b'oj'), 'decode')('utf-8'))\n",
        ))
        .expect("folds");
        assert!(
            folded.source.starts_with("a2, = int,\n")
                || folded.source.starts_with("a2, = (int,)\n"),
            "{}",
            folded.source
        );
        assert!(folded.source.contains("D(b'oj')"), "{}", folded.source);
        assert!(folded.binds_names);
    }

    #[test]
    fn a_key_that_overflows_a_byte_is_not_folded() {
        let folded: PayloadFold =
            fold_payload(&payload("300, 3", "a1(a6(D(b'oj'), 'decode')('utf-8'))\n"))
                .expect("folds");
        assert!(folded.source.contains("D(b'oj')"), "{}", folded.source);
        assert!(folded.source.contains("lambda d"), "{}", folded.source);
    }

    #[test]
    fn getattr_folds_only_to_plain_attribute_names() {
        let folded: PayloadFold = fold_payload(&payload(
            "7, 3",
            "x = []\na6(x, 'append')(1)\na6(x, '__secret')\na6(x, 'class')\na6(x, '__len__')()\n",
        ))
        .expect("folds");
        assert!(folded.source.contains("x.append(1)"), "{}", folded.source);
        assert!(folded.source.contains("x.__len__()"), "{}", folded.source);
        assert!(
            folded.source.contains("getattr(x, '__secret')"),
            "{}",
            folded.source
        );
        assert!(
            folded.source.contains("getattr(x, 'class')"),
            "{}",
            folded.source
        );
    }

    #[test]
    fn import_helper_calls_become_import_statements() {
        let folded: PayloadFold = fold_payload(&payload(
            "7, 3",
            "s, = (a7('asyncio'),)\nA, Generic = (a6(H('typing', 'Generic'), 'Generic'), a6(H('typing', 'TypeVar'), 'TypeVar'))\n",
        ))
        .expect("folds");
        assert_eq!(
            folded.source,
            "import asyncio as s\nfrom typing import Generic as A, TypeVar as Generic\n"
        );
        assert_eq!(folded.imports, 2);
        let dotted: PayloadFold = fold_payload(&payload(
            "7, 3",
            "p, = (a7('os.path'),)\nq = a6(H('a.b', 'c'), 'c')\n",
        ))
        .expect("folds");
        assert!(
            dotted.source.contains("__import__('os.path')"),
            "{}",
            dotted.source
        );
        assert!(
            dotted.source.contains("H('a.b', 'c').c"),
            "{}",
            dotted.source
        );
        let keywords: PayloadFold = fold_payload(&payload(
            "7, 3",
            "A = a6(H('typing', 'Generic', globals=None, locals=None, level=0), 'Generic')\nB = a6(H('typing', 'Any', level=1), 'Any')\n",
        ))
        .expect("folds");
        assert!(
            keywords.source.starts_with("def H(")
                && keywords
                    .source
                    .contains("from typing import Generic as A\n")
                && keywords.source.contains("H('typing', 'Any', level=1).Any"),
            "{}",
            keywords.source
        );
    }

    #[test]
    fn a_helper_with_another_body_is_not_an_import_helper() {
        let source: String = format!(
            "{ALIASES}def H(m, n, *r, **k):\n    try:\n        return a7(n + '.' + m, *r, **k)\n    except a8:\n        return a7(m, *r, **k)\nq = a6(H('typing', 'Generic'), 'Generic')\n"
        );
        let folded: PayloadFold = fold_payload(&source).expect("folds");
        assert!(folded.source.contains("def H("), "{}", folded.source);
        assert_eq!(folded.imports, 0);
    }

    #[test]
    fn a_used_import_helper_and_a_star_import_are_respected() {
        let used: PayloadFold =
            fold_payload(&payload("7, 3", "m = H('os', 'path')\n")).expect("folds");
        assert!(used.source.contains("def H("), "{}", used.source);
        assert!(
            fold_payload(&payload("7, 3", "from os import *\n")).is_none(),
            "a star import can shadow any builtin, so the aliases must stay"
        );
    }
}
