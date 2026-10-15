use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use ruff_python_ast::name::Name;
use ruff_python_ast::visitor::transformer::{Transformer, walk_expr, walk_stmt};
use ruff_python_ast::visitor::{Visitor, walk_expr as walk_ref, walk_stmt as walk_stmt_ref};
use ruff_python_ast::{
    AtomicNodeIndex, Comprehension, Expr, ExprAttribute, ExprContext, ExprDictComp, ExprName,
    Identifier, ModModule, Parameters, Stmt, StmtAssign,
};
use ruff_python_codegen::{Generator, Stylist};
use ruff_python_parser::{Parsed, parse_module};
use ruff_text_size::TextRange;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AliasTarget {
    Builtin(String),
    ModuleAttribute { module: String, attribute: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AliasFold {
    pub(crate) source: String,
    pub(crate) folded: BTreeMap<String, AliasTarget>,
}

pub(crate) fn fold_alias_views(
    source: &str,
    is_alias_name: fn(&str) -> bool,
    is_builtin: fn(&str) -> bool,
) -> Option<AliasFold> {
    let parsed: Parsed<ModModule> = parse_module(source).ok()?;
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), source);
    let mut module: ModModule = parsed.into_syntax();
    if has_type_params(&module.body) {
        return None;
    }
    let imported: BTreeSet<String> = plain_imports(&module.body);
    let prologue: usize = module
        .body
        .iter()
        .take_while(|stmt: &&Stmt| {
            matches!(stmt, Stmt::Import(_) | Stmt::ImportFrom(_))
                || is_docstring(stmt)
                || alias_of(stmt, &imported, is_alias_name, is_builtin).is_some()
        })
        .count();
    let module_bound: BTreeMap<String, usize> = module_scope_bindings(&module.body);
    let declared_global: BTreeSet<String> = global_declarations(&module.body);
    let mut candidates: BTreeMap<String, AliasTarget> = BTreeMap::new();
    let eligible = |index: usize, stmt: &Stmt| -> Option<(String, AliasTarget)> {
        let (alias, target): (&str, AliasTarget) =
            alias_of(stmt, &imported, is_alias_name, is_builtin)?;
        (matches!(target, AliasTarget::Builtin(_)) || index < prologue)
            .then(|| (alias.to_owned(), target))
    };
    for (index, stmt) in module.body.iter().enumerate() {
        let Some((alias, target)) = eligible(index, stmt) else {
            continue;
        };
        let alias: &str = &alias;
        let source_name: &str = match &target {
            AliasTarget::Builtin(name) => name,
            AliasTarget::ModuleAttribute { module, .. } => module,
        };
        let source_ok: bool = match &target {
            AliasTarget::Builtin(_) => !module_bound.contains_key(source_name),
            AliasTarget::ModuleAttribute { .. } => module_bound.get(source_name) == Some(&1),
        };
        if module_bound.get(alias) == Some(&1)
            && !declared_global.contains(alias)
            && !declared_global.contains(source_name)
            && source_ok
            && !candidates.contains_key(alias)
        {
            candidates.insert(alias.to_owned(), target);
        }
    }
    if candidates.is_empty() {
        return None;
    }
    let folder: ScopedFolder<'_> = ScopedFolder {
        candidates: &candidates,
        scopes: RefCell::new(Vec::new()),
        kept: RefCell::new(BTreeSet::new()),
        replaced: Cell::new(0),
    };
    for (index, stmt) in module.body.iter_mut().enumerate() {
        if eligible(index, stmt).is_some_and(|(alias, _)| candidates.contains_key(&alias)) {
            continue;
        }
        folder.visit_stmt(stmt);
    }
    let kept: BTreeSet<String> = folder.kept.into_inner();
    let folded: BTreeMap<String, AliasTarget> = candidates
        .into_iter()
        .filter(|(alias, _): &(String, AliasTarget)| !kept.contains(alias))
        .collect();
    if folded.is_empty() {
        return None;
    }
    let mut index: usize = 0;
    module.body.retain(|stmt: &Stmt| {
        let drop: bool =
            eligible(index, stmt).is_some_and(|(alias, _)| folded.contains_key(&alias));
        index += 1;
        !drop
    });
    let mut out: String = String::with_capacity(source.len());
    for stmt in &module.body {
        out.push_str(&Generator::from(&stylist).stmt(stmt));
        out.push('\n');
    }
    Some(AliasFold {
        source: out,
        folded,
    })
}

fn alias_of<'a>(
    stmt: &'a Stmt,
    imported: &BTreeSet<String>,
    is_alias_name: fn(&str) -> bool,
    is_builtin: fn(&str) -> bool,
) -> Option<(&'a str, AliasTarget)> {
    let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt else {
        return None;
    };
    let [Expr::Name(alias)] = targets.as_slice() else {
        return None;
    };
    if !is_alias_name(alias.id.as_str()) {
        return None;
    }
    let target: AliasTarget = match value.as_ref() {
        Expr::Name(builtin) if is_builtin(builtin.id.as_str()) => {
            AliasTarget::Builtin(builtin.id.to_string())
        }
        Expr::Attribute(ExprAttribute { value, attr, .. }) => match value.as_ref() {
            Expr::Name(module) if imported.contains(module.id.as_str()) => {
                AliasTarget::ModuleAttribute {
                    module: module.id.to_string(),
                    attribute: attr.to_string(),
                }
            }
            _ => return None,
        },
        _ => return None,
    };
    Some((alias.id.as_str(), target))
}

fn is_docstring(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Expr(expr) if matches!(expr.value.as_ref(), Expr::StringLiteral(_)))
}

fn plain_imports(body: &[Stmt]) -> BTreeSet<String> {
    body.iter()
        .filter_map(|stmt: &Stmt| match stmt {
            Stmt::Import(import) => Some(
                import
                    .names
                    .iter()
                    .filter(|alias| alias.asname.is_none() && !alias.name.as_str().contains('.'))
                    .map(|alias| alias.name.to_string()),
            ),
            _ => None,
        })
        .flatten()
        .collect()
}

fn has_type_params(body: &[Stmt]) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'a> Visitor<'a> for Finder {
        fn visit_stmt(&mut self, stmt: &'a Stmt) {
            match stmt {
                Stmt::FunctionDef(function) if function.type_params.is_some() => {
                    self.found = true;
                }
                Stmt::ClassDef(class) if class.type_params.is_some() => self.found = true,
                Stmt::TypeAlias(_) => self.found = true,
                _ => {}
            }
            walk_stmt_ref(self, stmt);
        }
    }
    let mut finder: Finder = Finder { found: false };
    for stmt in body {
        finder.visit_stmt(stmt);
    }
    finder.found
}

fn global_declarations(body: &[Stmt]) -> BTreeSet<String> {
    struct Globals {
        names: BTreeSet<String>,
    }
    impl<'a> Visitor<'a> for Globals {
        fn visit_stmt(&mut self, stmt: &'a Stmt) {
            match stmt {
                Stmt::Global(global) => {
                    self.names
                        .extend(global.names.iter().map(Identifier::to_string));
                }
                Stmt::Nonlocal(nonlocal) => {
                    self.names
                        .extend(nonlocal.names.iter().map(Identifier::to_string));
                }
                _ => {}
            }
            walk_stmt_ref(self, stmt);
        }
    }
    let mut globals: Globals = Globals {
        names: BTreeSet::new(),
    };
    for stmt in body {
        globals.visit_stmt(stmt);
    }
    globals.names
}

#[derive(Default)]
struct ScopeStores {
    names: BTreeMap<String, usize>,
}

impl ScopeStores {
    fn bind(&mut self, name: &str) {
        *self.names.entry(name.to_owned()).or_default() += 1;
    }

    fn stmts(&mut self, body: &[Stmt]) {
        for stmt in body {
            self.stmt(stmt);
        }
    }

    fn stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::FunctionDef(function) => {
                self.bind(function.name.as_str());
                for decorator in &function.decorator_list {
                    self.expr(&decorator.expression);
                }
            }
            Stmt::ClassDef(class) => {
                self.bind(class.name.as_str());
                for decorator in &class.decorator_list {
                    self.expr(&decorator.expression);
                }
            }
            Stmt::Import(import) => {
                for alias in &import.names {
                    let bound: &str = alias.asname.as_ref().map_or_else(
                        || alias.name.as_str().split('.').next().unwrap_or_default(),
                        Identifier::as_str,
                    );
                    self.bind(bound);
                }
            }
            Stmt::ImportFrom(import) => {
                for alias in &import.names {
                    self.bind(
                        alias
                            .asname
                            .as_ref()
                            .map_or_else(|| alias.name.as_str(), Identifier::as_str),
                    );
                }
            }
            Stmt::Try(attempt) => {
                for handler in &attempt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
                    if let Some(name) = &handler.name {
                        self.bind(name.as_str());
                    }
                    self.stmts(&handler.body);
                }
                self.stmts(&attempt.body);
                self.stmts(&attempt.orelse);
                self.stmts(&attempt.finalbody);
                return;
            }
            _ => {}
        }
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            return;
        }
        let mut exprs: ExprStores<'_> = ExprStores { stores: self };
        walk_stmt_ref(&mut exprs, stmt);
    }

    fn expr(&mut self, expr: &Expr) {
        let mut exprs: ExprStores<'_> = ExprStores { stores: self };
        exprs.visit_expr(expr);
    }
}

struct ExprStores<'a> {
    stores: &'a mut ScopeStores,
}

impl<'b> Visitor<'b> for ExprStores<'_> {
    fn visit_stmt(&mut self, stmt: &'b Stmt) {
        self.stores.stmt(stmt);
    }

    fn visit_expr(&mut self, expr: &'b Expr) {
        match expr {
            Expr::Name(name) if matches!(name.ctx, ExprContext::Store | ExprContext::Del) => {
                self.stores.bind(name.id.as_str());
            }
            Expr::Named(named) => {
                if let Expr::Name(target) = named.target.as_ref() {
                    self.stores.bind(target.id.as_str());
                }
                self.visit_expr(&named.value);
            }
            Expr::Lambda(lambda) => {
                if let Some(parameters) = &lambda.parameters {
                    for default in parameter_defaults(parameters) {
                        self.visit_expr(default);
                    }
                }
            }
            Expr::ListComp(comp) => self.comprehension(&comp.generators, &[&comp.elt]),
            Expr::SetComp(comp) => self.comprehension(&comp.generators, &[&comp.elt]),
            Expr::Generator(comp) => self.comprehension(&comp.generators, &[&comp.elt]),
            Expr::DictComp(comp) => {
                let parts: Vec<&Expr> = comp
                    .key
                    .as_deref()
                    .into_iter()
                    .chain(std::iter::once(comp.value.as_ref()))
                    .collect();
                self.comprehension(&comp.generators, &parts);
            }
            _ => walk_ref(self, expr),
        }
    }

    fn visit_pattern(&mut self, pattern: &'b ruff_python_ast::Pattern) {
        match pattern {
            ruff_python_ast::Pattern::MatchAs(capture) => {
                if let Some(name) = &capture.name {
                    self.stores.bind(name.as_str());
                }
            }
            ruff_python_ast::Pattern::MatchStar(star) => {
                if let Some(name) = &star.name {
                    self.stores.bind(name.as_str());
                }
            }
            ruff_python_ast::Pattern::MatchMapping(mapping) => {
                if let Some(rest) = &mapping.rest {
                    self.stores.bind(rest.as_str());
                }
            }
            _ => {}
        }
        ruff_python_ast::visitor::walk_pattern(self, pattern);
    }
}

impl ExprStores<'_> {
    fn comprehension(&mut self, generators: &[Comprehension], parts: &[&Expr]) {
        if let Some(first) = generators.first() {
            self.visit_expr(&first.iter);
        }
        let mut walrus: WalrusTargets = WalrusTargets {
            names: BTreeSet::new(),
        };
        for generator in generators {
            walrus.visit_expr(&generator.iter);
            for condition in &generator.ifs {
                walrus.visit_expr(condition);
            }
        }
        for part in parts {
            walrus.visit_expr(part);
        }
        for name in walrus.names {
            self.stores.bind(&name);
        }
    }
}

struct WalrusTargets {
    names: BTreeSet<String>,
}

impl<'a> Visitor<'a> for WalrusTargets {
    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Named(named) = expr
            && let Expr::Name(target) = named.target.as_ref()
        {
            self.names.insert(target.id.to_string());
        }
        if !matches!(expr, Expr::Lambda(_)) {
            walk_ref(self, expr);
        }
    }
}

fn scope_globals(body: &[Stmt], out: &mut BTreeSet<String>) {
    for stmt in body {
        match stmt {
            Stmt::Global(global) => out.extend(global.names.iter().map(Identifier::to_string)),
            Stmt::If(conditional) => {
                scope_globals(&conditional.body, out);
                for clause in &conditional.elif_else_clauses {
                    scope_globals(&clause.body, out);
                }
            }
            Stmt::For(loop_) => {
                scope_globals(&loop_.body, out);
                scope_globals(&loop_.orelse, out);
            }
            Stmt::While(loop_) => {
                scope_globals(&loop_.body, out);
                scope_globals(&loop_.orelse, out);
            }
            Stmt::With(with) => scope_globals(&with.body, out),
            Stmt::Try(attempt) => {
                scope_globals(&attempt.body, out);
                for handler in &attempt.handlers {
                    let ruff_python_ast::ExceptHandler::ExceptHandler(handler) = handler;
                    scope_globals(&handler.body, out);
                }
                scope_globals(&attempt.orelse, out);
                scope_globals(&attempt.finalbody, out);
            }
            Stmt::Match(matched) => {
                for case in &matched.cases {
                    scope_globals(&case.body, out);
                }
            }
            _ => {}
        }
    }
}

fn parameter_defaults(parameters: &Parameters) -> impl Iterator<Item = &Expr> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .filter_map(|parameter| parameter.default.as_deref())
}

fn parameter_names(parameters: &Parameters) -> BTreeSet<String> {
    parameters
        .posonlyargs
        .iter()
        .chain(&parameters.args)
        .chain(&parameters.kwonlyargs)
        .map(|parameter| parameter.parameter.name.to_string())
        .chain(
            parameters
                .vararg
                .iter()
                .chain(&parameters.kwarg)
                .map(|parameter| parameter.name.to_string()),
        )
        .collect()
}

fn module_scope_bindings(body: &[Stmt]) -> BTreeMap<String, usize> {
    let mut stores: ScopeStores = ScopeStores::default();
    stores.stmts(body);
    stores.names
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Function,
    Class,
}

#[derive(Debug)]
struct Scope {
    kind: ScopeKind,
    locals: BTreeSet<String>,
    globals: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolution {
    Global,
    Local,
    Unknown,
}

struct ScopedFolder<'a> {
    candidates: &'a BTreeMap<String, AliasTarget>,
    scopes: RefCell<Vec<Scope>>,
    kept: RefCell<BTreeSet<String>>,
    replaced: Cell<usize>,
}

impl ScopedFolder<'_> {
    fn resolve(&self, name: &str) -> Resolution {
        let scopes = self.scopes.borrow();
        for (depth, scope) in scopes.iter().enumerate().rev() {
            let innermost: bool = depth + 1 == scopes.len();
            if scope.globals.contains(name) {
                return Resolution::Global;
            }
            match scope.kind {
                ScopeKind::Class if innermost && scope.locals.contains(name) => {
                    return Resolution::Unknown;
                }
                ScopeKind::Function if scope.locals.contains(name) => return Resolution::Local,
                ScopeKind::Class | ScopeKind::Function => {}
            }
        }
        Resolution::Global
    }

    fn enter(&self, kind: ScopeKind, locals: BTreeSet<String>, body: &[Stmt]) {
        let mut globals: BTreeSet<String> = BTreeSet::new();
        scope_globals(body, &mut globals);
        self.scopes.borrow_mut().push(Scope {
            kind,
            locals,
            globals,
        });
    }

    fn leave(&self) {
        self.scopes.borrow_mut().pop();
    }

    fn replacement(&self, alias: &str, range: TextRange) -> Option<Expr> {
        let target: &AliasTarget = self.candidates.get(alias)?;
        let source: &str = match target {
            AliasTarget::Builtin(name) => name,
            AliasTarget::ModuleAttribute { module, .. } => module,
        };
        if self.resolve(source) != Resolution::Global {
            return None;
        }
        let name = |id: &str| {
            Expr::Name(ExprName {
                node_index: AtomicNodeIndex::default(),
                range,
                id: Name::new(id),
                ctx: ExprContext::Load,
            })
        };
        Some(match target {
            AliasTarget::Builtin(builtin) => name(builtin),
            AliasTarget::ModuleAttribute { module, attribute } => Expr::Attribute(ExprAttribute {
                node_index: AtomicNodeIndex::default(),
                range,
                value: Box::new(name(module)),
                attr: Identifier::new(attribute, range),
                ctx: ExprContext::Load,
            }),
        })
    }

    fn comprehension(&self, generators: &mut [Comprehension], parts: &mut [&mut Expr]) {
        let Some((first, rest)) = generators.split_first_mut() else {
            return;
        };
        self.visit_expr(&mut first.iter);
        let mut locals: ScopeStores = ScopeStores::default();
        locals.expr(&first.target);
        for generator in rest.iter() {
            locals.expr(&generator.target);
        }
        self.enter(ScopeKind::Function, locals.names.into_keys().collect(), &[]);
        for condition in &mut first.ifs {
            self.visit_expr(condition);
        }
        for generator in rest {
            self.visit_expr(&mut generator.iter);
            for condition in &mut generator.ifs {
                self.visit_expr(condition);
            }
        }
        for part in parts {
            self.visit_expr(part);
        }
        self.leave();
    }
}

impl Transformer for ScopedFolder<'_> {
    fn visit_stmt(&self, stmt: &mut Stmt) {
        match stmt {
            Stmt::FunctionDef(function) => {
                for decorator in &mut function.decorator_list {
                    self.visit_expr(&mut decorator.expression);
                }
                for default in function
                    .parameters
                    .posonlyargs
                    .iter_mut()
                    .chain(&mut function.parameters.args)
                    .chain(&mut function.parameters.kwonlyargs)
                {
                    if let Some(value) = default.default.as_deref_mut() {
                        self.visit_expr(value);
                    }
                    if let Some(annotation) = default.parameter.annotation.as_deref_mut() {
                        self.visit_expr(annotation);
                    }
                }
                for variadic in function
                    .parameters
                    .vararg
                    .iter_mut()
                    .chain(function.parameters.kwarg.iter_mut())
                {
                    if let Some(annotation) = variadic.annotation.as_deref_mut() {
                        self.visit_expr(annotation);
                    }
                }
                if let Some(returns) = function.returns.as_deref_mut() {
                    self.visit_expr(returns);
                }
                let mut locals: ScopeStores = ScopeStores::default();
                locals.stmts(&function.body);
                let mut names: BTreeSet<String> = parameter_names(&function.parameters);
                names.extend(locals.names.into_keys());
                self.enter(ScopeKind::Function, names, &function.body);
                for inner in &mut function.body {
                    self.visit_stmt(inner);
                }
                self.leave();
            }
            Stmt::ClassDef(class) => {
                for decorator in &mut class.decorator_list {
                    self.visit_expr(&mut decorator.expression);
                }
                if let Some(arguments) = class.arguments.as_deref_mut() {
                    for argument in &mut arguments.args {
                        self.visit_expr(argument);
                    }
                    for keyword in &mut arguments.keywords {
                        self.visit_expr(&mut keyword.value);
                    }
                }
                let mut locals: ScopeStores = ScopeStores::default();
                locals.stmts(&class.body);
                self.enter(
                    ScopeKind::Class,
                    locals.names.into_keys().collect(),
                    &class.body,
                );
                for inner in &mut class.body {
                    self.visit_stmt(inner);
                }
                self.leave();
            }
            _ => walk_stmt(self, stmt),
        }
    }

    fn visit_expr(&self, expr: &mut Expr) {
        match expr {
            Expr::Name(ExprName {
                id,
                ctx: ExprContext::Load,
                range,
                ..
            }) if self.candidates.contains_key(id.as_str()) => {
                let alias: String = id.to_string();
                match self.resolve(&alias) {
                    Resolution::Global => match self.replacement(&alias, *range) {
                        Some(replacement) => {
                            *expr = replacement;
                            self.replaced.set(self.replaced.get() + 1);
                        }
                        _ => {
                            self.kept.borrow_mut().insert(alias);
                        }
                    },
                    Resolution::Unknown => {
                        self.kept.borrow_mut().insert(alias);
                    }
                    Resolution::Local => {}
                }
            }
            Expr::Lambda(lambda) => {
                if let Some(parameters) = lambda.parameters.as_deref_mut() {
                    for parameter in parameters
                        .posonlyargs
                        .iter_mut()
                        .chain(&mut parameters.args)
                        .chain(&mut parameters.kwonlyargs)
                    {
                        if let Some(value) = parameter.default.as_deref_mut() {
                            self.visit_expr(value);
                        }
                    }
                }
                let names: BTreeSet<String> = lambda
                    .parameters
                    .as_deref()
                    .map(parameter_names)
                    .unwrap_or_default();
                self.enter(ScopeKind::Function, names, &[]);
                self.visit_expr(&mut lambda.body);
                self.leave();
            }
            Expr::ListComp(comp) => self.comprehension(&mut comp.generators, &mut [&mut comp.elt]),
            Expr::SetComp(comp) => self.comprehension(&mut comp.generators, &mut [&mut comp.elt]),
            Expr::Generator(comp) => {
                self.comprehension(&mut comp.generators, &mut [&mut comp.elt]);
            }
            Expr::DictComp(comp) => {
                let ExprDictComp {
                    key,
                    value,
                    generators,
                    ..
                } = comp;
                let mut parts: Vec<&mut Expr> = key
                    .as_deref_mut()
                    .into_iter()
                    .chain(std::iter::once(value.as_mut()))
                    .collect();
                self.comprehension(generators, &mut parts);
            }
            _ => walk_expr(self, expr),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn short(name: &str) -> bool {
        name.len() <= 2
    }

    fn builtin(name: &str) -> bool {
        matches!(name, "print" | "len" | "range" | "int")
    }

    fn fold(source: &str) -> Option<String> {
        fold_alias_views(source, short, builtin).map(|fold: AliasFold| fold.source)
    }

    #[test]
    fn only_loads_that_reach_the_module_alias_are_replaced() {
        let source: &str = "A = print\nB = len\ndef f(A):\n    return A + B([A])\ndef g(x):\n    A = x\n    return [A for A in range(A)]\ndef h(xs):\n    return [B(y) for y in xs] + [A for A in xs]\nA(f(1), g(2), h('ab'))\n";
        assert_eq!(
            fold(source).expect("folds"),
            "def f(A):\n    return A + len([A])\ndef g(x):\n    A = x\n    return [A for A in range(A)]\ndef h(xs):\n    return [len(y) for y in xs] + [A for A in xs]\nprint(f(1), g(2), h('ab'))\n"
        );
    }

    #[test]
    fn a_shadowed_builtin_or_a_class_binding_keeps_the_alias() {
        let shadowed: &str = "P = print\ndef f(print):\n    return P(print)\nf(1)\n";
        assert_eq!(fold(shadowed), None);
        let class_body: &str = "L = len\nclass C:\n    n = L('ab')\n    L = 3\nprint(C.n)\n";
        assert_eq!(fold(class_body), None);
    }

    #[test]
    fn module_attribute_aliases_fold_back_to_attribute_access() {
        let source: &str =
            "import asyncio\ns = asyncio.sleep\nasync def Y():\n    await s(0)\n    return 1\n";
        assert_eq!(
            fold(source).expect("folds"),
            "import asyncio\nasync def Y():\n    await asyncio.sleep(0)\n    return 1\n"
        );
    }

    #[test]
    fn aliases_outside_the_prologue_or_rebound_stay() {
        for source in [
            "import os\nprint(1)\nP = os.path\nP(1)\n",
            "A = print\nA = len\nA(2)\n",
            "A = print\ndef f():\n    global A\n    A = len\nA(2)\n",
            "A = print\nprint = len\nA(2)\n",
            "import os\nos = 3\nP = os.path\nP(1)\n",
        ] {
            assert_eq!(fold(source), None, "{source}");
        }
    }

    #[test]
    fn a_global_declaration_reads_the_module_alias() {
        let source: &str = "A = print\ndef f():\n    global A\n    return A\nf()\n";
        assert_eq!(fold(source), None);
        let read: &str =
            "A = print\ndef f(x):\n    if x:\n        global B\n    return A(x)\nf(1)\n";
        assert_eq!(
            fold(read).expect("folds"),
            "def f(x):\n    if x:\n        global B\n    return print(x)\nf(1)\n"
        );
    }
}
