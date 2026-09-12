use std::collections::BTreeMap;

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_pass_py_decompile::ast::node::BinOpKind;
use disrobe_pass_py_decompile::ast::{
    AstBuilder, AstModule, Comprehension, DefaultAstBuilder, ExceptHandler, Expr, Keyword,
    MatchCase, Stmt, TStrItem, WithItem,
};
use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{NativeDecompile, decompile_pyc};
use disrobe_pass_py_decompile::frame_tree::{FrameTree, builder_for};
use disrobe_py_marshal::{CodeObject, PyVersion as MarshalVersion};

use crate::error::{LiftError, Result};
use crate::usize_to_u32_saturating;

const FUNCTION_STRIDE: u64 = 1 << 20;
const IMPORT_BASE: u64 = 1 << 40;
const MODULE_FUNCTION_NAME: &str = "<module>";
const MAX_EMIT_DEPTH: usize = 512;
const MAX_AST_NODES: usize = 262_144;

pub fn lift_pyc(bytes: &[u8]) -> Result<NirModule> {
    let decompiled: NativeDecompile =
        decompile_pyc(bytes).map_err(|e: disrobe_pass_py_decompile::DecompileError| {
            LiftError::Source(format!("pyc decompile: {e}"))
        })?;
    let ast: AstModule = build_ast(
        &decompiled.code,
        &decompiled.decompile_version,
        decompiled.marshal_version,
    )?;
    let source_hash: [u8; 32] = *blake3::hash(bytes).as_bytes();
    lift_ast(&ast, source_hash)
}

pub fn lift_python(module: &AstModule) -> Result<NirModule> {
    enforce_ast_depth(module)?;
    let serialized: String = format!("{module:?}");
    let source_hash: [u8; 32] = *blake3::hash(serialized.as_bytes()).as_bytes();
    lift_ast(module, source_hash)
}

enum AstNode<'a> {
    Stmt(&'a Stmt),
    Expr(&'a Expr),
}

fn enforce_ast_depth(module: &AstModule) -> Result<()> {
    let mut work: Vec<(AstNode<'_>, usize)> = Vec::new();
    let mut scheduled: usize = 0;
    for stmt in &module.body {
        push_node(AstNode::Stmt(stmt), 1, &mut work, &mut scheduled)?;
    }
    while let Some((node, depth)) = work.pop() {
        if depth > MAX_EMIT_DEPTH {
            return Err(LiftError::DepthExceeded {
                limit: MAX_EMIT_DEPTH,
            });
        }
        match node {
            AstNode::Stmt(stmt) => push_stmt_children(stmt, depth, &mut work, &mut scheduled)?,
            AstNode::Expr(expr) => push_expr_children(expr, depth, &mut work, &mut scheduled)?,
        }
    }
    Ok(())
}

fn push_node<'a>(
    node: AstNode<'a>,
    depth: usize,
    work: &mut Vec<(AstNode<'a>, usize)>,
    scheduled: &mut usize,
) -> Result<()> {
    if *scheduled >= MAX_AST_NODES {
        return Err(LiftError::AstSizeExceeded {
            limit: MAX_AST_NODES,
        });
    }
    *scheduled = scheduled.saturating_add(1);
    work.push((node, depth));
    Ok(())
}

fn push_stmt_children<'a>(
    stmt: &'a Stmt,
    depth: usize,
    work: &mut Vec<(AstNode<'a>, usize)>,
    scheduled: &mut usize,
) -> Result<()> {
    let next: usize = depth.saturating_add(1);
    match stmt {
        Stmt::Expr(expr) | Stmt::AugAssign { value: expr, .. } => {
            push_node(AstNode::Expr(expr), next, work, scheduled)?;
        }
        Stmt::Return(opt) | Stmt::Raise { exc: opt, .. } => {
            if let Some(expr) = opt {
                push_node(AstNode::Expr(expr), next, work, scheduled)?;
            }
        }
        Stmt::Delete(exprs) => push_exprs(exprs, next, work, scheduled)?,
        Stmt::Assign { targets, value, .. } => {
            push_exprs(targets, next, work, scheduled)?;
            push_node(AstNode::Expr(value), next, work, scheduled)?;
        }
        Stmt::AnnAssign {
            target,
            annotation,
            value,
            ..
        } => {
            push_node(AstNode::Expr(target), next, work, scheduled)?;
            push_node(AstNode::Expr(annotation), next, work, scheduled)?;
            if let Some(value) = value {
                push_node(AstNode::Expr(value), next, work, scheduled)?;
            }
        }
        Stmt::TypeAlias { value, .. } => push_node(AstNode::Expr(value), next, work, scheduled)?,
        Stmt::FunctionDef {
            body,
            decorators,
            returns,
            ..
        } => {
            push_stmts(body, next, work, scheduled)?;
            push_exprs(decorators, next, work, scheduled)?;
            if let Some(returns) = returns {
                push_node(AstNode::Expr(returns), next, work, scheduled)?;
            }
        }
        Stmt::ClassDef {
            bases,
            keywords,
            body,
            decorators,
            ..
        } => {
            push_exprs(bases, next, work, scheduled)?;
            push_keywords(keywords, next, work, scheduled)?;
            push_stmts(body, next, work, scheduled)?;
            push_exprs(decorators, next, work, scheduled)?;
        }
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            ..
        } => {
            push_node(AstNode::Expr(target), next, work, scheduled)?;
            push_node(AstNode::Expr(iter), next, work, scheduled)?;
            push_stmts(body, next, work, scheduled)?;
            push_stmts(orelse, next, work, scheduled)?;
        }
        Stmt::While {
            test, body, orelse, ..
        }
        | Stmt::If {
            test, body, orelse, ..
        } => {
            push_node(AstNode::Expr(test), next, work, scheduled)?;
            push_stmts(body, next, work, scheduled)?;
            push_stmts(orelse, next, work, scheduled)?;
        }
        Stmt::With { items, body, .. } => {
            for item in items {
                push_node(AstNode::Expr(&item.context_expr), next, work, scheduled)?;
                if let Some(vars) = &item.optional_vars {
                    push_node(AstNode::Expr(vars), next, work, scheduled)?;
                }
            }
            push_stmts(body, next, work, scheduled)?;
        }
        Stmt::Match { subject, cases, .. } => {
            push_node(AstNode::Expr(subject), next, work, scheduled)?;
            for case in cases {
                if let Some(guard) = &case.guard {
                    push_node(AstNode::Expr(guard), next, work, scheduled)?;
                }
                push_stmts(&case.body, next, work, scheduled)?;
            }
        }
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        }
        | Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => {
            push_stmts(body, next, work, scheduled)?;
            for handler in handlers {
                if let Some(typ) = &handler.typ {
                    push_node(AstNode::Expr(typ), next, work, scheduled)?;
                }
                push_stmts(&handler.body, next, work, scheduled)?;
            }
            push_stmts(orelse, next, work, scheduled)?;
            push_stmts(finalbody, next, work, scheduled)?;
        }
        Stmt::Assert { test, msg, .. } => {
            push_node(AstNode::Expr(test), next, work, scheduled)?;
            if let Some(msg) = msg {
                push_node(AstNode::Expr(msg), next, work, scheduled)?;
            }
        }
        Stmt::Import(_)
        | Stmt::ImportFrom { .. }
        | Stmt::Global(_)
        | Stmt::Nonlocal(_)
        | Stmt::Pass
        | Stmt::Break
        | Stmt::Continue => {}
    }
    Ok(())
}

fn push_expr_children<'a>(
    expr: &'a Expr,
    depth: usize,
    work: &mut Vec<(AstNode<'a>, usize)>,
    scheduled: &mut usize,
) -> Result<()> {
    let next: usize = depth.saturating_add(1);
    match expr {
        Expr::BinOp { left, right, .. } => {
            push_node(AstNode::Expr(left), next, work, scheduled)?;
            push_node(AstNode::Expr(right), next, work, scheduled)?;
        }
        Expr::NamedExpr { target, value } => {
            push_node(AstNode::Expr(target), next, work, scheduled)?;
            push_node(AstNode::Expr(value), next, work, scheduled)?;
        }
        Expr::UnaryOp { operand: inner, .. }
        | Expr::Starred { value: inner, .. }
        | Expr::Attribute { value: inner, .. }
        | Expr::Await(inner)
        | Expr::YieldFrom(inner) => push_node(AstNode::Expr(inner), next, work, scheduled)?,
        Expr::FormattedValue {
            value, format_spec, ..
        } => {
            push_node(AstNode::Expr(value), next, work, scheduled)?;
            if let Some(spec) = format_spec {
                push_node(AstNode::Expr(spec), next, work, scheduled)?;
            }
        }
        Expr::Lambda { body, .. } => push_node(AstNode::Expr(body), next, work, scheduled)?,
        Expr::IfExp { test, body, orelse } => {
            push_node(AstNode::Expr(test), next, work, scheduled)?;
            push_node(AstNode::Expr(body), next, work, scheduled)?;
            push_node(AstNode::Expr(orelse), next, work, scheduled)?;
        }
        Expr::Yield(opt) => {
            if let Some(inner) = opt {
                push_node(AstNode::Expr(inner), next, work, scheduled)?;
            }
        }
        Expr::BoolOp { values: items, .. }
        | Expr::JoinedStr { values: items, .. }
        | Expr::Set(items)
        | Expr::List { elts: items, .. }
        | Expr::Tuple { elts: items, .. } => push_exprs(items, next, work, scheduled)?,
        Expr::TStr { items, .. } => {
            for item in items {
                if let TStrItem::Interp {
                    value, format_spec, ..
                } = item
                {
                    push_node(AstNode::Expr(value), next, work, scheduled)?;
                    if let Some(spec) = format_spec {
                        push_node(AstNode::Expr(spec), next, work, scheduled)?;
                    }
                }
            }
        }
        Expr::Dict { keys, values } => {
            for key in keys.iter().flatten() {
                push_node(AstNode::Expr(key), next, work, scheduled)?;
            }
            push_exprs(values, next, work, scheduled)?;
        }
        Expr::ListComp { elt, generators }
        | Expr::SetComp { elt, generators }
        | Expr::GeneratorExp { elt, generators } => {
            push_node(AstNode::Expr(elt), next, work, scheduled)?;
            push_comprehensions(generators, next, work, scheduled)?;
        }
        Expr::DictComp {
            key,
            value,
            generators,
        } => {
            push_node(AstNode::Expr(key), next, work, scheduled)?;
            push_node(AstNode::Expr(value), next, work, scheduled)?;
            push_comprehensions(generators, next, work, scheduled)?;
        }
        Expr::Compare {
            left, comparators, ..
        } => {
            push_node(AstNode::Expr(left), next, work, scheduled)?;
            push_exprs(comparators, next, work, scheduled)?;
        }
        Expr::Call {
            func,
            args,
            keywords,
        } => {
            push_node(AstNode::Expr(func), next, work, scheduled)?;
            push_exprs(args, next, work, scheduled)?;
            push_keywords(keywords, next, work, scheduled)?;
        }
        Expr::Subscript { value, slice, .. } => {
            push_node(AstNode::Expr(value), next, work, scheduled)?;
            push_node(AstNode::Expr(slice), next, work, scheduled)?;
        }
        Expr::Slice { lower, upper, step } => {
            for inner in [lower, upper, step].into_iter().flatten() {
                push_node(AstNode::Expr(inner), next, work, scheduled)?;
            }
        }
        Expr::Constant { .. }
        | Expr::Name { .. }
        | Expr::EmptyDictUnpack
        | Expr::EmptyDictKeyUnpack => {}
    }
    Ok(())
}

fn push_exprs<'a>(
    exprs: &'a [Expr],
    depth: usize,
    work: &mut Vec<(AstNode<'a>, usize)>,
    scheduled: &mut usize,
) -> Result<()> {
    for expr in exprs {
        push_node(AstNode::Expr(expr), depth, work, scheduled)?;
    }
    Ok(())
}

fn push_stmts<'a>(
    stmts: &'a [Stmt],
    depth: usize,
    work: &mut Vec<(AstNode<'a>, usize)>,
    scheduled: &mut usize,
) -> Result<()> {
    for stmt in stmts {
        push_node(AstNode::Stmt(stmt), depth, work, scheduled)?;
    }
    Ok(())
}

fn push_keywords<'a>(
    keywords: &'a [Keyword],
    depth: usize,
    work: &mut Vec<(AstNode<'a>, usize)>,
    scheduled: &mut usize,
) -> Result<()> {
    for keyword in keywords {
        push_node(AstNode::Expr(&keyword.value), depth, work, scheduled)?;
    }
    Ok(())
}

fn push_comprehensions<'a>(
    generators: &'a [Comprehension],
    depth: usize,
    work: &mut Vec<(AstNode<'a>, usize)>,
    scheduled: &mut usize,
) -> Result<()> {
    for generator in generators {
        push_node(AstNode::Expr(&generator.target), depth, work, scheduled)?;
        push_node(AstNode::Expr(&generator.iter), depth, work, scheduled)?;
        push_exprs(&generator.ifs, depth, work, scheduled)?;
    }
    Ok(())
}

fn build_ast(
    code: &CodeObject,
    decompile_version: &DecompileVersion,
    marshal_version: MarshalVersion,
) -> Result<AstModule> {
    let frame_tree: FrameTree = builder_for(marshal_version)
        .build(code, marshal_version)
        .map_err(|e: disrobe_pass_py_decompile::DecompileError| {
            LiftError::Source(format!("frame tree: {e}"))
        })?;
    DefaultAstBuilder::new()
        .build_module(code, &frame_tree, decompile_version)
        .map_err(|e: disrobe_pass_py_decompile::DecompileError| {
            LiftError::Source(format!("ast structure: {e}"))
        })
}

#[must_use]
pub const fn function_address(function_index: u32) -> u64 {
    (function_index as u64)
        .saturating_add(1)
        .saturating_mul(FUNCTION_STRIDE)
}

struct FunctionScope {
    qualified_name: String,
    address: u64,
    body: Vec<Stmt>,
    is_export: bool,
}

fn lift_ast(module: &AstModule, source_hash: [u8; 32]) -> Result<NirModule> {
    let mut scopes: Vec<FunctionScope> = Vec::new();
    let module_scope: FunctionScope = FunctionScope {
        qualified_name: MODULE_FUNCTION_NAME.to_owned(),
        address: function_address(0),
        body: module.body.clone(),
        is_export: true,
    };
    scopes.push(module_scope);
    collect_function_scopes(&module.body, "", &mut scopes, 0);

    let internal_by_name: BTreeMap<String, u64> = scopes
        .iter()
        .filter(|scope: &&FunctionScope| scope.qualified_name != MODULE_FUNCTION_NAME)
        .map(|scope: &FunctionScope| (scope.qualified_name.clone(), scope.address))
        .collect();

    let mut nir: NirModule = NirModule::new(source_hash, SourceLang::Python);
    for scope in &scopes {
        nir.symbols.push(NirSymbol {
            address: scope.address,
            name: scope.qualified_name.clone(),
            kind: if scope.is_export {
                SymbolKind::Export
            } else {
                SymbolKind::Function
            },
        });
    }

    let mut imports: ImportTable = ImportTable::new();
    for scope in &scopes {
        let function: NirFunction = lift_scope(scope, &internal_by_name, &mut imports)?;
        nir.functions.push(function);
    }

    for (symbol, address) in imports.into_sorted() {
        nir.symbols.push(NirSymbol {
            address,
            name: symbol,
            kind: SymbolKind::Import,
        });
    }

    if nir.functions.is_empty() {
        return Err(LiftError::Empty);
    }
    Ok(nir)
}

fn collect_function_scopes(
    body: &[Stmt],
    prefix: &str,
    scopes: &mut Vec<FunctionScope>,
    depth: usize,
) {
    const MAX_SCOPE_DEPTH: usize = 256;
    if depth >= MAX_SCOPE_DEPTH {
        return;
    }
    for stmt in body {
        match stmt {
            Stmt::FunctionDef {
                name,
                body: inner,
                decorators,
                ..
            } => {
                let qualified: String = qualify(prefix, name);
                let index: u32 = usize_to_u32_saturating(scopes.len());
                scopes.push(FunctionScope {
                    qualified_name: qualified.clone(),
                    address: function_address(index),
                    body: inner.clone(),
                    is_export: prefix.is_empty() && !is_private(name) && decorators.is_empty(),
                });
                collect_function_scopes(inner, &qualified, scopes, depth + 1);
            }
            Stmt::ClassDef {
                name, body: inner, ..
            } => {
                let qualified: String = qualify(prefix, name);
                collect_function_scopes(inner, &qualified, scopes, depth + 1);
            }
            Stmt::If { body, orelse, .. }
            | Stmt::For { body, orelse, .. }
            | Stmt::While { body, orelse, .. } => {
                collect_function_scopes(body, prefix, scopes, depth + 1);
                collect_function_scopes(orelse, prefix, scopes, depth + 1);
            }
            Stmt::With { body, .. } => collect_function_scopes(body, prefix, scopes, depth + 1),
            Stmt::Try {
                body,
                handlers,
                orelse,
                finalbody,
                ..
            }
            | Stmt::TryStar {
                body,
                handlers,
                orelse,
                finalbody,
                ..
            } => {
                collect_function_scopes(body, prefix, scopes, depth + 1);
                for handler in handlers {
                    collect_function_scopes(&handler.body, prefix, scopes, depth + 1);
                }
                collect_function_scopes(orelse, prefix, scopes, depth + 1);
                collect_function_scopes(finalbody, prefix, scopes, depth + 1);
            }
            Stmt::Match { cases, .. } => {
                for case in cases {
                    collect_function_scopes(&case.body, prefix, scopes, depth + 1);
                }
            }
            Stmt::Return(_)
            | Stmt::Delete(_)
            | Stmt::Assign { .. }
            | Stmt::AugAssign { .. }
            | Stmt::AnnAssign { .. }
            | Stmt::TypeAlias { .. }
            | Stmt::Raise { .. }
            | Stmt::Assert { .. }
            | Stmt::Import(_)
            | Stmt::ImportFrom { .. }
            | Stmt::Global(_)
            | Stmt::Nonlocal(_)
            | Stmt::Expr(_)
            | Stmt::Pass
            | Stmt::Break
            | Stmt::Continue => {}
        }
    }
}

fn qualify(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}.{name}")
    }
}

fn is_private(name: &str) -> bool {
    name.starts_with('_')
}

struct ImportTable {
    by_name: BTreeMap<String, u64>,
    next: u64,
}

impl ImportTable {
    const fn new() -> Self {
        Self {
            by_name: BTreeMap::new(),
            next: IMPORT_BASE,
        }
    }

    fn address_of(&mut self, symbol: &str) -> u64 {
        if let Some(addr) = self.by_name.get(symbol) {
            return *addr;
        }
        let addr: u64 = self.next;
        self.next = self.next.saturating_add(1);
        self.by_name.insert(symbol.to_owned(), addr);
        addr
    }

    fn into_sorted(self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self.by_name.into_iter().collect();
        out.sort_by_key(|(_, addr): &(String, u64)| *addr);
        out
    }
}

struct Emitter<'a> {
    base: u64,
    cursor: u64,
    instructions: Vec<NirInstr>,
    internal_by_name: &'a BTreeMap<String, u64>,
    imports: &'a mut ImportTable,
    depth: usize,
    overflowed: bool,
}

impl Emitter<'_> {
    const fn enter(&mut self) -> bool {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_EMIT_DEPTH {
            self.overflowed = true;
            return false;
        }
        true
    }

    const fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    const fn next_address(&mut self) -> u64 {
        let addr: u64 = self.cursor;
        self.cursor = self.cursor.saturating_add(1);
        addr
    }

    fn push(&mut self, op: NirOp, mnemonic: &str, operands: Vec<String>) -> u64 {
        let address: u64 = self.next_address();
        let byte_width: bool = operands
            .iter()
            .any(|operand: &String| operand.starts_with("byte "));
        let (reads_memory, writes_memory): (bool, bool) = match op {
            NirOp::Load => (true, false),
            NirOp::Store => (false, true),
            _ => (false, false),
        };
        self.instructions.push(NirInstr {
            address,
            op,
            mnemonic: mnemonic.to_owned(),
            operands,
            reads_memory,
            writes_memory,
            byte_width,
            source: SourceRef::new(SourceLang::Python, address),
        });
        address
    }

    fn resolve_call_target(&mut self, callee: &str) -> u64 {
        if let Some(addr) = self.internal_by_name.get(callee).copied() {
            return addr;
        }
        self.imports.address_of(callee)
    }
}

fn lift_scope(
    scope: &FunctionScope,
    internal_by_name: &BTreeMap<String, u64>,
    imports: &mut ImportTable,
) -> Result<NirFunction> {
    let mut emitter: Emitter<'_> = Emitter {
        base: scope.address,
        cursor: scope.address,
        instructions: Vec::new(),
        internal_by_name,
        imports,
        depth: 0,
        overflowed: false,
    };
    emit_body(&scope.body, &mut emitter);
    if emitter.overflowed {
        return Err(LiftError::DepthExceeded {
            limit: MAX_EMIT_DEPTH,
        });
    }
    emitter.push(NirOp::Return, "return", Vec::new());

    let end: u64 = emitter.cursor;
    Ok(NirFunction {
        name: scope.qualified_name.clone(),
        address: scope.address,
        end,
        is_export: scope.is_export,
        instructions: emitter.instructions,
        source: SourceRef::labelled(
            SourceLang::Python,
            scope.address,
            scope.qualified_name.clone(),
        ),
    })
}

fn emit_body(body: &[Stmt], emitter: &mut Emitter<'_>) {
    for stmt in body {
        emit_stmt(stmt, emitter);
    }
}

fn emit_each<'e>(exprs: impl IntoIterator<Item = &'e Expr>, emitter: &mut Emitter<'_>) {
    for expr in exprs {
        emit_expr(expr, emitter);
    }
}

fn emit_stmt(stmt: &Stmt, emitter: &mut Emitter<'_>) {
    if !emitter.enter() {
        return;
    }
    emit_stmt_inner(stmt, emitter);
    emitter.leave();
}

fn emit_stmt_inner(stmt: &Stmt, emitter: &mut Emitter<'_>) {
    match stmt {
        Stmt::Expr(expr) => emit_expr(expr, emitter),
        Stmt::Return(Some(expr)) => {
            emit_expr(expr, emitter);
            emitter.push(NirOp::Return, "return", Vec::new());
        }
        Stmt::Return(None) => {
            emitter.push(NirOp::Return, "return", Vec::new());
        }
        Stmt::Assign { targets, value, .. } => {
            emit_expr(value, emitter);
            for target in targets {
                emit_store_target(target, emitter);
            }
        }
        Stmt::AnnAssign { target, value, .. } => {
            if let Some(value) = value {
                emit_expr(value, emitter);
                emit_store_target(target, emitter);
            }
        }
        Stmt::AugAssign {
            target, op, value, ..
        } => {
            emit_expr(target, emitter);
            emit_expr(value, emitter);
            if let Some(binary_op) = binary_op(*op) {
                let operands: Vec<String> = augassign_operands(target);
                emitter.push(
                    NirOp::BinOp { op: binary_op },
                    binary_op.mnemonic(),
                    operands,
                );
            }
            emit_store_target(target, emitter);
        }
        Stmt::For {
            target,
            iter,
            body,
            orelse,
            ..
        } => emit_loop(Some(target), iter, body, orelse, emitter),
        Stmt::While {
            test, body, orelse, ..
        } => emit_loop(None, test, body, orelse, emitter),
        Stmt::If {
            test, body, orelse, ..
        } => {
            emit_expr(test, emitter);
            let branch: u64 = emitter.push(NirOp::CondBranch { target: None }, "if", Vec::new());
            emit_body(body, emitter);
            emit_body(orelse, emitter);
            let join: u64 = emitter.cursor;
            patch_forward(emitter, branch, join);
        }
        Stmt::With { items, body, .. } => {
            for item in items {
                emit_with_item(item, emitter);
            }
            emit_body(body, emitter);
        }
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        }
        | Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => {
            emit_body(body, emitter);
            for handler in handlers {
                emit_handler(handler, emitter);
            }
            emit_body(orelse, emitter);
            emit_body(finalbody, emitter);
        }
        Stmt::Match { subject, cases, .. } => {
            emit_expr(subject, emitter);
            for case in cases {
                emit_match_case(case, emitter);
            }
        }
        Stmt::Raise { exc, cause, .. } => {
            if let Some(exc) = exc {
                emit_expr(exc, emitter);
            }
            if let Some(cause) = cause {
                emit_expr(cause, emitter);
            }
            emitter.push(NirOp::Interrupt, "raise", Vec::new());
        }
        Stmt::Assert { test, msg, .. } => {
            emit_expr(test, emitter);
            if let Some(msg) = msg {
                emit_expr(msg, emitter);
            }
        }
        Stmt::Delete(exprs) => {
            for expr in exprs {
                emit_expr(expr, emitter);
            }
        }
        Stmt::Break => {
            emitter.push(NirOp::Branch { target: None }, "break", Vec::new());
        }
        Stmt::Continue => {
            emitter.push(NirOp::Branch { target: None }, "continue", Vec::new());
        }
        Stmt::FunctionDef { .. }
        | Stmt::ClassDef { .. }
        | Stmt::Import(_)
        | Stmt::ImportFrom { .. }
        | Stmt::Global(_)
        | Stmt::Nonlocal(_)
        | Stmt::TypeAlias { .. }
        | Stmt::Pass => {}
    }
}

fn emit_handler(handler: &ExceptHandler, emitter: &mut Emitter<'_>) {
    if let Some(typ) = &handler.typ {
        emit_expr(typ, emitter);
    }
    emit_body(&handler.body, emitter);
}

fn emit_match_case(case: &MatchCase, emitter: &mut Emitter<'_>) {
    if let Some(guard) = &case.guard {
        emit_expr(guard, emitter);
    }
    let branch: u64 = emitter.push(NirOp::CondBranch { target: None }, "case", Vec::new());
    emit_body(&case.body, emitter);
    let join: u64 = emitter.cursor;
    patch_forward(emitter, branch, join);
}

fn emit_with_item(item: &WithItem, emitter: &mut Emitter<'_>) {
    emit_expr(&item.context_expr, emitter);
    if let Some(vars) = &item.optional_vars {
        emit_store_target(vars, emitter);
    }
}

fn emit_loop(
    target: Option<&Expr>,
    iter: &Expr,
    body: &[Stmt],
    orelse: &[Stmt],
    emitter: &mut Emitter<'_>,
) {
    emit_expr(iter, emitter);
    let header: u64 = emitter.cursor;
    let guard: u64 = emitter.push(NirOp::CondBranch { target: None }, "loop", Vec::new());
    if let Some(target) = target {
        emit_store_target(target, emitter);
    }
    emit_body(body, emitter);
    emitter.push(
        NirOp::Branch {
            target: Some(header),
        },
        "jump",
        Vec::new(),
    );
    let after: u64 = emitter.cursor;
    patch_forward(emitter, guard, after);
    emit_body(orelse, emitter);
}

fn patch_forward(emitter: &mut Emitter<'_>, branch_address: u64, target: u64) {
    let index: usize = (branch_address.saturating_sub(emitter.base)) as usize;
    if let Some(instr) = emitter.instructions.get_mut(index)
        && let NirOp::CondBranch { target: slot } = &mut instr.op
    {
        *slot = Some(target);
    }
}

fn emit_expr(expr: &Expr, emitter: &mut Emitter<'_>) {
    if !emitter.enter() {
        return;
    }
    emit_expr_inner(expr, emitter);
    emitter.leave();
}

fn emit_expr_inner(expr: &Expr, emitter: &mut Emitter<'_>) {
    match expr {
        Expr::Call {
            func,
            args,
            keywords,
        } => emit_call(func, args, keywords, emitter),
        Expr::BinOp { left, op, right } => emit_binop(left, *op, right, emitter),
        Expr::BoolOp { values: items, .. }
        | Expr::Tuple { elts: items, .. }
        | Expr::List { elts: items, .. }
        | Expr::Set(items)
        | Expr::JoinedStr { values: items, .. } => emit_each(items, emitter),
        Expr::UnaryOp { operand: inner, .. }
        | Expr::Attribute { value: inner, .. }
        | Expr::Starred { value: inner, .. }
        | Expr::Await(inner)
        | Expr::YieldFrom(inner)
        | Expr::Yield(Some(inner))
        | Expr::FormattedValue { value: inner, .. }
        | Expr::Lambda { body: inner, .. } => emit_expr(inner, emitter),
        Expr::Compare {
            left, comparators, ..
        } => {
            emit_expr(left, emitter);
            emit_each(comparators, emitter);
        }
        Expr::Subscript { value, slice, .. } => {
            emit_expr(value, emitter);
            emit_expr(slice, emitter);
            emitter.push(NirOp::Load, "load", vec![subscript_operand(value)]);
        }
        Expr::IfExp { test, body, orelse } => {
            emit_each([test.as_ref(), body.as_ref(), orelse.as_ref()], emitter);
        }
        Expr::NamedExpr { target, value } => {
            emit_expr(value, emitter);
            emit_store_target(target, emitter);
        }
        Expr::Dict { keys, values } => {
            emit_each(keys.iter().flatten(), emitter);
            emit_each(values, emitter);
        }
        Expr::ListComp { elt, generators }
        | Expr::SetComp { elt, generators }
        | Expr::GeneratorExp { elt, generators } => {
            emit_comprehension(elt, None, generators, emitter);
        }
        Expr::DictComp {
            key,
            value,
            generators,
        } => emit_comprehension(key, Some(value), generators, emitter),
        Expr::Slice { lower, upper, step } => {
            emit_each(
                [lower, upper, step].into_iter().flatten().map(Box::as_ref),
                emitter,
            );
        }
        Expr::TStr { items, .. } => emit_tstr_items(items, emitter),
        Expr::Yield(None)
        | Expr::Constant { .. }
        | Expr::Name { .. }
        | Expr::EmptyDictUnpack
        | Expr::EmptyDictKeyUnpack => {}
    }
}

fn emit_tstr_items(items: &[TStrItem], emitter: &mut Emitter<'_>) {
    for item in items {
        let TStrItem::Interp {
            value, format_spec, ..
        } = item
        else {
            continue;
        };
        emit_expr(value, emitter);
        if let Some(spec) = format_spec {
            emit_expr(spec, emitter);
        }
    }
}

fn emit_comprehension(
    elt: &Expr,
    value: Option<&Expr>,
    generators: &[Comprehension],
    emitter: &mut Emitter<'_>,
) {
    for generator in generators {
        emit_expr(&generator.iter, emitter);
        let header: u64 = emitter.cursor;
        let guard: u64 = emitter.push(NirOp::CondBranch { target: None }, "loop", Vec::new());
        emit_store_target(&generator.target, emitter);
        for cond in &generator.ifs {
            emit_expr(cond, emitter);
        }
        emit_expr(elt, emitter);
        if let Some(value) = value {
            emit_expr(value, emitter);
        }
        emitter.push(
            NirOp::Branch {
                target: Some(header),
            },
            "jump",
            Vec::new(),
        );
        let after: u64 = emitter.cursor;
        patch_forward(emitter, guard, after);
    }
}

fn emit_call(func: &Expr, args: &[Expr], keywords: &[Keyword], emitter: &mut Emitter<'_>) {
    for arg in args {
        emit_expr(arg, emitter);
    }
    for keyword in keywords {
        emit_expr(&keyword.value, emitter);
    }
    if let Expr::Attribute { value, .. } = func {
        emit_expr(value, emitter);
    }
    let Some(name): Option<String> = callee_name(func) else {
        emit_expr(func, emitter);
        emitter.push(NirOp::IndirectCall, "call", Vec::new());
        return;
    };
    let target: u64 = emitter.resolve_call_target(&name);
    emitter.push(
        NirOp::Call {
            target: Some(target),
        },
        "call",
        vec![name],
    );
}

fn emit_binop(left: &Expr, op: BinOpKind, right: &Expr, emitter: &mut Emitter<'_>) {
    emit_expr(left, emitter);
    emit_expr(right, emitter);
    let Some(binary_op): Option<BinaryOp> = binary_op(op) else {
        return;
    };
    let operands: Vec<String> = binop_operands(left, right);
    emitter.push(
        NirOp::BinOp { op: binary_op },
        binary_op.mnemonic(),
        operands,
    );
}

fn emit_store_target(target: &Expr, emitter: &mut Emitter<'_>) {
    match target {
        Expr::Subscript { value, slice, .. } => {
            emit_expr(value, emitter);
            emit_expr(slice, emitter);
            emitter.push(NirOp::Store, "store", vec![subscript_operand(value)]);
        }
        Expr::Attribute { value, .. } => emit_expr(value, emitter),
        Expr::Tuple { elts, .. } | Expr::List { elts, .. } => {
            for elt in elts {
                emit_store_target(elt, emitter);
            }
        }
        Expr::Starred { value, .. } => emit_store_target(value, emitter),
        _ => {}
    }
}

const fn binary_op(op: BinOpKind) -> Option<BinaryOp> {
    Some(match op {
        BinOpKind::Add | BinOpKind::InplaceAdd => BinaryOp::Add,
        BinOpKind::Sub | BinOpKind::InplaceSub => BinaryOp::Sub,
        BinOpKind::Mul | BinOpKind::InplaceMul => BinaryOp::Mul,
        BinOpKind::TrueDiv
        | BinOpKind::FloorDiv
        | BinOpKind::OldDivide
        | BinOpKind::InplaceTrueDiv
        | BinOpKind::InplaceFloorDiv
        | BinOpKind::InplaceOldDivide => BinaryOp::Div,
        BinOpKind::Mod | BinOpKind::InplaceMod => BinaryOp::Rem,
        BinOpKind::BitAnd | BinOpKind::InplaceBitAnd => BinaryOp::And,
        BinOpKind::BitOr | BinOpKind::InplaceBitOr => BinaryOp::Or,
        BinOpKind::BitXor | BinOpKind::InplaceBitXor => BinaryOp::Xor,
        BinOpKind::Lshift | BinOpKind::InplaceLshift => BinaryOp::Shl,
        BinOpKind::Rshift | BinOpKind::InplaceRshift => BinaryOp::Shr,
        BinOpKind::MatMul
        | BinOpKind::Pow
        | BinOpKind::InplaceMatMul
        | BinOpKind::InplacePow
        | BinOpKind::Generic(_) => return None,
    })
}

fn binop_operands(left: &Expr, right: &Expr) -> Vec<String> {
    let mut operands: Vec<String> = Vec::new();
    if is_byte_operand(left) || is_byte_operand(right) {
        operands.push("byte stack".to_owned());
    }
    operands
}

fn augassign_operands(target: &Expr) -> Vec<String> {
    if is_byte_operand(target) {
        vec!["byte stack".to_owned()]
    } else {
        Vec::new()
    }
}

fn is_byte_operand(expr: &Expr) -> bool {
    match expr {
        Expr::Subscript { .. } => true,
        Expr::Call { func, .. } => matches!(callee_name(func).as_deref(), Some("ord")),
        Expr::UnaryOp { operand, .. } => is_byte_operand(operand),
        _ => false,
    }
}

fn subscript_operand(value: &Expr) -> String {
    let container: String = base_identifier(value).unwrap_or_else(|| "mem".to_owned());
    format!("byte [{container}]")
}

fn base_identifier(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name { id, .. } => Some(id.clone()),
        Expr::Attribute { value, attr, .. } => {
            base_identifier(value).map(|base: String| format!("{base}.{attr}"))
        }
        Expr::Subscript { value, .. } => base_identifier(value),
        _ => None,
    }
}

fn callee_name(func: &Expr) -> Option<String> {
    match func {
        Expr::Name { id, .. } => Some(id.clone()),
        Expr::Attribute { value, attr, .. } => Some(
            base_identifier(value)
                .map_or_else(|| attr.clone(), |base: String| format!("{base}.{attr}")),
        ),
        _ => None,
    }
}
