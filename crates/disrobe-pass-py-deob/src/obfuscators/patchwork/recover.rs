use ruff_python_ast::visitor::transformer::{Transformer, walk_expr as transform_walk_expr};
use ruff_python_ast::visitor::{Visitor, walk_expr as visit_walk_expr};
use ruff_python_ast::{
    AtomicNodeIndex, Expr, ExprBooleanLiteral, ExprCall, ExprContext, ExprName, ModModule, Stmt,
    StmtAssign,
};
use ruff_python_codegen::{Generator, Stylist};
use ruff_python_parser::{Mode, ParseOptions, parse};

use super::value::{ConstValue, eval_const};
use crate::error::{Error, Result};

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RecoverStats {
    pub(crate) tautologies_folded: usize,
    pub(crate) pool_literals_inlined: usize,
    pub(crate) runtime_defs_removed: usize,
}

#[derive(Debug, Default, Clone)]
struct RuntimeBindings {
    seed_name: Option<String>,
    pool_name: Option<String>,
    str_decoder: Option<String>,
    bytes_decoder: Option<String>,
    decode_entry: Option<String>,
}

pub(crate) fn reverse_source_transforms(source: &str) -> Result<(String, RecoverStats)> {
    let parsed: ruff_python_parser::Parsed<ruff_python_ast::Mod> =
        parse(source, ParseOptions::from(Mode::Module))
            .map_err(|e| Error::AstCleanup(format!("ruff parse failed: {e}")))?;
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), source);
    let mut module: ModModule = match parsed.into_syntax() {
        ruff_python_ast::Mod::Module(m) => m,
        ruff_python_ast::Mod::Expression(_) => {
            return Err(Error::AstCleanup("expected module".to_owned()));
        }
    };

    let mut stats: RecoverStats = RecoverStats::default();
    let bindings: RuntimeBindings = discover_runtime_bindings(&module);
    let pool: Option<Vec<LiteralEntry>> = bindings
        .pool_name
        .as_deref()
        .and_then(|name: &str| extract_pool(&module, name));
    let decoders: DecoderNames = DecoderNames {
        str_decoder: bindings.str_decoder.clone(),
        bytes_decoder: bindings.bytes_decoder.clone(),
    };

    for stmt in &mut module.body {
        if let Some(seed) = bindings.seed_name.as_deref() {
            fold_seed_in_stmt(stmt, seed, &mut stats);
        }
        if let Some(entries) = pool.as_ref() {
            inline_pool_in_stmt(stmt, entries, &decoders, &mut stats);
        }
    }

    prune_dead_branches_recursive(&mut module.body);

    for _ in 0..8 {
        let referenced: ReferenceSet = collect_referenced_names(&module);
        let before: usize = module.body.len();
        module.body.retain(|stmt: &Stmt| {
            let keep: bool = !is_dead_runtime_artifact(stmt, &bindings, &referenced);
            if !keep {
                stats.runtime_defs_removed += 1;
            }
            keep
        });
        if module.body.len() == before {
            break;
        }
    }

    let mut emitted: String = String::with_capacity(source.len());
    let mut first: bool = true;
    for stmt in &module.body {
        if !first {
            emitted.push('\n');
        }
        first = false;
        emitted.push_str(&Generator::from(&stylist).stmt(stmt));
    }
    if !emitted.ends_with('\n') {
        emitted.push('\n');
    }
    Ok((emitted, stats))
}

fn discover_runtime_bindings(module: &ModModule) -> RuntimeBindings {
    let mut bindings: RuntimeBindings = RuntimeBindings::default();
    for stmt in &module.body {
        match stmt {
            Stmt::Assign(StmtAssign { targets, value, .. }) => {
                if let [Expr::Name(name)] = targets.as_slice() {
                    if bindings.seed_name.is_none() && is_seed_expr(value) {
                        bindings.seed_name = Some(name.id.to_string());
                    }
                    if bindings.pool_name.is_none() && looks_like_pool(value) {
                        bindings.pool_name = Some(name.id.to_string());
                    }
                }
            }
            Stmt::FunctionDef(func) => {
                if let Some(inner) = decode_str_inner(func) {
                    bindings.str_decoder = Some(func.name.to_string());
                    bindings.decode_entry = Some(inner);
                }
            }
            _ => {}
        }
    }
    if let Some(entry) = bindings.decode_entry.clone() {
        for stmt in &module.body {
            let Stmt::FunctionDef(func): &Stmt = stmt else {
                continue;
            };
            if Some(func.name.as_str()) == bindings.str_decoder.as_deref() {
                continue;
            }
            if returns_direct_call_to(func, &entry) {
                bindings.bytes_decoder = Some(func.name.to_string());
                break;
            }
        }
        if bindings.bytes_decoder.is_none() {
            bindings.bytes_decoder = Some(entry);
        }
    }
    bindings
}

fn returns_direct_call_to(func: &ruff_python_ast::StmtFunctionDef, callee: &str) -> bool {
    if func.parameters.args.len() != 2 {
        return false;
    }
    let [Stmt::Return(ret)]: &[Stmt] = func.body.as_slice() else {
        return false;
    };
    let Some(Expr::Call(call)): Option<&Expr> = ret.value.as_deref() else {
        return false;
    };
    matches!(call.func.as_ref(), Expr::Name(ExprName { id, .. }) if id.as_str() == callee)
}

fn is_seed_expr(expr: &Expr) -> bool {
    let Expr::BinOp(b): &Expr = expr else {
        return false;
    };
    if !matches!(b.op, ruff_python_ast::Operator::BitAnd) {
        return false;
    }
    let Expr::Call(call): &Expr = b.left.as_ref() else {
        return false;
    };
    let Expr::Name(ExprName { id, .. }): &Expr = call.func.as_ref() else {
        return false;
    };
    if id.as_str() != "id" {
        return false;
    }
    matches!(call.arguments.args.first(), Some(Expr::Name(n)) if n.id.as_str() == "int")
}

fn looks_like_pool(expr: &Expr) -> bool {
    let Some(ConstValue::Tuple(entries)): Option<ConstValue> = eval_const(expr) else {
        return false;
    };
    if entries.is_empty() {
        return false;
    }
    entries.iter().all(|entry: &ConstValue| {
        matches!(entry, ConstValue::Tuple(fields) if fields.len() == 6)
            && parse_pool_entry(entry).is_some()
    })
}

fn decode_str_inner(func: &ruff_python_ast::StmtFunctionDef) -> Option<String> {
    if func.parameters.args.len() != 2 {
        return None;
    }
    let [Stmt::Return(ret)]: &[Stmt] = func.body.as_slice() else {
        return None;
    };
    let Expr::Call(decode_call): &Expr = ret.value.as_ref()? else {
        return None;
    };
    let Expr::Attribute(attr): &Expr = decode_call.func.as_ref() else {
        return None;
    };
    if attr.attr.as_str() != "decode" {
        return None;
    }
    let Expr::Call(inner_call): &Expr = attr.value.as_ref() else {
        return None;
    };
    let Expr::Name(ExprName { id, .. }): &Expr = inner_call.func.as_ref() else {
        return None;
    };
    Some(id.to_string())
}

#[derive(Debug, Default, Clone)]
struct DecoderNames {
    str_decoder: Option<String>,
    bytes_decoder: Option<String>,
}

#[derive(Debug, Clone)]
struct LiteralEntry {
    data_chunks: Vec<Vec<u8>>,
    key_chunks: Vec<Vec<u8>>,
    data_order: Vec<usize>,
    key_order: Vec<usize>,
    rotation: usize,
    mode: i64,
}

fn extract_pool(module: &ModModule, pool_name: &str) -> Option<Vec<LiteralEntry>> {
    for stmt in &module.body {
        let Stmt::Assign(StmtAssign { targets, value, .. }): &Stmt = stmt else {
            continue;
        };
        let [Expr::Name(name)]: &[Expr] = targets.as_slice() else {
            continue;
        };
        if name.id.as_str() != pool_name {
            continue;
        }
        let ConstValue::Tuple(entries): ConstValue = eval_const(value)? else {
            return None;
        };
        let mut out: Vec<LiteralEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            out.push(parse_pool_entry(&entry)?);
        }
        return Some(out);
    }
    None
}

fn parse_pool_entry(entry: &ConstValue) -> Option<LiteralEntry> {
    let ConstValue::Tuple(fields): &ConstValue = entry else {
        return None;
    };
    let [
        data_chunks,
        key_chunks,
        data_order,
        key_order,
        rotation,
        mode,
    ]: &[ConstValue] = fields.as_slice()
    else {
        return None;
    };
    Some(LiteralEntry {
        data_chunks: bytes_tuple(data_chunks)?,
        key_chunks: bytes_tuple(key_chunks)?,
        data_order: usize_tuple(data_order)?,
        key_order: usize_tuple(key_order)?,
        rotation: usize::try_from(int_value(rotation)?).ok()?,
        mode: int_value(mode)?,
    })
}

fn bytes_tuple(value: &ConstValue) -> Option<Vec<Vec<u8>>> {
    let ConstValue::Tuple(items): &ConstValue = value else {
        return None;
    };
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(items.len());
    for item in items {
        let ConstValue::Bytes(b): &ConstValue = item else {
            return None;
        };
        out.push(b.clone());
    }
    Some(out)
}

fn usize_tuple(value: &ConstValue) -> Option<Vec<usize>> {
    let ConstValue::Tuple(items): &ConstValue = value else {
        return None;
    };
    let mut out: Vec<usize> = Vec::with_capacity(items.len());
    for item in items {
        out.push(usize::try_from(int_value(item)?).ok()?);
    }
    Some(out)
}

const fn int_value(value: &ConstValue) -> Option<i64> {
    match value {
        ConstValue::Int(n) => Some(*n),
        _ => None,
    }
}

fn decode_entry(entry: &LiteralEntry) -> Option<Vec<u8>> {
    let data: Vec<u8> = join_chunks(&entry.data_chunks, &entry.data_order)?;
    let data: Vec<u8> = unrotate(&data, entry.rotation);
    let key: Vec<u8> = join_chunks(&entry.key_chunks, &entry.key_order)?;
    if key.is_empty() {
        return Some(data);
    }
    let _ = entry.mode;
    Some(
        data.iter()
            .enumerate()
            .map(|(i, &b): (usize, &u8)| b ^ key[i % key.len()])
            .collect(),
    )
}

fn join_chunks(chunks: &[Vec<u8>], order: &[usize]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    for &idx in order {
        out.extend_from_slice(chunks.get(idx)?);
    }
    Some(out)
}

fn unrotate(data: &[u8], amount: usize) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }
    let amount: usize = amount % data.len();
    if amount == 0 {
        return data.to_vec();
    }
    let split: usize = data.len() - amount;
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[split..]);
    out.extend_from_slice(&data[..split]);
    out
}

struct PoolInliner<'a> {
    entries: &'a [LiteralEntry],
    decoders: &'a DecoderNames,
    inlined: std::cell::Cell<usize>,
}

impl Transformer for PoolInliner<'_> {
    fn visit_expr(&self, expr: &mut Expr) {
        transform_walk_expr(self, expr);
        if let Some(replacement) = pool_call_replacement(expr, self.entries, self.decoders) {
            *expr = replacement;
            self.inlined.set(self.inlined.get() + 1);
        }
    }
}

fn inline_pool_in_stmt(
    stmt: &mut Stmt,
    entries: &[LiteralEntry],
    decoders: &DecoderNames,
    stats: &mut RecoverStats,
) {
    let inliner: PoolInliner<'_> = PoolInliner {
        entries,
        decoders,
        inlined: std::cell::Cell::new(0),
    };
    inliner.visit_stmt(stmt);
    stats.pool_literals_inlined += inliner.inlined.get();
}

fn pool_call_replacement(
    expr: &Expr,
    entries: &[LiteralEntry],
    decoders: &DecoderNames,
) -> Option<Expr> {
    let Expr::Call(ExprCall {
        func, arguments, ..
    }): &Expr = expr
    else {
        return None;
    };
    let Expr::Name(ExprName { id, .. }): &Expr = func.as_ref() else {
        return None;
    };
    let is_str: bool = decoders.str_decoder.as_deref() == Some(id.as_str());
    let is_bytes: bool = decoders.bytes_decoder.as_deref() == Some(id.as_str());
    if !is_str && !is_bytes {
        return None;
    }
    let [pool_arg, index_arg]: &[Expr] = arguments.args.as_ref() else {
        return None;
    };
    if !matches!(pool_arg, Expr::Name(_)) {
        return None;
    }
    let ConstValue::Int(idx): ConstValue = eval_const(index_arg)? else {
        return None;
    };
    let entry: &LiteralEntry = entries.get(usize::try_from(idx).ok()?)?;
    let decoded: Vec<u8> = decode_entry(entry)?;
    if is_str {
        let text: String = String::from_utf8(decoded).ok()?;
        Some(string_literal(&text))
    } else {
        Some(bytes_literal(&decoded))
    }
}

fn string_literal(text: &str) -> Expr {
    Expr::StringLiteral(ruff_python_ast::ExprStringLiteral {
        range: ruff_text_size::TextRange::default(),
        node_index: AtomicNodeIndex::default(),
        value: ruff_python_ast::StringLiteralValue::single(ruff_python_ast::StringLiteral {
            range: ruff_text_size::TextRange::default(),
            node_index: AtomicNodeIndex::default(),
            value: text.to_owned().into_boxed_str(),
            flags: ruff_python_ast::StringLiteralFlags::empty(),
        }),
    })
}

fn bytes_literal(data: &[u8]) -> Expr {
    Expr::BytesLiteral(ruff_python_ast::ExprBytesLiteral {
        range: ruff_text_size::TextRange::default(),
        node_index: AtomicNodeIndex::default(),
        value: ruff_python_ast::BytesLiteralValue::single(ruff_python_ast::BytesLiteral {
            range: ruff_text_size::TextRange::default(),
            node_index: AtomicNodeIndex::default(),
            value: data.to_vec().into_boxed_slice(),
            flags: ruff_python_ast::BytesLiteralFlags::empty(),
        }),
    })
}

struct SeedFolder<'a> {
    seed_name: &'a str,
    folded: std::cell::Cell<usize>,
}

impl Transformer for SeedFolder<'_> {
    fn visit_expr(&self, expr: &mut Expr) {
        transform_walk_expr(self, expr);
        if let Some(value) = seed_tautology_value(expr, self.seed_name) {
            *expr = bool_literal(value);
            self.folded.set(self.folded.get() + 1);
        }
        simplify_boolop_identity(expr);
    }
}

fn fold_seed_in_stmt(stmt: &mut Stmt, seed_name: &str, stats: &mut RecoverStats) {
    let folder: SeedFolder<'_> = SeedFolder {
        seed_name,
        folded: std::cell::Cell::new(0),
    };
    folder.visit_stmt(stmt);
    stats.tautologies_folded += folder.folded.get();
}

fn simplify_boolop_identity(expr: &mut Expr) {
    let Expr::BoolOp(boolop): &mut Expr = expr else {
        return;
    };
    let identity: bool = matches!(boolop.op, ruff_python_ast::BoolOp::And);
    let values: Vec<Expr> = std::mem::take(&mut boolop.values);
    let mut kept: Vec<Expr> = Vec::with_capacity(values.len());
    let mut short_circuit: Option<bool> = None;
    for value in values {
        match literal_bool(&value) {
            Some(b) if b == identity => {}
            Some(b) => {
                short_circuit = Some(b);
                break;
            }
            None => kept.push(value),
        }
    }
    if let Some(b) = short_circuit {
        *expr = bool_literal(b);
        return;
    }
    match kept.len() {
        0 => *expr = bool_literal(identity),
        1 => {
            *expr = kept
                .into_iter()
                .next()
                .unwrap_or_else(|| bool_literal(identity));
        }
        _ => boolop.values = kept,
    }
}

const fn literal_bool(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::BooleanLiteral(ExprBooleanLiteral { value, .. }) => Some(*value),
        _ => None,
    }
}

fn seed_tautology_value(expr: &Expr, seed_name: &str) -> Option<bool> {
    let Expr::Compare(compare): &Expr = expr else {
        return None;
    };
    if compare.ops.len() != 1 || compare.comparators.len() != 1 {
        return None;
    }
    if !matches!(compare.ops.first()?, ruff_python_ast::CmpOp::Eq) {
        return None;
    }
    let ConstValue::Int(0): ConstValue = eval_const(compare.comparators.first()?)? else {
        return None;
    };
    let Expr::BinOp(modulo): &Expr = compare.left.as_ref() else {
        return None;
    };
    if !matches!(modulo.op, ruff_python_ast::Operator::Mod) {
        return None;
    }
    if !references_seed(&modulo.left, seed_name) {
        return None;
    }
    let const_offset: i64 = trailing_const_offset(&modulo.left);
    Some(const_offset == 0)
}

fn trailing_const_offset(expr: &Expr) -> i64 {
    let Expr::BinOp(b): &Expr = expr else {
        return 0;
    };
    if matches!(
        b.op,
        ruff_python_ast::Operator::Add | ruff_python_ast::Operator::Sub
    ) && let Some(ConstValue::Int(n)) = eval_const(&b.right)
    {
        return n;
    }
    0
}

fn references_seed(expr: &Expr, seed_name: &str) -> bool {
    match expr {
        Expr::Name(ExprName { id, .. }) => id.as_str() == seed_name,
        Expr::BinOp(b) => {
            references_seed(&b.left, seed_name) || references_seed(&b.right, seed_name)
        }
        Expr::UnaryOp(u) => references_seed(&u.operand, seed_name),
        Expr::Call(c) => c
            .arguments
            .args
            .iter()
            .any(|arg: &Expr| references_seed(arg, seed_name)),
        _ => false,
    }
}

fn bool_literal(value: bool) -> Expr {
    Expr::BooleanLiteral(ExprBooleanLiteral {
        range: ruff_text_size::TextRange::default(),
        node_index: AtomicNodeIndex::default(),
        value,
    })
}

type ReferenceSet = std::collections::BTreeMap<String, usize>;

fn prune_dead_branches_recursive(body: &mut Vec<Stmt>) {
    for stmt in body.iter_mut() {
        match stmt {
            Stmt::FunctionDef(func) => prune_dead_branches_recursive(&mut func.body),
            Stmt::ClassDef(class) => prune_dead_branches_recursive(&mut class.body),
            Stmt::If(i) => {
                prune_dead_branches_recursive(&mut i.body);
                for clause in &mut i.elif_else_clauses {
                    prune_dead_branches_recursive(&mut clause.body);
                }
            }
            Stmt::While(w) => prune_dead_branches_recursive(&mut w.body),
            Stmt::For(f) => prune_dead_branches_recursive(&mut f.body),
            Stmt::With(w) => prune_dead_branches_recursive(&mut w.body),
            Stmt::Try(t) => {
                prune_dead_branches_recursive(&mut t.body);
                prune_dead_branches_recursive(&mut t.orelse);
                prune_dead_branches_recursive(&mut t.finalbody);
            }
            _ => {}
        }
    }
    crate::dead_branch::prune(body);
}

struct LoadCounter {
    counts: ReferenceSet,
}

impl<'a> Visitor<'a> for LoadCounter {
    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Name(ExprName { id, ctx, .. }) = expr
            && matches!(ctx, ExprContext::Load)
        {
            *self.counts.entry(id.to_string()).or_insert(0) += 1;
        }
        visit_walk_expr(self, expr);
    }
}

fn collect_referenced_names(module: &ModModule) -> ReferenceSet {
    let mut counter: LoadCounter = LoadCounter {
        counts: ReferenceSet::new(),
    };
    for stmt in &module.body {
        counter.visit_stmt(stmt);
    }
    counter.counts
}

fn is_dead_runtime_artifact(
    stmt: &Stmt,
    bindings: &RuntimeBindings,
    referenced: &ReferenceSet,
) -> bool {
    let name: &str = match stmt {
        Stmt::Assign(StmtAssign { targets, .. }) => {
            let [Expr::Name(n)]: &[Expr] = targets.as_slice() else {
                return false;
            };
            n.id.as_str()
        }
        Stmt::FunctionDef(func) => func.name.as_str(),
        _ => return false,
    };
    let is_runtime_root: bool = bindings.seed_name.as_deref() == Some(name)
        || bindings.pool_name.as_deref() == Some(name)
        || bindings.str_decoder.as_deref() == Some(name)
        || bindings.bytes_decoder.as_deref() == Some(name)
        || is_runtime_helper_name(name, referenced, bindings);
    if !is_runtime_root {
        return false;
    }
    referenced.get(name).copied().unwrap_or(0) == 0
}

fn is_runtime_helper_name(
    name: &str,
    referenced: &ReferenceSet,
    bindings: &RuntimeBindings,
) -> bool {
    if !name.starts_with('_') {
        return false;
    }
    if referenced.get(name).copied().unwrap_or(0) != 0 {
        return false;
    }
    let _ = bindings;
    true
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn parse(source: &str) -> ModModule {
        let parsed: ruff_python_parser::Parsed<ruff_python_ast::Mod> =
            ruff_python_parser::parse(source, ParseOptions::from(Mode::Module)).expect("parse");
        match parsed.into_syntax() {
            ruff_python_ast::Mod::Module(m) => m,
            ruff_python_ast::Mod::Expression(_) => panic!("expected module"),
        }
    }

    #[test]
    fn reference_counting_descends_into_fstrings() {
        let module: ModModule = parse("_helper()\nx = f\"{_target(1)}\"\n");
        let refs: ReferenceSet = collect_referenced_names(&module);
        assert_eq!(
            refs.get("_target").copied().unwrap_or(0),
            1,
            "name used only inside an f-string must be counted as referenced"
        );
        assert_eq!(refs.get("_helper").copied().unwrap_or(0), 1);
    }

    #[test]
    fn reference_counting_descends_into_match_and_comprehension() {
        let module: ModModule = parse(
            "match v:\n    case 0:\n        y = _in_case()\n    case _:\n        pass\nz = [_in_comp(i) for i in range(3)]\n",
        );
        let refs: ReferenceSet = collect_referenced_names(&module);
        assert_eq!(refs.get("_in_case").copied().unwrap_or(0), 1);
        assert_eq!(refs.get("_in_comp").copied().unwrap_or(0), 1);
    }

    #[test]
    fn runtime_helper_referenced_only_in_fstring_is_kept() {
        let source: &str = "def _decoder():\n    return 'x'\nprint(f\"{_decoder()}\")\n";
        let (out, _stats): (String, RecoverStats) =
            reverse_source_transforms(source).expect("reverse");
        assert!(
            out.contains("def _decoder"),
            "helper referenced only inside an f-string was wrongly pruned:\n{out}"
        );
    }
}
