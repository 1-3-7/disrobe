use std::collections::{BTreeMap, BTreeSet};

use crate::decompile::Fidelity;
use crate::error::Result;
use crate::obfuscator::hercules_vm::{Devirtualized, devirtualize};
use crate::obfuscator::prometheus_vm_ast::{
    AssignTarget, BinOp, Block, Expr, ExprKind, LocalId, Parser, Span, Stat, StatKind, TableField,
    UnOp, Var,
};

const MAX_ROUNDS: usize = 1024;
const MAX_FOLDED_STRING_BYTES: usize = 1 << 20;
const MAX_CAESAR_KEY: i64 = 1 << 20;

const WATERMARK: &str = "Obfuscated by Hercules";

const PREAMBLE_TEMPLATE: &str = "if not math.ldexp then math.ldexp = function(x, n) return x * 2 ^ n end end \
if not math.frexp then math.frexp = function(x) if x == 0 then return 0, 0 end \
local exp = math.floor(math.log(math.abs(x)) / math.log(2)) + 1 local mantissa = x / 2 ^ exp \
return mantissa, exp end end \
if not loadstring and load then loadstring = load end \
if not loadstring then loadstring = function(s) return load(s) end end";

const ALNUM_TEST: &str =
    "return (b >= 48 and b <= 57) or (b >= 65 and b <= 90) or (b >= 97 and b <= 122)";

const DECODER_BODY_HEAD: &str = "local r = {} for i = 1, #c do local b = c:byte(i) if ";

const DECODER_BODY_TAIL: &str = " then local n \
if b >= 48 and b <= 57 then n = ((b - 48 - o + 10) % 10) + 48 \
elseif b >= 65 and b <= 90 then n = ((b - 65 - o + 26) % 26) + 65 \
elseif b >= 97 and b <= 122 then n = ((b - 97 - o + 26) % 26) + 97 end \
table.insert(r, string.char(n)) else table.insert(r, string.char(b)) end end \
return table.concat(r)";

const VM_MARKERS: [&str; 3] = ["BcToState", "gChunk", "Protected By Hercules"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    Preamble,
    WrapInFunction,
    AntiTamper,
    GarbageCode,
    ControlFlow,
    VirtualMachine,
    GlobalAliases,
    StringToExpressions,
    StringConcat,
    StringEncoding,
    DecoderHelpers,
    DynamicCode,
    OpaquePredicates,
    FunctionInlining,
}

const RULE_ORDER: [Layer; 14] = [
    Layer::Preamble,
    Layer::WrapInFunction,
    Layer::AntiTamper,
    Layer::GarbageCode,
    Layer::ControlFlow,
    Layer::VirtualMachine,
    Layer::GlobalAliases,
    Layer::StringToExpressions,
    Layer::StringConcat,
    Layer::StringEncoding,
    Layer::DecoderHelpers,
    Layer::DynamicCode,
    Layer::OpaquePredicates,
    Layer::FunctionInlining,
];

impl Layer {
    const fn name(self) -> &'static str {
        match self {
            Self::Preamble => "polyfill-preamble-and-watermark",
            Self::WrapInFunction => "wrap-in-function",
            Self::AntiTamper => "anti-tamper",
            Self::GarbageCode => "garbage-code",
            Self::ControlFlow => "control-flow-wrapper",
            Self::VirtualMachine => "vm-devirtualize",
            Self::GlobalAliases => "global-alias-block",
            Self::StringToExpressions => "string-to-expressions",
            Self::StringConcat => "string-concat-fold",
            Self::StringEncoding => "string-encoding",
            Self::DecoderHelpers => "string-decoder-helpers",
            Self::DynamicCode => "dynamic-code",
            Self::OpaquePredicates => "opaque-predicates",
            Self::FunctionInlining => "function-inlining",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SourceRecovery {
    pub(crate) source: String,
    pub(crate) passes: Vec<String>,
    pub(crate) residual: Vec<String>,
    pub(crate) strings: Vec<String>,
}

pub(crate) fn recover_source(src: &str) -> SourceRecovery {
    let templates: Templates = match Templates::build() {
        Ok(templates) => templates,
        Err(err) => {
            return SourceRecovery {
                source: src.to_owned(),
                passes: Vec::new(),
                residual: vec![format!(
                    "hercules: internal template parse failed ({err}); no source layer was removed"
                )],
                strings: Vec::new(),
            };
        }
    };
    let mut current: String = src.to_owned();
    let mut counts: BTreeMap<Layer, usize> = BTreeMap::new();
    let mut strings: BTreeSet<String> = BTreeSet::new();
    let mut residual: BTreeSet<String> = BTreeSet::new();
    let mut evidence: bool = false;
    let mut rounds: usize = 0;
    loop {
        let mut parser: Parser<'_> = match Parser::new(&current) {
            Ok(parser) => parser,
            Err(err) => {
                residual.insert(format!(
                    "hercules: source does not parse as Lua 5.4 ({err}); remaining layers were not removed"
                ));
                break;
            }
        };
        let chunk: Block = match parser.parse_chunk() {
            Ok(chunk) => chunk,
            Err(err) => {
                residual.insert(format!(
                    "hercules: source does not parse as Lua 5.4 ({err}); remaining layers were not removed"
                ));
                break;
            }
        };
        let ctx: Ctx<'_> = Ctx::new(&current, &chunk, &parser, &templates, evidence);
        let mut fired: Option<(Layer, RuleOutcome)> = None;
        let mut blocked: Vec<String> = Vec::new();
        for layer in RULE_ORDER {
            let outcome: RuleOutcome = ctx.run(layer);
            if outcome.groups.is_empty() {
                blocked.extend(outcome.blocked);
            } else {
                fired = Some((layer, outcome));
                break;
            }
        }
        let Some((layer, outcome)) = fired else {
            residual.extend(blocked);
            if VM_MARKERS
                .iter()
                .all(|marker: &&str| current.contains(marker))
            {
                residual.insert(
                    "hercules: VMGenerator layer (BcToState/gChunk bytecode interpreter) remains; the virtualized program is not lifted back to Lua source"
                        .to_owned(),
                );
            }
            break;
        };
        rounds += 1;
        if rounds > MAX_ROUNDS {
            residual.insert(format!(
                "hercules: rewrite budget of {MAX_ROUNDS} rounds exhausted while removing {}",
                layer.name()
            ));
            break;
        }
        let Some(next) = apply_groups(&current, outcome.groups) else {
            residual.insert(format!(
                "hercules: {} rewrite produced no applicable edit",
                layer.name()
            ));
            break;
        };
        if next == current {
            residual.insert(format!(
                "hercules: {} rewrite made no progress",
                layer.name()
            ));
            break;
        }
        if Parser::new(&next)
            .and_then(|mut p: Parser<'_>| p.parse_chunk())
            .is_err()
        {
            residual.insert(format!(
                "hercules: {} rewrite would leave unparseable source, so it was not applied",
                layer.name()
            ));
            break;
        }
        if matches!(layer, Layer::WrapInFunction | Layer::AntiTamper) {
            evidence = true;
        }
        for decoded in outcome.strings {
            strings.insert(decoded);
        }
        residual.extend(outcome.residual);
        *counts.entry(layer).or_insert(0) += 1;
        current = next;
    }
    let passes: Vec<String> = counts
        .iter()
        .map(|(layer, rounds): (&Layer, &usize)| {
            format!("hercules-{} ({rounds} round(s))", layer.name())
        })
        .collect();
    let mut source: String = layout(&current).unwrap_or(current).trim().to_owned();
    source.push('\n');
    SourceRecovery {
        source,
        passes,
        residual: residual.into_iter().collect(),
        strings: strings.into_iter().collect(),
    }
}

fn layout(src: &str) -> Option<String> {
    let mut parser: Parser<'_> = Parser::new(src).ok()?;
    let chunk: Block = parser.parse_chunk().ok()?;
    let mut walker: Walker<'_, '_> = Walker {
        src,
        facts: Facts::default(),
    };
    walker.block(&chunk, Vec::new());
    let bytes: &[u8] = src.as_bytes();
    let mut edits: Vec<Vec<Edit>> = Vec::new();
    for (path, block) in &walker.facts.blocks {
        let depth: usize = path.len();
        let indent: String = "  ".repeat(depth);
        let (Some(first), Some(last)) = (block.stats.first(), block.stats.last()) else {
            continue;
        };
        let lead_end: usize = first.span.start as usize;
        let lead_start: usize = gap_start(bytes, lead_end);
        let lead: String = if depth == 0 {
            String::new()
        } else {
            format!("\n{indent}")
        };
        edits.push(vec![Edit {
            start: lead_start,
            end: lead_end,
            text: lead,
        }]);
        for pair in block.stats.windows(2) {
            let start: usize = pair[0].span.end as usize;
            let end: usize = pair[1].span.start as usize;
            let gap: &str = src.get(start..end)?;
            if gap.contains("--")
                || !gap
                    .bytes()
                    .all(|b: u8| b.is_ascii_whitespace() || b == b';')
            {
                continue;
            }
            let separator: &str = if bytes.get(end) == Some(&b'(') {
                ";"
            } else {
                ""
            };
            edits.push(vec![Edit {
                start,
                end,
                text: format!("{separator}\n{indent}"),
            }]);
        }
        if depth > 0 {
            let tail_start: usize = last.span.end as usize;
            let tail_end: usize = gap_end(bytes, tail_start);
            edits.push(vec![Edit {
                start: tail_start,
                end: tail_end,
                text: format!("\n{}", "  ".repeat(depth - 1)),
            }]);
        }
    }
    let laid_out: String = apply_groups_exact(src, edits)?;
    Parser::new(&laid_out)
        .and_then(|mut p: Parser<'_>| p.parse_chunk())
        .ok()
        .map(|_| laid_out)
}

fn gap_start(bytes: &[u8], end: usize) -> usize {
    let mut start: usize = end;
    while start > 0 && (bytes[start - 1].is_ascii_whitespace() || bytes[start - 1] == b';') {
        start -= 1;
    }
    start
}

fn gap_end(bytes: &[u8], start: usize) -> usize {
    let mut end: usize = start;
    while end < bytes.len() && (bytes[end].is_ascii_whitespace() || bytes[end] == b';') {
        end += 1;
    }
    end
}

pub(crate) fn function_literal_count(src: &str) -> Result<usize> {
    let mut parser: Parser<'_> = Parser::new(src)?;
    let chunk: Block = parser.parse_chunk()?;
    let mut count: usize = 0;
    for_each_expr_in_block(&chunk, &mut |expr: &Expr| {
        if matches!(expr.kind, ExprKind::Function { .. }) {
            count += 1;
        }
    });
    Ok(count)
}

#[derive(Debug)]
struct Templates {
    preamble: Vec<String>,
    alnum: String,
    decoder_named: String,
    decoder_inline: String,
}

impl Templates {
    fn build() -> Result<Self> {
        let preamble: Vec<String> = {
            let mut parser: Parser<'_> = Parser::new(PREAMBLE_TEMPLATE)?;
            let chunk: Block = parser.parse_chunk()?;
            chunk
                .stats
                .iter()
                .map(|stat: &Stat| Fingerprint::of_stat(PREAMBLE_TEMPLATE, stat))
                .collect()
        };
        let alnum_src: String = format!("local v = function(b) {ALNUM_TEST} end");
        let named_src: String = format!(
            "local v local d = function(c, o) {DECODER_BODY_HEAD}v(b){DECODER_BODY_TAIL} end"
        );
        let inline_src: String = format!(
            "local d = function(c, o) {DECODER_BODY_HEAD}(function(b) {ALNUM_TEST} end)(b){DECODER_BODY_TAIL} end"
        );
        Ok(Self {
            preamble,
            alnum: single_function_fingerprint(&alnum_src)?,
            decoder_named: single_function_fingerprint(&named_src)?,
            decoder_inline: single_function_fingerprint(&inline_src)?,
        })
    }
}

fn single_function_fingerprint(src: &str) -> Result<String> {
    let mut parser: Parser<'_> = Parser::new(src)?;
    let chunk: Block = parser.parse_chunk()?;
    let function: Option<&Expr> = chunk.stats.last().and_then(|stat: &Stat| match &stat.kind {
        StatKind::Local { values, .. } => values.first(),
        _ => None,
    });
    match function {
        Some(function) => Ok(Fingerprint::of_function(src, FreeNames::Positional, function).0),
        None => Err(crate::error::Error::DecompileUnsupported(
            "hercules template carries no function literal",
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreeNames {
    Positional,
    Identity,
}

#[derive(Debug)]
struct Fingerprint<'s> {
    src: &'s str,
    mode: FreeNames,
    bound: BTreeMap<LocalId, usize>,
    free: Vec<LocalId>,
    out: String,
}

impl<'s> Fingerprint<'s> {
    const fn new(src: &'s str, mode: FreeNames) -> Self {
        Self {
            src,
            mode,
            bound: BTreeMap::new(),
            free: Vec::new(),
            out: String::new(),
        }
    }

    fn of_function(src: &'s str, mode: FreeNames, function: &Expr) -> (String, Vec<LocalId>) {
        let mut fp: Self = Self::new(src, mode);
        fp.expr(function);
        (fp.out, fp.free)
    }

    fn of_stat(src: &'s str, stat: &Stat) -> String {
        let mut fp: Self = Self::new(src, FreeNames::Positional);
        fp.stat(stat);
        fp.out
    }

    fn tag(&mut self, tag: &str) {
        self.out.push_str(tag);
        self.out.push(' ');
    }

    fn numbered(&mut self, tag: &str, n: usize) {
        self.out.push_str(tag);
        self.out.push_str(&n.to_string());
        self.out.push(' ');
    }

    fn declare(&mut self, id: LocalId) {
        let n: usize = self.bound.len();
        self.bound.insert(id, n);
        self.numbered("D", n);
    }

    fn local(&mut self, id: LocalId) {
        if let Some(&n) = self.bound.get(&id) {
            self.numbered("L", n);
            return;
        }
        match self.mode {
            FreeNames::Positional => {
                let k: usize = match self.free.iter().position(|seen: &LocalId| *seen == id) {
                    Some(k) => k,
                    None => {
                        self.free.push(id);
                        self.free.len() - 1
                    }
                };
                self.numbered("F", k);
            }
            FreeNames::Identity => {
                if !self.free.contains(&id) {
                    self.free.push(id);
                }
                self.numbered("U", id as usize);
            }
        }
    }

    fn text(&mut self, prefix: &str, span: Span) {
        self.out.push_str(prefix);
        self.out.push_str(span.text(self.src));
        self.out.push(' ');
    }

    fn block(&mut self, block: &Block) {
        self.tag("{");
        for stat in &block.stats {
            self.stat(stat);
        }
        self.tag("}");
    }

    fn stat(&mut self, stat: &Stat) {
        match &stat.kind {
            StatKind::Local { targets, values } => {
                self.tag("local");
                if is_local_function_stat(self.src, stat) {
                    for target in targets {
                        self.declare(*target);
                    }
                    for value in values {
                        self.expr(value);
                    }
                } else {
                    for value in values {
                        self.expr(value);
                    }
                    self.tag("=");
                    for target in targets {
                        self.declare(*target);
                    }
                }
            }
            StatKind::Assign { targets, values } => {
                self.tag("assign");
                for target in targets {
                    match target {
                        AssignTarget::Var(var, _) => self.var(var),
                        AssignTarget::Index(base, key, _) => {
                            self.tag("[");
                            self.expr(base);
                            self.expr(key);
                            self.tag("]");
                        }
                    }
                }
                self.tag("=");
                for value in values {
                    self.expr(value);
                }
            }
            StatKind::ExprStat(expr) => {
                self.tag("call");
                self.expr(expr);
            }
            StatKind::Do(body) => {
                self.tag("do");
                self.block(body);
            }
            StatKind::While { cond, body } => {
                self.tag("while");
                self.expr(cond);
                self.block(body);
            }
            StatKind::Repeat { body, cond } => {
                self.tag("repeat");
                self.block(body);
                self.expr(cond);
            }
            StatKind::If { arms, else_body } => {
                self.tag("if");
                for (cond, body) in arms {
                    self.expr(cond);
                    self.block(body);
                }
                if let Some(body) = else_body {
                    self.tag("else");
                    self.block(body);
                }
            }
            StatKind::NumericFor {
                var,
                start,
                stop,
                step,
                body,
            } => {
                self.tag("fornum");
                self.expr(start);
                self.expr(stop);
                if let Some(step) = step {
                    self.expr(step);
                }
                self.declare(*var);
                self.block(body);
            }
            StatKind::GenericFor { vars, exprs, body } => {
                self.tag("forin");
                for expr in exprs {
                    self.expr(expr);
                }
                for var in vars {
                    self.declare(*var);
                }
                self.block(body);
            }
            StatKind::Return(values) => {
                self.tag("return");
                for value in values {
                    self.expr(value);
                }
            }
            StatKind::Break => self.tag("break"),
            StatKind::Goto(label) => self.text("goto:", *label),
            StatKind::Label(label) => self.text("label:", *label),
        }
    }

    fn var(&mut self, var: &Var) {
        match var {
            Var::Local(id) => self.local(*id),
            Var::Global(span) => self.text("G", *span),
        }
    }

    fn expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Nil => self.tag("nil"),
            ExprKind::True => self.tag("true"),
            ExprKind::False => self.tag("false"),
            ExprKind::Vararg => self.tag("..."),
            ExprKind::Number(_) => self.text("#", expr.span),
            ExprKind::Str => {
                let text: &str = expr.span.text(self.src);
                match literal_bytes(text) {
                    Some(bytes) => {
                        self.out.push('S');
                        for byte in bytes {
                            self.out.push_str(&format!("{byte:02x}"));
                        }
                        self.out.push(' ');
                    }
                    None => self.text("N", expr.span),
                }
            }
            ExprKind::Var(var) => self.var(var),
            ExprKind::Index(base, key) => {
                self.tag("[");
                self.expr(base);
                self.expr(key);
                self.tag("]");
            }
            ExprKind::Call { base, args } => {
                self.tag("(");
                self.expr(base);
                for arg in args {
                    self.expr(arg);
                }
                self.tag(")");
            }
            ExprKind::MethodCall { base, method, args } => {
                self.tag(":(");
                self.expr(base);
                self.text("M", *method);
                for arg in args {
                    self.expr(arg);
                }
                self.tag(")");
            }
            ExprKind::Function {
                params,
                is_vararg,
                body,
            } => {
                self.tag("function");
                for param in params {
                    self.declare(*param);
                }
                if *is_vararg {
                    self.tag("...");
                }
                self.block(body);
            }
            ExprKind::Table(fields) => {
                self.tag("table{");
                for field in fields {
                    match field {
                        TableField::Positional(value) => self.expr(value),
                        TableField::Named(name, value) => {
                            self.text("K", *name);
                            self.expr(value);
                        }
                        TableField::Indexed(key, value) => {
                            self.tag("[]");
                            self.expr(key);
                            self.expr(value);
                        }
                    }
                }
                self.tag("}");
            }
            ExprKind::Binary(op, left, right) => {
                self.out.push_str(&format!("{op:?} "));
                self.expr(left);
                self.expr(right);
            }
            ExprKind::Unary(op, operand) => {
                self.out.push_str(&format!("{op:?} "));
                self.expr(operand);
            }
            ExprKind::Paren(inner) => {
                if matches!(
                    inner.kind,
                    ExprKind::Call { .. } | ExprKind::MethodCall { .. } | ExprKind::Vararg
                ) {
                    self.tag("truncate");
                }
                self.expr(inner);
            }
        }
    }
}

type BlockPath = Vec<(usize, usize)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeclKind {
    Param,
    Plain,
    LocalFunction,
}

#[derive(Debug, Clone)]
struct Decl {
    path: BlockPath,
    index: Option<usize>,
    kind: DeclKind,
}

#[derive(Debug)]
struct Site<'a> {
    call: &'a Expr,
    callee: &'a Expr,
    function: &'a Expr,
    path: BlockPath,
    index: usize,
}

#[derive(Debug, Default)]
struct Facts<'a> {
    reads: BTreeMap<LocalId, Vec<Span>>,
    writes: BTreeMap<LocalId, usize>,
    global_reads: BTreeSet<String>,
    global_writes: BTreeSet<String>,
    decls: BTreeMap<LocalId, Decl>,
    blocks: BTreeMap<BlockPath, &'a Block>,
    sites: Vec<Site<'a>>,
    local_functions: BTreeMap<LocalId, &'a Expr>,
}

impl Facts<'_> {
    fn reads_of(&self, id: LocalId) -> usize {
        self.reads.get(&id).map_or(0, Vec::len)
    }

    fn writes_of(&self, id: LocalId) -> usize {
        self.writes.get(&id).copied().unwrap_or(0)
    }
}

#[derive(Debug)]
struct Cursor<'p> {
    path: &'p BlockPath,
    index: usize,
    ordinal: usize,
}

impl Cursor<'_> {
    fn child(&mut self) -> BlockPath {
        let mut path: BlockPath = self.path.clone();
        path.push((self.index, self.ordinal));
        self.ordinal += 1;
        path
    }
}

#[derive(Debug)]
struct Walker<'a, 's> {
    src: &'s str,
    facts: Facts<'a>,
}

impl<'a> Walker<'a, '_> {
    fn block(&mut self, block: &'a Block, path: BlockPath) {
        for (index, stat) in block.stats.iter().enumerate() {
            let mut cursor: Cursor<'_> = Cursor {
                path: &path,
                index,
                ordinal: 0,
            };
            self.stat(stat, &mut cursor);
        }
        self.facts.blocks.insert(path, block);
    }

    fn declare(&mut self, id: LocalId, path: &BlockPath, index: Option<usize>, kind: DeclKind) {
        self.facts.decls.insert(
            id,
            Decl {
                path: path.clone(),
                index,
                kind,
            },
        );
    }

    fn stat(&mut self, stat: &'a Stat, cursor: &mut Cursor<'_>) {
        match &stat.kind {
            StatKind::Local { targets, values } => {
                let kind: DeclKind = if is_local_function_stat(self.src, stat) {
                    DeclKind::LocalFunction
                } else {
                    DeclKind::Plain
                };
                for value in values {
                    self.expr(value, cursor);
                }
                for target in targets {
                    self.declare(*target, cursor.path, Some(cursor.index), kind);
                }
                if let ([target], [value]) = (targets.as_slice(), values.as_slice())
                    && matches!(value.kind, ExprKind::Function { .. })
                {
                    self.facts.local_functions.insert(*target, value);
                }
            }
            StatKind::Assign { targets, values } => {
                for target in targets {
                    match target {
                        AssignTarget::Var(Var::Local(id), _) => {
                            *self.facts.writes.entry(*id).or_insert(0) += 1;
                        }
                        AssignTarget::Var(Var::Global(span), _) => {
                            self.facts
                                .global_writes
                                .insert(span.text(self.src).to_owned());
                        }
                        AssignTarget::Index(base, key, _) => {
                            if let ExprKind::Var(Var::Global(root)) = &base.kind
                                && let Some(field) = field_name(self.src, key)
                            {
                                self.facts
                                    .global_writes
                                    .insert(format!("{}.{field}", root.text(self.src)));
                            }
                            self.expr(base, cursor);
                            self.expr(key, cursor);
                        }
                    }
                }
                for value in values {
                    self.expr(value, cursor);
                }
            }
            StatKind::ExprStat(expr) => self.expr(expr, cursor),
            StatKind::Do(body) => {
                let path: BlockPath = cursor.child();
                self.block(body, path);
            }
            StatKind::While { cond, body } => {
                self.expr(cond, cursor);
                let path: BlockPath = cursor.child();
                self.block(body, path);
            }
            StatKind::Repeat { body, cond } => {
                let path: BlockPath = cursor.child();
                self.block(body, path);
                self.expr(cond, cursor);
            }
            StatKind::If { arms, else_body } => {
                for (cond, body) in arms {
                    self.expr(cond, cursor);
                    let path: BlockPath = cursor.child();
                    self.block(body, path);
                }
                if let Some(body) = else_body {
                    let path: BlockPath = cursor.child();
                    self.block(body, path);
                }
            }
            StatKind::NumericFor {
                var,
                start,
                stop,
                step,
                body,
            } => {
                self.expr(start, cursor);
                self.expr(stop, cursor);
                if let Some(step) = step {
                    self.expr(step, cursor);
                }
                let path: BlockPath = cursor.child();
                self.declare(*var, &path, None, DeclKind::Param);
                self.block(body, path);
            }
            StatKind::GenericFor { vars, exprs, body } => {
                for expr in exprs {
                    self.expr(expr, cursor);
                }
                let path: BlockPath = cursor.child();
                for var in vars {
                    self.declare(*var, &path, None, DeclKind::Param);
                }
                self.block(body, path);
            }
            StatKind::Return(values) => {
                for value in values {
                    self.expr(value, cursor);
                }
            }
            StatKind::Break | StatKind::Goto(_) | StatKind::Label(_) => {}
        }
    }

    fn expr(&mut self, expr: &'a Expr, cursor: &mut Cursor<'_>) {
        match &expr.kind {
            ExprKind::Nil
            | ExprKind::True
            | ExprKind::False
            | ExprKind::Vararg
            | ExprKind::Number(_)
            | ExprKind::Str => {}
            ExprKind::Var(Var::Local(id)) => {
                self.facts.reads.entry(*id).or_default().push(expr.span);
            }
            ExprKind::Var(Var::Global(span)) => {
                self.facts
                    .global_reads
                    .insert(span.text(self.src).to_owned());
            }
            ExprKind::Index(base, key) => {
                self.expr(base, cursor);
                self.expr(key, cursor);
            }
            ExprKind::Call { base, args } => {
                if let ExprKind::Paren(inner) = &base.kind
                    && matches!(inner.kind, ExprKind::Function { .. })
                {
                    self.facts.sites.push(Site {
                        call: expr,
                        callee: base,
                        function: inner,
                        path: cursor.path.clone(),
                        index: cursor.index,
                    });
                }
                self.expr(base, cursor);
                for arg in args {
                    self.expr(arg, cursor);
                }
            }
            ExprKind::MethodCall { base, args, .. } => {
                self.expr(base, cursor);
                for arg in args {
                    self.expr(arg, cursor);
                }
            }
            ExprKind::Function { params, body, .. } => {
                let path: BlockPath = cursor.child();
                for param in params {
                    self.declare(*param, &path, None, DeclKind::Param);
                }
                self.block(body, path);
            }
            ExprKind::Table(fields) => {
                for field in fields {
                    match field {
                        TableField::Positional(value) | TableField::Named(_, value) => {
                            self.expr(value, cursor);
                        }
                        TableField::Indexed(key, value) => {
                            self.expr(key, cursor);
                            self.expr(value, cursor);
                        }
                    }
                }
            }
            ExprKind::Binary(_, left, right) => {
                self.expr(left, cursor);
                self.expr(right, cursor);
            }
            ExprKind::Unary(_, inner) | ExprKind::Paren(inner) => self.expr(inner, cursor),
        }
    }
}

#[derive(Debug, Default)]
struct RuleOutcome {
    groups: Vec<Vec<Edit>>,
    blocked: Vec<String>,
    strings: Vec<String>,
    residual: Vec<String>,
}

#[derive(Debug, Clone)]
struct Edit {
    start: usize,
    end: usize,
    text: String,
}

impl Edit {
    fn replace(span: Span, text: String) -> Self {
        Self {
            start: span.start as usize,
            end: span.end as usize,
            text,
        }
    }

    const fn delete(start: usize, end: usize) -> Self {
        Self {
            start,
            end,
            text: String::new(),
        }
    }
}

#[derive(Debug)]
struct Ctx<'a> {
    src: &'a str,
    chunk: &'a Block,
    parser: &'a Parser<'a>,
    templates: &'a Templates,
    facts: Facts<'a>,
    local_names: BTreeSet<&'a [u8]>,
    evidence: bool,
}

impl<'a> Ctx<'a> {
    fn new(
        src: &'a str,
        chunk: &'a Block,
        parser: &'a Parser<'a>,
        templates: &'a Templates,
        evidence: bool,
    ) -> Self {
        let mut walker: Walker<'a, 'a> = Walker {
            src,
            facts: Facts::default(),
        };
        walker.block(chunk, Vec::new());
        let local_names: BTreeSet<&'a [u8]> = (0..parser.local_count())
            .filter_map(|id: LocalId| parser.local_name(id))
            .collect();
        Self {
            src,
            chunk,
            parser,
            templates,
            facts: walker.facts,
            local_names,
            evidence,
        }
    }

    fn run(&self, layer: Layer) -> RuleOutcome {
        match layer {
            Layer::Preamble => self.preamble(),
            Layer::WrapInFunction => self.wrap_in_function(),
            Layer::AntiTamper => self.anti_tamper(),
            Layer::GarbageCode => self.garbage_code(),
            Layer::ControlFlow => self.control_flow(),
            Layer::VirtualMachine => self.virtual_machine(),
            Layer::GlobalAliases => self.global_aliases(),
            Layer::StringToExpressions => self.string_to_expressions(),
            Layer::StringConcat => self.string_concat(),
            Layer::StringEncoding => self.string_encoding(),
            Layer::DecoderHelpers => self.decoder_helpers(),
            Layer::DynamicCode => self.dynamic_code(),
            Layer::OpaquePredicates => self.opaque_predicates(),
            Layer::FunctionInlining => self.function_inlining(),
        }
    }

    fn name_of(&self, id: LocalId) -> &[u8] {
        self.parser.local_name(id).unwrap_or_default()
    }

    fn text(&self, span: Span) -> &'a str {
        span.text(self.src)
    }

    fn block_text(&self, block: &Block) -> &'a str {
        match (block.stats.first(), block.stats.last()) {
            (Some(first), Some(last)) => {
                &self.src[first.span.start as usize..last.span.end as usize]
            }
            _ => "",
        }
    }

    fn block_as_statements(&self, block: &Block) -> String {
        let body: &str = self.block_text(block);
        if body.is_empty() {
            " ".to_owned()
        } else if block_declares(block) || block_ends_with_return(block) {
            format!(" do {body} end ")
        } else {
            format!(" {body} ")
        }
    }

    fn preamble(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        let stats: &[Stat] = &self.chunk.stats;
        let template: &[String] = &self.templates.preamble;
        let prelude: usize = if stats.len() >= template.len()
            && stats
                .iter()
                .zip(template)
                .all(|(stat, expected): (&Stat, &String)| {
                    Fingerprint::of_stat(self.src, stat) == *expected
                }) {
            template.len()
        } else {
            0
        };
        let end: usize = stats
            .get(prelude)
            .map_or(self.src.len(), |stat: &Stat| stat.span.start as usize);
        if prelude > 0 || self.src[..end].contains(WATERMARK) {
            outcome.groups.push(vec![Edit::delete(0, end)]);
        }
        outcome
    }

    fn wrap_in_function(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        let [stat] = self.chunk.stats.as_slice() else {
            return outcome;
        };
        let StatKind::ExprStat(call) = &stat.kind else {
            return outcome;
        };
        let ExprKind::Call { base, args } = &call.kind else {
            return outcome;
        };
        let ExprKind::Paren(inner) = &base.kind else {
            return outcome;
        };
        let ExprKind::Function {
            params,
            is_vararg: true,
            body,
        } = &inner.kind
        else {
            return outcome;
        };
        if params.is_empty() && args.is_empty() {
            outcome.groups.push(vec![Edit::replace(
                stat.span,
                self.block_text(body).to_owned(),
            )]);
        }
        outcome
    }

    fn anti_tamper(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        for_each_stat(self.chunk, &mut |stat: &Stat| {
            if let StatKind::Do(body) = &stat.kind
                && self.is_anti_tamper_block(body)
            {
                outcome
                    .groups
                    .push(vec![Edit::replace(stat.span, " ".to_owned())]);
            }
        });
        outcome
    }

    fn is_anti_tamper_block(&self, body: &Block) -> bool {
        let [refs, debug_tables, check_decl, check_call] = body.stats.as_slice() else {
            return false;
        };
        let StatKind::Local { targets, values } = &refs.kind else {
            return false;
        };
        let refs_shape: bool = targets.len() == 7
            && values.len() == 7
            && matches!(&values[0].kind, ExprKind::Table(fields) if fields.iter().all(|field: &TableField| matches!(field, TableField::Indexed(..))))
            && matches!(values[1].kind, ExprKind::Table(_));
        let debug_shape: bool = matches!(&debug_tables.kind, StatKind::Local { targets, values } if targets.len() == 1 && values.len() == 1 && matches!(values[0].kind, ExprKind::Table(_)));
        let StatKind::Local {
            targets: check_targets,
            values: check_values,
        } = &check_decl.kind
        else {
            return false;
        };
        let ([check_id], [check_fn]) = (check_targets.as_slice(), check_values.as_slice()) else {
            return false;
        };
        let ExprKind::Function {
            body: check_body, ..
        } = &check_fn.kind
        else {
            return false;
        };
        let calls_check: bool = matches!(&check_call.kind, StatKind::ExprStat(call) if matches!(&call.kind, ExprKind::Call { base, args } if args.is_empty() && matches!(base.kind, ExprKind::Var(Var::Local(id)) if id == *check_id)));
        let mut reports_tamper: bool = false;
        for_each_expr_in_block(check_body, &mut |expr: &Expr| {
            if matches!(expr.kind, ExprKind::Str)
                && literal_bytes(self.text(expr.span))
                    .is_some_and(|bytes: Vec<u8>| bytes.starts_with(b"Tamper Detected!"))
            {
                reports_tamper = true;
            }
        });
        refs_shape && debug_shape && calls_check && reports_tamper
    }

    fn garbage_code(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        for_each_block(self.chunk, &mut |block: &Block| {
            let mut index: usize = 0;
            while index < block.stats.len() {
                let stat: &Stat = &block.stats[index];
                if let Some(next) = block.stats.get(index + 1)
                    && self.is_dummy_counter(stat, next)
                {
                    outcome.groups.push(vec![Edit::delete(
                        stat.span.start as usize,
                        next.span.end as usize,
                    )]);
                    index += 2;
                    continue;
                }
                if self.is_garbage_statement(stat) {
                    outcome
                        .groups
                        .push(vec![Edit::replace(stat.span, " ".to_owned())]);
                }
                index += 1;
            }
        });
        outcome
    }

    fn is_garbage_statement(&self, stat: &Stat) -> bool {
        match &stat.kind {
            StatKind::Local { targets, values } => {
                let ([target], [value]) = (targets.as_slice(), values.as_slice()) else {
                    return false;
                };
                if !is_garbage_name(self.name_of(*target))
                    || self.facts.reads_of(*target) != 0
                    || self.facts.writes_of(*target) != 0
                {
                    return false;
                }
                match &value.kind {
                    ExprKind::Number(_) => int_literal(self.text(value.span)).is_some(),
                    ExprKind::Function {
                        params,
                        is_vararg: false,
                        body,
                    } => {
                        is_local_function_stat(self.src, stat)
                            && matches!(params.as_slice(), [param] if is_garbage_name(self.name_of(*param)))
                            && self.is_underscore_filler(body)
                    }
                    _ => false,
                }
            }
            StatKind::While { cond, body } => {
                matches!(cond.kind, ExprKind::False)
                    && matches!(body.stats.as_slice(), [filler, brk] if self.is_underscore_local(filler) && matches!(brk.kind, StatKind::Break))
            }
            StatKind::If { arms, else_body } => {
                else_body.is_none()
                    && matches!(arms.as_slice(), [(cond, body)] if matches!(cond.kind, ExprKind::True | ExprKind::False) && self.is_underscore_filler(body))
            }
            _ => false,
        }
    }

    fn is_underscore_filler(&self, body: &Block) -> bool {
        matches!(body.stats.as_slice(), [filler] if self.is_underscore_local(filler))
    }

    fn is_underscore_local(&self, stat: &Stat) -> bool {
        matches!(&stat.kind, StatKind::Local { targets, values } if matches!((targets.as_slice(), values.as_slice()), ([target], [value]) if self.name_of(*target) == b"_" && matches!(value.kind, ExprKind::Number(_)) && int_literal(self.text(value.span)).is_some()))
    }

    fn is_dummy_counter(&self, decl: &Stat, bump: &Stat) -> bool {
        let StatKind::Local { targets, values } = &decl.kind else {
            return false;
        };
        let ([dummy], [one]) = (targets.as_slice(), values.as_slice()) else {
            return false;
        };
        if self.name_of(*dummy) != b"dummy" || int_literal(self.text(one.span)) != Some(1) {
            return false;
        }
        let StatKind::Assign {
            targets: bump_targets,
            values: bump_values,
        } = &bump.kind
        else {
            return false;
        };
        let target_is_dummy: bool = matches!(bump_targets.as_slice(), [AssignTarget::Var(Var::Local(id), _)] if id == dummy);
        let value_bumps_dummy: bool = matches!(bump_values.as_slice(), [value] if matches!(&value.kind, ExprKind::Binary(BinOp::Add, left, right) if matches!(left.kind, ExprKind::Var(Var::Local(id)) if id == *dummy) && int_literal(self.text(right.span)).is_some()));
        target_is_dummy
            && value_bumps_dummy
            && self.facts.reads_of(*dummy) == 1
            && self.facts.writes_of(*dummy) == 1
    }

    fn control_flow(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        for_each_block(self.chunk, &mut |block: &Block| {
            for index in 0..block.stats.len() {
                let Some(window) = block.stats.get(index..index + 4) else {
                    break;
                };
                match self.control_flow_program(window) {
                    ControlFlowMatch::NotWrapper => {}
                    ControlFlowMatch::Blocked(reason) => outcome.blocked.push(reason),
                    ControlFlowMatch::Program(program) => {
                        let rest: &[Stat] = &block.stats[index + 4..];
                        let body: &str = self.block_text(program);
                        let scoped: bool = self.program_conflicts_with(program, rest)
                            || (block_ends_with_return(program) && !rest.is_empty());
                        let text: String = if scoped {
                            format!(" do {body} end ")
                        } else {
                            format!(" {body} ")
                        };
                        outcome.groups.push(vec![Edit {
                            start: window[0].span.start as usize,
                            end: window[3].span.end as usize,
                            text,
                        }]);
                    }
                }
            }
        });
        outcome
    }

    fn control_flow_program<'b>(&self, window: &'b [Stat]) -> ControlFlowMatch<'b> {
        let [thing, thing2, counter, wrapper] = window else {
            return ControlFlowMatch::NotWrapper;
        };
        let Some((thing_id, thing_value)) = self.int_local(thing, b"thing") else {
            return ControlFlowMatch::NotWrapper;
        };
        let Some((thing2_id, thing2_value)) = self.int_local(thing2, b"thing2") else {
            return ControlFlowMatch::NotWrapper;
        };
        let Some((counter_id, 0)) = self.int_local(counter, b"counter") else {
            return ControlFlowMatch::NotWrapper;
        };
        let StatKind::While { cond, body } = &wrapper.kind else {
            return ControlFlowMatch::NotWrapper;
        };
        let cond_shape: bool = matches!(&cond.kind, ExprKind::Binary(BinOp::And, eq, lt)
            if is_local_compare(eq, BinOp::Eq, thing_id, thing2_id)
                && matches!(&lt.kind, ExprKind::Binary(BinOp::Lt, c, one) if is_local(c, counter_id) && int_literal(self.text(one.span)) == Some(1)));
        let [bump_thing, bump_counter, branch] = body.stats.as_slice() else {
            return ControlFlowMatch::NotWrapper;
        };
        let StatKind::If { arms, else_body } = &branch.kind else {
            return ControlFlowMatch::NotWrapper;
        };
        let ([(arm_cond, _spoof)], Some(else_block)) = (arms.as_slice(), else_body) else {
            return ControlFlowMatch::NotWrapper;
        };
        let [program_stat, brk] = else_block.stats.as_slice() else {
            return ControlFlowMatch::NotWrapper;
        };
        let StatKind::Do(program) = &program_stat.kind else {
            return ControlFlowMatch::NotWrapper;
        };
        let shape: bool = cond_shape
            && thing_value == thing2_value
            && self.is_increment(bump_thing, thing_id)
            && self.is_increment(bump_counter, counter_id)
            && is_local_compare(arm_cond, BinOp::Eq, thing_id, thing2_id)
            && matches!(brk.kind, StatKind::Break);
        if !shape {
            return ControlFlowMatch::NotWrapper;
        }
        let isolated: bool = self.facts.reads_of(thing_id) == 3
            && self.facts.reads_of(thing2_id) == 2
            && self.facts.reads_of(counter_id) == 2
            && self.facts.writes_of(thing_id) == 1
            && self.facts.writes_of(thing2_id) == 0
            && self.facts.writes_of(counter_id) == 1;
        if isolated {
            ControlFlowMatch::Program(program)
        } else {
            ControlFlowMatch::Blocked(
                "hercules: control-flow wrapper kept because the wrapped program reads its thing/thing2/counter locals"
                    .to_owned(),
            )
        }
    }

    fn int_local(&self, stat: &Stat, name: &[u8]) -> Option<(LocalId, i64)> {
        let StatKind::Local { targets, values } = &stat.kind else {
            return None;
        };
        let ([target], [value]) = (targets.as_slice(), values.as_slice()) else {
            return None;
        };
        if self.name_of(*target) != name {
            return None;
        }
        int_literal(self.text(value.span)).map(|v: i64| (*target, v))
    }

    fn is_increment(&self, stat: &Stat, id: LocalId) -> bool {
        matches!(&stat.kind, StatKind::Assign { targets, values }
            if matches!(targets.as_slice(), [AssignTarget::Var(Var::Local(t), _)] if *t == id)
                && matches!(values.as_slice(), [value] if matches!(&value.kind, ExprKind::Binary(BinOp::Add, left, right) if is_local(left, id) && int_literal(self.text(right.span)) == Some(1))))
    }

    fn program_conflicts_with(&self, program: &Block, rest: &[Stat]) -> bool {
        let mut declared: BTreeSet<&[u8]> = BTreeSet::new();
        let mut labels: BTreeSet<&str> = BTreeSet::new();
        for stat in &program.stats {
            match &stat.kind {
                StatKind::Local { targets, .. } => {
                    for target in targets {
                        declared.insert(self.name_of(*target));
                    }
                }
                StatKind::Label(name) => {
                    labels.insert(self.text(*name));
                }
                _ => {}
            }
        }
        let mut conflict: bool = false;
        for stat in rest {
            for_each_expr_in_stat(stat, &mut |expr: &Expr| {
                if let ExprKind::Var(Var::Global(span)) = &expr.kind
                    && declared.contains(self.text(*span).as_bytes())
                {
                    conflict = true;
                }
            });
            if let StatKind::Assign { targets, .. } = &stat.kind {
                for target in targets {
                    if let AssignTarget::Var(Var::Global(span), _) = target
                        && declared.contains(self.text(*span).as_bytes())
                    {
                        conflict = true;
                    }
                }
            }
            for_each_stat_in(stat, &mut |inner: &Stat| {
                if let StatKind::Goto(label) = &inner.kind
                    && labels.contains(self.text(*label))
                {
                    conflict = true;
                }
            });
        }
        conflict
    }

    fn virtual_machine(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        if !VM_MARKERS
            .iter()
            .all(|marker: &&str| self.src.contains(marker))
        {
            return outcome;
        }
        let Some((bytecode, charset)) = self
            .chunk
            .stats
            .last()
            .and_then(|stat: &Stat| self.vm_entry(stat))
        else {
            outcome.blocked.push(
                "hercules: VMGenerator runtime found but its WrapState(BcToState(...)) entry call is not the last statement"
                    .to_owned(),
            );
            return outcome;
        };
        match devirtualize(&bytecode, &charset) {
            Ok(Devirtualized {
                fidelity: Fidelity::BestEffort,
                protos,
                instructions,
                ..
            }) => outcome.blocked.push(format!(
                "hercules: VMGenerator payload decoded to {protos} Lua 5.1 function(s) and {instructions} instruction(s), but its decompile is best-effort, so the VM layer is kept"
            )),
            Ok(Devirtualized {
                source,
                fidelity,
                protos,
                instructions,
            }) => {
                if fidelity != Fidelity::Lossless {
                    outcome.residual.push(format!(
                        "hercules: the devirtualized VM program ({protos} function(s), {instructions} instruction(s)) decompiled with {fidelity:?} fidelity"
                    ));
                }
                outcome.groups.push(vec![Edit {
                    start: 0,
                    end: self.src.len(),
                    text: source,
                }]);
            }
            Err(err) => outcome.blocked.push(format!(
                "hercules: VMGenerator payload not devirtualized ({err})"
            )),
        }
        outcome
    }

    fn vm_entry(&self, stat: &Stat) -> Option<(Vec<u8>, Vec<u8>)> {
        let StatKind::ExprStat(call) = &stat.kind else {
            return None;
        };
        let ExprKind::Call { base, args } = &call.kind else {
            return None;
        };
        if !args.is_empty() {
            return None;
        }
        let ExprKind::Call {
            base: wrap,
            args: wrap_args,
        } = &base.kind
        else {
            return None;
        };
        let [state, _env] = wrap_args.as_slice() else {
            return None;
        };
        let ExprKind::Call {
            base: decoder,
            args: decoder_args,
        } = &state.kind
        else {
            return None;
        };
        let [payload, charset] = decoder_args.as_slice() else {
            return None;
        };
        let named: bool =
            self.text(wrap.span) == "WrapState" && self.text(decoder.span) == "BcToState";
        if !named
            || !matches!(payload.kind, ExprKind::Str)
            || !matches!(charset.kind, ExprKind::Str)
        {
            return None;
        }
        Some((
            literal_bytes(self.text(payload.span))?,
            literal_bytes(self.text(charset.span))?,
        ))
    }

    fn global_aliases(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        let dynamic_env: Option<&str> = DYNAMIC_ENV_GLOBALS
            .iter()
            .copied()
            .find(|name: &&str| self.facts.global_reads.contains(*name));
        for_each_block(self.chunk, &mut |block: &Block| {
            for (index, stat) in block.stats.iter().enumerate() {
                let StatKind::Local { targets, values } = &stat.kind else {
                    continue;
                };
                if targets.is_empty() || !values.is_empty() {
                    continue;
                }
                let Some(assigns) = block.stats.get(index + 1..index + 1 + targets.len()) else {
                    continue;
                };
                let Some(bindings) = self.alias_bindings(targets, assigns) else {
                    continue;
                };
                if let Some(name) = dynamic_env {
                    outcome.blocked.push(format!(
                        "hercules: global alias block kept because the program reads `{name}`, which can rebind globals at run time"
                    ));
                    continue;
                }
                let mut group: Vec<Edit> = vec![Edit::delete(
                    stat.span.start as usize,
                    assigns[assigns.len() - 1].span.end as usize,
                )];
                let mut refused: Option<String> = None;
                for (alias, target) in &bindings {
                    if let Some(reason) = self.alias_refusal(*alias, target) {
                        refused = Some(reason);
                        break;
                    }
                    let replacement: &str = self.text(target.span);
                    for read in self.facts.reads.get(alias).into_iter().flatten() {
                        group.push(Edit::replace(*read, replacement.to_owned()));
                    }
                }
                match refused {
                    Some(reason) => outcome.blocked.push(reason),
                    None => outcome.groups.push(group),
                }
            }
        });
        outcome
    }

    fn alias_bindings(
        &self,
        targets: &[LocalId],
        assigns: &'a [Stat],
    ) -> Option<Vec<(LocalId, &'a Expr)>> {
        let mut bindings: Vec<(LocalId, &'a Expr)> = Vec::with_capacity(targets.len());
        for (target, assign) in targets.iter().zip(assigns) {
            let StatKind::Assign {
                targets: assign_targets,
                values,
            } = &assign.kind
            else {
                return None;
            };
            let ([AssignTarget::Var(Var::Local(id), _)], [value]) =
                (assign_targets.as_slice(), values.as_slice())
            else {
                return None;
            };
            if id != target || global_path(self.src, value).is_none() {
                return None;
            }
            bindings.push((*id, value));
        }
        Some(bindings)
    }

    fn alias_refusal(&self, alias: LocalId, target: &Expr) -> Option<String> {
        let (root, field): (&str, Option<String>) = global_path(self.src, target)?;
        if self.facts.writes_of(alias) != 1 {
            return Some(format!(
                "hercules: global alias for `{}` kept because the alias local is reassigned",
                self.text(target.span)
            ));
        }
        let shadowed: bool = self.local_names.contains(root.as_bytes());
        let rebound: bool = self.facts.global_writes.contains(root)
            || field.is_some_and(|field: String| {
                self.facts
                    .global_writes
                    .contains(&format!("{root}.{field}"))
            });
        if shadowed || rebound {
            return Some(format!(
                "hercules: global alias for `{}` kept because the program declares a local `{root}` or rebinds the global",
                self.text(target.span)
            ));
        }
        None
    }

    fn string_to_expressions(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        let mut tables: BTreeMap<LocalId, (Span, BTreeMap<i64, &'a str>)> = BTreeMap::new();
        for_each_stat(self.chunk, &mut |stat: &Stat| {
            if let StatKind::Local { targets, values } = &stat.kind
                && let ([table_id], [table]) = (targets.as_slice(), values.as_slice())
                && self.facts.writes_of(*table_id) == 0
                && let Some(chars) = self.char_table(table)
            {
                tables.insert(*table_id, (stat.span, chars));
            }
        });
        if tables.is_empty() {
            return outcome;
        }
        let mut lookups: BTreeMap<LocalId, Vec<Edit>> = BTreeMap::new();
        for_each_expr_in_block(self.chunk, &mut |expr: &Expr| {
            if let ExprKind::Index(base, key) = &expr.kind
                && let ExprKind::Var(Var::Local(id)) = &base.kind
                && let Some((_, chars)) = tables.get(id)
                && let Some(value) = eval_const(self.src, key).and_then(Const::as_int)
                && let Some(text) = chars.get(&value)
            {
                lookups
                    .entry(*id)
                    .or_default()
                    .push(Edit::replace(expr.span, (*text).to_owned()));
            }
        });
        for (id, (decl, _)) in &tables {
            let edits: Vec<Edit> = lookups.remove(id).unwrap_or_default();
            if edits.len() == self.facts.reads_of(*id) {
                let mut group: Vec<Edit> = vec![Edit::replace(*decl, " ".to_owned())];
                group.extend(edits);
                outcome.groups.push(group);
            } else {
                outcome.blocked.push(
                    "hercules: string-to-expressions character table kept because some lookups are not constant"
                        .to_owned(),
                );
            }
        }
        outcome
    }

    fn char_table(&self, table: &Expr) -> Option<BTreeMap<i64, &'a str>> {
        let ExprKind::Table(fields) = &table.kind else {
            return None;
        };
        if fields.is_empty() {
            return None;
        }
        let mut chars: BTreeMap<i64, &'a str> = BTreeMap::new();
        for field in fields {
            let TableField::Indexed(key, value) = field else {
                return None;
            };
            let code: i64 = int_literal(self.text(key.span))?;
            let text: &'a str = self.text(value.span);
            if !matches!(value.kind, ExprKind::Str)
                || literal_bytes(text)? != [u8::try_from(code).ok()?]
            {
                return None;
            }
            chars.insert(code, text);
        }
        Some(chars)
    }

    fn string_concat(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        self.collect_string_folds(self.chunk, &mut outcome);
        outcome
    }

    fn collect_string_folds(&self, block: &Block, outcome: &mut RuleOutcome) {
        for stat in &block.stats {
            for_each_direct_expr(stat, &mut |expr: &Expr| {
                self.fold_strings_in(expr, false, outcome);
            });
            for_each_child_block(stat, &mut |child: &Block| {
                self.collect_string_folds(child, outcome);
            });
        }
    }

    fn fold_strings_in(&self, expr: &Expr, is_prefix: bool, outcome: &mut RuleOutcome) {
        match &expr.kind {
            ExprKind::Binary(BinOp::Concat, _, _) => {
                if let Some(bytes) = self.const_string(expr) {
                    outcome
                        .groups
                        .push(vec![Edit::replace(expr.span, lua_quote(&bytes))]);
                    return;
                }
            }
            ExprKind::Paren(inner) if !is_prefix => {
                if matches!(inner.kind, ExprKind::Str) && is_literal(self.text(inner.span)) {
                    outcome.groups.push(vec![Edit::replace(
                        expr.span,
                        self.text(inner.span).to_owned(),
                    )]);
                    return;
                }
            }
            ExprKind::Function { body, .. } => {
                self.collect_string_folds(body, outcome);
                return;
            }
            _ => {}
        }
        match &expr.kind {
            ExprKind::Index(base, key) => {
                self.fold_strings_in(base, true, outcome);
                self.fold_strings_in(key, false, outcome);
            }
            ExprKind::Call { base, args } => {
                self.fold_strings_in(base, true, outcome);
                for arg in args {
                    self.fold_strings_in(arg, false, outcome);
                }
            }
            ExprKind::MethodCall { base, args, .. } => {
                self.fold_strings_in(base, true, outcome);
                for arg in args {
                    self.fold_strings_in(arg, false, outcome);
                }
            }
            ExprKind::Table(fields) => {
                for field in fields {
                    match field {
                        TableField::Positional(value) | TableField::Named(_, value) => {
                            self.fold_strings_in(value, false, outcome);
                        }
                        TableField::Indexed(key, value) => {
                            self.fold_strings_in(key, false, outcome);
                            self.fold_strings_in(value, false, outcome);
                        }
                    }
                }
            }
            ExprKind::Binary(_, left, right) => {
                self.fold_strings_in(left, false, outcome);
                self.fold_strings_in(right, false, outcome);
            }
            ExprKind::Unary(_, inner) | ExprKind::Paren(inner) => {
                self.fold_strings_in(inner, false, outcome);
            }
            _ => {}
        }
    }

    fn const_string(&self, expr: &Expr) -> Option<Vec<u8>> {
        match &expr.kind {
            ExprKind::Str => {
                let text: &str = self.text(expr.span);
                if is_literal(text) {
                    literal_bytes(text)
                } else {
                    None
                }
            }
            ExprKind::Paren(inner) => self.const_string(inner),
            ExprKind::Binary(BinOp::Concat, left, right) => {
                let mut bytes: Vec<u8> = self.const_string(left)?;
                let tail: Vec<u8> = self.const_string(right)?;
                if bytes.len() + tail.len() > MAX_FOLDED_STRING_BYTES {
                    return None;
                }
                bytes.extend(tail);
                Some(bytes)
            }
            _ => None,
        }
    }

    fn string_encoding(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        let named: BTreeSet<LocalId> = self.named_decoders();
        for_each_expr_in_block(self.chunk, &mut |expr: &Expr| {
            let ExprKind::Call { base, args } = &expr.kind else {
                return;
            };
            let is_decoder: bool = match &base.kind {
                ExprKind::Var(Var::Local(id)) => named.contains(id),
                ExprKind::Paren(inner) => {
                    matches!(inner.kind, ExprKind::Function { .. })
                        && Fingerprint::of_function(self.src, FreeNames::Positional, inner).0
                            == self.templates.decoder_inline
                }
                _ => false,
            };
            if !is_decoder {
                return;
            }
            let decoded: Option<Vec<u8>> = match args.as_slice() {
                [text, key] => self.const_string(text).and_then(|bytes: Vec<u8>| {
                    int_literal(self.text(key.span)).and_then(|key: i64| caesar_decode(&bytes, key))
                }),
                _ => None,
            };
            match decoded {
                Some(bytes) => {
                    outcome
                        .strings
                        .push(String::from_utf8_lossy(&bytes).into_owned());
                    outcome
                        .groups
                        .push(vec![Edit::replace(expr.span, lua_quote(&bytes))]);
                }
                None => outcome.blocked.push(format!(
                    "hercules: string-encoding call `{}` kept because its arguments are not constant",
                    truncate(self.text(expr.span), 80)
                )),
            }
        });
        outcome
    }

    fn named_decoders(&self) -> BTreeSet<LocalId> {
        let mut named: BTreeSet<LocalId> = BTreeSet::new();
        for (id, function) in &self.facts.local_functions {
            if self.facts.writes_of(*id) != 0 {
                continue;
            }
            let (fingerprint, free): (String, Vec<LocalId>) =
                Fingerprint::of_function(self.src, FreeNames::Positional, function);
            if fingerprint != self.templates.decoder_named {
                continue;
            }
            if let [helper] = free.as_slice()
                && self.facts.writes_of(*helper) == 0
                && self
                    .facts
                    .local_functions
                    .get(helper)
                    .is_some_and(|helper_fn: &&Expr| {
                        Fingerprint::of_function(self.src, FreeNames::Positional, helper_fn).0
                            == self.templates.alnum
                    })
            {
                named.insert(*id);
            }
        }
        named
    }

    fn decoder_helpers(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        for_each_stat(self.chunk, &mut |stat: &Stat| {
            let StatKind::Local { targets, values } = &stat.kind else {
                return;
            };
            let ([id], [function]) = (targets.as_slice(), values.as_slice()) else {
                return;
            };
            if !matches!(function.kind, ExprKind::Function { .. }) {
                return;
            }
            let fingerprint: String =
                Fingerprint::of_function(self.src, FreeNames::Positional, function).0;
            let is_helper: bool = fingerprint == self.templates.alnum
                || fingerprint == self.templates.decoder_named
                || fingerprint == self.templates.decoder_inline;
            if !is_helper {
                return;
            }
            if self.facts.reads_of(*id) == 0 && self.facts.writes_of(*id) == 0 {
                outcome
                    .groups
                    .push(vec![Edit::replace(stat.span, " ".to_owned())]);
            } else {
                outcome.blocked.push(
                    "hercules: string-encoding decoder function kept because calls to it remain"
                        .to_owned(),
                );
            }
        });
        outcome
    }

    fn dynamic_code(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        for_each_stat(self.chunk, &mut |stat: &Stat| {
            let StatKind::Do(wrapper) = &stat.kind else {
                return;
            };
            let [inner] = wrapper.stats.as_slice() else {
                return;
            };
            let StatKind::ExprStat(call) = &inner.kind else {
                return;
            };
            let ExprKind::Call { base, args } = &call.kind else {
                return;
            };
            let ExprKind::Paren(function) = &base.kind else {
                return;
            };
            let ExprKind::Function {
                params,
                is_vararg: false,
                body,
            } = &function.kind
            else {
                return;
            };
            if !params.is_empty() || !args.is_empty() {
                return;
            }
            if block_returns(body) {
                outcome.blocked.push(
                    "hercules: dynamic-code closure kept because its body returns".to_owned(),
                );
                return;
            }
            outcome.groups.push(vec![Edit::replace(
                stat.span,
                self.block_as_statements(body),
            )]);
        });
        outcome
    }

    fn opaque_predicates(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        for_each_stat(self.chunk, &mut |stat: &Stat| match &stat.kind {
            StatKind::If { arms, else_body } => {
                let Some((cond, body)) = arms.first() else {
                    return;
                };
                match eval_const(self.src, cond).map(Const::truthy) {
                    Some(true) => outcome.groups.push(vec![Edit::replace(
                        stat.span,
                        self.block_as_statements(body),
                    )]),
                    Some(false) if arms.len() == 1 && else_body.is_none() => {
                        outcome
                            .groups
                            .push(vec![Edit::replace(stat.span, " ".to_owned())]);
                    }
                    _ => {}
                }
            }
            StatKind::While { cond, .. }
                if eval_const(self.src, cond).is_some_and(|value: Const| !value.truthy()) =>
            {
                outcome
                    .groups
                    .push(vec![Edit::replace(stat.span, " ".to_owned())]);
            }
            _ => {}
        });
        outcome
    }

    fn function_inlining(&self) -> RuleOutcome {
        let mut outcome: RuleOutcome = RuleOutcome::default();
        let vm_runtime: bool = VM_MARKERS
            .iter()
            .all(|marker: &&str| self.src.contains(marker));
        if !self.evidence || vm_runtime || self.facts.sites.is_empty() {
            return outcome;
        }
        let mut groups: BTreeMap<String, Vec<&Site<'a>>> = BTreeMap::new();
        let mut free_of: BTreeMap<String, Vec<LocalId>> = BTreeMap::new();
        let mut call_starts: Vec<u32> = self
            .facts
            .sites
            .iter()
            .map(|site: &Site<'a>| site.call.span.start)
            .collect();
        call_starts.sort_unstable();
        for site in &self.facts.sites {
            let span: Span = site.function.span;
            let first_inside: usize =
                call_starts.partition_point(|start: &u32| *start < span.start);
            if call_starts
                .get(first_inside)
                .is_some_and(|start: &u32| *start < span.end)
            {
                continue;
            }
            let (fingerprint, free): (String, Vec<LocalId>) =
                Fingerprint::of_function(self.src, FreeNames::Identity, site.function);
            groups.entry(fingerprint.clone()).or_default().push(site);
            free_of.insert(fingerprint, free);
        }
        let mut ordered: Vec<(&String, &Vec<&Site<'a>>)> = groups.iter().collect();
        ordered.sort_by_key(|(_, sites): &(&String, &Vec<&Site<'a>>)| {
            sites
                .first()
                .map_or(u32::MAX, |site: &&Site<'a>| site.call.span.start)
        });
        let mut taken: BTreeSet<String> = BTreeSet::new();
        let mut counter: usize = 0;
        for (fingerprint, sites) in ordered {
            let Some((hoist_path, hoist_index)) = hoist_point(sites) else {
                continue;
            };
            let Some(block) = self.facts.blocks.get(&hoist_path) else {
                continue;
            };
            let Some(anchor) = block.stats.get(hoist_index) else {
                continue;
            };
            if block.stats[hoist_index..]
                .iter()
                .any(|stat: &Stat| matches!(stat.kind, StatKind::Label(_)))
            {
                outcome.blocked.push(
                    "hercules: inlined function kept because a label follows its hoist point"
                        .to_owned(),
                );
                continue;
            }
            let free: &[LocalId] = free_of.get(fingerprint).map_or(&[], Vec::as_slice);
            let visible: bool = free.iter().all(|id: &LocalId| {
                self.facts
                    .decls
                    .get(id)
                    .is_some_and(|decl: &Decl| decl_visible_at(decl, &hoist_path, hoist_index))
            });
            if !visible {
                outcome.blocked.push(
                    "hercules: inlined function kept because an upvalue it reads is not in scope at a common hoist point"
                        .to_owned(),
                );
                continue;
            }
            let Some(first) = sites.first() else {
                continue;
            };
            let literal: &str = self.text(first.function.span);
            let Some(signature) = literal.strip_prefix("function") else {
                continue;
            };
            let name: String = loop {
                counter += 1;
                let candidate: String = format!("fn_{counter}");
                if !self.name_in_use(&candidate) && !taken.contains(&candidate) {
                    break candidate;
                }
            };
            taken.insert(name.clone());
            let mut group: Vec<Edit> = vec![Edit {
                start: anchor.span.start as usize,
                end: anchor.span.start as usize,
                text: format!(" local function {name}{signature} "),
            }];
            for site in sites {
                group.push(Edit::replace(site.callee.span, name.clone()));
            }
            outcome.groups.push(group);
        }
        if outcome.groups.is_empty() {
            outcome.blocked.push(format!(
                "hercules: function-inlining layer remains ({} immediately invoked function literal(s) not re-outlined)",
                self.facts.sites.len()
            ));
        }
        outcome
    }

    fn name_in_use(&self, name: &str) -> bool {
        self.facts.global_reads.contains(name)
            || self.facts.global_writes.contains(name)
            || self.local_names.contains(name.as_bytes())
    }
}

const DYNAMIC_ENV_GLOBALS: [&str; 11] = [
    "_ENV",
    "_G",
    "setfenv",
    "getfenv",
    "load",
    "loadstring",
    "loadfile",
    "dofile",
    "require",
    "rawset",
    "debug",
];

#[derive(Debug)]
enum ControlFlowMatch<'b> {
    NotWrapper,
    Blocked(String),
    Program(&'b Block),
}

fn hoist_point(sites: &[&Site<'_>]) -> Option<(BlockPath, usize)> {
    let first: &Site<'_> = sites.first()?;
    let mut common: usize = first.path.len();
    for site in sites {
        let shared: usize = first
            .path
            .iter()
            .zip(&site.path)
            .take_while(|(a, b): &(&(usize, usize), &(usize, usize))| a == b)
            .count();
        common = common.min(shared);
    }
    let index: usize = sites
        .iter()
        .map(|site: &&Site<'_>| {
            site.path
                .get(common)
                .map_or(site.index, |step: &(usize, usize)| step.0)
        })
        .min()?;
    Some((first.path[..common].to_vec(), index))
}

fn decl_visible_at(decl: &Decl, hoist_path: &[(usize, usize)], hoist_index: usize) -> bool {
    let depth: usize = decl.path.len();
    if depth > hoist_path.len() || decl.path[..] != hoist_path[..depth] {
        return false;
    }
    let Some(index) = decl.index else {
        return true;
    };
    let (limit, nested): (usize, bool) = hoist_path
        .get(depth)
        .map_or((hoist_index, false), |step: &(usize, usize)| (step.0, true));
    index < limit || (index == limit && nested && decl.kind == DeclKind::LocalFunction)
}

fn apply_groups(src: &str, groups: Vec<Vec<Edit>>) -> Option<String> {
    splice(src, groups, true)
}

fn apply_groups_exact(src: &str, groups: Vec<Vec<Edit>>) -> Option<String> {
    splice(src, groups, false)
}

fn splice(src: &str, groups: Vec<Vec<Edit>>, guard_tokens: bool) -> Option<String> {
    let mut accepted: BTreeMap<(usize, usize, usize), Edit> = BTreeMap::new();
    let mut sequence: usize = 0;
    for group in groups {
        let mut staged: Vec<(usize, usize, usize)> = Vec::with_capacity(group.len());
        let mut clash: bool = false;
        for edit in group {
            if edit.start > edit.end || edit.end > src.len() || overlaps(&accepted, &edit) {
                clash = true;
                break;
            }
            let key: (usize, usize, usize) = (edit.start, edit.end, sequence);
            sequence += 1;
            accepted.insert(key, edit);
            staged.push(key);
        }
        if clash {
            for key in staged {
                accepted.remove(&key);
            }
        }
    }
    if accepted.is_empty() {
        return None;
    }
    let mut out: String = String::with_capacity(src.len());
    let mut cursor: usize = 0;
    for edit in accepted.values() {
        push_joined(&mut out, src.get(cursor..edit.start)?, guard_tokens);
        push_joined(&mut out, &edit.text, guard_tokens);
        cursor = edit.end;
    }
    push_joined(&mut out, src.get(cursor..)?, guard_tokens);
    Some(out)
}

fn overlaps(accepted: &BTreeMap<(usize, usize, usize), Edit>, edit: &Edit) -> bool {
    accepted.range(..(edit.end, 0, 0)).next_back().is_some_and(
        |((start, end, _), _): (&(usize, usize, usize), &Edit)| {
            *end > edit.start && *start < edit.end
        },
    )
}

fn push_joined(out: &mut String, piece: &str, guard_tokens: bool) {
    if guard_tokens
        && let (Some(left), Some(right)) = (out.as_bytes().last(), piece.as_bytes().first())
        && would_merge(*left, *right)
    {
        out.push(' ');
    }
    out.push_str(piece);
}

const fn would_merge(left: u8, right: u8) -> bool {
    let left_word: bool = left.is_ascii_alphanumeric() || left == b'_';
    let right_word: bool = right.is_ascii_alphanumeric() || right == b'_';
    (left_word && right_word)
        || matches!(
            (left, right),
            (b'-', b'-')
                | (b'=' | b'<' | b'>' | b'~', b'=')
                | (b'<', b'<')
                | (b'>', b'>')
                | (b'/', b'/')
                | (b':', b':')
                | (b'.', b'.')
                | (b'[', b'[' | b'=')
        )
        || (left == b'.' && right.is_ascii_digit())
        || (left.is_ascii_digit() && right == b'.')
}

fn is_local_function_stat(src: &str, stat: &Stat) -> bool {
    let text: &str = stat.span.text(src);
    text.strip_prefix("local")
        .map(str::trim_start)
        .and_then(|rest: &str| rest.strip_prefix("function"))
        .is_some_and(|rest: &str| {
            rest.bytes()
                .next()
                .is_some_and(|b: u8| !(b.is_ascii_alphanumeric() || b == b'_'))
        })
}

fn is_garbage_name(name: &[u8]) -> bool {
    name.len() == 6 && name.iter().all(u8::is_ascii_lowercase)
}

fn block_declares(block: &Block) -> bool {
    block
        .stats
        .iter()
        .any(|stat: &Stat| matches!(stat.kind, StatKind::Local { .. } | StatKind::Label(_)))
}

fn block_ends_with_return(block: &Block) -> bool {
    block
        .stats
        .last()
        .is_some_and(|stat: &Stat| matches!(stat.kind, StatKind::Return(_)))
}

fn block_returns(block: &Block) -> bool {
    let mut returns: bool = false;
    for stat in &block.stats {
        if matches!(stat.kind, StatKind::Return(_)) {
            returns = true;
        }
        for_each_child_block(stat, &mut |child: &Block| {
            if block_returns(child) {
                returns = true;
            }
        });
    }
    returns
}

fn is_local(expr: &Expr, id: LocalId) -> bool {
    matches!(expr.kind, ExprKind::Var(Var::Local(found)) if found == id)
}

fn is_local_compare(expr: &Expr, op: BinOp, left: LocalId, right: LocalId) -> bool {
    matches!(&expr.kind, ExprKind::Binary(found, a, b) if *found == op && is_local(a, left) && is_local(b, right))
}

fn field_name(src: &str, key: &Expr) -> Option<String> {
    if !matches!(key.kind, ExprKind::Str) {
        return None;
    }
    let text: &str = key.span.text(src);
    if is_literal(text) {
        literal_bytes(text).and_then(|bytes: Vec<u8>| String::from_utf8(bytes).ok())
    } else {
        Some(text.to_owned())
    }
}

fn global_path<'s>(src: &'s str, expr: &Expr) -> Option<(&'s str, Option<String>)> {
    match &expr.kind {
        ExprKind::Var(Var::Global(span)) => Some((span.text(src), None)),
        ExprKind::Index(base, key) => {
            let ExprKind::Var(Var::Global(span)) = &base.kind else {
                return None;
            };
            let field: &str = key.span.text(src);
            if matches!(key.kind, ExprKind::Str) && !is_literal(field) {
                Some((span.text(src), Some(field.to_owned())))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn truncate(text: &str, limit: usize) -> &str {
    let mut end: usize = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Const {
    Int(i64),
    Bool(bool),
}

impl Const {
    const fn truthy(self) -> bool {
        match self {
            Self::Int(_) => true,
            Self::Bool(value) => value,
        }
    }

    const fn as_int(self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(value),
            Self::Bool(_) => None,
        }
    }
}

fn eval_const(src: &str, expr: &Expr) -> Option<Const> {
    match &expr.kind {
        ExprKind::Number(_) => int_literal(expr.span.text(src)).map(Const::Int),
        ExprKind::True => Some(Const::Bool(true)),
        ExprKind::False => Some(Const::Bool(false)),
        ExprKind::Paren(inner) => eval_const(src, inner),
        ExprKind::Unary(UnOp::Neg, inner) => eval_const(src, inner)?
            .as_int()?
            .checked_neg()
            .map(Const::Int),
        ExprKind::Unary(UnOp::Not, inner) => Some(Const::Bool(!eval_const(src, inner)?.truthy())),
        ExprKind::Binary(op, left, right) => {
            let a: Const = eval_const(src, left)?;
            match op {
                BinOp::And => {
                    return if a.truthy() {
                        eval_const(src, right)
                    } else {
                        Some(a)
                    };
                }
                BinOp::Or => {
                    return if a.truthy() {
                        Some(a)
                    } else {
                        eval_const(src, right)
                    };
                }
                _ => {}
            }
            let b: Const = eval_const(src, right)?;
            match op {
                BinOp::Eq => Some(Const::Bool(a == b)),
                BinOp::Ne => Some(Const::Bool(a != b)),
                BinOp::Add => a.as_int()?.checked_add(b.as_int()?).map(Const::Int),
                BinOp::Sub => a.as_int()?.checked_sub(b.as_int()?).map(Const::Int),
                BinOp::Mul => a.as_int()?.checked_mul(b.as_int()?).map(Const::Int),
                BinOp::Mod => lua_floor_mod(a.as_int()?, b.as_int()?).map(Const::Int),
                BinOp::Lt => Some(Const::Bool(a.as_int()? < b.as_int()?)),
                BinOp::Le => Some(Const::Bool(a.as_int()? <= b.as_int()?)),
                BinOp::Gt => Some(Const::Bool(a.as_int()? > b.as_int()?)),
                BinOp::Ge => Some(Const::Bool(a.as_int()? >= b.as_int()?)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn lua_floor_mod(a: i64, b: i64) -> Option<i64> {
    let r: i64 = a.checked_rem(b)?;
    if r != 0 && (r < 0) != (b < 0) {
        r.checked_add(b)
    } else {
        Some(r)
    }
}

fn int_literal(text: &str) -> Option<i64> {
    if text.is_empty() || text.len() > 18 || !text.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

fn caesar_decode(bytes: &[u8], key: i64) -> Option<Vec<u8>> {
    if key.abs() > MAX_CAESAR_KEY {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    for &byte in bytes {
        let value: i64 = i64::from(byte);
        let shifted: i64 = match byte {
            b'0'..=b'9' => lua_floor_mod(value - 48 - key + 10, 10)? + 48,
            b'A'..=b'Z' => lua_floor_mod(value - 65 - key + 26, 26)? + 65,
            b'a'..=b'z' => lua_floor_mod(value - 97 - key + 26, 26)? + 97,
            _ => value,
        };
        out.push(u8::try_from(shifted).ok()?);
    }
    Some(out)
}

fn is_literal(text: &str) -> bool {
    matches!(text.as_bytes().first(), Some(b'"' | b'\'' | b'['))
}

fn literal_bytes(text: &str) -> Option<Vec<u8>> {
    let bytes: &[u8] = text.as_bytes();
    match bytes.first()? {
        b'[' => long_literal_bytes(bytes),
        quote @ (b'"' | b'\'') => {
            if bytes.len() < 2 || bytes[bytes.len() - 1] != *quote {
                return None;
            }
            short_literal_bytes(&bytes[1..bytes.len() - 1])
        }
        _ => None,
    }
}

fn long_literal_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let level: usize = bytes[1..].iter().take_while(|b: &&u8| **b == b'=').count();
    let open: usize = level + 2;
    if bytes.get(open - 1) != Some(&b'[') || bytes.len() < open * 2 {
        return None;
    }
    let mut body: &[u8] = &bytes[open..bytes.len() - open];
    if body.first() == Some(&b'\r') {
        body = &body[1..];
        if body.first() == Some(&b'\n') {
            body = &body[1..];
        }
    } else if body.first() == Some(&b'\n') {
        body = &body[1..];
        if body.first() == Some(&b'\r') {
            body = &body[1..];
        }
    }
    Some(body.to_vec())
}

fn short_literal_bytes(body: &[u8]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len());
    let mut i: usize = 0;
    while i < body.len() {
        let byte: u8 = body[i];
        if byte != b'\\' {
            out.push(byte);
            i += 1;
            continue;
        }
        let escape: u8 = *body.get(i + 1)?;
        i += 2;
        match escape {
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0C),
            b'n' | b'\n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0B),
            b'\\' | b'"' | b'\'' => out.push(escape),
            b'\r' => {
                out.push(b'\n');
                if body.get(i) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'x' => {
                let hi: u8 = hex_value(*body.get(i)?)?;
                let lo: u8 = hex_value(*body.get(i + 1)?)?;
                out.push((hi << 4) | lo);
                i += 2;
            }
            b'z' => {
                while body.get(i).is_some_and(u8::is_ascii_whitespace) {
                    i += 1;
                }
            }
            b'u' => {
                if body.get(i) != Some(&b'{') {
                    return None;
                }
                let close: usize = i + body[i..].iter().position(|b: &u8| *b == b'}')?;
                let digits: &str = core::str::from_utf8(&body[i + 1..close]).ok()?;
                let code: u32 = u32::from_str_radix(digits, 16).ok()?;
                let ch: char = char::from_u32(code)?;
                let mut buf: [u8; 4] = [0; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                i = close + 1;
            }
            b'0'..=b'9' => {
                let mut value: u32 = u32::from(escape - b'0');
                let mut taken: usize = 1;
                while taken < 3
                    && let Some(digit) = body.get(i).filter(|b: &&u8| b.is_ascii_digit())
                {
                    value = value * 10 + u32::from(digit - b'0');
                    i += 1;
                    taken += 1;
                }
                out.push(u8::try_from(value).ok()?);
            }
            _ => return None,
        }
    }
    Some(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn lua_quote(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\{byte:03}")),
        }
    }
    out.push('"');
    out
}

fn for_each_child_block(stat: &Stat, f: &mut dyn FnMut(&Block)) {
    match &stat.kind {
        StatKind::Do(body)
        | StatKind::While { body, .. }
        | StatKind::Repeat { body, .. }
        | StatKind::NumericFor { body, .. }
        | StatKind::GenericFor { body, .. } => f(body),
        StatKind::If { arms, else_body } => {
            for (_, body) in arms {
                f(body);
            }
            if let Some(body) = else_body {
                f(body);
            }
        }
        StatKind::Local { .. }
        | StatKind::Assign { .. }
        | StatKind::ExprStat(_)
        | StatKind::Return(_)
        | StatKind::Break
        | StatKind::Goto(_)
        | StatKind::Label(_) => {}
    }
}

fn for_each_direct_expr(stat: &Stat, f: &mut dyn FnMut(&Expr)) {
    match &stat.kind {
        StatKind::Local { values, .. } => {
            for value in values {
                f(value);
            }
        }
        StatKind::Assign { targets, values } => {
            for target in targets {
                if let AssignTarget::Index(base, key, _) = target {
                    f(base);
                    f(key);
                }
            }
            for value in values {
                f(value);
            }
        }
        StatKind::ExprStat(expr) => f(expr),
        StatKind::While { cond, .. } | StatKind::Repeat { cond, .. } => f(cond),
        StatKind::If { arms, .. } => {
            for (cond, _) in arms {
                f(cond);
            }
        }
        StatKind::NumericFor {
            start, stop, step, ..
        } => {
            f(start);
            f(stop);
            if let Some(step) = step {
                f(step);
            }
        }
        StatKind::GenericFor { exprs, .. } => {
            for expr in exprs {
                f(expr);
            }
        }
        StatKind::Return(values) => {
            for value in values {
                f(value);
            }
        }
        StatKind::Do(_) | StatKind::Break | StatKind::Goto(_) | StatKind::Label(_) => {}
    }
}

fn for_each_subexpr(expr: &Expr, f: &mut dyn FnMut(&Expr)) {
    match &expr.kind {
        ExprKind::Index(base, key) => {
            f(base);
            f(key);
        }
        ExprKind::Call { base, args } | ExprKind::MethodCall { base, args, .. } => {
            f(base);
            for arg in args {
                f(arg);
            }
        }
        ExprKind::Table(fields) => {
            for field in fields {
                match field {
                    TableField::Positional(value) | TableField::Named(_, value) => f(value),
                    TableField::Indexed(key, value) => {
                        f(key);
                        f(value);
                    }
                }
            }
        }
        ExprKind::Binary(_, left, right) => {
            f(left);
            f(right);
        }
        ExprKind::Unary(_, inner) | ExprKind::Paren(inner) => f(inner),
        ExprKind::Nil
        | ExprKind::True
        | ExprKind::False
        | ExprKind::Vararg
        | ExprKind::Number(_)
        | ExprKind::Str
        | ExprKind::Var(_)
        | ExprKind::Function { .. } => {}
    }
}

fn visit_expr_deep(expr: &Expr, f: &mut dyn FnMut(&Expr)) {
    f(expr);
    if let ExprKind::Function { body, .. } = &expr.kind {
        for_each_expr_in_block(body, f);
        return;
    }
    for_each_subexpr(expr, &mut |child: &Expr| visit_expr_deep(child, f));
}

fn for_each_expr_in_stat(stat: &Stat, f: &mut dyn FnMut(&Expr)) {
    for_each_direct_expr(stat, &mut |expr: &Expr| visit_expr_deep(expr, f));
    for_each_child_block(stat, &mut |child: &Block| for_each_expr_in_block(child, f));
}

fn for_each_expr_in_block(block: &Block, f: &mut dyn FnMut(&Expr)) {
    for stat in &block.stats {
        for_each_expr_in_stat(stat, f);
    }
}

fn visit_expr_shallow(expr: &Expr, f: &mut dyn FnMut(&Expr)) {
    f(expr);
    if !matches!(expr.kind, ExprKind::Function { .. }) {
        for_each_subexpr(expr, &mut |child: &Expr| visit_expr_shallow(child, f));
    }
}

fn for_each_function_body(stat: &Stat, f: &mut dyn FnMut(&Block)) {
    for_each_direct_expr(stat, &mut |expr: &Expr| {
        visit_expr_shallow(expr, &mut |inner: &Expr| {
            if let ExprKind::Function { body, .. } = &inner.kind {
                f(body);
            }
        });
    });
}

fn for_each_stat_in(stat: &Stat, f: &mut dyn FnMut(&Stat)) {
    f(stat);
    for_each_child_block(stat, &mut |child: &Block| {
        for inner in &child.stats {
            for_each_stat_in(inner, f);
        }
    });
    for_each_function_body(stat, &mut |body: &Block| {
        for nested in &body.stats {
            for_each_stat_in(nested, f);
        }
    });
}

fn for_each_stat(block: &Block, f: &mut dyn FnMut(&Stat)) {
    for stat in &block.stats {
        for_each_stat_in(stat, f);
    }
}

fn for_each_block(block: &Block, f: &mut dyn FnMut(&Block)) {
    f(block);
    for stat in &block.stats {
        for_each_child_block(stat, &mut |child: &Block| for_each_block(child, f));
        for_each_function_body(stat, &mut |body: &Block| for_each_block(body, f));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{
        Edit, SourceRecovery, apply_groups, caesar_decode, literal_bytes, lua_quote, recover_source,
    };

    fn recover(src: &str) -> SourceRecovery {
        recover_source(src)
    }

    #[test]
    fn caesar_decode_inverts_the_hercules_cipher() {
        assert_eq!(
            caesar_decode(b"Gdkkn Vnqkc", 25).expect("decode"),
            b"Hello World".to_vec()
        );
        assert_eq!(
            caesar_decode(b"%4.1y|%w|%l", 19).expect("decode"),
            b"%5.2f|%d|%s".to_vec()
        );
        assert!(caesar_decode(b"a", i64::MAX).is_none());
    }

    #[test]
    fn literal_bytes_follow_lua_escape_rules() {
        assert_eq!(
            literal_bytes(r#""\65\x42\u{43}\z    D\n\"""#).expect("short literal"),
            b"ABCD\n\"".to_vec()
        );
        assert_eq!(
            literal_bytes("[==[\nx]]y]==]").expect("long literal"),
            b"x]]y".to_vec()
        );
        assert!(literal_bytes("name").is_none());
        assert!(literal_bytes(r#""\300""#).is_none());
        assert_eq!(lua_quote(b"a\"\\\n\x01"), r#""a\"\\\n\001""#);
    }

    #[test]
    fn overlapping_edit_groups_apply_atomically() {
        let src: &str = "[{(<>)}]";
        let groups: Vec<Vec<Edit>> = vec![
            vec![Edit::delete(1, 3)],
            vec![Edit::delete(4, 5), Edit::delete(2, 4)],
            vec![
                Edit {
                    start: 5,
                    end: 5,
                    text: "X".to_owned(),
                },
                Edit::delete(5, 6),
            ],
        ];
        assert_eq!(apply_groups(src, groups).expect("edits"), "[<>X}]");
        assert_eq!(
            apply_groups("end;local x", vec![vec![Edit::delete(3, 4)]]).expect("edits"),
            "end local x"
        );
    }

    #[test]
    fn alias_block_stays_when_the_aliased_global_is_rebound() {
        let src: &str = "local a,b;a=print;b=type;print=function(...) end;a(b(1))";
        let out: SourceRecovery = recover(src);
        assert!(out.source.contains("a=print"), "{}", out.source);
        assert!(
            out.residual
                .iter()
                .any(|marker: &String| marker.contains("global alias")),
            "{:?}",
            out.residual
        );
    }

    #[test]
    fn alias_block_inlines_when_globals_are_stable() {
        let src: &str = "local a,b;a=print;b=string.format;a(b(\"%d\",1))";
        let out: SourceRecovery = recover(src);
        assert_eq!(out.source, "print(string.format(\"%d\",1))\n");
        assert!(out.residual.is_empty(), "{:?}", out.residual);
    }

    #[test]
    fn control_flow_wrapper_stays_when_the_program_reads_its_counter() {
        let src: &str = "local thing=5;local thing2=5;local counter=0;while thing==thing2 and counter<1 do thing=thing+1;counter=counter+1;if thing==thing2 then local x=1 else do print(counter) end break end end";
        let out: SourceRecovery = recover(src);
        assert!(out.source.contains("thing==thing2"), "{}", out.source);
        assert!(
            out.residual
                .iter()
                .any(|marker: &String| marker.contains("control-flow")),
            "{:?}",
            out.residual
        );
    }

    #[test]
    fn opaque_predicates_fold_and_keep_scoped_bodies() {
        let src: &str = "if 7%7==0 then print(1) end if (not(3>=60))==(3<60) then local x=2 print(x) elseif 4>4 then end local y=3 print(y)";
        let out: SourceRecovery = recover(src);
        assert_eq!(
            out.source,
            "print(1)\ndo\n  local x=2\n  print(x)\nend\nlocal y=3\nprint(y)\n"
        );
    }

    #[test]
    fn inlined_function_reading_an_out_of_scope_upvalue_is_named_not_hoisted() {
        let src: &str = "(function(...) local function g(n) if n>0 then return (function(m) return g(m) end)(n-1) end return 0 end print((function(m) return g(m) end)(3)) end)()";
        let out: SourceRecovery = recover(src);
        assert!(out.source.contains("(function(m)"), "{}", out.source);
        assert!(
            out.residual
                .iter()
                .any(|marker: &String| marker.contains("function-inlining")
                    || marker.contains("inlined function")),
            "{:?}",
            out.residual
        );
    }

    #[test]
    fn hostile_sources_end_in_a_named_residual_without_panicking() {
        let deep: String = format!("{}print(1){}", "do ".repeat(400), " end".repeat(400));
        let wide: String = "local a=(function() return 1 end)() ".repeat(2000);
        for src in [
            "",
            "((((",
            "local",
            "\"open",
            "goto",
            "::x",
            deep.as_str(),
            wide.as_str(),
        ] {
            let out: SourceRecovery = recover(src);
            assert!(out.source.ends_with('\n'));
            if src.starts_with("((") || src == "local" || src == "\"open" || src == "::x" {
                assert!(
                    out.residual
                        .iter()
                        .any(|marker: &String| marker.contains("does not parse")),
                    "{src:?}: {:?}",
                    out.residual
                );
            }
        }
    }

    #[test]
    fn lua_5_4_source_without_layers_round_trips() {
        let src: &str = "local x <const> = 7 // 2 goto done print(x) ::done:: print(1 << 4, ~0)";
        let out: SourceRecovery = recover(src);
        assert!(out.residual.is_empty(), "{:?}", out.residual);
        assert!(out.passes.is_empty(), "{:?}", out.passes);
        assert_eq!(
            out.source,
            "local x <const> = 7 // 2\ngoto done\nprint(x)\n::done::\nprint(1 << 4, ~0)\n"
        );
    }
}
