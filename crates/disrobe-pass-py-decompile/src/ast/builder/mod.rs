use disrobe_py_marshal::{CodeObject, Object};

use crate::ast::node::{AstModule, ConstValue, Expr, Stmt};
use crate::bytecode::flow::ExceptionTableEntry;
use crate::bytecode::opcode::{CanonicalOp, CmpOp, OpcodeMap, map_for};
use crate::bytecode::version::PyVersion;
use crate::error::{DecompileError, Result};
use crate::frame_tree::{Frame, FrameKind, FrameTree};

mod branches;
mod comprehensions;
mod exprs;
mod function_meta;
mod loops;
mod postprocess;
mod stmts;
mod try_with;

use self::exprs::name_at;
use self::function_meta::{prepend_global_decls, thread_module_annotations};
pub(crate) use self::postprocess::is_simple_identifier;
use self::postprocess::{
    BodyKind, postprocess_body, strip_module_docstring_stmt, strip_module_implicit_return,
    strip_module_scope_implicit_returns,
};
use self::stmts::{
    OpenCodedAnyAll, build_frame, detect_inline_comprehension, detect_open_coded_any_all_guard,
    recover_open_coded_call, resolve_jump_target, structure_stmts,
};

const MAX_SYNTH_OPERANDS: usize = 1 << 16;

pub trait AstBuilder: Send + Sync + core::fmt::Debug {
    fn build_module(
        &self,
        code: &CodeObject,
        frame_tree: &FrameTree,
        version: &PyVersion,
    ) -> Result<AstModule>;
}

#[derive(Debug, Default)]
pub struct DefaultAstBuilder;

impl DefaultAstBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl AstBuilder for DefaultAstBuilder {
    fn build_module(
        &self,
        code: &CodeObject,
        frame_tree: &FrameTree,
        version: &PyVersion,
    ) -> Result<AstModule> {
        set_active_version(version);
        set_future_annotations(code.flags);
        let opmap: Box<dyn OpcodeMap> = map_for(version.clone());
        let stream: DecodedStream = decode_stream_with_offsets(code, opmap.as_ref(), version);
        let module_docstring: Option<String> = class_docstring(code, &stream.ops);
        let route_via_sim: bool = matches!(frame_tree.root.kind, FrameKind::Module)
            && (frame_tree.root.children.is_empty()
                || legacy_loop_module_route(version, &frame_tree.root)
                || module_loop_flatten_route(&frame_tree.root)
                || module_exc_route(&frame_tree.root)
                || module_inline_comp_route(&stream, &frame_tree.root));
        let raw_body: Vec<Stmt> = if route_via_sim {
            let _code_scope: NestedCodeScope = NestedCodeScope::enter();
            let region_end: usize = module_reachable_end(&stream);
            structure_stmts(code, &stream, 0, region_end)?
        } else {
            build_frame(code, &frame_tree.root, &stream.ops)?
        };
        let stripped: Vec<Stmt> =
            strip_module_implicit_return(strip_module_docstring_stmt(raw_body, code));
        let mut postprocessed: Vec<Stmt> = postprocess_body(stripped, BodyKind::Module);
        strip_module_scope_implicit_returns(&mut postprocessed);
        let body: Vec<Stmt> =
            prepend_global_decls(code, &stream.ops, thread_module_annotations(postprocessed));
        Ok(AstModule {
            docstring: module_docstring,
            body,
            blank_lines: std::collections::BTreeMap::new(),
        })
    }
}

fn legacy_loop_module_route(version: &PyVersion, root: &Frame) -> bool {
    let is_legacy: bool = version.major() < 3 || version.minor() < 2;
    is_legacy
        && !root.children.is_empty()
        && root.children.iter().all(|c: &Frame| {
            matches!(
                c.kind,
                FrameKind::WhileLoop
                    | FrameKind::ForLoop
                    | FrameKind::AsyncForLoop
                    | FrameKind::Try
            )
        })
}

fn module_loop_flatten_route(root: &Frame) -> bool {
    root.children.iter().any(|c: &Frame| {
        matches!(
            c.kind,
            FrameKind::ForLoop | FrameKind::AsyncForLoop | FrameKind::WhileLoop
        )
    })
}

fn module_exc_route(root: &Frame) -> bool {
    root.children.iter().any(|c: &Frame| {
        matches!(
            c.kind,
            FrameKind::Try | FrameKind::With | FrameKind::AsyncWith | FrameKind::ExceptGroup
        )
    })
}

fn module_inline_comp_route(stream: &DecodedStream, root: &Frame) -> bool {
    matches!(root.kind, FrameKind::Module)
        && detect_inline_comprehension(stream, 0, stream.ops.len()).is_some()
}

fn module_reachable_end(stream: &DecodedStream) -> usize {
    let full: usize = stream.ops.len();
    if stream.exception_table.is_empty() {
        return full;
    }
    let Some(min_target): Option<u32> = stream
        .exception_table
        .iter()
        .map(|e: &ExceptionTableEntry| e.target)
        .min()
    else {
        return full;
    };
    let Some(cluster_start): Option<usize> = stream.index_for_offset(min_target) else {
        return full;
    };
    if cluster_start == 0 || cluster_start >= full {
        return full;
    }
    if !prev_significant_is_hard_terminator(stream, cluster_start) {
        return full;
    }
    if !trailing_cluster_is_with_or_cleanup_only(stream, min_target) {
        return full;
    }
    if reachable_jump_enters_cluster(stream, cluster_start) {
        return full;
    }
    cluster_start
}

fn reachable_jump_enters_cluster(stream: &DecodedStream, cluster_start: usize) -> bool {
    (0..cluster_start).any(|i: usize| {
        resolve_jump_target(stream, i, &stream.ops[i]).is_some_and(|t: usize| t >= cluster_start)
    })
}

fn prev_significant_is_hard_terminator(stream: &DecodedStream, from: usize) -> bool {
    (0..from)
        .rev()
        .find_map(|i: usize| match &stream.ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => None,
            other => Some(matches!(
                other,
                CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Reraise(_)
            )),
        })
        .unwrap_or(false)
}

fn trailing_cluster_is_with_or_cleanup_only(stream: &DecodedStream, min_target: u32) -> bool {
    stream
        .exception_table
        .iter()
        .filter(|e: &&ExceptionTableEntry| e.target >= min_target)
        .all(|e: &ExceptionTableEntry| {
            stream
                .index_for_offset(e.target)
                .is_some_and(|hidx: usize| handler_is_with_or_cleanup(stream, hidx))
        })
}

fn handler_is_with_or_cleanup(stream: &DecodedStream, hidx: usize) -> bool {
    let next_significant = |from: usize| -> Option<usize> {
        (from..stream.ops.len()).find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
    };
    match stream.ops.get(hidx) {
        Some(CanonicalOp::PushExcInfo) => next_significant(hidx + 1)
            .is_some_and(|nx: usize| matches!(stream.ops[nx], CanonicalOp::WithExceptStart)),
        Some(CanonicalOp::Copy(_)) => next_significant(hidx + 1)
            .and_then(|a: usize| matches!(stream.ops[a], CanonicalOp::PopExcept).then_some(a))
            .and_then(|a: usize| next_significant(a + 1))
            .is_some_and(|b: usize| matches!(stream.ops[b], CanonicalOp::Reraise(_))),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FrameDispatch {
    Module,
    FunctionDef,
    ClassDef,
    Try,
    With,
    AsyncWith,
    For,
    AsyncFor,
    While,
    IfChain,
    Match,
    Lambda,
    Comprehension,
    ExceptHandler,
    FinallyClause,
    ExceptGroup,
}

impl FrameDispatch {
    #[must_use]
    pub const fn from_kind(kind: FrameKind) -> Self {
        match kind {
            FrameKind::Module => Self::Module,
            FrameKind::FunctionDef => Self::FunctionDef,
            FrameKind::ClassDef => Self::ClassDef,
            FrameKind::Try => Self::Try,
            FrameKind::With => Self::With,
            FrameKind::AsyncWith => Self::AsyncWith,
            FrameKind::ForLoop => Self::For,
            FrameKind::AsyncForLoop => Self::AsyncFor,
            FrameKind::WhileLoop => Self::While,
            FrameKind::IfChain => Self::IfChain,
            FrameKind::MatchStmt => Self::Match,
            FrameKind::Lambda => Self::Lambda,
            FrameKind::Comprehension => Self::Comprehension,
            FrameKind::ExceptHandler => Self::ExceptHandler,
            FrameKind::FinallyClause => Self::FinallyClause,
            FrameKind::ExceptGroup => Self::ExceptGroup,
        }
    }
}

const PY_CO_FLAG_HAS_DOCSTRING: i32 = 0x4_000_000;

const PY_CO_FLAG_FUNCTION_SCOPE: i32 = 0x0001 | 0x0002;

fn version_uses_docstring_flag() -> bool {
    active_version().is_some_and(|v: PyVersion| {
        let (maj, min): (u8, u8) = (v.major(), v.minor());
        maj > 3 || (maj == 3 && min >= 14)
    })
}

fn extract_docstring(code: &CodeObject) -> Option<String> {
    let is_function: bool = (code.flags & PY_CO_FLAG_FUNCTION_SCOPE) == PY_CO_FLAG_FUNCTION_SCOPE;
    if is_function && version_uses_docstring_flag() && (code.flags & PY_CO_FLAG_HAS_DOCSTRING) == 0
    {
        return None;
    }
    match code.consts.first()? {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

fn const_str_at(code: &CodeObject, idx: u32) -> Option<String> {
    match code.consts.get(idx as usize)? {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

fn class_docstring(code: &CodeObject, ops: &[CanonicalOp]) -> Option<String> {
    for window in ops.windows(2) {
        if let [CanonicalOp::LoadConst(k), CanonicalOp::StoreName(n)] = window
            && name_at(&code.names, *n, 0, "name").is_ok_and(|s: String| s == "__doc__")
        {
            return const_str_at(code, *k);
        }
    }
    None
}

fn decode_stream(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
) -> Vec<CanonicalOp> {
    let mut out: Vec<CanonicalOp> = Vec::new();
    if version.supports_word_code() {
        decode_wordcode(code, opmap, version, &mut out);
    } else {
        decode_legacy(code, opmap, &mut out);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoneJumpKind {
    IsNotNone,

    IsNone,
}

#[derive(Debug, Clone)]
struct DecodedStream {
    ops: Vec<CanonicalOp>,
    offsets: Vec<u32>,
    next_offsets: Vec<u32>,
    code_len: u32,
    lines: Vec<Option<u32>>,
    wordcode: bool,
    instr_unit_jumps: bool,
    relative_cond_jumps: bool,
    exception_table: Vec<crate::bytecode::flow::ExceptionTableEntry>,
    pre311_end_finally_idx: std::collections::BTreeSet<usize>,
    pre311_pop_block_idx: std::collections::BTreeSet<usize>,
    pre311_break_loop_idx: std::collections::BTreeSet<usize>,
    setup_loop_end: std::collections::BTreeMap<usize, usize>,
    none_jump_kind: std::collections::BTreeMap<usize, NoneJumpKind>,
    version: PyVersion,
}

impl DecodedStream {
    fn index_for_offset(&self, byte_offset: u32) -> Option<usize> {
        self.offsets.binary_search(&byte_offset).ok()
    }

    fn index_for_offset_ceil(&self, byte_offset: u32) -> Option<usize> {
        let idx: usize = self.offsets.partition_point(|&o: &u32| o < byte_offset);
        if idx < self.offsets.len() {
            Some(idx)
        } else {
            None
        }
    }

    fn supports_match(&self) -> bool {
        let (maj, min): (u8, u8) = (self.version.major(), self.version.minor());
        maj > 3 || (maj == 3 && min >= 10)
    }

    fn line_at(&self, idx: usize) -> Option<u32> {
        self.lines.get(idx).copied().flatten()
    }

    fn is_pre_311(&self) -> bool {
        self.version.is_pre_311()
    }
}

fn decode_stream_with_offsets(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
) -> DecodedStream {
    let mut ops: Vec<CanonicalOp> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();
    let mut next_offsets: Vec<u32> = Vec::new();
    let mut extended_arg_lead_ins: Vec<u32> = Vec::new();
    let wordcode: bool = version.supports_word_code();
    if wordcode {
        decode_wordcode_with_offsets(
            code,
            opmap,
            version,
            &mut ops,
            &mut offsets,
            &mut next_offsets,
            &mut extended_arg_lead_ins,
        );
    } else {
        decode_legacy_with_offsets(code, opmap, &mut ops, &mut offsets, &mut next_offsets);
    }
    let instr_unit_jumps: bool =
        version.major() > 3 || (version.major() == 3 && version.minor() >= 10);
    let relative_cond_jumps: bool = !version.is_pre_311();
    let code_len: u32 = u32::try_from(code.code.len()).unwrap_or(u32::MAX);
    let exception_table: Vec<crate::bytecode::flow::ExceptionTableEntry> = if version
        .supports_pep_657_exception_table()
        && !code.exceptiontable.is_empty()
    {
        let parsed: Vec<crate::bytecode::flow::ExceptionTableEntry> =
            crate::bytecode::flow::parse_exception_table(&code.exceptiontable).unwrap_or_default();
        let boundary_offsets: Vec<u32> = if extended_arg_lead_ins.is_empty() {
            offsets.clone()
        } else {
            let mut merged: Vec<u32> =
                Vec::with_capacity(offsets.len() + extended_arg_lead_ins.len());
            merged.extend_from_slice(&offsets);
            merged.extend_from_slice(&extended_arg_lead_ins);
            merged.sort_unstable();
            merged.dedup();
            merged
        };
        crate::bytecode::flow::followable_exception_entries(&parsed, &boundary_offsets, code_len)
    } else if version.is_pre_311() {
        synthesize_pre_311_exception_table(code, opmap, version)
    } else {
        Vec::new()
    };
    let pre311_end_finally_idx: std::collections::BTreeSet<usize> = if version.is_pre_311() {
        collect_pre_311_opcode_indices(
            code,
            opmap,
            version,
            &offsets,
            &["END_FINALLY", "END_ASYNC_FOR"],
        )
    } else {
        std::collections::BTreeSet::new()
    };
    let pre311_pop_block_idx: std::collections::BTreeSet<usize> = if version.is_pre_311() {
        collect_pre_311_opcode_indices(code, opmap, version, &offsets, &["POP_BLOCK"])
    } else {
        std::collections::BTreeSet::new()
    };
    let pre311_break_loop_idx: std::collections::BTreeSet<usize> = if version.is_pre_311() {
        collect_pre_311_opcode_indices(code, opmap, version, &offsets, &["BREAK_LOOP"])
    } else {
        std::collections::BTreeSet::new()
    };
    let setup_loop_end: std::collections::BTreeMap<usize, usize> =
        if version.major() < 3 || version.minor() < 2 {
            collect_setup_loop_ends(code, opmap, &offsets)
        } else if version.major() == 3 && version.minor() < 8 {
            collect_setup_loop_ends_wordcode(code, opmap, &offsets)
        } else {
            std::collections::BTreeMap::new()
        };
    let lines: Vec<Option<u32>> = decode_lines_for_offsets(code, version, &offsets);
    let none_jump_kind: std::collections::BTreeMap<usize, NoneJumpKind> =
        collect_none_jump_kinds(code, opmap, version, &offsets);
    let mut stream: DecodedStream = DecodedStream {
        ops,
        offsets,
        next_offsets,
        code_len,
        lines,
        wordcode,
        instr_unit_jumps,
        relative_cond_jumps,
        exception_table,
        pre311_end_finally_idx,
        pre311_pop_block_idx,
        pre311_break_loop_idx,
        setup_loop_end,
        none_jump_kind,
        version: version.clone(),
    };
    normalize_open_coded_idioms(code, &mut stream);
    stream
}

fn normalize_open_coded_idioms(code: &CodeObject, stream: &mut DecodedStream) {
    let mut rewrites: Vec<(usize, Vec<CanonicalOp>, usize)> = Vec::new();
    let mut idiom_offset_spans: Vec<(u32, u32)> = Vec::new();
    let mut cursor: usize = 0;
    while cursor < stream.ops.len() {
        let Some((builtin, fallback_start)): Option<(&'static str, usize)> =
            detect_open_coded_any_all_guard(code, stream, cursor, stream.ops.len())
        else {
            cursor += 1;
            continue;
        };
        let idiom: OpenCodedAnyAll = OpenCodedAnyAll {
            builtin,
            fallback_start,
        };
        let Ok(Some((_, terminal_call))): Result<Option<(Expr, usize)>> =
            recover_open_coded_call(code, stream, &idiom, stream.ops.len())
        else {
            cursor += 1;
            continue;
        };
        if terminal_call <= cursor || fallback_start <= cursor {
            cursor += 1;
            continue;
        }
        let mut replacement: Vec<CanonicalOp> = Vec::with_capacity(terminal_call - cursor + 1);
        replacement.push(stream.ops[cursor].clone());
        replacement.extend_from_slice(&stream.ops[fallback_start..=terminal_call]);
        let span: usize = terminal_call - cursor + 1;
        if replacement.len() > span {
            cursor = terminal_call + 1;
            continue;
        }
        if let (Some(&span_lo), Some(&span_hi)) = (
            stream.offsets.get(cursor),
            stream.next_offsets.get(terminal_call),
        ) {
            idiom_offset_spans.push((span_lo, span_hi));
        }
        rewrites.push((cursor, replacement, span));
        cursor = terminal_call + 1;
    }
    for (start, replacement, span) in rewrites {
        let replacement_len: usize = replacement.len();
        stream.ops[start..start + replacement_len].clone_from_slice(&replacement);
        for slot in &mut stream.ops[start + replacement_len..start + span] {
            *slot = CanonicalOp::Nop;
        }
    }
    coalesce_open_coded_exc_fragments(stream, &idiom_offset_spans);
}

fn coalesce_open_coded_exc_fragments(
    stream: &mut DecodedStream,
    idiom_offset_spans: &[(u32, u32)],
) {
    if stream.exception_table.len() < 2 || idiom_offset_spans.is_empty() {
        return;
    }
    let touches_idiom = |lo: u32, hi: u32| -> bool {
        idiom_offset_spans
            .iter()
            .any(|&(s, e): &(u32, u32)| lo < e && s < hi)
    };
    let original: Vec<crate::bytecode::flow::ExceptionTableEntry> = stream.exception_table.clone();
    let gap_holds_nested = |target: u32, gap_lo: u32, gap_hi: u32| -> bool {
        original
            .iter()
            .any(|e: &crate::bytecode::flow::ExceptionTableEntry| {
                e.target != target && e.start < gap_hi && e.end() > gap_lo
            })
    };
    let mut entries: Vec<crate::bytecode::flow::ExceptionTableEntry> = original.clone();
    entries.sort_by_key(|e: &crate::bytecode::flow::ExceptionTableEntry| e.start);
    let mut merged: Vec<crate::bytecode::flow::ExceptionTableEntry> =
        Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(last) = merged.last_mut() {
            let same_handler: bool = last.target == entry.target
                && last.depth == entry.depth
                && last.lasti == entry.lasti;
            let ordered: bool = entry.start >= last.end();
            if same_handler
                && ordered
                && !gap_holds_nested(entry.target, last.end(), entry.start)
                && (touches_idiom(last.start, last.end())
                    || touches_idiom(entry.start, entry.end()))
            {
                last.length = entry.end().saturating_sub(last.start);
                continue;
            }
        }
        merged.push(entry);
    }
    if merged.len() < original.len() {
        stream.exception_table = merged;
    }
}

fn decode_lines_for_offsets(
    code: &CodeObject,
    version: &PyVersion,
    offsets: &[u32],
) -> Vec<Option<u32>> {
    let marshal_version: disrobe_py_marshal::PyVersion = disrobe_py_marshal::PyVersion {
        major: version.major(),
        minor: version.minor(),
    };
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    let table_bytes: &[u8] = if maj > 3 || (maj == 3 && min >= 10) {
        &code.linetable
    } else {
        &code.lnotab
    };
    let table: Vec<crate::bytecode::flow::LineTableEntry> =
        crate::bytecode::flow::parse_line_table(table_bytes, marshal_version).unwrap_or_default();
    offsets
        .iter()
        .map(|&off: &u32| crate::bytecode::flow::line_for_offset(&table, off))
        .collect()
}

fn collect_none_jump_kinds(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
    offsets: &[u32],
) -> std::collections::BTreeMap<usize, NoneJumpKind> {
    let classify = |name: &str| -> Option<NoneJumpKind> {
        match name {
            "POP_JUMP_IF_NONE" | "POP_JUMP_FORWARD_IF_NONE" | "POP_JUMP_BACKWARD_IF_NONE" => {
                Some(NoneJumpKind::IsNotNone)
            }
            "POP_JUMP_IF_NOT_NONE"
            | "POP_JUMP_FORWARD_IF_NOT_NONE"
            | "POP_JUMP_BACKWARD_IF_NOT_NONE" => Some(NoneJumpKind::IsNone),
            _ => None,
        }
    };
    let bytes: &[u8] = &code.code;
    let wordcode: bool = version.supports_word_code();
    let mut byte_kind: std::collections::BTreeMap<u32, NoneJumpKind> =
        std::collections::BTreeMap::new();
    let mut cursor: usize = 0;
    if wordcode {
        while cursor + 1 < bytes.len() {
            let raw: u8 = bytes[cursor];
            if is_extended_arg(opmap, raw) {
                cursor += WIDE_STEP;
                continue;
            }
            if let Some(kind) = classify(opmap.opname(raw)) {
                byte_kind.insert(u32::try_from(cursor).unwrap_or(u32::MAX), kind);
            }
            cursor += WIDE_STEP;
            let caches: usize = usize::from(opmap.cache_size(raw));
            if caches > 0 {
                cursor += caches * WIDE_STEP;
            }
        }
    } else {
        while cursor < bytes.len() {
            let raw: u8 = bytes[cursor];
            if let Some(kind) = classify(opmap.opname(raw)) {
                byte_kind.insert(u32::try_from(cursor).unwrap_or(u32::MAX), kind);
            }
            if raw < LEGACY_HAVE_ARGUMENT {
                cursor += NARROW_STEP;
                continue;
            }
            if cursor + 2 >= bytes.len() {
                break;
            }
            cursor += 3;
        }
    }
    let mut out: std::collections::BTreeMap<usize, NoneJumpKind> =
        std::collections::BTreeMap::new();
    for (idx, off) in offsets.iter().enumerate() {
        if let Some(kind) = byte_kind.get(off) {
            out.insert(idx, *kind);
        }
    }
    out
}

fn none_jump_test(stream: &DecodedStream, jump_idx: usize, val: Expr) -> Option<Expr> {
    let op: CmpOp = match stream.none_jump_kind.get(&jump_idx)? {
        NoneJumpKind::IsNotNone => CmpOp::IsNot,
        NoneJumpKind::IsNone => CmpOp::Is,
    };
    Some(Expr::Compare {
        left: Box::new(val),
        ops: vec![op],
        comparators: vec![Expr::Constant {
            value: ConstValue::None,
            line: None,
        }],
    })
}

fn none_jump_test_taken(stream: &DecodedStream, jump_idx: usize, val: Expr) -> Option<Expr> {
    let op: CmpOp = match stream.none_jump_kind.get(&jump_idx)? {
        NoneJumpKind::IsNotNone => CmpOp::Is,
        NoneJumpKind::IsNone => CmpOp::IsNot,
    };
    Some(Expr::Compare {
        left: Box::new(val),
        ops: vec![op],
        comparators: vec![Expr::Constant {
            value: ConstValue::None,
            line: None,
        }],
    })
}

fn negate_cond_expr(expr: Expr) -> Expr {
    match expr {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand,
        } => *operand,
        Expr::Compare {
            left,
            ops,
            comparators,
        } if matches!(ops.as_slice(), [CmpOp::Is | CmpOp::IsNot])
            && matches!(
                comparators.as_slice(),
                [Expr::Constant {
                    value: ConstValue::None,
                    ..
                }]
            ) =>
        {
            let flipped: CmpOp = if ops[0] == CmpOp::Is {
                CmpOp::IsNot
            } else {
                CmpOp::Is
            };
            Expr::Compare {
                left,
                ops: vec![flipped],
                comparators,
            }
        }
        other => Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(other),
        },
    }
}

fn fallthrough_cond_test(stream: &DecodedStream, jump_idx: usize, raw: Expr) -> Expr {
    if let Some(test) = none_jump_test(stream, jump_idx, raw.clone()) {
        return test;
    }
    if matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
    ) {
        raw
    } else {
        negate_cond_expr(raw)
    }
}

fn collect_pre_311_opcode_indices(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
    offsets: &[u32],
    names: &[&str],
) -> std::collections::BTreeSet<usize> {
    let bytes: &[u8] = &code.code;
    let wordcode: bool = version.supports_word_code();
    let mut byte_set: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut cursor: usize = 0;
    if wordcode {
        while cursor + 1 < bytes.len() {
            let raw: u8 = bytes[cursor];
            if is_extended_arg(opmap, raw) {
                cursor += WIDE_STEP;
                continue;
            }
            let name: &str = opmap.opname(raw);
            if names.contains(&name) {
                byte_set.insert(u32::try_from(cursor).unwrap_or(u32::MAX));
            }
            cursor += WIDE_STEP;
            let caches: usize = usize::from(opmap.cache_size(raw));
            if caches > 0 {
                cursor += caches * WIDE_STEP;
            }
        }
    } else {
        while cursor < bytes.len() {
            let raw: u8 = bytes[cursor];
            let name: &str = opmap.opname(raw);
            if names.contains(&name) {
                byte_set.insert(u32::try_from(cursor).unwrap_or(u32::MAX));
            }
            if raw < LEGACY_HAVE_ARGUMENT {
                cursor += NARROW_STEP;
                continue;
            }
            if cursor + 2 >= bytes.len() {
                break;
            }
            cursor += 3;
        }
    }
    let mut out: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (idx, off) in offsets.iter().enumerate() {
        if byte_set.contains(off) {
            out.insert(idx);
        }
    }
    out
}

fn collect_setup_loop_ends(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    offsets: &[u32],
) -> std::collections::BTreeMap<usize, usize> {
    let bytes: &[u8] = &code.code;
    let mut byte_ends: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let raw: u8 = bytes[cursor];
        let name: &str = opmap.opname(raw);
        if raw < LEGACY_HAVE_ARGUMENT {
            cursor += NARROW_STEP;
            continue;
        }
        if cursor + 2 >= bytes.len() {
            break;
        }
        if name == "SETUP_LOOP" {
            let arg: u32 = u32::from(bytes[cursor + 1]) | (u32::from(bytes[cursor + 2]) << 8);
            let after: u32 = u32::try_from(cursor + 3).unwrap_or(u32::MAX);
            let end_byte: u32 = after.saturating_add(arg);
            byte_ends.insert(u32::try_from(cursor).unwrap_or(u32::MAX), end_byte);
        }
        cursor += 3;
    }
    let mut out: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for (idx, off) in offsets.iter().enumerate() {
        if let Some(end_byte) = byte_ends.get(off) {
            let end_idx: usize = offsets.partition_point(|&o: &u32| o < *end_byte);
            out.insert(idx, end_idx);
        }
    }
    out
}

fn collect_setup_loop_ends_wordcode(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    offsets: &[u32],
) -> std::collections::BTreeMap<usize, usize> {
    let bytes: &[u8] = &code.code;
    let mut byte_ends: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();
    let mut cursor: usize = 0;
    let mut extended: u64 = 0;
    while cursor + 1 < bytes.len() {
        let raw: u8 = bytes[cursor];
        let arg_byte: u8 = bytes[cursor + 1];
        if is_extended_arg(opmap, raw) {
            extended = accumulate_extended_arg(extended, arg_byte);
            cursor += 2;
            continue;
        }
        let arg: u32 = finalize_extended_arg(extended, arg_byte);
        extended = 0;
        if opmap.opname(raw) == "SETUP_LOOP" {
            let after: u32 = u32::try_from(cursor + 2).unwrap_or(u32::MAX);
            let end_byte: u32 = after.saturating_add(arg);
            byte_ends.insert(u32::try_from(cursor).unwrap_or(u32::MAX), end_byte);
        }
        cursor += 2;
    }
    let mut out: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for (idx, off) in offsets.iter().enumerate() {
        if let Some(end_byte) = byte_ends.get(off) {
            let end_idx: usize = offsets.partition_point(|&o: &u32| o < *end_byte);
            out.insert(idx, end_idx);
        }
    }
    out
}

fn synthesize_pre_311_exception_table(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
) -> Vec<crate::bytecode::flow::ExceptionTableEntry> {
    let bytes: &[u8] = &code.code;
    let wordcode: bool = version.supports_word_code();
    let mut entries: Vec<crate::bytecode::flow::ExceptionTableEntry> = Vec::new();
    let mut cursor: usize = 0;
    if wordcode {
        let mut extended: u64 = 0;
        while cursor + 1 < bytes.len() {
            let raw: u8 = bytes[cursor];
            let arg_byte: u8 = bytes[cursor + 1];
            if is_extended_arg(opmap, raw) {
                extended = accumulate_extended_arg(extended, arg_byte);
                cursor += WIDE_STEP;
                continue;
            }
            let arg: u32 = finalize_extended_arg(extended, arg_byte);
            extended = 0;
            let name: &str = opmap.opname(raw);
            if matches!(name, "SETUP_FINALLY" | "SETUP_EXCEPT") {
                let after: u32 = u32::try_from(cursor + WIDE_STEP).unwrap_or(u32::MAX);
                let delta_bytes: u32 = if version.major() == 3 && version.minor() >= 10 {
                    arg.saturating_mul(2)
                } else {
                    arg
                };
                let target: u32 = after.saturating_add(delta_bytes);
                let start: u32 = after;
                let length: u32 = target.saturating_sub(start);
                entries.push(crate::bytecode::flow::ExceptionTableEntry {
                    start,
                    length,
                    target,
                    depth: 0,
                    lasti: false,
                });
            }
            cursor += WIDE_STEP;
            let caches: usize = usize::from(opmap.cache_size(raw));
            if caches > 0 {
                cursor += caches * WIDE_STEP;
            }
        }
    } else {
        while cursor < bytes.len() {
            let raw: u8 = bytes[cursor];
            if raw < LEGACY_HAVE_ARGUMENT {
                cursor += NARROW_STEP;
                continue;
            }
            if cursor + 2 >= bytes.len() {
                break;
            }
            let arg: u32 = u32::from(bytes[cursor + 1]) | (u32::from(bytes[cursor + 2]) << 8);
            let name: &str = opmap.opname(raw);
            if matches!(name, "SETUP_FINALLY" | "SETUP_EXCEPT") {
                let after: u32 = u32::try_from(cursor + 3).unwrap_or(u32::MAX);
                let target: u32 = after.saturating_add(arg);
                entries.push(crate::bytecode::flow::ExceptionTableEntry {
                    start: after,
                    length: target.saturating_sub(after),
                    target,
                    depth: 0,
                    lasti: false,
                });
            }
            cursor += 3;
        }
    }
    entries
}

fn decode_wordcode_with_offsets(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
    ops: &mut Vec<CanonicalOp>,
    offsets: &mut Vec<u32>,
    next_offsets: &mut Vec<u32>,
    extended_arg_lead_ins: &mut Vec<u32>,
) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    let mut extended: u64 = 0;
    let mut extended_lead_in: Option<u32> = None;
    while cursor + 1 < bytes.len() {
        let raw: u8 = bytes[cursor];
        let arg_byte: u8 = bytes[cursor + 1];
        if is_extended_arg(opmap, raw) {
            if extended_lead_in.is_none() {
                extended_lead_in = Some(u32::try_from(cursor).unwrap_or(u32::MAX));
            }
            extended = accumulate_extended_arg(extended, arg_byte);
            cursor += WIDE_STEP;
            continue;
        }
        let arg: u32 = finalize_extended_arg(extended, arg_byte);
        extended = 0;
        if let Some(lead_in) = extended_lead_in.take() {
            extended_arg_lead_ins.push(lead_in);
        }
        let here: u32 = u32::try_from(cursor).unwrap_or(u32::MAX);
        let entry_start: usize = ops.len();
        if crate::bytecode::opcode::shared_pushes_self_slot(version, raw, arg) {
            offsets.push(here);
            ops.push(CanonicalOp::Push(0));
        }
        offsets.push(here);
        ops.push(opmap.decode(raw, arg));
        if crate::bytecode::opcode::shared_method_form_load_attr(version, raw, arg) {
            offsets.push(here);
            ops.push(CanonicalOp::Push(0));
        }
        cursor += WIDE_STEP;
        let caches: usize = usize::from(opmap.cache_size(raw));
        if caches > 0 {
            cursor += caches * WIDE_STEP;
        }
        let post: u32 = u32::try_from(cursor).unwrap_or(u32::MAX);
        for _ in entry_start..ops.len() {
            next_offsets.push(post);
        }
    }
}

fn decode_legacy_with_offsets(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    ops: &mut Vec<CanonicalOp>,
    offsets: &mut Vec<u32>,
    next_offsets: &mut Vec<u32>,
) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let raw: u8 = bytes[cursor];
        if raw < LEGACY_HAVE_ARGUMENT {
            offsets.push(u32::try_from(cursor).unwrap_or(u32::MAX));
            ops.push(opmap.decode(raw, 0));
            cursor += NARROW_STEP;
            next_offsets.push(u32::try_from(cursor).unwrap_or(u32::MAX));
            continue;
        }
        if cursor + 2 >= bytes.len() {
            break;
        }
        let arg: u32 = u32::from(bytes[cursor + 1]) | (u32::from(bytes[cursor + 2]) << 8);
        offsets.push(u32::try_from(cursor).unwrap_or(u32::MAX));
        ops.push(opmap.decode(raw, arg));
        cursor += 3;
        next_offsets.push(u32::try_from(cursor).unwrap_or(u32::MAX));
    }
}

const LEGACY_HAVE_ARGUMENT: u8 = 90;
const WIDE_STEP: usize = 2;
const NARROW_STEP: usize = 1;

#[inline]
fn is_extended_arg(opmap: &dyn OpcodeMap, raw: u8) -> bool {
    opmap.opname(raw) == "EXTENDED_ARG"
}

fn accumulate_extended_arg(extended: u64, arg_byte: u8) -> u64 {
    (extended | u64::from(arg_byte))
        .checked_shl(8)
        .unwrap_or(u64::MAX)
}

fn finalize_extended_arg(extended: u64, arg_byte: u8) -> u32 {
    u32::try_from(extended | u64::from(arg_byte)).unwrap_or(u32::MAX)
}

fn decode_wordcode(
    code: &CodeObject,
    opmap: &dyn OpcodeMap,
    version: &PyVersion,
    out: &mut Vec<CanonicalOp>,
) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    let mut extended: u64 = 0;
    while cursor + 1 < bytes.len() {
        let raw: u8 = bytes[cursor];
        let arg_byte: u8 = bytes[cursor + 1];
        if is_extended_arg(opmap, raw) {
            extended = accumulate_extended_arg(extended, arg_byte);
            cursor += WIDE_STEP;
            continue;
        }
        let arg: u32 = finalize_extended_arg(extended, arg_byte);
        extended = 0;
        if crate::bytecode::opcode::shared_pushes_self_slot(version, raw, arg) {
            out.push(CanonicalOp::Push(0));
        }
        out.push(opmap.decode(raw, arg));
        if crate::bytecode::opcode::shared_method_form_load_attr(version, raw, arg) {
            out.push(CanonicalOp::Push(0));
        }
        cursor += WIDE_STEP;
        let caches: usize = usize::from(opmap.cache_size(raw));
        if caches > 0 {
            cursor += caches * WIDE_STEP;
        }
    }
}

fn decode_legacy(code: &CodeObject, opmap: &dyn OpcodeMap, out: &mut Vec<CanonicalOp>) {
    let bytes: &[u8] = &code.code;
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let raw: u8 = bytes[cursor];
        if raw < LEGACY_HAVE_ARGUMENT {
            out.push(opmap.decode(raw, 0));
            cursor += NARROW_STEP;
            continue;
        }
        if cursor + 2 >= bytes.len() {
            break;
        }
        let arg: u32 = u32::from(bytes[cursor + 1]) | (u32::from(bytes[cursor + 2]) << 8);
        out.push(opmap.decode(raw, arg));
        cursor += 3;
    }
}

thread_local! {
    static ACTIVE_VERSION: std::cell::RefCell<Option<PyVersion>> =
        const { std::cell::RefCell::new(None) };
    static LOOP_FRAMES: std::cell::RefCell<Vec<LoopFrame>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static FUTURE_ANNOTATIONS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static BOOLOP_MERGES: std::cell::RefCell<Option<(BoolopSliceKey, Vec<usize>)>> =
        const { std::cell::RefCell::new(None) };
    static BOOLOP_SC: std::cell::RefCell<Option<(BoolopSliceKey, Vec<ScDesc>)>> =
        const { std::cell::RefCell::new(None) };
    static STRUCTURE_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static STRUCTURE_ACTIVE: std::cell::RefCell<Vec<(usize, usize)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static STRUCTURE_HI_CAP: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static THEN_ARM_END_CAP: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CODEOBJ_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn structure_hi_cap() -> usize {
    STRUCTURE_HI_CAP.with(|slot: &std::cell::Cell<usize>| slot.get())
}

fn then_arm_end_cap() -> usize {
    THEN_ARM_END_CAP.with(|slot: &std::cell::Cell<usize>| slot.get())
}

#[derive(Debug)]
struct ThenArmEndCapGuard {
    restore: usize,
}

impl ThenArmEndCapGuard {
    fn enter(cap: usize) -> Self {
        let restore: usize = THEN_ARM_END_CAP.with(|slot: &std::cell::Cell<usize>| {
            let prev: usize = slot.get();
            let next: usize = if prev == 0 { cap } else { prev.min(cap) };
            slot.set(next);
            prev
        });
        Self { restore }
    }
}

impl Drop for ThenArmEndCapGuard {
    fn drop(&mut self) {
        THEN_ARM_END_CAP.with(|slot: &std::cell::Cell<usize>| slot.set(self.restore));
    }
}

#[derive(Debug)]
struct StructureHiCapGuard {
    restore: usize,
}

impl StructureHiCapGuard {
    fn enter(cap: usize) -> Self {
        let restore: usize = STRUCTURE_HI_CAP.with(|slot: &std::cell::Cell<usize>| {
            let prev: usize = slot.get();
            let next: usize = if prev == 0 { cap } else { prev.min(cap) };
            slot.set(next);
            prev
        });
        Self { restore }
    }
}

impl Drop for StructureHiCapGuard {
    fn drop(&mut self) {
        STRUCTURE_HI_CAP.with(|slot: &std::cell::Cell<usize>| slot.set(self.restore));
    }
}

const STRUCTURE_DEPTH_LIMIT: usize = 600;

#[derive(Debug)]
struct StructureDepthGuard;

impl Drop for StructureDepthGuard {
    fn drop(&mut self) {
        STRUCTURE_DEPTH
            .with(|slot: &std::cell::Cell<usize>| slot.set(slot.get().saturating_sub(1)));
    }
}

fn enter_structure_depth() -> Result<StructureDepthGuard> {
    STRUCTURE_DEPTH.with(|slot: &std::cell::Cell<usize>| {
        let next: usize = slot.get() + 1;
        if next > STRUCTURE_DEPTH_LIMIT {
            return Err(DecompileError::StructuringDepthExceeded {
                limit: STRUCTURE_DEPTH_LIMIT,
            });
        }
        slot.set(next);
        Ok(StructureDepthGuard)
    })
}

const STRUCTURE_REENTRY_LIMIT: usize = 4;

#[derive(Debug)]
struct ActiveRegionGuard;

impl Drop for ActiveRegionGuard {
    fn drop(&mut self) {
        STRUCTURE_ACTIVE.with(|s: &std::cell::RefCell<Vec<(usize, usize)>>| {
            s.borrow_mut().pop();
        });
    }
}

fn enter_active_region(lo: usize, hi: usize) -> Option<ActiveRegionGuard> {
    STRUCTURE_ACTIVE.with(|s: &std::cell::RefCell<Vec<(usize, usize)>>| {
        let mut active: std::cell::RefMut<Vec<(usize, usize)>> = s.borrow_mut();
        let seen: usize = active
            .iter()
            .filter(|&&r: &&(usize, usize)| r == (lo, hi))
            .count();
        if seen >= STRUCTURE_REENTRY_LIMIT {
            return None;
        }
        active.push((lo, hi));
        Some(ActiveRegionGuard)
    })
}

const CODEOBJ_DEPTH_LIMIT: usize = 200;

#[derive(Debug)]
pub(super) struct CodeObjDepthGuard;

impl Drop for CodeObjDepthGuard {
    fn drop(&mut self) {
        CODEOBJ_DEPTH.with(|slot: &std::cell::Cell<usize>| slot.set(slot.get().saturating_sub(1)));
    }
}

pub(super) fn enter_codeobj_depth() -> Result<CodeObjDepthGuard> {
    CODEOBJ_DEPTH.with(|slot: &std::cell::Cell<usize>| {
        let next: usize = slot.get().saturating_add(1);
        if next > CODEOBJ_DEPTH_LIMIT {
            return Err(DecompileError::StructuringDepthExceeded {
                limit: CODEOBJ_DEPTH_LIMIT,
            });
        }
        slot.set(next);
        Ok(CodeObjDepthGuard)
    })
}

#[derive(Debug)]
struct NestedCodeScope {
    depth: usize,
    hi_cap: usize,
    frames: Vec<LoopFrame>,
    active: Vec<(usize, usize)>,
}

impl NestedCodeScope {
    fn enter() -> Self {
        let depth: usize = STRUCTURE_DEPTH.with(|slot: &std::cell::Cell<usize>| slot.replace(0));
        let hi_cap: usize = STRUCTURE_HI_CAP.with(|slot: &std::cell::Cell<usize>| slot.replace(0));
        let frames: Vec<LoopFrame> =
            LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| {
                std::mem::take(&mut *slot.borrow_mut())
            });
        let active: Vec<(usize, usize)> =
            STRUCTURE_ACTIVE.with(|slot: &std::cell::RefCell<Vec<(usize, usize)>>| {
                std::mem::take(&mut *slot.borrow_mut())
            });
        Self {
            depth,
            hi_cap,
            frames,
            active,
        }
    }
}

impl Drop for NestedCodeScope {
    fn drop(&mut self) {
        STRUCTURE_DEPTH.with(|slot: &std::cell::Cell<usize>| slot.set(self.depth));
        STRUCTURE_HI_CAP.with(|slot: &std::cell::Cell<usize>| slot.set(self.hi_cap));
        LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| {
            *slot.borrow_mut() = std::mem::take(&mut self.frames);
        });
        STRUCTURE_ACTIVE.with(|slot: &std::cell::RefCell<Vec<(usize, usize)>>| {
            *slot.borrow_mut() = std::mem::take(&mut self.active);
        });
    }
}

type BoolopSliceKey = (*const CanonicalOp, usize);

#[inline]
fn boolop_slice_key(ops: &[CanonicalOp]) -> BoolopSliceKey {
    (ops.as_ptr(), ops.len())
}

fn with_boolop_merges<T>(ops: &[CanonicalOp], merges: Vec<usize>, f: impl FnOnce() -> T) -> T {
    with_boolop_context(ops, merges, Vec::new(), f)
}

fn boolop_merge_after(ops: &[CanonicalOp], idx: usize) -> usize {
    let key: BoolopSliceKey = boolop_slice_key(ops);
    BOOLOP_MERGES.with(
        |slot: &std::cell::RefCell<Option<(BoolopSliceKey, Vec<usize>)>>| {
            let guard: std::cell::Ref<'_, Option<(BoolopSliceKey, Vec<usize>)>> = slot.borrow();
            let Some((stored_key, merges)): &Option<(BoolopSliceKey, Vec<usize>)> = &guard else {
                return 0;
            };
            if *stored_key != key {
                return 0;
            }
            merges
                .iter()
                .copied()
                .find(|&m: &usize| m > idx)
                .unwrap_or(0)
        },
    )
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ScDesc {
    pub(super) sc_idx: usize,
    pub(super) target: usize,
    pub(super) kind: crate::ast::node::BoolOpKind,
}

pub(super) fn with_boolop_context<T>(
    ops: &[CanonicalOp],
    merges: Vec<usize>,
    descriptors: Vec<ScDesc>,
    f: impl FnOnce() -> T,
) -> T {
    let key: BoolopSliceKey = boolop_slice_key(ops);
    let prev_merges: Option<(BoolopSliceKey, Vec<usize>)> = BOOLOP_MERGES.with(
        |slot: &std::cell::RefCell<Option<(BoolopSliceKey, Vec<usize>)>>| {
            slot.borrow_mut().replace((key, merges))
        },
    );
    let prev_sc: Option<(BoolopSliceKey, Vec<ScDesc>)> = BOOLOP_SC.with(
        |slot: &std::cell::RefCell<Option<(BoolopSliceKey, Vec<ScDesc>)>>| {
            slot.borrow_mut().replace((key, descriptors))
        },
    );
    let result: T = f();
    BOOLOP_MERGES.with(
        |slot: &std::cell::RefCell<Option<(BoolopSliceKey, Vec<usize>)>>| {
            *slot.borrow_mut() = prev_merges;
        },
    );
    BOOLOP_SC.with(
        |slot: &std::cell::RefCell<Option<(BoolopSliceKey, Vec<ScDesc>)>>| {
            *slot.borrow_mut() = prev_sc;
        },
    );
    result
}

pub(super) fn boolop_sc_descriptors(ops: &[CanonicalOp]) -> Option<Vec<ScDesc>> {
    let key: BoolopSliceKey = boolop_slice_key(ops);
    BOOLOP_SC.with(
        |slot: &std::cell::RefCell<Option<(BoolopSliceKey, Vec<ScDesc>)>>| {
            let guard: std::cell::Ref<'_, Option<(BoolopSliceKey, Vec<ScDesc>)>> = slot.borrow();
            let (stored_key, descriptors): &(BoolopSliceKey, Vec<ScDesc>) = guard.as_ref()?;
            if *stored_key != key {
                return None;
            }
            Some(descriptors.clone())
        },
    )
}

const CO_FUTURE_ANNOTATIONS: i32 = 0x0100_0000;

fn set_future_annotations(flags: i32) {
    FUTURE_ANNOTATIONS.with(|slot: &std::cell::Cell<bool>| {
        slot.set(flags & CO_FUTURE_ANNOTATIONS != 0);
    });
}

fn future_annotations_active() -> bool {
    FUTURE_ANNOTATIONS.with(std::cell::Cell::get)
}

#[derive(Debug, Clone)]
struct LoopFrame {
    header: usize,
    exit: usize,

    exit_return: Option<Expr>,
    exit_tail_range: Option<(usize, usize)>,
}

fn push_loop_frame(frame: LoopFrame) {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| slot.borrow_mut().push(frame));
}

fn pop_loop_frame() {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| {
        let _ = slot.borrow_mut().pop();
    });
}

fn loop_break_target() -> Option<usize> {
    LOOP_FRAMES
        .with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| slot.borrow().last().map(|f| f.exit))
}

pub(super) fn loop_continue_target() -> Option<usize> {
    LOOP_FRAMES
        .with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| slot.borrow().last().map(|f| f.header))
}

fn loop_frame_has_header(header: usize) -> bool {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| {
        slot.borrow().iter().any(|f: &LoopFrame| f.header == header)
    })
}

fn loop_exit_return() -> Option<Expr> {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| {
        slot.borrow()
            .last()
            .and_then(|f: &LoopFrame| f.exit_return.clone())
    })
}

fn loop_exit_tail_range() -> Option<(usize, usize)> {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| {
        slot.borrow()
            .last()
            .and_then(|f: &LoopFrame| f.exit_tail_range)
    })
}

fn loop_frame_depth() -> usize {
    LOOP_FRAMES.with(|slot: &std::cell::RefCell<Vec<LoopFrame>>| slot.borrow().len())
}

fn set_active_version(version: &PyVersion) {
    ACTIVE_VERSION.with(|slot: &std::cell::RefCell<Option<PyVersion>>| {
        *slot.borrow_mut() = Some(version.clone());
    });
}

fn active_version() -> Option<PyVersion> {
    ACTIVE_VERSION.with(|slot: &std::cell::RefCell<Option<PyVersion>>| slot.borrow().clone())
}

fn pick_nested_version(code: &CodeObject) -> PyVersion {
    use disrobe_py_marshal::CodeEra;
    if let Some(active) = active_version() {
        let matches_era: bool = match code.era {
            CodeEra::Py10to12 => active.major() == 1 && active.minor() <= 2,
            CodeEra::Py13to14 => active.major() == 1 && (3..=4).contains(&active.minor()),
            CodeEra::Py15to20 => {
                (active.major() == 1 && active.minor() >= 5)
                    || (active.major() == 2 && active.minor() == 0)
            }
            CodeEra::Py21to22 => active.major() == 2 && (1..=2).contains(&active.minor()),
            CodeEra::Py27 => active.major() == 2 && active.minor() >= 3,
            CodeEra::Py30to37 => active.major() == 3 && active.minor() <= 7,
            CodeEra::Py38to310 => {
                active.major() == 3 && active.minor() >= 8 && active.minor() <= 10
            }
            CodeEra::Py311Plus => active.major() > 3 || active.minor() >= 11,
        };
        if matches_era {
            return active;
        }
    }
    match code.era {
        CodeEra::Py10to12 => PyVersion::V1_1,
        CodeEra::Py13to14 => PyVersion::V1_4,
        CodeEra::Py15to20 => PyVersion::V1_5,
        CodeEra::Py21to22 => PyVersion::V2_1,
        CodeEra::Py27 => PyVersion::V2_7,
        CodeEra::Py30to37 => PyVersion::V3_7,
        CodeEra::Py38to310 => PyVersion::V3_10,
        CodeEra::Py311Plus => PyVersion::V3_14,
    }
}
