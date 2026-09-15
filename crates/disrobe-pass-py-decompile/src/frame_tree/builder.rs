use std::ops::Range;

use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::bytecode::flow::{
    ExceptionTableEntry, LineTableEntry, line_for_offset, parse_exception_table, parse_line_table,
};
use crate::error::{DecompileError, Result};
use crate::frame_tree::{Frame, FrameId, FrameKind, FrameTree, FrameTreeBuilder, HandlerRange};

#[derive(Debug, Clone, Copy)]
struct BlockOps {
    setup_loop: Option<u8>,
    setup_except: Option<u8>,
    setup_finally: Option<u8>,
    setup_with: Option<u8>,
    setup_async_with: Option<u8>,
    pop_block: Option<u8>,
    for_iter: Option<u8>,
}

impl BlockOps {
    const fn for_version(version: PyVersion) -> Self {
        match (version.major, version.minor) {
            (2, _) | (3, 0..=7) => Self {
                setup_loop: Some(120),
                setup_except: Some(121),
                setup_finally: Some(122),
                setup_with: Some(143),
                setup_async_with: if version.major == 3 && version.minor >= 5 {
                    Some(154)
                } else {
                    None
                },
                pop_block: Some(87),
                for_iter: Some(93),
            },
            (3, 8..=10) => Self {
                setup_loop: None,
                setup_except: None,
                setup_finally: Some(122),
                setup_with: Some(143),
                setup_async_with: Some(154),
                pop_block: Some(87),
                for_iter: Some(93),
            },
            _ => Self {
                setup_loop: None,
                setup_except: None,
                setup_finally: None,
                setup_with: None,
                setup_async_with: None,
                pop_block: None,
                for_iter: Some(93),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct Post311Ops {
    push_exc_info: u8,
    before_with: Option<u8>,
    before_async_with: Option<u8>,
    with_except_start: u8,
    get_iter: u8,
    get_aiter: u8,
    get_anext: u8,
    for_iter: u8,
    jump_backward: u8,
    end_async_for: u8,
    match_class: u8,
    match_mapping: u8,
    match_sequence: u8,
    match_keys: u8,
    copy: u8,
    swap: u8,
}

impl Post311Ops {
    const fn for_version(version: PyVersion) -> Self {
        match (version.major, version.minor) {
            (3, 15) => Self {
                push_exc_info: 30,
                before_with: None,
                before_async_with: None,
                with_except_start: 41,
                get_iter: 70,
                get_aiter: 14,
                get_anext: 15,
                for_iter: 68,
                jump_backward: 74,
                end_async_for: 66,
                match_class: 98,
                match_mapping: 23,
                match_sequence: 24,
                match_keys: 22,
                copy: 57,
                swap: 116,
            },
            (3, 14) => Self {
                push_exc_info: 32,
                before_with: None,
                before_async_with: None,
                with_except_start: 43,
                get_iter: 16,
                get_aiter: 14,
                get_anext: 15,
                for_iter: 70,
                jump_backward: 75,
                end_async_for: 68,
                match_class: 99,
                match_mapping: 25,
                match_sequence: 26,
                match_keys: 24,
                copy: 59,
                swap: 117,
            },
            (3, 13) => Self {
                push_exc_info: 33,
                before_with: Some(2),
                before_async_with: Some(1),
                with_except_start: 44,
                get_iter: 19,
                get_aiter: 16,
                get_anext: 18,
                for_iter: 72,
                jump_backward: 77,
                end_async_for: 10,
                match_class: 96,
                match_mapping: 28,
                match_sequence: 29,
                match_keys: 27,
                copy: 61,
                swap: 115,
            },
            _ => Self {
                push_exc_info: 35,
                before_with: Some(53),
                before_async_with: Some(52),
                with_except_start: 49,
                get_iter: 68,
                get_aiter: 50,
                get_anext: 51,
                for_iter: 93,
                jump_backward: 140,
                end_async_for: 54,
                match_class: 152,
                match_mapping: 31,
                match_sequence: 32,
                match_keys: 33,
                copy: 120,
                swap: 99,
            },
        }
    }
}

#[derive(Debug, Default)]
pub struct Pre311Builder;

impl Pre311Builder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FrameTreeBuilder for Pre311Builder {
    fn build(&self, code: &CodeObject, version: PyVersion) -> Result<FrameTree> {
        let mut ctx: BuildCtx<'_> = BuildCtx::new(code, version)?;
        let module_root: Frame = walk_block_ops(&mut ctx)?;
        Ok(FrameTree::new(module_root))
    }
}

#[derive(Debug, Default)]
pub struct Post311Builder;

impl Post311Builder {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FrameTreeBuilder for Post311Builder {
    fn build(&self, code: &CodeObject, version: PyVersion) -> Result<FrameTree> {
        let mut ctx: BuildCtx<'_> = BuildCtx::new(code, version)?;
        let module_root: Frame = build_from_exception_table(&mut ctx)?;
        Ok(FrameTree::new(module_root))
    }
}

#[derive(Debug)]
struct BuildCtx<'a> {
    code: &'a [u8],
    version: PyVersion,
    line_table: Vec<LineTableEntry>,
    exception_table: Vec<ExceptionTableEntry>,
    next_id: u32,
}

impl<'a> BuildCtx<'a> {
    fn new(code: &'a CodeObject, version: PyVersion) -> Result<Self> {
        let line_table: Vec<LineTableEntry> = if version.major >= 3 && version.minor >= 10 {
            parse_line_table(&code.linetable, version).unwrap_or_default()
        } else {
            parse_line_table(&code.lnotab, version).unwrap_or_default()
        };
        let exception_table: Vec<ExceptionTableEntry> =
            if version.major > 3 || (version.major == 3 && version.minor >= 11) {
                parse_exception_table(&code.exceptiontable)?
            } else {
                Vec::new()
            };
        Ok(Self {
            code: &code.code,
            version,
            line_table,
            exception_table,
            next_id: 0,
        })
    }

    fn alloc_id(&mut self) -> FrameId {
        let id: FrameId = FrameId(self.next_id);
        self.next_id += 1;
        id
    }

    fn line_at(&self, offset: u32) -> Option<u32> {
        line_for_offset(&self.line_table, offset)
    }
}

fn code_len_u32(code: &[u8]) -> Result<u32> {
    u32::try_from(code.len()).map_err(|_| DecompileError::AstDesync {
        offset: 0,
        reason: "code length exceeds u32".to_owned(),
    })
}

fn walk_block_ops(ctx: &mut BuildCtx<'_>) -> Result<Frame> {
    let module_id: FrameId = ctx.alloc_id();
    let code_len: u32 = code_len_u32(ctx.code)?;
    let mut root: Frame = Frame::new(module_id, FrameKind::Module, 0..code_len);
    root.line = ctx.line_at(0);

    let ops: BlockOps = BlockOps::for_version(ctx.version);
    let wordcode: bool = ctx.version.is_wordcode();

    let mut stack: Vec<OpenBlock> = Vec::new();
    let mut closed: Vec<Frame> = Vec::new();
    let mut cursor: InstrCursor<'_> = InstrCursor::new(ctx.code, wordcode);

    while let Some(instr) = cursor.next()? {
        if let Some(op) = ops.setup_loop
            && instr.opcode == op
        {
            push_block(ctx, &mut stack, instr, FrameKind::WhileLoop)?;
            continue;
        }
        if let Some(op) = ops.setup_except
            && instr.opcode == op
        {
            push_block(ctx, &mut stack, instr, FrameKind::Try)?;
            continue;
        }
        if let Some(op) = ops.setup_finally
            && instr.opcode == op
        {
            push_block(ctx, &mut stack, instr, FrameKind::Try)?;
            continue;
        }
        if let Some(op) = ops.setup_with
            && instr.opcode == op
        {
            push_block(ctx, &mut stack, instr, FrameKind::With)?;
            continue;
        }
        if let Some(op) = ops.setup_async_with
            && instr.opcode == op
        {
            push_block(ctx, &mut stack, instr, FrameKind::AsyncWith)?;
            continue;
        }
        if let Some(op) = ops.pop_block
            && instr.opcode == op
        {
            close_top(&mut stack, &mut closed, instr.next_offset)?;
            continue;
        }
        if let Some(op) = ops.for_iter
            && instr.opcode == op
        {
            push_block(ctx, &mut stack, instr, FrameKind::ForLoop)?;
        }
    }

    while let Some(open) = stack.pop() {
        closed.push(finalize_open(open, code_len));
    }

    root.children = nest_frames(closed);
    root.child_ranges = root
        .children
        .iter()
        .map(|f: &Frame| f.range.clone())
        .collect();
    Ok(root)
}

#[derive(Debug)]
struct OpenBlock {
    id: FrameId,
    kind: FrameKind,
    start: u32,
    line: Option<u32>,
}

fn push_block(
    ctx: &mut BuildCtx<'_>,
    stack: &mut Vec<OpenBlock>,
    instr: Instr,
    kind: FrameKind,
) -> Result<()> {
    let id: FrameId = ctx.alloc_id();
    stack.push(OpenBlock {
        id,
        kind,
        start: instr.offset,
        line: ctx.line_at(instr.offset),
    });
    Ok(())
}

fn close_top(stack: &mut Vec<OpenBlock>, closed: &mut Vec<Frame>, end: u32) -> Result<()> {
    let Some(open): Option<OpenBlock> = stack.pop() else {
        return Err(DecompileError::FrameTreeInvariant {
            reason: "POP_BLOCK with empty stack".to_owned(),
        });
    };
    closed.push(finalize_open(open, end));
    Ok(())
}

fn finalize_open(open: OpenBlock, end: u32) -> Frame {
    let mut frame: Frame = Frame::new(open.id, open.kind, open.start..end);
    frame.line = open.line;
    frame
}

fn nest_frames(mut frames: Vec<Frame>) -> Vec<Frame> {
    frames.sort_by(|a: &Frame, b: &Frame| {
        a.range
            .start
            .cmp(&b.range.start)
            .then_with(|| b.range.end.cmp(&a.range.end))
    });
    let mut roots: Vec<Frame> = Vec::new();
    for frame in frames {
        attach_into(&mut roots, frame, 0);
    }
    roots
}

const MAX_FRAME_NEST_DEPTH: usize = 256;

fn attach_into(siblings: &mut Vec<Frame>, frame: Frame, depth: usize) {
    if depth < MAX_FRAME_NEST_DEPTH {
        for existing in siblings.iter_mut() {
            if existing.range.start <= frame.range.start && existing.range.end >= frame.range.end {
                attach_into(&mut existing.children, frame, depth + 1);
                existing.child_ranges = existing
                    .children
                    .iter()
                    .map(|f: &Frame| f.range.clone())
                    .collect();
                return;
            }
        }
    }
    siblings.push(frame);
}

fn build_from_exception_table(ctx: &mut BuildCtx<'_>) -> Result<Frame> {
    let code_len: u32 = code_len_u32(ctx.code)?;
    let module_id: FrameId = ctx.alloc_id();
    let mut root: Frame = Frame::new(module_id, FrameKind::Module, 0..code_len);
    root.line = ctx.line_at(0);

    let mut try_frames: Vec<Frame> = Vec::new();
    let entries: Vec<ExceptionTableEntry> = sort_entries(&ctx.exception_table);

    let ops: Post311Ops = Post311Ops::for_version(ctx.version);

    for entry in &entries {
        let id: FrameId = ctx.alloc_id();
        let body: Range<u32> = entry.start..entry.start + entry.length;
        let handler_kind: FrameKind = classify_handler(ctx.code, entry.target, ops);
        let kind: FrameKind = match handler_kind {
            FrameKind::With => FrameKind::With,
            FrameKind::AsyncWith => FrameKind::AsyncWith,
            _ => FrameKind::Try,
        };
        let mut frame: Frame = Frame::new(id, kind, body.clone());
        frame.body_range = body;
        frame.line = ctx.line_at(entry.start);
        let handler_end: u32 = handler_end_estimate(ctx.code, entry.target, &entries);
        frame.handlers.push(HandlerRange {
            range: entry.target..handler_end,
            exception_target: entry.target,
            depth: entry.depth,
        });
        frame.range = entry.start..handler_end;
        try_frames.push(frame);
    }

    let loop_frames: Vec<Frame> = detect_loops(ctx, ops);
    let mut all_frames: Vec<Frame> = try_frames;
    all_frames.extend(loop_frames);

    root.children = nest_frames(all_frames);
    root.child_ranges = root
        .children
        .iter()
        .map(|f: &Frame| f.range.clone())
        .collect();
    Ok(root)
}

fn sort_entries(entries: &[ExceptionTableEntry]) -> Vec<ExceptionTableEntry> {
    let mut sorted: Vec<ExceptionTableEntry> = entries.to_vec();
    sorted.sort_by(|a: &ExceptionTableEntry, b: &ExceptionTableEntry| {
        a.start.cmp(&b.start).then_with(|| b.end().cmp(&a.end()))
    });
    sorted
}

fn classify_handler(code: &[u8], target: u32, ops: Post311Ops) -> FrameKind {
    let target_usize: usize = target as usize;
    let window_end: usize = (target_usize + 16).min(code.len());
    if target_usize >= code.len() {
        return FrameKind::Try;
    }
    let window: &[u8] = &code[target_usize..window_end];
    let mut i: usize = 0;
    while i + 1 < window.len() {
        let op: u8 = window[i];
        if op == ops.with_except_start {
            return FrameKind::With;
        }
        if op == ops.push_exc_info {
            return FrameKind::Try;
        }
        i += 2;
    }
    FrameKind::Try
}

fn handler_end_estimate(code: &[u8], target: u32, entries: &[ExceptionTableEntry]) -> u32 {
    let code_len: u32 = u32::try_from(code.len()).unwrap_or(u32::MAX);
    let mut end: u32 = code_len;
    for entry in entries {
        if entry.start > target && entry.start < end {
            end = entry.start;
        }
    }
    end
}

fn detect_loops(ctx: &mut BuildCtx<'_>, ops: Post311Ops) -> Vec<Frame> {
    let wordcode: bool = ctx.version.is_wordcode();
    let mut cursor: InstrCursor<'_> = InstrCursor::new(ctx.code, wordcode);
    let mut for_iter_offsets: Vec<u32> = Vec::new();
    let mut backward_jumps: Vec<(u32, u32)> = Vec::new();

    let mut get_anext_offsets: Vec<u32> = Vec::new();
    while let Ok(Some(instr)) = cursor.next() {
        if instr.opcode == ops.for_iter {
            for_iter_offsets.push(instr.offset);
        }
        if instr.opcode == ops.get_anext {
            get_anext_offsets.push(instr.offset);
        }
        if instr.opcode == ops.jump_backward {
            let displacement: u32 = u32::from(instr.arg);
            let unit: u32 = if wordcode { 2 } else { 1 };
            let raw_target: u32 = instr
                .next_offset
                .saturating_sub(displacement.saturating_mul(unit));
            backward_jumps.push((instr.offset, raw_target));
        }
    }

    let mut loops: Vec<Frame> = Vec::new();
    for (jump_from, jump_to) in &backward_jumps {
        let is_async_for: bool = get_anext_offsets.contains(jump_to);
        let is_for: bool = for_iter_offsets.contains(jump_to);
        let id: FrameId = ctx.alloc_id();
        let kind: FrameKind = if is_async_for {
            FrameKind::AsyncForLoop
        } else if is_for {
            FrameKind::ForLoop
        } else {
            FrameKind::WhileLoop
        };
        let mut frame: Frame = Frame::new(id, kind, *jump_to..*jump_from + 2);
        frame.line = ctx.line_at(*jump_to);
        loops.push(frame);
    }
    loops
}

#[derive(Debug, Clone, Copy)]
struct Instr {
    offset: u32,
    next_offset: u32,
    opcode: u8,
    arg: u8,
}

#[derive(Debug)]
struct InstrCursor<'a> {
    code: &'a [u8],
    pos: usize,
    wordcode: bool,
}

impl<'a> InstrCursor<'a> {
    const fn new(code: &'a [u8], wordcode: bool) -> Self {
        Self {
            code,
            pos: 0,
            wordcode,
        }
    }

    fn next(&mut self) -> Result<Option<Instr>> {
        if self.pos >= self.code.len() {
            return Ok(None);
        }
        let offset: u32 = u32::try_from(self.pos).map_err(|_| DecompileError::AstDesync {
            offset: self.pos,
            reason: "offset exceeds u32".to_owned(),
        })?;
        let opcode: u8 = self.code[self.pos];
        let (arg, advance): (u8, usize) = if self.wordcode {
            if self.pos + 1 >= self.code.len() {
                return Ok(None);
            }
            (self.code[self.pos + 1], 2)
        } else if opcode >= 90 {
            if self.pos + 2 >= self.code.len() {
                return Ok(None);
            }
            (self.code[self.pos + 1], 3)
        } else {
            (0, 1)
        };
        self.pos += advance;
        let advance_u32: u32 = u32::try_from(advance).unwrap_or(u32::MAX);
        let next_offset: u32 = offset + advance_u32;
        Ok(Some(Instr {
            offset,
            next_offset,
            opcode,
            arg,
        }))
    }
}
