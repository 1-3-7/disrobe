use std::fmt::Arguments;

use serde::{Deserialize, Serialize};

use super::RegExpTableEntry;
use crate::debug::{dbg_line, dbg_section};

const FLAG_ICASE: u8 = 1 << 0;
const FLAG_GLOBAL: u8 = 1 << 1;
const FLAG_MULTILINE: u8 = 1 << 2;
const FLAG_UNICODE: u8 = 1 << 3;
const FLAG_DOTALL: u8 = 1 << 4;
const FLAG_STICKY: u8 = 1 << 5;
const FLAG_INDICES: u8 = 1 << 6;

const CLASS_DIGITS: u8 = 1 << 0;
const CLASS_SPACES: u8 = 1 << 1;
const CLASS_WORDS: u8 = 1 << 2;

const REGEX_HEADER_SIZE: usize = 6;

const BRACKET_RANGE_SIZE: usize = 8;

const LOOP_UNBOUNDED: u32 = u32::MAX;

const MAX_REGEX_INSNS: usize = 1 << 16;

macro_rules! push_text {
    ($output:expr, $($arg:tt)*) => {
        push_format(&mut $output, format_args!($($arg)*))
    };
}

fn push_format(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => {}
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RegexOpcode {
    Goal = 0,
    LeftAnchor = 1,
    RightAnchor = 2,
    MatchAny = 3,
    U16MatchAny = 4,
    MatchAnyButNewline = 5,
    U16MatchAnyButNewline = 6,
    MatchChar8 = 7,
    MatchChar16 = 8,
    U16MatchChar32 = 9,
    MatchNChar8 = 10,
    MatchNCharICase8 = 11,
    MatchCharICase8 = 12,
    MatchCharICase16 = 13,
    U16MatchCharICase32 = 14,
    Alternation = 15,
    Jump32 = 16,
    Bracket = 17,
    U16Bracket = 18,
    BeginMarkedSubexpression = 19,
    EndMarkedSubexpression = 20,
    BackRef = 21,
    WordBoundary = 22,
    Lookaround = 23,
    BeginLoop = 24,
    EndLoop = 25,
    BeginSimpleLoop = 26,
    EndSimpleLoop = 27,
    Width1Loop = 28,
}

impl RegexOpcode {
    #[must_use]
    const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Goal,
            1 => Self::LeftAnchor,
            2 => Self::RightAnchor,
            3 => Self::MatchAny,
            4 => Self::U16MatchAny,
            5 => Self::MatchAnyButNewline,
            6 => Self::U16MatchAnyButNewline,
            7 => Self::MatchChar8,
            8 => Self::MatchChar16,
            9 => Self::U16MatchChar32,
            10 => Self::MatchNChar8,
            11 => Self::MatchNCharICase8,
            12 => Self::MatchCharICase8,
            13 => Self::MatchCharICase16,
            14 => Self::U16MatchCharICase32,
            15 => Self::Alternation,
            16 => Self::Jump32,
            17 => Self::Bracket,
            18 => Self::U16Bracket,
            19 => Self::BeginMarkedSubexpression,
            20 => Self::EndMarkedSubexpression,
            21 => Self::BackRef,
            22 => Self::WordBoundary,
            23 => Self::Lookaround,
            24 => Self::BeginLoop,
            25 => Self::EndLoop,
            26 => Self::BeginSimpleLoop,
            27 => Self::EndSimpleLoop,
            28 => Self::Width1Loop,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Insn {
    Goal,
    LeftAnchor,
    RightAnchor,
    MatchAny,
    MatchAnyButNewline,
    MatchChar { code: u32, icase: bool },
    MatchNChar { chars: Vec<u32>, icase: bool },
    Alternation { secondary: usize },
    Jump32 { target: usize },
    Bracket(Bracket),
    BeginMarkedSubexpression { mexp: u16 },
    EndMarkedSubexpression { mexp: u16 },
    BackRef { mexp: u16 },
    WordBoundary { invert: bool },
    Lookaround(Lookaround),
    BeginLoop(Loop),
    EndLoop { target: usize },
    BeginSimpleLoop { not_taken: usize },
    EndSimpleLoop { target: usize },
    Width1Loop(Loop),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Bracket {
    negate: bool,
    positive_classes: u8,
    negative_classes: u8,
    ranges: Vec<(u32, u32)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lookaround {
    invert: bool,
    forwards: bool,
    continuation: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Loop {
    min: u32,
    max: u32,
    greedy: bool,
    not_taken: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedInsn {
    offset: usize,
    size: usize,
    insn: Insn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredRegExp {
    pub index: usize,
    pub flags: String,
    pub marked_count: u16,
    pub loop_count: u16,
    pub pattern: String,
    pub fully_modeled: bool,
}

impl RecoveredRegExp {
    #[must_use]
    pub fn to_js_literal(&self) -> String {
        format!("/{}/{}", self.pattern, self.flags)
    }
}

#[must_use]
pub fn flags_to_string(byte: u8) -> String {
    let mut out: String = String::with_capacity(7);
    if byte & FLAG_INDICES != 0 {
        out.push('d');
    }
    if byte & FLAG_GLOBAL != 0 {
        out.push('g');
    }
    if byte & FLAG_ICASE != 0 {
        out.push('i');
    }
    if byte & FLAG_MULTILINE != 0 {
        out.push('m');
    }
    if byte & FLAG_DOTALL != 0 {
        out.push('s');
    }
    if byte & FLAG_UNICODE != 0 {
        out.push('u');
    }
    if byte & FLAG_STICKY != 0 {
        out.push('y');
    }
    out
}

#[must_use]
pub fn recover_regexp(
    table: &[RegExpTableEntry],
    storage: &[u8],
    index: usize,
) -> Option<RecoveredRegExp> {
    let entry: &RegExpTableEntry = table.get(index)?;
    let slice: &[u8] = regexp_entry_slice(*entry, storage)?;
    Some(recover_one(index, slice))
}

#[must_use]
pub fn recover_regexps(table: &[RegExpTableEntry], storage: &[u8]) -> Vec<RecoveredRegExp> {
    dbg_section("hermes.regex");
    let mut out: Vec<RecoveredRegExp> = Vec::with_capacity(table.len());
    for (index, entry) in table.iter().enumerate() {
        let Some(slice): Option<&[u8]> = regexp_entry_slice(*entry, storage) else {
            dbg_line(|| {
                format!(
                    "re[{index}] wall: bytecode out of storage bounds (offset={} len={})",
                    entry.offset, entry.length
                )
            });
            out.push(RecoveredRegExp {
                index,
                flags: String::new(),
                marked_count: 0,
                loop_count: 0,
                pattern: String::new(),
                fully_modeled: false,
            });
            continue;
        };
        let recovered: RecoveredRegExp = recover_one(index, slice);
        dbg_line(|| {
            format!(
                "re[{index}] /{}/{} marked={} loops={} modeled={}",
                recovered.pattern,
                recovered.flags,
                recovered.marked_count,
                recovered.loop_count,
                recovered.fully_modeled
            )
        });
        out.push(recovered);
    }
    out
}

fn regexp_entry_slice(entry: RegExpTableEntry, storage: &[u8]) -> Option<&[u8]> {
    let start: usize = usize::try_from(entry.offset).ok()?;
    let length: usize = usize::try_from(entry.length).ok()?;
    if length < REGEX_HEADER_SIZE {
        return None;
    }
    let end: usize = start.checked_add(length)?;
    storage.get(start..end)
}

#[must_use]
fn recover_one(index: usize, slice: &[u8]) -> RecoveredRegExp {
    let marked_count: u16 = u16::from_le_bytes([slice[0], slice[1]]);
    let loop_count: u16 = u16::from_le_bytes([slice[2], slice[3]]);
    let syntax_flags: u8 = slice[4];
    let flags: String = flags_to_string(syntax_flags);
    let body: &[u8] = &slice[REGEX_HEADER_SIZE..];
    let (insns, decode_clean): (Vec<DecodedInsn>, bool) = decode_body(body);
    let mut builder: PatternBuilder<'_> = PatternBuilder::new(&insns);
    let pattern: String = builder.render_range(0, body.len());
    RecoveredRegExp {
        index,
        flags,
        marked_count,
        loop_count,
        pattern,
        fully_modeled: decode_clean && builder.fully_modeled,
    }
}

#[must_use]
fn decode_body(body: &[u8]) -> (Vec<DecodedInsn>, bool) {
    let mut out: Vec<DecodedInsn> = Vec::new();
    let mut pc: usize = 0;
    let mut clean: bool = true;
    while pc < body.len() && out.len() < MAX_REGEX_INSNS {
        let Some(op): Option<RegexOpcode> = RegexOpcode::from_byte(body[pc]) else {
            clean = false;
            break;
        };
        let Some((insn, size)): Option<(Insn, usize)> = decode_one(op, body, pc) else {
            clean = false;
            break;
        };
        out.push(DecodedInsn {
            offset: pc,
            size,
            insn,
        });
        if size == 0 {
            clean = false;
            break;
        }
        pc += size;
    }
    (out, clean)
}

#[must_use]
fn decode_one(op: RegexOpcode, body: &[u8], pc: usize) -> Option<(Insn, usize)> {
    let after: &[u8] = body.get(pc + 1..)?;
    Some(match op {
        RegexOpcode::Goal => (Insn::Goal, 1),
        RegexOpcode::LeftAnchor => (Insn::LeftAnchor, 1),
        RegexOpcode::RightAnchor => (Insn::RightAnchor, 1),
        RegexOpcode::MatchAny | RegexOpcode::U16MatchAny => (Insn::MatchAny, 1),
        RegexOpcode::MatchAnyButNewline | RegexOpcode::U16MatchAnyButNewline => {
            (Insn::MatchAnyButNewline, 1)
        }
        RegexOpcode::MatchChar8 => (
            Insn::MatchChar {
                code: *after.first()? as u32,
                icase: false,
            },
            2,
        ),
        RegexOpcode::MatchCharICase8 => (
            Insn::MatchChar {
                code: *after.first()? as u32,
                icase: true,
            },
            2,
        ),
        RegexOpcode::MatchChar16 => (
            Insn::MatchChar {
                code: u16::from_le_bytes([*after.first()?, *after.get(1)?]) as u32,
                icase: false,
            },
            3,
        ),
        RegexOpcode::MatchCharICase16 => (
            Insn::MatchChar {
                code: u16::from_le_bytes([*after.first()?, *after.get(1)?]) as u32,
                icase: true,
            },
            3,
        ),
        RegexOpcode::U16MatchChar32 => (
            Insn::MatchChar {
                code: u32::from_le_bytes([
                    *after.first()?,
                    *after.get(1)?,
                    *after.get(2)?,
                    *after.get(3)?,
                ]),
                icase: false,
            },
            5,
        ),
        RegexOpcode::U16MatchCharICase32 => (
            Insn::MatchChar {
                code: u32::from_le_bytes([
                    *after.first()?,
                    *after.get(1)?,
                    *after.get(2)?,
                    *after.get(3)?,
                ]),
                icase: true,
            },
            5,
        ),
        RegexOpcode::MatchNChar8 | RegexOpcode::MatchNCharICase8 => {
            let count: usize = *after.first()? as usize;
            let chars_slice: &[u8] = after.get(1..1 + count)?;
            let chars: Vec<u32> = chars_slice.iter().map(|b: &u8| *b as u32).collect();
            (
                Insn::MatchNChar {
                    chars,
                    icase: matches!(op, RegexOpcode::MatchNCharICase8),
                },
                2 + count,
            )
        }
        RegexOpcode::Alternation => {
            let secondary: u32 = u32::from_le_bytes([
                *after.first()?,
                *after.get(1)?,
                *after.get(2)?,
                *after.get(3)?,
            ]);
            (
                Insn::Alternation {
                    secondary: secondary as usize,
                },
                7,
            )
        }
        RegexOpcode::Jump32 => {
            let target: u32 = u32::from_le_bytes([
                *after.first()?,
                *after.get(1)?,
                *after.get(2)?,
                *after.get(3)?,
            ]);
            (
                Insn::Jump32 {
                    target: target as usize,
                },
                5,
            )
        }
        RegexOpcode::Bracket | RegexOpcode::U16Bracket => {
            let range_count: u32 = u32::from_le_bytes([
                *after.first()?,
                *after.get(1)?,
                *after.get(2)?,
                *after.get(3)?,
            ]);
            let class_byte: u8 = *after.get(4)?;
            let negate: bool = (class_byte & 0b0000_0001) != 0;
            let positive_classes: u8 = (class_byte >> 1) & 0b0000_0111;
            let negative_classes: u8 = (class_byte >> 4) & 0b0000_0111;
            let count: usize = range_count as usize;
            let ranges_bytes: usize = count.checked_mul(BRACKET_RANGE_SIZE)?;
            let ranges_slice: &[u8] = after.get(5..5 + ranges_bytes)?;
            let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(count);
            for chunk in ranges_slice.chunks_exact(BRACKET_RANGE_SIZE) {
                let start: u32 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let end: u32 = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                ranges.push((start, end));
            }
            (
                Insn::Bracket(Bracket {
                    negate,
                    positive_classes,
                    negative_classes,
                    ranges,
                }),
                6 + ranges_bytes,
            )
        }
        RegexOpcode::BeginMarkedSubexpression => (
            Insn::BeginMarkedSubexpression {
                mexp: u16::from_le_bytes([*after.first()?, *after.get(1)?]),
            },
            3,
        ),
        RegexOpcode::EndMarkedSubexpression => (
            Insn::EndMarkedSubexpression {
                mexp: u16::from_le_bytes([*after.first()?, *after.get(1)?]),
            },
            3,
        ),
        RegexOpcode::BackRef => (
            Insn::BackRef {
                mexp: u16::from_le_bytes([*after.first()?, *after.get(1)?]),
            },
            3,
        ),
        RegexOpcode::WordBoundary => (
            Insn::WordBoundary {
                invert: *after.first()? != 0,
            },
            2,
        ),
        RegexOpcode::Lookaround => {
            let invert: bool = *after.first()? != 0;
            let forwards: bool = *after.get(1)? != 0;
            let continuation: u32 = u32::from_le_bytes([
                *after.get(7)?,
                *after.get(8)?,
                *after.get(9)?,
                *after.get(10)?,
            ]);
            (
                Insn::Lookaround(Lookaround {
                    invert,
                    forwards,
                    continuation: continuation as usize,
                }),
                12,
            )
        }
        RegexOpcode::BeginLoop => {
            let min: u32 = u32::from_le_bytes([
                *after.get(4)?,
                *after.get(5)?,
                *after.get(6)?,
                *after.get(7)?,
            ]);
            let max: u32 = u32::from_le_bytes([
                *after.get(8)?,
                *after.get(9)?,
                *after.get(10)?,
                *after.get(11)?,
            ]);
            let greedy: bool = *after.get(16)? != 0;
            let not_taken: u32 = u32::from_le_bytes([
                *after.get(18)?,
                *after.get(19)?,
                *after.get(20)?,
                *after.get(21)?,
            ]);
            (
                Insn::BeginLoop(Loop {
                    min,
                    max,
                    greedy,
                    not_taken: not_taken as usize,
                }),
                23,
            )
        }
        RegexOpcode::EndLoop => {
            let target: u32 = u32::from_le_bytes([
                *after.first()?,
                *after.get(1)?,
                *after.get(2)?,
                *after.get(3)?,
            ]);
            (
                Insn::EndLoop {
                    target: target as usize,
                },
                5,
            )
        }
        RegexOpcode::BeginSimpleLoop => {
            let not_taken: u32 = u32::from_le_bytes([
                *after.get(1)?,
                *after.get(2)?,
                *after.get(3)?,
                *after.get(4)?,
            ]);
            (
                Insn::BeginSimpleLoop {
                    not_taken: not_taken as usize,
                },
                6,
            )
        }
        RegexOpcode::EndSimpleLoop => {
            let target: u32 = u32::from_le_bytes([
                *after.first()?,
                *after.get(1)?,
                *after.get(2)?,
                *after.get(3)?,
            ]);
            (
                Insn::EndSimpleLoop {
                    target: target as usize,
                },
                5,
            )
        }
        RegexOpcode::Width1Loop => {
            let min: u32 = u32::from_le_bytes([
                *after.get(4)?,
                *after.get(5)?,
                *after.get(6)?,
                *after.get(7)?,
            ]);
            let max: u32 = u32::from_le_bytes([
                *after.get(8)?,
                *after.get(9)?,
                *after.get(10)?,
                *after.get(11)?,
            ]);
            let greedy: bool = *after.get(12)? != 0;
            let not_taken: u32 = u32::from_le_bytes([
                *after.get(13)?,
                *after.get(14)?,
                *after.get(15)?,
                *after.get(16)?,
            ]);
            (
                Insn::Width1Loop(Loop {
                    min,
                    max,
                    greedy,
                    not_taken: not_taken as usize,
                }),
                18,
            )
        }
    })
}

const MAX_REGEX_DEPTH: usize = 512;

struct PatternBuilder<'a> {
    insns: &'a [DecodedInsn],
    fully_modeled: bool,
    depth: usize,
}

impl<'a> PatternBuilder<'a> {
    fn new(insns: &'a [DecodedInsn]) -> Self {
        PatternBuilder {
            insns,
            fully_modeled: true,
            depth: 0,
        }
    }

    fn index_at(&self, offset: usize) -> Option<usize> {
        self.insns
            .iter()
            .position(|d: &DecodedInsn| d.offset == offset)
    }

    fn render_range(&mut self, start: usize, end: usize) -> String {
        if self.depth >= MAX_REGEX_DEPTH {
            self.fully_modeled = false;
            return String::new();
        }
        self.depth += 1;
        let rendered: String = self.render_range_inner(start, end);
        self.depth -= 1;
        rendered
    }

    fn render_range_inner(&mut self, start: usize, end: usize) -> String {
        let mut out: String = String::new();
        let mut offset: usize = start;
        let mut guard: usize = 0;
        while offset < end && guard < MAX_REGEX_INSNS {
            guard += 1;
            let Some(idx): Option<usize> = self.index_at(offset) else {
                self.fully_modeled = false;
                break;
            };
            let decoded: &DecodedInsn = &self.insns[idx];
            let next_offset: usize = offset + decoded.size;
            match &decoded.insn {
                Insn::Goal => break,
                Insn::LeftAnchor => {
                    out.push('^');
                    offset = next_offset;
                }
                Insn::RightAnchor => {
                    out.push('$');
                    offset = next_offset;
                }
                Insn::MatchAny => {
                    out.push('.');
                    offset = next_offset;
                }
                Insn::MatchAnyButNewline => {
                    out.push('.');
                    offset = next_offset;
                }
                Insn::MatchChar { code, .. } => {
                    push_literal_char(&mut out, *code);
                    offset = next_offset;
                }
                Insn::MatchNChar { chars, .. } => {
                    for code in chars {
                        push_literal_char(&mut out, *code);
                    }
                    offset = next_offset;
                }
                Insn::Bracket(bracket) => {
                    out.push_str(&render_bracket(bracket));
                    offset = next_offset;
                }
                Insn::WordBoundary { invert } => {
                    out.push_str(if *invert { "\\B" } else { "\\b" });
                    offset = next_offset;
                }
                Insn::BackRef { mexp } => {
                    push_text!(out, "\\{}", mexp + 1);
                    offset = next_offset;
                }
                Insn::BeginMarkedSubexpression { mexp } => {
                    offset = self.render_group(&mut out, idx, *mexp, end);
                }
                Insn::Alternation { .. } => {
                    offset = self.render_alternation(&mut out, idx, end);
                }
                Insn::Lookaround(look) => {
                    offset = self.render_lookaround(&mut out, idx, *look, end);
                }
                Insn::Width1Loop(lp) => {
                    offset = self.render_width1_loop(&mut out, idx, *lp);
                }
                Insn::BeginLoop(lp) => {
                    offset = self.render_begin_loop(&mut out, idx, *lp, end);
                }
                Insn::BeginSimpleLoop { not_taken } => {
                    offset = self.render_simple_loop(&mut out, idx, *not_taken, end);
                }
                Insn::EndMarkedSubexpression { .. }
                | Insn::EndLoop { .. }
                | Insn::EndSimpleLoop { .. }
                | Insn::Jump32 { .. } => {
                    offset = next_offset;
                }
            }
        }
        out
    }

    fn render_group(&mut self, out: &mut String, idx: usize, mexp: u16, end: usize) -> usize {
        let begin: &DecodedInsn = &self.insns[idx];
        let body_start: usize = begin.offset + begin.size;
        let Some(end_offset): Option<usize> = self.find_group_end(idx, mexp, end) else {
            self.fully_modeled = false;
            out.push('(');
            out.push_str(&self.render_range(body_start, end));
            out.push(')');
            return end;
        };
        let inner: String = self.render_range(body_start, end_offset);
        out.push('(');
        out.push_str(&inner);
        out.push(')');
        let end_idx: usize = self.index_at(end_offset).unwrap_or(idx);
        self.insns[end_idx].offset + self.insns[end_idx].size
    }

    fn find_group_end(&self, begin_idx: usize, mexp: u16, end: usize) -> Option<usize> {
        let mut depth: usize = 0;
        for decoded in &self.insns[begin_idx + 1..] {
            if decoded.offset >= end {
                break;
            }
            match &decoded.insn {
                Insn::BeginMarkedSubexpression { .. } => depth += 1,
                Insn::EndMarkedSubexpression { mexp: e } => {
                    if depth == 0 && *e == mexp {
                        return Some(decoded.offset);
                    }
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        None
    }

    fn render_alternation(&mut self, out: &mut String, idx: usize, end: usize) -> usize {
        let mut branches: Vec<(usize, usize)> = Vec::new();
        let mut cur_idx: usize = idx;
        let mut alt_end: usize = end;
        loop {
            let decoded: &DecodedInsn = &self.insns[cur_idx];
            let Insn::Alternation { secondary } = decoded.insn else {
                break;
            };
            let primary_start: usize = decoded.offset + decoded.size;
            let (primary_end, jump_dest): (usize, Option<usize>) =
                self.primary_branch_extent(primary_start, secondary);
            branches.push((primary_start, primary_end));
            if let Some(dest) = jump_dest {
                alt_end = alt_end.max(dest);
            }
            let Some(next_idx): Option<usize> = self.index_at(secondary) else {
                alt_end = alt_end.max(secondary);
                break;
            };
            if matches!(self.insns[next_idx].insn, Insn::Alternation { .. }) {
                cur_idx = next_idx;
                continue;
            }
            let last_end: usize = if alt_end > secondary { alt_end } else { end };
            branches.push((secondary, last_end));
            alt_end = alt_end.max(last_end);
            break;
        }
        let rendered: Vec<String> = branches
            .iter()
            .map(|(s, e): &(usize, usize)| self.render_range(*s, *e))
            .collect();
        out.push_str(&rendered.join("|"));
        alt_end
    }

    fn primary_branch_extent(&self, start: usize, secondary: usize) -> (usize, Option<usize>) {
        let mut last: usize = start;
        for decoded in self
            .insns
            .iter()
            .filter(|d: &&DecodedInsn| d.offset >= start)
        {
            if decoded.offset >= secondary {
                break;
            }
            if let Insn::Jump32 { target } = decoded.insn {
                return (decoded.offset, Some(target));
            }
            last = decoded.offset + decoded.size;
        }
        (last.min(secondary), None)
    }

    fn render_lookaround(
        &mut self,
        out: &mut String,
        idx: usize,
        look: Lookaround,
        end: usize,
    ) -> usize {
        let begin: &DecodedInsn = &self.insns[idx];
        let body_start: usize = begin.offset + begin.size;
        let body_end: usize = look.continuation.min(end);
        let inner: String = if look.forwards {
            self.render_range(body_start, body_end)
        } else {
            self.render_lookbehind_body(body_start, body_end)
        };
        let prefix: &str = match (look.forwards, look.invert) {
            (true, false) => "(?=",
            (true, true) => "(?!",
            (false, false) => "(?<=",
            (false, true) => "(?<!",
        };
        out.push_str(prefix);
        out.push_str(&inner);
        out.push(')');
        look.continuation
    }

    fn render_lookbehind_body(&mut self, start: usize, end: usize) -> String {
        let atoms: Vec<usize> = self
            .insns
            .iter()
            .enumerate()
            .filter(|(_, d): &(usize, &DecodedInsn)| d.offset >= start && d.offset < end)
            .map(|(i, _): (usize, &DecodedInsn)| i)
            .collect();
        let reversible: bool = atoms.iter().all(|i: &usize| {
            matches!(
                self.insns[*i].insn,
                Insn::MatchChar { .. }
                    | Insn::MatchNChar { .. }
                    | Insn::MatchAny
                    | Insn::MatchAnyButNewline
                    | Insn::Bracket(_)
                    | Insn::WordBoundary { .. }
                    | Insn::LeftAnchor
                    | Insn::RightAnchor
                    | Insn::Goal
            )
        });
        if !reversible {
            self.fully_modeled = false;
            return self.render_range(start, end);
        }
        let mut out: String = String::new();
        for i in atoms.iter().rev() {
            match &self.insns[*i].insn {
                Insn::Goal => {}
                Insn::MatchNChar { chars, .. } => {
                    for code in chars.iter().rev() {
                        push_literal_char(&mut out, *code);
                    }
                }
                _ => out.push_str(&self.render_atom(*i)),
            }
        }
        out
    }

    fn render_width1_loop(&mut self, out: &mut String, idx: usize, lp: Loop) -> usize {
        let begin: &DecodedInsn = &self.insns[idx];
        let body_start: usize = begin.offset + begin.size;
        let Some(body_idx): Option<usize> = self.index_at(body_start) else {
            self.fully_modeled = false;
            return lp.not_taken.max(body_start);
        };
        let body: &DecodedInsn = &self.insns[body_idx];
        let body_end: usize = body.offset + body.size;
        let inner: String = self.render_atom(body_idx);
        out.push_str(&wrap_quantified(&inner, lp));
        body_end
    }

    fn render_begin_loop(&mut self, out: &mut String, idx: usize, lp: Loop, end: usize) -> usize {
        let begin: &DecodedInsn = &self.insns[idx];
        let body_start: usize = begin.offset + begin.size;
        let body_end: usize = self.find_end_loop(body_start, lp.not_taken).min(end);
        let inner: String = self.render_grouped_body(body_start, body_end);
        out.push_str(&wrap_quantified(&inner, lp));
        lp.not_taken
    }

    fn render_simple_loop(
        &mut self,
        out: &mut String,
        idx: usize,
        not_taken: usize,
        end: usize,
    ) -> usize {
        let begin: &DecodedInsn = &self.insns[idx];
        let body_start: usize = begin.offset + begin.size;
        let body_end: usize = self.find_end_simple_loop(body_start, not_taken).min(end);
        let inner: String = self.render_grouped_body(body_start, body_end);
        out.push_str(&inner);
        out.push('*');
        not_taken
    }

    fn render_grouped_body(&mut self, start: usize, end: usize) -> String {
        let inner: String = self.render_range(start, end);
        if needs_group_wrap(&inner) {
            format!("(?:{inner})")
        } else {
            inner
        }
    }

    fn render_atom(&mut self, idx: usize) -> String {
        let decoded: &DecodedInsn = &self.insns[idx];
        let mut out: String = String::new();
        match &decoded.insn {
            Insn::MatchChar { code, .. } => push_literal_char(&mut out, *code),
            Insn::MatchAny | Insn::MatchAnyButNewline => out.push('.'),
            Insn::Bracket(bracket) => out.push_str(&render_bracket(bracket)),
            Insn::LeftAnchor => out.push('^'),
            Insn::RightAnchor => out.push('$'),
            Insn::WordBoundary { invert } => out.push_str(if *invert { "\\B" } else { "\\b" }),
            Insn::MatchNChar { chars, .. } => {
                for code in chars {
                    push_literal_char(&mut out, *code);
                }
            }
            _ => {
                self.fully_modeled = false;
                out.push_str("(?:?)");
            }
        }
        out
    }

    fn find_end_loop(&self, start: usize, fallback: usize) -> usize {
        let mut depth: usize = 0;
        for decoded in self
            .insns
            .iter()
            .filter(|d: &&DecodedInsn| d.offset >= start)
        {
            match &decoded.insn {
                Insn::BeginLoop(_) => depth += 1,
                Insn::EndLoop { .. } => {
                    if depth == 0 {
                        return decoded.offset;
                    }
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        fallback
    }

    fn find_end_simple_loop(&self, start: usize, fallback: usize) -> usize {
        let mut depth: usize = 0;
        for decoded in self
            .insns
            .iter()
            .filter(|d: &&DecodedInsn| d.offset >= start)
        {
            match &decoded.insn {
                Insn::BeginSimpleLoop { .. } => depth += 1,
                Insn::EndSimpleLoop { .. } => {
                    if depth == 0 {
                        return decoded.offset;
                    }
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        fallback
    }
}

#[must_use]
fn wrap_quantified(atom: &str, lp: Loop) -> String {
    let base: String = if needs_group_wrap(atom) {
        format!("(?:{atom})")
    } else {
        atom.to_owned()
    };
    let quant: String = quantifier(lp.min, lp.max);
    let suffix: &str = if lp.greedy { "" } else { "?" };
    format!("{base}{quant}{suffix}")
}

#[must_use]
fn quantifier(min: u32, max: u32) -> String {
    match (min, max) {
        (0, LOOP_UNBOUNDED) => "*".to_owned(),
        (1, LOOP_UNBOUNDED) => "+".to_owned(),
        (0, 1) => "?".to_owned(),
        (a, b) if a == b => format!("{{{a}}}"),
        (a, LOOP_UNBOUNDED) => format!("{{{a},}}"),
        (a, b) => format!("{{{a},{b}}}"),
    }
}

#[must_use]
fn needs_group_wrap(atom: &str) -> bool {
    if atom.is_empty() {
        return true;
    }
    let mut chars: std::str::Chars<'_> = atom.chars();
    let first: char = chars.next().unwrap_or(' ');
    if first == '(' || first == '[' {
        let last: Option<char> = atom.chars().last();
        let closer: char = if first == '(' { ')' } else { ']' };
        if last == Some(closer) && balanced(atom, first, closer) {
            return false;
        }
        return true;
    }
    if first == '\\' {
        return atom.chars().count() != 2;
    }
    atom.chars().count() != 1
}

#[must_use]
fn balanced(s: &str, open: char, close: char) -> bool {
    let mut depth: i32 = 0;
    let mut escaped: bool = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return i == s.len() - close.len_utf8();
            }
        }
    }
    false
}

#[must_use]
fn render_bracket(bracket: &Bracket) -> String {
    if let Some(bare) = bracket_as_bare_class(bracket) {
        return bare;
    }
    let mut out: String = String::new();
    out.push('[');
    if bracket.negate {
        out.push('^');
    }
    append_classes(&mut out, bracket.positive_classes, false);
    append_classes(&mut out, bracket.negative_classes, true);
    for (start, end) in &bracket.ranges {
        push_class_char(&mut out, *start);
        if start != end {
            out.push('-');
            push_class_char(&mut out, *end);
        }
    }
    out.push(']');
    out
}

#[must_use]
fn bracket_as_bare_class(bracket: &Bracket) -> Option<String> {
    if bracket.negate || !bracket.ranges.is_empty() {
        return None;
    }
    match (
        bracket.positive_classes,
        bracket.negative_classes,
        bracket.positive_classes.count_ones() + bracket.negative_classes.count_ones(),
    ) {
        (CLASS_DIGITS, 0, 1) => Some("\\d".to_owned()),
        (CLASS_SPACES, 0, 1) => Some("\\s".to_owned()),
        (CLASS_WORDS, 0, 1) => Some("\\w".to_owned()),
        (0, CLASS_DIGITS, 1) => Some("\\D".to_owned()),
        (0, CLASS_SPACES, 1) => Some("\\S".to_owned()),
        (0, CLASS_WORDS, 1) => Some("\\W".to_owned()),
        _ => None,
    }
}

fn append_classes(out: &mut String, classes: u8, negated: bool) {
    if classes & CLASS_DIGITS != 0 {
        out.push_str(if negated { "\\D" } else { "\\d" });
    }
    if classes & CLASS_SPACES != 0 {
        out.push_str(if negated { "\\S" } else { "\\s" });
    }
    if classes & CLASS_WORDS != 0 {
        out.push_str(if negated { "\\W" } else { "\\w" });
    }
}

fn push_class_char(mut out: &mut String, code: u32) {
    match char::from_u32(code) {
        Some(c) if matches!(c, ']' | '\\' | '^' | '-') => {
            out.push('\\');
            out.push(c);
        }
        Some(c) if (c as u32) >= 0x20 && (c as u32) < 0x7f => out.push(c),
        _ => {
            push_text!(out, "\\u{code:04x}");
        }
    }
}

fn push_literal_char(mut out: &mut String, code: u32) {
    match char::from_u32(code) {
        Some(c) if is_regex_metachar(c) => {
            out.push('\\');
            out.push(c);
        }
        Some(c) if (c as u32) >= 0x20 && (c as u32) < 0x7f => out.push(c),
        _ => {
            push_text!(out, "\\u{code:04x}");
        }
    }
}

#[must_use]
const fn is_regex_metachar(c: char) -> bool {
    matches!(
        c,
        '.' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' | '/'
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn regex_blob(marked: u16, loops: u16, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(REGEX_HEADER_SIZE + body.len());
        v.extend_from_slice(&marked.to_le_bytes());
        v.extend_from_slice(&loops.to_le_bytes());
        v.extend_from_slice(&[flags, 0u8]);
        v.extend_from_slice(body);
        v
    }

    fn recover_single(marked: u16, loops: u16, flags: u8, body: &[u8]) -> RecoveredRegExp {
        let blob: Vec<u8> = regex_blob(marked, loops, flags, body);
        let table: Vec<RegExpTableEntry> = vec![RegExpTableEntry {
            offset: 0,
            length: blob.len() as u32,
        }];
        recover_regexps(&table, &blob).remove(0)
    }

    #[test]
    fn flags_decode_es2022_order() {
        assert_eq!(flags_to_string(FLAG_GLOBAL | FLAG_ICASE), "gi");
        assert_eq!(
            flags_to_string(FLAG_INDICES | FLAG_GLOBAL | FLAG_MULTILINE | FLAG_STICKY),
            "dgmy"
        );
        assert_eq!(flags_to_string(0), "");
        assert_eq!(
            flags_to_string(
                FLAG_ICASE
                    | FLAG_GLOBAL
                    | FLAG_MULTILINE
                    | FLAG_UNICODE
                    | FLAG_DOTALL
                    | FLAG_STICKY
            ),
            "gimsuy"
        );
    }

    #[test]
    fn match_n_char_emits_run() {
        let mut body: Vec<u8> = Vec::new();
        body.push(RegexOpcode::MatchNChar8 as u8);
        body.push(5u8);
        body.extend_from_slice(b"hello");
        body.push(RegexOpcode::Goal as u8);
        let r: RecoveredRegExp = recover_single(0, 0, 0, &body);
        assert_eq!(r.pattern, "hello");
        assert!(r.fully_modeled);
    }

    #[test]
    fn anchors_and_literals_round_trip() {
        let mut body: Vec<u8> = Vec::new();
        body.push(RegexOpcode::LeftAnchor as u8);
        body.push(RegexOpcode::MatchNChar8 as u8);
        body.push(3u8);
        body.extend_from_slice(b"abc");
        body.push(RegexOpcode::RightAnchor as u8);
        body.push(RegexOpcode::Goal as u8);
        let r: RecoveredRegExp = recover_single(0, 0, FLAG_GLOBAL, &body);
        assert_eq!(r.flags, "g");
        assert_eq!(r.pattern, "^abc$");
        assert_eq!(r.to_js_literal(), "/^abc$/g");
        assert!(r.fully_modeled);
    }

    #[test]
    fn metachar_in_literal_is_escaped() {
        let body: Vec<u8> = vec![RegexOpcode::MatchChar8 as u8, b'.', RegexOpcode::Goal as u8];
        let r: RecoveredRegExp = recover_single(0, 0, 0, &body);
        assert_eq!(r.pattern, "\\.");
    }

    #[test]
    fn out_of_bounds_entry_yields_empty_recovery() {
        let storage: Vec<u8> = vec![0u8; 4];
        let table: Vec<RegExpTableEntry> = vec![RegExpTableEntry {
            offset: 100,
            length: 50,
        }];
        let recovered: Vec<RecoveredRegExp> = recover_regexps(&table, &storage);
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].pattern.is_empty());
    }

    #[test]
    fn quantifier_strings() {
        assert_eq!(quantifier(0, LOOP_UNBOUNDED), "*");
        assert_eq!(quantifier(1, LOOP_UNBOUNDED), "+");
        assert_eq!(quantifier(0, 1), "?");
        assert_eq!(quantifier(3, 3), "{3}");
        assert_eq!(quantifier(2, LOOP_UNBOUNDED), "{2,}");
        assert_eq!(quantifier(2, 5), "{2,5}");
    }

    #[test]
    fn unknown_opcode_marks_unmodeled_without_guessing() {
        let body: Vec<u8> = vec![
            RegexOpcode::MatchChar8 as u8,
            b'a',
            0xfe,
            RegexOpcode::Goal as u8,
        ];
        let r: RecoveredRegExp = recover_single(0, 0, 0, &body);
        assert_eq!(r.pattern, "a");
        assert!(
            !r.fully_modeled,
            "unknown opcode must not be marked modeled"
        );
    }

    #[test]
    fn bare_single_class_simplifies_outside_bracket() {
        let mut body: Vec<u8> = Vec::new();
        body.push(RegexOpcode::Bracket as u8);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(CLASS_WORDS << 1);
        body.push(RegexOpcode::Goal as u8);
        let r: RecoveredRegExp = recover_single(0, 0, 0, &body);
        assert_eq!(r.pattern, "\\w");
        assert!(r.fully_modeled);
    }

    #[test]
    fn bracket_class_and_range() {
        let bracket: Bracket = Bracket {
            negate: false,
            positive_classes: CLASS_DIGITS | CLASS_SPACES,
            negative_classes: 0,
            ranges: Vec::new(),
        };
        assert_eq!(render_bracket(&bracket), "[\\d\\s]");
        let negated: Bracket = Bracket {
            negate: true,
            positive_classes: 0,
            negative_classes: 0,
            ranges: vec![(b'0' as u32, b'9' as u32)],
        };
        assert_eq!(render_bracket(&negated), "[^0-9]");
    }
}
