use serde::{Deserialize, Serialize};

use super::RegExpTableEntry;

/// Syntax-flag bit values from Hermes `regex::constants::SyntaxFlags::FlagBits`.
const FLAG_ICASE: u8 = 1 << 0;
const FLAG_GLOBAL: u8 = 1 << 1;
const FLAG_MULTILINE: u8 = 1 << 2;
const FLAG_UNICODE: u8 = 1 << 3;
const FLAG_DOTALL: u8 = 1 << 4;
const FLAG_STICKY: u8 = 1 << 5;
const FLAG_INDICES: u8 = 1 << 6;

/// Size of the `RegexBytecodeHeader`: markedCount(u16) + loopCount(u16) + syntaxFlags(u8) + constraints(u8).
const REGEX_HEADER_SIZE: usize = 6;

/// Upper bound on regex opcodes decoded per pattern.
const MAX_REGEX_INSNS: usize = 1 << 16;

/// Regex opcode ordinals from Hermes `RegexOpcodes.def` (declaration order maps
/// to the `Opcode` enum value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RegexOpcode {
    Goal = 0,
    LeftAnchor = 1,
    LeftAnchorMultiline = 2,
    RightAnchor = 3,
    RightAnchorMultiline = 4,
    MatchAny = 5,
    U16MatchAny = 6,
    MatchAnyButNewline = 7,
    U16MatchAnyButNewline = 8,
    MatchChar8 = 9,
    MatchChar16 = 10,
    U16MatchChar32 = 11,
    MatchNChar8 = 12,
    MatchNCharICase8 = 13,
    MatchCharICase8 = 14,
    MatchCharICase16 = 15,
    U16MatchCharICase32 = 16,
    Alternation = 17,
    Jump32 = 18,
    Bracket = 19,
    BracketICase = 20,
    U16Bracket = 21,
    U16BracketICase = 22,
    BeginMarkedSubexpression = 23,
    EndMarkedSubexpression = 24,
    BackRef = 25,
    BackRefICase = 26,
    WordBoundary = 27,
    WordBoundaryICase = 28,
    Lookaround = 29,
    BeginLoop = 30,
    EndLoop = 31,
    BeginSimpleLoop = 32,
    EndSimpleLoop = 33,
    Width1Loop = 34,
}

impl RegexOpcode {
    #[must_use]
    const fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Goal,
            1 => Self::LeftAnchor,
            2 => Self::LeftAnchorMultiline,
            3 => Self::RightAnchor,
            4 => Self::RightAnchorMultiline,
            5 => Self::MatchAny,
            6 => Self::U16MatchAny,
            7 => Self::MatchAnyButNewline,
            8 => Self::U16MatchAnyButNewline,
            9 => Self::MatchChar8,
            10 => Self::MatchChar16,
            11 => Self::U16MatchChar32,
            12 => Self::MatchNChar8,
            13 => Self::MatchNCharICase8,
            14 => Self::MatchCharICase8,
            15 => Self::MatchCharICase16,
            16 => Self::U16MatchCharICase32,
            17 => Self::Alternation,
            18 => Self::Jump32,
            19 => Self::Bracket,
            20 => Self::BracketICase,
            21 => Self::U16Bracket,
            22 => Self::U16BracketICase,
            23 => Self::BeginMarkedSubexpression,
            24 => Self::EndMarkedSubexpression,
            25 => Self::BackRef,
            26 => Self::BackRefICase,
            27 => Self::WordBoundary,
            28 => Self::WordBoundaryICase,
            29 => Self::Lookaround,
            30 => Self::BeginLoop,
            31 => Self::EndLoop,
            32 => Self::BeginSimpleLoop,
            33 => Self::EndSimpleLoop,
            34 => Self::Width1Loop,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredRegExp {
    pub index: usize,
    pub flags: String,
    pub marked_count: u16,
    pub loop_count: u16,
    pub pattern_skeleton: String,
    pub fully_literal: bool,
}

impl RecoveredRegExp {
    /// Renders the recovered regex as a JavaScript regex literal.
    #[must_use]
    pub fn to_js_literal(&self) -> String {
        format!("/{}/{}", self.pattern_skeleton, self.flags)
    }
}

/// Decodes the JS flag string from a `syntaxFlags` byte in ES2022 order (d g i m s u y).
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

/// Recovers every regexp in a module from its compiled bytecode.
#[must_use]
pub fn recover_regexps(table: &[RegExpTableEntry], storage: &[u8]) -> Vec<RecoveredRegExp> {
    let mut out: Vec<RecoveredRegExp> = Vec::with_capacity(table.len());
    for (index, entry) in table.iter().enumerate() {
        let start: usize = entry.offset as usize;
        let end: usize = start.saturating_add(entry.length as usize);
        if start >= storage.len()
            || end > storage.len()
            || entry.length as usize <= REGEX_HEADER_SIZE
        {
            out.push(RecoveredRegExp {
                index,
                flags: String::new(),
                marked_count: 0,
                loop_count: 0,
                pattern_skeleton: String::new(),
                fully_literal: false,
            });
            continue;
        }
        let slice: &[u8] = &storage[start..end];
        out.push(recover_one(index, slice));
    }
    out
}

#[must_use]
fn recover_one(index: usize, slice: &[u8]) -> RecoveredRegExp {
    let marked_count: u16 = u16::from_le_bytes([slice[0], slice[1]]);
    let loop_count: u16 = u16::from_le_bytes([slice[2], slice[3]]);
    let syntax_flags: u8 = slice[4];
    let flags: String = flags_to_string(syntax_flags);
    let body: &[u8] = &slice[REGEX_HEADER_SIZE..];
    let (skeleton, fully_literal): (String, bool) = disassemble_pattern(body);
    RecoveredRegExp {
        index,
        flags,
        marked_count,
        loop_count,
        pattern_skeleton: skeleton,
        fully_literal,
    }
}

#[must_use]
fn disassemble_pattern(body: &[u8]) -> (String, bool) {
    let mut out: String = String::new();
    let mut fully_literal: bool = true;
    let mut pc: usize = 0;
    let mut insns: usize = 0;
    while pc < body.len() && insns < MAX_REGEX_INSNS {
        insns += 1;
        let Some(op): Option<RegexOpcode> = RegexOpcode::from_byte(body[pc]) else {
            fully_literal = false;
            out.push_str("(?:?)");
            break;
        };
        pc += 1;
        match op {
            RegexOpcode::Goal => break,
            RegexOpcode::LeftAnchor | RegexOpcode::LeftAnchorMultiline => out.push('^'),
            RegexOpcode::RightAnchor | RegexOpcode::RightAnchorMultiline => out.push('$'),
            RegexOpcode::MatchAny | RegexOpcode::U16MatchAny => out.push('.'),
            RegexOpcode::MatchAnyButNewline | RegexOpcode::U16MatchAnyButNewline => out.push('.'),
            RegexOpcode::MatchChar8 | RegexOpcode::MatchCharICase8 => {
                let Some(c): Option<&u8> = body.get(pc) else {
                    fully_literal = false;
                    break;
                };
                push_literal_char(&mut out, *c as u32);
                pc += 1;
            }
            RegexOpcode::MatchChar16 | RegexOpcode::MatchCharICase16 => {
                if pc + 1 < body.len() {
                    let c: u32 = u16::from_le_bytes([body[pc], body[pc + 1]]) as u32;
                    push_literal_char(&mut out, c);
                    pc += 2;
                } else {
                    fully_literal = false;
                    break;
                }
            }
            RegexOpcode::U16MatchChar32 | RegexOpcode::U16MatchCharICase32 => {
                if pc + 3 < body.len() {
                    let c: u32 =
                        u32::from_le_bytes([body[pc], body[pc + 1], body[pc + 2], body[pc + 3]]);
                    push_literal_char(&mut out, c);
                    pc += 4;
                } else {
                    fully_literal = false;
                    break;
                }
            }
            RegexOpcode::MatchNChar8 | RegexOpcode::MatchNCharICase8 => {
                let Some(n): Option<&u8> = body.get(pc) else {
                    fully_literal = false;
                    break;
                };
                let count: usize = *n as usize;
                pc += 1;
                let avail: usize = (body.len() - pc).min(count);
                for k in 0..avail {
                    push_literal_char(&mut out, body[pc + k] as u32);
                }
                pc += avail;
                if avail < count {
                    fully_literal = false;
                    break;
                }
            }
            RegexOpcode::BeginMarkedSubexpression => {
                out.push('(');
                fully_literal = false;
                pc += 2;
            }
            RegexOpcode::EndMarkedSubexpression => {
                out.push(')');
                pc += 2;
            }
            RegexOpcode::WordBoundary => out.push_str("\\b"),
            RegexOpcode::WordBoundaryICase => out.push_str("\\b"),
            _ => {
                fully_literal = false;
                out.push_str("(?:...)");
                break;
            }
        }
    }
    (out, fully_literal)
}

fn push_literal_char(out: &mut String, code: u32) {
    match char::from_u32(code) {
        Some(c) if is_regex_metachar(c) => {
            out.push('\\');
            out.push(c);
        }
        Some(c) if (c as u32) >= 0x20 && (c as u32) < 0x7f => out.push(c),
        Some(_) | None => {
            use std::fmt::Write as _;
            let _ = write!(out, "\\u{code:04x}");
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
    fn literal_pattern_round_trips() {
        let mut body: Vec<u8> = Vec::new();
        body.push(RegexOpcode::LeftAnchor as u8);
        for c in b"abc" {
            body.push(RegexOpcode::MatchChar8 as u8);
            body.push(*c);
        }
        body.push(RegexOpcode::RightAnchor as u8);
        body.push(RegexOpcode::Goal as u8);
        let blob: Vec<u8> = regex_blob(0, 0, FLAG_GLOBAL, &body);
        let table: Vec<RegExpTableEntry> = vec![RegExpTableEntry {
            offset: 0,
            length: blob.len() as u32,
        }];
        let recovered: Vec<RecoveredRegExp> = recover_regexps(&table, &blob);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].flags, "g");
        assert!(recovered[0].fully_literal);
        assert_eq!(recovered[0].pattern_skeleton, "^abc$");
        assert_eq!(recovered[0].to_js_literal(), "/^abc$/g");
    }

    #[test]
    fn match_n_char_emits_run() {
        let mut body: Vec<u8> = Vec::new();
        body.push(RegexOpcode::MatchNChar8 as u8);
        body.push(5u8);
        body.extend_from_slice(b"hello");
        body.push(RegexOpcode::Goal as u8);
        let blob: Vec<u8> = regex_blob(0, 0, 0, &body);
        let table: Vec<RegExpTableEntry> = vec![RegExpTableEntry {
            offset: 0,
            length: blob.len() as u32,
        }];
        let recovered: Vec<RecoveredRegExp> = recover_regexps(&table, &blob);
        assert_eq!(recovered[0].pattern_skeleton, "hello");
    }

    #[test]
    fn metachar_in_literal_is_escaped() {
        let body: Vec<u8> = vec![RegexOpcode::MatchChar8 as u8, b'.', RegexOpcode::Goal as u8];
        let blob: Vec<u8> = regex_blob(0, 0, 0, &body);
        let table: Vec<RegExpTableEntry> = vec![RegExpTableEntry {
            offset: 0,
            length: blob.len() as u32,
        }];
        let recovered: Vec<RecoveredRegExp> = recover_regexps(&table, &blob);
        assert_eq!(recovered[0].pattern_skeleton, "\\.");
    }

    #[test]
    fn captured_group_marks_non_literal() {
        let mut body: Vec<u8> = Vec::new();
        body.push(RegexOpcode::BeginMarkedSubexpression as u8);
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(RegexOpcode::MatchChar8 as u8);
        body.push(b'x');
        body.push(RegexOpcode::EndMarkedSubexpression as u8);
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(RegexOpcode::Goal as u8);
        let blob: Vec<u8> = regex_blob(1, 0, FLAG_ICASE, &body);
        let table: Vec<RegExpTableEntry> = vec![RegExpTableEntry {
            offset: 0,
            length: blob.len() as u32,
        }];
        let recovered: Vec<RecoveredRegExp> = recover_regexps(&table, &blob);
        assert_eq!(recovered[0].marked_count, 1);
        assert_eq!(recovered[0].flags, "i");
        assert!(!recovered[0].fully_literal);
        assert_eq!(recovered[0].pattern_skeleton, "(x)");
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
        assert!(recovered[0].pattern_skeleton.is_empty());
    }
}
