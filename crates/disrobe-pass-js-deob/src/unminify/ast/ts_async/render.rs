use std::cmp::Reverse;
use std::collections::BTreeMap;

use oxc_span::Span;

use super::Refusal;

const MAX_RENDER_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LabelId(pub(super) usize);

#[derive(Debug, Clone)]
pub(super) enum Piece {
    Text(String),
    Label(LabelId),
}

#[derive(Debug, Clone, Default)]
pub(super) struct Code {
    pub(super) pieces: Vec<Piece>,
}

impl Code {
    pub(super) fn text(text: &str) -> Self {
        let mut code: Self = Self::default();
        code.push_str(text);
        code
    }

    pub(super) fn push_str(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if let Some(Piece::Text(last)) = self.pieces.last_mut() {
            last.push_str(text);
        } else {
            self.pieces.push(Piece::Text(text.to_owned()));
        }
    }

    pub(super) fn push_label(&mut self, label: LabelId) {
        self.pieces.push(Piece::Label(label));
    }

    pub(super) fn append(&mut self, other: Self) {
        for piece in other.pieces {
            match piece {
                Piece::Text(text) => self.push_str(&text),
                Piece::Label(label) => self.push_label(label),
            }
        }
    }

    pub(super) fn wrapped(inner: Self, open: &str, close: &str) -> Self {
        let mut code: Self = Self::text(open);
        code.append(inner);
        code.push_str(close);
        code
    }

    pub(super) fn plain_text(&self) -> Option<&str> {
        match self.pieces.as_slice() {
            [] => Some(""),
            [Piece::Text(text)] => Some(text),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Wrap {
    Bare,
    Parenthesized,
}

#[derive(Debug, Clone)]
pub(super) enum Callee {
    Plain(Span),
    StaticMember {
        object: Span,
        object_wrap: Wrap,
        property: String,
    },
    ComputedMember {
        object: Span,
        object_wrap: Wrap,
        key: Span,
    },
}

#[derive(Debug, Clone)]
pub(super) enum Replacement {
    Code(Code),
    Await {
        operand: Span,
        operand_wrap: Wrap,
        outer_wrap: Wrap,
    },
    Moved {
        expression: Span,
        wrap: Wrap,
    },
    Call {
        callee: Callee,
        arguments: Vec<Span>,
        wrap: Wrap,
    },
    Array {
        elements: Vec<Span>,
    },
    Return {
        argument: Option<Span>,
    },
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Checkpoint(usize);

#[derive(Debug)]
pub(super) struct Renderer<'s> {
    source: &'s str,
    replacements: BTreeMap<(u32, Reverse<u32>), Replacement>,
    journal: Vec<(u32, Reverse<u32>)>,
}

impl<'s> Renderer<'s> {
    pub(super) const fn new(source: &'s str) -> Self {
        Self {
            source,
            replacements: BTreeMap::new(),
            journal: Vec::new(),
        }
    }

    pub(super) const fn checkpoint(&self) -> Checkpoint {
        Checkpoint(self.journal.len())
    }

    pub(super) fn rollback(&mut self, checkpoint: Checkpoint) {
        while self.journal.len() > checkpoint.0 {
            if let Some(key) = self.journal.pop() {
                self.replacements.remove(&key);
            }
        }
    }

    pub(super) const fn source(&self) -> &'s str {
        self.source
    }

    pub(super) fn insert(&mut self, span: Span, replacement: Replacement) -> Result<(), Refusal> {
        let key: (u32, Reverse<u32>) = (span.start, Reverse(span.end));
        if self.replacements.contains_key(&key) {
            return Err(Refusal::OverlappingRewrite);
        }
        self.replacements.insert(key, replacement);
        self.journal.push(key);
        Ok(())
    }

    pub(super) fn slice(&self, start: u32, end: u32) -> Result<&'s str, Refusal> {
        self.source
            .get(start as usize..end as usize)
            .ok_or(Refusal::OverlappingRewrite)
    }

    pub(super) fn render(&self, span: Span) -> Result<Code, Refusal> {
        self.render_at(span, 0)
    }

    fn render_at(&self, span: Span, depth: usize) -> Result<Code, Refusal> {
        if depth > MAX_RENDER_DEPTH {
            return Err(Refusal::TooDeep);
        }
        self.replacements
            .get(&(span.start, Reverse(span.end)))
            .map_or_else(
                || self.render_inside(span.start, span.end, depth),
                |replacement: &Replacement| self.apply(replacement, depth + 1),
            )
    }

    fn render_inside(&self, start: u32, end: u32, depth: usize) -> Result<Code, Refusal> {
        let mut code: Code = Code::default();
        let mut cursor: u32 = start;
        for (&(from, Reverse(to)), replacement) in self
            .replacements
            .range((start, Reverse(u32::MAX))..(end, Reverse(0)))
        {
            if to > end || (from == start && to == end) {
                continue;
            }
            if from < cursor {
                if to <= cursor {
                    continue;
                }
                return Err(Refusal::OverlappingRewrite);
            }
            code.push_str(self.slice(cursor, from)?);
            code.append(self.apply(replacement, depth + 1)?);
            cursor = to;
        }
        code.push_str(self.slice(cursor, end)?);
        Ok(code)
    }

    fn apply(&self, replacement: &Replacement, depth: usize) -> Result<Code, Refusal> {
        match replacement {
            Replacement::Code(code) => Ok(code.clone()),
            Replacement::Await {
                operand,
                operand_wrap,
                outer_wrap,
            } => {
                let mut code: Code = Code::text("await ");
                code.append(wrap(self.render_at(*operand, depth)?, *operand_wrap));
                Ok(wrap(code, *outer_wrap))
            }
            Replacement::Moved {
                expression,
                wrap: moved_wrap,
            } => Ok(wrap(self.render_at(*expression, depth)?, *moved_wrap)),
            Replacement::Call {
                callee,
                arguments,
                wrap: call_wrap,
            } => {
                let mut code: Code = match callee {
                    Callee::Plain(span) => self.render_at(*span, depth)?,
                    Callee::StaticMember {
                        object,
                        object_wrap,
                        property,
                    } => {
                        let mut member: Code = wrap(self.render_at(*object, depth)?, *object_wrap);
                        member.push_str(".");
                        member.push_str(property);
                        member
                    }
                    Callee::ComputedMember {
                        object,
                        object_wrap,
                        key,
                    } => {
                        let mut member: Code = wrap(self.render_at(*object, depth)?, *object_wrap);
                        member.append(Code::wrapped(self.render_at(*key, depth)?, "[", "]"));
                        member
                    }
                };
                code.append(Code::wrapped(self.render_list(arguments, depth)?, "(", ")"));
                Ok(wrap(code, *call_wrap))
            }
            Replacement::Array { elements } => {
                Ok(Code::wrapped(self.render_list(elements, depth)?, "[", "]"))
            }
            Replacement::Return { argument } => {
                let mut code: Code = Code::text("return");
                if let Some(argument) = argument {
                    code.push_str(" ");
                    code.append(self.render_at(*argument, depth)?);
                }
                code.push_str(";");
                Ok(code)
            }
        }
    }

    fn render_list(&self, spans: &[Span], depth: usize) -> Result<Code, Refusal> {
        let mut code: Code = Code::default();
        for (index, span) in spans.iter().enumerate() {
            if index > 0 {
                code.push_str(", ");
            }
            code.append(self.render_at(*span, depth)?);
        }
        Ok(code)
    }
}

fn wrap(code: Code, mode: Wrap) -> Code {
    match mode {
        Wrap::Bare => code,
        Wrap::Parenthesized => Code::wrapped(code, "(", ")"),
    }
}
