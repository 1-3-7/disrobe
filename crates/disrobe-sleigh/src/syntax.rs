use std::collections::{BTreeMap, BTreeSet};

use crate::SleighError;

const MAX_ITEM_DEPTH: usize = 64;
const MAX_PATTERN_NESTING: usize = 64;
const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOKEN_COUNT: usize = 500_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    Big,
    Little,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpaceDef {
    pub attributes: BTreeMap<String, String>,
    pub name: String,
    pub size_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterDef {
    pub name: String,
    pub offset: u64,
    pub size_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldDef {
    pub high_bit: u8,
    pub low_bit: u8,
    pub name: String,
    pub signed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenDef {
    pub bits: u32,
    pub endian: Option<Endian>,
    pub fields: Vec<FieldDef>,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextDef {
    pub high_bit: u8,
    pub low_bit: u8,
    pub name: String,
    pub noflow: bool,
    pub register: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitRangeDef {
    pub bit_offset: u32,
    pub bit_size: u32,
    pub name: String,
    pub register: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentKind {
    Names,
    Values,
    Variables,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachmentValue {
    Identifier(String),
    Integer(i64),
    Name(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attachment {
    pub fields: Vec<String>,
    pub kind: AttachmentKind,
    pub values: Vec<AttachmentValue>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompareOp {
    Equal,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    NotEqual,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PatternValue {
    Add { identifier: String, amount: i64 },
    Identifier(String),
    Integer(i64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatternAtom {
    Compare {
        left: String,
        op: CompareOp,
        right: PatternValue,
    },
    Residual(String),
    Symbol(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatternExpr {
    All(Vec<Self>),
    Any(Vec<Self>),
    Atom(PatternAtom),
    Next(Box<Self>, Box<Self>),
    True,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayToken {
    Concatenate,
    Literal(String),
    Symbol(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Constructor {
    pub context_tokens: Vec<String>,
    pub display_tokens: Vec<DisplayToken>,
    pub mnemonic: String,
    pub pattern: PatternExpr,
    pub semantic_tokens: Vec<String>,
    pub source_order: usize,
    pub table: String,
    pub unimplemented: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SleighSpec {
    pub alignment: Option<u32>,
    pub attachments: Vec<Attachment>,
    pub bitranges: Vec<BitRangeDef>,
    pub constructors: Vec<Constructor>,
    pub contexts: Vec<ContextDef>,
    pub endian: Option<Endian>,
    pub pcodeops: BTreeSet<String>,
    pub registers: Vec<RegisterDef>,
    pub spaces: Vec<SpaceDef>,
    pub tokens: Vec<TokenDef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LexemeKind {
    Identifier,
    Number,
    String,
    Symbol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Lexeme {
    kind: LexemeKind,
    offset: usize,
    text: String,
}

#[derive(Debug)]
struct Parser {
    index: usize,
    item_depth: usize,
    spec: SleighSpec,
    tokens: Vec<Lexeme>,
}

pub fn parse_spec(source: &str) -> Result<SleighSpec, SleighError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(SleighError::Parse {
            message: format!("Sleigh source exceeds {MAX_SOURCE_BYTES} bytes"),
            offset: MAX_SOURCE_BYTES,
        });
    }
    let tokens: Vec<Lexeme> = lex(source)?;
    let mut parser: Parser = Parser {
        index: 0,
        item_depth: 0,
        spec: SleighSpec::default(),
        tokens,
    };
    parser.parse_items(parser.tokens.len(), None)?;
    Ok(parser.spec)
}

impl Parser {
    fn parse_items(
        &mut self,
        end: usize,
        inherited_pattern: Option<PatternExpr>,
    ) -> Result<(), SleighError> {
        while self.index < end {
            if self.text_is("define") {
                self.parse_define(end)?;
            } else if self.text_is("attach") {
                self.parse_attachment(end)?;
            } else if self.text_is("macro") {
                self.skip_braced_item(end)?;
            } else if self.text_is("with") {
                self.parse_with(end, inherited_pattern.clone())?;
            } else if self.text_is(":") || self.identifier_followed_by_colon(end) {
                self.parse_constructor(end, inherited_pattern.clone())?;
            } else {
                return Self::parse_error(
                    &self.tokens[self.index..end],
                    "unsupported top-level Sleigh item",
                );
            }
        }
        Ok(())
    }

    fn parse_define(&mut self, end: usize) -> Result<(), SleighError> {
        let start: usize = self.index;
        let statement_end: usize = self.find_statement_end(start, end)?;
        let body: Vec<Lexeme> = self.tokens[start..statement_end].to_vec();
        let kind: &str = body.get(1).map_or("", |token: &Lexeme| token.text.as_str());
        match kind {
            "alignment" => self.parse_alignment(&body)?,
            "bitrange" => self.parse_bitrange(&body)?,
            "endian" => self.parse_endian(&body)?,
            "space" => self.parse_space(&body)?,
            "register" => self.parse_registers(&body)?,
            "token" => self.parse_token(&body)?,
            "context" => self.parse_context(&body)?,
            "pcodeop" => self.parse_pcodeop(&body)?,
            _ => return Self::parse_error(&body, "unsupported define declaration"),
        }
        self.index = statement_end.saturating_add(1);
        Ok(())
    }

    fn parse_alignment(&mut self, body: &[Lexeme]) -> Result<(), SleighError> {
        let alignment: u32 = value_after(body, "alignment")
            .and_then(parse_u64)
            .and_then(|value: u64| u32::try_from(value).ok())
            .filter(|value: &u32| *value > 0)
            .ok_or_else(|| SleighError::Parse {
                message: "alignment must be positive".to_owned(),
                offset: body.first().map_or(0, |token: &Lexeme| token.offset),
            })?;
        self.spec.alignment = Some(alignment);
        Ok(())
    }

    fn parse_bitrange(&mut self, body: &[Lexeme]) -> Result<(), SleighError> {
        let name: String = required_text(body, 2, "bitrange name")?;
        let register: String = required_text(body, 4, "bitrange register")?;
        if body.get(3).is_none_or(|token: &Lexeme| token.text != "=")
            || body.get(5).is_none_or(|token: &Lexeme| token.text != "[")
            || body.get(7).is_none_or(|token: &Lexeme| token.text != ",")
            || body.get(9).is_none_or(|token: &Lexeme| token.text != "]")
        {
            return Self::parse_error(body, "malformed bitrange declaration");
        }
        let bit_offset: u32 = body
            .get(6)
            .and_then(|token: &Lexeme| parse_u64(&token.text))
            .and_then(|value: u64| u32::try_from(value).ok())
            .ok_or_else(|| SleighError::Parse {
                message: "invalid bitrange offset".to_owned(),
                offset: body.first().map_or(0, |token: &Lexeme| token.offset),
            })?;
        let bit_size: u32 = body
            .get(8)
            .and_then(|token: &Lexeme| parse_u64(&token.text))
            .and_then(|value: u64| u32::try_from(value).ok())
            .filter(|value: &u32| *value > 0)
            .ok_or_else(|| SleighError::Parse {
                message: "invalid bitrange size".to_owned(),
                offset: body.first().map_or(0, |token: &Lexeme| token.offset),
            })?;
        let register_bits: u32 = self
            .spec
            .registers
            .iter()
            .find(|definition: &&RegisterDef| definition.name == register)
            .and_then(|definition: &RegisterDef| definition.size_bytes.checked_mul(8))
            .ok_or_else(|| SleighError::Parse {
                message: format!("undefined bitrange register {register}"),
                offset: body.first().map_or(0, |token: &Lexeme| token.offset),
            })?;
        let end: u32 = bit_offset
            .checked_add(bit_size)
            .ok_or_else(|| SleighError::Parse {
                message: "bitrange bounds overflow".to_owned(),
                offset: body.first().map_or(0, |token: &Lexeme| token.offset),
            })?;
        if end > register_bits {
            return Self::parse_error(body, "bitrange exceeds register width");
        }
        self.spec.bitranges.push(BitRangeDef {
            bit_offset,
            bit_size,
            name,
            register,
        });
        Ok(())
    }

    fn parse_endian(&mut self, body: &[Lexeme]) -> Result<(), SleighError> {
        if body.len() != 4 || body[2].text != "=" {
            return Self::parse_error(body, "invalid endian declaration");
        }
        self.spec.endian = match body[3].text.as_str() {
            "little" => Some(Endian::Little),
            "big" => Some(Endian::Big),
            _ => return Self::parse_error(body, "invalid endian declaration"),
        };
        Ok(())
    }

    fn parse_space(&mut self, body: &[Lexeme]) -> Result<(), SleighError> {
        let name: String = required_text(body, 2, "space name")?;
        let attributes: BTreeMap<String, String> = key_values(&body[3..]);
        let size_bytes: u32 = attributes
            .get("size")
            .and_then(|value: &String| parse_u64(value))
            .and_then(|value: u64| u32::try_from(value).ok())
            .filter(|value: &u32| *value > 0)
            .ok_or_else(|| SleighError::Parse {
                message: "space size must be positive".to_owned(),
                offset: body.first().map_or(0, |token: &Lexeme| token.offset),
            })?;
        self.spec.spaces.push(SpaceDef {
            attributes,
            name,
            size_bytes,
        });
        Ok(())
    }

    fn parse_registers(&mut self, body: &[Lexeme]) -> Result<(), SleighError> {
        let mut base_offset: Option<u64> = None;
        let mut size_bytes: Option<u32> = None;
        let mut index: usize = 2;
        while body.get(index).is_some_and(|token: &Lexeme| {
            token.kind == LexemeKind::Identifier
                && body
                    .get(index.saturating_add(1))
                    .is_some_and(|next: &Lexeme| next.text == "=")
        }) {
            let key: &str = body[index].text.as_str();
            let value: &Lexeme =
                body.get(index.saturating_add(2))
                    .ok_or_else(|| SleighError::Parse {
                        message: "missing register attribute value".to_owned(),
                        offset: body[index].offset,
                    })?;
            match key {
                "offset" if base_offset.is_none() => {
                    base_offset = parse_u64(&value.text);
                    if base_offset.is_none() {
                        return Self::parse_error(body, "invalid register offset");
                    }
                }
                "size" if size_bytes.is_none() => {
                    size_bytes = parse_u64(&value.text)
                        .and_then(|parsed: u64| u32::try_from(parsed).ok())
                        .filter(|parsed: &u32| *parsed > 0);
                    if size_bytes.is_none() {
                        return Self::parse_error(body, "register size must be positive");
                    }
                }
                "offset" | "size" => {
                    return Self::parse_error(body, "duplicate register attribute");
                }
                _ => return Self::parse_error(body, "unknown register attribute"),
            }
            index = index.saturating_add(3);
        }
        let base_offset: u64 = base_offset.ok_or_else(|| SleighError::Parse {
            message: "missing register offset".to_owned(),
            offset: body.first().map_or(0, |token: &Lexeme| token.offset),
        })?;
        let size_bytes: u32 = size_bytes.ok_or_else(|| SleighError::Parse {
            message: "missing register size".to_owned(),
            offset: body.first().map_or(0, |token: &Lexeme| token.offset),
        })?;
        let register_names: Vec<String> = if body
            .get(index)
            .is_some_and(|token: &Lexeme| token.text == "[")
        {
            if body.last().is_none_or(|token: &Lexeme| token.text != "]") {
                return Self::parse_error(body, "unterminated register list");
            }
            let names: &[Lexeme] = body
                .get(index.saturating_add(1)..body.len().saturating_sub(1))
                .unwrap_or_default();
            if names.is_empty()
                || names
                    .iter()
                    .any(|token: &Lexeme| token.kind != LexemeKind::Identifier)
            {
                return Self::parse_error(body, "invalid register list");
            }
            names
                .iter()
                .map(|token: &Lexeme| token.text.clone())
                .collect()
        } else {
            let Some(name) = body.get(index) else {
                return Self::parse_error(body, "missing register name");
            };
            if index.saturating_add(1) != body.len() || name.kind != LexemeKind::Identifier {
                return Self::parse_error(body, "invalid scalar register name");
            }
            vec![name.text.clone()]
        };
        for (position, name) in register_names.into_iter().enumerate() {
            if name == "_" {
                continue;
            }
            let position_u64: u64 = u64::try_from(position).unwrap_or(u64::MAX);
            let stride: u64 = u64::from(size_bytes);
            let Some(delta) = position_u64.checked_mul(stride) else {
                return Self::parse_error(body, "register offset overflow");
            };
            let Some(offset) = base_offset.checked_add(delta) else {
                return Self::parse_error(body, "register offset overflow");
            };
            self.spec.registers.push(RegisterDef {
                name,
                offset,
                size_bytes,
            });
        }
        Ok(())
    }

    fn parse_token(&mut self, body: &[Lexeme]) -> Result<(), SleighError> {
        let name: String = required_text(body, 2, "token name")?;
        if body.get(3).is_none_or(|token: &Lexeme| token.text != "(")
            || body.get(5).is_none_or(|token: &Lexeme| token.text != ")")
        {
            return Self::parse_error(body, "invalid token width declaration");
        }
        let bits: u32 = body
            .get(4)
            .and_then(|token: &Lexeme| parse_u64(&token.text))
            .and_then(|value: u64| u32::try_from(value).ok())
            .unwrap_or(0);
        if bits == 0 || !bits.is_multiple_of(8) {
            return Self::parse_error(body, "token width must be a positive byte multiple");
        }
        let mut index: usize = 6;
        let endian: Option<Endian> = if body
            .get(index)
            .is_some_and(|token: &Lexeme| token.text == "endian")
        {
            if body
                .get(index.saturating_add(1))
                .is_none_or(|token: &Lexeme| token.text != "=")
            {
                return Self::parse_error(body, "invalid token endian");
            }
            let parsed: Endian = match body
                .get(index.saturating_add(2))
                .map(|token: &Lexeme| token.text.as_str())
            {
                Some("little") => Endian::Little,
                Some("big") => Endian::Big,
                _ => return Self::parse_error(body, "invalid token endian"),
            };
            index = index.saturating_add(3);
            Some(parsed)
        } else {
            None
        };
        let mut fields: Vec<FieldDef> = Vec::new();
        while index < body.len() {
            let (field, consumed): (FieldDef, usize) = parse_field_at(body, index)?;
            fields.push(field);
            index = index.saturating_add(consumed);
        }
        if fields
            .iter()
            .any(|field: &FieldDef| u32::from(field.high_bit) >= bits)
        {
            return Self::parse_error(body, "token field exceeds token width");
        }
        self.spec.tokens.push(TokenDef {
            bits,
            endian,
            fields,
            name,
        });
        Ok(())
    }

    fn parse_context(&mut self, body: &[Lexeme]) -> Result<(), SleighError> {
        let register: String = required_text(body, 2, "context register")?;
        let fields: Vec<FieldDef> = parse_fields(body)?;
        let register_bits: u32 = self
            .spec
            .registers
            .iter()
            .find(|definition: &&RegisterDef| definition.name == register)
            .and_then(|definition: &RegisterDef| definition.size_bytes.checked_mul(8))
            .ok_or_else(|| SleighError::Parse {
                message: format!("undefined context register {register}"),
                offset: body.first().map_or(0, |token: &Lexeme| token.offset),
            })?;
        if fields
            .iter()
            .any(|field: &FieldDef| u32::from(field.high_bit) >= register_bits)
        {
            return Self::parse_error(body, "context field exceeds register width");
        }
        for field in fields {
            let noflow: bool = field_attribute(body, &field.name, "noflow");
            self.spec.contexts.push(ContextDef {
                high_bit: field.high_bit,
                low_bit: field.low_bit,
                name: field.name,
                noflow,
                register: register.clone(),
            });
        }
        Ok(())
    }

    fn parse_pcodeop(&mut self, body: &[Lexeme]) -> Result<(), SleighError> {
        let name: String = required_text(body, 2, "pcodeop name")?;
        self.spec.pcodeops.insert(name);
        Ok(())
    }

    fn parse_attachment(&mut self, end: usize) -> Result<(), SleighError> {
        let start: usize = self.index;
        let statement_end: usize = self.find_statement_end(start, end)?;
        let body: &[Lexeme] = &self.tokens[start..statement_end];
        let kind: AttachmentKind = match body.get(1).map(|token: &Lexeme| token.text.as_str()) {
            Some("variables") => AttachmentKind::Variables,
            Some("names") => AttachmentKind::Names,
            Some("values") => AttachmentKind::Values,
            _ => return Self::parse_error(body, "invalid attachment kind"),
        };
        let lists: Vec<Vec<Lexeme>> = all_bracket_items(body);
        let fields: Vec<String> = lists.first().map_or_else(
            || {
                body.get(2)
                    .filter(|token: &&Lexeme| token.kind == LexemeKind::Identifier)
                    .map(|token: &Lexeme| vec![token.text.clone()])
                    .unwrap_or_default()
            },
            |first: &Vec<Lexeme>| {
                first
                    .iter()
                    .filter(|token: &&Lexeme| token.kind == LexemeKind::Identifier)
                    .map(|token: &Lexeme| token.text.clone())
                    .collect()
            },
        );
        let value_tokens: Vec<Lexeme> = lists.get(1).cloned().unwrap_or_default();
        let mut values: Vec<AttachmentValue> = Vec::new();
        let mut value_index: usize = 0;
        while value_index < value_tokens.len() {
            let token: &Lexeme = &value_tokens[value_index];
            if token.text == "-" && value_index.saturating_add(1) < value_tokens.len() {
                let next: &Lexeme = &value_tokens[value_index.saturating_add(1)];
                if let Some(value) = parse_i64(&format!("-{}", next.text)) {
                    values.push(AttachmentValue::Integer(value));
                    value_index = value_index.saturating_add(2);
                    continue;
                }
            }
            match token.kind {
                LexemeKind::String => values.push(AttachmentValue::Name(token.text.clone())),
                LexemeKind::Number => {
                    if let Some(value) = parse_i64(&token.text) {
                        values.push(AttachmentValue::Integer(value));
                    }
                }
                LexemeKind::Identifier => {
                    values.push(AttachmentValue::Identifier(token.text.clone()));
                }
                LexemeKind::Symbol => {}
            }
            value_index = value_index.saturating_add(1);
        }
        self.spec.attachments.push(Attachment {
            fields,
            kind,
            values,
        });
        self.index = statement_end.saturating_add(1);
        Ok(())
    }

    fn parse_with(
        &mut self,
        end: usize,
        inherited_pattern: Option<PatternExpr>,
    ) -> Result<(), SleighError> {
        let start: usize = self.index;
        let Some(open) = self.find_text(start, end, "{") else {
            return Self::parse_error(&self.tokens[start..end], "with block has no body");
        };
        let close: usize = self.matching_delimiter(open, end, "{", "}")?;
        let header: &[Lexeme] = &self.tokens[start.saturating_add(1)..open];
        let pattern_start: usize = header
            .iter()
            .position(|token: &Lexeme| token.text == ":" || token.text == "is")
            .map_or(0, |position: usize| position.saturating_add(1));
        let local_pattern: PatternExpr = parse_pattern(&header[pattern_start..]);
        let combined: PatternExpr = combine_patterns(inherited_pattern, local_pattern);
        if self.item_depth >= MAX_ITEM_DEPTH {
            return Self::parse_error(&self.tokens[start..end], "with nesting limit exceeded");
        }
        self.index = open.saturating_add(1);
        self.item_depth = self.item_depth.saturating_add(1);
        let parse_result: Result<(), SleighError> = self.parse_items(close, Some(combined));
        self.item_depth = self.item_depth.saturating_sub(1);
        parse_result?;
        self.index = close.saturating_add(1);
        Ok(())
    }

    fn parse_constructor(
        &mut self,
        end: usize,
        inherited_pattern: Option<PatternExpr>,
    ) -> Result<(), SleighError> {
        let source_order: usize = self.spec.constructors.len();
        let table: String = if self.text_is(":") {
            self.index = self.index.saturating_add(1);
            "instruction".to_owned()
        } else {
            let name: String = self.tokens[self.index].text.clone();
            self.index = self.index.saturating_add(2);
            name
        };
        let display_start: usize = self.index;
        let Some(is_position) = self.find_text(display_start, end, "is") else {
            return Self::parse_error(
                &self.tokens[display_start..end],
                "constructor has no pattern separator",
            );
        };
        let display: Vec<Lexeme> = self.tokens[display_start..is_position].to_vec();
        let pattern_start: usize = is_position.saturating_add(1);
        let mut delimiter: usize = pattern_start;
        let mut paren_depth: usize = 0;
        while delimiter < end {
            let text: &str = &self.tokens[delimiter].text;
            if text == "(" {
                paren_depth = paren_depth.saturating_add(1);
            } else if text == ")" {
                paren_depth = paren_depth.saturating_sub(1);
            } else if paren_depth == 0 && matches!(text, "[" | "{" | "unimpl") {
                break;
            }
            delimiter = delimiter.saturating_add(1);
        }
        if delimiter >= end {
            return Self::parse_error(
                &self.tokens[pattern_start..end],
                "constructor has no semantic section",
            );
        }
        let own_pattern: PatternExpr = parse_pattern(&self.tokens[pattern_start..delimiter]);
        let pattern: PatternExpr = combine_patterns(inherited_pattern, own_pattern);
        let mut context_tokens: Vec<String> = Vec::new();
        if self.tokens[delimiter].text == "[" {
            let close: usize = self.matching_delimiter(delimiter, end, "[", "]")?;
            context_tokens = token_texts(&self.tokens[delimiter.saturating_add(1)..close]);
            delimiter = close.saturating_add(1);
        }
        let mut semantic_tokens: Vec<String> = Vec::new();
        let mut unimplemented: bool = false;
        if delimiter < end && self.tokens[delimiter].text == "{" {
            let close: usize = self.matching_delimiter(delimiter, end, "{", "}")?;
            semantic_tokens = token_texts(&self.tokens[delimiter.saturating_add(1)..close]);
            self.index = close.saturating_add(1);
        } else if delimiter < end && self.tokens[delimiter].text == "unimpl" {
            unimplemented = true;
            self.index = delimiter.saturating_add(1);
        } else {
            return Self::parse_error(
                &self.tokens[delimiter..end],
                "constructor semantic section is malformed",
            );
        }
        let display_tokens: Vec<DisplayToken> = display.iter().map(display_token).collect();
        let mnemonic: String = display
            .first()
            .map_or_else(String::new, |token: &Lexeme| token.text.clone());
        self.spec.constructors.push(Constructor {
            context_tokens,
            display_tokens,
            mnemonic,
            pattern,
            semantic_tokens,
            source_order,
            table,
            unimplemented,
        });
        Ok(())
    }

    fn skip_braced_item(&mut self, end: usize) -> Result<(), SleighError> {
        let start: usize = self.index;
        let Some(open) = self.find_text(start, end, "{") else {
            return Self::parse_error(&self.tokens[start..end], "braced item has no body");
        };
        let close: usize = self.matching_delimiter(open, end, "{", "}")?;
        self.index = close.saturating_add(1);
        Ok(())
    }

    fn find_statement_end(&self, start: usize, end: usize) -> Result<usize, SleighError> {
        let Some(position) = self.find_text(start, end, ";") else {
            return Self::parse_error(&self.tokens[start..end], "statement has no terminator");
        };
        Ok(position)
    }

    fn find_text(&self, start: usize, end: usize, text: &str) -> Option<usize> {
        self.tokens[start..end]
            .iter()
            .position(|token: &Lexeme| token.text == text)
            .map(|relative: usize| start.saturating_add(relative))
    }

    fn matching_delimiter(
        &self,
        open: usize,
        end: usize,
        open_text: &str,
        close_text: &str,
    ) -> Result<usize, SleighError> {
        let mut depth: usize = 0;
        for position in open..end {
            let text: &str = &self.tokens[position].text;
            if text == open_text {
                depth = depth.saturating_add(1);
            } else if text == close_text {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(position);
                }
            }
        }
        Self::parse_error(&self.tokens[open..end], "unbalanced delimiter")
    }

    fn identifier_followed_by_colon(&self, end: usize) -> bool {
        self.index.saturating_add(1) < end
            && self.tokens[self.index].kind == LexemeKind::Identifier
            && self.tokens[self.index.saturating_add(1)].text == ":"
    }

    fn text_is(&self, text: &str) -> bool {
        self.tokens
            .get(self.index)
            .is_some_and(|token: &Lexeme| token.text == text)
    }

    fn parse_error<T>(body: &[Lexeme], message: &str) -> Result<T, SleighError> {
        let offset: usize = body.first().map_or(0, |token: &Lexeme| token.offset);
        Err(SleighError::Parse {
            message: message.to_owned(),
            offset,
        })
    }
}

fn lex(source: &str) -> Result<Vec<Lexeme>, SleighError> {
    if let Some(offset) = source.bytes().position(|byte: u8| !byte.is_ascii()) {
        return Err(SleighError::Parse {
            message: "non-ASCII Sleigh source".to_owned(),
            offset,
        });
    }
    let bytes: &[u8] = source.as_bytes();
    let mut tokens: Vec<Lexeme> = Vec::new();
    let mut index: usize = 0;
    while index < bytes.len() {
        let byte: u8 = bytes[index];
        if byte.is_ascii_whitespace() {
            index = index.saturating_add(1);
            continue;
        }
        if byte == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                index = index.saturating_add(1);
            }
            continue;
        }
        if byte == b'"' {
            let start: usize = index;
            index = index.saturating_add(1);
            let content_start: usize = index;
            while index < bytes.len() && bytes[index] != b'"' {
                index = index.saturating_add(1);
            }
            if index >= bytes.len() {
                return Err(SleighError::Parse {
                    message: "unterminated string".to_owned(),
                    offset: start,
                });
            }
            let text: String = source[content_start..index].to_owned();
            push_lexeme(
                &mut tokens,
                Lexeme {
                    kind: LexemeKind::String,
                    offset: start,
                    text,
                },
            )?;
            index = index.saturating_add(1);
            continue;
        }
        if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'.' | b'$') {
            let start: usize = index;
            index = index.saturating_add(1);
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || matches!(bytes[index], b'_' | b'.' | b'$'))
            {
                index = index.saturating_add(1);
            }
            push_lexeme(
                &mut tokens,
                Lexeme {
                    kind: LexemeKind::Identifier,
                    offset: start,
                    text: source[start..index].to_owned(),
                },
            )?;
            continue;
        }
        if byte.is_ascii_digit() {
            let start: usize = index;
            if source[index..].starts_with("0x") || source[index..].starts_with("0X") {
                index = index.saturating_add(2);
                while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                    index = index.saturating_add(1);
                }
            } else if source[index..].starts_with("0b") || source[index..].starts_with("0B") {
                index = index.saturating_add(2);
                while index < bytes.len() && matches!(bytes[index], b'0' | b'1') {
                    index = index.saturating_add(1);
                }
            } else {
                index = index.saturating_add(1);
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index = index.saturating_add(1);
                }
            }
            push_lexeme(
                &mut tokens,
                Lexeme {
                    kind: LexemeKind::Number,
                    offset: start,
                    text: source[start..index].to_owned(),
                },
            )?;
            continue;
        }
        let start: usize = index;
        let remaining: &str = &source[index..];
        let symbol: &str = ["s<=", "s>=", "==", "!=", "<=", ">=", "<<", ">>", "s<", "s>"]
            .into_iter()
            .find(|candidate: &&str| remaining.starts_with(*candidate))
            .unwrap_or_else(|| &source[index..index.saturating_add(1)]);
        index = index.saturating_add(symbol.len());
        push_lexeme(
            &mut tokens,
            Lexeme {
                kind: LexemeKind::Symbol,
                offset: start,
                text: symbol.to_owned(),
            },
        )?;
    }
    Ok(tokens)
}

fn push_lexeme(tokens: &mut Vec<Lexeme>, lexeme: Lexeme) -> Result<(), SleighError> {
    if tokens.len() >= MAX_TOKEN_COUNT {
        return Err(SleighError::Parse {
            message: format!("Sleigh token count exceeds {MAX_TOKEN_COUNT}"),
            offset: lexeme.offset,
        });
    }
    tokens.push(lexeme);
    Ok(())
}

fn required_text(body: &[Lexeme], index: usize, description: &str) -> Result<String, SleighError> {
    body.get(index)
        .filter(|token: &&Lexeme| token.kind == LexemeKind::Identifier)
        .map(|token: &Lexeme| token.text.clone())
        .ok_or_else(|| SleighError::Parse {
            message: format!("missing {description}"),
            offset: body.first().map_or(0, |token: &Lexeme| token.offset),
        })
}

fn key_values(body: &[Lexeme]) -> BTreeMap<String, String> {
    let mut attributes: BTreeMap<String, String> = BTreeMap::new();
    for window in body.windows(3) {
        if window[0].kind == LexemeKind::Identifier && window[1].text == "=" {
            attributes.insert(window[0].text.clone(), window[2].text.clone());
        }
    }
    attributes
}

fn value_after<'a>(body: &'a [Lexeme], key: &str) -> Option<&'a str> {
    body.windows(3)
        .find(|window: &&[Lexeme]| window[0].text == key && window[1].text == "=")
        .map(|window: &[Lexeme]| window[2].text.as_str())
}

fn all_bracket_items(body: &[Lexeme]) -> Vec<Vec<Lexeme>> {
    let mut lists: Vec<Vec<Lexeme>> = Vec::new();
    let mut index: usize = 0;
    while index < body.len() {
        if body[index].text != "[" {
            index = index.saturating_add(1);
            continue;
        }
        let start: usize = index.saturating_add(1);
        let mut depth: usize = 1;
        index = index.saturating_add(1);
        while index < body.len() && depth > 0 {
            if body[index].text == "[" {
                depth = depth.saturating_add(1);
            } else if body[index].text == "]" {
                depth = depth.saturating_sub(1);
            }
            if depth > 0 {
                index = index.saturating_add(1);
            }
        }
        if depth == 0 {
            lists.push(body[start..index].to_vec());
        }
        index = index.saturating_add(1);
    }
    lists
}

fn parse_fields(body: &[Lexeme]) -> Result<Vec<FieldDef>, SleighError> {
    let mut fields: Vec<FieldDef> = Vec::new();
    let mut index: usize = 0;
    let mut bracket_depth: usize = 0;
    while index < body.len() {
        if body[index].text == "[" {
            bracket_depth = bracket_depth.saturating_add(1);
            index = index.saturating_add(1);
            continue;
        }
        if body[index].text == "]" {
            bracket_depth = bracket_depth.saturating_sub(1);
            index = index.saturating_add(1);
            continue;
        }
        let starts_field: bool = bracket_depth == 0
            && body[index].kind == LexemeKind::Identifier
            && body
                .get(index.saturating_add(1))
                .is_some_and(|token: &Lexeme| token.text == "=")
            && body
                .get(index.saturating_add(2))
                .is_some_and(|token: &Lexeme| token.text == "(");
        if !starts_field {
            index = index.saturating_add(1);
            continue;
        }
        let (field, consumed): (FieldDef, usize) = parse_field_at(body, index)?;
        fields.push(field);
        index = index.saturating_add(consumed);
    }
    Ok(fields)
}

fn parse_field_at(body: &[Lexeme], index: usize) -> Result<(FieldDef, usize), SleighError> {
    let field: &Lexeme = body.get(index).ok_or_else(|| SleighError::Parse {
        message: "missing field declaration".to_owned(),
        offset: body.first().map_or(0, |token: &Lexeme| token.offset),
    })?;
    if field.kind != LexemeKind::Identifier
        || body
            .get(index.saturating_add(1))
            .is_none_or(|token: &Lexeme| token.text != "=")
        || body
            .get(index.saturating_add(2))
            .is_none_or(|token: &Lexeme| token.text != "(")
        || body
            .get(index.saturating_add(4))
            .is_none_or(|token: &Lexeme| token.text != ",")
        || body
            .get(index.saturating_add(6))
            .is_none_or(|token: &Lexeme| token.text != ")")
    {
        return Err(SleighError::Parse {
            message: "invalid field declaration".to_owned(),
            offset: field.offset,
        });
    }
    let low: u64 = body
        .get(index.saturating_add(3))
        .and_then(|token: &Lexeme| parse_u64(&token.text))
        .ok_or_else(|| SleighError::Parse {
            message: "invalid field low bit".to_owned(),
            offset: field.offset,
        })?;
    let high: u64 = body
        .get(index.saturating_add(5))
        .and_then(|token: &Lexeme| parse_u64(&token.text))
        .ok_or_else(|| SleighError::Parse {
            message: "invalid field high bit".to_owned(),
            offset: field.offset,
        })?;
    let low_bit: u8 = u8::try_from(low).map_err(|_| SleighError::Parse {
        message: "field bit exceeds 255".to_owned(),
        offset: field.offset,
    })?;
    let high_bit: u8 = u8::try_from(high).map_err(|_| SleighError::Parse {
        message: "field bit exceeds 255".to_owned(),
        offset: field.offset,
    })?;
    if high_bit < low_bit {
        return Err(SleighError::Parse {
            message: "field high bit is below low bit".to_owned(),
            offset: field.offset,
        });
    }
    let signed: bool = body
        .get(index.saturating_add(7))
        .is_some_and(|token: &Lexeme| token.text == "signed");
    let consumed: usize = if signed { 8 } else { 7 };
    Ok((
        FieldDef {
            high_bit,
            low_bit,
            name: field.text.clone(),
            signed,
        },
        consumed,
    ))
}

fn field_attribute(body: &[Lexeme], field: &str, attribute: &str) -> bool {
    let Some(position) = body.iter().position(|token: &Lexeme| token.text == field) else {
        return false;
    };
    body[position..]
        .iter()
        .take_while(|token: &&Lexeme| token.text != ";")
        .any(|token: &Lexeme| token.text == attribute)
}

fn parse_pattern(tokens: &[Lexeme]) -> PatternExpr {
    if pattern_nesting_exceeds(tokens) {
        return PatternExpr::Atom(PatternAtom::Residual(token_texts(tokens).join(" ")));
    }
    let stripped: &[Lexeme] = strip_outer_parentheses(tokens);
    if stripped.is_empty() {
        return PatternExpr::True;
    }
    if stripped.len() == 1 && stripped[0].text == "epsilon" {
        return PatternExpr::True;
    }
    if let Some(parts) = split_top_level(stripped, ";") {
        let mut expressions: Vec<PatternExpr> = parts.into_iter().map(parse_pattern).collect();
        let first: PatternExpr = expressions.remove(0);
        return expressions
            .into_iter()
            .fold(first, |left: PatternExpr, right: PatternExpr| {
                PatternExpr::Next(Box::new(left), Box::new(right))
            });
    }
    if let Some(parts) = split_top_level(stripped, "|") {
        return PatternExpr::Any(parts.into_iter().map(parse_pattern).collect());
    }
    if let Some(parts) = split_top_level(stripped, "&") {
        return PatternExpr::All(parts.into_iter().map(parse_pattern).collect());
    }
    PatternExpr::Atom(parse_pattern_atom(stripped))
}

fn pattern_nesting_exceeds(tokens: &[Lexeme]) -> bool {
    let mut depth: usize = 0;
    for token in tokens {
        if token.text == "(" {
            depth = depth.saturating_add(1);
            if depth > MAX_PATTERN_NESTING {
                return true;
            }
        } else if token.text == ")" {
            depth = depth.saturating_sub(1);
        }
    }
    false
}

fn parse_pattern_atom(tokens: &[Lexeme]) -> PatternAtom {
    let stripped: &[Lexeme] = strip_outer_parentheses(tokens);
    if stripped.len() == 1 && stripped[0].kind == LexemeKind::Identifier {
        return PatternAtom::Symbol(stripped[0].text.clone());
    }
    if stripped.len() >= 3 && stripped[0].kind == LexemeKind::Identifier {
        let op: Option<CompareOp> = match stripped[1].text.as_str() {
            "=" | "==" => Some(CompareOp::Equal),
            "!=" => Some(CompareOp::NotEqual),
            "<" => Some(CompareOp::Less),
            "<=" => Some(CompareOp::LessEqual),
            ">" => Some(CompareOp::Greater),
            ">=" => Some(CompareOp::GreaterEqual),
            _ => None,
        };
        if let Some(operator) = op {
            let right: PatternValue = if stripped[2].kind == LexemeKind::Identifier
                && stripped.len() == 5
                && stripped[3].text == "+"
            {
                parse_i64(&stripped[4].text).map_or_else(
                    || PatternValue::Identifier(stripped[2].text.clone()),
                    |amount: i64| PatternValue::Add {
                        identifier: stripped[2].text.clone(),
                        amount,
                    },
                )
            } else if stripped[2].kind == LexemeKind::Number && stripped.len() == 3 {
                parse_i64(&stripped[2].text).map_or_else(
                    || PatternValue::Identifier(stripped[2].text.clone()),
                    PatternValue::Integer,
                )
            } else if stripped[2].text == "-" && stripped.len() == 4 {
                parse_i64(&format!("-{}", stripped[3].text)).map_or_else(
                    || PatternValue::Identifier(token_texts(stripped).join("")),
                    PatternValue::Integer,
                )
            } else if stripped.len() == 3 {
                PatternValue::Identifier(stripped[2].text.clone())
            } else {
                return PatternAtom::Residual(token_texts(stripped).join(" "));
            };
            return PatternAtom::Compare {
                left: stripped[0].text.clone(),
                op: operator,
                right,
            };
        }
    }
    PatternAtom::Residual(token_texts(stripped).join(" "))
}

fn strip_outer_parentheses(mut tokens: &[Lexeme]) -> &[Lexeme] {
    loop {
        if tokens.len() < 2 || tokens[0].text != "(" || tokens[tokens.len() - 1].text != ")" {
            return tokens;
        }
        let mut depth: usize = 0;
        let mut encloses_all: bool = true;
        for (position, token) in tokens.iter().enumerate() {
            if token.text == "(" {
                depth = depth.saturating_add(1);
            } else if token.text == ")" {
                depth = depth.saturating_sub(1);
                if depth == 0 && position != tokens.len() - 1 {
                    encloses_all = false;
                    break;
                }
            }
        }
        if !encloses_all {
            return tokens;
        }
        tokens = &tokens[1..tokens.len() - 1];
    }
}

fn split_top_level<'a>(tokens: &'a [Lexeme], operator: &str) -> Option<Vec<&'a [Lexeme]>> {
    let mut depth: usize = 0;
    let mut start: usize = 0;
    let mut parts: Vec<&[Lexeme]> = Vec::new();
    for (position, token) in tokens.iter().enumerate() {
        if token.text == "(" {
            depth = depth.saturating_add(1);
        } else if token.text == ")" {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && token.text == operator {
            parts.push(&tokens[start..position]);
            start = position.saturating_add(1);
        }
    }
    if parts.is_empty() {
        return None;
    }
    parts.push(&tokens[start..]);
    Some(parts)
}

fn combine_patterns(inherited: Option<PatternExpr>, local: PatternExpr) -> PatternExpr {
    if let Some(parent) = inherited {
        PatternExpr::All(vec![parent, local])
    } else {
        local
    }
}

fn display_token(token: &Lexeme) -> DisplayToken {
    match token.kind {
        LexemeKind::Identifier => DisplayToken::Symbol(token.text.clone()),
        LexemeKind::Symbol if token.text == "^" => DisplayToken::Concatenate,
        LexemeKind::Number | LexemeKind::String | LexemeKind::Symbol => {
            DisplayToken::Literal(token.text.clone())
        }
    }
}

fn token_texts(tokens: &[Lexeme]) -> Vec<String> {
    tokens
        .iter()
        .map(|token: &Lexeme| token.text.clone())
        .collect()
}

fn parse_u64(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || {
                value
                    .strip_prefix("0b")
                    .or_else(|| value.strip_prefix("0B"))
                    .map_or_else(
                        || value.parse::<u64>().ok(),
                        |binary: &str| u64::from_str_radix(binary, 2).ok(),
                    )
            },
            |hex: &str| u64::from_str_radix(hex, 16).ok(),
        )
}

fn parse_i64(value: &str) -> Option<i64> {
    value.strip_prefix('-').map_or_else(
        || parse_u64(value).and_then(|number: u64| i64::try_from(number).ok()),
        |negative: &str| {
            parse_u64(negative).and_then(|number: u64| i64::try_from(number).ok()?.checked_neg())
        },
    )
}
