use crate::egraph::RingOp;
use crate::expr::UnOp;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::OnceLock;
use thiserror::Error;

const MAX_RULE_FILE_BYTES: usize = 128 * 1024;
const MAX_RULES: usize = 256;
const MAX_RULE_NAME_BYTES: usize = 128;
const MAX_PROVENANCE_BYTES: usize = 256;
const MAX_TERM_BYTES: usize = 512;
const MAX_TERM_NODES: usize = 64;
const MAX_TERM_DEPTH: usize = 16;
pub(crate) const MAX_RULE_CAPTURES: usize = 8;

pub(crate) const MBA_EGRAPH_RULES: &str = include_str!("rules_data/mba_egraph.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Pattern,
    Rewrite,
}

impl fmt::Display for Side {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text: &str = match self {
            Self::Pattern => "pattern",
            Self::Rewrite => "rewrite",
        };
        formatter.write_str(text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum TermError {
    #[error("term text is {bytes} bytes, above the {max} byte cap")]
    TooLong { bytes: usize, max: usize },
    #[error("term text is empty")]
    Empty,
    #[error("byte {byte:?} at offset {offset} is not part of the term grammar")]
    UnexpectedByte { byte: char, offset: usize },
    #[error("closing parenthesis at offset {offset} has no opening parenthesis")]
    Unbalanced { offset: usize },
    #[error("term ends inside an unclosed list")]
    Unclosed,
    #[error("text after the first term starts at offset {offset}")]
    Trailing { offset: usize },
    #[error("symbol {symbol:?} is not part of the term grammar")]
    UnknownSymbol { symbol: String },
    #[error("operator {operator:?} is not carried by the e-node language")]
    UnsupportedOperator { operator: String },
    #[error("operator {operator:?} takes {expected} operands but was given {found}")]
    Arity {
        operator: String,
        expected: usize,
        found: usize,
    },
    #[error("a list must start with an operator symbol, not {found:?}")]
    MissingOperator { found: String },
    #[error("integer literal {literal:?} does not fit a 64 bit constant")]
    BadInteger { literal: String },
    #[error("capture name {name:?} is empty or contains an unsupported byte")]
    BadCapture { name: String },
    #[error("term nests deeper than the {max} level cap")]
    TooDeep { max: usize },
    #[error("term has more than the {max} node cap")]
    TooManyNodes { max: usize },
}

#[derive(Debug, Error)]
pub(crate) enum EgraphRuleError {
    #[error("e-graph rule file is not valid toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("e-graph rule file is {bytes} bytes, above the {max} byte cap")]
    TooLarge { bytes: usize, max: usize },
    #[error("e-graph rule file declares no rules")]
    Empty,
    #[error("e-graph rule file declares {count} rules, above the {max} rule cap")]
    TooManyRules { count: usize, max: usize },
    #[error("e-graph rule name {rule:?} is empty or contains an unsupported byte")]
    InvalidRuleName { rule: String },
    #[error("e-graph rule name {rule:?} is {bytes} bytes, above the {max} byte cap")]
    RuleNameTooLong {
        rule: String,
        bytes: usize,
        max: usize,
    },
    #[error("e-graph rule {rule:?} has a duplicate name")]
    DuplicateRuleName { rule: String },
    #[error("e-graph rule {rule:?} records no provenance")]
    MissingProvenance { rule: String },
    #[error("e-graph rule {rule:?} provenance is {bytes} bytes, above the {max} byte cap")]
    ProvenanceTooLong {
        rule: String,
        bytes: usize,
        max: usize,
    },
    #[error("e-graph rule {rule:?} {side} side is malformed: {source}")]
    Malformed {
        rule: String,
        side: Side,
        #[source]
        source: TermError,
    },
    #[error("e-graph rule {rule:?} {side} side is a bare atom, which matches every e-class")]
    AtomPattern { rule: String, side: Side },
    #[error("e-graph rule {rule:?} uses capture {capture:?} that its {side} side never binds")]
    UnboundCapture {
        rule: String,
        side: Side,
        capture: String,
    },
    #[error("e-graph rule {rule:?} binds {count} captures, above the {max} capture cap")]
    TooManyCaptures {
        rule: String,
        count: usize,
        max: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Term {
    Capture(String),
    Const(u64),
    AllOnes,
    Unary(UnOp, Box<Self>),
    Binary(RingOp, Box<Self>, Box<Self>),
}

impl Term {
    pub(crate) const fn is_atom(&self) -> bool {
        matches!(self, Self::Capture(_) | Self::Const(_) | Self::AllOnes)
    }

    fn collect_captures<'term>(&'term self, into: &mut Vec<&'term str>) {
        match self {
            Self::Capture(name) => {
                let known: &str = name.as_str();
                if !into.contains(&known) {
                    into.push(known);
                }
            }
            Self::Const(_) | Self::AllOnes => {}
            Self::Unary(_, inner) => inner.collect_captures(into),
            Self::Binary(_, left, right) => {
                left.collect_captures(into);
                right.collect_captures(into);
            }
        }
    }

    pub(crate) fn captures(&self) -> Vec<&str> {
        let mut names: Vec<&str> = Vec::new();
        self.collect_captures(&mut names);
        names
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    Contract,
    Bidirectional,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    name: String,
    provenance: String,
    direction: Direction,
    pattern: String,
    rewrite: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuleSet {
    rules: Vec<RawRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgraphRule {
    pub(crate) name: String,
    pub(crate) provenance: String,
    pub(crate) direction: Direction,
    pub(crate) pattern: Term,
    pub(crate) rewrite: Term,
    pub(crate) captures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgraphRuleSet {
    pub(crate) rules: Vec<EgraphRule>,
}

impl EgraphRuleSet {
    pub(crate) fn directed_pairs(&self) -> Vec<(&EgraphRule, &Term, &Term)> {
        let mut pairs: Vec<(&EgraphRule, &Term, &Term)> = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            pairs.push((rule, &rule.pattern, &rule.rewrite));
            if rule.direction == Direction::Bidirectional {
                pairs.push((rule, &rule.rewrite, &rule.pattern));
            }
        }
        pairs
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Open(usize),
    Close(usize),
    Atom(usize, String),
}

fn tokenize(text: &str) -> Result<Vec<Token>, TermError> {
    let bytes: usize = text.len();
    if bytes > MAX_TERM_BYTES {
        return Err(TermError::TooLong {
            bytes,
            max: MAX_TERM_BYTES,
        });
    }
    let mut tokens: Vec<Token> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (offset, character) in text.char_indices() {
        match character {
            '(' | ')' => {
                if let Some((start, symbol)) = pending.take() {
                    tokens.push(Token::Atom(start, symbol));
                }
                tokens.push(if character == '(' {
                    Token::Open(offset)
                } else {
                    Token::Close(offset)
                });
            }
            ' ' | '\t' | '\n' | '\r' => {
                if let Some((start, symbol)) = pending.take() {
                    tokens.push(Token::Atom(start, symbol));
                }
            }
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '?' => match pending.as_mut() {
                Some((_, symbol)) => symbol.push(character),
                None => pending = Some((offset, String::from(character))),
            },
            other => {
                return Err(TermError::UnexpectedByte {
                    byte: other,
                    offset,
                });
            }
        }
    }
    if let Some((start, symbol)) = pending.take() {
        tokens.push(Token::Atom(start, symbol));
    }
    if tokens.is_empty() {
        return Err(TermError::Empty);
    }
    Ok(tokens)
}

struct Parser<'tokens> {
    tokens: &'tokens [Token],
    index: usize,
    nodes: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn advance(&mut self) -> Option<&Token> {
        let token: Option<&Token> = self.tokens.get(self.index);
        if token.is_some() {
            self.index += 1;
        }
        token
    }

    const fn charge(&mut self) -> Result<(), TermError> {
        self.nodes += 1;
        if self.nodes > MAX_TERM_NODES {
            return Err(TermError::TooManyNodes {
                max: MAX_TERM_NODES,
            });
        }
        Ok(())
    }

    fn parse(&mut self, depth: usize) -> Result<Term, TermError> {
        if depth > MAX_TERM_DEPTH {
            return Err(TermError::TooDeep {
                max: MAX_TERM_DEPTH,
            });
        }
        self.charge()?;
        let Some(token): Option<&Token> = self.advance() else {
            return Err(TermError::Unclosed);
        };
        match token {
            Token::Close(offset) => Err(TermError::Unbalanced { offset: *offset }),
            Token::Atom(_, symbol) => parse_atom(symbol),
            Token::Open(_) => self.parse_list(depth),
        }
    }

    fn parse_list(&mut self, depth: usize) -> Result<Term, TermError> {
        let operator: String = match self.advance() {
            Some(Token::Atom(_, symbol)) => symbol.clone(),
            Some(Token::Open(_)) => {
                return Err(TermError::MissingOperator {
                    found: String::from("("),
                });
            }
            Some(Token::Close(_)) => {
                return Err(TermError::MissingOperator {
                    found: String::from(")"),
                });
            }
            None => return Err(TermError::Unclosed),
        };
        let mut operands: Vec<Term> = Vec::new();
        loop {
            match self.peek() {
                Some(Token::Close(_)) => {
                    self.index += 1;
                    break;
                }
                Some(_) => operands.push(self.parse(depth + 1)?),
                None => return Err(TermError::Unclosed),
            }
        }
        build_application(&operator, operands)
    }
}

fn build_application(operator: &str, operands: Vec<Term>) -> Result<Term, TermError> {
    if let Some(op) = unary_operator(operator) {
        let mut iterator: std::vec::IntoIter<Term> = operands.into_iter();
        let Some(operand): Option<Term> = iterator.next() else {
            return Err(TermError::Arity {
                operator: operator.to_owned(),
                expected: 1,
                found: 0,
            });
        };
        let extra: usize = iterator.count();
        if extra > 0 {
            return Err(TermError::Arity {
                operator: operator.to_owned(),
                expected: 1,
                found: 1 + extra,
            });
        }
        return Ok(Term::Unary(op, Box::new(operand)));
    }
    if let Some(op) = RingOp::from_symbol(operator) {
        let found: usize = operands.len();
        let mut iterator: std::vec::IntoIter<Term> = operands.into_iter();
        let (Some(left), Some(right)): (Option<Term>, Option<Term>) =
            (iterator.next(), iterator.next())
        else {
            return Err(TermError::Arity {
                operator: operator.to_owned(),
                expected: 2,
                found,
            });
        };
        if iterator.next().is_some() {
            return Err(TermError::Arity {
                operator: operator.to_owned(),
                expected: 2,
                found,
            });
        }
        return Ok(Term::Binary(op, Box::new(left), Box::new(right)));
    }
    if matches!(operator, "shl" | "shr" | "sar" | "udiv" | "urem") {
        return Err(TermError::UnsupportedOperator {
            operator: operator.to_owned(),
        });
    }
    Err(TermError::UnknownSymbol {
        symbol: operator.to_owned(),
    })
}

const fn unary_operator(symbol: &str) -> Option<UnOp> {
    match symbol.as_bytes() {
        b"neg" => Some(UnOp::Neg),
        b"not" => Some(UnOp::Not),
        _ => None,
    }
}

fn parse_atom(symbol: &str) -> Result<Term, TermError> {
    if let Some(name) = symbol.strip_prefix('?') {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(TermError::BadCapture {
                name: name.to_owned(),
            });
        }
        return Ok(Term::Capture(name.to_owned()));
    }
    if symbol == "ones" {
        return Ok(Term::AllOnes);
    }
    if symbol.starts_with(|character: char| character.is_ascii_digit()) {
        let (digits, radix): (&str, u32) = symbol
            .strip_prefix("0x")
            .map_or((symbol, 10), |hex: &str| (hex, 16));
        let Ok(value): Result<u64, _> = u64::from_str_radix(digits, radix) else {
            return Err(TermError::BadInteger {
                literal: symbol.to_owned(),
            });
        };
        return Ok(Term::Const(value));
    }
    Err(TermError::UnknownSymbol {
        symbol: symbol.to_owned(),
    })
}

fn parse_term(text: &str) -> Result<Term, TermError> {
    let tokens: Vec<Token> = tokenize(text)?;
    let mut parser: Parser<'_> = Parser {
        tokens: &tokens,
        index: 0,
        nodes: 0,
    };
    let term: Term = parser.parse(0)?;
    match parser.peek() {
        None => Ok(term),
        Some(Token::Open(offset) | Token::Close(offset) | Token::Atom(offset, _)) => {
            Err(TermError::Trailing { offset: *offset })
        }
    }
}

pub(crate) fn load_egraph_rules(text: &str) -> Result<EgraphRuleSet, EgraphRuleError> {
    let bytes: usize = text.len();
    if bytes > MAX_RULE_FILE_BYTES {
        return Err(EgraphRuleError::TooLarge {
            bytes,
            max: MAX_RULE_FILE_BYTES,
        });
    }
    let raw: RawRuleSet = toml::from_str(text)?;
    if raw.rules.is_empty() {
        return Err(EgraphRuleError::Empty);
    }
    let count: usize = raw.rules.len();
    if count > MAX_RULES {
        return Err(EgraphRuleError::TooManyRules {
            count,
            max: MAX_RULES,
        });
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rules: Vec<EgraphRule> = Vec::with_capacity(count);
    for raw_rule in raw.rules {
        let rule: EgraphRule = compile_rule(raw_rule)?;
        if !seen.insert(rule.name.clone()) {
            return Err(EgraphRuleError::DuplicateRuleName { rule: rule.name });
        }
        rules.push(rule);
    }
    Ok(EgraphRuleSet { rules })
}

fn compile_rule(raw: RawRule) -> Result<EgraphRule, EgraphRuleError> {
    validate_name(&raw.name)?;
    validate_provenance(&raw.name, &raw.provenance)?;
    let pattern: Term = parse_side(&raw.name, Side::Pattern, &raw.pattern)?;
    let rewrite: Term = parse_side(&raw.name, Side::Rewrite, &raw.rewrite)?;
    if pattern.is_atom() {
        return Err(EgraphRuleError::AtomPattern {
            rule: raw.name,
            side: Side::Pattern,
        });
    }
    let pattern_captures: Vec<&str> = pattern.captures();
    let rewrite_captures: Vec<&str> = rewrite.captures();
    let mut captures: Vec<String> = pattern_captures
        .iter()
        .map(|name: &&str| (*name).to_owned())
        .collect();
    for capture in &rewrite_captures {
        let owned: String = (*capture).to_owned();
        if !captures.contains(&owned) {
            captures.push(owned);
        }
    }
    if captures.len() > MAX_RULE_CAPTURES {
        let count: usize = captures.len();
        return Err(EgraphRuleError::TooManyCaptures {
            rule: raw.name,
            count,
            max: MAX_RULE_CAPTURES,
        });
    }
    for capture in &rewrite_captures {
        if !pattern_captures.contains(capture) {
            let capture: String = (*capture).to_owned();
            return Err(EgraphRuleError::UnboundCapture {
                rule: raw.name,
                side: Side::Pattern,
                capture,
            });
        }
    }
    if raw.direction == Direction::Bidirectional {
        if rewrite.is_atom() {
            return Err(EgraphRuleError::AtomPattern {
                rule: raw.name,
                side: Side::Rewrite,
            });
        }
        for capture in &pattern_captures {
            if !rewrite_captures.contains(capture) {
                let capture: String = (*capture).to_owned();
                return Err(EgraphRuleError::UnboundCapture {
                    rule: raw.name,
                    side: Side::Rewrite,
                    capture,
                });
            }
        }
    }
    Ok(EgraphRule {
        name: raw.name,
        provenance: raw.provenance,
        direction: raw.direction,
        pattern,
        rewrite,
        captures,
    })
}

fn parse_side(name: &str, side: Side, text: &str) -> Result<Term, EgraphRuleError> {
    parse_term(text).map_err(|source: TermError| EgraphRuleError::Malformed {
        rule: name.to_owned(),
        side,
        source,
    })
}

fn validate_name(name: &str) -> Result<(), EgraphRuleError> {
    let bytes: usize = name.len();
    if bytes > MAX_RULE_NAME_BYTES {
        return Err(EgraphRuleError::RuleNameTooLong {
            rule: name.to_owned(),
            bytes,
            max: MAX_RULE_NAME_BYTES,
        });
    }
    let valid: bool = !name.is_empty()
        && name
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(EgraphRuleError::InvalidRuleName {
            rule: name.to_owned(),
        })
    }
}

fn validate_provenance(name: &str, provenance: &str) -> Result<(), EgraphRuleError> {
    let bytes: usize = provenance.len();
    if bytes > MAX_PROVENANCE_BYTES {
        return Err(EgraphRuleError::ProvenanceTooLong {
            rule: name.to_owned(),
            bytes,
            max: MAX_PROVENANCE_BYTES,
        });
    }
    if provenance.trim().is_empty() {
        return Err(EgraphRuleError::MissingProvenance {
            rule: name.to_owned(),
        });
    }
    Ok(())
}

static EGRAPH_RULES: OnceLock<EgraphRuleSet> = OnceLock::new();

#[allow(
    clippy::panic,
    reason = "the e-graph rule table is a compile-time include_str! const proven to load and validate by the shipped_egraph_rules_load test; a parse failure here is a build-integrity bug, and failing loud beats silently disabling the saturation layer"
)]
pub(crate) fn egraph_rules() -> &'static EgraphRuleSet {
    EGRAPH_RULES.get_or_init(|| match load_egraph_rules(MBA_EGRAPH_RULES) {
        Ok(set) => set,
        Err(error) => panic!("shipped mba e-graph rules must validate: {error}"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn rule_text(direction: &str, pattern: &str, rewrite: &str) -> String {
        format!(
            "[[rules]]\nname = \"probe\"\nprovenance = \"unit test\"\ndirection = \"{direction}\"\npattern = \"{pattern}\"\nrewrite = \"{rewrite}\"\n"
        )
    }

    fn error_of(text: &str) -> EgraphRuleError {
        match load_egraph_rules(text) {
            Ok(set) => panic!("expected a load failure, got {} rules", set.rules.len()),
            Err(error) => error,
        }
    }

    #[test]
    fn shipped_egraph_rules_load() {
        let set: EgraphRuleSet = match load_egraph_rules(MBA_EGRAPH_RULES) {
            Ok(set) => set,
            Err(error) => panic!("shipped rule table failed to load: {error}"),
        };
        assert!(set.rules.len() >= 30, "rule table shrank unexpectedly");
        for rule in &set.rules {
            assert!(
                !rule.provenance.trim().is_empty(),
                "{} has no provenance",
                rule.name
            );
        }
        assert!(set.directed_pairs().len() > set.rules.len());
    }

    #[test]
    fn a_shift_operator_is_refused_because_the_enode_language_has_none() {
        let text: String = rule_text("contract", "(shl ?x 1)", "(mul ?x 2)");
        let error: EgraphRuleError = error_of(&text);
        assert!(
            matches!(
                &error,
                EgraphRuleError::Malformed {
                    source: TermError::UnsupportedOperator { operator },
                    ..
                } if operator == "shl"
            ),
            "a shift rule must be refused by name, got {error}"
        );
    }

    #[test]
    fn a_rewrite_capture_the_pattern_never_binds_is_refused() {
        let text: String = rule_text("contract", "(add ?x 0)", "(add ?x ?y)");
        let error: EgraphRuleError = error_of(&text);
        assert!(
            matches!(
                &error,
                EgraphRuleError::UnboundCapture { capture, side: Side::Pattern, .. } if capture == "y"
            ),
            "got {error}"
        );
    }

    #[test]
    fn a_bare_capture_pattern_is_refused() {
        let text: String = rule_text("contract", "?x", "0");
        let error: EgraphRuleError = error_of(&text);
        assert!(
            matches!(
                &error,
                EgraphRuleError::AtomPattern {
                    side: Side::Pattern,
                    ..
                }
            ),
            "got {error}"
        );
    }

    #[test]
    fn a_bidirectional_rule_that_drops_a_capture_is_refused() {
        let text: String = rule_text("bidirectional", "(and ?x (or ?x ?y))", "(add ?x 0)");
        let error: EgraphRuleError = error_of(&text);
        assert!(
            matches!(
                &error,
                EgraphRuleError::UnboundCapture { capture, side: Side::Rewrite, .. } if capture == "y"
            ),
            "got {error}"
        );
    }

    #[test]
    fn an_empty_provenance_is_refused() {
        let text: &str = "[[rules]]\nname = \"probe\"\nprovenance = \"  \"\ndirection = \"contract\"\npattern = \"(add ?x 0)\"\nrewrite = \"?x\"\n";
        let error: EgraphRuleError = error_of(text);
        assert!(
            matches!(&error, EgraphRuleError::MissingProvenance { rule } if rule == "probe"),
            "got {error}"
        );
    }

    #[test]
    fn a_duplicate_rule_name_is_refused() {
        let single: String = rule_text("contract", "(add ?x 0)", "?x");
        let text: String = format!("{single}{single}");
        let error: EgraphRuleError = error_of(&text);
        assert!(
            matches!(&error, EgraphRuleError::DuplicateRuleName { rule } if rule == "probe"),
            "got {error}"
        );
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let text: &str = "[[rules]]\nname = \"probe\"\nprovenance = \"unit test\"\ndirection = \"contract\"\npattern = \"(add ?x 0)\"\nrewrite = \"?x\"\nweight = 3\n";
        assert!(matches!(error_of(text), EgraphRuleError::Toml(_)));
    }

    #[test]
    fn parser_bounds_are_enforced() {
        let mut deep: String = String::new();
        for _ in 0..=MAX_TERM_DEPTH {
            deep.push_str("(neg ");
        }
        deep.push_str("?x");
        for _ in 0..=MAX_TERM_DEPTH {
            deep.push(')');
        }
        assert!(matches!(
            parse_term(&deep),
            Err(TermError::TooDeep {
                max: MAX_TERM_DEPTH
            })
        ));

        let long: String = "x".repeat(MAX_TERM_BYTES + 1);
        assert!(matches!(
            parse_term(&long),
            Err(TermError::TooLong {
                bytes,
                max: MAX_TERM_BYTES
            }) if bytes == MAX_TERM_BYTES + 1
        ));

        assert!(matches!(
            parse_term("(add ?x ?y) (add ?x ?y)"),
            Err(TermError::Trailing { .. })
        ));
        assert!(matches!(parse_term("(add ?x"), Err(TermError::Unclosed)));
        assert!(matches!(
            parse_term(")"),
            Err(TermError::Unbalanced { offset: 0 })
        ));
        assert!(matches!(
            parse_term("(add ?x ?y ?z)"),
            Err(TermError::Arity {
                expected: 2,
                found: 3,
                ..
            })
        ));
        assert!(matches!(
            parse_term("(neg)"),
            Err(TermError::Arity {
                expected: 1,
                found: 0,
                ..
            })
        ));
        assert!(matches!(
            parse_term("(add ?x 18446744073709551616)"),
            Err(TermError::BadInteger { .. })
        ));
        assert!(matches!(
            parse_term("(add ?x $)"),
            Err(TermError::UnexpectedByte { byte: '$', .. })
        ));
        assert!(matches!(
            parse_term("(add ? 0)"),
            Err(TermError::BadCapture { .. })
        ));
        assert!(matches!(
            parse_term("(frobnicate ?x)"),
            Err(TermError::UnknownSymbol { .. })
        ));
        assert!(matches!(parse_term("   "), Err(TermError::Empty)));
    }

    #[test]
    fn atoms_parse_to_their_typed_forms() {
        assert_eq!(parse_term("?x"), Ok(Term::Capture(String::from("x"))));
        assert_eq!(parse_term("ones"), Ok(Term::AllOnes));
        assert_eq!(parse_term("0x1f"), Ok(Term::Const(31)));
        assert_eq!(parse_term("31"), Ok(Term::Const(31)));
        assert_eq!(
            parse_term("(mul 2 (and ?x ?y))"),
            Ok(Term::Binary(
                RingOp::Mul,
                Box::new(Term::Const(2)),
                Box::new(Term::Binary(
                    RingOp::And,
                    Box::new(Term::Capture(String::from("x"))),
                    Box::new(Term::Capture(String::from("y")))
                ))
            ))
        );
    }

    #[test]
    fn capture_order_is_first_appearance() {
        let Ok(term): Result<Term, TermError> = parse_term("(sub (xor ?b ?a) ?b)") else {
            panic!("term must parse");
        };
        assert_eq!(term.captures(), vec!["b", "a"]);
    }
}
