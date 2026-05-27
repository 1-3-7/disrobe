//! `--chain` grammar parser (spec §8).
//!
//! Grammar (PEG sketch):
//!
//! ```text
//! ChainSpec   := "auto" (":" Cap)?
//!              | PassList
//!              | PassList "," "*"
//!              | "?" (":" Cap)?
//! PassList    := PassToken ("," PassToken)*
//! PassToken   := PassId ("(" KvList ")")?
//! PassId      := [a-z][a-z0-9._-]*
//! KvList      := Kv ("," Kv)*
//! Kv          := Key "=" Value
//! Cap         := 1..=16
//! ```
//!
//! The parser is intentionally strict: unknown shapes produce a typed
//! [`ChainSpecError`] rather than silently routing to `auto`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_CAP: u8 = 8;
pub const MAX_CAP: u8 = 16;

/// A pass-id with optional key/value arguments. Arguments are deliberately
/// parsed as plain strings; each pass crate validates its own keys at run
/// time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassToken {
    pub pass_id: String,
    pub kv: BTreeMap<String, String>,
}

impl PassToken {
    #[inline]
    #[must_use]
    pub fn new(pass_id: impl Into<String>) -> Self {
        Self {
            pass_id: pass_id.into(),
            kv: BTreeMap::new(),
        }
    }
}

/// Parsed `--chain` argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ChainSpec {
    Auto { cap: u8 },
    Explicit { passes: Vec<PassToken> },
    PrefixThenAuto { prefix: Vec<PassToken>, cap: u8 },
    PlanOnly { cap: u8 },
}

/// Cheap discriminant used in `chain.json` rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpecKind {
    Auto,
    Explicit,
    PrefixThenAuto,
    PlanOnly,
}

impl ChainSpec {
    /// Effective depth budget for this spec.
    #[inline]
    #[must_use]
    pub fn cap(&self) -> u8 {
        match self {
            Self::Auto { cap } | Self::PlanOnly { cap } => *cap,
            Self::Explicit { passes } => u8::try_from(passes.len()).unwrap_or(MAX_CAP),
            Self::PrefixThenAuto { prefix, cap } => {
                let p: u8 = u8::try_from(prefix.len()).unwrap_or(MAX_CAP);
                p.saturating_add(cap.saturating_sub(p))
            }
        }
    }

    #[inline]
    #[must_use]
    pub const fn kind(&self) -> SpecKind {
        match self {
            Self::Auto { .. } => SpecKind::Auto,
            Self::Explicit { .. } => SpecKind::Explicit,
            Self::PrefixThenAuto { .. } => SpecKind::PrefixThenAuto,
            Self::PlanOnly { .. } => SpecKind::PlanOnly,
        }
    }

    /// `true` when the planner should not run any passes — only emit the
    /// chain it would have run.
    #[inline]
    #[must_use]
    pub const fn is_plan_only(&self) -> bool {
        matches!(self, Self::PlanOnly { .. })
    }

    /// Returns the pinned pass for the given cursor depth, or `None` if
    /// the spec leaves the choice to the auto planner.
    #[must_use]
    pub fn pin_at(&self, cursor: SpecCursor) -> Option<&PassToken> {
        match self {
            Self::Auto { .. } | Self::PlanOnly { .. } => None,
            Self::Explicit { passes } => passes.get(cursor.0 as usize),
            Self::PrefixThenAuto { prefix, .. } => prefix.get(cursor.0 as usize),
        }
    }

    #[inline]
    #[must_use]
    pub const fn cursor_for_root() -> SpecCursor {
        SpecCursor(0)
    }

    /// Parse the user-facing `--chain` argument.
    ///
    /// ```
    /// # #[cfg(feature = "chain")] {
    /// use disrobe_core::chain::{ChainSpec, SpecKind};
    /// let s: ChainSpec = ChainSpec::parse("auto:16").unwrap();
    /// assert_eq!(s.kind(), SpecKind::Auto);
    /// assert_eq!(s.cap(), 16);
    /// # }
    /// ```
    pub fn parse(s: &str) -> Result<Self, ChainSpecError> {
        if s.is_empty() {
            return Err(ChainSpecError::Empty);
        }
        if s.contains(char::is_whitespace) {
            return Err(ChainSpecError::WhitespaceForbidden);
        }
        if s == "?" {
            return Ok(Self::PlanOnly { cap: DEFAULT_CAP });
        }
        if let Some(rest) = s.strip_prefix("?:") {
            let cap: u8 = parse_cap(rest)?;
            return Ok(Self::PlanOnly { cap });
        }
        if s.contains('?') {
            return Err(ChainSpecError::PlanOnlyExclusive);
        }
        if s == "auto" {
            return Ok(Self::Auto { cap: DEFAULT_CAP });
        }
        if let Some(rest) = s.strip_prefix("auto:") {
            let cap: u8 = parse_cap(rest)?;
            return Ok(Self::Auto { cap });
        }
        let tokens: Vec<&str> = split_top_level_commas(s)?;
        let has_star_suffix: bool = tokens.last().copied() == Some("*");
        if tokens
            .iter()
            .enumerate()
            .any(|(i, t): (usize, &&str)| *t == "*" && i + 1 != tokens.len())
        {
            return Err(ChainSpecError::StarMustBeLast);
        }
        let body_slice: &[&str] = if has_star_suffix {
            &tokens[..tokens.len() - 1]
        } else {
            &tokens[..]
        };
        if body_slice.is_empty() {
            return Err(ChainSpecError::Empty);
        }
        let mut parsed: Vec<PassToken> = Vec::with_capacity(body_slice.len());
        for raw in body_slice {
            parsed.push(parse_pass_token(raw)?);
        }
        if has_star_suffix {
            Ok(Self::PrefixThenAuto {
                prefix: parsed,
                cap: DEFAULT_CAP,
            })
        } else {
            if parsed.len() > MAX_CAP as usize {
                return Err(ChainSpecError::CapOutOfRange(parsed.len()));
            }
            Ok(Self::Explicit { passes: parsed })
        }
    }
}

/// Where in the spec the driver is, for `pin_at` lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecCursor(pub u8);

impl SpecCursor {
    #[inline]
    #[must_use]
    pub const fn advance(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[derive(Debug, Error)]
pub enum ChainSpecError {
    #[error("DR-CORE-0101: chain spec is empty")]
    Empty,
    #[error("DR-CORE-0102: chain spec must not contain whitespace; quote the argument")]
    WhitespaceForbidden,
    #[error("DR-CORE-0103: `*` must only appear as the final token")]
    StarMustBeLast,
    #[error("DR-CORE-0104: `?` is mutually exclusive with other tokens")]
    PlanOnlyExclusive,
    #[error("DR-CORE-0105: cap {0} is out of range; valid: 1..={MAX_CAP}")]
    CapOutOfRange(usize),
    #[error("DR-CORE-0106: invalid cap {0:?}: {1}")]
    BadCap(String, String),
    #[error("DR-CORE-0107: invalid pass id {0:?} ({1})")]
    BadPassId(String, &'static str),
    #[error("DR-CORE-0108: malformed kv argument {0:?} in pass {1:?}")]
    BadKvSyntax(String, String),
}

fn split_top_level_commas(s: &str) -> Result<Vec<&str>, ChainSpecError> {
    let mut out: Vec<&str> = Vec::new();
    let mut depth: i32 = 0;
    let mut start: usize = 0;
    let bytes: &[u8] = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(ChainSpecError::BadKvSyntax(s.to_string(), s.to_string()));
                }
            }
            b',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(ChainSpecError::BadKvSyntax(s.to_string(), s.to_string()));
    }
    out.push(&s[start..]);
    Ok(out)
}

fn parse_cap(raw: &str) -> Result<u8, ChainSpecError> {
    let n: u8 = raw
        .parse::<u8>()
        .map_err(|e| ChainSpecError::BadCap(raw.to_string(), e.to_string()))?;
    if !(1..=MAX_CAP).contains(&n) {
        return Err(ChainSpecError::CapOutOfRange(n as usize));
    }
    Ok(n)
}

fn parse_pass_token(raw: &str) -> Result<PassToken, ChainSpecError> {
    let (id_part, kv_part): (&str, Option<&str>) = match raw.find('(') {
        None => (raw, None),
        Some(open_idx) => {
            let close_idx: usize = raw
                .rfind(')')
                .ok_or_else(|| ChainSpecError::BadKvSyntax(raw.to_string(), raw.to_string()))?;
            if close_idx + 1 != raw.len() {
                return Err(ChainSpecError::BadKvSyntax(
                    raw.to_string(),
                    raw.to_string(),
                ));
            }
            (&raw[..open_idx], Some(&raw[open_idx + 1..close_idx]))
        }
    };
    validate_pass_id(id_part)?;
    let mut kv: BTreeMap<String, String> = BTreeMap::new();
    if let Some(body) = kv_part {
        if body.is_empty() {
            return Ok(PassToken {
                pass_id: id_part.to_string(),
                kv,
            });
        }
        for piece in body.split(',') {
            let (k, v): (&str, &str) = piece.split_once('=').ok_or_else(|| {
                ChainSpecError::BadKvSyntax(piece.to_string(), id_part.to_string())
            })?;
            if k.is_empty() {
                return Err(ChainSpecError::BadKvSyntax(
                    piece.to_string(),
                    id_part.to_string(),
                ));
            }
            kv.insert(k.to_string(), v.to_string());
        }
    }
    Ok(PassToken {
        pass_id: id_part.to_string(),
        kv,
    })
}

fn validate_pass_id(s: &str) -> Result<(), ChainSpecError> {
    let mut chars: std::str::Chars<'_> = s.chars();
    let first: char = chars
        .next()
        .ok_or_else(|| ChainSpecError::BadPassId(s.to_string(), "empty pass id"))?;
    if !first.is_ascii_lowercase() {
        return Err(ChainSpecError::BadPassId(
            s.to_string(),
            "pass id must start with [a-z]",
        ));
    }
    for ch in chars {
        let ok: bool =
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-');
        if !ok {
            return Err(ChainSpecError::BadPassId(
                s.to_string(),
                "pass id chars must match [a-z0-9._-]",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_auto() {
        let s: ChainSpec = ChainSpec::parse("auto").unwrap();
        assert!(matches!(s, ChainSpec::Auto { cap: 8 }));
    }

    #[test]
    fn parse_auto_with_cap() {
        let s: ChainSpec = ChainSpec::parse("auto:16").unwrap();
        assert!(matches!(s, ChainSpec::Auto { cap: 16 }));
    }

    #[test]
    fn parse_cap_one() {
        let s: ChainSpec = ChainSpec::parse("auto:1").unwrap();
        assert!(matches!(s, ChainSpec::Auto { cap: 1 }));
    }

    #[test]
    fn parse_cap_out_of_range() {
        assert!(matches!(
            ChainSpec::parse("auto:17"),
            Err(ChainSpecError::CapOutOfRange(17))
        ));
        assert!(matches!(
            ChainSpec::parse("auto:0"),
            Err(ChainSpecError::CapOutOfRange(0))
        ));
    }

    #[test]
    fn parse_explicit_single() {
        let s: ChainSpec = ChainSpec::parse("pyarmor").unwrap();
        let ChainSpec::Explicit { passes } = s else {
            panic!("wrong shape")
        };
        assert_eq!(passes.len(), 1);
        assert_eq!(passes[0].pass_id, "pyarmor");
    }

    #[test]
    fn parse_explicit_two() {
        let s: ChainSpec = ChainSpec::parse("pyarmor,py-deob").unwrap();
        let ChainSpec::Explicit { passes } = s else {
            panic!()
        };
        assert_eq!(passes.len(), 2);
        assert_eq!(passes[1].pass_id, "py-deob");
    }

    #[test]
    fn parse_prefix_then_auto() {
        let s: ChainSpec = ChainSpec::parse("pyarmor,*").unwrap();
        let ChainSpec::PrefixThenAuto { prefix, cap } = s else {
            panic!()
        };
        assert_eq!(prefix.len(), 1);
        assert_eq!(cap, 8);
    }

    #[test]
    fn parse_plan_only_default() {
        let s: ChainSpec = ChainSpec::parse("?").unwrap();
        assert!(matches!(s, ChainSpec::PlanOnly { cap: 8 }));
    }

    #[test]
    fn parse_plan_only_with_cap() {
        let s: ChainSpec = ChainSpec::parse("?:16").unwrap();
        assert!(matches!(s, ChainSpec::PlanOnly { cap: 16 }));
    }

    #[test]
    fn reject_star_not_last() {
        assert!(matches!(
            ChainSpec::parse("foo,*,bar"),
            Err(ChainSpecError::StarMustBeLast)
        ));
    }

    #[test]
    fn reject_question_mark_mixed() {
        assert!(matches!(
            ChainSpec::parse("?,foo"),
            Err(ChainSpecError::PlanOnlyExclusive)
        ));
    }

    #[test]
    fn reject_whitespace() {
        assert!(matches!(
            ChainSpec::parse("foo, bar"),
            Err(ChainSpecError::WhitespaceForbidden)
        ));
    }

    #[test]
    fn reject_empty() {
        assert!(matches!(ChainSpec::parse(""), Err(ChainSpecError::Empty)));
    }

    #[test]
    fn parse_pass_token_kv_args() {
        let s: ChainSpec = ChainSpec::parse("pyarmor(version=v8,key=abc)").unwrap();
        let ChainSpec::Explicit { passes } = s else {
            panic!()
        };
        assert_eq!(passes[0].pass_id, "pyarmor");
        assert_eq!(passes[0].kv.get("version").map(String::as_str), Some("v8"));
        assert_eq!(passes[0].kv.get("key").map(String::as_str), Some("abc"));
    }

    #[test]
    fn reject_bad_pass_id_uppercase() {
        assert!(matches!(
            ChainSpec::parse("PYARMOR"),
            Err(ChainSpecError::BadPassId(_, _))
        ));
    }

    #[test]
    fn reject_bad_pass_id_starts_with_digit() {
        assert!(matches!(
            ChainSpec::parse("1pyarmor"),
            Err(ChainSpecError::BadPassId(_, _))
        ));
    }

    #[test]
    fn pin_at_explicit_returns_token() {
        let s: ChainSpec = ChainSpec::parse("a,b,c").unwrap();
        assert_eq!(
            s.pin_at(SpecCursor(0)).map(|t| t.pass_id.as_str()),
            Some("a")
        );
        assert_eq!(
            s.pin_at(SpecCursor(2)).map(|t| t.pass_id.as_str()),
            Some("c")
        );
        assert_eq!(s.pin_at(SpecCursor(3)), None);
    }

    #[test]
    fn pin_at_auto_always_none() {
        let s: ChainSpec = ChainSpec::parse("auto:8").unwrap();
        assert_eq!(s.pin_at(SpecCursor(0)), None);
        assert_eq!(s.pin_at(SpecCursor(5)), None);
    }

    #[test]
    fn explicit_cap_equals_len() {
        let s: ChainSpec = ChainSpec::parse("a,b,c").unwrap();
        assert_eq!(s.cap(), 3);
    }

    #[test]
    fn prefix_then_auto_cap_default_eight() {
        let s: ChainSpec = ChainSpec::parse("a,b,*").unwrap();
        assert_eq!(s.cap(), 8);
    }

    #[test]
    fn cursor_advance_saturates() {
        let c: SpecCursor = SpecCursor(u8::MAX);
        assert_eq!(c.advance().0, u8::MAX);
    }
}
