//! Decodes BEAM `bs_match` command lists into binary-pattern segments.
//!
//! `bs_match Fail Ctx {commands, ...}` carries a flat command list whose leading
//! `ensure_at_least`/`ensure_exactly` directive is followed by zero or more
//! segment descriptors `Type, Live, Flags, Size, Unit, Dst`. Each descriptor is
//! one element of the surface binary pattern `<<Dst:Size/Type-Flags>>`; this
//! module turns the command list into `(BinSegment, Dst)` pairs so the lifter can
//! bind the destination registers and assemble the clause-head pattern.

use crate::body_lift::expr::{BinSegment, Expr};
use crate::chunks::Chunks;
use crate::disasm::Operand;

/// One decoded match segment: the surface pattern element plus the destination
/// register it binds (absent for skipped segments).
#[derive(Debug, Clone)]
pub struct MatchSegment {
    pub segment: BinSegment,
    pub dst: Option<Operand>,
}

/// Decodes the `bs_match` command list into ordered match segments.
#[must_use]
pub fn decode_match_commands(items: &[Operand], chunks: &Chunks) -> Vec<MatchSegment> {
    let mut segments: Vec<MatchSegment> = Vec::new();
    let mut i: usize = 0;
    while i < items.len() {
        let directive: &str = atom_name(&items[i], chunks);
        match directive {
            "ensure_at_least" | "ensure_exactly" => i += 3,
            "skip" => {
                if i + 2 < items.len() {
                    let size: Expr = literal_expr(&items[i + 1]);
                    let unit: u32 = literal_u32(&items[i + 2]);
                    segments.push(MatchSegment {
                        segment: BinSegment {
                            value: Box::new(Expr::Var("_".to_owned())),
                            size: Some(Box::new(size)),
                            unit,
                            kind: "integer".to_owned(),
                            flags: Vec::new(),
                        },
                        dst: None,
                    });
                }
                i += 3;
            }
            "integer" | "binary" | "float" | "utf8" | "utf16" | "utf32" => {
                if i + 5 >= items.len() {
                    break;
                }
                let kind: String = normalize_kind(directive);
                let flags: Vec<String> = decode_flags(&items[i + 2], chunks);
                let size: Option<Box<Expr>> = match &items[i + 3] {
                    Operand::Atom(a) if chunks.atoms.get(*a) == Some("all") => None,
                    other => Some(Box::new(literal_expr(other))),
                };
                let unit: u32 = literal_u32(&items[i + 4]);
                let dst: Operand = items[i + 5].clone();
                segments.push(MatchSegment {
                    segment: BinSegment {
                        value: Box::new(Expr::Var("_".to_owned())),
                        size,
                        unit,
                        kind,
                        flags,
                    },
                    dst: Some(dst),
                });
                i += 6;
            }
            _ => {
                i += 1;
            }
        }
    }
    segments
}

fn normalize_kind(directive: &str) -> String {
    match directive {
        "binary" => "binary".to_owned(),
        "float" => "float".to_owned(),
        "utf8" => "utf8".to_owned(),
        "utf16" => "utf16".to_owned(),
        "utf32" => "utf32".to_owned(),
        _ => "integer".to_owned(),
    }
}

/// Decodes the flags field of a `bs_create_bin` construction segment into surface
/// type-specifier flags (`little`, `signed`, ...). `big`/`unsigned` are defaults
/// and omitted.
#[must_use]
pub fn decode_construct_flags(op: &Operand, chunks: &Chunks) -> Vec<String> {
    decode_flags(op, chunks)
}

fn decode_flags(op: &Operand, chunks: &Chunks) -> Vec<String> {
    let bits: u32 = match op {
        Operand::Literal(v) => u32::try_from(*v).unwrap_or(0),
        Operand::LiteralIndex(_) | Operand::Atom(_) => return flags_from_term(op, chunks),
        _ => 0,
    };
    bits_to_flags(bits)
}

fn flags_from_term(op: &Operand, chunks: &Chunks) -> Vec<String> {
    match op {
        Operand::LiteralIndex(i) => chunks
            .literals
            .as_ref()
            .and_then(|l| l.literals.get(*i as usize))
            .map_or_else(Vec::new, term_flags),
        Operand::Atom(a) if chunks.atoms.get(*a) == Some("little") => vec!["little".to_owned()],
        Operand::Atom(a) if chunks.atoms.get(*a) == Some("signed") => vec!["signed".to_owned()],
        _ => Vec::new(),
    }
}

fn term_flags(term: &crate::etf::Term) -> Vec<String> {
    match term {
        crate::etf::Term::SmallInt(v) => bits_to_flags(u32::from(*v)),
        crate::etf::Term::Int(v) => bits_to_flags(u32::try_from(*v).unwrap_or(0)),
        crate::etf::Term::List { elements, .. } => elements
            .iter()
            .filter_map(|e: &crate::etf::Term| match e {
                crate::etf::Term::Atom(a) if a == "little" || a == "signed" || a == "native" => {
                    Some(a.clone())
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn bits_to_flags(bits: u32) -> Vec<String> {
    let mut flags: Vec<String> = Vec::new();
    if bits & 0b10 != 0 {
        flags.push("little".to_owned());
    }
    if bits & 0b100 != 0 {
        flags.push("signed".to_owned());
    }
    flags
}

fn atom_name<'a>(op: &Operand, chunks: &'a Chunks) -> &'a str {
    match op {
        Operand::Atom(a) => chunks.atoms.get(*a).unwrap_or(""),
        _ => "",
    }
}

fn literal_expr(op: &Operand) -> Expr {
    match op {
        Operand::Literal(v) => Expr::Int(i64::try_from(*v).unwrap_or(0)),
        Operand::SignedInteger(v) => Expr::Int(*v),
        Operand::Character(c) => Expr::Int(i64::from(*c)),
        _ => Expr::Int(0),
    }
}

fn literal_u32(op: &Operand) -> u32 {
    match op {
        Operand::Literal(v) => u32::try_from(*v).unwrap_or(0),
        Operand::SignedInteger(v) => u32::try_from(*v).unwrap_or(0),
        Operand::Character(c) => *c,
        _ => 0,
    }
}
