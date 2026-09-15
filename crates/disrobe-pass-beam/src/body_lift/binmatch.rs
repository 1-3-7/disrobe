use crate::body_lift::expr::{BinSegment, Expr};
use crate::chunks::Chunks;
use crate::disasm::Operand;

#[derive(Debug, Clone)]
pub struct MatchSegment {
    pub segment: BinSegment,
    pub dst: Option<Operand>,
    pub size_src: Option<Operand>,
    pub binds: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MatchCommands {
    pub segments: Vec<MatchSegment>,
    pub exact: bool,
    pub degraded: bool,
}

#[must_use]
pub fn decode_match_commands(items: &[Operand], chunks: &Chunks) -> MatchCommands {
    let mut out: MatchCommands = MatchCommands::default();
    let mut i: usize = 0;
    while i < items.len() {
        let directive: &str = atom_name(&items[i], chunks);
        match directive {
            "ensure_at_least" if i + 2 < items.len() => i += 3,
            "ensure_exactly" if i + 1 < items.len() => {
                out.exact = true;
                i += 2;
            }
            "test_tail" if i + 1 < items.len() => {
                out.exact = true;
                if let Some(bits) = positive_bits(&items[i + 1]) {
                    out.segments.push(skip_segment(bits, 1));
                }
                i += 2;
            }
            "skip" if i + 1 < items.len() => {
                if let Some(bits) = positive_bits(&items[i + 1]) {
                    out.segments.push(skip_segment(bits, 1));
                } else {
                    out.degraded = true;
                }
                i += 2;
            }
            "get_tail" if i + 3 < items.len() => {
                out.segments.push(tail_segment(
                    literal_u32(&items[i + 2]),
                    Some(items[i + 3].clone()),
                ));
                i += 4;
            }
            "=:=" if i + 3 < items.len() => {
                let bits: u32 = literal_u32(&items[i + 2]);
                match (integer_operand(&items[i + 3]), bits) {
                    (Some(value), 1..) => out.segments.push(literal_segment(value, bits)),
                    (_, bits) => {
                        out.degraded = true;
                        if bits > 0 {
                            out.segments.push(skip_segment(bits, 1));
                        }
                    }
                }
                i += 4;
            }
            "integer" | "binary" | "float" | "utf8" | "utf16" | "utf32" => {
                if i + 5 >= items.len() {
                    out.degraded = true;
                    break;
                }
                let (size, size_src): (Option<Box<Expr>>, Option<Operand>) =
                    split_size(&items[i + 3], chunks);
                out.segments.push(MatchSegment {
                    segment: BinSegment {
                        value: Box::new(Expr::Var("_".to_owned())),
                        size,
                        unit: literal_u32(&items[i + 4]),
                        kind: normalize_kind(directive),
                        flags: decode_flags(&items[i + 2], chunks),
                    },
                    dst: Some(items[i + 5].clone()),
                    size_src,
                    binds: true,
                });
                i += 6;
            }
            _ => {
                out.degraded = true;
                i += 1;
            }
        }
    }
    out
}

#[must_use]
pub fn decode_get_segment(name: &str, ops: &[Operand], chunks: &Chunks) -> Option<MatchSegment> {
    let kind: &str = name.strip_prefix("bs_get_")?;
    if kind.starts_with("utf") {
        let (flags, dst): (&Operand, &Operand) = (ops.get(3)?, ops.get(4)?);
        return Some(MatchSegment {
            segment: BinSegment {
                value: Box::new(Expr::Var("_".to_owned())),
                size: None,
                unit: 1,
                kind: kind.to_owned(),
                flags: decode_flags(flags, chunks),
            },
            dst: Some(dst.clone()),
            size_src: None,
            binds: true,
        });
    }
    let (size, size_src): (Option<Box<Expr>>, Option<Operand>) = split_size(ops.get(3)?, chunks);
    Some(MatchSegment {
        segment: BinSegment {
            value: Box::new(Expr::Var("_".to_owned())),
            size,
            unit: literal_u32(ops.get(4)?),
            kind: normalize_kind(kind.trim_end_matches('2')),
            flags: decode_flags(ops.get(5)?, chunks),
        },
        dst: Some(ops.get(6)?.clone()),
        size_src,
        binds: true,
    })
}

#[must_use]
pub fn decode_skip_segment(name: &str, ops: &[Operand], chunks: &Chunks) -> Option<MatchSegment> {
    let kind: &str = name.strip_prefix("bs_skip_")?;
    if kind.starts_with("utf") {
        return Some(MatchSegment {
            segment: BinSegment {
                value: Box::new(Expr::Var("_".to_owned())),
                size: None,
                unit: 1,
                kind: kind.to_owned(),
                flags: Vec::new(),
            },
            dst: None,
            size_src: None,
            binds: false,
        });
    }
    let (size, size_src): (Option<Box<Expr>>, Option<Operand>) = split_size(ops.get(2)?, chunks);
    Some(MatchSegment {
        segment: BinSegment {
            value: Box::new(Expr::Var("_".to_owned())),
            size,
            unit: literal_u32(ops.get(3)?),
            kind: "integer".to_owned(),
            flags: decode_flags(ops.get(4)?, chunks),
        },
        dst: None,
        size_src,
        binds: false,
    })
}

#[must_use]
pub fn tail_segment(unit: u32, dst: Option<Operand>) -> MatchSegment {
    MatchSegment {
        segment: BinSegment {
            value: Box::new(Expr::Var("_".to_owned())),
            size: None,
            unit,
            kind: "binary".to_owned(),
            flags: Vec::new(),
        },
        dst,
        size_src: None,
        binds: true,
    }
}

#[must_use]
pub fn fixed_segment(segment: BinSegment) -> MatchSegment {
    MatchSegment {
        segment,
        dst: None,
        size_src: None,
        binds: false,
    }
}

#[must_use]
pub fn skip_segment(bits: u32, unit: u32) -> MatchSegment {
    MatchSegment {
        segment: BinSegment {
            value: Box::new(Expr::Var("_".to_owned())),
            size: Some(Box::new(Expr::Int(i64::from(bits)))),
            unit,
            kind: "integer".to_owned(),
            flags: Vec::new(),
        },
        dst: None,
        size_src: None,
        binds: false,
    }
}

#[must_use]
pub fn literal_segment(value: i64, bits: u32) -> MatchSegment {
    MatchSegment {
        segment: BinSegment {
            value: Box::new(Expr::Int(value)),
            size: Some(Box::new(Expr::Int(i64::from(bits)))),
            unit: 1,
            kind: "integer".to_owned(),
            flags: Vec::new(),
        },
        dst: None,
        size_src: None,
        binds: false,
    }
}

fn split_size(op: &Operand, chunks: &Chunks) -> (Option<Box<Expr>>, Option<Operand>) {
    match op {
        Operand::Atom(a) if chunks.atoms.get(*a) == Some("all") => (None, None),
        Operand::Atom(0) => (None, None),
        other => match integer_operand(other) {
            Some(value) => (Some(Box::new(Expr::Int(value))), None),
            None => (None, Some(other.clone())),
        },
    }
}

fn integer_operand(op: &Operand) -> Option<i64> {
    match op {
        Operand::Literal(v) => i64::try_from(*v).ok(),
        Operand::SignedInteger(v) => Some(*v),
        Operand::Character(c) => Some(i64::from(*c)),
        _ => None,
    }
}

fn positive_bits(op: &Operand) -> Option<u32> {
    match integer_operand(op)? {
        v @ 1.. => u32::try_from(v).ok(),
        _ => None,
    }
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
    if bits & 0b1_0000 != 0 {
        flags.push("native".to_owned());
    }
    flags
}

fn atom_name<'a>(op: &Operand, chunks: &'a Chunks) -> &'a str {
    match op {
        Operand::Atom(a) => chunks.atoms.get(*a).unwrap_or(""),
        _ => "",
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chunks::AtomTable;
    use std::collections::BTreeMap;

    const DIRECTIVES: [&str; 11] = [
        "ensure_at_least",
        "ensure_exactly",
        "integer",
        "binary",
        "float",
        "utf8",
        "skip",
        "get_tail",
        "=:=",
        "test_tail",
        "nil",
    ];

    fn chunks() -> Chunks {
        Chunks {
            atoms: AtomTable {
                atoms: DIRECTIVES.iter().map(|s: &&str| (*s).to_owned()).collect(),
            },
            code: None,
            strings: None,
            attributes: None,
            compile_info: None,
            dbgi: None,
            docs: None,
            exports: Vec::new(),
            imports: Vec::new(),
            locals: Vec::new(),
            literals: None,
            line: None,
            funs: Vec::new(),
            other: BTreeMap::new(),
        }
    }

    fn directive(name: &str) -> Operand {
        let index: usize = DIRECTIVES
            .iter()
            .position(|d: &&str| *d == name)
            .expect("directive is in the test atom table");
        Operand::Atom(u32::try_from(index).unwrap() + 1)
    }

    fn signed_flags() -> Operand {
        Operand::Literal(0b100)
    }

    fn value_command(kind: &str, size: u64, dst: u32) -> Vec<Operand> {
        vec![
            directive(kind),
            Operand::Literal(3),
            signed_flags(),
            Operand::Literal(size),
            Operand::Literal(1),
            Operand::XReg(dst),
        ]
    }

    fn sizes(decoded: &MatchCommands) -> Vec<Option<i64>> {
        decoded
            .segments
            .iter()
            .map(|s: &MatchSegment| match s.segment.size.as_deref() {
                Some(Expr::Int(v)) => Some(*v),
                _ => None,
            })
            .collect()
    }

    fn dsts(decoded: &MatchCommands) -> Vec<Option<u32>> {
        decoded
            .segments
            .iter()
            .map(|s: &MatchSegment| match &s.dst {
                Some(Operand::XReg(r)) => Some(*r),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn ensure_exactly_carries_one_operand_and_keeps_every_later_segment() {
        let mut items: Vec<Operand> = vec![directive("ensure_exactly"), Operand::Literal(24)];
        items.extend(value_command("integer", 8, 1));
        items.extend(value_command("integer", 16, 2));
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(decoded.exact, "ensure_exactly fixes the whole binary size");
        assert!(!decoded.degraded);
        assert_eq!(sizes(&decoded), vec![Some(8), Some(16)]);
        assert_eq!(dsts(&decoded), vec![Some(1), Some(2)]);
        assert_eq!(decoded.segments[0].segment.flags, vec!["signed".to_owned()]);
    }

    #[test]
    fn ensure_at_least_carries_two_operands_and_leaves_the_tail_open() {
        let mut items: Vec<Operand> = vec![
            directive("ensure_at_least"),
            Operand::Literal(8),
            Operand::Literal(1),
        ];
        items.extend(value_command("integer", 8, 1));
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(!decoded.exact);
        assert!(!decoded.degraded);
        assert_eq!(sizes(&decoded), vec![Some(8)]);
        assert_eq!(dsts(&decoded), vec![Some(1)]);
    }

    #[test]
    fn skip_carries_one_stride_operand() {
        let mut items: Vec<Operand> = vec![directive("skip"), Operand::Literal(16)];
        items.extend(value_command("integer", 8, 1));
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(!decoded.degraded);
        assert_eq!(sizes(&decoded), vec![Some(16), Some(8)]);
        assert_eq!(dsts(&decoded), vec![None, Some(1)]);
        assert!(!decoded.segments[0].binds, "a skip binds no variable");
        assert_eq!(decoded.segments[0].segment.unit, 1);
    }

    #[test]
    fn get_tail_carries_three_operands_and_binds_its_destination() {
        let mut items: Vec<Operand> = value_command("integer", 8, 1);
        items.extend([
            directive("get_tail"),
            Operand::Literal(3),
            Operand::Literal(8),
            Operand::XReg(4),
        ]);
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(!decoded.degraded);
        assert_eq!(sizes(&decoded), vec![Some(8), None]);
        assert_eq!(dsts(&decoded), vec![Some(1), Some(4)]);
        let tail: &MatchSegment = &decoded.segments[1];
        assert_eq!(tail.segment.kind, "binary");
        assert_eq!(tail.segment.unit, 8);
        assert!(tail.binds);
    }

    #[test]
    fn literal_equality_carries_three_operands_and_recovers_the_matched_value() {
        let mut items: Vec<Operand> = vec![
            directive("=:="),
            directive("nil"),
            Operand::Literal(8),
            Operand::Literal(97),
        ];
        items.extend(value_command("integer", 16, 2));
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(!decoded.degraded);
        assert_eq!(sizes(&decoded), vec![Some(8), Some(16)]);
        assert_eq!(dsts(&decoded), vec![None, Some(2)]);
        assert!(!decoded.segments[0].binds);
        assert_eq!(*decoded.segments[0].segment.value, Expr::Int(97));
    }

    #[test]
    fn test_tail_closes_the_pattern() {
        let items: Vec<Operand> = vec![directive("test_tail"), Operand::Literal(0)];
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(decoded.exact);
        assert!(decoded.segments.is_empty());
    }

    #[test]
    fn a_register_size_is_reported_for_the_caller_to_resolve() {
        let items: Vec<Operand> = vec![
            directive("binary"),
            Operand::Literal(3),
            Operand::Literal(0),
            Operand::XReg(1),
            Operand::Literal(8),
            Operand::XReg(2),
        ];
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(!decoded.degraded);
        assert_eq!(decoded.segments.len(), 1);
        assert!(
            decoded.segments[0].segment.size.is_none(),
            "a register size is never a literal bit count"
        );
        assert_eq!(decoded.segments[0].size_src, Some(Operand::XReg(1)));
    }

    #[test]
    fn an_unknown_directive_reports_a_degraded_decode() {
        let items: Vec<Operand> = vec![Operand::Atom(u32::MAX), Operand::Literal(1)];
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(decoded.degraded);
        assert!(decoded.segments.is_empty());
    }

    #[test]
    fn a_truncated_value_command_reports_a_degraded_decode() {
        let items: Vec<Operand> = vec![directive("integer"), Operand::Literal(3), signed_flags()];
        let decoded: MatchCommands = decode_match_commands(&items, &chunks());
        assert!(decoded.degraded);
        assert!(decoded.segments.is_empty());
    }

    #[test]
    fn a_legacy_get_reads_its_size_unit_flags_and_destination() {
        let ops: Vec<Operand> = vec![
            Operand::Label(7),
            Operand::XReg(0),
            Operand::Literal(3),
            Operand::Literal(16),
            Operand::Literal(1),
            signed_flags(),
            Operand::XReg(2),
        ];
        let seg: MatchSegment =
            decode_get_segment("bs_get_integer2", &ops, &chunks()).expect("a legacy get decodes");
        assert_eq!(seg.segment.kind, "integer");
        assert_eq!(seg.segment.size.as_deref(), Some(&Expr::Int(16)));
        assert_eq!(seg.segment.unit, 1);
        assert_eq!(seg.segment.flags, vec!["signed".to_owned()]);
        assert_eq!(seg.dst, Some(Operand::XReg(2)));
        assert!(seg.binds);
    }

    #[test]
    fn a_legacy_utf_get_has_no_size_and_binds_its_destination() {
        let ops: Vec<Operand> = vec![
            Operand::Label(7),
            Operand::XReg(0),
            Operand::Literal(3),
            Operand::Literal(0),
            Operand::XReg(1),
        ];
        let seg: MatchSegment =
            decode_get_segment("bs_get_utf8", &ops, &chunks()).expect("a legacy utf get decodes");
        assert_eq!(seg.segment.kind, "utf8");
        assert!(seg.segment.size.is_none());
        assert_eq!(seg.dst, Some(Operand::XReg(1)));
        assert!(seg.binds);
    }

    #[test]
    fn a_legacy_skip_binds_nothing() {
        let ops: Vec<Operand> = vec![
            Operand::Label(7),
            Operand::XReg(0),
            Operand::Literal(32),
            Operand::Literal(1),
            Operand::Literal(0),
        ];
        let seg: MatchSegment =
            decode_skip_segment("bs_skip_bits2", &ops, &chunks()).expect("a legacy skip decodes");
        assert_eq!(seg.segment.size.as_deref(), Some(&Expr::Int(32)));
        assert!(!seg.binds);
        assert_eq!(seg.dst, None);
    }

    fn instr(name: &'static str, operands: Vec<Operand>) -> crate::disasm::Instruction {
        crate::disasm::Instruction {
            offset: 0,
            opcode: 0,
            name,
            operands,
        }
    }

    #[test]
    fn an_exactly_sized_clause_binds_every_variable_its_body_reads() {
        let mut commands: Vec<Operand> = vec![directive("ensure_exactly"), Operand::Literal(24)];
        commands.extend(value_command("integer", 8, 1));
        commands.extend(value_command("integer", 16, 2));
        let instrs: Vec<crate::disasm::Instruction> = vec![
            instr("label", vec![Operand::Literal(1)]),
            instr(
                "bs_start_match3",
                vec![
                    Operand::Label(0),
                    Operand::XReg(0),
                    Operand::Literal(1),
                    Operand::XReg(0),
                ],
            ),
            instr(
                "bs_match",
                vec![Operand::Label(0), Operand::XReg(0), Operand::List(commands)],
            ),
            instr(
                "put_tuple2",
                vec![
                    Operand::XReg(0),
                    Operand::List(vec![Operand::XReg(1), Operand::XReg(2)]),
                ],
            ),
            instr("return", Vec::new()),
        ];

        let (clauses, complete): (Vec<crate::body_lift::expr::FnClause>, bool) =
            crate::body_lift::lift_function(&instrs, 1, &chunks(), &BTreeMap::new());
        assert!(complete, "an exactly sized match is a complete lift");
        assert_eq!(clauses.len(), 1);
        assert_eq!(
            crate::body_lift::render::render_expr(&clauses[0].patterns[0]),
            "<<B0:8/signed, B1:16/signed>>",
            "both segments belong in the head and the size is exact, so no tail is invented"
        );
        assert_eq!(
            crate::body_lift::render::render_body(&clauses[0].body, 0),
            "{B0, B1}",
            "the body reads the pattern variables, never a raw register name"
        );
    }

    #[test]
    fn native_field_flags_survive_the_decode() {
        assert_eq!(bits_to_flags(0b1_0000), vec!["native".to_owned()]);
        assert_eq!(
            bits_to_flags(0b110),
            vec!["little".to_owned(), "signed".to_owned()]
        );
    }
}
