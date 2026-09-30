use super::{
    ATOM_EXPRESSION_DEPTH, AbstentionKind, Expr, Lifter, TargetLang, TokenNamer,
    array_element_type, is_comparison_or_logical, paren, render_bounded_expression,
};
use crate::names::NameTable;

const INFERENCE_DEPTH_LIMIT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntWidth {
    Int32,
    Int64,
    Native,
}

impl IntWidth {
    const fn keyword(self, unsigned: bool) -> &'static str {
        match (self, unsigned) {
            (Self::Int32, false) => "int",
            (Self::Int32, true) => "uint",
            (Self::Int64, false) => "long",
            (Self::Int64, true) => "ulong",
            (Self::Native, false) => "nint",
            (Self::Native, true) => "nuint",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StackKind {
    Int { width: IntWidth, unsigned: bool },
    Float,
    Bool,
    Pointer,
    Reference,
    Unknown,
}

impl StackKind {
    pub(crate) const SIGNED_INT32: Self = Self::Int {
        width: IntWidth::Int32,
        unsigned: false,
    };
    pub(crate) const SIGNED_INT64: Self = Self::Int {
        width: IntWidth::Int64,
        unsigned: false,
    };
    pub(crate) const UNSIGNED_INT32: Self = Self::Int {
        width: IntWidth::Int32,
        unsigned: true,
    };

    pub(crate) fn of_type_name(name: &str) -> Self {
        let name: &str = name.trim();
        match name {
            "bool" | "Boolean" | "System.Boolean" => Self::Bool,
            "sbyte" | "byte" | "short" | "ushort" | "char" | "int" | "System.SByte"
            | "System.Byte" | "System.Int16" | "System.UInt16" | "System.Char" | "System.Int32" => {
                Self::SIGNED_INT32
            }
            "uint" | "System.UInt32" => Self::UNSIGNED_INT32,
            "long" | "System.Int64" => Self::SIGNED_INT64,
            "ulong" | "System.UInt64" => Self::Int {
                width: IntWidth::Int64,
                unsigned: true,
            },
            "nint" | "IntPtr" | "System.IntPtr" => Self::Int {
                width: IntWidth::Native,
                unsigned: false,
            },
            "nuint" | "UIntPtr" | "System.UIntPtr" => Self::Int {
                width: IntWidth::Native,
                unsigned: true,
            },
            "float" | "double" | "System.Single" | "System.Double" => Self::Float,
            "string" | "object" | "String" | "Object" | "System.String" | "System.Object" => {
                Self::Reference
            }
            other if other.ends_with(']') => Self::Reference,
            other if other.ends_with('*') || other.ends_with('&') || other.starts_with("ref ") => {
                Self::Pointer
            }
            _ => Self::Unknown,
        }
    }

    fn of_optional_type_name(name: Option<&str>) -> Self {
        name.map_or(Self::Unknown, Self::of_type_name)
    }

    pub(crate) fn of_element_opcode(opcode: &str) -> Self {
        let suffix: &str = opcode
            .strip_prefix("ldelem.")
            .or_else(|| opcode.strip_prefix("ldind."))
            .unwrap_or_default();
        match suffix {
            "i1" | "u1" | "i2" | "u2" | "i4" => Self::SIGNED_INT32,
            "u4" => Self::UNSIGNED_INT32,
            "r4" | "r8" => Self::Float,
            "ref" => Self::Reference,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signedness {
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArithmeticForm {
    Agnostic,
    Sensitive(Signedness),
    Checked(Signedness),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Comparison {
    Signed,
    Unsigned { true_when_unordered: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConversionSource {
    Signed,
    Unsigned,
    Truncating,
}

impl ConversionSource {
    pub(crate) fn of_opcode(name: &str) -> Self {
        if name.strip_suffix(".un").is_some() || matches!(name, "conv.u8" | "conv.u") {
            Self::Unsigned
        } else if name.starts_with("conv.ovf.")
            || matches!(name, "conv.i8" | "conv.i" | "conv.r4" | "conv.r8")
        {
            Self::Signed
        } else {
            Self::Truncating
        }
    }
}

pub(crate) fn infer_stack_kind(expression: &Expr, names: &NameTable) -> StackKind {
    infer_bounded(expression, names, 0)
}

fn infer_bounded(expression: &Expr, names: &NameTable, depth: usize) -> StackKind {
    if depth > INFERENCE_DEPTH_LIMIT {
        return StackKind::Unknown;
    }
    let next: usize = depth.saturating_add(1);
    match expression {
        Expr::Local(slot) => StackKind::of_optional_type_name(names.local_type(*slot)),
        Expr::Arg(slot) => StackKind::of_optional_type_name(names.arg_type(*slot)),
        Expr::Const(text) => const_kind(text),
        Expr::Cast(ty, _)
        | Expr::UnboxAny {
            target: Some(ty), ..
        } => StackKind::of_type_name(ty),
        Expr::Null
        | Expr::StringLit(_)
        | Expr::This
        | Expr::NewArr { .. }
        | Expr::IsInst { .. }
        | Expr::TypeOf(_) => StackKind::Reference,
        Expr::AddressOf(_) | Expr::MethodPtr { .. } => StackKind::Pointer,
        Expr::Unary(op, operand) => {
            if *op == "!" {
                StackKind::Bool
            } else {
                infer_bounded(operand, names, next)
            }
        }
        Expr::Binary(op, lhs, rhs) => {
            if is_comparison_or_logical(op) {
                StackKind::Bool
            } else {
                combine(
                    infer_bounded(lhs, names, next),
                    is_integer_const(lhs),
                    infer_bounded(rhs, names, next),
                    is_integer_const(rhs),
                )
            }
        }
        Expr::Cond {
            when_true,
            when_false,
            ..
        } => {
            let kind: StackKind = infer_bounded(when_true, names, next);
            if kind == infer_bounded(when_false, names, next) {
                kind
            } else {
                StackKind::Unknown
            }
        }
        Expr::LoadElem(array, _) => {
            StackKind::of_optional_type_name(array_element_type(array, names).as_deref())
        }
        _ => StackKind::Unknown,
    }
}

fn const_kind(text: &str) -> StackKind {
    if matches!(text, "true" | "false") {
        return StackKind::Bool;
    }
    if integer_literal_value(text).is_some() {
        return StackKind::SIGNED_INT32;
    }
    if text
        .strip_suffix('L')
        .and_then(integer_literal_value)
        .is_some()
    {
        return StackKind::SIGNED_INT64;
    }
    let unsuffixed: &str = text.strip_suffix('f').unwrap_or(text);
    if text.starts_with("float.")
        || text.starts_with("double.")
        || unsuffixed.parse::<f64>().is_ok()
    {
        return StackKind::Float;
    }
    StackKind::Unknown
}

fn integer_literal_value(text: &str) -> Option<i64> {
    let digits: &str = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

fn is_integer_const(expression: &Expr) -> bool {
    matches!(expression, Expr::Const(text) if const_kind(text) == StackKind::SIGNED_INT32
        || const_kind(text) == StackKind::SIGNED_INT64)
}

pub(crate) fn combine(
    lhs: StackKind,
    lhs_const: bool,
    rhs: StackKind,
    rhs_const: bool,
) -> StackKind {
    if lhs_const && !rhs_const {
        return rhs;
    }
    if rhs_const && !lhs_const {
        return lhs;
    }
    if lhs == rhs {
        return lhs;
    }
    match (lhs, rhs) {
        (StackKind::Pointer, StackKind::Int { .. })
        | (StackKind::Int { .. }, StackKind::Pointer) => StackKind::Pointer,
        _ => StackKind::Unknown,
    }
}

fn same_width_ints(lhs: StackKind, rhs: StackKind) -> Option<(IntWidth, bool, bool)> {
    match (lhs, rhs) {
        (
            StackKind::Int {
                width: lhs_width,
                unsigned: lhs_unsigned,
            },
            StackKind::Int {
                width: rhs_width,
                unsigned: rhs_unsigned,
            },
        ) if lhs_width == rhs_width => Some((lhs_width, lhs_unsigned, rhs_unsigned)),
        _ => None,
    }
}

fn declared_signedness(operands: [(&Expr, bool); 2]) -> Option<bool> {
    let mut declared: Option<bool> = None;
    for (expression, unsigned) in operands {
        if is_integer_const(expression) {
            continue;
        }
        match declared {
            None => declared = Some(unsigned),
            Some(previous) if previous != unsigned => return None,
            Some(_) => {}
        }
    }
    declared
}

fn may_convert(expression: &Expr, depth: usize) -> bool {
    if depth > INFERENCE_DEPTH_LIMIT {
        return true;
    }
    let next: usize = depth.saturating_add(1);
    match expression {
        Expr::Const(_)
        | Expr::Local(_)
        | Expr::Arg(_)
        | Expr::This
        | Expr::Null
        | Expr::StringLit(_)
        | Expr::Temp { .. } => false,
        Expr::Field { text, .. } | Expr::Raw(text) => text.contains('('),
        Expr::Unary(_, operand)
        | Expr::LoadLen(operand)
        | Expr::Deref(operand)
        | Expr::AddressOf(operand) => may_convert(operand, next),
        Expr::Binary(_, lhs, rhs) | Expr::LoadElem(lhs, rhs) => {
            may_convert(lhs, next) || may_convert(rhs, next)
        }
        Expr::Call { target, args, .. } => {
            target.contains('(') || args.iter().any(|arg: &Expr| may_convert(arg, next))
        }
        _ => true,
    }
}

const fn inverse_relation(op: &'static str) -> Option<&'static str> {
    match op.as_bytes() {
        b"<" => Some(">="),
        b"<=" => Some(">"),
        b">" => Some("<="),
        b">=" => Some("<"),
        _ => None,
    }
}

impl<N: TokenNamer> Lifter<'_, N> {
    fn reinterpret(&self, expression: Expr, width: IntWidth, unsigned: bool) -> Expr {
        let keyword: &'static str = width.keyword(unsigned);
        if let Expr::Const(text) = &expression {
            let value: Option<i64> = match width {
                IntWidth::Int64 => text.strip_suffix('L').and_then(integer_literal_value),
                IntWidth::Int32 | IntWidth::Native => integer_literal_value(text),
            };
            if let Some(value) = value {
                return match (width, unsigned) {
                    (IntWidth::Int32, true) => i32::try_from(value).map_or_else(
                        |_| Expr::Raw(format!("unchecked(({keyword})({value}))")),
                        |narrow: i32| Expr::Const(format!("{}u", narrow.cast_unsigned())),
                    ),
                    (IntWidth::Int64, true) => Expr::Const(format!("{}UL", value.cast_unsigned())),
                    (IntWidth::Native, true) if value < 0 => {
                        Expr::Raw(format!("unchecked(({keyword})({value}))"))
                    }
                    _ => expression,
                };
            }
        }
        Expr::Raw(format!(
            "({keyword}){}",
            paren(&expression, self.lang, self.names)
        ))
    }

    fn guard_unchecked(&self, expression: Expr) -> Expr {
        if may_convert(&expression, 0) {
            let rendered: String = render_bounded_expression(expression, self.lang, self.names);
            Expr::Raw(format!("unchecked({rendered})"))
        } else {
            expression
        }
    }

    fn refuse_operand_kind(&mut self) -> Expr {
        self.abstain(AbstentionKind::UnresolvedOperandKind)
    }

    pub(super) fn arithmetic(&mut self, op: &'static str, form: ArithmeticForm) {
        let (rhs, rhs_depth, rhs_kind): (Expr, usize, StackKind) = self.pop_typed();
        let (lhs, lhs_depth, lhs_kind): (Expr, usize, StackKind) = self.pop_typed();
        let depth: usize = lhs_depth.max(rhs_depth).saturating_add(1);
        let plain_kind: StackKind = combine(
            lhs_kind,
            is_integer_const(&lhs),
            rhs_kind,
            is_integer_const(&rhs),
        );
        let (signedness, checked): (Signedness, bool) = match form {
            ArithmeticForm::Sensitive(signedness) if self.lang == TargetLang::CSharp => {
                (signedness, false)
            }
            ArithmeticForm::Checked(signedness) if self.lang == TargetLang::CSharp => {
                (signedness, true)
            }
            ArithmeticForm::Agnostic
            | ArithmeticForm::Sensitive(_)
            | ArithmeticForm::Checked(_) => {
                let expression: Expr = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
                self.push_entry(expression, depth, plain_kind);
                return;
            }
        };
        let Some((width, lhs_unsigned, rhs_unsigned)): Option<(IntWidth, bool, bool)> =
            same_width_ints(lhs_kind, rhs_kind)
        else {
            if signedness == Signedness::Signed && !checked {
                let expression: Expr = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
                self.push_entry(expression, depth, plain_kind);
            } else {
                let refusal: Expr = self.refuse_operand_kind();
                self.push_entry(refusal, ATOM_EXPRESSION_DEPTH, StackKind::Unknown);
            }
            return;
        };
        let want_unsigned: bool = signedness == Signedness::Unsigned;
        let declared: Option<bool> =
            declared_signedness([(&lhs, lhs_unsigned), (&rhs, rhs_unsigned)]);
        let lhs: Expr = if lhs_unsigned == want_unsigned {
            lhs
        } else {
            self.reinterpret(lhs, width, want_unsigned)
        };
        let rhs: Expr = if rhs_unsigned == want_unsigned {
            rhs
        } else {
            self.reinterpret(rhs, width, want_unsigned)
        };
        let expression: Expr = if checked {
            let lhs: Expr = self.guard_unchecked(lhs);
            let rhs: Expr = self.guard_unchecked(rhs);
            let rendered: String = render_bounded_expression(
                Expr::Binary(op, Box::new(lhs), Box::new(rhs)),
                self.lang,
                self.names,
            );
            Expr::Raw(format!("checked({rendered})"))
        } else {
            Expr::Binary(op, Box::new(lhs), Box::new(rhs))
        };
        match declared {
            Some(unsigned) if unsigned != want_unsigned => {
                let restored: Expr =
                    Expr::Cast(width.keyword(unsigned).to_owned(), Box::new(expression));
                self.push_entry(
                    restored,
                    depth.saturating_add(1),
                    StackKind::Int { width, unsigned },
                );
            }
            _ => self.push_entry(
                expression,
                depth,
                StackKind::Int {
                    width,
                    unsigned: want_unsigned,
                },
            ),
        }
    }

    pub(super) fn shift_right(&mut self, unsigned_shift: bool) {
        let (amount, amount_depth, _): (Expr, usize, StackKind) = self.pop_typed();
        let (value, value_depth, value_kind): (Expr, usize, StackKind) = self.pop_typed();
        let depth: usize = value_depth.max(amount_depth).saturating_add(1);
        let op: &'static str = if unsigned_shift { ">>>" } else { ">>" };
        match value_kind {
            StackKind::Int {
                width,
                unsigned: true,
            } if !unsigned_shift && self.lang == TargetLang::CSharp => {
                let signed: Expr = self.reinterpret(value, width, false);
                let shifted: Expr = Expr::Binary(op, Box::new(signed), Box::new(amount));
                let restored: Expr = Expr::Cast(width.keyword(true).to_owned(), Box::new(shifted));
                self.push_entry(restored, depth.saturating_add(1), value_kind);
            }
            _ => {
                let shifted: Expr = Expr::Binary(op, Box::new(value), Box::new(amount));
                self.push_entry(shifted, depth, value_kind);
            }
        }
    }

    pub(super) fn comparison(&mut self, op: &'static str, semantics: Comparison) -> (Expr, usize) {
        let (rhs, rhs_depth, rhs_kind): (Expr, usize, StackKind) = self.pop_typed();
        let (lhs, lhs_depth, lhs_kind): (Expr, usize, StackKind) = self.pop_typed();
        let depth: usize = lhs_depth.max(rhs_depth).saturating_add(1);
        let plain = |lhs: Expr, rhs: Expr| (Expr::Binary(op, Box::new(lhs), Box::new(rhs)), depth);
        let Some(inverse): Option<&'static str> = inverse_relation(op) else {
            return plain(lhs, rhs);
        };
        if self.lang != TargetLang::CSharp {
            return plain(lhs, rhs);
        }
        match semantics {
            Comparison::Signed => match same_width_ints(lhs_kind, rhs_kind) {
                Some((width, lhs_unsigned, rhs_unsigned)) if lhs_unsigned || rhs_unsigned => {
                    let lhs: Expr = if lhs_unsigned {
                        self.reinterpret(lhs, width, false)
                    } else {
                        lhs
                    };
                    let rhs: Expr = if rhs_unsigned {
                        self.reinterpret(rhs, width, false)
                    } else {
                        rhs
                    };
                    plain(lhs, rhs)
                }
                _ => plain(lhs, rhs),
            },
            Comparison::Unsigned {
                true_when_unordered,
            } => match (lhs_kind, rhs_kind) {
                (StackKind::Float, StackKind::Float) => {
                    if true_when_unordered {
                        let ordered: Expr = Expr::Binary(inverse, Box::new(lhs), Box::new(rhs));
                        (Expr::Unary("!", Box::new(ordered)), depth.saturating_add(1))
                    } else {
                        plain(lhs, rhs)
                    }
                }
                (
                    StackKind::Reference | StackKind::Bool | StackKind::Pointer,
                    StackKind::Reference | StackKind::Bool | StackKind::Pointer,
                )
                | (StackKind::Reference, _)
                | (_, StackKind::Reference) => plain(lhs, rhs),
                _ => match same_width_ints(lhs_kind, rhs_kind) {
                    Some((width, lhs_unsigned, rhs_unsigned)) => {
                        let lhs: Expr = if lhs_unsigned {
                            lhs
                        } else {
                            self.reinterpret(lhs, width, true)
                        };
                        let rhs: Expr = if rhs_unsigned {
                            rhs
                        } else {
                            self.reinterpret(rhs, width, true)
                        };
                        plain(lhs, rhs)
                    }
                    None => (self.refuse_operand_kind(), ATOM_EXPRESSION_DEPTH),
                },
            },
        }
    }

    pub(super) fn push_comparison(&mut self, op: &'static str, semantics: Comparison) {
        let (expression, depth): (Expr, usize) = self.comparison(op, semantics);
        self.push_entry(expression, depth, StackKind::Bool);
    }

    pub(super) fn conversion_operand(
        &mut self,
        opcode: &str,
        target: &'static str,
        checked: bool,
    ) -> Expr {
        let (operand, _, kind): (Expr, usize, StackKind) = self.pop_typed();
        let wanted: Signedness = match ConversionSource::of_opcode(opcode) {
            ConversionSource::Truncating => return operand,
            ConversionSource::Signed => Signedness::Signed,
            ConversionSource::Unsigned => Signedness::Unsigned,
        };
        let want_unsigned: bool = wanted == Signedness::Unsigned;
        match kind {
            StackKind::Int { width, unsigned } if unsigned != want_unsigned => {
                if !checked && width.keyword(want_unsigned) == target {
                    operand
                } else {
                    self.reinterpret(operand, width, want_unsigned)
                }
            }
            StackKind::Int { .. } | StackKind::Float | StackKind::Pointer => operand,
            StackKind::Bool | StackKind::Reference | StackKind::Unknown => {
                if want_unsigned {
                    self.refuse_operand_kind()
                } else {
                    operand
                }
            }
        }
    }

    pub(super) fn checked_operand(&self, operand: Expr) -> Expr {
        self.guard_unchecked(operand)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn type_names_map_to_stack_kinds() {
        assert_eq!(StackKind::of_type_name("int"), StackKind::SIGNED_INT32);
        assert_eq!(StackKind::of_type_name("byte"), StackKind::SIGNED_INT32);
        assert_eq!(StackKind::of_type_name("uint"), StackKind::UNSIGNED_INT32);
        assert_eq!(
            StackKind::of_type_name("System.Int64"),
            StackKind::SIGNED_INT64
        );
        assert_eq!(StackKind::of_type_name("double"), StackKind::Float);
        assert_eq!(StackKind::of_type_name("int[]"), StackKind::Reference);
        assert_eq!(StackKind::of_type_name("byte*"), StackKind::Pointer);
        assert_eq!(StackKind::of_type_name("DayOfWeek"), StackKind::Unknown);
    }

    #[test]
    fn literal_kinds_follow_their_suffix() {
        assert_eq!(const_kind("-7"), StackKind::SIGNED_INT32);
        assert_eq!(const_kind("7L"), StackKind::SIGNED_INT64);
        assert_eq!(const_kind("1.5f"), StackKind::Float);
        assert_eq!(const_kind("double.NaN"), StackKind::Float);
        assert_eq!(const_kind("true"), StackKind::Bool);
        assert_eq!(const_kind("'a'"), StackKind::Unknown);
    }

    #[test]
    fn conversion_sources_follow_the_opcode() {
        assert_eq!(
            ConversionSource::of_opcode("conv.u8"),
            ConversionSource::Unsigned
        );
        assert_eq!(
            ConversionSource::of_opcode("conv.r.un"),
            ConversionSource::Unsigned
        );
        assert_eq!(
            ConversionSource::of_opcode("conv.ovf.u1.un"),
            ConversionSource::Unsigned
        );
        assert_eq!(
            ConversionSource::of_opcode("conv.ovf.u1"),
            ConversionSource::Signed
        );
        assert_eq!(
            ConversionSource::of_opcode("conv.i8"),
            ConversionSource::Signed
        );
        assert_eq!(
            ConversionSource::of_opcode("conv.u4"),
            ConversionSource::Truncating
        );
    }
}
