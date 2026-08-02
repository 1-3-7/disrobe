use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue};
use crate::model::Resolver;
use crate::names::NameTable;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TargetLang {
    #[default]
    CSharp,
    FSharp,
    VbNet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataTokenKind {
    Type,
    Field,
    Method,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMethod {
    pub token: u32,
    pub signature: String,
    pub body: String,
    pub statement_count: u32,
    pub recovered_locals: u32,
    pub recovered_branches: u32,
    pub typed_locals: u32,
    pub named_params: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallInfo {
    pub arg_count: usize,

    pub returns_value: bool,

    pub has_this: bool,

    pub byref_param_mask: u64,
}

impl CallInfo {
    #[must_use]
    fn arg_is_byref(&self, arg_index: usize) -> bool {
        let param_index: usize = arg_index.saturating_sub(usize::from(self.has_this));
        param_index < 64 && self.byref_param_mask & (1u64 << param_index) != 0
    }
}

pub trait TokenNamer {
    fn name(&self, token: u32) -> String;

    fn token_kind(&self, _token: u32) -> MetadataTokenKind {
        MetadataTokenKind::Unknown
    }

    fn field_rva_bytes(&self, _token: u32) -> Option<&[u8]> {
        None
    }

    fn field_rva_primitive(&self, _token: u32) -> Option<FieldRvaPrimitive> {
        None
    }

    fn is_initialize_array(&self, _token: u32) -> bool {
        false
    }

    fn call_info(&self, _token: u32) -> Option<CallInfo> {
        None
    }

    fn enum_param_type(&self, _token: u32, _param_index: usize) -> Option<String> {
        None
    }

    fn param_type_name(&self, _token: u32, _param_index: usize) -> Option<String> {
        None
    }

    fn field_type_name(&self, _token: u32) -> Option<String> {
        None
    }

    fn callee_is_virtual_definition(&self, _token: u32) -> bool {
        false
    }

    fn enclosing_type(&self) -> Option<&str> {
        None
    }

    fn outer_has_this(&self) -> bool {
        true
    }
}

impl TokenNamer for Resolver {
    #[inline]
    fn name(&self, token: u32) -> String {
        self.resolve_token(token)
    }

    #[inline]
    fn token_kind(&self, token: u32) -> MetadataTokenKind {
        self.metadata_token_kind(token)
    }

    #[inline]
    fn field_rva_primitive(&self, token: u32) -> Option<FieldRvaPrimitive> {
        self.field_rva_primitive_from_type_ref(token)
    }

    fn call_info(&self, token: u32) -> Option<CallInfo> {
        self.callee_signature(token).map(|sig| {
            let params: usize = sig.params.len();
            let has_this: bool = sig.has_this;
            let byref_param_mask: u64 = sig
                .params
                .iter()
                .take(64)
                .enumerate()
                .filter(|(_, p): &(usize, &crate::signature::TypeSig)| {
                    matches!(p, crate::signature::TypeSig::ByRef(_))
                })
                .fold(
                    0u64,
                    |acc: u64, (idx, _): (usize, &crate::signature::TypeSig)| acc | (1u64 << idx),
                );
            CallInfo {
                arg_count: params + usize::from(has_this),
                returns_value: !matches!(sig.return_type, crate::signature::TypeSigOrVoid::Void),
                has_this,
                byref_param_mask,
            }
        })
    }

    fn enum_param_type(&self, token: u32, param_index: usize) -> Option<String> {
        self.enum_param_type_name(token, param_index)
    }

    fn param_type_name(&self, token: u32, param_index: usize) -> Option<String> {
        self.callee_param_type_name(token, param_index)
    }

    fn field_type_name(&self, token: u32) -> Option<String> {
        self.field_token_type_name(token)
    }

    fn callee_is_virtual_definition(&self, token: u32) -> bool {
        Self::callee_is_virtual_definition(self, token)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MethodNamer<'a> {
    pub resolver: &'a Resolver,
    pub has_this: bool,
    pub enclosing_type: Option<&'a str>,
}

impl TokenNamer for MethodNamer<'_> {
    #[inline]
    fn name(&self, token: u32) -> String {
        self.resolver.resolve_token(token)
    }

    #[inline]
    fn token_kind(&self, token: u32) -> MetadataTokenKind {
        self.resolver.metadata_token_kind(token)
    }

    #[inline]
    fn field_rva_primitive(&self, token: u32) -> Option<FieldRvaPrimitive> {
        self.resolver.field_rva_primitive_from_type_ref(token)
    }

    #[inline]
    fn call_info(&self, token: u32) -> Option<CallInfo> {
        self.resolver.call_info(token)
    }

    #[inline]
    fn enum_param_type(&self, token: u32, param_index: usize) -> Option<String> {
        self.resolver.enum_param_type_name(token, param_index)
    }

    #[inline]
    fn param_type_name(&self, token: u32, param_index: usize) -> Option<String> {
        self.resolver.callee_param_type_name(token, param_index)
    }

    #[inline]
    fn field_type_name(&self, token: u32) -> Option<String> {
        self.resolver.field_token_type_name(token)
    }

    #[inline]
    fn callee_is_virtual_definition(&self, token: u32) -> bool {
        self.resolver.callee_is_virtual_definition(token)
    }

    #[inline]
    fn enclosing_type(&self) -> Option<&str> {
        self.enclosing_type
    }

    #[inline]
    fn outer_has_this(&self) -> bool {
        self.has_this
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HexNamer;

impl TokenNamer for HexNamer {
    #[inline]
    fn name(&self, token: u32) -> String {
        format!("token_{token:08X}")
    }
}

#[derive(Debug, Clone)]
enum Expr {
    Const(String),
    Local(u32),
    Arg(u32),
    Field(String),
    Unary(&'static str, Box<Self>),
    Binary(&'static str, Box<Self>, Box<Self>),
    Call {
        target: String,
        args: Vec<Self>,
    },
    NewObj {
        ctor: String,
        args: Vec<Self>,
    },
    Tuple(Vec<Self>),
    Coalesce(Box<Self>, Box<Self>),
    Cast(String, Box<Self>),
    IsInst(String, Box<Self>),
    LoadElem(Box<Self>, Box<Self>),
    LoadLen(Box<Self>),
    NewArr {
        ty: String,
        element_token: u32,
        allocation_id: u64,
        length: Box<Self>,
        elements: Vec<Self>,
    },
    AddressOf(Box<Self>),
    Deref(Box<Self>),
    StringLit(String),
    Null,
    This,
    MethodPtr {
        receiver: Option<Box<Self>>,
        method: String,
    },
    TypeHandle(String),
    FieldHandle(u32),
    MethodHandle(u32),
    OpaqueHandle(u32),
    TypeOf(String),
    Raw(String),
}

const MAX_EXPR_DEPTH: usize = 256;
const UNRECOVERED_EXPRESSION: &str = "__unrecovered_expression";
const UNRECONSTRUCTED_RUNTIME_HANDLE: &str = "__unreconstructed_runtime_handle";

fn runtime_handle_refusal(lang: TargetLang, handle_type: &str, detail: &str) -> String {
    match lang {
        TargetLang::CSharp => format!(
            "(new System.Func<{handle_type}>(() => {{ throw new System.NotSupportedException(\"{detail}\"); }}))()"
        ),
        TargetLang::FSharp => format!(
            "((fun () -> raise (System.NotSupportedException(\"{detail}\")))() : {handle_type})"
        ),
        TargetLang::VbNet => format!(
            "(New System.Func(Of {handle_type})(Function()\nThrow New System.NotSupportedException(\"{detail}\")\nEnd Function)).Invoke()"
        ),
    }
}

impl Expr {
    fn render(&self, lang: TargetLang, names: &NameTable) -> String {
        render_expr(RenderAction::Expr(self), lang, names)
    }

    fn unlink_children(&mut self, pending: &mut Vec<Self>) {
        match self {
            Self::Unary(_, child)
            | Self::Cast(_, child)
            | Self::IsInst(_, child)
            | Self::LoadLen(child)
            | Self::AddressOf(child)
            | Self::Deref(child) => {
                let child: Self = std::mem::replace(child.as_mut(), Self::Raw(String::new()));
                pending.push(child);
            }
            Self::NewArr {
                length, elements, ..
            } => {
                let child: Self = std::mem::replace(length.as_mut(), Self::Raw(String::new()));
                pending.push(child);
                pending.extend(std::mem::take(elements));
            }
            Self::Binary(_, lhs, rhs) | Self::Coalesce(lhs, rhs) | Self::LoadElem(lhs, rhs) => {
                let lhs: Self = std::mem::replace(lhs.as_mut(), Self::Raw(String::new()));
                let rhs: Self = std::mem::replace(rhs.as_mut(), Self::Raw(String::new()));
                pending.push(lhs);
                pending.push(rhs);
            }
            Self::Call { args, .. } | Self::NewObj { args, .. } | Self::Tuple(args) => {
                pending.extend(std::mem::take(args));
            }
            Self::MethodPtr { receiver, .. } => {
                if let Some(child) = receiver.take() {
                    pending.push(*child);
                }
            }
            Self::Const(_)
            | Self::Local(_)
            | Self::Arg(_)
            | Self::Field(_)
            | Self::StringLit(_)
            | Self::Null
            | Self::This
            | Self::TypeHandle(_)
            | Self::FieldHandle(_)
            | Self::MethodHandle(_)
            | Self::OpaqueHandle(_)
            | Self::TypeOf(_)
            | Self::Raw(_) => {}
        }
    }

    const fn is_atom(&self) -> bool {
        matches!(
            self,
            Self::Const(_)
                | Self::Local(_)
                | Self::Arg(_)
                | Self::Field(_)
                | Self::Raw(_)
                | Self::StringLit(_)
                | Self::Null
                | Self::This
                | Self::Call { .. }
                | Self::NewObj { .. }
                | Self::Tuple(_)
                | Self::LoadElem(_, _)
                | Self::LoadLen(_)
                | Self::MethodPtr { .. }
                | Self::TypeOf(_)
        )
    }
}

impl Drop for Expr {
    fn drop(&mut self) {
        let mut pending: Vec<Self> = Vec::new();
        self.unlink_children(&mut pending);
        while let Some(mut expression) = pending.pop() {
            expression.unlink_children(&mut pending);
        }
    }
}

fn expression_depth(expression: &Expr) -> usize {
    let mut maximum: usize = 0;
    let mut pending: Vec<(&Expr, usize)> = vec![(expression, 1)];
    loop {
        let next: Option<(&Expr, usize)> = pending.pop();
        let Some((current, depth)) = next else {
            break;
        };
        maximum = maximum.max(depth);
        if maximum > MAX_EXPR_DEPTH {
            return maximum;
        }
        let child_depth: usize = depth.saturating_add(1);
        match current {
            Expr::Unary(_, child)
            | Expr::Cast(_, child)
            | Expr::IsInst(_, child)
            | Expr::LoadLen(child)
            | Expr::AddressOf(child)
            | Expr::Deref(child)
            | Expr::MethodPtr {
                receiver: Some(child),
                ..
            } => pending.push((child, child_depth)),
            Expr::NewArr {
                length, elements, ..
            } => {
                pending.push((length, child_depth));
                for child in elements {
                    pending.push((child, child_depth));
                }
            }
            Expr::Binary(_, lhs, rhs) | Expr::Coalesce(lhs, rhs) | Expr::LoadElem(lhs, rhs) => {
                pending.push((lhs, child_depth));
                pending.push((rhs, child_depth));
            }
            Expr::Call { args, .. } | Expr::NewObj { args, .. } | Expr::Tuple(args) => {
                for child in args {
                    pending.push((child, child_depth));
                }
            }
            Expr::Const(_)
            | Expr::Local(_)
            | Expr::Arg(_)
            | Expr::Field(_)
            | Expr::StringLit(_)
            | Expr::Null
            | Expr::This
            | Expr::MethodPtr { receiver: None, .. }
            | Expr::TypeHandle(_)
            | Expr::FieldHandle(_)
            | Expr::MethodHandle(_)
            | Expr::OpaqueHandle(_)
            | Expr::TypeOf(_)
            | Expr::Raw(_) => {}
        }
    }
    maximum
}

fn bounded_expression(expression: Expr, depth: usize) -> (Expr, usize) {
    if depth > MAX_EXPR_DEPTH {
        (Expr::Raw(UNRECOVERED_EXPRESSION.to_owned()), 1)
    } else {
        (expression, depth)
    }
}

fn render_bounded_expression(expression: Expr, lang: TargetLang, names: &NameTable) -> String {
    let depth: usize = expression_depth(&expression);
    let (expression, _): (Expr, usize) = bounded_expression(expression, depth);
    expression.render(lang, names)
}

enum RenderAction<'a> {
    Expr(&'a Expr),
    Paren(&'a Expr),
    Args(&'a [Expr], usize),
    Text(&'a str),
    Short(&'a str),
}

fn render_expr(initial: RenderAction<'_>, lang: TargetLang, names: &NameTable) -> String {
    let mut output: String = String::new();
    let mut pending: Vec<RenderAction<'_>> = vec![initial];
    while let Some(action) = pending.pop() {
        match action {
            RenderAction::Text(text) => output.push_str(text),
            RenderAction::Short(text) => output.push_str(&short(text)),
            RenderAction::Paren(expression) => {
                if expression.is_atom() {
                    pending.push(RenderAction::Expr(expression));
                } else {
                    pending.push(RenderAction::Text(")"));
                    pending.push(RenderAction::Expr(expression));
                    pending.push(RenderAction::Text("("));
                }
            }
            RenderAction::Args(args, index) => {
                if let Some(expression) = args.get(index) {
                    if index + 1 < args.len() {
                        pending.push(RenderAction::Args(args, index + 1));
                        pending.push(RenderAction::Text(", "));
                    }
                    pending.push(RenderAction::Expr(expression));
                }
            }
            RenderAction::Expr(expression) => match expression {
                Expr::Const(text) | Expr::Field(text) | Expr::Raw(text) => {
                    output.push_str(text);
                }
                Expr::TypeHandle(_) => {
                    output.push_str(&runtime_handle_refusal(
                        lang,
                        "System.RuntimeTypeHandle",
                        UNRECONSTRUCTED_RUNTIME_HANDLE,
                    ));
                }
                Expr::FieldHandle(token) => {
                    output.push_str(&runtime_handle_refusal(
                        lang,
                        "System.RuntimeFieldHandle",
                        &format!("{UNRECONSTRUCTED_RUNTIME_HANDLE}: 0x{token:08X}"),
                    ));
                }
                Expr::MethodHandle(token) => {
                    output.push_str(&runtime_handle_refusal(
                        lang,
                        "System.RuntimeMethodHandle",
                        &format!("{UNRECONSTRUCTED_RUNTIME_HANDLE}: 0x{token:08X}"),
                    ));
                }
                Expr::OpaqueHandle(token) => {
                    output.push_str(&runtime_handle_refusal(
                        lang,
                        "System.RuntimeTypeHandle",
                        &format!("{UNRECONSTRUCTED_RUNTIME_HANDLE}: 0x{token:08X}"),
                    ));
                }
                Expr::TypeOf(ty) => {
                    output.push_str("typeof(");
                    output.push_str(ty);
                    output.push(')');
                }
                Expr::Local(index) => output.push_str(&NameTable::local_name(*index)),
                Expr::Arg(index) => output.push_str(&names.arg_name(*index)),
                Expr::Unary(op, operand) => {
                    output.push_str(map_unary_op(op, lang));
                    pending.push(RenderAction::Paren(operand));
                }
                Expr::Binary(op, lhs, rhs) => {
                    pending.push(RenderAction::Paren(rhs));
                    pending.push(RenderAction::Text(" "));
                    pending.push(RenderAction::Text(map_binary_op(op, lang)));
                    pending.push(RenderAction::Text(" "));
                    pending.push(RenderAction::Paren(lhs));
                }
                Expr::Call { target, args } => {
                    output.push_str(target);
                    output.push('(');
                    pending.push(RenderAction::Text(")"));
                    pending.push(RenderAction::Args(args, 0));
                }
                Expr::NewObj { ctor, args } => {
                    if lang == TargetLang::CSharp {
                        output.push_str("new ");
                    } else if lang == TargetLang::VbNet {
                        output.push_str("New ");
                    }
                    output.push_str(ctor);
                    output.push('(');
                    pending.push(RenderAction::Text(")"));
                    pending.push(RenderAction::Args(args, 0));
                }
                Expr::Tuple(elements) => {
                    output.push('(');
                    pending.push(RenderAction::Text(")"));
                    pending.push(RenderAction::Args(elements, 0));
                }
                Expr::Coalesce(lhs, rhs) => match lang {
                    TargetLang::CSharp => {
                        pending.push(RenderAction::Paren(rhs));
                        pending.push(RenderAction::Text(" ?? "));
                        pending.push(RenderAction::Paren(lhs));
                    }
                    TargetLang::FSharp => {
                        pending.push(RenderAction::Text(")"));
                        pending.push(RenderAction::Paren(rhs));
                        pending.push(RenderAction::Text(" else "));
                        pending.push(RenderAction::Paren(lhs));
                        pending.push(RenderAction::Text(" then "));
                        pending.push(RenderAction::Text(" <> null"));
                        pending.push(RenderAction::Paren(lhs));
                        pending.push(RenderAction::Text("(if "));
                    }
                    TargetLang::VbNet => {
                        pending.push(RenderAction::Text(")"));
                        pending.push(RenderAction::Paren(rhs));
                        pending.push(RenderAction::Text(", "));
                        pending.push(RenderAction::Paren(lhs));
                        pending.push(RenderAction::Text("If("));
                    }
                },
                Expr::Cast(ty, operand) => match lang {
                    TargetLang::CSharp => {
                        output.push('(');
                        output.push_str(ty);
                        output.push(')');
                        pending.push(RenderAction::Paren(operand));
                    }
                    TargetLang::FSharp => {
                        pending.push(RenderAction::Text(")"));
                        pending.push(RenderAction::Text(ty));
                        pending.push(RenderAction::Text(" :?> "));
                        pending.push(RenderAction::Expr(operand));
                        pending.push(RenderAction::Text("("));
                    }
                    TargetLang::VbNet => {
                        pending.push(RenderAction::Text(")"));
                        pending.push(RenderAction::Text(ty));
                        pending.push(RenderAction::Text(", "));
                        pending.push(RenderAction::Expr(operand));
                        pending.push(RenderAction::Text("CType("));
                    }
                },
                Expr::IsInst(ty, operand) => match lang {
                    TargetLang::CSharp => {
                        pending.push(RenderAction::Text(ty));
                        pending.push(RenderAction::Text(" as "));
                        pending.push(RenderAction::Paren(operand));
                    }
                    TargetLang::FSharp => {
                        pending.push(RenderAction::Text(")"));
                        pending.push(RenderAction::Text(ty));
                        pending.push(RenderAction::Text(" :?> "));
                        pending.push(RenderAction::Expr(operand));
                        pending.push(RenderAction::Text("("));
                    }
                    TargetLang::VbNet => {
                        pending.push(RenderAction::Text(")"));
                        pending.push(RenderAction::Text(ty));
                        pending.push(RenderAction::Text(", "));
                        pending.push(RenderAction::Expr(operand));
                        pending.push(RenderAction::Text("TryCast("));
                    }
                },
                Expr::LoadElem(array, index) => {
                    pending.push(RenderAction::Text("]"));
                    pending.push(RenderAction::Expr(index));
                    pending.push(RenderAction::Text("["));
                    pending.push(RenderAction::Paren(array));
                }
                Expr::LoadLen(array) => {
                    pending.push(RenderAction::Text(".Length"));
                    pending.push(RenderAction::Paren(array));
                }
                Expr::NewArr {
                    ty,
                    length,
                    elements,
                    ..
                } => {
                    output.push_str("new ");
                    output.push_str(ty);
                    output.push('[');
                    if elements.is_empty() {
                        pending.push(RenderAction::Text("]"));
                    } else {
                        let unset: usize = const_operand_value(length)
                            .unwrap_or_default()
                            .saturating_sub(elements.len());
                        pending.push(RenderAction::Text(" }"));
                        for _ in 0..unset {
                            pending.push(RenderAction::Text(", default"));
                        }
                        pending.push(RenderAction::Args(elements, 0));
                        pending.push(RenderAction::Text("] { "));
                    }
                    pending.push(RenderAction::Expr(length));
                }
                Expr::AddressOf(operand) => match lang {
                    TargetLang::CSharp | TargetLang::FSharp => {
                        output.push('&');
                        pending.push(RenderAction::Paren(operand));
                    }
                    TargetLang::VbNet => pending.push(RenderAction::Expr(operand)),
                },
                Expr::Deref(operand) => match lang {
                    TargetLang::CSharp if is_managed_byref_expr(operand, names) => {
                        pending.push(RenderAction::Expr(operand));
                    }
                    TargetLang::CSharp => {
                        output.push('*');
                        pending.push(RenderAction::Paren(operand));
                    }
                    TargetLang::FSharp => {
                        pending.push(RenderAction::Text(".Value"));
                        pending.push(RenderAction::Paren(operand));
                    }
                    TargetLang::VbNet => pending.push(RenderAction::Expr(operand)),
                },
                Expr::StringLit(text) => {
                    output.push('"');
                    output.push_str(&escape(text));
                    output.push('"');
                }
                Expr::Null => {
                    output.push_str(if lang == TargetLang::VbNet {
                        "Nothing"
                    } else {
                        "null"
                    });
                }
                Expr::This => {
                    output.push_str(if lang == TargetLang::VbNet {
                        "Me"
                    } else {
                        "this"
                    });
                }
                Expr::MethodPtr { receiver, method } => match receiver {
                    Some(receiver) => {
                        pending.push(RenderAction::Short(method));
                        pending.push(RenderAction::Text("."));
                        pending.push(RenderAction::Paren(receiver));
                    }
                    None => output.push_str(&short(method)),
                },
            },
        }
    }
    output
}

const MAX_ARRAY_LITERAL_ELEMENTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldRvaPrimitive {
    Boolean,
    Char,
    I1,
    U1,
    I2,
    U2,
    I4,
    U4,
    I8,
    U8,
}

impl FieldRvaPrimitive {
    const fn width(self) -> usize {
        match self {
            Self::Boolean | Self::I1 | Self::U1 => 1,
            Self::Char | Self::I2 | Self::U2 => 2,
            Self::I4 | Self::U4 => 4,
            Self::I8 | Self::U8 => 8,
        }
    }

    fn decode(self, bytes: &[u8]) -> Option<Expr> {
        let literal: String = match self {
            Self::Boolean => match bytes {
                [0] => "false".to_owned(),
                [1] => "true".to_owned(),
                _ => return None,
            },
            Self::Char => char_literal(&u16::from_le_bytes(bytes.try_into().ok()?).to_string())?,
            Self::I1 => i8::from_le_bytes(bytes.try_into().ok()?).to_string(),
            Self::U1 => u8::from_le_bytes(bytes.try_into().ok()?).to_string(),
            Self::I2 => i16::from_le_bytes(bytes.try_into().ok()?).to_string(),
            Self::U2 => u16::from_le_bytes(bytes.try_into().ok()?).to_string(),
            Self::I4 => i32::from_le_bytes(bytes.try_into().ok()?).to_string(),
            Self::U4 => format!("{}U", u32::from_le_bytes(bytes.try_into().ok()?)),
            Self::I8 => format!("{}L", i64::from_le_bytes(bytes.try_into().ok()?)),
            Self::U8 => format!("{}UL", u64::from_le_bytes(bytes.try_into().ok()?)),
        };
        Some(Expr::Const(literal))
    }
}

const fn boolean_literal(text: &str) -> Option<&'static str> {
    match text.as_bytes() {
        b"0" => Some("false"),
        b"1" => Some("true"),
        _ => None,
    }
}

fn char_literal(text: &str) -> Option<String> {
    let code_unit: u16 = text.parse::<u16>().ok()?;
    let escaped: String = match code_unit {
        0x0027 => "\\'".to_owned(),
        0x005C => "\\\\".to_owned(),
        0x0020..=0x007E => char::from_u32(u32::from(code_unit))?.to_string(),
        _ => format!("\\u{code_unit:04X}"),
    };
    Some(format!("'{escaped}'"))
}

fn is_char_type_name(ty: &str) -> bool {
    matches!(ty.trim(), "char" | "Char" | "System.Char")
}

fn coerced_literal(value: &str, target_type: &str, lang: TargetLang) -> Option<String> {
    if lang != TargetLang::CSharp || !is_bare_integer_literal(value) {
        return None;
    }
    if is_bool_type_name(target_type.trim()) {
        return boolean_literal(value).map(str::to_owned);
    }
    if is_char_type_name(target_type) {
        return char_literal(value);
    }
    None
}

fn array_element_type(array: &Expr, names: &NameTable) -> Option<String> {
    let declared: &str = match array {
        Expr::NewArr { ty, .. } => return Some(ty.clone()),
        Expr::Local(slot) => names.local_type(*slot)?,
        Expr::Arg(slot) => names.arg_type(*slot)?,
        _ => return None,
    };
    declared.strip_suffix("[]").map(str::to_owned)
}

fn coerce_constant(value: Expr, target_type: Option<&str>, lang: TargetLang) -> Expr {
    let literal: Option<String> = match (&value, target_type) {
        (Expr::Const(text), Some(ty)) => coerced_literal(text, ty, lang),
        _ => None,
    };
    literal.map_or(value, Expr::Const)
}

fn const_operand_value(expression: &Expr) -> Option<usize> {
    match expression {
        Expr::Const(text) => text.parse::<usize>().ok(),
        _ => None,
    }
}

fn paren(e: &Expr, lang: TargetLang, names: &NameTable) -> String {
    render_expr(RenderAction::Paren(e), lang, names)
}

fn call_receiver(e: &Expr, lang: TargetLang, names: &NameTable) -> String {
    match e {
        Expr::AddressOf(inner) => paren(inner, lang, names),
        other => paren(other, lang, names),
    }
}

fn deref_target(addr: &Expr, lang: TargetLang, names: &NameTable) -> String {
    match addr {
        Expr::AddressOf(inner) => inner.render(lang, names),
        other if lang == TargetLang::CSharp && is_managed_byref_expr(other, names) => {
            other.render(lang, names)
        }
        other => format!("*{}", paren(other, lang, names)),
    }
}

fn is_managed_byref_expr(e: &Expr, names: &NameTable) -> bool {
    match e {
        Expr::Arg(n) => names.arg_is_managed_byref(*n),
        Expr::Local(n) => names.local_is_managed_byref(*n),
        _ => false,
    }
}

fn is_singleton_field(name: &str) -> bool {
    let short: &str = name.rsplit("::").next().unwrap_or(name);
    short == "<>9" || short.starts_with("<>9__")
}

fn is_value_tuple_ctor(ctor: &str) -> bool {
    ctor == "ValueTuple" || ctor.starts_with("ValueTuple<")
}

fn is_tuple_factory_owner(raw: &str) -> bool {
    let Some((owner, _)): Option<(&str, &str)> = raw.rsplit_once("::") else {
        return false;
    };
    let owner_short: &str = owner.rsplit('.').next().unwrap_or(owner);
    let base: &str = owner_short.split('<').next().unwrap_or(owner_short);
    base == "Tuple" || base == "ValueTuple"
}

fn property_getter_name(member: &str) -> Option<&str> {
    let name: &str = member.strip_prefix("get_")?;
    if is_property_identifier(name) {
        Some(name)
    } else {
        None
    }
}

fn property_setter_name(member: &str) -> Option<&str> {
    let name: &str = member.strip_prefix("set_")?;
    if is_property_identifier(name) {
        Some(name)
    } else {
        None
    }
}

fn is_indexer_property(name: &str) -> bool {
    matches!(name, "Item" | "Chars")
}

fn is_property_identifier(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn binary_operator_special_name(member: &str) -> Option<&'static str> {
    match member {
        "op_Equality" => Some("=="),
        "op_Inequality" => Some("!="),
        "op_GreaterThan" => Some(">"),
        "op_LessThan" => Some("<"),
        "op_GreaterThanOrEqual" => Some(">="),
        "op_LessThanOrEqual" => Some("<="),
        "op_Addition" => Some("+"),
        "op_Subtraction" => Some("-"),
        "op_Multiply" => Some("*"),
        "op_Division" => Some("/"),
        "op_Modulus" => Some("%"),
        "op_BitwiseAnd" => Some("&"),
        "op_BitwiseOr" => Some("|"),
        "op_ExclusiveOr" => Some("^"),
        "op_LeftShift" => Some("<<"),
        "op_RightShift" => Some(">>"),
        _ => None,
    }
}

fn unary_operator_special_name(member: &str) -> Option<&'static str> {
    match member {
        "op_UnaryNegation" => Some("-"),
        "op_UnaryPlus" => Some("+"),
        "op_LogicalNot" => Some("!"),
        "op_OnesComplement" => Some("~"),
        _ => None,
    }
}

fn map_binary_op(op: &str, lang: TargetLang) -> &'static str {
    match (op, lang) {
        ("&&", TargetLang::VbNet) => "AndAlso",
        ("||", TargetLang::VbNet) => "OrElse",
        ("==", TargetLang::VbNet) => "=",
        ("!=", TargetLang::VbNet) => "<>",
        ("+", _) => "+",
        ("-", _) => "-",
        ("*", _) => "*",
        ("/", _) => "/",
        ("%", _) => "%",
        ("&", _) => "&",
        ("|", _) => "|",
        ("^", _) => "^",
        ("<<", _) => "<<",
        (">>", _) | (">>>", TargetLang::VbNet) => ">>",
        (">>>", _) => ">>>",
        ("==", _) => "==",
        ("!=", _) => "!=",
        (">", _) => ">",
        ("<", _) => "<",
        (">=", _) => ">=",
        ("<=", _) => "<=",
        ("&&", _) => "&&",
        ("||", _) => "||",
        _ => "?",
    }
}

fn map_unary_op(op: &str, lang: TargetLang) -> &'static str {
    match (op, lang) {
        ("!", TargetLang::FSharp) => "not ",
        ("!", TargetLang::VbNet) => "Not ",
        ("-", _) => "-",
        ("+", _) => "+",
        ("~", _) => "~",
        _ => "!",
    }
}

fn conv_csharp_target(name: &str) -> Option<(&'static str, bool)> {
    let checked: bool = name.starts_with("conv.ovf.");
    let ty: &'static str = match name {
        "conv.i1" | "conv.ovf.i1" | "conv.ovf.i1.un" => "sbyte",
        "conv.u1" | "conv.ovf.u1" | "conv.ovf.u1.un" => "byte",
        "conv.i2" | "conv.ovf.i2" | "conv.ovf.i2.un" => "short",
        "conv.u2" | "conv.ovf.u2" | "conv.ovf.u2.un" => "ushort",
        "conv.i4" | "conv.ovf.i4" | "conv.ovf.i4.un" => "int",
        "conv.u4" | "conv.ovf.u4" | "conv.ovf.u4.un" => "uint",
        "conv.i8" | "conv.ovf.i8" | "conv.ovf.i8.un" => "long",
        "conv.u8" | "conv.ovf.u8" | "conv.ovf.u8.un" => "ulong",
        "conv.i" | "conv.ovf.i" | "conv.ovf.i.un" => "nint",
        "conv.u" | "conv.ovf.u" | "conv.ovf.u.un" => "nuint",
        "conv.r4" => "float",
        "conv.r8" | "conv.r.un" => "double",
        _ => return None,
    };
    Some((ty, checked))
}

#[must_use]
pub(crate) fn csharp_string_literal(s: &str) -> String {
    format!("\"{}\"", escape(s))
}

#[must_use]
pub fn csharp_escape_identifier(name: &str) -> String {
    if name.is_empty() || name.starts_with('@') || !is_csharp_keyword(name) {
        name.to_owned()
    } else {
        format!("@{name}")
    }
}

fn is_csharp_keyword(s: &str) -> bool {
    matches!(
        s,
        "abstract"
            | "as"
            | "base"
            | "bool"
            | "break"
            | "byte"
            | "case"
            | "catch"
            | "char"
            | "checked"
            | "class"
            | "const"
            | "continue"
            | "decimal"
            | "default"
            | "delegate"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "event"
            | "explicit"
            | "extern"
            | "false"
            | "finally"
            | "fixed"
            | "float"
            | "for"
            | "foreach"
            | "goto"
            | "if"
            | "implicit"
            | "in"
            | "int"
            | "interface"
            | "internal"
            | "is"
            | "lock"
            | "long"
            | "namespace"
            | "new"
            | "null"
            | "object"
            | "operator"
            | "out"
            | "override"
            | "params"
            | "private"
            | "protected"
            | "public"
            | "readonly"
            | "ref"
            | "return"
            | "sbyte"
            | "sealed"
            | "short"
            | "sizeof"
            | "stackalloc"
            | "static"
            | "string"
            | "struct"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "uint"
            | "ulong"
            | "unchecked"
            | "unsafe"
            | "ushort"
            | "using"
            | "virtual"
            | "void"
            | "volatile"
            | "while"
    )
}

fn csharp_double(v: f64) -> String {
    if v.is_nan() {
        "double.NaN".to_owned()
    } else if v.is_infinite() {
        if v.is_sign_negative() {
            "double.NegativeInfinity".to_owned()
        } else {
            "double.PositiveInfinity".to_owned()
        }
    } else {
        format!("{v}D")
    }
}

fn csharp_single(v: f32) -> String {
    if v.is_nan() {
        "float.NaN".to_owned()
    } else if v.is_infinite() {
        if v.is_sign_negative() {
            "float.NegativeInfinity".to_owned()
        } else {
            "float.PositiveInfinity".to_owned()
        }
    } else {
        format!("{v}f")
    }
}

fn escape(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone)]
enum Stmt {
    Assign { target: String, value: String },
    Expr(String),
    Return(Option<String>),
    Throw(Option<String>),
    Comment(String),
}

struct Lifter<'a, N: TokenNamer> {
    namer: &'a N,
    names: &'a NameTable,
    lang: TargetLang,
    stack: Vec<Expr>,
    stack_depths: Vec<usize>,
    stmts: Vec<Stmt>,
    locals_used: BTreeSet<u32>,
    locals_assigned: BTreeSet<u32>,
    pending_null_cond: bool,
    next_array_id: u64,
}

impl<'a, N: TokenNamer> Lifter<'a, N> {
    const fn new(namer: &'a N, names: &'a NameTable, lang: TargetLang) -> Self {
        Self {
            namer,
            names,
            lang,
            stack: Vec::new(),
            stack_depths: Vec::new(),
            stmts: Vec::new(),
            locals_used: BTreeSet::new(),
            locals_assigned: BTreeSet::new(),
            pending_null_cond: false,
            next_array_id: 0,
        }
    }

    #[inline]
    fn push(&mut self, e: Expr) {
        let depth: usize = expression_depth(&e);
        self.push_with_depth(e, depth);
    }

    #[inline]
    fn push_with_depth(&mut self, expression: Expr, depth: usize) {
        let (expression, depth): (Expr, usize) = bounded_expression(expression, depth);
        self.stack.push(expression);
        self.stack_depths.push(depth);
    }

    #[inline]
    fn pop(&mut self) -> Expr {
        self.pop_with_depth().0
    }

    #[inline]
    fn pop_with_depth(&mut self) -> (Expr, usize) {
        let expression: Expr = self
            .stack
            .pop()
            .unwrap_or_else(|| Expr::Raw("__stack_underflow".to_owned()));
        let depth: usize = self.stack_depths.pop().unwrap_or(1);
        (expression, depth)
    }

    fn clear_stack(&mut self) {
        self.stack.clear();
        self.stack_depths.clear();
    }

    fn pop_n(&mut self, n: usize) -> Vec<Expr> {
        let mut v: Vec<Expr> = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.pop());
        }
        v.reverse();
        v
    }

    fn append_to_duplicated_array_literal(
        &mut self,
        array: &Expr,
        index: &Expr,
        value: Expr,
    ) -> std::result::Result<(), Expr> {
        if self.lang != TargetLang::CSharp {
            return Err(value);
        }
        let Expr::NewArr {
            ty,
            allocation_id,
            length,
            elements,
            ..
        } = array
        else {
            return Err(value);
        };
        let (Some(slot), Some(capacity)): (Option<usize>, Option<usize>) =
            (const_operand_value(index), const_operand_value(length))
        else {
            return Err(value);
        };
        if slot != elements.len() || slot >= capacity || capacity > MAX_ARRAY_LITERAL_ELEMENTS {
            return Err(value);
        }
        let duplicated: bool = match self.stack.last() {
            Some(Expr::NewArr {
                ty: twin_ty,
                allocation_id: twin_allocation_id,
                length: twin_length,
                elements: twin_elements,
                ..
            }) => {
                twin_ty == ty
                    && twin_allocation_id == allocation_id
                    && twin_elements.len() == elements.len()
                    && const_operand_value(twin_length).is_some_and(|len: usize| len == capacity)
            }
            _ => false,
        };
        if !duplicated {
            return Err(value);
        }
        let Some(Expr::NewArr {
            elements: twin_elements,
            ..
        }) = self.stack.last_mut()
        else {
            return Err(value);
        };
        twin_elements.push(value);
        if let Some(top) = self.stack.last()
            && let Some(depth) = self.stack_depths.last_mut()
        {
            *depth = expression_depth(top);
        }
        Ok(())
    }

    fn populate_field_rva_duplicate_array(&mut self, array: &Expr, field_token: u32) -> bool {
        if self.lang != TargetLang::CSharp {
            return false;
        }
        let Expr::NewArr {
            element_token,
            allocation_id,
            length,
            elements,
            ..
        } = array
        else {
            return false;
        };
        if !elements.is_empty() {
            return false;
        }
        let Some(capacity): Option<usize> = const_operand_value(length) else {
            return false;
        };
        if capacity == 0 || capacity > MAX_ARRAY_LITERAL_ELEMENTS {
            return false;
        }
        let Some(primitive): Option<FieldRvaPrimitive> =
            self.namer.field_rva_primitive(*element_token)
        else {
            return false;
        };
        let Some(expected_bytes): Option<usize> = capacity.checked_mul(primitive.width()) else {
            return false;
        };
        let Some(bytes): Option<&[u8]> = self.namer.field_rva_bytes(field_token) else {
            return false;
        };
        if bytes.len() != expected_bytes {
            return false;
        }
        let mut decoded: Vec<Expr> = Vec::with_capacity(capacity);
        for chunk in bytes.chunks_exact(primitive.width()) {
            let Some(value): Option<Expr> = primitive.decode(chunk) else {
                return false;
            };
            decoded.push(value);
        }
        let duplicated: bool = match self.stack.last() {
            Some(Expr::NewArr {
                element_token: twin_element_token,
                allocation_id: twin_allocation_id,
                length: twin_length,
                elements: twin_elements,
                ..
            }) => {
                twin_element_token == element_token
                    && twin_allocation_id == allocation_id
                    && twin_elements.is_empty()
                    && const_operand_value(twin_length).is_some_and(|len: usize| len == capacity)
            }
            _ => false,
        };
        if !duplicated {
            return false;
        }
        let Some(Expr::NewArr {
            elements: twin_elements,
            ..
        }) = self.stack.last_mut()
        else {
            return false;
        };
        twin_elements.extend(decoded);
        if let Some(top) = self.stack.last()
            && let Some(depth) = self.stack_depths.last_mut()
        {
            *depth = expression_depth(top);
        }
        true
    }

    fn binary(&mut self, op: &'static str) {
        let (b, b_depth): (Expr, usize) = self.pop_with_depth();
        let (a, a_depth): (Expr, usize) = self.pop_with_depth();
        let depth: usize = a_depth.max(b_depth).saturating_add(1);
        self.push_with_depth(Expr::Binary(op, Box::new(a), Box::new(b)), depth);
    }

    fn unary(&mut self, op: &'static str) {
        let (a, a_depth): (Expr, usize) = self.pop_with_depth();
        let depth: usize = a_depth.saturating_add(1);
        self.push_with_depth(Expr::Unary(op, Box::new(a)), depth);
    }

    fn emit_conv(&mut self, name: &str) {
        if self.lang != TargetLang::CSharp {
            return;
        }
        let Some((ty, is_checked)): Option<(&'static str, bool)> = conv_csharp_target(name) else {
            return;
        };
        let e: Expr = self.pop();
        let operand_is_const: bool = matches!(e, Expr::Const(_));
        let cast: Expr = Expr::Cast(ty.to_owned(), Box::new(e));
        if is_checked {
            let rendered: String = render_bounded_expression(cast, self.lang, self.names);
            self.push(Expr::Raw(format!("checked({rendered})")));
        } else if operand_is_const {
            let rendered: String = render_bounded_expression(cast, self.lang, self.names);
            self.push(Expr::Raw(format!("unchecked({rendered})")));
        } else {
            self.push(cast);
        }
    }

    fn token_name(&self, ins: &Instruction) -> String {
        match ins.operand {
            OperandValue::Token(t) => self.namer.name(t),
            _ => "__token".to_owned(),
        }
    }

    fn stored_field_type(&self, ins: &Instruction) -> Option<String> {
        match ins.operand {
            OperandValue::Token(t) => self.namer.field_type_name(t),
            _ => None,
        }
    }

    fn is_inherited_call(&self, raw: &str) -> bool {
        let Some((declaring, _)): Option<(&str, &str)> = raw.rsplit_once("::") else {
            return false;
        };
        let Some(enclosing): Option<&str> = self.namer.enclosing_type() else {
            return false;
        };
        let declaring: &str = declaring.split('<').next().unwrap_or(declaring);
        !declaring.is_empty() && declaring != enclosing
    }

    fn receiver_text(&self, receiver: &Expr, base_call: bool) -> String {
        if base_call && matches!(receiver, Expr::This) {
            return "base".to_owned();
        }
        call_receiver(receiver, self.lang, self.names)
    }

    fn float_const(ins: &Instruction) -> String {
        match ins.operand {
            OperandValue::F32Bits(b) => csharp_single(f32::from_bits(b)),
            OperandValue::F64Bits(b) => csharp_double(f64::from_bits(b)),
            _ => "0".to_owned(),
        }
    }

    fn int_const(ins: &Instruction, name: &str) -> i64 {
        if let Some(rest) = name.strip_prefix("ldc.i4.") {
            return match rest {
                "s" => match ins.operand {
                    OperandValue::U8(b) => i64::from(b.cast_signed()),
                    _ => 0,
                },
                d => d.parse::<i64>().unwrap_or(0),
            };
        }
        if name == "ldc.i4"
            && let OperandValue::I32(v) = ins.operand
        {
            return i64::from(v);
        }
        0
    }

    fn store_loc(&mut self, ins: &Instruction, name: &str) {
        let n: u32 = local_index(ins, name);
        self.locals_used.insert(n);
        let val: Expr = self.pop();
        let val: Expr = coerce_constant(val, self.names.local_type(n), self.lang);
        self.locals_assigned.insert(n);
        self.stmts.push(Stmt::Assign {
            target: NameTable::local_name(n),
            value: val.render(self.lang, self.names),
        });
    }

    fn render_subscript(&self, indices: Vec<Expr>) -> String {
        indices
            .into_iter()
            .map(|index: Expr| index.render(self.lang, self.names))
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn render_byref_args(
        &mut self,
        args: &[Expr],
        info: Option<CallInfo>,
        has_this: bool,
    ) -> Vec<Expr> {
        let Some(info): Option<CallInfo> = info.filter(|c: &CallInfo| c.byref_param_mask != 0)
        else {
            return args.to_vec();
        };
        args.iter()
            .enumerate()
            .map(|(idx, arg): (usize, &Expr)| {
                if idx == 0 && has_this {
                    return arg.clone();
                }
                let Expr::AddressOf(inner): &Expr = arg else {
                    return arg.clone();
                };
                if !info.arg_is_byref(idx) {
                    return arg.clone();
                }
                let keyword: &str = match inner.as_ref() {
                    Expr::Local(slot) if !self.locals_assigned.contains(slot) => {
                        self.locals_assigned.insert(*slot);
                        "out"
                    }
                    _ => "ref",
                };
                Expr::Raw(format!("{keyword} {}", inner.render(self.lang, self.names)))
            })
            .collect()
    }

    fn emit_call(&mut self, ins: &Instruction) {
        let null_cond: bool = std::mem::take(&mut self.pending_null_cond);
        let raw: String = self.token_name(ins);
        let member: &str = raw.rsplit("::").next().unwrap_or(&raw);
        let is_ctor: bool = member == ".ctor" || member == ".cctor";
        let token: u32 = match ins.operand {
            OperandValue::Token(t) => t,
            _ => 0,
        };
        let info: Option<CallInfo> = self.namer.call_info(token);
        let arg_count: usize = info.map_or(0, |c: CallInfo| c.arg_count);
        let returns_value: bool = info.map_or(!is_ctor, |c: CallInfo| c.returns_value);
        let has_this: bool = info.map_or_else(|| raw.contains("::"), |c: CallInfo| c.has_this);
        let base_call: bool = self.lang == TargetLang::CSharp
            && ins.name == "call"
            && has_this
            && !is_ctor
            && self.namer.callee_is_virtual_definition(token)
            && self.is_inherited_call(&raw);

        let mut args: Vec<Expr> = self.pop_n(arg_count);
        if token != 0 {
            let recv_off: usize = usize::from(has_this);
            for (idx, arg) in args.iter_mut().enumerate() {
                if idx < recv_off {
                    continue;
                }
                if let Expr::Const(value) = arg
                    && is_bare_integer_literal(value)
                {
                    let param_index: usize = idx - recv_off;
                    if let Some(enum_ty) = self.namer.enum_param_type(token, param_index) {
                        *arg = Expr::Cast(enum_ty, Box::new(Expr::Const(value.clone())));
                    } else if let Some(literal) = self
                        .namer
                        .param_type_name(token, param_index)
                        .and_then(|ty: String| coerced_literal(value, &ty, self.lang))
                    {
                        *arg = Expr::Const(literal);
                    }
                }
            }
        }
        if ins.name == "call"
            && info.is_some_and(|call: CallInfo| {
                call.arg_count == 2 && !call.has_this && !call.returns_value
            })
            && self.namer.is_initialize_array(token)
            && let [array, Expr::FieldHandle(field_token)] = args.as_slice()
            && self.populate_field_rva_duplicate_array(array, *field_token)
        {
            return;
        }
        if !has_this
            && let Some(op) = binary_operator_special_name(member)
            && args.len() == 2
        {
            let b: Expr = args.pop().unwrap_or(Expr::Null);
            let a: Expr = args.pop().unwrap_or(Expr::Null);
            let folded: Expr = Expr::Binary(op, Box::new(a), Box::new(b));
            if returns_value {
                self.push(folded);
            } else {
                self.stmts.push(Stmt::Expr(render_bounded_expression(
                    folded, self.lang, self.names,
                )));
            }
            return;
        }
        if !has_this
            && let Some(op) = unary_operator_special_name(member)
            && args.len() == 1
        {
            let a: Expr = args.pop().unwrap_or(Expr::Null);
            let folded: Expr = Expr::Unary(op, Box::new(a));
            if returns_value {
                self.push(folded);
            } else {
                self.stmts.push(Stmt::Expr(render_bounded_expression(
                    folded, self.lang, self.names,
                )));
            }
            return;
        }
        if member == "GetTypeFromHandle" && args.len() == 1 {
            let handle: Expr = args.pop().unwrap_or(Expr::Null);
            let type_expression: Expr = match &handle {
                Expr::TypeHandle(ty) => Expr::TypeOf(ty.clone()),
                _ => Expr::Raw(format!(
                    "throw new System.NotSupportedException(\"{UNRECONSTRUCTED_RUNTIME_HANDLE}\")"
                )),
            };
            self.push(type_expression);
            return;
        }
        if !has_this
            && member == "Create"
            && is_tuple_factory_owner(&raw)
            && (2..=8).contains(&args.len())
        {
            self.push(Expr::Tuple(args));
            return;
        }
        if let Some(prop) = property_getter_name(member)
            && returns_value
        {
            if has_this && args.len() == 1 {
                let recv: Expr = args.pop().unwrap_or(Expr::Null);
                self.push(Expr::Field(format!(
                    "{}.{prop}",
                    self.receiver_text(&recv, base_call)
                )));
                return;
            }
            if !has_this && args.is_empty() {
                self.push(Expr::Field(prop.to_owned()));
                return;
            }
            if has_this
                && args.len() > 1
                && self.lang == TargetLang::CSharp
                && is_indexer_property(prop)
            {
                let indices: Vec<Expr> = args.split_off(1);
                let recv: Expr = args.pop().unwrap_or(Expr::Null);
                let subscript: String = self.render_subscript(indices);
                self.push(Expr::Field(format!(
                    "{}[{subscript}]",
                    self.receiver_text(&recv, base_call)
                )));
                return;
            }
        }
        if let Some(prop) = property_setter_name(member)
            && !returns_value
        {
            if has_this
                && args.len() > 2
                && self.lang == TargetLang::CSharp
                && is_indexer_property(prop)
            {
                let value: Expr = args.pop().unwrap_or(Expr::Null);
                let indices: Vec<Expr> = args.split_off(1);
                let recv: Expr = args.pop().unwrap_or(Expr::Null);
                let subscript: String = self.render_subscript(indices);
                self.stmts.push(Stmt::Assign {
                    target: format!("{}[{subscript}]", self.receiver_text(&recv, base_call)),
                    value: value.render(self.lang, self.names),
                });
                return;
            }
            if has_this && args.len() == 2 {
                let value: Expr = args.pop().unwrap_or(Expr::Null);
                let recv: Expr = args.pop().unwrap_or(Expr::Null);
                self.stmts.push(Stmt::Assign {
                    target: format!("{}.{prop}", self.receiver_text(&recv, base_call)),
                    value: value.render(self.lang, self.names),
                });
                return;
            }
            if !has_this && args.len() == 1 {
                let value: Expr = args.pop().unwrap_or(Expr::Null);
                self.stmts.push(Stmt::Assign {
                    target: prop.to_owned(),
                    value: value.render(self.lang, self.names),
                });
                return;
            }
        }
        let rendered_args: Vec<Expr> = self.render_byref_args(&args, info, has_this);
        let call: Expr = if has_this && !rendered_args.is_empty() {
            let mut rendered_args: Vec<Expr> = rendered_args;
            let recv: Expr = rendered_args.remove(0);
            let sep: &str = if null_cond && self.lang == TargetLang::CSharp {
                "?."
            } else {
                "."
            };
            Expr::Call {
                target: format!(
                    "{}{sep}{}",
                    self.receiver_text(&recv, base_call),
                    short(&raw)
                ),
                args: rendered_args,
            }
        } else {
            Expr::Call {
                target: static_call_target(&raw, self.lang),
                args: rendered_args,
            }
        };
        if is_ctor || !returns_value {
            self.stmts.push(Stmt::Expr(render_bounded_expression(
                call, self.lang, self.names,
            )));
        } else {
            self.push(call);
        }
    }

    fn cmp_cond(&mut self, op: &'static str, lang: TargetLang) -> String {
        let b: Expr = self.pop();
        let a: Expr = self.pop();
        render_bounded_expression(Expr::Binary(op, Box::new(a), Box::new(b)), lang, self.names)
    }

    fn arg_slot(&self, idx: u32) -> u32 {
        if self.namer.outer_has_this() {
            idx
        } else {
            idx.saturating_add(1)
        }
    }

    fn forwarded_arg_name(&self, raw_slot: usize, has_this: bool) -> String {
        if raw_slot == 0 && has_this {
            return match self.lang {
                TargetLang::VbNet => "Me".to_owned(),
                _ => "this".to_owned(),
            };
        }
        let raw: u32 = u32::try_from(raw_slot).unwrap_or(u32::MAX);
        let slot: u32 = if has_this { raw } else { raw.saturating_add(1) };
        self.names.arg_name(slot)
    }

    fn as_method_group(args: &[Expr]) -> Option<Expr> {
        let [target, Expr::MethodPtr { receiver, method }]: &[Expr] = args else {
            return None;
        };
        if let Some(bound) = receiver {
            return Some(Expr::MethodPtr {
                receiver: Some(bound.clone()),
                method: method.clone(),
            });
        }
        let bound: Option<Box<Expr>> = match target {
            Expr::Null => None,
            Expr::Field(f) if is_singleton_field(f) => None,
            other => Some(Box::new(other.clone())),
        };
        Some(Expr::MethodPtr {
            receiver: bound,
            method: method.clone(),
        })
    }

    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn lift_one(&mut self, ins: &Instruction) {
        match ins.name.as_str() {
            "nop" | "break" => {}
            "ldnull" => self.push(Expr::Null),
            "ldstr" => {
                let s: String = match ins.operand {
                    OperandValue::Token(t) => self.namer.name(t),
                    _ => String::new(),
                };
                self.push(Expr::StringLit(s));
            }
            "ldc.i4.m1" => self.push(Expr::Const("-1".to_owned())),
            "__coalesce" => {
                let alt: Expr = self.pop();
                let primary: Expr = self.pop();
                self.push(Expr::Coalesce(Box::new(primary), Box::new(alt)));
            }
            "__null_cond" => {
                self.pending_null_cond = true;
            }
            "__throw_expr" => {
                let exc: Expr = self.pop();
                let keyword: &str = match self.lang {
                    TargetLang::FSharp => "raise",
                    _ => "throw",
                };
                self.push(Expr::Raw(format!(
                    "{keyword} {}",
                    exc.render(self.lang, self.names)
                )));
            }
            "dup" => {
                let e: Expr = self.pop();
                if e.is_atom() {
                    let r: String = e.render(self.lang, self.names);
                    self.push(e);
                    self.push(Expr::Raw(r));
                } else {
                    self.push(e.clone());
                    self.push(e);
                }
            }
            "pop" => {
                let e: Expr = self.pop();
                if matches!(e, Expr::Call { .. } | Expr::NewObj { .. }) {
                    self.stmts.push(Stmt::Expr(e.render(self.lang, self.names)));
                }
            }
            "ret" => {
                let val: Option<String> = if self.stack.is_empty() {
                    None
                } else {
                    Some(self.pop().render(self.lang, self.names))
                };
                self.stmts.push(Stmt::Return(val));
            }
            "add" | "add.ovf" | "add.ovf.un" => self.binary("+"),
            "sub" | "sub.ovf" | "sub.ovf.un" => self.binary("-"),
            "mul" | "mul.ovf" | "mul.ovf.un" => self.binary("*"),
            "div" | "div.un" => self.binary("/"),
            "rem" | "rem.un" => self.binary("%"),
            "and" => self.binary("&"),
            "or" => self.binary("|"),
            "xor" => self.binary("^"),
            "shl" => self.binary("<<"),
            "shr" => self.binary(">>"),
            "shr.un" => self.binary(">>>"),
            "neg" => self.unary("-"),
            "not" => self.unary("~"),
            "ceq" => self.binary("=="),
            "cgt" | "cgt.un" => self.binary(">"),
            "clt" | "clt.un" => self.binary("<"),
            "ldlen" => {
                let arr: Expr = self.pop();
                self.push(Expr::LoadLen(Box::new(arr)));
            }
            "throw" => {
                let e: Expr = self.pop();
                self.stmts
                    .push(Stmt::Throw(Some(e.render(self.lang, self.names))));
            }
            "rethrow" => self.stmts.push(Stmt::Throw(None)),
            "newarr" => {
                let len: Expr = self.pop();
                let ty: String = qualified_type_name(&self.token_name(ins), self.lang);
                let element_token: u32 = match ins.operand {
                    OperandValue::Token(token) => token,
                    _ => 0,
                };
                let allocation_id: u64 = self.next_array_id;
                self.next_array_id = self.next_array_id.saturating_add(1);
                self.push(Expr::NewArr {
                    ty,
                    element_token,
                    allocation_id,
                    length: Box::new(len),
                    elements: Vec::new(),
                });
            }
            "newobj" => {
                let raw: String = self.token_name(ins);
                let token: u32 = match ins.operand {
                    OperandValue::Token(t) => t,
                    _ => 0,
                };
                let argc: usize = self.namer.call_info(token).map_or(0, |c: CallInfo| {
                    c.arg_count.saturating_sub(usize::from(c.has_this))
                });
                let args: Vec<Expr> = self.pop_n(argc);
                let declared: String = raw.replace("::.ctor", "");
                let ctor: String = short(&declared);
                if let Some(group) = Self::as_method_group(&args) {
                    self.push(group);
                } else if is_value_tuple_ctor(&ctor) && (2..=8).contains(&args.len()) {
                    self.push(Expr::Tuple(args));
                } else {
                    self.push(Expr::NewObj {
                        ctor: qualified_type_name(&declared, self.lang),
                        args,
                    });
                }
            }
            "call" | "callvirt" | "calli" => self.emit_call(ins),
            "castclass" => {
                let e: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.push(Expr::Cast(ty, Box::new(e)));
            }
            "isinst" => {
                let e: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.push(Expr::IsInst(ty, Box::new(e)));
            }
            "box" => {
                let literal: Option<&'static str> = (self.lang == TargetLang::CSharp
                    && self.token_name(ins) == "System.Boolean")
                    .then(|| match self.stack.last() {
                        Some(Expr::Const(text)) => boolean_literal(text),
                        _ => None,
                    })
                    .flatten();
                if let Some(literal) = literal {
                    let (_, depth): (Expr, usize) = self.pop_with_depth();
                    self.push_with_depth(Expr::Const(literal.to_owned()), depth);
                }
            }
            "unbox.any" | "unbox" | "readonly." | "volatile." | "tail." | "constrained."
            | "no." => {}
            "ldobj" => {
                let addr: Expr = self.pop();
                self.push(Expr::Deref(Box::new(addr)));
            }
            "stobj" | "cpobj" => {
                let val: Expr = self.pop();
                let addr: Expr = self.pop();
                self.stmts.push(Stmt::Assign {
                    target: deref_target(&addr, self.lang, self.names),
                    value: val.render(self.lang, self.names),
                });
            }
            "initobj" => {
                let addr: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.stmts.push(Stmt::Assign {
                    target: deref_target(&addr, self.lang, self.names),
                    value: format!("default({ty})"),
                });
            }
            "ldtoken" => {
                let token: u32 = match ins.operand {
                    OperandValue::Token(token) => token,
                    _ => 0,
                };
                let handle: Expr = match self.namer.token_kind(token) {
                    MetadataTokenKind::Type => Expr::TypeHandle(short(&self.token_name(ins))),
                    MetadataTokenKind::Field => Expr::FieldHandle(token),
                    MetadataTokenKind::Method => Expr::MethodHandle(token),
                    MetadataTokenKind::Unknown => Expr::OpaqueHandle(token),
                };
                self.push(handle);
            }
            "ldftn" => {
                let method: String = self.token_name(ins);
                self.push(Expr::MethodPtr {
                    receiver: None,
                    method,
                });
            }
            "ldvirtftn" => {
                let obj: Expr = self.pop();
                let method: String = self.token_name(ins);
                self.push(Expr::MethodPtr {
                    receiver: Some(Box::new(obj)),
                    method,
                });
            }
            "sizeof" => {
                self.push(Expr::Raw(format!(
                    "sizeof({})",
                    short(&self.token_name(ins))
                )));
            }
            "localloc" => {
                let size: Expr = self.pop();
                self.push(Expr::Raw(format!(
                    "stackalloc byte[{}]",
                    size.render(self.lang, self.names)
                )));
            }
            "ldfld" => {
                let obj: Expr = self.pop();
                let fld: String = field_name(&self.token_name(ins));
                self.push(Expr::Field(format!(
                    "{}.{}",
                    paren(&obj, self.lang, self.names),
                    fld
                )));
            }
            "ldflda" => {
                let obj: Expr = self.pop();
                let fld: String = field_name(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Field(format!(
                    "{}.{}",
                    paren(&obj, self.lang, self.names),
                    fld
                )))));
            }
            "ldsfld" => {
                let fld: String = field_name(&self.token_name(ins));
                self.push(Expr::Field(fld));
            }
            "ldsflda" => {
                let fld: String = field_name(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Field(fld))));
            }
            "stfld" => {
                let val: Expr = self.pop();
                let obj: Expr = self.pop();
                let fld: String = field_name(&self.token_name(ins));
                let field_type: Option<String> = self.stored_field_type(ins);
                let val: Expr = coerce_constant(val, field_type.as_deref(), self.lang);
                self.stmts.push(Stmt::Assign {
                    target: format!("{}.{}", paren(&obj, self.lang, self.names), fld),
                    value: val.render(self.lang, self.names),
                });
            }
            "stsfld" => {
                let val: Expr = self.pop();
                let fld: String = field_name(&self.token_name(ins));
                let field_type: Option<String> = self.stored_field_type(ins);
                let val: Expr = coerce_constant(val, field_type.as_deref(), self.lang);
                self.stmts.push(Stmt::Assign {
                    target: fld,
                    value: val.render(self.lang, self.names),
                });
            }
            "ldelema" => {
                let idx: Expr = self.pop();
                let arr: Expr = self.pop();
                self.push(Expr::AddressOf(Box::new(Expr::LoadElem(
                    Box::new(arr),
                    Box::new(idx),
                ))));
            }
            n if n.starts_with("ldelem") => {
                let idx: Expr = self.pop();
                let arr: Expr = self.pop();
                self.push(Expr::LoadElem(Box::new(arr), Box::new(idx)));
            }
            n if n.starts_with("stelem") => {
                let val: Expr = self.pop();
                let idx: Expr = self.pop();
                let arr: Expr = self.pop();
                let element_type: Option<String> = array_element_type(&arr, self.names);
                let val: Expr = coerce_constant(val, element_type.as_deref(), self.lang);
                if let Err(val) = self.append_to_duplicated_array_literal(&arr, &idx, val) {
                    self.stmts.push(Stmt::Assign {
                        target: format!(
                            "{}[{}]",
                            paren(&arr, self.lang, self.names),
                            idx.render(self.lang, self.names)
                        ),
                        value: val.render(self.lang, self.names),
                    });
                }
            }
            n if n.starts_with("ldc.i4") => {
                self.push(Expr::Const(Self::int_const(ins, n).to_string()));
            }
            "ldc.i8" => {
                if let OperandValue::I64(v) = ins.operand {
                    self.push(Expr::Const(format!("{v}L")));
                }
            }
            "ldc.r4" | "ldc.r8" => self.push(Expr::Const(Self::float_const(ins))),
            n if n.starts_with("ldarga") => {
                let idx: u32 = local_index(ins, n);
                if idx == 0 && self.namer.outer_has_this() {
                    self.push(Expr::AddressOf(Box::new(Expr::This)));
                } else {
                    self.push(Expr::AddressOf(Box::new(Expr::Arg(self.arg_slot(idx)))));
                }
            }
            n if n.starts_with("ldarg") => {
                let idx: u32 = local_index(ins, n);
                if idx == 0 && self.namer.outer_has_this() {
                    self.push(Expr::This);
                } else {
                    self.push(Expr::Arg(self.arg_slot(idx)));
                }
            }
            n if n.starts_with("ldloca") => {
                let idx: u32 = local_index(ins, n);
                self.locals_used.insert(idx);
                self.push(Expr::AddressOf(Box::new(Expr::Local(idx))));
            }
            n if n.starts_with("ldloc") => {
                let idx: u32 = local_index(ins, n);
                self.locals_used.insert(idx);
                self.push(Expr::Local(idx));
            }
            n if n.starts_with("starg") => {
                let idx: u32 = local_index(ins, n);
                let slot: u32 = self.arg_slot(idx);
                let val: Expr = self.pop();
                let val: Expr = coerce_constant(val, self.names.arg_type(slot), self.lang);
                self.stmts.push(Stmt::Assign {
                    target: self.names.arg_name(slot),
                    value: val.render(self.lang, self.names),
                });
            }
            n if n.starts_with("stloc") => self.store_loc(ins, n),
            n if n.starts_with("conv.") => self.emit_conv(n),
            n if n.starts_with("ldind.") => {
                let addr: Expr = self.pop();
                self.push(Expr::Deref(Box::new(addr)));
            }
            n if n.starts_with("stind.") => {
                let val: Expr = self.pop();
                let addr: Expr = self.pop();
                self.stmts.push(Stmt::Assign {
                    target: deref_target(&addr, self.lang, self.names),
                    value: val.render(self.lang, self.names),
                });
            }
            "br" | "br.s" | "leave" | "leave.s" => {
                self.clear_stack();
            }
            "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s" => {
                let _: Expr = self.pop();
            }
            "beq" | "beq.s" | "bne.un" | "bne.un.s" | "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s"
            | "bge" | "bge.s" | "bge.un" | "bge.un.s" | "blt" | "blt.s" | "blt.un" | "blt.un.s"
            | "ble" | "ble.s" | "ble.un" | "ble.un.s" => {
                let _: Expr = self.pop();
                let _: Expr = self.pop();
            }
            "switch" => {
                let _: Expr = self.pop();
            }
            "endfinally" | "endfilter" => self.clear_stack(),
            "ckfinite" | "unaligned." => {}
            "jmp" => {
                let raw: String = self.token_name(ins);
                let token: u32 = match ins.operand {
                    OperandValue::Token(t) => t,
                    _ => 0,
                };
                let argc: usize = self
                    .namer
                    .call_info(token)
                    .map_or(0, |c: CallInfo| c.arg_count);
                let has_this: bool = self.namer.outer_has_this();
                let forwarded: String = (0..argc)
                    .map(|i: usize| self.forwarded_arg_name(i, has_this))
                    .collect::<Vec<String>>()
                    .join(", ");
                self.stmts
                    .push(Stmt::Return(Some(format!("{}({forwarded})", short(&raw)))));
            }
            "arglist" => self.push(Expr::Raw("__arglist".to_owned())),
            "mkrefany" => {
                let addr: Expr = self.pop();
                self.push(Expr::Raw(format!(
                    "__makeref({})",
                    render_bounded_expression(Expr::Deref(Box::new(addr)), self.lang, self.names)
                )));
            }
            "refanyval" => {
                let tr: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Raw(format!(
                    "__refvalue({}, {ty})",
                    tr.render(self.lang, self.names)
                )))));
            }
            "refanytype" => {
                let tr: Expr = self.pop();
                self.push(Expr::Raw(format!(
                    "__reftype({})",
                    tr.render(self.lang, self.names)
                )));
            }
            "cpblk" => {
                let size: Expr = self.pop();
                let src: Expr = self.pop();
                let dest: Expr = self.pop();
                self.stmts.push(Stmt::Expr(format!(
                    "Unsafe.CopyBlock({}, {}, {})",
                    dest.render(self.lang, self.names),
                    src.render(self.lang, self.names),
                    size.render(self.lang, self.names)
                )));
            }
            "initblk" => {
                let size: Expr = self.pop();
                let value: Expr = self.pop();
                let addr: Expr = self.pop();
                self.stmts.push(Stmt::Expr(format!(
                    "Unsafe.InitBlock({}, {}, {})",
                    addr.render(self.lang, self.names),
                    value.render(self.lang, self.names),
                    size.render(self.lang, self.names)
                )));
            }
            other => self.stmts.push(Stmt::Comment(format!(
                "{other} {}",
                render_operand(&ins.operand)
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum LinearStmt {
    Assign { target: String, value: String },
    Expr(String),
    Return(Option<String>),
    Throw(Option<String>),
    Comment(String),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BlockCode {
    pub stmts: Vec<LinearStmt>,
    pub condition: Option<String>,
    pub switch_selector: Option<String>,
    pub locals_used: BTreeSet<u32>,
}

fn branch_target(ins: &Instruction) -> Option<u32> {
    match ins.operand {
        OperandValue::BrTarget(rel) => {
            Some(u32::try_from(i64::from(ins.offset) + i64::from(rel)).unwrap_or(ins.offset))
        }
        _ => None,
    }
}

fn continue_op_for_and(branch: &str) -> Option<&'static str> {
    match branch {
        "bne.un" | "bne.un.s" => Some("=="),
        "beq" | "beq.s" => Some("!="),
        "bge" | "bge.s" | "bge.un" | "bge.un.s" => Some("<"),
        "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => Some("<="),
        "ble" | "ble.s" | "ble.un" | "ble.un.s" => Some(">"),
        "blt" | "blt.s" | "blt.un" | "blt.un.s" => Some(">="),
        _ => None,
    }
}

pub(crate) fn lift_filter_condition<N: TokenNamer>(
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    instrs: &[Instruction],
    first: usize,
    last: usize,
) -> Option<(Option<String>, String)> {
    let region: &[Instruction] = &instrs[first..=last];
    let catch_type: Option<String> = region
        .iter()
        .find(|i: &&Instruction| matches!(i.name.as_str(), "isinst" | "castclass"))
        .map(|i: &Instruction| {
            let raw: String = match i.operand {
                OperandValue::Token(t) => namer.name(t),
                _ => "__token".to_owned(),
            };
            match lang {
                TargetLang::CSharp => qualified_type_name(&raw, lang),
                TargetLang::FSharp | TargetLang::VbNet => short(&raw),
            }
        });
    let entry: u32 = region
        .iter()
        .find(|i: &&Instruction| matches!(i.name.as_str(), "brtrue" | "brtrue.s"))
        .and_then(branch_target)
        .unwrap_or(region.first()?.offset);
    let end_off: u32 = region
        .iter()
        .find(|i: &&Instruction| i.name == "endfilter")
        .map(|i: &Instruction| i.offset)?;
    let full_body: Vec<&Instruction> = region
        .iter()
        .filter(|i: &&Instruction| i.offset >= entry && i.offset < end_off)
        .collect();
    let true_exit: Option<usize> = full_body
        .iter()
        .position(|i: &&Instruction| matches!(i.name.as_str(), "br" | "br.s"));
    let cond_body: &[&Instruction] =
        true_exit.map_or(full_body.as_slice(), |idx: usize| &full_body[..idx]);
    let false_sink: Option<u32> = cond_body
        .iter()
        .filter(|i: &&&Instruction| continue_op_for_and(&i.name).is_some())
        .filter_map(|i: &&Instruction| branch_target(i))
        .max();
    let conjuncts: Vec<String> = reconstruct_conjuncts(namer, names, lang, cond_body, false_sink);
    if conjuncts.is_empty() {
        return None;
    }
    let joined: String = conjuncts.join(" && ");
    if joined == "ex" || joined.is_empty() {
        return None;
    }
    Some((catch_type, joined))
}

fn reconstruct_conjuncts<N: TokenNamer>(
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    cond_body: &[&Instruction],
    false_sink: Option<u32>,
) -> Vec<String> {
    let mut lifter: Lifter<'_, N> = Lifter::new(namer, names, lang);
    let mut conjuncts: Vec<String> = Vec::new();
    for ins in cond_body {
        let name: &str = ins.name.as_str();
        if let Some(op) = continue_op_for_and(name) {
            if branch_target(ins) == false_sink {
                let b: Expr = lifter.pop();
                let a: Expr = lifter.pop();
                conjuncts.push(render_bounded_expression(
                    Expr::Binary(op, Box::new(a), Box::new(b)),
                    lang,
                    names,
                ));
            } else {
                let _: Expr = lifter.pop();
                let _: Expr = lifter.pop();
            }
            continue;
        }
        match name {
            "brfalse" | "brfalse.s" if branch_target(ins) == false_sink => {
                conjuncts.push(lifter.pop().render(lang, names));
            }
            "brtrue" | "brtrue.s" if branch_target(ins) == false_sink => {
                let e: Expr = lifter.pop();
                conjuncts.push(render_bounded_expression(
                    Expr::Unary("!", Box::new(e)),
                    lang,
                    names,
                ));
            }
            "isinst" | "castclass" => {
                let _: Expr = lifter.pop();
                lifter.push(Expr::Raw("ex".to_owned()));
            }
            "pop" => {
                let _: Expr = lifter.pop();
            }
            "br" | "br.s" | "nop" | "endfilter" => {}
            "ldc.i4.0" if is_bool_normalize(cond_body, ins) => {}
            "cgt.un" if is_bool_normalize_consumer(cond_body, ins) => {}
            _ => lifter.lift_one(ins),
        }
    }
    if let Some(tail) = final_comparison(&mut lifter, lang) {
        conjuncts.push(tail);
    }
    conjuncts
}

fn is_bool_normalize(cond_body: &[&Instruction], cur: &Instruction) -> bool {
    cond_body
        .iter()
        .position(|i: &&Instruction| i.offset == cur.offset)
        .and_then(|idx: usize| cond_body.get(idx + 1))
        .is_some_and(|next: &&Instruction| next.name == "cgt.un")
}

fn is_bool_normalize_consumer(cond_body: &[&Instruction], cur: &Instruction) -> bool {
    cond_body
        .iter()
        .position(|i: &&Instruction| i.offset == cur.offset)
        .and_then(|idx: usize| idx.checked_sub(1).and_then(|p: usize| cond_body.get(p)))
        .is_some_and(|prev: &&Instruction| prev.name == "ldc.i4.0")
}

fn final_comparison<N: TokenNamer>(lifter: &mut Lifter<'_, N>, lang: TargetLang) -> Option<String> {
    if lifter.stack.is_empty() {
        return None;
    }
    let tail: String = lifter.pop().render(lang, lifter.names);
    (tail != "ex" && !tail.is_empty()).then_some(tail)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondKind {
    Bool,
    Reference,
    Integral,
}

fn is_comparison_or_logical(op: &str) -> bool {
    matches!(op, "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||")
}

fn is_bool_type_name(ty: &str) -> bool {
    matches!(ty, "bool" | "Boolean" | "System.Boolean")
}

fn is_reference_type_name(ty: &str) -> bool {
    ty.ends_with("[]")
        || ty.contains('<')
        || matches!(
            ty,
            "string" | "String" | "System.String" | "object" | "Object" | "System.Object"
        )
}

fn is_integral_type_name(ty: &str) -> bool {
    matches!(
        ty,
        "int"
            | "uint"
            | "long"
            | "ulong"
            | "short"
            | "ushort"
            | "byte"
            | "sbyte"
            | "char"
            | "nint"
            | "nuint"
            | "IntPtr"
            | "UIntPtr"
            | "Int32"
            | "UInt32"
            | "Int64"
            | "UInt64"
            | "Int16"
            | "UInt16"
            | "Byte"
            | "SByte"
            | "Char"
            | "System.Int32"
            | "System.UInt32"
            | "System.Int64"
            | "System.UInt64"
            | "System.Int16"
            | "System.UInt16"
            | "System.Byte"
            | "System.SByte"
            | "System.Char"
            | "System.IntPtr"
            | "System.UIntPtr"
    )
}

fn classify_type_str(ty: &str) -> CondKind {
    let t: &str = ty.trim();
    if is_bool_type_name(t) {
        CondKind::Bool
    } else if is_reference_type_name(t) {
        CondKind::Reference
    } else if is_integral_type_name(t) {
        CondKind::Integral
    } else {
        CondKind::Bool
    }
}

fn classify_cond_kind(e: &Expr, names: &NameTable) -> CondKind {
    match e {
        Expr::Binary(op, _, _) => {
            if is_comparison_or_logical(op) {
                CondKind::Bool
            } else {
                CondKind::Integral
            }
        }
        Expr::Unary(op, _) => {
            if *op == "!" {
                CondKind::Bool
            } else {
                CondKind::Integral
            }
        }
        Expr::LoadLen(_) => CondKind::Integral,
        Expr::Const(c) => {
            if is_bare_integer_literal(c) {
                CondKind::Integral
            } else {
                CondKind::Bool
            }
        }
        Expr::Null
        | Expr::StringLit(_)
        | Expr::This
        | Expr::NewObj { .. }
        | Expr::NewArr { .. } => CondKind::Reference,
        Expr::Local(n) => names
            .local_type(*n)
            .map_or(CondKind::Bool, classify_type_str),
        Expr::Arg(n) => names.arg_type(*n).map_or(CondKind::Bool, classify_type_str),
        Expr::Cast(ty, _) => classify_type_str(ty),
        _ => CondKind::Bool,
    }
}

fn branch_condition(e: Expr, brtrue: bool, lang: TargetLang, names: &NameTable) -> String {
    let kind: CondKind = if lang == TargetLang::CSharp {
        classify_cond_kind(&e, names)
    } else {
        CondKind::Bool
    };
    match kind {
        CondKind::Bool if brtrue => e.render(lang, names),
        CondKind::Bool => render_bounded_expression(Expr::Unary("!", Box::new(e)), lang, names),
        CondKind::Reference => {
            let op: &'static str = if brtrue { "!=" } else { "==" };
            render_bounded_expression(
                Expr::Binary(op, Box::new(e), Box::new(Expr::Null)),
                lang,
                names,
            )
        }
        CondKind::Integral => {
            let op: &'static str = if brtrue { "!=" } else { "==" };
            render_bounded_expression(
                Expr::Binary(op, Box::new(e), Box::new(Expr::Const("0".to_owned()))),
                lang,
                names,
            )
        }
    }
}

pub(crate) fn lift_block<N: TokenNamer>(
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    instrs: &[Instruction],
    first: usize,
    last: usize,
) -> BlockCode {
    let mut lifter: Lifter<'_, N> = Lifter::new(namer, names, lang);
    let mut condition: Option<String> = None;
    let mut switch_selector: Option<String> = None;
    for ins in &instrs[first..=last] {
        match ins.flow {
            FlowControl::CondBranch => match ins.name.as_str() {
                "brtrue" | "brtrue.s" => {
                    condition = Some(branch_condition(lifter.pop(), true, lang, names));
                }
                "brfalse" | "brfalse.s" => {
                    condition = Some(branch_condition(lifter.pop(), false, lang, names));
                }
                "beq" | "beq.s" => condition = Some(lifter.cmp_cond("==", lang)),
                "bne.un" | "bne.un.s" => condition = Some(lifter.cmp_cond("!=", lang)),
                "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => {
                    condition = Some(lifter.cmp_cond(">", lang));
                }
                "bge" | "bge.s" | "bge.un" | "bge.un.s" => {
                    condition = Some(lifter.cmp_cond(">=", lang));
                }
                "blt" | "blt.s" | "blt.un" | "blt.un.s" => {
                    condition = Some(lifter.cmp_cond("<", lang));
                }
                "ble" | "ble.s" | "ble.un" | "ble.un.s" => {
                    condition = Some(lifter.cmp_cond("<=", lang));
                }
                "switch" => switch_selector = Some(lifter.pop().render(lang, names)),
                _ => lifter.lift_one(ins),
            },
            FlowControl::Branch
                if matches!(ins.name.as_str(), "br" | "br.s" | "leave" | "leave.s") => {}
            FlowControl::Return if matches!(ins.name.as_str(), "endfinally" | "endfilter") => {}
            _ => lifter.lift_one(ins),
        }
    }
    let stmts: Vec<LinearStmt> = lifter.stmts.into_iter().map(stmt_to_linear).collect();
    BlockCode {
        stmts,
        condition,
        switch_selector,
        locals_used: lifter.locals_used,
    }
}

fn stmt_to_linear(s: Stmt) -> LinearStmt {
    match s {
        Stmt::Assign { target, value } => LinearStmt::Assign { target, value },
        Stmt::Expr(e) => LinearStmt::Expr(e),
        Stmt::Return(v) => LinearStmt::Return(v),
        Stmt::Throw(v) => LinearStmt::Throw(v),
        Stmt::Comment(c) => LinearStmt::Comment(c),
    }
}

fn normalize_branches(body: &MethodBody) -> MethodBody {
    let offsets: Vec<u32> = body
        .instructions
        .iter()
        .map(|i: &Instruction| i.offset)
        .collect();
    let mut patched: MethodBody = body.clone();
    let last_size: u32 = body
        .code_size
        .checked_sub(offsets.last().copied().unwrap_or(0))
        .unwrap_or(1)
        .max(1);
    for (idx, ins) in patched.instructions.iter_mut().enumerate() {
        let next_off: u32 = offsets
            .get(idx + 1)
            .copied()
            .unwrap_or_else(|| ins.offset + last_size);
        match &mut ins.operand {
            OperandValue::BrTarget(rel) => {
                let abs: i64 = i64::from(next_off) + i64::from(*rel);
                *rel = i32::try_from(abs - i64::from(ins.offset)).unwrap_or(*rel);
            }
            OperandValue::Switch(rels) => {
                for r in rels.iter_mut() {
                    let abs: i64 = i64::from(next_off) + i64::from(*r);
                    *r = i32::try_from(abs - i64::from(ins.offset)).unwrap_or(*r);
                }
            }
            _ => {}
        }
    }
    patched
}

#[must_use]
pub fn normalize_branches_pub(body: &MethodBody) -> MethodBody {
    normalize_branches(body)
}

#[must_use]
pub fn decompile_method<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
) -> StructuredMethod {
    decompile_method_in(signature, body, namer, TargetLang::CSharp)
}

#[must_use]
pub fn decompile_method_in<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
    lang: TargetLang,
) -> StructuredMethod {
    decompile_method_named(signature, body, namer, &NameTable::default(), lang)
}

#[must_use]
pub fn decompile_method_named<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> StructuredMethod {
    let normalized: MethodBody = normalize_branches(body);
    let prepared: MethodBody = if lang == TargetLang::CSharp {
        crate::cil::fold_null_coalesce(&crate::cil::fold_null_conditional_call(&normalized))
    } else {
        normalized
    };
    let recovered: crate::structure_emit::StructuredOutput =
        crate::structure_emit::structure_method(&prepared, namer, names, lang);
    finish_structured(signature, recovered, names, lang)
}

#[must_use]
pub fn decompile_move_next_named<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    is_async: bool,
) -> StructuredMethod {
    let prepared: MethodBody = crate::cil::fold_null_coalesce(
        &crate::cil::fold_null_conditional_call(&normalize_branches(body)),
    );
    let recovered: crate::structure_emit::StructuredOutput =
        crate::structure_emit::structure_move_next(&prepared, namer, names, lang, is_async);
    finish_structured(signature, recovered, names, lang)
}

#[must_use]
fn finish_structured(
    signature: &str,
    recovered: crate::structure_emit::StructuredOutput,
    names: &NameTable,
    lang: TargetLang,
) -> StructuredMethod {
    let recovered_body: String = if lang == TargetLang::CSharp {
        canonicalize_bool_returns(&recovered.body, signature)
    } else {
        recovered.body.clone()
    };
    let mut text: String = String::with_capacity(recovered_body.len() + 128);
    write_prologue(&mut text, signature, &recovered.locals_used, names, lang);
    text.push_str(&recovered_body);
    write_epilogue(&mut text, signature, lang);

    let statement_count: u32 = u32::try_from(recovered_body.lines().count()).unwrap_or(u32::MAX);
    let used_locals: Vec<u32> = recovered.locals_used.iter().copied().collect();
    StructuredMethod {
        token: 0,
        signature: signature.to_owned(),
        body: text,
        statement_count,
        recovered_locals: u32::try_from(recovered.locals_used.len()).unwrap_or(u32::MAX),
        recovered_branches: recovered.residual_gotos,
        typed_locals: names.typed_locals_count(&used_locals),
        named_params: names.named_params_count(),
    }
}

fn canonicalize_bool_returns(body: &str, signature: &str) -> String {
    if !csharp_return_type_is_bool(signature) {
        return body.to_owned();
    }
    let has_target: bool = body
        .lines()
        .any(|l: &str| matches!(l.trim(), "return 0;" | "return 1;"));
    if !has_target {
        return body.to_owned();
    }
    let trailing_newline: bool = body.ends_with('\n');
    let mut lines: Vec<String> = Vec::new();
    for line in body.lines() {
        let trimmed: &str = line.trim_start();
        let indent: &str = &line[..line.len() - trimmed.len()];
        match trimmed {
            "return 0;" => lines.push(format!("{indent}return false;")),
            "return 1;" => lines.push(format!("{indent}return true;")),
            _ => lines.push(line.to_owned()),
        }
    }
    let mut out: String = lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }
    out
}

fn csharp_return_type_is_bool(signature: &str) -> bool {
    let header: &str = signature
        .lines()
        .find(|l: &&str| !l.trim_start().starts_with("//"))
        .unwrap_or(signature);
    let before_params: &str = header.split('(').next().unwrap_or(header).trim_end();
    let Some((qualifiers, _name)): Option<(&str, &str)> = before_params.rsplit_once(' ') else {
        return false;
    };
    matches!(
        qualifiers.rsplit(' ').next(),
        Some("bool" | "System.Boolean")
    )
}

const FSHARP_GOTO_BANNER: &str =
    "    // note: unstructured CIL jumps preserved as comments; F# has no goto";

fn write_prologue(
    text: &mut String,
    signature: &str,
    locals: &BTreeSet<u32>,
    names: &NameTable,
    lang: TargetLang,
) {
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "{signature}");
            let _ = writeln!(text, "{{");
            for n in locals {
                let _ = writeln!(text, "    {}", names.local_decl(*n, lang));
            }
        }
        TargetLang::FSharp => {
            let _ = writeln!(text, "{signature} =");
            let _ = writeln!(text, "{FSHARP_GOTO_BANNER}");
            for n in locals {
                let _ = writeln!(text, "    {}", names.local_decl(*n, lang));
            }
        }
        TargetLang::VbNet => {
            let _ = writeln!(text, "{signature}");
            for n in locals {
                let _ = writeln!(text, "    {}", names.local_decl(*n, lang));
            }
        }
    }
    if !locals.is_empty() {
        let _ = writeln!(text);
    }
}

fn write_epilogue(text: &mut String, signature: &str, lang: TargetLang) {
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "}}");
        }
        TargetLang::FSharp => {}
        TargetLang::VbNet => {
            let _ = writeln!(text, "{}", vb_body_terminator(signature));
        }
    }
}

fn vb_body_terminator(signature: &str) -> &'static str {
    if signature.contains(") As ") {
        "End Function"
    } else {
        "End Sub"
    }
}

fn is_bare_integer_literal(value: &str) -> bool {
    let digits: &str = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b: u8| b.is_ascii_digit())
}

fn short(name: &str) -> String {
    let member: &str = name.rsplit("::").next().unwrap_or(name);
    let head: &str = member.split('<').next().unwrap_or(member);
    let prefix_len: usize = head.rfind('.').map_or(0, |dot: usize| dot + 1);
    member[prefix_len..].to_owned()
}

fn static_call_target(raw: &str, lang: TargetLang) -> String {
    let member: String = short(raw);
    if lang != TargetLang::CSharp {
        return member;
    }
    if crate::lambda_reverse::LINQ_EXTENSIONS.contains(&member.as_str()) {
        return member;
    }
    let Some((owner, _)): Option<(&str, &str)> = raw.rsplit_once("::") else {
        return member;
    };
    if owner.is_empty()
        || owner.contains('<')
        || owner.contains('>')
        || owner.contains('!')
        || owner.contains('[')
        || !owner
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        return member;
    }
    let owner_head: &str = owner.rsplit('.').next().unwrap_or(owner);
    if owner_head.is_empty() || !is_simple_identifier(owner_head) {
        return member;
    }
    format!("{owner}.{member}")
}

pub(crate) fn qualified_type_name(raw: &str, lang: TargetLang) -> String {
    let member: String = short(raw);
    if lang != TargetLang::CSharp || raw.contains("::") {
        return member;
    }
    let dotted: bool = !raw.is_empty()
        && raw
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.');
    if !dotted || !raw.rsplit('.').next().is_some_and(is_simple_identifier) {
        return member;
    }
    raw.to_owned()
}

pub fn field_name(name: &str) -> String {
    let raw: String = short(name);
    let recovered: Option<String> = auto_property_backing_name(&raw).map(str::to_owned);
    recovered.unwrap_or(raw)
}

fn auto_property_backing_name(short_name: &str) -> Option<&str> {
    short_name
        .strip_prefix('<')?
        .strip_suffix(">k__BackingField")
        .filter(|p: &&str| !p.is_empty() && is_simple_identifier(p))
}

fn is_simple_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c: char| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c: char| c == '_' || c.is_ascii_alphanumeric())
}

fn render_operand(op: &OperandValue) -> String {
    match op {
        OperandValue::None => String::new(),
        OperandValue::I32(v) => v.to_string(),
        OperandValue::I64(v) => format!("{v}L"),
        OperandValue::U8(v) => v.to_string(),
        OperandValue::U16(v) => v.to_string(),
        OperandValue::F32Bits(b) => f32::from_bits(*b).to_string(),
        OperandValue::F64Bits(b) => f64::from_bits(*b).to_string(),
        OperandValue::BrTarget(t) => format!("{t:+}"),
        OperandValue::Token(t) => format!("0x{t:08X}"),
        OperandValue::Switch(t) => format!("[{} targets]", t.len()),
    }
}

fn local_index(ins: &Instruction, name: &str) -> u32 {
    if let Some(rest) = name.rsplit('.').next()
        && let Ok(n) = rest.parse::<u32>()
    {
        return n;
    }
    match ins.operand {
        OperandValue::U8(b) => u32::from(b),
        OperandValue::U16(v) => u32::from(v),
        OperandValue::I32(v) => v.cast_unsigned(),
        _ => 0,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::{MethodBody, disassemble};

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    struct DelegateNamer;

    impl TokenNamer for DelegateNamer {
        fn name(&self, token: u32) -> String {
            match token {
                0x0400_0001 => "<>c::<>9".to_owned(),
                0x0600_0010 => "<>c::<Doubled>b__1_0".to_owned(),
                0x0600_0020 => "Repository::Process".to_owned(),
                0x0A00_0030 => "System.Func`2::.ctor".to_owned(),
                0x0A00_0040 => "System.Action::.ctor".to_owned(),
                other => format!("token_{other:08X}"),
            }
        }

        fn call_info(&self, token: u32) -> Option<CallInfo> {
            matches!(token, 0x0A00_0030 | 0x0A00_0040).then_some(CallInfo {
                arg_count: 3,
                returns_value: false,
                has_this: true,
                byref_param_mask: 0,
            })
        }
    }

    struct RuntimeHandleNamer;

    impl TokenNamer for RuntimeHandleNamer {
        fn name(&self, token: u32) -> String {
            match token {
                0x0400_0001 => "<PrivateImplementationDetails>::Data".to_owned(),
                0x0A00_0001 => "System.Type::GetTypeFromHandle".to_owned(),
                other => format!("token_{other:08X}"),
            }
        }

        fn token_kind(&self, token: u32) -> MetadataTokenKind {
            match token {
                0x0400_0001 => MetadataTokenKind::Field,
                0x0A00_0001 => MetadataTokenKind::Method,
                _ => MetadataTokenKind::Unknown,
            }
        }

        fn call_info(&self, token: u32) -> Option<CallInfo> {
            (token == 0x0A00_0001).then_some(CallInfo {
                arg_count: 1,
                returns_value: true,
                has_this: false,
                byref_param_mask: 0,
            })
        }
    }

    #[test]
    fn field_handle_never_lifts_as_a_typeof_expression() {
        let mut code: Vec<u8> = vec![0xD0];
        code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
        code.push(0x28);
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("Type M()", &body, &RuntimeHandleNamer);
        assert!(
            out.body.contains("__unreconstructed_runtime_handle"),
            "field handles must remain explicitly unreconstructed; got:\n{}",
            out.body
        );
    }

    #[test]
    fn runtime_handle_refusal_compiles_in_return_assignment_and_argument_positions() {
        let expression: String = runtime_handle_refusal(
            TargetLang::CSharp,
            "System.RuntimeFieldHandle",
            UNRECONSTRUCTED_RUNTIME_HANDLE,
        );
        let source: String = format!(
            "public static class RuntimeHandleProbe\n{{\n    public static System.RuntimeFieldHandle ReturnHandle()\n    {{\n        return {expression};\n    }}\n\n    public static void AssignHandle()\n    {{\n        System.RuntimeFieldHandle value = {expression};\n    }}\n\n    public static void PassHandle()\n    {{\n        Accept({expression});\n    }}\n\n    private static void Accept(System.RuntimeFieldHandle value)\n    {{\n    }}\n}}\n"
        );
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_runtime_handle_refusal")
                .expect("create runtime-handle compiler scratch directory");
        let directory: &std::path::Path = scratch.path();
        std::fs::write(
            directory.join("RuntimeHandleProbe.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net9.0</TargetFramework><Nullable>disable</Nullable><ImplicitUsings>disable</ImplicitUsings><GenerateAssemblyInfo>false</GenerateAssemblyInfo></PropertyGroup></Project>",
        )
        .expect("write runtime-handle compiler project");
        std::fs::write(directory.join("RuntimeHandleProbe.cs"), source)
            .expect("write runtime-handle compiler source");
        let output: std::process::Output = std::process::Command::new("dotnet")
            .args(["build", "-c", "Release", "-v", "q", "-nologo"])
            .current_dir(directory)
            .output()
            .expect("run runtime-handle compiler");
        assert!(
            output.status.success(),
            "runtime-handle refusal must compile in every C# expression position:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    struct FieldRvaNamer;

    impl TokenNamer for FieldRvaNamer {
        fn name(&self, token: u32) -> String {
            match token {
                0x0100_0001 => "System.Int32".to_owned(),
                0x0400_0001 => "<PrivateImplementationDetails>::Data".to_owned(),
                0x0A00_0001 => {
                    "System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray".to_owned()
                }
                other => format!("token_{other:08X}"),
            }
        }

        fn token_kind(&self, token: u32) -> MetadataTokenKind {
            match token {
                0x0100_0001 => MetadataTokenKind::Type,
                0x0400_0001 => MetadataTokenKind::Field,
                0x0A00_0001 => MetadataTokenKind::Method,
                _ => MetadataTokenKind::Unknown,
            }
        }

        fn call_info(&self, token: u32) -> Option<CallInfo> {
            (token == 0x0A00_0001).then_some(CallInfo {
                arg_count: 2,
                returns_value: false,
                has_this: false,
                byref_param_mask: 0,
            })
        }

        fn field_rva_bytes(&self, token: u32) -> Option<&[u8]> {
            (token == 0x0400_0001).then_some(&[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0][..])
        }

        fn field_rva_primitive(&self, token: u32) -> Option<FieldRvaPrimitive> {
            (token == 0x0100_0001).then_some(FieldRvaPrimitive::I4)
        }

        fn is_initialize_array(&self, token: u32) -> bool {
            token == 0x0A00_0001
        }
    }

    #[test]
    fn authenticated_initialize_array_lifts_a_fixed_width_literal() {
        let mut code: Vec<u8> = vec![0x19, 0x8D];
        code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        code.push(0x25);
        code.push(0xD0);
        code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
        code.push(0x28);
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.extend_from_slice(&[0x0A, 0x2A]);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M()", &body, &FieldRvaNamer);
        assert!(
            out.body
                .contains("local0 = new System.Int32[3] { 1, 2, 3 };"),
            "authenticated FieldRVA bytes must become the literal initializer; got:\n{}",
            out.body
        );
    }

    #[test]
    fn initialize_array_without_duplicate_never_mutates_another_equal_array() {
        let mut code: Vec<u8> = vec![0x19, 0x8D];
        code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        code.extend_from_slice(&[0x19, 0x8D]);
        code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        code.push(0xD0);
        code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
        code.push(0x28);
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("int[] M()", &body, &FieldRvaNamer);
        assert!(
            !out.body.contains("new System.Int32[3] { 1, 2, 3 }"),
            "InitializeArray without dup must not mutate the unrelated retained array; got:\n{}",
            out.body
        );
    }

    struct SpoofedPrimitiveNamer;

    impl TokenNamer for SpoofedPrimitiveNamer {
        fn name(&self, token: u32) -> String {
            FieldRvaNamer.name(token)
        }

        fn token_kind(&self, token: u32) -> MetadataTokenKind {
            FieldRvaNamer.token_kind(token)
        }

        fn call_info(&self, token: u32) -> Option<CallInfo> {
            FieldRvaNamer.call_info(token)
        }

        fn field_rva_bytes(&self, token: u32) -> Option<&[u8]> {
            FieldRvaNamer.field_rva_bytes(token)
        }

        fn is_initialize_array(&self, token: u32) -> bool {
            FieldRvaNamer.is_initialize_array(token)
        }
    }

    #[test]
    fn rendered_primitive_name_without_corelib_identity_does_not_fold_field_rva() {
        let mut code: Vec<u8> = vec![0x19, 0x8D];
        code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        code.push(0x25);
        code.push(0xD0);
        code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
        code.push(0x28);
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.extend_from_slice(&[0x0A, 0x2A]);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M()", &body, &SpoofedPrimitiveNamer);
        assert!(
            !out.body.contains("new System.Int32[3] { 1, 2, 3 }"),
            "a rendered System.Int32 name without authenticated corelib identity must not fold FieldRVA bytes; got:\n{}",
            out.body
        );
    }

    #[test]
    fn lifts_addition_to_return_expression() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x58, 0x2A]);
        let out: StructuredMethod =
            decompile_method("int Add(int arg1, int arg2)", &body, &HexNamer);
        assert!(
            out.body.contains("return arg1 + arg2;"),
            "got:\n{}",
            out.body
        );
    }

    #[test]
    fn lifts_local_store_and_load() {
        let body: MethodBody = body_from(&[0x1B, 0x0A, 0x06, 0x2A]);
        let out: StructuredMethod = decompile_method("int M()", &body, &HexNamer);
        assert!(out.body.contains("local0 = 5;"), "got:\n{}", out.body);
        assert!(out.body.contains("return local0;"));
        assert_eq!(out.recovered_locals, 1);
    }

    #[test]
    fn conditional_branch_emits_structured_if() {
        let body: MethodBody = body_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method("void M(bool arg0)", &body, &HexNamer);
        assert!(out.body.contains("if ("), "got:\n{}", out.body);
        assert!(
            !out.body.contains("goto IL_"),
            "structured if must not leave a goto; got:\n{}",
            out.body
        );
        assert_eq!(out.recovered_branches, 0, "no residual gotos");
    }

    #[test]
    fn compare_branch_recovers_canonical_guard_polarity() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x2F, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method("void M(int a, int b)", &body, &HexNamer);
        assert!(
            out.body.contains("if (arg1 < arg2)"),
            "bge taken to the tail recovers the negated fall-through guard csc emits canonically; got:\n{}",
            out.body
        );
    }

    #[test]
    fn switch_renders_switch_header() {
        let code: [u8; 14] = [
            0x03, 0x45, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M(int arg1)", &body, &HexNamer);
        assert!(out.body.contains("switch (arg1)"), "got:\n{}", out.body);
    }

    #[test]
    fn signature_and_braces_present() {
        let body: MethodBody = body_from(&[0x2A]);
        let out: StructuredMethod = decompile_method("void Empty()", &body, &HexNamer);
        assert!(out.body.starts_with("void Empty()\n{\n"));
        assert!(out.body.trim_end().ends_with('}'));
    }

    #[test]
    fn dup_of_a_compound_keeps_parentheses_when_reused_as_a_binary_operand() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x58, 0x25, 0x5A, 0x2A]);
        let out: StructuredMethod = decompile_method("int M(int arg1, int arg2)", &body, &HexNamer);
        assert!(
            out.body.contains("return (arg1 + arg2) * (arg1 + arg2);"),
            "a duplicated additive subexpression multiplied by itself must stay parenthesized so the value is (a+b)*(a+b); got:\n{}",
            out.body
        );
        assert!(
            !out.body.contains("* arg1 + arg2"),
            "dropping the parentheses reassociates to (a+b)*a + b and changes the value; got:\n{}",
            out.body
        );
    }

    #[test]
    fn ldstr_renders_string_literal() {
        let mut code: Vec<u8> = vec![0x72];
        code.extend_from_slice(&0x7000_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M()", &body, &HexNamer);
        assert!(out.body.contains('"'), "got:\n{}", out.body);
    }

    struct LineSeparatorNamer;

    impl TokenNamer for LineSeparatorNamer {
        fn name(&self, _token: u32) -> String {
            "start\u{2028}mid\u{2029}end".to_owned()
        }
    }

    #[test]
    fn keyword_identifiers_take_the_at_prefix() {
        assert_eq!(csharp_escape_identifier("object"), "@object");
        assert_eq!(csharp_escape_identifier("string"), "@string");
        assert_eq!(csharp_escape_identifier("event"), "@event");
        assert_eq!(csharp_escape_identifier("ref"), "@ref");
        assert_eq!(csharp_escape_identifier("params"), "@params");
    }

    #[test]
    fn non_keyword_and_already_escaped_identifiers_are_unchanged() {
        assert_eq!(csharp_escape_identifier("count"), "count");
        assert_eq!(csharp_escape_identifier("var"), "var");
        assert_eq!(csharp_escape_identifier("value"), "value");
        assert_eq!(csharp_escape_identifier("async"), "async");
        assert_eq!(csharp_escape_identifier("@object"), "@object");
        assert_eq!(csharp_escape_identifier(""), "");
    }

    #[test]
    fn line_separator_code_points_escape_for_recompile() {
        assert_eq!(csharp_string_literal("a\u{2028}b"), "\"a\\u2028b\"");
        assert_eq!(csharp_string_literal("x\u{2029}y"), "\"x\\u2029y\"");
        let literal: String = csharp_string_literal("p\u{2028}q\u{2029}r");
        assert!(
            !literal.contains('\u{2028}'),
            "raw line separator leaked: {literal}"
        );
        assert!(
            !literal.contains('\u{2029}'),
            "raw paragraph separator leaked: {literal}"
        );
    }

    #[test]
    fn ldstr_escapes_line_and_paragraph_separators() {
        let mut code: Vec<u8> = vec![0x72];
        code.extend_from_slice(&0x7000_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M()", &body, &LineSeparatorNamer);
        assert!(
            out.body.contains("\"start\\u2028mid\\u2029end\""),
            "got:\n{}",
            out.body
        );
        assert!(
            !out.body.contains('\u{2028}') && !out.body.contains('\u{2029}'),
            "raw separator leaked into recompilable output:\n{}",
            out.body
        );
    }

    #[test]
    fn throw_renders_throw_statement() {
        let mut code: Vec<u8> = vec![0x73];
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.push(0x7A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M()", &body, &HexNamer);
        assert!(out.body.contains("throw new"), "got:\n{}", out.body);
    }

    #[test]
    fn vbnet_lifts_addition_to_return() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x58, 0x2A]);
        let out: StructuredMethod = decompile_method_in(
            "Public Function Add(arg1 As Integer, arg2 As Integer) As Integer",
            &body,
            &HexNamer,
            TargetLang::VbNet,
        );
        assert!(
            out.body.contains("Return arg1 + arg2"),
            "got:\n{}",
            out.body
        );
        assert!(out.body.contains("End Function"), "got:\n{}", out.body);
    }

    #[test]
    fn fsharp_lifts_addition_to_return() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x58, 0x2A]);
        let out: StructuredMethod = decompile_method_in(
            "member Add(arg1: int, arg2: int) : int",
            &body,
            &HexNamer,
            TargetLang::FSharp,
        );
        assert!(out.body.contains("arg1 + arg2"), "got:\n{}", out.body);
        assert!(out.body.contains(FSHARP_GOTO_BANNER), "got:\n{}", out.body);
    }

    #[test]
    fn vbnet_local_store_uses_dim_and_assign() {
        let body: MethodBody = body_from(&[0x1B, 0x0A, 0x06, 0x2A]);
        let out: StructuredMethod =
            decompile_method_in("Public Sub M()", &body, &HexNamer, TargetLang::VbNet);
        assert!(out.body.contains("Dim local0"), "got:\n{}", out.body);
        assert!(out.body.contains("local0 = 5"), "got:\n{}", out.body);
        assert!(out.body.contains("Return local0"), "got:\n{}", out.body);
        assert!(out.body.contains("End Sub"), "got:\n{}", out.body);
    }

    #[test]
    fn fsharp_local_store_uses_let_mutable_and_rebind() {
        let body: MethodBody = body_from(&[0x1B, 0x0A, 0x06, 0x2A]);
        let out: StructuredMethod =
            decompile_method_in("member M() : int", &body, &HexNamer, TargetLang::FSharp);
        assert!(
            out.body.contains("let mutable local0"),
            "got:\n{}",
            out.body
        );
        assert!(out.body.contains("local0 <- 5"), "got:\n{}", out.body);
    }

    #[test]
    fn fsharp_conditional_branch_is_structured_if() {
        let body: MethodBody = body_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method_in(
            "member M(arg0: bool) : unit",
            &body,
            &HexNamer,
            TargetLang::FSharp,
        );
        assert!(out.body.contains("if "), "got:\n{}", out.body);
        assert!(
            !out.body
                .lines()
                .any(|l: &str| l.trim_start().starts_with("goto ")),
            "F# must never emit a bare goto; got:\n{}",
            out.body
        );
    }

    #[test]
    fn vbnet_conditional_branch_emits_structured_if() {
        let body: MethodBody = body_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method_in(
            "Public Sub M(arg0 As Boolean)",
            &body,
            &HexNamer,
            TargetLang::VbNet,
        );
        assert!(out.body.contains("If "), "got:\n{}", out.body);
        assert!(out.body.contains("End If"), "got:\n{}", out.body);
        assert!(
            !out.body.contains("GoTo IL_"),
            "structured if must not leave a goto; got:\n{}",
            out.body
        );
    }

    #[test]
    fn vbnet_switch_renders_select_case_header() {
        let code: [u8; 14] = [
            0x03, 0x45, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method_in(
            "Public Sub M(arg1 As Integer)",
            &body,
            &HexNamer,
            TargetLang::VbNet,
        );
        assert!(out.body.contains("Select Case arg1"), "got:\n{}", out.body);
        assert!(out.body.contains("End Select"), "got:\n{}", out.body);
    }

    #[test]
    fn ldelema_lifts_to_element_address_not_value() {
        let mut code: Vec<u8> = vec![0x03, 0x17, 0x8F];
        code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M(int[] arg1)", &body, &HexNamer);
        assert!(
            out.body.contains("return &arg1[1];"),
            "ldelema must yield an element address, not a value; got:\n{}",
            out.body
        );
        assert!(
            !out.body.contains("ldelema"),
            "no opcode comment placeholder remains; got:\n{}",
            out.body
        );
    }

    #[test]
    fn ckfinite_passes_value_through() {
        let body: MethodBody = body_from(&[0x03, 0xC3, 0x2A]);
        let out: StructuredMethod = decompile_method("double M(double arg1)", &body, &HexNamer);
        assert!(out.body.contains("return arg1;"), "got:\n{}", out.body);
        assert!(!out.body.contains("ckfinite"), "got:\n{}", out.body);
    }

    #[test]
    fn arglist_lifts_to_runtime_argument_handle() {
        let body: MethodBody = body_from(&[0xFE, 0x00, 0x2A]);
        let out: StructuredMethod = decompile_method("RuntimeArgumentHandle M()", &body, &HexNamer);
        assert!(out.body.contains("return __arglist;"), "got:\n{}", out.body);
    }

    #[test]
    fn cpblk_lifts_to_copyblock_intrinsic() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x05, 0xFE, 0x17, 0x2A]);
        let out: StructuredMethod = decompile_method(
            "void M(void* arg1, void* arg2, uint arg3)",
            &body,
            &HexNamer,
        );
        assert!(
            out.body.contains("Unsafe.CopyBlock(arg1, arg2, arg3)"),
            "cpblk must lift to the CopyBlock intrinsic; got:\n{}",
            out.body
        );
        assert!(!out.body.contains("cpblk"), "got:\n{}", out.body);
    }

    #[test]
    fn initblk_lifts_to_initblock_intrinsic() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x05, 0xFE, 0x18, 0x2A]);
        let out: StructuredMethod =
            decompile_method("void M(void* arg1, byte arg2, uint arg3)", &body, &HexNamer);
        assert!(
            out.body.contains("Unsafe.InitBlock(arg1, arg2, arg3)"),
            "initblk must lift to the InitBlock intrinsic; got:\n{}",
            out.body
        );
        assert!(!out.body.contains("initblk"), "got:\n{}", out.body);
    }

    #[test]
    fn static_lambda_delegate_recovers_method_group() {
        let mut code: Vec<u8> = vec![0x7E];
        code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
        code.extend_from_slice(&[0xFE, 0x06]);
        code.extend_from_slice(&0x0600_0010u32.to_le_bytes());
        code.push(0x73);
        code.extend_from_slice(&0x0A00_0030u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("Func<int, int> M()", &body, &DelegateNamer);
        assert!(
            out.body.contains("return <Doubled>b__1_0;"),
            "ldftn->newobj must collapse to a bare method group for a static lambda; got:\n{}",
            out.body
        );
        assert!(
            !out.body.contains("new Func") && !out.body.contains("<>9"),
            "delegate ctor and synthetic singleton receiver dropped; got:\n{}",
            out.body
        );
    }

    #[test]
    fn instance_delegate_recovers_bound_method_group() {
        let mut code: Vec<u8> = vec![0x02];
        code.extend_from_slice(&[0xFE, 0x06]);
        code.extend_from_slice(&0x0600_0020u32.to_le_bytes());
        code.push(0x73);
        code.extend_from_slice(&0x0A00_0040u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("Action M()", &body, &DelegateNamer);
        assert!(
            out.body.contains("return this.Process;"),
            "instance delegate must bind the receiver into a method group; got:\n{}",
            out.body
        );
        assert!(!out.body.contains("new Action"), "got:\n{}", out.body);
    }

    #[test]
    fn ldvirtftn_delegate_recovers_virtual_method_group() {
        let mut code: Vec<u8> = vec![0x02, 0x25];
        code.extend_from_slice(&[0xFE, 0x07]);
        code.extend_from_slice(&0x0600_0020u32.to_le_bytes());
        code.push(0x73);
        code.extend_from_slice(&0x0A00_0040u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("Action M()", &body, &DelegateNamer);
        assert!(
            out.body.contains("return this.Process;"),
            "ldvirtftn delegate must bind its receiver into a method group; got:\n{}",
            out.body
        );
    }

    struct FilterNamer;

    impl TokenNamer for FilterNamer {
        fn name(&self, token: u32) -> String {
            match token {
                0x0100_0050 => "System.InvalidOperationException".to_owned(),
                other => format!("token_{other:08X}"),
            }
        }

        fn outer_has_this(&self) -> bool {
            false
        }
    }

    #[test]
    fn filter_single_comparison_recovers_typed_guard() {
        let mut code: Vec<u8> = vec![0x75];
        code.extend_from_slice(&0x0100_0050u32.to_le_bytes());
        code.extend_from_slice(&[0x25, 0x2D, 0x04, 0x26, 0x16, 0x2B, 0x05, 0x02, 0x1F, 0x05]);
        code.extend_from_slice(&[0xFE, 0x01, 0xFE, 0x11]);
        let body: MethodBody = normalize_branches(&body_from(&code));
        let last: usize = body.instructions.len() - 1;
        let (catch_type, cond): (Option<String>, String) = lift_filter_condition(
            &FilterNamer,
            &NameTable::default(),
            TargetLang::CSharp,
            &body.instructions,
            0,
            last,
        )
        .expect("filter recovered");
        assert_eq!(
            catch_type.as_deref(),
            Some("System.InvalidOperationException")
        );
        assert_eq!(cond, "arg1 == 5");
    }

    #[test]
    fn filter_short_circuit_and_recovers_conjunction() {
        let mut code: Vec<u8> = vec![0x75];
        code.extend_from_slice(&0x0100_0050u32.to_le_bytes());
        code.extend_from_slice(&[0x25, 0x2D, 0x04, 0x26, 0x16, 0x2B, 0x0E]);
        code.extend_from_slice(&[0x02, 0x1F, 0x05, 0x33, 0x06]);
        code.extend_from_slice(&[0x03, 0x1F, 0x07, 0xFE, 0x01]);
        code.extend_from_slice(&[0x2B, 0x01, 0x16, 0xFE, 0x11]);
        let body: MethodBody = normalize_branches(&body_from(&code));
        let last: usize = body.instructions.len() - 1;
        let (catch_type, cond): (Option<String>, String) = lift_filter_condition(
            &FilterNamer,
            &NameTable::default(),
            TargetLang::CSharp,
            &body.instructions,
            0,
            last,
        )
        .expect("filter recovered");
        assert_eq!(
            catch_type.as_deref(),
            Some("System.InvalidOperationException")
        );
        assert_eq!(
            cond, "arg1 == 5 && arg2 == 7",
            "short-circuit && must reconstruct both positive conjuncts"
        );
    }

    #[test]
    fn static_call_qualifies_with_declaring_type() {
        assert_eq!(
            static_call_target("System.Threading.Tasks.Task::WhenAny", TargetLang::CSharp),
            "System.Threading.Tasks.Task.WhenAny"
        );
        assert_eq!(
            static_call_target("System.IO.Directory::EnumerateFiles", TargetLang::CSharp),
            "System.IO.Directory.EnumerateFiles"
        );
    }

    #[test]
    fn static_call_leaves_generated_and_placeholder_owners_bare() {
        assert_eq!(
            static_call_target("<>c__DisplayClass0_0::Foo", TargetLang::CSharp),
            "Foo"
        );
        assert_eq!(
            static_call_target(
                "EdgeCases.More.GraphAdjacency<!0>::Neighbors",
                TargetLang::CSharp
            ),
            "Neighbors"
        );
        assert_eq!(
            static_call_target("BareName", TargetLang::CSharp),
            "BareName"
        );
    }

    #[test]
    fn static_call_qualification_is_csharp_only() {
        assert_eq!(
            static_call_target("System.String::Format", TargetLang::VbNet),
            "Format"
        );
    }

    #[test]
    fn call_receiver_drops_address_of() {
        let names: NameTable = NameTable::default();
        let recv: Expr = Expr::AddressOf(Box::new(Expr::Local(2)));
        assert_eq!(call_receiver(&recv, TargetLang::CSharp, &names), "local2");
        let field_recv: Expr = Expr::AddressOf(Box::new(Expr::Field("this.x".to_owned())));
        assert_eq!(
            call_receiver(&field_recv, TargetLang::CSharp, &names),
            "this.x"
        );
    }

    #[test]
    fn deref_target_collapses_address_of_to_plain_lvalue() {
        let names: NameTable = NameTable::default();
        let addr: Expr = Expr::AddressOf(Box::new(Expr::Local(2)));
        assert_eq!(deref_target(&addr, TargetLang::CSharp, &names), "local2");
        let raw_ptr: Expr = Expr::Local(5);
        assert_eq!(
            deref_target(&raw_ptr, TargetLang::CSharp, &names),
            "*local5"
        );
    }

    #[test]
    fn managed_byref_arg_derefs_directly_but_pointer_keeps_star() {
        let byref: NameTable = NameTable::new(
            true,
            vec!["value".to_owned()],
            vec!["ref int".to_owned()],
            Vec::new(),
        );
        let arg: Expr = Expr::Arg(1);
        assert_eq!(deref_target(&arg, TargetLang::CSharp, &byref), "value");
        assert_eq!(
            Expr::Deref(Box::new(Expr::Arg(1))).render(TargetLang::CSharp, &byref),
            "value"
        );
        let ptr: NameTable = NameTable::new(
            true,
            vec!["value".to_owned()],
            vec!["int*".to_owned()],
            Vec::new(),
        );
        assert_eq!(deref_target(&arg, TargetLang::CSharp, &ptr), "*value");
        assert_eq!(
            Expr::Deref(Box::new(Expr::Arg(1))).render(TargetLang::CSharp, &ptr),
            "*value"
        );
    }

    #[test]
    fn call_info_arg_byref_accounts_for_receiver_slot() {
        let info: CallInfo = CallInfo {
            arg_count: 3,
            returns_value: true,
            has_this: true,
            byref_param_mask: 0b10,
        };
        assert!(!info.arg_is_byref(0));
        assert!(!info.arg_is_byref(1));
        assert!(info.arg_is_byref(2));
    }

    fn returned_literal(sig: &str, code: &[u8]) -> String {
        let body: MethodBody = body_from(code);
        let out: StructuredMethod = decompile_method(sig, &body, &HexNamer);
        out.body
    }

    #[test]
    fn integral_double_keeps_double_type() {
        let body: String =
            returned_literal("double M()", &[0x23, 0, 0, 0, 0, 0, 0, 0x08, 0x40, 0x2A]);
        assert!(body.contains("return 3D;"), "got:\n{body}");
        assert!(!body.contains("return 3;"), "got:\n{body}");
    }

    #[test]
    fn double_specials_render_as_named_members() {
        let nan: String =
            returned_literal("double M()", &[0x23, 0, 0, 0, 0, 0, 0, 0xF8, 0x7F, 0x2A]);
        assert!(nan.contains("return double.NaN;"), "got:\n{nan}");
        let pinf: String =
            returned_literal("double M()", &[0x23, 0, 0, 0, 0, 0, 0, 0xF0, 0x7F, 0x2A]);
        assert!(
            pinf.contains("return double.PositiveInfinity;"),
            "got:\n{pinf}"
        );
        let ninf: String =
            returned_literal("double M()", &[0x23, 0, 0, 0, 0, 0, 0, 0xF0, 0xFF, 0x2A]);
        assert!(
            ninf.contains("return double.NegativeInfinity;"),
            "got:\n{ninf}"
        );
    }

    #[test]
    fn single_specials_render_as_named_members() {
        let three: String = returned_literal("float M()", &[0x22, 0, 0, 0x40, 0x40, 0x2A]);
        assert!(three.contains("return 3f;"), "got:\n{three}");
        let nan: String = returned_literal("float M()", &[0x22, 0, 0, 0xC0, 0x7F, 0x2A]);
        assert!(nan.contains("return float.NaN;"), "got:\n{nan}");
        let pinf: String = returned_literal("float M()", &[0x22, 0, 0, 0x80, 0x7F, 0x2A]);
        assert!(
            pinf.contains("return float.PositiveInfinity;"),
            "got:\n{pinf}"
        );
    }

    #[test]
    fn binary_expression_past_bound_is_marked_unrecovered() {
        let mut code: Vec<u8> = Vec::with_capacity(3 * MAX_EXPR_DEPTH + 2);
        code.push(0x16);
        for _index in 0..MAX_EXPR_DEPTH {
            code.extend_from_slice(&[0x17, 0x58]);
        }
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let output: StructuredMethod = decompile_method("int Deep()", &body, &HexNamer);
        assert!(output.body.contains("unrecovered"), "got:\n{}", output.body);
    }

    #[test]
    fn unary_expression_past_bound_is_marked_unrecovered() {
        let mut code: Vec<u8> = Vec::with_capacity(MAX_EXPR_DEPTH + 2);
        code.push(0x17);
        code.extend(std::iter::repeat_n(0x65, MAX_EXPR_DEPTH));
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let output: StructuredMethod = decompile_method("int Deep()", &body, &HexNamer);
        assert!(output.body.contains("unrecovered"), "got:\n{}", output.body);
    }

    #[test]
    fn maximum_bounded_expression_builds_without_a_marker() {
        let mut code: Vec<u8> = Vec::with_capacity(MAX_EXPR_DEPTH + 1);
        code.push(0x17);
        code.extend(std::iter::repeat_n(0x65, MAX_EXPR_DEPTH - 1));
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let output: StructuredMethod = decompile_method("int Deep()", &body, &HexNamer);
        assert!(
            !output.body.contains("unrecovered"),
            "got:\n{}",
            output.body
        );
        assert!(output.body.contains('1'));
    }

    #[test]
    fn maximum_bounded_expression_renders() {
        let mut expression: Expr = Expr::Const("1".to_owned());
        for _index in 1..256 {
            expression = Expr::Unary("-", Box::new(expression));
        }
        let rendered: String = expression.render(TargetLang::CSharp, &NameTable::default());
        assert!(rendered.contains('1'));
    }

    #[test]
    fn fsharp_coalesce_renderer_keeps_the_null_predicate() {
        let expression: Expr = Expr::Coalesce(
            Box::new(Expr::Local(0)),
            Box::new(Expr::Const("fallback".to_owned())),
        );
        let rendered: String = expression.render(TargetLang::FSharp, &NameTable::default());
        assert_eq!(rendered, "(if local0 <> null then local0 else fallback)");
    }

    #[test]
    fn expression_renderer_does_not_use_tree_depth_as_call_depth() {
        let handle: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(1_048_576)
            .spawn(|| {
                let mut expression: Expr = Expr::Const("1".to_owned());
                for _index in 0..10_000 {
                    expression = Expr::Unary("-", Box::new(expression));
                }
                let rendered: String = expression.render(TargetLang::CSharp, &NameTable::default());
                assert!(rendered.contains('1'));
                std::mem::forget(expression);
            })
            .expect("spawn render thread");
        handle.join().expect("render thread");
    }

    #[test]
    fn deep_expression_drop_does_not_use_tree_depth_as_call_depth() {
        let handle: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(1_048_576)
            .spawn(|| {
                let mut expression: Expr = Expr::Const("1".to_owned());
                for _index in 0..100_000 {
                    expression = Expr::Unary("-", Box::new(expression));
                }
                std::hint::black_box(&expression);
            })
            .expect("spawn drop thread");
        handle.join().expect("drop thread");
    }
}
