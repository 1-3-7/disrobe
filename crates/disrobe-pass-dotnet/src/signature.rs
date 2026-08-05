use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::metadata::decompress_uint;
use crate::structurize::TargetLang;

pub mod element_type {
    pub const VOID: u8 = 0x01;
    pub const BOOLEAN: u8 = 0x02;
    pub const CHAR: u8 = 0x03;
    pub const I1: u8 = 0x04;
    pub const U1: u8 = 0x05;
    pub const I2: u8 = 0x06;
    pub const U2: u8 = 0x07;
    pub const I4: u8 = 0x08;
    pub const U4: u8 = 0x09;
    pub const I8: u8 = 0x0A;
    pub const U8: u8 = 0x0B;
    pub const R4: u8 = 0x0C;
    pub const R8: u8 = 0x0D;
    pub const STRING: u8 = 0x0E;
    pub const PTR: u8 = 0x0F;
    pub const BYREF: u8 = 0x10;
    pub const VALUETYPE: u8 = 0x11;
    pub const CLASS: u8 = 0x12;
    pub const VAR: u8 = 0x13;
    pub const ARRAY: u8 = 0x14;
    pub const GENERICINST: u8 = 0x15;
    pub const TYPEDBYREF: u8 = 0x16;
    pub const I: u8 = 0x18;
    pub const U: u8 = 0x19;
    pub const FNPTR: u8 = 0x1B;
    pub const OBJECT: u8 = 0x1C;
    pub const SZARRAY: u8 = 0x1D;
    pub const MVAR: u8 = 0x1E;
    pub const CMOD_REQD: u8 = 0x1F;
    pub const CMOD_OPT: u8 = 0x20;
    pub const PINNED: u8 = 0x45;
}

pub const SIG_HASTHIS: u8 = 0x20;
pub const SIG_EXPLICITTHIS: u8 = 0x40;
pub const SIG_GENERIC: u8 = 0x10;
pub const SIG_KIND_MASK: u8 = 0x0F;
pub const SIG_DEFAULT: u8 = 0x00;
pub const SIG_VARARG: u8 = 0x05;
pub const SIG_FIELD: u8 = 0x06;
pub const SIG_LOCAL: u8 = 0x07;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FieldSig {
    pub field_type: TypeSig,
    pub required_modifiers: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConditionKind {
    Boolean,
    Integral,
    Reference,
    GenericParameter,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSig {
    Void,
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
    R4,
    R8,
    String,
    IntPtr,
    UIntPtr,
    Object,
    TypedByRef,

    NamedType {
        is_value_type: bool,
        token: u32,
    },
    SzArray(Box<Self>),
    Array {
        element: Box<Self>,
        rank: u32,
    },
    Ptr(Box<Self>),
    ByRef(Box<Self>),
    Pinned(Box<Self>),
    GenericInst {
        base: Box<Self>,
        args: Vec<Self>,
    },

    Var(u32),

    MVar(u32),
    FnPtr,
    #[default]
    Unknown,
}

impl TypeSig {
    #[must_use]
    pub fn condition_kind(&self) -> ConditionKind {
        match self {
            Self::Boolean => ConditionKind::Boolean,
            Self::Char
            | Self::I1
            | Self::U1
            | Self::I2
            | Self::U2
            | Self::I4
            | Self::U4
            | Self::I8
            | Self::U8
            | Self::R4
            | Self::R8
            | Self::IntPtr
            | Self::UIntPtr
            | Self::Ptr(_)
            | Self::FnPtr => ConditionKind::Integral,
            Self::String | Self::Object | Self::SzArray(_) | Self::Array { .. } => {
                ConditionKind::Reference
            }
            Self::NamedType { is_value_type, .. } => {
                if *is_value_type {
                    ConditionKind::Integral
                } else {
                    ConditionKind::Reference
                }
            }
            Self::GenericInst { base, .. } => base.condition_kind(),
            Self::Pinned(inner) => inner.condition_kind(),
            Self::Var(_) | Self::MVar(_) => ConditionKind::GenericParameter,
            Self::Void | Self::TypedByRef | Self::ByRef(_) | Self::Unknown => {
                ConditionKind::Unknown
            }
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        self.render_in(TargetLang::CSharp)
    }

    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn render_in(&self, lang: TargetLang) -> String {
        match self {
            Self::Void => match lang {
                TargetLang::CSharp => "void".to_owned(),
                TargetLang::FSharp => "unit".to_owned(),
                TargetLang::VbNet => "void".to_owned(),
            },
            Self::Boolean => match lang {
                TargetLang::VbNet => "Boolean".to_owned(),
                _ => "bool".to_owned(),
            },
            Self::Char => match lang {
                TargetLang::VbNet => "Char".to_owned(),
                _ => "char".to_owned(),
            },
            Self::I1 => match lang {
                TargetLang::VbNet => "SByte".to_owned(),
                _ => "sbyte".to_owned(),
            },
            Self::U1 => match lang {
                TargetLang::VbNet => "Byte".to_owned(),
                _ => "byte".to_owned(),
            },
            Self::I2 => match lang {
                TargetLang::CSharp => "short".to_owned(),
                TargetLang::FSharp => "int16".to_owned(),
                TargetLang::VbNet => "Short".to_owned(),
            },
            Self::U2 => match lang {
                TargetLang::CSharp => "ushort".to_owned(),
                TargetLang::FSharp => "uint16".to_owned(),
                TargetLang::VbNet => "UShort".to_owned(),
            },
            Self::I4 => match lang {
                TargetLang::VbNet => "Integer".to_owned(),
                _ => "int".to_owned(),
            },
            Self::U4 => match lang {
                TargetLang::CSharp => "uint".to_owned(),
                TargetLang::FSharp => "uint32".to_owned(),
                TargetLang::VbNet => "UInteger".to_owned(),
            },
            Self::I8 => match lang {
                TargetLang::CSharp => "long".to_owned(),
                TargetLang::FSharp => "int64".to_owned(),
                TargetLang::VbNet => "Long".to_owned(),
            },
            Self::U8 => match lang {
                TargetLang::CSharp => "ulong".to_owned(),
                TargetLang::FSharp => "uint64".to_owned(),
                TargetLang::VbNet => "ULong".to_owned(),
            },
            Self::R4 => match lang {
                TargetLang::CSharp => "float".to_owned(),
                TargetLang::FSharp => "float32".to_owned(),
                TargetLang::VbNet => "Single".to_owned(),
            },
            Self::R8 => match lang {
                TargetLang::CSharp => "double".to_owned(),
                TargetLang::FSharp => "float".to_owned(),
                TargetLang::VbNet => "Double".to_owned(),
            },
            Self::String => match lang {
                TargetLang::VbNet => "String".to_owned(),
                _ => "string".to_owned(),
            },
            Self::IntPtr => match lang {
                TargetLang::CSharp => "nint".to_owned(),
                TargetLang::FSharp => "nativeint".to_owned(),
                TargetLang::VbNet => "IntPtr".to_owned(),
            },
            Self::UIntPtr => match lang {
                TargetLang::CSharp => "nuint".to_owned(),
                TargetLang::FSharp => "unativeint".to_owned(),
                TargetLang::VbNet => "UIntPtr".to_owned(),
            },
            Self::Object => match lang {
                TargetLang::CSharp => "object".to_owned(),
                TargetLang::FSharp => "obj".to_owned(),
                TargetLang::VbNet => "Object".to_owned(),
            },
            Self::TypedByRef => "System.TypedReference".to_owned(),
            Self::NamedType { token, .. } => format!("type(0x{token:08X})"),
            Self::SzArray(inner) => match lang {
                TargetLang::VbNet => format!("{}()", inner.render_in(lang)),
                _ => format!("{}[]", inner.render_in(lang)),
            },
            Self::Array { element, rank } => {
                let commas: String = ",".repeat((*rank).saturating_sub(1) as usize);
                format!("{}[{commas}]", element.render_in(lang))
            }
            Self::Ptr(inner) => format!("{}*", inner.render_in(lang)),
            Self::ByRef(inner) => match lang {
                TargetLang::CSharp => format!("ref {}", inner.render_in(lang)),
                TargetLang::FSharp => format!("byref<{}>", inner.render_in(lang)),
                TargetLang::VbNet => format!("ByRef {}", inner.render_in(lang)),
            },
            Self::Pinned(inner) => inner.render_in(lang),
            Self::GenericInst { base, args } => {
                let rendered: Vec<String> = args.iter().map(|a: &Self| a.render_in(lang)).collect();
                match lang {
                    TargetLang::VbNet => {
                        format!("{}(Of {})", base.render_in(lang), rendered.join(", "))
                    }
                    _ => format!("{}<{}>", base.render_in(lang), rendered.join(", ")),
                }
            }
            Self::Var(n) => format!("!{n}"),
            Self::MVar(n) => format!("!!{n}"),
            Self::FnPtr => "method*".to_owned(),
            Self::Unknown => match lang {
                TargetLang::CSharp => "object".to_owned(),
                TargetLang::FSharp => "obj".to_owned(),
                TargetLang::VbNet => "Object".to_owned(),
            },
        }
    }

    pub fn collect_tokens(&self, out: &mut Vec<u32>) {
        match self {
            Self::NamedType { token, .. } => out.push(*token),
            Self::SzArray(i) | Self::Ptr(i) | Self::ByRef(i) | Self::Pinned(i) => {
                i.collect_tokens(out);
            }
            Self::Array { element, .. } => element.collect_tokens(out),
            Self::GenericInst { base, args } => {
                base.collect_tokens(out);
                for a in args {
                    a.collect_tokens(out);
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MethodSig {
    pub calling_convention: u8,
    pub has_this: bool,
    pub explicit_this: bool,
    pub generic_param_count: u32,
    pub return_type: TypeSigOrVoid,
    pub params: Vec<TypeSig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeSigOrVoid {
    #[default]
    Void,
    Type(TypeSig),
}

impl TypeSigOrVoid {
    #[must_use]
    pub fn render(&self) -> String {
        self.render_in(TargetLang::CSharp)
    }

    #[must_use]
    pub fn render_in(&self, lang: TargetLang) -> String {
        match self {
            Self::Void => match lang {
                TargetLang::CSharp | TargetLang::VbNet => "void".to_owned(),
                TargetLang::FSharp => "unit".to_owned(),
            },
            Self::Type(t) => t.render_in(lang),
        }
    }
}

const MAX_SIG_DEPTH: usize = 256;
const MAX_SIGNATURE_NODES: usize = 4096;

struct SigReader<'a> {
    reader: ByteReader<'a>,
    depth: usize,
    nodes: usize,
    reject_custom_modifiers: bool,
}

impl<'a> SigReader<'a> {
    #[inline]
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            reader: ByteReader::new(bytes),
            depth: 0,
            nodes: 0,
            reject_custom_modifiers: false,
        }
    }

    #[inline]
    const fn new_strict(bytes: &'a [u8]) -> Self {
        Self {
            reader: ByteReader::new(bytes),
            depth: 0,
            nodes: 0,
            reject_custom_modifiers: true,
        }
    }

    #[inline]
    fn byte(&mut self) -> Result<u8> {
        let position: usize = self.reader.position();
        self.reader
            .read_u8()
            .map_err(|_| Error::BadCompressedUint(position))
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.reader.peek_u8().ok()
    }

    #[inline]
    const fn remaining(&self) -> usize {
        self.reader.remaining()
    }

    fn signature_capacity(&self, count: u32) -> Result<usize> {
        let count: usize = usize::try_from(count)
            .map_err(|_| Error::SignatureTooManyNodes(MAX_SIGNATURE_NODES))?;
        if count > MAX_SIGNATURE_NODES.saturating_sub(self.nodes) {
            return Err(Error::SignatureTooManyNodes(MAX_SIGNATURE_NODES));
        }
        Ok(count)
    }

    fn consume_node(&mut self) -> Result<()> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .filter(|nodes: &usize| *nodes <= MAX_SIGNATURE_NODES)
            .ok_or(Error::SignatureTooManyNodes(MAX_SIGNATURE_NODES))?;
        Ok(())
    }

    #[inline]
    fn compressed(&mut self) -> Result<u32> {
        let position: usize = self.reader.position();
        let bytes: &[u8] = self
            .reader
            .peek_bytes(self.reader.remaining())
            .map_err(|_| Error::BadCompressedUint(position))?;
        let (v, n): (u32, usize) =
            decompress_uint(bytes).ok_or(Error::BadCompressedUint(position))?;
        self.reader
            .skip(n)
            .map_err(|_| Error::BadCompressedUint(position))?;
        Ok(v)
    }

    fn type_def_or_ref(&mut self) -> Result<u32> {
        let coded: u32 = self.compressed()?;
        let tag: u32 = coded & 0x03;
        let rid: u32 = coded >> 2;
        if rid == 0 || rid > 0x00FF_FFFF {
            return Err(Error::BadCompressedUint(self.reader.position()));
        }
        let table: u32 = match tag {
            0 => 0x02,
            1 => 0x01,
            2 => 0x1B,
            _ => return Err(Error::BadCompressedUint(self.reader.position())),
        };
        Ok((table << 24) | rid)
    }

    fn type_sig(&mut self) -> Result<TypeSig> {
        self.consume_node()?;
        self.depth += 1;
        if self.depth > MAX_SIG_DEPTH {
            return Err(Error::SignatureTooDeep(MAX_SIG_DEPTH));
        }
        let parsed: Result<TypeSig> = self.type_sig_inner();
        self.depth -= 1;
        parsed
    }

    fn type_sig_inner(&mut self) -> Result<TypeSig> {
        use element_type as et;
        let mut leading_modifiers: bool = true;
        while leading_modifiers {
            match self.peek() {
                Some(et::CMOD_REQD | et::CMOD_OPT) => {
                    if self.reject_custom_modifiers {
                        return Err(Error::BadCompressedUint(self.reader.position()));
                    }
                    let _: u8 = self.byte()?;
                    let _ = self.type_def_or_ref()?;
                }
                Some(et::PINNED) => {
                    let _: u8 = self.byte()?;
                    let inner: TypeSig = self.type_sig()?;
                    return Ok(TypeSig::Pinned(Box::new(inner)));
                }
                _ => leading_modifiers = false,
            }
        }
        let elem: u8 = self.byte()?;
        Ok(match elem {
            et::VOID => TypeSig::Void,
            et::BOOLEAN => TypeSig::Boolean,
            et::CHAR => TypeSig::Char,
            et::I1 => TypeSig::I1,
            et::U1 => TypeSig::U1,
            et::I2 => TypeSig::I2,
            et::U2 => TypeSig::U2,
            et::I4 => TypeSig::I4,
            et::U4 => TypeSig::U4,
            et::I8 => TypeSig::I8,
            et::U8 => TypeSig::U8,
            et::R4 => TypeSig::R4,
            et::R8 => TypeSig::R8,
            et::STRING => TypeSig::String,
            et::OBJECT => TypeSig::Object,
            et::I => TypeSig::IntPtr,
            et::U => TypeSig::UIntPtr,
            et::TYPEDBYREF => TypeSig::TypedByRef,
            et::VALUETYPE => TypeSig::NamedType {
                is_value_type: true,
                token: self.type_def_or_ref()?,
            },
            et::CLASS => TypeSig::NamedType {
                is_value_type: false,
                token: self.type_def_or_ref()?,
            },
            et::SZARRAY => TypeSig::SzArray(Box::new(self.type_sig()?)),
            et::PTR => TypeSig::Ptr(Box::new(self.type_sig()?)),
            et::BYREF => TypeSig::ByRef(Box::new(self.type_sig()?)),
            et::VAR => TypeSig::Var(self.compressed()?),
            et::MVAR => TypeSig::MVar(self.compressed()?),
            et::ARRAY => {
                let element: TypeSig = self.type_sig()?;
                let rank: u32 = self.compressed()?;
                let num_sizes: u32 = self.compressed()?;
                if self.reject_custom_modifiers && (rank == 0 || num_sizes > rank) {
                    return Err(Error::BadCompressedUint(self.reader.position()));
                }
                for _ in 0..num_sizes {
                    let _ = self.compressed()?;
                }
                let num_lo: u32 = self.compressed()?;
                if self.reject_custom_modifiers && num_lo > rank {
                    return Err(Error::BadCompressedUint(self.reader.position()));
                }
                for _ in 0..num_lo {
                    let _ = self.compressed()?;
                }
                TypeSig::Array {
                    element: Box::new(element),
                    rank,
                }
            }
            et::GENERICINST => {
                let base_position: usize = self.reader.position();
                let base: TypeSig = self.type_sig()?;
                if self.reject_custom_modifiers && !matches!(base, TypeSig::NamedType { .. }) {
                    return Err(Error::BadCompressedUint(base_position));
                }
                let argc: u32 = self.compressed()?;
                if self.reject_custom_modifiers && argc == 0 {
                    return Err(Error::BadCompressedUint(self.reader.position()));
                }
                let capacity: usize = self.signature_capacity(argc)?;
                let mut args: Vec<TypeSig> = Vec::with_capacity(capacity);
                for _ in 0..argc {
                    args.push(self.type_sig()?);
                }
                TypeSig::GenericInst {
                    base: Box::new(base),
                    args,
                }
            }
            et::FNPTR => {
                let _ = self.parse_method_inner()?;
                TypeSig::FnPtr
            }
            _ if self.reject_custom_modifiers => {
                return Err(Error::BadCompressedUint(
                    self.reader.position().saturating_sub(1),
                ));
            }
            _ => TypeSig::Unknown,
        })
    }

    fn parse_method_inner(&mut self) -> Result<MethodSig> {
        let cc: u8 = self.byte()?;
        let calling_convention: u8 = cc;
        let has_this: bool = cc & SIG_HASTHIS != 0;
        let explicit_this: bool = cc & SIG_EXPLICITTHIS != 0;
        let generic_param_count: u32 = if cc & SIG_GENERIC != 0 {
            self.compressed()?
        } else {
            0
        };
        let param_count: u32 = self.compressed()?;
        let return_type: TypeSigOrVoid = match self.type_sig()? {
            TypeSig::Void => TypeSigOrVoid::Void,
            other => TypeSigOrVoid::Type(other),
        };
        let capacity: usize = self.signature_capacity(param_count)?;
        let mut params: Vec<TypeSig> = Vec::with_capacity(capacity);
        for _ in 0..param_count {
            if self.peek().is_none() {
                return Err(Error::BadCompressedUint(self.reader.position()));
            }
            params.push(self.type_sig()?);
        }
        Ok(MethodSig {
            calling_convention,
            has_this,
            explicit_this,
            generic_param_count,
            return_type,
            params,
        })
    }
}

fn parse_method_sig_with_reader(mut reader: SigReader<'_>) -> Result<MethodSig> {
    let signature: MethodSig = reader.parse_method_inner()?;
    if reader.remaining() != 0 {
        return Err(Error::BadCompressedUint(reader.reader.position()));
    }
    Ok(signature)
}

pub fn parse_method_sig(blob: &[u8]) -> Result<MethodSig> {
    if blob.is_empty() {
        return Err(Error::BadCompressedUint(0));
    }
    parse_method_sig_with_reader(SigReader::new(blob))
}

pub(crate) fn parse_method_sig_strict(blob: &[u8]) -> Result<MethodSig> {
    if blob.is_empty() {
        return Err(Error::BadCompressedUint(0));
    }
    parse_method_sig_with_reader(SigReader::new_strict(blob))
}

fn parse_method_spec_sig_with_reader(mut r: SigReader<'_>) -> Result<Vec<TypeSig>> {
    let cc: u8 = r.byte()?;
    if cc != 0x0A {
        return Err(Error::BadCompressedUint(0));
    }
    let count: u32 = r.compressed()?;
    let capacity: usize = r.signature_capacity(count)?;
    let mut args: Vec<TypeSig> = Vec::with_capacity(capacity);
    for _ in 0..count {
        if r.peek().is_none() {
            return Err(Error::BadCompressedUint(r.reader.position()));
        }
        args.push(r.type_sig()?);
    }
    if r.remaining() != 0 {
        return Err(Error::BadCompressedUint(r.reader.position()));
    }
    Ok(args)
}

pub fn parse_method_spec_sig(blob: &[u8]) -> Result<Vec<TypeSig>> {
    parse_method_spec_sig_with_reader(SigReader::new(blob))
}

pub(crate) fn parse_method_spec_sig_strict(blob: &[u8]) -> Result<Vec<TypeSig>> {
    parse_method_spec_sig_with_reader(SigReader::new_strict(blob))
}

fn parse_field_sig_with_modifiers_reader(mut r: SigReader<'_>) -> Result<FieldSig> {
    let cc: u8 = r.byte()?;
    if cc != SIG_FIELD {
        return Err(Error::BadCompressedUint(0));
    }
    let mut required_modifiers: Vec<u32> = Vec::new();
    let mut modifier_count: usize = 0;
    loop {
        match r.peek() {
            Some(element_type::CMOD_REQD) => {
                let _: u8 = r.byte()?;
                if modifier_count >= MAX_SIGNATURE_NODES {
                    return Err(Error::SignatureTooManyNodes(MAX_SIGNATURE_NODES));
                }
                modifier_count += 1;
                required_modifiers.push(r.type_def_or_ref()?);
            }
            Some(element_type::CMOD_OPT) => {
                let _: u8 = r.byte()?;
                if modifier_count >= MAX_SIGNATURE_NODES {
                    return Err(Error::SignatureTooManyNodes(MAX_SIGNATURE_NODES));
                }
                modifier_count += 1;
                let _: u32 = r.type_def_or_ref()?;
            }
            _ => break,
        }
    }
    let field_type: TypeSig = r.type_sig()?;
    if r.remaining() != 0 {
        return Err(Error::BadCompressedUint(r.reader.position()));
    }
    Ok(FieldSig {
        field_type,
        required_modifiers,
    })
}

pub fn parse_field_sig(blob: &[u8]) -> Result<TypeSig> {
    Ok(parse_field_sig_with_modifiers(blob)?.field_type)
}

pub(crate) fn parse_field_sig_with_modifiers(blob: &[u8]) -> Result<FieldSig> {
    parse_field_sig_with_modifiers_reader(SigReader::new(blob))
}

pub(crate) fn parse_field_sig_strict(blob: &[u8]) -> Result<TypeSig> {
    let mut r: SigReader<'_> = SigReader::new_strict(blob);
    let cc: u8 = r.byte()?;
    if cc != SIG_FIELD {
        return Err(Error::BadCompressedUint(0));
    }
    let signature: TypeSig = r.type_sig()?;
    if r.remaining() != 0 {
        return Err(Error::BadCompressedUint(r.reader.position()));
    }
    Ok(signature)
}

fn parse_local_sig_with_reader(mut r: SigReader<'_>) -> Result<Vec<TypeSig>> {
    let cc: u8 = r.byte()?;
    if cc != SIG_LOCAL {
        return Err(Error::BadCompressedUint(0));
    }
    let count: u32 = r.compressed()?;
    let capacity: usize = r.signature_capacity(count)?;
    let mut locals: Vec<TypeSig> = Vec::with_capacity(capacity);
    for _ in 0..count {
        if r.peek().is_none() {
            return Err(Error::BadCompressedUint(r.reader.position()));
        }
        if r.peek() == Some(element_type::TYPEDBYREF) {
            r.consume_node()?;
            let marker: u8 = r.byte()?;
            if marker != element_type::TYPEDBYREF {
                return Err(Error::BadCompressedUint(
                    r.reader.position().saturating_sub(1),
                ));
            }
            locals.push(TypeSig::TypedByRef);
            continue;
        }
        let local: TypeSig = r.type_sig()?;
        if r.reject_custom_modifiers && !valid_strict_local_type(&local) {
            return Err(Error::BadCompressedUint(r.reader.position()));
        }
        locals.push(local);
    }
    if r.remaining() != 0 {
        return Err(Error::BadCompressedUint(r.reader.position()));
    }
    Ok(locals)
}

pub fn parse_local_sig(blob: &[u8]) -> Result<Vec<TypeSig>> {
    parse_local_sig_with_reader(SigReader::new(blob))
}

pub(crate) fn parse_local_sig_strict(blob: &[u8]) -> Result<Vec<TypeSig>> {
    parse_local_sig_with_reader(SigReader::new_strict(blob))
}

fn valid_strict_local_type(signature: &TypeSig) -> bool {
    match signature {
        TypeSig::Void | TypeSig::Unknown => false,
        TypeSig::SzArray(inner)
        | TypeSig::Ptr(inner)
        | TypeSig::ByRef(inner)
        | TypeSig::Pinned(inner) => valid_strict_local_type(inner),
        TypeSig::Array { element, .. } => valid_strict_local_type(element),
        TypeSig::GenericInst { base, args } => {
            valid_strict_local_type(base) && args.iter().all(valid_strict_local_type)
        }
        _ => true,
    }
}

fn valid_strict_generic_argument(signature: &TypeSig) -> bool {
    match signature {
        TypeSig::Boolean
        | TypeSig::Char
        | TypeSig::I1
        | TypeSig::U1
        | TypeSig::I2
        | TypeSig::U2
        | TypeSig::I4
        | TypeSig::U4
        | TypeSig::I8
        | TypeSig::U8
        | TypeSig::R4
        | TypeSig::R8
        | TypeSig::String
        | TypeSig::IntPtr
        | TypeSig::UIntPtr
        | TypeSig::Object
        | TypeSig::NamedType { .. }
        | TypeSig::Var(_)
        | TypeSig::MVar(_) => true,
        TypeSig::Void
        | TypeSig::TypedByRef
        | TypeSig::Ptr(_)
        | TypeSig::ByRef(_)
        | TypeSig::Pinned(_)
        | TypeSig::FnPtr
        | TypeSig::Unknown => false,
        TypeSig::SzArray(inner) => valid_strict_generic_argument(inner),
        TypeSig::Array { element, rank } => *rank != 0 && valid_strict_generic_argument(element),
        TypeSig::GenericInst { base, args } => {
            matches!(base.as_ref(), TypeSig::NamedType { .. })
                && !args.is_empty()
                && args.iter().all(valid_strict_generic_argument)
        }
    }
}

fn valid_strict_type_spec(signature: &TypeSig) -> bool {
    match signature {
        TypeSig::SzArray(inner)
        | TypeSig::Ptr(inner)
        | TypeSig::ByRef(inner)
        | TypeSig::Pinned(inner) => valid_strict_type_spec(inner),
        TypeSig::Array { element, rank } => *rank != 0 && valid_strict_type_spec(element),
        TypeSig::GenericInst { base, args } => {
            matches!(base.as_ref(), TypeSig::NamedType { .. })
                && args.iter().all(valid_strict_generic_argument)
        }
        _ => valid_strict_local_type(signature),
    }
}

pub fn parse_type_spec_sig(blob: &[u8]) -> Result<TypeSig> {
    let mut r: SigReader<'_> = SigReader::new(blob);
    let signature: TypeSig = r.type_sig()?;
    if r.remaining() != 0 {
        return Err(Error::BadCompressedUint(r.reader.position()));
    }
    Ok(signature)
}

pub(crate) fn parse_type_spec_sig_strict(blob: &[u8]) -> Result<TypeSig> {
    let mut r: SigReader<'_> = SigReader::new_strict(blob);
    let signature: TypeSig = r.type_sig()?;
    if r.remaining() != 0 || !valid_strict_type_spec(&signature) {
        return Err(Error::BadCompressedUint(r.reader.position()));
    }
    Ok(signature)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generic_inst_huge_argc_hits_node_quota() {
        let blob: [u8; 8] = [
            SIG_FIELD,
            element_type::GENERICINST,
            element_type::CLASS,
            0x05,
            0xDF,
            0xFF,
            0xFF,
            0xFF,
        ];
        let result: Result<TypeSig> = parse_field_sig(&blob);
        assert!(
            matches!(
                result,
                Err(Error::SignatureTooManyNodes(MAX_SIGNATURE_NODES))
            ),
            "huge generic argc must fail before allocation; got {result:?}"
        );
    }

    #[test]
    fn deeply_nested_ptr_blob_errors_without_overflow() {
        const PTR_COUNT: usize = 100_000;
        let mut blob: Vec<u8> = Vec::with_capacity(PTR_COUNT + 2);
        blob.push(SIG_FIELD);
        blob.extend(std::iter::repeat_n(element_type::PTR, PTR_COUNT));
        blob.push(element_type::I4);
        let result: Result<TypeSig> = parse_field_sig(&blob);
        assert!(matches!(
            result,
            Err(Error::SignatureTooDeep(MAX_SIG_DEPTH))
        ));
    }

    #[test]
    fn type_spec_at_depth_limit_parses() {
        let mut blob: Vec<u8> = vec![element_type::PTR; MAX_SIG_DEPTH - 1];
        blob.push(element_type::I4);
        let sig: TypeSig = parse_type_spec_sig(&blob).expect("at-limit nesting parses");
        let mut node: &TypeSig = &sig;
        let mut levels: usize = 0;
        while let TypeSig::Ptr(inner) = node {
            node = inner;
            levels += 1;
        }
        assert_eq!(levels, MAX_SIG_DEPTH - 1);
        assert_eq!(*node, TypeSig::I4);
    }

    #[test]
    fn type_spec_one_past_limit_errors() {
        let mut blob: Vec<u8> = vec![element_type::PTR; MAX_SIG_DEPTH];
        blob.push(element_type::I4);
        let result: Result<TypeSig> = parse_type_spec_sig(&blob);
        assert!(matches!(
            result,
            Err(Error::SignatureTooDeep(MAX_SIG_DEPTH))
        ));
    }

    #[test]
    fn type_spec_rejects_trailing_bytes_and_invalid_generic_instances() {
        assert!(parse_type_spec_sig(&[element_type::I4, element_type::I8]).is_err());
        assert!(
            parse_type_spec_sig_strict(&[
                element_type::GENERICINST,
                element_type::I4,
                0x01,
                element_type::I4,
            ])
            .is_err()
        );
        assert!(
            parse_type_spec_sig_strict(&[
                element_type::GENERICINST,
                element_type::CLASS,
                0x05,
                0x01,
                element_type::ARRAY,
                element_type::I4,
                0x01,
                0x02,
                0x01,
                0x01,
                0x00,
            ])
            .is_err()
        );
        assert!(
            parse_type_spec_sig_strict(&[
                element_type::SZARRAY,
                element_type::GENERICINST,
                element_type::CLASS,
                0x05,
                0x01,
                element_type::BYREF,
                element_type::I4,
            ])
            .is_err()
        );
        assert!(
            parse_type_spec_sig_strict(&[
                element_type::GENERICINST,
                element_type::CLASS,
                0x05,
                0x01,
                element_type::BYREF,
                element_type::I4,
            ])
            .is_err()
        );
        assert!(
            parse_type_spec_sig_strict(&[
                element_type::GENERICINST,
                element_type::CLASS,
                0x05,
                0x00,
            ])
            .is_err()
        );
        assert!(
            parse_type_spec_sig_strict(&[
                element_type::GENERICINST,
                element_type::CLASS,
                0x05,
                0x01,
                0xFF,
            ])
            .is_err()
        );
        assert!(
            parse_type_spec_sig_strict(&[
                element_type::GENERICINST,
                element_type::CLASS,
                0x05,
                0x01,
                element_type::CMOD_OPT,
                0x05,
                element_type::I4,
            ])
            .is_err()
        );
        let valid: TypeSig = parse_type_spec_sig_strict(&[
            element_type::GENERICINST,
            element_type::CLASS,
            0x05,
            0x02,
            element_type::VAR,
            0x00,
            element_type::VAR,
            0x01,
        ])
        .expect("valid strict generic instance");
        assert_eq!(
            valid,
            TypeSig::GenericInst {
                base: Box::new(TypeSig::NamedType {
                    is_value_type: false,
                    token: 0x0100_0001,
                }),
                args: vec![TypeSig::Var(0), TypeSig::Var(1)],
            }
        );
    }

    #[test]
    fn field_sig_int32() {
        let sig: TypeSig = parse_field_sig(&[SIG_FIELD, element_type::I4]).expect("field");
        assert_eq!(sig, TypeSig::I4);
        assert_eq!(sig.render(), "int");
    }

    #[test]
    fn field_sig_string_array() {
        let sig: TypeSig =
            parse_field_sig(&[SIG_FIELD, element_type::SZARRAY, element_type::STRING])
                .expect("field");
        assert_eq!(sig.render(), "string[]");
    }

    #[test]
    fn field_sig_flags_and_trailing_bytes_error() {
        assert!(parse_field_sig(&[SIG_FIELD | SIG_HASTHIS, element_type::I4]).is_err());
        assert!(parse_field_sig(&[SIG_FIELD, element_type::I4, element_type::I8]).is_err());
    }

    #[test]
    fn field_sig_rejects_reserved_and_zero_type_tokens() {
        assert!(parse_field_sig(&[SIG_FIELD, element_type::CLASS, 0x07]).is_err());
        assert!(parse_field_sig(&[SIG_FIELD, element_type::CLASS, 0x00]).is_err());
        assert!(
            parse_field_sig(&[SIG_FIELD, element_type::CLASS, 0xC4, 0x00, 0x00, 0x00]).is_err()
        );
    }

    #[test]
    fn strict_signatures_reject_custom_modifiers() {
        assert!(
            parse_field_sig(&[SIG_FIELD, element_type::CMOD_REQD, 0x05, element_type::I4]).is_ok()
        );
        assert!(
            parse_field_sig_strict(&[SIG_FIELD, element_type::CMOD_REQD, 0x05, element_type::I4,])
                .is_err()
        );
        assert!(
            parse_method_sig_strict(&[
                SIG_DEFAULT,
                0x00,
                element_type::CMOD_OPT,
                0x05,
                element_type::VOID,
            ])
            .is_err()
        );
        assert!(
            parse_method_spec_sig_strict(&[
                0x0A,
                0x01,
                element_type::CMOD_OPT,
                0x05,
                element_type::I4,
            ])
            .is_err()
        );
        assert!(
            parse_local_sig_strict(&[
                SIG_LOCAL,
                0x01,
                element_type::CMOD_REQD,
                0x05,
                element_type::I4,
            ])
            .is_err()
        );
        assert!(parse_field_sig(&[SIG_FIELD, 0x17]).is_ok());
        assert!(parse_field_sig_strict(&[SIG_FIELD, 0x17]).is_err());
        assert!(parse_local_sig_strict(&[SIG_LOCAL, 0x01, element_type::VOID]).is_err());
    }

    #[test]
    fn method_sig_void_no_args() {
        let sig: MethodSig =
            parse_method_sig(&[SIG_DEFAULT, 0x00, element_type::VOID]).expect("method");
        assert_eq!(sig.return_type, TypeSigOrVoid::Void);
        assert!(sig.params.is_empty());
        assert!(!sig.has_this);
    }

    #[test]
    fn method_sig_truncated_before_declared_parameter_count_errors() {
        assert!(
            parse_method_sig(&[SIG_DEFAULT, 0x02, element_type::VOID, element_type::I4]).is_err()
        );
    }

    #[test]
    fn method_sig_trailing_bytes_error() {
        assert!(
            parse_method_sig(&[SIG_DEFAULT, 0x00, element_type::VOID, element_type::I4]).is_err()
        );
    }

    #[test]
    fn method_sig_instance_int_of_string() {
        let sig: MethodSig =
            parse_method_sig(&[SIG_HASTHIS, 0x01, element_type::I4, element_type::STRING])
                .expect("method");
        assert!(sig.has_this);
        assert_eq!(sig.return_type.render(), "int");
        assert_eq!(sig.params.len(), 1);
        assert_eq!(sig.params[0].render(), "string");
    }

    #[test]
    fn generic_inst_renders_angle_brackets() {
        let sig: TypeSig = TypeSig::GenericInst {
            base: Box::new(TypeSig::NamedType {
                is_value_type: false,
                token: 0x0100_0001,
            }),
            args: vec![TypeSig::I4, TypeSig::String],
        };
        assert!(sig.render().contains("<int, string>"));
    }

    #[test]
    fn byref_renders_ref_prefix() {
        assert_eq!(TypeSig::ByRef(Box::new(TypeSig::I4)).render(), "ref int");
    }

    #[test]
    fn empty_blob_errors() {
        assert!(parse_method_sig(&[]).is_err());
    }

    #[test]
    fn local_sig_mixed_kinds() {
        let blob: [u8; 7] = [
            SIG_LOCAL,
            0x03,
            element_type::I4,
            element_type::BYREF,
            element_type::I8,
            element_type::PINNED,
            element_type::OBJECT,
        ];
        let locals: Vec<TypeSig> = parse_local_sig(&blob).expect("local sig");
        assert_eq!(locals.len(), 3);
        assert_eq!(locals[0], TypeSig::I4);
        assert_eq!(locals[1], TypeSig::ByRef(Box::new(TypeSig::I8)));
        assert_eq!(locals[2], TypeSig::Pinned(Box::new(TypeSig::Object)));
    }

    #[test]
    fn local_sig_typed_byref_marker() {
        let blob: [u8; 3] = [SIG_LOCAL, 0x01, element_type::TYPEDBYREF];
        let locals: Vec<TypeSig> = parse_local_sig(&blob).expect("local sig");
        assert_eq!(locals, vec![TypeSig::TypedByRef]);
    }

    #[test]
    fn local_sig_wrong_calling_convention_errors() {
        assert!(parse_local_sig(&[SIG_FIELD, element_type::I4]).is_err());
    }

    #[test]
    fn local_sig_truncated_before_declared_count_errors() {
        assert!(parse_local_sig(&[SIG_LOCAL, 0x02, element_type::I4]).is_err());
    }

    #[test]
    fn local_sig_flags_and_trailing_bytes_error() {
        assert!(parse_local_sig(&[SIG_LOCAL | SIG_HASTHIS, 0x00]).is_err());
        assert!(parse_local_sig(&[SIG_LOCAL, 0x00, element_type::I4]).is_err());
    }

    #[test]
    fn field_sig_preserves_required_custom_modifiers() {
        let blob: [u8; 4] = [SIG_FIELD, element_type::CMOD_REQD, 0x05, element_type::I4];
        let signature: FieldSig = parse_field_sig_with_modifiers(&blob).expect("field signature");
        assert_eq!(
            (signature.field_type, signature.required_modifiers),
            (TypeSig::I4, vec![0x0100_0001])
        );
    }

    #[test]
    fn field_sig_rejects_too_many_optional_custom_modifiers() {
        let mut blob: Vec<u8> = vec![SIG_FIELD];
        for _ in 0..=MAX_SIGNATURE_NODES {
            blob.push(element_type::CMOD_OPT);
            blob.push(0x05);
        }
        blob.push(element_type::I4);
        assert!(parse_field_sig_with_modifiers(&blob).is_err());
    }

    #[test]
    fn method_spec_sig_reads_generic_instantiation() {
        let blob: [u8; 4] = [0x0A, 0x01, element_type::MVAR, 0x00];
        let args: Vec<TypeSig> = parse_method_spec_sig(&blob).expect("method spec sig");
        assert_eq!(args, vec![TypeSig::MVar(0)]);
    }

    #[test]
    fn method_spec_sig_wrong_calling_convention_errors() {
        assert!(parse_method_spec_sig(&[SIG_FIELD, 0x01, element_type::I4]).is_err());
    }

    #[test]
    fn collect_tokens_descends_generics() {
        let sig: TypeSig = TypeSig::SzArray(Box::new(TypeSig::NamedType {
            is_value_type: true,
            token: 0x0200_0003,
        }));
        let mut tokens: Vec<u32> = Vec::new();
        sig.collect_tokens(&mut tokens);
        assert_eq!(tokens, vec![0x0200_0003]);
    }
}
