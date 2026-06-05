//! ECMA-335 Partition II §23.2 signature-blob decoding.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::metadata::decompress_uint;
use crate::structurize::TargetLang;

/// `ELEMENT_TYPE_*` constants (§II.23.1.16).
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

/// Calling-convention flags in the first signature byte (§II.23.2.3).
pub const SIG_HASTHIS: u8 = 0x20;
pub const SIG_EXPLICITTHIS: u8 = 0x40;
pub const SIG_GENERIC: u8 = 0x10;
pub const SIG_KIND_MASK: u8 = 0x0F;
pub const SIG_DEFAULT: u8 = 0x00;
pub const SIG_VARARG: u8 = 0x05;
pub const SIG_FIELD: u8 = 0x06;

/// A decoded type within a signature.
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
    /// `valuetype`/`class` token reference (a `TypeDefOrRef` coded index, already decoded to a token).
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
    /// `!n` - generic type parameter.
    Var(u32),
    /// `!!n` - generic method parameter.
    MVar(u32),
    FnPtr,
    #[default]
    Unknown,
}

impl TypeSig {
    /// Render as a C#-style type name. Back-compat shim over [`Self::render_in`].
    #[must_use]
    pub fn render(&self) -> String {
        self.render_in(TargetLang::CSharp)
    }

    /// Render the type keyword for the requested target language.
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

    /// Collect every embedded type-reference token so a resolver can substitute real names.
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

/// A decoded MethodDef/MethodRef signature (§II.23.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MethodSig {
    pub has_this: bool,
    pub explicit_this: bool,
    pub generic_param_count: u32,
    pub return_type: TypeSigOrVoid,
    pub params: Vec<TypeSig>,
}

/// Distinguishes a present return type from `void` while keeping `Default` derivable.
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

/// Upper bound on `type_sig` recursion depth.
const MAX_SIG_DEPTH: usize = 256;

struct SigReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> SigReader<'a> {
    #[inline]
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            depth: 0,
        }
    }

    #[inline]
    fn byte(&mut self) -> Result<u8> {
        let b: u8 = *self
            .bytes
            .get(self.pos)
            .ok_or(Error::BadCompressedUint(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    #[inline]
    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    fn compressed(&mut self) -> Result<u32> {
        let (v, n): (u32, usize) =
            decompress_uint(&self.bytes[self.pos..]).ok_or(Error::BadCompressedUint(self.pos))?;
        self.pos += n;
        Ok(v)
    }

    /// Decode a `TypeDefOrRef` coded index (§II.23.2.8) into a metadata token.
    fn type_def_or_ref(&mut self) -> Result<u32> {
        let coded: u32 = self.compressed()?;
        let tag: u32 = coded & 0x03;
        let rid: u32 = coded >> 2;
        let table: u32 = match tag {
            1 => 0x01,
            2 => 0x1B,
            _ => 0x02,
        };
        Ok((table << 24) | rid)
    }

    fn type_sig(&mut self) -> Result<TypeSig> {
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
                    self.pos += 1;
                    let _ = self.type_def_or_ref()?;
                }
                Some(et::PINNED) => {
                    self.pos += 1;
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
                for _ in 0..num_sizes {
                    let _ = self.compressed()?;
                }
                let num_lo: u32 = self.compressed()?;
                for _ in 0..num_lo {
                    let _ = self.compressed()?;
                }
                TypeSig::Array {
                    element: Box::new(element),
                    rank,
                }
            }
            et::GENERICINST => {
                let base: TypeSig = self.type_sig()?;
                let argc: u32 = self.compressed()?;
                let mut args: Vec<TypeSig> =
                    Vec::with_capacity((argc as usize).min(self.remaining()));
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
            _ => TypeSig::Unknown,
        })
    }

    fn parse_method_inner(&mut self) -> Result<MethodSig> {
        let cc: u8 = self.byte()?;
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
        let mut params: Vec<TypeSig> =
            Vec::with_capacity((param_count as usize).min(self.remaining()));
        for _ in 0..param_count {
            if self.peek().is_none() {
                break;
            }
            params.push(self.type_sig()?);
        }
        Ok(MethodSig {
            has_this,
            explicit_this,
            generic_param_count,
            return_type,
            params,
        })
    }
}

/// Decode a `MethodDef` / `MemberRef` method signature blob.
pub fn parse_method_sig(blob: &[u8]) -> Result<MethodSig> {
    if blob.is_empty() {
        return Err(Error::BadCompressedUint(0));
    }
    SigReader::new(blob).parse_method_inner()
}

/// Decode a `Field` signature blob (§II.23.2.4): a `FIELD` (`0x06`) tag then one `Type`.
pub fn parse_field_sig(blob: &[u8]) -> Result<TypeSig> {
    let mut r: SigReader<'_> = SigReader::new(blob);
    let cc: u8 = r.byte()?;
    if cc & SIG_KIND_MASK != SIG_FIELD {
        return Ok(TypeSig::Unknown);
    }
    r.type_sig()
}

/// Parse a `TypeSpec` signature blob (§II.23.2.14).
///
/// # Errors
/// Returns an error if the blob is truncated or encodes a malformed element type.
pub fn parse_type_spec_sig(blob: &[u8]) -> Result<TypeSig> {
    let mut r: SigReader<'_> = SigReader::new(blob);
    r.type_sig()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generic_inst_huge_argc_does_not_pre_allocate() {
        let blob: [u8; 8] = [
            SIG_FIELD,
            element_type::GENERICINST,
            element_type::CLASS,
            0x01,
            0xDF,
            0xFF,
            0xFF,
            0xFF,
        ];
        let result: Result<TypeSig> = parse_field_sig(&blob);
        assert!(result.is_err());
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
    fn method_sig_void_no_args() {
        let sig: MethodSig =
            parse_method_sig(&[SIG_DEFAULT, 0x00, element_type::VOID]).expect("method");
        assert_eq!(sig.return_type, TypeSigOrVoid::Void);
        assert!(sig.params.is_empty());
        assert!(!sig.has_this);
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
