use crate::pdb_cxx::catalog::UdtFamily;
use crate::pdb_cxx::spelling::{ResolvedSpelling, TypeOp, apply_cv};

pub(crate) fn finish_primitive(
    p: pdb::PrimitiveType,
    mut ops: Vec<TypeOp>,
    const_q: bool,
    volatile_q: bool,
    opaque_refs: Vec<(UdtFamily, String)>,
) -> ResolvedSpelling {
    let spelling: PrimitiveSpelling = primitive_kind_spelling(p.kind);
    if let Some(indirection) = p.indirection {
        ops.push(TypeOp::Pointer {
            const_q,
            volatile_q,
        });
        let ptr_size: u64 = indirection_byte_size(indirection);
        let mut base_ops: Vec<TypeOp> = ops;
        if let Some(raw_bytes) = spelling.raw_array_len {
            base_ops.push(TypeOp::Array(raw_bytes));
        }
        return ResolvedSpelling {
            base_text: spelling.text,
            ops: base_ops,
            byte_size: Some(ptr_size),
            degraded: spelling.degraded,
            bitfield: None,
            opaque_refs,
            value_dependency: None,
        };
    }
    if let Some(raw_bytes) = spelling.raw_array_len {
        ops.push(TypeOp::Array(raw_bytes));
    }
    ResolvedSpelling {
        base_text: apply_cv(spelling.text, const_q, volatile_q),
        ops,
        byte_size: spelling.byte_size,
        degraded: spelling.degraded,
        bitfield: None,
        opaque_refs,
        value_dependency: None,
    }
}

fn indirection_byte_size(indirection: pdb::Indirection) -> u64 {
    match indirection {
        pdb::Indirection::Near16 | pdb::Indirection::Far16 | pdb::Indirection::Huge16 => 2,
        pdb::Indirection::Near32 | pdb::Indirection::Far32 => 4,
        pdb::Indirection::Near64 => 8,
        pdb::Indirection::Near128 => 16,
    }
}

struct PrimitiveSpelling {
    text: String,
    byte_size: Option<u64>,
    degraded: bool,
    raw_array_len: Option<u64>,
}

impl PrimitiveSpelling {
    fn plain(text: &str, size: u64) -> Self {
        Self {
            text: text.to_owned(),
            byte_size: Some(size),
            degraded: false,
            raw_array_len: None,
        }
    }

    fn degraded_bytes(len: u64) -> Self {
        Self {
            text: "unsigned char".to_owned(),
            byte_size: Some(len),
            degraded: true,
            raw_array_len: Some(len),
        }
    }
}

fn primitive_kind_spelling(kind: pdb::PrimitiveKind) -> PrimitiveSpelling {
    use pdb::PrimitiveKind as K;
    match kind {
        K::NoType | K::Void => PrimitiveSpelling {
            text: "void".to_owned(),
            byte_size: None,
            degraded: false,
            raw_array_len: None,
        },
        K::HRESULT => PrimitiveSpelling::plain("long", 4),
        K::Char => PrimitiveSpelling::plain("char", 1),
        K::UChar | K::U8 => PrimitiveSpelling::plain("unsigned char", 1),
        K::RChar => PrimitiveSpelling::plain("char", 1),
        K::WChar => PrimitiveSpelling::plain("wchar_t", 2),
        K::RChar16 => PrimitiveSpelling::plain("char16_t", 2),
        K::RChar32 => PrimitiveSpelling::plain("char32_t", 4),
        K::I8 => PrimitiveSpelling::plain("signed char", 1),
        K::Short | K::I16 => PrimitiveSpelling::plain("short", 2),
        K::UShort | K::U16 => PrimitiveSpelling::plain("unsigned short", 2),
        K::Long => PrimitiveSpelling::plain("long", 4),
        K::ULong => PrimitiveSpelling::plain("unsigned long", 4),
        K::I32 => PrimitiveSpelling::plain("int", 4),
        K::U32 => PrimitiveSpelling::plain("unsigned int", 4),
        K::Quad | K::I64 => PrimitiveSpelling::plain("long long", 8),
        K::UQuad | K::U64 => PrimitiveSpelling::plain("unsigned long long", 8),
        K::F32 => PrimitiveSpelling::plain("float", 4),
        K::F64 => PrimitiveSpelling::plain("double", 8),
        K::F32PP => PrimitiveSpelling {
            degraded: true,
            ..PrimitiveSpelling::plain("float", 4)
        },
        K::Bool8 => PrimitiveSpelling::plain("bool", 1),
        K::Bool16 => PrimitiveSpelling::degraded_bytes(2),
        K::Bool32 => PrimitiveSpelling::degraded_bytes(4),
        K::Bool64 => PrimitiveSpelling::degraded_bytes(8),
        K::Octa | K::UOcta | K::I128 | K::U128 => PrimitiveSpelling::degraded_bytes(16),
        K::F16 => PrimitiveSpelling::degraded_bytes(2),
        K::F48 => PrimitiveSpelling::degraded_bytes(6),
        K::F80 => PrimitiveSpelling::degraded_bytes(10),
        K::F128 => PrimitiveSpelling::degraded_bytes(16),
        K::Complex32 => PrimitiveSpelling::degraded_bytes(8),
        K::Complex64 => PrimitiveSpelling::degraded_bytes(16),
        K::Complex80 => PrimitiveSpelling::degraded_bytes(20),
        K::Complex128 => PrimitiveSpelling::degraded_bytes(32),
        _ => PrimitiveSpelling::degraded_bytes(0),
    }
}
