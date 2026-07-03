use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cil::{Instruction, MethodBody, OperandValue, parse_method_body};
use crate::cil_emulator::{FieldInitEnv, StubInput, StubOutput, emulate_stub_with_init};
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::signature::TypeSig;

use super::blocks::int_literal;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InlinedLiteral {
    Text(String),
    Bytes(Vec<u8>),
    Int(i64),
    RuntimeKeyUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallSite {
    pub caller_token: u32,
    pub caller_name: String,
    pub decryptor_token: u32,
    pub argument: i64,
    pub literal: InlinedLiteral,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DecryptInlineReport {
    pub decryptor_methods: u32,
    pub call_sites: Vec<CallSite>,
}

const FIELD_RVA_READ_CAP: usize = 1 << 16;
const FIELD_TABLE_ID: u32 = 0x0400_0000;

#[must_use]
const fn is_integral(sig: &TypeSig) -> bool {
    matches!(
        sig,
        TypeSig::I1
            | TypeSig::U1
            | TypeSig::I2
            | TypeSig::U2
            | TypeSig::I4
            | TypeSig::U4
            | TypeSig::I8
            | TypeSig::U8
            | TypeSig::Char
    )
}

fn build_field_env(image: &[u8], pe: &PeImage, resolver: &Resolver) -> FieldInitEnv {
    let mut env: FieldInitEnv = FieldInitEnv::default();
    for row in &resolver.tables().field_rvas {
        let token: u32 = FIELD_TABLE_ID | row.field;
        let Some(off): Option<usize> = pe.rva_to_offset(row.rva) else {
            continue;
        };
        let end: usize = off.saturating_add(FIELD_RVA_READ_CAP).min(image.len());
        if off >= end {
            continue;
        }
        env.field_data.insert(token, image[off..end].to_vec());
    }
    env
}

fn init_array_tokens(resolver: &Resolver) -> std::collections::BTreeSet<u32> {
    let mut tokens: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for (idx, _row) in resolver.tables().member_refs.iter().enumerate() {
        let rid: u32 = u32::try_from(idx + 1).unwrap_or(0);
        let token: u32 = 0x0A00_0000 | rid;
        if resolver.resolve_token(token).contains("InitializeArray") {
            tokens.insert(token);
        }
    }
    tokens
}

fn elem_size_for_type(name: &str) -> Option<usize> {
    let short: &str = name.rsplit('.').next().unwrap_or(name);
    match short {
        "Char" | "Int16" | "UInt16" => Some(2),
        "Byte" | "SByte" | "Boolean" => Some(1),
        "Int32" | "UInt32" | "Single" => Some(4),
        "Int64" | "UInt64" | "Double" => Some(8),
        _ => None,
    }
}

fn array_elem_sizes(
    image: &[u8],
    pe: &PeImage,
    resolver: &Resolver,
    model: &AssemblyModel,
) -> BTreeMap<u32, usize> {
    let mut sizes: BTreeMap<u32, usize> = BTreeMap::new();
    for ty in &model.types {
        for m in &ty.methods {
            if m.rva == 0 {
                continue;
            }
            let Some(off): Option<usize> = pe.rva_to_offset(m.rva) else {
                continue;
            };
            let Some(body_bytes): Option<&[u8]> = image.get(off..) else {
                continue;
            };
            let Ok(body): crate::error::Result<MethodBody> = parse_method_body(body_bytes) else {
                continue;
            };
            for ins in &body.instructions {
                if ins.name != "newarr" {
                    continue;
                }
                let OperandValue::Token(t) = ins.operand else {
                    continue;
                };
                if let Some(size) = elem_size_for_type(&resolver.resolve_token(t)) {
                    sizes.insert(t, size);
                }
            }
        }
    }
    sizes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeShape {
    Utf16,
    Bytes,
    Int,
}

fn decode_shape(m: &MethodModel) -> Option<DecodeShape> {
    use crate::signature::{TypeSig as Ts, TypeSigOrVoid};
    match &m.signature.return_type {
        TypeSigOrVoid::Type(Ts::SzArray(inner)) => match inner.as_ref() {
            Ts::Char => Some(DecodeShape::Utf16),
            Ts::U1 | Ts::I1 => Some(DecodeShape::Bytes),
            _ => None,
        },
        TypeSigOrVoid::Type(Ts::String) => Some(DecodeShape::Utf16),
        TypeSigOrVoid::Type(t) if is_integral(t) => Some(DecodeShape::Int),
        _ => None,
    }
}

fn pure_int_decryptor(
    image: &[u8],
    pe: &PeImage,
    m: &MethodModel,
) -> Option<(MethodBody, DecodeShape)> {
    if m.rva == 0 || !m.is_static() {
        return None;
    }
    if m.signature.params.len() != 1 || !is_integral(&m.signature.params[0]) {
        return None;
    }
    let shape: DecodeShape = decode_shape(m)?;
    let off: usize = pe.rva_to_offset(m.rva)?;
    let body: MethodBody = parse_method_body(image.get(off..)?).ok()?;
    Some((body, shape))
}

fn run_decryptor(
    body: &MethodBody,
    shape: DecodeShape,
    arg: i64,
    env: &FieldInitEnv,
) -> InlinedLiteral {
    let input: StubInput = StubInput {
        int_args: vec![arg],
        byte_array_args: Vec::new(),
        char_array_args: Vec::new(),
    };
    match emulate_stub_with_init(body, &input, env) {
        Ok(StubOutput::Utf16(s)) if shape != DecodeShape::Int => InlinedLiteral::Text(s),
        Ok(StubOutput::Bytes(b)) if shape == DecodeShape::Bytes => InlinedLiteral::Bytes(b),
        Ok(StubOutput::Bytes(b)) if shape == DecodeShape::Utf16 => {
            let units: Vec<u16> = b
                .chunks_exact(2)
                .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            InlinedLiteral::Text(String::from_utf16_lossy(&units))
        }
        Ok(StubOutput::Int(i)) => InlinedLiteral::Int(i),
        _ => InlinedLiteral::RuntimeKeyUnavailable,
    }
}

fn scan_call_sites(
    body: &MethodBody,
    caller: &MethodModel,
    caller_owner: &str,
    decryptors: &BTreeMap<u32, (MethodBody, DecodeShape)>,
    env: &FieldInitEnv,
    out: &mut Vec<CallSite>,
) {
    let instrs: &[Instruction] = &body.instructions;
    for (idx, ins) in instrs.iter().enumerate() {
        if ins.name != "call" {
            continue;
        }
        let OperandValue::Token(callee) = ins.operand else {
            continue;
        };
        let Some((dbody, shape)): Option<&(MethodBody, DecodeShape)> = decryptors.get(&callee)
        else {
            continue;
        };
        let Some(prev): Option<&Instruction> =
            idx.checked_sub(1).and_then(|p: usize| instrs.get(p))
        else {
            continue;
        };
        let Some(arg): Option<i64> = int_literal(prev) else {
            continue;
        };
        let literal: InlinedLiteral = run_decryptor(dbody, *shape, arg, env);
        out.push(CallSite {
            caller_token: caller.token,
            caller_name: format!("{caller_owner}::{}", caller.name),
            decryptor_token: callee,
            argument: arg,
            literal,
        });
    }
}

pub fn inline_decryptors(image: &[u8]) -> Option<DecryptInlineReport> {
    let pe: PeImage = parse(image).ok()?;
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).ok()?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root).ok()?;
    let model: AssemblyModel = resolver.model();

    let mut env: FieldInitEnv = build_field_env(image, &pe, &resolver);
    env.init_array_tokens = init_array_tokens(&resolver);
    env.array_elem_sizes = array_elem_sizes(image, &pe, &resolver, &model);

    let mut decryptors: BTreeMap<u32, (MethodBody, DecodeShape)> = BTreeMap::new();
    for ty in &model.types {
        for m in &ty.methods {
            if let Some(found) = pure_int_decryptor(image, &pe, m) {
                decryptors.insert(m.token, found);
            }
        }
    }

    let mut report: DecryptInlineReport = DecryptInlineReport {
        decryptor_methods: u32::try_from(decryptors.len()).unwrap_or(u32::MAX),
        call_sites: Vec::new(),
    };
    for ty in &model.types {
        for m in &ty.methods {
            if m.rva == 0 {
                continue;
            }
            let Some(off): Option<usize> = pe.rva_to_offset(m.rva) else {
                continue;
            };
            let Some(body_bytes): Option<&[u8]> = image.get(off..) else {
                continue;
            };
            let Ok(body): crate::error::Result<MethodBody> = parse_method_body(body_bytes) else {
                continue;
            };
            scan_call_sites(
                &body,
                m,
                &ty.full_name,
                &decryptors,
                &env,
                &mut report.call_sites,
            );
        }
    }
    let _: &TypeModel = model.types.first()?;
    Some(report)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn load(rel: &str) -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(rel);
        std::fs::read(&path).unwrap()
    }

    #[test]
    fn inlines_real_pure_decryptor_against_known_literals() {
        let image: Vec<u8> = load("../../corpus/dotnet/cff/DecryptSample.exe");
        let report: DecryptInlineReport =
            inline_decryptors(&image).expect("decryptor inliner runs on real sample");
        assert!(
            report.decryptor_methods >= 1,
            "the pure Decrypt(int) method must be recognized"
        );
        let texts: Vec<&str> = report
            .call_sites
            .iter()
            .filter_map(|c: &CallSite| match &c.literal {
                InlinedLiteral::Text(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            texts.contains(&"genuine"),
            "Decrypt(100) must virtually execute to the known literal 'genuine'; got {texts:?}"
        );
        assert!(
            texts.contains(&"payload"),
            "Decrypt(200) must virtually execute to the known literal 'payload'; got {texts:?}"
        );
    }
}
