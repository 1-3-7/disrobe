use serde::{Deserialize, Serialize};

use crate::cil::{MethodBody, OperandValue, parse_method_body};
use crate::cil_emulator::{StubInput, StubOutput, emulate_stub};
use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::Resolver;
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredConstant {
    pub method_token: u32,
    pub method_name: String,
    pub int_arg: i64,
    pub decoded: DecodedValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodedValue {
    Int(i64),
    Bytes(Vec<u8>),
    Utf16(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StaticDecryptReport {
    pub pure_decoders_found: u32,
    pub constants_recovered: Vec<RecoveredConstant>,
}

const MAX_PROBE_ARGS: i64 = 64;

#[must_use]
pub fn is_pure_transform(body: &MethodBody) -> bool {
    if body.instructions.is_empty() {
        return false;
    }
    body.instructions.iter().all(|ins| {
        !matches!(
            ins.name.as_str(),
            "call"
                | "callvirt"
                | "calli"
                | "newobj"
                | "ldsfld"
                | "ldsflda"
                | "ldfld"
                | "ldflda"
                | "stfld"
                | "stsfld"
                | "ldstr"
                | "ldtoken"
                | "box"
                | "unbox"
                | "unbox.any"
                | "castclass"
                | "isinst"
                | "throw"
                | "rethrow"
        )
    })
}

pub fn recover_static_decoders(image: &[u8]) -> Result<StaticDecryptReport> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)?;
    let model: crate::model::AssemblyModel = resolver.model();

    let mut report: StaticDecryptReport = StaticDecryptReport::default();
    for ty in &model.types {
        for m in &ty.methods {
            if m.rva == 0 || !m.is_static() {
                continue;
            }
            let takes_single_int: bool =
                m.signature.params.len() == 1 && is_integral(&m.signature.params[0]);
            if !takes_single_int {
                continue;
            }
            let Some(off): Option<usize> = pe.rva_to_offset(m.rva) else {
                continue;
            };
            if off >= image.len() {
                continue;
            }
            let Ok(body): Result<MethodBody> = parse_method_body(&image[off..]) else {
                continue;
            };
            if !is_pure_transform(&body) {
                continue;
            }
            report.pure_decoders_found = report.pure_decoders_found.saturating_add(1);
            probe_decoder(&body, m, &mut report);
        }
    }
    Ok(report)
}

fn probe_decoder(
    body: &MethodBody,
    m: &crate::model::MethodModel,
    report: &mut StaticDecryptReport,
) {
    for arg in 0..MAX_PROBE_ARGS {
        let input: StubInput = StubInput {
            int_args: vec![arg],
            byte_array_args: Vec::new(),
            char_array_args: Vec::new(),
        };
        let Ok(out): std::result::Result<StubOutput, _> = emulate_stub(body, &input) else {
            break;
        };
        let decoded: DecodedValue = match out {
            StubOutput::Int(i) => DecodedValue::Int(i),
            StubOutput::Bytes(b) => DecodedValue::Bytes(b),
            StubOutput::Utf16(s) => DecodedValue::Utf16(s),
        };
        report.constants_recovered.push(RecoveredConstant {
            method_token: m.token,
            method_name: m.name.clone(),
            int_arg: arg,
            decoded,
        });
        if report.constants_recovered.len() > 4096 {
            return;
        }
    }
}

const fn is_integral(sig: &crate::signature::TypeSig) -> bool {
    use crate::signature::TypeSig;
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

#[must_use]
pub fn count_ldstr_sites(body: &MethodBody) -> u32 {
    body.instructions
        .iter()
        .filter(|ins| matches!(ins.operand, OperandValue::Token(t) if (t >> 24) == 0x70))
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: true,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    #[test]
    fn pure_transform_accepts_arithmetic_body() {
        let body: MethodBody = body_from(&[0x02, 0x1F, 0x5A, 0x61, 0x2A]);
        assert!(is_pure_transform(&body));
    }

    #[test]
    fn pure_transform_rejects_call_body() {
        let mut code: Vec<u8> = vec![0x16, 0x28];
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        assert!(!is_pure_transform(&body));
    }

    #[test]
    fn pure_transform_rejects_ldstr_body() {
        let mut code: Vec<u8> = vec![0x72];
        code.extend_from_slice(&0x7000_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        assert!(!is_pure_transform(&body));
    }

    #[test]
    fn recover_static_decoders_on_real_baseline_is_clean() {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let bytes: Vec<u8> = std::fs::read(&path).expect("fixture");
        let report: StaticDecryptReport = recover_static_decoders(&bytes).expect("scan");
        let _ = report.pure_decoders_found;
    }
}
