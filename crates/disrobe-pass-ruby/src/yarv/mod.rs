pub mod decompile;
pub mod disasm;
pub mod opcodes;
pub mod reader;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::yarv::decompile::{YarvDecompiled, decompile};
use crate::yarv::disasm::{YarvDisasm, disassemble, render_iseq_disasm};
use crate::yarv::opcodes::YarvVersion;
use crate::yarv::reader::{YarvBinaryHeader, read_header};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvAnalysis {
    pub header: YarvBinaryHeader,
    pub version: YarvVersion,
    pub disasm: YarvDisasm,
    pub disasm_text: String,
    pub decompiled: YarvDecompiled,
}

pub(crate) fn analyze(bytes: &[u8]) -> Result<YarvAnalysis> {
    let header: YarvBinaryHeader = read_header(bytes)?;
    let version: YarvVersion = YarvVersion::new(header.major, header.minor);
    let code_start: usize = crate::yarv::reader::HEADER_SIZE;
    let body: &[u8] = if code_start < bytes.len() {
        &bytes[code_start..]
    } else {
        &[]
    };
    let safe_body: &[u8] = sanitize_body(body, version);
    let d: YarvDisasm = disassemble(safe_body, version, "<top>")?;
    let text: String = render_iseq_disasm(&d);
    let decompiled: YarvDecompiled = decompile(&d);
    Ok(YarvAnalysis {
        header,
        version,
        disasm: d,
        disasm_text: text,
        decompiled,
    })
}

fn sanitize_body(body: &[u8], version: YarvVersion) -> &[u8] {
    let table: std::collections::BTreeMap<u8, opcodes::OpcodeSpec> = opcodes::opcode_table(version);
    let mut cursor: usize = 0usize;
    while cursor < body.len() {
        let op: u8 = body[cursor];
        let Some(spec) = table.get(&op) else {
            return &body[..cursor];
        };
        let step: usize = 1 + (spec.operands as usize) * 4;
        if cursor + step > body.len() {
            return &body[..cursor];
        }
        cursor += step;
    }
    body
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::detect::YARV_MAGIC;
    use crate::yarv::reader::HEADER_SIZE;

    fn synth_yarv(version: (u32, u32), body: &[u8]) -> Vec<u8> {
        let header_size_u32: u32 = u32::try_from(HEADER_SIZE).expect("size fits u32");
        let body_len_u32: u32 = u32::try_from(body.len()).expect("body fits u32");
        let mut v: Vec<u8> = Vec::with_capacity(HEADER_SIZE + body.len());
        v.extend_from_slice(YARV_MAGIC);
        v.extend_from_slice(&version.0.to_le_bytes());
        v.extend_from_slice(&version.1.to_le_bytes());
        v.extend_from_slice(&(header_size_u32 + body_len_u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&header_size_u32.to_le_bytes());
        v.extend_from_slice(&header_size_u32.to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn analyze_end_to_end() {
        let body: Vec<u8> = vec![0x00, 0x2E];
        let bytes: Vec<u8> = synth_yarv((3, 2), &body);
        let a: YarvAnalysis = analyze(&bytes).expect("analyze");
        assert_eq!(a.disasm.instructions.len(), 2);
        assert!(a.disasm_text.contains("nop"));
        assert!(a.decompiled.source.contains("return"));
    }

    #[test]
    fn analyze_truncates_at_unknown_safely() {
        let mut body: Vec<u8> = vec![0x00, 0x2E];
        body.push(0xFFu8);
        let bytes: Vec<u8> = synth_yarv((3, 2), &body);
        let a: YarvAnalysis = analyze(&bytes).expect("analyze");
        assert_eq!(a.disasm.instructions.len(), 2);
    }
}
