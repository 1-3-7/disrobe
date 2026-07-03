use std::collections::BTreeSet;

use serde::Serialize;

use crate::error::{Error, Result};

use super::extract::vba_project_bin_from_bytes;
use super::pcode_real::{RealModuleDisasm, RealPCodeLine, RealPCodeReport, disassemble_pcode_real};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PCodeWall {
    NoVbaProjectStream,
    UnsupportedVersion,
    UnknownEndianMarker,
    InsufficientStreamBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PCodeStreamHeader {
    pub magic: u16,
    pub version: u16,
    pub endian_marker: u16,
    pub language_id: u16,
    pub is_big_endian: bool,
    pub bitness_hint: Option<bool>,
    pub stream_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PCodeDisasm {
    pub header: Option<PCodeStreamHeader>,
    pub strings: Vec<String>,
    pub instructions: Vec<PCodeInstruction>,
    pub walls: Vec<PCodeWallDetail>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PCodeWallDetail {
    pub kind: PCodeWall,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PCodeInstruction {
    pub offset: usize,
    pub opcode_raw: u16,
    pub mnemonic: String,
}

const VBA_PROJECT_MAGIC: u16 = 0x61CC;
const BIG_ENDIAN_MARKER: u16 = 0x000E;
const OLE_CFB_MAGIC: &[u8; 8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

pub fn disassemble_pcode(stream: &[u8]) -> Result<PCodeDisasm> {
    let real: Option<PCodeDisasm> = disassemble_container_pcode(stream)?;
    if let Some(real) = real {
        return Ok(real);
    }
    if stream.len() < 6 {
        return Err(Error::VbaPcode {
            reason: "pcode stream too short (need at least 6 bytes for header)".to_owned(),
        });
    }
    let magic: u16 = u16::from_le_bytes([stream[0], stream[1]]);
    let version: u16 = u16::from_le_bytes([stream[2], stream[3]]);
    let endian_marker: u16 = u16::from_le_bytes([stream[4], stream[5]]);
    let mut walls: Vec<PCodeWallDetail> = Vec::new();
    if magic != VBA_PROJECT_MAGIC {
        walls.push(PCodeWallDetail {
            kind: PCodeWall::NoVbaProjectStream,
            reason: format!(
                "stream magic {magic:#06x} is not _VBA_PROJECT magic {VBA_PROJECT_MAGIC:#06x}; pass an extracted _VBA_PROJECT cache stream"
            ),
        });
        return Ok(PCodeDisasm {
            header: None,
            strings: Vec::new(),
            instructions: Vec::new(),
            walls,
        });
    }
    let is_big_endian: bool = endian_marker == BIG_ENDIAN_MARKER;
    let language_id: u16 = if stream.len() >= 8 {
        u16::from_le_bytes([stream[6], stream[7]])
    } else {
        0
    };
    let bitness: Option<bool> = None;
    let header: PCodeStreamHeader = PCodeStreamHeader {
        magic,
        version,
        endian_marker,
        language_id,
        is_big_endian,
        bitness_hint: bitness,
        stream_bytes: stream.len(),
    };
    walls.push(PCodeWallDetail {
        kind: PCodeWall::InsufficientStreamBytes,
        reason: format!(
            "_VBA_PROJECT cache stream alone lacks the dir stream and per-module streams needed for real p-code disassembly; pass a full OLE vbaProject.bin or OOXML document. detected _VBA_PROJECT version {version:#06x} language_id={language_id:#06x}"
        ),
    });
    if endian_marker != BIG_ENDIAN_MARKER && endian_marker != 0 {
        walls.push(PCodeWallDetail {
            kind: PCodeWall::UnknownEndianMarker,
            reason: format!("unrecognised endian marker {endian_marker:#06x}"),
        });
    }
    Ok(PCodeDisasm {
        header: Some(header),
        strings: Vec::new(),
        instructions: Vec::new(),
        walls,
    })
}

fn disassemble_container_pcode(bytes: &[u8]) -> Result<Option<PCodeDisasm>> {
    if bytes.starts_with(OLE_CFB_MAGIC) {
        let report: RealPCodeReport = disassemble_pcode_real(bytes)?;
        return Ok(Some(real_report_to_disasm(report)));
    }
    if !bytes.starts_with(b"PK\x03\x04") {
        return Ok(None);
    }
    let Ok(ole_bytes): Result<Vec<u8>> = vba_project_bin_from_bytes(bytes) else {
        return Ok(None);
    };
    let report: RealPCodeReport = disassemble_pcode_real(&ole_bytes)?;
    Ok(Some(real_report_to_disasm(report)))
}

fn real_report_to_disasm(report: RealPCodeReport) -> PCodeDisasm {
    let mut strings: BTreeSet<String> = BTreeSet::new();
    let mut instructions: Vec<PCodeInstruction> = Vec::new();
    for module in report.modules {
        collect_module_disasm(module, &mut strings, &mut instructions);
    }
    PCodeDisasm {
        header: Some(report.header),
        strings: strings.into_iter().collect(),
        instructions,
        walls: report.walls,
    }
}

fn collect_module_disasm(
    module: RealModuleDisasm,
    strings: &mut BTreeSet<String>,
    instructions: &mut Vec<PCodeInstruction>,
) {
    for line in module.lines {
        collect_line_strings(&line, strings);
        instructions.extend(line.instructions);
    }
}

fn collect_line_strings(line: &RealPCodeLine, strings: &mut BTreeSet<String>) {
    let bytes: &[u8] = line.text.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let start: usize = i + 1;
        let mut end: usize = start;
        while end < bytes.len() && bytes[end] != b'"' {
            end += 1;
        }
        if end > start && end <= line.text.len() {
            strings.insert(line.text[start..end].to_owned());
        }
        i = end.saturating_add(1);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_stream() {
        let r: Result<PCodeDisasm> = disassemble_pcode(&[0u8]);
        assert!(r.is_err());
    }

    #[test]
    fn detects_non_vba_project_magic_with_wall() -> Result<()> {
        let bytes: &[u8] = &[0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00];
        let r: PCodeDisasm = disassemble_pcode(bytes)?;
        assert!(r.header.is_none());
        assert!(
            r.walls
                .iter()
                .any(|w: &PCodeWallDetail| w.kind == PCodeWall::NoVbaProjectStream)
        );
        Ok(())
    }

    #[test]
    fn parses_real_vba_project_header_and_walls_disasm() -> Result<()> {
        let bytes: &[u8] = &[0xCC, 0x61, 0xB5, 0x00, 0x00, 0x03, 0x09, 0x04];
        let r: PCodeDisasm = disassemble_pcode(bytes)?;
        let h: &PCodeStreamHeader = r.header.as_ref().expect("header parsed");
        assert_eq!(h.magic, VBA_PROJECT_MAGIC);
        assert_eq!(h.version, 0x00B5);
        assert_eq!(h.bitness_hint, None);
        assert!(
            r.walls
                .iter()
                .any(|w: &PCodeWallDetail| w.kind == PCodeWall::InsufficientStreamBytes)
        );
        Ok(())
    }
}
