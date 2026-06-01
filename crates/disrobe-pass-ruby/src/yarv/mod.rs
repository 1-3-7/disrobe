pub mod decompile;
pub mod disasm;
pub mod ibf;
pub mod opcode_tables;
pub mod opcodes;
pub mod reader;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::yarv::decompile::{YarvDecompiled, decompile_from_ibf};
use crate::yarv::ibf::{IbfImage, parse_image};
use crate::yarv::opcodes::YarvVersion;
use crate::yarv::reader::{YarvBinaryHeader, read_header};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvAnalysis {
    pub header: YarvBinaryHeader,
    pub version: YarvVersion,
    pub ibf: IbfImage,
    pub disasm_text: String,
    pub decompiled: YarvDecompiled,
}

pub(crate) fn analyze(bytes: &[u8]) -> Result<YarvAnalysis> {
    let header: YarvBinaryHeader = read_header(bytes)?;
    let version: YarvVersion = YarvVersion::new(header.major, header.minor);
    let image: IbfImage = parse_image(bytes, &header, version);
    let text: String = render_ibf_summary(&image, version);
    let decompiled: YarvDecompiled = decompile_from_ibf(&image);
    Ok(YarvAnalysis {
        header,
        version,
        ibf: image,
        disasm_text: text,
        decompiled,
    })
}

fn render_ibf_summary(image: &IbfImage, version: YarvVersion) -> String {
    use core::fmt::Write as _;
    let mut out: String = String::with_capacity(image.objects.len() * 24 + 64);
    let _: core::result::Result<(), core::fmt::Error> = writeln!(
        out,
        "== disasm: <top> (ruby {}.{}) ==",
        version.major, version.minor
    );
    let _: core::result::Result<(), core::fmt::Error> = writeln!(
        out,
        "; IBF image: {} iseq(s), {} global object(s), {} literal(s), {} instruction(s) recovered",
        image.iseq_offsets.len(),
        image.objects.len(),
        image.recovered_literal_count,
        image.recovered_instruction_count
    );
    for obj in &image.objects {
        match &obj.literal {
            Some(text) => {
                let _: core::result::Result<(), core::fmt::Error> =
                    writeln!(out, "obj[{}] {:?} = {:?}", obj.index, obj.kind, text);
            }
            None => {
                let _: core::result::Result<(), core::fmt::Error> =
                    writeln!(out, "obj[{}] {:?}", obj.index, obj.kind);
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::detect::YARV_MAGIC;
    use crate::yarv::reader::HEADER_SIZE;

    fn synth_ibf_with_string(version: (u32, u32), literal: &str) -> Vec<u8> {
        let header_size_u32: u32 = u32::try_from(HEADER_SIZE).expect("size fits u32");
        let mut v: Vec<u8> = Vec::with_capacity(HEADER_SIZE + 64);
        v.extend_from_slice(YARV_MAGIC);
        v.extend_from_slice(&version.0.to_le_bytes());
        v.extend_from_slice(&version.1.to_le_bytes());
        let string_obj_off: u32 = header_size_u32;
        let mut string_obj: Vec<u8> = Vec::new();
        string_obj.push(0x45);
        string_obj.push(0x03);
        let len_small: u8 = u8::try_from((literal.len() << 1) | 1).expect("len fits");
        string_obj.push(len_small);
        string_obj.extend_from_slice(literal.as_bytes());
        let iseq_list_off: u32 = string_obj_off + u32::try_from(string_obj.len()).expect("fits");
        let obj_list_off: u32 = iseq_list_off + 4;
        let total: u32 = obj_list_off + 4;
        v.extend_from_slice(&total.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&iseq_list_off.to_le_bytes());
        v.extend_from_slice(&obj_list_off.to_le_bytes());
        v.extend_from_slice(&string_obj);
        v.extend_from_slice(&string_obj_off.to_le_bytes());
        v.extend_from_slice(&string_obj_off.to_le_bytes());
        v
    }

    #[test]
    fn analyze_recovers_real_string_literal() {
        let bytes: Vec<u8> = synth_ibf_with_string((3, 4), "hello world");
        let a: YarvAnalysis = analyze(&bytes).expect("analyze");
        assert_eq!(a.ibf.objects.len(), 1);
        assert_eq!(a.ibf.recovered_literal_count, 1);
        assert!(a.disasm_text.contains("ruby 3.4"));
        assert!(
            a.decompiled
                .recovered_strings
                .contains(&"hello world".to_owned())
        );
    }

    #[test]
    fn analyze_out_of_range_object_offset_is_safe() {
        let mut bytes: Vec<u8> = synth_ibf_with_string((3, 2), "x");
        let len: usize = bytes.len();
        bytes[len - 8..len - 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let a: YarvAnalysis = analyze(&bytes).expect("analyze must not panic");
        assert_eq!(a.ibf.objects.len(), 1);
    }
}
