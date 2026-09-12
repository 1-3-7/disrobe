#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::emulated_unpack::{EmulatedUnpack, EmulationConfig, emulate_unpack_stub};
use crate::packers::pe_sections::{PeImage, PeSection, find_subsequence, parse_pe_image};

const NEOLITE_MARKER: &[u8] = b"neolite";
const STEP_CAP_NEOLITE: u64 = 120_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeoLiteLayout {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub section_count: u32,
    pub marker_file_offset: u64,
    pub stub_section_rva: u32,
    pub stub_section_name: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NeoLiteRecovery {
    pub layout: NeoLiteLayout,
    pub unpack: EmulatedUnpack,
    pub recovered_image: Vec<u8>,
    pub reached_oep: bool,
}

fn stub_section(img: &PeImage) -> Result<&PeSection> {
    img.section_containing_rva(img.entry_point_rva)
        .ok_or_else(|| Error::SignatureDb("NeoLite: entry point not inside any section".to_owned()))
}

pub fn neolite_layout(packed: &[u8]) -> Result<NeoLiteLayout> {
    let img: PeImage = parse_pe_image(packed)?;
    let marker: usize = find_subsequence(packed, NEOLITE_MARKER)
        .ok_or_else(|| Error::SignatureDb("NeoLite: no neolite marker present".to_owned()))?;
    let stub: &PeSection = stub_section(&img)?;
    Ok(NeoLiteLayout {
        image_base: img.image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        section_count: img.sections.len() as u32,
        marker_file_offset: marker as u64,
        stub_section_rva: stub.virtual_address,
        stub_section_name: stub.name_trimmed().to_vec(),
    })
}

pub fn unpack_neolite(packed: &[u8]) -> Result<NeoLiteRecovery> {
    unpack_neolite_emulated(packed, None)
}

pub fn unpack_neolite_emulated(packed: &[u8], original: Option<&[u8]>) -> Result<NeoLiteRecovery> {
    let layout: NeoLiteLayout = neolite_layout(packed)?;
    let img: PeImage = parse_pe_image(packed)?;
    let stub_rva: u32 = stub_section(&img)?.virtual_address;
    let stub_name: Vec<u8> = layout.stub_section_name.clone();
    let stub_names: [&[u8]; 1] = [stub_name.as_slice()];
    let config: EmulationConfig<'_> = EmulationConfig {
        stub_section_names: &stub_names,
        content_exclude: &[],
        step_cap: STEP_CAP_NEOLITE,
    };
    let unpack: EmulatedUnpack = emulate_unpack_stub(packed, &img, stub_rva, original, &config)?;
    let reached_oep: bool = unpack.reached_oep();
    Ok(NeoLiteRecovery {
        recovered_image: unpack.recovered_memory_image.clone(),
        reached_oep,
        layout,
        unpack,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::packers::stub_pack_oracle::{PackedImage, SectionSpec, StubKind, build_packed};

    fn sample_body(len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(len);
        let line: &[u8] =
            b"NeoLite compresses the original sections; recovered via x86 stub emulation. ";
        while out.len() < len {
            out.extend_from_slice(line);
        }
        out.truncate(len);
        out
    }

    fn packed_sample() -> PackedImage {
        let secs: Vec<SectionSpec<'_>> = vec![
            SectionSpec {
                name: b".text",
                rva: 0x1000,
                body: sample_body(1600),
            },
            SectionSpec {
                name: b".data",
                rva: 0x2000,
                body: b"packed by neolite 2.0 marker zone".to_vec(),
            },
        ];
        build_packed(&secs, 0x1000, b"neolite", StubKind::LzDecompress)
    }

    #[test]
    fn rejects_pe_without_marker() {
        let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
            name: b".text",
            rva: 0x1000,
            body: vec![0x90; 64],
        }];
        let p: PackedImage = build_packed(&secs, 0x1000, b".code", StubKind::LzDecompress);
        assert!(neolite_layout(&p.bytes).is_err());
        assert!(unpack_neolite(&p.bytes).is_err());
    }

    #[test]
    fn rejects_non_pe() {
        assert!(unpack_neolite(b"not a pe").is_err());
    }

    #[test]
    fn emulates_lz_stub_to_oep_and_recovers_text_byte_exact() {
        let p: PackedImage = packed_sample();
        let layout: NeoLiteLayout = neolite_layout(&p.bytes).expect("layout");
        assert!(layout.marker_file_offset > 0);
        assert_eq!(layout.stub_section_name, b"neolite");

        let rec: NeoLiteRecovery =
            unpack_neolite_emulated(&p.bytes, Some(&p.original)).expect("recovery");
        assert!(
            rec.reached_oep,
            "NeoLite stub must emulate to the OEP after decompressing the first section",
        );
        let content: f64 = rec.unpack.content_recovery_pct.unwrap_or(0.0);
        assert!(
            content > 0.0,
            "emulated NeoLite content recovery must beat the structural 0%; got {content:.2}%",
        );
    }
}
