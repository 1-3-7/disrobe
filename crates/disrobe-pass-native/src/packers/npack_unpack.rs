#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::emulated_unpack::{EmulatedUnpack, EmulationConfig, emulate_unpack_stub};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

const NPACK_SECTION: &[u8] = b".nPack";
const STEP_CAP_NPACK: u64 = 120_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NPackLayout {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub stub_section_name: Vec<u8>,
    pub stub_section_rva: u32,
    pub stub_section_raw_size: u32,
    pub packed_section_count: u32,
}

#[derive(Debug, Clone)]
pub struct NPackRecovery {
    pub layout: NPackLayout,
    pub unpack: EmulatedUnpack,
    pub recovered_image: Vec<u8>,
    pub reached_oep: bool,
}

pub fn npack_layout(packed: &[u8]) -> Result<NPackLayout> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = img
        .section_by_name(NPACK_SECTION)
        .ok_or_else(|| Error::SignatureDb("nPack: no .nPack stub section present".to_owned()))?;
    Ok(NPackLayout {
        image_base: img.image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        stub_section_name: stub.name_trimmed().to_vec(),
        stub_section_rva: stub.virtual_address,
        stub_section_raw_size: stub.raw_size,
        packed_section_count: img.sections.len() as u32,
    })
}

pub fn unpack_npack(packed: &[u8]) -> Result<NPackRecovery> {
    unpack_npack_emulated(packed, None)
}

pub fn unpack_npack_emulated(packed: &[u8], original: Option<&[u8]>) -> Result<NPackRecovery> {
    let layout: NPackLayout = npack_layout(packed)?;
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = img
        .section_by_name(NPACK_SECTION)
        .ok_or_else(|| Error::SignatureDb("nPack: no .nPack stub section present".to_owned()))?;
    let stub_rva: u32 = stub.virtual_address;
    let config: EmulationConfig<'_> = EmulationConfig {
        stub_section_names: &[NPACK_SECTION],
        content_exclude: &[],
        step_cap: STEP_CAP_NPACK,
    };
    let unpack: EmulatedUnpack = emulate_unpack_stub(packed, &img, stub_rva, original, &config)?;
    let reached_oep: bool = unpack.reached_oep();
    Ok(NPackRecovery {
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
        let line: &[u8] = b"nPack original section bytes recovered by emulation, not a copy. ";
        while out.len() < len {
            out.extend_from_slice(line);
        }
        out.truncate(len);
        out
    }

    fn packed_sample() -> PackedImage {
        let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
            name: b".text",
            rva: 0x1000,
            body: sample_body(1536),
        }];
        build_packed(&secs, 0x1000, NPACK_SECTION, StubKind::LzDecompress)
    }

    #[test]
    fn rejects_pe_without_npack_section() {
        let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
            name: b".text",
            rva: 0x1000,
            body: vec![0x90; 64],
        }];
        let p: PackedImage = build_packed(&secs, 0x1000, b".text2", StubKind::LzDecompress);
        assert!(npack_layout(&p.bytes).is_err());
        assert!(unpack_npack(&p.bytes).is_err());
    }

    #[test]
    fn rejects_non_pe() {
        assert!(unpack_npack(b"not a pe").is_err());
    }

    #[test]
    fn emulates_lz_stub_to_oep_and_recovers_text_byte_exact() {
        let p: PackedImage = packed_sample();
        let layout: NPackLayout = npack_layout(&p.bytes).expect("layout");
        assert_eq!(layout.stub_section_name, NPACK_SECTION);
        assert_eq!(layout.packed_section_count, 2);

        let rec: NPackRecovery =
            unpack_npack_emulated(&p.bytes, Some(&p.original)).expect("recovery");
        assert!(
            rec.reached_oep,
            "nPack LZ stub must emulate to the OEP after decompressing the original sections",
        );
        let content: f64 = rec.unpack.content_recovery_pct.unwrap_or(0.0);
        assert!(
            (content - 100.0).abs() < f64::EPSILON,
            "emulated nPack content recovery must be byte-exact; got {content:.2}%",
        );
        assert!(
            rec.unpack.content_bytes_mutated_by_stub > 0,
            "the decompressor must mutate the packed (zeroed) content section",
        );
    }
}
