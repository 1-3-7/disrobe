#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::emulated_unpack::{EmulatedUnpack, EmulationConfig, emulate_unpack_stub};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

const STEP_CAP_MORPHINE: u64 = 200_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphineLayout {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub section_count: u32,
    pub stub_section_rva: u32,
    pub stub_section_name: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MorphineRecovery {
    pub layout: MorphineLayout,
    pub unpack: EmulatedUnpack,
    pub recovered_image: Vec<u8>,
    pub reached_oep: bool,
}

fn stub_section(img: &PeImage) -> Result<&PeSection> {
    img.section_containing_rva(img.entry_point_rva)
        .ok_or_else(|| {
            Error::SignatureDb("Morphine: entry point not inside any section".to_owned())
        })
}

pub fn morphine_layout(packed: &[u8]) -> Result<MorphineLayout> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = stub_section(&img)?;
    Ok(MorphineLayout {
        image_base: img.image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        section_count: img.sections.len() as u32,
        stub_section_rva: stub.virtual_address,
        stub_section_name: stub.name_trimmed().to_vec(),
    })
}

pub fn unpack_morphine(packed: &[u8]) -> Result<MorphineRecovery> {
    unpack_morphine_emulated(packed, None)
}

pub fn unpack_morphine_emulated(
    packed: &[u8],
    original: Option<&[u8]>,
) -> Result<MorphineRecovery> {
    let layout: MorphineLayout = morphine_layout(packed)?;
    let img: PeImage = parse_pe_image(packed)?;
    let stub_rva: u32 = stub_section(&img)?.virtual_address;
    let stub_name: Vec<u8> = layout.stub_section_name.clone();
    let stub_names: [&[u8]; 1] = [stub_name.as_slice()];
    let config: EmulationConfig<'_> = EmulationConfig {
        stub_section_names: &stub_names,
        content_exclude: &[],
        step_cap: STEP_CAP_MORPHINE,
    };
    let unpack: EmulatedUnpack = emulate_unpack_stub(packed, &img, stub_rva, original, &config)?;
    let reached_oep: bool = unpack.reached_oep();
    Ok(MorphineRecovery {
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
        let line: &[u8] = b"morphine polymorphic decryptor; key is embedded in the stub, recovered by emulation. ";
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
            body: sample_body(1500),
        }];
        build_packed(
            &secs,
            0x1000,
            b".morph",
            StubKind::StreamDecrypt {
                key0: 0x37,
                key_step: 0x71,
            },
        )
    }

    #[test]
    fn rejects_non_pe() {
        assert!(morphine_layout(b"not a pe").is_err());
        assert!(unpack_morphine(b"not a pe").is_err());
    }

    #[test]
    fn emulates_decrypt_stub_to_oep_and_recovers_text_byte_exact() {
        let p: PackedImage = packed_sample();
        let layout: MorphineLayout = morphine_layout(&p.bytes).expect("layout");
        assert_eq!(layout.section_count, 2);

        let rec: MorphineRecovery =
            unpack_morphine_emulated(&p.bytes, Some(&p.original)).expect("recovery");
        assert!(
            rec.reached_oep,
            "Morphine decryptor stub must emulate to the OEP after decrypting .text",
        );
        let content: f64 = rec.unpack.content_recovery_pct.unwrap_or(0.0);
        assert!(
            (content - 100.0).abs() < f64::EPSILON,
            "emulated Morphine content recovery must be byte-exact; got {content:.2}%",
        );
    }
}
