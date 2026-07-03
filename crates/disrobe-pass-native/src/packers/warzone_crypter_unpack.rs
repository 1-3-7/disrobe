#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::emulated_unpack::{EmulatedUnpack, EmulationConfig, emulate_unpack_stub};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

const STEP_CAP_WARZONE: u64 = 200_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarzoneCrypterLayout {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub section_count: u32,
    pub stub_section_rva: u32,
    pub stub_section_name: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WarzoneCrypterRecovery {
    pub layout: WarzoneCrypterLayout,
    pub unpack: EmulatedUnpack,
    pub recovered_image: Vec<u8>,
    pub reached_oep: bool,
}

fn stub_section(img: &PeImage) -> Result<&PeSection> {
    img.section_containing_rva(img.entry_point_rva)
        .ok_or_else(|| {
            Error::SignatureDb("Warzone crypter: entry point not inside any section".to_owned())
        })
}

pub fn warzone_crypter_layout(packed: &[u8]) -> Result<WarzoneCrypterLayout> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = stub_section(&img)?;
    Ok(WarzoneCrypterLayout {
        image_base: img.image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        section_count: img.sections.len() as u32,
        stub_section_rva: stub.virtual_address,
        stub_section_name: stub.name_trimmed().to_vec(),
    })
}

pub fn unpack_warzone_crypter(packed: &[u8]) -> Result<WarzoneCrypterRecovery> {
    unpack_warzone_crypter_emulated(packed, None)
}

pub fn unpack_warzone_crypter_emulated(
    packed: &[u8],
    original: Option<&[u8]>,
) -> Result<WarzoneCrypterRecovery> {
    let layout: WarzoneCrypterLayout = warzone_crypter_layout(packed)?;
    let img: PeImage = parse_pe_image(packed)?;
    let stub_rva: u32 = stub_section(&img)?.virtual_address;
    let stub_name: Vec<u8> = layout.stub_section_name.clone();
    let stub_names: [&[u8]; 1] = [stub_name.as_slice()];
    let config: EmulationConfig<'_> = EmulationConfig {
        stub_section_names: &stub_names,
        content_exclude: &[],
        step_cap: STEP_CAP_WARZONE,
    };
    let unpack: EmulatedUnpack = emulate_unpack_stub(packed, &img, stub_rva, original, &config)?;
    let reached_oep: bool = unpack.reached_oep();
    Ok(WarzoneCrypterRecovery {
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
            b"Warzone crypter stream-decrypts the embedded payload at entry; key is on disk, recovered by emulation. ";
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
            b".wz0",
            StubKind::StreamDecrypt {
                key0: 0xA1,
                key_step: 0x1D,
            },
        )
    }

    #[test]
    fn rejects_non_pe() {
        assert!(warzone_crypter_layout(b"not a pe").is_err());
        assert!(unpack_warzone_crypter(b"not a pe").is_err());
    }

    #[test]
    fn emulates_decrypt_stub_to_oep_and_recovers_payload_byte_exact() {
        let p: PackedImage = packed_sample();
        let layout: WarzoneCrypterLayout = warzone_crypter_layout(&p.bytes).expect("layout");
        assert_eq!(layout.section_count, 2);

        let rec: WarzoneCrypterRecovery =
            unpack_warzone_crypter_emulated(&p.bytes, Some(&p.original)).expect("recovery");
        assert!(
            rec.reached_oep,
            "Warzone crypter decrypt stub must emulate to the OEP after decrypting the payload",
        );
        let content: f64 = rec.unpack.content_recovery_pct.unwrap_or(0.0);
        assert!(
            (content - 100.0).abs() < f64::EPSILON,
            "emulated Warzone crypter content recovery must be byte-exact; got {content:.2}%",
        );
        assert!(
            rec.unpack.content_bytes_mutated_by_stub > 0,
            "the decryptor must mutate the encrypted content section",
        );
    }
}
