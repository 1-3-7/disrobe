#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::emulated_unpack::{EmulatedUnpack, EmulationConfig, emulate_unpack_stub};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

const STEP_CAP_POLYCRYPTOR: u64 = 200_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolyCryptorLayout {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub section_count: u32,
    pub stub_section_rva: u32,
    pub stub_section_name: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PolyCryptorRecovery {
    pub layout: PolyCryptorLayout,
    pub unpack: EmulatedUnpack,
    pub recovered_image: Vec<u8>,
    pub reached_oep: bool,
}

fn stub_section(img: &PeImage) -> Result<&PeSection> {
    img.section_containing_rva(img.entry_point_rva)
        .ok_or_else(|| {
            Error::SignatureDb("PolyCryptor: entry point not inside any section".to_owned())
        })
}

pub fn polycryptor_layout(packed: &[u8]) -> Result<PolyCryptorLayout> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = stub_section(&img)?;
    Ok(PolyCryptorLayout {
        image_base: img.image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        section_count: img.sections.len() as u32,
        stub_section_rva: stub.virtual_address,
        stub_section_name: stub.name_trimmed().to_vec(),
    })
}

pub fn unpack_polycryptor(packed: &[u8]) -> Result<PolyCryptorRecovery> {
    unpack_polycryptor_emulated(packed, None)
}

pub fn unpack_polycryptor_emulated(
    packed: &[u8],
    original: Option<&[u8]>,
) -> Result<PolyCryptorRecovery> {
    let layout: PolyCryptorLayout = polycryptor_layout(packed)?;
    let img: PeImage = parse_pe_image(packed)?;
    let stub_rva: u32 = stub_section(&img)?.virtual_address;
    let stub_name: Vec<u8> = layout.stub_section_name.clone();
    let stub_names: [&[u8]; 1] = [stub_name.as_slice()];
    let config: EmulationConfig<'_> = EmulationConfig {
        stub_section_names: &stub_names,
        content_exclude: &[],
        step_cap: STEP_CAP_POLYCRYPTOR,
    };
    let unpack: EmulatedUnpack = emulate_unpack_stub(packed, &img, stub_rva, original, &config)?;
    let reached_oep: bool = unpack.reached_oep();
    Ok(PolyCryptorRecovery {
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
            b"PolyCryptor XOR-stream encrypts the payload; the key rides in the stub, recovered by emulation. ";
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
            body: sample_body(1600),
        }];
        build_packed(
            &secs,
            0x1000,
            b".pc0",
            StubKind::StreamDecrypt {
                key0: 0x5C,
                key_step: 0x33,
            },
        )
    }

    #[test]
    fn rejects_non_pe() {
        assert!(polycryptor_layout(b"not a pe").is_err());
        assert!(unpack_polycryptor(b"not a pe").is_err());
    }

    #[test]
    fn emulates_decrypt_stub_to_oep_and_recovers_payload_byte_exact() {
        let p: PackedImage = packed_sample();
        let layout: PolyCryptorLayout = polycryptor_layout(&p.bytes).expect("layout");
        assert_eq!(layout.section_count, 2);

        let rec: PolyCryptorRecovery =
            unpack_polycryptor_emulated(&p.bytes, Some(&p.original)).expect("recovery");
        assert!(
            rec.reached_oep,
            "PolyCryptor decrypt stub must emulate to the OEP after decrypting the payload",
        );
        let content: f64 = rec.unpack.content_recovery_pct.unwrap_or(0.0);
        assert!(
            (content - 100.0).abs() < f64::EPSILON,
            "emulated PolyCryptor content recovery must be byte-exact; got {content:.2}%",
        );
        assert!(
            rec.unpack.content_bytes_mutated_by_stub > 0,
            "the decryptor must mutate the encrypted content section",
        );
    }
}
