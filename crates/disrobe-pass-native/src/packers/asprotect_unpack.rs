#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::packers::emulated_unpack::{EmulatedUnpack, EmulationConfig, emulate_unpack_stub};
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

const ASPROTECT_SECTIONS: &[&[u8]] = &[b".aspr", b".aspack", b".adata", b".data"];
const STEP_CAP_ASPROTECT: u64 = 200_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsProtectLayout {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub stub_section_name: Vec<u8>,
    pub stub_section_rva: u32,
    pub stub_section_raw_size: u32,
}

#[derive(Debug, Clone)]
pub struct AsProtectRecovery {
    pub layout: AsProtectLayout,
    pub unpack: EmulatedUnpack,
    pub recovered_image: Vec<u8>,
    pub reached_oep: bool,
}

fn stub_section(img: &PeImage) -> Result<&PeSection> {
    img.section_containing_rva(img.entry_point_rva)
        .ok_or_else(|| {
            Error::SignatureDb("ASProtect: entry point not inside any section".to_owned())
        })
}

pub fn asprotect_layout(packed: &[u8]) -> Result<AsProtectLayout> {
    let img: PeImage = parse_pe_image(packed)?;
    let stub: &PeSection = img
        .sections
        .iter()
        .find(|s: &&PeSection| {
            ASPROTECT_SECTIONS
                .iter()
                .any(|name: &&[u8]| s.name_trimmed() == *name)
        })
        .or_else(|| stub_section(&img).ok())
        .ok_or_else(|| {
            Error::SignatureDb(
                "ASProtect: no .asprotect/.aspr/.aspack stub section present".to_owned(),
            )
        })?;
    Ok(AsProtectLayout {
        image_base: img.image_base,
        entry_point_rva: img.entry_point_rva,
        size_of_image: img.size_of_image,
        stub_section_name: stub.name_trimmed().to_vec(),
        stub_section_rva: stub.virtual_address,
        stub_section_raw_size: stub.raw_size,
    })
}

pub fn unpack_asprotect(packed: &[u8]) -> Result<AsProtectRecovery> {
    unpack_asprotect_emulated(packed, None)
}

pub fn unpack_asprotect_emulated(
    packed: &[u8],
    original: Option<&[u8]>,
) -> Result<AsProtectRecovery> {
    let layout: AsProtectLayout = asprotect_layout(packed)?;
    let img: PeImage = parse_pe_image(packed)?;
    let stub_rva: u32 = stub_section(&img)?.virtual_address;
    let config: EmulationConfig<'_> = EmulationConfig {
        stub_section_names: &[b".aspr", b".aspack", b".adata"],
        content_exclude: &[],
        step_cap: STEP_CAP_ASPROTECT,
    };
    let unpack: EmulatedUnpack = emulate_unpack_stub(packed, &img, stub_rva, original, &config)?;
    let reached_oep: bool = unpack.reached_oep();
    Ok(AsProtectRecovery {
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
            b"ASProtect stream-encrypts the original code; recovered by emulating the decryptor. ";
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
            body: sample_body(1700),
        }];
        build_packed(
            &secs,
            0x1000,
            b".aspr",
            StubKind::StreamDecrypt {
                key0: 0x9C,
                key_step: 0x4D,
            },
        )
    }

    #[test]
    fn rejects_non_pe() {
        assert!(unpack_asprotect(b"not a pe").is_err());
    }

    #[test]
    fn emulates_decrypt_stub_to_oep_and_recovers_text_byte_exact() {
        let p: PackedImage = packed_sample();
        let layout: AsProtectLayout = asprotect_layout(&p.bytes).expect("layout");
        assert_eq!(layout.stub_section_name, b".aspr");

        let rec: AsProtectRecovery =
            unpack_asprotect_emulated(&p.bytes, Some(&p.original)).expect("recovery");
        assert!(
            rec.reached_oep,
            "ASProtect decrypt stub must emulate to the OEP after decrypting .text",
        );
        let content: f64 = rec.unpack.content_recovery_pct.unwrap_or(0.0);
        assert!(
            (content - 100.0).abs() < f64::EPSILON,
            "emulated ASProtect content recovery must be byte-exact; got {content:.2}%",
        );
        assert!(
            rec.unpack.content_bytes_mutated_by_stub > 0,
            "the decryptor must mutate the encrypted content section",
        );
    }
}
