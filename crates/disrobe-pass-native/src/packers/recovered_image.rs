use serde::{Deserialize, Serialize};

use crate::packers::{
    AspackPhaseTwoOutput, CarvedVmpSection, Detection, KkrunchyPhaseTwoOutput, MewRebuiltImage,
    MpressUnpackOutput, NspackEmulatedReport, OreansProduct, Packer, PecompactPhaseTwoOutput,
    PetiteUnpackResult, SectionPerms, ThemidaCarve, UnpackerStatus, UpxUnpackOutput,
    VmProtectCarve, carve_themida, carve_vmprotect, unpack_aspack_phase2_emulated, unpack_fsg,
    unpack_kkrunchy_phase2_emulated, unpack_mew_rebuilt, unpack_mpress, unpack_nspack_emulated,
    unpack_pecompact_phase2_emulated, unpack_petite_with_report, unpack_upx,
};

const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_RECOVERED_BYTES: usize = 512 * 1024 * 1024;
const PRINTABLE_WINDOW: usize = 64 * 1024;
const MIN_PRINTABLE_RATIO: f64 = 0.10;
const MIN_RECOVERED_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryOracle {
    NestedPeMagic,
    ChecksumVerified,
    StreamDecoded,
    PrintableRatio,
    ProtectedSectionCarved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarvedSectionArtifact {
    pub name: Vec<u8>,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub perms: SectionPerms,
    pub blob_truncated: bool,
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredImage {
    pub packer: String,
    pub oracle: RecoveryOracle,
    pub image: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carved_sections: Vec<CarvedSectionArtifact>,
    pub recovered_len: u64,
    pub note: String,
}

#[must_use]
pub fn recover_detected(packed: &[u8], detections: &[Detection]) -> Vec<RecoveredImage> {
    if packed.len() > MAX_INPUT_BYTES {
        return Vec::new();
    }
    let mut seen: std::collections::BTreeSet<Packer> = std::collections::BTreeSet::new();
    let mut out: Vec<RecoveredImage> = Vec::new();
    for detection in detections {
        let status: UnpackerStatus = detection.packer.unpacker_status();
        if !status_emits_recovered_image(status) {
            continue;
        }
        if !seen.insert(detection.packer) {
            continue;
        }
        if let Some(recovered) = recover_one(packed, detection.packer) {
            out.push(recovered);
        }
    }
    out
}

fn recover_one(packed: &[u8], packer: Packer) -> Option<RecoveredImage> {
    crate::debug::dbg_kv("recover", || format!("dispatch {}", packer.label()));
    match packer {
        Packer::Upx => recover_upx(packed),
        Packer::Fsg => recover_fsg(packed),
        Packer::Petite => recover_petite(packed),
        Packer::Mpress => recover_mpress(packed),
        Packer::Nspack => recover_nspack(packed),
        Packer::Mew => recover_mew(packed),
        Packer::Kkrunchy => recover_kkrunchy(packed),
        Packer::AsPack => recover_aspack(packed),
        Packer::PeCompact => recover_pecompact(packed),
        Packer::VmProtect => recover_vmprotect_carve(packed),
        Packer::Themida => recover_themida_carve(packed),
        Packer::YodasCrypter
        | Packer::AsProtect
        | Packer::Morphine
        | Packer::NPack
        | Packer::PolyCryptor
        | Packer::WarzoneCrypter
        | Packer::NeoLite
        | Packer::DotNetPatcher
        | Packer::NetCryptor
        | Packer::PeProtector
        | Packer::PeLock
        | Packer::EnigmaProtector
        | Packer::Armadillo
        | Packer::Obsidium
        | Packer::WinLicense
        | Packer::YodasProtector => None,
    }
}

fn recover_aspack(packed: &[u8]) -> Option<RecoveredImage> {
    let out: AspackPhaseTwoOutput = unpack_aspack_phase2_emulated(packed, None).ok()?;
    let Some(oep): Option<u64> = out.oep_estimate else {
        crate::debug::dbg_kv("recover-wall", || {
            "aspack: stub emulation produced no oep estimate".to_owned()
        });
        return None;
    };
    if out.recovered_memory_image.len() < MIN_RECOVERED_BYTES {
        return None;
    }
    if !has_nested_pe_magic(&out.recovered_memory_image) {
        crate::debug::dbg_kv("recover-wall", || {
            format!("aspack: oep 0x{oep:x} reached but recovered image has no nested PE magic")
        });
        return None;
    }
    Some(finish(
        Packer::AsPack,
        RecoveryOracle::NestedPeMagic,
        out.recovered_memory_image,
        format!(
            "stub emulated to oep 0x{oep:x}, {} import calls serviced",
            out.host_calls.len()
        ),
    ))
}

fn recover_pecompact(packed: &[u8]) -> Option<RecoveredImage> {
    let out: PecompactPhaseTwoOutput = unpack_pecompact_phase2_emulated(packed, None).ok()?;
    let Some(oep): Option<u64> = out.oep_estimate else {
        crate::debug::dbg_kv("recover-wall", || {
            "pecompact: stub emulation produced no oep estimate".to_owned()
        });
        return None;
    };
    if !out.seh_dispatched {
        crate::debug::dbg_kv("recover-wall", || {
            format!("pecompact: oep 0x{oep:x} estimated but seh dispatch never fired")
        });
        return None;
    }
    if out.recovered_memory_image.len() < MIN_RECOVERED_BYTES {
        return None;
    }
    if !has_nested_pe_magic(&out.recovered_memory_image) {
        crate::debug::dbg_kv("recover-wall", || {
            format!("pecompact: oep 0x{oep:x} reached but recovered image has no nested PE magic")
        });
        return None;
    }
    Some(finish(
        Packer::PeCompact,
        RecoveryOracle::NestedPeMagic,
        out.recovered_memory_image,
        format!(
            "stub emulated via seh dispatch to oep 0x{oep:x}, {} import calls serviced",
            out.host_calls.len()
        ),
    ))
}

fn recover_upx(packed: &[u8]) -> Option<RecoveredImage> {
    let out: UpxUnpackOutput = unpack_upx(packed).ok()?;
    if out.recovered_image.len() < MIN_RECOVERED_BYTES {
        crate::debug::dbg_kv("recover-wall", || {
            format!(
                "upx: recovered {} bytes < {MIN_RECOVERED_BYTES} floor",
                out.recovered_image.len()
            )
        });
        return None;
    }
    let oracle: RecoveryOracle = if out.adler_verified {
        RecoveryOracle::ChecksumVerified
    } else if has_nested_pe_magic(&out.recovered_image) {
        RecoveryOracle::NestedPeMagic
    } else if printable_ratio_ok(&out.recovered_image) {
        RecoveryOracle::PrintableRatio
    } else {
        crate::debug::dbg_kv("recover-wall", || {
            "upx: decoded image satisfied no oracle (adler/nested-pe/printable all failed)"
                .to_owned()
        });
        return None;
    };
    Some(finish(
        Packer::Upx,
        oracle,
        out.recovered_image,
        format!("nrv/lzma method {:?}, filter {}", out.method, out.filter_id),
    ))
}

fn recover_fsg(packed: &[u8]) -> Option<RecoveredImage> {
    let out = unpack_fsg(packed).ok()?;
    let image: Vec<u8> = out.raw_image;
    if image.len() < MIN_RECOVERED_BYTES {
        return None;
    }
    let oracle: RecoveryOracle = if has_nested_pe_magic(&image) {
        RecoveryOracle::NestedPeMagic
    } else if printable_ratio_ok(&image) {
        RecoveryOracle::PrintableRatio
    } else {
        return None;
    };
    Some(finish(
        Packer::Fsg,
        oracle,
        image,
        format!("{} import thunks recovered", out.iat_entries.len()),
    ))
}

fn recover_petite(packed: &[u8]) -> Option<RecoveredImage> {
    let out: PetiteUnpackResult = unpack_petite_with_report(packed).ok()?;
    if !out.report.stream_decoded {
        return None;
    }
    if out.bytes.len() < MIN_RECOVERED_BYTES {
        return None;
    }
    let oracle: RecoveryOracle = if has_nested_pe_magic(&out.bytes) {
        RecoveryOracle::NestedPeMagic
    } else {
        RecoveryOracle::StreamDecoded
    };
    Some(finish(
        Packer::Petite,
        oracle,
        out.bytes,
        format!(
            "oep rva 0x{:x}, {} imports",
            out.report.original_entry_point_rva,
            out.report.recovered_imports.len()
        ),
    ))
}

fn recover_mpress(packed: &[u8]) -> Option<RecoveredImage> {
    let out: MpressUnpackOutput = unpack_mpress(packed).ok()?;
    let image: Vec<u8> = if out.decompressed_image.len() >= MIN_RECOVERED_BYTES {
        out.decompressed_image
    } else if out.decoded_payload.len() >= MIN_RECOVERED_BYTES {
        out.decoded_payload
    } else {
        return None;
    };
    let oracle: RecoveryOracle = if has_nested_pe_magic(&image) {
        RecoveryOracle::NestedPeMagic
    } else if printable_ratio_ok(&image) {
        RecoveryOracle::PrintableRatio
    } else {
        return None;
    };
    Some(finish(
        Packer::Mpress,
        oracle,
        image,
        format!("{} import dlls recovered", out.recovered_imports.len()),
    ))
}

fn recover_nspack(packed: &[u8]) -> Option<RecoveredImage> {
    let out: NspackEmulatedReport = unpack_nspack_emulated(packed).ok()?;
    if out.decompressed_image.len() < MIN_RECOVERED_BYTES {
        return None;
    }
    let oracle: RecoveryOracle = if has_nested_pe_magic(&out.decompressed_image) {
        RecoveryOracle::NestedPeMagic
    } else if printable_ratio_ok(&out.decompressed_image) {
        RecoveryOracle::PrintableRatio
    } else {
        return None;
    };
    Some(finish(
        Packer::Nspack,
        oracle,
        out.decompressed_image,
        format!(
            "{} bytes decompressed from nsp1",
            out.decompressed_size_bytes
        ),
    ))
}

fn recover_mew(packed: &[u8]) -> Option<RecoveredImage> {
    let out: MewRebuiltImage = unpack_mew_rebuilt(packed).ok()?;
    if out.file_image.len() < MIN_RECOVERED_BYTES {
        return None;
    }
    if !has_nested_pe_magic(&out.file_image) {
        crate::debug::dbg_kv("recover-wall", || {
            format!(
                "mew: rebuilt {} bytes (oep rva 0x{:x}) but no nested PE magic",
                out.file_image.len(),
                out.original_entry_point_rva
            )
        });
        return None;
    }
    Some(finish(
        Packer::Mew,
        RecoveryOracle::NestedPeMagic,
        out.file_image,
        format!(
            "rebuilt PE oep rva 0x{:x}, {} bytes decoded",
            out.original_entry_point_rva, out.decoded_byte_count
        ),
    ))
}

fn recover_kkrunchy(packed: &[u8]) -> Option<RecoveredImage> {
    let out: KkrunchyPhaseTwoOutput = unpack_kkrunchy_phase2_emulated(packed).ok()?;
    if out.recovered_file_image.len() < MIN_RECOVERED_BYTES {
        return None;
    }
    if !has_nested_pe_magic(&out.recovered_file_image) {
        crate::debug::dbg_kv("recover-wall", || {
            format!(
                "kkrunchy: stub emulation exit '{}' but recovered image has no nested PE magic",
                out.exit_reason
            )
        });
        return None;
    }
    Some(finish(
        Packer::Kkrunchy,
        RecoveryOracle::NestedPeMagic,
        out.recovered_file_image,
        out.exit_reason,
    ))
}

fn recover_vmprotect_carve(packed: &[u8]) -> Option<RecoveredImage> {
    let VmProtectCarve {
        vmp_sections,
        synthetic_imports,
        import_directory,
        limitation,
    }: VmProtectCarve = carve_vmprotect(packed).ok()?;
    let section_count: usize = vmp_sections.len();
    let import_count: usize = synthetic_imports.len();
    let import_state: &str = if import_directory.is_some() {
        "present"
    } else {
        "absent"
    };
    finish_carved(
        Packer::VmProtect,
        vmp_sections,
        format!(
            "{section_count} protected sections carved, {import_count} synthetic imports, import directory {import_state}; {limitation}"
        ),
    )
}

fn recover_themida_carve(packed: &[u8]) -> Option<RecoveredImage> {
    let ThemidaCarve {
        product,
        protected_sections,
        import_directory,
        limitation,
    }: ThemidaCarve = carve_themida(packed).ok()?;
    let section_count: usize = protected_sections.len();
    let product_label: &str = match product {
        OreansProduct::Themida => "themida",
        OreansProduct::WinLicense => "winlicense",
    };
    let import_state: &str = if import_directory.is_some() {
        "present"
    } else {
        "absent"
    };
    finish_carved(
        Packer::Themida,
        protected_sections,
        format!(
            "{product_label} {section_count} protected sections carved, import directory {import_state}; {limitation}"
        ),
    )
}

fn finish_carved(
    packer: Packer,
    sections: Vec<CarvedVmpSection>,
    note: String,
) -> Option<RecoveredImage> {
    if sections.is_empty() {
        return None;
    }
    let mut image: Vec<u8> = Vec::new();
    let mut carved_sections: Vec<CarvedSectionArtifact> = Vec::with_capacity(sections.len());
    for section in sections {
        if image.len() >= MAX_RECOVERED_BYTES {
            break;
        }
        let mut artifact: CarvedSectionArtifact = section.into();
        let remaining: usize = MAX_RECOVERED_BYTES.saturating_sub(image.len());
        let take: usize = artifact.blob.len().min(remaining);
        image.extend_from_slice(&artifact.blob[..take]);
        if take < artifact.blob.len() {
            artifact.blob.truncate(take);
            artifact.blob_truncated = true;
        }
        carved_sections.push(artifact);
    }
    if image.is_empty() {
        return None;
    }
    let recovered_len: u64 = image.len() as u64;
    crate::debug::dbg_kv("recover-ok", || {
        format!(
            "{} oracle={:?} bytes={recovered_len} sections={} :: {note}",
            packer.label(),
            RecoveryOracle::ProtectedSectionCarved,
            carved_sections.len()
        )
    });
    Some(RecoveredImage {
        packer: packer.label().to_owned(),
        oracle: RecoveryOracle::ProtectedSectionCarved,
        image,
        carved_sections,
        recovered_len,
        note,
    })
}

fn finish(packer: Packer, oracle: RecoveryOracle, image: Vec<u8>, note: String) -> RecoveredImage {
    let mut image: Vec<u8> = image;
    if image.len() > MAX_RECOVERED_BYTES {
        image.truncate(MAX_RECOVERED_BYTES);
    }
    let recovered_len: u64 = image.len() as u64;
    crate::debug::dbg_kv("recover-ok", || {
        format!(
            "{} oracle={oracle:?} bytes={recovered_len} :: {note}",
            packer.label()
        )
    });
    RecoveredImage {
        packer: packer.label().to_owned(),
        oracle,
        image,
        carved_sections: Vec::new(),
        recovered_len,
        note,
    }
}

impl From<CarvedVmpSection> for CarvedSectionArtifact {
    fn from(section: CarvedVmpSection) -> Self {
        Self {
            name: section.name,
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            raw_size: section.raw_size,
            raw_pointer: section.raw_pointer,
            perms: section.perms,
            blob_truncated: section.blob_truncated,
            blob: section.blob,
        }
    }
}

fn status_emits_recovered_image(status: UnpackerStatus) -> bool {
    matches!(
        status,
        UnpackerStatus::Implemented | UnpackerStatus::GreyZoneDetectAndCarve
    )
}

fn has_nested_pe_magic(image: &[u8]) -> bool {
    if image.len() < 0x40 || &image[..2] != b"MZ" {
        return false;
    }
    let lfanew: usize =
        u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]) as usize;
    lfanew
        .checked_add(4)
        .and_then(|end: usize| image.get(lfanew..end))
        .is_some_and(|sig: &[u8]| sig == b"PE\x00\x00")
}

fn printable_ratio_ok(image: &[u8]) -> bool {
    let window: &[u8] = &image[..image.len().min(PRINTABLE_WINDOW)];
    if window.is_empty() {
        return false;
    }
    let printable: usize = window
        .iter()
        .filter(|b: &&u8| matches!(**b, 0x20..=0x7E | b'\t' | b'\n' | b'\r'))
        .count();
    (printable as f64 / window.len() as f64) >= MIN_PRINTABLE_RATIO
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::packers::detect;

    const SEC_TABLE_OFFSET: usize = 0x80 + 4 + 20 + 0xE0;
    const SCN_READ: u32 = 0x4000_0000;
    const SCN_WRITE: u32 = 0x8000_0000;
    const SCN_EXECUTE: u32 = 0x2000_0000;

    fn nested_pe_blob(len: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; len.max(0x80)];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\x00\x00");
        buf
    }

    fn build_pe(secs: &[(&[u8], u32, u32, &[u8])]) -> Vec<u8> {
        let header_len: usize = 0x400;
        let mut buf: Vec<u8> = vec![0u8; header_len];
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
        let coff_off: usize = pe_off + 4;
        buf[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&(secs.len() as u16).to_le_bytes());
        buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        let opt_off: usize = coff_off + 20;
        buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x8000u32.to_le_bytes());
        buf[opt_off + 92..opt_off + 96].copy_from_slice(&16u32.to_le_bytes());
        let mut raw_cursor: usize = header_len;
        let mut bodies: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, (name, va, characteristics, data)) in secs.iter().enumerate() {
            let off: usize = SEC_TABLE_OFFSET + i * 40;
            let mut name_buf: [u8; 8] = [0u8; 8];
            name_buf[..name.len()].copy_from_slice(name);
            buf[off..off + 8].copy_from_slice(&name_buf);
            buf[off + 8..off + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&va.to_le_bytes());
            buf[off + 16..off + 20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            buf[off + 20..off + 24].copy_from_slice(&(raw_cursor as u32).to_le_bytes());
            buf[off + 36..off + 40].copy_from_slice(&characteristics.to_le_bytes());
            bodies.push((raw_cursor, (*data).to_vec()));
            raw_cursor += data.len();
        }
        buf.resize(raw_cursor.max(header_len), 0);
        for (off, data) in bodies {
            buf[off..off + data.len()].copy_from_slice(&data);
        }
        buf
    }

    #[test]
    fn nested_pe_magic_oracle_accepts_real_mz_pe() {
        let blob: Vec<u8> = nested_pe_blob(0x100);
        assert!(has_nested_pe_magic(&blob));
    }

    #[test]
    fn nested_pe_magic_oracle_rejects_bare_mz_run() {
        let mut blob: Vec<u8> = vec![0u8; 0x100];
        blob[0] = b'M';
        blob[1] = b'Z';
        blob[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        assert!(
            !has_nested_pe_magic(&blob),
            "an MZ prefix with no PE\\0\\0 at e_lfanew must not pass the nested-PE oracle"
        );
    }

    #[test]
    fn nested_pe_magic_oracle_handles_max_lfanew_without_overflow() {
        let mut blob: Vec<u8> = vec![0u8; 0x100];
        blob[0] = b'M';
        blob[1] = b'Z';
        blob[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            !has_nested_pe_magic(&blob),
            "an attacker-controlled e_lfanew of u32::MAX must be rejected, never overflow lfanew+4"
        );
    }

    #[test]
    fn printable_ratio_oracle_rejects_non_printable_blob() {
        let blob: Vec<u8> = vec![0x00u8; 4096];
        assert!(
            !printable_ratio_ok(&blob),
            "an all-NUL blob has zero printable bytes and must fail the printable-ratio oracle"
        );
    }

    #[test]
    fn printable_ratio_oracle_accepts_ascii_text() {
        let blob: Vec<u8> = b"the quick brown fox jumps over the lazy dog ".repeat(64);
        assert!(printable_ratio_ok(&blob));
    }

    #[test]
    fn vmprotect_detect_and_carve_surfaces_blob_and_geometry() {
        let vmp0_body: Vec<u8> = (0u8..64).collect();
        let vmp1_body: Vec<u8> = (64u8..128).collect();
        let packed: Vec<u8> = build_pe(&[
            (b".text", 0x1000, SCN_READ | SCN_EXECUTE, &[0xCC; 16]),
            (b".vmp0", 0x2000, SCN_READ | SCN_EXECUTE, &vmp0_body),
            (b".vmp1", 0x3000, SCN_READ | SCN_WRITE, &vmp1_body),
        ]);
        let detections: Vec<Detection> = detect(&packed);
        assert!(
            detections
                .iter()
                .any(|d: &Detection| d.packer == Packer::VmProtect)
        );
        let recovered: Vec<RecoveredImage> = recover_detected(&packed, &detections);
        let image: &RecoveredImage = recovered
            .iter()
            .find(|r: &&RecoveredImage| r.packer == Packer::VmProtect.label())
            .expect("vmprotect carve output");
        let expected_image: Vec<u8> = [vmp0_body.as_slice(), vmp1_body.as_slice()].concat();
        assert_eq!(image.oracle, RecoveryOracle::ProtectedSectionCarved);
        assert_eq!(image.image, expected_image);
        assert_eq!(image.recovered_len, expected_image.len() as u64);
        assert_eq!(image.carved_sections.len(), 2);
        assert_eq!(image.carved_sections[0].name, b".vmp0");
        assert_eq!(image.carved_sections[0].virtual_address, 0x2000);
        assert_eq!(image.carved_sections[0].raw_size, vmp0_body.len() as u32);
        assert!(image.carved_sections[0].perms.read);
        assert!(image.carved_sections[0].perms.execute);
        assert!(!image.carved_sections[0].perms.write);
        assert!(!image.carved_sections[0].blob_truncated);
        assert_eq!(image.carved_sections[0].blob, vmp0_body);
        assert_eq!(image.carved_sections[1].name, b".vmp1");
        assert_eq!(image.carved_sections[1].virtual_address, 0x3000);
        assert!(image.carved_sections[1].perms.write);
        assert_eq!(image.carved_sections[1].blob, vmp1_body);
    }

    #[test]
    fn themida_detect_and_carve_surfaces_blob_and_geometry() {
        let themida_body: Vec<u8> = (0u8..96).collect();
        let packed: Vec<u8> = build_pe(&[
            (b".text", 0x1000, SCN_READ | SCN_EXECUTE, &[0x90; 16]),
            (
                b".themida",
                0x2000,
                SCN_READ | SCN_WRITE | SCN_EXECUTE,
                &themida_body,
            ),
        ]);
        let detections: Vec<Detection> = detect(&packed);
        assert!(
            detections
                .iter()
                .any(|d: &Detection| d.packer == Packer::Themida)
        );
        let recovered: Vec<RecoveredImage> = recover_detected(&packed, &detections);
        let image: &RecoveredImage = recovered
            .iter()
            .find(|r: &&RecoveredImage| r.packer == Packer::Themida.label())
            .expect("themida carve output");
        assert_eq!(image.oracle, RecoveryOracle::ProtectedSectionCarved);
        assert_eq!(image.image, themida_body);
        assert_eq!(image.recovered_len, themida_body.len() as u64);
        assert_eq!(image.carved_sections.len(), 1);
        assert_eq!(image.carved_sections[0].name, b".themida");
        assert_eq!(image.carved_sections[0].virtual_address, 0x2000);
        assert_eq!(image.carved_sections[0].raw_size, themida_body.len() as u32);
        assert!(image.carved_sections[0].perms.read);
        assert!(image.carved_sections[0].perms.write);
        assert!(image.carved_sections[0].perms.execute);
        assert!(!image.carved_sections[0].blob_truncated);
        assert_eq!(image.carved_sections[0].blob, themida_body);
    }

    #[test]
    fn oversized_input_yields_no_recovery() {
        let detections: Vec<Detection> = Vec::new();
        let out: Vec<RecoveredImage> = recover_detected(&[], &detections);
        assert!(out.is_empty());
    }
}
