use std::collections::BTreeMap;

use super::mpress_lzma::decode_mpress_lzma;
use super::pe_sections::{PeImage, PeSection, parse_pe_image, read_u32};
use crate::error::{Error, Result};

const MAX_IMAGE_BYTES: usize = 256 * 1024 * 1024;

const MPRESS_MAX_IMAGE_RATIO: usize = 1024;

const MPRESS1_NAME: &[u8; 8] = b".MPRESS1";
const MPRESS2_NAME: &[u8; 8] = b".MPRESS2";

const MPRESS_HEADER_SIZE: usize = 6;
const MPRESS_PAGE_SHIFT: u32 = 12;
const MPRESS_FILTER_TAIL: usize = 0x1000;

#[derive(Debug, Clone, Copy)]
pub struct MpressInfo {
    pub mpress1_va: u32,
    pub mpress1_vsize: u32,
    pub mpress1_raw_off: u32,
    pub mpress1_raw_size: u32,
    pub mpress2_va: u32,
    pub mpress2_vsize: u32,
    pub mpress2_raw_off: u32,
    pub mpress2_raw_size: u32,
    pub address_of_entry_point: u32,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub file_alignment: u32,
    pub section_alignment: u32,
    pub pe_header_off: u32,
    pub is_pe32_plus: bool,
    pub base_of_code: u32,
    pub size_of_code: u32,
    pub mpress_page_count: u16,
    pub mpress_payload_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpressRecoveryStatus {
    StructuralOnly,
    LzmatDecoded,
}

#[derive(Debug, Clone)]
pub struct MpressUnpackOutput {
    pub original_pe: Vec<u8>,
    pub decompressed_image: Vec<u8>,
    pub info: MpressInfo,
    pub section_names: Vec<String>,
    pub recovery_status: MpressRecoveryStatus,
    pub lzmat_payload: Vec<u8>,
    pub decoded_payload: Vec<u8>,
    pub recovered_imports: Vec<MpressImport>,
}

#[derive(Debug, Clone)]
pub struct MpressImport {
    pub dll_name: String,
    pub iat_rva: u32,
}

pub fn unpack_mpress(packed_bytes: &[u8]) -> Result<MpressUnpackOutput> {
    let info: MpressInfo = locate_mpress_sections(packed_bytes)?;
    let mpress1_slice: &[u8] =
        slice_section(packed_bytes, info.mpress1_raw_off, info.mpress1_raw_size)?;
    if mpress1_slice.len() < MPRESS_HEADER_SIZE {
        return Err(Error::Truncated {
            needed: MPRESS_HEADER_SIZE,
            had: mpress1_slice.len(),
        });
    }
    let payload_len: usize = info.mpress_payload_len as usize;
    if payload_len > mpress1_slice.len().saturating_sub(MPRESS_HEADER_SIZE) {
        return Err(Error::SignatureDb(format!(
            "MPRESS header payload_len={payload_len:#x} exceeds .MPRESS1 raw bytes available {}",
            mpress1_slice.len() - MPRESS_HEADER_SIZE
        )));
    }
    let lzmat_payload: Vec<u8> =
        mpress1_slice[MPRESS_HEADER_SIZE..MPRESS_HEADER_SIZE + payload_len].to_vec();

    let mpress2_slice: &[u8] =
        slice_section(packed_bytes, info.mpress2_raw_off, info.mpress2_raw_size)?;
    let recovered_imports: Vec<MpressImport> = scan_mpress2_imports(mpress2_slice, &info);

    let image_size: usize = info.size_of_image as usize;
    let image_ceiling: usize =
        MAX_IMAGE_BYTES.min(packed_bytes.len().saturating_mul(MPRESS_MAX_IMAGE_RATIO));
    if image_size > image_ceiling {
        return Err(Error::SignatureDb(format!(
            "MPRESS: declared SizeOfImage {image_size} exceeds safety ceiling {image_ceiling} \
             (packed input {} bytes) - refusing oversized allocation",
            packed_bytes.len()
        )));
    }
    let payload_decompressed_size: usize =
        ((info.mpress_page_count as usize) << MPRESS_PAGE_SHIFT).min(image_ceiling);

    let (decompressed_image, recovery_status, decoded_payload): (
        Vec<u8>,
        MpressRecoveryStatus,
        Vec<u8>,
    ) = decode_mpress_lzma(&lzmat_payload, payload_decompressed_size).map_or_else(
        |_| {
            let fallback: Vec<u8> =
                build_structural_image(packed_bytes, &info, &lzmat_payload, image_size);
            (fallback, MpressRecoveryStatus::StructuralOnly, Vec::new())
        },
        |decoded: Vec<u8>| {
            let img: Vec<u8> =
                assemble_image_from_payload(packed_bytes, &info, &decoded, image_size);
            (img, MpressRecoveryStatus::LzmatDecoded, decoded)
        },
    );

    let (original_pe, section_names): (Vec<u8>, Vec<String>) =
        synthesize_structural_pe(packed_bytes, &info, &lzmat_payload)?;

    Ok(MpressUnpackOutput {
        original_pe,
        decompressed_image,
        info,
        section_names,
        recovery_status,
        lzmat_payload,
        decoded_payload,
        recovered_imports,
    })
}

fn assemble_image_from_payload(
    packed_bytes: &[u8],
    info: &MpressInfo,
    decoded_payload: &[u8],
    image_size: usize,
) -> Vec<u8> {
    let mut image: Vec<u8> = vec![0u8; image_size];
    let hdr_copy: usize = (info.size_of_headers as usize)
        .min(packed_bytes.len())
        .min(image_size);
    image[..hdr_copy].copy_from_slice(&packed_bytes[..hdr_copy]);
    let start_off: usize = info.mpress1_va as usize;
    let max_copy: usize = decoded_payload
        .len()
        .min(image_size.saturating_sub(start_off));
    if max_copy > 0 {
        let mut payload: Vec<u8> = decoded_payload.to_vec();
        unfilter_code_branches(&mut payload);
        image[start_off..start_off + max_copy].copy_from_slice(&payload[..max_copy]);
    }
    let mpress2_dst: usize = info.mpress2_va as usize;
    let mpress2_avail: usize = (info.mpress2_raw_size as usize).min(
        packed_bytes
            .len()
            .saturating_sub(info.mpress2_raw_off as usize),
    );
    let mpress2_copy: usize = mpress2_avail.min(image_size.saturating_sub(mpress2_dst));
    if mpress2_copy > 0 {
        let src_start: usize = info.mpress2_raw_off as usize;
        image[mpress2_dst..mpress2_dst + mpress2_copy]
            .copy_from_slice(&packed_bytes[src_start..src_start + mpress2_copy]);
    }
    image
}

fn unfilter_code_branches(payload: &mut [u8]) {
    let len: usize = payload.len();
    if len <= MPRESS_FILTER_TAIL {
        return;
    }
    let max_addr: i64 = (len - MPRESS_FILTER_TAIL) as i64;
    let mut pos: usize = 0;
    while (pos as i64) < max_addr {
        let opcode: u8 = payload[pos];
        if opcode & 0xFE == 0xE8 {
            if pos + 5 > len {
                break;
            }
            recover_displacement(payload, pos + 1, max_addr);
            pos += 5;
            continue;
        }
        if (opcode == 0x8D || opcode == 0xFF)
            && pos + 6 <= len
            && (payload[pos + 1] & 0xC7) == 0x05
            && rip_field_is_filtered(opcode, payload[pos + 1])
        {
            recover_displacement(payload, pos + 2, max_addr);
            pos += 6;
            continue;
        }
        pos += 1;
    }
}

fn rip_field_is_filtered(opcode: u8, modrm: u8) -> bool {
    match opcode {
        0x8D => true,
        0xFF => (modrm >> 3) & 0x07 == 0x02,
        _ => false,
    }
}

fn recover_displacement(payload: &mut [u8], field: usize, max_addr: i64) {
    let move_offset: i64 = field as i64;
    let stored: i64 = i64::from(i32::from_le_bytes([
        payload[field],
        payload[field + 1],
        payload[field + 2],
        payload[field + 3],
    ]));
    let recovered: Option<i64> = if stored >= 0 {
        (stored < max_addr).then_some(stored - move_offset)
    } else {
        (stored + move_offset >= 0).then_some(stored + max_addr)
    };
    if let Some(value) = recovered {
        payload[field..field + 4].copy_from_slice(&(value as i32).to_le_bytes());
    }
}

fn build_structural_image(
    packed_bytes: &[u8],
    info: &MpressInfo,
    lzmat_payload: &[u8],
    image_size: usize,
) -> Vec<u8> {
    let mut image: Vec<u8> = vec![0u8; image_size];
    let hdr_copy: usize = (info.size_of_headers as usize)
        .min(packed_bytes.len())
        .min(image_size);
    image[..hdr_copy].copy_from_slice(&packed_bytes[..hdr_copy]);
    let start_off: usize = info.mpress1_va as usize;
    let max_copy: usize = lzmat_payload
        .len()
        .min(image_size.saturating_sub(start_off));
    if max_copy > 0 {
        image[start_off..start_off + max_copy].copy_from_slice(&lzmat_payload[..max_copy]);
    }
    let mpress2_dst: usize = info.mpress2_va as usize;
    let mpress2_avail: usize = (info.mpress2_raw_size as usize).min(
        packed_bytes
            .len()
            .saturating_sub(info.mpress2_raw_off as usize),
    );
    let mpress2_copy: usize = mpress2_avail.min(image_size.saturating_sub(mpress2_dst));
    if mpress2_copy > 0 {
        let src_start: usize = info.mpress2_raw_off as usize;
        image[mpress2_dst..mpress2_dst + mpress2_copy]
            .copy_from_slice(&packed_bytes[src_start..src_start + mpress2_copy]);
    }
    image
}

fn synthesize_structural_pe(
    packed_bytes: &[u8],
    info: &MpressInfo,
    lzmat_payload: &[u8],
) -> Result<(Vec<u8>, Vec<String>)> {
    let image_ceiling: usize =
        MAX_IMAGE_BYTES.min(packed_bytes.len().saturating_mul(MPRESS_MAX_IMAGE_RATIO));
    let file_align: u32 = info.file_alignment.max(1);
    let hdr_aligned: u32 = checked_align_up(info.size_of_headers, file_align)
        .ok_or_else(|| structural_overflow("size_of_headers"))?;
    let payload_aligned: u32 = checked_align_up(lzmat_payload.len() as u32, file_align)
        .ok_or_else(|| structural_overflow("payload"))?;
    let mpress2_size: u32 = info.mpress2_raw_size;
    let mpress2_aligned: u32 =
        checked_align_up(mpress2_size, file_align).ok_or_else(|| structural_overflow("mpress2"))?;
    let total_size: u32 = hdr_aligned
        .checked_add(payload_aligned)
        .and_then(|t: u32| t.checked_add(mpress2_aligned))
        .ok_or_else(|| structural_overflow("total"))?;
    let total_usize: usize = total_size as usize;
    if total_usize > image_ceiling {
        return Err(Error::SignatureDb(format!(
            "MPRESS: structural image {total_usize} exceeds safety ceiling {image_ceiling} \
             (packed input {} bytes) - refusing oversized allocation",
            packed_bytes.len()
        )));
    }
    let mut out: Vec<u8> = vec![0u8; total_usize];
    let hdr_copy: usize = (info.size_of_headers as usize).min(packed_bytes.len());
    out[..hdr_copy].copy_from_slice(&packed_bytes[..hdr_copy]);
    let payload_off: usize = hdr_aligned as usize;
    let payload_copy: usize = lzmat_payload.len().min(out.len() - payload_off);
    out[payload_off..payload_off + payload_copy].copy_from_slice(&lzmat_payload[..payload_copy]);
    let mpress2_off: usize = (hdr_aligned + payload_aligned) as usize;
    let mpress2_src: usize = info.mpress2_raw_off as usize;
    let mpress2_copy_len: usize = (mpress2_size as usize)
        .min(packed_bytes.len().saturating_sub(mpress2_src))
        .min(out.len() - mpress2_off);
    if mpress2_copy_len > 0 {
        out[mpress2_off..mpress2_off + mpress2_copy_len]
            .copy_from_slice(&packed_bytes[mpress2_src..mpress2_src + mpress2_copy_len]);
    }
    let section_names: Vec<String> = vec!["mp1.lzmat".to_owned(), "mp2.stub".to_owned()];
    let _ = info;
    Ok((out, section_names))
}

fn scan_mpress2_imports(mpress2: &[u8], info: &MpressInfo) -> Vec<MpressImport> {
    let mut imports: Vec<MpressImport> = Vec::new();
    let mut i: usize = 0;
    while i < mpress2.len() {
        let b: u8 = mpress2[i];
        let is_printable: bool = (0x20..=0x7E).contains(&b);
        if is_printable {
            let mut j: usize = i;
            while j < mpress2.len() && (0x20..=0x7E).contains(&mpress2[j]) {
                j += 1;
            }
            let len: usize = j - i;
            if (5..=64).contains(&len) && mpress2.get(j).copied() == Some(0) {
                let candidate: &[u8] = &mpress2[i..j];
                let looks_like_dll: bool = candidate
                    .windows(4)
                    .any(|w: &[u8]| w.eq_ignore_ascii_case(b".dll"));
                if looks_like_dll {
                    let name: String = String::from_utf8_lossy(candidate).into_owned();
                    imports.push(MpressImport {
                        dll_name: name,
                        iat_rva: info.mpress2_va.saturating_add(i as u32),
                    });
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    imports
}

fn slice_section(bytes: &[u8], offset: u32, size: u32) -> Result<&[u8]> {
    let start: usize = offset as usize;
    let end: usize = start.checked_add(size as usize).ok_or(Error::Truncated {
        needed: usize::MAX,
        had: bytes.len(),
    })?;
    if end > bytes.len() {
        return Err(Error::Truncated {
            needed: end,
            had: bytes.len(),
        });
    }
    Ok(&bytes[start..end])
}

fn locate_mpress_sections(bytes: &[u8]) -> Result<MpressInfo> {
    if bytes.len() < 0x40 {
        return Err(Error::Truncated {
            needed: 0x40,
            had: bytes.len(),
        });
    }
    if &bytes[0..2] != b"MZ" {
        return Err(Error::UnknownFormat);
    }
    let image: PeImage = parse_pe_image(bytes)?;
    let mut sections: BTreeMap<u32, &PeSection> = BTreeMap::new();
    for section in &image.sections {
        sections.insert(section.virtual_address, section);
    }
    let mut mpress1: Option<&PeSection> = None;
    let mut mpress2: Option<&PeSection> = None;
    for entry in sections.values() {
        if &entry.name == MPRESS1_NAME {
            mpress1 = Some(entry);
        } else if &entry.name == MPRESS2_NAME {
            mpress2 = Some(entry);
        }
    }
    let m1: &PeSection = mpress1.ok_or_else(|| {
        Error::SignatureDb(
            ".MPRESS1 section not found in PE - not an MPRESS-packed binary".to_owned(),
        )
    })?;
    let m2: &PeSection = mpress2.ok_or_else(|| {
        Error::SignatureDb(
            ".MPRESS2 section not found in PE - not an MPRESS-packed binary".to_owned(),
        )
    })?;
    let (mpress_page_count, mpress_payload_len): (u16, u32) =
        read_mpress_header(bytes, m1.raw_pointer, m1.raw_size)?;
    let claimed_decompressed: u32 = u32::from(mpress_page_count) << MPRESS_PAGE_SHIFT;
    if claimed_decompressed == 0 {
        return Err(Error::SignatureDb(
            "MPRESS header reported zero decompressed size".to_owned(),
        ));
    }
    let opt_off: usize = (image.pe_header_offset as usize).saturating_add(24);
    let size_of_code: u32 = read_u32(bytes, opt_off.saturating_add(4)).unwrap_or(0);
    let base_of_code: u32 = read_u32(bytes, opt_off.saturating_add(20)).unwrap_or(0);
    Ok(MpressInfo {
        mpress1_va: m1.virtual_address,
        mpress1_vsize: m1.virtual_size,
        mpress1_raw_off: m1.raw_pointer,
        mpress1_raw_size: m1.raw_size,
        mpress2_va: m2.virtual_address,
        mpress2_vsize: m2.virtual_size,
        mpress2_raw_off: m2.raw_pointer,
        mpress2_raw_size: m2.raw_size,
        address_of_entry_point: image.entry_point_rva,
        size_of_headers: image.size_of_headers,
        size_of_image: image.size_of_image,
        file_alignment: image.file_alignment,
        section_alignment: image.section_alignment,
        pe_header_off: image.pe_header_offset,
        is_pe32_plus: image.is_pe32_plus,
        base_of_code,
        size_of_code,
        mpress_page_count,
        mpress_payload_len,
    })
}

fn read_mpress_header(bytes: &[u8], raw_off: u32, raw_size: u32) -> Result<(u16, u32)> {
    let slice: &[u8] = slice_section(bytes, raw_off, raw_size)?;
    if slice.len() < MPRESS_HEADER_SIZE {
        return Err(Error::Truncated {
            needed: MPRESS_HEADER_SIZE,
            had: slice.len(),
        });
    }
    let page_count: u16 = u16::from_le_bytes([slice[0], slice[1]]);
    let payload_len: u32 = u32::from_le_bytes([slice[2], slice[3], slice[4], slice[5]]);
    Ok((page_count, payload_len))
}

const fn checked_align_up(value: u32, alignment: u32) -> Option<u32> {
    if alignment == 0 {
        return Some(value);
    }
    let mask: u32 = alignment - 1;
    match value.checked_add(mask) {
        Some(sum) => Some(sum & !mask),
        None => None,
    }
}

fn structural_overflow(field: &str) -> Error {
    Error::SignatureDb(format!(
        "MPRESS: structural-PE {field} size math overflowed u32 - refusing allocation"
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        MpressInfo, MpressRecoveryStatus, MpressUnpackOutput, Result, checked_align_up,
        locate_mpress_sections, unpack_mpress,
    };
    use crate::error::Error;

    #[test]
    fn checked_align_up_works() {
        assert_eq!(checked_align_up(0, 0x200), Some(0));
        assert_eq!(checked_align_up(1, 0x200), Some(0x200));
        assert_eq!(checked_align_up(0x1FF, 0x200), Some(0x200));
        assert_eq!(checked_align_up(0x200, 0x200), Some(0x200));
        assert_eq!(checked_align_up(0x201, 0x200), Some(0x400));
        assert_eq!(checked_align_up(0, 0), Some(0));
    }

    #[test]
    fn checked_align_up_rejects_overflow() {
        assert_eq!(
            checked_align_up(u32::MAX, 0x200),
            None,
            "a near-u32::MAX value plus alignment mask must not wrap"
        );
        assert_eq!(checked_align_up(u32::MAX - 0x100, 0x200), None);
    }

    #[test]
    fn rejects_non_mz_input() {
        let buf: Vec<u8> = vec![0u8; 256];
        let r: Result<MpressUnpackOutput> = unpack_mpress(&buf);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_missing_mpress_sections() {
        let mut buf: Vec<u8> = vec![0u8; 1024];
        buf[0] = b'M';
        buf[1] = b'Z';
        let pe_off: u32 = 0x80;
        buf[0x3C] = pe_off as u8;
        buf[0x3D] = (pe_off >> 8) as u8;
        buf[0x80] = b'P';
        buf[0x81] = b'E';
        let r: Result<MpressUnpackOutput> = unpack_mpress(&buf);
        assert!(matches!(
            r,
            Err(Error::UnknownFormat | Error::Truncated { .. } | Error::SignatureDb(_))
        ));
    }

    #[test]
    fn structural_status_is_distinct_from_full_decode() {
        assert_ne!(
            MpressRecoveryStatus::StructuralOnly,
            MpressRecoveryStatus::LzmatDecoded
        );
    }

    fn build_mpress_pe_with_size_of_image(size_of_image: u32) -> Vec<u8> {
        let pe_off: usize = 0x80;
        let opt_off: usize = pe_off + 24;
        let opt_size: usize = 0xE0;
        let sec_table_off: usize = opt_off + opt_size;
        let mpress1_raw_off: usize = 0x600;
        let mpress2_raw_off: usize = 0x700;
        let total: usize = (mpress2_raw_off + 0x100).max(sec_table_off + 2 * 40);
        let mut buf: Vec<u8> = vec![0u8; total];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        buf[pe_off + 4 + 2..pe_off + 4 + 4].copy_from_slice(&2u16.to_le_bytes());
        buf[pe_off + 4 + 16..pe_off + 4 + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        buf[opt_off..opt_off + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_off + 56..opt_off + 60].copy_from_slice(&size_of_image.to_le_bytes());
        buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let s0: usize = sec_table_off;
        buf[s0..s0 + 8].copy_from_slice(b".MPRESS1");
        buf[s0 + 8..s0 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[s0 + 12..s0 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[s0 + 16..s0 + 20].copy_from_slice(&0x40u32.to_le_bytes());
        buf[s0 + 20..s0 + 24].copy_from_slice(&(mpress1_raw_off as u32).to_le_bytes());
        let s1: usize = sec_table_off + 40;
        buf[s1..s1 + 8].copy_from_slice(b".MPRESS2");
        buf[s1 + 8..s1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[s1 + 12..s1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[s1 + 16..s1 + 20].copy_from_slice(&0x40u32.to_le_bytes());
        buf[s1 + 20..s1 + 24].copy_from_slice(&(mpress2_raw_off as u32).to_le_bytes());
        buf[mpress1_raw_off..mpress1_raw_off + 2].copy_from_slice(&1u16.to_le_bytes());
        buf[mpress1_raw_off + 2..mpress1_raw_off + 6].copy_from_slice(&0u32.to_le_bytes());
        buf
    }

    #[test]
    fn rejects_oversized_size_of_image() {
        let pe: Vec<u8> = build_mpress_pe_with_size_of_image(0xFFFF_F000);
        let start: std::time::Instant = std::time::Instant::now();
        let r: Result<MpressUnpackOutput> = unpack_mpress(&pe);
        assert!(
            matches!(r, Err(Error::SignatureDb(ref m)) if m.contains("SizeOfImage")),
            "crafted ~4 GiB SizeOfImage must be rejected with a real error, got {r:?}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "rejection must be immediate, never allocating gigabytes"
        );
    }

    #[test]
    fn accepts_sane_size_of_image() {
        let pe: Vec<u8> = build_mpress_pe_with_size_of_image(0x4000);
        let info: MpressInfo = locate_mpress_sections(&pe).expect("MPRESS layout");
        assert_eq!(info.mpress1_va, 0x1000);
        assert_eq!(info.mpress1_vsize, 0x1000);
        assert_eq!(info.mpress1_raw_off, 0x600);
        assert_eq!(info.mpress1_raw_size, 0x40);
        assert_eq!(info.mpress2_va, 0x2000);
        assert_eq!(info.mpress2_vsize, 0x1000);
        assert_eq!(info.mpress2_raw_off, 0x700);
        assert_eq!(info.mpress2_raw_size, 0x40);
        assert_eq!(info.address_of_entry_point, 0);
        assert_eq!(info.size_of_headers, 0x200);
        assert_eq!(info.size_of_image, 0x4000);
        assert_eq!(info.file_alignment, 0x200);
        assert_eq!(info.section_alignment, 0x1000);
        assert_eq!(info.pe_header_off, 0x80);
        assert!(!info.is_pe32_plus);
        assert_eq!(info.mpress_page_count, 1);
        assert_eq!(info.mpress_payload_len, 0);
        let r: Result<MpressUnpackOutput> = unpack_mpress(&pe);
        assert!(
            !matches!(r, Err(Error::SignatureDb(ref m)) if m.contains("SizeOfImage")),
            "a sane SizeOfImage must not trip the allocation ceiling: {r:?}"
        );
    }

    #[test]
    fn structural_size_math_overflow_is_rejected_without_panic() {
        let mut pe: Vec<u8> = build_mpress_pe_with_size_of_image(0x4000);
        let opt_off: usize = 0x80 + 24;
        pe[opt_off + 60..opt_off + 64].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        let start: std::time::Instant = std::time::Instant::now();
        let r: Result<MpressUnpackOutput> = unpack_mpress(&pe);
        assert!(
            matches!(r, Err(Error::SignatureDb(ref m)) if m.contains("MPRESS")),
            "a hostile SizeOfHeaders that overflows the align/total math must fault, got {r:?}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "structural overflow rejection must be immediate, never a multi-GiB allocation"
        );
    }
}
