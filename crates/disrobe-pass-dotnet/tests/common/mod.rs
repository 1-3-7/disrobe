#![allow(dead_code, clippy::redundant_pub_crate, unreachable_pub)]
pub(crate) mod protector_pe;

pub(crate) const PE_BASE_LEN: usize = 0x600;

#[must_use]
pub(crate) fn synth_minimal_dotnet_pe(runtime_version: &str) -> Vec<u8> {
    let mut img: Vec<u8> = vec![0u8; PE_BASE_LEN];
    img[0] = b'M';
    img[1] = b'Z';
    let pe_offset: u32 = 0x80;
    img[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
    let pe_off: usize = pe_offset as usize;
    img[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    img[pe_off + 4..pe_off + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
    img[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
    img[pe_off + 8..pe_off + 12].copy_from_slice(&0u32.to_le_bytes());
    img[pe_off + 12..pe_off + 16].copy_from_slice(&0u32.to_le_bytes());
    img[pe_off + 16..pe_off + 20].copy_from_slice(&0u32.to_le_bytes());
    let opt_size: u16 = 0xE0;
    img[pe_off + 20..pe_off + 22].copy_from_slice(&opt_size.to_le_bytes());
    img[pe_off + 22..pe_off + 24].copy_from_slice(&0x2102u16.to_le_bytes());
    let opt_start: usize = pe_off + 24;
    img[opt_start..opt_start + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    img[opt_start + 2] = 8;
    img[opt_start + 3] = 0;
    img[opt_start + 16..opt_start + 20].copy_from_slice(&0x2050u32.to_le_bytes());
    img[opt_start + 28..opt_start + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    let directories_start: usize = opt_start + 96;
    let number_of_dirs: u32 = 16;
    img[opt_start + 92..opt_start + 96].copy_from_slice(&number_of_dirs.to_le_bytes());
    let clr_rva: u32 = 0x2008;
    let clr_size: u32 = 72;
    let clr_dir_offset: usize = directories_start + 14 * 8;
    img[clr_dir_offset..clr_dir_offset + 4].copy_from_slice(&clr_rva.to_le_bytes());
    img[clr_dir_offset + 4..clr_dir_offset + 8].copy_from_slice(&clr_size.to_le_bytes());
    let sections_start: usize = opt_start + opt_size as usize;
    let section_name: &[u8; 8] = b".text\0\0\0";
    img[sections_start..sections_start + 8].copy_from_slice(section_name);
    img[sections_start + 8..sections_start + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    img[sections_start + 12..sections_start + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    img[sections_start + 16..sections_start + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    let raw_pointer: u32 = 0x200;
    img[sections_start + 20..sections_start + 24].copy_from_slice(&raw_pointer.to_le_bytes());
    img[sections_start + 36..sections_start + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    let clr_file_offset: usize = (raw_pointer + (clr_rva - 0x2000)) as usize;
    img[clr_file_offset..clr_file_offset + 4].copy_from_slice(&72u32.to_le_bytes());
    img[clr_file_offset + 4..clr_file_offset + 6].copy_from_slice(&4u16.to_le_bytes());
    img[clr_file_offset + 6..clr_file_offset + 8].copy_from_slice(&0u16.to_le_bytes());
    let metadata_rva: u32 = 0x2100;
    let metadata_size: u32 = 0x80;
    img[clr_file_offset + 8..clr_file_offset + 12].copy_from_slice(&metadata_rva.to_le_bytes());
    img[clr_file_offset + 12..clr_file_offset + 16].copy_from_slice(&metadata_size.to_le_bytes());
    let metadata_file_offset: usize = (raw_pointer + (metadata_rva - 0x2000)) as usize;
    img[metadata_file_offset..metadata_file_offset + 4]
        .copy_from_slice(&0x424A_5342u32.to_le_bytes());
    img[metadata_file_offset + 4..metadata_file_offset + 6].copy_from_slice(&1u16.to_le_bytes());
    img[metadata_file_offset + 6..metadata_file_offset + 8].copy_from_slice(&1u16.to_le_bytes());
    img[metadata_file_offset + 8..metadata_file_offset + 12].copy_from_slice(&0u32.to_le_bytes());
    let version_bytes: &[u8] = runtime_version.as_bytes();
    let padded_len: usize = ((version_bytes.len() + 1).div_ceil(4)) * 4;
    img[metadata_file_offset + 12..metadata_file_offset + 16]
        .copy_from_slice(&u32::try_from(padded_len).unwrap_or(16).to_le_bytes());
    img[metadata_file_offset + 16..metadata_file_offset + 16 + version_bytes.len()]
        .copy_from_slice(version_bytes);
    let after_version: usize = metadata_file_offset + 16 + padded_len;
    img[after_version..after_version + 2].copy_from_slice(&0u16.to_le_bytes());
    img[after_version + 2..after_version + 4].copy_from_slice(&0u16.to_le_bytes());
    img
}

pub(crate) fn embed_signature(image: &mut Vec<u8>, signature: &[u8]) {
    let pad_start: usize = 0x500;
    if pad_start + signature.len() <= image.len() {
        image[pad_start..pad_start + signature.len()].copy_from_slice(signature);
    } else {
        image.extend_from_slice(signature);
    }
}
