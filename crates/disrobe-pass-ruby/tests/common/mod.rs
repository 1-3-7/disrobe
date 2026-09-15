#![allow(dead_code, unreachable_pub, clippy::expect_used)]
pub const YARV_MAGIC: &[u8; 4] = b"YARB";
pub const RITE_MAGIC: &[u8; 4] = b"RITE";
pub const YARV_HEADER_SIZE: usize = 36;
pub const RITE_HEADER_SIZE: usize = 20;

#[must_use]
pub fn synth_yarv(major: u32, minor: u32, body: &[u8]) -> Vec<u8> {
    let header_size_u32: u32 = u32::try_from(YARV_HEADER_SIZE).expect("size fits u32");
    let body_len_u32: u32 = u32::try_from(body.len()).expect("body fits u32");
    let mut v: Vec<u8> = Vec::with_capacity(YARV_HEADER_SIZE + body.len());
    v.extend_from_slice(YARV_MAGIC);
    v.extend_from_slice(&major.to_le_bytes());
    v.extend_from_slice(&minor.to_le_bytes());
    v.extend_from_slice(&(header_size_u32 + body_len_u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&header_size_u32.to_le_bytes());
    v.extend_from_slice(&header_size_u32.to_le_bytes());
    v.extend_from_slice(body);
    v
}

#[must_use]
pub fn synth_section(id: [u8; 4], body: &[u8]) -> Vec<u8> {
    let size: u32 = 8u32 + u32::try_from(body.len()).expect("body fits u32");
    let mut v: Vec<u8> = Vec::with_capacity(size as usize);
    v.extend_from_slice(&id);
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(body);
    v
}

#[must_use]
pub fn synth_rite(format_version: [u8; 4], sections: &[Vec<u8>]) -> Vec<u8> {
    let body_len: usize = sections.iter().map(Vec::len).sum::<usize>();
    let total: u32 = u32::try_from(RITE_HEADER_SIZE + body_len).expect("size fits u32");
    let mut v: Vec<u8> = Vec::with_capacity(total as usize);
    v.extend_from_slice(RITE_MAGIC);
    v.extend_from_slice(&format_version);
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(b"MATZ");
    v.extend_from_slice(b"0000");
    for s in sections {
        v.extend_from_slice(s);
    }
    v
}
