const SECTION_ENTRY_SIZE: usize = 40;
const IMAGE_SCN_CODE_EXEC_READ: u32 = 0x6000_0020;
const PE64_IMAGE_BASE: u64 = 0x0000_0001_4000_0000;

#[must_use]
pub(crate) fn pe64_with_text(text: &[u8], text_va: u32) -> Vec<u8> {
    let opt_size: usize = 0xF0;
    let sec_off: usize = 0x80 + 4 + 20 + opt_size;
    let header_len: usize = sec_off + SECTION_ENTRY_SIZE;
    let raw_off: usize = header_len.max(0x200);
    let mut buf: Vec<u8> = vec![0u8; raw_off + text.len()];
    buf[0] = b'M';
    buf[1] = b'Z';
    let e_lfanew: u32 = 0x80;
    buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let pe_off: usize = e_lfanew as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
    let coff: usize = pe_off + 4;
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&text_va.to_le_bytes());
    buf[opt + 24..opt + 32].copy_from_slice(&PE64_IMAGE_BASE.to_le_bytes());
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    let base: usize = sec_off;
    buf[base..base + 5].copy_from_slice(b".text");
    buf[base + 8..base + 12].copy_from_slice(&(text.len() as u32).to_le_bytes());
    buf[base + 12..base + 16].copy_from_slice(&text_va.to_le_bytes());
    buf[base + 16..base + 20].copy_from_slice(&(text.len() as u32).to_le_bytes());
    buf[base + 20..base + 24].copy_from_slice(&(raw_off as u32).to_le_bytes());
    buf[base + 36..base + 40].copy_from_slice(&IMAGE_SCN_CODE_EXEC_READ.to_le_bytes());
    buf[raw_off..raw_off + text.len()].copy_from_slice(text);
    buf
}

#[must_use]
pub(crate) fn pe64_text_base() -> u64 {
    PE64_IMAGE_BASE
}
