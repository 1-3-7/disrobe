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

pub(crate) struct SyntheticSection {
    pub(crate) name: [u8; 8],
    pub(crate) virtual_address: u32,
    pub(crate) virtual_size: u32,
    pub(crate) raw: Vec<u8>,
    pub(crate) characteristics: u32,
}

impl SyntheticSection {
    #[must_use]
    pub(crate) fn backed(
        name: [u8; 8],
        virtual_address: u32,
        raw: Vec<u8>,
        characteristics: u32,
    ) -> Self {
        Self {
            name,
            virtual_address,
            virtual_size: raw.len() as u32,
            raw,
            characteristics,
        }
    }

    #[must_use]
    pub(crate) fn unbacked(
        name: [u8; 8],
        virtual_address: u32,
        virtual_size: u32,
        characteristics: u32,
    ) -> Self {
        Self {
            name,
            virtual_address,
            virtual_size,
            raw: Vec::new(),
            characteristics,
        }
    }
}

const LAYOUT_HEADERS: usize = 0x400;
const LAYOUT_FILE_ALIGNMENT: usize = 0x200;

#[must_use]
pub(crate) fn pe64_layout(sections: &[SyntheticSection], entry_rva: u32) -> Vec<u8> {
    pe64_layout_with_directories(sections, entry_rva, &[])
}

#[must_use]
pub(crate) fn pe64_layout_with_directories(
    sections: &[SyntheticSection],
    entry_rva: u32,
    directories: &[(usize, u32, u32)],
) -> Vec<u8> {
    let opt_size: usize = 0xF0;
    let sec_off: usize = 0x80 + 4 + 20 + opt_size;
    assert!(sec_off + sections.len() * SECTION_ENTRY_SIZE <= LAYOUT_HEADERS);
    let mut buf: Vec<u8> = vec![0u8; LAYOUT_HEADERS];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    let coff: usize = 0x84;
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    let count: u16 = sections.len() as u16;
    buf[coff + 2..coff + 4].copy_from_slice(&count.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
    let opt: usize = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
    buf[opt + 24..opt + 32].copy_from_slice(&PE64_IMAGE_BASE.to_le_bytes());
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 36..opt + 40].copy_from_slice(&(LAYOUT_FILE_ALIGNMENT as u32).to_le_bytes());
    let image_end: u32 = sections
        .iter()
        .map(|s: &SyntheticSection| s.virtual_address + s.virtual_size.max(1))
        .max()
        .unwrap_or(0x1000);
    let size_of_image: u32 = image_end.div_ceil(0x1000) * 0x1000;
    buf[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());
    buf[opt + 60..opt + 64].copy_from_slice(&(LAYOUT_HEADERS as u32).to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes());
    buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    for &(index, rva, size) in directories {
        let at: usize = opt + 112 + index * 8;
        buf[at..at + 4].copy_from_slice(&rva.to_le_bytes());
        buf[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
    }
    for (index, section) in sections.iter().enumerate() {
        let row: usize = sec_off + index * SECTION_ENTRY_SIZE;
        let raw_size: usize = section.raw.len().next_multiple_of(LAYOUT_FILE_ALIGNMENT);
        let raw_pointer: usize = if raw_size == 0 { 0 } else { buf.len() };
        buf[row..row + 8].copy_from_slice(&section.name);
        buf[row + 8..row + 12].copy_from_slice(&section.virtual_size.to_le_bytes());
        buf[row + 12..row + 16].copy_from_slice(&section.virtual_address.to_le_bytes());
        buf[row + 16..row + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
        buf[row + 20..row + 24].copy_from_slice(&(raw_pointer as u32).to_le_bytes());
        buf[row + 36..row + 40].copy_from_slice(&section.characteristics.to_le_bytes());
        if raw_size != 0 {
            buf.extend_from_slice(&section.raw);
            buf.resize(raw_pointer + raw_size, 0);
        }
    }
    buf
}
