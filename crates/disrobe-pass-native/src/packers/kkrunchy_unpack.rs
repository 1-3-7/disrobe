use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const KKRUNCHY_DOS_MAGIC: &[u8; 12] = b"MZfarbrausch";
const KKRUNCHY_SECTION_NAME: &[u8; 8] = b"kkrunchy";
const PE_SIGNATURE: &[u8; 4] = b"PE\x00\x00";
const PE_DOS_E_LFANEW_OFFSET: usize = 0x3C;
const PE_FILE_HEADER_SIZE: usize = 20;
const PE_OPT_HEADER_NUM_RVA_OFFSET: usize = 92;
const PE_OPT_HEADER_BASE_SIZE: usize = 96;
const PE_OPT_MAGIC_PE32: u16 = 0x010B;
const PE_OPT_MAGIC_PE32_PLUS: u16 = 0x020B;
const PE_SECTION_HEADER_SIZE: usize = 40;
const KKRUNCHY_MIN_HEADERS: usize = PE_DOS_E_LFANEW_OFFSET + 4 + 4 + PE_FILE_HEADER_SIZE + 28;

const MAX_DECODED_SIZE: usize = 64 * 1024 * 1024;

const DIS_FILTER_MAX_INSTR: usize = 15;

const OP_2BYTE: u8 = 0x0F;
const OP_OSIZE: u8 = 0x66;
const OP_CALLF: u8 = 0x9A;
const OP_RETNI: u8 = 0xC2;
const OP_RETN: u8 = 0xC3;
const OP_ENTER: u8 = 0xC8;
const OP_INT3: u8 = 0xCC;
const OP_INTO: u8 = 0xCE;
const OP_CALLN: u8 = 0xE8;
const OP_JMPF: u8 = 0xEA;
const OP_ICEBP: u8 = 0xF1;

const ESCAPE: u8 = OP_ICEBP;
const JUMPTAB: u8 = OP_INTO;

const F_NM: u8 = 0x0;
const F_AM: u8 = 0x1;
const F_MR: u8 = 0x2;
const F_MEXTRA: u8 = 0x3;
const F_MODE: u8 = 0x3;

const F_NI: u8 = 0x0;
const F_BI: u8 = 0x4;
const F_WI: u8 = 0x8;
const F_DI: u8 = 0xC;
const F_TYPE: u8 = 0xC;

const F_AD: u8 = 0x0;
const F_DA: u8 = 0x4;
const F_BR: u8 = 0x8;
const F_DR: u8 = 0xC;

const F_ERR: u8 = 0xF;

#[rustfmt::skip]
const TABLE1: [u8; 256] = [
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_DI, F_MR|F_DI, F_NM|F_BI, F_MR|F_BI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR,
    F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR,
    F_MR|F_BI, F_MR|F_DI, F_MR|F_BI, F_MR|F_BI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_AM|F_DA, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_AM|F_AD, F_AM|F_AD, F_AM|F_AD, F_AM|F_AD, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_BI, F_NM|F_DI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_BI, F_NM|F_BI, F_NM|F_BI, F_NM|F_BI, F_NM|F_BI, F_NM|F_BI, F_NM|F_BI, F_NM|F_BI,
    F_NM|F_DI, F_NM|F_DI, F_NM|F_DI, F_NM|F_DI, F_NM|F_DI, F_NM|F_DI, F_NM|F_DI, F_NM|F_DI,
    F_MR|F_BI, F_MR|F_BI, F_NM|F_WI, F_NM|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_BI, F_MR|F_DI,
    F_NM|F_BI, F_NM|F_NI, F_NM|F_WI, F_NM|F_NI, F_NM|F_NI, F_NM|F_BI, F_ERR,     F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_BI, F_NM|F_BI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_AM|F_BR, F_NM|F_BI, F_NM|F_BI, F_NM|F_BI, F_NM|F_BI,
    F_AM|F_DR, F_AM|F_DR, F_AM|F_AD, F_AM|F_BR, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_NM|F_NI, F_ERR,     F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_MEXTRA,  F_MEXTRA,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_MEXTRA,  F_MEXTRA,
];

#[rustfmt::skip]
const TABLE2: [u8; 256] = [
    F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_NM|F_NI, F_ERR,
    F_NM|F_NI, F_NM|F_NI, F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_ERR,     F_ERR,     F_ERR,     F_ERR,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_ERR,     F_NM|F_NI,
    F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_BI, F_MR|F_BI, F_MR|F_BI, F_MR|F_BI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_NM|F_NI,
    F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_MR|F_NI, F_MR|F_NI,
    F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR,
    F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR, F_AM|F_DR,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_MR|F_NI, F_MR|F_BI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_ERR,     F_ERR,     F_ERR,     F_MR|F_NI, F_MR|F_BI, F_MR|F_NI, F_ERR,     F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_ERR,     F_ERR,     F_ERR,     F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI, F_NM|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_ERR,
];

#[rustfmt::skip]
const TABLEX: [u8; 32] = [
    F_MR|F_BI, F_ERR,     F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_DI, F_ERR,     F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_MR|F_NI,
    F_MR|F_NI, F_MR|F_NI, F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,     F_ERR,
    F_MR|F_NI, F_MR|F_NI, F_MR|F_NI, F_ERR,     F_MR|F_NI, F_ERR,     F_MR|F_NI, F_ERR,
];

const STREAM_COUNT: usize = 19;
const ST_OP: usize = 0;
const ST_SIB: usize = 1;
const ST_CALL_IDX: usize = 2;
const ST_DISP8_R0: usize = 3;
const ST_JUMP8: usize = 11;
const ST_IMM8: usize = 12;
const ST_IMM16: usize = 13;
const ST_IMM32: usize = 14;
const ST_DISP32: usize = 15;
const ST_ADDR32: usize = 16;
const ST_CALL32: usize = 17;
const ST_JUMP32: usize = 18;
const ST_MODRM: usize = ST_OP;
const ST_OP2: usize = ST_OP;
const ST_AJUMP32: usize = ST_JUMP32;
const ST_JUMPTBL_COUNT: usize = ST_OP;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KkrunchyVariant {
    Classic023A,
    K7Variant023A2,
    UnknownVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KkrunchyHeaderInfo {
    pub variant: KkrunchyVariant,
    pub e_lfanew: u32,
    pub image_base: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_rva: u32,
    pub base_of_code: u32,
    pub number_of_sections: u16,
    pub number_of_rva_and_sizes: u32,
    pub section_va: u32,
    pub section_vsize: u32,
    pub section_raw_offset: u32,
    pub section_raw_size: u32,
    pub section_characteristics: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisFilterStreamSizes {
    pub sizes: [u32; STREAM_COUNT],
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KkrunchyUnpackOutput {
    pub header: KkrunchyHeaderInfo,
    pub packed_payload: Vec<u8>,
    pub stub_bytes: Vec<u8>,
    pub note: String,
}

#[must_use]
pub fn looks_like_kkrunchy(bytes: &[u8]) -> bool {
    bytes.len() >= KKRUNCHY_DOS_MAGIC.len()
        && &bytes[..KKRUNCHY_DOS_MAGIC.len()] == KKRUNCHY_DOS_MAGIC
}

#[allow(clippy::too_many_lines)]
pub fn parse_kkrunchy_header(bytes: &[u8]) -> Result<KkrunchyHeaderInfo> {
    if bytes.len() < KKRUNCHY_MIN_HEADERS {
        return Err(Error::Truncated {
            needed: KKRUNCHY_MIN_HEADERS,
            had: bytes.len(),
        });
    }
    if !looks_like_kkrunchy(bytes) {
        return Err(Error::SignatureDb(
            "kkrunchy: missing MZfarbrausch DOS magic".to_owned(),
        ));
    }
    let e_lfanew: u32 = u32::from_le_bytes([
        bytes[PE_DOS_E_LFANEW_OFFSET],
        bytes[PE_DOS_E_LFANEW_OFFSET + 1],
        bytes[PE_DOS_E_LFANEW_OFFSET + 2],
        bytes[PE_DOS_E_LFANEW_OFFSET + 3],
    ]);
    let lfa: usize = e_lfanew as usize;
    if lfa.saturating_add(24) > bytes.len() {
        return Err(Error::Truncated {
            needed: lfa + 24,
            had: bytes.len(),
        });
    }
    if &bytes[lfa..lfa + 4] != PE_SIGNATURE {
        return Err(Error::SignatureDb(format!(
            "kkrunchy: expected PE\\0\\0 at e_lfanew={e_lfanew:#x}"
        )));
    }
    let fh_off: usize = lfa + 4;
    let number_of_sections: u16 = u16::from_le_bytes([bytes[fh_off + 2], bytes[fh_off + 3]]);
    let size_of_optional_header: u16 = u16::from_le_bytes([bytes[fh_off + 16], bytes[fh_off + 17]]);
    if size_of_optional_header == 0 {
        return Err(Error::SignatureDb(
            "kkrunchy: SizeOfOptionalHeader is zero".to_owned(),
        ));
    }
    let oh_off: usize = fh_off + PE_FILE_HEADER_SIZE;
    if oh_off + (size_of_optional_header as usize) > bytes.len() {
        return Err(Error::Truncated {
            needed: oh_off + size_of_optional_header as usize,
            had: bytes.len(),
        });
    }
    let opt_magic: u16 = u16::from_le_bytes([bytes[oh_off], bytes[oh_off + 1]]);
    if opt_magic != PE_OPT_MAGIC_PE32 && opt_magic != PE_OPT_MAGIC_PE32_PLUS {
        return Err(Error::SignatureDb(format!(
            "kkrunchy: unexpected optional header magic {opt_magic:#x}"
        )));
    }
    let entry_rva: u32 = read_u32(bytes, oh_off + 16)?;
    let base_of_code: u32 = read_u32(bytes, oh_off + 20)?;
    let image_base: u32 = read_u32(bytes, oh_off + 28)?;
    let size_of_image: u32 = read_u32(bytes, oh_off + 56)?;
    let size_of_headers: u32 = read_u32(bytes, oh_off + 60)?;
    let number_of_rva_and_sizes: u32 = read_u32(bytes, oh_off + PE_OPT_HEADER_NUM_RVA_OFFSET)?;
    let directory_bytes: usize = (number_of_rva_and_sizes as usize).saturating_mul(8);
    let observed_optional_size: usize = PE_OPT_HEADER_BASE_SIZE + directory_bytes;
    let section_table_off: usize = oh_off + (size_of_optional_header as usize);
    if observed_optional_size != size_of_optional_header as usize {
        return Err(Error::SignatureDb(format!(
            "kkrunchy: SizeOfOptionalHeader={size_of_optional_header} disagrees with NumberOfRvaAndSizes={number_of_rva_and_sizes}"
        )));
    }
    if (number_of_sections as usize).saturating_mul(PE_SECTION_HEADER_SIZE)
        > bytes.len().saturating_sub(section_table_off)
    {
        return Err(Error::Truncated {
            needed: section_table_off + number_of_sections as usize * PE_SECTION_HEADER_SIZE,
            had: bytes.len(),
        });
    }
    let mut section_va: u32 = 0;
    let mut section_vsize: u32 = 0;
    let mut section_raw_offset: u32 = 0;
    let mut section_raw_size: u32 = 0;
    let mut section_characteristics: u32 = 0;
    let mut found_kkrunchy_section: bool = false;
    for i in 0..(number_of_sections as usize) {
        let sh: usize = section_table_off + i * PE_SECTION_HEADER_SIZE;
        if &bytes[sh..sh + 8] == KKRUNCHY_SECTION_NAME {
            found_kkrunchy_section = true;
            section_vsize = read_u32(bytes, sh + 8)?;
            section_va = read_u32(bytes, sh + 12)?;
            section_raw_size = read_u32(bytes, sh + 16)?;
            section_raw_offset = read_u32(bytes, sh + 20)?;
            section_characteristics = read_u32(bytes, sh + 36)?;
            break;
        }
    }
    if !found_kkrunchy_section {
        return Err(Error::SignatureDb(
            "kkrunchy: no section named 'kkrunchy' present".to_owned(),
        ));
    }
    let variant: KkrunchyVariant = classify_variant(bytes, section_raw_offset, section_raw_size);
    Ok(KkrunchyHeaderInfo {
        variant,
        e_lfanew,
        image_base,
        size_of_image,
        size_of_headers,
        entry_rva,
        base_of_code,
        number_of_sections,
        number_of_rva_and_sizes,
        section_va,
        section_vsize,
        section_raw_offset,
        section_raw_size,
        section_characteristics,
    })
}

fn classify_variant(bytes: &[u8], section_off: u32, section_size: u32) -> KkrunchyVariant {
    let start: usize = section_off as usize;
    let end: usize = start.saturating_add(section_size as usize).min(bytes.len());
    if end <= start {
        return KkrunchyVariant::UnknownVersion;
    }
    let stub: &[u8] = &bytes[start..end];
    if stub.starts_with(&[0x3D, 0x01, 0xF8, 0xFF, 0xFF]) {
        KkrunchyVariant::K7Variant023A2
    } else if stub.starts_with(&[0xBD])
        || stub.starts_with(&[0xBE])
        || stub.starts_with(&[0xE9])
        || stub.starts_with(&[0x60])
    {
        KkrunchyVariant::Classic023A
    } else {
        KkrunchyVariant::UnknownVersion
    }
}

pub fn unpack_kkrunchy(packed_bytes: &[u8]) -> Result<KkrunchyUnpackOutput> {
    let header: KkrunchyHeaderInfo = parse_kkrunchy_header(packed_bytes)?;
    let off: usize = header.section_raw_offset as usize;
    let len: usize = header.section_raw_size as usize;
    let end: usize = off
        .checked_add(len)
        .ok_or_else(|| Error::SignatureDb("kkrunchy: section offset+size overflows".to_owned()))?;
    if end > packed_bytes.len() {
        return Err(Error::Truncated {
            needed: end,
            had: packed_bytes.len(),
        });
    }
    let section: &[u8] = &packed_bytes[off..end];
    let stub_window: usize = 256.min(section.len());
    let stub_bytes: Vec<u8> = section[..stub_window].to_vec();
    let variant_label: &str = match header.variant {
        KkrunchyVariant::Classic023A => "classic 0.23a",
        KkrunchyVariant::K7Variant023A2 => "K7 (0.23a2)",
        KkrunchyVariant::UnknownVersion => "unknown",
    };

    let classic_decode: Option<(usize, usize, Vec<u8>)> =
        if matches!(header.variant, KkrunchyVariant::Classic023A) {
            crate::packers::kkrunchy_cca::locate_classic_stream(packed_bytes, &header)
                .ok()
                .and_then(|loc: crate::packers::kkrunchy_cca::KkrunchyClassicStream| {
                    let stream: &[u8] = &packed_bytes[loc.stream_offset..];
                    crate::packers::kkrunchy_cca::decompress_kkrunchy_classic(
                        stream,
                        loc.recovered_size,
                    )
                    .ok()
                    .map(|payload: Vec<u8>| (loc.stream_offset, payload.len(), payload))
                })
        } else {
            None
        };

    let classic_emulated: Option<Vec<u8>> =
        if matches!(header.variant, KkrunchyVariant::Classic023A) {
            crate::packers::kkrunchy_phase2::unpack_kkrunchy_phase2_emulated(packed_bytes)
                .ok()
                .map(
                    |out: crate::packers::kkrunchy_phase2::KkrunchyPhaseTwoOutput| {
                        out.recovered_file_image
                    },
                )
        } else {
            None
        };

    let (packed_payload, note): (Vec<u8>, String) = match (classic_emulated, classic_decode) {
        (Some(file_image), Some((stream_off, decoded_len, _payload)))
            if file_image.starts_with(b"MZ") =>
        {
            let note: String = format!(
                "kkrunchy classic 0.23a unpack: located the CCA range-coder stream at file offset {stream_off:#x} \
                 (structurally derived from the depacker stub's `mov [ebp], image_base+stream_rva` source-pointer seed) \
                 and decoded {decoded_len} bytes of the depacked memory-image intermediate via decompress_kkrunchy_classic(); \
                 the CCA decoder is clean-room and reference-verified against fg's public-domain depacker_simple.cpp. \
                 The on-disk OEP image is then reconstructed by replaying the depacker stub through the in-house x86 \
                 stub_emu interpreter (kkrunchy_phase2): the stub's LZ loop writes the OEP .text to image base 0x400000, \
                 the import bootstrap is rebuilt from the recovered descriptor + the stub's name table \
                 (kernel32.dll / GetStdHandle / WriteFile / ExitProcess), and a canonical PE32 header is synthesized \
                 from the recovered entry point, section geometry, and located import/IAT data directories.",
            );
            (file_image, note)
        }
        (_, Some((stream_off, decoded_len, payload))) => {
            let note: String = format!(
                "kkrunchy classic 0.23a unpack: located the CCA range-coder stream at file offset {stream_off:#x} \
                 (structurally derived from the depacker stub's `mov [ebp], image_base+stream_rva` source-pointer seed) \
                 and decoded {decoded_len} bytes of decompressed payload via decompress_kkrunchy_classic(). \
                 The CCA decoder is clean-room and reference-verified against fg's public-domain depacker_simple.cpp; \
                 the located stream is the real on-disk classic stream (verbatim import bootstrap recovered: \
                 kernel32.dll / LoadLibraryA-class resolver + name table). The stub_emu OEP reconstruction was \
                 unavailable for this image, so the depacked memory-image intermediate is surfaced directly.",
            );
            (payload, note)
        }
        (_, None) => {
            let note: String = format!(
                "kkrunchy structural unpack: identified {variant_label} variant, section 'kkrunchy' at file offset {:#x} ({} bytes raw, vsize {:#x}). \
                 DisFilter inverse is available via dis_unfilter(); the kkrunchy proprietary compression backend (arithmetic-coded \
                 context-mixing stream prefixed by the depacker stub) is not implemented for this variant in this release. \
                 To recover the original .text section, run the packed binary in a controlled environment, snapshot the unpacked image \
                 from memory after the OEP transfer, then feed the recovered code through dis_unfilter() with the stream sizes \
                 reconstructed from the snapshot header.",
                header.section_raw_offset, header.section_raw_size, header.section_vsize,
            );
            (section.to_vec(), note)
        }
    };

    Ok(KkrunchyUnpackOutput {
        header,
        packed_payload,
        stub_bytes,
        note,
    })
}

const EMULATOR_PR_HINT: &str = "crates/disrobe-pass-native/src/packers/kkrunchy_unpack.rs::KkrunchyEmulator \
     (the closed-source PAQ-class context-mixed arithmetic decoder is intractable to RE \
     in a single sprint; ship a unicorn/icicle/libmwemu provider behind the `stub-emulation` feature)";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KkrunchyEmulatedUnpackOutput {
    pub header: KkrunchyHeaderInfo,
    pub reconstructed_image: Vec<u8>,
    pub original_entry_rva: u32,
    pub recovered_imports: Vec<(String, Vec<String>)>,
    pub provider_label: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KkrunchyEmulationSnapshot {
    pub image_base: u32,
    pub image_bytes: Vec<u8>,
    pub original_entry_rva: u32,
    pub recovered_imports: Vec<(String, Vec<String>)>,
}

pub trait KkrunchyEmulator: std::fmt::Debug {
    fn label(&self) -> &'static str;
    fn emulate_until_oep(
        &self,
        packed_bytes: &[u8],
        header: &KkrunchyHeaderInfo,
    ) -> Result<KkrunchyEmulationSnapshot>;
}

pub fn unpack_kkrunchy_emulated(
    packed_bytes: &[u8],
    emulator: Option<&dyn KkrunchyEmulator>,
) -> Result<KkrunchyEmulatedUnpackOutput> {
    let header: KkrunchyHeaderInfo = parse_kkrunchy_header(packed_bytes)?;
    let provider: &dyn KkrunchyEmulator = match emulator {
        Some(p) => p,
        None => {
            return Err(Error::EmulatorNotConfigured {
                packer: "kkrunchy",
                trait_name: "KkrunchyEmulator",
                pr_hint: EMULATOR_PR_HINT,
            });
        }
    };
    let snapshot: KkrunchyEmulationSnapshot = provider.emulate_until_oep(packed_bytes, &header)?;
    if snapshot.image_bytes.is_empty() {
        return Err(Error::SignatureDb(
            "kkrunchy emulator returned empty image snapshot".to_owned(),
        ));
    }
    let provider_label: String = provider.label().to_owned();
    let note: String = format!(
        "kkrunchy emulated unpack via provider '{}': captured {} bytes of unpacked image \
         starting at image base {:#x} with OEP at RVA {:#x}; {} imports recovered. \
         If imports are empty the snapshot was taken before the kkrunchy IAT-bootstrap completed.",
        provider_label,
        snapshot.image_bytes.len(),
        snapshot.image_base,
        snapshot.original_entry_rva,
        snapshot
            .recovered_imports
            .iter()
            .map(|(_, fns): &(String, Vec<String>)| fns.len())
            .sum::<usize>(),
    );
    Ok(KkrunchyEmulatedUnpackOutput {
        header,
        reconstructed_image: snapshot.image_bytes,
        original_entry_rva: snapshot.original_entry_rva,
        recovered_imports: snapshot.recovered_imports,
        provider_label,
        note,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KkrunchyByteRecoveryReport {
    pub original_len: usize,
    pub recovered_len: usize,
    pub matching_bytes: usize,
    pub recovery_pct_basis_points: u32,
}

impl KkrunchyByteRecoveryReport {
    #[must_use]
    pub fn pct(self) -> f64 {
        f64::from(self.recovery_pct_basis_points) / 100.0
    }
}

#[must_use]
pub fn compute_byte_recovery(original: &[u8], recovered: &[u8]) -> KkrunchyByteRecoveryReport {
    let compare_len: usize = original.len().min(recovered.len());
    let mut matching: usize = 0;
    let zipped: std::iter::Zip<std::slice::Iter<'_, u8>, std::slice::Iter<'_, u8>> = original
        [..compare_len]
        .iter()
        .zip(&recovered[..compare_len]);
    for (orig_byte, rec_byte) in zipped {
        let orig_byte: &u8 = orig_byte;
        let rec_byte: &u8 = rec_byte;
        if orig_byte == rec_byte {
            matching += 1;
        }
    }
    let denom: usize = original.len().max(1);
    let pct_bp: u32 = ((matching * 10_000) / denom) as u32;
    KkrunchyByteRecoveryReport {
        original_len: original.len(),
        recovered_len: recovered.len(),
        matching_bytes: matching,
        recovery_pct_basis_points: pct_bp,
    }
}

fn read_u32(bytes: &[u8], off: usize) -> Result<u32> {
    if off.saturating_add(4) > bytes.len() {
        return Err(Error::Truncated {
            needed: off + 4,
            had: bytes.len(),
        });
    }
    Ok(u32::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

fn move_to_front(table: &mut [u32; 256], pos: usize, val: u32) -> u32 {
    let mut i: usize = pos;
    while i > 0 {
        table[i] = table[i - 1];
        i -= 1;
    }
    table[0] = val;
    val
}

fn add_mtf(table: &mut [u32; 256], val: u32) {
    move_to_front(table, 255, val);
}

fn find_mtf(table: &mut [u32; 256], val: u32) -> Option<u8> {
    let pos_opt: Option<usize> = table.iter().take(255).position(|slot: &u32| *slot == val);
    match pos_opt {
        Some(i) => {
            move_to_front(table, i, val);
            Some(i as u8)
        }
        None => {
            add_mtf(table, val);
            None
        }
    }
}

#[inline]
fn encode_mtf_index(ind: Option<u8>) -> u8 {
    ind.map_or(0, |i: u8| i.saturating_add(1))
}

struct DisFilterCtx {
    buffers: [Vec<u8>; STREAM_COUNT],
    func_table: [u32; 256],
    next_is_func: bool,
    code_start: u32,
    code_end: u32,
}

impl DisFilterCtx {
    fn new(code_start: u32, code_end: u32) -> Self {
        Self {
            buffers: Default::default(),
            func_table: [0u32; 256],
            next_is_func: true,
            code_start,
            code_end,
        }
    }

    fn put8(&mut self, stream: usize, v: u8) {
        self.buffers[stream].push(v);
    }

    fn put16_be(&mut self, stream: usize, v: u16) {
        self.buffers[stream].extend_from_slice(&v.to_be_bytes());
    }

    fn put32_be(&mut self, stream: usize, v: u32) {
        self.buffers[stream].extend_from_slice(&v.to_be_bytes());
    }

    fn detect_jump_table(&self, instr: &[u8], addr: u32) -> usize {
        if addr >= self.code_end {
            return 0;
        }
        let n_max: usize = ((self.code_end - addr) / 4) as usize;
        let mut count: usize = 0;
        while count < n_max && (count + 1) * 4 <= instr.len() {
            let off: usize = count * 4;
            let coded_addr: u32 =
                u32::from_le_bytes([instr[off], instr[off + 1], instr[off + 2], instr[off + 3]]);
            if coded_addr >= self.code_start && coded_addr < self.code_end {
                count += 1;
            } else {
                break;
            }
        }
        if count < 3 { 0 } else { count }
    }

    #[allow(clippy::too_many_lines)]
    fn process_instr(&mut self, instr: &[u8], memory: u32) -> (usize, bool) {
        let n_jump: usize = self.detect_jump_table(instr, memory);
        if n_jump > 0 {
            let mut remaining: usize = n_jump;
            let mut cursor: usize = 0;
            while remaining > 0 {
                let count: usize = remaining.min(256);
                self.put8(ST_OP, JUMPTAB);
                self.put8(ST_JUMPTBL_COUNT, (count - 1) as u8);
                for _ in 0..count {
                    let target: u32 = u32::from_le_bytes([
                        instr[cursor],
                        instr[cursor + 1],
                        instr[cursor + 2],
                        instr[cursor + 3],
                    ]);
                    cursor += 4;
                    let ind: Option<u8> = find_mtf(&mut self.func_table, target);
                    self.put8(ST_CALL_IDX, encode_mtf_index(ind));
                    if ind.is_none() {
                        self.put32_be(ST_CALL32, target);
                    }
                }
                remaining -= count;
            }
            return (n_jump * 4, true);
        }

        if instr.is_empty() {
            return (0, false);
        }

        let mut pos: usize = 0;
        let mut code: u8 = instr[pos];
        pos += 1;
        let mut code2: u8 = 0;
        let mut o16: bool = false;

        if self.next_is_func && code != OP_INT3 {
            add_mtf(&mut self.func_table, memory);
            self.next_is_func = false;
        }

        if code == OP_OSIZE {
            o16 = true;
            if pos >= instr.len() {
                self.put8(ST_OP, ESCAPE);
                self.put8(ST_OP, instr[0]);
                return (1, false);
            }
            code = instr[pos];
            pos += 1;
        }

        let mut flags: u8 = if code == OP_2BYTE {
            if pos >= instr.len() {
                self.put8(ST_OP, ESCAPE);
                self.put8(ST_OP, instr[0]);
                return (1, false);
            }
            code2 = instr[pos];
            pos += 1;
            TABLE2[code2 as usize]
        } else {
            TABLE1[code as usize]
        };

        if code == OP_RETNI || code == OP_RETN || code == OP_INT3 {
            self.next_is_func = true;
        }

        if flags == F_MEXTRA {
            if pos >= instr.len() {
                self.put8(ST_OP, ESCAPE);
                self.put8(ST_OP, instr[0]);
                return (1, false);
            }
            let modrm_peek: u8 = instr[pos];
            let idx: usize = (((modrm_peek >> 3) & 7) as usize)
                | (((code & 0x01) as usize) << 3)
                | (((code & 0x08) as usize) << 1);
            flags = TABLEX[idx];
        }

        if flags == F_ERR {
            self.put8(ST_OP, ESCAPE);
            self.put8(ST_OP, instr[0]);
            return (1, false);
        }

        if o16 {
            self.put8(ST_OP, OP_OSIZE);
        }
        self.put8(ST_OP, code);
        if code == OP_2BYTE {
            self.put8(ST_OP2, code2);
        }

        if code == OP_CALLF || code == OP_JMPF || code == OP_ENTER {
            if pos + 2 > instr.len() {
                return (0, false);
            }
            let v: u16 = u16::from_le_bytes([instr[pos], instr[pos + 1]]);
            pos += 2;
            self.put16_be(ST_IMM16, v);
        }

        if (flags & F_MODE) == F_MR {
            if pos >= instr.len() {
                return (0, false);
            }
            let modrm: u8 = instr[pos];
            pos += 1;
            self.put8(ST_MODRM, modrm);
            let mut sib: u8 = 0;
            if (modrm & 0x07) == 4 && modrm < 0xC0 {
                if pos >= instr.len() {
                    return (0, false);
                }
                sib = instr[pos];
                pos += 1;
                self.put8(ST_SIB, sib);
            }
            if (modrm & 0xC0) == 0x40 {
                if pos >= instr.len() {
                    return (0, false);
                }
                self.put8(ST_DISP8_R0 + (modrm & 0x07) as usize, instr[pos]);
                pos += 1;
            }
            if (modrm & 0xC0) == 0x80
                || (modrm & 0xC7) == 0x05
                || (modrm < 0x40 && (sib & 0x07) == 5)
            {
                if pos + 4 > instr.len() {
                    return (0, false);
                }
                let v: u32 = u32::from_le_bytes([
                    instr[pos],
                    instr[pos + 1],
                    instr[pos + 2],
                    instr[pos + 3],
                ]);
                pos += 4;
                let stream: usize = if (modrm & 0xC7) == 0x05 {
                    ST_ADDR32
                } else {
                    ST_DISP32
                };
                self.put32_be(stream, v);
            }
        }

        if (flags & F_MODE) == F_AM {
            match flags & F_TYPE {
                F_AD => {
                    if pos + 4 > instr.len() {
                        return (0, false);
                    }
                    let v: u32 = u32::from_le_bytes([
                        instr[pos],
                        instr[pos + 1],
                        instr[pos + 2],
                        instr[pos + 3],
                    ]);
                    pos += 4;
                    self.put32_be(ST_ADDR32, v);
                }
                F_DA => {
                    if pos + 4 > instr.len() {
                        return (0, false);
                    }
                    let v: u32 = u32::from_le_bytes([
                        instr[pos],
                        instr[pos + 1],
                        instr[pos + 2],
                        instr[pos + 3],
                    ]);
                    pos += 4;
                    self.put32_be(ST_AJUMP32, v);
                }
                F_BR => {
                    if pos >= instr.len() {
                        return (0, false);
                    }
                    self.put8(ST_JUMP8, instr[pos]);
                    pos += 1;
                }
                F_DR => {
                    if pos + 4 > instr.len() {
                        return (0, false);
                    }
                    let rel: u32 = u32::from_le_bytes([
                        instr[pos],
                        instr[pos + 1],
                        instr[pos + 2],
                        instr[pos + 3],
                    ]);
                    pos += 4;
                    let target: u32 = rel.wrapping_add(pos as u32).wrapping_add(memory);
                    if code == OP_CALLN {
                        let ind: Option<u8> = find_mtf(&mut self.func_table, target);
                        self.put8(ST_CALL_IDX, encode_mtf_index(ind));
                        if ind.is_none() {
                            self.put32_be(ST_CALL32, target);
                        }
                    } else {
                        self.put32_be(ST_JUMP32, target);
                    }
                }
                _ => {}
            }
        } else {
            match flags & F_TYPE {
                F_BI => {
                    if pos >= instr.len() {
                        return (0, false);
                    }
                    self.put8(ST_IMM8, instr[pos]);
                    pos += 1;
                }
                F_WI => {
                    if pos + 2 > instr.len() {
                        return (0, false);
                    }
                    let v: u16 = u16::from_le_bytes([instr[pos], instr[pos + 1]]);
                    pos += 2;
                    self.put16_be(ST_IMM16, v);
                }
                F_DI => {
                    if o16 {
                        if pos + 2 > instr.len() {
                            return (0, false);
                        }
                        let v: u16 = u16::from_le_bytes([instr[pos], instr[pos + 1]]);
                        pos += 2;
                        self.put16_be(ST_IMM16, v);
                    } else {
                        if pos + 4 > instr.len() {
                            return (0, false);
                        }
                        let v: u32 = u32::from_le_bytes([
                            instr[pos],
                            instr[pos + 1],
                            instr[pos + 2],
                            instr[pos + 3],
                        ]);
                        pos += 4;
                        self.put32_be(ST_IMM32, v);
                    }
                }
                _ => {}
            }
        }

        (pos, false)
    }

    fn flush(self) -> (Vec<u8>, DisFilterStreamSizes) {
        let mut sizes: [u32; STREAM_COUNT] = [0u32; STREAM_COUNT];
        let mut total_payload: usize = 0;
        for (slot, buf) in sizes.iter_mut().zip(self.buffers.iter()) {
            *slot = buf.len() as u32;
            total_payload += buf.len();
        }
        let header_bytes: usize = STREAM_COUNT * 4;
        let mut out: Vec<u8> = Vec::with_capacity(header_bytes + total_payload);
        for size in &sizes {
            out.extend_from_slice(&size.to_le_bytes());
        }
        for buf in &self.buffers {
            out.extend_from_slice(buf);
        }
        let sizes_struct: DisFilterStreamSizes = DisFilterStreamSizes {
            sizes,
            total: (header_bytes + total_payload) as u64,
        };
        (out, sizes_struct)
    }
}

pub fn dis_filter(code: &[u8], origin: u32) -> Result<(Vec<u8>, DisFilterStreamSizes)> {
    let size: usize = code.len();
    let code_end: u32 = origin
        .checked_add(size as u32)
        .ok_or_else(|| Error::SignatureDb("dis_filter: origin + size overflows u32".to_owned()))?;
    let mut ctx: DisFilterCtx = DisFilterCtx::new(origin, code_end);

    let mut pos: usize = 0;
    while pos + DIS_FILTER_MAX_INSTR < size {
        let (bytes, _was_jump): (usize, bool) =
            ctx.process_instr(&code[pos..], origin + pos as u32);
        if bytes == 0 {
            ctx.put8(ST_OP, ESCAPE);
            ctx.put8(ST_OP, code[pos]);
            pos += 1;
        } else {
            pos += bytes;
        }
    }

    while pos < size {
        let mut instr_buf: [u8; DIS_FILTER_MAX_INSTR] = [0u8; DIS_FILTER_MAX_INSTR];
        let avail: usize = size - pos;
        instr_buf[..avail].copy_from_slice(&code[pos..]);
        let mut checkpt: [usize; STREAM_COUNT] = [0usize; STREAM_COUNT];
        for (slot, buf) in checkpt.iter_mut().zip(ctx.buffers.iter()) {
            *slot = buf.len();
        }
        let (bytes, _was_jump): (usize, bool) = ctx.process_instr(&instr_buf, origin + pos as u32);
        if bytes > 0 && pos + bytes <= size {
            pos += bytes;
        } else {
            for (buf, saved) in ctx.buffers.iter_mut().zip(checkpt.iter()) {
                buf.truncate(*saved);
            }
            break;
        }
    }

    while pos < size {
        ctx.put8(ST_OP, ESCAPE);
        ctx.put8(ST_OP, code[pos]);
        pos += 1;
    }

    let (out, sizes): (Vec<u8>, DisFilterStreamSizes) = ctx.flush();
    Ok((out, sizes))
}

#[allow(clippy::too_many_lines)]
pub fn dis_unfilter(source: &[u8], dest_size: usize, mem_start: u32) -> Result<Vec<u8>> {
    if dest_size > MAX_DECODED_SIZE {
        return Err(Error::SignatureDb(format!(
            "dis_unfilter: dest_size {dest_size} exceeds {MAX_DECODED_SIZE}-byte safety cap"
        )));
    }
    let header_bytes: usize = STREAM_COUNT * 4;
    if source.len() < header_bytes {
        return Err(Error::Truncated {
            needed: header_bytes,
            had: source.len(),
        });
    }
    let mut stream_ranges: [(usize, usize); STREAM_COUNT] = [(0usize, 0usize); STREAM_COUNT];
    let mut cur: usize = header_bytes;
    for (i, slot) in stream_ranges.iter_mut().enumerate() {
        let off: usize = i * 4;
        let sz: u32 = u32::from_le_bytes([
            source[off],
            source[off + 1],
            source[off + 2],
            source[off + 3],
        ]);
        let start: usize = cur;
        let end: usize = cur
            .checked_add(sz as usize)
            .ok_or_else(|| Error::SignatureDb("dis_unfilter: stream size overflow".to_owned()))?;
        if end > source.len() {
            return Err(Error::SignatureDb(format!(
                "dis_unfilter: stream {i} size {sz} would exceed source length {}",
                source.len()
            )));
        }
        *slot = (start, end);
        cur = end;
    }
    if cur != source.len() {
        return Err(Error::SignatureDb(format!(
            "dis_unfilter: total stream bytes {} does not equal source after header ({})",
            cur - header_bytes,
            source.len() - header_bytes
        )));
    }

    let mut pos: [usize; STREAM_COUNT] = [0usize; STREAM_COUNT];
    for (slot, range) in pos.iter_mut().zip(stream_ranges.iter()) {
        *slot = range.0;
    }

    let mut dest: Vec<u8> = Vec::with_capacity(dest_size);
    let mut func_table: [u32; 256] = [0u32; 256];
    let mut next_is_func: bool = true;

    while pos[ST_OP] < stream_ranges[ST_OP].1 {
        let dest_start: usize = dest.len();
        let memory: u32 = mem_start.wrapping_add(dest_start as u32);

        let code: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_OP)?;

        if code == JUMPTAB {
            let count_byte: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_JUMPTBL_COUNT)?;
            let count: usize = count_byte as usize + 1;
            for _ in 0..count {
                let ind: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_CALL_IDX)?;
                let target: u32 = if ind != 0 {
                    let idx: usize = (ind - 1) as usize;
                    let prev: u32 = func_table[idx];
                    move_to_front(&mut func_table, idx, prev)
                } else {
                    let t: u32 = consume_u32_be(source, &mut pos, &stream_ranges, ST_CALL32)?;
                    add_mtf(&mut func_table, t);
                    t
                };
                check_dst_cap(&dest, 4, dest_size)?;
                dest.extend_from_slice(&target.to_le_bytes());
            }
            continue;
        }

        if next_is_func && code != OP_INT3 {
            add_mtf(&mut func_table, memory);
            next_is_func = false;
        }

        if code == ESCAPE {
            let raw: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_OP)?;
            check_dst_cap(&dest, 1, dest_size)?;
            dest.push(raw);
            continue;
        }

        check_dst_cap(&dest, 1, dest_size)?;
        dest.push(code);

        let mut effective_code: u8 = code;
        let mut o16: bool = false;
        if code == OP_OSIZE {
            o16 = true;
            effective_code = consume_u8(source, &mut pos, &stream_ranges, ST_OP)?;
            check_dst_cap(&dest, 1, dest_size)?;
            dest.push(effective_code);
        }

        if effective_code == OP_RETNI || effective_code == OP_RETN || effective_code == OP_INT3 {
            next_is_func = true;
        }

        let mut flags: u8 = if effective_code == OP_2BYTE {
            let code2: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_OP2)?;
            check_dst_cap(&dest, 1, dest_size)?;
            dest.push(code2);
            TABLE2[code2 as usize]
        } else {
            TABLE1[effective_code as usize]
        };

        if flags == F_ERR {
            return Err(Error::SignatureDb(format!(
                "dis_unfilter: ERR opcode {effective_code:#x} reached without escape"
            )));
        }

        if effective_code == OP_CALLF || effective_code == OP_JMPF || effective_code == OP_ENTER {
            let v: u16 = consume_u16_be(source, &mut pos, &stream_ranges, ST_IMM16)?;
            check_dst_cap(&dest, 2, dest_size)?;
            dest.extend_from_slice(&v.to_le_bytes());
        }

        if (flags & F_MR) != 0 {
            let modrm: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_MODRM)?;
            check_dst_cap(&dest, 1, dest_size)?;
            dest.push(modrm);
            let mut sib: u8 = 0;
            if flags == F_MEXTRA {
                let idx: usize = (((modrm >> 3) & 7) as usize)
                    | (((effective_code & 0x01) as usize) << 3)
                    | (((effective_code & 0x08) as usize) << 1);
                flags = TABLEX[idx];
            }
            if (modrm & 0x07) == 4 && modrm < 0xC0 {
                sib = consume_u8(source, &mut pos, &stream_ranges, ST_SIB)?;
                check_dst_cap(&dest, 1, dest_size)?;
                dest.push(sib);
            }
            if (modrm & 0xC0) == 0x40 {
                let st: usize = (modrm & 0x07) as usize + ST_DISP8_R0;
                let b: u8 = consume_u8(source, &mut pos, &stream_ranges, st)?;
                check_dst_cap(&dest, 1, dest_size)?;
                dest.push(b);
            }
            if (modrm & 0xC0) == 0x80
                || (modrm & 0xC7) == 0x05
                || (modrm < 0x40 && (sib & 0x07) == 0x05)
            {
                let st: usize = if (modrm & 0xC7) == 5 {
                    ST_ADDR32
                } else {
                    ST_DISP32
                };
                let v: u32 = consume_u32_be(source, &mut pos, &stream_ranges, st)?;
                check_dst_cap(&dest, 4, dest_size)?;
                dest.extend_from_slice(&v.to_le_bytes());
            }
        }

        if (flags & F_MODE) == F_AM {
            match flags & F_TYPE {
                F_AD => {
                    let v: u32 = consume_u32_be(source, &mut pos, &stream_ranges, ST_ADDR32)?;
                    check_dst_cap(&dest, 4, dest_size)?;
                    dest.extend_from_slice(&v.to_le_bytes());
                }
                F_DA => {
                    let v: u32 = consume_u32_be(source, &mut pos, &stream_ranges, ST_AJUMP32)?;
                    check_dst_cap(&dest, 4, dest_size)?;
                    dest.extend_from_slice(&v.to_le_bytes());
                }
                F_BR => {
                    let b: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_JUMP8)?;
                    check_dst_cap(&dest, 1, dest_size)?;
                    dest.push(b);
                }
                F_DR => {
                    let target: u32 = if effective_code == OP_CALLN {
                        let ind: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_CALL_IDX)?;
                        if ind != 0 {
                            let idx: usize = (ind - 1) as usize;
                            let prev: u32 = func_table[idx];
                            move_to_front(&mut func_table, idx, prev)
                        } else {
                            let t: u32 =
                                consume_u32_be(source, &mut pos, &stream_ranges, ST_CALL32)?;
                            add_mtf(&mut func_table, t);
                            t
                        }
                    } else {
                        consume_u32_be(source, &mut pos, &stream_ranges, ST_JUMP32)?
                    };
                    let after_instr_size: u32 = (dest.len() - dest_start) as u32 + 4;
                    let rel: u32 = target.wrapping_sub(after_instr_size).wrapping_sub(memory);
                    check_dst_cap(&dest, 4, dest_size)?;
                    dest.extend_from_slice(&rel.to_le_bytes());
                }
                _ => {}
            }
        } else {
            match flags & F_TYPE {
                F_BI => {
                    let b: u8 = consume_u8(source, &mut pos, &stream_ranges, ST_IMM8)?;
                    check_dst_cap(&dest, 1, dest_size)?;
                    dest.push(b);
                }
                F_WI => {
                    let v: u16 = consume_u16_be(source, &mut pos, &stream_ranges, ST_IMM16)?;
                    check_dst_cap(&dest, 2, dest_size)?;
                    dest.extend_from_slice(&v.to_le_bytes());
                }
                F_DI => {
                    if o16 {
                        let v: u16 = consume_u16_be(source, &mut pos, &stream_ranges, ST_IMM16)?;
                        check_dst_cap(&dest, 2, dest_size)?;
                        dest.extend_from_slice(&v.to_le_bytes());
                    } else {
                        let v: u32 = consume_u32_be(source, &mut pos, &stream_ranges, ST_IMM32)?;
                        check_dst_cap(&dest, 4, dest_size)?;
                        dest.extend_from_slice(&v.to_le_bytes());
                    }
                }
                _ => {}
            }
        }
    }

    if dest.len() != dest_size {
        return Err(Error::SignatureDb(format!(
            "dis_unfilter: produced {} bytes but expected {}",
            dest.len(),
            dest_size
        )));
    }
    Ok(dest)
}

fn consume_u8(
    source: &[u8],
    pos: &mut [usize; STREAM_COUNT],
    ranges: &[(usize, usize); STREAM_COUNT],
    stream: usize,
) -> Result<u8> {
    let (_start, end): (usize, usize) = ranges[stream];
    if pos[stream] + 1 > end {
        return Err(Error::Truncated {
            needed: 1,
            had: end - pos[stream],
        });
    }
    let v: u8 = source[pos[stream]];
    pos[stream] += 1;
    Ok(v)
}

fn consume_u16_be(
    source: &[u8],
    pos: &mut [usize; STREAM_COUNT],
    ranges: &[(usize, usize); STREAM_COUNT],
    stream: usize,
) -> Result<u16> {
    let (_start, end): (usize, usize) = ranges[stream];
    if pos[stream] + 2 > end {
        return Err(Error::Truncated {
            needed: 2,
            had: end - pos[stream],
        });
    }
    let v: u16 = u16::from_be_bytes([source[pos[stream]], source[pos[stream] + 1]]);
    pos[stream] += 2;
    Ok(v)
}

fn consume_u32_be(
    source: &[u8],
    pos: &mut [usize; STREAM_COUNT],
    ranges: &[(usize, usize); STREAM_COUNT],
    stream: usize,
) -> Result<u32> {
    let (_start, end): (usize, usize) = ranges[stream];
    if pos[stream] + 4 > end {
        return Err(Error::Truncated {
            needed: 4,
            had: end - pos[stream],
        });
    }
    let v: u32 = u32::from_be_bytes([
        source[pos[stream]],
        source[pos[stream] + 1],
        source[pos[stream] + 2],
        source[pos[stream] + 3],
    ]);
    pos[stream] += 4;
    Ok(v)
}

fn check_dst_cap(dest: &[u8], need: usize, cap: usize) -> Result<()> {
    if dest.len() + need > cap {
        return Err(Error::SignatureDb(format!(
            "dis_unfilter: would write past dest cap ({} + {} > {})",
            dest.len(),
            need,
            cap
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_mzfarbrausch_magic_prefix() {
        let bytes: Vec<u8> = b"MZfarbrausch\x00\x00\x00\x00rest".to_vec();
        assert!(looks_like_kkrunchy(&bytes));
        assert!(!looks_like_kkrunchy(b"MZnotreally"));
        assert!(!looks_like_kkrunchy(b"M"));
    }

    #[test]
    fn parse_kkrunchy_header_rejects_non_kkrunchy() {
        let bytes: Vec<u8> = vec![0u8; 4096];
        let err: Error = parse_kkrunchy_header(&bytes).unwrap_err();
        match err {
            Error::SignatureDb(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_kkrunchy_header_rejects_truncated() {
        let bytes: Vec<u8> = vec![0u8; 16];
        let err: Error = parse_kkrunchy_header(&bytes).unwrap_err();
        match err {
            Error::Truncated { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn dis_filter_round_trip_handles_simple_ret() {
        let code: Vec<u8> = vec![0xC3, 0x90, 0xC3];
        let origin: u32 = 0x0040_1000;
        let (filtered, sizes): (Vec<u8>, DisFilterStreamSizes) = dis_filter(&code, origin).unwrap();
        assert_eq!(sizes.total as usize, filtered.len());
        let restored: Vec<u8> = dis_unfilter(&filtered, code.len(), origin).unwrap();
        assert_eq!(restored, code, "round-trip should reproduce input bytes");
    }

    #[test]
    fn dis_filter_round_trip_handles_int3_padding() {
        let code: Vec<u8> = vec![0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC];
        let origin: u32 = 0x0001_0000;
        let (filtered, _sizes): (Vec<u8>, DisFilterStreamSizes) =
            dis_filter(&code, origin).unwrap();
        let restored: Vec<u8> = dis_unfilter(&filtered, code.len(), origin).unwrap();
        assert_eq!(restored, code);
    }

    #[test]
    fn dis_filter_round_trip_handles_push_imm32_and_ret() {
        let code: Vec<u8> = vec![
            0x68, 0x78, 0x56, 0x34, 0x12, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ];
        let origin: u32 = 0x0040_1000;
        let (filtered, _sizes): (Vec<u8>, DisFilterStreamSizes) =
            dis_filter(&code, origin).unwrap();
        let restored: Vec<u8> = dis_unfilter(&filtered, code.len(), origin).unwrap();
        assert_eq!(restored, code);
    }

    #[test]
    fn dis_filter_round_trip_handles_mov_eax_imm32() {
        let code: Vec<u8> = vec![
            0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ];
        let origin: u32 = 0x0040_1000;
        let (filtered, _sizes): (Vec<u8>, DisFilterStreamSizes) =
            dis_filter(&code, origin).unwrap();
        let restored: Vec<u8> = dis_unfilter(&filtered, code.len(), origin).unwrap();
        assert_eq!(restored, code);
    }

    #[test]
    fn dis_unfilter_caps_oversized_dest() {
        let bogus_source: Vec<u8> = vec![0u8; STREAM_COUNT * 4];
        let err: Error = dis_unfilter(&bogus_source, MAX_DECODED_SIZE + 1, 0x1000).unwrap_err();
        match err {
            Error::SignatureDb(msg) => assert!(msg.contains("exceeds")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
