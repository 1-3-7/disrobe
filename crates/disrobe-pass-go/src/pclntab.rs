use crate::binary::{Endian, GoImage};
use crate::error::{Error, Result};

pub const MAGIC_GO12: u32 = 0xffff_fffb;
pub const MAGIC_GO116: u32 = 0xffff_fffa;
pub const MAGIC_GO118: u32 = 0xffff_fff0;
pub const MAGIC_GO120: u32 = 0xffff_fff1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum PclntabVersion {
    Go12,
    Go116,
    Go118,
    Go120,
}

impl PclntabVersion {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Go12 => "go1.2..go1.15",
            Self::Go116 => "go1.16..go1.17",
            Self::Go118 => "go1.18..go1.19",
            Self::Go120 => "go1.20..go1.25",
        }
    }

    pub const fn from_magic(magic: u32) -> Result<Self> {
        Ok(match magic {
            MAGIC_GO12 => Self::Go12,
            MAGIC_GO116 => Self::Go116,
            MAGIC_GO118 => Self::Go118,
            MAGIC_GO120 => Self::Go120,
            other => return Err(Error::PclntabMagic { magic: other }),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PclntabHeader {
    pub version: PclntabVersion,
    pub quantum: u8,
    pub ptr_size: u8,
    pub endian: Endian,
    pub n_funcs: u64,
    pub n_files: u64,
    pub text_start: u64,
    pub funcname_off: u64,
    pub cu_off: u64,
    pub filetab_off: u64,
    pub pctab_off: u64,
    pub funcdata_off: u64,
    pub section_addr: u64,
    pub section_len: usize,
}

#[derive(Debug, Clone)]
pub struct LocatedPclntab<'a> {
    pub header: PclntabHeader,
    pub data: &'a [u8],
}

pub fn locate_pclntab<'a>(image: &GoImage<'a>) -> Result<LocatedPclntab<'a>> {
    let candidates: Vec<&'static [u8]> = vec![
        &[0xfb, 0xff, 0xff, 0xff],
        &[0xfa, 0xff, 0xff, 0xff],
        &[0xf0, 0xff, 0xff, 0xff],
        &[0xf1, 0xff, 0xff, 0xff],
    ];
    for sec in &image.sections {
        if sec.data.len() < 16 {
            continue;
        }
        for needle in &candidates {
            if let Some(pos) = find_aligned(sec.data, needle, 16)
                && pos + 16 <= sec.data.len()
            {
                let zero_ok: bool = sec.data[pos + 4] == 0 && sec.data[pos + 5] == 0;
                if !zero_ok {
                    continue;
                }
                let quantum: u8 = sec.data[pos + 6];
                let ptr_size: u8 = sec.data[pos + 7];
                if !matches!(quantum, 1 | 2 | 4) {
                    continue;
                }
                if !matches!(ptr_size, 4 | 8) {
                    continue;
                }
                let body: &[u8] = &sec.data[pos..];
                let header: PclntabHeader =
                    parse_header(body, sec.address + pos as u64, image.endian)?;
                return Ok(LocatedPclntab { header, data: body });
            }
        }
    }
    Err(Error::PclntabMissing)
}

fn find_aligned(haystack: &[u8], needle: &[u8], align: usize) -> Option<usize> {
    let mut i: usize = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += align;
    }
    let mut j: usize = 0;
    while j + needle.len() <= haystack.len() {
        if &haystack[j..j + needle.len()] == needle {
            return Some(j);
        }
        j += 1;
    }
    None
}

fn parse_header(body: &[u8], section_addr: u64, endian: Endian) -> Result<PclntabHeader> {
    let magic: u32 = read_u32(body, 0, endian)?;
    let version: PclntabVersion = PclntabVersion::from_magic(magic)?;
    let quantum: u8 = read_u8(body, 6)?;
    let ptr_size: u8 = read_u8(body, 7)?;
    if quantum == 0 || ptr_size == 0 {
        return Err(Error::PclntabInvariant("zero quantum/ptr_size"));
    }
    let ps: usize = ptr_size as usize;
    let read_word = |off: usize| -> Result<u64> {
        if ptr_size == 4 {
            Ok(u64::from(read_u32(body, off, endian)?))
        } else {
            read_u64(body, off, endian)
        }
    };

    let header: PclntabHeader = match version {
        PclntabVersion::Go12 => {
            let n_funcs: u64 = read_word(8)?;
            PclntabHeader {
                version,
                quantum,
                ptr_size,
                endian,
                n_funcs,
                n_files: 0,
                text_start: 0,
                funcname_off: 0,
                cu_off: 0,
                filetab_off: 0,
                pctab_off: 0,
                funcdata_off: 0,
                section_addr,
                section_len: body.len(),
            }
        }
        PclntabVersion::Go116 => {
            let n_funcs: u64 = read_word(8)?;
            let n_files: u64 = read_word(8 + ps)?;
            let funcname_off: u64 = read_word(8 + 2 * ps)?;
            let cu_off: u64 = read_word(8 + 3 * ps)?;
            let filetab_off: u64 = read_word(8 + 4 * ps)?;
            let pctab_off: u64 = read_word(8 + 5 * ps)?;
            let funcdata_off: u64 = read_word(8 + 6 * ps)?;
            PclntabHeader {
                version,
                quantum,
                ptr_size,
                endian,
                n_funcs,
                n_files,
                text_start: 0,
                funcname_off,
                cu_off,
                filetab_off,
                pctab_off,
                funcdata_off,
                section_addr,
                section_len: body.len(),
            }
        }
        PclntabVersion::Go118 | PclntabVersion::Go120 => {
            let n_funcs: u64 = read_word(8)?;
            let n_files: u64 = read_word(8 + ps)?;
            let text_start: u64 = read_word(8 + 2 * ps)?;
            let funcname_off: u64 = read_word(8 + 3 * ps)?;
            let cu_off: u64 = read_word(8 + 4 * ps)?;
            let filetab_off: u64 = read_word(8 + 5 * ps)?;
            let pctab_off: u64 = read_word(8 + 6 * ps)?;
            let funcdata_off: u64 = read_word(8 + 7 * ps)?;
            PclntabHeader {
                version,
                quantum,
                ptr_size,
                endian,
                n_funcs,
                n_files,
                text_start,
                funcname_off,
                cu_off,
                filetab_off,
                pctab_off,
                funcdata_off,
                section_addr,
                section_len: body.len(),
            }
        }
    };
    Ok(header)
}

pub(crate) fn read_u8(buf: &[u8], off: usize) -> Result<u8> {
    buf.get(off).copied().ok_or(Error::PclntabRead {
        offset: off,
        len: buf.len(),
    })
}

pub(crate) fn read_u32(buf: &[u8], off: usize, endian: Endian) -> Result<u32> {
    let slice: &[u8] = buf.get(off..off + 4).ok_or(Error::PclntabRead {
        offset: off,
        len: buf.len(),
    })?;
    let arr: [u8; 4] = slice.try_into().map_err(|_| Error::PclntabRead {
        offset: off,
        len: buf.len(),
    })?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(arr),
        Endian::Big => u32::from_be_bytes(arr),
    })
}

pub(crate) fn read_u64(buf: &[u8], off: usize, endian: Endian) -> Result<u64> {
    let slice: &[u8] = buf.get(off..off + 8).ok_or(Error::PclntabRead {
        offset: off,
        len: buf.len(),
    })?;
    let arr: [u8; 8] = slice.try_into().map_err(|_| Error::PclntabRead {
        offset: off,
        len: buf.len(),
    })?;
    Ok(match endian {
        Endian::Little => u64::from_le_bytes(arr),
        Endian::Big => u64::from_be_bytes(arr),
    })
}
