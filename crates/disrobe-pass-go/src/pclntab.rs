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
    #[must_use]
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

const fn magic_needle(magic: u32, endian: Endian) -> [u8; 4] {
    match endian {
        Endian::Little => magic.to_le_bytes(),
        Endian::Big => magic.to_be_bytes(),
    }
}

pub fn locate_pclntab<'a>(image: &GoImage<'a>) -> Result<LocatedPclntab<'a>> {
    let candidates: [[u8; 4]; 4] = [
        magic_needle(MAGIC_GO12, image.endian),
        magic_needle(MAGIC_GO116, image.endian),
        magic_needle(MAGIC_GO118, image.endian),
        magic_needle(MAGIC_GO120, image.endian),
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
    signature_scan_pclntab(image)
}

pub fn signature_scan_pclntab<'a>(image: &GoImage<'a>) -> Result<LocatedPclntab<'a>> {
    let magics: [u32; 4] = [MAGIC_GO12, MAGIC_GO116, MAGIC_GO118, MAGIC_GO120];
    let mut best: Option<(u64, LocatedPclntab<'a>)> = None;

    for sec in &image.sections {
        let data: &[u8] = sec.data;
        if data.len() < 64 {
            continue;
        }
        for magic in magics {
            let magic_bytes: [u8; 4] = magic_needle(magic, image.endian);
            let mut search: usize = 0;
            while let Some(rel) = find_subslice(&data[search..], &magic_bytes) {
                let pos: usize = search + rel;
                search = pos + 1;
                consider_candidate(image, sec.address, data, pos, magic, false, &mut best);
            }
        }
    }

    for sec in &image.sections {
        let data: &[u8] = sec.data;
        if data.len() < 64 {
            continue;
        }
        let mut pos: usize = 0;
        while pos + 16 <= data.len() {
            if data[pos + 4] == 0
                && data[pos + 5] == 0
                && matches!(data[pos + 6], 1 | 2 | 4)
                && matches!(data[pos + 7], 4 | 8)
            {
                for magic in magics {
                    consider_candidate(image, sec.address, data, pos, magic, true, &mut best);
                }
            }
            pos += SIG_SCAN_STEP;
        }
    }

    best.map(|(_, located): (u64, LocatedPclntab<'a>)| located)
        .ok_or(Error::PclntabMissing)
}

const SIG_SCAN_STEP: usize = 8;

fn consider_candidate<'a>(
    image: &GoImage<'a>,
    sec_addr: u64,
    data: &'a [u8],
    pos: usize,
    magic: u32,
    magic_stomped: bool,
    best: &mut Option<(u64, LocatedPclntab<'a>)>,
) {
    let Some(located): Option<LocatedPclntab<'a>> =
        try_structural_header(image, sec_addr, data, pos, magic, magic_stomped)
    else {
        return;
    };
    let score: u64 = score_resolvable_names(&located.header, located.data);
    if score < SIG_MIN_RESOLVED_NAMES {
        return;
    }
    if best.as_ref().is_none_or(|(s, _): &(u64, _)| score > *s) {
        *best = Some((score, located));
    }
}

fn try_structural_header<'a>(
    image: &GoImage<'a>,
    sec_addr: u64,
    data: &'a [u8],
    pos: usize,
    magic: u32,
    magic_stomped: bool,
) -> Option<LocatedPclntab<'a>> {
    let body: &[u8] = data.get(pos..)?;
    if body.len() < 16 {
        return None;
    }
    if !magic_stomped {
        let observed: u32 = read_u32(body, 0, image.endian).ok()?;
        if observed != magic {
            return None;
        }
    }
    if body[4] != 0 || body[5] != 0 {
        return None;
    }
    if !matches!(body[6], 1 | 2 | 4) || !matches!(body[7], 4 | 8) {
        return None;
    }
    let version: PclntabVersion = PclntabVersion::from_magic(magic).ok()?;
    let header: PclntabHeader =
        parse_header_with_version(body, sec_addr + pos as u64, image.endian, version)?;
    if !validate_header_structure(&header, body) {
        return None;
    }
    Some(LocatedPclntab { header, data: body })
}

const SIG_MIN_RESOLVED_NAMES: u64 = 8;
const SIG_NAME_SAMPLE: u64 = 64;

fn score_resolvable_names(header: &PclntabHeader, body: &[u8]) -> u64 {
    match header.version {
        PclntabVersion::Go12 => score_go12_names(header, body),
        PclntabVersion::Go116 => score_go116_names(header, body),
        PclntabVersion::Go118 | PclntabVersion::Go120 => score_go118_names(header, body),
    }
}

fn score_go12_names(header: &PclntabHeader, body: &[u8]) -> u64 {
    let ps: usize = header.ptr_size as usize;
    let tab_off: usize = 8 + ps;
    let stride: usize = 2 * ps;
    let n: u64 = header.n_funcs.min(SIG_NAME_SAMPLE);
    let mut hits: u64 = 0;
    for i in 0..n {
        let entry_off: usize = tab_off + (i as usize) * stride;
        let Some(funcoff): Option<u64> = read_word_opt(body, entry_off + ps, header) else {
            break;
        };
        let Ok(funcoff_us): core::result::Result<usize, _> = usize::try_from(funcoff) else {
            continue;
        };
        let nameoff_field: usize = funcoff_us.saturating_add(ps);
        let Ok(nameoff): core::result::Result<u32, _> =
            read_u32(body, nameoff_field, header.endian)
        else {
            continue;
        };
        if cstring_is_symbol(body, nameoff as usize) {
            hits += 1;
        }
    }
    hits
}

fn score_go116_names(header: &PclntabHeader, body: &[u8]) -> u64 {
    let ftab_off: usize = usize::try_from(header.filetab_off).unwrap_or(usize::MAX);
    let funcname_off: usize = usize::try_from(header.funcname_off).unwrap_or(usize::MAX);
    let funcdata_off: usize = usize::try_from(header.funcdata_off).unwrap_or(usize::MAX);
    let stride: usize = 2 * header.ptr_size as usize;
    let n: u64 = header.n_funcs.min(SIG_NAME_SAMPLE);
    let mut hits: u64 = 0;
    for i in 0..n {
        let pos: usize = ftab_off.saturating_add((i as usize) * stride);
        let Some(off_native): Option<u64> =
            read_word_opt(body, pos.saturating_add(header.ptr_size as usize), header)
        else {
            break;
        };
        let funcoff: usize = funcdata_off.saturating_add(off_native as usize);
        let nameoff_field: usize = funcoff.saturating_add(header.ptr_size as usize);
        let Ok(nameoff): core::result::Result<u32, _> =
            read_u32(body, nameoff_field, header.endian)
        else {
            continue;
        };
        if cstring_is_symbol(body, funcname_off.saturating_add(nameoff as usize)) {
            hits += 1;
        }
    }
    hits
}

fn score_go118_names(header: &PclntabHeader, body: &[u8]) -> u64 {
    let funcdata_off: usize = usize::try_from(header.funcdata_off).unwrap_or(usize::MAX);
    let funcname_off: usize = usize::try_from(header.funcname_off).unwrap_or(usize::MAX);
    let stride: usize = 8;
    let n: u64 = header.n_funcs.min(SIG_NAME_SAMPLE);
    let mut hits: u64 = 0;
    for i in 0..n {
        let pos: usize = funcdata_off.saturating_add((i as usize) * stride);
        let Ok(funcoff): core::result::Result<u32, _> =
            read_u32(body, pos.saturating_add(4), header.endian)
        else {
            break;
        };
        let func_struct_at: usize = funcdata_off.saturating_add(funcoff as usize);
        let Ok(nameoff): core::result::Result<u32, _> =
            read_u32(body, func_struct_at.saturating_add(4), header.endian)
        else {
            continue;
        };
        if cstring_is_symbol(body, funcname_off.saturating_add(nameoff as usize)) {
            hits += 1;
        }
    }
    hits
}

fn read_word_opt(buf: &[u8], off: usize, header: &PclntabHeader) -> Option<u64> {
    match header.ptr_size {
        4 => read_u32(buf, off, header.endian).ok().map(u64::from),
        8 => read_u64(buf, off, header.endian).ok(),
        _ => None,
    }
}

fn cstring_is_symbol(buf: &[u8], off: usize) -> bool {
    let Some(tail): Option<&[u8]> = buf.get(off..) else {
        return false;
    };
    let probe: &[u8] = &tail[..tail.len().min(256)];
    let nul: usize = probe
        .iter()
        .position(|b: &u8| *b == 0)
        .unwrap_or(probe.len());
    if nul < 2 {
        return false;
    }
    let name: &[u8] = &probe[..nul];
    name.iter()
        .all(|b: &u8| (0x20..0x7f).contains(b) || *b == b'\t')
        && symbol_has_separator(name)
}

fn parse_header_with_version(
    body: &[u8],
    section_addr: u64,
    endian: Endian,
    version: PclntabVersion,
) -> Option<PclntabHeader> {
    let quantum: u8 = read_u8(body, 6).ok()?;
    let ptr_size: u8 = read_u8(body, 7).ok()?;
    if quantum == 0 || ptr_size == 0 {
        return None;
    }
    let ps: usize = ptr_size as usize;
    let read_word = |off: usize| -> Option<u64> {
        if ptr_size == 4 {
            read_u32(body, off, endian).ok().map(u64::from)
        } else {
            read_u64(body, off, endian).ok()
        }
    };
    let header: PclntabHeader = match version {
        PclntabVersion::Go12 => PclntabHeader {
            version,
            quantum,
            ptr_size,
            endian,
            n_funcs: read_word(8)?,
            n_files: 0,
            text_start: 0,
            funcname_off: 0,
            cu_off: 0,
            filetab_off: 0,
            pctab_off: 0,
            funcdata_off: 0,
            section_addr,
            section_len: body.len(),
        },
        PclntabVersion::Go116 => PclntabHeader {
            version,
            quantum,
            ptr_size,
            endian,
            n_funcs: read_word(8)?,
            n_files: read_word(8 + ps)?,
            text_start: 0,
            funcname_off: read_word(8 + 2 * ps)?,
            cu_off: read_word(8 + 3 * ps)?,
            filetab_off: read_word(8 + 4 * ps)?,
            pctab_off: read_word(8 + 5 * ps)?,
            funcdata_off: read_word(8 + 6 * ps)?,
            section_addr,
            section_len: body.len(),
        },
        PclntabVersion::Go118 | PclntabVersion::Go120 => PclntabHeader {
            version,
            quantum,
            ptr_size,
            endian,
            n_funcs: read_word(8)?,
            n_files: read_word(8 + ps)?,
            text_start: read_word(8 + 2 * ps)?,
            funcname_off: read_word(8 + 3 * ps)?,
            cu_off: read_word(8 + 4 * ps)?,
            filetab_off: read_word(8 + 5 * ps)?,
            pctab_off: read_word(8 + 6 * ps)?,
            funcdata_off: read_word(8 + 7 * ps)?,
            section_addr,
            section_len: body.len(),
        },
    };
    Some(header)
}

const SIG_MIN_FUNCS: u64 = 8;
const MAX_PLAUSIBLE_SIG_FUNCS: u64 = 16 * 1024 * 1024;

fn validate_header_structure(header: &PclntabHeader, body: &[u8]) -> bool {
    let len: u64 = body.len() as u64;
    if header.n_funcs < SIG_MIN_FUNCS || header.n_funcs > MAX_PLAUSIBLE_SIG_FUNCS {
        return false;
    }
    match header.version {
        PclntabVersion::Go12 => header.n_funcs * 2 * u64::from(header.ptr_size) < len,
        PclntabVersion::Go116 | PclntabVersion::Go118 | PclntabVersion::Go120 => {
            let offsets: [u64; 5] = [
                header.funcname_off,
                header.cu_off,
                header.filetab_off,
                header.pctab_off,
                header.funcdata_off,
            ];
            if offsets.iter().any(|o: &u64| *o == 0 || *o >= len) {
                return false;
            }
            if header.funcname_off >= header.funcdata_off {
                return false;
            }
            funcname_table_opens_with_symbol(body, header.funcname_off)
        }
    }
}

fn funcname_table_opens_with_symbol(body: &[u8], funcname_off: u64) -> bool {
    let Ok(off): core::result::Result<usize, _> = usize::try_from(funcname_off) else {
        return false;
    };
    let tail: &[u8] = match body.get(off..) {
        Some(t) if t.len() >= 2 => t,
        _ => return false,
    };
    let probe: &[u8] = &tail[..tail.len().min(128)];
    let nul: usize = probe
        .iter()
        .position(|b: &u8| *b == 0)
        .unwrap_or(probe.len());
    if nul < 2 {
        return false;
    }
    let first: &[u8] = &probe[..nul];
    let all_print: bool = first
        .iter()
        .all(|b: &u8| (0x20..0x7f).contains(b) || *b == b'\t');
    all_print && symbol_has_separator(first)
}

fn symbol_has_separator(name: &[u8]) -> bool {
    name.contains(&b'.') || name.contains(&b'/') || name.contains(&b':')
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
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
    let end: usize = off.checked_add(4).ok_or(Error::PclntabRead {
        offset: off,
        len: buf.len(),
    })?;
    let slice: &[u8] = buf.get(off..end).ok_or(Error::PclntabRead {
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
    let end: usize = off.checked_add(8).ok_or(Error::PclntabRead {
        offset: off,
        len: buf.len(),
    })?;
    let slice: &[u8] = buf.get(off..end).ok_or(Error::PclntabRead {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn magic_needle_encodes_image_byte_order() {
        assert_eq!(
            magic_needle(MAGIC_GO120, Endian::Little),
            [0xf1, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            magic_needle(MAGIC_GO120, Endian::Big),
            [0xff, 0xff, 0xff, 0xf1]
        );
        assert_eq!(
            magic_needle(MAGIC_GO12, Endian::Big),
            [0xff, 0xff, 0xff, 0xfb]
        );
        assert_eq!(
            magic_needle(MAGIC_GO116, Endian::Little),
            [0xfa, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn symbol_separator_accepts_go_pseudo_symbols() {
        assert!(symbol_has_separator(b"go:buildid"));
        assert!(symbol_has_separator(b"type:.eq.foo"));
        assert!(symbol_has_separator(b"main.main"));
        assert!(symbol_has_separator(b"net/http.Serve"));
        assert!(!symbol_has_separator(b"plainword"));
    }

    #[test]
    fn cstring_symbol_rejects_short_and_garbage() {
        let buf: &[u8] = b"go:buildid\0internal/abi.TypeOf\0";
        assert!(cstring_is_symbol(buf, 0));
        assert!(cstring_is_symbol(buf, 11));
        assert!(!cstring_is_symbol(b"x\0", 0));
        assert!(!cstring_is_symbol(&[0x01, 0x02, 0x03, 0x00], 0));
        assert!(!cstring_is_symbol(b"noseparator\0", 0));
    }

    #[test]
    fn find_subslice_locates_needle() {
        assert_eq!(find_subslice(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_subslice(b"abcdef", b"xy"), None);
        assert_eq!(find_subslice(b"ab", b"abc"), None);
    }

    #[test]
    fn validate_rejects_low_func_count() {
        let header: PclntabHeader = PclntabHeader {
            version: PclntabVersion::Go120,
            quantum: 1,
            ptr_size: 8,
            endian: Endian::Little,
            n_funcs: 2,
            n_files: 1,
            text_start: 0,
            funcname_off: 0x40,
            cu_off: 0x80,
            filetab_off: 0xc0,
            pctab_off: 0x100,
            funcdata_off: 0x200,
            section_addr: 0,
            section_len: 0x1000,
        };
        let body: Vec<u8> = vec![0u8; 0x1000];
        assert!(!validate_header_structure(&header, &body));
    }

    #[test]
    fn validate_rejects_out_of_bounds_offset() {
        let header: PclntabHeader = PclntabHeader {
            version: PclntabVersion::Go120,
            quantum: 1,
            ptr_size: 8,
            endian: Endian::Little,
            n_funcs: 64,
            n_files: 1,
            text_start: 0,
            funcname_off: 0x40,
            cu_off: 0x80,
            filetab_off: 0xc0,
            pctab_off: 0x100,
            funcdata_off: 0x9999,
            section_addr: 0,
            section_len: 0x1000,
        };
        let body: Vec<u8> = vec![0u8; 0x1000];
        assert!(!validate_header_structure(&header, &body));
    }
}
