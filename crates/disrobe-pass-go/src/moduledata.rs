use serde::{Deserialize, Serialize};

use crate::binary::GoImage;
use crate::pclntab::LocatedPclntab;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moduledata {
    pub pclntab_va: u64,
    pub typelinks_va: u64,
    pub typelinks_len: u64,
    pub itablinks_va: u64,
    pub itablinks_len: u64,
    pub types_va: u64,
    pub etypes_va: u64,
    pub text_va: u64,
    pub etext_va: u64,
    pub modulename: Option<String>,
    pub buildversion: Option<String>,
    pub via: ModuledataSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuledataSource {
    SymbolRuntimeFirstmoduledata,
    PclntabBacksearch,
    None,
}

const RUNTIME_FIRSTMODULE_SYM: &str = "runtime.firstmoduledata";

pub fn locate_moduledata(image: &GoImage<'_>, located: &LocatedPclntab<'_>) -> Moduledata {
    if let Some(md) = via_symbol(image) {
        return md;
    }
    if let Some(md) = via_pclntab_backsearch(image, located) {
        return md;
    }
    Moduledata {
        pclntab_va: located.header.section_addr,
        typelinks_va: 0,
        typelinks_len: 0,
        itablinks_va: 0,
        itablinks_len: 0,
        types_va: 0,
        etypes_va: 0,
        text_va: located.header.text_start,
        etext_va: 0,
        modulename: None,
        buildversion: extract_buildversion(image),
        via: ModuledataSource::None,
    }
}

fn via_symbol(image: &GoImage<'_>) -> Option<Moduledata> {
    let entry: &(String, u64, u64) = image
        .symbol_addrs
        .iter()
        .find(|(n, _, _)| n == RUNTIME_FIRSTMODULE_SYM)?;
    let va: u64 = entry.1;
    walk_moduledata(image, va, ModuledataSource::SymbolRuntimeFirstmoduledata)
}

fn via_pclntab_backsearch(image: &GoImage<'_>, located: &LocatedPclntab<'_>) -> Option<Moduledata> {
    let pclntab_va: u64 = located.header.section_addr;
    let ps: u8 = image.ptr_size;
    for sec in &image.sections {
        if sec.data.is_empty() {
            continue;
        }
        let step: usize = ps as usize;
        let mut off: usize = 0;
        while off + step <= sec.data.len() {
            let val: u64 = match ps {
                4 => {
                    let mut a: [u8; 4] = [0u8; 4];
                    a.copy_from_slice(&sec.data[off..off + 4]);
                    u64::from(u32::from_le_bytes(a))
                }
                8 => {
                    let mut a: [u8; 8] = [0u8; 8];
                    a.copy_from_slice(&sec.data[off..off + 8]);
                    u64::from_le_bytes(a)
                }
                _ => 0,
            };
            if val == pclntab_va {
                let candidate_va: u64 = sec.address + off as u64;
                if let Some(md) =
                    walk_moduledata(image, candidate_va, ModuledataSource::PclntabBacksearch)
                {
                    return Some(md);
                }
            }
            off += step;
        }
    }
    None
}

const MD_WORD_TEXT: u64 = 22;
const MD_WORD_ETEXT: u64 = 23;
const MD_WORD_TYPES: u64 = 37;
const MD_WORD_ETYPES: u64 = 38;
const MD_WORD_TYPELINKS_PTR: u64 = 45;
const MD_WORD_TYPELINKS_LEN: u64 = 46;
const MD_WORD_ITABLINKS_PTR: u64 = 48;
const MD_WORD_ITABLINKS_LEN: u64 = 49;

const MAX_PLAUSIBLE_SLICE_LEN: u64 = 1 << 22;

fn walk_moduledata(image: &GoImage<'_>, base: u64, via: ModuledataSource) -> Option<Moduledata> {
    let ps: u64 = u64::from(image.ptr_size);
    let word = |index: u64| -> u64 { image.read_ptr(base.wrapping_add(ps * index)).unwrap_or(0) };
    let pclntab_va: u64 = image.read_ptr(base)?;
    let text_va: u64 = word(MD_WORD_TEXT);
    let etext_va: u64 = word(MD_WORD_ETEXT);
    let types_va: u64 = word(MD_WORD_TYPES);
    let etypes_va: u64 = word(MD_WORD_ETYPES);
    let (typelinks_va, typelinks_len): (u64, u64) = validated_slice(
        image,
        word(MD_WORD_TYPELINKS_PTR),
        word(MD_WORD_TYPELINKS_LEN),
        4,
    );
    let (itablinks_va, itablinks_len): (u64, u64) = validated_slice(
        image,
        word(MD_WORD_ITABLINKS_PTR),
        word(MD_WORD_ITABLINKS_LEN),
        ps,
    );
    Some(Moduledata {
        pclntab_va,
        typelinks_va,
        typelinks_len,
        itablinks_va,
        itablinks_len,
        types_va,
        etypes_va,
        text_va,
        etext_va,
        modulename: None,
        buildversion: extract_buildversion(image),
        via,
    })
}

fn validated_slice(image: &GoImage<'_>, ptr: u64, len: u64, elem_size: u64) -> (u64, u64) {
    if ptr == 0 || len == 0 || len > MAX_PLAUSIBLE_SLICE_LEN {
        return (0, 0);
    }
    let Some(span) = len.checked_mul(elem_size) else {
        return (0, 0);
    };
    if image.data_at_va(ptr, 1).is_none()
        || image.data_at_va(ptr.wrapping_add(span - 1), 1).is_none()
    {
        return (0, 0);
    }
    (ptr, len)
}

pub fn extract_buildversion(image: &GoImage<'_>) -> Option<String> {
    for sec in &image.sections {
        let needle: &[u8] = b"go1.";
        let mut i: usize = 0;
        while i + needle.len() <= sec.data.len() {
            if &sec.data[i..i + needle.len()] == needle {
                let tail: &[u8] = &sec.data[i..];
                let limit: usize = tail.len().min(32);
                let end: usize = tail
                    .iter()
                    .position(|b: &u8| !(b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-'))
                    .unwrap_or(limit);
                if (4..=24).contains(&end)
                    && let Ok(s) = std::str::from_utf8(&tail[..end])
                    && s.chars().filter(|c: &char| *c == '.').count() >= 1
                {
                    return Some(s.to_owned());
                }
            }
            i += 1;
        }
    }
    None
}
