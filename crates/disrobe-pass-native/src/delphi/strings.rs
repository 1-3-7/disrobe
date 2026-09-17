use serde::{Deserialize, Serialize};

use super::image::PeView;

const CONSTANT_REFCOUNT: u32 = 0xFFFF_FFFF;
const MAX_SCAN_POSITIONS: usize = 16_000_000;
const MAX_STRINGS: usize = 65_536;
const MAX_STRING_UNITS: u32 = 1 << 20;
const MIN_STRING_UNITS: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DelphiStringKind {
    LegacyAnsi,
    Ansi,
    Unicode,
}

impl DelphiStringKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LegacyAnsi => "pre-2009 long string, no code page header",
            Self::Ansi => "code page string, one byte per element",
            Self::Unicode => "UTF-16 string, two bytes per element",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelphiString {
    pub va: u64,
    pub kind: DelphiStringKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_page: Option<u16>,
    pub text: String,
}

fn is_layout_char(c: char) -> bool {
    c == '\t' || c == '\n' || c == '\r'
}

fn is_acceptable_text(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    text.chars()
        .all(|c: char| is_layout_char(c) || !c.is_control())
}

fn is_ascii_text(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    text.chars()
        .all(|c: char| is_layout_char(c) || (c.is_ascii() && !c.is_control()))
}

fn decode_ansi(bytes: &[u8]) -> Option<String> {
    let text: String = bytes.iter().map(|b: &u8| char::from(*b)).collect();
    is_acceptable_text(&text).then_some(text)
}

fn decode_ascii(bytes: &[u8]) -> Option<String> {
    let text: String = bytes.iter().map(|b: &u8| char::from(*b)).collect();
    is_ascii_text(&text).then_some(text)
}

fn decode_unicode(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c: &[u8]| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text: String = char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()?;
    is_acceptable_text(&text).then_some(text)
}

fn terminator_is_null(view: &PeView<'_>, data_off: usize, span: usize, elem: usize) -> bool {
    let Some(end): Option<usize> = data_off.checked_add(span) else {
        return false;
    };
    view.slice(end, elem)
        .is_some_and(|t: &[u8]| t.iter().all(|b: &u8| *b == 0))
}

fn read_candidate(view: &PeView<'_>, refcount_off: usize, va: u64) -> Option<DelphiString> {
    let length: u32 = view.read_u32(refcount_off.checked_add(4)?)?;
    if !(MIN_STRING_UNITS..=MAX_STRING_UNITS).contains(&length) {
        return None;
    }
    let data_off: usize = refcount_off.checked_add(8)?;

    if refcount_off >= 4
        && let Some(element_size) = view.read_u16(refcount_off - 2)
        && let Some(code_page) = view.read_u16(refcount_off - 4)
        && (element_size == 1 || element_size == 2)
    {
        let elem: usize = element_size as usize;
        let span: usize = (length as usize).checked_mul(elem)?;
        if terminator_is_null(view, data_off, span, elem) {
            let raw: &[u8] = view.slice(data_off, span)?;
            let text: Option<String> = if element_size == 1 {
                decode_ansi(raw)
            } else {
                decode_unicode(raw)
            };
            if let Some(text) = text {
                return Some(DelphiString {
                    va,
                    kind: if element_size == 1 {
                        DelphiStringKind::Ansi
                    } else {
                        DelphiStringKind::Unicode
                    },
                    code_page: Some(code_page),
                    text,
                });
            }
        }
    }

    let span: usize = length as usize;
    if !terminator_is_null(view, data_off, span, 1) {
        return None;
    }
    let raw: &[u8] = view.slice(data_off, span)?;
    let text: String = decode_ascii(raw)?;
    Some(DelphiString {
        va,
        kind: DelphiStringKind::LegacyAnsi,
        code_page: None,
        text,
    })
}

pub(super) fn scan(view: &PeView<'_>) -> Vec<DelphiString> {
    let image_base: u64 = view.image_base();
    let mut out: Vec<DelphiString> = Vec::new();
    let mut scanned: usize = 0;

    'outer: for sec in &view.image.sections {
        let span: u32 = sec.virtual_size.min(sec.raw_size);
        if span < 12 {
            continue;
        }
        let mut rva: u32 = sec.virtual_address;
        let end_rva: u64 = u64::from(sec.virtual_address) + u64::from(span) - 12;
        while u64::from(rva) <= end_rva {
            if scanned >= MAX_SCAN_POSITIONS || out.len() >= MAX_STRINGS {
                break 'outer;
            }
            scanned += 1;
            if let Some(off) = view.rva_to_off(rva)
                && view.read_u32(off) == Some(CONSTANT_REFCOUNT)
            {
                let va: u64 = image_base.wrapping_add(u64::from(rva)).wrapping_add(8);
                if let Some(found) = read_candidate(view, off, va) {
                    out.push(found);
                }
            }
            let Some(next): Option<u32> = rva.checked_add(4) else {
                break;
            };
            rva = next;
        }
    }

    out.sort_by_key(|s: &DelphiString| s.va);
    out
}
