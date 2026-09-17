use super::biff::{BiffRecord, read_short_xlunicode, read_u16};
use super::boundsheet::{REC_EOF, SheetEntry};
use super::limits::{MAX_EXTERN_NAMES, MAX_XTI};

const REC_EXTERNSHEET: u32 = 0x0017;
const REC_EXTERNNAME: u32 = 0x0023;
const REC_SUPBOOK: u32 = 0x01AE;

const SUPBOOK_SELF: u16 = 0x0401;
const XTI_SIZE: usize = 6;
const EXTERNNAME_TEXT_AT: usize = 6;

#[derive(Debug, Clone)]
struct XtiEntry {
    supbook: usize,
    label: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct XtiScope {
    entries: Vec<XtiEntry>,
    extern_names: Vec<Vec<String>>,
}

impl XtiScope {
    #[must_use]
    pub fn build(records: &[BiffRecord], sheets: &[SheetEntry]) -> Self {
        let mut is_self: Vec<bool> = Vec::new();
        let mut extern_names: Vec<Vec<String>> = Vec::new();
        let mut raw_xti: Vec<(usize, i16, i16)> = Vec::new();
        for rec in records {
            if rec.rt == REC_EOF {
                break;
            }
            match rec.rt {
                REC_SUPBOOK => {
                    is_self.push(read_u16(&rec.data, 2) == Some(SUPBOOK_SELF));
                    extern_names.push(Vec::new());
                }
                REC_EXTERNNAME => {
                    let Some(bucket): Option<&mut Vec<String>> = extern_names.last_mut() else {
                        continue;
                    };
                    if bucket.len() >= MAX_EXTERN_NAMES {
                        continue;
                    }
                    if let Some((name, _consumed)) =
                        read_short_xlunicode(&rec.data, EXTERNNAME_TEXT_AT)
                    {
                        bucket.push(name);
                    }
                }
                REC_EXTERNSHEET => raw_xti.extend(parse_externsheet(&rec.data)),
                _ => {}
            }
        }
        let entries: Vec<XtiEntry> = raw_xti
            .into_iter()
            .map(|(supbook, first, last): (usize, i16, i16)| XtiEntry {
                supbook,
                label: sheet_label(is_self.get(supbook).copied(), sheets, first, last),
            })
            .collect();
        Self {
            entries,
            extern_names,
        }
    }

    #[must_use]
    pub fn sheet_label(&self, ixti: u16) -> Option<&str> {
        self.entries
            .get(usize::from(ixti))?
            .label
            .as_deref()
            .filter(|label: &&str| !label.is_empty())
    }

    #[must_use]
    pub fn extern_name(&self, ixti: u16, index: u32) -> Option<&str> {
        let entry: &XtiEntry = self.entries.get(usize::from(ixti))?;
        let position: usize = usize::try_from(index).ok()?.checked_sub(1)?;
        self.extern_names
            .get(entry.supbook)?
            .get(position)
            .map(String::as_str)
    }
}

fn parse_externsheet(data: &[u8]) -> Vec<(usize, i16, i16)> {
    let Some(count): Option<u16> = read_u16(data, 0) else {
        return Vec::new();
    };
    let capped: usize = usize::from(count).min(MAX_XTI);
    let mut out: Vec<(usize, i16, i16)> = Vec::with_capacity(capped);
    for slot in 0..capped {
        let at: usize = 2 + slot * XTI_SIZE;
        let (Some(supbook), Some(first), Some(last)): (Option<u16>, Option<u16>, Option<u16>) = (
            read_u16(data, at),
            read_u16(data, at + 2),
            read_u16(data, at + 4),
        ) else {
            break;
        };
        out.push((usize::from(supbook), first as i16, last as i16));
    }
    out
}

fn sheet_label(
    is_self: Option<bool>,
    sheets: &[SheetEntry],
    first: i16,
    last: i16,
) -> Option<String> {
    if is_self != Some(true) || first < 0 {
        return None;
    }
    let head: &SheetEntry = sheets.get(usize::try_from(first).ok()?)?;
    if first == last {
        return Some(head.name.clone());
    }
    let tail: &SheetEntry = sheets.get(usize::try_from(last).ok()?)?;
    Some(format!("{}:{}", head.name, tail.name))
}
