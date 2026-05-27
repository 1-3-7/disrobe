use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::binary::GoImage;
use crate::moduledata::Moduledata;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoTypeRef {
    pub va: u64,
    pub name: Option<String>,
    pub kind: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoItab {
    pub va: u64,
    pub interface_name: Option<String>,
    pub concrete_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoTypeMeta {
    pub types: Vec<GoTypeRef>,
    pub itabs: Vec<GoItab>,
    pub strings: Vec<String>,
}

pub fn extract_typemeta(image: &GoImage<'_>, md: &Moduledata) -> GoTypeMeta {
    let mut types: Vec<GoTypeRef> = Vec::new();
    let mut itabs: Vec<GoItab> = Vec::new();
    let mut strings: BTreeSet<String> = BTreeSet::new();

    if md.typelinks_va != 0 && md.typelinks_len != 0 && md.types_va != 0 {
        let n: usize = usize::try_from(md.typelinks_len).unwrap_or(0);
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for i in 0..n.min(1 << 14) {
            let entry_va: u64 = md.typelinks_va.wrapping_add((i as u64) * 4);
            let Some(off) = image.read_u32(entry_va) else {
                break;
            };
            let type_va: u64 = md.types_va.wrapping_add(u64::from(off));
            if !seen.insert(type_va) {
                continue;
            }
            let name: Option<String> = read_type_name(image, md, type_va);
            let kind: Option<u8> = read_type_kind(image, type_va);
            if let Some(ref n_str) = name {
                strings.insert(n_str.clone());
            }
            types.push(GoTypeRef {
                va: type_va,
                name,
                kind,
            });
        }
    }

    if md.itablinks_va != 0 && md.itablinks_len != 0 {
        let n: usize = usize::try_from(md.itablinks_len).unwrap_or(0);
        let ps: u64 = u64::from(image.ptr_size);
        for i in 0..n.min(1 << 14) {
            let slot_va: u64 = md.itablinks_va.wrapping_add((i as u64) * ps);
            let Some(itab_va) = image.read_ptr(slot_va) else {
                break;
            };
            if itab_va == 0 {
                continue;
            }
            let inter_va: u64 = image.read_ptr(itab_va).unwrap_or(0);
            let concrete_va: u64 = image.read_ptr(itab_va.wrapping_add(ps)).unwrap_or(0);
            let inter_name: Option<String> = if inter_va != 0 {
                read_type_name(image, md, inter_va)
            } else {
                None
            };
            let concrete_name: Option<String> = if concrete_va != 0 {
                read_type_name(image, md, concrete_va)
            } else {
                None
            };
            itabs.push(GoItab {
                va: itab_va,
                interface_name: inter_name,
                concrete_name,
            });
        }
    }

    GoTypeMeta {
        types,
        itabs,
        strings: strings.into_iter().collect(),
    }
}

fn read_type_kind(image: &GoImage<'_>, type_va: u64) -> Option<u8> {
    let ps: u64 = u64::from(image.ptr_size);
    let kind_off: u64 = ps + ps + 4 + 4 + 1 + 1 + 1;
    let buf: &[u8] = image.data_at_va(type_va + kind_off, 1)?;
    Some(buf[0] & 0x1f)
}

fn read_type_name(image: &GoImage<'_>, md: &Moduledata, type_va: u64) -> Option<String> {
    let ps: u64 = u64::from(image.ptr_size);
    let nameoff_field: u64 = type_va + (ps * 4) + 16;
    let nameoff: u32 = image.read_u32(nameoff_field)?;
    let name_va: u64 = md.types_va.wrapping_add(u64::from(nameoff));
    let header: &[u8] = image.data_at_va(name_va, 3)?;
    let len: usize = (usize::from(header[1]) << 8) | usize::from(header[2]);
    if len == 0 || len > 4096 {
        return None;
    }
    let body: &[u8] = image.data_at_va(name_va + 3, len)?;
    Some(String::from_utf8_lossy(body).into_owned())
}
