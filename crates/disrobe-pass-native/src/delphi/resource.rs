use super::image::PeView;

const RT_RCDATA: u32 = 10;
const RESOURCE_DIR_INDEX: usize = 2;
const DIR_HEADER_SIZE: u32 = 16;
const ENTRY_SIZE: u32 = 8;
const SUBDIR_FLAG: u32 = 0x8000_0000;
const OFFSET_MASK: u32 = 0x7FFF_FFFF;
const MAX_ENTRIES: u32 = 8192;
const MAX_RESOURCES: usize = 8192;
const MAX_NAME_CHARS: usize = 512;

#[derive(Debug, Clone)]
pub(super) struct RawResource {
    pub name: String,
    pub data: Vec<u8>,
}

pub(super) fn collect_rcdata(view: &PeView<'_>) -> Vec<RawResource> {
    let mut out: Vec<RawResource> = Vec::new();
    let Some(dir): Option<&crate::packers::pe_sections::DataDirectory> =
        view.image.data_directories.get(RESOURCE_DIR_INDEX)
    else {
        return out;
    };
    if dir.virtual_address == 0 || dir.size == 0 {
        return out;
    }
    let Some(base_off): Option<usize> = view.rva_to_off(dir.virtual_address) else {
        return out;
    };
    walk_types(view, base_off, 0, &mut out);
    out
}

fn read_u16(view: &PeView<'_>, base_off: usize, rel: u32) -> Option<u16> {
    view.read_u16(base_off.checked_add(rel as usize)?)
}

fn read_u32(view: &PeView<'_>, base_off: usize, rel: u32) -> Option<u32> {
    view.read_u32(base_off.checked_add(rel as usize)?)
}

fn entry_count(view: &PeView<'_>, base_off: usize, dir_rel: u32) -> u32 {
    let named: u32 = u32::from(read_u16(view, base_off, dir_rel + 12).unwrap_or(0));
    let ids: u32 = u32::from(read_u16(view, base_off, dir_rel + 14).unwrap_or(0));
    named.saturating_add(ids).min(MAX_ENTRIES)
}

fn walk_types(view: &PeView<'_>, base_off: usize, dir_rel: u32, out: &mut Vec<RawResource>) {
    let count: u32 = entry_count(view, base_off, dir_rel);
    for i in 0..count {
        if out.len() >= MAX_RESOURCES {
            return;
        }
        let entry_rel: u32 = dir_rel + DIR_HEADER_SIZE + i * ENTRY_SIZE;
        let Some(name_field): Option<u32> = read_u32(view, base_off, entry_rel) else {
            continue;
        };
        let Some(offset_field): Option<u32> = read_u32(view, base_off, entry_rel + 4) else {
            continue;
        };
        if name_field & SUBDIR_FLAG != 0 {
            continue;
        }
        if name_field != RT_RCDATA {
            continue;
        }
        if offset_field & SUBDIR_FLAG == 0 {
            continue;
        }
        walk_names(view, base_off, offset_field & OFFSET_MASK, out);
    }
}

fn walk_names(view: &PeView<'_>, base_off: usize, dir_rel: u32, out: &mut Vec<RawResource>) {
    let count: u32 = entry_count(view, base_off, dir_rel);
    for i in 0..count {
        if out.len() >= MAX_RESOURCES {
            return;
        }
        let entry_rel: u32 = dir_rel + DIR_HEADER_SIZE + i * ENTRY_SIZE;
        let Some(name_field): Option<u32> = read_u32(view, base_off, entry_rel) else {
            continue;
        };
        let Some(offset_field): Option<u32> = read_u32(view, base_off, entry_rel + 4) else {
            continue;
        };
        let name: String = if name_field & SUBDIR_FLAG != 0 {
            read_res_name(view, base_off, name_field & OFFSET_MASK)
                .unwrap_or_else(|| format!("#{}", name_field & OFFSET_MASK))
        } else {
            format!("#{name_field}")
        };
        if offset_field & SUBDIR_FLAG == 0 {
            continue;
        }
        walk_langs(view, base_off, offset_field & OFFSET_MASK, &name, out);
    }
}

fn walk_langs(
    view: &PeView<'_>,
    base_off: usize,
    dir_rel: u32,
    name: &str,
    out: &mut Vec<RawResource>,
) {
    let count: u32 = entry_count(view, base_off, dir_rel);
    for i in 0..count {
        if out.len() >= MAX_RESOURCES {
            return;
        }
        let entry_rel: u32 = dir_rel + DIR_HEADER_SIZE + i * ENTRY_SIZE;
        let Some(offset_field): Option<u32> = read_u32(view, base_off, entry_rel + 4) else {
            continue;
        };
        if offset_field & SUBDIR_FLAG != 0 {
            continue;
        }
        let data_entry_rel: u32 = offset_field & OFFSET_MASK;
        let Some(data_rva): Option<u32> = read_u32(view, base_off, data_entry_rel) else {
            continue;
        };
        let Some(size): Option<u32> = read_u32(view, base_off, data_entry_rel + 4) else {
            continue;
        };
        let Some(data_off): Option<usize> = view.rva_to_off(data_rva) else {
            continue;
        };
        let end: usize = match data_off.checked_add(size as usize) {
            Some(e) if e <= view.bytes.len() => e,
            _ => continue,
        };
        let data: &[u8] = &view.bytes[data_off..end];
        if data.starts_with(b"TPF0") {
            out.push(RawResource {
                name: name.to_owned(),
                data: data.to_vec(),
            });
        }
    }
}

fn read_res_name(view: &PeView<'_>, base_off: usize, rel: u32) -> Option<String> {
    let len: usize = usize::from(read_u16(view, base_off, rel)?).min(MAX_NAME_CHARS);
    let start: usize = base_off.checked_add(rel as usize)?.checked_add(2)?;
    let mut units: Vec<u16> = Vec::with_capacity(len);
    for i in 0..len {
        let at: usize = start.checked_add(i * 2)?;
        units.push(view.read_u16(at)?);
    }
    Some(String::from_utf16_lossy(&units))
}
