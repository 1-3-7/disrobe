use super::image::{MAX_SHORTSTRING_LEN, PeView, is_plausible_symbol};
use super::layout::VmtLayout;
use super::{DelphiDynamicMethod, DelphiInterface};

const MAX_FIELDS_PER_CLASS: u16 = 4096;
const MAX_FIELD_CLASSES: u16 = 8192;
const MAX_DYNAMIC_METHODS: u16 = 4096;
const MAX_INTERFACES: i32 = 1024;
const GUID_BYTES: usize = 16;

#[derive(Debug, Clone)]
pub(super) struct RawField {
    pub name: String,
    pub offset: u32,
    pub type_index: u16,
}

#[derive(Debug, Clone)]
pub(super) struct RawFieldTable {
    pub class_tab_va: u64,
    pub fields: Vec<RawField>,
}

pub(super) fn parse_field_table(
    view: &PeView<'_>,
    table_va: u64,
    layout: &VmtLayout,
    instance_size: u32,
) -> Option<RawFieldTable> {
    let ptr: usize = layout.ptr_size as usize;
    let mut off: usize = view.va_to_off(table_va)?;
    let count: u16 = view.read_u16(off)?;
    if count == 0 || count > MAX_FIELDS_PER_CLASS {
        return None;
    }
    off = off.checked_add(2)?;
    let class_tab_va: u64 = view.read_ptr(off)?;
    off = off.checked_add(ptr)?;

    let mut fields: Vec<RawField> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let field_offset: u32 = view.read_u32(off)?;
        off = off.checked_add(4)?;
        let type_index: u16 = view.read_u16(off)?;
        off = off.checked_add(2)?;
        let (name, consumed): (String, usize) = view.read_shortstring(off, MAX_SHORTSTRING_LEN)?;
        off = off.checked_add(consumed)?;
        if !is_plausible_symbol(&name) {
            return None;
        }
        if field_offset < layout.ptr_size as u32 || field_offset >= instance_size {
            return None;
        }
        fields.push(RawField {
            name,
            offset: field_offset,
            type_index,
        });
    }

    Some(RawFieldTable {
        class_tab_va,
        fields,
    })
}

pub(super) fn field_class_candidates(
    view: &PeView<'_>,
    class_tab_va: u64,
    index: u16,
    layout: &VmtLayout,
) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    if class_tab_va == 0 {
        return out;
    }
    let Some(base): Option<usize> = view.va_to_off(class_tab_va) else {
        return out;
    };
    let Some(count): Option<u16> = view.read_u16(base) else {
        return out;
    };
    if count == 0 || count > MAX_FIELD_CLASSES || index >= count {
        return out;
    }
    let Some(slot_va): Option<u64> =
        class_tab_va.checked_add(2 + u64::from(index) * layout.ptr_size)
    else {
        return out;
    };
    let Some(reference): Option<u64> = view.read_ptr_at_va(slot_va) else {
        return out;
    };
    if reference == 0 {
        return out;
    }
    out.push(reference);
    if let Some(indirect) = view.read_ptr_at_va(reference)
        && indirect != 0
    {
        out.push(indirect);
    }
    out
}

pub(super) fn parse_dynamic_table(
    view: &PeView<'_>,
    table_va: u64,
    layout: &VmtLayout,
) -> Option<Vec<DelphiDynamicMethod>> {
    let ptr: usize = layout.ptr_size as usize;
    let base: usize = view.va_to_off(table_va)?;
    let count: u16 = view.read_u16(base)?;
    if count == 0 || count > MAX_DYNAMIC_METHODS {
        return None;
    }
    let index_base: usize = base.checked_add(2)?;
    let address_base: usize = index_base.checked_add(usize::from(count).checked_mul(2)?)?;

    let mut out: Vec<DelphiDynamicMethod> = Vec::with_capacity(count as usize);
    for i in 0..usize::from(count) {
        let index: i16 = view.read_i16(index_base.checked_add(i.checked_mul(2)?)?)?;
        let address: u64 = view.read_ptr(address_base.checked_add(i.checked_mul(ptr)?)?)?;
        if !view.is_executable_va(address) {
            return None;
        }
        out.push(DelphiDynamicMethod { index, address });
    }
    Some(out)
}

pub(super) fn parse_interface_table(
    view: &PeView<'_>,
    table_va: u64,
    layout: &VmtLayout,
    instance_size: u32,
) -> Option<Vec<DelphiInterface>> {
    let ptr: usize = layout.ptr_size as usize;
    let base: usize = view.va_to_off(table_va)?;
    let count: i32 = view.read_i32(base)?;
    if count <= 0 || count > MAX_INTERFACES {
        return None;
    }
    let entry_size: usize = GUID_BYTES.checked_add(ptr)?.checked_add(8)?;
    let mut off: usize = base.checked_add(4)?;

    let mut out: Vec<DelphiInterface> = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let guid: &[u8] = view.slice(off, GUID_BYTES)?;
        let vtable: u64 = view.read_ptr(off.checked_add(GUID_BYTES)?)?;
        let instance_offset: i32 = view.read_i32(off.checked_add(GUID_BYTES)?.checked_add(ptr)?)?;
        let resolvable: bool = vtable != 0 && view.va_to_off(vtable).is_some();
        let delegated: bool = instance_offset > 0 && (instance_offset as u32) < instance_size;
        if !resolvable && !delegated {
            return None;
        }
        out.push(DelphiInterface {
            iid: format_guid(guid),
            vtable,
            instance_offset,
        });
        off = off.checked_add(entry_size)?;
    }
    Some(out)
}

fn format_guid(raw: &[u8]) -> String {
    if raw.len() < GUID_BYTES {
        return String::new();
    }
    let d1: u32 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let d2: u16 = u16::from_le_bytes([raw[4], raw[5]]);
    let d3: u16 = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    )
}
