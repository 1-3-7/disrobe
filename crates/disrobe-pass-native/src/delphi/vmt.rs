use std::collections::BTreeMap;

use super::image::{MAX_SHORTSTRING_LEN, PeView, is_plausible_symbol};
use super::{DelphiClass, DelphiEra, DelphiMethod, DelphiProperty};

const TK_CLASS: u8 = 7;
const TK_MIN: u8 = 1;
const TK_MAX: u8 = 25;

const MAX_SCAN_POSITIONS: usize = 8_000_000;
const MAX_CLASSES: usize = 8192;
const MAX_PROPS_PER_CLASS: u16 = 8192;
const MAX_METHODS_PER_CLASS: u16 = 8192;
const MAX_INSTANCE_SIZE: u32 = 0x0100_0000;
const MAX_PARENT_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy)]
struct VmtLayout {
    era: DelphiEra,
    ptr_size: u64,
    self_ptr_abs: u64,
    type_info: i64,
    method_table: i64,
    class_name: i64,
    instance_size: i64,
    parent: i64,
}

const LAYOUT_LEGACY32: VmtLayout = VmtLayout {
    era: DelphiEra::Legacy32,
    ptr_size: 4,
    self_ptr_abs: 76,
    type_info: -60,
    method_table: -52,
    class_name: -44,
    instance_size: -40,
    parent: -36,
};

const LAYOUT_MODERN32: VmtLayout = VmtLayout {
    era: DelphiEra::Modern32,
    ptr_size: 4,
    self_ptr_abs: 88,
    type_info: -72,
    method_table: -64,
    class_name: -56,
    instance_size: -52,
    parent: -48,
};

const LAYOUT_MODERN64: VmtLayout = VmtLayout {
    era: DelphiEra::Modern64,
    ptr_size: 8,
    self_ptr_abs: 176,
    type_info: -144,
    method_table: -128,
    class_name: -112,
    instance_size: -104,
    parent: -96,
};

fn variants_for(view: &PeView<'_>) -> &'static [VmtLayout] {
    if view.is_64() {
        &[LAYOUT_MODERN64]
    } else {
        &[LAYOUT_LEGACY32, LAYOUT_MODERN32]
    }
}

fn add_signed(base: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        base.checked_add(delta as u64)
    } else {
        base.checked_sub(delta.unsigned_abs())
    }
}

#[derive(Debug, Clone)]
struct RawClass {
    va: u64,
    era: DelphiEra,
    name: String,
    parent_va: Option<u64>,
    unit_name: Option<String>,
    instance_size: u32,
    own_props: Vec<DelphiProperty>,
    methods: Vec<DelphiMethod>,
}

#[derive(Debug, Clone)]
pub(super) struct ScanOutcome {
    pub classes: Vec<DelphiClass>,
    pub era: Option<DelphiEra>,
    pub anchor_count: usize,
    pub scan_truncated: bool,
}

pub(super) fn scan_classes(view: &PeView<'_>) -> ScanOutcome {
    let variants: &[VmtLayout] = variants_for(view);
    let ptr_size: usize = view.ptr_size();
    let image_base: u64 = view.image_base();
    let mut raw: BTreeMap<u64, RawClass> = BTreeMap::new();
    let mut anchor_count: usize = 0;
    let mut scanned: usize = 0;
    let mut scan_truncated: bool = false;
    let mut era_votes: BTreeMap<DelphiEra, usize> = BTreeMap::new();

    'outer: for sec in &view.image.sections {
        let span: u32 = sec.virtual_size.min(sec.raw_size);
        if span < ptr_size as u32 {
            continue;
        }
        let mut rva: u32 = sec.virtual_address;
        let end_rva: u64 = u64::from(sec.virtual_address) + u64::from(span) - ptr_size as u64;
        while u64::from(rva) <= end_rva {
            if scanned >= MAX_SCAN_POSITIONS || raw.len() >= MAX_CLASSES {
                scan_truncated = true;
                break 'outer;
            }
            scanned += 1;
            if let Some(off) = view.rva_to_off(rva)
                && let Some(value) = view.read_ptr(off)
            {
                let slot_va: u64 = image_base.wrapping_add(u64::from(rva));
                for layout in variants {
                    if value.wrapping_sub(slot_va) == layout.self_ptr_abs {
                        anchor_count += 1;
                        let candidate: u64 = value;
                        if !raw.contains_key(&candidate)
                            && let Some(rc) = validate_class(view, candidate, layout)
                        {
                            *era_votes.entry(rc.era).or_insert(0) += 1;
                            raw.insert(candidate, rc);
                        }
                    }
                }
            }
            let Some(next): Option<u32> = rva.checked_add(ptr_size as u32) else {
                break;
            };
            rva = next;
        }
    }

    let era: Option<DelphiEra> = era_votes
        .into_iter()
        .max_by_key(|entry: &(DelphiEra, usize)| entry.1)
        .map(|entry: (DelphiEra, usize)| entry.0);

    let classes: Vec<DelphiClass> = accumulate(&raw);
    ScanOutcome {
        classes,
        era,
        anchor_count,
        scan_truncated,
    }
}

fn is_self_consistent(view: &PeView<'_>, candidate: u64, layout: &VmtLayout) -> bool {
    let self_slot: Option<u64> = add_signed(candidate, -(layout.self_ptr_abs as i64));
    self_slot
        .and_then(|va: u64| view.read_ptr_at_va(va))
        .is_some_and(|v: u64| v == candidate)
}

fn class_name_of(view: &PeView<'_>, candidate: u64, layout: &VmtLayout) -> Option<String> {
    let name_slot: u64 = add_signed(candidate, layout.class_name)?;
    let name_ptr: u64 = view.read_ptr_at_va(name_slot)?;
    let off: usize = view.va_to_off(name_ptr)?;
    let (name, _): (String, usize) = view.read_shortstring(off, MAX_SHORTSTRING_LEN)?;
    if is_plausible_symbol(&name) {
        Some(name)
    } else {
        None
    }
}

fn validate_class(view: &PeView<'_>, candidate: u64, layout: &VmtLayout) -> Option<RawClass> {
    if !is_self_consistent(view, candidate, layout) {
        return None;
    }
    let name: String = class_name_of(view, candidate, layout)?;

    let size_slot: u64 = add_signed(candidate, layout.instance_size)?;
    let instance_size: u32 = view.read_u32(view.va_to_off(size_slot)?)?;
    if instance_size < layout.ptr_size as u32 || instance_size > MAX_INSTANCE_SIZE {
        return None;
    }

    let parent_slot: u64 = add_signed(candidate, layout.parent)?;
    let parent_field: u64 = view.read_ptr_at_va(parent_slot).unwrap_or(0);
    let parent_va: Option<u64> = resolve_parent(view, parent_field, layout);

    let type_info_slot: u64 = add_signed(candidate, layout.type_info)?;
    let type_info_va: u64 = view.read_ptr_at_va(type_info_slot).unwrap_or(0);
    let (own_props, unit_name): (Vec<DelphiProperty>, Option<String>) = if type_info_va != 0 {
        parse_typeinfo(view, type_info_va, layout)
    } else {
        (Vec::new(), None)
    };

    let method_slot: u64 = add_signed(candidate, layout.method_table)?;
    let method_table_va: u64 = view.read_ptr_at_va(method_slot).unwrap_or(0);
    let methods: Vec<DelphiMethod> = if method_table_va != 0 {
        parse_method_table(view, method_table_va, layout)
    } else {
        Vec::new()
    };

    Some(RawClass {
        va: candidate,
        era: layout.era,
        name,
        parent_va,
        unit_name,
        instance_size,
        own_props,
        methods,
    })
}

fn resolve_parent(view: &PeView<'_>, field: u64, layout: &VmtLayout) -> Option<u64> {
    if field == 0 {
        return None;
    }
    if is_self_consistent(view, field, layout) && class_name_of(view, field, layout).is_some() {
        return Some(field);
    }
    let indirect: u64 = view.read_ptr_at_va(field)?;
    if indirect != 0
        && is_self_consistent(view, indirect, layout)
        && class_name_of(view, indirect, layout).is_some()
    {
        return Some(indirect);
    }
    None
}

fn parse_typeinfo(
    view: &PeView<'_>,
    type_info_va: u64,
    layout: &VmtLayout,
) -> (Vec<DelphiProperty>, Option<String>) {
    let mut props: Vec<DelphiProperty> = Vec::new();
    let ptr: usize = layout.ptr_size as usize;
    let Some(mut off): Option<usize> = view.va_to_off(type_info_va) else {
        return (props, None);
    };
    let Some(&kind): Option<&u8> = view.bytes.get(off) else {
        return (props, None);
    };
    if kind != TK_CLASS {
        return (props, None);
    }
    off += 1;
    let Some((_name, consumed)): Option<(String, usize)> =
        view.read_shortstring(off, MAX_SHORTSTRING_LEN)
    else {
        return (props, None);
    };
    off += consumed;
    off += ptr;
    off += ptr;
    let Some(_prop_count_total): Option<u16> = view.read_u16(off) else {
        return (props, None);
    };
    off += 2;
    let Some((unit_name, uconsumed)): Option<(String, usize)> =
        view.read_shortstring(off, MAX_SHORTSTRING_LEN)
    else {
        return (props, None);
    };
    off += uconsumed;
    let Some(own_count): Option<u16> = view.read_u16(off) else {
        return (props, Some(unit_name));
    };
    off += 2;
    let own_count: u16 = own_count.min(MAX_PROPS_PER_CLASS);

    for _ in 0..own_count {
        let Some(prop_type_field): Option<u64> = view.read_ptr(off) else {
            break;
        };
        let Some(next): Option<usize> = off.checked_add(ptr + 3 * ptr) else {
            break;
        };
        off = next;
        if view.read_u32(off).is_none() {
            break;
        }
        off += 4;
        if view.read_u32(off).is_none() {
            break;
        }
        off += 4;
        if view.read_u16(off).is_none() {
            break;
        }
        off += 2;
        let Some((pname, pconsumed)): Option<(String, usize)> =
            view.read_shortstring(off, MAX_SHORTSTRING_LEN)
        else {
            break;
        };
        off += pconsumed;
        if !is_plausible_symbol(&pname) {
            break;
        }
        let type_name: Option<String> = resolve_type_name(view, prop_type_field);
        props.push(DelphiProperty {
            name: pname,
            type_name,
            inherited_from: None,
        });
    }

    (props, Some(unit_name))
}

fn resolve_type_name(view: &PeView<'_>, field: u64) -> Option<String> {
    if field == 0 {
        return None;
    }
    let off0: usize = view.va_to_off(field)?;
    if let Some(name) = typeinfo_name_at(view, off0) {
        return Some(name);
    }
    let ptr2: u64 = view.read_ptr(off0)?;
    if ptr2 == 0 {
        return None;
    }
    let off1: usize = view.va_to_off(ptr2)?;
    typeinfo_name_at(view, off1)
}

fn typeinfo_name_at(view: &PeView<'_>, off: usize) -> Option<String> {
    let kind: u8 = *view.bytes.get(off)?;
    if !(TK_MIN..=TK_MAX).contains(&kind) {
        return None;
    }
    let (name, _consumed): (String, usize) = view.read_shortstring(off + 1, MAX_SHORTSTRING_LEN)?;
    if is_plausible_symbol(&name) {
        Some(name)
    } else {
        None
    }
}

fn parse_method_table(view: &PeView<'_>, mt_va: u64, layout: &VmtLayout) -> Vec<DelphiMethod> {
    let mut methods: Vec<DelphiMethod> = Vec::new();
    let ptr: usize = layout.ptr_size as usize;
    let Some(base): Option<usize> = view.va_to_off(mt_va) else {
        return methods;
    };
    let Some(count): Option<u16> = view.read_u16(base) else {
        return methods;
    };
    let count: u16 = count.min(MAX_METHODS_PER_CLASS);
    let mut off: usize = base + 2;
    let min_entry: usize = 2 + ptr + 1;

    for _ in 0..count {
        let entry_start: usize = off;
        let Some(size): Option<u16> = view.read_u16(off) else {
            break;
        };
        let Some(address): Option<u64> = view.read_ptr(off + 2) else {
            break;
        };
        let name_off: usize = off + 2 + ptr;
        let Some((name, _consumed)): Option<(String, usize)> =
            view.read_shortstring(name_off, MAX_SHORTSTRING_LEN)
        else {
            break;
        };
        if is_plausible_symbol(&name) {
            methods.push(DelphiMethod { name, address });
        }
        let size: usize = size as usize;
        if size < min_entry {
            break;
        }
        let Some(next): Option<usize> = entry_start.checked_add(size) else {
            break;
        };
        off = next;
    }

    methods
}

fn accumulate(raw: &BTreeMap<u64, RawClass>) -> Vec<DelphiClass> {
    let mut out: Vec<DelphiClass> = Vec::with_capacity(raw.len());
    for rc in raw.values() {
        let parent: Option<String> = rc
            .parent_va
            .and_then(|pv: u64| raw.get(&pv))
            .map(|p: &RawClass| p.name.clone());

        let mut properties: Vec<DelphiProperty> = rc.own_props.clone();
        let mut seen: std::collections::BTreeSet<String> = properties
            .iter()
            .map(|p: &DelphiProperty| p.name.clone())
            .collect();
        let mut visited: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        visited.insert(rc.va);
        let mut cursor: Option<u64> = rc.parent_va;
        let mut depth: usize = 0;
        while let Some(pv) = cursor {
            if depth >= MAX_PARENT_DEPTH || !visited.insert(pv) {
                break;
            }
            depth += 1;
            let Some(ancestor): Option<&RawClass> = raw.get(&pv) else {
                break;
            };
            for prop in &ancestor.own_props {
                if seen.insert(prop.name.clone()) {
                    properties.push(DelphiProperty {
                        name: prop.name.clone(),
                        type_name: prop.type_name.clone(),
                        inherited_from: Some(ancestor.name.clone()),
                    });
                }
            }
            cursor = ancestor.parent_va;
        }

        out.push(DelphiClass {
            name: rc.name.clone(),
            parent,
            unit_name: rc.unit_name.clone(),
            era: rc.era,
            instance_size: rc.instance_size,
            vmt_va: rc.va,
            properties,
            methods: rc.methods.clone(),
        });
    }
    out.sort_by(|a: &DelphiClass, b: &DelphiClass| {
        a.name.cmp(&b.name).then(a.vmt_va.cmp(&b.vmt_va))
    });
    out
}
