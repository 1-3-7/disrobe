use serde::{Deserialize, Serialize};

use crate::macho::{self, ParsedSlice, SliceView};

const FAST_DATA_MASK: u64 = macho::FAST_DATA_MASK;
const RO_META: u32 = 0x1;
const SMALL_METHOD_LIST_FLAG: u32 = 0x8000_0000;
const ENTSIZE_MASK: u32 = 0xffff_0003;
const METHOD_T_BIG: usize = 24;
const METHOD_T_SMALL: usize = 12;
const IVAR_T_SIZE: usize = 32;
const PROPERTY_T_SIZE: usize = 16;
const RO_NAME_OFF: usize = 0x18;
const RO_BASE_METHODS_OFF: usize = 0x20;
const RO_IVARS_OFF: usize = 0x30;
const RO_BASE_PROPS_OFF: usize = 0x40;
const CLASS_SUPERCLASS_OFF: usize = 0x08;
const CLASS_DATA_OFF: usize = 0x20;
const MAX_LIST_COUNT: usize = 1 << 18;
const MAX_CLASSES: usize = 1 << 16;
const MAX_CSTR: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjcMethod {
    pub name: String,
    pub types: Option<String>,
    pub is_class_method: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjcIvar {
    pub name: String,
    pub type_encoding: Option<String>,
    pub offset: Option<u32>,
    pub size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjcProperty {
    pub name: String,
    pub attributes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjcInterface {
    pub name: String,
    pub superclass: Option<String>,
    pub instance_methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub ivars: Vec<ObjcIvar>,
    pub properties: Vec<ObjcProperty>,
}

impl ObjcInterface {
    #[must_use]
    pub fn render(&self) -> String {
        let mut out: String = String::new();
        let superclass: &str = self.superclass.as_deref().unwrap_or("NSObject");
        out.push_str("@interface ");
        out.push_str(&self.name);
        out.push_str(" : ");
        out.push_str(superclass);
        out.push('\n');
        if !self.ivars.is_empty() {
            out.push_str("{\n");
            for ivar in &self.ivars {
                let enc: &str = ivar.type_encoding.as_deref().unwrap_or("?");
                out.push_str("    id ");
                out.push_str(&ivar.name);
                out.push_str("; // enc=");
                out.push_str(enc);
                out.push('\n');
            }
            out.push_str("}\n");
        }
        for prop in &self.properties {
            let attrs: &str = prop.attributes.as_deref().unwrap_or("");
            out.push_str("@property (");
            out.push_str(attrs);
            out.push_str(") ");
            out.push_str(&prop.name);
            out.push_str(";\n");
        }
        for m in &self.class_methods {
            let types: &str = m.types.as_deref().unwrap_or("");
            out.push_str("+ (");
            out.push_str(types);
            out.push(')');
            out.push_str(&m.name);
            out.push_str("; \n");
        }
        for m in &self.instance_methods {
            let types: &str = m.types.as_deref().unwrap_or("");
            out.push_str("- (");
            out.push_str(types);
            out.push(')');
            out.push_str(&m.name);
            out.push_str("; \n");
        }
        out.push_str("@end\n");
        out
    }
}

fn read_entsize_list_header(view: &SliceView<'_>, off: usize) -> Option<(u32, usize)> {
    let raw_entsize: u32 = view.read_u32_at(off)?;
    let count: u32 = view.read_u32_at(off + 4)?;
    let count_usize: usize = count as usize;
    if count_usize > MAX_LIST_COUNT {
        return None;
    }
    Some((raw_entsize, count_usize))
}

fn parse_methods(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    list_vmaddr: u64,
    is_class: bool,
) -> Vec<ObjcMethod> {
    let mut out: Vec<ObjcMethod> = Vec::new();
    let Some(list_off): Option<usize> = macho::vmaddr_to_offset(parsed, list_vmaddr) else {
        return out;
    };
    let Some((raw_entsize, count)): Option<(u32, usize)> = read_entsize_list_header(view, list_off)
    else {
        return out;
    };
    let is_small: bool = raw_entsize & SMALL_METHOD_LIST_FLAG != 0;
    let entsize: usize = (raw_entsize & !ENTSIZE_MASK) as usize;
    let elem_size: usize = if entsize == 0 {
        if is_small {
            METHOD_T_SMALL
        } else {
            METHOD_T_BIG
        }
    } else {
        entsize
    };
    let elems_base: usize = list_off + 8;
    out.reserve(count.min(MAX_LIST_COUNT));
    for i in 0..count {
        let elem_off: usize = elems_base + i * elem_size;
        let method: Option<ObjcMethod> = if is_small {
            parse_small_method(view, parsed, elem_off, is_class)
        } else {
            parse_big_method(view, parsed, elem_off, is_class)
        };
        if let Some(m) = method {
            out.push(m);
        }
    }
    out
}

fn parse_small_method(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    elem_off: usize,
    is_class: bool,
) -> Option<ObjcMethod> {
    let name_rel: i32 = view.read_u32_at(elem_off)? as i32;
    let types_rel: i32 = view.read_u32_at(elem_off + 4)? as i32;
    let name_ptr_off: usize = apply_rel(elem_off, name_rel)?;
    let sel_vmaddr: u64 = view.read_u64_at(name_ptr_off)?;
    let sel_decoded: u64 = macho::decode_bound_pointer(sel_vmaddr, view.base());
    let name: String = view.cstr_at_vmaddr(parsed, sel_decoded, MAX_CSTR)?;
    let types_off: usize = apply_rel(elem_off + 4, types_rel)?;
    let types: Option<String> = view.cstr_at_offset(types_off, MAX_CSTR);
    Some(ObjcMethod {
        name,
        types,
        is_class_method: is_class,
    })
}

fn parse_big_method(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    elem_off: usize,
    is_class: bool,
) -> Option<ObjcMethod> {
    let name_ptr: u64 = view.read_pointer_at(parsed, elem_off)?;
    let name: String = view.cstr_at_vmaddr(parsed, name_ptr, MAX_CSTR)?;
    let types: Option<String> = view
        .read_pointer_at(parsed, elem_off + 8)
        .and_then(|p: u64| view.cstr_at_vmaddr(parsed, p, MAX_CSTR));
    Some(ObjcMethod {
        name,
        types,
        is_class_method: is_class,
    })
}

fn parse_ivars(view: &SliceView<'_>, parsed: &ParsedSlice, list_vmaddr: u64) -> Vec<ObjcIvar> {
    let mut out: Vec<ObjcIvar> = Vec::new();
    let Some(list_off): Option<usize> = macho::vmaddr_to_offset(parsed, list_vmaddr) else {
        return out;
    };
    let Some((raw_entsize, count)): Option<(u32, usize)> = read_entsize_list_header(view, list_off)
    else {
        return out;
    };
    let entsize: usize = (raw_entsize & !ENTSIZE_MASK) as usize;
    let elem_size: usize = if entsize == 0 { IVAR_T_SIZE } else { entsize };
    let elems_base: usize = list_off + 8;
    out.reserve(count.min(MAX_LIST_COUNT));
    for i in 0..count {
        let elem_off: usize = elems_base + i * elem_size;
        let Some(name_ptr): Option<u64> = view.read_pointer_at(parsed, elem_off + 8) else {
            continue;
        };
        let Some(name): Option<String> = view.cstr_at_vmaddr(parsed, name_ptr, MAX_CSTR) else {
            continue;
        };
        let type_encoding: Option<String> = view
            .read_pointer_at(parsed, elem_off + 16)
            .and_then(|p: u64| view.cstr_at_vmaddr(parsed, p, MAX_CSTR));
        let offset: Option<u32> = view
            .read_pointer_at(parsed, elem_off)
            .and_then(|p: u64| macho::vmaddr_to_offset(parsed, p))
            .and_then(|o: usize| view.read_u32_at(o));
        let size: Option<u32> = view.read_u32_at(elem_off + 28);
        out.push(ObjcIvar {
            name,
            type_encoding,
            offset,
            size,
        });
    }
    out
}

fn parse_properties(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    list_vmaddr: u64,
) -> Vec<ObjcProperty> {
    let mut out: Vec<ObjcProperty> = Vec::new();
    let Some(list_off): Option<usize> = macho::vmaddr_to_offset(parsed, list_vmaddr) else {
        return out;
    };
    let Some((raw_entsize, count)): Option<(u32, usize)> = read_entsize_list_header(view, list_off)
    else {
        return out;
    };
    let entsize: usize = (raw_entsize & !ENTSIZE_MASK) as usize;
    let elem_size: usize = if entsize == 0 {
        PROPERTY_T_SIZE
    } else {
        entsize
    };
    let elems_base: usize = list_off + 8;
    out.reserve(count.min(MAX_LIST_COUNT));
    for i in 0..count {
        let elem_off: usize = elems_base + i * elem_size;
        let Some(name_ptr): Option<u64> = view.read_pointer_at(parsed, elem_off) else {
            continue;
        };
        let Some(name): Option<String> = view.cstr_at_vmaddr(parsed, name_ptr, MAX_CSTR) else {
            continue;
        };
        let attributes: Option<String> = view
            .read_pointer_at(parsed, elem_off + 8)
            .and_then(|p: u64| view.cstr_at_vmaddr(parsed, p, MAX_CSTR));
        out.push(ObjcProperty { name, attributes });
    }
    out
}

#[derive(Debug)]
struct ParsedClassRo {
    name: String,
    superclass: Option<String>,
    methods: Vec<ObjcMethod>,
    ivars: Vec<ObjcIvar>,
    properties: Vec<ObjcProperty>,
}

fn parse_class_ro(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    class_vmaddr: u64,
) -> Option<ParsedClassRo> {
    let class_off: usize = macho::vmaddr_to_offset(parsed, class_vmaddr)?;
    let bits: u64 = view.read_u64_at(class_off + CLASS_DATA_OFF)?;
    let data_vmaddr: u64 = macho::decode_bound_pointer(bits & FAST_DATA_MASK, view.base());
    let ro_off: usize = macho::vmaddr_to_offset(parsed, data_vmaddr)?;
    let flags: u32 = view.read_u32_at(ro_off)?;
    let is_meta: bool = flags & RO_META != 0;
    let name_ptr: u64 = view.read_pointer_at(parsed, ro_off + RO_NAME_OFF)?;
    let name: String = view.cstr_at_vmaddr(parsed, name_ptr, MAX_CSTR)?;

    let methods: Vec<ObjcMethod> = view
        .read_pointer_at(parsed, ro_off + RO_BASE_METHODS_OFF)
        .map(|p: u64| parse_methods(view, parsed, p, is_meta))
        .unwrap_or_default();
    let ivars: Vec<ObjcIvar> = view
        .read_pointer_at(parsed, ro_off + RO_IVARS_OFF)
        .map(|p: u64| parse_ivars(view, parsed, p))
        .unwrap_or_default();
    let properties: Vec<ObjcProperty> = view
        .read_pointer_at(parsed, ro_off + RO_BASE_PROPS_OFF)
        .map(|p: u64| parse_properties(view, parsed, p))
        .unwrap_or_default();

    let superclass: Option<String> = view
        .read_pointer_at(parsed, class_off + CLASS_SUPERCLASS_OFF)
        .and_then(|p: u64| macho::vmaddr_to_offset(parsed, p))
        .and_then(|super_off: usize| {
            let super_bits: u64 = view.read_u64_at(super_off + CLASS_DATA_OFF)?;
            let super_data: u64 =
                macho::decode_bound_pointer(super_bits & FAST_DATA_MASK, view.base());
            let super_ro: usize = macho::vmaddr_to_offset(parsed, super_data)?;
            let super_name_ptr: u64 = view.read_pointer_at(parsed, super_ro + RO_NAME_OFF)?;
            view.cstr_at_vmaddr(parsed, super_name_ptr, MAX_CSTR)
        });

    Some(ParsedClassRo {
        name,
        superclass,
        methods,
        ivars,
        properties,
    })
}

#[must_use]
pub fn recover_interfaces(
    slice: &[u8],
    parsed: &ParsedSlice,
    classlist_pointers: &[u64],
) -> Vec<ObjcInterface> {
    let Some(view): Option<SliceView<'_>> = SliceView::new(slice, parsed) else {
        return Vec::new();
    };
    let cap: usize = classlist_pointers.len().min(MAX_CLASSES);
    let mut out: Vec<ObjcInterface> = Vec::with_capacity(cap);
    for raw in classlist_pointers.iter().take(MAX_CLASSES) {
        let class_vmaddr: u64 = macho::decode_bound_pointer(*raw, view.base());
        if class_vmaddr == 0 {
            continue;
        }
        let Some(ro): Option<ParsedClassRo> = parse_class_ro(&view, parsed, class_vmaddr) else {
            continue;
        };
        let class_methods: Vec<ObjcMethod> =
            class_methods_via_metaclass(&view, parsed, class_vmaddr);
        out.push(ObjcInterface {
            name: ro.name,
            superclass: ro.superclass,
            instance_methods: ro.methods,
            class_methods,
            ivars: ro.ivars,
            properties: ro.properties,
        });
    }
    out
}

fn class_methods_via_metaclass(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    class_vmaddr: u64,
) -> Vec<ObjcMethod> {
    let Some(class_off): Option<usize> = macho::vmaddr_to_offset(parsed, class_vmaddr) else {
        return Vec::new();
    };
    let Some(meta_vmaddr): Option<u64> = view.read_pointer_at(parsed, class_off) else {
        return Vec::new();
    };
    parse_class_ro(view, parsed, meta_vmaddr)
        .map(|ro: ParsedClassRo| ro.methods)
        .unwrap_or_default()
}

#[inline]
fn apply_rel(base_off: usize, rel: i32) -> Option<usize> {
    let signed: i64 = i64::try_from(base_off).ok()? + i64::from(rel);
    usize::try_from(signed).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::macho::{
        Bitness, CpuKind, Endian, ParsedSlice, Section, Segment, SliceHeader, SliceView,
    };

    const SEG_VMADDR: u64 = 0x1000;
    const NAME_VMADDR: u64 = 0x1000;
    const IVAR_LIST_VMADDR: u64 = 0x1010;

    fn single_segment_slice() -> ParsedSlice {
        ParsedSlice {
            header: SliceHeader {
                cpu: CpuKind::Arm64,
                bitness: Bitness::Bits64,
                endian: Endian::Little,
                ncmds: 0,
                sizeofcmds: 0,
                filetype: 0,
                flags: 0,
            },
            segments: vec![Segment {
                name: "__TEXT".to_owned(),
                vmaddr: SEG_VMADDR,
                vmsize: 0x1000,
                fileoff: 0,
                filesize: 0x1000,
                sections: Vec::<Section>::new(),
            }],
            ..ParsedSlice::default()
        }
    }

    fn ivar_list_bytes(include_size_field: bool) -> Vec<u8> {
        let list_off: usize = (IVAR_LIST_VMADDR - SEG_VMADDR) as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(list_off + 32);
        buf.extend_from_slice(b"_count\0");
        buf.resize(list_off, 0);
        buf.extend_from_slice(&IVAR_T_SIZE.to_le_bytes()[..4]);
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&NAME_VMADDR.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        if include_size_field {
            buf.extend_from_slice(&8u32.to_le_bytes());
        }
        buf
    }

    #[test]
    fn truncated_ivar_size_field_is_none_not_zero() {
        let parsed: ParsedSlice = single_segment_slice();
        let bytes: Vec<u8> = ivar_list_bytes(false);
        let view: SliceView<'_> = SliceView::new(&bytes, &parsed).expect("view");
        let ivars: Vec<ObjcIvar> = parse_ivars(&view, &parsed, IVAR_LIST_VMADDR);
        let ivar: &ObjcIvar = ivars.first().expect("one recovered ivar");
        assert_eq!(ivar.name, "_count");
        assert_eq!(
            ivar.size, None,
            "an unreadable ivar size must be honestly absent, never a fabricated 0"
        );
    }

    #[test]
    fn readable_ivar_size_field_is_some() {
        let parsed: ParsedSlice = single_segment_slice();
        let bytes: Vec<u8> = ivar_list_bytes(true);
        let view: SliceView<'_> = SliceView::new(&bytes, &parsed).expect("view");
        let ivars: Vec<ObjcIvar> = parse_ivars(&view, &parsed, IVAR_LIST_VMADDR);
        let ivar: &ObjcIvar = ivars.first().expect("one recovered ivar");
        assert_eq!(ivar.name, "_count");
        assert_eq!(ivar.size, Some(8));
    }

    #[test]
    fn apply_rel_handles_negative() {
        assert_eq!(apply_rel(100, -40), Some(60));
        assert_eq!(apply_rel(100, 40), Some(140));
        assert_eq!(apply_rel(0, -1), None);
    }

    #[test]
    fn render_emits_interface_block() {
        let iface: ObjcInterface = ObjcInterface {
            name: "Foo".to_owned(),
            superclass: Some("NSObject".to_owned()),
            instance_methods: vec![ObjcMethod {
                name: "doThing:".to_owned(),
                types: Some("v16@0:8".to_owned()),
                is_class_method: false,
            }],
            class_methods: Vec::new(),
            ivars: vec![ObjcIvar {
                name: "_count".to_owned(),
                type_encoding: Some("q".to_owned()),
                offset: Some(8),
                size: Some(8),
            }],
            properties: Vec::new(),
        };
        let rendered: String = iface.render();
        assert!(rendered.contains("@interface Foo : NSObject"));
        assert!(rendered.contains("doThing:"));
        assert!(rendered.contains("_count"));
        assert!(rendered.trim_end().ends_with("@end"));
    }
}
