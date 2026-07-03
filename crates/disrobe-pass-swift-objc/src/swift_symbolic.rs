use crate::macho::{MangledName, SliceView, SymbolicRef};

const RELATIVE_PTR_WORD: usize = 4;
const TYPE_CONTEXT_KIND_MASK: u32 = 0x1F;
const CONTEXT_KIND_MODULE: u32 = 0x00;
const CONTEXT_KIND_EXTENSION: u32 = 0x01;
const CONTEXT_KIND_PROTOCOL: u32 = 0x03;
const CONTEXT_KIND_CLASS: u32 = 0x10;
const CONTEXT_KIND_STRUCT: u32 = 0x11;
const CONTEXT_KIND_ENUM: u32 = 0x12;
const MAX_NAME_LEN: usize = 4096;
const MAX_PARENT_WALK: usize = 16;

const fn nominal_tag(kind: u32) -> Option<&'static str> {
    match kind {
        CONTEXT_KIND_CLASS => Some("C"),
        CONTEXT_KIND_STRUCT => Some("V"),
        CONTEXT_KIND_ENUM => Some("O"),
        CONTEXT_KIND_PROTOCOL => Some("P"),
        _ => None,
    }
}

fn descriptor_name(view: &SliceView<'_>, descriptor_off: usize) -> Option<String> {
    let name_field: usize = descriptor_off + 2 * RELATIVE_PTR_WORD;
    view.resolve_relative(name_field)
        .and_then(|t: usize| view.cstr_at_offset(t, MAX_NAME_LEN))
        .filter(|s: &String| !s.is_empty() && s.bytes().all(|b: u8| b >= 0x20))
}

fn synthesize_nominal_mangling(view: &SliceView<'_>, descriptor_off: usize) -> Option<String> {
    let flags: u32 = view.read_u32_at(descriptor_off)?;
    let kind: u32 = flags & TYPE_CONTEXT_KIND_MASK;
    let tag: &str = nominal_tag(kind)?;

    let mut segments: Vec<String> = Vec::new();
    let leaf_name: String = descriptor_name(view, descriptor_off)?;
    segments.push(leaf_name);

    let mut cursor: usize = descriptor_off;
    let mut guard: usize = 0;
    loop {
        if guard >= MAX_PARENT_WALK {
            break;
        }
        guard += 1;
        let parent_field: usize = cursor + RELATIVE_PTR_WORD;
        let Some((parent_off, indirect)): Option<(usize, bool)> =
            view.resolve_indirectable_relative(parent_field)
        else {
            break;
        };
        if indirect {
            return None;
        }
        let Some(parent_flags): Option<u32> = view.read_u32_at(parent_off) else {
            break;
        };
        let parent_kind: u32 = parent_flags & TYPE_CONTEXT_KIND_MASK;
        if parent_kind == CONTEXT_KIND_EXTENSION {
            return None;
        }
        let Some(pname): Option<String> = descriptor_name(view, parent_off) else {
            break;
        };
        segments.push(pname);
        if parent_kind == CONTEXT_KIND_MODULE {
            break;
        }
        cursor = parent_off;
    }

    segments.reverse();
    let mut out: String = String::new();
    for seg in &segments {
        let count: usize = seg.chars().count();
        out.push_str(&count.to_string());
        out.push_str(seg);
    }
    out.push_str(tag);
    Some(out)
}

fn resolve_one(view: &SliceView<'_>, symref: &SymbolicRef) -> Option<String> {
    match symref.kind {
        0x01 => synthesize_nominal_mangling(view, symref.target),
        0x02 => {
            let descriptor_off: usize = view.resolve_relative(symref.target)?;
            synthesize_nominal_mangling(view, descriptor_off)
        }
        _ => None,
    }
}

#[must_use]
pub fn resolve_to_plain_mangling(view: &SliceView<'_>, name: &MangledName) -> Option<String> {
    if name.refs.is_empty() {
        return name.as_plain_string();
    }
    let mut out: Vec<u8> = Vec::with_capacity(name.raw.len());
    let mut ref_iter: std::slice::Iter<'_, SymbolicRef> = name.refs.iter();
    let mut pending: Option<&SymbolicRef> = ref_iter.next();
    for (idx, &byte) in name.raw.iter().enumerate() {
        if let Some(symref) = pending
            && symref.raw_index == idx
        {
            let synthesized: String = resolve_one(view, symref)?;
            out.extend_from_slice(synthesized.as_bytes());
            pending = ref_iter.next();
            continue;
        }
        out.push(byte);
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn nominal_tag_maps_kinds() {
        assert_eq!(nominal_tag(CONTEXT_KIND_CLASS), Some("C"));
        assert_eq!(nominal_tag(CONTEXT_KIND_STRUCT), Some("V"));
        assert_eq!(nominal_tag(CONTEXT_KIND_ENUM), Some("O"));
        assert_eq!(nominal_tag(CONTEXT_KIND_PROTOCOL), Some("P"));
        assert_eq!(nominal_tag(0x07), None);
    }
}
