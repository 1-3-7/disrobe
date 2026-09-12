use std::collections::BTreeMap;

use crate::metadata::{MetadataRoot, StreamHeader, read_strings_heap, read_us_heap_strings};
use crate::model::{AssemblyModel, MethodModel, TypeModel};
use crate::pe::{ClrHeader, PeImage};

fn fnv_masked(s: &str) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for c in s.chars() {
        h ^= u32::from(c);
        h = h.wrapping_mul(16_777_619);
    }
    h & 0x0FFF_FFFF
}

#[must_use]
pub fn member_id(name: &str) -> i32 {
    (fnv_masked(name) | 0x4000_0000).cast_signed()
}

#[must_use]
pub fn string_id(s: &str) -> i32 {
    (fnv_masked(s) | 0x2000_0000).cast_signed()
}

#[derive(Debug, Clone, Default)]
pub struct NameTable {
    member_by_id: BTreeMap<i32, String>,
    string_by_id: BTreeMap<i32, String>,
}

impl NameTable {
    #[must_use]
    pub fn resolve_member(&self, id: i32) -> Option<&str> {
        self.member_by_id.get(&id).map(String::as_str)
    }

    #[must_use]
    pub fn resolve_string(&self, id: i32) -> Option<&str> {
        self.string_by_id.get(&id).map(String::as_str)
    }
}

#[must_use]
pub fn build_name_table(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
    root: &MetadataRoot,
    model: &AssemblyModel,
) -> NameTable {
    let mut member_by_id: BTreeMap<i32, String> = BTreeMap::new();
    for ty in &model.types {
        collect_member_names(ty, &mut member_by_id);
    }

    let mut string_by_id: BTreeMap<i32, String> = BTreeMap::new();
    for literal in user_strings(image, pe, clr, root) {
        string_by_id.entry(string_id(&literal)).or_insert(literal);
    }
    let _ = read_strings_heap;

    NameTable {
        member_by_id,
        string_by_id,
    }
}

fn collect_member_names(ty: &TypeModel, out: &mut BTreeMap<i32, String>) {
    for method in &ty.methods {
        record_name(&method.name, out);
        record_method_full(ty, method, out);
    }
    for field in &ty.fields {
        record_name(&field.name, out);
    }
}

fn record_method_full(ty: &TypeModel, method: &MethodModel, out: &mut BTreeMap<i32, String>) {
    let full: String = format!("{}::{}", ty.full_name, method.name);
    out.entry(member_id(&full)).or_insert(full);
}

fn record_name(name: &str, out: &mut BTreeMap<i32, String>) {
    if name.is_empty() {
        return;
    }
    out.entry(member_id(name))
        .or_insert_with(|| name.to_string());
}

fn user_strings(image: &[u8], pe: &PeImage, clr: &ClrHeader, root: &MetadataRoot) -> Vec<String> {
    let Ok(metadata): Result<&[u8], _> =
        pe.slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)
    else {
        return Vec::new();
    };
    let Some(us_header): Option<&StreamHeader> = root.streams.get("#US") else {
        return Vec::new();
    };
    read_us_heap_strings(metadata, *us_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_and_string_ids_carry_tags() {
        assert!(member_id("Add") & 0x4000_0000 != 0);
        assert!(string_id("hello") & 0x2000_0000 != 0);
        assert_ne!(member_id("Add"), member_id("Sub"));
    }
}
