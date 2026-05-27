use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::macho::{self, ParsedSlice, Section};

pub const SEG_DATA: &str = "__DATA";
pub const SEG_DATA_CONST: &str = "__DATA_CONST";
pub const SEG_TEXT: &str = "__TEXT";

pub const SECT_OBJC_CLASSLIST: &str = "__objc_classlist";
pub const SECT_OBJC_CATLIST: &str = "__objc_catlist";
pub const SECT_OBJC_PROTOLIST: &str = "__objc_protolist";
pub const SECT_OBJC_METHNAME: &str = "__objc_methname";
pub const SECT_OBJC_METHTYPE: &str = "__objc_methtype";
pub const SECT_OBJC_CLASSNAME: &str = "__objc_classname";
pub const SECT_OBJC_SELREFS: &str = "__objc_selrefs";
pub const SECT_OBJC_CONST: &str = "__objc_const";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcPointerList {
    pub seg: String,
    pub name: String,
    pub pointer_count: usize,
    pub pointers: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcStringTable {
    pub seg: String,
    pub name: String,
    pub strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjcClassDump {
    pub classlist: Option<ObjcPointerList>,
    pub catlist: Option<ObjcPointerList>,
    pub protolist: Option<ObjcPointerList>,
    pub selectors: Option<ObjcStringTable>,
    pub method_types: Option<ObjcStringTable>,
    pub class_names: Option<ObjcStringTable>,
    pub selrefs_count: usize,
    pub class_count: usize,
    pub category_count: usize,
    pub protocol_count: usize,
    pub unique_selectors: BTreeSet<String>,
    pub unique_class_names: BTreeSet<String>,
    pub unique_method_types: BTreeSet<String>,
}

pub fn class_dump(slice: &[u8], parsed: &ParsedSlice) -> ObjcClassDump {
    let classlist: Option<ObjcPointerList> = section_pointers_any_seg(
        slice,
        parsed,
        &[SEG_DATA, SEG_DATA_CONST],
        SECT_OBJC_CLASSLIST,
    );
    let catlist: Option<ObjcPointerList> = section_pointers_any_seg(
        slice,
        parsed,
        &[SEG_DATA, SEG_DATA_CONST],
        SECT_OBJC_CATLIST,
    );
    let protolist: Option<ObjcPointerList> = section_pointers_any_seg(
        slice,
        parsed,
        &[SEG_DATA, SEG_DATA_CONST],
        SECT_OBJC_PROTOLIST,
    );
    let selrefs: Option<ObjcPointerList> = section_pointers_any_seg(
        slice,
        parsed,
        &[SEG_DATA, SEG_DATA_CONST],
        SECT_OBJC_SELREFS,
    );
    let selectors: Option<ObjcStringTable> =
        section_strings_any_seg(slice, parsed, &[SEG_TEXT], SECT_OBJC_METHNAME);
    let method_types: Option<ObjcStringTable> =
        section_strings_any_seg(slice, parsed, &[SEG_TEXT], SECT_OBJC_METHTYPE);
    let class_names: Option<ObjcStringTable> =
        section_strings_any_seg(slice, parsed, &[SEG_TEXT], SECT_OBJC_CLASSNAME);

    let selrefs_count: usize = selrefs
        .as_ref()
        .map_or(0, |s: &ObjcPointerList| s.pointer_count);
    let class_count: usize = classlist
        .as_ref()
        .map_or(0, |s: &ObjcPointerList| s.pointer_count);
    let category_count: usize = catlist
        .as_ref()
        .map_or(0, |s: &ObjcPointerList| s.pointer_count);
    let protocol_count: usize = protolist
        .as_ref()
        .map_or(0, |s: &ObjcPointerList| s.pointer_count);

    let unique_selectors: BTreeSet<String> = selectors
        .as_ref()
        .map(|t: &ObjcStringTable| t.strings.iter().cloned().collect())
        .unwrap_or_default();
    let unique_class_names: BTreeSet<String> = class_names
        .as_ref()
        .map(|t: &ObjcStringTable| t.strings.iter().cloned().collect())
        .unwrap_or_default();
    let unique_method_types: BTreeSet<String> = method_types
        .as_ref()
        .map(|t: &ObjcStringTable| t.strings.iter().cloned().collect())
        .unwrap_or_default();

    ObjcClassDump {
        classlist,
        catlist,
        protolist,
        selectors,
        method_types,
        class_names,
        selrefs_count,
        class_count,
        category_count,
        protocol_count,
        unique_selectors,
        unique_class_names,
        unique_method_types,
    }
}

fn section_pointers_any_seg(
    slice: &[u8],
    parsed: &ParsedSlice,
    segs: &[&str],
    name: &str,
) -> Option<ObjcPointerList> {
    for seg in segs {
        if let Some(s) = macho::find_section(parsed, seg, name) {
            return section_pointers_in(slice, s);
        }
    }
    None
}

fn section_strings_any_seg(
    slice: &[u8],
    parsed: &ParsedSlice,
    segs: &[&str],
    name: &str,
) -> Option<ObjcStringTable> {
    for seg in segs {
        if let Some(s) = macho::find_section(parsed, seg, name) {
            let bytes: &[u8] = macho::section_bytes(slice, s)?;
            return Some(ObjcStringTable {
                seg: (*seg).to_owned(),
                name: name.to_owned(),
                strings: split_cstrings(bytes),
            });
        }
    }
    None
}

fn section_pointers_in(slice: &[u8], section: &Section) -> Option<ObjcPointerList> {
    let bytes: &[u8] = macho::section_bytes(slice, section)?;
    let count: usize = bytes.len() / 8;
    let mut pointers: Vec<u64> = Vec::with_capacity(count);
    for i in 0..count {
        let off: usize = i * 8;
        let mut arr: [u8; 8] = [0u8; 8];
        arr.copy_from_slice(&bytes[off..off + 8]);
        pointers.push(u64::from_le_bytes(arr));
    }
    Some(ObjcPointerList {
        seg: section.seg.clone(),
        name: section.name.clone(),
        pointer_count: count,
        pointers,
    })
}

fn split_cstrings(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == 0 {
            if i > start {
                let chunk: &[u8] = &bytes[start..i];
                if let Ok(s) = std::str::from_utf8(chunk) {
                    out.push(s.to_owned());
                }
            }
            start = i + 1;
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorIndex {
    pub by_class_hint: BTreeMap<String, Vec<String>>,
    pub setters: BTreeSet<String>,
    pub getters: BTreeSet<String>,
    pub init_family: BTreeSet<String>,
    pub copy_family: BTreeSet<String>,
}

#[must_use]
pub fn index_selectors(dump: &ObjcClassDump) -> SelectorIndex {
    let mut by_class_hint: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut setters: BTreeSet<String> = BTreeSet::new();
    let mut getters: BTreeSet<String> = BTreeSet::new();
    let mut init_family: BTreeSet<String> = BTreeSet::new();
    let mut copy_family: BTreeSet<String> = BTreeSet::new();
    for sel in &dump.unique_selectors {
        if sel.starts_with("set")
            && sel.ends_with(':')
            && sel
                .as_bytes()
                .get(3)
                .is_some_and(|b: &u8| b.is_ascii_uppercase())
        {
            setters.insert(sel.clone());
            continue;
        }
        if sel.starts_with("init") {
            init_family.insert(sel.clone());
        }
        if sel.starts_with("copy") || sel.starts_with("mutableCopy") {
            copy_family.insert(sel.clone());
        }
        if !sel.contains(':') && !sel.is_empty() {
            getters.insert(sel.clone());
        }
        for class_name in &dump.unique_class_names {
            if sel.contains(class_name.as_str()) {
                by_class_hint
                    .entry(class_name.clone())
                    .or_default()
                    .push(sel.clone());
            }
        }
    }
    SelectorIndex {
        by_class_hint,
        setters,
        getters,
        init_family,
        copy_family,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn split_cstrings_handles_multiple_nuls() {
        let bytes: &[u8] = b"foo\0bar\0\0baz\0";
        let out: Vec<String> = split_cstrings(bytes);
        assert_eq!(
            out,
            vec!["foo".to_owned(), "bar".to_owned(), "baz".to_owned()]
        );
    }

    #[test]
    fn index_selectors_classifies_setter_and_getter() {
        let dump: ObjcClassDump = ObjcClassDump {
            classlist: None,
            catlist: None,
            protolist: None,
            selectors: None,
            method_types: None,
            class_names: None,
            selrefs_count: 0,
            class_count: 0,
            category_count: 0,
            protocol_count: 0,
            unique_selectors: ["setName:", "name", "initWithFoo:", "copyZone"]
                .iter()
                .map(|s: &&str| (*s).to_owned())
                .collect(),
            unique_class_names: BTreeSet::new(),
            unique_method_types: BTreeSet::new(),
        };
        let idx: SelectorIndex = index_selectors(&dump);
        assert!(idx.setters.contains("setName:"));
        assert!(idx.getters.contains("name"));
        assert!(idx.init_family.contains("initWithFoo:"));
        assert!(idx.copy_family.contains("copyZone"));
    }
}
