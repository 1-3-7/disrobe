use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

const CLASS_SUFFIX: &str = "_Cls";
const KEYWORD_SUFFIX: &str = "_";

const JAVA_RESERVED: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
    "_",
];

#[must_use]
fn is_reserved(token: &str) -> bool {
    JAVA_RESERVED.binary_search(&token).is_ok()
}

#[derive(Debug, Clone, Default)]
pub struct NameDisambiguator {
    class_renames: BTreeMap<String, String>,
    all_names: BTreeSet<String>,
}

impl NameDisambiguator {
    #[must_use]
    pub fn build<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let all_names: BTreeSet<String> = names
            .into_iter()
            .map(|s: S| s.as_ref().to_string())
            .collect();

        let package_prefixes: BTreeSet<&str> = collect_package_prefixes(&all_names);
        let mut taken: BTreeSet<String> = all_names.clone();
        let mut class_renames: BTreeMap<String, String> = BTreeMap::new();

        let mut ordered: Vec<&String> = all_names.iter().collect();
        ordered.sort_unstable();

        for name in ordered {
            let collides_as_package: bool = package_prefixes.contains(name.as_str());
            let leaf: &str = name.rsplit('/').next().unwrap_or(name.as_str());
            let leaf_reserved: bool = is_reserved(leaf);
            if !collides_as_package && !leaf_reserved {
                continue;
            }
            let parent: &str = name.rfind('/').map_or("", |p: usize| &name[..p]);
            let base_suffix: &str = if collides_as_package {
                CLASS_SUFFIX
            } else {
                KEYWORD_SUFFIX
            };
            let renamed: String =
                unique_renamed(parent, leaf, base_suffix, &taken, &package_prefixes);
            taken.insert(renamed.clone());
            class_renames.insert(name.clone(), renamed);
        }

        Self {
            class_renames,
            all_names,
        }
    }

    #[must_use]
    pub fn rewrite(&self, binary: &str) -> String {
        if let Some(renamed) = self.class_renames.get(binary) {
            return renamed.clone();
        }
        binary.to_string()
    }

    #[must_use]
    pub fn rename_count(&self) -> usize {
        self.class_renames.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.class_renames.is_empty()
    }

    #[must_use]
    pub fn contains(&self, binary: &str) -> bool {
        self.all_names.contains(binary)
    }

    #[must_use]
    fn as_scope(&self) -> RenameScope {
        RenameScope {
            map: self.class_renames.clone(),
        }
    }
}

fn collect_package_prefixes(all_names: &BTreeSet<String>) -> BTreeSet<&str> {
    let mut prefixes: BTreeSet<&str> = BTreeSet::new();
    for name in all_names {
        let mut start: usize = 0;
        while let Some(rel) = name[start..].find('/') {
            let cut: usize = start + rel;
            prefixes.insert(&name[..cut]);
            start = cut + 1;
        }
    }
    prefixes
}

fn unique_renamed(
    parent: &str,
    leaf: &str,
    base_suffix: &str,
    taken: &BTreeSet<String>,
    package_prefixes: &BTreeSet<&str>,
) -> String {
    let mut attempt: usize = 0;
    loop {
        let leaf_candidate: String = if attempt == 0 {
            format!("{leaf}{base_suffix}")
        } else {
            format!("{leaf}{base_suffix}{attempt}")
        };
        let full: String = if parent.is_empty() {
            leaf_candidate.clone()
        } else {
            format!("{parent}/{leaf_candidate}")
        };
        let clashes: bool = taken.contains(&full)
            || package_prefixes.contains(full.as_str())
            || is_reserved(&leaf_candidate);
        if !clashes {
            return full;
        }
        attempt += 1;
    }
}

#[derive(Debug, Clone, Default)]
struct RenameScope {
    map: BTreeMap<String, String>,
}

thread_local! {
    static ACTIVE_SCOPE: RefCell<Option<RenameScope>> = const { RefCell::new(None) };
}

pub fn with_rename_scope<T>(disambiguator: &NameDisambiguator, body: impl FnOnce() -> T) -> T {
    install_scope(disambiguator.as_scope(), body)
}

pub fn with_self_rename_scope<T>(
    disambiguator: &NameDisambiguator,
    this_binary: &str,
    body: impl FnOnce() -> T,
) -> T {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let renamed: String = disambiguator.rewrite(this_binary);
    if renamed != this_binary {
        map.insert(this_binary.to_string(), renamed);
    }
    install_scope(RenameScope { map }, body)
}

fn install_scope<T>(scope: RenameScope, body: impl FnOnce() -> T) -> T {
    ACTIVE_SCOPE.with(|slot: &RefCell<Option<RenameScope>>| {
        let prev: Option<RenameScope> = slot.borrow_mut().replace(scope);
        let result: T = body();
        *slot.borrow_mut() = prev;
        result
    })
}

#[must_use]
pub fn rewrite_active(binary: &str) -> String {
    ACTIVE_SCOPE.with(
        |slot: &RefCell<Option<RenameScope>>| match &*slot.borrow() {
            Some(scope) => scope
                .map
                .get(binary)
                .cloned()
                .unwrap_or_else(|| binary.to_string()),
            None => binary.to_string(),
        },
    )
}

#[must_use]
pub fn remap_class_bytes(disambiguator: &NameDisambiguator, bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 10 || bytes[0..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
        return None;
    }
    let cp_count: usize = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
    if cp_count == 0 {
        return None;
    }

    let mut pos: usize = 10;
    let mut entries: Vec<CpEntry> = Vec::with_capacity(cp_count);
    let mut class_name_utf8: BTreeSet<usize> = BTreeSet::new();
    let mut descriptor_utf8: BTreeSet<usize> = BTreeSet::new();
    let mut i: usize = 1;
    while i < cp_count {
        let start: usize = pos;
        let tag: u8 = *bytes.get(pos)?;
        pos += 1;
        let (entry, wide): (CpEntry, bool) = match tag {
            1 => {
                let len: usize =
                    usize::from(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]));
                pos += 2;
                let raw: &[u8] = bytes.get(pos..pos + len)?;
                pos += len;
                let text: String = String::from_utf8_lossy(raw).into_owned();
                (CpEntry::Utf8 { index: i, text }, false)
            }
            7 => {
                let name_index: usize =
                    usize::from(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]));
                pos += 2;
                class_name_utf8.insert(name_index);
                (CpEntry::Raw, false)
            }
            12 => {
                let descriptor_index: usize = usize::from(u16::from_be_bytes([
                    *bytes.get(pos + 2)?,
                    *bytes.get(pos + 3)?,
                ]));
                pos += 4;
                descriptor_utf8.insert(descriptor_index);
                (CpEntry::Raw, false)
            }
            16 => {
                let descriptor_index: usize =
                    usize::from(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]));
                pos += 2;
                descriptor_utf8.insert(descriptor_index);
                (CpEntry::Raw, false)
            }
            3 | 4 | 9 | 10 | 11 | 17 | 18 => {
                pos += 4;
                (CpEntry::Raw, false)
            }
            8 | 19 | 20 => {
                pos += 2;
                (CpEntry::Raw, false)
            }
            15 => {
                pos += 3;
                (CpEntry::Raw, false)
            }
            5 | 6 => {
                pos += 8;
                (CpEntry::Raw, true)
            }
            _ => return None,
        };
        let span: &[u8] = bytes.get(start..pos)?;
        entries.push(CpEntry::with_bytes(entry, span));
        i += if wide { 2 } else { 1 };
    }

    let field_method_descriptors: BTreeSet<usize> = scan_member_descriptor_indices(bytes, pos)?;

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 64);
    out.extend_from_slice(&bytes[0..10]);
    for entry in &entries {
        match entry {
            CpEntry::Utf8Bytes { index, text, raw } => {
                let is_class_name: bool = class_name_utf8.contains(index);
                let is_descriptor: bool =
                    descriptor_utf8.contains(index) || field_method_descriptors.contains(index);
                let rewritten: Option<String> = if is_class_name {
                    let renamed: String = disambiguator.rewrite(text);
                    (renamed != *text).then_some(renamed)
                } else if is_descriptor {
                    rewrite_descriptor(disambiguator, text)
                } else {
                    None
                };
                match rewritten {
                    Some(new_text) => {
                        let new_bytes: &[u8] = new_text.as_bytes();
                        out.push(1);
                        out.extend_from_slice(&(new_bytes.len() as u16).to_be_bytes());
                        out.extend_from_slice(new_bytes);
                    }
                    None => out.extend_from_slice(raw),
                }
            }
            CpEntry::RawBytes(raw) => out.extend_from_slice(raw),
            CpEntry::Utf8 { .. } | CpEntry::Raw => {}
        }
    }
    out.extend_from_slice(&bytes[pos..]);
    Some(out)
}

#[derive(Debug, Clone)]
enum CpEntry {
    Utf8 {
        index: usize,
        text: String,
    },
    Raw,
    Utf8Bytes {
        index: usize,
        text: String,
        raw: Vec<u8>,
    },
    RawBytes(Vec<u8>),
}

impl CpEntry {
    fn with_bytes(entry: Self, span: &[u8]) -> Self {
        match entry {
            Self::Utf8 { index, text } => Self::Utf8Bytes {
                index,
                text,
                raw: span.to_vec(),
            },
            _ => Self::RawBytes(span.to_vec()),
        }
    }
}

fn scan_member_descriptor_indices(bytes: &[u8], cp_end: usize) -> Option<BTreeSet<usize>> {
    let mut pos: usize = cp_end;
    pos += 6;
    let interfaces_count: usize =
        usize::from(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]));
    pos += 2 + interfaces_count * 2;
    let mut out: BTreeSet<usize> = BTreeSet::new();
    for _ in 0..2 {
        let count: usize =
            usize::from(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]));
        pos += 2;
        for _ in 0..count {
            pos += 2;
            pos += 2;
            let descriptor_index: usize =
                usize::from(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]));
            pos += 2;
            out.insert(descriptor_index);
            let attr_count: usize =
                usize::from(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]));
            pos += 2;
            for _ in 0..attr_count {
                pos += 2;
                let len: usize = u32::from_be_bytes([
                    *bytes.get(pos)?,
                    *bytes.get(pos + 1)?,
                    *bytes.get(pos + 2)?,
                    *bytes.get(pos + 3)?,
                ]) as usize;
                pos += 4 + len;
            }
        }
    }
    Some(out)
}

fn rewrite_descriptor(disambiguator: &NameDisambiguator, descriptor: &str) -> Option<String> {
    if !descriptor.contains('L') || !descriptor.is_ascii() {
        return None;
    }
    let mut out: String = String::with_capacity(descriptor.len());
    let mut changed: bool = false;
    let bytes: &[u8] = descriptor.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'L'
            && let Some(end) = descriptor[i..].find(';')
        {
            let abs_end: usize = i + end;
            let name: &str = &descriptor[i + 1..abs_end];
            let renamed: String = disambiguator.rewrite(name);
            out.push('L');
            if renamed != name {
                changed = true;
            }
            out.push_str(&renamed);
            out.push(';');
            i = abs_end + 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    changed.then_some(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollisionReport {
    pub package_class_collisions: usize,
    pub reserved_word_names: usize,
}

#[must_use]
pub fn classify(names: &BTreeSet<String>) -> CollisionReport {
    let prefixes: BTreeSet<&str> = collect_package_prefixes(names);
    let mut report: CollisionReport = CollisionReport::default();
    for name in names {
        if prefixes.contains(name.as_str()) {
            report.package_class_collisions += 1;
        }
        let leaf: &str = name.rsplit('/').next().unwrap_or(name.as_str());
        if is_reserved(leaf) {
            report.reserved_word_names += 1;
        }
    }
    report
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_package_class_collision() {
        let names: Vec<&str> = vec!["a/b/HOHOOH", "a/b/HOHOOH/X", "a/b/Other"];
        let d: NameDisambiguator = NameDisambiguator::build(names);
        assert_eq!(d.rewrite("a/b/HOHOOH"), "a/b/HOHOOH_Cls");
        assert_eq!(d.rewrite("a/b/HOHOOH/X"), "a/b/HOHOOH/X");
        assert_eq!(d.rewrite("a/b/Other"), "a/b/Other");
    }

    #[test]
    fn renames_reserved_word_leaf() {
        let names: Vec<&str> = vec!["p/int", "p/Foo"];
        let d: NameDisambiguator = NameDisambiguator::build(names);
        assert_eq!(d.rewrite("p/int"), "p/int_");
        assert_eq!(d.rewrite("p/Foo"), "p/Foo");
    }

    #[test]
    fn rename_is_unique_against_existing() {
        let names: Vec<&str> = vec!["a/X", "a/X/Y", "a/X_Cls"];
        let d: NameDisambiguator = NameDisambiguator::build(names);
        let renamed: String = d.rewrite("a/X");
        assert_ne!(renamed, "a/X");
        assert_ne!(renamed, "a/X_Cls");
        assert!(renamed.starts_with("a/X_Cls"));
    }

    #[test]
    fn no_rename_when_clean() {
        let names: Vec<&str> = vec!["com/example/Foo", "com/example/Bar"];
        let d: NameDisambiguator = NameDisambiguator::build(names);
        assert!(d.is_empty());
        assert_eq!(d.rewrite("com/example/Foo"), "com/example/Foo");
    }

    #[test]
    fn rewrites_renamed_name_inside_descriptor() {
        let names: Vec<&str> = vec!["a/b/HOHOOH", "a/b/HOHOOH/X", "a/b/Other"];
        let d: NameDisambiguator = NameDisambiguator::build(names);
        assert_eq!(
            rewrite_descriptor(&d, "(La/b/HOHOOH;La/b/Other;)La/b/HOHOOH;").as_deref(),
            Some("(La/b/HOHOOH_Cls;La/b/Other;)La/b/HOHOOH_Cls;")
        );
    }

    #[test]
    fn leaves_unrenamed_descriptor_untouched() {
        let names: Vec<&str> = vec!["a/b/HOHOOH", "a/b/HOHOOH/X"];
        let d: NameDisambiguator = NameDisambiguator::build(names);
        assert_eq!(rewrite_descriptor(&d, "(I[Ljava/lang/String;)V"), None);
    }

    #[test]
    fn remap_rejects_non_class_bytes() {
        let d: NameDisambiguator = NameDisambiguator::build(["a/b/HOHOOH", "a/b/HOHOOH/X"]);
        assert!(remap_class_bytes(&d, &[0x00, 0x01, 0x02, 0x03]).is_none());
    }

    #[test]
    fn scope_threads_through_active() {
        let names: Vec<&str> = vec!["a/b/HOHOOH", "a/b/HOHOOH/X"];
        let d: NameDisambiguator = NameDisambiguator::build(names);
        assert_eq!(rewrite_active("a/b/HOHOOH"), "a/b/HOHOOH");
        with_rename_scope(&d, || {
            assert_eq!(rewrite_active("a/b/HOHOOH"), "a/b/HOHOOH_Cls");
        });
        assert_eq!(rewrite_active("a/b/HOHOOH"), "a/b/HOHOOH");
    }

    #[test]
    fn classify_counts_both() {
        let names: BTreeSet<String> = ["a/b/HOHOOH", "a/b/HOHOOH/X", "p/int"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let report: CollisionReport = classify(&names);
        assert_eq!(report.package_class_collisions, 1);
        assert_eq!(report.reserved_word_names, 1);
    }
}
