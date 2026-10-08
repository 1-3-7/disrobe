use std::collections::{BTreeMap, BTreeSet};

use crate::metadata::{MetadataRoot, StreamHeader};
use crate::pe::{ClrHeader, PeImage};
use crate::tables::{RowRef, TableId, Tables};

pub(crate) const LAYER_NAMES: &str = "renamer output outside the C# identifier grammar";
pub(crate) const LAYER_SHADOWED_MEMBERS: &str = "members named like their enclosing type";

const MAX_NAME_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameRole {
    Type,
    Namespace,
    Member,
}

const fn is_identifier_byte(byte: u8, first: bool) -> bool {
    if byte >= 0x80 {
        return true;
    }
    if first {
        byte == b'_' || byte.is_ascii_alphabetic()
    } else {
        byte == b'_' || byte.is_ascii_alphanumeric()
    }
}

fn is_compiler_pattern(name: &[u8]) -> bool {
    if name.first() == Some(&b'.') {
        return true;
    }
    if name.first() != Some(&b'<') {
        return false;
    }
    let Some(close): Option<usize> = name.iter().rposition(|b: &u8| *b == b'>') else {
        return false;
    };
    let inner: &[u8] = &name[1..close];
    let tail: &[u8] = &name[close + 1..];
    let inner_ok: bool = inner
        .iter()
        .all(|b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'<' | b'>' | b'.' | b'`'));
    let tail_ok: bool = tail
        .iter()
        .all(|b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'`' | b'|' | b'$'));
    inner_ok && tail_ok
}

fn repaired(name: &[u8], role: NameRole) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || is_compiler_pattern(name) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(name.len());
    let mut changed: bool = false;
    let mut first: bool = true;
    for byte in name {
        let keep: bool = match role {
            NameRole::Namespace => *byte == b'.' || is_identifier_byte(*byte, first),
            NameRole::Type => *byte == b'`' || is_identifier_byte(*byte, first),
            NameRole::Member => is_identifier_byte(*byte, first),
        };
        if keep {
            out.push(*byte);
        } else {
            out.push(b'_');
            changed = true;
        }
        first = *byte == b'.' && role == NameRole::Namespace;
    }
    changed.then_some(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct NameRepair {
    pub(crate) rewritten: u32,
    pub(crate) type_renames: BTreeMap<u32, String>,
    pub(crate) member_renames: BTreeMap<u32, String>,
}

pub(crate) fn repair_identifiers(
    image: &mut [u8],
    pe: &PeImage,
    clr: &ClrHeader,
    root: &MetadataRoot,
    tables: &Tables,
) -> Option<NameRepair> {
    let strings: &StreamHeader = root.streams.get("#Strings")?;
    let metadata_offset: usize = pe.rva_to_offset(clr.metadata.rva)?;
    let heap_start: usize = metadata_offset.checked_add(usize::try_from(strings.offset).ok()?)?;
    let heap_end: usize = heap_start
        .checked_add(usize::try_from(strings.size).ok()?)?
        .min(image.len());
    if heap_start >= heap_end {
        return None;
    }
    let explicit_bodies: BTreeSet<u32> = tables
        .method_impls
        .iter()
        .filter_map(|row| row.method_body)
        .filter(|r: &RowRef| r.table == TableId::MethodDef)
        .map(|r: RowRef| r.row)
        .collect();
    let mut work: Vec<(u32, NameRole, Option<u32>)> = Vec::new();
    for (index, row) in tables.type_defs.iter().enumerate() {
        let token: u32 = 0x0200_0000 | u32::try_from(index + 1).unwrap_or(u32::MAX);
        work.push((row.name, NameRole::Type, Some(token)));
        work.push((row.namespace, NameRole::Namespace, None));
    }
    for (index, row) in tables.methods.iter().enumerate() {
        let rid: u32 = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if explicit_bodies.contains(&rid) {
            continue;
        }
        work.push((row.name, NameRole::Member, Some(0x0600_0000 | rid)));
    }
    for (index, row) in tables.fields.iter().enumerate() {
        let token: u32 = 0x0400_0000 | u32::try_from(index + 1).unwrap_or(u32::MAX);
        work.push((row.name, NameRole::Member, Some(token)));
    }
    for row in &tables.params {
        work.push((row.name, NameRole::Member, None));
    }
    let mut referenced: Vec<u32> = Vec::new();
    referenced.extend(tables.modules.iter().map(|r| r.name));
    referenced.extend(tables.type_refs.iter().flat_map(|r| [r.name, r.namespace]));
    referenced.extend(tables.type_defs.iter().flat_map(|r| [r.name, r.namespace]));
    referenced.extend(tables.fields.iter().map(|r| r.name));
    referenced.extend(tables.methods.iter().map(|r| r.name));
    referenced.extend(tables.params.iter().map(|r| r.name));
    referenced.extend(tables.member_refs.iter().map(|r| r.name));
    referenced.extend(tables.module_refs.iter().map(|r| r.name));
    referenced.extend(
        tables
            .assembly_refs
            .iter()
            .flat_map(|r| [r.name, r.culture]),
    );
    referenced.extend(tables.generic_params.iter().map(|r| r.name));
    referenced.extend(tables.manifest_resources.iter().map(|r| r.name));
    referenced.retain(|index: &u32| *index != 0);
    referenced.sort_unstable();
    referenced.dedup();
    let string_len = |index: u32| -> Option<usize> {
        let start: usize = heap_start.checked_add(usize::try_from(index).ok()?)?;
        if start >= heap_end {
            return None;
        }
        Some(
            image[start..heap_end]
                .iter()
                .position(|b: &u8| *b == 0)
                .unwrap_or(heap_end - start),
        )
    };
    let lengths: BTreeMap<u32, usize> = referenced
        .iter()
        .filter_map(|index: &u32| Some((*index, string_len(*index)?)))
        .collect();
    let shares_bytes = |index: u32, len: usize| -> bool {
        let end: u32 = index.saturating_add(u32::try_from(len).unwrap_or(u32::MAX));
        lengths.iter().any(|(other, other_len): (&u32, &usize)| {
            if *other == index {
                return false;
            }
            if *other > index && *other <= end {
                return true;
            }
            *other < index
                && other.saturating_add(u32::try_from(*other_len).unwrap_or(u32::MAX)) >= index
        })
    };
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut repair: NameRepair = NameRepair::default();
    for (index, role, token) in work {
        if index == 0 {
            continue;
        }
        let Some(len): Option<usize> = lengths.get(&index).copied() else {
            continue;
        };
        let start: usize = heap_start.checked_add(usize::try_from(index).ok()?)?;
        let Some(fixed): Option<Vec<u8>> = repaired(&image[start..start + len], role) else {
            continue;
        };
        if shares_bytes(index, len) {
            // the heap bytes are shared with another name, so this row is renamed in the
            // resolver instead of in place
            if let (Some(token), Ok(name)) = (token, String::from_utf8(fixed)) {
                match role {
                    NameRole::Type => {
                        repair.type_renames.insert(token, name);
                    }
                    NameRole::Member => {
                        repair.member_renames.insert(token, name);
                    }
                    NameRole::Namespace => {}
                }
            }
            continue;
        }
        if !seen.insert(index) {
            continue;
        }
        image[start..start + len].copy_from_slice(&fixed);
        repair.rewritten = repair.rewritten.saturating_add(1);
    }
    Some(repair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_and_dots_in_member_names_become_underscores() {
        assert_eq!(
            repaired(b"Log get_Syntax Load.FixedUpdate", NameRole::Member),
            Some(b"Log_get_Syntax_Load_FixedUpdate".to_vec())
        );
        assert_eq!(repaired(b"6", NameRole::Member), Some(b"_".to_vec()));
        assert_eq!(repaired(b"Classify", NameRole::Member), None);
        assert_eq!(repaired(b"<Main>b__0", NameRole::Member), None);
        assert_eq!(repaired(b".ctor", NameRole::Member), None);
    }

    #[test]
    fn namespaces_keep_their_dots_and_types_keep_generic_arity() {
        assert_eq!(
            repaired(b"A.B c", NameRole::Namespace),
            Some(b"A.B_c".to_vec())
        );
        assert_eq!(repaired(b"System.Collections", NameRole::Namespace), None);
        assert_eq!(repaired(b"Dictionary`2", NameRole::Type), None);
        assert_eq!(
            repaired(
                b"get_Permissions set_Directory LogError.get_Name",
                NameRole::Type
            ),
            Some(b"get_Permissions_set_Directory_LogError_get_Name".to_vec())
        );
    }
}
