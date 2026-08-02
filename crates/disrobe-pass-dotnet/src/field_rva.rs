use std::collections::BTreeMap;

use crate::model::Resolver;
use crate::pe::PeImage;
use crate::signature::TypeSig;
use crate::tables::{TableId, Tables};

const FIELD_STATIC: u16 = 0x0010;
const FIELD_HAS_RVA: u16 = 0x0100;
const TYPE_LAYOUT_MASK: u32 = 0x0018;
const TYPE_EXPLICIT_LAYOUT: u32 = 0x0010;
const MAX_FIELD_RVA_BYTES: u32 = 512;

#[derive(Debug, Clone, Copy)]
struct FieldRvaLocation {
    rva: u32,
    size: usize,
}

#[derive(Debug)]
pub(crate) struct FieldRvaData<'a> {
    image: &'a [u8],
    pe: &'a PeImage,
    fields: BTreeMap<u32, FieldRvaLocation>,
}

impl<'a> FieldRvaData<'a> {
    #[must_use]
    pub(crate) fn build(image: &'a [u8], pe: &'a PeImage, resolver: &Resolver) -> Self {
        let tables: &Tables = resolver.tables();
        let field_rvas: BTreeMap<u32, Option<u32>> = unique_field_rvas(tables);
        let class_layouts: BTreeMap<u32, Option<u32>> = unique_class_layouts(tables);
        let field_ownership: Vec<bool> = field_ownership(tables);
        let mut fields: BTreeMap<u32, FieldRvaLocation> = BTreeMap::new();
        for (index, field) in tables.fields.iter().enumerate() {
            let Some(rid): Option<u32> = u32::try_from(index + 1).ok() else {
                continue;
            };
            let Some(size): Option<usize> = exact_field_rva_size(
                resolver,
                rid,
                field.flags,
                field.signature,
                &field_ownership,
                &class_layouts,
            ) else {
                continue;
            };
            let Some(Some(rva)): Option<&Option<u32>> = field_rvas.get(&rid) else {
                continue;
            };
            if pe.slice_exact_file_backed_rva(image, *rva, size).is_none() {
                continue;
            }
            fields.insert(0x0400_0000 | rid, FieldRvaLocation { rva: *rva, size });
        }
        Self { image, pe, fields }
    }

    #[must_use]
    pub(crate) fn bytes(&self, field_token: u32) -> Option<&'a [u8]> {
        let location: FieldRvaLocation = *self.fields.get(&field_token)?;
        self.pe
            .slice_exact_file_backed_rva(self.image, location.rva, location.size)
    }
}

fn unique_field_rvas(tables: &Tables) -> BTreeMap<u32, Option<u32>> {
    let mut indexed: BTreeMap<u32, Option<u32>> = BTreeMap::new();
    for row in &tables.field_rvas {
        match indexed.entry(row.field) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(row.rva));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }
    indexed
}

fn unique_class_layouts(tables: &Tables) -> BTreeMap<u32, Option<u32>> {
    let mut indexed: BTreeMap<u32, Option<u32>> = BTreeMap::new();
    for row in &tables.class_layouts {
        match indexed.entry(row.parent) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(row.class_size));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
        }
    }
    indexed
}

fn field_ownership(tables: &Tables) -> Vec<bool> {
    let mut owned: Vec<bool> = vec![false; tables.fields.len()];
    let Some(field_count): Option<u32> = u32::try_from(owned.len()).ok() else {
        return owned;
    };
    let one_past_last: u32 = field_count.saturating_add(1);
    let mut previous: u32 = 1;
    for type_def in &tables.type_defs {
        let current: u32 = type_def.field_list;
        if current == 0 || current < previous || current > one_past_last {
            return owned;
        }
        previous = current;
    }
    for (index, type_def) in tables.type_defs.iter().enumerate() {
        let next: u32 = tables
            .type_defs
            .get(index.saturating_add(1))
            .map_or(one_past_last, |row| row.field_list);
        let start: u32 = type_def.field_list;
        if start == 0 || start > next || next > one_past_last {
            continue;
        }
        let Some(start_index): Option<usize> = usize::try_from(start.saturating_sub(1)).ok() else {
            continue;
        };
        let Some(end_index): Option<usize> = usize::try_from(next.saturating_sub(1)).ok() else {
            continue;
        };
        if let Some(slice) = owned.get_mut(start_index..end_index) {
            slice.fill(true);
        }
    }
    owned
}

fn exact_field_rva_size(
    resolver: &Resolver,
    field_rid: u32,
    field_flags: u16,
    field_signature: u32,
    field_ownership: &[bool],
    class_layouts: &BTreeMap<u32, Option<u32>>,
) -> Option<usize> {
    if field_flags & (FIELD_STATIC | FIELD_HAS_RVA) != (FIELD_STATIC | FIELD_HAS_RVA) {
        return None;
    }
    let TypeSig::NamedType {
        is_value_type: true,
        token,
    } = resolver.strict_field_signature(field_signature)?
    else {
        return None;
    };
    let type_rid: u32 = type_def_rid(token)?;
    let tables: &Tables = resolver.tables();
    let type_index: usize = usize::try_from(type_rid.checked_sub(1)?).ok()?;
    let type_def: &crate::tables::TypeDefRow = tables.type_defs.get(type_index)?;
    if type_def.flags & TYPE_LAYOUT_MASK != TYPE_EXPLICIT_LAYOUT {
        return None;
    }
    let field_index: usize = usize::try_from(field_rid.checked_sub(1)?).ok()?;
    if !field_ownership.get(field_index).copied().unwrap_or(false) {
        return None;
    }
    let class_size: u32 = (*class_layouts.get(&type_rid)?)?;
    (1..=MAX_FIELD_RVA_BYTES)
        .contains(&class_size)
        .then_some(class_size as usize)
}

fn type_def_rid(token: u32) -> Option<u32> {
    (TableId::from_index(u8::try_from(token >> 24).ok()?) == Some(TableId::TypeDef))
        .then_some(token & 0x00FF_FFFF)
        .filter(|rid| *rid != 0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::metadata::{metadata_slice, parse_metadata_root};
    use crate::pe::{parse, parse_clr_header};
    use crate::tables::{FieldRow, TypeDefRow};

    const EDGECASES_DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

    fn fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(EDGECASES_DLL)
    }

    #[test]
    fn non_monotonic_field_lists_have_no_accepted_ownership() {
        let tables: Tables = Tables {
            fields: vec![
                FieldRow {
                    flags: 0,
                    name: 0,
                    signature: 0,
                };
                3
            ],
            type_defs: vec![
                TypeDefRow {
                    flags: 0,
                    name: 0,
                    namespace: 0,
                    extends: None,
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: 0,
                    namespace: 0,
                    extends: None,
                    field_list: 3,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: 0,
                    namespace: 0,
                    extends: None,
                    field_list: 2,
                    method_list: 1,
                },
            ],
            ..Tables::default()
        };
        assert_eq!(field_ownership(&tables), vec![false, false, false]);
    }

    #[test]
    fn collection_field_rva_bytes_are_metadata_sized_and_file_backed() {
        let image: Vec<u8> = std::fs::read(fixture_path()).expect("read EdgeCases baseline");
        let pe: PeImage = parse(&image).expect("parse PE");
        let clr = parse_clr_header(&image, &pe).expect("parse CLR");
        let root = parse_metadata_root(&image, &pe, &clr).expect("parse metadata");
        let resolver: Resolver = Resolver::build(&image, &pe, &clr, &root).expect("build resolver");
        let field_rid: u32 = 0x89;
        let field = resolver
            .tables()
            .fields
            .get(field_rid as usize - 1)
            .expect("collection FieldRVA field");
        assert_eq!(
            field.flags & (FIELD_STATIC | FIELD_HAS_RVA),
            FIELD_STATIC | FIELD_HAS_RVA,
            "collection field must be static FieldRVA"
        );
        let TypeSig::NamedType {
            is_value_type: true,
            token,
        } = resolver
            .strict_field_signature(field.signature)
            .expect("strict FieldRVA signature")
        else {
            panic!("collection field must name a value type");
        };
        let layout_rid: u32 = type_def_rid(token).expect("explicit layout TypeDef");
        let layout = resolver
            .tables()
            .class_layouts
            .iter()
            .find(|layout| layout.parent == layout_rid)
            .expect("class layout row");
        assert_eq!(layout.class_size, 12, "compiler layout size");
        let rva = resolver
            .tables()
            .field_rvas
            .iter()
            .find(|row| row.field == field_rid)
            .expect("FieldRVA row");
        let raw: &[u8] = pe
            .slice_exact_file_backed_rva(&image, rva.rva, layout.class_size as usize)
            .expect("exact file-backed FieldRVA range");
        assert_eq!(raw, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
        let metadata: &[u8] = metadata_slice(&image, &pe, &clr, &root).expect("metadata slice");
        let blob_stream = root.streams.get("#Blob").expect("#Blob stream");
        let start: usize = blob_stream.offset as usize;
        let end: usize = start + blob_stream.size as usize;
        let init_tokens =
            crate::peel::deflatten::decrypt::init_array_tokens(&resolver, &metadata[start..end]);
        assert!(
            init_tokens.iter().any(|token| resolver
                .resolve_token(*token)
                .contains("RuntimeHelpers::InitializeArray")),
            "the exact RuntimeHelpers.InitializeArray member reference must be identified"
        );
        let field_data: FieldRvaData<'_> = FieldRvaData::build(&image, &pe, &resolver);
        assert_eq!(field_data.bytes(0x0400_0089), Some(raw));
    }
}
