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

#[derive(Debug, Default)]
pub(crate) struct FieldRvaData {
    fields: BTreeMap<u32, Vec<u8>>,
}

impl FieldRvaData {
    #[must_use]
    pub(crate) fn build(image: &[u8], pe: &PeImage, resolver: &Resolver) -> Self {
        let mut fields: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for (index, field) in resolver.tables().fields.iter().enumerate() {
            let Some(rid): Option<u32> = u32::try_from(index + 1).ok() else {
                continue;
            };
            let Some(size): Option<usize> =
                exact_field_rva_size(resolver, rid, field.flags, field.signature)
            else {
                continue;
            };
            let matching: Vec<u32> = resolver
                .tables()
                .field_rvas
                .iter()
                .filter(|row| row.field == rid)
                .map(|row| row.rva)
                .collect();
            let [rva] = matching.as_slice() else {
                continue;
            };
            let Some(bytes): Option<&[u8]> = pe.slice_exact_file_backed_rva(image, *rva, size)
            else {
                continue;
            };
            fields.insert(0x0400_0000 | rid, bytes.to_vec());
        }
        Self { fields }
    }

    #[must_use]
    pub(crate) fn bytes(&self, field_token: u32) -> Option<&[u8]> {
        self.fields.get(&field_token).map(Vec::as_slice)
    }
}

fn exact_field_rva_size(
    resolver: &Resolver,
    field_rid: u32,
    field_flags: u16,
    field_signature: u32,
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
    let type_def = tables.type_defs.get(type_rid.checked_sub(1)? as usize)?;
    if type_def.flags & TYPE_LAYOUT_MASK != TYPE_EXPLICIT_LAYOUT {
        return None;
    }
    if !field_belongs_to_a_type(tables, field_rid) {
        return None;
    }
    let layouts: Vec<u32> = tables
        .class_layouts
        .iter()
        .filter(|layout| layout.parent == type_rid)
        .map(|layout| layout.class_size)
        .collect();
    let [class_size] = layouts.as_slice() else {
        return None;
    };
    (1..=MAX_FIELD_RVA_BYTES)
        .contains(class_size)
        .then_some(*class_size as usize)
}

fn type_def_rid(token: u32) -> Option<u32> {
    (TableId::from_index(u8::try_from(token >> 24).ok()?) == Some(TableId::TypeDef))
        .then_some(token & 0x00FF_FFFF)
        .filter(|rid| *rid != 0)
}

fn field_belongs_to_a_type(tables: &Tables, field_rid: u32) -> bool {
    let declared: u32 = u32::try_from(tables.fields.len()).unwrap_or(u32::MAX);
    if field_rid == 0 || field_rid > declared {
        return false;
    }
    tables
        .type_defs
        .iter()
        .enumerate()
        .any(|(index, type_def)| {
            let start: u32 = type_def.field_list;
            let end: u32 = tables
                .type_defs
                .get(index.saturating_add(1))
                .map_or(declared.saturating_add(1), |next| next.field_list);
            start <= field_rid && field_rid < end
        })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::metadata::{metadata_slice, parse_metadata_root};
    use crate::pe::{parse, parse_clr_header};

    const EDGECASES_DLL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

    fn fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(EDGECASES_DLL)
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
        let field_data: FieldRvaData = FieldRvaData::build(&image, &pe, &resolver);
        assert_eq!(field_data.bytes(0x0400_0089), Some(raw));
    }
}
