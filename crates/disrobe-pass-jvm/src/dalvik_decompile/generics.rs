use std::collections::BTreeMap;

use crate::dex::{DexFieldDecl, DexFile, DexMethodCode, DexSystemMetadata};
use crate::signature::{RecoveredClassSignature, RecoveredMethodSignature};

#[derive(Debug, Default)]
pub(super) struct MemberGenerics {
    classes: BTreeMap<String, String>,
    methods: BTreeMap<u32, String>,
    fields: BTreeMap<(String, String, String), String>,
    throws: BTreeMap<u32, Vec<String>>,
}

impl MemberGenerics {
    pub(super) fn from_metadata(dex: &DexFile, metadata: &DexSystemMetadata) -> Self {
        let classes: BTreeMap<String, String> = metadata
            .classes
            .iter()
            .filter_map(|(class, class_metadata)| {
                class_metadata
                    .signature
                    .as_ref()
                    .map(|signature: &String| (class.clone(), signature.clone()))
            })
            .collect();
        let fields: BTreeMap<(String, String, String), String> = metadata
            .field_signatures
            .iter()
            .filter_map(|(index, signature): (&u32, &String)| {
                let field: &crate::dex::FieldId = dex.field_ids.get(*index as usize)?;
                Some((
                    (
                        field.class.clone(),
                        field.name.clone(),
                        field.type_name.clone(),
                    ),
                    signature.clone(),
                ))
            })
            .collect();
        Self {
            classes,
            methods: metadata.method_signatures.clone(),
            fields,
            throws: metadata.method_throws.clone(),
        }
    }
}

pub(super) fn class_signature(
    generics: &MemberGenerics,
    class_descriptor: &str,
    declaration: Option<&crate::dalvik_desugar::ClassDeclaration>,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
) -> Option<RecoveredClassSignature> {
    let raw: &String = generics.classes.get(class_descriptor)?;
    let declaration: &crate::dalvik_desugar::ClassDeclaration = declaration?;
    let superclass: String = desugar
        .core_library
        .project_type(declaration.superclass.as_deref()?);
    let interfaces: Vec<String> = declaration
        .interfaces
        .iter()
        .map(|interface: &String| desugar.core_library.project_type(interface))
        .collect();
    let projected: String = project_signature(raw, desugar.core_library);
    crate::signature::recover_class_raw(&projected, &superclass, &interfaces).ok()
}

pub(super) fn method_signature(
    generics: &MemberGenerics,
    method: &DexMethodCode,
    class_signature: Option<&RecoveredClassSignature>,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
) -> Option<RecoveredMethodSignature> {
    let raw: &String = generics.methods.get(&method.method_index)?;
    let descriptor: String = desugar.core_library.project_type(&method.method_descriptor);
    let projected: String = project_signature(raw, desugar.core_library);
    let recovered: RecoveredMethodSignature =
        crate::signature::recover_method_raw(&projected, &descriptor, class_signature, None, false)
            .ok()?;
    if !recovered.type_parameter_names.is_empty() {
        return None;
    }
    let class_variables: Vec<&str> = class_signature
        .map(|signature: &RecoveredClassSignature| signature.type_parameter_names().collect())
        .unwrap_or_default();
    let mentions_class_variable: bool = recovered
        .parameters
        .iter()
        .chain(std::iter::once(&recovered.result))
        .any(|rendered: &String| {
            class_variables
                .iter()
                .any(|name: &&str| super::loops::mentions(rendered, name))
        });
    if mentions_class_variable {
        return None;
    }
    Some(recovered)
}

pub(super) fn method_throws(
    generics: &MemberGenerics,
    method: &DexMethodCode,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
) -> Vec<String> {
    generics
        .throws
        .get(&method.method_index)
        .map(|types: &Vec<String>| {
            types
                .iter()
                .map(|descriptor: &String| {
                    crate::descriptor::binary_to_source(
                        &desugar.core_library.project_type(descriptor),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn field_type(
    generics: &MemberGenerics,
    field: &DexFieldDecl,
    class_signature: Option<&RecoveredClassSignature>,
    desugar: crate::dalvik_desugar::DesugarView<'_>,
) -> Option<String> {
    let raw: &String = generics.fields.get(&(
        field.class.clone(),
        field.name.clone(),
        field.type_name.clone(),
    ))?;
    let descriptor: String = desugar.core_library.project_type(&field.type_name);
    let projected: String = project_signature(raw, desugar.core_library);
    let rendered: String =
        crate::signature::recover_field_raw(&projected, &descriptor, class_signature).ok()?;
    let mentions_class_variable: bool =
        class_signature.is_some_and(|signature: &RecoveredClassSignature| {
            signature
                .type_parameter_names()
                .any(|name: &str| super::loops::mentions(&rendered, name))
        });
    if mentions_class_variable {
        return None;
    }
    Some(rendered)
}

pub(super) fn project_signature(
    raw: &str,
    core_library: &crate::dalvik_core_library::CoreLibraryRecovery,
) -> String {
    let mut out: String = String::with_capacity(raw.len());
    let bytes: &[u8] = raw.as_bytes();
    let mut index: usize = 0;
    let mut expect_type: bool = true;
    while index < bytes.len() {
        let byte: u8 = bytes[index];
        if expect_type && byte == b'L' {
            let start: usize = index + 1;
            let mut end: usize = start;
            while end < bytes.len() && !matches!(bytes[end], b'<' | b';' | b'.' | b':') {
                end += 1;
            }
            if end < bytes.len() && bytes[end] != b':' {
                let name: &str = &raw[start..end];
                let projected: String = core_library.project_type(&format!("L{name};"));
                let projected_name: &str = projected
                    .strip_prefix('L')
                    .and_then(|rest: &str| rest.strip_suffix(';'))
                    .unwrap_or(name);
                out.push('L');
                out.push_str(projected_name);
                index = end;
                expect_type = false;
                continue;
            }
        }
        out.push(char::from(byte));
        expect_type = matches!(
            byte,
            b'(' | b')' | b'<' | b';' | b'+' | b'-' | b'[' | b':' | b'^' | b'*'
        );
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desugared_core_library_names_are_projected_inside_signatures() {
        let core: crate::dalvik_core_library::CoreLibraryRecovery =
            crate::dalvik_core_library::CoreLibraryRecovery::for_tests(true);
        let raw: &str = "<T:Ljava/lang/Object;>(Lj$/util/function/Function<TT;Lj$/util/Optional<[I>;>;)Lj$/util/stream/Stream<TT;>;^Ljava/io/IOException;";
        assert_eq!(
            project_signature(raw, &core),
            "<T:Ljava/lang/Object;>(Ljava/util/function/Function<TT;Ljava/util/Optional<[I>;>;)Ljava/util/stream/Stream<TT;>;^Ljava/io/IOException;"
        );
    }

    #[test]
    fn a_type_parameter_named_like_a_class_prefix_is_left_alone() {
        let core: crate::dalvik_core_library::CoreLibraryRecovery =
            crate::dalvik_core_library::CoreLibraryRecovery::for_tests(true);
        let raw: &str = "<L:Ljava/lang/Object;>(TL;)V";
        assert_eq!(project_signature(raw, &core), raw);
    }
}
