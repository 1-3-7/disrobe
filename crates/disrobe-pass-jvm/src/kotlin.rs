use serde::{Deserialize, Serialize};

use crate::attributes::{
    Annotation, AnnotationOutcome, AnnotationValue, DeclarationAnnotations,
    parse_declaration_annotations,
};
use crate::classfile::ClassFile;
use crate::descriptor::{JavaType, MethodDescriptor};
use crate::error::{Error, Result};

const METADATA_ANNOTATION: &str = "Lkotlin/Metadata;";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KotlinKind {
    Class,
    File,
    SyntheticClass,
    MultifileClassFacade,
    MultifileClassPart,
    Unknown,
}

impl KotlinKind {
    #[inline]
    #[must_use]
    pub const fn from_kind(k: i32) -> Self {
        match k {
            1 => Self::Class,
            2 => Self::File,
            3 => Self::SyntheticClass,
            4 => Self::MultifileClassFacade,
            5 => Self::MultifileClassPart,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KotlinMetadata {
    pub kind: KotlinKind,
    pub metadata_version: Vec<i32>,
    pub bytecode_version: Vec<i32>,
    pub package_name: Option<String>,
}

#[must_use]
pub fn is_metadata_absent_suspend_signature(
    metadata_is_absent: bool,
    source_file: Option<&str>,
    method_name: &str,
    descriptor: &MethodDescriptor,
    continuation_is_unused: bool,
    continuation_impl_bridge: bool,
) -> bool {
    let kotlin_source: bool =
        source_file.is_some_and(|file: &str| file.ends_with(".kt") || file.ends_with(".kts"));
    let continuation_final: bool = matches!(
        descriptor.params.last(),
        Some(JavaType::Object(name)) if name == "Lkotlin/coroutines/Continuation;"
    );
    let returns_object: bool = matches!(
        descriptor.returns,
        JavaType::Object(ref name) if name == "Ljava/lang/Object;"
    );
    metadata_is_absent
        && kotlin_source
        && continuation_final
        && returns_object
        && continuation_is_unused
        && !continuation_impl_bridge
        && !matches!(method_name, "create" | "invoke" | "invokeSuspend")
}

pub fn recover_metadata(cf: &ClassFile) -> Result<Option<KotlinMetadata>> {
    let declarations: DeclarationAnnotations = parse_declaration_annotations(cf);
    let annotations: &[Annotation] = match &declarations.visible {
        AnnotationOutcome::Absent => return Ok(None),
        AnnotationOutcome::Parsed(annotations) => annotations,
        AnnotationOutcome::Rejected { .. } => {
            return Err(Error::BadKotlinMetadata(
                "runtime-visible annotation attribute rejected",
            ));
        }
    };
    let Some(annotation): Option<&Annotation> = annotations
        .iter()
        .find(|annotation: &&Annotation| annotation.type_descriptor == METADATA_ANNOTATION)
    else {
        return Ok(None);
    };
    let kind: KotlinKind = match annotation.element("k") {
        Some(AnnotationValue::Int(value)) => KotlinKind::from_kind(*value),
        Some(_) => return Err(Error::BadKotlinMetadata("k is not an integer")),
        None => KotlinKind::Class,
    };
    let metadata_version: Vec<i32> = annotation_int_array(annotation, "mv")?;
    let bytecode_version: Vec<i32> = annotation_int_array(annotation, "bv")?;
    let package_name: Option<String> = match annotation.element("pn") {
        Some(AnnotationValue::String(value)) => Some(value.clone()),
        Some(_) => return Err(Error::BadKotlinMetadata("pn is not a string")),
        None => None,
    };
    Ok(Some(KotlinMetadata {
        kind,
        metadata_version,
        bytecode_version,
        package_name,
    }))
}

fn annotation_int_array(annotation: &Annotation, name: &str) -> Result<Vec<i32>> {
    let Some(value): Option<&AnnotationValue> = annotation.element(name) else {
        return Ok(Vec::new());
    };
    let AnnotationValue::Array(values) = value else {
        return Err(Error::BadKotlinMetadata("metadata version is not an array"));
    };
    values
        .iter()
        .map(|value: &AnnotationValue| match value {
            AnnotationValue::Int(value) => Ok(*value),
            _ => Err(Error::BadKotlinMetadata(
                "metadata version element is not an integer",
            )),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::classfile::{Attribute, ConstantPoolEntry};

    #[test]
    fn kotlin_kind_round_trip() {
        for k in [1, 2, 3, 4, 5] {
            assert!(!matches!(KotlinKind::from_kind(k), KotlinKind::Unknown));
        }
        assert!(matches!(KotlinKind::from_kind(99), KotlinKind::Unknown));
    }

    #[test]
    fn recover_returns_none_when_no_annotations() {
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![ConstantPoolEntry::Placeholder],
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let out: Option<KotlinMetadata> = recover_metadata(&cf).expect("ok");
        assert!(out.is_none());
    }

    #[test]
    fn metadata_survives_source_unrepresentable_sibling_annotation() {
        let constant_pool: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("RuntimeVisibleAnnotations".into()),
            ConstantPoolEntry::Utf8("Lkotlin/Metadata;".into()),
            ConstantPoolEntry::Utf8("k".into()),
            ConstantPoolEntry::Integer(1),
            ConstantPoolEntry::Utf8("mv".into()),
            ConstantPoolEntry::Integer(2),
            ConstantPoolEntry::Integer(0),
            ConstantPoolEntry::Integer(0),
            ConstantPoolEntry::Utf8("Lpkg/Odd;".into()),
            ConstantPoolEntry::Utf8("class".into()),
        ];
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&3u16.to_be_bytes());
        info.push(b'I');
        info.extend_from_slice(&4u16.to_be_bytes());
        info.extend_from_slice(&5u16.to_be_bytes());
        info.push(b'[');
        info.extend_from_slice(&3u16.to_be_bytes());
        for index in [6u16, 7, 8] {
            info.push(b'I');
            info.extend_from_slice(&index.to_be_bytes());
        }
        info.extend_from_slice(&9u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&10u16.to_be_bytes());
        info.push(b'I');
        info.extend_from_slice(&4u16.to_be_bytes());
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool,
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: vec![Attribute {
                name_index: 1,
                info,
            }],
        };
        let metadata: KotlinMetadata = recover_metadata(&cf)
            .expect("metadata parse")
            .expect("metadata annotation");
        assert_eq!(metadata.kind, KotlinKind::Class);
        assert_eq!(metadata.metadata_version, vec![2, 0, 0]);
    }
}
