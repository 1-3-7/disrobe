use crate::dalvik::DalvikInsn;
use crate::dex::DexFile;

use super::meta::{ACC_FINAL, ACC_STATIC, ACC_SYNTHETIC, DexMeta, MethodMeta};

pub(crate) const MAX_HELPER_ARITY: usize = 6;

const R8_NAMESPACE_MARKERS: [&str; 7] = [
    "$$ExternalSynthetic",
    "-$$",
    "$r8$",
    "com/android/tools/r8",
    "$$Nest",
    "$$Lambda",
    "$$InlineOutline",
];

pub(crate) fn is_r8_namespace(class: &str, name: &str) -> bool {
    R8_NAMESPACE_MARKERS
        .iter()
        .any(|marker: &&str| class.contains(marker) || name.contains(marker))
}

pub(crate) const fn is_synthetic_static(flags: u32) -> bool {
    flags & ACC_SYNTHETIC != 0 && flags & ACC_STATIC != 0
}

pub(crate) fn straight_line_return(insns: &[DalvikInsn]) -> Option<usize> {
    let mut ret: Option<usize> = None;
    for (i, insn) in insns.iter().enumerate() {
        if insn.is_conditional_branch() || insn.is_switch() || insn.is_unconditional_goto() {
            return None;
        }
        if insn.is_throw() {
            return None;
        }
        if insn.is_return() {
            if !matches!(insn.op, 0x0F..=0x11) {
                return None;
            }
            if ret.is_some() {
                return None;
            }
            ret = Some(i);
        } else if ret.is_some() && insn.op != 0x00 {
            return None;
        }
    }
    ret
}

fn is_values_field_name(name: &str) -> bool {
    name == "$VALUES" || name == "ENUM$VALUES" || name.starts_with("$VALUES")
}

#[derive(Debug, Clone)]
pub(crate) struct EnumValuesFacts {
    pub(crate) enum_class: String,
    pub(crate) field_name: String,
    pub(crate) field_type: String,
    pub(crate) has_values_method: bool,
}

fn class_extends_enum(dex: &DexFile, class: &str) -> bool {
    dex.class_super_descriptors
        .get(class)
        .is_some_and(|s: &String| s == "Ljava/lang/Enum;")
}

fn has_synthetic_values_method(meta: &DexMeta, enum_class: &str) -> bool {
    meta.methods.iter().any(|m: &MethodMeta| {
        m.class == enum_class
            && m.name == "values"
            && m.descriptor.starts_with("()[")
            && m.access_flags & ACC_SYNTHETIC != 0
    })
}

pub(crate) fn detect_enum_values(dex: &DexFile, meta: &DexMeta) -> Vec<EnumValuesFacts> {
    let mut out: Vec<EnumValuesFacts> = Vec::new();
    for field in &meta.fields {
        let candidate: bool = field.is_static
            && field.access_flags & ACC_SYNTHETIC != 0
            && field.access_flags & ACC_FINAL != 0
            && is_values_field_name(&field.name)
            && field.type_desc.starts_with("[L")
            && class_extends_enum(dex, &field.class);
        if !candidate {
            continue;
        }
        out.push(EnumValuesFacts {
            enum_class: field.class.clone(),
            field_name: field.name.clone(),
            field_type: field.type_desc.clone(),
            has_values_method: has_synthetic_values_method(meta, &field.class),
        });
    }
    out
}
