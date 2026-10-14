use std::collections::BTreeMap;

use crate::classfile::{Attribute, ClassFile, ConstantPoolEntry};
use crate::proguard::{
    ClassHierarchy, ClassMapping, FieldMapping, InheritedField, InheritedMethod, Mapping,
    MethodMapping, remap_descriptor, select_field, select_overload,
};

const INNER_CLASSES_ATTRIBUTE: &str = "InnerClasses";
const MAX_INNER_CLASS_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenameReport {
    pub classes_renamed: usize,
    pub members_renamed: usize,
    pub references_renamed: usize,
    pub pool_exhausted: bool,
}

struct Pool {
    entries: Vec<ConstantPoolEntry>,
    utf8: BTreeMap<String, u16>,
    name_and_type: BTreeMap<(u16, u16), u16>,
    exhausted: bool,
}

impl Pool {
    fn new(entries: Vec<ConstantPoolEntry>) -> Self {
        let mut utf8: BTreeMap<String, u16> = BTreeMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if let ConstantPoolEntry::Utf8(text) = entry
                && let Ok(index) = u16::try_from(index)
            {
                utf8.entry(text.clone()).or_insert(index);
            }
        }
        Self {
            entries,
            utf8,
            name_and_type: BTreeMap::new(),
            exhausted: false,
        }
    }

    fn push(&mut self, entry: ConstantPoolEntry) -> Option<u16> {
        let index: u16 = u16::try_from(self.entries.len()).ok()?;
        if index == u16::MAX {
            self.exhausted = true;
            return None;
        }
        self.entries.push(entry);
        Some(index)
    }

    fn utf8(&mut self, text: &str) -> Option<u16> {
        if let Some(index) = self.utf8.get(text) {
            return Some(*index);
        }
        let index: u16 = self.push(ConstantPoolEntry::Utf8(text.to_owned()))?;
        self.utf8.insert(text.to_owned(), index);
        Some(index)
    }

    fn name_and_type(&mut self, name: &str, descriptor: &str) -> Option<u16> {
        let name_index: u16 = self.utf8(name)?;
        let descriptor_index: u16 = self.utf8(descriptor)?;
        if let Some(index) = self.name_and_type.get(&(name_index, descriptor_index)) {
            return Some(*index);
        }
        let index: u16 = self.push(ConstantPoolEntry::NameAndType {
            name_index,
            descriptor_index,
        })?;
        self.name_and_type
            .insert((name_index, descriptor_index), index);
        Some(index)
    }
}

fn original_class_name(mapping: &Mapping, obfuscated: &str) -> Option<String> {
    if obfuscated.starts_with('[') {
        return remap_descriptor(mapping, obfuscated);
    }
    mapping
        .original_binary_for_obfuscated(obfuscated)
        .filter(|original: &String| original != obfuscated)
}

fn original_field_name(
    mapping: &Mapping,
    hierarchy: &ClassHierarchy,
    owner: &str,
    name: &str,
    descriptor: &str,
) -> Option<String> {
    let entry: Option<&ClassMapping> = mapping.lookup_obfuscated_class(&owner.replace('/', "."));
    let local: Option<&str> = entry.and_then(|entry: &ClassMapping| {
        entry
            .field_overloads
            .get(name)
            .and_then(|overloads: &Vec<FieldMapping>| select_field(overloads, Some(descriptor)))
            .map(|field: &FieldMapping| field.original_name.as_str())
            .or_else(|| entry.fields.get(name).map(String::as_str))
    });
    let original: String = match local {
        Some(original) => original.to_owned(),
        None => mapping
            .resolve_field_with_inheritance(hierarchy, owner, name, Some(descriptor))
            .map(|field: InheritedField| field.original_name)?,
    };
    (original != name).then_some(original)
}

fn original_method_name(
    mapping: &Mapping,
    hierarchy: &ClassHierarchy,
    owner: &str,
    name: &str,
    descriptor: &str,
) -> Option<String> {
    if name.starts_with('<') {
        return None;
    }
    let local: Option<&MethodMapping> = mapping
        .lookup_obfuscated_class(&owner.replace('/', "."))
        .and_then(|entry: &ClassMapping| entry.methods.get(name))
        .and_then(|overloads: &Vec<MethodMapping>| select_overload(overloads, Some(descriptor)));
    let original: String = match local {
        Some(method) => method.original_name.clone(),
        None => mapping
            .resolve_method_with_inheritance(hierarchy, owner, name, Some(descriptor))
            .map(|method: InheritedMethod| method.original_name)?,
    };
    (original != name).then_some(original)
}

fn simple_name(binary: &str) -> &str {
    let leaf: &str = binary.rsplit('/').next().unwrap_or(binary);
    leaf.rsplit('$').next().unwrap_or(leaf)
}

fn rewrite_inner_classes(
    cf: &ClassFile,
    mapping: &Mapping,
    pool: &mut Pool,
    attribute: &Attribute,
) -> Option<Vec<u8>> {
    let info: &[u8] = &attribute.info;
    let count: usize = usize::from(u16::from_be_bytes([*info.first()?, *info.get(1)?]));
    if count > MAX_INNER_CLASS_ENTRIES || info.len() != 2 + count * 8 {
        return None;
    }
    let mut out: Vec<u8> = info.to_vec();
    let mut changed: bool = false;
    for entry in 0..count {
        let base: usize = 2 + entry * 8;
        let inner_index: u16 = u16::from_be_bytes([info[base], info[base + 1]]);
        let name_slot: usize = base + 4;
        let inner_name_index: u16 = u16::from_be_bytes([info[name_slot], info[name_slot + 1]]);
        if inner_name_index == 0 {
            continue;
        }
        let Ok(inner): Result<&str, _> = cf.class_name(inner_index) else {
            continue;
        };
        let Some(original): Option<String> = original_class_name(mapping, inner) else {
            continue;
        };
        let simple: &str = simple_name(&original);
        if cf.utf8_at(inner_name_index).ok() == Some(simple) {
            continue;
        }
        let fresh: u16 = pool.utf8(simple)?;
        out[name_slot..name_slot + 2].copy_from_slice(&fresh.to_be_bytes());
        changed = true;
    }
    changed.then_some(out)
}

#[must_use]
pub fn rename_classfile(
    mapping: &Mapping,
    cf: &ClassFile,
    hierarchy: &ClassHierarchy,
) -> (ClassFile, RenameReport) {
    let mut report: RenameReport = RenameReport::default();
    let mut pool: Pool = Pool::new(cf.constant_pool.clone());
    let mut out: ClassFile = cf.clone();
    let this_name: Option<&str> = cf.this_class_name().ok();

    for index in 0..cf.constant_pool.len() {
        match &cf.constant_pool[index] {
            ConstantPoolEntry::Class { name_index } => {
                let Ok(name): Result<&str, _> = cf.utf8_at(*name_index) else {
                    continue;
                };
                let Some(original): Option<String> = original_class_name(mapping, name) else {
                    continue;
                };
                let Some(fresh): Option<u16> = pool.utf8(&original) else {
                    break;
                };
                pool.entries[index] = ConstantPoolEntry::Class { name_index: fresh };
                report.classes_renamed += 1;
            }
            ConstantPoolEntry::Fieldref {
                class_index,
                name_and_type_index,
            } => {
                let Some((owner, name, descriptor)) =
                    member_reference(cf, *class_index, *name_and_type_index)
                else {
                    continue;
                };
                let renamed: Option<String> =
                    original_field_name(mapping, hierarchy, owner, name, descriptor);
                let remapped: Option<String> = remap_descriptor(mapping, descriptor);
                if renamed.is_none() && remapped.is_none() {
                    continue;
                }
                let Some(fresh): Option<u16> = pool.name_and_type(
                    renamed.as_deref().unwrap_or(name),
                    remapped.as_deref().unwrap_or(descriptor),
                ) else {
                    break;
                };
                pool.entries[index] = ConstantPoolEntry::Fieldref {
                    class_index: *class_index,
                    name_and_type_index: fresh,
                };
                report.references_renamed += 1;
            }
            ConstantPoolEntry::Methodref {
                class_index,
                name_and_type_index,
            }
            | ConstantPoolEntry::InterfaceMethodref {
                class_index,
                name_and_type_index,
            } => {
                let Some((owner, name, descriptor)) =
                    member_reference(cf, *class_index, *name_and_type_index)
                else {
                    continue;
                };
                let renamed: Option<String> =
                    original_method_name(mapping, hierarchy, owner, name, descriptor);
                let remapped: Option<String> = remap_descriptor(mapping, descriptor);
                if renamed.is_none() && remapped.is_none() {
                    continue;
                }
                let Some(fresh): Option<u16> = pool.name_and_type(
                    renamed.as_deref().unwrap_or(name),
                    remapped.as_deref().unwrap_or(descriptor),
                ) else {
                    break;
                };
                let interface: bool = matches!(
                    cf.constant_pool[index],
                    ConstantPoolEntry::InterfaceMethodref { .. }
                );
                pool.entries[index] = if interface {
                    ConstantPoolEntry::InterfaceMethodref {
                        class_index: *class_index,
                        name_and_type_index: fresh,
                    }
                } else {
                    ConstantPoolEntry::Methodref {
                        class_index: *class_index,
                        name_and_type_index: fresh,
                    }
                };
                report.references_renamed += 1;
            }
            ConstantPoolEntry::InvokeDynamic {
                bootstrap_method_attr_index,
                name_and_type_index,
            } => {
                let Some((name, descriptor)) = name_and_type(cf, *name_and_type_index) else {
                    continue;
                };
                let Some(remapped): Option<String> = remap_descriptor(mapping, descriptor) else {
                    continue;
                };
                let Some(fresh): Option<u16> = pool.name_and_type(name, &remapped) else {
                    break;
                };
                pool.entries[index] = ConstantPoolEntry::InvokeDynamic {
                    bootstrap_method_attr_index: *bootstrap_method_attr_index,
                    name_and_type_index: fresh,
                };
                report.references_renamed += 1;
            }
            ConstantPoolEntry::MethodType { descriptor_index } => {
                let Ok(descriptor): Result<&str, _> = cf.utf8_at(*descriptor_index) else {
                    continue;
                };
                let Some(remapped): Option<String> = remap_descriptor(mapping, descriptor) else {
                    continue;
                };
                let Some(fresh): Option<u16> = pool.utf8(&remapped) else {
                    break;
                };
                pool.entries[index] = ConstantPoolEntry::MethodType {
                    descriptor_index: fresh,
                };
                report.references_renamed += 1;
            }
            _ => {}
        }
    }

    if let Some(this) = this_name {
        for (slot, field) in cf.fields.iter().enumerate() {
            let (Ok(name), Ok(descriptor)): (Result<&str, _>, Result<&str, _>) = (
                cf.utf8_at(field.name_index),
                cf.utf8_at(field.descriptor_index),
            ) else {
                continue;
            };
            if let Some(original) = original_field_name(mapping, hierarchy, this, name, descriptor)
                && let Some(fresh) = pool.utf8(&original)
            {
                out.fields[slot].name_index = fresh;
                report.members_renamed += 1;
            }
            if let Some(remapped) = remap_descriptor(mapping, descriptor)
                && let Some(fresh) = pool.utf8(&remapped)
            {
                out.fields[slot].descriptor_index = fresh;
            }
        }
        for (slot, method) in cf.methods.iter().enumerate() {
            let (Ok(name), Ok(descriptor)): (Result<&str, _>, Result<&str, _>) = (
                cf.utf8_at(method.name_index),
                cf.utf8_at(method.descriptor_index),
            ) else {
                continue;
            };
            if let Some(original) = original_method_name(mapping, hierarchy, this, name, descriptor)
                && let Some(fresh) = pool.utf8(&original)
            {
                out.methods[slot].name_index = fresh;
                report.members_renamed += 1;
            }
            if let Some(remapped) = remap_descriptor(mapping, descriptor)
                && let Some(fresh) = pool.utf8(&remapped)
            {
                out.methods[slot].descriptor_index = fresh;
            }
        }
    }

    for (slot, attribute) in cf.attributes.iter().enumerate() {
        if cf.utf8_at(attribute.name_index).ok() != Some(INNER_CLASSES_ATTRIBUTE) {
            continue;
        }
        if let Some(info) = rewrite_inner_classes(cf, mapping, &mut pool, attribute) {
            out.attributes[slot].info = info;
        }
    }

    report.pool_exhausted = pool.exhausted;
    out.constant_pool = pool.entries;
    (out, report)
}

fn name_and_type(cf: &ClassFile, index: u16) -> Option<(&str, &str)> {
    let ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = cf.constant_pool.get(usize::from(index))?
    else {
        return None;
    };
    Some((
        cf.utf8_at(*name_index).ok()?,
        cf.utf8_at(*descriptor_index).ok()?,
    ))
}

fn member_reference(
    cf: &ClassFile,
    class_index: u16,
    name_and_type_index: u16,
) -> Option<(&str, &str, &str)> {
    let owner: &str = cf.class_name(class_index).ok()?;
    let (name, descriptor): (&str, &str) = name_and_type(cf, name_and_type_index)?;
    Some((owner, name, descriptor))
}
