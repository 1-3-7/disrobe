use serde::{Deserialize, Serialize};

use crate::classfile::{Attribute, ClassFile};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapMethod {
    pub method_ref_index: u16,
    pub arguments: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordComponent {
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassStructure {
    pub bootstrap_methods: Vec<BootstrapMethod>,
    pub record_components: Vec<RecordComponent>,
    pub permitted_subclasses: Vec<String>,
    pub nest_host: Option<String>,
    pub nest_members: Vec<String>,
    pub source_file: Option<String>,
    pub signature: Option<String>,
    pub is_record: bool,
    pub is_sealed: bool,
}

#[inline]
fn be_u16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
}

#[must_use]
pub fn analyze(cf: &ClassFile) -> ClassStructure {
    let mut out: ClassStructure = ClassStructure::default();
    for attr in &cf.attributes {
        let Ok(name): Result<&str, _> = cf.utf8_at(attr.name_index) else {
            continue;
        };
        match name {
            "BootstrapMethods" => out.bootstrap_methods = parse_bootstrap_methods(&attr.info),
            "Record" => {
                out.record_components = parse_record(cf, attr);
                out.is_record = true;
            }
            "PermittedSubclasses" => {
                out.permitted_subclasses = parse_class_index_list(cf, &attr.info);
                out.is_sealed = true;
            }
            "NestHost" => {
                if let Some(idx) = be_u16(&attr.info, 0) {
                    out.nest_host = cf.class_name(idx).ok().map(str::to_string);
                }
            }
            "NestMembers" => out.nest_members = parse_class_index_list(cf, &attr.info),
            "SourceFile" => {
                if let Some(idx) = be_u16(&attr.info, 0) {
                    out.source_file = cf.utf8_at(idx).ok().map(str::to_string);
                }
            }
            "Signature" => {
                if let Some(idx) = be_u16(&attr.info, 0) {
                    out.signature = cf.utf8_at(idx).ok().map(str::to_string);
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_bootstrap_methods(info: &[u8]) -> Vec<BootstrapMethod> {
    let Some(count): Option<u16> = be_u16(info, 0) else {
        return Vec::new();
    };
    let mut out: Vec<BootstrapMethod> = Vec::with_capacity(usize::from(count).min(info.len()));
    let mut pos: usize = 2;
    for _ in 0..count {
        let (Some(method_ref_index), Some(num_args)): (Option<u16>, Option<u16>) =
            (be_u16(info, pos), be_u16(info, pos + 2))
        else {
            break;
        };
        pos += 4;
        let arg_count: usize = usize::from(num_args);
        let mut arguments: Vec<u16> = Vec::with_capacity(arg_count.min(info.len()));
        for _ in 0..arg_count {
            let Some(arg): Option<u16> = be_u16(info, pos) else {
                break;
            };
            arguments.push(arg);
            pos += 2;
        }
        out.push(BootstrapMethod {
            method_ref_index,
            arguments,
        });
    }
    out
}

fn parse_record(cf: &ClassFile, attr: &Attribute) -> Vec<RecordComponent> {
    let info: &[u8] = &attr.info;
    let Some(count): Option<u16> = be_u16(info, 0) else {
        return Vec::new();
    };
    let mut out: Vec<RecordComponent> = Vec::with_capacity(usize::from(count).min(info.len()));
    let mut pos: usize = 2;
    for _ in 0..count {
        let (Some(name_idx), Some(desc_idx), Some(attr_count)): (
            Option<u16>,
            Option<u16>,
            Option<u16>,
        ) = (
            be_u16(info, pos),
            be_u16(info, pos + 2),
            be_u16(info, pos + 4),
        ) else {
            break;
        };
        pos += 6;
        let name: String = cf.utf8_at(name_idx).unwrap_or("?").to_string();
        let descriptor: String = cf.utf8_at(desc_idx).unwrap_or("?").to_string();
        out.push(RecordComponent { name, descriptor });
        for _ in 0..attr_count {
            let Some(_inner_name): Option<u16> = be_u16(info, pos) else {
                break;
            };
            let Some(inner_len): Option<u16> = be_u16(info, pos + 2) else {
                break;
            };
            pos = pos.saturating_add(6).saturating_add(usize::from(inner_len));
        }
    }
    out
}

fn parse_class_index_list(cf: &ClassFile, info: &[u8]) -> Vec<String> {
    let Some(count): Option<u16> = be_u16(info, 0) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::with_capacity(usize::from(count).min(info.len()));
    let mut pos: usize = 2;
    for _ in 0..count {
        let Some(idx): Option<u16> = be_u16(info, pos) else {
            break;
        };
        if let Ok(name) = cf.class_name(idx) {
            out.push(name.to_string());
        }
        pos += 2;
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::classfile::ConstantPoolEntry;

    fn class_with(attrs: Vec<Attribute>, cp: Vec<ConstantPoolEntry>) -> ClassFile {
        ClassFile {
            minor_version: 0,
            major_version: 61,
            constant_pool: cp,
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: attrs,
        }
    }

    #[test]
    fn detects_record_components() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("Record".into()));
        cp.push(ConstantPoolEntry::Utf8("x".into()));
        cp.push(ConstantPoolEntry::Utf8("I".into()));
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&3u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let s: ClassStructure = analyze(&cf);
        assert!(s.is_record);
        assert_eq!(s.record_components.len(), 1);
        assert_eq!(s.record_components[0].name, "x");
        assert_eq!(s.record_components[0].descriptor, "I");
    }

    #[test]
    fn detects_sealed_permitted_subclasses() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("PermittedSubclasses".into()));
        cp.push(ConstantPoolEntry::Utf8("com/example/Impl".into()));
        cp.push(ConstantPoolEntry::Class { name_index: 2 });
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&3u16.to_be_bytes());
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let s: ClassStructure = analyze(&cf);
        assert!(s.is_sealed);
        assert_eq!(s.permitted_subclasses, vec!["com/example/Impl".to_string()]);
    }

    #[test]
    fn parses_bootstrap_methods() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("BootstrapMethods".into()));
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&5u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&7u16.to_be_bytes());
        info.extend_from_slice(&8u16.to_be_bytes());
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let s: ClassStructure = analyze(&cf);
        assert_eq!(s.bootstrap_methods.len(), 1);
        assert_eq!(s.bootstrap_methods[0].method_ref_index, 5);
        assert_eq!(s.bootstrap_methods[0].arguments, vec![7, 8]);
    }

    #[test]
    fn captures_nest_host() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("NestHost".into()));
        cp.push(ConstantPoolEntry::Utf8("com/example/Outer".into()));
        cp.push(ConstantPoolEntry::Class { name_index: 2 });
        let info: Vec<u8> = 3u16.to_be_bytes().to_vec();
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let s: ClassStructure = analyze(&cf);
        assert_eq!(s.nest_host.as_deref(), Some("com/example/Outer"));
    }
}
