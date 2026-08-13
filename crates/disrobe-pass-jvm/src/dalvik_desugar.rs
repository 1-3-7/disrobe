use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::{DalvikInsn, decode_method};
use crate::descriptor::{JavaType, MethodDescriptor};
use crate::dex::{
    ACC_ABSTRACT, ACC_STATIC, CodeItem, CodeItemsReport, DexCodeState, DexFile, DexMethodCode,
};

const ACC_INTERFACE: u32 = 0x0200;

#[derive(Debug, Clone)]
pub(crate) struct DefaultInterfaceMethod {
    pub(crate) interface: String,
    pub(crate) name: String,
    pub(crate) descriptor: String,
    pub(crate) bridge_item: usize,
    pub(crate) bridge_method: u32,
}

#[derive(Debug, Default)]
pub(crate) struct DefaultInterfaceRecovery {
    methods: BTreeMap<(String, String, String), DefaultInterfaceMethod>,
    suppressed_classes: BTreeSet<String>,
    suppressed_methods: BTreeSet<(String, String, String)>,
    implemented_interfaces: BTreeMap<String, BTreeSet<String>>,
    calls: BTreeMap<u32, DefaultInterfaceMethod>,
}

struct ReferenceScan<'a> {
    call_sites: BTreeMap<u32, Vec<ForwarderSite<'a>>>,
    escaped_companions: BTreeSet<String>,
}

struct ForwarderSite<'a> {
    item: &'a CodeItem,
    method: &'a DexMethodCode,
}

struct ClassDeclaration {
    access_flags: u32,
    interfaces: Vec<String>,
}

impl DefaultInterfaceRecovery {
    pub(crate) fn analyze(dex: &DexFile, bytes: &[u8], report: &CodeItemsReport) -> Self {
        let Some(class_declarations): Option<BTreeMap<String, ClassDeclaration>> =
            class_declarations(dex, bytes)
        else {
            return Self::default();
        };
        let mut candidates: BTreeMap<String, Vec<DefaultInterfaceMethod>> = BTreeMap::new();
        let mut rejected_companions: BTreeSet<String> = BTreeSet::new();
        for method in report.methods() {
            let Some(interface): Option<&str> = method.class.strip_suffix("$-CC;") else {
                continue;
            };
            let interface: String = format!("{interface};");
            let Some(name): Option<&str> = method.method_name.strip_prefix("$default$") else {
                rejected_companions.insert(method.class.clone());
                continue;
            };
            let DexCodeState::Decoded(bridge_item) = method.state else {
                rejected_companions.insert(method.class.clone());
                continue;
            };
            if method.access_flags & ACC_STATIC != ACC_STATIC {
                rejected_companions.insert(method.class.clone());
                continue;
            }
            let Some(bridge_id) = dex.method_ids.get(method.method_index as usize) else {
                rejected_companions.insert(method.class.clone());
                continue;
            };
            let owner_matches: bool = bridge_id.class == method.class;
            let name_matches: bool = bridge_id.name == method.method_name;
            let receiver_matches: bool = bridge_id.proto.parameters.first() == Some(&interface);
            if !owner_matches || !name_matches || !receiver_matches {
                rejected_companions.insert(method.class.clone());
                continue;
            }
            let Some(target) = report.methods().iter().find(|target| {
                target.class == interface
                    && target.method_name == name
                    && target.access_flags & ACC_ABSTRACT != 0
                    && target.method_descriptor == descriptor_without_receiver(bridge_id)
            }) else {
                rejected_companions.insert(method.class.clone());
                continue;
            };
            let bridge_method: u32 = method.method_index;
            candidates
                .entry(method.class.clone())
                .or_default()
                .push(DefaultInterfaceMethod {
                    interface,
                    name: name.to_string(),
                    descriptor: target.method_descriptor.clone(),
                    bridge_item,
                    bridge_method,
                });
        }
        for rejected in rejected_companions {
            candidates.remove(&rejected);
        }

        let Some(references): Option<ReferenceScan<'_>> = scan_references(dex, report, &candidates)
        else {
            return Self::default();
        };

        let mut recovery: Self = Self::default();
        for (companion, methods) in candidates {
            if methods.is_empty()
                || !all_companion_methods_recovered(report, &companion, methods.len())
                || references.escaped_companions.contains(&companion)
                || methods.iter().any(|method: &DefaultInterfaceMethod| {
                    class_declarations.get(&method.interface).is_none_or(
                        |class: &ClassDeclaration| class.access_flags & ACC_INTERFACE == 0,
                    )
                })
            {
                continue;
            }
            let mut forwarders: Vec<(String, String, String)> = Vec::new();
            let mut interfaces: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            let mut valid: bool = true;
            for method in &methods {
                let sites: &[ForwarderSite<'_>] = references
                    .call_sites
                    .get(&method.bridge_method)
                    .map_or(&[], Vec::as_slice);
                if sites.is_empty()
                    || sites.iter().any(|site: &ForwarderSite<'_>| {
                        !class_declares_interface(
                            &class_declarations,
                            &site.item.class,
                            &method.interface,
                        ) || !is_forwarder(
                            site.item,
                            site.method,
                            method.bridge_method,
                            &method.name,
                            &method.descriptor,
                        )
                    })
                {
                    valid = false;
                    break;
                }
                for site in sites {
                    forwarders.push((
                        site.item.class.clone(),
                        site.item.method_name.clone(),
                        site.item.method_descriptor.clone(),
                    ));
                    interfaces
                        .entry(site.item.class.clone())
                        .or_default()
                        .insert(method.interface.clone());
                }
            }
            if !valid {
                continue;
            }
            recovery.suppressed_classes.insert(companion);
            recovery.suppressed_methods.extend(forwarders);
            for (implementation, implemented) in interfaces {
                recovery
                    .implemented_interfaces
                    .entry(implementation)
                    .or_default()
                    .extend(implemented);
            }
            for method in methods {
                recovery.calls.insert(method.bridge_method, method.clone());
                recovery.methods.insert(
                    (
                        method.interface.clone(),
                        method.name.clone(),
                        method.descriptor.clone(),
                    ),
                    method,
                );
            }
        }
        recovery
    }

    pub(crate) fn suppresses_class(&self, class: &str) -> bool {
        self.suppressed_classes.contains(class)
    }

    pub(crate) fn suppresses_method(&self, class: &str, name: &str, descriptor: &str) -> bool {
        self.suppressed_methods.contains(&(
            class.to_string(),
            name.to_string(),
            descriptor.to_string(),
        ))
    }

    pub(crate) fn recovered_method(
        &self,
        class: &str,
        name: &str,
        descriptor: &str,
    ) -> Option<&DefaultInterfaceMethod> {
        self.methods
            .get(&(class.to_string(), name.to_string(), descriptor.to_string()))
    }

    pub(crate) fn implemented_interfaces(&self, class: &str) -> Option<&BTreeSet<String>> {
        self.implemented_interfaces.get(class)
    }

    pub(crate) fn recovers_interface(&self, class: &str) -> bool {
        self.methods
            .values()
            .any(|method: &DefaultInterfaceMethod| method.interface == class)
    }

    pub(crate) fn rewrites_call(&self, method: u32) -> Option<&DefaultInterfaceMethod> {
        self.calls.get(&method)
    }
}

fn descriptor_without_receiver(method: &crate::dex::MethodId) -> String {
    let parameters: String = method
        .proto
        .parameters
        .iter()
        .skip(1)
        .map(String::as_str)
        .collect();
    format!("({parameters}){}", method.proto.return_type)
}

fn all_companion_methods_recovered(
    report: &CodeItemsReport,
    companion: &str,
    recovered: usize,
) -> bool {
    report
        .methods()
        .iter()
        .filter(|method| method.class == companion)
        .count()
        == recovered
}

const MAX_DESUGAR_SCAN_INSNS: usize = 1_048_576;

fn scan_references<'a>(
    dex: &DexFile,
    report: &'a CodeItemsReport,
    candidates: &BTreeMap<String, Vec<DefaultInterfaceMethod>>,
) -> Option<ReferenceScan<'a>> {
    if !report.is_fully_decoded() || dex.call_site_ids_size != 0 || dex.method_handles_size != 0 {
        return None;
    }
    let bridge_owners: BTreeMap<u32, String> = candidates
        .iter()
        .flat_map(|(companion, methods)| {
            methods
                .iter()
                .map(|method| (method.bridge_method, companion.clone()))
        })
        .collect();
    let companions: BTreeSet<String> = candidates.keys().cloned().collect();
    let binary_companions: BTreeMap<String, String> = companions
        .iter()
        .map(|companion: &String| {
            (
                companion
                    .trim_start_matches('L')
                    .trim_end_matches(';')
                    .replace('/', "."),
                companion.clone(),
            )
        })
        .collect();
    let mut escaped: BTreeSet<String> = BTreeSet::new();
    for field in &dex.field_ids {
        if companions.contains(&field.class) {
            escaped.insert(field.class.clone());
        }
        if companions.contains(&field.type_name) {
            escaped.insert(field.type_name.clone());
        }
    }
    for method in &dex.method_ids {
        if method.class != method.proto.return_type
            && companions.contains(&method.proto.return_type)
        {
            escaped.insert(method.proto.return_type.clone());
        }
        for parameter in &method.proto.parameters {
            if companions.contains(parameter) {
                escaped.insert(parameter.clone());
            }
        }
    }
    let methods: BTreeMap<(&str, &str, &str), &DexMethodCode> = report
        .methods()
        .iter()
        .map(|method: &DexMethodCode| {
            (
                (
                    method.class.as_str(),
                    method.method_name.as_str(),
                    method.method_descriptor.as_str(),
                ),
                method,
            )
        })
        .collect();
    let mut call_sites: BTreeMap<u32, Vec<ForwarderSite<'a>>> = BTreeMap::new();
    let mut work: usize = 0;
    for item in report.decoded() {
        let instructions: Vec<DalvikInsn> = decode_method(&item.insns);
        work = work.checked_add(instructions.len())?;
        if work > MAX_DESUGAR_SCAN_INSNS {
            return None;
        }
        for insn in instructions {
            if matches!(insn.op, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb) {
                if let Some(index) = insn.index {
                    if bridge_owners.contains_key(&index) && matches!(insn.op, 0x71 | 0x77) {
                        let method: &DexMethodCode = *methods.get(&(
                            item.class.as_str(),
                            item.method_name.as_str(),
                            item.method_descriptor.as_str(),
                        ))?;
                        call_sites
                            .entry(index)
                            .or_default()
                            .push(ForwarderSite { item, method });
                    } else if let Some(method) = dex.method_ids.get(index as usize)
                        && companions.contains(&method.class)
                    {
                        escaped.insert(method.class.clone());
                    }
                }
                if matches!(insn.op, 0xfa | 0xfb) {
                    let proto_offset: usize = usize::try_from(insn.pc).ok()?.checked_add(3)?;
                    let proto_index: usize = usize::from(*item.insns.get(proto_offset)?);
                    let proto: &crate::dex::ProtoId = dex.proto_ids.get(proto_index)?;
                    mark_proto_escapes(proto, &companions, &mut escaped);
                }
            } else if insn.op == 0xff
                && let Some(proto) = insn
                    .index
                    .and_then(|index: u32| dex.proto_ids.get(index as usize))
            {
                mark_proto_escapes(proto, &companions, &mut escaped);
            } else if matches!(insn.op, 0x1a | 0x1b) {
                if let Some(companion) = insn
                    .index
                    .and_then(|index: u32| dex.strings.get(index as usize))
                    .and_then(|value: &String| binary_companions.get(value))
                {
                    escaped.insert(companion.clone());
                }
            } else if matches!(insn.op, 0x1c | 0x1f | 0x20 | 0x22..=0x25)
                && let Some(companion) = insn
                    .index
                    .and_then(|index: u32| dex.type_names.get(index as usize))
                    .filter(|ty: &&String| companions.contains(*ty))
            {
                escaped.insert(companion.clone());
            }
        }
    }
    Some(ReferenceScan {
        call_sites,
        escaped_companions: escaped,
    })
}

fn mark_proto_escapes(
    proto: &crate::dex::ProtoId,
    companions: &BTreeSet<String>,
    escaped: &mut BTreeSet<String>,
) {
    if companions.contains(&proto.return_type) {
        escaped.insert(proto.return_type.clone());
    }
    for parameter in &proto.parameters {
        if companions.contains(parameter) {
            escaped.insert(parameter.clone());
        }
    }
}

fn class_declares_interface(
    classes: &BTreeMap<String, ClassDeclaration>,
    class: &str,
    interface: &str,
) -> bool {
    classes
        .get(class)
        .is_some_and(|declaration: &ClassDeclaration| {
            declaration
                .interfaces
                .iter()
                .any(|value| value == interface)
        })
}

fn class_declarations(dex: &DexFile, bytes: &[u8]) -> Option<BTreeMap<String, ClassDeclaration>> {
    let base: usize = usize::try_from(dex.header.class_defs_off).ok()?;
    let count: usize = usize::try_from(dex.header.class_defs_size).ok()?;
    let table_bytes: usize = count.checked_mul(32)?;
    let table_end: usize = base.checked_add(table_bytes)?;
    if table_end > bytes.len() {
        return None;
    }
    let mut remaining_interfaces: usize = bytes.len();
    let mut classes: BTreeMap<String, ClassDeclaration> = BTreeMap::new();
    for ordinal in 0..count {
        let offset: usize = base.checked_add(ordinal.checked_mul(32)?)?;
        let class_index: usize = usize::try_from(read_u32(bytes, offset)?).ok()?;
        let access_flags: u32 = read_u32(bytes, offset + 4)?;
        let interfaces_offset: usize = usize::try_from(read_u32(bytes, offset + 12)?).ok()?;
        let class: String = dex.type_names.get(class_index)?.clone();
        let interfaces: Vec<String> = if interfaces_offset == 0 {
            Vec::new()
        } else {
            let interface_count: usize =
                usize::try_from(read_u32(bytes, interfaces_offset)?).ok()?;
            if interface_count > remaining_interfaces {
                return None;
            }
            let entries_start: usize = interfaces_offset.checked_add(4)?;
            let entries_bytes: usize = interface_count.checked_mul(2)?;
            let entries_end: usize = entries_start.checked_add(entries_bytes)?;
            if entries_end > bytes.len() {
                return None;
            }
            remaining_interfaces -= interface_count;
            let mut values: Vec<String> = Vec::with_capacity(interface_count);
            for index in 0..interface_count {
                let entry: usize = entries_start.checked_add(index.checked_mul(2)?)?;
                let type_index: usize = usize::from(read_u16(bytes, entry)?);
                values.push(dex.type_names.get(type_index)?.clone());
            }
            values
        };
        if classes
            .insert(
                class,
                ClassDeclaration {
                    access_flags,
                    interfaces,
                },
            )
            .is_some()
        {
            return None;
        }
    }
    Some(classes)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value: &[u8] = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value: &[u8] = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn is_forwarder(
    item: &CodeItem,
    metadata: &DexMethodCode,
    method: u32,
    name: &str,
    descriptor: &str,
) -> bool {
    if item.method_name != name
        || item.method_descriptor != descriptor
        || item.is_direct
        || metadata.is_direct
        || metadata.access_flags & ACC_STATIC != 0
    {
        return false;
    }
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    let Some(invoke): Option<&DalvikInsn> = insns.first() else {
        return false;
    };
    let Some(parsed): Option<MethodDescriptor> = crate::descriptor::parse_method(descriptor) else {
        return false;
    };
    let parameter_words: usize = parsed
        .params
        .iter()
        .fold(1usize, |words: usize, ty: &JavaType| {
            words.saturating_add(if ty.category_two() { 2 } else { 1 })
        });
    if usize::from(item.ins_size) != parameter_words {
        return false;
    }
    let expected_receiver: u16 = item.registers_size.saturating_sub(item.ins_size);
    let expected_registers: Vec<u16> = (expected_receiver..item.registers_size).collect();
    let result_pair: Option<(u8, u8)> = match parsed.returns {
        JavaType::Void => None,
        JavaType::Long | JavaType::Double => Some((0x0b, 0x10)),
        JavaType::Object(_) | JavaType::Array(_) => Some((0x0c, 0x11)),
        JavaType::Byte
        | JavaType::Char
        | JavaType::Float
        | JavaType::Int
        | JavaType::Short
        | JavaType::Boolean => Some((0x0a, 0x0f)),
    };
    matches!(invoke.op, 0x71 | 0x77)
        && invoke.index == Some(method)
        && invoke.regs == expected_registers
        && match result_pair {
            None => matches!(insns.as_slice(), [_, ret] if ret.op == 0x0e),
            Some((move_result, return_value)) => {
                matches!(insns.as_slice(), [_, result, ret] if result.op == move_result && ret.op == return_value && result.regs == ret.regs)
            }
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dex::DexCodeState;

    fn metadata(descriptor: &str) -> DexMethodCode {
        DexMethodCode {
            method_index: 7,
            class: "Lp/Impl;".to_owned(),
            method_name: "run".to_owned(),
            method_descriptor: descriptor.to_owned(),
            access_flags: 0x0001,
            is_direct: false,
            code_offset: 1,
            state: DexCodeState::Decoded(0),
        }
    }

    fn item(descriptor: &str, insns: Vec<u16>, ins_size: u16) -> CodeItem {
        CodeItem {
            method_name: "run".to_owned(),
            method_descriptor: descriptor.to_owned(),
            class: "Lp/Impl;".to_owned(),
            is_direct: false,
            registers_size: ins_size,
            ins_size,
            outs_size: ins_size,
            insns,
            tries: Vec::new(),
            param_names: Vec::new(),
        }
    }

    #[test]
    fn forwarder_requires_exact_arguments_and_supports_void() {
        let descriptor: &str = "(II)V";
        let exact: CodeItem = item(descriptor, vec![0x3071, 7, 0x0210, 0x000e], 3);
        assert!(is_forwarder(
            &exact,
            &metadata(descriptor),
            7,
            "run",
            descriptor
        ));

        let permuted: CodeItem = item(descriptor, vec![0x3071, 7, 0x0120, 0x000e], 3);
        assert!(!is_forwarder(
            &permuted,
            &metadata(descriptor),
            7,
            "run",
            descriptor
        ));

        let mut direct: DexMethodCode = metadata(descriptor);
        direct.is_direct = true;
        assert!(!is_forwarder(&exact, &direct, 7, "run", descriptor));

        let mut static_method: DexMethodCode = metadata(descriptor);
        static_method.access_flags |= ACC_STATIC;
        assert!(!is_forwarder(&exact, &static_method, 7, "run", descriptor));

        let inconsistent: CodeItem = item(descriptor, vec![0x2071, 7, 0x0010, 0x000e], 2);
        assert!(!is_forwarder(
            &inconsistent,
            &metadata(descriptor),
            7,
            "run",
            descriptor
        ));

        let wide_descriptor: &str = "(J)J";
        let wide: CodeItem = item(wide_descriptor, vec![0x3071, 7, 0x0210, 0x010b, 0x0110], 3);
        assert!(is_forwarder(
            &wide,
            &metadata(wide_descriptor),
            7,
            "run",
            wide_descriptor
        ));
        let wrong_return: CodeItem =
            item(wide_descriptor, vec![0x3071, 7, 0x0210, 0x010a, 0x010f], 3);
        assert!(!is_forwarder(
            &wrong_return,
            &metadata(wide_descriptor),
            7,
            "run",
            wide_descriptor
        ));
    }
}
