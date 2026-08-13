use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::{DalvikInsn, decode_method};
use crate::descriptor::{JavaType, MethodDescriptor};
use crate::dex::{
    ACC_ABSTRACT, ACC_STATIC, CodeItem, CodeItemsReport, DexCodeState, DexFile, DexMethodCode,
};

const ACC_INTERFACE: u32 = 0x0200;
const ACC_FINAL: u32 = 0x0010;
const ACC_SYNTHETIC: u32 = 0x1000;
const OBJECT_DESCRIPTOR: &str = "Ljava/lang/Object;";

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
    superclass: Option<String>,
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
        let superclass_index: u32 = read_u32(bytes, offset + 8)?;
        let interfaces_offset: usize = usize::try_from(read_u32(bytes, offset + 12)?).ok()?;
        let class: String = dex.type_names.get(class_index)?.clone();
        let superclass: Option<String> = if superclass_index == crate::dex::DEX_NO_INDEX {
            None
        } else {
            Some(
                dex.type_names
                    .get(usize::try_from(superclass_index).ok()?)?
                    .clone(),
            )
        };
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
                    superclass,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MethodRefKind {
    Static,
    UnboundInstance,
    BoundInstance,
    Constructor,
}

#[derive(Debug, Clone)]
pub(crate) struct RecoveredMethodRef {
    pub(crate) kind: MethodRefKind,
    pub(crate) owner: String,
    pub(crate) name: String,
}

#[derive(Debug, Default)]
pub(crate) struct MethodReferenceRecovery {
    by_class: BTreeMap<String, RecoveredMethodRef>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DesugarView<'a> {
    pub(crate) interfaces: &'a DefaultInterfaceRecovery,
    pub(crate) method_refs: &'a MethodReferenceRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefValue {
    Receiver,
    Parameter(usize),
    Capture(usize),
    Allocation(u32),
    Product,
    Unknown,
}

#[derive(Debug)]
struct TargetCall {
    method_index: u32,
    receiver: Option<RefValue>,
    args: Vec<RefValue>,
    is_constructor: bool,
    is_static: bool,
}

const MAX_REFERENCE_BODY_INSNS: usize = 64;
const BOX_TYPES: [(&str, &str, &str); 8] = [
    ("Ljava/lang/Boolean;", "booleanValue", "Z"),
    ("Ljava/lang/Byte;", "byteValue", "B"),
    ("Ljava/lang/Character;", "charValue", "C"),
    ("Ljava/lang/Double;", "doubleValue", "D"),
    ("Ljava/lang/Float;", "floatValue", "F"),
    ("Ljava/lang/Integer;", "intValue", "I"),
    ("Ljava/lang/Long;", "longValue", "J"),
    ("Ljava/lang/Short;", "shortValue", "S"),
];

impl MethodReferenceRecovery {
    pub(crate) fn analyze(dex: &DexFile, bytes: &[u8], report: &CodeItemsReport) -> Self {
        if !report.is_fully_decoded() || dex.call_site_ids_size != 0 || dex.method_handles_size != 0
        {
            return Self::default();
        }
        let Some(classes): Option<BTreeMap<String, ClassDeclaration>> =
            class_declarations(dex, bytes)
        else {
            return Self::default();
        };
        let declared_access: BTreeMap<u32, u32> = report
            .methods()
            .iter()
            .map(|method: &DexMethodCode| (method.method_index, method.access_flags))
            .collect();
        let mut owned: BTreeMap<&str, Vec<&DexMethodCode>> = BTreeMap::new();
        for method in report.methods() {
            owned.entry(method.class.as_str()).or_default().push(method);
        }
        let mut candidates: BTreeMap<String, RecoveredMethodRef> = BTreeMap::new();
        for (class, declaration) in &classes {
            if !is_lambda_shaped(declaration) {
                continue;
            }
            let Some(methods): Option<&Vec<&DexMethodCode>> = owned.get(class.as_str()) else {
                continue;
            };
            let Some(recovered): Option<RecoveredMethodRef> = match_lambda_class(
                dex,
                report,
                &classes,
                &declared_access,
                class,
                methods.as_slice(),
            ) else {
                continue;
            };
            candidates.insert(class.clone(), recovered);
        }
        if candidates.is_empty() {
            return Self::default();
        }
        let accepted: BTreeSet<String> =
            exclusively_constructed(dex, report, &classes, &candidates).unwrap_or_default();
        Self {
            by_class: candidates
                .into_iter()
                .filter(|(class, _): &(String, RecoveredMethodRef)| accepted.contains(class))
                .collect(),
        }
    }

    pub(crate) fn suppresses_class(&self, class: &str) -> bool {
        self.by_class.contains_key(class)
    }

    pub(crate) fn recovered(&self, class: &str) -> Option<&RecoveredMethodRef> {
        self.by_class.get(class)
    }
}

fn is_lambda_shaped(declaration: &ClassDeclaration) -> bool {
    declaration.access_flags & ACC_SYNTHETIC != 0
        && declaration.access_flags & ACC_FINAL != 0
        && declaration.access_flags & ACC_INTERFACE == 0
        && declaration.access_flags & ACC_ABSTRACT == 0
        && declaration.superclass.as_deref() == Some(OBJECT_DESCRIPTOR)
        && declaration.interfaces.len() == 1
}

fn match_lambda_class(
    dex: &DexFile,
    report: &CodeItemsReport,
    classes: &BTreeMap<String, ClassDeclaration>,
    declared_access: &BTreeMap<u32, u32>,
    class: &str,
    methods: &[&DexMethodCode],
) -> Option<RecoveredMethodRef> {
    if methods.len() != 2 {
        return None;
    }
    let first: &DexMethodCode = methods.first().copied()?;
    let second: &DexMethodCode = methods.get(1).copied()?;
    let (constructor, implementation): (&DexMethodCode, &DexMethodCode) =
        match (first.is_direct, second.is_direct) {
            (true, false) => (first, second),
            (false, true) => (second, first),
            _ => return None,
        };
    if constructor.method_name != "<init>"
        || implementation.access_flags & (ACC_STATIC | ACC_ABSTRACT) != 0
        || implementation.access_flags & ACC_SYNTHETIC != 0
    {
        return None;
    }
    let DexCodeState::Decoded(constructor_index) = constructor.state else {
        return None;
    };
    let DexCodeState::Decoded(implementation_index) = implementation.state else {
        return None;
    };
    let constructor_item: &CodeItem = report.decoded().get(constructor_index)?;
    let implementation_item: &CodeItem = report.decoded().get(implementation_index)?;
    let captures: Vec<u32> = constructor_captures(dex, class, constructor_item)?;
    match_reference_body(
        dex,
        classes,
        declared_access,
        implementation_item,
        &captures,
    )
}

fn instance_parameter_layout(item: &CodeItem) -> Option<(u16, Vec<u16>)> {
    let parsed: MethodDescriptor = crate::descriptor::parse_method(&item.method_descriptor)?;
    let mut cursor: u16 = item.registers_size.checked_sub(item.ins_size)?;
    let this_reg: u16 = cursor;
    cursor = cursor.checked_add(1)?;
    let mut params: Vec<u16> = Vec::with_capacity(parsed.params.len());
    for param in &parsed.params {
        params.push(cursor);
        cursor = cursor.checked_add(if param.category_two() { 2 } else { 1 })?;
    }
    if cursor != item.registers_size {
        return None;
    }
    Some((this_reg, params))
}

fn constructor_captures(dex: &DexFile, class: &str, item: &CodeItem) -> Option<Vec<u32>> {
    if !item.tries.is_empty() {
        return None;
    }
    let (this_reg, param_regs): (u16, Vec<u16>) = instance_parameter_layout(item)?;
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if insns.len() != param_regs.len().checked_add(2)? {
        return None;
    }
    let opening: &DalvikInsn = insns.first()?;
    if opening.op != 0x70 || opening.regs.as_slice() != [this_reg] {
        return None;
    }
    let superclass_init: &crate::dex::MethodId = dex.method_ids.get(opening.index? as usize)?;
    if superclass_init.class != OBJECT_DESCRIPTOR
        || superclass_init.name != "<init>"
        || !superclass_init.proto.parameters.is_empty()
    {
        return None;
    }
    let mut captures: Vec<u32> = Vec::with_capacity(param_regs.len());
    for (position, &param_reg) in param_regs.iter().enumerate() {
        let store: &DalvikInsn = insns.get(position.checked_add(1)?)?;
        if !matches!(store.op, 0x59..=0x5F) || store.regs.as_slice() != [param_reg, this_reg] {
            return None;
        }
        let field_index: u32 = store.index?;
        let field: &crate::dex::FieldId = dex.field_ids.get(field_index as usize)?;
        if field.class != class || captures.contains(&field_index) {
            return None;
        }
        captures.push(field_index);
    }
    if insns.last()?.op != 0x0E {
        return None;
    }
    Some(captures)
}

fn is_boxing_adapter(method: &crate::dex::MethodId) -> bool {
    BOX_TYPES
        .iter()
        .any(|&(boxed, unbox, primitive): &(&str, &str, &str)| {
            if method.class != boxed {
                return false;
            }
            let unboxes: bool = method.name == unbox
                && method.proto.parameters.is_empty()
                && method.proto.return_type == primitive;
            let boxes: bool = method.name == "valueOf"
                && method.proto.return_type == boxed
                && method.proto.parameters.len() == 1
                && method
                    .proto
                    .parameters
                    .first()
                    .is_some_and(|p: &String| p == primitive);
            unboxes || boxes
        })
}

const fn is_category_two(descriptor: &str) -> bool {
    matches!(descriptor.as_bytes(), [b'J' | b'D'])
}

fn match_reference_body(
    dex: &DexFile,
    classes: &BTreeMap<String, ClassDeclaration>,
    declared_access: &BTreeMap<u32, u32>,
    item: &CodeItem,
    captures: &[u32],
) -> Option<RecoveredMethodRef> {
    if !item.tries.is_empty() {
        return None;
    }
    let parsed: MethodDescriptor = crate::descriptor::parse_method(&item.method_descriptor)?;
    let (this_reg, param_regs): (u16, Vec<u16>) = instance_parameter_layout(item)?;
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    if insns.is_empty() || insns.len() > MAX_REFERENCE_BODY_INSNS {
        return None;
    }
    let mut invoke_total: usize = 0;
    let mut non_adapter: usize = 0;
    for insn in &insns {
        if !matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78) {
            continue;
        }
        invoke_total = invoke_total.checked_add(1)?;
        let method: &crate::dex::MethodId = dex.method_ids.get(insn.index? as usize)?;
        if !is_boxing_adapter(method) {
            non_adapter = non_adapter.checked_add(1)?;
        }
    }
    let adapters_transparent: bool = invoke_total > 1;
    if invoke_total == 0 || (adapters_transparent && non_adapter != 1) {
        return None;
    }

    let mut values: BTreeMap<u16, RefValue> = BTreeMap::new();
    values.insert(this_reg, RefValue::Receiver);
    for (position, &reg) in param_regs.iter().enumerate() {
        values.insert(reg, RefValue::Parameter(position));
    }
    let mut pending: Option<RefValue> = None;
    let mut target: Option<TargetCall> = None;
    let mut exit: Option<Option<RefValue>> = None;

    for (position, insn) in insns.iter().enumerate() {
        if exit.is_some() {
            return None;
        }
        let last: bool = position.checked_add(1)? == insns.len();
        match insn.op {
            0x01..=0x09 => {
                let (&dest, &src): (&u16, &u16) = (insn.regs.first()?, insn.regs.get(1)?);
                let value: RefValue = *values.get(&src)?;
                values.insert(dest, value);
            }
            0x0A..=0x0C => {
                let &dest: &u16 = insn.regs.first()?;
                values.insert(dest, pending.take()?);
            }
            0x0E => {
                if !last {
                    return None;
                }
                exit = Some(None);
            }
            0x0F..=0x11 => {
                if !last {
                    return None;
                }
                let &reg: &u16 = insn.regs.first()?;
                exit = Some(Some(*values.get(&reg)?));
            }
            0x1F => {
                let &reg: &u16 = insn.regs.first()?;
                if !values.contains_key(&reg) {
                    return None;
                }
            }
            0x22 => {
                let &dest: &u16 = insn.regs.first()?;
                values.insert(dest, RefValue::Allocation(insn.index?));
            }
            0x52..=0x58 => {
                let (&dest, &object): (&u16, &u16) = (insn.regs.first()?, insn.regs.get(1)?);
                if values.get(&object) != Some(&RefValue::Receiver) {
                    return None;
                }
                let field_index: u32 = insn.index?;
                let slot: usize = captures
                    .iter()
                    .position(|&candidate: &u32| candidate == field_index)?;
                values.insert(dest, RefValue::Capture(slot));
            }
            0x6E..=0x72 => {
                let call: TargetCall = read_invoke(dex, &values, insn)?;
                let method: &crate::dex::MethodId =
                    dex.method_ids.get(call.method_index as usize)?;
                if adapters_transparent && is_boxing_adapter(method) {
                    pending = Some(adapter_source(&call)?);
                    continue;
                }
                if target.is_some()
                    || declared_access
                        .get(&call.method_index)
                        .is_some_and(|flags: &u32| flags & ACC_SYNTHETIC != 0)
                    || classes
                        .get(&method.class)
                        .is_some_and(|d: &ClassDeclaration| d.access_flags & ACC_SYNTHETIC != 0)
                {
                    return None;
                }
                match (insn.op, call.is_constructor) {
                    (0x70, true) => {
                        let RefValue::Allocation(type_index) = call.receiver? else {
                            return None;
                        };
                        if dex.type_names.get(type_index as usize)? != &method.class {
                            return None;
                        }
                        let &allocated: &u16 = insn.regs.first()?;
                        values.insert(allocated, RefValue::Product);
                        pending = None;
                    }
                    (0x6E | 0x71 | 0x72, false) => {
                        pending = if method.proto.return_type == "V" {
                            None
                        } else {
                            Some(RefValue::Product)
                        };
                    }
                    _ => return None,
                }
                target = Some(call);
            }
            _ => return None,
        }
    }

    let target: TargetCall = target?;
    let method: &crate::dex::MethodId = dex.method_ids.get(target.method_index as usize)?;
    match (parsed.returns, exit?) {
        (crate::descriptor::JavaType::Void, None) => {}
        (crate::descriptor::JavaType::Void, Some(_)) | (_, None) => return None,
        (_, Some(returned)) => {
            if returned != RefValue::Product {
                return None;
            }
        }
    }
    classify_reference(method, &target, captures.len(), param_regs.len())
}

fn adapter_source(call: &TargetCall) -> Option<RefValue> {
    if call.is_static {
        if call.args.len() != 1 {
            return None;
        }
        return call.args.first().copied();
    }
    if !call.args.is_empty() {
        return None;
    }
    call.receiver
}

fn read_invoke(
    dex: &DexFile,
    values: &BTreeMap<u16, RefValue>,
    insn: &DalvikInsn,
) -> Option<TargetCall> {
    let method_index: u32 = insn.index?;
    let method: &crate::dex::MethodId = dex.method_ids.get(method_index as usize)?;
    let is_static: bool = insn.op == 0x71;
    let mut slots: std::slice::Iter<'_, u16> = insn.regs.iter();
    let receiver: Option<RefValue> = if is_static {
        None
    } else {
        Some(*values.get(slots.next()?)?)
    };
    let mut args: Vec<RefValue> = Vec::with_capacity(method.proto.parameters.len());
    for parameter in &method.proto.parameters {
        let &reg: &u16 = slots.next()?;
        args.push(*values.get(&reg).unwrap_or(&RefValue::Unknown));
        if is_category_two(parameter) {
            let _: &u16 = slots.next()?;
        }
    }
    if slots.next().is_some() {
        return None;
    }
    Some(TargetCall {
        method_index,
        receiver,
        args,
        is_constructor: method.name == "<init>",
        is_static,
    })
}

fn args_are_parameters(args: &[RefValue], offset: usize) -> bool {
    args.iter()
        .enumerate()
        .all(|(position, value): (usize, &RefValue)| {
            position
                .checked_add(offset)
                .is_some_and(|expected: usize| *value == RefValue::Parameter(expected))
        })
}

fn classify_reference(
    method: &crate::dex::MethodId,
    target: &TargetCall,
    captures: usize,
    interface_arity: usize,
) -> Option<RecoveredMethodRef> {
    let kind: MethodRefKind = if target.is_constructor {
        if captures != 0
            || target.args.len() != interface_arity
            || !args_are_parameters(&target.args, 0)
        {
            return None;
        }
        MethodRefKind::Constructor
    } else if target.is_static {
        if captures != 0
            || target.args.len() != interface_arity
            || !args_are_parameters(&target.args, 0)
        {
            return None;
        }
        MethodRefKind::Static
    } else {
        match target.receiver? {
            RefValue::Parameter(0) => {
                if captures != 0
                    || interface_arity == 0
                    || target.args.len().checked_add(1)? != interface_arity
                    || !args_are_parameters(&target.args, 1)
                {
                    return None;
                }
                MethodRefKind::UnboundInstance
            }
            RefValue::Capture(0) => {
                if captures != 1
                    || target.args.len() != interface_arity
                    || !args_are_parameters(&target.args, 0)
                {
                    return None;
                }
                MethodRefKind::BoundInstance
            }
            _ => return None,
        }
    };
    let name: String = if target.is_constructor {
        "new".to_owned()
    } else {
        if !crate::name_disambig::is_java_source_identifier(&method.name) {
            return None;
        }
        method.name.clone()
    };
    Some(RecoveredMethodRef {
        kind,
        owner: method.class.clone(),
        name,
    })
}

fn exclusively_constructed(
    dex: &DexFile,
    report: &CodeItemsReport,
    classes: &BTreeMap<String, ClassDeclaration>,
    candidates: &BTreeMap<String, RecoveredMethodRef>,
) -> Option<BTreeSet<String>> {
    let mut accepted: BTreeSet<String> = candidates.keys().cloned().collect();
    let types: BTreeMap<u32, String> = dex
        .type_names
        .iter()
        .enumerate()
        .filter(|(_, name): &(usize, &String)| candidates.contains_key(*name))
        .filter_map(|(index, name): (usize, &String)| {
            Some((u32::try_from(index).ok()?, name.clone()))
        })
        .collect();
    let binary_names: BTreeMap<String, String> = candidates
        .keys()
        .map(|class: &String| {
            (
                class
                    .trim_start_matches('L')
                    .trim_end_matches(';')
                    .replace('/', "."),
                class.clone(),
            )
        })
        .collect();
    for declaration in classes.values() {
        if let Some(superclass) = declaration.superclass.as_ref() {
            accepted.remove(superclass);
        }
        for interface in &declaration.interfaces {
            accepted.remove(interface);
        }
    }
    for field in &dex.field_ids {
        accepted.remove(&field.type_name);
    }
    for method in &dex.method_ids {
        accepted.remove(&method.proto.return_type);
        for parameter in &method.proto.parameters {
            accepted.remove(parameter);
        }
    }
    for value in &dex.strings {
        if let Some(class) = binary_names.get(value.as_str()) {
            accepted.remove(class);
        }
    }
    let mut work: usize = 0;
    let mut constructed_here: BTreeSet<String> = BTreeSet::new();
    for item in report.decoded() {
        if candidates.contains_key(item.class.as_str()) {
            continue;
        }
        let insns: Vec<DalvikInsn> = decode_method(&item.insns);
        work = work.checked_add(insns.len())?;
        if work > MAX_DESUGAR_SCAN_INSNS {
            return None;
        }
        let mut live: BTreeMap<u16, String> = BTreeMap::new();
        for insn in &insns {
            let constructed: Option<String> = construction_site(dex, candidates, insn);
            if let Some(class) = constructed {
                constructed_here.insert(class.clone());
                let receiver: u16 = *insn.regs.first()?;
                match live.remove(&receiver) {
                    Some(pending) if pending == class => {}
                    Some(pending) => {
                        accepted.remove(&pending);
                        accepted.remove(&class);
                    }
                    None => {
                        accepted.remove(&class);
                    }
                }
                for &reg in insn.regs.iter().skip(1) {
                    if let Some(pending) = live.get(&reg) {
                        accepted.remove(pending);
                    }
                }
                continue;
            }
            if insn.op == 0x22
                && let Some(class) = insn.index.and_then(|i: u32| types.get(&i))
            {
                let dest: u16 = *insn.regs.first()?;
                if let Some(pending) = live.insert(dest, class.clone()) {
                    accepted.remove(&pending);
                }
                continue;
            }
            if !live.is_empty() && transfers_control(insn.op) {
                for pending in live.values() {
                    accepted.remove(pending);
                }
                live.clear();
            }
            for &reg in &insn.regs {
                if let Some(pending) = live.get(&reg) {
                    accepted.remove(pending);
                }
            }
            if let Some(class) = referenced_candidate(dex, candidates, &types, insn) {
                accepted.remove(&class);
            }
        }
        for pending in live.values() {
            accepted.remove(pending);
        }
    }
    accepted.retain(|class: &String| constructed_here.contains(class));
    Some(accepted)
}

const fn transfers_control(op: u8) -> bool {
    matches!(op, 0x0E..=0x11 | 0x27..=0x2C | 0x32..=0x3D)
}

fn construction_site(
    dex: &DexFile,
    candidates: &BTreeMap<String, RecoveredMethodRef>,
    insn: &DalvikInsn,
) -> Option<String> {
    if insn.op != 0x70 {
        return None;
    }
    let method: &crate::dex::MethodId = dex.method_ids.get(insn.index? as usize)?;
    if method.name != "<init>" || !candidates.contains_key(&method.class) {
        return None;
    }
    Some(method.class.clone())
}

fn referenced_candidate(
    dex: &DexFile,
    candidates: &BTreeMap<String, RecoveredMethodRef>,
    types: &BTreeMap<u32, String>,
    insn: &DalvikInsn,
) -> Option<String> {
    let index: u32 = insn.index?;
    match insn.op {
        0x1C | 0x1F | 0x20 | 0x22..=0x25 => types.get(&index).cloned(),
        0x52..=0x6D => dex
            .field_ids
            .get(index as usize)
            .map(|field: &crate::dex::FieldId| field.class.clone())
            .filter(|class: &String| candidates.contains_key(class)),
        0x6E..=0x72 | 0x74..=0x78 => dex
            .method_ids
            .get(index as usize)
            .map(|method: &crate::dex::MethodId| method.class.clone())
            .filter(|class: &String| candidates.contains_key(class)),
        _ => None,
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
