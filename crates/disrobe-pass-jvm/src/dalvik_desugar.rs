use std::collections::{BTreeMap, BTreeSet};

use crate::dalvik::{DalvikInsn, decode_method};
use crate::descriptor::{JavaType, MethodDescriptor};
use crate::dex::{
    ACC_ABSTRACT, ACC_STATIC, CodeItem, CodeItemsReport, DexCodeState, DexFile, DexMethodCode,
};

const ACC_INTERFACE: u32 = 0x0200;
const ACC_PUBLIC: u32 = 0x0001;
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
    pub(crate) kind: InterfaceMethodKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InterfaceMethodKind {
    Default,
    Static,
}

#[derive(Debug, Default)]
pub(crate) struct DefaultInterfaceRecovery {
    methods: BTreeMap<(String, String, String), DefaultInterfaceMethod>,
    injected_methods: BTreeMap<String, Vec<DefaultInterfaceMethod>>,
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
            let DexCodeState::Decoded(bridge_item) = method.state else {
                rejected_companions.insert(method.class.clone());
                continue;
            };
            if report.decoded().get(bridge_item).is_none() {
                rejected_companions.insert(method.class.clone());
                continue;
            }
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
            if !owner_matches || !name_matches {
                rejected_companions.insert(method.class.clone());
                continue;
            }
            let (name, descriptor, kind): (String, String, InterfaceMethodKind) =
                if let Some(name) = method.method_name.strip_prefix("$default$") {
                    if bridge_id.proto.parameters.first() != Some(&interface) {
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
                    (
                        name.to_string(),
                        target.method_descriptor.clone(),
                        InterfaceMethodKind::Default,
                    )
                } else {
                    if method.method_name.starts_with('<')
                        || method.access_flags != (ACC_PUBLIC | ACC_STATIC)
                        || report.methods().iter().any(|target: &DexMethodCode| {
                            target.class == interface
                                && target.method_name == method.method_name
                                && target.method_descriptor == method.method_descriptor
                        })
                    {
                        rejected_companions.insert(method.class.clone());
                        continue;
                    }
                    (
                        method.method_name.clone(),
                        method.method_descriptor.clone(),
                        InterfaceMethodKind::Static,
                    )
                };
            let bridge_method: u32 = method.method_index;
            candidates
                .entry(method.class.clone())
                .or_default()
                .push(DefaultInterfaceMethod {
                    interface,
                    name,
                    descriptor,
                    bridge_item,
                    bridge_method,
                    kind,
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
                if method.kind == InterfaceMethodKind::Default
                    && (sites.is_empty()
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
                        }))
                {
                    valid = false;
                    break;
                }
                if method.kind == InterfaceMethodKind::Default {
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
                match method.kind {
                    InterfaceMethodKind::Default => {
                        recovery.methods.insert(
                            (
                                method.interface.clone(),
                                method.name.clone(),
                                method.descriptor.clone(),
                            ),
                            method,
                        );
                    }
                    InterfaceMethodKind::Static => recovery
                        .injected_methods
                        .entry(method.interface.clone())
                        .or_default()
                        .push(method),
                }
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

    pub(crate) fn injected_methods(&self, class: &str) -> &[DefaultInterfaceMethod] {
        self.injected_methods.get(class).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn recovers_interface(&self, class: &str) -> bool {
        self.methods
            .values()
            .any(|method: &DefaultInterfaceMethod| method.interface == class)
            || self.injected_methods.contains_key(class)
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
                crate::descriptor::descriptor_to_binary_name(companion).replace('/', "."),
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
                    if let Some(companion) = bridge_owners.get(&index)
                        && matches!(insn.op, 0x71 | 0x77)
                    {
                        let target: &crate::dex::MethodId = dex.method_ids.get(index as usize)?;
                        if invoke_word_count(target) != Some(insn.regs.len()) {
                            escaped.insert(companion.clone());
                            continue;
                        }
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

fn invoke_word_count(method: &crate::dex::MethodId) -> Option<usize> {
    method
        .proto
        .parameters
        .iter()
        .try_fold(0usize, |words: usize, parameter: &String| {
            words.checked_add(usize::from(matches!(parameter.as_str(), "J" | "D")) + 1)
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

#[derive(Debug, Clone)]
pub(crate) struct HelperBody {
    pub(crate) insns: Vec<u16>,
    pub(crate) registers_size: u16,
    pub(crate) ins_size: u16,
    pub(crate) descriptor: String,
    pub(crate) is_static: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct RecoveredCapturedLambda {
    pub(crate) helper_owner: String,
    pub(crate) helper_name: String,
    pub(crate) receiver_capture: bool,
    pub(crate) capture_count: usize,
    pub(crate) parameter_count: usize,
    pub(crate) helper_index: u32,
    pub(crate) helper_body: Option<HelperBody>,
}

#[derive(Debug, Clone)]
pub(crate) enum RecoveredFunctional {
    MethodReference(RecoveredMethodRef),
    CapturedLambda(RecoveredCapturedLambda),
}

#[derive(Debug, Default)]
pub(crate) struct FunctionalRecovery {
    by_class: BTreeMap<String, RecoveredFunctional>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DesugarView<'a> {
    pub(crate) interfaces: &'a DefaultInterfaceRecovery,
    pub(crate) functionals: &'a FunctionalRecovery,
    pub(crate) core_library: &'a crate::dalvik_core_library::CoreLibraryRecovery,
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
const LAMBDA_HELPER_PREFIX: &str = "lambda$";
const FUNCTIONAL_INTERFACES: [(&str, &str, &str); 66] = [
    (
        "Landroid/animation/ValueAnimator$AnimatorUpdateListener;",
        "onAnimationUpdate",
        "(Landroid/animation/ValueAnimator;)V",
    ),
    (
        "Landroid/content/DialogInterface$OnCancelListener;",
        "onCancel",
        "(Landroid/content/DialogInterface;)V",
    ),
    (
        "Landroid/content/DialogInterface$OnClickListener;",
        "onClick",
        "(Landroid/content/DialogInterface;I)V",
    ),
    (
        "Landroid/content/DialogInterface$OnDismissListener;",
        "onDismiss",
        "(Landroid/content/DialogInterface;)V",
    ),
    (
        "Landroid/os/Handler$Callback;",
        "handleMessage",
        "(Landroid/os/Message;)Z",
    ),
    (
        "Landroid/view/MenuItem$OnMenuItemClickListener;",
        "onMenuItemClick",
        "(Landroid/view/MenuItem;)Z",
    ),
    (
        "Landroid/view/View$OnClickListener;",
        "onClick",
        "(Landroid/view/View;)V",
    ),
    (
        "Landroid/view/View$OnFocusChangeListener;",
        "onFocusChange",
        "(Landroid/view/View;Z)V",
    ),
    (
        "Landroid/view/View$OnLongClickListener;",
        "onLongClick",
        "(Landroid/view/View;)Z",
    ),
    (
        "Landroid/view/View$OnTouchListener;",
        "onTouch",
        "(Landroid/view/View;Landroid/view/MotionEvent;)Z",
    ),
    (
        "Landroid/widget/AdapterView$OnItemClickListener;",
        "onItemClick",
        "(Landroid/widget/AdapterView;Landroid/view/View;IJ)V",
    ),
    (
        "Landroid/widget/CompoundButton$OnCheckedChangeListener;",
        "onCheckedChanged",
        "(Landroid/widget/CompoundButton;Z)V",
    ),
    ("Ljava/io/FileFilter;", "accept", "(Ljava/io/File;)Z"),
    (
        "Ljava/io/FilenameFilter;",
        "accept",
        "(Ljava/io/File;Ljava/lang/String;)Z",
    ),
    ("Ljava/lang/Iterable;", "iterator", "()Ljava/util/Iterator;"),
    ("Ljava/lang/Runnable;", "run", "()V"),
    (
        "Ljava/lang/Thread$UncaughtExceptionHandler;",
        "uncaughtException",
        "(Ljava/lang/Thread;Ljava/lang/Throwable;)V",
    ),
    (
        "Ljava/nio/file/PathMatcher;",
        "matches",
        "(Ljava/nio/file/Path;)Z",
    ),
    (
        "Ljava/security/PrivilegedAction;",
        "run",
        "()Ljava/lang/Object;",
    ),
    (
        "Ljava/util/Comparator;",
        "compare",
        "(Ljava/lang/Object;Ljava/lang/Object;)I",
    ),
    (
        "Ljava/util/concurrent/Callable;",
        "call",
        "()Ljava/lang/Object;",
    ),
    (
        "Ljava/util/concurrent/Executor;",
        "execute",
        "(Ljava/lang/Runnable;)V",
    ),
    (
        "Ljava/util/concurrent/ThreadFactory;",
        "newThread",
        "(Ljava/lang/Runnable;)Ljava/lang/Thread;",
    ),
    (
        "Ljava/util/function/BiConsumer;",
        "accept",
        "(Ljava/lang/Object;Ljava/lang/Object;)V",
    ),
    (
        "Ljava/util/function/BiFunction;",
        "apply",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
    ),
    (
        "Ljava/util/function/BiPredicate;",
        "test",
        "(Ljava/lang/Object;Ljava/lang/Object;)Z",
    ),
    (
        "Ljava/util/function/BinaryOperator;",
        "apply",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
    ),
    (
        "Ljava/util/function/BooleanSupplier;",
        "getAsBoolean",
        "()Z",
    ),
    (
        "Ljava/util/function/Consumer;",
        "accept",
        "(Ljava/lang/Object;)V",
    ),
    (
        "Ljava/util/function/DoubleBinaryOperator;",
        "applyAsDouble",
        "(DD)D",
    ),
    ("Ljava/util/function/DoubleConsumer;", "accept", "(D)V"),
    (
        "Ljava/util/function/DoubleFunction;",
        "apply",
        "(D)Ljava/lang/Object;",
    ),
    ("Ljava/util/function/DoublePredicate;", "test", "(D)Z"),
    ("Ljava/util/function/DoubleSupplier;", "getAsDouble", "()D"),
    (
        "Ljava/util/function/DoubleToIntFunction;",
        "applyAsInt",
        "(D)I",
    ),
    (
        "Ljava/util/function/DoubleToLongFunction;",
        "applyAsLong",
        "(D)J",
    ),
    (
        "Ljava/util/function/DoubleUnaryOperator;",
        "applyAsDouble",
        "(D)D",
    ),
    (
        "Ljava/util/function/Function;",
        "apply",
        "(Ljava/lang/Object;)Ljava/lang/Object;",
    ),
    (
        "Ljava/util/function/IntBinaryOperator;",
        "applyAsInt",
        "(II)I",
    ),
    ("Ljava/util/function/IntConsumer;", "accept", "(I)V"),
    (
        "Ljava/util/function/IntFunction;",
        "apply",
        "(I)Ljava/lang/Object;",
    ),
    ("Ljava/util/function/IntPredicate;", "test", "(I)Z"),
    ("Ljava/util/function/IntSupplier;", "getAsInt", "()I"),
    (
        "Ljava/util/function/IntToDoubleFunction;",
        "applyAsDouble",
        "(I)D",
    ),
    (
        "Ljava/util/function/IntToLongFunction;",
        "applyAsLong",
        "(I)J",
    ),
    (
        "Ljava/util/function/IntUnaryOperator;",
        "applyAsInt",
        "(I)I",
    ),
    (
        "Ljava/util/function/LongBinaryOperator;",
        "applyAsLong",
        "(JJ)J",
    ),
    ("Ljava/util/function/LongConsumer;", "accept", "(J)V"),
    (
        "Ljava/util/function/LongFunction;",
        "apply",
        "(J)Ljava/lang/Object;",
    ),
    ("Ljava/util/function/LongPredicate;", "test", "(J)Z"),
    ("Ljava/util/function/LongSupplier;", "getAsLong", "()J"),
    (
        "Ljava/util/function/LongToDoubleFunction;",
        "applyAsDouble",
        "(J)D",
    ),
    (
        "Ljava/util/function/LongToIntFunction;",
        "applyAsInt",
        "(J)I",
    ),
    (
        "Ljava/util/function/LongUnaryOperator;",
        "applyAsLong",
        "(J)J",
    ),
    (
        "Ljava/util/function/ObjDoubleConsumer;",
        "accept",
        "(Ljava/lang/Object;D)V",
    ),
    (
        "Ljava/util/function/ObjIntConsumer;",
        "accept",
        "(Ljava/lang/Object;I)V",
    ),
    (
        "Ljava/util/function/ObjLongConsumer;",
        "accept",
        "(Ljava/lang/Object;J)V",
    ),
    (
        "Ljava/util/function/Predicate;",
        "test",
        "(Ljava/lang/Object;)Z",
    ),
    (
        "Ljava/util/function/Supplier;",
        "get",
        "()Ljava/lang/Object;",
    ),
    (
        "Ljava/util/function/ToDoubleBiFunction;",
        "applyAsDouble",
        "(Ljava/lang/Object;Ljava/lang/Object;)D",
    ),
    (
        "Ljava/util/function/ToDoubleFunction;",
        "applyAsDouble",
        "(Ljava/lang/Object;)D",
    ),
    (
        "Ljava/util/function/ToIntBiFunction;",
        "applyAsInt",
        "(Ljava/lang/Object;Ljava/lang/Object;)I",
    ),
    (
        "Ljava/util/function/ToIntFunction;",
        "applyAsInt",
        "(Ljava/lang/Object;)I",
    ),
    (
        "Ljava/util/function/ToLongBiFunction;",
        "applyAsLong",
        "(Ljava/lang/Object;Ljava/lang/Object;)J",
    ),
    (
        "Ljava/util/function/ToLongFunction;",
        "applyAsLong",
        "(Ljava/lang/Object;)J",
    ),
    (
        "Ljava/util/function/UnaryOperator;",
        "apply",
        "(Ljava/lang/Object;)Ljava/lang/Object;",
    ),
];
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

impl FunctionalRecovery {
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
        let invoke_counts: BTreeMap<u32, usize> = invoke_target_counts(report).unwrap_or_default();
        let mut candidates: BTreeMap<String, RecoveredFunctional> = BTreeMap::new();
        for (class, declaration) in &classes {
            if !is_lambda_shaped(declaration) {
                continue;
            }
            let Some(methods): Option<&Vec<&DexMethodCode>> = owned.get(class.as_str()) else {
                continue;
            };
            let Some(recovered): Option<RecoveredFunctional> = match_functional_class(
                dex,
                report,
                &classes,
                &declared_access,
                class,
                methods.as_slice(),
            ) else {
                continue;
            };
            let recovered: RecoveredFunctional = match recovered {
                RecoveredFunctional::CapturedLambda(mut lambda) => {
                    lambda.helper_body =
                        inlinable_helper_body(report, &invoke_counts, lambda.helper_index);
                    RecoveredFunctional::CapturedLambda(lambda)
                }
                other @ RecoveredFunctional::MethodReference(_) => other,
            };
            candidates.insert(class.clone(), recovered);
        }
        if candidates.is_empty() {
            return Self::default();
        }
        let candidate_classes: BTreeSet<String> = candidates.keys().cloned().collect();
        let accepted: BTreeSet<String> =
            exclusively_constructed(dex, report, &classes, &candidate_classes).unwrap_or_default();
        Self {
            by_class: candidates
                .into_iter()
                .filter(|(class, _): &(String, RecoveredFunctional)| accepted.contains(class))
                .collect(),
        }
    }

    pub(crate) fn suppresses_class(&self, class: &str) -> bool {
        self.by_class.contains_key(class)
    }

    pub(crate) fn recovered(&self, class: &str) -> Option<&RecoveredFunctional> {
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

fn match_functional_class(
    dex: &DexFile,
    report: &CodeItemsReport,
    classes: &BTreeMap<String, ClassDeclaration>,
    declared_access: &BTreeMap<u32, u32>,
    class: &str,
    methods: &[&DexMethodCode],
) -> Option<RecoveredFunctional> {
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
    let functional_interface: &str = classes.get(class)?.interfaces.first()?;
    let single_abstract_method: bool = declares_single_abstract_method(
        report,
        classes,
        functional_interface,
        &implementation.method_name,
        &implementation.method_descriptor,
    );
    match_reference_body(
        dex,
        classes,
        declared_access,
        implementation_item,
        implementation.method_index,
        &captures,
        single_abstract_method,
    )
}

fn roster_abstract_method(descriptor: &str) -> Option<(&'static str, &'static str)> {
    let index: usize = FUNCTIONAL_INTERFACES
        .binary_search_by(|entry: &(&str, &str, &str)| entry.0.cmp(descriptor))
        .ok()?;
    let entry: &(&'static str, &'static str, &'static str) = FUNCTIONAL_INTERFACES.get(index)?;
    Some((entry.1, entry.2))
}

fn declares_single_abstract_method(
    report: &CodeItemsReport,
    classes: &BTreeMap<String, ClassDeclaration>,
    interface: &str,
    name: &str,
    descriptor: &str,
) -> bool {
    if let Some(declaration) = classes.get(interface) {
        if declaration.access_flags & ACC_INTERFACE == 0 {
            return false;
        }
        let mut declared: Vec<&DexMethodCode> = report
            .methods()
            .iter()
            .filter(|candidate: &&DexMethodCode| {
                candidate.class == interface
                    && candidate.access_flags & ACC_ABSTRACT != 0
                    && candidate.access_flags & ACC_STATIC == 0
            })
            .collect();
        let Some(single): Option<&DexMethodCode> = declared.pop() else {
            return false;
        };
        return declared.is_empty()
            && single.method_name == name
            && single.method_descriptor == descriptor;
    }
    let relocated: String = match interface.strip_prefix("Lj$/") {
        Some(rest) => format!("Ljava/{rest}"),
        None => interface.to_owned(),
    };
    roster_abstract_method(&relocated).is_some_and(
        |(roster_name, roster_descriptor): (&str, &str)| {
            roster_name == name && roster_descriptor == descriptor
        },
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
    implementation_method: u32,
    captures: &[u32],
    single_abstract_method: bool,
) -> Option<RecoveredFunctional> {
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
    let synthetic_target: bool = declared_access
        .get(&target.method_index)
        .is_some_and(|flags: &u32| flags & ACC_SYNTHETIC != 0);
    if synthetic_target {
        return classify_captured_lambda(
            dex,
            method,
            &target,
            implementation_method,
            captures,
            param_regs.len(),
            single_abstract_method,
        )
        .map(RecoveredFunctional::CapturedLambda);
    }
    classify_reference(method, &target, captures.len(), param_regs.len())
        .map(RecoveredFunctional::MethodReference)
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

const fn is_reference_descriptor(descriptor: &str) -> bool {
    matches!(descriptor.as_bytes().first(), Some(b'L' | b'['))
}

fn erasure_compatible(declared: &str, erased: &str) -> bool {
    declared == erased || (is_reference_descriptor(declared) && is_reference_descriptor(erased))
}

fn classify_captured_lambda(
    dex: &DexFile,
    method: &crate::dex::MethodId,
    target: &TargetCall,
    implementation_method: u32,
    captures: &[u32],
    interface_arity: usize,
    single_abstract_method: bool,
) -> Option<RecoveredCapturedLambda> {
    if !single_abstract_method
        || target.is_constructor
        || !method.name.starts_with(LAMBDA_HELPER_PREFIX)
        || !crate::name_disambig::is_java_source_identifier(&method.name)
    {
        return None;
    }
    let implementation: &crate::dex::MethodId =
        dex.method_ids.get(implementation_method as usize)?;
    if implementation.proto.parameters.len() != interface_arity
        || !erasure_compatible(&method.proto.return_type, &implementation.proto.return_type)
    {
        return None;
    }
    let mut capture_types: Vec<&str> = Vec::with_capacity(captures.len());
    for &field_index in captures {
        let field: &crate::dex::FieldId = dex.field_ids.get(field_index as usize)?;
        capture_types.push(field.type_name.as_str());
    }
    let receiver_capture: bool = !target.is_static;
    let forwarded: &[&str] = if receiver_capture {
        if target.receiver != Some(RefValue::Capture(0))
            || capture_types.first().copied() != Some(method.class.as_str())
        {
            return None;
        }
        capture_types.get(1..)?
    } else {
        if target.receiver.is_some() {
            return None;
        }
        capture_types.as_slice()
    };
    let first_forwarded: usize = usize::from(receiver_capture);
    let mut expected_arguments: Vec<RefValue> =
        Vec::with_capacity(forwarded.len().checked_add(interface_arity)?);
    for slot in 0..forwarded.len() {
        expected_arguments.push(RefValue::Capture(slot.checked_add(first_forwarded)?));
    }
    for position in 0..interface_arity {
        expected_arguments.push(RefValue::Parameter(position));
    }
    if target.args != expected_arguments {
        return None;
    }
    if method.proto.parameters.len() != forwarded.len().checked_add(interface_arity)? {
        return None;
    }
    for (position, declared) in method.proto.parameters.iter().enumerate() {
        let matches: bool = match forwarded.get(position) {
            Some(capture) => declared.as_str() == *capture,
            None => erasure_compatible(
                declared,
                implementation
                    .proto
                    .parameters
                    .get(position.checked_sub(forwarded.len())?)?,
            ),
        };
        if !matches {
            return None;
        }
    }
    Some(RecoveredCapturedLambda {
        helper_owner: method.class.clone(),
        helper_name: method.name.clone(),
        receiver_capture,
        capture_count: captures.len(),
        parameter_count: interface_arity,
        helper_index: target.method_index,
        helper_body: None,
    })
}

const MAX_INLINE_BODY_INSNS: usize = 64;

const fn inlinable_opcode(op: u8) -> bool {
    matches!(
        op,
        0x00 | 0x01..=0x0C
            | 0x0E..=0x1B
            | 0x1F..=0x22
            | 0x2D..=0x31
            | 0x44..=0x4A
            | 0x52..=0x58
            | 0x60..=0x66
            | 0x6E..=0x72
            | 0x74..=0x78
            | 0x7B..=0xE2
    )
}

fn invoke_target_counts(report: &CodeItemsReport) -> Option<BTreeMap<u32, usize>> {
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    let mut work: usize = 0;
    for item in report.decoded() {
        let instructions: Vec<DalvikInsn> = decode_method(&item.insns);
        work = work.checked_add(instructions.len())?;
        if work > MAX_DESUGAR_SCAN_INSNS {
            return None;
        }
        for insn in instructions {
            if matches!(insn.op, 0x6E..=0x72 | 0x74..=0x78)
                && let Some(index) = insn.index
            {
                let seen: &mut usize = counts.entry(index).or_insert(0);
                *seen = seen.checked_add(1)?;
            }
        }
    }
    Some(counts)
}

fn inlinable_helper_body(
    report: &CodeItemsReport,
    invoke_counts: &BTreeMap<u32, usize>,
    helper_index: u32,
) -> Option<HelperBody> {
    if invoke_counts.get(&helper_index).copied() != Some(1) {
        return None;
    }
    let method: &DexMethodCode = report
        .methods()
        .iter()
        .find(|candidate: &&DexMethodCode| candidate.method_index == helper_index)?;
    let DexCodeState::Decoded(index) = method.state else {
        return None;
    };
    let item: &CodeItem = report.decoded().get(index)?;
    if !item.tries.is_empty() {
        return None;
    }
    let instructions: Vec<DalvikInsn> = decode_method(&item.insns);
    if instructions.is_empty() || instructions.len() > MAX_INLINE_BODY_INSNS {
        return None;
    }
    if !instructions
        .iter()
        .all(|insn: &DalvikInsn| inlinable_opcode(insn.op))
    {
        return None;
    }
    Some(HelperBody {
        insns: item.insns.clone(),
        registers_size: item.registers_size,
        ins_size: item.ins_size,
        descriptor: item.method_descriptor.clone(),
        is_static: method.access_flags & ACC_STATIC != 0,
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
    candidates: &BTreeSet<String>,
) -> Option<BTreeSet<String>> {
    let mut accepted: BTreeSet<String> = candidates.clone();
    let types: BTreeMap<u32, String> = dex
        .type_names
        .iter()
        .enumerate()
        .filter(|(_, name): &(usize, &String)| candidates.contains(*name))
        .filter_map(|(index, name): (usize, &String)| {
            Some((u32::try_from(index).ok()?, name.clone()))
        })
        .collect();
    let binary_names: BTreeMap<String, String> = candidates
        .iter()
        .map(|class: &String| {
            (
                crate::descriptor::descriptor_to_binary_name(class).replace('/', "."),
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
        let owner_is_candidate: bool = candidates.contains(item.class.as_str());
        let insns: Vec<DalvikInsn> = decode_method(&item.insns);
        work = work.checked_add(insns.len())?;
        if work > MAX_DESUGAR_SCAN_INSNS {
            return None;
        }
        let mut live: BTreeMap<u16, String> = BTreeMap::new();
        for insn in &insns {
            let constructed: Option<String> = construction_site(dex, candidates, insn);
            if let Some(class) = constructed {
                if owner_is_candidate {
                    accepted.remove(item.class.as_str());
                    accepted.remove(&class);
                    continue;
                }
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
                debit_candidate_reference(&mut accepted, item.class.as_str(), &class);
            }
        }
        for pending in live.values() {
            accepted.remove(pending);
        }
    }
    accepted.retain(|class: &String| constructed_here.contains(class));
    Some(accepted)
}

fn debit_candidate_reference(accepted: &mut BTreeSet<String>, owner: &str, referenced: &str) {
    if owner == referenced {
        return;
    }
    accepted.remove(referenced);
    accepted.remove(owner);
}

const fn transfers_control(op: u8) -> bool {
    matches!(op, 0x0E..=0x11 | 0x27..=0x2C | 0x32..=0x3D)
}

fn construction_site(
    dex: &DexFile,
    candidates: &BTreeSet<String>,
    insn: &DalvikInsn,
) -> Option<String> {
    if insn.op != 0x70 {
        return None;
    }
    let method: &crate::dex::MethodId = dex.method_ids.get(insn.index? as usize)?;
    if method.name != "<init>" || !candidates.contains(&method.class) {
        return None;
    }
    Some(method.class.clone())
}

fn referenced_candidate(
    dex: &DexFile,
    candidates: &BTreeSet<String>,
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
            .filter(|class: &String| candidates.contains(class)),
        0x6E..=0x72 | 0x74..=0x78 => dex
            .method_ids
            .get(index as usize)
            .map(|method: &crate::dex::MethodId| method.class.clone())
            .filter(|class: &String| candidates.contains(class)),
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

    #[test]
    fn functional_interface_roster_is_sorted_unique_and_parseable() {
        for pair in FUNCTIONAL_INTERFACES.windows(2) {
            let (left, right): (&(&str, &str, &str), &(&str, &str, &str)) = (&pair[0], &pair[1]);
            assert!(
                left.0 < right.0,
                "the roster must be sorted for binary search: {} then {}",
                left.0,
                right.0
            );
        }
        for entry in FUNCTIONAL_INTERFACES {
            assert!(
                entry.0.starts_with('L') && entry.0.ends_with(';'),
                "{} must be a type descriptor",
                entry.0
            );
            assert!(
                crate::name_disambig::is_java_source_identifier(entry.1),
                "{} must be a method name",
                entry.1
            );
            assert!(
                crate::descriptor::parse_method(entry.2).is_some(),
                "{} must be a method descriptor",
                entry.2
            );
            assert_eq!(
                roster_abstract_method(entry.0),
                Some((entry.1, entry.2)),
                "{} must be reachable by binary search",
                entry.0
            );
        }
        assert_eq!(roster_abstract_method("Ljava/io/Serializable;"), None);
        assert_eq!(
            roster_abstract_method("Ljava/util/function/Zzz;"),
            None,
            "an absent descriptor must not resolve to a neighbour"
        );
    }

    #[test]
    fn erasure_compatibility_admits_references_and_pins_primitives() {
        assert!(erasure_compatible(
            "Ljava/lang/String;",
            "Ljava/lang/Object;"
        ));
        assert!(erasure_compatible("[I", "Ljava/lang/Object;"));
        assert!(erasure_compatible("I", "I"));
        assert!(!erasure_compatible("I", "J"));
        assert!(!erasure_compatible("I", "Ljava/lang/Object;"));
        assert!(!erasure_compatible("Ljava/lang/Object;", "I"));
    }

    #[test]
    fn candidate_census_preserves_self_references_and_debits_cross_references() {
        let mut accepted: BTreeSet<String> = ["LA;", "LB;", "LC;"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        debit_candidate_reference(&mut accepted, "LA;", "LA;");
        assert_eq!(accepted.len(), 3);
        debit_candidate_reference(&mut accepted, "LA;", "LB;");
        assert_eq!(accepted, BTreeSet::from(["LC;".to_owned()]));
        debit_candidate_reference(&mut accepted, "LCaller;", "LC;");
        assert!(accepted.is_empty());
    }
}
