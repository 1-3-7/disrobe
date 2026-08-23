use disrobe_pass_native::{
    LeafRecovery, PseudoAbi, PseudoParameterBinding, PseudoReg, PseudoScalarType, SretReturn,
};

use super::{
    AotFieldLayout, AotMethod, AotMethodSignature, AotSignatureAbstention, AotType, AotTypeLayout,
    AotTypeSignature, AotTypeSignatureKind,
};

type Reattached<T> = Result<T, AotSignatureAbstention>;

const CALLING_CONVENTION_MASK: u32 = 0x0f;
const AMD64_REGISTER_EQUIVALENT_CONVENTIONS: [u32; 2] = [0x00, 0x01];
const GENERIC_SIGNATURE: u32 = 0x10;
const HAS_THIS: u32 = 0x20;
const EXPLICIT_THIS: u32 = 0x40;
const SYSTEM_NAMESPACE: &str = "System";
const VOID_TYPE_NAME: &str = "Void";
const MS_X64_INTEGER_ARGUMENTS: [PseudoReg; 4] =
    [PseudoReg::Rcx, PseudoReg::Rdx, PseudoReg::R8, PseudoReg::R9];
const OBJECT_REFERENCE_C_TYPE: &str = "uintptr_t";
const VOID_C_TYPE: &str = "void";
const STDBOOL_INCLUDE: &str = "#include <stdbool.h>\n";
const PROTOTYPE_NAME: &str = " recovered(";
const PROTOTYPE_TAIL: &str = ") {\n";
const GENERIC_PARAMETER_TYPE: &str = "uint64_t";
const RETURN_STATEMENT: &str = "    return ";
const STATEMENT_TERMINATOR: &str = ";\n";
const CLOSING_BRACE_LINE: &str = "}\n";
const LIFTED_STRUCT_RETURN_TYPE: &str = "recovered_sret_t";
const STRUCT_RETURN_LOCAL: &str = "__sret";
const STRUCT_RETURN_MEMBER_ACCESS: &str = "__sret.";
const TYPEDEF_STRUCT_HEAD: &str = "typedef struct {\n";
const TYPEDEF_FIELD_PREFIX: &str = "    ";
const TYPEDEF_CLOSE: &str = "} ";
const STRUCT_POINTER_MARK: &str = "*";
const TYPEDEF_STRUCT_HEAD_PACKED: &str = "typedef struct __attribute__((packed, may_alias)) {
";
const LIFTED_AGGREGATE_TYPE_PREFIX: &str = "recovered_struct_";
const LIFTED_AGGREGATE_TYPE_SUFFIX: &str = "_t";
const LIFTED_AGGREGATE_FIELD_PREFIX: &str = "field_";
const MS_X64_REGISTER_BODY_NAMES: [&str; 4] = ["r_rcx", "r_rdx", "r_r8", "r_r9"];
const LOCAL_DECLARATION_PREFIX: &str = "    uint64_t ";
const REGISTER_BINDING_PREFIX: &str = "    uint64_t r_";
const FLOAT_REGISTER_BINDING_PREFIX: &str = "    uint64_t x_";
const ZERO_INITIALIZER: &str = " = 0;\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedPrimitive {
    Boolean,
    SByte,
    Byte,
    Int16,
    UInt16,
    Char,
    Int32,
    UInt32,
    Int64,
    UInt64,
    IntPtr,
    UIntPtr,
}

const MANAGED_PRIMITIVES: [(&str, ManagedPrimitive); 12] = [
    ("Boolean", ManagedPrimitive::Boolean),
    ("SByte", ManagedPrimitive::SByte),
    ("Byte", ManagedPrimitive::Byte),
    ("Int16", ManagedPrimitive::Int16),
    ("UInt16", ManagedPrimitive::UInt16),
    ("Char", ManagedPrimitive::Char),
    ("Int32", ManagedPrimitive::Int32),
    ("UInt32", ManagedPrimitive::UInt32),
    ("Int64", ManagedPrimitive::Int64),
    ("UInt64", ManagedPrimitive::UInt64),
    ("IntPtr", ManagedPrimitive::IntPtr),
    ("UIntPtr", ManagedPrimitive::UIntPtr),
];

impl ManagedPrimitive {
    const fn c_type(self) -> &'static str {
        match self {
            Self::Boolean => "bool",
            Self::SByte => "int8_t",
            Self::Byte => "uint8_t",
            Self::Int16 => "int16_t",
            Self::UInt16 | Self::Char => "uint16_t",
            Self::Int32 => "int32_t",
            Self::UInt32 => "uint32_t",
            Self::Int64 => "int64_t",
            Self::UInt64 => "uint64_t",
            Self::IntPtr => "intptr_t",
            Self::UIntPtr => "uintptr_t",
        }
    }

    const fn unsigned_c_type(self) -> &'static str {
        match self {
            Self::Boolean | Self::SByte | Self::Byte => "uint8_t",
            Self::Int16 | Self::UInt16 | Self::Char => "uint16_t",
            Self::Int32 | Self::UInt32 => "uint32_t",
            Self::Int64 | Self::UInt64 => "uint64_t",
            Self::IntPtr | Self::UIntPtr => "uintptr_t",
        }
    }

    const fn reinterprets_unsigned_bits(self) -> bool {
        matches!(
            self,
            Self::Boolean | Self::SByte | Self::Int16 | Self::Int32 | Self::Int64 | Self::IntPtr
        )
    }

    const fn is_boolean(self) -> bool {
        matches!(self, Self::Boolean)
    }

    const fn size(self) -> usize {
        match self {
            Self::Boolean | Self::SByte | Self::Byte => 1,
            Self::Int16 | Self::UInt16 | Self::Char => 2,
            Self::Int32 | Self::UInt32 => 4,
            Self::Int64 | Self::UInt64 | Self::IntPtr | Self::UIntPtr => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedFloat {
    Single,
    Double,
}

const MANAGED_FLOATS: [(&str, ManagedFloat); 2] = [
    ("Single", ManagedFloat::Single),
    ("Double", ManagedFloat::Double),
];

impl ManagedFloat {
    const fn c_type(self) -> &'static str {
        match self {
            Self::Single => "float",
            Self::Double => "double",
        }
    }

    const fn scalar_type(self) -> PseudoScalarType {
        match self {
            Self::Single => PseudoScalarType::Float,
            Self::Double => PseudoScalarType::Double,
        }
    }

    const fn size(self) -> usize {
        match self {
            Self::Single => 4,
            Self::Double => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedValue {
    Integral(ManagedPrimitive),
    Floating(ManagedFloat),
}

impl ManagedValue {
    const fn c_type(self) -> &'static str {
        match self {
            Self::Integral(primitive) => primitive.c_type(),
            Self::Floating(width) => width.c_type(),
        }
    }

    const fn size(self) -> usize {
        match self {
            Self::Integral(primitive) => primitive.size(),
            Self::Floating(width) => width.size(),
        }
    }

    const fn is_boolean(self) -> bool {
        match self {
            Self::Integral(primitive) => primitive.is_boolean(),
            Self::Floating(_width) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedStructField {
    name: String,
    value: ManagedValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedStruct {
    name: String,
    fields: Vec<ManagedStructField>,
    size: usize,
}

const fn lifted_field_c_type(width: u32) -> &'static str {
    match width {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        _ => GENERIC_PARAMETER_TYPE,
    }
}

fn lifted_struct_typedef(widths: &[u32]) -> String {
    let mut rendered: String = String::from(TYPEDEF_STRUCT_HEAD);
    for (index, width) in widths.iter().enumerate() {
        rendered.push_str(TYPEDEF_FIELD_PREFIX);
        rendered.push_str(lifted_field_c_type(*width));
        rendered.push_str(format!(" f{index}").as_str());
        rendered.push_str(STATEMENT_TERMINATOR);
    }
    rendered.push_str(TYPEDEF_CLOSE);
    rendered.push_str(LIFTED_STRUCT_RETURN_TYPE);
    rendered.push_str(STATEMENT_TERMINATOR);
    rendered
}

impl ManagedStruct {
    fn managed_typedef(&self) -> String {
        let mut rendered: String = String::from(TYPEDEF_STRUCT_HEAD);
        for field in &self.fields {
            rendered.push_str(TYPEDEF_FIELD_PREFIX);
            rendered.push_str(field.value.c_type());
            rendered.push(' ');
            rendered.push_str(field.name.as_str());
            rendered.push_str(STATEMENT_TERMINATOR);
        }
        rendered.push_str(TYPEDEF_CLOSE);
        rendered.push_str(self.name.as_str());
        rendered.push_str(STATEMENT_TERMINATOR);
        rendered
    }

    fn uses_boolean(&self) -> bool {
        self.fields
            .iter()
            .any(|field: &ManagedStructField| field.value.is_boolean())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManagedReturn {
    Void,
    Value(ManagedValue),
    Struct(ManagedStruct),
}

impl ManagedReturn {
    const fn c_type(&self) -> &str {
        match self {
            Self::Void => VOID_C_TYPE,
            Self::Value(value) => value.c_type(),
            Self::Struct(managed) => managed.name.as_str(),
        }
    }

    const fn lifted_c_type(&self) -> &'static str {
        match self {
            Self::Void | Self::Value(ManagedValue::Integral(_)) => GENERIC_PARAMETER_TYPE,
            Self::Value(ManagedValue::Floating(width)) => width.c_type(),
            Self::Struct(_managed) => LIFTED_STRUCT_RETURN_TYPE,
        }
    }

    const fn floating(&self) -> Option<ManagedFloat> {
        match self {
            Self::Void | Self::Value(ManagedValue::Integral(_)) | Self::Struct(_) => None,
            Self::Value(ManagedValue::Floating(width)) => Some(*width),
        }
    }

    fn is_boolean(&self) -> bool {
        match self {
            Self::Void | Self::Value(ManagedValue::Floating(_)) => false,
            Self::Value(ManagedValue::Integral(primitive)) => primitive.is_boolean(),
            Self::Struct(managed) => managed.uses_boolean(),
        }
    }

    const fn managed_struct(&self) -> Option<&ManagedStruct> {
        match self {
            Self::Void | Self::Value(_) => None,
            Self::Struct(managed) => Some(managed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManagedSlot {
    InstanceReference,
    Value(ManagedValue),
    StructPointer(ManagedStruct),
}

impl ManagedSlot {
    fn declaration(&self, index: usize) -> String {
        match self {
            Self::InstanceReference => format!("{OBJECT_REFERENCE_C_TYPE} a{index}"),
            Self::Value(value) => format!("{} a{index}", value.c_type()),
            Self::StructPointer(managed) => {
                format!("{} {STRUCT_POINTER_MARK}a{index}", managed.name)
            }
        }
    }

    const fn lifted_c_type(&self) -> &'static str {
        match self {
            Self::InstanceReference
            | Self::Value(ManagedValue::Integral(_))
            | Self::StructPointer(_) => GENERIC_PARAMETER_TYPE,
            Self::Value(ManagedValue::Floating(width)) => width.c_type(),
        }
    }

    const fn floating(&self) -> Option<ManagedFloat> {
        match self {
            Self::InstanceReference
            | Self::Value(ManagedValue::Integral(_))
            | Self::StructPointer(_) => None,
            Self::Value(ManagedValue::Floating(width)) => Some(*width),
        }
    }

    const fn reinterpreted_integral(&self) -> Option<ManagedPrimitive> {
        match self {
            Self::InstanceReference
            | Self::Value(ManagedValue::Floating(_))
            | Self::StructPointer(_) => None,
            Self::Value(ManagedValue::Integral(primitive)) => {
                if primitive.reinterprets_unsigned_bits() {
                    Some(*primitive)
                } else {
                    None
                }
            }
        }
    }

    fn is_boolean(&self) -> bool {
        match self {
            Self::InstanceReference | Self::Value(ManagedValue::Floating(_)) => false,
            Self::Value(ManagedValue::Integral(primitive)) => primitive.is_boolean(),
            Self::StructPointer(managed) => managed.uses_boolean(),
        }
    }

    const fn managed_struct(&self) -> Option<&ManagedStruct> {
        match self {
            Self::InstanceReference | Self::Value(_) => None,
            Self::StructPointer(managed) => Some(managed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedPlan {
    slots: Vec<ManagedSlot>,
    return_type: ManagedReturn,
}

impl ManagedPlan {
    fn for_method(
        method: &AotMethod,
        types: &[AotType],
        layouts: &[AotTypeLayout],
        hidden_struct_return: bool,
    ) -> Reattached<Self> {
        let signature: &AotMethodSignature = method
            .signature
            .as_ref()
            .ok_or(AotSignatureAbstention::AbsentManagedSignature)?;
        let convention: u32 = signature.calling_convention;
        if !AMD64_REGISTER_EQUIVALENT_CONVENTIONS.contains(&(convention & CALLING_CONVENTION_MASK))
        {
            return Err(AotSignatureAbstention::UnsupportedCallingConvention);
        }
        if convention & EXPLICIT_THIS != 0 {
            return Err(AotSignatureAbstention::ExplicitThis);
        }
        if convention & GENERIC_SIGNATURE != 0 || signature.generic_parameter_count != 0 {
            return Err(AotSignatureAbstention::GenericSignature);
        }
        if !signature.vararg_parameter_types.is_empty() {
            return Err(AotSignatureAbstention::VarargSignature);
        }
        let has_this: bool = convention & HAS_THIS != 0;
        let slot_count: usize = signature
            .parameter_types
            .len()
            .checked_add(usize::from(has_this))
            .ok_or(AotSignatureAbstention::ArgumentPositionsExceeded)?;
        let available_slots: usize = MS_X64_INTEGER_ARGUMENTS
            .len()
            .checked_sub(usize::from(hidden_struct_return))
            .ok_or(AotSignatureAbstention::ArgumentPositionsExceeded)?;
        if slot_count > available_slots {
            return Err(AotSignatureAbstention::ArgumentPositionsExceeded);
        }
        let mut slots: Vec<ManagedSlot> = Vec::new();
        slots.try_reserve_exact(slot_count).map_err(
            |_error: std::collections::TryReserveError| AotSignatureAbstention::AllocationFailed,
        )?;
        if has_this {
            slots.push(ManagedSlot::InstanceReference);
        }
        for parameter in &signature.parameter_types {
            slots.push(resolve_slot(*parameter, types, layouts)?);
        }
        Ok(Self {
            slots,
            return_type: resolve_return(signature.return_type, types, layouts)?,
        })
    }

    fn include_prefix(&self, preamble: &str) -> String {
        let uses_boolean: bool =
            self.return_type.is_boolean() || self.slots.iter().any(ManagedSlot::is_boolean);
        if uses_boolean && !preamble.contains(STDBOOL_INCLUDE) {
            format!("{STDBOOL_INCLUDE}{preamble}")
        } else {
            preamble.to_owned()
        }
    }

    fn parameter_list(&self, lifted: bool) -> String {
        if self.slots.is_empty() {
            return VOID_C_TYPE.to_owned();
        }
        self.slots
            .iter()
            .enumerate()
            .map(|(index, slot): (usize, &ManagedSlot)| {
                if lifted {
                    format!("{} a{index}", slot.lifted_c_type())
                } else {
                    slot.declaration(index)
                }
            })
            .collect::<Vec<String>>()
            .join(", ")
    }
}

fn resolve_declaration(signature: AotTypeSignature, types: &[AotType]) -> Reattached<&AotType> {
    if signature.kind != AotTypeSignatureKind::Definition {
        return Err(AotSignatureAbstention::TypeSignatureKindUnsupported);
    }
    types
        .iter()
        .find(|candidate: &&AotType| candidate.record_offset == signature.record_offset)
        .ok_or(AotSignatureAbstention::TypeRecordAbsent)
}

fn resolve_system_type_name(signature: AotTypeSignature, types: &[AotType]) -> Reattached<&str> {
    let declaration: &AotType = resolve_declaration(signature, types)?;
    if declaration.namespace.as_deref() != Some(SYSTEM_NAMESPACE) {
        return Err(AotSignatureAbstention::TypeNamespaceNotSystem);
    }
    Ok(declaration.name.as_str())
}

const C_RESERVED_WORDS: [&str; 51] = [
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "bool",
    "true",
    "false",
    "memcpy",
    "recovered",
    "stack_frame",
    STRUCT_RETURN_LOCAL,
];

const RESERVED_TYPEDEF_SUFFIX: &str = "_t";

fn is_c_identifier(name: &str) -> bool {
    let mut bytes: std::str::Bytes<'_> = name.bytes();
    let Some(first): Option<u8> = bytes.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && first != b'_' {
        return false;
    }
    if !bytes.all(is_identifier_byte) {
        return false;
    }
    if name.starts_with("__") || name.ends_with(RESERVED_TYPEDEF_SUFFIX) {
        return false;
    }
    !C_RESERVED_WORDS.contains(&name)
}

fn resolve_struct(
    declaration: &AotType,
    types: &[AotType],
    layouts: &[AotTypeLayout],
) -> Reattached<ManagedStruct> {
    let hidden = || AotSignatureAbstention::HiddenStructReturn;
    let layout: &AotTypeLayout = layouts
        .iter()
        .find(|candidate: &&AotTypeLayout| candidate.record_offset == declaration.record_offset)
        .ok_or(AotSignatureAbstention::TypeOutsidePrimitiveTable)?;
    if !layout.sequential || layout.packing_size != 0 || layout.instance_fields.is_empty() {
        return Err(hidden());
    }
    if !is_c_identifier(declaration.name.as_str()) || declaration.name.starts_with('_') {
        return Err(hidden());
    }
    let mut fields: Vec<ManagedStructField> = Vec::new();
    fields
        .try_reserve_exact(layout.instance_fields.len())
        .map_err(|_error: std::collections::TryReserveError| {
            AotSignatureAbstention::AllocationFailed
        })?;
    let mut size: usize = 0;
    let mut alignment: usize = 1;
    let entries: &[AotFieldLayout] = layout.instance_fields.as_slice();
    for field in entries {
        if !is_c_identifier(field.name.as_str())
            || fields
                .iter()
                .any(|placed: &ManagedStructField| placed.name == field.name)
        {
            return Err(hidden());
        }
        let value: ManagedValue = resolve_value(field.field_type, types)?;
        let width: usize = value.size();
        if !size.is_multiple_of(width) {
            return Err(hidden());
        }
        size = size
            .checked_add(width)
            .ok_or(AotSignatureAbstention::AllocationFailed)?;
        alignment = alignment.max(width);
        fields.push(ManagedStructField {
            name: field.name.clone(),
            value,
        });
    }
    if !size.is_multiple_of(alignment) {
        return Err(hidden());
    }
    if layout.declared_size != 0 && usize::try_from(layout.declared_size) != Ok(size) {
        return Err(hidden());
    }
    Ok(ManagedStruct {
        name: declaration.name.clone(),
        fields,
        size,
    })
}

fn resolve_value(signature: AotTypeSignature, types: &[AotType]) -> Reattached<ManagedValue> {
    let name: &str = resolve_system_type_name(signature, types)?;
    MANAGED_PRIMITIVES
        .iter()
        .find(|(candidate, _primitive): &&(&str, ManagedPrimitive)| *candidate == name)
        .map(|(_candidate, primitive): &(&str, ManagedPrimitive)| {
            ManagedValue::Integral(*primitive)
        })
        .or_else(|| {
            MANAGED_FLOATS
                .iter()
                .find(|(candidate, _width): &&(&str, ManagedFloat)| *candidate == name)
                .map(|(_candidate, width): &(&str, ManagedFloat)| ManagedValue::Floating(*width))
        })
        .ok_or(AotSignatureAbstention::TypeOutsidePrimitiveTable)
}

const fn passed_in_register(size: usize) -> bool {
    matches!(size, 1 | 2 | 4 | 8)
}

fn resolve_slot(
    signature: AotTypeSignature,
    types: &[AotType],
    layouts: &[AotTypeLayout],
) -> Reattached<ManagedSlot> {
    let declaration: &AotType = resolve_declaration(signature, types)?;
    let scalar: AotSignatureAbstention = match resolve_value(signature, types) {
        Ok(value) => return Ok(ManagedSlot::Value(value)),
        Err(abstention) => abstention,
    };
    let managed: ManagedStruct = resolve_struct(declaration, types, layouts)
        .map_err(|_error: AotSignatureAbstention| scalar)?;
    if passed_in_register(managed.size) {
        return Err(AotSignatureAbstention::TypeOutsidePrimitiveTable);
    }
    Ok(ManagedSlot::StructPointer(managed))
}

fn lifted_aggregate_widths(body: &str, index: &str) -> Reattached<Vec<(usize, usize)>> {
    let unverified = || AotSignatureAbstention::TypeOutsidePrimitiveTable;
    let head: &str = TYPEDEF_STRUCT_HEAD_PACKED;
    let close: String = format!(
        "{TYPEDEF_CLOSE}{LIFTED_AGGREGATE_TYPE_PREFIX}{index}{LIFTED_AGGREGATE_TYPE_SUFFIX}{STATEMENT_TERMINATOR}"
    );
    let at: usize = body.find(close.as_str()).ok_or_else(unverified)?;
    let opened: usize = body
        .get(..at)
        .and_then(|before: &str| before.rfind(head))
        .ok_or_else(unverified)?;
    let start: usize = opened.checked_add(head.len()).ok_or_else(unverified)?;
    let members: &str = body.get(start..at).ok_or_else(unverified)?;
    let mut fields: Vec<(usize, usize)> = Vec::new();
    for line in members.lines() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (scalar, member): (&str, &str) = trimmed
            .strip_suffix(';')
            .and_then(|entry: &str| entry.split_once(' '))
            .ok_or_else(unverified)?;
        let offset_text: &str = member
            .strip_prefix(LIFTED_AGGREGATE_FIELD_PREFIX)
            .ok_or_else(unverified)?;
        let offset: usize = usize::from_str_radix(offset_text, 16)
            .map_err(|_error: std::num::ParseIntError| unverified())?;
        let width: usize = match scalar {
            "uint8_t" => 1,
            "uint16_t" => 2,
            "uint32_t" => 4,
            "uint64_t" => 8,
            _ => return Err(unverified()),
        };
        fields.push((offset, width));
    }
    if fields.is_empty() {
        return Err(unverified());
    }
    Ok(fields)
}

fn aggregate_agrees(body: &str, register: &str, managed: &ManagedStruct) -> Reattached<bool> {
    let unverified = || AotSignatureAbstention::TypeOutsidePrimitiveTable;
    let mut found: Option<String> = None;
    for line in body.lines() {
        let trimmed: &str = line.trim();
        let Some(rest): Option<&str> = trimmed.strip_prefix(LIFTED_AGGREGATE_TYPE_PREFIX) else {
            continue;
        };
        let Some((index, tail)): Option<(&str, &str)> =
            rest.split_once(LIFTED_AGGREGATE_TYPE_SUFFIX)
        else {
            continue;
        };
        let binding: String = format!(
            " *{LIFTED_AGGREGATE_TYPE_PREFIX}{index} = ({LIFTED_AGGREGATE_TYPE_PREFIX}{index}{LIFTED_AGGREGATE_TYPE_SUFFIX} *)(uintptr_t){register};"
        );
        if tail != binding {
            continue;
        }
        if found.is_some() {
            return Err(unverified());
        }
        found = Some(index.to_owned());
    }
    let Some(index): Option<String> = found else {
        return Ok(false);
    };
    let lifted: Vec<(usize, usize)> = lifted_aggregate_widths(body, index.as_str())?;
    let mut offset: usize = 0;
    let mut declared: Vec<(usize, usize)> = Vec::new();
    for field in &managed.fields {
        declared.push((offset, field.value.size()));
        offset = offset
            .checked_add(field.value.size())
            .ok_or(AotSignatureAbstention::AllocationFailed)?;
    }
    if lifted.len() > declared.len() {
        return Err(unverified());
    }
    for entry in &lifted {
        if !declared.contains(entry) {
            return Err(unverified());
        }
    }
    Ok(true)
}

fn resolve_return(
    signature: AotTypeSignature,
    types: &[AotType],
    layouts: &[AotTypeLayout],
) -> Reattached<ManagedReturn> {
    let declaration: &AotType = resolve_declaration(signature, types)?;
    if declaration.namespace.as_deref() == Some(SYSTEM_NAMESPACE) {
        if declaration.name == VOID_TYPE_NAME {
            return Ok(ManagedReturn::Void);
        }
        if let Ok(value) = resolve_value(signature, types) {
            return Ok(ManagedReturn::Value(value));
        }
    }
    resolve_struct(declaration, types, layouts).map(ManagedReturn::Struct)
}

fn return_agrees(recovery: &LeafRecovery, return_type: &ManagedReturn) -> Reattached<()> {
    let agrees: bool = return_type.floating().map_or_else(
        || recovery.returns_fp.is_none(),
        |width: ManagedFloat| recovery.returns_fp == Some(width.scalar_type()),
    );
    if agrees {
        Ok(())
    } else {
        Err(AotSignatureAbstention::ReturnClassDisagreement)
    }
}

fn struct_return_agrees(recovery: &LeafRecovery, managed: &ManagedStruct) -> Reattached<()> {
    let hidden = || AotSignatureAbstention::HiddenStructReturn;
    let sret: &SretReturn = recovery.sret.as_ref().ok_or_else(hidden)?;
    if sret.size != managed.size {
        return Err(hidden());
    }
    if sret.field_widths.len() != managed.fields.len() {
        return Err(hidden());
    }
    sret.field_widths
        .iter()
        .copied()
        .zip(managed.fields.iter())
        .try_for_each(|(width, field): (u32, &ManagedStructField)| {
            if usize::try_from(width) == Ok(field.value.size()) {
                Ok(())
            } else {
                Err(hidden())
            }
        })
}

fn slot_binding_agrees(
    index: usize,
    slot: &ManagedSlot,
    binding: PseudoParameterBinding,
) -> Reattached<()> {
    if let PseudoParameterBinding::UnobservedMsX64 { .. } = binding {
        return Err(AotSignatureAbstention::UnobservedArgumentPosition);
    }
    if let PseudoParameterBinding::Vector { .. } = binding {
        return Err(AotSignatureAbstention::VectorArgumentBinding);
    }
    slot.floating().map_or_else(
        || {
            let agrees: bool = MS_X64_INTEGER_ARGUMENTS.get(index).is_some_and(
                |expected: &PseudoReg| {
                    matches!(
                        binding,
                        PseudoParameterBinding::Integer { register, .. } if register == *expected
                    )
                },
            );
            if agrees {
                Ok(())
            } else {
                Err(AotSignatureAbstention::ArgumentRegisterDisagreement)
            }
        },
        |width: ManagedFloat| {
            let agrees: bool = u8::try_from(index).is_ok_and(|position: u8| {
                matches!(
                    binding,
                    PseudoParameterBinding::FloatingPoint {
                        register_index,
                        scalar_type,
                    } if register_index == position && scalar_type == width.scalar_type()
                )
            });
            if agrees {
                Ok(())
            } else {
                Err(AotSignatureAbstention::FloatingPointRegisterDisagreement)
            }
        },
    )
}

fn abi_agrees(recovery: &LeafRecovery) -> Reattached<()> {
    if recovery.signature.abi() == PseudoAbi::MsX64 {
        Ok(())
    } else {
        Err(AotSignatureAbstention::NonMicrosoftX64Recovery)
    }
}

fn recovery_shape_agrees(recovery: &LeafRecovery, return_type: &ManagedReturn) -> Reattached<()> {
    abi_agrees(recovery)?;
    match (recovery.sret.is_some(), return_type.managed_struct()) {
        (false, None) => Ok(()),
        (true, Some(managed)) => struct_return_agrees(recovery, managed),
        (true, None) | (false, Some(_)) => Err(AotSignatureAbstention::HiddenStructReturn),
    }
}

fn bindings_agree(recovery: &LeafRecovery, slots: &[ManagedSlot]) -> Reattached<()> {
    let hidden_slots: usize = usize::from(recovery.sret.is_some());
    let bindings: &[PseudoParameterBinding] = recovery.signature.parameter_bindings();
    if bindings.len() != slots.len() {
        return Err(AotSignatureAbstention::ArgumentCountDisagreement);
    }
    bindings
        .iter()
        .copied()
        .zip(slots.iter())
        .enumerate()
        .try_for_each(
            |(index, (binding, slot)): (usize, (PseudoParameterBinding, &ManagedSlot))| {
                let physical: usize = index
                    .checked_add(hidden_slots)
                    .ok_or(AotSignatureAbstention::ArgumentPositionsExceeded)?;
                slot_binding_agrees(physical, slot, binding)
            },
        )
}

const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn identifier_occurrences(text: &str, identifier: &str) -> usize {
    let bytes: &[u8] = text.as_bytes();
    text.match_indices(identifier)
        .filter(|(at, _needle): &(usize, &str)| {
            let before: bool = at
                .checked_sub(1)
                .and_then(|previous: usize| bytes.get(previous).copied())
                .is_some_and(is_identifier_byte);
            let after: bool = at
                .checked_add(identifier.len())
                .and_then(|next: usize| bytes.get(next).copied())
                .is_some_and(is_identifier_byte);
            !before && !after
        })
        .count()
}

fn reinterpret(value: &str, c_type: &str, unsigned_c_type: &str, reinterpreted: bool) -> String {
    if reinterpreted {
        format!("({c_type})({unsigned_c_type})({value})")
    } else {
        format!("({c_type})({value})")
    }
}

fn split_prototype(source: &str, plan: &ManagedPlan) -> Reattached<(String, String)> {
    let lifted: String = format!(
        "{}{PROTOTYPE_NAME}{}{PROTOTYPE_TAIL}",
        plan.return_type.lifted_c_type(),
        plan.parameter_list(true)
    );
    if source.matches(lifted.as_str()).count() != 1 {
        return Err(AotSignatureAbstention::PrototypeNotIsolated);
    }
    let isolated = || AotSignatureAbstention::PrototypeNotIsolated;
    let at: usize = source.find(lifted.as_str()).ok_or_else(isolated)?;
    let preamble: &str = source.get(..at).ok_or_else(isolated)?;
    let body: &str = source
        .get(at.checked_add(lifted.len()).ok_or_else(isolated)?..)
        .ok_or_else(isolated)?;
    let preamble: String = rewrite_struct_typedef(plan.include_prefix(preamble).as_str(), plan)?;
    let preamble: String = parameter_typedefs(preamble.as_str(), plan)?;
    let managed: String = format!(
        "{preamble}{}{PROTOTYPE_NAME}{}{PROTOTYPE_TAIL}",
        plan.return_type.c_type(),
        plan.parameter_list(false)
    );
    Ok((managed, body.to_owned()))
}

fn parameter_layouts_are_evidenced(
    body: &str,
    plan: &ManagedPlan,
    hidden_slots: usize,
) -> Reattached<()> {
    let unverified = || AotSignatureAbstention::TypeOutsidePrimitiveTable;
    for (index, slot) in plan.slots.iter().enumerate() {
        let Some(managed): Option<&ManagedStruct> = slot.managed_struct() else {
            continue;
        };
        let physical: usize = index.checked_add(hidden_slots).ok_or_else(unverified)?;
        let register: &str = MS_X64_REGISTER_BODY_NAMES
            .get(physical)
            .copied()
            .ok_or_else(unverified)?;
        if aggregate_agrees(body, register, managed)? {
            continue;
        }
        let returned: bool = plan
            .return_type
            .managed_struct()
            .is_some_and(|declared: &ManagedStruct| declared == managed);
        if !returned {
            return Err(unverified());
        }
    }
    Ok(())
}

fn parameter_typedefs(preamble: &str, plan: &ManagedPlan) -> Reattached<String> {
    let collides = || AotSignatureAbstention::PrototypeNotIsolated;
    let mut rendered: String = preamble.to_owned();
    let mut emitted: Vec<&ManagedStruct> = plan.return_type.managed_struct().into_iter().collect();
    for slot in &plan.slots {
        let Some(managed): Option<&ManagedStruct> = slot.managed_struct() else {
            continue;
        };
        if emitted.contains(&managed) {
            continue;
        }
        if emitted
            .iter()
            .any(|placed: &&ManagedStruct| placed.name == managed.name)
        {
            return Err(collides());
        }
        rendered.push_str(managed.managed_typedef().as_str());
        emitted.push(managed);
    }
    Ok(rendered)
}

fn rewrite_struct_typedef(preamble: &str, plan: &ManagedPlan) -> Reattached<String> {
    let Some(managed): Option<&ManagedStruct> = plan.return_type.managed_struct() else {
        return Ok(preamble.to_owned());
    };
    let hidden = || AotSignatureAbstention::HiddenStructReturn;
    let widths: Vec<u32> = managed
        .fields
        .iter()
        .map(|field: &ManagedStructField| {
            u32::try_from(field.value.size()).map_err(|_error: std::num::TryFromIntError| hidden())
        })
        .collect::<Reattached<Vec<u32>>>()?;
    let lifted: String = lifted_struct_typedef(&widths);
    if preamble.matches(lifted.as_str()).count() != 1 {
        return Err(hidden());
    }
    Ok(preamble.replacen(lifted.as_str(), managed.managed_typedef().as_str(), 1))
}

fn rewrite_struct_return_local(body: &str, plan: &ManagedPlan) -> Reattached<String> {
    let Some(managed): Option<&ManagedStruct> = plan.return_type.managed_struct() else {
        return Ok(body.to_owned());
    };
    let hidden = || AotSignatureAbstention::HiddenStructReturn;
    if body.contains(STRUCT_RETURN_MEMBER_ACCESS) {
        return Err(hidden());
    }
    let declaration: String =
        format!("    {LIFTED_STRUCT_RETURN_TYPE} {STRUCT_RETURN_LOCAL}{STATEMENT_TERMINATOR}");
    if body.matches(declaration.as_str()).count() != 1 {
        return Err(hidden());
    }
    let rewritten: String = body.replacen(
        declaration.as_str(),
        format!(
            "    {} {STRUCT_RETURN_LOCAL}{STATEMENT_TERMINATOR}",
            managed.name
        )
        .as_str(),
        1,
    );
    if identifier_occurrences(rewritten.as_str(), LIFTED_STRUCT_RETURN_TYPE) != 0 {
        return Err(hidden());
    }
    Ok(rewritten)
}

fn unique_line_containing(lines: &[String], identifier: &str) -> Option<usize> {
    let mut found: Option<usize> = None;
    for (index, line) in lines.iter().enumerate() {
        if identifier_occurrences(line.as_str(), identifier) == 0 {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(index);
    }
    found
}

fn rewrite_argument_bindings(body: &str, plan: &ManagedPlan) -> Reattached<String> {
    let isolated = || AotSignatureAbstention::ArgumentBindingNotIsolated;
    let mut lines: Vec<String> = body.split_inclusive('\n').map(str::to_owned).collect();
    for (index, slot) in plan.slots.iter().enumerate() {
        let argument: String = format!("a{index}");
        if identifier_occurrences(body, argument.as_str()) != 1 {
            return Err(isolated());
        }
        let line_index: usize =
            unique_line_containing(&lines, argument.as_str()).ok_or_else(isolated)?;
        let line: &String = lines.get(line_index).ok_or_else(isolated)?;
        if slot.floating().is_some() {
            let suffix: String = format!("({argument}));\n");
            if !line.starts_with(FLOAT_REGISTER_BINDING_PREFIX) || !line.ends_with(suffix.as_str())
            {
                return Err(isolated());
            }
            continue;
        }
        let suffix: String = format!(" = {argument};\n");
        if !line.starts_with(REGISTER_BINDING_PREFIX) || !line.ends_with(suffix.as_str()) {
            return Err(isolated());
        }
        let head: String = line
            .strip_suffix(suffix.as_str())
            .ok_or_else(isolated)?
            .to_owned();
        if slot.managed_struct().is_some() {
            let target: &mut String = lines.get_mut(line_index).ok_or_else(isolated)?;
            *target = format!(
                "{head} = ({GENERIC_PARAMETER_TYPE})({OBJECT_REFERENCE_C_TYPE}){argument};\n"
            );
            continue;
        }
        let Some(primitive): Option<ManagedPrimitive> = slot.reinterpreted_integral() else {
            continue;
        };
        let target: &mut String = lines.get_mut(line_index).ok_or_else(isolated)?;
        *target = format!("{head} = ({}){argument};\n", primitive.unsigned_c_type());
    }
    Ok(lines.concat())
}

fn drop_dead_result_binding(lines: &mut Vec<String>, expression: &str) {
    if expression.is_empty() || !expression.bytes().all(is_identifier_byte) {
        return;
    }
    if identifier_occurrences(lines.concat().as_str(), expression) != 1 {
        return;
    }
    let declaration: String = format!("{LOCAL_DECLARATION_PREFIX}{expression}{ZERO_INITIALIZER}");
    let Some(index): Option<usize> = lines
        .iter()
        .position(|line: &String| *line == declaration.as_str())
    else {
        return;
    };
    lines.remove(index);
}

fn rewrite_return(body: &str, plan: &ManagedPlan) -> Reattached<String> {
    let isolated = || AotSignatureAbstention::ReturnStatementNotIsolated;
    let mut lines: Vec<String> = body.split_inclusive('\n').map(str::to_owned).collect();
    let returns: usize = lines
        .iter()
        .filter(|line: &&String| line.starts_with(RETURN_STATEMENT))
        .count();
    if returns != 1 || lines.last().map(String::as_str) != Some(CLOSING_BRACE_LINE) {
        return Err(isolated());
    }
    let return_index: usize = lines.len().checked_sub(2).ok_or_else(isolated)?;
    let expression: String = lines
        .get(return_index)
        .ok_or_else(isolated)?
        .strip_prefix(RETURN_STATEMENT)
        .ok_or_else(isolated)?
        .strip_suffix(STATEMENT_TERMINATOR)
        .ok_or_else(isolated)?
        .to_owned();
    match plan.return_type {
        ManagedReturn::Void => {
            lines.remove(return_index);
            drop_dead_result_binding(&mut lines, expression.as_str());
        }
        ManagedReturn::Value(ManagedValue::Floating(_)) | ManagedReturn::Struct(_) => {}
        ManagedReturn::Value(ManagedValue::Integral(primitive)) => {
            let converted: String = reinterpret(
                expression.as_str(),
                primitive.c_type(),
                primitive.unsigned_c_type(),
                primitive.reinterprets_unsigned_bits(),
            );
            let line: &mut String = lines.get_mut(return_index).ok_or_else(isolated)?;
            *line = format!("{RETURN_STATEMENT}{converted}{STATEMENT_TERMINATOR}");
        }
    }
    Ok(lines.concat())
}

pub(super) fn reassociate(
    recovery: &LeafRecovery,
    method: &AotMethod,
    types: &[AotType],
    layouts: &[AotTypeLayout],
) -> Reattached<String> {
    abi_agrees(recovery)?;
    let plan: ManagedPlan =
        ManagedPlan::for_method(method, types, layouts, recovery.sret.is_some())?;
    recovery_shape_agrees(recovery, &plan.return_type)?;
    return_agrees(recovery, &plan.return_type)?;
    bindings_agree(recovery, &plan.slots)?;
    let (prototype, body): (String, String) = split_prototype(&recovery.source, &plan)?;
    parameter_layouts_are_evidenced(&body, &plan, usize::from(recovery.sret.is_some()))?;
    let body: String = rewrite_struct_return_local(&body, &plan)?;
    let body: String = rewrite_argument_bindings(&body, &plan)?;
    let body: String = rewrite_return(&body, &plan)?;
    Ok(format!("{prototype}{body}"))
}

#[cfg(test)]
mod tests {
    use super::{
        AotMethod, AotMethodSignature, AotSignatureAbstention, AotType, AotTypeSignature,
        AotTypeSignatureKind, ManagedFloat, ManagedPlan, ManagedPrimitive, ManagedReturn,
        ManagedSlot, ManagedStruct, ManagedStructField, ManagedValue, PseudoParameterBinding,
        PseudoReg, PseudoScalarType, abi_agrees, bindings_agree, identifier_occurrences,
        recovery_shape_agrees, resolve_return, resolve_value, return_agrees,
        rewrite_argument_bindings, rewrite_return, slot_binding_agrees, split_prototype,
    };
    use crate::aot::{AOT_SIGNATURE_ABSTENTIONS, AotCodeRange};
    use disrobe_pass_native::{LeafRecovery, PseudoAbi, RecoveredSignature, SretReturn};

    const INT32: u32 = 1;
    const VOID: u32 = 7;
    const SINGLE: u32 = 8;
    const DOUBLE: u32 = 9;

    fn primitive_type(record_offset: u32, name: &str) -> AotType {
        AotType {
            record_offset,
            namespace: Some("System".to_owned()),
            name: name.to_owned(),
            enclosing_type_record_offset: None,
            method_record_offsets: Vec::new(),
        }
    }

    fn definition(record_offset: u32) -> AotTypeSignature {
        AotTypeSignature {
            kind: AotTypeSignatureKind::Definition,
            record_offset,
        }
    }

    fn probe(signature: AotMethodSignature) -> AotMethod {
        AotMethod {
            record_offset: 1,
            name: "Probe".to_owned(),
            signature: Some(signature),
            entrypoint_rva: Some(0x1000),
            code_range: Some(AotCodeRange {
                start_rva: 0x1000,
                end_rva: 0x1004,
            }),
            body: None,
        }
    }

    fn signature(calling_convention: u32, parameters: usize) -> AotMethodSignature {
        shaped_signature(calling_convention, vec![INT32; parameters], INT32)
    }

    fn shaped_signature(
        calling_convention: u32,
        parameters: Vec<u32>,
        return_type: u32,
    ) -> AotMethodSignature {
        AotMethodSignature {
            record_offset: 9,
            calling_convention,
            generic_parameter_count: 0,
            return_type: definition(return_type),
            parameter_types: parameters
                .into_iter()
                .map(definition)
                .collect::<Vec<AotTypeSignature>>(),
            vararg_parameter_types: Vec::new(),
        }
    }

    fn type_table() -> Vec<AotType> {
        vec![
            primitive_type(INT32, "Int32"),
            primitive_type(VOID, "Void"),
            primitive_type(SINGLE, "Single"),
            primitive_type(DOUBLE, "Double"),
        ]
    }

    fn plan(signature: AotMethodSignature) -> Result<ManagedPlan, AotSignatureAbstention> {
        ManagedPlan::for_method(&probe(signature), &type_table(), &[], false)
    }

    #[test]
    fn every_abstention_carries_a_distinct_stable_wire_name() {
        let mut wires: Vec<&'static str> = AOT_SIGNATURE_ABSTENTIONS
            .iter()
            .map(|abstention: &AotSignatureAbstention| abstention.wire())
            .collect();
        let declared: usize = wires.len();
        wires.sort_unstable();
        wires.dedup();

        assert_eq!(
            wires.len(),
            declared,
            "abstention wire names must be unique"
        );
        for abstention in AOT_SIGNATURE_ABSTENTIONS {
            let rendered: String = serde_json::to_string(&abstention)
                .unwrap_or_else(|_error: serde_json::Error| String::new());
            assert_eq!(
                rendered,
                format!("\"{}\"", abstention.wire()),
                "{abstention:?} must serialize as its wire name"
            );
        }
    }

    #[test]
    fn every_managed_primitive_resolves_only_through_a_system_definition() {
        let types: Vec<AotType> = vec![
            primitive_type(1, "Int32"),
            primitive_type(2, "Boolean"),
            AotType {
                record_offset: 3,
                namespace: Some("Probe".to_owned()),
                name: "Int32".to_owned(),
                enclosing_type_record_offset: None,
                method_record_offsets: Vec::new(),
            },
            primitive_type(4, "DateTime"),
            primitive_type(5, "Single"),
            primitive_type(6, "Double"),
            primitive_type(VOID, "Void"),
        ];

        assert_eq!(
            resolve_value(definition(1), &types),
            Ok(ManagedValue::Integral(ManagedPrimitive::Int32))
        );
        assert_eq!(
            resolve_value(definition(2), &types),
            Ok(ManagedValue::Integral(ManagedPrimitive::Boolean))
        );
        assert_eq!(
            resolve_value(definition(3), &types),
            Err(AotSignatureAbstention::TypeNamespaceNotSystem)
        );
        assert_eq!(
            resolve_value(definition(4), &types),
            Err(AotSignatureAbstention::TypeOutsidePrimitiveTable)
        );
        assert_eq!(
            resolve_value(definition(10), &types),
            Err(AotSignatureAbstention::TypeRecordAbsent)
        );
        assert_eq!(
            resolve_value(definition(5), &types),
            Ok(ManagedValue::Floating(ManagedFloat::Single))
        );
        assert_eq!(
            resolve_value(definition(6), &types),
            Ok(ManagedValue::Floating(ManagedFloat::Double))
        );
        assert_eq!(
            resolve_value(definition(VOID), &types),
            Err(AotSignatureAbstention::TypeOutsidePrimitiveTable)
        );
        assert_eq!(
            resolve_return(definition(VOID), &types, &[]),
            Ok(ManagedReturn::Void)
        );
        assert_eq!(
            resolve_return(definition(6), &types, &[]),
            Ok(ManagedReturn::Value(ManagedValue::Floating(
                ManagedFloat::Double
            )))
        );
        assert_eq!(
            resolve_return(definition(4), &types, &[]),
            Err(AotSignatureAbstention::TypeOutsidePrimitiveTable)
        );
        for kind in [
            AotTypeSignatureKind::Reference,
            AotTypeSignatureKind::Specification,
            AotTypeSignatureKind::Modified,
        ] {
            assert_eq!(
                resolve_value(
                    AotTypeSignature {
                        kind,
                        record_offset: 1,
                    },
                    &types
                ),
                Err(AotSignatureAbstention::TypeSignatureKindUnsupported),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn an_instance_signature_reserves_the_first_integer_slot() -> Result<(), &'static str> {
        let planned: ManagedPlan = plan(signature(0x20, 1))
            .map_err(|_error: AotSignatureAbstention| "an instance signature must plan")?;

        assert_eq!(
            planned.slots,
            vec![
                ManagedSlot::InstanceReference,
                ManagedSlot::Value(ManagedValue::Integral(ManagedPrimitive::Int32))
            ]
        );
        assert_eq!(
            planned.return_type,
            ManagedReturn::Value(ManagedValue::Integral(ManagedPrimitive::Int32))
        );
        assert_eq!(
            planned.parameter_list(false),
            "uintptr_t a0, int32_t a1".to_owned()
        );
        Ok(())
    }

    #[test]
    fn every_signature_shaped_abstention_names_its_own_rule() {
        assert_eq!(
            ManagedPlan::for_method(
                &AotMethod {
                    record_offset: 1,
                    name: "Probe".to_owned(),
                    signature: None,
                    entrypoint_rva: None,
                    code_range: None,
                    body: None,
                },
                &type_table(),
                &[],
                false
            ),
            Err(AotSignatureAbstention::AbsentManagedSignature)
        );
        assert_eq!(
            plan(signature(0, 5)),
            Err(AotSignatureAbstention::ArgumentPositionsExceeded)
        );
        assert_eq!(
            plan(signature(0x20, 4)),
            Err(AotSignatureAbstention::ArgumentPositionsExceeded)
        );
        assert!(plan(signature(0, 4)).is_ok());
        assert_eq!(
            plan(signature(0x40, 1)),
            Err(AotSignatureAbstention::ExplicitThis)
        );
        assert_eq!(
            plan(signature(0x10, 1)),
            Err(AotSignatureAbstention::GenericSignature)
        );
        let mut generic: AotMethodSignature = signature(0, 1);
        generic.generic_parameter_count = 2;
        assert_eq!(plan(generic), Err(AotSignatureAbstention::GenericSignature));
        let mut vararg: AotMethodSignature = signature(0, 1);
        vararg.vararg_parameter_types = vec![definition(INT32)];
        assert_eq!(plan(vararg), Err(AotSignatureAbstention::VarargSignature));
        for convention in [0x02u32, 0x03, 0x04, 0x05, 0x09] {
            assert_eq!(
                plan(signature(convention, 1)),
                Err(AotSignatureAbstention::UnsupportedCallingConvention),
                "0x{convention:02x}"
            );
        }
        for convention in [0x00u32, 0x01, 0x20, 0x21] {
            assert!(plan(signature(convention, 1)).is_ok(), "0x{convention:02x}");
        }
    }

    #[test]
    fn a_void_return_renders_a_parameterless_static_prototype() -> Result<(), &'static str> {
        let planned: ManagedPlan = plan(shaped_signature(0, Vec::new(), VOID))
            .map_err(|_error: AotSignatureAbstention| "a static void signature must plan")?;

        assert_eq!(planned.return_type, ManagedReturn::Void);
        assert_eq!(planned.parameter_list(false), "void".to_owned());
        assert_eq!(planned.parameter_list(true), "void".to_owned());
        Ok(())
    }

    #[test]
    fn a_floating_point_slot_keeps_its_lifted_scalar_type() -> Result<(), &'static str> {
        let planned: ManagedPlan =
            plan(shaped_signature(0, vec![INT32, SINGLE, DOUBLE], SINGLE))
                .map_err(|_error: AotSignatureAbstention| "a mixed signature must plan")?;

        assert_eq!(
            planned.parameter_list(true),
            "uint64_t a0, float a1, double a2".to_owned()
        );
        assert_eq!(
            planned.parameter_list(false),
            "int32_t a0, float a1, double a2".to_owned()
        );
        assert_eq!(
            split_prototype(
                "#include <stdint.h>\nfloat recovered(uint64_t a0, float a1, double a2) {\n}\n",
                &planned
            ),
            Ok((
                "#include <stdint.h>\nfloat recovered(int32_t a0, float a1, double a2) {\n"
                    .to_owned(),
                "}\n".to_owned()
            ))
        );
        assert_eq!(
            split_prototype(
                "#include <stdint.h>\nfloat recovered(void) {\n}\n",
                &planned
            ),
            Err(AotSignatureAbstention::PrototypeNotIsolated)
        );
        Ok(())
    }

    #[test]
    fn an_argument_referenced_outside_its_binding_line_abstains() -> Result<(), &'static str> {
        let planned: ManagedPlan = plan(signature(0, 1))
            .map_err(|_error: AotSignatureAbstention| "a one-parameter signature must plan")?;
        let reused: &str =
            "    uint64_t r_rcx = a0;\n    uint64_t r_rax = a0;\n    return r_rax;\n}\n";
        let bound: &str = "    uint64_t r_rcx = a0;\n    return r_rcx;\n}\n";

        assert_eq!(
            rewrite_argument_bindings(reused, &planned),
            Err(AotSignatureAbstention::ArgumentBindingNotIsolated)
        );
        assert_eq!(
            rewrite_argument_bindings(bound, &planned),
            Ok("    uint64_t r_rcx = (uint32_t)a0;\n    return r_rcx;\n}\n".to_owned())
        );
        assert_eq!(identifier_occurrences("a0 a01 xa0 a0;", "a0"), 2);
        Ok(())
    }

    #[test]
    fn a_floating_point_argument_must_reach_a_vector_register_binding() -> Result<(), &'static str>
    {
        let planned: ManagedPlan = plan(shaped_signature(0, vec![DOUBLE], DOUBLE))
            .map_err(|_error: AotSignatureAbstention| "a double signature must plan")?;
        let bound: &str = "    uint64_t x_xmm0 = fp_d_to_bits((double)(a0));\n    return \
                           fp_d_from_bits(x_xmm0);\n}\n";
        let integer_bound: &str = "    uint64_t r_rcx = a0;\n    return \
                                   fp_d_from_bits(x_xmm0);\n}\n";

        assert_eq!(
            rewrite_argument_bindings(bound, &planned),
            Ok(bound.to_owned())
        );
        assert_eq!(
            rewrite_argument_bindings(integer_bound, &planned),
            Err(AotSignatureAbstention::ArgumentBindingNotIsolated)
        );
        assert_eq!(
            rewrite_return(bound, &planned),
            Ok(bound.to_owned()),
            "a floating-point return needs no reinterpretation"
        );
        Ok(())
    }

    #[test]
    fn a_body_with_more_than_one_return_abstains() -> Result<(), &'static str> {
        let planned: ManagedPlan = plan(signature(0, 1))
            .map_err(|_error: AotSignatureAbstention| "a one-parameter signature must plan")?;

        assert_eq!(
            rewrite_return("    return r_rax;\n    return r_rcx;\n}\n", &planned),
            Err(AotSignatureAbstention::ReturnStatementNotIsolated)
        );
        assert_eq!(
            rewrite_return("    return r_rax\n}\n", &planned),
            Err(AotSignatureAbstention::ReturnStatementNotIsolated)
        );
        assert_eq!(
            rewrite_return("    return r_rax;\n}\n", &planned),
            Ok("    return (int32_t)(uint32_t)(r_rax);\n}\n".to_owned())
        );
        Ok(())
    }

    #[test]
    fn a_void_return_drops_the_statement_and_only_a_dead_result_binding() -> Result<(), &'static str>
    {
        let planned: ManagedPlan = plan(shaped_signature(0x20, vec![INT32], VOID))
            .map_err(|_error: AotSignatureAbstention| "an instance void signature must plan")?;
        let dead: &str = "    uint64_t r_rcx = a0;\n    uint64_t r_rax = 0;\n    (*(uint32_t*)(uintptr_t)(r_rcx)) = 1;\n    return r_rax;\n}\n";
        let live: &str = "    uint64_t r_rax = 0;\n    r_rax = 1;\n    (*(uint32_t*)(uintptr_t)(r_rax)) = 1;\n    return (r_rax) & 0xffffffffULL;\n}\n";

        assert_eq!(
            rewrite_return(dead, &planned),
            Ok(
                "    uint64_t r_rcx = a0;\n    (*(uint32_t*)(uintptr_t)(r_rcx)) = 1;\n}\n"
                    .to_owned()
            )
        );
        assert_eq!(
            rewrite_return(live, &planned),
            Ok(
                "    uint64_t r_rax = 0;\n    r_rax = 1;\n    (*(uint32_t*)(uintptr_t)(r_rax)) = 1;\n}\n"
                    .to_owned()
            )
        );
        Ok(())
    }

    #[test]
    fn only_the_declared_argument_class_at_its_own_position_agrees() {
        const INTEGRAL: ManagedSlot =
            ManagedSlot::Value(ManagedValue::Integral(ManagedPrimitive::Int32));
        const FLOATING: ManagedSlot =
            ManagedSlot::Value(ManagedValue::Floating(ManagedFloat::Double));
        const UNOBSERVED: PseudoParameterBinding =
            PseudoParameterBinding::UnobservedMsX64 { slot: 1 };
        const VECTOR: PseudoParameterBinding = PseudoParameterBinding::Vector {
            register_index: 1,
            width_bits: 128,
        };
        const RDX: PseudoParameterBinding = PseudoParameterBinding::Integer {
            register: PseudoReg::Rdx,
            width_bits: 64,
        };
        const XMM1_DOUBLE: PseudoParameterBinding = PseudoParameterBinding::FloatingPoint {
            register_index: 1,
            scalar_type: PseudoScalarType::Double,
        };

        for slot in &[INTEGRAL, FLOATING, ManagedSlot::InstanceReference] {
            assert_eq!(
                slot_binding_agrees(1, slot, UNOBSERVED),
                Err(AotSignatureAbstention::UnobservedArgumentPosition),
                "{slot:?}"
            );
            assert_eq!(
                slot_binding_agrees(1, slot, VECTOR),
                Err(AotSignatureAbstention::VectorArgumentBinding),
                "{slot:?}"
            );
        }
        assert_eq!(slot_binding_agrees(1, &INTEGRAL, RDX), Ok(()));
        assert_eq!(
            slot_binding_agrees(1, &ManagedSlot::InstanceReference, RDX),
            Ok(())
        );
        assert_eq!(
            slot_binding_agrees(1, &FLOATING, RDX),
            Err(AotSignatureAbstention::FloatingPointRegisterDisagreement)
        );
        assert_eq!(
            slot_binding_agrees(0, &INTEGRAL, RDX),
            Err(AotSignatureAbstention::ArgumentRegisterDisagreement)
        );
        assert_eq!(slot_binding_agrees(1, &FLOATING, XMM1_DOUBLE), Ok(()));
        assert_eq!(
            slot_binding_agrees(0, &FLOATING, XMM1_DOUBLE),
            Err(AotSignatureAbstention::FloatingPointRegisterDisagreement)
        );
        assert_eq!(
            slot_binding_agrees(1, &INTEGRAL, XMM1_DOUBLE),
            Err(AotSignatureAbstention::ArgumentRegisterDisagreement)
        );
        for scalar_type in [
            PseudoScalarType::Float,
            PseudoScalarType::Half,
            PseudoScalarType::Int,
        ] {
            assert_eq!(
                slot_binding_agrees(
                    1,
                    &FLOATING,
                    PseudoParameterBinding::FloatingPoint {
                        register_index: 1,
                        scalar_type,
                    }
                ),
                Err(AotSignatureAbstention::FloatingPointRegisterDisagreement),
                "{scalar_type:?}"
            );
        }
        assert_eq!(
            slot_binding_agrees(4, &INTEGRAL, RDX),
            Err(AotSignatureAbstention::ArgumentRegisterDisagreement)
        );
    }

    fn leaf(
        abi: PseudoAbi,
        bindings: Vec<PseudoParameterBinding>,
        returns_fp: Option<PseudoScalarType>,
        sret: Option<SretReturn>,
    ) -> Result<LeafRecovery, &'static str> {
        let signature: RecoveredSignature = RecoveredSignature::from_bindings(abi, bindings)
            .map_err(|_error: disrobe_pass_native::Error| "the probe bindings must validate")?;
        Ok(LeafRecovery {
            source: String::new(),
            rust_source: None,
            return_width_bits: 64,
            signature,
            returns_fp,
            lifted_split_return: false,
            lifted_loop: false,
            lifted_switch: false,
            call_targets: Vec::new(),
            sret,
            call_site_signature: None,
        })
    }

    #[test]
    fn a_recovery_shape_the_managed_abi_cannot_describe_names_its_own_rule()
    -> Result<(), &'static str> {
        const INT32: ManagedSlot =
            ManagedSlot::Value(ManagedValue::Integral(ManagedPrimitive::Int32));
        let rcx: PseudoParameterBinding = PseudoParameterBinding::Integer {
            register: PseudoReg::Rcx,
            width_bits: 64,
        };
        let sysv: LeafRecovery = leaf(PseudoAbi::SysV, vec![rcx], None, None)?;
        let hidden: LeafRecovery = leaf(
            PseudoAbi::MsX64,
            vec![rcx],
            None,
            Some(SretReturn {
                field_widths: vec![8, 8],
                size: 16,
            }),
        )?;
        let plain: LeafRecovery = leaf(PseudoAbi::MsX64, vec![rcx], None, None)?;
        let floating: LeafRecovery = leaf(
            PseudoAbi::MsX64,
            vec![rcx],
            Some(PseudoScalarType::Double),
            None,
        )?;

        assert_eq!(
            abi_agrees(&sysv),
            Err(AotSignatureAbstention::NonMicrosoftX64Recovery)
        );
        assert_eq!(abi_agrees(&plain), Ok(()));
        assert_eq!(
            recovery_shape_agrees(
                &hidden,
                &ManagedReturn::Value(ManagedValue::Integral(ManagedPrimitive::Int32))
            ),
            Err(AotSignatureAbstention::HiddenStructReturn)
        );
        assert_eq!(
            recovery_shape_agrees(
                &plain,
                &ManagedReturn::Struct(ManagedStruct {
                    name: "Probe".to_owned(),
                    fields: Vec::new(),
                    size: 16,
                })
            ),
            Err(AotSignatureAbstention::HiddenStructReturn)
        );
        assert_eq!(
            recovery_shape_agrees(
                &hidden,
                &ManagedReturn::Struct(ManagedStruct {
                    name: "Probe".to_owned(),
                    fields: vec![
                        ManagedStructField {
                            name: "Low".to_owned(),
                            value: ManagedValue::Integral(ManagedPrimitive::Int32),
                        },
                        ManagedStructField {
                            name: "High".to_owned(),
                            value: ManagedValue::Integral(ManagedPrimitive::Int64),
                        },
                    ],
                    size: 16,
                })
            ),
            Err(AotSignatureAbstention::HiddenStructReturn)
        );
        assert_eq!(
            bindings_agree(&hidden, &[INT32]),
            Err(AotSignatureAbstention::ArgumentRegisterDisagreement)
        );
        assert_eq!(
            bindings_agree(&plain, &[INT32, INT32]),
            Err(AotSignatureAbstention::ArgumentCountDisagreement)
        );
        assert_eq!(bindings_agree(&plain, &[INT32]), Ok(()));
        assert_eq!(
            return_agrees(&floating, &ManagedReturn::Void),
            Err(AotSignatureAbstention::ReturnClassDisagreement)
        );
        assert_eq!(
            return_agrees(
                &plain,
                &ManagedReturn::Value(ManagedValue::Floating(ManagedFloat::Double))
            ),
            Err(AotSignatureAbstention::ReturnClassDisagreement)
        );
        assert_eq!(
            return_agrees(
                &floating,
                &ManagedReturn::Value(ManagedValue::Floating(ManagedFloat::Single))
            ),
            Err(AotSignatureAbstention::ReturnClassDisagreement)
        );
        assert_eq!(
            return_agrees(
                &floating,
                &ManagedReturn::Value(ManagedValue::Floating(ManagedFloat::Double))
            ),
            Ok(())
        );
        assert_eq!(return_agrees(&plain, &ManagedReturn::Void), Ok(()));
        Ok(())
    }
}
