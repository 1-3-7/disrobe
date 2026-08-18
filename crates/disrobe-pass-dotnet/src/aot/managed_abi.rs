use disrobe_pass_native::{
    LeafRecovery, PseudoAbi, PseudoParameterBinding, PseudoReg, PseudoScalarType,
};

use super::{
    AotMethod, AotMethodSignature, AotSignatureAbstention, AotType, AotTypeSignature,
    AotTypeSignatureKind,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedReturn {
    Void,
    Value(ManagedValue),
}

impl ManagedReturn {
    const fn c_type(self) -> &'static str {
        match self {
            Self::Void => VOID_C_TYPE,
            Self::Value(value) => value.c_type(),
        }
    }

    const fn lifted_c_type(self) -> &'static str {
        match self {
            Self::Void | Self::Value(ManagedValue::Integral(_)) => GENERIC_PARAMETER_TYPE,
            Self::Value(ManagedValue::Floating(width)) => width.c_type(),
        }
    }

    const fn floating(self) -> Option<ManagedFloat> {
        match self {
            Self::Void | Self::Value(ManagedValue::Integral(_)) => None,
            Self::Value(ManagedValue::Floating(width)) => Some(width),
        }
    }

    const fn is_boolean(self) -> bool {
        match self {
            Self::Void | Self::Value(ManagedValue::Floating(_)) => false,
            Self::Value(ManagedValue::Integral(primitive)) => primitive.is_boolean(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedSlot {
    InstanceReference,
    Value(ManagedValue),
}

impl ManagedSlot {
    const fn c_type(self) -> &'static str {
        match self {
            Self::InstanceReference => OBJECT_REFERENCE_C_TYPE,
            Self::Value(value) => value.c_type(),
        }
    }

    const fn lifted_c_type(self) -> &'static str {
        match self {
            Self::InstanceReference | Self::Value(ManagedValue::Integral(_)) => {
                GENERIC_PARAMETER_TYPE
            }
            Self::Value(ManagedValue::Floating(width)) => width.c_type(),
        }
    }

    const fn floating(self) -> Option<ManagedFloat> {
        match self {
            Self::InstanceReference | Self::Value(ManagedValue::Integral(_)) => None,
            Self::Value(ManagedValue::Floating(width)) => Some(width),
        }
    }

    const fn reinterpreted_integral(self) -> Option<ManagedPrimitive> {
        match self {
            Self::InstanceReference | Self::Value(ManagedValue::Floating(_)) => None,
            Self::Value(ManagedValue::Integral(primitive)) => {
                if primitive.reinterprets_unsigned_bits() {
                    Some(primitive)
                } else {
                    None
                }
            }
        }
    }

    const fn is_boolean(self) -> bool {
        match self {
            Self::InstanceReference | Self::Value(ManagedValue::Floating(_)) => false,
            Self::Value(ManagedValue::Integral(primitive)) => primitive.is_boolean(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedPlan {
    slots: Vec<ManagedSlot>,
    return_type: ManagedReturn,
}

impl ManagedPlan {
    fn for_method(method: &AotMethod, types: &[AotType]) -> Reattached<Self> {
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
        if slot_count > MS_X64_INTEGER_ARGUMENTS.len() {
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
            slots.push(ManagedSlot::Value(resolve_value(*parameter, types)?));
        }
        Ok(Self {
            slots,
            return_type: resolve_return(signature.return_type, types)?,
        })
    }

    fn include_prefix(&self, preamble: &str) -> String {
        let uses_boolean: bool = self.return_type.is_boolean()
            || self.slots.iter().copied().any(ManagedSlot::is_boolean);
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
                let rendered: &'static str = if lifted {
                    slot.lifted_c_type()
                } else {
                    slot.c_type()
                };
                format!("{rendered} a{index}")
            })
            .collect::<Vec<String>>()
            .join(", ")
    }
}

fn resolve_system_type_name(signature: AotTypeSignature, types: &[AotType]) -> Reattached<&str> {
    if signature.kind != AotTypeSignatureKind::Definition {
        return Err(AotSignatureAbstention::TypeSignatureKindUnsupported);
    }
    let declaration: &AotType = types
        .iter()
        .find(|candidate: &&AotType| candidate.record_offset == signature.record_offset)
        .ok_or(AotSignatureAbstention::TypeRecordAbsent)?;
    if declaration.namespace.as_deref() != Some(SYSTEM_NAMESPACE) {
        return Err(AotSignatureAbstention::TypeNamespaceNotSystem);
    }
    Ok(declaration.name.as_str())
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

fn resolve_return(signature: AotTypeSignature, types: &[AotType]) -> Reattached<ManagedReturn> {
    if resolve_system_type_name(signature, types)? == VOID_TYPE_NAME {
        return Ok(ManagedReturn::Void);
    }
    resolve_value(signature, types).map(ManagedReturn::Value)
}

fn return_agrees(recovery: &LeafRecovery, return_type: ManagedReturn) -> Reattached<()> {
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

fn slot_binding_agrees(
    index: usize,
    slot: ManagedSlot,
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

fn recovery_shape_agrees(recovery: &LeafRecovery) -> Reattached<()> {
    if recovery.signature.abi() != PseudoAbi::MsX64 {
        return Err(AotSignatureAbstention::NonMicrosoftX64Recovery);
    }
    if recovery.sret.is_some() {
        return Err(AotSignatureAbstention::HiddenStructReturn);
    }
    Ok(())
}

fn bindings_agree(recovery: &LeafRecovery, slots: &[ManagedSlot]) -> Reattached<()> {
    recovery_shape_agrees(recovery)?;
    let bindings: &[PseudoParameterBinding] = recovery.signature.parameter_bindings();
    if bindings.len() != slots.len() {
        return Err(AotSignatureAbstention::ArgumentCountDisagreement);
    }
    bindings
        .iter()
        .copied()
        .zip(slots.iter().copied())
        .enumerate()
        .try_for_each(
            |(index, (binding, slot)): (usize, (PseudoParameterBinding, ManagedSlot))| {
                slot_binding_agrees(index, slot, binding)
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
    let managed: String = format!(
        "{}{}{PROTOTYPE_NAME}{}{PROTOTYPE_TAIL}",
        plan.include_prefix(preamble),
        plan.return_type.c_type(),
        plan.parameter_list(false)
    );
    Ok((managed, body.to_owned()))
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
        let Some(primitive): Option<ManagedPrimitive> = slot.reinterpreted_integral() else {
            continue;
        };
        let head: String = line
            .strip_suffix(suffix.as_str())
            .ok_or_else(isolated)?
            .to_owned();
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
        ManagedReturn::Value(ManagedValue::Floating(_width)) => {}
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
) -> Reattached<String> {
    recovery_shape_agrees(recovery)?;
    let plan: ManagedPlan = ManagedPlan::for_method(method, types)?;
    return_agrees(recovery, plan.return_type)?;
    bindings_agree(recovery, &plan.slots)?;
    let (prototype, body): (String, String) = split_prototype(&recovery.source, &plan)?;
    let body: String = rewrite_argument_bindings(&body, &plan)?;
    let body: String = rewrite_return(&body, &plan)?;
    Ok(format!("{prototype}{body}"))
}

#[cfg(test)]
mod tests {
    use super::{
        AotMethod, AotMethodSignature, AotSignatureAbstention, AotType, AotTypeSignature,
        AotTypeSignatureKind, ManagedFloat, ManagedPlan, ManagedPrimitive, ManagedReturn,
        ManagedSlot, ManagedValue, PseudoParameterBinding, PseudoReg, PseudoScalarType,
        bindings_agree, identifier_occurrences, resolve_return, resolve_value, return_agrees,
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
        ManagedPlan::for_method(&probe(signature), &type_table())
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
            resolve_return(definition(VOID), &types),
            Ok(ManagedReturn::Void)
        );
        assert_eq!(
            resolve_return(definition(6), &types),
            Ok(ManagedReturn::Value(ManagedValue::Floating(
                ManagedFloat::Double
            )))
        );
        assert_eq!(
            resolve_return(definition(4), &types),
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
                &type_table()
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

        for slot in [INTEGRAL, FLOATING, ManagedSlot::InstanceReference] {
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
        assert_eq!(slot_binding_agrees(1, INTEGRAL, RDX), Ok(()));
        assert_eq!(
            slot_binding_agrees(1, ManagedSlot::InstanceReference, RDX),
            Ok(())
        );
        assert_eq!(
            slot_binding_agrees(1, FLOATING, RDX),
            Err(AotSignatureAbstention::FloatingPointRegisterDisagreement)
        );
        assert_eq!(
            slot_binding_agrees(0, INTEGRAL, RDX),
            Err(AotSignatureAbstention::ArgumentRegisterDisagreement)
        );
        assert_eq!(slot_binding_agrees(1, FLOATING, XMM1_DOUBLE), Ok(()));
        assert_eq!(
            slot_binding_agrees(0, FLOATING, XMM1_DOUBLE),
            Err(AotSignatureAbstention::FloatingPointRegisterDisagreement)
        );
        assert_eq!(
            slot_binding_agrees(1, INTEGRAL, XMM1_DOUBLE),
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
                    FLOATING,
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
            slot_binding_agrees(4, INTEGRAL, RDX),
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
            bindings_agree(&sysv, &[INT32]),
            Err(AotSignatureAbstention::NonMicrosoftX64Recovery)
        );
        assert_eq!(
            bindings_agree(&hidden, &[INT32]),
            Err(AotSignatureAbstention::HiddenStructReturn)
        );
        assert_eq!(
            bindings_agree(&plain, &[INT32, INT32]),
            Err(AotSignatureAbstention::ArgumentCountDisagreement)
        );
        assert_eq!(bindings_agree(&plain, &[INT32]), Ok(()));
        assert_eq!(
            return_agrees(&floating, ManagedReturn::Void),
            Err(AotSignatureAbstention::ReturnClassDisagreement)
        );
        assert_eq!(
            return_agrees(
                &plain,
                ManagedReturn::Value(ManagedValue::Floating(ManagedFloat::Double))
            ),
            Err(AotSignatureAbstention::ReturnClassDisagreement)
        );
        assert_eq!(
            return_agrees(
                &floating,
                ManagedReturn::Value(ManagedValue::Floating(ManagedFloat::Single))
            ),
            Err(AotSignatureAbstention::ReturnClassDisagreement)
        );
        assert_eq!(
            return_agrees(
                &floating,
                ManagedReturn::Value(ManagedValue::Floating(ManagedFloat::Double))
            ),
            Ok(())
        );
        assert_eq!(return_agrees(&plain, ManagedReturn::Void), Ok(()));
        Ok(())
    }
}
