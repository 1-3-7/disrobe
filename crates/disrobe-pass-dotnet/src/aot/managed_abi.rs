use disrobe_pass_native::{LeafRecovery, PseudoAbi, PseudoParameterBinding, PseudoReg};

use super::{AotMethod, AotMethodSignature, AotType, AotTypeSignature, AotTypeSignatureKind};

const CALLING_CONVENTION_MASK: u32 = 0x0f;
const AMD64_REGISTER_EQUIVALENT_CONVENTIONS: [u32; 2] = [0x00, 0x01];
const GENERIC_SIGNATURE: u32 = 0x10;
const HAS_THIS: u32 = 0x20;
const EXPLICIT_THIS: u32 = 0x40;
const SYSTEM_NAMESPACE: &str = "System";
const MS_X64_INTEGER_ARGUMENTS: [PseudoReg; 4] =
    [PseudoReg::Rcx, PseudoReg::Rdx, PseudoReg::R8, PseudoReg::R9];
const OBJECT_REFERENCE_C_TYPE: &str = "uintptr_t";
const STDINT_INCLUDE: &str = "#include <stdint.h>\n";
const STDBOOL_AND_STDINT_INCLUDE: &str = "#include <stdbool.h>\n#include <stdint.h>\n";
const PROTOTYPE_NAME: &str = " recovered(";
const PROTOTYPE_TAIL: &str = ") {\n";
const GENERIC_PARAMETER_TYPE: &str = "uint64_t";
const RETURN_STATEMENT: &str = "    return ";
const STATEMENT_TERMINATOR: &str = ";\n";
const CLOSING_BRACE_LINE: &str = "}\n";
const REGISTER_BINDING_PREFIX: &str = "    uint64_t r_";

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
enum ManagedSlot {
    InstanceReference,
    Value(ManagedPrimitive),
}

impl ManagedSlot {
    const fn c_type(self) -> &'static str {
        match self {
            Self::InstanceReference => OBJECT_REFERENCE_C_TYPE,
            Self::Value(primitive) => primitive.c_type(),
        }
    }

    const fn unsigned_c_type(self) -> &'static str {
        match self {
            Self::InstanceReference => OBJECT_REFERENCE_C_TYPE,
            Self::Value(primitive) => primitive.unsigned_c_type(),
        }
    }

    const fn reinterprets_unsigned_bits(self) -> bool {
        match self {
            Self::InstanceReference => false,
            Self::Value(primitive) => primitive.reinterprets_unsigned_bits(),
        }
    }

    const fn is_boolean(self) -> bool {
        match self {
            Self::InstanceReference => false,
            Self::Value(primitive) => primitive.is_boolean(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedPlan {
    slots: Vec<ManagedSlot>,
    return_type: ManagedPrimitive,
}

impl ManagedPlan {
    fn for_method(method: &AotMethod, types: &[AotType]) -> Option<Self> {
        let signature: &AotMethodSignature = method.signature.as_ref()?;
        let convention: u32 = signature.calling_convention;
        if !AMD64_REGISTER_EQUIVALENT_CONVENTIONS.contains(&(convention & CALLING_CONVENTION_MASK))
            || convention & (EXPLICIT_THIS | GENERIC_SIGNATURE) != 0
            || signature.generic_parameter_count != 0
            || !signature.vararg_parameter_types.is_empty()
        {
            return None;
        }
        let has_this: bool = convention & HAS_THIS != 0;
        let slot_count: usize = signature
            .parameter_types
            .len()
            .checked_add(usize::from(has_this))?;
        if slot_count > MS_X64_INTEGER_ARGUMENTS.len() {
            return None;
        }
        let mut slots: Vec<ManagedSlot> = Vec::new();
        slots.try_reserve_exact(slot_count).ok()?;
        if has_this {
            slots.push(ManagedSlot::InstanceReference);
        }
        for parameter in &signature.parameter_types {
            slots.push(ManagedSlot::Value(resolve_primitive(*parameter, types)?));
        }
        Some(Self {
            slots,
            return_type: resolve_primitive(signature.return_type, types)?,
        })
    }

    fn include_directive(&self) -> &'static str {
        let uses_boolean: bool = self.return_type.is_boolean()
            || self.slots.iter().copied().any(ManagedSlot::is_boolean);
        if uses_boolean {
            STDBOOL_AND_STDINT_INCLUDE
        } else {
            STDINT_INCLUDE
        }
    }

    fn parameter_list(&self, generic: bool) -> String {
        self.slots
            .iter()
            .enumerate()
            .map(|(index, slot): (usize, &ManagedSlot)| {
                let rendered: &'static str = if generic {
                    GENERIC_PARAMETER_TYPE
                } else {
                    slot.c_type()
                };
                format!("{rendered} a{index}")
            })
            .collect::<Vec<String>>()
            .join(", ")
    }
}

fn resolve_primitive(signature: AotTypeSignature, types: &[AotType]) -> Option<ManagedPrimitive> {
    if signature.kind != AotTypeSignatureKind::Definition {
        return None;
    }
    let declaration: &AotType = types
        .iter()
        .find(|candidate: &&AotType| candidate.record_offset == signature.record_offset)?;
    if declaration.namespace.as_deref() != Some(SYSTEM_NAMESPACE) {
        return None;
    }
    MANAGED_PRIMITIVES
        .iter()
        .find(|(name, _primitive): &&(&str, ManagedPrimitive)| *name == declaration.name)
        .map(|(_name, primitive): &(&str, ManagedPrimitive)| *primitive)
}

fn bindings_agree(recovery: &LeafRecovery, slots: &[ManagedSlot]) -> bool {
    if recovery.signature.abi() != PseudoAbi::MsX64 || recovery.sret.is_some() {
        return false;
    }
    let bindings: &[PseudoParameterBinding] = recovery.signature.parameter_bindings();
    if bindings.len() != slots.len() {
        return false;
    }
    bindings.iter().zip(MS_X64_INTEGER_ARGUMENTS.iter()).all(
        |(binding, expected): (&PseudoParameterBinding, &PseudoReg)| {
            matches!(
                binding,
                PseudoParameterBinding::Integer { register, .. } if register == expected
            )
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

fn split_prototype(source: &str, plan: &ManagedPlan) -> Option<(String, String)> {
    let after_include: &str = source.strip_prefix(STDINT_INCLUDE)?;
    let declared: String = format!(
        "{GENERIC_PARAMETER_TYPE}{PROTOTYPE_NAME}{}{PROTOTYPE_TAIL}",
        plan.parameter_list(true)
    );
    let body: &str = after_include.strip_prefix(declared.as_str())?;
    let managed: String = format!(
        "{}{}{PROTOTYPE_NAME}{}{PROTOTYPE_TAIL}",
        plan.include_directive(),
        plan.return_type.c_type(),
        plan.parameter_list(false)
    );
    Some((managed, body.to_owned()))
}

fn rewrite_argument_bindings(body: &str, plan: &ManagedPlan) -> Option<String> {
    let mut lines: Vec<String> = body.split_inclusive('\n').map(str::to_owned).collect();
    for (index, slot) in plan.slots.iter().enumerate() {
        let argument: String = format!("a{index}");
        if identifier_occurrences(body, argument.as_str()) != 1 {
            return None;
        }
        let suffix: String = format!(" = {argument};\n");
        let mut matched: Option<usize> = None;
        for (line_index, line) in lines.iter().enumerate() {
            if !line.starts_with(REGISTER_BINDING_PREFIX) || !line.ends_with(suffix.as_str()) {
                continue;
            }
            if matched.is_some() {
                return None;
            }
            matched = Some(line_index);
        }
        let line_index: usize = matched?;
        if !slot.reinterprets_unsigned_bits() {
            continue;
        }
        let line: &mut String = lines.get_mut(line_index)?;
        let head: String = line.strip_suffix(suffix.as_str())?.to_owned();
        *line = format!("{head} = ({}){argument};\n", slot.unsigned_c_type());
    }
    Some(lines.concat())
}

fn rewrite_return(body: &str, plan: &ManagedPlan) -> Option<String> {
    let mut lines: Vec<String> = body.split_inclusive('\n').map(str::to_owned).collect();
    let returns: usize = lines
        .iter()
        .filter(|line: &&String| line.starts_with(RETURN_STATEMENT))
        .count();
    if returns != 1 || lines.last().map(String::as_str) != Some(CLOSING_BRACE_LINE) {
        return None;
    }
    let return_index: usize = lines.len().checked_sub(2)?;
    let line: &mut String = lines.get_mut(return_index)?;
    let expression: String = line
        .strip_prefix(RETURN_STATEMENT)?
        .strip_suffix(STATEMENT_TERMINATOR)?
        .to_owned();
    let converted: String = reinterpret(
        expression.as_str(),
        plan.return_type.c_type(),
        plan.return_type.unsigned_c_type(),
        plan.return_type.reinterprets_unsigned_bits(),
    );
    *line = format!("{RETURN_STATEMENT}{converted}{STATEMENT_TERMINATOR}");
    Some(lines.concat())
}

pub(super) fn reassociate(
    recovery: &LeafRecovery,
    method: &AotMethod,
    types: &[AotType],
) -> Option<String> {
    let plan: ManagedPlan = ManagedPlan::for_method(method, types)?;
    if !bindings_agree(recovery, &plan.slots) {
        return None;
    }
    let (prototype, body): (String, String) = split_prototype(&recovery.source, &plan)?;
    let body: String = rewrite_argument_bindings(&body, &plan)?;
    let body: String = rewrite_return(&body, &plan)?;
    Some(format!("{prototype}{body}"))
}

#[cfg(test)]
mod tests {
    use super::{
        AotMethod, AotMethodSignature, AotType, AotTypeSignature, AotTypeSignatureKind,
        ManagedPlan, ManagedPrimitive, ManagedSlot, identifier_occurrences, resolve_primitive,
        rewrite_argument_bindings, rewrite_return,
    };
    use crate::aot::AotCodeRange;

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
        AotMethodSignature {
            record_offset: 9,
            calling_convention,
            generic_parameter_count: 0,
            return_type: definition(1),
            parameter_types: vec![definition(1); parameters],
            vararg_parameter_types: Vec::new(),
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
        ];

        assert_eq!(
            resolve_primitive(definition(1), &types),
            Some(ManagedPrimitive::Int32)
        );
        assert_eq!(
            resolve_primitive(definition(2), &types),
            Some(ManagedPrimitive::Boolean)
        );
        assert_eq!(resolve_primitive(definition(3), &types), None);
        assert_eq!(resolve_primitive(definition(4), &types), None);
        assert_eq!(resolve_primitive(definition(5), &types), None);
        assert_eq!(
            resolve_primitive(
                AotTypeSignature {
                    kind: AotTypeSignatureKind::Reference,
                    record_offset: 1,
                },
                &types
            ),
            None
        );
    }

    #[test]
    fn an_instance_signature_reserves_the_first_integer_slot() -> Result<(), &'static str> {
        let types: Vec<AotType> = vec![primitive_type(1, "Int32")];
        let plan: ManagedPlan = ManagedPlan::for_method(&probe(signature(0x20, 1)), &types)
            .ok_or("an instance signature over primitives must plan")?;

        assert_eq!(
            plan.slots,
            vec![
                ManagedSlot::InstanceReference,
                ManagedSlot::Value(ManagedPrimitive::Int32)
            ]
        );
        assert_eq!(plan.return_type, ManagedPrimitive::Int32);
        assert_eq!(
            plan.parameter_list(false),
            "uintptr_t a0, int32_t a1".to_owned()
        );
        Ok(())
    }

    #[test]
    fn a_signature_that_overflows_the_integer_registers_abstains() {
        let types: Vec<AotType> = vec![primitive_type(1, "Int32")];
        assert_eq!(
            ManagedPlan::for_method(&probe(signature(0, 5)), &types),
            None
        );
        assert_eq!(
            ManagedPlan::for_method(&probe(signature(0x20, 4)), &types),
            None
        );
        assert!(ManagedPlan::for_method(&probe(signature(0, 4)), &types).is_some());
    }

    #[test]
    fn only_the_amd64_register_equivalent_conventions_plan() {
        let types: Vec<AotType> = vec![primitive_type(1, "Int32")];
        for convention in [0x02u32, 0x03, 0x04, 0x05, 0x09, 0x10, 0x40, 0x60] {
            assert_eq!(
                ManagedPlan::for_method(&probe(signature(convention, 1)), &types),
                None,
                "0x{convention:02x}"
            );
        }
        for convention in [0x00u32, 0x01, 0x20, 0x21] {
            assert!(
                ManagedPlan::for_method(&probe(signature(convention, 1)), &types).is_some(),
                "0x{convention:02x}"
            );
        }
    }

    #[test]
    fn an_argument_referenced_outside_its_binding_line_abstains() -> Result<(), &'static str> {
        let types: Vec<AotType> = vec![primitive_type(1, "Int32")];
        let plan: ManagedPlan = ManagedPlan::for_method(&probe(signature(0, 1)), &types)
            .ok_or("a static one-parameter primitive signature must plan")?;
        let reused: &str =
            "    uint64_t r_rcx = a0;\n    uint64_t r_rax = a0;\n    return r_rax;\n}\n";
        let bound: &str = "    uint64_t r_rcx = a0;\n    return r_rcx;\n}\n";

        assert_eq!(rewrite_argument_bindings(reused, &plan), None);
        assert_eq!(
            rewrite_argument_bindings(bound, &plan),
            Some("    uint64_t r_rcx = (uint32_t)a0;\n    return r_rcx;\n}\n".to_owned())
        );
        assert_eq!(identifier_occurrences("a0 a01 xa0 a0;", "a0"), 2);
        Ok(())
    }

    #[test]
    fn a_body_with_more_than_one_return_abstains() -> Result<(), &'static str> {
        let types: Vec<AotType> = vec![primitive_type(1, "Int32")];
        let plan: ManagedPlan = ManagedPlan::for_method(&probe(signature(0, 1)), &types)
            .ok_or("a static one-parameter primitive signature must plan")?;

        assert_eq!(
            rewrite_return("    return r_rax;\n    return r_rcx;\n}\n", &plan),
            None
        );
        assert_eq!(rewrite_return("    return r_rax\n}\n", &plan), None);
        assert_eq!(
            rewrite_return("    return r_rax;\n}\n", &plan),
            Some("    return (int32_t)(uint32_t)(r_rax);\n}\n".to_owned())
        );
        Ok(())
    }
}
