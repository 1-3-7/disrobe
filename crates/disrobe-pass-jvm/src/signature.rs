use std::collections::{BTreeMap, BTreeSet};

use crate::classfile::{Attribute, ClassFile, FieldInfo, MethodInfo};
use crate::descriptor::{self, JavaType, MethodDescriptor};

const MAX_SIGNATURE_BYTES: usize = 65_535;
const MAX_SIGNATURE_DEPTH: u16 = 64;
const MAX_SIGNATURE_NODES: u32 = 4_096;
const MAX_SIGNATURE_ITEMS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum JavaTypeSignature {
    Base(JavaType),
    Reference(ReferenceTypeSignature),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReferenceTypeSignature {
    Class(ClassTypeSignature),
    TypeVariable(String),
    Array(Box<JavaTypeSignature>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassTypeSignature {
    package: Vec<String>,
    segments: Vec<ClassSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassSegment {
    name: String,
    arguments: Vec<TypeArgument>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TypeArgument {
    Any,
    Extends(ReferenceTypeSignature),
    Super(ReferenceTypeSignature),
    Exact(ReferenceTypeSignature),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypeParameter {
    name: String,
    class_bound: Option<ReferenceTypeSignature>,
    interface_bounds: Vec<ReferenceTypeSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedClassSignature {
    type_parameters: Vec<TypeParameter>,
    superclass: ClassTypeSignature,
    interfaces: Vec<ClassTypeSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedMethodSignature {
    type_parameters: Vec<TypeParameter>,
    parameters: Vec<JavaTypeSignature>,
    result: Option<JavaTypeSignature>,
    throws: Vec<ThrowsSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ThrowsSignature {
    Class(ClassTypeSignature),
    TypeVariable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveredClassSignature {
    pub(crate) type_parameters: String,
    pub(crate) superclass: String,
    pub(crate) interfaces: Vec<String>,
    scope: TypeScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveredMethodSignature {
    pub(crate) type_parameters: String,
    pub(crate) parameters: Vec<String>,
    pub(crate) result: String,
    pub(crate) throws: Vec<String>,
    pub(crate) type_parameter_names: BTreeSet<String>,
    pub(crate) type_parameter_erasures: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypeScope {
    parameters: BTreeMap<String, TypeParameter>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AttributeSignature<'a> {
    Absent,
    Present(&'a str),
    Rejected(String),
}

struct Parser<'a> {
    input: &'a str,
    bytes: &'a [u8],
    position: usize,
    depth: u16,
    nodes: u32,
    work: usize,
    max_work: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Result<Self, String> {
        if input.is_empty() || input.len() > MAX_SIGNATURE_BYTES {
            return Err("signature length is outside the accepted range".to_string());
        }
        let max_work: usize = input
            .len()
            .checked_mul(8)
            .and_then(|value: usize| value.checked_add(128))
            .ok_or_else(|| "signature work budget overflowed".to_string())?;
        Ok(Self {
            input,
            bytes: input.as_bytes(),
            position: 0,
            depth: 0,
            nodes: 0,
            work: 0,
            max_work,
        })
    }

    fn error(&self, reason: &str) -> String {
        format!("byte {}: {reason}", self.position)
    }

    fn charge(&mut self) -> Result<(), String> {
        self.work = self
            .work
            .checked_add(1)
            .ok_or_else(|| self.error("work counter overflowed"))?;
        if self.work > self.max_work {
            return Err(self.error("work budget exceeded"));
        }
        Ok(())
    }

    fn node(&mut self) -> Result<(), String> {
        self.charge()?;
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| self.error("node counter overflowed"))?;
        if self.nodes > MAX_SIGNATURE_NODES {
            return Err(self.error("node budget exceeded"));
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<(), String> {
        self.charge()?;
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| self.error("depth counter overflowed"))?;
        if self.depth > MAX_SIGNATURE_DEPTH {
            self.depth = self.depth.saturating_sub(1);
            return Err(self.error("recursion depth exceeded"));
        }
        Ok(())
    }

    const fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn peek(&mut self) -> Result<Option<u8>, String> {
        self.charge()?;
        Ok(self.bytes.get(self.position).copied())
    }

    fn consume(&mut self, expected: u8) -> Result<bool, String> {
        self.charge()?;
        if self.bytes.get(self.position) == Some(&expected) {
            self.position += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), String> {
        if self.consume(expected)? {
            Ok(())
        } else {
            Err(self.error(&format!("expected {:?}", char::from(expected))))
        }
    }

    fn identifier(&mut self) -> Result<String, String> {
        self.charge()?;
        let start: usize = self.position;
        while let Some(byte) = self.bytes.get(self.position).copied() {
            if matches!(byte, b'.' | b';' | b'[' | b'/' | b'<' | b'>' | b':') {
                break;
            }
            self.position += 1;
            self.charge()?;
        }
        if self.position == start {
            return Err(self.error("identifier is empty"));
        }
        let identifier: &str = self
            .input
            .get(start..self.position)
            .ok_or_else(|| self.error("identifier is not on UTF-8 boundaries"))?;
        Ok(identifier.to_string())
    }

    fn type_parameters(&mut self) -> Result<Vec<TypeParameter>, String> {
        if !self.consume(b'<')? {
            return Ok(Vec::new());
        }
        let mut parameters: Vec<TypeParameter> = Vec::new();
        while self.peek()? != Some(b'>') {
            if parameters.len() >= MAX_SIGNATURE_ITEMS {
                return Err(self.error("type parameter count exceeded"));
            }
            parameters.push(self.type_parameter()?);
        }
        if parameters.is_empty() {
            return Err(self.error("type parameter list is empty"));
        }
        self.expect(b'>')?;
        Ok(parameters)
    }

    fn type_parameter(&mut self) -> Result<TypeParameter, String> {
        self.node()?;
        let name: String = self.identifier()?;
        self.expect(b':')?;
        let class_bound: Option<ReferenceTypeSignature> = match self.peek()? {
            Some(b'L' | b'T' | b'[') => Some(self.reference_type()?),
            _ => None,
        };
        let mut interface_bounds: Vec<ReferenceTypeSignature> = Vec::new();
        while self.consume(b':')? {
            if interface_bounds.len() >= MAX_SIGNATURE_ITEMS {
                return Err(self.error("interface bound count exceeded"));
            }
            interface_bounds.push(self.reference_type()?);
        }
        Ok(TypeParameter {
            name,
            class_bound,
            interface_bounds,
        })
    }

    fn java_type(&mut self) -> Result<JavaTypeSignature, String> {
        self.node()?;
        let signature: JavaTypeSignature = match self.peek()? {
            Some(b'B') => {
                self.position += 1;
                JavaTypeSignature::Base(JavaType::Byte)
            }
            Some(b'C') => {
                self.position += 1;
                JavaTypeSignature::Base(JavaType::Char)
            }
            Some(b'D') => {
                self.position += 1;
                JavaTypeSignature::Base(JavaType::Double)
            }
            Some(b'F') => {
                self.position += 1;
                JavaTypeSignature::Base(JavaType::Float)
            }
            Some(b'I') => {
                self.position += 1;
                JavaTypeSignature::Base(JavaType::Int)
            }
            Some(b'J') => {
                self.position += 1;
                JavaTypeSignature::Base(JavaType::Long)
            }
            Some(b'S') => {
                self.position += 1;
                JavaTypeSignature::Base(JavaType::Short)
            }
            Some(b'Z') => {
                self.position += 1;
                JavaTypeSignature::Base(JavaType::Boolean)
            }
            Some(b'L' | b'T' | b'[') => JavaTypeSignature::Reference(self.reference_type()?),
            _ => return Err(self.error("expected Java type signature")),
        };
        Ok(signature)
    }

    fn reference_type(&mut self) -> Result<ReferenceTypeSignature, String> {
        self.enter()?;
        self.node()?;
        let result: Result<ReferenceTypeSignature, String> = match self.peek()? {
            Some(b'L') => self.class_type().map(ReferenceTypeSignature::Class),
            Some(b'T') => {
                self.position += 1;
                let name: String = self.identifier()?;
                self.expect(b';')?;
                Ok(ReferenceTypeSignature::TypeVariable(name))
            }
            Some(b'[') => {
                self.position += 1;
                self.java_type().map(|element: JavaTypeSignature| {
                    ReferenceTypeSignature::Array(Box::new(element))
                })
            }
            _ => Err(self.error("expected reference type signature")),
        };
        self.leave();
        result
    }

    fn class_type(&mut self) -> Result<ClassTypeSignature, String> {
        self.expect(b'L')?;
        let mut package: Vec<String> = Vec::new();
        let mut name: String = self.identifier()?;
        while self.consume(b'/')? {
            if package.len() >= MAX_SIGNATURE_ITEMS {
                return Err(self.error("package segment count exceeded"));
            }
            package.push(name);
            name = self.identifier()?;
        }
        let arguments: Vec<TypeArgument> = self.type_arguments()?;
        let mut segments: Vec<ClassSegment> = vec![ClassSegment { name, arguments }];
        while self.consume(b'.')? {
            if segments.len() >= MAX_SIGNATURE_ITEMS {
                return Err(self.error("class suffix count exceeded"));
            }
            let suffix_name: String = self.identifier()?;
            let suffix_arguments: Vec<TypeArgument> = self.type_arguments()?;
            segments.push(ClassSegment {
                name: suffix_name,
                arguments: suffix_arguments,
            });
        }
        self.expect(b';')?;
        Ok(ClassTypeSignature { package, segments })
    }

    fn type_arguments(&mut self) -> Result<Vec<TypeArgument>, String> {
        if !self.consume(b'<')? {
            return Ok(Vec::new());
        }
        let mut arguments: Vec<TypeArgument> = Vec::new();
        while self.peek()? != Some(b'>') {
            if arguments.len() >= MAX_SIGNATURE_ITEMS {
                return Err(self.error("type argument count exceeded"));
            }
            self.node()?;
            let argument: TypeArgument = match self.peek()? {
                Some(b'*') => {
                    self.position += 1;
                    TypeArgument::Any
                }
                Some(b'+') => {
                    self.position += 1;
                    TypeArgument::Extends(self.reference_type()?)
                }
                Some(b'-') => {
                    self.position += 1;
                    TypeArgument::Super(self.reference_type()?)
                }
                _ => TypeArgument::Exact(self.reference_type()?),
            };
            arguments.push(argument);
        }
        if arguments.is_empty() {
            return Err(self.error("type argument list is empty"));
        }
        self.expect(b'>')?;
        Ok(arguments)
    }

    fn class_signature(&mut self) -> Result<ParsedClassSignature, String> {
        let type_parameters: Vec<TypeParameter> = self.type_parameters()?;
        let superclass: ClassTypeSignature = self.class_type()?;
        let mut interfaces: Vec<ClassTypeSignature> = Vec::new();
        while self.position < self.bytes.len() {
            if interfaces.len() >= MAX_SIGNATURE_ITEMS {
                return Err(self.error("superinterface count exceeded"));
            }
            interfaces.push(self.class_type()?);
        }
        self.finish()?;
        Ok(ParsedClassSignature {
            type_parameters,
            superclass,
            interfaces,
        })
    }

    fn method_signature(&mut self) -> Result<ParsedMethodSignature, String> {
        let type_parameters: Vec<TypeParameter> = self.type_parameters()?;
        self.expect(b'(')?;
        let mut parameters: Vec<JavaTypeSignature> = Vec::new();
        while self.peek()? != Some(b')') {
            if parameters.len() >= MAX_SIGNATURE_ITEMS {
                return Err(self.error("method parameter count exceeded"));
            }
            parameters.push(self.java_type()?);
        }
        self.expect(b')')?;
        let result: Option<JavaTypeSignature> = if self.consume(b'V')? {
            None
        } else {
            Some(self.java_type()?)
        };
        let mut throws: Vec<ThrowsSignature> = Vec::new();
        while self.consume(b'^')? {
            if throws.len() >= MAX_SIGNATURE_ITEMS {
                return Err(self.error("throws signature count exceeded"));
            }
            let throws_signature: ThrowsSignature = match self.peek()? {
                Some(b'L') => ThrowsSignature::Class(self.class_type()?),
                Some(b'T') => {
                    self.position += 1;
                    let name: String = self.identifier()?;
                    self.expect(b';')?;
                    ThrowsSignature::TypeVariable(name)
                }
                _ => return Err(self.error("expected class or type variable throws signature")),
            };
            throws.push(throws_signature);
        }
        self.finish()?;
        Ok(ParsedMethodSignature {
            type_parameters,
            parameters,
            result,
            throws,
        })
    }

    fn field_signature(&mut self) -> Result<ReferenceTypeSignature, String> {
        let signature: ReferenceTypeSignature = self.reference_type()?;
        self.finish()?;
        Ok(signature)
    }

    fn finish(&self) -> Result<(), String> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(self.error("trailing signature input"))
        }
    }
}

fn signature_attribute<'a>(
    cf: &'a ClassFile,
    attributes: &'a [Attribute],
) -> AttributeSignature<'a> {
    let mut found: Option<&Attribute> = None;
    for attribute in attributes {
        if !cf
            .utf8_at(attribute.name_index)
            .is_ok_and(|name: &str| name == "Signature")
        {
            continue;
        }
        if found.is_some() {
            return AttributeSignature::Rejected("duplicate Signature attributes".to_string());
        }
        found = Some(attribute);
    }
    let Some(attribute): Option<&Attribute> = found else {
        return AttributeSignature::Absent;
    };
    let Ok(bytes): Result<[u8; 2], _> = attribute.info.as_slice().try_into() else {
        return AttributeSignature::Rejected("Signature attribute length is not two".to_string());
    };
    match cf.utf8_at(u16::from_be_bytes(bytes)) {
        Ok(value) => AttributeSignature::Present(value),
        Err(error) => AttributeSignature::Rejected(format!("Signature index is invalid: {error}")),
    }
}

fn reject(cf: &ClassFile, location: &str, reason: &str) {
    crate::debug::dbg_kv("generic-signature-reject", || {
        format!(
            "{} {location}: {reason}",
            cf.this_class_name().unwrap_or("<unknown>")
        )
    });
}

fn validate_identifier(identifier: &str, type_identifier: bool) -> Result<(), String> {
    let valid: bool = if type_identifier {
        crate::name_disambig::is_java_type_identifier(identifier)
    } else {
        crate::name_disambig::is_java_source_identifier(identifier)
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "identifier {identifier:?} is not Java-source representable"
        ))
    }
}

fn validate_class_type_names(signature: &ClassTypeSignature) -> Result<(), String> {
    for package in &signature.package {
        validate_identifier(package, false)?;
    }
    for segment in &signature.segments {
        validate_identifier(&segment.name, true)?;
        for argument in &segment.arguments {
            match argument {
                TypeArgument::Any => {}
                TypeArgument::Extends(reference)
                | TypeArgument::Super(reference)
                | TypeArgument::Exact(reference) => validate_reference_names(reference)?,
            }
        }
    }
    Ok(())
}

fn validate_reference_names(signature: &ReferenceTypeSignature) -> Result<(), String> {
    match signature {
        ReferenceTypeSignature::Class(class_type) => validate_class_type_names(class_type),
        ReferenceTypeSignature::TypeVariable(name) => validate_identifier(name, true),
        ReferenceTypeSignature::Array(element) => validate_java_type_names(element),
    }
}

fn validate_java_type_names(signature: &JavaTypeSignature) -> Result<(), String> {
    match signature {
        JavaTypeSignature::Base(_) => Ok(()),
        JavaTypeSignature::Reference(reference) => validate_reference_names(reference),
    }
}

fn build_scope(
    outer: Option<&TypeScope>,
    parameters: &[TypeParameter],
) -> Result<TypeScope, String> {
    let mut scope: TypeScope = outer.cloned().unwrap_or(TypeScope {
        parameters: BTreeMap::new(),
    });
    let mut local_names: BTreeSet<&str> = BTreeSet::new();
    for parameter in parameters {
        validate_identifier(&parameter.name, true)?;
        if !local_names.insert(&parameter.name) {
            return Err(format!("duplicate type parameter {:?}", parameter.name));
        }
        scope
            .parameters
            .insert(parameter.name.clone(), parameter.clone());
    }
    for parameter in parameters {
        if parameter.class_bound.is_none() && parameter.interface_bounds.is_empty() {
            return Err(format!(
                "type parameter {:?} has no representable bound",
                parameter.name
            ));
        }
        if matches!(
            parameter.class_bound,
            Some(ReferenceTypeSignature::Array(_))
        ) {
            return Err(format!(
                "array class bound on {:?} is not source representable",
                parameter.name
            ));
        }
        if parameter
            .interface_bounds
            .iter()
            .any(|bound: &ReferenceTypeSignature| {
                !matches!(bound, ReferenceTypeSignature::Class(_))
            })
        {
            return Err(format!(
                "non-class interface bound on {:?} is not source representable",
                parameter.name
            ));
        }
        if let Some(bound) = &parameter.class_bound {
            validate_reference(bound, &scope)?;
        }
        for bound in &parameter.interface_bounds {
            validate_reference(bound, &scope)?;
        }
        let bounds: Vec<&ReferenceTypeSignature> = parameter
            .class_bound
            .iter()
            .chain(&parameter.interface_bounds)
            .collect();
        let mut erasures: BTreeSet<String> = BTreeSet::new();
        for bound in bounds {
            let mut visiting: BTreeSet<String> = BTreeSet::new();
            let erasure: String = erase_reference(bound, &scope, &mut visiting)?.render();
            if !erasures.insert(erasure) {
                return Err(format!(
                    "type parameter {:?} repeats a bound erasure",
                    parameter.name
                ));
            }
        }
    }
    for parameter in parameters {
        let mut visiting: BTreeSet<String> = BTreeSet::new();
        erase_type_variable(&parameter.name, &scope, &mut visiting)?;
    }
    Ok(scope)
}

fn validate_reference(signature: &ReferenceTypeSignature, scope: &TypeScope) -> Result<(), String> {
    validate_reference_names(signature)?;
    match signature {
        ReferenceTypeSignature::Class(class_type) => validate_class_type(class_type, scope),
        ReferenceTypeSignature::TypeVariable(name) => {
            if scope.parameters.contains_key(name) {
                Ok(())
            } else {
                Err(format!("undeclared type variable {name:?}"))
            }
        }
        ReferenceTypeSignature::Array(element) => validate_java_type(element, scope),
    }
}

fn validate_class_type(signature: &ClassTypeSignature, scope: &TypeScope) -> Result<(), String> {
    validate_class_type_names(signature)?;
    for segment in &signature.segments {
        for argument in &segment.arguments {
            match argument {
                TypeArgument::Any => {}
                TypeArgument::Extends(reference)
                | TypeArgument::Super(reference)
                | TypeArgument::Exact(reference) => validate_reference(reference, scope)?,
            }
        }
    }
    Ok(())
}

fn validate_class_header_type(
    signature: &ClassTypeSignature,
    scope: &TypeScope,
) -> Result<(), String> {
    validate_class_type(signature, scope)?;
    if signature.segments.iter().any(|segment: &ClassSegment| {
        segment
            .arguments
            .iter()
            .any(|argument: &TypeArgument| !matches!(argument, TypeArgument::Exact(_)))
    }) {
        return Err(
            "wildcard type argument in a class header is not source representable".to_string(),
        );
    }
    if signature.segments.len() > 1
        && signature
            .segments
            .iter()
            .take(signature.segments.len() - 1)
            .any(|segment: &ClassSegment| !segment.arguments.is_empty())
    {
        return Err(
            "parameterized enclosing type in a class header cannot be resolved safely".to_string(),
        );
    }
    Ok(())
}

fn has_type_arguments(signature: &ClassTypeSignature) -> bool {
    signature
        .segments
        .iter()
        .any(|segment: &ClassSegment| !segment.arguments.is_empty())
}

fn is_proven_throwable(binary_name: &str) -> bool {
    matches!(
        binary_name,
        "java/lang/Throwable"
            | "java/lang/Exception"
            | "java/lang/RuntimeException"
            | "java/lang/Error"
    )
}

fn throwable_type_variable_erasure(name: &str, scope: &TypeScope) -> Result<String, String> {
    validate_identifier(name, true)?;
    if !scope.parameters.contains_key(name) {
        return Err(format!("undeclared throws type variable {name:?}"));
    }
    let mut visiting: BTreeSet<String> = BTreeSet::new();
    let erased: JavaType = erase_type_variable(name, scope, &mut visiting)?;
    let JavaType::Object(binary) = erased else {
        return Err("throws type variable does not erase to a class".to_string());
    };
    let binary_name: &str = binary
        .strip_prefix('L')
        .and_then(|value: &str| value.strip_suffix(';'))
        .ok_or_else(|| "throws erasure is not an object descriptor".to_string())?;
    if !is_proven_throwable(binary_name) {
        return Err("throws type variable does not have a proven Throwable bound".to_string());
    }
    Ok(binary_name.to_string())
}

fn validate_java_type(signature: &JavaTypeSignature, scope: &TypeScope) -> Result<(), String> {
    validate_java_type_names(signature)?;
    match signature {
        JavaTypeSignature::Base(_) => Ok(()),
        JavaTypeSignature::Reference(reference) => validate_reference(reference, scope),
    }
}

fn class_binary_name(signature: &ClassTypeSignature) -> Result<String, String> {
    let Some(first): Option<&ClassSegment> = signature.segments.first() else {
        return Err("class type has no segments".to_string());
    };
    let mut name: String = String::new();
    if !signature.package.is_empty() {
        name.push_str(&signature.package.join("/"));
        name.push('/');
    }
    name.push_str(&first.name);
    for segment in signature.segments.iter().skip(1) {
        name.push('$');
        name.push_str(&segment.name);
    }
    Ok(name)
}

fn erase_class_type(signature: &ClassTypeSignature) -> Result<JavaType, String> {
    Ok(JavaType::Object(format!(
        "L{};",
        class_binary_name(signature)?
    )))
}

fn erase_java_type(signature: &JavaTypeSignature, scope: &TypeScope) -> Result<JavaType, String> {
    match signature {
        JavaTypeSignature::Base(base) => Ok(base.clone()),
        JavaTypeSignature::Reference(reference) => {
            let mut visiting: BTreeSet<String> = BTreeSet::new();
            erase_reference(reference, scope, &mut visiting)
        }
    }
}

fn erase_reference(
    signature: &ReferenceTypeSignature,
    scope: &TypeScope,
    visiting: &mut BTreeSet<String>,
) -> Result<JavaType, String> {
    match signature {
        ReferenceTypeSignature::Class(class_type) => erase_class_type(class_type),
        ReferenceTypeSignature::TypeVariable(name) => {
            erase_type_variable_with_set(name, scope, visiting)
        }
        ReferenceTypeSignature::Array(element) => {
            Ok(JavaType::Array(Box::new(match element.as_ref() {
                JavaTypeSignature::Base(base) => base.clone(),
                JavaTypeSignature::Reference(reference) => {
                    erase_reference(reference, scope, visiting)?
                }
            })))
        }
    }
}

fn erase_type_variable(
    name: &str,
    scope: &TypeScope,
    visiting: &mut BTreeSet<String>,
) -> Result<JavaType, String> {
    erase_type_variable_with_set(name, scope, visiting)
}

fn erase_type_variable_with_set(
    name: &str,
    scope: &TypeScope,
    visiting: &mut BTreeSet<String>,
) -> Result<JavaType, String> {
    if !visiting.insert(name.to_string()) {
        return Err(format!("cyclic erasure for type variable {name:?}"));
    }
    let parameter: &TypeParameter = scope
        .parameters
        .get(name)
        .ok_or_else(|| format!("undeclared type variable {name:?}"))?;
    let erased: Result<JavaType, String> = if let Some(bound) = &parameter.class_bound {
        erase_reference(bound, scope, visiting)
    } else if let Some(bound) = parameter.interface_bounds.first() {
        erase_reference(bound, scope, visiting)
    } else {
        Ok(JavaType::Object("Ljava/lang/Object;".to_string()))
    };
    visiting.remove(name);
    erased
}

fn render_class_type(signature: &ClassTypeSignature) -> Result<String, String> {
    let Some(first): Option<&ClassSegment> = signature.segments.first() else {
        return Err("class type has no segments".to_string());
    };
    let mut first_binary: String = String::new();
    if !signature.package.is_empty() {
        first_binary.push_str(&signature.package.join("/"));
        first_binary.push('/');
    }
    first_binary.push_str(&first.name);
    let mut rendered: String = descriptor::binary_to_source(&first_binary);
    rendered.push_str(&render_type_arguments(&first.arguments)?);
    for segment in signature.segments.iter().skip(1) {
        rendered.push('.');
        rendered.push_str(&crate::name_disambig::rewrite_active(&segment.name));
        rendered.push_str(&render_type_arguments(&segment.arguments)?);
    }
    Ok(rendered)
}

fn render_type_arguments(arguments: &[TypeArgument]) -> Result<String, String> {
    if arguments.is_empty() {
        return Ok(String::new());
    }
    let mut rendered: Vec<String> = Vec::new();
    rendered
        .try_reserve(arguments.len())
        .map_err(|error: std::collections::TryReserveError| error.to_string())?;
    for argument in arguments {
        rendered.push(match argument {
            TypeArgument::Any => "?".to_string(),
            TypeArgument::Extends(reference) => {
                format!("? extends {}", render_reference(reference)?)
            }
            TypeArgument::Super(reference) => format!("? super {}", render_reference(reference)?),
            TypeArgument::Exact(reference) => render_reference(reference)?,
        });
    }
    Ok(format!("<{}>", rendered.join(", ")))
}

fn render_java_type(signature: &JavaTypeSignature) -> Result<String, String> {
    match signature {
        JavaTypeSignature::Base(base) => Ok(base.render()),
        JavaTypeSignature::Reference(reference) => render_reference(reference),
    }
}

fn render_reference(signature: &ReferenceTypeSignature) -> Result<String, String> {
    match signature {
        ReferenceTypeSignature::Class(class_type) => render_class_type(class_type),
        ReferenceTypeSignature::TypeVariable(name) => Ok(name.clone()),
        ReferenceTypeSignature::Array(element) => Ok(format!("{}[]", render_java_type(element)?)),
    }
}

fn render_type_parameters(parameters: &[TypeParameter]) -> Result<String, String> {
    if parameters.is_empty() {
        return Ok(String::new());
    }
    let mut rendered: Vec<String> = Vec::new();
    rendered
        .try_reserve(parameters.len())
        .map_err(|error: std::collections::TryReserveError| error.to_string())?;
    for parameter in parameters {
        let mut bounds: Vec<String> = Vec::new();
        if let Some(class_bound) = &parameter.class_bound {
            let class_rendered: String = render_reference(class_bound)?;
            if class_rendered != "Object" || !parameter.interface_bounds.is_empty() {
                bounds.push(class_rendered);
            }
        }
        for interface_bound in &parameter.interface_bounds {
            bounds.push(render_reference(interface_bound)?);
        }
        if bounds.is_empty() {
            rendered.push(parameter.name.clone());
        } else {
            rendered.push(format!("{} extends {}", parameter.name, bounds.join(" & ")));
        }
    }
    Ok(format!("<{}>", rendered.join(", ")))
}

fn java_type_matches(left: &JavaType, right: &JavaType) -> bool {
    match (left, right) {
        (JavaType::Object(left_name), JavaType::Object(right_name)) => left_name == right_name,
        (JavaType::Array(left_element), JavaType::Array(right_element)) => {
            java_type_matches(left_element, right_element)
        }
        _ => left == right,
    }
}

fn parse_class(input: &str) -> Result<ParsedClassSignature, String> {
    Parser::new(input)?.class_signature()
}

fn parse_method(input: &str) -> Result<ParsedMethodSignature, String> {
    Parser::new(input)?.method_signature()
}

fn parse_field(input: &str) -> Result<ReferenceTypeSignature, String> {
    Parser::new(input)?.field_signature()
}

pub(crate) fn recover_class(cf: &ClassFile) -> Option<RecoveredClassSignature> {
    let raw: &str = match signature_attribute(cf, &cf.attributes) {
        AttributeSignature::Absent => return None,
        AttributeSignature::Present(raw) => raw,
        AttributeSignature::Rejected(reason) => {
            reject(cf, "class", &reason);
            return None;
        }
    };
    let recovered: Result<RecoveredClassSignature, String> = (|| {
        let parsed: ParsedClassSignature = parse_class(raw)?;
        let scope: TypeScope = build_scope(None, &parsed.type_parameters)?;
        validate_class_header_type(&parsed.superclass, &scope)?;
        for interface in &parsed.interfaces {
            validate_class_header_type(interface, &scope)?;
        }
        let actual_superclass: JavaType = erase_class_type(&parsed.superclass)?;
        let expected_superclass: JavaType = JavaType::Object(format!(
            "L{};",
            cf.class_name(cf.super_class)
                .map_err(|error| error.to_string())?
        ));
        if !java_type_matches(&actual_superclass, &expected_superclass) {
            return Err(
                "class signature superclass erasure mismatches the class header".to_string(),
            );
        }
        if parsed.interfaces.len() != cf.interfaces.len() {
            return Err("class signature interface count mismatches the class header".to_string());
        }
        for (signature, index) in parsed.interfaces.iter().zip(&cf.interfaces) {
            let actual: JavaType = erase_class_type(signature)?;
            let expected: JavaType = JavaType::Object(format!(
                "L{};",
                cf.class_name(*index).map_err(|error| error.to_string())?
            ));
            if !java_type_matches(&actual, &expected) {
                return Err(
                    "class signature interface erasure mismatches the class header".to_string(),
                );
            }
        }
        Ok(RecoveredClassSignature {
            type_parameters: render_type_parameters(&parsed.type_parameters)?,
            superclass: render_class_type(&parsed.superclass)?,
            interfaces: parsed
                .interfaces
                .iter()
                .map(render_class_type)
                .collect::<Result<Vec<String>, String>>()?,
            scope,
        })
    })();
    match recovered {
        Ok(signature) => Some(signature),
        Err(reason) => {
            reject(cf, "class", &reason);
            None
        }
    }
}

pub(crate) fn recover_field(
    cf: &ClassFile,
    field: &FieldInfo,
    class_signature: Option<&RecoveredClassSignature>,
) -> Option<String> {
    let raw: &str = match signature_attribute(cf, &field.attributes) {
        AttributeSignature::Absent => return None,
        AttributeSignature::Present(raw) => raw,
        AttributeSignature::Rejected(reason) => {
            reject(cf, "field", &reason);
            return None;
        }
    };
    let recovered: Result<String, String> = (|| {
        let signature: ReferenceTypeSignature = parse_field(raw)?;
        let empty_scope: TypeScope = TypeScope {
            parameters: BTreeMap::new(),
        };
        let scope: &TypeScope = class_signature.map_or(&empty_scope, |value| &value.scope);
        validate_reference(&signature, scope)?;
        let mut visiting: BTreeSet<String> = BTreeSet::new();
        let actual: JavaType = erase_reference(&signature, scope, &mut visiting)?;
        let descriptor: &str = cf
            .utf8_at(field.descriptor_index)
            .map_err(|error| error.to_string())?;
        let expected: JavaType = descriptor::parse_field(descriptor)
            .ok_or_else(|| "field descriptor is malformed".to_string())?;
        if !java_type_matches(&actual, &expected) {
            return Err("field signature erasure mismatches its descriptor".to_string());
        }
        render_reference(&signature)
    })();
    match recovered {
        Ok(signature) => Some(signature),
        Err(reason) => {
            reject(cf, "field", &reason);
            None
        }
    }
}

fn exceptions(cf: &ClassFile, method: &MethodInfo) -> Result<Option<Vec<String>>, String> {
    let mut found: Option<&Attribute> = None;
    for attribute in &method.attributes {
        if !cf
            .utf8_at(attribute.name_index)
            .is_ok_and(|name: &str| name == "Exceptions")
        {
            continue;
        }
        if found.is_some() {
            return Err("duplicate Exceptions attributes".to_string());
        }
        found = Some(attribute);
    }
    let Some(attribute): Option<&Attribute> = found else {
        return Ok(None);
    };
    let Some(count_bytes): Option<&[u8]> = attribute.info.get(0..2) else {
        return Err("Exceptions attribute is truncated".to_string());
    };
    let count: usize = usize::from(u16::from_be_bytes([count_bytes[0], count_bytes[1]]));
    if count > MAX_SIGNATURE_ITEMS {
        return Err("Exceptions attribute count exceeded".to_string());
    }
    let expected_length: usize = count
        .checked_mul(2)
        .and_then(|value: usize| value.checked_add(2))
        .ok_or_else(|| "Exceptions attribute length overflowed".to_string())?;
    if attribute.info.len() != expected_length {
        return Err("Exceptions attribute length mismatches its count".to_string());
    }
    let mut names: Vec<String> = Vec::new();
    names
        .try_reserve(count)
        .map_err(|error: std::collections::TryReserveError| error.to_string())?;
    for index in 0..count {
        let offset: usize = 2 + index * 2;
        let class_index: u16 =
            u16::from_be_bytes([attribute.info[offset], attribute.info[offset + 1]]);
        names.push(
            cf.class_name(class_index)
                .map_err(|error| error.to_string())?
                .to_string(),
        );
    }
    Ok(Some(names))
}

pub(crate) fn recover_method(
    cf: &ClassFile,
    method: &MethodInfo,
    class_signature: Option<&RecoveredClassSignature>,
) -> Option<RecoveredMethodSignature> {
    let raw: &str = match signature_attribute(cf, &method.attributes) {
        AttributeSignature::Absent => return None,
        AttributeSignature::Present(raw) => raw,
        AttributeSignature::Rejected(reason) => {
            reject(cf, "method", &reason);
            return None;
        }
    };
    let recovered: Result<RecoveredMethodSignature, String> = (|| {
        let signature: ParsedMethodSignature = parse_method(raw)?;
        let scope: TypeScope = build_scope(
            class_signature.map(|value: &RecoveredClassSignature| &value.scope),
            &signature.type_parameters,
        )?;
        for parameter in &signature.parameters {
            validate_java_type(parameter, &scope)?;
        }
        if let Some(result) = &signature.result {
            validate_java_type(result, &scope)?;
        }
        let descriptor: &str = cf
            .utf8_at(method.descriptor_index)
            .map_err(|error| error.to_string())?;
        let expected: MethodDescriptor = descriptor::parse_method(descriptor)
            .ok_or_else(|| "method descriptor is malformed".to_string())?;
        if signature.parameters.len() != expected.params.len() {
            return Err("method signature parameter count mismatches its descriptor".to_string());
        }
        for (actual_signature, expected_type) in signature.parameters.iter().zip(&expected.params) {
            let actual: JavaType = erase_java_type(actual_signature, &scope)?;
            if !java_type_matches(&actual, expected_type) {
                return Err(
                    "method signature parameter erasure mismatches its descriptor".to_string(),
                );
            }
        }
        let actual_result: JavaType = signature.result.as_ref().map_or_else(
            || Ok(JavaType::Void),
            |value| erase_java_type(value, &scope),
        )?;
        if !java_type_matches(&actual_result, &expected.returns) {
            return Err("method signature return erasure mismatches its descriptor".to_string());
        }
        let mut rendered_throws: Vec<String> = Vec::new();
        let mut erased_throws: Vec<String> = Vec::new();
        for throws_signature in &signature.throws {
            match throws_signature {
                ThrowsSignature::Class(class_type) => {
                    validate_class_type(class_type, &scope)?;
                    if has_type_arguments(class_type) {
                        return Err(
                            "parameterized class in a throws signature is not source representable"
                                .to_string(),
                        );
                    }
                    rendered_throws.push(render_class_type(class_type)?);
                    erased_throws.push(class_binary_name(class_type)?);
                }
                ThrowsSignature::TypeVariable(name) => {
                    erased_throws.push(throwable_type_variable_erasure(name, &scope)?);
                    rendered_throws.push(name.clone());
                }
            }
        }
        if !signature.throws.is_empty() {
            let declared: Vec<String> = exceptions(cf, method)?.ok_or_else(|| {
                "generic throws signature has no Exceptions attribute".to_string()
            })?;
            if erased_throws != declared {
                return Err("method signature throws erasures mismatch Exceptions".to_string());
            }
        }
        Ok(RecoveredMethodSignature {
            type_parameters: render_type_parameters(&signature.type_parameters)?,
            parameters: signature
                .parameters
                .iter()
                .map(render_java_type)
                .collect::<Result<Vec<String>, String>>()?,
            result: signature
                .result
                .as_ref()
                .map_or_else(|| Ok("void".to_string()), render_java_type)?,
            throws: rendered_throws,
            type_parameter_names: scope.parameters.keys().cloned().collect(),
            type_parameter_erasures: scope
                .parameters
                .keys()
                .map(|name: &String| {
                    let mut visiting: BTreeSet<String> = BTreeSet::new();
                    erase_type_variable(name, &scope, &mut visiting)
                        .map(|erasure: JavaType| (name.clone(), erasure.render()))
                })
                .collect::<Result<BTreeMap<String, String>, String>>()?,
        })
    })();
    match recovered {
        Ok(signature) => Some(signature),
        Err(reason) => {
            reject(cf, "method", &reason);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_signature_roots_with_full_consumption() -> Result<(), String> {
        let class: ParsedClassSignature = parse_class(
            "<T:Ljava/lang/Number;:Ljava/lang/Comparable<TT;>;>Ljava/lang/Object;Ljava/util/function/Supplier<TT;>;",
        )?;
        assert_eq!(class.type_parameters.len(), 1);
        assert_eq!(class.interfaces.len(), 1);

        let method: ParsedMethodSignature = parse_method(
            "<K::Ljava/lang/Comparable<-TK;>;V:Ljava/lang/Object;>(Ljava/util/Map<+TK;+TV;>;)Ljava/util/Map<TK;TV;>;^Ljava/io/IOException;",
        )?;
        assert_eq!(method.type_parameters.len(), 2);
        assert_eq!(method.parameters.len(), 1);
        assert_eq!(method.throws.len(), 1);

        let field: ReferenceTypeSignature = parse_field("Ljava/util/Map<Ljava/lang/String;-TT;>;")?;
        assert_eq!(
            render_reference(&field)?,
            "java.util.Map<String, ? super T>"
        );

        assert!(parse_field("Ljava/util/List<TT;>;!").is_err());
        assert!(parse_method("<>()V").is_err());
        assert!(parse_field("Ljava/util/List<>;").is_err());
        Ok(())
    }

    #[test]
    fn parses_parameterized_member_class_suffixes() -> Result<(), String> {
        let field: ReferenceTypeSignature = parse_field("Lpkg/Outer<TT;>.Inner<TU;>;")?;
        assert_eq!(render_reference(&field)?, "pkg.Outer<T>.Inner<U>");
        let erased: JavaType = erase_reference(
            &field,
            &TypeScope {
                parameters: BTreeMap::new(),
            },
            &mut BTreeSet::new(),
        )?;
        assert_eq!(erased, JavaType::Object("Lpkg/Outer$Inner;".to_string()));
        Ok(())
    }

    #[test]
    fn rejects_depth_and_type_variable_cycles() {
        let deep: String = format!("{}Ljava/lang/String;", "[".repeat(65));
        assert!(parse_field(&deep).is_err());
        let parameters: Vec<TypeParameter> = vec![
            TypeParameter {
                name: "T".to_string(),
                class_bound: Some(ReferenceTypeSignature::TypeVariable("U".to_string())),
                interface_bounds: Vec::new(),
            },
            TypeParameter {
                name: "U".to_string(),
                class_bound: Some(ReferenceTypeSignature::TypeVariable("T".to_string())),
                interface_bounds: Vec::new(),
            },
        ];
        assert!(build_scope(None, &parameters).is_err());
    }

    #[test]
    fn rejects_every_truncated_prefix_and_repeated_bound_erasure() -> Result<(), String> {
        let signature: &str = "Ljava/util/Map<Ljava/lang/String;+Ljava/util/List<[TT;>;>;";
        for end in 0..signature.len() {
            assert!(
                parse_field(&signature[..end]).is_err(),
                "accepted prefix {end}"
            );
        }
        assert!(parse_field(signature).is_ok());

        let bound: ReferenceTypeSignature = parse_field("Ljava/lang/Number;")?;
        let repeated: Vec<TypeParameter> = vec![TypeParameter {
            name: "T".to_string(),
            class_bound: Some(bound.clone()),
            interface_bounds: vec![bound],
        }];
        assert!(build_scope(None, &repeated).is_err());
        Ok(())
    }

    #[test]
    fn rejects_source_invalid_headers_and_throws_bounds() -> Result<(), String> {
        let parsed: ParsedClassSignature = parse_class("Ljava/util/ArrayList<*>;")?;
        let scope: TypeScope = build_scope(None, &parsed.type_parameters)?;
        assert!(validate_class_header_type(&parsed.superclass, &scope).is_err());

        assert!(!is_proven_throwable("java/lang/String"));
        assert!(is_proven_throwable("java/lang/Exception"));

        let invalid_parameters: Vec<TypeParameter> = vec![TypeParameter {
            name: "T".to_string(),
            class_bound: Some(parse_field("Ljava/lang/String;")?),
            interface_bounds: Vec::new(),
        }];
        let invalid_scope: TypeScope = build_scope(None, &invalid_parameters)?;
        assert!(throwable_type_variable_erasure("T", &invalid_scope).is_err());

        let valid_parameters: Vec<TypeParameter> = vec![TypeParameter {
            name: "T".to_string(),
            class_bound: Some(parse_field("Ljava/lang/Exception;")?),
            interface_bounds: Vec::new(),
        }];
        let valid_scope: TypeScope = build_scope(None, &valid_parameters)?;
        assert_eq!(
            throwable_type_variable_erasure("T", &valid_scope)?,
            "java/lang/Exception"
        );
        Ok(())
    }
}
