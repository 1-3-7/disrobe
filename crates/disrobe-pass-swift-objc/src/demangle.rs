use std::rc::Rc;

use crate::error::{Error, Result};

const MAX_DEPTH: usize = 1024;
const MAX_NODES: usize = 1 << 18;
const MAX_REPEAT_COUNT: u32 = 2048;
const MAX_SYMBOL_LEN: usize = 1 << 16;
const REABSTRACTION_THUNK_OPERATORS: [&[u8; 2]; 4] = [b"TR", b"Tr", b"Ty", b"TU"];

#[must_use]
pub fn looks_like_swift_mangled(s: &str) -> bool {
    s.starts_with("_$s")
        || s.starts_with("$s")
        || s.starts_with("_$S")
        || s.starts_with("$S")
        || s.starts_with("_T")
}

#[must_use]
pub fn contains_symbolic_reference(mangled: &str) -> bool {
    mangled.bytes().any(|b: u8| b < 0x20)
}

pub fn demangle(symbol: &str) -> Result<String> {
    if symbol.len() > MAX_SYMBOL_LEN {
        let truncated: String = symbol.chars().take(64).collect();
        return Err(Error::Demangle(format!(
            "{truncated}... ({} bytes, over the {MAX_SYMBOL_LEN}-byte bound)",
            symbol.len()
        )));
    }
    let trimmed: &str = symbol.strip_prefix('_').unwrap_or(symbol);
    let body: &str = trimmed
        .strip_prefix("$s")
        .or_else(|| trimmed.strip_prefix("$S"))
        .or_else(|| trimmed.strip_prefix("T0"))
        .ok_or_else(|| Error::Demangle(symbol.to_owned()))?;
    let mut dem: Demangler<'_> = Demangler::new(body);
    let node: NodeRef = dem
        .demangle_global()
        .ok_or_else(|| Error::Demangle(symbol.to_owned()))?;
    if dem.pos != dem.src.len() {
        return Err(Error::DemangleResidue {
            symbol: symbol.to_owned(),
            consumed: dem.pos,
            total: dem.src.len(),
        });
    }
    let rendered: String = print_node(&node, Mode::Symbol);
    if rendered.is_empty() || rendered.bytes().any(|b: u8| b < 0x20) {
        return Err(Error::Demangle(symbol.to_owned()));
    }
    Ok(rendered)
}

#[must_use]
pub fn demangle_type(mangled: &str) -> Option<String> {
    if mangled.is_empty() || mangled.len() > MAX_SYMBOL_LEN || contains_symbolic_reference(mangled)
    {
        return None;
    }
    let mut dem: Demangler<'_> = Demangler::new(mangled);
    let node: NodeRef = dem.demangle_type()?;
    if dem.pos != dem.src.len() {
        return None;
    }
    let rendered: String = print_node(&node, Mode::Type);
    if rendered.is_empty()
        || rendered == mangled
        || rendered.contains("<symbolic>")
        || rendered.bytes().any(|b: u8| b < 0x20)
    {
        None
    } else {
        Some(rendered)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Type,
    Symbol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Global,
    Module,
    Identifier,
    Class,
    Structure,
    Enum,
    Protocol,
    TypeAlias,
    OtherNominalType,
    BoundGenericClass,
    BoundGenericStructure,
    BoundGenericEnum,
    BoundGenericOther,
    Tuple,
    TupleElement,
    FunctionType,
    ImplFunctionType,
    ImplParameter,
    ImplResult,
    ImplYield,
    ImplErrorResult,
    ImplSendingResult,
    ImplPatternSubstitutions,
    ImplInvocationSubstitutions,
    TypeList,
    ArgumentTuple,
    ReturnType,
    Function,
    Variable,
    Allocator,
    Constructor,
    Destructor,
    Deallocator,
    Getter,
    Setter,
    ModifyAccessor,
    ReadAccessor,
    UnsafeAddressor,
    UnsafeMutableAddressor,
    MaterializeForSet,
    Subscript,
    Static,
    Optional,
    Array,
    Dictionary,
    Metatype,
    ExistentialMetatype,
    LabelList,
    DependentGenericParamType,
    DependentGenericSignature,
    DependentGenericParamCount,
    DependentGenericConformanceRequirement,
    DependentGenericSameTypeRequirement,
    DependentGenericLayoutRequirement,
    DependentMemberType,
    InOut,
    Shared,
    Owned,
    DependentAssociatedType,
    AssociatedTypeDescriptor,
    DispatchThunk,
    AnyObjectExistential,
    ExtensionContext,
    BaseConformanceDescriptor,
    AssociatedConformanceDescriptor,
    EnumCase,
    ProtocolConformanceDescriptorExt,
    ConformanceWithGenericSig,
    ProtocolWitnessTableConformance,
    ProtocolWitnessTablePatternConformance,
    TypeMetadata,
    FullTypeMetadata,
    TypeMetadataAccessFunction,
    NominalTypeDescriptor,
    Metaclass,
    ClassMetadataBaseOffset,
    ProtocolDescriptor,
    ProtocolRequirementsBaseDescriptor,
    ProtocolConformanceDescriptor,
    ProtocolWitnessTable,
    ValueWitnessTable,
    ReflectionMetadataFieldDescriptor,
    FieldOffset,
    MethodDescriptor,
    ModuleDescriptor,
    GenericTypeMetadataPattern,
    ProtocolWitnessTablePattern,
    ThrowsAnnotation,
    AsyncAnnotation,
    ConventionAnnotation,
    ValueWitness,
    ProtocolSelfConformanceWitnessTable,
    PropertyDescriptor,
    GenericSpecialization,
    IsolatedAnyAnnotation,
    GlobalActorAnnotation,
    NonisolatedCallerAnnotation,
    TypedThrowsAnnotation,
    SendingResultAnnotation,
    Isolated,
    Sending,
    Variadic,
    OpaqueReturnType,
    MacroExpansion,
    AsyncFunctionPointer,
    MergedFunction,
    PackExpansion,
    Pack,
    DependentGenericParamPackMarker,
    SendableAnnotation,
    AsyncResumePartialFunction,
    OpaqueTypeDescriptor,
    TypeMetadataInstantiationCache,
    TypeMetadataInstantiationFunction,
    TypeMetadataCompletionFunction,
    TypeMetadataSingletonInitializationCache,
    OutlinedInitWithCopy,
    OutlinedDestroy,
    DefaultArgumentInitializer,
    VariableInitializationExpression,
    OneTimeInitializationFunction,
    OneTimeInitializationToken,
    MetadataInstantiationCache,
    ProtocolConformanceContext,
    ProtocolWitnessThunk,
    PartialApplyForwarder,
    ReabstractionThunk,
    ReabstractionThunkHelper,
    ReabstractionThunkHelperWithSelf,
    ReabstractionThunkHelperWithGlobalActor,
    KeyPathThunk,
    LazyWitnessTableCacheVariable,
    LazyWitnessTableAccessor,
    DistributedThunk,
    DistributedAccessor,
    ObjCAttribute,
    NonObjCAttribute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SpecializationParam {
    Unmodified,
    Effects(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FunctionConvention {
    Swift,
    C,
    Block,
    Autoclosure,
}

#[derive(Debug, Clone)]
enum ImplPreamble {
    Type(NodeRef),
    Signature(NodeRef),
    Separator,
}

#[derive(Debug, Clone)]
enum ParsedImplFunctionConvention {
    Absent,
    Present(String),
}

impl FunctionConvention {
    const fn annotation(self) -> Option<&'static str> {
        match self {
            Self::Swift => None,
            Self::C => Some("@convention(c) "),
            Self::Block => Some("@convention(block) "),
            Self::Autoclosure => Some("@autoclosure "),
        }
    }
}

#[derive(Debug, Clone)]
struct Node {
    kind: Kind,
    text: Option<String>,
    children: Vec<NodeRef>,
}

type NodeRef = Rc<Node>;

#[derive(Debug, Clone)]
struct Checkpoint {
    pos: usize,
    subs: usize,
    words: usize,
    depth: usize,
    pending: Vec<NodeRef>,
}

impl Node {
    fn leaf(kind: Kind, text: String) -> NodeRef {
        Rc::new(Self {
            kind,
            text: Some(text),
            children: Vec::new(),
        })
    }

    fn branch(kind: Kind, children: Vec<NodeRef>) -> NodeRef {
        Rc::new(Self {
            kind,
            text: None,
            children,
        })
    }

    fn unary(kind: Kind, child: NodeRef) -> NodeRef {
        Rc::new(Self {
            kind,
            text: None,
            children: vec![child],
        })
    }

    fn branch_with_text(kind: Kind, text: String, children: Vec<NodeRef>) -> NodeRef {
        Rc::new(Self {
            kind,
            text: Some(text),
            children,
        })
    }

    fn with_kind(&self, kind: Kind) -> NodeRef {
        Rc::new(Self {
            kind,
            text: self.text.clone(),
            children: self.children.clone(),
        })
    }
}

struct Demangler<'a> {
    src: &'a [u8],
    pos: usize,
    substitutions: Vec<NodeRef>,
    words: Vec<String>,
    depth: usize,
    node_budget: usize,
    suppress_tuple: bool,
    suppress_function_suffix: bool,
    suppress_result_function: bool,
    pending_substitutions: Vec<NodeRef>,
}

impl<'a> Demangler<'a> {
    const fn new(s: &'a str) -> Self {
        Self {
            src: s.as_bytes(),
            pos: 0,
            substitutions: Vec::new(),
            words: Vec::new(),
            depth: 0,
            node_budget: MAX_NODES,
            suppress_tuple: false,
            suppress_function_suffix: false,
            suppress_result_function: false,
            pending_substitutions: Vec::new(),
        }
    }

    fn spend(&mut self) -> Option<()> {
        self.node_budget = self.node_budget.checked_sub(1)?;
        Some(())
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.src.get(self.pos + ahead).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b: Option<u8> = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn next_if(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn add_substitution(&mut self, node: &NodeRef) {
        self.substitutions.push(Rc::clone(node));
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            pos: self.pos,
            subs: self.substitutions.len(),
            words: self.words.len(),
            depth: self.depth,
            pending: self.pending_substitutions.clone(),
        }
    }

    fn restore(&mut self, cp: Checkpoint) {
        self.pos = cp.pos;
        self.substitutions.truncate(cp.subs);
        self.words.truncate(cp.words);
        self.depth = cp.depth;
        self.pending_substitutions = cp.pending;
    }

    fn demangle_global(&mut self) -> Option<NodeRef> {
        let node: NodeRef = self.demangle_global_inner()?;
        Some(Node::unary(Kind::Global, node))
    }

    fn demangle_global_inner(&mut self) -> Option<NodeRef> {
        if self.ends_with_reabstraction_thunk_operator()
            && let Some(thunk) = self.try_demangle_reabstraction_thunk()
        {
            return Some(thunk);
        }
        if let Some(descriptor) = self.try_demangle_assoc_type_descriptor() {
            return Some(descriptor);
        }
        if let Some(descriptor) = self.try_demangle_associated_conformance_descriptor() {
            return Some(descriptor);
        }
        let entity: NodeRef = self.demangle_entity_or_type()?;
        let entity: NodeRef = self.demangle_trailing_entity_spec(entity)?;
        self.demangle_operator_suffix(entity)
    }

    fn ends_with_reabstraction_thunk_operator(&self) -> bool {
        REABSTRACTION_THUNK_OPERATORS
            .iter()
            .any(|operator: &&[u8; 2]| self.src.ends_with(operator.as_slice()))
    }

    fn try_demangle_reabstraction_thunk(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let parsed: Option<NodeRef> = (|| {
            let from: NodeRef = self.demangle_impl_function_type()?;
            let to: NodeRef = self.demangle_impl_function_type()?;
            let generic_signature: Option<NodeRef> = if self.peek() == Some(b'T') {
                None
            } else {
                self.try_demangle_generic_signature_node()
            };
            let self_type: Option<NodeRef> = if self.peek() == Some(b'T') {
                None
            } else {
                Some(self.demangle_type()?)
            };
            if !self.next_if(b'T') {
                return None;
            }
            let kind: Kind = match self.next()? {
                b'R' if self_type.is_none() => Kind::ReabstractionThunkHelper,
                b'r' if self_type.is_none() => Kind::ReabstractionThunk,
                b'y' if self_type.is_some() => Kind::ReabstractionThunkHelperWithSelf,
                _ => return None,
            };
            let mut children: Vec<NodeRef> = Vec::with_capacity(4);
            children.extend(generic_signature);
            children.push(from);
            children.push(to);
            children.extend(self_type);
            let thunk: NodeRef = Node::branch(kind, children);
            if self.pos == self.src.len() {
                return Some(thunk);
            }
            let global_actor: NodeRef = self.demangle_type()?;
            if !(self.next_if(b'T') && self.next_if(b'U') && self.pos == self.src.len()) {
                return None;
            }
            Some(Node::branch(
                Kind::ReabstractionThunkHelperWithGlobalActor,
                vec![thunk, global_actor],
            ))
        })();
        if parsed.is_none() {
            self.restore(cp);
        }
        parsed
    }

    fn demangle_impl_function_type(&mut self) -> Option<NodeRef> {
        let mut preamble: Vec<ImplPreamble> = Vec::new();
        while self.peek() != Some(b'I') || !self.pending_substitutions.is_empty() {
            self.spend()?;
            if let Some(signature) = self.try_demangle_generic_signature_node() {
                preamble.push(ImplPreamble::Signature(signature));
            } else if let Some(ty) = self.try_demangle_type_node() {
                preamble.push(ImplPreamble::Type(ty));
            } else if self.next_if(b'y') {
                preamble.push(ImplPreamble::Separator);
            } else {
                return None;
            }
            if preamble.len() > MAX_DEPTH {
                return None;
            }
        }
        self.pos += 1;
        let has_pattern_substitutions: bool = self.next_if(b's');
        let has_invocation_substitutions: bool = self.next_if(b'I');
        let pattern_substitutions: Option<Vec<NodeRef>> = if has_pattern_substitutions {
            Some(Self::take_impl_substitutions(&mut preamble)?)
        } else {
            None
        };
        let pattern_signature: Option<NodeRef> = if has_pattern_substitutions {
            match preamble.pop()? {
                ImplPreamble::Signature(signature) => Some(signature),
                ImplPreamble::Type(_) | ImplPreamble::Separator => return None,
            }
        } else {
            None
        };
        let invocation_substitutions: Option<Vec<NodeRef>> = if has_invocation_substitutions {
            Some(Self::take_impl_substitutions(&mut preamble)?)
        } else {
            None
        };
        let generic_signature: Option<NodeRef> = match preamble.last() {
            Some(ImplPreamble::Signature(_)) => match preamble.pop()? {
                ImplPreamble::Signature(signature) => Some(signature),
                ImplPreamble::Type(_) | ImplPreamble::Separator => return None,
            },
            Some(ImplPreamble::Type(_) | ImplPreamble::Separator) | None => None,
        };
        if self.next_if(b'P') && generic_signature.is_none() {
            return None;
        }
        let mut types: Vec<NodeRef> = Vec::with_capacity(preamble.len());
        for item in preamble {
            match item {
                ImplPreamble::Type(ty) => types.push(ty),
                ImplPreamble::Signature(_) | ImplPreamble::Separator => return None,
            }
        }
        let mut attributes: Vec<String> = Vec::new();
        if self.next_if(b'e') {
            attributes.push("@escaping".to_owned());
        }
        if self.next_if(b'A') {
            attributes.push("@isolated(any)".to_owned());
        }
        let differentiability: Option<&'static str> = match self.peek() {
            Some(b'd') => Some("@differentiable"),
            Some(b'l') => Some("@differentiable(_linear)"),
            Some(b'f') => Some("@differentiable(_forward)"),
            Some(b'r') => Some("@differentiable(reverse)"),
            _ => None,
        };
        if let Some(differentiability) = differentiability {
            self.pos += 1;
            attributes.push(differentiability.to_owned());
        }
        let callee: &'static str = match self.next()? {
            b'y' => "@callee_unowned",
            b'g' => "@callee_guaranteed",
            b'x' => "@callee_owned",
            b't' => "@convention(thin)",
            _ => return None,
        };
        attributes.push(callee.to_owned());
        match self.demangle_impl_function_convention()? {
            ParsedImplFunctionConvention::Present(function_convention) => {
                attributes.push(function_convention);
            }
            ParsedImplFunctionConvention::Absent => {}
        }
        let coroutine: Option<&'static str> = match self.peek() {
            Some(b'A') => Some("@yield_once"),
            Some(b'I') => Some("@yield_once_2"),
            Some(b'G') => Some("@yield_many"),
            _ => None,
        };
        if let Some(coroutine) = coroutine {
            self.pos += 1;
            attributes.push(coroutine.to_owned());
        }
        if self.next_if(b'h') {
            attributes.push("@Sendable".to_owned());
        }
        if self.next_if(b'H') {
            attributes.push("@async".to_owned());
        }
        let sending_result: bool = self.next_if(b'T');
        let mut conventions: Vec<(Kind, String)> = Vec::new();
        while let Some(convention) = self.demangle_impl_parameter_convention() {
            let no_derivative: bool = self.next_if(b'w');
            let mut modifiers: Vec<&'static str> = Vec::new();
            if self.next_if(b'T') {
                modifiers.push("sending");
            }
            if self.next_if(b'I') {
                modifiers.push("isolated");
            }
            if self.next_if(b'L') {
                modifiers.push("sil_implicit_leading_param");
            }
            let rendered_modifiers: Vec<&str> = if modifiers.len() <= 1 {
                no_derivative
                    .then_some("@noDerivative")
                    .into_iter()
                    .chain(modifiers)
                    .collect()
            } else {
                Vec::new()
            };
            let text: String = std::iter::once(convention)
                .chain(rendered_modifiers)
                .collect::<Vec<&str>>()
                .join(" ");
            conventions.push((Kind::ImplParameter, text));
        }
        while let Some(convention) = self.demangle_impl_result_convention() {
            let differentiability: &str = if self.next_if(b'w') {
                " @noDerivative"
            } else {
                ""
            };
            conventions.push((Kind::ImplResult, format!("{convention}{differentiability}")));
        }
        while self.next_if(b'Y') {
            let convention: &'static str = self.demangle_impl_parameter_convention()?;
            conventions.push((Kind::ImplYield, convention.to_owned()));
        }
        if self.next_if(b'z') {
            let convention: &'static str = self.demangle_impl_result_convention()?;
            conventions.push((Kind::ImplErrorResult, convention.to_owned()));
        }
        if !self.next_if(b'_') || conventions.len() != types.len() {
            return None;
        }
        let mut children: Vec<NodeRef> = Vec::with_capacity(types.len() + 4);
        if let (Some(signature), Some(substitutions)) = (pattern_signature, pattern_substitutions) {
            children.push(Node::branch(
                Kind::ImplPatternSubstitutions,
                vec![signature, Node::branch(Kind::TypeList, substitutions)],
            ));
        }
        if let Some(substitutions) = invocation_substitutions {
            children.push(Node::unary(
                Kind::ImplInvocationSubstitutions,
                Node::branch(Kind::TypeList, substitutions),
            ));
        }
        children.extend(generic_signature);
        if sending_result {
            children.push(Node::branch(Kind::ImplSendingResult, Vec::new()));
        }
        for ((kind, convention), ty) in conventions.into_iter().zip(types) {
            children.push(Node::branch_with_text(kind, convention, vec![ty]));
        }
        Some(Node::branch_with_text(
            Kind::ImplFunctionType,
            attributes.join(" "),
            children,
        ))
    }

    fn try_demangle_generic_signature_node(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let depth: usize = self.depth;
        let parsed: Option<NodeRef> = self.demangle_generic_signature();
        self.depth = depth;
        if parsed.is_none() {
            self.restore(cp);
        }
        parsed
    }

    fn try_demangle_type_node(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let parsed: Option<NodeRef> = self.demangle_type();
        if parsed.is_none() {
            self.restore(cp);
        }
        parsed
    }

    fn take_impl_substitutions(preamble: &mut Vec<ImplPreamble>) -> Option<Vec<NodeRef>> {
        let separator: usize = preamble
            .iter()
            .rposition(|item: &ImplPreamble| matches!(item, ImplPreamble::Separator))?;
        let tail: Vec<ImplPreamble> = preamble.split_off(separator + 1);
        match preamble.pop()? {
            ImplPreamble::Separator => {}
            ImplPreamble::Type(_) | ImplPreamble::Signature(_) => return None,
        }
        tail.into_iter()
            .map(|item: ImplPreamble| match item {
                ImplPreamble::Type(ty) => Some(ty),
                ImplPreamble::Signature(_) | ImplPreamble::Separator => None,
            })
            .collect()
    }

    fn demangle_impl_function_convention(&mut self) -> Option<ParsedImplFunctionConvention> {
        let convention: Option<String> = match self.peek() {
            Some(b'B') => Some("@convention(block)".to_owned()),
            Some(b'C') => Some("@convention(c)".to_owned()),
            Some(b'M') => Some("@convention(method)".to_owned()),
            Some(b'O') => Some("@convention(objc_method)".to_owned()),
            Some(b'K') => Some("@convention(closure)".to_owned()),
            Some(b'W') => Some("@convention(witness_method)".to_owned()),
            Some(b'z') if matches!(self.peek_at(1), Some(b'B' | b'C')) => {
                self.pos += 1;
                let name: &'static str = match self.next()? {
                    b'B' => "block",
                    b'C' => "c",
                    _ => return None,
                };
                let length_start: usize = self.pos;
                let length: usize = usize::try_from(self.demangle_natural()).ok()?;
                if length == 0 || self.pos == length_start {
                    return None;
                }
                let end: usize = self.pos.checked_add(length)?;
                let encoded: &str = std::str::from_utf8(self.src.get(self.pos..end)?).ok()?;
                self.pos = end;
                return Some(ParsedImplFunctionConvention::Present(format!(
                    "@convention({name}, mangledCType: \"{encoded}\")"
                )));
            }
            _ => None,
        };
        if convention.is_some() {
            self.pos += 1;
        }
        Some(convention.map_or(
            ParsedImplFunctionConvention::Absent,
            ParsedImplFunctionConvention::Present,
        ))
    }

    fn demangle_impl_parameter_convention(&mut self) -> Option<&'static str> {
        let convention: &'static str = match self.peek()? {
            b'i' => "@in",
            b'c' => "@in_constant",
            b'l' => "@inout",
            b'b' => "@inout_aliasable",
            b'n' => "@in_guaranteed",
            b'X' => "@in_cxx",
            b'x' => "@owned",
            b'y' => "@unowned",
            b'g' => "@guaranteed",
            b'e' => "@deallocating",
            b'v' => "@pack_owned",
            b'p' => "@pack_guaranteed",
            b'm' => "@pack_inout",
            _ => return None,
        };
        self.pos += 1;
        Some(convention)
    }

    fn demangle_impl_result_convention(&mut self) -> Option<&'static str> {
        let convention: &'static str = match self.peek()? {
            b'r' => "@out",
            b'o' => "@owned",
            b'd' => "@unowned",
            b'u' => "@unowned_inner_pointer",
            b'a' => "@autoreleased",
            b'k' => "@pack_out",
            b'l' => "@guaranteed_address",
            b'g' => "@guaranteed",
            b'm' => "@inout",
            _ => return None,
        };
        self.pos += 1;
        Some(convention)
    }

    fn try_demangle_assoc_type_descriptor(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(node) = self.demangle_assoc_type_descriptor_inner() {
            return Some(node);
        }
        self.restore(cp);
        None
    }

    fn try_demangle_associated_conformance_descriptor(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(node) = self.demangle_associated_conformance_inner() {
            return Some(node);
        }
        self.restore(cp);
        None
    }

    fn demangle_associated_conformance_inner(&mut self) -> Option<NodeRef> {
        let conforming: NodeRef = self.demangle_protocol_type()?;
        let assoc_name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
        let base_proto: NodeRef = self.demangle_protocol_type()?;
        if !self.next_if(b'_') {
            return None;
        }
        let requirement: NodeRef = self.demangle_protocol_type()?;
        if !(self.next_if(b'T') && self.next_if(b'n')) {
            return None;
        }
        if self.pos != self.src.len() {
            return None;
        }
        let assoc_ref: NodeRef =
            Node::branch(Kind::DependentAssociatedType, vec![base_proto, assoc_name]);
        Some(Node::branch(
            Kind::AssociatedConformanceDescriptor,
            vec![conforming, assoc_ref, requirement],
        ))
    }

    fn demangle_assoc_type_descriptor_inner(&mut self) -> Option<NodeRef> {
        let assoc_name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
        let protocol: NodeRef = self.demangle_assoc_descriptor_protocol()?;
        if !(self.next_if(b'T') && self.next_if(b'l')) {
            return None;
        }
        if self.pos != self.src.len() {
            return None;
        }
        Some(Node::branch(
            Kind::AssociatedTypeDescriptor,
            vec![assoc_name, protocol],
        ))
    }

    fn demangle_assoc_descriptor_protocol(&mut self) -> Option<NodeRef> {
        match self.peek()? {
            b'S' => {
                self.pos += 1;
                let letter: u8 = self.next()?;
                let (module, name, _): (&str, &str, Kind) = standard_substitution(letter)?;
                Some(Node::branch(
                    Kind::OtherNominalType,
                    vec![
                        Node::leaf(Kind::Module, module.to_owned()),
                        Node::leaf(Kind::Identifier, name.to_owned()),
                    ],
                ))
            }
            b's' => {
                self.pos += 1;
                let module: NodeRef = Node::leaf(Kind::Module, "Swift".to_owned());
                self.demangle_protocol_in_context(module)
            }
            c if c.is_ascii_digit() => {
                let module: NodeRef = self.demangle_identifier(Kind::Module)?;
                self.demangle_protocol_in_context(module)
            }
            _ => None,
        }
    }

    fn demangle_trailing_entity_spec(&mut self, context: NodeRef) -> Option<NodeRef> {
        if !is_context_kind(context.kind) {
            if is_conformance_subject_kind(context.kind) {
                if let Some(conf) = self.try_demangle_conformance_descriptor(&context) {
                    return Some(conf);
                }
                if let Some(wtable) = self.try_demangle_protocol_conformance_record(&context) {
                    return Some(wtable);
                }
                if let Some(witness) = self.try_demangle_protocol_witness_context(&context) {
                    return Some(witness);
                }
                if let Some(lazy) = self.try_demangle_lazy_witness_accessor(&context) {
                    return Some(lazy);
                }
            }
            return Some(context);
        }
        if context.kind == Kind::Protocol
            && let Some(base_conf) = self.try_demangle_base_conformance(&context)
        {
            return Some(base_conf);
        }
        if let Some(conf) = self.try_demangle_conformance_descriptor(&context) {
            return Some(conf);
        }
        if let Some(wtable) = self.try_demangle_protocol_conformance_record(&context) {
            return Some(wtable);
        }
        if let Some(witness) = self.try_demangle_protocol_witness_context(&context) {
            return Some(witness);
        }
        if let Some(lazy) = self.try_demangle_lazy_witness_accessor(&context) {
            return Some(lazy);
        }
        match self.peek() {
            Some(b'f') => {
                self.pos += 1;
                self.demangle_destructor_or_init(context)
            }
            Some(c) if c.is_ascii_digit() => {
                if let Some(node) = self.try_demangle_extension_then_entity(&context) {
                    return Some(node);
                }
                if let Some(node) = self.try_demangle_anonymous_entity(&context) {
                    return Some(node);
                }
                let name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
                Some(self.demangle_named_entity_spec(context, name))
            }
            Some(b'y' | b'_' | b'A' | b'S' | b's' | b'x' | b'q' | b'B') => {
                if let Some(node) = self.try_demangle_extension_then_entity(&context) {
                    return Some(node);
                }
                if let Some(node) = self.try_demangle_anonymous_entity(&context) {
                    return Some(node);
                }
                if let Some(node) = self.try_demangle_bound_generic_subject(&context) {
                    return Some(node);
                }
                Some(context)
            }
            _ => Some(context),
        }
    }

    fn try_demangle_bound_generic_subject(&mut self, context: &NodeRef) -> Option<NodeRef> {
        if self.peek() != Some(b'y') || !is_conformance_subject_kind(context.kind) {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        let Some(bound): Option<NodeRef> = self.apply_type_suffixes(context.clone()) else {
            self.restore(cp);
            return None;
        };
        if self.pos == cp.pos {
            self.restore(cp);
            return None;
        }
        if let Some(conf) = self.try_demangle_conformance_descriptor(&bound) {
            return Some(conf);
        }
        if let Some(wtable) = self.try_demangle_protocol_conformance_record(&bound) {
            return Some(wtable);
        }
        if let Some(witness) = self.try_demangle_protocol_witness_context(&bound) {
            return Some(witness);
        }
        let after_bound: Checkpoint = self.checkpoint();
        let _: Option<NodeRef> = self.try_demangle_trailing_generic_signature();
        if self.peek() == Some(b'W') && self.peek_at(1) == Some(b'O') {
            return Some(bound);
        }
        self.restore(after_bound);
        self.restore(cp);
        None
    }

    fn try_demangle_extension_then_entity(&mut self, base: &NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(node) = self.demangle_extension_then_entity_inner(base) {
            return Some(node);
        }
        self.restore(cp);
        None
    }

    fn demangle_extension_then_entity_inner(&mut self, base: &NodeRef) -> Option<NodeRef> {
        let module: NodeRef = match self.peek()? {
            b'A' => self.demangle_substitution()?,
            b's' => {
                self.pos += 1;
                Node::leaf(Kind::Module, "Swift".to_owned())
            }
            c if c.is_ascii_digit() => {
                let module: NodeRef = self.demangle_identifier(Kind::Module)?;
                self.add_substitution(&module);
                module
            }
            _ => return None,
        };
        let generic_sig: Option<NodeRef> = self.try_demangle_extension_generic_signature();
        if !self.next_if(b'E') {
            return None;
        }
        let mut children: Vec<NodeRef> = vec![module, base.clone()];
        if let Some(sig) = generic_sig {
            children.push(sig);
        }
        let extension: NodeRef = Node::branch(Kind::ExtensionContext, children);
        Some(
            self.demangle_trailing_entity_spec(extension.clone())
                .unwrap_or(extension),
        )
    }

    fn try_demangle_extension_generic_signature(&mut self) -> Option<NodeRef> {
        if self.peek() == Some(b'E') {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        match self.demangle_generic_signature() {
            Some(sig) if self.peek() == Some(b'E') => Some(sig),
            _ => {
                self.restore(cp);
                None
            }
        }
    }

    fn try_demangle_anonymous_entity(&mut self, context: &NodeRef) -> Option<NodeRef> {
        if let Some(node) = self.try_demangle_subscript(context) {
            return Some(node);
        }
        let cp: Checkpoint = self.checkpoint();
        let labels: Option<NodeRef> = self.demangle_label_list();
        if let Some(sig) = self.try_demangle_init_signature() {
            let generic: Option<NodeRef> = self.try_demangle_trailing_generic_signature();
            if self.next_if(b'f') {
                let init: NodeRef = match self.next() {
                    Some(b'C') => build_init(Kind::Allocator, context.clone(), Some(sig), labels),
                    Some(b'c') => build_init(Kind::Constructor, context.clone(), Some(sig), labels),
                    _ => {
                        self.restore(cp);
                        return None;
                    }
                };
                let with_generic: NodeRef = attach_generic(init, generic);
                return Some(with_generic);
            }
        }
        self.restore(cp);
        None
    }

    fn try_demangle_init_signature(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let result: NodeRef = self.demangle_result_type_no_funckind()?;
        let params: NodeRef = self.demangle_params()?;
        let annotations: Vec<NodeRef> = self.consume_function_annotations();
        if !self.next_if(b'c') {
            self.restore(cp);
            return None;
        }
        let mut children: Vec<NodeRef> = vec![
            Node::unary(Kind::ArgumentTuple, params),
            Node::unary(Kind::ReturnType, result),
        ];
        children.extend(annotations);
        Some(Node::branch(Kind::FunctionType, children))
    }

    fn consume_function_annotations(&mut self) -> Vec<NodeRef> {
        let mut annotations: Vec<NodeRef> = Vec::new();
        loop {
            if self.next_if(b'K') {
                annotations.push(Node::leaf(Kind::ThrowsAnnotation, "throws".to_owned()));
                continue;
            }
            if self.peek() == Some(b'Y') {
                match self.peek_at(1) {
                    Some(b'a') => {
                        self.pos += 2;
                        annotations.push(Node::leaf(Kind::AsyncAnnotation, "async".to_owned()));
                        continue;
                    }
                    Some(b'b') => {
                        self.pos += 2;
                        annotations.push(Node::branch(Kind::SendableAnnotation, Vec::new()));
                        continue;
                    }
                    Some(b'A') => {
                        self.pos += 2;
                        annotations.push(Node::branch(Kind::IsolatedAnyAnnotation, Vec::new()));
                        continue;
                    }
                    Some(b'C') => {
                        self.pos += 2;
                        annotations
                            .push(Node::branch(Kind::NonisolatedCallerAnnotation, Vec::new()));
                        continue;
                    }
                    Some(b'T') => {
                        self.pos += 2;
                        annotations.push(Node::branch(Kind::SendingResultAnnotation, Vec::new()));
                        continue;
                    }
                    _ => {}
                }
            }
            match self.try_demangle_type_prefixed_function_annotation() {
                Some(node) => annotations.push(node),
                None => break,
            }
        }
        annotations
    }

    fn try_demangle_type_prefixed_function_annotation(&mut self) -> Option<NodeRef> {
        if !self
            .src
            .get(self.pos..)
            .is_some_and(|rest: &[u8]| rest.windows(2).any(|w: &[u8]| w == b"Yc" || w == b"YK"))
        {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        let ty: NodeRef = self.try_demangle_type()?;
        if self.peek() != Some(b'Y') {
            self.restore(cp);
            return None;
        }
        match self.peek_at(1) {
            Some(b'c') => {
                self.pos += 2;
                Some(Node::unary(Kind::GlobalActorAnnotation, ty))
            }
            Some(b'K') => {
                self.pos += 2;
                Some(Node::unary(Kind::TypedThrowsAnnotation, ty))
            }
            _ => {
                self.restore(cp);
                None
            }
        }
    }

    fn demangle_result_type_no_funckind(&mut self) -> Option<NodeRef> {
        let restore: bool = self.suppress_function_suffix;
        let restore_result: bool = self.suppress_result_function;
        self.suppress_function_suffix = true;
        self.suppress_result_function = true;
        let result: Option<NodeRef> = self.try_demangle_type();
        self.suppress_function_suffix = restore;
        self.suppress_result_function = restore_result;
        result
    }

    fn demangle_named_entity_spec(&mut self, context: NodeRef, name: NodeRef) -> NodeRef {
        self.add_substitution(&name);
        let name: NodeRef = self.maybe_operator_name(name);
        if let Some(node) = self.try_demangle_macro_expansion(&context, &name) {
            return node;
        }
        let name: NodeRef = self.consume_private_discriminator(name);
        if let Some(c) = self.peek()
            && matches!(c, b'C' | b'V' | b'O' | b'a')
        {
            let parent_with_name: NodeRef =
                Node::branch(Kind::OtherNominalType, vec![context, name]);
            let nominal: NodeRef = self.finish_nominal_named(parent_with_name, c);
            return self
                .demangle_trailing_entity_spec(nominal.clone())
                .unwrap_or(nominal);
        }
        if self.peek() == Some(b'P') {
            self.pos += 1;
            let parent_with_name: NodeRef =
                Node::branch(Kind::OtherNominalType, vec![context, name]);
            let node: NodeRef = Node::unary(Kind::Protocol, parent_with_name);
            self.add_substitution(&node);
            return node;
        }
        if self.peek() == Some(b'_') && self.peek_at(1) == Some(b'p') {
            self.pos += 2;
            let parent_with_name: NodeRef =
                Node::branch(Kind::OtherNominalType, vec![context, name]);
            let node: NodeRef = Node::unary(Kind::Protocol, parent_with_name);
            self.add_substitution(&node);
            return node;
        }
        if self.peek() == Some(b'_') {
            let underscore_cp: Checkpoint = self.checkpoint();
            self.pos += 1;
            if let Some(node) = self.demangle_one_time_init(name.clone()) {
                return node;
            }
            self.restore(underscore_cp);
        }
        let cp: Checkpoint = self.checkpoint();
        if let Some(node) = self.try_demangle_storage_entity(&context, &name) {
            return node;
        }
        self.restore(cp);
        if matches!(
            self.peek(),
            Some(b'M' | b'N' | b'W' | b'H' | b'T' | b'w') | None
        ) {
            return Node::branch(Kind::OtherNominalType, vec![context, name]);
        }
        let (labels, signature, generic_sig): (Option<NodeRef>, Option<NodeRef>, Option<NodeRef>) =
            self.demangle_function_body();
        let is_static: bool = self.consume_function_terminator();
        let func: NodeRef = build_function(context, name, labels, signature, generic_sig);
        if is_static {
            Node::unary(Kind::Static, func)
        } else {
            func
        }
    }

    fn try_demangle_macro_expansion(
        &mut self,
        context: &NodeRef,
        attached_name: &NodeRef,
    ) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(node) = self.demangle_macro_expansion_inner(context, attached_name) {
            return Some(node);
        }
        self.restore(cp);
        None
    }

    fn demangle_macro_expansion_inner(
        &mut self,
        context: &NodeRef,
        attached_name: &NodeRef,
    ) -> Option<NodeRef> {
        let macro_name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
        if !(self.next_if(b'f') && self.next_if(b'M')) {
            return None;
        }
        let role: &'static str = match self.next() {
            Some(b'a') => "accessor",
            Some(b'r') => "memberAttribute",
            Some(b'm') => "member",
            Some(b'p') => "peer",
            Some(b'c') => "conformance",
            Some(b'e') => "extension",
            Some(b'q') => "preamble",
            Some(b'b') => "body",
            _ => return None,
        };
        let discriminator: u32 = self.demangle_index()?;
        Some(Node::branch_with_text(
            Kind::MacroExpansion,
            role.to_owned(),
            vec![
                context.clone(),
                attached_name.clone(),
                macro_name,
                Node::leaf(
                    Kind::Identifier,
                    discriminator.saturating_add(1).to_string(),
                ),
            ],
        ))
    }

    fn consume_function_terminator(&mut self) -> bool {
        let mut is_static: bool = self.next_if(b'Z');
        self.next_if(b'F');
        if !is_static {
            is_static = self.next_if(b'Z');
        }
        is_static
    }

    fn try_demangle_storage_entity(
        &mut self,
        context: &NodeRef,
        name: &NodeRef,
    ) -> Option<NodeRef> {
        let base: Checkpoint = self.checkpoint();
        if let Some(ty) = self.try_demangle_type()
            && self.peek() == Some(b'v')
        {
            self.pos += 1;
            return Some(self.demangle_variable(context.clone(), name.clone(), Some(ty)));
        }
        self.restore(base);
        let _labels: Option<NodeRef> = self.demangle_label_list();
        let ty: NodeRef = self.try_demangle_type()?;
        match self.peek() {
            Some(b'v') => {
                self.pos += 1;
                Some(self.demangle_variable(context.clone(), name.clone(), Some(ty)))
            }
            _ => None,
        }
    }

    fn demangle_destructor_or_init(&mut self, context: NodeRef) -> Option<NodeRef> {
        let c: u8 = self.next()?;
        match c {
            b'D' | b'Z' => Some(Node::unary(Kind::Deallocator, context)),
            b'd' | b'E' | b'e' => Some(Node::unary(Kind::Destructor, context)),
            _ => None,
        }
    }

    fn demangle_operator_suffix(&mut self, base: NodeRef) -> Option<NodeRef> {
        let mut node: NodeRef = base;
        loop {
            self.depth = self.depth.checked_add(1)?;
            if self.depth > MAX_DEPTH {
                return None;
            }
            let Some(c): Option<u8> = self.peek() else {
                return Some(node);
            };
            let cp: Checkpoint = self.checkpoint();
            let consumed: Option<NodeRef> = match c {
                b'N' => {
                    self.pos += 1;
                    Some(Node::unary(Kind::TypeMetadata, node.clone()))
                }
                b'M' => {
                    self.pos += 1;
                    self.demangle_metadata(node.clone())
                }
                b'W' => {
                    self.pos += 1;
                    self.demangle_witness(node.clone())
                }
                b'T' => {
                    self.pos += 1;
                    self.demangle_thunk(node.clone())
                }
                b'H' => {
                    self.pos += 1;
                    Some(self.demangle_runtime_record(node.clone()))
                }
                b'w' => {
                    self.pos += 1;
                    self.demangle_value_witness(node.clone())
                }
                b'Q' => {
                    self.pos += 1;
                    self.demangle_opaque_type_marker(node.clone())
                }
                b'f' => {
                    self.pos += 1;
                    self.demangle_related_entity(node.clone())
                }
                _ => self
                    .try_demangle_specialization(&node)
                    .or_else(|| self.try_demangle_keypath_thunk(&node)),
            };
            let Some(next): Option<NodeRef> = consumed else {
                self.restore(cp);
                return Some(node);
            };
            node = next;
        }
    }

    fn try_demangle_specialization(&mut self, base: &NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let mut params: Vec<NodeRef> = Vec::new();
        while let Some(ty) = self.try_demangle_type() {
            params.push(ty);
            if !self.next_if(b'_') {
                break;
            }
        }
        if params.is_empty() || !self.next_if(b'T') {
            self.restore(cp);
            return None;
        }
        let Some(desc): Option<&'static str> = self.demangle_specialization_kind() else {
            self.restore(cp);
            return None;
        };
        self.next_if(b'q');
        self.next_if(b'a');
        self.next_if(b'r');
        if !self.peek().is_some_and(|c: u8| c.is_ascii_digit()) {
            self.restore(cp);
            return None;
        }
        let _pass_id: u32 = self.demangle_natural();
        let mut children: Vec<NodeRef> = Vec::with_capacity(params.len() + 1);
        children.push(base.clone());
        children.extend(params);
        Some(Node::branch_with_text(
            Kind::GenericSpecialization,
            desc.to_owned(),
            children,
        ))
    }

    fn try_demangle_keypath_thunk(&mut self, base: &NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let Some(containing): Option<NodeRef> = self.try_demangle_type() else {
            self.restore(cp);
            return None;
        };
        if self.pos == cp.pos || self.peek() != Some(b'T') {
            self.restore(cp);
            return None;
        }
        let role: &'static str = match self.peek_at(1) {
            Some(b'K') => "getter",
            Some(b'k') => "setter",
            _ => {
                self.restore(cp);
                return None;
            }
        };
        self.pos += 2;
        Some(Node::branch_with_text(
            Kind::KeyPathThunk,
            role.to_owned(),
            vec![base.clone(), containing],
        ))
    }

    fn demangle_specialization_kind(&mut self) -> Option<&'static str> {
        match self.next()? {
            b'g' | b'B' => Some("generic specialization"),
            b'G' => Some("generic specialization (not reabstracted)"),
            b's' => Some("generic pre-specialization"),
            b'i' => Some("inlined generic function"),
            _ => None,
        }
    }

    fn demangle_metadata(&mut self, base: NodeRef) -> Option<NodeRef> {
        let c: u8 = self.next()?;
        let node: NodeRef = match c {
            b'n' => Node::unary(Kind::NominalTypeDescriptor, base),
            b'a' => Node::unary(Kind::TypeMetadataAccessFunction, base),
            b'f' => Node::unary(Kind::FullTypeMetadata, base),
            b'm' => Node::unary(Kind::Metaclass, base),
            b'p' => Node::unary(Kind::ProtocolDescriptor, base),
            b'c' => Node::unary(Kind::ProtocolConformanceDescriptor, base),
            b'F' => Node::unary(Kind::ReflectionMetadataFieldDescriptor, base),
            b'o' => Node::unary(Kind::ClassMetadataBaseOffset, base),
            b'P' => Node::unary(Kind::GenericTypeMetadataPattern, base),
            b'V' => Node::unary(Kind::PropertyDescriptor, base),
            b'I' => Node::unary(Kind::TypeMetadataInstantiationCache, base),
            b'i' => Node::unary(Kind::TypeMetadataInstantiationFunction, base),
            b'r' => Node::unary(Kind::TypeMetadataCompletionFunction, base),
            b'l' => Node::unary(Kind::TypeMetadataSingletonInitializationCache, base),
            b'Q' => Node::unary(Kind::OpaqueTypeDescriptor, base),
            b'K' => Node::unary(Kind::MetadataInstantiationCache, base),
            b'L' | b'u' | b'U' | b'C' | b'B' | b'z' | b'J' | b'N' | b'q' => {
                Node::unary(Kind::TypeMetadata, base)
            }
            b'X' => {
                let x: u8 = self.next()?;
                match x {
                    b'M' => Node::unary(Kind::ModuleDescriptor, base),
                    _ => Node::unary(Kind::TypeMetadata, base),
                }
            }
            _ => return None,
        };
        Some(node)
    }

    fn demangle_opaque_type_marker(&mut self, base: NodeRef) -> Option<NodeRef> {
        match self.next()? {
            b'O' => Some(base),
            _ => None,
        }
    }

    fn demangle_related_entity(&mut self, base: NodeRef) -> Option<NodeRef> {
        match self.next()? {
            b'i' => Some(Node::unary(Kind::VariableInitializationExpression, base)),
            b'A' => {
                let idx: u32 = self.demangle_index()?;
                Some(Node::branch_with_text(
                    Kind::DefaultArgumentInitializer,
                    idx.to_string(),
                    vec![base],
                ))
            }
            _ => None,
        }
    }

    fn demangle_witness(&mut self, base: NodeRef) -> Option<NodeRef> {
        let c: u8 = self.next()?;
        let node: NodeRef = match c {
            b'P' => Node::unary(Kind::ProtocolWitnessTable, base),
            b'p' => Node::unary(Kind::ProtocolWitnessTablePattern, base),
            b'V' => Node::unary(Kind::ValueWitnessTable, base),
            b'O' => {
                let outlined: u8 = self.next()?;
                match outlined {
                    b'c' => Node::unary(Kind::OutlinedInitWithCopy, base),
                    b'h' => Node::unary(Kind::OutlinedDestroy, base),
                    _ => return None,
                }
            }
            b'v' => {
                let directness: &'static str = self.consume_directness();
                Node::branch_with_text(Kind::FieldOffset, directness.to_owned(), vec![base])
            }
            b'C' => Node::unary(Kind::EnumCase, base),
            b'S' => Node::unary(Kind::ProtocolSelfConformanceWitnessTable, base),
            b'a' | b'G' | b'I' | b'l' | b'L' | b'b' | b'T' | b't' | b'r' => {
                Node::unary(Kind::ProtocolWitnessTable, base)
            }
            _ => return None,
        };
        Some(node)
    }

    fn consume_directness(&mut self) -> &'static str {
        match self.peek() {
            Some(b'd') => {
                self.pos += 1;
                "direct "
            }
            Some(b'i') => {
                self.pos += 1;
                "indirect "
            }
            _ => "",
        }
    }

    fn demangle_thunk(&mut self, base: NodeRef) -> Option<NodeRef> {
        let c: u8 = self.next()?;
        match c {
            b'q' => Some(Node::unary(Kind::MethodDescriptor, base)),
            b'j' => Some(Node::unary(Kind::DispatchThunk, base)),
            b'L' => Some(Node::unary(Kind::ProtocolRequirementsBaseDescriptor, base)),
            b'u' => Some(Node::unary(Kind::AsyncFunctionPointer, base)),
            b'm' => Some(Node::unary(Kind::MergedFunction, base)),
            b'Q' => {
                let idx: u32 = self.demangle_index()?;
                Some(Node::branch_with_text(
                    Kind::AsyncResumePartialFunction,
                    "await".to_owned(),
                    vec![base, Node::leaf(Kind::Identifier, idx.to_string())],
                ))
            }
            b'Y' => {
                let idx: u32 = self.demangle_index()?;
                Some(Node::branch_with_text(
                    Kind::AsyncResumePartialFunction,
                    "suspend".to_owned(),
                    vec![base, Node::leaf(Kind::Identifier, idx.to_string())],
                ))
            }
            b'W' => Some(Node::unary(Kind::ProtocolWitnessThunk, base)),
            b'A' => Some(Node::unary(Kind::PartialApplyForwarder, base)),
            b'E' => Some(Node::unary(Kind::DistributedThunk, base)),
            b'F' if base.kind == Kind::DistributedThunk => {
                Some(Node::unary(Kind::DistributedAccessor, base))
            }
            b'o' => Some(Node::unary(Kind::ObjCAttribute, base)),
            b'O' => Some(Node::unary(Kind::NonObjCAttribute, base)),
            b'f' => self.demangle_function_signature_specialization(base),
            b'D' | b'd' | b'V' | b'I' | b'X' | b'F' | b'c' => Some(base),
            _ => None,
        }
    }

    fn demangle_function_signature_specialization(&mut self, base: NodeRef) -> Option<NodeRef> {
        let serialized: bool = self.next_if(b'q');
        if !self.peek().is_some_and(|c: u8| c.is_ascii_digit()) {
            return None;
        }
        self.pos += 1;
        let mut entries: Vec<NodeRef> = Vec::new();
        if serialized {
            entries.push(Node::leaf(Kind::Identifier, "serialized".to_owned()));
        }
        let mut index: usize = 0;
        while !self.next_if(b'_') {
            self.spend()?;
            let param: SpecializationParam = self.demangle_specialization_param()?;
            if let SpecializationParam::Effects(effects) = param {
                entries.push(Node::leaf(
                    Kind::Identifier,
                    format!("Arg[{index}] = {effects}"),
                ));
            }
            index = index.checked_add(1)?;
        }
        if !self.next_if(b'n') {
            let param: SpecializationParam = self.demangle_specialization_param()?;
            if let SpecializationParam::Effects(effects) = param {
                entries.push(Node::leaf(Kind::Identifier, format!("Return = {effects}")));
            }
        }
        let mut children: Vec<NodeRef> = Vec::with_capacity(entries.len() + 1);
        children.push(base);
        children.extend(entries);
        Some(Node::branch_with_text(
            Kind::GenericSpecialization,
            "function signature specialization".to_owned(),
            children,
        ))
    }

    fn demangle_specialization_param(&mut self) -> Option<SpecializationParam> {
        let mut effects: Vec<&'static str> = Vec::new();
        match self.next()? {
            b'n' => return Some(SpecializationParam::Unmodified),
            b'd' => {
                effects.push("Dead");
                if self.next_if(b'G') {
                    effects.push("Owned To Guaranteed");
                }
                if self.next_if(b'X') {
                    effects.push("Exploded");
                }
            }
            b'g' => {
                effects.push("Owned To Guaranteed");
                if self.next_if(b'X') {
                    effects.push("Exploded");
                }
            }
            b'o' => effects.push("Guaranteed To Owned"),
            b'x' => effects.push("Exploded"),
            b'i' => effects.push("Value Promoted from Box"),
            b's' => effects.push("Stack Promoted from Box"),
            b'r' => effects.push("InOut Converted to Out"),
            _ => return None,
        }
        Some(SpecializationParam::Effects(effects.join(" and ")))
    }

    fn demangle_runtime_record(&mut self, base: NodeRef) -> NodeRef {
        let _: Option<u8> = self.next();
        base
    }

    fn demangle_value_witness(&mut self, base: NodeRef) -> Option<NodeRef> {
        let first: u8 = self.next()?;
        let second: u8 = self.next()?;
        let name: &'static str = value_witness_name(first, second)?;
        Some(Node::branch_with_text(
            Kind::ValueWitness,
            name.to_owned(),
            vec![base],
        ))
    }

    fn demangle_entity_or_type(&mut self) -> Option<NodeRef> {
        let c: u8 = self.peek()?;
        if matches!(c, b'S' | b'B' | b'x' | b'q' | b'y')
            && let Some(ty) = self.try_demangle_type()
        {
            return Some(ty);
        }
        self.demangle_entity()
    }

    fn try_demangle_type(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(n) = self.demangle_type() {
            return Some(n);
        }
        self.restore(cp);
        None
    }

    fn demangle_entity(&mut self) -> Option<NodeRef> {
        self.spend()?;
        self.depth = self.depth.checked_add(1)?;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let context: NodeRef = self.demangle_context()?;
        self.demangle_entity_spec(context)
    }

    fn demangle_context(&mut self) -> Option<NodeRef> {
        let c: u8 = self.peek()?;
        if c.is_ascii_digit() || c == b'0' {
            let module: NodeRef = self.demangle_identifier(Kind::Module)?;
            self.add_substitution(&module);
            return Some(module);
        }
        match c {
            b's' => {
                self.pos += 1;
                let module: NodeRef = Node::leaf(Kind::Module, "Swift".to_owned());
                Some(module)
            }
            b'S' => {
                let saved: usize = self.pos;
                if let Some(ty) = self.try_demangle_type() {
                    return Some(ty);
                }
                self.pos = saved;
                None
            }
            b'A' => self.demangle_substitution(),
            _ => self.demangle_type(),
        }
    }

    fn demangle_entity_spec(&mut self, context: NodeRef) -> Option<NodeRef> {
        let c: u8 = self.peek()?;
        match c {
            b'C' | b'V' | b'O' | b'a' => Some(self.finish_nominal(context, c)),
            b'P' => {
                self.pos += 1;
                Some(Node::unary(Kind::Protocol, context))
            }
            b'M' | b'N' | b'W' | b'H' if context.kind == Kind::Module => Some(context),
            b'y' | b'_' => self
                .try_demangle_subscript(&context)
                .or_else(|| self.demangle_named_entity(context)),
            _ => self.demangle_named_entity(context),
        }
    }

    fn try_demangle_subscript(&mut self, context: &NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let labels: Option<NodeRef> = self.demangle_label_list();
        if let Some(sig) = self.try_demangle_type()
            && sig.kind == Kind::FunctionType
        {
            let generic_sig: Option<NodeRef> = self.try_demangle_trailing_generic_signature();
            self.next_if(b'u');
            if self.next_if(b'i') {
                let subscript: NodeRef = build_subscript(context.clone(), Some(sig), labels);
                let subscript: NodeRef = attach_generic(subscript, generic_sig);
                if let Some(node) = self.wrap_accessor(subscript) {
                    return Some(node);
                }
            }
        }
        self.restore(cp);
        None
    }

    fn wrap_accessor(&mut self, target: NodeRef) -> Option<NodeRef> {
        let accessor: u8 = self.peek()?;
        match accessor {
            b'g' => {
                self.pos += 1;
                Some(Node::unary(Kind::Getter, target))
            }
            b's' => {
                self.pos += 1;
                Some(Node::unary(Kind::Setter, target))
            }
            b'M' | b'x' => {
                self.pos += 1;
                Some(Node::unary(Kind::ModifyAccessor, target))
            }
            b'r' | b'y' => {
                self.pos += 1;
                Some(Node::unary(Kind::ReadAccessor, target))
            }
            b'm' => {
                self.pos += 1;
                Some(Node::unary(Kind::MaterializeForSet, target))
            }
            b'a' => {
                self.pos += 1;
                self.consume_addressor_kind();
                Some(Node::unary(Kind::UnsafeMutableAddressor, target))
            }
            b'l' => {
                self.pos += 1;
                self.consume_addressor_kind();
                Some(Node::unary(Kind::UnsafeAddressor, target))
            }
            b'p' | b'G' | b'w' | b'W' | b'b' | b'z' => {
                self.pos += 1;
                Some(target)
            }
            _ => None,
        }
    }

    fn consume_addressor_kind(&mut self) {
        if matches!(self.peek(), Some(b'u' | b'O' | b'o' | b'p')) {
            self.pos += 1;
        }
    }

    fn finish_nominal(&mut self, context: NodeRef, tag: u8) -> NodeRef {
        self.pos += 1;
        let node: NodeRef = Node::unary(nominal_kind_for_tag(tag), context);
        self.add_substitution(&node);
        node
    }

    fn maybe_operator_name(&mut self, name: NodeRef) -> NodeRef {
        let suffix: &str = match (self.peek(), self.peek_at(1)) {
            (Some(b'o'), Some(b'i')) => " infix",
            (Some(b'o'), Some(b'p')) => " prefix",
            (Some(b'o'), Some(b'P')) => " postfix",
            _ => return name,
        };
        let Some(text): Option<&String> = name.text.as_ref() else {
            return name;
        };
        let Some(decoded): Option<String> = decode_operator_chars(text) else {
            return name;
        };
        self.pos += 2;
        Node::leaf(Kind::Identifier, format!("{decoded}{suffix}"))
    }

    fn consume_private_discriminator(&mut self, name: NodeRef) -> NodeRef {
        let Some(text): Option<&String> = name.text.as_ref() else {
            return name;
        };
        if !self.peek().is_some_and(|c: u8| c.is_ascii_digit()) {
            return name;
        }
        let cp: Checkpoint = self.checkpoint();
        let Some(discriminator): Option<NodeRef> = self.demangle_identifier(Kind::Identifier)
        else {
            self.restore(cp);
            return name;
        };
        if !(self.next_if(b'L') && self.next_if(b'L')) {
            self.restore(cp);
            return name;
        }
        let disc_text: &str = discriminator.text.as_deref().unwrap_or_default();
        Node::leaf(Kind::Identifier, format!("({text} in {disc_text})"))
    }

    fn demangle_protocol_member_or_self(&mut self, protocol: NodeRef) -> Option<NodeRef> {
        if let Some(base_conf) = self.try_demangle_base_conformance(&protocol) {
            return Some(base_conf);
        }
        let extension: Option<NodeRef> = self.try_demangle_extension_context(&protocol);
        let context: NodeRef = extension.unwrap_or(protocol);
        match self.peek() {
            Some(c) if c.is_ascii_digit() => {
                if let Some(node) = self.try_demangle_anonymous_entity(&context) {
                    return Some(node);
                }
                let name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
                Some(self.demangle_named_entity_spec(context, name))
            }
            _ => self
                .demangle_trailing_entity_spec(context.clone())
                .or(Some(context)),
        }
    }

    fn try_demangle_conformance_descriptor(&mut self, ty: &NodeRef) -> Option<NodeRef> {
        if !is_conformance_subject_kind(ty.kind) {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        if let Some(proto) = self.demangle_protocol_type() {
            let module: Option<NodeRef> = self.try_demangle_conformance_module();
            let generic_sig: Option<NodeRef> = self.try_demangle_conformance_generic_sig();
            if self.next_if(b'M') && self.next_if(b'c') {
                let mut children: Vec<NodeRef> = vec![ty.clone(), proto];
                if let Some(m) = module {
                    children.push(m);
                }
                let node: NodeRef = Node::branch(Kind::ProtocolConformanceDescriptorExt, children);
                return Some(match generic_sig {
                    Some(sig) => Node::branch(Kind::ConformanceWithGenericSig, vec![node, sig]),
                    None => node,
                });
            }
        }
        self.restore(cp);
        None
    }

    fn try_demangle_conformance_generic_sig(&mut self) -> Option<NodeRef> {
        if self.peek() == Some(b'M') {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        if let Some(sig) = self.demangle_generic_signature() {
            return Some(sig);
        }
        self.restore(cp);
        None
    }

    fn try_demangle_protocol_conformance_record(&mut self, ty: &NodeRef) -> Option<NodeRef> {
        if !is_conformance_subject_kind(ty.kind) {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        if let Some(proto) = self.demangle_protocol_type() {
            let module: Option<NodeRef> = self.try_demangle_conformance_module();
            if self.next_if(b'W')
                && let Some(record_kind) = self.conformance_record_kind()
            {
                let mut children: Vec<NodeRef> = vec![ty.clone(), proto];
                if let Some(m) = module {
                    children.push(m);
                }
                return Some(Node::branch(record_kind, children));
            }
        }
        self.restore(cp);
        None
    }

    fn conformance_record_kind(&mut self) -> Option<Kind> {
        match self.next()? {
            b'P' => Some(Kind::ProtocolWitnessTableConformance),
            b'p' => Some(Kind::ProtocolWitnessTablePatternConformance),
            _ => None,
        }
    }

    fn try_demangle_protocol_witness_context(&mut self, ty: &NodeRef) -> Option<NodeRef> {
        if !is_conformance_subject_kind(ty.kind) {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        let Some(proto): Option<NodeRef> = self.demangle_protocol_type() else {
            self.restore(cp);
            return None;
        };
        let module: Option<NodeRef> = self.witness_conformance_module();
        let mut children: Vec<NodeRef> = vec![ty.clone(), proto];
        if let Some(m) = module {
            children.push(m);
        }
        let conformance_ctx: NodeRef = Node::branch(Kind::ProtocolConformanceContext, children);
        let Some((is_static, requirement)): Option<(bool, NodeRef)> =
            self.demangle_witness_requirement(conformance_ctx)
        else {
            self.restore(cp);
            return None;
        };
        if self.peek() != Some(b'T') || self.peek_at(1) != Some(b'W') {
            self.restore(cp);
            return None;
        }
        Some(if is_static {
            Node::unary(Kind::Static, requirement)
        } else {
            requirement
        })
    }

    fn try_demangle_lazy_witness_accessor(&mut self, ty: &NodeRef) -> Option<NodeRef> {
        if !is_conformance_subject_kind(ty.kind) {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        let explicit: Option<NodeRef> = if self.peek() == Some(b'A') {
            self.demangle_substitution()
        } else {
            None
        };
        if let Some(explicit_self) = explicit
            && let Some(node) = self.finish_lazy_witness_accessor(ty, explicit_self)
        {
            return Some(node);
        }
        self.restore(cp.clone());
        if let Some(node) = self.finish_lazy_witness_accessor(ty, ty.clone()) {
            return Some(node);
        }
        self.restore(cp);
        None
    }

    fn finish_lazy_witness_accessor(&mut self, ty: &NodeRef, self_ty: NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let Some(proto): Option<NodeRef> = self.demangle_protocol_type() else {
            self.restore(cp);
            return None;
        };
        let module: Option<NodeRef> = self.witness_conformance_module();
        if !self.next_if(b'W') {
            self.restore(cp);
            return None;
        }
        let kind: Kind = match self.next() {
            Some(b'L') => Kind::LazyWitnessTableCacheVariable,
            Some(b'l') => Kind::LazyWitnessTableAccessor,
            _ => {
                self.restore(cp);
                return None;
            }
        };
        let mut conf_children: Vec<NodeRef> = vec![ty.clone(), proto];
        if let Some(m) = module {
            conf_children.push(m);
        }
        let conformance: NodeRef = Node::branch(Kind::ProtocolConformanceContext, conf_children);
        Some(Node::branch(kind, vec![self_ty, conformance]))
    }

    fn witness_conformance_module(&mut self) -> Option<NodeRef> {
        match self.peek()? {
            b'A' => {
                let chain: Vec<NodeRef> = self.demangle_substitution_chain()?;
                chain.into_iter().next()
            }
            b's' => {
                self.pos += 1;
                Some(Node::leaf(Kind::Module, "Swift".to_owned()))
            }
            c if c.is_ascii_digit() => self.demangle_identifier(Kind::Module),
            _ => None,
        }
    }

    fn demangle_witness_requirement(&mut self, context: NodeRef) -> Option<(bool, NodeRef)> {
        const MAX_DISCARDED_TOKENS: usize = 4;
        for _ in 0..MAX_DISCARDED_TOKENS {
            if self.next_if(b'P') {
                continue;
            }
            let is_static: bool = self.peek() == Some(b's')
                && self.peek_at(1).is_some_and(|c: u8| c.is_ascii_digit());
            if is_static {
                self.pos += 1;
            }
            if self.peek().is_some_and(|c: u8| c.is_ascii_digit()) {
                let name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
                return Some((is_static, self.demangle_named_entity_spec(context, name)));
            }
            if is_static {
                return None;
            }
            let cp: Checkpoint = self.checkpoint();
            if self.try_demangle_type().is_none() {
                self.restore(cp);
                return None;
            }
        }
        None
    }

    fn try_demangle_conformance_module(&mut self) -> Option<NodeRef> {
        match self.peek()? {
            b'A' => self.demangle_substitution(),
            b's' => {
                self.pos += 1;
                Some(Node::leaf(Kind::Module, "Swift".to_owned()))
            }
            c if c.is_ascii_digit() => self.demangle_identifier(Kind::Module),
            _ => None,
        }
    }

    fn try_demangle_base_conformance(&mut self, protocol: &NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(base_proto) = self.demangle_protocol_type()
            && self.next_if(b'T')
            && self.next_if(b'b')
            && self.pos == self.src.len()
        {
            return Some(Node::branch(
                Kind::BaseConformanceDescriptor,
                vec![protocol.clone(), base_proto],
            ));
        }
        self.restore(cp);
        None
    }

    fn demangle_protocol_type(&mut self) -> Option<NodeRef> {
        match self.peek()? {
            b's' => {
                self.pos += 1;
                let module: NodeRef = Node::leaf(Kind::Module, "Swift".to_owned());
                self.add_substitution(&module);
                self.demangle_protocol_in_context(module)
            }
            c if c.is_ascii_digit() => {
                let module: NodeRef = self.demangle_identifier(Kind::Module)?;
                self.add_substitution(&module);
                self.demangle_protocol_in_context(module)
            }
            b'S' => {
                self.pos += 1;
                let letter: u8 = self.next()?;
                standard_substitution_node(letter)
            }
            b'A' => {
                let base: NodeRef = self.demangle_substitution()?;
                if matches!(self.peek(), Some(c) if c.is_ascii_digit()) && base.kind == Kind::Module
                {
                    self.demangle_protocol_in_context(base)
                } else {
                    Some(base)
                }
            }
            _ => None,
        }
    }

    fn try_demangle_extension_context(&mut self, base: &NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(node) = self.demangle_extension_context_inner(base) {
            return Some(node);
        }
        self.restore(cp);
        None
    }

    fn demangle_extension_context_inner(&mut self, base: &NodeRef) -> Option<NodeRef> {
        let module: NodeRef = match self.peek()? {
            b'A' => self.demangle_substitution()?,
            b's' => {
                self.pos += 1;
                Node::leaf(Kind::Module, "Swift".to_owned())
            }
            c if c.is_ascii_digit() => {
                let module: NodeRef = self.demangle_identifier(Kind::Module)?;
                self.add_substitution(&module);
                module
            }
            _ => return None,
        };
        if !self.next_if(b'E') {
            return None;
        }
        Some(Node::branch(
            Kind::ExtensionContext,
            vec![module, base.clone()],
        ))
    }

    fn demangle_named_entity(&mut self, context: NodeRef) -> Option<NodeRef> {
        let raw_name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
        self.add_substitution(&raw_name);
        let name: NodeRef = self.maybe_operator_name(raw_name);
        let name: NodeRef = self.consume_private_discriminator(name);
        let c: u8 = self.peek()?;
        match c {
            b'C' | b'V' | b'O' | b'a' => {
                let parent_with_name: NodeRef =
                    Node::branch(Kind::OtherNominalType, vec![context, name]);
                Some(self.finish_nominal_named(parent_with_name, c))
            }
            b'P' => {
                self.pos += 1;
                let parent_with_name: NodeRef =
                    Node::branch(Kind::OtherNominalType, vec![context, name]);
                let protocol: NodeRef = Node::unary(Kind::Protocol, parent_with_name);
                self.add_substitution(&protocol);
                self.demangle_protocol_member_or_self(protocol)
            }
            b'f' => {
                self.pos += 1;
                self.demangle_function_like(context, name)
            }
            b'v' => {
                self.pos += 1;
                Some(self.demangle_variable(context, name, None))
            }
            b'M' | b'N' | b'W' | b'H' | b'T' | b'w' => {
                Some(Node::branch(Kind::OtherNominalType, vec![context, name]))
            }
            b'_' if self.peek_at(1) == Some(b'p') => {
                self.pos += 2;
                let parent_with_name: NodeRef =
                    Node::branch(Kind::OtherNominalType, vec![context, name]);
                let protocol: NodeRef = Node::unary(Kind::Protocol, parent_with_name);
                self.add_substitution(&protocol);
                Some(protocol)
            }
            _ => {
                if c == b'_' {
                    let underscore_cp: Checkpoint = self.checkpoint();
                    self.pos += 1;
                    if let Some(node) = self.demangle_one_time_init(name.clone()) {
                        return Some(node);
                    }
                    self.restore(underscore_cp);
                }
                let cp: Checkpoint = self.checkpoint();
                if let Some(node) = self.try_demangle_storage_entity(&context, &name) {
                    return Some(node);
                }
                self.restore(cp);
                Some(self.demangle_function(context, name))
            }
        }
    }

    fn demangle_one_time_init(&mut self, name: NodeRef) -> Option<NodeRef> {
        if !self.next_if(b'W') {
            return None;
        }
        match self.next()? {
            b'Z' => Some(Node::unary(Kind::OneTimeInitializationFunction, name)),
            b'z' => Some(Node::unary(Kind::OneTimeInitializationToken, name)),
            _ => None,
        }
    }

    fn finish_nominal_named(&mut self, ctx_with_name: NodeRef, tag: u8) -> NodeRef {
        self.pos += 1;
        let node: NodeRef = Node::unary(nominal_kind_for_tag(tag), ctx_with_name);
        self.add_substitution(&node);
        node
    }

    fn demangle_function_like(&mut self, context: NodeRef, name: NodeRef) -> Option<NodeRef> {
        let c: u8 = self.next()?;
        match c {
            b'C' => {
                let sig: Option<NodeRef> = self.try_demangle_function_signature();
                Some(build_init(Kind::Allocator, context, sig, None))
            }
            b'c' => {
                let sig: Option<NodeRef> = self.try_demangle_function_signature();
                Some(build_init(Kind::Constructor, context, sig, None))
            }
            b'D' | b'Z' => Some(Node::unary(Kind::Deallocator, context)),
            b'd' | b'E' | b'e' => Some(Node::unary(Kind::Destructor, context)),
            _ => Some(Node::branch(Kind::Function, vec![context, name])),
        }
    }

    fn demangle_variable(
        &mut self,
        context: NodeRef,
        name: NodeRef,
        ty: Option<NodeRef>,
    ) -> NodeRef {
        let mut children: Vec<NodeRef> = vec![context, name];
        if let Some(t) = ty {
            children.push(t);
        }
        let var: NodeRef = Node::branch(Kind::Variable, children);
        let accessed: NodeRef = self.wrap_accessor(var.clone()).unwrap_or(var);
        if self.next_if(b'Z') {
            Node::unary(Kind::Static, accessed)
        } else {
            accessed
        }
    }

    fn demangle_function(&mut self, context: NodeRef, name: NodeRef) -> NodeRef {
        let (labels, signature, generic_sig): (Option<NodeRef>, Option<NodeRef>, Option<NodeRef>) =
            self.demangle_function_body();
        let is_static: bool = self.consume_function_terminator();
        let func: NodeRef = build_function(context, name, labels, signature, generic_sig);
        if is_static {
            Node::unary(Kind::Static, func)
        } else {
            func
        }
    }

    fn demangle_function_body(&mut self) -> (Option<NodeRef>, Option<NodeRef>, Option<NodeRef>) {
        let cp: Checkpoint = self.checkpoint();
        if let Some(result) = self.try_demangle_function_body_with_labels() {
            return result;
        }
        self.restore(cp);
        let signature: Option<NodeRef> = self.try_demangle_function_signature();
        let generic_sig: Option<NodeRef> = self.try_demangle_trailing_generic_signature();
        (None, signature, generic_sig)
    }

    fn try_demangle_function_body_with_labels(
        &mut self,
    ) -> Option<(Option<NodeRef>, Option<NodeRef>, Option<NodeRef>)> {
        let base: Checkpoint = self.checkpoint();
        let empty_marker: bool = self.next_if(b'y');
        self.restore(base.clone());
        let max_labels: usize = if empty_marker {
            0
        } else {
            self.scan_label_count()
        };
        self.restore(base.clone());
        let mut count: usize = max_labels;
        loop {
            self.restore(base.clone());
            let labels: NodeRef = self.consume_n_labels(count, empty_marker);
            if let Some(signature) = self.try_demangle_function_signature() {
                let generic_sig: Option<NodeRef> = self.try_demangle_trailing_generic_signature();
                if matches!(self.peek(), Some(b'F' | b'Z') | None) {
                    return Some((Some(labels), Some(signature), generic_sig));
                }
            }
            if count == 0 {
                self.restore(base);
                return None;
            }
            count -= 1;
        }
    }

    fn scan_label_count(&mut self) -> usize {
        let mut count: usize = 0;
        loop {
            match self.peek() {
                Some(b'_') => {
                    self.pos += 1;
                    count += 1;
                }
                Some(c) if c.is_ascii_digit() => {
                    let saved: usize = self.pos;
                    if self.demangle_identifier(Kind::Identifier).is_none() {
                        self.pos = saved;
                        break;
                    }
                    count += 1;
                }
                _ => break,
            }
        }
        count
    }

    fn consume_n_labels(&mut self, count: usize, empty_marker: bool) -> NodeRef {
        if empty_marker && count == 0 {
            self.next_if(b'y');
            return Node::branch(Kind::LabelList, Vec::new());
        }
        let mut labels: Vec<NodeRef> = Vec::with_capacity(count);
        for _ in 0..count {
            match self.peek() {
                Some(b'_') => {
                    self.pos += 1;
                    labels.push(Node::leaf(Kind::Identifier, String::new()));
                }
                Some(c) if c.is_ascii_digit() => {
                    if let Some(name) = self.demangle_identifier_sub(Kind::Identifier) {
                        labels.push(name);
                    }
                }
                _ => break,
            }
        }
        Node::branch(Kind::LabelList, labels)
    }

    fn try_demangle_trailing_generic_signature(&mut self) -> Option<NodeRef> {
        match self.peek() {
            None | Some(b'F' | b'Z') => return None,
            _ => {}
        }
        let cp: Checkpoint = self.checkpoint();
        if let Some(sig) = self.demangle_generic_signature() {
            return Some(sig);
        }
        self.restore(cp);
        None
    }

    fn demangle_label_list(&mut self) -> Option<NodeRef> {
        if self.pending_substitutions.is_empty() && self.next_if(b'y') {
            return Some(Node::branch(Kind::LabelList, Vec::new()));
        }
        let mut labels: Vec<NodeRef> = Vec::new();
        loop {
            match self.peek() {
                Some(b'_') => {
                    self.pos += 1;
                    labels.push(Node::leaf(Kind::Identifier, String::new()));
                }
                Some(c) if c.is_ascii_digit() => {
                    let saved: usize = self.pos;
                    let Some(name): Option<NodeRef> = self.demangle_identifier(Kind::Identifier)
                    else {
                        self.pos = saved;
                        break;
                    };
                    labels.push(name);
                }
                _ => break,
            }
        }
        if labels.is_empty() {
            None
        } else {
            Some(Node::branch(Kind::LabelList, labels))
        }
    }

    fn try_demangle_function_signature(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(n) = self.demangle_function_signature() {
            return Some(n);
        }
        self.restore(cp);
        None
    }

    fn demangle_function_signature(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(sig) = self.demangle_function_signature_with(true) {
            return Some(sig);
        }
        self.restore(cp);
        self.demangle_function_signature_with(false)
    }

    fn demangle_function_signature_with(&mut self, single_result: bool) -> Option<NodeRef> {
        let result: NodeRef = self.demangle_result_type(single_result)?;
        let params: NodeRef = self.demangle_params()?;
        let annotations: Vec<NodeRef> = self.consume_function_annotations();
        let mut children: Vec<NodeRef> = vec![
            Node::unary(Kind::ArgumentTuple, params),
            Node::unary(Kind::ReturnType, result),
        ];
        children.extend(annotations);
        Some(Node::branch(Kind::FunctionType, children))
    }

    fn demangle_result_type(&mut self, single_result: bool) -> Option<NodeRef> {
        let restore: bool = self.suppress_tuple;
        if single_result {
            self.suppress_tuple = true;
        }
        let ty: Option<NodeRef> = self.try_demangle_type();
        self.suppress_tuple = restore;
        if let Some(ty) = ty {
            return Some(ty);
        }
        if self.next_if(b'y') {
            return Some(Node::branch(Kind::Tuple, Vec::new()));
        }
        None
    }

    fn demangle_params(&mut self) -> Option<NodeRef> {
        if self.peek() == Some(b'y') && !self.peek_param_is_type_after_y() {
            self.pos += 1;
            return Some(Node::branch(Kind::Tuple, Vec::new()));
        }
        let first: NodeRef = self.demangle_type()?;
        let first: NodeRef = self.apply_param_flags(first);
        if self.pending_substitutions.is_empty()
            && self.peek_at(1) == Some(b't')
            && self.peek() == Some(b'_')
        {
            self.pos += 2;
            return Some(Node::branch(
                Kind::Tuple,
                vec![Node::unary(Kind::TupleElement, first)],
            ));
        }
        if self.peek() != Some(b'_') {
            return Some(first);
        }
        self.demangle_param_tuple_tail(first)
    }

    fn peek_param_is_type_after_y(&mut self) -> bool {
        let cp: Checkpoint = self.checkpoint();
        let parsed: bool = self.demangle_type().is_some() && self.at_param_list_terminator();
        self.restore(cp);
        parsed
    }

    fn at_param_list_terminator(&mut self) -> bool {
        let saved: usize = self.pos;
        self.skip_param_flags();
        let terminated: bool = matches!(
            self.peek(),
            Some(b'_' | b't' | b'K' | b'Y' | b'F' | b'Z' | b'u') | None
        ) || self.consume_extended_function_kind().is_some();
        self.pos = saved;
        terminated
    }

    fn skip_param_flags(&mut self) {
        loop {
            match self.peek() {
                Some(b'z' | b'h' | b'n' | b'd') => self.pos += 1,
                Some(b'Y') if self.peek_at(1) == Some(b'i') => self.pos += 2,
                _ => return,
            }
        }
    }

    fn demangle_param_tuple_tail(&mut self, first: NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        self.pos += 1;
        let mut elements: Vec<NodeRef> = vec![Node::unary(Kind::TupleElement, first.clone())];
        loop {
            if self.pending_substitutions.is_empty() && self.next_if(b't') {
                return Some(Node::branch(Kind::Tuple, elements));
            }
            self.depth = self.depth.checked_add(1)?;
            if self.depth > MAX_DEPTH {
                return None;
            }
            let Some(element): Option<NodeRef> = self.demangle_tuple_element() else {
                self.restore(cp);
                return Some(first);
            };
            elements.push(element);
        }
    }

    fn apply_param_flags(&mut self, ty: NodeRef) -> NodeRef {
        let mut ty: NodeRef = ty;
        loop {
            ty = match self.peek() {
                Some(b'z') => {
                    self.pos += 1;
                    Node::unary(Kind::InOut, ty)
                }
                Some(b'h') => {
                    self.pos += 1;
                    Node::unary(Kind::Shared, ty)
                }
                Some(b'n') => {
                    self.pos += 1;
                    Node::unary(Kind::Owned, ty)
                }
                Some(b'd') => {
                    self.pos += 1;
                    Node::unary(Kind::Variadic, ty)
                }
                Some(b'Y') if self.peek_at(1) == Some(b'i') => {
                    self.pos += 2;
                    Node::unary(Kind::Isolated, ty)
                }
                _ => return ty,
            };
        }
    }

    fn demangle_type(&mut self) -> Option<NodeRef> {
        self.spend()?;
        self.depth = self.depth.checked_add(1)?;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let result: Option<NodeRef> = self.demangle_type_inner();
        self.depth -= 1;
        result
    }

    fn demangle_type_inner(&mut self) -> Option<NodeRef> {
        let suppress_funckind: bool = self.suppress_function_suffix;
        let suppress_result_fn: bool = self.suppress_result_function;
        self.suppress_function_suffix = false;
        self.suppress_result_function = false;
        if !self.pending_substitutions.is_empty() {
            let node: NodeRef = self.pending_substitutions.remove(0);
            return if suppress_funckind {
                self.apply_type_suffixes_no_funckind(node)
            } else {
                self.apply_type_suffixes(node)
            };
        }
        if self.peek() == Some(b'y') {
            match self.peek_at(1) {
                Some(b't') => {
                    self.pos += 2;
                    let tuple: NodeRef = Node::branch(Kind::Tuple, Vec::new());
                    return self.apply_type_suffixes(tuple);
                }
                Some(b'p') => {
                    self.pos += 2;
                    let any: NodeRef = Node::unary(
                        Kind::OtherNominalType,
                        Node::leaf(Kind::Identifier, "Any".to_owned()),
                    );
                    return self.apply_type_suffixes(any);
                }
                Some(b'X') if self.peek_at(2) == Some(b'l') => {
                    self.pos += 3;
                    let any: NodeRef = Node::branch(Kind::AnyObjectExistential, Vec::new());
                    return self.apply_type_suffixes(any);
                }
                _ => {}
            }
            if !suppress_funckind && let Some(func) = self.try_demangle_empty_result_function() {
                return self.apply_type_suffixes(func);
            }
        }
        if !self.suppress_tuple
            && let Some(tuple) = self.try_demangle_top_level_tuple()
        {
            return self.apply_type_suffixes(tuple);
        }
        let base: NodeRef = self.demangle_type_base()?;
        self.suppress_result_function = suppress_result_fn;
        let suffixed: Option<NodeRef> = if suppress_funckind {
            self.apply_type_suffixes_no_funckind(base)
        } else {
            self.apply_type_suffixes(base)
        };
        self.suppress_result_function = suppress_result_fn;
        suffixed
    }

    fn consume_extended_function_kind(&mut self) -> Option<FunctionConvention> {
        match self.peek() {
            Some(b'c') => {
                self.pos += 1;
                Some(FunctionConvention::Swift)
            }
            Some(b'X') => match self.peek_at(1) {
                Some(b'C') => {
                    self.pos += 2;
                    Some(FunctionConvention::C)
                }
                Some(b'B') => {
                    self.pos += 2;
                    Some(FunctionConvention::Block)
                }
                Some(b'E' | b'e') => {
                    self.pos += 2;
                    Some(FunctionConvention::Swift)
                }
                Some(b'K') => {
                    self.pos += 2;
                    Some(FunctionConvention::Autoclosure)
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn apply_type_suffixes_no_funckind(&mut self, node: NodeRef) -> Option<NodeRef> {
        if matches!(self.peek(), Some(b'y')) && self.peek_function_kind_after(1) {
            return Some(node);
        }
        self.apply_type_suffixes(node)
    }

    fn try_demangle_empty_result_function(&mut self) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        self.pos += 1;
        let result: NodeRef = Node::branch(Kind::Tuple, Vec::new());
        let after_result: usize = self.pos;
        if self.next_if(b'y')
            && let Some(convention) = self.consume_function_kind()
        {
            let params: NodeRef = Node::branch(Kind::Tuple, Vec::new());
            return Some(make_function_type(params, result, convention));
        }
        self.pos = after_result;
        let params: Option<NodeRef> = self.demangle_params();
        if let Some(params) = params {
            let annotations: Vec<NodeRef> = self.consume_function_annotations();
            if let Some(convention) = self.consume_extended_function_kind() {
                return Some(make_function_type_full(
                    params,
                    result,
                    convention,
                    annotations,
                ));
            }
        }
        self.restore(cp);
        None
    }

    fn try_demangle_top_level_tuple(&mut self) -> Option<NodeRef> {
        if !matches!(
            self.peek(),
            Some(b'S' | b's' | b'B' | b'A' | b'x' | b'q' | b'y' | b'Q' | b'0'..=b'9')
        ) {
            return None;
        }
        if self.peek() == Some(b'S') && self.peek_at(1).is_some_and(|d: u8| d.is_ascii_digit()) {
            return None;
        }
        let cp: Checkpoint = self.checkpoint();
        if let Some(node) = self.demangle_tuple_body()
            && self.next_if(b't')
        {
            return Some(node);
        }
        self.restore(cp);
        None
    }

    fn demangle_tuple_body(&mut self) -> Option<NodeRef> {
        let mut elements: Vec<NodeRef> = Vec::new();
        let mut saw_separator: bool = false;
        loop {
            if self.pending_substitutions.is_empty() && self.peek() == Some(b't') {
                break;
            }
            self.depth = self.depth.checked_add(1)?;
            if self.depth > MAX_DEPTH {
                return None;
            }
            let element: NodeRef = self.demangle_tuple_element()?;
            elements.push(element);
            if elements.len() == 1 {
                saw_separator = self.next_if(b'_');
            }
        }
        if elements.len() < 2 && !tuple_has_label(&elements) && !tuple_element_is_pack(&elements) {
            return None;
        }
        if elements.len() >= 2 && !saw_separator {
            return None;
        }
        Some(Node::branch(Kind::Tuple, elements))
    }

    fn demangle_tuple_element(&mut self) -> Option<NodeRef> {
        let restore_suppress: bool = self.suppress_tuple;
        self.suppress_tuple = true;
        let ty: Option<NodeRef> = self.demangle_type();
        self.suppress_tuple = restore_suppress;
        let ty: NodeRef = ty?;
        let ty: NodeRef = self.apply_param_flags(ty);
        let label: Option<String> = match self.peek() {
            Some(c) if c.is_ascii_digit() && c != b'0' => self
                .demangle_identifier(Kind::Identifier)
                .and_then(|n: NodeRef| n.text.clone()),
            _ => None,
        };
        match label {
            Some(name) => Some(Node::branch(
                Kind::TupleElement,
                vec![Node::leaf(Kind::Identifier, name), ty],
            )),
            None => Some(Node::unary(Kind::TupleElement, ty)),
        }
    }

    fn demangle_type_base(&mut self) -> Option<NodeRef> {
        let c: u8 = self.peek()?;
        match c {
            b'0'..=b'9' => self.demangle_nominal_or_assoc_type(),
            b's' => {
                self.pos += 1;
                let module: NodeRef = Node::leaf(Kind::Module, "Swift".to_owned());
                self.demangle_nominal_in_context(module)
            }
            b'S' => self.demangle_standard_substitution(),
            b'A' => self.demangle_substitution_type(),
            b'x' => {
                self.pos += 1;
                Some(make_generic_param(0, 0))
            }
            b'q' => {
                self.pos += 1;
                let (depth, idx): (u32, u32) = self.demangle_v0_generic_param_index()?;
                Some(make_generic_param(depth, idx))
            }
            b'B' => self.demangle_builtin_type(),
            b'Q' => self.demangle_opaque_return_type(),
            _ => None,
        }
    }

    fn demangle_opaque_return_type(&mut self) -> Option<NodeRef> {
        self.pos += 1;
        match self.next()? {
            b'r' => Some(Node::branch(Kind::OpaqueReturnType, Vec::new())),
            b'R' => {
                let _ordinal: u32 = self.demangle_index()?;
                Some(Node::branch(Kind::OpaqueReturnType, Vec::new()))
            }
            _ => None,
        }
    }

    fn demangle_substitution_type(&mut self) -> Option<NodeRef> {
        let mut chain: Vec<NodeRef> = self.demangle_substitution_chain()?;
        let last: NodeRef = chain.pop()?;
        let last: NodeRef = self.continue_nominal_after_substitution(last)?;
        chain.push(last);
        let first: NodeRef = chain.remove(0);
        for node in chain {
            self.pending_substitutions.push(node);
        }
        Some(first)
    }

    fn demangle_substitution_chain(&mut self) -> Option<Vec<NodeRef>> {
        self.pos += 1;
        let mut repeat: i64 = -1;
        let mut chain: Vec<NodeRef> = Vec::new();
        loop {
            let c: u8 = self.peek()?;
            if c == b'_' {
                self.pos += 1;
                let idx: usize = usize::try_from(repeat.checked_add(27)?).ok()?;
                chain.push(self.substitutions.get(idx).cloned()?);
                return Some(chain);
            }
            if c.is_ascii_lowercase() {
                self.pos += 1;
                let idx: usize = (c - b'a') as usize;
                let node: NodeRef = self.substitutions.get(idx).cloned()?;
                let count: i64 = repeat.max(1);
                for _ in 0..count {
                    self.spend()?;
                    chain.push(Rc::clone(&node));
                }
                repeat = -1;
                continue;
            }
            if c.is_ascii_uppercase() {
                self.pos += 1;
                let idx: usize = (c - b'A') as usize;
                let node: NodeRef = self.substitutions.get(idx).cloned()?;
                let count: i64 = repeat.max(1);
                for _ in 0..count {
                    self.spend()?;
                    chain.push(Rc::clone(&node));
                }
                return Some(chain);
            }
            if c.is_ascii_digit() {
                repeat = i64::from(self.demangle_natural());
                if repeat <= 0 || repeat > i64::from(MAX_REPEAT_COUNT) {
                    return None;
                }
                if !self.peek().is_some_and(|d: u8| d.is_ascii_alphabetic()) {
                    return None;
                }
                continue;
            }
            return None;
        }
    }

    fn continue_nominal_after_substitution(&mut self, sub: NodeRef) -> Option<NodeRef> {
        if !is_context_kind(sub.kind) {
            return Some(sub);
        }
        match self.peek() {
            Some(c) if c.is_ascii_digit() => self.demangle_nominal_in_context(sub),
            Some(b'C' | b'V' | b'O' | b'a' | b'P') => self.demangle_nominal_in_context(sub),
            _ => Some(sub),
        }
    }

    fn apply_type_suffixes(&mut self, mut node: NodeRef) -> Option<NodeRef> {
        loop {
            self.depth = self.depth.checked_add(1)?;
            if self.depth > MAX_DEPTH {
                return None;
            }
            match self.peek() {
                Some(b'y') => {
                    if let Some(func) = self.try_demangle_empty_param_function(node.clone()) {
                        node = func;
                    } else {
                        let cp: Checkpoint = self.checkpoint();
                        self.pos += 1;
                        if let Some(bound) = self.demangle_bound_generic_args(node.clone()) {
                            node = bound;
                        } else {
                            self.restore(cp);
                            break;
                        }
                    }
                }
                Some(b'_') if self.peek_at(1) == Some(b'p') && node.kind == Kind::Protocol => {
                    self.pos += 2;
                }
                Some(b'_') if self.peek_at(1) == Some(b'Q') && self.peek_at(2) == Some(b'P') => {
                    self.pos += 3;
                    node = Node::unary(Kind::Pack, node);
                }
                Some(b'S' | b's' | b'B' | b'A' | b'x' | b'q' | b'0'..=b'9')
                    if self.pack_expansion_ahead() =>
                {
                    node = self.demangle_pack_expansion(node)?;
                }
                Some(b'S') if self.peek_at(1) == Some(b'g') => {
                    self.pos += 2;
                    node = self.apply_suffix_to_pending_or(node, Kind::Optional);
                }
                Some(b'm') => {
                    self.pos += 1;
                    node = self.apply_suffix_to_pending_or(node, Kind::Metatype);
                }
                Some(b'Q') => match self.peek_at(1) {
                    Some(b'x') => {
                        self.pos += 2;
                        let assoc: NodeRef = self.demangle_identifier(Kind::Identifier)?;
                        node = Node::branch(Kind::DependentAssociatedType, vec![node, assoc]);
                        self.add_substitution(&node);
                    }
                    Some(b'X') => {
                        self.pos += 2;
                        let assoc: NodeRef = self.demangle_assoc_type_list()?;
                        node = Node::branch(Kind::DependentAssociatedType, vec![node, assoc]);
                        self.add_substitution(&node);
                    }
                    _ => break,
                },
                Some(b'X') => match self.peek_at(1) {
                    Some(b'M') => {
                        let representation: &'static str = match self.peek_at(2)? {
                            b't' => "@thin",
                            b'T' => "@thick",
                            b'o' => "@objc_metatype",
                            _ => return None,
                        };
                        self.pos += 3;
                        node = Node::branch_with_text(
                            Kind::Metatype,
                            representation.to_owned(),
                            vec![node],
                        );
                    }
                    Some(b'p') => {
                        self.pos += 2;
                        node = Node::unary(Kind::ExistentialMetatype, node);
                    }
                    Some(b'D') => {
                        self.pos += 2;
                    }
                    _ => break,
                },
                Some(b'Y') if self.peek_at(1) == Some(b'u') => {
                    self.pos += 2;
                    node = Node::unary(Kind::Sending, node);
                }
                Some(b'A' | b's' | b'0'..=b'9')
                    if is_context_kind(node.kind) && self.peek_is_type_extension() =>
                {
                    match self.try_demangle_type_extension(node.clone()) {
                        Some(ext) => node = ext,
                        None => break,
                    }
                }
                Some(b'S' | b's' | b'B' | b'A' | b'x' | b'q' | b'0'..=b'9')
                    if !self.suppress_result_function =>
                {
                    match self.try_demangle_function_from_result(node.clone()) {
                        Some(func) => node = func,
                        None => break,
                    }
                }
                _ => break,
            }
        }
        Some(node)
    }

    fn peek_is_type_extension(&mut self) -> bool {
        let cp: Checkpoint = self.checkpoint();
        let module: Option<NodeRef> = match self.peek() {
            Some(b'A') => self
                .demangle_substitution_chain()
                .and_then(|c: Vec<NodeRef>| c.into_iter().next()),
            Some(b's') => {
                self.pos += 1;
                Some(Node::leaf(Kind::Module, "Swift".to_owned()))
            }
            Some(c) if c.is_ascii_digit() => self.demangle_identifier(Kind::Module),
            _ => None,
        };
        let ok: bool = module.is_some_and(|m: NodeRef| m.kind == Kind::Module)
            && self.next_if(b'E')
            && self.peek_is_nested_nominal();
        self.restore(cp);
        ok
    }

    fn try_demangle_type_extension(&mut self, base: NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let module: Option<NodeRef> = match self.peek() {
            Some(b'A') => {
                let chain: Option<Vec<NodeRef>> = self.demangle_substitution_chain();
                chain.and_then(|c: Vec<NodeRef>| c.into_iter().next())
            }
            Some(b's') => {
                self.pos += 1;
                Some(Node::leaf(Kind::Module, "Swift".to_owned()))
            }
            Some(c) if c.is_ascii_digit() => self.demangle_identifier(Kind::Module),
            _ => None,
        };
        let module: NodeRef = match module {
            Some(m) if m.kind == Kind::Module && self.next_if(b'E') => m,
            _ => {
                self.restore(cp);
                return None;
            }
        };
        let ext: NodeRef = Node::branch(Kind::ExtensionContext, vec![module, base]);
        let Some(nested): Option<NodeRef> = self.demangle_nominal_in_context(ext) else {
            self.restore(cp);
            return None;
        };
        Some(nested)
    }

    fn try_demangle_function_from_result(&mut self, result: NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        let arg: Option<NodeRef> = self.demangle_params();
        if let Some(arg) = arg {
            let annotations: Vec<NodeRef> = self.consume_function_annotations();
            if let Some(convention) = self.consume_extended_function_kind() {
                return Some(make_function_type_full(
                    arg,
                    result,
                    convention,
                    annotations,
                ));
            }
        }
        self.restore(cp);
        None
    }

    fn try_demangle_empty_param_function(&mut self, result: NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        self.pos += 1;
        let annotations: Vec<NodeRef> = self.consume_function_annotations();
        if let Some(convention) = self.consume_extended_function_kind() {
            let params: NodeRef = Node::branch(Kind::Tuple, Vec::new());
            return Some(make_function_type_full(
                params,
                result,
                convention,
                annotations,
            ));
        }
        self.restore(cp);
        None
    }

    fn apply_suffix_to_pending_or(&mut self, node: NodeRef, kind: Kind) -> NodeRef {
        if let Some(last) = self.pending_substitutions.last_mut() {
            let wrapped: NodeRef = Node::unary(kind, Rc::clone(last));
            *last = Rc::clone(&wrapped);
            self.substitutions.push(wrapped);
            node
        } else {
            let wrapped: NodeRef = Node::unary(kind, node);
            self.add_substitution(&wrapped);
            wrapped
        }
    }

    fn pack_expansion_ahead(&mut self) -> bool {
        if !self
            .src
            .get(self.pos..)
            .is_some_and(|rest: &[u8]| rest.windows(2).any(|w: &[u8]| w == b"Qp"))
        {
            return false;
        }
        let cp: Checkpoint = self.checkpoint();
        let saved_flags: (bool, bool, bool) = self.suppress_flags();
        let ahead: bool = self.demangle_type().is_some()
            && self.peek() == Some(b'Q')
            && self.peek_at(1) == Some(b'p');
        self.restore(cp);
        self.restore_suppress_flags(saved_flags);
        ahead
    }

    fn demangle_pack_expansion(&mut self, pattern: NodeRef) -> Option<NodeRef> {
        let saved_flags: (bool, bool, bool) = self.suppress_flags();
        let count: Option<NodeRef> = self.demangle_type();
        self.restore_suppress_flags(saved_flags);
        let count: NodeRef = count?;
        if !(self.next_if(b'Q') && self.next_if(b'p')) {
            return None;
        }
        Some(Node::branch(Kind::PackExpansion, vec![pattern, count]))
    }

    const fn suppress_flags(&self) -> (bool, bool, bool) {
        (
            self.suppress_tuple,
            self.suppress_function_suffix,
            self.suppress_result_function,
        )
    }

    const fn restore_suppress_flags(&mut self, flags: (bool, bool, bool)) {
        (
            self.suppress_tuple,
            self.suppress_function_suffix,
            self.suppress_result_function,
        ) = flags;
    }

    fn peek_function_kind_after(&self, ahead: usize) -> bool {
        match self.peek_at(ahead) {
            Some(b'c') => true,
            Some(b'X') => matches!(self.peek_at(ahead + 1), Some(b'C' | b'B' | b'K')),
            _ => false,
        }
    }

    fn consume_function_kind(&mut self) -> Option<FunctionConvention> {
        match self.peek() {
            Some(b'c') => {
                self.pos += 1;
                Some(FunctionConvention::Swift)
            }
            Some(b'X') if self.peek_at(1) == Some(b'C') => {
                self.pos += 2;
                Some(FunctionConvention::C)
            }
            Some(b'X') if self.peek_at(1) == Some(b'B') => {
                self.pos += 2;
                Some(FunctionConvention::Block)
            }
            Some(b'X') if self.peek_at(1) == Some(b'K') => {
                self.pos += 2;
                Some(FunctionConvention::Autoclosure)
            }
            _ => None,
        }
    }

    fn demangle_nominal_or_assoc_type(&mut self) -> Option<NodeRef> {
        let first: NodeRef = self.demangle_identifier(Kind::Identifier)?;
        if self.peek() == Some(b'Q') {
            self.add_substitution(&first);
            return self.demangle_associated_type_standalone(first);
        }
        let module: NodeRef = first.with_kind(Kind::Module);
        self.add_substitution(&module);
        self.demangle_nominal_in_context(module)
    }

    fn demangle_assoc_type_list(&mut self) -> Option<NodeRef> {
        let mut names: Vec<NodeRef> = Vec::new();
        loop {
            self.depth = self.depth.checked_add(1)?;
            if self.depth > MAX_DEPTH {
                return None;
            }
            let name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
            names.push(name);
            if !self.next_if(b'_') {
                break;
            }
        }
        if names.len() == 1 {
            return names.into_iter().next();
        }
        Some(Node::branch(Kind::OtherNominalType, names))
    }

    fn demangle_associated_type_standalone(&mut self, assoc_name: NodeRef) -> Option<NodeRef> {
        self.pos += 1;
        let base: NodeRef = match self.next()? {
            b'z' => make_generic_param(0, 0),
            b'y' => {
                let (depth, idx): (u32, u32) = self.demangle_v0_generic_param_index()?;
                make_generic_param(depth, idx)
            }
            _ => return None,
        };
        let node: NodeRef = Node::branch(Kind::DependentAssociatedType, vec![base, assoc_name]);
        self.add_substitution(&node);
        Some(node)
    }

    fn demangle_nominal_in_context(&mut self, mut context: NodeRef) -> Option<NodeRef> {
        loop {
            self.depth = self.depth.checked_add(1)?;
            if self.depth > MAX_DEPTH {
                return None;
            }
            let c: u8 = self.peek()?;
            match c {
                b'C' | b'V' | b'O' | b'a' => {
                    self.pos += 1;
                    let kind: Kind = match c {
                        b'C' => Kind::Class,
                        b'V' => Kind::Structure,
                        b'O' => Kind::Enum,
                        _ => Kind::TypeAlias,
                    };
                    let node: NodeRef = Node::unary(kind, context);
                    self.add_substitution(&node);
                    if self.peek_is_nested_nominal() {
                        context = node;
                        continue;
                    }
                    return Some(node);
                }
                b'P' => {
                    self.pos += 1;
                    let node: NodeRef = Node::unary(Kind::Protocol, context);
                    self.add_substitution(&node);
                    return Some(node);
                }
                b'0'..=b'9' => {
                    let nested: NodeRef = self.demangle_identifier_sub(Kind::Identifier)?;
                    context = Node::branch(Kind::OtherNominalType, vec![context, nested]);
                }
                b'_' if self.peek_at(1) == Some(b'p') => {
                    let node: NodeRef = Node::unary(Kind::Protocol, context);
                    self.add_substitution(&node);
                    return Some(node);
                }
                b'_' => {
                    self.pos += 1;
                    let nested: NodeRef = self.demangle_identifier_sub(Kind::Identifier)?;
                    context = Node::branch(Kind::OtherNominalType, vec![context, nested]);
                }
                b'M' | b'N' | b'W' | b'H' if context.kind == Kind::Module => {
                    return Some(context);
                }
                _ => return None,
            }
        }
    }

    fn demangle_bound_generic_args(&mut self, base: NodeRef) -> Option<NodeRef> {
        let mut args: Vec<NodeRef> = Vec::new();
        loop {
            self.depth = self.depth.checked_add(1)?;
            if self.depth > MAX_DEPTH {
                return None;
            }
            match self.peek() {
                Some(b'G') => {
                    self.pos += 1;
                    break;
                }
                Some(b'_') => {
                    self.pos += 1;
                }
                Some(b'S') if self.peek_at(1).is_some_and(|d: u8| d.is_ascii_digit()) => {
                    let repeated: Vec<NodeRef> = self.demangle_repeated_standard_substitution()?;
                    args.extend(repeated);
                }
                None => return None,
                _ => {
                    let arg: NodeRef = self.demangle_type()?;
                    args.push(arg);
                }
            }
        }
        let node: NodeRef = apply_bound_generic(base, args);
        self.add_substitution(&node);
        Some(node)
    }

    fn demangle_repeated_standard_substitution(&mut self) -> Option<Vec<NodeRef>> {
        self.pos += 1;
        let count: u32 = self.demangle_natural();
        if count == 0 || count > MAX_REPEAT_COUNT {
            return None;
        }
        let letter: u8 = self.next()?;
        let node: NodeRef = standard_substitution_node(letter)?;
        Some((0..count).map(|_| Rc::clone(&node)).collect())
    }

    fn demangle_standard_substitution(&mut self) -> Option<NodeRef> {
        if self.peek_at(1).is_some_and(|d: u8| d.is_ascii_digit()) {
            let nodes: Vec<NodeRef> = self.demangle_repeated_standard_substitution()?;
            let mut it: std::vec::IntoIter<NodeRef> = nodes.into_iter();
            let first: NodeRef = it.next()?;
            self.pending_substitutions.extend(it);
            return Some(first);
        }
        self.pos += 1;
        let c: u8 = self.next()?;
        if c == b'o' || c == b'C' {
            let module: NodeRef = Node::leaf(Kind::Module, "__C".to_owned());
            return self.demangle_nominal_in_context(module);
        }
        let base: NodeRef = if c == b'c' {
            let letter: u8 = self.next()?;
            concurrency_substitution_node(letter)?
        } else {
            standard_substitution_node(c)?
        };
        if self.peek_is_nested_nominal() {
            return self.demangle_nominal_in_context(base);
        }
        Some(base)
    }

    fn peek_is_nested_nominal(&mut self) -> bool {
        if !self.peek().is_some_and(|c: u8| c.is_ascii_digit()) {
            return false;
        }
        let cp: Checkpoint = self.checkpoint();
        let has_id: bool = self.demangle_identifier(Kind::Identifier).is_some();
        let nested: bool = has_id
            && (matches!(self.peek(), Some(b'C' | b'V' | b'O' | b'a' | b'P'))
                || (self.peek() == Some(b'_') && self.peek_at(1) == Some(b'p')));
        self.restore(cp);
        nested
    }

    fn demangle_builtin_type(&mut self) -> Option<NodeRef> {
        self.pos += 1;
        let c: u8 = self.next()?;
        let name: String = match c {
            b'i' => {
                let width: u32 = self.demangle_natural();
                self.next_if(b'_');
                format!("Builtin.Int{width}")
            }
            b'f' => {
                let width: u32 = self.demangle_natural();
                self.next_if(b'_');
                format!("Builtin.FPIEEE{width}")
            }
            b'w' => "Builtin.Word".to_owned(),
            b'o' => "Builtin.NativeObject".to_owned(),
            b'p' => "Builtin.RawPointer".to_owned(),
            b'b' => "Builtin.BridgeObject".to_owned(),
            b'B' => "Builtin.UnsafeValueBuffer".to_owned(),
            b'O' => "Builtin.UnknownObject".to_owned(),
            b'P' => "Builtin.PackIndex".to_owned(),
            b't' => "Builtin.SILToken".to_owned(),
            b'd' => "Builtin.NonDefaultDistributedActorStorage".to_owned(),
            b'j' => "Builtin.Job".to_owned(),
            b'c' => "Builtin.RawUnsafeContinuation".to_owned(),
            _ => "Builtin".to_owned(),
        };
        Some(Node::leaf(Kind::Structure, name))
    }

    fn demangle_substitution(&mut self) -> Option<NodeRef> {
        self.pos += 1;
        let mut repeat: i64 = -1;
        loop {
            let c: u8 = self.peek()?;
            if c == b'_' {
                self.pos += 1;
                let idx: usize = usize::try_from(repeat.checked_add(27)?).ok()?;
                return self.substitutions.get(idx).cloned();
            }
            if c.is_ascii_lowercase() {
                self.pos += 1;
                let idx: usize = (c - b'a') as usize;
                let node: NodeRef = self.substitutions.get(idx).cloned()?;
                let count: i64 = repeat.max(1);
                for _ in 1..count {
                    self.spend()?;
                    self.pending_substitutions.push(Rc::clone(&node));
                }
                repeat = -1;
                continue;
            }
            if c.is_ascii_uppercase() {
                self.pos += 1;
                let idx: usize = (c - b'A') as usize;
                let node: NodeRef = self.substitutions.get(idx).cloned()?;
                let count: i64 = repeat.max(1);
                for _ in 1..count {
                    self.spend()?;
                    self.pending_substitutions.push(Rc::clone(&node));
                }
                return Some(node);
            }
            if c.is_ascii_digit() {
                repeat = i64::from(self.demangle_natural());
                if repeat <= 0 || repeat > i64::from(MAX_REPEAT_COUNT) {
                    return None;
                }
                if !self.peek().is_some_and(|d: u8| d.is_ascii_alphabetic()) {
                    return None;
                }
                continue;
            }
            return None;
        }
    }

    fn demangle_natural(&mut self) -> u32 {
        let mut value: u32 = 0;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                value = value.saturating_mul(10).saturating_add(u32::from(c - b'0'));
                self.pos += 1;
            } else {
                break;
            }
        }
        value
    }

    fn demangle_index(&mut self) -> Option<u32> {
        if self.next_if(b'_') {
            return Some(0);
        }
        let n: u32 = self.demangle_natural();
        if !self.next_if(b'_') {
            return None;
        }
        n.checked_add(1)
    }

    fn demangle_v0_generic_param_index(&mut self) -> Option<(u32, u32)> {
        match self.peek()? {
            b'z' | b's' => {
                self.pos += 1;
                Some((0, 0))
            }
            b'd' => {
                self.pos += 1;
                let depth: u32 = self.demangle_index()?.checked_add(1)?;
                let idx: u32 = self.demangle_index()?;
                Some((depth, idx))
            }
            _ => {
                let idx: u32 = self.demangle_index()?.checked_add(1)?;
                Some((0, idx))
            }
        }
    }

    fn demangle_generic_signature(&mut self) -> Option<NodeRef> {
        let mut requirements: Vec<NodeRef> = Vec::new();
        let mut pack_markers: Vec<NodeRef> = Vec::new();
        let mut param_counts: Vec<u32> = Vec::new();
        let mut multi_param: bool = false;
        let mut constraint: Option<NodeRef> = None;
        let mut associated_name: Option<NodeRef> = None;
        loop {
            self.depth = self.depth.checked_add(1)?;
            if self.depth > MAX_DEPTH {
                return None;
            }
            match self.peek()? {
                b'l' => {
                    self.pos += 1;
                    break;
                }
                b'r' => {
                    self.pos += 1;
                    multi_param = true;
                    loop {
                        match self.peek()? {
                            b'l' => {
                                self.pos += 1;
                                break;
                            }
                            b'z' => {
                                self.pos += 1;
                                param_counts.push(0);
                            }
                            c if c.is_ascii_digit() => {
                                let n: u32 = self.demangle_index()?;
                                param_counts.push(n.checked_add(1)?);
                            }
                            _ => return None,
                        }
                    }
                    break;
                }
                b'R' => {
                    self.pos += 1;
                    if self.next_if(b'v') {
                        let (depth, idx): (u32, u32) = self.demangle_v0_generic_param_index()?;
                        pack_markers.push(Node::unary(
                            Kind::DependentGenericParamPackMarker,
                            make_generic_param(depth, idx),
                        ));
                        continue;
                    }
                    let lhs: NodeRef = constraint.take()?;
                    let req: NodeRef =
                        self.demangle_generic_requirement(lhs, associated_name.take())?;
                    requirements.push(req);
                }
                b'v' => {
                    self.pos += 1;
                    self.demangle_v0_generic_param_index()?;
                }
                _ => {
                    if constraint.is_some() {
                        let cp: Checkpoint = self.checkpoint();
                        let candidate: Option<NodeRef> = match self.peek() {
                            Some(c) if c.is_ascii_digit() => {
                                self.demangle_identifier(Kind::Identifier)
                            }
                            Some(b'A') => self.demangle_substitution(),
                            _ => None,
                        };
                        if candidate.is_some() && self.peek() == Some(b'R') {
                            associated_name = candidate;
                            continue;
                        }
                        self.restore(cp);
                    }
                    constraint = Some(self.demangle_constraint()?);
                }
            }
        }
        if constraint.is_some() || associated_name.is_some() {
            return None;
        }
        let param_count: u32 = if param_counts.is_empty() {
            u32::from(!multi_param)
        } else {
            param_counts.iter().copied().sum()
        };
        let counts_node: NodeRef =
            Node::leaf(Kind::DependentGenericParamCount, param_count.to_string());
        let mut children: Vec<NodeRef> =
            Vec::with_capacity(1 + pack_markers.len() + requirements.len());
        children.push(counts_node);
        children.extend(pack_markers);
        children.extend(requirements);
        Some(Node::branch(Kind::DependentGenericSignature, children))
    }

    fn demangle_constraint(&mut self) -> Option<NodeRef> {
        match self.peek()? {
            b'0'..=b'9' => {
                let cp: Checkpoint = self.checkpoint();
                if self.demangle_identifier(Kind::Identifier).is_some() && self.peek() == Some(b'Q')
                {
                    self.restore(cp);
                    return self.demangle_type();
                }
                self.restore(cp);
                let module: NodeRef = self.demangle_identifier(Kind::Module)?;
                self.add_substitution(&module);
                self.demangle_constraint_in_context(module)
            }
            b's' => {
                self.pos += 1;
                let module: NodeRef = Node::leaf(Kind::Module, "Swift".to_owned());
                self.demangle_constraint_in_context(module)
            }
            b'A' => {
                let base: NodeRef = self.demangle_substitution()?;
                if self.peek() == Some(b'Q') {
                    return self.demangle_associated_type_standalone(base);
                }
                if matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.demangle_protocol_in_context(base)
                } else {
                    Some(base)
                }
            }
            _ => self.demangle_type(),
        }
    }

    fn demangle_constraint_in_context(&mut self, context: NodeRef) -> Option<NodeRef> {
        let cp: Checkpoint = self.checkpoint();
        if let Some(nominal) = self.demangle_nominal_in_context(context.clone()) {
            return Some(nominal);
        }
        self.restore(cp);
        self.demangle_protocol_in_context(context)
    }

    fn demangle_protocol_in_context(&mut self, context: NodeRef) -> Option<NodeRef> {
        let name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
        let path: NodeRef = Node::branch(Kind::OtherNominalType, vec![context, name]);
        self.next_if(b'P');
        let node: NodeRef = Node::unary(Kind::Protocol, path);
        self.add_substitution(&node);
        Some(node)
    }

    fn demangle_generic_requirement(
        &mut self,
        lhs: NodeRef,
        associated_name: Option<NodeRef>,
    ) -> Option<NodeRef> {
        match self.peek()? {
            b'l' | b'm' => {
                let is_assoc: bool = self.peek() == Some(b'm');
                self.pos += 1;
                if is_assoc {
                    self.demangle_identifier(Kind::Identifier)?;
                }
                let _ = &lhs;
                let constrained: NodeRef = self.requirement_subject()?;
                let layout: &str = self.demangle_layout_constraint()?;
                Some(Node::branch(
                    Kind::DependentGenericLayoutRequirement,
                    vec![constrained, Node::leaf(Kind::Identifier, layout.to_owned())],
                ))
            }
            b's' => {
                self.pos += 1;
                let constrained: NodeRef = self.requirement_subject()?;
                Some(Node::branch(
                    Kind::DependentGenericSameTypeRequirement,
                    vec![constrained, lhs],
                ))
            }
            b't' => {
                self.pos += 1;
                let subject: NodeRef = self.requirement_member_subject(associated_name)?;
                Some(Node::branch(
                    Kind::DependentGenericSameTypeRequirement,
                    vec![subject, lhs],
                ))
            }
            b'b' => {
                self.pos += 1;
                let constrained: NodeRef = self.requirement_subject()?;
                Some(Node::branch(
                    Kind::DependentGenericConformanceRequirement,
                    vec![constrained, lhs],
                ))
            }
            b'p' => {
                self.pos += 1;
                let assoc: NodeRef = match associated_name {
                    Some(name) => name,
                    None => self.demangle_identifier(Kind::Identifier)?,
                };
                let (depth, idx): (u32, u32) = self.demangle_v0_generic_param_index()?;
                let base: NodeRef = make_generic_param(depth, idx);
                let member: NodeRef = Node::branch(Kind::DependentMemberType, vec![base, assoc]);
                Some(Node::branch(
                    Kind::DependentGenericConformanceRequirement,
                    vec![member, lhs],
                ))
            }
            b'S' if self.peek_at(1) == Some(b'A') => {
                self.pos += 1;
                let rhs: NodeRef = self.demangle_substitution()?;
                Some(Node::branch(
                    Kind::DependentGenericSameTypeRequirement,
                    vec![rhs, lhs],
                ))
            }
            b'B' if self.peek_at(1) == Some(b'A') => {
                self.pos += 1;
                let rhs: NodeRef = self.demangle_substitution()?;
                Some(Node::branch(
                    Kind::DependentGenericConformanceRequirement,
                    vec![rhs, lhs],
                ))
            }
            _ => {
                let constrained: NodeRef = self.requirement_subject()?;
                Some(Node::branch(
                    Kind::DependentGenericConformanceRequirement,
                    vec![constrained, lhs],
                ))
            }
        }
    }

    fn requirement_subject(&mut self) -> Option<NodeRef> {
        let (depth, idx): (u32, u32) = self.demangle_v0_generic_param_index()?;
        Some(make_generic_param(depth, idx))
    }

    fn requirement_member_subject(&mut self, associated_name: Option<NodeRef>) -> Option<NodeRef> {
        let (depth, idx): (u32, u32) = self.demangle_v0_generic_param_index()?;
        let base: NodeRef = make_generic_param(depth, idx);
        match associated_name {
            Some(name) => Some(Node::branch(Kind::DependentMemberType, vec![base, name])),
            None => Some(base),
        }
    }

    fn demangle_layout_constraint(&mut self) -> Option<&'static str> {
        let c: u8 = self.next()?;
        let name: &str = match c {
            b'N' => "_NativeRefCountedObject",
            b'R' => "_RefCountedObject",
            b'T' => "_Trivial",
            b'C' => "_Class",
            b'D' => "_NativeClass",
            b'U' => "_UnknownLayout",
            b'B' => "_BridgeObject",
            b'S' => "_TrivialStride",
            b'E' | b'e' => {
                self.demangle_index()?;
                if c == b'E' {
                    self.demangle_index()?;
                }
                "_Trivial"
            }
            b'M' | b'm' => {
                self.demangle_index()?;
                if c == b'M' {
                    self.demangle_index()?;
                }
                "_TrivialAtMost"
            }
            _ => return None,
        };
        Some(name)
    }

    fn demangle_identifier(&mut self, kind: Kind) -> Option<NodeRef> {
        self.spend()?;
        let c: u8 = self.peek()?;
        if !c.is_ascii_digit() {
            return None;
        }
        let mut has_word_substs: bool = false;
        let mut is_punycoded: bool = false;
        if c == b'0' {
            self.pos += 1;
            if self.peek() == Some(b'0') {
                self.pos += 1;
                is_punycoded = true;
            } else {
                has_word_substs = true;
            }
        }
        let mut identifier: String = String::new();
        loop {
            while has_word_substs && self.peek().is_some_and(|b: u8| b.is_ascii_alphabetic()) {
                let letter: u8 = self.next()?;
                let word_idx: usize = if letter.is_ascii_lowercase() {
                    (letter - b'a') as usize
                } else {
                    has_word_substs = false;
                    (letter - b'A') as usize
                };
                let word: &String = self.words.get(word_idx)?;
                identifier.push_str(word);
            }
            if self.next_if(b'0') {
                break;
            }
            let num_chars: usize = self.demangle_natural() as usize;
            if num_chars == 0 {
                return None;
            }
            if is_punycoded {
                self.next_if(b'_');
            }
            let end: usize = self.pos.checked_add(num_chars)?;
            let raw: &[u8] = self.src.get(self.pos..end)?;
            let slice: String = if is_punycoded {
                decode_swift_punycode(raw)?
            } else {
                let decoded: String = String::from_utf8_lossy(raw).into_owned();
                record_words(&decoded, &mut self.words);
                decoded
            };
            identifier.push_str(&slice);
            self.pos = end;
            if !has_word_substs {
                break;
            }
        }
        if identifier.is_empty() {
            return None;
        }
        Some(Node::leaf(kind, identifier))
    }

    fn demangle_identifier_sub(&mut self, kind: Kind) -> Option<NodeRef> {
        let node: NodeRef = self.demangle_identifier(kind)?;
        self.add_substitution(&node);
        Some(node)
    }
}

const PUNYCODE_BASE: u32 = 36;
const PUNYCODE_TMIN: u32 = 1;
const PUNYCODE_TMAX: u32 = 26;
const PUNYCODE_SKEW: u32 = 38;
const PUNYCODE_DAMP: u32 = 700;
const PUNYCODE_INITIAL_BIAS: u32 = 72;
const PUNYCODE_INITIAL_N: u32 = 128;
const PUNYCODE_MAX_OUTPUT: usize = 4096;

const fn punycode_digit(value: u8) -> Option<u32> {
    if value.is_ascii_lowercase() {
        Some((value - b'a') as u32)
    } else if value >= b'A' && value <= b'J' {
        Some((value - b'A') as u32 + 26)
    } else {
        None
    }
}

fn punycode_adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
    delta = if first_time {
        delta / PUNYCODE_DAMP
    } else {
        delta / 2
    };
    delta = delta.saturating_add(delta / num_points.max(1));
    let mut k: u32 = 0;
    while delta > ((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) / 2 {
        delta /= PUNYCODE_BASE - PUNYCODE_TMIN;
        k = k.saturating_add(PUNYCODE_BASE);
    }
    k.saturating_add(((PUNYCODE_BASE - PUNYCODE_TMIN + 1) * delta) / (delta + PUNYCODE_SKEW))
}

fn punycode_valid_scalar(value: u32) -> bool {
    value < 0xD880 || (0xE000..=0x0010_FFFF).contains(&value)
}

fn decode_swift_punycode(input: &[u8]) -> Option<String> {
    if !input.is_ascii() {
        return None;
    }
    let mut output: Vec<u32> = Vec::new();
    let basic_end: usize = input
        .iter()
        .rposition(|&b: &u8| b == b'_')
        .map_or(0, |p: usize| {
            for &b in &input[..p] {
                output.push(u32::from(b));
            }
            p + 1
        });
    let mut n: u32 = PUNYCODE_INITIAL_N;
    let mut i: u32 = 0;
    let mut bias: u32 = PUNYCODE_INITIAL_BIAS;
    let mut cursor: usize = basic_end;
    while cursor < input.len() {
        if output.len() >= PUNYCODE_MAX_OUTPUT {
            return None;
        }
        let old_i: u32 = i;
        let mut weight: u32 = 1;
        let mut k: u32 = PUNYCODE_BASE;
        loop {
            let digit: u32 = punycode_digit(*input.get(cursor)?)?;
            cursor += 1;
            i = i.checked_add(digit.checked_mul(weight)?)?;
            let threshold: u32 = if k <= bias {
                PUNYCODE_TMIN
            } else if k >= bias + PUNYCODE_TMAX {
                PUNYCODE_TMAX
            } else {
                k - bias
            };
            if digit < threshold {
                break;
            }
            weight = weight.checked_mul(PUNYCODE_BASE - threshold)?;
            k = k.checked_add(PUNYCODE_BASE)?;
        }
        let out_len: u32 = u32::try_from(output.len()).ok()?.checked_add(1)?;
        bias = punycode_adapt(i - old_i, out_len, old_i == 0);
        n = n.checked_add(i / out_len)?;
        i %= out_len;
        if !punycode_valid_scalar(n) {
            return None;
        }
        let scalar: u32 = if (0xD800..0xD880).contains(&n) {
            n - 0xD800
        } else {
            n
        };
        output.insert(i as usize, scalar);
        i += 1;
    }
    let mut decoded: String = String::with_capacity(output.len());
    for value in output {
        decoded.push(char::from_u32(value)?);
    }
    Some(decoded)
}

fn record_words(slice: &str, words: &mut Vec<String>) {
    const MAX_WORDS: usize = 26;
    let bytes: &[u8] = slice.as_bytes();
    let mut word_start: Option<usize> = None;
    let len: usize = bytes.len();
    for idx in 0..=len {
        let c: u8 = if idx < len { bytes[idx] } else { 0 };
        let prev: u8 = if idx > 0 { bytes[idx - 1] } else { 0 };
        if let Some(start) = word_start
            && is_word_end(c, prev)
        {
            if idx - start >= 2 && words.len() < MAX_WORDS {
                words.push(slice[start..idx].to_owned());
            }
            word_start = None;
        }
        if word_start.is_none() && is_word_start(c) {
            word_start = Some(idx);
        }
    }
}

const fn nominal_kind_for_tag(tag: u8) -> Kind {
    match tag {
        b'C' => Kind::Class,
        b'V' => Kind::Structure,
        b'O' => Kind::Enum,
        b'a' => Kind::TypeAlias,
        _ => Kind::OtherNominalType,
    }
}

#[inline]
const fn is_word_start(c: u8) -> bool {
    !c.is_ascii_digit() && c != b'_' && c != 0
}

#[inline]
const fn is_word_end(c: u8, prev: u8) -> bool {
    if c == b'_' || c == 0 {
        return true;
    }
    !prev.is_ascii_uppercase() && c.is_ascii_uppercase()
}

fn generic_param_name(depth: u32, idx: u32) -> String {
    let letter: char = char::from(b'A' + (idx % 26) as u8);
    let base: String = if idx < 26 {
        letter.to_string()
    } else {
        format!("{letter}{}", idx / 26)
    };
    if depth == 0 {
        base
    } else {
        format!("{base}{depth}")
    }
}

const fn standard_substitution(c: u8) -> Option<(&'static str, &'static str, Kind)> {
    let entry: (&str, &str, Kind) = match c {
        b'A' => (
            "Swift",
            "AutoreleasingUnsafeMutablePointer",
            Kind::Structure,
        ),
        b'a' => ("Swift", "Array", Kind::Structure),
        b'b' => ("Swift", "Bool", Kind::Structure),
        b'c' => ("Swift", "UnsafeContinuation", Kind::Structure),
        b'D' => ("Swift", "Dictionary", Kind::Structure),
        b'd' => ("Swift", "Double", Kind::Structure),
        b'f' => ("Swift", "Float", Kind::Structure),
        b'h' => ("Swift", "Set", Kind::Structure),
        b'I' => ("Swift", "DefaultIndices", Kind::Structure),
        b'i' => ("Swift", "Int", Kind::Structure),
        b'J' => ("Swift", "Character", Kind::Structure),
        b'N' => ("Swift", "ClosedRange", Kind::Structure),
        b'n' => ("Swift", "Range", Kind::Structure),
        b'O' => ("Swift", "ObjectIdentifier", Kind::Structure),
        b'P' => ("Swift", "UnsafePointer", Kind::Structure),
        b'p' => ("Swift", "UnsafeMutablePointer", Kind::Structure),
        b'q' => ("Swift", "Optional", Kind::Enum),
        b'R' => ("Swift", "UnsafeBufferPointer", Kind::Structure),
        b'r' => ("Swift", "UnsafeMutableBufferPointer", Kind::Structure),
        b'S' => ("Swift", "String", Kind::Structure),
        b's' => ("Swift", "Substring", Kind::Structure),
        b'u' => ("Swift", "UInt", Kind::Structure),
        b'V' => ("Swift", "UnsafeRawPointer", Kind::Structure),
        b'v' => ("Swift", "UnsafeMutableRawPointer", Kind::Structure),
        b'W' => ("Swift", "UnsafeRawBufferPointer", Kind::Structure),
        b'w' => ("Swift", "UnsafeMutableRawBufferPointer", Kind::Structure),
        b'B' => ("Swift", "BinaryFloatingPoint", Kind::Protocol),
        b'E' => ("Swift", "Encodable", Kind::Protocol),
        b'e' => ("Swift", "Decodable", Kind::Protocol),
        b'F' => ("Swift", "FloatingPoint", Kind::Protocol),
        b'G' => ("Swift", "RandomNumberGenerator", Kind::Protocol),
        b'H' => ("Swift", "Hashable", Kind::Protocol),
        b'j' => ("Swift", "Numeric", Kind::Protocol),
        b'K' => ("Swift", "BidirectionalCollection", Kind::Protocol),
        b'k' => ("Swift", "RandomAccessCollection", Kind::Protocol),
        b'L' => ("Swift", "Comparable", Kind::Protocol),
        b'l' => ("Swift", "Collection", Kind::Protocol),
        b'M' => ("Swift", "MutableCollection", Kind::Protocol),
        b'm' => ("Swift", "RangeReplaceableCollection", Kind::Protocol),
        b'Q' => ("Swift", "Equatable", Kind::Protocol),
        b'T' => ("Swift", "Sequence", Kind::Protocol),
        b't' => ("Swift", "IteratorProtocol", Kind::Protocol),
        b'U' => ("Swift", "UnsignedInteger", Kind::Protocol),
        b'X' => ("Swift", "RangeExpression", Kind::Protocol),
        b'x' => ("Swift", "Strideable", Kind::Protocol),
        b'Y' => ("Swift", "RawRepresentable", Kind::Protocol),
        b'y' => ("Swift", "StringProtocol", Kind::Protocol),
        b'Z' => ("Swift", "SignedInteger", Kind::Protocol),
        b'z' => ("Swift", "BinaryInteger", Kind::Protocol),
        _ => return None,
    };
    Some(entry)
}

const fn concurrency_substitution(c: u8) -> Option<(&'static str, &'static str, Kind)> {
    let entry: (&str, &str, Kind) = match c {
        b'A' => ("Swift", "Actor", Kind::Protocol),
        b'C' => ("Swift", "CheckedContinuation", Kind::Structure),
        b'c' => ("Swift", "UnsafeContinuation", Kind::Structure),
        b'E' => ("Swift", "CancellationError", Kind::Structure),
        b'e' => ("Swift", "UnownedSerialExecutor", Kind::Structure),
        b'F' => ("Swift", "Executor", Kind::Protocol),
        b'f' => ("Swift", "SerialExecutor", Kind::Protocol),
        b'G' => ("Swift", "TaskGroup", Kind::Structure),
        b'g' => ("Swift", "ThrowingTaskGroup", Kind::Structure),
        b'I' => ("Swift", "AsyncIteratorProtocol", Kind::Protocol),
        b'i' => ("Swift", "AsyncSequence", Kind::Protocol),
        b'J' => ("Swift", "UnownedJob", Kind::Structure),
        b'M' => ("Swift", "MainActor", Kind::Structure),
        b'P' => ("Swift", "TaskPriority", Kind::Structure),
        b'S' => ("Swift", "AsyncStream", Kind::Structure),
        b's' => ("Swift", "AsyncThrowingStream", Kind::Structure),
        b'T' => ("Swift", "Task", Kind::Structure),
        b't' => ("Swift", "UnsafeCurrentTask", Kind::Structure),
        _ => return None,
    };
    Some(entry)
}

fn concurrency_substitution_node(letter: u8) -> Option<NodeRef> {
    let (module, name, kind): (&str, &str, Kind) = concurrency_substitution(letter)?;
    let module_node: NodeRef = Node::leaf(Kind::Module, module.to_owned());
    let nested: NodeRef = Node::branch(
        Kind::OtherNominalType,
        vec![module_node, Node::leaf(Kind::Identifier, name.to_owned())],
    );
    Some(Node::unary(kind, nested))
}

fn standard_substitution_node(letter: u8) -> Option<NodeRef> {
    let (module, name, kind): (&str, &str, Kind) = standard_substitution(letter)?;
    let module_node: NodeRef = Node::leaf(Kind::Module, module.to_owned());
    let nested: NodeRef = Node::branch(
        Kind::OtherNominalType,
        vec![module_node, Node::leaf(Kind::Identifier, name.to_owned())],
    );
    Some(Node::unary(kind, nested))
}

fn build_function(
    context: NodeRef,
    name: NodeRef,
    labels: Option<NodeRef>,
    signature: Option<NodeRef>,
    generic_sig: Option<NodeRef>,
) -> NodeRef {
    let mut children: Vec<NodeRef> = Vec::with_capacity(5);
    children.push(context);
    children.push(name);
    if let Some(sig) = signature {
        children.push(sig);
    }
    if let Some(gsig) = generic_sig {
        children.push(gsig);
    }
    if let Some(label_list) = labels {
        children.push(label_list);
    }
    Node::branch(Kind::Function, children)
}

fn decode_operator_chars(encoded: &str) -> Option<String> {
    const OP_CHARS: &[u8] = b"& @/= >    <*!|+?%-~   ^ .";
    let mut out: String = String::with_capacity(encoded.len());
    for b in encoded.bytes() {
        if b.is_ascii_lowercase() {
            let idx: usize = (b - b'a') as usize;
            let mapped: u8 = *OP_CHARS.get(idx)?;
            if mapped == b' ' {
                return None;
            }
            out.push(char::from(mapped));
        } else if b == b'_' {
            out.push('_');
        } else {
            return None;
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn build_init(
    kind: Kind,
    context: NodeRef,
    signature: Option<NodeRef>,
    labels: Option<NodeRef>,
) -> NodeRef {
    let mut children: Vec<NodeRef> = Vec::with_capacity(3);
    children.push(context);
    if let Some(sig) = signature {
        children.push(sig);
    }
    if let Some(label_list) = labels {
        children.push(label_list);
    }
    Node::branch(kind, children)
}

fn attach_generic(node: NodeRef, generic: Option<NodeRef>) -> NodeRef {
    match generic {
        Some(g) => {
            let mut children: Vec<NodeRef> = node.children.clone();
            children.push(g);
            Rc::new(Node {
                kind: node.kind,
                text: node.text.clone(),
                children,
            })
        }
        None => node,
    }
}

fn build_subscript(
    context: NodeRef,
    signature: Option<NodeRef>,
    labels: Option<NodeRef>,
) -> NodeRef {
    let mut children: Vec<NodeRef> = Vec::with_capacity(3);
    children.push(context);
    if let Some(sig) = signature {
        children.push(sig);
    }
    if let Some(label_list) = labels {
        children.push(label_list);
    }
    Node::branch(Kind::Subscript, children)
}

fn make_generic_param(depth: u32, idx: u32) -> NodeRef {
    Node::leaf(
        Kind::DependentGenericParamType,
        generic_param_name(depth, idx),
    )
}

fn make_function_type(params: NodeRef, result: NodeRef, convention: FunctionConvention) -> NodeRef {
    let mut children: Vec<NodeRef> = Vec::with_capacity(3);
    if let Some(annotation) = convention.annotation() {
        children.push(Node::leaf(
            Kind::ConventionAnnotation,
            annotation.to_owned(),
        ));
    }
    children.push(Node::unary(Kind::ArgumentTuple, params));
    children.push(Node::unary(Kind::ReturnType, result));
    Node::branch(Kind::FunctionType, children)
}

fn make_function_type_full(
    params: NodeRef,
    result: NodeRef,
    convention: FunctionConvention,
    annotations: Vec<NodeRef>,
) -> NodeRef {
    let mut children: Vec<NodeRef> = Vec::with_capacity(3 + annotations.len());
    if let Some(annotation) = convention.annotation() {
        children.push(Node::leaf(
            Kind::ConventionAnnotation,
            annotation.to_owned(),
        ));
    }
    children.push(Node::unary(Kind::ArgumentTuple, params));
    children.push(Node::unary(Kind::ReturnType, result));
    children.extend(annotations);
    Node::branch(Kind::FunctionType, children)
}

fn apply_bound_generic(base: NodeRef, args: Vec<NodeRef>) -> NodeRef {
    if let Some(name) = nominal_full_name(&base) {
        if name == "Swift.Array" && args.len() == 1 {
            return Node::unary(Kind::Array, args.into_iter().next().unwrap_or(base));
        }
        if name == "Swift.Optional" && args.len() == 1 {
            return Node::unary(Kind::Optional, args.into_iter().next().unwrap_or(base));
        }
        if name == "Swift.Dictionary" && args.len() == 2 {
            let mut it: std::vec::IntoIter<NodeRef> = args.into_iter();
            let k: NodeRef = it.next().unwrap_or_else(|| base.clone());
            let v: NodeRef = it.next().unwrap_or(base);
            return Node::branch(Kind::Dictionary, vec![k, v]);
        }
    }
    let kind: Kind = match base.kind {
        Kind::Class => Kind::BoundGenericClass,
        Kind::Structure => Kind::BoundGenericStructure,
        Kind::Enum => Kind::BoundGenericEnum,
        _ => Kind::BoundGenericOther,
    };
    let mut children: Vec<NodeRef> = Vec::with_capacity(1 + args.len());
    children.push(base);
    children.extend(args);
    Node::branch(kind, children)
}

fn nominal_full_name(node: &Node) -> Option<String> {
    match node.kind {
        Kind::Class
        | Kind::Structure
        | Kind::Enum
        | Kind::Protocol
        | Kind::TypeAlias
        | Kind::OtherNominalType => Some(print_context_path(node)),
        _ => None,
    }
}

const fn is_conformance_subject_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Class
            | Kind::Structure
            | Kind::Enum
            | Kind::OtherNominalType
            | Kind::BoundGenericClass
            | Kind::BoundGenericStructure
            | Kind::BoundGenericEnum
            | Kind::BoundGenericOther
            | Kind::Array
            | Kind::Dictionary
            | Kind::Optional
    )
}

const fn is_context_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Class
            | Kind::Structure
            | Kind::Enum
            | Kind::Protocol
            | Kind::TypeAlias
            | Kind::OtherNominalType
            | Kind::ExtensionContext
            | Kind::Module
    )
}

fn print_context_path(node: &Node) -> String {
    match node.kind {
        Kind::Module | Kind::Identifier => node.text.clone().unwrap_or_default(),
        Kind::Class | Kind::Structure | Kind::Enum | Kind::Protocol | Kind::TypeAlias => {
            node.children.first().map_or_else(
                || node.text.clone().unwrap_or_default(),
                |c: &NodeRef| print_context_path(c),
            )
        }
        Kind::OtherNominalType => {
            let parts: Vec<String> = node
                .children
                .iter()
                .map(|c: &NodeRef| print_context_path(c))
                .filter(|s: &String| !s.is_empty())
                .collect();
            parts.join(".")
        }
        Kind::ExtensionContext => {
            let module: String = node
                .children
                .first()
                .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
            let base: String = node
                .children
                .get(1)
                .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
            let generic: String = node
                .children
                .get(2)
                .filter(|c: &&NodeRef| c.kind == Kind::DependentGenericSignature)
                .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type));
            format!("(extension in {module}):{base}{generic}")
        }
        Kind::ProtocolConformanceContext => node
            .children
            .get(1)
            .map_or_else(String::new, |c: &NodeRef| print_context_path(c)),
        _ => print_node(node, Mode::Type),
    }
}

const fn value_witness_name(first: u8, second: u8) -> Option<&'static str> {
    let name: &'static str = match [first, second] {
        [b'a', b'l'] => "allocateBuffer",
        [b'c', b'a'] => "assignWithCopy",
        [b't', b'a'] => "assignWithTake",
        [b'd', b'e'] => "deallocateBuffer",
        [b'x', b'x'] => "destroy",
        [b'X', b'X'] => "destroyBuffer",
        [b'X', b'x'] => "destroyArray",
        [b'C', b'P'] => "initializeBufferWithCopyOfBuffer",
        [b'C', b'p'] => "initializeBufferWithCopy",
        [b'c', b'p'] => "initializeWithCopy",
        [b'T', b'K'] => "initializeBufferWithTakeOfBuffer",
        [b'T', b'k'] => "initializeBufferWithTake",
        [b't', b'k'] => "initializeWithTake",
        [b'C', b'c'] => "initializeArrayWithCopy",
        [b'T', b't'] => "initializeArrayWithTakeFrontToBack",
        [b't', b'T'] => "initializeArrayWithTakeBackToFront",
        [b'p', b'r'] => "projectBuffer",
        [b'x', b's'] => "storeExtraInhabitant",
        [b'x', b'g'] => "getExtraInhabitantIndex",
        [b'u', b'g'] => "getEnumTag",
        [b'u', b'p'] => "destructiveProjectEnumData",
        [b'u', b'i'] => "destructiveInjectEnumTag",
        [b'e', b't'] => "getEnumTagSinglePayload",
        [b's', b't'] => "storeEnumTagSinglePayload",
        _ => return None,
    };
    Some(name)
}

fn nominal_kind_suffix(kind: Kind, mode: Mode) -> &'static str {
    if mode == Mode::Type {
        return "";
    }
    match kind {
        Kind::Class => " (class)",
        Kind::Structure => " (struct)",
        Kind::Enum => " (enum)",
        Kind::Protocol => " (protocol)",
        _ => "",
    }
}

fn print_node(node: &Node, mode: Mode) -> String {
    match node.kind {
        Kind::Global => node
            .children
            .first()
            .map_or_else(String::new, |c: &NodeRef| print_node(c, mode)),
        Kind::Module
        | Kind::Identifier
        | Kind::DependentGenericParamType
        | Kind::DependentGenericParamCount
        | Kind::ThrowsAnnotation
        | Kind::ConventionAnnotation
        | Kind::AsyncAnnotation => node.text.clone().unwrap_or_default(),
        Kind::ValueWitness => format!(
            "{} value witness for {}",
            node.text.as_deref().unwrap_or_default(),
            print_child(node, 0)
        ),
        Kind::MergedFunction => node.children.first().map_or_else(
            || "merged ".to_owned(),
            |c: &NodeRef| format!("merged {}", print_node(c, Mode::Symbol)),
        ),
        Kind::Class | Kind::Structure | Kind::Enum | Kind::Protocol => {
            format!(
                "{}{}",
                print_context_path(node),
                nominal_kind_suffix(node.kind, mode)
            )
        }
        Kind::TypeAlias | Kind::OtherNominalType | Kind::ExtensionContext => {
            print_context_path(node)
        }
        Kind::BoundGenericClass
        | Kind::BoundGenericStructure
        | Kind::BoundGenericEnum
        | Kind::BoundGenericOther => print_bound_generic(node),
        Kind::Optional => format!("{}?", print_child_parenthesized(node, 0)),
        Kind::Array => format!("[{}]", print_child(node, 0)),
        Kind::Dictionary => format!("[{} : {}]", print_child(node, 0), print_child(node, 1)),
        Kind::Tuple => {
            let parts: Vec<String> = node
                .children
                .iter()
                .map(|c: &NodeRef| print_node(c, Mode::Type))
                .collect();
            format!("({})", parts.join(", "))
        }
        Kind::TupleElement => print_tuple_element(node),
        Kind::LabelList => String::new(),
        Kind::Metatype => {
            let representation: &str = node.text.as_deref().unwrap_or_default();
            let separator: &str = if representation.is_empty() { "" } else { " " };
            format!("{representation}{separator}{}.Type", print_child(node, 0))
        }
        Kind::ExistentialMetatype => format!("{}.Type", print_child(node, 0)),
        Kind::DependentGenericSignature => print_generic_signature(node),
        Kind::DependentGenericConformanceRequirement | Kind::DependentGenericLayoutRequirement => {
            format!("{}: {}", print_child(node, 0), print_child(node, 1))
        }
        Kind::DependentGenericSameTypeRequirement => {
            format!("{} == {}", print_child(node, 0), print_child(node, 1))
        }
        Kind::DependentMemberType | Kind::DependentAssociatedType => {
            format!("{}.{}", print_child(node, 0), print_child(node, 1))
        }
        Kind::InOut => format!("inout {}", print_child(node, 0)),
        Kind::Shared => format!("__shared {}", print_child(node, 0)),
        Kind::Owned => format!("__owned {}", print_child(node, 0)),
        Kind::AnyObjectExistential => "Swift.AnyObject".to_owned(),
        Kind::AssociatedTypeDescriptor => {
            let protocol: String = node
                .children
                .get(1)
                .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
            let assoc: String = print_child(node, 0);
            format!("associated type descriptor for {protocol}.{assoc}")
        }
        Kind::DispatchThunk => format!("dispatch thunk of {}", print_child(node, 0)),
        Kind::EnumCase => format!("enum case for {}", print_child(node, 0)),
        Kind::AssociatedConformanceDescriptor => {
            let conforming: String = node
                .children
                .first()
                .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
            let assoc_path: String = print_child(node, 1);
            let requirement: String = node
                .children
                .get(2)
                .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
            format!(
                "associated conformance descriptor for {conforming}.{assoc_path}: {requirement}"
            )
        }
        Kind::BaseConformanceDescriptor => {
            let base: String = node
                .children
                .first()
                .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
            let proto: String = print_child(node, 1);
            format!("base conformance descriptor for {base}: {proto}")
        }
        Kind::ProtocolConformanceDescriptorExt => print_conformance_descriptor(node),
        Kind::ConformanceWithGenericSig => print_conformance_with_generic_sig(node),
        Kind::ProtocolWitnessTableConformance => {
            print_conformance_record(node, "protocol witness table for")
        }
        Kind::ProtocolWitnessTablePatternConformance => {
            print_conformance_record(node, "protocol witness table pattern for")
        }
        Kind::Subscript => print_subscript(node),
        Kind::MaterializeForSet => print_accessor(node, "materializeForSet"),
        Kind::UnsafeAddressor => print_accessor(node, "unsafeAddressor"),
        Kind::UnsafeMutableAddressor => print_accessor(node, "unsafeMutableAddressor"),
        Kind::FunctionType => print_function_type(node),
        Kind::ImplFunctionType => print_impl_function_type(node),
        Kind::ImplParameter | Kind::ImplResult => {
            format!(
                "{} {}",
                node.text.as_deref().unwrap_or_default(),
                print_child(node, 0)
            )
        }
        Kind::ImplYield => format!(
            "@yields {} {}",
            node.text.as_deref().unwrap_or_default(),
            print_child(node, 0)
        ),
        Kind::ImplErrorResult => format!(
            "@error {} {}",
            node.text.as_deref().unwrap_or_default(),
            print_child(node, 0)
        ),
        Kind::ImplSendingResult => "sending".to_owned(),
        Kind::ImplPatternSubstitutions => format!(
            "@substituted {} for <{}>",
            print_child(node, 0),
            print_child(node, 1)
        ),
        Kind::ImplInvocationSubstitutions => format!("for <{}>", print_child(node, 0)),
        Kind::TypeList => node
            .children
            .iter()
            .map(|child: &NodeRef| print_node(child, Mode::Type))
            .collect::<Vec<String>>()
            .join(", "),
        Kind::ArgumentTuple => print_argument_tuple(node),
        Kind::ReturnType => print_child(node, 0),
        Kind::Function => print_function(node),
        Kind::Variable => print_variable(node),
        Kind::Static => format!("static {}", print_child(node, 0)),
        Kind::Allocator => print_init(node, allocator_suffix(node)),
        Kind::Constructor => print_init(node, ".init"),
        Kind::Destructor => format!("{}.deinit", context_first_path(node)),
        Kind::Deallocator => format!("{}.__deallocating_deinit", context_first_path(node)),
        Kind::Getter => print_accessor(node, "getter"),
        Kind::Setter => print_accessor(node, "setter"),
        Kind::ModifyAccessor => print_accessor(node, "modify"),
        Kind::ReadAccessor => print_accessor(node, "read"),
        Kind::TypeMetadata => format!("type metadata for {}", print_child(node, 0)),
        Kind::FullTypeMetadata => format!("full type metadata for {}", print_child(node, 0)),
        Kind::TypeMetadataAccessFunction => {
            format!("type metadata accessor for {}", print_child(node, 0))
        }
        Kind::NominalTypeDescriptor => {
            format!("nominal type descriptor for {}", print_child(node, 0))
        }
        Kind::TypeMetadataInstantiationCache => {
            format!(
                "type metadata instantiation cache for {}",
                print_child(node, 0)
            )
        }
        Kind::TypeMetadataInstantiationFunction => {
            format!(
                "type metadata instantiation function for {}",
                print_child(node, 0)
            )
        }
        Kind::TypeMetadataCompletionFunction => {
            format!(
                "type metadata completion function for {}",
                print_child(node, 0)
            )
        }
        Kind::TypeMetadataSingletonInitializationCache => {
            format!(
                "type metadata singleton initialization cache for {}",
                print_child(node, 0)
            )
        }
        Kind::OutlinedInitWithCopy => {
            format!("outlined init with copy of {}", print_child(node, 0))
        }
        Kind::OutlinedDestroy => format!("outlined destroy of {}", print_child(node, 0)),
        Kind::DefaultArgumentInitializer => format!(
            "default argument {} of {}",
            node.text.as_deref().unwrap_or_default(),
            print_child(node, 0)
        ),
        Kind::VariableInitializationExpression => {
            format!(
                "variable initialization expression of {}",
                print_child(node, 0)
            )
        }
        Kind::OneTimeInitializationFunction => {
            format!(
                "one-time initialization function for {}",
                print_child(node, 0)
            )
        }
        Kind::OneTimeInitializationToken => {
            format!("one-time initialization token for {}", print_child(node, 0))
        }
        Kind::MetadataInstantiationCache => {
            format!("metadata instantiation cache for {}", print_child(node, 0))
        }
        Kind::ProtocolConformanceContext => print_conformance_context_bare(node),
        Kind::ProtocolWitnessThunk => print_protocol_witness_thunk(node),
        Kind::PartialApplyForwarder => {
            format!("partial apply forwarder for {}", print_child(node, 0))
        }
        Kind::ReabstractionThunk => print_reabstraction_thunk(node, false),
        Kind::ReabstractionThunkHelper => print_reabstraction_thunk(node, true),
        Kind::ReabstractionThunkHelperWithSelf => print_reabstraction_thunk_with_self(node),
        Kind::ReabstractionThunkHelperWithGlobalActor => format!(
            "{} with global actor constraint {}",
            print_child(node, 0),
            print_child(node, 1)
        ),
        Kind::KeyPathThunk => print_keypath_thunk(node),
        Kind::LazyWitnessTableCacheVariable => {
            print_lazy_witness_accessor(node, "lazy protocol witness table cache variable")
        }
        Kind::LazyWitnessTableAccessor => {
            print_lazy_witness_accessor(node, "lazy protocol witness table accessor")
        }
        Kind::DistributedThunk => format!("distributed thunk {}", print_child(node, 0)),
        Kind::DistributedAccessor => {
            format!("distributed accessor for {}", print_child(node, 0))
        }
        Kind::ObjCAttribute => format!("@objc {}", print_child(node, 0)),
        Kind::NonObjCAttribute => format!("@nonobjc {}", print_child(node, 0)),
        Kind::Metaclass => format!("metaclass for {}", print_child(node, 0)),
        Kind::ClassMetadataBaseOffset => {
            format!("class metadata base offset for {}", print_child(node, 0))
        }
        Kind::GenericTypeMetadataPattern => {
            format!("generic type metadata pattern for {}", print_child(node, 0))
        }
        Kind::ProtocolDescriptor => format!("protocol descriptor for {}", print_child(node, 0)),
        Kind::ProtocolRequirementsBaseDescriptor => format!(
            "protocol requirements base descriptor for {}",
            print_child(node, 0)
        ),
        Kind::ProtocolConformanceDescriptor => format!(
            "protocol conformance descriptor for {}",
            print_child(node, 0)
        ),
        Kind::ProtocolWitnessTable => {
            format!("protocol witness table for {}", print_child(node, 0))
        }
        Kind::ProtocolWitnessTablePattern => {
            format!(
                "protocol witness table pattern for {}",
                print_child(node, 0)
            )
        }
        Kind::ValueWitnessTable => format!("value witness table for {}", print_child(node, 0)),
        Kind::ReflectionMetadataFieldDescriptor => {
            format!(
                "reflection metadata field descriptor {}",
                print_child(node, 0)
            )
        }
        Kind::FieldOffset => format!(
            "{}field offset for {}",
            node.text.as_deref().unwrap_or_default(),
            print_child(node, 0)
        ),
        Kind::MethodDescriptor => format!("method descriptor for {}", print_child(node, 0)),
        Kind::ModuleDescriptor => format!("module descriptor {}", print_child(node, 0)),
        Kind::ProtocolSelfConformanceWitnessTable => {
            format!(
                "protocol self-conformance witness table for {}",
                print_child(node, 0)
            )
        }
        Kind::PropertyDescriptor => format!("property descriptor for {}", print_child(node, 0)),
        Kind::GenericSpecialization => print_generic_specialization(node),
        Kind::IsolatedAnyAnnotation => "@isolated(any) ".to_owned(),
        Kind::GlobalActorAnnotation => format!("@{} ", print_child(node, 0)),
        Kind::NonisolatedCallerAnnotation => "nonisolated(nonsending) ".to_owned(),
        Kind::TypedThrowsAnnotation => format!(" throws({})", print_child(node, 0)),
        Kind::SendingResultAnnotation => "sending ".to_owned(),
        Kind::Isolated => format!("isolated {}", print_child(node, 0)),
        Kind::Sending => format!("sending {}", print_child(node, 0)),
        Kind::Variadic => format!("{}...", print_child(node, 0)),
        Kind::PackExpansion => format!("repeat {}", print_child(node, 0)),
        Kind::Pack => {
            let parts: Vec<String> = node
                .children
                .iter()
                .map(|c: &NodeRef| print_node(c, Mode::Type))
                .collect();
            format!("Pack{{{}}}", parts.join(", "))
        }
        Kind::DependentGenericParamPackMarker => format!("each {}", print_child(node, 0)),
        Kind::OpaqueReturnType => "some".to_owned(),
        Kind::MacroExpansion => print_macro_expansion(node),
        Kind::AsyncFunctionPointer => {
            format!("async function pointer to {}", print_child(node, 0))
        }
        Kind::SendableAnnotation => "@Sendable ".to_owned(),
        Kind::AsyncResumePartialFunction => print_async_resume_partial(node),
        Kind::OpaqueTypeDescriptor => format!(
            "opaque type descriptor for <<opaque return type of {}>>",
            print_child(node, 0)
        ),
    }
}

fn print_generic_specialization(node: &Node) -> String {
    let desc: &str = node.text.as_deref().unwrap_or("generic specialization");
    let Some(base): Option<&NodeRef> = node.children.first() else {
        return desc.to_owned();
    };
    let params: Vec<String> = node
        .children
        .iter()
        .skip(1)
        .map(|c: &NodeRef| print_node(c, Mode::Type))
        .collect();
    format!(
        "{desc} <{}> of {}",
        params.join(", "),
        print_node(base, Mode::Symbol)
    )
}

fn print_conformance_context_bare(node: &Node) -> String {
    print_context_path(node)
}

fn print_lazy_witness_accessor(node: &Node, prefix: &str) -> String {
    let self_ty: String = node
        .children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let Some(conformance): Option<&NodeRef> = node.children.get(1) else {
        return String::new();
    };
    let ty: String = conformance
        .children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let proto: String = conformance
        .children
        .get(1)
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let module: String = conformance
        .children
        .get(2)
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let conformance_text: String = if module.is_empty() {
        format!("{ty} : {proto}")
    } else {
        format!("{ty} : {proto} in {module}")
    };
    format!("{prefix} for type {self_ty} and conformance {conformance_text}")
}

fn print_keypath_thunk(node: &Node) -> String {
    let role: &str = node.text.as_deref().unwrap_or("getter");
    let entity: String = print_child(node, 0);
    let containing: String = print_child(node, 1);
    format!("key path {role} for {entity} : {containing}")
}

fn innermost_witness_entity(node: &Node) -> &Node {
    match node.kind {
        Kind::Static
        | Kind::Getter
        | Kind::Setter
        | Kind::ModifyAccessor
        | Kind::ReadAccessor
        | Kind::MaterializeForSet
        | Kind::UnsafeAddressor
        | Kind::UnsafeMutableAddressor => node
            .children
            .first()
            .map_or(node, |c: &NodeRef| innermost_witness_entity(c)),
        _ => node,
    }
}

fn print_protocol_witness_thunk(node: &Node) -> String {
    let Some(requirement): Option<&NodeRef> = node.children.first() else {
        return String::new();
    };
    let inner: &Node = innermost_witness_entity(requirement);
    let Some(conformance_ctx): Option<&NodeRef> = inner
        .children
        .first()
        .filter(|c: &&NodeRef| c.kind == Kind::ProtocolConformanceContext)
    else {
        return print_node(requirement, Mode::Symbol);
    };
    let ty: String = conformance_ctx
        .children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let proto: String = conformance_ctx
        .children
        .get(1)
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let module: String = conformance_ctx
        .children
        .get(2)
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let requirement_text: String = print_node(requirement, Mode::Symbol);
    let conformance_text: String = if module.is_empty() {
        format!("{ty} : {proto}")
    } else {
        format!("{ty} : {proto} in {module}")
    };
    format!("protocol witness for {requirement_text} in conformance {conformance_text}")
}

fn print_async_resume_partial(node: &Node) -> String {
    let role: &str = node.text.as_deref().unwrap_or("await");
    let index: String = node
        .children
        .get(1)
        .and_then(|c: &NodeRef| c.text.as_deref())
        .unwrap_or("1")
        .to_owned();
    let base: String = node
        .children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Symbol));
    format!("({index}) {role} resume partial function for {base}")
}

fn print_macro_expansion(node: &Node) -> String {
    let role: &str = node.text.as_deref().unwrap_or("macro");
    let context: String = node
        .children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let attached_name: String = node
        .children
        .get(1)
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let macro_name: String = node
        .children
        .get(2)
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let discriminator: &str = node
        .children
        .get(3)
        .and_then(|c: &NodeRef| c.text.as_deref())
        .unwrap_or("1");
    format!("{role} macro @{macro_name} expansion #{discriminator} of {attached_name} in {context}")
}

fn entity_path(node: &Node) -> String {
    if node.children.len() >= 2 {
        let ctx: String = print_context_path(&node.children[0]);
        let name: String = print_context_path(&node.children[1]);
        if ctx.is_empty() {
            name
        } else {
            format!("{ctx}.{name}")
        }
    } else {
        node.children
            .first()
            .map_or_else(String::new, |c: &NodeRef| print_context_path(c))
    }
}

fn allocator_suffix(node: &Node) -> &'static str {
    match node.children.first().map(|c: &NodeRef| c.kind) {
        Some(Kind::Class) => ".__allocating_init",
        _ => ".init",
    }
}

fn context_first_path(node: &Node) -> String {
    node.children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c))
}

fn print_conformance_descriptor(node: &Node) -> String {
    let ty: String = node
        .children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let proto: String = print_child(node, 1);
    let module: String = node
        .children
        .get(2)
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    if module.is_empty() {
        format!("protocol conformance descriptor for {ty} : {proto}")
    } else {
        format!("protocol conformance descriptor for {ty} : {proto} in {module}")
    }
}

fn print_conformance_with_generic_sig(node: &Node) -> String {
    let Some(inner): Option<&NodeRef> = node.children.first() else {
        return String::new();
    };
    let where_clause: String = node
        .children
        .get(1)
        .map_or_else(String::new, |c: &NodeRef| generic_sig_where_only(c));
    let body: String = print_node(inner, Mode::Symbol);
    match body.strip_prefix("protocol conformance descriptor for ") {
        Some(rest) if !where_clause.is_empty() => {
            format!("protocol conformance descriptor for {where_clause} {rest}")
        }
        _ => body,
    }
}

fn generic_sig_where_only(node: &Node) -> String {
    print_generic_signature(node)
}

fn print_conformance_record(node: &Node, prefix: &str) -> String {
    let ty: String = node
        .children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let proto: String = print_child(node, 1);
    let module: String = node
        .children
        .get(2)
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    if module.is_empty() {
        format!("{prefix} {ty} : {proto}")
    } else {
        format!("{prefix} {ty} : {proto} in {module}")
    }
}

fn print_variable(node: &Node) -> String {
    let path: String = entity_path(node);
    match node.children.get(2) {
        Some(ty) => format!("{path} : {}", print_node(ty, Mode::Type)),
        None => path,
    }
}

fn print_accessor(node: &Node, accessor: &str) -> String {
    let inner: Option<&NodeRef> = node.children.first();
    match inner {
        Some(c) if c.kind == Kind::Variable => {
            let path: String = entity_path(c);
            c.children.get(2).map_or_else(
                || format!("{path}.{accessor}"),
                |ty: &NodeRef| format!("{path}.{accessor} : {}", print_node(ty, Mode::Type)),
            )
        }
        Some(c) if c.kind == Kind::Subscript => print_subscript_accessor(c, accessor),
        Some(c) => format!("{}.{accessor}", print_node(c, Mode::Type)),
        None => format!(".{accessor}"),
    }
}

fn print_init(node: &Node, suffix: &str) -> String {
    let base: String = context_first_path(node);
    let labels: Option<&NodeRef> = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::LabelList);
    let signature: Option<&NodeRef> = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::FunctionType);
    signature.map_or_else(
        || format!("{base}{suffix}"),
        |sig: &NodeRef| {
            format!(
                "{base}{suffix}{}",
                print_function_type_with_labels(sig, labels)
            )
        },
    )
}

fn print_subscript_accessor(node: &Node, accessor: &str) -> String {
    let base: String = context_first_path(node);
    let labels: Option<&NodeRef> = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::LabelList);
    let generic: String = subscript_generic(node);
    let signature: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::FunctionType)
        .map_or_else(
            || "()".to_owned(),
            |c: &NodeRef| print_subscript_signature(c, labels, &generic),
        );
    if base.is_empty() {
        format!("subscript.{accessor}{signature}")
    } else {
        format!("{base}.subscript.{accessor}{signature}")
    }
}

fn print_subscript_signature(node: &Node, labels: Option<&NodeRef>, generic: &str) -> String {
    format!(
        " : {generic}{}",
        print_function_type_with_labels(node, labels)
    )
}

fn subscript_generic(node: &Node) -> String {
    node.children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::DependentGenericSignature)
        .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type))
}

fn print_subscript(node: &Node) -> String {
    let base: String = context_first_path(node);
    let labels: Option<&NodeRef> = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::LabelList);
    let generic: String = subscript_generic(node);
    let signature: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::FunctionType)
        .map_or_else(String::new, |c: &NodeRef| {
            print_subscript_signature(c, labels, &generic)
        });
    if base.is_empty() {
        format!("subscript{signature}")
    } else {
        format!("{base}.subscript{signature}")
    }
}

fn print_function(node: &Node) -> String {
    let base: String = entity_path(node);
    let generic: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::DependentGenericSignature)
        .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type));
    let labels: Option<&NodeRef> = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::LabelList);
    let signature: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::FunctionType)
        .map_or_else(
            || "()".to_owned(),
            |c: &NodeRef| print_function_type_with_labels(c, labels),
        );
    format!("{base}{generic}{signature}")
}

fn print_function_type_with_labels(node: &Node, labels: Option<&NodeRef>) -> String {
    let Some(label_list): Option<&NodeRef> = labels else {
        return print_node(node, Mode::Type);
    };
    let args: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::ArgumentTuple)
        .map_or_else(
            || "()".to_owned(),
            |c: &NodeRef| print_argument_tuple_with_labels(c, &label_list.children),
        );
    let trailing: String = function_type_trailing(node);
    let prefix: String = function_type_isolation_prefix(node);
    format!("{prefix}{args}{trailing}")
}

fn function_type_trailing(node: &Node) -> String {
    let ret: String = function_type_return(node);
    let is_async: bool = node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::AsyncAnnotation);
    let mut middle: String = String::new();
    if is_async {
        middle.push_str(" async");
    }
    middle.push_str(&function_type_throws_clause(node));
    format!("{middle} -> {ret}")
}

fn function_type_isolation_prefix(node: &Node) -> String {
    let mut prefix: String = String::new();
    if node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::SendableAnnotation)
    {
        prefix.push_str("@Sendable ");
    }
    if node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::IsolatedAnyAnnotation)
    {
        prefix.push_str("@isolated(any) ");
    }
    if node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::NonisolatedCallerAnnotation)
    {
        prefix.push_str("nonisolated(nonsending) ");
    }
    if let Some(actor) = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::GlobalActorAnnotation)
    {
        prefix.push_str(&print_node(actor, Mode::Type));
    }
    prefix
}

fn function_type_throws_clause(node: &Node) -> String {
    let typed: Option<&NodeRef> = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::TypedThrowsAnnotation);
    let bare_throws: bool = node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::ThrowsAnnotation);
    typed.map_or_else(
        || {
            if bare_throws {
                " throws".to_owned()
            } else {
                String::new()
            }
        },
        |t: &NodeRef| print_node(t, Mode::Type),
    )
}

fn function_type_return(node: &Node) -> String {
    let ret: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::ReturnType)
        .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type));
    if node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::SendingResultAnnotation)
    {
        format!("sending {ret}")
    } else {
        ret
    }
}

fn print_argument_tuple_with_labels(node: &Node, labels: &[NodeRef]) -> String {
    let inner: &NodeRef = match node.children.first() {
        Some(c) => c,
        None => return "()".to_owned(),
    };
    let elements: Vec<String> = match inner.kind {
        Kind::Tuple => inner
            .children
            .iter()
            .enumerate()
            .map(|(i, c): (usize, &NodeRef)| label_param(labels.get(i), c))
            .collect(),
        _ => vec![label_param(labels.first(), inner)],
    };
    format!("({})", elements.join(", "))
}

fn label_param(label: Option<&NodeRef>, element: &Node) -> String {
    let ty: String = match element.kind {
        Kind::TupleElement => print_tuple_element(element),
        _ => print_node(element, Mode::Type),
    };
    let has_inline_label: bool = element.kind == Kind::TupleElement && element.children.len() == 2;
    if has_inline_label {
        return ty;
    }
    match label.and_then(|l: &NodeRef| l.text.as_deref()) {
        Some(name) if !name.is_empty() => format!("{name}: {ty}"),
        Some(_) => format!("_: {ty}"),
        None => ty,
    }
}

fn print_generic_signature(node: &Node) -> String {
    let count: u32 = node
        .children
        .first()
        .filter(|c: &&NodeRef| c.kind == Kind::DependentGenericParamCount)
        .and_then(|c: &NodeRef| c.text.as_deref())
        .and_then(|t: &str| t.parse::<u32>().ok())
        .unwrap_or(1);
    let pack_params: Vec<String> = node
        .children
        .iter()
        .filter(|c: &&NodeRef| c.kind == Kind::DependentGenericParamPackMarker)
        .filter_map(|c: &NodeRef| c.children.first())
        .filter_map(|p: &NodeRef| p.text.clone())
        .collect();
    let params: Vec<String> = (0..count.min(64))
        .map(|i: u32| {
            let name: String = generic_param_name(0, i);
            if pack_params.contains(&name) {
                format!("each {name}")
            } else {
                name
            }
        })
        .collect();
    let requirements: Vec<String> = node
        .children
        .iter()
        .filter(|c: &&NodeRef| {
            matches!(
                c.kind,
                Kind::DependentGenericConformanceRequirement
                    | Kind::DependentGenericSameTypeRequirement
                    | Kind::DependentGenericLayoutRequirement
            )
        })
        .map(|c: &NodeRef| print_node(c, Mode::Type))
        .collect();
    if params.is_empty() && requirements.is_empty() {
        return String::new();
    }
    if requirements.is_empty() {
        format!("<{}>", params.join(", "))
    } else {
        format!("<{} where {}>", params.join(", "), requirements.join(", "))
    }
}

fn print_function_type(node: &Node) -> String {
    let args: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::ArgumentTuple)
        .map_or_else(|| "()".to_owned(), |c: &NodeRef| print_node(c, Mode::Type));
    let ret: String = function_type_return(node);
    let is_async: bool = node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::AsyncAnnotation);
    let convention: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::ConventionAnnotation)
        .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type));
    let prefix: String = function_type_isolation_prefix(node);
    let mut middle: String = String::new();
    if is_async {
        middle.push_str(" async");
    }
    middle.push_str(&function_type_throws_clause(node));
    format!("{convention}{prefix}{args}{middle} -> {ret}")
}

fn print_impl_function_type(node: &Node) -> String {
    let generic_signature: Option<String> = node
        .children
        .iter()
        .find(|child: &&NodeRef| child.kind == Kind::DependentGenericSignature)
        .map(|child: &NodeRef| print_node(child, Mode::Type));
    let pattern_substitutions: Option<&NodeRef> = node
        .children
        .iter()
        .find(|child: &&NodeRef| child.kind == Kind::ImplPatternSubstitutions);
    let invocation_substitutions: Option<&NodeRef> = node
        .children
        .iter()
        .find(|child: &&NodeRef| child.kind == Kind::ImplInvocationSubstitutions);
    let mut attributes: Vec<String> = vec![node.text.clone().unwrap_or_default()];
    attributes.extend(generic_signature);
    if let Some(pattern) = pattern_substitutions {
        attributes.push(format!("@substituted {}", print_child(pattern, 0)));
    }
    attributes.retain(|attribute: &String| !attribute.is_empty());
    let parameters: Vec<String> = node
        .children
        .iter()
        .filter(|child: &&NodeRef| child.kind == Kind::ImplParameter)
        .map(|child: &NodeRef| print_node(child, Mode::Type))
        .collect();
    let results: Vec<String> = node
        .children
        .iter()
        .filter(|child: &&NodeRef| {
            matches!(
                child.kind,
                Kind::ImplResult | Kind::ImplYield | Kind::ImplErrorResult
            )
        })
        .map(|child: &NodeRef| print_node(child, Mode::Type))
        .collect();
    let sending_result: &str = if node
        .children
        .iter()
        .any(|child: &NodeRef| child.kind == Kind::ImplSendingResult)
    {
        "sending "
    } else {
        ""
    };
    let mut rendered: String = format!(
        "{} ({}) -> {sending_result}({})",
        attributes.join(" "),
        parameters.join(", "),
        results.join(", ")
    );
    if let Some(pattern) = pattern_substitutions {
        rendered.push_str(" for <");
        rendered.push_str(&print_child(pattern, 1));
        rendered.push('>');
    }
    if let Some(invocation) = invocation_substitutions {
        rendered.push_str(" for <");
        rendered.push_str(&print_child(invocation, 0));
        rendered.push('>');
    }
    rendered
}

fn print_reabstraction_thunk(node: &Node, helper: bool) -> String {
    let has_signature: bool = node
        .children
        .first()
        .is_some_and(|child: &NodeRef| child.kind == Kind::DependentGenericSignature);
    let index: usize = usize::from(has_signature);
    let signature: String = if has_signature {
        format!("{} ", print_child(node, 0))
    } else {
        String::new()
    };
    let helper: &str = if helper { " helper" } else { "" };
    format!(
        "reabstraction thunk{helper} {signature}from {} to {}",
        print_child(node, index),
        print_child(node, index + 1)
    )
}

fn print_reabstraction_thunk_with_self(node: &Node) -> String {
    let has_signature: bool = node
        .children
        .first()
        .is_some_and(|child: &NodeRef| child.kind == Kind::DependentGenericSignature);
    let index: usize = usize::from(has_signature);
    let signature: String = if has_signature {
        format!("{} ", print_child(node, 0))
    } else {
        String::new()
    };
    format!(
        "reabstraction thunk {signature}from {} to {} self {}",
        print_child(node, index),
        print_child(node, index + 1),
        print_child(node, index + 2)
    )
}

fn print_argument_tuple(node: &Node) -> String {
    let inner: &NodeRef = match node.children.first() {
        Some(c) => c,
        None => return "()".to_owned(),
    };
    match inner.kind {
        Kind::Tuple => print_node(inner, Mode::Type),
        _ => format!("({})", print_node(inner, Mode::Type)),
    }
}

fn tuple_has_label(elements: &[NodeRef]) -> bool {
    elements
        .iter()
        .any(|e: &NodeRef| e.children.len() == 2 && e.children[0].kind == Kind::Identifier)
}

fn tuple_element_is_pack(elements: &[NodeRef]) -> bool {
    elements
        .iter()
        .filter_map(|e: &NodeRef| e.children.last())
        .any(|ty: &NodeRef| ty.kind == Kind::PackExpansion)
}

fn print_tuple_element(node: &Node) -> String {
    if node.children.len() == 2 && node.children[0].kind == Kind::Identifier {
        let label: &str = node.children[0].text.as_deref().unwrap_or_default();
        let ty: String = print_node(&node.children[1], Mode::Type);
        format!("{label}: {ty}")
    } else {
        node.children
            .first()
            .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type))
    }
}

fn print_bound_generic(node: &Node) -> String {
    let Some(base): Option<&NodeRef> = node.children.first() else {
        return String::new();
    };
    let args: Vec<String> = node
        .children
        .iter()
        .skip(1)
        .map(|c: &NodeRef| print_node(c, Mode::Type))
        .collect();
    let (root, suffix): (&Node, Vec<String>) = nominal_root_and_suffix(base);
    if suffix.is_empty() {
        return format!("{}<{}>", print_context_path(base), args.join(", "));
    }
    let root_name: String = print_context_path(root);
    let root_render: String = match root_name.as_str() {
        "Swift.Array" if args.len() == 1 => format!("[{}]", args[0]),
        "Swift.Optional" if args.len() == 1 => format!("{}?", args[0]),
        "Swift.Dictionary" if args.len() == 2 => format!("[{} : {}]", args[0], args[1]),
        _ => format!("{root_name}<{}>", args.join(", ")),
    };
    format!("{root_render}.{}", suffix.join("."))
}

fn nominal_root_and_suffix(node: &Node) -> (&Node, Vec<String>) {
    let Some(inner): Option<&NodeRef> = node.children.first() else {
        return (node, Vec::new());
    };
    if node.kind == Kind::OtherNominalType && node.children.len() == 2 {
        let context: &NodeRef = &node.children[0];
        let name: String = print_context_path(&node.children[1]);
        if matches!(
            context.kind,
            Kind::Class | Kind::Structure | Kind::Enum | Kind::OtherNominalType
        ) {
            let (root, mut suffix): (&Node, Vec<String>) = nominal_root_and_suffix(context);
            suffix.push(name);
            return (root, suffix);
        }
        return (node, Vec::new());
    }
    if matches!(node.kind, Kind::Class | Kind::Structure | Kind::Enum) {
        let (root, suffix): (&Node, Vec<String>) = nominal_root_and_suffix(inner);
        if suffix.is_empty() {
            return (node, Vec::new());
        }
        return (root, suffix);
    }
    (node, Vec::new())
}

fn print_child(node: &Node, idx: usize) -> String {
    node.children
        .get(idx)
        .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type))
}

fn print_child_parenthesized(node: &Node, idx: usize) -> String {
    match node.children.get(idx) {
        Some(c) if c.kind == Kind::FunctionType => {
            format!("({})", print_node(c, Mode::Type))
        }
        Some(c) => print_node(c, Mode::Type),
        None => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn demangle_simple_class() {
        assert_eq!(
            demangle("$s5Hello5WorldC").expect("d"),
            "Hello.World (class)"
        );
    }

    #[test]
    fn demangle_simple_struct() {
        assert_eq!(demangle("$s3App4UserV").expect("d"), "App.User (struct)");
    }

    #[test]
    fn demangle_three_component_path() {
        assert_eq!(
            demangle("$s11SwiftDriver10ProcessSetC").expect("d"),
            "SwiftDriver.ProcessSet (class)"
        );
    }

    #[test]
    fn demangle_rejects_non_swift() {
        assert!(demangle("foo").is_err());
    }

    #[test]
    fn demangle_nominal_type_descriptor_operator() {
        assert_eq!(
            demangle("$s10SwiftHello19LoginViewControllerCMn").expect("d"),
            "nominal type descriptor for SwiftHello.LoginViewController"
        );
    }

    #[test]
    fn demangle_type_metadata_operator() {
        assert_eq!(
            demangle("$s10SwiftHello21AuthenticationServiceCN").expect("d"),
            "type metadata for SwiftHello.AuthenticationService"
        );
    }

    #[test]
    fn demangle_metaclass_operator() {
        assert_eq!(
            demangle("$s10SwiftHello19LoginViewControllerCMm").expect("d"),
            "metaclass for SwiftHello.LoginViewController"
        );
    }

    #[test]
    fn demangle_protocol_descriptor_word_substitution() {
        let out: String = demangle("$s10SwiftHello0B9GreetableMp").expect("d");
        assert!(out.starts_with("protocol descriptor for "), "got {out}");
        assert!(out.contains("Greetable"), "got {out}");
    }

    #[test]
    fn demangle_deallocating_destructor() {
        assert_eq!(
            demangle("$s10SwiftHello19LoginViewControllerCfD").expect("d"),
            "SwiftHello.LoginViewController.__deallocating_deinit"
        );
    }

    #[test]
    fn demangle_field_offset_operator() {
        let direct: String =
            demangle("$s10SwiftHello19LoginViewControllerC17displayedUserNameSSvpWvd").expect("d");
        assert_eq!(
            direct,
            "direct field offset for SwiftHello.LoginViewController.displayedUserName : Swift.String"
        );
        let indirect: String =
            demangle("$s10SwiftHello19LoginViewControllerC17displayedUserNameSSvpWvi").expect("d");
        assert!(
            indirect.starts_with("indirect field offset for "),
            "got {indirect}"
        );
    }

    #[test]
    fn demangle_type_standard_substitutions() {
        assert_eq!(demangle_type("Si").as_deref(), Some("Swift.Int"));
        assert_eq!(demangle_type("SS").as_deref(), Some("Swift.String"));
        assert_eq!(demangle_type("Su").as_deref(), Some("Swift.UInt"));
        assert_eq!(demangle_type("Sb").as_deref(), Some("Swift.Bool"));
        assert_eq!(demangle_type("Sd").as_deref(), Some("Swift.Double"));
    }

    #[test]
    fn demangle_type_array_of_string() {
        assert_eq!(demangle_type("SaySSG").as_deref(), Some("[Swift.String]"));
    }

    #[test]
    fn demangle_type_dictionary_sugar() {
        assert_eq!(
            demangle_type("SDySSSiG").as_deref(),
            Some("[Swift.String : Swift.Int]")
        );
    }

    #[test]
    fn demangle_type_optional_postfix() {
        assert_eq!(demangle_type("SSSg").as_deref(), Some("Swift.String?"));
    }

    #[test]
    fn demangle_type_nominal_path() {
        assert_eq!(
            demangle_type("11SwiftDriver10ProcessSetC").as_deref(),
            Some("SwiftDriver.ProcessSet")
        );
    }

    #[test]
    fn demangle_type_symbolic_ref_is_none() {
        let symbolic: Vec<u8> = vec![0x01, 0x6b, 0xab, 0x00, 0x02];
        let s: String = String::from_utf8_lossy(&symbolic).into_owned();
        assert!(demangle_type(&s).is_none());
    }

    #[test]
    fn demangle_type_generic_class() {
        assert_eq!(
            demangle_type("5Cache5BoxedCySiG").as_deref(),
            Some("Cache.Boxed<Swift.Int>")
        );
    }

    #[test]
    fn demangle_type_labeled_tuple_payload() {
        assert_eq!(
            demangle_type("Si5index_SS8argumentt").as_deref(),
            Some("(index: Swift.Int, argument: Swift.String)")
        );
    }

    #[test]
    fn demangle_type_unlabeled_tuple() {
        assert_eq!(
            demangle_type("SS_Sit").as_deref(),
            Some("(Swift.String, Swift.Int)")
        );
    }

    #[test]
    fn demangle_type_single_element_labeled_tuple() {
        assert_eq!(
            demangle_type("Si5width_t").as_deref(),
            Some("(width: Swift.Int)")
        );
    }

    #[test]
    fn demangle_type_two_labeled_tuple() {
        assert_eq!(
            demangle_type("SS3key_Si5valuet").as_deref(),
            Some("(key: Swift.String, value: Swift.Int)")
        );
    }

    #[test]
    fn demangle_type_tuple_with_optional_and_sugar() {
        assert_eq!(
            demangle_type("SaySSG_Sb7lenientt").as_deref(),
            Some("([Swift.String], lenient: Swift.Bool)")
        );
        assert_eq!(
            demangle_type("SS_SSSgt").as_deref(),
            Some("(Swift.String, Swift.String?)")
        );
    }

    #[test]
    fn demangle_type_bare_substitution_is_not_a_tuple() {
        assert_eq!(demangle_type("Si").as_deref(), Some("Swift.Int"));
        assert_eq!(demangle_type("SS").as_deref(), Some("Swift.String"));
    }

    #[test]
    fn demangle_type_objc_imported_class() {
        assert_eq!(demangle_type("So6NSLockC").as_deref(), Some("__C.NSLock"));
        assert_eq!(
            demangle_type("So17OS_dispatch_queueC").as_deref(),
            Some("__C.OS_dispatch_queue")
        );
    }

    #[test]
    fn demangle_type_objc_class_optional() {
        assert_eq!(
            demangle_type("So12NSFileHandleCSg").as_deref(),
            Some("__C.NSFileHandle?")
        );
    }

    #[test]
    fn demangle_type_dictionary_repeat_count_substitution() {
        assert_eq!(
            demangle_type("SDyS2SG").as_deref(),
            Some("[Swift.String : Swift.String]")
        );
        assert_eq!(
            demangle_type("SDyS2SGSg").as_deref(),
            Some("[Swift.String : Swift.String]?")
        );
    }

    #[test]
    fn demangle_type_three_element_tuple_single_separator() {
        assert_eq!(
            demangle_type("SSSg_SaySSGSSt").as_deref(),
            Some("(Swift.String?, [Swift.String], Swift.String)")
        );
    }

    #[test]
    fn demangle_type_unlabeled_triple_has_one_separator() {
        assert_eq!(
            demangle_type("Si_SiSit").as_deref(),
            Some("(Swift.Int, Swift.Int, Swift.Int)")
        );
    }

    #[test]
    fn demangle_type_c_function_empty_params() {
        assert_eq!(
            demangle_type("SvSgyXCSg").as_deref(),
            Some("(@convention(c) () -> Swift.UnsafeMutableRawPointer?)?")
        );
    }

    #[test]
    fn demangle_type_c_function_empty_result() {
        assert_eq!(
            demangle_type("ySvSgXCSg").as_deref(),
            Some("(@convention(c) (Swift.UnsafeMutableRawPointer?) -> ())?")
        );
    }

    #[test]
    fn demangle_type_autoclosure_function() {
        assert_eq!(
            demangle_type("SiyXK").as_deref(),
            Some("@autoclosure () -> Swift.Int")
        );
    }

    #[test]
    fn demangle_autoclosure_parameter_in_function() {
        assert_eq!(
            demangle("$s2b26autoclyySiyXKF").expect("d"),
            "b2.autocl(@autoclosure () -> Swift.Int) -> ()"
        );
    }

    #[test]
    fn demangle_type_swift_escaping_function() {
        assert_eq!(
            demangle_type("12SwiftOptions6OptionVycSg").as_deref(),
            Some("(() -> SwiftOptions.Option)?")
        );
    }

    #[test]
    fn demangle_type_single_protocol_existential() {
        assert_eq!(
            demangle_type("20SwiftDriverExecution21LLBuildEngineDelegateP_p").as_deref(),
            Some("SwiftDriverExecution.LLBuildEngineDelegate")
        );
    }

    #[test]
    fn punycode_decode_spec_vector() {
        assert_eq!(
            decode_swift_punycode(b"vergenza_JFa").as_deref(),
            Some("verg\u{fc}enza")
        );
    }

    #[test]
    fn punycode_identifier_in_global() {
        assert_eq!(
            demangle("$s8mangling0012vergenza_JFaV").expect("d"),
            "mangling.verg\u{fc}enza (struct)"
        );
    }

    #[test]
    fn punycode_rejects_truncated_extension() {
        assert!(decode_swift_punycode(b"a_99").is_none());
    }

    #[test]
    fn generic_signature_single_conformance() {
        assert_eq!(
            demangle("$s5assoc6ncIteryyxAA1PRzlF").expect("d"),
            "assoc.ncIter<A where A: assoc.P>(A) -> ()"
        );
    }

    #[test]
    fn generic_signature_bare_param_list() {
        assert_eq!(demangle("$s1A1gyyxlF").expect("d"), "A.g<A>(A) -> ()");
        assert_eq!(
            demangle("$s4Test6testityyxlF").expect("d"),
            "Test.testit<A>(A) -> ()"
        );
    }

    #[test]
    fn generic_signature_two_parameters() {
        assert_eq!(
            demangle("$s4test3fooyyx_q_tr0_lF").expect("d"),
            "test.foo<A, B>(A, B) -> ()"
        );
    }

    #[test]
    fn function_full_param_types_two_args() {
        assert_eq!(
            demangle("$s3foo3barC3bazyySi_SStF").expect("d"),
            "foo.bar.baz(Swift.Int, Swift.String) -> ()"
        );
    }

    #[test]
    fn function_single_param_type() {
        assert_eq!(
            demangle("$s3foo3barC3bazyySSF").expect("d"),
            "foo.bar.baz(Swift.String) -> ()"
        );
    }

    #[test]
    fn function_async_and_throws_annotations() {
        assert_eq!(
            demangle("$s7example1fyyYaF").expect("d"),
            "example.f() async -> ()"
        );
        assert_eq!(
            demangle("$s7example1fyyYaKF").expect("d"),
            "example.f() async throws -> ()"
        );
    }

    #[test]
    fn function_labeled_parameters_rendered() {
        assert_eq!(
            demangle("$s9MacroUser13testStringify1a1bySi_SitF").expect("d"),
            "MacroUser.testStringify(a: Swift.Int, b: Swift.Int) -> ()"
        );
    }

    #[test]
    fn generic_signature_does_not_corrupt_unsupported_requirements() {
        let out: String = demangle("$s5assoc12bothCopyableyyxAA1PRzs0C08IteratorRpzlF").expect("d");
        assert_eq!(
            out,
            "assoc.bothCopyable<A where A: assoc.P, A.Iterator: Swift.Copyable>(A) -> ()"
        );
    }

    #[test]
    fn demangle_init_with_self_result() {
        assert_eq!(
            demangle("$s10Foundation11JSONDecoderCACycfc").expect("d"),
            "Foundation.JSONDecoder.init() -> Foundation.JSONDecoder"
        );
    }

    #[test]
    fn demangle_init_with_labeled_param() {
        assert_eq!(
            demangle("$s10Foundation13__DataStorageC6lengthACSi_tcfc").expect("d"),
            "Foundation.__DataStorage.init(length: Swift.Int) -> Foundation.__DataStorage"
        );
    }

    #[test]
    fn demangle_variable_getter_carries_type() {
        assert_eq!(
            demangle("$s10Foundation13__DataStorageC7_lengthSivg").expect("d"),
            "Foundation.__DataStorage._length.getter : Swift.Int"
        );
    }

    #[test]
    fn demangle_static_getter_has_static_and_type() {
        assert_eq!(
            demangle("$s10Foundation11JSONEncoderC16OutputFormattingV10sortedKeysAEvgZ")
                .expect("d"),
            "static Foundation.JSONEncoder.OutputFormatting.sortedKeys.getter : \
             Foundation.JSONEncoder.OutputFormatting"
        );
    }

    #[test]
    fn demangle_init_with_optional_and_two_labels() {
        assert_eq!(
            demangle("$s10Foundation13__DataStorageC5bytes6lengthACSVSg_Sitcfc").expect("d"),
            "Foundation.__DataStorage.init(bytes: Swift.UnsafeRawPointer?, length: Swift.Int) \
             -> Foundation.__DataStorage"
        );
    }

    #[test]
    fn demangle_operator_method_descriptor_static() {
        assert_eq!(
            demangle("$ss18AdditiveArithmeticP1poiyxx_xtFZTq").expect("d"),
            "method descriptor for static Swift.AdditiveArithmetic.+ infix(A, A) -> A"
        );
    }

    #[test]
    fn demangle_static_function_with_objc_optional_param() {
        assert_eq!(
            demangle("$s10Foundation4DataV36_unconditionallyBridgeFromObjectiveCyACSo6NSDataCSgFZ")
                .expect("d"),
            "static Foundation.Data._unconditionallyBridgeFromObjectiveC(__C.NSData?) \
             -> Foundation.Data"
        );
    }

    #[test]
    fn demangle_single_protocol_existential_without_p_tag() {
        assert_eq!(
            demangle("$s10Foundation22_convertNSErrorToErrorys0E0_pSo0C0CSgF").expect("d"),
            "Foundation._convertNSErrorToError(__C.NSError?) -> Swift.Error"
        );
    }

    #[test]
    fn demangle_protocol_descriptor_bare() {
        assert_eq!(
            demangle("$s10Foundation13CustomNSErrorMp").expect("d"),
            "protocol descriptor for Foundation.CustomNSError"
        );
    }

    #[test]
    fn demangle_method_descriptor_of_protocol_member() {
        assert_eq!(
            demangle("$sSH13_rawHashValue4seedS2i_tFTq").expect("d"),
            "method descriptor for Swift.Hashable._rawHashValue(seed: Swift.Int) -> Swift.Int"
        );
    }

    #[test]
    fn demangle_inout_parameter() {
        assert_eq!(
            demangle("$sSH4hash4intoys6HasherVz_tFTq").expect("d"),
            "method descriptor for Swift.Hashable.hash(into: inout Swift.Hasher) -> ()"
        );
    }

    #[test]
    fn demangle_extension_member_getter() {
        assert_eq!(
            demangle("$s10Foundation13CustomNSErrorPAAE9errorCodeSivg").expect("d"),
            "(extension in Foundation):Foundation.CustomNSError.errorCode.getter : Swift.Int"
        );
    }

    #[test]
    fn demangle_base_conformance_descriptor() {
        assert_eq!(
            demangle("$sSHSQTb").expect("d"),
            "base conformance descriptor for Swift.Hashable: Swift.Equatable"
        );
    }

    #[test]
    fn demangle_associated_type_descriptor_standard_protocol() {
        assert_eq!(
            demangle("$s11SubSequenceSlTl").expect("d"),
            "associated type descriptor for Swift.Collection.SubSequence"
        );
    }

    #[test]
    fn demangle_repeated_substitution_in_signature() {
        assert_eq!(
            demangle("$sSH13_rawHashValue4seedS2i_tFTj").expect("d"),
            "dispatch thunk of Swift.Hashable._rawHashValue(seed: Swift.Int) -> Swift.Int"
        );
    }

    #[test]
    fn demangle_dispatch_thunk_generic_function() {
        assert_eq!(
            demangle("$s10Foundation11JSONEncoderC6encodeyAA4DataVxKSERzlFTj").expect("d"),
            "dispatch thunk of Foundation.JSONEncoder.encode<A where A: Swift.Encodable>(A) \
             throws -> Foundation.Data"
        );
    }

    #[test]
    fn demangle_closure_parameter_with_generic_result() {
        assert_eq!(
            demangle(
                "$s10Foundation3URLV34withUnsafeFileSystemRepresentationyxxSPys4Int8VGSgKXEKlF"
            )
            .expect("d"),
            "Foundation.URL.withUnsafeFileSystemRepresentation<A>((Swift.UnsafePointer<Swift.Int8>?) \
             throws -> A) throws -> A"
        );
    }

    #[test]
    fn demangle_global_variable_addressor_with_type() {
        assert_eq!(
            demangle("$s8TSCBasic12stderrStreamAA020ThreadSafeOutputByteC0Cvau").expect("d"),
            "TSCBasic.stderrStream.unsafeMutableAddressor : TSCBasic.ThreadSafeOutputByteStream"
        );
    }

    #[test]
    fn demangle_value_type_allocator_renders_init() {
        assert_eq!(
            demangle("$s10Foundation4DateVACycfC").expect("d"),
            "Foundation.Date.init() -> Foundation.Date"
        );
    }

    #[test]
    fn demangle_class_allocator_renders_allocating_init() {
        assert_eq!(
            demangle("$s10Foundation11JSONDecoderCACycfC").expect("d"),
            "Foundation.JSONDecoder.__allocating_init() -> Foundation.JSONDecoder"
        );
    }

    #[test]
    fn demangle_value_type_init_does_not_grab_param_as_result_function() {
        assert_eq!(
            demangle("$s8TSCBasic12AbsolutePathVyACSScfC").expect("d"),
            "TSCBasic.AbsolutePath.init(Swift.String) -> TSCBasic.AbsolutePath"
        );
    }

    #[test]
    fn demangle_protocol_conformance_descriptor_with_module() {
        assert_eq!(
            demangle("$s8TSCBasic15UnknownLocationCAA010DiagnosticC0AAMc").expect("d"),
            "protocol conformance descriptor for TSCBasic.UnknownLocation : \
             TSCBasic.DiagnosticLocation in TSCBasic"
        );
    }

    #[test]
    fn demangle_protocol_witness_table_conformance_record() {
        assert_eq!(
            demangle("$sSS8TSCBasic14ByteStreamableAAWP").expect("d"),
            "protocol witness table for Swift.String : TSCBasic.ByteStreamable in TSCBasic"
        );
        assert_eq!(
            demangle("$sSJSQsWP").expect("d"),
            "protocol witness table for Swift.Character : Swift.Equatable in Swift"
        );
    }

    #[test]
    fn demangle_value_witness_table_for_builtin() {
        assert_eq!(
            demangle("$sBOWV").expect("d"),
            "value witness table for Builtin.UnknownObject"
        );
        assert_eq!(
            demangle("$sBi32_WV").expect("d"),
            "value witness table for Builtin.Int32"
        );
        assert_eq!(demangle("$sytWV").expect("d"), "value witness table for ()");
    }

    #[test]
    fn demangle_value_witness_functions() {
        assert_eq!(
            demangle("$sSiwxx").expect("d"),
            "destroy value witness for Swift.Int"
        );
        assert_eq!(
            demangle("$sSiwCP").expect("d"),
            "initializeBufferWithCopyOfBuffer value witness for Swift.Int"
        );
        assert_eq!(
            demangle("$sSiwca").expect("d"),
            "assignWithCopy value witness for Swift.Int"
        );
        assert_eq!(
            demangle("$sSiwet").expect("d"),
            "getEnumTagSinglePayload value witness for Swift.Int"
        );
        assert_eq!(
            demangle("$sSiwug").expect("d"),
            "getEnumTag value witness for Swift.Int"
        );
    }

    #[test]
    fn demangle_merged_value_witness_thunk() {
        assert_eq!(
            demangle("$sSiwcaTm").expect("d"),
            "merged assignWithCopy value witness for Swift.Int"
        );
    }

    #[test]
    fn unknown_value_witness_code_never_fabricates_a_name() {
        let out: String = demangle("$sSiwzz").unwrap_or_default();
        assert!(!out.contains("value witness"), "got {out}");
    }

    #[test]
    fn demangle_extension_context_on_standard_library_type() {
        assert_eq!(
            demangle("$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF").expect("d"),
            "(extension in Foundation):Swift.String._bridgeToObjectiveC() -> __C.NSString"
        );
    }

    #[test]
    fn demangle_nested_member_after_standard_substitution() {
        assert_eq!(
            demangle("$sSS14removeSubrangeyySnySS5IndexVGF").expect("d"),
            "Swift.String.removeSubrange(Swift.Range<Swift.String.Index>) -> ()"
        );
    }

    #[test]
    fn demangle_void_and_any_type_markers() {
        assert_eq!(
            demangle("$s10Foundation13CustomNSErrorP13errorUserInfoSDySSypGvgTq").expect("d"),
            "method descriptor for Foundation.CustomNSError.errorUserInfo.getter : \
             [Swift.String : Any]"
        );
    }

    #[test]
    fn demangle_wide_generic_tuple_init_matches_reference_and_stays_bounded() {
        for width in [16_usize, 32, 64] {
            let filler: String = "x".repeat(width - 1);
            let mangled: String = format!("$ss6SIMD{width}VyAByxGx_{filler}tcfC");
            let joined: String = vec!["A"; width].join(", ");
            let expected: String =
                format!("Swift.SIMD{width}.init({joined}) -> Swift.SIMD{width}<A>");
            assert_eq!(
                demangle(&mangled).expect("wide generic tuple init must demangle"),
                expected,
                "SIMD{width} initializer must recover every generic-parameter element"
            );
        }
    }

    #[test]
    fn demangle_type_rejects_oversized_standard_substitution_repeat() {
        assert_eq!(demangle_type("S900000000i"), None);
        assert_eq!(demangle_type("SDyS900000000SG"), None);
    }

    #[test]
    fn demangle_type_rejects_standard_substitution_repeat_just_over_cap() {
        assert_eq!(demangle_type("SDyS2049SG"), None);
    }

    #[test]
    fn demangle_type_small_standard_substitution_repeat_still_recovers() {
        assert_eq!(
            demangle_type("SDyS2SG").as_deref(),
            Some("[Swift.String : Swift.String]")
        );
    }

    #[test]
    fn demangle_substitution_chain_rejects_oversized_repeat() {
        let node: NodeRef = Node::leaf(Kind::Structure, "Demo".to_owned());
        let mut dem: Demangler<'_> = Demangler::new("A900000000A");
        dem.substitutions.push(Rc::clone(&node));
        assert!(dem.demangle_substitution_chain().is_none());
    }

    #[test]
    fn demangle_substitution_chain_small_repeat_fans_out() {
        let node: NodeRef = Node::leaf(Kind::Structure, "Demo".to_owned());
        let mut dem: Demangler<'_> = Demangler::new("A2A");
        dem.substitutions.push(Rc::clone(&node));
        let chain: Vec<NodeRef> = dem
            .demangle_substitution_chain()
            .expect("small repeat chain must resolve");
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn demangle_substitution_rejects_oversized_repeat() {
        let node: NodeRef = Node::leaf(Kind::Structure, "Demo".to_owned());
        let mut dem: Demangler<'_> = Demangler::new("A900000000A");
        dem.substitutions.push(Rc::clone(&node));
        assert!(dem.demangle_substitution().is_none());
    }

    #[test]
    fn demangle_substitution_small_repeat_populates_pending() {
        let node: NodeRef = Node::leaf(Kind::Structure, "Demo".to_owned());
        let mut dem: Demangler<'_> = Demangler::new("A2A");
        dem.substitutions.push(Rc::clone(&node));
        let resolved: NodeRef = dem
            .demangle_substitution()
            .expect("small repeat substitution must resolve");
        assert_eq!(resolved.kind, Kind::Structure);
        assert_eq!(dem.pending_substitutions.len(), 1);
    }

    #[test]
    fn demangle_substitution_chain_total_length_is_budget_bounded() {
        let node: NodeRef = Node::leaf(Kind::Structure, "Demo".to_owned());
        let input: String = format!("A{}_", "2048a".repeat(200));
        let mut dem: Demangler<'_> = Demangler::new(&input);
        dem.substitutions.push(Rc::clone(&node));
        assert!(
            dem.demangle_substitution_chain().is_none(),
            "a run of in-range repeat groups must stop at the node budget"
        );
        assert_eq!(
            dem.node_budget, 0,
            "each chain clone must be charged against the global node budget"
        );
    }

    #[test]
    fn demangle_substitution_total_length_is_budget_bounded() {
        let node: NodeRef = Node::leaf(Kind::Structure, "Demo".to_owned());
        let input: String = format!("A{}_", "2048a".repeat(200));
        let mut dem: Demangler<'_> = Demangler::new(&input);
        dem.substitutions.push(Rc::clone(&node));
        assert!(
            dem.demangle_substitution().is_none(),
            "a run of in-range repeat groups must stop at the node budget"
        );
        assert_eq!(
            dem.node_budget, 0,
            "each pending-substitution clone must be charged against the global node budget"
        );
    }

    #[test]
    fn demangle_impl_function_types_preserve_abi_conventions() {
        let mut dem: Demangler<'_> = Demangler::new("ypypIgnn_S2iIegyy_");
        let from: NodeRef = dem
            .demangle_impl_function_type()
            .expect("parse the from implementation type");
        assert_eq!(
            print_node(&from, Mode::Type),
            "@callee_guaranteed (@in_guaranteed Any, @in_guaranteed Any) -> ()"
        );
        assert_eq!(dem.peek(), Some(b'S'));
        let mut probe: Demangler<'_> = Demangler::new("S2iIegyy_");
        let first: NodeRef = probe.demangle_type().expect("parse repeated Swift.Int");
        assert_eq!(print_node(&first, Mode::Type), "Swift.Int");
        assert_eq!((probe.pos, probe.pending_substitutions.len()), (3, 1));
        let to: NodeRef = dem
            .demangle_impl_function_type()
            .expect("parse the to implementation type");
        assert_eq!(
            print_node(&to, Mode::Type),
            "@escaping @callee_guaranteed (@unowned Swift.Int, @unowned Swift.Int) -> ()"
        );
        assert_eq!(dem.pos, dem.src.len());
    }

    #[test]
    fn impl_function_attributes_outside_the_reference_grammar_abstain() {
        for symbol in [
            "$sINg_INg_TR",
            "$sIOg_IOg_TR",
            "$sIPg_IPg_TR",
            "$sIzg_Izg_TR",
        ] {
            assert!(
                demangle(symbol).is_err(),
                "{symbol} encodes an implementation-type attribute the reference toolchain \
                 rejects, so it must abstain rather than invent a rendering"
            );
        }
    }

    #[test]
    fn demangle_impl_function_differentiability_kinds_are_exact() {
        let cases: [(&str, &str); 4] = [
            ("d", "@differentiable"),
            ("l", "@differentiable(_linear)"),
            ("f", "@differentiable(_forward)"),
            ("r", "@differentiable(reverse)"),
        ];
        for (operator, expected) in cases {
            let symbol: String = format!("$sI{operator}g_I{operator}g_TR");
            let rendered: String = demangle(&symbol).expect("parse differentiability fixture");
            assert_eq!(
                rendered,
                format!(
                    "reabstraction thunk helper from {expected} @callee_guaranteed () -> () to \
                     {expected} @callee_guaranteed () -> ()"
                )
            );
        }
    }

    #[test]
    fn demangle_impl_function_conventions_are_exact() {
        let cases: [(&str, &str); 6] = [
            ("B", "block"),
            ("C", "c"),
            ("M", "method"),
            ("O", "objc_method"),
            ("K", "closure"),
            ("W", "witness_method"),
        ];
        for (operator, expected) in cases {
            let symbol: String = format!("$sIg{operator}_Ig{operator}_TR");
            let rendered: String = demangle(&symbol).expect("parse convention fixture");
            assert_eq!(
                rendered,
                format!(
                    "reabstraction thunk helper from @callee_guaranteed \
                     @convention({expected}) () -> () to @callee_guaranteed \
                     @convention({expected}) () -> ()"
                )
            );
        }
    }

    #[test]
    fn reabstraction_thunks_reject_partial_and_unknown_encodings() {
        for symbol in [
            "$sIg_Ig_T",
            "$sIg_Ig_TQ",
            "$sIg_Ig_TRx",
            "$sIg_Ig_TRSi",
            "$sIg_Ig_TRSiTV",
            "$sIg_Ig_lTQ",
            "$sIg_Ig_lTRx",
            "$sIg_Ig_SiTyx",
            "$sIg_Ig_TRSiTUx",
            "$sIgzB4abc_Ig_TR",
        ] {
            assert!(
                demangle(symbol).is_err(),
                "{symbol} must abstain instead of accepting a partial or unknown encoding"
            );
        }
    }
}
