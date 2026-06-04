use std::rc::Rc;

use crate::error::{Error, Result};

const MAX_DEPTH: usize = 1024;
const MAX_NODES: usize = 1 << 18;

#[must_use]
pub fn looks_like_swift_mangled(s: &str) -> bool {
    s.starts_with("_$s")
        || s.starts_with("$s")
        || s.starts_with("_$S")
        || s.starts_with("$S")
        || s.starts_with("_T0")
        || s.starts_with("_T")
}

#[must_use]
pub fn contains_symbolic_reference(mangled: &str) -> bool {
    mangled.bytes().any(|b: u8| b < 0x20)
}

pub fn demangle(symbol: &str) -> Result<String> {
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
    let rendered: String = print_node(&node, Mode::Symbol);
    if rendered.is_empty() || rendered.bytes().any(|b: u8| b < 0x20) {
        return Err(Error::Demangle(symbol.to_owned()));
    }
    Ok(rendered)
}

#[must_use]
pub fn demangle_type(mangled: &str) -> Option<String> {
    if mangled.is_empty() || contains_symbolic_reference(mangled) {
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
    FunctionType,
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
    Static,
    Optional,
    Array,
    Dictionary,
    Metatype,
    ExistentialMetatype,
    DependentGenericParamType,
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
    ValueWitness,
}

#[derive(Debug, Clone)]
struct Node {
    kind: Kind,
    text: Option<String>,
    children: Vec<NodeRef>,
}

type NodeRef = Rc<Node>;

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
}

struct Demangler<'a> {
    src: &'a [u8],
    pos: usize,
    substitutions: Vec<NodeRef>,
    words: Vec<String>,
    depth: usize,
    node_budget: usize,
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

    fn demangle_global(&mut self) -> Option<NodeRef> {
        let node: NodeRef = self.demangle_global_inner()?;
        Some(Node::unary(Kind::Global, node))
    }

    fn demangle_global_inner(&mut self) -> Option<NodeRef> {
        let entity: NodeRef = self.demangle_entity_or_type()?;
        let entity: NodeRef = self.demangle_trailing_entity_spec(entity)?;
        self.demangle_operator_suffix(entity)
    }

    fn demangle_trailing_entity_spec(&mut self, context: NodeRef) -> Option<NodeRef> {
        if !is_context_kind(context.kind) {
            return Some(context);
        }
        match self.peek() {
            Some(b'f') => {
                self.pos += 1;
                self.demangle_destructor_or_init(context)
            }
            Some(c) if c.is_ascii_digit() => {
                let name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
                self.demangle_named_entity_spec(context, name)
            }
            _ => Some(context),
        }
    }

    fn demangle_named_entity_spec(&mut self, context: NodeRef, name: NodeRef) -> Option<NodeRef> {
        self.skip_label_list();
        let _ty: Option<NodeRef> = self.try_demangle_type();
        match self.peek() {
            Some(b'v') => {
                self.pos += 1;
                self.demangle_variable(context, name)
            }
            Some(b'f') => {
                self.pos += 1;
                self.demangle_function_like(context, name)
            }
            _ => {
                let is_static: bool = self.next_if(b'Z');
                self.next_if(b'F');
                let func: NodeRef = Node::branch(Kind::Function, vec![context, name]);
                if is_static {
                    Some(Node::unary(Kind::Static, func))
                } else {
                    Some(func)
                }
            }
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
                _ => None,
            };
            match consumed {
                Some(next) => node = next,
                None => return Some(node),
            }
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
            b'L' | b'K' | b'I' | b'i' | b'r' | b'u' | b'U' | b'C' | b'B' | b'l' | b'z' | b'J'
            | b'N' | b'q' => Node::unary(Kind::TypeMetadata, base),
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

    fn demangle_witness(&mut self, base: NodeRef) -> Option<NodeRef> {
        let c: u8 = self.next()?;
        let node: NodeRef = match c {
            b'P' => Node::unary(Kind::ProtocolWitnessTable, base),
            b'p' => Node::unary(Kind::ProtocolWitnessTablePattern, base),
            b'V' => Node::unary(Kind::ValueWitnessTable, base),
            b'v' => {
                self.consume_directness();
                Node::unary(Kind::FieldOffset, base)
            }
            b'a' | b'G' | b'I' | b'l' | b'L' | b'S' | b'b' | b'C' | b'T' | b't' | b'r' | b'O' => {
                Node::unary(Kind::ProtocolWitnessTable, base)
            }
            _ => return None,
        };
        Some(node)
    }

    fn consume_directness(&mut self) {
        if matches!(self.peek(), Some(b'd' | b'i')) {
            self.pos += 1;
        }
    }

    fn demangle_thunk(&mut self, base: NodeRef) -> Option<NodeRef> {
        let c: u8 = self.next()?;
        match c {
            b'q' => Some(Node::unary(Kind::MethodDescriptor, base)),
            b'L' => Some(Node::unary(Kind::ProtocolRequirementsBaseDescriptor, base)),
            b'j' | b'D' | b'd' | b'O' | b'o' | b'V' | b'I' | b'X' | b'u' | b'E' | b'F' | b'c'
            | b'm' => Some(base),
            _ => {
                self.skip_to_end();
                Some(base)
            }
        }
    }

    fn demangle_runtime_record(&mut self, base: NodeRef) -> NodeRef {
        let _: Option<u8> = self.next();
        base
    }

    fn demangle_value_witness(&mut self, base: NodeRef) -> Option<NodeRef> {
        self.next()?;
        self.next()?;
        Some(Node::unary(Kind::ValueWitness, base))
    }

    const fn skip_to_end(&mut self) {
        self.pos = self.src.len();
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
        let saved: usize = self.pos;
        let subs: usize = self.substitutions.len();
        let words: usize = self.words.len();
        if let Some(n) = self.demangle_type() {
            return Some(n);
        }
        self.pos = saved;
        self.substitutions.truncate(subs);
        self.words.truncate(words);
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
            _ => self.demangle_named_entity(context),
        }
    }

    fn finish_nominal(&mut self, context: NodeRef, tag: u8) -> NodeRef {
        self.pos += 1;
        let node: NodeRef = Node::unary(nominal_kind_for_tag(tag), context);
        self.add_substitution(&node);
        node
    }

    fn demangle_named_entity(&mut self, context: NodeRef) -> Option<NodeRef> {
        let name: NodeRef = self.demangle_identifier(Kind::Identifier)?;
        let c: u8 = self.peek()?;
        match c {
            b'C' | b'V' | b'O' | b'a' => {
                let parent_with_name: NodeRef =
                    Node::branch(Kind::OtherNominalType, vec![context, name]);
                Some(self.finish_nominal_named(parent_with_name, c))
            }
            b'f' => {
                self.pos += 1;
                self.demangle_function_like(context, name)
            }
            b'v' => {
                self.pos += 1;
                self.demangle_variable(context, name)
            }
            _ => Some(self.demangle_function(context, name)),
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
                let _ty: Option<NodeRef> = self.try_demangle_type();
                Some(Node::branch(Kind::Allocator, vec![context, name]))
            }
            b'c' => {
                let _ty: Option<NodeRef> = self.try_demangle_type();
                Some(Node::branch(Kind::Constructor, vec![context, name]))
            }
            b'D' | b'Z' => Some(Node::unary(Kind::Deallocator, context)),
            b'd' | b'E' | b'e' => Some(Node::unary(Kind::Destructor, context)),
            _ => Some(Node::branch(Kind::Function, vec![context, name])),
        }
    }

    fn demangle_variable(&mut self, context: NodeRef, name: NodeRef) -> Option<NodeRef> {
        let accessor: u8 = self.peek()?;
        let var: NodeRef = Node::branch(Kind::Variable, vec![context, name]);
        match accessor {
            b'g' => {
                self.pos += 1;
                Some(Node::unary(Kind::Getter, var))
            }
            b's' => {
                self.pos += 1;
                Some(Node::unary(Kind::Setter, var))
            }
            b'M' | b'x' => {
                self.pos += 1;
                Some(Node::unary(Kind::ModifyAccessor, var))
            }
            b'r' | b'y' => {
                self.pos += 1;
                Some(Node::unary(Kind::ReadAccessor, var))
            }
            b'p' => {
                self.pos += 1;
                Some(var)
            }
            _ => Some(var),
        }
    }

    fn demangle_function(&mut self, context: NodeRef, name: NodeRef) -> NodeRef {
        self.skip_label_list();
        let signature: Option<NodeRef> = self.try_demangle_function_signature();
        let is_static: bool = self.next_if(b'Z');
        self.next_if(b'F');
        let mut children: Vec<NodeRef> = vec![context, name];
        if let Some(sig) = signature {
            children.push(sig);
        }
        let func: NodeRef = Node::branch(Kind::Function, children);
        if is_static {
            Node::unary(Kind::Static, func)
        } else {
            func
        }
    }

    fn skip_label_list(&mut self) {
        loop {
            match self.peek() {
                Some(b'_') => {
                    self.pos += 1;
                }
                Some(c) if c.is_ascii_digit() && c != b'0' => {
                    let saved: usize = self.pos;
                    if self.demangle_identifier(Kind::Identifier).is_none() {
                        self.pos = saved;
                        break;
                    }
                }
                _ => break,
            }
            if matches!(self.peek(), Some(b'y' | b'S' | b'x' | b'q' | b'B' | b'G')) {
                break;
            }
        }
    }

    fn try_demangle_function_signature(&mut self) -> Option<NodeRef> {
        let saved: usize = self.pos;
        let subs: usize = self.substitutions.len();
        let words: usize = self.words.len();
        if let Some(n) = self.demangle_function_signature() {
            return Some(n);
        }
        self.pos = saved;
        self.substitutions.truncate(subs);
        self.words.truncate(words);
        None
    }

    fn demangle_function_signature(&mut self) -> Option<NodeRef> {
        let result: NodeRef = self.demangle_type()?;
        let params: NodeRef = self.demangle_params()?;
        let mut annotations: Vec<NodeRef> = Vec::new();
        loop {
            match self.peek() {
                Some(b'K') => {
                    self.pos += 1;
                    annotations.push(Node::leaf(Kind::ThrowsAnnotation, "throws".to_owned()));
                }
                Some(b'Y') => {
                    self.pos += 1;
                    if self.next_if(b'a') {
                        annotations.push(Node::leaf(Kind::AsyncAnnotation, "async".to_owned()));
                    } else {
                        self.next_if(b'b');
                    }
                }
                _ => break,
            }
        }
        let mut children: Vec<NodeRef> = vec![
            Node::unary(Kind::ArgumentTuple, params),
            Node::unary(Kind::ReturnType, result),
        ];
        children.extend(annotations);
        Some(Node::branch(Kind::FunctionType, children))
    }

    fn demangle_params(&mut self) -> Option<NodeRef> {
        if self.next_if(b'y') {
            return Some(Node::branch(Kind::Tuple, Vec::new()));
        }
        let ty: NodeRef = self.demangle_type()?;
        self.next_if(b'z');
        self.next_if(b'h');
        Some(ty)
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
        let base: NodeRef = self.demangle_type_base()?;
        self.apply_type_suffixes(base)
    }

    fn demangle_type_base(&mut self) -> Option<NodeRef> {
        let c: u8 = self.peek()?;
        match c {
            b'0'..=b'9' => self.demangle_nominal_type(),
            b's' => {
                self.pos += 1;
                let module: NodeRef = Node::leaf(Kind::Module, "Swift".to_owned());
                self.demangle_nominal_in_context(module)
            }
            b'S' => self.demangle_standard_substitution(),
            b'A' => self.demangle_substitution(),
            b'x' => {
                self.pos += 1;
                Some(make_generic_param(0, 0))
            }
            b'q' => {
                self.pos += 1;
                let idx: u32 = self.demangle_generic_param_index();
                Some(make_generic_param(0, idx))
            }
            b'B' => self.demangle_builtin_type(),
            _ => None,
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
                    self.pos += 1;
                    node = self.demangle_bound_generic_args(node)?;
                }
                Some(b'S') if self.peek_at(1) == Some(b'g') => {
                    self.pos += 2;
                    node = Node::unary(Kind::Optional, node);
                }
                Some(b'm') => {
                    self.pos += 1;
                    node = Node::unary(Kind::Metatype, node);
                }
                Some(b'X') => match self.peek_at(1) {
                    Some(b'p') => {
                        self.pos += 2;
                        node = Node::unary(Kind::ExistentialMetatype, node);
                    }
                    Some(b'D') => {
                        self.pos += 2;
                    }
                    _ => break,
                },
                _ => break,
            }
        }
        Some(node)
    }

    fn demangle_nominal_type(&mut self) -> Option<NodeRef> {
        let first: NodeRef = self.demangle_identifier(Kind::Module)?;
        self.add_substitution(&first);
        self.demangle_nominal_in_context(first)
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
                    return Some(node);
                }
                b'P' => {
                    self.pos += 1;
                    let node: NodeRef = Node::unary(Kind::Protocol, context);
                    self.add_substitution(&node);
                    return Some(node);
                }
                b'0'..=b'9' => {
                    let nested: NodeRef = self.demangle_identifier(Kind::Identifier)?;
                    context = Node::branch(Kind::OtherNominalType, vec![context, nested]);
                }
                b'_' => {
                    self.pos += 1;
                    let nested: NodeRef = self.demangle_identifier(Kind::Identifier)?;
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
                None => return None,
                _ => {
                    let arg: NodeRef = self.demangle_type()?;
                    args.push(arg);
                }
            }
        }
        Some(apply_bound_generic(base, args))
    }

    fn demangle_standard_substitution(&mut self) -> Option<NodeRef> {
        self.pos += 1;
        let c: u8 = self.next()?;
        if let Some((module, name, kind)) = standard_substitution(c) {
            let module_node: NodeRef = Node::leaf(Kind::Module, module.to_owned());
            let nested: NodeRef = Node::branch(
                Kind::OtherNominalType,
                vec![module_node, Node::leaf(Kind::Identifier, name.to_owned())],
            );
            let node: NodeRef = Node::unary(kind, nested);
            return Some(node);
        }
        if c == b'g' || c == b'q' {
            return None;
        }
        None
    }

    fn demangle_builtin_type(&mut self) -> Option<NodeRef> {
        self.pos += 1;
        let c: u8 = self.next()?;
        let name: &str = match c {
            b'i' => {
                self.demangle_natural();
                self.next_if(b'_');
                "Builtin.Int"
            }
            b'f' => {
                self.demangle_natural();
                self.next_if(b'_');
                "Builtin.FPIEEE"
            }
            b'w' => "Builtin.Word",
            b'o' => "Builtin.NativeObject",
            b'p' => "Builtin.RawPointer",
            b'b' => "Builtin.BridgeObject",
            b'O' => "Builtin.UnknownObject",
            _ => "Builtin",
        };
        Some(Node::leaf(Kind::Structure, name.to_owned()))
    }

    fn demangle_substitution(&mut self) -> Option<NodeRef> {
        self.pos += 1;
        let mut idx: usize = 0;
        let mut saw: bool = false;
        loop {
            let c: u8 = self.peek()?;
            if c.is_ascii_digit() {
                idx = idx.checked_mul(10)?.checked_add((c - b'0') as usize)?;
                self.pos += 1;
                saw = true;
                continue;
            }
            if c.is_ascii_lowercase() {
                self.pos += 1;
                let resolved: usize = if saw {
                    idx.checked_mul(26)? + (c - b'a') as usize + 27
                } else {
                    (c - b'a') as usize
                };
                self.substitutions.get(resolved)?;
                idx = 0;
                saw = false;
                continue;
            }
            if c.is_ascii_uppercase() {
                self.pos += 1;
                let resolved: usize = if saw {
                    idx.checked_mul(26)? + (c - b'A') as usize + 27
                } else {
                    (c - b'A') as usize
                };
                return self.substitutions.get(resolved).cloned();
            }
            return None;
        }
    }

    fn demangle_generic_param_index(&mut self) -> u32 {
        if self.next_if(b'_') {
            return 0;
        }
        let n: u32 = self.demangle_natural();
        self.next_if(b'_');
        n + 1
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
            let slice: String = String::from_utf8_lossy(raw).into_owned();
            if !is_punycoded {
                record_words(&slice, &mut self.words);
            }
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
    if depth == 0 {
        let letter: char = char::from(b'A' + (idx % 26) as u8);
        if idx < 26 {
            letter.to_string()
        } else {
            format!("{letter}{}", idx / 26)
        }
    } else {
        format!("τ_{depth}_{idx}")
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

fn make_generic_param(depth: u32, idx: u32) -> NodeRef {
    Node::leaf(
        Kind::DependentGenericParamType,
        generic_param_name(depth, idx),
    )
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

const fn is_context_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Class
            | Kind::Structure
            | Kind::Enum
            | Kind::Protocol
            | Kind::TypeAlias
            | Kind::OtherNominalType
            | Kind::Module
    )
}

fn print_context_path(node: &Node) -> String {
    match node.kind {
        Kind::Module | Kind::Identifier => node.text.clone().unwrap_or_default(),
        Kind::Class | Kind::Structure | Kind::Enum | Kind::Protocol | Kind::TypeAlias => node
            .children
            .first()
            .map_or_else(String::new, |c: &NodeRef| print_context_path(c)),
        Kind::OtherNominalType => {
            let parts: Vec<String> = node
                .children
                .iter()
                .map(|c: &NodeRef| print_context_path(c))
                .filter(|s: &String| !s.is_empty())
                .collect();
            parts.join(".")
        }
        _ => print_node(node, Mode::Type),
    }
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
        | Kind::ValueWitness
        | Kind::ThrowsAnnotation
        | Kind::AsyncAnnotation => node.text.clone().unwrap_or_default(),
        Kind::Class | Kind::Structure | Kind::Enum | Kind::Protocol => {
            format!(
                "{}{}",
                print_context_path(node),
                nominal_kind_suffix(node.kind, mode)
            )
        }
        Kind::TypeAlias | Kind::OtherNominalType => print_context_path(node),
        Kind::BoundGenericClass
        | Kind::BoundGenericStructure
        | Kind::BoundGenericEnum
        | Kind::BoundGenericOther => print_bound_generic(node),
        Kind::Optional => format!("{}?", print_child(node, 0)),
        Kind::Array => format!("[{}]", print_child(node, 0)),
        Kind::Dictionary => format!("[{}: {}]", print_child(node, 0), print_child(node, 1)),
        Kind::Tuple => {
            let parts: Vec<String> = node
                .children
                .iter()
                .map(|c: &NodeRef| print_node(c, Mode::Type))
                .collect();
            format!("({})", parts.join(", "))
        }
        Kind::Metatype | Kind::ExistentialMetatype => format!("{}.Type", print_child(node, 0)),
        Kind::FunctionType => print_function_type(node),
        Kind::ArgumentTuple => print_argument_tuple(node),
        Kind::ReturnType => print_child(node, 0),
        Kind::Function => print_function(node),
        Kind::Variable => entity_path(node),
        Kind::Static => format!("static {}", print_child(node, 0)),
        Kind::Allocator => format!("{}.__allocating_init", entity_path(node)),
        Kind::Constructor => format!("{}.init", entity_path(node)),
        Kind::Destructor => format!("{}.deinit", context_first_path(node)),
        Kind::Deallocator => format!("{}.__deallocating_deinit", context_first_path(node)),
        Kind::Getter => format!("{}.getter", print_child(node, 0)),
        Kind::Setter => format!("{}.setter", print_child(node, 0)),
        Kind::ModifyAccessor => format!("{}.modify", print_child(node, 0)),
        Kind::ReadAccessor => format!("{}._read", print_child(node, 0)),
        Kind::TypeMetadata => format!("type metadata for {}", print_child(node, 0)),
        Kind::FullTypeMetadata => format!("full type metadata for {}", print_child(node, 0)),
        Kind::TypeMetadataAccessFunction => {
            format!("type metadata accessor for {}", print_child(node, 0))
        }
        Kind::NominalTypeDescriptor => {
            format!("nominal type descriptor for {}", print_child(node, 0))
        }
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
                "reflection metadata field descriptor for {}",
                print_child(node, 0)
            )
        }
        Kind::FieldOffset => format!("field offset for {}", print_child(node, 0)),
        Kind::MethodDescriptor => format!("method descriptor for {}", print_child(node, 0)),
        Kind::ModuleDescriptor => format!("module descriptor {}", print_child(node, 0)),
    }
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

fn context_first_path(node: &Node) -> String {
    node.children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c))
}

fn print_function(node: &Node) -> String {
    let base: String = entity_path(node);
    let signature: String = node
        .children
        .get(2)
        .map_or_else(|| "()".to_owned(), |c: &NodeRef| print_node(c, Mode::Type));
    format!("{base}{signature}")
}

fn print_function_type(node: &Node) -> String {
    let args: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::ArgumentTuple)
        .map_or_else(|| "()".to_owned(), |c: &NodeRef| print_node(c, Mode::Type));
    let ret: String = node
        .children
        .iter()
        .find(|c: &&NodeRef| c.kind == Kind::ReturnType)
        .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type));
    let throws: bool = node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::ThrowsAnnotation);
    let is_async: bool = node
        .children
        .iter()
        .any(|c: &NodeRef| c.kind == Kind::AsyncAnnotation);
    let mut middle: String = String::new();
    if is_async {
        middle.push_str(" async");
    }
    if throws {
        middle.push_str(" throws");
    }
    format!("{args}{middle} -> {ret}")
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

fn print_bound_generic(node: &Node) -> String {
    let base: String = node
        .children
        .first()
        .map_or_else(String::new, |c: &NodeRef| print_context_path(c));
    let args: Vec<String> = node
        .children
        .iter()
        .skip(1)
        .map(|c: &NodeRef| print_node(c, Mode::Type))
        .collect();
    format!("{base}<{}>", args.join(", "))
}

fn print_child(node: &Node, idx: usize) -> String {
    node.children
        .get(idx)
        .map_or_else(String::new, |c: &NodeRef| print_node(c, Mode::Type))
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
        let out: String =
            demangle("$s10SwiftHello19LoginViewControllerC17displayedUserNameSSvpWvd").expect("d");
        assert!(out.starts_with("field offset for "), "got {out}");
        assert!(out.contains("displayedUserName"), "got {out}");
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
            Some("[Swift.String: Swift.Int]")
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
}
