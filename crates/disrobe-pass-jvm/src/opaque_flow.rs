use std::collections::{BTreeMap, BTreeSet};

use crate::bytecode::{
    CodeAttribute, ExceptionEntry, Instruction, Operands, disassemble, parse_code_attribute,
};
use crate::classfile::{ClassFile, ConstantPoolEntry, MethodInfo};
use crate::descriptor::{self, JavaType};

const BOOLEAN_CLASS: &str = "java/lang/Boolean";
const BOOLEAN_DESCRIPTOR: &str = "Ljava/lang/Boolean;";
const ACC_STATIC: u16 = 0x0008;
const VISITS_PER_INSTRUCTION: usize = 32;
const HANDLER_STEPS: usize = 64;
const GOTO_HOPS: usize = 16;
const CLEANUP_ROUNDS: usize = 4;
const MAX_STACK_WORDS: usize = 65_535;
const PURE_FUNCTION_INSTRUCTIONS: usize = 4_096;
const PURE_FUNCTION_STEPS: usize = 100_000;
const PURE_FUNCTION_STACK: usize = 256;

const NOP: u8 = 0x00;
const POP: u8 = 0x57;
const POP2: u8 = 0x58;
const DUP: u8 = 0x59;
const GOTO: u8 = 0xA7;
const ATHROW: u8 = 0xBF;
const NEW: u8 = 0xBB;
const GETSTATIC: u8 = 0xB2;
const PUTSTATIC: u8 = 0xB3;
const INVOKEVIRTUAL: u8 = 0xB6;
const INVOKESPECIAL: u8 = 0xB7;
const INVOKESTATIC: u8 = 0xB8;
const IFLT: u8 = 0x9B;
const IFGE: u8 = 0x9C;

const THROWABLE: &str = "java/lang/Throwable";
const EXCEPTION: &str = "java/lang/Exception";
const RUNTIME: &str = "java/lang/RuntimeException";
const REFLECTIVE: &str = "java/lang/ReflectiveOperationException";
const IO: &str = "java/io/IOException";
const INDEX: &str = "java/lang/IndexOutOfBoundsException";

const EXCEPTION_ANCESTRY: &[(&str, &[&str])] = &[
    (THROWABLE, &[]),
    (EXCEPTION, &[THROWABLE]),
    ("java/lang/Error", &[THROWABLE]),
    (RUNTIME, &[EXCEPTION, THROWABLE]),
    (IO, &[EXCEPTION, THROWABLE]),
    ("java/io/FileNotFoundException", &[IO, EXCEPTION, THROWABLE]),
    (
        "java/io/UncheckedIOException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (REFLECTIVE, &[EXCEPTION, THROWABLE]),
    (
        "java/lang/IllegalAccessException",
        &[REFLECTIVE, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/ClassNotFoundException",
        &[REFLECTIVE, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/NoSuchMethodException",
        &[REFLECTIVE, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/NoSuchFieldException",
        &[REFLECTIVE, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/InstantiationException",
        &[REFLECTIVE, EXCEPTION, THROWABLE],
    ),
    ("java/lang/InterruptedException", &[EXCEPTION, THROWABLE]),
    (
        "java/lang/CloneNotSupportedException",
        &[EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/IllegalStateException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/IllegalArgumentException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/UnsupportedOperationException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/ArithmeticException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/NullPointerException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/ClassCastException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/SecurityException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/IllegalMonitorStateException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/NegativeArraySizeException",
        &[RUNTIME, EXCEPTION, THROWABLE],
    ),
    (INDEX, &[RUNTIME, EXCEPTION, THROWABLE]),
    (
        "java/lang/ArrayIndexOutOfBoundsException",
        &[INDEX, RUNTIME, EXCEPTION, THROWABLE],
    ),
    (
        "java/lang/StringIndexOutOfBoundsException",
        &[INDEX, RUNTIME, EXCEPTION, THROWABLE],
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpaqueValue {
    Int(i32),
    Boxed(bool),
}

pub(crate) type FunctionKey = (String, String, String);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OpaqueStatics {
    values: BTreeMap<(String, String), OpaqueValue>,
    functions: BTreeMap<FunctionKey, PureFunction>,
}

impl OpaqueStatics {
    pub(crate) const fn empty() -> Self {
        Self {
            values: BTreeMap::new(),
            functions: BTreeMap::new(),
        }
    }

    fn get(&self, owner: &str, name: &str) -> Option<OpaqueValue> {
        self.values
            .get(&(owner.to_owned(), name.to_owned()))
            .copied()
    }

    fn function(&self, member: &MemberRef) -> Option<&PureFunction> {
        self.functions.get(&(
            member.owner.clone(),
            member.name.clone(),
            member.descriptor.clone(),
        ))
    }

    pub(crate) fn add_functions(&mut self, functions: &BTreeMap<FunctionKey, PureFunction>) {
        for (key, function) in functions {
            self.functions
                .entry(key.clone())
                .or_insert_with(|| function.clone());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedBody {
    pub(crate) insns: Vec<Instruction>,
    pub(crate) exception_table: Vec<ExceptionEntry>,
    pub(crate) folded_branches: usize,
    pub(crate) pruned_handlers: usize,
    pub(crate) removed_instructions: usize,
    pub(crate) control_throws: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    Unknown,
    Int(i32),
    Hashed(i32),
    Boxed(bool),
    Caught,
    Fresh(usize),
    Text(u16),
}

impl Val {
    const fn number(self) -> Option<i32> {
        match self {
            Self::Int(value) | Self::Hashed(value) => Some(value),
            _ => None,
        }
    }

    const fn hashed(self) -> bool {
        matches!(self, Self::Hashed(_))
    }

    const fn numeric(value: i32, hashed: bool) -> Self {
        if hashed {
            Self::Hashed(value)
        } else {
            Self::Int(value)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    stack: Vec<Val>,
    locals: BTreeMap<u16, Val>,
}

struct MemberRef {
    owner: String,
    name: String,
    descriptor: String,
}

fn member_ref(cf: &ClassFile, index: u16) -> Option<MemberRef> {
    let (class_index, name_and_type_index): (u16, u16) =
        match cf.constant_pool.get(usize::from(index))? {
            ConstantPoolEntry::Fieldref {
                class_index,
                name_and_type_index,
            }
            | ConstantPoolEntry::Methodref {
                class_index,
                name_and_type_index,
            }
            | ConstantPoolEntry::InterfaceMethodref {
                class_index,
                name_and_type_index,
            } => (*class_index, *name_and_type_index),
            _ => return None,
        };
    let ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = cf.constant_pool.get(usize::from(name_and_type_index))?
    else {
        return None;
    };
    Some(MemberRef {
        owner: cf.class_name(class_index).ok()?.to_owned(),
        name: cf.utf8_at(*name_index).ok()?.to_owned(),
        descriptor: cf.utf8_at(*descriptor_index).ok()?.to_owned(),
    })
}

const fn pool_index(insn: &Instruction) -> Option<u16> {
    match insn.operands {
        Operands::ConstPool(index)
        | Operands::InvokeInterface { index, .. }
        | Operands::InvokeDynamic(index)
        | Operands::MultiANewArray { index, .. } => Some(index),
        _ => None,
    }
}

fn method_code(cf: &ClassFile, method: &MethodInfo) -> Option<CodeAttribute> {
    method.attributes.iter().find_map(|attribute| {
        (cf.utf8_at(attribute.name_index).ok()? == "Code")
            .then(|| parse_code_attribute(&attribute.info).ok())
            .flatten()
    })
}

fn is_boolean_value_call(cf: &ClassFile, insn: &Instruction) -> bool {
    insn.opcode == INVOKEVIRTUAL
        && pool_index(insn)
            .and_then(|index: u16| member_ref(cf, index))
            .is_some_and(|member: MemberRef| {
                member.owner == BOOLEAN_CLASS
                    && member.name == "booleanValue"
                    && member.descriptor == "()Z"
            })
}

fn own_static_field(cf: &ClassFile, this: &str, insn: &Instruction, opcode: u8) -> Option<String> {
    if insn.opcode != opcode {
        return None;
    }
    let member: MemberRef = member_ref(cf, pool_index(insn)?)?;
    (member.owner == this).then_some(member.name)
}

fn boxed_initializer(cf: &ClassFile, insns: &[Instruction], at: usize) -> Option<bool> {
    let before: &[Instruction] = &insns[..at];
    let constant = |insn: &Instruction| -> Option<bool> {
        match insn.opcode {
            0x03 => Some(false),
            0x04 => Some(true),
            _ => None,
        }
    };
    if let [.., new, dup, value, init] = before
        && new.opcode == NEW
        && dup.opcode == DUP
        && init.opcode == INVOKESPECIAL
        && pool_index(new).and_then(|index: u16| cf.class_name(index).ok()) == Some(BOOLEAN_CLASS)
        && pool_index(init)
            .and_then(|index: u16| member_ref(cf, index))
            .is_some_and(|member: MemberRef| {
                member.owner == BOOLEAN_CLASS
                    && member.name == "<init>"
                    && member.descriptor == "(Z)V"
            })
    {
        return constant(value);
    }
    if let [.., value, call] = before
        && call.opcode == INVOKESTATIC
        && pool_index(call)
            .and_then(|index: u16| member_ref(cf, index))
            .is_some_and(|member: MemberRef| {
                member.owner == BOOLEAN_CLASS
                    && member.name == "valueOf"
                    && member.descriptor == "(Z)Ljava/lang/Boolean;"
            })
    {
        return constant(value);
    }
    if let [.., load] = before
        && load.opcode == GETSTATIC
        && let Some(member) = pool_index(load).and_then(|index: u16| member_ref(cf, index))
        && member.owner == BOOLEAN_CLASS
        && member.descriptor == BOOLEAN_DESCRIPTOR
    {
        return match member.name.as_str() {
            "TRUE" => Some(true),
            "FALSE" => Some(false),
            _ => None,
        };
    }
    None
}

const fn is_branching(opcode: u8) -> bool {
    matches!(opcode, 0x99..=0xAB | 0xC6..=0xC9 | ATHROW)
}

fn compared_with_tell(
    cf: &ClassFile,
    this: &str,
    insns: &[Instruction],
    at: usize,
    tells: &BTreeSet<String>,
) -> bool {
    let tell_value = |load: &Instruction, call: &Instruction| -> bool {
        own_static_field(cf, this, load, GETSTATIC)
            .is_some_and(|name: String| tells.contains(&name))
            && is_boolean_value_call(cf, call)
    };
    let is_compare = |insn: &Instruction| matches!(insn.opcode, 0x9F..=0xA4);
    let after: Option<&[Instruction]> = insns.get(at + 1..);
    if let Some([load, call, compare, ..]) = after
        && tell_value(load, call)
        && is_compare(compare)
    {
        return true;
    }
    at >= 2
        && insns
            .get(at + 1)
            .is_some_and(|compare: &Instruction| is_compare(compare))
        && tell_value(&insns[at - 2], &insns[at - 1])
}

#[must_use]
pub(crate) fn opaque_statics(cf: &ClassFile) -> OpaqueStatics {
    let mut statics: OpaqueStatics = OpaqueStatics::empty();
    statics.functions = pure_functions(cf);
    let Ok(this) = cf.this_class_name() else {
        return statics;
    };
    let mut bodies: Vec<(bool, Vec<Instruction>, usize)> = Vec::new();
    for method in &cf.methods {
        let Some(code): Option<CodeAttribute> = method_code(cf, method) else {
            continue;
        };
        let Ok(insns): crate::error::Result<Vec<Instruction>> = disassemble(&code.code) else {
            return statics;
        };
        let is_clinit: bool = cf
            .utf8_at(method.name_index)
            .is_ok_and(|name: &str| name == "<clinit>");
        bodies.push((is_clinit, insns, code.exception_table.len()));
    }
    let mut tells: BTreeSet<String> = BTreeSet::new();
    for (_, insns, _) in &bodies {
        for window in insns.windows(3) {
            if let Some(name) = own_static_field(cf, this, &window[0], GETSTATIC)
                && is_boolean_value_call(cf, &window[1])
                && matches!(window[2].opcode, IFGE | IFLT)
            {
                tells.insert(name);
            }
        }
    }
    if tells.is_empty() {
        return statics;
    }
    let mut writes: BTreeMap<String, Vec<Option<bool>>> = BTreeMap::new();
    for (is_clinit, insns, handlers) in &bodies {
        let straight: bool = *is_clinit
            && *handlers == 0
            && !insns
                .iter()
                .any(|insn: &Instruction| is_branching(insn.opcode));
        for (at, insn) in insns.iter().enumerate() {
            if let Some(name) = own_static_field(cf, this, insn, PUTSTATIC) {
                let value: Option<bool> = if straight {
                    boxed_initializer(cf, insns, at)
                } else {
                    None
                };
                writes.entry(name).or_default().push(value);
            }
        }
    }
    let mut declared: BTreeMap<String, String> = BTreeMap::new();
    for field in &cf.fields {
        if field.access_flags & ACC_STATIC == 0 {
            continue;
        }
        let (Ok(name), Ok(descriptor)) = (
            cf.utf8_at(field.name_index),
            cf.utf8_at(field.descriptor_index),
        ) else {
            continue;
        };
        let has_constant_value: bool = field.attributes.iter().any(|attribute| {
            cf.utf8_at(attribute.name_index)
                .is_ok_and(|kind: &str| kind == "ConstantValue")
        });
        if !has_constant_value {
            declared.insert(name.to_owned(), descriptor.to_owned());
        }
    }
    let mut boxed: BTreeSet<String> = BTreeSet::new();
    for name in &tells {
        if declared.get(name).map(String::as_str) != Some(BOOLEAN_DESCRIPTOR) {
            continue;
        }
        if let Some([Some(value)]) = writes.get(name).map(Vec::as_slice) {
            statics
                .values
                .insert((this.to_owned(), name.clone()), OpaqueValue::Boxed(*value));
            boxed.insert(name.clone());
        }
    }
    if boxed.is_empty() {
        return statics;
    }
    for (name, descriptor) in &declared {
        if !matches!(descriptor.as_str(), "Z" | "I" | "B" | "S" | "C") || writes.contains_key(name)
        {
            continue;
        }
        let mut reads: usize = 0;
        let only_compared: bool = bodies.iter().all(|(_, insns, _)| {
            insns.iter().enumerate().all(|(at, insn)| {
                if own_static_field(cf, this, insn, GETSTATIC).as_ref() != Some(name) {
                    return true;
                }
                reads += 1;
                compared_with_tell(cf, this, insns, at, &boxed)
            })
        });
        if only_compared && reads > 0 {
            statics
                .values
                .insert((this.to_owned(), name.clone()), OpaqueValue::Int(0));
        }
    }
    statics
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PureOp {
    Push(i32),
    Load(u16),
    Store(u16),
    Increment(u16, i32),
    Binary(u8),
    Unary(u8),
    Pop,
    Dup,
    Swap,
    Branch(u8, usize),
    Jump(usize),
    Switch(usize),
    Return,
    Nop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PureSwitch {
    keys: Vec<(i32, usize)>,
    default: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PureFunction {
    parameters: u16,
    max_locals: u16,
    ops: Vec<PureOp>,
    switches: Vec<PureSwitch>,
}

impl PureFunction {
    fn lower(cf: &ClassFile, method: &MethodInfo, parameters: u16) -> Option<Self> {
        let code: CodeAttribute = method_code(cf, method)?;
        if !code.exception_table.is_empty() {
            return None;
        }
        let insns: Vec<Instruction> = disassemble(&code.code).ok()?;
        if insns.is_empty() || insns.len() > PURE_FUNCTION_INSTRUCTIONS {
            return None;
        }
        let layout: Layout = Layout::new(&insns);
        let mut ops: Vec<PureOp> = Vec::with_capacity(insns.len());
        let mut switches: Vec<PureSwitch> = Vec::new();
        for insn in &insns {
            let targets: Vec<u32> = branch_targets(insn);
            let target = |at: usize| -> Option<usize> { layout.index(*targets.get(at)?) };
            let op: PureOp = if let Some(value) = const_int(cf, insn) {
                PureOp::Push(value)
            } else {
                match insn.opcode {
                    NOP => PureOp::Nop,
                    0x15 | 0x1A..=0x1D => PureOp::Load(local_operand(insn, 0x1A)?),
                    0x36 | 0x3B..=0x3E => PureOp::Store(local_operand(insn, 0x3B)?),
                    0x84 => match insn.operands {
                        Operands::Iinc { index, delta } => PureOp::Increment(index, delta),
                        _ => return None,
                    },
                    0x60 | 0x64 | 0x68 | 0x6C | 0x70 | 0x78 | 0x7A | 0x7C | 0x7E | 0x80 | 0x82 => {
                        PureOp::Binary(insn.opcode)
                    }
                    0x74 | 0x91..=0x93 => PureOp::Unary(insn.opcode),
                    POP => PureOp::Pop,
                    DUP => PureOp::Dup,
                    0x5F => PureOp::Swap,
                    0x99..=0xA4 => PureOp::Branch(insn.opcode, target(0)?),
                    GOTO | 0xC8 => PureOp::Jump(target(0)?),
                    0xAA | 0xAB => {
                        let default: usize = target(0)?;
                        let keys: Vec<(i32, usize)> = match &insn.operands {
                            Operands::TableSwitch { low, .. } => targets[1..]
                                .iter()
                                .enumerate()
                                .map(|(slot, pc): (usize, &u32)| {
                                    let key: i32 = low.checked_add(i32::try_from(slot).ok()?)?;
                                    Some((key, layout.index(*pc)?))
                                })
                                .collect::<Option<Vec<(i32, usize)>>>()?,
                            Operands::LookupSwitch { pairs, .. } => pairs
                                .iter()
                                .zip(&targets[1..])
                                .map(|((key, _), pc): (&(i32, i32), &u32)| {
                                    Some((*key, layout.index(*pc)?))
                                })
                                .collect::<Option<Vec<(i32, usize)>>>()?,
                            _ => return None,
                        };
                        switches.push(PureSwitch { keys, default });
                        PureOp::Switch(switches.len() - 1)
                    }
                    0xAC => PureOp::Return,
                    _ => return None,
                }
            };
            ops.push(op);
        }
        Some(Self {
            parameters,
            max_locals: code.max_locals.max(parameters),
            ops,
            switches,
        })
    }

    fn evaluate(&self, arguments: &[i32]) -> Option<i32> {
        if arguments.len() != usize::from(self.parameters) {
            return None;
        }
        let mut locals: Vec<Option<i32>> = vec![None; usize::from(self.max_locals)];
        for (slot, value) in arguments.iter().enumerate() {
            *locals.get_mut(slot)? = Some(*value);
        }
        let mut stack: Vec<i32> = Vec::new();
        let mut at: usize = 0;
        for _ in 0..PURE_FUNCTION_STEPS {
            let op: PureOp = *self.ops.get(at)?;
            at += 1;
            match op {
                PureOp::Push(value) => stack.push(value),
                PureOp::Load(slot) => stack.push((*locals.get(usize::from(slot))?)?),
                PureOp::Store(slot) => *locals.get_mut(usize::from(slot))? = Some(stack.pop()?),
                PureOp::Increment(slot, delta) => {
                    let held: &mut Option<i32> = locals.get_mut(usize::from(slot))?;
                    *held = Some(held.as_ref()?.wrapping_add(delta));
                }
                PureOp::Binary(opcode) => {
                    let rhs: i32 = stack.pop()?;
                    let lhs: i32 = stack.pop()?;
                    stack.push(int_binary(opcode, lhs, rhs)?);
                }
                PureOp::Unary(opcode) => {
                    let value: i32 = stack.pop()?;
                    stack.push(int_unary(opcode, value)?);
                }
                PureOp::Pop => {
                    stack.pop()?;
                }
                PureOp::Dup => stack.push(*stack.last()?),
                PureOp::Swap => {
                    let top: i32 = stack.pop()?;
                    let below: i32 = stack.pop()?;
                    stack.extend([top, below]);
                }
                PureOp::Branch(opcode, target) => {
                    let taken: bool = if opcode >= 0x9F {
                        let rhs: i32 = stack.pop()?;
                        let lhs: i32 = stack.pop()?;
                        compare(opcode - 0x9F, lhs, rhs)
                    } else {
                        compare(opcode - 0x99, stack.pop()?, 0)
                    };
                    if taken {
                        at = target;
                    }
                }
                PureOp::Jump(target) => at = target,
                PureOp::Switch(index) => {
                    let key: i32 = stack.pop()?;
                    let table: &PureSwitch = self.switches.get(index)?;
                    at = table
                        .keys
                        .iter()
                        .find(|(candidate, _): &&(i32, usize)| *candidate == key)
                        .map_or(table.default, |(_, target): &(i32, usize)| *target);
                }
                PureOp::Return => return stack.pop(),
                PureOp::Nop => {}
            }
            if stack.len() > PURE_FUNCTION_STACK {
                return None;
            }
        }
        None
    }
}

const fn compare(kind: u8, lhs: i32, rhs: i32) -> bool {
    match kind {
        0 => lhs == rhs,
        1 => lhs != rhs,
        2 => lhs < rhs,
        3 => lhs >= rhs,
        4 => lhs > rhs,
        _ => lhs <= rhs,
    }
}

#[must_use]
pub(crate) fn pure_functions(cf: &ClassFile) -> BTreeMap<FunctionKey, PureFunction> {
    let mut functions: BTreeMap<FunctionKey, PureFunction> = BTreeMap::new();
    let Ok(owner) = cf.this_class_name() else {
        return functions;
    };
    for method in &cf.methods {
        if method.access_flags & ACC_STATIC == 0 {
            continue;
        }
        let (Ok(name), Ok(descriptor_text)) = (
            cf.utf8_at(method.name_index),
            cf.utf8_at(method.descriptor_index),
        ) else {
            continue;
        };
        let Some(parsed): Option<descriptor::MethodDescriptor> =
            descriptor::parse_method(descriptor_text)
        else {
            continue;
        };
        if parsed.returns != JavaType::Int
            || parsed.params.is_empty()
            || parsed
                .params
                .iter()
                .any(|ty: &JavaType| *ty != JavaType::Int)
        {
            continue;
        }
        let Ok(parameters): std::result::Result<u16, std::num::TryFromIntError> =
            u16::try_from(parsed.params.len())
        else {
            continue;
        };
        if let Some(function) = PureFunction::lower(cf, method, parameters) {
            functions.insert(
                (
                    owner.to_owned(),
                    name.to_owned(),
                    descriptor_text.to_owned(),
                ),
                function,
            );
        }
    }
    functions
}

fn branch_targets(insn: &Instruction) -> Vec<u32> {
    let target = |offset: i32| -> u32 { (i64::from(insn.pc) + i64::from(offset)) as u32 };
    match &insn.operands {
        Operands::Branch(offset) => vec![target(*offset)],
        Operands::TableSwitch {
            default, offsets, ..
        } => std::iter::once(*default)
            .chain(offsets.iter().copied())
            .map(target)
            .collect(),
        Operands::LookupSwitch { default, pairs } => std::iter::once(*default)
            .chain(pairs.iter().map(|(_, offset): &(i32, i32)| *offset))
            .map(target)
            .collect(),
        _ => Vec::new(),
    }
}

const fn ends_flow(opcode: u8) -> bool {
    matches!(
        opcode,
        GOTO | 0xA8 | 0xA9 | 0xAA | 0xAB | 0xAC..=0xB1 | ATHROW | 0xC8 | 0xC9
    )
}

const fn is_conditional(opcode: u8) -> bool {
    matches!(opcode, 0x99..=0xA6 | 0xC6 | 0xC7)
}

const fn opcode_never_throws(opcode: u8) -> bool {
    matches!(
        opcode,
        0x00..=0x11
            | 0x15..=0x2D
            | 0x36..=0x4E
            | 0x57..=0x6B
            | 0x6E
            | 0x6F
            | 0x72..=0xA7
            | 0xAA
            | 0xAB
            | 0xC6..=0xC8
    )
}

const fn type_words(ty: &JavaType) -> usize {
    match ty {
        JavaType::Void => 0,
        JavaType::Long | JavaType::Double => 2,
        _ => 1,
    }
}

fn field_words(descriptor: &str) -> Option<usize> {
    descriptor::parse_field(descriptor).map(|ty: JavaType| type_words(&ty))
}

const fn int_binary(opcode: u8, a: i32, b: i32) -> Option<i32> {
    match opcode {
        0x60 => Some(a.wrapping_add(b)),
        0x64 => Some(a.wrapping_sub(b)),
        0x68 => Some(a.wrapping_mul(b)),
        0x6C if b != 0 => Some(a.wrapping_div(b)),
        0x70 if b != 0 => Some(a.wrapping_rem(b)),
        0x78 => Some(a.wrapping_shl(b as u32 & 31)),
        0x7A => Some(a.wrapping_shr(b as u32 & 31)),
        0x7C => Some(((a as u32) >> (b as u32 & 31)) as i32),
        0x7E => Some(a & b),
        0x80 => Some(a | b),
        0x82 => Some(a ^ b),
        _ => None,
    }
}

fn int_unary(opcode: u8, a: i32) -> Option<i32> {
    match opcode {
        0x74 => Some(a.wrapping_neg()),
        0x91 => Some(i32::from(a as i8)),
        0x92 => Some(i32::from(a as u16)),
        0x93 => Some(i32::from(a as i16)),
        _ => None,
    }
}

fn const_int(cf: &ClassFile, insn: &Instruction) -> Option<i32> {
    match insn.opcode {
        0x02..=0x08 => Some(i32::from(insn.opcode) - 3),
        0x10 | 0x11 => match insn.operands {
            Operands::Byte(value) | Operands::Short(value) => Some(value),
            _ => None,
        },
        0x12 | 0x13 => match cf.constant_pool.get(usize::from(pool_index(insn)?)) {
            Some(ConstantPoolEntry::Integer(value)) => Some(*value),
            _ => None,
        },
        _ => None,
    }
}

fn plain_constant(cf: &ClassFile, insn: &Instruction) -> bool {
    pool_index(insn).is_some_and(|index: u16| {
        matches!(
            cf.constant_pool.get(usize::from(index)),
            Some(
                ConstantPoolEntry::Integer(_)
                    | ConstantPoolEntry::Float(_)
                    | ConstantPoolEntry::Long(_)
                    | ConstantPoolEntry::Double(_)
                    | ConstantPoolEntry::String { .. }
            )
        )
    })
}

fn string_constant(cf: &ClassFile, insn: &Instruction) -> bool {
    matches!(insn.opcode, 0x12 | 0x13)
        && pool_index(insn).is_some_and(|index: u16| {
            matches!(
                cf.constant_pool.get(usize::from(index)),
                Some(ConstantPoolEntry::String { .. })
            )
        })
}

fn local_operand(insn: &Instruction, short_base: u8) -> Option<u16> {
    match insn.operands {
        Operands::Local(index) => Some(index),
        _ if insn.opcode >= short_base && insn.opcode < short_base + 4 => {
            Some(u16::from(insn.opcode - short_base))
        }
        _ => None,
    }
}

fn is_parse_int(member: &MemberRef) -> bool {
    member.owner == "java/lang/Integer"
        && member.name == "parseInt"
        && member.descriptor == "(Ljava/lang/String;)I"
}

fn parse_decimal_int(cf: &ClassFile, index: u16) -> Option<i32> {
    let ConstantPoolEntry::String { utf8_index } = cf.constant_pool.get(usize::from(index))? else {
        return None;
    };
    let text: &str = cf.utf8_at(*utf8_index).ok()?;
    let digits: &str = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte: u8| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<i32>().ok()
}

fn exception_ancestry(class: &str) -> Option<&'static [&'static str]> {
    EXCEPTION_ANCESTRY
        .iter()
        .find(|(name, _): &&(&str, &[&str])| *name == class)
        .map(|(_, ancestors): &(&str, &[&str])| *ancestors)
}

fn allocated_exception(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    if insn.opcode != NEW {
        return None;
    }
    let class: &str = cf.class_name(pool_index(insn)?).ok()?;
    exception_ancestry(class).map(|_| class.to_owned())
}

fn exception_constructor(cf: &ClassFile, insn: &Instruction) -> Option<MemberRef> {
    if insn.opcode != INVOKESPECIAL {
        return None;
    }
    let member: MemberRef = member_ref(cf, pool_index(insn)?)?;
    (member.name == "<init>"
        && matches!(member.descriptor.as_str(), "()V" | "(Ljava/lang/String;)V")
        && exception_ancestry(&member.owner).is_some())
    .then_some(member)
}

fn catches(cf: &ClassFile, entry: &ExceptionEntry, thrown: &str) -> Option<bool> {
    if entry.catch_type == 0 {
        return Some(true);
    }
    let caught: &str = cf.class_name(entry.catch_type).ok()?;
    Some(caught == thrown || exception_ancestry(thrown)?.contains(&caught))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Branch {
    Jump(u32),
    Next,
}

impl Branch {
    const fn target(self) -> Option<u32> {
        match self {
            Self::Jump(target) => Some(target),
            Self::Next => None,
        }
    }
}

fn decide(insn: &Instruction, stack: &[Val]) -> Option<Branch> {
    let top = |depth: usize| -> Option<i32> {
        stack
            .len()
            .checked_sub(depth + 1)
            .and_then(|at: usize| stack[at].number())
    };
    let taken = |condition: bool| -> Option<Branch> {
        let target: u32 = branch_targets(insn).first().copied()?;
        Some(if condition {
            Branch::Jump(target)
        } else {
            Branch::Next
        })
    };
    match insn.opcode {
        0x99..=0x9E => taken(compare(insn.opcode - 0x99, top(0)?, 0)),
        0x9F..=0xA4 => taken(compare(insn.opcode - 0x9F, top(1)?, top(0)?)),
        0xAA | 0xAB => {
            let key: i32 = top(0)?;
            let offset: i32 = match &insn.operands {
                Operands::TableSwitch {
                    default,
                    low,
                    offsets,
                    ..
                } => usize::try_from(i64::from(key) - i64::from(*low))
                    .ok()
                    .and_then(|slot: usize| offsets.get(slot).copied())
                    .unwrap_or(*default),
                Operands::LookupSwitch { default, pairs } => pairs
                    .iter()
                    .find(|(match_key, _): &&(i32, i32)| *match_key == key)
                    .map_or(*default, |(_, offset): &(i32, i32)| *offset),
                _ => return None,
            };
            Some(Branch::Jump(
                (i64::from(insn.pc) + i64::from(offset)) as u32,
            ))
        }
        _ => None,
    }
}

fn decision_is_hashed(insn: &Instruction, stack: &[Val]) -> bool {
    let words: usize = if matches!(insn.opcode, 0x9F..=0xA4) {
        2
    } else {
        1
    };
    stack
        .iter()
        .rev()
        .take(words)
        .any(|value: &Val| value.hashed())
}

struct Interpreter<'a> {
    cf: &'a ClassFile,
    statics: &'a OpaqueStatics,
}

impl Interpreter<'_> {
    fn pop(stack: &mut Vec<Val>, words: usize) -> Option<()> {
        let keep: usize = stack.len().checked_sub(words)?;
        stack.truncate(keep);
        Some(())
    }

    fn push(stack: &mut Vec<Val>, value: Val, words: usize) -> Option<()> {
        if stack.len() + words > MAX_STACK_WORDS {
            return None;
        }
        match words {
            0 => {}
            1 => stack.push(value),
            _ => {
                stack.push(Val::Unknown);
                stack.push(Val::Unknown);
            }
        }
        Some(())
    }

    fn pure_call(&self, insn: &Instruction, stack: &[Val]) -> Option<Val> {
        if insn.opcode != INVOKESTATIC {
            return None;
        }
        let member: MemberRef = member_ref(self.cf, pool_index(insn)?)?;
        if is_parse_int(&member) {
            let Val::Text(index) = *stack.last()? else {
                return None;
            };
            return parse_decimal_int(self.cf, index).map(Val::Hashed);
        }
        let function: &PureFunction = self.statics.function(&member)?;
        let count: usize = usize::from(function.parameters);
        let arguments: Vec<i32> = stack
            .get(stack.len().checked_sub(count)?..)?
            .iter()
            .map(|value: &Val| value.number())
            .collect::<Option<Vec<i32>>>()?;
        function.evaluate(&arguments).map(Val::Hashed)
    }

    fn may_throw(&self, insn: &Instruction, before: &Frame) -> bool {
        if opcode_never_throws(insn.opcode) {
            return false;
        }
        match insn.opcode {
            0x12..=0x14 => !plain_constant(self.cf, insn),
            0x6C | 0x70 => before
                .stack
                .last()
                .and_then(|value: &Val| value.number())
                .is_none_or(|divisor: i32| divisor == 0),
            NEW => allocated_exception(self.cf, insn).is_none(),
            INVOKESPECIAL => exception_constructor(self.cf, insn).is_none(),
            INVOKESTATIC => self.pure_call(insn, &before.stack).is_none(),
            GETSTATIC => !pool_index(insn)
                .and_then(|index: u16| member_ref(self.cf, index))
                .is_some_and(|member: MemberRef| {
                    self.statics.get(&member.owner, &member.name).is_some()
                }),
            INVOKEVIRTUAL => {
                !(is_boolean_value_call(self.cf, insn)
                    && matches!(before.stack.last(), Some(Val::Boxed(_))))
            }
            _ => true,
        }
    }

    fn step(&self, index: usize, insn: &Instruction, frame: &mut Frame) -> Option<()> {
        let stack: &mut Vec<Val> = &mut frame.stack;
        let op: u8 = insn.opcode;
        if let Some(value) = const_int(self.cf, insn) {
            return Self::push(stack, Val::Int(value), 1);
        }
        match op {
            NOP => Some(()),
            0x12 | 0x13 if string_constant(self.cf, insn) => {
                Self::push(stack, Val::Text(pool_index(insn)?), 1)
            }
            0x01 | 0x0B..=0x0D | 0x12 | 0x13 => Self::push(stack, Val::Unknown, 1),
            0x09 | 0x0A | 0x0E | 0x0F | 0x14 => Self::push(stack, Val::Unknown, 2),
            0x15 | 0x1A..=0x1D => {
                let slot: u16 = local_operand(insn, 0x1A)?;
                let held: Val = *frame.locals.get(&slot)?;
                let value: Val = if held.number().is_some() {
                    held
                } else {
                    Val::Unknown
                };
                Self::push(stack, value, 1)
            }
            0x19 | 0x2A..=0x2D => {
                let slot: u16 = local_operand(insn, 0x2A)?;
                let value: Val = match frame.locals.get(&slot)? {
                    held @ (Val::Boxed(_) | Val::Caught) => *held,
                    _ => Val::Unknown,
                };
                Self::push(stack, value, 1)
            }
            0x17 | 0x22..=0x25 => {
                frame.locals.get(&local_operand(insn, 0x22)?)?;
                Self::push(stack, Val::Unknown, 1)
            }
            0x16 | 0x18 | 0x1E..=0x21 | 0x26..=0x29 => {
                let base: u8 = if matches!(op, 0x16 | 0x1E..=0x21) {
                    0x1E
                } else {
                    0x26
                };
                frame.locals.get(&local_operand(insn, base)?)?;
                Self::push(stack, Val::Unknown, 2)
            }
            0x2E | 0x30 | 0x32..=0x35 => {
                Self::pop(stack, 2)?;
                Self::push(stack, Val::Unknown, 1)
            }
            0x2F | 0x31 => {
                Self::pop(stack, 2)?;
                Self::push(stack, Val::Unknown, 2)
            }
            0x36 | 0x38 | 0x3A | 0x3B..=0x3E | 0x43..=0x46 | 0x4B..=0x4E => {
                let base: u8 = match op {
                    0x3B..=0x3E => 0x3B,
                    0x43..=0x46 => 0x43,
                    _ => 0x4B,
                };
                let slot: u16 = local_operand(insn, base)?;
                let value: Val = stack.pop()?;
                let kept: Val = match (op, value) {
                    (0x36 | 0x3B..=0x3E, Val::Int(_) | Val::Hashed(_))
                    | (0x3A | 0x4B..=0x4E, Val::Boxed(_) | Val::Caught) => value,
                    _ => Val::Unknown,
                };
                frame.locals.insert(slot, kept);
                Some(())
            }
            0x37 | 0x39 | 0x3F..=0x42 | 0x47..=0x4A => {
                let base: u8 = if matches!(op, 0x3F..=0x42) {
                    0x3F
                } else {
                    0x47
                };
                let slot: u16 = local_operand(insn, base)?;
                Self::pop(stack, 2)?;
                frame.locals.insert(slot, Val::Unknown);
                frame.locals.insert(slot.checked_add(1)?, Val::Unknown);
                Some(())
            }
            0x4F | 0x51 | 0x53..=0x56 => Self::pop(stack, 3),
            0x50 | 0x52 => Self::pop(stack, 4),
            POP => Self::pop(stack, 1),
            POP2 => Self::pop(stack, 2),
            DUP => {
                let top: Val = *stack.last()?;
                Self::push(stack, top, 1)
            }
            0x5A => {
                let (b, a): (Val, Val) = (stack.pop()?, stack.pop()?);
                stack.extend([b, a, b]);
                Some(())
            }
            0x5B => {
                let (c, b, a): (Val, Val, Val) = (stack.pop()?, stack.pop()?, stack.pop()?);
                stack.extend([c, a, b, c]);
                Some(())
            }
            0x5C => {
                let (b, a): (Val, Val) = (stack.pop()?, stack.pop()?);
                stack.extend([a, b, a, b]);
                Some(())
            }
            0x5D => {
                let (c, b, a): (Val, Val, Val) = (stack.pop()?, stack.pop()?, stack.pop()?);
                stack.extend([b, c, a, b, c]);
                Some(())
            }
            0x5E => {
                let (d, c, b, a): (Val, Val, Val, Val) =
                    (stack.pop()?, stack.pop()?, stack.pop()?, stack.pop()?);
                stack.extend([c, d, a, b, c, d]);
                Some(())
            }
            0x5F => {
                let top: Val = stack.pop()?;
                let below: Val = stack.pop()?;
                stack.extend([top, below]);
                Some(())
            }
            0x60 | 0x64 | 0x68 | 0x6C | 0x70 | 0x78 | 0x7A | 0x7C | 0x7E | 0x80 | 0x82 => {
                let rhs: Val = stack.pop()?;
                let lhs: Val = stack.pop()?;
                let value: Val = match (lhs.number(), rhs.number()) {
                    (Some(a), Some(b)) => int_binary(op, a, b)
                        .map_or(Val::Unknown, |result: i32| {
                            Val::numeric(result, lhs.hashed() || rhs.hashed())
                        }),
                    _ => Val::Unknown,
                };
                Self::push(stack, value, 1)
            }
            0x62 | 0x66 | 0x6A | 0x6E | 0x72 | 0x95 | 0x96 => {
                Self::pop(stack, 2)?;
                Self::push(stack, Val::Unknown, 1)
            }
            0x61 | 0x63 | 0x65 | 0x67 | 0x69 | 0x6B | 0x6D | 0x6F | 0x71 | 0x73 | 0x7F | 0x81
            | 0x83 => {
                Self::pop(stack, 4)?;
                Self::push(stack, Val::Unknown, 2)
            }
            0x79 | 0x7B | 0x7D => {
                Self::pop(stack, 3)?;
                Self::push(stack, Val::Unknown, 2)
            }
            0x74 | 0x91..=0x93 => {
                let operand: Val = stack.pop()?;
                let value: Val = operand
                    .number()
                    .and_then(|a: i32| int_unary(op, a))
                    .map_or(Val::Unknown, |result: i32| {
                        Val::numeric(result, operand.hashed())
                    });
                Self::push(stack, value, 1)
            }
            0x76 | 0x86 | 0x8B => {
                Self::pop(stack, 1)?;
                Self::push(stack, Val::Unknown, 1)
            }
            0x75 | 0x77 | 0x8A | 0x8F => {
                Self::pop(stack, 2)?;
                Self::push(stack, Val::Unknown, 2)
            }
            0x85 | 0x87 | 0x8C | 0x8D => {
                Self::pop(stack, 1)?;
                Self::push(stack, Val::Unknown, 2)
            }
            0x88 | 0x89 | 0x8E | 0x90 => {
                Self::pop(stack, 2)?;
                Self::push(stack, Val::Unknown, 1)
            }
            0x84 => {
                let Operands::Iinc { index, delta } = insn.operands else {
                    return None;
                };
                let held: Val = *frame.locals.get(&index)?;
                let value: Val = held.number().map_or(Val::Unknown, |current: i32| {
                    Val::numeric(current.wrapping_add(delta), held.hashed())
                });
                frame.locals.insert(index, value);
                Some(())
            }
            0x94 | 0x97 | 0x98 => {
                Self::pop(stack, 4)?;
                Self::push(stack, Val::Unknown, 1)
            }
            0x99..=0x9E | 0xC6 | 0xC7 | 0xAA | 0xAB | 0xC2 | 0xC3 => Self::pop(stack, 1),
            0x9F..=0xA6 => Self::pop(stack, 2),
            GOTO | 0xC8 | 0xB1 => Some(()),
            0xAC | 0xAE | 0xB0 | ATHROW => Self::pop(stack, 1),
            0xAD | 0xAF => Self::pop(stack, 2),
            GETSTATIC => {
                let member: MemberRef = member_ref(self.cf, pool_index(insn)?)?;
                let words: usize = field_words(&member.descriptor)?;
                let value: Val = match self.statics.get(&member.owner, &member.name) {
                    Some(OpaqueValue::Int(value)) => Val::Int(value),
                    Some(OpaqueValue::Boxed(value)) => Val::Boxed(value),
                    None => Val::Unknown,
                };
                Self::push(stack, value, words)
            }
            PUTSTATIC => {
                let member: MemberRef = member_ref(self.cf, pool_index(insn)?)?;
                Self::pop(stack, field_words(&member.descriptor)?)
            }
            0xB4 => {
                let member: MemberRef = member_ref(self.cf, pool_index(insn)?)?;
                Self::pop(stack, 1)?;
                Self::push(stack, Val::Unknown, field_words(&member.descriptor)?)
            }
            0xB5 => {
                let member: MemberRef = member_ref(self.cf, pool_index(insn)?)?;
                Self::pop(stack, 1 + field_words(&member.descriptor)?)
            }
            INVOKEVIRTUAL | INVOKESPECIAL | INVOKESTATIC | 0xB9 => {
                let member: MemberRef = member_ref(self.cf, pool_index(insn)?)?;
                let parsed: descriptor::MethodDescriptor =
                    descriptor::parse_method(&member.descriptor)?;
                let arguments: usize = parsed.params.iter().map(type_words).sum();
                let receiver: usize = usize::from(op != INVOKESTATIC);
                let result: Val = if is_boolean_value_call(self.cf, insn) {
                    match stack.last() {
                        Some(Val::Boxed(value)) => Val::Int(i32::from(*value)),
                        _ => Val::Unknown,
                    }
                } else {
                    self.pure_call(insn, stack).unwrap_or(Val::Unknown)
                };
                Self::pop(stack, arguments + receiver)?;
                Self::push(stack, result, type_words(&parsed.returns))
            }
            0xBA => {
                let index: u16 = pool_index(insn)?;
                let (_, descriptor_text): (String, String) =
                    crate::bytecode::method_name_descriptor_at(self.cf, index)?;
                let parsed: descriptor::MethodDescriptor =
                    descriptor::parse_method(&descriptor_text)?;
                Self::pop(stack, parsed.params.iter().map(type_words).sum())?;
                Self::push(stack, Val::Unknown, type_words(&parsed.returns))
            }
            NEW => {
                let value: Val = if allocated_exception(self.cf, insn).is_some() {
                    Val::Fresh(index)
                } else {
                    Val::Unknown
                };
                Self::push(stack, value, 1)
            }
            0xBC | 0xBD | 0xBE | 0xC0 | 0xC1 => {
                Self::pop(stack, 1)?;
                Self::push(stack, Val::Unknown, 1)
            }
            0xC5 => {
                let Operands::MultiANewArray { dimensions, .. } = insn.operands else {
                    return None;
                };
                Self::pop(stack, usize::from(dimensions))?;
                Self::push(stack, Val::Unknown, 1)
            }
            _ => None,
        }
    }
}

fn merged(held: Val, arriving: Val) -> Val {
    if held == arriving {
        return held;
    }
    match (held.number(), arriving.number()) {
        (Some(a), Some(b)) if a == b => Val::Hashed(a),
        _ => Val::Unknown,
    }
}

fn merge_frame(slot: &mut Option<Frame>, incoming: &Frame) -> Option<bool> {
    let Some(existing) = slot else {
        *slot = Some(incoming.clone());
        return Some(true);
    };
    if existing.stack.len() != incoming.stack.len() {
        return None;
    }
    let mut changed: bool = false;
    for (held, arriving) in existing.stack.iter_mut().zip(&incoming.stack) {
        let next: Val = merged(*held, *arriving);
        if next != *held {
            *held = next;
            changed = true;
        }
    }
    for (local, arriving) in &incoming.locals {
        match existing.locals.get_mut(local) {
            None => {
                existing.locals.insert(*local, *arriving);
                changed = true;
            }
            Some(held) => {
                let next: Val = merged(*held, *arriving);
                if next != *held {
                    *held = next;
                    changed = true;
                }
            }
        }
    }
    Some(changed)
}

struct Layout {
    index_of: BTreeMap<u32, usize>,
}

impl Layout {
    fn new(insns: &[Instruction]) -> Self {
        Self {
            index_of: insns
                .iter()
                .enumerate()
                .map(|(index, insn): (usize, &Instruction)| (insn.pc, index))
                .collect(),
        }
    }

    fn index(&self, pc: u32) -> Option<usize> {
        self.index_of.get(&pc).copied()
    }
}

fn covers(entry: &ExceptionEntry, pc: u32) -> bool {
    u32::from(entry.start_pc) <= pc && pc < u32::from(entry.end_pc)
}

struct Method<'a> {
    interpreter: Interpreter<'a>,
    insns: &'a [Instruction],
    layout: Layout,
}

enum Thrown {
    Handler(usize),
    Exits,
    Unknown,
}

impl Method<'_> {
    fn fresh_throw(&self, table: &[ExceptionEntry], index: usize, before: &Frame) -> Thrown {
        let insn: &Instruction = &self.insns[index];
        let Some(Val::Fresh(allocation)) = before.stack.last().copied() else {
            return Thrown::Unknown;
        };
        if insn.opcode != ATHROW {
            return Thrown::Unknown;
        }
        let Some(class): Option<String> =
            allocated_exception(self.interpreter.cf, &self.insns[allocation])
        else {
            return Thrown::Unknown;
        };
        for entry in table.iter().filter(|entry| covers(entry, insn.pc)) {
            match catches(self.interpreter.cf, entry, &class) {
                Some(true) => {
                    return self
                        .layout
                        .index(u32::from(entry.handler_pc))
                        .map_or(Thrown::Unknown, Thrown::Handler);
                }
                Some(false) => {}
                None => return Thrown::Unknown,
            }
        }
        Thrown::Exits
    }

    fn edges(
        &self,
        table: &[ExceptionEntry],
        index: usize,
        before: &Frame,
        after: &Frame,
    ) -> Option<Vec<(usize, Frame)>> {
        let insn: &Instruction = &self.insns[index];
        let mut edges: Vec<(usize, Frame)> = Vec::new();
        match self.fresh_throw(table, index, before) {
            Thrown::Handler(handler) => edges.push((
                handler,
                Frame {
                    stack: vec![*before.stack.last()?],
                    locals: before.locals.clone(),
                },
            )),
            Thrown::Exits => {}
            Thrown::Unknown => {
                let throws: bool = self.interpreter.may_throw(insn, before);
                for entry in table.iter().filter(|entry| covers(entry, insn.pc)) {
                    if entry.catch_type == 0 || throws {
                        edges.push((
                            self.layout.index(u32::from(entry.handler_pc))?,
                            Frame {
                                stack: vec![Val::Unknown],
                                locals: before.locals.clone(),
                            },
                        ));
                    }
                }
            }
        }
        match decide(insn, &before.stack) {
            Some(Branch::Jump(target)) => edges.push((self.layout.index(target)?, after.clone())),
            Some(Branch::Next) => edges.push((index + 1, after.clone())),
            None => {
                for target in branch_targets(insn) {
                    edges.push((self.layout.index(target)?, after.clone()));
                }
                if !ends_flow(insn.opcode) {
                    edges.push((index + 1, after.clone()));
                }
            }
        }
        edges
            .iter()
            .all(|(target, _): &(usize, Frame)| *target < self.insns.len())
            .then_some(edges)
    }

    fn after(&self, index: usize, before: &Frame) -> Option<Frame> {
        let mut after: Frame = before.clone();
        self.interpreter
            .step(index, &self.insns[index], &mut after)?;
        Some(after)
    }

    fn solve(
        &self,
        table: &[ExceptionEntry],
        entry_slots: u16,
    ) -> Result<Vec<Option<Frame>>, &'static str> {
        let mut frames: Vec<Option<Frame>> = vec![None; self.insns.len()];
        frames[0] = Some(Frame {
            stack: Vec::new(),
            locals: (0..entry_slots)
                .map(|slot: u16| (slot, Val::Unknown))
                .collect(),
        });
        let mut worklist: Vec<usize> = vec![0];
        let budget: usize = self
            .insns
            .len()
            .saturating_mul(VISITS_PER_INSTRUCTION)
            .saturating_add(64);
        let mut visits: usize = 0;
        while let Some(index) = worklist.pop() {
            visits += 1;
            if visits > budget {
                return Err("the constant-flow analysis exceeded its visit budget");
            }
            if matches!(self.insns[index].opcode, 0xA8 | 0xA9 | 0xC9) {
                return Err("the body uses subroutines");
            }
            let before: Frame = frames[index]
                .clone()
                .ok_or("a queued instruction has no frame")?;
            let after: Frame = self
                .after(index, &before)
                .ok_or("an instruction reads an unassigned local or underflows the stack")?;
            let edges: Vec<(usize, Frame)> = self
                .edges(table, index, &before, &after)
                .ok_or("a successor lies outside the body")?;
            for (target, arriving) in edges {
                if merge_frame(&mut frames[target], &arriving)
                    .ok_or("stack heights differ where paths join")?
                {
                    worklist.push(target);
                }
            }
        }
        Ok(frames)
    }

    fn handler_rethrows_unchanged(&self, handler: usize) -> Option<Vec<usize>> {
        let mut frame: Frame = Frame {
            stack: vec![Val::Caught],
            locals: BTreeMap::new(),
        };
        let mut index: usize = handler;
        let mut path: Vec<usize> = Vec::new();
        for _ in 0..HANDLER_STEPS {
            let insn: &Instruction = self.insns.get(index)?;
            path.push(index);
            let pure: bool = matches!(
                insn.opcode,
                0x00..=0x08
                    | 0x10..=0x13
                    | 0x15
                    | 0x19
                    | 0x1A..=0x1D
                    | 0x2A..=0x2D
                    | 0x36
                    | 0x3A
                    | 0x3B..=0x3E
                    | 0x4B..=0x4E
                    | POP
                    | DUP
                    | 0x5F
                    | 0x60
                    | 0x64
                    | 0x68
                    | 0x70
                    | 0x6C
                    | 0x74
                    | 0x78
                    | 0x7A
                    | 0x7C
                    | 0x7E
                    | 0x80
                    | 0x82
                    | 0x84
                    | 0x91..=0x93
            );
            match insn.opcode {
                ATHROW => return (frame.stack.last() == Some(&Val::Caught)).then_some(path),
                GOTO | 0xC8 => {
                    index = self.layout.index(*branch_targets(insn).first()?)?;
                }
                opcode if is_conditional(opcode) => {
                    let decided: Branch = decide(insn, &frame.stack)?;
                    self.interpreter.step(index, insn, &mut frame)?;
                    index = match decided {
                        Branch::Jump(target) => self.layout.index(target)?,
                        Branch::Next => index + 1,
                    };
                }
                _ if pure => {
                    self.interpreter.step(index, insn, &mut frame)?;
                    index += 1;
                }
                _ => return None,
            }
        }
        None
    }

    fn identity_handlers(&self, table: &[ExceptionEntry]) -> BTreeSet<usize> {
        let mut pruned: BTreeSet<usize> = BTreeSet::new();
        for (position, entry) in table.iter().enumerate() {
            let Some(handler): Option<usize> = self.layout.index(u32::from(entry.handler_pc))
            else {
                continue;
            };
            let Some(path): Option<Vec<usize>> = self.handler_rethrows_unchanged(handler) else {
                continue;
            };
            let mut handler_cover: Option<Vec<usize>> = None;
            let consistent: bool = path.iter().all(|step: &usize| {
                let cover: Vec<usize> = covering_entries(table, self.insns[*step].pc, 0);
                if cover.contains(&position) {
                    return false;
                }
                match &handler_cover {
                    Some(existing) => *existing == cover,
                    None => {
                        handler_cover = Some(cover);
                        true
                    }
                }
            });
            let handler_cover: Vec<usize> = handler_cover.unwrap_or_default();
            let equivalent: bool = consistent
                && self
                    .insns
                    .iter()
                    .filter(|insn: &&Instruction| covers(entry, insn.pc))
                    .all(|insn: &Instruction| {
                        covering_entries(table, insn.pc, position + 1) == handler_cover
                    });
            if equivalent {
                pruned.insert(position);
            }
        }
        pruned
    }

    fn allocation_parts(&self, allocation: usize, leaders: &BTreeSet<u32>) -> Option<Vec<usize>> {
        let cf: &ClassFile = self.interpreter.cf;
        let class: String = allocated_exception(cf, self.insns.get(allocation)?)?;
        if self.insns.get(allocation + 1)?.opcode != DUP {
            return None;
        }
        let mut parts: Vec<usize> = vec![allocation, allocation + 1];
        let mut cursor: usize = allocation + 2;
        if string_constant(cf, self.insns.get(cursor)?) {
            parts.push(cursor);
            cursor += 1;
        }
        let init: MemberRef = exception_constructor(cf, self.insns.get(cursor)?)?;
        let takes_message: bool = init.descriptor == "(Ljava/lang/String;)V";
        if init.owner != class || takes_message != (parts.len() == 3) {
            return None;
        }
        parts.push(cursor);
        parts[1..]
            .iter()
            .all(|part: &usize| !leaders.contains(&self.insns[*part].pc))
            .then_some(parts)
    }

    fn control_throws(
        &self,
        table: &[ExceptionEntry],
        frames: &[Option<Frame>],
        leaders: &BTreeSet<u32>,
    ) -> Option<ControlThrows> {
        let mut parts: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (index, insn) in self.insns.iter().enumerate() {
            if insn.opcode != NEW
                || !frames[index]
                    .as_ref()
                    .is_some_and(|frame: &Frame| frame.stack.is_empty())
            {
                continue;
            }
            if let Some(found) = self.allocation_parts(index, leaders) {
                parts.insert(index, found);
            }
        }
        let mut escaped: BTreeSet<usize> = BTreeSet::new();
        let mut throws: Vec<(usize, usize, u32)> = Vec::new();
        let mut pops: Vec<(usize, usize)> = Vec::new();
        for (index, frame) in frames.iter().enumerate() {
            let Some(before): Option<&Frame> = frame.as_ref() else {
                continue;
            };
            let after: Frame = self.after(index, before)?;
            let kept: usize = before
                .stack
                .iter()
                .zip(&after.stack)
                .take_while(|(held, now): &(&Val, &Val)| held == now)
                .count();
            let opcode: u8 = self.insns[index].opcode;
            for value in &before.stack[kept..] {
                let Val::Fresh(allocation) = *value else {
                    continue;
                };
                let constructed: bool = parts
                    .get(&allocation)
                    .is_some_and(|found: &Vec<usize>| found.last() == Some(&index));
                if constructed {
                    continue;
                }
                match (opcode, self.fresh_throw(table, index, before)) {
                    (POP, _) if before.stack.last() == Some(value) => {
                        pops.push((allocation, index));
                    }
                    (ATHROW, Thrown::Handler(handler)) if before.stack.len() == 1 => {
                        throws.push((allocation, index, self.insns[handler].pc));
                    }
                    _ => {
                        escaped.insert(allocation);
                    }
                }
            }
            for (target, arriving) in self.edges(table, index, before, &after)? {
                let landed: Option<&Frame> = frames.get(target)?.as_ref();
                for (position, value) in arriving.stack.iter().enumerate() {
                    if let Val::Fresh(allocation) = *value
                        && landed.and_then(|frame: &Frame| frame.stack.get(position)) != Some(value)
                    {
                        escaped.insert(allocation);
                    }
                }
                for value in arriving.locals.values() {
                    if let Val::Fresh(allocation) = *value {
                        escaped.insert(allocation);
                    }
                }
            }
        }
        let mut control: ControlThrows = ControlThrows::default();
        for (allocation, found) in parts {
            let thrown: bool = throws
                .iter()
                .any(|(owner, _, _): &(usize, usize, u32)| *owner == allocation);
            if escaped.contains(&allocation) || !thrown {
                continue;
            }
            control.silenced.extend(found);
            control.silenced.extend(
                pops.iter()
                    .filter(|(owner, _): &&(usize, usize)| *owner == allocation)
                    .map(|(_, index): &(usize, usize)| *index),
            );
            for (owner, index, handler_pc) in &throws {
                if *owner == allocation {
                    control.jumps.insert(*index, *handler_pc);
                }
            }
        }
        Some(control)
    }
}

#[derive(Default)]
struct ControlThrows {
    silenced: BTreeSet<usize>,
    jumps: BTreeMap<usize, u32>,
}

fn covering_entries(table: &[ExceptionEntry], pc: u32, after: usize) -> Vec<usize> {
    table
        .iter()
        .enumerate()
        .skip(after)
        .filter(|(_, entry): &(usize, &ExceptionEntry)| covers(entry, pc))
        .map(|(position, _): (usize, &ExceptionEntry)| position)
        .collect()
}

const fn simple(pc: u32, opcode: u8, mnemonic: &'static str, operands: Operands) -> Instruction {
    Instruction {
        pc,
        opcode,
        mnemonic,
        wide: false,
        operands,
    }
}

const fn nop_at(pc: u32) -> Instruction {
    simple(pc, NOP, "nop", Operands::None)
}

fn goto_to(pc: u32, target: u32) -> Instruction {
    simple(
        pc,
        GOTO,
        "goto",
        Operands::Branch((i64::from(target) - i64::from(pc)) as i32),
    )
}

const fn operand_words(opcode: u8) -> usize {
    if matches!(opcode, 0x9F..=0xA6) { 2 } else { 1 }
}

fn pure_producer_effect(
    interpreter: &Interpreter<'_>,
    insn: &Instruction,
) -> Option<(usize, usize)> {
    if const_int(interpreter.cf, insn).is_some() {
        return Some((0, 1));
    }
    match insn.opcode {
        0x15 | 0x1A..=0x1D => Some((0, 1)),
        GETSTATIC => {
            let member: MemberRef = member_ref(interpreter.cf, pool_index(insn)?)?;
            interpreter
                .statics
                .get(&member.owner, &member.name)
                .map(|_| (0, 1))
        }
        INVOKEVIRTUAL if is_boolean_value_call(interpreter.cf, insn) => Some((1, 1)),
        INVOKESTATIC => {
            let member: MemberRef = member_ref(interpreter.cf, pool_index(insn)?)?;
            if is_parse_int(&member) {
                return Some((1, 1));
            }
            interpreter
                .statics
                .function(&member)
                .map(|function: &PureFunction| (usize::from(function.parameters), 1))
        }
        0x12 | 0x13 if string_constant(interpreter.cf, insn) => Some((0, 1)),
        0x60 | 0x64 | 0x68 | 0x78 | 0x7A | 0x7C | 0x7E | 0x80 | 0x82 => Some((2, 1)),
        0x74 | 0x91..=0x93 => Some((1, 1)),
        _ => None,
    }
}

fn operand_producers(
    interpreter: &Interpreter<'_>,
    insns: &[Instruction],
    branch: usize,
    leaders: &BTreeSet<u32>,
) -> Option<Vec<usize>> {
    let mut need: usize = operand_words(insns[branch].opcode);
    let mut producers: Vec<usize> = Vec::new();
    let mut index: usize = branch;
    while need > 0 {
        if leaders.contains(&insns[index].pc) {
            return None;
        }
        index = index.checked_sub(1)?;
        let (pops, pushes): (usize, usize) = pure_producer_effect(interpreter, &insns[index])?;
        need = need.checked_sub(pushes)? + pops;
        producers.push(index);
    }
    Some(producers)
}

fn leaders_of(insns: &[Instruction], table: &[ExceptionEntry]) -> BTreeSet<u32> {
    let mut leaders: BTreeSet<u32> = insns.iter().flat_map(branch_targets).collect();
    leaders.extend(
        table
            .iter()
            .map(|entry: &ExceptionEntry| u32::from(entry.handler_pc)),
    );
    leaders
}

fn plain_reachability(
    insns: &[Instruction],
    table: &[ExceptionEntry],
    layout: &Layout,
) -> Option<Vec<bool>> {
    let mut reached: Vec<bool> = vec![false; insns.len()];
    let mut worklist: Vec<usize> = vec![0];
    while let Some(index) = worklist.pop() {
        if reached[index] {
            continue;
        }
        reached[index] = true;
        let insn: &Instruction = &insns[index];
        let mut successors: Vec<usize> = Vec::new();
        for target in branch_targets(insn) {
            successors.push(layout.index(target)?);
        }
        if !ends_flow(insn.opcode) {
            successors.push(index + 1);
        }
        for entry in table.iter().filter(|entry| covers(entry, insn.pc)) {
            successors.push(layout.index(u32::from(entry.handler_pc))?);
        }
        for successor in successors {
            if successor >= insns.len() {
                return None;
            }
            if !reached[successor] {
                worklist.push(successor);
            }
        }
    }
    Some(reached)
}

fn rebuild_table(
    insns: &[Instruction],
    table: &[ExceptionEntry],
    code_length: u32,
    safe: &BTreeSet<u32>,
) -> Option<Vec<ExceptionEntry>> {
    let mut rebuilt: Vec<ExceptionEntry> = Vec::with_capacity(table.len());
    for entry in table {
        let covered: Vec<&Instruction> = insns
            .iter()
            .filter(|insn: &&Instruction| covers(entry, insn.pc))
            .collect();
        let live: bool = if entry.catch_type == 0 {
            !covered.is_empty()
        } else {
            covered.iter().any(|insn: &&Instruction| {
                !safe.contains(&insn.pc) && !matches!(insn.opcode, NOP | GOTO | POP | POP2)
            })
        };
        if !live {
            continue;
        }
        let start: u32 = covered.first()?.pc;
        let end: u32 = insns
            .iter()
            .map(|insn: &Instruction| insn.pc)
            .find(|pc: &u32| *pc >= u32::from(entry.end_pc))
            .unwrap_or(code_length);
        rebuilt.push(ExceptionEntry {
            start_pc: u16::try_from(start).ok()?,
            end_pc: u16::try_from(end).ok()?,
            handler_pc: entry.handler_pc,
            catch_type: entry.catch_type,
        });
    }
    Some(rebuilt)
}

fn thread_gotos(insns: &mut [Instruction]) {
    let layout: Layout = Layout::new(insns);
    for index in 0..insns.len() {
        if insns[index].opcode != GOTO {
            continue;
        }
        let Some(mut target): Option<u32> = branch_targets(&insns[index]).first().copied() else {
            continue;
        };
        for _ in 0..GOTO_HOPS {
            match layout.index(target).map(|at: usize| &insns[at]) {
                Some(next) if next.opcode == GOTO && next.pc != insns[index].pc => {
                    let Some(hop): Option<u32> = branch_targets(next).first().copied() else {
                        break;
                    };
                    target = hop;
                }
                _ => break,
            }
        }
        let following: Option<u32> = insns.get(index + 1).map(|insn: &Instruction| insn.pc);
        let pc: u32 = insns[index].pc;
        insns[index] = if following == Some(target) {
            nop_at(pc)
        } else {
            goto_to(pc, target)
        };
    }
}

fn method_is_obfuscated(method: &Method<'_>, table: &[ExceptionEntry]) -> Option<bool> {
    let interpreter: &Interpreter<'_> = &method.interpreter;
    let reads_opaque: bool = method.insns.iter().any(|insn: &Instruction| {
        insn.opcode == GETSTATIC
            && pool_index(insn)
                .and_then(|index: u16| member_ref(interpreter.cf, index))
                .is_some_and(|member: MemberRef| {
                    interpreter
                        .statics
                        .get(&member.owner, &member.name)
                        .is_some()
                })
    });
    if reads_opaque {
        return Some(true);
    }
    let reached: Vec<bool> = plain_reachability(method.insns, table, &method.layout)?;
    if reached.iter().any(|reached: &bool| !reached) {
        return Some(true);
    }
    let targets: BTreeSet<u32> = method.insns.iter().flat_map(branch_targets).collect();
    Some(
        table
            .iter()
            .any(|entry: &ExceptionEntry| targets.contains(&u32::from(entry.handler_pc))),
    )
}

fn calls_pure_function(method: &Method<'_>) -> bool {
    method.insns.iter().any(|insn: &Instruction| {
        insn.opcode == INVOKESTATIC
            && pool_index(insn)
                .and_then(|index: u16| member_ref(method.interpreter.cf, index))
                .is_some_and(|member: MemberRef| {
                    is_parse_int(&member) || method.interpreter.statics.function(&member).is_some()
                })
    })
}

fn refused<T>(reason: &'static str) -> Option<T> {
    crate::debug::dbg_kv("opaque-flow", || format!("left unchanged: {reason}"));
    None
}

#[must_use]
pub(crate) fn normalize(
    cf: &ClassFile,
    insns: &[Instruction],
    table: &[ExceptionEntry],
    code_length: usize,
    entry_slots: u16,
    statics: &OpaqueStatics,
) -> Option<NormalizedBody> {
    if insns.is_empty() || insns.len() > usize::from(u16::MAX) {
        return None;
    }
    let code_length: u32 = u32::try_from(code_length).ok()?;
    let method: Method<'_> = Method {
        interpreter: Interpreter { cf, statics },
        insns,
        layout: Layout::new(insns),
    };
    let pruned: BTreeSet<usize> = method.identity_handlers(table);
    let typed_rethrow: bool = pruned
        .iter()
        .any(|position: &usize| table[*position].catch_type != 0);
    let obfuscated: bool = typed_rethrow
        || match method_is_obfuscated(&method, table) {
            Some(obfuscated) => obfuscated,
            None => return refused("control flow leaves the method body"),
        };
    if !obfuscated && !calls_pure_function(&method) {
        return None;
    }
    let kept: Vec<ExceptionEntry> = table
        .iter()
        .enumerate()
        .filter(|(position, _): &(usize, &ExceptionEntry)| !pruned.contains(position))
        .map(|(_, entry): (usize, &ExceptionEntry)| entry.clone())
        .collect();
    let frames: Vec<Option<Frame>> = match method.solve(&kept, entry_slots) {
        Ok(frames) => frames,
        Err(reason) => return refused(reason),
    };
    let leaders: BTreeSet<u32> = leaders_of(insns, &kept);
    let mut folded: usize = 0;
    let mut hashed: bool = false;
    let mut silenced: BTreeSet<usize> = BTreeSet::new();
    let mut replacements: BTreeMap<usize, Vec<Instruction>> = BTreeMap::new();
    for (index, insn) in insns.iter().enumerate() {
        let Some(frame): Option<&Frame> = frames[index].as_ref() else {
            continue;
        };
        let is_switch: bool = matches!(insn.opcode, 0xAA | 0xAB);
        if !(is_switch || is_conditional(insn.opcode)) {
            continue;
        }
        let Some(decided): Option<Branch> = decide(insn, &frame.stack) else {
            continue;
        };
        folded += 1;
        hashed |= decision_is_hashed(insn, &frame.stack);
        let jump: Option<Instruction> =
            decided.target().map(|target: u32| goto_to(insn.pc, target));
        match operand_producers(&method.interpreter, insns, index, &leaders) {
            Some(producers) => {
                silenced.extend(producers);
                replacements.insert(index, vec![jump.unwrap_or_else(|| nop_at(insn.pc))]);
            }
            None => {
                let discard: Instruction = if operand_words(insn.opcode) == 2 {
                    simple(insn.pc, POP2, "pop2", Operands::None)
                } else {
                    simple(insn.pc, POP, "pop", Operands::None)
                };
                let mut sequence: Vec<Instruction> = vec![discard];
                if let Branch::Jump(target) = decided {
                    sequence.push(goto_to(insn.pc + 1, target));
                }
                replacements.insert(index, sequence);
            }
        }
    }
    if !obfuscated && !hashed {
        return None;
    }
    let Some(control): Option<ControlThrows> = method.control_throws(&kept, &frames, &leaders)
    else {
        return refused("a thrown allocation could not be traced");
    };
    silenced.extend(control.silenced.iter().copied());
    for (index, handler_pc) in &control.jumps {
        replacements.insert(*index, vec![goto_to(insns[*index].pc, *handler_pc)]);
    }
    let safe: BTreeSet<u32> = insns
        .iter()
        .enumerate()
        .filter(|(index, insn): &(usize, &Instruction)| {
            frames[*index]
                .as_ref()
                .is_some_and(|frame: &Frame| !method.interpreter.may_throw(insn, frame))
                || control.jumps.contains_key(index)
                || control.silenced.contains(index)
        })
        .map(|(_, insn): (usize, &Instruction)| insn.pc)
        .collect();
    let mut rewritten: Vec<Instruction> = Vec::with_capacity(insns.len());
    let mut removed: usize = 0;
    for (index, insn) in insns.iter().enumerate() {
        if frames[index].is_none() {
            removed += 1;
            continue;
        }
        if let Some(sequence) = replacements.remove(&index) {
            rewritten.extend(sequence);
        } else if silenced.contains(&index) {
            rewritten.push(nop_at(insn.pc));
        } else {
            rewritten.push(insn.clone());
        }
    }
    let Some(mut exception_table): Option<Vec<ExceptionEntry>> =
        rebuild_table(&rewritten, &kept, code_length, &safe)
    else {
        return refused("an exception range no longer fits the rewritten body");
    };
    for _ in 0..CLEANUP_ROUNDS {
        let current: Layout = Layout::new(&rewritten);
        let reached: Vec<bool> = plain_reachability(&rewritten, &exception_table, &current)?;
        if reached.iter().all(|reached: &bool| *reached) {
            break;
        }
        let before: usize = rewritten.len();
        rewritten = rewritten
            .into_iter()
            .zip(reached)
            .filter_map(|(insn, reached): (Instruction, bool)| reached.then_some(insn))
            .collect();
        removed += before - rewritten.len();
        exception_table = rebuild_table(&rewritten, &exception_table, code_length, &safe)?;
    }
    thread_gotos(&mut rewritten);
    if folded == 0 && pruned.is_empty() && removed == 0 && control.jumps.is_empty() {
        return None;
    }
    let check: Layout = Layout::new(&rewritten);
    let closed: bool = rewritten.iter().all(|insn: &Instruction| {
        branch_targets(insn)
            .iter()
            .all(|target: &u32| check.index(*target).is_some())
    }) && exception_table
        .iter()
        .all(|entry: &ExceptionEntry| check.index(u32::from(entry.handler_pc)).is_some());
    if !closed || rewritten.last().is_some_and(|insn| !ends_flow(insn.opcode)) {
        return refused("the rewritten body would branch outside itself");
    }
    crate::debug::dbg_kv("opaque-flow-body", || {
        rewritten
            .iter()
            .map(|insn: &Instruction| match branch_targets(insn).as_slice() {
                [] => format!("{}:{}", insn.pc, insn.mnemonic),
                targets => format!("{}:{}->{targets:?}", insn.pc, insn.mnemonic),
            })
            .collect::<Vec<String>>()
            .join(" ")
    });
    Some(NormalizedBody {
        insns: rewritten,
        exception_table,
        folded_branches: folded,
        pruned_handlers: pruned.len(),
        removed_instructions: removed,
        control_throws: control.jumps.len(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::classfile::{Attribute, FieldInfo};

    fn utf8(text: &str) -> ConstantPoolEntry {
        ConstantPoolEntry::Utf8(text.to_owned())
    }

    fn pool() -> Vec<ConstantPoolEntry> {
        vec![
            ConstantPoolEntry::Placeholder,
            utf8("T"),
            ConstantPoolEntry::Class { name_index: 1 },
            utf8("F"),
            utf8(BOOLEAN_DESCRIPTOR),
            ConstantPoolEntry::NameAndType {
                name_index: 3,
                descriptor_index: 4,
            },
            ConstantPoolEntry::Fieldref {
                class_index: 2,
                name_and_type_index: 5,
            },
            utf8(BOOLEAN_CLASS),
            ConstantPoolEntry::Class { name_index: 7 },
            utf8("booleanValue"),
            utf8("()Z"),
            ConstantPoolEntry::NameAndType {
                name_index: 9,
                descriptor_index: 10,
            },
            ConstantPoolEntry::Methodref {
                class_index: 8,
                name_and_type_index: 11,
            },
            utf8("<init>"),
            utf8("(Z)V"),
            ConstantPoolEntry::NameAndType {
                name_index: 13,
                descriptor_index: 14,
            },
            ConstantPoolEntry::Methodref {
                class_index: 8,
                name_and_type_index: 15,
            },
            utf8("<clinit>"),
            utf8("()V"),
            utf8("Code"),
            utf8("run"),
            utf8("()I"),
            utf8("G"),
            utf8("Z"),
            ConstantPoolEntry::NameAndType {
                name_index: 22,
                descriptor_index: 23,
            },
            ConstantPoolEntry::Fieldref {
                class_index: 2,
                name_and_type_index: 24,
            },
            utf8(RUNTIME),
            ConstantPoolEntry::Class { name_index: 26 },
            ConstantPoolEntry::NameAndType {
                name_index: 13,
                descriptor_index: 18,
            },
            ConstantPoolEntry::Methodref {
                class_index: 27,
                name_and_type_index: 28,
            },
            utf8("(I)I"),
            utf8("hash"),
            ConstantPoolEntry::NameAndType {
                name_index: 31,
                descriptor_index: 30,
            },
            ConstantPoolEntry::Methodref {
                class_index: 2,
                name_and_type_index: 32,
            },
            utf8("spin"),
        ]
    }

    fn code_attribute(code: &[u8]) -> Attribute {
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&8u16.to_be_bytes());
        info.extend_from_slice(&8u16.to_be_bytes());
        info.extend_from_slice(&u32::try_from(code.len()).expect("length").to_be_bytes());
        info.extend_from_slice(code);
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        Attribute {
            name_index: 19,
            info,
        }
    }

    fn method(name_index: u16, descriptor_index: u16, code: &[u8]) -> MethodInfo {
        MethodInfo {
            access_flags: ACC_STATIC,
            name_index,
            descriptor_index,
            attributes: vec![code_attribute(code)],
        }
    }

    const CLINIT_TRUE: &[u8] = &[
        0xBB, 0x00, 0x08, 0x59, 0x04, 0xB7, 0x00, 0x10, 0xB3, 0x00, 0x06, 0xB1,
    ];
    const OPAQUE_RETURN: &[u8] = &[
        0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0x9C, 0x00, 0x06, 0x05, 0xAC, 0xBF, 0x04, 0xAC,
    ];

    fn class(methods: Vec<MethodInfo>) -> ClassFile {
        ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: pool(),
            access_flags: 0x0021,
            this_class: 2,
            super_class: 0,
            interfaces: Vec::new(),
            fields: vec![
                FieldInfo {
                    access_flags: 0x0009,
                    name_index: 3,
                    descriptor_index: 4,
                    attributes: Vec::new(),
                },
                FieldInfo {
                    access_flags: 0x0009,
                    name_index: 22,
                    descriptor_index: 23,
                    attributes: Vec::new(),
                },
            ],
            methods,
            attributes: Vec::new(),
        }
    }

    fn jbco_class() -> ClassFile {
        class(vec![
            method(17, 18, CLINIT_TRUE),
            method(20, 21, OPAQUE_RETURN),
        ])
    }

    fn opcodes(insns: &[Instruction]) -> Vec<u8> {
        insns.iter().map(|insn: &Instruction| insn.opcode).collect()
    }

    fn normalized(
        cf: &ClassFile,
        code: &[u8],
        table: &[ExceptionEntry],
        entry_slots: u16,
    ) -> Option<NormalizedBody> {
        let insns: Vec<Instruction> = disassemble(code).expect("disassemble");
        normalize(
            cf,
            &insns,
            table,
            code.len(),
            entry_slots,
            &opaque_statics(cf),
        )
    }

    fn catch_all(start_pc: u16, end_pc: u16, handler_pc: u16) -> ExceptionEntry {
        ExceptionEntry {
            start_pc,
            end_pc,
            handler_pc,
            catch_type: 0,
        }
    }

    #[test]
    fn a_boxed_true_field_tested_with_ifge_is_an_opaque_constant() {
        let cf: ClassFile = jbco_class();
        assert_eq!(
            opaque_statics(&cf).get("T", "F"),
            Some(OpaqueValue::Boxed(true))
        );
        let body: NormalizedBody = normalized(&cf, OPAQUE_RETURN, &[], 0).expect("normalized");
        assert_eq!(opcodes(&body.insns), vec![NOP, NOP, NOP, 0x04, 0xAC]);
        assert_eq!(body.folded_branches, 1);
        assert_eq!(body.removed_instructions, 3);
    }

    #[test]
    fn a_field_written_outside_the_initializer_is_not_opaque() {
        let writer: &[u8] = &[0xB2, 0x00, 0x06, 0xB3, 0x00, 0x06, 0xB1];
        let cf: ClassFile = class(vec![
            method(17, 18, CLINIT_TRUE),
            method(20, 21, OPAQUE_RETURN),
            method(3, 18, writer),
        ]);
        assert_eq!(opaque_statics(&cf), OpaqueStatics::empty());
    }

    #[test]
    fn a_class_without_the_boolean_sign_test_has_no_opaque_fields() {
        let plain: &[u8] = &[
            0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0x99, 0x00, 0x05, 0x05, 0xAC, 0x04, 0xAC,
        ];
        let cf: ClassFile = class(vec![method(17, 18, CLINIT_TRUE), method(20, 21, plain)]);
        assert_eq!(opaque_statics(&cf), OpaqueStatics::empty());
        assert!(normalized(&cf, plain, &[], 0).is_none());
    }

    #[test]
    fn an_unwritten_boolean_compared_with_the_boxed_field_reads_as_false() {
        let compare: &[u8] = &[
            0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0xB2, 0x00, 0x19, 0xA0, 0x00, 0x05, 0x05, 0xAC,
            0x04, 0xAC,
        ];
        let cf: ClassFile = class(vec![
            method(17, 18, CLINIT_TRUE),
            method(20, 21, OPAQUE_RETURN),
            method(20, 21, compare),
        ]);
        assert_eq!(opaque_statics(&cf).get("T", "G"), Some(OpaqueValue::Int(0)));
        let body: NormalizedBody = normalized(&cf, compare, &[], 0).expect("normalized");
        assert_eq!(opcodes(&body.insns), vec![NOP, NOP, NOP, NOP, 0x04, 0xAC]);
    }

    #[test]
    fn a_handler_that_rethrows_its_exception_is_removed() {
        let code: &[u8] = &[0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0xAC, 0xBF];
        let body: NormalizedBody =
            normalized(&jbco_class(), code, &[catch_all(0, 7, 7)], 0).expect("normalized");
        assert_eq!(body.pruned_handlers, 1);
        assert!(body.exception_table.is_empty());
        assert_eq!(opcodes(&body.insns), vec![GETSTATIC, INVOKEVIRTUAL, 0xAC]);
    }

    #[test]
    fn a_handler_that_throws_a_different_value_is_kept() {
        let code: &[u8] = &[0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0xAC, 0x57, 0x01, 0xBF];
        let body: Option<NormalizedBody> =
            normalized(&jbco_class(), code, &[catch_all(0, 7, 7)], 0);
        assert!(body.is_none_or(|body: NormalizedBody| body.exception_table.len() == 1));
    }

    #[test]
    fn a_rethrow_that_another_handler_would_catch_differently_is_kept() {
        let code: &[u8] = &[
            0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0xAC, 0xBF, 0x57, 0x04, 0xAC,
        ];
        let table: [ExceptionEntry; 2] = [catch_all(0, 7, 7), catch_all(0, 7, 8)];
        let body: Option<NormalizedBody> = normalized(&jbco_class(), code, &table, 0);
        assert!(body.is_none_or(|body: NormalizedBody| body.pruned_handlers == 0));
    }

    #[test]
    fn javac_shaped_code_is_left_alone() {
        let code: &[u8] = &[0x1A, 0x99, 0x00, 0x05, 0x04, 0xAC, 0x05, 0xAC];
        assert!(normalized(&class(Vec::new()), code, &[], 1).is_none());
    }

    #[test]
    fn a_parameter_written_on_one_path_is_not_treated_as_constant() {
        let code: &[u8] = &[
            0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0x9C, 0x00, 0x04, 0xBF, 0x1A, 0x99, 0x00, 0x08,
            0x05, 0x3B, 0xA7, 0x00, 0x03, 0x1A, 0xAC,
        ];
        let body: NormalizedBody = normalized(&jbco_class(), code, &[], 1).expect("normalized");
        assert_eq!(body.folded_branches, 1);
        assert!(
            body.insns
                .iter()
                .any(|insn: &Instruction| insn.opcode == 0x99)
        );
    }

    #[test]
    fn mismatched_stack_heights_at_a_join_refuse_without_panicking() {
        let code: &[u8] = &[
            0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0x9C, 0x00, 0x04, 0xBF, 0x1A, 0x99, 0x00, 0x04,
            0x04, 0x04, 0xAC,
        ];
        assert!(normalized(&jbco_class(), code, &[], 1).is_none());
    }

    const HASH: &[u8] = &[0x1A, 0x06, 0x78, 0xAC];
    const SPIN: &[u8] = &[0xA7, 0x00, 0x00];

    fn typed_catch(start_pc: u16, end_pc: u16, handler_pc: u16, catch_type: u16) -> ExceptionEntry {
        ExceptionEntry {
            start_pc,
            end_pc,
            handler_pc,
            catch_type,
        }
    }

    const CAUGHT_JUMP: &[u8] = &[
        0xB2, 0x00, 0x06, 0xB6, 0x00, 0x0C, 0x57, 0xBB, 0x00, 0x1B, 0x59, 0xB7, 0x00, 0x1D, 0xBF,
        0x57, 0x04, 0xAC,
    ];

    #[test]
    fn an_exception_thrown_only_to_reach_its_own_handler_becomes_a_jump() {
        let body: NormalizedBody =
            normalized(&jbco_class(), CAUGHT_JUMP, &[typed_catch(7, 15, 15, 27)], 0)
                .expect("normalized");
        assert_eq!(body.control_throws, 1);
        assert!(body.exception_table.is_empty());
        let kinds: Vec<u8> = opcodes(&body.insns);
        assert!(
            !kinds.contains(&ATHROW) && !kinds.contains(&NEW),
            "{kinds:?}"
        );
        assert_eq!(
            kinds.iter().filter(|opcode: &&u8| **opcode == POP).count(),
            1,
            "only the pop of the opaque Boolean remains: {kinds:?}"
        );
        assert_eq!(opcodes(&body.insns).last(), Some(&0xAC));
    }

    #[test]
    fn a_throw_its_handler_does_not_catch_stays_a_throw() {
        let body: Option<NormalizedBody> =
            normalized(&jbco_class(), CAUGHT_JUMP, &[typed_catch(7, 15, 15, 2)], 0);
        assert!(body.is_none_or(|body: NormalizedBody| {
            body.control_throws == 0
                && body
                    .insns
                    .iter()
                    .any(|insn: &Instruction| insn.opcode == ATHROW)
        }));
    }

    #[test]
    fn pure_functions_evaluate_within_their_step_bound() {
        let cf: ClassFile = class(vec![method(31, 30, HASH), method(34, 30, SPIN)]);
        let functions: BTreeMap<FunctionKey, PureFunction> = pure_functions(&cf);
        let key = |name: &str| ("T".to_owned(), name.to_owned(), "(I)I".to_owned());
        assert_eq!(functions[&key("hash")].evaluate(&[5]), Some(40));
        assert_eq!(functions[&key("hash")].evaluate(&[5, 6]), None);
        assert_eq!(functions[&key("spin")].evaluate(&[5]), None);
    }

    #[test]
    fn a_branch_on_a_pure_hash_of_constants_folds() {
        let cf: ClassFile = class(vec![method(31, 30, HASH)]);
        let code: &[u8] = &[
            0x10, 0x05, 0xB8, 0x00, 0x21, 0x10, 0x28, 0xA0, 0x00, 0x05, 0x04, 0xAC, 0x05, 0xAC,
        ];
        let body: NormalizedBody = normalized(&cf, code, &[], 0).expect("normalized");
        assert_eq!(body.folded_branches, 1);
        assert_eq!(opcodes(&body.insns), vec![NOP, NOP, NOP, NOP, 0x04, 0xAC]);
    }
}
