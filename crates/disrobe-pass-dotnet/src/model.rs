use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue};
use crate::error::{Error, Result};
use crate::metadata::{MetadataRoot, decompress_uint};
use crate::pe::{ClrHeader, PeImage};
use crate::signature::{
    FieldSig, MethodSig, TypeSig, parse_field_sig, parse_field_sig_with_modifiers,
    parse_method_sig, parse_method_sig_strict,
};
use crate::structurize::TargetLang;
use crate::tables::{
    FieldRow, GenericParamRow, InterfaceImplRow, MemberRefRow, MethodDefRow, MethodSpecRow, RowRef,
    TableId, Tables, TypeDefRow, TypeRefRow, TypeSpecRow, parse_tables,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeModel {
    pub token: u32,
    pub namespace: String,
    pub name: String,
    pub full_name: String,
    pub flags: u32,
    pub base_type: Option<String>,
    pub fields: Vec<FieldModel>,
    pub methods: Vec<MethodModel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldModel {
    pub token: u32,
    pub name: String,
    pub flags: u16,
    pub field_type: TypeSig,
    pub is_volatile: bool,
    pub constant: Option<FieldConstant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldConstant {
    pub element_type: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodModel {
    pub token: u32,
    pub name: String,
    pub flags: u16,
    pub impl_flags: u16,
    pub rva: u32,
    pub signature: MethodSig,
    pub parameters: Vec<ParamModel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamModel {
    pub sequence: u16,
    pub name: String,
}

const METHOD_STATIC: u16 = 0x0010;
const METHOD_ACCESS_MASK: u16 = 0x0007;
const METHOD_PUBLIC: u16 = 0x0006;
const METHOD_VIRTUAL: u16 = 0x0040;
const METHOD_NEW_SLOT: u16 = 0x0100;
const METHOD_ABSTRACT: u16 = 0x0400;
const TYPE_INTERFACE: u32 = 0x0020;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiverFact {
    Unknown,
    Exact(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiverState {
    stack: Vec<ReceiverFact>,
    locals: BTreeMap<u32, ReceiverFact>,
    poisoned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CalleeDescriptor {
    owner_type: u32,
    name: String,
    signature: MethodSig,
    method_def_rid: Option<u32>,
}

impl MethodModel {
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.flags & METHOD_STATIC != 0
    }

    #[must_use]
    pub fn csharp_signature(&self) -> String {
        self.signature_in(TargetLang::CSharp)
    }

    #[must_use]
    pub fn fsharp_signature(&self) -> String {
        self.signature_in(TargetLang::FSharp)
    }

    #[must_use]
    pub fn vbnet_signature(&self) -> String {
        self.signature_in(TargetLang::VbNet)
    }

    fn display_name(&self) -> String {
        self.name
            .rsplit("::")
            .next()
            .unwrap_or(&self.name)
            .to_owned()
    }

    #[must_use]
    pub fn param_name(&self, index: usize) -> String {
        self.parameters
            .iter()
            .find(|pm: &&ParamModel| usize::from(pm.sequence) == index.saturating_add(1))
            .map_or_else(
                || format!("arg{}", index.saturating_add(1)),
                |pm: &ParamModel| pm.name.clone(),
            )
    }

    #[must_use]
    pub fn param_names(&self) -> Vec<String> {
        (0..self.signature.params.len())
            .map(|i: usize| self.param_name(i))
            .collect()
    }

    fn signature_in(&self, lang: TargetLang) -> String {
        match lang {
            TargetLang::CSharp => self.csharp_header(),
            TargetLang::FSharp => self.fsharp_header(),
            TargetLang::VbNet => self.vbnet_header(),
        }
    }

    fn csharp_header(&self) -> String {
        let vis: &str = match self.flags & METHOD_ACCESS_MASK {
            0x0001 => "private ",
            0x0002 => "private protected ",
            0x0003 => "internal ",
            0x0004 => "protected ",
            0x0005 => "protected internal ",
            METHOD_PUBLIC => "public ",
            _ => "",
        };
        let stat: &str = if self.is_static() { "static " } else { "" };
        let ret: String = self.signature.return_type.render_in(TargetLang::CSharp);
        let display_name: String = self.display_name();
        let mut rendered: Vec<String> = Vec::with_capacity(self.signature.params.len());
        for (i, p) in self.signature.params.iter().enumerate() {
            rendered.push(format!(
                "{} {}",
                p.render_in(TargetLang::CSharp),
                crate::structurize::csharp_escape_identifier(&self.param_name(i))
            ));
        }
        format!("{vis}{stat}{ret} {display_name}({})", rendered.join(", "))
    }

    fn fsharp_header(&self) -> String {
        let member: &str = if self.is_static() {
            "static member"
        } else {
            "member"
        };
        let ret: String = self.signature.return_type.render_in(TargetLang::FSharp);
        let display_name: String = self.display_name();
        let mut rendered: Vec<String> = Vec::with_capacity(self.signature.params.len());
        for (i, p) in self.signature.params.iter().enumerate() {
            rendered.push(format!(
                "{}: {}",
                self.param_name(i),
                p.render_in(TargetLang::FSharp)
            ));
        }
        format!("{member} {display_name}({}) : {ret}", rendered.join(", "))
    }

    fn vbnet_header(&self) -> String {
        let vis: &str = match self.flags & METHOD_ACCESS_MASK {
            0x0001 => "Private ",
            0x0002 => "Private Protected ",
            0x0003 => "Friend ",
            0x0004 => "Protected ",
            0x0005 => "Protected Friend ",
            METHOD_PUBLIC => "Public ",
            _ => "",
        };
        let shared: &str = if self.is_static() { "Shared " } else { "" };
        let returns_value: bool = !matches!(
            self.signature.return_type,
            crate::signature::TypeSigOrVoid::Void
        );
        let keyword: &str = if returns_value { "Function" } else { "Sub" };
        let display_name: String = self.display_name();
        let mut rendered: Vec<String> = Vec::with_capacity(self.signature.params.len());
        for (i, p) in self.signature.params.iter().enumerate() {
            rendered.push(format!(
                "{} As {}",
                self.param_name(i),
                p.render_in(TargetLang::VbNet)
            ));
        }
        let head: String = format!(
            "{vis}{shared}{keyword} {display_name}({})",
            rendered.join(", ")
        );
        if returns_value {
            format!(
                "{head} As {}",
                self.signature.return_type.render_in(TargetLang::VbNet)
            )
        } else {
            head
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyModel {
    pub module_name: String,
    pub assembly_name: Option<String>,
    pub types: Vec<TypeModel>,
    pub method_count: u32,
    pub field_count: u32,
    pub type_count: u32,
}

#[derive(Debug)]
pub struct Resolver {
    tables: Tables,
    method_impl_types: BTreeSet<u32>,
    strings_heap: Vec<u8>,
    blob: Vec<u8>,
    us: Vec<u8>,
}

impl Resolver {
    pub fn build(image: &[u8], pe: &PeImage, clr: &ClrHeader, root: &MetadataRoot) -> Result<Self> {
        let metadata_slice: &[u8] = crate::metadata::metadata_slice(image, pe, clr, root)?;
        let table_header: crate::metadata::StreamHeader = root
            .streams
            .get("#~")
            .or_else(|| root.streams.get("#-"))
            .copied()
            .ok_or_else(|| Error::UnknownStream("#~".to_owned()))?;
        let tables: Tables = parse_tables(metadata_slice, table_header)?;
        let method_impl_types: BTreeSet<u32> = tables
            .method_impls
            .iter()
            .map(|mapping| mapping.class_type)
            .collect();
        let strings_heap: Vec<u8> = root
            .streams
            .get("#Strings")
            .map(|h| {
                let o: usize = h.offset as usize;
                let e: usize = o.saturating_add(h.size as usize).min(metadata_slice.len());
                if o < e {
                    metadata_slice[o..e].to_vec()
                } else {
                    Vec::new()
                }
            })
            .unwrap_or_default();
        let blob: Vec<u8> = root
            .streams
            .get("#Blob")
            .map(|h| {
                let o: usize = h.offset as usize;
                let e: usize = o.saturating_add(h.size as usize).min(metadata_slice.len());
                if o < e {
                    metadata_slice[o..e].to_vec()
                } else {
                    Vec::new()
                }
            })
            .unwrap_or_default();
        let us: Vec<u8> = root
            .streams
            .get("#US")
            .map(|h| {
                let o: usize = h.offset as usize;
                let e: usize = o.saturating_add(h.size as usize).min(metadata_slice.len());
                if o < e {
                    metadata_slice[o..e].to_vec()
                } else {
                    Vec::new()
                }
            })
            .unwrap_or_default();
        Ok(Self {
            tables,
            method_impl_types,
            strings_heap,
            blob,
            us,
        })
    }

    #[must_use]
    pub const fn tables(&self) -> &Tables {
        &self.tables
    }

    #[must_use]
    pub fn devirtualize_callvirt(&self, body: &MethodBody) -> MethodBody {
        if !body.exception_clauses.is_empty() {
            return body.clone();
        }
        if !body
            .instructions
            .iter()
            .any(|instruction: &Instruction| instruction.name == "callvirt")
        {
            return body.clone();
        }
        let states: Vec<Option<ReceiverState>> = self.receiver_states(body);
        let mut patched: MethodBody = body.clone();
        for (index, instruction) in body.instructions.iter().enumerate() {
            if instruction.name != "callvirt" {
                continue;
            }
            let token: u32 = match instruction.operand {
                OperandValue::Token(token) => token,
                _ => continue,
            };
            let state: Option<&ReceiverState> = states.get(index).and_then(Option::as_ref);
            let receiver_type: Option<u32> =
                state.and_then(|state: &ReceiverState| self.receiver_before_call(state, token));
            let target: Option<u32> = self.resolve_callvirt_target(token, receiver_type);
            let Some(target): Option<u32> = target else {
                continue;
            };
            let rewritten: &mut Instruction = &mut patched.instructions[index];
            rewritten.opcode = 0x28;
            rewritten.name.clear();
            rewritten.name.push_str("call");
            rewritten.operand = OperandValue::Token(target);
        }
        patched
    }

    fn receiver_states(&self, body: &MethodBody) -> Vec<Option<ReceiverState>> {
        let count: usize = body.instructions.len();
        let mut states: Vec<Option<ReceiverState>> = vec![None; count];
        if count == 0 {
            return states;
        }
        let mut offsets: BTreeMap<u32, usize> = BTreeMap::new();
        for (index, instruction) in body.instructions.iter().enumerate() {
            offsets.insert(instruction.offset, index);
        }
        if !control_flow_targets_are_valid(body, &offsets) {
            return states;
        }
        states[0] = Some(ReceiverState {
            stack: Vec::new(),
            locals: BTreeMap::new(),
            poisoned: false,
        });
        let mut worklist: VecDeque<usize> = VecDeque::from([0usize]);
        while let Some(index) = worklist.pop_front() {
            let incoming: Option<ReceiverState> = states.get(index).cloned().flatten();
            let Some(incoming): Option<ReceiverState> = incoming else {
                continue;
            };
            let outgoing: ReceiverState =
                self.transfer_receiver_state(&incoming, &body.instructions[index]);
            let successors: Vec<usize> = Self::successors(body, index, &offsets);
            for successor in successors {
                let previous: Option<ReceiverState> = states[successor].clone();
                let merged: ReceiverState = previous.as_ref().map_or_else(
                    || outgoing.clone(),
                    |previous: &ReceiverState| Self::merge_receiver_states(previous, &outgoing),
                );
                if previous.as_ref() != Some(&merged) {
                    states[successor] = Some(merged);
                    worklist.push_back(successor);
                }
            }
        }
        states
    }

    fn receiver_before_call(&self, state: &ReceiverState, token: u32) -> Option<u32> {
        if state.poisoned {
            return None;
        }
        let signature: MethodSig = self.callee_signature(token)?;
        if !signature.has_this {
            return None;
        }
        let args: usize = signature.params.len().checked_add(1)?;
        let receiver_index: usize = state.stack.len().checked_sub(args)?;
        match state.stack.get(receiver_index) {
            Some(ReceiverFact::Exact(type_rid)) => Some(*type_rid),
            Some(ReceiverFact::Unknown) | None => None,
        }
    }

    fn transfer_receiver_state(
        &self,
        incoming: &ReceiverState,
        instruction: &Instruction,
    ) -> ReceiverState {
        if incoming.poisoned {
            return incoming.clone();
        }
        let mut outgoing: ReceiverState = incoming.clone();
        match instruction.name.as_str() {
            "nop" | "break" | "readonly." | "tail." | "volatile." | "unaligned." | "no." => {}
            "constrained." => poison_receiver_state(&mut outgoing),
            _ if matches!(
                instruction.flow,
                FlowControl::Branch | FlowControl::CondBranch
            ) => {}
            "ldloc.0" | "ldloc.1" | "ldloc.2" | "ldloc.3" | "ldloc" | "ldloc.s" => {
                let slot: u32 = crate::cil_emulator::slot_index(instruction, &instruction.name);
                let fact: ReceiverFact = outgoing
                    .locals
                    .get(&slot)
                    .map_or(ReceiverFact::Unknown, |fact: &ReceiverFact| *fact);
                outgoing.stack.push(fact);
            }
            "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc" | "stloc.s" => {
                let slot: u32 = crate::cil_emulator::slot_index(instruction, &instruction.name);
                let value: ReceiverFact = pop_receiver_fact(&mut outgoing);
                match value {
                    ReceiverFact::Exact(_) => {
                        outgoing.locals.insert(slot, value);
                    }
                    ReceiverFact::Unknown => {
                        outgoing.locals.remove(&slot);
                    }
                }
            }
            "ldloca" | "ldloca.s" => {
                let slot: u32 = crate::cil_emulator::slot_index(instruction, &instruction.name);
                outgoing.locals.remove(&slot);
                outgoing.stack.push(ReceiverFact::Unknown);
            }
            "ldarga" | "ldarga.s" => outgoing.stack.push(ReceiverFact::Unknown),
            name if name.starts_with("ldarg") => outgoing.stack.push(ReceiverFact::Unknown),
            name if name.starts_with("starg") => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
            }
            "dup" => {
                let value: ReceiverFact = pop_receiver_fact(&mut outgoing);
                outgoing.stack.push(value);
                outgoing.stack.push(value);
            }
            "newobj" => self.transfer_newobj(&mut outgoing, instruction),
            "ldsfld" | "ldsflda" => outgoing.stack.push(ReceiverFact::Unknown),
            "pop" | "stsfld" | "initobj" => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
            }
            "ldfld" | "ldflda" | "isinst" | "box" | "unbox" | "unbox.any" | "ldobj"
            | "ldind.i1" | "ldind.u1" | "ldind.i2" | "ldind.u2" | "ldind.i4" | "ldind.u4"
            | "ldind.i8" | "ldind.i" | "ldind.r4" | "ldind.r8" | "ldind.ref" | "newarr"
            | "localloc" | "ldlen" => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                outgoing.stack.push(ReceiverFact::Unknown);
            }
            "stfld" | "stobj" | "cpobj" | "stind.i1" | "stind.i2" | "stind.i4" | "stind.i8"
            | "stind.r4" | "stind.r8" | "stind.ref" => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
            }
            "call" | "callvirt" => self.transfer_call(&mut outgoing, instruction),
            "calli" | "jmp" => poison_receiver_state(&mut outgoing),
            "castclass" => {
                let value: ReceiverFact = pop_receiver_fact(&mut outgoing);
                outgoing.stack.push(value);
            }
            "ldelema" => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                outgoing.stack.push(ReceiverFact::Unknown);
            }
            name if name.starts_with("ldelem") => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                outgoing.stack.push(ReceiverFact::Unknown);
            }
            name if name.starts_with("stelem") => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
            }
            "throw" => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
            }
            "ldnull" | "ldstr" | "ldtoken" | "ldftn" | "arglist" | "sizeof" => {
                outgoing.stack.push(ReceiverFact::Unknown);
            }
            "ldvirtftn" => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                outgoing.stack.push(ReceiverFact::Unknown);
            }
            name if name.starts_with("ldc.") => outgoing.stack.push(ReceiverFact::Unknown),
            name if name.starts_with("conv.") || name == "neg" || name == "not" => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                outgoing.stack.push(ReceiverFact::Unknown);
            }
            "add" | "add.ovf" | "add.ovf.un" | "sub" | "sub.ovf" | "sub.ovf.un" | "mul"
            | "mul.ovf" | "mul.ovf.un" | "div" | "div.un" | "rem" | "rem.un" | "and" | "or"
            | "xor" | "shl" | "shr" | "shr.un" | "ceq" | "cgt" | "cgt.un" | "clt" | "clt.un" => {
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                let _: ReceiverFact = pop_receiver_fact(&mut outgoing);
                outgoing.stack.push(ReceiverFact::Unknown);
            }
            _ => clear_receiver_stack(&mut outgoing),
        }
        Self::consume_branch_operands(&mut outgoing, instruction);
        if matches!(instruction.name.as_str(), "leave" | "leave.s") {
            outgoing.stack.clear();
        }
        outgoing
    }

    fn transfer_newobj(&self, state: &mut ReceiverState, instruction: &Instruction) {
        let OperandValue::Token(token) = instruction.operand else {
            poison_receiver_state(state);
            return;
        };
        let signature: Option<MethodSig> = self.callee_signature(token);
        let owner_type: Option<u32> = self
            .callee_descriptor(token)
            .map(|descriptor: CalleeDescriptor| descriptor.owner_type);
        let Some(signature): Option<MethodSig> = signature else {
            poison_receiver_state(state);
            return;
        };
        pop_receiver_count(state, signature.params.len());
        match owner_type {
            Some(type_rid)
                if !self.type_has_generic_params(type_rid)
                    && !self.type_is_value_type(type_rid) =>
            {
                state.stack.push(ReceiverFact::Exact(type_rid));
            }
            _ => state.stack.push(ReceiverFact::Unknown),
        }
    }

    fn transfer_call(&self, state: &mut ReceiverState, instruction: &Instruction) {
        let OperandValue::Token(token) = instruction.operand else {
            poison_receiver_state(state);
            return;
        };
        let Some(signature): Option<MethodSig> = self.callee_signature(token) else {
            poison_receiver_state(state);
            return;
        };
        let count: usize = signature
            .params
            .len()
            .saturating_add(usize::from(signature.has_this));
        pop_receiver_count(state, count);
        if !matches!(signature.return_type, crate::signature::TypeSigOrVoid::Void) {
            state.stack.push(ReceiverFact::Unknown);
        }
    }

    fn consume_branch_operands(state: &mut ReceiverState, instruction: &Instruction) {
        if instruction.flow != FlowControl::CondBranch {
            return;
        }
        match instruction.name.as_str() {
            "brfalse" | "brfalse.s" | "brtrue" | "brtrue.s" | "switch" => {
                let _: ReceiverFact = pop_receiver_fact(state);
            }
            _ => pop_receiver_count(state, 2),
        }
    }

    fn successors(body: &MethodBody, index: usize, offsets: &BTreeMap<u32, usize>) -> Vec<usize> {
        let instruction: &Instruction = &body.instructions[index];
        if instruction.name == "jmp" {
            return Vec::new();
        }
        let next: Option<usize> = index
            .checked_add(1)
            .filter(|next: &usize| *next < body.instructions.len());
        let mut out: Vec<usize> = Vec::new();
        match instruction.flow {
            FlowControl::Branch => {
                if let Some(target) = branch_successor(body, index, offsets) {
                    out.push(target);
                }
            }
            FlowControl::CondBranch => {
                for target in branch_successors(body, index, offsets) {
                    if !out.contains(&target) {
                        out.push(target);
                    }
                }
                if let Some(next) = next
                    && !out.contains(&next)
                {
                    out.push(next);
                }
            }
            FlowControl::Return | FlowControl::Throw => {}
            FlowControl::Next | FlowControl::Call | FlowControl::Meta | FlowControl::Break => {
                if let Some(next) = next {
                    out.push(next);
                }
            }
        }
        out
    }

    fn merge_receiver_states(existing: &ReceiverState, incoming: &ReceiverState) -> ReceiverState {
        if existing.poisoned || incoming.poisoned || existing.stack.len() != incoming.stack.len() {
            return ReceiverState {
                stack: Vec::new(),
                locals: BTreeMap::new(),
                poisoned: true,
            };
        }
        let stack: Vec<ReceiverFact> = existing
            .stack
            .iter()
            .zip(&incoming.stack)
            .map(|(left, right): (&ReceiverFact, &ReceiverFact)| {
                if left == right {
                    *left
                } else {
                    ReceiverFact::Unknown
                }
            })
            .collect();
        let keys: BTreeSet<u32> = existing
            .locals
            .keys()
            .chain(incoming.locals.keys())
            .copied()
            .collect();
        let mut locals: BTreeMap<u32, ReceiverFact> = BTreeMap::new();
        for key in keys {
            let left: Option<&ReceiverFact> = existing.locals.get(&key);
            let right: Option<&ReceiverFact> = incoming.locals.get(&key);
            if let (Some(ReceiverFact::Exact(left)), Some(ReceiverFact::Exact(right))) =
                (left, right)
                && left == right
            {
                locals.insert(key, ReceiverFact::Exact(*left));
            }
        }
        ReceiverState {
            stack,
            locals,
            poisoned: false,
        }
    }

    fn resolve_callvirt_target(&self, token: u32, receiver_type: Option<u32>) -> Option<u32> {
        let descriptor: CalleeDescriptor = self.callee_descriptor(token)?;
        let receiver_type: u32 = receiver_type?;
        if self.type_has_generic_params(descriptor.owner_type)
            || self.type_has_generic_params(receiver_type)
            || self.type_is_value_type(receiver_type)
            || self.has_method_impl_in_hierarchy(receiver_type)
            || self.has_ambiguous_matching_method_in_hierarchy(receiver_type, &descriptor)
            || self.has_ambiguous_matching_methods(descriptor.owner_type, &descriptor)
        {
            return None;
        }
        self.resolve_exact_receiver_target(receiver_type, &descriptor)
    }

    fn resolve_exact_receiver_target(
        &self,
        receiver_type: u32,
        descriptor: &CalleeDescriptor,
    ) -> Option<u32> {
        if self.type_is_interface(descriptor.owner_type) {
            self.resolve_interface_dispatch(receiver_type, descriptor)
        } else {
            self.resolve_class_dispatch(receiver_type, descriptor)
        }
    }

    fn resolve_class_dispatch(
        &self,
        receiver_type: u32,
        descriptor: &CalleeDescriptor,
    ) -> Option<u32> {
        if !self.type_is_or_derived_from(receiver_type, descriptor.owner_type) {
            return None;
        }
        let declaration: u32 = self.declaration_method(descriptor)?;
        let declaration_row: &MethodDefRow = self
            .tables
            .methods
            .get(declaration.checked_sub(1)? as usize)?;
        if declaration_row.flags & (METHOD_VIRTUAL | METHOD_ABSTRACT) == 0 {
            return Some(method_def_token(declaration));
        }
        let mut current: u32 = receiver_type;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current) {
            if let Some(candidate) = self.find_matching_declared_method(current, descriptor)
                && self.method_uses_virtual_slot(candidate, declaration)
            {
                return Some(method_def_token(candidate));
            }
            if current == descriptor.owner_type {
                return Some(method_def_token(declaration));
            }
            let base: u32 = self.base_type_rid(current)?;
            current = base;
        }
        None
    }

    fn resolve_interface_dispatch(
        &self,
        receiver_type: u32,
        descriptor: &CalleeDescriptor,
    ) -> Option<u32> {
        if !self.type_implements_interface(receiver_type, descriptor.owner_type) {
            return None;
        }
        let _: u32 = self.declaration_method(descriptor)?;
        let lineage: Vec<u32> =
            self.interface_implementation_lineage(receiver_type, descriptor.owner_type)?;
        let interface_root: u32 = *lineage.last()?;
        let (declaration_owner, declaration): (u32, u32) =
            self.implicit_interface_method(interface_root, descriptor)?;
        let declaration_row: &MethodDefRow = self
            .tables
            .methods
            .get(declaration.checked_sub(1)? as usize)?;
        let mut class_type: u32 = receiver_type;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(class_type) {
            let Some(candidate): Option<u32> =
                self.find_matching_declared_method(class_type, descriptor)
            else {
                if class_type == declaration_owner {
                    return Some(method_def_token(declaration));
                }
                class_type = self.base_type_rid(class_type)?;
                continue;
            };
            let candidate_row: &MethodDefRow = self
                .tables
                .methods
                .get(candidate.checked_sub(1)? as usize)?;
            if class_type == declaration_owner
                || declaration_row.flags & METHOD_VIRTUAL != 0
                    && candidate_row.flags & METHOD_VIRTUAL != 0
                    && self.method_uses_virtual_slot(candidate, declaration)
            {
                return Some(method_def_token(candidate));
            }
            class_type = self.base_type_rid(class_type)?;
        }
        None
    }

    fn method_uses_virtual_slot(&self, method_rid: u32, declaration: u32) -> bool {
        let mut current_method: u32 = method_rid;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current_method) {
            if current_method == declaration {
                return true;
            }
            let Some(method_index): Option<usize> = current_method
                .checked_sub(1)
                .and_then(|rid: u32| usize::try_from(rid).ok())
            else {
                return false;
            };
            let Some(row): Option<&MethodDefRow> = self.tables.methods.get(method_index) else {
                return false;
            };
            if row.flags & METHOD_VIRTUAL == 0 || row.flags & METHOD_NEW_SLOT != 0 {
                return false;
            }
            let Some(owner): Option<u32> = self.method_owner_rid(current_method) else {
                return false;
            };
            let Some(descriptor): Option<CalleeDescriptor> =
                self.callee_descriptor(method_def_token(current_method))
            else {
                return false;
            };
            let Some(base_method): Option<u32> = self.nearest_base_slot_method(owner, &descriptor)
            else {
                return false;
            };
            current_method = base_method;
        }
        false
    }

    fn nearest_base_slot_method(&self, owner: u32, descriptor: &CalleeDescriptor) -> Option<u32> {
        let mut current: u32 = self.base_type_rid(owner)?;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current) {
            if let Some(candidate) = self.find_matching_declared_method(current, descriptor) {
                let row: &MethodDefRow = self
                    .tables
                    .methods
                    .get(candidate.checked_sub(1)? as usize)?;
                if row.flags & METHOD_VIRTUAL != 0 {
                    return Some(candidate);
                }
            }
            current = self.base_type_rid(current)?;
        }
        None
    }

    fn interface_implementation_lineage(
        &self,
        receiver_type: u32,
        interface_type: u32,
    ) -> Option<Vec<u32>> {
        let mut current: u32 = receiver_type;
        let mut lineage: Vec<u32> = Vec::new();
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current) {
            lineage.push(current);
            if self.type_directly_implements_interface(current, interface_type) {
                return Some(lineage);
            }
            current = self.base_type_rid(current)?;
        }
        None
    }

    fn implicit_interface_method(
        &self,
        interface_root: u32,
        descriptor: &CalleeDescriptor,
    ) -> Option<(u32, u32)> {
        let mut current: u32 = interface_root;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current) {
            if let Some(method) = self.find_implicit_interface_method(current, descriptor) {
                return Some((current, method));
            }
            current = self.base_type_rid(current)?;
        }
        None
    }

    fn has_method_impl_in_hierarchy(&self, receiver_type: u32) -> bool {
        let mut current: u32 = receiver_type;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current) {
            if self.method_impl_types.contains(&current) {
                return true;
            }
            let Some(base): Option<u32> = self.base_type_rid(current) else {
                return false;
            };
            current = base;
        }
        true
    }

    fn callee_descriptor(&self, token: u32) -> Option<CalleeDescriptor> {
        let table: TableId = token_table(token)?;
        let rid: u32 = token_rid(token)?;
        match table {
            TableId::MethodDef => {
                let row: &MethodDefRow = self.tables.methods.get(rid.checked_sub(1)? as usize)?;
                let signature: MethodSig = self.method_signature(row.signature)?;
                let owner_type: u32 = self.method_owner_rid(rid)?;
                Some(CalleeDescriptor {
                    owner_type,
                    name: self.string(row.name),
                    signature,
                    method_def_rid: Some(rid),
                })
            }
            TableId::MemberRef => {
                let row: &MemberRefRow =
                    self.tables.member_refs.get(rid.checked_sub(1)? as usize)?;
                let parent: RowRef = row.parent?;
                if parent.table != TableId::TypeDef {
                    return None;
                }
                let signature: MethodSig = self.method_signature(row.signature)?;
                Some(CalleeDescriptor {
                    owner_type: parent.row,
                    name: self.string(row.name),
                    signature,
                    method_def_rid: None,
                })
            }
            _ => None,
        }
    }

    fn method_signature(&self, blob_index: u32) -> Option<MethodSig> {
        let blob: &[u8] = self.blob(blob_index)?;
        let signature: MethodSig = parse_method_sig_strict(blob).ok()?;
        signature_is_closed(&signature).then_some(signature)
    }

    fn find_matching_declared_method(
        &self,
        type_rid: u32,
        descriptor: &CalleeDescriptor,
    ) -> Option<u32> {
        if self.matching_declared_method_count(type_rid, descriptor)? != 1 {
            return None;
        }
        let (start, end): (u32, u32) = self.method_range(type_rid)?;
        for method_rid in start..end {
            let row: &MethodDefRow = self
                .tables
                .methods
                .get(method_rid.checked_sub(1)? as usize)?;
            if !self.method_matches_descriptor(row, descriptor)? {
                continue;
            }
            return Some(method_rid);
        }
        None
    }

    fn declaration_method(&self, descriptor: &CalleeDescriptor) -> Option<u32> {
        match descriptor.method_def_rid {
            Some(method_rid)
                if self.method_owner_rid(method_rid) == Some(descriptor.owner_type) =>
            {
                Some(method_rid)
            }
            Some(_) => None,
            None => self.find_matching_declared_method(descriptor.owner_type, descriptor),
        }
    }

    fn find_implicit_interface_method(
        &self,
        type_rid: u32,
        descriptor: &CalleeDescriptor,
    ) -> Option<u32> {
        let (start, end): (u32, u32) = self.method_range(type_rid)?;
        let mut matched: Option<u32> = None;
        for method_rid in start..end {
            let row: &MethodDefRow = self
                .tables
                .methods
                .get(method_rid.checked_sub(1)? as usize)?;
            if row.flags & METHOD_VIRTUAL == 0
                || row.flags & METHOD_ACCESS_MASK != METHOD_PUBLIC
                || !self.method_matches_descriptor(row, descriptor)?
            {
                continue;
            }
            matched = Some(method_rid);
        }
        matched
    }

    fn has_ambiguous_matching_methods(&self, type_rid: u32, descriptor: &CalleeDescriptor) -> bool {
        self.matching_declared_method_count(type_rid, descriptor)
            .is_none_or(|count: usize| count > 1)
    }

    fn has_ambiguous_matching_method_in_hierarchy(
        &self,
        type_rid: u32,
        descriptor: &CalleeDescriptor,
    ) -> bool {
        let mut current: u32 = type_rid;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current) {
            if self.has_ambiguous_matching_methods(current, descriptor) {
                return true;
            }
            let Some(base): Option<u32> = self.base_type_rid(current) else {
                return false;
            };
            current = base;
        }
        true
    }

    fn matching_declared_method_count(
        &self,
        type_rid: u32,
        descriptor: &CalleeDescriptor,
    ) -> Option<usize> {
        let (start, end): (u32, u32) = self.method_range(type_rid)?;
        let mut count: usize = 0;
        for method_rid in start..end {
            let row: &MethodDefRow = self
                .tables
                .methods
                .get(method_rid.checked_sub(1)? as usize)?;
            if self.method_matches_descriptor(row, descriptor)? {
                count = count.checked_add(1)?;
            }
        }
        Some(count)
    }

    fn method_matches_descriptor(
        &self,
        row: &MethodDefRow,
        descriptor: &CalleeDescriptor,
    ) -> Option<bool> {
        if row.flags & METHOD_STATIC != 0 || self.string(row.name) != descriptor.name {
            return Some(false);
        }
        Some(self.method_signature(row.signature)? == descriptor.signature)
    }

    fn method_range(&self, type_rid: u32) -> Option<(u32, u32)> {
        let index: usize = usize::try_from(type_rid.checked_sub(1)?).ok()?;
        let type_row: &TypeDefRow = self.tables.type_defs.get(index)?;
        let start: u32 = type_row.method_list;
        let end: u32 = match self.tables.type_defs.get(index.checked_add(1)?) {
            Some(next) => next.method_list,
            None => u32::try_from(self.tables.methods.len())
                .ok()?
                .checked_add(1)?,
        };
        (start <= end).then_some((start, end))
    }

    fn method_owner_rid(&self, method_rid: u32) -> Option<u32> {
        for (index, type_row) in self.tables.type_defs.iter().enumerate() {
            let start: u32 = type_row.method_list;
            let end: u32 = match self.tables.type_defs.get(index.checked_add(1)?) {
                Some(next) => next.method_list,
                None => u32::try_from(self.tables.methods.len())
                    .ok()?
                    .checked_add(1)?,
            };
            if method_rid >= start && method_rid < end {
                return u32::try_from(index).ok()?.checked_add(1);
            }
        }
        None
    }

    fn type_is_or_derived_from(&self, candidate: u32, ancestor: u32) -> bool {
        let mut current: u32 = candidate;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current) {
            if current == ancestor {
                return true;
            }
            let Some(base) = self.base_type_rid(current) else {
                return false;
            };
            current = base;
        }
        false
    }

    fn type_implements_interface(&self, type_rid: u32, interface_type: u32) -> bool {
        let mut current: u32 = type_rid;
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        while visited.insert(current) {
            if self.type_directly_implements_interface(current, interface_type) {
                return true;
            }
            let Some(base) = self.base_type_rid(current) else {
                return false;
            };
            current = base;
        }
        false
    }

    fn type_directly_implements_interface(&self, type_rid: u32, interface_type: u32) -> bool {
        self.tables
            .interface_impls
            .iter()
            .filter(|row: &&InterfaceImplRow| row.class_type == type_rid)
            .filter_map(|row: &InterfaceImplRow| row.interface)
            .any(|implemented: RowRef| {
                self.interface_reference_matches(implemented, interface_type, &mut BTreeSet::new())
            })
    }

    fn interface_reference_matches(
        &self,
        implemented: RowRef,
        target: u32,
        visited: &mut BTreeSet<u32>,
    ) -> bool {
        if implemented.table != TableId::TypeDef || !visited.insert(implemented.row) {
            return false;
        }
        if implemented.row == target {
            return true;
        }
        self.tables
            .interface_impls
            .iter()
            .filter(|row: &&InterfaceImplRow| row.class_type == implemented.row)
            .filter_map(|row: &InterfaceImplRow| row.interface)
            .any(|parent: RowRef| self.interface_reference_matches(parent, target, visited))
    }

    fn base_type_rid(&self, type_rid: u32) -> Option<u32> {
        let type_row: &TypeDefRow = self
            .tables
            .type_defs
            .get(type_rid.checked_sub(1)? as usize)?;
        let parent: RowRef = type_row.extends?;
        (parent.table == TableId::TypeDef).then_some(parent.row)
    }

    fn type_is_interface(&self, type_rid: u32) -> bool {
        self.type_flags(type_rid)
            .is_some_and(|flags: u32| flags & TYPE_INTERFACE != 0)
    }

    fn type_is_value_type(&self, type_rid: u32) -> bool {
        let Some(index): Option<usize> = type_rid
            .checked_sub(1)
            .and_then(|rid: u32| usize::try_from(rid).ok())
        else {
            return false;
        };
        let Some(type_row): Option<&TypeDefRow> = self.tables.type_defs.get(index) else {
            return false;
        };
        let Some(parent): Option<RowRef> = type_row.extends else {
            return false;
        };
        if parent.table != TableId::TypeRef {
            return false;
        }
        self.type_ref_name(parent.row)
            .is_some_and(|name: String| name == "System.ValueType" || name == "System.Enum")
    }

    fn type_flags(&self, type_rid: u32) -> Option<u32> {
        Some(
            self.tables
                .type_defs
                .get(type_rid.checked_sub(1)? as usize)?
                .flags,
        )
    }

    fn type_has_generic_params(&self, type_rid: u32) -> bool {
        self.tables
            .generic_params
            .iter()
            .any(|parameter: &GenericParamRow| {
                parameter.owner.is_some_and(|owner: RowRef| {
                    owner.table == TableId::TypeDef && owner.row == type_rid
                })
            })
    }

    #[must_use]
    pub fn type_generic_param_names(&self, type_def_rid: u32) -> Vec<String> {
        let mut named: Vec<(u16, String)> = self
            .tables
            .generic_params
            .iter()
            .filter(|g: &&GenericParamRow| {
                g.owner.is_some_and(|o: RowRef| {
                    matches!(o.table, TableId::TypeDef) && o.row == type_def_rid
                })
            })
            .map(|g: &GenericParamRow| (g.number, self.string(g.name)))
            .filter(|(_, name): &(u16, String)| !name.is_empty())
            .collect();
        named.sort_by_key(|(number, _): &(u16, String)| *number);
        named
            .into_iter()
            .map(|(_, name): (u16, String)| name)
            .collect()
    }

    #[must_use]
    pub fn method_generic_param_names(&self, method_def_rid: u32) -> Vec<String> {
        let mut named: Vec<(u16, String)> = self
            .tables
            .generic_params
            .iter()
            .filter(|g: &&GenericParamRow| {
                g.owner.is_some_and(|o: RowRef| {
                    matches!(o.table, TableId::MethodDef) && o.row == method_def_rid
                })
            })
            .map(|g: &GenericParamRow| (g.number, self.string(g.name)))
            .filter(|(_, name): &(u16, String)| !name.is_empty())
            .collect();
        named.sort_by_key(|(number, _): &(u16, String)| *number);
        named
            .into_iter()
            .map(|(_, name): (u16, String)| name)
            .collect()
    }

    #[must_use]
    pub(crate) fn string(&self, index: u32) -> String {
        if index == 0 {
            return String::new();
        }
        let start: usize = index as usize;
        if start >= self.strings_heap.len() {
            return String::new();
        }
        let rest: &[u8] = &self.strings_heap[start..];
        let len: usize = rest.iter().position(|&b: &u8| b == 0).unwrap_or(rest.len());
        String::from_utf8_lossy(&rest[..len]).into_owned()
    }

    #[must_use]
    pub(crate) fn blob(&self, index: u32) -> Option<&[u8]> {
        let i: usize = index as usize;
        if i >= self.blob.len() {
            return None;
        }
        let (len, consumed): (u32, usize) = decompress_uint(&self.blob[i..])?;
        let start: usize = i + consumed;
        let end: usize = start.checked_add(len as usize)?;
        if end > self.blob.len() {
            return None;
        }
        Some(&self.blob[start..end])
    }

    #[must_use]
    pub(crate) fn string_len(&self, index: u32) -> Option<usize> {
        if index == 0 {
            return Some(0);
        }
        let start: usize = usize::try_from(index).ok()?;
        let rest: &[u8] = self.strings_heap.get(start..)?;
        Some(
            rest.iter()
                .position(|byte: &u8| *byte == 0)
                .unwrap_or(rest.len()),
        )
    }

    #[must_use]
    pub fn user_string(&self, offset: u32) -> Option<String> {
        let i: usize = offset as usize;
        if i >= self.us.len() {
            return None;
        }
        let (len, consumed): (u32, usize) = decompress_uint(&self.us[i..])?;
        let start: usize = i + consumed;
        let blob_len: usize = len as usize;
        let end: usize = start.checked_add(blob_len)?;
        if end > self.us.len() || blob_len == 0 {
            return None;
        }
        let char_bytes: usize = blob_len - 1;
        let units: usize = char_bytes / 2;
        let mut buf: Vec<u16> = Vec::with_capacity(units);
        for u in 0..units {
            buf.push(u16::from_le_bytes([
                self.us[start + u * 2],
                self.us[start + u * 2 + 1],
            ]));
        }
        Some(String::from_utf16_lossy(&buf))
    }

    #[must_use]
    pub(crate) fn user_string_strict(&self, offset: u32) -> Option<String> {
        let index: usize = usize::try_from(offset).ok()?;
        let tail: &[u8] = self.us.get(index..)?;
        let (length, consumed): (u32, usize) = decompress_uint(tail)?;
        let length: usize = usize::try_from(length).ok()?;
        let start: usize = index.checked_add(consumed)?;
        let end: usize = start.checked_add(length)?;
        let blob: &[u8] = self.us.get(start..end)?;
        let (terminal, characters): (&u8, &[u8]) = blob.split_last()?;
        if *terminal > 1 || !characters.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = characters
            .chunks_exact(2)
            .map(|unit: &[u8]| {
                let bytes: [u8; 2] = unit.try_into().ok()?;
                Some(u16::from_le_bytes(bytes))
            })
            .collect::<Option<Vec<u16>>>()?;
        String::from_utf16(&units).ok()
    }

    #[must_use]
    pub fn resolve_token(&self, token: u32) -> String {
        let table_idx: u8 = u8::try_from(token >> 24).unwrap_or(0xFF);
        let rid: u32 = token & 0x00FF_FFFF;
        if table_idx == 0x70 {
            return self
                .user_string(rid)
                .unwrap_or_else(|| format!("us(0x{rid:06X})"));
        }
        let Some(table): Option<TableId> = TableId::from_index(table_idx) else {
            return format!("token(0x{token:08X})");
        };
        match table {
            TableId::TypeDef => self
                .type_def_name(rid)
                .unwrap_or_else(|| format!("TypeDef[{rid}]")),
            TableId::TypeRef => self
                .type_ref_name(rid)
                .unwrap_or_else(|| format!("TypeRef[{rid}]")),
            TableId::MethodDef => self
                .method_name(rid)
                .unwrap_or_else(|| format!("MethodDef[{rid}]")),
            TableId::Field => self
                .field_name(rid)
                .unwrap_or_else(|| format!("Field[{rid}]")),
            TableId::MemberRef => self
                .member_ref_name(rid)
                .unwrap_or_else(|| format!("MemberRef[{rid}]")),
            TableId::TypeSpec => self
                .type_spec_name(rid)
                .unwrap_or_else(|| format!("TypeSpec[{rid}]")),
            TableId::MethodSpec => self
                .method_spec_name(rid)
                .unwrap_or_else(|| format!("MethodSpec[{rid}]")),
            _ => format!("{table:?}[{rid}]"),
        }
    }

    #[must_use]
    fn type_def_name(&self, rid: u32) -> Option<String> {
        let row: &TypeDefRow = self.tables.type_defs.get(rid.checked_sub(1)? as usize)?;
        Some(Self::qualify(
            self.string(row.namespace),
            self.string(row.name),
        ))
    }

    #[must_use]
    fn type_ref_name(&self, rid: u32) -> Option<String> {
        let row: &TypeRefRow = self.tables.type_refs.get(rid.checked_sub(1)? as usize)?;
        Some(Self::qualify(
            self.string(row.namespace),
            self.string(row.name),
        ))
    }

    #[must_use]
    fn method_name(&self, rid: u32) -> Option<String> {
        let row: &MethodDefRow = self.tables.methods.get(rid.checked_sub(1)? as usize)?;
        let owner: Option<String> = self.method_owner_name(rid);
        let m: String = self.string(row.name);
        Some(match owner {
            Some(o) => format!("{o}::{m}"),
            None => m,
        })
    }

    #[must_use]
    fn field_name(&self, rid: u32) -> Option<String> {
        let row: &FieldRow = self.tables.fields.get(rid.checked_sub(1)? as usize)?;
        Some(self.string(row.name))
    }

    #[must_use]
    fn member_ref_name(&self, rid: u32) -> Option<String> {
        let row: &MemberRefRow = self.tables.member_refs.get(rid.checked_sub(1)? as usize)?;
        let parent: Option<String> = row.parent.map(|p: RowRef| self.row_ref_name(p));
        let m: String = self.string(row.name);
        Some(match parent {
            Some(o) => format!("{o}::{m}"),
            None => m,
        })
    }

    #[must_use]
    fn method_spec_name(&self, rid: u32) -> Option<String> {
        let row: &MethodSpecRow = self.tables.method_specs.get(rid.checked_sub(1)? as usize)?;
        let method: RowRef = row.method?;
        let base: String = self.row_ref_name(method);
        if base.contains('<') {
            return Some(base);
        }
        let inferable: bool = self
            .callee_signature(row_ref_token(method))
            .is_none_or(|sig: MethodSig| !sig.params.is_empty());
        if inferable {
            return Some(base);
        }
        let args: Vec<crate::signature::TypeSig> = self
            .blob(row.instantiation)
            .and_then(|blob: &[u8]| crate::signature::parse_method_spec_sig(blob).ok())
            .unwrap_or_default();
        if args.is_empty() {
            return Some(base);
        }
        let rendered: String = args
            .iter()
            .map(|a: &crate::signature::TypeSig| self.substitute_type_tokens(&a.render()))
            .collect::<Vec<String>>()
            .join(", ");
        Some(format!("{base}<{rendered}>"))
    }

    #[must_use]
    fn type_spec_name(&self, rid: u32) -> Option<String> {
        let row: &TypeSpecRow = self.tables.type_specs.get(rid.checked_sub(1)? as usize)?;
        let blob: &[u8] = self.blob(row.signature)?;
        let sig: crate::signature::TypeSig = crate::signature::parse_type_spec_sig(blob).ok()?;
        Some(self.substitute_type_tokens(&sig.render()))
    }

    #[must_use]
    pub fn resolve_type_tokens(&self, rendered: &str) -> String {
        self.substitute_type_tokens(rendered)
    }

    #[must_use]
    fn substitute_type_tokens(&self, rendered: &str) -> String {
        let mut out: String = String::with_capacity(rendered.len());
        let mut rest: &str = rendered;
        while let Some(pos) = rest.find("type(0x") {
            out.push_str(&rest[..pos]);
            let after: &str = &rest[pos + "type(0x".len()..];
            if let Some(end) = after.find(')')
                && end == 8
                && let Ok(token) = u32::from_str_radix(&after[..8], 16)
            {
                out.push_str(&self.resolve_token(token));
                rest = &after[end + 1..];
            } else {
                out.push_str("type(0x");
                rest = after;
            }
        }
        out.push_str(rest);
        out
    }

    #[must_use]
    fn row_ref_name(&self, r: RowRef) -> String {
        let token: u32 = (u32::from(r.table.index()) << 24) | r.row;
        self.resolve_token(token)
    }

    #[must_use]
    fn method_owner_name(&self, method_rid: u32) -> Option<String> {
        let types: &[crate::tables::TypeDefRow] = &self.tables.type_defs;
        for (idx, t) in types.iter().enumerate() {
            let start: u32 = t.method_list;
            let next: u32 = types
                .get(idx + 1)
                .map_or(self.tables.methods.len() as u32 + 1, |n| n.method_list);
            if method_rid >= start && method_rid < next {
                return Some(Self::qualify(self.string(t.namespace), self.string(t.name)));
            }
        }
        None
    }

    #[must_use]
    fn qualify(ns: String, name: String) -> String {
        let name: String = strip_generic_arity(&name);
        if ns.is_empty() {
            name
        } else {
            format!("{ns}.{name}")
        }
    }

    #[must_use]
    pub fn model(&self) -> AssemblyModel {
        let module_name: String = self
            .tables
            .modules
            .first()
            .map(|m| self.string(m.name))
            .unwrap_or_default();
        let assembly_name: Option<String> = self
            .tables
            .assembly
            .map(|a| self.string(a.name))
            .filter(|s: &String| !s.is_empty());

        let type_count: u32 = self.tables.type_defs.len() as u32;
        let field_total: u32 = self.tables.fields.len() as u32;
        let method_total: u32 = self.tables.methods.len() as u32;
        let field_constants: BTreeMap<u32, FieldConstant> = self.materialize_field_constants();

        let mut types: Vec<TypeModel> = Vec::with_capacity(self.tables.type_defs.len());
        let n_types: usize = self.tables.type_defs.len();
        for (idx, t) in self.tables.type_defs.iter().enumerate() {
            let type_rid: u32 = idx as u32 + 1;
            let field_start: u32 = t.field_list;
            let field_end: u32 = self
                .tables
                .type_defs
                .get(idx + 1)
                .map_or(field_total + 1, |n| n.field_list);
            let method_start: u32 = t.method_list;
            let method_end: u32 = self
                .tables
                .type_defs
                .get(idx + 1)
                .map_or(method_total + 1, |n| n.method_list);

            let fields: Vec<FieldModel> =
                self.materialize_fields(field_start, field_end, field_total, &field_constants);
            let methods: Vec<MethodModel> =
                self.materialize_methods(method_start, method_end, method_total);

            let namespace: String = self.string(t.namespace);
            let name: String = self.string(t.name);
            let full_name: String = Self::qualify(namespace.clone(), name.clone());
            let base_type: Option<String> = t.extends.map(|e: RowRef| self.row_ref_name(e));
            types.push(TypeModel {
                token: (u32::from(TableId::TypeDef.index()) << 24) | type_rid,
                namespace,
                name,
                full_name,
                flags: t.flags,
                base_type,
                fields,
                methods,
            });
            let _ = n_types;
        }

        AssemblyModel {
            module_name,
            assembly_name,
            types,
            method_count: method_total,
            field_count: field_total,
            type_count,
        }
    }

    fn materialize_field_constants(&self) -> BTreeMap<u32, FieldConstant> {
        let mut constants: BTreeMap<u32, FieldConstant> = BTreeMap::new();
        for row in &self.tables.constants {
            let parent: Option<RowRef> = row.parent;
            let Some(parent): Option<RowRef> = parent else {
                continue;
            };
            if parent.table != TableId::Field {
                continue;
            }
            let value: Option<&[u8]> = self.blob(row.value);
            let Some(value): Option<&[u8]> = value else {
                continue;
            };
            let constant: FieldConstant = FieldConstant {
                element_type: row.element_type,
                value: value.to_vec(),
            };
            constants.entry(parent.row).or_insert(constant);
        }
        constants
    }

    fn materialize_fields(
        &self,
        start: u32,
        end: u32,
        total: u32,
        constants: &BTreeMap<u32, FieldConstant>,
    ) -> Vec<FieldModel> {
        let lo: u32 = start.clamp(1, total.saturating_add(1));
        let hi: u32 = end.clamp(lo, total.saturating_add(1));
        let mut out: Vec<FieldModel> = Vec::with_capacity((hi - lo) as usize);
        for rid in lo..hi {
            let Some(row) = self.tables.fields.get((rid - 1) as usize) else {
                break;
            };
            let signature: FieldSig = self
                .blob(row.signature)
                .and_then(|blob: &[u8]| parse_field_sig_with_modifiers(blob).ok())
                .unwrap_or_default();
            let is_volatile: bool = signature.required_modifiers.iter().any(|token: &u32| {
                self.resolve_token(*token) == "System.Runtime.CompilerServices.IsVolatile"
            });
            out.push(FieldModel {
                token: (u32::from(TableId::Field.index()) << 24) | rid,
                name: self.string(row.name),
                flags: row.flags,
                field_type: signature.field_type,
                is_volatile,
                constant: constants.get(&rid).cloned(),
            });
        }
        out
    }

    fn materialize_methods(&self, start: u32, end: u32, total: u32) -> Vec<MethodModel> {
        let lo: u32 = start.clamp(1, total.saturating_add(1));
        let hi: u32 = end.clamp(lo, total.saturating_add(1));
        let mut out: Vec<MethodModel> = Vec::with_capacity((hi - lo) as usize);
        for rid in lo..hi {
            let Some(row): Option<&MethodDefRow> = self.tables.methods.get((rid - 1) as usize)
            else {
                break;
            };
            let signature: MethodSig = self
                .blob(row.signature)
                .and_then(|b: &[u8]| parse_method_sig(b).ok())
                .unwrap_or_default();
            let parameters: Vec<ParamModel> = self.materialize_params(rid);
            out.push(MethodModel {
                token: (u32::from(TableId::MethodDef.index()) << 24) | rid,
                name: self.string(row.name),
                flags: row.flags,
                impl_flags: row.impl_flags,
                rva: row.rva,
                signature,
                parameters,
            });
        }
        out
    }

    fn materialize_params(&self, method_rid: u32) -> Vec<ParamModel> {
        let methods: &[MethodDefRow] = &self.tables.methods;
        let Some(row): Option<&MethodDefRow> = methods.get((method_rid - 1) as usize) else {
            return Vec::new();
        };
        let start: u32 = row.param_list;
        let total: u32 = self.tables.params.len() as u32;
        let end: u32 = methods
            .get(method_rid as usize)
            .map_or(total + 1, |n: &MethodDefRow| n.param_list);
        let lo: u32 = start.clamp(1, total.saturating_add(1));
        let hi: u32 = end.clamp(lo, total.saturating_add(1));
        let mut out: Vec<ParamModel> = Vec::new();
        for rid in lo..hi {
            let Some(p) = self.tables.params.get((rid - 1) as usize) else {
                break;
            };
            out.push(ParamModel {
                sequence: p.sequence,
                name: self.string(p.name),
            });
        }
        out
    }

    #[must_use]
    pub fn render_type(&self, sig: &TypeSig, lang: TargetLang) -> String {
        if let TypeSig::GenericInst { base, args } = sig
            && let TypeSig::NamedType { token, .. } = base.as_ref()
            && let Some(rendered) = self.render_nested_generic_inst(*token, args, lang)
        {
            return rendered;
        }
        self.substitute_type_tokens(&sig.render_in(lang))
    }

    fn type_ref_nesting_chain(&self, rid: u32) -> Option<Vec<(String, String)>> {
        let mut chain: Vec<(String, String)> = Vec::new();
        let mut cur: u32 = rid;
        loop {
            let row: &crate::tables::TypeRefRow =
                self.tables.type_refs.get(cur.checked_sub(1)? as usize)?;
            chain.push((self.string(row.namespace), self.string(row.name)));
            match row.resolution_scope {
                Some(scope) if scope.table == TableId::TypeRef => cur = scope.row,
                _ => break,
            }
            if chain.len() > 16 {
                break;
            }
        }
        chain.reverse();
        Some(chain)
    }

    fn render_nested_generic_inst(
        &self,
        token: u32,
        args: &[TypeSig],
        lang: TargetLang,
    ) -> Option<String> {
        if TableId::from_index(u8::try_from(token >> 24).unwrap_or(0xFF))? != TableId::TypeRef {
            return None;
        }
        let chain: Vec<(String, String)> = self.type_ref_nesting_chain(token & 0x00FF_FFFF)?;
        if chain.len() < 2 {
            return None;
        }
        let mut parts: Vec<String> = Vec::with_capacity(chain.len());
        let mut consumed: usize = 0;
        for (idx, (ns, raw)) in chain.iter().enumerate() {
            let arity: usize = generic_arity(raw);
            let simple: String = strip_generic_arity(raw);
            let name: String = if idx == 0 && !ns.is_empty() {
                format!("{ns}.{simple}")
            } else {
                simple
            };
            let end: usize = consumed.checked_add(arity)?;
            let seg: &[TypeSig] = args.get(consumed..end)?;
            consumed = end;
            if seg.is_empty() {
                parts.push(name);
            } else {
                let rendered: Vec<String> = seg
                    .iter()
                    .map(|a: &TypeSig| self.render_type(a, lang))
                    .collect();
                match lang {
                    TargetLang::VbNet => parts.push(format!("{name}(Of {})", rendered.join(", "))),
                    _ => parts.push(format!("{name}<{}>", rendered.join(", "))),
                }
            }
        }
        (consumed == args.len()).then(|| parts.join("."))
    }

    #[must_use]
    pub fn local_types(&self, local_var_sig_tok: u32, lang: TargetLang) -> Vec<String> {
        if local_var_sig_tok == 0 {
            return Vec::new();
        }
        let table_idx: u8 = u8::try_from(local_var_sig_tok >> 24).unwrap_or(0xFF);
        if TableId::from_index(table_idx) != Some(TableId::StandAloneSig) {
            return Vec::new();
        }
        let Some(rid): Option<usize> = (local_var_sig_tok & 0x00FF_FFFF)
            .checked_sub(1)
            .map(|r: u32| r as usize)
        else {
            return Vec::new();
        };
        let Some(row): Option<&crate::tables::StandAloneSigRow> =
            self.tables.standalone_sigs.get(rid)
        else {
            return Vec::new();
        };
        let Some(blob): Option<&[u8]> = self.blob(row.signature) else {
            return Vec::new();
        };
        crate::signature::parse_local_sig(blob).map_or_else(
            |_| Vec::new(),
            |locals: Vec<TypeSig>| {
                locals
                    .iter()
                    .map(|t: &TypeSig| self.render_type(t, lang))
                    .collect()
            },
        )
    }

    #[must_use]
    pub fn callee_signature(&self, token: u32) -> Option<MethodSig> {
        let table_idx: u8 = u8::try_from(token >> 24).unwrap_or(0xFF);
        let rid: usize = (token & 0x00FF_FFFF).checked_sub(1)? as usize;
        let blob_index: u32 = match TableId::from_index(table_idx)? {
            TableId::MethodDef => self.tables.methods.get(rid)?.signature,
            TableId::MemberRef => self.tables.member_refs.get(rid)?.signature,
            TableId::MethodSpec => {
                let method: RowRef = self.tables.method_specs.get(rid)?.method?;
                return self.callee_signature(row_ref_token(method));
            }
            _ => return None,
        };
        let blob: &[u8] = self.blob(blob_index)?;
        parse_method_sig(blob).ok()
    }

    #[must_use]
    pub fn callee_is_virtual_definition(&self, token: u32) -> bool {
        let table_idx: u8 = u8::try_from(token >> 24).unwrap_or(0xFF);
        if TableId::from_index(table_idx) != Some(TableId::MethodDef) {
            return false;
        }
        let Some(rid): Option<usize> = (token & 0x00FF_FFFF)
            .checked_sub(1)
            .map(|r: u32| r as usize)
        else {
            return false;
        };
        self.tables
            .methods
            .get(rid)
            .is_some_and(|row: &MethodDefRow| row.flags & METHOD_VIRTUAL != 0)
    }

    #[must_use]
    pub fn callee_param_type_name(&self, token: u32, param_index: usize) -> Option<String> {
        let sig: MethodSig = self.callee_signature(token)?;
        let param: &TypeSig = sig.params.get(param_index)?;
        let rendered: String = self.render_type(param, TargetLang::CSharp);
        (!rendered.is_empty()).then_some(rendered)
    }

    #[must_use]
    pub fn field_token_type_name(&self, token: u32) -> Option<String> {
        let table_idx: u8 = u8::try_from(token >> 24).unwrap_or(0xFF);
        let rid: usize = (token & 0x00FF_FFFF).checked_sub(1)? as usize;
        let blob_index: u32 = match TableId::from_index(table_idx)? {
            TableId::Field => self.tables.fields.get(rid)?.signature,
            TableId::MemberRef => self.tables.member_refs.get(rid)?.signature,
            _ => return None,
        };
        let blob: &[u8] = self.blob(blob_index)?;
        let sig: TypeSig = parse_field_sig(blob).ok()?;
        let rendered: String = self.render_type(&sig, TargetLang::CSharp);
        (!rendered.is_empty()).then_some(rendered)
    }

    #[must_use]
    pub fn enum_param_type_name(&self, token: u32, param_index: usize) -> Option<String> {
        let sig: MethodSig = self.callee_signature(token)?;
        let param: &TypeSig = sig.params.get(param_index)?;
        match param {
            TypeSig::NamedType {
                is_value_type: true,
                ..
            } => {
                let rendered: String = self.render_type(param, TargetLang::CSharp);
                (!rendered.is_empty()
                    && !rendered.contains('<')
                    && !rendered.contains('[')
                    && !rendered.contains('!'))
                .then_some(rendered)
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn methods_with_bodies(&self) -> Vec<(u32, String, u32)> {
        let mut out: Vec<(u32, String, u32)> = Vec::new();
        for (idx, m) in self.tables.methods.iter().enumerate() {
            if m.rva != 0 {
                let rid: u32 = idx as u32 + 1;
                let name: String = self.method_name(rid).unwrap_or_else(|| self.string(m.name));
                out.push((rid, name, m.rva));
            }
        }
        out
    }
}

fn pop_receiver_fact(state: &mut ReceiverState) -> ReceiverFact {
    if let Some(value) = state.stack.pop() {
        value
    } else {
        state.poisoned = true;
        ReceiverFact::Unknown
    }
}

fn pop_receiver_count(state: &mut ReceiverState, count: usize) {
    for _ in 0..count {
        let _: ReceiverFact = pop_receiver_fact(state);
    }
}

fn clear_receiver_stack(state: &mut ReceiverState) {
    state.stack.clear();
    state.locals.clear();
    state.poisoned = true;
}

fn poison_receiver_state(state: &mut ReceiverState) {
    clear_receiver_stack(state);
}

fn branch_successor(
    body: &MethodBody,
    index: usize,
    offsets: &BTreeMap<u32, usize>,
) -> Option<usize> {
    branch_successors(body, index, offsets).into_iter().next()
}

fn branch_successors(
    body: &MethodBody,
    index: usize,
    offsets: &BTreeMap<u32, usize>,
) -> Vec<usize> {
    let instruction: &Instruction = match body.instructions.get(index) {
        Some(instruction) => instruction,
        None => return Vec::new(),
    };
    let next_index: Option<usize> = index.checked_add(1);
    let next_offset: u32 = next_index
        .and_then(|next: usize| body.instructions.get(next))
        .map_or(body.code_size, |next: &Instruction| next.offset);
    let mut out: Vec<usize> = Vec::new();
    let mut push_relative = |relative: i32| {
        let Some(index): Option<usize> = branch_target_index(next_offset, relative, offsets) else {
            return;
        };
        if !out.contains(&index) {
            out.push(index);
        }
    };
    match &instruction.operand {
        OperandValue::BrTarget(relative) => push_relative(*relative),
        OperandValue::Switch(relatives) => {
            for relative in relatives {
                push_relative(*relative);
            }
        }
        _ => {}
    }
    out
}

fn control_flow_targets_are_valid(body: &MethodBody, offsets: &BTreeMap<u32, usize>) -> bool {
    body.instructions
        .iter()
        .enumerate()
        .all(|(index, instruction): (usize, &Instruction)| {
            let next_offset: u32 = index
                .checked_add(1)
                .and_then(|next: usize| body.instructions.get(next))
                .map_or(body.code_size, |next: &Instruction| next.offset);
            match instruction.flow {
                FlowControl::Branch if instruction.name == "jmp" => true,
                FlowControl::Branch | FlowControl::CondBranch => match &instruction.operand {
                    OperandValue::BrTarget(relative) => {
                        branch_target_index(next_offset, *relative, offsets).is_some()
                    }
                    OperandValue::Switch(relatives) => relatives.iter().all(|relative: &i32| {
                        branch_target_index(next_offset, *relative, offsets).is_some()
                    }),
                    _ => false,
                },
                FlowControl::Next
                | FlowControl::Call
                | FlowControl::Return
                | FlowControl::Throw
                | FlowControl::Meta
                | FlowControl::Break => true,
            }
        })
}

fn branch_target_index(
    next_offset: u32,
    relative: i32,
    offsets: &BTreeMap<u32, usize>,
) -> Option<usize> {
    let target: i64 = i64::from(next_offset).checked_add(i64::from(relative))?;
    let target: u32 = u32::try_from(target).ok()?;
    offsets.get(&target).copied()
}

fn token_table(token: u32) -> Option<TableId> {
    let index: u8 = u8::try_from(token >> 24).ok()?;
    TableId::from_index(index)
}

fn token_rid(token: u32) -> Option<u32> {
    let rid: u32 = token & 0x00FF_FFFF;
    (rid != 0).then_some(rid)
}

fn method_def_token(method_rid: u32) -> u32 {
    (u32::from(TableId::MethodDef.index()) << 24) | method_rid
}

fn signature_is_closed(signature: &MethodSig) -> bool {
    if signature.generic_param_count != 0 || signature.explicit_this {
        return false;
    }
    let return_closed: bool = match &signature.return_type {
        crate::signature::TypeSigOrVoid::Void => true,
        crate::signature::TypeSigOrVoid::Type(ty) => type_sig_is_closed(ty),
    };
    return_closed && signature.params.iter().all(type_sig_is_closed)
}

fn type_sig_is_closed(ty: &TypeSig) -> bool {
    match ty {
        TypeSig::NamedType { .. }
        | TypeSig::Void
        | TypeSig::Boolean
        | TypeSig::Char
        | TypeSig::I1
        | TypeSig::U1
        | TypeSig::I2
        | TypeSig::U2
        | TypeSig::I4
        | TypeSig::U4
        | TypeSig::I8
        | TypeSig::U8
        | TypeSig::R4
        | TypeSig::R8
        | TypeSig::String
        | TypeSig::IntPtr
        | TypeSig::UIntPtr
        | TypeSig::Object
        | TypeSig::TypedByRef => true,
        TypeSig::SzArray(inner)
        | TypeSig::Ptr(inner)
        | TypeSig::ByRef(inner)
        | TypeSig::Pinned(inner) => type_sig_is_closed(inner),
        TypeSig::Array { element, .. } => type_sig_is_closed(element),
        TypeSig::GenericInst { .. }
        | TypeSig::Var(_)
        | TypeSig::MVar(_)
        | TypeSig::FnPtr
        | TypeSig::Unknown => false,
    }
}

#[must_use]
fn row_ref_token(r: RowRef) -> u32 {
    (u32::from(r.table as u8) << 24) | (r.row & 0x00FF_FFFF)
}

#[must_use]
fn strip_generic_arity(name: &str) -> String {
    match name.split_once('`') {
        Some((base, rest)) if rest.bytes().all(|b: u8| b.is_ascii_digit()) => base.to_owned(),
        _ => name.to_owned(),
    }
}

fn generic_arity(name: &str) -> usize {
    match name.split_once('`') {
        Some((_, rest)) => rest.parse::<usize>().unwrap_or(0),
        None => 0,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pe::{parse, parse_clr_header};

    fn load(rel: &str) -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(rel);
        std::fs::read(&path).expect("fixture")
    }

    fn resolver_for(rel: &str) -> Resolver {
        let bytes: Vec<u8> = load(rel);
        let pe: PeImage = parse(&bytes).expect("pe");
        let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr");
        let root: MetadataRoot =
            crate::metadata::parse_metadata_root(&bytes, &pe, &clr).expect("root");
        Resolver::build(&bytes, &pe, &clr, &root).expect("resolver")
    }

    #[test]
    fn generic_arity_reads_backtick_suffix() {
        assert_eq!(generic_arity("List`1"), 1);
        assert_eq!(generic_arity("Dictionary`2"), 2);
        assert_eq!(generic_arity("Enumerator"), 0);
        assert_eq!(generic_arity("Weird`x"), 0);
    }

    #[test]
    fn csharp_signature_escapes_keyword_parameter_name() {
        let method: MethodModel = MethodModel {
            token: 0x0600_0001,
            name: "Sample.K::M".to_owned(),
            flags: METHOD_PUBLIC | METHOD_STATIC,
            impl_flags: 0,
            rva: 0,
            signature: MethodSig {
                calling_convention: 0,
                has_this: false,
                explicit_this: false,
                generic_param_count: 0,
                return_type: crate::signature::TypeSigOrVoid::Void,
                params: vec![TypeSig::I4],
            },
            parameters: vec![ParamModel {
                sequence: 1,
                name: "object".to_owned(),
            }],
        };
        let sig: String = method.csharp_signature();
        assert!(sig.ends_with("M(int @object)"), "got: {sig}");
    }

    #[test]
    fn malformed_branch_targets_are_rejected() {
        let body: MethodBody = MethodBody {
            max_stack: 0,
            code_size: 2,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: vec![
                Instruction {
                    offset: 0,
                    opcode: 0x2B,
                    name: "br.s".to_owned(),
                    operand: OperandValue::BrTarget(16),
                    flow: FlowControl::Branch,
                },
                Instruction {
                    offset: 1,
                    opcode: 0x2A,
                    name: "ret".to_owned(),
                    operand: OperandValue::None,
                    flow: FlowControl::Return,
                },
            ],
            exception_clauses: Vec::new(),
        };
        let offsets: BTreeMap<u32, usize> = [(0, 0), (1, 1)].into_iter().collect();
        assert!(!control_flow_targets_are_valid(&body, &offsets));
    }

    #[test]
    fn strict_user_strings_reject_malformed_utf16_and_trailers() {
        let resolver: fn(Vec<u8>) -> Resolver = |us: Vec<u8>| Resolver {
            tables: Tables::default(),
            method_impl_types: BTreeSet::new(),
            strings_heap: Vec::new(),
            blob: Vec::new(),
            us,
        };
        assert_eq!(
            resolver(vec![0, 3, 0x41, 0, 0]).user_string_strict(1),
            Some("A".to_string())
        );
        assert_eq!(resolver(vec![0, 2, 0x41, 0]).user_string_strict(1), None);
        assert_eq!(
            resolver(vec![0, 3, 0x00, 0xD8, 1]).user_string_strict(1),
            None
        );
        assert_eq!(resolver(vec![0, 3, 0x41, 0, 2]).user_string_strict(1), None);
    }

    #[test]
    fn builds_model_from_real_helloapp() {
        let r: Resolver = resolver_for("../../corpus/dotnet/HelloApp.dll");
        let model: AssemblyModel = r.model();
        assert!(model.type_count >= 1, "must have at least <Module>");
        assert!(
            model.method_count >= 1,
            "HelloApp must declare at least one method"
        );
        assert!(!model.module_name.is_empty(), "module row carries a name");
    }

    #[test]
    fn generic_state_machine_type_resolves_its_declared_parameter_name() {
        let r: Resolver = resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let model: AssemblyModel = r.model();
        let bfs: &TypeModel = model
            .types
            .iter()
            .find(|t: &&TypeModel| t.name.starts_with("<Bfs>d__"))
            .expect("<Bfs> iterator state machine type");
        let names: Vec<String> = r.type_generic_param_names(bfs.token & 0x00FF_FFFF);
        assert_eq!(
            names,
            vec!["T".to_owned()],
            "the <Bfs> state machine carries a single declared type parameter T"
        );
    }

    #[test]
    fn non_generic_type_has_no_generic_parameters() {
        let r: Resolver = resolver_for("../../corpus/dotnet/HelloApp.dll");
        let model: AssemblyModel = r.model();
        let ty: &TypeModel = model
            .types
            .iter()
            .find(|t: &&TypeModel| !t.name.is_empty() && t.name != "<Module>")
            .expect("a named type");
        assert!(
            r.type_generic_param_names(ty.token & 0x00FF_FFFF)
                .is_empty(),
            "a non-generic type yields no generic parameter names"
        );
    }

    #[test]
    fn helloapp_has_program_type_with_main() {
        let r: Resolver = resolver_for("../../corpus/dotnet/HelloApp.dll");
        let model: AssemblyModel = r.model();
        let has_method: bool = model
            .types
            .iter()
            .flat_map(|t: &TypeModel| t.methods.iter())
            .any(|m: &MethodModel| !m.name.is_empty());
        assert!(has_method, "at least one named method resolved");
    }

    #[test]
    fn methodspec_callee_signature_resolves_through_to_the_parent_method() {
        let r: Resolver = resolver_for("../../corpus/dotnet/constructs/Constructs.dll");
        let spec_count: usize = r.tables.method_specs.len();
        assert!(
            spec_count > 0,
            "Constructs uses generic LINQ (Enumerable.Select/Sum), so it must carry MethodSpec rows"
        );
        let mut resolved_with_params: usize = 0;
        for rid in 1..=spec_count {
            let table_idx: u32 = u32::from(TableId::MethodSpec as u8);
            let token: u32 = (table_idx << 24) | u32::try_from(rid).unwrap_or(0);
            if let Some(sig) = r.callee_signature(token) {
                let argc: usize = sig.params.len() + usize::from(sig.has_this);
                if argc > 0 {
                    resolved_with_params += 1;
                }
            }
        }
        assert!(
            resolved_with_params > 0,
            "at least one generic-method call must resolve a non-zero argument count through its MethodSpec parent (Select takes the source + a selector)"
        );
    }

    #[test]
    fn methods_with_bodies_have_rvas() {
        let r: Resolver = resolver_for("../../corpus/dotnet/HelloApp.dll");
        let bodies: Vec<(u32, String, u32)> = r.methods_with_bodies();
        assert!(!bodies.is_empty(), "HelloApp has methods with CIL bodies");
        for (_, _, rva) in &bodies {
            assert_ne!(*rva, 0);
        }
    }

    #[test]
    fn token_resolution_yields_names_on_megafile() {
        let r: Resolver = resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let model: AssemblyModel = r.model();
        assert!(
            model.type_count > 10,
            "EdgeCases megafile declares many types; got {}",
            model.type_count
        );
        let named_types: usize = model
            .types
            .iter()
            .filter(|t: &&TypeModel| !t.name.is_empty())
            .count();
        assert!(named_types > 5, "most types resolve a name");
    }
}
