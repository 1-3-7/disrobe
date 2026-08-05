use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue, SlotOp};
use crate::error::{Error, Result};
use crate::metadata::{MetadataRoot, decompress_uint};
use crate::pe::{ClrHeader, PeImage};
use crate::signature::{
    FieldSig, MethodSig, SIG_DEFAULT, SIG_HASTHIS, TypeSig, TypeSigOrVoid, parse_field_sig,
    parse_field_sig_strict, parse_field_sig_with_modifiers, parse_method_sig,
    parse_method_sig_strict,
};
use crate::structurize::{
    FieldRvaPrimitive, MetadataTokenKind, TargetLang, csharp_escape_identifier,
    is_simple_identifier,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsInstTargetKind {
    ValueType,
    ReferenceType,
    RenderableUnknown,
    #[default]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CSharpTypeCategory {
    ValueType,
    ReferenceType,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CSharpTypeTarget {
    rendered: String,
    category: CSharpTypeCategory,
    nullable: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CSharpOverrideKind {
    Override,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamModel {
    pub sequence: u16,
    pub name: String,
}

const METHOD_STATIC: u16 = 0x0010;
const METHOD_ACCESS_MASK: u16 = 0x0007;
const METHOD_PUBLIC: u16 = 0x0006;
const METHOD_FINAL: u16 = 0x0020;
const METHOD_VIRTUAL: u16 = 0x0040;
const METHOD_HIDE_BY_SIG: u16 = 0x0080;
const METHOD_NEW_SLOT: u16 = 0x0100;
const METHOD_ABSTRACT: u16 = 0x0400;
const METHOD_SPECIAL_NAME: u16 = 0x0800;
const METHOD_RUNTIME_SPECIAL_NAME: u16 = 0x1000;
const FIELD_PRIVATE_INIT_ONLY: u16 = 0x0021;
const TYPE_ABSTRACT: u32 = 0x0080;
const TYPE_SEALED: u32 = 0x0100;
const TYPE_INTERFACE: u32 = 0x0020;
const TYPE_BEFORE_FIELD_INIT: u32 = 0x0010_0000;
const ANONYMOUS_TYPE_FLAGS: u32 = TYPE_SEALED | TYPE_BEFORE_FIELD_INIT;
const ANONYMOUS_CONSTRUCTOR_FLAGS: u16 =
    METHOD_PUBLIC | METHOD_HIDE_BY_SIG | METHOD_SPECIAL_NAME | METHOD_RUNTIME_SPECIAL_NAME;

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
    pub(crate) fn csharp_signature_with_override(
        &self,
        override_kind: Option<CSharpOverrideKind>,
    ) -> String {
        self.csharp_header_with_override(override_kind)
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
        self.csharp_header_with_override(None)
    }

    fn csharp_header_with_override(&self, override_kind: Option<CSharpOverrideKind>) -> String {
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
        let override_modifier: &str = match override_kind {
            Some(CSharpOverrideKind::Override) => "override ",
            None => "",
        };
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
        format!(
            "{vis}{stat}{override_modifier}{ret} {display_name}({})",
            rendered.join(", ")
        )
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
    method_impl_indices_by_type: BTreeMap<u32, Vec<usize>>,
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
        let method_impl_indices_by_type: BTreeMap<u32, Vec<usize>> =
            Self::index_method_impls_by_type(&tables.method_impls);
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
            method_impl_indices_by_type,
            strings_heap,
            blob,
            us,
        })
    }

    #[must_use]
    pub const fn tables(&self) -> &Tables {
        &self.tables
    }

    fn index_method_impls_by_type(
        method_impls: &[crate::tables::MethodImplRow],
    ) -> BTreeMap<u32, Vec<usize>> {
        let mut indices_by_type: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for (index, mapping) in method_impls.iter().enumerate() {
            indices_by_type
                .entry(mapping.class_type)
                .or_default()
                .push(index);
        }
        indices_by_type
    }

    fn method_impl_indices_for_type(&self, class_type: u32) -> &[usize] {
        self.method_impl_indices_by_type
            .get(&class_type)
            .map_or(&[], Vec::as_slice)
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
                let fact: ReceiverFact = crate::cil::slot_index_of(instruction, SlotOp::LoadLocal)
                    .and_then(|slot: u16| outgoing.locals.get(&u32::from(slot)).copied())
                    .unwrap_or(ReceiverFact::Unknown);
                outgoing.stack.push(fact);
            }
            "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc" | "stloc.s" => {
                let value: ReceiverFact = pop_receiver_fact(&mut outgoing);
                match crate::cil::slot_index_of(instruction, SlotOp::StoreLocal) {
                    Some(slot) => match value {
                        ReceiverFact::Exact(_) => {
                            outgoing.locals.insert(u32::from(slot), value);
                        }
                        ReceiverFact::Unknown => {
                            outgoing.locals.remove(&u32::from(slot));
                        }
                    },
                    None => outgoing.locals.clear(),
                }
            }
            "ldloca" | "ldloca.s" => {
                match crate::cil::slot_index_of(instruction, SlotOp::LocalAddress) {
                    Some(slot) => {
                        outgoing.locals.remove(&u32::from(slot));
                    }
                    None => outgoing.locals.clear(),
                }
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
            if self.method_impl_indices_by_type.contains_key(&current) {
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
        if self.type_def_is_corelib_value_root(type_rid) {
            return false;
        }
        let Some(parent): Option<RowRef> = type_row.extends else {
            return false;
        };
        self.is_corelib_value_type_parent(parent)
    }

    #[must_use]
    pub(crate) fn csharp_value_type_override_kind(
        &self,
        declaring_type_token: u32,
        method_token: u32,
    ) -> Option<CSharpOverrideKind> {
        if token_table(declaring_type_token)? != TableId::TypeDef
            || token_table(method_token)? != TableId::MethodDef
        {
            return None;
        }
        let declaring_type_rid: u32 = token_rid(declaring_type_token)?;
        let method_rid: u32 = token_rid(method_token)?;
        if !self.is_csharp_struct_override_declaring_type(declaring_type_rid) {
            return None;
        }
        let (method_start, method_end): (u32, u32) = self.method_range(declaring_type_rid)?;
        if !(method_start..method_end).contains(&method_rid) {
            return None;
        }
        let method: &MethodDefRow = self
            .tables
            .methods
            .get(method_rid.checked_sub(1)? as usize)?;
        if method.rva == 0
            || (method.flags & !METHOD_FINAL)
                != (METHOD_PUBLIC | METHOD_VIRTUAL | METHOD_HIDE_BY_SIG)
            || !self.method_matches_csharp_object_override_signature(method)
        {
            return None;
        }
        if self.method_has_explicit_impl_body(declaring_type_rid, method_rid) {
            return None;
        }
        Some(CSharpOverrideKind::Override)
    }

    fn is_csharp_struct_override_declaring_type(&self, type_rid: u32) -> bool {
        let Some(index): Option<usize> = type_rid
            .checked_sub(1)
            .and_then(|value: u32| usize::try_from(value).ok())
        else {
            return false;
        };
        let Some(type_def): Option<&TypeDefRow> = self.tables.type_defs.get(index) else {
            return false;
        };
        type_def.flags & TYPE_SEALED != 0
            && type_def.flags & (TYPE_ABSTRACT | TYPE_INTERFACE) == 0
            && type_def
                .extends
                .is_some_and(|parent: RowRef| self.is_corelib_value_type_parent_exact(parent))
    }

    fn is_corelib_value_type_parent_exact(&self, parent: RowRef) -> bool {
        match parent.table {
            TableId::TypeDef => self.type_def_is_corelib_value_type(parent.row),
            TableId::TypeRef => self.type_ref_is_corelib_value_type(parent.row),
            _ => false,
        }
    }

    fn type_def_is_corelib_value_type(&self, rid: u32) -> bool {
        if !self.is_corelib_definition_assembly() {
            return false;
        }
        let Some(index): Option<usize> = rid
            .checked_sub(1)
            .and_then(|value: u32| usize::try_from(value).ok())
        else {
            return false;
        };
        let Some(type_def): Option<&TypeDefRow> = self.tables.type_defs.get(index) else {
            return false;
        };
        self.string(type_def.namespace) == "System" && self.string(type_def.name) == "ValueType"
    }

    fn type_ref_is_corelib_value_type(&self, rid: u32) -> bool {
        let Some(index): Option<usize> = rid
            .checked_sub(1)
            .and_then(|value: u32| usize::try_from(value).ok())
        else {
            return false;
        };
        let Some(type_ref): Option<&TypeRefRow> = self.tables.type_refs.get(index) else {
            return false;
        };
        self.string(type_ref.namespace) == "System"
            && self.string(type_ref.name) == "ValueType"
            && type_ref
                .resolution_scope
                .is_some_and(|scope: RowRef| self.is_corelib_assembly_ref(scope))
    }

    fn method_has_explicit_impl_body(&self, declaring_type_rid: u32, method_rid: u32) -> bool {
        self.method_impl_indices_for_type(declaring_type_rid)
            .iter()
            .any(|index: &usize| {
                let Some(mapping): Option<&crate::tables::MethodImplRow> =
                    self.tables.method_impls.get(*index)
                else {
                    return true;
                };
                let Some(body): Option<RowRef> = mapping.method_body else {
                    return true;
                };
                match body.table {
                    TableId::MethodDef => body.row == method_rid,
                    TableId::MemberRef => self
                        .member_ref_targets_method(body.row, declaring_type_rid, method_rid)
                        .unwrap_or(true),
                    _ => true,
                }
            })
    }

    fn member_ref_targets_method(
        &self,
        member_ref_rid: u32,
        declaring_type_rid: u32,
        method_rid: u32,
    ) -> Option<bool> {
        let member_ref_index: usize = member_ref_rid
            .checked_sub(1)
            .and_then(|value: u32| usize::try_from(value).ok())?;
        let member_ref: &MemberRefRow = self.tables.member_refs.get(member_ref_index)?;
        let parent: RowRef = member_ref.parent?;
        if parent.table != TableId::TypeDef {
            return None;
        }
        if parent.row != declaring_type_rid {
            return Some(false);
        }
        let method_index: usize = method_rid
            .checked_sub(1)
            .and_then(|value: u32| usize::try_from(value).ok())?;
        let method: &MethodDefRow = self.tables.methods.get(method_index)?;
        Some(
            self.string(member_ref.name) == self.string(method.name)
                && self.method_signature(member_ref.signature)?
                    == self.method_signature(method.signature)?,
        )
    }

    fn method_matches_csharp_object_override_signature(&self, method: &MethodDefRow) -> bool {
        let Some(signature): Option<MethodSig> = self.method_signature(method.signature) else {
            return false;
        };
        if signature.calling_convention != (SIG_HASTHIS | SIG_DEFAULT)
            || !signature.has_this
            || signature.explicit_this
            || signature.generic_param_count != 0
        {
            return false;
        }
        matches!(
            (
                self.string(method.name).as_str(),
                &signature.return_type,
                signature.params.as_slice(),
            ),
            (
                "Equals",
                TypeSigOrVoid::Type(TypeSig::Boolean),
                [TypeSig::Object]
            ) | ("GetHashCode", TypeSigOrVoid::Type(TypeSig::I4), [])
                | ("ToString", TypeSigOrVoid::Type(TypeSig::String), [])
        )
    }

    fn is_corelib_value_type_parent(&self, parent: RowRef) -> bool {
        match parent.table {
            TableId::TypeDef => self.type_def_is_corelib_value_root(parent.row),
            TableId::TypeRef => self.type_ref_is_corelib_value_root(parent.row),
            _ => false,
        }
    }

    fn type_def_is_corelib_value_root(&self, rid: u32) -> bool {
        if !self.is_corelib_definition_assembly() {
            return false;
        }
        let Some(index): Option<usize> = rid
            .checked_sub(1)
            .and_then(|row: u32| usize::try_from(row).ok())
        else {
            return false;
        };
        let Some(type_def): Option<&TypeDefRow> = self.tables.type_defs.get(index) else {
            return false;
        };
        self.string(type_def.namespace) == "System"
            && matches!(self.string(type_def.name).as_str(), "ValueType" | "Enum")
    }

    fn type_ref_is_corelib_value_root(&self, rid: u32) -> bool {
        let Some(index): Option<usize> = rid
            .checked_sub(1)
            .and_then(|row: u32| usize::try_from(row).ok())
        else {
            return false;
        };
        let Some(type_ref): Option<&TypeRefRow> = self.tables.type_refs.get(index) else {
            return false;
        };
        self.string(type_ref.namespace) == "System"
            && matches!(self.string(type_ref.name).as_str(), "ValueType" | "Enum")
            && type_ref
                .resolution_scope
                .is_some_and(|scope: RowRef| self.is_corelib_assembly_ref(scope))
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
    pub fn isinst_target_kind(&self, token: u32) -> IsInstTargetKind {
        self.csharp_type_target(token)
            .map_or(IsInstTargetKind::Unsupported, |target: CSharpTypeTarget| {
                Self::isinst_target_kind_for_csharp_type(&target)
            })
    }

    #[must_use]
    pub fn unbox_any_target_name(&self, token: u32) -> Option<String> {
        self.csharp_type_target(token)
            .map(|target: CSharpTypeTarget| target.rendered)
    }

    fn csharp_type_target(&self, token: u32) -> Option<CSharpTypeTarget> {
        let table: TableId = token_table(token)?;
        let rid: u32 = token_rid(token)?;
        match table {
            TableId::TypeDef => {
                (self.csharp_named_type_arity(token) == Some(0)).then_some(())?;
                let rendered: String = self.type_def_name(rid)?;
                let category: CSharpTypeCategory = if self.type_is_value_type(rid) {
                    CSharpTypeCategory::ValueType
                } else {
                    CSharpTypeCategory::ReferenceType
                };
                Some(CSharpTypeTarget {
                    rendered,
                    category,
                    nullable: false,
                })
            }
            TableId::TypeRef => {
                (self.csharp_named_type_arity(token) == Some(0)).then_some(())?;
                Some(CSharpTypeTarget {
                    rendered: self.type_ref_name(rid)?,
                    category: CSharpTypeCategory::Unknown,
                    nullable: false,
                })
            }
            TableId::TypeSpec => self
                .type_spec_signature(rid)
                .as_ref()
                .and_then(|signature: &TypeSig| self.csharp_type_target_from_signature(signature)),
            _ => None,
        }
    }

    #[cfg(test)]
    fn isinst_target_kind_from_signature(&self, signature: &TypeSig) -> IsInstTargetKind {
        self.csharp_type_target_from_signature(signature)
            .map_or(IsInstTargetKind::Unsupported, |target: CSharpTypeTarget| {
                Self::isinst_target_kind_for_csharp_type(&target)
            })
    }

    #[cfg(test)]
    fn unbox_any_target_name_from_signature(&self, signature: &TypeSig) -> Option<String> {
        self.csharp_type_target_from_signature(signature)
            .map(|target: CSharpTypeTarget| target.rendered)
    }

    const fn isinst_target_kind_for_csharp_type(target: &CSharpTypeTarget) -> IsInstTargetKind {
        if target.nullable {
            return IsInstTargetKind::Unsupported;
        }
        match target.category {
            CSharpTypeCategory::ValueType => IsInstTargetKind::ValueType,
            CSharpTypeCategory::ReferenceType => IsInstTargetKind::ReferenceType,
            CSharpTypeCategory::Unknown => IsInstTargetKind::RenderableUnknown,
        }
    }

    fn csharp_type_target_from_signature(&self, signature: &TypeSig) -> Option<CSharpTypeTarget> {
        if !self.csharp_signature_is_renderable(signature) {
            return None;
        }
        let (category, nullable): (CSharpTypeCategory, bool) = match signature {
            TypeSig::Boolean
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
            | TypeSig::IntPtr
            | TypeSig::UIntPtr => (CSharpTypeCategory::ValueType, false),
            TypeSig::String | TypeSig::Object | TypeSig::SzArray(_) | TypeSig::Array { .. } => {
                (CSharpTypeCategory::ReferenceType, false)
            }
            TypeSig::NamedType { is_value_type, .. } => {
                if *is_value_type {
                    (CSharpTypeCategory::ValueType, false)
                } else {
                    (CSharpTypeCategory::ReferenceType, false)
                }
            }
            TypeSig::GenericInst { base, .. } => match base.as_ref() {
                TypeSig::NamedType {
                    is_value_type,
                    token,
                } => {
                    if *is_value_type {
                        (
                            CSharpTypeCategory::ValueType,
                            self.isinst_nullable_type(*token),
                        )
                    } else {
                        (
                            CSharpTypeCategory::ReferenceType,
                            self.isinst_nullable_type(*token),
                        )
                    }
                }
                _ => return None,
            },
            TypeSig::Void
            | TypeSig::TypedByRef
            | TypeSig::Ptr(_)
            | TypeSig::ByRef(_)
            | TypeSig::Pinned(_)
            | TypeSig::Var(_)
            | TypeSig::MVar(_)
            | TypeSig::FnPtr
            | TypeSig::Unknown => return None,
        };
        Some(CSharpTypeTarget {
            rendered: self.render_type(signature, TargetLang::CSharp),
            category,
            nullable,
        })
    }

    fn isinst_nullable_type(&self, token: u32) -> bool {
        let Some(table): Option<TableId> = token_table(token) else {
            return false;
        };
        let Some(rid): Option<u32> = token_rid(token) else {
            return false;
        };
        let name: Option<String> = match table {
            TableId::TypeDef => self.type_def_name(rid),
            TableId::TypeRef => self.type_ref_name(rid),
            _ => None,
        };
        name.is_some_and(|value: String| value == "System.Nullable")
    }

    fn csharp_signature_is_renderable(&self, signature: &TypeSig) -> bool {
        match signature {
            TypeSig::Boolean
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
            | TypeSig::Object => true,
            TypeSig::NamedType { token, .. } => self.csharp_named_type_arity(*token) == Some(0),
            TypeSig::SzArray(element) => self.csharp_signature_is_renderable(element),
            TypeSig::Array { element, rank } => {
                (2..=32).contains(rank) && self.csharp_signature_is_renderable(element)
            }
            TypeSig::GenericInst { base, args } => {
                let TypeSig::NamedType { token, .. } = base.as_ref() else {
                    return false;
                };
                self.csharp_named_type_arity(*token) == Some(args.len())
                    && args
                        .iter()
                        .all(|arg: &TypeSig| self.csharp_signature_is_renderable(arg))
            }
            TypeSig::Void
            | TypeSig::TypedByRef
            | TypeSig::Ptr(_)
            | TypeSig::ByRef(_)
            | TypeSig::Pinned(_)
            | TypeSig::Var(_)
            | TypeSig::MVar(_)
            | TypeSig::FnPtr
            | TypeSig::Unknown => false,
        }
    }

    fn csharp_named_type_arity(&self, token: u32) -> Option<usize> {
        let table: TableId = token_table(token)?;
        let rid: u32 = token_rid(token)?;
        let index: usize = rid
            .checked_sub(1)
            .and_then(|value: u32| usize::try_from(value).ok())?;
        match table {
            TableId::TypeDef => {
                let row: &TypeDefRow = self.tables.type_defs.get(index)?;
                let arity: usize = type_name_arity(&self.string(row.name))?;
                let generic_params: usize = self
                    .tables
                    .generic_params
                    .iter()
                    .filter(|parameter: &&GenericParamRow| {
                        parameter.owner.is_some_and(|owner: RowRef| {
                            owner.table == TableId::TypeDef && owner.row == rid
                        })
                    })
                    .count();
                let rendered: String = self.type_def_name(rid)?;
                (arity == generic_params && csharp_type_name_is_renderable(&rendered))
                    .then_some(arity)
            }
            TableId::TypeRef => {
                let row: &TypeRefRow = self.tables.type_refs.get(index)?;
                if row
                    .resolution_scope
                    .is_some_and(|scope: RowRef| scope.table == TableId::TypeRef)
                {
                    return None;
                }
                let arity: usize = type_name_arity(&self.string(row.name))?;
                let rendered: String = self.type_ref_name(rid)?;
                csharp_type_name_is_renderable(&rendered).then_some(arity)
            }
            _ => None,
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
        let token: u32 = (u32::from(TableId::TypeRef.index()) << 24) | rid;
        if let Some(rendered) = self.render_nested_type_ref(token, &[], TargetLang::CSharp) {
            return Some(rendered);
        }
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
        let sig: TypeSig = self.type_spec_signature(rid)?;
        Some(self.substitute_type_tokens(&sig.render()))
    }

    fn type_spec_signature(&self, rid: u32) -> Option<TypeSig> {
        let index: usize = rid
            .checked_sub(1)
            .and_then(|value: u32| usize::try_from(value).ok())?;
        let row: &TypeSpecRow = self.tables.type_specs.get(index)?;
        let blob: &[u8] = self.blob(row.signature)?;
        crate::signature::parse_type_spec_sig(blob).ok()
    }

    fn type_spec_signature_strict(&self, rid: u32) -> Option<TypeSig> {
        let index: usize = rid
            .checked_sub(1)
            .and_then(|value: u32| usize::try_from(value).ok())?;
        let row: &TypeSpecRow = self.tables.type_specs.get(index)?;
        let blob: &[u8] = self.blob(row.signature)?;
        crate::signature::parse_type_spec_sig_strict(blob).ok()
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
            && let Some(rendered) = self.render_nested_type_ref(*token, args, lang)
        {
            return rendered;
        }
        self.substitute_type_tokens(&sig.render_in(lang))
    }

    fn type_ref_nesting_chain(&self, rid: u32) -> Option<Vec<(String, String)>> {
        let mut chain: Vec<(String, String)> = Vec::new();
        let mut visited: BTreeSet<u32> = BTreeSet::new();
        let mut cur: u32 = rid;
        loop {
            if chain.len() >= 16 || !visited.insert(cur) {
                return None;
            }
            let row: &crate::tables::TypeRefRow =
                self.tables.type_refs.get(cur.checked_sub(1)? as usize)?;
            chain.push((self.string(row.namespace), self.string(row.name)));
            match row.resolution_scope {
                Some(scope) if scope.table == TableId::TypeRef => cur = scope.row,
                _ => break,
            }
        }
        chain.reverse();
        Some(chain)
    }

    fn render_nested_type_ref(
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
    pub fn csharp_anonymous_object_member_names(&self, token: u32) -> Option<Vec<String>> {
        let member_ref_rid: u32 = token_rid(token)?;
        (token_table(token) == Some(TableId::MemberRef)).then_some(())?;
        let member_ref: &MemberRefRow = self
            .tables
            .member_refs
            .get(member_ref_rid.checked_sub(1)? as usize)?;
        (self.string(member_ref.name) == ".ctor").then_some(())?;
        let parent: RowRef = member_ref.parent?;
        (parent.table == TableId::TypeSpec).then_some(())?;
        let signature: TypeSig = self.type_spec_signature_strict(parent.row)?;
        let TypeSig::GenericInst { base, args } = signature else {
            return None;
        };
        let TypeSig::NamedType {
            is_value_type,
            token: type_token,
        } = base.as_ref()
        else {
            return None;
        };
        (!is_value_type).then_some(())?;
        let type_rid: u32 = token_rid(*type_token)?;
        (token_table(*type_token) == Some(TableId::TypeDef)).then_some(())?;
        let type_def: &TypeDefRow = self
            .tables
            .type_defs
            .get(type_rid.checked_sub(1)? as usize)?;
        (type_def.flags == ANONYMOUS_TYPE_FLAGS && self.string(type_def.namespace).is_empty())
            .then_some(())?;
        (!self
            .tables
            .nested_classes
            .iter()
            .any(|nested: &crate::tables::NestedClassRow| nested.nested_class == type_rid))
        .then_some(())?;
        let base_type: RowRef = type_def.extends?;
        let base_type_index: usize = base_type
            .row
            .checked_sub(1)
            .and_then(|row: u32| usize::try_from(row).ok())?;
        let base_type_ref: &TypeRefRow = (base_type.table == TableId::TypeRef)
            .then(|| self.tables.type_refs.get(base_type_index))
            .flatten()?;
        (self.string(base_type_ref.namespace) == "System"
            && self.string(base_type_ref.name) == "Object"
            && base_type_ref
                .resolution_scope
                .is_some_and(|scope: RowRef| self.is_corelib_assembly_ref(scope)))
        .then_some(())?;
        let type_name: String = self.string(type_def.name);
        let (stem, arity): (&str, &str) = type_name.rsplit_once('`')?;
        let ordinal: &str = stem.strip_prefix("<>f__AnonymousType")?;
        (!ordinal.is_empty() && ordinal.bytes().all(|byte: u8| byte.is_ascii_digit()))
            .then_some(())?;
        let arity: usize = arity.parse().ok()?;
        (arity != 0 && arity == args.len() && self.type_has_compiler_generated_attribute(type_rid))
            .then_some(())?;
        let member_ref_signature: MethodSig =
            parse_method_sig_strict(self.blob(member_ref.signature)?).ok()?;
        (member_ref_signature.has_this
            && member_ref_signature.calling_convention == (SIG_HASTHIS | SIG_DEFAULT)
            && !member_ref_signature.explicit_this
            && member_ref_signature.generic_param_count == 0
            && matches!(member_ref_signature.return_type, TypeSigOrVoid::Void)
            && member_ref_signature.params.len() == arity)
            .then_some(())?;
        let mut generic_params: Vec<(u16, u16, String)> = self
            .tables
            .generic_params
            .iter()
            .filter(|parameter: &&GenericParamRow| {
                parameter.owner.is_some_and(|owner: RowRef| {
                    owner.table == TableId::TypeDef && owner.row == type_rid
                })
            })
            .map(|parameter: &GenericParamRow| {
                (
                    parameter.number,
                    parameter.flags,
                    self.string(parameter.name),
                )
            })
            .collect();
        generic_params.sort_by_key(|(number, _, _): &(u16, u16, String)| *number);
        (generic_params.len() == arity
            && generic_params.iter().enumerate().all(
                |(index, (number, flags, _)): (usize, &(u16, u16, String))| {
                    usize::from(*number) == index && *flags == 0
                },
            ))
        .then_some(())?;
        let member_names: Vec<String> = generic_params
            .into_iter()
            .map(|(_, _, name): (u16, u16, String)| {
                name.strip_prefix('<')?
                    .strip_suffix(">j__TPar")
                    .filter(|member: &&str| is_simple_identifier(member))
                    .map(str::to_owned)
            })
            .collect::<Option<Vec<String>>>()?;
        let unique: BTreeSet<&str> = member_names.iter().map(String::as_str).collect();
        (unique.len() == member_names.len()).then_some(())?;
        (!self
            .tables
            .interface_impls
            .iter()
            .any(|implementation: &InterfaceImplRow| implementation.class_type == type_rid)
            && !self.tables.method_impls.iter().any(
                |implementation: &crate::tables::MethodImplRow| {
                    implementation.class_type == type_rid
                },
            ))
        .then_some(())?;
        self.validate_anonymous_type_fields(type_rid, &member_names)?;
        let (method_start, method_end): (u32, u32) = self.method_range(type_rid)?;
        let constructors: Vec<(u32, &MethodDefRow)> = (method_start..method_end)
            .filter_map(|rid: u32| {
                self.tables
                    .methods
                    .get(rid.checked_sub(1)? as usize)
                    .filter(|method: &&MethodDefRow| self.string(method.name) == ".ctor")
                    .map(|method: &MethodDefRow| (rid, method))
            })
            .collect();
        let [(constructor_rid, constructor)]: &[(u32, &MethodDefRow)] = constructors.as_slice()
        else {
            return None;
        };
        let constructor_signature: MethodSig =
            parse_method_sig_strict(self.blob(constructor.signature)?).ok()?;
        (constructor.flags == ANONYMOUS_CONSTRUCTOR_FLAGS
            && constructor.impl_flags == 0
            && constructor_signature.calling_convention == (SIG_HASTHIS | SIG_DEFAULT)
            && constructor_signature.has_this
            && !constructor_signature.explicit_this
            && constructor_signature.generic_param_count == 0
            && matches!(constructor_signature.return_type, TypeSigOrVoid::Void)
            && constructor_signature.params.len() == arity
            && constructor_signature.params == member_ref_signature.params
            && constructor_signature
                .params
                .iter()
                .enumerate()
                .all(|(index, parameter): (usize, &TypeSig)| {
                    matches!(parameter, TypeSig::Var(number) if usize::try_from(*number).ok() == Some(index))
                }))
        .then_some(())?;
        let mut parameters: Vec<ParamModel> = self
            .materialize_params(*constructor_rid)
            .into_iter()
            .filter(|parameter: &ParamModel| parameter.sequence != 0)
            .collect();
        self.anonymous_constructor_params_have_zero_flags(*constructor_rid)?;
        parameters.sort_by_key(|parameter: &ParamModel| parameter.sequence);
        (parameters.len() == arity
            && parameters
                .iter()
                .enumerate()
                .all(|(index, parameter): (usize, &ParamModel)| {
                    usize::from(parameter.sequence) == index + 1
                        && parameter.name == member_names[index]
                }))
        .then_some(member_names)
    }

    fn anonymous_constructor_params_have_zero_flags(&self, constructor_rid: u32) -> Option<()> {
        let constructor_index: usize = constructor_rid
            .checked_sub(1)
            .and_then(|row: u32| usize::try_from(row).ok())?;
        let constructor: &MethodDefRow = self.tables.methods.get(constructor_index)?;
        let start: u32 = constructor.param_list;
        let end: u32 = self
            .tables
            .methods
            .get(constructor_index.checked_add(1)?)
            .map_or_else(
                || {
                    u32::try_from(self.tables.params.len())
                        .ok()
                        .and_then(|count: u32| count.checked_add(1))
                },
                |next: &MethodDefRow| Some(next.param_list),
            )?;
        (start..end)
            .map(|rid: u32| {
                rid.checked_sub(1)
                    .and_then(|row: u32| usize::try_from(row).ok())
                    .and_then(|index: usize| self.tables.params.get(index))
            })
            .collect::<Option<Vec<&crate::tables::ParamRow>>>()?
            .into_iter()
            .filter(|parameter: &&crate::tables::ParamRow| parameter.sequence != 0)
            .all(|parameter: &crate::tables::ParamRow| parameter.flags == 0)
            .then_some(())
    }

    fn validate_anonymous_type_fields(&self, type_rid: u32, member_names: &[String]) -> Option<()> {
        let type_index: usize = type_rid
            .checked_sub(1)
            .and_then(|row: u32| usize::try_from(row).ok())?;
        let type_def: &TypeDefRow = self.tables.type_defs.get(type_index)?;
        let field_start: u32 = type_def.field_list;
        let field_end: u32 = self
            .tables
            .type_defs
            .get(type_index.checked_add(1)?)
            .map_or_else(
                || {
                    u32::try_from(self.tables.fields.len())
                        .ok()
                        .and_then(|count: u32| count.checked_add(1))
                },
                |next: &TypeDefRow| Some(next.field_list),
            )?;
        let fields: Vec<&FieldRow> = (field_start..field_end)
            .map(|rid: u32| {
                rid.checked_sub(1)
                    .and_then(|row: u32| usize::try_from(row).ok())
                    .and_then(|index: usize| self.tables.fields.get(index))
            })
            .collect::<Option<Vec<&FieldRow>>>()?;
        (fields.len() == member_names.len()
            && fields.iter().enumerate().all(
                |(index, field): (usize, &&FieldRow)| {
                    field.flags == FIELD_PRIVATE_INIT_ONLY
                        && self.string(field.name) == format!("<{}>i__Field", member_names[index])
                        && self
                            .blob(field.signature)
                            .and_then(|blob: &[u8]| parse_field_sig_strict(blob).ok())
                            .is_some_and(|signature: TypeSig| {
                                matches!(signature, TypeSig::Var(number) if usize::try_from(number).ok() == Some(index))
                            })
                },
            ))
        .then_some(())
    }

    fn type_has_compiler_generated_attribute(&self, type_rid: u32) -> bool {
        self.tables
            .custom_attributes
            .iter()
            .filter(|attribute: &&crate::tables::CustomAttributeRow| {
                attribute.parent.is_some_and(|parent: RowRef| {
                    parent.table == TableId::TypeDef && parent.row == type_rid
                })
            })
            .any(|attribute: &crate::tables::CustomAttributeRow| {
                self.blob(attribute.value) == Some([0x01, 0x00, 0x00, 0x00].as_slice())
                    && attribute.attr_type.is_some_and(|constructor: RowRef| {
                        self.is_compiler_generated_attribute_constructor(constructor)
                    })
            })
    }

    fn is_compiler_generated_attribute_constructor(&self, constructor: RowRef) -> bool {
        if constructor.table != TableId::MemberRef {
            return false;
        }
        let Some(member_index): Option<usize> = constructor
            .row
            .checked_sub(1)
            .and_then(|row: u32| usize::try_from(row).ok())
        else {
            return false;
        };
        let Some(member): Option<&MemberRefRow> = self.tables.member_refs.get(member_index) else {
            return false;
        };
        let Some(signature): Option<MethodSig> = self
            .blob(member.signature)
            .and_then(|blob: &[u8]| parse_method_sig_strict(blob).ok())
        else {
            return false;
        };
        if self.string(member.name) != ".ctor"
            || signature.calling_convention != (SIG_HASTHIS | SIG_DEFAULT)
            || !signature.has_this
            || signature.explicit_this
            || signature.generic_param_count != 0
            || !matches!(signature.return_type, TypeSigOrVoid::Void)
            || !signature.params.is_empty()
        {
            return false;
        }
        let Some(owner): Option<RowRef> = member.parent else {
            return false;
        };
        if owner.table != TableId::TypeRef {
            return false;
        }
        let Some(owner_index): Option<usize> = owner
            .row
            .checked_sub(1)
            .and_then(|row: u32| usize::try_from(row).ok())
        else {
            return false;
        };
        let Some(row): Option<&TypeRefRow> = self.tables.type_refs.get(owner_index) else {
            return false;
        };
        self.string(row.namespace) == "System.Runtime.CompilerServices"
            && self.string(row.name) == "CompilerGeneratedAttribute"
            && row
                .resolution_scope
                .is_some_and(|scope: RowRef| self.is_corelib_assembly_ref(scope))
    }

    #[must_use]
    pub fn metadata_token_kind(&self, token: u32) -> MetadataTokenKind {
        let table_idx: u8 = u8::try_from(token >> 24).unwrap_or(0xFF);
        let Some(table): Option<TableId> = TableId::from_index(table_idx) else {
            return MetadataTokenKind::Unknown;
        };
        let Some(rid): Option<usize> = (token & 0x00FF_FFFF)
            .checked_sub(1)
            .map(|value: u32| value as usize)
        else {
            return MetadataTokenKind::Unknown;
        };
        match table {
            TableId::TypeRef if self.tables.type_refs.get(rid).is_some() => MetadataTokenKind::Type,
            TableId::TypeDef if self.tables.type_defs.get(rid).is_some() => MetadataTokenKind::Type,
            TableId::TypeSpec if self.tables.type_specs.get(rid).is_some() => {
                MetadataTokenKind::Type
            }
            TableId::Field if self.tables.fields.get(rid).is_some() => MetadataTokenKind::Field,
            TableId::MethodDef if self.tables.methods.get(rid).is_some() => {
                MetadataTokenKind::Method
            }
            TableId::MethodSpec if self.tables.method_specs.get(rid).is_some() => {
                MetadataTokenKind::Method
            }
            TableId::MemberRef => {
                let Some(row): Option<&MemberRefRow> = self.tables.member_refs.get(rid) else {
                    return MetadataTokenKind::Unknown;
                };
                let Some(blob): Option<&[u8]> = self.blob(row.signature) else {
                    return MetadataTokenKind::Unknown;
                };
                if parse_field_sig_strict(blob).is_ok() {
                    MetadataTokenKind::Field
                } else if parse_method_sig_strict(blob).is_ok() {
                    MetadataTokenKind::Method
                } else {
                    MetadataTokenKind::Unknown
                }
            }
            _ => MetadataTokenKind::Unknown,
        }
    }

    #[must_use]
    pub(crate) fn field_rva_primitive_from_type_ref(
        &self,
        token: u32,
    ) -> Option<FieldRvaPrimitive> {
        let table_index: u8 = u8::try_from(token >> 24).ok()?;
        if TableId::from_index(table_index) != Some(TableId::TypeRef) {
            return None;
        }
        let type_ref_index: usize = usize::try_from((token & 0x00FF_FFFF).checked_sub(1)?).ok()?;
        let type_ref: &TypeRefRow = self.tables.type_refs.get(type_ref_index)?;
        if self.string(type_ref.namespace) != "System" {
            return None;
        }
        let scope: RowRef = type_ref.resolution_scope?;
        if !self.is_corelib_assembly_ref(scope) {
            return None;
        }
        match self.string(type_ref.name).as_str() {
            "Boolean" => Some(FieldRvaPrimitive::Boolean),
            "Char" => Some(FieldRvaPrimitive::Char),
            "SByte" => Some(FieldRvaPrimitive::I1),
            "Byte" => Some(FieldRvaPrimitive::U1),
            "Int16" => Some(FieldRvaPrimitive::I2),
            "UInt16" => Some(FieldRvaPrimitive::U2),
            "Int32" => Some(FieldRvaPrimitive::I4),
            "UInt32" => Some(FieldRvaPrimitive::U4),
            "Int64" => Some(FieldRvaPrimitive::I8),
            "UInt64" => Some(FieldRvaPrimitive::U8),
            _ => None,
        }
    }

    fn is_corelib_assembly_ref(&self, scope: RowRef) -> bool {
        if scope.table != TableId::AssemblyRef || scope.row == 0 {
            return false;
        }
        let Some(index): Option<usize> = scope
            .row
            .checked_sub(1)
            .and_then(|row: u32| usize::try_from(row).ok())
        else {
            return false;
        };
        let Some(assembly) = self.tables.assembly_refs.get(index) else {
            return false;
        };
        let Some(public_key_or_token): Option<&[u8]> = self.blob(assembly.public_key_or_token)
        else {
            return false;
        };
        let Some(public_key_token): Option<[u8; 8]> =
            assembly_public_key_token(public_key_or_token, assembly.flags)
        else {
            return false;
        };
        let name: String = self.string(assembly.name);
        Self::is_corelib_identity(&name, public_key_token)
    }

    fn is_corelib_definition_assembly(&self) -> bool {
        let Some(assembly) = self.tables.assembly.as_ref() else {
            return false;
        };
        if assembly.flags & ASSEMBLY_REF_PUBLIC_KEY == 0 {
            return false;
        }
        let Some(public_key): Option<&[u8]> = self.blob(assembly.public_key) else {
            return false;
        };
        let Some(public_key_token): Option<[u8; 8]> =
            assembly_public_key_token(public_key, assembly.flags)
        else {
            return false;
        };
        let name: String = self.string(assembly.name);
        Self::is_corelib_definition_identity(&name, public_key_token)
    }

    fn is_corelib_identity(name: &str, public_key_token: [u8; 8]) -> bool {
        matches!(
            (name, public_key_token),
            ("mscorlib", [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89])
                | (
                    "System.Runtime",
                    [0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A]
                )
                | (
                    "netstandard",
                    [0xCC, 0x7B, 0x13, 0xFF, 0xCD, 0x2D, 0xDD, 0x51]
                )
                | (
                    "System.Private.CoreLib",
                    [0x7C, 0xEC, 0x85, 0xD7, 0xBE, 0xA7, 0x79, 0x8E]
                )
        )
    }

    fn is_corelib_definition_identity(name: &str, public_key_token: [u8; 8]) -> bool {
        matches!(
            (name, public_key_token),
            ("mscorlib", [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89])
                | (
                    "System.Private.CoreLib",
                    [0x7C, 0xEC, 0x85, 0xD7, 0xBE, 0xA7, 0x79, 0x8E]
                )
        )
    }

    #[must_use]
    pub(crate) fn strict_field_signature(&self, blob_index: u32) -> Option<TypeSig> {
        parse_field_sig_strict(self.blob(blob_index)?).ok()
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

const ASSEMBLY_REF_PUBLIC_KEY: u32 = 0x0001;

fn assembly_public_key_token(public_key_or_token: &[u8], flags: u32) -> Option<[u8; 8]> {
    if flags & ASSEMBLY_REF_PUBLIC_KEY == 0 {
        return public_key_or_token.try_into().ok();
    }
    let digest: [u8; 20] = crate::peel::dotnet_crypto::sha1_digest(public_key_or_token);
    let mut token: [u8; 8] = [0u8; 8];
    for (index, byte) in digest[12..].iter().rev().enumerate() {
        *token.get_mut(index)? = *byte;
    }
    Some(token)
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

fn type_name_arity(name: &str) -> Option<usize> {
    let (base, arity): (&str, usize) = match name.split_once('`') {
        Some((base, suffix)) => (
            base,
            suffix.parse::<usize>().ok().filter(|arity| *arity != 0)?,
        ),
        None => (name, 0),
    };
    (is_simple_identifier(base) && csharp_escape_identifier(base) == base).then_some(arity)
}

fn csharp_type_name_is_renderable(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|segment: &str| {
            is_simple_identifier(segment) && csharp_escape_identifier(segment) == segment
        })
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

    fn push_heap_string(heap: &mut Vec<u8>, value: &str) -> u32 {
        let index: u32 = u32::try_from(heap.len()).expect("string heap index");
        heap.extend_from_slice(value.as_bytes());
        heap.push(0);
        index
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
    fn type_ref_nesting_chain_rejects_cycles() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let outer: usize = resolver
            .tables
            .type_refs
            .iter()
            .position(|row: &TypeRefRow| {
                resolver.string(row.name) == "ConfiguredValueTaskAwaitable"
            })
            .expect("ConfiguredValueTaskAwaitable TypeRef");
        let nested: usize = resolver
            .tables
            .type_refs
            .iter()
            .position(|row: &TypeRefRow| resolver.string(row.name) == "ConfiguredValueTaskAwaiter")
            .expect("ConfiguredValueTaskAwaiter TypeRef");
        let outer_rid: u32 = u32::try_from(outer + 1).expect("outer TypeRef rid");
        let nested_rid: u32 = u32::try_from(nested + 1).expect("nested TypeRef rid");
        resolver.tables.type_refs[outer].resolution_scope = Some(RowRef {
            table: TableId::TypeRef,
            row: nested_rid,
        });
        resolver.tables.type_refs[nested].resolution_scope = Some(RowRef {
            table: TableId::TypeRef,
            row: outer_rid,
        });

        assert_eq!(resolver.type_ref_nesting_chain(nested_rid), None);
    }

    #[test]
    fn full_assembly_public_key_normalizes_to_its_known_token() {
        let key: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let token: [u8; 8] = [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89];
        assert_eq!(
            assembly_public_key_token(&key, ASSEMBLY_REF_PUBLIC_KEY),
            Some(token)
        );
        assert_eq!(assembly_public_key_token(&token, 0), Some(token));
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
            method_impl_indices_by_type: BTreeMap::new(),
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

    #[test]
    fn isinst_target_kind_uses_typedef_metadata_and_safe_typeref_patterns() {
        let resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let model: AssemblyModel = resolver.model();
        let money: &TypeModel = model
            .types
            .iter()
            .find(|ty: &&TypeModel| ty.full_name == "EdgeCases.Money")
            .expect("Money TypeDef");
        let event_source: &TypeModel = model
            .types
            .iter()
            .find(|ty: &&TypeModel| ty.full_name == "EdgeCases.EventSource")
            .expect("EventSource TypeDef");
        assert_eq!(
            resolver.isinst_target_kind(money.token),
            IsInstTargetKind::ValueType
        );
        assert_eq!(
            resolver.isinst_target_kind(event_source.token),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind((u32::from(TableId::TypeRef as u8) << 24) | 1),
            IsInstTargetKind::RenderableUnknown
        );
        assert_eq!(
            resolver.isinst_target_kind(0),
            IsInstTargetKind::Unsupported
        );
    }

    #[test]
    fn csharp_value_type_overrides_require_the_verified_corelib_contract() {
        let resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let model: AssemblyModel = resolver.model();
        let money: &TypeModel = model
            .types
            .iter()
            .find(|ty: &&TypeModel| ty.full_name == "EdgeCases.Money")
            .expect("Money TypeDef");
        let object_equals: &MethodModel = money
            .methods
            .iter()
            .find(|method: &&MethodModel| {
                method.display_name() == "Equals" && method.signature.params == [TypeSig::Object]
            })
            .expect("Money.Equals(object)");
        let get_hash_code: &MethodModel = money
            .methods
            .iter()
            .find(|method: &&MethodModel| method.display_name() == "GetHashCode")
            .expect("Money.GetHashCode");
        let to_string: &MethodModel = money
            .methods
            .iter()
            .find(|method: &&MethodModel| method.display_name() == "ToString")
            .expect("Money.ToString");
        let value_equals: &MethodModel = money
            .methods
            .iter()
            .find(|method: &&MethodModel| {
                method.display_name() == "Equals" && method.signature.params != [TypeSig::Object]
            })
            .expect("Money.Equals(Money)");

        for method in [object_equals, get_hash_code, to_string] {
            assert_eq!(
                resolver.csharp_value_type_override_kind(money.token, method.token),
                Some(CSharpOverrideKind::Override),
                "{}",
                method.name
            );
            assert!(
                method
                    .csharp_signature_with_override(Some(CSharpOverrideKind::Override))
                    .contains(" override "),
                "{}",
                method.name
            );
        }
        assert_eq!(
            resolver.csharp_value_type_override_kind(money.token, value_equals.token),
            None
        );
    }

    fn money_method_tokens(resolver: &Resolver) -> (u32, u32, u32, u32) {
        let model: AssemblyModel = resolver.model();
        let money: &TypeModel = model
            .types
            .iter()
            .find(|ty: &&TypeModel| ty.full_name == "EdgeCases.Money")
            .expect("Money TypeDef");
        let object_equals: &MethodModel = money
            .methods
            .iter()
            .find(|method: &&MethodModel| {
                method.display_name() == "Equals" && method.signature.params == [TypeSig::Object]
            })
            .expect("Money.Equals(object)");
        let value_equals: &MethodModel = money
            .methods
            .iter()
            .find(|method: &&MethodModel| {
                method.display_name() == "Equals" && method.signature.params != [TypeSig::Object]
            })
            .expect("Money.Equals(Money)");
        let get_hash_code: &MethodModel = money
            .methods
            .iter()
            .find(|method: &&MethodModel| method.display_name() == "GetHashCode")
            .expect("Money.GetHashCode");
        (
            money.token,
            object_equals.token,
            value_equals.token,
            get_hash_code.token,
        )
    }

    fn token_row_index(token: u32) -> usize {
        let rid: u32 = token_rid(token).expect("metadata row id");
        usize::try_from(rid - 1).expect("metadata row index")
    }

    fn add_method_impl_mapping(resolver: &mut Resolver, mapping: crate::tables::MethodImplRow) {
        let index: usize = resolver.tables.method_impls.len();
        resolver
            .method_impl_indices_by_type
            .entry(mapping.class_type)
            .or_default()
            .push(index);
        resolver.tables.method_impls.push(mapping);
    }

    fn add_object_method_declaration(resolver: &mut Resolver, method_token: u32) -> RowRef {
        let method_index: usize = token_row_index(method_token);
        let (name, signature): (u32, u32) = {
            let method: &MethodDefRow = resolver
                .tables
                .methods
                .get(method_index)
                .expect("Money MethodDef row");
            (method.name, method.signature)
        };
        let object_type_ref_index: usize = resolver
            .tables
            .type_refs
            .iter()
            .position(|type_ref: &TypeRefRow| {
                resolver.string(type_ref.namespace) == "System"
                    && resolver.string(type_ref.name) == "Object"
            })
            .expect("System.Object TypeRef");
        resolver
            .tables
            .member_refs
            .push(crate::tables::MemberRefRow {
                parent: Some(RowRef {
                    table: TableId::TypeRef,
                    row: u32::try_from(object_type_ref_index + 1).expect("Object TypeRef rid"),
                }),
                name,
                signature,
            });
        RowRef {
            table: TableId::MemberRef,
            row: u32::try_from(resolver.tables.member_refs.len()).expect("MemberRef rid"),
        }
    }

    fn add_local_method_reference(
        resolver: &mut Resolver,
        declaring_type_token: u32,
        method_token: u32,
    ) -> RowRef {
        let method_index: usize = token_row_index(method_token);
        let method: &MethodDefRow = resolver
            .tables
            .methods
            .get(method_index)
            .expect("local MethodDef row");
        resolver
            .tables
            .member_refs
            .push(crate::tables::MemberRefRow {
                parent: Some(RowRef {
                    table: TableId::TypeDef,
                    row: token_rid(declaring_type_token).expect("declaring TypeDef rid"),
                }),
                name: method.name,
                signature: method.signature,
            });
        RowRef {
            table: TableId::MemberRef,
            row: u32::try_from(resolver.tables.member_refs.len()).expect("MemberRef rid"),
        }
    }

    fn add_unresolved_type_ref_method_reference(
        resolver: &mut Resolver,
        method_token: u32,
    ) -> RowRef {
        let method_index: usize = token_row_index(method_token);
        let method: &MethodDefRow = resolver
            .tables
            .methods
            .get(method_index)
            .expect("local MethodDef row");
        resolver
            .tables
            .member_refs
            .push(crate::tables::MemberRefRow {
                parent: Some(RowRef {
                    table: TableId::TypeRef,
                    row: u32::MAX,
                }),
                name: method.name,
                signature: method.signature,
            });
        RowRef {
            table: TableId::MemberRef,
            row: u32::try_from(resolver.tables.member_refs.len()).expect("MemberRef rid"),
        }
    }

    #[test]
    fn method_impl_index_limits_lookup_to_the_requested_class() {
        let rows: Vec<crate::tables::MethodImplRow> = vec![
            crate::tables::MethodImplRow {
                class_type: 7,
                method_body: Some(RowRef {
                    table: TableId::MethodDef,
                    row: 11,
                }),
                method_declaration: None,
            },
            crate::tables::MethodImplRow {
                class_type: 3,
                method_body: Some(RowRef {
                    table: TableId::MethodDef,
                    row: 12,
                }),
                method_declaration: None,
            },
            crate::tables::MethodImplRow {
                class_type: 7,
                method_body: Some(RowRef {
                    table: TableId::MethodDef,
                    row: 13,
                }),
                method_declaration: None,
            },
        ];
        let tables: Tables = Tables {
            method_impls: rows,
            ..Tables::default()
        };
        let method_impl_indices_by_type: BTreeMap<u32, Vec<usize>> =
            Resolver::index_method_impls_by_type(&tables.method_impls);
        let resolver: Resolver = Resolver {
            tables,
            method_impl_indices_by_type,
            strings_heap: Vec::new(),
            blob: Vec::new(),
            us: Vec::new(),
        };

        assert_eq!(resolver.method_impl_indices_for_type(7), &[0, 2]);
        assert_eq!(resolver.method_impl_indices_for_type(3), &[1]);
        assert!(resolver.method_impl_indices_for_type(99).is_empty());
        assert!(
            resolver
                .method_impl_indices_for_type(7)
                .iter()
                .all(|index: &usize| resolver.tables.method_impls[*index].class_type == 7)
        );
    }

    #[test]
    fn csharp_value_type_override_accepts_final_on_a_reused_slot() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let method_index: usize = token_row_index(object_equals_token);
        resolver
            .tables
            .methods
            .get_mut(method_index)
            .expect("Money.Equals(object) MethodDef row")
            .flags |= METHOD_FINAL;
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            Some(CSharpOverrideKind::Override)
        );
    }

    #[test]
    fn csharp_value_type_override_rejects_non_csharp_slot_flags() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let method_index: usize = token_row_index(object_equals_token);
        let original_flags: u16 = resolver
            .tables
            .methods
            .get(method_index)
            .expect("Money.Equals(object) MethodDef row")
            .flags;
        let special_name: u16 = 0x0800;
        let cases: [(&str, u16); 8] = [
            (
                "private visibility",
                (original_flags & !METHOD_ACCESS_MASK) | 0x0001,
            ),
            ("static", original_flags | METHOD_STATIC),
            ("abstract", original_flags | METHOD_ABSTRACT),
            ("special name", original_flags | special_name),
            ("new slot", original_flags | METHOD_NEW_SLOT),
            (
                "final new slot",
                original_flags | METHOD_FINAL | METHOD_NEW_SLOT,
            ),
            ("non-virtual", original_flags & !METHOD_VIRTUAL),
            (
                "not hide by signature",
                original_flags & !METHOD_HIDE_BY_SIG,
            ),
        ];
        for (case, flags) in cases {
            resolver
                .tables
                .methods
                .get_mut(method_index)
                .expect("Money.Equals(object) MethodDef row")
                .flags = flags;
            assert_eq!(
                resolver.csharp_value_type_override_kind(money_token, object_equals_token),
                None,
                "{case}"
            );
        }
    }

    #[test]
    fn csharp_value_type_override_rejects_invalid_declaring_type_shapes() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let type_index: usize = token_row_index(money_token);
        let original_flags: u32 = resolver
            .tables
            .type_defs
            .get(type_index)
            .expect("Money TypeDef row")
            .flags;
        let cases: [(&str, u32); 3] = [
            ("unsealed", original_flags & !TYPE_SEALED),
            ("abstract", original_flags | TYPE_ABSTRACT),
            ("interface", original_flags | TYPE_INTERFACE),
        ];
        for (case, flags) in cases {
            resolver
                .tables
                .type_defs
                .get_mut(type_index)
                .expect("Money TypeDef row")
                .flags = flags;
            assert_eq!(
                resolver.csharp_value_type_override_kind(money_token, object_equals_token),
                None,
                "{case}"
            );
        }
    }

    #[test]
    fn csharp_value_type_override_rejects_wrong_scope_value_type_parent() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let type_index: usize = token_row_index(money_token);
        let parent: RowRef = resolver
            .tables
            .type_defs
            .get(type_index)
            .expect("Money TypeDef row")
            .extends
            .expect("Money base type");
        assert_eq!(parent.table, TableId::TypeRef);
        let parent_index: usize =
            usize::try_from(parent.row.checked_sub(1).expect("base TypeRef rid"))
                .expect("base TypeRef index");
        let base_type_ref: &mut TypeRefRow = resolver
            .tables
            .type_refs
            .get_mut(parent_index)
            .expect("Money base TypeRef row");
        base_type_ref.resolution_scope = Some(RowRef {
            table: TableId::Module,
            row: 1,
        });
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            None
        );
    }

    #[test]
    fn csharp_value_type_override_rejects_wrong_method_owner() {
        let resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let model: AssemblyModel = resolver.model();
        let other_type_token: u32 = model
            .types
            .iter()
            .find(|ty: &&TypeModel| ty.token != money_token)
            .expect("non-Money TypeDef")
            .token;
        assert_eq!(
            resolver.csharp_value_type_override_kind(other_type_token, object_equals_token),
            None
        );
    }

    #[test]
    fn csharp_value_type_override_rejects_a_method_without_a_body() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        resolver
            .tables
            .methods
            .get_mut(token_row_index(object_equals_token))
            .expect("Money.Equals(object) MethodDef row")
            .rva = 0;
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            None
        );
    }

    #[test]
    fn csharp_value_type_override_rejects_a_non_contract_signature() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, value_equals_token, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let value_signature: u32 = resolver
            .tables
            .methods
            .get(token_row_index(value_equals_token))
            .expect("Money.Equals(Money) MethodDef row")
            .signature;
        resolver
            .tables
            .methods
            .get_mut(token_row_index(object_equals_token))
            .expect("Money.Equals(object) MethodDef row")
            .signature = value_signature;
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            None
        );
    }

    #[test]
    fn csharp_value_type_override_rejects_a_methoddef_methodimpl_body() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let declaration: RowRef = add_object_method_declaration(&mut resolver, object_equals_token);
        add_method_impl_mapping(
            &mut resolver,
            crate::tables::MethodImplRow {
                class_type: token_rid(money_token).expect("Money TypeDef rid"),
                method_body: Some(RowRef {
                    table: TableId::MethodDef,
                    row: token_rid(object_equals_token).expect("Equals MethodDef rid"),
                }),
                method_declaration: Some(declaration),
            },
        );
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            None
        );
    }

    #[test]
    fn csharp_value_type_override_ignores_an_unrelated_methodimpl_body() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, get_hash_code_token): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let declaration: RowRef = add_object_method_declaration(&mut resolver, get_hash_code_token);
        add_method_impl_mapping(
            &mut resolver,
            crate::tables::MethodImplRow {
                class_type: token_rid(money_token).expect("Money TypeDef rid"),
                method_body: Some(RowRef {
                    table: TableId::MethodDef,
                    row: token_rid(get_hash_code_token).expect("GetHashCode MethodDef rid"),
                }),
                method_declaration: Some(declaration),
            },
        );
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            Some(CSharpOverrideKind::Override)
        );
    }

    #[test]
    fn csharp_value_type_override_rejects_a_memberref_methodimpl_body() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let declaration: RowRef = add_object_method_declaration(&mut resolver, object_equals_token);
        let body: RowRef =
            add_local_method_reference(&mut resolver, money_token, object_equals_token);
        add_method_impl_mapping(
            &mut resolver,
            crate::tables::MethodImplRow {
                class_type: token_rid(money_token).expect("Money TypeDef rid"),
                method_body: Some(body),
                method_declaration: Some(declaration),
            },
        );
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            None
        );
    }

    #[test]
    fn csharp_value_type_override_rejects_an_unresolved_memberref_methodimpl_body() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let declaration: RowRef = add_object_method_declaration(&mut resolver, object_equals_token);
        add_method_impl_mapping(
            &mut resolver,
            crate::tables::MethodImplRow {
                class_type: token_rid(money_token).expect("Money TypeDef rid"),
                method_body: Some(RowRef {
                    table: TableId::MemberRef,
                    row: u32::MAX,
                }),
                method_declaration: Some(declaration),
            },
        );
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            None
        );
    }

    #[test]
    fn csharp_value_type_override_rejects_a_typeref_parent_methodimpl_body() {
        let mut resolver: Resolver =
            resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let (money_token, object_equals_token, _, _): (u32, u32, u32, u32) =
            money_method_tokens(&resolver);
        let declaration: RowRef = add_object_method_declaration(&mut resolver, object_equals_token);
        let body: RowRef =
            add_unresolved_type_ref_method_reference(&mut resolver, object_equals_token);
        add_method_impl_mapping(
            &mut resolver,
            crate::tables::MethodImplRow {
                class_type: token_rid(money_token).expect("Money TypeDef rid"),
                method_body: Some(body),
                method_declaration: Some(declaration),
            },
        );
        assert_eq!(
            resolver.csharp_value_type_override_kind(money_token, object_equals_token),
            None
        );
    }

    #[test]
    fn isinst_target_kind_requires_corelib_value_type_identity() {
        let mut strings_heap: Vec<u8> = vec![0];
        let system: u32 = push_heap_string(&mut strings_heap, "System");
        let value_type: u32 = push_heap_string(&mut strings_heap, "ValueType");
        let enum_type: u32 = push_heap_string(&mut strings_heap, "Enum");
        let object: u32 = push_heap_string(&mut strings_heap, "Object");
        let money: u32 = push_heap_string(&mut strings_heap, "Money");
        let color: u32 = push_heap_string(&mut strings_heap, "Color");
        let base: u32 = push_heap_string(&mut strings_heap, "Base");
        let derived: u32 = push_heap_string(&mut strings_heap, "Derived");
        let spoofed_money: u32 = push_heap_string(&mut strings_heap, "SpoofedMoney");
        let corelib: u32 = push_heap_string(&mut strings_heap, "System.Private.CoreLib");
        let system_runtime: u32 = push_heap_string(&mut strings_heap, "System.Runtime");
        let untrusted_money: u32 = push_heap_string(&mut strings_heap, "UntrustedMoney");
        let corelib_scope: RowRef = RowRef {
            table: TableId::AssemblyRef,
            row: 1,
        };
        let tables: Tables = Tables {
            assembly_refs: vec![
                crate::tables::AssemblyRefRow {
                    major: 0,
                    minor: 0,
                    build: 0,
                    revision: 0,
                    flags: 0,
                    public_key_or_token: 1,
                    name: corelib,
                    culture: 0,
                    hash_value: 0,
                },
                crate::tables::AssemblyRefRow {
                    major: 0,
                    minor: 0,
                    build: 0,
                    revision: 0,
                    flags: 0,
                    public_key_or_token: 10,
                    name: system_runtime,
                    culture: 0,
                    hash_value: 0,
                },
            ],
            type_refs: vec![
                TypeRefRow {
                    resolution_scope: Some(corelib_scope),
                    name: value_type,
                    namespace: system,
                },
                TypeRefRow {
                    resolution_scope: Some(corelib_scope),
                    name: enum_type,
                    namespace: system,
                },
                TypeRefRow {
                    resolution_scope: Some(corelib_scope),
                    name: object,
                    namespace: system,
                },
                TypeRefRow {
                    resolution_scope: Some(RowRef {
                        table: TableId::AssemblyRef,
                        row: 2,
                    }),
                    name: value_type,
                    namespace: system,
                },
            ],
            type_defs: vec![
                TypeDefRow {
                    flags: 0,
                    name: money,
                    namespace: 0,
                    extends: Some(RowRef {
                        table: TableId::TypeRef,
                        row: 1,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: color,
                    namespace: 0,
                    extends: Some(RowRef {
                        table: TableId::TypeRef,
                        row: 2,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: base,
                    namespace: 0,
                    extends: Some(RowRef {
                        table: TableId::TypeRef,
                        row: 3,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: derived,
                    namespace: 0,
                    extends: Some(RowRef {
                        table: TableId::TypeDef,
                        row: 3,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: value_type,
                    namespace: system,
                    extends: Some(RowRef {
                        table: TableId::TypeRef,
                        row: 3,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: spoofed_money,
                    namespace: 0,
                    extends: Some(RowRef {
                        table: TableId::TypeDef,
                        row: 5,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: untrusted_money,
                    namespace: 0,
                    extends: Some(RowRef {
                        table: TableId::TypeRef,
                        row: 4,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
            ],
            ..Tables::default()
        };
        let resolver: Resolver = Resolver {
            tables,
            method_impl_indices_by_type: BTreeMap::new(),
            strings_heap,
            blob: vec![
                0, 8, 0x7C, 0xEC, 0x85, 0xD7, 0xBE, 0xA7, 0x79, 0x8E, 8, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            us: Vec::new(),
        };
        let type_def_token: u32 = u32::from(TableId::TypeDef as u8) << 24;
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 2),
            IsInstTargetKind::ValueType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 6),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 7),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 5),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 4),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 1),
            IsInstTargetKind::ValueType
        );
    }

    #[test]
    fn isinst_target_kind_recognizes_genuine_corelib_type_defs() {
        let mut strings_heap: Vec<u8> = vec![0];
        let system: u32 = push_heap_string(&mut strings_heap, "System");
        let value_type: u32 = push_heap_string(&mut strings_heap, "ValueType");
        let enum_type: u32 = push_heap_string(&mut strings_heap, "Enum");
        let money: u32 = push_heap_string(&mut strings_heap, "Money");
        let color: u32 = push_heap_string(&mut strings_heap, "Color");
        let mscorlib: u32 = push_heap_string(&mut strings_heap, "mscorlib");
        let tables: Tables = Tables {
            assembly: Some(crate::tables::AssemblyRow {
                hash_alg_id: 0,
                major: 0,
                minor: 0,
                build: 0,
                revision: 0,
                flags: ASSEMBLY_REF_PUBLIC_KEY,
                public_key: 1,
                name: mscorlib,
                culture: 0,
            }),
            type_defs: vec![
                TypeDefRow {
                    flags: 0,
                    name: value_type,
                    namespace: system,
                    extends: None,
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: enum_type,
                    namespace: system,
                    extends: Some(RowRef {
                        table: TableId::TypeDef,
                        row: 1,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: money,
                    namespace: 0,
                    extends: Some(RowRef {
                        table: TableId::TypeDef,
                        row: 1,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: color,
                    namespace: 0,
                    extends: Some(RowRef {
                        table: TableId::TypeDef,
                        row: 2,
                    }),
                    field_list: 1,
                    method_list: 1,
                },
            ],
            ..Tables::default()
        };
        let resolver: Resolver = Resolver {
            tables,
            method_impl_indices_by_type: BTreeMap::new(),
            strings_heap,
            blob: vec![0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0],
            us: Vec::new(),
        };
        let type_def_token: u32 = u32::from(TableId::TypeDef as u8) << 24;
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 1),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 2),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 3),
            IsInstTargetKind::ValueType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_def_token | 4),
            IsInstTargetKind::ValueType
        );
    }

    #[test]
    fn isinst_target_kind_uses_typespec_category_and_refuses_generic_parameters() {
        let tables: Tables = Tables {
            type_refs: vec![
                TypeRefRow {
                    resolution_scope: None,
                    name: 1,
                    namespace: 0,
                },
                TypeRefRow {
                    resolution_scope: None,
                    name: 13,
                    namespace: 0,
                },
                TypeRefRow {
                    resolution_scope: None,
                    name: 29,
                    namespace: 0,
                },
                TypeRefRow {
                    resolution_scope: None,
                    name: 75,
                    namespace: 68,
                },
            ],
            type_defs: vec![
                TypeDefRow {
                    flags: 0,
                    name: 42,
                    namespace: 0,
                    extends: None,
                    field_list: 1,
                    method_list: 1,
                },
                TypeDefRow {
                    flags: 0,
                    name: 53,
                    namespace: 0,
                    extends: None,
                    field_list: 1,
                    method_list: 1,
                },
            ],
            type_specs: vec![
                TypeSpecRow { signature: 1 },
                TypeSpecRow { signature: 4 },
                TypeSpecRow { signature: 7 },
                TypeSpecRow { signature: 10 },
                TypeSpecRow { signature: 13 },
            ],
            ..Default::default()
        };
        let resolver: Resolver = Resolver {
            tables,
            method_impl_indices_by_type: BTreeMap::new(),
            strings_heap:
                b"\0ValueTarget\0ReferenceTarget\0GenericBox`1\0LocalValue\0LocalReference\0System\0Nullable`1\0"
                    .to_vec(),
            blob: vec![
                0, 2, 0x11, 0x05, 2, 0x12, 0x09, 2, 0x1E, 0, 2, 0x11, 0x11, 5, 0x15, 0x11, 0x0D, 1,
                0x0E,
            ],
            us: Vec::new(),
        };
        let type_spec_token: u32 = u32::from(TableId::TypeSpec as u8) << 24;
        assert_eq!(
            resolver.isinst_target_kind(type_spec_token | 1),
            IsInstTargetKind::ValueType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_spec_token | 2),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind(type_spec_token | 3),
            IsInstTargetKind::Unsupported
        );
        assert_eq!(
            resolver.isinst_target_kind(type_spec_token | 4),
            IsInstTargetKind::Unsupported
        );
        assert_eq!(
            resolver.isinst_target_kind(type_spec_token | 5),
            IsInstTargetKind::ValueType
        );
        assert_eq!(
            resolver.resolve_token(type_spec_token | 5),
            "GenericBox<string>"
        );
        let type_ref_token: u32 = u32::from(TableId::TypeRef as u8) << 24;
        assert_eq!(
            resolver.isinst_target_kind(type_ref_token | 1),
            IsInstTargetKind::RenderableUnknown
        );
        assert_eq!(
            resolver.isinst_target_kind(type_ref_token | 3),
            IsInstTargetKind::Unsupported
        );

        let value: TypeSig = TypeSig::NamedType {
            is_value_type: true,
            token: 0x0100_0001,
        };
        let reference: TypeSig = TypeSig::NamedType {
            is_value_type: false,
            token: 0x0100_0002,
        };
        let generic_value: TypeSig = TypeSig::GenericInst {
            base: Box::new(TypeSig::NamedType {
                is_value_type: true,
                token: 0x0100_0003,
            }),
            args: vec![TypeSig::String],
        };
        let nullable_value: TypeSig = TypeSig::GenericInst {
            base: Box::new(TypeSig::NamedType {
                is_value_type: true,
                token: 0x0100_0004,
            }),
            args: vec![TypeSig::I4],
        };
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&value),
            IsInstTargetKind::ValueType
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&reference),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&generic_value),
            IsInstTargetKind::ValueType
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&TypeSig::SzArray(Box::new(TypeSig::I4))),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.unbox_any_target_name_from_signature(&TypeSig::SzArray(Box::new(TypeSig::I4))),
            Some("int[]".to_owned())
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&TypeSig::Array {
                element: Box::new(TypeSig::I4),
                rank: 1,
            }),
            IsInstTargetKind::Unsupported
        );
        assert_eq!(
            resolver.unbox_any_target_name_from_signature(&TypeSig::Array {
                element: Box::new(TypeSig::I4),
                rank: 1,
            }),
            None
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&TypeSig::Array {
                element: Box::new(TypeSig::I4),
                rank: 2,
            }),
            IsInstTargetKind::ReferenceType
        );
        assert_eq!(
            resolver.unbox_any_target_name_from_signature(&TypeSig::Array {
                element: Box::new(TypeSig::I4),
                rank: 2,
            }),
            Some("int[,]".to_owned())
        );
        assert_eq!(
            resolver.unbox_any_target_name_from_signature(&TypeSig::Array {
                element: Box::new(TypeSig::I4),
                rank: 33,
            }),
            None
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&TypeSig::MVar(0)),
            IsInstTargetKind::Unsupported
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&nullable_value),
            IsInstTargetKind::Unsupported
        );
        assert_eq!(
            resolver.unbox_any_target_name_from_signature(&nullable_value),
            Some("System.Nullable<int>".to_owned())
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&TypeSig::NamedType {
                is_value_type: true,
                token: 0x0200_0003,
            }),
            IsInstTargetKind::Unsupported
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&TypeSig::GenericInst {
                base: Box::new(TypeSig::NamedType {
                    is_value_type: true,
                    token: 0x0100_0003,
                }),
                args: Vec::new(),
            }),
            IsInstTargetKind::Unsupported
        );
        assert_eq!(
            resolver.isinst_target_kind_from_signature(&TypeSig::GenericInst {
                base: Box::new(TypeSig::NamedType {
                    is_value_type: true,
                    token: 0x0100_0003,
                }),
                args: vec![TypeSig::String, TypeSig::I4],
            }),
            IsInstTargetKind::Unsupported
        );
    }
}
