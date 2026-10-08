use std::collections::{BTreeMap, BTreeSet};

use disrobe_core::neutralize::{
    Anchor, NeutralizationPlan, NeutralizeError, Patch, Refusal, RuntimeCheck,
};
use disrobe_typerec::ImportMap;
use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, Encoder, Formatter, Instruction, Mnemonic,
    NasmFormatter, OpKind, Register,
};
use object::{Object, ObjectSection, SectionKind};

use crate::error::{Error, Result};

pub const MAX_DECODED_INSTRUCTIONS: usize = 4_000_000;
pub const MAX_CODE_BYTES: usize = 64 * 1024 * 1024;
const CALL_WINDOW: usize = 48;
const CONSUMER_WINDOW: usize = 16;
const PEB_WINDOW: usize = 24;
const TRAP_STORE_WINDOW: usize = 6;
const LEAF_WINDOW: usize = 6;
const HYPERVISOR_BIT: u64 = 0x8000_0000;
const PROCESS_DEBUG_PORT: u64 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: u64 = 0x1E;
const PROCESS_DEBUG_FLAGS: u64 = 0x1F;
const THREAD_HIDE_FROM_DEBUGGER: u64 = 0x11;
const DIRECTORY_TLS: usize = 9;

#[derive(Debug, Clone)]
pub struct RuntimeCheckScan {
    pub plan: NeutralizationPlan,
    pub bits: u32,
    pub decoded_instructions: usize,
}

struct Section<'a> {
    address: u64,
    file_offset: u64,
    data: &'a [u8],
}

struct Code32 {
    insns: Vec<Instruction>,
    by_addr: BTreeMap<u64, usize>,
    file_offset: u64,
    base: u64,
}

#[derive(Debug, Clone)]
struct CallSite {
    name: String,
    span_start: usize,
}

impl Code32 {
    fn file_offset_of(&self, insn: &Instruction) -> u64 {
        self.file_offset + (insn.ip() - self.base)
    }

    fn bytes_of<'a>(&self, data: &'a [u8], insn: &Instruction) -> &'a [u8] {
        let start: usize = (insn.ip() - self.base) as usize;
        &data[start..start + insn.len()]
    }

    fn span_bytes<'a>(&self, data: &'a [u8], first: usize, last: usize) -> &'a [u8] {
        let start: usize = (self.insns[first].ip() - self.base) as usize;
        let end: usize = (self.insns[last].next_ip() - self.base) as usize;
        &data[start..end]
    }
}

struct Producer<'a> {
    bytes: &'a [u8],
    bits: u32,
    imports: ImportMap,
    plan: NeutralizationPlan,
    formatter: NasmFormatter,
    seen_sites: BTreeSet<(RuntimeCheck, u64)>,
}

pub fn plan_runtime_check_neutralization(bytes: &[u8]) -> Result<RuntimeCheckScan> {
    let file: object::File<'_> =
        object::File::parse(bytes).map_err(|e| Error::ObjectParse(e.to_string()))?;
    let bits: u32 = match file.architecture() {
        object::Architecture::X86_64 => 64,
        object::Architecture::I386 => 32,
        _ => {
            return Ok(RuntimeCheckScan {
                plan: NeutralizationPlan::new(bytes),
                bits: 0,
                decoded_instructions: 0,
            });
        }
    };
    let mut producer: Producer<'_> = Producer {
        bytes,
        bits,
        imports: ImportMap::from_image(bytes),
        plan: NeutralizationPlan::new(bytes),
        formatter: NasmFormatter::new(),
        seen_sites: BTreeSet::new(),
    };
    let mut decoded_total: usize = 0;
    let mut budget: usize = MAX_CODE_BYTES;
    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let Some((file_offset, _)): Option<(u64, u64)> = section.file_range() else {
            continue;
        };
        let Ok(data): std::result::Result<&[u8], _> = section.data() else {
            continue;
        };
        if data.is_empty() || budget == 0 {
            continue;
        }
        let take: usize = data.len().min(budget);
        budget -= take;
        let sec: Section<'_> = Section {
            address: section.address(),
            file_offset,
            data: &data[..take],
        };
        decoded_total += producer.scan_section(&sec);
    }
    producer.scan_tls_directory(&file);
    Ok(RuntimeCheckScan {
        plan: producer.plan,
        bits,
        decoded_instructions: decoded_total,
    })
}

fn decode(bits: u32, data: &[u8], base: u64) -> Vec<Instruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(bits, data, base, DecoderOptions::NONE);
    let mut out: Vec<Instruction> = Vec::new();
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() && out.len() < MAX_DECODED_INSTRUCTIONS {
        decoder.decode_out(&mut insn);
        out.push(insn);
    }
    out
}

fn multi_byte_nop(len: usize) -> Vec<u8> {
    const NOPS: [&[u8]; 9] = [
        &[0x90],
        &[0x66, 0x90],
        &[0x0F, 0x1F, 0x00],
        &[0x0F, 0x1F, 0x40, 0x00],
        &[0x0F, 0x1F, 0x44, 0x00, 0x00],
        &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],
        &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut remaining: usize = len;
    while remaining > 0 {
        let take: usize = remaining.min(NOPS.len());
        out.extend_from_slice(NOPS[take - 1]);
        remaining -= take;
    }
    out
}

fn encode_with_nop_tail(bits: u32, insn: Instruction, ip: u64, len: usize) -> Option<Vec<u8>> {
    let mut encoder: Encoder = Encoder::new(bits);
    encoder.encode(&insn, ip).ok()?;
    let mut bytes: Vec<u8> = encoder.take_buffer();
    if bytes.len() > len {
        return None;
    }
    let tail: usize = len - bytes.len();
    bytes.extend(multi_byte_nop(tail));
    Some(bytes)
}

fn zero_register_patch(bits: u32, dest: Register, ip: u64, len: usize) -> Option<Vec<u8>> {
    let r32: Register = dest.full_register32();
    if r32 == Register::None || !r32.is_gpr32() {
        return None;
    }
    let xor: Instruction = Instruction::with2(Code::Xor_r32_rm32, r32, r32).ok()?;
    encode_with_nop_tail(bits, xor, ip, len)
}

fn constant_eax_patch(bits: u32, value: u32, ip: u64, len: usize) -> Option<Vec<u8>> {
    let insn: Instruction = if value == 0 {
        Instruction::with2(Code::Xor_r32_rm32, Register::EAX, Register::EAX).ok()?
    } else {
        Instruction::with2(Code::Mov_r32_imm32, Register::EAX, value).ok()?
    };
    encode_with_nop_tail(bits, insn, ip, len)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchFix {
    ForceJump,
    NeverJump,
}

fn branch_patch(insn: &Instruction, original: &[u8], fix: BranchFix) -> Option<Vec<u8>> {
    if insn.op0_kind() != OpKind::NearBranch64
        && insn.op0_kind() != OpKind::NearBranch32
        && insn.op0_kind() != OpKind::NearBranch16
    {
        return None;
    }
    match (original.len(), fix) {
        (2, BranchFix::ForceJump) if (0x70..=0x7F).contains(&original[0]) => {
            Some(vec![0xEB, original[1]])
        }
        (2, BranchFix::NeverJump) if (0x70..=0x7F).contains(&original[0]) => Some(vec![0x90, 0x90]),
        (6, BranchFix::ForceJump)
            if original[0] == 0x0F && (0x80..=0x8F).contains(&original[1]) =>
        {
            let mut out: Vec<u8> = vec![0x90, 0xE9];
            out.extend_from_slice(&original[2..6]);
            Some(out)
        }
        (6, BranchFix::NeverJump)
            if original[0] == 0x0F && (0x80..=0x8F).contains(&original[1]) =>
        {
            Some(multi_byte_nop(6))
        }
        _ => None,
    }
}

fn jump_taken_means_large(cc: ConditionCode) -> Option<bool> {
    match cc {
        ConditionCode::a | ConditionCode::ae | ConditionCode::g | ConditionCode::ge => Some(true),
        ConditionCode::b | ConditionCode::be | ConditionCode::l | ConditionCode::le => Some(false),
        _ => None,
    }
}

fn jump_taken_means_nonzero(cc: ConditionCode) -> Option<bool> {
    match cc {
        ConditionCode::ne => Some(true),
        ConditionCode::e => Some(false),
        _ => None,
    }
}

fn jump_taken_means_carry(cc: ConditionCode) -> Option<bool> {
    match cc {
        ConditionCode::b => Some(true),
        ConditionCode::ae => Some(false),
        _ => None,
    }
}

fn import_name(name: &str) -> &str {
    let bare: &str = name.rsplit('!').next().unwrap_or(name);
    bare.split_once('@')
        .map_or(bare, |(base, _): (&str, &str)| base)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Holder {
    Reg(Register),
    Slot(Register, i64),
}

fn full(reg: Register, bits: u32) -> Register {
    if bits == 64 {
        reg.full_register()
    } else {
        reg.full_register32()
    }
}

fn memory_holder(insn: &Instruction, bits: u32) -> Option<Holder> {
    let base: Register = insn.memory_base();
    if insn.memory_index() != Register::None {
        return None;
    }
    let frame: bool = matches!(
        base,
        Register::RBP | Register::RSP | Register::EBP | Register::ESP
    );
    frame.then(|| Holder::Slot(full(base, bits), insn.memory_displacement64() as i64))
}

fn operand_holder(insn: &Instruction, op: u32, bits: u32) -> Option<Holder> {
    match insn.op_kind(op) {
        OpKind::Register => Some(Holder::Reg(full(insn.op_register(op), bits))),
        OpKind::Memory => memory_holder(insn, bits),
        _ => None,
    }
}

impl Producer<'_> {
    fn format(&mut self, insn: &Instruction) -> String {
        let mut text: String = String::new();
        self.formatter.format(insn, &mut text);
        text
    }

    fn anchor(&mut self, insn: &Instruction, pattern: String) -> Anchor {
        Anchor {
            address: insn.ip(),
            instruction: self.format(insn),
            pattern,
        }
    }

    fn push_patch(
        &mut self,
        check: RuntimeCheck,
        insn: &Instruction,
        pattern: String,
        file_offset: u64,
        original: &[u8],
        replacement: Vec<u8>,
        risk: &str,
    ) {
        if !self.seen_sites.insert((check, insn.ip())) {
            return;
        }
        let anchor: Anchor = self.anchor(insn, pattern);
        let patch: Patch = Patch {
            id: format!("{}-{:x}", check.label(), insn.ip()),
            check,
            anchor: anchor.clone(),
            file_offset,
            original: original.to_vec(),
            replacement,
            risk: risk.to_owned(),
        };
        if let Err(error) = self.plan.push_patch(patch) {
            let reason: String = match error {
                NeutralizeError::PlanTooLarge { limit } => {
                    format!("plan already holds {limit} patches")
                }
                other => other.to_string(),
            };
            self.plan.refusals.push(Refusal {
                check,
                anchor,
                reason,
            });
        }
    }

    fn refuse(&mut self, check: RuntimeCheck, insn: &Instruction, pattern: String, reason: &str) {
        if !self.seen_sites.insert((check, insn.ip())) {
            return;
        }
        let anchor: Anchor = self.anchor(insn, pattern);
        self.plan.refusals.push(Refusal {
            check,
            anchor,
            reason: reason.to_owned(),
        });
    }

    fn import_slot_name(&self, insn: &Instruction) -> Option<String> {
        if insn.op_count() == 0 && insn.op1_kind() != OpKind::Memory {
            return None;
        }
        let memory_operand: bool =
            (0..insn.op_count()).any(|op: u32| insn.op_kind(op) == OpKind::Memory);
        if !memory_operand {
            return None;
        }
        let slot: u64 = if insn.is_ip_rel_memory_operand() {
            insn.ip_rel_memory_address()
        } else if insn.memory_base() == Register::None && insn.memory_index() == Register::None {
            insn.memory_displacement64()
        } else {
            return None;
        };
        self.imports
            .resolve(slot)
            .and_then(|import| import.lookup_key())
            .map(|name: &str| import_name(name).to_owned())
    }

    fn resolve_call(&self, code: &Code32, index: usize) -> Option<CallSite> {
        let insn: Instruction = code.insns[index];
        if insn.mnemonic() != Mnemonic::Call {
            return None;
        }
        match insn.op0_kind() {
            OpKind::Memory => self.import_slot_name(&insn).map(|name: String| CallSite {
                name,
                span_start: index,
            }),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                let target: u64 = insn.near_branch_target();
                let thunk_index: usize = *code.by_addr.get(&target)?;
                let thunk: &Instruction = code.insns.get(thunk_index)?;
                if thunk.mnemonic() == Mnemonic::Jmp && thunk.op0_kind() == OpKind::Memory {
                    self.import_slot_name(thunk).map(|name: String| CallSite {
                        name,
                        span_start: index,
                    })
                } else {
                    None
                }
            }
            OpKind::Register => {
                let reg: Register = full(insn.op0_register(), self.bits);
                let start: usize = index.saturating_sub(4);
                for k in (start..index).rev() {
                    let prior: Instruction = code.insns[k];
                    if prior.mnemonic() == Mnemonic::Mov
                        && prior.op0_kind() == OpKind::Register
                        && full(prior.op0_register(), self.bits) == reg
                    {
                        return self.import_slot_name(&prior).map(|name: String| CallSite {
                            name,
                            span_start: if k + 1 == index { k } else { index },
                        });
                    }
                    let writes_reg: bool = (0..prior.op_count()).any(|op: u32| {
                        prior.op_kind(op) == OpKind::Register
                            && full(prior.op_register(op), self.bits) == reg
                    });
                    if writes_reg || prior.mnemonic() == Mnemonic::Call {
                        return None;
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn scan_section(&mut self, section: &Section<'_>) -> usize {
        let insns: Vec<Instruction> = decode(self.bits, section.data, section.address);
        let by_addr: BTreeMap<u64, usize> = insns
            .iter()
            .enumerate()
            .map(|(i, insn): (usize, &Instruction)| (insn.ip(), i))
            .collect();
        let code: Code32 = Code32 {
            insns,
            by_addr,
            file_offset: section.file_offset,
            base: section.address,
        };
        let count: usize = code.insns.len();
        let mut call_names: Vec<Option<CallSite>> = Vec::with_capacity(count);
        for i in 0..count {
            call_names.push(self.resolve_call(&code, i));
        }
        for i in 0..count {
            let insn: Instruction = code.insns[i];
            if insn.is_invalid() {
                continue;
            }
            if let Some(site) = call_names[i].clone() {
                self.handle_import_call(&code, section.data, i, &site, &call_names);
            }
            match insn.mnemonic() {
                Mnemonic::Rdtsc | Mnemonic::Rdtscp => {
                    self.handle_rdtsc(&code, section.data, i);
                }
                Mnemonic::Cpuid => self.handle_cpuid(&code, section.data, i),
                Mnemonic::Int if insn.immediate8() == 0x2D => {
                    self.handle_trap(&code, section.data, i, RuntimeCheck::Int2dTrap);
                }
                Mnemonic::Int1 => {
                    self.handle_trap(&code, section.data, i, RuntimeCheck::IcebpTrap);
                }
                Mnemonic::Mov if self.is_peb_load(&insn) => {
                    self.handle_peb(&code, section.data, i);
                }
                _ => {}
            }
        }
        count
    }

    fn is_peb_load(&self, insn: &Instruction) -> bool {
        if insn.op1_kind() != OpKind::Memory || insn.op0_kind() != OpKind::Register {
            return false;
        }
        let segment: Register = insn.memory_segment();
        let disp: u64 = insn.memory_displacement64();
        match self.bits {
            64 => segment == Register::GS && disp == 0x60,
            _ => segment == Register::FS && disp == 0x30,
        }
    }

    fn handle_import_call(
        &mut self,
        code: &Code32,
        data: &[u8],
        i: usize,
        call_site: &CallSite,
        call_names: &[Option<CallSite>],
    ) {
        let insn: Instruction = code.insns[i];
        let name: &str = call_site.name.as_str();
        let original: &[u8] = code.span_bytes(data, call_site.span_start, i);
        let offset: u64 = code.file_offset_of(&code.insns[call_site.span_start]);
        let len: usize = original.len();
        let site: String = if call_site.span_start == i {
            format!("call site resolving to {name} through the import table")
        } else {
            format!(
                "import slot of {name} loaded at {:#x} and called here; both instructions are rewritten",
                code.insns[call_site.span_start].ip()
            )
        };
        match name {
            "IsDebuggerPresent" => {
                match constant_eax_patch(self.bits, 0, insn.ip(), len) {
                    Some(replacement) => self.push_patch(
                        RuntimeCheck::IsDebuggerPresent,
                        &insn,
                        site,
                        offset,
                        original,
                        replacement,
                        "the call becomes `xor eax, eax`; code that relied on the call for its side effects on flags or on the stack pointer (cdecl cleanup) keeps the original stack shape because the import call pops nothing",
                    ),
                    None => self.refuse(
                        RuntimeCheck::IsDebuggerPresent,
                        &insn,
                        site,
                        "the call encoding is shorter than a register clear",
                    ),
                }
            }
            "CheckRemoteDebuggerPresent" => {
                match constant_eax_patch(self.bits, 1, insn.ip(), len) {
                    Some(replacement) => self.push_patch(
                        RuntimeCheck::CheckRemoteDebuggerPresent,
                        &insn,
                        site,
                        offset,
                        original,
                        replacement,
                        "the call becomes `mov eax, 1` (success) and the out-flag keeps the value the caller stored before the call; a caller that left it uninitialised reads stack garbage",
                    ),
                    None => self.refuse(
                        RuntimeCheck::CheckRemoteDebuggerPresent,
                        &insn,
                        site,
                        "the call encoding is shorter than a constant load",
                    ),
                }
            }
            "NtQueryInformationProcess" | "ZwQueryInformationProcess" => {
                let class: Option<u64> = self.second_argument(code, i);
                let check: Option<RuntimeCheck> = match class {
                    Some(PROCESS_DEBUG_PORT) => Some(RuntimeCheck::NtQueryInformationProcessDebugPort),
                    Some(PROCESS_DEBUG_OBJECT_HANDLE) => {
                        Some(RuntimeCheck::NtQueryInformationProcessDebugObjectHandle)
                    }
                    Some(PROCESS_DEBUG_FLAGS) => Some(RuntimeCheck::NtQueryInformationProcessDebugFlags),
                    _ => None,
                };
                match check {
                    Some(check) => match constant_eax_patch(self.bits, 0, insn.ip(), len) {
                        Some(replacement) => self.push_patch(
                            check,
                            &insn,
                            format!("{site} with ProcessInformationClass {}", class.unwrap_or(0)),
                            offset,
                            original,
                            replacement,
                            "the call becomes `xor eax, eax` (STATUS_SUCCESS) and the information buffer keeps whatever the caller stored before the call; a caller expecting ReturnLength to be written reads its old value",
                        ),
                        None => self.refuse(
                            check,
                            &insn,
                            site,
                            "the call encoding is shorter than a register clear",
                        ),
                    },
                    None => {
                        if class.is_none() {
                            self.refuse(
                                RuntimeCheck::NtQueryInformationProcessDebugPort,
                                &insn,
                                site,
                                "ProcessInformationClass is not an immediate within the call window, so the debug class cannot be proven",
                            );
                        }
                    }
                }
            }
            "NtSetInformationThread" | "ZwSetInformationThread" => {
                if self.second_argument(code, i) == Some(THREAD_HIDE_FROM_DEBUGGER) {
                    match constant_eax_patch(self.bits, 0, insn.ip(), len) {
                        Some(replacement) => self.push_patch(
                            RuntimeCheck::NtSetInformationThreadHideFromDebugger,
                            &insn,
                            format!("{site} with ThreadInformationClass 0x11"),
                            offset,
                            original,
                            replacement,
                            "the call becomes `xor eax, eax` (STATUS_SUCCESS) so the thread is never hidden; nothing else in the program observes the difference",
                        ),
                        None => self.refuse(
                            RuntimeCheck::NtSetInformationThreadHideFromDebugger,
                            &insn,
                            site,
                            "the call encoding is shorter than a register clear",
                        ),
                    }
                }
            }
            "OutputDebugStringA" | "OutputDebugStringW" => {
                self.refuse(
                    RuntimeCheck::OutputDebugString,
                    &insn,
                    site,
                    "the check reads GetLastError after the call; the last-error flow is not rewritten statically",
                );
            }
            "AddVectoredExceptionHandler" | "RtlAddVectoredExceptionHandler" => {
                self.refuse(
                    RuntimeCheck::VectoredExceptionHandler,
                    &insn,
                    site,
                    "handler registration is program structure; the stub emulator dispatches the handler in its sandbox instead of patching it out",
                );
            }
            "GetTickCount" | "GetTickCount64" | "timeGetTime" => {
                self.handle_timing_pair(code, data, i, name, call_names, RuntimeCheck::TickCountDelta);
            }
            "QueryPerformanceCounter" => {
                self.handle_timing_pair(
                    code,
                    data,
                    i,
                    name,
                    call_names,
                    RuntimeCheck::PerformanceCounterDelta,
                );
            }
            _ => {}
        }
    }

    fn second_argument(&self, code: &Code32, call_index: usize) -> Option<u64> {
        let start: usize = call_index.saturating_sub(CONSUMER_WINDOW);
        if self.bits == 64 {
            for insn in code.insns[start..call_index].iter().rev() {
                if insn.mnemonic() == Mnemonic::Mov
                    && insn.op0_kind() == OpKind::Register
                    && matches!(insn.op0_register(), Register::EDX | Register::RDX)
                {
                    return insn.try_immediate(1).ok();
                }
                if insn.mnemonic() == Mnemonic::Call {
                    return None;
                }
            }
        } else {
            let mut pushes: Vec<Option<u64>> = Vec::new();
            for insn in code.insns[start..call_index].iter().rev() {
                if insn.mnemonic() == Mnemonic::Push {
                    pushes.push(insn.try_immediate(0).ok());
                    if pushes.len() == 2 {
                        return pushes[1];
                    }
                }
                if insn.mnemonic() == Mnemonic::Call {
                    return None;
                }
            }
        }
        None
    }

    fn consumer_branch(code: &Code32, from: usize, window: usize) -> Option<(usize, Instruction)> {
        let end: usize = (from + window).min(code.insns.len());
        for (k, insn) in code.insns[from..end].iter().enumerate() {
            if insn.mnemonic() == Mnemonic::Call || insn.mnemonic() == Mnemonic::Ret {
                return None;
            }
            if insn.is_jcc_short_or_near() {
                return Some((from + k, *insn));
            }
        }
        None
    }

    fn compare_before(code: &Code32, branch: usize, limit: usize) -> Option<Instruction> {
        let start: usize = branch.saturating_sub(limit);
        for insn in code.insns[start..branch].iter().rev() {
            match insn.mnemonic() {
                Mnemonic::Cmp | Mnemonic::Test | Mnemonic::And | Mnemonic::Bt | Mnemonic::Sub => {
                    return Some(*insn);
                }
                Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsxd | Mnemonic::Lea => {}
                _ => return None,
            }
        }
        None
    }

    fn apply_branch_fix(
        &mut self,
        code: &Code32,
        data: &[u8],
        branch: &Instruction,
        check: RuntimeCheck,
        pattern: String,
        fix: BranchFix,
        risk: &str,
    ) {
        let original: &[u8] = code.bytes_of(data, branch);
        match branch_patch(branch, original, fix) {
            Some(replacement) => {
                let offset: u64 = code.file_offset_of(branch);
                self.push_patch(check, branch, pattern, offset, original, replacement, risk);
            }
            None => self.refuse(
                check,
                branch,
                pattern,
                "the consuming branch is not a short or near conditional jump that can be rewritten in place",
            ),
        }
    }

    fn handle_timing_pair(
        &mut self,
        code: &Code32,
        data: &[u8],
        i: usize,
        name: &str,
        call_names: &[Option<CallSite>],
        check: RuntimeCheck,
    ) {
        let start: usize = i.saturating_sub(CALL_WINDOW);
        let earlier: bool = (start..i).any(|k: usize| {
            call_names[k]
                .as_ref()
                .is_some_and(|site: &CallSite| site.name == name)
        });
        if !earlier {
            return;
        }
        let Some((branch_index, branch)): Option<(usize, Instruction)> =
            Self::consumer_branch(code, i + 1, CONSUMER_WINDOW)
        else {
            return;
        };
        let subtracted: bool = code.insns[i + 1..branch_index]
            .iter()
            .any(|insn: &Instruction| insn.mnemonic() == Mnemonic::Sub);
        if !subtracted {
            return;
        }
        let pattern: String = format!(
            "second {name} call at {:#x} feeds a subtraction and this threshold compare",
            code.insns[i].ip()
        );
        let Some(cmp): Option<Instruction> = Self::compare_before(code, branch_index, 4) else {
            self.refuse(
                check,
                &branch,
                pattern,
                "no compare feeds the branch after the delta",
            );
            return;
        };
        self.timing_fix(code, data, &branch, &cmp, check, pattern);
    }

    fn timing_fix(
        &mut self,
        code: &Code32,
        data: &[u8],
        branch: &Instruction,
        cmp: &Instruction,
        check: RuntimeCheck,
        pattern: String,
    ) {
        let Ok(threshold): std::result::Result<u64, _> = cmp.try_immediate(1) else {
            self.refuse(
                check,
                branch,
                pattern,
                "the threshold is not an immediate operand, so the direction of the compare cannot be proven",
            );
            return;
        };
        if cmp.mnemonic() != Mnemonic::Cmp {
            self.refuse(
                check,
                branch,
                pattern,
                "the delta is not compared against the threshold with cmp",
            );
            return;
        }
        let cc: ConditionCode = branch.condition_code();
        let jump_means_large: Option<bool> = jump_taken_means_large(cc).or_else(|| {
            (threshold == 0)
                .then(|| jump_taken_means_nonzero(cc))
                .flatten()
        });
        let Some(jump_means_large): Option<bool> = jump_means_large else {
            self.refuse(
                check,
                branch,
                pattern,
                "the branch condition is not an ordered compare against the threshold",
            );
            return;
        };
        let fix: BranchFix = if jump_means_large {
            BranchFix::NeverJump
        } else {
            BranchFix::ForceJump
        };
        self.apply_branch_fix(
            code,
            data,
            branch,
            check,
            pattern,
            fix,
            "the branch is rewritten so the small-delta path is always taken; code after the compare that reuses the flags register reads stale flags",
        );
    }

    fn handle_rdtsc(&mut self, code: &Code32, data: &[u8], i: usize) {
        let start: usize = i.saturating_sub(CALL_WINDOW);
        let earlier: bool = code.insns[start..i].iter().any(|insn: &Instruction| {
            matches!(insn.mnemonic(), Mnemonic::Rdtsc | Mnemonic::Rdtscp)
        });
        if !earlier {
            return;
        }
        let Some((branch_index, branch)): Option<(usize, Instruction)> =
            Self::consumer_branch(code, i + 1, CONSUMER_WINDOW)
        else {
            return;
        };
        let subtracted: bool = code.insns[i + 1..branch_index]
            .iter()
            .any(|insn: &Instruction| insn.mnemonic() == Mnemonic::Sub);
        if !subtracted {
            return;
        }
        let pattern: String = format!(
            "second rdtsc at {:#x} feeds a subtraction and this threshold compare",
            code.insns[i].ip()
        );
        let Some(cmp): Option<Instruction> = Self::compare_before(code, branch_index, 4) else {
            self.refuse(
                RuntimeCheck::RdtscDelta,
                &branch,
                pattern,
                "no compare feeds the branch after the delta",
            );
            return;
        };
        self.timing_fix(code, data, &branch, &cmp, RuntimeCheck::RdtscDelta, pattern);
    }

    fn handle_cpuid(&mut self, code: &Code32, data: &[u8], i: usize) {
        let start: usize = i.saturating_sub(LEAF_WINDOW);
        let mut leaf: Option<u64> = None;
        for (k, insn) in code.insns[start..i].iter().enumerate().rev() {
            if insn.mnemonic() == Mnemonic::Mov
                && insn.op0_kind() == OpKind::Register
                && matches!(insn.op0_register(), Register::EAX | Register::RAX)
            {
                leaf = match insn.op1_kind() {
                    OpKind::Memory => memory_holder(insn, self.bits).and_then(|slot: Holder| {
                        let slot_start: usize = (start + k).saturating_sub(LEAF_WINDOW);
                        code.insns[slot_start..start + k]
                            .iter()
                            .rev()
                            .find(|store: &&Instruction| {
                                store.mnemonic() == Mnemonic::Mov
                                    && store.op0_kind() == OpKind::Memory
                                    && memory_holder(store, self.bits) == Some(slot)
                            })
                            .and_then(|store: &Instruction| store.try_immediate(1).ok())
                    }),
                    _ => insn.try_immediate(1).ok(),
                };
                break;
            }
            if insn.mnemonic() == Mnemonic::Xor
                && insn.op0_kind() == OpKind::Register
                && insn.op1_kind() == OpKind::Register
                && insn.op0_register() == insn.op1_register()
                && matches!(insn.op0_register(), Register::EAX | Register::RAX)
            {
                leaf = Some(0);
                break;
            }
        }
        let cpuid: Instruction = code.insns[i];
        match leaf {
            Some(1) => {}
            Some(0x4000_0000..=0x4000_00FF) => {
                self.refuse(
                    RuntimeCheck::CpuidHypervisorLeaf,
                    &cpuid,
                    "cpuid with a hypervisor vendor leaf in eax".to_owned(),
                    "the vendor string is consumed by string compares that are not rewritten statically; the stub emulator answers the leaf with zeros",
                );
                return;
            }
            _ => return,
        }
        let end: usize = (i + 1 + CONSUMER_WINDOW).min(code.insns.len());
        let mut test_index: Option<usize> = None;
        let mut via_carry: bool = false;
        for k in i + 1..end {
            let insn: Instruction = code.insns[k];
            match insn.mnemonic() {
                Mnemonic::Test | Mnemonic::And
                    if insn.try_immediate(1).ok() == Some(HYPERVISOR_BIT) =>
                {
                    test_index = Some(k);
                    break;
                }
                Mnemonic::Bt if insn.try_immediate(1).ok() == Some(31) => {
                    test_index = Some(k);
                    via_carry = true;
                    break;
                }
                Mnemonic::Shr if insn.try_immediate(1).ok() == Some(31) => {
                    test_index = Some(k);
                    break;
                }
                Mnemonic::Call | Mnemonic::Ret | Mnemonic::Cpuid => break,
                _ => {}
            }
        }
        let Some(test_index): Option<usize> = test_index else {
            return;
        };
        let Some((_, branch)): Option<(usize, Instruction)> =
            Self::consumer_branch(code, test_index + 1, 6)
        else {
            self.refuse(
                RuntimeCheck::CpuidHypervisorBit,
                &cpuid,
                "cpuid leaf 1 with an ECX bit 31 test".to_owned(),
                "the hypervisor bit is tested but no conditional branch consumes it within the window",
            );
            return;
        };
        let pattern: String = format!(
            "cpuid leaf 1 at {:#x}, ECX bit 31 tested at {:#x}, consumed by this branch",
            cpuid.ip(),
            code.insns[test_index].ip()
        );
        let jump_means_present: Option<bool> = if via_carry {
            jump_taken_means_carry(branch.condition_code())
        } else {
            jump_taken_means_nonzero(branch.condition_code())
        };
        let Some(jump_means_present): Option<bool> = jump_means_present else {
            self.refuse(
                RuntimeCheck::CpuidHypervisorBit,
                &branch,
                pattern,
                "the branch condition does not test the hypervisor bit directly",
            );
            return;
        };
        let fix: BranchFix = if jump_means_present {
            BranchFix::NeverJump
        } else {
            BranchFix::ForceJump
        };
        self.apply_branch_fix(
            code,
            data,
            &branch,
            RuntimeCheck::CpuidHypervisorBit,
            pattern,
            fix,
            "the branch is rewritten so the no-hypervisor path is always taken; other CPUID feature bits read by the same code are untouched",
        );
    }

    fn handle_trap(&mut self, code: &Code32, data: &[u8], i: usize, check: RuntimeCheck) {
        let trap: Instruction = code.insns[i];
        let start: usize = i.saturating_sub(TRAP_STORE_WINDOW);
        let mut flag: Option<(Holder, u64, bool)> = None;
        for insn in code.insns[start..i].iter().rev() {
            if insn.mnemonic() == Mnemonic::Mov
                && insn.op0_kind() == OpKind::Memory
                && let Ok(value) = insn.try_immediate(1)
            {
                let key: Option<Holder> = if insn.is_ip_rel_memory_operand() {
                    Some(Holder::Slot(
                        Register::RIP,
                        insn.ip_rel_memory_address() as i64,
                    ))
                } else {
                    memory_holder(insn, self.bits)
                };
                if let Some(key) = key {
                    flag = Some((key, insn.ip(), value != 0));
                    break;
                }
            }
        }
        let trap_text: &str = if check == RuntimeCheck::Int2dTrap {
            "int 2dh"
        } else {
            "icebp"
        };
        let Some((flag_key, store_ip, assumes_debugged)): Option<(Holder, u64, bool)> = flag else {
            self.refuse(
                check,
                &trap,
                format!("{trap_text} without a flag store in the preceding instructions"),
                "no flag assignment precedes the trap, so the handler's effect cannot be located",
            );
            return;
        };
        let end: usize = (i + 1 + CONSUMER_WINDOW).min(code.insns.len());
        let mut consumer: Option<usize> = None;
        for k in i + 1..end {
            let insn: Instruction = code.insns[k];
            if insn.mnemonic() == Mnemonic::Call || insn.mnemonic() == Mnemonic::Ret {
                break;
            }
            let reads_flag: bool = matches!(
                insn.mnemonic(),
                Mnemonic::Mov | Mnemonic::Cmp | Mnemonic::Movzx
            ) && (insn.op1_kind() == OpKind::Memory
                || insn.op0_kind() == OpKind::Memory)
                && {
                    let key: Option<Holder> = if insn.is_ip_rel_memory_operand() {
                        Some(Holder::Slot(
                            Register::RIP,
                            insn.ip_rel_memory_address() as i64,
                        ))
                    } else {
                        memory_holder(&insn, self.bits)
                    };
                    key == Some(flag_key)
                };
            if reads_flag {
                consumer = Some(k);
                break;
            }
        }
        let Some(consumer): Option<usize> = consumer else {
            self.refuse(
                check,
                &trap,
                format!("{trap_text} after a flag store at {store_ip:#x}"),
                "the flag written before the trap is not read back within the window",
            );
            return;
        };
        let Some((_, branch)): Option<(usize, Instruction)> =
            Self::consumer_branch(code, consumer + 1, 4)
        else {
            self.refuse(
                check,
                &trap,
                format!("{trap_text} after a flag store at {store_ip:#x}"),
                "the flag is read back but no conditional branch consumes it",
            );
            return;
        };
        let Some(jump_means_nonzero): Option<bool> =
            jump_taken_means_nonzero(branch.condition_code())
        else {
            self.refuse(
                check,
                &branch,
                format!(
                    "{trap_text} at {:#x} with a flag compare feeding this branch",
                    trap.ip()
                ),
                "the branch is not an equality test on the flag",
            );
            return;
        };
        let fix: BranchFix = match (assumes_debugged, jump_means_nonzero) {
            (true, true) | (false, false) => BranchFix::NeverJump,
            (true, false) | (false, true) => BranchFix::ForceJump,
        };
        let pattern: String = format!(
            "{trap_text} at {:#x}; flag stored at {store_ip:#x} (assumes {}) and consumed by this branch",
            trap.ip(),
            if assumes_debugged {
                "debugged"
            } else {
                "clean"
            }
        );
        self.apply_branch_fix(
            code,
            data,
            &branch,
            check,
            pattern,
            fix,
            "the trap itself stays in place so the handler still runs; only the branch on the handler's flag is forced to the clean path",
        );
    }

    fn handle_peb(&mut self, code: &Code32, data: &[u8], i: usize) {
        let load: Instruction = code.insns[i];
        let mut holders: BTreeSet<Holder> =
            BTreeSet::from([Holder::Reg(full(load.op0_register(), self.bits))]);
        let (flag_off, being_debugged_off): (u64, u64) = if self.bits == 64 {
            (0xBC, 0x02)
        } else {
            (0x68, 0x02)
        };
        let end: usize = (i + 1 + PEB_WINDOW).min(code.insns.len());
        for k in i + 1..end {
            let insn: Instruction = code.insns[k];
            if insn.mnemonic() == Mnemonic::Call || insn.mnemonic() == Mnemonic::Ret {
                return;
            }
            let is_load: bool = matches!(insn.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx)
                && insn.op1_kind() == OpKind::Memory
                && insn.op0_kind() == OpKind::Register;
            if is_load
                && insn.memory_index() == Register::None
                && holders.contains(&Holder::Reg(full(insn.memory_base(), self.bits)))
            {
                let disp: u64 = insn.memory_displacement64();
                let check: Option<(RuntimeCheck, &str)> = if disp == being_debugged_off {
                    Some((RuntimeCheck::PebBeingDebugged, "BeingDebugged"))
                } else if disp == flag_off {
                    Some((RuntimeCheck::PebNtGlobalFlag, "NtGlobalFlag"))
                } else {
                    None
                };
                if let Some((check, field)) = check {
                    let original: &[u8] = code.bytes_of(data, &insn);
                    let pattern: String = format!(
                        "PEB base loaded at {:#x}, {field} (+{disp:#x}) read here",
                        load.ip()
                    );
                    match zero_register_patch(
                        self.bits,
                        insn.op0_register(),
                        insn.ip(),
                        original.len(),
                    ) {
                        Some(replacement) => {
                            let offset: u64 = code.file_offset_of(&insn);
                            self.push_patch(
                                check,
                                &insn,
                                pattern,
                                offset,
                                original,
                                replacement,
                                "the field read becomes a register clear; the PEB base register keeps its value for later reads",
                            );
                        }
                        None => self.refuse(
                            check,
                            &insn,
                            pattern,
                            "the destination register cannot be cleared within the read's length",
                        ),
                    }
                    return;
                }
                continue;
            }
            if insn.mnemonic() == Mnemonic::Mov {
                let src: Option<Holder> = operand_holder(&insn, 1, self.bits);
                let dst: Option<Holder> = operand_holder(&insn, 0, self.bits);
                match (dst, src) {
                    (Some(d), Some(s)) if holders.contains(&s) => {
                        holders.insert(d);
                    }
                    (Some(d), _) => {
                        holders.remove(&d);
                    }
                    _ => {}
                }
            }
        }
    }

    fn scan_tls_directory(&mut self, file: &object::File<'_>) {
        let Ok(img): Result<crate::packers::pe_sections::PeImage> =
            crate::packers::pe_sections::parse_pe_image(self.bytes)
        else {
            return;
        };
        let Some(dir): Option<&crate::packers::pe_sections::DataDirectory> =
            img.data_directories.get(DIRECTORY_TLS)
        else {
            return;
        };
        if dir.virtual_address == 0 || dir.size == 0 {
            return;
        }
        let ptr: u64 = u64::from(file.is_64()) * 4 + 4;
        let tls_va: u64 = img.image_base + u64::from(dir.virtual_address);
        let Some(callbacks_va): Option<u64> = self.read_va(&img, tls_va + 3 * ptr, ptr) else {
            return;
        };
        if callbacks_va == 0 {
            return;
        }
        for i in 0..crate::packers::emulated_unpack::MAX_TLS_CALLBACKS as u64 {
            let Some(callback): Option<u64> = self.read_va(&img, callbacks_va + i * ptr, ptr)
            else {
                break;
            };
            if callback == 0 {
                break;
            }
            let anchor: Anchor = Anchor {
                address: callback,
                instruction: "tls callback".to_owned(),
                pattern: format!(
                    "IMAGE_TLS_DIRECTORY at {tls_va:#x} lists callback {callback:#x}, which runs before the entry point"
                ),
            };
            self.plan.refusals.push(Refusal {
                check: RuntimeCheck::TlsCallback,
                anchor,
                reason: "pre-entry code is program structure; the stub emulator runs it in its sandbox before the entry point instead of patching it out".to_owned(),
            });
        }
    }

    fn read_va(
        &self,
        img: &crate::packers::pe_sections::PeImage,
        va: u64,
        ptr: u64,
    ) -> Option<u64> {
        let rva: u32 = u32::try_from(va.checked_sub(img.image_base)?).ok()?;
        let offset: usize = img.file_offset_for_rva(rva, self.bytes.len()).ok()?;
        let end: usize = offset.checked_add(ptr as usize)?;
        let slice: &[u8] = self.bytes.get(offset..end)?;
        Some(if ptr == 8 {
            u64::from_le_bytes(slice.try_into().ok()?)
        } else {
            u64::from(u32::from_le_bytes(slice.try_into().ok()?))
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn multi_byte_nops_cover_every_length_exactly() {
        for len in 1..=20usize {
            let nop: Vec<u8> = multi_byte_nop(len);
            assert_eq!(nop.len(), len);
            let decoded: Vec<Instruction> = decode(64, &nop, 0x1000);
            assert!(
                decoded
                    .iter()
                    .all(|i: &Instruction| i.mnemonic() == Mnemonic::Nop),
                "{len}: {decoded:?}"
            );
        }
    }

    #[test]
    fn branch_patches_keep_the_instruction_length_and_target() {
        let short: [u8; 2] = [0x74, 0x10];
        let short_insn: Instruction = decode(64, &short, 0x1000)[0];
        assert_eq!(
            branch_patch(&short_insn, &short, BranchFix::ForceJump).unwrap(),
            vec![0xEB, 0x10]
        );
        assert_eq!(
            branch_patch(&short_insn, &short, BranchFix::NeverJump).unwrap(),
            vec![0x90, 0x90]
        );
        let near: [u8; 6] = [0x0F, 0x87, 0x44, 0x33, 0x22, 0x11];
        let near_insn: Instruction = decode(64, &near, 0x1000)[0];
        let forced: Vec<u8> = branch_patch(&near_insn, &near, BranchFix::ForceJump).unwrap();
        let forced_insns: Vec<Instruction> = decode(64, &forced, 0x1000);
        assert_eq!(forced_insns.len(), 2);
        assert_eq!(forced_insns[1].mnemonic(), Mnemonic::Jmp);
        assert_eq!(
            forced_insns[1].near_branch_target(),
            near_insn.near_branch_target(),
            "the forced jump lands where the conditional jump went"
        );
        assert_eq!(
            branch_patch(&near_insn, &near, BranchFix::NeverJump)
                .unwrap()
                .len(),
            6
        );
    }

    #[test]
    fn register_clears_fit_the_replaced_load() {
        let movzx: Vec<u8> = zero_register_patch(64, Register::EAX, 0x1000, 4).unwrap();
        assert_eq!(movzx.len(), 4);
        let decoded: Vec<Instruction> = decode(64, &movzx, 0x1000);
        assert_eq!(decoded[0].mnemonic(), Mnemonic::Xor);
        assert_eq!(decoded[0].op0_register(), Register::EAX);
        let r9: Vec<u8> = zero_register_patch(64, Register::R9D, 0x1000, 7).unwrap();
        assert_eq!(r9.len(), 7);
        assert!(zero_register_patch(64, Register::R9D, 0x1000, 2).is_none());
        let x86: Vec<u8> = zero_register_patch(32, Register::ECX, 0x1000, 3).unwrap();
        assert_eq!(x86.len(), 3);
        let x86_insns: Vec<Instruction> = decode(32, &x86, 0x1000);
        assert_eq!(x86_insns.len(), 2);
        assert_eq!(x86_insns[0].mnemonic(), Mnemonic::Xor);
        assert_eq!(x86_insns[0].op0_register(), Register::ECX);
        assert_eq!(x86_insns[0].op1_register(), Register::ECX);
        assert_eq!(x86_insns[1].mnemonic(), Mnemonic::Nop);
    }

    #[test]
    fn garbage_input_is_a_typed_parse_error_not_a_panic() {
        assert!(matches!(
            plan_runtime_check_neutralization(b"not an object"),
            Err(Error::ObjectParse(_))
        ));
    }
}
