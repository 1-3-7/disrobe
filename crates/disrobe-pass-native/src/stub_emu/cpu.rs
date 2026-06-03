//! Fetch / decode / execute loop driven by `iced-x86`.

use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register,
};

use crate::error::{Error, Result};
use crate::stub_emu::mem::{Memory, Perm};
use crate::stub_emu::regs::{CpuMode, Reg, Regs, classify, classify_mm};

/// Reason the emulator returned control to the host.
#[derive(Debug, Clone)]
pub enum ExitReason {
    /// Instruction-count budget exhausted.
    StepCap(u64),
    /// Branched into a page that is not mapped - taken as OEP transfer.
    JumpedOutOfRange { from: u64, to: u64 },
    /// A host call (Win32 import) requested termination of emulation.
    HostHalt(String),
    /// Emulator hit an opcode it doesn't implement.
    UnsupportedInstr { ip: u64, mnemonic: String },
    /// A guest exception (read-from-unmapped, divide-by-zero, etc).
    GuestFault(String),
}

/// Callback the emulator invokes for `call dword ptr [addr]` thunks that
/// dereference into a host-managed Win32 import shim.
pub trait HostCall {
    /// Invoked when the emulator is about to dispatch a CALL whose target
    /// address falls outside any mapped page. Implementations should consult
    /// their shim table, mutate `regs` / `mem` to reflect the call's effect,
    /// and return either `Ok(true)` (continue at the address now in
    /// `regs.rip`, which the host has set, typically to the return address
    /// already popped) or `Ok(false)` (stop emulation, surfacing
    /// `ExitReason::HostHalt`).
    fn dispatch(&mut self, target: u64, regs: &mut Regs, mem: &mut Memory) -> Result<bool>;
}

/// Marker host that refuses every Win32 import call.
#[derive(Debug, Default)]
pub struct NoopHost;

impl HostCall for NoopHost {
    fn dispatch(&mut self, _target: u64, _regs: &mut Regs, _mem: &mut Memory) -> Result<bool> {
        Ok(false)
    }
}

/// Stub-emulator core.
#[derive(Debug)]
pub struct Cpu {
    pub regs: Regs,
    pub mem: Memory,
    pub mode: CpuMode,
    fs_base: u64,
    gs_base: u64,
    seh_dispatch: bool,
}

impl Cpu {
    #[must_use]
    pub fn new(mode: CpuMode) -> Self {
        Self {
            regs: Regs::new(mode),
            mem: Memory::new(),
            mode,
            fs_base: 0,
            gs_base: 0,
            seh_dispatch: false,
        }
    }

    /// Enable structured-exception-handling dispatch on guest memory faults.
    ///
    /// PECompact 2.x (and other SEH-driven packers) deliberately raise an access
    /// violation - typically `mov [eax], ecx` with `eax = 0` - to transfer
    /// control into the decompressor installed as the current SEH handler. When
    /// enabled, a guest fault is not surfaced as [`ExitReason::GuestFault`];
    /// instead the emulator reads the `EXCEPTION_REGISTRATION_RECORD` at
    /// `fs:[0]`, sets `EAX = ContinueExecution(0)` per the handler ABI, pushes a
    /// synthetic return frame, and transfers to the handler. The handler chain is
    /// walked at most [`Self::SEH_MAX_DEPTH`] deep so a corrupt chain cannot spin.
    pub fn enable_seh_dispatch(&mut self) {
        self.seh_dispatch = true;
        self.mem.block_null_page();
    }

    const SEH_MAX_DEPTH: u32 = 16;
    const SEH_END_OF_CHAIN: u64 = 0xFFFF_FFFF;

    /// Set the linear base address that an `fs:`-prefixed memory operand adds
    /// to its computed effective address. On Win32 the FS segment points at the
    /// Thread Environment Block; packer stubs read `fs:[0]` (the SEH chain head)
    /// and `fs:[0x18]` (the TEB self-pointer) during bootstrap. Mapping a
    /// synthetic TEB and pointing FS at it lets the emulator service those reads
    /// instead of faulting on linear address 0.
    pub fn set_fs_base(&mut self, base: u64) {
        self.fs_base = base;
    }

    /// Set the linear base address that a `gs:`-prefixed memory operand adds to
    /// its computed effective address (x64 TEB convention).
    pub fn set_gs_base(&mut self, base: u64) {
        self.gs_base = base;
    }

    /// Run until exhaustion, OEP-jump, or unsupported opcode.
    pub fn run<H: HostCall>(&mut self, host: &mut H, step_cap: u64) -> Result<ExitReason> {
        let trace: bool = std::env::var_os("STUB_EMU_TRACE").is_some();
        let mut histogram: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        let mut ring: std::collections::VecDeque<(u64, String, u64)> =
            std::collections::VecDeque::with_capacity(40);
        let mut steps: u64 = 0;
        let result: ExitReason = loop {
            if steps >= step_cap {
                break ExitReason::StepCap(steps);
            }
            steps += 1;
            let ip: u64 = self.regs.rip;
            if !self.mem.is_mapped(ip) {
                break ExitReason::JumpedOutOfRange { from: ip, to: ip };
            }
            let bytes: Vec<u8> = self.mem.read_lossy(ip, 16);
            let mut decoder: Decoder<'_> =
                Decoder::with_ip(self.mode.bits(), &bytes, ip, DecoderOptions::NONE);
            let mut insn: Instruction = Instruction::default();
            decoder.decode_out(&mut insn);
            if insn.is_invalid() {
                break ExitReason::UnsupportedInstr {
                    ip,
                    mnemonic: "INVALID".to_owned(),
                };
            }
            if trace {
                let key: String = format!("{:?}", insn.code());
                *histogram.entry(key.clone()).or_insert(0) += 1;
                if ring.len() == 40 {
                    ring.pop_front();
                }
                ring.push_back((ip, key, self.regs.get(Reg::Rsp)));
            }
            let next_ip: u64 = insn.next_ip();
            self.regs.rip = next_ip;
            match self.execute_one(&insn, host) {
                Ok(Some(reason)) => break reason,
                Ok(None) => {}
                Err(e) => {
                    if self.seh_dispatch && self.dispatch_seh(ip) {
                        continue;
                    }
                    break ExitReason::GuestFault(e.to_string());
                }
            }
        };
        if trace {
            eprintln!("STUB_EMU_TRACE exit={result:?} steps={steps}");
            eprintln!("STUB_EMU_TRACE last 40 instructions before exit:");
            for (ip, code, sp) in &ring {
                eprintln!("  ip=0x{ip:08x} {code} rsp=0x{sp:08x}");
            }
            let mut by_count: Vec<(&String, &u64)> = histogram.iter().collect();
            by_count.sort_by(|a: &(&String, &u64), b: &(&String, &u64)| b.1.cmp(a.1));
            eprintln!("STUB_EMU_TRACE opcode histogram (top 40):");
            for (code, count) in by_count.iter().take(40) {
                eprintln!("  {count:>10} {code}");
            }
        }
        Ok(result)
    }

    /// Dispatch a guest access violation to the current Win32 SEH handler.
    ///
    /// Reads the `EXCEPTION_REGISTRATION_RECORD` head at `fs:[0]`, builds the
    /// standard x86 dispatch frame - a synthetic `EXCEPTION_RECORD`, a `CONTEXT`
    /// capturing the faulting register state (notably `CONTEXT.Eip = fault_ip`),
    /// and the four handler arguments - then transfers to the handler. PECompact
    /// installs its decompressor as this handler; it inspects the `CONTEXT`,
    /// rewrites `Eip` to the next stage, and the dispatch frame's resume path
    /// continues there. Returns `true` if a handler was found and entered.
    fn dispatch_seh(&mut self, fault_ip: u64) -> bool {
        if self.mode != CpuMode::Bits32 {
            return false;
        }
        let chain_head: u64 = match self.mem.read_u32(self.fs_base) {
            Ok(v) => u64::from(v),
            Err(_) => return false,
        };
        let mut record: u64 = chain_head;
        let mut depth: u32 = 0;
        while record != Self::SEH_END_OF_CHAIN && record != 0 && depth < Self::SEH_MAX_DEPTH {
            let handler: u64 = match self.mem.read_u32(record.wrapping_add(4)) {
                Ok(v) => u64::from(v),
                Err(_) => return false,
            };
            if self.mem.is_mapped(handler) {
                return self.enter_seh_handler(handler, record, fault_ip);
            }
            let next: u64 = match self.mem.read_u32(record) {
                Ok(v) => u64::from(v),
                Err(_) => return false,
            };
            if next == record {
                break;
            }
            record = next;
            depth += 1;
        }
        false
    }

    fn enter_seh_handler(&mut self, handler: u64, frame: u64, fault_ip: u64) -> bool {
        const CONTEXT_EAX: u64 = 0xB0;
        const CONTEXT_EIP: u64 = 0xB8;
        let ctx: u64 = self.regs.get(Reg::Rsp).wrapping_sub(0x400) & !0xFu64;
        let exc_rec: u64 = ctx.wrapping_sub(0x100);
        if self.mem.write_u32(exc_rec, 0xC000_0005).is_err() {
            return false;
        }
        let _ = self.mem.write_u32(exc_rec + 4, 0);
        let _ = self.mem.write_u32(exc_rec + 8, 0);
        let _ = self.mem.write_u32(exc_rec + 12, fault_ip as u32);
        for off in (0..0x2cc).step_by(4) {
            let _ = self.mem.write_u32(ctx + off, 0);
        }
        let _ = self
            .mem
            .write_u32(ctx + CONTEXT_EAX, self.regs.get(Reg::Rax) as u32);
        let _ = self
            .mem
            .write_u32(ctx + CONTEXT_EAX + 4, self.regs.get(Reg::Rcx) as u32);
        let _ = self
            .mem
            .write_u32(ctx + CONTEXT_EAX + 8, self.regs.get(Reg::Rdx) as u32);
        let _ = self
            .mem
            .write_u32(ctx + CONTEXT_EAX + 12, self.regs.get(Reg::Rbx) as u32);
        let _ = self
            .mem
            .write_u32(ctx + CONTEXT_EAX + 16, self.regs.get(Reg::Rsp) as u32);
        let _ = self
            .mem
            .write_u32(ctx + CONTEXT_EAX + 20, self.regs.get(Reg::Rbp) as u32);
        let _ = self
            .mem
            .write_u32(ctx + CONTEXT_EAX + 24, self.regs.get(Reg::Rsi) as u32);
        let _ = self
            .mem
            .write_u32(ctx + CONTEXT_EAX + 28, self.regs.get(Reg::Rdi) as u32);
        let _ = self.mem.write_u32(ctx + CONTEXT_EIP, fault_ip as u32);
        let dispatcher: u64 = ctx.wrapping_sub(0x200);
        let mut sp: u64 = ctx.wrapping_sub(0x40) & !0xFu64;
        let push = |cpu: &mut Self, sp: &mut u64, v: u64| {
            *sp = sp.wrapping_sub(4);
            let _ = cpu.mem.write_u32(*sp, v as u32);
        };
        push(self, &mut sp, dispatcher);
        push(self, &mut sp, ctx);
        push(self, &mut sp, frame);
        push(self, &mut sp, exc_rec);
        push(self, &mut sp, fault_ip);
        self.regs.set(Reg::Rsp, sp);
        self.regs.rip = handler;
        true
    }

    #[allow(clippy::too_many_lines)]
    fn execute_one<H: HostCall>(
        &mut self,
        insn: &Instruction,
        host: &mut H,
    ) -> Result<Option<ExitReason>> {
        let code: Code = insn.code();
        let mnem: &str = format!("{:?}", insn.mnemonic()).leak();
        match insn.flow_control() {
            FlowControl::Next => {}
            FlowControl::UnconditionalBranch => {
                let target: u64 = self.branch_target(insn)?;
                if !self.mem.is_mapped(target) {
                    return Ok(Some(ExitReason::JumpedOutOfRange {
                        from: insn.ip(),
                        to: target,
                    }));
                }
                self.regs.rip = target;
                return Ok(None);
            }
            FlowControl::ConditionalBranch => {
                use iced_x86::Mnemonic as M;
                let mnem: iced_x86::Mnemonic = insn.mnemonic();
                if matches!(
                    mnem,
                    M::Loop | M::Loope | M::Loopne | M::Jrcxz | M::Jcxz | M::Jecxz
                ) {
                    let _ = self.try_data_op(insn, insn.code())?;
                    return Ok(None);
                }
                let take: bool = self.cond_true(insn.condition_code());
                if take {
                    let target: u64 = self.branch_target(insn)?;
                    if !self.mem.is_mapped(target) {
                        return Ok(Some(ExitReason::JumpedOutOfRange {
                            from: insn.ip(),
                            to: target,
                        }));
                    }
                    self.regs.rip = target;
                }
                return Ok(None);
            }
            FlowControl::Call => {
                let target: u64 = self.branch_target(insn)?;
                let ret_ip: u64 = insn.next_ip();
                self.push(ret_ip)?;
                if !self.mem.is_mapped(target) {
                    let ret: u64 = self.pop()?;
                    let cont: bool = host.dispatch(target, &mut self.regs, &mut self.mem)?;
                    if !cont {
                        return Ok(Some(ExitReason::HostHalt(format!(
                            "host refused call to 0x{target:016x}"
                        ))));
                    }
                    self.regs.rip = ret;
                    return Ok(None);
                }
                self.regs.rip = target;
                return Ok(None);
            }
            FlowControl::Return => {
                let ret: u64 = self.pop()?;
                if !self.mem.is_mapped(ret) {
                    return Ok(Some(ExitReason::JumpedOutOfRange {
                        from: insn.ip(),
                        to: ret,
                    }));
                }
                if insn.code() == Code::Retnq_imm16
                    || insn.code() == Code::Retnd_imm16
                    || insn.code() == Code::Retnw_imm16
                {
                    let extra: u64 = u64::from(insn.immediate16());
                    let new_sp: u64 = self.regs.get(Reg::Rsp).wrapping_add(extra);
                    self.regs.set(Reg::Rsp, new_sp);
                }
                self.regs.rip = ret;
                return Ok(None);
            }
            FlowControl::IndirectBranch => {
                let target: u64 = self.indirect_target(insn)?;
                if !self.mem.is_mapped(target) {
                    return Ok(Some(ExitReason::JumpedOutOfRange {
                        from: insn.ip(),
                        to: target,
                    }));
                }
                self.regs.rip = target;
                return Ok(None);
            }
            FlowControl::IndirectCall => {
                let target: u64 = self.indirect_target(insn)?;
                let ret_ip: u64 = insn.next_ip();
                self.push(ret_ip)?;
                if !self.mem.is_mapped(target) {
                    let ret: u64 = self.pop()?;
                    let cont: bool = host.dispatch(target, &mut self.regs, &mut self.mem)?;
                    if !cont {
                        return Ok(Some(ExitReason::HostHalt(format!(
                            "host refused indirect call to 0x{target:016x}"
                        ))));
                    }
                    self.regs.rip = ret;
                    return Ok(None);
                }
                self.regs.rip = target;
                return Ok(None);
            }
            FlowControl::Interrupt | FlowControl::XbeginXabortXend | FlowControl::Exception => {
                return Ok(Some(ExitReason::UnsupportedInstr {
                    ip: insn.ip(),
                    mnemonic: mnem.to_owned(),
                }));
            }
        }

        if let Some(handled) = self.try_string_op(insn)? {
            if handled {
                return Ok(None);
            }
        }
        if self.try_data_op(insn, code)? {
            return Ok(None);
        }
        if self.try_mmx_op(insn)? {
            return Ok(None);
        }
        Ok(Some(ExitReason::UnsupportedInstr {
            ip: insn.ip(),
            mnemonic: format!("{code:?}"),
        }))
    }

    fn branch_target(&self, insn: &Instruction) -> Result<u64> {
        match insn.op0_kind() {
            OpKind::NearBranch16 => Ok(u64::from(insn.near_branch16())),
            OpKind::NearBranch32 => Ok(u64::from(insn.near_branch32())),
            OpKind::NearBranch64 => Ok(insn.near_branch64()),
            OpKind::FarBranch16 | OpKind::FarBranch32 => {
                Err(Error::GoblinParse("far branch not supported".into()))
            }
            _ => self.indirect_target(insn),
        }
    }

    fn indirect_target(&self, insn: &Instruction) -> Result<u64> {
        let target: u64 = match insn.op0_kind() {
            OpKind::Register => self.read_reg(insn.op0_register())?,
            OpKind::Memory => self.read_mem_operand(insn, 0)?,
            _ => return Err(Error::GoblinParse("unsupported branch operand".into())),
        };
        Ok(target)
    }

    fn cond_true(&self, c: ConditionCode) -> bool {
        let f: &crate::stub_emu::regs::Flags = &self.regs.flags;
        match c {
            ConditionCode::None => true,
            ConditionCode::o => f.of,
            ConditionCode::no => !f.of,
            ConditionCode::b => f.cf,
            ConditionCode::ae => !f.cf,
            ConditionCode::e => f.zf,
            ConditionCode::ne => !f.zf,
            ConditionCode::be => f.cf || f.zf,
            ConditionCode::a => !f.cf && !f.zf,
            ConditionCode::s => f.sf,
            ConditionCode::ns => !f.sf,
            ConditionCode::p => f.pf,
            ConditionCode::np => !f.pf,
            ConditionCode::l => f.sf != f.of,
            ConditionCode::ge => f.sf == f.of,
            ConditionCode::le => f.zf || (f.sf != f.of),
            ConditionCode::g => !f.zf && (f.sf == f.of),
        }
    }

    fn push(&mut self, v: u64) -> Result<()> {
        let ps: u8 = self.mode.ptr_size();
        let sp: u64 = self.regs.get(Reg::Rsp).wrapping_sub(u64::from(ps));
        self.regs.set(Reg::Rsp, sp);
        if ps == 4 {
            self.mem.write_u32(sp, v as u32)
        } else {
            self.mem.write_u64(sp, v)
        }
    }

    fn pop(&mut self) -> Result<u64> {
        let ps: u8 = self.mode.ptr_size();
        let sp: u64 = self.regs.get(Reg::Rsp);
        let v: u64 = if ps == 4 {
            u64::from(self.mem.read_u32(sp)?)
        } else {
            self.mem.read_u64(sp)?
        };
        self.regs.set(Reg::Rsp, sp.wrapping_add(u64::from(ps)));
        Ok(v)
    }

    fn read_reg(&self, r: Register) -> Result<u64> {
        let (lg, size, high): (Reg, u8, bool) =
            classify(r).ok_or_else(|| Error::GoblinParse(format!("unsupported register {r:?}")))?;
        Ok(if high {
            self.regs.read_high8(lg)
        } else {
            self.regs.read_sized(lg, size)
        })
    }

    fn write_reg(&mut self, r: Register, value: u64) -> Result<()> {
        let (lg, size, high): (Reg, u8, bool) =
            classify(r).ok_or_else(|| Error::GoblinParse(format!("unsupported register {r:?}")))?;
        if high {
            self.regs.write_high8(lg, value);
        } else {
            self.regs.write_sized(lg, value, size);
        }
        Ok(())
    }

    fn effective_addr(&self, insn: &Instruction, operand: u32) -> Result<u64> {
        let base: u64 = if insn.memory_base() != Register::None {
            self.read_reg(insn.memory_base())?
        } else {
            0
        };
        let index_reg: Register = insn.memory_index();
        let index_val: u64 = if index_reg != Register::None {
            self.read_reg(index_reg)?
        } else {
            0
        };
        let scale: u64 = u64::from(insn.memory_index_scale());
        let disp: u64 = insn.memory_displacement64();
        let _ = operand;
        let mut addr: u64 = base
            .wrapping_add(index_val.wrapping_mul(scale))
            .wrapping_add(disp);
        if insn.memory_size().size() == 4 || self.mode == CpuMode::Bits32 {
            addr &= 0xFFFF_FFFF;
        }
        addr = match insn.segment_prefix() {
            Register::FS => addr.wrapping_add(self.fs_base),
            Register::GS => addr.wrapping_add(self.gs_base),
            _ => addr,
        };
        Ok(addr)
    }

    fn mem_size_bits(insn: &Instruction) -> u8 {
        let s: usize = insn.memory_size().size();
        match s {
            1 => 8,
            2 => 16,
            4 => 32,
            8 => 64,
            _ => 32,
        }
    }

    fn read_mem_operand(&self, insn: &Instruction, operand: u32) -> Result<u64> {
        let addr: u64 = self.effective_addr(insn, operand)?;
        let bits: u8 = Self::mem_size_bits(insn);
        Ok(match bits {
            8 => u64::from(self.mem.read_u8(addr)?),
            16 => u64::from(self.mem.read_u16(addr)?),
            32 => u64::from(self.mem.read_u32(addr)?),
            _ => self.mem.read_u64(addr)?,
        })
    }

    fn write_mem_operand(&mut self, insn: &Instruction, operand: u32, value: u64) -> Result<()> {
        let addr: u64 = self.effective_addr(insn, operand)?;
        let bits: u8 = Self::mem_size_bits(insn);
        match bits {
            8 => self.mem.write_u8(addr, value as u8),
            16 => self.mem.write_u16(addr, value as u16),
            32 => self.mem.write_u32(addr, value as u32),
            _ => self.mem.write_u64(addr, value),
        }
    }

    fn read_operand(&self, insn: &Instruction, operand: u32) -> Result<u64> {
        match insn.op_kind(operand) {
            OpKind::Register => self.read_reg(insn.op_register(operand)),
            OpKind::Memory => self.read_mem_operand(insn, operand),
            OpKind::Immediate8 => Ok(u64::from(insn.immediate8())),
            OpKind::Immediate8_2nd => Ok(u64::from(insn.immediate8_2nd())),
            OpKind::Immediate16 => Ok(u64::from(insn.immediate16())),
            OpKind::Immediate32 => Ok(u64::from(insn.immediate32())),
            OpKind::Immediate64 => Ok(insn.immediate64()),
            OpKind::Immediate8to16 => Ok(insn.immediate8to16() as u64),
            OpKind::Immediate8to32 => Ok(insn.immediate8to32() as u64),
            OpKind::Immediate8to64 => Ok(insn.immediate8to64() as u64),
            OpKind::Immediate32to64 => Ok(insn.immediate32to64() as u64),
            _ => Err(Error::GoblinParse(format!(
                "unsupported operand kind {:?}",
                insn.op_kind(operand)
            ))),
        }
    }

    fn write_operand(&mut self, insn: &Instruction, operand: u32, value: u64) -> Result<()> {
        match insn.op_kind(operand) {
            OpKind::Register => self.write_reg(insn.op_register(operand), value),
            OpKind::Memory => self.write_mem_operand(insn, operand, value),
            _ => Err(Error::GoblinParse(format!(
                "cannot write to operand kind {:?}",
                insn.op_kind(operand)
            ))),
        }
    }

    fn operand_size_bits(insn: &Instruction, operand: u32) -> u8 {
        match insn.op_kind(operand) {
            OpKind::Register => match insn.op_register(operand).size() {
                1 => 8,
                2 => 16,
                4 => 32,
                _ => 64,
            },
            OpKind::Memory => Self::mem_size_bits(insn),
            _ => match insn.op_kind(operand) {
                OpKind::Immediate8 | OpKind::Immediate8_2nd => 8,
                OpKind::Immediate16 => 16,
                OpKind::Immediate32 | OpKind::Immediate8to32 => 32,
                OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => 64,
                OpKind::Immediate8to16 => 16,
                _ => 64,
            },
        }
    }

    fn mask(bits: u8) -> u64 {
        if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits).wrapping_sub(1)
        }
    }

    fn sign_bit(bits: u8) -> u64 {
        1u64 << (bits - 1)
    }

    fn set_logical_flags(&mut self, result: u64, bits: u8) {
        let m: u64 = Self::mask(bits);
        let r: u64 = result & m;
        self.regs.flags.cf = false;
        self.regs.flags.of = false;
        self.regs.flags.zf = r == 0;
        self.regs.flags.sf = (r & Self::sign_bit(bits)) != 0;
        self.regs.flags.pf = (r as u8).count_ones() % 2 == 0;
    }

    fn set_arith_flags(
        &mut self,
        a: u64,
        b: u64,
        result: u64,
        bits: u8,
        is_sub: bool,
        _with_carry_in: bool,
    ) {
        let m: u64 = Self::mask(bits);
        let sb: u64 = Self::sign_bit(bits);
        let r: u64 = result & m;
        let a_s: u64 = a & m;
        let b_s: u64 = b & m;
        self.regs.flags.zf = r == 0;
        self.regs.flags.sf = (r & sb) != 0;
        self.regs.flags.pf = (r as u8).count_ones() % 2 == 0;
        if is_sub {
            self.regs.flags.cf = a_s < b_s;
            let av: bool = (a_s & sb) != 0;
            let bv: bool = (b_s & sb) != 0;
            let rv: bool = (r & sb) != 0;
            self.regs.flags.of = (av != bv) && (rv != av);
        } else {
            let sum_full: u128 = u128::from(a_s) + u128::from(b_s);
            self.regs.flags.cf = sum_full >> bits != 0;
            let av: bool = (a_s & sb) != 0;
            let bv: bool = (b_s & sb) != 0;
            let rv: bool = (r & sb) != 0;
            self.regs.flags.of = (av == bv) && (rv != av);
        }
        self.regs.flags.af = ((a_s ^ b_s ^ r) & 0x10) != 0;
    }

    #[allow(clippy::too_many_lines)]
    fn try_data_op(&mut self, insn: &Instruction, code: Code) -> Result<bool> {
        let mnem: iced_x86::Mnemonic = insn.mnemonic();
        use iced_x86::Mnemonic as M;
        match mnem {
            M::Mov => {
                let v: u64 = self.read_operand(insn, 1)?;
                self.write_operand(insn, 0, v)?;
                Ok(true)
            }
            M::Movzx => {
                let v: u64 = self.read_operand(insn, 1)?;
                let src_bits: u8 = Self::operand_size_bits(insn, 1);
                let m: u64 = Self::mask(src_bits);
                self.write_operand(insn, 0, v & m)?;
                Ok(true)
            }
            M::Movsx | M::Movsxd => {
                let v: u64 = self.read_operand(insn, 1)?;
                let src_bits: u8 = Self::operand_size_bits(insn, 1);
                let dst_bits: u8 = Self::operand_size_bits(insn, 0);
                let m_src: u64 = Self::mask(src_bits);
                let sb: u64 = Self::sign_bit(src_bits);
                let val: u64 = v & m_src;
                let extended: u64 = if (val & sb) != 0 { val | !m_src } else { val };
                self.write_operand(insn, 0, extended & Self::mask(dst_bits))?;
                Ok(true)
            }
            M::Lea => {
                let addr: u64 = self.effective_addr(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                self.write_operand(insn, 0, addr & Self::mask(bits))?;
                Ok(true)
            }
            M::Xchg => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                self.write_operand(insn, 0, b)?;
                self.write_operand(insn, 1, a)?;
                Ok(true)
            }
            M::Push => {
                let v: u64 = self.read_operand(insn, 0)?;
                let bits: u8 =
                    if matches!(code, Code::Push_r16 | Code::Push_rm16 | Code::Push_imm16) {
                        16
                    } else {
                        u8::from(self.mode.ptr_size() * 8)
                    };
                let m: u64 = Self::mask(bits);
                let ps: u8 = bits / 8;
                let sp: u64 = self.regs.get(Reg::Rsp).wrapping_sub(u64::from(ps));
                self.regs.set(Reg::Rsp, sp);
                if ps == 2 {
                    self.mem.write_u16(sp, (v & m) as u16)?;
                } else if ps == 4 {
                    self.mem.write_u32(sp, (v & m) as u32)?;
                } else {
                    self.mem.write_u64(sp, v & m)?;
                }
                Ok(true)
            }
            M::Pop => {
                let bits: u8 = if matches!(code, Code::Pop_r16 | Code::Pop_rm16) {
                    16
                } else {
                    u8::from(self.mode.ptr_size() * 8)
                };
                let ps: u8 = bits / 8;
                let sp: u64 = self.regs.get(Reg::Rsp);
                let v: u64 = if ps == 2 {
                    u64::from(self.mem.read_u16(sp)?)
                } else if ps == 4 {
                    u64::from(self.mem.read_u32(sp)?)
                } else {
                    self.mem.read_u64(sp)?
                };
                self.regs.set(Reg::Rsp, sp.wrapping_add(u64::from(ps)));
                self.write_operand(insn, 0, v)?;
                Ok(true)
            }
            M::Pushad | M::Pusha => {
                let eax: u64 = self.regs.get(Reg::Rax);
                let ecx: u64 = self.regs.get(Reg::Rcx);
                let edx: u64 = self.regs.get(Reg::Rdx);
                let ebx: u64 = self.regs.get(Reg::Rbx);
                let esp_orig: u64 = self.regs.get(Reg::Rsp);
                let ebp: u64 = self.regs.get(Reg::Rbp);
                let esi: u64 = self.regs.get(Reg::Rsi);
                let edi: u64 = self.regs.get(Reg::Rdi);
                for v in [eax, ecx, edx, ebx, esp_orig, ebp, esi, edi] {
                    let sp: u64 = self.regs.get(Reg::Rsp).wrapping_sub(4);
                    self.regs.set(Reg::Rsp, sp);
                    self.mem.write_u32(sp, v as u32)?;
                }
                Ok(true)
            }
            M::Popad | M::Popa => {
                let mut vals: [u64; 8] = [0u64; 8];
                for v in vals.iter_mut() {
                    let sp: u64 = self.regs.get(Reg::Rsp);
                    *v = u64::from(self.mem.read_u32(sp)?);
                    self.regs.set(Reg::Rsp, sp.wrapping_add(4));
                }
                let [edi, esi, ebp, _esp_skip, ebx, edx, ecx, eax] = vals;
                self.regs.write_sized(Reg::Rdi, edi, 32);
                self.regs.write_sized(Reg::Rsi, esi, 32);
                self.regs.write_sized(Reg::Rbp, ebp, 32);
                self.regs.write_sized(Reg::Rbx, ebx, 32);
                self.regs.write_sized(Reg::Rdx, edx, 32);
                self.regs.write_sized(Reg::Rcx, ecx, 32);
                self.regs.write_sized(Reg::Rax, eax, 32);
                Ok(true)
            }
            M::Pushfd | M::Pushfq | M::Pushf => {
                let eflags: u64 = self.encode_flags();
                let ps: u8 = self.mode.ptr_size();
                let sp: u64 = self.regs.get(Reg::Rsp).wrapping_sub(u64::from(ps));
                self.regs.set(Reg::Rsp, sp);
                if ps == 4 {
                    self.mem.write_u32(sp, eflags as u32)?;
                } else {
                    self.mem.write_u64(sp, eflags)?;
                }
                Ok(true)
            }
            M::Popfd | M::Popfq | M::Popf => {
                let ps: u8 = self.mode.ptr_size();
                let sp: u64 = self.regs.get(Reg::Rsp);
                let v: u64 = if ps == 4 {
                    u64::from(self.mem.read_u32(sp)?)
                } else {
                    self.mem.read_u64(sp)?
                };
                self.regs.set(Reg::Rsp, sp.wrapping_add(u64::from(ps)));
                self.decode_flags(v);
                Ok(true)
            }
            M::Add => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a.wrapping_add(b);
                self.set_arith_flags(a, b, r, bits, false, false);
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Adc => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let cin: u64 = u64::from(self.regs.flags.cf);
                let m: u64 = Self::mask(bits);
                let sb: u64 = Self::sign_bit(bits);
                let a_m: u64 = a & m;
                let b_m: u64 = b & m;
                let sum_full: u128 = u128::from(a_m) + u128::from(b_m) + u128::from(cin);
                let r: u64 = sum_full as u64 & m;
                self.regs.flags.zf = r == 0;
                self.regs.flags.sf = (r & sb) != 0;
                self.regs.flags.pf = (r as u8).count_ones() % 2 == 0;
                self.regs.flags.cf = sum_full >> bits != 0;
                let av: bool = (a_m & sb) != 0;
                let bv: bool = (b_m & sb) != 0;
                let rv: bool = (r & sb) != 0;
                self.regs.flags.of = (av == bv) && (rv != av);
                self.regs.flags.af = ((a_m ^ b_m ^ r) & 0x10) != 0;
                self.write_operand(insn, 0, r)?;
                Ok(true)
            }
            M::Sub => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a.wrapping_sub(b);
                self.set_arith_flags(a, b, r, bits, true, false);
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Sbb => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let cin: u64 = u64::from(self.regs.flags.cf);
                let m: u64 = Self::mask(bits);
                let sb: u64 = Self::sign_bit(bits);
                let a_m: u64 = a & m;
                let b_m: u64 = b & m;
                let total_sub: u128 = u128::from(b_m) + u128::from(cin);
                let r: u64 = a_m.wrapping_sub(b_m).wrapping_sub(cin) & m;
                self.regs.flags.zf = r == 0;
                self.regs.flags.sf = (r & sb) != 0;
                self.regs.flags.pf = (r as u8).count_ones() % 2 == 0;
                self.regs.flags.cf = u128::from(a_m) < total_sub;
                let av: bool = (a_m & sb) != 0;
                let bv: bool = (b_m & sb) != 0;
                let rv: bool = (r & sb) != 0;
                self.regs.flags.of = (av != bv) && (rv != av);
                self.regs.flags.af = ((a_m ^ b_m ^ r) & 0x10) != 0;
                self.write_operand(insn, 0, r)?;
                Ok(true)
            }
            M::Cmp => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a.wrapping_sub(b);
                self.set_arith_flags(a, b, r, bits, true, false);
                Ok(true)
            }
            M::Test => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                self.set_logical_flags(a & b, bits);
                Ok(true)
            }
            M::And => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a & b;
                self.set_logical_flags(r, bits);
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Or => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a | b;
                self.set_logical_flags(r, bits);
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Xor => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a ^ b;
                self.set_logical_flags(r, bits);
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Not => {
                let a: u64 = self.read_operand(insn, 0)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                self.write_operand(insn, 0, (!a) & Self::mask(bits))?;
                Ok(true)
            }
            M::Neg => {
                let a: u64 = self.read_operand(insn, 0)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = 0u64.wrapping_sub(a);
                self.set_arith_flags(0, a, r, bits, true, false);
                self.regs.flags.cf = (a & Self::mask(bits)) != 0;
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Inc => {
                let a: u64 = self.read_operand(insn, 0)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a.wrapping_add(1);
                let cf_save: bool = self.regs.flags.cf;
                self.set_arith_flags(a, 1, r, bits, false, false);
                self.regs.flags.cf = cf_save;
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Dec => {
                let a: u64 = self.read_operand(insn, 0)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a.wrapping_sub(1);
                let cf_save: bool = self.regs.flags.cf;
                self.set_arith_flags(a, 1, r, bits, true, false);
                self.regs.flags.cf = cf_save;
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Shl | M::Sal => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = if b == 0 {
                    a
                } else {
                    (a & Self::mask(bits)).wrapping_shl(b as u32)
                };
                self.set_logical_flags(r, bits);
                if b > 0 {
                    let cf_bit: u64 = 1u64 << (bits as u64 - b);
                    self.regs.flags.cf = (a & cf_bit) != 0;
                }
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Shr => {
                let a: u64 =
                    self.read_operand(insn, 0)? & Self::mask(Self::operand_size_bits(insn, 0));
                let b: u64 = self.read_operand(insn, 1)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = if b == 0 { a } else { a >> b };
                self.set_logical_flags(r, bits);
                if b > 0 {
                    self.regs.flags.cf = ((a >> (b - 1)) & 1) != 0;
                }
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Sar => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let m: u64 = Self::mask(bits);
                let sb: u64 = Self::sign_bit(bits);
                let a_s: u64 = a & m;
                let signed_a: i64 = if (a_s & sb) != 0 {
                    (a_s | !m) as i64
                } else {
                    a_s as i64
                };
                let r: u64 = if b == 0 {
                    a_s
                } else {
                    (signed_a >> b) as u64 & m
                };
                self.set_logical_flags(r, bits);
                if b > 0 {
                    self.regs.flags.cf = ((a_s >> (b - 1)) & 1) != 0;
                }
                self.write_operand(insn, 0, r & m)?;
                Ok(true)
            }
            M::Rol => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let m: u64 = Self::mask(bits);
                let count: u64 = b % u64::from(bits);
                let a_m: u64 = a & m;
                let r: u64 = if count == 0 {
                    a_m
                } else {
                    ((a_m << count) | (a_m >> (u64::from(bits) - count))) & m
                };
                self.write_operand(insn, 0, r)?;
                if count > 0 {
                    self.regs.flags.cf = (r & 1) != 0;
                }
                Ok(true)
            }
            M::Ror => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let m: u64 = Self::mask(bits);
                let count: u64 = b % u64::from(bits);
                let a_m: u64 = a & m;
                let r: u64 = if count == 0 {
                    a_m
                } else {
                    ((a_m >> count) | (a_m << (u64::from(bits) - count))) & m
                };
                self.write_operand(insn, 0, r)?;
                if count > 0 {
                    self.regs.flags.cf = (r & Self::sign_bit(bits)) != 0;
                }
                Ok(true)
            }
            M::Imul => {
                let r: u64 = match insn.op_count() {
                    1 => {
                        let bits: u8 = Self::operand_size_bits(insn, 0);
                        let m: u64 = Self::mask(bits);
                        let sb: u64 = Self::sign_bit(bits);
                        let a_raw: u64 = self.regs.read_sized(Reg::Rax, bits);
                        let b_raw: u64 = self.read_operand(insn, 0)? & m;
                        let a_s: i128 = if (a_raw & sb) != 0 {
                            i128::from(a_raw as i64) - (i128::from(m) + 1)
                        } else {
                            i128::from(a_raw)
                        };
                        let b_s: i128 = if (b_raw & sb) != 0 {
                            i128::from(b_raw as i64) - (i128::from(m) + 1)
                        } else {
                            i128::from(b_raw)
                        };
                        let prod: i128 = a_s * b_s;
                        let prod_u: u128 = prod as u128;
                        match bits {
                            8 => {
                                self.regs.write_sized(Reg::Rax, prod_u as u64 & 0xFFFF, 16);
                            }
                            16 => {
                                self.regs.write_sized(Reg::Rax, prod_u as u64 & 0xFFFF, 16);
                                self.regs
                                    .write_sized(Reg::Rdx, (prod_u >> 16) as u64 & 0xFFFF, 16);
                            }
                            32 => {
                                self.regs
                                    .write_sized(Reg::Rax, prod_u as u64 & 0xFFFF_FFFF, 32);
                                self.regs.write_sized(
                                    Reg::Rdx,
                                    (prod_u >> 32) as u64 & 0xFFFF_FFFF,
                                    32,
                                );
                            }
                            _ => {
                                self.regs.set(Reg::Rax, prod_u as u64);
                                self.regs.set(Reg::Rdx, (prod_u >> 64) as u64);
                            }
                        }
                        prod_u as u64
                    }
                    2 => {
                        let bits: u8 = Self::operand_size_bits(insn, 0);
                        let m: u64 = Self::mask(bits);
                        let sb: u64 = Self::sign_bit(bits);
                        let a_raw: u64 = self.read_operand(insn, 0)? & m;
                        let b_raw: u64 = self.read_operand(insn, 1)? & m;
                        let a_s: i128 = if (a_raw & sb) != 0 {
                            i128::from(a_raw as i64) - (i128::from(m) + 1)
                        } else {
                            i128::from(a_raw)
                        };
                        let b_s: i128 = if (b_raw & sb) != 0 {
                            i128::from(b_raw as i64) - (i128::from(m) + 1)
                        } else {
                            i128::from(b_raw)
                        };
                        let prod: i128 = a_s * b_s;
                        let r: u64 = (prod as i128 as u128) as u64 & m;
                        self.write_operand(insn, 0, r)?;
                        r
                    }
                    _ => {
                        let bits: u8 = Self::operand_size_bits(insn, 0);
                        let m: u64 = Self::mask(bits);
                        let sb: u64 = Self::sign_bit(bits);
                        let a_raw: u64 = self.read_operand(insn, 1)? & m;
                        let b_raw: u64 = self.read_operand(insn, 2)? & m;
                        let a_s: i128 = if (a_raw & sb) != 0 {
                            i128::from(a_raw as i64) - (i128::from(m) + 1)
                        } else {
                            i128::from(a_raw)
                        };
                        let b_s: i128 = if (b_raw & sb) != 0 {
                            i128::from(b_raw as i64) - (i128::from(m) + 1)
                        } else {
                            i128::from(b_raw)
                        };
                        let prod: i128 = a_s * b_s;
                        let r: u64 = (prod as i128 as u128) as u64 & m;
                        self.write_operand(insn, 0, r)?;
                        r
                    }
                };
                let _ = r;
                Ok(true)
            }
            M::Mul => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let a: u64 = self.regs.read_sized(Reg::Rax, bits);
                let b: u64 = self.read_operand(insn, 0)? & Self::mask(bits);
                let prod: u128 = u128::from(a) * u128::from(b);
                match bits {
                    8 => self.regs.write_sized(Reg::Rax, prod as u64 & 0xFFFF, 16),
                    16 => {
                        self.regs.write_sized(Reg::Rax, prod as u64 & 0xFFFF, 16);
                        self.regs
                            .write_sized(Reg::Rdx, (prod >> 16) as u64 & 0xFFFF, 16);
                    }
                    32 => {
                        self.regs
                            .write_sized(Reg::Rax, prod as u64 & 0xFFFF_FFFF, 32);
                        self.regs
                            .write_sized(Reg::Rdx, (prod >> 32) as u64 & 0xFFFF_FFFF, 32);
                    }
                    _ => {
                        self.regs.set(Reg::Rax, prod as u64);
                        self.regs.set(Reg::Rdx, (prod >> 64) as u64);
                    }
                }
                Ok(true)
            }
            M::Div => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let divisor: u64 = self.read_operand(insn, 0)? & Self::mask(bits);
                if divisor == 0 {
                    return Err(Error::GoblinParse("emu: div by zero".into()));
                }
                let dividend: u128 = match bits {
                    8 => u128::from(self.regs.read_sized(Reg::Rax, 16)),
                    16 => {
                        u128::from(self.regs.read_sized(Reg::Rax, 16))
                            | (u128::from(self.regs.read_sized(Reg::Rdx, 16)) << 16)
                    }
                    32 => {
                        u128::from(self.regs.read_sized(Reg::Rax, 32))
                            | (u128::from(self.regs.read_sized(Reg::Rdx, 32)) << 32)
                    }
                    _ => {
                        u128::from(self.regs.get(Reg::Rax))
                            | (u128::from(self.regs.get(Reg::Rdx)) << 64)
                    }
                };
                let q: u128 = dividend / u128::from(divisor);
                let rem: u128 = dividend % u128::from(divisor);
                match bits {
                    8 => {
                        self.regs.write_sized(Reg::Rax, q as u64 & 0xFF, 8);
                        self.regs.write_high8(Reg::Rax, rem as u64 & 0xFF);
                    }
                    16 => {
                        self.regs.write_sized(Reg::Rax, q as u64 & 0xFFFF, 16);
                        self.regs.write_sized(Reg::Rdx, rem as u64 & 0xFFFF, 16);
                    }
                    32 => {
                        self.regs.write_sized(Reg::Rax, q as u64 & 0xFFFF_FFFF, 32);
                        self.regs
                            .write_sized(Reg::Rdx, rem as u64 & 0xFFFF_FFFF, 32);
                    }
                    _ => {
                        self.regs.set(Reg::Rax, q as u64);
                        self.regs.set(Reg::Rdx, rem as u64);
                    }
                }
                Ok(true)
            }
            M::Idiv => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let divisor: u64 = self.read_operand(insn, 0)? & Self::mask(bits);
                if divisor == 0 {
                    return Err(Error::GoblinParse("emu: idiv by zero".into()));
                }
                let m: u64 = Self::mask(bits);
                let sb: u64 = Self::sign_bit(bits);
                let dividend_u: u128 = match bits {
                    8 => u128::from(self.regs.read_sized(Reg::Rax, 16)),
                    16 => {
                        u128::from(self.regs.read_sized(Reg::Rax, 16))
                            | (u128::from(self.regs.read_sized(Reg::Rdx, 16)) << 16)
                    }
                    32 => {
                        u128::from(self.regs.read_sized(Reg::Rax, 32))
                            | (u128::from(self.regs.read_sized(Reg::Rdx, 32)) << 32)
                    }
                    _ => {
                        u128::from(self.regs.get(Reg::Rax))
                            | (u128::from(self.regs.get(Reg::Rdx)) << 64)
                    }
                };
                let div_bits: u8 = bits * 2;
                let dividend_mask: u128 = if div_bits == 128 {
                    u128::MAX
                } else {
                    (1u128 << div_bits) - 1
                };
                let div_sb: u128 = 1u128 << (div_bits - 1);
                let dividend_i: i128 = if (dividend_u & div_sb) != 0 {
                    (dividend_u | !dividend_mask) as i128
                } else {
                    dividend_u as i128
                };
                let divisor_i: i128 = if (divisor & sb) != 0 {
                    (i128::from(divisor as i64) - (i128::from(m) + 1)) as i128
                } else {
                    i128::from(divisor)
                };
                let q: i128 = dividend_i / divisor_i;
                let rem: i128 = dividend_i % divisor_i;
                let q_u: u64 = (q as i128 as u128) as u64 & m;
                let r_u: u64 = (rem as i128 as u128) as u64 & m;
                match bits {
                    8 => {
                        self.regs.write_sized(Reg::Rax, q_u, 8);
                        self.regs.write_high8(Reg::Rax, r_u);
                    }
                    16 => {
                        self.regs.write_sized(Reg::Rax, q_u, 16);
                        self.regs.write_sized(Reg::Rdx, r_u, 16);
                    }
                    32 => {
                        self.regs.write_sized(Reg::Rax, q_u, 32);
                        self.regs.write_sized(Reg::Rdx, r_u, 32);
                    }
                    _ => {
                        self.regs.set(Reg::Rax, q_u);
                        self.regs.set(Reg::Rdx, r_u);
                    }
                }
                Ok(true)
            }
            M::Cdq | M::Cwd | M::Cqo => {
                let bits: u8 = match mnem {
                    M::Cwd => 16,
                    M::Cdq => 32,
                    _ => 64,
                };
                let v: u64 = self.regs.read_sized(Reg::Rax, bits);
                let extended: u64 = if (v & Self::sign_bit(bits)) != 0 {
                    Self::mask(bits)
                } else {
                    0
                };
                self.regs.write_sized(Reg::Rdx, extended, bits);
                Ok(true)
            }
            M::Cbw | M::Cwde | M::Cdqe => {
                let src_bits: u8 = match mnem {
                    M::Cbw => 8,
                    M::Cwde => 16,
                    _ => 32,
                };
                let dst_bits: u8 = src_bits * 2;
                let v: u64 = self.regs.read_sized(Reg::Rax, src_bits);
                let m: u64 = Self::mask(src_bits);
                let sb: u64 = Self::sign_bit(src_bits);
                let extended: u64 = if (v & sb) != 0 { v | !m } else { v };
                self.regs
                    .write_sized(Reg::Rax, extended & Self::mask(dst_bits), dst_bits);
                Ok(true)
            }
            M::Loop | M::Loope | M::Loopne => {
                let bits: u8 = self.mode.bits() as u8;
                let c: u64 = self.regs.read_sized(Reg::Rcx, bits).wrapping_sub(1);
                self.regs.write_sized(Reg::Rcx, c, bits);
                let take: bool = match mnem {
                    M::Loope => c != 0 && self.regs.flags.zf,
                    M::Loopne => c != 0 && !self.regs.flags.zf,
                    M::Loop => c != 0,
                    _ => c != 0,
                };
                if take {
                    let target: u64 = self.branch_target(insn)?;
                    if !self.mem.is_mapped(target) {
                        return Ok(true);
                    }
                    self.regs.rip = target;
                }
                Ok(true)
            }
            M::Jcxz | M::Jecxz | M::Jrcxz => {
                let bits: u8 = match mnem {
                    M::Jcxz => 16,
                    M::Jecxz => 32,
                    _ => 64,
                };
                let c: u64 = self.regs.read_sized(Reg::Rcx, bits);
                if c == 0 {
                    let target: u64 = self.branch_target(insn)?;
                    if self.mem.is_mapped(target) {
                        self.regs.rip = target;
                    }
                }
                Ok(true)
            }
            M::Jmp => {
                let target: u64 = self.branch_target(insn)?;
                if !self.mem.is_mapped(target) {
                    return Ok(true);
                }
                self.regs.rip = target;
                Ok(true)
            }
            M::Nop | M::Endbr32 | M::Endbr64 | M::Pause | M::Cld | M::Std | M::Clc | M::Stc => {
                match mnem {
                    M::Cld => self.regs.flags.df = false,
                    M::Std => self.regs.flags.df = true,
                    M::Clc => self.regs.flags.cf = false,
                    M::Stc => self.regs.flags.cf = true,
                    _ => {}
                }
                Ok(true)
            }
            M::Setb
            | M::Setae
            | M::Sete
            | M::Setne
            | M::Setbe
            | M::Seta
            | M::Sets
            | M::Setns
            | M::Setp
            | M::Setnp
            | M::Setl
            | M::Setge
            | M::Setle
            | M::Setg
            | M::Seto
            | M::Setno => {
                let cond: bool = self.cond_true(insn.condition_code());
                self.write_operand(insn, 0, u64::from(cond))?;
                Ok(true)
            }
            M::Cmovb
            | M::Cmovae
            | M::Cmove
            | M::Cmovne
            | M::Cmovbe
            | M::Cmova
            | M::Cmovs
            | M::Cmovns
            | M::Cmovp
            | M::Cmovnp
            | M::Cmovl
            | M::Cmovge
            | M::Cmovle
            | M::Cmovg
            | M::Cmovo
            | M::Cmovno => {
                let take: bool = self.cond_true(insn.condition_code());
                if take {
                    let v: u64 = self.read_operand(insn, 1)?;
                    self.write_operand(insn, 0, v)?;
                }
                Ok(true)
            }
            M::Bswap => {
                let v: u64 = self.read_operand(insn, 0)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = match bits {
                    32 => u64::from((v as u32).swap_bytes()),
                    64 => v.swap_bytes(),
                    _ => v,
                };
                self.write_operand(insn, 0, r)?;
                Ok(true)
            }
            M::Bt | M::Bts | M::Btr | M::Btc => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let base: u64 = self.read_operand(insn, 0)?;
                let index: u64 = self.read_operand(insn, 1)? % u64::from(bits.max(1));
                let mask: u64 = 1u64 << index;
                self.regs.flags.cf = (base & mask) != 0;
                let updated: u64 = match mnem {
                    M::Bts => base | mask,
                    M::Btr => base & !mask,
                    M::Btc => base ^ mask,
                    _ => base,
                };
                if !matches!(mnem, M::Bt) {
                    self.write_operand(insn, 0, updated & Self::mask(bits))?;
                }
                Ok(true)
            }
            M::Bsf | M::Bsr => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let src: u64 = self.read_operand(insn, 1)? & Self::mask(bits);
                if src == 0 {
                    self.regs.flags.zf = true;
                } else {
                    self.regs.flags.zf = false;
                    let pos: u32 = if matches!(mnem, M::Bsf) {
                        src.trailing_zeros()
                    } else {
                        src.ilog2()
                    };
                    self.write_operand(insn, 0, u64::from(pos))?;
                }
                Ok(true)
            }
            M::Leave => {
                let ps: u8 = self.mode.ptr_size();
                let bits: u8 = ps * 8;
                let bp: u64 = self.regs.read_sized(Reg::Rbp, bits);
                self.regs.write_sized(Reg::Rsp, bp, bits);
                let new_bp: u64 = if ps == 4 {
                    u64::from(self.mem.read_u32(bp)?)
                } else {
                    self.mem.read_u64(bp)?
                };
                let new_sp: u64 = bp.wrapping_add(u64::from(ps));
                self.regs.write_sized(Reg::Rbp, new_bp, bits);
                self.regs.write_sized(Reg::Rsp, new_sp, bits);
                Ok(true)
            }
            M::Enter => {
                let ps: u8 = self.mode.ptr_size();
                let bits: u8 = ps * 8;
                let alloc: u64 = self.read_operand(insn, 0)?;
                let nesting: u64 = self.read_operand(insn, 1)? & 0x1F;
                let bp_old: u64 = self.regs.read_sized(Reg::Rbp, bits);
                let sp_after_push_bp: u64 = self
                    .regs
                    .read_sized(Reg::Rsp, bits)
                    .wrapping_sub(u64::from(ps));
                self.regs.write_sized(Reg::Rsp, sp_after_push_bp, bits);
                if ps == 4 {
                    self.mem.write_u32(sp_after_push_bp, bp_old as u32)?;
                } else {
                    self.mem.write_u64(sp_after_push_bp, bp_old)?;
                }
                let frame_temp: u64 = sp_after_push_bp;
                if nesting > 0 {
                    let mut bp_walker: u64 = bp_old;
                    for _ in 1..nesting {
                        bp_walker = bp_walker.wrapping_sub(u64::from(ps));
                        let v: u64 = if ps == 4 {
                            u64::from(self.mem.read_u32(bp_walker)?)
                        } else {
                            self.mem.read_u64(bp_walker)?
                        };
                        let new_sp: u64 = self
                            .regs
                            .read_sized(Reg::Rsp, bits)
                            .wrapping_sub(u64::from(ps));
                        self.regs.write_sized(Reg::Rsp, new_sp, bits);
                        if ps == 4 {
                            self.mem.write_u32(new_sp, v as u32)?;
                        } else {
                            self.mem.write_u64(new_sp, v)?;
                        }
                    }
                    let new_sp: u64 = self
                        .regs
                        .read_sized(Reg::Rsp, bits)
                        .wrapping_sub(u64::from(ps));
                    self.regs.write_sized(Reg::Rsp, new_sp, bits);
                    if ps == 4 {
                        self.mem.write_u32(new_sp, frame_temp as u32)?;
                    } else {
                        self.mem.write_u64(new_sp, frame_temp)?;
                    }
                }
                self.regs.write_sized(Reg::Rbp, frame_temp, bits);
                let new_sp: u64 = frame_temp.wrapping_sub(alloc);
                self.regs.write_sized(Reg::Rsp, new_sp, bits);
                Ok(true)
            }
            M::Rcl => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let m: u64 = Self::mask(bits);
                let width: u64 = u64::from(bits) + 1;
                let count: u64 = b % width;
                let a_m: u64 = a & m;
                let cin: u64 = u64::from(self.regs.flags.cf);
                let mut val: u128 = u128::from(a_m) | (u128::from(cin) << bits);
                if count > 0 {
                    let shifted: u128 = (val << count) | (val >> (width - count));
                    val = shifted & (((1u128 << width).wrapping_sub(1)) as u128);
                }
                let r: u64 = (val as u64) & m;
                let cf_out: bool = ((val >> bits) & 1) != 0;
                self.write_operand(insn, 0, r)?;
                if count > 0 {
                    self.regs.flags.cf = cf_out;
                }
                Ok(true)
            }
            M::Rcr => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let m: u64 = Self::mask(bits);
                let width: u64 = u64::from(bits) + 1;
                let count: u64 = b % width;
                let a_m: u64 = a & m;
                let cin: u64 = u64::from(self.regs.flags.cf);
                let mut val: u128 = u128::from(a_m) | (u128::from(cin) << bits);
                if count > 0 {
                    let shifted: u128 = (val >> count) | (val << (width - count));
                    val = shifted & (((1u128 << width).wrapping_sub(1)) as u128);
                }
                let r: u64 = (val as u64) & m;
                let cf_out: bool = ((val >> bits) & 1) != 0;
                self.write_operand(insn, 0, r)?;
                if count > 0 {
                    self.regs.flags.cf = cf_out;
                }
                Ok(true)
            }
            M::Shld => {
                let dst: u64 = self.read_operand(insn, 0)?;
                let src: u64 = self.read_operand(insn, 1)?;
                let shift_raw: u64 = self.read_operand(insn, 2)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let bits_mask: u64 = Self::mask(bits);
                let count: u64 = shift_raw % u64::from(bits.max(1));
                let dst_m: u64 = dst & bits_mask;
                let src_m: u64 = src & bits_mask;
                let result: u64 = if count == 0 {
                    dst_m
                } else {
                    ((dst_m << count) | (src_m >> (u64::from(bits) - count))) & bits_mask
                };
                self.set_logical_flags(result, bits);
                if count > 0 {
                    let cf_bit: u64 = 1u64 << (u64::from(bits) - count);
                    self.regs.flags.cf = (dst_m & cf_bit) != 0;
                }
                self.write_operand(insn, 0, result)?;
                Ok(true)
            }
            M::Shrd => {
                let dst: u64 = self.read_operand(insn, 0)?;
                let src: u64 = self.read_operand(insn, 1)?;
                let shift_raw: u64 = self.read_operand(insn, 2)? & 0x3F;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let bits_mask: u64 = Self::mask(bits);
                let count: u64 = shift_raw % u64::from(bits.max(1));
                let dst_m: u64 = dst & bits_mask;
                let src_m: u64 = src & bits_mask;
                let result: u64 = if count == 0 {
                    dst_m
                } else {
                    ((dst_m >> count) | (src_m << (u64::from(bits) - count))) & bits_mask
                };
                self.set_logical_flags(result, bits);
                if count > 0 {
                    self.regs.flags.cf = ((dst_m >> (count - 1)) & 1) != 0;
                }
                self.write_operand(insn, 0, result)?;
                Ok(true)
            }
            M::Xadd => {
                let a: u64 = self.read_operand(insn, 0)?;
                let b: u64 = self.read_operand(insn, 1)?;
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let r: u64 = a.wrapping_add(b);
                self.set_arith_flags(a, b, r, bits, false, false);
                self.write_operand(insn, 1, a & Self::mask(bits))?;
                self.write_operand(insn, 0, r & Self::mask(bits))?;
                Ok(true)
            }
            M::Cmpxchg => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let dst: u64 = self.read_operand(insn, 0)?;
                let acc: u64 = self.regs.read_sized(Reg::Rax, bits);
                let src: u64 = self.read_operand(insn, 1)?;
                let r: u64 = acc.wrapping_sub(dst);
                self.set_arith_flags(acc, dst, r, bits, true, false);
                if self.regs.flags.zf {
                    self.write_operand(insn, 0, src & Self::mask(bits))?;
                } else {
                    self.regs
                        .write_sized(Reg::Rax, dst & Self::mask(bits), bits);
                }
                Ok(true)
            }
            M::Popcnt => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let v: u64 = self.read_operand(insn, 1)? & Self::mask(bits);
                let pop: u64 = u64::from(v.count_ones());
                self.regs.flags.zf = pop == 0;
                self.regs.flags.cf = false;
                self.regs.flags.of = false;
                self.regs.flags.sf = false;
                self.regs.flags.pf = false;
                self.write_operand(insn, 0, pop & Self::mask(bits))?;
                Ok(true)
            }
            M::Lzcnt => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let v: u64 = self.read_operand(insn, 1)? & Self::mask(bits);
                let lz: u32 = if v == 0 {
                    u32::from(bits)
                } else {
                    let pad: u32 = 64u32 - u32::from(bits);
                    v.leading_zeros().saturating_sub(pad)
                };
                self.regs.flags.cf = v == 0;
                self.regs.flags.zf = lz == 0;
                self.write_operand(insn, 0, u64::from(lz) & Self::mask(bits))?;
                Ok(true)
            }
            M::Tzcnt => {
                let bits: u8 = Self::operand_size_bits(insn, 0);
                let v: u64 = self.read_operand(insn, 1)? & Self::mask(bits);
                let tz: u32 = if v == 0 {
                    u32::from(bits)
                } else {
                    v.trailing_zeros()
                };
                self.regs.flags.cf = v == 0;
                self.regs.flags.zf = tz == 0;
                self.write_operand(insn, 0, u64::from(tz) & Self::mask(bits))?;
                Ok(true)
            }
            M::Salc => {
                let v: u64 = if self.regs.flags.cf { 0xFF } else { 0x00 };
                self.regs.write_sized(Reg::Rax, v, 8);
                Ok(true)
            }
            M::Xlatb => {
                let bits: u8 = self.mode.bits() as u8;
                let bx: u64 = self.regs.read_sized(Reg::Rbx, bits);
                let al: u64 = self.regs.read_sized(Reg::Rax, 8);
                let addr: u64 = match insn.segment_prefix() {
                    Register::FS => bx.wrapping_add(al).wrapping_add(self.fs_base),
                    Register::GS => bx.wrapping_add(al).wrapping_add(self.gs_base),
                    _ => bx.wrapping_add(al),
                };
                let b: u8 = self.mem.read_u8(addr)?;
                self.regs.write_sized(Reg::Rax, u64::from(b), 8);
                Ok(true)
            }
            M::Cmc => {
                self.regs.flags.cf = !self.regs.flags.cf;
                Ok(true)
            }
            M::Cli | M::Sti | M::Sahf | M::Lahf | M::Wait | M::Fnop => {
                if matches!(mnem, M::Lahf) {
                    let f: u64 = self.encode_flags();
                    self.regs.write_high8(Reg::Rax, f & 0xFF);
                } else if matches!(mnem, M::Sahf) {
                    let ah: u64 = self.regs.read_high8(Reg::Rax);
                    let f: u64 = self.encode_flags();
                    self.decode_flags((f & !0xFFu64) | (ah & 0xFF));
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn read_mm_reg(&self, reg: Register) -> Result<u64> {
        let index: u8 = classify_mm(reg)
            .ok_or_else(|| Error::GoblinParse(format!("emu: not an MMX register {reg:?}")))?;
        Ok(self.regs.get_mm(index))
    }

    fn write_mm_reg(&mut self, reg: Register, value: u64) -> Result<()> {
        let index: u8 = classify_mm(reg)
            .ok_or_else(|| Error::GoblinParse(format!("emu: not an MMX register {reg:?}")))?;
        self.regs.set_mm(index, value);
        Ok(())
    }

    fn read_mm_packed_operand(&self, insn: &Instruction, operand: u32) -> Result<u64> {
        match insn.op_kind(operand) {
            OpKind::Register => self.read_mm_reg(insn.op_register(operand)),
            OpKind::Memory => self.mem.read_u64(self.effective_addr(insn, operand)?),
            other => Err(Error::GoblinParse(format!(
                "emu: unsupported MMX source operand {other:?}"
            ))),
        }
    }

    fn read_mm_dword_operand(&self, insn: &Instruction, operand: u32) -> Result<u64> {
        match insn.op_kind(operand) {
            OpKind::Register => self.read_mm_reg(insn.op_register(operand)),
            OpKind::Memory => Ok(u64::from(
                self.mem.read_u32(self.effective_addr(insn, operand)?)?,
            )),
            other => Err(Error::GoblinParse(format!(
                "emu: unsupported MMX source operand {other:?}"
            ))),
        }
    }

    fn lanes_u16(value: u64) -> [u16; 4] {
        let bytes: [u8; 8] = value.to_le_bytes();
        [
            u16::from_le_bytes([bytes[0], bytes[1]]),
            u16::from_le_bytes([bytes[2], bytes[3]]),
            u16::from_le_bytes([bytes[4], bytes[5]]),
            u16::from_le_bytes([bytes[6], bytes[7]]),
        ]
    }

    fn lanes_u32(value: u64) -> [u32; 2] {
        let bytes: [u8; 8] = value.to_le_bytes();
        [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        ]
    }

    fn pack_u16(lanes: [u16; 4]) -> u64 {
        let mut bytes: [u8; 8] = [0u8; 8];
        for (i, lane) in lanes.iter().enumerate() {
            let lb: [u8; 2] = lane.to_le_bytes();
            bytes[i * 2] = lb[0];
            bytes[i * 2 + 1] = lb[1];
        }
        u64::from_le_bytes(bytes)
    }

    fn pack_u32(lanes: [u32; 2]) -> u64 {
        let mut bytes: [u8; 8] = [0u8; 8];
        for (i, lane) in lanes.iter().enumerate() {
            let lb: [u8; 4] = lane.to_le_bytes();
            bytes[i * 4..i * 4 + 4].copy_from_slice(&lb);
        }
        u64::from_le_bytes(bytes)
    }

    #[allow(clippy::too_many_lines)]
    fn try_mmx_op(&mut self, insn: &Instruction) -> Result<bool> {
        let code: Code = insn.code();
        match code {
            Code::Movd_mm_rm32 => {
                let src: u64 = self.read_operand(insn, 1)? & 0xFFFF_FFFF;
                self.write_mm_reg(insn.op_register(0), src)?;
                Ok(true)
            }
            Code::Movd_rm32_mm => {
                let src: u64 = self.read_mm_reg(insn.op_register(1))?;
                self.write_operand(insn, 0, src & 0xFFFF_FFFF)?;
                Ok(true)
            }
            Code::Movq_mm_mmm64 | Code::Movq_mm_rm64 => {
                let src: u64 = self.read_mm_packed_operand(insn, 1)?;
                self.write_mm_reg(insn.op_register(0), src)?;
                Ok(true)
            }
            Code::Movq_mmm64_mm => {
                let src: u64 = self.read_mm_reg(insn.op_register(1))?;
                match insn.op_kind(0) {
                    OpKind::Register => self.write_mm_reg(insn.op_register(0), src)?,
                    OpKind::Memory => self.mem.write_u64(self.effective_addr(insn, 0)?, src)?,
                    other => {
                        return Err(Error::GoblinParse(format!(
                            "emu: unsupported movq destination {other:?}"
                        )));
                    }
                }
                Ok(true)
            }
            Code::Pxor_mm_mmm64 => {
                let dst: u64 = self.read_mm_reg(insn.op_register(0))?;
                let src: u64 = self.read_mm_packed_operand(insn, 1)?;
                self.write_mm_reg(insn.op_register(0), dst ^ src)?;
                Ok(true)
            }
            Code::Pcmpeqb_mm_mmm64 => {
                let dst: [u8; 8] = self.read_mm_reg(insn.op_register(0))?.to_le_bytes();
                let src: [u8; 8] = self.read_mm_packed_operand(insn, 1)?.to_le_bytes();
                let mut out: [u8; 8] = [0u8; 8];
                for i in 0..8 {
                    out[i] = if dst[i] == src[i] { 0xFF } else { 0x00 };
                }
                self.write_mm_reg(insn.op_register(0), u64::from_le_bytes(out))?;
                Ok(true)
            }
            Code::Paddb_mm_mmm64 => {
                let dst: [u8; 8] = self.read_mm_reg(insn.op_register(0))?.to_le_bytes();
                let src: [u8; 8] = self.read_mm_packed_operand(insn, 1)?.to_le_bytes();
                let mut out: [u8; 8] = [0u8; 8];
                for i in 0..8 {
                    out[i] = dst[i].wrapping_add(src[i]);
                }
                self.write_mm_reg(insn.op_register(0), u64::from_le_bytes(out))?;
                Ok(true)
            }
            Code::Paddd_mm_mmm64 => {
                let dst: [u32; 2] = Self::lanes_u32(self.read_mm_reg(insn.op_register(0))?);
                let src: [u32; 2] = Self::lanes_u32(self.read_mm_packed_operand(insn, 1)?);
                let out: [u32; 2] = [dst[0].wrapping_add(src[0]), dst[1].wrapping_add(src[1])];
                self.write_mm_reg(insn.op_register(0), Self::pack_u32(out))?;
                Ok(true)
            }
            Code::Psubd_mm_mmm64 => {
                let dst: [u32; 2] = Self::lanes_u32(self.read_mm_reg(insn.op_register(0))?);
                let src: [u32; 2] = Self::lanes_u32(self.read_mm_packed_operand(insn, 1)?);
                let out: [u32; 2] = [dst[0].wrapping_sub(src[0]), dst[1].wrapping_sub(src[1])];
                self.write_mm_reg(insn.op_register(0), Self::pack_u32(out))?;
                Ok(true)
            }
            Code::Paddsw_mm_mmm64 => {
                let dst: [u16; 4] = Self::lanes_u16(self.read_mm_reg(insn.op_register(0))?);
                let src: [u16; 4] = Self::lanes_u16(self.read_mm_packed_operand(insn, 1)?);
                let mut out: [u16; 4] = [0u16; 4];
                for i in 0..4 {
                    let sum: i32 = i32::from(dst[i] as i16) + i32::from(src[i] as i16);
                    out[i] = sum.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16 as u16;
                }
                self.write_mm_reg(insn.op_register(0), Self::pack_u16(out))?;
                Ok(true)
            }
            Code::Pmulhw_mm_mmm64 => {
                let dst: [u16; 4] = Self::lanes_u16(self.read_mm_reg(insn.op_register(0))?);
                let src: [u16; 4] = Self::lanes_u16(self.read_mm_packed_operand(insn, 1)?);
                let mut out: [u16; 4] = [0u16; 4];
                for i in 0..4 {
                    let prod: i32 = i32::from(dst[i] as i16) * i32::from(src[i] as i16);
                    out[i] = (prod >> 16) as u16;
                }
                self.write_mm_reg(insn.op_register(0), Self::pack_u16(out))?;
                Ok(true)
            }
            Code::Pmaddwd_mm_mmm64 => {
                let dst: [u16; 4] = Self::lanes_u16(self.read_mm_reg(insn.op_register(0))?);
                let src: [u16; 4] = Self::lanes_u16(self.read_mm_packed_operand(insn, 1)?);
                let lo: i32 = i32::from(dst[0] as i16) * i32::from(src[0] as i16)
                    + i32::from(dst[1] as i16) * i32::from(src[1] as i16);
                let hi: i32 = i32::from(dst[2] as i16) * i32::from(src[2] as i16)
                    + i32::from(dst[3] as i16) * i32::from(src[3] as i16);
                self.write_mm_reg(insn.op_register(0), Self::pack_u32([lo as u32, hi as u32]))?;
                Ok(true)
            }
            Code::Psadbw_mm_mmm64 => {
                let dst: [u8; 8] = self.read_mm_reg(insn.op_register(0))?.to_le_bytes();
                let src: [u8; 8] = self.read_mm_packed_operand(insn, 1)?.to_le_bytes();
                let mut acc: u16 = 0;
                for i in 0..8 {
                    acc += u16::from(dst[i].abs_diff(src[i]));
                }
                self.write_mm_reg(insn.op_register(0), u64::from(acc))?;
                Ok(true)
            }
            Code::Punpcklwd_mm_mmm32 => {
                let dst: [u16; 4] = Self::lanes_u16(self.read_mm_reg(insn.op_register(0))?);
                let src: [u16; 4] = Self::lanes_u16(self.read_mm_dword_operand(insn, 1)?);
                let out: [u16; 4] = [dst[0], src[0], dst[1], src[1]];
                self.write_mm_reg(insn.op_register(0), Self::pack_u16(out))?;
                Ok(true)
            }
            Code::Psrlw_mm_imm8 => {
                let count: u32 = u32::from(insn.immediate8());
                let lanes: [u16; 4] = Self::lanes_u16(self.read_mm_reg(insn.op_register(0))?);
                let out: [u16; 4] = lanes.map(|l: u16| if count >= 16 { 0 } else { l >> count });
                self.write_mm_reg(insn.op_register(0), Self::pack_u16(out))?;
                Ok(true)
            }
            Code::Psraw_mm_imm8 => {
                let count: u32 = u32::from(insn.immediate8());
                let lanes: [u16; 4] = Self::lanes_u16(self.read_mm_reg(insn.op_register(0))?);
                let out: [u16; 4] = lanes.map(|l: u16| {
                    let shift: u32 = count.min(15);
                    ((l as i16) >> shift) as u16
                });
                self.write_mm_reg(insn.op_register(0), Self::pack_u16(out))?;
                Ok(true)
            }
            Code::Psrad_mm_imm8 => {
                let count: u32 = u32::from(insn.immediate8());
                let lanes: [u32; 2] = Self::lanes_u32(self.read_mm_reg(insn.op_register(0))?);
                let out: [u32; 2] = lanes.map(|l: u32| {
                    let shift: u32 = count.min(31);
                    ((l as i32) >> shift) as u32
                });
                self.write_mm_reg(insn.op_register(0), Self::pack_u32(out))?;
                Ok(true)
            }
            Code::Psrlq_mm_imm8 => {
                let count: u32 = u32::from(insn.immediate8());
                let value: u64 = self.read_mm_reg(insn.op_register(0))?;
                let out: u64 = if count >= 64 { 0 } else { value >> count };
                self.write_mm_reg(insn.op_register(0), out)?;
                Ok(true)
            }
            Code::Psrlq_mm_mmm64 => {
                let count: u64 = self.read_mm_packed_operand(insn, 1)?;
                let value: u64 = self.read_mm_reg(insn.op_register(0))?;
                let out: u64 = if count >= 64 { 0 } else { value >> count };
                self.write_mm_reg(insn.op_register(0), out)?;
                Ok(true)
            }
            Code::Emms => Ok(true),
            _ => Ok(false),
        }
    }

    fn try_string_op(&mut self, insn: &Instruction) -> Result<Option<bool>> {
        use iced_x86::Mnemonic as M;
        let mnem = insn.mnemonic();
        let dir: i64 = if self.regs.flags.df { -1 } else { 1 };
        let bits: u8 = self.mode.bits() as u8;
        let count_ptr_bits: u8 = bits;
        let has_rep: bool =
            insn.has_rep_prefix() || insn.has_repe_prefix() || insn.has_repne_prefix();
        match mnem {
            M::Movsb | M::Movsw | M::Movsd | M::Movsq => {
                let stride: i64 = match mnem {
                    M::Movsb => 1,
                    M::Movsw => 2,
                    M::Movsd => 4,
                    _ => 8,
                };
                let do_one = |cpu: &mut Self| -> Result<()> {
                    let si: u64 = cpu.regs.read_sized(Reg::Rsi, bits);
                    let di: u64 = cpu.regs.read_sized(Reg::Rdi, bits);
                    let v: u64 = match stride {
                        1 => u64::from(cpu.mem.read_u8(si)?),
                        2 => u64::from(cpu.mem.read_u16(si)?),
                        4 => u64::from(cpu.mem.read_u32(si)?),
                        _ => cpu.mem.read_u64(si)?,
                    };
                    match stride {
                        1 => cpu.mem.write_u8(di, v as u8)?,
                        2 => cpu.mem.write_u16(di, v as u16)?,
                        4 => cpu.mem.write_u32(di, v as u32)?,
                        _ => cpu.mem.write_u64(di, v)?,
                    }
                    cpu.regs
                        .write_sized(Reg::Rsi, si.wrapping_add(stride as u64), bits);
                    cpu.regs
                        .write_sized(Reg::Rdi, di.wrapping_add(stride as u64), bits);
                    Ok(())
                };
                let _ = dir;
                self.run_string(has_rep, count_ptr_bits, do_one, None)?;
                Ok(Some(true))
            }
            M::Lodsb | M::Lodsw | M::Lodsd | M::Lodsq => {
                let stride: i64 = match mnem {
                    M::Lodsb => 1,
                    M::Lodsw => 2,
                    M::Lodsd => 4,
                    _ => 8,
                };
                let do_one = |cpu: &mut Self| -> Result<()> {
                    let si: u64 = cpu.regs.read_sized(Reg::Rsi, bits);
                    let v: u64 = match stride {
                        1 => u64::from(cpu.mem.read_u8(si)?),
                        2 => u64::from(cpu.mem.read_u16(si)?),
                        4 => u64::from(cpu.mem.read_u32(si)?),
                        _ => cpu.mem.read_u64(si)?,
                    };
                    cpu.regs.write_sized(Reg::Rax, v, (stride * 8) as u8);
                    cpu.regs
                        .write_sized(Reg::Rsi, si.wrapping_add(stride as u64), bits);
                    Ok(())
                };
                self.run_string(has_rep, count_ptr_bits, do_one, None)?;
                Ok(Some(true))
            }
            M::Stosb | M::Stosw | M::Stosd | M::Stosq => {
                let stride: i64 = match mnem {
                    M::Stosb => 1,
                    M::Stosw => 2,
                    M::Stosd => 4,
                    _ => 8,
                };
                let do_one = |cpu: &mut Self| -> Result<()> {
                    let di: u64 = cpu.regs.read_sized(Reg::Rdi, bits);
                    let v: u64 = cpu.regs.read_sized(Reg::Rax, (stride * 8) as u8);
                    match stride {
                        1 => cpu.mem.write_u8(di, v as u8)?,
                        2 => cpu.mem.write_u16(di, v as u16)?,
                        4 => cpu.mem.write_u32(di, v as u32)?,
                        _ => cpu.mem.write_u64(di, v)?,
                    }
                    cpu.regs
                        .write_sized(Reg::Rdi, di.wrapping_add(stride as u64), bits);
                    Ok(())
                };
                self.run_string(has_rep, count_ptr_bits, do_one, None)?;
                Ok(Some(true))
            }
            M::Cmpsb | M::Cmpsw | M::Cmpsd | M::Cmpsq => {
                let stride: i64 = match mnem {
                    M::Cmpsb => 1,
                    M::Cmpsw => 2,
                    M::Cmpsd => 4,
                    _ => 8,
                };
                let elem_bits: u8 = (stride * 8) as u8;
                let do_one = |cpu: &mut Self| -> Result<bool> {
                    let si: u64 = cpu.regs.read_sized(Reg::Rsi, bits);
                    let di: u64 = cpu.regs.read_sized(Reg::Rdi, bits);
                    let a: u64 = match stride {
                        1 => u64::from(cpu.mem.read_u8(si)?),
                        2 => u64::from(cpu.mem.read_u16(si)?),
                        4 => u64::from(cpu.mem.read_u32(si)?),
                        _ => cpu.mem.read_u64(si)?,
                    };
                    let b: u64 = match stride {
                        1 => u64::from(cpu.mem.read_u8(di)?),
                        2 => u64::from(cpu.mem.read_u16(di)?),
                        4 => u64::from(cpu.mem.read_u32(di)?),
                        _ => cpu.mem.read_u64(di)?,
                    };
                    let r: u64 = a.wrapping_sub(b);
                    cpu.set_arith_flags(a, b, r, elem_bits, true, false);
                    cpu.regs
                        .write_sized(Reg::Rsi, si.wrapping_add(stride as u64), bits);
                    cpu.regs
                        .write_sized(Reg::Rdi, di.wrapping_add(stride as u64), bits);
                    Ok(cpu.regs.flags.zf)
                };
                let zf_target: Option<bool> = if insn.has_repe_prefix() {
                    Some(true)
                } else if insn.has_repne_prefix() {
                    Some(false)
                } else {
                    None
                };
                self.run_string_cmp(has_rep, count_ptr_bits, do_one, zf_target)?;
                Ok(Some(true))
            }
            M::Scasb | M::Scasw | M::Scasd | M::Scasq => {
                let stride: i64 = match mnem {
                    M::Scasb => 1,
                    M::Scasw => 2,
                    M::Scasd => 4,
                    _ => 8,
                };
                let elem_bits: u8 = (stride * 8) as u8;
                let do_one = |cpu: &mut Self| -> Result<bool> {
                    let di: u64 = cpu.regs.read_sized(Reg::Rdi, bits);
                    let a: u64 = cpu.regs.read_sized(Reg::Rax, elem_bits);
                    let b: u64 = match stride {
                        1 => u64::from(cpu.mem.read_u8(di)?),
                        2 => u64::from(cpu.mem.read_u16(di)?),
                        4 => u64::from(cpu.mem.read_u32(di)?),
                        _ => cpu.mem.read_u64(di)?,
                    };
                    let r: u64 = a.wrapping_sub(b);
                    cpu.set_arith_flags(a, b, r, elem_bits, true, false);
                    cpu.regs
                        .write_sized(Reg::Rdi, di.wrapping_add(stride as u64), bits);
                    Ok(cpu.regs.flags.zf)
                };
                let zf_target: Option<bool> = if insn.has_repe_prefix() {
                    Some(true)
                } else if insn.has_repne_prefix() {
                    Some(false)
                } else {
                    None
                };
                self.run_string_cmp(has_rep, count_ptr_bits, do_one, zf_target)?;
                Ok(Some(true))
            }
            _ => Ok(None),
        }
    }

    fn run_string<F: FnMut(&mut Self) -> Result<()>>(
        &mut self,
        has_rep: bool,
        count_bits: u8,
        mut body: F,
        _zf_target: Option<bool>,
    ) -> Result<()> {
        if has_rep {
            loop {
                let c: u64 = self.regs.read_sized(Reg::Rcx, count_bits);
                if c == 0 {
                    break;
                }
                body(self)?;
                let nc: u64 = c.wrapping_sub(1);
                self.regs.write_sized(Reg::Rcx, nc, count_bits);
            }
        } else {
            body(self)?;
        }
        Ok(())
    }

    fn run_string_cmp<F: FnMut(&mut Self) -> Result<bool>>(
        &mut self,
        has_rep: bool,
        count_bits: u8,
        mut body: F,
        zf_target: Option<bool>,
    ) -> Result<()> {
        if has_rep {
            loop {
                let c: u64 = self.regs.read_sized(Reg::Rcx, count_bits);
                if c == 0 {
                    break;
                }
                let zf: bool = body(self)?;
                let nc: u64 = c.wrapping_sub(1);
                self.regs.write_sized(Reg::Rcx, nc, count_bits);
                if let Some(target) = zf_target {
                    if zf != target {
                        break;
                    }
                }
            }
        } else {
            body(self)?;
        }
        Ok(())
    }

    fn encode_flags(&self) -> u64 {
        let f: &crate::stub_emu::regs::Flags = &self.regs.flags;
        (u64::from(f.cf))
            | (u64::from(f.pf) << 2)
            | (u64::from(f.af) << 4)
            | (u64::from(f.zf) << 6)
            | (u64::from(f.sf) << 7)
            | (u64::from(f.df) << 10)
            | (u64::from(f.of) << 11)
            | 0x2
    }

    fn decode_flags(&mut self, v: u64) {
        let f: &mut crate::stub_emu::regs::Flags = &mut self.regs.flags;
        f.cf = (v & 0x001) != 0;
        f.pf = (v & 0x004) != 0;
        f.af = (v & 0x010) != 0;
        f.zf = (v & 0x040) != 0;
        f.sf = (v & 0x080) != 0;
        f.df = (v & 0x400) != 0;
        f.of = (v & 0x800) != 0;
    }
}

/// Map a buffer into emulated memory at the given guest address.
pub fn map_buffer(mem: &mut Memory, addr: u64, bytes: &[u8], perm: Perm) -> Result<()> {
    mem.map(addr, bytes.len() as u64, perm);
    mem.write_unchecked(addr, bytes);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_cpu_with(prog: &[u8], base: u64) -> Cpu {
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
        cpu.mem.map(base, 0x1000, Perm::RWX);
        cpu.mem.write_unchecked(base, prog);
        cpu.mem.map(0x2_0000, 0x1000, Perm::RW);
        cpu.regs.set(Reg::Rsp, 0x2_0FF0);
        cpu.regs.rip = base;
        cpu
    }

    #[test]
    fn seh_dispatch_transfers_null_write_fault_to_handler() {
        const TEB: u64 = 0x7EFD_E000;
        const HANDLER: u64 = 0x0050_0000;
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
        cpu.enable_seh_dispatch();
        cpu.mem.map(0x4000, 0x1000, Perm::RWX);
        cpu.mem.map(0x2_0000, 0x4000, Perm::RW);
        cpu.mem.map(TEB, 0x2000, Perm::RW);
        cpu.mem.map(HANDLER, 0x1000, Perm::RWX);
        cpu.set_fs_base(TEB);
        let frame: u64 = 0x2_2000;
        cpu.mem.write_u32(frame, 0xFFFF_FFFF).unwrap();
        cpu.mem.write_u32(frame + 4, HANDLER as u32).unwrap();
        cpu.mem.write_u32(TEB, frame as u32).unwrap();
        let prog: [u8; 4] = [0x33, 0xC0, 0x89, 0x08];
        cpu.mem.write_unchecked(0x4000, &prog);
        cpu.mem.write_unchecked(HANDLER, &[0xEB, 0xFE]);
        cpu.regs.rip = 0x4000;
        cpu.regs.set(Reg::Rsp, 0x2_3F00);
        let mut host: NoopHost = NoopHost;
        let exit: ExitReason = cpu.run(&mut host, 100).unwrap();
        assert!(
            matches!(exit, ExitReason::StepCap(_)),
            "handler is an infinite loop; SEH dispatch must keep running, got {exit:?}",
        );
        assert_eq!(
            cpu.regs.rip, HANDLER,
            "a null write under SEH dispatch must transfer to the registered handler",
        );
    }

    #[test]
    fn seh_dispatch_disabled_surfaces_guest_fault() {
        let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
        cpu.mem.map(0x4000, 0x1000, Perm::RWX);
        cpu.mem.map(0x2_0000, 0x1000, Perm::RW);
        cpu.mem.write_unchecked(0x4000, &[0x33, 0xC0, 0x89, 0x08]);
        cpu.regs.rip = 0x4000;
        cpu.regs.set(Reg::Rsp, 0x2_0FF0);
        let mut host: NoopHost = NoopHost;
        let exit: ExitReason = cpu.run(&mut host, 100).unwrap();
        assert!(
            matches!(exit, ExitReason::GuestFault(_)),
            "without SEH dispatch a null write must surface as a guest fault, got {exit:?}",
        );
    }

    #[test]
    fn mov_add_runs() {
        let prog: [u8; 12] = [
            0xB8, 0x05, 0x00, 0x00, 0x00, 0x05, 0x03, 0x00, 0x00, 0x00, 0xEB, 0xFE,
        ];
        let mut cpu: Cpu = build_cpu_with(&prog, 0x1000);
        let mut host: NoopHost = NoopHost;
        let _r: ExitReason = cpu.run(&mut host, 5).unwrap();
        assert_eq!(cpu.regs.get(Reg::Rax) & 0xFFFF_FFFF, 8);
    }

    #[test]
    fn loop_decrements_and_jumps() {
        let mut prog: Vec<u8> = Vec::new();
        prog.extend_from_slice(&[0xB9, 0x05, 0x00, 0x00, 0x00]);
        prog.extend_from_slice(&[0xBB, 0x00, 0x00, 0x00, 0x00]);
        prog.extend_from_slice(&[0x43]);
        prog.extend_from_slice(&[0xE2, 0xFD]);
        prog.push(0xCC);
        let mut cpu: Cpu = build_cpu_with(&prog, 0x100);
        let mut host: NoopHost = NoopHost;
        let _r: ExitReason = cpu.run(&mut host, 200).unwrap();
        assert_eq!(
            cpu.regs.read_sized(Reg::Rcx, 32),
            0,
            "loop must drive ecx to 0"
        );
        assert_eq!(
            cpu.regs.read_sized(Reg::Rbx, 32),
            5,
            "inc ebx must run 5 times"
        );
    }

    #[test]
    fn lodsb_stosb_loop_runs() {
        let mut prog: Vec<u8> = Vec::new();
        prog.extend_from_slice(&[0xBE, 0x00, 0x10, 0x00, 0x00]);
        prog.extend_from_slice(&[0xBF, 0x80, 0x10, 0x00, 0x00]);
        prog.extend_from_slice(&[0xB9, 0x04, 0x00, 0x00, 0x00]);
        prog.extend_from_slice(&[0xAC]);
        prog.extend_from_slice(&[0xAA]);
        prog.extend_from_slice(&[0xE2, 0xFC]);
        prog.push(0xCC);
        let mut cpu: Cpu = build_cpu_with(&prog, 0x100);
        cpu.mem.write_unchecked(0x1000, b"WXYZ");
        let mut host: NoopHost = NoopHost;
        let _r: ExitReason = cpu.run(&mut host, 200).unwrap();
        assert_eq!(cpu.mem.read_lossy(0x1080, 4), b"WXYZ".to_vec());
    }

    #[test]
    fn btr_clears_bit_and_sets_carry() {
        let prog: [u8; 12] = [
            0xB8, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0xBA, 0xF0, 0x01, 0x90, 0xEB, 0xFE,
        ];
        let mut cpu: Cpu = build_cpu_with(&prog, 0x100);
        let mut host: NoopHost = NoopHost;
        let _r: ExitReason = cpu.run(&mut host, 6).unwrap();
        assert_eq!(
            cpu.regs.read_sized(Reg::Rax, 32),
            0x0D,
            "btr eax,1 must clear bit 1 of 0x0F → 0x0D"
        );
        assert!(
            cpu.regs.flags.cf,
            "btr must set CF to the prior bit value (1)"
        );
    }

    #[test]
    fn bsf_finds_lowest_set_bit() {
        let prog: [u8; 11] = [
            0xB8, 0x00, 0x01, 0x00, 0x00, 0x0F, 0xBC, 0xC0, 0x90, 0xEB, 0xFE,
        ];
        let mut cpu: Cpu = build_cpu_with(&prog, 0x100);
        let mut host: NoopHost = NoopHost;
        let _r: ExitReason = cpu.run(&mut host, 6).unwrap();
        assert_eq!(
            cpu.regs.read_sized(Reg::Rax, 32),
            8,
            "bsf eax,eax on 0x100 must yield bit index 8"
        );
        assert!(!cpu.regs.flags.zf, "bsf on nonzero source must clear ZF");
    }

    #[test]
    fn fs_segment_read_resolves_to_teb_base() {
        let prog: [u8; 8] = [0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, 0xEB, 0xFE];
        let mut cpu: Cpu = build_cpu_with(&prog, 0x100);
        cpu.mem.map(0x7EFD_E000, 0x1000, Perm::RW);
        cpu.mem.write_u32(0x7EFD_E018, 0xDEAD_BEEF).unwrap();
        cpu.set_fs_base(0x7EFD_E000);
        let mut host: NoopHost = NoopHost;
        let _r: ExitReason = cpu.run(&mut host, 4).unwrap();
        assert_eq!(
            cpu.regs.read_sized(Reg::Rax, 32),
            0xDEAD_BEEF,
            "mov eax, fs:[0x18] must read the TEB self-pointer via the FS base"
        );
    }

    #[test]
    fn lazy_commit_bounds_unmapped_writes() {
        let prog: [u8; 8] = [0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0xEB, 0xFE];
        let mut cpu: Cpu = build_cpu_with(&prog, 0x100);
        cpu.regs.set(Reg::Rax, 0x9_0000);
        cpu.mem.enable_lazy_commit(4);
        let mut host: NoopHost = NoopHost;
        let _r: ExitReason = cpu.run(&mut host, 4).unwrap();
        assert_eq!(
            cpu.mem.read_u32(0x9_0000).unwrap(),
            1,
            "lazy-commit must map the page on first unmapped write and persist the store"
        );
    }

    const MMX_DATA_A: u64 = 0x2_0100;
    const MMX_DATA_B: u64 = 0x2_0108;

    fn run_mmx(prog: &[u8], a: u64, b: u64, steps: u64) -> Cpu {
        let mut cpu: Cpu = build_cpu_with(prog, 0x100);
        cpu.mem.write_u64(MMX_DATA_A, a).unwrap();
        cpu.mem.write_u64(MMX_DATA_B, b).unwrap();
        let mut host: NoopHost = NoopHost;
        let _r: ExitReason = cpu.run(&mut host, steps).unwrap();
        cpu
    }

    const LOAD_MM0_A: [u8; 8] = [0xBE, 0x00, 0x01, 0x02, 0x00, 0x0F, 0x6F, 0x06];
    const LOAD_MM1_B: [u8; 8] = [0xBF, 0x08, 0x01, 0x02, 0x00, 0x0F, 0x6F, 0x0F];

    fn mmx_prog(tail: &[u8]) -> Vec<u8> {
        let mut prog: Vec<u8> = Vec::new();
        prog.extend_from_slice(&LOAD_MM0_A);
        prog.extend_from_slice(&LOAD_MM1_B);
        prog.extend_from_slice(tail);
        prog
    }

    #[test]
    fn mmx_movd_punpcklwd_known_answer() {
        let prog: [u8; 14] = [
            0xB8, 0x34, 0x12, 0x00, 0x00, 0x0F, 0x6E, 0xC0, 0x0F, 0x61, 0xC0, 0x0F, 0x61, 0xC0,
        ];
        let cpu: Cpu = run_mmx(&prog, 0, 0, 4);
        assert_eq!(
            cpu.regs.get_mm(0),
            0x1234_1234_1234_1234,
            "movd then two punpcklwd must broadcast low word 0x1234 across all four lanes"
        );
    }

    #[test]
    fn mmx_pcmpeqb_psrlw_all_ones_path() {
        let prog: Vec<u8> = mmx_prog(&[0x0F, 0x74, 0xC1, 0x0F, 0x71, 0xD0, 0x0F]);
        let cpu: Cpu = run_mmx(&prog, 0x1122_3344_5566_7788, 0x1100_3300_5500_7700, 6);
        assert_eq!(
            cpu.regs.get_mm(0),
            0x0001_0001_0001_0001,
            "pcmpeqb yields 0xFF00 per word where the high byte matches; psrlw 15 leaves 0x0001 per lane"
        );
    }

    #[test]
    fn mmx_paddsw_saturates_signed_words() {
        let prog: Vec<u8> = mmx_prog(&[0x0F, 0xED, 0xC1]);
        let cpu: Cpu = run_mmx(&prog, 0x7FFF_7FFF_8000_8000, 0x7FFF_7FFF_8000_8000, 5);
        assert_eq!(
            cpu.regs.get_mm(0),
            0x7FFF_7FFF_8000_8000,
            "0x7FFF+0x7FFF saturates to 0x7FFF; 0x8000+0x8000 saturates to i16::MIN 0x8000"
        );
    }

    #[test]
    fn mmx_pmulhw_high_signed_product() {
        let prog: Vec<u8> = mmx_prog(&[0x0F, 0xE5, 0xC1]);
        let cpu: Cpu = run_mmx(&prog, 0x4000_4000_4000_4000, 0x4000_4000_4000_4000, 5);
        assert_eq!(
            cpu.regs.get_mm(0),
            0x1000_1000_1000_1000,
            "0x4000 * 0x4000 = 0x1000_0000; high 16 bits = 0x1000 per lane"
        );
    }

    #[test]
    fn mmx_pmaddwd_sums_adjacent_products() {
        let prog: Vec<u8> = mmx_prog(&[0x0F, 0xF5, 0xC1]);
        let cpu: Cpu = run_mmx(&prog, 0x0002_0002_0002_0002, 0x0002_0002_0002_0002, 5);
        assert_eq!(
            cpu.regs.get_mm(0),
            0x0000_0008_0000_0008,
            "each dword lane = 2*2 + 2*2 = 8"
        );
    }

    #[test]
    fn mmx_psadbw_sum_of_absolute_differences() {
        let prog: Vec<u8> = mmx_prog(&[0x0F, 0xF6, 0xC1]);
        let cpu: Cpu = run_mmx(&prog, 0x0102_0304_0506_0708, 0x0000_0000_0000_0000, 5);
        assert_eq!(
            cpu.regs.get_mm(0),
            36u64,
            "sum of |byte - 0| over the eight bytes 1..8 = 36, placed in low word of lane 0"
        );
    }

    #[test]
    fn mmx_psrad_sign_extends_per_dword() {
        let prog: Vec<u8> = mmx_prog(&[0x0F, 0x72, 0xE0, 0x04]);
        let cpu: Cpu = run_mmx(&prog, 0x8000_0000_8000_0000, 0, 5);
        assert_eq!(
            cpu.regs.get_mm(0),
            0xF800_0000_F800_0000,
            "psrad by 4 on 0x80000000 sign-extends to 0xF8000000 per dword lane"
        );
    }

    #[test]
    fn mmx_paddd_paddb_psubd_lanes() {
        let prog_d: Vec<u8> = mmx_prog(&[0x0F, 0xFE, 0xC1]);
        let cpu_d: Cpu = run_mmx(&prog_d, 0xFFFF_FFFF_0000_0001, 0x0000_0002_0000_0002, 5);
        assert_eq!(
            cpu_d.regs.get_mm(0),
            0x0000_0001_0000_0003,
            "paddd: 0x00000001+0x00000002=3; 0xFFFFFFFF+0x00000002 wraps to 0x00000001"
        );

        let prog_b: Vec<u8> = mmx_prog(&[0x0F, 0xFC, 0xC1]);
        let cpu_b: Cpu = run_mmx(&prog_b, 0x0102_0304_05FF_FF01, 0x0101_0101_0101_01FF, 5);
        assert_eq!(
            cpu_b.regs.get_mm(0),
            0x0203_0405_0600_0000,
            "paddb wraps each byte lane independently"
        );

        let prog_s: Vec<u8> = mmx_prog(&[0x0F, 0xFA, 0xC1]);
        let cpu_s: Cpu = run_mmx(&prog_s, 0x0000_0005_0000_0001, 0x0000_0002_0000_0002, 5);
        assert_eq!(
            cpu_s.regs.get_mm(0),
            0x0000_0003_FFFF_FFFF,
            "psubd: 1-2 wraps to 0xFFFFFFFF; 5-2=3"
        );
    }

    #[test]
    fn mmx_pxor_and_emms_zero_register() {
        let prog: Vec<u8> = mmx_prog(&[0x0F, 0xEF, 0xC0, 0x0F, 0x77]);
        let cpu: Cpu = run_mmx(&prog, 0xDEAD_BEEF_CAFE_BABE, 0, 5);
        assert_eq!(
            cpu.regs.get_mm(0),
            0,
            "pxor mm0,mm0 zeroes the register; emms is a clean no-op for the model"
        );
    }

    #[test]
    fn mmx_movq_mem_roundtrip() {
        let prog: Vec<u8> = mmx_prog(&[0x0F, 0x7F, 0x4E, 0x10]);
        let cpu: Cpu = run_mmx(&prog, 0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF00, 5);
        assert_eq!(
            cpu.mem.read_u64(MMX_DATA_A + 0x10).unwrap(),
            0x99AA_BBCC_DDEE_FF00,
            "movq [esi+0x10], mm1 must store the 64-bit MMX value little-endian"
        );
    }
}
