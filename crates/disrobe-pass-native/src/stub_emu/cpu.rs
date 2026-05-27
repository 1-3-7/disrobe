//! Fetch / decode / execute loop driven by `iced-x86`.

use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register,
};

use crate::error::{Error, Result};
use crate::stub_emu::mem::{Memory, Perm};
use crate::stub_emu::regs::{CpuMode, Reg, Regs, classify};

/// Reason the emulator returned control to the host.
#[derive(Debug, Clone)]
pub enum ExitReason {
    /// Instruction-count budget exhausted.
    StepCap(u64),
    /// Branched into a page that is not mapped — taken as OEP transfer.
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
}

impl Cpu {
    #[must_use]
    pub fn new(mode: CpuMode) -> Self {
        Self {
            regs: Regs::new(mode),
            mem: Memory::new(),
            mode,
        }
    }

    /// Run until exhaustion, OEP-jump, or unsupported opcode.
    pub fn run<H: HostCall>(&mut self, host: &mut H, step_cap: u64) -> Result<ExitReason> {
        let mut steps: u64 = 0;
        loop {
            if steps >= step_cap {
                return Ok(ExitReason::StepCap(steps));
            }
            steps += 1;
            let ip: u64 = self.regs.rip;
            if !self.mem.is_mapped(ip) {
                return Ok(ExitReason::JumpedOutOfRange { from: ip, to: ip });
            }
            let bytes: Vec<u8> = self.mem.read_lossy(ip, 16);
            let mut decoder: Decoder<'_> =
                Decoder::with_ip(self.mode.bits(), &bytes, ip, DecoderOptions::NONE);
            let mut insn: Instruction = Instruction::default();
            decoder.decode_out(&mut insn);
            if insn.is_invalid() {
                return Ok(ExitReason::UnsupportedInstr {
                    ip,
                    mnemonic: "INVALID".to_owned(),
                });
            }
            let next_ip: u64 = insn.next_ip();
            self.regs.rip = next_ip;
            match self.execute_one(&insn, host) {
                Ok(Some(reason)) => return Ok(reason),
                Ok(None) => {}
                Err(e) => return Ok(ExitReason::GuestFault(e.to_string())),
            }
        }
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
                let mnem = insn.mnemonic();
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
        let f = &self.regs.flags;
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
        let mnem = insn.mnemonic();
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
        let f = &self.regs.flags;
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
        let f = &mut self.regs.flags;
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
}
