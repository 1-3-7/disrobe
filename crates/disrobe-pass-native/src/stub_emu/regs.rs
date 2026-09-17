use iced_x86::Register;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuMode {
    Bits32,
    Bits64,
}

impl CpuMode {
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }

    #[must_use]
    pub const fn ptr_size(self) -> u8 {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Reg {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

const NUM_GPR: usize = 16;

const NUM_MMX: usize = 8;

#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {
    pub cf: bool,
    pub pf: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
    pub af: bool,
    pub df: bool,
}

#[derive(Debug, Clone)]
pub struct Regs {
    gpr: [u64; NUM_GPR],
    mmx: [u64; NUM_MMX],
    pub rip: u64,
    pub flags: Flags,
    pub mode: CpuMode,
}

impl Regs {
    #[must_use]
    pub fn new(mode: CpuMode) -> Self {
        Self {
            gpr: [0u64; NUM_GPR],
            mmx: [0u64; NUM_MMX],
            rip: 0,
            flags: Flags::default(),
            mode,
        }
    }

    #[must_use]
    pub fn get_mm(&self, index: u8) -> u64 {
        self.mmx[index as usize]
    }

    pub fn set_mm(&mut self, index: u8, value: u64) {
        self.mmx[index as usize] = value;
    }

    #[must_use]
    pub fn get(&self, r: Reg) -> u64 {
        self.gpr[r as usize]
    }

    pub fn set(&mut self, r: Reg, v: u64) {
        self.gpr[r as usize] = v;
    }

    pub fn write_sized(&mut self, r: Reg, value: u64, size_bits: u8) {
        let idx: usize = r as usize;
        let cur: u64 = self.gpr[idx];
        let new: u64 = match size_bits {
            8 => (cur & !0xFFu64) | (value & 0xFF),
            16 => (cur & !0xFFFFu64) | (value & 0xFFFF),
            32 => value & 0xFFFF_FFFFu64,
            _ => value,
        };
        self.gpr[idx] = new;
    }

    #[must_use]
    pub fn read_sized(&self, r: Reg, size_bits: u8) -> u64 {
        let v: u64 = self.gpr[r as usize];
        match size_bits {
            8 => v & 0xFF,
            16 => v & 0xFFFF,
            32 => v & 0xFFFF_FFFF,
            _ => v,
        }
    }

    #[must_use]
    pub fn read_high8(&self, r: Reg) -> u64 {
        (self.gpr[r as usize] >> 8) & 0xFF
    }

    pub fn write_high8(&mut self, r: Reg, value: u64) {
        let idx: usize = r as usize;
        let cur: u64 = self.gpr[idx];
        self.gpr[idx] = (cur & !0xFF00u64) | ((value & 0xFF) << 8);
    }
}

#[must_use]
pub fn classify(reg: Register) -> Option<(Reg, u8, bool)> {
    use Register as R;
    let m: (Reg, u8, bool) = match reg {
        R::AL => (Reg::Rax, 8, false),
        R::CL => (Reg::Rcx, 8, false),
        R::DL => (Reg::Rdx, 8, false),
        R::BL => (Reg::Rbx, 8, false),
        R::SPL => (Reg::Rsp, 8, false),
        R::BPL => (Reg::Rbp, 8, false),
        R::SIL => (Reg::Rsi, 8, false),
        R::DIL => (Reg::Rdi, 8, false),
        R::R8L => (Reg::R8, 8, false),
        R::R9L => (Reg::R9, 8, false),
        R::R10L => (Reg::R10, 8, false),
        R::R11L => (Reg::R11, 8, false),
        R::R12L => (Reg::R12, 8, false),
        R::R13L => (Reg::R13, 8, false),
        R::R14L => (Reg::R14, 8, false),
        R::R15L => (Reg::R15, 8, false),

        R::AH => (Reg::Rax, 8, true),
        R::CH => (Reg::Rcx, 8, true),
        R::DH => (Reg::Rdx, 8, true),
        R::BH => (Reg::Rbx, 8, true),

        R::AX => (Reg::Rax, 16, false),
        R::CX => (Reg::Rcx, 16, false),
        R::DX => (Reg::Rdx, 16, false),
        R::BX => (Reg::Rbx, 16, false),
        R::SP => (Reg::Rsp, 16, false),
        R::BP => (Reg::Rbp, 16, false),
        R::SI => (Reg::Rsi, 16, false),
        R::DI => (Reg::Rdi, 16, false),
        R::R8W => (Reg::R8, 16, false),
        R::R9W => (Reg::R9, 16, false),
        R::R10W => (Reg::R10, 16, false),
        R::R11W => (Reg::R11, 16, false),
        R::R12W => (Reg::R12, 16, false),
        R::R13W => (Reg::R13, 16, false),
        R::R14W => (Reg::R14, 16, false),
        R::R15W => (Reg::R15, 16, false),

        R::EAX => (Reg::Rax, 32, false),
        R::ECX => (Reg::Rcx, 32, false),
        R::EDX => (Reg::Rdx, 32, false),
        R::EBX => (Reg::Rbx, 32, false),
        R::ESP => (Reg::Rsp, 32, false),
        R::EBP => (Reg::Rbp, 32, false),
        R::ESI => (Reg::Rsi, 32, false),
        R::EDI => (Reg::Rdi, 32, false),
        R::R8D => (Reg::R8, 32, false),
        R::R9D => (Reg::R9, 32, false),
        R::R10D => (Reg::R10, 32, false),
        R::R11D => (Reg::R11, 32, false),
        R::R12D => (Reg::R12, 32, false),
        R::R13D => (Reg::R13, 32, false),
        R::R14D => (Reg::R14, 32, false),
        R::R15D => (Reg::R15, 32, false),

        R::RAX => (Reg::Rax, 64, false),
        R::RCX => (Reg::Rcx, 64, false),
        R::RDX => (Reg::Rdx, 64, false),
        R::RBX => (Reg::Rbx, 64, false),
        R::RSP => (Reg::Rsp, 64, false),
        R::RBP => (Reg::Rbp, 64, false),
        R::RSI => (Reg::Rsi, 64, false),
        R::RDI => (Reg::Rdi, 64, false),
        R::R8 => (Reg::R8, 64, false),
        R::R9 => (Reg::R9, 64, false),
        R::R10 => (Reg::R10, 64, false),
        R::R11 => (Reg::R11, 64, false),
        R::R12 => (Reg::R12, 64, false),
        R::R13 => (Reg::R13, 64, false),
        R::R14 => (Reg::R14, 64, false),
        R::R15 => (Reg::R15, 64, false),

        _ => return None,
    };
    Some(m)
}

#[must_use]
pub fn classify_mm(reg: Register) -> Option<u8> {
    use Register as R;
    let index: u8 = match reg {
        R::MM0 => 0,
        R::MM1 => 1,
        R::MM2 => 2,
        R::MM3 => 3,
        R::MM4 => 4,
        R::MM5 => 5,
        R::MM6 => 6,
        R::MM7 => 7,
        _ => return None,
    };
    Some(index)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn write_sized_zero_extends_32() {
        let mut r: Regs = Regs::new(CpuMode::Bits64);
        r.set(Reg::Rax, 0xFFFF_FFFF_FFFF_FFFF);
        r.write_sized(Reg::Rax, 0x12345678, 32);
        assert_eq!(r.get(Reg::Rax), 0x12345678);
    }

    #[test]
    fn write_sized_8_preserves_upper() {
        let mut r: Regs = Regs::new(CpuMode::Bits32);
        r.set(Reg::Rax, 0xAABB_CCDD);
        r.write_sized(Reg::Rax, 0x11, 8);
        assert_eq!(r.get(Reg::Rax), 0xAABB_CC11);
    }

    #[test]
    fn high8_roundtrip() {
        let mut r: Regs = Regs::new(CpuMode::Bits32);
        r.set(Reg::Rax, 0);
        r.write_high8(Reg::Rax, 0x99);
        assert_eq!(r.read_high8(Reg::Rax), 0x99);
    }
}
