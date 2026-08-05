use std::collections::BTreeMap;

pub(crate) const IMAGE_BASE: u64 = 0x1000;
pub(crate) const IMAGE_BYTES: usize = 0x3000;
pub(crate) const CODE_ADDRESS: u64 = 0x1000;
pub(crate) const DATA_BASE: u64 = 0x2000;
pub(crate) const STACK_POINTER: u64 = 0x3800;
pub(crate) const GPR_COUNT: usize = 16;

pub(crate) const CARRY_BIT: u32 = 0;
pub(crate) const PARITY_BIT: u32 = 2;
pub(crate) const ADJUST_BIT: u32 = 4;
pub(crate) const ZERO_BIT: u32 = 6;
pub(crate) const SIGN_BIT: u32 = 7;
pub(crate) const DIRECTION_BIT: u32 = 10;
pub(crate) const OVERFLOW_BIT: u32 = 11;

pub(crate) const OBSERVED_FLAGS: u16 = (1 << CARRY_BIT)
    | (1 << PARITY_BIT)
    | (1 << ADJUST_BIT)
    | (1 << ZERO_BIT)
    | (1 << SIGN_BIT)
    | (1 << DIRECTION_BIT)
    | (1 << OVERFLOW_BIT);

pub(crate) const FLAG_NAMES: [(u32, &str); 7] = [
    (CARRY_BIT, "CF"),
    (PARITY_BIT, "PF"),
    (ADJUST_BIT, "AF"),
    (ZERO_BIT, "ZF"),
    (SIGN_BIT, "SF"),
    (DIRECTION_BIT, "DF"),
    (OVERFLOW_BIT, "OF"),
];

pub(crate) const REGISTER_NAMES: [&str; GPR_COUNT] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MachineState {
    pub(crate) registers: [u64; GPR_COUNT],
    pub(crate) rip: u64,
    pub(crate) flags: u16,
    pub(crate) memory: Vec<u8>,
}

impl MachineState {
    pub(crate) const fn new(memory: Vec<u8>) -> Self {
        Self {
            registers: [0; GPR_COUNT],
            rip: CODE_ADDRESS,
            flags: 0,
            memory,
        }
    }

    pub(crate) fn write_memory(&mut self, address: u64, size_bytes: usize, value: u64) -> bool {
        let Ok(start): Result<usize, _> = usize::try_from(address.wrapping_sub(IMAGE_BASE)) else {
            return false;
        };
        if address < IMAGE_BASE {
            return false;
        }
        let Some(end): Option<usize> = start.checked_add(size_bytes) else {
            return false;
        };
        let Some(slice): Option<&mut [u8]> = self.memory.get_mut(start..end) else {
            return false;
        };
        for (index, byte) in slice.iter_mut().enumerate() {
            let shift: u32 = u32::try_from(index).unwrap_or(0).saturating_mul(8);
            *byte = value.checked_shr(shift).unwrap_or(0) as u8;
        }
        true
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct StateDelta {
    pub(crate) registers: BTreeMap<usize, u64>,
    pub(crate) rip: u64,
    pub(crate) flags: u16,
    pub(crate) memory: BTreeMap<u64, u8>,
}

impl StateDelta {
    pub(crate) fn between(before: &MachineState, after: &MachineState) -> Self {
        let mut registers: BTreeMap<usize, u64> = BTreeMap::new();
        for index in 0..GPR_COUNT {
            let (previous, current): (Option<&u64>, Option<&u64>) =
                (before.registers.get(index), after.registers.get(index));
            if previous != current
                && let Some(value) = current
            {
                let _: Option<u64> = registers.insert(index, *value);
            }
        }
        let mut memory: BTreeMap<u64, u8> = BTreeMap::new();
        for (offset, byte) in after.memory.iter().enumerate() {
            if before.memory.get(offset) != Some(byte) {
                let address: u64 = IMAGE_BASE.wrapping_add(offset as u64);
                let _: Option<u8> = memory.insert(address, *byte);
            }
        }
        Self {
            registers,
            rip: after.rip,
            flags: after.flags & OBSERVED_FLAGS,
            memory,
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut delta: Self = Self::default();
        let mut saw_rip: bool = false;
        let mut saw_flags: bool = false;
        for field in text.split('|') {
            let (key, value): (&str, &str) = field.split_once('=')?;
            match key {
                "ip" => {
                    delta.rip = u64::from_str_radix(value, 16).ok()?;
                    saw_rip = true;
                }
                "f" => {
                    delta.flags = u16::from_str_radix(value, 16).ok()? & OBSERVED_FLAGS;
                    saw_flags = true;
                }
                register if register.starts_with('r') => {
                    let index: usize = register.get(1..)?.parse().ok()?;
                    if index >= GPR_COUNT {
                        return None;
                    }
                    let _: Option<u64> = delta
                        .registers
                        .insert(index, u64::from_str_radix(value, 16).ok()?);
                }
                location if location.starts_with('m') => {
                    let address: u64 = u64::from_str_radix(location.get(1..)?, 16).ok()?;
                    let _: Option<u8> = delta
                        .memory
                        .insert(address, u8::from_str_radix(value, 16).ok()?);
                }
                _ => return None,
            }
        }
        (saw_rip && saw_flags).then_some(delta)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    Completed(Box<StateDelta>),
    Faulted(String),
    Rejected(String),
}

impl Outcome {
    pub(crate) fn parse(status: &str, payload: &str) -> Option<Self> {
        match status {
            "ok" => {
                StateDelta::parse(payload).map(|delta: StateDelta| Self::Completed(Box::new(delta)))
            }
            "fault" if !payload.is_empty() => Some(Self::Faulted(payload.to_owned())),
            "reject" if !payload.is_empty() => Some(Self::Rejected(payload.to_owned())),
            _ => None,
        }
    }
}

pub(crate) fn is_address_fault(reason: &str) -> bool {
    reason.ends_with("_UNMAPPED") || reason.ends_with("_PROT")
}

pub(crate) fn flag_label(bit: u32) -> &'static str {
    FLAG_NAMES
        .iter()
        .find(|(position, _): &&(u32, &'static str)| *position == bit)
        .map_or("??", |(_, name): &(u32, &'static str)| *name)
}

pub(crate) fn register_label(index: usize) -> &'static str {
    REGISTER_NAMES.get(index).copied().unwrap_or("r??")
}
