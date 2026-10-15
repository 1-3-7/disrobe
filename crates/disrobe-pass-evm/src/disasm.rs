use std::fmt::Write as _;

use serde::Serialize;

use crate::opcode::{self, JUMPDEST};
use crate::u256::U256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Instruction {
    pub pc: usize,
    pub opcode: u8,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immediate: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[must_use]
pub fn mnemonic(opcode: u8) -> String {
    opcode::info(opcode).map_or_else(
        || format!("UNDEFINED(0x{opcode:02x})"),
        |op| op.name.to_owned(),
    )
}

#[must_use]
pub fn push_value(code: &[u8], pc: usize) -> (U256, bool) {
    let width: usize = opcode::immediate_len(code[pc]);
    let start: usize = pc + 1;
    let end: usize = (start + width).min(code.len());
    let available: &[u8] = code.get(start..end).unwrap_or(&[]);
    let mut padded: [u8; 32] = [0; 32];
    padded[32 - width..32 - width + available.len()].copy_from_slice(available);
    (U256::from_be_bytes(padded), available.len() < width)
}

#[must_use]
pub fn decode(code: &[u8]) -> Vec<Instruction> {
    let mut out: Vec<Instruction> = Vec::new();
    let mut pc: usize = 0;
    while pc < code.len() {
        let byte: u8 = code[pc];
        let width: usize = opcode::immediate_len(byte);
        let (immediate, truncated): (Option<String>, bool) = if width > 0 {
            let (value, truncated) = push_value(code, pc);
            let digits: String = value.to_be_bytes()[32 - width..].iter().fold(
                String::new(),
                |mut text: String, byte: &u8| {
                    let _ = write!(text, "{byte:02x}");
                    text
                },
            );
            (Some(format!("0x{digits}")), truncated)
        } else {
            (None, false)
        };
        out.push(Instruction {
            pc,
            opcode: byte,
            name: mnemonic(byte),
            immediate,
            truncated,
        });
        pc += 1 + width;
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpDests {
    bits: Vec<u64>,
}

impl JumpDests {
    #[must_use]
    pub fn analyse(code: &[u8]) -> Self {
        let mut bits: Vec<u64> = vec![0; code.len().div_ceil(64)];
        let mut pc: usize = 0;
        while pc < code.len() {
            if code[pc] == JUMPDEST {
                bits[pc / 64] |= 1 << (pc % 64);
            }
            pc += 1 + opcode::immediate_len(code[pc]);
        }
        Self { bits }
    }

    #[must_use]
    pub fn contains(&self, pc: usize) -> bool {
        self.bits
            .get(pc / 64)
            .is_some_and(|word: &u64| (word >> (pc % 64)) & 1 == 1)
    }

    #[must_use]
    pub fn valid_target(&self, target: U256) -> Option<usize> {
        target.to_usize().filter(|pc: &usize| self.contains(*pc))
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.bits
            .iter()
            .map(|word: &u64| word.count_ones() as usize)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::{JumpDests, decode};

    #[test]
    fn push_data_hides_jumpdest_bytes() {
        let code: [u8; 6] = [0x61, 0x5b, 0x5b, 0x5b, 0x60, 0x01];
        let dests: JumpDests = JumpDests::analyse(&code);
        assert!(!dests.contains(1));
        assert!(!dests.contains(2));
        assert!(dests.contains(3));
        let listing = decode(&code);
        assert_eq!(listing.len(), 3);
        assert_eq!(listing[0].immediate.as_deref(), Some("0x5b5b"));
        assert_eq!(listing[2].name, "PUSH1");
        let truncated = decode(&[0x62, 0x01]);
        assert!(truncated[0].truncated);
        assert_eq!(truncated[0].immediate.as_deref(), Some("0x010000"));
    }
}
