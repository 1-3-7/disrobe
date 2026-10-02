use crate::chunks::Chunks;
use crate::disasm::Operand;

const TYPE_INTEGER: u16 = 1 << 5;
const TYPE_KINDS: u16 = (1 << 12) - 1;
const HAS_LOWER_BOUND: u16 = 1 << 12;
const HAS_UPPER_BOUND: u16 = 1 << 13;
const HAS_UNIT: u16 = 1 << 14;
const MAX_TYPE_ENTRIES: u32 = 1 << 20;

#[derive(Debug, Default)]
pub(super) struct OperandTypes {
    kinds: Vec<u16>,
}

impl OperandTypes {
    pub(super) fn decode(chunks: &Chunks) -> Self {
        chunks
            .other
            .get("Type")
            .and_then(|data: &Vec<u8>| decode_table(data))
            .map_or_else(Self::default, |kinds: Vec<u16>| Self { kinds })
    }

    pub(super) fn is_integer(&self, op: &Operand) -> bool {
        match op {
            Operand::Literal(_) | Operand::SignedInteger(_) | Operand::BigInteger { .. } => true,
            Operand::TypedReg { type_index, .. } => usize::try_from(*type_index)
                .ok()
                .and_then(|index: usize| self.kinds.get(index))
                .is_some_and(|kinds: &u16| *kinds == TYPE_INTEGER),
            _ => false,
        }
    }

    pub(super) fn is_nonzero_integer_literal(op: &Operand) -> bool {
        match op {
            Operand::Literal(value) => *value != 0,
            Operand::SignedInteger(value) => *value != 0,
            Operand::BigInteger { magnitude_be, .. } => magnitude_be.iter().any(|b: &u8| *b != 0),
            _ => false,
        }
    }
}

fn decode_table(data: &[u8]) -> Option<Vec<u16>> {
    let version: u32 = u32::from_be_bytes(data.get(0..4)?.try_into().ok()?);
    let count: u32 = u32::from_be_bytes(data.get(4..8)?.try_into().ok()?);
    if count > MAX_TYPE_ENTRIES {
        return None;
    }
    let mut cursor: usize = 8;
    let mut kinds: Vec<u16> = Vec::with_capacity(usize::try_from(count).ok()?.min(data.len() / 2));
    for _ in 0..count {
        let raw: u16 = u16::from_be_bytes(data.get(cursor..cursor + 2)?.try_into().ok()?);
        cursor += 2;
        let bits: u16 = match version {
            3 => raw,
            1 | 2 => (raw & 3) | ((raw & !3) >> 1),
            _ => return None,
        };
        let extra: usize = if version == 1 {
            16
        } else {
            [(HAS_LOWER_BOUND, 8), (HAS_UPPER_BOUND, 8), (HAS_UNIT, 1)]
                .iter()
                .filter(|(flag, _): &&(u16, usize)| bits & flag != 0)
                .map(|(_, size): &(u16, usize)| size)
                .sum()
        };
        cursor = cursor.checked_add(extra)?;
        if cursor > data.len() {
            return None;
        }
        kinds.push(bits & TYPE_KINDS);
    }
    (cursor == data.len()).then_some(kinds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_three_entries_skip_their_bounds_and_unit() {
        let mut data: Vec<u8> = vec![0, 0, 0, 3, 0, 0, 0, 3];
        data.extend_from_slice(&(TYPE_INTEGER | HAS_LOWER_BOUND | HAS_UPPER_BOUND).to_be_bytes());
        data.extend_from_slice(&0i64.to_be_bytes());
        data.extend_from_slice(&255i64.to_be_bytes());
        data.extend_from_slice(&((1u16 << 1) | HAS_UNIT).to_be_bytes());
        data.push(7);
        data.extend_from_slice(&(TYPE_INTEGER | (1 << 3)).to_be_bytes());
        assert_eq!(
            decode_table(&data),
            Some(vec![TYPE_INTEGER, 1 << 1, TYPE_INTEGER | (1 << 3)])
        );
    }

    #[test]
    fn a_truncated_or_padded_table_yields_no_facts() {
        let mut data: Vec<u8> = vec![0, 0, 0, 3, 0, 0, 0, 1];
        data.extend_from_slice(&(TYPE_INTEGER | HAS_LOWER_BOUND).to_be_bytes());
        data.extend_from_slice(&[0, 0, 0]);
        assert_eq!(decode_table(&data), None);
        let mut padded: Vec<u8> = vec![0, 0, 0, 3, 0, 0, 0, 1];
        padded.extend_from_slice(&TYPE_INTEGER.to_be_bytes());
        padded.push(0);
        assert_eq!(decode_table(&padded), None);
    }

    #[test]
    fn version_two_drops_the_match_context_bit() {
        let mut data: Vec<u8> = vec![0, 0, 0, 2, 0, 0, 0, 1];
        data.extend_from_slice(&((TYPE_INTEGER << 1) | (HAS_LOWER_BOUND << 1)).to_be_bytes());
        data.extend_from_slice(&1i64.to_be_bytes());
        assert_eq!(decode_table(&data), Some(vec![TYPE_INTEGER]));
    }
}
