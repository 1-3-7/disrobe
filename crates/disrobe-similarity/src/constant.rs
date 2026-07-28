pub const SMALL_INTEGER_CEILING: u64 = 0x100;

const CANDIDATE_WIDTH_BITS: [u32; 4] = [8, 16, 32, 64];

const SMALLEST_REPEATING_UNIT_BITS: u32 = 8;

#[must_use]
pub const fn is_discriminating_constant(value: u64) -> bool {
    if value <= SMALL_INTEGER_CEILING {
        return false;
    }
    if value.is_power_of_two() || value.wrapping_add(1).is_power_of_two() {
        return false;
    }
    let mut index: usize = 0;
    while index < CANDIDATE_WIDTH_BITS.len() {
        let bits: u32 = CANDIDATE_WIDTH_BITS[index];
        if fits_in_width(value, bits) && is_ordinary_at_width(value, bits) {
            return false;
        }
        index += 1;
    }
    true
}

const fn fits_in_width(value: u64, bits: u32) -> bool {
    bits >= u64::BITS || value < (1u64 << bits)
}

const fn is_ordinary_at_width(value: u64, bits: u32) -> bool {
    let magnitude: u64 = sign_extended_magnitude(value, bits);
    magnitude <= SMALL_INTEGER_CEILING
        || magnitude.is_power_of_two()
        || magnitude.wrapping_add(1).is_power_of_two()
        || has_repeating_unit(value, bits)
}

const fn sign_extended_magnitude(value: u64, bits: u32) -> u64 {
    if bits >= u64::BITS {
        return value.cast_signed().unsigned_abs();
    }
    let vacant: u32 = u64::BITS - bits;
    ((value << vacant).cast_signed() >> vacant).unsigned_abs()
}

const fn has_repeating_unit(value: u64, bits: u32) -> bool {
    let mut unit: u32 = SMALLEST_REPEATING_UNIT_BITS;
    while unit < bits {
        if is_uniform_repetition(value, bits, unit) {
            return true;
        }
        unit *= 2;
    }
    false
}

const fn is_uniform_repetition(value: u64, bits: u32, unit: u32) -> bool {
    let mask: u64 = (1u64 << unit) - 1;
    let head: u64 = value & mask;
    let mut shift: u32 = unit;
    while shift < bits {
        if (value >> shift) & mask != head {
            return false;
        }
        shift += unit;
    }
    true
}
