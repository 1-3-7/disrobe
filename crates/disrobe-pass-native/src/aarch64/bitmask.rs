#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitMasks {
    pub wmask: u64,
    pub tmask: u64,
}

pub fn decode_bit_masks(
    n: bool,
    imms: u8,
    immr: u8,
    immediate: bool,
    width: u8,
) -> Option<BitMasks> {
    if imms > 0x3f || immr > 0x3f || (width != 32 && width != 64) {
        return None;
    }
    let complement: u8 = (!imms) & 0x3f;
    let length_input: u8 = (u8::from(n) << 6) | complement;
    let length: u8 = highest_set_bit(length_input)?;
    if length == 0 {
        return None;
    }
    let element_size: u8 = 1_u8.checked_shl(u32::from(length))?;
    if element_size > width {
        return None;
    }
    let levels: u8 = element_size.checked_sub(1)?;
    let s: u8 = imms & levels;
    if immediate && s == levels {
        return None;
    }
    let r: u8 = immr & levels;
    let difference: u16 = u16::from(s)
        .checked_add(u16::from(element_size))?
        .checked_sub(u16::from(r))?;
    let d: u8 = u8::try_from(difference & u16::from(levels)).ok()?;
    let welem: u64 = ones(s.checked_add(1)?);
    let telem: u64 = ones(d.checked_add(1)?);
    let rotated: u64 = rotate_right_element(welem, r, element_size)?;
    let wmask: u64 = replicate(rotated, element_size, width)?;
    let tmask: u64 = replicate(telem, element_size, width)?;
    Some(BitMasks { wmask, tmask })
}

fn highest_set_bit(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }
    let leading: u32 = value.leading_zeros();
    u8::try_from(u8::BITS.checked_sub(1)?.checked_sub(leading)?).ok()
}

fn ones(count: u8) -> u64 {
    match count {
        0 => 0,
        64 => u64::MAX,
        _ => (1_u64 << u32::from(count)) - 1,
    }
}

fn rotate_right_element(value: u64, amount: u8, width: u8) -> Option<u64> {
    if width == 0 || width > 64 || amount >= width {
        return None;
    }
    let mask: u64 = ones(width);
    if amount == 0 {
        return Some(value & mask);
    }
    let shift: u32 = u32::from(amount);
    let complement: u32 = u32::from(width).checked_sub(shift)?;
    Some(((value >> shift) | (value << complement)) & mask)
}

fn replicate(element: u64, element_width: u8, width: u8) -> Option<u64> {
    if element_width == 0 || width == 0 || width % element_width != 0 {
        return None;
    }
    let copies: u8 = width.checked_div(element_width)?;
    let mut result: u64 = 0;
    let mut copy: u8 = 0;
    while copy < copies {
        let shift: u32 = u32::from(copy).checked_mul(u32::from(element_width))?;
        result |= element.checked_shl(shift)?;
        copy = copy.checked_add(1)?;
    }
    Some(result)
}
