use super::opcodes::{KOI_OP_MAX, KoiOp, KoiReg};
use super::random::NetRandom;

#[derive(Debug, Clone)]
pub struct KoiDescriptors {
    opcode_decode: [Option<KoiOp>; 256],
    register_decode: [Option<KoiReg>; 256],
    vcall_order: [u32; 256],
    seed: i32,
}

impl KoiDescriptors {
    #[must_use]
    pub fn from_seed(seed: i32) -> Self {
        let mut rng: NetRandom = NetRandom::new(seed);

        let mut opcode_order: [u8; 256] = core::array::from_fn(|i: usize| i as u8);
        rng.shuffle(&mut opcode_order);

        let mut flag_order: [i32; 8] = core::array::from_fn(|i: usize| i as i32);
        rng.shuffle(&mut flag_order);

        let mut reg_order: [u8; 16] = core::array::from_fn(|i: usize| i as u8);
        rng.shuffle(&mut reg_order);

        let mut call_order: [u32; 256] = core::array::from_fn(|i: usize| i as u32);
        let mut call_order_i32: [i32; 256] = core::array::from_fn(|i: usize| i as i32);
        rng.shuffle(&mut call_order_i32);
        for (slot, value) in call_order.iter_mut().zip(call_order_i32.iter()) {
            *slot = value.cast_unsigned();
        }

        let mut opcode_decode: [Option<KoiOp>; 256] = [None; 256];
        for ordinal in 0u8..KOI_OP_MAX {
            let encoded: u8 = opcode_order[usize::from(ordinal)];
            opcode_decode[usize::from(encoded)] = KoiOp::from_ordinal(ordinal);
        }

        let mut register_decode: [Option<KoiReg>; 256] = [None; 256];
        for ordinal in 0u8..16u8 {
            let encoded: u8 = reg_order[usize::from(ordinal)];
            register_decode[usize::from(encoded)] = KoiReg::from_ordinal(ordinal);
        }

        Self {
            opcode_decode,
            register_decode,
            vcall_order: call_order,
            seed,
        }
    }

    #[must_use]
    pub const fn seed(&self) -> i32 {
        self.seed
    }

    #[must_use]
    pub fn decode_opcode(&self, encoded: u8) -> Option<KoiOp> {
        self.opcode_decode[usize::from(encoded)]
    }

    #[must_use]
    pub fn decode_register(&self, encoded: u8) -> Option<KoiReg> {
        self.register_decode[usize::from(encoded)]
    }

    #[must_use]
    pub fn vcall_name(&self, code: u32) -> Option<&'static str> {
        const NAMES: [&str; 17] = [
            "EXIT",
            "BREAK",
            "ECALL",
            "CAST",
            "CKFINITE",
            "CKOVERFLOW",
            "RANGECHK",
            "INITOBJ",
            "LDFLD",
            "LDFTN",
            "TOKEN",
            "THROW",
            "SIZEOF",
            "STFLD",
            "BOX",
            "UNBOX",
            "LOCALLOC",
        ];
        for (ordinal, name) in NAMES.iter().enumerate() {
            if self.vcall_order[ordinal] == code {
                return Some(name);
            }
        }
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decode_round_trips_opcode_map_seed0() {
        let desc: KoiDescriptors = KoiDescriptors::from_seed(0);
        assert_eq!(desc.decode_opcode(144), Some(KoiOp::Nop));
        assert_eq!(desc.decode_opcode(198), Some(KoiOp::LindPtr));
        assert_eq!(desc.decode_opcode(189), Some(KoiOp::LindObject));
        assert_eq!(desc.decode_opcode(36), Some(KoiOp::LindByte));
    }

    #[test]
    fn decode_round_trips_register_map_seed0() {
        let desc: KoiDescriptors = KoiDescriptors::from_seed(0);
        assert_eq!(desc.decode_register(1), Some(KoiReg::R0));
        assert_eq!(desc.decode_register(3), Some(KoiReg::R1));
        assert_eq!(desc.decode_register(15), Some(KoiReg::R2));
        assert_eq!(desc.decode_register(12), Some(KoiReg::M2));
    }

    #[test]
    fn vcall_names_resolve_seed0() {
        let desc: KoiDescriptors = KoiDescriptors::from_seed(0);
        assert_eq!(desc.vcall_name(166), Some("EXIT"));
        assert_eq!(desc.vcall_name(58), Some("BREAK"));
        assert_eq!(desc.vcall_name(13), Some("CAST"));
    }
}
