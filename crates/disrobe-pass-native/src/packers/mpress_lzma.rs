use crate::error::{Error, Result};

const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

const LZMA_LIT_SIZE: usize = 0x300;

const STATES: usize = 12;
const LIT_STATES: usize = 7;

const MAX_POS_BITS: usize = 4;
const MAX_POS_STATES: usize = 1 << MAX_POS_BITS;

const LEN_LOW_BITS: usize = 3;
const LEN_LOW_SYMBOLS: usize = 1 << LEN_LOW_BITS;
const LEN_MID_BITS: usize = 3;
const LEN_MID_SYMBOLS: usize = 1 << LEN_MID_BITS;
const LEN_HIGH_BITS: usize = 8;
const LEN_HIGH_SYMBOLS: usize = 1 << LEN_HIGH_BITS;

const POS_SLOT_BITS: usize = 6;
const NUM_LEN_TO_POS_STATES: usize = 4;
const NUM_ALIGN_BITS: usize = 4;
const NUM_ALIGN: usize = 1 << NUM_ALIGN_BITS;

const START_POS_MODEL_INDEX: usize = 4;
const END_POS_MODEL_INDEX: usize = 14;
const NUM_FULL_DISTANCES: usize = 1 << (END_POS_MODEL_INDEX >> 1);

const MATCH_MIN_LEN: u32 = 2;

const OFFSET_IS_MATCH: usize = 0;
const OFFSET_IS_REP: usize = OFFSET_IS_MATCH + (STATES << MAX_POS_BITS);
const OFFSET_IS_REP_G0: usize = OFFSET_IS_REP + STATES;
const OFFSET_IS_REP_G1: usize = OFFSET_IS_REP_G0 + STATES;
const OFFSET_IS_REP_G2: usize = OFFSET_IS_REP_G1 + STATES;
const OFFSET_IS_REP0_LONG: usize = OFFSET_IS_REP_G2 + STATES;
const OFFSET_POS_SLOT: usize = OFFSET_IS_REP0_LONG + (STATES << MAX_POS_BITS);
const OFFSET_SPEC_POS: usize = OFFSET_POS_SLOT + (NUM_LEN_TO_POS_STATES << POS_SLOT_BITS);
const OFFSET_ALIGN: usize = OFFSET_SPEC_POS + NUM_FULL_DISTANCES - END_POS_MODEL_INDEX;
const OFFSET_LEN_CODER: usize = OFFSET_ALIGN + NUM_ALIGN;
const LEN_CHOICE_2_OFF: usize = 1;
const LEN_LOW_OFF: usize = 2;
const LEN_MID_OFF: usize = LEN_LOW_OFF + (MAX_POS_STATES * LEN_LOW_SYMBOLS);
const LEN_HIGH_OFF: usize = LEN_MID_OFF + (MAX_POS_STATES * LEN_MID_SYMBOLS);
const LEN_CODER_SIZE: usize = LEN_HIGH_OFF + LEN_HIGH_SYMBOLS;
const OFFSET_REP_LEN_CODER: usize = OFFSET_LEN_CODER + LEN_CODER_SIZE;
const OFFSET_LITERAL: usize = OFFSET_REP_LEN_CODER + LEN_CODER_SIZE;

const PROB_INIT_VAL: u16 = 0x400;
const RANGE_TOP: u32 = 1 << 24;
const NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const NUM_MOVE_BITS: u32 = 5;

#[derive(Debug, Clone, Copy)]
pub struct MpressLzmaProps {
    pub lc: u8,
    pub lp: u8,
    pub pb: u8,
}

impl MpressLzmaProps {
    pub fn from_stream(stream: &[u8]) -> Result<Self> {
        if stream.len() < 2 {
            return Err(Error::Truncated {
                needed: 2,
                had: stream.len(),
            });
        }
        let byte0: u8 = stream[0];
        let byte1: u8 = stream[1];
        let pb: u8 = byte0 >> 4;
        let lp: u8 = byte0 & 0x0F;
        let lc: u8 = byte1;
        if lc > 8 || lp > 4 || pb > 4 {
            return Err(Error::SignatureDb(format!(
                "MPRESS LZMA props out of range: lc={lc} lp={lp} pb={pb}"
            )));
        }
        Ok(Self { lc, lp, pb })
    }

    #[must_use]
    pub const fn total_probs(self) -> usize {
        OFFSET_LITERAL + (LZMA_LIT_SIZE << (self.lc as usize + self.lp as usize))
    }
}

pub fn decode_mpress_lzma(stream: &[u8], decompressed_size: usize) -> Result<Vec<u8>> {
    if stream.len() < 7 {
        return Err(Error::Truncated {
            needed: 7,
            had: stream.len(),
        });
    }
    if decompressed_size > MAX_DECOMPRESSED_BYTES {
        return Err(Error::SignatureDb(format!(
            "MPRESS LZMA declared output {decompressed_size} exceeds {MAX_DECOMPRESSED_BYTES}-byte safety cap"
        )));
    }
    let props: MpressLzmaProps = MpressLzmaProps::from_stream(stream)?;
    let mut model: Vec<u16> = vec![PROB_INIT_VAL; props.total_probs()];
    let mut out: Vec<u8> = Vec::new();
    let mut decoder: Decoder = Decoder::new(&stream[2..], props, &mut model);
    decoder.init_range_coder()?;
    decoder.decode_loop(&mut out, decompressed_size)?;
    Ok(out)
}

struct Decoder<'a> {
    input: &'a [u8],
    input_pos: usize,
    props: MpressLzmaProps,
    model: &'a mut [u16],
    range: u32,
    code: u32,
    state: u32,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8], props: MpressLzmaProps, model: &'a mut [u16]) -> Self {
        Self {
            input,
            input_pos: 0,
            props,
            model,
            range: 0xFFFF_FFFF,
            code: 0,
            state: 0,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,
        }
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.input_pos >= self.input.len() {
            return Err(Error::Truncated {
                needed: self.input_pos + 1,
                had: self.input.len(),
            });
        }
        let b: u8 = self.input[self.input_pos];
        self.input_pos += 1;
        Ok(b)
    }

    fn init_range_coder(&mut self) -> Result<()> {
        let mut code: u32 = 0;
        for _ in 0..5 {
            let b: u8 = self.read_byte()?;
            code = code.wrapping_shl(8) | u32::from(b);
        }
        self.code = code;
        Ok(())
    }

    fn normalize(&mut self) -> Result<()> {
        if self.range < RANGE_TOP {
            self.range <<= 8;
            let b: u8 = self.read_byte()?;
            self.code = (self.code << 8) | u32::from(b);
        }
        Ok(())
    }

    fn decode_bit(&mut self, prob_index: usize) -> Result<u32> {
        let prob: u32 = u32::from(self.model[prob_index]);
        let bound: u32 = (self.range >> NUM_BIT_MODEL_TOTAL_BITS) * prob;
        if self.code < bound {
            self.range = bound;
            self.model[prob_index] = u16::try_from(
                u32::from(self.model[prob_index])
                    + (((1u32 << NUM_BIT_MODEL_TOTAL_BITS) - prob) >> NUM_MOVE_BITS),
            )
            .unwrap_or(u16::MAX);
            self.normalize()?;
            Ok(0)
        } else {
            self.range -= bound;
            self.code -= bound;
            self.model[prob_index] =
                u16::try_from(u32::from(self.model[prob_index]) - (prob >> NUM_MOVE_BITS))
                    .unwrap_or(0);
            self.normalize()?;
            Ok(1)
        }
    }

    fn decode_bit_tree(&mut self, prob_index: usize, num_bits: u32) -> Result<u32> {
        let mut m: u32 = 1;
        for _ in 0..num_bits {
            let bit: u32 = self.decode_bit(prob_index + m as usize)?;
            m = (m << 1) + bit;
        }
        Ok(m - (1u32 << num_bits))
    }

    fn decode_reverse_bit_tree(&mut self, prob_index: usize, num_bits: u32) -> Result<u32> {
        let mut m: u32 = 1;
        let mut sym: u32 = 0;
        for i in 0..num_bits {
            let bit: u32 = self.decode_bit(prob_index + m as usize)?;
            m = (m << 1) + bit;
            sym |= bit << i;
        }
        Ok(sym)
    }

    fn decode_direct_bits(&mut self, num_bits: u32) -> Result<u32> {
        let mut res: u32 = 0;
        for _ in 0..num_bits {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t: u32 = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            if self.code == self.range {
                return Err(Error::SignatureDb(
                    "MPRESS LZMA direct-bits range collapsed".to_owned(),
                ));
            }
            res = (res << 1).wrapping_add(t.wrapping_add(1));
            if self.range < RANGE_TOP {
                self.range <<= 8;
                let b: u8 = self.read_byte()?;
                self.code = (self.code << 8) | u32::from(b);
            }
        }
        Ok(res)
    }

    fn literal_probs_offset(&self, prev_byte: u8, out_pos: usize) -> usize {
        let lc: u32 = u32::from(self.props.lc);
        let lp: u32 = u32::from(self.props.lp);
        let lp_mask: usize = (1usize << lp) - 1;
        let prev_part: usize = if lc == 0 {
            0
        } else {
            (prev_byte as usize) >> (8 - lc as usize)
        };
        let index: usize = ((out_pos & lp_mask) << lc) + prev_part;
        OFFSET_LITERAL + index * LZMA_LIT_SIZE
    }

    fn decode_literal(&mut self, out: &[u8], prev_byte: u8) -> Result<u8> {
        let base: usize = self.literal_probs_offset(prev_byte, out.len());
        let mut sym: u32 = 1;
        if self.state >= 7 {
            let mut match_byte: u32 = u32::from(self.peek_match_byte(out)?);
            loop {
                let match_bit: u32 = (match_byte >> 7) & 1;
                match_byte <<= 1;
                let bit: u32 = self.decode_bit(base + (((1 + match_bit) << 8) | sym) as usize)?;
                sym = (sym << 1) | bit;
                if match_bit != bit {
                    break;
                }
                if sym >= 0x100 {
                    break;
                }
            }
        }
        while sym < 0x100 {
            let bit: u32 = self.decode_bit(base + sym as usize)?;
            sym = (sym << 1) | bit;
        }
        Ok((sym - 0x100) as u8)
    }

    fn peek_match_byte(&self, out: &[u8]) -> Result<u8> {
        let dist: usize = self.rep0 as usize + 1;
        if dist > out.len() {
            return Err(Error::SignatureDb(format!(
                "MPRESS LZMA match-byte peek out-of-range: dist={dist} out.len={}",
                out.len()
            )));
        }
        Ok(out[out.len() - dist])
    }

    fn decode_len(&mut self, len_coder_base: usize, pos_state: usize) -> Result<u32> {
        if self.decode_bit(len_coder_base)? == 0 {
            let probs_off: usize = len_coder_base + LEN_LOW_OFF + pos_state * LEN_LOW_SYMBOLS;
            let sym: u32 = self.decode_bit_tree(probs_off, LEN_LOW_BITS as u32)?;
            return Ok(MATCH_MIN_LEN + sym);
        }
        if self.decode_bit(len_coder_base + LEN_CHOICE_2_OFF)? == 0 {
            let probs_off: usize = len_coder_base + LEN_MID_OFF + pos_state * LEN_MID_SYMBOLS;
            let sym: u32 = self.decode_bit_tree(probs_off, LEN_MID_BITS as u32)?;
            return Ok(MATCH_MIN_LEN + LEN_LOW_SYMBOLS as u32 + sym);
        }
        let probs_off: usize = len_coder_base + LEN_HIGH_OFF;
        let sym: u32 = self.decode_bit_tree(probs_off, LEN_HIGH_BITS as u32)?;
        Ok(MATCH_MIN_LEN + LEN_LOW_SYMBOLS as u32 + LEN_MID_SYMBOLS as u32 + sym)
    }

    fn decode_distance(&mut self, len: u32) -> Result<u32> {
        let pos_state_for_distance: usize =
            (len as usize - MATCH_MIN_LEN as usize).min(NUM_LEN_TO_POS_STATES - 1);
        let pos_slot_base: usize = OFFSET_POS_SLOT + (pos_state_for_distance << POS_SLOT_BITS);
        let pos_slot: u32 = self.decode_bit_tree(pos_slot_base, POS_SLOT_BITS as u32)?;
        if (pos_slot as usize) < START_POS_MODEL_INDEX {
            return Ok(pos_slot);
        }
        let num_direct_bits: u32 = (pos_slot >> 1) - 1;
        let mut dist: u32 = (2 | (pos_slot & 1)) << num_direct_bits;
        if (pos_slot as usize) < END_POS_MODEL_INDEX {
            let probs_off: usize = OFFSET_SPEC_POS + dist as usize - pos_slot as usize;
            let extra: u32 = self.decode_reverse_bit_tree(probs_off, num_direct_bits)?;
            dist += extra;
        } else {
            let extra_high: u32 =
                self.decode_direct_bits(num_direct_bits - NUM_ALIGN_BITS as u32)?;
            dist += extra_high << NUM_ALIGN_BITS;
            let extra_low: u32 =
                self.decode_reverse_bit_tree(OFFSET_ALIGN, NUM_ALIGN_BITS as u32)?;
            dist += extra_low;
        }
        Ok(dist)
    }

    fn write_match(&self, out: &mut Vec<u8>, len: u32) -> Result<()> {
        let dist: usize = self.rep0 as usize + 1;
        if dist > out.len() {
            return Err(Error::SignatureDb(format!(
                "MPRESS LZMA copy-match dist={dist} exceeds out.len={}",
                out.len()
            )));
        }
        for _ in 0..len {
            let src: usize = out.len() - dist;
            let b: u8 = out[src];
            out.push(b);
        }
        Ok(())
    }

    fn update_state_literal(&mut self) {
        self.state = match self.state {
            0..=3 => 0,
            4..=9 => self.state - 3,
            _ => self.state - 6,
        };
    }

    fn update_state_match(&mut self) {
        self.state = if (self.state as usize) < LIT_STATES {
            7
        } else {
            10
        };
    }

    fn update_state_rep(&mut self) {
        self.state = if (self.state as usize) < LIT_STATES {
            8
        } else {
            11
        };
    }

    fn update_state_short_rep(&mut self) {
        self.state = if (self.state as usize) < LIT_STATES {
            9
        } else {
            11
        };
    }

    fn decode_loop(&mut self, out: &mut Vec<u8>, target_size: usize) -> Result<()> {
        let pb_mask: usize = (1usize << self.props.pb) - 1;
        while out.len() < target_size {
            let pos_state: usize = out.len() & pb_mask;
            let is_match_index: usize =
                OFFSET_IS_MATCH + ((self.state as usize) << MAX_POS_BITS) + pos_state;
            if self.decode_bit(is_match_index)? == 0 {
                let prev_byte: u8 = if out.is_empty() {
                    0
                } else {
                    out[out.len() - 1]
                };
                let byte: u8 = self.decode_literal(out, prev_byte)?;
                out.push(byte);
                self.update_state_literal();
                continue;
            }
            let len: u32;
            if self.decode_bit(OFFSET_IS_REP + self.state as usize)? != 0 {
                if self.decode_bit(OFFSET_IS_REP_G0 + self.state as usize)? == 0 {
                    let is_rep0_long_index: usize =
                        OFFSET_IS_REP0_LONG + ((self.state as usize) << MAX_POS_BITS) + pos_state;
                    if self.decode_bit(is_rep0_long_index)? == 0 {
                        let prev: u8 = self.peek_match_byte(out)?;
                        out.push(prev);
                        self.update_state_short_rep();
                        continue;
                    }
                } else {
                    let dist: u32;
                    if self.decode_bit(OFFSET_IS_REP_G1 + self.state as usize)? == 0 {
                        dist = self.rep1;
                    } else {
                        if self.decode_bit(OFFSET_IS_REP_G2 + self.state as usize)? == 0 {
                            dist = self.rep2;
                        } else {
                            dist = self.rep3;
                            self.rep3 = self.rep2;
                        }
                        self.rep2 = self.rep1;
                    }
                    self.rep1 = self.rep0;
                    self.rep0 = dist;
                }
                len = self.decode_len(OFFSET_REP_LEN_CODER, pos_state)?;
                self.update_state_rep();
            } else {
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                len = self.decode_len(OFFSET_LEN_CODER, pos_state)?;
                self.update_state_match();
                let dist: u32 = self.decode_distance(len)?;
                if dist == u32::MAX {
                    return Ok(());
                }
                self.rep0 = dist;
            }
            self.write_match(out, len)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::similar_names
)]
mod tests {
    use super::*;

    #[test]
    fn props_split_nibbles_correctly() {
        let stream: [u8; 2] = [0x10, 0x00];
        let p: MpressLzmaProps = MpressLzmaProps::from_stream(&stream).unwrap();
        assert_eq!(p.pb, 1, "stream[0] high nibble -> pb");
        assert_eq!(p.lp, 0, "stream[0] low nibble -> lp");
        assert_eq!(p.lc, 0, "stream[1] -> lc");
    }

    #[test]
    fn props_rejects_short_stream() {
        let stream: [u8; 1] = [0x10];
        assert!(MpressLzmaProps::from_stream(&stream).is_err());
    }

    #[test]
    fn props_rejects_out_of_range() {
        let high_lp: [u8; 2] = [0x05, 0x00];
        assert!(MpressLzmaProps::from_stream(&high_lp).is_err());
        let high_pb: [u8; 2] = [0x50, 0x00];
        assert!(MpressLzmaProps::from_stream(&high_pb).is_err());
        let high_lc: [u8; 2] = [0x00, 0x09];
        assert!(MpressLzmaProps::from_stream(&high_lc).is_err());
    }

    #[test]
    fn total_probs_matches_formula() {
        let p: MpressLzmaProps = MpressLzmaProps {
            lc: 1,
            lp: 0,
            pb: 0,
        };
        let expected: usize = OFFSET_LITERAL + (LZMA_LIT_SIZE << 1);
        assert_eq!(p.total_probs(), expected);
    }

    #[test]
    fn decode_rejects_truncated_stream() {
        let r: Result<Vec<u8>> = decode_mpress_lzma(&[0x10, 0x00], 16);
        assert!(r.is_err());
    }

    #[test]
    fn decode_short_stream_errors() {
        let stream: [u8; 7] = [0x10, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78];
        let r: Result<Vec<u8>> = decode_mpress_lzma(&stream, 16);
        assert!(matches!(
            r,
            Err(Error::Truncated { .. } | Error::SignatureDb(_))
        ));
    }
}
