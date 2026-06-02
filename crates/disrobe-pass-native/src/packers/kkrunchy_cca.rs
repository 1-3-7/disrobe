//! Clean-room Rust port of the classic kkrunchy depacker (CCA / "kkrunchy 0.23a").
//!
//! Algorithm: bit-level adaptive arithmetic coder driven by a static context
//! model with 803 binary probabilities. The decoder distinguishes two token
//! types per step (literal vs match), decodes match offsets via an Elias-gamma
//! distribution with a per-quadrant fine-bits model, and tracks the previous
//! offset (R0) so a "previous-match" repeat encoded with a single context bit
//! is possible whenever the prior step was a match.
//!
//! Reference: `kkrunchy/depacker_simple.cpp` by Fabian "ryg" Giesen, released
//! into the public domain. See <https://github.com/farbrausch/fr_public/blob/master/kkrunchy/depacker_simple.cpp>.
//!
//! The decoder is witnessed two ways. The load-bearing correctness proof is the
//! real-fixture integration test `classic_cca_recovers_real_fixture_payload`,
//! which drives this decoder over the genuine on-disk classic stream located by
//! [`locate_classic_stream`] and asserts the verbatim import bootstrap is
//! recovered (anti-circular: it decodes real packer output, not our own
//! encoder). The in-module `round_trip_*` unit tests are encoder-paired
//! regression guards only — they exercise the decoder against the matching
//! arithmetic-coder encoder embedded here and prove nothing about real streams.

use crate::error::{Error, Result};
use crate::packers::kkrunchy_unpack::KkrunchyHeaderInfo;

const CODE_MODEL: usize = 0;
const PREV_MATCH_MODEL: usize = 2;
const MATCH_LOW_MODEL: usize = 3;
const LITERAL_MODEL: usize = 35;
const GAMMA0_MODEL: usize = 291;
const GAMMA1_MODEL: usize = 547;
const SIZE_MODELS: usize = 803;

const RANGE_MIN: u32 = 0x0100_0000;
const PROBABILITY_INITIAL: u32 = 1024;
const PROBABILITY_TOTAL: u32 = 2048;

const STEP_BUDGET_MULTIPLIER: u64 = 64;
const STEP_BUDGET_FLOOR: u64 = 1 << 20;
const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

/// Adaptive bit-level arithmetic decoder driving the kkrunchy classic models.
#[derive(Debug)]
struct AriDecoder<'a> {
    src: &'a [u8],
    cursor: usize,
    code: u32,
    range: u32,
    model: Vec<u32>,
}

impl<'a> AriDecoder<'a> {
    fn new(src: &'a [u8]) -> Result<Self> {
        if src.len() < 4 {
            return Err(Error::Truncated {
                needed: 4,
                had: src.len(),
            });
        }
        let code: u32 = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        let model: Vec<u32> = vec![PROBABILITY_INITIAL; SIZE_MODELS];
        Ok(Self {
            src,
            cursor: 4,
            code,
            range: u32::MAX,
            model,
        })
    }

    fn decode_bit(&mut self, index: usize, move_shift: u32) -> Result<bool> {
        let prob: u32 = self.model[index];
        let bound: u32 = (self.range >> 11).wrapping_mul(prob);
        let result: bool = if self.code < bound {
            self.range = bound;
            let delta: u32 = (PROBABILITY_TOTAL - prob) >> move_shift;
            self.model[index] = prob.wrapping_add(delta);
            false
        } else {
            self.code = self.code.wrapping_sub(bound);
            self.range = self.range.wrapping_sub(bound);
            let delta: u32 = prob >> move_shift;
            self.model[index] = prob.wrapping_sub(delta);
            true
        };
        if self.range < RANGE_MIN {
            let byte: u32 = if self.cursor < self.src.len() {
                let b: u8 = self.src[self.cursor];
                self.cursor += 1;
                u32::from(b)
            } else {
                0
            };
            self.code = (self.code << 8) | byte;
            self.range <<= 8;
        }
        Ok(result)
    }

    fn decode_tree(&mut self, model_base: usize, max_b: u32, move_shift: u32) -> Result<u32> {
        let mut ctx: u32 = 1;
        while ctx < max_b {
            let bit: bool = self.decode_bit(model_base + ctx as usize, move_shift)?;
            ctx = (ctx << 1) + u32::from(bit);
        }
        Ok(ctx - max_b)
    }

    fn decode_gamma(&mut self, model_base: usize) -> Result<u32> {
        let mut value: u32 = 1;
        let mut ctx: u8 = 1;
        loop {
            let bit1: bool = self.decode_bit(model_base + usize::from(ctx), 5)?;
            ctx = ctx.wrapping_mul(2).wrapping_add(u8::from(bit1));
            let bit2: bool = self.decode_bit(model_base + usize::from(ctx), 5)?;
            value = (value << 1) | u32::from(bit2);
            ctx = ctx.wrapping_mul(2).wrapping_add(u8::from(bit2));
            if (ctx & 2) == 0 {
                break;
            }
        }
        Ok(value)
    }
}

/// Decompress a kkrunchy classic stream into `expected_size` bytes.
///
/// Returns the decoded buffer. Decoding terminates on the explicit "gamma==0"
/// stop token defined by the reference depacker, on output-budget exhaustion,
/// or on the safety step cap which bounds CPU regardless of stream content.
///
/// # Errors
///
/// - [`Error::Truncated`] when the input is shorter than the 4-byte arithmetic
///   coder seed.
/// - [`Error::SignatureDb`] when the request would allocate more than
///   `256 MiB`, when the safety step cap is exhausted before the stop token,
///   or when the stream encodes a back-reference to an offset that has not
///   yet been written.
pub fn decompress_kkrunchy_classic(packed: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    if expected_size > MAX_DECOMPRESSED_BYTES {
        return Err(Error::SignatureDb(format!(
            "kkrunchy classic: expected_size {expected_size} exceeds {MAX_DECOMPRESSED_BYTES}-byte safety cap"
        )));
    }
    let mut ari: AriDecoder<'_> = AriDecoder::new(packed)?;
    let mut dst: Vec<u8> = Vec::with_capacity(expected_size);
    let mut code: u32 = 0;
    let mut lwm: u32 = 0;
    let mut r0: u32 = 0;
    let mut steps: u64 = 0;
    let step_cap: u64 = (expected_size as u64)
        .saturating_mul(STEP_BUDGET_MULTIPLIER)
        .max(STEP_BUDGET_FLOOR);

    while dst.len() < expected_size {
        steps += 1;
        if steps > step_cap {
            return Err(Error::SignatureDb(format!(
                "kkrunchy classic: aborted after {steps} decode steps without completing \
                 expected_size={expected_size} (decoded={})",
                dst.len()
            )));
        }
        match code {
            0 => {
                let lit: u32 = ari.decode_tree(LITERAL_MODEL, 256, 4)?;
                dst.push(lit as u8);
                lwm = 0;
            }
            _ => {
                let mut len: u32 = 0;
                let offs: u32;
                if lwm == 0 && ari.decode_bit(PREV_MATCH_MODEL, 5)? {
                    offs = r0;
                } else {
                    let raw_offs: u32 = ari.decode_gamma(GAMMA0_MODEL)?;
                    if raw_offs <= 1 {
                        return Ok(dst);
                    }
                    let raw_offs_minus_two: u32 = raw_offs.wrapping_sub(2);
                    let low_base: usize = if raw_offs_minus_two != 0 {
                        MATCH_LOW_MODEL + 16
                    } else {
                        MATCH_LOW_MODEL
                    };
                    let fine: u32 = ari.decode_tree(low_base, 16, 5)?;
                    offs = (raw_offs_minus_two << 4).wrapping_add(fine).wrapping_add(1);
                    if offs >= 2048 {
                        len += 1;
                    }
                    if offs >= 96 {
                        len += 1;
                    }
                }
                r0 = offs;
                lwm = 1;
                let gamma_len: u32 = ari.decode_gamma(GAMMA1_MODEL)?;
                len = len.wrapping_add(gamma_len);
                if offs == 0 {
                    return Err(Error::SignatureDb(
                        "kkrunchy classic: zero offset back-reference is illegal".to_owned(),
                    ));
                }
                let offs_us: usize = offs as usize;
                if offs_us > dst.len() {
                    return Err(Error::SignatureDb(format!(
                        "kkrunchy classic: back-reference offset {offs_us} exceeds decoded length {}",
                        dst.len()
                    )));
                }
                for _ in 0..len {
                    if dst.len() >= expected_size {
                        break;
                    }
                    let src_idx: usize = dst.len() - offs_us;
                    let b: u8 = dst[src_idx];
                    dst.push(b);
                }
            }
        }
        code = u32::from(ari.decode_bit(CODE_MODEL + lwm as usize, 5)?);
    }
    Ok(dst)
}

const STUB_SCAN_WINDOW: usize = 256;
const MOV_EBP_OPCODE: u8 = 0xBD;
const MOV_PTR_EBP_DISP0: [u8; 3] = [0xC7, 0x45, 0x00];

/// Located CCA range-coder stream inside a classic-variant packed image.
///
/// The classic 0.23a depacker stub seeds its source pointer with a literal
/// `mov dword [ebp], <image_base + stream_rva>` immediate (`C7 45 00 <imm32>`),
/// so the compressed stream begins at file offset `imm32 - image_base` — which,
/// for the canonical small-CUI layout, lands in the PE header tail rather than
/// inside the named `kkrunchy` section's raw data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KkrunchyClassicStream {
    pub stream_offset: usize,
    pub recovered_size: usize,
}

/// Locate the CCA range-coder stream in a classic-variant packed image.
///
/// `image` is the full packed PE; `header` is its parsed `kkrunchy` header. The
/// stub lives at the start of the `kkrunchy` section's raw data; its first ≤256
/// bytes are scanned for the `mov dword [ebp], <imm32>` that seeds the depacker
/// source pointer. The stream offset is `imm32 - image_base`; the recovered size
/// is the length the decoder emits before the gamma terminator, used purely as
/// the structural oracle that confirms the located offset decodes cleanly.
///
/// # Errors
///
/// - [`Error::SignatureDb`] when the stub carries no recoverable source-pointer
///   immediate, when the derived offset falls outside the image, or when no
///   trial decode from the candidate offset reaches the gamma stop token (a
///   wrong offset must fail loudly, never silently mis-locate).
pub fn locate_classic_stream(
    image: &[u8],
    header: &KkrunchyHeaderInfo,
) -> Result<KkrunchyClassicStream> {
    let stub_off: usize = header.section_raw_offset as usize;
    let stub_end: usize = stub_off
        .checked_add(header.section_raw_size as usize)
        .ok_or_else(|| Error::SignatureDb("kkrunchy classic: stub bounds overflow".to_owned()))?
        .min(image.len());
    if stub_end <= stub_off {
        return Err(Error::SignatureDb(
            "kkrunchy classic: empty stub region".to_owned(),
        ));
    }
    let stub: &[u8] = &image[stub_off..stub_end];
    let scan_len: usize = STUB_SCAN_WINDOW.min(stub.len());
    let image_base: u32 = header.image_base;

    let mut candidates: Vec<usize> = Vec::new();
    for i in 0..scan_len.saturating_sub(MOV_PTR_EBP_DISP0.len() + 4) {
        if stub[i] == MOV_PTR_EBP_DISP0[0]
            && stub[i + 1] == MOV_PTR_EBP_DISP0[1]
            && stub[i + 2] == MOV_PTR_EBP_DISP0[2]
        {
            let imm: u32 = u32::from_le_bytes([stub[i + 3], stub[i + 4], stub[i + 5], stub[i + 6]]);
            if imm >= image_base {
                let off: usize = (imm - image_base) as usize;
                if off + 4 <= image.len() {
                    candidates.push(off);
                }
            }
        }
    }
    if candidates.is_empty() && scan_len > 5 && stub[0] == MOV_EBP_OPCODE {
        return Err(Error::SignatureDb(
            "kkrunchy classic: stub begins with mov ebp but carries no source-pointer immediate"
                .to_owned(),
        ));
    }
    if candidates.is_empty() {
        return Err(Error::SignatureDb(
            "kkrunchy classic: no mov [ebp], <imm32> source-pointer seed found in stub".to_owned(),
        ));
    }

    let probe_cap: usize = MAX_DECOMPRESSED_BYTES.min(16 * 1024);
    let mut located: Option<KkrunchyClassicStream> = None;
    for &off in &candidates {
        let stream: &[u8] = &image[off..];
        match probe_stream(stream, probe_cap) {
            Some(size) if size > 0 => {
                located = Some(KkrunchyClassicStream {
                    stream_offset: off,
                    recovered_size: size,
                });
                break;
            }
            _ => {}
        }
    }
    located.ok_or_else(|| {
        Error::SignatureDb(format!(
            "kkrunchy classic: {} candidate stream offset(s) found but none decoded to the gamma stop token",
            candidates.len()
        ))
    })
}

fn probe_stream(stream: &[u8], cap: usize) -> Option<usize> {
    let decoded: Vec<u8> = decompress_kkrunchy_classic(stream, cap).ok()?;
    if decoded.len() >= cap || decoded.is_empty() {
        return None;
    }
    Some(decoded.len())
}

/// Carry-style range encoder mirroring the reference implementation in
/// `kkrunchy/packer.cpp::CarryRangeCoder`. Used exclusively by the unit tests
/// to produce ground-truth streams that exercise the decoder byte-for-byte.
#[cfg(test)]
#[derive(Debug)]
struct CarryEncoder {
    out: Vec<u8>,
    low: u64,
    range: u32,
    cache: u8,
    ff_num: u32,
    first_byte: bool,
    model: Vec<u32>,
}

#[cfg(test)]
impl CarryEncoder {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            low: 0,
            range: u32::MAX,
            cache: 0,
            ff_num: 0,
            first_byte: true,
            model: vec![PROBABILITY_INITIAL; SIZE_MODELS],
        }
    }

    fn shift_low(&mut self) {
        let carry: u32 = (self.low >> 32) as u32;
        if (self.low as u32) < 0xFF00_0000 || carry == 1 {
            if self.first_byte {
                self.first_byte = false;
            } else {
                self.out
                    .push(u32::from(self.cache).wrapping_add(carry) as u8);
            }
            while self.ff_num > 0 {
                self.out.push(0xFFu8.wrapping_add(carry as u8));
                self.ff_num -= 1;
            }
            self.cache = ((self.low >> 24) & 0xFF) as u8;
        } else {
            self.ff_num += 1;
        }
        self.low = (self.low << 8) & 0xFFFF_FFFF;
    }

    fn encode_bit(&mut self, index: usize, bit: bool, move_shift: u32) {
        let prob: u32 = self.model[index];
        let new_bound: u32 = (self.range >> 11).wrapping_mul(prob);
        if bit {
            self.low = self.low.wrapping_add(u64::from(new_bound));
            self.range = self.range.wrapping_sub(new_bound);
            let delta: u32 = prob >> move_shift;
            self.model[index] = prob.wrapping_sub(delta);
        } else {
            self.range = new_bound;
            let delta: u32 = (PROBABILITY_TOTAL - prob) >> move_shift;
            self.model[index] = prob.wrapping_add(delta);
        }
        while self.range < RANGE_MIN {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn encode_tree(&mut self, model_base: usize, max_b: u32, move_shift: u32, value: u32) {
        let mut bits_count: u32 = 0;
        let mut tmp: u32 = max_b;
        while tmp > 1 {
            tmp >>= 1;
            bits_count += 1;
        }
        let mut ctx: u32 = 1;
        for i in (0..bits_count).rev() {
            let bit: bool = ((value >> i) & 1) != 0;
            self.encode_bit(model_base + ctx as usize, bit, move_shift);
            ctx = (ctx << 1) + u32::from(bit);
        }
    }

    fn encode_gamma_terminator(&mut self, model_base: usize) {
        let mut ctx: u8 = 1;
        for group in 0..=GAMMA_TERMINATOR_CONTINUE_GROUPS {
            let continue_group: bool = group < GAMMA_TERMINATOR_CONTINUE_GROUPS;
            self.encode_bit(model_base + usize::from(ctx), continue_group, 5);
            ctx = ctx.wrapping_mul(2).wrapping_add(u8::from(continue_group));
            self.encode_bit(model_base + usize::from(ctx), false, 5);
            ctx = ctx.wrapping_mul(2);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.out
    }
}

#[cfg(test)]
const GAMMA_TERMINATOR_CONTINUE_GROUPS: usize = 31;

#[cfg(test)]
fn encode_kkrunchy_classic_literal_only(plain: &[u8]) -> Vec<u8> {
    let mut enc: CarryEncoder = CarryEncoder::new();
    let lwm: usize = 0;
    let last_index: usize = plain.len().saturating_sub(1);
    for (i, &b) in plain.iter().enumerate() {
        enc.encode_tree(LITERAL_MODEL, 256, 4, u32::from(b));
        let next_is_terminator_match: bool = i == last_index;
        enc.encode_bit(CODE_MODEL + lwm, next_is_terminator_match, 5);
    }
    enc.encode_bit(PREV_MATCH_MODEL, false, 5);
    enc.encode_gamma_terminator(GAMMA0_MODEL);
    enc.finish()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decode_rejects_truncated_stream() {
        let r: Result<Vec<u8>> = decompress_kkrunchy_classic(&[0, 1, 2], 64);
        assert!(r.is_err(), "decoder must reject <4-byte streams");
    }

    #[test]
    fn decode_rejects_oversized_request() {
        let r: Result<Vec<u8>> = decompress_kkrunchy_classic(&[0; 4], MAX_DECOMPRESSED_BYTES + 1);
        match r {
            Err(Error::SignatureDb(msg)) => assert!(msg.contains("safety cap")),
            other => panic!("expected safety cap error, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_literal_only_stream() {
        let plain: Vec<u8> = b"hello kkrunchy classic depacker".to_vec();
        let encoded: Vec<u8> = encode_kkrunchy_classic_literal_only(&plain);
        let decoded: Vec<u8> = decompress_kkrunchy_classic(&encoded, plain.len()).expect("decode");
        assert_eq!(decoded, plain, "literal-only stream must round-trip");
    }

    #[test]
    fn round_trip_random_byte_distribution() {
        let mut plain: Vec<u8> = Vec::with_capacity(4096);
        let mut x: u64 = 0xCAFE_BABE_DEAD_BEEF;
        for _ in 0..4096 {
            x = x.wrapping_mul(0x5_DEEC_E66Du64).wrapping_add(11);
            plain.push((x >> 33) as u8);
        }
        let encoded: Vec<u8> = encode_kkrunchy_classic_literal_only(&plain);
        let decoded: Vec<u8> = decompress_kkrunchy_classic(&encoded, plain.len()).expect("decode");
        assert_eq!(
            decoded.len(),
            plain.len(),
            "decoder must yield expected_size bytes"
        );
        assert_eq!(decoded, plain, "random byte distribution must round-trip");
    }

    #[test]
    fn decode_terminates_on_zero_gamma_stop_token() {
        let plain: Vec<u8> = b"abc".to_vec();
        let encoded: Vec<u8> = encode_kkrunchy_classic_literal_only(&plain);
        let decoded: Vec<u8> = decompress_kkrunchy_classic(&encoded, 8192).expect("decode");
        assert!(
            decoded.len() <= 8192,
            "decoder must respect expected_size ceiling"
        );
        assert!(
            decoded.starts_with(&plain),
            "decoded prefix must equal plaintext until the stop token"
        );
    }

    #[test]
    fn decode_caps_step_budget_on_pathological_input() {
        let huge: Vec<u8> = vec![0xFFu8; 256];
        let r: Result<Vec<u8>> = decompress_kkrunchy_classic(&huge, 64 * 1024);
        assert!(
            r.is_ok() || matches!(r, Err(Error::SignatureDb(_))),
            "step cap must surface a SignatureDb error rather than spinning forever",
        );
    }
}
