use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrvVariant {
    Nrv2b,
    Nrv2d,
    Nrv2e,
}

struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,
    buf: u32,
    bits_left: u32,
}

impl<'a> BitReader<'a> {
    const fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            buf: 0,
            bits_left: 0,
        }
    }

    fn next_byte(&mut self) -> Result<u8> {
        let byte: u8 = *self
            .src
            .get(self.pos)
            .ok_or_else(|| Error::Decompression("ucl: bitstream underrun".to_owned()))?;
        self.pos += 1;
        Ok(byte)
    }

    fn get_bit(&mut self) -> Result<u32> {
        if self.bits_left == 0 {
            let b0: u32 = u32::from(self.next_byte()?);
            let b1: u32 = u32::from(self.next_byte()?);
            let b2: u32 = u32::from(self.next_byte()?);
            let b3: u32 = u32::from(self.next_byte()?);
            self.buf = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            self.bits_left = 32;
        }
        self.bits_left -= 1;
        let bit: u32 = (self.buf >> 31) & 1;
        self.buf <<= 1;
        Ok(bit)
    }
}

const ACCUM_CEILING: usize = 1 << 40;

fn guard_accum(value: usize) -> Result<usize> {
    if value > ACCUM_CEILING {
        return Err(Error::Decompression(
            "ucl: bitstream length accumulator overflow".to_owned(),
        ));
    }
    Ok(value)
}

fn copy_match(out: &mut Vec<u8>, distance: usize, len: usize, cap: usize) -> Result<()> {
    if distance == 0 || distance > out.len() {
        return Err(Error::Decompression(format!(
            "ucl: match distance {distance} out of range (output {})",
            out.len()
        )));
    }
    if out.len() + len > cap {
        return Err(Error::Decompression("ucl: output exceeds cap".to_owned()));
    }
    let start: usize = out.len() - distance;
    for index in start..start + len {
        let byte: u8 = out[index];
        out.push(byte);
    }
    Ok(())
}

fn push_literal(reader: &mut BitReader<'_>, out: &mut Vec<u8>, cap: usize) -> Result<()> {
    if out.len() + 1 > cap {
        return Err(Error::Decompression("ucl: output exceeds cap".to_owned()));
    }
    out.push(reader.next_byte()?);
    Ok(())
}

pub fn decompress(variant: NrvVariant, src: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    let out: Vec<u8> = decompress_to_eos(variant, src, expected_len)?;
    if out.len() != expected_len {
        return Err(Error::Decompression(format!(
            "ucl: decoded {} bytes, expected {expected_len}",
            out.len()
        )));
    }
    Ok(out)
}

pub fn decompress_to_eos(variant: NrvVariant, src: &[u8], cap: usize) -> Result<Vec<u8>> {
    match variant {
        NrvVariant::Nrv2b => decompress_nrv2b(src, cap),
        NrvVariant::Nrv2d => decompress_nrv2d(src, cap),
        NrvVariant::Nrv2e => decompress_nrv2e(src, cap),
    }
}

fn decompress_nrv2b(src: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut reader: BitReader<'_> = BitReader::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    let mut last_m_off: usize = 1;
    loop {
        while reader.get_bit()? == 1 {
            push_literal(&mut reader, &mut out, cap)?;
        }
        let mut m_off: usize = 1;
        loop {
            m_off = guard_accum((m_off << 1) + reader.get_bit()? as usize)?;
            if reader.get_bit()? == 1 {
                break;
            }
        }
        if m_off == 2 {
            m_off = last_m_off;
        } else {
            m_off = (m_off - 3) * 256 + reader.next_byte()? as usize;
            if m_off == 0xFFFF_FFFF {
                break;
            }
            m_off += 1;
            last_m_off = m_off;
        }
        let mut m_len: usize = reader.get_bit()? as usize;
        m_len = (m_len << 1) + reader.get_bit()? as usize;
        if m_len == 0 {
            m_len = 1;
            loop {
                m_len = guard_accum((m_len << 1) + reader.get_bit()? as usize)?;
                if reader.get_bit()? == 1 {
                    break;
                }
            }
            m_len += 2;
        }
        m_len += usize::from(m_off > 0xd00);
        copy_match(&mut out, m_off, m_len + 1, cap)?;
    }
    Ok(out)
}

fn decompress_nrv2d(src: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut reader: BitReader<'_> = BitReader::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    let mut last_m_off: usize = 1;
    loop {
        while reader.get_bit()? == 1 {
            push_literal(&mut reader, &mut out, cap)?;
        }
        let mut m_off: usize = 1;
        loop {
            m_off = guard_accum((m_off << 1) + reader.get_bit()? as usize)?;
            if reader.get_bit()? == 1 {
                break;
            }
            m_off = guard_accum((m_off << 1) - 1 + reader.get_bit()? as usize)?;
            if reader.get_bit()? == 1 {
                break;
            }
        }
        let mut m_len: usize;
        if m_off == 2 {
            m_off = last_m_off;
            m_len = reader.get_bit()? as usize;
        } else {
            m_off = (m_off - 3) * 256 + reader.next_byte()? as usize;
            if m_off == 0xFFFF_FFFF {
                break;
            }
            m_len = m_off & 1;
            m_off = (m_off >> 1) + 1;
            last_m_off = m_off;
        }
        m_len = (m_len << 1) + reader.get_bit()? as usize;
        if m_len == 0 {
            m_len = 1;
            loop {
                m_len = guard_accum((m_len << 1) + reader.get_bit()? as usize)?;
                if reader.get_bit()? == 1 {
                    break;
                }
            }
            m_len += 2;
        }
        m_len += usize::from(m_off > 0x500);
        copy_match(&mut out, m_off, m_len + 1, cap)?;
    }
    Ok(out)
}

fn decompress_nrv2e(src: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut reader: BitReader<'_> = BitReader::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    let mut last_m_off: usize = 1;
    loop {
        while reader.get_bit()? == 1 {
            push_literal(&mut reader, &mut out, cap)?;
        }
        let mut m_off: usize = 1;
        loop {
            m_off = guard_accum((m_off << 1) + reader.get_bit()? as usize)?;
            if reader.get_bit()? == 1 {
                break;
            }
            m_off = guard_accum((m_off << 1) - 1 + reader.get_bit()? as usize)?;
            if reader.get_bit()? == 1 {
                break;
            }
        }
        let mut m_len: usize;
        if m_off == 2 {
            m_off = last_m_off;
            m_len = reader.get_bit()? as usize;
            m_len = (m_len << 1) + reader.get_bit()? as usize;
        } else {
            m_off = (m_off - 3) * 256 + reader.next_byte()? as usize;
            if m_off == 0xFFFF_FFFF {
                break;
            }
            m_len = m_off & 1;
            m_off = (m_off >> 1) + 1;
            last_m_off = m_off;
            m_len = (m_len << 1) + reader.get_bit()? as usize;
            if m_len == 0 {
                m_len = 1;
                loop {
                    m_len = guard_accum((m_len << 1) + reader.get_bit()? as usize)?;
                    if reader.get_bit()? == 1 {
                        break;
                    }
                }
                m_len += 2;
            }
        }
        m_len += usize::from(m_off > 0x500);
        copy_match(&mut out, m_off, m_len + 2, cap)?;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    struct BitWriter {
        out: Vec<u8>,
        word: u32,
        bits_used: u32,
        word_slot: usize,
        started: bool,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                word: 0,
                bits_used: 0,
                word_slot: 0,
                started: false,
            }
        }

        fn flush_word(&mut self) {
            let bytes: [u8; 4] = self.word.to_le_bytes();
            self.out[self.word_slot..self.word_slot + 4].copy_from_slice(&bytes);
        }

        fn put_bit(&mut self, bit: u32) {
            if !self.started || self.bits_used == 32 {
                if self.started {
                    self.flush_word();
                }
                self.word_slot = self.out.len();
                self.out.extend_from_slice(&[0u8; 4]);
                self.word = 0;
                self.bits_used = 0;
                self.started = true;
            }
            self.word = (self.word << 1) | (bit & 1);
            self.bits_used += 1;
        }

        fn put_byte(&mut self, byte: u8) {
            self.out.push(byte);
        }

        fn finish(mut self) -> Vec<u8> {
            if self.started {
                self.word <<= 32 - self.bits_used;
                self.flush_word();
            }
            self.out
        }
    }

    fn write_gamma(w: &mut BitWriter, value: usize) {
        let mut bits: Vec<u32> = Vec::new();
        let mut v: usize = value;
        while v > 1 {
            bits.push((v & 1) as u32);
            v >>= 1;
        }
        for (index, &bit) in bits.iter().rev().enumerate() {
            w.put_bit(bit);
            let is_last: bool = index + 1 == bits.len();
            w.put_bit(u32::from(is_last));
        }
    }

    fn encode_nrv2b(input: &[u8]) -> Vec<u8> {
        let mut w: BitWriter = BitWriter::new();
        let mut last_m_off: usize = 1;
        let mut pos: usize = 0;
        while pos < input.len() {
            let (best_off, best_len): (usize, usize) = find_match(input, pos, last_m_off);
            if best_len >= 3 {
                w.put_bit(0);
                if best_off == last_m_off {
                    write_gamma(&mut w, 2);
                } else {
                    let encoded: usize = (best_off - 1) + 3 * 256;
                    let high: usize = encoded / 256;
                    let low: usize = encoded % 256;
                    write_gamma(&mut w, high);
                    w.put_byte(low as u8);
                    last_m_off = best_off;
                }
                let extra: usize = usize::from(best_off > 0xd00);
                let copy_len: usize = best_len - 1 - extra;
                write_match_len_nrv2b(&mut w, copy_len);
                pos += best_len;
            } else {
                w.put_bit(1);
                w.put_byte(input[pos]);
                pos += 1;
            }
        }
        w.put_bit(0);
        write_gamma(&mut w, 0x0100_0002);
        w.put_byte(0xFF);
        w.finish()
    }

    fn write_match_len_nrv2b(w: &mut BitWriter, copy_len: usize) {
        if (1..=3).contains(&copy_len) {
            w.put_bit(((copy_len >> 1) & 1) as u32);
            w.put_bit((copy_len & 1) as u32);
        } else {
            w.put_bit(0);
            w.put_bit(0);
            write_gamma(w, copy_len - 2);
        }
    }

    fn find_match(input: &[u8], pos: usize, last_m_off: usize) -> (usize, usize) {
        let max_len: usize = input.len() - pos;
        let mut best_off: usize = 0;
        let mut best_len: usize = 0;
        let lower: usize = pos.saturating_sub(0xFFFF);
        for start in lower..pos {
            let off: usize = pos - start;
            let mut len: usize = 0;
            while len < max_len && input[start + len] == input[pos + len] {
                len += 1;
            }
            if len > best_len || (len == best_len && off == last_m_off) {
                best_len = len;
                best_off = off;
            }
        }
        let _ = last_m_off;
        (best_off, best_len)
    }

    #[test]
    fn nrv2b_round_trip_literals_only() {
        let input: &[u8] = b"hello ucl nrv2b literal-only stream";
        let encoded: Vec<u8> = encode_nrv2b(input);
        let decoded: Vec<u8> =
            decompress(NrvVariant::Nrv2b, &encoded, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn nrv2b_round_trip_with_repeats() {
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"abcabcabcabc");
        input.extend(std::iter::repeat_n(b'Z', 64));
        input.extend_from_slice(b"abcabcabc tail abcabcabc");
        let encoded: Vec<u8> = encode_nrv2b(&input);
        let decoded: Vec<u8> =
            decompress(NrvVariant::Nrv2b, &encoded, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn nrv2b_round_trip_binary() {
        let input: Vec<u8> = (0u8..=255).cycle().take(2000).collect();
        let encoded: Vec<u8> = encode_nrv2b(&input);
        let decoded: Vec<u8> =
            decompress(NrvVariant::Nrv2b, &encoded, input.len()).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn nrv2b_wrong_expected_len_errors() {
        let input: &[u8] = b"size mismatch must fail";
        let encoded: Vec<u8> = encode_nrv2b(input);
        assert!(decompress(NrvVariant::Nrv2b, &encoded, input.len() + 9).is_err());
    }

    #[test]
    fn truncated_stream_errors() {
        assert!(decompress(NrvVariant::Nrv2b, &[0x00], 100).is_err());
    }
}
