use std::io::Read;

use disrobe_core::codec::DecodeError;
use disrobe_core::codec::hex::{HexDecodeOptions, WRAPPED_STREAM};
use flate2::read::ZlibDecoder;

use crate::debug::dbg_kv;
use crate::error::{Error, Result};

const BASE85_ALPHABET: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

const fn build_base85_lookup() -> [u8; 256] {
    let mut table: [u8; 256] = [u8::MAX; 256];
    let mut i: u8 = 0;
    while (i as usize) < BASE85_ALPHABET.len() {
        table[BASE85_ALPHABET[i as usize] as usize] = i;
        i += 1;
    }
    table
}

const BASE85_LOOKUP: [u8; 256] = build_base85_lookup();
pub(crate) const MAX_ARMORED_INPUT_BYTES: usize = 96 * 1024 * 1024;
pub(crate) const MAX_HEX_INPUT_BYTES: usize = 96 * 1024 * 1024;
const MAX_ARMORED_OUTPUT_BYTES: usize = 256 * 1024 * 1024;

const fn check_input_limit(input_len: usize, limit: usize, surface: &'static str) -> Result<()> {
    if input_len > limit {
        return Err(Error::InputLimit {
            surface,
            observed: input_len,
            limit,
        });
    }
    Ok(())
}

fn extend_bounded(out: &mut Vec<u8>, bytes: &[u8], surface: &'static str) -> Result<()> {
    let next_len: usize = out
        .len()
        .checked_add(bytes.len())
        .ok_or(Error::InputLimit {
            surface,
            observed: usize::MAX,
            limit: MAX_ARMORED_OUTPUT_BYTES,
        })?;
    if next_len > MAX_ARMORED_OUTPUT_BYTES {
        return Err(Error::InputLimit {
            surface,
            observed: next_len,
            limit: MAX_ARMORED_OUTPUT_BYTES,
        });
    }
    out.extend_from_slice(bytes);
    Ok(())
}

#[inline]
pub fn base85_decode_rfc1924(input: &[u8]) -> Result<Vec<u8>> {
    check_input_limit(input.len(), MAX_ARMORED_INPUT_BYTES, "base85 input")?;
    let prealloc: usize = base85_output_capacity(input.len()).min(MAX_ARMORED_OUTPUT_BYTES);
    let mut out: Vec<u8> = Vec::with_capacity(prealloc);
    let mut group: [u8; 5] = [0u8; 5];
    let mut count: usize = 0;
    for &b in input {
        if !b.is_ascii_whitespace() {
            let Some(slot): Option<&mut u8> = group.get_mut(count) else {
                return Err(Error::Base85 {
                    field: "chunk".to_owned(),
                    message: "base85 chunk length exceeds five characters".to_owned(),
                });
            };
            *slot = b;
            count += 1;
            if count == 5 {
                let acc: u32 = decode_chunk(&group)?;
                extend_bounded(&mut out, &acc.to_be_bytes(), "base85 decoded output")?;
                count = 0;
            }
        }
    }
    if count == 1 {
        return Err(Error::Base85 {
            field: "chunk".to_owned(),
            message: "dangling single base85 char".to_owned(),
        });
    }
    if count > 0 {
        for slot in group.iter_mut().skip(count) {
            *slot = b'~';
        }
        let acc: u32 = decode_chunk(&group)?;
        let bytes_to_take: usize = count - 1;
        let chunk_bytes: [u8; 4] = acc.to_be_bytes();
        let chunk: &[u8] = chunk_bytes
            .get(..bytes_to_take)
            .ok_or_else(|| Error::Base85 {
                field: "chunk".to_owned(),
                message: "base85 trailing chunk length is invalid".to_owned(),
            })?;
        extend_bounded(&mut out, chunk, "base85 decoded output")?;
    }
    Ok(out)
}

const fn base85_output_capacity(input_len: usize) -> usize {
    let groups: usize = input_len / 5;
    groups.saturating_mul(4).saturating_add(4)
}

#[inline]
fn decode_chunk(chunk: &[u8]) -> Result<u32> {
    let mut acc: u64 = 0;
    for &c in chunk {
        let Some(v): Option<u8> = BASE85_LOOKUP.get(usize::from(c)).copied() else {
            return Err(Error::Base85 {
                field: "chunk".to_owned(),
                message: "base85 character is out of range".to_owned(),
            });
        };
        if v == u8::MAX {
            return Err(Error::Base85 {
                field: "chunk".to_owned(),
                message: format!("invalid base85 char 0x{c:02x}"),
            });
        }
        acc = acc * 85 + u64::from(v);
    }
    if acc > u64::from(u32::MAX) {
        return Err(Error::Base85 {
            field: "chunk".to_owned(),
            message: "base85 chunk overflows u32".to_owned(),
        });
    }
    u32::try_from(acc).map_err(|_| Error::Base85 {
        field: "chunk".to_owned(),
        message: "base85 chunk overflows u32".to_owned(),
    })
}

#[inline]
pub fn ascii85_decode(input: &[u8]) -> Result<Vec<u8>> {
    check_input_limit(input.len(), MAX_ARMORED_INPUT_BYTES, "ascii85 input")?;
    let prealloc: usize = base85_output_capacity(input.len()).min(MAX_ARMORED_OUTPUT_BYTES);
    let mut out: Vec<u8> = Vec::with_capacity(prealloc);
    let mut group: [u32; 5] = [0u32; 5];
    let mut count: usize = 0;
    for &b in input {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'z' && count == 0 {
            extend_bounded(&mut out, &[0u8; 4], "ascii85 decoded output")?;
            continue;
        }
        if !(0x21..=0x75).contains(&b) {
            return Err(Error::Base85 {
                field: "ascii85".to_owned(),
                message: format!("invalid ascii85 char 0x{b:02x}"),
            });
        }
        let Some(slot): Option<&mut u32> = group.get_mut(count) else {
            return Err(Error::Base85 {
                field: "ascii85".to_owned(),
                message: "ascii85 chunk length exceeds five characters".to_owned(),
            });
        };
        *slot = u32::from(b - 0x21);
        count += 1;
        if count == 5 {
            let acc: u32 = pack_ascii85_group(&group, 5)?;
            extend_bounded(&mut out, &acc.to_be_bytes(), "ascii85 decoded output")?;
            count = 0;
        }
    }
    if count == 1 {
        return Err(Error::Base85 {
            field: "ascii85".to_owned(),
            message: "dangling single ascii85 char".to_owned(),
        });
    }
    if count > 0 {
        for slot in group.iter_mut().skip(count) {
            *slot = 84;
        }
        let acc: u32 = pack_ascii85_group(&group, count)?;
        let acc_bytes: [u8; 4] = acc.to_be_bytes();
        let bytes_to_take: usize = count - 1;
        let chunk: &[u8] = acc_bytes
            .get(..bytes_to_take)
            .ok_or_else(|| Error::Base85 {
                field: "ascii85".to_owned(),
                message: "ascii85 trailing chunk length is invalid".to_owned(),
            })?;
        extend_bounded(&mut out, chunk, "ascii85 decoded output")?;
    }
    Ok(out)
}

#[inline]
fn pack_ascii85_group(group: &[u32; 5], used: usize) -> Result<u32> {
    let mut acc: u64 = 0;
    for &digit in group.iter().take(5) {
        acc = acc * 85 + u64::from(digit);
    }
    if used == 5 && acc > u64::from(u32::MAX) {
        return Err(Error::Base85 {
            field: "ascii85".to_owned(),
            message: "ascii85 group overflows u32".to_owned(),
        });
    }
    Ok((acc & u64::from(u32::MAX)) as u32)
}

const MAX_SOURCEDEFENDER_INFLATE: usize = 256 * 1024 * 1024;

#[inline]
fn zlib_inflate(data: &[u8]) -> Result<Vec<u8>> {
    zlib_inflate_bounded(data, MAX_SOURCEDEFENDER_INFLATE)
}

#[inline]
fn zlib_inflate_bounded(data: &[u8], cap: usize) -> Result<Vec<u8>> {
    let decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(data);
    let prealloc: usize = data.len().saturating_mul(2).min(cap);
    let mut out: Vec<u8> = Vec::with_capacity(prealloc);
    let limit: u64 = (cap as u64).saturating_add(1);
    decoder
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|e| Error::Base85 {
            field: "zlib".to_owned(),
            message: format!("inflate failed: {e}"),
        })?;
    if out.len() > cap {
        dbg_kv("zlib-inflate-cap", || {
            format!("output exceeded {cap}-byte cap, refusing")
        });
        return Err(Error::Base85 {
            field: "zlib".to_owned(),
            message: "inflated output exceeds cap".to_owned(),
        });
    }
    dbg_kv("zlib-inflate", || {
        format!("{} compressed -> {} inflated bytes", data.len(), out.len())
    });
    Ok(out)
}

#[inline]
pub fn decode_armored_line(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(Error::Base85 {
            field: "armor".to_owned(),
            message: "armored input is empty".to_owned(),
        });
    }
    if let Ok(raw) = base85_decode_rfc1924(input) {
        dbg_kv("armor-decode", || {
            format!("rfc1924-base85 -> {} bytes", raw.len())
        });
        return Ok(raw);
    }
    let stage: Vec<u8> = ascii85_decode(input)?;
    dbg_kv("armor-decode", || {
        format!("ascii85 -> {} bytes, inflating", stage.len())
    });
    zlib_inflate(&stage)
}

const HEX_DECODE_PROFILE: HexDecodeOptions =
    WRAPPED_STREAM.with_max_input_bytes(MAX_HEX_INPUT_BYTES);

#[inline]
pub fn hex_decode(input: &[u8]) -> Result<Vec<u8>> {
    disrobe_core::codec::hex::decode_with(input, HEX_DECODE_PROFILE).map_err(|err: DecodeError| {
        match err {
            DecodeError::TooLarge { len } => Error::InputLimit {
                surface: "hex input",
                observed: len,
                limit: MAX_HEX_INPUT_BYTES,
            },
            DecodeError::InvalidSymbol { symbol } => Error::Base85 {
                field: "hex".to_owned(),
                message: format!("invalid hex char 0x{symbol:02x}"),
            },
            DecodeError::BadLength { .. } => Error::Base85 {
                field: "hex".to_owned(),
                message: "odd number of hex digits".to_owned(),
            },
            DecodeError::MissingFrame | DecodeError::Overflow | DecodeError::BadPadding => {
                Error::Base85 {
                    field: "hex".to_owned(),
                    message: "hex decode failed".to_owned(),
                }
            }
        }
    })
}

#[inline]
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut s: String = String::with_capacity(hex_output_capacity(bytes.len()));
    for byte in bytes.iter().copied() {
        s.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        s.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    s
}

const fn hex_output_capacity(len: usize) -> usize {
    len.saturating_mul(2usize)
}

#[inline]
#[must_use]
pub fn basename_of(path: &str) -> &str {
    path.rfind(['/', '\\']).map_or(path, |idx| &path[idx + 1..])
}

#[inline]
#[must_use]
pub fn strip_extension(name: &str) -> &str {
    name.rfind('.').map_or(name, |idx| &name[..idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_roundtrip_zero() {
        assert_eq!(hex_encode(&[0u8; 4]), "00000000");
    }

    #[test]
    fn hex_decode_accepts_empty_and_all_whitespace_input() {
        let Ok(empty): Result<Vec<u8>> = hex_decode(b"") else {
            unreachable!("empty input must decode")
        };
        assert_eq!(empty, Vec::<u8>::new());
        let Ok(whitespace): Result<Vec<u8>> = hex_decode(b"  \t\r\n") else {
            unreachable!("all-whitespace input must decode")
        };
        assert_eq!(whitespace, Vec::<u8>::new());
    }

    #[test]
    fn hex_decode_accepts_whitespace_split_across_a_pair() {
        let Ok(wrapped): Result<Vec<u8>> = hex_decode(b"de ad\tbe\r\nef") else {
            unreachable!("wrapped stream must decode")
        };
        assert_eq!(wrapped, [0xde, 0xad, 0xbe, 0xef]);
        let Ok(split): Result<Vec<u8>> = hex_decode(b"a b") else {
            unreachable!("a whitespace-split pair must decode")
        };
        assert_eq!(split, [0xab]);
    }

    #[test]
    fn hex_decode_rejects_a_lone_odd_digit() {
        let Err(err): Result<Vec<u8>> = hex_decode(b"a") else {
            unreachable!("one byte is odd")
        };
        assert!(matches!(&err, Error::Base85 { field, message }
            if field == "hex" && message == "odd number of hex digits"));
    }

    #[test]
    fn hex_decode_rejects_an_odd_tail_above_two_digits() {
        let Err(err): Result<Vec<u8>> = hex_decode(b"abc") else {
            unreachable!("odd length must be refused")
        };
        assert!(matches!(&err, Error::Base85 { field, message }
            if field == "hex" && message == "odd number of hex digits"));
    }

    #[test]
    fn hex_decode_rejects_an_invalid_symbol_at_even_length() {
        let Err(err): Result<Vec<u8>> = hex_decode(b"gg") else {
            unreachable!("invalid symbol must be refused")
        };
        assert!(matches!(&err, Error::Base85 { field, message }
            if field == "hex" && message == "invalid hex char 0x67"));
    }

    #[test]
    fn hex_decode_reports_the_odd_length_when_the_tail_also_holds_an_invalid_symbol() {
        let Err(err): Result<Vec<u8>> = hex_decode(b"abz") else {
            unreachable!("odd and invalid input must be refused")
        };
        assert!(matches!(&err, Error::Base85 { field, message }
            if field == "hex" && message == "odd number of hex digits"));
    }

    #[test]
    fn hex_decode_accepts_a_normal_mixed_case_run() {
        let Ok(decoded): Result<Vec<u8>> = hex_decode(b"DEADbeef01") else {
            unreachable!("mixed-case input must decode")
        };
        assert_eq!(decoded, [0xde, 0xad, 0xbe, 0xef, 0x01]);
    }

    #[test]
    fn hex_decode_wires_the_ninety_six_mebibyte_cap_into_the_shared_decoder() {
        assert_eq!(
            HEX_DECODE_PROFILE.max_input_bytes,
            Some(MAX_HEX_INPUT_BYTES)
        );
        assert_eq!(MAX_HEX_INPUT_BYTES, 96 * 1024 * 1024);
    }

    #[test]
    fn hex_encode_full_byte() {
        assert_eq!(hex_encode(&[0x0a, 0xff]), "0aff");
    }

    #[test]
    fn hex_output_capacity_saturates() {
        assert_eq!(hex_output_capacity(usize::MAX), usize::MAX);
    }

    #[test]
    fn basename_strips_path() {
        assert_eq!(basename_of("a/b/c.pye"), "c.pye");
        assert_eq!(basename_of("c:\\dir\\foo.pye"), "foo.pye");
        assert_eq!(basename_of("plain"), "plain");
    }

    #[test]
    fn strip_extension_works() {
        assert_eq!(strip_extension("foo.pye"), "foo");
        assert_eq!(strip_extension("foo"), "foo");
        assert_eq!(strip_extension("a.b.c"), "a.b");
    }

    #[test]
    fn base85_rejects_garbage() {
        let r: Result<Vec<u8>> = base85_decode_rfc1924(b"\x01\x02\x03\x04\x05");
        assert!(r.is_err());
    }

    #[test]
    fn base85_rejects_lone_trailing_symbol() {
        let r: Result<Vec<u8>> = base85_decode_rfc1924(b"X");
        assert!(r.is_err());
    }

    #[test]
    fn base85_streams_past_whitespace() {
        let Ok(out): Result<Vec<u8>> = base85_decode_rfc1924(b"00 000\r\n") else {
            unreachable!("decode failed")
        };
        assert_eq!(out, vec![0u8; 4]);
    }

    #[test]
    fn ascii85_decodes_known_iv_line() {
        let Ok(iv): Result<Vec<u8>> = decode_armored_line(b"GhOt7h7Jm.?sE?I;!%a(cCM6@0X(^n") else {
            unreachable!("decode iv failed")
        };
        assert_eq!(hex_encode(&iv), "310dbdb90f30b66ba95503502209b91d");
    }

    #[test]
    fn ascii85_z_shortcut_expands_to_four_zero_bytes() {
        let Ok(out): Result<Vec<u8>> = ascii85_decode(b"z") else {
            unreachable!("decode z failed")
        };
        assert_eq!(out, vec![0u8; 4]);
    }

    fn zlib_compress(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        let Ok(()): std::io::Result<()> = encoder.write_all(bytes) else {
            unreachable!("zlib write_all failed")
        };
        let Ok(compressed): std::io::Result<Vec<u8>> = encoder.finish() else {
            unreachable!("zlib finish failed")
        };
        compressed
    }

    #[test]
    fn zlib_inflate_accepts_stream_within_cap() {
        let payload: Vec<u8> = vec![0u8; 4096];
        let compressed: Vec<u8> = zlib_compress(&payload);
        let Ok(out): Result<Vec<u8>> = zlib_inflate_bounded(&compressed, 1 << 20) else {
            unreachable!("under-cap inflate must succeed")
        };
        assert_eq!(out, payload);
    }

    #[test]
    fn zlib_inflate_rejects_decompression_bomb_over_cap() {
        let inflated_len: usize = 8 * 1024 * 1024;
        let compressed: Vec<u8> = zlib_compress(&vec![0u8; inflated_len]);
        assert!(
            compressed.len() < 128 * 1024,
            "a run of zeros must compress far below its inflated size"
        );
        let cap: usize = 64 * 1024;
        let outcome: Result<Vec<u8>> = zlib_inflate_bounded(&compressed, cap);
        let Err(err): Result<Vec<u8>> = outcome else {
            unreachable!("a bomb inflating past the cap must be refused")
        };
        assert!(
            matches!(&err, Error::Base85 { field, message }
                if field == "zlib" && message.contains("exceeds cap")),
            "expected the decompressed-size cap to abort inflation, got {err:?}"
        );
    }
}
