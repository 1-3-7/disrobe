mod bits;
mod entropy;
mod huffman;
mod kraken;
mod leviathan;
mod lz;
mod mermaid;
mod tans;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const BLOCK_HEADER_LEN: usize = 2;
pub const BLOCK_SPAN: usize = 0x4_0000;
pub const SUB_BLOCK_SPAN: usize = 0x2_0000;
pub const MAX_OUTPUT_BYTES: usize = 1 << 30;
pub const MAX_ENTROPY_DEPTH: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OodleDecoderKind {
    Lzna,
    Kraken,
    Mermaid,
    BitKnit,
    Leviathan,
}

impl OodleDecoderKind {
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            5 => Some(Self::Lzna),
            6 => Some(Self::Kraken),
            10 => Some(Self::Mermaid),
            11 => Some(Self::BitKnit),
            12 => Some(Self::Leviathan),
            _ => None,
        }
    }

    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Lzna => 5,
            Self::Kraken => 6,
            Self::Mermaid => 10,
            Self::BitKnit => 11,
            Self::Leviathan => 12,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Lzna => "lzna",
            Self::Kraken => "kraken",
            Self::Mermaid => "mermaid",
            Self::BitKnit => "bitknit",
            Self::Leviathan => "leviathan",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OodleBlockHeader {
    pub decoder: OodleDecoderKind,
    pub restart_decoder: bool,
    pub uncompressed: bool,
    pub checksums: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OodleError {
    #[error("Oodle block header {first:#04x} {second:#04x} is not an Oodle LZ block header")]
    BadBlockHeader { first: u8, second: u8 },
    #[error(
        "Oodle decoder type {id} is not one of the Oodle 2 decoders (LZNA, Kraken, Mermaid/Selkie, BitKnit, Leviathan); the legacy codecs LZH, LZHLW, LZNIB, LZB16, LZBLW, LZA and LZQ1 have no open specification"
    )]
    UnknownDecoder { id: u8 },
    #[error(
        "Oodle {name} streams are refused: no open encoder and no local stream exists to grade a decoder against"
    )]
    DecoderUnsupported { name: &'static str },
    #[error(
        "Oodle per-quantum checksums are refused: no open source documents their algorithm, so the stream cannot be verified"
    )]
    ChecksumsUnsupported,
    #[error("Oodle Kraken excess-bytes sub-blocks are refused: no open decoder documents them")]
    ExcessBytesUnsupported,
    #[error("Oodle quantum header {value:#08x} uses an escape no open decoder defines")]
    BadQuantumHeader { value: u32 },
    #[error("declared Oodle output of {declared} bytes exceeds the {cap}-byte cap")]
    OutputTooLarge { declared: usize, cap: usize },
    #[error("malformed Oodle stream: {0}")]
    Malformed(&'static str),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OodleCensus {
    pub paths: BTreeMap<String, u64>,
}

impl OodleCensus {
    fn bump(&mut self, path: &'static str) {
        if let Some(count) = self.paths.get_mut(path) {
            *count += 1;
        } else {
            self.paths.insert(path.to_owned(), 1);
        }
    }

    pub fn merge(&mut self, other: &Self) {
        for (path, count) in &other.paths {
            *self.paths.entry(path.clone()).or_insert(0) += count;
        }
    }
}

pub(super) struct Ctx<'c> {
    census: &'c mut OodleCensus,
    depth: u32,
}

impl Ctx<'_> {
    fn bump(&mut self, path: &'static str) {
        self.census.bump(path);
    }

    const fn enter(&mut self) -> Result<(), OodleError> {
        if self.depth >= MAX_ENTROPY_DEPTH {
            return Err(OodleError::Malformed(
                "entropy arrays nest deeper than the decoder allows",
            ));
        }
        self.depth += 1;
        Ok(())
    }

    const fn leave(&mut self) {
        self.depth -= 1;
    }
}

pub fn parse_block_header(bytes: &[u8]) -> Result<OodleBlockHeader, OodleError> {
    let (first, second): (u8, u8) = match bytes {
        [first, second, ..] => (*first, *second),
        _ => return Err(OodleError::Malformed("block header truncated")),
    };
    if first & 0x0F != 0x0C || first & 0x30 != 0 {
        return Err(OodleError::BadBlockHeader { first, second });
    }
    let id: u8 = second & 0x7F;
    let decoder: OodleDecoderKind =
        OodleDecoderKind::from_code(id).ok_or(OodleError::UnknownDecoder { id })?;
    Ok(OodleBlockHeader {
        decoder,
        restart_decoder: first & 0x80 != 0,
        uncompressed: first & 0x40 != 0,
        checksums: second & 0x80 != 0,
    })
}

fn be24(bytes: &[u8], at: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(at..at + 3)?;
    Some((u32::from(slice[0]) << 16) | (u32::from(slice[1]) << 8) | u32::from(slice[2]))
}

pub fn decode(src: &[u8], dst_len: usize, census: &mut OodleCensus) -> Result<Vec<u8>, OodleError> {
    if dst_len > MAX_OUTPUT_BYTES {
        return Err(OodleError::OutputTooLarge {
            declared: dst_len,
            cap: MAX_OUTPUT_BYTES,
        });
    }
    let mut out: Vec<u8> = Vec::new();
    let mut ctx: Ctx<'_> = Ctx { census, depth: 0 };
    let mut at: usize = 0;
    let mut pos: usize = 0;
    while pos < dst_len {
        let header: OodleBlockHeader = parse_block_header(src.get(at..).unwrap_or(&[]))?;
        at += BLOCK_HEADER_LEN;
        match header.decoder {
            OodleDecoderKind::Lzna | OodleDecoderKind::BitKnit => {
                return Err(OodleError::DecoderUnsupported {
                    name: header.decoder.label(),
                });
            }
            OodleDecoderKind::Kraken | OodleDecoderKind::Mermaid | OodleDecoderKind::Leviathan => {}
        }
        let span: usize = (dst_len - pos).min(BLOCK_SPAN);
        out.resize(pos + span, 0);
        if header.uncompressed {
            let raw: &[u8] = src
                .get(at..at + span)
                .ok_or(OodleError::Malformed("uncompressed block truncated"))?;
            out[pos..pos + span].copy_from_slice(raw);
            ctx.bump("block:uncompressed");
            at += span;
            pos += span;
            continue;
        }
        if header.checksums {
            return Err(OodleError::ChecksumsUnsupported);
        }
        let value: u32 = be24(src, at).ok_or(OodleError::Malformed("quantum header truncated"))?;
        let size: u32 = value & 0x3_FFFF;
        if size == 0x3_FFFF {
            if value >> 18 != 1 {
                return Err(OodleError::BadQuantumHeader { value });
            }
            let fill: u8 = *src
                .get(at + 3)
                .ok_or(OodleError::Malformed("memset quantum truncated"))?;
            out[pos..pos + span].fill(fill);
            ctx.bump("quantum:memset");
            at += 4;
            pos += span;
            continue;
        }
        at += 3;
        let compressed: usize = size as usize + 1;
        if compressed > span {
            return Err(OodleError::Malformed(
                "quantum compressed size exceeds its output span",
            ));
        }
        let body: &[u8] = src
            .get(at..at + compressed)
            .ok_or(OodleError::Malformed("quantum body truncated"))?;
        if compressed == span {
            out[pos..pos + span].copy_from_slice(body);
            ctx.bump("quantum:stored");
        } else {
            decode_quantum(&mut ctx, header.decoder, body, &mut out, pos, span)?;
        }
        at += compressed;
        pos += span;
    }
    if at != src.len() {
        return Err(OodleError::Malformed(
            "input continues after the last Oodle block",
        ));
    }
    Ok(out)
}

fn decode_quantum(
    ctx: &mut Ctx<'_>,
    decoder: OodleDecoderKind,
    src: &[u8],
    out: &mut [u8],
    start: usize,
    span: usize,
) -> Result<(), OodleError> {
    let mut at: usize = 0;
    let mut pos: usize = start;
    let end: usize = start + span;
    while pos < end {
        let count: usize = (end - pos).min(SUB_BLOCK_SPAN);
        if src.len() - at < 4 {
            return Err(OodleError::Malformed("sub-block header truncated"));
        }
        let header: u32 =
            be24(src, at).ok_or(OodleError::Malformed("sub-block header truncated"))?;
        if header & 0x80_0000 == 0 {
            let mut decoded: Vec<u8> = Vec::with_capacity(count);
            let used: usize = entropy::decode_bytes(ctx, &src[at..], count, &mut decoded)?;
            if decoded.len() != count {
                return Err(OodleError::Malformed(
                    "entropy-only sub-block decodes to the wrong length",
                ));
            }
            out[pos..pos + count].copy_from_slice(&decoded);
            ctx.bump("sub-block:entropy-only");
            at += used;
        } else {
            at += 3;
            let used: usize = (header & 0x7_FFFF) as usize;
            let mode: u32 = (header >> 19) & 0xF;
            let body: &[u8] = src
                .get(at..at + used)
                .ok_or(OodleError::Malformed("sub-block body truncated"))?;
            if used < count {
                ctx.bump("sub-block:lz");
                let window: &mut [u8] = &mut out[..pos + count];
                match decoder {
                    OodleDecoderKind::Kraken => kraken::decode(ctx, body, mode, window, pos)?,
                    OodleDecoderKind::Mermaid => mermaid::decode(ctx, body, mode, window, pos)?,
                    OodleDecoderKind::Leviathan => leviathan::decode(ctx, body, mode, window, pos)?,
                    OodleDecoderKind::Lzna | OodleDecoderKind::BitKnit => {
                        return Err(OodleError::DecoderUnsupported {
                            name: decoder.label(),
                        });
                    }
                }
            } else if used == count && mode == 0 {
                out[pos..pos + count].copy_from_slice(body);
                ctx.bump("sub-block:stored");
            } else {
                return Err(OodleError::Malformed(
                    "sub-block declares more input than output or a mode on stored bytes",
                ));
            }
            at += used;
        }
        pos += count;
    }
    if at != src.len() {
        return Err(OodleError::Malformed(
            "quantum input continues after its last sub-block",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn block_headers_name_their_decoder() {
        let header: OodleBlockHeader = parse_block_header(&[0x8C, 0x0C]).unwrap();
        assert_eq!(header.decoder, OodleDecoderKind::Leviathan);
        assert!(header.restart_decoder);
        assert!(!header.uncompressed);
        assert!(!header.checksums);
        let kraken: OodleBlockHeader = parse_block_header(&[0x4C, 0x86]).unwrap();
        assert_eq!(kraken.decoder, OodleDecoderKind::Kraken);
        assert!(kraken.uncompressed);
        assert!(kraken.checksums);
        assert_eq!(
            parse_block_header(&[0x8D, 0x0C]),
            Err(OodleError::BadBlockHeader {
                first: 0x8D,
                second: 0x0C
            })
        );
        assert_eq!(
            parse_block_header(&[0x9C, 0x0C]),
            Err(OodleError::BadBlockHeader {
                first: 0x9C,
                second: 0x0C
            })
        );
        assert_eq!(
            parse_block_header(&[0x8C, 0x07]),
            Err(OodleError::UnknownDecoder { id: 7 })
        );
        assert!(parse_block_header(&[0x8C]).is_err());
    }

    #[test]
    fn refused_decoders_and_variants_are_named() {
        let mut census: OodleCensus = OodleCensus::default();
        assert_eq!(
            decode(&[0x8C, 0x05, 0, 0, 0], 16, &mut census),
            Err(OodleError::DecoderUnsupported { name: "lzna" })
        );
        assert_eq!(
            decode(&[0x8C, 0x0B, 0, 0, 0], 16, &mut census),
            Err(OodleError::DecoderUnsupported { name: "bitknit" })
        );
        assert_eq!(
            decode(&[0x8C, 0x8C, 0, 0, 0], 16, &mut census),
            Err(OodleError::ChecksumsUnsupported)
        );
        assert_eq!(
            decode(&[0x8C, 0x0C, 0xFF, 0xFF, 0xFF], 16, &mut census),
            Err(OodleError::BadQuantumHeader { value: 0xFF_FFFF })
        );
        assert_eq!(
            decode(&[0x8C, 0x0C], MAX_OUTPUT_BYTES + 1, &mut census),
            Err(OodleError::OutputTooLarge {
                declared: MAX_OUTPUT_BYTES + 1,
                cap: MAX_OUTPUT_BYTES
            })
        );
    }

    #[test]
    fn memset_stored_and_uncompressed_blocks_decode_exactly() {
        let mut census: OodleCensus = OodleCensus::default();
        assert_eq!(
            decode(&[0x8C, 0x0C, 0x07, 0xFF, 0xFF, 0x5A], 300, &mut census).unwrap(),
            vec![0x5A; 300]
        );
        let mut stored: Vec<u8> = vec![0x8C, 0x06, 0x00, 0x00, 0x03];
        stored.extend_from_slice(b"abcd");
        assert_eq!(decode(&stored, 4, &mut census).unwrap(), b"abcd");
        let mut raw: Vec<u8> = vec![0xCC, 0x0A];
        raw.extend_from_slice(b"xyz");
        assert_eq!(decode(&raw, 3, &mut census).unwrap(), b"xyz");
        raw.push(0);
        assert!(decode(&raw, 3, &mut census).is_err());
        assert_eq!(census.paths.get("quantum:memset"), Some(&1));
        assert_eq!(census.paths.get("quantum:stored"), Some(&1));
    }
}
