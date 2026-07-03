use std::io::Read as _;

use crate::containers::ucl::{self, NrvVariant};
use crate::error::{Error, Result};

const SEGMENT_MAX_OUT: usize = 0x10000;

const STARTUP_SIGNATURE: u32 = 0x00ff_7eeb;
const FLAGS1_BIGENDIAN: u8 = 0x02;
const FLAGS1_COMPRESS_MASK: u8 = 0x1c;
const FLAGS1_COMPRESS_NONE: u8 = 0x00;
const FLAGS1_COMPRESS_ZLIB: u8 = 0x04;
const FLAGS1_COMPRESS_LZO: u8 = 0x08;
const FLAGS1_COMPRESS_UCL: u8 = 0x0c;
const GZIP_MAGIC: [u8; 3] = [0x1f, 0x8b, 0x08];
const IMAGE_SIGNATURE: &[u8; 7] = b"imagefs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QnxCompress {
    None,
    Zlib,
    Lzo,
    Ucl,
}

#[derive(Debug, Clone, Copy)]
pub struct QnxStartup {
    pub big_endian: bool,
    pub compress: QnxCompress,
    pub startup_size: u32,
    pub stored_size: u32,
    pub imagefs_size: u32,
}

#[must_use]
pub fn parse_startup_header(bytes: &[u8]) -> Option<QnxStartup> {
    let head: &[u8] = bytes.get(..0x30)?;
    let le_sig: u32 = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    let be_sig: u32 = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let big_endian: bool = if le_sig == STARTUP_SIGNATURE {
        false
    } else if be_sig == STARTUP_SIGNATURE {
        true
    } else {
        return None;
    };
    let flags1: u8 = head[6];
    if big_endian != (flags1 & FLAGS1_BIGENDIAN != 0) {
        return None;
    }
    let read_u32 = |at: usize| -> u32 {
        let raw: [u8; 4] = [head[at], head[at + 1], head[at + 2], head[at + 3]];
        if big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        }
    };
    let compress: QnxCompress = match flags1 & FLAGS1_COMPRESS_MASK {
        FLAGS1_COMPRESS_NONE => QnxCompress::None,
        FLAGS1_COMPRESS_ZLIB => QnxCompress::Zlib,
        FLAGS1_COMPRESS_LZO => QnxCompress::Lzo,
        FLAGS1_COMPRESS_UCL => QnxCompress::Ucl,
        _ => return None,
    };
    Some(QnxStartup {
        big_endian,
        compress,
        startup_size: read_u32(0x20),
        stored_size: read_u32(0x24),
        imagefs_size: read_u32(0x2c),
    })
}

pub fn inflate_startup_zlib(
    bytes: &[u8],
    header: &QnxStartup,
    max_total: usize,
) -> Result<Vec<u8>> {
    let scan_floor: usize = header.startup_size as usize;
    let scan_cap: usize = (header.stored_size as usize).min(bytes.len());
    let gzip_at: usize = locate_gzip(bytes, scan_floor, scan_cap)
        .ok_or_else(|| Error::Qnx("qnx: zlib startup gzip stream not found".to_owned()))?;
    let cap: usize = if header.imagefs_size == 0 {
        max_total
    } else {
        (header.imagefs_size as usize).min(max_total)
    };
    let mut decoder: flate2::read::GzDecoder<&[u8]> =
        flate2::read::GzDecoder::new(&bytes[gzip_at..]);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .by_ref()
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| Error::Qnx(format!("qnx: zlib inflate: {e}")))?;
    if out.len() > cap {
        return Err(Error::Qnx("qnx: zlib image exceeds cap".to_owned()));
    }
    if !out.starts_with(IMAGE_SIGNATURE) && !out.starts_with(b"sfegami") {
        return Err(Error::Qnx(
            "qnx: inflated startup image lacks imagefs signature".to_owned(),
        ));
    }
    Ok(out)
}

fn locate_gzip(bytes: &[u8], floor: usize, cap: usize) -> Option<usize> {
    let start: usize = floor.min(bytes.len());
    let end: usize = cap.min(bytes.len());
    bytes
        .get(start..end)?
        .windows(GZIP_MAGIC.len())
        .position(|w: &[u8]| w == GZIP_MAGIC)
        .map(|rel: usize| start + rel)
}

pub fn decompress_ucl_segments(
    variant: NrvVariant,
    data: &[u8],
    max_total: usize,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut cursor: usize = 0;
    loop {
        let header: &[u8] = data
            .get(cursor..cursor + 2)
            .ok_or_else(|| Error::Qnx("qnx: truncated segment length".to_owned()))?;
        let seg_len: usize = usize::from(u16::from_be_bytes([header[0], header[1]]));
        cursor += 2;
        if seg_len == 0 {
            break;
        }
        let seg: &[u8] = data
            .get(cursor..cursor + seg_len)
            .ok_or_else(|| Error::Qnx("qnx: segment runs past end".to_owned()))?;
        cursor += seg_len;
        let want: usize = SEGMENT_MAX_OUT.min(max_total.saturating_sub(out.len()).max(1));
        let chunk: Vec<u8> = ucl::decompress_to_eos(variant, seg, want)
            .map_err(|e: Error| Error::Qnx(format!("qnx: ucl segment decode: {e}")))?;
        out.extend_from_slice(&chunk);
        if out.len() > max_total {
            return Err(Error::Qnx("qnx: decompressed image exceeds cap".to_owned()));
        }
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
            w.put_bit(u32::from(index + 1 == bits.len()));
        }
    }

    fn encode_nrv2b_literals(input: &[u8]) -> Vec<u8> {
        let mut w: BitWriter = BitWriter::new();
        for &byte in input {
            w.put_bit(1);
            w.put_byte(byte);
        }
        w.put_bit(0);
        write_gamma(&mut w, 0x0100_0002);
        w.put_byte(0xFF);
        w.finish()
    }

    fn frame_segments(segments: &[Vec<u8>]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for seg in segments {
            out.extend_from_slice(&(seg.len() as u16).to_be_bytes());
            out.extend_from_slice(seg);
        }
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    #[test]
    fn reconstructs_two_nrv2b_segments() {
        let part_a: &[u8] = b"qnx ifs first segment payload bytes";
        let part_b: &[u8] = b"and the second compressed segment here";
        let seg_a: Vec<u8> = encode_nrv2b_literals(part_a);
        let seg_b: Vec<u8> = encode_nrv2b_literals(part_b);
        let stream: Vec<u8> = frame_segments(&[seg_a, seg_b]);
        let decoded: Vec<u8> =
            decompress_ucl_segments(NrvVariant::Nrv2b, &stream, 1 << 20).expect("decode");
        let mut expected: Vec<u8> = part_a.to_vec();
        expected.extend_from_slice(part_b);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn truncated_segment_errors() {
        let stream: Vec<u8> = vec![0x00, 0x05, 0x01, 0x02];
        assert!(decompress_ucl_segments(NrvVariant::Nrv2b, &stream, 1 << 20).is_err());
    }

    #[test]
    fn extract_to_decodes_ifs_startup_segment_stream() {
        let payload: Vec<u8> = {
            let mut v: Vec<u8> = b"qnx ifs image filesystem payload ".to_vec();
            v.extend(std::iter::repeat_n(b'.', 600));
            v
        };
        let seg: Vec<u8> = encode_nrv2b_literals(&payload);
        let stream: Vec<u8> = frame_segments(&[seg]);
        let mut image: Vec<u8> = vec![0xeb, 0x7e, 0xff, 0x00];
        image.extend(std::iter::repeat_n(0u8, 60));
        image.extend_from_slice(&stream);

        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-qnx-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Qnx, &image, &dir)
                .expect("qnx extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Qnx);
        let written: Vec<u8> = std::fs::read(dir.join("qnx-ifs.img")).expect("ifs image");
        assert_eq!(written, payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn gzip_compress(input: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(input).expect("gz write");
        enc.finish().expect("gz finish")
    }

    fn build_zlib_startup(payload: &[u8]) -> Vec<u8> {
        let startup_size: u32 = 0x40;
        let mut header: Vec<u8> = vec![0u8; startup_size as usize];
        header[0..4].copy_from_slice(&STARTUP_SIGNATURE.to_le_bytes());
        header[4..6].copy_from_slice(&1u16.to_le_bytes());
        header[6] = FLAGS1_COMPRESS_ZLIB;
        header[8..10].copy_from_slice(&0x0100u16.to_le_bytes());
        header[0x20..0x24].copy_from_slice(&startup_size.to_le_bytes());
        let gz: Vec<u8> = gzip_compress(payload);
        let stored_size: u32 = startup_size + gz.len() as u32;
        header[0x24..0x28].copy_from_slice(&stored_size.to_le_bytes());
        header[0x2c..0x30].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let mut out: Vec<u8> = header;
        out.extend_from_slice(&gz);
        out
    }

    #[test]
    fn parse_startup_reads_zlib_flag() {
        let payload: Vec<u8> = {
            let mut v: Vec<u8> = IMAGE_SIGNATURE.to_vec();
            v.extend_from_slice(b" qnx imagefs body content here");
            v
        };
        let image: Vec<u8> = build_zlib_startup(&payload);
        let header: QnxStartup = parse_startup_header(&image).expect("startup header");
        assert_eq!(header.compress, QnxCompress::Zlib);
        assert!(!header.big_endian);
        assert_eq!(header.imagefs_size, payload.len() as u32);
    }

    #[test]
    fn extract_to_inflates_zlib_startup_image() {
        let payload: Vec<u8> = {
            let mut v: Vec<u8> = IMAGE_SIGNATURE.to_vec();
            v.push(0x01);
            v.extend(b"qnx zlib imagefs payload ".repeat(40));
            v
        };
        let image: Vec<u8> = build_zlib_startup(&payload);
        let header: QnxStartup = parse_startup_header(&image).expect("hdr");
        let inflated: Vec<u8> = inflate_startup_zlib(&image, &header, 1 << 24).expect("inflate");
        assert_eq!(inflated, payload);

        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-qnx-zlib-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let result: crate::extract::ExtractionResult =
            crate::extract::extract_to(crate::container::ContainerKind::Qnx, &image, &dir)
                .expect("qnx zlib extract");
        assert_eq!(result.kind, crate::container::ContainerKind::Qnx);
        let written: Vec<u8> = std::fs::read(dir.join("qnx-ifs.img")).expect("ifs image");
        assert_eq!(written, payload);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
