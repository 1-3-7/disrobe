use std::io::Read as _;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const KOLY_MAGIC: &[u8; 4] = b"koly";
const KOLY_LEN: usize = 512;
const MISH_MAGIC: u32 = 0x6D69_7368;
const CHUNK_HEADER_OFFSET: usize = 204;
const CHUNK_LEN: usize = 40;
const SECTOR: u64 = 512;
const MAX_IMAGE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_CHUNK_PREALLOC: usize = 4 * 1024 * 1024;
const MAX_CHUNKS: usize = 5_000_000;

const TYPE_ZERO: u32 = 0x0000_0000;
const TYPE_RAW: u32 = 0x0000_0001;
const TYPE_IGNORE: u32 = 0x0000_0002;
const TYPE_ADC: u32 = 0x8000_0004;
const TYPE_ZLIB: u32 = 0x8000_0005;
const TYPE_BZIP2: u32 = 0x8000_0006;
const TYPE_LZFSE: u32 = 0x8000_0007;
const TYPE_LZMA: u32 = 0x8000_0008;
const TYPE_COMMENT: u32 = 0x7FFF_FFFE;
const TYPE_TERMINATOR: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KolyTrailer {
    pub data_fork_offset: u64,
    pub data_fork_length: u64,
    pub xml_offset: u64,
    pub xml_length: u64,
    pub sector_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmgSummary {
    pub koly: KolyTrailer,
    pub blkx_blocks: usize,
    pub chunks: usize,
    pub image_len: u64,
    pub unsupported_chunk_types: Vec<u32>,
}

#[inline]
fn read_u32_be(bytes: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_be_at(bytes, at).ok()
}

#[inline]
fn read_u64_be(bytes: &[u8], at: usize) -> Option<u64> {
    disrobe_bytes::read_u64_be_at(bytes, at).ok()
}

pub fn detect_dmg(bytes: &[u8]) -> bool {
    bytes.len() >= KOLY_LEN
        && bytes
            .get(bytes.len() - KOLY_LEN..bytes.len() - KOLY_LEN + 4)
            .is_some_and(|m: &[u8]| m == KOLY_MAGIC)
}

pub fn parse_koly(bytes: &[u8]) -> Result<KolyTrailer> {
    if bytes.len() < KOLY_LEN {
        return Err(Error::Decompression(
            "dmg shorter than koly trailer".to_owned(),
        ));
    }
    let base: usize = bytes.len() - KOLY_LEN;
    if bytes.get(base..base + 4) != Some(KOLY_MAGIC.as_slice()) {
        return Err(Error::Decompression(
            "dmg koly trailer magic not found at end of file".to_owned(),
        ));
    }
    Ok(KolyTrailer {
        data_fork_offset: read_u64_be(bytes, base + 24)
            .ok_or_else(|| Error::Decompression("koly data fork offset truncated".to_owned()))?,
        data_fork_length: read_u64_be(bytes, base + 32)
            .ok_or_else(|| Error::Decompression("koly data fork length truncated".to_owned()))?,
        xml_offset: read_u64_be(bytes, base + 216)
            .ok_or_else(|| Error::Decompression("koly xml offset truncated".to_owned()))?,
        xml_length: read_u64_be(bytes, base + 224)
            .ok_or_else(|| Error::Decompression("koly xml length truncated".to_owned()))?,
        sector_count: read_u64_be(bytes, base + 492)
            .ok_or_else(|| Error::Decompression("koly sector count truncated".to_owned()))?,
    })
}

#[derive(Debug, Clone)]
struct BlockChunk {
    entry_type: u32,
    sector_number: u64,
    sector_count: u64,
    compressed_offset: u64,
    compressed_length: u64,
}

fn blkx_data_values(xml: &[u8]) -> Result<Vec<Vec<u8>>> {
    let value: plist::Value = plist::from_bytes(xml)
        .map_err(|e: plist::Error| Error::Decompression(format!("dmg plist parse failed: {e}")))?;
    let dict: &plist::Dictionary = value
        .as_dictionary()
        .ok_or_else(|| Error::Decompression("dmg plist root is not a dictionary".to_owned()))?;
    let resource_fork: &plist::Dictionary = dict
        .get("resource-fork")
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| Error::Decompression("dmg plist missing resource-fork".to_owned()))?;
    let blkx: &Vec<plist::Value> = resource_fork
        .get("blkx")
        .and_then(plist::Value::as_array)
        .ok_or_else(|| Error::Decompression("dmg plist missing blkx array".to_owned()))?;
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(blkx.len());
    for entry in blkx {
        if let Some(data) = entry
            .as_dictionary()
            .and_then(|d: &plist::Dictionary| d.get("Data"))
        {
            if let Some(raw) = data.as_data() {
                out.push(raw.to_vec());
            } else if let Some(text) = data.as_string() {
                let cleaned: String = text.split_whitespace().collect();
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(cleaned) {
                    out.push(decoded);
                }
            }
        }
    }
    Ok(out)
}

fn parse_mish_chunks(mish: &[u8]) -> Option<(u64, Vec<BlockChunk>)> {
    if read_u32_be(mish, 0)? != MISH_MAGIC {
        return None;
    }
    let block_sector_number: u64 = read_u64_be(mish, 8)?;
    let chunk_count: usize = read_u32_be(mish, 200)? as usize;
    if chunk_count > MAX_CHUNKS {
        return None;
    }
    let mut chunks: Vec<BlockChunk> = Vec::with_capacity(chunk_count.min(4096));
    for i in 0..chunk_count {
        let base: usize = CHUNK_HEADER_OFFSET + i * CHUNK_LEN;
        let entry_type: u32 = read_u32_be(mish, base)?;
        let sector_number: u64 = read_u64_be(mish, base + 8)?;
        let sector_count: u64 = read_u64_be(mish, base + 16)?;
        let compressed_offset: u64 = read_u64_be(mish, base + 24)?;
        let compressed_length: u64 = read_u64_be(mish, base + 32)?;
        if entry_type == TYPE_TERMINATOR {
            break;
        }
        chunks.push(BlockChunk {
            entry_type,
            sector_number,
            sector_count,
            compressed_offset,
            compressed_length,
        });
    }
    Some((block_sector_number, chunks))
}

pub fn reconstruct_image(bytes: &[u8]) -> Result<(Vec<u8>, DmgSummary)> {
    let koly: KolyTrailer = parse_koly(bytes)?;
    let xml_start: usize =
        usize::try_from(koly.xml_offset).map_err(|_e: std::num::TryFromIntError| {
            Error::Decompression("dmg xml offset overflow".to_owned())
        })?;
    let xml_end: usize = xml_start
        .checked_add(koly.xml_length as usize)
        .ok_or_else(|| Error::Decompression("dmg xml range overflow".to_owned()))?;
    let xml: &[u8] = bytes
        .get(xml_start..xml_end.min(bytes.len()))
        .ok_or_else(|| Error::Decompression("dmg xml plist out of bounds".to_owned()))?;

    let blocks: Vec<Vec<u8>> = blkx_data_values(xml)?;
    let image_len: u64 = (koly.sector_count.saturating_mul(SECTOR)).min(MAX_IMAGE_BYTES);
    if image_len == 0 {
        return Err(Error::Decompression(
            "dmg declares a zero-length image".to_owned(),
        ));
    }
    let mut image: Vec<u8> = vec![0u8; image_len as usize];

    let mut total_chunks: usize = 0;
    let mut unsupported: Vec<u32> = Vec::new();
    for mish in &blocks {
        let Some((block_sector, chunks)): Option<(u64, Vec<BlockChunk>)> = parse_mish_chunks(mish)
        else {
            continue;
        };
        for chunk in chunks {
            total_chunks += 1;
            let dest: u64 = block_sector
                .checked_add(chunk.sector_number)
                .and_then(|s: u64| s.checked_mul(SECTOR))
                .ok_or_else(|| Error::Decompression("dmg chunk destination overflow".to_owned()))?;
            let dest: usize = dest as usize;
            let out_len: usize =
                (chunk.sector_count.saturating_mul(SECTOR)).min(MAX_IMAGE_BYTES) as usize;
            let src_start: usize = (koly.data_fork_offset + chunk.compressed_offset) as usize;
            let src_end: usize = src_start.saturating_add(chunk.compressed_length as usize);
            let decoded: Vec<u8> = match chunk.entry_type {
                TYPE_ZERO | TYPE_IGNORE => vec![0u8; out_len],
                TYPE_RAW => bytes
                    .get(src_start..src_end.min(bytes.len()))
                    .map_or(&[] as &[u8], |value: &[u8]| value)
                    .to_vec(),
                TYPE_ADC => adc_decompress(
                    bytes
                        .get(src_start..src_end.min(bytes.len()))
                        .map_or(&[] as &[u8], |value: &[u8]| value),
                    out_len,
                )?,
                TYPE_ZLIB => inflate_zlib(
                    bytes
                        .get(src_start..src_end.min(bytes.len()))
                        .map_or(&[] as &[u8], |value: &[u8]| value),
                    out_len,
                )?,
                TYPE_BZIP2 => decode_bzip2(
                    bytes
                        .get(src_start..src_end.min(bytes.len()))
                        .map_or(&[] as &[u8], |value: &[u8]| value),
                    out_len,
                )?,
                TYPE_LZFSE => decode_lzfse(
                    bytes
                        .get(src_start..src_end.min(bytes.len()))
                        .map_or(&[] as &[u8], |value: &[u8]| value),
                    out_len,
                )?,
                TYPE_LZMA => decode_lzma(
                    bytes
                        .get(src_start..src_end.min(bytes.len()))
                        .map_or(&[] as &[u8], |value: &[u8]| value),
                    out_len,
                )?,
                TYPE_COMMENT => continue,
                other => {
                    if !unsupported.contains(&other) {
                        unsupported.push(other);
                    }
                    continue;
                }
            };
            let copy_len: usize = decoded.len().min(image.len().saturating_sub(dest));
            if copy_len > 0 {
                image[dest..dest + copy_len].copy_from_slice(&decoded[..copy_len]);
            }
        }
    }

    let summary: DmgSummary = DmgSummary {
        koly,
        blkx_blocks: blocks.len(),
        chunks: total_chunks,
        image_len,
        unsupported_chunk_types: unsupported,
    };
    Ok((image, summary))
}

fn inflate_zlib(src: &[u8], expected: usize) -> Result<Vec<u8>> {
    let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(src);
    read_limited_chunk(decoder, expected, "zlib")
}

fn decode_bzip2(src: &[u8], expected: usize) -> Result<Vec<u8>> {
    let decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(src);
    read_limited_chunk(decoder, expected, "bzip2")
}

fn decode_lzfse(src: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(src);
    let mut decoder: lzfse_rust::LzfseRingDecoder = lzfse_rust::LzfseRingDecoder::default();
    let mut writer: DmgChunkWriter = DmgChunkWriter::new(expected, "lzfse");
    decoder
        .decode(&mut reader, &mut writer)
        .map_err(|e: lzfse_rust::Error| {
            Error::Decompression(format!("dmg lzfse chunk failed: {e}"))
        })?;
    Ok(writer.finish())
}

fn decode_lzma(src: &[u8], expected: usize) -> Result<Vec<u8>> {
    if let Ok(out) = decode_xz(src, expected) {
        return Ok(out);
    }
    let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(src);
    let mut writer: DmgChunkWriter = DmgChunkWriter::new(expected, "lzma");
    lzma_rs::lzma_decompress(&mut reader, &mut writer).map_err(|e: lzma_rs::error::Error| {
        Error::Decompression(format!("dmg lzma chunk failed: {e}"))
    })?;
    Ok(writer.finish())
}

fn decode_xz(src: &[u8], expected: usize) -> Result<Vec<u8>> {
    let decoder: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(src);
    read_limited_chunk(decoder, expected, "xz")
}

fn read_limited_chunk<R: std::io::Read>(
    reader: R,
    expected: usize,
    label: &'static str,
) -> Result<Vec<u8>> {
    let limit: usize = dmg_chunk_limit(expected);
    let read_limit: u64 = u64::try_from(limit)
        .map_err(|_| Error::Decompression(format!("dmg {label} chunk limit overflow")))?
        .checked_add(1)
        .ok_or_else(|| Error::Decompression(format!("dmg {label} read limit overflow")))?;
    let mut out: Vec<u8> = Vec::with_capacity(dmg_chunk_capacity(expected));
    reader
        .take(read_limit)
        .read_to_end(&mut out)
        .map_err(|e: std::io::Error| {
            Error::Decompression(format!("dmg {label} chunk failed: {e}"))
        })?;
    if out.len() > limit {
        return Err(dmg_chunk_cap_error(label, limit));
    }
    Ok(out)
}

fn adc_decompress(src: &[u8], expected: usize) -> Result<Vec<u8>> {
    let limit: usize = dmg_chunk_limit(expected);
    let mut out: Vec<u8> = Vec::with_capacity(dmg_chunk_capacity(expected));
    let mut i: usize = 0;
    while i < src.len() {
        let b: u8 = src[i];
        if b & 0x80 != 0 {
            let len: usize = usize::from(b & 0x7F) + 1;
            let start: usize = i
                .checked_add(1)
                .ok_or_else(|| Error::Decompression("dmg adc literal start overflow".to_owned()))?;
            let end: usize = start
                .checked_add(len)
                .ok_or_else(|| Error::Decompression("dmg adc literal end overflow".to_owned()))?;
            let run: &[u8] = src.get(start..end).ok_or_else(|| {
                Error::Decompression("dmg adc literal run out of bounds".to_owned())
            })?;
            ensure_dmg_chunk_space(out.len(), run.len(), "adc", limit)?;
            out.extend_from_slice(run);
            i = end;
        } else if b & 0x40 != 0 {
            let len: usize = usize::from((b >> 2) & 0x0F) + 3;
            let lo: u8 = *src
                .get(i + 1)
                .ok_or_else(|| Error::Decompression("dmg adc short match truncated".to_owned()))?;
            let off: usize = (usize::from(b & 0x03) << 8) + usize::from(lo);
            adc_copy(&mut out, off, len, limit)?;
            i = i
                .checked_add(2)
                .ok_or_else(|| Error::Decompression("dmg adc short cursor overflow".to_owned()))?;
        } else {
            let len: usize = usize::from(b & 0x3F) + 4;
            let hi: u8 = *src
                .get(i + 1)
                .ok_or_else(|| Error::Decompression("dmg adc long match truncated".to_owned()))?;
            let lo: u8 = *src
                .get(i + 2)
                .ok_or_else(|| Error::Decompression("dmg adc long match truncated".to_owned()))?;
            let off: usize = (usize::from(hi) << 8) + usize::from(lo);
            adc_copy(&mut out, off, len, limit)?;
            i = i
                .checked_add(3)
                .ok_or_else(|| Error::Decompression("dmg adc long cursor overflow".to_owned()))?;
        }
    }
    Ok(out)
}

fn adc_copy(out: &mut Vec<u8>, off: usize, len: usize, limit: usize) -> Result<()> {
    ensure_dmg_chunk_space(out.len(), len, "adc", limit)?;
    let start: usize = out
        .len()
        .checked_sub(1)
        .and_then(|v: usize| v.checked_sub(off))
        .ok_or_else(|| Error::Decompression("dmg adc back-reference underflow".to_owned()))?;
    for k in 0..len {
        let byte: u8 = *out.get(start + k).ok_or_else(|| {
            Error::Decompression("dmg adc back-reference out of bounds".to_owned())
        })?;
        out.push(byte);
    }
    Ok(())
}

fn ensure_dmg_chunk_space(
    current: usize,
    additional: usize,
    label: &'static str,
    limit: usize,
) -> Result<()> {
    let next: usize = current
        .checked_add(additional)
        .ok_or_else(|| Error::Decompression(format!("dmg {label} chunk length overflow")))?;
    if next > limit {
        return Err(dmg_chunk_cap_error(label, limit));
    }
    Ok(())
}

#[inline]
fn dmg_chunk_capacity(expected: usize) -> usize {
    dmg_chunk_limit(expected).min(MAX_CHUNK_PREALLOC)
}

#[inline]
fn dmg_chunk_limit(expected: usize) -> usize {
    expected.min(max_image_bytes_usize())
}

#[inline]
fn max_image_bytes_usize() -> usize {
    usize::try_from(MAX_IMAGE_BYTES).map_or(usize::MAX, |v: usize| v)
}

#[inline]
fn dmg_chunk_cap_error(label: &'static str, limit: usize) -> Error {
    Error::Decompression(format!("dmg {label} chunk exceeds {limit}-byte output cap"))
}

struct DmgChunkWriter {
    out: Vec<u8>,
    limit: usize,
    label: &'static str,
}

impl DmgChunkWriter {
    fn new(expected: usize, label: &'static str) -> Self {
        Self {
            out: Vec::with_capacity(dmg_chunk_capacity(expected)),
            limit: dmg_chunk_limit(expected),
            label,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.out
    }
}

impl std::io::Write for DmgChunkWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next: usize = self
            .out
            .len()
            .checked_add(buf.len())
            .ok_or_else(|| std::io::Error::other("dmg chunk length overflow"))?;
        if next > self.limit {
            return Err(std::io::Error::other(format!(
                "dmg {} chunk exceeds {}-byte output cap",
                self.label, self.limit
            )));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn adc_compress_literal(data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for chunk in data.chunks(0x80) {
            out.push(0x80 | (chunk.len() as u8 - 1));
            out.extend_from_slice(chunk);
        }
        out
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).expect("zlib write");
        e.finish().expect("zlib finish")
    }

    fn put_chunk(buf: &mut Vec<u8>, ty: u32, sector: u64, count: u64, off: u64, len: u64) {
        buf.extend_from_slice(&ty.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&sector.to_be_bytes());
        buf.extend_from_slice(&count.to_be_bytes());
        buf.extend_from_slice(&off.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
    }

    fn build_dmg(sector0: &[u8], sector1: &[u8], sector2: &[u8]) -> Vec<u8> {
        let raw: Vec<u8> = sector0.to_vec();
        let zl: Vec<u8> = zlib(sector1);
        let adc: Vec<u8> = adc_compress_literal(sector2);
        let mut data_fork: Vec<u8> = Vec::new();
        let raw_off: u64 = data_fork.len() as u64;
        data_fork.extend_from_slice(&raw);
        let zl_off: u64 = data_fork.len() as u64;
        data_fork.extend_from_slice(&zl);
        let adc_off: u64 = data_fork.len() as u64;
        data_fork.extend_from_slice(&adc);

        let mut mish: Vec<u8> = Vec::new();
        mish.extend_from_slice(&MISH_MAGIC.to_be_bytes());
        mish.extend_from_slice(&1u32.to_be_bytes());
        mish.extend_from_slice(&0u64.to_be_bytes());
        mish.extend_from_slice(&3u64.to_be_bytes());
        mish.extend_from_slice(&0u64.to_be_bytes());
        mish.extend_from_slice(&0u32.to_be_bytes());
        mish.extend_from_slice(&0u32.to_be_bytes());
        mish.extend_from_slice(&[0u8; 24]);
        mish.extend_from_slice(&[0u8; 136]);
        mish.extend_from_slice(&4u32.to_be_bytes());
        put_chunk(&mut mish, TYPE_RAW, 0, 1, raw_off, raw.len() as u64);
        put_chunk(&mut mish, TYPE_ZLIB, 1, 1, zl_off, zl.len() as u64);
        put_chunk(&mut mish, TYPE_ADC, 2, 1, adc_off, adc.len() as u64);
        put_chunk(&mut mish, TYPE_TERMINATOR, 3, 0, 0, 0);

        let b64: String = base64::engine::general_purpose::STANDARD.encode(&mish);
        let xml: String = format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>resource-fork</key><dict><key>blkx</key><array><dict><key>Name</key><string>disk</string><key>Data</key><data>{b64}</data></dict></array></dict></dict></plist>"
        );

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&data_fork);
        let xml_offset: u64 = out.len() as u64;
        out.extend_from_slice(xml.as_bytes());
        let xml_length: u64 = xml.len() as u64;

        let mut koly: Vec<u8> = vec![0u8; KOLY_LEN];
        koly[0..4].copy_from_slice(KOLY_MAGIC);
        koly[24..32].copy_from_slice(&0u64.to_be_bytes());
        koly[32..40].copy_from_slice(&(data_fork.len() as u64).to_be_bytes());
        koly[216..224].copy_from_slice(&xml_offset.to_be_bytes());
        koly[224..232].copy_from_slice(&xml_length.to_be_bytes());
        koly[492..500].copy_from_slice(&3u64.to_be_bytes());
        out.extend_from_slice(&koly);
        out
    }

    #[test]
    fn adc_roundtrips_with_backref() {
        let original: &[u8] = b"ABCABCABCABCABCABCABCABC";
        let mut compressed: Vec<u8> = Vec::new();
        compressed.push(0x82);
        compressed.extend_from_slice(b"ABC");
        let len: u8 = (original.len() - 3) as u8;
        compressed.push(len - 4);
        compressed.push(0x00);
        compressed.push(0x02);
        let out: Vec<u8> = adc_decompress(&compressed, original.len()).expect("adc");
        assert_eq!(out, original);
    }

    #[test]
    fn adc_rejects_output_past_declared_chunk() {
        let compressed: Vec<u8> = vec![0x83, b't', b'e', b's', b't'];
        let err: Error = adc_decompress(&compressed, 3).expect_err("adc cap");
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn reconstructs_three_chunk_dmg() {
        let s0: Vec<u8> = vec![0xAA; 512];
        let s1: Vec<u8> = {
            let mut v: Vec<u8> = b"ABCABCABC".to_vec();
            v.resize(512, 0u8);
            v
        };
        let s2: Vec<u8> = (0..512u16).map(|i: u16| (i & 0xff) as u8).collect();
        let image: Vec<u8> = build_dmg(&s0, &s1, &s2);
        assert!(detect_dmg(&image));
        let (out, summary): (Vec<u8>, DmgSummary) = reconstruct_image(&image).expect("reconstruct");
        assert_eq!(out.len(), 1536);
        assert_eq!(&out[0..512], &s0[..]);
        assert_eq!(&out[512..1024], &s1[..]);
        assert_eq!(&out[1024..1536], &s2[..]);
        assert_eq!(summary.chunks, 3);
        assert!(summary.unsupported_chunk_types.is_empty());
    }

    #[test]
    fn rejects_non_dmg() {
        assert!(!detect_dmg(&[0u8; 1024]));
        assert!(parse_koly(&[0u8; 1024]).is_err());
    }

    #[test]
    fn lzfse_chunk_roundtrips() {
        let original: Vec<u8> = (0..4096u32)
            .map(|i: u32| (i.wrapping_mul(37) & 0xff) as u8)
            .collect();
        let mut compressed: Vec<u8> = Vec::new();
        lzfse_rust::encode_bytes(&original, &mut compressed).expect("lzfse encode");
        let out: Vec<u8> = decode_lzfse(&compressed, original.len()).expect("lzfse decode");
        assert_eq!(out, original);
    }
}
