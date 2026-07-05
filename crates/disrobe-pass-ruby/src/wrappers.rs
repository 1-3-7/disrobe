use std::io::Write;

use disrobe_core::byte_search::find;
use serde::{Deserialize, Serialize};

use crate::detect::{RUBYSCRIPT2EXE_MARKER, has_ocra_signature};
use crate::error::{Result, RubyError};

const OP_END: u32 = 0;
const OP_CREATE_DIRECTORY: u32 = 1;
const OP_CREATE_FILE: u32 = 2;
const OP_CREATE_PROCESS: u32 = 3;
const OP_DECOMPRESS_LZMA: u32 = 4;
const OP_SETENV: u32 = 5;
const OP_POST_CREATE_PROCESS: u32 = 6;
const OP_ENABLE_DEBUG_MODE: u32 = 7;
const OP_CREATE_INST_DIRECTORY: u32 = 8;
const OP_MAX: u32 = 9;

const LZMA_ALONE_PROPS_MAX: u8 = 225;
const OCRA_DECOMPRESS_CAP: u64 = 512 * 1024 * 1024;
const OCRA_MAX_OPCODES: usize = 1 << 20;
const OCRA_MAX_LZMA_DEPTH: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WrapperKind {
    Ruby2Exe,
    Ocra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OcraFile {
    pub path: String,
    pub size: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OcraProcess {
    pub image: String,
    pub command_line: String,
    pub post_create: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OcraImage {
    pub directories: Vec<String>,
    pub files: Vec<OcraFile>,
    pub env: Vec<(String, String)>,
    pub processes: Vec<OcraProcess>,
    pub debug_mode: bool,
    pub lzma_chunks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrapperExtract {
    pub kind: WrapperKind,
    pub marker_offset: u32,
    pub embedded_payload_offset: u32,
    pub embedded_payload_len: u32,
    pub container_format: String,
    pub ocra: Option<OcraImage>,
}

#[must_use]
pub(crate) fn looks_like_ocra_opcode_stream(bytes: &[u8]) -> bool {
    let mut cursor: Cursor<'_> = Cursor::new(bytes);
    let Some(first): Option<u32> = cursor.u32() else {
        return false;
    };
    if first >= OP_MAX {
        return false;
    }
    if first != OP_CREATE_INST_DIRECTORY && first != OP_ENABLE_DEBUG_MODE {
        return false;
    }
    true
}

pub(crate) fn extract(bytes: &[u8]) -> Result<WrapperExtract> {
    if has_ocra_signature(bytes) {
        return extract_ocra(bytes);
    }
    if looks_like_ocra_opcode_stream(bytes)
        && let Ok(extracted) = extract_ocra(bytes)
    {
        return Ok(extracted);
    }
    if let Some(marker_offset) = find(bytes, RUBYSCRIPT2EXE_MARKER) {
        let container: &str = container_format(bytes);
        let payload_offset: usize = marker_offset.saturating_add(RUBYSCRIPT2EXE_MARKER.len());
        let payload_len: usize = bytes.len().saturating_sub(payload_offset);
        return Ok(WrapperExtract {
            kind: WrapperKind::Ruby2Exe,
            marker_offset: clamp_u32(marker_offset),
            embedded_payload_offset: clamp_u32(payload_offset),
            embedded_payload_len: clamp_u32(payload_len),
            container_format: container.to_owned(),
            ocra: None,
        });
    }
    Err(RubyError::Ruby2ExeNoSignature)
}

fn extract_ocra(bytes: &[u8]) -> Result<WrapperExtract> {
    let (stream_offset, marker_offset): (usize, usize) = locate_ocra_stream(bytes)?;
    let stream: &[u8] = bytes
        .get(stream_offset..)
        .ok_or(RubyError::OcraOpcodeStreamTruncated { at: stream_offset })?;
    let mut image: OcraImage = OcraImage::default();
    parse_opcode_stream(stream, &mut image, 0)?;
    Ok(WrapperExtract {
        kind: WrapperKind::Ocra,
        marker_offset: clamp_u32(marker_offset),
        embedded_payload_offset: clamp_u32(stream_offset),
        embedded_payload_len: clamp_u32(bytes.len().saturating_sub(stream_offset)),
        container_format: container_format(bytes).to_owned(),
        ocra: Some(image),
    })
}

fn locate_ocra_stream(bytes: &[u8]) -> Result<(usize, usize)> {
    let len: usize = bytes.len();
    if len >= 8 && &bytes[len - 4..] == crate::detect::OCRA_SIGNATURE.as_slice() {
        let mut cursor: Cursor<'_> = Cursor::new(&bytes[len - 8..len - 4]);
        if let Some(offset) = cursor.u32() {
            let offset: usize = offset as usize;
            if offset < len {
                return Ok((offset, len - 4));
            }
            return Err(RubyError::OcraOpcodeStreamTruncated { at: offset });
        }
        return Err(RubyError::OcraOpcodeStreamTruncated { at: len - 8 });
    }
    if let Some(sig) = find(bytes, crate::detect::OCRA_SIGNATURE.as_slice()) {
        if sig >= 4 {
            let mut cursor: Cursor<'_> = Cursor::new(&bytes[sig - 4..sig]);
            if let Some(offset) = cursor.u32() {
                let offset: usize = offset as usize;
                if offset < len {
                    return Ok((offset, sig));
                }
                return Err(RubyError::OcraOpcodeStreamTruncated { at: offset });
            }
        }
        return Ok((0, sig));
    }
    Ok((0, 0))
}

fn parse_opcode_stream(stream: &[u8], image: &mut OcraImage, depth: u8) -> Result<()> {
    if depth > OCRA_MAX_LZMA_DEPTH {
        return Err(RubyError::OcraOpcodeStreamTruncated { at: 0 });
    }
    let mut cursor: Cursor<'_> = Cursor::new(stream);
    let mut executed: usize = 0;
    loop {
        if executed > OCRA_MAX_OPCODES {
            return Err(RubyError::OcraTooManyOpcodes);
        }
        executed += 1;
        let at: usize = cursor.pos;
        if cursor.at_end() {
            return Ok(());
        }
        let Some(opcode): Option<u32> = cursor.u32() else {
            return Err(RubyError::OcraOpcodeStreamTruncated { at });
        };
        match opcode {
            OP_END => return Ok(()),
            OP_CREATE_INST_DIRECTORY => {
                let _debug_extract: u32 = cursor
                    .u32()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                let _delete_after: u32 = cursor
                    .u32()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                let _chdir: u32 = cursor
                    .u32()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
            }
            OP_ENABLE_DEBUG_MODE => {
                image.debug_mode = true;
            }
            OP_CREATE_DIRECTORY => {
                let name: String = cursor
                    .ascii_z()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                image.directories.push(name);
            }
            OP_CREATE_FILE => {
                let path: String = cursor
                    .ascii_z()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                let size: u32 = cursor
                    .u32()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                let data: Vec<u8> = cursor
                    .take(size as usize)
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?
                    .to_vec();
                image.files.push(OcraFile { path, size, data });
            }
            OP_SETENV => {
                let name: String = cursor
                    .ascii_z()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                let value: String = cursor
                    .ascii_z()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                image.env.push((name, value));
            }
            OP_CREATE_PROCESS | OP_POST_CREATE_PROCESS => {
                let cmd_image: String = cursor
                    .ascii_z()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                let command_line: String = cursor
                    .ascii_z()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                image.processes.push(OcraProcess {
                    image: cmd_image,
                    command_line,
                    post_create: opcode == OP_POST_CREATE_PROCESS,
                });
            }
            OP_DECOMPRESS_LZMA => {
                if depth >= OCRA_MAX_LZMA_DEPTH {
                    return Err(RubyError::OcraLzmaDecode(format!(
                        "lzma nesting depth exceeds safety bound {OCRA_MAX_LZMA_DEPTH}"
                    )));
                }
                let size: u32 = cursor
                    .u32()
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                let blob: &[u8] = cursor
                    .take(size as usize)
                    .ok_or(RubyError::OcraOpcodeStreamTruncated { at })?;
                image.lzma_chunks = image.lzma_chunks.saturating_add(1);
                let inner: Vec<u8> = decompress_lzma_alone(blob, OCRA_DECOMPRESS_CAP)?;
                parse_opcode_stream(&inner, image, depth + 1)?;
            }
            other => return Err(RubyError::OcraUnknownOpcode { opcode: other, at }),
        }
    }
}

struct CapWriter {
    inner: Vec<u8>,
    cap: u64,
    overflowed: bool,
}

impl Write for CapWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.inner.len() as u64 + buf.len() as u64 > self.cap {
            self.overflowed = true;
            return Err(std::io::Error::other("lzma-alone output exceeds bomb cap"));
        }
        self.inner.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn lzma_alone_header_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() < 13 {
        return false;
    }
    let props: u8 = bytes[0];
    if props > LZMA_ALONE_PROPS_MAX {
        return false;
    }
    let dict_size: u32 = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if dict_size < (1u32 << 12) {
        return false;
    }
    let uncompressed: u64 = u64::from_le_bytes([
        bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
    ]);
    uncompressed == u64::MAX || uncompressed < (1u64 << 56)
}

fn decompress_lzma_alone(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    if !lzma_alone_header_is_valid(bytes) {
        return Err(RubyError::OcraLzmaDecode(
            "lzma-alone: header is not a valid 13-byte lzma-alone prelude".to_owned(),
        ));
    }
    let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let mut sink: CapWriter = CapWriter {
        inner: Vec::new(),
        cap,
        overflowed: false,
    };
    let options: lzma_rs::decompress::Options = lzma_rs::decompress::Options {
        memlimit: Some(512 * 1024 * 1024),
        ..Default::default()
    };
    match lzma_rs::lzma_decompress_with_options(&mut reader, &mut sink, &options) {
        Ok(()) => Ok(sink.inner),
        Err(e) => {
            if sink.overflowed {
                Err(RubyError::OcraLzmaDecode(format!(
                    "decompressed stream exceeds bomb cap {cap}"
                )))
            } else {
                Err(RubyError::OcraLzmaDecode(format!("lzma-alone decode: {e}")))
            }
        }
    }
}

fn container_format(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"MZ") {
        "pe"
    } else if bytes.starts_with(b"\x7FELF") {
        "elf"
    } else {
        "raw-opcode-stream"
    }
}

#[inline]
fn clamp_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    const fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    #[inline]
    fn u32(&mut self) -> Option<u32> {
        let slice: &[u8] = self.bytes.get(self.pos..self.pos + 4)?;
        let value: u32 = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        self.pos += 4;
        Some(value)
    }

    #[inline]
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end: usize = self.pos.checked_add(count)?;
        let slice: &[u8] = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    #[inline]
    fn ascii_z(&mut self) -> Option<String> {
        let rest: &[u8] = self.bytes.get(self.pos..)?;
        let nul: usize = rest.iter().position(|&b: &u8| b == 0)?;
        let raw: &[u8] = &rest[..nul];
        self.pos += nul + 1;
        Some(String::from_utf8_lossy(raw).into_owned())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn build_inst_dir() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&OP_CREATE_INST_DIRECTORY.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v
    }

    #[test]
    fn parses_real_committed_opcode_stream() {
        let bytes: &[u8] = include_bytes!("../../../corpus/ruby/ocra/tmpin");
        let w: WrapperExtract = extract(bytes).expect("extract");
        assert_eq!(w.kind, WrapperKind::Ocra);
        let image: OcraImage = w.ocra.expect("ocra image");
        assert_eq!(image.directories, vec!["src".to_owned()]);
        assert_eq!(image.files.len(), 1);
        let file: &OcraFile = &image.files[0];
        assert_eq!(file.path, "src\\hello.rb");
        assert_eq!(file.size, 19);
        assert_eq!(file.data, b"puts \"hello world\"\n");
    }

    #[test]
    fn recovered_file_matches_reference_source() {
        let bytes: &[u8] = include_bytes!("../../../corpus/ruby/ocra/tmpin");
        let reference: &[u8] = include_bytes!("../../../corpus/ruby/ocra/hello.rb");
        let w: WrapperExtract = extract(bytes).expect("extract");
        let image: OcraImage = w.ocra.expect("ocra image");
        let recovered: &OcraFile = image
            .files
            .iter()
            .find(|f: &&OcraFile| f.path.ends_with("hello.rb"))
            .expect("hello.rb recovered");
        assert_eq!(recovered.data, reference);
    }

    #[test]
    fn extracts_synthetic_lzma_wrapped_exe() {
        let mut inner: Vec<u8> = build_inst_dir();
        inner.extend_from_slice(&OP_CREATE_FILE.to_le_bytes());
        inner.extend_from_slice(b"app.rb\x00");
        let payload: &[u8] = b"puts 42\n";
        inner.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        inner.extend_from_slice(payload);
        inner.extend_from_slice(&OP_END.to_le_bytes());

        let compressed: Vec<u8> = lzma_alone_compress(&inner);

        let mut stub: Vec<u8> = b"MZ".to_vec();
        stub.extend_from_slice(&[0u8; 64]);
        let opcode_offset: u32 = clamp_u32(stub.len());
        stub.extend_from_slice(&OP_DECOMPRESS_LZMA.to_le_bytes());
        stub.extend_from_slice(&clamp_u32(compressed.len()).to_le_bytes());
        stub.extend_from_slice(&compressed);
        stub.extend_from_slice(&OP_END.to_le_bytes());
        stub.extend_from_slice(&opcode_offset.to_le_bytes());
        stub.extend_from_slice(crate::detect::OCRA_SIGNATURE.as_slice());

        let w: WrapperExtract = extract(&stub).expect("extract lzma exe");
        assert_eq!(w.container_format, "pe");
        let image: OcraImage = w.ocra.expect("ocra image");
        assert_eq!(image.lzma_chunks, 1);
        assert_eq!(image.files.len(), 1);
        assert_eq!(image.files[0].path, "app.rb");
        assert_eq!(image.files[0].data, payload);
    }

    #[test]
    fn rejects_lzma_depth_before_reading_body() {
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&OP_DECOMPRESS_LZMA.to_le_bytes());
        let mut image: OcraImage = OcraImage::default();
        let err: RubyError =
            parse_opcode_stream(&stream, &mut image, OCRA_MAX_LZMA_DEPTH).expect_err("depth");
        assert!(matches!(err, RubyError::OcraLzmaDecode(_)));
    }

    #[test]
    fn rejects_no_signature() {
        let err: RubyError = extract(b"MZ\x00\x00\x00").expect_err("none");
        assert!(matches!(err, RubyError::Ruby2ExeNoSignature));
    }

    #[test]
    fn rejects_ocra_signature_with_out_of_range_stream_offset() {
        let mut bytes: Vec<u8> = b"MZ".to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(crate::detect::OCRA_SIGNATURE.as_slice());
        let err: RubyError = extract(&bytes).expect_err("bad offset");
        assert!(matches!(
            err,
            RubyError::OcraOpcodeStreamTruncated { at } if at == u32::MAX as usize
        ));
    }

    #[test]
    fn detects_rubyscript2exe_marker() {
        let mut bytes: Vec<u8> = b"MZ".to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(b"require \"rubyscript2exe\"\n");
        let w: WrapperExtract = extract(&bytes).expect("extract");
        assert_eq!(w.kind, WrapperKind::Ruby2Exe);
        assert!(w.ocra.is_none());
    }

    fn lzma_alone_compress(data: &[u8]) -> Vec<u8> {
        let mut reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(data);
        let mut sink: Vec<u8> = Vec::new();
        lzma_rs::lzma_compress(&mut reader, &mut sink).expect("lzma compress");
        sink
    }
}
