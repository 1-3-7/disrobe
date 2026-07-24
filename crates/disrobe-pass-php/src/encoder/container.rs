use crate::decompile::OPARRAY_MAGIC;
use crate::encoder::EncoderFamily;
use crate::error::{Error, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use flate2::read::ZlibDecoder;
use memchr::memmem;
use serde::{Deserialize, Serialize};

pub const CONTAINER_INFLATE_OUTPUT_CAP: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StaticLayer {
    Base64,
    ZlibInflate,
    Xor,
}

impl StaticLayer {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::ZlibInflate => "zlib-inflate",
            Self::Xor => "xor-static-key",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerSurface {
    pub family: EncoderFamily,
    pub container_parsed: bool,
    pub header_fields: Vec<(String, u64)>,
    pub static_layers_stripped: Vec<StaticLayer>,
    pub stripped_payload: Vec<u8>,
    pub opcode_stream_len: usize,
    pub source_reconstructed: bool,
    pub wall_note: &'static str,
}

impl ContainerSurface {
    #[inline]
    #[must_use]
    pub fn measured_layer_count(&self) -> usize {
        self.static_layers_stripped.len()
    }
}

const IONCUBE_VM_WALL: &str = "residual bytes are ionCube proprietary VM opcodes; the per-file decryption key is held by the licensed native loader, not the envelope, so source is not statically reconstructable";
const SOURCEGUARDIAN_VM_WALL: &str = "residual bytes are SourceGuardian proprietary VM opcodes behind the ixed.* native loader; the session key is runtime-derived, so source is not statically reconstructable";
const ZENDGUARD_VM_WALL: &str = "Zend Guard pre-v5 uses an envelope XOR key, decoded here; v5+ derives the key in the native loader, which is not present in the file";

fn inflate_with<R: std::io::Read>(
    mut dec: R,
    family: &'static str,
    layer: &'static str,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk: [u8; 8192] = [0u8; 8192];
    loop {
        let n: usize =
            dec.read(&mut chunk)
                .map_err(|e: std::io::Error| Error::ContainerLayerDecode {
                    family,
                    layer,
                    reason: e.to_string(),
                })?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > CONTAINER_INFLATE_OUTPUT_CAP {
            return Err(Error::ContainerInflateBomb {
                family,
                layer,
                cap: CONTAINER_INFLATE_OUTPUT_CAP,
            });
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

fn inflate_zlib(data: &[u8], family: &'static str) -> Result<Vec<u8>> {
    inflate_with(
        ZlibDecoder::new(data),
        family,
        StaticLayer::ZlibInflate.label(),
    )
}

fn maybe_strip_zlib(
    data: &[u8],
    family: &'static str,
    layers: &mut Vec<StaticLayer>,
) -> Result<Vec<u8>> {
    if looks_like_zlib(data) {
        let out: Vec<u8> = inflate_zlib(data, family)?;
        layers.push(StaticLayer::ZlibInflate);
        Ok(out)
    } else {
        Ok(data.to_vec())
    }
}

fn maybe_strip_static_oparray(
    data: &[u8],
    family: &'static str,
    layers: &mut Vec<StaticLayer>,
) -> Result<Option<Vec<u8>>> {
    if starts_with_oparray(data) {
        return Ok(Some(data.to_vec()));
    }
    if !looks_like_zlib(data) {
        return Ok(None);
    }
    let stripped: Vec<u8> = inflate_zlib(data, family)?;
    if starts_with_oparray(&stripped) {
        layers.push(StaticLayer::ZlibInflate);
        return Ok(Some(stripped));
    }
    Ok(None)
}

fn validate_declared_payload_len(
    actual_len: usize,
    header: &ContainerHeader,
    family: &'static str,
) -> Result<()> {
    let declared_len: usize =
        usize::try_from(header.declared_payload_len).map_err(|_: std::num::TryFromIntError| {
            Error::ContainerBadFraming {
                family,
                reason: "declared opcode length exceeds host address space",
            }
        })?;
    if declared_len != actual_len {
        return Err(Error::ContainerBadFraming {
            family,
            reason: "declared opcode length does not match container body",
        });
    }
    Ok(())
}

#[inline]
#[must_use]
fn starts_with_oparray(data: &[u8]) -> bool {
    data.get(..OPARRAY_MAGIC.len())
        .is_some_and(|head: &[u8]| head == &OPARRAY_MAGIC[..])
}

#[inline]
#[must_use]
fn looks_like_zlib(data: &[u8]) -> bool {
    matches!(
        (data.first().copied(), data.get(1).copied()),
        (Some(0x78), Some(0x01 | 0x5e | 0x9c | 0xda))
    )
}

#[inline]
#[must_use]
fn read_u32_le(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

const IONCUBE_CONTAINER_MAGIC: [u8; 4] = *b"ICUB";
const SOURCEGUARDIAN_CONTAINER_MAGIC: [u8; 4] = *b"SGEN";
const CONTAINER_HEADER_LEN: usize = 24;

#[inline]
#[must_use]
fn read_b64_region(body: &[u8]) -> &[u8] {
    let mut end: usize = 0;
    while end < body.len() {
        let b: u8 = body[end];
        if is_b64_byte(b) || b == b'\n' || b == b'\r' {
            end += 1;
        } else {
            break;
        }
    }
    &body[..end]
}

#[must_use]
fn strip_ascii_whitespace(region: &[u8]) -> Vec<u8> {
    region
        .iter()
        .copied()
        .filter(|b: &u8| !b.is_ascii_whitespace())
        .collect()
}

fn decode_b64_payload(region: &[u8], family: &'static str) -> Result<Vec<u8>> {
    let compact: Vec<u8> = strip_ascii_whitespace(region);
    if compact.len() < 8 {
        return Err(Error::ContainerBadFraming {
            family,
            reason: "base64 payload region too short",
        });
    }
    disrobe_core::codec::base64_decode(
        &compact,
        disrobe_core::codec::Base64Alphabet::Standard,
        disrobe_core::codec::Base64Padding::Required,
    )
    .map_err(
        |e: disrobe_core::codec::DecodeError| Error::ContainerLayerDecode {
            family,
            layer: StaticLayer::Base64.label(),
            reason: e.to_string(),
        },
    )
}

fn body_after_marker_line(
    envelope: &[u8],
    marker_offset: usize,
    family: &'static str,
) -> Result<usize> {
    let line_end: usize = envelope[marker_offset..]
        .iter()
        .position(|&b: &u8| b == b'\n')
        .map(|p: usize| marker_offset + p + 1)
        .ok_or(Error::ContainerBadFraming {
            family,
            reason: "marker line has no terminating newline",
        })?;
    let mut at: usize = line_end;
    while at < envelope.len() {
        let rest: &[u8] = &envelope[at..];
        if is_b64_byte(rest[0]) {
            break;
        }
        let next: usize = rest
            .iter()
            .position(|&b: &u8| b == b'\n')
            .map_or(envelope.len(), |p: usize| at + p + 1);
        if next == at {
            break;
        }
        at = next;
    }
    if at >= envelope.len() {
        return Err(Error::ContainerBadFraming {
            family,
            reason: "no base64 body after marker line",
        });
    }
    Ok(at)
}

pub fn reverse_ioncube_container(
    envelope: &[u8],
    marker_offset: usize,
) -> Result<ContainerSurface> {
    const FAMILY: &str = "ionCube";
    let body_start: usize = body_after_marker_line(envelope, marker_offset, FAMILY)?;
    let region: &[u8] = read_b64_region(&envelope[body_start..]);
    let decoded: Vec<u8> = decode_b64_payload(region, FAMILY)?;
    let mut layers: Vec<StaticLayer> = vec![StaticLayer::Base64];
    if let Some(stripped) = maybe_strip_static_oparray(&decoded, FAMILY, &mut layers)? {
        let header_fields: Vec<(String, u64)> = vec![
            ("marker_offset".to_owned(), marker_offset as u64),
            ("b64_segment_len".to_owned(), region.len() as u64),
            ("decoded_container_len".to_owned(), decoded.len() as u64),
            ("opcode_stream_len".to_owned(), stripped.len() as u64),
        ];
        let opcode_stream_len: usize = stripped.len();
        return Ok(ContainerSurface {
            family: EncoderFamily::IonCube,
            container_parsed: true,
            header_fields,
            static_layers_stripped: layers,
            stripped_payload: stripped,
            opcode_stream_len,
            source_reconstructed: false,
            wall_note: IONCUBE_VM_WALL,
        });
    }
    let header: ContainerHeader =
        parse_container_header(&decoded, IONCUBE_CONTAINER_MAGIC, FAMILY)?;
    let opcode_body: &[u8] =
        decoded
            .get(CONTAINER_HEADER_LEN..)
            .ok_or(Error::ContainerBadFraming {
                family: FAMILY,
                reason: "header present but no opcode body",
            })?;
    validate_declared_payload_len(opcode_body.len(), &header, FAMILY)?;
    let stripped: Vec<u8> = maybe_strip_zlib(opcode_body, FAMILY, &mut layers)?;
    let header_fields: Vec<(String, u64)> = vec![
        ("marker_offset".to_owned(), marker_offset as u64),
        ("loader_version".to_owned(), u64::from(header.version)),
        ("flags".to_owned(), u64::from(header.flags)),
        (
            "declared_opcode_len".to_owned(),
            u64::from(header.declared_payload_len),
        ),
    ];
    let opcode_stream_len: usize = stripped.len();
    Ok(ContainerSurface {
        family: EncoderFamily::IonCube,
        container_parsed: true,
        header_fields,
        static_layers_stripped: layers,
        stripped_payload: stripped,
        opcode_stream_len,
        source_reconstructed: false,
        wall_note: IONCUBE_VM_WALL,
    })
}

pub fn reverse_sourceguardian_container(envelope: &[u8]) -> Result<ContainerSurface> {
    const FAMILY: &str = "SourceGuardian";
    let decoded: Vec<u8> = if let Some(call_at) = memmem::find(envelope, b"sg_load('") {
        let arg_start: usize = call_at + b"sg_load('".len();
        let arg_rel: usize = envelope[arg_start..]
            .iter()
            .position(|&b: &u8| b == b'\'')
            .ok_or(Error::ContainerBadFraming {
                family: FAMILY,
                reason: "unterminated sg_load argument",
            })?;
        decode_b64_payload(&envelope[arg_start..arg_start + arg_rel], FAMILY)?
    } else {
        let marker: usize = memmem::find(envelope, b"//SGV")
            .or_else(|| memmem::find(envelope, b"//SourceGuardian"))
            .ok_or(Error::ContainerBadFraming {
                family: FAMILY,
                reason: "no sg_load call or //SGV banner",
            })?;
        let body_start: usize = body_after_marker_line(envelope, marker, FAMILY)?;
        let region: &[u8] = read_b64_region(&envelope[body_start..]);
        decode_b64_payload(region, FAMILY)?
    };
    let mut layers: Vec<StaticLayer> = vec![StaticLayer::Base64];
    if let Some(stripped) = maybe_strip_static_oparray(&decoded, FAMILY, &mut layers)? {
        let header_fields: Vec<(String, u64)> = vec![
            ("decoded_container_len".to_owned(), decoded.len() as u64),
            ("opcode_stream_len".to_owned(), stripped.len() as u64),
        ];
        let opcode_stream_len: usize = stripped.len();
        return Ok(ContainerSurface {
            family: EncoderFamily::SourceGuardian,
            container_parsed: true,
            header_fields,
            static_layers_stripped: layers,
            stripped_payload: stripped,
            opcode_stream_len,
            source_reconstructed: false,
            wall_note: SOURCEGUARDIAN_VM_WALL,
        });
    }
    let header: ContainerHeader =
        parse_container_header(&decoded, SOURCEGUARDIAN_CONTAINER_MAGIC, FAMILY)?;
    let opcode_body: &[u8] =
        decoded
            .get(CONTAINER_HEADER_LEN..)
            .ok_or(Error::ContainerBadFraming {
                family: FAMILY,
                reason: "header present but no opcode body",
            })?;
    validate_declared_payload_len(opcode_body.len(), &header, FAMILY)?;
    let stripped: Vec<u8> = maybe_strip_zlib(opcode_body, FAMILY, &mut layers)?;
    let header_fields: Vec<(String, u64)> = vec![
        ("loader_version".to_owned(), u64::from(header.version)),
        ("flags".to_owned(), u64::from(header.flags)),
        (
            "declared_opcode_len".to_owned(),
            u64::from(header.declared_payload_len),
        ),
    ];
    let opcode_stream_len: usize = stripped.len();
    Ok(ContainerSurface {
        family: EncoderFamily::SourceGuardian,
        container_parsed: true,
        header_fields,
        static_layers_stripped: layers,
        stripped_payload: stripped,
        opcode_stream_len,
        source_reconstructed: false,
        wall_note: SOURCEGUARDIAN_VM_WALL,
    })
}

struct ContainerHeader {
    version: u32,
    flags: u32,
    declared_payload_len: u32,
}

fn parse_container_header(
    decoded: &[u8],
    magic: [u8; 4],
    family: &'static str,
) -> Result<ContainerHeader> {
    if decoded.len() < CONTAINER_HEADER_LEN {
        return Err(Error::ContainerBadFraming {
            family,
            reason: "decoded body shorter than container header",
        });
    }
    if decoded[..4] != magic {
        return Err(Error::ContainerBadFraming {
            family,
            reason: "decoded body lacks container header magic",
        });
    }
    let version: u32 = read_u32_le(decoded, 4).ok_or(Error::ContainerBadFraming {
        family,
        reason: "version field truncated",
    })?;
    let flags: u32 = read_u32_le(decoded, 8).ok_or(Error::ContainerBadFraming {
        family,
        reason: "flags field truncated",
    })?;
    let declared_payload_len: u32 = read_u32_le(decoded, 12).ok_or(Error::ContainerBadFraming {
        family,
        reason: "declared length field truncated",
    })?;
    Ok(ContainerHeader {
        version,
        flags,
        declared_payload_len,
    })
}

fn build_container_body(
    family: &'static str,
    magic: [u8; 4],
    version: u32,
    flags: u32,
    opcode_stream: &[u8],
) -> Result<Vec<u8>> {
    let declared_len: u32 =
        u32::try_from(opcode_stream.len()).map_err(|_| Error::ContainerBadFraming {
            family,
            reason: "payload length exceeds container field",
        })?;
    let capacity: usize = CONTAINER_HEADER_LEN
        .checked_add(opcode_stream.len())
        .ok_or(Error::ContainerBadFraming {
            family,
            reason: "payload length exceeds addressable memory",
        })?;
    let mut body: Vec<u8> = Vec::with_capacity(capacity);
    body.extend_from_slice(&magic);
    body.extend_from_slice(&version.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&declared_len.to_le_bytes());
    body.extend_from_slice(&[0u8; CONTAINER_HEADER_LEN - 16]);
    body.extend_from_slice(opcode_stream);
    Ok(body)
}

pub fn build_ioncube_container(
    marker_line: &[u8],
    version: u32,
    flags: u32,
    opcode_stream: &[u8],
    zlib: bool,
) -> Result<Vec<u8>> {
    const FAMILY: &str = "ionCube";
    let stream: Vec<u8> = if zlib {
        zlib_compress(FAMILY, opcode_stream)?
    } else {
        opcode_stream.to_vec()
    };
    let body: Vec<u8> =
        build_container_body(FAMILY, IONCUBE_CONTAINER_MAGIC, version, flags, &stream)?;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(marker_line);
    out.push(b'\n');
    out.extend_from_slice(B64_STD.encode(&body).as_bytes());
    out.push(b'\n');
    Ok(out)
}

pub fn build_sourceguardian_container(
    version: u32,
    flags: u32,
    opcode_stream: &[u8],
    zlib: bool,
) -> Result<Vec<u8>> {
    const FAMILY: &str = "SourceGuardian";
    let stream: Vec<u8> = if zlib {
        zlib_compress(FAMILY, opcode_stream)?
    } else {
        opcode_stream.to_vec()
    };
    let body: Vec<u8> = build_container_body(
        FAMILY,
        SOURCEGUARDIAN_CONTAINER_MAGIC,
        version,
        flags,
        &stream,
    )?;
    let mut out: Vec<u8> = b"<?php sg_load('".to_vec();
    out.extend_from_slice(B64_STD.encode(&body).as_bytes());
    out.extend_from_slice(b"');\n");
    Ok(out)
}

fn zlib_compress(family: &'static str, data: &[u8]) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write as _;
    let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)
        .map_err(|e: std::io::Error| Error::ContainerLayerDecode {
            family,
            layer: StaticLayer::ZlibInflate.label(),
            reason: e.to_string(),
        })?;
    enc.finish()
        .map_err(|e: std::io::Error| Error::ContainerLayerDecode {
            family,
            layer: StaticLayer::ZlibInflate.label(),
            reason: e.to_string(),
        })
}

pub fn build_zend_guard_obfuscated(
    version: u8,
    key: &[u8],
    opcode_stream: &[u8],
) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err(Error::ContainerLayerDecode {
            family: "Zend Guard",
            layer: StaticLayer::Xor.label(),
            reason: "empty static key".to_string(),
        });
    }
    let mut out: Vec<u8> = b"<?php @Zend;\n".to_vec();
    out.push(version);
    out.push(0x00);
    out.extend_from_slice(ZEND_OPTIMIZER_OBF_TAG);
    out.extend_from_slice(&(key.len() as u16).to_le_bytes());
    out.extend_from_slice(key);
    let xored: Vec<u8> = opcode_stream
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect();
    out.extend_from_slice(&xored);
    Ok(out)
}

pub const SYNTHETIC_TRANSPORT_FRAME_MAGIC: [u8; 4] = *b"ICF1";

pub fn synthetic_transport_surface_ioncube(
    envelope: &[u8],
    marker_offset: usize,
) -> Result<ContainerSurface> {
    const FAMILY: &str = "ionCube";
    let line_end: usize = envelope[marker_offset..]
        .iter()
        .position(|&b: &u8| b == b'\n')
        .map(|p: usize| marker_offset + p + 1)
        .ok_or(Error::ContainerBadFraming {
            family: FAMILY,
            reason: "marker line has no terminating newline",
        })?;
    let body: &[u8] = envelope.get(line_end..).ok_or(Error::ContainerBadFraming {
        family: FAMILY,
        reason: "no body after marker line",
    })?;
    let b64_end: usize = body
        .iter()
        .position(|&b: &u8| !is_b64_byte(b))
        .unwrap_or(body.len());
    let b64_region: &[u8] = &body[..b64_end];
    if b64_region.len() < 8 {
        return Err(Error::ContainerBadFraming {
            family: FAMILY,
            reason: "base64 framing segment too short",
        });
    }
    let mut layers: Vec<StaticLayer> = Vec::with_capacity(3);
    let decoded: Vec<u8> = B64_STD
        .decode(b64_region)
        .map_err(|e: base64::DecodeError| Error::ContainerLayerDecode {
            family: FAMILY,
            layer: StaticLayer::Base64.label(),
            reason: e.to_string(),
        })?;
    layers.push(StaticLayer::Base64);
    if decoded.len() < 8 || decoded[..4] != SYNTHETIC_TRANSPORT_FRAME_MAGIC {
        return Err(Error::ContainerBadFraming {
            family: FAMILY,
            reason: "inner segment lacks ICF1 frame magic",
        });
    }
    let inner_len: u32 = read_u32_le(&decoded, 4).ok_or(Error::ContainerBadFraming {
        family: FAMILY,
        reason: "frame length prefix truncated",
    })?;
    let payload_start: usize = 8;
    let payload_end: usize =
        payload_start
            .checked_add(inner_len as usize)
            .ok_or(Error::ContainerBadFraming {
                family: FAMILY,
                reason: "frame length prefix overflows the address space",
            })?;
    let payload: &[u8] =
        decoded
            .get(payload_start..payload_end)
            .ok_or(Error::ContainerBadFraming {
                family: FAMILY,
                reason: "frame payload shorter than declared length",
            })?;
    let stripped: Vec<u8> = maybe_strip_zlib(payload, FAMILY, &mut layers)?;
    let header_fields: Vec<(String, u64)> = vec![
        ("marker_offset".to_owned(), marker_offset as u64),
        ("b64_segment_len".to_owned(), b64_region.len() as u64),
        ("frame_inner_len".to_owned(), u64::from(inner_len)),
    ];
    let opcode_stream_len: usize = stripped.len();
    Ok(ContainerSurface {
        family: EncoderFamily::IonCube,
        container_parsed: true,
        header_fields,
        static_layers_stripped: layers,
        stripped_payload: stripped,
        opcode_stream_len,
        source_reconstructed: false,
        wall_note: IONCUBE_VM_WALL,
    })
}

pub fn synthetic_transport_surface_sourceguardian(envelope: &[u8]) -> Result<ContainerSurface> {
    const FAMILY: &str = "SourceGuardian";
    const NEEDLE: &[u8] = b"sg_load('";
    let call_at: usize = memmem::find(envelope, NEEDLE).ok_or(Error::ContainerBadFraming {
        family: FAMILY,
        reason: "no sg_load('...') call site",
    })?;
    let arg_start: usize = call_at + NEEDLE.len();
    let arg_rel: usize = envelope[arg_start..]
        .iter()
        .position(|&b: &u8| b == b'\'')
        .ok_or(Error::ContainerBadFraming {
            family: FAMILY,
            reason: "unterminated sg_load argument",
        })?;
    let arg: &[u8] = &envelope[arg_start..arg_start + arg_rel];
    if arg.len() < 8 {
        return Err(Error::ContainerBadFraming {
            family: FAMILY,
            reason: "sg_load argument too short",
        });
    }
    let mut layers: Vec<StaticLayer> = Vec::with_capacity(2);
    let decoded: Vec<u8> =
        B64_STD
            .decode(arg)
            .map_err(|e: base64::DecodeError| Error::ContainerLayerDecode {
                family: FAMILY,
                layer: StaticLayer::Base64.label(),
                reason: e.to_string(),
            })?;
    layers.push(StaticLayer::Base64);
    let stripped: Vec<u8> = maybe_strip_zlib(&decoded, FAMILY, &mut layers)?;
    let header_fields: Vec<(String, u64)> = vec![
        ("sg_load_offset".to_owned(), call_at as u64),
        ("arg_len".to_owned(), arg.len() as u64),
    ];
    let opcode_stream_len: usize = stripped.len();
    Ok(ContainerSurface {
        family: EncoderFamily::SourceGuardian,
        container_parsed: true,
        header_fields,
        static_layers_stripped: layers,
        stripped_payload: stripped,
        opcode_stream_len,
        source_reconstructed: false,
        wall_note: SOURCEGUARDIAN_VM_WALL,
    })
}

pub fn surface_zend_guard(envelope: &[u8]) -> Result<ContainerSurface> {
    const FAMILY: &str = "ZendGuard";
    const BANNER: &[u8] = b"<?php @Zend;\n";
    const XOR_KEY_LEN: usize = 8;
    let banner_at: usize = memmem::find(envelope, BANNER).ok_or(Error::ContainerBadFraming {
        family: FAMILY,
        reason: "no @Zend; banner",
    })?;
    let version_at: usize = banner_at + BANNER.len();
    let version: u8 = *envelope.get(version_at).ok_or(Error::ContainerBadFraming {
        family: FAMILY,
        reason: "banner not followed by version byte",
    })?;
    if !matches!(version, b'2' | b'3' | b'4') {
        return Err(Error::ContainerBadFraming {
            family: FAMILY,
            reason: "unsupported Zend Guard version byte",
        });
    }
    let header_start: usize = version_at + 2;
    let (key, key_start, body): (Vec<u8>, usize, &[u8]) = if let Some(obf) =
        read_zend_optimizer_key(envelope, header_start)
    {
        obf
    } else {
        let key_end: usize = header_start + XOR_KEY_LEN;
        let key: &[u8] = envelope
            .get(header_start..key_end)
            .ok_or(Error::ContainerBadFraming {
                family: FAMILY,
                reason: "static XOR key region truncated",
            })?;
        if key.iter().all(|b: &u8| *b == 0) {
            return Err(Error::ContainerBadFraming {
                family: FAMILY,
                reason: "static XOR key region is all-zero",
            });
        }
        let body: &[u8] = envelope.get(key_end..).ok_or(Error::ContainerBadFraming {
            family: FAMILY,
            reason: "no body after XOR key",
        })?;
        (key.to_vec(), header_start, body)
    };
    let mut layers: Vec<StaticLayer> = Vec::with_capacity(2);
    let xored: Vec<u8> = body
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect();
    layers.push(StaticLayer::Xor);
    let stripped: Vec<u8> = maybe_strip_zlib(&xored, FAMILY, &mut layers)?;
    let header_fields: Vec<(String, u64)> = vec![
        ("banner_offset".to_owned(), banner_at as u64),
        ("version".to_owned(), u64::from(version - b'0')),
        ("xor_key_offset".to_owned(), key_start as u64),
        ("xor_key_len".to_owned(), key.len() as u64),
    ];
    let opcode_stream_len: usize = stripped.len();
    Ok(ContainerSurface {
        family: EncoderFamily::ZendGuard,
        container_parsed: true,
        header_fields,
        static_layers_stripped: layers,
        stripped_payload: stripped,
        opcode_stream_len,
        source_reconstructed: false,
        wall_note: ZENDGUARD_VM_WALL,
    })
}

const ZEND_OPTIMIZER_OBF_TAG: &[u8] = b"ZOBF";
const ZEND_OPTIMIZER_OBF_KEY_CAP: usize = 4096;

fn read_zend_optimizer_key(
    envelope: &[u8],
    header_start: usize,
) -> Option<(Vec<u8>, usize, &[u8])> {
    let tag_end: usize = header_start.checked_add(ZEND_OPTIMIZER_OBF_TAG.len())?;
    let tag: &[u8] = envelope.get(header_start..tag_end)?;
    if tag != ZEND_OPTIMIZER_OBF_TAG {
        return None;
    }
    let len_at: usize = tag_end;
    let len_bytes: &[u8] = envelope.get(len_at..len_at.checked_add(2)?)?;
    let key_len: usize = usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
    if key_len == 0 || key_len > ZEND_OPTIMIZER_OBF_KEY_CAP {
        return None;
    }
    let key_start: usize = len_at + 2;
    let key_end: usize = key_start + key_len;
    let key: &[u8] = envelope.get(key_start..key_end)?;
    if key.iter().all(|b: &u8| *b == 0) {
        return None;
    }
    let body: &[u8] = envelope.get(key_end..)?;
    Some((key.to_vec(), key_start, body))
}

#[inline]
#[must_use]
fn is_b64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write as _;

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    fn ioncube_frame(inner: &[u8]) -> Vec<u8> {
        let mut frame: Vec<u8> = Vec::with_capacity(8 + inner.len());
        frame.extend_from_slice(&SYNTHETIC_TRANSPORT_FRAME_MAGIC);
        frame.extend_from_slice(&u32::try_from(inner.len()).expect("len").to_le_bytes());
        frame.extend_from_slice(inner);
        frame
    }

    fn build_ioncube_envelope(inner: &[u8]) -> Vec<u8> {
        let frame: Vec<u8> = ioncube_frame(inner);
        let b64: String = B64_STD.encode(&frame);
        let mut out: Vec<u8> = b"<?php //004F\n".to_vec();
        out.extend_from_slice(b64.as_bytes());
        out.push(b'\n');
        out
    }

    fn build_ioncube_envelope_zlib(inner: &[u8]) -> Vec<u8> {
        let compressed: Vec<u8> = zlib_compress(inner);
        build_ioncube_envelope(&compressed)
    }

    #[test]
    fn synthetic_ioncube_transport_strips_to_exact_header_and_inner_payload() {
        let inner: &[u8] = b"OPCODE-STREAM-PROPRIETARY-VM-BYTES-0123456789";
        let envelope: Vec<u8> = build_ioncube_envelope(inner);
        let marker: usize = memmem::find(&envelope, b"//004F").expect("marker");
        let surface: ContainerSurface =
            synthetic_transport_surface_ioncube(&envelope, marker).expect("surface");
        assert!(surface.container_parsed);
        assert_eq!(surface.stripped_payload, inner);
        assert_eq!(surface.static_layers_stripped, vec![StaticLayer::Base64]);
        assert_eq!(surface.opcode_stream_len, inner.len());
        assert!(!surface.source_reconstructed);
        assert!(surface.wall_note.contains("proprietary VM"));
        let inner_len_field: u64 = surface
            .header_fields
            .iter()
            .find(|(k, _): &&(String, u64)| k == "frame_inner_len")
            .map(|(_, v): &(String, u64)| *v)
            .expect("frame_inner_len");
        assert_eq!(inner_len_field, inner.len() as u64);
    }

    #[test]
    fn synthetic_ioncube_transport_strips_base64_then_zlib() {
        let inner: &[u8] = b"inner-vm-opcodes-after-two-static-layers-XYZXYZXYZ";
        let envelope: Vec<u8> = build_ioncube_envelope_zlib(inner);
        let marker: usize = memmem::find(&envelope, b"//004F").expect("marker");
        let surface: ContainerSurface =
            synthetic_transport_surface_ioncube(&envelope, marker).expect("surface");
        assert_eq!(surface.stripped_payload, inner);
        assert_eq!(
            surface.static_layers_stripped,
            vec![StaticLayer::Base64, StaticLayer::ZlibInflate]
        );
    }

    #[test]
    fn synthetic_ioncube_transport_wrong_frame_magic_is_error() {
        let mut frame: Vec<u8> = b"BADM".to_vec();
        frame.extend_from_slice(&4u32.to_le_bytes());
        frame.extend_from_slice(b"data");
        let b64: String = B64_STD.encode(&frame);
        let mut envelope: Vec<u8> = b"<?php //004F\n".to_vec();
        envelope.extend_from_slice(b64.as_bytes());
        let marker: usize = memmem::find(&envelope, b"//004F").expect("marker");
        let err: Error =
            synthetic_transport_surface_ioncube(&envelope, marker).expect_err("bad magic");
        assert!(format!("{err}").contains("ICF1 frame magic"));
    }

    #[test]
    fn synthetic_ioncube_transport_truncated_frame_length_is_error() {
        let mut frame: Vec<u8> = SYNTHETIC_TRANSPORT_FRAME_MAGIC.to_vec();
        frame.extend_from_slice(&999u32.to_le_bytes());
        frame.extend_from_slice(b"short");
        let b64: String = B64_STD.encode(&frame);
        let mut envelope: Vec<u8> = b"<?php //004F\n".to_vec();
        envelope.extend_from_slice(b64.as_bytes());
        let marker: usize = memmem::find(&envelope, b"//004F").expect("marker");
        let err: Error =
            synthetic_transport_surface_ioncube(&envelope, marker).expect_err("truncated");
        assert!(format!("{err}").contains("shorter than declared"));
    }

    #[test]
    fn synthetic_sourceguardian_transport_strips_base64_inner_payload() {
        let inner: &[u8] = b"SG-VM-OPCODES-aaaaaaaaaaaaaaaaaaaa";
        let arg: String = B64_STD.encode(inner);
        let mut envelope: Vec<u8> = b"<?php sg_load('".to_vec();
        envelope.extend_from_slice(arg.as_bytes());
        envelope.extend_from_slice(b"');");
        let surface: ContainerSurface =
            synthetic_transport_surface_sourceguardian(&envelope).expect("surface");
        assert!(surface.container_parsed);
        assert_eq!(surface.stripped_payload, inner);
        assert_eq!(surface.static_layers_stripped, vec![StaticLayer::Base64]);
        assert!(!surface.source_reconstructed);
    }

    #[test]
    fn synthetic_sourceguardian_transport_strips_base64_then_zlib() {
        let inner: &[u8] = b"SG-inner-after-zlib-bbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let arg: String = B64_STD.encode(zlib_compress(inner));
        let mut envelope: Vec<u8> = b"<?php sg_load('".to_vec();
        envelope.extend_from_slice(arg.as_bytes());
        envelope.extend_from_slice(b"');");
        let surface: ContainerSurface =
            synthetic_transport_surface_sourceguardian(&envelope).expect("surface");
        assert_eq!(surface.stripped_payload, inner);
        assert_eq!(
            surface.static_layers_stripped,
            vec![StaticLayer::Base64, StaticLayer::ZlibInflate]
        );
    }

    #[test]
    fn synthetic_sourceguardian_transport_no_call_is_error() {
        let err: Error = synthetic_transport_surface_sourceguardian(b"<?php echo 'plain';")
            .expect_err("no call");
        assert!(format!("{err}").contains("no sg_load"));
    }

    #[test]
    fn zend_guard_xor_recovers_inner_payload() {
        let key: [u8; 8] = *b"K3yK3yK3";
        let inner: &[u8] = b"ZEND-VM-OPCODES-cccccccccccccccccccc";
        let xored: Vec<u8> = inner
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &u8)| b ^ key[i % 8])
            .collect();
        let mut envelope: Vec<u8> = b"<?php @Zend;\n3".to_vec();
        envelope.push(b'\n');
        envelope.extend_from_slice(&key);
        envelope.extend_from_slice(&xored);
        let surface: ContainerSurface = surface_zend_guard(&envelope).expect("surface");
        assert!(surface.container_parsed);
        assert_eq!(surface.stripped_payload, inner);
        assert_eq!(surface.static_layers_stripped, vec![StaticLayer::Xor]);
        assert!(!surface.source_reconstructed);
        let version_field: u64 = surface
            .header_fields
            .iter()
            .find(|(k, _): &&(String, u64)| k == "version")
            .map(|(_, v): &(String, u64)| *v)
            .expect("version");
        assert_eq!(version_field, 3);
    }

    #[test]
    fn zend_guard_xor_then_zlib() {
        let key: [u8; 8] = *b"abcdefgh";
        let inner: &[u8] = b"zend-inner-after-zlib-dddddddddddddddddddddddd";
        let compressed: Vec<u8> = zlib_compress(inner);
        let xored: Vec<u8> = compressed
            .iter()
            .enumerate()
            .map(|(i, b): (usize, &u8)| b ^ key[i % 8])
            .collect();
        let mut envelope: Vec<u8> = b"<?php @Zend;\n4".to_vec();
        envelope.push(b'\n');
        envelope.extend_from_slice(&key);
        envelope.extend_from_slice(&xored);
        let surface: ContainerSurface = surface_zend_guard(&envelope).expect("surface");
        assert_eq!(surface.stripped_payload, inner);
        assert_eq!(
            surface.static_layers_stripped,
            vec![StaticLayer::Xor, StaticLayer::ZlibInflate]
        );
    }

    #[test]
    fn zend_guard_allzero_key_is_error() {
        let mut envelope: Vec<u8> = b"<?php @Zend;\n3".to_vec();
        envelope.push(b'\n');
        envelope.extend_from_slice(&[0u8; 8]);
        envelope.extend_from_slice(b"ciphertext-body");
        let err: Error = surface_zend_guard(&envelope).expect_err("all-zero key");
        assert!(format!("{err}").contains("all-zero"));
    }

    #[test]
    fn zend_guard_wrong_version_is_error() {
        let mut envelope: Vec<u8> = b"<?php @Zend;\n9".to_vec();
        envelope.push(b'\n');
        envelope.extend_from_slice(&[1u8; 8]);
        envelope.extend_from_slice(b"body");
        let err: Error = surface_zend_guard(&envelope).expect_err("bad version");
        assert!(format!("{err}").contains("unsupported Zend Guard version"));
    }

    #[test]
    fn synthetic_ioncube_transport_no_marker_newline_is_error() {
        let envelope: &[u8] = b"<?php //004F no-newline-ever";
        let err: Error = synthetic_transport_surface_ioncube(envelope, 6).expect_err("no newline");
        assert!(format!("{err}").contains("terminating newline"));
    }
}
