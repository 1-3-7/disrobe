#![allow(
    clippy::needless_range_loop,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use serde::{Deserialize, Serialize};

use crate::decompile::{Decompilation, OPARRAY_MAGIC, OpArray, decompile, parse_oparray};
use crate::encoder::{
    ContainerSurface, EncoderFamily, reverse_ioncube_container, reverse_sourceguardian_container,
    surface_zend_guard,
};
use crate::error::Result;

pub mod ioncube;
pub mod sourceguardian;
pub mod zend_guard;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtectorFamily {
    IonCube,
    SourceGuardian,
    ZendGuard,
}

impl ProtectorFamily {
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::IonCube => "ionCube",
            Self::SourceGuardian => "SourceGuardian",
            Self::ZendGuard => "ZendGuard",
        }
    }

    #[inline]
    #[must_use]
    pub const fn wall_reason(self) -> &'static str {
        match self {
            Self::IonCube => {
                "ionCube container framing and transport layers are reversed statically; when the opcode body is the per-file symmetric-key-encrypted ionCube VM stream, that key is derived in the native loader via an RSA license handshake and is not present in the file, so that body cannot be lifted statically"
            }
            Self::SourceGuardian => {
                "SourceGuardian container framing and transport layers are reversed statically; when the opcode body is encrypted with the session key the ixed native loader derives at runtime, that key is not present in the file, so that body cannot be lifted statically"
            }
            Self::ZendGuard => {
                "Zend Guard envelope, static XOR header, and Zend Optimizer obfuscation key are recovered statically when present; only opcode bodies behind a loader-derived runtime key remain unliftable"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectorDetection {
    pub family: ProtectorFamily,
    pub version_label: String,
    pub marker_offset: usize,
    pub confident: bool,
    pub payload_offset: Option<usize>,
    pub payload_len: usize,
    pub recovered_strings: Vec<String>,
    pub wall_reason: &'static str,
    pub container_parsed: bool,
    pub static_layers_stripped: Vec<String>,
    pub opcode_stream_len: usize,
    pub source_reconstructed: bool,
    pub recovered_source: Option<String>,
    pub decompilation: Option<Decompilation>,
}

impl ProtectorDetection {
    #[inline]
    #[must_use]
    pub fn new(
        family: ProtectorFamily,
        version_label: String,
        marker_offset: usize,
        confident: bool,
    ) -> Self {
        Self {
            family,
            version_label,
            marker_offset,
            confident,
            payload_offset: None,
            payload_len: 0,
            recovered_strings: Vec::new(),
            wall_reason: family.wall_reason(),
            container_parsed: false,
            static_layers_stripped: Vec::new(),
            opcode_stream_len: 0,
            source_reconstructed: false,
            recovered_source: None,
            decompilation: None,
        }
    }

    pub fn apply_static_recovery(&mut self, bytes: &[u8]) {
        let surface: Result<ContainerSurface> = match self.family {
            ProtectorFamily::IonCube => reverse_ioncube_container(bytes, self.marker_offset),
            ProtectorFamily::SourceGuardian => reverse_sourceguardian_container(bytes),
            ProtectorFamily::ZendGuard => surface_zend_guard(bytes),
        };
        let Ok(surface): Result<ContainerSurface> = surface else {
            return;
        };
        self.container_parsed = surface.container_parsed;
        self.static_layers_stripped = surface
            .static_layers_stripped
            .iter()
            .map(|l: &crate::encoder::StaticLayer| l.label().to_owned())
            .collect();
        self.opcode_stream_len = surface.opcode_stream_len;
        if let Some(decomp) = lift_op_array(&surface.stripped_payload) {
            self.source_reconstructed = true;
            self.recovered_source = Some(decomp.php_skeleton.clone());
            self.decompilation = Some(decomp);
        }
    }
}

fn lift_op_array(payload: &[u8]) -> Option<Decompilation> {
    if payload.len() < 5 || &payload[..4] != OPARRAY_MAGIC {
        return None;
    }
    let parsed: OpArray = parse_oparray(payload).ok()?;
    Some(decompile(&parsed))
}

#[must_use]
pub fn family_to_encoder(family: ProtectorFamily) -> EncoderFamily {
    match family {
        ProtectorFamily::IonCube => EncoderFamily::IonCube,
        ProtectorFamily::SourceGuardian => EncoderFamily::SourceGuardian,
        ProtectorFamily::ZendGuard => EncoderFamily::ZendGuard,
    }
}

pub fn extract_envelope_strings(plaintext: &[u8], min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let flush = |buf: &mut Vec<u8>, out: &mut Vec<String>| {
        if buf.len() >= min_len
            && let Ok(s) = std::str::from_utf8(buf)
        {
            out.push(s.to_string());
        }
        buf.clear();
    };
    for &b in plaintext {
        if (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\t' {
            buf.push(b);
        } else {
            flush(&mut buf, &mut out);
        }
    }
    flush(&mut buf, &mut out);
    out
}
