use crate::detect::PyarmorVersion;
use crate::error::Result;
use crate::key::{RuntimeKeyMaterial, extract_runtime_key};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeArch {
    WinX64,
    LinuxX64,
    DarwinArm64,
    LinuxArm64,
    Unknown,
}

impl RuntimeArch {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WinX64 => "win-x64",
            Self::LinuxX64 => "linux-x64",
            Self::DarwinArm64 => "darwin-arm64",
            Self::LinuxArm64 => "linux-arm64",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone)]
pub struct RuntimeInfoSummary {
    pub serial: String,
    pub aes_key: [u8; 16],
    pub mix_str_nonce: [u8; 12],
    pub arch: RuntimeArch,
    pub embedded_data_offset: Option<usize>,
    pub size_hint: usize,
    pub descriptor_version: Option<PyarmorVersion>,
}

impl core::fmt::Debug for RuntimeInfoSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RuntimeInfoSummary")
            .field("serial", &self.serial)
            .field("aes_key", &"[redacted; 16]")
            .field("mix_str_nonce", &"[redacted; 12]")
            .field("arch", &self.arch.label())
            .field("embedded_data_offset", &self.embedded_data_offset)
            .field("size_hint", &self.size_hint)
            .field("descriptor_version", &self.descriptor_version)
            .finish()
    }
}

pub fn load_runtime_info(runtime_bytes: &[u8]) -> Result<RuntimeInfoSummary> {
    let material: RuntimeKeyMaterial = extract_runtime_key(runtime_bytes)?;
    let arch: RuntimeArch = sniff_arch(runtime_bytes);
    let embedded_data_offset: Option<usize> = locate_pyarmor_vax(runtime_bytes);
    let descriptor_version: Option<PyarmorVersion> = match material.runtime_descriptor {
        Some(1u32) => Some(PyarmorVersion::V8),
        Some(3u32) => Some(PyarmorVersion::V9),
        _ => None,
    };
    Ok(RuntimeInfoSummary {
        serial: material.serial,
        aes_key: material.aes_key,
        mix_str_nonce: material.mix_str_nonce,
        arch,
        embedded_data_offset,
        size_hint: runtime_bytes.len(),
        descriptor_version,
    })
}

fn locate_pyarmor_vax(bytes: &[u8]) -> Option<usize> {
    bytes.windows(11).position(|w: &[u8]| w == b"pyarmor-vax")
}

fn sniff_arch(bytes: &[u8]) -> RuntimeArch {
    if bytes.len() >= 4 && bytes.starts_with(&[0x7fu8, b'E', b'L', b'F']) {
        if bytes.len() >= 19 {
            return match (bytes[4], bytes[18]) {
                (2u8, 0x3eu8) => RuntimeArch::LinuxX64,
                (2u8, 0xb7u8) => RuntimeArch::LinuxArm64,
                _ => RuntimeArch::Unknown,
            };
        }
        return RuntimeArch::Unknown;
    }
    if bytes.starts_with(b"MZ") {
        return RuntimeArch::WinX64;
    }
    if bytes.starts_with(&[0xcfu8, 0xfau8, 0xedu8, 0xfeu8])
        || bytes.starts_with(&[0xfeu8, 0xedu8, 0xfau8, 0xcfu8])
    {
        return RuntimeArch::DarwinArm64;
    }
    RuntimeArch::Unknown
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn arch_sniff_elf_amd64() {
        let mut bytes: Vec<u8> = vec![0u8; 32];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[18] = 0x3e;
        assert_eq!(sniff_arch(&bytes), RuntimeArch::LinuxX64);
    }

    #[test]
    fn arch_sniff_elf_aarch64() {
        let mut bytes: Vec<u8> = vec![0u8; 32];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[18] = 0xb7;
        assert_eq!(sniff_arch(&bytes), RuntimeArch::LinuxArm64);
    }

    #[test]
    fn arch_sniff_pe() {
        let bytes: Vec<u8> = b"MZ\x00\x00".to_vec();
        assert_eq!(sniff_arch(&bytes), RuntimeArch::WinX64);
    }

    #[test]
    fn arch_sniff_macho() {
        let bytes: Vec<u8> = vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0];
        assert_eq!(sniff_arch(&bytes), RuntimeArch::DarwinArm64);
    }

    #[test]
    fn locate_vax_finds_anchor() {
        let mut bytes: Vec<u8> = vec![0u8; 256];
        bytes[100..111].copy_from_slice(b"pyarmor-vax");
        assert_eq!(locate_pyarmor_vax(&bytes), Some(100));
    }
}
