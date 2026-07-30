#![allow(clippy::doc_markdown)]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::metadata::{MetadataRoot, StreamHeader, parse_metadata_root};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::tables::{MethodDefRow, Tables, parse_tables};

pub const MAXTOCODE_SECTION_NAMES: &[&str] = &[".mtc", ".maxtc", ".text1"];

pub const MAX_SECTION_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaxToCodeRecovery {
    pub zero_rva_methods: u32,
    pub method_total: u32,
    pub protected_method_rids: Vec<u32>,
    pub encrypted_section_located: bool,
    pub section_name: Option<String>,
    pub section_rva: Option<u32>,
    pub section_size: Option<u32>,
    pub section_sha256: Option<[u8; 32]>,
    pub bodies_recovered: u32,
    pub bodies_total: u32,
    pub recovered_bodies: Vec<RecoveredBody>,
    pub key_origin: MaxKeyOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredBody {
    pub method_rid: u32,
    pub il: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaxKeyOrigin {
    None,
    NativeStubWall,
}

impl MaxToCodeRecovery {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            zero_rva_methods: 0,
            method_total: 0,
            protected_method_rids: Vec::new(),
            encrypted_section_located: false,
            section_name: None,
            section_rva: None,
            section_size: None,
            section_sha256: None,
            bodies_recovered: 0,
            bodies_total: 0,
            recovered_bodies: Vec::new(),
            key_origin: MaxKeyOrigin::None,
        }
    }

    #[must_use]
    pub const fn recovery_ratio(&self) -> Option<(u32, u32)> {
        if self.bodies_total == 0 {
            None
        } else {
            Some((self.bodies_recovered, self.bodies_total))
        }
    }
}

pub fn recover_maxtocode_bodies(image: &[u8]) -> Result<MaxToCodeRecovery> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] = crate::metadata::metadata_slice(image, &pe, &clr, &root)?;
    let table_header: &StreamHeader =
        match root.streams.get("#~").or_else(|| root.streams.get("#-")) {
            Some(h) => h,
            None => return Ok(MaxToCodeRecovery::empty()),
        };
    let tables: Tables = parse_tables(metadata_slice, *table_header)?;

    let mut recovery: MaxToCodeRecovery = MaxToCodeRecovery::empty();
    classify_methods(&tables.methods, &mut recovery);

    let section: Option<EncryptedSection> = locate_encrypted_section(image, &pe);
    if let Some(section) = section {
        recovery.encrypted_section_located = true;
        recovery.section_rva = Some(section.rva);
        recovery.section_size = Some(section.size_u32());
        recovery.section_sha256 = Some(sha256(&section.bytes));
        recovery.section_name = Some(section.name);
    }

    recovery.bodies_total = recovery.zero_rva_methods;
    if recovery.bodies_total == 0 {
        recovery.key_origin = MaxKeyOrigin::None;
        return Ok(recovery);
    }

    recovery.key_origin = MaxKeyOrigin::NativeStubWall;
    Ok(recovery)
}

fn classify_methods(methods: &[MethodDefRow], recovery: &mut MaxToCodeRecovery) {
    for (index, method) in methods.iter().enumerate() {
        recovery.method_total = recovery.method_total.saturating_add(1);
        let is_managed_il: bool = method.impl_flags.trailing_zeros() >= 2;
        if method.rva == 0 && is_managed_il {
            recovery.zero_rva_methods = recovery.zero_rva_methods.saturating_add(1);
            let rid: u32 = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
            recovery.protected_method_rids.push(rid);
        }
    }
}

#[derive(Debug, Clone)]
struct EncryptedSection {
    name: String,
    rva: u32,
    bytes: Vec<u8>,
}

impl EncryptedSection {
    fn size_u32(&self) -> u32 {
        u32::try_from(self.bytes.len()).unwrap_or(u32::MAX)
    }
}

fn locate_encrypted_section(image: &[u8], pe: &PeImage) -> Option<EncryptedSection> {
    for section in &pe.sections {
        let name: &str = section.name.trim_end_matches('\0');
        if !MAXTOCODE_SECTION_NAMES.contains(&name) {
            continue;
        }
        let size: usize =
            (section.virtual_size.max(section.raw_size) as usize).min(MAX_SECTION_BYTES);
        if size == 0 {
            continue;
        }
        let off: usize = pe.rva_to_offset(section.virtual_address)?;
        let end: usize = off.checked_add(size)?.min(image.len());
        if end <= off {
            continue;
        }
        return Some(EncryptedSection {
            name: name.to_string(),
            rva: section.virtual_address,
            bytes: image[off..end].to_vec(),
        });
    }
    None
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    let digest: sha2::digest::generic_array::GenericArray<u8, _> = hasher.finalize();
    let mut out: [u8; 32] = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn empty_recovery_defaults() {
        let r: MaxToCodeRecovery = MaxToCodeRecovery::empty();
        assert_eq!(r.bodies_recovered, 0);
        assert_eq!(r.key_origin, MaxKeyOrigin::None);
        assert!(!r.encrypted_section_located);
        assert_eq!(r.recovery_ratio(), None);
    }

    #[test]
    fn recover_on_clean_baseline_finds_no_encrypted_section() {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let bytes: Vec<u8> = std::fs::read(&path).expect("fixture");
        let r: MaxToCodeRecovery = recover_maxtocode_bodies(&bytes).expect("scan");
        assert!(!r.encrypted_section_located);
        assert_eq!(r.bodies_recovered, 0);
    }
}
