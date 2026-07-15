use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DART_SNAPSHOT_MAGIC: u32 = 0xdcdc_f5f5;
pub const DART_3_12_2_SNAPSHOT_COMPATIBILITY_HASH: &str = "ace654289f5abc240509fc941453ebc5";
pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES: &str = "product no-code_comments no-dwarf_stack_traces_mode dedup_instructions no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers";
pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES: &str = "product no-code_comments dwarf_stack_traces_mode dedup_instructions no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers";
const FIXED_HEADER_SIZE: usize = 52;
const MAGIC_SIZE: i64 = 4;
const FEATURE_STRING_CAP: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(i64)]
pub enum SnapshotKind {
    FullAot = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotHeader {
    pub declared_length: usize,
    pub kind: SnapshotKind,
    pub snapshot_compatibility_hash: String,
    pub features: String,
    pub clustered_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportStatus {
    Supported,
    UnsupportedVersion,
    UnsupportedFeatures,
}

pub fn parse_snapshot_header(bytes: &[u8]) -> Result<SnapshotHeader> {
    if bytes.len() < FIXED_HEADER_SIZE {
        return Err(Error::InputTooSmall {
            actual: bytes.len(),
            minimum: FIXED_HEADER_SIZE,
        });
    }
    let magic_bytes: [u8; 4] = bytes[0..4].try_into().map_err(|_| Error::InputTooSmall {
        actual: bytes.len(),
        minimum: FIXED_HEADER_SIZE,
    })?;
    let magic: u32 = u32::from_le_bytes(magic_bytes);
    if magic != DART_SNAPSHOT_MAGIC {
        return Err(Error::InvalidMagic);
    }
    let length_bytes: [u8; 8] = bytes[4..12].try_into().map_err(|_| Error::InputTooSmall {
        actual: bytes.len(),
        minimum: FIXED_HEADER_SIZE,
    })?;
    let stored_length: i64 = i64::from_le_bytes(length_bytes);
    let declared_i64: i64 =
        stored_length
            .checked_add(MAGIC_SIZE)
            .ok_or(Error::InvalidDeclaredLength {
                value: stored_length,
            })?;
    let declared_length: usize =
        usize::try_from(declared_i64).map_err(|_| Error::InvalidDeclaredLength {
            value: stored_length,
        })?;
    if declared_length < FIXED_HEADER_SIZE || declared_length > bytes.len() {
        return Err(Error::DeclaredLengthOutOfBounds {
            declared: declared_length,
            available: bytes.len(),
        });
    }
    let kind_bytes: [u8; 8] = bytes[12..20].try_into().map_err(|_| Error::InputTooSmall {
        actual: bytes.len(),
        minimum: FIXED_HEADER_SIZE,
    })?;
    let kind_raw: i64 = i64::from_le_bytes(kind_bytes);
    let kind: SnapshotKind = match kind_raw {
        value if value == SnapshotKind::FullAot as i64 => SnapshotKind::FullAot,
        value => return Err(Error::UnsupportedSnapshotKind(value)),
    };
    let version_bytes: &[u8] = &bytes[20..FIXED_HEADER_SIZE];
    if version_bytes.len() != 32 || !version_bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::InvalidSnapshotCompatibilityHash);
    }
    let snapshot_compatibility_hash: String = std::str::from_utf8(version_bytes)
        .map_err(|_| Error::InvalidSnapshotCompatibilityHash)?
        .to_ascii_lowercase();
    let feature_limit: usize =
        declared_length.min(FIXED_HEADER_SIZE.checked_add(FEATURE_STRING_CAP).ok_or(
            Error::FeatureStringTooLong {
                limit: FEATURE_STRING_CAP,
            },
        )?);
    let feature_region: &[u8] = &bytes[FIXED_HEADER_SIZE..feature_limit];
    let terminator: usize = feature_region
        .iter()
        .position(|value: &u8| *value == 0)
        .ok_or_else(|| {
            if declared_length.saturating_sub(FIXED_HEADER_SIZE) > FEATURE_STRING_CAP {
                Error::FeatureStringTooLong {
                    limit: FEATURE_STRING_CAP,
                }
            } else {
                Error::UnterminatedFeatures
            }
        })?;
    let features: String = std::str::from_utf8(&feature_region[..terminator])
        .map_err(|_| Error::InvalidFeatures)?
        .to_owned();
    let clustered_offset: usize = FIXED_HEADER_SIZE
        .checked_add(terminator)
        .and_then(|value: usize| value.checked_add(1))
        .ok_or(Error::FeatureStringTooLong {
            limit: FEATURE_STRING_CAP,
        })?;
    Ok(SnapshotHeader {
        declared_length,
        kind,
        snapshot_compatibility_hash,
        features,
        clustered_offset,
    })
}

#[must_use]
pub fn support_status(header: &SnapshotHeader) -> SupportStatus {
    if !crate::layout::has_layout_compatibility_hash(&header.snapshot_compatibility_hash) {
        SupportStatus::UnsupportedVersion
    } else if crate::layout::layout_descriptor(
        &header.snapshot_compatibility_hash,
        &header.features,
    )
    .is_none()
    {
        SupportStatus::UnsupportedFeatures
    } else {
        SupportStatus::Supported
    }
}
