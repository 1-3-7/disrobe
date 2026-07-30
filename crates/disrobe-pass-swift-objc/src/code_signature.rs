use disrobe_bytes::{read_bytes_at, read_u8_at, read_u32_be_at, read_u64_be_at};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::macho::ParsedSlice;

pub const CSMAGIC_REQUIREMENT: u32 = 0xFADE_0C00;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xFADE_0C01;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE_0C02;
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xFADE_0CC1;
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xFADE_0B01;
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xFADE_7171;
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xFADE_7172;

const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_INFOSLOT: u32 = 1;
const CSSLOT_REQUIREMENTS: u32 = 2;
const CSSLOT_RESOURCEDIR: u32 = 3;
const CSSLOT_APPLICATION: u32 = 4;
const CSSLOT_ENTITLEMENTS: u32 = 5;
const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
const CSSLOT_LAUNCH_CONSTRAINT_SELF: u32 = 8;
const CSSLOT_LAUNCH_CONSTRAINT_PARENT: u32 = 9;
const CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE: u32 = 10;
const CSSLOT_LIBRARY_CONSTRAINT: u32 = 11;
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT: u32 = 0x1005;
const CSSLOT_SIGNATURESLOT: u32 = 0x1_0000;

const CS_ADHOC: u32 = 0x0000_0002;
const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
const CS_INSTALLER: u32 = 0x0000_0008;
const CS_FORCED_LV: u32 = 0x0000_0010;
const CS_INVALID_ALLOWED: u32 = 0x0000_0020;
const CS_HARD: u32 = 0x0000_0100;
const CS_KILL: u32 = 0x0000_0200;
const CS_CHECK_EXPIRATION: u32 = 0x0000_0400;
const CS_RESTRICT: u32 = 0x0000_0800;
const CS_ENFORCEMENT: u32 = 0x0000_1000;
const CS_REQUIRE_LV: u32 = 0x0000_2000;
const CS_ENTITLEMENTS_VALIDATED: u32 = 0x0000_4000;
const CS_NVRAM_UNRESTRICTED: u32 = 0x0000_8000;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_LINKER_SIGNED: u32 = 0x0002_0000;

const CD_SUPPORTS_TEAM_ID: u32 = 0x0002_0200;
const CD_SUPPORTS_CODE_LIMIT_64: u32 = 0x0002_0300;
const CD_SUPPORTS_EXEC_SEG: u32 = 0x0002_0400;

const CD_TEAM_OFFSET_FIELD: usize = 48;
const CD_CODE_LIMIT_64_FIELD: usize = 56;
const CD_EXEC_SEG_BASE_FIELD: usize = 64;
const CD_HEADER_MIN: usize = 44;

const MAX_SLOT_COUNT: usize = 1024;
const MAX_BLOB_LEN: u32 = 64 * 1024 * 1024;
const MAX_IDENTIFIER_LEN: usize = 1024;
const MAX_VERIFIED_PAGES: u32 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotKind {
    CodeDirectory,
    InfoPlist,
    Requirements,
    ResourceDirectory,
    Application,
    Entitlements,
    DerEntitlements,
    LaunchConstraintSelf,
    LaunchConstraintParent,
    LaunchConstraintResponsible,
    LibraryConstraint,
    AlternateCodeDirectory,
    CmsSignature,
    Unknown,
}

impl SlotKind {
    #[must_use]
    pub const fn from_slot_type(raw: u32) -> Self {
        match raw {
            CSSLOT_CODEDIRECTORY => Self::CodeDirectory,
            CSSLOT_INFOSLOT => Self::InfoPlist,
            CSSLOT_REQUIREMENTS => Self::Requirements,
            CSSLOT_RESOURCEDIR => Self::ResourceDirectory,
            CSSLOT_APPLICATION => Self::Application,
            CSSLOT_ENTITLEMENTS => Self::Entitlements,
            CSSLOT_DER_ENTITLEMENTS => Self::DerEntitlements,
            CSSLOT_LAUNCH_CONSTRAINT_SELF => Self::LaunchConstraintSelf,
            CSSLOT_LAUNCH_CONSTRAINT_PARENT => Self::LaunchConstraintParent,
            CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE => Self::LaunchConstraintResponsible,
            CSSLOT_LIBRARY_CONSTRAINT => Self::LibraryConstraint,
            CSSLOT_SIGNATURESLOT => Self::CmsSignature,
            other
                if other >= CSSLOT_ALTERNATE_CODEDIRECTORIES
                    && other < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT =>
            {
                Self::AlternateCodeDirectory
            }
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CodeDirectory => "code-directory",
            Self::InfoPlist => "info-plist-hash",
            Self::Requirements => "requirements",
            Self::ResourceDirectory => "resource-directory-hash",
            Self::Application => "application",
            Self::Entitlements => "entitlements",
            Self::DerEntitlements => "der-entitlements",
            Self::LaunchConstraintSelf => "launch-constraint-self",
            Self::LaunchConstraintParent => "launch-constraint-parent",
            Self::LaunchConstraintResponsible => "launch-constraint-responsible",
            Self::LibraryConstraint => "library-constraint",
            Self::AlternateCodeDirectory => "alternate-code-directory",
            Self::CmsSignature => "cms-signature",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashKind {
    Sha1,
    Sha256,
    Sha256Truncated,
    Sha384,
    Sha512,
    Unknown(u8),
}

impl HashKind {
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Sha1,
            2 => Self::Sha256,
            3 => Self::Sha256Truncated,
            4 => Self::Sha384,
            5 => Self::Sha512,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha256Truncated => "sha256-truncated",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Unknown(_) => "unknown",
        }
    }
}

fn digest_bytes(kind: HashKind, data: &[u8]) -> Option<Vec<u8>> {
    match kind {
        HashKind::Sha1 => Some(Sha1::digest(data).to_vec()),
        HashKind::Sha256 | HashKind::Sha256Truncated => Some(Sha256::digest(data).to_vec()),
        HashKind::Sha384 => Some(Sha384::digest(data).to_vec()),
        HashKind::Sha512 => Some(Sha512::digest(data).to_vec()),
        HashKind::Unknown(_) => None,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _: core::result::Result<(), core::fmt::Error> = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobSlot {
    pub slot_type: u32,
    pub kind: SlotKind,
    pub offset: u32,
    pub magic: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeDirectory {
    pub version: u32,
    pub flags: u32,
    pub flag_names: Vec<String>,
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub hash_kind: HashKind,
    pub hash_size: u8,
    pub page_size_log2: u8,
    pub page_size: u32,
    pub special_slot_count: u32,
    pub code_slot_count: u32,
    pub code_limit: u64,
    pub platform: u8,
    pub exec_segment_base: Option<u64>,
    pub exec_segment_limit: Option<u64>,
    pub exec_segment_flags: Option<u64>,
    pub cd_hash: Option<String>,
    pub cd_hash_truncated: Option<String>,
    pub is_adhoc: bool,
    pub is_linker_signed: bool,
    pub is_hardened_runtime: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PageHashVerdict {
    AllPagesMatch,
    Mismatch,
    NotAttempted,
}

impl PageHashVerdict {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AllPagesMatch => "all-pages-match",
            Self::Mismatch => "mismatch",
            Self::NotAttempted => "not-attempted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageHashAudit {
    pub verdict: PageHashVerdict,
    pub pages_declared: u32,
    pub pages_checked: u32,
    pub pages_matched: u32,
    pub first_mismatch_page: Option<u32>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureCoverage {
    pub code_limit: u64,
    pub signature_offset: u64,
    pub slice_len: u64,
    pub covers_all_bytes_before_signature: bool,
    pub unsigned_gap_bytes: u64,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSignature {
    pub superblob_magic: u32,
    pub superblob_length: u32,
    pub slot_count: usize,
    pub slots: Vec<BlobSlot>,
    pub code_directory: Option<CodeDirectory>,
    pub alternate_code_directories: Vec<CodeDirectory>,
    pub entitlements_xml: Option<String>,
    pub has_der_entitlements: bool,
    pub has_cms_signature: bool,
    pub cms_length: u32,
    pub is_adhoc_signed: bool,
    pub coverage: SignatureCoverage,
    pub page_hashes: PageHashAudit,
}

fn flag_names_for(flags: u32) -> Vec<String> {
    const TABLE: [(u32, &str); 16] = [
        (0x0000_0001, "valid"),
        (CS_ADHOC, "adhoc"),
        (CS_GET_TASK_ALLOW, "get-task-allow"),
        (CS_INSTALLER, "installer"),
        (CS_FORCED_LV, "forced-library-validation"),
        (CS_INVALID_ALLOWED, "invalid-allowed"),
        (CS_HARD, "hard"),
        (CS_KILL, "kill"),
        (CS_CHECK_EXPIRATION, "check-expiration"),
        (CS_RESTRICT, "restrict"),
        (CS_ENFORCEMENT, "enforcement"),
        (CS_REQUIRE_LV, "require-library-validation"),
        (CS_ENTITLEMENTS_VALIDATED, "entitlements-validated"),
        (CS_NVRAM_UNRESTRICTED, "nvram-unrestricted"),
        (CS_RUNTIME, "hardened-runtime"),
        (CS_LINKER_SIGNED, "linker-signed"),
    ];
    TABLE
        .iter()
        .filter(|(bit, _): &&(u32, &str)| flags & *bit != 0)
        .map(|(_, name): &(u32, &str)| (*name).to_owned())
        .collect()
}

fn read_cstr_bounded(blob: &[u8], start: usize) -> Option<String> {
    let cap: usize = start.checked_add(MAX_IDENTIFIER_LEN)?.min(blob.len());
    let window: &[u8] = blob.get(start..cap)?;
    let nul: usize = window.iter().position(|b: &u8| *b == 0)?;
    std::str::from_utf8(&window[..nul]).ok().map(str::to_owned)
}

fn parse_code_directory(blob: &[u8], base: usize, length: u32) -> Option<CodeDirectory> {
    let len_usize: usize = usize::try_from(length).ok()?;
    if len_usize < CD_HEADER_MIN {
        return None;
    }
    let body: &[u8] = blob.get(base..base.checked_add(len_usize)?)?;
    let version: u32 = read_u32_be_at(body, 8).ok()?;
    let flags: u32 = read_u32_be_at(body, 12).ok()?;
    let ident_offset: u32 = read_u32_be_at(body, 20).ok()?;
    let special_slot_count: u32 = read_u32_be_at(body, 24).ok()?;
    let code_slot_count: u32 = read_u32_be_at(body, 28).ok()?;
    let code_limit_32: u32 = read_u32_be_at(body, 32).ok()?;
    let hash_size: u8 = read_u8_at(body, 36).ok()?;
    let hash_type_raw: u8 = read_u8_at(body, 37).ok()?;
    let platform: u8 = read_u8_at(body, 38).ok()?;
    let page_size_log2: u8 = read_u8_at(body, 39).ok()?;

    let identifier: Option<String> = usize::try_from(ident_offset)
        .ok()
        .filter(|off: &usize| *off > 0)
        .and_then(|off: usize| read_cstr_bounded(body, off));
    let team_id: Option<String> = if version >= CD_SUPPORTS_TEAM_ID {
        read_u32_be_at(body, CD_TEAM_OFFSET_FIELD)
            .ok()
            .and_then(|raw: u32| usize::try_from(raw).ok())
            .filter(|off: &usize| *off > 0)
            .and_then(|off: usize| read_cstr_bounded(body, off))
    } else {
        None
    };
    let code_limit: u64 = if version >= CD_SUPPORTS_CODE_LIMIT_64 {
        let wide: u64 = read_u64_be_at(body, CD_CODE_LIMIT_64_FIELD).unwrap_or(0);
        if wide > 0 {
            wide
        } else {
            u64::from(code_limit_32)
        }
    } else {
        u64::from(code_limit_32)
    };
    let (exec_segment_base, exec_segment_limit, exec_segment_flags): (
        Option<u64>,
        Option<u64>,
        Option<u64>,
    ) = if version >= CD_SUPPORTS_EXEC_SEG {
        (
            read_u64_be_at(body, CD_EXEC_SEG_BASE_FIELD).ok(),
            read_u64_be_at(body, CD_EXEC_SEG_BASE_FIELD + 8).ok(),
            read_u64_be_at(body, CD_EXEC_SEG_BASE_FIELD + 16).ok(),
        )
    } else {
        (None, None, None)
    };

    let hash_kind: HashKind = HashKind::from_raw(hash_type_raw);
    let digest: Option<Vec<u8>> = digest_bytes(hash_kind, body);
    let cd_hash: Option<String> = digest.as_deref().map(to_hex);
    let cd_hash_truncated: Option<String> = digest
        .as_deref()
        .map(|full: &[u8]| to_hex(&full[..full.len().min(20)]));
    let page_size: u32 = if page_size_log2 == 0 {
        0
    } else {
        1u32.checked_shl(u32::from(page_size_log2)).unwrap_or(0)
    };

    Some(CodeDirectory {
        version,
        flags,
        flag_names: flag_names_for(flags),
        identifier,
        team_id,
        hash_kind,
        hash_size,
        page_size_log2,
        page_size,
        special_slot_count,
        code_slot_count,
        code_limit,
        platform,
        exec_segment_base,
        exec_segment_limit,
        exec_segment_flags,
        cd_hash,
        cd_hash_truncated,
        is_adhoc: flags & CS_ADHOC != 0,
        is_linker_signed: flags & CS_LINKER_SIGNED != 0,
        is_hardened_runtime: flags & CS_RUNTIME != 0,
    })
}

fn verify_page_hashes(
    slice: &[u8],
    blob: &[u8],
    cd_base: usize,
    directory: &CodeDirectory,
) -> PageHashAudit {
    let declared: u32 = directory.code_slot_count;
    let not_attempted = |note: &str| PageHashAudit {
        verdict: PageHashVerdict::NotAttempted,
        pages_declared: declared,
        pages_checked: 0,
        pages_matched: 0,
        first_mismatch_page: None,
        note: note.to_owned(),
    };
    if directory.hash_size == 0 || directory.page_size == 0 {
        return not_attempted("the directory declares no hash size or no page size");
    }
    if matches!(directory.hash_kind, HashKind::Unknown(_)) {
        return not_attempted("the directory names a hash algorithm this build does not compute");
    }
    let Ok(hash_offset): Result<u32, _> = read_u32_be_at(blob, cd_base + 16) else {
        return not_attempted("the directory hash-slot offset is not readable");
    };
    let Ok(hash_base): Result<usize, _> = usize::try_from(hash_offset) else {
        return not_attempted("the directory hash-slot offset is not addressable");
    };
    let hash_size: usize = usize::from(directory.hash_size);
    let checked_limit: u32 = declared.min(MAX_VERIFIED_PAGES);
    let mut matched: u32 = 0;
    let mut checked: u32 = 0;
    let mut first_mismatch: Option<u32> = None;
    for index in 0..checked_limit {
        let Some(slot_off): Option<usize> = usize::try_from(index)
            .ok()
            .and_then(|i: usize| i.checked_mul(hash_size))
            .and_then(|delta: usize| cd_base.checked_add(hash_base)?.checked_add(delta))
        else {
            break;
        };
        let Ok(expected): Result<&[u8], _> = read_bytes_at(blob, slot_off, hash_size) else {
            break;
        };
        let start: u64 = u64::from(index).saturating_mul(u64::from(directory.page_size));
        let end: u64 = start
            .saturating_add(u64::from(directory.page_size))
            .min(directory.code_limit);
        if start >= end {
            break;
        }
        let (Ok(start_usize), Ok(end_usize)): (Result<usize, _>, Result<usize, _>) =
            (usize::try_from(start), usize::try_from(end))
        else {
            break;
        };
        let Some(page): Option<&[u8]> = slice.get(start_usize..end_usize) else {
            break;
        };
        let Some(actual): Option<Vec<u8>> = digest_bytes(directory.hash_kind, page) else {
            break;
        };
        checked = checked.saturating_add(1);
        if actual.get(..hash_size) == Some(expected) {
            matched = matched.saturating_add(1);
        } else if first_mismatch.is_none() {
            first_mismatch = Some(index);
        }
    }
    if checked == 0 {
        return not_attempted("no code page was readable at the declared hash slots");
    }
    let truncated: bool = checked < declared;
    let verdict: PageHashVerdict = if matched == checked {
        PageHashVerdict::AllPagesMatch
    } else {
        PageHashVerdict::Mismatch
    };
    let note: String = match (verdict, truncated) {
        (PageHashVerdict::AllPagesMatch, false) => format!(
            "every one of the {checked} signed code pages hashes to the digest the directory records for it"
        ),
        (PageHashVerdict::AllPagesMatch, true) => format!(
            "the first {checked} of {declared} signed code pages hash to the digest the directory records for them; the remainder was not read because this build checks at most {MAX_VERIFIED_PAGES} pages"
        ),
        (PageHashVerdict::Mismatch, _) => format!(
            "{matched} of {checked} checked code pages hash to the digest the directory records for them, so the signed content does not match the file"
        ),
        (PageHashVerdict::NotAttempted, _) => "not attempted".to_owned(),
    };
    PageHashAudit {
        verdict,
        pages_declared: declared,
        pages_checked: checked,
        pages_matched: matched,
        first_mismatch_page: first_mismatch,
        note,
    }
}

fn coverage_for(code_limit: u64, signature_offset: u64, slice_len: u64) -> SignatureCoverage {
    let covers: bool = code_limit == signature_offset;
    let gap: u64 = signature_offset.saturating_sub(code_limit);
    let note: String = if covers {
        "the signed range ends exactly where the signature blob begins, so every byte of the image outside the signature is covered".to_owned()
    } else if code_limit > signature_offset {
        format!(
            "the directory claims to sign {code_limit} bytes but the signature blob starts at {signature_offset}, so the claimed range overlaps the signature itself"
        )
    } else {
        format!(
            "{gap} bytes between the end of the signed range at {code_limit} and the signature blob at {signature_offset} are not covered by the signature"
        )
    };
    SignatureCoverage {
        code_limit,
        signature_offset,
        slice_len,
        covers_all_bytes_before_signature: covers,
        unsigned_gap_bytes: gap,
        note,
    }
}

#[must_use]
pub fn parse(slice: &[u8], parsed: &ParsedSlice) -> Option<CodeSignature> {
    let sig_off: u32 = parsed.code_signature_off?;
    let sig_size: u32 = parsed.code_signature_size?;
    let base: usize = usize::try_from(sig_off).ok()?;
    let len: usize = usize::try_from(sig_size).ok()?;
    let blob: &[u8] = slice.get(base..base.checked_add(len)?)?;

    let superblob_magic: u32 = read_u32_be_at(blob, 0).ok()?;
    if superblob_magic != CSMAGIC_EMBEDDED_SIGNATURE
        && superblob_magic != CSMAGIC_DETACHED_SIGNATURE
    {
        return None;
    }
    let superblob_length: u32 = read_u32_be_at(blob, 4).ok()?;
    let raw_count: u32 = read_u32_be_at(blob, 8).ok()?;
    let count: usize = usize::try_from(raw_count).ok()?.min(MAX_SLOT_COUNT);

    let mut slots: Vec<BlobSlot> = Vec::with_capacity(count);
    let mut code_directory: Option<CodeDirectory> = None;
    let mut code_directory_base: Option<usize> = None;
    let mut alternate_code_directories: Vec<CodeDirectory> = Vec::new();
    let mut entitlements_xml: Option<String> = None;
    let mut has_der_entitlements: bool = false;
    let mut has_cms_signature: bool = false;
    let mut cms_length: u32 = 0;

    for index in 0..count {
        let entry_off: usize = 12usize.checked_add(index.checked_mul(8)?)?;
        let Ok(slot_type): Result<u32, _> = read_u32_be_at(blob, entry_off) else {
            break;
        };
        let Ok(offset): Result<u32, _> = read_u32_be_at(blob, entry_off + 4) else {
            break;
        };
        let Ok(blob_base): Result<usize, _> = usize::try_from(offset) else {
            break;
        };
        let Ok(magic): Result<u32, _> = read_u32_be_at(blob, blob_base) else {
            break;
        };
        let Ok(length): Result<u32, _> = read_u32_be_at(blob, blob_base + 4) else {
            break;
        };
        if length > MAX_BLOB_LEN {
            break;
        }
        let kind: SlotKind = SlotKind::from_slot_type(slot_type);
        slots.push(BlobSlot {
            slot_type,
            kind,
            offset,
            magic,
            length,
        });
        match (kind, magic) {
            (SlotKind::CodeDirectory, CSMAGIC_CODEDIRECTORY) => {
                if let Some(directory) = parse_code_directory(blob, blob_base, length) {
                    code_directory = Some(directory);
                    code_directory_base = Some(blob_base);
                }
            }
            (SlotKind::AlternateCodeDirectory, CSMAGIC_CODEDIRECTORY) => {
                if let Some(directory) = parse_code_directory(blob, blob_base, length) {
                    alternate_code_directories.push(directory);
                }
            }
            (SlotKind::Entitlements, CSMAGIC_EMBEDDED_ENTITLEMENTS) => {
                let payload_start: usize = blob_base.saturating_add(8);
                let payload_end: usize = blob_base.saturating_add(usize::try_from(length).ok()?);
                if let Some(body) = blob.get(payload_start..payload_end) {
                    entitlements_xml = Some(String::from_utf8_lossy(body).into_owned());
                }
            }
            (SlotKind::DerEntitlements, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS) => {
                has_der_entitlements = true;
            }
            (SlotKind::CmsSignature, CSMAGIC_BLOBWRAPPER) => {
                has_cms_signature = length > 8;
                cms_length = length.saturating_sub(8);
            }
            _ => {}
        }
    }

    let code_limit: u64 = code_directory
        .as_ref()
        .map_or(0, |directory: &CodeDirectory| directory.code_limit);
    let coverage: SignatureCoverage = coverage_for(
        code_limit,
        u64::from(sig_off),
        u64::try_from(slice.len()).unwrap_or(u64::MAX),
    );
    let page_hashes: PageHashAudit = match (code_directory.as_ref(), code_directory_base) {
        (Some(directory), Some(cd_base)) => verify_page_hashes(slice, blob, cd_base, directory),
        _ => PageHashAudit {
            verdict: PageHashVerdict::NotAttempted,
            pages_declared: 0,
            pages_checked: 0,
            pages_matched: 0,
            first_mismatch_page: None,
            note: "the signature carries no readable code directory".to_owned(),
        },
    };
    let is_adhoc_signed: bool = code_directory
        .as_ref()
        .is_some_and(|directory: &CodeDirectory| directory.is_adhoc);

    Some(CodeSignature {
        superblob_magic,
        superblob_length,
        slot_count: slots.len(),
        slots,
        code_directory,
        alternate_code_directories,
        entitlements_xml,
        has_der_entitlements,
        has_cms_signature,
        cms_length,
        is_adhoc_signed,
        coverage,
        page_hashes,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn slot_kind_maps_every_documented_slot() {
        assert_eq!(SlotKind::from_slot_type(0), SlotKind::CodeDirectory);
        assert_eq!(SlotKind::from_slot_type(5), SlotKind::Entitlements);
        assert_eq!(SlotKind::from_slot_type(7), SlotKind::DerEntitlements);
        assert_eq!(SlotKind::from_slot_type(0x1_0000), SlotKind::CmsSignature);
        assert_eq!(
            SlotKind::from_slot_type(0x1000),
            SlotKind::AlternateCodeDirectory
        );
        assert_eq!(SlotKind::from_slot_type(0x4242), SlotKind::Unknown);
    }

    #[test]
    fn flag_names_decode_adhoc_linker_signed() {
        let names: Vec<String> = flag_names_for(0x0002_0002);
        assert!(names.contains(&"adhoc".to_owned()), "got {names:?}");
        assert!(names.contains(&"linker-signed".to_owned()), "got {names:?}");
        assert_eq!(names.len(), 2, "no other flag is claimed: {names:?}");
    }

    #[test]
    fn coverage_flags_an_unsigned_gap() {
        let exact: SignatureCoverage = coverage_for(1000, 1000, 2000);
        assert!(exact.covers_all_bytes_before_signature);
        assert_eq!(exact.unsigned_gap_bytes, 0);

        let gapped: SignatureCoverage = coverage_for(900, 1000, 2000);
        assert!(!gapped.covers_all_bytes_before_signature);
        assert_eq!(gapped.unsigned_gap_bytes, 100);
        assert!(
            gapped.note.contains("not covered"),
            "an unsigned gap must say so: {}",
            gapped.note
        );
    }

    #[test]
    fn coverage_flags_a_range_overlapping_the_signature() {
        let overlapping: SignatureCoverage = coverage_for(1200, 1000, 2000);
        assert!(!overlapping.covers_all_bytes_before_signature);
        assert!(
            overlapping.note.contains("overlaps"),
            "an overlong claimed range must say so: {}",
            overlapping.note
        );
    }

    #[test]
    fn hash_kind_maps_documented_algorithms() {
        assert_eq!(HashKind::from_raw(1), HashKind::Sha1);
        assert_eq!(HashKind::from_raw(2), HashKind::Sha256);
        assert_eq!(HashKind::from_raw(4), HashKind::Sha384);
        assert_eq!(HashKind::from_raw(9), HashKind::Unknown(9));
        assert!(digest_bytes(HashKind::Unknown(9), b"x").is_none());
        assert_eq!(
            digest_bytes(HashKind::Sha256, b"").map(|d: Vec<u8>| d.len()),
            Some(32)
        );
    }

    #[test]
    fn parse_rejects_bytes_that_are_not_a_superblob() {
        let slice: Vec<u8> = vec![0u8; 64];
        let parsed: ParsedSlice = ParsedSlice {
            header: crate::macho::SliceHeader {
                cpu: crate::macho::CpuKind::Arm64,
                bitness: crate::macho::Bitness::Bits64,
                endian: crate::macho::Endian::Little,
                ncmds: 0,
                sizeofcmds: 0,
                filetype: 0,
                flags: 0,
            },
            segments: Vec::new(),
            load_commands: Vec::new(),
            encryption: None,
            code_signature_off: Some(0),
            code_signature_size: Some(64),
            symtab: None,
        };
        assert!(parse(&slice, &parsed).is_none());
    }
}
