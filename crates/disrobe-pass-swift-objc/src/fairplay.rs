use serde::{Deserialize, Serialize};

use crate::macho::{self, EncryptedRegion, EncryptionInfo, ParsedSlice, Section, Segment};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairPlayStatus {
    pub has_encryption_info_lc: bool,
    pub crypt_id: u32,
    pub crypt_off: u32,
    pub crypt_size: u32,
    pub is_encrypted: bool,
    pub method: String,
    pub residual_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedTextNotice {
    pub crypt_id: u32,
    pub file_off: u64,
    pub file_end: u64,
    pub withheld_sections: Vec<String>,
    pub statement: String,
}

#[must_use]
pub fn encrypted_text_notice(parsed: &ParsedSlice) -> Option<EncryptedTextNotice> {
    let region: EncryptedRegion = macho::encrypted_region(parsed)?;
    let withheld_sections: Vec<String> = parsed
        .segments
        .iter()
        .flat_map(|segment: &Segment| segment.sections.iter())
        .filter(|section: &&Section| macho::section_is_encrypted_at_rest(parsed, section))
        .map(|section: &Section| format!("{}/{}", section.seg, section.name))
        .collect();
    Some(EncryptedTextNotice {
        crypt_id: region.crypt_id,
        file_off: region.file_off,
        file_end: region.end(),
        withheld_sections,
        statement: format!(
            "LC_ENCRYPTION_INFO[_64] declares cryptid {}, so file bytes {}..{} are encrypted at \
             rest. The key is wrapped to the device and is absent from this file, so nothing in \
             that range is recoverable from these bytes and no text read out of it is reported.",
            region.crypt_id,
            region.file_off,
            region.end()
        ),
    })
}

#[must_use]
pub fn detect(parsed: &ParsedSlice) -> FairPlayStatus {
    let Some(info): Option<&EncryptionInfo> = parsed.encryption.as_ref() else {
        return FairPlayStatus {
            has_encryption_info_lc: false,
            crypt_id: 0,
            crypt_off: 0,
            crypt_size: 0,
            is_encrypted: false,
            method: "no LC_ENCRYPTION_INFO[_64] load command present".to_owned(),
            residual_note: None,
        };
    };
    let EncryptionInfo {
        crypt_off,
        crypt_size,
        crypt_id,
    }: EncryptionInfo = *info;
    let is_encrypted: bool = crypt_id != 0;
    FairPlayStatus {
        has_encryption_info_lc: true,
        crypt_id,
        crypt_off,
        crypt_size,
        is_encrypted,
        method: "LC_ENCRYPTION_INFO[_64].cryptid > 0 indicates FairPlay-encrypted region"
            .to_owned(),
        residual_note: is_encrypted.then(|| {
            "FairPlay: the __TEXT region key is wrapped to the device hardware / Apple-ID key and unwrapped only in the secure enclave at load; neither the key nor the decrypted cleartext is present in the IPA".to_owned()
        }),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::macho::{Bitness, CpuKind, Endian, SliceHeader};

    fn empty_parsed(encryption: Option<EncryptionInfo>) -> ParsedSlice {
        ParsedSlice {
            header: SliceHeader {
                cpu: CpuKind::Arm64,
                bitness: Bitness::Bits64,
                endian: Endian::Little,
                ncmds: 0,
                sizeofcmds: 0,
                filetype: 0,
                flags: 0,
            },
            encryption,
            ..ParsedSlice::default()
        }
    }

    #[test]
    fn no_lc_means_not_encrypted() {
        let parsed: ParsedSlice = empty_parsed(None);
        let status: FairPlayStatus = detect(&parsed);
        assert!(!status.has_encryption_info_lc);
        assert!(!status.is_encrypted);
    }

    #[test]
    fn cryptid_one_is_encrypted() {
        let parsed: ParsedSlice = empty_parsed(Some(EncryptionInfo {
            crypt_off: 0x4000,
            crypt_size: 0x1000,
            crypt_id: 1,
        }));
        let status: FairPlayStatus = detect(&parsed);
        assert!(status.has_encryption_info_lc);
        assert!(status.is_encrypted);
        assert_eq!(status.crypt_id, 1);
    }

    #[test]
    fn cryptid_zero_is_not_encrypted() {
        let parsed: ParsedSlice = empty_parsed(Some(EncryptionInfo {
            crypt_off: 0,
            crypt_size: 0,
            crypt_id: 0,
        }));
        let status: FairPlayStatus = detect(&parsed);
        assert!(status.has_encryption_info_lc);
        assert!(!status.is_encrypted);
    }
}
