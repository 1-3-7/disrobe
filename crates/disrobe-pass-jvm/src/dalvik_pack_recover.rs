use serde::{Deserialize, Serialize};

use crate::dex::{self, DEX_MAGIC_PREFIX, DexFile, DexHeader};
use crate::jar::{self, JarEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackingSchemeKind {
    StubLoaderKeystream,
}

impl PackingSchemeKind {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::StubLoaderKeystream => {
                "minimal stub-loader Application class plus a length-and-checksum-framed \
                 encrypted payload asset"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationSignals {
    pub magic_valid: bool,
    pub header_self_consistent: bool,
    pub embedded_checksum_matched: bool,
    pub embedded_signature_matched: bool,
    pub structural_parser_accepted: bool,
    pub existing_parser_succeeded: bool,
    #[serde(default)]
    pub code_items_fully_decoded: bool,
    pub sample_bytecode_decoded: bool,
    pub class_count: usize,
    pub method_count: usize,
    pub string_count: usize,
}

impl VerificationSignals {
    #[must_use]
    pub const fn all_required_signals_pass(&self) -> bool {
        self.magic_valid
            && self.header_self_consistent
            && self.embedded_checksum_matched
            && self.embedded_signature_matched
            && self.structural_parser_accepted
            && self.existing_parser_succeeded
            && self.code_items_fully_decoded
            && self.class_count > 0
    }

    #[must_use]
    pub fn failing_signal_names(&self) -> Vec<&'static str> {
        let mut failed: Vec<&'static str> = Vec::new();
        if !self.magic_valid {
            failed.push("magic_valid");
        }
        if !self.header_self_consistent {
            failed.push("header_self_consistent");
        }
        if !self.embedded_checksum_matched {
            failed.push("embedded_checksum_matched");
        }
        if !self.embedded_signature_matched {
            failed.push("embedded_signature_matched");
        }
        if !self.structural_parser_accepted {
            failed.push("structural_parser_accepted");
        }
        if !self.existing_parser_succeeded {
            failed.push("existing_parser_succeeded");
        }
        if !self.code_items_fully_decoded {
            failed.push("code_items_fully_decoded");
        }
        if self.class_count == 0 {
            failed.push("class_count");
        }
        failed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryOutcome {
    Recovered {
        dex_bytes: Vec<u8>,
        verification: VerificationSignals,
    },
    Indeterminate(String),
    Rejected(String),
}

pub trait PackingScheme {
    fn kind(&self) -> PackingSchemeKind;
    fn fingerprint(&self, entries: &[JarEntry]) -> u8;
    fn locate(&self, entries: &[JarEntry]) -> Option<LocatedPayload>;
    fn recover(&self, located: &LocatedPayload) -> RecoveryOutcome;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatedPayload {
    pub container_path: String,
    pub key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub keystream_seed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeCandidate {
    pub kind: PackingSchemeKind,
    pub confidence: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRecoveryReport {
    pub candidates: Vec<SchemeCandidate>,
    pub selected: Option<PackingSchemeKind>,
    pub outcome: Option<RecoveryOutcome>,
}

fn registered_schemes() -> Vec<Box<dyn PackingScheme + Send + Sync>> {
    vec![Box::new(
        crate::dalvik_pack_stub_loader::StubLoaderKeystreamScheme,
    )]
}

#[must_use]
pub fn recover_packed_dex(apk_bytes: &[u8]) -> PackageRecoveryReport {
    let mut report: PackageRecoveryReport = PackageRecoveryReport::default();
    let Ok(extract): Result<jar::JarExtract, _> = jar::extract(apk_bytes) else {
        return report;
    };
    let schemes: Vec<Box<dyn PackingScheme + Send + Sync>> = registered_schemes();
    let mut best_idx: Option<usize> = None;
    for (idx, scheme) in schemes.iter().enumerate() {
        let confidence: u8 = scheme.fingerprint(&extract.entries);
        report.candidates.push(SchemeCandidate {
            kind: scheme.kind(),
            confidence,
        });
        let is_new_best: bool = match best_idx {
            Some(current) => confidence > report.candidates[current].confidence,
            None => confidence > 0,
        };
        if is_new_best {
            best_idx = Some(idx);
        }
    }
    let Some(idx): Option<usize> = best_idx else {
        return report;
    };
    let scheme: &(dyn PackingScheme + Send + Sync) = schemes[idx].as_ref();
    report.selected = Some(scheme.kind());
    let Some(located): Option<LocatedPayload> = scheme.locate(&extract.entries) else {
        return report;
    };
    report.outcome = Some(scheme.recover(&located));
    report
}

fn dex_header_self_consistent(header: &DexHeader, buffer_len: usize) -> bool {
    if header.header_size != 0x70 || header.endian_tag != dex::DEX_ENDIAN_TAG {
        return false;
    }
    if header.file_size as usize != buffer_len {
        return false;
    }
    let sections: [(u32, u32, usize); 6] = [
        (header.string_ids_off, header.string_ids_size, 4),
        (header.type_ids_off, header.type_ids_size, 4),
        (header.proto_ids_off, header.proto_ids_size, 12),
        (header.field_ids_off, header.field_ids_size, 8),
        (header.method_ids_off, header.method_ids_size, 8),
        (header.class_defs_off, header.class_defs_size, 32),
    ];
    for (off, size, stride) in sections {
        if size == 0 {
            continue;
        }
        if (off as usize) < 0x70 {
            return false;
        }
        let Some(span): Option<usize> = (size as usize).checked_mul(stride) else {
            return false;
        };
        let Some(end): Option<usize> = (off as usize).checked_add(span) else {
            return false;
        };
        if end > buffer_len {
            return false;
        }
    }
    if header.data_size > 0 {
        let Some(data_end): Option<usize> =
            (header.data_off as usize).checked_add(header.data_size as usize)
        else {
            return false;
        };
        if data_end > buffer_len {
            return false;
        }
    }
    true
}

#[must_use]
pub fn verify_recovered_dex(bytes: &[u8]) -> VerificationSignals {
    let magic_valid: bool = bytes.len() >= 8 && bytes[..4] == DEX_MAGIC_PREFIX && bytes[7] == 0;
    let structural_parser_accepted: bool = disrobe_binfmt::structural::validate_dex(bytes);
    let parsed_header: Option<DexHeader> = dex::parse_header(bytes).ok();
    let header_self_consistent: bool = parsed_header
        .as_ref()
        .is_some_and(|h: &DexHeader| dex_header_self_consistent(h, bytes.len()));
    let embedded_checksum_matched: bool = parsed_header.as_ref().is_some_and(|h: &DexHeader| {
        bytes.len() > 12 && crate::dex_builder::adler32(&bytes[12..]) == h.checksum
    });
    let embedded_signature_matched: bool = parsed_header.as_ref().is_some_and(|h: &DexHeader| {
        bytes.len() > 32 && crate::dex_builder::sha1(&bytes[32..]) == h.signature
    });
    let parsed: Option<DexFile> = dex::parse(bytes).ok();
    let existing_parser_succeeded: bool = parsed.is_some();
    let (class_count, method_count, string_count): (usize, usize, usize) =
        parsed.as_ref().map_or((0, 0, 0), |d: &DexFile| {
            (
                d.class_descriptors.len(),
                d.method_ids.len(),
                d.strings.len(),
            )
        });
    let (code_items_fully_decoded, sample_bytecode_decoded): (bool, bool) =
        parsed.as_ref().map_or((false, false), |d: &DexFile| {
            let code_report: dex::CodeItemsReport = dex::parse_code_items(d, bytes);
            let complete: bool = code_report.is_fully_decoded();
            let sample: bool = code_report.decoded().iter().any(|item: &dex::CodeItem| {
                !item.insns.is_empty() && !crate::dalvik::disassemble_units(&item.insns).is_empty()
            });
            (complete, sample)
        });
    VerificationSignals {
        magic_valid,
        header_self_consistent,
        embedded_checksum_matched,
        embedded_signature_matched,
        structural_parser_accepted,
        existing_parser_succeeded,
        code_items_fully_decoded,
        sample_bytecode_decoded,
        class_count,
        method_count,
        string_count,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};

    #[test]
    fn empty_input_yields_no_candidates() {
        let report: PackageRecoveryReport = recover_packed_dex(b"not a zip");
        assert!(report.candidates.is_empty());
        assert!(report.selected.is_none());
        assert!(report.outcome.is_none());
    }

    #[test]
    fn verification_rejects_truncated_garbage() {
        let signals: VerificationSignals = verify_recovered_dex(b"dex\n035\0garbage");
        assert!(!signals.all_required_signals_pass());
        assert!(!signals.failing_signal_names().is_empty());
    }

    #[test]
    fn verification_rejects_a_structurally_valid_dex_with_malformed_bytecode() {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Invalid;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "Lcom/disrobe/Invalid;".to_owned(),
                    proto: ProtoRef {
                        return_type: "V".to_owned(),
                        params: Vec::new(),
                    },
                    name: "body".to_owned(),
                },
                access_flags: 0x0001,
                is_direct: false,
                registers_size: 1,
                ins_size: 0,
                outs_size: 0,
                insns: vec![0x0014],
                relocations: Vec::new(),
            }],
        });
        let bytes: Vec<u8> = builder.build();
        let signals: VerificationSignals = verify_recovered_dex(&bytes);

        assert!(signals.magic_valid);
        assert!(signals.header_self_consistent);
        assert!(signals.embedded_checksum_matched);
        assert!(signals.embedded_signature_matched);
        assert!(signals.structural_parser_accepted);
        assert!(signals.existing_parser_succeeded);
        assert!(!signals.all_required_signals_pass());
    }
}
