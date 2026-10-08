use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cil::MethodBody;
use crate::pe::PeImage;

pub const NEUTRALIZED_SUFFIX: &str = "neutralized";
const MAX_PATCHES: usize = 65_536;
const MAX_PATCH_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Technique {
    AntiTamper,
    AntiDebug,
    AntiDump,
    AntiDebugBreakpoints,
    DotNetHook,
    HeaderCorruption,
}

impl Technique {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AntiTamper => "anti-tamper",
            Self::AntiDebug => "anti-debug",
            Self::AntiDump => "anti-dump",
            Self::AntiDebugBreakpoints => "anti-debug-breakpoints",
            Self::DotNetHook => "dotnet-hook",
            Self::HeaderCorruption => "header-corruption",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub method_token: Option<u32>,
    pub il_offset: Option<u32>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    pub id: String,
    pub technique: Technique,
    pub evidence: Evidence,
    pub file_offset: u64,
    pub length: u32,
    pub original: Vec<u8>,
    pub replacement: Vec<u8>,
    pub risk: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeutralizationPlan {
    pub patches: Vec<Patch>,
}

impl NeutralizationPlan {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    #[must_use]
    pub fn techniques(&self) -> BTreeSet<Technique> {
        self.patches.iter().map(|p: &Patch| p.technique).collect()
    }

    #[must_use]
    pub fn count(&self, technique: Technique) -> usize {
        self.patches
            .iter()
            .filter(|p: &&Patch| p.technique == technique)
            .count()
    }

    pub(crate) fn push(&mut self, patch: Patch) -> bool {
        if self.patches.len() >= MAX_PATCHES
            || patch.original.len() != patch.replacement.len()
            || patch.original.len() > MAX_PATCH_BYTES
            || usize::try_from(patch.length).ok() != Some(patch.original.len())
            || patch.original == patch.replacement
            || self.patches.iter().any(|p: &Patch| p.id == patch.id)
        {
            return false;
        }
        self.patches.push(patch);
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    All,
    Only(BTreeSet<String>),
}

impl Selection {
    fn includes(&self, id: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(ids) => ids.contains(id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedPatch {
    pub id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeutralizationReport {
    pub applied: Vec<String>,
    pub declined: Vec<String>,
    pub refused: Vec<RefusedPatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub bytes: Vec<u8>,
    pub report: NeutralizationReport,
}

#[derive(Debug, Error)]
pub enum NeutralizeError {
    #[error("the plan selects no patch that could be applied: {0}")]
    NothingApplied(String),
}

pub fn apply(
    original: &[u8],
    plan: &NeutralizationPlan,
    selection: &Selection,
) -> Result<Applied, NeutralizeError> {
    let mut bytes: Vec<u8> = original.to_vec();
    let mut report: NeutralizationReport = NeutralizationReport::default();
    let mut touched: BTreeSet<u64> = BTreeSet::new();
    for patch in &plan.patches {
        if !selection.includes(&patch.id) {
            report.declined.push(patch.id.clone());
            continue;
        }
        let Some(start): Option<usize> = usize::try_from(patch.file_offset).ok() else {
            report.refused.push(RefusedPatch {
                id: patch.id.clone(),
                reason: "the file offset does not fit this platform".to_owned(),
            });
            continue;
        };
        let Some(end): Option<usize> = start.checked_add(patch.original.len()) else {
            report.refused.push(RefusedPatch {
                id: patch.id.clone(),
                reason: "the patch range overflows".to_owned(),
            });
            continue;
        };
        let Some(current): Option<&[u8]> = original.get(start..end) else {
            report.refused.push(RefusedPatch {
                id: patch.id.clone(),
                reason: format!(
                    "the patch range {start:#x}..{end:#x} lies outside the {} input bytes",
                    original.len()
                ),
            });
            continue;
        };
        if current != patch.original.as_slice() {
            let first: usize = current
                .iter()
                .zip(&patch.original)
                .position(|(a, b): (&u8, &u8)| a != b)
                .unwrap_or(0);
            report.refused.push(RefusedPatch {
                id: patch.id.clone(),
                reason: format!(
                    "the input bytes at {:#x} differ from the bytes the plan was built on (first mismatch at +{first})",
                    patch.file_offset
                ),
            });
            continue;
        }
        if patch.replacement.len() != patch.original.len() {
            report.refused.push(RefusedPatch {
                id: patch.id.clone(),
                reason: "the replacement does not have the original's length".to_owned(),
            });
            continue;
        }
        if (start..end).any(|offset: usize| !touched.insert(offset as u64)) {
            report.refused.push(RefusedPatch {
                id: patch.id.clone(),
                reason: "the range overlaps a patch applied earlier in the plan".to_owned(),
            });
            continue;
        }
        bytes[start..end].copy_from_slice(&patch.replacement);
        report.applied.push(patch.id.clone());
    }
    if report.applied.is_empty() && !plan.patches.is_empty() && matches!(selection, Selection::All)
    {
        let reasons: Vec<String> = report
            .refused
            .iter()
            .map(|r: &RefusedPatch| format!("{}: {}", r.id, r.reason))
            .collect();
        return Err(NeutralizeError::NothingApplied(reasons.join("; ")));
    }
    Ok(Applied { bytes, report })
}

#[must_use]
pub fn neutralized_path(input: &Path) -> PathBuf {
    let stem: String = input.file_stem().map_or_else(
        || "output".to_owned(),
        |s: &std::ffi::OsStr| s.to_string_lossy().into_owned(),
    );
    let name: String = input.extension().map_or_else(
        || format!("{stem}.{NEUTRALIZED_SUFFIX}"),
        |ext: &std::ffi::OsStr| format!("{stem}.{NEUTRALIZED_SUFFIX}.{}", ext.to_string_lossy()),
    );
    input.with_file_name(name)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MethodRef {
    pub(crate) token: u32,
    pub(crate) rva: u32,
}

impl MethodRef {
    pub(crate) const fn new(token: u32, rva: u32) -> Self {
        Self { token, rva }
    }
}

pub(crate) struct IlSite<'a> {
    pub(crate) input: &'a [u8],
    pub(crate) pe: &'a PeImage,
}

impl IlSite<'_> {
    pub(crate) fn file_offset(&self, method_rva: u32, il_offset: u32) -> Option<u64> {
        let body_start: usize = self.pe.rva_to_offset(method_rva)?;
        let header: usize = crate::cil::method_header_size(self.input.get(body_start..)?).ok()?;
        let offset: usize = body_start
            .checked_add(header)?
            .checked_add(usize::try_from(il_offset).ok()?)?;
        u64::try_from(offset).ok()
    }

    pub(crate) fn original(&self, file_offset: u64, length: usize) -> Option<Vec<u8>> {
        let start: usize = usize::try_from(file_offset).ok()?;
        self.input
            .get(start..start.checked_add(length)?)
            .map(<[u8]>::to_vec)
    }

    pub(crate) fn nop_patch(
        &self,
        technique: Technique,
        method: MethodRef,
        body: &MethodBody,
        span: (usize, usize),
        detail: String,
        risk: &str,
    ) -> Option<Patch> {
        let (first, end): (usize, usize) = span;
        let MethodRef {
            token: method_token,
            rva: method_rva,
        } = method;
        let start_offset: u32 = body.instructions.get(first)?.offset;
        let end_offset: u32 = body
            .instructions
            .get(end)
            .map_or(body.code_size, |i| i.offset);
        let length: usize = usize::try_from(end_offset.checked_sub(start_offset)?).ok()?;
        if length == 0 {
            return None;
        }
        let file_offset: u64 = self.file_offset(method_rva, start_offset)?;
        let original: Vec<u8> = self.original(file_offset, length)?;
        Some(Patch {
            id: format!(
                "{}:{method_token:#010x}:{start_offset:#x}",
                technique.label()
            ),
            technique,
            evidence: Evidence {
                method_token: Some(method_token),
                il_offset: Some(start_offset),
                detail,
            },
            file_offset,
            length: u32::try_from(length).ok()?,
            original,
            replacement: vec![0x00; length],
            risk: risk.to_owned(),
        })
    }

    pub(crate) fn token_patch(
        &self,
        technique: Technique,
        method: MethodRef,
        il_offset: u32,
        from: u32,
        to: u32,
        detail: String,
        risk: &str,
    ) -> Option<Patch> {
        let MethodRef {
            token: method_token,
            rva: method_rva,
        } = method;
        let file_offset: u64 = self.file_offset(method_rva, il_offset)?.checked_add(1)?;
        let original: Vec<u8> = self.original(file_offset, 4)?;
        if original != from.to_le_bytes() {
            return None;
        }
        Some(Patch {
            id: format!("{}:{method_token:#010x}:{il_offset:#x}", technique.label()),
            technique,
            evidence: Evidence {
                method_token: Some(method_token),
                il_offset: Some(il_offset),
                detail,
            },
            file_offset,
            length: 4,
            original,
            replacement: to.to_le_bytes().to_vec(),
            risk: risk.to_owned(),
        })
    }
}

#[must_use]
pub(crate) fn raw_patch(
    input: &[u8],
    technique: Technique,
    id_suffix: &str,
    file_offset: usize,
    replacement: Vec<u8>,
    detail: String,
    risk: &str,
) -> Option<Patch> {
    let original: Vec<u8> = input
        .get(file_offset..file_offset.checked_add(replacement.len())?)?
        .to_vec();
    Some(Patch {
        id: format!("{}:{id_suffix}:{file_offset:#x}", technique.label()),
        technique,
        evidence: Evidence {
            method_token: None,
            il_offset: None,
            detail,
        },
        file_offset: u64::try_from(file_offset).ok()?,
        length: u32::try_from(replacement.len()).ok()?,
        original,
        replacement,
        risk: risk.to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn plan_with(file_offset: u64, original: &[u8], replacement: &[u8]) -> NeutralizationPlan {
        let mut plan: NeutralizationPlan = NeutralizationPlan::default();
        assert!(plan.push(Patch {
            id: format!("anti-debug:{file_offset:#x}"),
            technique: Technique::AntiDebug,
            evidence: Evidence {
                method_token: Some(0x0600_0001),
                il_offset: Some(0),
                detail: "test".to_owned(),
            },
            file_offset,
            length: u32::try_from(original.len()).unwrap(),
            original: original.to_vec(),
            replacement: replacement.to_vec(),
            risk: "none".to_owned(),
        }));
        plan
    }

    #[test]
    fn apply_rewrites_only_verified_ranges() {
        let input: Vec<u8> = (0u8..32).collect();
        let plan: NeutralizationPlan = plan_with(4, &[4, 5, 6, 7, 8], &[0, 0, 0, 0, 0]);
        let applied: Applied = apply(&input, &plan, &Selection::All).expect("applies");
        assert_eq!(&applied.bytes[4..9], &[0, 0, 0, 0, 0]);
        assert_eq!(&applied.bytes[..4], &input[..4]);
        assert_eq!(&applied.bytes[9..], &input[9..]);
        assert_eq!(applied.report.applied.len(), 1);
        assert!(applied.report.refused.is_empty());
    }

    #[test]
    fn a_changed_original_byte_refuses_the_patch() {
        let mut input: Vec<u8> = (0u8..32).collect();
        let plan: NeutralizationPlan = plan_with(4, &[4, 5, 6, 7, 8], &[0, 0, 0, 0, 0]);
        input[6] ^= 0xFF;
        let outcome: Result<Applied, NeutralizeError> = apply(&input, &plan, &Selection::All);
        assert!(
            matches!(outcome, Err(NeutralizeError::NothingApplied(ref why)) if why.contains("+2"))
        );
        let partial: Applied =
            apply(&input, &plan, &Selection::Only(BTreeSet::new())).expect("declined");
        assert_eq!(partial.bytes, input);
        assert_eq!(partial.report.declined.len(), 1);
    }

    #[test]
    fn declining_leaves_the_bytes_untouched() {
        let input: Vec<u8> = (0u8..32).collect();
        let plan: NeutralizationPlan = plan_with(4, &[4, 5, 6, 7, 8], &[0, 0, 0, 0, 0]);
        let applied: Applied = apply(
            &input,
            &plan,
            &Selection::Only(BTreeSet::from(["other".to_owned()])),
        )
        .unwrap();
        assert_eq!(applied.bytes, input);
        assert_eq!(
            applied.report.declined,
            vec![format!("anti-debug:{:#x}", 4)]
        );
    }

    #[test]
    fn plans_reject_malformed_patches() {
        let mut plan: NeutralizationPlan = NeutralizationPlan::default();
        assert!(!plan.push(Patch {
            id: "x".to_owned(),
            technique: Technique::AntiDump,
            evidence: Evidence {
                method_token: None,
                il_offset: None,
                detail: String::new(),
            },
            file_offset: 0,
            length: 2,
            original: vec![1, 2],
            replacement: vec![1],
            risk: String::new(),
        }));
        assert!(plan.is_empty());
    }

    #[test]
    fn neutralized_path_keeps_the_extension() {
        assert_eq!(
            neutralized_path(Path::new("out/Sample.exe")),
            PathBuf::from("out/Sample.neutralized.exe")
        );
        assert_eq!(
            neutralized_path(Path::new("Sample")),
            PathBuf::from("Sample.neutralized")
        );
    }
}
