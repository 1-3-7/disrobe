use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::anti_analysis::Technique;

pub const NEUTRALIZATION_PLAN_SCHEMA: &str = "disrobe.neutralization-plan/v1";
pub const NEUTRALIZATION_REPORT_SCHEMA: &str = "disrobe.neutralization-report/v1";

pub const MAX_PATCHES_PER_PLAN: usize = 4096;
pub const MAX_PATCH_LENGTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeCheck {
    IsDebuggerPresent,
    CheckRemoteDebuggerPresent,
    NtQueryInformationProcessDebugPort,
    NtQueryInformationProcessDebugObjectHandle,
    NtQueryInformationProcessDebugFlags,
    NtSetInformationThreadHideFromDebugger,
    OutputDebugString,
    PebBeingDebugged,
    PebNtGlobalFlag,
    HeapFlags,
    RdtscDelta,
    TickCountDelta,
    PerformanceCounterDelta,
    Int2dTrap,
    IcebpTrap,
    CpuidHypervisorBit,
    CpuidHypervisorLeaf,
    TlsCallback,
    VectoredExceptionHandler,
    JsDomainLock,
    JsHostEnvironmentProbe,
    JsDateLock,
    JsDebuggerTrap,
    JsConsoleHijack,
    JsIntegrityHash,
}

impl RuntimeCheck {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::IsDebuggerPresent => "is-debugger-present",
            Self::CheckRemoteDebuggerPresent => "check-remote-debugger-present",
            Self::NtQueryInformationProcessDebugPort => "nt-query-information-process-debug-port",
            Self::NtQueryInformationProcessDebugObjectHandle => {
                "nt-query-information-process-debug-object-handle"
            }
            Self::NtQueryInformationProcessDebugFlags => "nt-query-information-process-debug-flags",
            Self::NtSetInformationThreadHideFromDebugger => {
                "nt-set-information-thread-hide-from-debugger"
            }
            Self::OutputDebugString => "output-debug-string",
            Self::PebBeingDebugged => "peb-being-debugged",
            Self::PebNtGlobalFlag => "peb-nt-global-flag",
            Self::HeapFlags => "heap-flags",
            Self::RdtscDelta => "rdtsc-delta",
            Self::TickCountDelta => "tick-count-delta",
            Self::PerformanceCounterDelta => "performance-counter-delta",
            Self::Int2dTrap => "int2d-trap",
            Self::IcebpTrap => "icebp-trap",
            Self::CpuidHypervisorBit => "cpuid-hypervisor-bit",
            Self::CpuidHypervisorLeaf => "cpuid-hypervisor-leaf",
            Self::TlsCallback => "tls-callback",
            Self::VectoredExceptionHandler => "vectored-exception-handler",
            Self::JsDomainLock => "js-domain-lock",
            Self::JsHostEnvironmentProbe => "js-host-environment-probe",
            Self::JsDateLock => "js-date-lock",
            Self::JsDebuggerTrap => "js-debugger-trap",
            Self::JsConsoleHijack => "js-console-hijack",
            Self::JsIntegrityHash => "js-integrity-hash",
        }
    }

    #[inline]
    #[must_use]
    pub const fn technique(self) -> Technique {
        match self {
            Self::IsDebuggerPresent
            | Self::CheckRemoteDebuggerPresent
            | Self::NtQueryInformationProcessDebugPort
            | Self::NtQueryInformationProcessDebugObjectHandle
            | Self::NtQueryInformationProcessDebugFlags
            | Self::NtSetInformationThreadHideFromDebugger
            | Self::OutputDebugString
            | Self::PebBeingDebugged
            | Self::PebNtGlobalFlag
            | Self::HeapFlags
            | Self::Int2dTrap
            | Self::IcebpTrap
            | Self::TlsCallback
            | Self::VectoredExceptionHandler
            | Self::JsDebuggerTrap
            | Self::JsConsoleHijack => Technique::AntiDebug,
            Self::RdtscDelta
            | Self::TickCountDelta
            | Self::PerformanceCounterDelta
            | Self::JsDateLock => Technique::TimingEvasion,
            Self::CpuidHypervisorBit | Self::CpuidHypervisorLeaf => Technique::AntiVm,
            Self::JsDomainLock | Self::JsHostEnvironmentProbe => Technique::AntiSandbox,
            Self::JsIntegrityHash => Technique::Rasp,
        }
    }

    #[inline]
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::IsDebuggerPresent => "kernel32!IsDebuggerPresent result consumed by a branch",
            Self::CheckRemoteDebuggerPresent => {
                "kernel32!CheckRemoteDebuggerPresent out-flag consumed by a branch"
            }
            Self::NtQueryInformationProcessDebugPort => {
                "ntdll!NtQueryInformationProcess(ProcessDebugPort) result consumed by a branch"
            }
            Self::NtQueryInformationProcessDebugObjectHandle => {
                "ntdll!NtQueryInformationProcess(ProcessDebugObjectHandle) result consumed by a branch"
            }
            Self::NtQueryInformationProcessDebugFlags => {
                "ntdll!NtQueryInformationProcess(ProcessDebugFlags) result consumed by a branch"
            }
            Self::NtSetInformationThreadHideFromDebugger => {
                "ntdll!NtSetInformationThread(ThreadHideFromDebugger) detaches the thread from a debugger"
            }
            Self::OutputDebugString => "kernel32!OutputDebugString last-error probe",
            Self::PebBeingDebugged => "PEB.BeingDebugged byte read",
            Self::PebNtGlobalFlag => "PEB.NtGlobalFlag heap-debug bits read",
            Self::HeapFlags => "process heap Flags/ForceFlags read",
            Self::RdtscDelta => "rdtsc pair with a threshold compare",
            Self::TickCountDelta => {
                "GetTickCount/GetTickCount64/timeGetTime pair with a threshold compare"
            }
            Self::PerformanceCounterDelta => {
                "QueryPerformanceCounter pair with a threshold compare"
            }
            Self::Int2dTrap => "int 2d software trap whose handler marks the clean path",
            Self::IcebpTrap => "icebp (int 1) software trap whose handler marks the clean path",
            Self::CpuidHypervisorBit => "cpuid leaf 1 ECX bit 31 hypervisor-present test",
            Self::CpuidHypervisorLeaf => "cpuid leaf 0x40000000 hypervisor vendor query",
            Self::TlsCallback => "TLS callback executed before the entry point",
            Self::VectoredExceptionHandler => {
                "vectored exception handler registered to redirect control flow"
            }
            Self::JsDomainLock => {
                "script compares the page hostname or domain against an allow list and diverts when it differs"
            }
            Self::JsHostEnvironmentProbe => {
                "script probes for a browser or Node.js host (window, document, navigator, process) and diverts on the unexpected one"
            }
            Self::JsDateLock => {
                "script compares the clock against a start or end date and diverts outside it"
            }
            Self::JsDebuggerTrap => {
                "debugger statement or Function-constructed debugger loop that stalls an attached debugger"
            }
            Self::JsConsoleHijack => "script replaces the console methods with silent stand-ins",
            Self::JsIntegrityHash => {
                "script hashes its own function source and traps when the digest differs from the embedded one"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub address: u64,
    pub instruction: String,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    pub id: String,
    pub check: RuntimeCheck,
    pub anchor: Anchor,
    pub file_offset: u64,
    pub original: Vec<u8>,
    pub replacement: Vec<u8>,
    pub risk: String,
}

impl Patch {
    #[inline]
    #[must_use]
    pub const fn length(&self) -> usize {
        self.original.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub check: RuntimeCheck,
    pub anchor: Anchor,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeutralizationPlan {
    pub schema: String,
    pub input_blake3: String,
    pub patches: Vec<Patch>,
    pub refusals: Vec<Refusal>,
}

impl NeutralizationPlan {
    #[must_use]
    pub fn new(input: &[u8]) -> Self {
        Self {
            schema: NEUTRALIZATION_PLAN_SCHEMA.to_owned(),
            input_blake3: blake3::hash(input).to_hex().to_string(),
            patches: Vec::new(),
            refusals: Vec::new(),
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    #[must_use]
    pub fn checks(&self) -> BTreeSet<RuntimeCheck> {
        self.patches
            .iter()
            .map(|patch: &Patch| patch.check)
            .collect()
    }

    #[must_use]
    pub fn techniques(&self) -> BTreeSet<Technique> {
        self.patches
            .iter()
            .map(|patch: &Patch| patch.check.technique())
            .collect()
    }

    pub fn push_patch(&mut self, patch: Patch) -> Result<(), NeutralizeError> {
        if self.patches.len() >= MAX_PATCHES_PER_PLAN {
            return Err(NeutralizeError::PlanTooLarge {
                limit: MAX_PATCHES_PER_PLAN,
            });
        }
        validate_shape(&patch)?;
        if self
            .patches
            .iter()
            .any(|existing: &Patch| existing.id == patch.id)
        {
            return Err(NeutralizeError::DuplicateId { id: patch.id });
        }
        self.patches.push(patch);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    All,
    Skip,
    Only(BTreeSet<String>),
}

impl Selection {
    fn verdict(&self, id: &str) -> PatchVerdict {
        match self {
            Self::All => PatchVerdict::Apply,
            Self::Skip => PatchVerdict::Skip,
            Self::Only(ids) => {
                if ids.contains(id) {
                    PatchVerdict::Apply
                } else {
                    PatchVerdict::Decline
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchVerdict {
    Apply,
    Decline,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedPatch {
    pub id: String,
    pub check: RuntimeCheck,
    pub file_offset: u64,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclinedPatch {
    pub id: String,
    pub check: RuntimeCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedPatch {
    pub id: String,
    pub check: RuntimeCheck,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeutralizationReport {
    pub schema: String,
    pub applied: Vec<AppliedPatch>,
    pub declined: Vec<DeclinedPatch>,
    pub skipped: Vec<SkippedPatch>,
    pub refusals: Vec<Refusal>,
}

impl NeutralizationReport {
    #[must_use]
    pub fn declined_checks(&self) -> BTreeSet<RuntimeCheck> {
        self.declined
            .iter()
            .map(|patch: &DeclinedPatch| patch.check)
            .chain(self.skipped.iter().map(|patch: &SkippedPatch| patch.check))
            .collect()
    }

    #[must_use]
    pub fn applied_checks(&self) -> BTreeSet<RuntimeCheck> {
        self.applied
            .iter()
            .map(|patch: &AppliedPatch| patch.check)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub bytes: Vec<u8>,
    pub report: NeutralizationReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NeutralizeError {
    #[error("DR-CORE-0040: patch {id} is empty")]
    EmptyPatch { id: String },

    #[error("DR-CORE-0041: patch {id} spans {length} bytes, above the {limit}-byte cap")]
    PatchTooLong {
        id: String,
        length: usize,
        limit: usize,
    },

    #[error(
        "DR-CORE-0042: patch {id} replaces {original} bytes with {replacement}; a patch never changes the instruction length"
    )]
    LengthMismatch {
        id: String,
        original: usize,
        replacement: usize,
    },

    #[error("DR-CORE-0043: patch id {id} occurs twice in the plan")]
    DuplicateId { id: String },

    #[error("DR-CORE-0044: plan holds more than {limit} patches")]
    PlanTooLarge { limit: usize },

    #[error(
        "DR-CORE-0045: patch {id} at file offset {file_offset:#x} with {length} bytes lies outside the {input_len}-byte input"
    )]
    OutOfRange {
        id: String,
        file_offset: u64,
        length: usize,
        input_len: usize,
    },

    #[error(
        "DR-CORE-0046: patch {id} at file offset {file_offset:#x} expected {expected} but the input holds {found}; the plan was made for different bytes"
    )]
    OriginalMismatch {
        id: String,
        file_offset: u64,
        expected: String,
        found: String,
    },

    #[error("DR-CORE-0047: patch {id} overlaps selected patch {other}")]
    Overlap { id: String, other: String },

    #[error(
        "DR-CORE-0048: the plan was made for input blake3 {plan} but this input hashes to {input}"
    )]
    InputMismatch { plan: String, input: String },
}

fn validate_shape(patch: &Patch) -> Result<(), NeutralizeError> {
    if patch.original.is_empty() {
        return Err(NeutralizeError::EmptyPatch {
            id: patch.id.clone(),
        });
    }
    if patch.original.len() > MAX_PATCH_LENGTH {
        return Err(NeutralizeError::PatchTooLong {
            id: patch.id.clone(),
            length: patch.original.len(),
            limit: MAX_PATCH_LENGTH,
        });
    }
    if patch.original.len() != patch.replacement.len() {
        return Err(NeutralizeError::LengthMismatch {
            id: patch.id.clone(),
            original: patch.original.len(),
            replacement: patch.replacement.len(),
        });
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b: &u8| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}

fn patch_range(patch: &Patch, input_len: usize) -> Result<(usize, usize), NeutralizeError> {
    let start: usize =
        usize::try_from(patch.file_offset).map_err(|_| NeutralizeError::OutOfRange {
            id: patch.id.clone(),
            file_offset: patch.file_offset,
            length: patch.length(),
            input_len,
        })?;
    let end: usize = start
        .checked_add(patch.length())
        .filter(|end: &usize| *end <= input_len)
        .ok_or_else(|| NeutralizeError::OutOfRange {
            id: patch.id.clone(),
            file_offset: patch.file_offset,
            length: patch.length(),
            input_len,
        })?;
    Ok((start, end))
}

pub fn apply(
    input: &[u8],
    plan: &NeutralizationPlan,
    selection: &Selection,
) -> Result<Applied, NeutralizeError> {
    let input_hash: String = blake3::hash(input).to_hex().to_string();
    if plan.input_blake3 != input_hash {
        return Err(NeutralizeError::InputMismatch {
            plan: plan.input_blake3.clone(),
            input: input_hash,
        });
    }
    if plan.patches.len() > MAX_PATCHES_PER_PLAN {
        return Err(NeutralizeError::PlanTooLarge {
            limit: MAX_PATCHES_PER_PLAN,
        });
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for patch in &plan.patches {
        validate_shape(patch)?;
        if !seen.insert(patch.id.as_str()) {
            return Err(NeutralizeError::DuplicateId {
                id: patch.id.clone(),
            });
        }
    }

    let mut bytes: Vec<u8> = input.to_vec();
    let mut report: NeutralizationReport = NeutralizationReport {
        schema: NEUTRALIZATION_REPORT_SCHEMA.to_owned(),
        applied: Vec::new(),
        declined: Vec::new(),
        skipped: Vec::new(),
        refusals: plan.refusals.clone(),
    };
    let mut written: Vec<(usize, usize, &str)> = Vec::new();
    for patch in &plan.patches {
        match selection.verdict(&patch.id) {
            PatchVerdict::Decline => {
                report.declined.push(DeclinedPatch {
                    id: patch.id.clone(),
                    check: patch.check,
                });
                continue;
            }
            PatchVerdict::Skip => {
                report.skipped.push(SkippedPatch {
                    id: patch.id.clone(),
                    check: patch.check,
                    reason: "neutralization mode skip left the check in place".to_owned(),
                });
                continue;
            }
            PatchVerdict::Apply => {}
        }
        let (start, end): (usize, usize) = patch_range(patch, input.len())?;
        if let Some((_, _, other)) = written
            .iter()
            .find(|(s, e, _): &&(usize, usize, &str)| start < *e && *s < end)
        {
            return Err(NeutralizeError::Overlap {
                id: patch.id.clone(),
                other: (*other).to_owned(),
            });
        }
        let found: &[u8] = &bytes[start..end];
        if found != patch.original.as_slice() {
            return Err(NeutralizeError::OriginalMismatch {
                id: patch.id.clone(),
                file_offset: patch.file_offset,
                expected: hex(&patch.original),
                found: hex(found),
            });
        }
        bytes[start..end].copy_from_slice(&patch.replacement);
        written.push((start, end, patch.id.as_str()));
        report.applied.push(AppliedPatch {
            id: patch.id.clone(),
            check: patch.check,
            file_offset: patch.file_offset,
            length: patch.length(),
        });
    }
    Ok(Applied { bytes, report })
}

#[must_use]
pub fn neutralized_path(input: &Path) -> PathBuf {
    let stem: String = input.file_stem().map_or_else(
        || "input".to_owned(),
        |s: &std::ffi::OsStr| s.to_string_lossy().into_owned(),
    );
    let name: String = input.extension().map_or_else(
        || format!("{stem}.neutralized"),
        |ext: &std::ffi::OsStr| format!("{stem}.neutralized.{}", ext.to_string_lossy()),
    );
    input.with_file_name(name)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeutralizedCheck {
    pub check: RuntimeCheck,
    pub anchor: Anchor,
    pub outcome: String,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn anchor(address: u64) -> Anchor {
        Anchor {
            address,
            instruction: "call [rip+0x2f3a]".to_owned(),
            pattern: "kernel32!IsDebuggerPresent".to_owned(),
        }
    }

    fn patch(id: &str, offset: u64, original: &[u8], replacement: &[u8]) -> Patch {
        Patch {
            id: id.to_owned(),
            check: RuntimeCheck::IsDebuggerPresent,
            anchor: anchor(0x1400 + offset),
            file_offset: offset,
            original: original.to_vec(),
            replacement: replacement.to_vec(),
            risk: "the branch after the call keeps its other operands".to_owned(),
        }
    }

    fn plan_for(input: &[u8], patches: Vec<Patch>) -> NeutralizationPlan {
        let mut plan: NeutralizationPlan = NeutralizationPlan::new(input);
        for p in patches {
            plan.push_patch(p).expect("well-formed patch");
        }
        plan
    }

    #[test]
    fn apply_all_writes_every_patch_and_reports_it() {
        let input: Vec<u8> = (0u8..32).collect();
        let plan: NeutralizationPlan = plan_for(
            &input,
            vec![
                patch("a", 4, &[4, 5, 6], &[0x31, 0xC0, 0x90]),
                patch("b", 20, &[20, 21], &[0x90, 0x90]),
            ],
        );
        let out: Applied = apply(&input, &plan, &Selection::All).expect("apply");
        assert_eq!(&out.bytes[4..7], &[0x31, 0xC0, 0x90]);
        assert_eq!(&out.bytes[20..22], &[0x90, 0x90]);
        assert_eq!(out.bytes[7], 7);
        assert_eq!(out.report.applied.len(), 2);
        assert!(out.report.declined.is_empty() && out.report.skipped.is_empty());
        assert_eq!(out.report.schema, NEUTRALIZATION_REPORT_SCHEMA);
    }

    #[test]
    fn a_patch_whose_original_bytes_no_longer_match_is_refused_as_a_typed_error() {
        let input: Vec<u8> = (0u8..32).collect();
        let plan: NeutralizationPlan =
            plan_for(&input, vec![patch("a", 4, &[4, 5, 7], &[0x90, 0x90, 0x90])]);
        let err: NeutralizeError = apply(&input, &plan, &Selection::All).expect_err("mismatch");
        assert!(
            matches!(err, NeutralizeError::OriginalMismatch { ref id, file_offset: 4, .. } if id == "a"),
            "{err:?}"
        );
    }

    #[test]
    fn a_plan_made_for_other_bytes_is_refused_before_any_write() {
        let input: Vec<u8> = (0u8..32).collect();
        let mut other: Vec<u8> = input.clone();
        other[31] ^= 1;
        let plan: NeutralizationPlan =
            plan_for(&other, vec![patch("a", 4, &[4, 5], &[0x90, 0x90])]);
        let err: NeutralizeError = apply(&input, &plan, &Selection::All).expect_err("hash");
        assert!(
            matches!(err, NeutralizeError::InputMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn declined_and_skipped_patches_leave_the_bytes_alone_and_are_listed() {
        let input: Vec<u8> = (0u8..32).collect();
        let plan: NeutralizationPlan = plan_for(
            &input,
            vec![
                patch("a", 4, &[4, 5], &[0x90, 0x90]),
                patch("b", 20, &[20, 21], &[0x90, 0x90]),
            ],
        );
        let only_b: Selection = Selection::Only(BTreeSet::from(["b".to_owned()]));
        let out: Applied = apply(&input, &plan, &only_b).expect("apply");
        assert_eq!(&out.bytes[4..6], &[4, 5]);
        assert_eq!(&out.bytes[20..22], &[0x90, 0x90]);
        assert_eq!(out.report.declined.len(), 1);
        assert_eq!(out.report.declined[0].id, "a");
        assert_eq!(out.report.applied.len(), 1);

        let skipped: Applied = apply(&input, &plan, &Selection::Skip).expect("apply");
        assert_eq!(skipped.bytes, input);
        assert_eq!(skipped.report.skipped.len(), 2);
        assert!(skipped.report.applied.is_empty());
        assert_eq!(
            skipped.report.declined_checks(),
            BTreeSet::from([RuntimeCheck::IsDebuggerPresent])
        );
    }

    #[test]
    fn out_of_range_and_overlapping_patches_are_typed_errors() {
        let input: Vec<u8> = (0u8..32).collect();
        let far: NeutralizationPlan =
            plan_for(&input, vec![patch("a", 31, &[31, 0], &[0x90, 0x90])]);
        assert!(matches!(
            apply(&input, &far, &Selection::All),
            Err(NeutralizeError::OutOfRange { .. })
        ));
        let overlap: NeutralizationPlan = plan_for(
            &input,
            vec![
                patch("a", 4, &[4, 5, 6], &[0x90, 0x90, 0x90]),
                patch("b", 6, &[6, 7], &[0x90, 0x90]),
            ],
        );
        assert!(matches!(
            apply(&input, &overlap, &Selection::All),
            Err(NeutralizeError::Overlap { .. })
        ));
    }

    #[test]
    fn the_plan_rejects_malformed_patches_at_construction() {
        let input: Vec<u8> = vec![0; 8];
        let mut plan: NeutralizationPlan = NeutralizationPlan::new(&input);
        assert!(matches!(
            plan.push_patch(patch("a", 0, &[0, 0], &[0x90])),
            Err(NeutralizeError::LengthMismatch { .. })
        ));
        assert!(matches!(
            plan.push_patch(patch("a", 0, &[], &[])),
            Err(NeutralizeError::EmptyPatch { .. })
        ));
        plan.push_patch(patch("a", 0, &[0], &[0x90]))
            .expect("first id");
        assert!(matches!(
            plan.push_patch(patch("a", 1, &[0], &[0x90])),
            Err(NeutralizeError::DuplicateId { .. })
        ));
        let long: Vec<u8> = vec![0; MAX_PATCH_LENGTH + 1];
        assert!(matches!(
            plan.push_patch(patch("c", 0, &long, &long)),
            Err(NeutralizeError::PatchTooLong { .. })
        ));
    }

    #[test]
    fn neutralized_path_keeps_the_extension_and_directory() {
        let p: PathBuf = neutralized_path(Path::new("out/app.exe"));
        assert_eq!(p, PathBuf::from("out/app.neutralized.exe"));
        let bare: PathBuf = neutralized_path(Path::new("out/app"));
        assert_eq!(bare, PathBuf::from("out/app.neutralized"));
    }

    #[test]
    fn every_runtime_check_maps_to_a_technique_and_a_kebab_label() {
        let all: [RuntimeCheck; 25] = [
            RuntimeCheck::IsDebuggerPresent,
            RuntimeCheck::CheckRemoteDebuggerPresent,
            RuntimeCheck::NtQueryInformationProcessDebugPort,
            RuntimeCheck::NtQueryInformationProcessDebugObjectHandle,
            RuntimeCheck::NtQueryInformationProcessDebugFlags,
            RuntimeCheck::NtSetInformationThreadHideFromDebugger,
            RuntimeCheck::OutputDebugString,
            RuntimeCheck::PebBeingDebugged,
            RuntimeCheck::PebNtGlobalFlag,
            RuntimeCheck::HeapFlags,
            RuntimeCheck::RdtscDelta,
            RuntimeCheck::TickCountDelta,
            RuntimeCheck::PerformanceCounterDelta,
            RuntimeCheck::Int2dTrap,
            RuntimeCheck::IcebpTrap,
            RuntimeCheck::CpuidHypervisorBit,
            RuntimeCheck::CpuidHypervisorLeaf,
            RuntimeCheck::TlsCallback,
            RuntimeCheck::VectoredExceptionHandler,
            RuntimeCheck::JsDomainLock,
            RuntimeCheck::JsHostEnvironmentProbe,
            RuntimeCheck::JsDateLock,
            RuntimeCheck::JsDebuggerTrap,
            RuntimeCheck::JsConsoleHijack,
            RuntimeCheck::JsIntegrityHash,
        ];
        let mut labels: BTreeSet<&str> = BTreeSet::new();
        for check in all {
            let label: &str = check.label();
            assert!(
                label
                    .bytes()
                    .all(|b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            );
            assert!(labels.insert(label), "duplicate label {label}");
            let json: String = serde_json::to_string(&check).unwrap();
            assert_eq!(json, format!("\"{label}\""));
            let _: Technique = check.technique();
            assert!(!check.describe().is_empty());
        }
    }

    #[test]
    fn plan_round_trips_through_json() {
        let input: Vec<u8> = (0u8..16).collect();
        let mut plan: NeutralizationPlan =
            plan_for(&input, vec![patch("a", 2, &[2, 3], &[0x90, 0x90])]);
        plan.refusals.push(Refusal {
            check: RuntimeCheck::Int2dTrap,
            anchor: anchor(0x2000),
            reason: "no flag consumer within the window".to_owned(),
        });
        let json: String = serde_json::to_string(&plan).unwrap();
        let back: NeutralizationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plan);
        assert_eq!(back.schema, NEUTRALIZATION_PLAN_SCHEMA);
        assert_eq!(back.techniques(), BTreeSet::from([Technique::AntiDebug]));
    }
}
