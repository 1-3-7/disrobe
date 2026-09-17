use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;

use super::BccLinkOutput;
use crate::bcc_lift::{
    BccLiftOutput, BccLiftRefusal, BccLiftRefusalReason, FunctionNameSource, PseudoCFunction,
};
use crate::error::{BccPublicationResource, Error, Result};
use crate::unpack::UnpackOutput;
use crate::v8v9::BccArch;

pub const BCC_RECOVERY_SCHEMA: &str = "disrobe.pyarmor.bcc.recovery/v1";
pub const BCC_RECOVERY_PATH: &str = "bcc/bcc-recovery.json";
pub const BCC_PSEUDO_C_PATH: &str = "bcc/bcc-pseudo-c.c";
pub const BCC_RECOVERED_PYTHON_PATH: &str = "bcc/bcc-recovered.py";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BccPublicationLimits {
    pub functions: usize,
    pub total_native_body_bytes: usize,
    pub body_bytes: usize,
    pub strings: usize,
    pub total_string_bytes: usize,
    pub json_bytes: usize,
    pub pseudo_c_bytes: usize,
    pub recovered_python_bytes: usize,
}

impl BccPublicationLimits {
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            functions: usize::MAX,
            total_native_body_bytes: usize::MAX,
            body_bytes: usize::MAX,
            strings: usize::MAX,
            total_string_bytes: usize::MAX,
            json_bytes: usize::MAX,
            pseudo_c_bytes: usize::MAX,
            recovered_python_bytes: usize::MAX,
        }
    }
}

impl Default for BccPublicationLimits {
    fn default() -> Self {
        Self {
            functions: 4_096,
            total_native_body_bytes: 32 * 1024 * 1024,
            body_bytes: 1024 * 1024,
            strings: 4_096,
            total_string_bytes: 1024 * 1024,
            json_bytes: 64 * 1024 * 1024,
            pseudo_c_bytes: 32 * 1024 * 1024,
            recovered_python_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BccPublicationSummary {
    pub blob_count: usize,
    pub refused_blob_count: usize,
    pub function_count: usize,
    pub modeled_count: usize,
    pub unmodeled_count: usize,
    pub native_body_bytes: usize,
    pub string_count: usize,
    pub string_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BccPublication {
    pub recovery_json: Vec<u8>,
    pub pseudo_c: Vec<u8>,
    pub recovered_python: Vec<u8>,
    pub summary: BccPublicationSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BccPublicationArtifact<'a> {
    pub relative_path: &'static str,
    pub bytes: &'a [u8],
}

impl BccPublication {
    #[must_use]
    pub fn artifacts(&self) -> [BccPublicationArtifact<'_>; 3] {
        [
            BccPublicationArtifact {
                relative_path: BCC_RECOVERY_PATH,
                bytes: &self.recovery_json,
            },
            BccPublicationArtifact {
                relative_path: BCC_PSEUDO_C_PATH,
                bytes: &self.pseudo_c,
            },
            BccPublicationArtifact {
                relative_path: BCC_RECOVERED_PYTHON_PATH,
                bytes: &self.recovered_python,
            },
        ]
    }

    #[must_use]
    pub fn manifest_value(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": BCC_RECOVERY_SCHEMA,
            "recovery_path": BCC_RECOVERY_PATH,
            "pseudo_c_path": BCC_PSEUDO_C_PATH,
            "recovered_python_path": BCC_RECOVERED_PYTHON_PATH,
            "blob_count": self.summary.blob_count,
            "refused_blob_count": self.summary.refused_blob_count,
            "function_count": self.summary.function_count,
            "modeled_count": self.summary.modeled_count,
            "unmodeled_count": self.summary.unmodeled_count,
        })
    }
}

#[derive(Serialize)]
struct RecoveryDocument {
    schema: &'static str,
    artifacts: ArtifactDocument,
    summary: BccPublicationSummary,
    function_map: serde_json::Value,
    strings: Vec<String>,
    blobs: Vec<BlobDocument>,
}

#[derive(Serialize)]
struct ArtifactDocument {
    recovery_json: &'static str,
    pseudo_c: &'static str,
    recovered_python: &'static str,
}

#[derive(Serialize)]
struct BlobDocument {
    container: String,
    architecture: String,
    status: &'static str,
    text_base: Option<String>,
    modeled_count: usize,
    unmodeled_count: usize,
    strings: Vec<String>,
    notes: Vec<String>,
    functions: Vec<FunctionDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<RefusalDocument>,
}

#[derive(Serialize)]
struct FunctionDocument {
    identity: String,
    name: String,
    entry: String,
    size: u32,
    parameter_count: u32,
    status: &'static str,
    signature: String,
    name_source: &'static str,
    resolved_callees: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<FunctionReasonDocument>,
    body: BodyDocument,
}

#[derive(Serialize)]
struct FunctionReasonDocument {
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum BodyDocument {
    Included { text: String },
    Omitted { reason: BodyOmissionDocument },
}

#[derive(Serialize)]
struct BodyOmissionDocument {
    code: &'static str,
    actual_bytes: usize,
    limit_bytes: usize,
}

#[derive(Serialize)]
struct RefusalDocument {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    architecture_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    message: String,
}

#[derive(Default)]
struct PublicationTotals {
    function_count: usize,
    modeled_count: usize,
    unmodeled_count: usize,
    native_body_bytes: usize,
    string_count: usize,
    string_bytes: usize,
}

#[must_use]
fn architecture_label(architecture: BccArch) -> String {
    match architecture {
        BccArch::WinX64 | BccArch::LinuxX64 | BccArch::DarwinArm64 => {
            architecture.label().to_owned()
        }
        BccArch::Other(id) => format!("other-{id:#x}"),
    }
}

fn checked_total(current: usize, addend: usize, detail: &str) -> Result<usize> {
    current
        .checked_add(addend)
        .ok_or_else(|| Error::BccPublicationAccountingMismatch {
            detail: format!("{detail} overflowed usize"),
        })
}

const fn enforce_quota(
    resource: BccPublicationResource,
    actual: usize,
    limit: usize,
) -> Result<()> {
    if actual > limit {
        return Err(Error::BccPublicationQuotaExceeded {
            resource,
            actual,
            limit,
        });
    }
    Ok(())
}

fn validate_native_identities(linked: &BccLinkOutput) -> Result<()> {
    let mut identities: BTreeSet<(String, u64)> = BTreeSet::new();
    for record in linked.map.native_records() {
        let Some(native) = record.native.as_ref() else {
            continue;
        };
        let identity: (String, u64) = (native.container.clone(), native.offset);
        if !identities.insert(identity.clone()) {
            return Err(Error::BccPublicationDuplicateNativeIdentity {
                container: identity.0,
                offset: identity.1,
            });
        }
    }
    Ok(())
}

fn preflight_publication(
    unpacked: &UnpackOutput,
    refusals: &BTreeMap<usize, &BccLiftRefusal>,
    limits: BccPublicationLimits,
) -> Result<PublicationTotals> {
    let mut totals: PublicationTotals = PublicationTotals::default();
    let mut lift_index: usize = 0;
    for (blob_index, blob) in unpacked.bcc_blobs.iter().enumerate() {
        if refusals.contains_key(&blob_index) {
            continue;
        }
        let lift: &BccLiftOutput = unpacked
            .bcc_lifts
            .get(lift_index)
            .ok_or(Error::BccPublicationMissingOutcome { blob_index })?;
        lift_index = checked_total(lift_index, 1, "lift outcome index")?;
        if lift.architecture != blob.architecture {
            return Err(Error::BccPublicationAccountingMismatch {
                detail: format!(
                    "blob {blob_index} architecture {} does not match lift architecture {}",
                    architecture_label(blob.architecture),
                    architecture_label(lift.architecture)
                ),
            });
        }
        let accounted: usize = lift
            .modeled_count
            .checked_add(lift.unmodeled_count)
            .ok_or_else(|| Error::BccPublicationAccountingMismatch {
                detail: format!("blob {blob_index} function counts overflowed usize"),
            })?;
        if accounted != lift.function_records.len() {
            return Err(Error::BccPublicationAccountingMismatch {
                detail: format!(
                    "blob {blob_index} reports {} modeled plus {} unmodeled functions but contains {}",
                    lift.modeled_count,
                    lift.unmodeled_count,
                    lift.function_records.len()
                ),
            });
        }
        totals.function_count = checked_total(
            totals.function_count,
            lift.function_records.len(),
            "function count",
        )?;
        totals.modeled_count =
            checked_total(totals.modeled_count, lift.modeled_count, "modeled count")?;
        totals.unmodeled_count = checked_total(
            totals.unmodeled_count,
            lift.unmodeled_count,
            "unmodeled count",
        )?;
        let container: String = format!(
            "bcc-image[{blob_index}] {}",
            architecture_label(lift.architecture)
        );
        let mut identities: BTreeSet<u64> = BTreeSet::new();
        for function in &lift.function_records {
            if !identities.insert(function.id.entry_va) {
                return Err(Error::BccPublicationDuplicateNativeIdentity {
                    container,
                    offset: function.id.entry_va,
                });
            }
        }
        for function in &lift.function_records {
            if function.size == 0 {
                return Err(Error::BccPublicationZeroLengthFunction {
                    entry_va: function.id.entry_va,
                    name: function.id.name.clone(),
                });
            }
            let body_bytes: usize = usize::try_from(function.size).map_err(|_| {
                Error::BccPublicationAccountingMismatch {
                    detail: format!("function {} size does not fit usize", function.id.name),
                }
            })?;
            totals.native_body_bytes = checked_total(
                totals.native_body_bytes,
                body_bytes,
                "native body byte count",
            )?;
        }
        totals.string_count =
            checked_total(totals.string_count, lift.strings.len(), "string count")?;
        for value in &lift.strings {
            totals.string_bytes =
                checked_total(totals.string_bytes, value.len(), "string byte count")?;
        }
        enforce_quota(
            BccPublicationResource::Functions,
            totals.function_count,
            limits.functions,
        )?;
        enforce_quota(
            BccPublicationResource::NativeBodyBytes,
            totals.native_body_bytes,
            limits.total_native_body_bytes,
        )?;
        enforce_quota(
            BccPublicationResource::Strings,
            totals.string_count,
            limits.strings,
        )?;
        enforce_quota(
            BccPublicationResource::StringBytes,
            totals.string_bytes,
            limits.total_string_bytes,
        )?;
    }
    if lift_index != unpacked.bcc_lifts.len() {
        return Err(Error::BccPublicationAccountingMismatch {
            detail: format!(
                "{} lift outcomes exceed {lift_index} non-refused blobs",
                unpacked.bcc_lifts.len()
            ),
        });
    }
    let accounted_functions: usize = totals
        .modeled_count
        .checked_add(totals.unmodeled_count)
        .ok_or_else(|| Error::BccPublicationAccountingMismatch {
            detail: "aggregate modeled and unmodeled counts overflowed usize".to_owned(),
        })?;
    if accounted_functions != totals.function_count {
        return Err(Error::BccPublicationAccountingMismatch {
            detail: format!(
                "aggregate reports {} modeled plus {} unmodeled functions but contains {}",
                totals.modeled_count, totals.unmodeled_count, totals.function_count
            ),
        });
    }
    Ok(totals)
}

fn refusal_document(reason: &BccLiftRefusalReason) -> RefusalDocument {
    match reason {
        BccLiftRefusalReason::UnsupportedArchitecture { id } => RefusalDocument {
            code: reason.code(),
            architecture_id: Some(format!("{id:#x}")),
            target: None,
            message: format!("BCC architecture id {id:#x} is not recognized"),
        },
        BccLiftRefusalReason::NativeLiftUnavailable { target } => RefusalDocument {
            code: reason.code(),
            architecture_id: None,
            target: Some(target.clone()),
            message: format!("BCC native lifting is unavailable for target {target}"),
        },
        BccLiftRefusalReason::LiftFailed { message } => RefusalDocument {
            code: reason.code(),
            architecture_id: None,
            target: None,
            message: message.clone(),
        },
    }
}

fn function_document(
    function: &PseudoCFunction,
    container: &str,
    limits: BccPublicationLimits,
    pseudo_c: &mut String,
) -> Result<FunctionDocument> {
    let body_bytes: usize =
        usize::try_from(function.size).map_err(|_| Error::BccPublicationAccountingMismatch {
            detail: format!("function {} size does not fit usize", function.id.name),
        })?;
    write!(pseudo_c, "/* {container}@{:#x}", function.id.entry_va)
        .map_err(|error: std::fmt::Error| Error::BccPublicationSerialization(error.to_string()))?;
    let body: BodyDocument = if body_bytes > limits.body_bytes {
        pseudo_c.push_str(": body omitted because it exceeds the publication limit */\n");
        BodyDocument::Omitted {
            reason: BodyOmissionDocument {
                code: "body_limit_exceeded",
                actual_bytes: body_bytes,
                limit_bytes: limits.body_bytes,
            },
        }
    } else {
        pseudo_c.push_str(" */\n");
        pseudo_c.push_str(function.pseudo_c.trim_end());
        pseudo_c.push_str("\n\n");
        BodyDocument::Included {
            text: function.pseudo_c.clone(),
        }
    };
    let mut resolved_callees: Vec<String> = function.resolved_callees.clone();
    resolved_callees.sort_unstable();
    resolved_callees.dedup();
    let name_source: &'static str = match function.name_source {
        FunctionNameSource::DispatchDescriptor => "dispatch_descriptor",
        FunctionNameSource::EntryAddress => "entry_address",
    };
    let reason: Option<FunctionReasonDocument> =
        (!function.modeled).then(|| FunctionReasonDocument {
            code: "native_recovery_declined",
            message: function
                .note
                .clone()
                .unwrap_or_else(|| "native recovery did not produce a modeled body".to_owned()),
        });
    Ok(FunctionDocument {
        identity: format!("{container}@{:#x}", function.id.entry_va),
        name: function.id.name.clone(),
        entry: format!("{:#x}", function.id.entry_va),
        size: function.size,
        parameter_count: function.parameter_count,
        status: if function.modeled {
            "modeled"
        } else {
            "unmodeled"
        },
        signature: function.signature.clone(),
        name_source,
        resolved_callees,
        note: function.note.clone(),
        reason,
        body,
    })
}

fn lifted_blob_document(
    blob_index: usize,
    lift: &BccLiftOutput,
    limits: BccPublicationLimits,
    pseudo_c: &mut String,
) -> Result<BlobDocument> {
    let container: String = format!(
        "bcc-image[{blob_index}] {}",
        architecture_label(lift.architecture)
    );
    let mut functions: Vec<FunctionDocument> = Vec::with_capacity(lift.function_records.len());
    for function in &lift.function_records {
        functions.push(function_document(function, &container, limits, pseudo_c)?);
    }
    let mut strings: Vec<String> = lift.strings.clone();
    strings.sort_unstable();
    let status: &'static str = match (lift.modeled_count, lift.unmodeled_count) {
        (0, 0) => "empty",
        (0, _) => "unmodeled",
        (_, 0) => "modeled",
        (_, _) => "mixed",
    };
    Ok(BlobDocument {
        container,
        architecture: architecture_label(lift.architecture),
        status,
        text_base: Some(format!("{:#x}", lift.text_base)),
        modeled_count: lift.modeled_count,
        unmodeled_count: lift.unmodeled_count,
        strings,
        notes: lift.notes.clone(),
        functions,
        refusal: None,
    })
}

fn refused_blob_document(blob_index: usize, refusal: &BccLiftRefusal) -> BlobDocument {
    BlobDocument {
        container: format!(
            "bcc-image[{blob_index}] {}",
            architecture_label(refusal.architecture)
        ),
        architecture: architecture_label(refusal.architecture),
        status: "refused",
        text_base: None,
        modeled_count: 0,
        unmodeled_count: 0,
        strings: Vec::new(),
        notes: Vec::new(),
        functions: Vec::new(),
        refusal: Some(refusal_document(&refusal.reason)),
    }
}

pub fn publish_bcc_recovery(
    unpacked: &UnpackOutput,
    linked: &BccLinkOutput,
) -> Result<BccPublication> {
    publish_bcc_recovery_with_limits(unpacked, linked, BccPublicationLimits::default())
}

pub fn publish_bcc_recovery_with_limits(
    unpacked: &UnpackOutput,
    linked: &BccLinkOutput,
    limits: BccPublicationLimits,
) -> Result<BccPublication> {
    validate_native_identities(linked)?;
    let mut refusals: BTreeMap<usize, &BccLiftRefusal> = BTreeMap::new();
    for refusal in &unpacked.bcc_lift_refusals {
        if refusal.blob_index >= unpacked.bcc_blobs.len() {
            return Err(Error::BccPublicationAccountingMismatch {
                detail: format!(
                    "refusal index {} exceeds {} BCC blobs",
                    refusal.blob_index,
                    unpacked.bcc_blobs.len()
                ),
            });
        }
        if refusal.architecture != unpacked.bcc_blobs[refusal.blob_index].architecture {
            return Err(Error::BccPublicationAccountingMismatch {
                detail: format!(
                    "refusal architecture for blob {} does not match the carved blob",
                    refusal.blob_index
                ),
            });
        }
        if refusals.insert(refusal.blob_index, refusal).is_some() {
            return Err(Error::BccPublicationAccountingMismatch {
                detail: format!("blob {} has multiple refusal outcomes", refusal.blob_index),
            });
        }
    }

    let totals: PublicationTotals = preflight_publication(unpacked, &refusals, limits)?;
    enforce_quota(
        BccPublicationResource::RecoveredPythonBytes,
        linked.skeleton.len(),
        limits.recovered_python_bytes,
    )?;
    let mut lift_iterator: std::slice::Iter<'_, BccLiftOutput> = unpacked.bcc_lifts.iter();
    let mut blobs: Vec<BlobDocument> = Vec::with_capacity(unpacked.bcc_blobs.len());
    let mut all_strings: Vec<String> = Vec::with_capacity(totals.string_count);
    let mut pseudo_c: String = String::new();
    for (blob_index, _) in unpacked.bcc_blobs.iter().enumerate() {
        if let Some(refusal) = refusals.get(&blob_index) {
            blobs.push(refused_blob_document(blob_index, refusal));
            continue;
        }
        let lift: &BccLiftOutput = lift_iterator
            .next()
            .ok_or(Error::BccPublicationMissingOutcome { blob_index })?;
        let document: BlobDocument = lifted_blob_document(blob_index, lift, limits, &mut pseudo_c)?;
        all_strings.extend(lift.strings.iter().cloned());
        blobs.push(document);
    }
    all_strings.sort_unstable();
    let summary: BccPublicationSummary = BccPublicationSummary {
        blob_count: unpacked.bcc_blobs.len(),
        refused_blob_count: refusals.len(),
        function_count: totals.function_count,
        modeled_count: totals.modeled_count,
        unmodeled_count: totals.unmodeled_count,
        native_body_bytes: totals.native_body_bytes,
        string_count: totals.string_count,
        string_bytes: totals.string_bytes,
    };
    let recovered_python: Vec<u8> = linked.skeleton.as_bytes().to_vec();
    let pseudo_c: Vec<u8> = pseudo_c.into_bytes();
    enforce_quota(
        BccPublicationResource::PseudoCBytes,
        pseudo_c.len(),
        limits.pseudo_c_bytes,
    )?;
    let document: RecoveryDocument = RecoveryDocument {
        schema: BCC_RECOVERY_SCHEMA,
        artifacts: ArtifactDocument {
            recovery_json: BCC_RECOVERY_PATH,
            pseudo_c: BCC_PSEUDO_C_PATH,
            recovered_python: BCC_RECOVERED_PYTHON_PATH,
        },
        summary: summary.clone(),
        function_map: linked.json_value(),
        strings: all_strings,
        blobs,
    };
    let recovery_json: Vec<u8> =
        serde_json::to_vec_pretty(&document).map_err(|error: serde_json::Error| {
            Error::BccPublicationSerialization(error.to_string())
        })?;
    enforce_quota(
        BccPublicationResource::JsonBytes,
        recovery_json.len(),
        limits.json_bytes,
    )?;
    Ok(BccPublication {
        recovery_json,
        pseudo_c,
        recovered_python,
        summary,
    })
}
