#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_binfmt::{StructuralFormat, identify_by_structure};
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::TERMINAL_HINT;
use disrobe_core::chain::{
    CatalogEntry, ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector,
    DetectorOutput, FAMILY_NATIVE_FORMAT, FAMILY_PACKER_ARCHIVE, ObfuscatorCatalog, OutputKind,
    Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::recon::{ReconConfig, ReconReport, report_bytes};

use crate::packers::{
    AspackPhaseTwoOutput, Detection as PackerDetection, DonutModuleType, FsgUnpackOutput,
    KkrunchyUnpackOutput, LoaderConfig, LoaderFamily, LoaderInspection, LoaderRecovery,
    MewUnpackOutput, MpressUnpackOutput, NspackEmulatedReport, Packer, PecompactPhaseTwoOutput,
    PetitePhase2EmulatedOutput, RecoveryField, UnpackerStatus, UpxUnpackOutput, YodasCrypterCarve,
    detect as detect_packers, recover_loader, recover_yodas_crypter_carve,
    unpack_aspack_phase2_emulated, unpack_fsg, unpack_kkrunchy, unpack_mew, unpack_mpress,
    unpack_nspack_emulated, unpack_pecompact_phase2_emulated, unpack_petite_phase2_emulated,
    unpack_upx,
};

pub const PASS_ID: PassId = "native.packer-unpack";

pub const IMAGE_PASS_ID: PassId = "native.image-classify";

const IMAGE_LAST_RESORT_CONFIDENCE: f32 = 0.55;

const IMAGE_SPECIFICITY: u16 = 70;

const _: () = assert!(
    IMAGE_LAST_RESORT_CONFIDENCE > disrobe_core::chain::SelectionPolicy::DEFAULT_MIN_CONFIDENCE,
    "a claim at or below the selection floor is dropped before ranking and the input stalls again"
);

const IMAGE_MANIFEST_PATH: &str = "native-image.manifest.json";

const PSEUDO_SOURCE_PATH: &str = "pseudo-source.json";

const MAX_AUTO_PSEUDO_IMAGE_BYTES: usize = 1024 * 1024;

const MAX_AUTO_PSEUDO_FUNCTIONS: usize = 256;

const MAX_AUTO_PSEUDO_REPORT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct NativeImageDetector;

impl Detector for NativeImageDetector {
    #[inline]
    fn id(&self) -> PassId {
        IMAGE_PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let image: StructuralFormat = linked_image_format(ctx.bytes)?;
        Some(image_verdict_for(image))
    }
}

#[derive(Debug)]
pub struct NativeImagePass;

impl Pass for NativeImagePass {
    #[inline]
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        IMAGE_META
    }

    #[inline]
    fn id(&self) -> PassId {
        IMAGE_PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &NativeImageDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let image: StructuralFormat = require_linked_image(&artifact.envelope)?;
        Ok(Artifact::new(
            Rung::Disasm,
            render_image_manifest(image, artifact.envelope.len()).into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let image: StructuralFormat = require_linked_image(&input.envelope)?;
        build_image_children(image, &input.envelope)
    }
}

pub const IMAGE_META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    IMAGE_PASS_ID,
    disrobe_core::chain::Ecosystem::Native,
    disrobe_core::chain::SupportQuality::Partial,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static NATIVE_IMAGE_PASS: NativeImagePass = NativeImagePass;

fn linked_image_format(bytes: &[u8]) -> Option<StructuralFormat> {
    match identify_by_structure(bytes)? {
        image @ (StructuralFormat::Pe
        | StructuralFormat::Elf
        | StructuralFormat::MachO
        | StructuralFormat::MachOFat) => Some(image),
        StructuralFormat::Wasm
        | StructuralFormat::Zip
        | StructuralFormat::Dex
        | StructuralFormat::JavaClass => None,
    }
}

fn require_linked_image(bytes: &[u8]) -> CoreResult<StructuralFormat> {
    linked_image_format(bytes).ok_or_else(|| {
        CoreError::PassFailure(
            "DR-NAT-0940: native.image-classify: input is not a structurally valid pe, elf or \
             mach-o image"
                .to_string(),
        )
    })
}

fn image_verdict_for(image: StructuralFormat) -> DetectVerdict {
    DetectVerdict::new(
        IMAGE_PASS_ID,
        image.label(),
        FAMILY_NATIVE_FORMAT,
        IMAGE_LAST_RESORT_CONFIDENCE,
        IMAGE_SPECIFICITY,
        vec!["structural-image-header"],
        format!(
            "structurally valid {label} image; this claim carries no ecosystem evidence, so it \
             ranks below every ecosystem detector and wins only when none of them fires",
            label = image.label()
        ),
    )
}

fn build_image_children(image: StructuralFormat, bytes: &[u8]) -> CoreResult<Vec<ChildArtifact>> {
    let mut children: Vec<ChildArtifact> = Vec::new();
    let identity: crate::sig_engine::SigReport = crate::sig_engine::analyze(bytes);
    let pseudo_report: Option<serde_json::Value> = aarch64_pseudo_report(bytes)?;
    let manifest: Vec<u8> = serialize_image_report(
        IMAGE_MANIFEST_PATH,
        &image_manifest(image, bytes.len(), &identity, pseudo_report.as_ref()),
    )?;
    push_image_terminal(&mut children, IMAGE_MANIFEST_PATH, manifest)?;
    let identity_json: Vec<u8> = serialize_image_report("identity.json", &identity)?;
    push_image_terminal(&mut children, "identity.json", identity_json)?;
    let signatures: Vec<u8> = serialize_image_report("signatures.json", &signatures_report(bytes))?;
    push_image_terminal(&mut children, "signatures.json", signatures)?;
    let symbols: crate::backend_export::SymbolMap =
        crate::backend_export::collect_recovered_symbols_with_oep(bytes, None).map_err(
            |error| {
                CoreError::PassFailure(format!(
                    "DR-NAT-0942: native.image-classify: recover symbols: {error}"
                ))
            },
        )?;
    let symbols_json: String =
        crate::backend_export::render_symbol_map_json(&symbols).map_err(|error| {
            CoreError::PassFailure(format!(
                "DR-NAT-0943: native.image-classify: serialize symbols.json: {error}"
            ))
        })?;
    push_image_terminal(&mut children, "symbols.json", symbols_json.into_bytes())?;
    let recon: ReconReport = report_bytes(bytes, None, &ReconConfig::default());
    if !recon.findings.is_empty() {
        let recon_json: Vec<u8> = serialize_image_report("recon.json", &recon)?;
        push_image_terminal(&mut children, "recon.json", recon_json)?;
    }
    if let Some(report) = pseudo_report {
        let mut pseudo_json: Vec<u8> = serialize_image_report(PSEUDO_SOURCE_PATH, &report)?;
        if pseudo_json.len() > MAX_AUTO_PSEUDO_REPORT_BYTES {
            pseudo_json = serialize_image_report(
                PSEUDO_SOURCE_PATH,
                &serde_json::json!({
                    "schema": "disrobe.native.pseudo-source/v1",
                    "run": false,
                    "reason": "pseudo-source report exceeds the bounded auto output",
                    "report_bytes": pseudo_json.len(),
                    "report_byte_limit": MAX_AUTO_PSEUDO_REPORT_BYTES,
                }),
            )?;
        }
        push_image_terminal(&mut children, PSEUDO_SOURCE_PATH, pseudo_json)?;
    }
    Ok(children)
}

fn aarch64_pseudo_report(bytes: &[u8]) -> CoreResult<Option<serde_json::Value>> {
    if crate::disasm_ir::image_arch(bytes) != Some(crate::arch::Arch::Aarch64) {
        return Ok(None);
    }
    if bytes.len() > MAX_AUTO_PSEUDO_IMAGE_BYTES {
        return Ok(Some(serde_json::json!({
            "schema": "disrobe.native.pseudo-source/v1",
            "run": false,
            "reason": "aarch64 image exceeds the bounded auto pseudo-source input",
            "image_bytes": bytes.len(),
            "image_byte_limit": MAX_AUTO_PSEUDO_IMAGE_BYTES,
        })));
    }
    let payload: disrobe_ir::payload::DisasmPayload = crate::disasm_ir::build_disasm_payload(bytes)
        .map_err(|error: crate::Error| {
            CoreError::PassFailure(format!(
                "DR-NAT-0944: native.image-classify: build aarch64 function inventory: {error}"
            ))
        })?;
    let spans: Vec<crate::disasm_ir::FunctionSpan> =
        crate::disasm_ir::function_spans(&payload, crate::arch::Arch::Aarch64);
    if spans.len() > MAX_AUTO_PSEUDO_FUNCTIONS {
        return Ok(Some(serde_json::json!({
            "schema": "disrobe.native.pseudo-source/v1",
            "run": false,
            "reason": "aarch64 function inventory exceeds the bounded auto pseudo-source sweep",
            "functions": spans.len(),
            "function_limit": MAX_AUTO_PSEUDO_FUNCTIONS,
        })));
    }
    let mut recovered: Vec<serde_json::Value> = Vec::with_capacity(spans.len());
    let mut unrecovered: Vec<serde_json::Value> = Vec::new();
    for span in spans {
        let code: Vec<u8> = payload
            .instructions
            .iter()
            .filter(|instruction: &&disrobe_ir::payload::DisasmInstruction| {
                instruction.offset >= span.address && instruction.offset < span.end
            })
            .flat_map(|instruction: &disrobe_ir::payload::DisasmInstruction| {
                instruction.bytes.iter().copied()
            })
            .collect();
        match crate::pseudo_c::recover_aarch64_function(&code, span.address) {
            Ok(function) => recovered.push(serde_json::json!({
                "name": span.name,
                "address": span.address,
                "source": function.source,
                "rust_source": function.rust_source,
            })),
            Err(error) => unrecovered.push(serde_json::json!({
                "name": span.name,
                "address": span.address,
                "reason": error.to_string(),
            })),
        }
    }
    Ok(Some(serde_json::json!({
        "schema": "disrobe.native.pseudo-source/v1",
        "run": true,
        "functions_recovered": recovered.len(),
        "functions_unrecovered": unrecovered.len(),
        "recovered": recovered,
        "unrecovered": unrecovered,
    })))
}

fn serialize_image_report<T: serde::Serialize>(path: &str, value: &T) -> CoreResult<Vec<u8>> {
    serde_json::to_vec_pretty(value).map_err(|error: serde_json::Error| {
        CoreError::PassFailure(format!(
            "DR-NAT-0941: native.image-classify: serialize {path}: {error}"
        ))
    })
}

fn image_manifest(
    image: StructuralFormat,
    byte_len: usize,
    identity: &crate::sig_engine::SigReport,
    pseudo_report: Option<&serde_json::Value>,
) -> serde_json::Value {
    let pseudo_run: bool = pseudo_report
        .and_then(|report: &serde_json::Value| report.get("run"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let pseudo_reason: &str = pseudo_report
        .and_then(|report: &serde_json::Value| report.get("reason"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("the bounded auto pseudo-source sweep is available only for aarch64 images");
    serde_json::json!({
        "schema": "disrobe.native.image-classify/v1",
        "structural_format": image.label(),
        "image_bytes": byte_len,
        "compiler": identity.compiler,
        "linker": identity.linker,
        "entropy": identity.entropy,
        "control_flow_recovery_sweep": {
            "run": pseudo_run,
            "reason": if pseudo_run {
                serde_json::Value::Null
            } else {
                pseudo_reason.into()
            },
        },
    })
}

fn render_image_manifest(image: StructuralFormat, byte_len: usize) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(64);
    s.push_str("native.image-classify\n");
    let _ = writeln!(s, "format={label} bytes={byte_len}", label = image.label());
    s
}

#[derive(Debug)]
pub struct PackerDetector;

impl Detector for PackerDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let dets: Vec<PackerDetection> = detect_packers(ctx.bytes);
        let pick: PackerDetection = highest_native_owned_priority(dets)?;
        Some(verdict_for(&pick))
    }
}

#[derive(Debug)]
pub struct PackerPass;

impl Pass for PackerPass {
    #[inline]
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        META
    }
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &PackerDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let recovery: PackerRecovery = recover(artifact)?;
        Ok(Artifact::new(
            Rung::Disasm,
            render_manifest(&recovery).into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let recovery: PackerRecovery = recover(input)?;
        build_children(&recovery)
    }
}

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Native,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static PACKER_PASS: PackerPass = PackerPass;

#[derive(Debug)]
struct PackerRecovery {
    packer: Packer,
    image: RecoveryField<Vec<u8>>,
    oep_va: Option<u64>,
    loader: Option<LoaderInspection>,
}

fn recover(artifact: &Artifact) -> CoreResult<PackerRecovery> {
    if let Ok(loader) = recover_loader(&artifact.envelope) {
        return loader_packer_recovery(loader);
    }
    let dets: Vec<PackerDetection> = detect_packers(&artifact.envelope);
    let Some(pick): Option<PackerDetection> = highest_priority(dets) else {
        return Err(CoreError::PassFailure(
            "DR-NAT-0901: native.packer-unpack: no packer signature in artifact".to_string(),
        ));
    };
    dispatch_unpack(pick.packer, artifact)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveredChildDescriptor {
    path: &'static str,
    hint: Option<&'static str>,
}

const RECOVERED_IMAGE: RecoveredChildDescriptor = RecoveredChildDescriptor {
    path: "recovered-image.bin",
    hint: None,
};

fn build_children(recovery: &PackerRecovery) -> CoreResult<Vec<ChildArtifact>> {
    let mut children: Vec<ChildArtifact> = Vec::new();
    let known_image: Option<(&[u8], RecoveredChildDescriptor)> = match &recovery.image {
        RecoveryField::Known { value } => {
            let descriptor: RecoveredChildDescriptor = recovered_child_descriptor(recovery);
            children.push(child(0, descriptor.path, descriptor.hint, value.clone()));
            Some((value.as_slice(), descriptor))
        }
        RecoveryField::Unknown { .. } => None,
    };

    let manifest: Vec<u8> = serde_json::to_vec_pretty(&unpack_manifest(recovery)).map_err(
        |error: serde_json::Error| {
            CoreError::PassFailure(format!(
                "DR-NAT-0933: native.packer-unpack: manifest serialization failed: {error}"
            ))
        },
    )?;
    push_terminal(&mut children, "packer-unpack.manifest.json", manifest);
    let Some((image, descriptor)): Option<(&[u8], RecoveredChildDescriptor)> = known_image else {
        return Ok(children);
    };
    let identity: crate::sig_engine::SigReport = crate::sig_engine::analyze(image);
    if let Ok(json) = serde_json::to_vec_pretty(&identity) {
        push_terminal(&mut children, "identity.json", json);
    }
    if let Ok(json) = serde_json::to_vec_pretty(&signatures_report(image)) {
        push_terminal(&mut children, "signatures.json", json);
    }
    if let Ok(map) =
        crate::backend_export::collect_recovered_symbols_with_oep(image, recovery.oep_va)
        && let Ok(json) = crate::backend_export::render_symbol_map_json(&map)
    {
        push_terminal(&mut children, "symbols.json", json.into_bytes());
    }
    if let Some(report) = crate::pass::analyze_deobf_report(image)
        && let Ok(json) = serde_json::to_vec_pretty(&report)
    {
        push_terminal(&mut children, "deobf.json", json);
    }
    let recon: ReconReport = report_bytes(image, Some(descriptor.path), &ReconConfig::default());
    if !recon.findings.is_empty()
        && let Ok(json) = serde_json::to_vec_pretty(&recon)
    {
        push_terminal(&mut children, "recon.json", json);
    }
    Ok(children)
}

fn recovered_child_descriptor(recovery: &PackerRecovery) -> RecoveredChildDescriptor {
    recovery
        .loader
        .as_ref()
        .map_or(RECOVERED_IMAGE, loader_child_descriptor)
}

fn loader_child_descriptor(inspection: &LoaderInspection) -> RecoveredChildDescriptor {
    if inspection.family == LoaderFamily::Srdi {
        return RecoveredChildDescriptor {
            path: RECOVERED_IMAGE.path,
            hint: None,
        };
    }
    let LoaderConfig::Donut(config) = &inspection.config else {
        return RecoveredChildDescriptor {
            path: "recovered-module.bin",
            hint: None,
        };
    };
    let RecoveryField::Known { value: module_type } = &config.module_type else {
        return RecoveredChildDescriptor {
            path: "recovered-module.bin",
            hint: None,
        };
    };
    match module_type {
        DonutModuleType::ManagedDll => RecoveredChildDescriptor {
            path: "recovered-module.dll",
            hint: None,
        },
        DonutModuleType::ManagedExe => RecoveredChildDescriptor {
            path: "recovered-module.exe",
            hint: None,
        },
        DonutModuleType::NativeDll => RecoveredChildDescriptor {
            path: RECOVERED_IMAGE.path,
            hint: None,
        },
        DonutModuleType::NativeExe => RecoveredChildDescriptor {
            path: RECOVERED_IMAGE.path,
            hint: None,
        },
        DonutModuleType::VbScript => RecoveredChildDescriptor {
            path: "recovered-module.vbs",
            hint: None,
        },
        DonutModuleType::JavaScript => RecoveredChildDescriptor {
            path: "recovered-module.js",
            hint: None,
        },
        DonutModuleType::Xsl => RecoveredChildDescriptor {
            path: "recovered-module.xsl",
            hint: None,
        },
        DonutModuleType::Unknown { .. } => RecoveredChildDescriptor {
            path: "recovered-module.bin",
            hint: None,
        },
    }
}

fn child(index: u32, path: &str, hint: Option<&str>, bytes: Vec<u8>) -> ChildArtifact {
    ChildArtifact {
        handle: ChildHandle {
            artifact_index: index,
            relative_path: path.to_string(),
            hint: hint.map(str::to_string),
        },
        bytes,
    }
}

fn push_terminal(children: &mut Vec<ChildArtifact>, path: &str, bytes: Vec<u8>) {
    let index: u32 = u32::try_from(children.len()).unwrap_or(u32::MAX);
    children.push(child(index, path, Some(TERMINAL_HINT), bytes));
}

fn push_image_terminal(
    children: &mut Vec<ChildArtifact>,
    path: &str,
    bytes: Vec<u8>,
) -> CoreResult<()> {
    let index: u32 = u32::try_from(children.len()).map_err(|error| {
        CoreError::PassFailure(format!(
            "DR-NAT-0944: native.image-classify: child count is not representable: {error}"
        ))
    })?;
    children.push(child(index, path, Some(TERMINAL_HINT), bytes));
    Ok(())
}

fn signatures_report(bytes: &[u8]) -> serde_json::Value {
    let crypto: Vec<crate::crypto_consts::CryptoConstHit> =
        crate::crypto_consts::detect_crypto_constants(bytes);
    let obfuscators: Vec<crate::obfuscators::ObfuscatorHit> = crate::obfuscators::detect(bytes);
    serde_json::json!({
        "schema": "disrobe.native.signatures/v1",
        "crypto_constants": crypto,
        "obfuscators": obfuscators,
    })
}

fn unpack_manifest(recovery: &PackerRecovery) -> serde_json::Value {
    let (recovered_image, recovered_image_bytes, recovery_status): (
        Option<&str>,
        Option<usize>,
        serde_json::Value,
    ) = match &recovery.image {
        RecoveryField::Known { value } => {
            let descriptor: RecoveredChildDescriptor = recovered_child_descriptor(recovery);
            (
                Some(descriptor.path),
                Some(value.len()),
                serde_json::json!({
                    "status": "known",
                    "path": descriptor.path,
                    "hint": descriptor.hint,
                    "bytes": value.len(),
                }),
            )
        }
        RecoveryField::Unknown { reason } => (
            None,
            None,
            serde_json::json!({
                "status": "unknown",
                "reason": reason,
            }),
        ),
    };
    serde_json::json!({
        "schema": "disrobe.native.packer-unpack/v1",
        "packer": recovery.packer.label(),
        "recovered_image": recovered_image,
        "recovered_image_bytes": recovered_image_bytes,
        "recovered_oep_va": recovery.oep_va,
        "recovery": recovery_status,
        "loader": recovery.loader,
    })
}

fn render_manifest(recovery: &PackerRecovery) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(128);
    s.push_str("native.packer-unpack\n");
    match &recovery.image {
        RecoveryField::Known { value } => {
            let _ = writeln!(
                s,
                "packer={label} recovery=known recovered_bytes={n} oep_va={oep:?}",
                label = recovery.packer.label(),
                n = value.len(),
                oep = recovery.oep_va,
            );
        }
        RecoveryField::Unknown { reason } => {
            let _ = writeln!(
                s,
                "packer={label} recovery=unknown reason={reason}",
                label = recovery.packer.label(),
            );
        }
    }
    s
}

fn dispatch_unpack(packer: Packer, artifact: &Artifact) -> CoreResult<PackerRecovery> {
    match packer.unpacker_status() {
        UnpackerStatus::Implemented => run_rust_unpacker(packer, artifact),
        UnpackerStatus::StubEvalPending => Err(CoreError::PassFailure(format!(
            "DR-NAT-0902: native.packer-unpack: {label} detected; stub emulator validated against a \
             synthetic stub, real packed-sample recovery unproven (detection is production-grade, \
             byte recovery on a captured sample not yet confirmed)",
            label = packer.label(),
        ))),
        UnpackerStatus::DelegatedToDotnet => Err(CoreError::PassFailure(format!(
            "DR-NAT-0930: native.packer-unpack: {label} is a managed CLR wrapper; route this \
             image through dotnet.classify for metadata, strings, constants, and IL body recovery",
            label = packer.label(),
        ))),
        UnpackerStatus::DetectOnly => Err(CoreError::PassFailure(format!(
            "DR-NAT-0907: native.packer-unpack: {label} is detect-only (crypter/loader family \
             without a deterministic unpack path)",
            label = packer.label(),
        ))),
        UnpackerStatus::GreyZoneDetectOnly => Err(CoreError::PassFailure(format!(
            "DR-NAT-0908: native.packer-unpack: {label} is a grey-zone protector; detection-only \
             per docs/legal stance (no unpack)",
            label = packer.label(),
        ))),
        UnpackerStatus::GreyZoneDetectAndCarve => Err(CoreError::PassFailure(format!(
            "DR-NAT-0909: native.packer-unpack: {label} is a grey-zone protector; \
             detect-and-carve only, original code is virtualized and not recoverable by unpacking",
            label = packer.label(),
        ))),
    }
}

fn run_rust_unpacker(packer: Packer, artifact: &Artifact) -> CoreResult<PackerRecovery> {
    let packed: &[u8] = &artifact.envelope;
    if matches!(packer, Packer::Donut | Packer::Srdi) {
        let out: LoaderRecovery =
            recover_loader(packed).map_err(|e| pass_err("DR-NAT-0931", packer, &e))?;
        return loader_packer_recovery(out);
    }
    let (recovered, oep_va, loader): (Vec<u8>, Option<u64>, Option<LoaderInspection>) = match packer
    {
        Packer::Upx => {
            let out: UpxUnpackOutput =
                unpack_upx(packed).map_err(|e| pass_err("DR-NAT-0917", packer, &e))?;
            (out.recovered_image, None, None)
        }
        Packer::Petite => {
            let out: PetitePhase2EmulatedOutput = unpack_petite_phase2_emulated(packed)
                .map_err(|e| pass_err("DR-NAT-0910", packer, &e))?;
            require_credible_oep(packer, out.oep_estimate)?;
            (out.recovered_image, out.oep_estimate, None)
        }
        Packer::Nspack => {
            let report: NspackEmulatedReport =
                unpack_nspack_emulated(packed).map_err(|e| pass_err("DR-NAT-0911", packer, &e))?;
            (report.decompressed_image, None, None)
        }
        Packer::Mew => {
            let out: MewUnpackOutput =
                unpack_mew(packed).map_err(|e| pass_err("DR-NAT-0912", packer, &e))?;
            (out.raw_image, None, None)
        }
        Packer::Fsg => {
            let out: FsgUnpackOutput =
                unpack_fsg(packed).map_err(|e| pass_err("DR-NAT-0913", packer, &e))?;
            (out.raw_image, None, None)
        }
        Packer::Mpress => {
            let out: MpressUnpackOutput =
                unpack_mpress(packed).map_err(|e| pass_err("DR-NAT-0916", packer, &e))?;
            (out.decompressed_image, None, None)
        }
        Packer::YodasCrypter => {
            let carve: YodasCrypterCarve = recover_yodas_crypter_carve(packed)
                .map_err(|e| pass_err("DR-NAT-0918", packer, &e))?;
            (carve.recovered_image, None, None)
        }
        Packer::AsPack => {
            let out: AspackPhaseTwoOutput = unpack_aspack_phase2_emulated(packed, None)
                .map_err(|e| pass_err("DR-NAT-0919", packer, &e))?;
            require_credible_oep(packer, out.oep_estimate)?;
            (out.recovered_memory_image, out.oep_estimate, None)
        }
        Packer::PeCompact => {
            let out: PecompactPhaseTwoOutput = unpack_pecompact_phase2_emulated(packed, None)
                .map_err(|e| pass_err("DR-NAT-0920", packer, &e))?;
            require_credible_oep(packer, out.oep_estimate)?;
            (out.recovered_memory_image, out.oep_estimate, None)
        }
        Packer::Kkrunchy => {
            let out: KkrunchyUnpackOutput =
                unpack_kkrunchy(packed).map_err(|e| pass_err("DR-NAT-0921", packer, &e))?;
            (out.packed_payload, None, None)
        }
        other => {
            return Err(CoreError::PassFailure(format!(
                "DR-NAT-0914: native.packer-unpack: {label} reports Implemented status but no \
                 dispatch arm is wired - fix run_rust_unpacker",
                label = other.label(),
            )));
        }
    };
    if recovered.is_empty() {
        return Err(CoreError::PassFailure(format!(
            "DR-NAT-0915: native.packer-unpack: {label} unpacker produced no bytes",
            label = packer.label(),
        )));
    }
    Ok(PackerRecovery {
        packer,
        image: RecoveryField::Known { value: recovered },
        oep_va,
        loader,
    })
}

fn loader_packer_recovery(out: LoaderRecovery) -> CoreResult<PackerRecovery> {
    let LoaderRecovery { inspection, module } = out;
    let packer: Packer = match inspection.family {
        crate::packers::LoaderFamily::Donut => Packer::Donut,
        crate::packers::LoaderFamily::Srdi => Packer::Srdi,
    };
    if matches!(&module, RecoveryField::Known { value } if value.is_empty()) {
        return Err(CoreError::PassFailure(format!(
            "DR-NAT-0915: native.packer-unpack: {label} unpacker produced no bytes",
            label = packer.label(),
        )));
    }
    Ok(PackerRecovery {
        packer,
        image: module,
        oep_va: None,
        loader: Some(inspection),
    })
}

fn require_credible_oep(packer: Packer, oep_estimate: Option<u64>) -> CoreResult<()> {
    if oep_estimate.is_some() {
        return Ok(());
    }
    Err(CoreError::PassFailure(format!(
        "DR-NAT-0928: native.packer-unpack: {label} detected and unpack attempted, but the stub \
         emulator did not reach a credible original entry point; reporting detected + attempted \
         rather than emitting a partial memory image as a recovery",
        label = packer.label(),
    )))
}

fn pass_err(code: &str, packer: Packer, err: &crate::error::Error) -> CoreError {
    CoreError::PassFailure(format!(
        "{code}: native.packer-unpack: {label} unpack failed: {err}",
        label = packer.label(),
    ))
}

fn highest_priority(mut dets: Vec<PackerDetection>) -> Option<PackerDetection> {
    if dets.is_empty() {
        return None;
    }
    dets.sort_by_key(|d: &PackerDetection| priority_rank(d.packer));
    Some(dets.remove(0))
}

fn highest_native_owned_priority(dets: Vec<PackerDetection>) -> Option<PackerDetection> {
    let owned: Vec<PackerDetection> = dets
        .into_iter()
        .filter(|d: &PackerDetection| {
            d.packer.unpacker_status() != UnpackerStatus::DelegatedToDotnet
        })
        .collect();
    highest_priority(owned)
}

const fn priority_rank(p: Packer) -> u8 {
    match p {
        Packer::Donut => 0,
        Packer::Srdi => 1,
        Packer::Upx => 2,
        Packer::Mpress => 3,
        Packer::Petite => 4,
        Packer::AsPack => 5,
        Packer::AsProtect => 6,
        _ => 9,
    }
}

fn verdict_for(d: &PackerDetection) -> DetectVerdict {
    let format_tag: &'static str = match d.packer {
        Packer::Donut => "donut",
        Packer::Srdi => "srdi",
        Packer::Upx => "upx",
        Packer::Mpress => "mpress",
        Packer::Petite => "petite",
        Packer::AsPack => "aspack",
        Packer::AsProtect => "asprotect",
        Packer::Fsg => "fsg",
        Packer::Mew => "mew",
        Packer::PeCompact => "pecompact",
        Packer::PolyCryptor => "polycryptor",
        Packer::Themida => "themida",
        Packer::VmProtect => "vmprotect",
        Packer::EnigmaProtector => "enigma",
        Packer::Obsidium => "obsidium",
        Packer::WinLicense => "winlicense",
        Packer::YodasCrypter => "yodas-crypter",
        Packer::YodasProtector => "yodas-protector",
        _ => "native-packer",
    };
    let confidence: f32 = match d.confidence {
        crate::packers::Confidence::High => 0.96,
        crate::packers::Confidence::Medium => 0.80,
        crate::packers::Confidence::Low => 0.60,
    };
    let specificity: u16 = 20;
    DetectVerdict::new(
        PASS_ID,
        format_tag,
        FAMILY_PACKER_ARCHIVE,
        confidence,
        specificity,
        vec![if matches!(d.packer, Packer::Donut | Packer::Srdi) {
            "loader-config"
        } else {
            "packer-section-magic"
        }],
        format!(
            "packer={label} note={note}",
            label = d.packer.label(),
            note = d.note
        ),
    )
}

#[derive(Debug)]
pub struct PackerEntry {
    pub packer: Packer,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
}

const fn quality_of(status: UnpackerStatus) -> SupportQuality {
    match status {
        UnpackerStatus::Implemented => SupportQuality::Full,
        UnpackerStatus::StubEvalPending | UnpackerStatus::DelegatedToDotnet => {
            SupportQuality::Partial
        }
        UnpackerStatus::DetectOnly
        | UnpackerStatus::GreyZoneDetectOnly
        | UnpackerStatus::GreyZoneDetectAndCarve => SupportQuality::DetectOnly,
    }
}

impl CatalogEntry for PackerEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.packer.label()
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.display_name
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        if self.packer == Packer::Donut {
            SupportQuality::Partial
        } else {
            quality_of(self.packer.unpacker_status())
        }
    }
}

const CATALOG_COUNT: usize = 27;

static CATALOG: [PackerEntry; CATALOG_COUNT] = [
    PackerEntry {
        packer: Packer::Donut,
        display_name: "Donut",
        aliases: &["go-donut"],
    },
    PackerEntry {
        packer: Packer::Srdi,
        display_name: "sRDI",
        aliases: &["shellcode-rdi"],
    },
    PackerEntry {
        packer: Packer::Upx,
        display_name: "UPX",
        aliases: &["ultimate-packer"],
    },
    PackerEntry {
        packer: Packer::AsPack,
        display_name: "ASPack",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::AsProtect,
        display_name: "ASProtect",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::Petite,
        display_name: "Petite",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::Mpress,
        display_name: "MPRESS",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::Fsg,
        display_name: "FSG",
        aliases: &["fast-small-good"],
    },
    PackerEntry {
        packer: Packer::Morphine,
        display_name: "Morphine",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::PeCompact,
        display_name: "PECompact",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::YodasCrypter,
        display_name: "Yoda's Crypter",
        aliases: &["yc"],
    },
    PackerEntry {
        packer: Packer::YodasProtector,
        display_name: "Yoda's Protector",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::NPack,
        display_name: "nPack",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::Nspack,
        display_name: "NSPack",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::NeoLite,
        display_name: "NeoLite",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::Mew,
        display_name: "MEW",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::Kkrunchy,
        display_name: "kkrunchy",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::PolyCryptor,
        display_name: "PolyCryptor",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::PeProtector,
        display_name: "PE-Protector",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::PeLock,
        display_name: "PELock",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::VmProtect,
        display_name: "VMProtect",
        aliases: &["vmp"],
    },
    PackerEntry {
        packer: Packer::Themida,
        display_name: "Themida / WinLicense",
        aliases: &["winlicense-vm"],
    },
    PackerEntry {
        packer: Packer::EnigmaProtector,
        display_name: "Enigma Protector",
        aliases: &["enigma"],
    },
    PackerEntry {
        packer: Packer::Armadillo,
        display_name: "Armadillo",
        aliases: &["software-passport"],
    },
    PackerEntry {
        packer: Packer::Obsidium,
        display_name: "Obsidium",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::WinLicense,
        display_name: "WinLicense",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::WarzoneCrypter,
        display_name: "Warzone Crypter",
        aliases: &["warzone-rat-crypter"],
    },
];

impl ObfuscatorCatalog for PackerDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static PackerEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let dets: Vec<PackerDetection> = detect_packers(ctx.bytes);
        let pick: PackerDetection = highest_native_owned_priority(dets)?;
        let confidence: f32 = match pick.confidence {
            crate::packers::Confidence::High => 0.96,
            crate::packers::Confidence::Medium => 0.80,
            crate::packers::Confidence::Low => 0.60,
        };
        Some(DetectorOutput::new(
            pick.packer.label(),
            confidence,
            vec![pick.note],
        ))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use disrobe_core::chain::ConfidenceBand;

    use super::*;
    use crate::packers::{
        ByteRegion, DonutConfig, DonutEntropy, LoaderArchitecture, LoaderVariant,
        WrappedModuleFormat, WrappedModuleMetadata,
    };

    const KNOWN_DONUT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/loader_generators/known.go-donut.bin"
    ));
    const FSG_PACKED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../corpus/native/packers/fsg/Hash.packed.fsg.exe"
    ));

    const PLAIN_PE: &str = "native/packers/aspack/AccessEnum.original.exe";
    const PLAIN_ELF: &str = "native/discovery/disc.unstripped.elf";

    fn image_ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    fn corpus_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(relative)
    }

    fn read_fixture(relative: &str) -> Vec<u8> {
        let path: PathBuf = corpus_path(relative);
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{} is tracked in git and this case grades nothing without it, so its absence is \
                 a damaged checkout rather than an optional dependency: {e}",
                path.display()
            )
        })
    }

    #[test]
    fn image_detector_id_is_stable() {
        assert_eq!(NativeImageDetector.id(), IMAGE_PASS_ID);
        assert_eq!(NATIVE_IMAGE_PASS.id(), IMAGE_PASS_ID);
        assert_eq!(IMAGE_META.id, IMAGE_PASS_ID);
    }

    #[test]
    fn image_detector_claims_a_real_unpacked_pe() {
        let bytes: Vec<u8> = read_fixture(PLAIN_PE);
        let v: DetectVerdict = Detector::detect(&NativeImageDetector, &image_ctx(&bytes))
            .expect("plain pe must be claimed");
        assert_eq!(v.format_tag, "pe");
        assert_eq!(v.family, FAMILY_NATIVE_FORMAT);
    }

    #[test]
    fn image_detector_claims_a_real_unpacked_elf() {
        let bytes: Vec<u8> = read_fixture(PLAIN_ELF);
        let v: DetectVerdict = Detector::detect(&NativeImageDetector, &image_ctx(&bytes))
            .expect("plain elf must be claimed");
        assert_eq!(v.format_tag, "elf");
        assert_eq!(v.family, FAMILY_NATIVE_FORMAT);
    }

    #[test]
    fn the_image_verdict_never_short_circuits_the_detector_sweep() {
        let bytes: Vec<u8> = read_fixture(PLAIN_PE);
        let v: DetectVerdict = Detector::detect(&NativeImageDetector, &image_ctx(&bytes))
            .expect("plain pe must be claimed");
        assert!(
            v.band != ConfidenceBand::High || v.specificity > 30,
            "PassRegistry::run_all stops the sweep on the first high-band verdict with \
             specificity <= 30. This pass sorts before nativelang, scriptlang and swift-objc, so \
             a decisive verdict here would silence every one of them. Got band={band:?} \
             specificity={spec}",
            band = v.band,
            spec = v.specificity,
        );
    }

    #[test]
    fn a_weaker_ecosystem_claim_still_outranks_the_image_claim() {
        let bytes: Vec<u8> = read_fixture(PLAIN_PE);
        let ours: DetectVerdict = Detector::detect(&NativeImageDetector, &image_ctx(&bytes))
            .expect("plain pe must be claimed");
        for (rival_id, rival_confidence, rival_specificity) in [
            ("nativelang.classify", 0.60_f32, 30_u16),
            ("go.classify", 0.78, 38),
            ("swift-objc.classify", 0.95, 40),
            ("dotnet.classify", 0.95, 25),
        ] {
            let rival: DetectVerdict = DetectVerdict::new(
                rival_id,
                "rival",
                FAMILY_NATIVE_FORMAT,
                rival_confidence,
                rival_specificity,
                vec![],
                String::new(),
            );
            assert_eq!(
                disrobe_core::chain::compare(&rival, &ours),
                std::cmp::Ordering::Greater,
                "{rival_id} at its weakest published confidence must still beat this fallback",
            );
        }
    }

    #[test]
    fn the_image_detector_abstains_on_every_other_structural_format() {
        for (relative, rejected) in [
            (
                "jvm/allatori/AllatoriCaller.class",
                StructuralFormat::JavaClass,
            ),
            (
                "jvm/obfuscators/jbco/Sample-clean.jar",
                StructuralFormat::Zip,
            ),
            ("wasm/wat/function_refs.wasm", StructuralFormat::Wasm),
            ("jvm/dex/Hello.dex", StructuralFormat::Dex),
        ] {
            let bytes: Vec<u8> = read_fixture(relative);
            assert_eq!(
                identify_by_structure(&bytes),
                Some(rejected),
                "{relative} must still be identified as {rejected:?}; if the fixture stopped \
                 parsing this case would pass while proving nothing",
            );
            assert!(
                Detector::detect(&NativeImageDetector, &image_ctx(&bytes)).is_none(),
                "{relative} is not a native image and must not be claimed by this pass",
            );
        }
    }

    #[test]
    fn the_image_detector_abstains_on_bytes_that_are_no_image_at_all() {
        for bytes in [vec![0u8; 4096], vec![0x55u8; 1024], b"MZ".to_vec()] {
            assert!(Detector::detect(&NativeImageDetector, &image_ctx(&bytes)).is_none());
        }
    }

    #[test]
    fn the_image_pass_refuses_bytes_that_are_not_a_native_image() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 512], [0u8; 32]);
        let err: CoreError = NATIVE_IMAGE_PASS.run(&a).expect_err("must refuse");
        assert!(format!("{err}").contains("DR-NAT-0940"));
        let err: CoreError = NATIVE_IMAGE_PASS
            .extract_children(&a)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("DR-NAT-0940"));
    }

    fn assert_image_sidecars(relative: &str, expected_format: &str) {
        let bytes: Vec<u8> = read_fixture(relative);
        let byte_len: usize = bytes.len();
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);

        let out: Artifact = NATIVE_IMAGE_PASS.run(&a).expect("run must succeed");
        assert!(!out.envelope.is_empty());

        let children: Vec<ChildArtifact> = NATIVE_IMAGE_PASS
            .extract_children(&a)
            .expect("child extraction must succeed");
        for sidecar in [IMAGE_MANIFEST_PATH, "identity.json", "signatures.json"] {
            let child: &ChildArtifact = children
                .iter()
                .find(|c: &&ChildArtifact| c.handle.relative_path == sidecar)
                .unwrap_or_else(|| panic!("auto must emit the {sidecar} sidecar for {relative}"));
            assert_eq!(
                child.handle.hint.as_deref(),
                Some(TERMINAL_HINT),
                "{sidecar} is a report, not a re-chained input; a non-terminal child would feed \
                 this pass's own output back into the chain",
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&child.bytes).expect("sidecar must be valid json");
            assert!(parsed.is_object());
        }
        assert!(
            children
                .iter()
                .all(|c: &ChildArtifact| c.handle.hint.as_deref() == Some(TERMINAL_HINT)),
            "every child must be terminal, otherwise the chain re-detects the same image and the \
             cycle guard turns a real recovery into a Cycle verdict",
        );

        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == IMAGE_MANIFEST_PATH)
            .expect("manifest present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest json");
        assert_eq!(parsed["structural_format"].as_str(), Some(expected_format));
        assert_eq!(parsed["image_bytes"].as_u64(), Some(byte_len as u64));

        let symbols: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "symbols.json")
            .unwrap_or_else(|| {
                panic!("{relative} carries a symbol table, so symbols.json must be emitted")
            });
        assert!(
            symbols.bytes.len() > 2,
            "symbols.json must carry the recovered symbol map, not an empty document",
        );
    }

    #[test]
    fn every_image_report_stays_well_under_a_second() {
        let bytes: Vec<u8> = read_fixture(PLAIN_PE);
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let started: std::time::Instant = std::time::Instant::now();
        let children: Vec<ChildArtifact> = NATIVE_IMAGE_PASS
            .extract_children(&a)
            .expect("child extraction must succeed");
        let elapsed: std::time::Duration = started.elapsed();
        assert!(!children.is_empty());
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "this pass claims the widest input class in the tool, so every report it emits must \
             stay cheap. The control-flow recovery sweep was measured at 47s for this 175 kb \
             image and 150s for a 2.4 mb image, which is why it is not on this path. Took \
             {elapsed:?}",
        );
    }

    #[test]
    fn a_real_pe_yields_real_image_sidecars() {
        assert_image_sidecars(PLAIN_PE, "pe");
    }

    #[test]
    fn a_real_elf_yields_real_image_sidecars() {
        assert_image_sidecars(PLAIN_ELF, "elf");
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(PackerDetector.id(), PASS_ID);
    }

    #[test]
    fn donut_module_types_select_child_paths_and_hints() {
        let cases: [(DonutModuleType, RecoveredChildDescriptor); 8] = [
            (
                DonutModuleType::ManagedDll,
                RecoveredChildDescriptor {
                    path: "recovered-module.dll",
                    hint: None,
                },
            ),
            (
                DonutModuleType::ManagedExe,
                RecoveredChildDescriptor {
                    path: "recovered-module.exe",
                    hint: None,
                },
            ),
            (
                DonutModuleType::NativeDll,
                RecoveredChildDescriptor {
                    path: RECOVERED_IMAGE.path,
                    hint: None,
                },
            ),
            (
                DonutModuleType::NativeExe,
                RecoveredChildDescriptor {
                    path: RECOVERED_IMAGE.path,
                    hint: None,
                },
            ),
            (
                DonutModuleType::VbScript,
                RecoveredChildDescriptor {
                    path: "recovered-module.vbs",
                    hint: None,
                },
            ),
            (
                DonutModuleType::JavaScript,
                RecoveredChildDescriptor {
                    path: "recovered-module.js",
                    hint: None,
                },
            ),
            (
                DonutModuleType::Xsl,
                RecoveredChildDescriptor {
                    path: "recovered-module.xsl",
                    hint: None,
                },
            ),
            (
                DonutModuleType::Unknown { value: 99 },
                RecoveredChildDescriptor {
                    path: "recovered-module.bin",
                    hint: None,
                },
            ),
        ];
        for case in cases {
            let (module_type, expected): (DonutModuleType, RecoveredChildDescriptor) = case;
            let inspection: LoaderInspection = donut_inspection(module_type);
            assert_eq!(loader_child_descriptor(&inspection), expected);
        }
    }

    #[test]
    fn srdi_recovered_pe_remains_available_to_downstream_passes() {
        let inspection: LoaderInspection = LoaderInspection {
            family: LoaderFamily::Srdi,
            variant: LoaderVariant::SrdiV1,
            architecture: LoaderArchitecture::X64,
            config_region: ByteRegion {
                offset: 0,
                length: 69,
            },
            config: LoaderConfig::Srdi(crate::packers::SrdiConfig {
                function_hash: 0,
                flags: 0,
                user_data_region: RecoveryField::Known {
                    value: ByteRegion {
                        offset: 69,
                        length: 0,
                    },
                },
            }),
            wrapped_module: WrappedModuleMetadata {
                region: RecoveryField::Known {
                    value: ByteRegion {
                        offset: 69,
                        length: 1,
                    },
                },
                format: RecoveryField::Known {
                    value: crate::packers::WrappedModuleFormat::Pe32Plus,
                },
                stored_size: RecoveryField::Known { value: 1 },
                original_size: RecoveryField::Known { value: 1 },
                entry_point_rva: RecoveryField::Known { value: 1 },
            },
        };
        assert_eq!(
            loader_child_descriptor(&inspection),
            RecoveredChildDescriptor {
                path: RECOVERED_IMAGE.path,
                hint: None,
            }
        );
    }

    #[test]
    fn donut_script_payloads_remain_typed_but_unrecovered() {
        #[derive(Clone, Copy)]
        struct ScriptCase {
            payload: &'static [u8],
            module_type: DonutModuleType,
            format: WrappedModuleFormat,
            label: &'static str,
            serialized_type: &'static str,
            expected_path: &'static str,
        }

        let cases: [ScriptCase; 6] = [
            ScriptCase {
                payload: b"const answer = 42;",
                module_type: DonutModuleType::JavaScript,
                format: WrappedModuleFormat::JavaScript,
                label: "javascript",
                serialized_type: "java-script",
                expected_path: "recovered-module.js",
            },
            ScriptCase {
                payload: b"const = ;",
                module_type: DonutModuleType::JavaScript,
                format: WrappedModuleFormat::JavaScript,
                label: "javascript",
                serialized_type: "java-script",
                expected_path: "recovered-module.js",
            },
            ScriptCase {
                payload: b"Option Explicit\r\nDim answer\r\nanswer = 42\r\n",
                module_type: DonutModuleType::VbScript,
                format: WrappedModuleFormat::VbScript,
                label: "vbscript",
                serialized_type: "vb-script",
                expected_path: "recovered-module.vbs",
            },
            ScriptCase {
                payload: b"Option Explicit\r\nDim\r\n",
                module_type: DonutModuleType::VbScript,
                format: WrappedModuleFormat::VbScript,
                label: "vbscript",
                serialized_type: "vb-script",
                expected_path: "recovered-module.vbs",
            },
            ScriptCase {
                payload: br#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"></xsl:stylesheet>"#,
                module_type: DonutModuleType::Xsl,
                format: WrappedModuleFormat::Xsl,
                label: "xsl",
                serialized_type: "xsl",
                expected_path: "recovered-module.xsl",
            },
            ScriptCase {
                payload: br#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"></xsl:stylesheet><"#,
                module_type: DonutModuleType::Xsl,
                format: WrappedModuleFormat::Xsl,
                label: "xsl",
                serialized_type: "xsl",
                expected_path: "recovered-module.xsl",
            },
        ];
        for case in cases {
            let wrapper: Vec<u8> = crate::packers::loader_generators::test_go_donut_wrapper(
                KNOWN_DONUT,
                case.payload,
                case.module_type,
                LoaderArchitecture::X64,
            )
            .expect("script Donut fixture");
            let recovery: LoaderRecovery = recover_loader(&wrapper).expect("script recovery");
            let LoaderConfig::Donut(config) = &recovery.inspection.config else {
                panic!("script wrapper lost Donut config");
            };
            assert_eq!(
                config.module_type,
                RecoveryField::Known {
                    value: case.module_type,
                }
            );
            assert_eq!(
                recovery.inspection.wrapped_module.format,
                RecoveryField::Known { value: case.format }
            );
            let RecoveryField::Unknown { reason } = &recovery.module else {
                panic!("{} script bytes were reported recovered", case.label);
            };
            assert!(reason.contains(case.label));
            assert!(reason.contains("static parser"));
            assert_eq!(
                loader_child_descriptor(&recovery.inspection),
                RecoveredChildDescriptor {
                    path: case.expected_path,
                    hint: None,
                }
            );
            let artifact: Artifact = Artifact::new(Rung::Raw, wrapper, [0u8; 32]);
            let children: Vec<ChildArtifact> = PACKER_PASS
                .extract_children(&artifact)
                .expect("script refusal children");
            assert!(
                children
                    .iter()
                    .all(|child: &ChildArtifact| child.handle.relative_path != case.expected_path)
            );
            let manifest_child: &ChildArtifact = children
                .iter()
                .find(|child: &&ChildArtifact| {
                    child.handle.relative_path == "packer-unpack.manifest.json"
                })
                .expect("script refusal manifest");
            let manifest: serde_json::Value = serde_json::from_slice(&manifest_child.bytes)
                .expect("script refusal manifest JSON");
            assert_eq!(manifest["recovery"]["status"], "unknown");
            assert_eq!(manifest["recovery"]["reason"], reason.as_str());
            assert_eq!(
                manifest["loader"]["config"]["value"]["module_type"]["value"]["kind"],
                case.serialized_type
            );
            assert_eq!(
                manifest["loader"]["wrapped_module"]["format"]["value"],
                case.serialized_type
            );
        }
    }

    #[test]
    fn donut_recovered_packer_reaches_the_real_downstream_detector() {
        use std::collections::BTreeMap;
        use std::time::Instant;

        use disrobe_core::chain::state_machine::PassRunner;
        use disrobe_core::chain::{
            ChainConfig, ChainDriver, ChainSpec, DetectorPick, PassRegistry, PassRunOutcome,
            Verdict,
        };

        #[derive(Debug)]
        struct Runner;

        impl PassRunner for Runner {
            fn run(
                &self,
                pick: &DetectorPick,
                bytes: Vec<u8>,
                _config: &ChainConfig,
                path_hint: Option<&str>,
            ) -> core::result::Result<PassRunOutcome, String> {
                let root_hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
                let artifact: Artifact = Artifact::new(Rung::Raw, bytes, root_hash);
                let started: Instant = Instant::now();
                let output: Artifact = pick
                    .pass
                    .run_with_path(&artifact, path_hint)
                    .map_err(|error: CoreError| error.to_string())?;
                let output_kind: OutputKind = pick.pass.output_kind(&output);
                let (kind, children): (OutputKind, Vec<Vec<u8>>) = if output_kind.is_mixed() {
                    let extracted: Vec<ChildArtifact> = pick
                        .pass
                        .extract_children(&artifact)
                        .map_err(|error: CoreError| error.to_string())?;
                    OutputKind::mixed_from_children(extracted)
                } else {
                    (output_kind, Vec::new())
                };
                Ok(PassRunOutcome {
                    output_bytes: output.envelope,
                    kind,
                    duration: started.elapsed(),
                    metadata: BTreeMap::new(),
                    children,
                })
            }
        }

        let wrapper: Vec<u8> = crate::packers::loader_generators::test_go_donut_wrapper(
            KNOWN_DONUT,
            FSG_PACKED,
            DonutModuleType::NativeExe,
            LoaderArchitecture::X86,
        )
        .expect("nested Donut fixture");
        let mut registry: PassRegistry = PassRegistry::new();
        let _replaced: Option<&'static dyn Pass> = registry.register(&PACKER_PASS);
        let runner: Runner = Runner;
        let driver: ChainDriver<'_, Runner> =
            ChainDriver::new(&registry, &runner, ChainConfig::default());
        let plan: disrobe_core::chain::ChainPlan =
            driver.run(wrapper, &ChainSpec::Auto { cap: 3 }, None);
        let donut_node: &disrobe_core::chain::Node = plan
            .nodes
            .iter()
            .find(|node: &&disrobe_core::chain::Node| {
                node.pass_id.as_deref() == Some(PASS_ID)
                    && node.format_tag_in.as_deref() == Some("donut")
            })
            .expect("Donut node");
        let fsg_node: &disrobe_core::chain::Node = plan
            .nodes
            .iter()
            .find(|node: &&disrobe_core::chain::Node| {
                node.parent_id == Some(donut_node.id)
                    && node.pass_id.as_deref() == Some(PASS_ID)
                    && node.format_tag_in.as_deref() == Some("fsg")
            })
            .expect("FSG downstream node");
        assert!(matches!(
            fsg_node.verdict,
            Verdict::FanOut { count } if count > 0
        ));
    }

    fn donut_inspection(module_type: DonutModuleType) -> LoaderInspection {
        let unavailable: String = "unavailable in routing test".to_owned();
        LoaderInspection {
            family: LoaderFamily::Donut,
            variant: LoaderVariant::GoDonutV1,
            architecture: LoaderArchitecture::X64,
            config_region: ByteRegion {
                offset: 5,
                length: 23_936,
            },
            config: LoaderConfig::Donut(DonutConfig {
                entropy: DonutEntropy::None,
                api_hash_count: RecoveryField::Known { value: 1 },
                module_type: RecoveryField::Known { value: module_type },
                compression: RecoveryField::Unknown {
                    reason: unavailable.clone(),
                },
                module_header_region: RecoveryField::Unknown {
                    reason: unavailable.clone(),
                },
            }),
            wrapped_module: WrappedModuleMetadata {
                region: RecoveryField::Unknown {
                    reason: unavailable.clone(),
                },
                format: RecoveryField::Unknown {
                    reason: unavailable.clone(),
                },
                stored_size: RecoveryField::Unknown {
                    reason: unavailable.clone(),
                },
                original_size: RecoveryField::Unknown {
                    reason: unavailable.clone(),
                },
                entry_point_rva: RecoveryField::Unknown {
                    reason: unavailable,
                },
            },
        }
    }

    #[test]
    fn detect_upx_marker() {
        let buf: Vec<u8> = pe_with_marker(b"UPX!");
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = Detector::detect(&PackerDetector, &ctx).expect("upx detected");
        assert_eq!(v.format_tag, "upx");
        assert!(v.confidence > 0.9);
    }

    fn pe_with_section(name: &[u8]) -> Vec<u8> {
        let opt_size: usize = 0xE0;
        let sec_table: usize = 0x80 + 4 + 20 + opt_size;
        let mut buf: Vec<u8> = vec![0u8; sec_table + 40 + 0x200];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        let coff: usize = 0x80 + 4;
        buf[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt: usize = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        let len: usize = name.len().min(8);
        buf[sec_table..sec_table + len].copy_from_slice(&name[..len]);
        buf
    }

    fn pe_with_marker(marker: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = pe_with_section(b".text");
        let body: usize = buf.len().saturating_sub(0x100);
        buf[body..body + marker.len()].copy_from_slice(marker);
        buf
    }

    #[test]
    fn detect_mpress_marker() {
        let buf: Vec<u8> = pe_with_section(b".MPRESS1");
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = Detector::detect(&PackerDetector, &ctx).expect("mpress detected");
        assert_eq!(v.format_tag, "mpress");
    }

    #[test]
    fn detect_misses_clean_bytes() {
        let buf: Vec<u8> = vec![0x55u8; 1024];
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(Detector::detect(&PackerDetector, &ctx).is_none());
    }

    #[test]
    fn pass_output_kind_is_mixed() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match PACKER_PASS.output_kind(&a) {
            OutputKind::Mixed { children } => assert!(children.is_empty()),
            _ => panic!("expected Mixed"),
        }
    }

    #[test]
    fn upx_priority_above_mpress() {
        assert!(priority_rank(Packer::Upx) < priority_rank(Packer::Mpress));
    }

    #[test]
    fn run_rejects_no_packer() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let r: CoreResult<Artifact> = PACKER_PASS.run(&a);
        assert!(r.is_err());
    }

    fn err_text(buf: Vec<u8>) -> String {
        let a: Artifact = Artifact::new(Rung::Raw, buf, [0u8; 32]);
        match PACKER_PASS.run(&a) {
            Ok(_) => panic!("synthetic non-PE input must not unpack"),
            Err(e) => format!("{e}"),
        }
    }

    #[test]
    fn implemented_packers_dispatch_to_real_unpacker_not_stub() {
        for (sig, unpack_code, section_scoped) in [
            (&b"petite\x00\x00"[..], "DR-NAT-0910", true),
            (&b"nsp1"[..], "DR-NAT-0911", true),
            (&b"MEW"[..], "DR-NAT-0912", true),
            (&b"FSG!"[..], "DR-NAT-0913", false),
            (&b".MPRESS1"[..], "DR-NAT-0916", true),
            (&b"yC2.0"[..], "DR-NAT-0918", false),
        ] {
            let buf: Vec<u8> = if section_scoped {
                pe_with_section(sig)
            } else {
                pe_with_marker(sig)
            };
            let msg: String = err_text(buf);
            let reached_real_unpacker: bool =
                msg.contains(unpack_code) || msg.contains("DR-NAT-0915");
            assert!(
                reached_real_unpacker,
                "signature {sig:?} must reach its real unpacker ({unpack_code} or empty-output \
                 DR-NAT-0915), not a stub/detect-only path; got: {msg}",
            );
            assert!(
                !msg.contains("DR-NAT-0902")
                    && !msg.contains("DR-NAT-0907")
                    && !msg.contains("DR-NAT-0914"),
                "Implemented packer must NOT report stub-eval / detect-only / missing-arm; got: {msg}",
            );
        }
    }

    #[test]
    fn grey_zone_protectors_return_honest_carve_error() {
        let buf: Vec<u8> = pe_with_section(b".vmp0");
        let msg: String = err_text(buf);
        assert!(
            msg.contains("DR-NAT-0909") && msg.contains("grey-zone"),
            "VMProtect must surface the honest grey-zone detect-and-carve error; got: {msg}",
        );
        assert!(!msg.contains("no Rust unpacker yet"), "got: {msg}");
    }

    #[test]
    fn delegated_dotnet_family_returns_delegation_error() {
        let buf: Vec<u8> = pe_with_marker(b"NETCryptor");
        let msg: String = err_text(buf);
        assert!(
            msg.contains("DR-NAT-0930") && msg.contains("dotnet.classify"),
            "NetCryptor must route managed recovery to the .NET pass; got: {msg}",
        );
    }

    #[test]
    fn native_catalog_and_detector_skip_delegated_dotnet_packers() {
        let buf: Vec<u8> = pe_with_marker(b"NETCryptor");
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(Detector::detect(&PackerDetector, &ctx).is_none());
        assert!(ObfuscatorCatalog::detect(&PackerDetector, &ctx).is_none());
        let entries: Vec<&'static dyn CatalogEntry> = PackerDetector.catalog();
        assert!(
            entries.iter().all(|e: &&dyn CatalogEntry| {
                e.id() != "dotnet-patcher" && e.id() != "netcryptor"
            }),
            "managed wrappers belong to the .NET catalog"
        );
    }

    fn dispatch_arm_is_wired(packer: Packer) -> bool {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 256], [0u8; 32]);
        match run_rust_unpacker(packer, &a) {
            Ok(_) => true,
            Err(e) => !format!("{e}").contains("DR-NAT-0914"),
        }
    }

    #[test]
    fn dispatch_arms_cover_exactly_the_implemented_packers() {
        for packer in Packer::ALL {
            let implemented: bool = packer.unpacker_status() == UnpackerStatus::Implemented;
            assert_eq!(
                dispatch_arm_is_wired(*packer),
                implemented,
                "{label} is {status:?} and run_rust_unpacker {has} an arm for it. An Implemented \
                 packer without an arm reports the missing-arm guard to a user instead of \
                 unpacking; an arm on any other tier is unreachable code whose recovery no \
                 published tier credits",
                label = packer.label(),
                status = packer.unpacker_status(),
                has = if implemented { "has no" } else { "has" },
            );
        }
    }

    #[test]
    fn stub_eval_pending_packers_report_detected_not_fabricated_success() {
        let stub_eval_pending: Vec<Packer> = Packer::ALL
            .iter()
            .copied()
            .filter(|p: &Packer| p.unpacker_status() == UnpackerStatus::StubEvalPending)
            .collect();
        assert!(
            !stub_eval_pending.is_empty(),
            "the stub-eval-pending tier is published with a count of its own; an empty filter here \
             would check nothing"
        );
        for p in stub_eval_pending {
            let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 256], [0u8; 32]);
            let msg: String = match dispatch_unpack(p, &a) {
                Ok(_) => panic!("{} must not report a recovery success", p.label()),
                Err(e) => format!("{e}"),
            };
            assert!(
                msg.contains("DR-NAT-0902") && msg.contains("real packed-sample recovery unproven"),
                "{} must surface the stub-eval-pending error stating recovery is unproven; got: \
                 {msg}",
                p.label()
            );
        }
    }

    fn upx_packed_fixture() -> Option<Vec<u8>> {
        let path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("native")
            .join("packers")
            .join("upx")
            .join("hello.packed.nrv2b.exe");
        std::fs::read(&path).ok()
    }

    #[test]
    fn extract_children_emits_dedicated_sidecars_for_real_upx_sample() {
        let Some(bytes): Option<Vec<u8>> = upx_packed_fixture() else {
            eprintln!("SKIP: upx packed fixture missing");
            return;
        };
        let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = PACKER_PASS
            .extract_children(&a)
            .expect("upx children extraction must succeed");

        let recovered: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == RECOVERED_IMAGE.path)
            .expect("the recovered image must be a chain child so auto re-chains it");
        assert!(
            recovered.handle.hint.is_none(),
            "the recovered image must be a non-terminal child so binfmt/native passes run on it",
        );
        assert!(
            !recovered.bytes.is_empty(),
            "the recovered image child must carry real bytes",
        );

        for sidecar in [
            "packer-unpack.manifest.json",
            "identity.json",
            "signatures.json",
        ] {
            let child: &ChildArtifact = children
                .iter()
                .find(|c: &&ChildArtifact| c.handle.relative_path == sidecar)
                .unwrap_or_else(|| panic!("auto must emit the dedicated {sidecar} sidecar child"));
            assert_eq!(
                child.handle.hint.as_deref(),
                Some(TERMINAL_HINT),
                "{sidecar} is a terminal report, not a re-chained input",
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&child.bytes).expect("sidecar must be valid json");
            assert!(
                parsed.is_object(),
                "{sidecar} must serialize to a json object"
            );
        }

        let manifest: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "packer-unpack.manifest.json")
            .expect("manifest present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest.bytes).expect("manifest json");
        assert_eq!(parsed["packer"].as_str(), Some("upx"));
        assert!(
            parsed["recovered_image_bytes"].as_u64().unwrap_or(0) > 0,
            "the manifest must record the recovered-image byte count",
        );
    }

    #[test]
    fn credible_oep_guard_rejects_missing_oep() {
        assert!(require_credible_oep(Packer::AsPack, None).is_err());
        assert!(require_credible_oep(Packer::PeCompact, Some(0x0040_1000)).is_ok());
    }

    #[test]
    fn catalog_lists_every_packer_with_honest_quality() {
        let entries: Vec<&'static dyn CatalogEntry> = PackerDetector.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        for e in &entries {
            assert!(!e.id().is_empty());
            assert!(!e.display_name().is_empty());
        }
        let upx: &dyn CatalogEntry = entries
            .iter()
            .copied()
            .find(|e| e.id() == "upx")
            .expect("upx in catalog");
        assert_eq!(upx.support_quality(), SupportQuality::Full);
        let donut: &dyn CatalogEntry = entries
            .iter()
            .copied()
            .find(|e| e.id() == "donut")
            .expect("donut in catalog");
        assert_eq!(donut.support_quality(), SupportQuality::Partial);
        let vmp: &dyn CatalogEntry = entries
            .iter()
            .copied()
            .find(|e| e.id() == "vmprotect")
            .expect("vmprotect in catalog");
        assert_eq!(vmp.support_quality(), SupportQuality::DetectOnly);
    }

    #[test]
    fn the_catalog_advertises_exactly_the_packers_this_pass_owns() {
        let owned: BTreeSet<&'static str> = Packer::ALL
            .iter()
            .filter(|packer: &&Packer| {
                packer.unpacker_status() != UnpackerStatus::DelegatedToDotnet
            })
            .map(|packer: &Packer| packer.label())
            .collect();
        let advertised: BTreeSet<&'static str> = CATALOG
            .iter()
            .map(|entry: &PackerEntry| entry.packer.label())
            .collect();
        let unadvertised: Vec<&'static str> = owned.difference(&advertised).copied().collect();
        let disowned: Vec<&'static str> = advertised.difference(&owned).copied().collect();
        assert!(
            unadvertised.is_empty() && disowned.is_empty(),
            "`disrobe catalog native` prints this catalog and {CATALOG_COUNT} is published as its \
             size, so it must hold every packer this pass owns, which is the `Packer` enum minus \
             the managed wrappers the .NET pass owns. Owned but never advertised: {unadvertised:?}. \
             Advertised but not owned: {disowned:?}"
        );
        assert_eq!(
            CATALOG.len(),
            advertised.len(),
            "one packer holds two catalog entries, so CATALOG_COUNT counts a family twice"
        );
        assert_eq!(
            CATALOG_COUNT,
            owned.len(),
            "CATALOG_COUNT is the number docs/src/catalog.md publishes for this pass"
        );
    }

    #[test]
    fn catalog_detects_a_real_upx_marker() {
        let buf: Vec<u8> = pe_with_marker(b"UPX!");
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let out: DetectorOutput =
            ObfuscatorCatalog::detect(&PackerDetector, &ctx).expect("upx marker must be detected");
        assert_eq!(out.entry_id, "upx");
        assert!(out.confidence > 0.9);
    }

    #[test]
    fn catalog_detect_misses_clean_bytes() {
        let buf: Vec<u8> = vec![0x55u8; 1024];
        let ctx: DetectContext<'_> = DetectContext {
            bytes: &buf,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(ObfuscatorCatalog::detect(&PackerDetector, &ctx).is_none());
    }
}
