#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::TERMINAL_HINT;
use disrobe_core::chain::{
    CatalogEntry, ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector,
    DetectorOutput, FAMILY_PACKER_ARCHIVE, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::recon::{ReconConfig, ReconReport, report_bytes};

use crate::packers::{
    AspackPhaseTwoOutput, Detection as PackerDetection, FsgUnpackOutput, KkrunchyUnpackOutput,
    LoaderInspection, LoaderRecovery, MewUnpackOutput, MpressUnpackOutput, NspackEmulatedReport,
    Packer, PecompactPhaseTwoOutput, PetitePhase2EmulatedOutput, RecoveryField, UnpackerStatus,
    UpxUnpackOutput, YodasCrypterCarve, detect as detect_packers, recover_loader,
    recover_yodas_crypter_carve, unpack_aspack_phase2_emulated, unpack_fsg, unpack_kkrunchy,
    unpack_mew, unpack_mpress, unpack_nspack_emulated, unpack_pecompact_phase2_emulated,
    unpack_petite_phase2_emulated, unpack_upx,
};

pub const PASS_ID: PassId = "native.packer-unpack";

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
        Ok(build_children(&recovery))
    }
}

pub static PACKER_PASS: PackerPass = PackerPass;

#[derive(Debug)]
struct PackerRecovery {
    packer: Packer,
    image: Vec<u8>,
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

const RECOVERED_IMAGE_PATH: &str = "recovered-image.bin";

fn build_children(recovery: &PackerRecovery) -> Vec<ChildArtifact> {
    let mut children: Vec<ChildArtifact> = Vec::new();
    let image: &[u8] = recovery.image.as_slice();

    children.push(child(0, RECOVERED_IMAGE_PATH, None, recovery.image.clone()));

    if let Ok(json) = serde_json::to_vec_pretty(&unpack_manifest(recovery)) {
        push_terminal(&mut children, "packer-unpack.manifest.json", json);
    }
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
    let recon: ReconReport =
        report_bytes(image, Some(RECOVERED_IMAGE_PATH), &ReconConfig::default());
    if !recon.findings.is_empty()
        && let Ok(json) = serde_json::to_vec_pretty(&recon)
    {
        push_terminal(&mut children, "recon.json", json);
    }
    children
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
    serde_json::json!({
        "schema": "disrobe.native.packer-unpack/v1",
        "packer": recovery.packer.label(),
        "recovered_image": RECOVERED_IMAGE_PATH,
        "recovered_image_bytes": recovery.image.len(),
        "recovered_oep_va": recovery.oep_va,
        "loader": recovery.loader,
    })
}

fn render_manifest(recovery: &PackerRecovery) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(128);
    s.push_str("native.packer-unpack\n");
    let _ = writeln!(
        s,
        "packer={label} recovered_bytes={n} oep_va={oep:?}",
        label = recovery.packer.label(),
        n = recovery.image.len(),
        oep = recovery.oep_va,
    );
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
        image: recovered,
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
    let image: Vec<u8> = match module {
        RecoveryField::Known { value } => value,
        RecoveryField::Unknown { reason } => {
            return Err(CoreError::PassFailure(format!(
                "DR-NAT-0932: native.packer-unpack: {label} module was not recovered: {reason}",
                label = packer.label(),
            )));
        }
    };
    if image.is_empty() {
        return Err(CoreError::PassFailure(format!(
            "DR-NAT-0915: native.packer-unpack: {label} unpacker produced no bytes",
            label = packer.label(),
        )));
    }
    Ok(PackerRecovery {
        packer,
        image,
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

    use super::*;

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(PackerDetector.id(), PASS_ID);
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
            .find(|c: &&ChildArtifact| c.handle.relative_path == RECOVERED_IMAGE_PATH)
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
