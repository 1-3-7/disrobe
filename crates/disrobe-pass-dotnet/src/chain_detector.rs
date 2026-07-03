#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::{ChildArtifact, ChildHandle, TERMINAL_HINT};
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_INTERPRETER_BYTECODE, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::decompile::{DecompiledAssembly, decompile_assembly};
use crate::pass::{PassSummary, analyze};
use crate::pe::{DataDirectory, PeImage, parse as parse_pe};
use crate::peel::confuserex_constants::{ConfuserConstantsRecovery, peel_confuserex_constants};
use crate::peel::static_decrypt::{DecodedValue, RecoveredConstant};
use crate::peel::string_emu::RecoveredString as EmulatedString;
use crate::peel::{PeelReport, PeelStrategy, RecoveredMethod, peel_by};
use crate::protectors::{DetectionReport, Handling, Protector, detect_all};
use crate::structurize::StructuredMethod;

pub const PASS_ID: PassId = "dotnet.classify";

const TAG_PE_CLR: &str = "dotnet-pe-clr";

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[derive(Debug)]
pub struct DotnetDetector;

impl Detector for DotnetDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 64 || &bytes[..2] != b"MZ" {
            return None;
        }
        let pe: PeImage = parse_pe(bytes).ok()?;
        let dir: DataDirectory = pe.clr_directory()?;
        if dir.rva == 0 || dir.size == 0 {
            return None;
        }
        Some(verdict_clr(dir))
    }
}

#[derive(Debug)]
pub struct DotnetPass;

impl Pass for DotnetPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &DotnetDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::CSharp,
            formatted: true,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let pe: PeImage = parse_pe(bytes).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("DR-DOTNET-0902: PE parse: {e}"))
        })?;
        let clr: DataDirectory = pe.clr_directory().ok_or_else(|| {
            CoreError::PassFailure(
                "DR-DOTNET-0903: dotnet.classify: PE has no CLR data directory".to_string(),
            )
        })?;
        if clr.rva == 0 || clr.size == 0 {
            return Err(CoreError::PassFailure(
                "DR-DOTNET-0904: dotnet.classify: empty CLR data directory".to_string(),
            ));
        }
        let assembly: DecompiledAssembly =
            decompile_assembly(bytes).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!("DR-DOTNET-0905: dotnet decompile: {e}"))
            })?;
        let recovered_constants: Vec<String> = peel_confuserex_constants(bytes)
            .ok()
            .flatten()
            .map(|r: ConfuserConstantsRecovery| {
                r.strings_recovered
                    .into_iter()
                    .map(|s: crate::peel::confuserex_constants::RecoveredString| s.text)
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();
        if assembly.methods.is_empty() && recovered_constants.is_empty() {
            return Err(CoreError::PassFailure(format!(
                "DR-DOTNET-0906: dotnet.classify: module {module} carries no recoverable method \
                 bodies (bodyless={bodyless}, failed={failed}) and no decryptable constants; body \
                 code is native-AOT/R2R or stripped, not statically present",
                module = assembly.module_name,
                bodyless = assembly.methods_bodyless,
                failed = assembly.methods_failed,
            )));
        }
        let source: String = render_csharp_source(&assembly, &recovered_constants);
        Ok(Artifact::new(
            Rung::Surface,
            source.into_bytes(),
            artifact.root_hash,
        ))
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let stem: String = decompile_assembly(bytes).ok().map_or_else(
            || "dotnet".to_string(),
            |a: DecompiledAssembly| a.module_name,
        );
        let mut children: Vec<ChildArtifact> = Vec::new();

        if let Ok(summary) = analyze(bytes)
            && let Ok(json) = serde_json::to_vec_pretty(&analyze_manifest(&summary))
        {
            push_terminal_child(&mut children, format!("{stem}.analyze.json"), json);
        }

        let detection: DetectionReport = detect_all(bytes);
        if let Some(protector) = detection.primary
            && let Some(Ok(report)) = peel_by(protector, bytes)
        {
            if let Ok(json) = serde_json::to_vec_pretty(&peel_manifest(protector, &report)) {
                push_terminal_child(&mut children, format!("{stem}.peel.json"), json);
            }
            let strings: String = render_recovered_strings(
                &report.recovered_constants,
                &report.recovered_strings,
                bytes,
            );
            if !strings.is_empty() {
                push_terminal_child(
                    &mut children,
                    format!("{stem}.recovered-strings.txt"),
                    strings.into_bytes(),
                );
            }
            if !report.recovered_methods.is_empty() {
                let cil: String = render_recovered_cil(&report.recovered_methods);
                push_terminal_child(
                    &mut children,
                    format!("{stem}.recovered-cil.txt"),
                    cil.into_bytes(),
                );
            }
        }

        Ok(children)
    }
}

pub static DOTNET_PASS: DotnetPass = DotnetPass;

fn push_terminal_child(children: &mut Vec<ChildArtifact>, relative_path: String, bytes: Vec<u8>) {
    let index: u32 = u32::try_from(children.len()).unwrap_or(u32::MAX);
    children.push(ChildArtifact {
        handle: ChildHandle {
            artifact_index: index,
            relative_path,
            hint: Some(TERMINAL_HINT.to_string()),
        },
        bytes,
    });
}

fn analyze_manifest(summary: &PassSummary) -> serde_json::Value {
    serde_json::json!({
        "schema": "disrobe.dotnet.analyze/v0",
        "pe_bitness": summary.pe_bitness,
        "machine": summary.machine,
        "clr_runtime_version": summary.clr_runtime_version,
        "runtime_label": format!("{:?}", summary.runtime_label),
        "r2r_present": summary.r2r_present,
        "native_aot": summary.native_aot,
        "primary_protector": summary.primary_protector.as_ref().map(|p: &Protector| format!("{p:?}")),
        "protectors_detected": summary
            .protectors_detected
            .iter()
            .map(|p: &Protector| format!("{p:?}"))
            .collect::<Vec<String>>(),
        "stream_names": summary.stream_names,
        "opcode_table_size": summary.opcode_table_size,
        "opcode_spec_coverage_pct": summary.opcode_spec_coverage_pct,
    })
}

fn peel_manifest(protector: Protector, report: &PeelReport) -> serde_json::Value {
    let walled: bool = report.strategy == PeelStrategy::DetectOnlyNativeOrVm;
    serde_json::json!({
        "schema": "disrobe.dotnet.peel/v0",
        "detected": protector.label(),
        "protector": protector,
        "strategy": report.strategy,
        "walled": walled,
        "attributes_stripped": report.attributes_stripped,
        "strings_total": report.strings_total,
        "strings_obfuscated_count": report.strings_obfuscated_count,
        "us_strings_total": report.us_strings_total,
        "renamable_identifiers": report.renamable_identifiers,
        "unobfuscatable_identifiers": report.unobfuscatable_identifiers,
        "recovered_decoders": report.recovered_decoders,
        "recovered_constants": report.recovered_constants,
        "recovered_strings": report.recovered_strings,
        "recovered_methods": report.recovered_methods,
        "bytes_in": report.bytes_in,
        "bytes_out": report.bytes_out,
        "notes": report.notes,
    })
}

fn render_recovered_strings(
    constants: &[RecoveredConstant],
    emulated: &[EmulatedString],
    bytes: &[u8],
) -> String {
    let mut text: String = String::new();
    for c in constants {
        if let DecodedValue::Utf16(s) = &c.decoded {
            push_format(
                &mut text,
                format_args!(
                    "static-decoder\t0x{:08X}\t{}\t{s:?}\n",
                    c.method_token, c.method_name
                ),
            );
        }
    }
    for s in emulated {
        push_format(
            &mut text,
            format_args!(
                "emulated-decryptor\t0x{:08X}\t{}\t{:?}\n",
                s.method_token, s.method_name, s.text
            ),
        );
    }
    if let Ok(Some(recovery)) = peel_confuserex_constants(bytes) {
        for rs in &recovery.strings_recovered {
            push_format(
                &mut text,
                format_args!(
                    "confuserex-constants\tcall_site=0x{:08X}\tmut_off={}\t{:?}\n",
                    rs.call_site_id, rs.mutated_offset, rs.text
                ),
            );
        }
    }
    text
}

fn render_recovered_cil(methods: &[RecoveredMethod]) -> String {
    let mut text: String = String::with_capacity(methods.len() * 128);
    for m in methods {
        push_format(
            &mut text,
            format_args!(
                "method {} token=0x{:08X} args={} locals={}\n",
                m.method_name, m.metadata_token, m.arg_count, m.local_count
            ),
        );
        for line in &m.cil {
            push_format(&mut text, format_args!("  {line}\n"));
        }
        text.push_str("end\n");
    }
    text
}

fn render_csharp_source(assembly: &DecompiledAssembly, recovered_constants: &[String]) -> String {
    let mut out: String = String::with_capacity(assembly.methods.len() * 128);
    out.push_str("// disrobe dotnet native CIL->C# decompilation (no runtime, no external tool)\n");
    push_format(
        &mut out,
        format_args!("// module: {}\n", assembly.module_name),
    );
    out.push('\n');
    for m in &assembly.methods {
        let StructuredMethod { body, .. } = m;
        out.push_str(body);
        out.push('\n');
    }
    if !recovered_constants.is_empty() {
        out.push_str("\n// recovered ConfuserEx constant-protected string literals:\n");
        for c in recovered_constants {
            push_format(&mut out, format_args!("//   {c:?}\n"));
        }
    }
    out
}

fn verdict_clr(dir: DataDirectory) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        TAG_PE_CLR,
        FAMILY_INTERPRETER_BYTECODE,
        0.95,
        25,
        vec!["PE+CLR-data-directory"],
        format!(
            "PE with CLR header rva={rva:#x} size={sz}",
            rva = dir.rva,
            sz = dir.size,
        ),
    )
}

#[derive(Debug)]
pub struct DotnetObfuscatorEntry {
    pub protector: Protector,
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    pub quality: SupportQuality,
}

impl CatalogEntry for DotnetObfuscatorEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.id
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.protector.label()
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        self.quality
    }
}

const fn quality_for(protector: Protector) -> SupportQuality {
    match protector {
        Protector::ConfuserEx2 | Protector::EazfuscatorNet | Protector::KoiVm => {
            SupportQuality::Full
        }
        Protector::Ilprotector | Protector::MaxToCode | Protector::ThemidaDotnet => {
            SupportQuality::DetectOnly
        }
        Protector::ConfuserEx
        | Protector::Dotfuscator
        | Protector::DotfuscatorCe
        | Protector::SmartAssembly
        | Protector::BabelDotnet
        | Protector::DeepSea
        | Protector::SpicesNet
        | Protector::Goliath
        | Protector::Skater
        | Protector::DotnetReactor
        | Protector::CryptoObfuscator
        | Protector::ArmDot
        | Protector::AgileNet
        | Protector::DotNetPatcher
        | Protector::NetCryptor
        | Protector::Obfuscar
        | Protector::BitMono => SupportQuality::Partial,
    }
}

const CATALOG_COUNT: usize = 22;

static CATALOG: [DotnetObfuscatorEntry; CATALOG_COUNT] = [
    DotnetObfuscatorEntry {
        protector: Protector::ConfuserEx2,
        id: "dotnet-confuserex2",
        aliases: &["confuserex2", "confuserex-2"],
        quality: quality_for(Protector::ConfuserEx2),
    },
    DotnetObfuscatorEntry {
        protector: Protector::ConfuserEx,
        id: "dotnet-confuserex",
        aliases: &["confuserex", "confuser"],
        quality: quality_for(Protector::ConfuserEx),
    },
    DotnetObfuscatorEntry {
        protector: Protector::EazfuscatorNet,
        id: "dotnet-eazfuscator",
        aliases: &["eazfuscator", "eazfuscator.net", "eaz"],
        quality: quality_for(Protector::EazfuscatorNet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::KoiVm,
        id: "dotnet-koivm",
        aliases: &["koivm", "koi"],
        quality: quality_for(Protector::KoiVm),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Ilprotector,
        id: "dotnet-ilprotector",
        aliases: &["ilprotector"],
        quality: quality_for(Protector::Ilprotector),
    },
    DotnetObfuscatorEntry {
        protector: Protector::MaxToCode,
        id: "dotnet-maxtocode",
        aliases: &["maxtocode"],
        quality: quality_for(Protector::MaxToCode),
    },
    DotnetObfuscatorEntry {
        protector: Protector::ThemidaDotnet,
        id: "dotnet-themida",
        aliases: &["themida", "winlicense"],
        quality: quality_for(Protector::ThemidaDotnet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::SmartAssembly,
        id: "dotnet-smartassembly",
        aliases: &["smartassembly"],
        quality: quality_for(Protector::SmartAssembly),
    },
    DotnetObfuscatorEntry {
        protector: Protector::BabelDotnet,
        id: "dotnet-babel",
        aliases: &["babel", "babelfor.net"],
        quality: quality_for(Protector::BabelDotnet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::CryptoObfuscator,
        id: "dotnet-cryptoobfuscator",
        aliases: &["cryptoobfuscator", "crypto-obfuscator"],
        quality: quality_for(Protector::CryptoObfuscator),
    },
    DotnetObfuscatorEntry {
        protector: Protector::DotnetReactor,
        id: "dotnet-reactor",
        aliases: &["dotnetreactor", "reactor", "eziriz"],
        quality: quality_for(Protector::DotnetReactor),
    },
    DotnetObfuscatorEntry {
        protector: Protector::AgileNet,
        id: "dotnet-agile",
        aliases: &["agile.net", "agiledotnet", "clisecure"],
        quality: quality_for(Protector::AgileNet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::DotNetPatcher,
        id: "dotnet-patcher",
        aliases: &["dotnetpatcher", "dnpatcher", "dn-patcher"],
        quality: quality_for(Protector::DotNetPatcher),
    },
    DotnetObfuscatorEntry {
        protector: Protector::NetCryptor,
        id: "dotnet-netcryptor",
        aliases: &["netcryptor", "net-cryptor"],
        quality: quality_for(Protector::NetCryptor),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Dotfuscator,
        id: "dotnet-dotfuscator",
        aliases: &["dotfuscator"],
        quality: quality_for(Protector::Dotfuscator),
    },
    DotnetObfuscatorEntry {
        protector: Protector::DotfuscatorCe,
        id: "dotnet-dotfuscator-ce",
        aliases: &["dotfuscator-ce", "dotfuscatorce"],
        quality: quality_for(Protector::DotfuscatorCe),
    },
    DotnetObfuscatorEntry {
        protector: Protector::DeepSea,
        id: "dotnet-deepsea",
        aliases: &["deepsea"],
        quality: quality_for(Protector::DeepSea),
    },
    DotnetObfuscatorEntry {
        protector: Protector::SpicesNet,
        id: "dotnet-spices",
        aliases: &["spices.net", "9rays"],
        quality: quality_for(Protector::SpicesNet),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Skater,
        id: "dotnet-skater",
        aliases: &["skater", "rustemsoft"],
        quality: quality_for(Protector::Skater),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Goliath,
        id: "dotnet-goliath",
        aliases: &["goliath", "goliath.net"],
        quality: quality_for(Protector::Goliath),
    },
    DotnetObfuscatorEntry {
        protector: Protector::ArmDot,
        id: "dotnet-armdot",
        aliases: &["armdot"],
        quality: quality_for(Protector::ArmDot),
    },
    DotnetObfuscatorEntry {
        protector: Protector::Obfuscar,
        id: "dotnet-obfuscar",
        aliases: &["obfuscar"],
        quality: quality_for(Protector::Obfuscar),
    },
];

fn catalog_id_for(protector: Protector) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&DotnetObfuscatorEntry| e.protector == protector)
        .map(|e: &DotnetObfuscatorEntry| e.id)
}

fn confidence_for(report: &DetectionReport, protector: Protector) -> f32 {
    let hit_count: usize = report.matches.get(&protector).map_or(0, Vec::len);
    let base: f32 = match protector.handling() {
        Handling::Devirtualize => 0.95,
        Handling::De4dotDelegate => 0.92,
        Handling::GatedDe4dotDelegate => 0.9,
        Handling::NativeStrip => 0.85,
        Handling::DetectOnly => 0.8,
    };
    let bonus: f32 = (hit_count.min(4) as f32) * 0.02;
    (base + bonus).min(0.99)
}

impl ObfuscatorCatalog for DotnetDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static DotnetObfuscatorEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 64 || &bytes[..2] != b"MZ" {
            return None;
        }
        let report: DetectionReport = detect_all(bytes);
        let primary: Protector = report.primary?;
        let entry_id: &'static str = catalog_id_for(primary)?;
        let confidence: f32 = confidence_for(&report, primary);
        let markers: Vec<String> = report
            .matches
            .keys()
            .filter_map(|p: &Protector| catalog_id_for(*p).map(str::to_owned))
            .collect();
        Some(DetectorOutput::new(entry_id, confidence, markers))
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use disrobe_core::Rung;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(DotnetDetector.id(), PASS_ID);
    }

    #[test]
    fn detect_misses_non_pe() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(Detector::detect(&DotnetDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn detect_misses_pe_without_clr() {
        let mut bytes: Vec<u8> = vec![0u8; 1024];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        assert!(Detector::detect(&DotnetDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn pass_output_kind_is_csharp_source() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
        match DOTNET_PASS.output_kind(&a) {
            OutputKind::Source {
                language,
                formatted,
            } => {
                assert_eq!(language, Language::CSharp);
                assert!(formatted);
            }
            _ => panic!("expected Source"),
        }
    }

    #[test]
    fn pass_run_rejects_non_pe() {
        let a: Artifact = Artifact::new(Rung::Raw, vec![0u8; 16], [0u8; 32]);
        let err: CoreError = DOTNET_PASS.run(&a).expect_err("must reject");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-DOTNET-0902") || msg.contains("DR-DOTNET-0903"));
    }

    fn corpus(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join(rel)
    }

    #[test]
    fn catalog_covers_every_protector_once() {
        let entries: Vec<&'static dyn CatalogEntry> = DotnetDetector.catalog();
        assert_eq!(entries.len(), CATALOG_COUNT);
        let mut ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), CATALOG_COUNT, "catalog ids must be unique");
        for e in &entries {
            assert!(e.id().starts_with("dotnet-"));
            assert!(!e.display_name().is_empty());
        }
    }

    #[test]
    fn quality_map_is_honest() {
        assert_eq!(quality_for(Protector::EazfuscatorNet), SupportQuality::Full);
        assert_eq!(quality_for(Protector::ConfuserEx2), SupportQuality::Full);
        assert_eq!(quality_for(Protector::KoiVm), SupportQuality::Full);
        assert_eq!(
            quality_for(Protector::Ilprotector),
            SupportQuality::DetectOnly
        );
        assert_eq!(
            quality_for(Protector::MaxToCode),
            SupportQuality::DetectOnly
        );
        assert_eq!(
            quality_for(Protector::ThemidaDotnet),
            SupportQuality::DetectOnly
        );
        assert_eq!(
            quality_for(Protector::SmartAssembly),
            SupportQuality::Partial
        );
        assert_eq!(
            quality_for(Protector::DotNetPatcher),
            SupportQuality::Partial
        );
        assert_eq!(quality_for(Protector::NetCryptor), SupportQuality::Partial);
        assert_eq!(quality_for(Protector::Obfuscar), SupportQuality::Partial);
    }

    #[test]
    fn catalog_detects_real_confuserex2_sample() {
        let path: std::path::PathBuf = corpus("dotnet/HelloAppLegacy.confuserex2.dll");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            eprintln!("SKIP: confuserex2 fixture missing at {}", path.display());
            return;
        };
        let out: DetectorOutput = ObfuscatorCatalog::detect(&DotnetDetector, &ctx(&bytes))
            .expect("real ConfuserEx2 assembly must be catalog-detected");
        assert_eq!(out.entry_id, "dotnet-confuserex2");
        assert!(out.confidence >= 0.9, "confidence={}", out.confidence);
        let entry: &dyn CatalogEntry = DotnetDetector
            .catalog()
            .into_iter()
            .find(|e: &&dyn CatalogEntry| e.id() == out.entry_id)
            .expect("detected id must be in catalog");
        assert_eq!(entry.support_quality(), SupportQuality::Full);
    }

    #[test]
    fn catalog_detect_misses_non_pe() {
        let bytes: Vec<u8> = vec![0u8; 256];
        assert!(ObfuscatorCatalog::detect(&DotnetDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn extract_children_emits_dedicated_sidecars_for_real_confuserex2() {
        let path: std::path::PathBuf = corpus("dotnet/HelloAppLegacy.confuserex2.dll");
        let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
            eprintln!("SKIP: confuserex2 fixture missing at {}", path.display());
            return;
        };
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = DOTNET_PASS
            .extract_children(&artifact)
            .expect("extract_children must not error on a real .NET PE");
        let has_analyze: bool = children
            .iter()
            .any(|c: &ChildArtifact| c.handle.relative_path.ends_with(".analyze.json"));
        let has_peel: bool = children
            .iter()
            .any(|c: &ChildArtifact| c.handle.relative_path.ends_with(".peel.json"));
        assert!(
            has_analyze,
            "auto/chain must emit the dedicated analyze manifest sidecar"
        );
        assert!(
            has_peel,
            "auto/chain must emit the dedicated peel report sidecar for a detected protector"
        );
        for c in &children {
            assert!(
                c.handle.is_terminal(),
                "dotnet sidecars are recovered outputs, must carry the terminal hint"
            );
            assert!(
                !c.bytes.is_empty(),
                "sidecar {} must not be empty",
                c.handle.relative_path
            );
        }
        let analyze_child: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path.ends_with(".analyze.json"))
            .expect("analyze sidecar present");
        let parsed: serde_json::Value =
            serde_json::from_slice(&analyze_child.bytes).expect("analyze sidecar is valid JSON");
        assert_eq!(parsed["schema"], "disrobe.dotnet.analyze/v0");
    }
}
