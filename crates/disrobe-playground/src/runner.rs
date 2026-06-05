use std::collections::BTreeMap;
use std::time::Instant;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::state_machine::PassRunner;
use disrobe_core::chain::{
    ChainConfig, ChainDriver, ChainPlan, ChainSpec, DetectContext, DetectorPick, OutputKind,
    PassRegistry, PassRunOutcome,
};

use disrobe_pass_native::{UpxUnpackOutput, unpack_fsg, unpack_mew, unpack_upx};
use disrobe_pass_py_decompile::{
    NativeDecompile, RoundtripStatus, decompile_pyc, roundtrip_native,
};
use disrobe_py_marshal::{CodeObject, Object, PycFile, read_pyc};

use crate::oracle::{OracleKind, OracleVerdict, ResolvedFixture};

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub max_input_bytes: u64,
    pub allow_recompile_interpreter: bool,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            allow_recompile_interpreter: true,
        }
    }
}

#[derive(Debug)]
pub struct Runner {
    config: RunnerConfig,
    registry: PassRegistry,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(RunnerConfig::default())
    }
}

impl Runner {
    #[must_use]
    pub fn new(config: RunnerConfig) -> Self {
        Self {
            config,
            registry: registry_full(),
        }
    }

    #[must_use]
    pub fn evaluate(&self, fx: &ResolvedFixture) -> OracleVerdict {
        if !fx.input_path.exists() {
            return OracleVerdict::FixtureAbsent {
                rel: fx.input_rel.clone(),
            };
        }
        let Ok(meta): Result<std::fs::Metadata, std::io::Error> = std::fs::metadata(&fx.input_path)
        else {
            return OracleVerdict::FixtureAbsent {
                rel: fx.input_rel.clone(),
            };
        };
        if meta.len() > self.config.max_input_bytes {
            return OracleVerdict::ToolMissing {
                tool: format!("memory-budget-exceeded:{}B", meta.len()),
            };
        }
        let Ok(bytes): Result<Vec<u8>, std::io::Error> = std::fs::read(&fx.input_path) else {
            return OracleVerdict::FixtureAbsent {
                rel: fx.input_rel.clone(),
            };
        };
        match fx.oracle {
            OracleKind::ByteIdenticalUnpack => self.eval_byte_identical(fx, &bytes),
            OracleKind::RecompileEquiv => self.eval_recompile(&bytes),
            OracleKind::DifferentialVsSource => self.eval_differential(fx, bytes),
            OracleKind::DetectionDeterministic => self.eval_detection(fx, &bytes),
        }
    }

    fn eval_byte_identical(&self, fx: &ResolvedFixture, packed: &[u8]) -> OracleVerdict {
        let _ = &self.config;
        let Some(baseline_path): Option<&std::path::PathBuf> = fx.baseline_path.as_ref() else {
            return OracleVerdict::NoRecovery {
                note: "manifest declared no baseline original/unpacked artifact".to_owned(),
            };
        };
        if !baseline_path.exists() {
            return OracleVerdict::FixtureAbsent {
                rel: fx.baseline_rel.clone().unwrap_or_default(),
            };
        }
        let Ok(baseline): Result<Vec<u8>, std::io::Error> = std::fs::read(baseline_path) else {
            return OracleVerdict::FixtureAbsent {
                rel: fx.baseline_rel.clone().unwrap_or_default(),
            };
        };
        let recovered: RecoveredImage = match recover_packed(&fx.fixture_id, packed) {
            Ok(image) => image,
            Err(note) => return OracleVerdict::NoRecovery { note },
        };
        if recovered.integrity_verified {
            return OracleVerdict::ByteIdentical;
        }
        parse_pe_sections(&baseline).map_or_else(
            || verdict_for_byte_recovery(&recovered.image, &baseline),
            |sections: Vec<PeSection>| verdict_for_section_witness(&recovered, &sections),
        )
    }

    fn eval_recompile(&self, pyc_bytes: &[u8]) -> OracleVerdict {
        if !self.config.allow_recompile_interpreter {
            return OracleVerdict::ToolMissing {
                tool: "python-interpreter (recompile disabled)".to_owned(),
            };
        }
        let decompiled: NativeDecompile = match decompile_pyc(pyc_bytes) {
            Ok(d) => d,
            Err(e) => {
                return OracleVerdict::PassError {
                    error: format!("py.decompile: {e}"),
                };
            }
        };
        let Some(original_code): Option<CodeObject> = extract_root_code(pyc_bytes) else {
            return OracleVerdict::PassError {
                error: "could not extract root CodeObject from pyc".to_owned(),
            };
        };
        let outcome: disrobe_pass_py_decompile::RoundtripOutcome = roundtrip_native(
            &decompiled.source,
            &original_code,
            &decompiled.decompile_version,
            decompiled.marshal_version,
        );
        match outcome.status {
            RoundtripStatus::Perfect | RoundtripStatus::Semantic => OracleVerdict::Recovered,
            RoundtripStatus::CodeDiff { detail } => OracleVerdict::NoRecovery { note: detail },
            RoundtripStatus::NoInterpreter { hint } => OracleVerdict::ToolMissing { tool: hint },
            RoundtripStatus::RecompileFailed { stderr } => OracleVerdict::PassError {
                error: format!("recompile failed: {stderr}"),
            },
            RoundtripStatus::Skipped => OracleVerdict::ToolMissing {
                tool: "recompile-skipped".to_owned(),
            },
        }
    }

    fn eval_differential(&self, fx: &ResolvedFixture, bytes: Vec<u8>) -> OracleVerdict {
        let source_path: String = format!("corpus://{}", fx.input_rel);
        let doc: ChainDocumentLite = match run_chain_capture(&self.registry, bytes, &source_path) {
            Ok(d) => d,
            Err(e) => return OracleVerdict::PassError { error: e },
        };
        if doc.first_pass.is_none() {
            return OracleVerdict::NoRecovery {
                note: "no pass dispatched for obfuscated input".to_owned(),
            };
        }
        if !doc.completed {
            return OracleVerdict::NoRecovery {
                note: doc
                    .error
                    .unwrap_or_else(|| "chain did not complete".to_owned()),
            };
        }
        let recovered_tokens: usize = doc.recovered_token_count;
        if recovered_tokens == 0 {
            return OracleVerdict::NoRecovery {
                note: "pass produced empty normalized token stream".to_owned(),
            };
        }
        OracleVerdict::Recovered
    }

    fn eval_detection(&self, fx: &ResolvedFixture, bytes: &[u8]) -> OracleVerdict {
        let Some(expected): Option<&String> = fx.expected_detection.as_ref() else {
            return OracleVerdict::NoRecovery {
                note: "manifest declared no expected detection label".to_owned(),
            };
        };
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: Some(fx.input_rel.as_str()),
            parent_hint: None,
            depth: 0,
        };
        let Some(pick): Option<DetectorPick> = self.registry.run_all_and_pick(&ctx) else {
            return OracleVerdict::DetectWrong {
                got: "<none>".to_owned(),
                expected: expected.clone(),
            };
        };
        let got: &str = pick.pass.id();
        if got == expected {
            OracleVerdict::DetectCorrect
        } else {
            OracleVerdict::DetectWrong {
                got: got.to_owned(),
                expected: expected.clone(),
            }
        }
    }
}

fn verdict_for_byte_recovery(recovered: &[u8], baseline: &[u8]) -> OracleVerdict {
    let recovered_hash: [u8; 32] = *blake3::hash(recovered).as_bytes();
    let baseline_hash: [u8; 32] = *blake3::hash(baseline).as_bytes();
    if recovered_hash == baseline_hash {
        return OracleVerdict::ByteIdentical;
    }
    let total: usize = recovered.len().max(baseline.len());
    if total == 0 {
        return OracleVerdict::NoRecovery {
            note: "empty recovered + baseline".to_owned(),
        };
    }
    let common: usize = recovered.len().min(baseline.len());
    let matching: usize = recovered
        .iter()
        .zip(baseline.iter())
        .take(common)
        .filter(|(a, b): &(&u8, &u8)| a == b)
        .count();
    let residual_bp: u32 = (((total - matching) as f64 / total as f64) * 10_000.0).round() as u32;
    OracleVerdict::Lossy {
        residual_bp,
        note: format!(
            "blake3 differs; {matching}/{total} bytes match (residual {residual_bp}bp); recovery is not byte-identical",
        ),
    }
}

#[derive(Debug)]
struct RecoveredImage {
    image: Vec<u8>,
    rva_indexed: bool,
    integrity_verified: bool,
}

fn recover_packed(fixture_id: &str, packed: &[u8]) -> Result<RecoveredImage, String> {
    if fixture_id.starts_with("upx:") {
        let out: UpxUnpackOutput = unpack_upx(packed)
            .map_err(|e: disrobe_pass_native::Error| format!("unpack_upx: {e}"))?;
        return Ok(RecoveredImage {
            image: out.recovered_image,
            rva_indexed: true,
            integrity_verified: out.adler_verified,
        });
    }
    if fixture_id.starts_with("fsg:") {
        let out: disrobe_pass_native::FsgUnpackOutput = unpack_fsg(packed)
            .map_err(|e: disrobe_pass_native::Error| format!("unpack_fsg: {e}"))?;
        return Ok(RecoveredImage {
            image: out.raw_image,
            rva_indexed: false,
            integrity_verified: false,
        });
    }
    if fixture_id.starts_with("mew:") {
        let out: disrobe_pass_native::MewUnpackOutput = unpack_mew(packed)
            .map_err(|e: disrobe_pass_native::Error| format!("unpack_mew: {e}"))?;
        return Ok(RecoveredImage {
            image: out.raw_image,
            rva_indexed: false,
            integrity_verified: false,
        });
    }
    Err(format!(
        "no byte-identical unpacker routed for fixture {fixture_id}",
    ))
}

#[derive(Debug)]
struct PeSection {
    rva: u32,
    bytes: Vec<u8>,
}

fn parse_pe_sections(pe: &[u8]) -> Option<Vec<PeSection>> {
    if pe.len() < 0x40 || pe.get(0..2) != Some(b"MZ") {
        return None;
    }
    let pe_off: usize = u32::from_le_bytes(pe.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if pe_off + 0x18 > pe.len() || pe.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return None;
    }
    let nsec: usize = usize::from(u16::from_le_bytes(
        pe.get(pe_off + 6..pe_off + 8)?.try_into().ok()?,
    ));
    let opt_sz: usize = usize::from(u16::from_le_bytes(
        pe.get(pe_off + 0x14..pe_off + 0x16)?.try_into().ok()?,
    ));
    let sec_off: usize = pe_off + 0x18 + opt_sz;
    let mut out: Vec<PeSection> = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let so: usize = sec_off + 0x28 * i;
        if so + 0x28 > pe.len() {
            break;
        }
        let vs: u32 = u32::from_le_bytes(pe.get(so + 8..so + 12)?.try_into().ok()?);
        let rva: u32 = u32::from_le_bytes(pe.get(so + 12..so + 16)?.try_into().ok()?);
        let rs: u32 = u32::from_le_bytes(pe.get(so + 16..so + 20)?.try_into().ok()?);
        let ro: usize = u32::from_le_bytes(pe.get(so + 20..so + 24)?.try_into().ok()?) as usize;
        let take: usize = rs.min(vs) as usize;
        if take == 0 || ro + take > pe.len() {
            continue;
        }
        out.push(PeSection {
            rva,
            bytes: pe[ro..ro + take].to_vec(),
        });
    }
    if out.is_empty() { None } else { Some(out) }
}

fn verdict_for_section_witness(
    recovered: &RecoveredImage,
    sections: &[PeSection],
) -> OracleVerdict {
    let mut total: usize = 0;
    let mut diffs: usize = 0;
    let mut witnessed: usize = 0;
    for sec in sections {
        let off: usize = if recovered.rva_indexed {
            sec.rva as usize
        } else {
            best_offset(&recovered.image, &sec.bytes)
        };
        if off >= recovered.image.len() {
            continue;
        }
        let avail: usize = recovered.image.len() - off;
        let take: usize = avail.min(sec.bytes.len());
        if take == 0 {
            continue;
        }
        let rec: &[u8] = &recovered.image[off..off + take];
        let orig: &[u8] = &sec.bytes[..take];
        let sec_diff: usize = rec
            .iter()
            .zip(orig.iter())
            .filter(|(a, b): &(&u8, &u8)| a != b)
            .count();
        total += take;
        diffs += sec_diff;
        witnessed += 1;
    }
    if witnessed == 0 || total == 0 {
        return OracleVerdict::NoRecovery {
            note: "no original PE sections witnessed in recovered image".to_owned(),
        };
    }
    if diffs == 0 {
        return OracleVerdict::ByteIdentical;
    }
    let residual_bp: u32 = ((diffs as f64 / total as f64) * 10_000.0).round() as u32;
    OracleVerdict::Lossy {
        residual_bp,
        note: format!(
            "section-witnessed {witnessed} section(s): {diffs}/{total} bytes differ (residual {residual_bp}bp)",
        ),
    }
}

fn best_offset(haystack: &[u8], needle: &[u8]) -> usize {
    let probe: &[u8] = &needle[..needle.len().min(64)];
    if probe.is_empty() {
        return 0;
    }
    haystack
        .windows(probe.len())
        .position(|w: &[u8]| w == probe)
        .unwrap_or(0x1000)
}

fn extract_root_code(pyc_bytes: &[u8]) -> Option<CodeObject> {
    let file: PycFile = read_pyc(pyc_bytes).ok()?;
    match file.code {
        Object::Code(boxed) => Some(*boxed),
        _ => None,
    }
}

#[derive(Debug)]
struct ChainDocumentLite {
    first_pass: Option<String>,
    completed: bool,
    recovered_token_count: usize,
    error: Option<String>,
}

#[derive(Debug, Default)]
struct CapturingRunner {
    captured: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
}

impl PassRunner for CapturingRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: &[u8],
        _config: &ChainConfig,
    ) -> Result<PassRunOutcome, String> {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), blake3_hash(bytes));
        let started: Instant = Instant::now();
        let out_artifact: Artifact = pick.pass.run(&artifact).map_err(|e| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        if let Ok(mut guard) = self.captured.lock() {
            let _prev: Option<Vec<u8>> =
                guard.insert(pick.pass.id().to_owned(), out_artifact.envelope.clone());
        }
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
        })
    }
}

fn run_chain_capture(
    registry: &PassRegistry,
    bytes: Vec<u8>,
    source_path: &str,
) -> Result<ChainDocumentLite, String> {
    let runner: CapturingRunner = CapturingRunner::default();
    let driver: ChainDriver<'_, CapturingRunner> =
        ChainDriver::new(registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let plan: ChainPlan = driver.run(bytes, &spec, Some(source_path.to_owned()));
    let doc: disrobe_core::chain::ChainDocument = disrobe_core::chain::ChainDocument::from_plan(
        &plan,
        &spec,
        "auto:8",
        "playground",
        Some(source_path.to_owned()),
    );
    let first_node: Option<&disrobe_core::chain::NodeDoc> = doc
        .nodes
        .iter()
        .find(|n: &&disrobe_core::chain::NodeDoc| n.pass.is_some());
    let first_pass: Option<String> =
        first_node.and_then(|n: &disrobe_core::chain::NodeDoc| n.pass.clone());
    let completed: bool = doc.nodes.iter().any(|n: &disrobe_core::chain::NodeDoc| {
        matches!(
            n.verdict,
            disrobe_core::chain::chain_json::VerdictDoc::Complete
                | disrobe_core::chain::chain_json::VerdictDoc::Ok
        )
    });
    let error: Option<String> = doc
        .nodes
        .iter()
        .find_map(|n: &disrobe_core::chain::NodeDoc| n.error.clone());
    let recovered_token_count: usize = {
        let guard: std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> = runner
            .captured
            .lock()
            .map_err(|_| "capture mutex poisoned".to_owned())?;
        guard
            .values()
            .map(|v: &Vec<u8>| count_tokens(v))
            .max()
            .unwrap_or(0)
    };
    Ok(ChainDocumentLite {
        first_pass,
        completed,
        recovered_token_count,
        error,
    })
}

fn count_tokens(bytes: &[u8]) -> usize {
    std::str::from_utf8(bytes).map_or(0, |text: &str| {
        text.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '{' | '}' | ',' | ';'))
            .filter(|t: &&str| !t.is_empty())
            .count()
    })
}

fn blake3_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn registry_full() -> PassRegistry {
    let mut r: PassRegistry = PassRegistry::new();
    r.register(&disrobe_pass_pyarmor::chain_detector::PYARMOR_PASS);
    r.register(&disrobe_pass_native::chain_detector::PACKER_PASS);
    r.register(&disrobe_pass_js_deob::chain_detector::JS_OBF_PASS);
    r.register(&disrobe_pass_py_deob::chain_detector::PY_DEOB_PASS);
    r.register(&disrobe_binfmt::chain_detector::CONTAINER_PASS);
    r.register(&disrobe_pass_sourcedefender::chain_detector::SOURCEDEFENDER_PASS);
    r.register(&disrobe_pass_pyfreeze::chain_detector::PYFREEZE_PASS);
    r.register(&disrobe_pass_nuitka::chain_detector::NUITKA_PASS);
    r.register(&disrobe_pass_wasm_deob::chain_detector::WASM_DEOB_PASS);
    r.register(&disrobe_pass_php::chain_detector::PHP_PASS);
    r.register(&disrobe_pass_ruby::chain_detector::RUBY_PASS);
    r.register(&disrobe_pass_shell::chain_detector::SHELL_PASS);
    r.register(&disrobe_pass_mobile::chain_detector::MOBILE_PASS);
    r.register(&disrobe_pass_lua::chain_detector::LUA_PASS);
    r.register(&disrobe_pass_swift_objc::chain_detector::SWIFT_OBJC_PASS);
    r.register(&disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS);
    r.register(&disrobe_pass_py_decompile::chain_detector::PY_DECOMPILE_PASS);
    r.register(&disrobe_pass_pyinstaller::chain_detector::PYINSTALLER_PASS);
    r.register(&disrobe_pass_jvm::chain_detector::JVM_PASS);
    r.register(&disrobe_pass_dotnet::chain_detector::DOTNET_PASS);
    r.register(&disrobe_pass_go::chain_detector::GO_PASS);
    r.register(&disrobe_pass_beam::chain_detector::BEAM_PASS);
    r.register(&disrobe_pass_as3::chain_detector::AS3_PASS);
    r
}
