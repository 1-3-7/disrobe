use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;
use std::time::Instant;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::state_machine::PassRunner;
use disrobe_core::chain::{
    ChainConfig, ChainDriver, ChainPlan, ChainSpec, ChildArtifact, DetectContext, DetectorPick,
    OutputKind, PassRegistry, PassRunOutcome,
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
        let bytes: Vec<u8> = match read_bounded_fixture(
            &fx.input_path,
            &fx.input_rel,
            self.config.max_input_bytes,
        ) {
            Ok(bytes) => bytes,
            Err(verdict) => return verdict,
        };
        match fx.oracle {
            OracleKind::ByteIdenticalUnpack => self.eval_byte_identical(fx, &bytes),
            OracleKind::RecompileEquiv => self.eval_recompile(&bytes),
            OracleKind::DifferentialVsSource => self.eval_differential(fx, bytes),
            OracleKind::DetectionDeterministic => self.eval_detection(fx, &bytes),
        }
    }

    fn eval_byte_identical(&self, fx: &ResolvedFixture, packed: &[u8]) -> OracleVerdict {
        let Some(baseline_path): Option<&std::path::PathBuf> = fx.baseline_path.as_ref() else {
            return OracleVerdict::NoRecovery {
                note: "manifest declared no baseline original/unpacked artifact".to_owned(),
            };
        };
        if !baseline_path.exists() {
            return OracleVerdict::FixtureAbsent {
                rel: fx
                    .baseline_rel
                    .as_ref()
                    .map_or_else(String::new, |value: &String| value.clone()),
            };
        }
        let baseline_rel: String = fx.baseline_rel.clone().unwrap_or_default();
        let baseline: Vec<u8> =
            match read_bounded_fixture(baseline_path, &baseline_rel, self.config.max_input_bytes) {
                Ok(bytes) => bytes,
                Err(verdict) => return verdict,
            };
        let recovered: RecoveredImage = match recover_packed(&fx.fixture_id, packed) {
            Ok(image) => image,
            Err(note) => return OracleVerdict::NoRecovery { note },
        };
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

fn read_bounded_fixture(path: &Path, rel: &str, limit: u64) -> Result<Vec<u8>, OracleVerdict> {
    let file: std::fs::File =
        std::fs::File::open(path).map_err(|_: std::io::Error| OracleVerdict::FixtureAbsent {
            rel: rel.to_owned(),
        })?;
    let reserve: usize = file.metadata().map_or(0, |metadata: std::fs::Metadata| {
        usize::try_from(metadata.len().min(limit)).map_or(0, std::convert::identity)
    });
    let mut reader: std::io::Take<std::fs::File> = file.take(limit.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::with_capacity(reserve);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_: std::io::Error| OracleVerdict::FixtureAbsent {
            rel: rel.to_owned(),
        })?;
    let len: u64 = u64::try_from(bytes.len()).map_or(u64::MAX, std::convert::identity);
    if len > limit {
        return Err(OracleVerdict::ToolMissing {
            tool: format!("memory-budget-exceeded:{len}B"),
        });
    }
    Ok(bytes)
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
    name: String,
    rva: u32,
    bytes: Vec<u8>,
}

fn parse_pe_sections(pe: &[u8]) -> Option<Vec<PeSection>> {
    if pe.len() < 0x40 || pe.get(0..2) != Some(b"MZ") {
        return None;
    }
    let pe_off: usize =
        usize::try_from(u32::from_le_bytes(pe.get(0x3C..0x40)?.try_into().ok()?)).ok()?;
    let pe_sig_end: usize = pe_off.checked_add(4)?;
    let coff_end: usize = pe_off.checked_add(0x18)?;
    if coff_end > pe.len() || pe.get(pe_off..pe_sig_end) != Some(b"PE\0\0") {
        return None;
    }
    let nsec: usize = usize::from(u16::from_le_bytes(
        pe.get(pe_off + 6..pe_off + 8)?.try_into().ok()?,
    ));
    let opt_sz: usize = usize::from(u16::from_le_bytes(
        pe.get(pe_off + 0x14..pe_off + 0x16)?.try_into().ok()?,
    ));
    let sec_off: usize = pe_off.checked_add(0x18)?.checked_add(opt_sz)?;
    let possible_sections: usize = pe.len().saturating_sub(sec_off) / 0x28;
    let mut out: Vec<PeSection> = Vec::with_capacity(nsec.min(possible_sections));
    for i in 0..nsec {
        let Some(so): Option<usize> = 0x28usize
            .checked_mul(i)
            .and_then(|delta| sec_off.checked_add(delta))
        else {
            break;
        };
        let Some(section_end): Option<usize> = so.checked_add(0x28) else {
            break;
        };
        if section_end > pe.len() {
            break;
        }
        let vs: u32 = u32::from_le_bytes(pe.get(so + 8..so + 12)?.try_into().ok()?);
        let rva: u32 = u32::from_le_bytes(pe.get(so + 12..so + 16)?.try_into().ok()?);
        let rs: u32 = u32::from_le_bytes(pe.get(so + 16..so + 20)?.try_into().ok()?);
        let ro: usize = usize::try_from(u32::from_le_bytes(
            pe.get(so + 20..so + 24)?.try_into().ok()?,
        ))
        .ok()?;
        let take: usize = usize::try_from(rs.min(vs)).ok()?;
        let Some(raw_end): Option<usize> = ro.checked_add(take) else {
            continue;
        };
        if take == 0 || raw_end > pe.len() {
            continue;
        }
        let name: String = pe.get(so..so + 8).map_or_else(String::new, |raw: &[u8]| {
            String::from_utf8_lossy(raw)
                .trim_end_matches('\0')
                .to_owned()
        });
        out.push(PeSection {
            name,
            rva,
            bytes: pe[ro..raw_end].to_vec(),
        });
    }
    if out.is_empty() { None } else { Some(out) }
}

fn is_loader_rebuilt_zone(name: &str) -> bool {
    matches!(name, ".reloc" | ".rdata" | ".data" | ".idata")
}

fn verdict_for_section_witness(
    recovered: &RecoveredImage,
    sections: &[PeSection],
) -> OracleVerdict {
    let image_base_rva: usize = sections
        .iter()
        .map(|s: &PeSection| usize::try_from(s.rva).map_or(usize::MAX, std::convert::identity))
        .min()
        .unwrap_or(0);
    let mut content_total: usize = 0;
    let mut content_diffs: usize = 0;
    let mut loader_total: usize = 0;
    let mut loader_diffs: usize = 0;
    let mut witnessed: usize = 0;
    for sec in sections {
        let off: usize = if recovered.rva_indexed {
            usize::try_from(sec.rva)
                .map_or(usize::MAX, std::convert::identity)
                .saturating_sub(image_base_rva)
        } else {
            let Some(found): Option<usize> = best_offset(&recovered.image, &sec.bytes) else {
                continue;
            };
            found
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
        if is_loader_rebuilt_zone(&sec.name) {
            loader_total += take;
            loader_diffs += sec_diff;
        } else {
            content_total += take;
            content_diffs += sec_diff;
        }
        witnessed += 1;
    }
    let total: usize = content_total + loader_total;
    if witnessed == 0 || total == 0 {
        return OracleVerdict::NoRecovery {
            note: "no original PE sections witnessed in recovered image".to_owned(),
        };
    }
    let diffs: usize = content_diffs + loader_diffs;
    if diffs == 0 {
        return OracleVerdict::ByteIdentical;
    }
    if content_diffs == 0 && recovered.integrity_verified {
        return OracleVerdict::ByteIdentical;
    }
    let residual_bp: u32 = ((diffs as f64 / total as f64) * 10_000.0).round() as u32;
    let adler_note: &str = if recovered.integrity_verified {
        "; unpacker self-checksum passed yet baseline content sections differ"
    } else {
        ""
    };
    OracleVerdict::Lossy {
        residual_bp,
        note: format!(
            "section-witnessed {witnessed} section(s): content {content_diffs}/{content_total} B, loader-rebuilt {loader_diffs}/{loader_total} B differ (residual {residual_bp}bp){adler_note}",
        ),
    }
}

fn best_offset(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let probe: &[u8] = &needle[..needle.len().min(64)];
    if probe.is_empty() {
        return None;
    }
    haystack
        .windows(probe.len())
        .position(|w: &[u8]| w == probe)
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
        bytes: Vec<u8>,
        _config: &ChainConfig,
        path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        let hash: [u8; 32] = blake3_hash(&bytes);
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, hash);
        let started: Instant = Instant::now();
        let out_artifact: Artifact = pick
            .pass
            .run_with_path(&artifact, path_hint)
            .map_err(|e| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        if let Ok(mut guard) = self.captured.lock() {
            let _prev: Option<Vec<u8>> =
                guard.insert(pick.pass.id().to_owned(), out_artifact.envelope.clone());
        }
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children(&artifact)
                .map_err(|e| format!("{e}"))?;
            OutputKind::mixed_from_children(extracted)
        } else {
            (kind, Vec::new())
        };
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
            children,
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
            .map_or(0, |value: usize| value)
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
    disrobe_passes::build_registry()
}

#[cfg(test)]
mod tests {
    use super::{
        OracleVerdict, PeSection, RecoveredImage, best_offset, parse_pe_sections,
        read_bounded_fixture, verdict_for_section_witness,
    };

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn pe_with_section(raw_offset: u32, raw_size: u32, virtual_size: u32) -> Vec<u8> {
        let mut pe: Vec<u8> = vec![0u8; 0x200];
        pe[0..2].copy_from_slice(b"MZ");
        let pe_off: usize = 0x80;
        write_u32(
            &mut pe,
            0x3c,
            u32::try_from(pe_off).map_or(u32::MAX, std::convert::identity),
        );
        pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut pe, pe_off + 6, 1);
        let section: usize = pe_off + 0x18;
        write_u32(&mut pe, section + 8, virtual_size);
        write_u32(&mut pe, section + 12, 0x1000);
        write_u32(&mut pe, section + 16, raw_size);
        write_u32(&mut pe, section + 20, raw_offset);
        let start: usize = usize::try_from(raw_offset).map_or(usize::MAX, std::convert::identity);
        if start < pe.len() {
            let end: usize = pe.len().min(start.saturating_add(4));
            pe[start..end].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd][..end - start]);
        }
        pe
    }

    #[test]
    fn pe_sections_read_valid_raw_range() {
        let sections: Option<Vec<PeSection>> = parse_pe_sections(&pe_with_section(0x100, 4, 4));
        assert_eq!(sections.as_ref().map(Vec::len), Some(1));
        if let Some(sections) = sections {
            assert_eq!(sections[0].rva, 0x1000);
            assert_eq!(sections[0].bytes, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        }
    }

    #[test]
    fn pe_sections_skip_raw_range_past_file() {
        assert!(parse_pe_sections(&pe_with_section(0x1f0, 0x40, 0x40)).is_none());
    }

    #[test]
    fn bounded_fixture_reader_rejects_over_limit_input() {
        let tmp_result: Result<tempfile::TempDir, std::io::Error> = tempfile::tempdir();
        assert!(tmp_result.is_ok());
        let Ok(tmp): Result<tempfile::TempDir, std::io::Error> = tmp_result else {
            return;
        };
        let path: std::path::PathBuf = tmp.path().join("sample.bin");
        let write_result: Result<(), std::io::Error> = std::fs::write(&path, b"abcd");
        assert!(write_result.is_ok());
        let result: Result<Vec<u8>, OracleVerdict> = read_bounded_fixture(&path, "sample.bin", 3);
        assert_eq!(
            result,
            Err(OracleVerdict::ToolMissing {
                tool: "memory-budget-exceeded:4B".to_owned(),
            })
        );
    }

    #[test]
    fn self_checksum_does_not_force_byte_identical_when_baseline_differs() {
        let mut image: Vec<u8> = vec![0u8; 0x20];
        image[0x00..0x04].copy_from_slice(&[0x09, 0x09, 0x09, 0x09]);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: true,
            integrity_verified: true,
        };
        let sections: Vec<PeSection> = vec![PeSection {
            name: ".text".to_owned(),
            rva: 0x1000,
            bytes: vec![0x01, 0x02, 0x03, 0x04],
        }];
        let verdict: OracleVerdict = verdict_for_section_witness(&recovered, &sections);
        assert!(
            !verdict.is_byte_identical(),
            "a passing unpacker self-checksum must not grade byte-identical against a differing content section: {verdict:?}",
        );
        assert!(matches!(verdict, OracleVerdict::Lossy { .. }));
    }

    #[test]
    fn byte_identical_derives_from_baseline_witness_not_checksum() {
        let mut image: Vec<u8> = vec![0u8; 0x20];
        image[0x00..0x04].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: true,
            integrity_verified: false,
        };
        let sections: Vec<PeSection> = vec![PeSection {
            name: ".text".to_owned(),
            rva: 0x1000,
            bytes: vec![0x01, 0x02, 0x03, 0x04],
        }];
        let verdict: OracleVerdict = verdict_for_section_witness(&recovered, &sections);
        assert_eq!(verdict, OracleVerdict::ByteIdentical);
    }

    #[test]
    fn loader_rebuilt_zone_residual_is_excused_only_with_verified_integrity() {
        let mut image: Vec<u8> = vec![0u8; 0x200];
        image[0x00..0x04].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        image[0x100..0x104].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let sections: Vec<PeSection> = vec![
            PeSection {
                name: ".text".to_owned(),
                rva: 0x1000,
                bytes: vec![0x01, 0x02, 0x03, 0x04],
            },
            PeSection {
                name: ".rdata".to_owned(),
                rva: 0x1100,
                bytes: vec![0x00, 0x00, 0x00, 0x00],
            },
        ];
        let with_witness: OracleVerdict = verdict_for_section_witness(
            &RecoveredImage {
                image: image.clone(),
                rva_indexed: true,
                integrity_verified: true,
            },
            &sections,
        );
        assert_eq!(
            with_witness,
            OracleVerdict::ByteIdentical,
            "content byte-identical plus a verified decompression witness must grade byte-identical even when a loader-rebuilt zone differs: {with_witness:?}",
        );
        let no_witness: OracleVerdict = verdict_for_section_witness(
            &RecoveredImage {
                image,
                rva_indexed: true,
                integrity_verified: false,
            },
            &sections,
        );
        assert!(
            matches!(no_witness, OracleVerdict::Lossy { .. }),
            "without a decompression witness a differing loader-rebuilt zone must stay lossy: {no_witness:?}",
        );
    }

    #[test]
    fn absent_section_is_not_witnessed_at_fabricated_offset() {
        let mut image: Vec<u8> = vec![0u8; 0x2000];
        image[0x1000..0x1004].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: false,
            integrity_verified: false,
        };
        let sections: Vec<PeSection> = vec![PeSection {
            name: ".text".to_owned(),
            rva: 0,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        }];
        let verdict: OracleVerdict = verdict_for_section_witness(&recovered, &sections);
        assert!(
            matches!(verdict, OracleVerdict::NoRecovery { .. }),
            "an absent section must not be counted as witnessed at a fabricated offset: {verdict:?}",
        );
    }

    #[test]
    fn best_offset_is_none_when_probe_absent() {
        assert_eq!(best_offset(&[0x01, 0x02, 0x03], &[0x09, 0x09]), None);
    }

    #[test]
    fn best_offset_locates_present_probe() {
        assert_eq!(
            best_offset(&[0x01, 0x02, 0x03, 0x04], &[0x03, 0x04]),
            Some(2)
        );
    }
}
