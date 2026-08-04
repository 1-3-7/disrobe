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
    let Some(residual_bp): Option<u32> = residual_basis_points(total - matching, total) else {
        return OracleVerdict::NoRecovery {
            note: "invalid byte-comparison totals".to_owned(),
        };
    };
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
    internal_checksum_verified: bool,
}

fn recover_packed(fixture_id: &str, packed: &[u8]) -> Result<RecoveredImage, String> {
    if fixture_id.starts_with("upx:") {
        let out: UpxUnpackOutput = unpack_upx(packed)
            .map_err(|e: disrobe_pass_native::Error| format!("unpack_upx: {e}"))?;
        return Ok(RecoveredImage {
            image: out.recovered_image,
            rva_indexed: true,
            internal_checksum_verified: out.adler_verified,
        });
    }
    if fixture_id.starts_with("fsg:") {
        let out: disrobe_pass_native::FsgUnpackOutput = unpack_fsg(packed)
            .map_err(|e: disrobe_pass_native::Error| format!("unpack_fsg: {e}"))?;
        return Ok(RecoveredImage {
            image: out.raw_image,
            rva_indexed: false,
            internal_checksum_verified: false,
        });
    }
    if fixture_id.starts_with("mew:") {
        let out: disrobe_pass_native::MewUnpackOutput = unpack_mew(packed)
            .map_err(|e: disrobe_pass_native::Error| format!("unpack_mew: {e}"))?;
        return Ok(RecoveredImage {
            image: out.raw_image,
            rva_indexed: false,
            internal_checksum_verified: false,
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
        let so: usize = 0x28usize
            .checked_mul(i)
            .and_then(|delta| sec_off.checked_add(delta))?;
        let section_end: usize = so.checked_add(0x28)?;
        if section_end > pe.len() {
            return None;
        }
        let vs: u32 = u32::from_le_bytes(pe.get(so + 8..so + 12)?.try_into().ok()?);
        let rva: u32 = u32::from_le_bytes(pe.get(so + 12..so + 16)?.try_into().ok()?);
        let rs: u32 = u32::from_le_bytes(pe.get(so + 16..so + 20)?.try_into().ok()?);
        let ro: usize = usize::try_from(u32::from_le_bytes(
            pe.get(so + 20..so + 24)?.try_into().ok()?,
        ))
        .ok()?;
        let take: usize = usize::try_from(rs.min(vs)).ok()?;
        let raw_end: usize = ro.checked_add(take)?;
        if take == 0 {
            continue;
        }
        if raw_end > pe.len() {
            return None;
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

fn is_loader_affected_section(name: &str) -> bool {
    matches!(name, ".reloc" | ".rdata" | ".data" | ".idata")
}

fn residual_basis_points(residual: usize, total: usize) -> Option<u32> {
    if total == 0 || residual > total {
        return None;
    }
    if residual == 0 {
        return Some(0);
    }
    let numerator: u128 = u128::try_from(residual).ok()?.checked_mul(10_000)?;
    let denominator: u128 = u128::try_from(total).ok()?;
    let mut low: u32 = 1;
    let mut high: u32 = 10_000;
    while low < high {
        let midpoint: u32 = low + (high - low) / 2;
        if u128::from(midpoint).saturating_mul(denominator) >= numerator {
            high = midpoint;
        } else {
            low = midpoint + 1;
        }
    }
    Some(low)
}

#[derive(Clone, Copy)]
struct NonRvaCandidate {
    offset: Option<usize>,
    end: usize,
    residual: usize,
}

struct NonRvaPlan {
    placements: Vec<Option<usize>>,
    residual: usize,
}

struct NonRvaSearchState {
    assigned: Vec<bool>,
    placements: Vec<Option<usize>>,
    claimed: Vec<(usize, usize)>,
    states: usize,
    work_units: usize,
    best: NonRvaPlan,
}

const MAX_NON_RVA_CANDIDATE_BYTES: usize = 64 * 1024 * 1024;

fn candidate_is_available(
    candidate: NonRvaCandidate,
    claimed: &[(usize, usize)],
    work_units: &mut usize,
) -> Result<bool, ()> {
    const MAX_SEARCH_WORK_UNITS: usize = 2_000_000;

    *work_units = work_units
        .checked_add(claimed.len().saturating_add(1))
        .ok_or(())?;
    if *work_units > MAX_SEARCH_WORK_UNITS {
        return Err(());
    }
    Ok(candidate.offset.is_none_or(|offset: usize| {
        claimed
            .iter()
            .all(|(start, end): &(usize, usize)| candidate.end <= *start || offset >= *end)
    }))
}

fn enumerate_non_rva_candidates(
    image: &[u8],
    section: &PeSection,
    examined_windows: &mut usize,
    candidate_bytes_compared: &mut usize,
) -> Result<Vec<NonRvaCandidate>, &'static str> {
    const MAX_CANDIDATES_PER_SECTION: usize = 256;
    const MAX_EXAMINED_WINDOWS: usize = 1_000_000;

    let probe: &[u8] = &section.bytes[..section.bytes.len().min(64)];
    if probe.is_empty() {
        return Ok(Vec::new());
    }
    let mut candidates: Vec<NonRvaCandidate> = Vec::new();
    for (offset, window) in image.windows(probe.len()).enumerate() {
        *examined_windows = examined_windows
            .checked_add(1)
            .ok_or("non-RVA section assignment exceeded its scan budget")?;
        if *examined_windows > MAX_EXAMINED_WINDOWS {
            return Err("non-RVA section assignment exceeded its scan budget");
        }
        if window != probe {
            continue;
        }
        let end: usize = offset
            .checked_add(section.bytes.len())
            .ok_or("non-RVA section candidate range overflowed")?;
        let Some(recovered): Option<&[u8]> = image.get(offset..end) else {
            continue;
        };
        *candidate_bytes_compared = candidate_bytes_compared
            .checked_add(section.bytes.len())
            .ok_or("non-RVA section assignment exceeded its comparison budget")?;
        if *candidate_bytes_compared > MAX_NON_RVA_CANDIDATE_BYTES {
            return Err("non-RVA section assignment exceeded its comparison budget");
        }
        let residual: usize = recovered
            .iter()
            .zip(section.bytes.iter())
            .filter(|(left, right): &(&u8, &u8)| left != right)
            .count();
        candidates.push(NonRvaCandidate {
            offset: Some(offset),
            end,
            residual,
        });
        if candidates.len() > MAX_CANDIDATES_PER_SECTION {
            return Err("non-RVA section assignment exceeded its candidate budget");
        }
    }
    candidates.push(NonRvaCandidate {
        offset: None,
        end: 0,
        residual: section.bytes.len(),
    });
    candidates.sort_by_key(|candidate: &NonRvaCandidate| {
        (candidate.residual, candidate.offset.unwrap_or(usize::MAX))
    });
    Ok(candidates)
}

fn search_non_rva_plan(
    sections: &[&PeSection],
    candidates: &[Vec<NonRvaCandidate>],
    accumulated: usize,
    state: &mut NonRvaSearchState,
) -> Result<bool, ()> {
    const MAX_SEARCH_STATES: usize = 200_000;

    state.states = state.states.checked_add(1).ok_or(())?;
    if state.states > MAX_SEARCH_STATES {
        return Err(());
    }
    let mut lower_bound: usize = accumulated;
    for (index, section_candidates) in candidates.iter().enumerate() {
        if state.assigned[index] {
            continue;
        }
        let mut minimum: usize = sections[index].bytes.len();
        for candidate in section_candidates {
            if candidate_is_available(*candidate, &state.claimed, &mut state.work_units)? {
                minimum = minimum.min(candidate.residual);
            }
        }
        lower_bound = lower_bound.saturating_add(minimum);
    }
    if lower_bound > state.best.residual {
        return Ok(false);
    }
    if state.assigned.iter().all(|value: &bool| *value) {
        if accumulated < state.best.residual
            || (accumulated == state.best.residual
                && state.placements.as_slice() < state.best.placements.as_slice())
        {
            state.best.residual = accumulated;
            state.best.placements.clone_from_slice(&state.placements);
        }
        return Ok(accumulated == 0);
    }
    let mut selected: Option<(usize, usize)> = None;
    for (index, section_candidates) in candidates.iter().enumerate() {
        if state.assigned[index] {
            continue;
        }
        let mut viable: usize = 0;
        for candidate in section_candidates {
            if candidate_is_available(*candidate, &state.claimed, &mut state.work_units)? {
                viable = viable.saturating_add(1);
            }
        }
        let replace: bool = selected.is_none_or(|(current, current_viable): (usize, usize)| {
            viable < current_viable
                || (viable == current_viable
                    && (sections[index].bytes.len() > sections[current].bytes.len()
                        || (sections[index].bytes.len() == sections[current].bytes.len()
                            && index < current)))
        });
        if replace {
            selected = Some((index, viable));
        }
    }
    let Some((index, _)): Option<(usize, usize)> = selected else {
        return Ok(false);
    };
    state.assigned[index] = true;
    for candidate in candidates[index].iter().copied() {
        if !candidate_is_available(candidate, &state.claimed, &mut state.work_units)? {
            continue;
        }
        state.placements[index] = candidate.offset;
        let claimed_range: bool = candidate.offset.is_some();
        if let Some(offset) = candidate.offset {
            let offset: usize = offset;
            state.claimed.push((offset, candidate.end));
        }
        let found_zero: bool = search_non_rva_plan(
            sections,
            candidates,
            accumulated.saturating_add(candidate.residual),
            state,
        )?;
        if claimed_range {
            state.claimed.pop();
        }
        if found_zero {
            state.assigned[index] = false;
            return Ok(true);
        }
    }
    state.placements[index] = None;
    state.assigned[index] = false;
    Ok(false)
}

fn optimize_non_rva_sections(
    image: &[u8],
    sections: &[PeSection],
) -> Result<NonRvaPlan, &'static str> {
    const MAX_NON_RVA_SECTIONS: usize = 32;
    const MAX_TOTAL_CANDIDATES: usize = 2_048;

    let expected: Vec<&PeSection> = sections
        .iter()
        .filter(|section: &&PeSection| !section.bytes.is_empty())
        .collect();
    if expected.is_empty() || expected.len() > MAX_NON_RVA_SECTIONS {
        return Err("non-RVA section assignment exceeded its section budget");
    }
    let mut candidate_sets: Vec<Vec<NonRvaCandidate>> = Vec::with_capacity(expected.len());
    let mut total_candidates: usize = 0;
    let mut examined_windows: usize = 0;
    let mut candidate_bytes_compared: usize = 0;
    for section in &expected {
        let candidates: Vec<NonRvaCandidate> = enumerate_non_rva_candidates(
            image,
            section,
            &mut examined_windows,
            &mut candidate_bytes_compared,
        )?;
        total_candidates = total_candidates.saturating_add(candidates.len());
        if total_candidates > MAX_TOTAL_CANDIDATES {
            return Err("non-RVA section assignment exceeded its candidate budget");
        }
        candidate_sets.push(candidates);
    }
    let initial_residual: usize = expected
        .iter()
        .map(|section: &&PeSection| section.bytes.len())
        .fold(0usize, usize::saturating_add);
    let mut state: NonRvaSearchState = NonRvaSearchState {
        assigned: vec![false; expected.len()],
        placements: vec![None; expected.len()],
        claimed: Vec::new(),
        states: 0,
        work_units: 0,
        best: NonRvaPlan {
            placements: vec![None; expected.len()],
            residual: initial_residual,
        },
    };
    search_non_rva_plan(&expected, &candidate_sets, 0, &mut state)
        .map_err(|()| "non-RVA section assignment exceeded its search budget")?;
    Ok(state.best)
}

fn verdict_for_non_rva_sections(
    recovered: &RecoveredImage,
    sections: &[PeSection],
) -> OracleVerdict {
    let expected: Vec<&PeSection> = sections
        .iter()
        .filter(|section: &&PeSection| !section.bytes.is_empty())
        .collect();
    let plan: NonRvaPlan = match optimize_non_rva_sections(&recovered.image, sections) {
        Ok(plan) => plan,
        Err(note) => {
            return OracleVerdict::NoRecovery {
                note: note.to_owned(),
            };
        }
    };
    let mut content_total: usize = 0;
    let mut content_residual: usize = 0;
    let mut loader_total: usize = 0;
    let mut loader_residual: usize = 0;
    let mut fully_compared_sections: usize = 0;
    let mut compared_bytes: usize = 0;
    let mut unlocated_sections: usize = 0;
    for (section, placement) in expected.iter().zip(plan.placements.iter()) {
        let loader_affected: bool = is_loader_affected_section(&section.name);
        let section_residual: usize = placement.map_or(section.bytes.len(), |offset: usize| {
            let end: usize = offset + section.bytes.len();
            let recovered_section: &[u8] = &recovered.image[offset..end];
            recovered_section
                .iter()
                .zip(section.bytes.iter())
                .filter(|(left, right): &(&u8, &u8)| left != right)
                .count()
        });
        if placement.is_some() {
            fully_compared_sections += 1;
            compared_bytes += section.bytes.len();
        } else {
            unlocated_sections += 1;
        }
        if loader_affected {
            loader_total += section.bytes.len();
            loader_residual += section_residual;
        } else {
            content_total += section.bytes.len();
            content_residual += section_residual;
        }
    }
    let total: usize = content_total + loader_total;
    if compared_bytes == 0 || total == 0 {
        return OracleVerdict::NoRecovery {
            note: "no baseline PE section probe was located in the recovered image".to_owned(),
        };
    }
    if plan.residual == 0 && fully_compared_sections == expected.len() {
        return OracleVerdict::ByteIdentical;
    }
    let Some(residual_bp): Option<u32> = residual_basis_points(plan.residual, total) else {
        return OracleVerdict::NoRecovery {
            note: "invalid section-comparison totals".to_owned(),
        };
    };
    let checksum_note: &str = if recovered.internal_checksum_verified {
        "; internal unpacker checksum passed"
    } else {
        ""
    };
    OracleVerdict::Lossy {
        residual_bp,
        note: format!(
            "baseline sections fully compared {fully_compared_sections}/{}; content residual {content_residual}/{content_total} B; loader-affected residual {loader_residual}/{loader_total} B; probe-unlocated {unlocated_sections}, truncated 0; residual {residual_bp}bp{checksum_note}",
            expected.len(),
        ),
    }
}

fn verdict_for_section_witness(
    recovered: &RecoveredImage,
    sections: &[PeSection],
) -> OracleVerdict {
    if !recovered.rva_indexed {
        return verdict_for_non_rva_sections(recovered, sections);
    }
    let image_base_rva: usize = sections
        .iter()
        .map(|s: &PeSection| usize::try_from(s.rva).map_or(usize::MAX, std::convert::identity))
        .min()
        .unwrap_or(0);
    let mut content_total: usize = 0;
    let mut content_residual: usize = 0;
    let mut loader_total: usize = 0;
    let mut loader_residual: usize = 0;
    let mut expected_sections: usize = 0;
    let mut fully_compared_sections: usize = 0;
    let mut compared_bytes: usize = 0;
    let mut unlocated_sections: usize = 0;
    let mut truncated_sections: usize = 0;
    for sec in sections {
        if sec.bytes.is_empty() {
            continue;
        }
        expected_sections += 1;
        let loader_affected: bool = is_loader_affected_section(&sec.name);
        if loader_affected {
            loader_total += sec.bytes.len();
        } else {
            content_total += sec.bytes.len();
        }
        let offset: Option<usize> = Some(
            usize::try_from(sec.rva)
                .map_or(usize::MAX, std::convert::identity)
                .saturating_sub(image_base_rva),
        );
        let Some(off): Option<usize> = offset else {
            unlocated_sections += 1;
            if loader_affected {
                loader_residual += sec.bytes.len();
            } else {
                content_residual += sec.bytes.len();
            }
            continue;
        };
        if off >= recovered.image.len() {
            unlocated_sections += 1;
            if loader_affected {
                loader_residual += sec.bytes.len();
            } else {
                content_residual += sec.bytes.len();
            }
            continue;
        }
        let avail: usize = recovered.image.len() - off;
        let take: usize = avail.min(sec.bytes.len());
        if take == 0 {
            unlocated_sections += 1;
            if loader_affected {
                loader_residual += sec.bytes.len();
            } else {
                content_residual += sec.bytes.len();
            }
            continue;
        }
        let rec: &[u8] = &recovered.image[off..off + take];
        let orig: &[u8] = &sec.bytes[..take];
        let compared_diffs: usize = rec
            .iter()
            .zip(orig.iter())
            .filter(|(a, b): &(&u8, &u8)| a != b)
            .count();
        let unavailable: usize = sec.bytes.len() - take;
        let section_residual: usize = compared_diffs + unavailable;
        compared_bytes += take;
        if unavailable == 0 {
            fully_compared_sections += 1;
        } else {
            truncated_sections += 1;
        }
        if loader_affected {
            loader_residual += section_residual;
        } else {
            content_residual += section_residual;
        }
    }
    let total: usize = content_total + loader_total;
    if compared_bytes == 0 || total == 0 {
        return OracleVerdict::NoRecovery {
            note: "no baseline PE section bytes were located in the recovered image".to_owned(),
        };
    }
    let residual_bytes: usize = content_residual + loader_residual;
    if residual_bytes == 0 && fully_compared_sections == expected_sections {
        return OracleVerdict::ByteIdentical;
    }
    let Some(residual_bp): Option<u32> = residual_basis_points(residual_bytes, total) else {
        return OracleVerdict::NoRecovery {
            note: "invalid section-comparison totals".to_owned(),
        };
    };
    let checksum_note: &str = if recovered.internal_checksum_verified {
        "; internal unpacker checksum passed"
    } else {
        ""
    };
    OracleVerdict::Lossy {
        residual_bp,
        note: format!(
            "baseline sections fully compared {fully_compared_sections}/{expected_sections}; content residual {content_residual}/{content_total} B; loader-affected residual {loader_residual}/{loader_total} B; unlocated {unlocated_sections}, truncated {truncated_sections}; residual {residual_bp}bp{checksum_note}",
        ),
    }
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

#[cfg(test)]
mod tests {
    use super::{
        MAX_NON_RVA_CANDIDATE_BYTES, OracleVerdict, PeSection, RecoveredImage,
        enumerate_non_rva_candidates, parse_pe_sections, read_bounded_fixture,
        verdict_for_byte_recovery, verdict_for_section_witness,
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
    fn pe_sections_reject_partial_declared_section_set() {
        let mut pe: Vec<u8> = pe_with_section(0x180, 4, 4);
        let pe_offset: usize = 0x80;
        write_u16(&mut pe, pe_offset + 6, 2);
        let second: usize = pe_offset + 0x18 + 0x28;
        write_u32(&mut pe, second + 8, 0x40);
        write_u32(&mut pe, second + 12, 0x1100);
        write_u32(&mut pe, second + 16, 0x40);
        write_u32(&mut pe, second + 20, 0x1f0);
        assert!(parse_pe_sections(&pe).is_none());
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
    fn internal_unpacker_checksum_does_not_override_baseline_difference() {
        let mut image: Vec<u8> = vec![0u8; 0x20];
        image[0x00..0x04].copy_from_slice(&[0x09, 0x09, 0x09, 0x09]);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: true,
            internal_checksum_verified: true,
        };
        let sections: Vec<PeSection> = vec![PeSection {
            name: ".text".to_owned(),
            rva: 0x1000,
            bytes: vec![0x01, 0x02, 0x03, 0x04],
        }];
        let verdict: OracleVerdict = verdict_for_section_witness(&recovered, &sections);
        assert!(
            !verdict.is_byte_identical(),
            "a passing internal unpacker checksum must not grade byte-identical against a differing content section: {verdict:?}",
        );
        assert!(matches!(verdict, OracleVerdict::Lossy { .. }));
    }

    #[test]
    fn real_upx_loader_residual_is_never_byte_identical() -> Result<(), String> {
        const PACKED: &[u8] =
            include_bytes!("../../../corpus/native/packers/upx/hello.packed.nrv2b.exe");
        const ORIGINAL: &[u8] =
            include_bytes!("../../../corpus/native/packers/upx/hello.original.exe");

        let recovered: RecoveredImage =
            super::recover_packed("upx:hello.packed.nrv2b.exe", PACKED)?;
        assert!(recovered.internal_checksum_verified);
        let sections: Vec<PeSection> = parse_pe_sections(ORIGINAL)
            .ok_or_else(|| "parse original UPX fixture sections".to_owned())?;
        let image_base_rva: usize = sections
            .iter()
            .map(|section: &PeSection| {
                usize::try_from(section.rva).map_or(usize::MAX, std::convert::identity)
            })
            .min()
            .ok_or_else(|| "original UPX fixture has no sections".to_owned())?;
        assert!(
            sections
                .iter()
                .filter(|section: &&PeSection| {
                    matches!(
                        section.name.as_str(),
                        ".reloc" | ".rdata" | ".data" | ".idata"
                    )
                })
                .any(|section: &PeSection| {
                    let offset: usize = usize::try_from(section.rva)
                        .map_or(usize::MAX, std::convert::identity)
                        .saturating_sub(image_base_rva);
                    offset
                        .checked_add(section.bytes.len())
                        .and_then(|end: usize| recovered.image.get(offset..end))
                        .is_some_and(|actual: &[u8]| actual != section.bytes.as_slice())
                }),
            "the committed UPX pair must contain a witnessed loader-affected residual",
        );
        let verdict: OracleVerdict = verdict_for_section_witness(&recovered, &sections);

        assert!(
            matches!(
                &verdict,
                OracleVerdict::Lossy { residual_bp, .. } if *residual_bp > 0
            ),
            "loader-affected bytes differ from the original, so the result cannot be byte-identical: {verdict:?}",
        );
        Ok(())
    }

    #[test]
    fn byte_identical_derives_from_baseline_witness_not_checksum() {
        let mut image: Vec<u8> = vec![0u8; 0x20];
        image[0x00..0x04].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: true,
            internal_checksum_verified: false,
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
    fn complete_exact_sections_are_byte_identical() {
        let mut image: Vec<u8> = vec![0u8; 0x104];
        image[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        image[0x100..0x104].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: true,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![
            PeSection {
                name: ".text".to_owned(),
                rva: 0x1000,
                bytes: vec![0x01, 0x02, 0x03, 0x04],
            },
            PeSection {
                name: ".rdata".to_owned(),
                rva: 0x1100,
                bytes: vec![0xaa, 0xbb, 0xcc, 0xdd],
            },
        ];
        assert_eq!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::ByteIdentical
        );
    }

    #[test]
    fn truncated_matching_section_is_lossy() {
        let recovered: RecoveredImage = RecoveredImage {
            image: vec![0x01, 0x02],
            rva_indexed: true,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![PeSection {
            name: ".text".to_owned(),
            rva: 0x1000,
            bytes: vec![0x01, 0x02, 0x03, 0x04],
        }];
        assert!(matches!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::Lossy {
                residual_bp: 5000,
                ..
            }
        ));
    }

    #[test]
    fn missing_section_prevents_byte_identical() {
        let recovered: RecoveredImage = RecoveredImage {
            image: vec![0x01, 0x02, 0x03, 0x04],
            rva_indexed: true,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![
            PeSection {
                name: ".text".to_owned(),
                rva: 0x1000,
                bytes: vec![0x01, 0x02, 0x03, 0x04],
            },
            PeSection {
                name: ".rdata".to_owned(),
                rva: 0x1100,
                bytes: vec![0xaa, 0xbb, 0xcc, 0xdd],
            },
        ];
        assert!(matches!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::Lossy {
                residual_bp: 5000,
                ..
            }
        ));
    }

    #[test]
    fn unlocated_section_prevents_byte_identical() {
        let recovered: RecoveredImage = RecoveredImage {
            image: vec![0x01, 0x02, 0x03, 0x04],
            rva_indexed: false,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![
            PeSection {
                name: ".text".to_owned(),
                rva: 0,
                bytes: vec![0x01, 0x02, 0x03, 0x04],
            },
            PeSection {
                name: ".data".to_owned(),
                rva: 0,
                bytes: vec![0xaa, 0xbb, 0xcc, 0xdd],
            },
        ];
        assert!(matches!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::Lossy {
                residual_bp: 5000,
                ..
            }
        ));
    }

    #[test]
    fn non_rva_section_matches_cannot_reuse_recovered_bytes() {
        let recovered: RecoveredImage = RecoveredImage {
            image: vec![0x01, 0x02, 0x03, 0x04],
            rva_indexed: false,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![
            PeSection {
                name: ".text".to_owned(),
                rva: 0,
                bytes: vec![0x01, 0x02, 0x03, 0x04],
            },
            PeSection {
                name: ".text2".to_owned(),
                rva: 0,
                bytes: vec![0x01, 0x02, 0x03, 0x04],
            },
        ];
        assert!(matches!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::Lossy {
                residual_bp: 5000,
                ..
            }
        ));
    }

    #[test]
    fn non_rva_assignment_avoids_greedy_false_loss() {
        let recovered: RecoveredImage = RecoveredImage {
            image: vec![1, 2, 3, 1, 2],
            rva_indexed: false,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![
            PeSection {
                name: ".first".to_owned(),
                rva: 0,
                bytes: vec![1, 2],
            },
            PeSection {
                name: ".second".to_owned(),
                rva: 0,
                bytes: vec![2, 3],
            },
        ];
        assert_eq!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::ByteIdentical
        );
    }

    #[test]
    fn non_rva_assignment_backtracks_to_complete_placement() {
        let section_a: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut image: Vec<u8> = vec![0u8; 30];
        image[0] = 10;
        image[1..11].copy_from_slice(&section_a);
        image[11] = 1;
        image[20..30].copy_from_slice(&section_a);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: false,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![
            PeSection {
                name: ".wide".to_owned(),
                rva: 0,
                bytes: section_a,
            },
            PeSection {
                name: ".pair".to_owned(),
                rva: 0,
                bytes: vec![10, 1],
            },
        ];
        assert_eq!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::ByteIdentical
        );
    }

    #[test]
    fn non_rva_assignment_considers_later_repeated_probe() {
        let mut section_bytes: Vec<u8> = vec![1u8; 65];
        section_bytes[64] = 2;
        let mut image: Vec<u8> = vec![1u8; 131];
        image[64] = 9;
        image[65] = 0;
        image[66..131].copy_from_slice(&section_bytes);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: false,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![PeSection {
            name: ".text".to_owned(),
            rva: 0,
            bytes: section_bytes,
        }];
        assert_eq!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::ByteIdentical
        );
    }

    #[test]
    fn non_rva_residual_is_section_order_independent() {
        let recovered: RecoveredImage = RecoveredImage {
            image: vec![1, 2, 3, 4],
            rva_indexed: false,
            internal_checksum_verified: false,
        };
        let short: PeSection = PeSection {
            name: ".short".to_owned(),
            rva: 0,
            bytes: vec![2, 3],
        };
        let long: PeSection = PeSection {
            name: ".long".to_owned(),
            rva: 0,
            bytes: vec![1, 2, 3, 4],
        };
        let short_first: OracleVerdict = verdict_for_section_witness(&recovered, &[short, long]);
        let long_first: OracleVerdict = verdict_for_section_witness(
            &recovered,
            &[
                PeSection {
                    name: ".long".to_owned(),
                    rva: 0,
                    bytes: vec![1, 2, 3, 4],
                },
                PeSection {
                    name: ".short".to_owned(),
                    rva: 0,
                    bytes: vec![2, 3],
                },
            ],
        );
        assert!(matches!(
            short_first,
            OracleVerdict::Lossy {
                residual_bp: 3334,
                ..
            }
        ));
        assert!(matches!(
            long_first,
            OracleVerdict::Lossy {
                residual_bp: 3334,
                ..
            }
        ));
    }

    #[test]
    fn non_rva_scan_budget_fails_closed() {
        let recovered: RecoveredImage = RecoveredImage {
            image: vec![0u8; 1_000_001],
            rva_indexed: false,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![PeSection {
            name: ".text".to_owned(),
            rva: 0,
            bytes: vec![1],
        }];
        assert_eq!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::NoRecovery {
                note: "non-RVA section assignment exceeded its scan budget".to_owned(),
            }
        );
    }

    #[test]
    fn non_rva_candidate_comparison_budget_fails_closed() {
        let section: PeSection = PeSection {
            name: ".text".to_owned(),
            rva: 0,
            bytes: vec![1, 2, 3, 4],
        };
        let mut examined_windows: usize = 0;
        let mut compared_bytes: usize = MAX_NON_RVA_CANDIDATE_BYTES;
        let result: Result<Vec<super::NonRvaCandidate>, &'static str> =
            enumerate_non_rva_candidates(
                &[1, 2, 3, 4],
                &section,
                &mut examined_windows,
                &mut compared_bytes,
            );
        assert!(matches!(
            result,
            Err("non-RVA section assignment exceeded its comparison budget")
        ));
    }

    #[test]
    fn nonzero_residual_rounds_up_to_one_basis_point() {
        let mut recovered_bytes: Vec<u8> = vec![0u8; 20_001];
        let baseline: Vec<u8> = vec![0u8; 20_001];
        recovered_bytes[20_000] = 1;
        assert!(matches!(
            verdict_for_byte_recovery(&recovered_bytes, &baseline),
            OracleVerdict::Lossy { residual_bp: 1, .. }
        ));
        let recovered: RecoveredImage = RecoveredImage {
            image: recovered_bytes,
            rva_indexed: true,
            internal_checksum_verified: false,
        };
        let sections: Vec<PeSection> = vec![PeSection {
            name: ".text".to_owned(),
            rva: 0x1000,
            bytes: baseline,
        }];
        assert!(matches!(
            verdict_for_section_witness(&recovered, &sections),
            OracleVerdict::Lossy { residual_bp: 1, .. }
        ));
    }

    #[test]
    fn loader_affected_residual_stays_lossy_with_internal_checksum() {
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
        let checksum_verified: OracleVerdict = verdict_for_section_witness(
            &RecoveredImage {
                image: image.clone(),
                rva_indexed: true,
                internal_checksum_verified: true,
            },
            &sections,
        );
        assert!(
            matches!(checksum_verified, OracleVerdict::Lossy { .. }),
            "an internal unpacker checksum must not excuse loader-affected bytes that differ from the original: {checksum_verified:?}",
        );
        let checksum_unverified: OracleVerdict = verdict_for_section_witness(
            &RecoveredImage {
                image,
                rva_indexed: true,
                internal_checksum_verified: false,
            },
            &sections,
        );
        assert!(
            matches!(checksum_unverified, OracleVerdict::Lossy { .. }),
            "without an internal unpacker checksum a differing loader-affected zone must stay lossy: {checksum_unverified:?}",
        );
    }

    #[test]
    fn absent_section_is_not_witnessed_at_fabricated_offset() {
        let mut image: Vec<u8> = vec![0u8; 0x2000];
        image[0x1000..0x1004].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let recovered: RecoveredImage = RecoveredImage {
            image,
            rva_indexed: false,
            internal_checksum_verified: false,
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
}
