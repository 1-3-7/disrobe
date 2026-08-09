use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

const CONTRACT_SCHEMA: u32 = 3;
const REPORT_GENERATOR: &str = "cargo run --manifest-path fuzz/Cargo.toml --bin seed_replay";
const MAX_CONTRACT_BYTES: u64 = 256 * 1024;
const MAX_ISOLATED_CAPTURE_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum SeedReachError {
    Io {
        action: String,
        source: std::io::Error,
    },
    Parse(toml::de::Error),
    Invalid(String),
    Exercise(String),
}

impl fmt::Display for SeedReachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { action, source } => write!(formatter, "{action}: {source}"),
            Self::Parse(source) => write!(formatter, "parsing the seed-reach contract: {source}"),
            Self::Invalid(message) | Self::Exercise(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for SeedReachError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::Invalid(_) | Self::Exercise(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum IsolatedReplayError {
    Spawn {
        program: PathBuf,
        source: std::io::Error,
    },
    Timeout {
        timeout: Duration,
    },
    Failed {
        exit_code: Option<i32>,
        stderr: String,
    },
}

impl fmt::Display for IsolatedReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { program, source } => {
                write!(
                    formatter,
                    "starting replay worker {}: {source}",
                    program.display()
                )
            }
            Self::Timeout { timeout } => {
                write!(formatter, "replay worker exceeded its {timeout:?} timeout")
            }
            Self::Failed { exit_code, stderr } => write!(
                formatter,
                "replay worker failed with exit code {exit_code:?}: {stderr}"
            ),
        }
    }
}

impl std::error::Error for IsolatedReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn { source, .. } => Some(source),
            Self::Timeout { .. } | Self::Failed { .. } => None,
        }
    }
}

pub fn run_isolated_replay<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    timeout: Duration,
) -> Result<Vec<u8>, IsolatedReplayError> {
    let captured: Option<disrobe_core::subprocess::CapturedOutput> =
        disrobe_core::subprocess::run_captured(program, args, timeout, MAX_ISOLATED_CAPTURE_BYTES)
            .map_err(|source: std::io::Error| IsolatedReplayError::Spawn {
                program: program.to_path_buf(),
                source,
            })?;
    let Some(output): Option<disrobe_core::subprocess::CapturedOutput> = captured else {
        return Err(IsolatedReplayError::Timeout { timeout });
    };
    if output.exit_code == Some(0) {
        return Ok(output.stdout);
    }
    Err(IsolatedReplayError::Failed {
        exit_code: output.exit_code,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[derive(Debug, Deserialize)]
struct RawContract {
    schema: u32,
    surface: Vec<SurfaceSpec>,
    seed: Vec<SeedSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReplayTarget {
    #[serde(rename = "python_bytecode")]
    PythonBytecode,
    #[serde(rename = "dex_jvm_classfile")]
    DexJvmClassfile,
}

impl fmt::Display for ReplayTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PythonBytecode => "python_bytecode",
            Self::DexJvmClassfile => "dex_jvm_classfile",
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SurfaceSpec {
    target: ReplayTarget,
    id: String,
    entry_point: ParserEntryPoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ParserEntryPoint {
    Python(disrobe_py_marshal::SemanticEntryPoint),
    Jvm(disrobe_pass_jvm::SemanticEntryPoint),
}

impl ParserEntryPoint {
    const fn belongs_to(self, target: ReplayTarget) -> bool {
        matches!(
            (self, target),
            (Self::Python(_), ReplayTarget::PythonBytecode)
                | (Self::Jvm(_), ReplayTarget::DexJvmClassfile)
        )
    }
}

impl Serialize for ParserEntryPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Python(entry_point) => entry_point.serialize(serializer),
            Self::Jvm(entry_point) => entry_point.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ParserEntryPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: String = String::deserialize(deserializer)?;
        let python: Result<disrobe_py_marshal::SemanticEntryPoint, serde::de::value::Error> =
            disrobe_py_marshal::SemanticEntryPoint::deserialize(value.as_str().into_deserializer());
        let jvm: Result<disrobe_pass_jvm::SemanticEntryPoint, serde::de::value::Error> =
            disrobe_pass_jvm::SemanticEntryPoint::deserialize(value.as_str().into_deserializer());
        match (python, jvm) {
            (Ok(entry_point), Err(_)) => Ok(Self::Python(entry_point)),
            (Err(_), Ok(entry_point)) => Ok(Self::Jvm(entry_point)),
            (Ok(_), Ok(_)) => Err(serde::de::Error::custom(format!(
                "semantic entry point {value} is ambiguous"
            ))),
            (Err(_), Err(_)) => Err(serde::de::Error::custom(format!(
                "unknown semantic entry point {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SeedSpec {
    target: ReplayTarget,
    source: String,
    offset: usize,
    length: usize,
    sha256: String,
    #[serde(default)]
    obligation: Vec<Obligation>,
}

#[derive(Debug, Clone, Deserialize)]
struct Obligation {
    surface: String,
    outcome: RequiredOutcome,
    minimum_bytes: usize,
    minimum_items: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RequiredOutcome {
    Accepted,
    Rejected,
}

#[derive(Debug)]
pub struct SeedContract {
    sha256: String,
    surfaces: Vec<SurfaceSpec>,
    seeds: Vec<SeedSpec>,
}

impl SeedContract {
    pub fn read(path: &Path) -> Result<Self, SeedReachError> {
        let metadata: fs::Metadata =
            fs::metadata(path).map_err(|source: std::io::Error| SeedReachError::Io {
                action: format!("reading metadata for {}", path.display()),
                source,
            })?;
        if metadata.len() > MAX_CONTRACT_BYTES {
            return Err(SeedReachError::Invalid(format!(
                "{} exceeds the {MAX_CONTRACT_BYTES}-byte seed contract limit",
                path.display()
            )));
        }
        let raw: String =
            fs::read_to_string(path).map_err(|source: std::io::Error| SeedReachError::Io {
                action: format!("reading {}", path.display()),
                source,
            })?;
        let parsed: RawContract = toml::from_str(&raw).map_err(SeedReachError::Parse)?;
        let contract: Self = Self {
            sha256: format!("{:x}", Sha256::digest(raw.as_bytes())),
            surfaces: parsed.surface,
            seeds: parsed.seed,
        };
        contract.validate(parsed.schema)?;
        Ok(contract)
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub fn seed_count(&self) -> usize {
        self.seeds.len()
    }

    #[must_use]
    pub fn target_seed_count(&self, target: ReplayTarget) -> usize {
        self.seeds
            .iter()
            .filter(|seed: &&SeedSpec| seed.target == target)
            .count()
    }

    pub fn manifest_target(&self, manifest_index: usize) -> Result<ReplayTarget, SeedReachError> {
        self.seeds
            .get(manifest_index)
            .map(|seed: &SeedSpec| seed.target)
            .ok_or_else(|| {
                SeedReachError::Invalid(format!(
                    "the seed-reach contract has no manifest index {manifest_index}"
                ))
            })
    }

    #[must_use]
    pub fn targets_in_manifest_order(&self) -> Vec<ReplayTarget> {
        let mut seen: BTreeSet<ReplayTarget> = BTreeSet::new();
        self.seeds
            .iter()
            .filter_map(|seed: &SeedSpec| seen.insert(seed.target).then_some(seed.target))
            .collect()
    }

    fn validate(&self, schema: u32) -> Result<(), SeedReachError> {
        if schema != CONTRACT_SCHEMA {
            return Err(SeedReachError::Invalid(format!(
                "seed-reach contract schema {schema} is unsupported"
            )));
        }
        if self.surfaces.is_empty() {
            return Err(SeedReachError::Invalid(
                "the seed-reach contract declares no semantic surfaces".to_owned(),
            ));
        }
        if self.seeds.is_empty() {
            return Err(SeedReachError::Invalid(
                "the seed-reach contract declares no seeds".to_owned(),
            ));
        }
        let mut surface_keys: BTreeSet<(ReplayTarget, String)> = BTreeSet::new();
        for surface in &self.surfaces {
            if surface.id.is_empty() {
                return Err(SeedReachError::Invalid(
                    "the seed-reach contract has an incomplete surface declaration".to_owned(),
                ));
            }
            if !surface_keys.insert((surface.target, surface.id.clone())) {
                return Err(SeedReachError::Invalid(format!(
                    "the seed-reach contract repeats surface {} for target {}",
                    surface.id, surface.target
                )));
            }
            if !surface.entry_point.belongs_to(surface.target) {
                return Err(SeedReachError::Invalid(format!(
                    "semantic entry point for surface {} does not belong to target {}",
                    surface.id, surface.target
                )));
            }
        }

        let mut seed_keys: BTreeSet<(ReplayTarget, String)> = BTreeSet::new();
        for seed in &self.seeds {
            validate_seed(seed, &surface_keys)?;
            if !seed_keys.insert((seed.target, seed.sha256.clone())) {
                return Err(SeedReachError::Invalid(format!(
                    "the seed-reach contract repeats seed {} for target {}",
                    seed.sha256, seed.target
                )));
            }
        }
        Ok(())
    }
}

fn validate_seed(
    seed: &SeedSpec,
    surface_keys: &BTreeSet<(ReplayTarget, String)>,
) -> Result<(), SeedReachError> {
    if seed.source.is_empty() {
        return Err(SeedReachError::Invalid(
            "the seed-reach contract has an incomplete seed declaration".to_owned(),
        ));
    }
    let source_path: &Path = Path::new(&seed.source);
    if source_path.is_absolute()
        || source_path
            .components()
            .any(|component: Component<'_>| !matches!(component, Component::Normal(_)))
    {
        return Err(SeedReachError::Invalid(format!(
            "seed {} has a non-relative source path",
            seed.sha256
        )));
    }
    if seed.length == 0 || seed.length > crate::MAX_INPUT_BYTES {
        return Err(SeedReachError::Invalid(format!(
            "seed {} has invalid length {}",
            seed.sha256, seed.length
        )));
    }
    if seed.offset.checked_add(seed.length).is_none() {
        return Err(SeedReachError::Invalid(format!(
            "seed {} offset plus length overflows usize",
            seed.sha256
        )));
    }
    if seed.sha256.len() != 64
        || !seed
            .sha256
            .bytes()
            .all(|byte: u8| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SeedReachError::Invalid(format!(
            "seed {} has an invalid SHA-256 digest",
            seed.sha256
        )));
    }
    if seed.obligation.is_empty() {
        return Err(SeedReachError::Invalid(format!(
            "seed {} declares zero obligations",
            seed.sha256
        )));
    }
    let mut obligations: BTreeSet<(String, RequiredOutcome)> = BTreeSet::new();
    for obligation in &seed.obligation {
        if !surface_keys.contains(&(seed.target, obligation.surface.clone())) {
            return Err(SeedReachError::Invalid(format!(
                "seed {} names unknown surface {} for target {}",
                seed.sha256, obligation.surface, seed.target
            )));
        }
        if !obligations.insert((obligation.surface.clone(), obligation.outcome)) {
            return Err(SeedReachError::Invalid(format!(
                "seed {} repeats its {} obligation",
                seed.sha256, obligation.surface
            )));
        }
        match obligation.outcome {
            RequiredOutcome::Accepted => {
                if obligation.minimum_bytes == 0 || obligation.minimum_items == 0 {
                    return Err(SeedReachError::Invalid(format!(
                        "seed {} has a vacuous accepted obligation for {}",
                        seed.sha256, obligation.surface
                    )));
                }
            }
            RequiredOutcome::Rejected => {
                if obligation.minimum_bytes != 0 || obligation.minimum_items != 0 {
                    return Err(SeedReachError::Invalid(format!(
                        "seed {} gives an expected rejection positive evidence thresholds",
                        seed.sha256
                    )));
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObservedPhase {
    Entered,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy)]
pub enum ReplayObservations<'a> {
    Python(&'a [disrobe_py_marshal::Observation]),
    Jvm(&'a [disrobe_pass_jvm::Observation]),
}

pub trait ReplayTrace {
    fn observations(&self) -> ReplayObservations<'_>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TraceEvent {
    span: u64,
    surface: String,
    entry_point: ParserEntryPoint,
    phase: ObservedPhase,
    bytes_consumed: usize,
    items: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeedReplay {
    sha256: String,
    trace: Vec<TraceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Witness {
    seed: String,
    entry_point: ParserEntryPoint,
    surface: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetReplay {
    name: ReplayTarget,
    satisfied_obligations: usize,
    declared_obligations: usize,
    positive_witnesses: Vec<Witness>,
    expected_rejection_witnesses: Vec<Witness>,
    seeds: Vec<SeedReplay>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObligationTotals {
    satisfied: usize,
    declared: usize,
    positive_witnesses: usize,
    expected_rejection_witnesses: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeedReachReport {
    schema: u32,
    generator: &'static str,
    contract_sha256: String,
    obligations: ObligationTotals,
    targets: Vec<TargetReplay>,
}

impl SeedReachReport {
    pub fn new(
        contract: &SeedContract,
        targets: Vec<TargetReplay>,
    ) -> Result<Self, SeedReachError> {
        if targets.is_empty() {
            return Err(SeedReachError::Invalid(
                "a seed-reach report requires at least one target".to_owned(),
            ));
        }
        let expected_targets: Vec<ReplayTarget> = contract.targets_in_manifest_order();
        let actual_targets: Vec<ReplayTarget> = targets
            .iter()
            .map(|target: &TargetReplay| target.name)
            .collect();
        if actual_targets != expected_targets {
            return Err(SeedReachError::Invalid(
                "seed-reach target reports do not match contract manifest order".to_owned(),
            ));
        }
        let mut names: BTreeSet<ReplayTarget> = BTreeSet::new();
        let mut satisfied: usize = 0;
        let mut declared: usize = 0;
        let mut positive_witnesses: usize = 0;
        let mut expected_rejection_witnesses: usize = 0;
        for target in &targets {
            if !names.insert(target.name) {
                return Err(SeedReachError::Invalid(format!(
                    "a seed-reach report repeats target {}",
                    target.name
                )));
            }
            satisfied = satisfied.saturating_add(target.satisfied_obligations);
            declared = declared.saturating_add(target.declared_obligations);
            positive_witnesses = positive_witnesses.saturating_add(target.positive_witnesses.len());
            expected_rejection_witnesses = expected_rejection_witnesses
                .saturating_add(target.expected_rejection_witnesses.len());
        }
        if declared == 0 || satisfied != declared {
            return Err(SeedReachError::Invalid(format!(
                "a seed-reach report satisfied {satisfied} of {declared} obligations"
            )));
        }
        Ok(Self {
            schema: CONTRACT_SCHEMA,
            generator: REPORT_GENERATOR,
            contract_sha256: contract.sha256.clone(),
            obligations: ObligationTotals {
                satisfied,
                declared,
                positive_witnesses,
                expected_rejection_witnesses,
            },
            targets,
        })
    }

    #[must_use]
    pub const fn satisfied_obligations(&self) -> usize {
        self.obligations.satisfied
    }

    #[must_use]
    pub const fn declared_obligations(&self) -> usize {
        self.obligations.declared
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(|mut rendered: String| {
            rendered.push('\n');
            rendered
        })
    }
}

impl TargetReplay {
    #[must_use]
    pub fn seed_count(&self) -> usize {
        self.seeds.len()
    }

    #[must_use]
    pub const fn satisfied_obligations(&self) -> usize {
        self.satisfied_obligations
    }

    #[must_use]
    pub const fn declared_obligations(&self) -> usize {
        self.declared_obligations
    }

    #[must_use]
    pub fn positive_witnesses(&self) -> usize {
        self.positive_witnesses.len()
    }

    #[must_use]
    pub fn expected_rejection_witnesses(&self) -> usize {
        self.expected_rejection_witnesses.len()
    }

    #[must_use]
    pub fn canonical_trace_runs(&self) -> usize {
        self.seeds.len()
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayOptions {
    pub jobs: usize,
    pub order_seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedReplayFragment {
    target: ReplayTarget,
    manifest_index: usize,
    replay: SeedReplay,
    positive_witnesses: Vec<Witness>,
    expected_rejection_witnesses: Vec<Witness>,
    declared_obligations: usize,
}

type SeedWorkResult = Result<SeedReplayFragment, SeedReachError>;
type SeedWorkSender = std::sync::mpsc::Sender<SeedWorkResult>;
type SeedWorkReceiver = std::sync::mpsc::Receiver<SeedWorkResult>;

impl SeedReplayFragment {
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    #[must_use]
    pub const fn manifest_index(&self) -> usize {
        self.manifest_index
    }
}

pub fn replay_target<R, E>(
    root: &Path,
    contract: &SeedContract,
    target: ReplayTarget,
    exercise: impl Fn(&[u8]) -> Result<R, E> + Sync,
) -> Result<TargetReplay, SeedReachError>
where
    R: ReplayTrace,
    E: fmt::Display,
{
    replay_target_with_options(
        root,
        contract,
        target,
        exercise,
        ReplayOptions {
            jobs: 1,
            order_seed: 0,
        },
    )
}

pub fn replay_target_with_options<R, E, F>(
    root: &Path,
    contract: &SeedContract,
    target: ReplayTarget,
    exercise: F,
    options: ReplayOptions,
) -> Result<TargetReplay, SeedReachError>
where
    R: ReplayTrace,
    E: fmt::Display,
    F: Fn(&[u8]) -> Result<R, E> + Sync,
{
    if options.jobs == 0 {
        return Err(SeedReachError::Invalid(
            "seed replay requires at least one worker".to_owned(),
        ));
    }
    let surfaces: BTreeMap<&str, &SurfaceSpec> = contract
        .surfaces
        .iter()
        .filter(|surface: &&SurfaceSpec| surface.target == target)
        .map(|surface: &SurfaceSpec| (surface.id.as_str(), surface))
        .collect();
    let mut scheduled: Vec<(usize, &SeedSpec)> = contract
        .seeds
        .iter()
        .enumerate()
        .filter(|(_, seed): &(usize, &SeedSpec)| seed.target == target)
        .collect();
    if surfaces.is_empty() || scheduled.is_empty() {
        return Err(SeedReachError::Invalid(format!(
            "the seed-reach contract has no complete target named {target}"
        )));
    }

    shuffle_schedule(&mut scheduled, options.order_seed);
    let workers: usize = options.jobs.min(scheduled.len());
    let mut completed: Vec<SeedReplayFragment> = Vec::with_capacity(scheduled.len());
    if workers == 1 {
        for (manifest_index, seed) in scheduled {
            completed.push(replay_one_seed(
                root,
                target,
                &surfaces,
                manifest_index,
                seed,
                &exercise,
            )?);
        }
    } else {
        let (sender, receiver): (SeedWorkSender, SeedWorkReceiver) = std::sync::mpsc::channel();
        std::thread::scope(|scope: &std::thread::Scope<'_, '_>| {
            for worker_index in 0..workers {
                let worker_sender: SeedWorkSender = sender.clone();
                let worker_schedule: Vec<(usize, &SeedSpec)> = scheduled
                    .iter()
                    .copied()
                    .skip(worker_index)
                    .step_by(workers)
                    .collect();
                let exercise_ref: &F = &exercise;
                let surfaces_ref: &BTreeMap<&str, &SurfaceSpec> = &surfaces;
                scope.spawn(move || {
                    for (manifest_index, seed) in worker_schedule {
                        let result: Result<SeedReplayFragment, SeedReachError> = replay_one_seed(
                            root,
                            target,
                            surfaces_ref,
                            manifest_index,
                            seed,
                            exercise_ref,
                        );
                        if worker_sender.send(result).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        drop(sender);
        for result in receiver {
            completed.push(result?);
        }
    }
    assemble_target_replay(contract, target, completed)
}

pub fn replay_target_seed<R, E, F>(
    root: &Path,
    contract: &SeedContract,
    target: ReplayTarget,
    manifest_index: usize,
    exercise: F,
) -> Result<SeedReplayFragment, SeedReachError>
where
    R: ReplayTrace,
    E: fmt::Display,
    F: Fn(&[u8]) -> Result<R, E>,
{
    let surfaces: BTreeMap<&str, &SurfaceSpec> = contract
        .surfaces
        .iter()
        .filter(|surface: &&SurfaceSpec| surface.target == target)
        .map(|surface: &SurfaceSpec| (surface.id.as_str(), surface))
        .collect();
    let Some(seed): Option<&SeedSpec> = contract.seeds.get(manifest_index) else {
        return Err(SeedReachError::Invalid(format!(
            "target {target} has no manifest index {manifest_index}"
        )));
    };
    if seed.target != target {
        return Err(SeedReachError::Invalid(format!(
            "manifest index {manifest_index} belongs to target {} instead of {target}",
            seed.target
        )));
    }
    replay_one_seed(root, target, &surfaces, manifest_index, seed, &exercise)
}

pub fn assemble_target_replay(
    contract: &SeedContract,
    target: ReplayTarget,
    mut completed: Vec<SeedReplayFragment>,
) -> Result<TargetReplay, SeedReachError> {
    let surfaces: BTreeMap<&str, &SurfaceSpec> = contract
        .surfaces
        .iter()
        .filter(|surface: &&SurfaceSpec| surface.target == target)
        .map(|surface: &SurfaceSpec| (surface.id.as_str(), surface))
        .collect();
    let seeds: Vec<(usize, &SeedSpec)> = contract
        .seeds
        .iter()
        .enumerate()
        .filter(|(_, seed): &(usize, &SeedSpec)| seed.target == target)
        .collect();
    if completed.len() != seeds.len() {
        return Err(SeedReachError::Invalid(format!(
            "target {target} returned {} of {} manifest indices",
            completed.len(),
            seeds.len()
        )));
    }
    completed.sort_by_key(|work: &SeedReplayFragment| work.manifest_index);
    let mut seen_indices: BTreeSet<usize> = BTreeSet::new();
    let mut replayed_seeds: Vec<SeedReplay> = Vec::with_capacity(seeds.len());
    let mut positive_witnesses: Vec<Witness> = Vec::new();
    let mut expected_rejection_witnesses: Vec<Witness> = Vec::new();
    let mut declared_obligations: usize = 0;
    for ((expected_index, seed), work) in seeds.iter().copied().zip(completed) {
        if work.target != target
            || work.manifest_index != expected_index
            || !seen_indices.insert(work.manifest_index)
        {
            return Err(SeedReachError::Invalid(format!(
                "target {target} returned a duplicate, missing, or foreign manifest index"
            )));
        }
        if work.replay.sha256 != seed.sha256 {
            return Err(SeedReachError::Invalid(format!(
                "target {target} manifest index {expected_index} returned seed {} instead of {}",
                work.replay.sha256, seed.sha256
            )));
        }
        validate_complete_trace(target, &seed.sha256, &work.replay.trace)?;
        let (expected_positive, expected_rejection): (Vec<Witness>, Vec<Witness>) =
            witnesses_for_seed(seed, &surfaces, &work.replay.trace)?;
        if work.positive_witnesses != expected_positive
            || work.expected_rejection_witnesses != expected_rejection
            || work.declared_obligations != seed.obligation.len()
        {
            return Err(SeedReachError::Invalid(format!(
                "target {target} manifest index {expected_index} returned inconsistent witnesses"
            )));
        }
        declared_obligations = declared_obligations.saturating_add(work.declared_obligations);
        positive_witnesses.extend(work.positive_witnesses);
        expected_rejection_witnesses.extend(work.expected_rejection_witnesses);
        replayed_seeds.push(work.replay);
    }
    let satisfied_obligations: usize = positive_witnesses
        .len()
        .saturating_add(expected_rejection_witnesses.len());
    if satisfied_obligations == 0 || satisfied_obligations != declared_obligations {
        return Err(SeedReachError::Invalid(format!(
            "target {target} satisfied {satisfied_obligations} of {declared_obligations} obligations"
        )));
    }
    Ok(TargetReplay {
        name: target,
        satisfied_obligations,
        declared_obligations,
        positive_witnesses,
        expected_rejection_witnesses,
        seeds: replayed_seeds,
    })
}

pub fn assemble_contract_replay(
    contract: &SeedContract,
    mut completed: Vec<SeedReplayFragment>,
) -> Result<Vec<TargetReplay>, SeedReachError> {
    if completed.len() != contract.seed_count() {
        return Err(SeedReachError::Invalid(format!(
            "seed replay returned {} of {} manifest indices",
            completed.len(),
            contract.seed_count()
        )));
    }
    completed.sort_by_key(|fragment: &SeedReplayFragment| fragment.manifest_index);
    let mut grouped: BTreeMap<ReplayTarget, Vec<SeedReplayFragment>> = BTreeMap::new();
    for (expected_index, fragment) in completed.into_iter().enumerate() {
        let expected_target: ReplayTarget = contract.manifest_target(expected_index)?;
        if fragment.manifest_index != expected_index || fragment.target != expected_target {
            return Err(SeedReachError::Invalid(
                "seed replay returned a duplicate, missing, or foreign manifest index".to_owned(),
            ));
        }
        grouped.entry(fragment.target).or_default().push(fragment);
    }
    let mut targets: Vec<TargetReplay> = Vec::with_capacity(grouped.len());
    for target in contract.targets_in_manifest_order() {
        let fragments: Vec<SeedReplayFragment> = grouped.remove(&target).ok_or_else(|| {
            SeedReachError::Invalid(format!("seed replay omitted target {target}"))
        })?;
        targets.push(assemble_target_replay(contract, target, fragments)?);
    }
    if !grouped.is_empty() {
        return Err(SeedReachError::Invalid(
            "seed replay returned a foreign target".to_owned(),
        ));
    }
    Ok(targets)
}

fn replay_one_seed<R, E, F>(
    root: &Path,
    target: ReplayTarget,
    surfaces: &BTreeMap<&str, &SurfaceSpec>,
    manifest_index: usize,
    seed: &SeedSpec,
    exercise: &F,
) -> Result<SeedReplayFragment, SeedReachError>
where
    R: ReplayTrace,
    E: fmt::Display,
    F: Fn(&[u8]) -> Result<R, E>,
{
    let payload: Vec<u8> = materialize_seed(root, seed)?;
    let replay: R = exercise(&payload).map_err(|error: E| {
        SeedReachError::Exercise(format!(
            "target {target} failed while replaying seed {}: {error}",
            seed.sha256
        ))
    })?;
    let trace: Vec<TraceEvent> = snapshot_trace(replay.observations());
    validate_complete_trace(target, &seed.sha256, &trace)?;
    let (positive_witnesses, expected_rejection_witnesses): (Vec<Witness>, Vec<Witness>) =
        witnesses_for_seed(seed, surfaces, &trace)?;
    Ok(SeedReplayFragment {
        target,
        manifest_index,
        replay: SeedReplay {
            sha256: seed.sha256.clone(),
            trace,
        },
        positive_witnesses,
        expected_rejection_witnesses,
        declared_obligations: seed.obligation.len(),
    })
}

fn witnesses_for_seed(
    seed: &SeedSpec,
    surfaces: &BTreeMap<&str, &SurfaceSpec>,
    trace: &[TraceEvent],
) -> Result<(Vec<Witness>, Vec<Witness>), SeedReachError> {
    let mut positive_witnesses: Vec<Witness> = Vec::new();
    let mut expected_rejection_witnesses: Vec<Witness> = Vec::new();
    for obligation in &seed.obligation {
        let Some(surface): Option<&&SurfaceSpec> = surfaces.get(obligation.surface.as_str()) else {
            return Err(SeedReachError::Invalid(format!(
                "seed {} names unknown target surface {}",
                seed.sha256, obligation.surface
            )));
        };
        if !obligation_satisfied(obligation, surface, trace) {
            return Err(SeedReachError::Invalid(format!(
                "seed {} did not satisfy its {} {:?} obligation",
                seed.sha256, obligation.surface, obligation.outcome
            )));
        }
        let witness: Witness = Witness {
            seed: seed.sha256.clone(),
            entry_point: surface.entry_point,
            surface: obligation.surface.clone(),
        };
        match obligation.outcome {
            RequiredOutcome::Accepted => positive_witnesses.push(witness),
            RequiredOutcome::Rejected => expected_rejection_witnesses.push(witness),
        }
    }
    Ok((positive_witnesses, expected_rejection_witnesses))
}

fn shuffle_schedule(values: &mut [(usize, &SeedSpec)], seed: u64) {
    if seed == 0 {
        return;
    }
    let mut state: u64 = seed;
    for index in (1..values.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let modulus: u64 =
            u64::try_from(index.saturating_add(1)).map_or(u64::MAX, |value: u64| value);
        let selected_u64: u64 = state % modulus;
        let selected: usize = usize::try_from(selected_u64).map_or(0, |value: usize| value);
        values.swap(index, selected);
    }
}

fn materialize_seed(root: &Path, seed: &SeedSpec) -> Result<Vec<u8>, SeedReachError> {
    let path: PathBuf = root.join(&seed.source);
    let metadata: fs::Metadata =
        fs::metadata(&path).map_err(|source: std::io::Error| SeedReachError::Io {
            action: format!("reading metadata for {}", path.display()),
            source,
        })?;
    let end: usize = seed.offset.checked_add(seed.length).ok_or_else(|| {
        SeedReachError::Invalid(format!(
            "seed {} offset plus length overflows usize",
            seed.sha256
        ))
    })?;
    let file_len: usize = usize::try_from(metadata.len()).map_err(|_| {
        SeedReachError::Invalid(format!("{} is too large for this platform", path.display()))
    })?;
    if end > file_len {
        return Err(SeedReachError::Invalid(format!(
            "seed {} range ends past {}",
            seed.sha256,
            path.display()
        )));
    }
    let mut file: File =
        File::open(&path).map_err(|source: std::io::Error| SeedReachError::Io {
            action: format!("opening {}", path.display()),
            source,
        })?;
    let offset: u64 = u64::try_from(seed.offset).map_err(|_| {
        SeedReachError::Invalid(format!("seed {} offset is too large", seed.sha256))
    })?;
    let _: u64 = file
        .seek(SeekFrom::Start(offset))
        .map_err(|source: std::io::Error| SeedReachError::Io {
            action: format!("seeking {}", path.display()),
            source,
        })?;
    let mut payload: Vec<u8> = vec![0; seed.length];
    file.read_exact(&mut payload)
        .map_err(|source: std::io::Error| SeedReachError::Io {
            action: format!("reading seed bytes from {}", path.display()),
            source,
        })?;
    let actual: String = format!("{:x}", Sha256::digest(&payload));
    if actual != seed.sha256 {
        return Err(SeedReachError::Invalid(format!(
            "seed {} is stale; its source bytes hash to {actual}",
            seed.sha256
        )));
    }
    Ok(payload)
}

fn snapshot_trace(observations: ReplayObservations<'_>) -> Vec<TraceEvent> {
    match observations {
        ReplayObservations::Python(values) => values
            .iter()
            .map(|observation: &disrobe_py_marshal::Observation| TraceEvent {
                span: observation.span(),
                surface: python_surface_id(observation.surface()).to_owned(),
                entry_point: ParserEntryPoint::Python(observation.entry_point()),
                phase: python_phase(observation.phase()),
                bytes_consumed: observation.bytes_consumed(),
                items: observation.items(),
            })
            .collect(),
        ReplayObservations::Jvm(values) => values
            .iter()
            .map(|observation: &disrobe_pass_jvm::Observation| TraceEvent {
                span: observation.span(),
                surface: jvm_surface_id(observation.surface()).to_owned(),
                entry_point: ParserEntryPoint::Jvm(observation.entry_point()),
                phase: jvm_phase(observation.phase()),
                bytes_consumed: observation.bytes_consumed(),
                items: observation.items(),
            })
            .collect(),
    }
}

const fn python_surface_id(surface: disrobe_py_marshal::SemanticSurface) -> &'static str {
    match surface {
        disrobe_py_marshal::SemanticSurface::PycHeader => "python.pyc.header",
        disrobe_py_marshal::SemanticSurface::MarshalRoot => "python.marshal.root",
        disrobe_py_marshal::SemanticSurface::ReferenceTable => "python.reference-table",
    }
}

const fn jvm_surface_id(surface: disrobe_pass_jvm::SemanticSurface) -> &'static str {
    match surface {
        disrobe_pass_jvm::SemanticSurface::ClassFile => "jvm.class-file",
        disrobe_pass_jvm::SemanticSurface::CodeAttribute => "jvm.code-attribute",
        disrobe_pass_jvm::SemanticSurface::Bytecode => "jvm.bytecode",
        disrobe_pass_jvm::SemanticSurface::DexHeader => "android.dex.header",
        disrobe_pass_jvm::SemanticSurface::DexFile => "android.dex.file",
        disrobe_pass_jvm::SemanticSurface::DexCodeItems => "android.dex.code-items",
    }
}

const fn python_phase(phase: disrobe_py_marshal::ObservationPhase) -> ObservedPhase {
    match phase {
        disrobe_py_marshal::ObservationPhase::Entered => ObservedPhase::Entered,
        disrobe_py_marshal::ObservationPhase::Accepted => ObservedPhase::Accepted,
        disrobe_py_marshal::ObservationPhase::Rejected => ObservedPhase::Rejected,
    }
}

const fn jvm_phase(phase: disrobe_pass_jvm::ObservationPhase) -> ObservedPhase {
    match phase {
        disrobe_pass_jvm::ObservationPhase::Entered => ObservedPhase::Entered,
        disrobe_pass_jvm::ObservationPhase::Accepted => ObservedPhase::Accepted,
        disrobe_pass_jvm::ObservationPhase::Rejected => ObservedPhase::Rejected,
    }
}

fn validate_complete_trace(
    target: ReplayTarget,
    seed: &str,
    trace: &[TraceEvent],
) -> Result<(), SeedReachError> {
    let mut spans: BTreeMap<u64, (&str, ParserEntryPoint, bool)> = BTreeMap::new();
    for observation in trace {
        match observation.phase {
            ObservedPhase::Entered => {
                if observation.bytes_consumed != 0 || observation.items != 0 {
                    return Err(SeedReachError::Invalid(format!(
                        "target {target} seed {seed} puts evidence on an entered observation"
                    )));
                }
                if spans
                    .insert(
                        observation.span,
                        (observation.surface.as_str(), observation.entry_point, false),
                    )
                    .is_some()
                {
                    return Err(SeedReachError::Invalid(format!(
                        "target {target} seed {seed} repeats span {}",
                        observation.span
                    )));
                }
            }
            ObservedPhase::Accepted | ObservedPhase::Rejected => {
                let Some((surface, entry_point, complete)): Option<&mut (
                    &str,
                    ParserEntryPoint,
                    bool,
                )> = spans.get_mut(&observation.span) else {
                    return Err(SeedReachError::Invalid(format!(
                        "target {target} seed {seed} terminates unknown span {}",
                        observation.span
                    )));
                };
                if *surface != observation.surface
                    || *entry_point != observation.entry_point
                    || *complete
                {
                    return Err(SeedReachError::Invalid(format!(
                        "target {target} seed {seed} has an invalid terminal for span {}",
                        observation.span
                    )));
                }
                *complete = true;
                if observation.phase == ObservedPhase::Accepted
                    && (observation.bytes_consumed == 0 || observation.items == 0)
                {
                    return Err(SeedReachError::Invalid(format!(
                        "target {target} seed {seed} has a vacuous accepted observation"
                    )));
                }
                if observation.phase == ObservedPhase::Rejected
                    && (observation.bytes_consumed != 0 || observation.items != 0)
                {
                    return Err(SeedReachError::Invalid(format!(
                        "target {target} seed {seed} puts evidence on a rejected observation"
                    )));
                }
            }
        }
    }
    if spans.is_empty()
        || spans
            .values()
            .any(|(_, _, complete): &(&str, ParserEntryPoint, bool)| !complete)
    {
        return Err(SeedReachError::Invalid(format!(
            "target {target} seed {seed} has an empty or incomplete trace"
        )));
    }
    Ok(())
}

fn obligation_satisfied(
    obligation: &Obligation,
    surface: &SurfaceSpec,
    trace: &[TraceEvent],
) -> bool {
    let required_phase: ObservedPhase = match obligation.outcome {
        RequiredOutcome::Accepted => ObservedPhase::Accepted,
        RequiredOutcome::Rejected => ObservedPhase::Rejected,
    };
    trace.iter().any(|observation: &TraceEvent| {
        observation.surface == obligation.surface
            && observation.entry_point == surface.entry_point
            && observation.phase == required_phase
            && observation.bytes_consumed >= obligation.minimum_bytes
            && observation.items >= obligation.minimum_items
    })
}
