#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeMap;
use std::time::Duration;

use disrobe_core::chain::detection::{DetectContext, DetectVerdict, OutputKind, PassRunOutcome};
use disrobe_core::chain::detector::{Detector, Pass};
use disrobe_core::chain::registry::DetectorPick;
use disrobe_core::chain::state_machine::{ChainDriver, ChainPlan, PassRunner, Verdict};
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainSpec, FAMILY_INTERPRETER_BYTECODE, FAMILY_OBFUSCATOR_WRAPPER,
    PassRegistry,
};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;
use disrobe_core::{Artifact, Rung};
use serde_json::Value;

const PASS_PEEL: PassId = "test.peel";
const PASS_DECOMPILE: PassId = "test.decompile";
const FORMAT_WRAPPER: &str = "test-wrapper";
const FORMAT_BYTECODE: &str = "test-bytecode";

const WRAP_PREFIX: &[u8] = b"WRAP:";
const BC_PREFIX: &[u8] = b"BC:";

#[derive(Debug)]
struct PeelDetector;
impl Detector for PeelDetector {
    fn id(&self) -> PassId {
        PASS_PEEL
    }
    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        ctx.bytes.starts_with(WRAP_PREFIX).then(|| {
            DetectVerdict::new(
                PASS_PEEL,
                FORMAT_WRAPPER,
                FAMILY_OBFUSCATOR_WRAPPER,
                0.98,
                10,
                vec!["wrap-marker"],
                "test wrapper".to_string(),
            )
        })
    }
}

#[derive(Debug)]
struct PeelPass;
impl Pass for PeelPass {
    fn id(&self) -> PassId {
        PASS_PEEL
    }
    fn detector(&self) -> &'static dyn Detector {
        &PeelDetector
    }
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Bytes {
            format_tag: FORMAT_BYTECODE,
            family: FAMILY_INTERPRETER_BYTECODE,
        }
    }
    fn run(&self, artifact: &Artifact) -> disrobe_core::error::Result<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let payload: Vec<u8> = bytes.strip_prefix(WRAP_PREFIX).map_or_else(
            || bytes.to_vec(),
            |rest: &[u8]| {
                let mut out: Vec<u8> = Vec::with_capacity(BC_PREFIX.len() + rest.len());
                out.extend_from_slice(BC_PREFIX);
                out.extend_from_slice(rest);
                out
            },
        );
        Ok(Artifact::new(Rung::Disasm, payload, artifact.root_hash))
    }
}

#[derive(Debug)]
struct DecompileDetector;
impl Detector for DecompileDetector {
    fn id(&self) -> PassId {
        PASS_DECOMPILE
    }
    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        ctx.bytes.starts_with(BC_PREFIX).then(|| {
            DetectVerdict::new(
                PASS_DECOMPILE,
                FORMAT_BYTECODE,
                FAMILY_INTERPRETER_BYTECODE,
                0.96,
                20,
                vec!["bc-marker"],
                "test bytecode".to_string(),
            )
        })
    }
}

#[derive(Debug)]
struct DecompilePass;
impl Pass for DecompilePass {
    fn id(&self) -> PassId {
        PASS_DECOMPILE
    }
    fn detector(&self) -> &'static dyn Detector {
        &DecompileDetector
    }
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Python,
            formatted: true,
        }
    }
    fn run(&self, artifact: &Artifact) -> disrobe_core::error::Result<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let body: Vec<u8> = format!("# decompiled\nprint({len})\n", len = bytes.len()).into_bytes();
        Ok(Artifact::new(Rung::Surface, body, artifact.root_hash))
    }
}

static PEEL: PeelPass = PeelPass;
static DECOMPILE: DecompilePass = DecompilePass;

#[derive(Debug)]
struct RealPassRunner;
impl PassRunner for RealPassRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: Vec<u8>,
        _config: &ChainConfig,
        _path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let out_artifact: Artifact = pick.pass.run(&artifact).map_err(|e| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: Duration::ZERO,
            metadata: BTreeMap::new(),
            children: Vec::new(),
        })
    }
}

fn build_registry() -> PassRegistry {
    let mut r: PassRegistry = PassRegistry::new();
    r.register(&PEEL);
    r.register(&DECOMPILE);
    r
}

fn scrub(value: &mut Value) {
    match value {
        Value::Object(m) => {
            for (k, v) in m.iter_mut() {
                if k == "total_ms" || k == "duration_ms" {
                    *v = Value::from(0u64);
                } else {
                    scrub(v);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub),
        _ => {}
    }
}

fn run_chain(seed: &[u8]) -> (ChainPlan, String) {
    let registry: PassRegistry = build_registry();
    let runner: RealPassRunner = RealPassRunner;
    let cfg: ChainConfig = ChainConfig {
        capture_stage_bytes: true,
        ..ChainConfig::default()
    };
    let driver: ChainDriver<'_, RealPassRunner> = ChainDriver::new(&registry, &runner, cfg);
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let plan: ChainPlan = driver.run(seed.to_vec(), &spec, Some("synthetic://idem".to_string()));
    let doc: ChainDocument = ChainDocument::from_plan(
        &plan,
        &spec,
        "auto:8",
        "0.0.0-idem",
        Some("synthetic://idem".to_string()),
    )
    .expect("valid chain metadata");
    let mut v: Value = serde_json::to_value(&doc).expect("doc serializes");
    scrub(&mut v);
    let rendered: String = serde_json::to_string_pretty(&v).expect("render");
    (plan, rendered)
}

fn final_recovered_bytes(plan: &ChainPlan) -> Vec<u8> {
    plan.nodes
        .iter()
        .find_map(|n| match &n.verdict {
            Verdict::Complete { .. } => n.output_bytes.clone(),
            _ => None,
        })
        .expect("a Complete node carrying captured source bytes")
}

#[test]
fn chain_reaches_a_complete_recovery_on_layered_seed() {
    let seed: &[u8] = b"WRAP:hello world payload bytes here";
    let (plan, _): (ChainPlan, String) = run_chain(seed);
    assert!(
        plan.nodes
            .iter()
            .any(|n| matches!(n.verdict, Verdict::Complete { .. })),
        "layered wrapper->bytecode->source seed must reach a Complete recovery",
    );
}

#[test]
fn rerunning_the_chain_on_recovered_output_is_a_stable_fixed_point() {
    let seed: &[u8] = b"WRAP:hello world payload bytes here";
    let (first_plan, _): (ChainPlan, String) = run_chain(seed);
    let recovered: Vec<u8> = final_recovered_bytes(&first_plan);

    let (second_plan, second_doc): (ChainPlan, String) = run_chain(&recovered);
    let productive_passes: Vec<&str> = second_plan
        .nodes
        .iter()
        .filter(|n| {
            n.pass_id.is_some()
                && matches!(
                    n.verdict,
                    Verdict::Complete { .. } | Verdict::Ok | Verdict::FanOut { .. }
                )
        })
        .filter_map(|n| n.pass_id.as_deref())
        .collect();
    assert!(
        productive_passes.is_empty(),
        "re-feeding fully recovered source must not trigger any further productive pass; got {productive_passes:?}",
    );
    assert!(
        matches!(second_plan.verdict, Verdict::Stalled),
        "a fully recovered artifact is a chain fixed point (no detector matches it), got {v:?}",
        v = second_plan.verdict,
    );

    let (_, second_doc_again): (ChainPlan, String) = run_chain(&recovered);
    assert_eq!(
        second_doc, second_doc_again,
        "run(run(x)) must be byte-identical across repeated runs (timings scrubbed)",
    );
}

#[test]
fn chain_history_guard_prevents_self_reentry_on_recovered_artifact() {
    let seed: &[u8] = b"WRAP:guarded reentry payload sample";
    let (plan, _): (ChainPlan, String) = run_chain(seed);
    let recovered: Vec<u8> = final_recovered_bytes(&plan);

    let (second, _): (ChainPlan, String) = run_chain(&recovered);
    assert_eq!(
        second.detector_calls, 0,
        "no detector may claim the fully recovered artifact, so the chain stalls at depth 1 \
         without looping a pass back onto its own output",
    );
    assert_eq!(
        second.nodes.len(),
        2,
        "the second run is a root plus a single Stalled terminal: no pass ever executes",
    );
}
