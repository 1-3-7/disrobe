#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::time::Duration;

use disrobe_core::chain::detection::{
    ConfidenceBand, DetectContext, DetectVerdict, OutputKind, PassRunOutcome,
};
use disrobe_core::chain::detector::{Detector, Pass};
use disrobe_core::chain::registry::DetectorPick;
use disrobe_core::chain::state_machine::{ChainDriver, ChainPlan, PassRunner};
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

#[derive(Debug)]
struct PeelDetector;
impl Detector for PeelDetector {
    fn id(&self) -> PassId {
        PASS_PEEL
    }
    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        if ctx.bytes.starts_with(b"WRAP:") {
            Some(DetectVerdict::new(
                PASS_PEEL,
                FORMAT_WRAPPER,
                FAMILY_OBFUSCATOR_WRAPPER,
                0.98,
                10,
                vec!["wrap-marker"],
                "test wrapper".to_string(),
            ))
        } else {
            None
        }
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
        let payload: Vec<u8> = if bytes.starts_with(b"WRAP:") {
            let mut out: Vec<u8> = Vec::with_capacity(bytes.len() - 5);
            out.extend_from_slice(b"BC:");
            out.extend_from_slice(&bytes[5..]);
            out
        } else {
            bytes.to_vec()
        };
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
        if ctx.bytes.starts_with(b"BC:") {
            Some(DetectVerdict::new(
                PASS_DECOMPILE,
                FORMAT_BYTECODE,
                FAMILY_INTERPRETER_BYTECODE,
                0.96,
                20,
                vec!["bc-marker"],
                "test bytecode".to_string(),
            ))
        } else {
            None
        }
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
        bytes: &[u8],
        _config: &ChainConfig,
    ) -> Result<PassRunOutcome, String> {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [0u8; 32]);
        let out_artifact: Artifact = pick.pass.run(&artifact).map_err(|e| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: Duration::ZERO,
            metadata: BTreeMap::new(),
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

fn run_once(seed: &[u8]) -> String {
    let registry: PassRegistry = build_registry();
    let runner: RealPassRunner = RealPassRunner;
    let driver: ChainDriver<'_, RealPassRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let plan: ChainPlan = driver.run(seed.to_vec(), &spec, Some("synthetic://det".to_string()));
    let doc: ChainDocument = ChainDocument::from_plan(
        &plan,
        &spec,
        "auto:8",
        "0.0.0-det",
        Some("synthetic://det".to_string()),
    );
    let mut v: Value = serde_json::to_value(&doc).expect("doc serializes");
    scrub(&mut v);
    serde_json::to_string_pretty(&v).expect("render")
}

#[test]
fn chain_json_is_byte_identical_across_100_runs() {
    let seed: &[u8] = b"WRAP:hello world payload bytes here";
    let baseline: String = run_once(seed);
    let counter: AtomicU32 = AtomicU32::new(0);
    let mut variants: BTreeSet<String> = BTreeSet::new();
    variants.insert(baseline);
    for _ in 0..100u32 {
        let next: String = run_once(seed);
        counter.fetch_add(1, AtomicOrdering::SeqCst);
        variants.insert(next);
    }
    assert_eq!(
        variants.len(),
        1,
        "expected exactly 1 distinct chain.json across 100 runs (timings scrubbed); got {n}",
        n = variants.len(),
    );
    assert_eq!(counter.load(AtomicOrdering::SeqCst), 100);
}

#[test]
fn pick_order_stable_across_repeated_runs() {
    let seed: &[u8] = b"WRAP:deterministic-pick";
    let registry: PassRegistry = build_registry();
    let ctx: DetectContext<'_> = DetectContext {
        bytes: seed,
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let pick_a: DetectorPick = registry.run_all_and_pick(&ctx).expect("first pick exists");
    for _ in 0..100u32 {
        let pick_n: DetectorPick = registry.run_all_and_pick(&ctx).expect("pick exists");
        assert_eq!(pick_n.verdict.pass_id, pick_a.verdict.pass_id);
        assert_eq!(pick_n.verdict.format_tag, pick_a.verdict.format_tag);
        assert_eq!(pick_n.verdict.specificity, pick_a.verdict.specificity);
        assert_eq!(pick_n.verdict.band, pick_a.verdict.band);
    }
}

#[test]
fn band_ordering_assumption_holds() {
    assert!(ConfidenceBand::Low < ConfidenceBand::Medium);
    assert!(ConfidenceBand::Medium < ConfidenceBand::High);
}
