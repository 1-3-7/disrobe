#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeMap;
use std::time::Duration;

use disrobe_core::chain::detection::{DetectContext, DetectVerdict, OutputKind, PassRunOutcome};
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

const PASS_PEEL: PassId = "bench.peel";
const PASS_DECOMPILE: PassId = "bench.decompile";

const DRIVER_SIZES_KIB: &[usize] = &[4, 64, 512, 2048];
const DETECTOR_SIZES_KIB: &[usize] = &[1, 64, 1024];

fn main() {
    divan::main();
}

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
                "bench-wrapper",
                FAMILY_OBFUSCATOR_WRAPPER,
                0.98,
                10,
                vec!["wrap"],
                "bench wrapper".to_string(),
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
            format_tag: "bench-bytecode",
            family: FAMILY_INTERPRETER_BYTECODE,
        }
    }
    fn run(&self, artifact: &Artifact) -> disrobe_core::error::Result<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let payload: Vec<u8> = if bytes.starts_with(b"WRAP:") {
            let mut out: Vec<u8> = Vec::with_capacity(bytes.len() - 5 + 3);
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
                "bench-bytecode",
                FAMILY_INTERPRETER_BYTECODE,
                0.96,
                20,
                vec!["bc"],
                "bench bytecode".to_string(),
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
        let body: Vec<u8> =
            format!("# decompiled n={len}\nprint(\"ok\")\n", len = bytes.len()).into_bytes();
        Ok(Artifact::new(Rung::Surface, body, artifact.root_hash))
    }
}

static PEEL: PeelPass = PeelPass;
static DECOMPILE: DecompilePass = DecompilePass;

#[derive(Debug)]
struct BenchRunner;
impl PassRunner for BenchRunner {
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

fn make_payload(size_bytes: usize) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(size_bytes);
    v.extend_from_slice(b"WRAP:");
    let pad: usize = size_bytes.saturating_sub(5);
    v.resize(5 + pad, 0xAB);
    v
}

#[divan::bench(args = DRIVER_SIZES_KIB)]
fn chain_driver_end_to_end(bencher: divan::Bencher, size_kib: usize) {
    let registry: PassRegistry = build_registry();
    let runner: BenchRunner = BenchRunner;
    let driver: ChainDriver<'_, BenchRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let payload: Vec<u8> = make_payload(size_kib * 1024);
    bencher
        .counter(divan::counter::BytesCount::new(payload.len()))
        .bench_local(|| {
            let plan: ChainPlan = driver.run(
                divan::black_box(payload.clone()),
                divan::black_box(&spec),
                None,
            );
            divan::black_box(plan);
        });
}

#[divan::bench]
fn chain_json_render(bencher: divan::Bencher) {
    let registry: PassRegistry = build_registry();
    let runner: BenchRunner = BenchRunner;
    let driver: ChainDriver<'_, BenchRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let payload: Vec<u8> = make_payload(64 * 1024);
    let plan: ChainPlan = driver.run(payload, &spec, None);
    bencher.bench_local(|| {
        let doc: ChainDocument = ChainDocument::from_plan(&plan, &spec, "auto:8", "bench", None);
        let s: Vec<u8> = serde_json::to_vec(&doc).expect("ok");
        divan::black_box(s);
    });
}

#[divan::bench(args = DETECTOR_SIZES_KIB)]
fn detector_only(bencher: divan::Bencher, size_kib: usize) {
    let registry: PassRegistry = build_registry();
    let payload: Vec<u8> = make_payload(size_kib * 1024);
    bencher
        .counter(divan::counter::BytesCount::new(payload.len()))
        .bench_local(|| {
            let ctx: DetectContext<'_> = DetectContext {
                bytes: divan::black_box(&payload),
                path_hint: None,
                parent_hint: None,
                depth: 0,
            };
            let pick: Option<DetectorPick> = registry.run_all_and_pick(&ctx);
            divan::black_box(pick);
        });
}
