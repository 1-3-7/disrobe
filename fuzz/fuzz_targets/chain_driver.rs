#![no_main]
#![cfg(feature = "chain")]
use libfuzzer_sys::fuzz_target;

use disrobe_core::chain::detection::{DetectContext, DetectVerdict, OutputKind, PassRunOutcome};
use disrobe_core::chain::detector::{Detector, Pass};
use disrobe_core::chain::registry::DetectorPick;
use disrobe_core::chain::state_machine::{ChainDriver, ChainPlan, PassRunner};
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainSpec, FAMILY_INTERPRETER_BYTECODE, PassRegistry,
};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;
use disrobe_core::{Artifact, Rung};

use std::collections::BTreeMap;
use std::time::Duration;

const FUZZ_PASS_ID: PassId = "fuzz.identity";

#[derive(Debug)]
struct FuzzDetector;
impl Detector for FuzzDetector {
    fn id(&self) -> PassId {
        FUZZ_PASS_ID
    }
    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        if ctx.bytes.is_empty() {
            return None;
        }
        Some(DetectVerdict::new(
            FUZZ_PASS_ID,
            "fuzz-identity",
            FAMILY_INTERPRETER_BYTECODE,
            0.91,
            99,
            vec!["fuzz"],
            "fuzz identity verdict".to_string(),
        ))
    }
}

#[derive(Debug)]
struct FuzzPass;
impl Pass for FuzzPass {
    fn id(&self) -> PassId {
        FUZZ_PASS_ID
    }
    fn detector(&self) -> &'static dyn Detector {
        &FuzzDetector
    }
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Python,
            formatted: false,
        }
    }
    fn run(&self, artifact: &Artifact) -> disrobe_core::error::Result<Artifact> {
        Ok(Artifact::new(
            Rung::Surface,
            artifact.envelope.clone(),
            artifact.root_hash,
        ))
    }
}

static FUZZ_PASS_STATIC: FuzzPass = FuzzPass;

#[derive(Debug)]
struct FuzzRunner;
impl PassRunner for FuzzRunner {
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

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let mut registry: PassRegistry = PassRegistry::new();
    registry.register(&FUZZ_PASS_STATIC);
    let runner: FuzzRunner = FuzzRunner;
    let driver: ChainDriver<'_, FuzzRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Auto { cap: 4 };
    let plan: ChainPlan = driver.run(data.to_vec(), &spec, None);
    let doc: ChainDocument = ChainDocument::from_plan(&plan, &spec, "auto:4", "0.0.0-fuzz", None);
    let _ = serde_json::to_vec(&doc);
});
