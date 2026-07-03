#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the correct visibility for these crate-internal chain helpers; redundant_pub_crate (nursery) and the workspace unreachable_pub lint cannot both hold for a private submodule, matching the crate-level allow already shipped in disrobe-cli"
)]

use std::collections::BTreeMap;
use std::time::Instant;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::state_machine::PassRunner;
use disrobe_core::chain::{
    ChainConfig, ChainDriver, ChainPlan, ChainSpec, ChildArtifact, DetectorPick, Node, OutputKind,
    PassRegistry, PassRunOutcome,
};

#[derive(Debug)]
struct McpPassRunner;

impl PassRunner for McpPassRunner {
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
            .map_err(|e: disrobe_core::error::CoreError| e.to_string())?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children(&artifact)
                .map_err(|e: disrobe_core::error::CoreError| e.to_string())?;
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

#[inline]
fn blake3_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn registry() -> PassRegistry {
    let mut r: PassRegistry = PassRegistry::new();
    r.register(&disrobe_pass_pyarmor::chain_detector::PYARMOR_PASS);
    r.register(&disrobe_pass_native::chain_detector::PACKER_PASS);
    r.register(&disrobe_pass_py_deob::chain_detector::PY_DEOB_PASS);
    r.register(&disrobe_binfmt::chain_detector::CONTAINER_PASS);
    r.register(&disrobe_pass_sourcedefender::chain_detector::SOURCEDEFENDER_PASS);
    r.register(&disrobe_pass_pyfreeze::chain_detector::PYFREEZE_PASS);
    r.register(&disrobe_pass_nuitka::chain_detector::NUITKA_PASS);
    r.register(&disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS);
    r.register(&disrobe_pass_py_decompile::chain_detector::PY_DECOMPILE_PASS);
    r.register(&disrobe_pass_pyinstaller::chain_detector::PYINSTALLER_PASS);
    r
}

#[derive(Debug)]
pub(crate) struct ChainRun {
    pub plan: ChainPlan,
    pub spec: ChainSpec,
    pub spec_raw: String,
}

pub(crate) fn run_auto(bytes: Vec<u8>, cap: u8) -> Result<ChainRun, String> {
    let spec_raw: String = format!("auto:{cap}");
    let spec: ChainSpec = ChainSpec::parse(&spec_raw).map_err(|e| e.to_string())?;
    let reg: PassRegistry = registry();
    let runner: McpPassRunner = McpPassRunner;
    let config: ChainConfig = ChainConfig {
        capture_stage_bytes: true,
        ..ChainConfig::default()
    };
    let driver: ChainDriver<'_, McpPassRunner> = ChainDriver::new(&reg, &runner, config);
    let plan: ChainPlan = driver.run(bytes, &spec, None);
    Ok(ChainRun {
        plan,
        spec,
        spec_raw,
    })
}

#[derive(Debug)]
pub(crate) struct RecoveredSource {
    pub pass: String,
    pub language: String,
    pub formatted: bool,
    pub source: String,
}

pub(crate) fn recovered_sources(plan: &ChainPlan) -> Vec<RecoveredSource> {
    let mut out: Vec<RecoveredSource> = Vec::new();
    for node in &plan.nodes {
        let is_terminal: bool = !plan
            .nodes
            .iter()
            .any(|other: &Node| other.parent_id == Some(node.id));
        if !is_terminal {
            continue;
        }
        let Some(OutputKind::Source {
            language,
            formatted,
        }): Option<&OutputKind> = node.output_kind.as_ref()
        else {
            continue;
        };
        let Some(raw): Option<&Vec<u8>> = node.output_bytes.as_ref() else {
            continue;
        };
        out.push(RecoveredSource {
            pass: node
                .pass_id
                .clone()
                .unwrap_or_else(|| "terminal".to_owned()),
            language: language.label().to_owned(),
            formatted: *formatted,
            source: String::from_utf8_lossy(raw).into_owned(),
        });
    }
    out
}
