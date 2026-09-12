use std::collections::BTreeMap;
use std::time::Instant;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::state_machine::PassRunner;
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainDriver, ChainPlan, ChainSpec, ChildArtifact, DetectorPick,
    OutputKind, PassRegistry, PassRunOutcome,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::err::{DisrobeError, map};
use crate::typed::ChainReport as PyChainReport;

const SCHEMA_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
struct ChainPassRunner;

impl PassRunner for ChainPassRunner {
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
            .map_err(|e: disrobe_core::error::CoreError| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children(&artifact)
                .map_err(|e: disrobe_core::error::CoreError| format!("{e}"))?;
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

fn build_registry() -> PassRegistry {
    disrobe_passes::build_registry()
}

#[pyfunction]
#[pyo3(signature = (input, *, max_depth = 8, path_hint = None))]
#[pyo3(text_signature = "(input, *, max_depth=8, path_hint=None)")]
fn auto(input: &[u8], max_depth: u8, path_hint: Option<String>) -> PyResult<PyChainReport> {
    if max_depth == 0 || max_depth > 16 {
        return Err(DisrobeError::new_err(
            "max_depth must be between 1 & 16 inclusive".to_owned(),
        ));
    }
    let spec_raw: String = format!("auto:{max_depth}");
    let spec: ChainSpec = ChainSpec::parse(&spec_raw).map_err(map("chain spec parse"))?;
    let registry: PassRegistry = build_registry();
    let runner: ChainPassRunner = ChainPassRunner;
    let driver: ChainDriver<'_, ChainPassRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let plan: ChainPlan = driver.run(input.to_vec(), &spec, path_hint.clone());
    let doc: ChainDocument =
        ChainDocument::from_plan(&plan, &spec, &spec_raw, SCHEMA_VERSION, path_hint)
            .map_err(map("chain metadata"))?;
    PyChainReport::from_serialize(&doc)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(auto, m)?)?;
    Ok(())
}
