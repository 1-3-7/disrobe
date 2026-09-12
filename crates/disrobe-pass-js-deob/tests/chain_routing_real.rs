#![cfg(feature = "chain")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

use disrobe_core::chain::state_machine::{
    ChainConfig, ChainDriver, ChainPlan, ExtractedArtifact, PassRunner,
};
use disrobe_core::chain::{
    ChainSpec, ChildArtifact, DetectorPick, OutputKind, PassRegistry, PassRunOutcome, Verdict,
};
use disrobe_core::pass::PassContext;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_js_deob::chain_detector::JS_OBF_PASS;

const OBFUSCATOR_IO_BASE64: &str =
    include_str!("../../../corpus/js/javascript-obfuscator/browser/obf_base64.js");
const OBFUSCATOR_IO_CFF: &str =
    include_str!("../../../corpus/js/javascript-obfuscator/browser/obf_cff.js");
const PACKER_DOUBLE_LAYER: &str =
    include_str!("../../../corpus/js/packer/real/double-layer.packed.js");
const RECOVERED_CHILD: &str = "js-deob.recovered.js";

#[derive(Debug)]
struct RecordingRunner {
    inputs: Mutex<Vec<Vec<u8>>>,
}

impl RecordingRunner {
    const fn new() -> Self {
        Self {
            inputs: Mutex::new(Vec::new()),
        }
    }

    fn inputs(&self) -> Vec<Vec<u8>> {
        self.inputs
            .lock()
            .expect("the runner input log must not be poisoned")
            .clone()
    }
}

impl PassRunner for RecordingRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: Vec<u8>,
        _config: &ChainConfig,
        path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        self.inputs
            .lock()
            .expect("the runner input log must not be poisoned")
            .push(bytes.clone());
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let started: Instant = Instant::now();
        let context: PassContext<'_> = PassContext {
            path_hint,
            i_have_authorization: false,
        };
        let output: Artifact = pick
            .pass
            .run_with_context(&artifact, context)
            .map_err(|error: disrobe_core::error::CoreError| error.to_string())?;
        let initial_kind: OutputKind = pick.pass.output_kind(&output);
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if initial_kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children_with_context(&artifact, context)
                .map_err(|error: disrobe_core::error::CoreError| error.to_string())?;
            OutputKind::mixed_from_children(extracted)
        } else {
            (initial_kind, Vec::new())
        };
        Ok(PassRunOutcome {
            output_bytes: output.envelope,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
            children,
        })
    }
}

fn drive(sample: &str) -> (ChainPlan, Vec<Vec<u8>>) {
    let mut registry: PassRegistry = PassRegistry::new();
    registry.register(&JS_OBF_PASS);
    let runner: RecordingRunner = RecordingRunner::new();
    let config: ChainConfig = ChainConfig {
        persist_children: true,
        ..ChainConfig::default()
    };
    let driver: ChainDriver<'_, RecordingRunner> = ChainDriver::new(&registry, &runner, config);
    let plan: ChainPlan = driver.run(
        sample.as_bytes().to_vec(),
        &ChainSpec::Auto { cap: 8 },
        None,
    );
    let inputs: Vec<Vec<u8>> = runner.inputs();
    (plan, inputs)
}

fn recovered_payloads(plan: &ChainPlan) -> Vec<Vec<u8>> {
    plan.extracted
        .iter()
        .filter(|a: &&ExtractedArtifact| a.relative_path == RECOVERED_CHILD)
        .map(|a: &ExtractedArtifact| a.bytes.clone())
        .collect()
}

fn sidecar_reports(plan: &ChainPlan) -> Vec<Vec<u8>> {
    plan.extracted
        .iter()
        .filter(|a: &&ExtractedArtifact| {
            std::path::Path::new(&a.relative_path)
                .extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("json"))
        })
        .map(|a: &ExtractedArtifact| a.bytes.clone())
        .collect()
}

#[test]
fn the_recovered_payload_reaches_the_next_pass_and_the_second_layer_is_peeled() {
    let (plan, inputs): (ChainPlan, Vec<Vec<u8>>) = drive(OBFUSCATOR_IO_BASE64);
    let payloads: Vec<Vec<u8>> = recovered_payloads(&plan);
    let first: &Vec<u8> = payloads
        .first()
        .expect("the first pass must emit a recovered javascript payload");
    assert!(
        inputs.len() >= 2,
        "the recovered payload must be offered to the chain, not held as the answer; \
         runner inputs={} sizes={:?}",
        inputs.len(),
        inputs.iter().map(Vec::len).collect::<Vec<usize>>()
    );
    assert_eq!(
        inputs[1].as_slice(),
        first.as_slice(),
        "the second pass must receive the recovered payload byte for byte; got {} bytes, \
         expected the {} byte payload",
        inputs[1].len(),
        first.len()
    );
    assert!(
        payloads.len() >= 2,
        "the inner obfuscation layer must be peeled too; recovered payload count={}",
        payloads.len()
    );
    assert_ne!(
        payloads[0], payloads[1],
        "the second peel must produce different bytes from the first"
    );
    assert!(
        !matches!(plan.verdict, Verdict::Stalled | Verdict::Error { .. }),
        "peeling a further layer must not turn a recovery into {:?}",
        plan.verdict
    );
}

#[test]
fn a_fully_recovered_payload_is_the_answer_and_does_not_stall_the_chain() {
    let (plan, inputs): (ChainPlan, Vec<Vec<u8>>) = drive(PACKER_DOUBLE_LAYER);
    assert_eq!(
        inputs.len(),
        1,
        "a recovered payload with nothing left to peel must not be re-offered; sizes={:?}",
        inputs.iter().map(Vec::len).collect::<Vec<usize>>()
    );
    assert_eq!(
        recovered_payloads(&plan).len(),
        1,
        "the packed sample recovers exactly one payload"
    );
    assert!(
        matches!(plan.verdict, Verdict::Ok | Verdict::Complete { .. }),
        "a complete recovery must not read as {:?}",
        plan.verdict
    );
}

#[test]
fn a_control_flow_flattened_sample_also_peels_its_inner_layer() {
    let (plan, inputs): (ChainPlan, Vec<Vec<u8>>) = drive(OBFUSCATOR_IO_CFF);
    let payloads: Vec<Vec<u8>> = recovered_payloads(&plan);
    assert!(
        inputs.len() >= 2,
        "the recovered payload must be re-detected; runner inputs={}",
        inputs.len()
    );
    assert!(
        payloads.len() >= 2,
        "the inner layer must be peeled; recovered payload count={}",
        payloads.len()
    );
    assert!(
        !matches!(plan.verdict, Verdict::Stalled | Verdict::Error { .. }),
        "peeling a further layer must not turn a recovery into {:?}",
        plan.verdict
    );
}

#[test]
fn a_pass_report_sidecar_is_never_handed_to_the_next_pass() {
    for sample in [OBFUSCATOR_IO_BASE64, OBFUSCATOR_IO_CFF] {
        let (plan, inputs): (ChainPlan, Vec<Vec<u8>>) = drive(sample);
        let reports: Vec<Vec<u8>> = sidecar_reports(&plan);
        assert!(
            !reports.is_empty(),
            "this sample must emit at least one json report sidecar"
        );
        for report in &reports {
            assert!(
                !inputs.iter().any(|seen: &Vec<u8>| seen == report),
                "a pass report sidecar of {} bytes was fed onward as a sample",
                report.len()
            );
        }
    }
}
