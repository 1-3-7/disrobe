#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use disrobe_core::chain::detection::{
    ChildArtifact, ChildHandle, DetectContext, DetectVerdict, OutputKind, PassRunOutcome,
    TERMINAL_HINT,
};
use disrobe_core::chain::detector::{Detector, Pass};
use disrobe_core::chain::registry::DetectorPick;
use disrobe_core::chain::state_machine::{ChainDriver, ChainPlan, ExtractedArtifact, PassRunner};
use disrobe_core::chain::{
    ChainConfig, ChainSpec, FAMILY_NATIVE_FORMAT, FAMILY_OBFUSCATOR_WRAPPER, Node, PassRegistry,
    Verdict,
};
use disrobe_core::pass::PassId;
use disrobe_core::{Artifact, Rung};

const STUB_PASS: PassId = "test.routing";
const STUB_TAG: &str = "test-routing";
const SEED: &[u8] = b"SEED: the original sample bytes";
const PAYLOAD: &[u8] = b"PAYLOAD: a recovered inner sample";
const REPORT: &[u8] = b"{\"schema\":\"test.report/v1\",\"note\":\"what the pass did\"}";

#[derive(Debug)]
struct StubDetector;

impl Detector for StubDetector {
    fn id(&self) -> PassId {
        STUB_PASS
    }

    fn detect(&self, _ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        Some(DetectVerdict::new(
            STUB_PASS,
            STUB_TAG,
            FAMILY_OBFUSCATOR_WRAPPER,
            0.99,
            40,
            vec!["always"],
            "the stub detector claims every artifact".to_string(),
        ))
    }
}

#[derive(Debug)]
struct StubPass;

impl Pass for StubPass {
    fn id(&self) -> PassId {
        STUB_PASS
    }

    fn detector(&self) -> &'static dyn Detector {
        &StubDetector
    }

    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Bytes {
            format_tag: STUB_TAG,
            family: FAMILY_OBFUSCATOR_WRAPPER,
        }
    }

    fn run(&self, artifact: &Artifact) -> disrobe_core::error::Result<Artifact> {
        Ok(Artifact::new(
            Rung::Raw,
            artifact.envelope.clone(),
            artifact.root_hash,
        ))
    }
}

static ROUTING_PASS: StubPass = StubPass;

type Script = Box<dyn Fn(usize) -> PassRunOutcome + Send + Sync>;

struct ScriptedRunner {
    inputs: Mutex<Vec<Vec<u8>>>,
    script: Script,
}

impl std::fmt::Debug for ScriptedRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScriptedRunner")
    }
}

impl ScriptedRunner {
    fn new(script: Script) -> Self {
        Self {
            inputs: Mutex::new(Vec::new()),
            script,
        }
    }

    fn inputs(&self) -> Vec<Vec<u8>> {
        self.inputs
            .lock()
            .expect("the runner input log must not be poisoned")
            .clone()
    }
}

impl PassRunner for ScriptedRunner {
    fn run(
        &self,
        _pick: &DetectorPick,
        bytes: Vec<u8>,
        _config: &ChainConfig,
        _path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        let call: usize = {
            let mut log: std::sync::MutexGuard<'_, Vec<Vec<u8>>> = self
                .inputs
                .lock()
                .expect("the runner input log must not be poisoned");
            log.push(bytes);
            log.len() - 1
        };
        Ok((self.script)(call))
    }
}

const fn outcome(
    kind: OutputKind,
    output_bytes: Vec<u8>,
    children: Vec<Vec<u8>>,
) -> PassRunOutcome {
    PassRunOutcome {
        output_bytes,
        kind,
        duration: Duration::from_millis(1),
        metadata: BTreeMap::new(),
        children,
    }
}

fn report_outcome() -> PassRunOutcome {
    outcome(
        OutputKind::Report {
            format_tag: "test.report",
            family: FAMILY_NATIVE_FORMAT,
        },
        REPORT.to_vec(),
        Vec::new(),
    )
}

fn bytes_outcome() -> PassRunOutcome {
    outcome(
        OutputKind::Bytes {
            format_tag: STUB_TAG,
            family: FAMILY_OBFUSCATOR_WRAPPER,
        },
        PAYLOAD.to_vec(),
        Vec::new(),
    )
}

fn mixed_outcome() -> PassRunOutcome {
    let (kind, children): (OutputKind, Vec<Vec<u8>>) = OutputKind::mixed_from_children(vec![
        ChildArtifact {
            handle: ChildHandle {
                artifact_index: u32::MAX,
                relative_path: "recovered.bin".to_string(),
                hint: None,
            },
            bytes: PAYLOAD.to_vec(),
        },
        ChildArtifact {
            handle: ChildHandle {
                artifact_index: u32::MAX,
                relative_path: "pass.report.json".to_string(),
                hint: Some(TERMINAL_HINT.to_string()),
            },
            bytes: REPORT.to_vec(),
        },
    ]);
    outcome(kind, Vec::new(), children)
}

fn drive(script: Script) -> (ChainPlan, Vec<Vec<u8>>) {
    let mut registry: PassRegistry = PassRegistry::new();
    registry.register(&ROUTING_PASS);
    let runner: ScriptedRunner = ScriptedRunner::new(script);
    let config: ChainConfig = ChainConfig {
        persist_children: true,
        ..ChainConfig::default()
    };
    let driver: ChainDriver<'_, ScriptedRunner> = ChainDriver::new(&registry, &runner, config);
    let plan: ChainPlan = driver.run(SEED.to_vec(), &ChainSpec::Auto { cap: 8 }, None);
    let inputs: Vec<Vec<u8>> = runner.inputs();
    (plan, inputs)
}

fn persisted(plan: &ChainPlan, relative_path: &str) -> Option<Vec<u8>> {
    plan.extracted
        .iter()
        .find(|a: &&ExtractedArtifact| a.relative_path == relative_path)
        .map(|a: &ExtractedArtifact| a.bytes.clone())
}

#[test]
fn a_report_output_is_the_answer_and_never_becomes_the_next_input() {
    let (plan, inputs): (ChainPlan, Vec<Vec<u8>>) =
        drive(Box::new(|_call: usize| report_outcome()));
    assert_eq!(
        inputs,
        vec![SEED.to_vec()],
        "the stub detector claims every artifact, so a second call proves the report was \
         re-detected as a sample"
    );
    assert!(matches!(plan.verdict, Verdict::Ok));
    assert_eq!(
        persisted(&plan, "chain-node-1-test.report.json").as_deref(),
        Some(REPORT),
        "the report must still reach the caller as an extracted artifact"
    );
}

#[test]
fn a_bytes_output_is_handed_to_the_next_pass_byte_for_byte() {
    let (plan, inputs): (ChainPlan, Vec<Vec<u8>>) = drive(Box::new(|call: usize| {
        if call == 0 {
            bytes_outcome()
        } else {
            report_outcome()
        }
    }));
    assert_eq!(
        inputs,
        vec![SEED.to_vec(), PAYLOAD.to_vec()],
        "a recovered payload must advance the chain unchanged"
    );
    assert!(matches!(plan.verdict, Verdict::Ok));
}

#[test]
fn a_payload_child_advances_while_a_report_child_stays_out_of_the_input_stream() {
    let (plan, inputs): (ChainPlan, Vec<Vec<u8>>) = drive(Box::new(|call: usize| {
        if call == 0 {
            mixed_outcome()
        } else {
            report_outcome()
        }
    }));
    assert_eq!(
        inputs,
        vec![SEED.to_vec(), PAYLOAD.to_vec()],
        "the payload child must be the only child offered to a pass"
    );
    assert!(
        !inputs
            .iter()
            .any(|seen: &Vec<u8>| seen.as_slice() == REPORT),
        "a report child must never be handed to a pass"
    );
    assert_eq!(
        persisted(&plan, "recovered.bin").as_deref(),
        Some(PAYLOAD),
        "the payload child must still be written out"
    );
    assert_eq!(
        persisted(&plan, "pass.report.json").as_deref(),
        Some(REPORT),
        "the report child must still be written out"
    );
}

#[test]
fn a_report_below_the_root_ends_its_branch_without_consuming_a_later_pass() {
    let (plan, inputs): (ChainPlan, Vec<Vec<u8>>) = drive(Box::new(|call: usize| {
        if call == 0 {
            bytes_outcome()
        } else {
            report_outcome()
        }
    }));
    let report_nodes: usize = plan
        .nodes
        .iter()
        .filter(|n: &&Node| n.output_kind.as_ref().is_some_and(OutputKind::is_report))
        .count();
    assert_eq!(report_nodes, 1, "the depth-2 node must record a report");
    assert_eq!(
        inputs.len(),
        2,
        "a report at depth 2 must not queue a third pass"
    );
}
