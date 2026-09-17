#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::time::Duration;

use disrobe_core::chain::detection::OutputKind;
use disrobe_core::chain::{ChainPlan, ChainRecoveryReport, Node, Verdict};
use disrobe_core::provenance::Language;
use serde_json::Value;

fn root_node() -> Node {
    Node {
        id: 0,
        parent_id: None,
        depth: 0,
        branch_id: "a".to_string(),
        pass_id: None,
        format_tag_in: None,
        input_blake3: [0xabu8; 32],
        input_size: 256,
        output_kind: None,
        output_blake3: None,
        output_size: None,
        output_bytes: None,
        duration: None,
        picks: Vec::new(),
        artifacts: Vec::new(),
        metadata: BTreeMap::new(),
        verdict: Verdict::Ok,
    }
}

fn node(
    id: u32,
    pass_id: &str,
    input_hash: [u8; 32],
    output_hash: Option<[u8; 32]>,
    kind: Option<OutputKind>,
    verdict: Verdict,
) -> Node {
    Node {
        id,
        parent_id: Some(0),
        depth: 1,
        branch_id: "a".to_string(),
        pass_id: Some(pass_id.to_string()),
        format_tag_in: Some("tag".to_string()),
        input_blake3: input_hash,
        input_size: 32,
        output_kind: kind,
        output_blake3: output_hash,
        output_size: output_hash.map(|_| 32),
        output_bytes: None,
        duration: Some(Duration::from_millis(11)),
        picks: Vec::new(),
        artifacts: Vec::new(),
        metadata: BTreeMap::new(),
        verdict,
    }
}

fn fixture_plan() -> ChainPlan {
    let source: Node = node(
        1,
        "py.decompile",
        [1u8; 32],
        Some([2u8; 32]),
        Some(OutputKind::Source {
            language: Language::Python,
            formatted: true,
        }),
        Verdict::Complete {
            formats: vec!["Python".to_string()],
        },
    );
    let bytes: Node = node(
        2,
        "pyarmor.unpack",
        [2u8; 32],
        Some([3u8; 32]),
        Some(OutputKind::Bytes {
            format_tag: "pyc-3.11",
            family: "interpreter-bytecode",
        }),
        Verdict::Ok,
    );
    let errored: Node = node(
        3,
        "nuitka.extract",
        [3u8; 32],
        None,
        None,
        Verdict::Error {
            message: "boom".to_string(),
        },
    );
    ChainPlan {
        nodes: vec![root_node(), source, bytes, errored],
        root_id: 0,
        verdict: Verdict::FanOutPartial { ok: 1, total: 2 },
        final_format: Some("Python".to_string()),
        total: Duration::from_millis(42),
        detector_calls: 3,
        rejected_passes: 0,
        has_multiple_branches: false,
        extracted: Vec::new(),
    }
}

#[test]
fn recovery_json_emits_real_per_pass_signals() {
    let plan: ChainPlan = fixture_plan();
    let report: ChainRecoveryReport =
        ChainRecoveryReport::from_plan(&plan, "9.9.9", Some("in.pyc".to_string()));
    let v: Value = serde_json::to_value(&report).expect("serialize recovery report");

    assert_eq!(v["schema"], "disrobe.recovery/v1");
    assert_eq!(v["tool_version"], "9.9.9");
    assert!(v["tool_version"].is_string());

    let blake3: &str = v["input"]["blake3"].as_str().expect("blake3 string");
    assert_eq!(blake3.len(), 64);
    assert!(blake3.chars().all(|c: char| c.is_ascii_hexdigit()));
    assert_eq!(v["input"]["size"].as_u64(), Some(256));
    assert_eq!(v["input"]["path"], "in.pyc");

    let passes: &Vec<Value> = v["passes"].as_array().expect("passes array");
    assert_eq!(passes.len(), plan.nodes.len() - 1);
    assert_eq!(passes.len(), 3);

    assert_eq!(passes[0]["status"], "recovered");
    assert_eq!(passes[0]["confidence"], "semantic");
    assert_eq!(passes[0]["format_out"], "Python");
    assert_eq!(passes[0]["duration_ms"].as_u64(), Some(11));
    assert_eq!(passes[0]["name"], "py.decompile");

    assert_eq!(passes[1]["status"], "advanced");
    assert_eq!(passes[1]["confidence"], "partial");

    assert_eq!(passes[2]["status"], "failed");
    assert_eq!(passes[2]["confidence"], "skeleton");

    let h: &Value = &v["histogram"];
    let exact: u64 = h["exact"].as_u64().expect("exact count");
    let semantic: u64 = h["semantic"].as_u64().expect("semantic count");
    let partial: u64 = h["partial"].as_u64().expect("partial count");
    let skeleton: u64 = h["skeleton"].as_u64().expect("skeleton count");
    assert_eq!(
        exact + semantic + partial + skeleton,
        passes.len() as u64,
        "histogram must sum to pass count"
    );
    assert_eq!(exact, 0);
    assert_eq!(partial, 1);
    assert_eq!(skeleton, 1);
    assert_eq!(semantic, 1);

    assert_eq!(v["total_ms"].as_u64(), Some(42));
    assert!(v["verdict"].is_string());
    assert_eq!(v["verdict"], "fan-out-partial");
}
