use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::state_machine::{ChainPlan, NodeId};
use crate::time::WallClock;

pub const RUN_SCHEMA_VERSION: &str = "disrobe.run/v1";
pub const RUN_FILE_NAME: &str = "run.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub schema: String,
    pub tool_version: String,
    pub started_at: String,
    pub ended_at: String,
    pub jobs: usize,
    pub total_ms: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub nodes: BTreeMap<NodeId, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunClock {
    pub started: WallClock,
    pub ended: WallClock,
    pub jobs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunRecordError {
    #[error("cannot write a timing record: chain node {node_id} has no measured duration")]
    MissingNodeDuration { node_id: NodeId },
}

#[must_use]
pub fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl RunRecord {
    pub fn for_chain(
        plan: &ChainPlan,
        clock: RunClock,
        tool_version: &str,
    ) -> Result<Self, RunRecordError> {
        let mut nodes: BTreeMap<NodeId, u64> = BTreeMap::new();
        for node in &plan.nodes {
            let duration: Duration = node
                .duration
                .ok_or(RunRecordError::MissingNodeDuration { node_id: node.id })?;
            nodes.insert(node.id, millis(duration));
        }
        Ok(Self {
            nodes,
            ..Self::empty(clock, tool_version, plan.total)
        })
    }

    #[must_use]
    pub fn for_batch(
        files: BTreeMap<String, u64>,
        total: Duration,
        clock: RunClock,
        tool_version: &str,
    ) -> Self {
        Self {
            files,
            ..Self::empty(clock, tool_version, total)
        }
    }

    fn empty(clock: RunClock, tool_version: &str, total: Duration) -> Self {
        Self {
            schema: RUN_SCHEMA_VERSION.to_string(),
            tool_version: tool_version.to_string(),
            started_at: clock.started.rfc3339_millis(),
            ended_at: clock.ended.rfc3339_millis(),
            jobs: clock.jobs,
            total_ms: millis(total),
            nodes: BTreeMap::new(),
            files: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::chain::state_machine::{Node, Verdict};

    fn node(id: NodeId, duration: Option<Duration>) -> Node {
        Node {
            id,
            parent_id: id.checked_sub(1),
            depth: u8::try_from(id).unwrap_or(u8::MAX),
            branch_id: "a".to_string(),
            pass_id: None,
            format_tag_in: None,
            input_blake3: [0u8; 32],
            input_size: 0,
            output_kind: None,
            output_blake3: None,
            output_size: None,
            output_bytes: None,
            duration,
            picks: Vec::new(),
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
            verdict: Verdict::Ok,
        }
    }

    fn clock(jobs: usize) -> RunClock {
        RunClock {
            started: WallClock::now(),
            ended: WallClock::now(),
            jobs,
        }
    }

    #[test]
    fn a_chain_record_keys_each_node_duration_by_node_id() {
        let plan: ChainPlan = ChainPlan {
            nodes: vec![
                node(0, Some(Duration::from_millis(42))),
                node(1, Some(Duration::from_millis(7))),
                node(2, Some(Duration::from_micros(300))),
                node(3, Some(Duration::ZERO)),
            ],
            root_id: 0,
            verdict: Verdict::Ok,
            final_format: None,
            total: Duration::from_millis(42),
            detector_calls: 0,
            rejected_passes: 0,
            has_multiple_branches: false,
            extracted: Vec::new(),
        };
        let record: RunRecord =
            RunRecord::for_chain(&plan, clock(1), "9.9.9").expect("all nodes are measured");
        let written: serde_json::Value = serde_json::to_value(&record).expect("serialize");
        assert_eq!(written["schema"], RUN_SCHEMA_VERSION);
        assert_eq!(written["total_ms"], 42);
        assert_eq!(written["jobs"], 1);
        assert_eq!(
            written["nodes"],
            serde_json::json!({ "0": 42, "1": 7, "2": 0, "3": 0 }),
            "every measured node is represented by its node id"
        );
        assert!(written.get("files").is_none());
        let parsed: RunRecord = serde_json::from_value(written).expect("round trip");
        assert_eq!(parsed, record);
    }

    #[test]
    fn a_chain_record_refuses_an_unmeasured_node() {
        let plan: ChainPlan = ChainPlan {
            nodes: vec![node(0, Some(Duration::ZERO)), node(1, None)],
            root_id: 0,
            verdict: Verdict::Ok,
            final_format: None,
            total: Duration::ZERO,
            detector_calls: 0,
            rejected_passes: 0,
            has_multiple_branches: false,
            extracted: Vec::new(),
        };
        assert_eq!(
            RunRecord::for_chain(&plan, clock(1), "9.9.9"),
            Err(RunRecordError::MissingNodeDuration { node_id: 1 })
        );
    }

    #[test]
    fn a_batch_record_keys_durations_by_file() {
        let files: BTreeMap<String, u64> = BTreeMap::from([("a.pyc".to_string(), 12)]);
        let record: RunRecord =
            RunRecord::for_batch(files, Duration::from_millis(20), clock(4), "9.9.9");
        let written: serde_json::Value = serde_json::to_value(&record).expect("serialize");
        assert_eq!(written["files"], serde_json::json!({ "a.pyc": 12 }));
        assert_eq!(written["jobs"], 4);
        assert_eq!(written["total_ms"], 20);
        assert!(written.get("nodes").is_none());
        let parsed: RunRecord = serde_json::from_value(written).expect("round trip");
        assert_eq!(parsed, record);
    }
}
