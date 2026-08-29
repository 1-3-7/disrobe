#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, wait_with_output_timeout};
use disrobe_pass_go::defers::{ControlEdge, ControlEdgeKind};
use disrobe_pass_go::{DeferCallKind, GoAnalysis, RuntimeDeferCall, analyze};

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
#[cfg(feature = "chain")]
use disrobe_pass_go::chain_detector::GO_PASS;

const SOURCE: &str = r#"package main

import "fmt"

var sink int

__GO_NOINLINE__
func ExplicitPanic(value int) {
	if value < 0 {
		panic(value)
	}
}

__GO_NOINLINE__
func BoundsPanic(values []int, index int) int {
	return values[index]
}

__GO_NOINLINE__
func TypePanic(value any) string {
	return value.(string)
}

__GO_NOINLINE__
func DirectRecover(value int) (result int) {
	defer func() {
		if recover() != nil {
			result = -1
		}
	}()
	ExplicitPanic(value)
	return value
}

__GO_NOINLINE__
func Sequence(limit int) func(func(int) bool) {
	return func(yield func(int) bool) {
		for value := 0; value < limit; value++ {
			if !yield(value) {
				return
			}
		}
	}
}

__GO_NOINLINE__
func RangeDefer(limit int) int {
	for value := range Sequence(limit) {
		defer func() { sink += value }()
	}
	return sink
}

__GO_NOINLINE__
func OrdinaryRuntimeCall(size int) []byte {
	return make([]byte, size)
}

func main() {
	defer func() { _ = recover() }()
	fmt.Println(DirectRecover(-1), BoundsPanic([]int{1}, 0), TypePanic("ok"))
	fmt.Println(RangeDefer(2), len(OrdinaryRuntimeCall(3)))
}
"#;

const TOOL_TIMEOUT: Duration = Duration::from_mins(2);
const TOOL_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ToolchainCall {
    function: String,
    kind: ControlEdgeKind,
    va: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ToolchainDeferCall {
    function: String,
    kind: DeferCallKind,
    va: u64,
}

fn parse_va(field: &str) -> Option<u64> {
    u64::from_str_radix(field.trim_start_matches("0x"), 16).ok()
}

fn control_kind(target: &str) -> Option<ControlEdgeKind> {
    match target {
        "runtime.gopanic" => Some(ControlEdgeKind::Panic),
        "runtime.gorecover" => Some(ControlEdgeKind::Recover),
        name if name
            .strip_prefix("runtime.panic")
            .is_some_and(|suffix: &str| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'_')
            }) =>
        {
            Some(ControlEdgeKind::Panic)
        }
        name if name
            .strip_prefix("runtime.goPanic")
            .is_some_and(|suffix: &str| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'_')
            }) =>
        {
            Some(ControlEdgeKind::Panic)
        }
        _ => None,
    }
}

fn checked_output(command: &mut Command, label: &str) -> CapturedOutput {
    let command_line: String = format!("{command:?}");
    let child: Child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("{label} could not start: {command_line}: {error}")
        });
    let output: CapturedOutput = wait_with_output_timeout(child, TOOL_TIMEOUT, TOOL_CAPTURE_BYTES)
        .unwrap_or_else(|| {
            panic!(
                "{label} timed out after {} seconds: {command_line}; status=<timeout>; stdout=<unavailable>; stderr=<unavailable>",
                TOOL_TIMEOUT.as_secs()
            )
        });
    assert_eq!(
        output.exit_code,
        Some(0),
        "{label} failed: {command_line}; status={:?}; stdout={}; stderr={}",
        output.exit_code,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn build_fixture(scratch: &common::GoBuildScratch) -> std::path::PathBuf {
    let binary: std::path::PathBuf = scratch.path().join("panic_edges.exe");
    let mut command: Command = Command::new("go");
    command
        .current_dir(scratch.path())
        .env("GOOS", "windows")
        .env("GOARCH", "amd64")
        .env("CGO_ENABLED", "0")
        .env("GO111MODULE", "on")
        .args(["build", "-trimpath", "-o"])
        .arg(&binary)
        .arg(".");
    let _: CapturedOutput = checked_output(&mut command, "go build panic fixture");
    binary
}

fn toolchain_calls(binary: &Path) -> (BTreeSet<ToolchainCall>, BTreeSet<ToolchainDeferCall>) {
    let mut command: Command = Command::new("go");
    command
        .args(["tool", "objdump", "-s", "^main\\."])
        .arg(binary);
    let output: CapturedOutput = checked_output(&mut command, "go tool objdump panic fixture");
    let text: String = String::from_utf8(output.stdout).expect("go objdump UTF-8");
    let mut function: Option<String> = None;
    let mut controls: BTreeSet<ToolchainCall> = BTreeSet::new();
    let mut range_defers: BTreeSet<ToolchainDeferCall> = BTreeSet::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() == Some(&"TEXT") {
            function = fields
                .get(1)
                .and_then(|name: &&str| name.strip_suffix("(SB)"))
                .map(str::to_owned);
            continue;
        }
        let Some(call_index): Option<usize> =
            fields.iter().position(|field: &&str| *field == "CALL")
        else {
            continue;
        };
        let Some(target): Option<&str> = fields
            .get(call_index + 1)
            .and_then(|field: &&str| field.strip_suffix("(SB)"))
        else {
            continue;
        };
        let Some(va): Option<u64> = fields.iter().find_map(|field: &&str| parse_va(field)) else {
            continue;
        };
        let Some(owner): Option<&String> = function.as_ref() else {
            continue;
        };
        if let Some(kind) = control_kind(target) {
            controls.insert(ToolchainCall {
                function: owner.clone(),
                kind,
                va,
            });
        }
        let defer_kind: Option<DeferCallKind> = match target {
            "runtime.deferrangefunc" => Some(DeferCallKind::RangeFunc),
            "runtime.deferprocat" => Some(DeferCallKind::ProcAt),
            _ => None,
        };
        if let Some(kind) = defer_kind {
            range_defers.insert(ToolchainDeferCall {
                function: owner.clone(),
                kind,
                va,
            });
        }
    }
    (controls, range_defers)
}

#[test]
fn current_go_runtime_edges_reach_the_registered_report_and_sidecar() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("panic_edges");
    let source: String = SOURCE.replace("__GO_NOINLINE__", "//go:noinline");
    common::write_module(&scratch, "disrobe.example/panicedges", &source);
    let binary: std::path::PathBuf = build_fixture(&scratch);
    let (expected_controls, expected_range_defers): (
        BTreeSet<ToolchainCall>,
        BTreeSet<ToolchainDeferCall>,
    ) = toolchain_calls(&binary);
    assert!(
        expected_controls
            .iter()
            .any(|call: &ToolchainCall| call.function == "main.ExplicitPanic"),
        "current toolchain emitted no explicit panic call"
    );
    assert!(
        expected_controls
            .iter()
            .any(|call: &ToolchainCall| call.function == "main.BoundsPanic"),
        "current toolchain emitted no bounds panic-family call"
    );
    assert!(
        expected_controls
            .iter()
            .any(|call: &ToolchainCall| call.function == "main.TypePanic"),
        "current toolchain emitted no type-assertion panic-family call"
    );
    assert!(
        expected_controls
            .iter()
            .any(|call: &ToolchainCall| call.kind == ControlEdgeKind::Recover),
        "current toolchain emitted no recover call"
    );
    assert_eq!(
        expected_range_defers
            .iter()
            .filter(|call: &&ToolchainDeferCall| call.kind == DeferCallKind::RangeFunc)
            .count(),
        1,
        "current toolchain must emit one runtime.deferrangefunc call"
    );
    assert_eq!(
        expected_range_defers
            .iter()
            .filter(|call: &&ToolchainDeferCall| call.kind == DeferCallKind::ProcAt)
            .count(),
        1,
        "current toolchain must emit one runtime.deferprocat call"
    );

    let bytes: Vec<u8> = std::fs::read(&binary).expect("read current Go panic fixture");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze current Go panic fixture");
    let actual_controls: BTreeSet<ToolchainCall> = analysis
        .defers
        .control_edges
        .iter()
        .filter(|edge: &&ControlEdge| edge.function.starts_with("main."))
        .map(|edge: &ControlEdge| ToolchainCall {
            function: edge.function.clone(),
            kind: edge.kind,
            va: edge.va,
        })
        .collect();
    assert_eq!(actual_controls, expected_controls);
    assert!(
        actual_controls
            .iter()
            .all(|edge: &ToolchainCall| edge.function != "main.OrdinaryRuntimeCall"),
        "an ordinary runtime allocation call was misclassified as a panic/recover edge"
    );
    let actual_range_defers: BTreeSet<ToolchainDeferCall> = analysis
        .defers
        .runtime_calls
        .iter()
        .filter(|call: &&RuntimeDeferCall| {
            matches!(call.kind, DeferCallKind::RangeFunc | DeferCallKind::ProcAt)
                && call.function.starts_with("main.")
        })
        .map(|call: &RuntimeDeferCall| ToolchainDeferCall {
            function: call.function.clone(),
            kind: call.kind,
            va: call.va,
        })
        .collect();
    assert_eq!(actual_range_defers, expected_range_defers);

    #[cfg(feature = "chain")]
    {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let rendered: Artifact = GO_PASS.run(&artifact).expect("registered Go pass run");
        let report: &str = std::str::from_utf8(&rendered.envelope).expect("Go report UTF-8");
        assert!(report.contains("panic edge main.BoundsPanic @ 0x"));
        assert!(report.contains("recover edge main.DirectRecover.func1 @ 0x"));
        assert!(report.contains("defer call deferrangefunc main.RangeDefer @ 0x"));
        assert!(report.contains("defer call deferprocat main.RangeDefer-range1 @ 0x"));
        let children: Vec<disrobe_core::chain::ChildArtifact> = GO_PASS
            .extract_children(&artifact)
            .expect("registered Go pass children");
        let sidecar: &disrobe_core::chain::ChildArtifact = children
            .iter()
            .find(|child: &&disrobe_core::chain::ChildArtifact| {
                child.handle.relative_path == "go-analysis.json"
            })
            .expect("registered Go pass analysis sidecar");
        let sidecar_analysis: GoAnalysis =
            serde_json::from_slice(&sidecar.bytes).expect("Go analysis sidecar JSON");
        assert_eq!(
            sidecar_analysis.defers.control_edges,
            analysis.defers.control_edges
        );
        assert_eq!(
            sidecar_analysis.defers.runtime_calls,
            analysis.defers.runtime_calls
        );
    }
}
