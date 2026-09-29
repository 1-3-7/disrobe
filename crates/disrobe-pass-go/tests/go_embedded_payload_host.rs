#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, analyze};

const PAYLOAD_MAIN: &str = r#"package main

import "fmt"

//go:noinline
func payloadMarker() int { return 41 }

func main() { fmt.Println(payloadMarker()) }
"#;

const HOST_MAIN: &str = r#"package main

import (
	_ "embed"
	"fmt"
)

//go:embed payload.bin
var payload []byte

//go:noinline
func hostMarker() int { return len(payload) }

func main() { fmt.Println(hostMarker()) }
"#;

#[test]
fn a_go_host_embedding_another_go_binary_reports_its_own_pclntab() {
    assert!(
        common::go_on_path(),
        "missing prerequisite: the Go toolchain (go on PATH, go1.26.3 in CI) builds this regression"
    );
    let payload_dir: common::GoBuildScratch = common::new_scratch("embedded_payload");
    common::write_module(&payload_dir, "example.com/payload", PAYLOAD_MAIN);
    let payload: PathBuf =
        common::go_build_cross_required(&payload_dir, "payload.exe", "windows", "amd64", &[])
            .unwrap_or_else(|error: String| panic!("{error}"));

    let host_dir: common::GoBuildScratch = common::new_scratch("embedding_host");
    common::write_module(&host_dir, "example.com/host", HOST_MAIN);
    std::fs::copy(&payload, host_dir.path().join("payload.bin")).expect("stage the payload");
    let host: PathBuf =
        common::go_build_cross_required(&host_dir, "host.exe", "windows", "amd64", &[])
            .unwrap_or_else(|error: String| panic!("{error}"));

    let bytes: Vec<u8> = std::fs::read(&host).expect("read the host build");
    let analysis: GoAnalysis = analyze(&bytes).expect("the host parses as Go");
    let names: BTreeSet<String> = common::recovered_function_names(&analysis);
    assert!(
        names.contains("main.hostMarker"),
        "the host's own functions must be recovered"
    );
    assert!(
        !names.contains("main.payloadMarker"),
        "the embedded payload's pclntab was reported instead of the host's"
    );
}
