#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_dataforensics::capture::{CaptureFormat, CaptureOptions, CaptureReport, inspect};
use disrobe_tool_process::{CommandSpec, Completion, Execution};
use serde_json::Value;

struct Generated {
    dir: ScratchDir,
    truth: Value,
}

fn exited_cleanly(execution: &Execution) -> bool {
    matches!(execution.completion, Completion::Exited(status) if status.success())
}

fn python() -> String {
    let probe = |candidate: &str| -> bool {
        CommandSpec::new(candidate, Duration::from_secs(30))
            .args(["-c", "import zipfile, gzip"])
            .run()
            .is_ok_and(|execution: Execution| exited_cleanly(&execution))
    };
    if let Ok(explicit) = std::env::var("DISROBE_PYTHON")
        && probe(&explicit)
    {
        return explicit;
    }
    let found: Option<&str> = ["python", "python3", "py"]
        .into_iter()
        .find(|candidate: &&str| probe(candidate));
    found.map_or_else(
        || panic!("the capture grader needs CPython 3 to write its reference captures; point DISROBE_PYTHON at one"),
        str::to_owned,
    )
}

fn generated() -> &'static Generated {
    static GENERATED: OnceLock<Generated> = OnceLock::new();
    GENERATED.get_or_init(|| {
        let dir: ScratchDir = ScratchDir::create("capture-reference").expect("scratch");
        let script: PathBuf =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/make_captures.py");
        let execution: Execution = CommandSpec::new(python(), Duration::from_mins(2))
            .arg(script.as_os_str())
            .arg(dir.path().as_os_str())
            .run()
            .expect("run the capture generator");
        assert!(
            exited_cleanly(&execution),
            "generator failed: {execution:?}"
        );
        let truth: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("truth.json")).expect("truth"))
                .expect("truth JSON");
        Generated { dir, truth }
    })
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(generated().dir.path().join(name)).expect("generated capture")
}

fn inspect_with_bodies(bytes: &[u8]) -> CaptureReport {
    inspect(
        bytes,
        &CaptureOptions {
            keep_bodies: true,
            ..CaptureOptions::default()
        },
    )
    .expect("capture parses")
}

fn check_packets(name: &str, report: &CaptureReport, with_v6: bool) {
    let truth: &Value = &generated().truth;
    let queries: BTreeSet<String> = report
        .dns
        .iter()
        .flat_map(|event| event.message.questions.iter().map(|q| q.name.clone()))
        .collect();
    for query in truth["dns_queries"].as_array().expect("queries") {
        let query: &str = query.as_str().expect("query");
        if query.starts_with("v6.") && !with_v6 {
            continue;
        }
        assert!(
            queries.contains(query),
            "{name}: DNS query {query} missing from {queries:?}"
        );
    }
    let answers: Vec<(String, u16, String)> = report
        .dns
        .iter()
        .flat_map(|event| {
            event
                .message
                .answers
                .iter()
                .map(|a| (a.name.clone(), a.rtype, a.data.clone()))
        })
        .collect();
    for answer in truth["dns_answers"].as_array().expect("answers") {
        let want: (String, u16, String) = (
            answer[0].as_str().expect("name").to_owned(),
            u16::try_from(answer[1].as_u64().expect("type")).expect("type"),
            answer[2].as_str().expect("data").to_owned(),
        );
        assert!(
            answers.contains(&want),
            "{name}: DNS answer {want:?} missing from {answers:?}"
        );
    }
    let http_truth: &Vec<Value> = truth["http"].as_array().expect("http");
    assert_eq!(
        report.http.len(),
        http_truth.len(),
        "{name}: {:?}",
        report.http
    );
    for (index, (exchange, want)) in report.http.iter().zip(http_truth).enumerate() {
        assert_eq!(
            exchange.method,
            want["method"].as_str().expect("method"),
            "{name}"
        );
        assert_eq!(
            exchange.target,
            want["target"].as_str().expect("target"),
            "{name}"
        );
        assert_eq!(exchange.host.as_deref(), want["host"].as_str(), "{name}");
        assert_eq!(
            exchange.status.map(u64::from),
            want["status"].as_u64(),
            "{name}"
        );
        assert_eq!(
            exchange.content_type.as_deref(),
            want["content_type"].as_str(),
            "{name}"
        );
        assert!(
            exchange.response_body_complete,
            "{name}: exchange {index} body incomplete"
        );
        let body = report
            .bodies
            .iter()
            .find(|body| body.exchange == index)
            .unwrap_or_else(|| panic!("{name}: no body for exchange {index}"));
        assert_eq!(
            String::from_utf8_lossy(&body.bytes),
            want["body"].as_str().expect("body"),
            "{name}: body of exchange {index}"
        );
    }
    let tls: &Value = &truth["tls"];
    assert_eq!(report.tls.len(), 1, "{name}: {:?}", report.tls);
    let hello = &report.tls[0].hello;
    assert_eq!(hello.sni.as_deref(), tls["sni"].as_str(), "{name}");
    assert_eq!(
        serde_json::to_value(&hello.alpn).expect("alpn"),
        tls["alpn"],
        "{name}"
    );
    assert_eq!(hello.ja3, tls["ja3"].as_str().expect("ja3"), "{name}");
    assert_eq!(
        hello.ja3_md5,
        tls["ja3_md5"].as_str().expect("md5"),
        "{name}"
    );
    assert_eq!(
        serde_json::to_value(&hello.supported_versions).expect("versions"),
        tls["supported_versions"],
        "{name}"
    );
    let tcp_flows: Vec<_> = report
        .flows
        .iter()
        .filter(|flow| flow.protocol == "tcp")
        .collect();
    assert_eq!(
        tcp_flows.len() as u64,
        truth["tcp_flows"].as_u64().expect("flows"),
        "{name}"
    );
    assert!(
        tcp_flows.iter().all(|flow| flow.stream_complete),
        "{name}: {tcp_flows:?}"
    );
    assert_eq!(
        report.protocols.get("ip-fragment").copied(),
        truth["fragments"].as_u64(),
        "{name}"
    );
    assert_eq!(report.protocols.get("icmp").copied(), Some(1), "{name}");
}

#[test]
fn pcap_and_pcapng_decode_to_the_written_ground_truth() {
    for (name, format, with_v6) in [
        ("capture.pcap", CaptureFormat::Pcap, true),
        ("capture-be.pcap", CaptureFormat::Pcap, true),
        ("capture-raw.pcap", CaptureFormat::Pcap, false),
        ("capture.pcapng", CaptureFormat::Pcapng, true),
    ] {
        let report: CaptureReport = inspect_with_bodies(&read(name));
        assert_eq!(report.format, format, "{name}");
        assert!(report.problems.is_empty(), "{name}: {:?}", report.problems);
        check_packets(name, &report, with_v6);
    }
}

#[test]
fn har_and_saz_sessions_list_their_exchanges() {
    let truth: &Value = &generated().truth;
    for (name, format, key) in [
        ("session.har", CaptureFormat::Har, "har"),
        ("session.saz", CaptureFormat::Saz, "saz"),
    ] {
        let report: CaptureReport = inspect_with_bodies(&read(name));
        assert_eq!(report.format, format, "{name}");
        let got: Vec<(String, String, Option<u16>)> = report
            .http
            .iter()
            .map(|exchange| {
                (
                    exchange.method.clone(),
                    exchange.target.clone(),
                    exchange.status,
                )
            })
            .collect();
        let want: Vec<(String, String, Option<u16>)> = truth[key]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry: &Value| {
                (
                    entry[0].as_str().expect("method").to_owned(),
                    entry[1].as_str().expect("url").to_owned(),
                    entry[2]
                        .as_u64()
                        .and_then(|code: u64| u16::try_from(code).ok()),
                )
            })
            .collect();
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn a_corrupted_hello_and_a_lost_segment_are_noticed() {
    let mut bytes: Vec<u8> = read("capture.pcap");
    let sni: &[u8] = b"secure.example.org";
    let at: usize = bytes
        .windows(sni.len())
        .position(|w: &[u8]| w == sni)
        .expect("SNI on the wire");
    bytes[at - 1] = 0xff;
    let report: CaptureReport = inspect_with_bodies(&bytes);
    assert!(
        report
            .tls
            .first()
            .is_none_or(|tls| tls.hello.sni.as_deref() != Some("secure.example.org")),
        "a broken SNI length must not yield the original name"
    );
    let full: Vec<u8> = read("capture-raw.pcap");
    let marker: &[u8] = b"POST /submit";
    let post: usize = full
        .windows(marker.len())
        .position(|w: &[u8]| w == marker)
        .expect("request bytes");
    let mut lossy: Vec<u8> = full;
    for byte in &mut lossy[post..post + 12] {
        *byte = b'#';
    }
    let report: CaptureReport = inspect_with_bodies(&lossy);
    assert!(
        report.http.len() < 2,
        "a damaged request must not parse as the original: {:?}",
        report.http
    );
}

#[test]
fn hostile_captures_never_panic() {
    let base: Vec<u8> = read("capture.pcapng");
    let mut seed: u64 = 0x0bad_cafe_1234_5678;
    for round in 0..500 {
        let mut bytes: Vec<u8> = base.clone();
        for _ in 0..6 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let at: usize = (seed as usize) % bytes.len();
            bytes[at] = (seed >> 24) as u8;
        }
        if round % 7 == 0 {
            bytes.truncate((seed as usize) % bytes.len());
        }
        let _ = inspect(&bytes, &CaptureOptions::default());
    }
    assert!(inspect(b"plain text", &CaptureOptions::default()).is_err());
}
