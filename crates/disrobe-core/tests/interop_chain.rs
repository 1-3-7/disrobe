#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;

use disrobe_core::interop::{
    self, ArtifactSchema, IndicatorAggregator, IndicatorBundle, IndicatorClass, UnifiedIndicator,
};
use disrobe_core::ioc::{self, IocReport};
use disrobe_core::recon::{self, ReconConfig, ReconReport};

const PLANTED_URL: &str = "http://c2.planted-fixture.test/gate.php";
const PLANTED_IPV4: &str = "203.0.113.77";
const PLANTED_DOMAIN: &str = "drop.planted-fixture.dev";
const PLANTED_EMAIL: &str = "operator@planted-fixture.dev";

fn planted_blob() -> Vec<u8> {
    format!(
        "beacon {PLANTED_URL} fallback {PLANTED_IPV4} mirror {PLANTED_DOMAIN} contact {PLANTED_EMAIL}\n"
    )
    .into_bytes()
}

fn recon_json(blob: &[u8]) -> (ReconReport, String) {
    let report: ReconReport =
        recon::report_bytes(blob, Some("fixture.bin"), &ReconConfig::default());
    let json: String = serde_json::to_string(&report).expect("serialize recon report");
    (report, json)
}

fn ioc_json(blob: &[u8]) -> (IocReport, String) {
    let report: IocReport = ioc::report(blob, Some("fixture.bin"));
    let json: String = serde_json::to_string(&report).expect("serialize ioc report");
    (report, json)
}

fn values_of(bundle: &IndicatorBundle, class: IndicatorClass) -> BTreeSet<String> {
    bundle
        .indicators
        .iter()
        .filter(|i: &&UnifiedIndicator| i.class == class)
        .map(|i: &UnifiedIndicator| i.value.clone())
        .collect()
}

#[test]
fn recon_and_ioc_artifacts_flow_into_indicator_bundle() {
    let blob: Vec<u8> = planted_blob();
    let (recon_report, recon): (ReconReport, String) = recon_json(&blob);
    let (ioc_report, ioc): (IocReport, String) = ioc_json(&blob);

    assert!(recon_report.total > 0, "recon must emit findings");
    assert!(ioc_report.total > 0, "ioc must emit indicators");

    let mut agg: IndicatorAggregator = IndicatorAggregator::new();
    assert_eq!(agg.ingest_json(&recon), Some(ArtifactSchema::Recon));
    assert_eq!(agg.ingest_json(&ioc), Some(ArtifactSchema::Ioc));
    let bundle: IndicatorBundle = agg.finish();

    let urls: BTreeSet<String> = values_of(&bundle, IndicatorClass::Url);
    assert!(
        urls.contains(PLANTED_URL),
        "planted url lost crossing the feature boundary: {urls:?}"
    );
    let ips: BTreeSet<String> = values_of(&bundle, IndicatorClass::Ipv4);
    assert!(
        ips.contains(PLANTED_IPV4),
        "planted ipv4 lost crossing the feature boundary: {ips:?}"
    );
    let domains: BTreeSet<String> = values_of(&bundle, IndicatorClass::Domain);
    assert!(
        domains.contains(PLANTED_DOMAIN),
        "planted domain lost crossing the feature boundary: {domains:?}"
    );
    let emails: BTreeSet<String> = values_of(&bundle, IndicatorClass::Email);
    assert!(
        emails.contains(PLANTED_EMAIL),
        "planted email lost crossing the feature boundary: {emails:?}"
    );

    assert_eq!(bundle.ingested, vec!["ioc", "recon"]);
}

#[test]
fn shared_indicator_carries_both_source_provenances() {
    let blob: Vec<u8> = planted_blob();
    let (_recon_report, recon): (ReconReport, String) = recon_json(&blob);
    let (_ioc_report, ioc): (IocReport, String) = ioc_json(&blob);

    let bundle: IndicatorBundle = interop::aggregate(&[&recon, &ioc]);
    let ip: &UnifiedIndicator = bundle
        .indicators
        .iter()
        .find(|i: &&UnifiedIndicator| i.value == PLANTED_IPV4)
        .expect("planted ip present after aggregation");
    assert!(
        ip.sources.contains(&"recon".to_owned()) && ip.sources.contains(&"ioc".to_owned()),
        "shared ipv4 must record both producing features: {:?}",
        ip.sources
    );
}

#[test]
fn aggregated_network_values_match_prowl_target_contract() {
    let blob: Vec<u8> = planted_blob();
    let (_r, recon): (ReconReport, String) = recon_json(&blob);
    let (_i, ioc): (IocReport, String) = ioc_json(&blob);

    let mut agg: IndicatorAggregator = IndicatorAggregator::new();
    agg.ingest_json(&recon).expect("recon");
    agg.ingest_json(&ioc).expect("ioc");
    let networks: Vec<String> = agg.network_values();

    for planted in [PLANTED_URL, PLANTED_IPV4, PLANTED_DOMAIN, PLANTED_EMAIL] {
        assert!(
            networks.iter().any(|n: &String| n == planted),
            "network re-seed value `{planted}` missing from {networks:?}"
        );
    }
    assert!(
        !networks.iter().any(|n: &String| n.starts_with("DR-")),
        "secrets must not leak into the re-seed target list: {networks:?}"
    );
}

#[test]
fn prowl_report_indicators_aggregate_back_into_bundle() {
    let prowl: &str = r#"{
        "schema":"disrobe.prowl/v0",
        "targets":["planted-fixture.dev"],
        "sources":["wayback","otx"],
        "url_total":1,"ioc_total":2,
        "urls":[{"url":"http://c2.planted-fixture.test/gate.php","source":"wayback"}],
        "iocs":[
            {"kind":"subdomain","value":"drop.planted-fixture.dev","source":"otx"},
            {"kind":"sha256","value":"deadbeefdeadbeefdeadbeefdeadbeef","source":"otx"}
        ]
    }"#;
    let blob: Vec<u8> = planted_blob();
    let (_r, recon): (ReconReport, String) = recon_json(&blob);

    let bundle: IndicatorBundle = interop::aggregate(&[&recon, prowl]);
    assert_eq!(bundle.ingested, vec!["prowl", "recon"]);

    let url: &UnifiedIndicator = bundle
        .indicators
        .iter()
        .find(|i: &&UnifiedIndicator| i.value == PLANTED_URL)
        .expect("url crosses recon+prowl boundary");
    assert!(
        url.sources.contains(&"recon".to_owned()) && url.sources.contains(&"prowl".to_owned()),
        "url found by both recon and prowl must merge provenances: {:?}",
        url.sources
    );
    assert!(
        bundle.indicators.iter().any(|i: &UnifiedIndicator| {
            i.class == IndicatorClass::Hash && i.value == "deadbeefdeadbeefdeadbeefdeadbeef"
        }),
        "prowl-only hash indicator missing from bundle"
    );
}
