use std::collections::BTreeSet;

use serde_json::Value;

use crate::filter::host_of;

#[must_use]
pub fn normalize_target(raw: &str) -> Option<String> {
    let line: &str = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if line.contains("://") {
        return host_of(line);
    }
    let pathless: &str = line.split('/').next().map_or(line, |value: &str| value);
    let authority: &str = pathless
        .rsplit('@')
        .next()
        .map_or(line, |value: &str| value);
    let host: &str = authority
        .split(':')
        .next()
        .map_or(line, |value: &str| value);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[must_use]
pub fn parse_target_lines(text: &str) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        push_target(line, &mut seen, &mut out);
    }
    out
}

#[must_use]
fn finding_is_url_or_ip(category: Option<&str>) -> bool {
    matches!(category, Some("url" | "ipv4" | "ipv6" | "domain"))
}

#[must_use]
pub fn targets_from_disrobe_report(json: &str) -> Vec<String> {
    let Ok(value): Result<Value, _> = serde_json::from_str(json) else {
        return Vec::new();
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();

    if let Some(findings) = value.get("findings").and_then(Value::as_array) {
        for f in findings {
            if finding_is_url_or_ip(f.get("category").and_then(Value::as_str))
                && let Some(v) = f.get("value").and_then(Value::as_str)
            {
                push_target(v, &mut seen, &mut out);
            }
        }
    }
    if let Some(indicators) = value.get("indicators").and_then(Value::as_array) {
        for ind in indicators {
            let kind: Option<&str> = ind.get("kind").and_then(Value::as_str);
            if matches!(kind, Some("url" | "domain" | "ipv4" | "ipv6"))
                && let Some(v) = ind.get("value").and_then(Value::as_str)
            {
                push_target(v, &mut seen, &mut out);
            }
        }
    }
    out
}

fn push_target(raw: &str, seen: &mut BTreeSet<String>, out: &mut Vec<String>) {
    if let Some(target) = normalize_target(raw)
        && seen.insert(target.clone())
    {
        out.push(target);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_scheme_and_path() {
        assert_eq!(
            normalize_target("https://api.example.com/login?x=1").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            normalize_target("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_target("Example.COM/path").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_target("  # comment").as_deref(), None);
        assert_eq!(normalize_target("   ").as_deref(), None);
    }

    #[test]
    fn target_lines_dedup_preserve_order() {
        let text: &str = "example.com\n# note\nhttps://example.com/x\napi.example.com\n";
        let targets: Vec<String> = parse_target_lines(text);
        assert_eq!(targets, vec!["example.com", "api.example.com"]);
    }

    #[test]
    fn recon_report_yields_url_and_ip_targets() {
        let json: &str = r#"{
            "schema":"disrobe.recon/v0",
            "findings":[
                {"category":"url","value":"https://recon.example/a","line":1,"column":1,"offset":0,"severity":"low","rule_id":"r1"},
                {"category":"ipv4","value":"198.51.100.9","line":1,"column":1,"offset":0,"severity":"low","rule_id":"r2"},
                {"category":"secret","value":"AKIAXXXX","line":1,"column":1,"offset":0,"severity":"high","rule_id":"r3"}
            ]
        }"#;
        let targets: Vec<String> = targets_from_disrobe_report(json);
        assert_eq!(targets, vec!["recon.example", "198.51.100.9"]);
    }

    #[test]
    fn ioc_report_yields_targets() {
        let json: &str = r#"{
            "schema":"disrobe.ioc/v0",
            "indicators":[
                {"kind":"domain","value":"c2.example","offset":0,"encoding":"plain"},
                {"kind":"ipv4","value":"203.0.113.5","offset":0,"encoding":"plain"},
                {"kind":"bitcoin_address","value":"1abc","offset":0,"encoding":"plain"}
            ]
        }"#;
        let targets: Vec<String> = targets_from_disrobe_report(json);
        assert_eq!(targets, vec!["c2.example", "203.0.113.5"]);
    }
}
