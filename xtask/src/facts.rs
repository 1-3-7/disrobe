use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use eyre::{Result, bail};
use serde::Deserialize;

use crate::fileio::read_text_bounded;

const MAX_RECOVERY_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

const UNPINNED_BARS: [(&str, &str); 6] = [
    (
        "CPython 3.10 (161 of the pinned modules)",
        "the interpreter-band figures are measured by the python harness under each interpreter in \
         turn, and no crate holds a constant to compare them against",
    ),
    (
        "CPython 3.12 (177 of the pinned modules)",
        "same interpreter-band harness as the 3.10 bar",
    ),
    (
        "CPython 3.14 (all 200 pinned modules)",
        "same interpreter-band harness as the 3.10 bar",
    ),
    (
        "CPython 3.15 (199 of the pinned modules)",
        "same interpreter-band harness as the 3.10 bar",
    ),
    (
        "proven-correct (local, full period interpreter set)",
        "the local leg of a bar whose enforced figure is the 150 of 191 floor in the bar above it, \
         which is pinned",
    ),
    (
        "functions parsed",
        "the production Hermes bundle is not redistributable, so the count is asserted in a test \
         that cannot run without it",
    ),
];

const MEASUREMENTS_NOT_RUN: [(&str, &str); 1] = [(
    "full 574-module stdlib (representative)",
    "full_stdlib_recompile_equivalence_gate drives all 574 modules through the real CLI under a \
     CPython 3.14 interpreter and is marked #[ignore], and no workflow runs it. What CI re-derives \
     is the 115-module slice beside it, which carries its own floors and is a different population \
     from this figure. The figure itself stands on a local run of that gate, and the row that \
     publishes it is tagged [local] for exactly this reason",
)];

const UNGRADED_DELIVERED_LEGS: [(&str, &str); 0] = [];

#[derive(Debug, Deserialize)]
struct Recovery {
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize)]
struct Group {
    bars: Vec<Bar>,
}

#[derive(Debug, Deserialize)]
struct Bar {
    label: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    delivered: Option<u64>,
    #[serde(default)]
    verified_by: Option<VerifiedBy>,
}

#[derive(Debug, Deserialize)]
struct VerifiedBy {
    path: String,
    function: String,
    #[serde(default)]
    conditional: Option<String>,
    #[serde(default)]
    measured_by: Option<String>,
}

const CITABLE_ROOTS: [&str; 2] = ["crates/", "benches/"];

const DELIVERED_KEY: &str = "\"delivered\"";

const SKIP_SHAPES: [(&str, &str); 5] = [
    ("return ;", "a bare early return"),
    ("return;", "a bare early return"),
    ("is_none() {", "an is_none guard"),
    ("is_err() {", "an is_err guard"),
    (".exists() {", "a path-existence guard"),
];

fn cited_function_region<'a>(text: &'a str, function: &str) -> Option<&'a str> {
    let needle: String = format!("fn {function}");
    let at: usize = text.find(&needle)?;
    let open: usize = at + text.get(at..)?.find('{')?;
    let body: &str = text.get(open..)?;

    let bytes: &[u8] = body.as_bytes();
    let mut depth: usize = 0;
    let mut index: usize = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'r' => {
                let mut hashes: usize = 0;
                let mut probe: usize = index + 1;
                while bytes.get(probe) == Some(&b'#') {
                    hashes += 1;
                    probe += 1;
                }
                if bytes.get(probe) == Some(&b'"') {
                    index = skip_raw_string(bytes, probe + 1, hashes);
                } else {
                    index += 1;
                }
            }
            b'"' => index = skip_quoted(bytes, index + 1, b'"'),
            b'\'' if is_char_literal(bytes, index) => {
                index = skip_quoted(bytes, index + 1, b'\'');
            }
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return body.get(..index);
                }
            }
            _ => index += 1,
        }
    }
    None
}

fn is_char_literal(bytes: &[u8], at: usize) -> bool {
    if bytes.get(at + 1) == Some(&b'\\') {
        return true;
    }
    bytes.get(at + 2) == Some(&b'\'')
}

fn skip_quoted(bytes: &[u8], from: usize, terminator: u8) -> usize {
    let mut index: usize = from;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == terminator => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

fn skip_raw_string(bytes: &[u8], from: usize, hashes: usize) -> usize {
    let mut index: usize = from;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let closed: bool = (1..=hashes).all(|off: usize| bytes.get(index + off) == Some(&b'#'));
            if closed {
                return index + hashes + 1;
            }
        }
        index += 1;
    }
    bytes.len()
}

fn skip_shapes_in(region: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    for (pattern, description) in &SKIP_SHAPES {
        if region.contains(pattern) && !found.contains(description) {
            found.push(description);
        }
    }
    found
}

fn provenance_cites_documentation(source: &str) -> Option<String> {
    for token in source.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ';') {
        let trimmed: &str = token.trim_matches(|c: char| c == ',' || c == '`' || c == '"');
        let is_doc: bool = Path::new(trimmed).extension().is_some_and(|ext: &OsStr| {
            ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("mdx")
        });
        if is_doc {
            return Some(trimmed.to_owned());
        }
    }
    None
}

fn attribute_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut depth: usize = 1;
    let mut index: usize = from;
    while index < bytes.len() {
        match bytes[index] {
            b'r' => {
                let mut hashes: usize = 0;
                let mut probe: usize = index + 1;
                while bytes.get(probe) == Some(&b'#') {
                    hashes += 1;
                    probe += 1;
                }
                if bytes.get(probe) == Some(&b'"') {
                    index = skip_raw_string(bytes, probe + 1, hashes);
                } else {
                    index += 1;
                }
            }
            b'"' => index = skip_quoted(bytes, index + 1, b'"'),
            b'[' => {
                depth += 1;
                index += 1;
            }
            b']' => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => index += 1,
        }
    }
    None
}

fn attribute_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes: &[u8] = text.as_bytes();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut index: usize = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'r' => {
                let mut hashes: usize = 0;
                let mut probe: usize = index + 1;
                while bytes.get(probe) == Some(&b'#') {
                    hashes += 1;
                    probe += 1;
                }
                if bytes.get(probe) == Some(&b'"') {
                    index = skip_raw_string(bytes, probe + 1, hashes);
                } else {
                    index += 1;
                }
            }
            b'"' => index = skip_quoted(bytes, index + 1, b'"'),
            b'\'' if is_char_literal(bytes, index) => {
                index = skip_quoted(bytes, index + 1, b'\'');
            }
            b'#' => {
                let open: usize = if bytes.get(index + 1) == Some(&b'!') {
                    index + 2
                } else {
                    index + 1
                };
                match bytes.get(open) {
                    Some(&b'[') => match attribute_end(bytes, open + 1) {
                        Some(end) => {
                            spans.push((index, end));
                            index = end;
                        }
                        None => index += 1,
                    },
                    _ => index += 1,
                }
            }
            _ => index += 1,
        }
    }
    spans
}

fn function_is_ignored(text: &str, spans: &[(usize, usize)], at: usize) -> bool {
    let mut cursor: usize = at;
    loop {
        let Some(head): Option<&str> = text.get(..cursor) else {
            return false;
        };
        let boundary: usize = head.trim_end().len();
        let Some(&(start, end)): Option<&(usize, usize)> = spans
            .iter()
            .rev()
            .find(|(_, end): &&(usize, usize)| *end == boundary)
        else {
            return false;
        };
        if text
            .get(start..end)
            .is_some_and(|attribute: &str| attribute.starts_with("#[ignore"))
        {
            return true;
        }
        cursor = start;
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Signals {
    measurement_parked: bool,
    delivered_ungraded: bool,
}

fn verify_measurement(
    text: &str,
    spans: &[(usize, usize)],
    bar: &Bar,
    cited: &VerifiedBy,
    allowed: Allowlists<'_>,
    issues: &mut Vec<String>,
) -> bool {
    let label: &str = &bar.label;
    let rel: &str = &cited.path;
    let parked_here: Vec<&str> = spans
        .iter()
        .filter(|(start, end): &&(usize, usize)| {
            text.get(*start..*end)
                .is_some_and(|attribute: &str| attribute.starts_with("#[ignore"))
        })
        .filter_map(|(_, end): &(usize, usize)| {
            let rest: &str = text.get(*end..)?;
            let at: usize = rest.find("fn ")?;
            let name: &str = rest.get(at + 3..)?;
            name.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
        })
        .collect();

    let Some(measured): Option<&str> = cited.measured_by.as_deref() else {
        if !parked_here.is_empty() {
            issues.push(format!(
                "bar `{label}` cites `{rel}`, which parks {} behind #[ignore], and the bar names no \
                 `measured_by`. A file that carries a check nobody runs is exactly where a \
                 published figure goes to rest: name the function that re-derives this number in a \
                 `measured_by` field on this bar's verified_by, so a reader can tell whether the \
                 parked one is it",
                parked_here.join(" and ")
            ));
        }
        return false;
    };

    let needle: String = format!("fn {measured}");
    let Some(at): Option<usize> = text.find(&needle) else {
        issues.push(format!(
            "bar `{label}` names `{measured}` in `{rel}` as what re-derives it, but that function \
             is not there"
        ));
        return false;
    };
    if !function_is_ignored(text, spans, at) {
        return false;
    }
    if !excused(allowed.measurements_not_run, label) {
        issues.push(format!(
            "bar `{label}` names `{measured}` as the run that re-derives it, and that function is \
             marked #[ignore], so nothing measures this figure. Un-ignore it, point the bar at a \
             measurement that runs, or record the bar in MEASUREMENTS_NOT_RUN in \
             xtask/src/facts.rs with the reason, so the gap is named rather than counted beside a \
             pass"
        ));
    }
    true
}

fn verify_delivered_leg(
    region: &str,
    bar: &Bar,
    cited: &VerifiedBy,
    allowed: Allowlists<'_>,
    issues: &mut Vec<String>,
) -> bool {
    let Some(delivered): Option<u64> = bar.delivered else {
        return false;
    };
    if region.contains(DELIVERED_KEY) {
        return false;
    }
    if !excused(allowed.ungraded_delivered, &bar.label) {
        issues.push(format!(
            "bar `{}` publishes a delivered count of {delivered}, but `{}` never reads the \
             {DELIVERED_KEY} key; it grades the detected count and stops. Half a checked bar reads \
             as a whole one, and naming the other leg in a message is not grading it: assert the \
             delivered count too, or record the bar in UNGRADED_DELIVERED_LEGS in \
             xtask/src/facts.rs with the reason no declaration collects it",
            bar.label, cited.function
        ));
    }
    true
}

fn verify_citation(
    root: &Path,
    bar: &Bar,
    cited: &VerifiedBy,
    allowed: Allowlists<'_>,
    issues: &mut Vec<String>,
) -> Signals {
    let mut signals: Signals = Signals::default();
    let label: &str = &bar.label;
    let rel: &str = &cited.path;

    if !CITABLE_ROOTS
        .iter()
        .any(|root: &&str| rel.starts_with(root))
    {
        issues.push(format!(
            "bar `{label}` is verified by `{rel}`, which is under none of {CITABLE_ROOTS:?}; a claim \
             must be checked by code the workspace builds, never by a document or a generated \
             artifact"
        ));
        return signals;
    }
    if !(rel.contains("/src/") || rel.contains("/tests/")) {
        issues.push(format!(
            "bar `{label}` cites `{rel}`, which is neither a src nor a tests path"
        ));
        return signals;
    }

    let absolute: PathBuf = root.join(rel);
    if !absolute.is_file() {
        issues.push(format!(
            "bar `{label}` cites `{rel}`, which does not exist; a citation that points at a moved \
             or renamed file proves nothing and is exactly how a stale number survives"
        ));
        return signals;
    }

    let text: String = match read_text_bounded(&absolute, MAX_SOURCE_BYTES) {
        Ok(text) => text,
        Err(error) => {
            issues.push(format!(
                "bar `{label}` cites `{rel}`, which could not be read: {error}"
            ));
            return signals;
        }
    };

    let needle: String = format!("fn {}", cited.function);
    let Some(at): Option<usize> = text.find(&needle) else {
        issues.push(format!(
            "bar `{label}` cites `{}` in `{rel}`, but that function is not there; the test was \
             renamed or removed while the number stayed",
            cited.function
        ));
        return signals;
    };

    let spans: Vec<(usize, usize)> = attribute_spans(&text);
    if function_is_ignored(&text, &spans, at) {
        issues.push(format!(
            "bar `{label}` is verified by `{}`, which is marked #[ignore]; a check that never runs \
             cannot fail",
            cited.function
        ));
    }

    if !text.contains(label) {
        issues.push(format!(
            "bar `{label}` cites `{}` in `{rel}`, but that file never names the bar it verifies, \
             so the citation is decorative and nothing ties the assertion to this claim",
            cited.function
        ));
    }

    let Some(region): Option<&str> = cited_function_region(&text, &cited.function) else {
        issues.push(format!(
            "bar `{label}` cites `{}` in `{rel}`, but its body could not be delimited, so this gate \
             cannot tell whether the check runs; treat that as a failure rather than a pass",
            cited.function
        ));
        return signals;
    };

    signals.measurement_parked = verify_measurement(&text, &spans, bar, cited, allowed, issues);
    signals.delivered_ungraded = verify_delivered_leg(region, bar, cited, allowed, issues);

    let shapes: Vec<&'static str> = skip_shapes_in(region);
    if !shapes.is_empty() && cited.conditional.is_none() {
        issues.push(format!(
            "bar `{label}` is verified by `{}`, whose body carries {}. A citation shaped like that \
             can grade nothing, or grade a smaller population than the published figure describes, \
             and still report success, so counting it as proof overstates what is checked. Either \
             make the absent input fatal the way enforce_fixture_requirement already does, or state \
             why enforcement is conditional in a `conditional` field on this bar's verified_by so \
             the weakness is declared and countable instead of invisible",
            cited.function,
            shapes.join(" and ")
        ));
    }
    signals
}

#[derive(Debug, Default)]
struct Provenance {
    issues: Vec<String>,
    verified: usize,
    conditional: usize,
    total: usize,
    unpinned: usize,
    measured: usize,
}

#[derive(Debug, Clone, Copy)]
struct Allowlists<'a> {
    unpinned: &'a [(&'a str, &'a str)],
    measurements_not_run: &'a [(&'a str, &'a str)],
    ungraded_delivered: &'a [(&'a str, &'a str)],
}

const LIVE: Allowlists<'static> = Allowlists {
    unpinned: &UNPINNED_BARS,
    measurements_not_run: &MEASUREMENTS_NOT_RUN,
    ungraded_delivered: &UNGRADED_DELIVERED_LEGS,
};

fn excused(allowed: &[(&str, &str)], label: &str) -> bool {
    allowed
        .iter()
        .any(|(excused, _): &(&str, &str)| *excused == label)
}

fn stale_entries(allowed: &[(&str, &str)], claimed: &[&str], list: &str) -> Vec<String> {
    allowed
        .iter()
        .filter(|(label, _): &&(&str, &str)| !claimed.contains(label))
        .map(|(label, reason): &(&str, &str)| {
            format!(
                "{list} in xtask/src/facts.rs still excuses `{label}` ({reason}), but that bar no \
                 longer carries the gap it described, or no longer exists. Remove the entry: an \
                 excuse that outlives its gap is how the next one slips in under it"
            )
        })
        .collect()
}

fn audit_recovery(root: &Path, recovery: &Recovery, allowed: Allowlists<'_>) -> Provenance {
    let mut issues: Vec<String> = Vec::new();
    let mut verified: usize = 0;
    let mut conditional: usize = 0;
    let mut total: usize = 0;
    let mut measured: usize = 0;
    let mut unpinned: Vec<&str> = Vec::new();
    let mut parked: Vec<&str> = Vec::new();
    let mut ungraded: Vec<&str> = Vec::new();

    for group in &recovery.groups {
        for bar in &group.bars {
            total += 1;
            if let Some(source) = bar.source.as_deref()
                && let Some(cited) = provenance_cites_documentation(source)
            {
                issues.push(format!(
                    "bar `{}` records its provenance as `{cited}`, a document this gate also \
                     validates against this same file; that is a copy checked against its own \
                     original and it can never fail. Cite the code instead.",
                    bar.label
                ));
            }
            let Some(cited): Option<&VerifiedBy> = bar.verified_by.as_ref() else {
                unpinned.push(&bar.label);
                if !excused(allowed.unpinned, &bar.label) {
                    issues.push(format!(
                        "bar `{}` names no test at all, and it is not one of the {} bar(s) \
                         UNPINNED_BARS in xtask/src/facts.rs records as knowingly unpinned. A \
                         published number with no citation is graded by nothing: give it a \
                         `verified_by`, or add it to that list with the reason no test can pin it \
                         so the gap is named rather than absorbed into a count",
                        bar.label,
                        allowed.unpinned.len()
                    ));
                }
                continue;
            };
            verified += 1;
            if cited.conditional.is_some() {
                conditional += 1;
            }
            if cited.measured_by.is_some() {
                measured += 1;
            }
            let signals: Signals = verify_citation(root, bar, cited, allowed, &mut issues);
            if signals.measurement_parked {
                parked.push(&bar.label);
            }
            if signals.delivered_ungraded {
                ungraded.push(&bar.label);
            }
        }
    }

    issues.extend(stale_entries(allowed.unpinned, &unpinned, "UNPINNED_BARS"));
    issues.extend(stale_entries(
        allowed.measurements_not_run,
        &parked,
        "MEASUREMENTS_NOT_RUN",
    ));
    issues.extend(stale_entries(
        allowed.ungraded_delivered,
        &ungraded,
        "UNGRADED_DELIVERED_LEGS",
    ));

    Provenance {
        issues,
        verified,
        conditional,
        total,
        unpinned: unpinned.len(),
        measured,
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let raw: String = read_text_bounded(&path, MAX_RECOVERY_JSON_BYTES)?;
    let recovery: Recovery = serde_json::from_str(&raw)?;

    let Provenance {
        issues,
        verified,
        conditional,
        total,
        unpinned,
        measured,
    }: Provenance = audit_recovery(root, &recovery, LIVE);

    if issues.is_empty() {
        let unconditional: usize = verified.saturating_sub(conditional);
        println!(
            "xtask regen: claim-provenance cross-check ok ({verified} of {total} bar(s) name a test \
             that exists, is not #[ignore]d and names the bar it verifies; {unconditional} of those \
             enforce unconditionally and {conditional} declare enforcement conditional on an input \
             this gate cannot guarantee is present, and no bar cites a document as its own source. \
             {measured} of them name the run that re-derives the figure where the cited check only \
             compares it against constants, and any cited file that parks a check behind #[ignore] \
             must name one. The remaining {unpinned} carry no citation at all. Every gap this \
             check tolerates is listed bar by bar in UNPINNED_BARS, MEASUREMENTS_NOT_RUN and \
             UNGRADED_DELIVERED_LEGS in xtask/src/facts.rs ({} entries between them), so a new one \
             fails instead of raising a count)",
            UNPINNED_BARS.len() + MEASUREMENTS_NOT_RUN.len() + UNGRADED_DELIVERED_LEGS.len()
        );
        Ok(())
    } else {
        bail!(
            "xtask regen: {} claim(s) in xtask/data/recovery.json are not sourced from code:\n  {}",
            issues.len(),
            issues.join("\n  ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bar(label: &str, verified_by: Option<VerifiedBy>) -> Bar {
        Bar {
            label: label.to_owned(),
            source: None,
            delivered: None,
            verified_by,
        }
    }

    fn recovery(bars: Vec<Bar>) -> Recovery {
        Recovery {
            groups: vec![Group { bars }],
        }
    }

    fn only_unpinned(unpinned: &'static [(&'static str, &'static str)]) -> Allowlists<'static> {
        Allowlists {
            unpinned,
            measurements_not_run: &[],
            ungraded_delivered: &[],
        }
    }

    const ONE_GAP: [(&str, &str); 1] = [("a known gap", "a reason")];

    #[test]
    fn an_uncited_bar_outside_the_allowlist_fails_instead_of_raising_a_count() {
        let document: Recovery = recovery(vec![bar("newly published figure", None)]);
        let result: Provenance = audit_recovery(Path::new("."), &document, only_unpinned(&ONE_GAP));
        assert_eq!(result.unpinned, 1);
        assert_eq!(
            result.issues.len(),
            2,
            "the new gap and the stale excuse are both reported, got {:?}",
            result.issues
        );
        assert!(
            result
                .issues
                .iter()
                .any(|issue: &String| issue.contains("newly published figure")
                    && issue.contains("names no test at all")),
            "got {:?}",
            result.issues
        );
    }

    #[test]
    fn an_uncited_bar_named_in_the_allowlist_passes() {
        let document: Recovery = recovery(vec![bar("a known gap", None)]);
        let result: Provenance = audit_recovery(Path::new("."), &document, only_unpinned(&ONE_GAP));
        assert!(
            result.issues.is_empty(),
            "a gap recorded by name is the one thing this list is for, got {:?}",
            result.issues
        );
        assert_eq!((result.total, result.verified, result.unpinned), (1, 0, 1));
    }

    #[test]
    fn an_allowlist_entry_that_outlives_its_gap_fails() {
        let document: Recovery = recovery(vec![bar(
            "a known gap",
            Some(VerifiedBy {
                path: "crates/x/tests/y.rs".to_owned(),
                function: "z".to_owned(),
                conditional: None,
                measured_by: None,
            }),
        )]);
        let result: Provenance = audit_recovery(Path::new("."), &document, only_unpinned(&ONE_GAP));
        assert!(
            result
                .issues
                .iter()
                .any(|issue: &String| issue.contains("still excuses `a known gap`")),
            "a bar that gained a citation must force its excuse out of the list, got {:?}",
            result.issues
        );
    }

    #[test]
    fn every_allowlisted_label_is_distinct() {
        for (list, entries) in [
            ("UNPINNED_BARS", UNPINNED_BARS.as_slice()),
            ("MEASUREMENTS_NOT_RUN", MEASUREMENTS_NOT_RUN.as_slice()),
            (
                "UNGRADED_DELIVERED_LEGS",
                UNGRADED_DELIVERED_LEGS.as_slice(),
            ),
        ] {
            let mut labels: Vec<&str> = entries
                .iter()
                .map(|(label, _): &(&str, &str)| *label)
                .collect();
            let before: usize = labels.len();
            labels.sort_unstable();
            labels.dedup();
            assert_eq!(
                labels.len(),
                before,
                "{list} names one bar twice, and one gap would cover another"
            );
        }
    }

    const IGNORED_MEASUREMENT: &str = "\
const LABEL: &str = \"a published figure\";

#[test]
fn compares_the_published_number_against_the_constants_this_file_pins() {
    assert_eq!(published(), FLOOR);
}

#[test]
#[ignore = \"walks the whole population through the real binary, which takes minutes and needs an \
             interpreter no workflow installs, so this is the one place the published figure is \
             actually re-derived and it is parked here rather than run. Drive it by hand with the \
             long command spelled out here, because a reason this detailed is the shape that used \
             to outrun a fixed-size lookback and read as a check that runs\"]
fn measures_the_whole_population() {
    assert!(measured() >= FLOOR);
}
";

    fn ignored_measurement_at(function: &str) -> usize {
        let at: Option<usize> = IGNORED_MEASUREMENT.find(&format!("fn {function}"));
        assert!(at.is_some(), "the fixture must declare {function}");
        at.unwrap_or_default()
    }

    #[test]
    fn an_ignore_reason_longer_than_a_fixed_window_still_reads_as_ignored() {
        let spans: Vec<(usize, usize)> = attribute_spans(IGNORED_MEASUREMENT);
        let measured: usize = ignored_measurement_at("measures_the_whole_population");
        let found: Option<usize> = IGNORED_MEASUREMENT.rfind("#[ignore");
        assert!(found.is_some(), "the fixture parks its measurement");
        let attribute: usize = found.unwrap_or_default();
        assert!(
            measured - attribute > 256,
            "this fixture only proves anything while its reason outruns a fixed lookback; the gap \
             is {} bytes",
            measured - attribute
        );
        assert!(
            function_is_ignored(IGNORED_MEASUREMENT, &spans, measured),
            "a verbose reason must not hide the attribute that parks the check"
        );
        assert!(
            !function_is_ignored(
                IGNORED_MEASUREMENT,
                &spans,
                ignored_measurement_at(
                    "compares_the_published_number_against_the_constants_this_file_pins"
                )
            ),
            "the check that does run must not inherit its neighbour's attribute"
        );
    }

    fn measurement_issues(measured_by: Option<&str>, allowed: &[(&str, &str)]) -> Vec<String> {
        let cited: VerifiedBy = VerifiedBy {
            path: "crates/x/tests/y.rs".to_owned(),
            function: "compares_the_published_number_against_the_constants_this_file_pins"
                .to_owned(),
            conditional: None,
            measured_by: measured_by.map(str::to_owned),
        };
        let mut issues: Vec<String> = Vec::new();
        verify_measurement(
            IGNORED_MEASUREMENT,
            &attribute_spans(IGNORED_MEASUREMENT),
            &bar("a published figure", None),
            &cited,
            Allowlists {
                unpinned: &[],
                measurements_not_run: allowed,
                ungraded_delivered: &[],
            },
            &mut issues,
        );
        issues
    }

    #[test]
    fn a_cited_file_that_parks_a_check_must_name_what_re_derives_the_figure() {
        let issues: Vec<String> = measurement_issues(None, &[]);
        assert_eq!(issues.len(), 1, "got {issues:?}");
        assert!(
            issues[0].contains("measures_the_whole_population")
                && issues[0].contains("names no `measured_by`"),
            "the parked function must be named in the failure, got {issues:?}"
        );
    }

    #[test]
    fn naming_an_ignored_function_as_the_measurement_fails_unless_the_bar_is_listed() {
        let issues: Vec<String> = measurement_issues(Some("measures_the_whole_population"), &[]);
        assert_eq!(issues.len(), 1, "got {issues:?}");
        assert!(
            issues[0].contains("nothing measures this figure"),
            "got {issues:?}"
        );
        assert!(
            measurement_issues(
                Some("measures_the_whole_population"),
                &[("a published figure", "a reason")]
            )
            .is_empty(),
            "a gap recorded by name is what the list is for"
        );
        assert!(
            measurement_issues(
                Some("compares_the_published_number_against_the_constants_this_file_pins"),
                &[]
            )
            .is_empty(),
            "naming a measurement that runs is the resolved case"
        );
    }

    #[test]
    fn a_measured_by_that_names_nothing_fails() {
        let issues: Vec<String> = measurement_issues(Some("a_function_that_was_renamed"), &[]);
        assert_eq!(issues.len(), 1, "got {issues:?}");
        assert!(issues[0].contains("is not there"), "got {issues:?}");
    }

    fn delivered_issues(region: &str, allowed: &[(&str, &str)]) -> (bool, Vec<String>) {
        let cited: VerifiedBy = VerifiedBy {
            path: "crates/x/src/roster.rs".to_owned(),
            function: "published_count_matches_this_enum".to_owned(),
            conditional: None,
            measured_by: None,
        };
        let mut published: Bar = bar("a breadth bar", None);
        published.delivered = Some(3);
        let mut issues: Vec<String> = Vec::new();
        let signal: bool = verify_delivered_leg(
            region,
            &published,
            &cited,
            Allowlists {
                unpinned: &[],
                measurements_not_run: &[],
                ungraded_delivered: allowed,
            },
            &mut issues,
        );
        (signal, issues)
    }

    #[test]
    fn a_bar_whose_citation_grades_only_the_detected_leg_is_reported() {
        let (signal, issues): (bool, Vec<String>) =
            delivered_issues("{ let detected = bar[\"detected\"]; }", &[]);
        assert!(signal, "the half-graded bar must be signalled for the list");
        assert_eq!(issues.len(), 1, "got {issues:?}");
        assert!(issues[0].contains("never reads the"), "got {issues:?}");
        let (still_signalled, excused): (bool, Vec<String>) = delivered_issues(
            "{ let detected = bar[\"detected\"]; }",
            &[("a breadth bar", "a reason")],
        );
        assert!(
            still_signalled && excused.is_empty(),
            "a listed bar stays counted as a gap and stops failing, got {excused:?}"
        );
        let (graded, clean): (bool, Vec<String>) =
            delivered_issues("{ let delivered = bar[\"delivered\"]; }", &[]);
        assert!(
            !graded && clean.is_empty(),
            "a citation that reads the delivered leg is the resolved case, got {clean:?}"
        );
    }

    #[test]
    fn naming_the_other_leg_in_a_message_does_not_count_as_grading_it() {
        let (signal, issues): (bool, Vec<String>) = delivered_issues(
            "{ let detected = bar[\"detected\"]; assert_eq!(detected, roster, \"this asserts the \
             detected leg; the delivered leg has no declaration to check it against\"); }",
            &[],
        );
        assert!(
            signal,
            "a bar whose citation only talks about the other leg is still ungraded"
        );
        assert_eq!(
            issues.len(),
            1,
            "prose naming the leg must not read as a check of it, got {issues:?}"
        );
    }
}
