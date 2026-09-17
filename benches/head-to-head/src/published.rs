use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::path::PathBuf;

use serde_json::Value;

use crate::tool::{MAX_TEXT_BYTES, read_bounded_string};

const PUBLISHED_VALUE_TOLERANCE: f64 = 0.05;
const MEMBERSHIP_FIELD: &str = "membership";

#[derive(Debug)]
pub(crate) struct PublishedBar {
    pub(crate) label: String,
    pub(crate) num: u64,
    pub(crate) den: u64,
    pub(crate) value: f64,
    pub(crate) membership: BTreeSet<String>,
}

pub(crate) fn checked_workspace_root() -> PathBuf {
    let bench_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolved: eyre::Result<PathBuf> = crate::workspace_root(&bench_dir);
    assert!(
        resolved.is_ok(),
        "the bench manifest dir {} must resolve to the workspace root: {:?}",
        bench_dir.display(),
        resolved.as_ref().err()
    );
    resolved.unwrap_or_default()
}

fn recovery_document() -> Value {
    let path: PathBuf = checked_workspace_root()
        .join("xtask")
        .join("data")
        .join("recovery.json");
    let raw: eyre::Result<String> = read_bounded_string(&path, MAX_TEXT_BYTES);
    assert!(
        raw.is_ok(),
        "{} must be readable, because every published figure is checked against it: {:?}",
        path.display(),
        raw.as_ref().err()
    );
    let parsed: serde_json::Result<Value> = serde_json::from_str(&raw.unwrap_or_default());
    assert!(
        parsed.is_ok(),
        "{} must parse as JSON: {:?}",
        path.display(),
        parsed.as_ref().err()
    );
    parsed.unwrap_or_default()
}

fn published_u64(bar: &Value, field: &str, label: &str) -> u64 {
    let found: Option<u64> = bar.get(field).and_then(Value::as_u64);
    assert!(
        found.is_some(),
        "xtask/data/recovery.json bar `{label}` must publish a `{field}` count; a figure that every \
         document renders but that carries no number behind it cannot be checked against a \
         measurement at all"
    );
    found.unwrap_or_default()
}

fn published_f64(bar: &Value, field: &str, label: &str) -> f64 {
    let found: Option<f64> = bar.get(field).and_then(Value::as_f64);
    assert!(
        found.is_some(),
        "xtask/data/recovery.json bar `{label}` must publish the `{field}` it plots"
    );
    found.unwrap_or_default()
}

fn published_membership(bar: &Value, label: &str) -> BTreeSet<String> {
    let found: Option<&Vec<Value>> = bar.get(MEMBERSHIP_FIELD).and_then(Value::as_array);
    assert!(
        found.is_some(),
        "xtask/data/recovery.json bar `{label}` must publish a `{MEMBERSHIP_FIELD}` array naming \
         exactly which items it recalls. A count alone stays green when one item stops being found \
         and a different one starts, which is the failure this list exists to catch"
    );
    let listed: Vec<String> = found
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let distinct: BTreeSet<String> = listed.iter().cloned().collect();
    assert_eq!(
        distinct.len(),
        listed.len(),
        "bar `{label}`: `{MEMBERSHIP_FIELD}` names the same item twice, so its length overstates \
         what is recalled: {listed:?}"
    );
    distinct
}

pub(crate) fn published_bar(heading_needle: &str, label: &str) -> PublishedBar {
    let document: Value = recovery_document();
    let groups: Option<&Vec<Value>> = document.get("groups").and_then(Value::as_array);
    assert!(
        groups.is_some(),
        "xtask/data/recovery.json must carry a `groups` array"
    );
    let mut matched: Vec<&Value> = Vec::new();
    for group in groups.into_iter().flatten() {
        let heading_matches: bool = group
            .get("heading")
            .and_then(Value::as_str)
            .is_some_and(|heading: &str| heading.contains(heading_needle));
        if !heading_matches {
            continue;
        }
        for bar in group
            .get("bars")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if bar.get("label").and_then(Value::as_str) == Some(label) {
                matched.push(bar);
            }
        }
    }
    assert_eq!(
        matched.len(),
        1,
        "xtask/data/recovery.json must carry exactly one bar labeled `{label}` under a heading \
         containing `{heading_needle}`, found {}. Until that bar exists the published figure rests \
         on nothing this check can read",
        matched.len()
    );
    let bar: Value = matched.into_iter().next().cloned().unwrap_or_default();

    let num: u64 = published_u64(&bar, "num", label);
    let den: u64 = published_u64(&bar, "den", label);
    let value: f64 = published_f64(&bar, "value", label);
    let membership: BTreeSet<String> = published_membership(&bar, label);

    assert!(
        num <= den,
        "bar `{label}`: the published numerator {num} cannot exceed its denominator {den}"
    );
    let derived: f64 = 100.0 * num as f64 / den.max(1) as f64;
    assert!(
        (derived - value).abs() < PUBLISHED_VALUE_TOLERANCE,
        "bar `{label}`: the plotted value {value} must equal its own {num}/{den} = {derived:.4}"
    );
    let listed: u64 = u64::try_from(membership.len()).unwrap_or(u64::MAX);
    assert_eq!(
        listed, num,
        "bar `{label}`: `{MEMBERSHIP_FIELD}` names {listed} item(s) but the published numerator is \
         {num}. The list and the count describe the same recall, so they cannot disagree"
    );

    PublishedBar {
        label: label.to_owned(),
        num,
        den,
        value,
        membership,
    }
}

fn assert_denominator_is_pinned(bar: &PublishedBar, universe: usize) {
    let measured: u64 = u64::try_from(universe).unwrap_or(u64::MAX);
    assert_eq!(
        measured, bar.den,
        "bar `{}`: xtask/data/recovery.json publishes a denominator of {} and every document \
         renders that number, but this run grades {measured} item(s). A run that inspects fewer \
         items must score worse, never shrink what it is measured against",
        bar.label, bar.den
    );
}

pub(crate) fn assert_published_membership_is_recovered(
    bar: &PublishedBar,
    measured: &BTreeSet<String>,
    universe: usize,
) {
    assert_denominator_is_pinned(bar, universe);
    let missing: Vec<&String> = bar.membership.difference(measured).collect();
    assert!(
        missing.is_empty(),
        "bar `{}`: xtask/data/recovery.json publishes {} of {} recalled and names them, but this \
         run did not recall {missing:?}. Raise the recovery or correct the published figure, never \
         the reverse",
        bar.label,
        bar.num,
        bar.den
    );
    let recalled: u64 = u64::try_from(measured.len()).unwrap_or(u64::MAX);
    assert!(
        recalled >= bar.num,
        "bar `{}`: recovery.json publishes {} of {} recalled; this run recalled {recalled}",
        bar.label,
        bar.num,
        bar.den
    );
}

pub(crate) fn assert_published_membership_is_exact(
    bar: &PublishedBar,
    measured: &BTreeSet<String>,
    universe: usize,
) {
    assert_denominator_is_pinned(bar, universe);
    assert_eq!(
        *measured, bar.membership,
        "bar `{}`: a comparison row states what another tool finds, so it has to be exact in both \
         directions. Publishing more than it finds overstates the other tool; publishing less \
         flatters disrobe. recovery.json names {:?}; this run measured {measured:?}",
        bar.label, bar.membership
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolRequirement {
    Optional,
    Mandatory,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompetitorTool {
    pub(crate) program: &'static str,
    pub(crate) require_var: &'static str,
    pub(crate) install_hint: &'static str,
}

pub(crate) fn requirement_from_value(value: Option<&OsStr>) -> ToolRequirement {
    let Some(raw): Option<&OsStr> = value else {
        return ToolRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => ToolRequirement::Optional,
        _ => ToolRequirement::Mandatory,
    }
}

pub(crate) fn requirement_for(tool: &CompetitorTool) -> ToolRequirement {
    let raw: Option<OsString> = std::env::var_os(tool.require_var);
    requirement_from_value(raw.as_deref())
}

pub(crate) fn enforce_requirement(
    tool: &CompetitorTool,
    graded: &str,
    defect: &str,
    requirement: ToolRequirement,
) {
    assert!(
        requirement == ToolRequirement::Optional,
        "{var} makes {program} mandatory for this run, so {graded} cannot be measured and this \
         case must not report success: {defect}. To fix it, {hint}; to permit a run that grades \
         only disrobe here, clear {var}.",
        var = tool.require_var,
        program = tool.program,
        hint = tool.install_hint,
    );
    announce_unmeasured(tool, graded, defect);
}

fn announce_unmeasured(tool: &CompetitorTool, graded: &str, defect: &str) {
    let line: String = format!(
        "\nNOT MEASURED: {graded} was compared against nothing and graded nothing, because \
         {program} is not usable here ({defect}). Set {var}=1 to fail instead of skipping when \
         {program} cannot be run.\n",
        program = tool.program,
        var = tool.require_var,
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::panic::UnwindSafe;

    use super::*;

    #[test]
    fn requirement_reads_the_off_switches_as_optional() {
        for off in ["", "0", "false", "no", "off", "optional", "OFF"] {
            assert_eq!(
                requirement_from_value(Some(OsStr::new(off))),
                ToolRequirement::Optional,
                "`{off}` must leave the competitor optional"
            );
        }
        assert_eq!(
            requirement_from_value(None),
            ToolRequirement::Optional,
            "an unset variable must leave the competitor optional"
        );
        for on in ["1", "true", "yes", "mandatory"] {
            assert_eq!(
                requirement_from_value(Some(OsStr::new(on))),
                ToolRequirement::Mandatory,
                "`{on}` must make the competitor mandatory"
            );
        }
    }

    #[test]
    fn a_mandatory_competitor_that_cannot_run_fails_instead_of_skipping() {
        let tool: CompetitorTool = CompetitorTool {
            program: "disrobe-competitor-that-is-not-installed",
            require_var: "DISROBE_REQUIRE_A_TOOL_NO_RUN_EVER_SETS",
            install_hint: "nothing, this name stands in for an absent competitor",
        };
        enforce_requirement(&tool, GRADED, DEFECT, ToolRequirement::Optional);
        let refused: String = seeded_defect_message(|| {
            enforce_requirement(&tool, GRADED, DEFECT, ToolRequirement::Mandatory);
        });
        assert!(
            refused.contains("mandatory for this run"),
            "a mandatory competitor that cannot run must fail the row rather than grade one side of \
             it, got: {refused}"
        );
    }

    const GRADED: &str = "the competitor side of a sample comparison row";
    const DEFECT: &str = "it is not on PATH";

    fn labels(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name: &&str| (*name).to_owned()).collect()
    }

    fn sample_bar() -> PublishedBar {
        PublishedBar {
            label: "sample".to_owned(),
            num: 3,
            den: 4,
            value: 75.0,
            membership: labels(&["a", "b", "c"]),
        }
    }

    fn seeded_defect_message(check: impl FnOnce() + UnwindSafe) -> String {
        eprintln!("seeding a defect; the panic below is the expected outcome");
        let outcome: std::thread::Result<()> = std::panic::catch_unwind(check);
        outcome
            .err()
            .map_or_else(String::new, |payload: Box<dyn Any + Send>| {
                let owned: Option<String> = payload.downcast_ref::<String>().cloned();
                owned.unwrap_or_else(|| {
                    payload
                        .downcast_ref::<&str>()
                        .map_or_else(String::new, |message: &&str| (*message).to_owned())
                })
            })
    }

    #[test]
    fn the_membership_check_rejects_a_lost_item_a_swap_and_a_shrunken_denominator() {
        let bar: PublishedBar = sample_bar();
        let measured: BTreeSet<String> = labels(&["a", "b", "c"]);
        assert_published_membership_is_recovered(&bar, &measured, 4);
        assert_published_membership_is_exact(&bar, &measured, 4);

        let lost: BTreeSet<String> = labels(&["a", "b"]);
        let dropped: String =
            seeded_defect_message(|| assert_published_membership_is_recovered(&bar, &lost, 4));
        assert!(
            dropped.contains("did not recall"),
            "losing a published item must be reported as a shortfall, got: {dropped}"
        );

        let swapped: BTreeSet<String> = labels(&["a", "b", "d"]);
        let traded: String =
            seeded_defect_message(|| assert_published_membership_is_recovered(&bar, &swapped, 4));
        assert!(
            traded.contains("did not recall"),
            "trading a published item for a different one holds the count at three and must still \
             fail, got: {traded}"
        );

        let shrunk: String =
            seeded_defect_message(|| assert_published_membership_is_recovered(&bar, &measured, 3));
        assert!(
            shrunk.contains("never shrink what it is measured against"),
            "grading fewer items than the published denominator must be rejected on the \
             denominator, got: {shrunk}"
        );
    }

    #[test]
    fn the_exact_check_rejects_a_competitor_that_now_finds_more_than_published() {
        let bar: PublishedBar = sample_bar();
        let more: BTreeSet<String> = labels(&["a", "b", "c", "d"]);
        let stale: String =
            seeded_defect_message(|| assert_published_membership_is_exact(&bar, &more, 4));
        assert!(
            stale.contains("exact in both directions"),
            "a competitor that recalls more than the row publishes leaves the row understating it, \
             which flatters disrobe, so it must fail, got: {stale}"
        );

        let fewer: BTreeSet<String> = labels(&["a", "b"]);
        let overstated: String =
            seeded_defect_message(|| assert_published_membership_is_exact(&bar, &fewer, 4));
        assert!(
            overstated.contains("exact in both directions"),
            "a competitor that recalls less than the row publishes leaves the row overstating it, \
             so it must fail, got: {overstated}"
        );
    }
}
