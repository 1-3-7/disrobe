#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_core::{BehaviorCategory, BehaviorReport, CategoryFinding, analyze_behavior};

const PUBLISHED_COUNT: usize = 7;

const DEPTH_DOC: &str = "docs/src/cli/analysis-depth.md";
const REFERENCE_DOC: &str = "docs/src/cli/reference.md";
const DEPTH_SECTION: &str = "## Behavior summary";
const DEPTH_COUNT_PHRASE: &str = "classifying it across seven categories";
const REFERENCE_COUNT_PHRASE: &str = "across 7 categories";

#[derive(Debug, Clone, Copy)]
struct PublishedCategory {
    category: BehaviorCategory,
    label: &'static str,
    describe: &'static str,
    import_signal: &'static str,
    attack_id: &'static str,
}

const PUBLISHED: [PublishedCategory; PUBLISHED_COUNT] = [
    PublishedCategory {
        category: BehaviorCategory::Network,
        label: "network",
        describe: "network communication",
        import_signal: "WSAStartup",
        attack_id: "T1095",
    },
    PublishedCategory {
        category: BehaviorCategory::Filesystem,
        label: "filesystem",
        describe: "filesystem access",
        import_signal: "FindFirstFileW",
        attack_id: "T1083",
    },
    PublishedCategory {
        category: BehaviorCategory::ProcessExec,
        label: "process_exec",
        describe: "process / command execution",
        import_signal: "CreateProcessW",
        attack_id: "T1106",
    },
    PublishedCategory {
        category: BehaviorCategory::RegistryPersistence,
        label: "registry_persistence",
        describe: "registry & persistence",
        import_signal: "RegSetValueExW",
        attack_id: "T1112",
    },
    PublishedCategory {
        category: BehaviorCategory::Crypto,
        label: "crypto",
        describe: "cryptographic operations",
        import_signal: "CryptEncrypt",
        attack_id: "T1486",
    },
    PublishedCategory {
        category: BehaviorCategory::AntiAnalysis,
        label: "anti_analysis",
        describe: "anti-analysis / anti-debug",
        import_signal: "IsDebuggerPresent",
        attack_id: "T1622",
    },
    PublishedCategory {
        category: BehaviorCategory::DynamicCode,
        label: "dynamic_code",
        describe: "dynamic code / loader",
        import_signal: "GetProcAddress",
        attack_id: "T1129",
    },
];

const fn published_label(category: BehaviorCategory) -> &'static str {
    match category {
        BehaviorCategory::Network => "network",
        BehaviorCategory::Filesystem => "filesystem",
        BehaviorCategory::ProcessExec => "process_exec",
        BehaviorCategory::RegistryPersistence => "registry_persistence",
        BehaviorCategory::Crypto => "crypto",
        BehaviorCategory::AntiAnalysis => "anti_analysis",
        BehaviorCategory::DynamicCode => "dynamic_code",
    }
}

fn repo_root() -> PathBuf {
    let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
        panic!(
            "the published behavior-category roster is stated in {DEPTH_DOC}, which lives two \
             directories above {}, so a manifest path with no grandparent leaves the published \
             count checked against nothing",
            manifest.display()
        )
    };
    root.to_path_buf()
}

fn published_doc(relative: &str) -> String {
    let path: PathBuf = repo_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{relative} is the surface that publishes the behavior-category roster, so a run that \
             cannot read it must fail rather than report a green that checked no document: {error} \
             at {}",
            path.display()
        )
    })
}

fn behavior_section(doc: &str) -> &str {
    let Some(at): Option<usize> = doc.find(DEPTH_SECTION) else {
        panic!(
            "{DEPTH_DOC} no longer carries a `{DEPTH_SECTION}` heading, so the category table this \
             check reads cannot be located and the published roster is bound to nothing"
        )
    };
    let Some(tail): Option<&str> = doc.get(at.saturating_add(DEPTH_SECTION.len())..) else {
        panic!(
            "`{DEPTH_SECTION}` in {DEPTH_DOC} starts mid-character, so its section cannot be read"
        )
    };
    let end: usize = tail.find("\n## ").unwrap_or(tail.len());
    let Some(section): Option<&str> = tail.get(..end) else {
        panic!("the `{DEPTH_SECTION}` section of {DEPTH_DOC} could not be delimited")
    };
    section
}

fn documented_labels(section: &str) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    for line in section.lines() {
        let trimmed: &str = line.trim();
        let Some(rest): Option<&str> = trimmed.strip_prefix("| `") else {
            continue;
        };
        let Some((token, _)): Option<(&str, &str)> = rest.split_once('`') else {
            continue;
        };
        labels.push(token.to_owned());
    }
    labels
}

fn category_labels(report: &BehaviorReport) -> BTreeSet<String> {
    report
        .categories
        .iter()
        .map(|finding: &CategoryFinding| published_label(finding.category).to_owned())
        .collect()
}

fn analyze_signals(signals: &[String]) -> BehaviorReport {
    analyze_behavior(&[], signals)
}

fn every_signal() -> Vec<String> {
    PUBLISHED
        .into_iter()
        .map(|row: PublishedCategory| row.import_signal.to_owned())
        .collect()
}

fn signals_without(skipped: BehaviorCategory) -> Vec<String> {
    PUBLISHED
        .into_iter()
        .filter(|row: &PublishedCategory| row.category != skipped)
        .map(|row: PublishedCategory| row.import_signal.to_owned())
        .collect()
}

fn published_labels() -> BTreeSet<String> {
    PUBLISHED
        .into_iter()
        .map(|row: PublishedCategory| row.label.to_owned())
        .collect()
}

#[test]
fn the_published_roster_names_every_category_the_report_can_emit() {
    assert_eq!(
        PUBLISHED.len(),
        PUBLISHED_COUNT,
        "the published roster is the denominator both `{DEPTH_COUNT_PHRASE}` in {DEPTH_DOC} and \
         `{REFERENCE_COUNT_PHRASE}` in {REFERENCE_DOC} state, so it is pinned by equality rather \
         than counted from whatever this table happens to hold"
    );

    let labels: BTreeSet<String> = published_labels();
    assert_eq!(
        labels.len(),
        PUBLISHED_COUNT,
        "two rows of the published roster share a label, so the set a reader is shown is smaller \
         than the {PUBLISHED_COUNT} the documents claim"
    );

    for row in PUBLISHED {
        assert_eq!(
            published_label(row.category),
            row.label,
            "the exhaustive mapping and the published roster disagree on how {:?} is spelled",
            row.category
        );
        assert_eq!(
            row.category.label(),
            row.label,
            "{:?} serializes as `{}` but the documents publish it as `{}`, so a report field and \
             the page that describes it name different things",
            row.category,
            row.category.label(),
            row.label
        );
        assert_eq!(
            row.category.describe(),
            row.describe,
            "{:?} describes itself as `{}` while {DEPTH_DOC} publishes `{}`",
            row.category,
            row.category.describe(),
            row.describe
        );
    }
}

#[test]
fn the_documents_state_the_same_seven_categories_this_crate_classifies() {
    let depth: String = published_doc(DEPTH_DOC);
    let reference: String = published_doc(REFERENCE_DOC);

    assert!(
        depth.contains(DEPTH_COUNT_PHRASE),
        "{DEPTH_DOC} must state `{DEPTH_COUNT_PHRASE}`, otherwise the count a reader is given and \
         the {PUBLISHED_COUNT} this crate carries can drift apart with nothing to catch it"
    );
    assert!(
        reference.contains(REFERENCE_COUNT_PHRASE),
        "{REFERENCE_DOC} must state `{REFERENCE_COUNT_PHRASE}` for the same reason"
    );

    let section: &str = behavior_section(&depth);
    let documented: Vec<String> = documented_labels(section);
    assert_eq!(
        documented.len(),
        PUBLISHED_COUNT,
        "the category table in {DEPTH_DOC} lists {} rows against the {PUBLISHED_COUNT} both \
         documents claim in prose: {documented:?}",
        documented.len()
    );

    let documented_set: BTreeSet<String> = documented.iter().cloned().collect();
    assert_eq!(
        documented_set,
        published_labels(),
        "the categories {DEPTH_DOC} tables and the categories this crate emits are different sets, \
         so a swap that preserved the count would leave the page describing something the report \
         never produces"
    );
}

#[test]
fn every_published_category_is_reached_by_the_signal_its_row_documents() {
    let report: BehaviorReport = analyze_signals(&every_signal());
    let reached: BTreeSet<String> = category_labels(&report);

    assert_eq!(
        reached,
        published_labels(),
        "one import per documented category must reach exactly the published set; a category that \
         stopped classifying drops out here rather than leaving a count green"
    );
    assert_eq!(
        report.categories.len(),
        PUBLISHED_COUNT,
        "the report emitted {} findings for {PUBLISHED_COUNT} distinct signals, so the population \
         this check grades is not the published one",
        report.categories.len()
    );

    for row in PUBLISHED {
        let finding: Option<&CategoryFinding> = report
            .categories
            .iter()
            .find(|found: &&CategoryFinding| found.category == row.category);
        let Some(found): Option<&CategoryFinding> = finding else {
            panic!(
                "`{}` is published under {DEPTH_DOC} as the signal class {:?} covers, but it \
                 produced no finding",
                row.import_signal, row.category
            )
        };
        assert!(
            found.attack_ids.contains(&row.attack_id),
            "{DEPTH_DOC} publishes the ATT&CK mapping for `{}` as {}, but the finding carries \
             {:?}",
            row.import_signal,
            row.attack_id,
            found.attack_ids
        );
        assert!(
            report.attack_ids.contains(&row.attack_id),
            "the aggregate `attack_ids` list is published as the union across all categories, but \
             it omits {} which one of its own findings carries",
            row.attack_id
        );
        assert!(
            found
                .evidence
                .iter()
                .any(|evidence: &disrobe_core::BehaviorEvidence| evidence.source == "import"),
            "{:?} was reached from an import table entry, so at least one piece of its evidence \
             must be tagged `import`; the documented source tags would otherwise describe \
             something the report does not record",
            row.category
        );
    }
}

#[test]
fn dropping_one_signal_drops_exactly_its_category_from_the_published_set() {
    for row in PUBLISHED {
        let report: BehaviorReport = analyze_signals(&signals_without(row.category));
        let reached: BTreeSet<String> = category_labels(&report);

        assert!(
            !reached.contains(row.label),
            "removing `{}` left {:?} classified anyway, so the membership check above would stay \
             green after that category stopped depending on its own signal",
            row.import_signal,
            row.category
        );
        assert_ne!(
            reached,
            published_labels(),
            "the membership assertion must reject a run missing {:?}, otherwise it proves nothing",
            row.category
        );
        assert_eq!(
            reached.len(),
            PUBLISHED_COUNT.saturating_sub(1),
            "removing `{}` changed {} categories rather than one, so the signals this check plants \
             are not separable and a single regression could be masked by a neighbour",
            row.import_signal,
            PUBLISHED_COUNT.saturating_sub(reached.len())
        );
    }
}

#[test]
fn input_carrying_none_of_the_published_signals_classifies_nothing() {
    let report: BehaviorReport =
        analyze_signals(&["a plain sentence of ordinary prose".to_owned()]);
    assert!(
        report.categories.is_empty(),
        "input carrying no published signal must classify nothing; a classifier that fires on \
         anything would satisfy every membership assertion above without recovering a thing: \
         {report:?}"
    );
    assert!(
        report.attack_ids.is_empty(),
        "an unclassified input must carry no ATT&CK ids: {report:?}"
    );
}
