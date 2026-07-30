#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use flate2::read::GzDecoder;

use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectorOutput, ObfuscatorCatalog, SupportQuality,
};
use disrobe_pass_shell::chain_detector::ShellDetector;
use disrobe_pass_shell::{Detection, Dialect, XlmCell, XlmRecovery, XlmSheet, detect, recover_xlm};

const PUBLISHED_GROUP: &str = "Detection and extraction breadth";
const PUBLISHED_BAR: &str = "Shell obfuscation modes";

const PUBLISHED_MODE_IDS: [&str; 19] = [
    "ps-invoke-obfuscation-token",
    "ps-invoke-obfuscation-ast",
    "ps-invoke-obfuscation-string",
    "ps-invoke-obfuscation-encoding",
    "ps-invoke-obfuscation-compress",
    "ps-invoke-obfuscation-launcher",
    "ps-invoke-stealth",
    "ps-powerhell",
    "ps-chameleon",
    "ps-psobf",
    "ps-isesteroids",
    "bash-bashfuscator-token",
    "bash-bashfuscator-string",
    "bash-bashfuscator-obfuscate",
    "bash-bashfuscator-compress",
    "bash-indirection",
    "bash-node-bash-obfuscate",
    "batch-random",
    "batch-set-indirection",
];

const EXCLUDED_SCRIPTING_FORMAT_IDS: [&str; 1] = ["vba-macro"];

const PARTIALLY_REVERSED_MODE_IDS: [&str; 2] = ["ps-invoke-obfuscation-launcher", "ps-isesteroids"];

const FULLY_REVERSED_MODES: usize = 17;

const XLM_GOLDEN: &str = "real_xlm_excel16.xls";
const XLM_GOLDEN_MACRO_FORMULA: &str = "=EXEC(\"calc.exe\")";

#[derive(Debug)]
struct ScriptingFormat {
    label: &'static str,
    dialect: Dialect,
    sample: &'static str,
}

const EXCLUDED_SCRIPTING_FORMATS: [ScriptingFormat; 3] = [
    ScriptingFormat {
        label: "VBA",
        dialect: Dialect::Vba,
        sample: "Attribute VB_Name = \"Module1\"\nSub Auto_Open()\n  MsgBox \"x\"\nEnd Sub\n",
    },
    ScriptingFormat {
        label: "VBS",
        dialect: Dialect::Vbs,
        sample: "Set s = CreateObject(\"WScript.Shell\")\ns.Run \"calc.exe\", 0, False\n",
    },
    ScriptingFormat {
        label: "WSH",
        dialect: Dialect::Wsh,
        sample: "<job id=\"main\"><script language=\"VBScript\">WScript.Echo 1</script></job>",
    },
];

fn recovery_json_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("xtask")
        .join("data")
        .join("recovery.json")
}

fn published_bar_legs() -> (u64, u64) {
    let path: PathBuf = recovery_json_path();
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|err: std::io::Error| panic!("read {}: {err}", path.display()));
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err: serde_json::Error| panic!("parse {}: {err}", path.display()));
    let groups: &Vec<serde_json::Value> = parsed["groups"]
        .as_array()
        .unwrap_or_else(|| panic!("{} must carry a groups array", path.display()));

    let mut legs: Option<(u64, u64)> = None;
    for group in groups {
        let heading: &str = group["heading"]
            .as_str()
            .unwrap_or_else(|| panic!("every group in {} must carry a heading", path.display()));
        if !heading.contains(PUBLISHED_GROUP) {
            continue;
        }
        let bars: &Vec<serde_json::Value> = group["bars"]
            .as_array()
            .unwrap_or_else(|| panic!("group `{heading}` in {} must carry bars", path.display()));
        for bar in bars {
            if bar["label"].as_str() != Some(PUBLISHED_BAR) {
                continue;
            }
            let detected: u64 = bar["detected"].as_u64().unwrap_or_else(|| {
                panic!("bar `{PUBLISHED_BAR}` must record an integer detected leg")
            });
            let delivered: u64 = bar["delivered"].as_u64().unwrap_or_else(|| {
                panic!("bar `{PUBLISHED_BAR}` must record an integer delivered leg")
            });
            legs = Some((detected, delivered));
        }
    }
    legs.unwrap_or_else(|| {
        panic!(
            "{} must carry a `{PUBLISHED_BAR}` bar under `{PUBLISHED_GROUP}`; README.md and \
             docs/src/catalog.md render that bar through the shell_families metric key, so its \
             absence means the published figure has no source at all",
            path.display()
        )
    })
}

fn catalog_ids() -> Vec<&'static str> {
    ObfuscatorCatalog::catalog(&ShellDetector)
        .into_iter()
        .map(|entry: &'static dyn CatalogEntry| entry.id())
        .collect()
}

fn support_quality_of(id: &str) -> SupportQuality {
    let entry: &'static dyn CatalogEntry = ObfuscatorCatalog::catalog(&ShellDetector)
        .into_iter()
        .find(|entry: &&'static dyn CatalogEntry| entry.id() == id)
        .unwrap_or_else(|| panic!("the shell chain catalog has no entry `{id}`"));
    entry.support_quality()
}

fn golden_xlm_workbook(name: &str) -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("xlm")
        .join(format!("{name}.gz.b64"));
    let armored: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|err: std::io::Error| panic!("read {}: {err}", path.display()));
    let packed: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(armored.replace(['\r', '\n'], ""))
        .unwrap_or_else(|err: base64::DecodeError| {
            panic!("undecodable fixture {}: {err}", path.display())
        });
    let mut raw: Vec<u8> = Vec::new();
    GzDecoder::new(packed.as_slice())
        .read_to_end(&mut raw)
        .unwrap_or_else(|err: std::io::Error| {
            panic!("uninflatable fixture {}: {err}", path.display())
        });
    raw
}

#[test]
fn published_shell_obfuscation_mode_count_matches_this_catalog() {
    let (detected, delivered): (u64, u64) = published_bar_legs();
    let catalog: Vec<&'static str> = catalog_ids();
    let observed: BTreeSet<&'static str> = catalog.iter().copied().collect();
    assert_eq!(
        observed.len(),
        catalog.len(),
        "the shell chain catalog repeats an entry id, so any count taken over it is wrong: \
         {catalog:?}"
    );

    let published: BTreeSet<&'static str> = PUBLISHED_MODE_IDS.into_iter().collect();
    let excluded: BTreeSet<&'static str> = EXCLUDED_SCRIPTING_FORMAT_IDS.into_iter().collect();
    assert_eq!(
        published.len(),
        PUBLISHED_MODE_IDS.len(),
        "PUBLISHED_MODE_IDS repeats an id, which would let a dropped mode hide behind a duplicate"
    );
    assert!(
        published.is_disjoint(&excluded),
        "an id cannot be both a published obfuscation mode and a scripting format held out of the \
         count: {:?}",
        published.intersection(&excluded).collect::<Vec<&&str>>()
    );

    for id in PUBLISHED_MODE_IDS {
        assert!(
            observed.contains(id),
            "the published figure counts `{id}` as a reversed shell obfuscation mode, but the \
             shell chain catalog no longer carries that entry; the catalog now reads {catalog:?}"
        );
    }
    for id in EXCLUDED_SCRIPTING_FORMAT_IDS {
        assert!(
            observed.contains(id),
            "`{id}` is the scripting-format entry held out of the published count, but the shell \
             chain catalog no longer carries it, so the exclusion now subtracts an entry that is \
             not there and the published figure is arithmetic over a population that changed \
             underneath it; the catalog now reads {catalog:?}"
        );
    }

    let classified: BTreeSet<&'static str> = published.union(&excluded).copied().collect();
    let unclassified: Vec<&'static str> = observed
        .iter()
        .copied()
        .filter(|id: &&'static str| !classified.contains(id))
        .collect();
    assert!(
        unclassified.is_empty(),
        "the shell chain catalog carries {} entries that are neither in PUBLISHED_MODE_IDS nor in \
         EXCLUDED_SCRIPTING_FORMAT_IDS: {unclassified:?}. Every entry must be either published or \
         named as an exclusion, otherwise the published total drifts silently",
        unclassified.len()
    );

    let expected: usize = catalog.len() - EXCLUDED_SCRIPTING_FORMAT_IDS.len();
    assert_eq!(
        expected,
        PUBLISHED_MODE_IDS.len(),
        "the shell chain catalog carries {} entries and {} of them are named scripting-format \
         exclusions ({:?}), which leaves {expected} published obfuscation modes, but \
         PUBLISHED_MODE_IDS lists {}",
        catalog.len(),
        EXCLUDED_SCRIPTING_FORMAT_IDS.len(),
        EXCLUDED_SCRIPTING_FORMAT_IDS,
        PUBLISHED_MODE_IDS.len()
    );

    let detected_usize: usize = usize::try_from(detected).expect("detected leg fits usize");
    assert_eq!(
        detected_usize,
        expected,
        "xtask/data/recovery.json publishes {detected} shell obfuscation modes on the `{PUBLISHED_BAR}` \
         bar, and README.md plus docs/src/catalog.md render that number through the shell_families \
         metric key, but this crate's chain catalog carries {} entries of which {:?} are scripting \
         formats covered alongside the obfuscators rather than counted as one, giving {expected}",
        catalog.len(),
        EXCLUDED_SCRIPTING_FORMAT_IDS
    );

    let delivered_usize: usize = usize::try_from(delivered).expect("delivered leg fits usize");
    assert_eq!(
        delivered_usize, detected_usize,
        "the `{PUBLISHED_BAR}` bar publishes {delivered} of {detected} modes reversed; a delivered \
         leg that no longer equals the detected leg must be re-derived against this catalog rather \
         than left to render as a rate nobody measured"
    );
}

#[test]
fn published_modes_declaring_partial_reversal_stay_named() {
    let partial: BTreeSet<&'static str> = PUBLISHED_MODE_IDS
        .into_iter()
        .filter(|id: &&'static str| support_quality_of(id) == SupportQuality::Partial)
        .collect();
    let declared: BTreeSet<&'static str> = PARTIALLY_REVERSED_MODE_IDS.into_iter().collect();
    assert_eq!(
        partial,
        declared,
        "the shell chain catalog declares {} of the {} published modes only partially reversed, \
         and this test names {:?}. The `{PUBLISHED_BAR}` bar publishes every published mode as \
         reversed, so when this split moves the delivered leg has to move with it",
        partial.len(),
        PUBLISHED_MODE_IDS.len(),
        PARTIALLY_REVERSED_MODE_IDS
    );

    let full: usize = PUBLISHED_MODE_IDS
        .into_iter()
        .filter(|id: &&'static str| support_quality_of(id) == SupportQuality::Full)
        .count();
    assert_eq!(
        full,
        FULLY_REVERSED_MODES,
        "the shell chain catalog declares {full} of the {} published modes fully reversed, not \
         {FULLY_REVERSED_MODES}; raise the published delivered leg to match a real gain, never \
         lower this figure to absorb a loss",
        PUBLISHED_MODE_IDS.len()
    );
}

#[test]
fn scripting_formats_excluded_from_the_published_count_stay_handled() {
    let excluded: BTreeSet<&'static str> = EXCLUDED_SCRIPTING_FORMAT_IDS.into_iter().collect();
    let mut routed: BTreeSet<&'static str> = BTreeSet::new();
    for format in EXCLUDED_SCRIPTING_FORMATS {
        let sample: &'static [u8] = format.sample.as_bytes();
        let detection: Detection = detect(sample);
        assert_eq!(
            detection.dialect, format.dialect,
            "{} is held out of the published shell obfuscator count because it is covered as a \
             scripting format, so it must keep classifying as {:?}; it classified as {:?}",
            format.label, format.dialect, detection.dialect
        );

        let output: DetectorOutput = ObfuscatorCatalog::detect(
            &ShellDetector,
            &DetectContext {
                bytes: sample,
                path_hint: None,
                parent_hint: None,
                depth: 0,
            },
        )
        .unwrap_or_else(|| {
            panic!(
                "the {} sample must still route to a shell chain catalog entry, otherwise the \
                 entry named in EXCLUDED_SCRIPTING_FORMAT_IDS is not the one this format uses",
                format.label
            )
        });
        routed.insert(output.entry_id);
    }
    assert_eq!(
        routed, excluded,
        "the scripting-format samples route to {routed:?} and EXCLUDED_SCRIPTING_FORMAT_IDS names \
         {excluded:?}. The exclusion must name the entries scripting formats actually use, so \
         subtracting a different entry of the same arithmetic weight cannot pass"
    );

    let workbook: Vec<u8> = golden_xlm_workbook(XLM_GOLDEN);
    let recovery: XlmRecovery = recover_xlm(&workbook).unwrap_or_else(|| {
        panic!(
            "{XLM_GOLDEN} is an Excel-authored workbook and Excel 4.0 macro coverage is why XLM is \
             held out of the published shell obfuscator count, but the reader returned nothing"
        )
    });
    assert!(
        recovery.has_macro_sheet(),
        "{XLM_GOLDEN} must still resolve an Excel 4.0 macro sheet; the reader returned sheets {:?}",
        recovery
            .sheets
            .iter()
            .map(|sheet: &XlmSheet| (sheet.name.clone(), sheet.kind.clone()))
            .collect::<Vec<(String, String)>>()
    );
    let recovered_exec: bool = recovery.sheets.iter().any(|sheet: &XlmSheet| {
        sheet
            .cells
            .iter()
            .any(|cell: &XlmCell| cell.formula == XLM_GOLDEN_MACRO_FORMULA)
    });
    assert!(
        recovered_exec,
        "{XLM_GOLDEN} carries {XLM_GOLDEN_MACRO_FORMULA} on its macro sheet and the reader \
         recovered {} formulas without it, so XLM coverage cannot be claimed as the reason the \
         published count excludes it",
        recovery.total_formulas()
    );
}
