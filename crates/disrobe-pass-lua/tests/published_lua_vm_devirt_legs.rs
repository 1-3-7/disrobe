#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/dvm1_reference.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod dvm1_reference;

#[path = "support/lua_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod lua_toolchain;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_lua::Result as LuaResult;
use disrobe_pass_lua::ironbrew2_recover::{
    RecoveredProgram, recover, recover_runnable, recovered_strings,
};
use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};
use dvm1_reference::PermRecipe;
use lua_toolchain::{LuaInterpreter, run_lua};

const PUBLISHED_GROUP: &str = "Obfuscator and bundler family coverage";

const REAL_TOOL_BAR: &str = "Lua VM-devirt on real tool output (IronBrew2 2.7.0)";
const IN_HOUSE_BAR: &str =
    "Lua VM-devirt on an in-house sample only (MoonSec shape, no real sample)";
const COMBINED_BAR: &str = "Lua VM-devirt (IronBrew2 real, MoonSec synthetic)";

const REAL_TOOL_FAMILY: &str = "ironbrew2";
const REAL_TOOL_FAMILY_COUNT: u64 = 1;
const IN_HOUSE_LEG_VALUE: u64 = 1;
const COMBINED_VALUE: u64 = REAL_TOOL_FAMILY_COUNT + IN_HOUSE_LEG_VALUE;

const IRONBREW_TOOL_HEADER: &str = "IronBrew:tm: obfuscation; Version 2.7.0";
const IRONBREW_RESIDUAL_MARKER: &str = "IronBrew";

const REAL_ORIGINALS: [&str; 5] = ["arith", "control", "edge", "hello", "tables"];
const REAL_MODES: [&str; 2] = ["max", "min"];
const REAL_SAMPLE_DENOMINATOR: usize = REAL_ORIGINALS.len() * REAL_MODES.len();

const REAL_SAMPLES_COMPLETE_OPCODE_TABLE: usize = 6;

const REAL_SAMPLES_WITH_PARTIAL_OPCODE_TABLE: [&str; 4] = [
    "edge.max.lua",
    "edge.min.lua",
    "tables.max.lua",
    "tables.min.lua",
];

const EXECUTION_EVIDENCE_FILE: &str = "ironbrew2_real_oracle.rs";
const EXECUTION_EVIDENCE_ENTRY_POINT: &str = "recover_runnable(";
const TEST_ATTRIBUTE: &str = "#[test]";
const IGNORE_ATTRIBUTE: &str = "#[ignore";
const ATTRIBUTE_LOOKBACK_BYTES: usize = 256;

const GOLDEN_REFRESH_VAR: &str = "DISROBE_WRITE_LUA_VM_DEVIRT_GOLDEN";
const REAL_TOOL_GOLDEN: &str = "real_tool_ironbrew2.txt";
const IN_HOUSE_GOLDEN: &str = "in_house_container_families.txt";
const CORPUS_INVENTORY_GOLDEN: &str = "corpus_lua_inventory.txt";

const IN_HOUSE_DISCLOSURE_MARKERS: [&str; 3] = ["in-house", "not real", "no real sample"];

type PeelFn = fn(&[u8], &DeobfOptions) -> LuaResult<PeelResult>;

#[derive(Debug, Clone, Copy)]
struct InHouseFamily {
    name: &'static str,
    header: &'static str,
    recipe: PermRecipe,
    authorization_required: bool,
    peel: PeelFn,
    committed_real_samples: &'static [&'static str],
}

const HERCULES_REAL_SAMPLES: [&str; 1] = ["hercules/gauntlet/gauntlet_obfuscated.lua"];
const LURAPH_REAL_SAMPLES: [&str; 1] = ["luraph/signature_header.lua"];
const NO_REAL_SAMPLES: [&str; 0] = [];

const IN_HOUSE_FAMILIES: [InHouseFamily; 9] = [
    InHouseFamily {
        name: "aztup_brew",
        header: "-- aztup_brew\nAZB_VM",
        recipe: PermRecipe {
            seed: 0x4242_4242,
            step: 11,
            base: 0x40,
            key_mask: 0xFF,
        },
        authorization_required: false,
        peel: disrobe_pass_lua::aztup_brew::peel,
        committed_real_samples: &NO_REAL_SAMPLES,
    },
    InHouseFamily {
        name: "boronide",
        header: "-- Boronide v0.6\nBORONIDE_VM",
        recipe: PermRecipe {
            seed: 0x1357_2468,
            step: 11,
            base: 0x40,
            key_mask: 0xFF,
        },
        authorization_required: false,
        peel: disrobe_pass_lua::boronide::peel,
        committed_real_samples: &NO_REAL_SAMPLES,
    },
    InHouseFamily {
        name: "darksec",
        header: "-- DarkSec\nDS_VM_BOOT",
        recipe: PermRecipe {
            seed: 0x7F7F_7F7F,
            step: 13,
            base: 0x60,
            key_mask: 0xFF,
        },
        authorization_required: false,
        peel: disrobe_pass_lua::darksec::peel,
        committed_real_samples: &NO_REAL_SAMPLES,
    },
    InHouseFamily {
        name: "hercules",
        header: "-- Obfuscated by Hercules\nhercules-obfuscator",
        recipe: PermRecipe {
            seed: 0x6161_7272,
            step: 7,
            base: 0x50,
            key_mask: 0xFF,
        },
        authorization_required: false,
        peel: disrobe_pass_lua::hercules::peel,
        committed_real_samples: &HERCULES_REAL_SAMPLES,
    },
    InHouseFamily {
        name: "luraph",
        header: "-- Luraph\nlura.ph",
        recipe: PermRecipe {
            seed: 0x7272_8383,
            step: 13,
            base: 0x60,
            key_mask: 0xFF,
        },
        authorization_required: false,
        peel: disrobe_pass_lua::luraph::peel,
        committed_real_samples: &LURAPH_REAL_SAMPLES,
    },
    InHouseFamily {
        name: "moonsec_v1",
        header: "-- MoonSec v1\nmoonsec_v1",
        recipe: PermRecipe {
            seed: 0x1111_2222,
            step: 9,
            base: 0x30,
            key_mask: 0xFF,
        },
        authorization_required: false,
        peel: disrobe_pass_lua::moonsec_v1::peel,
        committed_real_samples: &NO_REAL_SAMPLES,
    },
    InHouseFamily {
        name: "moonsec_v2",
        header: "-- MoonSec v2\nMS_V2_KEY",
        recipe: PermRecipe {
            seed: 0x2222_3333,
            step: 7,
            base: 0x50,
            key_mask: 0xFF,
        },
        authorization_required: false,
        peel: disrobe_pass_lua::moonsec_v2::peel,
        committed_real_samples: &NO_REAL_SAMPLES,
    },
    InHouseFamily {
        name: "moonsec_v3",
        header: "-- MoonSec v3\nMS_VM_ENTRY",
        recipe: PermRecipe {
            seed: 0x3333_4444,
            step: 13,
            base: 0x60,
            key_mask: 0xFF,
        },
        authorization_required: true,
        peel: disrobe_pass_lua::moonsec_v3::peel,
        committed_real_samples: &NO_REAL_SAMPLES,
    },
    InHouseFamily {
        name: "psu",
        header: "-- PSU 4.5\nPSU_VM_KEY",
        recipe: PermRecipe {
            seed: 0x0042_0042,
            step: 7,
            base: 0x50,
            key_mask: 0xFF,
        },
        authorization_required: false,
        peel: disrobe_pass_lua::psu::peel,
        committed_real_samples: &NO_REAL_SAMPLES,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Publication {
    Split { real: u64, in_house: u64 },
    Combined { total: u64 },
}

fn repo_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn corpus_lua_root() -> PathBuf {
    repo_root().join("corpus").join("lua")
}

fn recovery_json_path() -> PathBuf {
    repo_root().join("xtask").join("data").join("recovery.json")
}

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("lua_vm_devirt")
        .join(name)
}

fn published_bars() -> Vec<serde_json::Value> {
    let path: PathBuf = recovery_json_path();
    let raw: String = fs::read_to_string(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "the Lua VM-devirt figure is graded against {}, so a run that cannot read it must fail \
             rather than measure nothing: {err}",
            path.display()
        )
    });
    bars_in_group(&raw, &path)
}

fn bars_in_group(raw: &str, path: &Path) -> Vec<serde_json::Value> {
    let doc: serde_json::Value = serde_json::from_str(raw)
        .unwrap_or_else(|err: serde_json::Error| panic!("parse {}: {err}", path.display()));
    let groups: &Vec<serde_json::Value> = doc["groups"]
        .as_array()
        .unwrap_or_else(|| panic!("{} must carry a groups array", path.display()));
    let mut bars: Vec<serde_json::Value> = Vec::new();
    for group in groups {
        let matches: bool = group["heading"]
            .as_str()
            .is_some_and(|heading: &str| heading.contains(PUBLISHED_GROUP));
        if matches {
            for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
                bars.push(bar.clone());
            }
        }
    }
    assert!(
        !bars.is_empty(),
        "{} carries no group whose heading contains `{PUBLISHED_GROUP}`, so the Lua VM-devirt bar \
         this crate is measured against has no home at all",
        path.display()
    );
    bars
}

fn bar_named(bars: &[serde_json::Value], label: &str) -> Option<serde_json::Value> {
    let matched: Vec<&serde_json::Value> = bars
        .iter()
        .filter(|bar: &&serde_json::Value| bar["label"].as_str() == Some(label))
        .collect();
    assert!(
        matched.len() <= 1,
        "recovery.json carries {} bars labelled `{label}` under `{PUBLISHED_GROUP}`; a duplicated \
         label lets one copy be graded while the other renders",
        matched.len()
    );
    matched
        .first()
        .map(|bar: &&serde_json::Value| (*bar).clone())
}

fn bar_count(bar: &serde_json::Value, label: &str) -> u64 {
    bar["value"].as_u64().unwrap_or_else(|| {
        panic!(
            "the `{label}` bar publishes a family count, so its value must be a whole number; \
             recovery.json carries {}",
            bar["value"]
        )
    })
}

fn bar_source(bar: &serde_json::Value, label: &str) -> String {
    bar["source"]
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "the `{label}` bar must record where its number comes from; recovery.json carries \
                 no source string for it"
            )
        })
        .to_owned()
}

fn lua_devirt_publication() -> Publication {
    publication_from_bars(&published_bars())
}

fn publication_from_bars(bars: &[serde_json::Value]) -> Publication {
    let real: Option<serde_json::Value> = bar_named(bars, REAL_TOOL_BAR);
    let in_house: Option<serde_json::Value> = bar_named(bars, IN_HOUSE_BAR);
    let combined: Option<serde_json::Value> = bar_named(bars, COMBINED_BAR);

    match (real, in_house, combined) {
        (Some(real), Some(in_house), None) => {
            let in_house_source: String = bar_source(&in_house, IN_HOUSE_BAR);
            for family in IN_HOUSE_FAMILIES {
                assert!(
                    in_house_source.contains(family.name),
                    "the `{IN_HOUSE_BAR}` bar stands for every Lua VM family that only round-trips \
                     an in-house sample, but its provenance never names `{}`; a reader cannot tell \
                     which families sit behind the weak leg. Provenance reads: {in_house_source}",
                    family.name
                );
            }
            assert!(
                IN_HOUSE_DISCLOSURE_MARKERS
                    .into_iter()
                    .any(|marker: &str| in_house_source.contains(marker)),
                "the `{IN_HOUSE_BAR}` bar must state in its provenance that the sample behind it is \
                 ours and not the obfuscator's own output; none of {IN_HOUSE_DISCLOSURE_MARKERS:?} \
                 appear in {in_house_source}"
            );
            Publication::Split {
                real: bar_count(&real, REAL_TOOL_BAR),
                in_house: bar_count(&in_house, IN_HOUSE_BAR),
            }
        }
        (None, None, Some(combined)) => Publication::Combined {
            total: bar_count(&combined, COMBINED_BAR),
        },
        (real, in_house, combined) => panic!(
            "the Lua VM-devirt figure must be published either as the two split bars \
             `{REAL_TOOL_BAR}` and `{IN_HOUSE_BAR}`, or as the single combined bar `{COMBINED_BAR}` \
             that still concedes one leg is ours, and never as a mixture. recovery.json currently \
             carries real={} in_house={} combined={}",
            real.is_some(),
            in_house.is_some(),
            combined.is_some()
        ),
    }
}

fn published_real_tool_families() -> u64 {
    match lua_devirt_publication() {
        Publication::Split { real, .. } => real,
        Publication::Combined { total } => {
            assert_eq!(
                total, COMBINED_VALUE,
                "the combined `{COMBINED_BAR}` bar publishes {total}, but it is the sum of \
                 {REAL_TOOL_FAMILY_COUNT} family graded on real tool output and \
                 {IN_HOUSE_LEG_VALUE} graded on a sample of our own, which is {COMBINED_VALUE}. \
                 Split the bar rather than moving the total"
            );
            total - IN_HOUSE_LEG_VALUE
        }
    }
}

fn published_in_house_leg() -> u64 {
    match lua_devirt_publication() {
        Publication::Split { in_house, .. } => in_house,
        Publication::Combined { total } => {
            assert_eq!(
                total, COMBINED_VALUE,
                "the combined `{COMBINED_BAR}` bar publishes {total}, not the \
                 {REAL_TOOL_FAMILY_COUNT} plus {IN_HOUSE_LEG_VALUE} it is made of"
            );
            total - REAL_TOOL_FAMILY_COUNT
        }
    }
}

fn read_corpus_lua(relative: &str) -> Vec<u8> {
    let mut path: PathBuf = corpus_lua_root();
    for segment in relative.split('/') {
        path.push(segment);
    }
    fs::read(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "a published Lua VM-devirt leg is graded against corpus/lua/{relative}, so a missing \
             or unreadable sample must fail rather than shrink what is measured: {err} at {}",
            path.display()
        )
    })
}

fn corpus_lua_inventory() -> Vec<String> {
    let root: PathBuf = corpus_lua_root();
    let mut found: Vec<String> = Vec::new();
    let mut pending: Vec<PathBuf> = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        let entries: fs::ReadDir = fs::read_dir(&dir).unwrap_or_else(|err: std::io::Error| {
            panic!(
                "the Lua corpus inventory is what proves no real sample landed without the \
                 published legs moving, so an unreadable directory must fail: {err} at {}",
                dir.display()
            )
        });
        for entry in entries {
            let entry: fs::DirEntry = entry.unwrap_or_else(|err: std::io::Error| {
                panic!("cannot walk {}: {err}", dir.display())
            });
            let path: PathBuf = entry.path();
            let kind: fs::FileType = entry.file_type().unwrap_or_else(|err: std::io::Error| {
                panic!("cannot stat {}: {err}", path.display())
            });
            if kind.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext == "lua")
            {
                let relative: &Path =
                    path.strip_prefix(&root)
                        .unwrap_or_else(|err: std::path::StripPrefixError| {
                            panic!("{} is not under {}: {err}", path.display(), root.display())
                        });
                found.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    found.sort();
    found
}

fn real_sample_names() -> Vec<String> {
    let dir: PathBuf = corpus_lua_root().join(REAL_TOOL_FAMILY).join("obfuscated");
    let entries: fs::ReadDir = fs::read_dir(&dir).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "the real-tool leg is cut from the committed IronBrew2 output in {}, so a run that \
             cannot list it must fail rather than grade a smaller population: {err}",
            dir.display()
        )
    });
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let entry: fs::DirEntry = entry
            .unwrap_or_else(|err: std::io::Error| panic!("cannot walk {}: {err}", dir.display()));
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    names
}

fn expected_real_sample_names() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for original in REAL_ORIGINALS {
        for mode in REAL_MODES {
            names.push(format!("{original}.{mode}.lua"));
        }
    }
    names.sort();
    names
}

#[derive(Debug, Clone)]
struct RealSampleOutcome {
    sample: String,
    original: String,
    obfuscated_bytes: usize,
    opcode_table_complete: bool,
    peel_fully_recovered: bool,
    recovered_strings: Vec<String>,
    recovered_source: String,
}

fn measure_real_samples() -> Vec<RealSampleOutcome> {
    let mut outcomes: Vec<RealSampleOutcome> = Vec::new();
    for name in expected_real_sample_names() {
        let original: String = name
            .split('.')
            .next()
            .unwrap_or_else(|| panic!("{name} carries no stem"))
            .to_owned();
        let raw: Vec<u8> = read_corpus_lua(&format!("{REAL_TOOL_FAMILY}/obfuscated/{name}"));
        let text: String = String::from_utf8(raw.clone())
            .unwrap_or_else(|err: std::string::FromUtf8Error| panic!("{name} is not utf8: {err}"));
        assert!(
            text.contains(IRONBREW_TOOL_HEADER),
            "{name} is counted on the real-tool leg, so it must be output the real obfuscator \
             wrote; its text does not carry `{IRONBREW_TOOL_HEADER}`, which means the leg would be \
             graded against something we produced"
        );

        let program: RecoveredProgram = recover(&text)
            .unwrap_or_else(|err: disrobe_pass_lua::Error| panic!("{name}: recover failed: {err}"));
        let mut strings: Vec<String> = recovered_strings(&program);
        strings.sort();
        strings.dedup();
        let recovered_source: String =
            recover_runnable(&text).unwrap_or_else(|err: disrobe_pass_lua::Error| {
                panic!("{name}: recover_runnable failed: {err}")
            });
        let peeled: PeelResult = disrobe_pass_lua::ironbrew2::peel(
            &raw,
            &DeobfOptions {
                i_have_authorization: true,
                strict: false,
            },
        )
        .unwrap_or_else(|err: disrobe_pass_lua::Error| panic!("{name}: peel failed: {err}"));

        outcomes.push(RealSampleOutcome {
            sample: name,
            original: format!("{original}.lua"),
            obfuscated_bytes: raw.len(),
            opcode_table_complete: program.stats.fully_recovered(),
            peel_fully_recovered: peeled.fully_recovered,
            recovered_strings: strings,
            recovered_source,
        });
    }
    outcomes
}

fn peel_reference_container(family: &InHouseFamily) -> PeelResult {
    let (boot, _payload): (String, Vec<u8>) =
        dvm1_reference::bootstrap_with_payload(family.header, &family.recipe);
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: family.authorization_required,
        strict: false,
    };
    (family.peel)(boot.as_bytes(), &opts).unwrap_or_else(|err: disrobe_pass_lua::Error| {
        panic!("{}: peel failed: {err}", family.name)
    })
}

#[derive(Debug, Clone)]
struct InHouseOutcome {
    family: &'static str,
    reference_container_round_trip: bool,
    committed_real_samples: usize,
    committed_real_samples_fully_recovered: usize,
}

fn measure_in_house_families() -> Vec<InHouseOutcome> {
    let mut outcomes: Vec<InHouseOutcome> = Vec::new();
    for family in IN_HOUSE_FAMILIES {
        let result: PeelResult = peel_reference_container(&family);
        let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
        let round_trip: bool = result.fully_recovered
            && recovered.contains("print")
            && recovered.contains('+')
            && result
                .recovered_strings
                .iter()
                .any(|text: &String| text == "print");

        let mut real_recovered: usize = 0;
        for sample in family.committed_real_samples {
            let bytes: Vec<u8> = read_corpus_lua(sample);
            let real: PeelResult = (family.peel)(&bytes, &DeobfOptions::default()).unwrap_or_else(
                |err: disrobe_pass_lua::Error| {
                    panic!("{}: peel of {sample} failed: {err}", family.name)
                },
            );
            if real.fully_recovered {
                real_recovered += 1;
            } else {
                assert!(
                    !real.residual_markers.is_empty(),
                    "{}: {sample} is real committed output that does not fully recover, so the \
                     pass must say what is left rather than return a silent partial",
                    family.name
                );
            }
        }

        outcomes.push(InHouseOutcome {
            family: family.name,
            reference_container_round_trip: round_trip,
            committed_real_samples: family.committed_real_samples.len(),
            committed_real_samples_fully_recovered: real_recovered,
        });
    }
    outcomes
}

fn compare_membership(golden: &str, measured: &[String]) {
    let path: PathBuf = golden_path(golden);
    let rendered: String = format!("{}\n", measured.join("\n"));
    if std::env::var_os(GOLDEN_REFRESH_VAR).is_some() {
        let parent: &Path = path.parent().expect("golden parent");
        fs::create_dir_all(parent)
            .unwrap_or_else(|err: std::io::Error| panic!("create {}: {err}", parent.display()));
        fs::write(&path, rendered.as_bytes())
            .unwrap_or_else(|err: std::io::Error| panic!("write {}: {err}", path.display()));
        eprintln!("wrote {} entries to {}", measured.len(), path.display());
        return;
    }

    let recorded: String = fs::read_to_string(&path)
        .unwrap_or_else(|err: std::io::Error| {
            panic!(
                "{} is the per-entry record that stops one entry regressing while a total holds, \
                 so its absence must fail rather than let the count alone stand ({} entries \
                 measured); re-run with {GOLDEN_REFRESH_VAR}=1 to record it: {err}",
                path.display(),
                measured.len()
            )
        })
        .replace("\r\n", "\n");

    let recorded_set: BTreeSet<&str> = recorded
        .lines()
        .filter(|line: &&str| !line.is_empty())
        .collect();
    let measured_set: BTreeSet<&str> = measured.iter().map(String::as_str).collect();
    assert_eq!(
        recorded_set.len(),
        recorded.lines().filter(|l: &&str| !l.is_empty()).count(),
        "{} repeats a line, so a lost entry could hide behind a duplicate",
        path.display()
    );

    let lost: Vec<&&str> = recorded_set.difference(&measured_set).collect();
    let gained: Vec<&&str> = measured_set.difference(&recorded_set).collect();
    assert!(
        lost.is_empty(),
        "{}: {} recorded outcome(s) no longer reproduce, so a published Lua VM-devirt leg regressed \
         while its total could stay flat: {lost:?}",
        path.display(),
        lost.len()
    );
    assert!(
        gained.is_empty(),
        "{}: {} measured outcome(s) are not recorded. A gain is welcome but must be recorded rather \
         than absorbed silently; re-run with {GOLDEN_REFRESH_VAR}=1 after checking each one: \
         {gained:?}",
        path.display(),
        gained.len()
    );
}

fn evidence_source() -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(EXECUTION_EVIDENCE_FILE);
    fs::read_to_string(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "the real-tool leg's strength is the execution differential in {}, so a run that \
             cannot read that file must fail rather than take the claim on trust: {err}",
            path.display()
        )
    })
}

fn attribute_window<'a>(source: &'a str, test_fn: &str) -> &'a str {
    let needle: String = format!("fn {test_fn}(");
    let Some(at): Option<usize> = source.find(&needle) else {
        panic!(
            "{EXECUTION_EVIDENCE_FILE} no longer declares `{test_fn}`, which is the execution \
             differential for one of the {REAL_SAMPLE_DENOMINATOR} real IronBrew2 samples the \
             published leg counts"
        )
    };
    let mut start: usize = at.saturating_sub(ATTRIBUTE_LOOKBACK_BYTES);
    while start < at && !source.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    source
        .get(start..at)
        .unwrap_or_else(|| panic!("the attributes above `{test_fn}` could not be read"))
}

fn evidence_test_name(sample: &str) -> String {
    let stem: &str = sample
        .strip_suffix(".lua")
        .unwrap_or_else(|| panic!("{sample} is not a .lua sample"));
    let (original, mode): (&str, &str) = stem
        .split_once('.')
        .unwrap_or_else(|| panic!("{sample} carries no mode suffix"));
    if mode == "min" {
        format!("oracle_{original}")
    } else {
        format!("oracle_{mode}_{original}")
    }
}

#[test]
fn published_real_tool_vm_devirt_leg_matches_the_real_ironbrew2_corpus() {
    let published: u64 = published_real_tool_families();
    assert_eq!(
        published, REAL_TOOL_FAMILY_COUNT,
        "the `{REAL_TOOL_BAR}` leg publishes {published} Lua obfuscator families devirtualized from \
         real tool output, but `{REAL_TOOL_FAMILY}` is the only family this crate grades that way; \
         every other family is measured on a sample of our own"
    );

    let listed: Vec<String> = real_sample_names();
    let expected: Vec<String> = expected_real_sample_names();
    assert_eq!(
        listed, expected,
        "the real-tool leg is cut from the committed IronBrew2 output, and that population is \
         pinned by name: corpus/lua/{REAL_TOOL_FAMILY}/obfuscated now holds {listed:?} where the \
         published figure is measured over {expected:?}"
    );
    assert_eq!(
        listed.len(),
        REAL_SAMPLE_DENOMINATOR,
        "the denominator behind the real-tool leg is {REAL_SAMPLE_DENOMINATOR} committed samples \
         ({} originals in {} modes); a run that inspects {} scores worse rather than quietly \
         measuring less",
        REAL_ORIGINALS.len(),
        REAL_MODES.len(),
        listed.len()
    );

    let outcomes: Vec<RealSampleOutcome> = measure_real_samples();
    assert_eq!(
        outcomes.len(),
        REAL_SAMPLE_DENOMINATOR,
        "every one of the {REAL_SAMPLE_DENOMINATOR} committed samples must be measured, not {}",
        outcomes.len()
    );

    for outcome in &outcomes {
        assert_eq!(
            outcome.opcode_table_complete, outcome.peel_fully_recovered,
            "{}: the devirtualizer and the family peeler disagree about whether this real sample \
             recovered completely, so the two figures cut from them can no longer be published as \
             one leg",
            outcome.sample
        );
        assert!(
            !outcome.recovered_source.contains(IRONBREW_RESIDUAL_MARKER),
            "{}: the recovered source still carries `{IRONBREW_RESIDUAL_MARKER}`, so the pass \
             handed back the obfuscated input rather than devirtualizing it",
            outcome.sample
        );
        assert!(
            outcome.recovered_source.len() * 4 < outcome.obfuscated_bytes,
            "{}: the recovered source is {} bytes against {} obfuscated, which is not a \
             devirtualized program but a copy of the bootstrap",
            outcome.sample,
            outcome.recovered_source.len(),
            outcome.obfuscated_bytes
        );
        let checkable: Vec<&String> = outcome
            .recovered_strings
            .iter()
            .filter(|constant: &&String| !constant.is_empty())
            .collect();
        assert!(
            !checkable.is_empty(),
            "{}: no non-empty string constant came out of the real payload, so nothing was decoded \
             that could be looked for in the recovered source",
            outcome.sample
        );
        for constant in checkable {
            assert!(
                outcome.recovered_source.contains(constant),
                "{}: `{constant}` was decoded from the real payload but never reaches the \
                 recovered source, so the constant pool and the emitted program disagree",
                outcome.sample
            );
        }
    }

    let complete: BTreeSet<&str> = outcomes
        .iter()
        .filter(|outcome: &&RealSampleOutcome| outcome.opcode_table_complete)
        .map(|outcome: &RealSampleOutcome| outcome.sample.as_str())
        .collect();
    let partial: BTreeSet<&str> = outcomes
        .iter()
        .filter(|outcome: &&RealSampleOutcome| !outcome.opcode_table_complete)
        .map(|outcome: &RealSampleOutcome| outcome.sample.as_str())
        .collect();
    let declared_partial: BTreeSet<&str> =
        REAL_SAMPLES_WITH_PARTIAL_OPCODE_TABLE.into_iter().collect();
    assert_eq!(
        partial, declared_partial,
        "the real-tool leg reverses every committed sample far enough to run, and this many of them \
         also classify the whole opcode table. That split is pinned by membership rather than by \
         size, so a sample that regresses while another improves cannot cancel out: {partial:?} are \
         partial where {declared_partial:?} is recorded"
    );
    assert_eq!(
        complete.len(),
        REAL_SAMPLES_COMPLETE_OPCODE_TABLE,
        "{} of the {REAL_SAMPLE_DENOMINATOR} committed samples classify the whole opcode table, not \
         {REAL_SAMPLES_COMPLETE_OPCODE_TABLE}; raise this figure for a real gain, never lower it to \
         absorb a loss",
        complete.len()
    );
    assert_eq!(
        complete.len() + partial.len(),
        REAL_SAMPLE_DENOMINATOR,
        "every committed sample is either complete or partial; {} plus {} does not account for the \
         whole population",
        complete.len(),
        partial.len()
    );

    let source: String = evidence_source();
    for outcome in &outcomes {
        let test_fn: String = evidence_test_name(&outcome.sample);
        let window: &str = attribute_window(&source, &test_fn);
        assert!(
            window.contains(TEST_ATTRIBUTE),
            "`{test_fn}` is the execution differential for {}, but it carries no \
             {TEST_ATTRIBUTE}, so it never runs and cannot fail",
            outcome.sample
        );
        assert!(
            !window.contains(IGNORE_ATTRIBUTE),
            "`{test_fn}` is the execution differential for {}, but it is marked \
             {IGNORE_ATTRIBUTE}, so the published leg would survive a recovery path that stopped \
             working",
            outcome.sample
        );
    }
    assert!(
        source.contains(EXECUTION_EVIDENCE_ENTRY_POINT),
        "{EXECUTION_EVIDENCE_FILE} is what makes the real-tool leg an execution differential \
         rather than a self-check, so it must call `{EXECUTION_EVIDENCE_ENTRY_POINT}`"
    );

    let membership: Vec<String> = {
        let mut lines: Vec<String> = Vec::new();
        for outcome in &outcomes {
            lines.push(format!(
                "{} original={} obfuscated_bytes={} opcode_table_complete={} \
                 peel_fully_recovered={}",
                outcome.sample,
                outcome.original,
                outcome.obfuscated_bytes,
                outcome.opcode_table_complete,
                outcome.peel_fully_recovered
            ));
            for constant in &outcome.recovered_strings {
                lines.push(format!("{} constant={constant}", outcome.sample));
            }
        }
        lines.sort();
        lines
    };
    compare_membership(REAL_TOOL_GOLDEN, &membership);

    let inventory: Vec<String> = corpus_lua_inventory();
    compare_membership(CORPUS_INVENTORY_GOLDEN, &inventory);
}

#[test]
fn published_in_house_leg_matches_the_families_with_no_real_sample() {
    let published: u64 = published_in_house_leg();
    assert_eq!(
        published,
        IN_HOUSE_LEG_VALUE,
        "the weak Lua VM-devirt leg publishes {published}, but this crate grades exactly \
         {IN_HOUSE_LEG_VALUE} MoonSec-shape recovery on a bootstrap of our own; the families \
         behind it are {:?} and none of them is graded on that obfuscator's own output",
        IN_HOUSE_FAMILIES.map(|family: InHouseFamily| family.name)
    );

    let outcomes: Vec<InHouseOutcome> = measure_in_house_families();
    let measured: BTreeSet<&'static str> = outcomes
        .iter()
        .filter(|outcome: &&InHouseOutcome| outcome.reference_container_round_trip)
        .map(|outcome: &InHouseOutcome| outcome.family)
        .collect();
    let declared: BTreeSet<&'static str> = IN_HOUSE_FAMILIES
        .into_iter()
        .map(|family: InHouseFamily| family.name)
        .collect();
    assert_eq!(
        declared.len(),
        IN_HOUSE_FAMILIES.len(),
        "IN_HOUSE_FAMILIES repeats a name, so a family that stopped working could hide behind a \
         duplicate"
    );
    assert_eq!(
        measured, declared,
        "the weak leg stands for the families that recover only an in-house sample, and that set is \
         pinned by membership rather than by size: {measured:?} round-trips the reference container \
         where {declared:?} is published"
    );

    for outcome in &outcomes {
        assert_eq!(
            outcome.committed_real_samples_fully_recovered,
            0,
            "{} fully recovers {} of its {} committed real sample(s). That is a real-tool win and \
             it must move to the `{REAL_TOOL_BAR}` leg instead of staying on the leg that says no \
             real sample is graded",
            outcome.family,
            outcome.committed_real_samples_fully_recovered,
            outcome.committed_real_samples
        );
    }

    let real: Vec<RealSampleOutcome> = measure_real_samples();
    let real_recovered: usize = real
        .iter()
        .filter(|outcome: &&RealSampleOutcome| outcome.peel_fully_recovered)
        .count();
    assert_eq!(
        real.len(),
        REAL_SAMPLE_DENOMINATOR,
        "the control must look at all {REAL_SAMPLE_DENOMINATOR} committed IronBrew2 samples, not {}",
        real.len()
    );
    assert_eq!(
        real_recovered, REAL_SAMPLES_COMPLETE_OPCODE_TABLE,
        "the claim that no in-house family fully recovers real output is only worth something if the \
         same measurement finds the family that does: `{REAL_TOOL_FAMILY}` reports full recovery on \
         {REAL_SAMPLES_COMPLETE_OPCODE_TABLE} of its {REAL_SAMPLE_DENOMINATOR} committed samples, \
         and this run found {real_recovered}. A run where nothing recovers would make the zeroes \
         above meaningless"
    );

    let membership: Vec<String> = {
        let mut lines: Vec<String> = outcomes
            .iter()
            .map(|outcome: &InHouseOutcome| {
                format!(
                    "{} reference_container_round_trip={} committed_real_samples={} \
                     committed_real_samples_fully_recovered={}",
                    outcome.family,
                    outcome.reference_container_round_trip,
                    outcome.committed_real_samples,
                    outcome.committed_real_samples_fully_recovered
                )
            })
            .collect();
        lines.sort();
        lines
    };
    compare_membership(IN_HOUSE_GOLDEN, &membership);
}

#[test]
fn recovered_real_ironbrew2_output_executes_like_the_original_under_real_lua() {
    let graded: String = format!(
        "the `{REAL_TOOL_BAR}` leg over {REAL_SAMPLE_DENOMINATOR} committed IronBrew2 samples"
    );
    let Some(interpreter): Option<LuaInterpreter> = lua_toolchain::require_interpreter(&graded)
    else {
        return;
    };
    eprintln!(
        "grading the real-tool leg with {} ({})",
        interpreter.program, interpreter.banner
    );

    let outcomes: Vec<RealSampleOutcome> = measure_real_samples();
    assert_eq!(
        outcomes.len(),
        REAL_SAMPLE_DENOMINATOR,
        "the execution differential must cover all {REAL_SAMPLE_DENOMINATOR} committed samples"
    );

    let mut equivalent: usize = 0;
    for outcome in &outcomes {
        let original: Vec<u8> =
            read_corpus_lua(&format!("{REAL_TOOL_FAMILY}/original/{}", outcome.original));
        let original: String = String::from_utf8(original)
            .unwrap_or_else(|err: std::string::FromUtf8Error| panic!("original not utf8: {err}"));
        let expected: String = run_lua(&interpreter, &outcome.original, &original);
        assert!(
            !expected.trim().is_empty(),
            "{}: the original prints nothing, so comparing stdout would pass on any recovered \
             program at all",
            outcome.sample
        );
        let actual: String = run_lua(&interpreter, &outcome.sample, &outcome.recovered_source);
        assert_eq!(
            actual.trim_end(),
            expected.trim_end(),
            "{}: the devirtualized program must print what the original prints\n--- recovered \
             ---\n{}",
            outcome.sample,
            outcome.recovered_source
        );
        equivalent += 1;
    }
    assert_eq!(
        equivalent, REAL_SAMPLE_DENOMINATOR,
        "the real-tool leg is published as every committed sample reaching output equivalence, and \
         {equivalent} of {REAL_SAMPLE_DENOMINATOR} did"
    );
}

static PANIC_HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn quietly<T>(probe: impl FnOnce() -> T + std::panic::UnwindSafe) -> std::thread::Result<T> {
    let guard: std::sync::MutexGuard<'_, ()> = PANIC_HOOK_LOCK
        .lock()
        .unwrap_or_else(|poisoned: std::sync::PoisonError<_>| poisoned.into_inner());
    let previous: Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send> =
        std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome: std::thread::Result<T> = std::panic::catch_unwind(probe);
    std::panic::set_hook(previous);
    drop(guard);
    outcome
}

fn candidate_document(bars: serde_json::Value) -> String {
    serde_json::json!({
        "groups": [{
            "heading": format!("{PUBLISHED_GROUP} (counts)"),
            "kind": "count",
            "bars": bars,
        }]
    })
    .to_string()
}

fn in_house_provenance() -> String {
    let families: Vec<&'static str> = IN_HOUSE_FAMILIES
        .into_iter()
        .map(|family: InHouseFamily| family.name)
        .collect();
    format!(
        "the DVM1 container is ours, so no real sample is graded for any of {}",
        families.join(", ")
    )
}

fn read_candidate(raw: &str) -> Publication {
    publication_from_bars(&bars_in_group(raw, Path::new("candidate")))
}

#[test]
fn both_published_shapes_read_back_as_the_legs_they_describe() {
    let split: String = candidate_document(serde_json::json!([
        {"label": REAL_TOOL_BAR, "value": 1, "source": "ironbrew2 real output"},
        {"label": IN_HOUSE_BAR, "value": 1, "source": in_house_provenance()},
    ]));
    assert_eq!(
        read_candidate(&split),
        Publication::Split {
            real: 1,
            in_house: 1
        },
        "the split shape is what this crate asks the chart to publish, so the reader must return \
         both legs; if this branch is wrong the two bars would be graded against nothing the moment \
         the chart is split"
    );

    let combined: String = candidate_document(serde_json::json!([
        {"label": COMBINED_BAR, "value": COMBINED_VALUE, "source": "one bar, both legs"},
    ]));
    assert_eq!(
        read_candidate(&combined),
        Publication::Combined {
            total: COMBINED_VALUE
        },
        "the combined shape must still read back while the chart carries one bar"
    );
}

#[test]
fn a_publication_that_hides_the_weak_leg_is_rejected() {
    let mixture: String = candidate_document(serde_json::json!([
        {"label": REAL_TOOL_BAR, "value": 1, "source": "real"},
        {"label": COMBINED_BAR, "value": 2, "source": "combined"},
    ]));
    let mixed: std::thread::Result<Publication> = quietly(|| read_candidate(&mixture));

    let unnamed: String = candidate_document(serde_json::json!([
        {"label": REAL_TOOL_BAR, "value": 1, "source": "real"},
        {"label": IN_HOUSE_BAR, "value": 1, "source": "no real sample is graded here"},
    ]));
    let families_missing: std::thread::Result<Publication> = quietly(|| read_candidate(&unnamed));

    let undisclosed: String = candidate_document(serde_json::json!([
        {"label": REAL_TOOL_BAR, "value": 1, "source": "real"},
        {"label": IN_HOUSE_BAR, "value": 1, "source": IN_HOUSE_FAMILIES
            .into_iter()
            .map(|family: InHouseFamily| family.name)
            .collect::<Vec<&str>>()
            .join(", ")},
    ]));
    let disclosure_missing: std::thread::Result<Publication> =
        quietly(|| read_candidate(&undisclosed));

    let duplicated: String = candidate_document(serde_json::json!([
        {"label": REAL_TOOL_BAR, "value": 1, "source": "real"},
        {"label": REAL_TOOL_BAR, "value": 9, "source": "real again"},
        {"label": IN_HOUSE_BAR, "value": 1, "source": in_house_provenance()},
    ]));
    let duplicate_label: std::thread::Result<Publication> = quietly(|| read_candidate(&duplicated));

    assert!(
        mixed.is_err(),
        "a chart carrying the combined bar next to the real-tool bar publishes the same family \
         twice, and the reader accepted it"
    );
    assert!(
        families_missing.is_err(),
        "the weak leg's provenance must name every family behind it; a provenance naming none of \
         them was accepted"
    );
    assert!(
        disclosure_missing.is_err(),
        "the weak leg's provenance must say the sample is ours; a provenance that only lists \
         families was accepted"
    );
    assert!(
        duplicate_label.is_err(),
        "two bars with the same label let one copy be graded while the other renders, and the \
         reader accepted it"
    );
}

#[test]
fn a_missing_interpreter_fails_the_execution_leg_when_ci_marks_it_mandatory() {
    use lua_toolchain::InterpreterRequirement;

    let graded: &str = "a case that must never report success without an interpreter";
    let defect: &str = "no interpreter was found on PATH";

    let mandatory: std::thread::Result<()> = quietly(|| {
        lua_toolchain::enforce_requirement(graded, defect, InterpreterRequirement::Mandatory);
    });
    let optional: std::thread::Result<()> = quietly(|| {
        lua_toolchain::enforce_requirement(graded, defect, InterpreterRequirement::Optional);
    });

    let payload: String = match &mandatory {
        Err(payload) => payload
            .downcast_ref::<String>()
            .map_or_else(String::new, Clone::clone),
        Ok(()) => String::new(),
    };
    assert!(
        mandatory.is_err(),
        "with {} set, an absent interpreter must fail the run; the gate returned success instead, \
         which is how an execution differential silently stops grading",
        lua_toolchain::REQUIRE_VAR
    );
    assert!(
        payload.contains(lua_toolchain::REQUIRE_VAR),
        "the failure must name {} so a CI log says how the run was made mandatory; it read: \
         {payload}",
        lua_toolchain::REQUIRE_VAR
    );
    assert!(
        optional.is_ok(),
        "without the variable set the gate announces that nothing was measured and lets the run \
         continue, so a developer without Lua installed is not blocked"
    );

    assert_eq!(
        lua_toolchain::requirement_from_value(None),
        InterpreterRequirement::Optional,
        "an unset variable must leave the interpreter optional"
    );
    assert_eq!(
        lua_toolchain::requirement_from_value(Some(std::ffi::OsStr::new("1"))),
        InterpreterRequirement::Mandatory,
        "{}=1 is what CI sets, so it must make the interpreter mandatory",
        lua_toolchain::REQUIRE_VAR
    );
    assert_eq!(
        lua_toolchain::requirement_from_value(Some(std::ffi::OsStr::new("0"))),
        InterpreterRequirement::Optional,
        "an explicit 0 must read as optional rather than as any non-empty value"
    );
}

#[test]
fn the_in_house_container_is_ours_and_carries_no_real_family_wire_format() {
    let family: InHouseFamily = IN_HOUSE_FAMILIES
        .into_iter()
        .find(|family: &InHouseFamily| family.name == "moonsec_v3")
        .expect("the MoonSec-shape leg must be on the in-house roster");
    let (boot, payload): (String, Vec<u8>) =
        dvm1_reference::bootstrap_with_payload(family.header, &family.recipe);

    assert!(
        payload.starts_with(disrobe_pass_lua::obfuscator::vm_devirt::VM_MAGIC),
        "the payload the weak leg is graded on is this crate's own container, so it must carry this \
         crate's own magic; if it ever carries a real MoonSec header the leg has become a real-tool \
         measurement and must move bars"
    );
    assert!(
        boot.contains("PERMBUILD="),
        "the in-house bootstrap declares its permutation builder in a field of our own design, \
         which is what makes this leg a sample we authored rather than MoonSec output"
    );
    assert!(
        boot.contains("MS_VM_ENTRY"),
        "the only MoonSec-specific thing about the weak leg is the marker string that routes it, \
         and that marker must stay visible in the bootstrap so nobody mistakes the container for \
         MoonSec's format"
    );
}

#[test]
fn the_real_tool_recovery_path_rejects_the_in_house_container() {
    let family: InHouseFamily = IN_HOUSE_FAMILIES
        .into_iter()
        .find(|family: &InHouseFamily| family.name == "moonsec_v3")
        .expect("the MoonSec-shape leg must be on the in-house roster");
    let (boot, _payload): (String, Vec<u8>) =
        dvm1_reference::bootstrap_with_payload(family.header, &family.recipe);

    let smuggled: bool =
        recover(&boot).is_ok_and(|program: RecoveredProgram| program.stats.fully_recovered());
    assert!(
        !smuggled,
        "the in-house container recovered through the real IronBrew2 path, which would let the weak \
         leg's sample be counted as a real-tool win; the two published legs must measure different \
         things"
    );

    let real: Vec<u8> = read_corpus_lua(&format!("{REAL_TOOL_FAMILY}/obfuscated/hello.min.lua"));
    let real: String = String::from_utf8(real)
        .unwrap_or_else(|err: std::string::FromUtf8Error| panic!("real sample not utf8: {err}"));
    let program: RecoveredProgram =
        recover(&real).unwrap_or_else(|err: disrobe_pass_lua::Error| {
            panic!("the real IronBrew2 path must still recover real output: {err}")
        });
    assert!(
        program.stats.fully_recovered(),
        "the rejection above is only meaningful if the same path accepts genuine IronBrew2 output, \
         and hello.min.lua did not fully recover"
    );

    let mut families: Vec<&'static str> = IN_HOUSE_FAMILIES
        .into_iter()
        .map(|entry: InHouseFamily| entry.name)
        .collect();
    families.push(REAL_TOOL_FAMILY);
    let distinct: BTreeSet<&&'static str> = families.iter().collect();
    assert_eq!(
        distinct.len(),
        families.len(),
        "`{REAL_TOOL_FAMILY}` appears on the in-house roster as well as the real-tool leg, so one \
         family would be counted by both published bars"
    );
    assert_eq!(
        families.len(),
        10,
        "this crate wires ten Lua families through the VM devirtualizer; if that changes, both \
         published legs have to be re-derived rather than left as they are"
    );
}
