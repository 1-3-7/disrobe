#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use common::{EvalOutcome, Terminal, try_eval_outcome_with_argv};

use disrobe_pass_js_deob::{
    JscramblerTransform, JscramblerTransformOpts, JscramblerTransformOutput,
    JscramblerTransformStats, Result as JscramblerResult, TemplateOutput,
    deobfuscate_jscrambler_transform_strict, deobfuscate_template_advanced_obfuscation,
    deobfuscate_template_anti_tampering_and_debugging, deobfuscate_template_browser_lock,
    deobfuscate_template_date_lock, deobfuscate_template_dead_objects,
    deobfuscate_template_domain_lock, deobfuscate_template_light_obfuscation,
    deobfuscate_template_minification, deobfuscate_template_obfuscation,
    deobfuscate_template_os_lock, deobfuscate_template_self_defending,
    deobfuscate_template_self_healing,
};
use oxc_allocator::Allocator;
use oxc_ast::AstKind;
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;

const PRODUCT_VERSION: &str = "8.5";
const ACQUISITION_SWEEP: &str = "2026-08-05";
const SAMPLES_ROOT: &str = "src/javascript/jscrambler-samples";
const WITNESS_TEMPLATE: &str = "minification";
const ACQUIRED_TEMPLATE_COUNT: usize = 7;
const TEMPLATE_COUNT: usize = 12;
const WITNESS_LITERAL_FLOOR: usize = 30;
const MIN_WITNESS_LITERAL_LEN: usize = 3;
const FIRST_BREAKING_STEP: Option<JscramblerTransform> = Some(JscramblerTransform::VariableMasking);
#[cfg(feature = "chain")]
const CATALOG_ENTRY_FOR_REAL_OUTPUT: Option<&str> = Some("js-jscrambler");

const SETTINGS_ADVANCED: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-advanced-obfuscation.json"
);
const SETTINGS_ANTI_TAMPERING: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-anti-tampering-and-debugging.json"
);
const SETTINGS_BROWSER_LOCK: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-browser-lock.json"
);
const SETTINGS_DATE_LOCK: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-date-lock.json"
);
const SETTINGS_DEAD_OBJECTS: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-dead-objects.json"
);
const SETTINGS_DOMAIN_LOCK: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-domain-lock.json"
);
const SETTINGS_LIGHT: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-light-obfuscation.json"
);
const SETTINGS_MINIFICATION: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-minification.json"
);
const SETTINGS_OBFUSCATION: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-obfuscation.json"
);
const SETTINGS_OS_LOCK: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-os-lock.json"
);
const SETTINGS_SELF_DEFENDING: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-self-defending.json"
);
const SETTINGS_SELF_HEALING: &str = include_str!(
    "../../../corpus/src/javascript/jscrambler-samples/_settings/template-self-healing.json"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    IdentifierRenaming,
    StringConcealing,
    StringSplitting,
    ControlFlowFlattening,
    DeadCodeInjection,
    DeadObjectInsertion,
    SelfDefending,
    SelfHealing,
    AntiDebugging,
    BrowserLock,
    DateLock,
    DomainLock,
    OsLock,
}

const ALL_FAMILIES: &[Family] = &[
    Family::IdentifierRenaming,
    Family::StringConcealing,
    Family::StringSplitting,
    Family::ControlFlowFlattening,
    Family::DeadCodeInjection,
    Family::DeadObjectInsertion,
    Family::SelfDefending,
    Family::SelfHealing,
    Family::AntiDebugging,
    Family::BrowserLock,
    Family::DateLock,
    Family::DomainLock,
    Family::OsLock,
];

const UNGRADED_FAMILIES: &[Family] = &[
    Family::StringSplitting,
    Family::ControlFlowFlattening,
    Family::DeadCodeInjection,
    Family::SelfHealing,
    Family::DateLock,
    Family::DomainLock,
    Family::OsLock,
];

fn family_for_param(param: &str) -> Option<Family> {
    match param {
        "identifiersRenaming" => Some(Family::IdentifierRenaming),
        "stringConcealing" => Some(Family::StringConcealing),
        "stringSplitting" => Some(Family::StringSplitting),
        "controlFlowFlattening" => Some(Family::ControlFlowFlattening),
        "deadCodeInjection" => Some(Family::DeadCodeInjection),
        "deadObjects" => Some(Family::DeadObjectInsertion),
        "selfDefending" => Some(Family::SelfDefending),
        "selfHealing" => Some(Family::SelfHealing),
        "antiDebugging" => Some(Family::AntiDebugging),
        "browserLock" => Some(Family::BrowserLock),
        "dateLock" => Some(Family::DateLock),
        "domainLock" => Some(Family::DomainLock),
        "osLock" => Some(Family::OsLock),
        _ => None,
    }
}

const UNPUBLISHED: &str = "the acquired Jscrambler 8.5 template set publishes a protected bundle \
                           for seven of the twelve profiles; this profile ships its settings file \
                           only, so no protected bytes exist to grade";

#[derive(Debug, Clone, Copy)]
enum Provenance {
    Acquired {
        directory: &'static str,
        sha256: &'static str,
    },
    Unacquired {
        attempted: &'static str,
        reason: &'static str,
    },
}

type TemplateChain = fn(&str, &JscramblerTransformOpts) -> JscramblerResult<TemplateOutput>;

#[derive(Debug)]
struct Template {
    name: &'static str,
    settings: &'static str,
    chain: TemplateChain,
    provenance: Provenance,
}

static TEMPLATES: &[Template] = &[
    Template {
        name: "advanced-obfuscation",
        settings: SETTINGS_ADVANCED,
        chain: deobfuscate_template_advanced_obfuscation,
        provenance: Provenance::Acquired {
            directory: "advanced-obfuscation",
            sha256: "3cd57fbfbb9b24ce25ae7e80096e493784202bffa7fe4d436b684e2bcc18d519",
        },
    },
    Template {
        name: "anti-tampering-and-debugging",
        settings: SETTINGS_ANTI_TAMPERING,
        chain: deobfuscate_template_anti_tampering_and_debugging,
        provenance: Provenance::Acquired {
            directory: "anti-tampering-debugging",
            sha256: "daa524b7ddc1256c31a62d91cc22eeddd139a1ae758c72cd4e64965772608a16",
        },
    },
    Template {
        name: "browser-lock",
        settings: SETTINGS_BROWSER_LOCK,
        chain: deobfuscate_template_browser_lock,
        provenance: Provenance::Unacquired {
            attempted: ACQUISITION_SWEEP,
            reason: UNPUBLISHED,
        },
    },
    Template {
        name: "date-lock",
        settings: SETTINGS_DATE_LOCK,
        chain: deobfuscate_template_date_lock,
        provenance: Provenance::Unacquired {
            attempted: ACQUISITION_SWEEP,
            reason: UNPUBLISHED,
        },
    },
    Template {
        name: "dead-objects",
        settings: SETTINGS_DEAD_OBJECTS,
        chain: deobfuscate_template_dead_objects,
        provenance: Provenance::Acquired {
            directory: "dead-objects",
            sha256: "14a7d4284b555f2b506b02679570ad0a4ccd8620d796e581427c824b8988b0c5",
        },
    },
    Template {
        name: "domain-lock",
        settings: SETTINGS_DOMAIN_LOCK,
        chain: deobfuscate_template_domain_lock,
        provenance: Provenance::Unacquired {
            attempted: ACQUISITION_SWEEP,
            reason: UNPUBLISHED,
        },
    },
    Template {
        name: "light-obfuscation",
        settings: SETTINGS_LIGHT,
        chain: deobfuscate_template_light_obfuscation,
        provenance: Provenance::Acquired {
            directory: "light-obfuscation",
            sha256: "563eabaa229c97418a435cbe5c187c07c3978f3addd479e99c1e22d08a1a17e8",
        },
    },
    Template {
        name: WITNESS_TEMPLATE,
        settings: SETTINGS_MINIFICATION,
        chain: deobfuscate_template_minification,
        provenance: Provenance::Acquired {
            directory: WITNESS_TEMPLATE,
            sha256: "b12a7bd3370f5a4527506d4e0702bd1ba06c8d1fd6e986c2f5e9b16d58cdf7a9",
        },
    },
    Template {
        name: "obfuscation",
        settings: SETTINGS_OBFUSCATION,
        chain: deobfuscate_template_obfuscation,
        provenance: Provenance::Acquired {
            directory: "obfuscation",
            sha256: "35e5f2234ae2f5940c1930ba11f60fcbb2c0fc099ae313388bf94366ed0719e8",
        },
    },
    Template {
        name: "os-lock",
        settings: SETTINGS_OS_LOCK,
        chain: deobfuscate_template_os_lock,
        provenance: Provenance::Unacquired {
            attempted: ACQUISITION_SWEEP,
            reason: UNPUBLISHED,
        },
    },
    Template {
        name: "self-defending",
        settings: SETTINGS_SELF_DEFENDING,
        chain: deobfuscate_template_self_defending,
        provenance: Provenance::Acquired {
            directory: "self-defending",
            sha256: "a5046f733506f4352d8aac08279415e985a2516147d97beae2cc7d56e89135d8",
        },
    },
    Template {
        name: "self-healing",
        settings: SETTINGS_SELF_HEALING,
        chain: deobfuscate_template_self_healing,
        provenance: Provenance::Unacquired {
            attempted: ACQUISITION_SWEEP,
            reason: UNPUBLISHED,
        },
    },
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut message: Vec<u8> = bytes.to_vec();
    let bit_length: u64 = (bytes.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut schedule: [u32; 64] = [0; 64];
        for (index, word) in schedule.iter_mut().take(16).enumerate() {
            let start: usize = index * 4;
            *word = u32::from_be_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }
        for index in 16..64 {
            let previous: u32 = schedule[index - 15];
            let recent: u32 = schedule[index - 2];
            let sigma0: u32 =
                previous.rotate_right(7) ^ previous.rotate_right(18) ^ (previous >> 3);
            let sigma1: u32 = recent.rotate_right(17) ^ recent.rotate_right(19) ^ (recent >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(sigma0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(sigma1);
        }
        let mut working: [u32; 8] = state;
        for (index, constant) in SHA256_ROUND_CONSTANTS.iter().enumerate() {
            let sum1: u32 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choose: u32 = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp1: u32 = working[7]
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(*constant)
                .wrapping_add(schedule[index]);
            let sum0: u32 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority: u32 =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2: u32 = sum0.wrapping_add(majority);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip(working) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut hex: String = String::with_capacity(64);
    for word in state {
        for byte in word.to_be_bytes() {
            hex.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            hex.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    hex
}

fn corpus_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(relative)
}

fn sample_relative(directory: &str) -> String {
    format!("{SAMPLES_ROOT}/templates/{directory}/protected.common.js")
}

fn read_sample(directory: &str) -> String {
    let path: PathBuf = corpus_path(&sample_relative(directory));
    fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("{}: {error}", path.display()))
}

fn settings_params(blob: &str) -> Vec<String> {
    let parsed: serde_json::Value =
        serde_json::from_str(blob).expect("template settings must be valid JSON");
    let params: &Vec<serde_json::Value> = parsed
        .get("params")
        .and_then(serde_json::Value::as_array)
        .expect("template settings must declare a params array");
    assert!(
        !params.is_empty(),
        "template params array must be non-empty"
    );
    params
        .iter()
        .map(|param: &serde_json::Value| {
            param
                .get("name")
                .and_then(serde_json::Value::as_str)
                .expect("every params entry must carry a name")
                .to_owned()
        })
        .collect()
}

fn settings_version(blob: &str) -> String {
    let parsed: serde_json::Value =
        serde_json::from_str(blob).expect("template settings must be valid JSON");
    parsed
        .get("jscramblerVersion")
        .and_then(serde_json::Value::as_str)
        .expect("template settings must record the Jscrambler product version")
        .to_owned()
}

fn families_of(template: &Template) -> BTreeSet<Family> {
    settings_params(template.settings)
        .iter()
        .filter_map(|param: &String| family_for_param(param))
        .collect()
}

fn parse_diagnostic(source: &str) -> Option<String> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return Some("parser panicked".to_owned());
    }
    parsed
        .errors
        .first()
        .map(|error: &oxc::diagnostics::OxcDiagnostic| format!("{error}"))
}

fn reparses(source: &str) -> bool {
    parse_diagnostic(source).is_none()
}

fn plain_literals(source: &str) -> BTreeSet<String> {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("literals.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return BTreeSet::new();
    }
    let built: oxc_semantic::SemanticBuilderReturn<'_> =
        SemanticBuilder::new().build(&parsed.program);
    let mut literals: BTreeSet<String> = BTreeSet::new();
    for node in built.semantic.nodes().iter() {
        if let AstKind::StringLiteral(literal) = node.kind() {
            let value: &str = literal.value.as_str();
            if value.len() >= MIN_WITNESS_LITERAL_LEN {
                literals.insert(value.to_owned());
            }
        }
    }
    literals
}

fn recall_percent(witness: &BTreeSet<String>, candidate: &BTreeSet<String>) -> f64 {
    if witness.is_empty() {
        return 0.0;
    }
    let hits: usize = witness
        .iter()
        .filter(|literal: &&String| candidate.contains(*literal))
        .count();
    (hits as f64) * 100.0 / (witness.len() as f64)
}

fn escape_sequences(source: &str) -> usize {
    source.matches("\\x").count() + source.matches("\\u").count()
}

#[derive(Debug, Clone, Copy)]
struct Measurement {
    protected_recall: f64,
    recovered_recall: f64,
    protected_escapes: usize,
    recovered_escapes: usize,
    reparsed: bool,
    changed: bool,
}

fn measure(template: &Template, witness: &BTreeSet<String>) -> Option<Measurement> {
    let Provenance::Acquired { directory, .. } = template.provenance else {
        return None;
    };
    let protected: String = read_sample(directory);
    let out: TemplateOutput = (template.chain)(&protected, &JscramblerTransformOpts::default())
        .unwrap_or_else(|error: disrobe_pass_js_deob::Error| {
            panic!("{}: template chain failed: {error}", template.name)
        });
    Some(Measurement {
        protected_recall: recall_percent(witness, &plain_literals(&protected)),
        recovered_recall: recall_percent(witness, &plain_literals(&out.source)),
        protected_escapes: escape_sequences(&protected),
        recovered_escapes: escape_sequences(&out.source),
        reparsed: reparses(&out.source),
        changed: out.source != protected,
    })
}

fn witness_literals() -> BTreeSet<String> {
    let witness: String = read_sample(WITNESS_TEMPLATE);
    let literals: BTreeSet<String> = plain_literals(&witness);
    assert!(
        literals.len() >= WITNESS_LITERAL_FLOOR,
        "the minification witness must expose the original program's literals; got {}",
        literals.len()
    );
    literals
}

fn saw(out: &TemplateOutput, transform: JscramblerTransform) -> bool {
    out.per_transform
        .iter()
        .any(|(kind, _): &(JscramblerTransform, JscramblerTransformStats)| *kind == transform)
}

#[test]
fn sha256_matches_published_test_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn every_template_settings_file_parses_and_pins_the_product_version() {
    assert_eq!(TEMPLATES.len(), TEMPLATE_COUNT);
    for template in TEMPLATES {
        let params: Vec<String> = settings_params(template.settings);
        assert!(
            !params.is_empty(),
            "{}: settings must declare parameters",
            template.name
        );
        assert_eq!(
            settings_version(template.settings),
            PRODUCT_VERSION,
            "{}: every fixture records the Jscrambler product version that produced it",
            template.name
        );
    }
}

#[test]
fn acquired_samples_match_their_recorded_digests() {
    let mut acquired: usize = 0;
    for template in TEMPLATES {
        let Provenance::Acquired { directory, sha256 } = template.provenance else {
            continue;
        };
        let relative: String = sample_relative(directory);
        let bytes: Vec<u8> = fs::read(corpus_path(&relative))
            .unwrap_or_else(|error: std::io::Error| panic!("{relative}: {error}"));
        assert_eq!(
            sha256_hex(&bytes),
            sha256,
            "{}: the committed protected bytes are not the ones every recorded figure was \
             measured against; restore them, or re-measure every figure and re-pin the digest in \
             the same change",
            template.name
        );
        acquired += 1;
    }
    assert_eq!(
        acquired, ACQUIRED_TEMPLATE_COUNT,
        "the acquired sample count is pinned by equality so a dropped fixture cannot silently \
         shrink the graded denominator"
    );
}

#[test]
fn unacquired_templates_record_their_acquisition_attempt() {
    let mut unacquired: usize = 0;
    for template in TEMPLATES {
        let Provenance::Unacquired { attempted, reason } = template.provenance else {
            continue;
        };
        assert_eq!(attempted, ACQUISITION_SWEEP);
        assert!(!reason.is_empty());
        assert!(
            !corpus_path(&sample_relative(template.name)).exists(),
            "{}: recorded as unacquired while a protected sample is present",
            template.name
        );
        unacquired += 1;
    }
    assert_eq!(unacquired, TEMPLATE_COUNT - ACQUIRED_TEMPLATE_COUNT);
}

#[test]
fn every_transform_family_is_graded_or_recorded_ungraded() {
    let mut graded: BTreeSet<Family> = BTreeSet::new();
    for template in TEMPLATES {
        let families: BTreeSet<Family> = families_of(template);
        if matches!(template.provenance, Provenance::Acquired { .. }) {
            graded.extend(families);
        }
    }
    let ungraded: Vec<Family> = ALL_FAMILIES
        .iter()
        .copied()
        .filter(|family: &Family| !graded.contains(family))
        .collect();
    eprintln!("graded transform families: {graded:?}");
    eprintln!("ungraded transform families: {ungraded:?}");
    assert_eq!(
        ungraded, UNGRADED_FAMILIES,
        "the ungraded transform families must stay exactly as recorded; a family that gains or \
         loses a graded sample moves in this list in the same change"
    );
    for family in ALL_FAMILIES {
        assert!(
            graded.contains(family) || ungraded.contains(family),
            "{family:?} is neither graded nor recorded ungraded"
        );
    }
}

#[test]
fn literal_recall_measure_is_not_vacuous() {
    let witness: BTreeSet<String> = witness_literals();
    let stripped: BTreeSet<String> = BTreeSet::new();
    assert!(recall_percent(&witness, &stripped).abs() < f64::EPSILON);
    assert!((recall_percent(&witness, &witness) - 100.0).abs() < f64::EPSILON);
    let protected: String = read_sample("obfuscation");
    let protected_recall: f64 = recall_percent(&witness, &plain_literals(&protected));
    assert!(
        protected_recall < 100.0,
        "the obfuscation template must conceal part of the original literal set, otherwise the \
         measure grades nothing; protected recall was {protected_recall:.1}%"
    );
}

#[test]
fn acquired_templates_recover_measurably_against_the_minification_witness() {
    let witness: BTreeSet<String> = witness_literals();
    let mut measurements: BTreeMap<&'static str, Measurement> = BTreeMap::new();
    for template in TEMPLATES {
        let Some(measurement): Option<Measurement> = measure(template, &witness) else {
            continue;
        };
        eprintln!(
            "  {name}: witness literal recall {before:.1}% protected -> {after:.1}% recovered, escapes {escapes_before} -> {escapes_after}, reparsed={reparsed}, rewritten={changed}",
            name = template.name,
            before = measurement.protected_recall,
            after = measurement.recovered_recall,
            escapes_before = measurement.protected_escapes,
            escapes_after = measurement.recovered_escapes,
            reparsed = measurement.reparsed,
            changed = measurement.changed,
        );
        measurements.insert(template.name, measurement);
    }
    assert_eq!(measurements.len(), ACQUIRED_TEMPLATE_COUNT);
    for (name, measurement) in &measurements {
        assert!(
            measurement.reparsed,
            "{name}: recovered output must still parse as JavaScript"
        );
        assert!(
            measurement.recovered_recall >= measurement.protected_recall,
            "{name}: recovery lost literals the protected input still exposed ({:.1}% -> {:.1}%)",
            measurement.protected_recall,
            measurement.recovered_recall
        );
        assert!(
            measurement.recovered_escapes <= measurement.protected_escapes,
            "{name}: recovery added escape sequences instead of folding them ({} -> {})",
            measurement.protected_escapes,
            measurement.recovered_escapes
        );
    }
    let full_literal_recovery: Vec<&&str> = measurements
        .iter()
        .filter(|(_, measurement): &(&&str, &Measurement)| {
            measurement.recovered_recall > measurement.protected_recall
        })
        .map(|(name, _): (&&str, &Measurement)| name)
        .collect();
    let escape_folding: Vec<&&str> = measurements
        .iter()
        .filter(|(_, measurement): &(&&str, &Measurement)| {
            measurement.recovered_escapes < measurement.protected_escapes
        })
        .map(|(name, _): (&&str, &Measurement)| name)
        .collect();
    eprintln!("templates that raise literal recall: {full_literal_recovery:?}");
    eprintln!("templates that fold escape sequences: {escape_folding:?}");
    assert!(
        full_literal_recovery.is_empty(),
        "a template now raises literal recall on real Jscrambler output; re-measure the catalog \
         quality in the same change: {full_literal_recovery:?}"
    );
    assert!(
        !escape_folding.is_empty(),
        "no acquired template folds a single escape sequence, which is below the partial support \
         the catalog records"
    );
}

const ORIGINAL_FILE_NAMES: &[&str] = &["source.js", "original.js", "src.js", "source.zip"];
const BEHAVIOR_PRESERVED_COUNT: usize = 3;

#[derive(Debug, Clone)]
enum BehaviorVerdict {
    Preserved,
    NotComparable(String),
    Diverged(String),
}

fn comparable(outcome: &EvalOutcome) -> Option<String> {
    match &outcome.terminal {
        Terminal::ParseFailed { kind, message } => Some(format!(
            "Boa cannot parse it as a script: {kind}: {message}"
        )),
        Terminal::ObservationLimitExceeded(reason) => {
            Some(format!("observation limit reached: {reason}"))
        }
        Terminal::Completed(_) | Terminal::Threw { .. } | Terminal::ExecutionLimitExceeded => None,
    }
}

fn grade_behavior(protected: &str, recovered: &str) -> BehaviorVerdict {
    let before: EvalOutcome = match try_eval_outcome_with_argv(protected, &[]) {
        Ok(outcome) => outcome,
        Err(reason) => {
            return BehaviorVerdict::NotComparable(format!("protected input: {reason}"));
        }
    };
    if let Some(reason) = comparable(&before) {
        return BehaviorVerdict::NotComparable(format!("protected input: {reason}"));
    }
    let after: EvalOutcome = match try_eval_outcome_with_argv(recovered, &[]) {
        Ok(outcome) => outcome,
        Err(reason) => {
            return BehaviorVerdict::Diverged(format!("recovered output: {reason}"));
        }
    };
    if before == after {
        return BehaviorVerdict::Preserved;
    }
    BehaviorVerdict::Diverged(format!(
        "--protected--\n{before:?}\n--recovered--\n{after:?}"
    ))
}

#[test]
fn no_template_ships_an_original_so_source_level_grading_is_impossible() {
    let mut with_original: Vec<&'static str> = Vec::new();
    for template in TEMPLATES {
        let Provenance::Acquired { directory, .. } = template.provenance else {
            continue;
        };
        for candidate in ORIGINAL_FILE_NAMES {
            let relative: String = format!("{SAMPLES_ROOT}/templates/{directory}/{candidate}");
            if corpus_path(&relative).exists() {
                with_original.push(template.name);
                break;
            }
        }
    }
    assert!(
        with_original.is_empty(),
        "these templates now ship an original, so their recovery must be graded against that \
         original instead of by literal recall and behavior preservation; raise the grading in the \
         same change that adds the file: {with_original:?}"
    );
    eprintln!(
        "the acquired Jscrambler {PRODUCT_VERSION} template set publishes protected bundles only, \
         so no template can be graded against an original source; the graded properties are \
         literal recall against the minification witness, escape folding, re-parse, and behavior \
         preservation under a real engine"
    );
}

#[test]
fn recovery_preserves_behavior_of_every_acquired_template_under_a_real_engine() {
    let mut preserved: Vec<&'static str> = Vec::new();
    let mut not_comparable: Vec<String> = Vec::new();
    let mut diverged: Vec<String> = Vec::new();
    let verdicts: Vec<(&'static str, BehaviorVerdict)> = std::thread::scope(
        |scope: &std::thread::Scope<'_, '_>| -> Vec<(&'static str, BehaviorVerdict)> {
            let mut handles: Vec<
                std::thread::ScopedJoinHandle<'_, (&'static str, BehaviorVerdict)>,
            > = Vec::with_capacity(ACQUIRED_TEMPLATE_COUNT);
            for template in TEMPLATES {
                let Provenance::Acquired { directory, .. } = template.provenance else {
                    continue;
                };
                handles.push(scope.spawn(move || -> (&'static str, BehaviorVerdict) {
                    let protected: String = read_sample(directory);
                    let out: TemplateOutput =
                        (template.chain)(&protected, &JscramblerTransformOpts::default())
                            .unwrap_or_else(|error: disrobe_pass_js_deob::Error| {
                                panic!("{}: template chain failed: {error}", template.name)
                            });
                    (template.name, grade_behavior(&protected, &out.source))
                }));
            }
            let mut verdicts: Vec<(&'static str, BehaviorVerdict)> =
                Vec::with_capacity(handles.len());
            for handle in handles {
                verdicts.push(handle.join().expect("behavior grading thread must finish"));
            }
            verdicts
        },
    );
    for (name, verdict) in verdicts {
        match verdict {
            BehaviorVerdict::Preserved => {
                eprintln!("  behavior preserved: {name}");
                preserved.push(name);
            }
            BehaviorVerdict::NotComparable(reason) => {
                not_comparable.push(format!("{name}: {reason}"));
            }
            BehaviorVerdict::Diverged(reason) => {
                diverged.push(format!("{name}: {reason}"));
            }
        }
    }
    for reason in &not_comparable {
        eprintln!("  not comparable: {reason}");
    }
    eprintln!(
        "behavior preservation under a real engine: {} preserved, {} not comparable, {} diverged (of {ACQUIRED_TEMPLATE_COUNT} acquired templates)",
        preserved.len(),
        not_comparable.len(),
        diverged.len()
    );
    assert!(
        diverged.is_empty(),
        "recovery changed what real Jscrambler output does:\n\n{}",
        diverged.join("\n\n")
    );
    assert_eq!(
        preserved.len(),
        BEHAVIOR_PRESERVED_COUNT,
        "the behaviorally graded template count is pinned by equality, so a template that stops \
         executing cannot silently leave the measurement"
    );
    assert_eq!(
        preserved.len() + not_comparable.len(),
        ACQUIRED_TEMPLATE_COUNT
    );
}

#[test]
fn behavior_preservation_rejects_a_deliberately_broken_recovery() {
    let protected: String = read_sample("minification");
    let out: TemplateOutput =
        deobfuscate_template_minification(&protected, &JscramblerTransformOpts::default())
            .expect("minification template runs");
    assert!(matches!(
        grade_behavior(&protected, &out.source),
        BehaviorVerdict::Preserved
    ));
    let broken: String = format!("console.log('injected');\n{}", out.source);
    assert!(
        matches!(
            grade_behavior(&protected, &broken),
            BehaviorVerdict::Diverged(_)
        ),
        "a recovery that adds an observable effect must fail behavior preservation, otherwise the \
         comparison grades nothing"
    );
}

#[cfg(feature = "chain")]
#[test]
fn catalog_quality_matches_the_measured_jscrambler_result() {
    use disrobe_core::chain::{CatalogEntry, DetectContext, ObfuscatorCatalog, SupportQuality};
    use disrobe_pass_js_deob::JsObfDetector;

    let entries: Vec<&'static dyn CatalogEntry> = JsObfDetector.catalog();
    let jscrambler: &&dyn CatalogEntry = entries
        .iter()
        .find(|entry: &&&dyn CatalogEntry| entry.id() == "js-jscrambler")
        .expect("the catalog lists Jscrambler");
    assert_eq!(
        jscrambler.support_quality(),
        SupportQuality::Partial,
        "the twelve-template measurement recovers no concealed original literal from real \
         Jscrambler 8.5 output, so the catalog cannot claim full support"
    );

    let protected: String = read_sample("obfuscation");
    let context: DetectContext<'_> = DetectContext {
        bytes: protected.as_bytes(),
        path_hint: None,
        parent_hint: None,
        depth: 0,
    };
    let detection: disrobe_pass_js_deob::Detection =
        disrobe_pass_js_deob::detect(protected.as_bytes());
    eprintln!(
        "  real Jscrambler 8.5 obfuscation template detects as {family:?} at {confidence} with markers {markers:?}",
        family = detection.family,
        confidence = detection.confidence,
        markers = detection.markers,
    );
    let detected: Option<disrobe_core::chain::DetectorOutput> =
        ObfuscatorCatalog::detect(&JsObfDetector, &context);
    assert_eq!(
        detected.map(|output: disrobe_core::chain::DetectorOutput| output.entry_id),
        CATALOG_ENTRY_FOR_REAL_OUTPUT,
        "the catalog entry that real Jscrambler output reaches must stay as recorded"
    );
}

#[test]
fn first_chain_step_that_breaks_real_output_is_located() {
    let probe: TemplateOutput =
        deobfuscate_template_obfuscation("var x = 1;", &JscramblerTransformOpts::default())
            .expect("chain order probe runs");
    let order: Vec<JscramblerTransform> = probe
        .per_transform
        .iter()
        .map(|(kind, _): &(JscramblerTransform, JscramblerTransformStats)| *kind)
        .collect();
    let mut current: String = read_sample("obfuscation");
    assert!(reparses(&current), "the protected sample must parse first");
    let mut culprit: Option<JscramblerTransform> = None;
    for transform in order {
        let stepped: JscramblerTransformOutput = match deobfuscate_jscrambler_transform_strict(
            transform,
            &current,
            &JscramblerTransformOpts::default(),
        ) {
            Ok(stepped) => stepped,
            Err(error) => {
                eprintln!("  {transform:?}: strict reverse refused: {error}");
                continue;
            }
        };
        current = stepped.source;
        if !reparses(&current) {
            culprit = Some(transform);
            eprintln!(
                "  {transform:?}: first step whose output stops parsing: {:?}",
                parse_diagnostic(&current)
            );
            break;
        }
    }
    assert_eq!(
        culprit, FIRST_BREAKING_STEP,
        "the recorded first breaking chain step must match the measured one"
    );
}

#[test]
fn template_advanced_obfuscation_chain_runs_with_control_flow_flattening() {
    let src: &str = "var x = 1; function f(){ return x; }";
    let out: TemplateOutput =
        deobfuscate_template_advanced_obfuscation(src, &JscramblerTransformOpts::default())
            .expect("advanced obfuscation template runs");
    assert!(saw(&out, JscramblerTransform::ControlFlowFlattening));
    assert!(saw(&out, JscramblerTransform::BrowserLock));
}

#[test]
fn template_anti_tampering_and_debugging_chain_includes_anti_debugging() {
    let src: &str = "function f(){ debugger; return 1; }";
    let out: TemplateOutput =
        deobfuscate_template_anti_tampering_and_debugging(src, &JscramblerTransformOpts::default())
            .expect("anti tampering template runs");
    assert!(saw(&out, JscramblerTransform::AntiDebugging));
    assert!(saw(&out, JscramblerTransform::AntiTampering));
}

#[test]
fn template_browser_lock_chain_includes_browser_lock_step() {
    let src: &str = "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }";
    let out: TemplateOutput =
        deobfuscate_template_browser_lock(src, &JscramblerTransformOpts::default())
            .expect("browser lock template runs");
    assert!(saw(&out, JscramblerTransform::BrowserLock));
}

#[test]
fn template_date_lock_chain_includes_date_lock_step() {
    let src: &str = "if (Date.now() > 1) { x(); }";
    let out: TemplateOutput =
        deobfuscate_template_date_lock(src, &JscramblerTransformOpts::default())
            .expect("date lock template runs");
    assert!(saw(&out, JscramblerTransform::DateLock));
}

#[test]
fn template_dead_objects_chain_includes_dead_objects_step_and_skips_unauthorized() {
    let src: &str = "var __deadX = { a: 1 };";
    let out: TemplateOutput =
        deobfuscate_template_dead_objects(src, &JscramblerTransformOpts::default())
            .expect("dead objects template runs");
    let dead_stats: &JscramblerTransformStats = out
        .per_transform
        .iter()
        .find(
            |(kind, _): &&(JscramblerTransform, JscramblerTransformStats)| {
                *kind == JscramblerTransform::DeadObjects
            },
        )
        .map(|(_, stats): &(JscramblerTransform, JscramblerTransformStats)| stats)
        .expect("dead objects step recorded");
    assert!(dead_stats.skipped >= 1);
}

#[test]
fn template_domain_lock_chain_includes_domain_lock_step() {
    let src: &str = "if (location.hostname !== 'x') { y(); }";
    let out: TemplateOutput =
        deobfuscate_template_domain_lock(src, &JscramblerTransformOpts::default())
            .expect("domain lock template runs");
    assert!(saw(&out, JscramblerTransform::DomainLock));
}

#[test]
fn template_light_obfuscation_handles_hex_strings_and_booleans() {
    let src: &str = r"var s = '\x68\x69'; if (![]) { run(); }";
    let out: TemplateOutput =
        deobfuscate_template_light_obfuscation(src, &JscramblerTransformOpts::default())
            .expect("light obfuscation template runs");
    assert!(out.source.contains("'hi'") || out.source.contains("\"hi\""));
    assert!(out.source.contains("false"));
}

#[test]
fn template_minification_chains_rename_and_whitespace() {
    let src: &str = "var a0_0xabcd = 1;";
    let out: TemplateOutput =
        deobfuscate_template_minification(src, &JscramblerTransformOpts::default())
            .expect("minification template runs");
    assert!(out.source.contains("v_1"));
    assert_eq!(out.per_transform.len(), 2);
}

#[test]
fn template_obfuscation_chain_runs_full_pipeline() {
    let src: &str = "var x = 1;";
    let out: TemplateOutput =
        deobfuscate_template_obfuscation(src, &JscramblerTransformOpts::default())
            .expect("obfuscation template runs");
    assert!(out.per_transform.len() >= 10);
}

#[test]
fn template_os_lock_chain_includes_os_lock_step() {
    let src: &str = "if (navigator.platform !== 'Win32') { stop(); }";
    let out: TemplateOutput =
        deobfuscate_template_os_lock(src, &JscramblerTransformOpts::default())
            .expect("os lock template runs");
    assert!(saw(&out, JscramblerTransform::OsLock));
}

#[test]
fn template_self_defending_chain_includes_self_defending_step() {
    let src: &str = "var x = 1;";
    let out: TemplateOutput =
        deobfuscate_template_self_defending(src, &JscramblerTransformOpts::default())
            .expect("self defending template runs");
    assert!(saw(&out, JscramblerTransform::SelfDefending));
}

#[test]
fn template_self_healing_chain_includes_self_healing_step() {
    let src: &str = "var x = 1;";
    let out: TemplateOutput =
        deobfuscate_template_self_healing(src, &JscramblerTransformOpts::default())
            .expect("self healing template runs");
    assert!(saw(&out, JscramblerTransform::SelfHealing));
}
