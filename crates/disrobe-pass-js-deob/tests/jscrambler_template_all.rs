#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    JscramblerTransform, JscramblerTransformOpts, TemplateOutput,
    deobfuscate_template_advanced_obfuscation, deobfuscate_template_anti_tampering_and_debugging,
    deobfuscate_template_browser_lock, deobfuscate_template_date_lock,
    deobfuscate_template_dead_objects, deobfuscate_template_domain_lock,
    deobfuscate_template_light_obfuscation, deobfuscate_template_minification,
    deobfuscate_template_obfuscation, deobfuscate_template_os_lock,
    deobfuscate_template_self_defending, deobfuscate_template_self_healing,
};

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

fn settings_parses(blob: &str) {
    let parsed: serde_json::Value =
        serde_json::from_str(blob).expect("template settings must be valid JSON");
    let params: &serde_json::Value = parsed
        .get("params")
        .expect("template settings must declare params");
    assert!(params.is_array(), "params must be a JSON array");
    let arr: &Vec<serde_json::Value> = params.as_array().expect("array");
    assert!(!arr.is_empty(), "template params array must be non-empty");
}

fn saw(out: &TemplateOutput, t: JscramblerTransform) -> bool {
    out.per_transform
        .iter()
        .any(|(k, _): &(JscramblerTransform, _)| *k == t)
}

#[test]
fn template_advanced_obfuscation_settings_parses() {
    settings_parses(SETTINGS_ADVANCED);
}

#[test]
fn template_advanced_obfuscation_chain_runs_with_control_flow_flattening() {
    let src: &str = "var x = 1; function f(){ return x; }";
    let out: TemplateOutput =
        deobfuscate_template_advanced_obfuscation(src, &JscramblerTransformOpts::default())
            .expect("ok");
    assert!(saw(&out, JscramblerTransform::ControlFlowFlattening));
    assert!(saw(&out, JscramblerTransform::BrowserLock));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/advanced-obfuscation/{source,protected}.zip"]
#[test]
fn template_advanced_obfuscation_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_anti_tampering_and_debugging_settings_parses() {
    settings_parses(SETTINGS_ANTI_TAMPERING);
}

#[test]
fn template_anti_tampering_and_debugging_chain_includes_anti_debugging() {
    let src: &str = "function f(){ debugger; return 1; }";
    let out: TemplateOutput =
        deobfuscate_template_anti_tampering_and_debugging(src, &JscramblerTransformOpts::default())
            .expect("ok");
    assert!(saw(&out, JscramblerTransform::AntiDebugging));
    assert!(saw(&out, JscramblerTransform::AntiTampering));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/anti-tampering-and-debugging/{source,protected}.zip"]
#[test]
fn template_anti_tampering_and_debugging_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_browser_lock_settings_parses() {
    settings_parses(SETTINGS_BROWSER_LOCK);
}

#[test]
fn template_browser_lock_chain_includes_browser_lock_step() {
    let src: &str = "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }";
    let out: TemplateOutput =
        deobfuscate_template_browser_lock(src, &JscramblerTransformOpts::default()).expect("ok");
    assert!(saw(&out, JscramblerTransform::BrowserLock));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/browser-lock/{source,protected}.zip"]
#[test]
fn template_browser_lock_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_date_lock_settings_parses() {
    settings_parses(SETTINGS_DATE_LOCK);
}

#[test]
fn template_date_lock_chain_includes_date_lock_step() {
    let src: &str = "if (Date.now() > 1) { x(); }";
    let out: TemplateOutput =
        deobfuscate_template_date_lock(src, &JscramblerTransformOpts::default()).expect("ok");
    assert!(saw(&out, JscramblerTransform::DateLock));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/date-lock/{source,protected}.zip"]
#[test]
fn template_date_lock_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_dead_objects_settings_parses() {
    settings_parses(SETTINGS_DEAD_OBJECTS);
}

#[test]
fn template_dead_objects_chain_includes_dead_objects_step_and_skips_unauthorized() {
    let src: &str = "var __deadX = { a: 1 };";
    let out: TemplateOutput =
        deobfuscate_template_dead_objects(src, &JscramblerTransformOpts::default()).expect("ok");
    let dead_stats: &_ = out
        .per_transform
        .iter()
        .find(|(t, _): &&(JscramblerTransform, _)| *t == JscramblerTransform::DeadObjects)
        .map(|(_, s): &(JscramblerTransform, _)| s)
        .expect("dead objects step recorded");
    assert!(dead_stats.skipped >= 1);
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/dead-objects/{source,protected}.zip"]
#[test]
fn template_dead_objects_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_domain_lock_settings_parses() {
    settings_parses(SETTINGS_DOMAIN_LOCK);
}

#[test]
fn template_domain_lock_chain_includes_domain_lock_step() {
    let src: &str = "if (location.hostname !== 'x') { y(); }";
    let out: TemplateOutput =
        deobfuscate_template_domain_lock(src, &JscramblerTransformOpts::default()).expect("ok");
    assert!(saw(&out, JscramblerTransform::DomainLock));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/domain-lock/{source,protected}.zip"]
#[test]
fn template_domain_lock_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_light_obfuscation_settings_parses() {
    settings_parses(SETTINGS_LIGHT);
}

#[test]
fn template_light_obfuscation_handles_hex_strings_and_booleans() {
    let src: &str = r"var s = '\x68\x69'; if (![]) { run(); }";
    let out: TemplateOutput =
        deobfuscate_template_light_obfuscation(src, &JscramblerTransformOpts::default())
            .expect("ok");
    assert!(out.source.contains("'hi'") || out.source.contains("\"hi\""));
    assert!(out.source.contains("false"));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/light-obfuscation/{source,protected}.zip"]
#[test]
fn template_light_obfuscation_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_minification_settings_parses() {
    settings_parses(SETTINGS_MINIFICATION);
}

#[test]
fn template_minification_chains_rename_and_whitespace() {
    let src: &str = "var a0_0xabcd = 1;";
    let out: TemplateOutput =
        deobfuscate_template_minification(src, &JscramblerTransformOpts::default()).expect("ok");
    assert!(out.source.contains("v_1"));
    assert_eq!(out.per_transform.len(), 2);
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/minification/{source,protected}.zip"]
#[test]
fn template_minification_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_obfuscation_settings_parses() {
    settings_parses(SETTINGS_OBFUSCATION);
}

#[test]
fn template_obfuscation_chain_runs_full_pipeline() {
    let src: &str = "var x = 1;";
    let out: TemplateOutput =
        deobfuscate_template_obfuscation(src, &JscramblerTransformOpts::default()).expect("ok");
    assert!(out.per_transform.len() >= 10);
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/obfuscation/{source,protected}.zip"]
#[test]
fn template_obfuscation_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_os_lock_settings_parses() {
    settings_parses(SETTINGS_OS_LOCK);
}

#[test]
fn template_os_lock_chain_includes_os_lock_step() {
    let src: &str = "if (navigator.platform !== 'Win32') { stop(); }";
    let out: TemplateOutput =
        deobfuscate_template_os_lock(src, &JscramblerTransformOpts::default()).expect("ok");
    assert!(saw(&out, JscramblerTransform::OsLock));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/os-lock/{source,protected}.zip"]
#[test]
fn template_os_lock_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_self_defending_settings_parses() {
    settings_parses(SETTINGS_SELF_DEFENDING);
}

#[test]
fn template_self_defending_chain_includes_self_defending_step() {
    let src: &str = "var x = 1;";
    let out: TemplateOutput =
        deobfuscate_template_self_defending(src, &JscramblerTransformOpts::default()).expect("ok");
    assert!(saw(&out, JscramblerTransform::SelfDefending));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/self-defending/{source,protected}.zip (sample pending per FEATURES.md L363)"]
#[test]
fn template_self_defending_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn template_self_healing_settings_parses() {
    settings_parses(SETTINGS_SELF_HEALING);
}

#[test]
fn template_self_healing_chain_includes_self_healing_step() {
    let src: &str = "var x = 1;";
    let out: TemplateOutput =
        deobfuscate_template_self_healing(src, &JscramblerTransformOpts::default()).expect("ok");
    assert!(saw(&out, JscramblerTransform::SelfHealing));
}

#[ignore = "FIXTURE PENDING: corpus/src/javascript/jscrambler-samples/templates/self-healing/{source,protected}.zip (sample pending per FEATURES.md L364)"]
#[test]
fn template_self_healing_e2e_against_corpus_fixture() {
    panic!("fixture pending");
}

#[test]
fn all_twelve_template_settings_files_parse_as_json() {
    for (name, blob) in [
        ("advanced-obfuscation", SETTINGS_ADVANCED),
        ("anti-tampering-and-debugging", SETTINGS_ANTI_TAMPERING),
        ("browser-lock", SETTINGS_BROWSER_LOCK),
        ("date-lock", SETTINGS_DATE_LOCK),
        ("dead-objects", SETTINGS_DEAD_OBJECTS),
        ("domain-lock", SETTINGS_DOMAIN_LOCK),
        ("light-obfuscation", SETTINGS_LIGHT),
        ("minification", SETTINGS_MINIFICATION),
        ("obfuscation", SETTINGS_OBFUSCATION),
        ("os-lock", SETTINGS_OS_LOCK),
        ("self-defending", SETTINGS_SELF_DEFENDING),
        ("self-healing", SETTINGS_SELF_HEALING),
    ] {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(blob);
        assert!(parsed.is_ok(), "settings for {name} failed to parse");
    }
}
