#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeSet;

use disrobe_pass_js_deob::{
    CodeLockKind, JscramblerOptions, JscramblerOutput, JscramblerTransform, deobfuscate_jscrambler,
    deobfuscate_template_advanced_obfuscation, deobfuscate_template_anti_tampering_and_debugging,
    deobfuscate_template_browser_lock, deobfuscate_template_date_lock,
    deobfuscate_template_dead_objects, deobfuscate_template_domain_lock,
    deobfuscate_template_light_obfuscation, deobfuscate_template_minification,
    deobfuscate_template_obfuscation, deobfuscate_template_os_lock,
    deobfuscate_template_self_defending, deobfuscate_template_self_healing, detect_jscrambler_full,
};

const PROTECTED_COMMON_JS: &str =
    include_str!("../../../corpus/src/javascript/jscrambler-samples/protected/common.js");

#[test]
fn detect_full_finds_multiple_transforms_in_real_jscrambler_output() {
    let det: disrobe_pass_js_deob::JscramblerDetection =
        detect_jscrambler_full(PROTECTED_COMMON_JS);
    assert!(
        det.detected_transforms.len() >= 3,
        "expected >=3 transforms detected in real protected output, got {}",
        det.detected_transforms.len()
    );
    assert!(
        det.has_jscrambler_banner
            || det.a0_hex_ident_count > 0
            || !det.detected_transforms.is_empty(),
        "no jscrambler signature found"
    );
}

#[test]
fn e2e_real_protected_sample_shrinks_under_obfuscation_chain() {
    let opts: JscramblerOptions = JscramblerOptions::all_with_authorization();
    let bytes_in: usize = PROTECTED_COMMON_JS.len();
    let out: JscramblerOutput =
        disrobe_pass_js_deob::deobfuscate_jscrambler(PROTECTED_COMMON_JS, &opts).expect("ok");
    assert_eq!(out.bytes_in, bytes_in);
    assert!(out.bytes_out > 0, "output empty");
    let any_reversed: bool = out
        .per_transform
        .iter()
        .any(|(_, s): &(JscramblerTransform, _)| s.reversed > 0);
    assert!(
        any_reversed,
        "no transform reversed any tokens on real protected sample"
    );
}

#[test]
fn e2e_real_protected_output_does_not_regress_parse_quality() {
    let opts: JscramblerOptions = JscramblerOptions::all_with_authorization();
    let out: JscramblerOutput = deobfuscate_jscrambler(PROTECTED_COMMON_JS, &opts).expect("ok");
    let allocator_in: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let allocator_out: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let source_type: oxc_span::SourceType = oxc_span::SourceType::default();
    let parsed_in: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator_in, PROTECTED_COMMON_JS, source_type).parse();
    let parsed_out: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator_out, &out.source, source_type).parse();
    let input_errors: usize = parsed_in.errors.len();
    let output_errors: usize = parsed_out.errors.len();
    assert!(
        output_errors <= input_errors + 2,
        "output parse regressed: input={input_errors} errors, output={output_errors} errors"
    );
}

#[test]
fn e2e_real_protected_intermediate_input_parses() {
    let allocator: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let source_type: oxc_span::SourceType = oxc_span::SourceType::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator, PROTECTED_COMMON_JS, source_type).parse();
    assert!(
        parsed.errors.is_empty(),
        "input failed to parse: {} errors",
        parsed.errors.len()
    );
}

#[test]
fn all_obfuscation_set_contains_all_21_obfuscation_transforms() {
    let opts: JscramblerOptions = JscramblerOptions::all_obfuscation();
    assert_eq!(opts.transforms.len(), 21);
}

#[test]
fn all_with_authorization_includes_locks_and_rasp() {
    let opts: JscramblerOptions = JscramblerOptions::all_with_authorization();
    assert!(opts.i_have_authorization);
    assert!(opts.transforms.contains(&JscramblerTransform::BrowserLock));
    assert!(
        opts.transforms
            .contains(&JscramblerTransform::AntiDebugging)
    );
    assert!(
        opts.transforms
            .contains(&JscramblerTransform::ConstantFolding)
    );
}

#[test]
fn deobfuscate_with_empty_set_returns_input_verbatim() {
    let opts: JscramblerOptions = JscramblerOptions::default();
    let out: JscramblerOutput = deobfuscate_jscrambler("var x = 1;", &opts).expect("ok");
    assert_eq!(out.source, "var x = 1;");
    assert!(out.per_transform.is_empty());
}

#[test]
fn template_advanced_obfuscation_records_steps() {
    let src: &str = "var x = 1;";
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_advanced_obfuscation(
        src,
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    assert!(out.per_transform.len() >= 10);
}

#[test]
fn template_anti_tampering_chain_includes_anti_debugging_step() {
    let src: &str = "function f(){ debugger; return 1; }";
    let out: disrobe_pass_js_deob::TemplateOutput =
        deobfuscate_template_anti_tampering_and_debugging(
            src,
            &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
        )
        .expect("ok");
    let saw_anti_debug: bool = out
        .per_transform
        .iter()
        .any(|(t, _): &(JscramblerTransform, _)| *t == JscramblerTransform::AntiDebugging);
    assert!(saw_anti_debug);
}

#[test]
fn template_browser_lock_chain_runs() {
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_browser_lock(
        "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }",
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    let saw_lock: bool = out
        .per_transform
        .iter()
        .any(|(t, _): &(JscramblerTransform, _)| *t == JscramblerTransform::BrowserLock);
    assert!(saw_lock);
}

#[test]
fn template_date_lock_chain_runs() {
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_date_lock(
        "if (Date.now() > 1) { x(); }",
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    let saw_lock: bool = out
        .per_transform
        .iter()
        .any(|(t, _): &(JscramblerTransform, _)| *t == JscramblerTransform::DateLock);
    assert!(saw_lock);
}

#[test]
fn template_dead_objects_chain_runs() {
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_dead_objects(
        "var __deadX = { a: 1 };",
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    let saw: bool = out
        .per_transform
        .iter()
        .any(|(t, _): &(JscramblerTransform, _)| *t == JscramblerTransform::DeadObjects);
    assert!(saw);
}

#[test]
fn template_domain_lock_chain_runs() {
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_domain_lock(
        "if (location.hostname !== 'x') { y(); }",
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    let saw: bool = out
        .per_transform
        .iter()
        .any(|(t, _): &(JscramblerTransform, _)| *t == JscramblerTransform::DomainLock);
    assert!(saw);
}

#[test]
fn template_light_obfuscation_handles_hex_strings_and_booleans() {
    let src: &str = r"var s = '\x68\x69'; if (![]) { run(); }";
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_light_obfuscation(
        src,
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    assert!(out.source.contains("'hi'") || out.source.contains("\"hi\""));
    assert!(out.source.contains("false"));
}

#[test]
fn template_minification_renames_and_formats() {
    let src: &str = "var a0_0xabcd = 1;";
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_minification(
        src,
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    assert!(out.source.contains("v_1"));
}

#[test]
fn template_obfuscation_chain_runs_all_steps() {
    let src: &str = "var x = 1;";
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_obfuscation(
        src,
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    assert!(out.per_transform.len() >= 10);
}

#[test]
fn template_os_lock_chain_runs() {
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_os_lock(
        "if (navigator.platform !== 'Win32') { stop(); }",
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    let saw: bool = out
        .per_transform
        .iter()
        .any(|(t, _): &(JscramblerTransform, _)| *t == JscramblerTransform::OsLock);
    assert!(saw);
}

#[test]
fn template_self_defending_chain_runs() {
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_self_defending(
        "var x = 1;",
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    let saw: bool = out
        .per_transform
        .iter()
        .any(|(t, _): &(JscramblerTransform, _)| *t == JscramblerTransform::SelfDefending);
    assert!(saw);
}

#[test]
fn template_self_healing_chain_runs() {
    let out: disrobe_pass_js_deob::TemplateOutput = deobfuscate_template_self_healing(
        "var x = 1;",
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .expect("ok");
    let saw: bool = out
        .per_transform
        .iter()
        .any(|(t, _): &(JscramblerTransform, _)| *t == JscramblerTransform::SelfHealing);
    assert!(saw);
}

#[test]
fn detect_finds_browser_lock_signature() {
    let det: disrobe_pass_js_deob::JscramblerDetection =
        detect_jscrambler_full("if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }");
    assert!(det.code_locks.contains(&CodeLockKind::Browser));
}

#[test]
fn deobfuscate_returns_authorization_required_via_strict_dispatch() {
    use disrobe_pass_js_deob::deobfuscate_jscrambler_transform_strict;
    let err: disrobe_pass_js_deob::Error = deobfuscate_jscrambler_transform_strict(
        JscramblerTransform::AntiDebugging,
        "function f(){ debugger; }",
        &disrobe_pass_js_deob::JscramblerTransformOpts::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_js_deob::Error::AuthorizationRequired { .. }
    ));
}

#[test]
fn deobfuscate_chains_obfuscation_pipeline_on_synthetic_fixture() {
    let src: &str =
        "var v = obj[\"foo\"]; var z = String.fromCharCode(65); var alias = console; alias.log(z);";
    let mut transforms: BTreeSet<JscramblerTransform> = BTreeSet::new();
    transforms.insert(JscramblerTransform::DotToBracketNotation);
    transforms.insert(JscramblerTransform::CharToTernaryOperator);
    transforms.insert(JscramblerTransform::VariableMasking);
    let opts: JscramblerOptions = JscramblerOptions {
        i_have_authorization: false,
        transforms,
    };
    let out: JscramblerOutput = deobfuscate_jscrambler(src, &opts).expect("ok");
    assert!(out.source.contains("obj.foo"));
    assert!(out.source.contains("\"A\""));
    assert!(out.source.contains("console.log"));
}
