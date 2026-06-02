use serde::Serialize;

use crate::error::Result;
use crate::jscrambler::detect::JscramblerTransform;
use crate::jscrambler::transforms::{TransformOpts, TransformStats};
use crate::jscrambler::{TransformOutput, dispatch_reverse};

#[derive(Debug, Clone, Serialize)]
pub struct TemplateOutput {
    pub source: String,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub per_transform: Vec<(JscramblerTransform, TransformStats)>,
}

pub fn deobfuscate_template_advanced_obfuscation(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    run_chain(source, opts, &advanced_obfuscation_chain())
}

pub fn deobfuscate_template_anti_tampering_and_debugging(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    run_chain(source, opts, &anti_tampering_chain())
}

pub fn deobfuscate_template_browser_lock(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::BrowserLock);
    run_chain(source, opts, &chain)
}

pub fn deobfuscate_template_date_lock(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::DateLock);
    run_chain(source, opts, &chain)
}

pub fn deobfuscate_template_dead_objects(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::DeadObjects);
    run_chain(source, opts, &chain)
}

pub fn deobfuscate_template_domain_lock(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::DomainLock);
    run_chain(source, opts, &chain)
}

pub fn deobfuscate_template_light_obfuscation(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    run_chain(source, opts, &light_obfuscation_chain())
}

pub fn deobfuscate_template_minification(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    run_chain(source, opts, &minification_chain())
}

pub fn deobfuscate_template_os_lock(source: &str, opts: &TransformOpts) -> Result<TemplateOutput> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::OsLock);
    run_chain(source, opts, &chain)
}

pub fn deobfuscate_template_obfuscation(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    run_chain(source, opts, &obfuscation_chain())
}

pub fn deobfuscate_template_self_defending(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::SelfDefending);
    run_chain(source, opts, &chain)
}

pub fn deobfuscate_template_self_healing(
    source: &str,
    opts: &TransformOpts,
) -> Result<TemplateOutput> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::SelfHealing);
    run_chain(source, opts, &chain)
}

fn run_chain(
    source: &str,
    opts: &TransformOpts,
    chain: &[JscramblerTransform],
) -> Result<TemplateOutput> {
    let bytes_in: usize = source.len();
    let mut current: String = source.to_owned();
    let mut per_transform: Vec<(JscramblerTransform, TransformStats)> =
        Vec::with_capacity(chain.len());
    for t in chain.iter().copied() {
        let out: TransformOutput = dispatch_reverse(t, &current, opts);
        current = out.source;
        per_transform.push((t, out.stats));
    }
    Ok(TemplateOutput {
        bytes_in,
        bytes_out: current.len(),
        source: current,
        per_transform,
    })
}

fn obfuscation_chain() -> Vec<JscramblerTransform> {
    vec![
        JscramblerTransform::StringEncoding,
        JscramblerTransform::StringConcealing,
        JscramblerTransform::PropertyKeysObfuscation,
        JscramblerTransform::DotToBracketNotation,
        JscramblerTransform::RegexObfuscation,
        JscramblerTransform::BooleanToAnything,
        JscramblerTransform::DuplicateLiteralsRemoval,
        JscramblerTransform::GlobalVariableIndirection,
        JscramblerTransform::VariableMasking,
        JscramblerTransform::VariableGrouping,
        JscramblerTransform::CommaOperatorUnfolding,
        JscramblerTransform::ExtendPredicates,
        JscramblerTransform::DeadCodeInjection,
        JscramblerTransform::ConstantFolding,
        JscramblerTransform::IdentifiersRenaming,
        JscramblerTransform::WhitespaceRemoval,
    ]
}

fn advanced_obfuscation_chain() -> Vec<JscramblerTransform> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::ControlFlowFlattening);
    chain.insert(0, JscramblerTransform::BrowserLock);
    chain
}

fn anti_tampering_chain() -> Vec<JscramblerTransform> {
    let mut chain: Vec<JscramblerTransform> = obfuscation_chain();
    chain.insert(0, JscramblerTransform::AntiTampering);
    chain.insert(0, JscramblerTransform::AntiDebugging);
    chain
}

fn light_obfuscation_chain() -> Vec<JscramblerTransform> {
    vec![
        JscramblerTransform::StringEncoding,
        JscramblerTransform::PropertyKeysObfuscation,
        JscramblerTransform::RegexObfuscation,
        JscramblerTransform::BooleanToAnything,
        JscramblerTransform::GlobalVariableIndirection,
        JscramblerTransform::WhitespaceRemoval,
    ]
}

fn minification_chain() -> Vec<JscramblerTransform> {
    vec![
        JscramblerTransform::IdentifiersRenaming,
        JscramblerTransform::WhitespaceRemoval,
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn light_template_runs_without_panic() {
        let src: &str = r"var s = '\x68\x69'; if (![]) { run(); }";
        let out: TemplateOutput =
            deobfuscate_template_light_obfuscation(src, &TransformOpts::default())
                .expect("light template ok");
        assert!(!out.per_transform.is_empty());
    }

    #[test]
    fn minification_template_chains_rename_and_whitespace() {
        let src: &str = "var a0_0xabcd = 1;";
        let out: TemplateOutput = deobfuscate_template_minification(src, &TransformOpts::default())
            .expect("minification template ok");
        assert!(out.source.contains("v_1"));
    }

    #[test]
    fn obfuscation_template_records_all_steps() {
        let src: &str = "var x = 1;";
        let out: TemplateOutput = deobfuscate_template_obfuscation(src, &TransformOpts::default())
            .expect("obfuscation template ok");
        assert_eq!(out.per_transform.len(), obfuscation_chain().len());
    }

    #[test]
    fn dead_objects_template_requires_auth_for_dead_objects_step() {
        let src: &str = "var __deadFoo = {a: 1};";
        let out: TemplateOutput = deobfuscate_template_dead_objects(src, &TransformOpts::default())
            .expect("template returns even when auth missing");
        let dead_objects_step: &TransformStats = out
            .per_transform
            .iter()
            .find(|(t, _): &&(JscramblerTransform, TransformStats)| {
                *t == JscramblerTransform::DeadObjects
            })
            .map(|(_, stats): &(JscramblerTransform, TransformStats)| stats)
            .expect("dead objects step recorded");
        assert!(dead_objects_step.skipped >= 1);
    }
}
