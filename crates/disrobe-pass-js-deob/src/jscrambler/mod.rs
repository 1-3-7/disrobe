#![allow(
    clippy::type_complexity,
    clippy::unnecessary_wraps,
    clippy::needless_continue,
    clippy::single_match_else,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

mod detect;
mod integrity;
mod scanner;
mod templates;
mod transforms;

use std::collections::BTreeSet;

use serde::Serialize;

use crate::error::Result;

pub use detect::{
    CodeLockKind, JscramblerDetection, JscramblerTier, JscramblerTransform, detect_free_tier,
    detect_full,
};
pub use integrity::{IntegrityStripStats, strip_integrity_loops};
pub use templates::{
    TemplateOutput, deobfuscate_template_advanced_obfuscation,
    deobfuscate_template_anti_tampering_and_debugging, deobfuscate_template_browser_lock,
    deobfuscate_template_date_lock, deobfuscate_template_dead_objects,
    deobfuscate_template_domain_lock, deobfuscate_template_light_obfuscation,
    deobfuscate_template_minification, deobfuscate_template_obfuscation,
    deobfuscate_template_os_lock, deobfuscate_template_self_defending,
    deobfuscate_template_self_healing,
};
pub use transforms::{TransformOpts, TransformOutput, TransformStats};

#[derive(Debug, Clone, Default)]
pub struct JscramblerOptions {
    pub i_have_authorization: bool,
    pub transforms: BTreeSet<JscramblerTransform>,
}

impl JscramblerOptions {
    #[must_use]
    pub fn all_obfuscation() -> Self {
        Self {
            i_have_authorization: false,
            transforms: obfuscation_set(),
        }
    }

    #[must_use]
    pub fn all_with_authorization() -> Self {
        let mut set: BTreeSet<JscramblerTransform> = obfuscation_set();
        for t in rasp_set() {
            set.insert(t);
        }
        for t in lock_set() {
            set.insert(t);
        }
        for t in optimization_set() {
            set.insert(t);
        }
        Self {
            i_have_authorization: true,
            transforms: set,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JscramblerOutput {
    pub source: String,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub detection: JscramblerDetection,
    pub per_transform: Vec<(JscramblerTransform, TransformStats)>,
    pub integrity_strip: IntegrityStripStats,
}

pub fn deobfuscate(source: &str, opts: &JscramblerOptions) -> Result<JscramblerOutput> {
    let detection: JscramblerDetection = detect_full(source);
    let (after_integrity, integrity_strip): (String, IntegrityStripStats) =
        strip_integrity_loops(source);
    let mut current: String = after_integrity;
    let mut per_transform: Vec<(JscramblerTransform, TransformStats)> = Vec::new();
    let bytes_in: usize = source.len();
    let opts_t: TransformOpts = TransformOpts {
        i_have_authorization: opts.i_have_authorization,
    };
    for transform in opts.transforms.iter().copied() {
        let out: TransformOutput = dispatch_reverse(transform, &current, &opts_t);
        current = out.source;
        per_transform.push((transform, out.stats));
    }
    Ok(JscramblerOutput {
        bytes_in,
        bytes_out: current.len(),
        source: current,
        detection,
        per_transform,
        integrity_strip,
    })
}

fn dispatch_reverse(t: JscramblerTransform, source: &str, opts: &TransformOpts) -> TransformOutput {
    match t {
        JscramblerTransform::BooleanToAnything => {
            transforms::boolean_to_anything::reverse(source, opts)
        }
        JscramblerTransform::CharToTernaryOperator => {
            transforms::char_to_ternary::reverse(source, opts)
        }
        JscramblerTransform::CommaOperatorUnfolding => {
            transforms::comma_unfolding::reverse(source, opts)
        }
        JscramblerTransform::ControlFlowFlattening => {
            transforms::control_flow_flattening::reverse(source, opts)
        }
        JscramblerTransform::DeadCodeInjection => {
            transforms::dead_code_injection::reverse(source, opts)
        }
        JscramblerTransform::DotToBracketNotation => {
            transforms::dot_to_bracket::reverse(source, opts)
        }
        JscramblerTransform::DuplicateLiteralsRemoval => {
            transforms::duplicate_literals_removal::reverse(source, opts)
        }
        JscramblerTransform::ExtendPredicates => {
            transforms::extend_predicates::reverse(source, opts)
        }
        JscramblerTransform::FunctionOutlining => {
            transforms::function_outlining::reverse(source, opts)
        }
        JscramblerTransform::FunctionReordering => {
            transforms::function_reordering::reverse(source, opts)
        }
        JscramblerTransform::GlobalVariableIndirection => {
            transforms::global_variable_indirection::reverse(source, opts)
        }
        JscramblerTransform::IdentifiersRenaming => {
            transforms::identifiers_renaming::reverse(source, opts)
        }
        JscramblerTransform::NumberToString => transforms::number_to_string::reverse(source, opts),
        JscramblerTransform::ObjectPropertiesSparsing => {
            transforms::object_properties_sparsing::reverse(source, opts)
        }
        JscramblerTransform::PropertyKeysObfuscation => {
            transforms::property_keys_obfuscation::reverse(source, opts)
        }
        JscramblerTransform::PropertyKeysReordering => {
            transforms::property_keys_reordering::reverse(source, opts)
        }
        JscramblerTransform::RegexObfuscation => {
            transforms::regex_obfuscation::reverse(source, opts)
        }
        JscramblerTransform::StringConcealing => {
            transforms::string_concealing::reverse(source, opts)
        }
        JscramblerTransform::StringEncoding => transforms::string_encoding::reverse(source, opts),
        JscramblerTransform::VariableGrouping => {
            transforms::variable_grouping::reverse(source, opts)
        }
        JscramblerTransform::VariableMasking => transforms::variable_masking::reverse(source, opts),
        JscramblerTransform::AssertionsRemoval => {
            transforms::assertions_removal::reverse(source, opts)
        }
        JscramblerTransform::ConstantFolding => transforms::constant_folding::reverse(source, opts),
        JscramblerTransform::DeadCodeElimination => {
            transforms::dead_code_elimination::reverse(source, opts)
        }
        JscramblerTransform::DebugCodeElimination => {
            transforms::debug_code_elimination::reverse(source, opts)
        }
        JscramblerTransform::WhitespaceRemoval => {
            transforms::whitespace_removal::reverse(source, opts)
        }
        JscramblerTransform::AntiDebugging => transforms::anti_debugging::reverse(source, opts),
        JscramblerTransform::AntiMonkeyPatching => {
            transforms::anti_monkey_patching::reverse(source, opts)
        }
        JscramblerTransform::AntiTampering => transforms::anti_tampering::reverse(source, opts),
        JscramblerTransform::DeadObjects => transforms::dead_objects::reverse(source, opts),
        JscramblerTransform::SelfDefending => transforms::self_defending::reverse(source, opts),
        JscramblerTransform::SelfHealing => transforms::self_healing::reverse(source, opts),
        JscramblerTransform::BrowserLock => transforms::browser_lock::reverse(source, opts),
        JscramblerTransform::DateLock => transforms::date_lock::reverse(source, opts),
        JscramblerTransform::DomainLock => transforms::domain_lock::reverse(source, opts),
        JscramblerTransform::OsLock => transforms::os_lock::reverse(source, opts),
    }
}

pub fn dispatch_reverse_strict(
    t: JscramblerTransform,
    source: &str,
    opts: &TransformOpts,
) -> Result<TransformOutput> {
    match t {
        JscramblerTransform::AntiDebugging => {
            transforms::anti_debugging::reverse_strict(source, opts)
        }
        JscramblerTransform::AntiMonkeyPatching => {
            transforms::anti_monkey_patching::reverse_strict(source, opts)
        }
        JscramblerTransform::AntiTampering => {
            transforms::anti_tampering::reverse_strict(source, opts)
        }
        JscramblerTransform::DeadObjects => transforms::dead_objects::reverse_strict(source, opts),
        JscramblerTransform::SelfDefending => {
            transforms::self_defending::reverse_strict(source, opts)
        }
        JscramblerTransform::SelfHealing => transforms::self_healing::reverse_strict(source, opts),
        JscramblerTransform::BrowserLock => transforms::browser_lock::reverse_strict(source, opts),
        JscramblerTransform::DateLock => transforms::date_lock::reverse_strict(source, opts),
        JscramblerTransform::DomainLock => transforms::domain_lock::reverse_strict(source, opts),
        JscramblerTransform::OsLock => transforms::os_lock::reverse_strict(source, opts),
        JscramblerTransform::FunctionOutlining => {
            transforms::function_outlining::reverse_strict(source, opts)
        }
        JscramblerTransform::FunctionReordering => {
            transforms::function_reordering::reverse_strict(source, opts)
        }
        JscramblerTransform::ObjectPropertiesSparsing => {
            transforms::object_properties_sparsing::reverse_strict(source, opts)
        }
        JscramblerTransform::PropertyKeysReordering => {
            transforms::property_keys_reordering::reverse_strict(source, opts)
        }
        other => Ok(dispatch_reverse(other, source, opts)),
    }
}

fn dispatch_detect(t: JscramblerTransform, source: &str) -> usize {
    match t {
        JscramblerTransform::BooleanToAnything => transforms::boolean_to_anything::detect(source),
        JscramblerTransform::CharToTernaryOperator => transforms::char_to_ternary::detect(source),
        JscramblerTransform::CommaOperatorUnfolding => transforms::comma_unfolding::detect(source),
        JscramblerTransform::ControlFlowFlattening => {
            transforms::control_flow_flattening::detect(source)
        }
        JscramblerTransform::DeadCodeInjection => transforms::dead_code_injection::detect(source),
        JscramblerTransform::DotToBracketNotation => transforms::dot_to_bracket::detect(source),
        JscramblerTransform::DuplicateLiteralsRemoval => {
            transforms::duplicate_literals_removal::detect(source)
        }
        JscramblerTransform::ExtendPredicates => transforms::extend_predicates::detect(source),
        JscramblerTransform::FunctionOutlining => transforms::function_outlining::detect(source),
        JscramblerTransform::FunctionReordering => transforms::function_reordering::detect(source),
        JscramblerTransform::GlobalVariableIndirection => {
            transforms::global_variable_indirection::detect(source)
        }
        JscramblerTransform::IdentifiersRenaming => {
            transforms::identifiers_renaming::detect(source)
        }
        JscramblerTransform::NumberToString => transforms::number_to_string::detect(source),
        JscramblerTransform::ObjectPropertiesSparsing => {
            transforms::object_properties_sparsing::detect(source)
        }
        JscramblerTransform::PropertyKeysObfuscation => {
            transforms::property_keys_obfuscation::detect(source)
        }
        JscramblerTransform::PropertyKeysReordering => {
            transforms::property_keys_reordering::detect(source)
        }
        JscramblerTransform::RegexObfuscation => transforms::regex_obfuscation::detect(source),
        JscramblerTransform::StringConcealing => transforms::string_concealing::detect(source),
        JscramblerTransform::StringEncoding => transforms::string_encoding::detect(source),
        JscramblerTransform::VariableGrouping => transforms::variable_grouping::detect(source),
        JscramblerTransform::VariableMasking => transforms::variable_masking::detect(source),
        JscramblerTransform::AssertionsRemoval => transforms::assertions_removal::detect(source),
        JscramblerTransform::ConstantFolding => transforms::constant_folding::detect(source),
        JscramblerTransform::DeadCodeElimination => {
            transforms::dead_code_elimination::detect(source)
        }
        JscramblerTransform::DebugCodeElimination => {
            transforms::debug_code_elimination::detect(source)
        }
        JscramblerTransform::WhitespaceRemoval => transforms::whitespace_removal::detect(source),
        JscramblerTransform::AntiDebugging => transforms::anti_debugging::detect(source),
        JscramblerTransform::AntiMonkeyPatching => transforms::anti_monkey_patching::detect(source),
        JscramblerTransform::AntiTampering => transforms::anti_tampering::detect(source),
        JscramblerTransform::DeadObjects => transforms::dead_objects::detect(source),
        JscramblerTransform::SelfDefending => transforms::self_defending::detect(source),
        JscramblerTransform::SelfHealing => transforms::self_healing::detect(source),
        JscramblerTransform::BrowserLock => transforms::browser_lock::detect(source),
        JscramblerTransform::DateLock => transforms::date_lock::detect(source),
        JscramblerTransform::DomainLock => transforms::domain_lock::detect(source),
        JscramblerTransform::OsLock => transforms::os_lock::detect(source),
    }
}

fn obfuscation_set() -> BTreeSet<JscramblerTransform> {
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    for t in [
        JscramblerTransform::BooleanToAnything,
        JscramblerTransform::CharToTernaryOperator,
        JscramblerTransform::CommaOperatorUnfolding,
        JscramblerTransform::ControlFlowFlattening,
        JscramblerTransform::DeadCodeInjection,
        JscramblerTransform::DotToBracketNotation,
        JscramblerTransform::DuplicateLiteralsRemoval,
        JscramblerTransform::ExtendPredicates,
        JscramblerTransform::FunctionOutlining,
        JscramblerTransform::FunctionReordering,
        JscramblerTransform::GlobalVariableIndirection,
        JscramblerTransform::IdentifiersRenaming,
        JscramblerTransform::NumberToString,
        JscramblerTransform::ObjectPropertiesSparsing,
        JscramblerTransform::PropertyKeysObfuscation,
        JscramblerTransform::PropertyKeysReordering,
        JscramblerTransform::RegexObfuscation,
        JscramblerTransform::StringConcealing,
        JscramblerTransform::StringEncoding,
        JscramblerTransform::VariableGrouping,
        JscramblerTransform::VariableMasking,
    ] {
        set.insert(t);
    }
    set
}

fn optimization_set() -> BTreeSet<JscramblerTransform> {
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    for t in [
        JscramblerTransform::AssertionsRemoval,
        JscramblerTransform::ConstantFolding,
        JscramblerTransform::DeadCodeElimination,
        JscramblerTransform::DebugCodeElimination,
        JscramblerTransform::WhitespaceRemoval,
    ] {
        set.insert(t);
    }
    set
}

fn rasp_set() -> BTreeSet<JscramblerTransform> {
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    for t in [
        JscramblerTransform::AntiDebugging,
        JscramblerTransform::AntiMonkeyPatching,
        JscramblerTransform::AntiTampering,
        JscramblerTransform::DeadObjects,
        JscramblerTransform::SelfDefending,
        JscramblerTransform::SelfHealing,
    ] {
        set.insert(t);
    }
    set
}

fn lock_set() -> BTreeSet<JscramblerTransform> {
    let mut set: BTreeSet<JscramblerTransform> = BTreeSet::new();
    for t in [
        JscramblerTransform::BrowserLock,
        JscramblerTransform::DateLock,
        JscramblerTransform::DomainLock,
        JscramblerTransform::OsLock,
    ] {
        set.insert(t);
    }
    set
}
