use serde::Serialize;

pub(super) mod anti_debugging;
pub(super) mod anti_monkey_patching;
pub(super) mod anti_tampering;
pub(super) mod assertions_removal;
pub(super) mod boolean_to_anything;
pub(super) mod browser_lock;
pub(super) mod char_to_ternary;
pub(super) mod comma_unfolding;
pub(super) mod constant_folding;
pub(super) mod control_flow_flattening;
pub(super) mod date_lock;
pub(super) mod dead_code_elimination;
pub(super) mod dead_code_injection;
pub(super) mod dead_objects;
pub(super) mod debug_code_elimination;
pub(super) mod domain_lock;
pub(super) mod dot_to_bracket;
pub(super) mod duplicate_literals_removal;
pub(super) mod extend_predicates;
pub(super) mod function_outlining;
pub(super) mod function_reordering;
pub(super) mod global_variable_indirection;
pub(super) mod identifiers_renaming;
pub(super) mod number_to_string;
pub(super) mod object_properties_sparsing;
pub(super) mod os_lock;
pub(super) mod property_keys_obfuscation;
pub(super) mod property_keys_reordering;
pub(super) mod regex_obfuscation;
pub(super) mod self_defending;
pub(super) mod self_healing;
pub(super) mod string_concealing;
pub(super) mod string_encoding;
pub(super) mod variable_grouping;
pub(super) mod variable_masking;
pub(super) mod whitespace_removal;

#[derive(Debug, Clone, Default, Serialize)]
pub struct TransformStats {
    pub matched: usize,
    pub reversed: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransformOutput {
    pub source: String,
    pub stats: TransformStats,
}

impl TransformOutput {
    pub(super) fn noop(source: &str) -> Self {
        Self {
            source: source.to_owned(),
            stats: TransformStats::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransformOpts {
    pub i_have_authorization: bool,
}
