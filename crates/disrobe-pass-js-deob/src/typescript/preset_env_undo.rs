use std::collections::BTreeMap;

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::Serialize;

use crate::unminify::{
    PresetEnvExpressionRestore, has_preset_env_async_protection,
    requires_preset_env_async_quarantine, restore_preset_env_expressions,
};

#[derive(Debug, Clone, Default, Serialize)]
pub struct PresetEnvUndoResult {
    pub rewritten: String,
    pub helpers_removed: BTreeMap<String, usize>,
    pub spreads_restored: usize,
    pub classes_restored: usize,
    pub async_restored: usize,
    pub optional_chains_restored: usize,
    pub nullish_coalesce_restored: usize,
}

fn reparses_javascript(source: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = match SourceType::from_path("input.js") {
        Ok(value) => value,
        Err(_) => return false,
    };
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

#[must_use]
pub fn undo_preset_env(source: &str) -> PresetEnvUndoResult {
    if requires_preset_env_async_quarantine(source) {
        return PresetEnvUndoResult {
            rewritten: source.to_owned(),
            helpers_removed: BTreeMap::new(),
            spreads_restored: 0,
            classes_restored: 0,
            async_restored: 0,
            optional_chains_restored: 0,
            nullish_coalesce_restored: 0,
        };
    }
    if has_preset_env_async_protection(source) {
        let expression_result: PresetEnvExpressionRestore = restore_preset_env_expressions(source);
        return PresetEnvUndoResult {
            rewritten: expression_result.rewritten,
            helpers_removed: BTreeMap::new(),
            spreads_restored: 0,
            classes_restored: 0,
            async_restored: 0,
            optional_chains_restored: expression_result.optional_chains_restored,
            nullish_coalesce_restored: expression_result.nullish_coalesce_restored,
        };
    }
    let async_base: String = source.to_owned();
    let async_restored: usize = 0;
    let mut out: String = source.to_owned();
    let expression_result: PresetEnvExpressionRestore = restore_preset_env_expressions(&out);
    out = expression_result.rewritten;
    let optional_chains_restored: usize = expression_result.optional_chains_restored;
    let nullish_coalesce_restored: usize = expression_result.nullish_coalesce_restored;

    if out != async_base && !reparses_javascript(&out) {
        return PresetEnvUndoResult {
            rewritten: async_base,
            helpers_removed: BTreeMap::new(),
            spreads_restored: 0,
            classes_restored: 0,
            async_restored,
            optional_chains_restored: 0,
            nullish_coalesce_restored: 0,
        };
    }

    PresetEnvUndoResult {
        rewritten: out,
        helpers_removed: BTreeMap::new(),
        spreads_restored: 0,
        classes_restored: 0,
        async_restored,
        optional_chains_restored,
        nullish_coalesce_restored,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn preserves_unverified_array_spread() {
        let src: &str = "var b = [].concat(_toConsumableArray(a), [1]);";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert_eq!(r.spreads_restored, 0);
        assert_eq!(r.rewritten, src);
    }

    #[test]
    fn preserves_unverified_class_call_check() {
        let src: &str = "function Foo() { _classCallCheck(this, Foo); this.x = 1; }";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert_eq!(r.classes_restored, 0);
        assert_eq!(r.rewritten, src);
    }

    #[test]
    fn preserves_direct_async_to_generator_assignment() {
        let src: &str = "import babelAsync from '@babel/runtime/helpers/asyncToGenerator'; var f = babelAsync(function* () { yield 1; });";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert_eq!(r.async_restored, 0);
        assert_eq!(r.rewritten, src);
    }

    #[test]
    fn restores_optional_chain() {
        let src: &str =
            "const obj = {}; var v = (obj === null || obj === void 0) ? void 0 : obj.field;";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert!(r.optional_chains_restored >= 1);
        assert!(r.rewritten.contains("obj?.field"));
    }

    #[test]
    fn restores_nullish_coalesce() {
        let src: &str = "const val = 7; var x = (val !== null && val !== void 0 ? val : fallback);";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert!(r.nullish_coalesce_restored >= 1);
        assert!(r.rewritten.contains("val ?? fallback"));
    }

    #[test]
    fn preserves_unverified_helper_definitions() {
        let src: &str = "function _classCallCheck(a, b) { if (!(a instanceof b)) throw new TypeError('x'); } function Foo() {}";
        let r: PresetEnvUndoResult = undo_preset_env(src);
        assert!(r.helpers_removed.is_empty());
        assert_eq!(r.rewritten, src);
    }
}
