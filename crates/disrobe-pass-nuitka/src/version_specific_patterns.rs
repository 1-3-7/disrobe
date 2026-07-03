use crate::markers::NuitkaEraGuess;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EraPatternPack {
    pub era: NuitkaEraGuess,
    pub verified_against_corpus: bool,
    pub rich_compare_lt: &'static str,
    pub rich_compare_eq: &'static str,
    pub binary_sub_long: &'static str,
    pub binary_add_object: &'static str,
    pub make_tuple_empty: &'static str,
    pub make_iterator_infallible: &'static str,
    pub builtin_format: &'static str,
    pub unicode_join: &'static str,
    pub lookup_builtin_print: &'static str,
    pub call_pos_args1: &'static str,
    pub raise_exception_with_value: &'static str,
    pub set_item0: &'static str,
}

const MODERN_PACK: EraPatternPack = EraPatternPack {
    era: NuitkaEraGuess::V3OrV4,
    verified_against_corpus: true,
    rich_compare_lt: "RICH_COMPARE_LT_NBOOL_OBJECT_LONG(",
    rich_compare_eq: "RICH_COMPARE_EQ_NBOOL_OBJECT_UNICODE(",
    binary_sub_long: "BINARY_OPERATION_SUB_OBJECT_OBJECT_LONG(",
    binary_add_object: "BINARY_OPERATION_ADD_OBJECT_OBJECT_OBJECT(",
    make_tuple_empty: "MAKE_TUPLE_EMPTY(",
    make_iterator_infallible: "MAKE_ITERATOR_INFALLIBLE(",
    builtin_format: "BUILTIN_FORMAT(tstate,",
    unicode_join: "PyUnicode_Join(",
    lookup_builtin_print: "LOOKUP_BUILTIN(const_str_plain_print)",
    call_pos_args1: "CALL_FUNCTION_WITH_POS_ARGS1(",
    raise_exception_with_value: "RAISE_EXCEPTION_WITH_VALUE(",
    set_item0: "PyTuple_SET_ITEM0(",
};

const V2_7_PACK: EraPatternPack = EraPatternPack {
    era: NuitkaEraGuess::V2_7Plus,
    verified_against_corpus: false,
    builtin_format: "BUILTIN_FORMAT(",
    ..MODERN_PACK
};

const V2_4_PACK: EraPatternPack = EraPatternPack {
    era: NuitkaEraGuess::V2_4ToV2_6,
    verified_against_corpus: false,
    make_iterator_infallible: "MAKE_ITERATOR(",
    builtin_format: "BUILTIN_FORMAT(",
    ..MODERN_PACK
};

const V2_0_PACK: EraPatternPack = EraPatternPack {
    era: NuitkaEraGuess::V2_0ToV2_3,
    verified_against_corpus: false,
    make_iterator_infallible: "MAKE_ITERATOR(",
    builtin_format: "BUILTIN_FORMAT(",
    call_pos_args1: "CALL_FUNCTION_WITH_ARGS1(",
    ..MODERN_PACK
};

const V1_4_PACK: EraPatternPack = EraPatternPack {
    era: NuitkaEraGuess::V1_4ToV1_9,
    verified_against_corpus: false,
    rich_compare_lt: "RICH_COMPARE_LT(",
    rich_compare_eq: "RICH_COMPARE_EQ(",
    make_iterator_infallible: "MAKE_ITERATOR(",
    builtin_format: "BUILTIN_FORMAT(",
    call_pos_args1: "CALL_FUNCTION_WITH_ARGS1(",
    ..MODERN_PACK
};

const PRE_1_4_PACK: EraPatternPack = EraPatternPack {
    era: NuitkaEraGuess::Pre1_4,
    verified_against_corpus: false,
    rich_compare_lt: "RICH_COMPARE_LT(",
    rich_compare_eq: "RICH_COMPARE_EQ(",
    binary_sub_long: "BINARY_OPERATION_SUB(",
    binary_add_object: "BINARY_OPERATION_ADD(",
    make_iterator_infallible: "MAKE_ITERATOR(",
    builtin_format: "BUILTIN_FORMAT(",
    call_pos_args1: "CALL_FUNCTION_WITH_ARGS1(",
    ..MODERN_PACK
};

#[must_use]
pub(crate) const fn pack_for_era(era: NuitkaEraGuess) -> EraPatternPack {
    match era {
        NuitkaEraGuess::Pre1_4 => PRE_1_4_PACK,
        NuitkaEraGuess::V1_4ToV1_9 => V1_4_PACK,
        NuitkaEraGuess::V2_0ToV2_3 => V2_0_PACK,
        NuitkaEraGuess::V2_4ToV2_6 => V2_4_PACK,
        NuitkaEraGuess::V2_7Plus => V2_7_PACK,
        NuitkaEraGuess::V3OrV4 | NuitkaEraGuess::Unknown => MODERN_PACK,
    }
}

#[must_use]
pub(crate) fn guess_era_from_csource(c_body: &str) -> NuitkaEraGuess {
    let has_module_loader: bool = c_body.contains("nuitka_module_loader");
    let has_err_normalize: bool = c_body.contains("Nuitka_Err_NormalizeException");
    let has_infallible_iter: bool = c_body.contains("MAKE_ITERATOR_INFALLIBLE");
    let has_nbool_compare: bool = c_body.contains("_NBOOL_OBJECT_");
    let has_make_cell: bool = c_body.contains("MAKE_CELL");
    let has_call_fast: bool = c_body.contains("CALL_FUNCTION_FAST");

    if has_module_loader || has_err_normalize || has_infallible_iter {
        return NuitkaEraGuess::V3OrV4;
    }
    if has_make_cell && has_call_fast {
        return NuitkaEraGuess::V2_4ToV2_6;
    }
    if has_nbool_compare {
        return NuitkaEraGuess::V2_0ToV2_3;
    }
    NuitkaEraGuess::Unknown
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn modern_pack_is_the_corpus_verified_one() {
        let pack: EraPatternPack = pack_for_era(NuitkaEraGuess::V3OrV4);
        assert!(pack.verified_against_corpus);
        assert_eq!(pack.rich_compare_lt, "RICH_COMPARE_LT_NBOOL_OBJECT_LONG(");
        assert_eq!(pack.make_iterator_infallible, "MAKE_ITERATOR_INFALLIBLE(");
    }

    #[test]
    fn unknown_era_falls_back_to_modern_pack() {
        assert_eq!(
            pack_for_era(NuitkaEraGuess::Unknown),
            pack_for_era(NuitkaEraGuess::V3OrV4)
        );
    }

    #[test]
    fn older_packs_are_flagged_unverified() {
        for era in [
            NuitkaEraGuess::Pre1_4,
            NuitkaEraGuess::V1_4ToV1_9,
            NuitkaEraGuess::V2_0ToV2_3,
            NuitkaEraGuess::V2_4ToV2_6,
            NuitkaEraGuess::V2_7Plus,
        ] {
            assert!(
                !pack_for_era(era).verified_against_corpus,
                "{era:?} pack must be honestly flagged unverified (no older corpus)"
            );
        }
    }

    #[test]
    fn older_packs_drop_the_infallible_iterator_suffix() {
        assert_eq!(
            pack_for_era(NuitkaEraGuess::V2_4ToV2_6).make_iterator_infallible,
            "MAKE_ITERATOR("
        );
        assert_eq!(
            pack_for_era(NuitkaEraGuess::Pre1_4).rich_compare_lt,
            "RICH_COMPARE_LT("
        );
    }

    #[test]
    fn era_guess_picks_modern_on_v3_markers() {
        assert_eq!(
            guess_era_from_csource("x = MAKE_ITERATOR_INFALLIBLE(tstate, y);"),
            NuitkaEraGuess::V3OrV4
        );
        assert_eq!(
            guess_era_from_csource("nuitka_module_loader"),
            NuitkaEraGuess::V3OrV4
        );
    }

    #[test]
    fn era_guess_unknown_on_bare_body() {
        assert_eq!(
            guess_era_from_csource("return NULL;"),
            NuitkaEraGuess::Unknown
        );
    }
}
