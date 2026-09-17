use std::collections::BTreeMap;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::util::find_subslice;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CSourceMarker {
    DictNewPresized,
    ObjectCallMethodObjArgs,
    MakeCell,
    CallFunctionFast,
    LoadConstantsBlob,
    MakeFunction,
    CreateGlobalConstants,
    NuitkaFrameFunction,
    NuitkaSetAttribute,
    NuitkaCalledThroughTuple,
    NuitkaImportName,
    NuitkaImportFrom,
    NuitkaListAppend,
    NuitkaTupleNew,
    NuitkaBoolFromLong,
    NuitkaFunctionObject,
    NuitkaGeneratorObject,
    NuitkaCoroutineObject,
    NuitkaAsyncgenObject,
    NuitkaCellObject,
    NuitkaCompiledMethodObject,
    NuitkaModuleObject,
    NuitkaVersionTag,
    NuitkaModuleLoader,
    NuitkaDistribution,
    NuitkaResourceReader,
    NuitkaEmptyFunction,
    NuitkaErrNormalize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NuitkaEraGuess {
    Pre1_4,
    V1_4ToV1_9,
    V2_0ToV2_3,
    V2_4ToV2_6,
    V2_7Plus,
    V3OrV4,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DecompReadyMarkers {
    pub markers: BTreeMap<CSourceMarker, u32>,
    pub total_hits: u32,
    pub era_guess: NuitkaEraGuess,
    pub confidence: f32,
}

impl Default for NuitkaEraGuess {
    #[inline]
    fn default() -> Self {
        Self::Unknown
    }
}

const MARKER_TABLE: &[(CSourceMarker, &[u8])] = &[
    (CSourceMarker::DictNewPresized, b"_PyDict_NewPresized"),
    (
        CSourceMarker::ObjectCallMethodObjArgs,
        b"PyObject_CallMethodObjArgs",
    ),
    (CSourceMarker::MakeCell, b"MAKE_CELL"),
    (CSourceMarker::CallFunctionFast, b"CALL_FUNCTION_FAST"),
    (CSourceMarker::LoadConstantsBlob, b"loadConstantsBlob"),
    (CSourceMarker::MakeFunction, b"MAKE_FUNCTION_"),
    (
        CSourceMarker::CreateGlobalConstants,
        b"createGlobalConstants",
    ),
    (CSourceMarker::NuitkaFrameFunction, b"Nuitka_Frame_"),
    (CSourceMarker::NuitkaSetAttribute, b"SET_ATTRIBUTE"),
    (
        CSourceMarker::NuitkaCalledThroughTuple,
        b"CALL_FUNCTION_WITH_ARGS",
    ),
    (CSourceMarker::NuitkaImportName, b"IMPORT_HARD_"),
    (CSourceMarker::NuitkaImportFrom, b"IMPORT_FROM_MODULE"),
    (CSourceMarker::NuitkaListAppend, b"LIST_APPEND1"),
    (CSourceMarker::NuitkaTupleNew, b"MAKE_TUPLE"),
    (CSourceMarker::NuitkaBoolFromLong, b"Nuitka_PyBool_FromLong"),
    (
        CSourceMarker::NuitkaFunctionObject,
        b"Nuitka_FunctionObject",
    ),
    (
        CSourceMarker::NuitkaGeneratorObject,
        b"Nuitka_GeneratorObject",
    ),
    (
        CSourceMarker::NuitkaCoroutineObject,
        b"Nuitka_CoroutineObject",
    ),
    (
        CSourceMarker::NuitkaAsyncgenObject,
        b"Nuitka_AsyncgenObject",
    ),
    (CSourceMarker::NuitkaCellObject, b"Nuitka_CellObject"),
    (
        CSourceMarker::NuitkaCompiledMethodObject,
        b"Nuitka_Method_New",
    ),
    (CSourceMarker::NuitkaModuleObject, b"Nuitka_Module_New"),
    (CSourceMarker::NuitkaVersionTag, b"__nuitka_version__"),
    (CSourceMarker::NuitkaModuleLoader, b"nuitka_module_loader"),
    (CSourceMarker::NuitkaDistribution, b"nuitka_distribution"),
    (
        CSourceMarker::NuitkaResourceReader,
        b"nuitka_resource_reader",
    ),
    (CSourceMarker::NuitkaEmptyFunction, b"nuitka_empty_function"),
    (
        CSourceMarker::NuitkaErrNormalize,
        b"Nuitka_Err_NormalizeException",
    ),
];

pub fn scan_c_source_markers(image: &[u8]) -> Result<DecompReadyMarkers> {
    let mut markers: BTreeMap<CSourceMarker, u32> = BTreeMap::new();
    let mut total_hits: u32 = 0u32;

    for (kind, needle) in MARKER_TABLE {
        let count: u32 = count_occurrences(image, needle);
        if count > 0 {
            markers.insert(*kind, count);
            total_hits = total_hits.saturating_add(count);
        }
    }

    if markers.is_empty() {
        return Err(Error::NotNuitka);
    }

    let era_guess: NuitkaEraGuess = guess_era(&markers);
    let confidence: f32 = compute_confidence(&markers, total_hits);

    Ok(DecompReadyMarkers {
        markers,
        total_hits,
        era_guess,
        confidence,
    })
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> u32 {
    if needle.is_empty() {
        return 0u32;
    }
    let mut count: u32 = 0u32;
    let mut cursor: usize = 0usize;
    while cursor + needle.len() <= haystack.len() {
        let Some(rel): Option<usize> = find_subslice(&haystack[cursor..], needle) else {
            break;
        };
        count = count.saturating_add(1);
        cursor = cursor + rel + needle.len();
    }
    count
}

fn guess_era(markers: &BTreeMap<CSourceMarker, u32>) -> NuitkaEraGuess {
    let has_version_tag: bool = markers.contains_key(&CSourceMarker::NuitkaVersionTag);
    let has_module_loader: bool = markers.contains_key(&CSourceMarker::NuitkaModuleLoader);
    let has_err_normalize: bool = markers.contains_key(&CSourceMarker::NuitkaErrNormalize);
    let has_make_cell: bool = markers.contains_key(&CSourceMarker::MakeCell);
    let has_call_fast: bool = markers.contains_key(&CSourceMarker::CallFunctionFast);
    let has_coroutine: bool = markers.contains_key(&CSourceMarker::NuitkaCoroutineObject);
    let has_asyncgen: bool = markers.contains_key(&CSourceMarker::NuitkaAsyncgenObject);
    let has_create_global: bool = markers.contains_key(&CSourceMarker::CreateGlobalConstants);
    let has_load_blob: bool = markers.contains_key(&CSourceMarker::LoadConstantsBlob);
    let has_compiled_method: bool =
        markers.contains_key(&CSourceMarker::NuitkaCompiledMethodObject);

    if has_version_tag && has_module_loader && has_err_normalize && !has_load_blob {
        return NuitkaEraGuess::V3OrV4;
    }
    if has_compiled_method && has_make_cell && has_call_fast && has_asyncgen {
        return NuitkaEraGuess::V2_7Plus;
    }
    if has_make_cell && has_call_fast && has_asyncgen {
        return NuitkaEraGuess::V2_4ToV2_6;
    }
    if has_coroutine && has_load_blob {
        return NuitkaEraGuess::V2_0ToV2_3;
    }
    if has_create_global && has_load_blob {
        return NuitkaEraGuess::V1_4ToV1_9;
    }
    if has_load_blob {
        return NuitkaEraGuess::Pre1_4;
    }
    NuitkaEraGuess::Unknown
}

#[allow(clippy::cast_precision_loss)]
fn compute_confidence(markers: &BTreeMap<CSourceMarker, u32>, total_hits: u32) -> f32 {
    let unique_kinds: f32 = markers.len() as f32;
    let total_kinds: f32 = MARKER_TABLE.len() as f32;
    let coverage: f32 = unique_kinds / total_kinds;
    let density: f32 = ((total_hits as f32).log10().max(0.0)) / 4.0_f32;
    coverage
        .mul_add(0.7_f32, density.min(1.0_f32) * 0.3_f32)
        .clamp(0.0_f32, 1.0_f32)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[test]
    fn empty_image_errors_not_nuitka() {
        let Err(err): Result<DecompReadyMarkers> = scan_c_source_markers(&[]) else {
            panic!("empty must error");
        };
        assert!(matches!(err, Error::NotNuitka));
    }

    #[test]
    fn detects_load_constants_blob_minimal() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        let m: DecompReadyMarkers = scan_c_source_markers(&bytes).expect("ok");
        assert!(m.markers.contains_key(&CSourceMarker::LoadConstantsBlob));
        assert!(m.total_hits >= 1);
        assert!(m.confidence > 0.0);
    }

    #[test]
    fn era_guess_pre_1_4_when_only_load_blob() {
        let mut bytes: Vec<u8> = vec![0u8; 4096];
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        let m: DecompReadyMarkers = scan_c_source_markers(&bytes).expect("ok");
        assert_eq!(m.era_guess, NuitkaEraGuess::Pre1_4);
    }

    #[test]
    fn era_guess_v1_when_create_global_present() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        bytes[200..221].copy_from_slice(b"createGlobalConstants");
        let m: DecompReadyMarkers = scan_c_source_markers(&bytes).expect("ok");
        assert_eq!(m.era_guess, NuitkaEraGuess::V1_4ToV1_9);
    }

    #[test]
    fn era_guess_v2_4_when_make_cell_call_fast_asyncgen() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        bytes[200..209].copy_from_slice(b"MAKE_CELL");
        bytes[300..318].copy_from_slice(b"CALL_FUNCTION_FAST");
        bytes[400..421].copy_from_slice(b"Nuitka_AsyncgenObject");
        let m: DecompReadyMarkers = scan_c_source_markers(&bytes).expect("ok");
        assert_eq!(m.era_guess, NuitkaEraGuess::V2_4ToV2_6);
    }

    #[test]
    fn era_guess_v2_7_when_compiled_method_present() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        bytes[200..209].copy_from_slice(b"MAKE_CELL");
        bytes[300..318].copy_from_slice(b"CALL_FUNCTION_FAST");
        bytes[400..421].copy_from_slice(b"Nuitka_AsyncgenObject");
        bytes[500..517].copy_from_slice(b"Nuitka_Method_New");
        let m: DecompReadyMarkers = scan_c_source_markers(&bytes).expect("ok");
        assert_eq!(m.era_guess, NuitkaEraGuess::V2_7Plus);
    }

    #[test]
    fn count_occurrences_counts_distinct_overlapping_matches() {
        let hay: &[u8] = b"abababab";
        assert_eq!(count_occurrences(hay, b"ab"), 4);
    }

    #[test]
    fn confidence_grows_with_more_unique_markers() {
        let mut bytes: Vec<u8> = vec![0u8; 8192];
        bytes[100..117].copy_from_slice(b"loadConstantsBlob");
        let low: DecompReadyMarkers = scan_c_source_markers(&bytes).expect("low");
        bytes[200..221].copy_from_slice(b"Nuitka_FunctionObject");
        bytes[300..322].copy_from_slice(b"Nuitka_GeneratorObject");
        bytes[400..419].copy_from_slice(b"_PyDict_NewPresized");
        let high: DecompReadyMarkers = scan_c_source_markers(&bytes).expect("high");
        assert!(high.confidence > low.confidence);
    }
}
