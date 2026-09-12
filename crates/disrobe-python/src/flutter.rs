use std::path::PathBuf;

use disrobe_pass_mobile::{
    FLUTTER_ENGINE_SYMBOL_CACHE_FORMAT, FLUTTER_ENGINE_SYMBOL_MAP_FORMAT, FlutterEngineIdentity,
    FlutterEngineSymbol, FlutterEngineSymbolCache, flutter_engine_identity_for_elf,
    parse_flutter_engine_symbol_map, validate_cached_flutter_engine_symbols_for_elf,
    validate_flutter_engine_symbol_map_for_elf,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map as map_error;
use crate::typed::FlutterEngineSymbols;

#[derive(Serialize)]
struct FlutterEngineSymbolsReport<'a> {
    identity: &'a FlutterEngineIdentity,
    symbols: &'a [FlutterEngineSymbol],
    provenance: &'a [FlutterEngineSymbolProvenance],
}

#[derive(Serialize)]
struct FlutterEngineSymbolProvenance {
    source: String,
    kind: &'static str,
    identity: String,
}

#[pyfunction]
#[pyo3(signature = (input, engine_symbol_map=None, *, source=None, cache_dir=None, no_cache=false))]
#[pyo3(
    text_signature = "(input, engine_symbol_map=None, *, source=None, cache_dir=None, no_cache=False)"
)]
fn flutter_engine_symbols(
    input: &[u8],
    engine_symbol_map: Option<&[u8]>,
    source: Option<String>,
    cache_dir: Option<PathBuf>,
    no_cache: bool,
) -> PyResult<FlutterEngineSymbols> {
    let cache: Option<FlutterEngineSymbolCache> = (!no_cache)
        .then(|| cache_dir.as_deref().map(FlutterEngineSymbolCache::new))
        .flatten();
    let (identity, symbols, provenance): (
        FlutterEngineIdentity,
        Vec<FlutterEngineSymbol>,
        Vec<FlutterEngineSymbolProvenance>,
    ) = if let Some(engine_symbol_map) = engine_symbol_map {
        let source: String = source.ok_or_else(|| {
            pyo3::exceptions::PyTypeError::new_err(
                "source is required when engine_symbol_map is supplied",
            )
        })?;
        let map = parse_flutter_engine_symbol_map(engine_symbol_map)
            .map_err(map_error("flutter engine symbol map"))?;
        let validated = validate_flutter_engine_symbol_map_for_elf(input, map)
            .map_err(map_error("flutter engine symbol map"))?;
        if let Some(cache) = &cache {
            cache
                .store_validated(&validated)
                .map_err(map_error("flutter engine symbol cache"))?;
        }
        let identity: FlutterEngineIdentity = validated.identity().clone();
        let symbols: Vec<FlutterEngineSymbol> = validated.symbols().to_vec();
        let provenance: Vec<FlutterEngineSymbolProvenance> = vec![FlutterEngineSymbolProvenance {
            source,
            kind: FLUTTER_ENGINE_SYMBOL_MAP_FORMAT,
            identity: identity.value.clone(),
        }];
        (identity, symbols, provenance)
    } else {
        let identity: FlutterEngineIdentity = flutter_engine_identity_for_elf(input)
            .map_err(map_error("flutter engine cache identity"))?;
        let validated = match cache.as_ref() {
            Some(cache) => cache
                .load(&identity)
                .map_err(map_error("flutter engine symbol cache"))?
                .and_then(|symbols: Vec<FlutterEngineSymbol>| {
                    validate_cached_flutter_engine_symbols_for_elf(input, identity.clone(), symbols)
                        .ok()
                }),
            None => None,
        };
        let (symbols, provenance): (Vec<FlutterEngineSymbol>, Vec<FlutterEngineSymbolProvenance>) =
            validated.map_or_else(
                || (Vec::new(), Vec::new()),
                |validated| {
                    (
                        validated.symbols().to_vec(),
                        vec![FlutterEngineSymbolProvenance {
                            source: "cache".to_owned(),
                            kind: FLUTTER_ENGINE_SYMBOL_CACHE_FORMAT,
                            identity: identity.value.clone(),
                        }],
                    )
                },
            );
        (identity, symbols, provenance)
    };
    let report = FlutterEngineSymbolsReport {
        identity: &identity,
        symbols: &symbols,
        provenance: &provenance,
    };
    FlutterEngineSymbols::from_serialize(&report)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(flutter_engine_symbols, m)?)?;
    Ok(())
}
