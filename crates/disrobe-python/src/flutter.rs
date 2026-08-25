use disrobe_pass_mobile::{
    FLUTTER_ENGINE_SYMBOL_MAP_FORMAT, FlutterEngineIdentity, FlutterEngineSymbol,
    parse_flutter_engine_symbol_map, validate_flutter_engine_symbol_map_for_elf,
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
    provenance: [FlutterEngineSymbolProvenance; 1],
}

#[derive(Serialize)]
struct FlutterEngineSymbolProvenance {
    source: String,
    kind: &'static str,
    identity: String,
}

#[pyfunction]
#[pyo3(signature = (input, engine_symbol_map, *, source))]
#[pyo3(text_signature = "(input, engine_symbol_map, *, source)")]
fn flutter_engine_symbols(
    input: &[u8],
    engine_symbol_map: &[u8],
    source: String,
) -> PyResult<FlutterEngineSymbols> {
    let map = parse_flutter_engine_symbol_map(engine_symbol_map)
        .map_err(map_error("flutter engine symbol map"))?;
    let validated = validate_flutter_engine_symbol_map_for_elf(input, map)
        .map_err(map_error("flutter engine symbol map"))?;
    let identity: &FlutterEngineIdentity = validated.identity();
    let report = FlutterEngineSymbolsReport {
        identity,
        symbols: validated.symbols(),
        provenance: [FlutterEngineSymbolProvenance {
            source,
            kind: FLUTTER_ENGINE_SYMBOL_MAP_FORMAT,
            identity: identity.value.clone(),
        }],
    };
    FlutterEngineSymbols::from_serialize(&report)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(flutter_engine_symbols, m)?)?;
    Ok(())
}
