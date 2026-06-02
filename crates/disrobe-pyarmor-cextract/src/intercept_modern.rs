use pyo3::prelude::*;
use pyo3::types::{PyCFunction, PyDict, PyModule};

use crate::error::{CextractError, Result};

const TOOL_NAME: &str = "disrobe-cextract";

#[derive(Debug, Clone, Copy)]
pub(crate) struct ModernInstallInfo {
    pub tool_id: i32,
    pub py_start_event: i32,
}

pub(crate) fn install(
    py: Python<'_>,
    callback: Bound<'_, PyCFunction>,
) -> Result<ModernInstallInfo> {
    let sys: Bound<'_, PyModule> = py.import("sys").map_err(CextractError::from)?;
    let monitoring: Bound<'_, PyAny> = sys
        .getattr("monitoring")
        .map_err(|_| CextractError::MonitoringUnavailable)?;

    let tool_id: i32 = pick_free_tool_id(&monitoring)?;
    monitoring
        .call_method1("use_tool_id", (tool_id, TOOL_NAME))
        .map_err(|e: PyErr| {
            CextractError::MonitoringSetup(format!("use_tool_id({tool_id}): {e}"))
        })?;

    let events_mod: Bound<'_, PyAny> = monitoring
        .getattr("events")
        .map_err(|e: PyErr| CextractError::MonitoringSetup(format!("events: {e}")))?;
    let py_start_obj: Bound<'_, PyAny> = events_mod
        .getattr("PY_START")
        .map_err(|e: PyErr| CextractError::MonitoringSetup(format!("PY_START: {e}")))?;
    let py_start_event: i32 = py_start_obj
        .extract::<i32>()
        .map_err(|e: PyErr| CextractError::MonitoringSetup(format!("PY_START extract: {e}")))?;

    monitoring
        .call_method1("register_callback", (tool_id, py_start_event, callback))
        .map_err(|e: PyErr| CextractError::MonitoringSetup(format!("register_callback: {e}")))?;
    monitoring
        .call_method1("set_events", (tool_id, py_start_event))
        .map_err(|e: PyErr| CextractError::MonitoringSetup(format!("set_events: {e}")))?;

    Ok(ModernInstallInfo {
        tool_id,
        py_start_event,
    })
}

pub(crate) fn uninstall(py: Python<'_>, info: ModernInstallInfo) -> Result<()> {
    let sys: Bound<'_, PyModule> = py.import("sys").map_err(CextractError::from)?;
    let monitoring: Bound<'_, PyAny> = sys
        .getattr("monitoring")
        .map_err(|_| CextractError::MonitoringUnavailable)?;
    let _: std::result::Result<Bound<'_, PyAny>, PyErr> =
        monitoring.call_method1("set_events", (info.tool_id, 0i32));
    let _: std::result::Result<Bound<'_, PyAny>, PyErr> = monitoring.call_method1(
        "register_callback",
        (info.tool_id, info.py_start_event, py.None()),
    );
    let _: std::result::Result<Bound<'_, PyAny>, PyErr> =
        monitoring.call_method1("free_tool_id", (info.tool_id,));
    Ok(())
}

fn pick_free_tool_id(monitoring: &Bound<'_, PyAny>) -> Result<i32> {
    for candidate in [5i32, 4, 3, 2, 1, 0] {
        let name_obj: PyResult<Bound<'_, PyAny>> =
            monitoring.call_method1("get_tool", (candidate,));
        let occupied: bool = name_obj.map_or(true, |obj: Bound<'_, PyAny>| !obj.is_none());
        if !occupied {
            return Ok(candidate);
        }
    }
    Err(CextractError::MonitoringSetup(
        "no free monitoring tool id (0..=5 all in use)".to_owned(),
    ))
}

pub(crate) fn supported(py: Python<'_>) -> bool {
    let Ok(sys): PyResult<Bound<'_, PyModule>> = py.import("sys") else {
        return false;
    };
    let Ok(version_info): PyResult<Bound<'_, PyAny>> = sys.getattr("version_info") else {
        return false;
    };
    let major: i32 = version_info
        .get_item(0)
        .and_then(|o: Bound<'_, PyAny>| o.extract::<i32>())
        .unwrap_or(0);
    let minor: i32 = version_info
        .get_item(1)
        .and_then(|o: Bound<'_, PyAny>| o.extract::<i32>())
        .unwrap_or(0);
    (major, minor) >= (3, 12) && sys.hasattr("monitoring").unwrap_or(false)
}

#[allow(dead_code)]
pub(crate) fn diagnostics(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let d: Bound<'_, PyDict> = PyDict::new(py);
    d.set_item("supported", supported(py))?;
    d.set_item("tool_name", TOOL_NAME)?;
    Ok(d)
}
