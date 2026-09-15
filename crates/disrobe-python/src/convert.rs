use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serde::Serialize;
use serde_json::{Map, Number, Value};

use crate::err::DisrobeError;

const MAX_PY_JSON_DEPTH: usize = 256;
const MAX_PY_JSON_ITEMS: usize = 1_000_000;

#[inline]
pub(crate) fn to_value<T: Serialize>(value: &T) -> PyResult<Value> {
    serde_json::to_value(value)
        .map_err(|e: serde_json::Error| DisrobeError::new_err(format!("serialize: {e}")))
}

#[inline]
pub(crate) fn to_py<'py, T: Serialize>(py: Python<'py>, value: &T) -> PyResult<Bound<'py, PyAny>> {
    let parsed: Value = to_value(value)?;
    value_to_py(py, &parsed)
}

pub(crate) fn value_to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    value_to_py_at_depth(py, value, 0)
}

fn value_to_py_at_depth<'py>(
    py: Python<'py>,
    value: &Value,
    depth: usize,
) -> PyResult<Bound<'py, PyAny>> {
    if depth > MAX_PY_JSON_DEPTH {
        return Err(DisrobeError::new_err(format!(
            "Python object exceeds conversion depth cap of {MAX_PY_JSON_DEPTH}"
        )));
    }
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(b) => bool_to_py(py, *b),
        Value::Number(n) => number_to_py(py, n),
        Value::String(s) => Ok(s.into_pyobject(py)?.into_any()),
        Value::Array(items) => {
            check_container_len("array", items.len())?;
            let next: usize = next_depth(depth)?;
            let list: Bound<'py, PyList> = PyList::empty(py);
            for item in items {
                list.append(value_to_py_at_depth(py, item, next)?)?;
            }
            Ok(list.into_any())
        }
        Value::Object(map) => {
            check_container_len("object", map.len())?;
            let next: usize = next_depth(depth)?;
            let dict: Bound<'py, PyDict> = PyDict::new(py);
            for (key, item) in map {
                dict.set_item(key, value_to_py_at_depth(py, item, next)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

#[inline]
fn bool_to_py(py: Python<'_>, value: bool) -> PyResult<Bound<'_, PyAny>> {
    Ok(value.into_pyobject(py)?.to_owned().into_any())
}

#[inline]
fn number_to_py<'py>(py: Python<'py>, number: &Number) -> PyResult<Bound<'py, PyAny>> {
    if let Some(unsigned) = number.as_u64() {
        return Ok(unsigned.into_pyobject(py)?.into_any());
    }
    if let Some(signed) = number.as_i64() {
        return Ok(signed.into_pyobject(py)?.into_any());
    }
    let float: f64 = number
        .as_f64()
        .ok_or_else(|| DisrobeError::new_err(format!("unrepresentable number: {number}")))?;
    Ok(float.into_pyobject(py)?.into_any())
}

pub(crate) fn from_py(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    from_py_at_depth(obj, 0)
}

fn from_py_at_depth(obj: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
    if depth > MAX_PY_JSON_DEPTH {
        return Err(DisrobeError::new_err(format!(
            "Python object exceeds conversion depth cap of {MAX_PY_JSON_DEPTH}"
        )));
    }
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = obj.cast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if let Ok(i) = obj.cast::<PyInt>() {
        return py_int_to_value(i);
    }
    if let Ok(f) = obj.cast::<PyFloat>() {
        let value: f64 = f.value();
        return Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| DisrobeError::new_err(format!("non-finite float: {value}")));
    }
    if let Ok(s) = obj.cast::<PyString>() {
        return Ok(Value::String(s.extract::<String>()?));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        check_container_len("list", list.len())?;
        let next: usize = next_depth(depth)?;
        let mut items: Vec<Value> = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(from_py_at_depth(&item, next)?);
        }
        return Ok(Value::Array(items));
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        check_container_len("dict", dict.len())?;
        let next: usize = next_depth(depth)?;
        let mut map: Map<String, Value> = Map::with_capacity(dict.len());
        for (key, item) in dict.iter() {
            let key_str: String = key.str()?.extract::<String>()?;
            map.insert(key_str, from_py_at_depth(&item, next)?);
        }
        return Ok(Value::Object(map));
    }
    Err(DisrobeError::new_err(format!(
        "unsupported Python type for conversion: {}",
        obj.get_type()
            .name()
            .map_or_else(|_| "?".to_owned(), |n: Bound<'_, PyString>| n.to_string())
    )))
}

fn next_depth(depth: usize) -> PyResult<usize> {
    let next: usize = depth
        .checked_add(1)
        .ok_or_else(|| DisrobeError::new_err("Python object conversion depth overflow"))?;
    if next > MAX_PY_JSON_DEPTH {
        return Err(DisrobeError::new_err(format!(
            "Python object exceeds conversion depth cap of {MAX_PY_JSON_DEPTH}"
        )));
    }
    Ok(next)
}

fn check_container_len(kind: &str, len: usize) -> PyResult<()> {
    if len > MAX_PY_JSON_ITEMS {
        return Err(DisrobeError::new_err(format!(
            "Python {kind} too large to convert: {len} items exceeds {MAX_PY_JSON_ITEMS}"
        )));
    }
    Ok(())
}

#[inline]
fn py_int_to_value(int: &Bound<'_, PyInt>) -> PyResult<Value> {
    if let Ok(signed) = int.extract::<i64>() {
        return Ok(Value::Number(Number::from(signed)));
    }
    if let Ok(unsigned) = int.extract::<u64>() {
        return Ok(Value::Number(Number::from(unsigned)));
    }
    let float: f64 = int.extract::<f64>()?;
    Number::from_f64(float)
        .map(Value::Number)
        .ok_or_else(|| DisrobeError::new_err(format!("integer too large to represent: {int}")))
}
