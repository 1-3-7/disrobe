use serde_json::{Map, Value};

use super::model::BccLinkMap;

const SCHEMA: &str = "disrobe.pyarmor.bcc.function_map/1";

pub(crate) fn to_json(map: &BccLinkMap) -> Value {
    let mut by_offset: Map<String, Value> = Map::new();
    for record in &map.records {
        let Some(native) = record.native.as_ref() else {
            continue;
        };
        let key: String = format!("{:#x}", native.offset);
        let value: Value = serde_json::to_value(record).unwrap_or(Value::Null);
        by_offset.insert(key, value);
    }

    let records: Vec<Value> = map
        .records
        .iter()
        .map(|record| serde_json::to_value(record).unwrap_or(Value::Null))
        .collect();

    let summary: Value = serde_json::to_value(&map.summary).unwrap_or(Value::Null);
    let notes: Value = serde_json::to_value(&map.notes).unwrap_or(Value::Null);

    let mut root: Map<String, Value> = Map::new();
    root.insert("schema".to_owned(), Value::String(SCHEMA.to_owned()));
    root.insert(
        "module".to_owned(),
        map.module.clone().map_or(Value::Null, Value::String),
    );
    root.insert(
        "py_path".to_owned(),
        map.py_path.clone().map_or(Value::Null, Value::String),
    );
    root.insert(
        "python_version".to_owned(),
        Value::String(map.python_version.clone()),
    );
    root.insert("summary".to_owned(), summary);
    root.insert("functions_by_offset".to_owned(), Value::Object(by_offset));
    root.insert("functions".to_owned(), Value::Array(records));
    root.insert("notes".to_owned(), notes);
    Value::Object(root)
}

pub(crate) fn to_json_string(map: &BccLinkMap) -> String {
    serde_json::to_string_pretty(&to_json(map)).unwrap_or_else(|_| "{}".to_owned())
}
