use std::collections::BTreeMap;

use disrobe_py_marshal::CodeObject;

use super::dispatch::{DispatchEntry, code_at};
use super::dispatch_recover::recover_bcc_arith;
use super::model::{BccLinkMap, FunctionRecord, NativeRef};
use super::recover::{PyAbi, RecoverOptions, RecoveredBody};
use super::residual::{FunctionArtifacts, collect_function_artifacts};
use crate::v8v9::BccBlob;

pub(crate) fn populate(
    map: &mut BccLinkMap,
    module_code: &CodeObject,
    blobs: &[BccBlob],
    dispatch: &[DispatchEntry],
) {
    let mut by_offset: BTreeMap<u64, &DispatchEntry> = BTreeMap::new();
    for entry in dispatch {
        by_offset.entry(entry.code_offset).or_insert(entry);
    }
    let artifacts: BTreeMap<String, FunctionArtifacts> = collect_function_artifacts(module_code);

    for record in &mut map.records {
        let Some(native): Option<&NativeRef> = record.native.as_ref() else {
            continue;
        };
        let Some(entry): Option<&&DispatchEntry> = by_offset.get(&native.offset) else {
            continue;
        };
        let Some(blob): Option<&BccBlob> = blobs.get(entry.container_index) else {
            continue;
        };
        let Some(code): Option<Vec<u8>> = code_at(&blob.bytes, native.offset, native.size) else {
            continue;
        };
        let argcount: usize = record.signature.argcount as usize;
        let artifact: Option<&FunctionArtifacts> = artifacts.get(&record.source.qualname);
        let mut options: RecoverOptions = RecoverOptions::new(
            bare_name(&record.source.qualname),
            PyAbi::from_arch(blob.architecture),
            argcount,
        );
        options.param_names = param_names(record, artifact, argcount);
        let empty: &[Option<i128>] = &[];
        let consts: &[Option<i128>] =
            artifact.map_or(empty, |a: &FunctionArtifacts| a.const_ints.as_slice());
        let body: RecoveredBody = recover_bcc_arith(&code, native.offset, &options, consts);
        record.recovered_body = body.recovered_python;
    }
}

fn param_names(
    record: &FunctionRecord,
    artifact: Option<&FunctionArtifacts>,
    argcount: usize,
) -> Vec<String> {
    if let Some(art) = artifact
        && art.param_names.len() == argcount
    {
        return art.param_names.clone();
    }
    record
        .signature
        .parameters
        .iter()
        .take(argcount)
        .map(|p: &super::model::Parameter| p.name.clone())
        .collect()
}

fn bare_name(qualname: &str) -> String {
    qualname.rsplit('.').next().unwrap_or(qualname).to_owned()
}
