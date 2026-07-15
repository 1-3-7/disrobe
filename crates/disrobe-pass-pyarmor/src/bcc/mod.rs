use std::path::Path;

use disrobe_py_marshal::{CodeObject, Object, PyVersion, load};

use crate::error::{Error, Result};
use crate::unpack::UnpackOutput;
use crate::v8v9::BccBlob;

mod dispatch;
mod join;
pub mod model;
mod residual;
mod skeleton;
mod stub;

mod map;

pub use model::{
    BccLinkMap, BodyStatus, EvidenceSource, FunctionKind, FunctionRecord, LinkConfidence,
    LinkSummary, NameStatus, NativeRef, ParamKind, Parameter, Signature, SourceIdentity,
};

#[derive(Debug, Clone)]
pub struct BccLinkOutput {
    pub map: BccLinkMap,
    pub skeleton: String,
}

impl BccLinkOutput {
    #[must_use]
    pub fn json_value(&self) -> serde_json::Value {
        map::to_json(&self.map)
    }

    #[must_use]
    pub fn json(&self) -> String {
        map::to_json_string(&self.map)
    }
}

#[must_use]
pub fn link_bcc_module(
    module_code: &CodeObject,
    blobs: &[BccBlob],
    wrapper_text: &str,
    wrapper_path: &Path,
    python_version: &str,
) -> BccLinkOutput {
    let residual: residual::ResidualModule = residual::extract_module(module_code);
    let stub: stub::StubInfo = stub::analyze_stub(wrapper_text, wrapper_path);
    let mut dispatch_entries: Vec<dispatch::DispatchEntry> = Vec::new();
    for (index, blob) in blobs.iter().enumerate() {
        dispatch_entries.extend(dispatch::parse_dispatch(
            &blob.bytes,
            blob.architecture,
            index,
        ));
    }
    let map: BccLinkMap = join::link(
        &residual,
        &dispatch_entries,
        &stub,
        python_version.to_owned(),
    );
    let skeleton: String = skeleton::render(&residual, &map);
    BccLinkOutput { map, skeleton }
}

pub fn link_bcc_from_unpack(
    output: &UnpackOutput,
    wrapper_text: &str,
    wrapper_path: &Path,
) -> Result<BccLinkOutput> {
    let pyc: &Vec<u8> = output
        .pyc
        .as_ref()
        .ok_or_else(|| Error::BccLinkNoResidual("no decrypted module pyc available".to_owned()))?;
    let py_version: PyVersion = output.py_version.unwrap_or_else(|| PyVersion::new(3, 12));
    let stream: &[u8] = pyc.get(16..).unwrap_or(&[]);
    let object: Object = load(stream, py_version)?;
    let Object::Code(module_code): Object = object else {
        return Err(Error::BccLinkNoResidual(
            "decrypted marshal root is not a module code object".to_owned(),
        ));
    };
    let version_str: String = format!("{}.{}", py_version.major, py_version.minor);
    Ok(link_bcc_module(
        &module_code,
        &output.bcc_blobs,
        wrapper_text,
        wrapper_path,
        &version_str,
    ))
}
