use disrobe_py_marshal::{CodeObject, Object, PyVersion, load as marshal_load};

use super::cipher::stream_xor;
use super::loader::LazyBlob;
use crate::error::{Error, Result};

const MAX_REINSERT_DEPTH: usize = 64;

pub(crate) struct ReinsertReport {
    pub(crate) restored: usize,
}

pub(crate) fn reinsert_lazy_blobs(
    code: &mut CodeObject,
    blobs: &[LazyBlob],
    version: PyVersion,
) -> Result<ReinsertReport> {
    let mut report: ReinsertReport = ReinsertReport { restored: 0 };
    reinsert_into(code, blobs, version, &mut report, 0)?;
    Ok(report)
}

fn reinsert_into(
    code: &mut CodeObject,
    blobs: &[LazyBlob],
    version: PyVersion,
    report: &mut ReinsertReport,
    depth: usize,
) -> Result<()> {
    if depth > MAX_REINSERT_DEPTH {
        return Err(Error::Marshal(
            "lazy reinsertion exceeded nesting depth".to_owned(),
        ));
    }
    for konst in &mut code.consts {
        let Object::Code(inner): &mut Object = konst else {
            continue;
        };
        if let Some(idx) = stub_index(&inner.name) {
            let blob: &LazyBlob = blobs
                .get(idx)
                .ok_or_else(|| Error::Marshal(format!("lazy blob index {idx} out of range")))?;
            let decrypted: Vec<u8> = stream_xor(&blob.ciphertext, &blob.key);
            let object: Object = marshal_load(&decrypted, version)
                .map_err(|e| Error::Marshal(format!("lazy blob {idx} demarshal failed: {e}")))?;
            let Object::Code(real): Object = object else {
                return Err(Error::Marshal(format!(
                    "lazy blob {idx} did not hold a code object"
                )));
            };
            *inner = real;
            report.restored += 1;
        }
        reinsert_into(inner, blobs, version, report, depth + 1)?;
    }
    Ok(())
}

fn stub_index(name: &Object) -> Option<usize> {
    let text: &str = match name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.as_str(),
        _ => return None,
    };
    let inner: &str = text.strip_prefix("<pw")?.strip_suffix('>')?;
    usize::from_str_radix(inner, 16).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn stub_index_parses_hex() {
        let name: Object = Object::String {
            value: "<pwa>".to_owned(),
            interned: false,
        };
        assert_eq!(stub_index(&name), Some(10));
        let plain: Object = Object::String {
            value: "greet".to_owned(),
            interned: false,
        };
        assert_eq!(stub_index(&plain), None);
    }
}
