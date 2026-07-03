mod manifest;

pub use manifest::{Manifest, ManifestError};

use std::io::Cursor;

use minisign::{PublicKey, SignatureBox};
use thiserror::Error;
use wasmtime::Engine;
use wasmtime::component::Component;

const MAX_SIGNED_COMPONENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LoaderError {
    #[error("component is too large: {len} bytes exceeds {limit}")]
    ComponentTooLarge { len: usize, limit: usize },

    #[error("signature is too large: {len} bytes exceeds {limit}")]
    SignatureTooLarge { len: usize, limit: usize },

    #[error("signature verification failed: {0}")]
    BadSignature(String),

    #[error("signature was produced by an untrusted key")]
    Untrusted,

    #[error("capability `{capability}` is imported but not granted by the manifest")]
    CapabilityDenied { capability: String },

    #[error("component is malformed: {0}")]
    Malformed(String),
}

pub fn load_signed(
    component: &[u8],
    signature: &[u8],
    trusted_key: &PublicKey,
    manifest: &Manifest,
) -> Result<Component, LoaderError> {
    if component.len() > MAX_SIGNED_COMPONENT_BYTES {
        return Err(LoaderError::ComponentTooLarge {
            len: component.len(),
            limit: MAX_SIGNED_COMPONENT_BYTES,
        });
    }
    if signature.len() > MAX_SIGNATURE_BYTES {
        return Err(LoaderError::SignatureTooLarge {
            len: signature.len(),
            limit: MAX_SIGNATURE_BYTES,
        });
    }

    let signature_text: &str = std::str::from_utf8(signature)
        .map_err(|err| LoaderError::BadSignature(format!("signature is not valid utf-8: {err}")))?;

    let signature_box: SignatureBox = SignatureBox::from_string(signature_text)
        .map_err(|err| LoaderError::BadSignature(format!("malformed signature: {err}")))?;

    if signature_box.keynum() != trusted_key.keynum() {
        return Err(LoaderError::Untrusted);
    }

    let reader: Cursor<&[u8]> = Cursor::new(component);
    minisign::verify(trusted_key, &signature_box, reader, true, false, false)
        .map_err(|err| LoaderError::BadSignature(err.to_string()))?;

    let engine: Engine = Engine::default();

    let compiled: Component = Component::from_binary(&engine, component)
        .map_err(|err| LoaderError::Malformed(err.to_string()))?;

    enforce_capabilities(&compiled, &engine, manifest)?;

    Ok(compiled)
}

fn enforce_capabilities(
    component: &Component,
    engine: &Engine,
    manifest: &Manifest,
) -> Result<(), LoaderError> {
    let component_type: wasmtime::component::types::Component = component.component_type();
    for (import_name, _item) in component_type.imports(engine) {
        if !manifest.grants(import_name) {
            return Err(LoaderError::CapabilityDenied {
                capability: import_name.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
