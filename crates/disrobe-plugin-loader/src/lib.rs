//! Signed WASM-Component plugin loader.

mod manifest;

pub use manifest::{Manifest, ManifestError};

use std::io::Cursor;

use minisign::{PublicKey, SignatureBox};
use thiserror::Error;
use wasmtime::Engine;
use wasmtime::component::Component;

/// Reasons the loader refuses to load a component.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LoaderError {
    /// The signature failed to parse or did not verify under the trusted key.
    #[error("signature verification failed: {0}")]
    BadSignature(String),

    /// The signature is well-formed but was produced by an untrusted key.
    #[error("signature was produced by an untrusted key")]
    Untrusted,

    /// The component imports a WIT capability the manifest does not grant.
    #[error("capability `{capability}` is imported but not granted by the manifest")]
    CapabilityDenied {
        /// The denied import name.
        capability: String,
    },

    /// The bytes are not a valid WebAssembly component.
    #[error("component is malformed: {0}")]
    Malformed(String),
}

/// Verify a signed component against `trusted_key`, enforce capability grants, and compile it.
///
/// # Errors
///
/// Returns a [`LoaderError`] when signature, trust, validity, or capability gates fail.
pub fn load_signed(
    component: &[u8],
    signature: &[u8],
    trusted_key: &PublicKey,
    manifest: &Manifest,
) -> Result<Component, LoaderError> {
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
