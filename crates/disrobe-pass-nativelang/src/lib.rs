#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![deny(missing_debug_implementations)]

pub mod demangle;
pub mod detect;
pub mod error;
pub mod image;
pub mod pass;
pub mod recover;

use serde::{Deserialize, Serialize};

pub use demangle::{DemangledSymbol, demangle_crystal, demangle_nim, demangle_zig};
pub use detect::{LangFingerprint, NativeLang, fingerprint};
pub use error::{Error, Result};
pub use image::{ImageKind, NativeImage, Section};
pub use pass::{
    NativeLangPass, NativeLangPassReport, PASS_INPUT_PATH_CAP, PassInput, decode_pass_input,
};
pub use recover::{GcMetadata, Recovery, module_histogram, recover};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeLangAnalysis {
    pub image_kind: ImageKind,
    pub ptr_size: u8,
    pub fingerprint: LangFingerprint,
    pub recovery: Recovery,
}

pub fn analyze(bytes: &[u8]) -> Result<NativeLangAnalysis> {
    let image: NativeImage<'_> = NativeImage::parse(bytes)?;
    let fp: LangFingerprint = fingerprint(&image).ok_or(Error::NoLanguageFingerprint)?;
    let recovery: Recovery = recover(&image, fp.lang);
    Ok(NativeLangAnalysis {
        image_kind: image.kind,
        ptr_size: image.ptr_size,
        fingerprint: fp,
        recovery,
    })
}
