mod detect;
mod rewrite;

pub use detect::{JsObfuDetection, detect_jsobfu};
pub use rewrite::{JsObfuRewriteStats, rewrite_bracket_access};
