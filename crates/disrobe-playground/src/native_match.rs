use disrobe_pass_native::{
    NATIVE_MATCH_DEFAULT_LIMIT, NativeMatchError, NativeMatchOptions, NativeMatchStage,
    match_native_images,
};
use disrobe_similarity::MatchSummary;

const MAX_NATIVE_MATCH_INPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeMatchRequest {
    pub limit: Option<usize>,
    pub function: Option<u64>,
    pub stage: Option<NativeMatchStage>,
}

impl Default for NativeMatchRequest {
    fn default() -> Self {
        Self {
            limit: Some(NATIVE_MATCH_DEFAULT_LIMIT),
            function: None,
            stage: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NativeMatchUploadError {
    #[error(
        "DR-PLAYGROUND-0100: upload {side} is {actual} bytes; the native match limit is {limit} bytes per input"
    )]
    InputTooLarge {
        side: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error(transparent)]
    Match(#[from] NativeMatchError),
}

pub fn match_native_uploads(
    a: &[u8],
    b: &[u8],
    request: NativeMatchRequest,
) -> Result<MatchSummary, NativeMatchUploadError> {
    ensure_input_bound("a", a)?;
    ensure_input_bound("b", b)?;
    match_native_images(
        "a",
        a,
        "b",
        b,
        NativeMatchOptions {
            limit: Some(request.limit.unwrap_or(NATIVE_MATCH_DEFAULT_LIMIT)),
            function: request.function,
            stage: request.stage,
        },
    )
    .map_err(Into::into)
}

const fn ensure_input_bound(
    side: &'static str,
    input: &[u8],
) -> Result<(), NativeMatchUploadError> {
    if input.len() > MAX_NATIVE_MATCH_INPUT_BYTES {
        return Err(NativeMatchUploadError::InputTooLarge {
            side,
            actual: input.len(),
            limit: MAX_NATIVE_MATCH_INPUT_BYTES,
        });
    }
    Ok(())
}
