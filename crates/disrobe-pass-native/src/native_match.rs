use disrobe_similarity::{
    DEFAULT_LISTING_LIMIT, FunctionFeatures, ListingStage, MatchReport, MatchSummary, Selector,
    StreamingMatchSummary, collect_listing, match_functions, streaming_summary, summarize,
};

use crate::extract_function_features;

pub use disrobe_similarity::ListingStage as NativeMatchStage;

pub const NATIVE_MATCH_DEFAULT_LIMIT: usize = DEFAULT_LISTING_LIMIT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeMatchOptions {
    pub limit: Option<usize>,
    pub function: Option<u64>,
    pub stage: Option<ListingStage>,
}

impl Default for NativeMatchOptions {
    fn default() -> Self {
        Self {
            limit: Some(DEFAULT_LISTING_LIMIT),
            function: None,
            stage: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NativeMatchError {
    #[error("DR-NATIVE-0202: cannot read functions from {label}: {reason}")]
    LeftFeatures { label: String, reason: String },
    #[error("DR-NATIVE-0203: cannot read functions from {label}: {reason}")]
    RightFeatures { label: String, reason: String },
    #[error(
        "DR-NATIVE-0204: no function to match: {left_label} carries {left_count} function(s), {right_label} carries {right_count}"
    )]
    NoFunctions {
        left_label: String,
        left_count: usize,
        right_label: String,
        right_count: usize,
    },
    #[error("DR-NATIVE-0208: no function at address {address:#x} in either input")]
    FunctionNotFound { address: u64 },
    #[error("DR-NATIVE-0209: function and stage cannot be combined")]
    ConflictingSelectors,
}

#[derive(Debug)]
pub struct NativeMatchAnalysis {
    left_label: String,
    right_label: String,
    left: Vec<FunctionFeatures>,
    right: Vec<FunctionFeatures>,
    report: MatchReport,
}

impl NativeMatchAnalysis {
    pub fn present_streaming(&self, stage: Option<ListingStage>) -> StreamingMatchSummary<'_> {
        let selector: Selector = stage.map_or(Selector::All, Selector::Stage);
        streaming_summary(
            &self.left_label,
            &self.right_label,
            &self.left,
            &self.right,
            &self.report,
            selector,
        )
    }

    pub fn present(&self, options: NativeMatchOptions) -> Result<MatchSummary, NativeMatchError> {
        if options.function.is_some() && options.stage.is_some() {
            return Err(NativeMatchError::ConflictingSelectors);
        }
        let selector: Selector = selector(options);
        let listing = collect_listing(&self.report, selector, options.limit);
        let summary: MatchSummary = summarize(
            &self.left_label,
            &self.right_label,
            &self.left,
            &self.right,
            &self.report,
            listing,
        );
        if let Some(address) = summary.listing.function
            && summary.a_verdicts.is_empty()
            && summary.b_verdicts.is_empty()
        {
            return Err(NativeMatchError::FunctionNotFound { address });
        }
        Ok(summary)
    }
}

pub fn analyze_native_images(
    left_label: &str,
    left_bytes: &[u8],
    right_label: &str,
    right_bytes: &[u8],
) -> Result<NativeMatchAnalysis, NativeMatchError> {
    let left: Vec<FunctionFeatures> =
        extract_function_features(left_bytes).map_err(|error| NativeMatchError::LeftFeatures {
            label: left_label.to_owned(),
            reason: error.to_string(),
        })?;
    let right: Vec<FunctionFeatures> = extract_function_features(right_bytes).map_err(|error| {
        NativeMatchError::RightFeatures {
            label: right_label.to_owned(),
            reason: error.to_string(),
        }
    })?;
    if left.is_empty() || right.is_empty() {
        return Err(NativeMatchError::NoFunctions {
            left_label: left_label.to_owned(),
            left_count: left.len(),
            right_label: right_label.to_owned(),
            right_count: right.len(),
        });
    }
    let report: MatchReport = match_functions(&left, &right);
    Ok(NativeMatchAnalysis {
        left_label: left_label.to_owned(),
        right_label: right_label.to_owned(),
        left,
        right,
        report,
    })
}

pub fn match_native_images(
    left_label: &str,
    left_bytes: &[u8],
    right_label: &str,
    right_bytes: &[u8],
    options: NativeMatchOptions,
) -> Result<MatchSummary, NativeMatchError> {
    analyze_native_images(left_label, left_bytes, right_label, right_bytes)?.present(options)
}

const fn selector(options: NativeMatchOptions) -> Selector {
    if let Some(address) = options.function {
        return Selector::Function(address);
    }
    match (options.stage, options.limit) {
        (Some(stage), _) => Selector::Stage(stage),
        (None, Some(_)) => Selector::Listing,
        (None, None) => Selector::All,
    }
}
