use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("rule file is not valid toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("rule file is {bytes} bytes, above the {max} byte cap")]
    TooLarge { bytes: usize, max: usize },
    #[error("rule set is empty")]
    Empty,
    #[error("rule set has {count} rules, above the {max} rule cap")]
    TooManyRules { count: usize, max: usize },
    #[error("rule name {rule:?} is empty or contains an unsupported byte")]
    InvalidRuleName { rule: String },
    #[error("rule name {rule:?} is {bytes} bytes, above the {max} byte cap")]
    RuleNameTooLong {
        rule: String,
        bytes: usize,
        max: usize,
    },
    #[error("rule {rule:?} has {count} conditions, above the {max} condition cap")]
    TooManyConditions {
        rule: String,
        count: usize,
        max: usize,
    },
    #[error("rule {rule:?} capture name {capture:?} is empty or contains an unsupported byte")]
    InvalidCaptureName { rule: String, capture: String },
    #[error("rule {rule:?} capture name {capture:?} is {bytes} bytes, above the {max} byte cap")]
    CaptureNameTooLong {
        rule: String,
        capture: String,
        bytes: usize,
        max: usize,
    },
    #[error("rule {rule:?} has invalid slice range [{lo}, {hi})")]
    InvalidSliceRange { rule: String, lo: u32, hi: u32 },
    #[error("rule {rule:?} pattern has {nodes} nodes, above the {max} node cap")]
    PatternTooLarge {
        rule: String,
        nodes: usize,
        max: usize,
    },
    #[error("rule {rule:?} rewrite has {nodes} nodes, above the {max} node cap")]
    TemplateTooLarge {
        rule: String,
        nodes: usize,
        max: usize,
    },
    #[error("rule {rule:?} references unbound capture {capture:?} in its rewrite or condition")]
    UnboundCapture { rule: String, capture: String },
    #[error("rule {rule:?} binds capture {capture:?} more than once")]
    DuplicateCapture { rule: String, capture: String },
    #[error("rule {rule:?} has a duplicate name")]
    DuplicateRuleName { rule: String },
    #[error("rule {rule:?} has no declared valid widths")]
    MissingWidths { rule: String },
    #[error("rule {rule:?} declares unsupported width {width}")]
    UnsupportedWidth { rule: String, width: u8 },
    #[error("rule {rule:?} declares width {width} more than once")]
    DuplicateWidth { rule: String, width: u8 },
    #[error("rule {rule:?} has no shared-oracle proof route")]
    MissingProofRoute { rule: String },
    #[error("rule {rule:?} has no source reference")]
    MissingSource { rule: String },
    #[error("rule {rule:?} did not prove equivalent at declared width {width}")]
    EquivalenceRejected { rule: String, width: u8 },
    #[error("unconditional rewrite rules form a cycle through {rule:?}")]
    RewriteCycle { rule: String },
}

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("rewrite template referenced capture {0:?} that the pattern never bound")]
    MissingCapture(String),
    #[error("rewrite template used capture {capture:?} as an expression but it bound a constant")]
    CaptureKindMismatch { capture: String },
    #[error("rewrite recursion exceeded the bound of {0} nodes")]
    DepthExceeded(usize),
}
