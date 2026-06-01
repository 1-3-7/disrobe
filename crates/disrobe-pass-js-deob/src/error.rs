use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-JSDEOB-0001: source does not match any known obfuscator pattern")]
    NoFamilyMatched,

    #[error("DR-JSDEOB-0002: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-JSDEOB-0003: oxc parse error: {0}")]
    OxcParse(String),

    #[error("DR-JSDEOB-0004: invalid UTF-8 in JS source")]
    Utf8,

    #[error(
        "DR-JSDEOB-0010: transform `{transform}` requires `--i-have-authorization`; \
        see LEGAL.md and docs/legal/jscrambler-stance.md before bypassing protector code locks or RASP guards"
    )]
    AuthorizationRequired { transform: &'static str },

    #[error("DR-JSDEOB-0011: transform `{transform}` not yet implemented (deferred-due-to-budget)")]
    TransformNotYetImplemented { transform: &'static str },

    #[error(
        "DR-JS-PACE-DetectOnly: PACE bypass is not implemented and will not be implemented under \
        any flag; see {stance_doc} for the §1201(a) analysis"
    )]
    PaceBypassUnsupported { stance_doc: &'static str },
}
