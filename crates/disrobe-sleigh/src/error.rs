use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SleighError {
    ConditionalDepth { limit: usize },
    ConditionalSyntax { line: String },
    ExpandedSourceLimit { limit: usize },
    IncludeCycle { stack: Vec<String> },
    IncludeDepth { limit: usize },
    InvalidDirective { line: String },
    InvalidPath { path: String },
    MacroExpansionLimit { limit: usize },
    MissingMacro { name: String },
    MissingSource { path: String },
    Parse { message: String, offset: usize },
    SourceCountLimit { limit: usize },
    SourceBytesLimit { limit: usize },
    UnbalancedConditional { path: String },
}

impl Display for SleighError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConditionalDepth { limit } => {
                write!(formatter, "conditional depth exceeds {limit}")
            }
            Self::ConditionalSyntax { line } => {
                write!(formatter, "invalid preprocessor condition: {line}")
            }
            Self::ExpandedSourceLimit { limit } => {
                write!(formatter, "expanded source exceeds {limit} bytes")
            }
            Self::IncludeCycle { stack } => {
                write!(formatter, "include cycle: {}", stack.join(" -> "))
            }
            Self::IncludeDepth { limit } => write!(formatter, "include depth exceeds {limit}"),
            Self::InvalidDirective { line } => {
                write!(formatter, "invalid preprocessor directive: {line}")
            }
            Self::InvalidPath { path } => write!(formatter, "invalid source path: {path}"),
            Self::MacroExpansionLimit { limit } => {
                write!(formatter, "macro expansion exceeds {limit} replacements")
            }
            Self::MissingMacro { name } => write!(formatter, "undefined macro: {name}"),
            Self::MissingSource { path } => write!(formatter, "missing source: {path}"),
            Self::Parse { message, offset } => {
                write!(formatter, "Sleigh parse error at byte {offset}: {message}")
            }
            Self::SourceCountLimit { limit } => {
                write!(formatter, "included source count exceeds {limit}")
            }
            Self::SourceBytesLimit { limit } => {
                write!(formatter, "input source exceeds {limit} total bytes")
            }
            Self::UnbalancedConditional { path } => {
                write!(formatter, "unbalanced conditional in {path}")
            }
        }
    }
}

impl Error for SleighError {}
