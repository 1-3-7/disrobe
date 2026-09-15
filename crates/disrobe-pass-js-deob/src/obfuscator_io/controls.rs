use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ObfControl {
    Booleans,
    ControlFlowFlattening,
    FunctionInlining,
    Identifiers,
    Numbers,
    Objects,
    Predicates,
    RegularExpressions,
    Statements,
    Strings,
    Variables,
    Minification,
}

impl ObfControl {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Booleans => "booleans",
            Self::ControlFlowFlattening => "controlFlowFlattening",
            Self::FunctionInlining => "functionInlining",
            Self::Identifiers => "identifiers",
            Self::Numbers => "numbers",
            Self::Objects => "objects",
            Self::Predicates => "predicates",
            Self::RegularExpressions => "regularExpressions",
            Self::Statements => "statements",
            Self::Strings => "strings",
            Self::Variables => "variables",
            Self::Minification => "minification",
        }
    }

    pub const ALL: [Self; 12] = [
        Self::Booleans,
        Self::ControlFlowFlattening,
        Self::FunctionInlining,
        Self::Identifiers,
        Self::Numbers,
        Self::Objects,
        Self::Predicates,
        Self::RegularExpressions,
        Self::Statements,
        Self::Strings,
        Self::Variables,
        Self::Minification,
    ];
}
