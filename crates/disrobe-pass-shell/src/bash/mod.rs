pub(crate) mod arith;
pub(crate) mod bash_eval;
pub mod bashfuscator;
pub mod indirect;
pub mod lexer;

pub use bashfuscator::{BashfuscatorLevel, BashfuscatorReport, reverse_bashfuscator};
pub use indirect::{IndirectionReport, peel_indirection, peel_indirection_with_policy};
pub use lexer::{BashToken, BashTokenKind, tokenize_bash};
