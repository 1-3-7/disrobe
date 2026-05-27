pub mod bashfuscator;
pub mod indirect;
pub mod lexer;

pub use bashfuscator::{BashfuscatorLevel, BashfuscatorReport, reverse_bashfuscator};
pub use indirect::{IndirectionReport, peel_indirection};
pub use lexer::{BashToken, BashTokenKind, tokenize_bash};
