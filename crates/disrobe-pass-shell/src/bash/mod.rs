pub(crate) mod arith;
pub(crate) mod bash_eval;
pub mod bashfuscator;
pub(crate) mod decode;
pub mod indirect;
pub mod lexer;
pub mod node_bash_obfuscate;
pub(crate) mod param_expand;

pub use bashfuscator::{
    BashfuscatorLevel, BashfuscatorReport, reverse_bashfuscator, reverse_bashfuscator_auto,
};
pub use indirect::{IndirectionReport, peel_indirection, peel_indirection_with_policy};
pub use lexer::{BashToken, BashTokenKind, tokenize_bash};
pub use node_bash_obfuscate::{
    NodeBashObfuscateReport, is_node_bash_obfuscate, reverse_node_bash_obfuscate,
};
