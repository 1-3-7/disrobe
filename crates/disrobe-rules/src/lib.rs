#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

pub use disrobe_mba::rules::{engine, error, loader, schema};

pub use disrobe_mba::rules::{
    ApplyError, Binary, Condition, LoadError, MBA_PEEPHOLE_RULES, Pattern, Rule, RuleHit, RuleSet,
    Template, Unary, apply_root, load_str, mba_peephole_rules, rewrite_fixpoint,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}
