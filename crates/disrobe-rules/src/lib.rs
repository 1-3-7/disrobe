#![forbid(unsafe_code)]
#![doc = "Data-driven deobfuscation rewrite rules for the disrobe suite."]
#![doc = ""]
#![doc = "Deobfuscation peephole identities are expressed as DATA: a serde-validated"]
#![doc = "schema pairs a match-pattern over the normalized bitvector expression shape"]
#![doc = "([`disrobe_mba::Expr`]) with a rewrite template. New coverage needs a rule in"]
#![doc = "a rules file, not a code fork."]
#![doc = ""]
#![doc = "The schema, loader, and bounded apply engine live in [`disrobe_mba::rules`],"]
#![doc = "where [`disrobe_mba::canonicalize`] drives them as the production rewrite path"]
#![doc = "for the migrated MBA peephole identities. This crate is the stable public"]
#![doc = "facade over that module: the rules-as-data are loaded and applied through the"]
#![doc = "same engine the simplifier itself uses, not a parallel mirror."]

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
