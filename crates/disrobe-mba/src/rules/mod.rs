use crate::expr::Expr;

pub mod egraph_rules;
pub mod engine;
pub mod error;
pub mod loader;
mod oracle;
pub mod schema;

pub use engine::{RuleHit, apply_root, rewrite_fixpoint};
pub use error::{ApplyError, LoadError};
pub use loader::load_str;
pub use schema::{Binary, Condition, Pattern, Rule, RuleSet, Template, Unary};

pub const MBA_PEEPHOLE_RULES: &str = include_str!("rules_data/mba_peephole.toml");
pub const MBA_PEEPHOLE_AUDIT: &str = include_str!("rules_data/mba_peephole_audit.toml");
pub const MBA_PEEPHOLE_RULE_PACK_METADATA_KEY: &str = "mba.rule_pack_id";

#[must_use]
pub fn mba_peephole_rule_pack_id() -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in MBA_PEEPHOLE_RULES
        .bytes()
        .chain([0].into_iter())
        .chain(MBA_PEEPHOLE_AUDIT.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("mba-peephole/fnv1a64-{hash:016x}")
}

pub fn mba_peephole_rules() -> Result<RuleSet, LoadError> {
    loader::load_str(MBA_PEEPHOLE_RULES)
}

use std::sync::OnceLock;

static MIGRATED_RULES: OnceLock<RuleSet> = OnceLock::new();

#[allow(
    clippy::panic,
    reason = "the rule set is a compile-time include_str! const proven to load and validate by the shipped_rules_load_and_have_six_migrated_rules test; a parse failure here is a build-integrity bug, and failing loud beats silently disabling the production rewrite path"
)]
#[must_use]
pub(crate) fn migrated_peephole_rules() -> &'static RuleSet {
    MIGRATED_RULES.get_or_init(|| match mba_peephole_rules() {
        Ok(set) => set,
        Err(error) => panic!("shipped mba peephole rules must validate: {error}"),
    })
}

#[must_use]
pub(crate) fn apply_migrated(expr: &Expr, width: crate::expr::Width) -> Option<Expr> {
    apply_root(migrated_peephole_rules(), expr, width).map(|hit: RuleHit| hit.result)
}
