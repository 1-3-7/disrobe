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
#[must_use]
pub fn mba_peephole_rule_pack_id() -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in MBA_PEEPHOLE_RULES
        .bytes()
        .chain(std::iter::once(0))
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

static MIGRATED_RULES: OnceLock<Result<RuleSet, LoadError>> = OnceLock::new();

pub(crate) fn migrated_peephole_rules() -> Result<&'static RuleSet, &'static LoadError> {
    MIGRATED_RULES.get_or_init(mba_peephole_rules).as_ref()
}

#[must_use]
pub(crate) fn apply_migrated(expr: &Expr, width: crate::expr::Width) -> Option<Expr> {
    let rules: &RuleSet = migrated_peephole_rules().ok()?;
    apply_root(rules, expr, width).map(|hit: RuleHit| hit.result)
}
