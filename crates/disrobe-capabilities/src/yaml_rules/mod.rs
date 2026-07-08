mod callgraph;
mod load;
mod node;
mod runtime;
mod schema;
mod vocab;

pub use load::{LoadError, load_rules};
pub use node::{LoadedRule, LoadedRuleSet, Node, UnsupportedRule};

use disrobe_query::Module;

use crate::eval::CapabilityMatch;
use crate::extract::ScopedFeatures;

#[must_use]
pub fn evaluate(
    rules: &LoadedRuleSet,
    module: &Module,
    scoped: &ScopedFeatures,
) -> Vec<CapabilityMatch> {
    runtime::run(&rules.rules, module, scoped)
}
