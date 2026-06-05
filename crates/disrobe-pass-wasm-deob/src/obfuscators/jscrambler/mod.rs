mod integrity_strip;
mod opaque_pred;

pub use integrity_strip::{
    IntegrityCfgStats, IntegrityStripStats, eliminate_integrity_guards, strip_integrity_imports,
};
pub use opaque_pred::{OpaquePredStats, kill_opaque_predicates};
