mod integrity_strip;
mod opaque_pred;

pub use integrity_strip::{IntegrityStripStats, strip_integrity_imports};
pub use opaque_pred::{OpaquePredStats, kill_opaque_predicates};
