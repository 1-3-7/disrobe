use crate::ast::node::Comprehension;
use crate::bytecode::version::PyVersion;

#[must_use]
pub fn supports_pep_709(version: &PyVersion) -> bool {
    let (maj, min): (u8, u8) = (version.major(), version.minor());
    maj > 3 || (maj == 3 && min >= 12)
}

#[must_use]
pub fn is_inlined(_c: &Comprehension, version: &PyVersion) -> bool {
    supports_pep_709(version)
}
