#![forbid(unsafe_code)]

mod error;
mod object;
mod pyc;
mod reader;
mod reftable;
mod validator;
mod version;
mod writer;

pub use error::{Error, Result};
pub use object::{BigInt, CodeEra, CodeObject, LocalKind, Object, code_era_for};
pub use pyc::{PycFile, PycHeader, read_pyc, write_pyc};
pub use reader::{load, load_with_reftable};
pub use reftable::{RefEntry, RefKind, RefTableDump, dump_reftable};
pub use validator::{RoundTripReport, validate_roundtrip, validate_roundtrip_strict};
pub use version::{PyVersion, magic_for, pyversion_from_magic};
pub use writer::dump;
