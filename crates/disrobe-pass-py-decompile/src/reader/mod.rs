use disrobe_py_marshal::{CodeObject, PyVersion};

use crate::error::Result;

#[derive(Debug)]
pub struct LoadedModule {
    pub code: CodeObject,
    pub version: PyVersion,
}

pub trait PycReader {
    fn load(&self, bytes: &[u8]) -> Result<LoadedModule>;
}
