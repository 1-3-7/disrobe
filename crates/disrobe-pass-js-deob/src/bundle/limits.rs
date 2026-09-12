use std::ops::Deref;

use super::ExtractedModule;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub struct UnbundleLimits {
    pub input_bytes: usize,
    pub modules: usize,
    pub output_bytes: usize,
}

impl UnbundleLimits {
    pub(super) const UNLIMITED: Self = Self {
        input_bytes: usize::MAX,
        modules: usize::MAX,
        output_bytes: usize::MAX,
    };
}

pub(super) const fn check_limit(kind: &'static str, value: usize, maximum: usize) -> Result<()> {
    if value > maximum {
        Err(Error::SyntaxLimit {
            kind,
            observed: value,
            maximum,
        })
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct ModuleCollector {
    modules: Vec<ExtractedModule>,
    limits: UnbundleLimits,
    bytes: usize,
    error: Option<Error>,
}

impl ModuleCollector {
    pub(super) const fn new(limits: UnbundleLimits) -> Self {
        Self {
            modules: Vec::new(),
            limits,
            bytes: 0,
            error: None,
        }
    }

    pub(super) fn push(&mut self, id: &str, chunk_id: Option<&str>, source: &str) {
        if self.error.is_some() {
            return;
        }
        let reserved: Result<usize> =
            self.reserve(id.len(), chunk_id.map_or(0, str::len), source.len());
        match reserved {
            Ok(bytes) => {
                self.modules.push(ExtractedModule {
                    id: id.to_owned(),
                    chunk_id: chunk_id.map(str::to_owned),
                    source: source.to_owned(),
                });
                self.bytes = bytes;
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn reserve(&self, id: usize, chunk: usize, source: usize) -> Result<usize> {
        check_limit(
            "bundle module count",
            self.modules.len().saturating_add(1),
            self.limits.modules,
        )?;
        let bytes: usize = self
            .bytes
            .checked_add(id)
            .and_then(|value: usize| value.checked_add(chunk))
            .and_then(|value: usize| value.checked_add(source))
            .ok_or(Error::SyntaxLimit {
                kind: "bundle output bytes",
                observed: usize::MAX,
                maximum: self.limits.output_bytes,
            })?;
        check_limit("bundle output bytes", bytes, self.limits.output_bytes)?;
        Ok(bytes)
    }

    pub(super) fn finish(self) -> Result<Vec<ExtractedModule>> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.modules),
        }
    }
}

impl Deref for ModuleCollector {
    type Target = [ExtractedModule];

    fn deref(&self) -> &Self::Target {
        &self.modules
    }
}

#[cfg(test)]
pub(super) fn collect_for_test(
    source: &str,
    collect: fn(&str, &mut ModuleCollector),
) -> Vec<ExtractedModule> {
    let mut modules: ModuleCollector = ModuleCollector::new(UnbundleLimits::UNLIMITED);
    collect(source, &mut modules);
    assert!(modules.error.is_none());
    modules.modules
}
