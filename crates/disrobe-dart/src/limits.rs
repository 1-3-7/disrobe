use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const HARD_CLUSTER_LIMIT: usize = 4096;
const HARD_OBJECT_LIMIT: usize = 2_000_000;
const HARD_REFERENCE_LIMIT: usize = 16_000_000;
const HARD_STRING_CODE_UNIT_LIMIT: usize = 16 * 1024 * 1024;
const HARD_TOTAL_STRING_BYTE_LIMIT: usize = 256 * 1024 * 1024;
const HARD_VARIABLE_LENGTH_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryLimits {
    pub clusters: usize,
    pub objects: usize,
    pub references: usize,
    pub string_code_units: usize,
    pub total_string_bytes: usize,
    pub variable_length: usize,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            clusters: 4096,
            objects: 2_000_000,
            references: 16_000_000,
            string_code_units: 16 * 1024 * 1024,
            total_string_bytes: 256 * 1024 * 1024,
            variable_length: 64 * 1024 * 1024,
        }
    }
}

impl RecoveryLimits {
    pub(crate) fn validate(self) -> Result<()> {
        validate_limit("configured clusters", self.clusters, HARD_CLUSTER_LIMIT)?;
        validate_limit("configured objects", self.objects, HARD_OBJECT_LIMIT)?;
        validate_limit(
            "configured references",
            self.references,
            HARD_REFERENCE_LIMIT,
        )?;
        validate_limit(
            "configured string code units",
            self.string_code_units,
            HARD_STRING_CODE_UNIT_LIMIT,
        )?;
        validate_limit(
            "configured total string bytes",
            self.total_string_bytes,
            HARD_TOTAL_STRING_BYTE_LIMIT,
        )?;
        validate_limit(
            "configured variable length",
            self.variable_length,
            HARD_VARIABLE_LENGTH_LIMIT,
        )?;
        Ok(())
    }
}

const fn validate_limit(resource: &'static str, actual: usize, limit: usize) -> Result<()> {
    if actual > limit {
        return Err(Error::LimitExceeded {
            resource,
            actual,
            limit,
        });
    }
    Ok(())
}
