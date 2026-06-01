#[derive(Debug, Clone)]
pub struct MutualInfoHint {
    pub plaintext_oracle_window: Vec<u8>,
    pub max_search_iterations: u32,
}

impl Default for MutualInfoHint {
    fn default() -> Self {
        Self {
            plaintext_oracle_window: b"\xe3\x00\x00\x00\x00".to_vec(),
            max_search_iterations: 1_000_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MutualInfoOutcome {
    pub recovered_key: Option<[u8; 16]>,
    pub iterations: u32,
    pub confidence: f64,
    pub notes: Vec<String>,
}

pub fn recover_with_mutual_info_hint(
    ciphertext: &[u8],
    hint: &MutualInfoHint,
) -> MutualInfoOutcome {
    let _ = ciphertext;
    let _ = hint;
    MutualInfoOutcome {
        recovered_key: None,
        iterations: 0,
        confidence: 0.0,
        notes: vec![
            "DR-PYARM-STATIC: mutual-information statistical recovery is reserved for partially corrupted streams; upstream does not implement this path either. API surface is preserved for future work."
                .to_owned(),
        ],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn returns_no_key_with_unimplemented_note() {
        let outcome: MutualInfoOutcome =
            recover_with_mutual_info_hint(&[0u8; 64], &MutualInfoHint::default());
        assert!(outcome.recovered_key.is_none());
        assert!(outcome.iterations == 0);
        assert!(!outcome.notes.is_empty());
    }
}
