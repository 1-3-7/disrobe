use crate::feature::{Characteristic, Feature, OperandFeature};

pub(super) fn normalize_tag(raw: &str) -> String {
    raw.trim()
        .chars()
        .map(|c: char| {
            if c == '_' || c == ' ' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

pub(super) fn characteristic_from_tag(raw: &str) -> Option<Characteristic> {
    match normalize_tag(raw).as_str() {
        "non-zeroing-xor" | "nzxor" => Some(Characteristic::NonZeroingXor),
        "tight-loop" => Some(Characteristic::TightLoop),
        "indirect-call" => Some(Characteristic::IndirectCall),
        "stack-string" => Some(Characteristic::StackString),
        "peb-access" => Some(Characteristic::PebAccess),
        "fs-access" => Some(Characteristic::FsAccess),
        "gs-access" => Some(Characteristic::GsAccess),
        "cross-section-flow" => Some(Characteristic::CrossSectionFlow),
        "loop" => Some(Characteristic::Loop),
        "recursive-call" => Some(Characteristic::RecursiveCall),
        "embedded-pe" => Some(Characteristic::EmbeddedPe),
        _ => None,
    }
}

pub(super) const fn feature_is_supported(feature: &Feature) -> bool {
    !matches!(
        feature,
        Feature::Bytes(_)
            | Feature::Operand {
                inner: OperandFeature::Offset(_),
                ..
            }
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_tag_folds_separators_and_case() {
        assert_eq!(normalize_tag("Tight Loop"), "tight-loop");
        assert_eq!(normalize_tag("non_zeroing_xor"), "non-zeroing-xor");
        assert_eq!(normalize_tag("EMBEDDED-PE"), "embedded-pe");
    }

    #[test]
    fn characteristic_tag_accepts_both_spelling_conventions() {
        assert_eq!(
            characteristic_from_tag("nzxor"),
            Some(Characteristic::NonZeroingXor)
        );
        assert_eq!(
            characteristic_from_tag("non-zeroing-xor"),
            Some(Characteristic::NonZeroingXor)
        );
        assert_eq!(characteristic_from_tag("tag-alpha"), None);
    }

    #[test]
    fn bytes_and_operand_offset_are_unsupported() {
        assert!(!feature_is_supported(&Feature::Bytes(vec![0x90])));
        assert!(!feature_is_supported(&Feature::Operand {
            index: 0,
            inner: OperandFeature::Offset(0x10)
        }));
        assert!(feature_is_supported(&Feature::Operand {
            index: 0,
            inner: OperandFeature::Number(0x10)
        }));
        assert!(feature_is_supported(&Feature::Mnemonic("xor".to_owned())));
    }
}
