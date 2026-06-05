use std::fmt::Debug;

use crate::pass::PassId;

use super::detection::{DetectContext, DetectVerdict};

pub use crate::pass::Pass;

pub trait Detector: Debug + Send + Sync {
    fn id(&self) -> PassId;
    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict>;
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::chain::detection::{ConfidenceBand, DetectVerdict};

    #[derive(Debug)]
    struct AlwaysHigh;
    impl Detector for AlwaysHigh {
        fn id(&self) -> PassId {
            "test.always-high"
        }
        fn detect(&self, _ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
            Some(DetectVerdict::new(
                "test.always-high",
                "tag",
                "obfuscator-wrapper",
                0.99,
                10,
                vec!["magic"],
                "always-high".to_string(),
            ))
        }
    }

    #[test]
    fn detector_trait_objects_dispatch() {
        let d: &dyn Detector = &AlwaysHigh;
        let ctx: DetectContext<'_> = DetectContext {
            bytes: b"any",
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let v: DetectVerdict = d.detect(&ctx).expect("detector returns Some");
        assert_eq!(v.band, ConfidenceBand::High);
        assert_eq!(v.specificity, 10);
        assert_eq!(d.id(), "test.always-high");
    }

    #[test]
    fn detector_returning_none_yields_no_verdict() {
        #[derive(Debug)]
        struct Never;
        impl Detector for Never {
            fn id(&self) -> PassId {
                "test.never"
            }
            fn detect(&self, _ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
                None
            }
        }
        let d: &dyn Detector = &Never;
        let ctx: DetectContext<'_> = DetectContext {
            bytes: b"",
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(d.detect(&ctx).is_none());
    }
}
