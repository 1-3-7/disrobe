use serde::{Deserialize, Serialize};

use crate::pass::PassId;

use super::detection::DetectContext;
use super::ecosystem::{Ecosystem, ecosystem_for};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportQuality {
    Full,
    Partial,
    DetectOnly,
}

impl SupportQuality {
    #[inline]
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::DetectOnly => "detect-only",
        }
    }
}

pub trait CatalogEntry: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn aliases(&self) -> &'static [&'static str];
    fn support_quality(&self) -> SupportQuality;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectorOutput {
    pub entry_id: &'static str,
    pub confidence: f32,
    pub markers: Vec<String>,
}

impl DetectorOutput {
    #[inline]
    #[must_use]
    pub const fn new(entry_id: &'static str, confidence: f32, markers: Vec<String>) -> Self {
        Self {
            entry_id,
            confidence,
            markers,
        }
    }
}

pub trait ObfuscatorCatalog: Send + Sync {
    fn pass_id(&self) -> PassId;
    fn catalog(&self) -> Vec<&'static dyn CatalogEntry>;
    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput>;
    fn hint_unidentified(&self, _ctx: &DetectContext<'_>) -> Option<String> {
        None
    }
    fn ecosystem(&self) -> Ecosystem {
        ecosystem_for(self.pass_id())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct StaticEntry;

    impl CatalogEntry for StaticEntry {
        fn id(&self) -> &'static str {
            "demo-obf"
        }
        fn display_name(&self) -> &'static str {
            "Demo Obfuscator"
        }
        fn aliases(&self) -> &'static [&'static str] {
            &["demo", "demoobf"]
        }
        fn support_quality(&self) -> SupportQuality {
            SupportQuality::Full
        }
    }

    static DEMO_ENTRY: StaticEntry = StaticEntry;

    #[derive(Debug)]
    struct DemoCatalog;

    impl ObfuscatorCatalog for DemoCatalog {
        fn pass_id(&self) -> PassId {
            "demo.pass"
        }
        fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
            vec![&DEMO_ENTRY]
        }
        fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
            if ctx.bytes.starts_with(b"DEMO") {
                Some(DetectorOutput::new(
                    "demo-obf",
                    0.95,
                    vec!["demo-magic".to_owned()],
                ))
            } else {
                None
            }
        }
    }

    #[test]
    fn support_quality_serializes_kebab_case() {
        let json: String = serde_json::to_string(&SupportQuality::DetectOnly).expect("serialize");
        assert_eq!(json, "\"detect-only\"");
        assert_eq!(SupportQuality::Partial.label(), "partial");
        assert_eq!(SupportQuality::Full.label(), "full");
    }

    #[test]
    fn catalog_entry_trait_object_dispatches() {
        let cat: DemoCatalog = DemoCatalog;
        let entries: Vec<&'static dyn CatalogEntry> = cat.catalog();
        assert_eq!(entries.len(), 1);
        let entry: &dyn CatalogEntry = entries[0];
        assert_eq!(entry.id(), "demo-obf");
        assert_eq!(entry.display_name(), "Demo Obfuscator");
        assert_eq!(entry.aliases(), &["demo", "demoobf"]);
        assert_eq!(entry.support_quality(), SupportQuality::Full);
        assert_eq!(cat.pass_id(), "demo.pass");
    }

    #[test]
    fn detect_returns_output_for_match() {
        let cat: DemoCatalog = DemoCatalog;
        let ctx: DetectContext<'_> = DetectContext {
            bytes: b"DEMO payload",
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let out: DetectorOutput = cat.detect(&ctx).expect("detector returns Some");
        assert_eq!(out.entry_id, "demo-obf");
        assert_eq!(out.confidence, 0.95);
        assert_eq!(out.markers, vec!["demo-magic".to_owned()]);
    }

    #[test]
    fn detect_returns_none_for_miss() {
        let cat: DemoCatalog = DemoCatalog;
        let ctx: DetectContext<'_> = DetectContext {
            bytes: b"other",
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(cat.detect(&ctx).is_none());
    }

    #[test]
    fn hint_unidentified_defaults_to_none() {
        let cat: DemoCatalog = DemoCatalog;
        let ctx: DetectContext<'_> = DetectContext {
            bytes: b"other",
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        assert!(cat.hint_unidentified(&ctx).is_none());
    }
}
