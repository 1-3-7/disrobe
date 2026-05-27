use serde::Serialize;

use crate::category::Category;

/// Const-friendly capability declaration for a pass crate.
///
/// Each pass declares its supported categories as a `const METADATA_CAPABILITY`
/// so the runtime can decide ahead of time which `emit_*` calls are worth
/// attempting — the trait default returns `None` for every method, but a pass
/// may also expose its capability matrix as data for tooling (CLI `--help`
/// rendering, schema-driven test gen) without ever calling the trait.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct MetadataCapability {
    pub pass: &'static str,
    pub pass_version: &'static str,
    pub supports: &'static [Category],
}

impl MetadataCapability {
    #[must_use]
    pub const fn new(
        pass: &'static str,
        pass_version: &'static str,
        supports: &'static [Category],
    ) -> Self {
        Self {
            pass,
            pass_version,
            supports,
        }
    }

    /// `const fn` membership test. Safe to call from `const` context, which lets
    /// pass crates encode capability-gated branches at compile time.
    #[must_use]
    pub const fn supports(&self, cat: Category) -> bool {
        let mut i: usize = 0;
        while i < self.supports.len() {
            if matches!(
                (self.supports[i], cat),
                (Category::Ast, Category::Ast)
                    | (Category::Disasm, Category::Disasm)
                    | (Category::Cfg, Category::Cfg)
                    | (Category::Dfg, Category::Dfg)
                    | (Category::Symbols, Category::Symbols)
                    | (Category::Strings, Category::Strings)
                    | (Category::Types, Category::Types)
                    | (Category::Imports, Category::Imports)
                    | (Category::Constants, Category::Constants)
                    | (Category::Signatures, Category::Signatures)
                    | (Category::Provenance, Category::Provenance)
                    | (Category::RoundtripVerdict, Category::RoundtripVerdict)
                    | (Category::SourceMap, Category::SourceMap)
                    | (Category::Manifest, Category::Manifest)
                    | (Category::DecryptionKeys, Category::DecryptionKeys)
                    | (Category::Confidence, Category::Confidence)
                    | (Category::OpcodeCoverage, Category::OpcodeCoverage)
                    | (Category::PiiMap, Category::PiiMap)
            ) {
                return true;
            }
            i += 1;
        }
        false
    }
}
