use std::collections::BTreeSet;

use disrobe_llm_metadata::Category;
#[cfg(feature = "full")]
use disrobe_llm_metadata::MetadataCapability;

use crate::cli::llm::LlmFlags;

#[cfg(feature = "full")]
const UNIMPLEMENTED_CATEGORIES: &[(Category, &str)] = &[(
    Category::PiiMap,
    "no pass implements emit_pii_map; the category is tracked for implementation or withdrawal",
)];

#[cfg(feature = "full")]
fn linked_capabilities() -> Vec<MetadataCapability> {
    let mut capabilities: Vec<MetadataCapability> = vec![
        disrobe_pass_native::NATIVE_METADATA_CAPABILITY,
        disrobe_pass_pyarmor::PYARMOR_METADATA_CAPABILITY,
        disrobe_pass_py_deob::PY_DEOB_METADATA_CAPABILITY,
        disrobe_pass_py_disasm::METADATA_CAPABILITY,
        disrobe_pass_py_decompile::METADATA_CAPABILITY,
    ];
    #[cfg(feature = "irsummary")]
    capabilities.push(disrobe_irsummary::METADATA_CAPABILITY);
    #[cfg(feature = "js")]
    capabilities.push(disrobe_pass_js_deob::JS_METADATA_CAPABILITY);
    #[cfg(feature = "wasm")]
    capabilities.push(disrobe_pass_wasm_deob::WASM_METADATA_CAPABILITY);
    #[cfg(feature = "jvm")]
    capabilities.push(disrobe_pass_jvm::JVM_METADATA_CAPABILITY);
    #[cfg(feature = "dotnet")]
    capabilities.push(disrobe_pass_dotnet::DOTNET_METADATA_CAPABILITY);
    #[cfg(feature = "go")]
    capabilities.push(disrobe_pass_go::GO_METADATA_CAPABILITY);
    capabilities
}

#[cfg(feature = "full")]
fn implementors_of(category: Category) -> Vec<&'static str> {
    linked_capabilities()
        .into_iter()
        .filter(|capability: &MetadataCapability| capability.supports(category))
        .map(|capability: MetadataCapability| capability.pass)
        .collect()
}

#[cfg(feature = "full")]
fn allowlisted(category: Category) -> bool {
    UNIMPLEMENTED_CATEGORIES
        .iter()
        .any(|(known, _): &(Category, &str)| *known == category)
}

#[test]
#[cfg(feature = "full")]
fn every_flag_category_has_an_implementor_linked_into_the_binary() {
    let uncovered: Vec<&'static str> = Category::ALL
        .into_iter()
        .filter(|category: &Category| !allowlisted(*category))
        .filter(|category: &Category| implementors_of(*category).is_empty())
        .map(Category::label)
        .collect();
    assert!(
        uncovered.is_empty(),
        "these categories are exposed as CLI flags and reach no emitter linked into this binary, \
         so requesting one can only ever report that no pass produced it: {}. Either wire a pass \
         that implements the matching emit_ method and add its capability to linked_capabilities, \
         or withdraw the category and its flag together",
        uncovered.join(", ")
    );
}

#[test]
#[cfg(feature = "full")]
fn the_unimplemented_allowlist_has_no_stale_entry() {
    for (category, reason) in UNIMPLEMENTED_CATEGORIES {
        let implementors: Vec<&'static str> = implementors_of(*category);
        assert!(
            implementors.is_empty(),
            "`{}` is on the unimplemented allowlist with the reason `{reason}`, but {} now \
             implements it; drop the allowlist entry so the coverage check guards it",
            category.label(),
            implementors.join(", ")
        );
    }
}

#[test]
#[cfg(all(feature = "full", feature = "irsummary"))]
fn cfg_and_dfg_reach_the_ir_summary_emitter() {
    assert_eq!(
        implementors_of(Category::Cfg),
        vec!["disrobe-irsummary"],
        "losing the disrobe-irsummary dependency or its llm-metadata feature makes --cfg emit \
         nothing again"
    );
    assert_eq!(implementors_of(Category::Dfg), vec!["disrobe-irsummary"]);
}

#[test]
fn the_flag_table_covers_every_category() {
    let flagged: BTreeSet<Category> = LlmFlags::default()
        .flag_categories()
        .into_iter()
        .map(|(_, category): (bool, Category)| category)
        .collect();
    let all: BTreeSet<Category> = Category::ALL.into_iter().collect();
    assert_eq!(
        flagged, all,
        "every category must be reachable from a CLI flag, or the coverage check above grades a \
         surface the user cannot request"
    );
}
