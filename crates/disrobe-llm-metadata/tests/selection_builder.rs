#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::iter_on_single_items
)]

use std::collections::BTreeSet;

use disrobe_llm_metadata::{Category, MetadataFormat, MetadataSelection, Pack, SelectionBuilder};
use proptest::prelude::*;

#[test]
fn empty_builder_resolves_to_empty() {
    let sel: MetadataSelection = SelectionBuilder::new().build();
    assert!(sel.is_empty());
    assert_eq!(sel.resolved(), BTreeSet::new());
}

#[test]
fn single_category_builds_singleton() {
    let sel: MetadataSelection = SelectionBuilder::new().category(Category::Symbols).build();
    let want: BTreeSet<Category> = [Category::Symbols].into_iter().collect();
    assert_eq!(sel.resolved(), want);
}

#[test]
fn pack_then_extra_category() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .pack(Pack::Pack2)
        .category(Category::Signatures)
        .build();
    let mut want: BTreeSet<Category> = Pack::Pack2.expand();
    want.insert(Category::Signatures);
    assert_eq!(sel.resolved(), want);
}

#[test]
fn exclude_is_applied_last() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .pack(Pack::Pack3)
        .exclude(Category::Ast)
        .build();
    let mut want: BTreeSet<Category> = Pack::Pack3.expand();
    want.remove(&Category::Ast);
    assert_eq!(sel.resolved(), want);
    assert!(!sel.contains(Category::Ast));
}

#[test]
fn exclude_overrides_explicit_category() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .category(Category::Ast)
        .exclude(Category::Ast)
        .build();
    assert!(!sel.contains(Category::Ast));
    assert!(sel.is_empty());
}

#[test]
fn format_propagates() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .format(MetadataFormat::Jsonl)
        .build();
    assert_eq!(sel.format, MetadataFormat::Jsonl);
}

#[test]
fn resolved_iteration_is_deterministic() {
    let a: BTreeSet<Category> = SelectionBuilder::new().pack(Pack::Pack4).build().resolved();
    let b: BTreeSet<Category> = SelectionBuilder::new()
        .categories(Pack::Pack4.expand())
        .build()
        .resolved();
    let a_seq: Vec<Category> = a.iter().copied().collect();
    let b_seq: Vec<Category> = b.iter().copied().collect();
    assert_eq!(a_seq, b_seq, "iteration order must be stable");
}

#[test]
fn batched_categories_accumulate() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .categories([Category::Ast, Category::Cfg, Category::Dfg])
        .excludes([Category::Cfg])
        .build();
    let want: BTreeSet<Category> = [Category::Ast, Category::Dfg].into_iter().collect();
    assert_eq!(sel.resolved(), want);
}

proptest! {
    #[test]
    fn pack_monotonicity_property(_dummy: u8) {
        let p1: BTreeSet<Category> = Pack::Pack1.expand();
        let p2: BTreeSet<Category> = Pack::Pack2.expand();
        let p3: BTreeSet<Category> = Pack::Pack3.expand();
        let p4: BTreeSet<Category> = Pack::Pack4.expand();
        prop_assert!(p1.is_subset(&p2));
        prop_assert!(p2.is_subset(&p3));
        prop_assert!(p3.is_subset(&p4));
    }

    #[test]
    fn exclude_is_always_subtractive(
        explicit in proptest::collection::vec(0u8..18, 0..8),
        excluded in proptest::collection::vec(0u8..18, 0..8),
    ) {
        let cat_of = |i: u8| -> Category { Category::ALL[i as usize] };
        let mut builder: SelectionBuilder = SelectionBuilder::new();
        for i in &explicit { builder = builder.category(cat_of(*i)); }
        for i in &excluded { builder = builder.exclude(cat_of(*i)); }
        let sel: MetadataSelection = builder.build();
        let resolved: BTreeSet<Category> = sel.resolved();
        for i in &excluded {
            prop_assert!(!resolved.contains(&cat_of(*i)), "exclude must remove");
        }
    }
}
