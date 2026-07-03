#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;

use disrobe_llm_metadata::{Category, LlmMetadataError, MetadataSelection, Pack, SelectionBuilder};

#[test]
fn pack4_without_auth_strips_decryption_keys() {
    let sel: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack4).build();
    let resolved: BTreeSet<Category> = sel.resolved();
    assert!(!resolved.contains(&Category::DecryptionKeys));
    assert_eq!(resolved.len(), 17);
}

#[test]
fn pack4_with_auth_keeps_decryption_keys() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .pack(Pack::Pack4)
        .authorize_decryption_keys()
        .build();
    let resolved: BTreeSet<Category> = sel.resolved();
    assert!(resolved.contains(&Category::DecryptionKeys));
    assert_eq!(resolved.len(), 18);
}

#[test]
fn explicit_request_without_auth_is_stripped_at_resolve() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .category(Category::DecryptionKeys)
        .build();
    assert!(!sel.contains(Category::DecryptionKeys));
}

#[test]
fn validate_auth_rejects_explicit_without_authorization() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .category(Category::DecryptionKeys)
        .build();
    let err: LlmMetadataError = sel.validate_auth().unwrap_err();
    assert_eq!(err, LlmMetadataError::UnauthorizedDecryptionKeys);
}

#[test]
fn validate_auth_accepts_when_authorized() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .category(Category::DecryptionKeys)
        .authorize_decryption_keys()
        .build();
    sel.validate_auth().expect("auth flag set, must validate");
}

#[test]
fn validate_auth_passes_when_pack4_without_explicit_category() {
    let sel: MetadataSelection = SelectionBuilder::new().pack(Pack::Pack4).build();
    sel.validate_auth().expect("pack-4 without auth is legal");
}

#[test]
fn exclude_decryption_keys_with_pack4_and_auth() {
    let sel: MetadataSelection = SelectionBuilder::new()
        .pack(Pack::Pack4)
        .authorize_decryption_keys()
        .exclude(Category::DecryptionKeys)
        .build();
    assert!(!sel.contains(Category::DecryptionKeys));
}
