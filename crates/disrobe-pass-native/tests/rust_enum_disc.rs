#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{EnumDiscriminant, recover_enum_discriminants};

#[test]
fn enum_variants_group_by_owning_type() {
    let syms: [&str; 4] = [
        "my::State::Idle",
        "my::State::Running",
        "my::State::Halted",
        "other::Mode::A",
    ];
    let groups: Vec<EnumDiscriminant> = recover_enum_discriminants(&syms);
    assert!(
        groups
            .iter()
            .any(|g| g.type_name == "my::State" && g.variants.len() == 3)
    );
    assert!(groups.iter().any(|g| g.type_name == "other::Mode"));
}
