#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    CxxAbi, CxxClass, CxxHierarchy, CxxInheritance, RttiEntry, StlTemplate, recover_cxx_hierarchy,
    recover_itanium_rtti,
};

const ITANIUM_FIXTURE: &[u8] = include_bytes!("fixtures/cxx_hierarchy_itanium.so");
const MSVC_FIXTURE: &[u8] = include_bytes!("fixtures/cxx_hierarchy_msvc.exe");

#[test]
fn rtti_recovery_clusters_typeinfo_vtable_typestring() {
    let syms: [&str; 3] = ["_ZTV5Class", "_ZTI5Class", "_ZTS5Class"];
    let out: Vec<RttiEntry> = recover_itanium_rtti(&syms);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].class_name, "5Class");
}

fn base_names(class: &CxxClass) -> Vec<String> {
    let mut names: Vec<String> = class.direct_bases.iter().map(|b| b.name.clone()).collect();
    names.sort();
    names
}

#[test]
fn itanium_hierarchy_matches_source() {
    let hierarchy: CxxHierarchy =
        recover_cxx_hierarchy(ITANIUM_FIXTURE).expect("itanium hierarchy recovered");
    assert_eq!(hierarchy.abi, CxxAbi::Itanium);

    let vbase: &CxxClass = hierarchy.class("VBase").expect("VBase present");
    assert_eq!(vbase.inheritance, CxxInheritance::None);
    assert!(vbase.direct_bases.is_empty());

    let vleft: &CxxClass = hierarchy.class("VLeft").expect("VLeft present");
    assert_eq!(base_names(vleft), vec!["VBase".to_owned()]);
    assert_eq!(vleft.inheritance, CxxInheritance::Virtual);
    assert!(vleft.direct_bases[0].is_virtual);

    let vright: &CxxClass = hierarchy.class("VRight").expect("VRight present");
    assert_eq!(base_names(vright), vec!["VBase".to_owned()]);
    assert_eq!(vright.inheritance, CxxInheritance::Virtual);

    let vdiamond: &CxxClass = hierarchy.class("VDiamond").expect("VDiamond present");
    assert_eq!(
        base_names(vdiamond),
        vec!["VLeft".to_owned(), "VRight".to_owned()]
    );
    assert_eq!(vdiamond.inheritance, CxxInheritance::Multiple);
    assert!(
        vdiamond.direct_bases.iter().all(|b| !b.is_virtual),
        "VLeft/VRight are non-virtual direct bases of VDiamond in the Itanium __vmi record"
    );
    let all: Vec<&str> = vdiamond.all_bases.iter().map(String::as_str).collect();
    assert!(all.contains(&"VLeft"));
    assert!(all.contains(&"VRight"));
    assert_eq!(
        vleft.direct_bases[0].name, "VBase",
        "the diamond's shared virtual base reaches VBase through VLeft"
    );
}

#[test]
fn itanium_vtable_binds_method_slots() {
    let hierarchy: CxxHierarchy =
        recover_cxx_hierarchy(ITANIUM_FIXTURE).expect("itanium hierarchy recovered");
    let vdiamond: &CxxClass = hierarchy.class("VDiamond").expect("VDiamond present");
    let vtable = vdiamond.vtable.as_ref().expect("VDiamond vtable bound");
    assert!(
        vtable.slot_count >= 2,
        "VDiamond declares vsound + dtor virtuals, got {} slots",
        vtable.slot_count
    );
    assert!(
        vtable.slots.iter().any(|s| s
            .symbol
            .as_deref()
            .is_some_and(|n| n.contains("vsound") || n.contains("VDiamond"))),
        "a VDiamond vtable slot should resolve to a VDiamond method symbol"
    );
}

#[test]
fn msvc_hierarchy_matches_source() {
    let hierarchy: CxxHierarchy =
        recover_cxx_hierarchy(MSVC_FIXTURE).expect("msvc hierarchy recovered");
    assert_eq!(hierarchy.abi, CxxAbi::Msvc);

    let base: &CxxClass = hierarchy.class("Base").expect("Base present");
    assert_eq!(base.inheritance, CxxInheritance::None);

    let derived: &CxxClass = hierarchy.class("Derived").expect("Derived present");
    assert_eq!(base_names(derived), vec!["Base".to_owned()]);
    assert_eq!(derived.inheritance, CxxInheritance::Single);

    let multi: &CxxClass = hierarchy.class("Multi").expect("Multi present");
    assert_eq!(
        base_names(multi),
        vec!["Left".to_owned(), "Right".to_owned()]
    );
    assert_eq!(multi.inheritance, CxxInheritance::Multiple);

    let vdiamond: &CxxClass = hierarchy.class("VDiamond").expect("VDiamond present");
    assert_eq!(
        base_names(vdiamond),
        vec!["VLeft".to_owned(), "VRight".to_owned()]
    );
    assert_eq!(vdiamond.inheritance, CxxInheritance::MultipleVirtual);
    assert!(
        vdiamond.direct_bases.iter().all(|b| !b.is_virtual),
        "VLeft/VRight are non-virtual direct bases of VDiamond"
    );
    let vleft: &CxxClass = hierarchy.class("VLeft").expect("VLeft present");
    assert_eq!(vleft.inheritance, CxxInheritance::Virtual);
    assert!(
        vleft
            .direct_bases
            .iter()
            .any(|b| b.is_virtual && b.name == "VBase")
    );
}

#[test]
fn msvc_vtable_binds_method_slots() {
    let hierarchy: CxxHierarchy =
        recover_cxx_hierarchy(MSVC_FIXTURE).expect("msvc hierarchy recovered");
    let base: &CxxClass = hierarchy.class("Base").expect("Base present");
    let vtable = base.vtable.as_ref().expect("Base vtable bound");
    assert!(
        vtable.slot_count >= 3,
        "Base declares kind/rank/dtor virtuals, got {} slots",
        vtable.slot_count
    );
    for slot in &vtable.slots {
        assert!(slot.function_address != 0);
    }
}

#[test]
fn stl_template_tagging() {
    assert_eq!(
        disrobe_pass_native::detect_stl_templates("std::vector<int, std::allocator<int> >"),
        vec![StlTemplate::Vector]
    );
    assert_eq!(
        disrobe_pass_native::detect_stl_templates("class std::basic_string<char>"),
        vec![StlTemplate::String]
    );
    let shared: Vec<StlTemplate> =
        disrobe_pass_native::detect_stl_templates("std::shared_ptr<Base>");
    assert_eq!(shared, vec![StlTemplate::SharedPtr]);
    assert!(disrobe_pass_native::detect_stl_templates("MyPlainClass").is_empty());
}
