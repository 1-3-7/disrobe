#![allow(clippy::expect_used)]

use disrobe_pass_jvm::{
    HierarchyKind, classfile_hierarchy_node, dex_hierarchy_nodes, parse_classfile,
};

const DEX: &[u8] = include_bytes!("fixtures/implementors/Hierarchy-d8.dex");
const EXTRA_DEX: &[u8] = include_bytes!("fixtures/implementors/Extra-d8.dex");
const DIRECT: &[u8] = include_bytes!("fixtures/implementors/classes/Direct.class");

#[test]
fn compiler_produced_java_and_d8_hierarchies_preserve_concrete_edges() {
    let direct = classfile_hierarchy_node(&parse_classfile(DIRECT).expect("parse javac class"))
        .expect("read javac hierarchy");
    assert_eq!(direct.descriptor, "Limplementors/Direct;");
    assert_eq!(direct.kind, HierarchyKind::Concrete);
    assert_eq!(
        direct.parents,
        vec!["Limplementors/Root;", "Ljava/lang/Object;"]
    );
    let nodes = dex_hierarchy_nodes(DEX).expect("parse d8 hierarchy");
    assert_eq!(nodes.len(), 5);
    let direct = nodes
        .iter()
        .find(|node| node.descriptor == "Limplementors/Direct;")
        .expect("direct");
    assert_eq!(direct.kind, HierarchyKind::Concrete);
    assert_eq!(
        direct.parents,
        vec!["Limplementors/Root;", "Ljava/lang/Object;"]
    );
    let extra = dex_hierarchy_nodes(EXTRA_DEX).expect("parse extra d8 hierarchy");
    assert_eq!(extra.len(), 2);
    let extra = extra
        .iter()
        .find(|node| node.descriptor == "Limplementors/Extra;")
        .expect("extra");
    assert_eq!(
        extra.parents,
        vec!["Limplementors/Root;", "Ljava/lang/Object;"]
    );
}
