use disrobe_query::{
    JvmHierarchyDiagnostic, JvmHierarchyNode, JvmTypeKind, MAX_JVM_HIERARCHY_EDGES,
    MAX_JVM_HIERARCHY_NODES, resolve_jvm_implementors,
};

fn node(descriptor: &str, kind: JvmTypeKind, parents: &[&str]) -> JvmHierarchyNode {
    JvmHierarchyNode {
        descriptor: descriptor.to_owned(),
        kind,
        parents: parents
            .iter()
            .map(|parent: &&str| (*parent).to_owned())
            .collect(),
    }
}

#[test]
fn resolves_concrete_implementors_through_classes_and_interfaces() {
    let nodes: Vec<JvmHierarchyNode> = vec![
        node("Lexample/Root;", JvmTypeKind::Interface, &[]),
        node(
            "Lexample/Middle;",
            JvmTypeKind::Interface,
            &["Lexample/Root;"],
        ),
        node(
            "Lexample/Base;",
            JvmTypeKind::Abstract,
            &["Lexample/Middle;"],
        ),
        node(
            "Lexample/Direct;",
            JvmTypeKind::Concrete,
            &["Lexample/Root;"],
        ),
        node("Lexample/Leaf;", JvmTypeKind::Concrete, &["Lexample/Base;"]),
    ];

    let result = resolve_jvm_implementors("Lexample/Root;", &nodes);

    assert_eq!(result.matches.len(), 2);
    assert_eq!(result.matches[0].descriptor, "Lexample/Direct;");
    assert_eq!(
        result.matches[0].proof_path,
        vec!["Lexample/Direct;", "Lexample/Root;"]
    );
    assert_eq!(result.matches[1].descriptor, "Lexample/Leaf;");
    assert_eq!(
        result.matches[1].proof_path,
        vec![
            "Lexample/Leaf;",
            "Lexample/Base;",
            "Lexample/Middle;",
            "Lexample/Root;"
        ]
    );
    assert!(result.diagnostics.is_empty());
}

#[test]
fn reports_partial_graph_defects_without_changing_valid_matches() {
    let nodes: Vec<JvmHierarchyNode> = vec![
        node("Lexample/Root;", JvmTypeKind::Interface, &[]),
        node("Lexample/Good;", JvmTypeKind::Concrete, &["Lexample/Root;"]),
        node(
            "Lexample/Missing;",
            JvmTypeKind::Concrete,
            &["Lexample/Absent;"],
        ),
        node("Lexample/Self;", JvmTypeKind::Concrete, &["Lexample/Self;"]),
        node("Lexample/A;", JvmTypeKind::Abstract, &["Lexample/B;"]),
        node("Lexample/B;", JvmTypeKind::Abstract, &["Lexample/A;"]),
        node(
            "Lexample/Bad;",
            JvmTypeKind::Concrete,
            &["not-a-descriptor"],
        ),
    ];

    let result = resolve_jvm_implementors("Lexample/Root;", &nodes);

    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].descriptor, "Lexample/Good;");
    assert!(
        result
            .diagnostics
            .contains(&JvmHierarchyDiagnostic::MissingDefinition {
                child: "Lexample/Missing;".to_owned(),
                parent: "Lexample/Absent;".to_owned(),
            })
    );
    assert!(
        result
            .diagnostics
            .contains(&JvmHierarchyDiagnostic::SelfEdge {
                descriptor: "Lexample/Self;".to_owned(),
            })
    );
    assert!(result.diagnostics.contains(&JvmHierarchyDiagnostic::Cycle {
        descriptors: vec!["Lexample/A;".to_owned(), "Lexample/B;".to_owned()],
    }));
    assert!(
        result
            .diagnostics
            .contains(&JvmHierarchyDiagnostic::MalformedDescriptor {
                descriptor: "not-a-descriptor".to_owned(),
            })
    );
}

#[test]
fn deduplicates_identical_artifacts_and_reports_conflicting_definitions_deterministically() {
    let mut reordered: Vec<JvmHierarchyNode> = vec![
        node("Lexample/Root;", JvmTypeKind::Interface, &[]),
        node("Lexample/Good;", JvmTypeKind::Concrete, &["Lexample/Root;"]),
    ];
    reordered.reverse();
    reordered.push(node(
        "Lexample/Good;",
        JvmTypeKind::Concrete,
        &["Lexample/Root;"],
    ));
    reordered.push(node(
        "Lexample/Conflict;",
        JvmTypeKind::Concrete,
        &["Lexample/Root;"],
    ));
    reordered.push(node(
        "Lexample/Conflict;",
        JvmTypeKind::Abstract,
        &["Lexample/Root;"],
    ));

    let first = resolve_jvm_implementors("Lexample/Root;", &reordered);
    let second = resolve_jvm_implementors(
        "Lexample/Root;",
        &reordered.into_iter().rev().collect::<Vec<_>>(),
    );

    assert_eq!(first, second);
    assert_eq!(first.matches.len(), 1);
    assert_eq!(first.matches[0].descriptor, "Lexample/Good;");
    assert!(
        first
            .diagnostics
            .contains(&JvmHierarchyDiagnostic::DuplicateDefinition {
                descriptor: "Lexample/Conflict;".to_owned(),
            })
    );
}

#[test]
fn bounds_hierarchy_population_with_a_typed_partial_result_diagnostic() {
    let mut nodes: Vec<JvmHierarchyNode> =
        vec![node("Lexample/Root;", JvmTypeKind::Interface, &[])];
    for index in 0..MAX_JVM_HIERARCHY_NODES {
        nodes.push(node(
            &format!("Lexample/N{index};"),
            JvmTypeKind::Concrete,
            &["Lexample/Root;"],
        ));
    }
    let result = resolve_jvm_implementors("Lexample/Root;", &nodes);
    assert!(
        result
            .diagnostics
            .contains(&JvmHierarchyDiagnostic::NodeLimit {
                max: MAX_JVM_HIERARCHY_NODES
            })
    );
    assert_eq!(result.matches.len(), MAX_JVM_HIERARCHY_NODES - 1);
}

#[test]
fn rejects_a_concrete_target() {
    let nodes = vec![node("Lexample/Concrete;", JvmTypeKind::Concrete, &[])];
    let result = resolve_jvm_implementors("Lexample/Concrete;", &nodes);
    assert!(result.matches.is_empty());
    assert!(
        result
            .diagnostics
            .contains(&JvmHierarchyDiagnostic::ConcreteTarget {
                descriptor: "Lexample/Concrete;".to_owned(),
            })
    );
}

#[test]
fn accepts_jvm_unicode_components_and_rejects_invalid_component_forms() {
    let root = node("Lpkg/naïve-名;", JvmTypeKind::Interface, &[]);
    let child = node("Lpkg/😀;", JvmTypeKind::Concrete, &["Lpkg/naïve-名;"]);
    let result = resolve_jvm_implementors("Lpkg/naïve-名;", &[root, child]);
    assert_eq!(result.matches.len(), 1);
    let root = node("Lpkg/\u{1b};", JvmTypeKind::Interface, &[]);
    let child = node("Lpkg/child;", JvmTypeKind::Concrete, &["Lpkg/\u{1b};"]);
    let result = resolve_jvm_implementors("Lpkg/\u{1b};", &[root, child]);
    assert_eq!(result.matches.len(), 1);
    for descriptor in [
        "L;",
        "L/pkg/Type;",
        "Lpkg//Type;",
        "Lpkg/Type.;",
        "Lpkg/Type[;",
        "Lpkg/Type;;",
        "[Lpkg/Type;",
        "I",
    ] {
        let result = resolve_jvm_implementors(descriptor, &[]);
        assert!(
            result
                .diagnostics
                .contains(&JvmHierarchyDiagnostic::InvalidTarget {
                    descriptor: descriptor.to_owned(),
                })
        );
    }
}

#[test]
fn canonical_cap_ignores_duplicate_prefixes_and_is_order_independent() {
    let root = node("Lexample/Root;", JvmTypeKind::Interface, &[]);
    let duplicate = node(
        "Lexample/Duplicate;",
        JvmTypeKind::Concrete,
        &["Lexample/Root;"],
    );
    let unique = node(
        "Lexample/Unique;",
        JvmTypeKind::Concrete,
        &["Lexample/Root;"],
    );
    let mut first = vec![root.clone()];
    first.extend(std::iter::repeat_n(
        duplicate.clone(),
        MAX_JVM_HIERARCHY_NODES + 8,
    ));
    first.push(unique.clone());
    let mut second = vec![unique, root];
    second.extend(std::iter::repeat_n(duplicate, MAX_JVM_HIERARCHY_NODES + 8));
    let left = resolve_jvm_implementors("Lexample/Root;", &first);
    let right = resolve_jvm_implementors("Lexample/Root;", &second);
    assert_eq!(left, right);
    assert_eq!(left.matches.len(), 2);
    assert!(left.diagnostics.is_empty());
}

#[test]
fn bounds_a_single_node_parent_population_before_cloning() {
    let mut parents: Vec<String> = Vec::with_capacity(MAX_JVM_HIERARCHY_EDGES + 2);
    parents.push("Lexample/Aroot;".to_owned());
    parents.extend((0..=MAX_JVM_HIERARCHY_EDGES).map(|index: usize| format!("Lexample/P{index};")));
    let root = node("Lexample/Aroot;", JvmTypeKind::Interface, &[]);
    let child = JvmHierarchyNode {
        descriptor: "Lexample/Child;".to_owned(),
        kind: JvmTypeKind::Concrete,
        parents: parents.clone(),
    };
    let first = resolve_jvm_implementors("Lexample/Aroot;", &[root.clone(), child.clone()]);
    parents.reverse();
    let second = resolve_jvm_implementors(
        "Lexample/Aroot;",
        &[JvmHierarchyNode { parents, ..child }, root],
    );

    assert_eq!(first, second);
    assert_eq!(first.matches.len(), 1);
    assert!(
        first
            .diagnostics
            .contains(&JvmHierarchyDiagnostic::EdgeLimit {
                max: MAX_JVM_HIERARCHY_EDGES,
            })
    );
}

#[test]
fn bounds_reordered_malformed_parent_diagnostics() {
    let invalid: Vec<String> = (0..=MAX_JVM_HIERARCHY_NODES)
        .map(|index: usize| format!("Lexample/Bad{index}.{};", "x".repeat(96)))
        .collect();
    let root = node("Lexample/Root;", JvmTypeKind::Interface, &[]);
    let child = JvmHierarchyNode {
        descriptor: "Lexample/Child;".to_owned(),
        kind: JvmTypeKind::Concrete,
        parents: invalid.clone(),
    };
    let first = resolve_jvm_implementors("Lexample/Root;", &[root.clone(), child.clone()]);
    let mut reversed = invalid;
    reversed.reverse();
    let second = resolve_jvm_implementors(
        "Lexample/Root;",
        &[
            root,
            JvmHierarchyNode {
                parents: reversed,
                ..child
            },
        ],
    );

    assert_eq!(first, second);
    assert!(first.diagnostics.contains(
        &JvmHierarchyDiagnostic::MalformedDescriptorDiagnosticLimit {
            max: MAX_JVM_HIERARCHY_NODES,
            max_bytes: 1_048_576,
        }
    ));
    assert!(
        first
            .diagnostics
            .iter()
            .filter(|diagnostic: &&JvmHierarchyDiagnostic| {
                matches!(
                    diagnostic,
                    JvmHierarchyDiagnostic::MalformedDescriptor { .. }
                )
            })
            .count()
            < MAX_JVM_HIERARCHY_NODES
    );
}

#[test]
fn reports_missing_definition_diagnostic_truncation_by_its_own_budget() {
    let parents: Vec<String> = (0..=MAX_JVM_HIERARCHY_NODES)
        .map(|index: usize| format!("Lmissing/P{index};"))
        .collect();
    let root = node("Lexample/Root;", JvmTypeKind::Interface, &[]);
    let child = JvmHierarchyNode {
        descriptor: "Lexample/Child;".to_owned(),
        kind: JvmTypeKind::Concrete,
        parents,
    };
    let result = resolve_jvm_implementors("Lexample/Root;", &[root, child]);

    assert!(result.diagnostics.contains(
        &JvmHierarchyDiagnostic::MissingDefinitionDiagnosticLimit {
            max: MAX_JVM_HIERARCHY_NODES,
            max_bytes: 1_048_576,
        }
    ));
}

#[test]
fn rejects_an_oversized_target_without_retaining_the_unbounded_input() {
    let target = format!("L{};", "a".repeat(1_048_576));
    let result = resolve_jvm_implementors(&target, &[]);

    assert!(result.target.len() <= 1_048_576);
    assert_eq!(
        result.diagnostics,
        vec![JvmHierarchyDiagnostic::TargetDescriptorBytesLimit { max: 1_048_576 }]
    );
    assert!(result.matches.is_empty());
}

#[test]
fn reports_a_missing_target_without_conflating_it_with_a_partial_graph() {
    let result = resolve_jvm_implementors("Lexample/Missing;", &[]);
    assert!(result.matches.is_empty());
    assert_eq!(
        result.diagnostics,
        vec![JvmHierarchyDiagnostic::MissingTarget {
            descriptor: "Lexample/Missing;".to_owned(),
        }]
    );
}

#[test]
fn bounds_hostile_inheritance_chains_without_retaining_every_path() {
    let mut nodes = vec![node("Lexample/Root;", JvmTypeKind::Interface, &[])];
    for index in 0..=256 {
        let descriptor = format!("Lexample/N{index};");
        let parent = if index == 0 {
            "Lexample/Root;".to_owned()
        } else {
            format!("Lexample/N{};", index - 1)
        };
        let kind = if index == 256 {
            JvmTypeKind::Concrete
        } else {
            JvmTypeKind::Abstract
        };
        nodes.push(node(&descriptor, kind, &[&parent]));
    }
    let result = resolve_jvm_implementors("Lexample/Root;", &nodes);
    assert!(result.matches.is_empty());
    assert!(
        result
            .diagnostics
            .contains(&JvmHierarchyDiagnostic::ProofDepthLimit { max: 256 })
    );
}
