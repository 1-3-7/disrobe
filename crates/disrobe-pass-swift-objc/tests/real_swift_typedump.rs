#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::macho::{CpuKind, ParsedSlice};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
use disrobe_pass_swift_objc::swift_typedump::{
    ConformanceProtocolKind, NominalKind, ProtocolRequirementKind, SwiftNominalType,
    SwiftProtocolConformance, SwiftProtocolDescriptor, SwiftProtocolRequirement, SwiftTypeDump,
};

use macho_corpus::{
    CorpusFixture, SWIFT_DRIVER, SWIFT_EDGE_CASES_OBFUSCATED, SWIFT_HELLO_ORIGINAL, first_slice,
    read_host_sourced, read_tracked, slice_preferring,
};

fn tracked_slice(fixture: CorpusFixture) -> (Vec<u8>, ParsedSlice) {
    let bytes: Vec<u8> = read_tracked(fixture);
    first_slice(fixture, &bytes)
}

fn driver_x86_64_slice() -> Option<(Vec<u8>, ParsedSlice)> {
    let bytes: Vec<u8> = read_host_sourced(SWIFT_DRIVER)?;
    Some(slice_preferring(SWIFT_DRIVER, &bytes, CpuKind::X86_64))
}

fn nominal_named<'a>(dump: &'a SwiftTypeDump, name: &str) -> Option<&'a SwiftNominalType> {
    dump.nominal_types
        .iter()
        .find(|t: &&SwiftNominalType| t.name == name || t.qualified_name.ends_with(name))
}

#[test]
fn swiftedgecases_recovers_full_structural_type_dump() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_EDGE_CASES_OBFUSCATED);
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);
    let td: &SwiftTypeDump = &dump.type_dump;

    assert_eq!(
        td.nominal_types.len(),
        11,
        "source has 5 classes + 3 structs + 2 enums + 1 @main struct = 11 nominal types"
    );
    assert_eq!(td.protocols.len(), 5, "source declares 5 protocols");

    let class_count: usize = td
        .nominal_types
        .iter()
        .filter(|t: &&SwiftNominalType| matches!(t.kind, NominalKind::Class))
        .count();
    let struct_count: usize = td
        .nominal_types
        .iter()
        .filter(|t: &&SwiftNominalType| matches!(t.kind, NominalKind::Struct))
        .count();
    let enum_count: usize = td
        .nominal_types
        .iter()
        .filter(|t: &&SwiftNominalType| matches!(t.kind, NominalKind::Enum))
        .count();
    assert_eq!((class_count, struct_count, enum_count), (5, 4, 2));

    let login: &SwiftNominalType =
        nominal_named(td, "X38jeD6t4T").expect("class X38jeD6t4T present");
    assert!(matches!(login.kind, NominalKind::Class));
    assert_eq!(login.qualified_name, "SwiftEdgeCases.X38jeD6t4T");
    let login_fields: Vec<&str> = login.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(login_fields, vec!["yWfiVoFmvO", "yfWJeBQpgP"]);
    assert!(
        login
            .fields
            .iter()
            .all(|f| f.demangled_type.as_deref() == Some("Swift.String")),
        "both stored properties are String"
    );

    let receipt: &SwiftNominalType =
        nominal_named(td, "Xni3uTaL45").expect("struct Xni3uTaL45 present");
    assert!(matches!(receipt.kind, NominalKind::Struct));
    assert_eq!(receipt.fields.len(), 3, "SubscriptionReceipt has 3 fields");

    let phase: &SwiftNominalType =
        nominal_named(td, "XFelyvUreX").expect("enum XFelyvUreX present");
    assert!(matches!(phase.kind, NominalKind::Enum));
    assert_eq!(phase.fields.len(), 5, "lifecycle enum has 5 cases");

    let in_module: usize = td
        .conformances
        .iter()
        .filter(|c: &&SwiftProtocolConformance| {
            matches!(c.protocol_kind, ConformanceProtocolKind::InModule)
        })
        .count();
    assert_eq!(
        in_module, 5,
        "5 classes each conform to one in-module protocol"
    );

    for class_name in [
        "X38jeD6t4T",
        "XqvOdKfWXe",
        "XpwngnQl6t",
        "XdsxgpYLEB",
        "X6zYFapyhU",
    ] {
        let ty: &SwiftNominalType = nominal_named(td, class_name).expect("class present");
        assert_eq!(
            ty.conformances.len(),
            1,
            "{class_name} should carry exactly one resolved protocol conformance"
        );
    }

    for proto in &td.protocols {
        assert_eq!(
            proto.requirements.len(),
            1,
            "protocol {} declares exactly one method requirement in source",
            proto.qualified_name
        );
        let req: &SwiftProtocolRequirement = &proto.requirements[0];
        assert!(
            matches!(req.kind, ProtocolRequirementKind::Method),
            "the lone requirement of {} is a method, got {:?}",
            proto.qualified_name,
            req.kind
        );
        assert!(
            req.is_instance,
            "the method requirement is an instance method"
        );
        assert_eq!(
            proto.num_requirements_in_signature, 0,
            "none of these protocols carry generic requirements"
        );
        assert!(
            proto.associated_type_names.is_empty(),
            "none of these protocols declare associated types"
        );
    }

    let rendered: String = td.render();
    assert!(rendered.contains("class SwiftEdgeCases.X38jeD6t4T : SwiftEdgeCases.XzSjUtuRk5 {"));
    assert!(rendered.contains("    let yWfiVoFmvO: Swift.String"));
    assert!(rendered.contains("enum SwiftEdgeCases.XFelyvUreX {"));
    assert!(rendered.contains("    case yDg5gtqJe9"));
    assert!(
        rendered.contains("protocol SwiftEdgeCases.XzSjUtuRk5 {") && rendered.contains("    func"),
        "render emits a real protocol body with a method requirement, not an empty brace pair"
    );
    assert!(
        !rendered.contains("protocol SwiftEdgeCases.XzSjUtuRk5 {}"),
        "protocols are no longer rendered as empty"
    );
}

#[test]
fn swifthello_original_recovers_named_types_and_conformances() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_HELLO_ORIGINAL);
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);
    let td: &SwiftTypeDump = &dump.type_dump;

    assert_eq!(td.nominal_types.len(), 2, "two classes in SwiftHello");
    assert_eq!(td.protocols.len(), 1, "one protocol HelloGreetable");

    let names: Vec<&str> = td
        .nominal_types
        .iter()
        .map(|t: &SwiftNominalType| t.name.as_str())
        .collect();
    assert!(names.contains(&"LoginViewController"));
    assert!(names.contains(&"AuthenticationService"));

    let login: &SwiftNominalType =
        nominal_named(td, "LoginViewController").expect("login class present");
    assert_eq!(login.fields.len(), 1);
    assert_eq!(login.fields[0].name, "displayedUserName");
    assert_eq!(
        login.fields[0].demangled_type.as_deref(),
        Some("Swift.String")
    );

    let in_module: usize = td
        .conformances
        .iter()
        .filter(|c: &&SwiftProtocolConformance| {
            matches!(c.protocol_kind, ConformanceProtocolKind::InModule)
        })
        .count();
    assert_eq!(in_module, 2, "both classes conform to HelloGreetable");
    assert!(
        td.conformances.iter().all(|c| c
            .protocol_name
            .as_deref()
            .is_some_and(|n: &str| n.ends_with("HelloGreetable"))),
        "every conformance resolves to HelloGreetable"
    );

    let greetable: &SwiftProtocolDescriptor = td
        .protocols
        .iter()
        .find(|p: &&SwiftProtocolDescriptor| p.name.ends_with("HelloGreetable"))
        .expect("HelloGreetable protocol descriptor recovered");
    assert_eq!(
        greetable.requirements.len(),
        1,
        "HelloGreetable declares exactly one requirement (greetWithBanner)"
    );
    assert!(
        matches!(
            greetable.requirements[0].kind,
            ProtocolRequirementKind::Method
        ),
        "greetWithBanner is a method requirement"
    );
    assert!(
        greetable.requirements[0].is_instance,
        "greetWithBanner is an instance method"
    );
    assert_eq!(greetable.num_requirements_in_signature, 0);
    assert!(greetable.associated_type_names.is_empty());
}

#[test]
fn swift_driver_yields_many_qualified_nominal_types() {
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_x86_64_slice() else {
        return;
    };
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);
    let td: &SwiftTypeDump = &dump.type_dump;
    assert!(
        td.nominal_types.len() >= 20,
        "swift-driver __swift5_types should yield many nominal types, got {}",
        td.nominal_types.len()
    );
    let qualified: usize = td
        .nominal_types
        .iter()
        .filter(|t: &&SwiftNominalType| t.qualified_name.contains('.'))
        .count();
    assert!(
        qualified * 2 >= td.nominal_types.len(),
        "most recovered nominal types should carry a module-qualified name"
    );
}
