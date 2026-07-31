#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use std::collections::BTreeSet;

use disrobe_pass_swift_objc::macho::ParsedSlice;
use disrobe_pass_swift_objc::objc::{self, ObjcClassDump};
use disrobe_pass_swift_objc::objc_records::{ObjcCategory, ObjcProtocol};
use disrobe_pass_swift_objc::pass::{self, EmbeddedImageReport, SliceReport, SwiftObjcReport};

use macho_corpus::{
    CorpusFixture, EDGE_CASES_FAT, FEATHER_IPA, ONION_BROWSER_IPA, PPSSPP_IPA,
    SWIFT_EDGE_CASES_OBFUSCATED, SWIFT_EDGE_CASES_ORIGINAL, SWIFT_HELLO_OBFUSCATED,
    SWIFT_HELLO_ORIGINAL, first_slice, read_host_sourced, read_tracked,
};

fn analyzed_ipa(fixture: CorpusFixture) -> Option<SwiftObjcReport> {
    let bytes: Vec<u8> = read_host_sourced(fixture)?;
    let report: SwiftObjcReport = pass::analyze(&bytes)
        .unwrap_or_else(|error| panic!("{} does not analyze: {error}", fixture.relative()));
    Some(report)
}

fn embedded_objc<'a>(
    report: &'a SwiftObjcReport,
    fixture: CorpusFixture,
    suffix: &str,
) -> &'a ObjcClassDump {
    let matches: Vec<&EmbeddedImageReport> = report
        .embedded_images
        .iter()
        .filter(|image: &&EmbeddedImageReport| image.path.ends_with(suffix))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "{} must carry exactly one embedded image ending in {suffix}, found {}: {:?}",
        fixture.relative(),
        matches.len(),
        report
            .embedded_images
            .iter()
            .map(|image: &EmbeddedImageReport| image.path.as_str())
            .collect::<Vec<&str>>()
    );
    let image: &EmbeddedImageReport = matches[0];
    assert_eq!(
        image.slices.len(),
        1,
        "{suffix} inside {} is a thin image and must yield exactly one analyzed slice",
        fixture.relative()
    );
    &image.slices[0].objc
}

fn main_objc(report: &SwiftObjcReport, fixture: CorpusFixture) -> &ObjcClassDump {
    assert_eq!(
        report.slices.len(),
        1,
        "the main binary of {} is a thin image and must yield exactly one analyzed slice",
        fixture.relative()
    );
    let slice: &SliceReport = &report.slices[0];
    &slice.objc
}

fn assert_every_pointer_dereferences(label: &str, dump: &ObjcClassDump) {
    assert_eq!(
        dump.categories.len(),
        dump.category_count,
        "{label} declares {} __objc_catlist pointers and {} of them turned into a recovered \
         category; a run that recovers a subset has not recovered the categories and must fail \
         rather than report what it managed",
        dump.category_count,
        dump.categories.len()
    );
    assert_eq!(
        dump.protocols.len(),
        dump.protocol_count,
        "{label} declares {} __objc_protolist pointers and {} of them turned into a recovered \
         protocol; a partial result must fail rather than pass",
        dump.protocol_count,
        dump.protocols.len()
    );
    assert!(
        dump.categories
            .iter()
            .all(|category: &ObjcCategory| !category.name.is_empty()),
        "{label} recovered a category with an empty name, which is a record we invented rather \
         than read"
    );
    assert!(
        dump.protocols
            .iter()
            .all(|protocol: &ObjcProtocol| !protocol.name.is_empty()),
        "{label} recovered a protocol with an empty name, which is a record we invented rather \
         than read"
    );
}

fn category_methods(dump: &ObjcClassDump) -> usize {
    dump.categories
        .iter()
        .map(|category: &ObjcCategory| {
            category.instance_methods.len() + category.class_methods.len()
        })
        .sum()
}

fn protocol_methods(dump: &ObjcClassDump) -> usize {
    dump.protocols
        .iter()
        .map(|protocol: &ObjcProtocol| {
            protocol.required_instance_methods.len()
                + protocol.required_class_methods.len()
                + protocol.optional_instance_methods.len()
                + protocol.optional_class_methods.len()
        })
        .sum()
}

fn protocol_properties(dump: &ObjcClassDump) -> usize {
    dump.protocols
        .iter()
        .map(|protocol: &ObjcProtocol| protocol.properties.len())
        .sum()
}

#[test]
fn tracked_fixtures_carry_no_categories_and_recover_none() {
    for fixture in [
        SWIFT_HELLO_ORIGINAL,
        SWIFT_HELLO_OBFUSCATED,
        SWIFT_EDGE_CASES_ORIGINAL,
        SWIFT_EDGE_CASES_OBFUSCATED,
        EDGE_CASES_FAT,
    ] {
        let bytes: Vec<u8> = read_tracked(fixture);
        let (slice, parsed): (Vec<u8>, ParsedSlice) = first_slice(fixture, &bytes);
        let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);
        assert_every_pointer_dereferences(&fixture.relative(), &dump);
        assert_eq!(
            dump.category_count,
            0,
            "{} carries no __objc_catlist section, so a nonzero category count would mean this \
             case is reading a different file than the one it pins",
            fixture.relative()
        );
        assert!(
            dump.categories.is_empty() && dump.protocols.is_empty(),
            "{} declares no category or protocol pointers, so recovering a record from it would \
             be an invention rather than a read",
            fixture.relative()
        );
        assert!(
            !dump.interfaces.is_empty(),
            "{} does carry classes, so a run that recovers nothing at all from it has measured \
             nothing",
            fixture.relative()
        );
    }
}

#[test]
fn molten_vk_recovers_every_category_with_the_class_it_extends() {
    let Some(report): Option<SwiftObjcReport> = analyzed_ipa(PPSSPP_IPA) else {
        return;
    };
    let dump: &ObjcClassDump = embedded_objc(&report, PPSSPP_IPA, "Frameworks/libMoltenVK.dylib");
    assert_every_pointer_dereferences("libMoltenVK.dylib", dump);

    assert_eq!(dump.category_count, 8, "libMoltenVK declares 8 categories");
    let extended: BTreeSet<&str> = dump
        .categories
        .iter()
        .filter_map(|category: &ObjcCategory| category.class_name.as_deref())
        .collect();
    let expected: BTreeSet<&str> = [
        "CAMetalLayer",
        "MTLRenderPassDepthAttachmentDescriptor",
        "MTLRenderPassDescriptor",
        "MTLRenderPassStencilAttachmentDescriptor",
        "MTLRenderPipelineDescriptor",
        "MTLSamplerDescriptor",
        "MTLTextureDescriptor",
        "NSMutableString",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        extended, expected,
        "every libMoltenVK category extends a Metal or Foundation class bound at load time, and \
         all 8 of those class names must come back"
    );
    assert!(
        dump.categories
            .iter()
            .all(|category: &ObjcCategory| category.name == "MoltenVK"),
        "every libMoltenVK category is named MoltenVK"
    );
    assert_eq!(
        category_methods(dump),
        32,
        "the 8 libMoltenVK categories carry 32 methods between them"
    );
    assert_eq!(
        dump.categories
            .iter()
            .map(|category: &ObjcCategory| category.instance_properties.len())
            .sum::<usize>(),
        15,
        "the 8 libMoltenVK categories carry 15 instance properties between them"
    );

    assert_eq!(dump.protocol_count, 3, "libMoltenVK declares 3 protocols");
    let protocol_names: BTreeSet<&str> = dump
        .protocols
        .iter()
        .map(|protocol: &ObjcProtocol| protocol.name.as_str())
        .collect();
    assert_eq!(
        protocol_names,
        ["MTLCommandQueue", "MTLDevice", "NSObject"]
            .into_iter()
            .collect::<BTreeSet<&str>>()
    );
    assert_eq!(protocol_methods(dump), 122);
    assert_eq!(protocol_properties(dump), 39);
}

#[test]
fn dt_foundation_recovers_its_seven_categories_and_both_protocols() {
    let Some(report): Option<SwiftObjcReport> = analyzed_ipa(ONION_BROWSER_IPA) else {
        return;
    };
    let dump: &ObjcClassDump = embedded_objc(
        &report,
        ONION_BROWSER_IPA,
        "Frameworks/DTFoundation.framework/DTFoundation",
    );
    assert_every_pointer_dereferences("DTFoundation", dump);

    assert_eq!(dump.category_count, 7, "DTFoundation declares 7 categories");
    let pairs: BTreeSet<(&str, &str)> = dump
        .categories
        .iter()
        .filter_map(|category: &ObjcCategory| {
            category
                .class_name
                .as_deref()
                .map(|class: &str| (class, category.name.as_str()))
        })
        .collect();
    let expected: BTreeSet<(&str, &str)> = [
        ("NSArray", "DTError"),
        ("NSData", "DTCrypto"),
        ("NSDictionary", "DTError"),
        ("NSFileWrapper", "DTCopying"),
        ("NSMutableArray", "DTMoving"),
        ("NSString", "DTFormatNumbers"),
        ("NSURL", "DTComparing"),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        pairs, expected,
        "each DTFoundation category must come back named and attached to the Foundation class it \
         extends"
    );
    assert_eq!(
        category_methods(dump),
        23,
        "the 7 DTFoundation categories carry 23 methods between them"
    );

    assert_eq!(dump.protocol_count, 2);
    assert_eq!(
        dump.protocols
            .iter()
            .map(|protocol: &ObjcProtocol| protocol.name.as_str())
            .collect::<BTreeSet<&str>>(),
        ["DTASN1ParserDelegate", "NSObject"]
            .into_iter()
            .collect::<BTreeSet<&str>>()
    );
    assert_eq!(protocol_methods(dump), 34);
    assert_eq!(protocol_properties(dump), 4);
}

#[test]
fn tor_framework_recovers_both_categories_with_their_class_properties() {
    let Some(report): Option<SwiftObjcReport> = analyzed_ipa(ONION_BROWSER_IPA) else {
        return;
    };
    let dump: &ObjcClassDump =
        embedded_objc(&report, ONION_BROWSER_IPA, "Frameworks/Tor.framework/Tor");
    assert_every_pointer_dereferences("Tor.framework", dump);

    assert_eq!(dump.category_count, 2);
    assert_eq!(
        dump.categories
            .iter()
            .map(|category: &ObjcCategory| category.name.as_str())
            .collect::<BTreeSet<&str>>(),
        ["GeoIP", "PredefinedSets"]
            .into_iter()
            .collect::<BTreeSet<&str>>()
    );
    assert_eq!(category_methods(dump), 5);
    assert_ne!(
        dump.image_info_flags & disrobe_pass_swift_objc::OBJC_IMAGE_HAS_CATEGORY_CLASS_PROPERTIES,
        0,
        "Tor.framework sets the image-info bit that says category_t carries the class-property \
         field, which is what makes reading that field a read rather than a guess"
    );
    assert_eq!(
        dump.categories
            .iter()
            .map(|category: &ObjcCategory| category.class_properties.len())
            .sum::<usize>(),
        3,
        "the two Tor.framework categories carry 3 class properties between them"
    );
    assert_eq!(dump.protocol_count, 2);
    assert_eq!(protocol_methods(dump), 3);
}

#[test]
fn onion_browser_main_binary_recovers_every_protocol_it_declares() {
    let Some(report): Option<SwiftObjcReport> = analyzed_ipa(ONION_BROWSER_IPA) else {
        return;
    };
    let dump: &ObjcClassDump = main_objc(&report, ONION_BROWSER_IPA);
    assert_every_pointer_dereferences("OnionBrowser", dump);

    assert_eq!(
        dump.protocol_count, 43,
        "OnionBrowser declares 43 protocols"
    );
    assert_eq!(protocol_methods(dump), 616);
    assert_eq!(protocol_properties(dump), 13);
    assert_eq!(dump.category_count, 1);
    let inherits: usize = dump
        .protocols
        .iter()
        .filter(|protocol: &&ObjcProtocol| !protocol.inherited_protocols.is_empty())
        .count();
    assert_eq!(
        inherits, 38,
        "38 of the 43 recovered protocols name the protocols they incorporate"
    );
}

#[test]
fn feather_main_binary_recovers_every_protocol_it_declares() {
    let Some(report): Option<SwiftObjcReport> = analyzed_ipa(FEATHER_IPA) else {
        return;
    };
    let dump: &ObjcClassDump = main_objc(&report, FEATHER_IPA);
    assert_every_pointer_dereferences("Feather", dump);

    assert_eq!(dump.protocol_count, 22, "Feather declares 22 protocols");
    assert_eq!(protocol_methods(dump), 407);
    assert_eq!(protocol_properties(dump), 21);
    assert_eq!(dump.category_count, 0);
}

#[test]
fn recovered_records_render_as_objc_declarations() {
    let Some(report): Option<SwiftObjcReport> = analyzed_ipa(ONION_BROWSER_IPA) else {
        return;
    };
    let dump: &ObjcClassDump = embedded_objc(
        &report,
        ONION_BROWSER_IPA,
        "Frameworks/DTFoundation.framework/DTFoundation",
    );
    let category: &ObjcCategory = dump
        .categories
        .iter()
        .find(|category: &&ObjcCategory| category.class_name.as_deref() == Some("NSString"))
        .expect("the NSString category is recovered");
    let rendered: String = category.render();
    assert!(
        rendered.starts_with("@interface NSString (DTFormatNumbers)"),
        "a category renders as the class it extends followed by the category name, got:\n{rendered}"
    );
    assert!(rendered.trim_end().ends_with("@end"));

    let protocol: &ObjcProtocol = dump
        .protocols
        .iter()
        .find(|protocol: &&ObjcProtocol| protocol.name == "DTASN1ParserDelegate")
        .expect("the DTASN1ParserDelegate protocol is recovered");
    let rendered: String = protocol.render();
    assert!(
        rendered.starts_with("@protocol DTASN1ParserDelegate <NSObject>"),
        "a protocol renders with the protocols it incorporates, got:\n{rendered}"
    );
    assert!(
        rendered.contains("@optional"),
        "DTASN1ParserDelegate declares only optional methods, so the rendering must say so"
    );
    assert!(rendered.trim_end().ends_with("@end"));
}
