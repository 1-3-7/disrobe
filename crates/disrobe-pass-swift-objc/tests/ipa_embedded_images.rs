#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

#[path = "fixtures/mod.rs"]
mod fixtures;

use std::collections::BTreeSet;

use disrobe_pass_swift_objc::ipa::{self, EmbeddedImage, EmbeddedImageRole, IpaInventory};
use disrobe_pass_swift_objc::pass::{self, ContainerKind, EmbeddedImageReport, SwiftObjcReport};

use fixtures::{
    MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_info_plist_with_executable,
    build_ipa_from_files, build_macho64_slice, build_objc_methname_payload,
};
use macho_corpus::{CorpusFixture, FEATHER_IPA, ONION_BROWSER_IPA, PPSSPP_IPA, read_host_sourced};

fn analyzed(fixture: CorpusFixture) -> Option<SwiftObjcReport> {
    let bytes: Vec<u8> = read_host_sourced(fixture)?;
    let report: SwiftObjcReport = pass::analyze(&bytes)
        .unwrap_or_else(|error| panic!("{} does not analyze: {error}", fixture.relative()));
    assert_eq!(report.container, ContainerKind::Ipa);
    Some(report)
}

fn assert_each_image_was_analyzed(fixture: CorpusFixture, report: &SwiftObjcReport) {
    assert!(
        report.unanalyzed_embedded_images.is_empty(),
        "{} left embedded images unanalyzed, and an image this pass enumerated but did not read \
         is a gap rather than a result: {:?}",
        fixture.relative(),
        report
            .unanalyzed_embedded_images
            .iter()
            .map(|skipped| (skipped.path.as_str(), skipped.reason.as_str()))
            .collect::<Vec<(&str, &str)>>()
    );
    for image in &report.embedded_images {
        assert!(
            !image.slices.is_empty(),
            "{} in {} was enumerated as a Mach-O image, so it must yield at least one analyzed \
             slice",
            image.path,
            fixture.relative()
        );
        assert_eq!(
            image.role,
            EmbeddedImageRole::Framework,
            "{} sits under Frameworks/",
            image.path
        );
    }
}

#[test]
fn onion_browser_analyzes_every_embedded_framework_as_its_own_image() {
    let Some(report): Option<SwiftObjcReport> = analyzed(ONION_BROWSER_IPA) else {
        return;
    };
    assert_each_image_was_analyzed(ONION_BROWSER_IPA, &report);

    let paths: BTreeSet<&str> = report
        .embedded_images
        .iter()
        .map(|image: &EmbeddedImageReport| image.path.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "Payload/OnionBrowser.app/Frameworks/DTFoundation.framework/DTFoundation",
        "Payload/OnionBrowser.app/Frameworks/Eureka.framework/Eureka",
        "Payload/OnionBrowser.app/Frameworks/FavIcon.framework/FavIcon",
        "Payload/OnionBrowser.app/Frameworks/ImageRow.framework/ImageRow",
        "Payload/OnionBrowser.app/Frameworks/MBProgressHUD.framework/MBProgressHUD",
        "Payload/OnionBrowser.app/Frameworks/OrbotKit.framework/OrbotKit",
        "Payload/OnionBrowser.app/Frameworks/ProgressHUD.framework/ProgressHUD",
        "Payload/OnionBrowser.app/Frameworks/SDCAlertView.framework/SDCAlertView",
        "Payload/OnionBrowser.app/Frameworks/SwiftSoup.framework/SwiftSoup",
        "Payload/OnionBrowser.app/Frameworks/TUSafariActivity.framework/TUSafariActivity",
        "Payload/OnionBrowser.app/Frameworks/Tor.framework/Tor",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        paths, expected,
        "every Mach-O image under Frameworks/ must be analyzed, and only those; recovering 9 of \
         11 would mean two frameworks went unread while the run still reported success"
    );

    let framework_classes: usize = report
        .embedded_images
        .iter()
        .flat_map(|image: &EmbeddedImageReport| image.slices.iter())
        .map(|slice| slice.objc.interfaces.len())
        .sum();
    assert_eq!(
        framework_classes, 182,
        "the embedded frameworks carry 182 recovered ObjC classes between them, which is metadata \
         the main binary alone does not expose"
    );
    let framework_categories: usize = report
        .embedded_images
        .iter()
        .flat_map(|image: &EmbeddedImageReport| image.slices.iter())
        .map(|slice| slice.objc.categories.len())
        .sum();
    assert_eq!(
        framework_categories, 9,
        "7 of the recovered categories live in DTFoundation and 2 in Tor, and neither shows up \
         when only the main binary is read"
    );
}

#[test]
fn feather_and_ppsspp_analyze_their_embedded_frameworks() {
    let feather: Option<SwiftObjcReport> = analyzed(FEATHER_IPA);
    if let Some(report) = feather.as_ref() {
        assert_each_image_was_analyzed(FEATHER_IPA, report);
        assert_eq!(
            report
                .embedded_images
                .iter()
                .map(|image: &EmbeddedImageReport| image.path.as_str())
                .collect::<Vec<&str>>(),
            vec!["Payload/Feather.app/Frameworks/OpenSSL.framework/OpenSSL"]
        );
    }

    let ppsspp: Option<SwiftObjcReport> = analyzed(PPSSPP_IPA);
    if let Some(report) = ppsspp.as_ref() {
        assert_each_image_was_analyzed(PPSSPP_IPA, report);
        assert_eq!(
            report
                .embedded_images
                .iter()
                .map(|image: &EmbeddedImageReport| image.path.as_str())
                .collect::<Vec<&str>>(),
            vec!["Payload/PPSSPP.app/Frameworks/libMoltenVK.dylib"],
            "a framework directory holds plain dylibs too, and one that is skipped takes its 8 \
             categories with it"
        );
    }
}

#[test]
fn enumeration_skips_archive_entries_that_are_not_mach_o() {
    let Some(bytes): Option<Vec<u8>> = read_host_sourced(ONION_BROWSER_IPA) else {
        return;
    };
    let inventory: IpaInventory = ipa::inventory(&bytes).expect("the archive is an ipa");
    let images: Vec<EmbeddedImage> =
        ipa::embedded_images(&bytes, &inventory).expect("the archive enumerates");
    assert!(
        inventory.frameworks.len() > images.len(),
        "a framework bundle carries resources and signatures beside its binary, so the image \
         count must be the Mach-O subset rather than the entry count ({} entries)",
        inventory.frameworks.len()
    );
    assert_eq!(images.len(), 11);
    assert!(
        images
            .iter()
            .all(|image: &EmbeddedImage| image.size > 0
                && image.role == EmbeddedImageRole::Framework),
    );
}

fn plugin_ipa() -> Vec<u8> {
    let slice: Vec<u8> = build_macho64_slice(&MachoSliceBuilder {
        segments: vec![MachoSegmentSpec {
            seg_name: "__TEXT",
            sections: vec![MachoSectionSpec {
                sect_name: "__objc_methname",
                seg_name: "__TEXT",
                data: build_objc_methname_payload(&["shareExtensionEntry", "beginRequest:"]),
            }],
        }],
        encryption_id: 0,
    });
    let plist: Vec<u8> = build_info_plist_with_executable("Sample", "Sample");
    build_ipa_from_files(&[
        ("Payload/Sample.app/Sample".to_owned(), slice.clone()),
        ("Payload/Sample.app/Info.plist".to_owned(), plist.clone()),
        (
            "Payload/Sample.app/PlugIns/Share.appex/Share".to_owned(),
            slice.clone(),
        ),
        (
            "Payload/Sample.app/PlugIns/Share.appex/Info.plist".to_owned(),
            plist,
        ),
        (
            "Payload/Sample.app/Frameworks/Helper.framework/Helper".to_owned(),
            slice,
        ),
    ])
}

#[test]
fn an_app_extension_under_plugins_is_analyzed_as_its_own_image() {
    let image: Vec<u8> = plugin_ipa();
    let report: SwiftObjcReport = pass::analyze(&image).expect("the archive analyzes");
    assert_eq!(report.container, ContainerKind::Ipa);
    assert!(report.unanalyzed_embedded_images.is_empty());

    let by_path: Vec<(&str, EmbeddedImageRole)> = report
        .embedded_images
        .iter()
        .map(|report: &EmbeddedImageReport| (report.path.as_str(), report.role))
        .collect();
    assert_eq!(
        by_path,
        vec![
            (
                "Payload/Sample.app/Frameworks/Helper.framework/Helper",
                EmbeddedImageRole::Framework
            ),
            (
                "Payload/Sample.app/PlugIns/Share.appex/Share",
                EmbeddedImageRole::PlugIn
            ),
        ],
        "an app extension is a separate image with its own metadata, so it is analyzed beside the \
         frameworks rather than folded into the main binary. This archive is assembled by this \
         case rather than produced by an Apple toolchain, so it proves the PlugIns path is \
         reached and says nothing about how much a real extension recovers"
    );
    for image in &report.embedded_images {
        assert_eq!(image.slices.len(), 1);
        assert_eq!(
            image.slices[0].objc.unique_selectors.len(),
            2,
            "each embedded image is read on its own, so the selectors this case wrote into {} \
             come back from it",
            image.path
        );
    }
}
