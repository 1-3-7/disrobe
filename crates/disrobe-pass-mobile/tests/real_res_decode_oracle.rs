#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::Cursor;
use std::path::PathBuf;

use disrobe_pass_mobile::apk_recon::{self, ApkReconReport};
use disrobe_pass_mobile::res_decode::{self, ResDecodeReport};

fn read_fixture(rel: &str) -> Vec<u8> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push(rel);
    std::fs::read(&p).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", p.display()))
}

fn decode(apk: &[u8]) -> ResDecodeReport {
    let cur: Cursor<&[u8]> = Cursor::new(apk);
    let mut z = zip::ZipArchive::new(cur).expect("open apk");
    let count: usize = z.len();
    let mut names: Vec<(usize, String, u64)> = Vec::new();
    for i in 0..count {
        if let Ok(f) = z.by_index(i) {
            names.push((i, f.name().to_owned(), f.size()));
        }
    }
    let arsc_raw: Vec<u8> = {
        use std::io::Read as _;
        let mut f = z.by_name("resources.arsc").expect("arsc entry");
        let mut b: Vec<u8> = Vec::new();
        f.read_to_end(&mut b).expect("read arsc");
        b
    };
    let table = disrobe_pass_mobile::arsc::parse(&arsc_raw).expect("parse arsc");
    res_decode::decode_archive(&mut z, &names, Some(&table))
}

#[test]
fn binary_layout_xml_reconstructs_known_source() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-res.apk");
    let report: ResDecodeReport = decode(&apk);

    assert!(
        report.binary_xml_count >= 1,
        "at least the activity_main.xml binary layout decoded, got {}",
        report.binary_xml_count
    );

    let layout = report
        .decoded_xml
        .iter()
        .find(|d| d.path.ends_with("/activity_main.xml") && d.xml.contains("<TextView"))
        .expect("a binary layout variant with the TextView element decoded");
    let xml: &str = &layout.xml;

    assert!(
        xml.contains("<LinearLayout"),
        "ground-truth source root element LinearLayout:\n{xml}"
    );
    assert!(
        xml.contains("<TextView"),
        "ground-truth source child element TextView:\n{xml}"
    );
    assert!(
        xml.contains("android:orientation=\"vertical\""),
        "literal source attribute orientation=vertical:\n{xml}"
    );
    assert!(
        xml.contains("android:layout_width=\"match_parent\""),
        "framework enum layout_width=match_parent:\n{xml}"
    );
    assert!(
        xml.contains("android:padding=\"@com.disrobe.resfixture:dimen/padding_default\""),
        "padding ref resolves against arsc to dimen/padding_default:\n{xml}"
    );
    assert!(
        xml.contains("android:text=\"@com.disrobe.resfixture:string/greeting\""),
        "text ref resolves to string/greeting:\n{xml}"
    );
    assert!(
        xml.contains("android:textColor=\"@com.disrobe.resfixture:color/brand_primary\""),
        "textColor ref resolves to color/brand_primary:\n{xml}"
    );
    assert!(
        xml.contains("@+id/title") || xml.contains("id/title"),
        "id reference recovered for TextView:\n{xml}"
    );
}

#[test]
fn values_resources_reconstruct_known_source() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-res.apk");
    let report: ResDecodeReport = decode(&apk);

    let default = report
        .values_files
        .iter()
        .find(|f| f.config.is_empty())
        .expect("default-config values file reconstructed");
    let xml: &str = &default.xml;

    assert!(
        xml.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>"),
        "well-formed resources prolog:\n{xml}"
    );
    assert!(xml.contains("</resources>"), "closing tag:\n{xml}");

    assert!(
        xml.contains("<string name=\"app_name\">DisrobeRes</string>"),
        "string/app_name reconstructed verbatim from source:\n{xml}"
    );
    assert!(
        xml.contains("<string name=\"greeting\">Hello Disrobe</string>"),
        "string/greeting reconstructed:\n{xml}"
    );
    assert!(
        xml.contains("<color name=\"brand_primary\">#ff336699</color>"),
        "color/brand_primary reconstructed from source #ff336699:\n{xml}"
    );
    assert!(
        xml.contains("<color name=\"brand_accent\">#ffcc0000</color>"),
        "color/brand_accent reconstructed:\n{xml}"
    );
    assert!(
        xml.contains("<dimen name=\"padding_default\">16.0dp</dimen>"),
        "dimen/padding_default reconstructed as 16dp:\n{xml}"
    );
    assert!(
        xml.contains("<dimen name=\"text_size_title\">22.0sp</dimen>"),
        "dimen/text_size_title reconstructed as 22sp:\n{xml}"
    );
    assert!(
        xml.contains("<bool name=\"is_production\">true</bool>"),
        "bool/is_production reconstructed:\n{xml}"
    );
    assert!(
        xml.contains("<integer name=\"max_retries\">5</integer>"),
        "integer/max_retries reconstructed:\n{xml}"
    );

    assert!(
        report.values_resource_count >= 8,
        "at least 8 value resources reconstructed (2 string, 2 color, 2 dimen, 1 bool, 1 integer), got {}",
        report.values_resource_count
    );
}

#[test]
fn apk_report_surfaces_decoded_resources() {
    let apk: Vec<u8> = read_fixture("corpus/apk/fixture-res.apk");
    let report: ApkReconReport = apk_recon::analyze(&apk).expect("analyze apk");

    assert!(
        report.resources_decoded.binary_xml_count >= 1,
        "apk report surfaces decoded binary res xml count"
    );
    assert!(
        report.resources_decoded.values_resource_count >= 8,
        "apk report surfaces reconstructed values resources"
    );
    assert!(
        report
            .resources_decoded
            .decoded_xml
            .iter()
            .any(|d| d.path.starts_with("res/layout/")),
        "a res/layout entry surfaced in the apk report"
    );
}
