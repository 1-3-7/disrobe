#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use disrobe_vulnmatch::{PackageType, PackageUrlError, build_package_url};

fn qualifier_map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value): &(&str, &str)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn assert_purl(
    package_type: PackageType,
    namespace: Option<&str>,
    name: &str,
    version: Option<&str>,
    qualifiers: &[(&str, &str)],
    subpath: Option<&str>,
    expected: &str,
) {
    let actual: String = build_package_url(
        package_type,
        namespace,
        name,
        version,
        &qualifier_map(qualifiers),
        subpath,
    )
    .expect("official package URL example should build");
    assert_eq!(actual, expected, "{package_type:?}");
}

#[test]
fn official_type_examples_cover_every_exposed_package_type() {
    assert_purl(
        PackageType::Debian,
        Some("DEBIAN"),
        "ATTR",
        Some("1:2.4.47-2"),
        &[("arch", "source")],
        None,
        "pkg:deb/debian/attr@1:2.4.47-2?arch=source",
    );
    assert_purl(
        PackageType::Rpm,
        Some("FEDORA"),
        "curl",
        Some("7.50.3-1.fc25"),
        &[("arch", "i386"), ("distro", "fedora-25")],
        None,
        "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
    );
    assert_purl(
        PackageType::Alpine,
        Some("ALPINE"),
        "CURL",
        Some("7.83.0-r0"),
        &[("arch", "x86")],
        None,
        "pkg:apk/alpine/curl@7.83.0-r0?arch=x86",
    );
    assert_purl(
        PackageType::Python,
        None,
        "Django_AllAuth",
        Some("12.23"),
        &[],
        None,
        "pkg:pypi/django-allauth@12.23",
    );
    assert_purl(
        PackageType::Maven,
        Some("org.apache.xmlgraphics"),
        "batik-anim",
        Some("1.9.1"),
        &[("classifier", "sources")],
        None,
        "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?classifier=sources",
    );
    assert_purl(
        PackageType::Npm,
        Some("angular"),
        "animation",
        Some("12.3.1"),
        &[],
        None,
        "pkg:npm/%40angular/animation@12.3.1",
    );
    assert_purl(
        PackageType::Ruby,
        None,
        "jruby-launcher",
        Some("1.1.2"),
        &[("platform", "java")],
        None,
        "pkg:gem/jruby-launcher@1.1.2?platform=java",
    );
    assert_purl(
        PackageType::Go,
        Some("google.golang.org"),
        "genproto",
        None,
        &[],
        Some("googleapis/api/annotations"),
        "pkg:golang/google.golang.org/genproto#googleapis/api/annotations",
    );
    assert_purl(
        PackageType::Cargo,
        None,
        "rand",
        Some("0.7.2"),
        &[],
        None,
        "pkg:cargo/rand@0.7.2",
    );
}

#[test]
fn type_specific_case_policy_preserves_only_case_sensitive_components() {
    assert_purl(
        PackageType::Rpm,
        Some("FEDORA"),
        "CaseSensitiveName",
        Some("1-RC1"),
        &[],
        None,
        "pkg:rpm/fedora/CaseSensitiveName@1-RC1",
    );
    assert_purl(
        PackageType::Python,
        None,
        "Case.Name",
        Some("1.0RC1"),
        &[],
        None,
        "pkg:pypi/case-name@1.0rc1",
    );
    assert_purl(
        PackageType::Maven,
        Some("Org.Example"),
        "CaseSensitiveName",
        Some("1-RC1"),
        &[],
        None,
        "pkg:maven/Org.Example/CaseSensitiveName@1-RC1",
    );
    assert_purl(
        PackageType::Npm,
        Some("Scope"),
        "CaseSensitiveName",
        Some("1-RC1"),
        &[],
        None,
        "pkg:npm/%40Scope/CaseSensitiveName@1-RC1",
    );
    assert_purl(
        PackageType::Ruby,
        None,
        "CaseSensitiveName",
        Some("1-RC1"),
        &[],
        None,
        "pkg:gem/CaseSensitiveName@1-RC1",
    );
    assert_purl(
        PackageType::Cargo,
        None,
        "CaseSensitiveName",
        Some("1-RC1"),
        &[],
        None,
        "pkg:cargo/CaseSensitiveName@1-RC1",
    );
    assert_purl(
        PackageType::Go,
        Some("EXAMPLE.COM"),
        "MODULE",
        Some("V1.0.0"),
        &[],
        None,
        "pkg:golang/example.com/module@V1.0.0",
    );
}

#[test]
fn core_encoding_preserves_colons_and_encodes_reserved_and_unicode_bytes() {
    assert_purl(
        PackageType::Cargo,
        None,
        "na:mé/@?=&#",
        Some("1:0+β"),
        &[],
        None,
        "pkg:cargo/na:m%C3%A9%2F%40%3F%3D%26%23@1:0%2B%CE%B2",
    );
    assert_purl(
        PackageType::Maven,
        Some("groovy"),
        "groovy",
        Some("1.0"),
        &[("repository_url", "https://maven.google.com")],
        None,
        "pkg:maven/groovy/groovy@1.0?repository_url=https:%2F%2Fmaven.google.com",
    );
}

#[test]
fn namespace_policies_are_enforced_for_all_package_types() {
    for package_type in [
        PackageType::Debian,
        PackageType::Rpm,
        PackageType::Alpine,
        PackageType::Maven,
        PackageType::Go,
    ] {
        assert_eq!(
            build_package_url(
                package_type,
                None,
                "package",
                Some("1"),
                &BTreeMap::new(),
                None,
            ),
            Err(PackageUrlError::MissingNamespace { package_type })
        );
    }

    assert_purl(
        PackageType::Npm,
        None,
        "foobar",
        Some("12.3.1"),
        &[],
        None,
        "pkg:npm/foobar@12.3.1",
    );

    for package_type in [PackageType::Python, PackageType::Ruby, PackageType::Cargo] {
        assert_eq!(
            build_package_url(
                package_type,
                Some("forbidden"),
                "package",
                Some("1"),
                &BTreeMap::new(),
                None,
            ),
            Err(PackageUrlError::ProhibitedNamespace { package_type })
        );
    }
}

#[test]
fn qualifier_policy_canonicalizes_keys_without_closing_the_core_key_space() {
    assert_purl(
        PackageType::Maven,
        Some("org.example"),
        "artifact",
        Some("1"),
        &[
            ("Repository_URL", "https://repo.example/a b"),
            ("TYPE", "zip"),
        ],
        None,
        "pkg:maven/org.example/artifact@1?repository_url=https:%2F%2Frepo.example%2Fa%20b&type=zip",
    );

    assert_purl(
        PackageType::Maven,
        Some("mygroup"),
        "myartifact",
        Some("1.0.0 Final"),
        &[("mykey", "my value")],
        None,
        "pkg:maven/mygroup/myartifact@1.0.0%20Final?mykey=my%20value",
    );
}

#[test]
fn qualifier_strings_are_sorted_lexicographically_after_encoding() {
    assert_purl(
        PackageType::Cargo,
        None,
        "crate",
        Some("1.0.0"),
        &[("a", "z"), ("a.b", "x")],
        None,
        "pkg:cargo/crate@1.0.0?a.b=x&a=z",
    );
}

#[test]
fn official_legacy_maven_packaging_qualifier_is_canonical() {
    assert_purl(
        PackageType::Maven,
        Some("org.apache.xmlgraphics"),
        "batik-anim",
        Some("1.9.1"),
        &[("packaging", "sources")],
        None,
        "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources",
    );
}

#[test]
fn qualifier_canonicalization_rejects_invalid_or_ambiguous_maps() {
    let digit_first: BTreeMap<String, String> = qualifier_map(&[("1arch", "x86")]);
    assert_eq!(
        build_package_url(
            PackageType::Debian,
            Some("debian"),
            "curl",
            Some("1"),
            &digit_first,
            None,
        ),
        Err(PackageUrlError::InvalidQualifier {
            key: "1arch".to_owned()
        })
    );

    let colliding: BTreeMap<String, String> = qualifier_map(&[("Arch", "x86"), ("arch", "arm64")]);
    assert_eq!(
        build_package_url(
            PackageType::Debian,
            Some("debian"),
            "curl",
            Some("1"),
            &colliding,
            None,
        ),
        Err(PackageUrlError::InvalidQualifier {
            key: "arch".to_owned(),
        })
    );

    assert_eq!(
        build_package_url(
            PackageType::Cargo,
            None,
            "rand",
            Some("0.7.2"),
            &qualifier_map(&[("vers", ">=0.7")]),
            None,
        ),
        Err(PackageUrlError::VersionAndVers)
    );
}

#[test]
fn empty_optional_values_and_path_edges_are_canonicalized() {
    assert_purl(
        PackageType::Maven,
        Some("/org.example/"),
        "/artifact/",
        Some(""),
        &[("classifier", ""), ("type", "jar")],
        Some("/src/main/"),
        "pkg:maven/org.example/artifact?type=jar#src/main",
    );
}

#[test]
fn empty_and_relative_subpath_segments_are_discarded() {
    let purl: String = build_package_url(
        PackageType::Maven,
        Some("org.example"),
        "artifact",
        None,
        &BTreeMap::new(),
        Some("/src//./generated/../main/"),
    )
    .expect("subpath segments should canonicalize");

    assert_eq!(purl, "pkg:maven/org.example/artifact#src/generated/main");
    let subpath: &str = purl
        .split_once('#')
        .map(|(_, value): (&str, &str)| value)
        .expect("canonical PURL should contain a subpath");
    assert!(
        subpath
            .split('/')
            .all(|segment: &str| !segment.is_empty() && !matches!(segment, "." | ".."))
    );
}

#[test]
fn input_and_encoded_output_have_explicit_byte_ceilings() {
    let oversized: String = "a".repeat(16_385);
    assert_eq!(
        build_package_url(
            PackageType::Cargo,
            None,
            &oversized,
            None,
            &BTreeMap::new(),
            None,
        ),
        Err(PackageUrlError::TooLong {
            actual: 16_385,
            limit: 16_384,
        })
    );

    let maximally_encoded: String = "é".repeat(8_192);
    let purl: String = build_package_url(
        PackageType::Cargo,
        None,
        &maximally_encoded,
        None,
        &BTreeMap::new(),
        None,
    )
    .expect("maximum-size encoded input should remain within the output ceiling");
    assert_eq!(purl.len(), 49_162);
    assert!(purl.starts_with("pkg:cargo/%C3%A9%C3%A9"));
    assert!(purl.ends_with("%C3%A9%C3%A9"));

    let lowercase_expansion: String = "İ".repeat(8_192);
    assert_eq!(
        build_package_url(
            PackageType::Python,
            None,
            &lowercase_expansion,
            None,
            &BTreeMap::new(),
            None,
        ),
        Err(PackageUrlError::OutputTooLong {
            actual: 57_353,
            limit: 57_344,
        })
    );
}
