#![allow(clippy::expect_used, clippy::panic)]

use disrobe_vulnmatch::{
    PackageMatchIssue, PackageMatchStatus, PackageRule, PackageVersion, VersionScheme,
    compare_versions, match_package_versions,
};
use std::cmp::Ordering;
use std::process::Command;

fn package(scheme: VersionScheme, version: &str) -> PackageVersion {
    PackageVersion {
        scheme,
        name: "demo".to_owned(),
        version: version.to_owned(),
    }
}

fn rule(scheme: VersionScheme, constraint: &str) -> PackageRule {
    PackageRule {
        id: format!("{scheme:?}-advisory"),
        scheme,
        package: "demo".to_owned(),
        constraint: constraint.to_owned(),
    }
}

#[test]
fn package_matcher_dispatches_each_m1_scheme_without_semver_fallback() {
    let cases: [(VersionScheme, &str, &str); 5] = [
        (
            VersionScheme::Debian,
            "1.0~rc1-1",
            ">= 1.0~beta1-1, < 1.0-1",
        ),
        (VersionScheme::Rpm, "1.0^git1-1", "> 1.0-1"),
        (VersionScheme::Alpine, "1.2_rc1-r0", "< 1.2-r0"),
        (VersionScheme::Python, "1!2.0rc1", ">= 1!2.0b1, < 1!2.0"),
        (VersionScheme::Semver, "v1.5.0", "^1.2.0 || 2.x"),
    ];

    for (scheme, version, constraint) in cases {
        let report =
            match_package_versions(&[package(scheme, version)], &[rule(scheme, constraint)]);

        assert!(report.complete, "{scheme:?}: {report:?}");
        assert_eq!(report.matches.len(), 1, "{scheme:?}: {report:?}");
        assert_eq!(report.matches[0].status, PackageMatchStatus::Affected);
    }
}

#[test]
fn package_matcher_reports_typed_indeterminate_outcomes() {
    let unsupported = match_package_versions(
        &[package(VersionScheme::Maven, "1.0")],
        &[rule(VersionScheme::Maven, "< 2.0")],
    );
    assert!(!unsupported.complete);
    assert!(matches!(
        unsupported.matches[0].status,
        PackageMatchStatus::Indeterminate(PackageMatchIssue::UnsupportedScheme {
            scheme: VersionScheme::Maven
        })
    ));

    let malformed = match_package_versions(
        &[package(VersionScheme::Semver, "1.0.0")],
        &[rule(VersionScheme::Semver, ">= nope")],
    );
    assert!(!malformed.complete);
    assert!(matches!(
        malformed.matches[0].status,
        PackageMatchStatus::Indeterminate(PackageMatchIssue::NonconformingConstraint { .. })
    ));
}

#[test]
fn m1_comparators_follow_scheme_specific_release_boundaries() {
    let ordered: [(VersionScheme, &[&str]); 5] = [
        (
            VersionScheme::Debian,
            &["1.0~beta1-1", "1.0~rc1-1", "1.0-1", "1:0-1"],
        ),
        (
            VersionScheme::Rpm,
            &["1.0~rc1-1", "1.0-1", "1.0^git1-1", "1.1-1"],
        ),
        (
            VersionScheme::Alpine,
            &[
                "1.0_alpha1-r0",
                "1.0_beta1-r0",
                "1.0_rc1-r0",
                "1.0-r0",
                "1.0_p1-r0",
                "1.0_p1-r1",
            ],
        ),
        (
            VersionScheme::Python,
            &[
                "1.0.dev1",
                "1.0a1",
                "1.0b1",
                "1.0rc1",
                "1.0",
                "1.0.post1",
                "1!0.1",
            ],
        ),
        (
            VersionScheme::Semver,
            &[
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-beta",
                "1.0.0-rc.1",
                "1.0.0",
                "1.0.1",
            ],
        ),
    ];

    for (scheme, versions) in ordered {
        for (index, left) in versions.iter().enumerate() {
            assert_eq!(
                compare_versions(scheme, left, left).expect("valid reflexive version"),
                Ordering::Equal,
                "{scheme:?}: {left}"
            );
            for right in &versions[index + 1..] {
                assert_eq!(
                    compare_versions(scheme, left, right).expect("valid ordered versions"),
                    Ordering::Less,
                    "{scheme:?}: {left} < {right}"
                );
                assert_eq!(
                    compare_versions(scheme, right, left).expect("valid reversed versions"),
                    Ordering::Greater,
                    "{scheme:?}: {right} > {left}"
                );
            }
        }
        for first in versions {
            for second in versions {
                let first_second =
                    compare_versions(scheme, first, second).expect("valid first comparison");
                let second_first =
                    compare_versions(scheme, second, first).expect("valid reverse comparison");
                assert_eq!(first_second, second_first.reverse());
                for third in versions {
                    let second_third =
                        compare_versions(scheme, second, third).expect("valid second comparison");
                    let first_third = compare_versions(scheme, first, third)
                        .expect("valid transitive comparison");
                    if first_second != Ordering::Greater && second_third != Ordering::Greater {
                        assert_ne!(
                            first_third,
                            Ordering::Greater,
                            "{scheme:?}: {first} <= {second} <= {third}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn debian_and_rpm_refuse_versions_outside_their_declared_alphabets() {
    assert!(compare_versions(VersionScheme::Debian, "1:2:3-1", "1:2.3-1").is_err());
    assert!(compare_versions(VersionScheme::Rpm, "1.0@vendor-1", "1.0-1").is_err());
}

#[test]
fn constraints_cover_union_exclusion_wildcard_and_compatible_ranges() {
    let cases: [(VersionScheme, &str, &str, PackageMatchStatus); 11] = [
        (
            VersionScheme::Semver,
            "1.4.5",
            ">=1.0.0, !=1.4.5",
            PackageMatchStatus::Unaffected,
        ),
        (
            VersionScheme::Semver,
            "2.3.0",
            "^1.2.0 || 2.x",
            PackageMatchStatus::Affected,
        ),
        (
            VersionScheme::Semver,
            "1.2.9",
            "~1.2.3",
            PackageMatchStatus::Affected,
        ),
        (
            VersionScheme::Semver,
            "1.3.0",
            "~1.2.3",
            PackageMatchStatus::Unaffected,
        ),
        (
            VersionScheme::Python,
            "1.4.9",
            "~=1.4",
            PackageMatchStatus::Affected,
        ),
        (
            VersionScheme::Python,
            "2.0",
            "~=1.4",
            PackageMatchStatus::Unaffected,
        ),
        (
            VersionScheme::Python,
            "1.4.7",
            "==1.4.*",
            PackageMatchStatus::Affected,
        ),
        (
            VersionScheme::Python,
            "1!1.4.7",
            "==1!1.4.*",
            PackageMatchStatus::Affected,
        ),
        (
            VersionScheme::Semver,
            "1.9.0",
            "^1.2",
            PackageMatchStatus::Affected,
        ),
        (
            VersionScheme::Semver,
            "1.2.9",
            "~1.2",
            PackageMatchStatus::Affected,
        ),
        (
            VersionScheme::Semver,
            "93.0.0",
            "*",
            PackageMatchStatus::Affected,
        ),
    ];

    for (scheme, version, constraint, expected) in cases {
        let report =
            match_package_versions(&[package(scheme, version)], &[rule(scheme, constraint)]);
        assert_eq!(
            report.matches[0].status, expected,
            "{scheme:?}: {constraint}"
        );
    }
}

#[test]
fn package_matching_bounds_versions_and_skips_unrelated_rules() {
    let oversized: String = "1".repeat(4 * 1024 + 1);
    let limited = match_package_versions(
        &[package(VersionScheme::Debian, &oversized)],
        &[rule(VersionScheme::Debian, "< 2")],
    );
    assert!(!limited.complete);
    assert_eq!(
        limited.matches[0].status,
        PackageMatchStatus::Indeterminate(PackageMatchIssue::LimitExceeded)
    );

    let unrelated = PackageRule {
        id: "other-advisory".to_owned(),
        scheme: VersionScheme::Semver,
        package: "other".to_owned(),
        constraint: "<2.0.0".to_owned(),
    };
    let report = match_package_versions(&[package(VersionScheme::Semver, "1.0.0")], &[unrelated]);
    assert!(report.complete);
    assert!(report.matches.is_empty());
}

#[test]
fn pep440_normalizes_primary_reference_aliases_and_implicit_post_releases() {
    let cases: [(&str, &str, Ordering); 6] = [
        ("1.0alpha1", "1.0a1", Ordering::Equal),
        ("1.0preview1", "1.0rc1", Ordering::Equal),
        ("1.0rev1", "1.0post1", Ordering::Equal),
        ("1.0-1", "1.0.post1", Ordering::Equal),
        ("1.0+abc.1", "1.0+abc.2", Ordering::Less),
        ("  v1.0  ", "1.0", Ordering::Equal),
    ];

    for (left, right, expected) in cases {
        assert_eq!(
            compare_versions(VersionScheme::Python, left, right).expect("valid PEP 440 versions"),
            expected,
            "{left} compared with {right}"
        );
    }
}

#[test]
fn package_matcher_caps_cartesian_result_growth() {
    let packages: Vec<PackageVersion> = (0..129)
        .map(|_: usize| package(VersionScheme::Semver, "1.0.0"))
        .collect();
    let rules: Vec<PackageRule> = (0..129)
        .map(|index: usize| PackageRule {
            id: format!("advisory-{index}"),
            scheme: VersionScheme::Semver,
            package: "demo".to_owned(),
            constraint: "<2.0.0".to_owned(),
        })
        .collect();

    let report = match_package_versions(&packages, &rules);

    assert!(!report.complete);
    assert_eq!(report.issue, Some(PackageMatchIssue::LimitExceeded));
    assert_eq!(report.matches.len(), 16_384);
}

#[test]
fn alpine_comparator_matches_upstream_token_boundaries() {
    let cases: [(&str, &str, Ordering); 5] = [
        ("8.2.01", "8.2.001", Ordering::Greater),
        ("0.1.0_alpha_pre2", "0.1.0_alpha", Ordering::Less),
        ("1.7", "1.7b", Ordering::Less),
        ("1.0~1234-r1", "1.0~2345-r0", Ordering::Less),
        ("1.0_p10-r0", "1.0_p9-r0", Ordering::Greater),
    ];

    for (left, right, expected) in cases {
        assert_eq!(
            compare_versions(VersionScheme::Alpine, left, right).expect("valid Alpine versions"),
            expected,
            "{left} compared with {right}"
        );
    }
}

#[test]
fn matcher_refuses_invalid_grammar_and_bounds_output_ownership() {
    assert!(compare_versions(VersionScheme::Semver, "1.0.0+", "1.0.0").is_err());
    assert!(compare_versions(VersionScheme::Semver, "1.0.0+one+two", "1.0.0").is_err());
    assert!(compare_versions(VersionScheme::Python, "1.0.dev1.post1", "1.0").is_err());
    assert!(compare_versions(VersionScheme::Debian, "1.0@bad", "1.0").is_err());
    assert!(compare_versions(VersionScheme::Rpm, "1.0 bad", "1.0").is_err());

    let unsupported_operator = match_package_versions(
        &[package(VersionScheme::Debian, "1.0-1")],
        &[rule(VersionScheme::Debian, "^1.0-1")],
    );
    assert!(matches!(
        unsupported_operator.matches[0].status,
        PackageMatchStatus::Indeterminate(PackageMatchIssue::NonconformingConstraint { .. })
    ));

    let oversized: String = "1".repeat(8 * 1024 + 1);
    let bounded = match_package_versions(
        &[package(VersionScheme::Debian, &oversized)],
        &[rule(VersionScheme::Debian, "<2")],
    );
    assert!(!bounded.complete);
    assert_eq!(bounded.issue, Some(PackageMatchIssue::LimitExceeded));
    assert!(bounded.matches.is_empty());

    let oversized_constraint: String = "<2 ".repeat(2_731);
    let bounded_constraint = match_package_versions(
        &[package(VersionScheme::Debian, "1.0-1")],
        &[rule(VersionScheme::Debian, &oversized_constraint)],
    );
    assert!(!bounded_constraint.complete);
    assert_eq!(
        bounded_constraint.issue,
        Some(PackageMatchIssue::LimitExceeded)
    );
    assert!(bounded_constraint.matches.is_empty());
}

#[test]
fn package_matcher_caps_aggregate_owned_result_text() {
    let name: String = "p".repeat(8 * 1024);
    let version: String = "1".repeat(8 * 1024);
    let id: String = "r".repeat(8 * 1024);
    let packages: Vec<PackageVersion> = (0..1_500)
        .map(|_: usize| PackageVersion {
            scheme: VersionScheme::Debian,
            name: name.clone(),
            version: version.clone(),
        })
        .collect();
    let report = match_package_versions(
        &packages,
        &[PackageRule {
            id,
            scheme: VersionScheme::Debian,
            package: name,
            constraint: ">=0".to_owned(),
        }],
    );
    assert!(!report.complete);
    assert_eq!(report.issue, Some(PackageMatchIssue::LimitExceeded));
    assert!(report.matches.len() < packages.len());
}

#[test]
fn debian_comparator_uses_dpkg_digit_rank_inside_non_digit_runs() {
    assert_eq!(
        compare_versions(VersionScheme::Debian, "1.a", "1.1").expect("valid Debian versions"),
        Ordering::Greater
    );
}

#[test]
fn pep440_compatible_release_preserves_epoch() {
    let affected = match_package_versions(
        &[package(VersionScheme::Python, "1!1.9")],
        &[rule(VersionScheme::Python, "~=1!1.4")],
    );
    assert_eq!(affected.matches[0].status, PackageMatchStatus::Affected);

    let unaffected = match_package_versions(
        &[package(VersionScheme::Python, "1!2.0")],
        &[rule(VersionScheme::Python, "~=1!1.4")],
    );
    assert_eq!(unaffected.matches[0].status, PackageMatchStatus::Unaffected);
}

#[test]
fn pep440_specifiers_apply_local_version_rules() {
    let public_equal = match_package_versions(
        &[package(VersionScheme::Python, "1.0+vendor.1")],
        &[rule(VersionScheme::Python, "==1.0")],
    );
    assert_eq!(public_equal.matches[0].status, PackageMatchStatus::Affected);

    let local_equal = match_package_versions(
        &[package(VersionScheme::Python, "1.0+vendor.2")],
        &[rule(VersionScheme::Python, "==1.0+vendor.1")],
    );
    assert_eq!(
        local_equal.matches[0].status,
        PackageMatchStatus::Unaffected
    );

    let invalid_ordered_local = match_package_versions(
        &[package(VersionScheme::Python, "1.1")],
        &[rule(VersionScheme::Python, ">=1.0+vendor.1")],
    );
    assert!(matches!(
        invalid_ordered_local.matches[0].status,
        PackageMatchStatus::Indeterminate(PackageMatchIssue::NonconformingConstraint { .. })
    ));

    let named_local = match_package_versions(
        &[package(VersionScheme::Python, "1.0+linux")],
        &[rule(VersionScheme::Python, "==1.0+linux")],
    );
    assert_eq!(named_local.matches[0].status, PackageMatchStatus::Affected);

    assert_eq!(
        compare_versions(VersionScheme::Python, "1.0", "1.0.post1.dev1")
            .expect("valid post-development release"),
        Ordering::Less
    );
}

#[test]
fn semver_ranges_admit_prereleases_only_from_the_same_named_tuple() {
    let refused: [(&str, &str); 4] = [
        ("1.3.0-alpha", ">=1.2.3 <2.0.0"),
        ("1.3.0-alpha", "^1.2.3"),
        ("1.3.0-alpha", "~1.2.3"),
        ("1.2.4-beta.2", "^1.2.3-beta.2"),
    ];
    for (version, constraint) in refused {
        let report = match_package_versions(
            &[package(VersionScheme::Semver, version)],
            &[rule(VersionScheme::Semver, constraint)],
        );
        assert_eq!(
            report.matches[0].status,
            PackageMatchStatus::Unaffected,
            "{version} against {constraint}"
        );
    }

    let admitted = match_package_versions(
        &[package(VersionScheme::Semver, "1.2.3-beta.4")],
        &[rule(VersionScheme::Semver, "^1.2.3-beta.2")],
    );
    assert_eq!(admitted.matches[0].status, PackageMatchStatus::Affected);

    let named_identifier = match_package_versions(
        &[package(VersionScheme::Semver, "1.2.3-x")],
        &[rule(VersionScheme::Semver, "==1.2.3-x")],
    );
    assert_eq!(
        named_identifier.matches[0].status,
        PackageMatchStatus::Affected
    );
}

#[test]
#[ignore = "requires Python packaging"]
fn pep440_comparator_matches_python_packaging() {
    let pairs: [(&str, &str); 10] = [
        ("1.0.dev1", "1.0a1"),
        ("1.0a1", "1.0b1"),
        ("1.0rc1", "1.0"),
        ("1.0", "1.0.post1"),
        ("1.0+abc", "1.0+1"),
        ("1!1.0", "2.0"),
        ("1.0-1", "1.0.post1"),
        ("1.0preview1", "1.0rc1"),
        ("1.0.post1.dev1", "1.0.post1"),
        ("1.0+abc.1", "1.0+abc.2"),
    ];

    for (left, right) in pairs {
        let output = Command::new("python")
            .args([
                "-c",
                "import sys; from packaging.version import Version; a=Version(sys.argv[1]); b=Version(sys.argv[2]); print((a>b)-(a<b))",
                left,
                right,
            ])
            .output()
            .expect("Python packaging reference must run");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference = match String::from_utf8_lossy(&output.stdout).trim() {
            "-1" => Ordering::Less,
            "0" => Ordering::Equal,
            "1" => Ordering::Greater,
            value => panic!("unexpected Python packaging result: {value}"),
        };
        assert_eq!(
            compare_versions(VersionScheme::Python, left, right).expect("valid PEP 440 versions"),
            reference,
            "{left} compared with {right}"
        );
    }
}

#[test]
#[ignore = "requires Python packaging"]
fn pep440_specifiers_match_python_packaging_local_rules() {
    let cases: [(&str, &str); 5] = [
        ("1.0+vendor.1", "==1.0"),
        ("1.0+vendor.1", "!=1.0"),
        ("1.0+vendor.2", "==1.0+vendor.1"),
        ("1.0+vendor.1", ">=1.0"),
        ("1.0+vendor.1", "==1.0.*"),
    ];

    for (version, constraint) in cases {
        let output = Command::new("python")
            .args([
                "-c",
                "import sys; from packaging.specifiers import SpecifierSet; print(int(SpecifierSet(sys.argv[2]).contains(sys.argv[1], prereleases=True)))",
                version,
                constraint,
            ])
            .output()
            .expect("Python packaging reference must run");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reference: bool = String::from_utf8_lossy(&output.stdout).trim() == "1";
        let report = match_package_versions(
            &[package(VersionScheme::Python, version)],
            &[rule(VersionScheme::Python, constraint)],
        );
        assert_eq!(
            report.matches[0].status == PackageMatchStatus::Affected,
            reference,
            "{version} against {constraint}"
        );
    }
}
