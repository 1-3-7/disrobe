#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_pass_scriptlang::lang::r_rds::{RdsEncoding, RdsObject, read_rds};
use disrobe_pass_scriptlang::lang::{ScriptArtifact, ScriptLang, analyze, classify};

const HELLO_RDS: &[u8] = include_bytes!("fixtures/hello.rds");
const HELLO_GZ_RDS: &[u8] = include_bytes!("fixtures/hello_gz.rds");

#[test]
fn real_uncompressed_rds_parses() {
    let obj: RdsObject = read_rds(HELLO_RDS).expect("real saveRDS uncompressed must parse");
    assert_eq!(obj.header.encoding, RdsEncoding::Xdr);
    assert_eq!(obj.header.version, 3);
}

#[test]
fn real_rds_recovers_list_names_oracle() {
    let obj: RdsObject = read_rds(HELLO_RDS).expect("parse");
    for expected in ["greeting", "numbers", "pi_approx", "labels"] {
        assert!(
            obj.names.iter().any(|n: &String| n == expected),
            "list element name '{expected}' must be recovered; got {:?}",
            obj.names
        );
    }
}

#[test]
fn real_rds_recovers_class_attribute_oracle() {
    let obj: RdsObject = read_rds(HELLO_RDS).expect("parse");
    assert!(
        obj.class.iter().any(|c: &String| c == "disrobe_demo"),
        "class() set in the source script must round-trip; got {:?}",
        obj.class
    );
}

#[test]
fn real_rds_recovers_string_values_oracle() {
    let obj: RdsObject = read_rds(HELLO_RDS).expect("parse");
    assert!(
        obj.string_values
            .iter()
            .any(|s: &String| s == "Hello, disrobe!"),
        "string value from source must be recovered; got {:?}",
        obj.string_values
    );
    for label in ["alpha", "beta", "gamma"] {
        assert!(
            obj.string_values.iter().any(|s: &String| s == label),
            "label '{label}' must be recovered"
        );
    }
}

#[test]
fn real_rds_root_is_list_of_four() {
    let obj: RdsObject = read_rds(HELLO_RDS).expect("parse");
    assert_eq!(obj.root_type, "list");
    assert_eq!(obj.root_length, Some(4));
}

#[test]
fn gzip_compressed_rds_is_classified_and_analyzed() {
    assert_eq!(classify(HELLO_GZ_RDS), Some(ScriptLang::R));
    let art: ScriptArtifact = analyze(HELLO_GZ_RDS).expect("gzip rds analyze");
    match art {
        ScriptArtifact::R(obj) => {
            assert!(obj.names.iter().any(|n: &String| n == "greeting"));
            assert!(obj.class.iter().any(|c: &String| c == "disrobe_demo"));
        }
        other => panic!("expected R artifact, got {other:?}"),
    }
}
