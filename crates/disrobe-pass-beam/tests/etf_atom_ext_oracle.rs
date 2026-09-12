#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_beam::etf::{ETF_MAGIC, TAG_ATOM_DEPRECATED};
use disrobe_pass_beam::{Error, Term, decode_etf};

use common::erlang_toolchain::{ERL, require, run_bounded};

const GRADED: &str = "the ETF ATOM_EXT character-limit differential";

fn require_oracle_erlang() -> PathBuf {
    require(&ERL, GRADED).unwrap_or_else(|| panic!("{GRADED} requires erl"))
}

fn atom_ext_latin1(length: u16) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![ETF_MAGIC, TAG_ATOM_DEPRECATED];
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend(std::iter::repeat_n(b'a', usize::from(length)));
    bytes
}

fn decode_utf8_hex(encoded: &str) -> String {
    assert!(
        encoded.len().is_multiple_of(2),
        "erl returned an odd-length UTF-8 hex payload {encoded:?}"
    );
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| {
            let digits: &str = core::str::from_utf8(pair).expect("erl hex output must be ASCII");
            u8::from_str_radix(digits, 16).expect("erl hex output must contain hexadecimal bytes")
        })
        .collect();
    String::from_utf8(bytes).expect("erl hex output must decode to UTF-8")
}

fn erl_decodes_atom(erl: &Path, bytes: &[u8]) -> Option<String> {
    let encoded: String = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<String>>()
        .join(",");
    let eval: String = format!(
        "case catch binary_to_term(<<{encoded}>>) of {{'EXIT', _}} -> io:format(\"reject\"); Atom when is_atom(Atom) -> io:format(\"accept:~s\", [binary:encode_hex(atom_to_binary(Atom, utf8))]); _ -> io:format(\"not-atom\") end, halt()."
    );
    let mut command: Command = Command::new(erl);
    command.arg("-noshell").arg("-eval").arg(&eval);
    match run_bounded(command) {
        Some((true, stdout, stderr)) => {
            let outcome: &str = stdout.trim();
            match outcome {
                "reject" => None,
                _ => {
                    let Some(atom): Option<&str> = outcome.strip_prefix("accept:") else {
                        panic!(
                            "erl returned an unknown ATOM_EXT outcome {outcome:?}: eval {eval:?}, stderr {stderr:?}"
                        );
                    };
                    Some(decode_utf8_hex(atom))
                }
            }
        }
        Some((false, stdout, stderr)) => {
            panic!(
                "erl could not evaluate ATOM_EXT: eval {eval:?}, stdout {stdout:?}, stderr {stderr:?}"
            )
        }
        None => panic!("erl timed out evaluating ATOM_EXT: {eval:?}"),
    }
}

#[test]
fn atom_ext_non_ascii_latin1_matches_erl_decoding() {
    let erl: PathBuf = require_oracle_erlang();
    let bytes: Vec<u8> = vec![ETF_MAGIC, TAG_ATOM_DEPRECATED, 0, 1, 0xe9];
    let expected: String = "\u{e9}".to_owned();

    assert_eq!(
        erl_decodes_atom(&erl, &bytes),
        Some(expected.clone()),
        "erl did not decode the hand-built non-ASCII Latin-1 ATOM_EXT as the expected atom"
    );
    assert_eq!(
        decode_etf(&bytes).expect("the accepted non-ASCII Latin-1 ATOM_EXT must decode"),
        Term::Atom(expected)
    );
}

#[test]
fn atom_ext_255_latin1_characters_matches_erl_acceptance() {
    let erl: PathBuf = require_oracle_erlang();
    let bytes: Vec<u8> = atom_ext_latin1(255);
    let expected: String = "a".repeat(255);

    assert_eq!(
        erl_decodes_atom(&erl, &bytes),
        Some(expected.clone()),
        "erl did not decode the hand-built 255-character ATOM_EXT boundary as the expected atom"
    );
    assert_eq!(
        decode_etf(&bytes).expect("the accepted ATOM_EXT must decode"),
        Term::Atom(expected)
    );
}

#[test]
fn atom_ext_256_latin1_mutation_matches_erl_rejection() {
    let erl: PathBuf = require_oracle_erlang();
    let bytes: Vec<u8> = atom_ext_latin1(256);

    assert!(
        erl_decodes_atom(&erl, &bytes).is_none(),
        "erl accepted a 256-character ATOM_EXT mutation"
    );
    assert!(matches!(
        decode_etf(&bytes),
        Err(Error::AtomTooLong {
            index: 0,
            scalars: 256,
            limit: 255
        })
    ));
}
