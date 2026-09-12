#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_pass_go::{GoAnalysis, analyze, probe_thunk_literals};

#[test]
fn garble_strings_include_embed_marker() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_NORMAL);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze normal");
    assert!(
        !analysis.garble.recovered_strings.is_empty(),
        "expected at least one recovered string from the rodata sections"
    );
    let any_marker_or_runtime: bool = analysis
        .garble
        .recovered_strings
        .iter()
        .any(|s| s.contains("disrobe-embed-payload-marker") || s.contains("runtime."));
    assert!(
        any_marker_or_runtime,
        "expected to recover either the embed marker or a runtime.* string fragment"
    );
}

#[test]
fn garble_strings_runs_on_garble_binary_without_panic() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_GARBLE);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze garbled");
    let _ = analysis.garble.recovered_strings.len();
}

const THUNK_ORACLE_LITERALS: &[&str] = &[
    "permission denied",
    "ExpandEnvironmentStringsW",
    "machine is not on the network",
    "SetFileInformationByHandle",
    "os: process handle unavailable",
    "socket operation on non-socket",
    "io: read/write on closed pipe",
];

#[test]
fn garble_thunk_emulation_recovers_encrypted_literals() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_GARBLE);

    for needle in THUNK_ORACLE_LITERALS {
        let plaintext_present: bool = bytes
            .windows(needle.len())
            .any(|w: &[u8]| w == needle.as_bytes());
        assert!(
            !plaintext_present,
            "oracle is only non-circular if `{needle}` is absent as cleartext in the garble \
             -literals binary; found it in plain rodata, so the fixture is not actually encrypting it"
        );
    }

    let recovered: Vec<(String, u64, u64)> =
        probe_thunk_literals(&bytes).expect("thunk recovery must run on the garble fixture");
    let recovered_set: Vec<&str> = recovered
        .iter()
        .map(|(s, _, _): &(String, u64, u64)| s.as_str())
        .collect();

    for needle in THUNK_ORACLE_LITERALS {
        assert!(
            recovered_set.iter().any(|s: &&str| s.contains(needle)),
            "the init-thunk x86 emulator must decrypt `{needle}` (encrypted by garble -literals, \
             absent as cleartext) but it was not in the recovered set ({} literals)",
            recovered_set.len()
        );
    }
}

#[test]
fn garble_thunk_recovery_surfaces_in_report() {
    let bytes: Vec<u8> = common::fixture(common::HELLO_GARBLE);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze garbled");
    assert!(
        analysis.garble.literal_recovery.garble_thunk >= 5,
        "thunk-emulated literal recoveries must be counted in the garble report; got {}",
        analysis.garble.literal_recovery.garble_thunk
    );
    let any_runtime_string: bool = analysis.garble.recovered_strings.iter().any(|s: &String| {
        s.contains("permission denied") || s.contains("ExpandEnvironmentStringsW")
    });
    assert!(
        any_runtime_string,
        "thunk-decrypted literals must be merged into the report's recovered_strings"
    );
}

const INDIRECT_LITERALS: &[&str] = &[
    "the quick brown fox jumps over the lazy dog by the riverbank twice",
    "failed to connect to the upstream server: invalid session token given",
    "https://telemetry.example.invalid/v2/collect/beacon/report/endpoint",
    "permission was denied while opening the configuration registry hive",
    "the secret key material has been rotated so the cache must be cleared",
    "C:\\Windows\\System32\\drivers\\etc\\hosts could not be opened to write",
    "the rate limiter rejected the inbound request from this remote client",
    "a fatal panic occurred inside the message dispatch goroutine handler!",
];

#[test]
fn garble_literals_indirect_decrypt_recovered_exactly() {
    let bytes: Vec<u8> = common::fixture(common::GARBLE_LITERALS_INDIRECT);

    for needle in INDIRECT_LITERALS {
        let present: bool = bytes
            .windows(needle.len())
            .any(|w: &[u8]| w == needle.as_bytes());
        assert!(
            !present,
            "the recovery oracle is only non-circular if `{needle}` is absent as cleartext; \
             garble -literals must have encrypted it but a plain copy is in the binary"
        );
    }

    let recovered: Vec<(String, u64, u64)> =
        probe_thunk_literals(&bytes).expect("thunk recovery must run on the indirect fixture");
    let joined: Vec<&str> = recovered
        .iter()
        .map(|(s, _, _): &(String, u64, u64)| s.as_str())
        .collect();

    for needle in INDIRECT_LITERALS {
        assert!(
            joined.iter().any(|s: &&str| s.contains(needle)),
            "static recovery of garble's indirect/late-init obfuscators (seed recursive \
             decFunc chain, split jump-table, proxy-dispatcher hidden keys and cast) must yield \
             `{needle}` byte-exact, but it was absent from the {} recovered literals",
            joined.len()
        );
    }
}

#[test]
fn garble_literals_indirect_surfaces_in_report() {
    let bytes: Vec<u8> = common::fixture(common::GARBLE_LITERALS_INDIRECT);
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze indirect fixture");
    let hits: usize = INDIRECT_LITERALS
        .iter()
        .filter(|needle: &&&str| {
            analysis
                .garble
                .recovered_strings
                .iter()
                .any(|s: &String| s.contains(*needle))
        })
        .count();
    assert_eq!(
        hits,
        INDIRECT_LITERALS.len(),
        "every indirect/late-init garble literal must reach the merged report; got {hits} of {}",
        INDIRECT_LITERALS.len()
    );
}
