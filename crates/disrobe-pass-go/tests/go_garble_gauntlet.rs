#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_go::{GarbleQuality, GoAnalysis, GoFunc, analyze};

const GAUNTLET_SOURCE: &str = r#"package main

import (
	"fmt"
	"os"
)

var sink int

//go:noinline
func emit(s string) { sink += len(s) }

func main() {
	emit("the configuration registry hive could not be opened for writing")
	emit("authentication token has expired and must be renewed by the client")
	emit("connection to the upstream server timed out after the deadline passed")
	emit("the rate limiter rejected this inbound request from the remote client")
	emit("unexpected response received from the remote endpoint network address")
	emit("the secret key material was rotated so the local cache must be flushed")
	fmt.Fprintln(os.Stdout, sink)
	os.Exit(sink & 0)
}
"#;

const USER_STRINGS_IN_SOURCE: &[&str] = &[
    "the configuration registry hive could not be opened for writing",
    "authentication token has expired and must be renewed by the client",
    "connection to the upstream server timed out after the deadline passed",
    "the rate limiter rejected this inbound request from the remote client",
    "unexpected response received from the remote endpoint network address",
    "the secret key material was rotated so the local cache must be flushed",
];

const USER_FUNC_HASHED_BY_GARBLE: &[&str] = &["main.emit"];
const ENTRYPOINT_ALWAYS_PRESENT: &str = "main.main";

fn recovered_func_names(analysis: &GoAnalysis) -> BTreeSet<String> {
    analysis
        .symbols
        .funcs
        .iter()
        .map(|f: &GoFunc| f.name.clone())
        .collect()
}

fn garble_preserved_stdlib(names: &BTreeSet<String>) -> BTreeSet<String> {
    names
        .iter()
        .filter(|n: &&String| n.starts_with("runtime.") || n.starts_with("internal/"))
        .cloned()
        .collect()
}

fn garble_hashed_stdlib(names: &BTreeSet<String>) -> BTreeSet<String> {
    names
        .iter()
        .filter(|n: &&String| {
            !n.starts_with("main.")
                && !n.starts_with("type:")
                && !n.starts_with("go:")
                && !n.starts_with("runtime.")
                && !n.starts_with("internal/")
                && !n.contains(".init")
                && n.contains('.')
        })
        .cloned()
        .collect()
}

struct GauntletBuilds {
    clean_nm_all: BTreeSet<String>,
    garble_plain: GoAnalysis,
    garble_lit_bytes: Vec<u8>,
    garble_lit: GoAnalysis,
    _scratch: common::GoBuildScratch,
}

fn build_gauntlet() -> Option<GauntletBuilds> {
    if !common::require_go() || !common::require_garble() {
        return None;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("garble_gauntlet");
    common::write_module(&scratch, "disrobe.example/gauntlet", GAUNTLET_SOURCE);

    let clean: PathBuf = common::go_build(&scratch, "clean.exe", &[])?;
    let plain: PathBuf = common::garble_build(&scratch, "gplain.exe", &[])?;
    let lit: PathBuf = common::garble_build(&scratch, "glit.exe", &["-literals"])?;

    let clean_nm_all: BTreeSet<String> = common::nm_text_symbols(&clean)?;

    let plain_bytes: Vec<u8> = std::fs::read(&plain).expect("read gplain");
    let lit_bytes: Vec<u8> = std::fs::read(&lit).expect("read glit");
    let garble_plain: GoAnalysis = analyze(&plain_bytes).expect("analyze gplain");
    let garble_lit: GoAnalysis = analyze(&lit_bytes).expect("analyze glit");

    Some(GauntletBuilds {
        clean_nm_all,
        garble_plain,
        garble_lit_bytes: lit_bytes,
        garble_lit,
        _scratch: scratch,
    })
}

#[test]
fn gauntlet_garble_detection_fires_on_real_build() {
    let Some(b): Option<GauntletBuilds> = build_gauntlet() else {
        return;
    };
    assert!(
        !matches!(b.garble_plain.garble.quality, GarbleQuality::None),
        "garble detection must fire on a freshly garble-built binary; got {:?}",
        b.garble_plain.garble.quality
    );
    assert!(
        b.garble_plain.garble.detection_score >= 1,
        "detection score must be non-zero; got {}",
        b.garble_plain.garble.detection_score
    );
    assert!(
        !b.garble_plain.garble.seed_recoverable,
        "a seedless garble build embeds no seed"
    );
    assert!(
        b.garble_plain.garble.name_recovery_wall.is_some(),
        "a seedless garble build must document the keyed-hash name-recovery wall"
    );
}

#[test]
fn gauntlet_stdlib_recovery_matches_clean_build_nm_oracle() {
    let Some(b): Option<GauntletBuilds> = build_gauntlet() else {
        return;
    };
    let preserved: BTreeSet<String> = garble_preserved_stdlib(&b.clean_nm_all);
    assert!(
        preserved.len() > 500,
        "the clean build must expose hundreds of runtime/internal funcs via `go tool nm`; got {}",
        preserved.len()
    );

    let recovered: BTreeSet<String> = recovered_func_names(&b.garble_plain);
    let hit: usize = preserved
        .iter()
        .filter(|n: &&String| recovered.contains(*n))
        .count();
    let total: usize = preserved.len();
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = hit as f64 / total.max(1) as f64;
    assert!(
        ratio >= 0.85,
        "garble does not obfuscate the runtime/internal package identifiers, so their pclntab \
         funcnames survive; disrobe's recovery from the GARBLED binary must match >= 85% of the \
         independent clean-build `go tool nm` runtime/internal set: {hit}/{total} = {ratio:.4}"
    );

    assert!(
        b.garble_plain.symbols.funcs.len() > 500,
        "pclntab must surface hundreds of stdlib funcs even after garble; got {}",
        b.garble_plain.symbols.funcs.len()
    );
    assert!(
        b.garble_plain.garble.stdlib_fingerprints_present >= 5,
        "at least 5 canonical stdlib fingerprint symbols must survive garble; got {}",
        b.garble_plain.garble.stdlib_fingerprints_present
    );
}

#[test]
fn gauntlet_non_runtime_stdlib_packages_are_hashed_by_garble() {
    let Some(b): Option<GauntletBuilds> = build_gauntlet() else {
        return;
    };
    let hashed: BTreeSet<String> = garble_hashed_stdlib(&b.clean_nm_all);
    assert!(
        hashed.iter().any(|n: &String| n.starts_with("fmt.")),
        "sanity: the clean build must contain fmt.* symbols in nm; got {} hashed-pkg names",
        hashed.len()
    );

    let recovered: BTreeSet<String> = recovered_func_names(&b.garble_plain);
    let leaked: Vec<&String> = hashed
        .iter()
        .filter(|n: &&String| recovered.contains(*n))
        .collect();
    #[allow(clippy::cast_precision_loss)]
    let leak_ratio: f64 = leaked.len() as f64 / hashed.len().max(1) as f64;
    assert!(
        leak_ratio <= 0.05,
        "garble hashes the package path of non-runtime stdlib packages (fmt/os/errors/strconv), \
         so those clean names are part of the keyed-hash wall and must NOT be recoverable under \
         their original names; leaked {}/{} = {leak_ratio:.4}: {:?}",
        leaked.len(),
        hashed.len(),
        &leaked[..leaked.len().min(10)]
    );
}

#[test]
fn gauntlet_user_names_are_the_information_theoretic_wall() {
    let Some(b): Option<GauntletBuilds> = build_gauntlet() else {
        return;
    };

    for user in USER_FUNC_HASHED_BY_GARBLE {
        assert!(
            b.clean_nm_all.contains(*user),
            "sanity: the clean-build `go tool nm` oracle must carry the user symbol {user}"
        );
    }
    assert!(
        b.clean_nm_all.contains(ENTRYPOINT_ALWAYS_PRESENT),
        "sanity: the clean build must carry {ENTRYPOINT_ALWAYS_PRESENT}"
    );

    let recovered: BTreeSet<String> = recovered_func_names(&b.garble_plain);
    let surviving_user: Vec<&&str> = USER_FUNC_HASHED_BY_GARBLE
        .iter()
        .filter(|u: &&&str| recovered.contains(**u))
        .collect();
    assert!(
        surviving_user.is_empty(),
        "the original user package/symbol names are keyed-HMAC hashed by garble and cannot be \
         recovered from a seedless build (this is the genuine information-theoretic wall); \
         but these leaked through readable: {surviving_user:?}"
    );
    assert!(
        recovered.contains(ENTRYPOINT_ALWAYS_PRESENT),
        "the runtime looks up main.main by name, so garble cannot hash the entrypoint; it must \
         still be recovered from the garbled binary"
    );
    assert!(
        b.garble_plain.garble.name_recovery.user_hashed_erased >= 1,
        "at least one user function must show the garble name-hash pattern; got {}",
        b.garble_plain.garble.name_recovery.user_hashed_erased
    );
}

#[test]
fn gauntlet_literals_strings_are_encrypted_not_cleartext() {
    let Some(b): Option<GauntletBuilds> = build_gauntlet() else {
        return;
    };
    for needle in USER_STRINGS_IN_SOURCE {
        let plaintext_present: bool = b
            .garble_lit_bytes
            .windows(needle.len())
            .any(|w: &[u8]| w == needle.as_bytes());
        assert!(
            !plaintext_present,
            "the oracle is only non-circular if `{needle}` is absent as cleartext in the \
             garble -literals binary; found it in plain, so the fixture is not encrypting it"
        );
    }
}

#[test]
fn gauntlet_literals_strings_recovered_byte_exact_vs_source() {
    let Some(b): Option<GauntletBuilds> = build_gauntlet() else {
        return;
    };
    assert!(
        b.garble_lit.garble.literal_recovery.garble_thunk >= 1,
        "thunk emulation must fire on the -literals build; got garble_thunk={}",
        b.garble_lit.garble.literal_recovery.garble_thunk
    );

    let recovered: &[String] = &b.garble_lit.garble.recovered_strings;
    let exact: Vec<&&str> = USER_STRINGS_IN_SOURCE
        .iter()
        .filter(|needle: &&&str| recovered.iter().any(|s: &String| s.as_str() == **needle))
        .collect();
    let missing: Vec<&&str> = USER_STRINGS_IN_SOURCE
        .iter()
        .filter(|needle: &&&str| !recovered.iter().any(|s: &String| s.as_str() == **needle))
        .collect();
    assert_eq!(
        exact.len(),
        USER_STRINGS_IN_SOURCE.len(),
        "init-thunk emulation must recover every known-source literal byte-exact from the \
         garble -literals binary; recovered {}/{}: missing {missing:?}",
        exact.len(),
        USER_STRINGS_IN_SOURCE.len(),
    );
}

#[test]
fn gauntlet_literals_stdlib_recovery_holds_vs_clean_nm() {
    let Some(b): Option<GauntletBuilds> = build_gauntlet() else {
        return;
    };
    let preserved: BTreeSet<String> = garble_preserved_stdlib(&b.clean_nm_all);
    let recovered: BTreeSet<String> = recovered_func_names(&b.garble_lit);
    let hit: usize = preserved
        .iter()
        .filter(|n: &&String| recovered.contains(*n))
        .count();
    let total: usize = preserved.len();
    #[allow(clippy::cast_precision_loss)]
    let ratio: f64 = hit as f64 / total.max(1) as f64;
    assert!(
        ratio >= 0.80,
        "runtime/internal recovery from the harder -literals build must still match >= 80% of \
         the independent clean-build `go tool nm` runtime/internal set: {hit}/{total} = {ratio:.4}"
    );
}
