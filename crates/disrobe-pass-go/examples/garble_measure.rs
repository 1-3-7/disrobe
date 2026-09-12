use std::path::PathBuf;
use std::process::ExitCode;

use disrobe_pass_go::{GarbleQuality, GoAnalysis, analyze};

const USER_STRINGS_IN_SOURCE: &[&str] = &[
    "failed to open the configuration registry hive",
    "connection to the upstream server timed out",
    "authentication token has expired and must be renewed",
    "unexpected response from the remote endpoint address",
    "the rate limiter rejected this inbound request",
    "endpoint must not be empty",
];

fn corpus(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("go");
    p.push("garble");
    p.push(name);
    p
}

fn fixture(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

fn report_fixture(name: &str) {
    let p: PathBuf = fixture(name);
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&p) else {
        println!("{name}: MISSING at {}", p.display());
        return;
    };
    let Ok(a): Result<GoAnalysis, _> = analyze(&bytes) else {
        println!("{name}: ERR");
        return;
    };
    let lr: disrobe_pass_go::LiteralRecoveryStats = a.garble.literal_recovery;
    let s: disrobe_pass_go::NameRecoveryStats = a.garble.name_recovery;
    #[allow(clippy::cast_precision_loss)]
    let stdlib_ratio: f64 = s.stdlib_recovered as f64 / s.total_funcs.max(1) as f64;
    println!(
        "==== {name} (fixture) ====\n  quality={:?} residual={:?} score={} | stdlib={:.1}% hashed_erased={} | thunk={} simple={} xor={} rep={}",
        a.garble.quality,
        a.garble.residual,
        a.garble.detection_score,
        stdlib_ratio * 100.0,
        s.user_hashed_erased,
        lr.garble_thunk,
        lr.garble_simple,
        lr.single_xor,
        lr.repeating_xor
    );
}

fn report(name: &str, check_literals: bool) {
    let p: PathBuf = corpus(name);
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&p) else {
        println!("{name}: MISSING at {}", p.display());
        return;
    };
    let a: GoAnalysis = match analyze(&bytes) {
        Ok(a) => a,
        Err(e) => {
            println!("{name}: ERR {e}");
            return;
        }
    };
    let q: GarbleQuality = a.garble.quality;
    let s: disrobe_pass_go::NameRecoveryStats = a.garble.name_recovery;
    #[allow(clippy::cast_precision_loss)]
    let stdlib_ratio: f64 = s.stdlib_recovered as f64 / s.total_funcs.max(1) as f64;
    #[allow(clippy::cast_precision_loss)]
    let recoverable: f64 =
        (s.stdlib_recovered + s.user_readable_surviving) as f64 / s.total_funcs.max(1) as f64;
    println!("==== {name} ====");
    println!(
        "  quality={q:?} residual={:?} score={} seed_recoverable={} fingerprints={}",
        a.garble.residual,
        a.garble.detection_score,
        a.garble.seed_recoverable,
        a.garble.stdlib_fingerprints_present
    );
    println!(
        "  names: total={} stdlib={} ({:.1}%) hashed_erased={} user_surviving={} recoverable={:.1}%",
        s.total_funcs,
        s.stdlib_recovered,
        stdlib_ratio * 100.0,
        s.user_hashed_erased,
        s.user_readable_surviving,
        recoverable * 100.0
    );
    let lr: disrobe_pass_go::LiteralRecoveryStats = a.garble.literal_recovery;
    println!(
        "  literals: plain={} thunk={} simple={} xor={} add={} sub={} rep={} total_recovered_strings={}",
        lr.plain_ascii,
        lr.garble_thunk,
        lr.garble_simple,
        lr.single_xor,
        lr.single_add,
        lr.single_sub,
        lr.repeating_xor,
        a.garble.recovered_strings.len()
    );
    if check_literals {
        let recovered: &[String] = &a.garble.recovered_strings;
        let mut exact: usize = 0;
        let mut contained: usize = 0;
        for needle in USER_STRINGS_IN_SOURCE {
            let is_exact: bool = recovered.iter().any(|s: &String| s.as_str() == *needle);
            let is_contained: bool = recovered.iter().any(|s: &String| s.contains(needle));
            if is_exact {
                exact += 1;
            }
            if is_contained {
                contained += 1;
            }
            let tag: &str = if is_exact {
                "EXACT"
            } else if is_contained {
                "contained"
            } else {
                "MISSING"
            };
            println!("    needle [{tag}] {needle:?}");
        }
        println!(
            "  literal recovery: {exact}/{} exact, {contained}/{} contained",
            USER_STRINGS_IN_SOURCE.len(),
            USER_STRINGS_IN_SOURCE.len()
        );
    }
}

fn main() -> ExitCode {
    report("gauntlet_garble.exe", false);
    report("gauntlet_garble_lit.exe", true);
    report_fixture("hello_normal.exe");
    report_fixture("hello_stripped.exe");
    report_fixture("hello_garble.exe");
    ExitCode::SUCCESS
}
