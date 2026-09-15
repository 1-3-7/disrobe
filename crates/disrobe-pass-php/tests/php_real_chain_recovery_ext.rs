#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unreachable_pub,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]

#[path = "support/php_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod php_toolchain;

use std::collections::BTreeSet;

use disrobe_pass_php::{DEFAULT_LOADER_DEPTH, LoaderReport, LoaderSink, peel_modern_loader};
use php_toolchain::{
    PhpRuntime, require_php, required_fixture, residual_decode_primitives, with_open_tag,
};

const GRADED: &str = "the loader-level peel of the php eval-chain corpus, each recovered body \
                      re-executed under the real php interpreter";

#[derive(Debug, Clone, Copy)]
struct PinnedLoader {
    fixture: &'static str,
    sink: LoaderSink,
    bound_variables: usize,
    trailing_newline: bool,
}

const PINNED_LOADERS: [PinnedLoader; 13] = [
    PinnedLoader {
        fixture: "c_octal_loader.php",
        sink: LoaderSink::Eval,
        bound_variables: 1,
        trailing_newline: true,
    },
    PinnedLoader {
        fixture: "h_hexname.php",
        sink: LoaderSink::Eval,
        bound_variables: 2,
        trailing_newline: true,
    },
    PinnedLoader {
        fixture: "p_decoy.php",
        sink: LoaderSink::Eval,
        bound_variables: 3,
        trailing_newline: true,
    },
    PinnedLoader {
        fixture: "p_globals.php",
        sink: LoaderSink::Eval,
        bound_variables: 1,
        trailing_newline: true,
    },
    PinnedLoader {
        fixture: "p_preg.php",
        sink: LoaderSink::PregReplaceEval,
        bound_variables: 1,
        trailing_newline: true,
    },
    PinnedLoader {
        fixture: "p_preg2.php",
        sink: LoaderSink::PregReplaceEval,
        bound_variables: 0,
        trailing_newline: true,
    },
    PinnedLoader {
        fixture: "x_arith_fname.php",
        sink: LoaderSink::Eval,
        bound_variables: 1,
        trailing_newline: false,
    },
    PinnedLoader {
        fixture: "x_concat_fname.php",
        sink: LoaderSink::Eval,
        bound_variables: 4,
        trailing_newline: false,
    },
    PinnedLoader {
        fixture: "x_createfunc.php",
        sink: LoaderSink::CreateFunction,
        bound_variables: 3,
        trailing_newline: false,
    },
    PinnedLoader {
        fixture: "x_globals_chain.php",
        sink: LoaderSink::Eval,
        bound_variables: 2,
        trailing_newline: false,
    },
    PinnedLoader {
        fixture: "x_globals_curly.php",
        sink: LoaderSink::Eval,
        bound_variables: 2,
        trailing_newline: false,
    },
    PinnedLoader {
        fixture: "x_implode_array.php",
        sink: LoaderSink::Eval,
        bound_variables: 2,
        trailing_newline: false,
    },
    PinnedLoader {
        fixture: "x_substr_fname.php",
        sink: LoaderSink::Eval,
        bound_variables: 1,
        trailing_newline: false,
    },
];

const NO_LOADER: [&str; 11] = [
    "c_octal_inline.php",
    "clean_control.php",
    "h_htmlwrap.php",
    "h_packhex.php",
    "p_deep5.php",
    "r_gotochain.php",
    "runtime_key.php",
    "s_doubleb64.php",
    "x_double_gz_b64.php",
    "x_hex2bin.php",
    "x_strrev_rot13_gz.php",
];

fn expected_body(trailing_newline: bool) -> Vec<u8> {
    let expected: Vec<u8> = required_fixture("php_real_chains/EXPECTED.txt");
    if trailing_newline {
        return expected;
    }
    let mut end: usize = expected.len();
    while end > 0 && matches!(expected[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    expected[..end].to_vec()
}

#[test]
fn the_loader_pins_cover_every_chain_fixture_exactly_once() {
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for pinned in &PINNED_LOADERS {
        assert!(
            seen.insert(pinned.fixture),
            "{} is pinned twice, so one row grades nothing",
            pinned.fixture
        );
    }
    for fixture in NO_LOADER {
        assert!(
            seen.insert(fixture),
            "{fixture} is pinned both as a loader and as a file with no loader"
        );
    }
    assert_eq!(
        seen.len(),
        PINNED_LOADERS.len() + NO_LOADER.len(),
        "the two pinned sets must partition the corpus"
    );
    assert_eq!(
        seen.len(),
        24,
        "the chain corpus holds 24 php files and every one must be pinned here as either a \
         recognized loader or a file the loader path declines, so a fixture cannot be added and \
         left ungraded at this level"
    );
}

#[test]
fn every_recognized_loader_reports_its_sink_and_recovers_the_original_body() {
    let Some(php): Option<PhpRuntime> = require_php(GRADED) else {
        return;
    };
    let truth: Vec<u8> = required_fixture("php_real_chains/EXPECTED.txt");
    let expected_stdout: Vec<u8> = php.stdout_of(
        "EXPECTED.txt",
        with_open_tag(&String::from_utf8_lossy(&truth)).as_bytes(),
    );
    assert!(
        !expected_stdout.is_empty(),
        "the ground-truth program prints nothing, so stdout comparison would accept a silent \
         recovery"
    );

    let mut defects: Vec<String> = Vec::new();
    let mut graded: usize = 0;
    for pinned in &PINNED_LOADERS {
        let bytes: Vec<u8> = required_fixture(&format!("php_real_chains/{}", pinned.fixture));
        let Some(report): Option<LoaderReport> = peel_modern_loader(&bytes, DEFAULT_LOADER_DEPTH)
        else {
            defects.push(format!(
                "{}: the loader path no longer recognizes this file, so a family that used to be \
                 peeled at the loader level is now unmeasured here",
                pinned.fixture
            ));
            graded += 1;
            continue;
        };
        if report.sink != pinned.sink {
            defects.push(format!(
                "{}: pinned to report the {:?} sink, reported {:?}",
                pinned.fixture, pinned.sink, report.sink
            ));
        }
        if report.bound_variable_count != pinned.bound_variables {
            defects.push(format!(
                "{}: pinned to resolve {} bound variables, resolved {}",
                pinned.fixture, pinned.bound_variables, report.bound_variable_count
            ));
        }
        let want: Vec<u8> = expected_body(pinned.trailing_newline);
        if report.recovered != want {
            defects.push(format!(
                "{}: the loader body must equal EXPECTED.txt byte for byte.\n--- expected ---\n{}\n\
                 --- recovered ---\n{}",
                pinned.fixture,
                String::from_utf8_lossy(&want),
                String::from_utf8_lossy(&report.recovered)
            ));
        }
        let recovered_text: String = String::from_utf8_lossy(&report.recovered).into_owned();
        let residual: Vec<&'static str> = residual_decode_primitives(&recovered_text);
        if !residual.is_empty() {
            defects.push(format!(
                "{}: the loader body still calls {residual:?}, so it is a peeled layer rather than \
                 the recovered program",
                pinned.fixture
            ));
        }
        let stdout: Vec<u8> =
            php.stdout_of(pinned.fixture, with_open_tag(&recovered_text).as_bytes());
        if stdout != expected_stdout {
            defects.push(format!(
                "{}: the loader body runs under php but prints {:?} where the original prints {:?}",
                pinned.fixture,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&expected_stdout)
            ));
        }
        graded += 1;
    }
    assert_eq!(
        graded,
        PINNED_LOADERS.len(),
        "every pinned loader must be measured, not skipped"
    );
    assert!(
        defects.is_empty(),
        "{} pinned loader grades failed across {graded} fixtures:\n\n{}",
        defects.len(),
        defects.join("\n\n")
    );
    println!("{graded} loader-level peels graded against {}", php.banner);
}

#[test]
fn the_files_with_no_recognized_loader_are_declined_rather_than_guessed() {
    let mut defects: Vec<String> = Vec::new();
    for fixture in NO_LOADER {
        let bytes: Vec<u8> = required_fixture(&format!("php_real_chains/{fixture}"));
        if let Some(report) = peel_modern_loader(&bytes, DEFAULT_LOADER_DEPTH) {
            defects.push(format!(
                "{fixture}: the loader path is pinned to decline this file, because its chain is \
                 peeled by the layer walker rather than the loader evaluator; it now claims the \
                 {:?} sink and hands back {} bytes. Either the loader genuinely gained this family, \
                 in which case move it into the pinned set with its expected body, or it is \
                 guessing.",
                report.sink,
                report.recovered.len()
            ));
        }
    }
    assert!(
        defects.is_empty(),
        "{} files changed loader classification:\n\n{}",
        defects.len(),
        defects.join("\n\n")
    );
}
