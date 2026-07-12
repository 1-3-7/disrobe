#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_go::{GoAnalysis, analyze};

const MODULE_PATH: &str = "github.com/acme.corp/tool";
const WORKER_PKG: &str = "github.com/acme.corp/tool/internal/worker";
const NETUTIL_PKG: &str = "github.com/acme.corp/tool/netutil";

const MAIN_GO: &str = "package main\n\
\n\
import (\n\
\t\"fmt\"\n\
\n\
\t\"github.com/acme.corp/tool/internal/worker\"\n\
\t\"github.com/acme.corp/tool/netutil\"\n\
)\n\
\n\
func main() {\n\
\tfmt.Println(worker.Run(3), netutil.Dial(\"x\"))\n\
}\n";

const WORKER_GO: &str = "package worker\n\
\n\
type Job struct{ N int }\n\
\n\
//go:noinline\n\
func (j *Job) Double() int { return j.N * 2 }\n\
\n\
//go:noinline\n\
func Run(n int) int {\n\
\tj := &Job{N: n}\n\
\treturn j.Double()\n\
}\n";

const NETUTIL_GO: &str = "package netutil\n\
\n\
type Conn struct{ Addr string }\n\
\n\
//go:noinline\n\
func (c Conn) String() string { return \"conn:\" + c.Addr }\n\
\n\
//go:noinline\n\
func Dial(addr string) string {\n\
\tc := Conn{Addr: addr}\n\
\treturn c.String()\n\
}\n";

struct BuiltPair {
    _scratch: common::GoBuildScratch,
    normal: GoAnalysis,
    stripped: GoAnalysis,
    normal_path: PathBuf,
}

fn build_pair() -> Option<BuiltPair> {
    let scratch: common::GoBuildScratch = common::new_scratch("pkgpath");
    common::write_module(&scratch, MODULE_PATH, MAIN_GO);
    common::write_file(&scratch, "internal/worker/worker.go", WORKER_GO);
    common::write_file(&scratch, "netutil/netutil.go", NETUTIL_GO);

    let normal: PathBuf = common::go_build(&scratch, "app_normal.exe", &[])?;
    let stripped: PathBuf = common::go_build(&scratch, "app_stripped.exe", &["-ldflags", "-s -w"])?;

    let normal_bytes: Vec<u8> = std::fs::read(&normal).expect("read normal build");
    let stripped_bytes: Vec<u8> = std::fs::read(&stripped).expect("read stripped build");
    let normal_analysis: GoAnalysis = analyze(&normal_bytes).expect("analyze normal");
    let stripped_analysis: GoAnalysis = analyze(&stripped_bytes).expect("analyze stripped");
    Some(BuiltPair {
        _scratch: scratch,
        normal: normal_analysis,
        stripped: stripped_analysis,
        normal_path: normal,
    })
}

#[test]
fn stripped_binary_recovers_dotted_import_paths_from_moduledata() {
    if !common::require_go() {
        return;
    }
    let Some(bp): Option<BuiltPair> = build_pair() else {
        panic!("go build failed");
    };

    assert!(
        bp.stripped.stripped.stripped,
        "the -s -w build must classify as stripped"
    );
    assert_eq!(
        bp.stripped.pclntab_version, "go1.20+",
        "go1.26 shares the 0xfffffff1 pclntab magic"
    );

    let pkgs: BTreeSet<String> = bp.stripped.symbols.package_set.iter().cloned().collect();

    assert!(
        pkgs.contains(WORKER_PKG),
        "the authored import path {WORKER_PKG} must survive the domain dot; got {:?}",
        bp.stripped.symbols.package_set
    );
    assert!(
        pkgs.contains(NETUTIL_PKG),
        "the authored import path {NETUTIL_PKG} must survive the domain dot; got {:?}",
        bp.stripped.symbols.package_set
    );
    assert!(
        !pkgs.contains("github"),
        "the first-dot split mangled github.com/... to `github`; the recovered set must not"
    );
    assert!(
        pkgs.iter().all(|p: &String| !p.contains(':')),
        "compiler pseudo-symbols (type:.eq., go:itab.) must never be reported as packages: {:?}",
        bp.stripped.symbols.package_set
    );

    let normal_pkgs: BTreeSet<String> = bp.normal.symbols.package_set.iter().cloned().collect();
    assert!(
        normal_pkgs.contains(WORKER_PKG) && normal_pkgs.contains(NETUTIL_PKG),
        "the unstripped build must recover the same dotted import paths; got {:?}",
        bp.normal.symbols.package_set
    );

    let nm: BTreeSet<String> =
        common::nm_text_symbols(&bp.normal_path).expect("go tool nm on normal build");
    for pkg in [WORKER_PKG, NETUTIL_PKG] {
        let prefix: String = format!("{pkg}.");
        assert!(
            nm.iter().any(|s: &String| s.starts_with(&prefix)),
            "go tool nm must confirm real text symbols under {pkg}; the ground truth is the linker \
             symbol table, not the recovery output"
        );
    }
}

#[test]
fn recovered_user_packages_exclude_assembly_and_pseudo_symbols() {
    if !common::require_go() {
        return;
    }
    let Some(bp): Option<BuiltPair> = build_pair() else {
        panic!("go build failed");
    };

    let user: &[String] = &bp.stripped.stripped.recovered_packages;
    assert!(
        user.iter().any(|p: &String| p == WORKER_PKG),
        "the user-package list must carry {WORKER_PKG}; got {user:?}"
    );
    assert!(
        user.iter().any(|p: &String| p == NETUTIL_PKG),
        "the user-package list must carry {NETUTIL_PKG}; got {user:?}"
    );

    let garbage: [&str; 5] = ["aeshashbody", "gogo", "github", "type:", "sigtramp"];
    for bad in garbage {
        assert!(
            !user.iter().any(|p: &String| p == bad),
            "assembly/marker symbol {bad} must not be classified as a user package; got {user:?}"
        );
    }

    assert!(
        bp.stripped.stripped.stdlib_ratio > 0.5,
        "most recovered functions are stdlib; ratio {:.3}",
        bp.stripped.stripped.stdlib_ratio
    );
}
