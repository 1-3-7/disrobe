#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

#[path = "support/dyld_cache_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod dyld_cache_fixture;

use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_swift_objc::dyld_cache::subcache::CacheFamily;
use disrobe_pass_swift_objc::dyld_cache::{
    self, DyldSharedCache, ReconstructBatch, ReconstructOptions,
};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

use dyld_cache_fixture::{BuiltCache, CacheSpec};
use macho_corpus::{SWIFT_HELLO_ORIGINAL, read_tracked};

const INSTALL_NAME: &str = "/usr/lib/libSwiftHello.dylib";

fn disrobe_cli() -> PathBuf {
    let cli: PathBuf = std::env::var_os("DISROBE_BIN").map(PathBuf::from).expect(
        "DISROBE_BIN is not set; build the CLI with `cargo build -p disrobe-cli --bin disrobe` \
         and point DISROBE_BIN at it, because this test grades the user-facing dyldcache command",
    );
    assert!(
        cli.is_file(),
        "DISROBE_BIN names {}, which is not a file",
        cli.display()
    );
    cli
}

fn write_family(dir: &Path, cache: &BuiltCache) -> PathBuf {
    let primary: PathBuf = dir.join("dyld_shared_cache_arm64e");
    std::fs::write(&primary, &cache.primary).expect("write the primary cache");
    if let Some(sibling) = cache.sibling.as_ref() {
        std::fs::write(dir.join("dyld_shared_cache_arm64e.1"), sibling)
            .expect("write the sibling cache");
    }
    if let Some(symbols) = cache.symbols.as_ref() {
        std::fs::write(dir.join("dyld_shared_cache_arm64e.symbols"), symbols)
            .expect("write the symbols cache");
    }
    primary
}

fn extract(primary: &Path, out: &Path, images: &[&str]) -> ToolOutput {
    let mut spec: CommandSpec = CommandSpec::new(disrobe_cli(), Duration::from_mins(2))
        .args(["macho", "dyldcache"])
        .arg(primary)
        .arg("--out")
        .arg(out);
    for image in images {
        spec = spec.arg("--image").arg(*image);
    }
    tool_output(spec).expect("start the disrobe CLI")
}

fn split_family(dir: &Path, spec: &CacheSpec) -> PathBuf {
    let image: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let cache: BuiltCache = dyld_cache_fixture::build(&image, spec);
    write_family(dir, &cache)
}

#[test]
fn a_split_cache_extracted_through_the_cli_matches_the_library_family_output() {
    let dir: ScratchDir = ScratchDir::create("dr-dyld-cli-split").expect("scratch directory");
    let primary: PathBuf = split_family(dir.path(), &CacheSpec::modern(INSTALL_NAME).split());
    let out: PathBuf = dir.path().join("out");

    let run: ToolOutput = extract(&primary, &out, &[]);

    assert!(
        run.success,
        "the split cache must extract: {}\n{}",
        run.stdout_text(),
        run.stderr_text()
    );
    assert!(
        run.stdout_text().contains("dyld shared cache: OK"),
        "{}",
        run.stdout_text()
    );
    let (family, parsed): (CacheFamily, DyldSharedCache) =
        dyld_cache::open_family(&primary).expect("the family opens");
    let batch: ReconstructBatch =
        dyld_cache::reconstruct_family(&family, &parsed, ReconstructOptions::COMPACT, None)
            .expect("the family reconstructs");
    assert_eq!(batch.dylibs.len(), 1);
    let written: Vec<u8> = std::fs::read(out.join("usr").join("lib").join("libSwiftHello.dylib"))
        .expect("the CLI writes the image under its install name");
    assert!(
        written == batch.dylibs[0].bytes,
        "the CLI output must equal the library's family reconstruction byte for byte"
    );
}

#[test]
fn an_image_the_cache_does_not_hold_is_refused_by_name() {
    let dir: ScratchDir = ScratchDir::create("dr-dyld-cli-absent").expect("scratch directory");
    let primary: PathBuf = split_family(dir.path(), &CacheSpec::modern(INSTALL_NAME));
    let out: PathBuf = dir.path().join("out");

    let run: ToolOutput = extract(&primary, &out, &[INSTALL_NAME, "/usr/lib/libAbsent.dylib"]);

    assert!(!run.success, "an absent image must fail the command");
    assert!(
        run.stderr_text().contains("DR-CLI-0502")
            && run.stderr_text().contains("/usr/lib/libAbsent.dylib")
            && !run.stderr_text().contains(INSTALL_NAME),
        "the refusal must name only the absent image: {}",
        run.stderr_text()
    );
}

#[test]
fn a_named_image_is_the_only_one_extracted() {
    let dir: ScratchDir = ScratchDir::create("dr-dyld-cli-named").expect("scratch directory");
    let primary: PathBuf = split_family(dir.path(), &CacheSpec::modern(INSTALL_NAME));
    let out: PathBuf = dir.path().join("out");

    let run: ToolOutput = extract(&primary, &out, &[INSTALL_NAME]);

    assert!(run.success, "{}", run.stderr_text());
    assert!(
        run.stdout_text()
            .contains("recovered:  1 standalone dylib(s)"),
        "{}",
        run.stdout_text()
    );
}

#[test]
fn an_image_that_cannot_be_rebuilt_is_reported_by_install_name() {
    let dir: ScratchDir = ScratchDir::create("dr-dyld-cli-partial").expect("scratch directory");
    let primary: PathBuf = split_family(
        dir.path(),
        &CacheSpec::modern(INSTALL_NAME)
            .split()
            .without_sibling_file(),
    );
    let out: PathBuf = dir.path().join("out");

    let run: ToolOutput = extract(&primary, &out, &[]);

    let stdout: String = run.stdout_text();
    assert!(run.success, "{}", run.stderr_text());
    assert!(stdout.contains("dyld shared cache: partial"), "{stdout}");
    assert!(
        stdout.contains(&format!("unresolved: {INSTALL_NAME} at 0x"))
            && stdout.contains("__LINKEDIT"),
        "the unresolved image must be printed with its reason: {stdout}"
    );
    assert!(
        stdout.contains("dyld_shared_cache_arm64e.1"),
        "the missing subcache must be named: {stdout}"
    );
}
