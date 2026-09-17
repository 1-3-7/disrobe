#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::pedantic,
    clippy::nursery
)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_scriptlang::lang::tcl::{StarkitContainer, StarkitEntry, StarkitFormat, extract};

#[path = "support/r_toolchain.rs"]
#[allow(
    dead_code,
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod r_toolchain;

use r_toolchain::{TclRuntime, require_tclsh, run_bounded};

const SDX_KIT: &[u8] = include_bytes!("fixtures/sdx.kit");

const DECLARED_MEMBERS: usize = 64;
const DECLARED_BYTES: usize = 400_100;
const STORED_RAW: usize = 8;
const STORED_DEFLATE: usize = 56;
const TCL_MEMBERS: usize = 59;
const PACKAGE_INDEX_MEMBERS: usize = 13;
const GIF_MEMBERS: usize = 3;
const GRADED: &str = "the recovered starkit Tcl sources parsed by real tclsh";

fn sdx() -> StarkitContainer {
    let container: StarkitContainer = extract(SDX_KIT).expect("extract sdx.kit");
    assert_eq!(container.format, StarkitFormat::Metakit);
    container
}

fn find_at(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let head: usize = needle.len().min(16);
    let last: usize = haystack.len() - needle.len();
    (0..=last).any(|start: usize| {
        haystack[start..start + head] == needle[..head]
            && &haystack[start..start + needle.len()] == needle
    })
}

fn inflates_from_container(container: &[u8], expected: &[u8]) -> bool {
    let ceiling: u64 = expected.len() as u64 + 1;
    (0..container.len().saturating_sub(2)).any(|start: usize| {
        if container[start] != 0x78 {
            return false;
        }
        let mut plain: Vec<u8> = Vec::with_capacity(expected.len());
        let mut reader: std::io::Take<flate2::read::ZlibDecoder<&[u8]>> =
            flate2::read::ZlibDecoder::new(&container[start..]).take(ceiling);
        reader.read_to_end(&mut plain).is_ok() && plain == expected
    })
}

#[test]
fn every_metakit_member_of_the_real_sdx_starkit_is_recovered_with_its_bytes() {
    let container: StarkitContainer = sdx();
    let recovered: usize = container.completeness.recovered_with_contents;
    let declared: usize = container.completeness.declared_entries;
    println!("metakit member recovery: {recovered}/{declared} members carry their bytes");
    assert_eq!(
        declared, DECLARED_MEMBERS,
        "the sdx.kit directory lists {DECLARED_MEMBERS} members"
    );
    assert_eq!(
        recovered, DECLARED_MEMBERS,
        "every listed member must come back with its bytes"
    );
    assert!((container.completeness.ratio() - 1.0).abs() < f64::EPSILON);
    let bytes: usize = container
        .entries
        .iter()
        .map(|entry: &StarkitEntry| entry.contents.len())
        .sum();
    println!("metakit byte recovery: {bytes} bytes across {declared} members");
    assert_eq!(bytes, DECLARED_BYTES);
}

#[test]
fn recovered_metakit_paths_carry_the_directory_tree_the_kit_declares() {
    let container: StarkitContainer = sdx();
    let paths: Vec<&str> = container
        .entries
        .iter()
        .map(|entry: &StarkitEntry| entry.path.as_str())
        .collect();
    for expected in [
        "main.tcl",
        "doc/sdx.tkd",
        "lib/app-sdx/sdx.tcl",
        "lib/app-sdx/wrap.tcl",
        "lib/base64/base64.tcl",
        "lib/ftp/ftp_lib.tcl",
        "lib/gbutton/up.gif",
        "lib/wikit/format.tcl",
    ] {
        assert!(
            paths.contains(&expected),
            "member '{expected}' must be recovered under its real directory; got {paths:?}"
        );
    }
    assert!(
        paths.windows(2).all(|pair: &[&str]| pair[0] <= pair[1]),
        "members must be emitted in a deterministic path order"
    );
    assert_eq!(
        container.tcl_source_files.len(),
        TCL_MEMBERS,
        "sdx.kit ships {TCL_MEMBERS} .tcl members"
    );
}

#[test]
fn every_recovered_member_is_present_in_the_container_verbatim_or_as_an_inflatable_stream() {
    let container: StarkitContainer = sdx();
    let mut raw: usize = 0usize;
    let mut deflate: usize = 0usize;
    for entry in &container.entries {
        if find_at(SDX_KIT, &entry.contents) {
            raw += 1usize;
            continue;
        }
        assert!(
            inflates_from_container(SDX_KIT, &entry.contents),
            "'{path}' ({len} bytes) is neither stored verbatim in sdx.kit nor the inflate of any \
             deflate stream it holds, so those bytes did not come out of this container",
            path = entry.path,
            len = entry.contents.len()
        );
        deflate += 1usize;
    }
    println!(
        "member provenance: {raw}/{total} stored verbatim, {deflate}/{total} recovered by \
         inflating a stream the container holds",
        total = container.entries.len()
    );
    assert_eq!(raw, STORED_RAW);
    assert_eq!(deflate, STORED_DEFLATE);
    assert_eq!(raw + deflate, DECLARED_MEMBERS);
}

#[test]
fn recovered_member_bytes_match_the_member_names_they_were_filed_under() {
    let container: StarkitContainer = sdx();
    let mut indexes: usize = 0usize;
    let mut images: usize = 0usize;
    for entry in &container.entries {
        if entry.path.ends_with("pkgIndex.tcl") {
            let text: &str = std::str::from_utf8(&entry.contents)
                .unwrap_or_else(|_| panic!("'{}' must be text", entry.path));
            assert!(
                text.contains("package ifneeded"),
                "a Tcl package index must register a package: '{}' holds {:?}",
                entry.path,
                text.chars().take(60).collect::<String>()
            );
            indexes += 1usize;
        }
        if entry.path.ends_with(".gif") {
            assert!(
                entry.contents.starts_with(b"GIF87a") || entry.contents.starts_with(b"GIF89a"),
                "'{}' must start with a GIF signature, got {:?}",
                entry.path,
                &entry.contents[..entry.contents.len().min(6)]
            );
            images += 1usize;
        }
    }
    println!("name-to-content binding: {indexes} package indexes and {images} images checked");
    assert_eq!(indexes, PACKAGE_INDEX_MEMBERS);
    assert_eq!(images, GIF_MEMBERS);
    let main: &StarkitEntry = container
        .entries
        .iter()
        .find(|entry: &&StarkitEntry| entry.path == "main.tcl")
        .expect("main.tcl");
    assert!(
        main.contents.starts_with(b"package require starkit"),
        "a starkit entry point opens by requiring the starkit package"
    );
}

#[test]
fn recovered_starkit_sources_are_complete_scripts_to_real_tclsh() {
    let scratch: ScratchDir = ScratchDir::create("scriptlang-metakit-tcl").expect("scratch");
    let Some(runtime): Option<TclRuntime> = require_tclsh(GRADED, scratch.path()) else {
        return;
    };
    let container: StarkitContainer = sdx();
    let mut sources: Vec<(String, PathBuf)> = Vec::new();
    for entry in &container.entries {
        if !entry.path.ends_with(".tcl") {
            continue;
        }
        let file: PathBuf = scratch
            .path()
            .join(format!("member{:03}.tcl", sources.len()));
        std::fs::write(&file, &entry.contents).expect("write member");
        sources.push((entry.path.clone(), file));
    }
    assert_eq!(sources.len(), TCL_MEMBERS);

    let driver: PathBuf = scratch.path().join("grade.tcl");
    std::fs::write(
        &driver,
        b"foreach path [lrange $argv 0 end] {\n  set fd [open $path rb]\n  set data [read $fd]\n  \
          close $fd\n  if {[info complete $data]} {\n    puts \"complete $path\"\n  } else {\n    \
          puts \"incomplete $path\"\n  }\n}\n",
    )
    .expect("write driver");

    let mut cmd: Command = Command::new(&runtime.tclsh);
    cmd.arg(&driver);
    for (_, file) in &sources {
        cmd.arg(file);
    }
    let (ok, out, err): (bool, String, String) =
        run_bounded(cmd).expect("tclsh answers within the bound");
    assert!(ok, "tclsh failed: stdout {out:?} stderr {err:?}");
    let complete: usize = out
        .lines()
        .filter(|l: &&str| l.starts_with("complete "))
        .count();
    let incomplete: Vec<&str> = out
        .lines()
        .filter(|l: &&str| l.starts_with("incomplete "))
        .collect();
    println!(
        "tcl {patchlevel} parse grade: {complete}/{total} recovered .tcl members are complete \
         scripts",
        patchlevel = runtime.patchlevel,
        total = sources.len()
    );
    assert!(
        incomplete.is_empty(),
        "tclsh reports these recovered members are not complete scripts: {incomplete:?}"
    );
    assert_eq!(complete, sources.len());
    scratch.close().expect("scratch cleanup");
}

#[test]
fn a_truncated_metakit_container_declines_the_payload_instead_of_guessing() {
    let head: &[u8] = &SDX_KIT[..SDX_KIT.len() / 2];
    let container: StarkitContainer = extract(head).expect("a truncated kit still lists filenames");
    assert_eq!(container.format, StarkitFormat::Metakit);
    assert_eq!(
        container.completeness.recovered_with_contents, 0,
        "a container whose commit mark is gone must report zero recovered payloads"
    );
    assert!(
        !container.entries.is_empty(),
        "the filename listing survives a truncated tail"
    );
}

#[test]
fn a_corrupted_commit_mark_never_panics_and_never_invents_contents() {
    for flip in [1usize, 4usize, 8usize, 12usize, 16usize] {
        let mut damaged: Vec<u8> = SDX_KIT.to_vec();
        let at: usize = damaged.len() - flip;
        damaged[at] ^= 0xffu8;
        let container: StarkitContainer = extract(&damaged).expect("damaged kit still classifies");
        assert!(
            container.completeness.recovered_with_contents
                <= container.completeness.declared_entries
        );
        for entry in &container.entries {
            assert_eq!(entry.size, entry.contents.len());
        }
    }
}

#[test]
fn a_directory_whose_parent_chain_loops_is_refused() {
    let mut looped: Vec<u8> = SDX_KIT.to_vec();
    let parents_at: usize = 256usize + 242usize;
    looped[parents_at] = 3u8;
    looped[parents_at + 3usize] = 0u8;
    let container: StarkitContainer = extract(&looped).expect("classification is unchanged");
    assert_eq!(container.format, StarkitFormat::Metakit);
    assert_eq!(
        container.completeness.recovered_with_contents, 0,
        "a cyclic directory tree must decline the whole payload rather than emit a partial tree"
    );
}

#[test]
fn the_scratch_helper_reports_a_real_interpreter_or_declines() {
    let scratch: ScratchDir = ScratchDir::create("scriptlang-metakit-probe").expect("scratch");
    if let Some(runtime) = require_tclsh(GRADED, scratch.path()) {
        assert!(Path::new(&runtime.tclsh).is_file());
        assert!(runtime.patchlevel.starts_with('8') || runtime.patchlevel.starts_with('9'));
    }
    scratch.close().expect("scratch cleanup");
}
