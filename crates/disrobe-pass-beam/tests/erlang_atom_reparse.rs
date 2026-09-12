#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_beam::body_lift::render::render_atom;

mod common;

use common::erlang_toolchain::{Erlang, require_erlang};

const GRADED: &str = "the emitted-atom reparse check";

fn erl_string_literal(raw: &str) -> String {
    let escaped: String = raw.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

const RESERVED_WORDS: &[&str] = &[
    "after", "and", "andalso", "band", "begin", "bnot", "bor", "bsl", "bsr", "bxor", "case",
    "catch", "cond", "div", "else", "end", "fun", "if", "let", "maybe", "not", "of", "or",
    "orelse", "receive", "rem", "try", "when", "xor",
];

fn atom_corpus() -> Vec<String> {
    let mut names: Vec<String> = RESERVED_WORDS
        .iter()
        .map(|w: &&str| (*w).to_owned())
        .collect();
    for extra in [
        "foo",
        "ok",
        "handle_call",
        "query",
        "iffy",
        "case_",
        "andalso2",
        "Foo",
        "foo bar",
        "it's ok",
        "a\\b",
        "",
    ] {
        names.push(extra.to_owned());
    }
    names
}

#[test]
fn emitted_atoms_reparse_to_intended_atom() {
    let names: Vec<String> = atom_corpus();

    let Some(erlang): Option<Erlang> = require_erlang(GRADED) else {
        return;
    };
    let erl: PathBuf = erlang.erl;

    let comparisons: Vec<String> = names
        .iter()
        .map(|name: &String| {
            format!(
                "({}) =:= list_to_atom({})",
                render_atom(name),
                erl_string_literal(name)
            )
        })
        .collect();
    let eval: String = format!(
        "io:format(\"~w~n\", [[{}]]), halt().",
        comparisons.join(", ")
    );

    let mut cmd: Command = Command::new(&erl);
    cmd.arg("-noshell").arg("-eval").arg(&eval);
    let output: std::process::Output = cmd.output().expect("run erl");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        output.status.success(),
        "erl exited non-zero re-parsing emitted atoms.\neval: {eval}\nstdout: {stdout}\nstderr: {stderr}"
    );
    let trimmed: &str = stdout.trim();
    assert!(
        !trimmed.contains("false"),
        "an emitted atom re-parsed to a different value.\neval: {eval}\nresult: {trimmed}"
    );
    let true_count: usize = trimmed.matches("true").count();
    assert_eq!(
        true_count,
        names.len(),
        "expected {} true comparisons, got {trimmed}",
        names.len()
    );
}
