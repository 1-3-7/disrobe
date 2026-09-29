#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_beam::{BeamFile, ErlangSurface, RecoverySource, recover_erlang};

mod common;

use common::erlang_toolchain::{
    ELIXIRC, Erlang, command_for, require, require_erlang, run_bounded,
};

const GRADED: &str = "the recovered-elixir recompile-execution check";

const MEGAFILE_BATTERY: &str = "M = 'Elixir.EdgeCases', Calls = [\
    fun() -> M:pattern_match_basic({ok, 42}) end, \
    fun() -> M:pattern_match_basic({partial, [3, 4]}) end, \
    fun() -> M:pattern_match_basic(foo) end, \
    fun() -> M:pattern_match_basic(<<\"x\">>) end, \
    fun() -> M:pattern_match_map(#{type => user, id => 1, name => <<\"n\">>}) end, \
    fun() -> M:pattern_match_map(#{}) end, \
    fun() -> M:pattern_match_map(#{type => admin}) end, \
    fun() -> M:pipe_chain([1, 2, 3, 4, 5]) end, \
    fun() -> M:pipe_with_named([1, 5, 3, 4]) end, \
    fun() -> M:with_demo(#{a => 1, b => 2}) end, \
    fun() -> M:with_demo(#{a => 1}) end, \
    fun() -> M:with_demo(#{a => -5, b => 2}) end, \
    fun() -> M:comprehension_simple([-1, 2, 3]) end, \
    fun() -> M:comprehension_multi([1, 2], [2, 3]) end, \
    fun() -> M:comprehension_into_map([{a, 1}, {<<\"b\">>, 2}, {c, x}]) end, \
    fun() -> M:comprehension_into_binary([65, 300, 66]) end, \
    fun() -> M:stream_demo(lists:seq(1, 12)) end, \
    fun() -> M:case_demo({ok, 3}) end, \
    fun() -> M:case_demo({ok, 0}) end, \
    fun() -> M:case_demo({error, e}) end, \
    fun() -> M:case_demo(z) end, \
    fun() -> [M:cond_demo(X) || X <- [-1, 0, 5, 50]] end, \
    fun() -> [M:if_demo(X) || X <- [500, 5, -5]] end, \
    fun() -> [M:unless_demo(X) || X <- [nil, false, 1]] end, \
    fun() -> M:named_args_demo(<<\"n\">>) end, \
    fun() -> M:named_args_demo(<<\"n\">>, [{verbose, true}]) end, \
    fun() -> {M:default_args(1), M:default_args(1, 2), M:default_args(1, 2, 3)} end, \
    fun() -> M:first_class_callable(fun(X) -> X * 3 end, [1, 2]) end, \
    fun() -> M:capture_demo() end, \
    fun() -> F = M:anonymous_multi_clause(), [F({ok, 7}), F({error, 1}), F(timeout)] end, \
    fun() -> {M:map_update(#{k => 1}, k), M:map_update(#{}, k)} end, \
    fun() -> M:map_get_in(#{user => #{addr => #{city => <<\"c\">>}}}) end, \
    fun() -> M:map_put_in(#{user => #{addr => #{}}}) end, \
    fun() -> M:map_update_in(#{user => #{}}) end, \
    fun() -> M:keyword_demo() end, \
    fun() -> M:list_ops([3, 1, 2, 3]) end, \
    fun() -> [M:tuple_destructure(T) || T <- [{1, 2, 3}, {1, 2, 3, 4}, {1, 2}]] end, \
    fun() -> [M:binary_pattern(B) || B <- [<<16#89, \"PNG\", 0>>, <<16#FF, 16#D8>>, <<\"GIF87a\">>, <<\"GIF89a\">>, <<\"x\">>]] end, \
    fun() -> M:binary_construct(tag, <<\"pay\">>) end, \
    fun() -> M:string_interp(<<\"n\">>, 3) end, \
    fun() -> {W, R, S, C, D} = M:sigil_demo(), {W, maps:get(source, R), S, C, D} end\
    ], [try F() catch Class:Reason -> {caught, Class, Reason} end || F <- Calls]";

fn corpus_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("corpus")
        .join("beam")
        .join(relative)
}

fn elixir_ebin(elixirc: &Path) -> PathBuf {
    let ebin: PathBuf = elixirc
        .parent()
        .and_then(Path::parent)
        .map(|root: &Path| root.join("lib").join("elixir").join("ebin"))
        .unwrap_or_else(|| panic!("{} has no install root", elixirc.display()));
    assert!(
        ebin.join("Elixir.Kernel.beam").is_file(),
        "{GRADED} runs the compiled modules on the Elixir runtime, expected at {}",
        ebin.display()
    );
    ebin
}

fn elixirc_compile(
    elixirc: &Path,
    sources: &[PathBuf],
    out_dir: &Path,
    prefix: &str,
) -> Result<BTreeSet<String>, String> {
    let mut cmd: Command = command_for(elixirc);
    cmd.arg("-o").arg(out_dir).args(sources);
    let (ok, so, se): (bool, String, String) =
        run_bounded(cmd).ok_or_else(|| "elixirc timed out".to_owned())?;
    let modules: BTreeSet<String> = compiled_modules(out_dir, prefix);
    if ok && !modules.is_empty() && !se.contains("error") {
        Ok(modules)
    } else {
        Err(format!("stdout:\n{so}\nstderr:\n{se}"))
    }
}

fn run_eval(
    erlang: &Erlang,
    ebin: &Path,
    code_dir: &Path,
    expression: &str,
) -> Result<String, String> {
    let eval: String = format!("io:format(\"~p~n\", [begin {expression} end]), halt().");
    let mut cmd: Command = Command::new(&erlang.erl);
    cmd.current_dir(code_dir)
        .arg("-noshell")
        .arg("-pa")
        .arg(ebin)
        .arg("-pa")
        .arg(code_dir)
        .arg("-eval")
        .arg(&eval);
    match run_bounded(cmd) {
        Some((true, so, _)) => Ok(so),
        Some((false, so, se)) => Err(format!("{expression} failed\nstdout:\n{so}\nstderr:\n{se}")),
        None => Err(format!("{expression} timed out")),
    }
}

fn compiled_modules(dir: &Path, prefix: &str) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("list compiled modules")
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name: &String| {
            name.starts_with(&format!("Elixir.{prefix}")) && name.ends_with(".beam")
        })
        .collect()
}

struct Graded {
    original: String,
    modules: BTreeSet<String>,
    recovered_modules: BTreeSet<String>,
    recovered_source: String,
    recovered: Result<String, String>,
}

impl Graded {
    fn recovered_output(&self) -> &str {
        self.recovered.as_deref().unwrap_or_else(|log: &String| {
            panic!(
                "recovered Elixir failed to compile or run:\n{log}\nsource:\n{}",
                self.recovered_source
            )
        })
    }
}

fn grade(source: &str, prefix: &str, expression: &str, transform: fn(&str) -> String) -> Graded {
    let elixirc: PathBuf = require(&ELIXIRC, GRADED);
    let erlang: Erlang = require_erlang(GRADED);
    let ebin: PathBuf = elixir_ebin(&elixirc);
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_elixir_recompile_eq").expect("create scratch directory");
    let orig_dir: PathBuf = scratch.path().join("orig");
    let rec_dir: PathBuf = scratch.path().join("rec");
    std::fs::create_dir_all(&orig_dir).expect("mkdir orig");
    std::fs::create_dir_all(&rec_dir).expect("mkdir rec");

    let modules: BTreeSet<String> =
        elixirc_compile(&elixirc, &[corpus_file(source)], &orig_dir, prefix)
            .unwrap_or_else(|log: String| panic!("corpus source {source} must compile:\n{log}"));
    let mut recovered_sources: Vec<(String, String)> = Vec::with_capacity(modules.len());
    for module in &modules {
        let bytes: Vec<u8> = std::fs::read(orig_dir.join(module)).expect("read beam");
        let beam: BeamFile = BeamFile::parse(&bytes).expect("parse original beam");
        let surface: ErlangSurface = recover_erlang(&beam).expect("recover");
        assert_eq!(
            surface.recovered_from,
            RecoverySource::ElixirDbgiForm,
            "{module}"
        );
        recovered_sources.push((module.clone(), surface.source));
    }
    let original: String = run_eval(&erlang, &ebin, &orig_dir, expression)
        .unwrap_or_else(|log: String| panic!("the original {source} must run:\n{log}"));

    let src_dir: PathBuf = scratch.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("mkdir src");
    let mut recovered_source: String = String::new();
    let mut rec_srcs: Vec<PathBuf> = Vec::with_capacity(recovered_sources.len());
    for (module, source) in &recovered_sources {
        let transformed: String = transform(source);
        let path: PathBuf = src_dir.join(format!("{module}.ex"));
        std::fs::write(&path, &transformed).expect("write recovered source");
        recovered_source.push_str(&transformed);
        recovered_source.push('\n');
        rec_srcs.push(path);
    }
    let recovered: Result<String, String> = elixirc_compile(&elixirc, &rec_srcs, &rec_dir, prefix)
        .and_then(|_: BTreeSet<String>| run_eval(&erlang, &ebin, &rec_dir, expression));
    let recovered_modules: BTreeSet<String> = compiled_modules(&rec_dir, prefix);
    Graded {
        original,
        modules,
        recovered_modules,
        recovered_source,
        recovered,
    }
}

#[test]
fn recovered_operators_recompile_and_return_what_the_original_returns() {
    let graded: Graded = grade(
        "elixir_recompile_oracle/operators.ex",
        "Operators",
        "'Elixir.Operators':test()",
        str::to_owned,
    );
    let recovered: &str = graded.recovered_output();
    assert!(
        graded.original.contains("false") && graded.original.contains("true"),
        "{GRADED} needs a result that separates strict from loose equality, got {}",
        graded.original
    );
    assert_eq!(
        recovered, graded.original,
        "recovered source:\n{}",
        graded.recovered_source
    );
}

#[test]
fn loosening_strict_equality_in_the_recovered_source_turns_the_grade_red() {
    let graded: Graded = grade(
        "elixir_recompile_oracle/operators.ex",
        "Operators",
        "'Elixir.Operators':test()",
        |source: &str| source.replace(" === ", " == "),
    );
    assert_ne!(
        graded.recovered_output(),
        graded.original,
        "{GRADED} cannot tell `===` from `==`"
    );
}

#[test]
fn recovered_literals_keep_hash_braces_and_control_characters() {
    let graded: Graded = grade(
        "elixir_recompile_oracle/literals.ex",
        "Literals",
        "'Elixir.Literals':test()",
        str::to_owned,
    );
    let recovered: &str = graded.recovered_output();
    assert!(
        graded.original.contains("#{"),
        "{GRADED} needs a literal hash-brace in the original result, got {}",
        graded.original
    );
    assert_eq!(
        recovered, graded.original,
        "recovered source:\n{}",
        graded.recovered_source
    );
}

#[test]
fn the_recovered_megafile_recompiles_every_module_and_answers_the_battery_alike() {
    let graded: Graded = grade(
        "megafile/edge_cases.ex",
        "EdgeCases",
        MEGAFILE_BATTERY,
        str::to_owned,
    );
    let recovered: &str = graded.recovered_output();
    assert_eq!(
        graded.recovered_modules, graded.modules,
        "the recovered source must define every original module"
    );
    assert!(
        !graded.original.contains("caught"),
        "the battery must run cleanly on the original: {}",
        graded.original
    );
    assert_eq!(
        recovered, graded.original,
        "recovered source:\n{}",
        graded.recovered_source
    );
}
