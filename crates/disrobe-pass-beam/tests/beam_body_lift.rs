#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_beam::body_lift::render::render_body;
use disrobe_pass_beam::body_lift::{LiftedBody, build_label_index, lift_body};
use disrobe_pass_beam::{
    BeamFile, CoreFunction, CoreModule, ErlangSurface, EzArchive, EzEntry, lift, recover_erlang,
};

use crate::common::{
    build_atu8, build_beam, build_chunk, build_code_chunk, build_expt, encode_compact_small,
};

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("beam")
}

fn megafile() -> BeamFile {
    let ez_path: PathBuf = corpus_root().join("megafile").join("edge_cases.ez");
    let bytes: Vec<u8> = std::fs::read(&ez_path)
        .unwrap_or_else(|e: std::io::Error| panic!("read tracked {}: {e}", ez_path.display()));
    let archive: EzArchive = EzArchive::parse(&bytes).expect("parse edge_cases.ez");
    let inner: &EzEntry = archive
        .beam_files()
        .into_iter()
        .find(|e: &&EzEntry| e.path.ends_with("ebin/edge_cases.beam"))
        .expect("edge_cases.beam inside tracked edge_cases.ez");
    BeamFile::parse(&inner.data).expect("parse inner edge_cases.beam")
}

macro_rules! megafile {
    () => {
        megafile()
    };
}

fn body_of(core: &CoreModule, name: &str, arity: u32) -> String {
    let f: &CoreFunction = core
        .functions
        .iter()
        .find(|f: &&CoreFunction| f.name == name && f.arity == arity)
        .unwrap_or_else(|| panic!("function {name}/{arity} not found"));
    render_body(&f.clauses[0].body.stmts, 1)
}

fn find_fn<'a>(core: &'a CoreModule, name: &str, arity: u32) -> &'a CoreFunction {
    core.functions
        .iter()
        .find(|f: &&CoreFunction| f.name == name && f.arity == arity)
        .unwrap_or_else(|| panic!("function {name}/{arity} not found"))
}

fn surface_of(core: &CoreModule, name: &str, arity: u32) -> String {
    use disrobe_pass_beam::body_lift::render::render_expr;
    let f: &CoreFunction = find_fn(core, name, arity);
    let mut out: String = String::new();
    for clause in &f.clauses {
        let pats: Vec<String> = clause.patterns.iter().map(render_expr).collect();
        out.push_str(name);
        out.push('(');
        out.push_str(&pats.join(", "));
        out.push(')');
        if let Some(g) = &clause.guard {
            out.push_str(&format!(" when {}", render_expr(g)));
        }
        out.push_str(" ->\n");
        out.push_str(&render_body(&clause.body.stmts, 1));
        out.push_str(";\n");
    }
    out
}

fn is_lift_complete(core: &CoreModule, name: &str, arity: u32) -> bool {
    find_fn(core, name, arity)
        .clauses
        .iter()
        .all(|c| c.body.lift_complete)
}

#[test]
fn megafile_tuple_pivot_reconstructs_tuple_construction() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "tuple_pivot", 1);
    assert!(body.contains("{E2, E1, E0}"), "tuple pivot body:\n{body}");
    assert!(
        body.contains("{E3, E2, E1, E0}"),
        "tuple pivot body:\n{body}"
    );
    assert!(body.contains("is_tuple(X0)"), "tuple pivot body:\n{body}");
}

#[test]
fn megafile_if_demo_reconstructs_guard_chain() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "if_demo", 1);
    assert!(body.starts_with("    if"), "if_demo body:\n{body}");
    assert!(body.contains("100 < X0 ->"), "if_demo body:\n{body}");
    assert!(body.contains("big"), "if_demo body:\n{body}");
    assert!(body.contains("medium"), "if_demo body:\n{body}");
    assert!(body.contains("small"), "if_demo body:\n{body}");
    assert!(body.contains("other"), "if_demo body:\n{body}");
}

#[test]
fn megafile_string_concat_reconstructs_binary_construction() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "string_concat_three", 3);
    assert!(
        body.contains("<<X0/binary, X1/binary, X2/binary>>"),
        "string_concat body:\n{body}"
    );
}

#[test]
fn megafile_multi_clause_recur_reconstructs_case_and_recursion() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "multi_clause_recur", 1);
    assert!(body.contains("case X0 of"), "recur body:\n{body}");
    assert!(body.contains("base"), "recur body:\n{body}");
    assert!(body.contains("(X0 rem 2) =:= 0"), "recur body:\n{body}");
    assert!(
        body.contains("multi_clause_recur(X0 - 2)"),
        "recur body should show recursion:\n{body}"
    );
    assert!(body.contains("{even,"), "recur body:\n{body}");
    assert!(body.contains("{odd,"), "recur body:\n{body}");
}

#[test]
fn megafile_main_reconstructs_sequential_side_effecting_calls() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "main", 0);
    assert!(
        body.contains("io:format(\"edge_cases main"),
        "main body:\n{body}"
    );
    assert!(body.contains("record_ops()"), "main body:\n{body}");
    assert!(body.contains("map_ops()"), "main body:\n{body}");
    assert!(body.trim_end().ends_with("ok"), "main body:\n{body}");
}

#[test]
fn megafile_map_update_reconstructs_map_match_and_update() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "map_update", 1);
    assert!(body.contains("is_map(X0)"), "map_update body:\n{body}");
    assert!(body.contains("count =>"), "map_update body:\n{body}");
    assert!(
        body.contains("#{count := "),
        "map_update should recover the map-key pattern match:\n{body}"
    );
}

#[test]
fn megafile_try_demo_reconstructs_try_catch() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "try_demo", 1);
    assert!(body.contains("try"), "try_demo body:\n{body}");
    assert!(body.contains("catch"), "try_demo body:\n{body}");
    assert!(body.contains("10 div X0"), "try_demo body:\n{body}");
    assert!(body.contains("{error, divzero}"), "try_demo body:\n{body}");
}

#[test]
fn megafile_receive_demo_reconstructs_receive() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "receive_demo", 0);
    assert!(body.contains("receive"), "receive_demo body:\n{body}");
    assert!(
        body.contains("! {hi, self()}"),
        "receive_demo body:\n{body}"
    );
    assert!(body.contains("stopped"), "receive_demo body:\n{body}");
}

#[test]
fn megafile_all_functions_lift_complete_coverage() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let total: usize = core.functions.len();
    let incomplete: Vec<String> = core
        .functions
        .iter()
        .filter(|f: &&CoreFunction| !f.clauses.iter().all(|c| c.body.lift_complete))
        .map(|f: &CoreFunction| format!("{}/{}", f.name, f.arity))
        .collect();
    assert!(
        incomplete.is_empty(),
        "lift coverage (self-reported, not fidelity): every one of {total} functions \
         must model all opcodes with no unrecovered marker; incomplete: {incomplete:?}"
    );
    assert_eq!(
        total, 84,
        "edge_cases megafile is expected to expose 84 functions"
    );
}

#[test]
fn megafile_surface_recovery_contains_real_bodies_not_ok_stub() {
    let surface: ErlangSurface = recover_erlang(&megafile!()).expect("recover");
    assert!(surface.source.contains("-module(edge_cases)."));
    assert!(
        surface.source.contains("when is_binary(Bin)"),
        "abstract-code surface should recover the original guard with variable names"
    );
    assert!(
        surface.source.contains("<<A/binary, B/binary, C/binary>>"),
        "abstract-code surface should recover the original binary construction names"
    );
    let bare_ok_bodies: usize = surface.source.matches("->\n    ok.\n").count();
    let function_arrows: usize = surface.source.matches(") ->\n").count();
    assert!(
        bare_ok_bodies <= 5,
        "surface has {bare_ok_bodies} bare `ok.` bodies out of {function_arrows} functions"
    );
    assert!(
        function_arrows >= 60,
        "expected >=60 rendered functions, got {function_arrows}"
    );
}

#[test]
fn megafile_binary_comprehension_helper_resugars_to_byte_match_recursion() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let f: &CoreFunction = core
        .functions
        .iter()
        .find(|f: &&CoreFunction| f.name.contains("lbc$^") && f.arity == 2)
        .expect("binary comprehension helper");
    let surface: String = surface_of(&core, &f.name, 2);
    assert!(
        surface.contains("<<B0:8, B1/binary>>"),
        "lbc helper must match a leading byte and rest:\n{surface}"
    );
    assert!(
        surface.contains("(B0 rem 2) =:= 0"),
        "lbc helper must keep the even filter on the bound byte:\n{surface}"
    );
    assert!(
        surface.contains("/2-0-'(B1,"),
        "lbc helper must recurse on the matched rest:\n{surface}"
    );
    assert!(
        f.clauses.iter().all(|c| c.body.lift_complete),
        "lbc helper lift coverage: all opcodes modeled, no unrecovered marker"
    );
}

#[test]
fn megafile_list_comprehension_helper_conses_mapped_value_not_tail() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let f: &CoreFunction = core
        .functions
        .iter()
        .find(|f: &&CoreFunction| f.name.contains("higher_order/2-lc$^"))
        .expect("higher_order lc helper");
    let body: String = render_body(&f.clauses[0].body.stmts, 1);
    assert!(
        body.contains("[X1(hd(X0)) |"),
        "lc helper must cons the mapped value F(hd), not the tail:\n{body}"
    );
    assert!(
        body.contains("is_list(X0) andalso (X0 =/= [])"),
        "nonempty-list test must exclude [] so the empty list hits the base case:\n{body}"
    );
}

#[test]
fn megafile_bit_syntax_decode_reconstructs_binary_pattern_clauses() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let f: &CoreFunction = find_fn(&core, "bit_syntax_decode", 1);
    assert_eq!(f.clauses.len(), 3, "three binary-pattern clauses expected");
    let surface: String = surface_of(&core, "bit_syntax_decode", 1);
    assert!(
        surface.contains("<<B0:8, B1:16, B2:32/little, B3/binary>>"),
        "first clause must recover the full binary pattern incl. /little and rest:\n{surface}"
    );
    assert!(
        surface.contains("byte_size(B3)"),
        "rest bound for byte_size:\n{surface}"
    );
    assert!(
        surface.contains("bit_syntax_decode(<<>>)"),
        "empty-binary clause:\n{surface}"
    );
    assert!(
        surface.contains("bit_syntax_decode(<<B0:8>>)"),
        "single-byte clause:\n{surface}"
    );
    assert!(is_lift_complete(&core, "bit_syntax_decode", 1));
}

#[test]
fn megafile_bit_syntax_encode_recovers_literal_string_segment() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "bit_syntax_encode", 1);
    assert!(
        body.contains("<<1:8, "),
        "leading 1:8 segment must be recovered from the StrT string literal:\n{body}"
    );
    assert!(
        body.contains("atom_to_binary(element(1, X0), utf8)"),
        "tag binary construction preserved:\n{body}"
    );
    assert!(is_lift_complete(&core, "bit_syntax_encode", 1));
}

#[test]
fn megafile_error_with_stacktrace_recovers_try_catch_class_and_stack() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "error_with_stacktrace", 0);
    assert!(body.contains("try"), "must be a try:\n{body}");
    assert!(body.contains("error(forced)"), "protected body:\n{body}");
    assert!(
        body.contains("error:Reason:Stack ->"),
        "catch clause must bind class error plus the stacktrace:\n{body}"
    );
    assert!(
        body.contains("length(Stack)"),
        "stacktrace is used in the handler body:\n{body}"
    );
    assert!(is_lift_complete(&core, "error_with_stacktrace", 0));
}

#[test]
fn megafile_catch_old_school_recovers_catch_value_binding() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "catch_old_school", 1);
    assert!(
        body.contains("(catch X0())"),
        "catch result must be parenthesized and bound:\n{body}"
    );
    assert!(
        body.contains("{error, element(2, ") && body.contains("{ok, "),
        "both EXIT and success arms recovered:\n{body}"
    );
    assert!(is_lift_complete(&core, "catch_old_school", 1));
}

#[test]
fn megafile_dets_demo_resugars_badmatch_chain_into_match_bindings() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "dets_demo", 0);
    assert!(
        body.contains("{ok, _} = "),
        "open_file result must be a `{{ok,_}} =` match, not a synthetic error:\n{body}"
    );
    assert!(
        body.contains("ok = dets:insert(demo_dets, {key, 42})"),
        "insert assertion recovered as match:\n{body}"
    );
    assert!(
        !body.contains("disrobe_unrecovered"),
        "no synthetic clause-exhaustion error must remain:\n{body}"
    );
    assert!(is_lift_complete(&core, "dets_demo", 0));
}

#[test]
fn megafile_nested_map_match_recovers_map_key_patterns() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "nested_map_match", 1);
    assert!(
        body.contains("#{outer := ") && body.contains("#{inner := "),
        "nested map-key patterns must be recovered (not maps:get in a guard):\n{body}"
    );
    assert!(
        !body.contains("is_map(maps:get"),
        "maps:get must never appear inside a guard:\n{body}"
    );
    assert!(is_lift_complete(&core, "nested_map_match", 1));
}

#[test]
fn megafile_handle_cast_recovers_record_update_via_setelement() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "handle_cast", 2);
    assert!(
        body.contains("setelement(2, X1,"),
        "record field update must lower to setelement:\n{body}"
    );
    assert!(is_lift_complete(&core, "handle_cast", 2));
}

#[test]
fn megafile_map_update_declines_unsafe_clause_split_keeps_map_pattern() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "map_update", 1);
    assert!(
        body.contains("is_map_key(count, X0)"),
        "the present-key branch must guard on is_map_key, not an unconditional match:\n{body}"
    );
    assert!(
        body.contains("X0#{count => "),
        "the fall-through clause must initialize count:\n{body}"
    );
    assert!(is_lift_complete(&core, "map_update", 1));
}

#[test]
fn megafile_exception_chain_recovers_throw_error_exit() {
    let core: CoreModule = lift(&megafile!()).expect("lift");
    let body: String = body_of(&core, "exception_chain", 1);
    assert!(body.contains("throw(zero)"), "throw arm:\n{body}");
    assert!(body.contains("error({negative,"), "error arm:\n{body}");
    assert!(body.contains("exit({too_big,"), "exit arm:\n{body}");
    assert!(is_lift_complete(&core, "exception_chain", 1));
}

fn synthetic_tuple_builder_beam() -> Vec<u8> {
    let atoms: Vec<u8> = build_atu8(&["m", "pair"]);
    let mut code: Vec<u8> = Vec::new();
    code.push(1u8);
    code.extend(encode_compact_small(0, 1));
    code.push(2u8);
    code.extend(encode_compact_small(2, 1));
    code.extend(encode_compact_small(2, 2));
    code.extend(encode_compact_small(0, 2));
    code.push(1u8);
    code.extend(encode_compact_small(0, 2));
    code.push(164u8);
    code.extend(encode_compact_small(3, 0));
    code.push(0x17);
    code.extend(encode_compact_small(0, 2));
    code.extend(encode_compact_small(3, 0));
    code.extend(encode_compact_small(3, 1));
    code.push(19u8);
    code.push(3u8);

    let chunks: Vec<Vec<u8>> = vec![
        build_chunk(b"AtU8", &atoms),
        build_chunk(b"Code", &build_code_chunk(2, 1, &code)),
        build_chunk(b"ExpT", &build_expt(&[(2u32, 2u32, 2u32)])),
    ];
    build_beam(&chunks)
}

#[test]
fn synthetic_put_tuple2_lifts_to_tuple_literal() {
    let buf: Vec<u8> = synthetic_tuple_builder_beam();
    let beam: BeamFile = BeamFile::parse(&buf).expect("parse");
    let core: CoreModule = lift(&beam).expect("lift");
    let f: &CoreFunction = core
        .functions
        .iter()
        .find(|f: &&CoreFunction| f.name == "pair")
        .expect("pair function");
    let body: String = render_body(&f.clauses[0].body.stmts, 1);
    assert!(body.contains("{X0, X1}"), "synthetic pair body:\n{body}");
}

#[test]
fn lift_body_empty_stream_yields_ok() {
    let beam: BeamFile = megafile!();
    let index: BTreeMap<u32, (String, u32)> = build_label_index(&beam.chunks);
    let body: LiftedBody = lift_body(&[], 0, &beam.chunks, &index);
    assert!(!body.lift_complete);
    assert_eq!(body.stmts.len(), 1);
}
