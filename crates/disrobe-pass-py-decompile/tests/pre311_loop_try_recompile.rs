#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const TRY_INSIDE_LOOP: &str = concat!(
    "def v_tuple(get, cache):\n",
    "    thread = current()\n",
    "    while True:\n",
    "        try:\n",
    "            task = get()\n",
    "        except (OSError, EOFError):\n",
    "            log('exit')\n",
    "            return\n",
    "        if thread.state != RUN:\n",
    "            break\n",
    "        if task is None:\n",
    "            break\n",
    "        cache.add(task)\n",
    "\n",
    "\n",
    "def v_single(get):\n",
    "    while True:\n",
    "        try:\n",
    "            item = get()\n",
    "        except KeyError:\n",
    "            return\n",
    "        if item is None:\n",
    "            break\n",
    "        handle(item)\n",
    "\n",
    "\n",
    "def v_return_val(q):\n",
    "    total = 0\n",
    "    while True:\n",
    "        try:\n",
    "            n = q.pop()\n",
    "        except IndexError:\n",
    "            return total\n",
    "        total += n\n",
);

const TRY_WRAPPING_LOOP: &str = concat!(
    "def worker(flag, stop, work, cleanup):\n",
    "    if flag:\n",
    "        try:\n",
    "            setup()\n",
    "        except OSError:\n",
    "            log('setup')\n",
    "            return\n",
    "    try:\n",
    "        while True:\n",
    "            if stop():\n",
    "                break\n",
    "            work()\n",
    "    except OSError:\n",
    "        cleanup()\n",
);

const WITH_IF_RETURN: &str = concat!(
    "def branch_else(ctx, width, a, b):\n",
    "    with ctx():\n",
    "        if width >= 9:\n",
    "            names = a\n",
    "        else:\n",
    "            names = b\n",
    "        name = names[width]\n",
    "        return name[:width].center(width)\n",
    "\n",
    "\n",
    "def branch_no_else(ctx, month, year, width, withyear):\n",
    "    with ctx():\n",
    "        s = month[year]\n",
    "        if withyear:\n",
    "            s = '%s %r' % (s, year)\n",
    "        return s.center(width)\n",
    "\n",
    "\n",
    "def branch_pre_return(ctx, flag, x):\n",
    "    with ctx():\n",
    "        y = 1\n",
    "        if flag:\n",
    "            y = x\n",
    "        z = y + 1\n",
    "        return z\n",
);

const NESTED_TRY_IN_EXCEPT: &str = concat!(
    "def end(dispatch, tag, data):\n",
    "    try:\n",
    "        f = dispatch[tag]\n",
    "    except KeyError:\n",
    "        if ':' not in tag:\n",
    "            return None\n",
    "        try:\n",
    "            f = dispatch[tag.split(':')[-1]]\n",
    "        except KeyError:\n",
    "            return None\n",
    "    return f(data)\n",
    "\n",
    "\n",
    "def end_dispatch(dispatch, tag, data):\n",
    "    try:\n",
    "        f = dispatch[tag]\n",
    "    except KeyError:\n",
    "        if ':' not in tag:\n",
    "            return None\n",
    "        try:\n",
    "            f = dispatch[tag.split(':')[-1]]\n",
    "        except KeyError:\n",
    "            return None\n",
    "    return f(data)\n",
);

const HANDLER_CONTINUES_LOOP: &str = concat!(
    "def near_keyword(command, args, keywords, get_word_index):\n",
    "    stdout = command_stdout(command, args)\n",
    "    if stdout is None:\n",
    "        return None\n",
    "    first_local = None\n",
    "    for line in stdout:\n",
    "        words = line.lower().rstrip().split()\n",
    "        for i in range(len(words)):\n",
    "            if words[i] in keywords:\n",
    "                try:\n",
    "                    word = words[get_word_index(i)]\n",
    "                    mac = int(word.replace(DELIM, b''), 16)\n",
    "                except (ValueError, IndexError):\n",
    "                    pass\n",
    "                else:\n",
    "                    if is_universal(mac):\n",
    "                        return mac\n",
    "                    first_local = first_local or mac\n",
    "    return first_local or None\n",
    "\n",
    "\n",
    "def body_handler_continues(rows, sink):\n",
    "    seen = 0\n",
    "    for row in rows:\n",
    "        try:\n",
    "            value = parse(row)\n",
    "        except ValueError:\n",
    "            record(row)\n",
    "        else:\n",
    "            sink.add(value)\n",
    "            seen += 1\n",
    "    return seen\n",
    "\n",
    "\n",
    "def bare_handler_continues(rows, sink):\n",
    "    seen = 0\n",
    "    for row in rows:\n",
    "        try:\n",
    "            value = parse(row)\n",
    "        except:\n",
    "            note(row)\n",
    "        else:\n",
    "            sink.add(value)\n",
    "            seen += 1\n",
    "    return seen\n",
    "\n",
    "\n",
    "def two_handlers_continue(rows, sink):\n",
    "    seen = 0\n",
    "    for row in rows:\n",
    "        try:\n",
    "            value = parse(row)\n",
    "        except ValueError:\n",
    "            note(row)\n",
    "        except KeyError:\n",
    "            warn(row)\n",
    "        else:\n",
    "            sink.add(value)\n",
    "            seen += 1\n",
    "    return seen\n",
    "\n",
    "\n",
    "def outer_loop_inner_handler(groups, sink):\n",
    "    seen = 0\n",
    "    for group in groups:\n",
    "        for row in group:\n",
    "            try:\n",
    "                value = parse(row)\n",
    "            except ValueError:\n",
    "                continue\n",
    "            else:\n",
    "                sink.add(value)\n",
    "                seen += 1\n",
    "        sink.flush(group)\n",
    "    return seen\n",
);

const HANDLER_CONTINUE_WRITTEN_OUT: &str = concat!(
    "def handler_continue_explicit(rows, sink):\n",
    "    seen = 0\n",
    "    for row in rows:\n",
    "        try:\n",
    "            value = parse(row)\n",
    "        except ValueError:\n",
    "            note(row)\n",
    "            continue\n",
    "        sink.add(value)\n",
    "        seen += 1\n",
    "    return seen\n",
);

const HANDLER_LEAVES_LOOP: &str = concat!(
    "def handler_breaks(rows, sink):\n",
    "    seen = 0\n",
    "    for row in rows:\n",
    "        try:\n",
    "            value = parse(row)\n",
    "        except ValueError:\n",
    "            break\n",
    "        else:\n",
    "            sink.add(value)\n",
    "            seen += 1\n",
    "    return seen\n",
    "\n",
    "\n",
    "def handler_returns(rows, sink):\n",
    "    seen = 0\n",
    "    for row in rows:\n",
    "        try:\n",
    "            value = parse(row)\n",
    "        except ValueError:\n",
    "            return seen\n",
    "        else:\n",
    "            sink.add(value)\n",
    "            seen += 1\n",
    "    return seen\n",
    "\n",
    "\n",
    "def handler_outside_loop(source, sink):\n",
    "    try:\n",
    "        value = source.take()\n",
    "    except LookupError:\n",
    "        note(source)\n",
    "    else:\n",
    "        sink.add(value)\n",
    "    return sink\n",
);

const HANDLER_FALLS_TO_LOOP_END: &str = concat!(
    "def tail_handler_pass(mods):\n",
    "    for m in mods:\n",
    "        try:\n",
    "            m.a = abspath(m.a)\n",
    "        except (AttributeError, OSError, TypeError):\n",
    "            pass\n",
    "        try:\n",
    "            m.b = abspath(m.b)\n",
    "        except (AttributeError, OSError, TypeError):\n",
    "            pass\n",
    "\n",
    "\n",
    "def only_handler_pass(rows):\n",
    "    for row in rows:\n",
    "        try:\n",
    "            consume(row)\n",
    "        except ValueError:\n",
    "            pass\n",
    "\n",
    "\n",
    "def tail_handler_body_then_loop_end(rows, sink):\n",
    "    for row in rows:\n",
    "        step(row)\n",
    "        try:\n",
    "            sink.add(parse(row))\n",
    "        except ValueError:\n",
    "            sink.miss(row)\n",
);

const HANDLER_TERMINATES_IN_LOOP: &str = concat!(
    "def handler_returns(rows, sink):\n",
    "    seen = 0\n",
    "    for row in rows:\n",
    "        try:\n",
    "            value = parse(row)\n",
    "        except ValueError:\n",
    "            return seen\n",
    "        else:\n",
    "            sink.add(value)\n",
    "            seen += 1\n",
    "    return seen\n",
    "\n",
    "\n",
    "def handler_raises(rows, sink):\n",
    "    seen = 0\n",
    "    for row in rows:\n",
    "        try:\n",
    "            value = parse(row)\n",
    "        except ValueError:\n",
    "            raise RuntimeError(row)\n",
    "        else:\n",
    "            sink.add(value)\n",
    "            seen += 1\n",
    "    return seen\n",
);

const PRE311_WHILE_TRY_BREAK_AND_CONTINUE: &str = concat!(
    "def drain(active, take, sink):\n",
    "    while active():\n",
    "        try:\n",
    "            value = take()\n",
    "        except ValueError:\n",
    "            sink.error()\n",
    "            continue\n",
    "        if value is None:\n",
    "            break\n",
    "        sink(value)\n",
    "    return sink\n",
);

const ALIASES: &[&str] = &["3.8", "3.9", "3.10", "3.11"];
const PRE311_ALIASES: &[&str] = &["3.8", "3.9", "3.10"];
const LEGACY_BLOCK_ALIASES: &[&str] = &["3.8", "3.9"];
const CONTINUE_FLIP_ALIASES: &[&str] = &["3.10", "3.11"];

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", alias])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn compile_source(interpreter: &Path, source_path: &Path, pyc_path: &Path) -> Result<(), String> {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            script,
            source_path.to_str().unwrap_or(""),
            pyc_path.to_str().unwrap_or(""),
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "exit={:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile = read_pyc(&bytes).map_err(|e| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

fn recover(
    scratch: &Path,
    alias: &str,
    fixture: &str,
) -> Option<(CodeObject, MarshalVersion, String)> {
    let interpreter: PathBuf = find_interpreter(alias)?;
    let source_path: PathBuf = scratch.join(format!("src.{alias}.py"));
    fs::write(&source_path, fixture).expect("write fixture");
    let orig_pyc: PathBuf = scratch.join(format!("orig.{alias}.pyc"));
    if let Err(e) = compile_source(&interpreter, &source_path, &orig_pyc) {
        eprintln!("SKIP {alias}: orig compile {e}");
        return None;
    }
    let (original, marshal_version): (CodeObject, MarshalVersion) =
        read_code(&orig_pyc).unwrap_or_else(|e| panic!("{alias} read orig: {e}"));
    let version: PyVersion = marshal_to_decompile(marshal_version)
        .unwrap_or_else(|e| panic!("{alias} version map: {e:?}"));
    let source: String = build_real_source(&original, &version, marshal_version)
        .unwrap_or_else(|e| panic!("{alias} decompile: {e}"));
    Some((original, marshal_version, source))
}

#[test]
fn try_inside_loop_recompiles_equivalent() {
    let scratch: PathBuf = PathBuf::from("../../target/py-try-inside-loop");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in ALIASES {
        let Some((original, marshal_version, source)): Option<(
            CodeObject,
            MarshalVersion,
            String,
        )> = recover(&scratch, alias, TRY_INSIDE_LOOP) else {
            continue;
        };
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &source).expect("write recovered");
        checked += 1;
        let interpreter: PathBuf = find_interpreter(alias).expect("interpreter re-resolve");
        let recompiled_pyc: PathBuf = scratch.join(format!("recovered.{alias}.pyc"));
        if let Err(e) = compile_source(&interpreter, &recovered_path, &recompiled_pyc) {
            failures.push(format!(
                "py{alias}: recovered does not parse: {e}\n{source}"
            ));
            continue;
        }
        let (recompiled, _): (CodeObject, MarshalVersion) =
            read_code(&recompiled_pyc).unwrap_or_else(|e| panic!("{alias} read recompiled: {e}"));
        match semantic_equiv(&original, &recompiled, marshal_version) {
            Verdict::Perfect | Verdict::Semantic => {}
            Verdict::CodeDiff(detail) => {
                failures.push(format!("py{alias}: not equivalent ({detail:?})\n{source}"));
            }
        }
    }

    assert!(
        checked > 0,
        "no CPython 3.8-3.11 interpreter resolvable via uv; the try-inside-loop proof is vacuous"
    );
    assert!(
        failures.is_empty(),
        "{} try-inside-loop recompile failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn try_wrapping_loop_handler_not_orphaned() {
    let scratch: PathBuf = PathBuf::from("../../target/py-try-wrapping-loop");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in PRE311_ALIASES {
        let Some((_, _, source)): Option<(CodeObject, MarshalVersion, String)> =
            recover(&scratch, alias, TRY_WRAPPING_LOOP)
        else {
            continue;
        };
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &source).expect("write recovered");
        checked += 1;
        if source.contains("exception matches") {
            failures.push(format!(
                "py{alias}: except handler leaked as exc-match:\n{source}"
            ));
            continue;
        }
        if !source.contains("except OSError") {
            failures.push(format!("py{alias}: except handler dropped:\n{source}"));
            continue;
        }
        let interpreter: PathBuf = find_interpreter(alias).expect("interpreter re-resolve");
        let recompiled_pyc: PathBuf = scratch.join(format!("recovered.{alias}.pyc"));
        if let Err(e) = compile_source(&interpreter, &recovered_path, &recompiled_pyc) {
            failures.push(format!(
                "py{alias}: recovered does not parse: {e}\n{source}"
            ));
        }
    }

    assert!(
        checked > 0,
        "no CPython 3.8-3.10 interpreter resolvable via uv; the try-wrapping-loop proof is vacuous"
    );
    assert!(
        failures.is_empty(),
        "{} try-wrapping-loop structuring failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

fn assert_recompiles_equivalent(scratch_name: &str, fixture: &str, label: &str, aliases: &[&str]) {
    let scratch: PathBuf = PathBuf::from(format!("../../target/{scratch_name}"));
    fs::create_dir_all(&scratch).expect("scratch");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in aliases {
        let Some((original, marshal_version, source)): Option<(
            CodeObject,
            MarshalVersion,
            String,
        )> = recover(&scratch, alias, fixture) else {
            continue;
        };
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &source).expect("write recovered");
        checked += 1;
        if source.contains("exception matches") {
            failures.push(format!(
                "py{alias}: exc-match leaked into source:\n{source}"
            ));
            continue;
        }
        let interpreter: PathBuf = find_interpreter(alias).expect("interpreter re-resolve");
        let recompiled_pyc: PathBuf = scratch.join(format!("recovered.{alias}.pyc"));
        if let Err(e) = compile_source(&interpreter, &recovered_path, &recompiled_pyc) {
            failures.push(format!(
                "py{alias}: recovered does not parse: {e}\n{source}"
            ));
            continue;
        }
        let (recompiled, _): (CodeObject, MarshalVersion) =
            read_code(&recompiled_pyc).unwrap_or_else(|e| panic!("{alias} read recompiled: {e}"));
        match semantic_equiv(&original, &recompiled, marshal_version) {
            Verdict::Perfect | Verdict::Semantic => {}
            Verdict::CodeDiff(detail) => {
                failures.push(format!("py{alias}: not equivalent ({detail:?})\n{source}"));
            }
        }
    }

    assert!(
        checked > 0,
        "no CPython interpreter resolvable via uv for {label}; the proof is vacuous"
    );
    assert!(
        failures.is_empty(),
        "{} {label} recompile failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn with_if_return_recompiles_equivalent() {
    assert_recompiles_equivalent(
        "py-with-if-return",
        WITH_IF_RETURN,
        "with-if-return",
        PRE311_ALIASES,
    );
}

#[test]
fn nested_try_in_except_recompiles_equivalent() {
    assert_recompiles_equivalent(
        "py-nested-try-in-except",
        NESTED_TRY_IN_EXCEPT,
        "nested-try-in-except",
        ALIASES,
    );
}

#[test]
fn handler_that_continues_the_loop_keeps_the_else_arm_guarded() {
    assert_recompiles_equivalent(
        "py-handler-continues-loop",
        HANDLER_CONTINUES_LOOP,
        "handler-continues-loop",
        CONTINUE_FLIP_ALIASES,
    );
}

#[test]
fn handler_continue_written_out_survives_the_pre311_block_model() {
    assert_recompiles_equivalent(
        "py-handler-continue-explicit",
        HANDLER_CONTINUE_WRITTEN_OUT,
        "handler-continue-explicit",
        ALIASES,
    );
}

#[test]
fn handler_that_leaves_the_loop_does_not_become_a_continue() {
    assert_recompiles_equivalent(
        "py-handler-leaves-loop",
        HANDLER_LEAVES_LOOP,
        "handler-leaves-loop",
        LEGACY_BLOCK_ALIASES,
    );
}

#[test]
fn handler_that_falls_through_to_the_loop_end_stays_a_fallthrough() {
    assert_recompiles_equivalent(
        "py-handler-falls-to-loop-end",
        HANDLER_FALLS_TO_LOOP_END,
        "handler-falls-to-loop-end",
        ALIASES,
    );
}

#[test]
fn handler_that_terminates_does_not_become_a_continue() {
    assert_recompiles_equivalent(
        "py-handler-terminates",
        HANDLER_TERMINATES_IN_LOOP,
        "handler-terminates",
        CONTINUE_FLIP_ALIASES,
    );
}

#[test]
fn pre311_while_try_preserves_handler_continue_and_body_break() {
    assert_recompiles_equivalent(
        "py-pre311-while-try-break-continue",
        PRE311_WHILE_TRY_BREAK_AND_CONTINUE,
        "pre311 while try break continue",
        &["3.10"],
    );
}
