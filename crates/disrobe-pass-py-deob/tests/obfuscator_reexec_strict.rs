#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_py_deob::{Error, PeelResult, RemappedRecovery, peel, recover_remapped_pyc};
use disrobe_pass_py_disasm::{RemapDetection, RemapError, RemapVerdict, detect_opcode_remap};
use disrobe_py_marshal::{CodeObject, Object, PycFile, read_pyc, write_pyc};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};
use ruff_python_ast::ModModule;
use ruff_python_ast::token::TokenKind;
use ruff_python_parser::{Parsed, parse_module};
use ruff_text_size::Ranged;
use sha2::{Digest, Sha256};

const PYTHON_TIMEOUT: Duration = Duration::from_mins(1);
const PROGRAM_FILE: &str = "program.py";
const BAND_SUPPORT: &str = "edge_cases_3_6";
const BAND_ORDER: [&str; 6] = [
    "edge_cases_3_6",
    "edge_cases_3_8",
    "edge_cases_3_9",
    "edge_cases_3_10",
    "edge_cases_3_11",
    "edge_cases_3_12",
];
const DYNAMIC_CODE_NAMES: [&str; 7] = [
    "exec",
    "eval",
    "compile",
    "marshal",
    "__import__",
    "importlib",
    "__builtins__",
];

const DRIVER: &str = r"
import __future__, asyncio, builtins, inspect, re, sys, types

probe, path, support, hoist = sys.argv[1:5]
sys.path.insert(0, support)
sys.dont_write_bytecode = True
ADDRESS = re.compile(r' at 0x[0-9A-Fa-f]+')
answers = iter(['alpha', 'beta', 'q'])

def scripted_input(prompt=''):
    print('input', repr(prompt))
    return next(answers)

builtins.input = scripted_input

def emit(*parts):
    print(ADDRESS.sub(' at 0x', ' '.join(str(p) for p in parts)))

def plain(value, depth=0):
    if isinstance(value, (bool, int, float, complex, str, bytes, type(None))):
        return repr(value)
    if isinstance(value, (tuple, list, set, frozenset, dict)) and len(value) > 64:
        return f'<{type(value).__name__} of {len(value)}>'

    if depth < 3 and isinstance(value, (tuple, list)):
        inner = ', '.join(plain(v, depth + 1) for v in value)
        return f'{type(value).__name__}[{inner}]'
    if depth < 3 and isinstance(value, (set, frozenset)):
        inner = ', '.join(sorted(plain(v, depth + 1) for v in value))
        return f'{type(value).__name__}{{{inner}}}'
    if depth < 3 and isinstance(value, dict):
        inner = ', '.join(f'{plain(k, depth + 1)}: {plain(v, depth + 1)}' for k, v in value.items())
        return f'dict{{{inner}}}'
    return f'<{type(value).__name__}>'

def signature(fn):
    try:
        if sys.version_info >= (3, 14):
            import annotationlib
            found = inspect.signature(fn, annotation_format=annotationlib.Format.FORWARDREF)
        else:
            found = inspect.signature(fn)
        params = found.parameters.values()
    except Exception:
        return '(?)'
    shown = []
    for p in params:
        text = f'{p.kind.name}:{p.name}'
        if p.default is not inspect.Parameter.empty:
            text += '=' + plain(p.default)
        shown.append(text)
    return '(' + ', '.join(shown) + ')'

def describe(value):
    if isinstance(value, types.ModuleType):
        return f'module {value.__name__}'
    if inspect.isclass(value):
        members = sorted(k for k in vars(value) if not (k.startswith('__') and k.endswith('__')))
        bases = [b.__name__ for b in value.__bases__]
        return f'class {value.__qualname__} bases={bases} members={members}'
    if inspect.isfunction(value) or inspect.isbuiltin(value):
        return f'{type(value).__name__} {value.__qualname__}{signature(value)}'
    return plain(value)

source = open(path, encoding='utf-8').read()
flags = 0
if hoist == 'hoist-future':
    lines = source.splitlines(keepends=True)
    kept = [line for line in lines if line.strip() != 'from __future__ import annotations']
    if len(kept) != len(lines):
        flags = __future__.annotations.compiler_flag
    source = ''.join(kept)

module = types.ModuleType('__main__')
module.__file__ = path
sys.modules['__main__'] = module
try:
    code = compile(source, 'program.py', 'exec', flags, dont_inherit=True)
    exec(code, module.__dict__)
    status = 'completed'
except SystemExit as error:
    status = f'SystemExit {error.code!r}'
except BaseException as error:
    status = f'{type(error).__name__}: {error}'
emit('status', status)

ns = module.__dict__
for name in sorted(ns):
    if name.startswith('__') and name.endswith('__'):
        continue
    emit('defines', name, describe(ns[name]))

PROBES = {
    'recursive': lambda: [ns['fact'](n) for n in (0, 1, 6)],
    'class_decorator': lambda: (ns['Box'].decorated, ns['Box'](3).v, ns['deco'](type('Plain', (), {})).decorated),
    'async_fn': lambda: asyncio.run(ns['fetch']()),
    'generator': lambda: list(ns['gen']()),
    'lambda_in_listcomp': lambda: ns['data'],
    'walrus_operator': lambda: ns['values'],
    'match_statement': lambda: [ns['shape_area'](s) for s in (('circle', 2), ('square', 3), ('hex', 1), 'x')],
    'structural_pattern': lambda: [ns['kind'](p) for p in ({'type': 'cat', 'x': 1}, {'kind': 1}, [1])],
    'typing_generic': lambda: (ns['Holder'](5).value, ns['Holder'][int](7).value, ns['T'].__name__),
}
if probe in PROBES:
    try:
        emit('probe', plain(PROBES[probe]()))
    except BaseException as error:
        emit('probe-error', type(error).__name__, error)
";

const ALPHA: &str = r"
import ast, sys

IDENTIFIERS = {
    ('Name', 'id'), ('arg', 'arg'), ('FunctionDef', 'name'), ('AsyncFunctionDef', 'name'),
    ('ClassDef', 'name'), ('keyword', 'arg'), ('MatchAs', 'name'), ('MatchStar', 'name'),
    ('MatchMapping', 'rest'), ('Global', 'names'), ('Nonlocal', 'names'), ('ExceptHandler', 'name'),
    ('TypeVar', 'name'), ('ParamSpec', 'name'), ('TypeVarTuple', 'name'),
}

JUMPS = (ast.Return, ast.Raise, ast.Continue, ast.Break)

class Differs(Exception):
    pass

def is_string_statement(stmt):
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)

def dedent_else(stmts):
    out = []
    for stmt in stmts:
        if isinstance(stmt, ast.If) and stmt.orelse and stmt.body and isinstance(stmt.body[-1], JUMPS):
            tail = stmt.orelse
            stmt.orelse = []
            out.append(stmt)
            out.extend(dedent_else(tail))
        else:
            out.append(stmt)
    return out

class Normalize(ast.NodeTransformer):
    def generic_visit(self, node):
        super().generic_visit(node)
        for field in ('body', 'orelse', 'finalbody'):
            stmts = getattr(node, field, None)
            if isinstance(stmts, list) and all(isinstance(s, ast.stmt) for s in stmts):
                setattr(node, field, dedent_else([s for s in stmts if not is_string_statement(s)]))
        return node

def bind(spaces, space, got, want, where):
    forward, backward = spaces.setdefault(space, ({}, {}))
    if forward.setdefault(got, want) != want or backward.setdefault(want, got) != got:
        raise Differs(f'{where}: {got!r} cannot also stand for {want!r}')

def walk(got, want, spaces, where):
    if type(got) is not type(want):
        raise Differs(f'{where}: {type(got).__name__} != {type(want).__name__}')
    if isinstance(got, list):
        if len(got) != len(want):
            raise Differs(f'{where}: {len(got)} != {len(want)} items')
        for index, pair in enumerate(zip(got, want)):
            walk(pair[0], pair[1], spaces, f'{where}[{index}]')
        return
    if not isinstance(got, ast.AST):
        if got != want:
            raise Differs(f'{where}: {got!r} != {want!r}')
        return
    kind = type(got).__name__
    if kind == 'alias':
        if got.name != want.name:
            raise Differs(f'{where}: imports {got.name!r} != {want.name!r}')
        bind(spaces, 'name', got.asname or got.name.split('.')[0], want.asname or want.name.split('.')[0], where)
        return
    for field in got._fields:
        mine, theirs = getattr(got, field, None), getattr(want, field, None)
        if (kind, field) in IDENTIFIERS:
            mine = mine if isinstance(mine, list) else [mine]
            theirs = theirs if isinstance(theirs, list) else [theirs]
            if len(mine) != len(theirs) or any((a is None) != (b is None) for a, b in zip(mine, theirs)):
                raise Differs(f'{where}.{field}: {mine!r} != {theirs!r}')
            for a, b in zip(mine, theirs):
                if a is not None:
                    bind(spaces, 'name', a, b, f'{where}.{field}')
            continue
        if kind == 'Attribute' and field == 'attr':
            bind(spaces, 'attribute', mine, theirs, f'{where}.attr')
            continue
        walk(mine, theirs, spaces, f'{where}.{field}')

got = Normalize().visit(ast.parse(open(sys.argv[1], encoding='utf-8').read()))
want = Normalize().visit(ast.parse(open(sys.argv[2], encoding='utf-8').read()))
spaces = {}
try:
    walk(got, want, spaces, 'module')
except Differs as error:
    print('differs', error)
else:
    renamed = sum(1 for forward, _ in spaces.values() for a, b in forward.items() if a != b)
    print('alpha-equal', renamed)
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Original {
    EdgeCase(&'static str),
    Band(&'static str),
    FlattenedBand(&'static str),
    Authored(&'static str),
}

impl Original {
    const fn probe(self) -> &'static str {
        match self {
            Self::EdgeCase(name) => name,
            Self::Band(_) | Self::FlattenedBand(_) | Self::Authored(_) => "program",
        }
    }

    const fn hoists_future(self) -> bool {
        matches!(self, Self::FlattenedBand(_))
    }

    fn needs_band_support(self) -> bool {
        matches!(self, Self::Band(name) if name != BAND_SUPPORT)
    }

    fn source(self) -> String {
        match self {
            Self::EdgeCase(name) => common::edge_case_source(name).to_owned(),
            Self::Band(name) => read_text(&playground_dir().join(format!("{name}.py"))),
            Self::FlattenedBand(through) => flatten_band(through),
            Self::Authored(relative) => read_text(&repo_root().join(relative)),
        }
    }
}

struct Case {
    family: &'static str,
    fixture: &'static str,
    original: Original,
}

const fn case(family: &'static str, fixture: &'static str, original: Original) -> Case {
    Case {
        family,
        fixture,
        original,
    }
}

const EDGE: [&str; 9] = [
    "async_fn",
    "class_decorator",
    "generator",
    "lambda_in_listcomp",
    "match_statement",
    "recursive",
    "structural_pattern",
    "typing_generic",
    "walrus_operator",
];

const CLEAN_FACT_BOX: &str = "corpus/python/obfuscators/clean/fact_box.py";
const CLEAN_GREET_ENV: &str = "corpus/python/obfuscators/clean/greet_env.py";

fn edge_cases(
    family: &'static str,
    names: &[&'static str],
    path: fn(&'static str) -> &'static str,
) -> Vec<Case> {
    names
        .iter()
        .map(|name: &&'static str| case(family, path(name), Original::EdgeCase(name)))
        .collect()
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn cases() -> Vec<Case> {
    let mut all: Vec<Case> = Vec::new();
    let with_hello: Vec<&'static str> = EDGE.iter().copied().chain(["hello_world"]).collect();

    all.extend(edge_cases("berserker", &EDGE, |n| {
        leak(format!("berserker/edge-cases/real_{n}.py"))
    }));
    all.push(case(
        "berserker",
        "berserker/real_hello.py",
        Original::EdgeCase("hello_world"),
    ));
    all.push(case(
        "berserker",
        "berserker/real_sample.py",
        Original::FlattenedBand("edge_cases_3_8"),
    ));
    all.push(case(
        "berserker",
        "berserker/real_application.py",
        Original::FlattenedBand("edge_cases_3_12"),
    ));
    all.push(case(
        "berserker",
        "playground/clean_greeting.berserker.py",
        Original::Authored("corpus/python/obfuscators/playground/clean_greeting.py"),
    ));

    all.extend(edge_cases("blankobf", &with_hello, |n| {
        leak(format!("blankobf/edge-cases/real_{n}.py"))
    }));
    for fixture in [
        "blankobf/real_edge_cases_3_8_r1.py",
        "blankobf/real_edge_cases_3_8_r1_imports.py",
    ] {
        all.push(case("blankobf", fixture, Original::Band("edge_cases_3_8")));
    }

    all.extend(edge_cases("kramer", &with_hello, |n| {
        leak(format!("kramer/edge-cases/real_{n}_pre_compile.py"))
    }));
    all.push(case(
        "kramer",
        "kramer/real_edge_cases_3_8_pre_compile.py",
        Original::Band("edge_cases_3_8"),
    ));
    all.push(case(
        "kramer",
        "kramer/gauntlet/real_gauntlet_kramer.py",
        Original::Authored("corpus/python/obfuscators/kramer/gauntlet/clean_original.py"),
    ));
    all.push(case(
        "kramer",
        "kramer/gauntlet/real_pyc_artifact.py.fixture",
        Original::Authored("corpus/python/obfuscators/kramer/gauntlet/clean_app.py"),
    ));

    all.extend(edge_cases(
        "manglify",
        &[
            "async_fn",
            "hello_world",
            "lambda_in_listcomp",
            "typing_generic",
            "walrus_operator",
        ],
        |n| leak(format!("manglify/edge-cases/real_{n}.py")),
    ));
    all.push(case(
        "manglify",
        "manglify/real_edge_cases_3_8.py",
        Original::Band("edge_cases_3_8"),
    ));

    all.extend(edge_cases(
        "obfuxtreme",
        &[
            "async_fn",
            "class_decorator",
            "generator",
            "hello_world",
            "lambda_in_listcomp",
            "recursive",
            "typing_generic",
            "walrus_operator",
        ],
        |n| leak(format!("obfuxtreme/edge-cases/real_{n}.py.fixture")),
    ));
    all.push(case(
        "obfuxtreme",
        "obfuxtreme/real_edge_cases_3_8.py.fixture",
        Original::Band("edge_cases_3_8"),
    ));
    all.push(case(
        "obfuxtreme",
        "obfuxtreme/gauntlet/real_v4_artifact.py.fixture",
        Original::Authored("corpus/python/obfuscators/obfuxtreme/gauntlet/clean_app.py"),
    ));

    all.extend(edge_cases("plusobf", &with_hello, |n| {
        leak(format!("plusobf/edge-cases/real_{n}.py"))
    }));
    for fixture in [
        "plusobf/real_edge_cases_3_8_hash.py",
        "plusobf/real_edge_cases_3_8_plus.py",
    ] {
        all.push(case("plusobf", fixture, Original::Band("edge_cases_3_8")));
    }

    all.extend(edge_cases(
        "pyminifier",
        &[
            "async_fn",
            "class_decorator",
            "generator",
            "hello_world",
            "lambda_in_listcomp",
            "recursive",
            "typing_generic",
        ],
        |n| leak(format!("pyminifier/edge-cases/real_{n}.py")),
    ));
    for flags in [
        "obfuscate",
        "obfuscate_builtins",
        "obfuscate_classes",
        "obfuscate_functions",
        "obfuscate_variables",
    ] {
        all.push(case(
            "pyminifier",
            leak(format!("pyminifier/real_edge_cases_3_6_{flags}.py")),
            Original::Band("edge_cases_3_6"),
        ));
    }
    for variant in [
        "bzip2",
        "gzip",
        "lzma",
        "nominify",
        "obfuscate",
        "obfuscate_builtins",
        "obfuscate_bzip2",
        "obfuscate_classes",
        "obfuscate_functions",
        "obfuscate_gzip",
        "obfuscate_import_methods",
        "obfuscate_lzma",
        "obfuscate_variables",
        "prepend",
        "replacement_length_1",
        "replacement_length_2",
        "replacement_length_3",
        "use_tabs",
    ] {
        all.push(case(
            "pyminifier",
            leak(format!("pyminifier/variants/{variant}.py")),
            Original::Band("edge_cases_3_6"),
        ));
    }
    all.push(case(
        "pyminifier",
        "pyminifier/real_gauntlet_pyminifier.py",
        Original::Authored("corpus/python/obfuscators/pyminifier/gauntlet/clean_original.py"),
    ));

    all.extend(edge_cases("python_obfuscator_pypi", &EDGE, |n| {
        leak(format!("python_obfuscator_pypi/edge-cases/real_{n}.py"))
    }));
    all.push(case(
        "python_obfuscator_pypi",
        "python_obfuscator_pypi/real_hello.py",
        Original::EdgeCase("hello_world"),
    ));
    all.push(case(
        "python_obfuscator_pypi",
        "python_obfuscator_pypi/real_sample.py",
        Original::FlattenedBand("edge_cases_3_8"),
    ));
    all.push(case(
        "python_obfuscator_pypi",
        "python_obfuscator_pypi/real_application.py",
        Original::FlattenedBand("edge_cases_3_12"),
    ));

    all.extend(edge_cases("pyobfuscator_mauricelambert", &EDGE, |n| {
        leak(format!(
            "pyobfuscator_mauricelambert/edge-cases/real_{n}.py"
        ))
    }));
    all.push(case(
        "pyobfuscator_mauricelambert",
        "pyobfuscator_mauricelambert/real_hello.py",
        Original::EdgeCase("hello_world"),
    ));

    for (family, hello, sample, clean) in [
        (
            "online_family",
            "online_family/real_hello.py",
            "online_family/real_sample.py",
            CLEAN_FACT_BOX,
        ),
        (
            "pyobfuscate_com",
            "pyobfuscate_com/real_hello.py",
            "pyobfuscate_com/real_sample.py",
            CLEAN_FACT_BOX,
        ),
        (
            "pyobfus",
            "pyobfus/real_hello.py",
            "pyobfus/real_sample.py",
            CLEAN_GREET_ENV,
        ),
        (
            "pypacker",
            "pypacker/real_hello.py",
            "pypacker/real_sample.py",
            CLEAN_GREET_ENV,
        ),
    ] {
        all.push(case(family, hello, Original::EdgeCase("hello_world")));
        all.push(case(family, sample, Original::Authored(clean)));
    }
    all.push(case(
        "pyobfus",
        "pyobfus/real_marshal.py",
        Original::Authored(CLEAN_GREET_ENV),
    ));
    for fixture in ["pypacker/real_bz2.py", "pypacker/real_gzip.py"] {
        all.push(case(
            "pypacker",
            fixture,
            Original::Authored(CLEAN_GREET_ENV),
        ));
    }

    for (fixture, original) in [
        ("real_hello_world.py", "orig_hello.py"),
        ("real_hello_world.pyc", "orig_hello.py"),
        ("real_hello_world_norename.py", "orig_hello.py"),
        ("real_features.py", "orig_features.py"),
        ("real_arith_abyss.py", "orig_arith.py"),
        ("real_arith_abyss.pyc", "orig_arith.py"),
        ("real_compare_abyss.py", "orig_compare.py"),
        ("real_loops_abyss.py", "orig_loops.py"),
        ("real_comp_abyss.py", "orig_comp.py"),
        ("real_fstr_abyss.py", "orig_fstr.py"),
        ("real_walrus_abyss.py", "orig_walrus.py"),
    ] {
        all.push(case(
            "patchwork",
            leak(format!("patchwork/{fixture}")),
            Original::Authored(leak(format!(
                "corpus/python/obfuscators/patchwork/{original}"
            ))),
        ));
    }
    all
}

const KRAMER_WALRUS: &str = "the capture fed Kramer a walrus program other than the shared edge case and did not record it, so there is no authored original to compare";
const OBFUXTREME_WALRUS: &str = "the capture fed ObfuXtreme a walrus program other than the shared edge case and did not record it, and ObfuXtreme renamed its names";
const OBFUXTREME_ATTRIBUTES: &str = "ObfuXtreme renamed the class attributes MAX and NAME to random v_ names but not the f-string reads of them, so its own output fails and the names cannot be mapped back";
const OBFUXTREME_RENAMED: &str =
    "ObfuXtreme renamed variables to random v_ hex names and keeps no mapping in the file";
const MANGLIFY_WALRUS: &str = "the capture fed Manglify a walrus program other than the shared edge case (the recovered payload counts to three instead of reading input) and did not record it, so there is no authored original to compare";
const PYOBFUSCATOR_RENAMED: &str = "PyObfuscator renamed every identifier, attribute names included, and keeps no mapping in the file";
const PYOBFUSCATOR_PATTERNS: &str = "PyObfuscator rewrote the strings inside case patterns into decoder calls, which a pattern cannot hold, so its own output does not compile";
const PATCHWORK_RENAMED: &str = "Patchwork renamed module identifiers to random I, l, O and 0 names and keeps no mapping in the file";
const PYPI_EMPTY_CLASS_PATTERNS: &str = "python-obfuscator emitted empty class patterns (case :) for the 3.10 band, so its own output does not compile";
const PYPI_RENAMED_COLLIDING: &str = "python-obfuscator renamed identifiers without a mapping and gave the match subject the name of one of its capture patterns";
const PYPI_RENAMED_ANNOTATIONS: &str = "python-obfuscator renamed identifiers without a mapping, renaming TypeVars but not their uses in annotations";
const PYOBFUSCATOR_RENAMED_LITERAL: &str = "PyObfuscator renamed every identifier, attribute names included, keeps no mapping, and writes the True the decorator assigns as the integer 1";
const PYOBFUSCATOR_RENAMED_ANNOTATION: &str = "PyObfuscator renamed every identifier and keeps no mapping, and dropped the TypeVar annotation of the parameter";
const PYPI_RENAMED: &str =
    "python-obfuscator renamed identifiers to random names and keeps no mapping in the file";
const PYOBFUSCATE_COM_RENAMED: &str =
    "pyobfuscate.com renamed functions, classes and parameters and keeps no mapping in the file";
const PYMINIFIER_STRING_PREFIX: &str = "pyminifier 2.1 renamed the f and b string prefixes as identifiers, so its own output does not compile";
const PYMINIFIER_RENAMED: &str = "pyminifier renamed identifiers to short generated names and keeps no mapping in the file; several renames also miss f-string fields, breaking the tool's own output";

const RENAME_ONLY: [&str; 5] = [
    OBFUXTREME_RENAMED,
    PATCHWORK_RENAMED,
    PYOBFUSCATE_COM_RENAMED,
    PYOBFUSCATOR_RENAMED,
    PYPI_RENAMED,
];

const RESIDUALS: &[(&str, &str)] = &[
    (
        "manglify/edge-cases/real_walrus_operator.py",
        MANGLIFY_WALRUS,
    ),
    (
        "kramer/edge-cases/real_walrus_operator_pre_compile.py",
        KRAMER_WALRUS,
    ),
    (
        "obfuxtreme/edge-cases/real_lambda_in_listcomp.py.fixture",
        OBFUXTREME_RENAMED,
    ),
    (
        "obfuxtreme/edge-cases/real_walrus_operator.py.fixture",
        OBFUXTREME_WALRUS,
    ),
    (
        "obfuxtreme/real_edge_cases_3_8.py.fixture",
        OBFUXTREME_ATTRIBUTES,
    ),
    ("patchwork/real_arith_abyss.py", PATCHWORK_RENAMED),
    ("patchwork/real_arith_abyss.pyc", PATCHWORK_RENAMED),
    ("patchwork/real_comp_abyss.py", PATCHWORK_RENAMED),
    ("patchwork/real_compare_abyss.py", PATCHWORK_RENAMED),
    ("patchwork/real_features.py", PATCHWORK_RENAMED),
    ("patchwork/real_fstr_abyss.py", PATCHWORK_RENAMED),
    ("patchwork/real_hello_world.py", PATCHWORK_RENAMED),
    ("patchwork/real_hello_world.pyc", PATCHWORK_RENAMED),
    ("patchwork/real_loops_abyss.py", PATCHWORK_RENAMED),
    ("patchwork/real_walrus_abyss.py", PATCHWORK_RENAMED),
    ("pyobfuscate_com/real_sample.py", PYOBFUSCATE_COM_RENAMED),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_async_fn.py",
        PYOBFUSCATOR_RENAMED,
    ),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_class_decorator.py",
        PYOBFUSCATOR_RENAMED_LITERAL,
    ),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_generator.py",
        PYOBFUSCATOR_RENAMED,
    ),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_lambda_in_listcomp.py",
        PYOBFUSCATOR_RENAMED,
    ),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_match_statement.py",
        PYOBFUSCATOR_PATTERNS,
    ),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_recursive.py",
        PYOBFUSCATOR_RENAMED,
    ),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_structural_pattern.py",
        PYOBFUSCATOR_PATTERNS,
    ),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_typing_generic.py",
        PYOBFUSCATOR_RENAMED_ANNOTATION,
    ),
    (
        "pyobfuscator_mauricelambert/edge-cases/real_walrus_operator.py",
        PYOBFUSCATOR_RENAMED,
    ),
    ("pyminifier/edge-cases/real_async_fn.py", PYMINIFIER_RENAMED),
    (
        "pyminifier/edge-cases/real_class_decorator.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/edge-cases/real_generator.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/edge-cases/real_lambda_in_listcomp.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/edge-cases/real_recursive.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/edge-cases/real_typing_generic.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/real_edge_cases_3_6_obfuscate.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/real_edge_cases_3_6_obfuscate_builtins.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/real_edge_cases_3_6_obfuscate_classes.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/real_edge_cases_3_6_obfuscate_functions.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/real_edge_cases_3_6_obfuscate_variables.py",
        PYMINIFIER_RENAMED,
    ),
    ("pyminifier/real_gauntlet_pyminifier.py", PYMINIFIER_RENAMED),
    ("pyminifier/variants/obfuscate.py", PYMINIFIER_RENAMED),
    (
        "pyminifier/variants/obfuscate_builtins.py",
        PYMINIFIER_STRING_PREFIX,
    ),
    ("pyminifier/variants/obfuscate_bzip2.py", PYMINIFIER_RENAMED),
    (
        "pyminifier/variants/obfuscate_classes.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/variants/obfuscate_functions.py",
        PYMINIFIER_RENAMED,
    ),
    ("pyminifier/variants/obfuscate_gzip.py", PYMINIFIER_RENAMED),
    ("pyminifier/variants/obfuscate_lzma.py", PYMINIFIER_RENAMED),
    (
        "pyminifier/variants/obfuscate_variables.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/variants/replacement_length_1.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/variants/replacement_length_2.py",
        PYMINIFIER_RENAMED,
    ),
    (
        "pyminifier/variants/replacement_length_3.py",
        PYMINIFIER_RENAMED,
    ),
    ("pyminifier/variants/use_tabs.py", PYMINIFIER_STRING_PREFIX),
    (
        "python_obfuscator_pypi/edge-cases/real_async_fn.py",
        PYPI_RENAMED,
    ),
    (
        "python_obfuscator_pypi/edge-cases/real_class_decorator.py",
        PYPI_RENAMED,
    ),
    (
        "python_obfuscator_pypi/edge-cases/real_generator.py",
        PYPI_RENAMED,
    ),
    (
        "python_obfuscator_pypi/edge-cases/real_lambda_in_listcomp.py",
        PYPI_RENAMED,
    ),
    (
        "python_obfuscator_pypi/edge-cases/real_match_statement.py",
        PYPI_RENAMED_COLLIDING,
    ),
    (
        "python_obfuscator_pypi/edge-cases/real_recursive.py",
        PYPI_RENAMED,
    ),
    (
        "python_obfuscator_pypi/edge-cases/real_structural_pattern.py",
        PYPI_RENAMED,
    ),
    (
        "python_obfuscator_pypi/edge-cases/real_typing_generic.py",
        PYPI_RENAMED_ANNOTATIONS,
    ),
    (
        "python_obfuscator_pypi/edge-cases/real_walrus_operator.py",
        PYPI_RENAMED,
    ),
    (
        "python_obfuscator_pypi/real_application.py",
        PYPI_EMPTY_CLASS_PATTERNS,
    ),
    (
        "python_obfuscator_pypi/real_sample.py",
        PYPI_RENAMED_ANNOTATIONS,
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn playground_dir() -> PathBuf {
    repo_root()
        .join("corpus")
        .join("python")
        .join("decompile")
        .join("playground")
}

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "the authored original {} is unreadable ({e}); restore it with git checkout",
            path.display()
        )
    })
}

fn flatten_band(through: &str) -> String {
    let last: usize = BAND_ORDER
        .iter()
        .position(|band: &&str| *band == through)
        .unwrap_or_else(|| panic!("{through} is not a playground band"));
    let mut out: String = format!("\"\"\"Flattened band corpus through {through}.py.\"\"\"\n\n");
    for band in &BAND_ORDER[..=last] {
        out.push_str("\n# === inlined from ");
        out.push_str(band);
        out.push_str(".py ===\n\n");
        let text: String = read_text(&playground_dir().join(format!("{band}.py")));
        for line in text.lines() {
            if !line.starts_with("from edge_cases_") {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

fn dynamic_name_counts(source: &str) -> Option<BTreeMap<&'static str, usize>> {
    let parsed: Parsed<ModModule> = parse_module(source).ok()?;
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for token in parsed.tokens() {
        if token.kind() != TokenKind::Name {
            continue;
        }
        let text: &str = &source[token.range()];
        if let Some(name) = DYNAMIC_CODE_NAMES
            .iter()
            .find(|name: &&&str| **name == text)
        {
            *counts.entry(*name).or_default() += 1;
        }
    }
    Some(counts)
}

fn dynamic_code_excess(recovered: &str, original: &str) -> Option<&'static str> {
    let Some(got) = dynamic_name_counts(recovered) else {
        return Some("<unparsed>");
    };
    let want: BTreeMap<&'static str, usize> =
        dynamic_name_counts(original).expect("the authored original parses");
    DYNAMIC_CODE_NAMES.iter().copied().find(|name: &&str| {
        got.get(name).copied().unwrap_or(0) > want.get(name).copied().unwrap_or(0)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Run {
    exit_code: Option<i32>,
    stdout: String,
}

fn python() -> PathBuf {
    common::require_python_314()
}

fn drive(python: &Path, original: Original, source: &str) -> Run {
    let scratch: ScratchDir = ScratchDir::create("disrobe_py_obf_reexec").expect("scratch dir");
    let program: PathBuf = scratch.path().join(PROGRAM_FILE);
    std::fs::write(&program, source).expect("write program");
    if original.needs_band_support() {
        std::fs::write(
            scratch.path().join(format!("{BAND_SUPPORT}.py")),
            read_text(&playground_dir().join(format!("{BAND_SUPPORT}.py"))),
        )
        .expect("write band support module");
    }
    let driver: PathBuf = scratch.path().join("strict_driver.py");
    std::fs::write(&driver, DRIVER).expect("write driver");
    let hoist: &str = if original.hoists_future() {
        "hoist-future"
    } else {
        "as-written"
    };
    let output: ToolOutput = tool_output(
        CommandSpec::new(python, PYTHON_TIMEOUT)
            .arg("-I")
            .arg("-X")
            .arg("utf8")
            .arg(&driver)
            .arg(original.probe())
            .arg(&program)
            .arg(scratch.path())
            .arg(hoist)
            .current_dir(scratch.path().to_path_buf())
            .env("PYTHONHASHSEED", "0")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("USER", "grader"),
    )
    .unwrap_or_else(|e| panic!("running the strict driver failed: {e}"));
    assert!(
        !output.timed_out,
        "the strict driver timed out on a {original:?} program"
    );
    Run {
        exit_code: output.exit_code,
        stdout: output.stdout_text().replace("\r\n", "\n"),
    }
}

fn alpha(python: &Path, recovered: &str, original: &str) -> String {
    let scratch: ScratchDir = ScratchDir::create("disrobe_py_obf_alpha").expect("scratch dir");
    let got: PathBuf = scratch.path().join("recovered.py");
    let want: PathBuf = scratch.path().join("original.py");
    let script: PathBuf = scratch.path().join("alpha.py");
    std::fs::write(&got, recovered).expect("write recovery");
    std::fs::write(&want, original).expect("write original");
    std::fs::write(&script, ALPHA).expect("write alpha script");
    let output: ToolOutput = tool_output(
        CommandSpec::new(python, PYTHON_TIMEOUT)
            .arg("-I")
            .arg("-X")
            .arg("utf8")
            .arg(&script)
            .arg(&got)
            .arg(&want)
            .current_dir(scratch.path().to_path_buf()),
    )
    .unwrap_or_else(|e| panic!("running the alpha comparison failed: {e}"));
    assert!(
        output.success,
        "the alpha comparison must parse both programs: {}",
        output.stderr_text()
    );
    output.stdout_text().trim().to_owned()
}

fn expected_runs(python: &Path, cases: &[&Case]) -> BTreeMap<Original, Run> {
    let mut runs: BTreeMap<Original, Run> = BTreeMap::new();
    for case in cases {
        if runs.contains_key(&case.original) {
            continue;
        }
        let run: Run = drive(python, case.original, &case.original.source());
        assert_eq!(
            run.exit_code,
            Some(0),
            "the driver must run the authored original {:?} to completion: {}",
            case.original,
            run.stdout
        );
        assert!(
            run.stdout.lines().count() >= 2 && run.stdout.contains("status "),
            "the authored original {:?} printed too little to grade anything: {}",
            case.original,
            run.stdout
        );
        runs.insert(case.original, run);
    }
    runs
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Same,
    Differs(String),
    NotRecovered(String),
    StillWrapped(&'static str),
}

fn first_difference(got: &Run, want: &Run) -> String {
    if got.exit_code != want.exit_code {
        return format!("exit {:?} != {:?}", got.exit_code, want.exit_code);
    }
    let mut want_lines: std::str::Lines<'_> = want.stdout.lines();
    for (index, line) in got.stdout.lines().enumerate() {
        match want_lines.next() {
            Some(expected) if expected == line => {}
            Some(expected) => {
                return format!("line {index}: {line:?} != {expected:?}");
            }
            None => return format!("line {index}: extra {line:?}"),
        }
    }
    want_lines.next().map_or_else(
        || "identical".to_owned(),
        |missing: &str| format!("missing {missing:?}"),
    )
}

fn grade(python: &Path, case: &Case, expected: &Run) -> Verdict {
    let bytes: Vec<u8> = common::require_corpus_file(case.fixture);
    let result: PeelResult = match peel(&bytes) {
        Ok(result) => result,
        Err(error) => return Verdict::NotRecovered(format!("peel error: {error}")),
    };
    if !result.recovered {
        return Verdict::NotRecovered("peel reported no recovery".to_owned());
    }
    let original: String = case.original.source();
    if let Some(name) = dynamic_code_excess(&result.final_source, &original) {
        return Verdict::StillWrapped(name);
    }
    let got: Run = drive(python, case.original, &result.final_source);
    if got == *expected {
        Verdict::Same
    } else {
        Verdict::Differs(first_difference(&got, expected))
    }
}

fn grade_family(family: &str) {
    let python: PathBuf = python();
    let all: Vec<Case> = cases();
    let selected: Vec<&Case> = all.iter().filter(|c: &&Case| c.family == family).collect();
    assert!(!selected.is_empty(), "no strict cases for {family}");
    let expected: BTreeMap<Original, Run> = expected_runs(&python, &selected);
    let mut failing: BTreeMap<&str, Verdict> = BTreeMap::new();
    for case in &selected {
        let verdict: Verdict = grade(&python, case, &expected[&case.original]);
        if verdict != Verdict::Same {
            failing.insert(case.fixture, verdict);
        }
    }
    let pinned: BTreeSet<&str> = RESIDUALS
        .iter()
        .map(|(fixture, _): &(&str, &str)| *fixture)
        .filter(|fixture: &&str| selected.iter().any(|c: &&Case| c.fixture == *fixture))
        .collect();
    let observed: BTreeSet<&str> = failing.keys().copied().collect();
    assert_eq!(
        observed,
        pinned,
        "{family}: RESIDUALS only shrinks. Remove a fixture once its recovered source behaves \
         like the authored original, and never add one to hide a regression. {} of {} cases \
         re-execute like their original; failing verdicts: {failing:#?}",
        selected.len() - failing.len(),
        selected.len()
    );
}

#[test]
fn every_residual_names_a_reason_and_a_known_case() {
    let all: Vec<Case> = cases();
    let fixtures: BTreeSet<&str> = all.iter().map(|c: &Case| c.fixture).collect();
    assert_eq!(fixtures.len(), all.len(), "a fixture is graded twice");
    for (fixture, reason) in RESIDUALS {
        assert!(fixtures.contains(fixture), "{fixture} is not a strict case");
        assert!(reason.len() > 20, "{fixture} needs a named residual reason");
    }
    for case in &all {
        common::require_corpus_file(case.fixture);
    }
}

#[test]
fn authored_originals_match_their_manifest_hashes() {
    let manifest: toml::Value = toml::from_str(&read_text(
        &repo_root().join("corpus/python/obfuscators/MANIFEST.toml"),
    ))
    .expect("the obfuscator MANIFEST parses");
    let rows: &toml::value::Table = manifest["obfuscators"]["clean"]["fixtures"]
        .as_table()
        .expect("the clean originals have MANIFEST rows");
    for path in [CLEAN_FACT_BOX, CLEAN_GREET_ENV, REMAP_SUBJECT] {
        let row: &toml::Value = rows
            .values()
            .find(|row: &&toml::Value| row["path"].as_str() == Some(path))
            .unwrap_or_else(|| panic!("{path} has no MANIFEST row"));
        let bytes: Vec<u8> = std::fs::read(repo_root().join(path)).expect("read original");
        assert_eq!(
            row["sha256"].as_str(),
            Some(format!("{:x}", Sha256::digest(&bytes)).as_str()),
            "{path} changed since it was recorded, so it no longer grades its fixtures"
        );
    }
}

#[test]
fn berserker_recoveries_reexecute_like_their_originals() {
    grade_family("berserker");
}

#[test]
fn blankobf_recoveries_reexecute_like_their_originals() {
    grade_family("blankobf");
}

#[test]
fn kramer_recoveries_reexecute_like_their_originals() {
    grade_family("kramer");
}

#[test]
fn manglify_recoveries_reexecute_like_their_originals() {
    grade_family("manglify");
}

#[test]
fn obfuxtreme_recoveries_reexecute_like_their_originals() {
    grade_family("obfuxtreme");
}

#[test]
fn plusobf_recoveries_reexecute_like_their_originals() {
    grade_family("plusobf");
}

#[test]
fn pyminifier_recoveries_reexecute_like_their_originals() {
    grade_family("pyminifier");
}

#[test]
fn python_obfuscator_pypi_recoveries_reexecute_like_their_originals() {
    grade_family("python_obfuscator_pypi");
}

#[test]
fn pyobfuscator_mauricelambert_recoveries_reexecute_like_their_originals() {
    grade_family("pyobfuscator_mauricelambert");
}

#[test]
fn online_family_recoveries_reexecute_like_their_originals() {
    grade_family("online_family");
}

#[test]
fn pyobfuscate_com_recoveries_reexecute_like_their_originals() {
    grade_family("pyobfuscate_com");
}

#[test]
fn pyobfus_recoveries_reexecute_like_their_originals() {
    grade_family("pyobfus");
}

#[test]
fn pypacker_recoveries_reexecute_like_their_originals() {
    grade_family("pypacker");
}

#[test]
fn patchwork_recoveries_reexecute_like_their_originals() {
    grade_family("patchwork");
}

#[test]
fn rename_only_residuals_match_their_originals_up_to_names() {
    let python: PathBuf = python();
    let all: Vec<Case> = cases();
    let mut graded: usize = 0;
    let mut wrong: BTreeMap<&str, String> = BTreeMap::new();
    for (fixture, reason) in RESIDUALS {
        if !RENAME_ONLY.contains(reason) {
            continue;
        }
        let case: &Case = all
            .iter()
            .find(|c: &&Case| c.fixture == *fixture)
            .unwrap_or_else(|| panic!("{fixture} is not a strict case"));
        let bytes: Vec<u8> = common::require_corpus_file(fixture);
        let recovered: String = peel(&bytes)
            .unwrap_or_else(|e| panic!("{fixture} no longer peels: {e}"))
            .final_source;
        let verdict: String = alpha(&python, &recovered, &case.original.source());
        let renamed: Option<usize> = verdict
            .strip_prefix("alpha-equal ")
            .and_then(|count: &str| count.parse::<usize>().ok());
        if renamed.is_none_or(|count: usize| count == 0) {
            wrong.insert(fixture, verdict);
        }
        graded += 1;
    }
    assert!(
        graded >= 20,
        "only {graded} rename-only residuals were graded"
    );
    assert!(
        wrong.is_empty(),
        "a residual named as renamed-only must equal its original once identifiers are mapped one to one; rename its reason if the tool changed more than names: {wrong:#?}"
    );
}

#[test]
fn mutation_controls_turn_the_strict_grader_red() {
    let python: PathBuf = python();
    let original: Original = Original::EdgeCase("recursive");
    let clean: String = original.source();
    let expected: Run = drive(&python, original, &clean);
    assert_eq!(drive(&python, original, &clean), expected);

    let changed_literal: String = clean.replacen("return 1", "return 2", 1);
    assert_ne!(changed_literal, clean);
    assert_ne!(
        drive(&python, original, &changed_literal),
        expected,
        "a changed literal must change the probe output"
    );

    let junk_variable: String = format!("{clean}aAaAa = 458\n");
    assert_ne!(
        drive(&python, original, &junk_variable),
        expected,
        "a leftover junk assignment must change the module inventory"
    );

    let renamed: String = clean.replace("fact", "func_0");
    assert_ne!(
        drive(&python, original, &renamed),
        expected,
        "a lost identifier must change the module inventory and the probe"
    );

    assert_ne!(
        drive(&python, original, ""),
        expected,
        "an empty recovery must not grade as recovered"
    );

    let wrapped: String = format!("exec({clean:?})\n");
    assert_eq!(
        dynamic_code_excess(&wrapped, &clean),
        Some("exec"),
        "a recovery that still execs a payload must never run"
    );

    assert_eq!(alpha(&python, &renamed, &clean), "alpha-equal 1");
    assert_eq!(alpha(&python, &clean, &clean), "alpha-equal 0");
    for (mutant, what) in [
        (&junk_variable, "a leftover junk assignment"),
        (&changed_literal, "a changed literal"),
        (
            &clean.replace("n - 1", "n - True"),
            "an int turned into a bool",
        ),
        (
            &clean.replace("return n *", "return fact *"),
            "two names merged into one",
        ),
    ] {
        assert!(
            alpha(&python, mutant, &clean).starts_with("differs "),
            "{what} must not count as a rename"
        );
    }
}

const REMAP_SUBJECT: &str = "corpus/python/obfuscators/clean/remap_subject.py";
const REMAP_PARTIAL_CUT: &str = "def summarize(";
const STOCK_RESUME_312: u8 = 151;

const fn custom_interpreter_opcode(stock: u8) -> u8 {
    stock.wrapping_mul(167).wrapping_add(89)
}

fn compile_312(python: &Path, source: &str) -> Vec<u8> {
    let scratch: ScratchDir = ScratchDir::create("disrobe_py_obf_remap").expect("scratch dir");
    let source_path: PathBuf = scratch.path().join("remap_subject.py");
    let pyc_path: PathBuf = scratch.path().join("remap_subject.pyc");
    let script: PathBuf = scratch.path().join("compile.py");
    std::fs::write(&source_path, source).expect("write subject");
    std::fs::write(
        &script,
        "import py_compile, sys\npy_compile.compile(sys.argv[1], cfile=sys.argv[2], dfile='remap_subject.py', doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)\n",
    )
    .expect("write compile script");
    let output: ToolOutput = tool_output(
        CommandSpec::new(python, PYTHON_TIMEOUT)
            .arg("-I")
            .arg(&script)
            .arg(&source_path)
            .arg(&pyc_path)
            .current_dir(scratch.path().to_path_buf()),
    )
    .unwrap_or_else(|e| panic!("CPython 3.12 could not compile the remap subject: {e}"));
    assert!(
        output.success,
        "CPython 3.12 must compile the authored remap subject: {}",
        output.stderr_text()
    );
    std::fs::read(&pyc_path).expect("read compiled pyc")
}

fn pyc_remap_detection(bytes: &[u8]) -> RemapDetection {
    let file: PycFile = read_pyc(bytes).expect("pyc parses");
    let Object::Code(code) = &file.code else {
        panic!("the pyc holds no code object");
    };
    detect_opcode_remap(code, file.header.version)
}

fn permute_opcodes(code: &mut CodeObject) {
    for op in code.code.iter_mut().step_by(2) {
        *op = custom_interpreter_opcode(*op);
    }
    for konst in &mut code.consts {
        if let Object::Code(inner) = konst {
            permute_opcodes(inner);
        }
    }
}

fn custom_interpreter_pyc(stock: &[u8]) -> Vec<u8> {
    let mut file: PycFile = read_pyc(stock).expect("stock pyc parses");
    let Object::Code(code) = &mut file.code else {
        panic!("stock pyc holds no code object");
    };
    permute_opcodes(code);
    write_pyc(&file).expect("remapped pyc writes")
}

#[test]
fn custom_interpreter_opcode_tables_are_named_and_recovered_from_a_stock_reference() {
    let python: PathBuf = common::require_python_312();
    let subject: String = read_text(&repo_root().join(REMAP_SUBJECT));
    let stock: Vec<u8> = compile_312(&python, &subject);
    let remapped: Vec<u8> = custom_interpreter_pyc(&stock);
    assert_ne!(remapped, stock);

    assert_eq!(pyc_remap_detection(&stock).verdict, RemapVerdict::Standard);
    let detection: RemapDetection = pyc_remap_detection(&remapped);
    assert_eq!(detection.verdict, RemapVerdict::Remapped, "{detection:?}");
    assert_eq!(
        detection.entry_opcode,
        Some(custom_interpreter_opcode(STOCK_RESUME_312))
    );

    let refusal: Error = peel(&remapped).expect_err("a remapped pyc must be refused, not guessed");
    assert!(
        matches!(
            refusal,
            Error::OpcodeRemap {
                major: 3,
                minor: 12,
                ..
            }
        ),
        "{refusal}"
    );
    assert!(
        refusal.to_string().contains("cpython-opcode-remap"),
        "{refusal}"
    );
    assert!(
        !matches!(peel(&stock), Err(Error::OpcodeRemap { .. })),
        "stock CPython output must never be reported as remapped"
    );

    let recovery: RemappedRecovery =
        recover_remapped_pyc(&remapped, &stock).expect("the stock reference covers every opcode");
    assert!(recovery.complete, "{}", recovery.source);
    assert!(recovery.aligned_code_objects >= 7);
    let original: Original = Original::Authored(REMAP_SUBJECT);
    let expected: Run = drive(&python, original, &subject);
    assert!(expected.stdout.contains("ann 282"), "{}", expected.stdout);
    assert_eq!(
        drive(&python, original, &recovery.source),
        expected,
        "the source decompiled through the recovered table must behave like the authored original:\n{}",
        recovery.source
    );

    let partial_reference: Vec<u8> = compile_312(
        &python,
        subject
            .split_once(REMAP_PARTIAL_CUT)
            .map(|(head, _): (&str, &str)| head)
            .expect("the subject defines summarize"),
    );
    let uncovered: Error = recover_remapped_pyc(&remapped, &partial_reference)
        .expect_err("a reference that lacks opcodes the file uses must be refused");
    assert!(
        matches!(uncovered, Error::OpcodeTable(RemapError::Uncovered { .. })),
        "{uncovered}"
    );

    let mut tampered: PycFile = read_pyc(&remapped).expect("remapped pyc parses");
    let Object::Code(code) = &mut tampered.code else {
        panic!("remapped pyc holds no code object");
    };
    code.code[1] ^= 1;
    let tampered: Vec<u8> = write_pyc(&tampered).expect("tampered pyc writes");
    assert!(
        matches!(
            recover_remapped_pyc(&tampered, &stock),
            Err(Error::OpcodeTable(RemapError::OperandMismatch { .. }))
        ),
        "an operand change is not an opcode permutation and must be refused"
    );
}
