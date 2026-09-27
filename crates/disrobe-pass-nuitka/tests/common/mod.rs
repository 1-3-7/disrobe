#![allow(dead_code, unreachable_pub, clippy::panic, clippy::expect_used)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const REQUIRE_LOCAL_CORPUS_VAR: &str = "DISROBE_REQUIRE_NUITKA_LOCAL_CORPUS";
pub const REQUIRE_NUITKA_VAR: &str = "DISROBE_REQUIRE_NUITKA";

const PROBE: &str = "import importlib.util, sys; \
                     print(f'{sys.version_info[0]}.{sys.version_info[1]}'); \
                     print(importlib.util.find_spec('nuitka') is not None); \
                     print(sys.executable)";

pub const SIGNATURE_PROBE: &str = "import ast, sys\n\
def signatures(path):\n\
\x20   tree = ast.parse(open(path, encoding='utf-8').read())\n\
\x20   return {f.name: (ast.dump(f.args), ast.dump(f.returns) if f.returns else None)\n\
\x20           for f in tree.body if isinstance(f, ast.FunctionDef)}\n\
recovered = signatures(sys.argv[1])\n\
expected = signatures(sys.argv[2])\n\
assert recovered == expected, f'recovered {recovered!r} != reference {expected!r}'\n";

const AST_PROBE: &str = "import ast, sys\n\
def definitions(path):\n\
\x20   tree = ast.parse(open(path, encoding='utf-8').read())\n\
\x20   return {node.name: ast.dump(node) for node in tree.body if isinstance(node, ast.FunctionDef)}\n\
recovered = definitions(sys.argv[1])\n\
original = definitions(sys.argv[2])\n\
names = sys.argv[3:] or sorted(original)\n\
assert sorted(recovered) == sorted(original), f'functions {sorted(recovered)} != {sorted(original)}'\n\
for name in names:\n\
\x20   assert recovered[name] == original[name], f'{name}:\\nrecovered {recovered[name]}\\noriginal  {original[name]}'\n";

pub fn assert_functions_match_original_ast(recovered_source: &str, module: &str, names: &[&str]) {
    let python: PathBuf = python314();
    let original: PathBuf = tracked(&format!("module/{module}.src.py"));
    let purpose: String = format!("disrobe-nuitka-ast-{module}-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let recovered: PathBuf = scratch.path().join(format!("recovered_{module}.py"));
    std::fs::write(&recovered, recovered_source.as_bytes()).expect("write recovered source");
    let output: Output = Command::new(&python)
        .env("PYTHONIOENCODING", "utf-8")
        .args(["-c", AST_PROBE])
        .arg(&recovered)
        .arg(&original)
        .args(names)
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("spawn CPython 3.14 at {}: {error}", python.display())
        });
    assert!(
        output.status.success(),
        "recovered {module} definitions {names:?} must be AST-equal to {module}.src.py:\n{}\n\
         RECOVERED:\n{recovered_source}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
        .join("nuitka")
}

pub fn tracked(relative: &str) -> PathBuf {
    let path: PathBuf = corpus_root().join(relative);
    assert!(
        path.is_file(),
        "the tracked Nuitka fixture {} is missing; restore it with git checkout, because this \
         test never regenerates fixtures",
        path.display()
    );
    path
}

pub fn read_tracked(relative: &str) -> Vec<u8> {
    let path: PathBuf = tracked(relative);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!("read the tracked fixture {}: {error}", path.display())
    })
}

pub fn read_tracked_text(relative: &str) -> String {
    let path: PathBuf = tracked(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!("read the tracked fixture {}: {error}", path.display())
    })
}

pub fn regen_hello_source() -> String {
    let script: &str = include_str!("../../regen.ps1");
    let marker: &str = script
        .lines()
        .find_map(|line: &str| line.trim().strip_prefix("$PlantedMarker = '"))
        .and_then(|rest: &str| rest.strip_suffix('\''))
        .expect("regen.ps1 assigns $PlantedMarker on one line");
    let body: &str = script
        .split_once("$body = @\"\n")
        .or_else(|| script.split_once("$body = @\"\r\n"))
        .and_then(|(_, rest): (&str, &str)| {
            rest.split_once("\n\"@").map(|(body, _): (&str, &str)| body)
        })
        .expect("regen.ps1 writes hello.py from one here-string");
    format!(
        "{}\n",
        body.replace("$PlantedMarker", marker).replace('\r', "")
    )
}

pub fn local_only(relative: &str) -> Option<PathBuf> {
    let path: PathBuf = corpus_root().join(relative);
    if path.exists() {
        return Some(path);
    }
    assert!(
        std::env::var_os(REQUIRE_LOCAL_CORPUS_VAR).is_none(),
        "{REQUIRE_LOCAL_CORPUS_VAR} is set, so the local-only Nuitka fixture {} must exist",
        path.display()
    );
    eprintln!(
        "UNGRADED: the local-only Nuitka fixture {} is absent; set {REQUIRE_LOCAL_CORPUS_VAR}=1 \
         to fail instead",
        path.display()
    );
    None
}

#[derive(Debug)]
struct Interpreter {
    version: String,
    has_nuitka: bool,
    executable: PathBuf,
}

fn probe(program: &OsStr, prefix: &[&str]) -> Result<Interpreter, String> {
    let output: Output = Command::new(program)
        .args(prefix)
        .args(["-c", PROBE])
        .output()
        .map_err(|error: std::io::Error| format!("does not start ({error})"))?;
    if !output.status.success() {
        return Err(format!(
            "exits with {} ({})",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let lines: Vec<&str> = stdout.lines().map(str::trim).collect();
    let [version, has_nuitka, executable] = lines.as_slice() else {
        return Err(format!("prints an unexpected probe answer {stdout:?}"));
    };
    Ok(Interpreter {
        version: (*version).to_owned(),
        has_nuitka: *has_nuitka == "True",
        executable: PathBuf::from(executable),
    })
}

fn uv_python_find() -> Result<PathBuf, String> {
    let output: Output = Command::new("uv")
        .args(["python", "find", "3.14"])
        .output()
        .map_err(|error: std::io::Error| format!("does not start ({error})"))?;
    if !output.status.success() {
        return Err(format!(
            "exits with {} ({})",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let found: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if found.is_empty() {
        return Err("prints no interpreter path".to_owned());
    }
    Ok(PathBuf::from(found))
}

fn accept(interpreter: Result<Interpreter, String>, need_nuitka: bool) -> Result<PathBuf, String> {
    let interpreter: Interpreter = interpreter?;
    if interpreter.version != "3.14" {
        return Err(format!("is Python {}", interpreter.version));
    }
    if need_nuitka && !interpreter.has_nuitka {
        return Err(format!(
            "is Python 3.14 at {} without an importable nuitka",
            interpreter.executable.display()
        ));
    }
    Ok(interpreter.executable)
}

fn locate(need_nuitka: bool) -> Result<PathBuf, Vec<String>> {
    let mut tried: Vec<String> = Vec::new();
    match uv_python_find() {
        Ok(found) => match accept(probe(found.as_os_str(), &[]), need_nuitka) {
            Ok(executable) => return Ok(executable),
            Err(why) => tried.push(format!(
                "`uv python find 3.14` -> {}: {why}",
                found.display()
            )),
        },
        Err(why) => tried.push(format!("`uv python find 3.14` {why}")),
    }
    let launchers: [(&str, &[&str]); 3] =
        [("py", &["-3.14"]), ("python3.14", &[]), ("python", &[])];
    for (program, prefix) in launchers {
        match accept(probe(OsStr::new(program), prefix), need_nuitka) {
            Ok(executable) => return Ok(executable),
            Err(why) => {
                let label: String = std::iter::once(program)
                    .chain(prefix.iter().copied())
                    .collect::<Vec<&str>>()
                    .join(" ");
                tried.push(format!("`{label}` {why}"));
            }
        }
    }
    Err(tried)
}

pub fn python314() -> PathBuf {
    locate(false).unwrap_or_else(|tried: Vec<String>| {
        panic!(
            "CPython 3.14 is required (CI installs it with uv on every shard); none of the \
             candidates answered as 3.14: {}",
            tried.join("; ")
        )
    })
}

pub fn python314_with_nuitka() -> Option<PathBuf> {
    match locate(true) {
        Ok(executable) => Some(executable),
        Err(tried) => {
            assert!(
                std::env::var_os(REQUIRE_NUITKA_VAR).is_none(),
                "{REQUIRE_NUITKA_VAR} is set, so a CPython 3.14 with Nuitka importable is \
                 required; tried: {}",
                tried.join("; ")
            );
            eprintln!(
                "UNGRADED: no CPython 3.14 with Nuitka importable ({}); set \
                 {REQUIRE_NUITKA_VAR}=1 to fail instead",
                tried.join("; ")
            );
            None
        }
    }
}

pub fn run_python(python: &Path, code: &str, args: &[&Path]) -> Output {
    Command::new(python)
        .env("PYTHONIOENCODING", "utf-8")
        .args(["-c", code])
        .args(args)
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("spawn CPython 3.14 at {}: {error}", python.display())
        })
}
