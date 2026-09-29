#![allow(clippy::expect_used, clippy::panic)]

use disrobe_pass_pickle::{
    Disassembly, PickleValue, Reconstruction, Session, disassemble, reconstruct,
};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const PYTHON_OVERRIDE_VAR: &str = "DISROBE_PYTHON";

const IMPORTED_NAMES: &str = "import ast, sys\n\
tree = ast.parse(sys.stdin.read())\n\
names = sorted({alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names})\n\
print(' '.join(names))\n";

fn python() -> String {
    std::env::var(PYTHON_OVERRIDE_VAR)
        .into_iter()
        .chain(["python", "python3"].map(str::to_owned))
        .find(|exe: &String| {
            Command::new(exe)
                .arg("--version")
                .output()
                .is_ok_and(|o: Output| o.status.success())
        })
        .unwrap_or_else(|| {
            panic!(
                "the reconstructed program is graded by CPython's own parser, and no python is on \
                 PATH; install CPython 3.11 or newer or point {PYTHON_OVERRIDE_VAR} at one"
            )
        })
}

fn imported_names(program: &str) -> String {
    let mut child: std::process::Child = Command::new(python())
        .args(["-I", "-c", IMPORTED_NAMES])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(program.as_bytes())
        .expect("write the program");
    let output: Output = child.wait_with_output().expect("python finishes");
    assert!(
        output.status.success(),
        "CPython rejected the reconstructed program: {}\n{program}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn an_injected_stack_global_parses_without_becoming_an_import() {
    let module: &[u8] = b"os\nimport shutil;shutil.rmtree('x')#";
    let mut stream: Vec<u8> = vec![0x80, 0x04, 0x8C];
    stream.push(u8::try_from(module.len()).expect("short module"));
    stream.extend_from_slice(module);
    stream.extend_from_slice(b"\x8C\x06system\x93.");
    let dis: Disassembly = disassemble(&stream).expect("disassemble");
    let mut session: Session = Session::new();
    let value: PickleValue = session.run(&dis).expect("the symbolic vm runs");
    let rebuilt: Reconstruction = reconstruct(&value, session.memo(), session.root_memo_key());
    assert!(!rebuilt.reexecutable, "{}", rebuilt.program);
    let imported: String = imported_names(&rebuilt.program);
    assert!(
        !imported.split(' ').any(|name: &str| name == "shutil"),
        "the module name became an import statement ({imported}):\n{}",
        rebuilt.program
    );
    assert!(
        !rebuilt.program.contains('\u{202e}')
            && !rebuilt
                .program
                .lines()
                .any(|line: &str| line.trim_start().starts_with("import shutil")),
        "{}",
        rebuilt.program
    );
}
