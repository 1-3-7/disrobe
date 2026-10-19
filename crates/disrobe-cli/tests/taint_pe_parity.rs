#![cfg(windows)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use serde_json::Value;

const COMPILE_TIMEOUT: Duration = Duration::from_mins(1);
const TAINT_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

const PRELUDE: &str = r"
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAINT_EXPORT __declspec(dllexport) __attribute__((noinline))
";

const WRITERS: &str = r#"
char *published_command;

void run_through_pointer(char **command);
void run_published(void);
void run_received(char *command);
void run_constant(char *command);
char *append_environment(char *data);
char *append_environment_elsewhere(char *data);

static int read_into(char *data)
{
    size_t length = strlen(data);
    return fgets(data + length, (int)(64 - length), stdin) != NULL;
}

TAINT_EXPORT void pointer_cell_tainted(void)
{
    char buffer[64] = "dir ";
    char *data = buffer;
    if (!read_into(data)) return;
    run_through_pointer(&data);
}

TAINT_EXPORT void pointer_cell_redirected(void)
{
    char buffer[64] = "dir ";
    char clean[64] = "dir";
    char *data = buffer;
    if (!read_into(data)) return;
    data = clean;
    run_through_pointer(&data);
}

TAINT_EXPORT void returned_pointer_tainted(void)
{
    char buffer[64] = "dir ";
    char *data = append_environment(buffer);
    system(data);
}

TAINT_EXPORT void returned_pointer_elsewhere(void)
{
    char buffer[64] = "dir ";
    char *data = append_environment_elsewhere(buffer);
    system(data);
}

TAINT_EXPORT void global_pointer_tainted(void)
{
    char buffer[64] = "dir ";
    char *data = buffer;
    if (!read_into(data)) return;
    published_command = data;
    run_published();
}

TAINT_EXPORT void global_pointer_redirected(void)
{
    char buffer[64] = "dir ";
    char clean[64] = "dir";
    char *data = buffer;
    if (!read_into(data)) return;
    published_command = clean;
    run_published();
}

TAINT_EXPORT void function_pointer_tainted(void)
{
    char buffer[64] = "dir ";
    void (*volatile runner)(char *) = run_received;
    if (!read_into(buffer)) return;
    runner(buffer);
}

TAINT_EXPORT void function_pointer_constant(void)
{
    char buffer[64] = "dir ";
    void (*volatile runner)(char *) = run_constant;
    if (!read_into(buffer)) return;
    runner(buffer);
}

TAINT_EXPORT void socket_input_tainted(SOCKET peer)
{
    char buffer[64] = "dir ";
    size_t length = strlen(buffer);
    int received = recv(peer, buffer + length, (int)(63 - length), 0);
    if (received <= 0) return;
    buffer[length + (size_t)received] = '\0';
    if (system(buffer) != 0) exit(1);
}

int main(void)
{
    pointer_cell_tainted();
    pointer_cell_redirected();
    returned_pointer_tainted();
    returned_pointer_elsewhere();
    global_pointer_tainted();
    global_pointer_redirected();
    function_pointer_tainted();
    function_pointer_constant();
    socket_input_tainted(INVALID_SOCKET);
    return 0;
}
"#;

const READERS: &str = r#"
extern char *published_command;

static char elsewhere[64] = "dir";

void run_through_pointer(char **command)
{
    system(*command);
}

void run_published(void)
{
    system(published_command);
}

void run_received(char *command)
{
    system(command);
}

void run_constant(char *command)
{
    (void)command;
    system("dir");
}

char *append_environment(char *data)
{
    size_t length = strlen(data);
    char *environment = getenv("ADD");
    if (environment != NULL) strncat(data + length, environment, 63 - length);
    return data;
}

char *append_environment_elsewhere(char *data)
{
    size_t length = strlen(data);
    char *environment = getenv("ADD");
    if (environment != NULL) strncat(data + length, environment, 63 - length);
    return elsewhere;
}
"#;

const HARNESS_VERDICTS: [(&str, bool); 9] = [
    ("pointer_cell_tainted", true),
    ("pointer_cell_redirected", false),
    ("returned_pointer_tainted", true),
    ("returned_pointer_elsewhere", false),
    ("global_pointer_tainted", true),
    ("global_pointer_redirected", false),
    ("function_pointer_tainted", true),
    ("function_pointer_constant", false),
    ("socket_input_tainted", true),
];

fn disrobe_bin() -> PathBuf {
    let bin: PathBuf = PathBuf::from(std::env::var_os("DISROBE_BIN").expect(
        "DISROBE_BIN must name the disrobe binary built by `cargo build -p disrobe-cli --bin disrobe` for this caller test",
    ));
    assert!(
        bin.is_file(),
        "DISROBE_BIN does not name a file: {}",
        bin.display()
    );
    bin
}

fn run(program: &Path, args: &[OsString], timeout: Duration) -> CapturedOutput {
    run_captured(program, args, timeout, MAX_CAPTURE_BYTES)
        .unwrap_or_else(|error| panic!("cannot start {}: {error}", program.display()))
        .unwrap_or_else(|| panic!("{} exceeded its timeout", program.display()))
}

struct Image {
    _directory: ScratchDir,
    path: PathBuf,
}

fn compile(opt_flag: &str) -> Image {
    let directory: ScratchDir =
        ScratchDir::create("disrobe-cli-taint-pe-parity").expect("create fixture directory");
    let writers: PathBuf = directory.path().join("writers.c");
    let readers: PathBuf = directory.path().join("readers.c");
    std::fs::write(&writers, format!("{PRELUDE}{WRITERS}")).expect("write writers.c");
    std::fs::write(&readers, format!("{PRELUDE}{READERS}")).expect("write readers.c");
    let path: PathBuf = directory.path().join("fixture.exe");
    let args: Vec<OsString> = vec![
        opt_flag.into(),
        "-fno-builtin".into(),
        writers.into_os_string(),
        readers.into_os_string(),
        "-o".into(),
        path.as_os_str().to_owned(),
        "-lws2_32".into(),
    ];
    let output: CapturedOutput = run(Path::new("gcc"), &args, COMPILE_TIMEOUT);
    assert_eq!(
        output.exit_code,
        Some(0),
        "gcc {opt_flag} failed to build the taint parity fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Image {
        _directory: directory,
        path,
    }
}

const PE32_PLUS_MAGIC: u16 = 0x20b;
const BASE_RELOCATION_DIRECTORY: usize = 5;

fn without_base_relocations(image: &Image) -> PathBuf {
    let mut bytes: Vec<u8> = std::fs::read(&image.path).expect("read fixture image");
    let header: usize =
        u32::from_le_bytes(bytes[0x3c..0x40].try_into().expect("e_lfanew")) as usize;
    assert_eq!(
        &bytes[header..header + 4],
        b"PE\0\0",
        "fixture is a PE image"
    );
    let optional: usize = header + 24;
    assert_eq!(
        u16::from_le_bytes(bytes[optional..optional + 2].try_into().expect("magic")),
        PE32_PLUS_MAGIC,
        "fixture is a PE32+ image"
    );
    let directory: usize = optional + 112 + BASE_RELOCATION_DIRECTORY * 8;
    assert_ne!(
        bytes[directory..directory + 8],
        [0u8; 8],
        "the fixture must carry base relocations for removing them to mean anything"
    );
    bytes[directory..directory + 8].fill(0);
    let path: PathBuf = image.path.with_file_name("fixture-without-relocations.exe");
    std::fs::write(&path, bytes).expect("write mutated image");
    path
}

fn flagged_functions(image: &Path) -> (BTreeSet<String>, String) {
    let args: Vec<OsString> = vec![
        "--json".into(),
        "taint".into(),
        image.as_os_str().to_owned(),
    ];
    let output: CapturedOutput = run(&disrobe_bin(), &args, TAINT_TIMEOUT);
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        output.exit_code,
        Some(0),
        "disrobe taint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_str(&stdout).expect("taint --json emits valid json");
    let flagged: BTreeSet<String> = parsed["findings"]
        .as_array()
        .expect("taint --json carries a findings array")
        .iter()
        .map(|finding: &Value| {
            finding["function"]
                .as_str()
                .expect("each finding names its function")
                .to_owned()
        })
        .collect();
    (flagged, stdout)
}

#[test]
fn the_taint_command_reports_the_harness_verdicts_on_pe_pointer_and_import_shapes() {
    for opt_flag in ["-O2", "-O0"] {
        let image: Image = compile(opt_flag);
        let (flagged, stdout): (BTreeSet<String>, String) = flagged_functions(&image.path);
        for (function, flows) in HARNESS_VERDICTS {
            assert_eq!(
                flagged.contains(function),
                flows,
                "{opt_flag} {function}: the CLI must report the verdict the in-process Juliet \
                 harness reports on this image, which needs the PE import-table call edges and \
                 the relocated constant pointer slots: {stdout}"
            );
        }
    }
}

#[test]
fn without_base_relocations_the_taint_command_cannot_name_the_global_behind_the_refptr_slot() {
    for opt_flag in ["-O2", "-O0"] {
        let image: Image = compile(opt_flag);
        let mutated: PathBuf = without_base_relocations(&image);
        let (flagged, stdout): (BTreeSet<String>, String) = flagged_functions(&mutated);
        assert!(
            flagged.contains("pointer_cell_tainted"),
            "{opt_flag}: stripping relocations leaves every flow that needs no pointer slot \
             intact: {stdout}"
        );
        assert!(
            !flagged.contains("global_pointer_tainted"),
            "{opt_flag}: with no base relocation the .refptr slot is not proven to hold an \
             address, so the sink's global stays unknown: {stdout}"
        );
    }
}
