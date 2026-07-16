#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_webview::{CarveReport, Error, RecoveredAsset, WebviewFamily, carve_report};

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir(tag: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base: PathBuf = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{pid}-{seq}"));
    fs::create_dir_all(&base).unwrap();
    base
}

fn have_cmd(name: &str) -> bool {
    let probe: &str = if name == "go" { "version" } else { "--version" };
    let mut command: Command = if cfg!(windows) {
        let mut c: Command = Command::new("cmd");
        c.args(["/C", name, probe]);
        c
    } else {
        let mut c: Command = Command::new(name);
        c.arg(probe);
        c
    };
    command.output().is_ok_and(|o| o.status.success())
}

fn assets_map(report: &CarveReport) -> BTreeMap<String, Vec<u8>> {
    report
        .assets
        .iter()
        .map(|asset: &RecoveredAsset| (asset.path.clone(), asset.bytes.clone()))
        .collect()
}

fn web_tree() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("index.html", b"<html><body>hi</body></html>".to_vec()),
        ("app.js", br#"console.log("app");"#.to_vec()),
        ("style.css", b"body{margin:0}".to_vec()),
        ("assets/deep/x.js", b"export const x=42;".to_vec()),
        ("assets/logo.png", b"PNGDATA-not-real-png".to_vec()),
        (
            "vendor/lib.js",
            b"export function id(v){return v;}".to_vec(),
        ),
    ]
}

fn write_tree(root: &Path, files: &[(&str, Vec<u8>)]) {
    for (rel, data) in files {
        let path: PathBuf = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, data).unwrap();
    }
}

fn expected_embed_map(prefix: &str, files: &[(&str, Vec<u8>)]) -> BTreeMap<String, Vec<u8>> {
    files
        .iter()
        .map(|(rel, data): &(&str, Vec<u8>)| (format!("{prefix}{rel}"), data.clone()))
        .collect()
}

const GO_MAIN: &str = "package main\n\nimport (\n\t\"embed\"\n\t\"fmt\"\n)\n\n//go:embed all:web\nvar content embed.FS\n\nfunc main() {\n\te, _ := content.ReadDir(\"web\")\n\tfmt.Println(len(e))\n}\n";

fn build_go(
    goos: Option<&str>,
    goarch: Option<&str>,
    pie: bool,
    out_name: &str,
) -> Option<Vec<u8>> {
    if !have_cmd("go") {
        return None;
    }
    let workdir: PathBuf = unique_dir("webview-go");
    fs::write(workdir.join("go.mod"), "module embedfix\n\ngo 1.24\n").unwrap();
    fs::write(workdir.join("main.go"), GO_MAIN).unwrap();
    write_tree(&workdir.join("web"), &web_tree());
    let out: PathBuf = workdir.join(out_name);
    let mut command: Command = Command::new("go");
    command.current_dir(&workdir);
    command.arg("build");
    if pie {
        command.args(["-buildmode=pie"]);
    }
    command.arg("-o").arg(&out).arg(".");
    command.env("CGO_ENABLED", "0");
    if let Some(os) = goos {
        command.env("GOOS", os);
    }
    if let Some(arch) = goarch {
        command.env("GOARCH", arch);
    }
    let ok: bool = command
        .output()
        .is_ok_and(|o| o.status.success() && out.exists());
    let bytes: Option<Vec<u8>> = if ok { fs::read(&out).ok() } else { None };
    let _ = fs::remove_dir_all(&workdir);
    bytes
}

fn clang_static_pie(source: &str, tag: &str) -> Option<Vec<u8>> {
    if !have_cmd("clang") {
        return None;
    }
    let workdir: PathBuf = unique_dir(tag);
    let src: PathBuf = workdir.join("fix.c");
    let out: PathBuf = workdir.join("fix.elf");
    fs::write(&src, source).unwrap();
    let mut command: Command = Command::new("clang");
    command.args([
        "-target",
        "x86_64-unknown-linux-gnu",
        "-nostdlib",
        "-static-pie",
        "-fPIE",
        "-O1",
        "-fuse-ld=lld",
        "-Wl,-e,_start",
    ]);
    command.arg("-o").arg(&out).arg(&src);
    let ok: bool = command
        .output()
        .is_ok_and(|o| o.status.success() && out.exists());
    let bytes: Option<Vec<u8>> = if ok { fs::read(&out).ok() } else { None };
    let _ = fs::remove_dir_all(&workdir);
    bytes
}

const CLANG_TABLE_SRC: &str = concat!(
    "typedef unsigned long usize;\n",
    "struct rec { const char* name; usize nlen; const char* data; usize dlen; };\n",
    "static const char n0[]=\"dist/index.html\"; static const char d0[]=\"<html>hi</html>\";\n",
    "static const char n1[]=\"dist/app.js\"; static const char d1[]=\"console.log(1)\";\n",
    "static const char n2[]=\"dist/style.css\"; static const char d2[]=\"body{margin:0}\";\n",
    "static const char n3[]=\"dist/a/b.js\"; static const char d3[]=\"export const x=1\";\n",
    "static const char n4[]=\"dist/logo.png\"; static const char d4[]=\"PNGDATA\";\n",
    "static const char n5[]=\"dist/data.json\"; static const char d5[]=\"{ok:true}\";\n",
    "static const char n6[]=\"dist/vendor.js\"; static const char d6[]=\"var v=42;\";\n",
    "static const char n7[]=\"dist/main.css\"; static const char d7[]=\".x{color:red}\";\n",
    "static const char n8[]=\"dist/x.txt\"; static const char d8[]=\"hello world\";\n",
    "__attribute__((used, retain)) const struct rec table[]={\n",
    " {n0,sizeof(n0)-1,d0,sizeof(d0)-1},{n1,sizeof(n1)-1,d1,sizeof(d1)-1},\n",
    " {n2,sizeof(n2)-1,d2,sizeof(d2)-1},{n3,sizeof(n3)-1,d3,sizeof(d3)-1},\n",
    " {n4,sizeof(n4)-1,d4,sizeof(d4)-1},{n5,sizeof(n5)-1,d5,sizeof(d5)-1},\n",
    " {n6,sizeof(n6)-1,d6,sizeof(d6)-1},{n7,sizeof(n7)-1,d7,sizeof(d7)-1},\n",
    " {n8,sizeof(n8)-1,d8,sizeof(d8)-1},\n",
    "};\n",
    "void _start(void){ __asm__ volatile(\"\":: \"r\"(table)); for(;;){} }\n",
);

fn clang_table_expected() -> BTreeMap<String, Vec<u8>> {
    [
        ("dist/index.html", "<html>hi</html>"),
        ("dist/app.js", "console.log(1)"),
        ("dist/style.css", "body{margin:0}"),
        ("dist/a/b.js", "export const x=1"),
        ("dist/logo.png", "PNGDATA"),
        ("dist/data.json", "{ok:true}"),
        ("dist/vendor.js", "var v=42;"),
        ("dist/main.css", ".x{color:red}"),
        ("dist/x.txt", "hello world"),
    ]
    .into_iter()
    .map(|(name, data): (&str, &str)| (name.to_owned(), data.as_bytes().to_vec()))
    .collect()
}

#[test]
fn carves_go_embed_native_pe() {
    let Some(bytes) = build_go(None, None, false, "app.exe") else {
        eprintln!("CORPUS: go toolchain unavailable; skipping native go-embed PE grade");
        return;
    };
    let report: CarveReport = carve_report(&bytes).expect("carve go pe");
    assert_eq!(report.family, WebviewFamily::Wails);
    assert_eq!(
        assets_map(&report),
        expected_embed_map("web/", &web_tree()),
        "recovered go-embed PE tree must be byte-identical to the source dist"
    );
}

#[test]
fn carves_go_embed_linux_pie_elf() {
    let Some(bytes) = build_go(Some("linux"), Some("amd64"), true, "app.elf") else {
        eprintln!("CORPUS: go toolchain unavailable; skipping cross go-embed PIE ELF grade");
        return;
    };
    let report: CarveReport = carve_report(&bytes).expect("carve go elf pie");
    assert_eq!(
        assets_map(&report),
        expected_embed_map("web/", &web_tree()),
        "recovered go-embed PIE ELF tree must be byte-identical to the source dist"
    );
}

#[test]
fn carves_clang_static_pie_elf_via_relocations() {
    let Some(bytes) = clang_static_pie(CLANG_TABLE_SRC, "webview-clang-table") else {
        eprintln!("CORPUS: clang cross toolchain unavailable; skipping relocation-path ELF grade");
        return;
    };
    let report: CarveReport = carve_report(&bytes).expect("carve clang static-pie elf");
    assert_eq!(
        assets_map(&report),
        clang_table_expected(),
        "recovered clang static-pie table must be byte-identical (pointers arrive via R_X86_64_RELATIVE)"
    );
}

#[test]
fn hand_built_elf_table_recovers_exact_tree() {
    let records: Vec<(&str, &[u8], bool)> = table_records();
    let bytes: Vec<u8> = build_elf64(&records, 32, false);
    let report: CarveReport = carve_report(&bytes).expect("carve hand-built elf");
    let expected: BTreeMap<String, Vec<u8>> = records
        .iter()
        .filter(|(_, data, is_dir): &&(&str, &[u8], bool)| !*is_dir && !data.is_empty())
        .map(|(name, data, _): &(&str, &[u8], bool)| ((*name).to_owned(), (*data).to_vec()))
        .collect();
    assert_eq!(assets_map(&report), expected);
    assert!(report.directories.iter().any(|d: &String| d == "dist"));
    assert!(
        report
            .directories
            .iter()
            .any(|d: &String| d == "dist/assets")
    );
}

#[test]
fn decoy_pointer_array_never_locks_a_table() {
    let records: Vec<(&str, &[u8], bool)> = table_records();
    let bytes: Vec<u8> = build_elf64(&records, 32, true);
    let err: Error = carve_report(&bytes).expect_err("decoy must not lock");
    assert!(
        matches!(err, Error::NoEmbeddedTable(_) | Error::NotDetected),
        "a pointer-shaped decoy array must abstain, got {err:?}"
    );
}

fn table_records() -> Vec<(&'static str, &'static [u8], bool)> {
    vec![
        ("dist/", b"".as_slice(), true),
        ("dist/index.html", b"<html>hi</html>".as_slice(), false),
        ("dist/app.js", b"console.log(1)".as_slice(), false),
        ("dist/style.css", b"body{margin:0}".as_slice(), false),
        ("dist/assets/", b"".as_slice(), true),
        ("dist/assets/logo.png", b"PNGDATA".as_slice(), false),
        (
            "dist/assets/app.2.js",
            b"export default 1".as_slice(),
            false,
        ),
        ("dist/vendor.js", b"var x=1", false),
        ("dist/main.css", b".a{color:blue}", false),
        ("dist/data.json", br#"{"k":1}"#.as_slice(), false),
    ]
}

const RODATA_VA: u64 = 0x1000;
const RODATA_OFF: usize = 0x200;

fn build_elf64(records: &[(&str, &[u8], bool)], stride: usize, corrupt_lengths: bool) -> Vec<u8> {
    let mut blob: Vec<u8> = Vec::new();
    let mut locs: Vec<(u64, u64, u64, u64)> = Vec::new();
    for (name, data, _is_dir) in records {
        let name_off: usize = blob.len();
        blob.extend_from_slice(name.as_bytes());
        let name_va: u64 = RODATA_VA + name_off as u64;
        let (data_va, data_len): (u64, u64) = if data.is_empty() {
            (0, 0)
        } else {
            let data_off: usize = blob.len();
            blob.extend_from_slice(data);
            (RODATA_VA + data_off as u64, data.len() as u64)
        };
        locs.push((name_va, name.len() as u64, data_va, data_len));
    }
    while !blob.len().is_multiple_of(8) {
        blob.push(0);
    }
    for (name_va, name_len, data_va, data_len) in &locs {
        let mut rec: Vec<u8> = Vec::with_capacity(stride);
        rec.extend_from_slice(&name_va.to_le_bytes());
        let name_len_field: u64 = if corrupt_lengths {
            0xFFFF_FFFF_FFFF_FFFF
        } else {
            *name_len
        };
        rec.extend_from_slice(&name_len_field.to_le_bytes());
        rec.extend_from_slice(&data_va.to_le_bytes());
        rec.extend_from_slice(&data_len.to_le_bytes());
        rec.resize(stride, 0);
        blob.extend_from_slice(&rec);
    }

    let mut out: Vec<u8> = vec![0u8; RODATA_OFF];
    out.extend_from_slice(&blob);
    let blob_size: u64 = blob.len() as u64;
    let shstr: &[u8] = b"\0.rodata\0.shstrtab\0";
    let shstr_off: usize = out.len();
    out.extend_from_slice(shstr);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    let shoff: usize = out.len();

    push_shdr(&mut out, &ShdrSpec::default());
    push_shdr(
        &mut out,
        &ShdrSpec {
            name: 1,
            sh_type: 1,
            flags: 2,
            addr: RODATA_VA,
            offset: RODATA_OFF as u64,
            size: blob_size,
            align: 8,
        },
    );
    push_shdr(
        &mut out,
        &ShdrSpec {
            name: 9,
            sh_type: 3,
            flags: 0,
            addr: 0,
            offset: shstr_off as u64,
            size: shstr.len() as u64,
            align: 1,
        },
    );

    write_elf_header(&mut out, shoff as u64, 3, 2);
    out
}

#[derive(Default)]
struct ShdrSpec {
    name: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    align: u64,
}

fn push_shdr(out: &mut Vec<u8>, spec: &ShdrSpec) {
    out.extend_from_slice(&spec.name.to_le_bytes());
    out.extend_from_slice(&spec.sh_type.to_le_bytes());
    out.extend_from_slice(&spec.flags.to_le_bytes());
    out.extend_from_slice(&spec.addr.to_le_bytes());
    out.extend_from_slice(&spec.offset.to_le_bytes());
    out.extend_from_slice(&spec.size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&spec.align.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
}

fn write_elf_header(out: &mut [u8], shoff: u64, shnum: u16, shstrndx: u16) {
    let header: &mut [u8] = &mut out[..64];
    header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    header[16..18].copy_from_slice(&3u16.to_le_bytes());
    header[18..20].copy_from_slice(&62u16.to_le_bytes());
    header[20..24].copy_from_slice(&1u32.to_le_bytes());
    header[40..48].copy_from_slice(&shoff.to_le_bytes());
    header[52..54].copy_from_slice(&64u16.to_le_bytes());
    header[58..60].copy_from_slice(&64u16.to_le_bytes());
    header[60..62].copy_from_slice(&shnum.to_le_bytes());
    header[62..64].copy_from_slice(&shstrndx.to_le_bytes());
}
