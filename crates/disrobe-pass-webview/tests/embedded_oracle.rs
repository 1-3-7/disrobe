#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_webview::{
    CarveConfig, CarveReport, Compression, Error, RecoveredAsset, WebviewFamily, carve_report,
    carve_with_config,
};

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

const REQUIRE_GO: &str = "DISROBE_REQUIRE_GO";
const REQUIRE_NATIVE_TOOLCHAIN: &str = "DISROBE_REQUIRE_NATIVE_TOOLCHAIN";

fn require_var(tool: &str) -> &'static str {
    if tool == "go" {
        REQUIRE_GO
    } else {
        REQUIRE_NATIVE_TOOLCHAIN
    }
}

fn tool_is_optional(var: &str) -> bool {
    let Some(raw): Option<std::ffi::OsString> = std::env::var_os(var) else {
        return true;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    matches!(
        text.as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

fn announce_unmeasured(tool: &str, grade: &str, defect: &str) {
    let var: &'static str = require_var(tool);
    assert!(
        tool_is_optional(var),
        "{var} makes {tool} mandatory for this run, so `{grade}` cannot be measured and must not \
         report success: {defect}. Install {tool} and put it on PATH, or clear {var} to permit a \
         run that measures nothing here."
    );
    println!(
        "NOT MEASURED: `{grade}` was skipped because {defect}. Set {var}=1 to fail instead of \
         skipping when {tool} is absent."
    );
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
    grade: &str,
) -> Option<Vec<u8>> {
    if !have_cmd("go") {
        announce_unmeasured("go", grade, "the go toolchain is not callable");
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
    if bytes.is_none() {
        announce_unmeasured("go", grade, "the go build produced no image to grade");
    }
    bytes
}

fn clang_static_pie(source: &str, tag: &str, grade: &str) -> Option<Vec<u8>> {
    if !have_cmd("clang") {
        announce_unmeasured("clang", grade, "clang is not callable");
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
    if bytes.is_none() {
        announce_unmeasured("clang", grade, "the clang build produced no image to grade");
    }
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
    let Some(bytes) = build_go(None, None, false, "app.exe", "carves_go_embed_native_pe") else {
        return;
    };
    let report: CarveReport = carve_report(&bytes).expect("carve go pe");
    assert_eq!(
        report.family,
        WebviewFamily::Unknown,
        "a bare go:embed image carries no Wails marker, so naming it Wails would be a guess"
    );
    assert_eq!(
        assets_map(&report),
        expected_embed_map("web/", &web_tree()),
        "recovered go-embed PE tree must be byte-identical to the source dist"
    );
}

#[test]
fn wails_markers_promote_the_same_go_embed_image_to_the_wails_family() {
    let Some(bytes) = build_go(
        None,
        None,
        false,
        "wailsapp.exe",
        "wails_markers_promote_the_same_go_embed_image_to_the_wails_family",
    ) else {
        return;
    };
    let plain: CarveReport = carve_report(&bytes).expect("carve go pe");
    assert_eq!(plain.family, WebviewFamily::Unknown);

    let mut marked: Vec<u8> = bytes;
    marked.extend_from_slice(b"wails://wails.localhost /wails/runtime WailsInvoke");
    let report: CarveReport = carve_report(&marked).expect("carve marked go pe");
    assert_eq!(
        report.family,
        WebviewFamily::Wails,
        "three Wails markers are positive evidence, not a fallback"
    );
    assert_eq!(
        assets_map(&report),
        expected_embed_map("web/", &web_tree()),
        "family attribution must not perturb the recovered tree"
    );
}

#[test]
fn carves_go_embed_linux_pie_elf() {
    let Some(bytes) = build_go(
        Some("linux"),
        Some("amd64"),
        true,
        "app.elf",
        "carves_go_embed_linux_pie_elf",
    ) else {
        return;
    };
    let report: CarveReport = carve_report(&bytes).expect("carve go elf pie");
    assert_eq!(
        assets_map(&report),
        expected_embed_map("web/", &web_tree()),
        "recovered go-embed PIE ELF tree must be byte-identical to the source dist"
    );
}

const BIG_ENDIAN_TARGETS: [(&str, &str); 3] =
    [("s390x", "64-bit"), ("ppc64", "64-bit"), ("mips", "32-bit")];
const LITTLE_ENDIAN_CONTROLS: [(&str, &str); 2] = [("ppc64le", "64-bit"), ("386", "32-bit")];

#[test]
fn carves_go_embed_in_both_endiannesses() {
    if !have_cmd("go") {
        announce_unmeasured(
            "go",
            "carves_go_embed_in_both_endiannesses",
            "the go toolchain is not callable",
        );
        return;
    }
    let expected: BTreeMap<String, Vec<u8>> = expected_embed_map("web/", &web_tree());
    let mut graded: usize = 0;
    for (goarch, width) in BIG_ENDIAN_TARGETS.iter().chain(&LITTLE_ENDIAN_CONTROLS) {
        let bytes: Vec<u8> = build_go(
            Some("linux"),
            Some(goarch),
            false,
            &format!("app-{goarch}.elf"),
            "carves_go_embed_in_both_endiannesses",
        )
        .unwrap_or_else(|| panic!("go build for linux/{goarch} failed"));
        let report: CarveReport =
            carve_report(&bytes).unwrap_or_else(|e| panic!("{goarch} ({width}) carve failed: {e}"));
        assert_eq!(
            assets_map(&report),
            expected,
            "{goarch} ({width}) recovered a tree that differs from the source dist, so pointer \
             words are being read in the wrong byte order for this image"
        );
        graded += 1;
    }
    assert_eq!(
        graded,
        BIG_ENDIAN_TARGETS.len() + LITTLE_ENDIAN_CONTROLS.len(),
        "every endianness and pointer width in the declared input space must be graded"
    );
}

const FAT_MAGIC_32: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const FAT_SLICE_ALIGN: usize = 1 << 14;
const FAT_ALIGN_POWER: u32 = 14;

fn universal_macho(magic: u32, slices: &[(u32, &[u8])]) -> Vec<u8> {
    let arch_size: usize = if magic == FAT_MAGIC_64 { 32 } else { 20 };
    let mut header: Vec<u8> = Vec::new();
    header.extend_from_slice(&magic.to_be_bytes());
    header.extend_from_slice(&u32::try_from(slices.len()).unwrap().to_be_bytes());
    let start: usize = (8 + slices.len() * arch_size).div_ceil(FAT_SLICE_ALIGN) * FAT_SLICE_ALIGN;
    let mut cursor: usize = start;
    for (cputype, data) in slices {
        header.extend_from_slice(&cputype.to_be_bytes());
        header.extend_from_slice(&0u32.to_be_bytes());
        if magic == FAT_MAGIC_64 {
            header.extend_from_slice(&(cursor as u64).to_be_bytes());
            header.extend_from_slice(&(data.len() as u64).to_be_bytes());
            header.extend_from_slice(&FAT_ALIGN_POWER.to_be_bytes());
            header.extend_from_slice(&0u32.to_be_bytes());
        } else {
            header.extend_from_slice(&u32::try_from(cursor).unwrap().to_be_bytes());
            header.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            header.extend_from_slice(&FAT_ALIGN_POWER.to_be_bytes());
        }
        cursor = (cursor + data.len()).div_ceil(FAT_SLICE_ALIGN) * FAT_SLICE_ALIGN;
    }
    let mut out: Vec<u8> = header;
    let mut cursor: usize = start;
    for (_, data) in slices {
        out.resize(cursor, 0);
        out.extend_from_slice(data);
        cursor = (cursor + data.len()).div_ceil(FAT_SLICE_ALIGN) * FAT_SLICE_ALIGN;
    }
    out
}

#[test]
fn carves_thin_and_universal_macho_go_embed() {
    if !have_cmd("go") {
        announce_unmeasured(
            "go",
            "carves_thin_and_universal_macho_go_embed",
            "the go toolchain is not callable",
        );
        return;
    }
    let expected: BTreeMap<String, Vec<u8>> = expected_embed_map("web/", &web_tree());
    let intel: Vec<u8> = build_go(
        Some("darwin"),
        Some("amd64"),
        false,
        "app-amd64.macho",
        "carves_thin_and_universal_macho_go_embed",
    )
    .unwrap_or_else(|| panic!("go build for darwin/amd64 failed"));
    let arm: Vec<u8> = build_go(
        Some("darwin"),
        Some("arm64"),
        false,
        "app-arm64.macho",
        "carves_thin_and_universal_macho_go_embed",
    )
    .unwrap_or_else(|| panic!("go build for darwin/arm64 failed"));
    for (label, thin) in [("amd64", &intel), ("arm64", &arm)] {
        let report: CarveReport =
            carve_report(thin).unwrap_or_else(|e| panic!("thin Mach-O {label} carve failed: {e}"));
        assert_eq!(assets_map(&report), expected, "thin Mach-O {label}");
    }
    for magic in [FAT_MAGIC_32, FAT_MAGIC_64] {
        let fat: Vec<u8> = universal_macho(
            magic,
            &[
                (CPU_TYPE_X86_64, intel.as_slice()),
                (CPU_TYPE_ARM64, arm.as_slice()),
            ],
        );
        let report: CarveReport = carve_report(&fat)
            .unwrap_or_else(|e| panic!("universal Mach-O {magic:#x} carve failed: {e}"));
        assert_eq!(
            assets_map(&report),
            expected,
            "a universal binary must carve the same tree its slices carry, not fall through as an \
             unsupported container"
        );
    }
}

#[test]
fn a_universal_binary_whose_slices_carry_nothing_is_refused() {
    let junk: Vec<u8> = vec![0x41u8; 4096];
    let fat: Vec<u8> = universal_macho(
        FAT_MAGIC_32,
        &[
            (CPU_TYPE_X86_64, junk.as_slice()),
            (CPU_TYPE_ARM64, junk.as_slice()),
        ],
    );
    let err: Error = carve_report(&fat).expect_err("a slice-free universal binary must abstain");
    assert!(
        matches!(err, Error::NotDetected | Error::FamilyNotExtractable { .. }),
        "got {err:?}"
    );
}

#[test]
fn carves_clang_static_pie_elf_via_relocations() {
    let Some(bytes) = clang_static_pie(
        CLANG_TABLE_SRC,
        "webview-clang-table",
        "carves_clang_static_pie_elf_via_relocations",
    ) else {
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
    let bytes: Vec<u8> = build_elf64(&records, 32, false, 0);
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
    let bytes: Vec<u8> = build_elf64(&records, 32, true, 0);
    let err: Error = carve_report(&bytes).expect_err("decoy must not lock");
    assert!(
        matches!(err, Error::NoEmbeddedTable(_) | Error::NotDetected),
        "a pointer-shaped decoy array must abstain, got {err:?}"
    );
}

#[test]
fn many_section_binary_recovers_exact_tree() {
    let records: Vec<(&str, &[u8], bool)> = table_records();
    let bytes: Vec<u8> = build_elf64(&records, 32, false, 800);
    let report: CarveReport = carve_report(&bytes).expect("carve many-section elf");
    let expected: BTreeMap<String, Vec<u8>> = records
        .iter()
        .filter(|(_, data, is_dir): &&(&str, &[u8], bool)| !*is_dir && !data.is_empty())
        .map(|(name, data, _): &(&str, &[u8], bool)| ((*name).to_owned(), (*data).to_vec()))
        .collect();
    assert_eq!(
        assets_map(&report),
        expected,
        "many extra sections must not perturb table recovery"
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

fn build_elf64(
    records: &[(&str, &[u8], bool)],
    stride: usize,
    corrupt_lengths: bool,
    extra_sections: usize,
) -> Vec<u8> {
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
    for i in 0..extra_sections {
        push_shdr(
            &mut out,
            &ShdrSpec {
                name: 1,
                sh_type: 1,
                flags: 2,
                addr: 0x8000 + (i as u64) * 0x100,
                offset: RODATA_OFF as u64,
                size: 8,
                align: 1,
            },
        );
    }

    let shnum: u16 = (3 + extra_sections) as u16;
    write_elf_header(&mut out, shoff as u64, shnum, 2);
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

fn compressible_payloads() -> Vec<(&'static str, Vec<u8>)> {
    let html: Vec<u8> = "<html><body><div class=\"app\">"
        .bytes()
        .chain(std::iter::repeat_n(b'x', 600))
        .chain("</div></body></html>".bytes())
        .collect();
    let script: Vec<u8> = "export function render(state){return state.items.map(i=>i.id);}"
        .repeat(12)
        .into_bytes();
    let style: Vec<u8> = ".panel{display:flex;align-items:center;padding:4px}"
        .repeat(14)
        .into_bytes();
    let json: Vec<u8> = "{\"name\":\"widget\",\"deps\":[\"a\",\"b\",\"c\"]}"
        .repeat(10)
        .into_bytes();
    let vendor: Vec<u8> = "function noop(){};var registry={};registry.add=noop;"
        .repeat(11)
        .into_bytes();
    let readme: Vec<u8> = "the quick brown fox jumps over the lazy dog. "
        .repeat(16)
        .into_bytes();
    let svg: Vec<u8> = "<svg><path d=\"M0 0 L10 10\"/></svg>"
        .repeat(13)
        .into_bytes();
    let worker: Vec<u8> = "self.onmessage=function(e){postMessage(e.data);};"
        .repeat(12)
        .into_bytes();
    let manifest: Vec<u8> = "{\"start_url\":\"/\",\"display\":\"standalone\"}"
        .repeat(9)
        .into_bytes();
    vec![
        ("dist/index.html", html),
        ("dist/app.js", script),
        ("dist/style.css", style),
        ("dist/data.json", json),
        ("dist/vendor.js", vendor),
        ("dist/readme.txt", readme),
        ("dist/logo.svg", svg),
        ("dist/worker.js", worker),
        ("dist/manifest.json", manifest),
    ]
}

fn gzip_encode(raw: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(raw).unwrap();
    encoder.finish().unwrap()
}

fn zstd_encode(raw: &[u8]) -> Vec<u8> {
    zstd::encode_all(raw, 19).unwrap()
}

fn brotli_encode(raw: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut input: &[u8] = raw;
    brotli::BrotliCompress(
        &mut input,
        &mut out,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .unwrap();
    out
}

fn c_byte_array(name: &str, bytes: &[u8]) -> String {
    let body: String = bytes
        .iter()
        .map(|byte: &u8| byte.to_string())
        .collect::<Vec<String>>()
        .join(",");
    format!("static const char {name}[]={{{body}}};\n")
}

fn compressed_table_source(entries: &[(&str, Vec<u8>)]) -> String {
    use std::fmt::Write;

    let mut source: String = String::from("typedef unsigned long usize;\n");
    source
        .push_str("struct rec { const char* name; usize nlen; const char* data; usize dlen; };\n");
    for (index, (name, blob)) in entries.iter().enumerate() {
        writeln!(source, "static const char n{index}[]=\"{name}\";").unwrap();
        source.push_str(&c_byte_array(&format!("d{index}"), blob));
    }
    source.push_str("__attribute__((used, retain)) const struct rec table[]={\n");
    for index in 0..entries.len() {
        writeln!(
            source,
            " {{n{index},sizeof(n{index})-1,d{index},sizeof(d{index})}},"
        )
        .unwrap();
    }
    source.push_str("};\n");
    source.push_str("void _start(void){ __asm__ volatile(\"\":: \"r\"(table)); for(;;){} }\n");
    source
}

fn carve_encoded_tree(
    encode: fn(&[u8]) -> Vec<u8>,
    tag: &str,
    grade: &str,
) -> Option<Vec<RecoveredAsset>> {
    let encoded: Vec<(&str, Vec<u8>)> = compressible_payloads()
        .iter()
        .map(|(name, raw): &(&'static str, Vec<u8>)| (*name, encode(raw)))
        .collect();
    let image: Vec<u8> = clang_static_pie(&compressed_table_source(&encoded), tag, grade)?;
    Some(carve_report(&image).unwrap().assets)
}

fn assert_encoder_round_trip(
    encode: fn(&[u8]) -> Vec<u8>,
    expected: Compression,
    tag: &str,
    grade: &str,
) {
    let Some(assets): Option<Vec<RecoveredAsset>> = carve_encoded_tree(encode, tag, grade) else {
        return;
    };
    let recovered: BTreeMap<String, &RecoveredAsset> = assets
        .iter()
        .map(|asset: &RecoveredAsset| (asset.path.clone(), asset))
        .collect();
    for (name, raw) in compressible_payloads() {
        let asset: &RecoveredAsset = recovered.get(name).unwrap_or_else(|| {
            panic!("{tag}: {name} was not recovered from the embedded table at all")
        });
        assert_eq!(
            asset.bytes, raw,
            "{tag}: {name} decoded to bytes the encoder was never given, so a caller reading this \
             asset gets wrong file content instead of an error"
        );
        assert_eq!(
            asset.compression, expected,
            "{tag}: {name} is reported as {:?} rather than {expected:?}, so the reported encoding \
             does not describe how the bytes were actually recovered",
            asset.compression
        );
    }
}

const TAURI_TRAILER: &[u8] = b"tauri://localhost __TAURI_INTERNALS__ __TAURI__ wry";

type Encoder = fn(&[u8]) -> Vec<u8>;
type CodecChoice = (Encoder, Compression);

fn tauri_asset_tree() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "/index.html",
            "<!doctype html><html><head><title>app</title></head><body><div id=\"root\"></div>"
                .repeat(6)
                .into_bytes(),
        ),
        (
            "/assets/index-a1b2c3.js",
            "export function mount(el){el.innerHTML=\"<p>hi</p>\";}"
                .repeat(14)
                .into_bytes(),
        ),
        (
            "/assets/index-d4e5f6.css",
            ":root{--bg:#111;--fg:#eee}body{background:var(--bg);color:var(--fg)}"
                .repeat(11)
                .into_bytes(),
        ),
        (
            "/assets/index-a1b2c3.js.map",
            "{\"version\":3,\"sources\":[\"src/main.ts\"],\"mappings\":\"AAAA\"}"
                .repeat(9)
                .into_bytes(),
        ),
        ("/assets/vendor.wasm", b"\x00asm\x01\x00\x00\x00".repeat(40)),
        ("/assets/logo.png", b"\x89PNG\r\n\x1a\n".repeat(48)),
        ("/assets/inter.woff2", b"wOF2\x00\x01\x00\x00".repeat(52)),
        (
            "/manifest.json",
            "{\"name\":\"app\",\"start_url\":\"/\",\"display\":\"standalone\"}"
                .repeat(10)
                .into_bytes(),
        ),
        (
            "/robots.txt",
            "user-agent: *\ndisallow:\n".repeat(20).into_bytes(),
        ),
        ("/empty.txt", Vec::new()),
        ("/one.txt", b"x".to_vec()),
    ]
}

fn expected_tauri_map(tree: &[(&'static str, Vec<u8>)]) -> BTreeMap<String, Vec<u8>> {
    tree.iter()
        .map(|(key, data): &(&'static str, Vec<u8>)| {
            (key.trim_start_matches('/').to_owned(), data.clone())
        })
        .collect()
}

fn image_from_entries(entries: &[(&str, Vec<u8>)], trailer: &[u8]) -> Vec<u8> {
    let records: Vec<(&str, &[u8], bool)> = entries
        .iter()
        .map(|(name, data): &(&str, Vec<u8>)| (*name, data.as_slice(), false))
        .collect();
    let mut image: Vec<u8> = build_elf64(&records, 32, false, 0);
    image.extend_from_slice(trailer);
    image
}

fn encode_tree(
    tree: &[(&'static str, Vec<u8>)],
    encode: fn(&[u8]) -> Vec<u8>,
) -> Vec<(&'static str, Vec<u8>)> {
    tree.iter()
        .map(|(name, data): &(&'static str, Vec<u8>)| {
            let blob: Vec<u8> = if data.is_empty() {
                Vec::new()
            } else {
                encode(data)
            };
            (*name, blob)
        })
        .collect()
}

#[test]
fn tauri_style_zstd_map_recovers_the_original_tree() {
    let tree: Vec<(&'static str, Vec<u8>)> = tauri_asset_tree();
    let encoded: Vec<(&str, Vec<u8>)> = encode_tree(&tree, zstd_encode);
    let image: Vec<u8> = image_from_entries(&encoded, TAURI_TRAILER);

    let report: CarveReport = carve_report(&image).expect("carve tauri-style map");
    assert_eq!(
        report.family,
        WebviewFamily::Tauri,
        "the Tauri markers in the image are the evidence, not a default"
    );
    assert_eq!(
        assets_map(&report),
        expected_tauri_map(&tree),
        "every root-relative asset key must resolve to the byte-identical original file"
    );
    for asset in &report.assets {
        let expected: Compression = if asset.bytes.is_empty() {
            Compression::None
        } else {
            Compression::Zstd
        };
        assert_eq!(
            asset.compression, expected,
            "{}: reported encoding must describe how the bytes were recovered",
            asset.path
        );
    }
    assert_eq!(report.declared, tree.len());
    assert_eq!(report.recovered, tree.len());
}

#[test]
fn tauri_style_brotli_map_recovers_the_original_tree_without_a_frame_to_detect() {
    let tree: Vec<(&'static str, Vec<u8>)> = tauri_asset_tree();
    let encoded: Vec<(&str, Vec<u8>)> = encode_tree(&tree, brotli_encode);
    let image: Vec<u8> = image_from_entries(&encoded, TAURI_TRAILER);

    let report: CarveReport = carve_report(&image).expect("carve tauri-style brotli map");
    assert_eq!(report.family, WebviewFamily::Tauri);
    assert_eq!(
        assets_map(&report),
        expected_tauri_map(&tree),
        "brotli carries no frame magic, so the map-wide anchor is the only thing that can decode \
         these blobs, and every one must come back byte-identical to the source file"
    );
    for asset in &report.assets {
        let expected: Compression = if asset.bytes.is_empty() {
            Compression::None
        } else {
            Compression::Brotli
        };
        assert_eq!(
            asset.compression, expected,
            "{}: reported encoding must describe how the bytes were recovered",
            asset.path
        );
    }
    assert_eq!(report.declared, tree.len());
    assert_eq!(
        report.recovered,
        tree.len(),
        "a zero-length member of a brotli map holds no stream to inflate, and dropping it would \
         lose an asset the source tree really has"
    );
}

#[test]
fn a_brotli_decompression_bomb_is_refused_by_the_quota() {
    let mut entries: Vec<(&str, Vec<u8>)> = encode_tree(&tauri_asset_tree(), brotli_encode);
    let bomb: Vec<u8> = brotli_encode(&vec![0u8; 4 * 1024 * 1024]);
    assert!(
        bomb.len() < 4096,
        "the bomb fixture must be small on disk to be a bomb at all, got {}",
        bomb.len()
    );
    entries.push(("/assets/bomb.bin", bomb));
    let image: Vec<u8> = image_from_entries(&entries, TAURI_TRAILER);

    let err: Error = carve_report(&image).expect_err("the bomb must not be admitted");
    match err {
        Error::Quota { entry, reason } => {
            assert_eq!(entry, "assets/bomb.bin");
            assert!(
                reason.contains("ratio"),
                "the refusal must name the expansion ratio, got {reason}"
            );
        }
        other => panic!("expected a quota refusal, got {other:?}"),
    }
}

#[test]
fn a_raw_member_of_a_brotli_map_is_withheld_rather_than_reported_as_bytes_it_never_held() {
    let tree: Vec<(&'static str, Vec<u8>)> = tauri_asset_tree();
    let mut entries: Vec<(&str, Vec<u8>)> = encode_tree(&tree, brotli_encode);
    let stored_raw: Vec<u8> = b".panel{display:flex}".repeat(30);
    entries.push(("/assets/stored.css", stored_raw.clone()));
    let image: Vec<u8> = image_from_entries(&entries, TAURI_TRAILER);

    let report: CarveReport = carve_report(&image).expect("carve brotli map holding a raw member");
    let recovered: BTreeMap<String, Vec<u8>> = assets_map(&report);
    match recovered.get("assets/stored.css") {
        None => assert_eq!(
            report.declared - report.recovered,
            1,
            "a member the anchor cannot inflate must still be counted as declared, so coverage \
             records the loss instead of hiding it"
        ),
        Some(bytes) => assert_eq!(
            *bytes, stored_raw,
            "a stored member reported at all must carry the bytes it was stored with, never an \
             inflation of them"
        ),
    }
    for (key, want) in expected_tauri_map(&tree) {
        assert_eq!(
            recovered.get(&key),
            Some(&want),
            "{key}: one member the anchor cannot inflate must not cost the rest of the map"
        );
    }
}

#[test]
fn a_mixed_encoding_map_recovers_each_entry_under_its_own_codec() {
    let tree: Vec<(&'static str, Vec<u8>)> = tauri_asset_tree();
    let codecs: [CodecChoice; 3] = [
        (gzip_encode, Compression::Gzip),
        (zstd_encode, Compression::Zstd),
        (brotli_encode, Compression::Brotli),
    ];
    let mut encoded: Vec<(&str, Vec<u8>)> = Vec::with_capacity(tree.len());
    let mut wanted: BTreeMap<String, Compression> = BTreeMap::new();
    for (index, (name, data)) in tree.iter().enumerate() {
        let key: String = name.trim_start_matches('/').to_owned();
        if data.is_empty() {
            encoded.push((*name, Vec::new()));
            wanted.insert(key, Compression::None);
            continue;
        }
        if index.is_multiple_of(4) {
            encoded.push((*name, data.clone()));
            wanted.insert(key, Compression::None);
            continue;
        }
        let (encode, label): CodecChoice = codecs[index % codecs.len()];
        encoded.push((*name, encode(data)));
        wanted.insert(key, label);
    }
    let image: Vec<u8> = image_from_entries(&encoded, TAURI_TRAILER);

    let report: CarveReport = carve_report(&image).expect("carve mixed map");
    assert_eq!(
        assets_map(&report),
        expected_tauri_map(&tree),
        "a mixed archive must round-trip every entry, whatever codec produced it"
    );
    for asset in &report.assets {
        assert_eq!(
            Some(&asset.compression),
            wanted.get(&asset.path),
            "{}: wrong codec reported for the recovered bytes",
            asset.path
        );
    }
}

#[test]
fn a_traversal_key_is_dropped_while_the_rest_of_the_map_survives() {
    let tree: Vec<(&'static str, Vec<u8>)> = tauri_asset_tree();
    let mut encoded: Vec<(&str, Vec<u8>)> = encode_tree(&tree, zstd_encode);
    encoded.push((
        "/../../etc/passwd",
        zstd_encode(b"root:x:0:0:".repeat(20).as_slice()),
    ));
    encoded.push((
        "C:/windows/win.ini",
        zstd_encode(b"[fonts]".repeat(30).as_slice()),
    ));
    let image: Vec<u8> = image_from_entries(&encoded, TAURI_TRAILER);

    let report: CarveReport = carve_report(&image).expect("carve map with hostile keys");
    assert_eq!(
        assets_map(&report),
        expected_tauri_map(&tree),
        "a key that escapes the output root must never become a recovered asset"
    );
    assert_eq!(
        report.declared - report.recovered,
        2,
        "the refused keys must still be counted as declared, so coverage stays honest"
    );
    assert!(report.coverage() < 1.0);
}

#[test]
fn an_exact_duplicate_keeps_the_first_record() {
    let mut entries: Vec<(&str, Vec<u8>)> = encode_tree(&tauri_asset_tree(), zstd_encode);
    let duplicate: Vec<u8> = zstd_encode(b"a different body for the same key".repeat(9).as_slice());
    entries.push(("/index.html", duplicate));
    let image: Vec<u8> = image_from_entries(&entries, TAURI_TRAILER);

    let report: CarveReport = carve_report(&image).expect("carve map with duplicate keys");
    let recovered: BTreeMap<String, Vec<u8>> = assets_map(&report);
    assert_eq!(
        recovered.get("index.html"),
        expected_tauri_map(&tauri_asset_tree()).get("index.html"),
        "the first record for a key wins, and the later duplicate must not overwrite it"
    );
}

#[test]
fn ascii_case_collisions_are_rejected_before_a_report_escapes() {
    let mut entries: Vec<(&str, Vec<u8>)> = encode_tree(&tauri_asset_tree(), zstd_encode);
    entries.push((
        "/Index.HTML",
        zstd_encode(b"the case variant body".repeat(9).as_slice()),
    ));
    let image: Vec<u8> = image_from_entries(&entries, TAURI_TRAILER);

    let error: Error = carve_report(&image).expect_err(
        "two output paths that differ only by ASCII case must not escape in one report",
    );
    match error {
        Error::PathCollision { first, second } => {
            assert_eq!(first, "index.html");
            assert_eq!(second, "Index.HTML");
        }
        other => panic!("expected a typed path collision, got {other:?}"),
    }
}

#[test]
fn unicode_case_expansion_collisions_are_rejected_before_a_report_escapes() {
    let mut entries: Vec<(&str, Vec<u8>)> = encode_tree(&tauri_asset_tree(), zstd_encode);
    entries.push((
        "/assets/Stra\u{00df}e.js",
        zstd_encode(b"export const sharp = true;".repeat(12).as_slice()),
    ));
    entries.push((
        "/assets/STRASSE.js",
        zstd_encode(b"export const capital = true;".repeat(12).as_slice()),
    ));
    let image: Vec<u8> = image_from_entries(&entries, TAURI_TRAILER);

    let error: Error = carve_report(&image)
        .expect_err("Unicode case expansion equivalents must not become colliding output paths");
    match error {
        Error::PathCollision { first, second } => {
            assert_eq!(first, "assets/Stra\u{00df}e.js");
            assert_eq!(second, "assets/STRASSE.js");
        }
        other => panic!("expected a typed path collision, got {other:?}"),
    }
}

#[test]
fn directory_paths_consume_the_collision_preflight_entry_quota() {
    let tree: Vec<(&'static str, Vec<u8>)> = tauri_asset_tree();
    let mut entries: Vec<(&str, Vec<u8>)> = encode_tree(&tree, zstd_encode);
    entries.push(("/assets/generated/", Vec::new()));
    let image: Vec<u8> = image_from_entries(&entries, TAURI_TRAILER);
    let mut config: CarveConfig = CarveConfig::default();
    config.quota.max_entries = tree.len();

    let error: Error = carve_with_config(&image, &config)
        .expect_err("a retained directory path beyond max_entries must be refused");
    match error {
        Error::Quota { entry, reason } => {
            assert_eq!(entry, "assets/generated");
            assert_eq!(reason, format!("max_entries={} reached", tree.len()));
        }
        other => panic!("expected a typed entry quota refusal, got {other:?}"),
    }
}

#[test]
fn a_decompression_bomb_is_refused_by_the_quota() {
    let mut entries: Vec<(&str, Vec<u8>)> = encode_tree(&tauri_asset_tree(), zstd_encode);
    let bomb: Vec<u8> = zstd_encode(&vec![0u8; 4 * 1024 * 1024]);
    assert!(
        bomb.len() < 4096,
        "the bomb fixture must be small on disk to be a bomb at all, got {}",
        bomb.len()
    );
    entries.push(("/assets/bomb.bin", bomb));
    let image: Vec<u8> = image_from_entries(&entries, TAURI_TRAILER);

    let err: Error = carve_report(&image).expect_err("the bomb must not be admitted");
    match err {
        Error::Quota { entry, reason } => {
            assert_eq!(entry, "assets/bomb.bin");
            assert!(
                reason.contains("ratio"),
                "the refusal must name the expansion ratio, got {reason}"
            );
        }
        other => panic!("expected a quota refusal, got {other:?}"),
    }
}

#[test]
fn gzip_embedded_assets_decode_to_what_the_encoder_was_given() {
    assert_encoder_round_trip(
        gzip_encode,
        Compression::Gzip,
        "webview-gzip",
        "gzip_embedded_assets_decode_to_what_the_encoder_was_given",
    );
}

#[test]
fn zstd_embedded_assets_decode_to_what_the_encoder_was_given() {
    assert_encoder_round_trip(
        zstd_encode,
        Compression::Zstd,
        "webview-zstd",
        "zstd_embedded_assets_decode_to_what_the_encoder_was_given",
    );
}

#[test]
fn brotli_embedded_assets_decode_to_what_the_encoder_was_given() {
    assert_encoder_round_trip(
        brotli_encode,
        Compression::Brotli,
        "webview-brotli",
        "brotli_embedded_assets_decode_to_what_the_encoder_was_given",
    );
}
