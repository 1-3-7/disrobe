#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes};

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

struct Tools {
    javac: PathBuf,
    java: PathBuf,
}

fn tools() -> Option<Tools> {
    Some(Tools {
        javac: find_on_path("javac")?,
        java: find_on_path("java")?,
    })
}

fn workdir(tag: &str) -> PathBuf {
    let dir: PathBuf = std::env::temp_dir().join(format!("disrobe_jvm_regress_{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn compile(tools: &Tools, dir: &Path, sources: &[(&str, &str)]) {
    let mut cmd: Command = Command::new(&tools.javac);
    cmd.arg("-nowarn").arg("-proc:none").arg("-d").arg(dir);
    for (name, src) in sources {
        let path: PathBuf = dir.join(name);
        std::fs::write(&path, src).expect("write src");
        cmd.arg(&path);
    }
    let out: std::process::Output = cmd.output().expect("javac");
    assert!(
        out.status.success(),
        "fixture javac failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn decompile_named(dir: &Path, class_simple: &str) -> String {
    let bytes: Vec<u8> =
        std::fs::read(dir.join(format!("{class_simple}.class"))).expect("read class");
    let d: DecompiledClass = decompile_classfile_bytes(&bytes).expect("decompile");
    d.source
}

fn run_main(tools: &Tools, dir: &Path, main_class: &str) -> String {
    let out: std::process::Output = Command::new(&tools.java)
        .arg("-cp")
        .arg(dir)
        .arg(main_class)
        .output()
        .expect("java run");
    assert!(
        out.status.success(),
        "running {main_class} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

const SM: &str = r"import java.util.*;
public class Sm {
    private final Object lock = new Object();
    private int counter;
    public int bump(int n) { synchronized (lock) { counter += n; return counter; } }
    public void log(List<String> sink, String msg) { synchronized (sink) { sink.add(msg); } }
    public int tally(int[] a) { synchronized (this) { int t = 0; for (int v : a) t += v; return t; } }
}
";

const SM_DRV: &str = r#"import java.util.*;
public class SmDrv {
    public static void main(String[] x) {
        Sm s = new Sm();
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i <= 5; i++) sb.append(s.bump(i)).append(',');
        List<String> sink = new ArrayList<>();
        s.log(sink, "x"); s.log(sink, "y");
        sb.append(sink).append(',');
        sb.append(s.tally(new int[]{2,4,6,8}));
        System.out.println(sb);
    }
}
"#;

#[test]
fn synchronized_block_reconstructs_and_recompiles_behaviorally() {
    let Some(tools): Option<Tools> = tools() else {
        eprintln!("SKIP: javac/java not on PATH; synchronized recompile gate NOT enforced");
        return;
    };
    let orig: PathBuf = workdir("sync_orig");
    compile(&tools, &orig, &[("Sm.java", SM), ("SmDrv.java", SM_DRV)]);
    let src: String = decompile_named(&orig, "Sm");

    assert!(
        src.contains("synchronized (this.lock)")
            && src.contains("synchronized (arg0)")
            && src.contains("synchronized (this)"),
        "synchronized blocks must reconstruct with their lock expressions; got:\n{src}"
    );
    assert!(
        !src.contains("monitorenter") && !src.contains("monitorexit"),
        "monitorenter/monitorexit must not leak as comments after reconstruction; got:\n{src}"
    );

    let dec: PathBuf = workdir("sync_dec");
    compile(&tools, &dec, &[("Sm.java", &src), ("SmDrv.java", SM_DRV)]);

    let javap: PathBuf = find_on_path("javap").expect("javap on PATH next to javac");
    let jp: std::process::Output = Command::new(&javap)
        .arg("-c")
        .arg("-p")
        .arg("-cp")
        .arg(&dec)
        .arg("Sm")
        .output()
        .expect("javap");
    let monitor_count: usize = String::from_utf8_lossy(&jp.stdout)
        .matches("monitorenter")
        .count();
    assert_eq!(
        monitor_count, 3,
        "recompiled synchronized methods must preserve all 3 monitorenter ops (real locking, not dropped)"
    );

    let orig_out: String = run_main(&tools, &orig, "SmDrv");
    let dec_out: String = run_main(&tools, &dec, "SmDrv");
    assert_eq!(
        orig_out, dec_out,
        "decompiled synchronized class must be behavior-equivalent to the original"
    );
}

const LAB: &str = r"public class Lab {
    public int find(int[][] grid, int target) {
        int found = -1;
        outer:
        for (int i = 0; i < grid.length; i++) {
            for (int j = 0; j < grid[i].length; j++) {
                if (grid[i][j] == target) { found = i * 100 + j; break outer; }
                if (grid[i][j] < 0) { continue outer; }
            }
        }
        return found;
    }
    public int count(int[] a, int limit) {
        int c = 0;
        scan:
        for (int i = 0; i < a.length; i++) {
            for (int k = 0; k < a[i]; k++) {
                c++;
                if (c >= limit) break scan;
                if (k == 2) continue scan;
            }
        }
        return c;
    }
}
";

const LAB_DRV: &str = r"public class LabDrv {
    public static void main(String[] x) {
        Lab L = new Lab();
        int[][] g = {{1,-1,9},{5,7,4},{2,8,3}};
        StringBuilder sb = new StringBuilder();
        sb.append(L.find(g, 7)).append(',');
        sb.append(L.find(g, 99)).append(',');
        sb.append(L.find(g, 3)).append(',');
        int[] a = {3,5,1,4};
        sb.append(L.count(a, 100)).append(',');
        sb.append(L.count(a, 4));
        System.out.println(sb);
    }
}
";

#[test]
fn labeled_break_continue_reconstructs_and_recompiles_behaviorally() {
    let Some(tools): Option<Tools> = tools() else {
        eprintln!("SKIP: javac/java not on PATH; labeled-break recompile gate NOT enforced");
        return;
    };
    let orig: PathBuf = workdir("lab_orig");
    compile(
        &tools,
        &orig,
        &[("Lab.java", LAB), ("LabDrv.java", LAB_DRV)],
    );
    let src: String = decompile_named(&orig, "Lab");

    assert!(
        src.contains("break L") && src.contains("continue L"),
        "labeled break/continue to an outer loop must emit labels; got:\n{src}"
    );
    let label_decls: usize = src
        .lines()
        .filter(|l: &&str| {
            let t: &str = l.trim();
            t.ends_with(':')
                && t.starts_with('L')
                && t[1..t.len() - 1].chars().all(|c| c.is_ascii_digit())
        })
        .count();
    assert!(
        label_decls >= 2,
        "outer loops with labeled jumps must carry a label declaration; got:\n{src}"
    );

    let dec: PathBuf = workdir("lab_dec");
    compile(
        &tools,
        &dec,
        &[("Lab.java", &src), ("LabDrv.java", LAB_DRV)],
    );

    let orig_out: String = run_main(&tools, &orig, "LabDrv");
    let dec_out: String = run_main(&tools, &dec, "LabDrv");
    assert_eq!(
        orig_out, dec_out,
        "decompiled labeled-loop class must be behavior-equivalent to the original"
    );
}

const ARR: &str = r"public class Arr {
    public String[][] makeArr() { return new String[3][]; }
    public int[][][] makeCube() { return new int[2][][]; }
    public Object[] flat() { return new Object[5]; }
    public int[] sizes() {
        String[][] a = makeArr();
        int[][][] b = makeCube();
        return new int[]{ a.length, b.length, flat().length };
    }
}
";

const ARR_DRV: &str = r"import java.util.Arrays;
public class ArrDrv {
    public static void main(String[] x) {
        System.out.println(Arrays.toString(new Arr().sizes()));
    }
}
";

#[test]
fn anewarray_of_array_preserves_sized_dimension() {
    let Some(tools): Option<Tools> = tools() else {
        eprintln!("SKIP: javac/java not on PATH; anewarray dimension gate NOT enforced");
        return;
    };
    let orig: PathBuf = workdir("arr_orig");
    compile(
        &tools,
        &orig,
        &[("Arr.java", ARR), ("ArrDrv.java", ARR_DRV)],
    );
    let src: String = decompile_named(&orig, "Arr");

    assert!(
        src.contains("new String[3][]") && src.contains("new int[2][][]"),
        "anewarray-of-array must place the sized dimension before the trailing brackets; got:\n{src}"
    );
    assert!(
        !src.contains("new String[][3]") && !src.contains("new int[][][2]"),
        "the sized dimension must not be appended after the element-type brackets; got:\n{src}"
    );

    let dec: PathBuf = workdir("arr_dec");
    compile(
        &tools,
        &dec,
        &[("Arr.java", &src), ("ArrDrv.java", ARR_DRV)],
    );
    let orig_out: String = run_main(&tools, &orig, "ArrDrv");
    let dec_out: String = run_main(&tools, &dec, "ArrDrv");
    assert_eq!(
        orig_out, dec_out,
        "decompiled array dimensions must be behavior-equivalent"
    );
}

const RAW: &str = r"public class Raw<T> {
    T value;
    T[] arr;
    public boolean isEmpty() { return value == null; }
    public boolean hasArr() { return arr != null; }
    static boolean check(Raw b) { return b.value == null; }
}
";

#[test]
fn raw_generic_field_null_check_stays_reference_comparison() {
    let Some(tools): Option<Tools> = tools() else {
        eprintln!("SKIP: javac not on PATH; raw-generic null gate NOT enforced");
        return;
    };
    let orig: PathBuf = workdir("raw_orig");
    compile(&tools, &orig, &[("Raw.java", RAW)]);
    let src: String = decompile_named(&orig, "Raw");

    assert!(
        src.contains("== null") && src.contains("!= null"),
        "a type-variable field erased to Object must keep its null comparison as `== null`/`!= null`, \
         not a `== 0` numeric compare; got:\n{src}"
    );
    assert!(
        !src.contains("value == 0") && !src.contains("arr != 0"),
        "erased type-variable field must not render a numeric-zero comparison; got:\n{src}"
    );
}
