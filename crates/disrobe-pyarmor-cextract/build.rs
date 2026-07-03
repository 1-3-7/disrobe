fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
    println!("cargo:rerun-if-env-changed=VIRTUAL_ENV");

    #[cfg(target_os = "windows")]
    emit_python_libs_search_path();

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}

#[cfg(target_os = "windows")]
fn emit_python_libs_search_path() {
    use std::path::PathBuf;

    if let Ok(py_exe) = std::env::var("PYO3_PYTHON") {
        let exe: PathBuf = PathBuf::from(py_exe);
        if let Some(libs) = libs_dir_for(&exe) {
            emit_search_path(&libs);
            return;
        }
    }

    if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
        let libs: PathBuf = PathBuf::from(&venv).join("libs");
        if libs.join("python3.lib").exists() {
            emit_search_path(&libs);
            return;
        }
    }

    let candidates: Vec<PathBuf> = candidate_python_libs_dirs();
    for libs in &candidates {
        if libs.join("python3.lib").exists() {
            emit_search_path(libs);
            return;
        }
    }

    println!(
        "cargo:warning=disrobe-pyarmor-cextract: no python3.lib found on PATH. Set PYO3_PYTHON=<path-to-python.exe> or install Python 3.9+ from https://www.python.org/downloads/ to build this crate on Windows."
    );
}

#[cfg(target_os = "windows")]
fn libs_dir_for(py_exe: &std::path::Path) -> Option<std::path::PathBuf> {
    let dir: &std::path::Path = py_exe.parent()?;
    let libs: std::path::PathBuf = dir.join("libs");
    libs.join("python3.lib").exists().then_some(libs)
}

#[cfg(target_os = "windows")]
fn candidate_python_libs_dirs() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut out: Vec<PathBuf> = Vec::new();

    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let root: PathBuf = PathBuf::from(local).join("Programs").join("Python");
        push_python_libs_under(&root, &mut out);
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        push_python_libs_under(&PathBuf::from(pf), &mut out);
    }
    for major in 9..=20u32 {
        let p: PathBuf = PathBuf::from(format!("C:\\Python3{major}\\libs"));
        if p.join("python3.lib").exists() {
            out.push(p);
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn push_python_libs_under(root: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name: std::ffi::OsString = entry.file_name();
        let s: &str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if !s.starts_with("Python3") {
            continue;
        }
        let libs: std::path::PathBuf = entry.path().join("libs");
        if libs.join("python3.lib").exists() {
            out.push(libs);
        }
    }
}

#[cfg(target_os = "windows")]
fn emit_search_path(libs: &std::path::Path) {
    println!("cargo:rustc-link-search=native={}", libs.display());
}
