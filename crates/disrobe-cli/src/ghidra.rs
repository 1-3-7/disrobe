use std::ffi::OsString;
use std::path::PathBuf;

pub fn locate_headless() -> Option<PathBuf> {
    let path_dirs: Vec<PathBuf> = path_dirs();
    let found: Option<PathBuf> = find_launcher(&path_dirs);
    if let Some(found) = found {
        return Some(found);
    }
    let support_dirs: Vec<PathBuf> = ghidra_support_dirs();
    find_launcher(&support_dirs)
}

const fn headless_candidates() -> [&'static str; 2] {
    if cfg!(windows) {
        ["analyzeHeadless.bat", "analyzeHeadless"]
    } else {
        ["analyzeHeadless", "analyzeHeadless.bat"]
    }
}

fn path_dirs() -> Vec<PathBuf> {
    let Some(path): Option<OsString> = std::env::var_os("PATH") else {
        return Vec::new();
    };
    std::env::split_paths(&path).collect()
}

fn ghidra_support_dirs() -> Vec<PathBuf> {
    const VARIABLES: [&str; 2] = ["GHIDRA_HOME", "GHIDRA_INSTALL_DIR"];
    let mut dirs: Vec<PathBuf> = Vec::with_capacity(VARIABLES.len());
    for variable in VARIABLES {
        let variable: &str = variable;
        let home: Option<OsString> = std::env::var_os(variable);
        let Some(home) = home else {
            continue;
        };
        dirs.push(PathBuf::from(home).join("support"));
    }
    dirs
}

fn find_launcher(directories: &[PathBuf]) -> Option<PathBuf> {
    for name in headless_candidates() {
        let name: &str = name;
        for directory in directories {
            let directory: &PathBuf = directory;
            let candidate: PathBuf = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_launcher_is_preferred_over_search_root_order() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe-ghidra-locator")
                .expect("create scratch directory");
        let first_root: PathBuf = scratch.path().join("first");
        let second_root: PathBuf = scratch.path().join("second");
        std::fs::create_dir_all(&first_root).expect("create first launcher directory");
        std::fs::create_dir_all(&second_root).expect("create second launcher directory");
        let candidates: [&str; 2] = headless_candidates();
        std::fs::write(first_root.join(candidates[1]), b"stub").expect("write second launcher");
        std::fs::write(second_root.join(candidates[0]), b"stub").expect("write first launcher");
        let found: Option<PathBuf> = find_launcher(&[first_root, second_root.clone()]);
        assert_eq!(found, Some(second_root.join(candidates[0])));
    }
}
