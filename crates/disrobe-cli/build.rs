use std::path::{Path, PathBuf};

const MAX_GIT_FILE_BYTES: u64 = 1 << 20;

fn read_small(path: &Path) -> Option<String> {
    let metadata: std::fs::Metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > MAX_GIT_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

fn is_commit_id(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b: u8| b.is_ascii_hexdigit())
}

fn git_dirs(workspace: &Path) -> Option<(PathBuf, PathBuf)> {
    let dot_git: PathBuf = workspace.join(".git");
    let git_dir: PathBuf = if dot_git.is_dir() {
        dot_git
    } else {
        let pointer: String = read_small(&dot_git)?;
        let target: &str = pointer.trim().strip_prefix("gitdir:")?.trim();
        workspace.join(target)
    };
    let common: PathBuf = read_small(&git_dir.join("commondir"))
        .map_or_else(|| git_dir.clone(), |rel: String| git_dir.join(rel.trim()));
    Some((git_dir, common))
}

fn head_commit(workspace: &Path) -> Option<String> {
    let (git_dir, common): (PathBuf, PathBuf) = git_dirs(workspace)?;
    let head_path: PathBuf = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());
    let head: String = read_small(&head_path)?;
    let head: &str = head.trim();
    if is_commit_id(head) {
        return Some(head.to_ascii_lowercase());
    }
    let reference: &str = head.strip_prefix("ref:")?.trim();
    for dir in [&git_dir, &common] {
        let loose: PathBuf = dir.join(reference);
        if let Some(id) = read_small(&loose) {
            println!("cargo:rerun-if-changed={}", loose.display());
            let id: &str = id.trim();
            if is_commit_id(id) {
                return Some(id.to_ascii_lowercase());
            }
        }
    }
    let packed_path: PathBuf = common.join("packed-refs");
    println!("cargo:rerun-if-changed={}", packed_path.display());
    let packed: String = read_small(&packed_path)?;
    packed.lines().find_map(|line: &str| {
        let (id, name): (&str, &str) = line.split_once(' ')?;
        (name.trim() == reference && is_commit_id(id)).then(|| id.to_ascii_lowercase())
    })
}

fn emit_commit() {
    println!("cargo:rerun-if-env-changed=DISROBE_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let from_env: Option<String> = ["DISROBE_BUILD_COMMIT", "GITHUB_SHA"]
        .iter()
        .filter_map(|key: &&str| std::env::var(key).ok())
        .map(|value: String| value.trim().to_ascii_lowercase())
        .find(|value: &String| is_commit_id(value));
    let workspace: Option<PathBuf> = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .and_then(|manifest: PathBuf| manifest.parent()?.parent().map(Path::to_path_buf));
    let commit: String = from_env
        .or_else(|| workspace.as_deref().and_then(head_commit))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=DISROBE_COMMIT={commit}");
}

#[cfg(feature = "server")]
fn compile_protos() -> std::io::Result<()> {
    let protoc: PathBuf = protoc_bin_vendored::protoc_bin_path()
        .map_err(|e| std::io::Error::other(format!("protoc-bin-vendored: {e}")))?;
    let proto_root: PathBuf = PathBuf::from("proto");
    let proto_file: PathBuf = proto_root.join("disrobe.proto");
    println!("cargo:rerun-if-changed={}", proto_file.display());
    println!("cargo:rerun-if-changed={}", proto_root.display());

    let out_dir: PathBuf = PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| {
        std::io::Error::other("OUT_DIR not set; cargo must be the caller of build.rs")
    })?);
    let descriptor_path: PathBuf = out_dir.join("disrobe_descriptor.bin");
    let proto_files: [PathBuf; 1] = [proto_file];
    let proto_includes: [PathBuf; 1] = [proto_root];
    let mut prost_config: tonic_build::Config = tonic_build::Config::new();
    prost_config.protoc_executable(protoc);
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos_with_config(prost_config, &proto_files, &proto_includes)?;
    println!(
        "cargo:rustc-env=DISROBE_DESCRIPTOR_PATH={}",
        descriptor_path.display()
    );
    Ok(())
}

#[cfg(feature = "server")]
fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_SERVER");
    emit_commit();
    compile_protos()
}

#[cfg(not(feature = "server"))]
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_SERVER");
    emit_commit();
}
