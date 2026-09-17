#[cfg(feature = "server")]
fn compile_protos() -> std::io::Result<()> {
    use std::path::PathBuf;

    let protoc: PathBuf = protoc_bin_vendored::protoc_bin_path()
        .map_err(|e| std::io::Error::other(format!("protoc-bin-vendored: {e}")))?;
    unsafe {
        std::env::set_var("PROTOC", &protoc);
    }
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
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&proto_files, &proto_includes)?;
    println!(
        "cargo:rustc-env=DISROBE_DESCRIPTOR_PATH={}",
        descriptor_path.display()
    );
    Ok(())
}

#[cfg(feature = "server")]
fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_SERVER");
    compile_protos()
}

#[cfg(not(feature = "server"))]
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_SERVER");
}
