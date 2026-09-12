fn main() -> Result<(), std::env::VarError> {
    println!("cargo::rerun-if-changed=build.rs");
    let arch: String = std::env::var("CARGO_CFG_TARGET_ARCH")?;
    if arch == "wasm32" {
        println!("cargo::rustc-link-arg-cdylib=--max-memory=536870912");
    }
    Ok(())
}
