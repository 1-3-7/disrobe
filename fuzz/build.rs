fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let target_env: Option<String> = std::env::var("CARGO_CFG_TARGET_ENV").ok();
    if target_env.as_deref() == Some("msvc") {
        println!("cargo::rustc-link-arg-bins=/include:main");
    }
}
