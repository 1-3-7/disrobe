#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;

#[test]
fn map_has_minimum_coverage() {
    let m: BTreeMap<&'static str, InstallSpec> = install_action_map();
    assert!(m.len() >= 30, "expected >= 30 tools, got {}", m.len());
    for key in [
        "ghidra", "rizin", "upx", "java", "kotlinc", "dotnet", "php", "ruby", "lua", "luajit",
        "python", "uv", "docker", "swift", "apktool",
    ] {
        assert!(m.contains_key(key), "missing tool key: {key}");
    }
}

#[test]
fn upx_resolves_on_all_platforms() {
    let m: BTreeMap<&'static str, InstallSpec> = install_action_map();
    let spec: &InstallSpec = m.get("upx").expect("upx");
    for plat in [
        Platform::Windows,
        Platform::MacOs,
        Platform::LinuxApt,
        Platform::LinuxDnf,
        Platform::LinuxPacman,
        Platform::LinuxApk,
    ] {
        assert!(
            spec.per_platform.contains_key(&plat),
            "upx missing platform {}",
            plat.as_str()
        );
    }
}

#[test]
fn alias_python_canonicalizes() {
    assert_eq!(canonicalize_alias("py"), "python");
    assert_eq!(canonicalize_alias("py3"), "python");
    assert_eq!(canonicalize_alias("ProGuard"), "proguard");
    assert_eq!(canonicalize_alias("ghidra-headless"), "ghidra");
}

#[test]
fn unknown_tool_passes_through() {
    assert_eq!(canonicalize_alias("nonsense-tool"), "nonsense-tool");
}

#[test]
fn dry_run_does_not_execute() {
    let m: BTreeMap<&'static str, InstallSpec> = install_action_map();
    let spec: &InstallSpec = m.get("bat").expect("bat");
    let r: InstallReport = perform_install("bat", spec, Platform::Windows, true, true);
    assert_eq!(r.status, "dry-run");
    assert!(r.action_cmd.is_some());
}

#[test]
fn unsupported_platform_reported() {
    let mut per: BTreeMap<Platform, InstallAction> = BTreeMap::new();
    per.insert(
        Platform::Windows,
        InstallAction {
            cmd: "echo",
            args: vec!["ok"],
            requires_admin: false,
        },
    );
    let spec: InstallSpec = InstallSpec {
        per_platform: per,
        note: None,
    };
    let r: InstallReport = perform_install("x", &spec, Platform::MacOs, true, true);
    assert_eq!(r.status, "unsupported-platform");
}

#[test]
fn tail_respects_char_boundaries() {
    let s: String = "hÃ©llo, world! ä½ å¥½".repeat(50);
    let t: String = tail(&s, 50);
    assert!(t.len() <= 50);
}
