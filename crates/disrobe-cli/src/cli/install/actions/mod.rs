use std::collections::BTreeMap;

use super::{InstallAction, InstallSpec, Platform};

mod lang;
mod native;

pub(crate) fn install_action_map() -> BTreeMap<&'static str, InstallSpec> {
    let mut m: BTreeMap<&'static str, InstallSpec> = BTreeMap::new();
    native::add_native_and_runtime_pkgs(&mut m);
    lang::add_lang_and_packaging_pkgs(&mut m);
    m
}

pub(super) struct ToolPkg {
    winget: Option<&'static str>,
    brew: Option<&'static str>,
    brew_cask: bool,
    apt: Option<&'static str>,
    dnf: Option<&'static str>,
    pacman: Option<&'static str>,
    apk: Option<&'static str>,
    cargo: Option<&'static str>,
    pip: Option<&'static str>,
}

pub(super) fn add_simple_pkg(
    m: &mut BTreeMap<&'static str, InstallSpec>,
    key: &'static str,
    note: &'static str,
    pkg: ToolPkg,
) {
    let mut per: BTreeMap<Platform, InstallAction> = BTreeMap::new();
    if let Some(id) = pkg.winget {
        per.insert(
            Platform::Windows,
            InstallAction {
                cmd: "winget",
                args: vec![
                    "install",
                    "--id",
                    id,
                    "--silent",
                    "--accept-source-agreements",
                    "--accept-package-agreements",
                    "--disable-interactivity",
                ],
                requires_admin: false,
            },
        );
    }
    if let Some(pkgname) = pkg.brew {
        let args: Vec<&'static str> = if pkg.brew_cask {
            vec!["install", "--cask", pkgname]
        } else {
            vec!["install", pkgname]
        };
        per.insert(
            Platform::MacOs,
            InstallAction {
                cmd: "brew",
                args,
                requires_admin: false,
            },
        );
    }
    if let Some(pkgname) = pkg.apt {
        per.insert(
            Platform::LinuxApt,
            InstallAction {
                cmd: "apt-get",
                args: vec!["install", "-y", pkgname],
                requires_admin: true,
            },
        );
    }
    if let Some(pkgname) = pkg.dnf {
        per.insert(
            Platform::LinuxDnf,
            InstallAction {
                cmd: "dnf",
                args: vec!["install", "-y", pkgname],
                requires_admin: true,
            },
        );
    }
    if let Some(pkgname) = pkg.pacman {
        per.insert(
            Platform::LinuxPacman,
            InstallAction {
                cmd: "pacman",
                args: vec!["-S", "--noconfirm", pkgname],
                requires_admin: true,
            },
        );
    }
    if let Some(pkgname) = pkg.apk {
        per.insert(
            Platform::LinuxApk,
            InstallAction {
                cmd: "apk",
                args: vec!["add", "--no-cache", pkgname],
                requires_admin: true,
            },
        );
    }
    if let Some(pkgname) = pkg.cargo {
        for plat in [
            Platform::Windows,
            Platform::MacOs,
            Platform::LinuxApt,
            Platform::LinuxDnf,
            Platform::LinuxPacman,
            Platform::LinuxApk,
            Platform::LinuxUnknown,
        ] {
            per.entry(plat).or_insert_with(|| InstallAction {
                cmd: "cargo",
                args: vec!["install", pkgname],
                requires_admin: false,
            });
        }
    }
    if let Some(pkgname) = pkg.pip {
        for plat in [
            Platform::Windows,
            Platform::MacOs,
            Platform::LinuxApt,
            Platform::LinuxDnf,
            Platform::LinuxPacman,
            Platform::LinuxApk,
            Platform::LinuxUnknown,
        ] {
            per.entry(plat).or_insert_with(|| InstallAction {
                cmd: "pip",
                args: vec!["install", "--user", pkgname],
                requires_admin: false,
            });
        }
    }
    m.insert(
        key,
        InstallSpec {
            per_platform: per,
            note: Some(note),
        },
    );
}
