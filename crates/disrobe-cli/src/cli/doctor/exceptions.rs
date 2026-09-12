use serde::Serialize;

#[cfg(test)]
pub(crate) const DOCTOR_ROSTER_CANARY_KEY: &str = "disrobe-doctor-roster-control";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SkipReason {
    CommercialOrLicenseGated,
    ShipsWithAnotherTool,
    PlatformExclusive,
    PreinstalledByTheOperatingSystem,
    NoManagerModelsItsInstallPath,
    NoPackageOnAnyManager,
    Unclassified,
}

impl SkipReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CommercialOrLicenseGated => "commercial or license gated",
            Self::ShipsWithAnotherTool => "ships with another tool",
            Self::PlatformExclusive => "platform exclusive",
            Self::PreinstalledByTheOperatingSystem => "preinstalled by the operating system",
            Self::NoManagerModelsItsInstallPath => "no supported manager models its install path",
            Self::NoPackageOnAnyManager => "no package on any manager",
            Self::Unclassified => "unclassified, no exception recorded",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DoctorOnlyException {
    pub(crate) key: &'static str,
    pub(crate) reason: SkipReason,
    pub(crate) ships_with: Option<&'static str>,
}

pub(crate) const DOCTOR_ONLY_EXCEPTIONS: &[DoctorOnlyException] = &[
    DoctorOnlyException {
        key: "ida",
        reason: SkipReason::CommercialOrLicenseGated,
        ships_with: None,
    },
    DoctorOnlyException {
        key: "javac",
        reason: SkipReason::ShipsWithAnotherTool,
        ships_with: Some("java"),
    },
    DoctorOnlyException {
        key: "llvm-mc",
        reason: SkipReason::ShipsWithAnotherTool,
        ships_with: Some("llvm"),
    },
    DoctorOnlyException {
        key: "llvm-objdump",
        reason: SkipReason::ShipsWithAnotherTool,
        ships_with: Some("llvm"),
    },
    DoctorOnlyException {
        key: "npm",
        reason: SkipReason::ShipsWithAnotherTool,
        ships_with: Some("node"),
    },
    DoctorOnlyException {
        key: "swiftc",
        reason: SkipReason::ShipsWithAnotherTool,
        ships_with: Some("swift"),
    },
    DoctorOnlyException {
        key: "codesign",
        reason: SkipReason::PlatformExclusive,
        ships_with: None,
    },
    DoctorOnlyException {
        key: "lipo",
        reason: SkipReason::PlatformExclusive,
        ships_with: None,
    },
    DoctorOnlyException {
        key: "otool",
        reason: SkipReason::PlatformExclusive,
        ships_with: None,
    },
    DoctorOnlyException {
        key: "bsdtar",
        reason: SkipReason::PreinstalledByTheOperatingSystem,
        ships_with: None,
    },
    DoctorOnlyException {
        key: "ilspycmd",
        reason: SkipReason::NoManagerModelsItsInstallPath,
        ships_with: None,
    },
    DoctorOnlyException {
        key: "de4dot",
        reason: SkipReason::NoPackageOnAnyManager,
        ships_with: None,
    },
];

pub(crate) fn skip_reason_for(canonical_key: &str) -> SkipReason {
    DOCTOR_ONLY_EXCEPTIONS
        .iter()
        .find(|entry: &&DoctorOnlyException| entry.key == canonical_key)
        .map_or(SkipReason::Unclassified, |entry: &DoctorOnlyException| {
            entry.reason
        })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstallOnlyReason {
    InstallerSelfTest,
    UmbrellaCoveredByIndividualProbes,
    LegacyOptOut,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct InstallOnlyException {
    pub(crate) key: &'static str,
    pub(crate) reason: InstallOnlyReason,
    pub(crate) covered_by: &'static [&'static str],
}

#[cfg(test)]
pub(crate) const INSTALL_ONLY_EXCEPTIONS: &[InstallOnlyException] = &[
    InstallOnlyException {
        key: "bat",
        reason: InstallOnlyReason::InstallerSelfTest,
        covered_by: &[],
    },
    InstallOnlyException {
        key: "llvm",
        reason: InstallOnlyReason::UmbrellaCoveredByIndividualProbes,
        covered_by: &["llvm-mc", "llvm-objdump"],
    },
    InstallOnlyException {
        key: "python2",
        reason: InstallOnlyReason::LegacyOptOut,
        covered_by: &[],
    },
];

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::cli::doctor::catalog::tool_catalog_all_platforms;
    use crate::cli::doctor::{
        ClassifiedMissing, ToolEntry, ToolKind, ToolStatus, classify_missing_tools, probe_entry,
    };
    use crate::cli::install::{InstallSpec, canonicalize_alias, install_action_map};

    fn all_platform_doctor_keys() -> BTreeSet<&'static str> {
        tool_catalog_all_platforms()
            .into_iter()
            .map(|entry: ToolEntry| entry.key)
            .filter(|key: &&str| *key != DOCTOR_ROSTER_CANARY_KEY)
            .collect()
    }

    #[test]
    fn no_doctor_only_exception_is_stale() {
        let doctor_keys: BTreeSet<&str> = all_platform_doctor_keys();
        let install_keys: BTreeSet<&str> = install_action_map().keys().copied().collect();
        for exception in DOCTOR_ONLY_EXCEPTIONS {
            assert!(
                doctor_keys.contains(exception.key),
                "`{}` is in the doctor-only exception list but is no longer probed by any \
                 platform's tool_catalog",
                exception.key
            );
            let canonical: &str = canonicalize_alias(exception.key);
            assert!(
                !install_keys.contains(canonical),
                "`{}` is in the doctor-only exception list but now resolves to a real install \
                 action; remove it from the exception list instead of leaving a stale entry",
                exception.key
            );
        }
    }

    #[test]
    fn no_install_only_exception_is_stale() {
        let doctor_keys: BTreeSet<&str> = all_platform_doctor_keys();
        let install_keys: BTreeSet<&str> = install_action_map().keys().copied().collect();
        for exception in INSTALL_ONLY_EXCEPTIONS {
            assert!(
                install_keys.contains(exception.key),
                "`{}` is in the install-only exception list but is no longer in \
                 install_action_map",
                exception.key
            );
            assert!(
                !doctor_keys.contains(exception.key),
                "`{}` is in the install-only exception list but is now probed by doctor; remove \
                 it from the exception list instead of leaving a stale entry",
                exception.key
            );
        }
    }

    #[test]
    fn every_doctor_only_divergence_is_a_recorded_exception() {
        let doctor_keys: BTreeSet<&str> = all_platform_doctor_keys();
        let install_keys: BTreeSet<&str> = install_action_map().keys().copied().collect();
        let excepted: BTreeSet<&str> = DOCTOR_ONLY_EXCEPTIONS
            .iter()
            .map(|entry: &DoctorOnlyException| entry.key)
            .collect();
        let mut unlisted: Vec<&str> = Vec::new();
        for key in &doctor_keys {
            let canonical: &str = canonicalize_alias(key);
            if install_keys.contains(canonical) {
                continue;
            }
            if !excepted.contains(key) {
                unlisted.push(key);
            }
        }
        assert!(
            unlisted.is_empty(),
            "doctor probes {unlisted:?} with no install action and no exception list entry"
        );
    }

    #[test]
    fn every_install_only_divergence_is_a_recorded_exception() {
        let doctor_keys: BTreeSet<&str> = all_platform_doctor_keys();
        let install_keys: BTreeSet<&str> = install_action_map().keys().copied().collect();
        let excepted: BTreeSet<&str> = INSTALL_ONLY_EXCEPTIONS
            .iter()
            .map(|entry: &InstallOnlyException| entry.key)
            .collect();
        let mut unlisted: Vec<&str> = Vec::new();
        for key in &install_keys {
            let covered: bool = doctor_keys
                .iter()
                .any(|doctor_key: &&str| canonicalize_alias(doctor_key) == *key);
            if covered {
                continue;
            }
            if !excepted.contains(key) {
                unlisted.push(key);
            }
        }
        assert!(
            unlisted.is_empty(),
            "install_action_map carries {unlisted:?} with no doctor entry and no exception list \
             entry"
        );
    }

    #[test]
    fn ships_with_another_tool_exceptions_name_a_real_install_key() {
        let install_keys: BTreeSet<&str> = install_action_map().keys().copied().collect();
        for exception in DOCTOR_ONLY_EXCEPTIONS {
            match exception.reason {
                SkipReason::ShipsWithAnotherTool => {
                    let parent: &str = exception
                        .ships_with
                        .expect("a ships-with-another-tool exception must name the parent tool");
                    assert!(
                        install_keys.contains(parent),
                        "`{}` claims to ship with `{parent}`, but `{parent}` has no install \
                         action",
                        exception.key
                    );
                }
                _ => assert!(
                    exception.ships_with.is_none(),
                    "`{}` names a parent tool but its reason is not ShipsWithAnotherTool",
                    exception.key
                ),
            }
        }
    }

    #[test]
    fn umbrella_install_only_exceptions_name_real_doctor_keys() {
        let doctor_keys: BTreeSet<&str> = all_platform_doctor_keys();
        for exception in INSTALL_ONLY_EXCEPTIONS {
            for covered_key in exception.covered_by {
                assert!(
                    doctor_keys.contains(covered_key),
                    "`{}` claims to be covered by probing `{covered_key}`, but that key is not \
                     in any platform's tool_catalog",
                    exception.key
                );
            }
        }
    }

    #[test]
    fn install_only_exceptions_carry_the_reason_the_item_documents() {
        let expected: BTreeMap<&str, InstallOnlyReason> = BTreeMap::from([
            ("bat", InstallOnlyReason::InstallerSelfTest),
            ("llvm", InstallOnlyReason::UmbrellaCoveredByIndividualProbes),
            ("python2", InstallOnlyReason::LegacyOptOut),
        ]);
        assert_eq!(
            INSTALL_ONLY_EXCEPTIONS.len(),
            expected.len(),
            "an install-only exception was added or removed without updating this pinned map"
        );
        for exception in INSTALL_ONLY_EXCEPTIONS {
            let want: InstallOnlyReason = *expected
                .get(exception.key)
                .unwrap_or_else(|| panic!("`{}` has no pinned expected reason", exception.key));
            assert_eq!(
                exception.reason, want,
                "`{}` changed reason; update the pinned map if that is deliberate",
                exception.key
            );
        }
    }

    #[test]
    fn disrobe_doctor_roster_control_canary_is_present_and_excluded_from_the_install_crosscheck() {
        let absent: ToolEntry = ToolEntry {
            key: DOCTOR_ROSTER_CANARY_KEY,
            probe_names: &["disrobe-tool-that-is-not-installed-anywhere"],
            env_overrides: &[],
            kind: ToolKind::Optional,
            used_by: "the control that proves an absent tool is reported absent",
            version_args: &["--version"],
        };
        let status: ToolStatus = probe_entry(&absent);
        assert!(
            !status.available,
            "the canary must still be reported missing by probe_entry"
        );

        let exclusion: BTreeSet<&str> = std::iter::once(DOCTOR_ROSTER_CANARY_KEY).collect();
        assert_eq!(
            exclusion.len(),
            1,
            "the canary exclusion must name exactly one key so it cannot silently grow to cover \
             a real divergence"
        );
        let doctor_keys_including_canary: BTreeSet<&str> = tool_catalog_all_platforms()
            .into_iter()
            .map(|entry: ToolEntry| entry.key)
            .collect();
        assert!(
            !doctor_keys_including_canary.contains(DOCTOR_ROSTER_CANARY_KEY),
            "the canary is a test fixture, not a tool_catalog member; if this ever fires, the \
             cross-check must start excluding it by name rather than requiring it to have a real \
             install action"
        );
    }

    #[test]
    fn every_alias_resolves_to_a_key_on_at_least_one_roster() {
        let doctor_keys: BTreeSet<&str> = all_platform_doctor_keys();
        let install_keys: BTreeSet<&str> = install_action_map().keys().copied().collect();
        let aliases: [&str; 15] = [
            "g",
            "ghidra-headless",
            "proguard",
            "ProGuard",
            "r8",
            "R8",
            "d8",
            "D8",
            "luajit2",
            "py3",
            "py",
            "py2",
            "uv-pip",
            "--py3",
            " py2 ",
        ];
        for alias in aliases {
            let canonical: &str = canonicalize_alias(alias);
            assert!(
                doctor_keys.contains(canonical) || install_keys.contains(canonical),
                "alias `{alias}` canonicalizes to `{canonical}`, which is on neither roster"
            );
        }
    }

    fn fake_status(key: &'static str, available: bool) -> ToolStatus {
        ToolStatus {
            name: key.to_owned(),
            kind: ToolKind::Optional.as_str(),
            available,
            version: None,
            path: None,
            env_source: None,
            used_by: "test",
            install_hint: if available {
                None
            } else {
                Some(format!("disrobe install {key}"))
            },
        }
    }

    #[test]
    fn missing_equals_attempts_plus_skips_when_every_tool_is_missing() {
        let catalog: Vec<ToolEntry> = tool_catalog_all_platforms();
        let statuses: Vec<ToolStatus> = catalog
            .iter()
            .map(|entry: &ToolEntry| fake_status(entry.key, false))
            .collect();
        let install_map: BTreeMap<&'static str, InstallSpec> = install_action_map();
        let classified: ClassifiedMissing<'_> = classify_missing_tools(&statuses, &install_map);
        let missing: usize = statuses
            .iter()
            .filter(|s: &&ToolStatus| !s.available)
            .count();
        assert_eq!(missing, classified.attempts.len() + classified.skips.len());
        assert!(
            !classified.skips.is_empty(),
            "at least one tool has no install action"
        );
        assert!(
            !classified.attempts.is_empty(),
            "at least one tool has a real install action"
        );
    }

    #[test]
    fn missing_equals_attempts_plus_skips_when_nothing_is_missing() {
        let catalog: Vec<ToolEntry> = tool_catalog_all_platforms();
        let statuses: Vec<ToolStatus> = catalog
            .iter()
            .map(|entry: &ToolEntry| fake_status(entry.key, true))
            .collect();
        let install_map: BTreeMap<&'static str, InstallSpec> = install_action_map();
        let classified: ClassifiedMissing<'_> = classify_missing_tools(&statuses, &install_map);
        assert!(classified.attempts.is_empty());
        assert!(classified.skips.is_empty());
    }

    #[test]
    fn an_unclassified_missing_tool_is_still_recorded_as_a_skip() {
        let statuses: Vec<ToolStatus> =
            vec![fake_status("definitely-not-catalogued-anywhere", false)];
        let install_map: BTreeMap<&'static str, InstallSpec> = install_action_map();
        let classified: ClassifiedMissing<'_> = classify_missing_tools(&statuses, &install_map);
        assert_eq!(classified.attempts.len(), 0);
        assert_eq!(classified.skips.len(), 1);
        assert_eq!(classified.skips[0].reason, SkipReason::Unclassified);
    }
}
