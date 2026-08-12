#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use disrobe_vulnmatch::{OfflineMatchError, OfflineMatchIssueKind, match_debian_rootfs};

fn rootfs(status: &[u8]) -> ScratchDir {
    let scratch: ScratchDir = ScratchDir::create("vulnmatch-offline-debian").expect("scratch");
    write(&scratch.path().join("var/lib/dpkg/status"), status);
    write(
        &scratch.path().join("etc/os-release"),
        b"ID=debian\nVERSION_ID=12\n",
    );
    scratch
}

fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("fixture directory");
    }
    std::fs::write(path, bytes).expect("fixture");
}

fn database(scratch: &ScratchDir, affected: &str) -> PathBuf {
    let path: PathBuf = scratch.path().join("osv.json");
    let document: String = format!(
        "{{\"schema_version\":\"1.2.0\",\"id\":\"DSA-1\",\"modified\":\"2026-08-12T00:00:00Z\",\"affected\":[{affected}]}}"
    );
    write(&path, document.as_bytes());
    path
}

#[test]
fn exact_installed_state_and_architecture_are_preserved() {
    let scratch: ScratchDir = rootfs(
        b"Package: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:1.2.13.dfsg-1\n\nPackage: zlib1g\nStatus: hold ok installed\nArchitecture: arm64\nVersion: 1:1.2.12.dfsg-1\n\nPackage: zlib1g\nStatus: install ok unpacked\nArchitecture: i386\nVersion: 1:1.2.11.dfsg-1\n",
    );
    let database: PathBuf = database(
        &scratch,
        r#"{"package":{"ecosystem":"Debian:12","name":"zlib1g"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.2.14.dfsg-1"}]}]}"#,
    );
    let report = match_debian_rootfs(scratch.path(), &database).expect("match");

    assert_eq!(report.packages_scanned, 1);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].package.architecture, "amd64");
}

#[test]
fn matching_indexes_package_names_without_losing_architectures() {
    let scratch: ScratchDir = rootfs(
        b"Package: unrelated\nStatus: install ok installed\nArchitecture: amd64\nVersion: 9.0-1\n\nPackage: zlib1g\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.0-1\n\nPackage: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n",
    );
    let database: PathBuf = database(
        &scratch,
        r#"{"package":{"ecosystem":"Debian:12","name":"zlib1g"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}"#,
    );
    let report = match_debian_rootfs(scratch.path(), &database).expect("match");

    assert_eq!(report.packages_scanned, 3);
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.findings[0].package.architecture, "amd64");
    assert_eq!(report.findings[1].package.architecture, "arm64");
}

#[test]
fn duplicate_identity_field_is_rejected() {
    let scratch: ScratchDir = rootfs(
        b"Package: zlib1g\nPackage: other\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n",
    );
    let database: PathBuf = database(&scratch, "");
    let error: OfflineMatchError =
        match_debian_rootfs(scratch.path(), &database).expect_err("duplicate rejected");

    assert!(matches!(
        error,
        OfflineMatchError::DuplicateField {
            field: "Package",
            ..
        }
    ));
}

#[test]
fn oversized_status_line_is_rejected_before_ownership_growth() {
    let mut status: Vec<u8> = b"Description: ".to_vec();
    status.extend(std::iter::repeat_n(b'x', 65 * 1024));
    let scratch: ScratchDir = rootfs(&status);
    let database: PathBuf = database(&scratch, "");
    let error: OfflineMatchError =
        match_debian_rootfs(scratch.path(), &database).expect_err("large line rejected");

    assert!(matches!(error, OfflineMatchError::LineTooLong { .. }));
}

#[test]
fn nonconforming_osv_event_is_typed_incomplete_output() {
    let scratch: ScratchDir = rootfs(
        b"Package: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n",
    );
    let database: PathBuf = database(
        &scratch,
        r#"{"package":{"ecosystem":"Debian:12","name":"zlib1g"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"2.0-1"}]}]}"#,
    );
    let report = match_debian_rootfs(scratch.path(), &database).expect("typed report");

    assert!(!report.complete);
    assert_eq!(report.issues.len(), 1);
    assert_eq!(
        report.issues[0].kind,
        OfflineMatchIssueKind::InvalidConstraint
    );
    assert!(report.findings.is_empty());
}

#[test]
fn supported_matching_range_wins_independent_of_unsupported_range_order() {
    let scratch: ScratchDir = rootfs(
        b"Package: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n",
    );
    let database: PathBuf = database(
        &scratch,
        r#"{"package":{"ecosystem":"Debian:12","name":"zlib1g"},"ranges":[{"type":"GIT","events":[{"introduced":"abc"}]},{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]}]}"#,
    );
    let report = match_debian_rootfs(scratch.path(), &database).expect("match");

    assert!(report.complete);
    assert_eq!(report.findings.len(), 1);
    assert!(report.issues.is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_status_file_cannot_escape_rootfs() {
    use std::os::unix::fs::symlink;

    let scratch: ScratchDir = ScratchDir::create("vulnmatch-root-escape").expect("scratch");
    let outside: PathBuf = scratch.path().join("outside-status");
    write(&outside, b"");
    let status: PathBuf = scratch.path().join("root/var/lib/dpkg/status");
    std::fs::create_dir_all(status.parent().expect("parent")).expect("fixture directory");
    symlink(&outside, &status).expect("symlink");
    write(
        &scratch.path().join("root/etc/os-release"),
        b"ID=debian\nVERSION_ID=12\n",
    );
    let database: PathBuf = database(&scratch, "");
    let error: OfflineMatchError =
        match_debian_rootfs(&scratch.path().join("root"), &database).expect_err("escape rejected");

    assert!(matches!(error, OfflineMatchError::RootEscape { .. }));
}
