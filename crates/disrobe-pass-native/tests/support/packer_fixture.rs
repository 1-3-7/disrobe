use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::PathBuf;

pub(crate) const REQUIRE_FIXTURES_VAR: &str = "DISROBE_REQUIRE_PACKER_FIXTURES";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixtureRequirement {
    Optional,
    Committed,
    Every,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PackerFixture<'a> {
    pub(crate) decoder: &'a str,
    pub(crate) family: &'a str,
    pub(crate) name: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CommittedFixture {
    pub(crate) family: &'static str,
    pub(crate) name: &'static str,
    pub(crate) size_bytes: u64,
    pub(crate) crc32: u32,
}

pub(crate) const COMMITTED_FIXTURES: &[CommittedFixture] = &[
    CommittedFixture {
        family: "fsg",
        name: "Hash.packed.fsg.exe",
        size_bytes: 16624,
        crc32: 0xa480_90fc,
    },
    CommittedFixture {
        family: "fsg",
        name: "Hash.original.exe",
        size_bytes: 29184,
        crc32: 0x26da_84e4,
    },
    CommittedFixture {
        family: "nspack",
        name: "hash.packed.nspack.exe",
        size_bytes: 19068,
        crc32: 0x28c2_279c,
    },
    CommittedFixture {
        family: "nspack",
        name: "hash.original.exe",
        size_bytes: 29184,
        crc32: 0x26da_84e4,
    },
    CommittedFixture {
        family: "petite",
        name: "hello.exe",
        size_bytes: 52144,
        crc32: 0x7e18_b1e5,
    },
    CommittedFixture {
        family: "petite",
        name: "hello.original.exe",
        size_bytes: 94720,
        crc32: 0xad20_9c87,
    },
];

pub(crate) fn requirement_from_value(value: Option<&OsStr>) -> FixtureRequirement {
    let Some(raw): Option<&OsStr> = value else {
        return FixtureRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => FixtureRequirement::Optional,
        "all" | "every" | "local" => FixtureRequirement::Every,
        _ => FixtureRequirement::Committed,
    }
}

pub(crate) fn fixture_requirement() -> FixtureRequirement {
    let raw: Option<OsString> = std::env::var_os(REQUIRE_FIXTURES_VAR);
    requirement_from_value(raw.as_deref())
}

pub(crate) fn packers_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("..");
    root.push("..");
    root.push("corpus");
    root.push("native");
    root.push("packers");
    root
}

pub(crate) fn fixture_path(family: &str, name: &str) -> PathBuf {
    let mut path: PathBuf = packers_root();
    path.push(family);
    path.push(name);
    path
}

pub(crate) fn is_committed(family: &str, name: &str) -> bool {
    COMMITTED_FIXTURES
        .iter()
        .any(|f: &CommittedFixture| f.family == family && f.name == name)
}

pub(crate) fn enforce_fixture_requirement(
    fixture: &PackerFixture<'_>,
    committed: bool,
    requirement: FixtureRequirement,
) {
    let fatal: bool = match requirement {
        FixtureRequirement::Optional => false,
        FixtureRequirement::Committed => committed,
        FixtureRequirement::Every => true,
    };
    assert!(
        !fatal,
        "{REQUIRE_FIXTURES_VAR} makes this fixture mandatory for this run, so the {} decoder \
         cannot be graded: corpus/native/packers/{}/{} is absent (committed_in_repo={committed})",
        fixture.decoder, fixture.family, fixture.name
    );
    announce_ungraded(fixture);
}

fn announce_ungraded(fixture: &PackerFixture<'_>) {
    let line: String = format!(
        "\nUNGRADED {}: corpus/native/packers/{}/{} is absent, so this case graded nothing. Set \
         {REQUIRE_FIXTURES_VAR}=1 to fail instead of skipping when a committed fixture is missing, \
         or {REQUIRE_FIXTURES_VAR}=all to fail on any absent fixture.\n",
        fixture.decoder, fixture.family, fixture.name
    );
    let mut sink: std::io::StderrLock<'static> = std::io::stderr().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

pub(crate) fn load_fixture(fixture: PackerFixture<'_>) -> Option<Vec<u8>> {
    let path: PathBuf = fixture_path(fixture.family, fixture.name);
    match fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let committed: bool = is_committed(fixture.family, fixture.name);
            enforce_fixture_requirement(&fixture, committed, fixture_requirement());
            None
        }
        Err(err) => panic!(
            "{} fixture {} exists but could not be read ({err}); an unreadable fixture is never a \
             skip, because that is how a quarantined or truncated sample silently stops grading",
            fixture.decoder,
            path.display()
        ),
    }
}

pub(crate) fn enforce_something_was_graded(decoder: &str, graded: usize, family: &str) {
    if graded > 0 {
        return;
    }
    let committed_here: bool = COMMITTED_FIXTURES
        .iter()
        .any(|f: &CommittedFixture| f.family == family);
    enforce_fixture_requirement(
        &PackerFixture {
            decoder,
            family,
            name: "<any fixture>",
        },
        committed_here,
        fixture_requirement(),
    );
}

pub(crate) fn committed_fixture_defect(fixture: &CommittedFixture) -> Option<String> {
    let path: PathBuf = fixture_path(fixture.family, fixture.name);
    let bytes: Vec<u8> = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Some(format!(
                "{}/{} is tracked in the repository but unreadable here ({err})",
                fixture.family, fixture.name
            ));
        }
    };
    if bytes.len() as u64 != fixture.size_bytes {
        return Some(format!(
            "{}/{} is {} bytes, expected {}",
            fixture.family,
            fixture.name,
            bytes.len(),
            fixture.size_bytes
        ));
    }
    let mut hasher: crc32fast::Hasher = crc32fast::Hasher::new();
    hasher.update(&bytes);
    let crc: u32 = hasher.finalize();
    (crc != fixture.crc32).then(|| {
        format!(
            "{}/{} has crc32 {crc:#010x}, expected {:#010x}; the measured floors were taken \
             against the declared bytes",
            fixture.family, fixture.name, fixture.crc32
        )
    })
}
