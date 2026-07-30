use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

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
        family: "aspack",
        name: "AccessEnum.original.exe",
        size_bytes: 174_968,
        crc32: 0x0a1a_c525,
    },
    CommittedFixture {
        family: "aspack",
        name: "AccessEnum.packed.aspack.exe",
        size_bytes: 52_736,
        crc32: 0x643b_3fbe,
    },
    CommittedFixture {
        family: "aspack",
        name: "Clockres.original.exe",
        size_bytes: 139_944,
        crc32: 0x46c2_7692,
    },
    CommittedFixture {
        family: "aspack",
        name: "Clockres.packed.aspack.exe",
        size_bytes: 59_904,
        crc32: 0x7df3_477b,
    },
    CommittedFixture {
        family: "fsg",
        name: "Hash.original.exe",
        size_bytes: 29_184,
        crc32: 0x26da_84e4,
    },
    CommittedFixture {
        family: "fsg",
        name: "Hash.packed.fsg.exe",
        size_bytes: 16_624,
        crc32: 0xa480_90fc,
    },
    CommittedFixture {
        family: "kkrunchy",
        name: "hello.exe",
        size_bytes: 1_024,
        crc32: 0x687e_5d0f,
    },
    CommittedFixture {
        family: "kkrunchy",
        name: "hello.packed.kkrunchy.exe",
        size_bytes: 5_632,
        crc32: 0x4633_b742,
    },
    CommittedFixture {
        family: "kkrunchy",
        name: "hello.packed.kkrunchy_classic.exe",
        size_bytes: 4_608,
        crc32: 0x14ac_dd76,
    },
    CommittedFixture {
        family: "mew",
        name: "AccessEnum.original.exe",
        size_bytes: 174_968,
        crc32: 0x0a1a_c525,
    },
    CommittedFixture {
        family: "mew",
        name: "AccessEnum.packed.mew.exe",
        size_bytes: 41_810,
        crc32: 0x6b68_c14e,
    },
    CommittedFixture {
        family: "mew",
        name: "Autologon.original.exe",
        size_bytes: 138_920,
        crc32: 0x358f_b1f0,
    },
    CommittedFixture {
        family: "mew",
        name: "Autologon.packed.mew.exe",
        size_bytes: 47_510,
        crc32: 0xb6c7_ae2f,
    },
    CommittedFixture {
        family: "mew",
        name: "Clockres.original.exe",
        size_bytes: 139_944,
        crc32: 0x46c2_7692,
    },
    CommittedFixture {
        family: "mew",
        name: "Clockres.packed.mew.exe",
        size_bytes: 47_784,
        crc32: 0x4d85_a2ba,
    },
    CommittedFixture {
        family: "mpress",
        name: "gauntlet/gauntlet_target.original.exe",
        size_bytes: 104_448,
        crc32: 0x3d68_bd5b,
    },
    CommittedFixture {
        family: "mpress",
        name: "gauntlet/gauntlet_target.packed.mpress219.exe",
        size_bytes: 50_176,
        crc32: 0x00c2_305c,
    },
    CommittedFixture {
        family: "nspack",
        name: "hash.original.exe",
        size_bytes: 29_184,
        crc32: 0x26da_84e4,
    },
    CommittedFixture {
        family: "nspack",
        name: "hash.packed.nspack.exe",
        size_bytes: 19_068,
        crc32: 0x28c2_279c,
    },
    CommittedFixture {
        family: "pecompact",
        name: "AccessEnum.original.exe",
        size_bytes: 174_968,
        crc32: 0x0a1a_c525,
    },
    CommittedFixture {
        family: "pecompact",
        name: "AccessEnum.packed.pecompact.exe",
        size_bytes: 52_600,
        crc32: 0xd36c_e0c6,
    },
    CommittedFixture {
        family: "pecompact",
        name: "Clockres.original.exe",
        size_bytes: 139_944,
        crc32: 0x46c2_7692,
    },
    CommittedFixture {
        family: "pecompact",
        name: "Clockres.packed.pecompact.exe",
        size_bytes: 68_264,
        crc32: 0xa761_e727,
    },
    CommittedFixture {
        family: "petite",
        name: "hello.exe",
        size_bytes: 52_144,
        crc32: 0x7e18_b1e5,
    },
    CommittedFixture {
        family: "petite",
        name: "hello.original.exe",
        size_bytes: 94_720,
        crc32: 0xad20_9c87,
    },
    CommittedFixture {
        family: "upx",
        name: "hello.original.exe",
        size_bytes: 104_448,
        crc32: 0x3d68_bd5b,
    },
    CommittedFixture {
        family: "upx",
        name: "hello.packed.lzma.exe",
        size_bytes: 51_712,
        crc32: 0xd8c7_3398,
    },
    CommittedFixture {
        family: "upx",
        name: "hello.packed.nrv2b.exe",
        size_bytes: 53_248,
        crc32: 0x1b63_6f0a,
    },
    CommittedFixture {
        family: "yodas_crypter",
        name: "AccessEnum.original.exe",
        size_bytes: 174_968,
        crc32: 0x0a1a_c525,
    },
    CommittedFixture {
        family: "yodas_crypter",
        name: "AccessEnum.packed.yodascrypter.exe",
        size_bytes: 171_134,
        crc32: 0x124b_fd3c,
    },
    CommittedFixture {
        family: "yodas_crypter",
        name: "Clockres.original.exe",
        size_bytes: 139_944,
        crc32: 0x46c2_7692,
    },
    CommittedFixture {
        family: "yodas_crypter",
        name: "Clockres.packed.yodascrypter.exe",
        size_bytes: 127_102,
        crc32: 0xc436_3b4d,
    },
    CommittedFixture {
        family: "yodas_protector",
        name: "AccessEnum.original.exe",
        size_bytes: 174_968,
        crc32: 0x0a1a_c525,
    },
    CommittedFixture {
        family: "yodas_protector",
        name: "AccessEnum.packed.yodasprotector.exe",
        size_bytes: 77_824,
        crc32: 0xc29e_0ca8,
    },
    CommittedFixture {
        family: "yodas_protector",
        name: "Clockres.original.exe",
        size_bytes: 139_944,
        crc32: 0x46c2_7692,
    },
    CommittedFixture {
        family: "yodas_protector",
        name: "Clockres.packed.yodasprotector.exe",
        size_bytes: 70_144,
        crc32: 0x7c85_e5b5,
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

pub(crate) fn fixture_role(name: &str) -> &'static str {
    if name.starts_with('<') {
        "unspecified-role"
    } else if name.contains(".original.") || name.contains(".unpacked.") {
        "original"
    } else {
        "packed"
    }
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
    let path: PathBuf = fixture_path(fixture.family, fixture.name);
    assert!(
        !fatal,
        "{REQUIRE_FIXTURES_VAR} makes this fixture mandatory for this run, so the {decoder} \
         decoder cannot be graded and this case must not report success. The {role} fixture of \
         family {family} is absent: expected it at {resolved}, which is \
         corpus/native/packers/{family}/{name} in the repository (tracked_in_git={committed}). \
         Restore that file, or clear {REQUIRE_FIXTURES_VAR} to permit a run that grades nothing \
         here.",
        decoder = fixture.decoder,
        role = fixture_role(fixture.name),
        family = fixture.family,
        resolved = path.display(),
        name = fixture.name,
    );
    announce_ungraded(fixture, &path);
}

fn announce_ungraded(fixture: &PackerFixture<'_>, path: &Path) {
    let line: String = format!(
        "\nUNGRADED {decoder}: the {role} fixture of family {family} is absent at {resolved} \
         (corpus/native/packers/{family}/{name}), so this case measured nothing and graded \
         nothing. Set {REQUIRE_FIXTURES_VAR}=1 to fail instead of skipping when a fixture tracked \
         in git is missing, or {REQUIRE_FIXTURES_VAR}=all to fail on any absent fixture.\n",
        decoder = fixture.decoder,
        role = fixture_role(fixture.name),
        family = fixture.family,
        resolved = path.display(),
        name = fixture.name,
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

pub(crate) fn load_fixture_with_requirement(
    fixture: PackerFixture<'_>,
    requirement: FixtureRequirement,
) -> Option<Vec<u8>> {
    let path: PathBuf = fixture_path(fixture.family, fixture.name);
    match fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let committed: bool = is_committed(fixture.family, fixture.name);
            enforce_fixture_requirement(&fixture, committed, requirement);
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

pub(crate) fn load_fixture(fixture: PackerFixture<'_>) -> Option<Vec<u8>> {
    load_fixture_with_requirement(fixture, fixture_requirement())
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
