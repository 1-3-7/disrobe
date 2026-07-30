use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{self, CpuKind, FatArchEntry, MachoKind, ParsedSlice};

pub(crate) const REQUIRE_CORPUS_VAR: &str = "DISROBE_REQUIRE_MACHO_CORPUS";

const MACHO_MAC_DIR: &str = "mobile/macho-mac";
const SWIFTSHIELD_EDGE_DIR: &str = "mobile/macho-mac/swiftshield-edgecases";
const CONFIDENTIAL_EDGE_DIR: &str = "mobile/macho-mac/confidential-edgecases";
const MEGAFILE_DIR: &str = "mac/megafile";
const IPA_DIR: &str = "mobile/ipa";
const ZIG_DIR: &str = "native/zig";

const MACOS_SYSTEM_HINT: &str = "copy the same-named binary out of /usr/bin or /usr/lib on a macOS \
                                 host into corpus/mobile/macho-mac";
const HOMEBREW_HINT: &str = "install the tool with Homebrew on a macOS host and copy the arm64 \
                             binary into corpus/mobile/macho-mac";
const SWIFT_DRIVER_HINT: &str = "copy swift-driver out of an installed Xcode toolchain on a macOS \
                                 host into corpus/mobile/macho-mac";
const CONFIDENTIAL_HINT: &str = "rebuild the Confidential sample on a macOS host as described in \
                                 corpus/mobile/macho-mac/confidential-edgecases";
const LIPO_THIN_HINT: &str = "carve the slice out of the committed EdgeCases.fat with \
                              `lipo -thin <arch> EdgeCases.fat -output <name>` on a macOS host";
const IPA_HINT: &str = "download the release .ipa named in corpus/mobile/ipa/MANIFEST.toml";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BytesPin {
    pub(crate) size_bytes: usize,
    pub(crate) blake3: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Provenance {
    TrackedInGit(Option<BytesPin>),
    SourcedOnTheHost(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CorpusFixture {
    pub(crate) dir: &'static str,
    pub(crate) name: &'static str,
    pub(crate) provenance: Provenance,
}

impl CorpusFixture {
    pub(crate) fn relative(&self) -> String {
        format!("corpus/{}/{}", self.dir, self.name)
    }

    pub(crate) fn path(&self) -> PathBuf {
        let mut path: PathBuf = corpus_root();
        for part in self.dir.split('/') {
            path.push(part);
        }
        path.push(self.name);
        path
    }
}

const fn tracked(dir: &'static str, name: &'static str, pin: BytesPin) -> CorpusFixture {
    CorpusFixture {
        dir,
        name,
        provenance: Provenance::TrackedInGit(Some(pin)),
    }
}

const fn tracked_unpinned(dir: &'static str, name: &'static str) -> CorpusFixture {
    CorpusFixture {
        dir,
        name,
        provenance: Provenance::TrackedInGit(None),
    }
}

pub(crate) const fn host_sourced(
    dir: &'static str,
    name: &'static str,
    hint: &'static str,
) -> CorpusFixture {
    CorpusFixture {
        dir,
        name,
        provenance: Provenance::SourcedOnTheHost(hint),
    }
}

pub(crate) const SWIFT_HELLO_ORIGINAL: CorpusFixture = tracked(
    MACHO_MAC_DIR,
    "SwiftHello.original",
    BytesPin {
        size_bytes: 61_816,
        blake3: "49f667381558ef2fc3688c323ff13e502e46e3c464f1df03788114553fb5015c",
    },
);

pub(crate) const SWIFT_HELLO_OBFUSCATED: CorpusFixture = tracked(
    MACHO_MAC_DIR,
    "SwiftHello.obfuscated",
    BytesPin {
        size_bytes: 61_432,
        blake3: "7aaa12a87180f86d30e5c8f7c48892fd2919a5966df10ce3563f9b60f7d9ce8d",
    },
);

pub(crate) const SWIFT_HELLO_SWIFTSHIELD_MAPPING: CorpusFixture = tracked(
    MACHO_MAC_DIR,
    "SwiftHello.swiftshield-mapping.txt",
    BytesPin {
        size_bytes: 588,
        blake3: "e73dea89b67f7633c6a0eaaa1b429837773c254065a2a9439d655e98c6d0faf3",
    },
);

pub(crate) const SWIFT_EDGE_CASES_ORIGINAL: CorpusFixture = tracked(
    SWIFTSHIELD_EDGE_DIR,
    "SwiftEdgeCases.original",
    BytesPin {
        size_bytes: 77_368,
        blake3: "59e58a2abcdd70292a85361489f29a895a704b7082d502e091d7f90e5545acad",
    },
);

pub(crate) const SWIFT_EDGE_CASES_OBFUSCATED: CorpusFixture = tracked(
    SWIFTSHIELD_EDGE_DIR,
    "SwiftEdgeCases.obfuscated",
    BytesPin {
        size_bytes: 71_512,
        blake3: "51c37abb5b887b73ef5483c5f8ae15fc86a844093dbc8808eec4612411062d27",
    },
);

pub(crate) const SWIFT_EDGE_CASES_SWIFTSHIELD_MAPPING: CorpusFixture = tracked(
    SWIFTSHIELD_EDGE_DIR,
    "SwiftEdgeCases.swiftshield-mapping.txt",
    BytesPin {
        size_bytes: 2_597,
        blake3: "7dcff5f25f49ffb49c7637e5a8f854f33965492f6d9a0f69071d8dcb15d660bc",
    },
);

pub(crate) const EDGE_CASES_FAT: CorpusFixture = tracked(
    MEGAFILE_DIR,
    "EdgeCases.fat",
    BytesPin {
        size_bytes: 546_272,
        blake3: "2e2c3755358b7f82073b09f071ea8ffa37715bf2857796f4c69c99669fb981aa",
    },
);

pub(crate) const ZIG_HELLO_ELF: CorpusFixture = tracked_unpinned(ZIG_DIR, "hello.zig.elf");

pub(crate) const EDGE_CASES_ARM64: CorpusFixture =
    host_sourced(MEGAFILE_DIR, "EdgeCases.arm64", LIPO_THIN_HINT);
pub(crate) const EDGE_CASES_X86_64: CorpusFixture =
    host_sourced(MEGAFILE_DIR, "EdgeCases.x86_64", LIPO_THIN_HINT);

pub(crate) const SWIFT_DRIVER: CorpusFixture =
    host_sourced(MACHO_MAC_DIR, "swift-driver", SWIFT_DRIVER_HINT);

pub(crate) const CONFIDENTIAL_APP: CorpusFixture =
    host_sourced(MACHO_MAC_DIR, "ConfidentialApp.bin", CONFIDENTIAL_HINT);
pub(crate) const CONFIDENTIAL_EDGE_BEFORE: CorpusFixture = host_sourced(
    CONFIDENTIAL_EDGE_DIR,
    "ConfidentialEdgeCases.before.bin",
    CONFIDENTIAL_HINT,
);

pub(crate) const fn macos_system_binary(name: &'static str) -> CorpusFixture {
    host_sourced(MACHO_MAC_DIR, name, MACOS_SYSTEM_HINT)
}

pub(crate) const fn homebrew_binary(name: &'static str) -> CorpusFixture {
    host_sourced(MACHO_MAC_DIR, name, HOMEBREW_HINT)
}

pub(crate) const fn released_ipa(name: &'static str) -> CorpusFixture {
    host_sourced(IPA_DIR, name, IPA_HINT)
}

pub(crate) fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("the crate sits two directories below the workspace root");
    workspace_root.join("corpus")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorpusRequirement {
    Optional,
    Mandatory,
}

pub(crate) fn requirement_from_value(value: Option<&OsStr>) -> CorpusRequirement {
    let Some(raw): Option<&OsStr> = value else {
        return CorpusRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => CorpusRequirement::Optional,
        _ => CorpusRequirement::Mandatory,
    }
}

pub(crate) fn corpus_requirement() -> CorpusRequirement {
    let raw: Option<OsString> = std::env::var_os(REQUIRE_CORPUS_VAR);
    requirement_from_value(raw.as_deref())
}

pub(crate) fn read_tracked(fixture: CorpusFixture) -> Vec<u8> {
    let Provenance::TrackedInGit(pin): Provenance = fixture.provenance else {
        panic!(
            "{} is registered as sourced on the host, so it must be loaded through \
             read_host_sourced; calling read_tracked would claim a guarantee the repository does \
             not make",
            fixture.relative()
        )
    };
    let path: PathBuf = fixture.path();
    let bytes: Vec<u8> = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => panic!(
            "{} is tracked in this repository and a graded figure is measured against it, so a run \
             that cannot read it must fail rather than measure nothing: nothing exists at {} \
             ({error}). Restore the file with `git checkout -- {}`",
            fixture.relative(),
            path.display(),
            fixture.relative()
        ),
        Err(error) => panic!(
            "{} exists at {} but could not be read ({error}); an unreadable fixture is never a \
             skip, because that is how a quarantined or half-written sample silently stops grading",
            fixture.relative(),
            path.display()
        ),
    };
    assert!(
        !bytes.is_empty(),
        "{} is tracked in this repository and read back empty at {}; a truncated input grades \
         nothing and must never report success",
        fixture.relative(),
        path.display()
    );
    if let Some(pin) = pin {
        enforce_pin(&fixture, pin, &bytes);
    }
    bytes
}

pub(crate) fn read_tracked_text(fixture: CorpusFixture) -> String {
    let bytes: Vec<u8> = read_tracked(fixture);
    String::from_utf8(bytes).unwrap_or_else(|error: std::string::FromUtf8Error| {
        panic!(
            "{} is graded as text but is not valid utf-8 ({error}); a fixture that cannot be \
             decoded is never a skip",
            fixture.relative()
        )
    })
}

pub(crate) fn read_host_sourced(fixture: CorpusFixture) -> Option<Vec<u8>> {
    read_host_sourced_with_requirement(fixture, corpus_requirement())
}

pub(crate) fn read_host_sourced_with_requirement(
    fixture: CorpusFixture,
    requirement: CorpusRequirement,
) -> Option<Vec<u8>> {
    let Provenance::SourcedOnTheHost(hint): Provenance = fixture.provenance else {
        panic!(
            "{} is tracked in this repository, so it must be loaded through read_tracked; treating \
             a committed fixture as optional is how a graded figure turns into a skip nobody reads",
            fixture.relative()
        )
    };
    let path: PathBuf = fixture.path();
    match fs::read(&path) {
        Ok(bytes) => {
            assert!(
                !bytes.is_empty(),
                "{} exists at {} but is empty; a truncated input grades nothing and must never \
                 report success",
                fixture.relative(),
                path.display()
            );
            Some(bytes)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            enforce_absent(&fixture, hint, requirement);
            None
        }
        Err(error) => panic!(
            "{} exists at {} but could not be read ({error}); an unreadable fixture is never a \
             skip, because that is how a quarantined or half-written sample silently stops grading",
            fixture.relative(),
            path.display()
        ),
    }
}

fn enforce_pin(fixture: &CorpusFixture, pin: BytesPin, bytes: &[u8]) {
    assert_eq!(
        bytes.len(),
        pin.size_bytes,
        "{} is {} bytes here but every figure measured against it was measured against {} bytes; \
         grading a different file would measure a different binary and the assertions below could \
         not fail on a real regression",
        fixture.relative(),
        bytes.len(),
        pin.size_bytes
    );
    let digest: String = blake3::hash(bytes).to_hex().to_string();
    assert_eq!(
        digest,
        pin.blake3,
        "{} is not the file the figures measured against it were measured against; restore the \
         committed bytes, or re-measure every figure and re-pin this digest in the same change",
        fixture.relative()
    );
}

fn enforce_absent(fixture: &CorpusFixture, hint: &str, requirement: CorpusRequirement) {
    assert!(
        requirement == CorpusRequirement::Optional,
        "{REQUIRE_CORPUS_VAR} makes every corpus fixture mandatory for this run, so {} cannot be \
         graded and this case must not report success: nothing exists at {}. To fix it, {hint}; to \
         permit a run that grades nothing here, clear {REQUIRE_CORPUS_VAR}.",
        fixture.relative(),
        fixture.path().display()
    );
    announce_ungraded(fixture, hint);
}

fn announce_ungraded(fixture: &CorpusFixture, hint: &str) {
    let line: String = format!(
        "\nUNGRADED: {} is absent at {}, so this case measured nothing and graded nothing. It is \
         sourced on the host rather than tracked in this repository. To grade it, {hint}; set \
         {REQUIRE_CORPUS_VAR}=1 to fail instead of skipping when it is absent.\n",
        fixture.relative(),
        fixture.path().display()
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

pub(crate) fn first_slice(fixture: CorpusFixture, bytes: &[u8]) -> (Vec<u8>, ParsedSlice) {
    select_slice(fixture, bytes, None)
}

pub(crate) fn slice_preferring(
    fixture: CorpusFixture,
    bytes: &[u8],
    cpu: CpuKind,
) -> (Vec<u8>, ParsedSlice) {
    select_slice(fixture, bytes, Some(cpu))
}

pub(crate) fn select_slice(
    fixture: CorpusFixture,
    bytes: &[u8],
    preferred: Option<CpuKind>,
) -> (Vec<u8>, ParsedSlice) {
    let Some(kind): Option<MachoKind> = macho::detect_magic(bytes) else {
        panic!(
            "{} carries no Mach-O magic in its first bytes; a fixture that is present but is not \
             the container this case grades is never a skip",
            fixture.relative()
        )
    };
    match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> = macho::walk_fat(bytes).unwrap_or_else(
                |error: disrobe_pass_swift_objc::error::Error| {
                    panic!(
                        "{} is a fat Mach-O whose arch table does not walk: {error}",
                        fixture.relative()
                    )
                },
            );
            let entry: &FatArchEntry = preferred
                .and_then(|cpu: CpuKind| entries.iter().find(|e: &&FatArchEntry| e.cpu == cpu))
                .or_else(|| entries.first())
                .unwrap_or_else(|| {
                    panic!(
                        "{} is a fat Mach-O carrying zero arch entries",
                        fixture.relative()
                    )
                });
            let inner: &[u8] = macho::slice_bytes(bytes, entry).unwrap_or_else(|| {
                panic!(
                    "{} declares a {:?} slice at offset {} size {} that lies outside the {} byte \
                     file",
                    fixture.relative(),
                    entry.cpu,
                    entry.offset,
                    entry.size,
                    bytes.len()
                )
            });
            let parsed: ParsedSlice = parse_or_panic(&fixture, inner);
            (inner.to_vec(), parsed)
        }
        _ => {
            let parsed: ParsedSlice = parse_or_panic(&fixture, bytes);
            (bytes.to_vec(), parsed)
        }
    }
}

fn parse_or_panic(fixture: &CorpusFixture, slice: &[u8]) -> ParsedSlice {
    macho::parse_slice(slice).unwrap_or_else(|error: disrobe_pass_swift_objc::error::Error| {
        panic!(
            "{} yields a Mach-O slice that does not parse: {error}",
            fixture.relative()
        )
    })
}
