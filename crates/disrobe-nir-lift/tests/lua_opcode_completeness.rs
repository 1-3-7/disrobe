#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use disrobe_nir::{NirFunction, NirInstr, NirModule, NirOp};
use disrobe_nir_lift::{lift_lua_chunk, lua_function_address};
use disrobe_pass_lua::read_auto;
use disrobe_pass_lua::reader::common::{LuaChunk, LuaDialect, LuaProto};

const COMMITTED_FIXTURES: [&str; 8] = [
    "hello.5_1.luac",
    "hello.5_2.luac",
    "hello.5_3.luac",
    "hello.5_4.luac",
    "edge_cases.5_1.luac",
    "edge_cases.5_2.luac",
    "edge_cases.5_3.luac",
    "edge_cases.5_4.luac",
];

const BROAD_FIXTURES: [&str; 4] = [
    "edge_cases.5_1.luac",
    "edge_cases.5_2.luac",
    "edge_cases.5_3.luac",
    "edge_cases.5_4.luac",
];

const GRADED_WALL_CLOCK: Duration = Duration::from_secs(90);

const INVENTORY: [(&str, &str); 17] = [
    (
        "fixture:forms.5_1.luac",
        "92c939efbc1686476f31bbc4abb54edb4e8456378ca2d5be2545d14a63c03afe",
    ),
    (
        "fixture:forms.5_3.luac",
        "4da4d035dcfba0b3a177e56a0d8bfae124eeefd3029614510efd46cc0cd3bd94",
    ),
    (
        "fixture:forms.5_4.luac",
        "c424ffc71eee1d748f9eb0b8c990a4ec6637a241e5ed82a0f62db5d508cbbd03",
    ),
    (
        "fixture:forms.5_1.mnemonics",
        "bcaaeebe46a42f2e9aee103c82769cefaec2c9b9a766c023bc0453c3c667323b",
    ),
    (
        "fixture:forms.5_3.mnemonics",
        "2544a50b4c6dcbf902fc135ad3152455e1f0ff1fd0b59683ae805d73b4de6382",
    ),
    (
        "fixture:forms.5_4.mnemonics",
        "7caa46a5b616fb162492073b56c129a133a27a8f4a73654497c3929c4c346c6e",
    ),
    (
        "fixture:opcode_space.5_1.txt",
        "718c3c2f0819ca5c7a9a027471facea151219a79ef4b0f900ad3cbc2a475e0ef",
    ),
    (
        "fixture:opcode_space.5_3.txt",
        "e07a1d3039fb7318d9eb2893ff58270b142f91c8e63cb413202cb0ed9a23c854",
    ),
    (
        "fixture:opcode_space.5_4.txt",
        "baa487658c7dfb2a8b5e45a6e33b37c4350cc68f8d35d2d2823f11a11a521e05",
    ),
    (
        "fixture:hello.5_1.luac",
        "956cc0e060c8ed89399bdf46ca1529b31bd94e618bcb56a94f78a14c7db34713",
    ),
    (
        "fixture:edge_cases.5_1.luac",
        "d16238a80ab3a7e2f084c70623e01738a2395abe06a326ed9057cff3d2f52af7",
    ),
    (
        "fixture:hello.5_1.mnemonics",
        "fd20c16c2341bea4150dd2e05b6d601a1c1fc4ced12a3917c7f9e1283aa13b83",
    ),
    (
        "fixture:edge_cases.5_1.mnemonics",
        "6f86eec7568b08ffd82399f0732aecd8c8fe3503742be17010e1ddf470f8bbff",
    ),
    (
        "fixture:hello.5_3.mnemonics",
        "56996e715a1fe8273daad21dbf9c88e841f0a3076cd1844ba1a3d4f7da07e27f",
    ),
    (
        "fixture:edge_cases.5_3.mnemonics",
        "cf8e771215063096ef70e4117e1d3ec4b83c0cded0c094dab295174a60e37240",
    ),
    (
        "fixture:hello.5_4.mnemonics",
        "2089a5b52923b89ede3f6fab31ad21c631181f6f8be84fc77c4333be3f9343d3",
    ),
    (
        "fixture:edge_cases.5_4.mnemonics",
        "54c83d0906358c45e9849accfb704c2d8018e63da6fc50516c5f8d4ac6b9e6dd",
    ),
];

const CORPUS_INVENTORY: [(&str, &str); 4] = [
    (
        "corpus:hello.5_3.luac",
        "3263e3df916c8b5ebdad89b2bca295cde0a0bdbbba756928f0431dd940754ef1",
    ),
    (
        "corpus:edge_cases.5_3.luac",
        "d8b660055902d19a9713936630091ce1624c5e7a09f736e4d6d72f14238d1528",
    ),
    (
        "corpus:hello.5_4.luac",
        "287f4251f579dfe52facca496397bc60b4a042e30e56e5fa6340c488ca6e2269",
    ),
    (
        "corpus:edge_cases.5_4.luac",
        "0999812ffe2e88f9c66fdf62e41f4456986482ba3f5dafceb92e5afa64069933",
    ),
];

struct GradedFixture {
    chunk: &'static str,
    listing: &'static str,
}

struct Band {
    label: &'static str,
    dialect: LuaDialect,
    space: &'static str,
    fixtures: [GradedFixture; 3],
    report: &'static str,
    present_vocabulary: &'static [&'static str],
    absent_vocabulary: &'static [&'static str],
}

const BANDS: [Band; 3] = [
    Band {
        label: "Lua 5.1.5",
        dialect: LuaDialect::Lua51,
        space: "fixture:opcode_space.5_1.txt",
        fixtures: [
            GradedFixture {
                chunk: "fixture:hello.5_1.luac",
                listing: "fixture:hello.5_1.mnemonics",
            },
            GradedFixture {
                chunk: "fixture:edge_cases.5_1.luac",
                listing: "fixture:edge_cases.5_1.mnemonics",
            },
            GradedFixture {
                chunk: "fixture:forms.5_1.luac",
                listing: "fixture:forms.5_1.mnemonics",
            },
        ],
        report: concat!(
            "band Lua 5.1.5\n",
            "reference opcode space 38\n",
            "corpus reach 38\n",
            "modelled opcodes 35\n",
            "declined opcodes 3\n",
            "graded functions 182\n",
            "graded instructions 3493\n",
            "modelled instructions 3044\n",
            "declined instructions 449\n",
            "declined CLOSE MOVE VARARG\n",
            "corpus absent \n",
        ),
        present_vocabulary: &[
            "GETGLOBAL",
            "SETGLOBAL",
            "LOADBOOL",
            "TFORLOOP",
            "SELF",
            "NOT",
            "CLOSE",
        ],
        absent_vocabulary: &["GETTABUP", "VARARGPREP", "MMBIN", "LOADI"],
    },
    Band {
        label: "Lua 5.3.6",
        dialect: LuaDialect::Lua53,
        space: "fixture:opcode_space.5_3.txt",
        fixtures: [
            GradedFixture {
                chunk: "corpus:hello.5_3.luac",
                listing: "fixture:hello.5_3.mnemonics",
            },
            GradedFixture {
                chunk: "corpus:edge_cases.5_3.luac",
                listing: "fixture:edge_cases.5_3.mnemonics",
            },
            GradedFixture {
                chunk: "fixture:forms.5_3.luac",
                listing: "fixture:forms.5_3.mnemonics",
            },
        ],
        report: concat!(
            "band Lua 5.3.6\n",
            "reference opcode space 47\n",
            "corpus reach 45\n",
            "modelled opcodes 43\n",
            "declined opcodes 2\n",
            "graded functions 184\n",
            "graded instructions 3415\n",
            "modelled instructions 3030\n",
            "declined instructions 385\n",
            "declined MOVE VARARG\n",
            "corpus absent EXTRAARG LOADKX\n",
        ),
        present_vocabulary: &[
            "GETTABUP", "SETTABUP", "TFORCALL", "SELF", "BAND", "IDIV", "SHL",
        ],
        absent_vocabulary: &["GETGLOBAL", "SETGLOBAL", "VARARGPREP", "MMBIN"],
    },
    Band {
        label: "Lua 5.4.8",
        dialect: LuaDialect::Lua54,
        space: "fixture:opcode_space.5_4.txt",
        fixtures: [
            GradedFixture {
                chunk: "corpus:hello.5_4.luac",
                listing: "fixture:hello.5_4.mnemonics",
            },
            GradedFixture {
                chunk: "corpus:edge_cases.5_4.luac",
                listing: "fixture:edge_cases.5_4.mnemonics",
            },
            GradedFixture {
                chunk: "fixture:forms.5_4.luac",
                listing: "fixture:forms.5_4.mnemonics",
            },
        ],
        report: concat!(
            "band Lua 5.4.8\n",
            "reference opcode space 83\n",
            "corpus reach 82\n",
            "modelled opcodes 72\n",
            "declined opcodes 10\n",
            "graded functions 187\n",
            "graded instructions 3829\n",
            "modelled instructions 3076\n",
            "declined instructions 753\n",
            "declined CLOSE EXTRAARG MMBIN MMBINI MMBINK MOVE TBC TFORPREP VARARG VARARGPREP\n",
            "corpus absent LOADKX\n",
        ),
        present_vocabulary: &[
            "VARARGPREP",
            "MMBIN",
            "LOADI",
            "GETFIELD",
            "TBC",
            "BANDK",
            "SHLI",
            "SETTABUP",
        ],
        absent_vocabulary: &["GETGLOBAL", "SETGLOBAL", "LOADBOOL"],
    },
];

fn fixture_path(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("lua");
    path.push("luac");
    path.push(name);
    path
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name))
        .unwrap_or_else(|e| panic!("committed luac fixture {name} present: {e}"))
}

fn reference_path(key: &str) -> PathBuf {
    let (space, name): (&str, &str) = key
        .split_once(':')
        .unwrap_or_else(|| panic!("reference key {key} must name its tree"));
    match space {
        "fixture" => {
            let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push("tests");
            path.push("fixtures");
            path.push("lua");
            path.push(name);
            path
        }
        "corpus" => fixture_path(name),
        other => panic!("reference key {key} names an unknown tree {other}"),
    }
}

fn pinned_hash(key: &str) -> &'static str {
    INVENTORY
        .iter()
        .chain(CORPUS_INVENTORY.iter())
        .find(|(name, _): &&(&str, &str)| *name == key)
        .map_or_else(
            || panic!("{key} must be listed in the pinned reference inventory"),
            |(_, hash): &(&str, &str)| *hash,
        )
}

fn reference_bytes(key: &str) -> Vec<u8> {
    let path: PathBuf = reference_path(key);
    let raw: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the committed independent reference {key} is required and missing at {}: {error}",
            path.display()
        )
    });
    let observed: String = blake3::hash(&raw).to_hex().to_string();
    assert_eq!(
        observed,
        pinned_hash(key),
        "{key} changed; the graded reference is hash-pinned so a rescored run cannot pass silently"
    );
    raw
}

fn reference_text(key: &str) -> String {
    let raw: Vec<u8> = reference_bytes(key);
    String::from_utf8(raw).unwrap_or_else(|error| panic!("{key} must be UTF-8: {error}"))
}

fn opcode_byte(raw: u32, dialect: LuaDialect) -> u8 {
    let mask: u32 = if dialect == LuaDialect::Lua54 {
        0x7F
    } else {
        0x3F
    };
    (raw & mask) as u8
}

fn proto_by_address(chunk: &LuaChunk) -> BTreeMap<u64, &LuaProto> {
    fn walk<'a>(proto: &'a LuaProto, next: &mut u32, out: &mut BTreeMap<u64, &'a LuaProto>) {
        let index: u32 = *next;
        *next = next.saturating_add(1);
        out.insert(lua_function_address(index), proto);
        for sub in &proto.protos {
            walk(sub, next, out);
        }
    }
    let mut out: BTreeMap<u64, &LuaProto> = BTreeMap::new();
    let mut next: u32 = 0;
    walk(&chunk.main, &mut next, &mut out);
    out
}

#[derive(Debug, Default)]
struct NirStats {
    total: usize,
    unmodeled: usize,
    nop: usize,
    opcodes: BTreeSet<u8>,
    mnemonics: BTreeSet<String>,
}

fn analyze(name: &str) -> NirStats {
    let bytes: Vec<u8> = fixture_bytes(name);
    let module: NirModule = lift_lua_chunk(&bytes).expect("lift lua chunk to NIR");
    let chunk: LuaChunk = read_auto(&bytes).expect("decode lua chunk");
    let dialect: LuaDialect = chunk.dialect;
    let protos: BTreeMap<u64, &LuaProto> = proto_by_address(&chunk);

    let mut stats: NirStats = NirStats::default();
    for function in &module.functions {
        let function: &NirFunction = function;
        let proto: &LuaProto = protos
            .get(&function.address)
            .copied()
            .expect("a decoded proto for every lifted function base");
        assert_eq!(
            function.instructions.len(),
            proto.code.len(),
            "one lifted instruction per bytecode word for {}",
            function.name
        );
        for (pc, instr) in function.instructions.iter().enumerate() {
            let instr: &NirInstr = instr;
            let raw: u32 = proto.code.get(pc).copied().unwrap_or_default();
            let opcode: u8 = opcode_byte(raw, dialect);
            let offset: u32 = u32::try_from(pc).unwrap_or(u32::MAX);
            assert_eq!(
                instr.address,
                function.address.saturating_add(u64::from(offset)),
                "lifted address must track the bytecode index for {}",
                function.name
            );
            stats.total += 1;
            stats.opcodes.insert(opcode);
            stats.mnemonics.insert(instr.mnemonic.clone());
            match &instr.op {
                NirOp::Nop => stats.nop += 1,
                NirOp::Unmodeled {
                    opcode: carried,
                    offset: carried_offset,
                } => {
                    assert_eq!(
                        *carried, opcode,
                        "Unmodeled must carry the real opcode for {} at pc {pc}",
                        function.name
                    );
                    assert_eq!(
                        *carried_offset, offset,
                        "Unmodeled must carry the real offset for {} at pc {pc}",
                        function.name
                    );
                    stats.unmodeled += 1;
                }
                _ => {}
            }
        }
    }
    stats
}

#[test]
fn committed_luac_fixtures_surface_unmodeled_without_silent_nop() {
    for name in COMMITTED_FIXTURES {
        let stats: NirStats = analyze(name);
        assert!(stats.total > 0, "{name} must lift to instructions");
        assert_eq!(
            stats.nop, 0,
            "no real lua opcode may silently lift to Nop in {name}: {stats:?}"
        );
    }
    for name in BROAD_FIXTURES {
        let stats: NirStats = analyze(name);
        assert!(
            stats.unmodeled >= 1,
            "{name} exercises opcodes disrobe surfaces as Unmodeled: {stats:?}"
        );
        assert!(
            stats.opcodes.len() >= 15,
            "{name} opcode range must be non-vacuous: {} distinct",
            stats.opcodes.len()
        );
    }
}

#[test]
fn move_opcode_surfaces_as_unmodeled_not_nop() {
    let bytes: Vec<u8> = fixture_bytes("edge_cases.5_1.luac");
    let module: NirModule = lift_lua_chunk(&bytes).expect("lift lua chunk to NIR");
    let mut saw_move: bool = false;
    for function in &module.functions {
        for instr in &function.instructions {
            let instr: &NirInstr = instr;
            if instr.mnemonic == "MOVE" {
                saw_move = true;
                assert!(
                    instr.op.is_unmodeled(),
                    "a real MOVE must never collapse to a silent Nop"
                );
                assert_eq!(
                    instr.op.unmodeled_opcode(),
                    Some(0),
                    "MOVE (opcode 0) must surface as Unmodeled carrying its real opcode"
                );
            }
        }
    }
    assert!(saw_move, "edge_cases exercises MOVE");
}

fn reference_streams(key: &str) -> Vec<Vec<String>> {
    let text: String = reference_text(key);
    let mut streams: Vec<Vec<String>> = Vec::new();
    for line in text.lines() {
        let trimmed: &str = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(index) = trimmed.strip_prefix("function ") {
            let parsed: usize = index
                .parse::<usize>()
                .unwrap_or_else(|error| panic!("{key} function marker {index}: {error}"));
            assert_eq!(
                parsed,
                streams.len(),
                "{key} function markers must be dense and in decode order"
            );
            streams.push(Vec::new());
            continue;
        }
        let stream: &mut Vec<String> = streams
            .last_mut()
            .unwrap_or_else(|| panic!("{key} lists an instruction before any function marker"));
        stream.push(trimmed.to_owned());
    }
    assert!(
        !streams.is_empty(),
        "{key} must describe at least one function"
    );
    streams
}

fn lifted_streams(module: &NirModule) -> Vec<Vec<String>> {
    module
        .functions
        .iter()
        .map(|function: &NirFunction| {
            function
                .instructions
                .iter()
                .map(|instr: &NirInstr| instr.mnemonic.clone())
                .collect::<Vec<String>>()
        })
        .collect()
}

#[derive(Debug, Default)]
struct Coverage {
    instructions: usize,
    functions: usize,
    modelled_instructions: usize,
    declined_instructions: usize,
    modelled: BTreeSet<String>,
    declined: BTreeSet<String>,
    reach: BTreeSet<String>,
}

fn grade_fixture(band: &Band, fixture: &GradedFixture, coverage: &mut Coverage) {
    let bytes: Vec<u8> = reference_bytes(fixture.chunk);
    let chunk: LuaChunk = read_auto(&bytes)
        .unwrap_or_else(|error| panic!("decode {} as a lua chunk: {error}", fixture.chunk));
    assert_eq!(
        chunk.dialect, band.dialect,
        "{} must decode as the {} band, not another dialect that also yields instructions",
        fixture.chunk, band.label
    );

    let module: NirModule = lift_lua_chunk(&bytes)
        .unwrap_or_else(|error| panic!("lift {} to NIR: {error}", fixture.chunk));
    let expected: Vec<Vec<String>> = reference_streams(fixture.listing);
    let observed: Vec<Vec<String>> = lifted_streams(&module);
    assert_eq!(
        observed.len(),
        expected.len(),
        "{} must lift one function per function the reference decoder prints",
        fixture.chunk
    );
    assert_eq!(
        observed, expected,
        "the lifted mnemonic stream for {} must equal the {} reference listing {}",
        fixture.chunk, band.label, fixture.listing
    );

    coverage.functions = coverage.functions.saturating_add(expected.len());
    for (function, reference) in module.functions.iter().zip(&expected) {
        let function: &NirFunction = function;
        for (instruction, mnemonic) in function.instructions.iter().zip(reference) {
            let instruction: &NirInstr = instruction;
            coverage.instructions = coverage.instructions.saturating_add(1);
            coverage.reach.insert(mnemonic.clone());
            match &instruction.op {
                NirOp::Nop => panic!(
                    "no lua opcode may lift to Nop; {mnemonic} did in {}",
                    fixture.chunk
                ),
                NirOp::Unmodeled { .. } => {
                    coverage.declined_instructions =
                        coverage.declined_instructions.saturating_add(1);
                    coverage.declined.insert(mnemonic.clone());
                }
                _ => {
                    coverage.modelled_instructions =
                        coverage.modelled_instructions.saturating_add(1);
                    coverage.modelled.insert(mnemonic.clone());
                }
            }
        }
    }
}

fn band_report(band: &Band, coverage: &Coverage, space: &[String]) -> String {
    let space_set: BTreeSet<String> = space.iter().cloned().collect();
    let corpus_absent: Vec<String> = space_set.difference(&coverage.reach).cloned().collect();
    let mut report: String = String::new();
    writeln!(report, "band {}", band.label).expect("write report");
    writeln!(report, "reference opcode space {}", space_set.len()).expect("write report");
    writeln!(report, "corpus reach {}", coverage.reach.len()).expect("write report");
    writeln!(report, "modelled opcodes {}", coverage.modelled.len()).expect("write report");
    writeln!(report, "declined opcodes {}", coverage.declined.len()).expect("write report");
    writeln!(report, "graded functions {}", coverage.functions).expect("write report");
    writeln!(report, "graded instructions {}", coverage.instructions).expect("write report");
    writeln!(
        report,
        "modelled instructions {}",
        coverage.modelled_instructions
    )
    .expect("write report");
    writeln!(
        report,
        "declined instructions {}",
        coverage.declined_instructions
    )
    .expect("write report");
    writeln!(
        report,
        "declined {}",
        coverage
            .declined
            .iter()
            .cloned()
            .collect::<Vec<String>>()
            .join(" ")
    )
    .expect("write report");
    writeln!(report, "corpus absent {}", corpus_absent.join(" ")).expect("write report");
    report
}

fn opcode_space(key: &str) -> Vec<String> {
    let text: String = reference_text(key);
    let names: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty())
        .map(str::to_owned)
        .collect();
    assert!(!names.is_empty(), "{key} must name the opcode space");
    names
}

#[test]
fn lua_lift_matches_the_committed_luac_reference_per_version() {
    for band in &BANDS {
        let started: Instant = Instant::now();
        let space: Vec<String> = opcode_space(band.space);
        let mut coverage: Coverage = Coverage::default();
        for fixture in &band.fixtures {
            grade_fixture(band, fixture, &mut coverage);
        }

        let space_set: BTreeSet<String> = space.iter().cloned().collect();
        assert_eq!(
            space_set.len(),
            space.len(),
            "{} opcode space must not repeat a name",
            band.label
        );
        let reference_absent: Vec<&String> = coverage.reach.difference(&space_set).collect();
        assert!(
            reference_absent.is_empty(),
            "{} lifted mnemonics the reference opcode space does not define: {reference_absent:?}",
            band.label
        );
        let both: Vec<&String> = coverage
            .modelled
            .intersection(&coverage.declined)
            .collect::<Vec<&String>>();
        assert!(
            both.is_empty(),
            "{} classifies these opcodes as both modelled and declined: {both:?}",
            band.label
        );
        let partition: BTreeSet<String> = coverage
            .modelled
            .union(&coverage.declined)
            .cloned()
            .collect();
        assert_eq!(
            partition, coverage.reach,
            "{} must report every reached opcode as modelled or declined",
            band.label
        );
        for mnemonic in band.present_vocabulary {
            assert!(
                space_set.contains(*mnemonic),
                "{} opcode space must define {mnemonic}",
                band.label
            );
            assert!(
                coverage.reach.contains(*mnemonic),
                "{} graded corpus must reach {mnemonic}",
                band.label
            );
        }
        for mnemonic in band.absent_vocabulary {
            assert!(
                !space_set.contains(*mnemonic),
                "{} opcode space must not define {mnemonic}; the wrong version reference is in play",
                band.label
            );
            assert!(
                !coverage.reach.contains(*mnemonic),
                "{} graded corpus must not reach {mnemonic}; the wrong decoder is in play",
                band.label
            );
        }

        let report: String = band_report(band, &coverage, &space);
        println!("{report}");
        assert_eq!(
            report, band.report,
            "the {} coverage report is pinned; a moved number or a grown decline list must be reviewed",
            band.label
        );

        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < GRADED_WALL_CLOCK,
            "grading the {} band took {elapsed:?}, over the {GRADED_WALL_CLOCK:?} cap",
            band.label
        );
    }
}

#[test]
fn the_committed_reference_inventory_is_hash_pinned() {
    let mut observed: Vec<(String, String)> = Vec::new();
    for (key, _) in INVENTORY.iter().chain(CORPUS_INVENTORY.iter()) {
        let path: PathBuf = reference_path(key);
        let raw: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "the committed independent reference {key} is required and missing at {}: {error}",
                path.display()
            )
        });
        observed.push(((*key).to_owned(), blake3::hash(&raw).to_hex().to_string()));
    }
    let pinned: Vec<(String, String)> = INVENTORY
        .iter()
        .chain(CORPUS_INVENTORY.iter())
        .map(|(key, hash): &(&str, &str)| ((*key).to_owned(), (*hash).to_owned()))
        .collect();
    assert_eq!(
        observed, pinned,
        "every graded chunk and reference listing is hash-pinned; regenerate the pins deliberately"
    );
}

#[test]
fn a_truncated_lua_chunk_is_refused_instead_of_partly_lifted() {
    let bytes: Vec<u8> = reference_bytes("corpus:edge_cases.5_4.luac");
    for keep in [bytes.len() / 2, bytes.len() - 1, 12] {
        let truncated: &[u8] = bytes.get(..keep).expect("prefix of the graded chunk");
        assert!(
            lift_lua_chunk(truncated).is_err(),
            "a chunk truncated to {keep} bytes must be refused, never partly lifted"
        );
    }
}

#[test]
fn the_thirty_two_bit_five_one_chunk_agrees_with_the_reference_stream() {
    let committed: Vec<u8> = fixture_bytes("hello.5_1.luac");
    let chunk: LuaChunk = read_auto(&committed).expect("decode the committed 32-bit 5.1 chunk");
    assert_eq!(
        chunk.size_of_size_t, 4,
        "the committed corpus 5.1 chunk is the 32-bit build the local reference decoder rejects"
    );
    let module: NirModule = lift_lua_chunk(&committed).expect("lift the committed 32-bit chunk");
    let observed: Vec<Vec<String>> = lifted_streams(&module);
    let expected: Vec<Vec<String>> = reference_streams("fixture:hello.5_1.mnemonics");
    assert_eq!(
        observed, expected,
        "the 32-bit and 64-bit 5.1 chunks of the same source must lift to the same reference stream"
    );
}
