#![cfg(feature = "lua")]
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
        "808a0f7d52af2aa7e62d513b570ed4f50ab109e050b1eb39926bf39419c8117f",
    ),
    (
        "fixture:forms.5_3.mnemonics",
        "ac837bc0b4d5660a0240a2607f5723ecb5f49a5be08871570b1c3a43fd38a77a",
    ),
    (
        "fixture:forms.5_4.mnemonics",
        "ada094c6dfdccfc0b7ba4de3ac73196b8e6d0bb54cb1e76c9c2c19ec8b9e0c5b",
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
        "88eb790850458b62a550044b71b71990e4a884c9f78ecddd1a1c6c122dba2509",
    ),
    (
        "fixture:hello.5_3.mnemonics",
        "56996e715a1fe8273daad21dbf9c88e841f0a3076cd1844ba1a3d4f7da07e27f",
    ),
    (
        "fixture:edge_cases.5_3.mnemonics",
        "29aae1919dcd23724ef25d9b87028cfa29b8514cdbfa961c87d154910bacb20f",
    ),
    (
        "fixture:hello.5_4.mnemonics",
        "2089a5b52923b89ede3f6fab31ad21c631181f6f8be84fc77c4333be3f9343d3",
    ),
    (
        "fixture:edge_cases.5_4.mnemonics",
        "7c830d06c4239353e6a0ae589a20d1abe1a3bf56299b8f6b9eb86acfa8279710",
    ),
];

const CORPUS_INVENTORY: [(&str, &str); 4] = [
    (
        "corpus:hello.5_3.luac",
        "0cb2b1910664e1cc44c7fb6678af2776b886254eb88f552b89486c4040220d49",
    ),
    (
        "corpus:edge_cases.5_3.luac",
        "f2f9fa94059809a5a2a2853008c29ffc55d2805bc2aaee093b0731999a50eb0d",
    ),
    (
        "corpus:hello.5_4.luac",
        "b93680519e81ad36574ed13386fcf87d1ccb0e5e5affae99ea53d024983ee3a0",
    ),
    (
        "corpus:edge_cases.5_4.luac",
        "1386279a711b8b934ba9b420e67c4ef180d43fcde594a5612d540130808fdd6d",
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
            "graded branch targets 319\n",
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
            "graded branch targets 318\n",
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
            "modelled opcodes 73\n",
            "declined opcodes 9\n",
            "graded functions 187\n",
            "graded instructions 3829\n",
            "modelled instructions 3092\n",
            "declined instructions 737\n",
            "graded branch targets 319\n",
            "declined CLOSE EXTRAARG MMBIN MMBINI MMBINK MOVE TBC VARARG VARARGPREP\n",
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

#[derive(Debug)]
struct ListedInstruction {
    mnemonic: String,
    target: Option<u64>,
}

fn reference_streams(key: &str) -> Vec<Vec<ListedInstruction>> {
    let text: String = reference_text(key);
    let mut streams: Vec<Vec<ListedInstruction>> = Vec::new();
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
        let stream: &mut Vec<ListedInstruction> = streams
            .last_mut()
            .unwrap_or_else(|| panic!("{key} lists an instruction before any function marker"));
        let listed: ListedInstruction = match trimmed.split_once(' ') {
            Some((mnemonic, target)) => ListedInstruction {
                mnemonic: mnemonic.to_owned(),
                target: Some(
                    target
                        .parse::<u64>()
                        .ok()
                        .filter(|target: &u64| *target > 0)
                        .unwrap_or_else(|| panic!("{key} lists a malformed target in {trimmed}")),
                ),
            },
            None => ListedInstruction {
                mnemonic: trimmed.to_owned(),
                target: None,
            },
        };
        stream.push(listed);
    }
    assert!(
        !streams.is_empty(),
        "{key} must describe at least one function"
    );
    streams
}

fn listed_mnemonics(streams: &[Vec<ListedInstruction>]) -> Vec<Vec<String>> {
    streams
        .iter()
        .map(|stream: &Vec<ListedInstruction>| {
            stream
                .iter()
                .map(|listed: &ListedInstruction| listed.mnemonic.clone())
                .collect()
        })
        .collect()
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
    graded_targets: usize,
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
    let listed: Vec<Vec<ListedInstruction>> = reference_streams(fixture.listing);
    let expected: Vec<Vec<String>> = listed_mnemonics(&listed);
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
    for (function, reference) in module.functions.iter().zip(&listed) {
        let function: &NirFunction = function;
        for (pc, (instruction, listed)) in function.instructions.iter().zip(reference).enumerate() {
            let instruction: &NirInstr = instruction;
            let mnemonic: &String = &listed.mnemonic;
            if let Some(target) = listed.target {
                let expected_address: u64 = function.address.saturating_add(target - 1);
                assert_eq!(
                    instruction.direct_target(),
                    Some(expected_address),
                    "{mnemonic} at pc {} of {} in {} must branch to instruction {target} as the {} reference listing annotates",
                    pc + 1,
                    function.name,
                    fixture.chunk,
                    band.label
                );
                coverage.graded_targets = coverage.graded_targets.saturating_add(1);
            }
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
    writeln!(report, "graded branch targets {}", coverage.graded_targets).expect("write report");
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
    let expected: Vec<Vec<String>> =
        listed_mnemonics(&reference_streams("fixture:hello.5_1.mnemonics"));
    assert_eq!(
        observed, expected,
        "the 32-bit and 64-bit 5.1 chunks of the same source must lift to the same reference stream"
    );
}
