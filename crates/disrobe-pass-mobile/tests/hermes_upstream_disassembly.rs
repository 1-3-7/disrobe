#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args
)]

use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    HERMES_LIFTED_VERSIONS, HermesModule, hermes_disasm_function, parse_hermes_module,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reference {
    version: u32,
    upstream_tag: &'static str,
    instructions: usize,
}

const REFERENCES: [Reference; 8] = [
    Reference {
        version: 62,
        upstream_tag: "v0.2.1",
        instructions: 161,
    },
    Reference {
        version: 71,
        upstream_tag: "v0.3.0",
        instructions: 161,
    },
    Reference {
        version: 74,
        upstream_tag: "v0.4.0",
        instructions: 98,
    },
    Reference {
        version: 76,
        upstream_tag: "v0.7.2",
        instructions: 98,
    },
    Reference {
        version: 83,
        upstream_tag: "v0.8.0",
        instructions: 98,
    },
    Reference {
        version: 84,
        upstream_tag: "v0.11.0",
        instructions: 98,
    },
    Reference {
        version: 89,
        upstream_tag: "v0.12.0",
        instructions: 98,
    },
    Reference {
        version: 96,
        upstream_tag: "v0.13.0",
        instructions: 99,
    },
];

const SWAPS: [(u32, u32); 4] = [(83, 74), (74, 83), (96, 89), (62, 96)];

const PINNED_REFERENCE_INSTRUCTIONS: usize = 911;
const PINNED_REFERENCE_FUNCTIONS: usize = 64;
const EXPECTED_FUNCTION_NAMES: [&str; 8] = [
    "global",
    "add",
    "sumRange",
    "greet",
    "Counter",
    "main",
    "increment",
    "label",
];

fn corpus(parts: &[&str]) -> PathBuf {
    let mut path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join("sample");
    for part in parts {
        path = path.join(part);
    }
    path
}

fn read(path: &Path, what: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{what} is committed to this repository, so a run that cannot read it must fail rather \
             than report a green that compared nothing: {error} at {}",
            path.display()
        )
    })
}

fn upstream_functions(version: u32) -> Vec<(String, Vec<String>)> {
    let path: PathBuf = corpus(&["upstream-disasm", &format!("hbc{version}.txt")]);
    let text: String = read(&path, "the upstream disassembly");
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Function<")
            && let Some(at) = rest.find(">(")
            && rest[at..].contains(" params")
        {
            if let Some(finished) = current.take() {
                out.push(finished);
            }
            current = Some((rest[..at].to_owned(), Vec::new()));
            continue;
        }
        let Some((_, body)): Option<&mut (String, Vec<String>)> = current.as_mut() else {
            continue;
        };
        let Some(indented): Option<&str> = line.strip_prefix("    ") else {
            continue;
        };
        let trimmed: &str = indented.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(mnemonic): Option<&str> = trimmed.split_whitespace().next() else {
            continue;
        };
        if mnemonic.ends_with(':') || mnemonic == "Offset" {
            continue;
        }
        body.push(mnemonic.to_owned());
    }
    if let Some(finished) = current {
        out.push(finished);
    }
    out
}

fn recovered_functions(version: u32) -> Vec<(String, Vec<String>)> {
    let path: PathBuf = corpus(&[&format!("sample.hbc.v{version}")]);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the graded bytecode is committed, so a run that cannot read it must fail: {error} at \
             {}",
            path.display()
        )
    });
    let module: HermesModule = parse_hermes_module(&bytes)
        .unwrap_or_else(|error| panic!("{} must parse: {error}", path.display()));
    assert_eq!(
        module.header.version,
        version,
        "{} must still declare bytecode version {version}",
        path.display()
    );
    (0..module.functions.len())
        .map(|index: usize| {
            let name: String = module
                .functions
                .get(index)
                .and_then(|f| module.string_by_global_id(f.function_name_id))
                .unwrap_or_default()
                .to_owned();
            let mnemonics: Vec<String> = hermes_disasm_function(&module, index)
                .iter()
                .map(|line: &String| {
                    let after: &str = line.split_once(": ").map_or(line.as_str(), |(_, r)| r);
                    after.split_once('(').map_or(after, |(m, _)| m).to_owned()
                })
                .collect();
            (name, mnemonics)
        })
        .collect()
}

#[test]
fn every_version_with_an_opcode_table_carries_the_disassembly_its_own_release_prints() {
    let listed: Vec<u32> = REFERENCES
        .iter()
        .map(|reference: &Reference| reference.version)
        .collect();
    assert_eq!(
        listed,
        HERMES_LIFTED_VERSIONS.to_vec(),
        "this file grades every opcode table against the disassembly the matching Hermes release \
         prints for the same committed bytes, so a lifted version missing here would decode its \
         instructions with nothing outside disrobe checking the names"
    );
}

#[test]
fn each_committed_bundle_decodes_to_the_instruction_sequence_its_own_release_prints() {
    let mut total_instructions: usize = 0;
    let mut total_functions: usize = 0;

    for reference in REFERENCES {
        let version: u32 = reference.version;
        let upstream: Vec<(String, Vec<String>)> = upstream_functions(version);
        let recovered: Vec<(String, Vec<String>)> = recovered_functions(version);

        assert_eq!(
            upstream.len(),
            EXPECTED_FUNCTION_NAMES.len(),
            "hbc v{version}: the reference printed by facebook/hermes {} lists {} functions, and \
             the committed bundle holds {}; a reference that parsed to a different shape grades \
             the wrong thing",
            reference.upstream_tag,
            upstream.len(),
            EXPECTED_FUNCTION_NAMES.len()
        );
        assert_eq!(
            recovered.len(),
            upstream.len(),
            "hbc v{version}: disrobe found {} functions where the release prints {}",
            recovered.len(),
            upstream.len()
        );

        let upstream_names: Vec<&str> = upstream
            .iter()
            .map(|(name, _): &(String, Vec<String>)| name.as_str())
            .collect();
        assert_eq!(
            upstream_names,
            EXPECTED_FUNCTION_NAMES.to_vec(),
            "hbc v{version}: the reference must name the eight functions of sample.js in table \
             order"
        );

        let mut version_instructions: usize = 0;
        for ((want_name, want_ops), (got_name, got_ops)) in upstream.iter().zip(recovered.iter()) {
            assert_eq!(
                got_name, want_name,
                "hbc v{version}: function table order diverges from the release disassembly"
            );
            assert!(
                !want_ops.is_empty(),
                "hbc v{version} {want_name}: the reference lists no instruction for this function, \
                 so comparing against it would compare two empty lists"
            );
            assert_eq!(
                got_ops,
                want_ops,
                "hbc v{version} {want_name}: disrobe decodes a different instruction sequence than \
                 the disassembler shipped in facebook/hermes {} prints for the same bytes. Each \
                 opcode byte is named through the per-version table, so a divergence here is that \
                 table naming the wrong instruction\n--release--\n{}\n--disrobe--\n{}",
                reference.upstream_tag,
                want_ops.join(" "),
                got_ops.join(" ")
            );
            version_instructions += want_ops.len();
            total_functions += 1;
        }

        assert_eq!(
            version_instructions, reference.instructions,
            "hbc v{version}: the instruction denominator is pinned by equality, so a reference \
             trimmed down to fewer instructions fails here rather than agreeing more easily"
        );
        total_instructions += version_instructions;
        eprintln!(
            "hbc v{version} ({}): {version_instructions} instructions over {} functions match the \
             release disassembly name for name",
            reference.upstream_tag,
            upstream.len()
        );
    }

    assert_eq!(total_instructions, PINNED_REFERENCE_INSTRUCTIONS);
    assert_eq!(total_functions, PINNED_REFERENCE_FUNCTIONS);
}

fn mnemonics_under_declared_version(source_version: u32, declared: u32) -> Vec<Vec<String>> {
    let path: PathBuf = corpus(&[&format!("sample.hbc.v{source_version}")]);
    let mut bytes: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("{} is committed: {error}", path.display()));
    bytes.splice(8..12, declared.to_le_bytes());
    let module: HermesModule = parse_hermes_module(&bytes).unwrap_or_else(|error| {
        panic!("v{declared} is inside the accepted band, so this must parse: {error}")
    });
    (0..module.functions.len())
        .map(|index: usize| {
            hermes_disasm_function(&module, index)
                .iter()
                .map(|line: &String| {
                    let after: &str = line.split_once(": ").map_or(line.as_str(), |(_, r)| r);
                    after.split_once('(').map_or(after, |(m, _)| m).to_owned()
                })
                .collect()
        })
        .collect()
}

#[test]
fn reading_one_release_through_another_release_table_names_different_instructions() {
    let v62: Vec<(String, Vec<String>)> = upstream_functions(62);
    let v96: Vec<(String, Vec<String>)> = upstream_functions(96);
    assert_ne!(
        v62, v96,
        "hbc v62 and v96 are compiled by releases that number opcodes differently and optimise \
         differently, so identical references would mean both files hold the same text"
    );

    for (source_version, declared) in SWAPS {
        let truthful: Vec<Vec<String>> =
            mnemonics_under_declared_version(source_version, source_version);
        let misread: Vec<Vec<String>> = mnemonics_under_declared_version(source_version, declared);
        assert_ne!(
            truthful, misread,
            "the hbc v{source_version} bundle read through the v{declared} opcode table decodes to \
             the same instruction names as under its own table. The two tables would then be \
             interchangeable for these bytes and the release comparison above would pass with one \
             shared table, so it would prove nothing about per-version numbering"
        );
    }
}
