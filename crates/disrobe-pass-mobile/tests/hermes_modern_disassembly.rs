#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    BufferKind, HERMES_DISASSEMBLED_VERSIONS, HermesExceptionEntry, HermesModule, LiteralFormat,
    LiteralValue, decode_hermes_literals_in, hermes_builtin_name, hermes_disasm_function,
    parse_hermes_module,
};
use sha2::{Digest, Sha256};

struct Fixture {
    name: &'static str,
    version: u32,
    sha256: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "sample",
        version: 98,
        sha256: "9c58ee4d169eeb1dd84fc433ca7c00688daf8058e9d65e4ac51e22566e1925d0",
    },
    Fixture {
        name: "sample",
        version: 99,
        sha256: "e216c1e64d27c40f43bf5f23c11191ce96813f7b083a3859b072d5ec92ef809b",
    },
    Fixture {
        name: "mixed",
        version: 98,
        sha256: "7d5924f63d3f6d99fcd2e1c501ce9cb04e7f0196346838967593602512d924e7",
    },
    Fixture {
        name: "mixed",
        version: 99,
        sha256: "321943514646d3de5d9954b9fc643085cc5be7cda50cd650cdf135018d1fa926",
    },
    Fixture {
        name: "control",
        version: 98,
        sha256: "bad1855e5e067a4019fb7ee9ef0f3b30ccc214949c8d3b50408f3e3082e79ec2",
    },
    Fixture {
        name: "control",
        version: 99,
        sha256: "74ee3587b394d455ce7fbcb38c4a741958f17f0f8e37f9b1afc74e319f7fbce0",
    },
    Fixture {
        name: "closures",
        version: 98,
        sha256: "3b2d289ea655381a14042321183261ab2a10c4c779ab4fffbaf293b63af126cb",
    },
    Fixture {
        name: "closures",
        version: 99,
        sha256: "b0851b31ed72abb848a49aeb883ca50270646515c83578fb2b6aefb6fdde0ea6",
    },
    Fixture {
        name: "objects",
        version: 98,
        sha256: "1d3c14e518c7349eee0a207d0513b7980b6fd893e537a5cc3cfc58c3ffe71128",
    },
    Fixture {
        name: "objects",
        version: 99,
        sha256: "eee8f92041c5bf6601ead293517e4bd83139307bf3d76cb752b45eecb16e5b35",
    },
    Fixture {
        name: "exceptions",
        version: 98,
        sha256: "02a8079abe9be120167520af4a6e8be9b923ef0cf97eefeaa350c233c50e3077",
    },
    Fixture {
        name: "exceptions",
        version: 99,
        sha256: "7006e77cd732215c85778c2b8dac5e6c81e83931476f16eac92f38b511c72da1",
    },
    Fixture {
        name: "generators",
        version: 98,
        sha256: "f71bb819def8ed426c3289eae8e399bf676d39b7eb6780ad15d1d9ec4320d320",
    },
    Fixture {
        name: "generators",
        version: 99,
        sha256: "30e124e607af27aec447fa3932985fbd88ac329577d38076360275c3a0cdb436",
    },
    Fixture {
        name: "async",
        version: 98,
        sha256: "6bc07a14d882092a365d7c0a7be32e76e870f40ca6265e644a7822de4116395d",
    },
    Fixture {
        name: "async",
        version: 99,
        sha256: "778d7c4f8c44e9c3b183ad1b91f9ede0c3d49b41ae73d22c20a7ad7a7663f5ff",
    },
    Fixture {
        name: "values",
        version: 98,
        sha256: "29565fe51ede2fb655635f79b5747e8c5f65172f012ad3e146edf63e038bc80d",
    },
    Fixture {
        name: "values",
        version: 99,
        sha256: "5646d0a229ac8295774b7f174d06823031f7b0e451b1ac8d344b0a2125954f55",
    },
    Fixture {
        name: "metro",
        version: 98,
        sha256: "524926896cc84c3fa0c913d7f34c63590b8de12380038d47c46ed76dd8e03802",
    },
    Fixture {
        name: "metro",
        version: 99,
        sha256: "7ee590e74cf0561ea8e36a7291ab2675b99bcb308a8e69c26c2cc43a8ecee23b",
    },
    Fixture {
        name: "construct",
        version: 98,
        sha256: "381deca2253f1093c532b112b6750cfbaa8f065e57c2792159d8dcd9ffbc229d",
    },
    Fixture {
        name: "construct",
        version: 99,
        sha256: "8f8b4d51855347781773f4f1d1858bba727756efa49e0b5d4782a72cf4535ced",
    },
    Fixture {
        name: "cleanup",
        version: 98,
        sha256: "55b728916d8dde7f84762bb3f5f48d8b505eb719c1c8be870bccf04c242ee611",
    },
    Fixture {
        name: "cleanup",
        version: 99,
        sha256: "bf0fb064dcb1004c6be7f11144f89080dda98af3f1e9e08f57de2484d784e71f",
    },
    Fixture {
        name: "delegation",
        version: 98,
        sha256: "f8fe8315cce5563fb7037a2150dab8163fb431400c7780c04dd285385824fe7c",
    },
    Fixture {
        name: "delegation",
        version: 99,
        sha256: "7e8e557930879c1f031fb52b5c35493e2b02eb6ae2f68e753843b6da3b6b7003",
    },
    Fixture {
        name: "names",
        version: 98,
        sha256: "5561c860b938d7c2aa9ef819435b65879a0d279067eed0dbf4e0c8e727116008",
    },
    Fixture {
        name: "names",
        version: 99,
        sha256: "4fe48b6fe5e488972fbf573386126876d4ebac803ca5832a6007bd6809aa587a",
    },
    Fixture {
        name: "rnassets",
        version: 98,
        sha256: "a692d9d8fdb7bbd99ef53c3fbafb43e59016ddf8dc4ec1cf73a82a66d8f35b2d",
    },
    Fixture {
        name: "rnassets",
        version: 99,
        sha256: "ca6d997a56ef477b2f968184ccd5c8e4dd4790235f5c564bbfe1b72b38cf8f5b",
    },
    Fixture {
        name: "branches",
        version: 85,
        sha256: "d13f2da5e96c24fdba09564f5b8deb1e6dbbaf352d28248a135d053031a9a4be",
    },
    Fixture {
        name: "branches",
        version: 90,
        sha256: "6d5b8667fce84ce8e7d4db4382358242e6cfafb675ce8f8f1fa6c18e05f08dea",
    },
    Fixture {
        name: "branches",
        version: 94,
        sha256: "a35f3bff11172b3f395c874a489134bdf8c65b8459354318811633a0c46fd2d9",
    },
    Fixture {
        name: "branches",
        version: 98,
        sha256: "59404a268a636a083d0d0f6d3828bdb56189365b33cd03eaa1e4611b7277ca2e",
    },
    Fixture {
        name: "branches",
        version: 99,
        sha256: "98f436d8892bde50dd43f8d4a1b47bc8f6b411ad85ba83718a1eeee78bc03c89",
    },
    Fixture {
        name: "features",
        version: 98,
        sha256: "f1da727ca78fde9063d142d23fa71366e21a2c49e35f1aaa4607c82d17d6e3a3",
    },
    Fixture {
        name: "features",
        version: 99,
        sha256: "513eb51b6bc254742b0a5d094d9dc7be3ae6da73149cd62d28df892f027da16e",
    },
    Fixture {
        name: "mixed",
        version: 85,
        sha256: "45bb24622b288cf2b70acf59be645cb81e03d826dfa6da77b89a5e9c8ae72300",
    },
    Fixture {
        name: "mixed",
        version: 90,
        sha256: "f35de7d7c24f99cf8837f0bf91ccd05858440fb56a652c03ad9f174a2c155cc4",
    },
    Fixture {
        name: "mixed",
        version: 94,
        sha256: "7e93776830c75c53356b28ab4ef25a93466ed15f3e950b4e5ef7bb03455d8128",
    },
    Fixture {
        name: "control",
        version: 85,
        sha256: "a6f2eece5f893775a47e00429af5ce5138834cf2ea26197861370ce265d5627a",
    },
    Fixture {
        name: "control",
        version: 90,
        sha256: "dd9a8e31605bbc2a7d6c2bcc442caaa668467a09e506a24e59d05d568c4b6b91",
    },
    Fixture {
        name: "control",
        version: 94,
        sha256: "79f2741b6406f34b17d87f3e90c6d8a31fd0b58abc1dfe3c5037d85ab2ea00a5",
    },
    Fixture {
        name: "closures",
        version: 85,
        sha256: "0ddd56e490c8c96cbf3a270f2e56dde0f46e535ed1d1e6f12119693ccb7dc2b2",
    },
    Fixture {
        name: "closures",
        version: 90,
        sha256: "760ca12aa38088b26cfd09d1187da8023875507360ecedbf234e94fbfbe8960b",
    },
    Fixture {
        name: "closures",
        version: 94,
        sha256: "9ee82b316c22fd5ec1342d6315417ec0d850788647f9aa3081d5d3963405c059",
    },
    Fixture {
        name: "objects",
        version: 90,
        sha256: "ebe79568a331cbc9e846c64d9cf4114c22a1a404b135264a121dbf8cdb1155fc",
    },
    Fixture {
        name: "objects",
        version: 94,
        sha256: "ab878b525c8c71c0d4ac79720d2a5f402285cbcb185a07638ec89c27b7fdb9a8",
    },
    Fixture {
        name: "exceptions",
        version: 85,
        sha256: "58e22f842651ce53069f5873a10f8855b6d17ee09c20ade4da8331cd04d837dd",
    },
    Fixture {
        name: "exceptions",
        version: 90,
        sha256: "d0ecb6a05515be7328c1732d3104965d34d870df2bf7eac9f96d2ef1acedb199",
    },
    Fixture {
        name: "exceptions",
        version: 94,
        sha256: "3a5f3ff480731d8e76f0515ac02ae1b4558dbe4e3d38c1960937598d20eb06a4",
    },
    Fixture {
        name: "generators",
        version: 85,
        sha256: "7cbe1842c0cdb2e3cfb733db2c1932be846a63b274ae78676e87c56e3e3fbced",
    },
    Fixture {
        name: "generators",
        version: 90,
        sha256: "7a77705ceb2442f32792e25eb1ba5ae8bf047d90180feee303924c8b78a2ac2a",
    },
    Fixture {
        name: "generators",
        version: 94,
        sha256: "440d641688af8e174fcb4b417b792e40edfd4bba51c357d6fed20ae6ce435965",
    },
    Fixture {
        name: "async",
        version: 85,
        sha256: "e624ede2a1a3b9fad8c9d6f6c4e5e80ebf20d5e348fdd93d0ef4b54de0f6e6b4",
    },
    Fixture {
        name: "async",
        version: 90,
        sha256: "51ecd844210e4b0ec2681059fc07cd4ff5c1f3f8932c4c33da77eb6f05a63df7",
    },
    Fixture {
        name: "async",
        version: 94,
        sha256: "50fc5028c66f997da63bc19266cd4906c66e1c02e87c2c50bee5b537de7223f4",
    },
    Fixture {
        name: "values",
        version: 90,
        sha256: "8b7d63f24b0f7008a46e2ca712e28355eb682f5fdec4368436f6617ab09ca17d",
    },
    Fixture {
        name: "values",
        version: 94,
        sha256: "503ab5455760309ce364b4359df420f17e751f91e3e7b77292ebe2f4fd711298",
    },
    Fixture {
        name: "metro",
        version: 85,
        sha256: "db19cf22cb6f0c9d856c44d0ee32d26604cae9c95f5d6c71107b84d5c2505da3",
    },
    Fixture {
        name: "metro",
        version: 90,
        sha256: "77617ccd740206dfaf1ab32944a6fab5ed4fa22aec414561edae0cf7271d2435",
    },
    Fixture {
        name: "metro",
        version: 94,
        sha256: "5be4e56d7a9c633b34f05e1acfadb0b2e83f5dd4a5231e3e3b8f46a8c498ae82",
    },
    Fixture {
        name: "construct",
        version: 85,
        sha256: "9272e12eb8f11cfd35a10979d47cd5022dd9199d53f0d3ba090323f3423f97d5",
    },
    Fixture {
        name: "construct",
        version: 90,
        sha256: "d7e35525719a11f7844b0a81e476c956ceaf7e0f875f0e424772b84b3d2575ea",
    },
    Fixture {
        name: "construct",
        version: 94,
        sha256: "0830925a56310284062d310550f54fe49b3aed15762bf6089b8e80231467aa02",
    },
    Fixture {
        name: "cleanup",
        version: 85,
        sha256: "af61d0b2f04bbaa1fcfd1498c187dc287cc0cbbae5f047eb1c517bacf940e16b",
    },
    Fixture {
        name: "cleanup",
        version: 90,
        sha256: "4ee8a989cfbf772bd18abcc1c97962bc024fbb248120bbc09ec3d9f6b539bcdb",
    },
    Fixture {
        name: "cleanup",
        version: 94,
        sha256: "15d19392f1002ba3a30893ab8a5e5974440b0061c9db6f7f4f1d4ca621e29f79",
    },
    Fixture {
        name: "delegation",
        version: 85,
        sha256: "d59e3dfd059f57d4c8763d1ce2bdcaf1c2133ba0c4bffcfacb84e5e860337ee8",
    },
    Fixture {
        name: "delegation",
        version: 90,
        sha256: "66164c631ff94d527e5886d77a2eb95e1277b8d46161ad38ed9a39ec8f291497",
    },
    Fixture {
        name: "delegation",
        version: 94,
        sha256: "2c9ae967000e1bc0b6b73263bc96a291384727a9cca47b966256a3012891c242",
    },
    Fixture {
        name: "names",
        version: 85,
        sha256: "96172e43ce3bc9ceb0ec4516ec5323a9a8663d3a84c41a7e206cfbf1c9cced44",
    },
    Fixture {
        name: "names",
        version: 90,
        sha256: "cfe959d1116351781d5ed0550a9a8d5493d551b58d82d26967b0dc0c2efe045c",
    },
    Fixture {
        name: "names",
        version: 94,
        sha256: "6cca2c97030250205ba82b3aece361dc105c1795a2558975cc8a08dbd1dd7b20",
    },
    Fixture {
        name: "rnassets",
        version: 85,
        sha256: "07489dc453eb30d0019fd39c53d9068e77d1831350df70f206cfcb6b0a79ea28",
    },
    Fixture {
        name: "rnassets",
        version: 90,
        sha256: "4287743b129aa13d44ca756b885048b7cbadca657bf0197003446a2412f3dbb6",
    },
    Fixture {
        name: "rnassets",
        version: 94,
        sha256: "65365d56350bb32feb8a7d099af386cf2e8ab10eb8bab96c9a6c338faefe1819",
    },
];

const GRADED_HERE: [u32; 5] = [85, 90, 94, 98, 99];

fn fixture_dir(version: u32) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("hermes")
        .join(if version >= 98 { "modern" } else { "bands" })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut acc: String, b: &u8| {
            use std::fmt::Write as _;
            let _: std::fmt::Result = write!(acc, "{b:02x}");
            acc
        })
}

fn bytes_of(fixture: &Fixture) -> Vec<u8> {
    let path: PathBuf =
        fixture_dir(fixture.version).join(format!("{}.hbc.v{}", fixture.name, fixture.version));
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is committed, so a run that cannot read it grades nothing: {error}",
            path.display()
        )
    });
    assert_eq!(
        sha256_hex(&bytes),
        fixture.sha256,
        "{} must be the bytes build.py wrote",
        path.display()
    );
    bytes
}

struct DumpFunction {
    name: String,
    mnemonics: Vec<String>,
    lines: Vec<String>,
    labels: BTreeMap<String, usize>,
    handlers: Vec<(String, String, String)>,
}

struct Dump {
    strings: Vec<String>,
    literal_values: Vec<String>,
    object_keys: Vec<String>,
    object_values: Vec<String>,
    shapes: Vec<(u32, u32)>,
    functions: Vec<DumpFunction>,
}

fn section_lines<'a>(text: &'a str, title: &str, entry: fn(&str) -> bool) -> Vec<&'a str> {
    let mut lines = text.lines().skip_while(|line: &&str| *line != title);
    lines.next();
    lines.take_while(|line: &&str| entry(line)).collect()
}

fn is_string_entry(line: &str) -> bool {
    let rest: &str = line
        .strip_prefix('s')
        .or_else(|| line.strip_prefix('i'))
        .unwrap_or("");
    let digits: usize = rest.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && rest[digits..].starts_with('[')
}

fn is_literal_entry(line: &str) -> bool {
    matches!(line, "null" | "true" | "false" | "undefined") || line.starts_with('[')
}

fn is_shape_entry(line: &str) -> bool {
    let digits: usize = line.chars().take_while(char::is_ascii_digit).count();
    digits > 0 && line[digits..].starts_with('[')
}

fn read_dump(fixture: &Fixture) -> Dump {
    let path: PathBuf = fixture_dir(fixture.version).join(format!(
        "{}.v{}.hermesc-dump.txt",
        fixture.name, fixture.version
    ));
    let text: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|error: std::io::Error| panic!("{} is committed: {error}", path.display()));
    let strings: Vec<String> = section_lines(&text, "Global String Table:", is_string_entry)
        .iter()
        .map(|line: &&str| {
            let (_, text): (&str, &str) = line.split_once("]: ").unwrap_or_else(|| {
                let (head, rest): (&str, &str) = line.split_once(": ").expect("string entry");
                (head, rest)
            });
            text.to_owned()
        })
        .collect();
    let literal_title: &str = if fixture.version >= 98 {
        "Literal Value Buffer:"
    } else {
        "Array Buffer:"
    };
    let literal_values: Vec<String> = section_lines(&text, literal_title, is_literal_entry)
        .iter()
        .map(|line: &&str| (*line).to_owned())
        .collect();
    let object_values: Vec<String> = section_lines(&text, "Object Value Buffer:", is_literal_entry)
        .iter()
        .map(|line: &&str| (*line).to_owned())
        .collect();
    let object_keys: Vec<String> = section_lines(&text, "Object Key Buffer:", is_literal_entry)
        .iter()
        .map(|line: &&str| (*line).to_owned())
        .collect();
    let shapes: Vec<(u32, u32)> = section_lines(&text, "Object Shape Table:", is_shape_entry)
        .iter()
        .map(|line: &&str| {
            let inner: &str = line
                .split_once('[')
                .and_then(|(_, rest): (&str, &str)| rest.strip_suffix(']'))
                .expect("shape entry");
            let (offset, count): (&str, &str) = inner.split_once(", ").expect("shape pair");
            (
                offset.parse().expect("offset"),
                count.parse().expect("count"),
            )
        })
        .collect();
    let mut functions: Vec<DumpFunction> = Vec::new();
    let mut in_handlers: bool = false;
    for line in text.lines() {
        let header: Option<&str> = line
            .strip_prefix("Function<")
            .or_else(|| line.strip_prefix("NCFunction<"))
            .or_else(|| line.strip_prefix("Constructor<"));
        if let Some(rest) = header
            && let Some(at) = rest.find(">(")
        {
            functions.push(DumpFunction {
                name: rest[..at].to_owned(),
                mnemonics: Vec::new(),
                lines: Vec::new(),
                labels: BTreeMap::new(),
                handlers: Vec::new(),
            });
            in_handlers = false;
            continue;
        }
        let Some(current) = functions.last_mut() else {
            continue;
        };
        if line == "Exception Handlers:" {
            in_handlers = true;
            continue;
        }
        if in_handlers {
            if let Some((_, rest)) = line.split_once(": start = ") {
                let (start, rest): (&str, &str) = rest.split_once(", end = ").expect("end");
                let (end, target): (&str, &str) = rest.split_once(", target = ").expect("target");
                current
                    .handlers
                    .push((start.to_owned(), end.to_owned(), target.to_owned()));
                continue;
            }
            in_handlers = false;
        }
        if let Some(label) = line.strip_suffix(':')
            && label.starts_with('L')
            && !label.contains(' ')
        {
            current
                .labels
                .insert(label.to_owned(), current.mnemonics.len());
            continue;
        }
        let Some(body) = line.strip_prefix("    ") else {
            continue;
        };
        let Some(word) = body.split_whitespace().next() else {
            continue;
        };
        if word.ends_with(':') || word == "Offset" {
            continue;
        }
        current.mnemonics.push(word.to_owned());
        current.lines.push(body.trim().to_owned());
    }
    Dump {
        strings,
        literal_values,
        object_keys,
        object_values,
        shapes,
        functions,
    }
}

fn builtin_operand(line: &str) -> Option<u64> {
    let inner: &str = line.split_once('(')?.1.strip_suffix(')')?;
    inner.split(", ").nth(1)?.parse().ok()
}

fn quoted(line: &str) -> Option<&str> {
    let start: usize = line.find('"')? + 1;
    let end: usize = start + line[start..].find('"')?;
    Some(&line[start..end])
}

fn recovered(module: &HermesModule, index: usize) -> (Vec<String>, Vec<usize>) {
    let mut mnemonics: Vec<String> = Vec::new();
    let mut offsets: Vec<usize> = Vec::new();
    for line in hermes_disasm_function(module, index) {
        let (offset, rest): (&str, &str) = line.split_once(": ").expect("offset prefix");
        offsets
            .push(usize::from_str_radix(offset.trim_start_matches("0x"), 16).expect("hex offset"));
        mnemonics.push(rest.split_once('(').map_or(rest, |(m, _)| m).to_owned());
    }
    (mnemonics, offsets)
}

const fn the_dump_prints_int32_bits_unsigned(value: i32) -> u32 {
    u32::from_le_bytes(value.to_le_bytes())
}

fn render_literal(value: &LiteralValue) -> String {
    match value {
        LiteralValue::Null => "null".to_owned(),
        LiteralValue::Undefined => "undefined".to_owned(),
        LiteralValue::Bool(flag) => flag.to_string(),
        LiteralValue::Integer(value) => {
            format!("[int {}]", the_dump_prints_int32_bits_unsigned(*value))
        }
        LiteralValue::Number(value) => format!("[double {value:.6}]"),
        LiteralValue::StringId(id) => format!("[String {id}]"),
        LiteralValue::PrivateName => "[private name]".to_owned(),
    }
}

fn instruction_index(offsets: &[usize], end: usize, offset: u32) -> usize {
    let offset: usize = offset as usize;
    offsets
        .iter()
        .position(|at: &usize| *at == offset)
        .unwrap_or_else(|| {
            assert_eq!(offset, end, "a handler bound must fall on an instruction");
            offsets.len()
        })
}

#[test]
fn every_modern_version_is_graded_here() {
    for fixture in FIXTURES {
        assert!(GRADED_HERE.contains(&fixture.version), "{}", fixture.name);
    }
    for version in HERMES_DISASSEMBLED_VERSIONS
        .iter()
        .filter(|v: &&u32| GRADED_HERE.contains(v))
    {
        assert!(
            FIXTURES.iter().any(|f: &Fixture| f.version == *version),
            "hbc v{version} has an opcode table, so it needs a fixture here"
        );
    }
}

#[test]
fn modern_bytecode_disassembles_to_what_its_own_compiler_prints() {
    let mut totals: BTreeMap<u32, (usize, usize, usize)> = BTreeMap::new();
    let mut builtin_names: BTreeMap<u32, usize> = BTreeMap::new();
    for fixture in FIXTURES {
        let label: String = format!("{}.v{}", fixture.name, fixture.version);
        let module: HermesModule =
            parse_hermes_module(&bytes_of(fixture)).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(module.header.version, fixture.version, "{label}");
        let dump: Dump = read_dump(fixture);

        let table: Vec<String> = (0..dump.strings.len())
            .map(|id: usize| {
                module
                    .string_by_global_id(u32::try_from(id).expect("id"))
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        assert_eq!(table, dump.strings, "{label}: string table");

        let format: LiteralFormat = LiteralFormat::for_version(fixture.version);
        let values: Vec<String> = decode_hermes_literals_in(
            format,
            &module.array_buffer,
            0,
            dump.literal_values.len(),
            BufferKind::Value,
        )
        .iter()
        .map(render_literal)
        .collect();
        assert_eq!(values, dump.literal_values, "{label}: literal value buffer");
        let keys: Vec<String> = decode_hermes_literals_in(
            format,
            &module.obj_key_buffer,
            0,
            dump.object_keys.len(),
            BufferKind::Key,
        )
        .iter()
        .map(render_literal)
        .collect();
        assert_eq!(keys, dump.object_keys, "{label}: object key buffer");
        let object_values: Vec<String> = decode_hermes_literals_in(
            format,
            &module.obj_value_buffer,
            0,
            dump.object_values.len(),
            BufferKind::Value,
        )
        .iter()
        .map(render_literal)
        .collect();
        assert_eq!(
            object_values, dump.object_values,
            "{label}: object value buffer"
        );
        let shapes: Vec<(u32, u32)> = module
            .obj_shape_table
            .iter()
            .map(|shape| (shape.key_buffer_offset, shape.property_count))
            .collect();
        assert_eq!(shapes, dump.shapes, "{label}: object shape table");

        assert_eq!(
            module.functions.len(),
            dump.functions.len(),
            "{label}: function count"
        );
        let (mut instructions, mut handlers): (usize, usize) = (0, 0);
        let mut builtins: usize = 0;
        for (index, want) in dump.functions.iter().enumerate() {
            let name: &str = module
                .string_by_global_id(module.functions[index].function_name_id)
                .unwrap_or_default();
            assert_eq!(name, want.name, "{label}: function {index} name");
            let (mnemonics, offsets): (Vec<String>, Vec<usize>) = recovered(&module, index);
            assert_eq!(
                mnemonics, want.mnemonics,
                "{label} {}: disrobe decodes a different instruction sequence than the compiler \
                 prints for the same bytes",
                want.name
            );
            let end: usize = module.functions[index].bytecode_size_bytes as usize;
            let table: Vec<HermesExceptionEntry> = module
                .exception_table(index)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            let got: Vec<(usize, usize, usize)> = table
                .iter()
                .map(|entry: &HermesExceptionEntry| {
                    (
                        instruction_index(&offsets, end, entry.start),
                        instruction_index(&offsets, end, entry.end),
                        instruction_index(&offsets, end, entry.target),
                    )
                })
                .collect();
            let at = |label_name: &str| -> usize {
                *want
                    .labels
                    .get(label_name)
                    .unwrap_or_else(|| panic!("{label}: label {label_name} is printed"))
            };
            let expected: Vec<(usize, usize, usize)> = want
                .handlers
                .iter()
                .map(|(start, end, target): &(String, String, String)| {
                    (at(start), at(end), at(target))
                })
                .collect();
            assert_eq!(got, expected, "{label} {}: exception handlers", want.name);
            let lines: Vec<String> = hermes_disasm_function(&module, index);
            for (ours, theirs) in lines.iter().zip(&want.lines) {
                let builtin: bool = ["CallBuiltin", "GetBuiltinClosure", "JmpBuiltinIs"]
                    .iter()
                    .any(|name: &&str| theirs.starts_with(name));
                if !builtin {
                    continue;
                }
                let id: u64 = builtin_operand(ours)
                    .unwrap_or_else(|| panic!("{label}: builtin operand in {ours}"));
                if theirs.starts_with("JmpBuiltinIs") {
                    let printed: Option<u64> = theirs
                        .split(", ")
                        .nth(1)
                        .and_then(|operand: &str| operand.trim().parse().ok());
                    assert_eq!(
                        printed,
                        Some(id),
                        "{label} {}: the compiler prints the builtin number of {theirs}",
                        want.name
                    );
                    builtins += 1;
                    continue;
                }
                let named: &str =
                    quoted(theirs).unwrap_or_else(|| panic!("{label}: quoted builtin in {theirs}"));
                assert_eq!(
                    hermes_builtin_name(fixture.version, id),
                    named,
                    "{label} {}: builtin {id} is named differently by the compiler",
                    want.name
                );
                builtins += 1;
            }
            instructions += mnemonics.len();
            handlers += expected.len();
        }
        let entry: &mut (usize, usize, usize) = totals.entry(fixture.version).or_default();
        entry.0 += instructions;
        entry.1 += dump.functions.len();
        entry.2 += handlers;
        *builtin_names.entry(fixture.version).or_default() += builtins;
    }
    assert_eq!(
        builtin_names,
        BTreeMap::from([
            (85, PINNED_BUILTINS_V85),
            (90, PINNED_BUILTINS_V90),
            (94, PINNED_BUILTINS_V94),
            (98, PINNED_BUILTINS_V98),
            (99, PINNED_BUILTINS_V99)
        ]),
        "every builtin the compiler names is resolved to the same name"
    );
    eprintln!("graded per version (instructions, functions, handlers): {totals:?}");
    assert_eq!(
        totals,
        BTreeMap::from([
            (85, PINNED_V85),
            (90, PINNED_V90),
            (94, PINNED_V94),
            (98, PINNED_V98),
            (99, PINNED_V99)
        ]),
        "the graded population is pinned by equality, so a reference trimmed to fewer \
         instructions fails instead of agreeing more easily"
    );
}

const PINNED_V85: (usize, usize, usize) = (5_301, 193, 57);
const PINNED_V90: (usize, usize, usize) = (6_238, 204, 67);
const PINNED_V94: (usize, usize, usize) = (6_238, 204, 67);
const PINNED_V98: (usize, usize, usize) = (8_985, 237, 212);
const PINNED_V99: (usize, usize, usize) = (8_986, 237, 212);
const PINNED_BUILTINS_V85: usize = 87;
const PINNED_BUILTINS_V90: usize = 95;
const PINNED_BUILTINS_V94: usize = 95;
const PINNED_BUILTINS_V98: usize = 116;
const PINNED_BUILTINS_V99: usize = 117;

#[test]
fn reading_v98_bytes_through_the_v99_layout_is_caught() {
    let fixture: &Fixture = FIXTURES
        .iter()
        .find(|f: &&Fixture| f.name == "objects" && f.version == 98)
        .expect("objects v98");
    let mut bytes: Vec<u8> = bytes_of(fixture);
    bytes.splice(8..12, 99u32.to_le_bytes());
    let dump: Dump = read_dump(fixture);
    let caught: bool = match parse_hermes_module(&bytes) {
        Err(_) => true,
        Ok(module) => {
            dump.functions
                .iter()
                .enumerate()
                .any(|(index, want): (usize, &DumpFunction)| {
                    recovered(&module, index).0 != want.mnemonics
                })
        }
    };
    assert!(
        caught,
        "v98 and v99 number their opcodes differently, so reading one through the other's table \
         must disagree with the compiler's own disassembly"
    );
}
