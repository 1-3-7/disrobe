#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unreadable_literal
)]

use std::process::Command;

use disrobe_pass_pyinstaller::{
    Cookie, EntryType, ExtractOutput, ExtractedEntry, PyzEntry, TocEntry, extract_archive,
    extract_pyz, find_cookie, walk_toc,
};
use disrobe_py_marshal::{Object, PyVersion, load, magic_for};

const MEI_MAGIC: &[u8; 8] = b"MEI\x0C\x0B\x0A\x0B\x0E";
const COOKIE_LEN_V21: usize = 88;

const REFERENCE_SOURCE: &str =
    "def main():\n    print('disrobe-multiver-hello')\nif __name__ == '__main__':\n    main()\n";
const REFERENCE_FILENAME: &str = "hello.py";
const REFERENCE_TOKEN: &str = "disrobe-multiver-hello";
const PYZ_MODULE_SOURCE: &str = "VALUE = 0xC0FFEE\ndef stdlib_shape(n):\n    return n * VALUE\n";

#[derive(Debug, Clone)]
struct OnBoxCPython {
    program: String,
    prefix_args: Vec<String>,
    minor: u8,
}

impl OnBoxCPython {
    fn run_capture(&self, code: &str) -> Option<Vec<u8>> {
        let mut cmd: Command = Command::new(&self.program);
        for a in &self.prefix_args {
            cmd.arg(a);
        }
        cmd.arg("-c").arg(code);
        let out: std::process::Output = cmd.output().ok()?;
        if !out.status.success() {
            eprintln!(
                "[disrobe-pyinstaller] 3.{} helper exited non-zero: {}",
                self.minor,
                String::from_utf8_lossy(&out.stderr)
            );
            return None;
        }
        Some(out.stdout)
    }

    const fn expected_magic_le(&self) -> [u8; 4] {
        magic_for(PyVersion::new(3, self.minor))
            .expect("on-box interpreter minor must be in the magic table")
            .to_le_bytes()
    }
}

fn probe_minor(program: &str, prefix: &[&str]) -> Option<u8> {
    let mut cmd: Command = Command::new(program);
    for a in prefix {
        cmd.arg(a);
    }
    cmd.arg("-c")
        .arg("import sys; v=sys.version_info; sys.stdout.write(f'{v.major}.{v.minor}')");
    let out: std::process::Output = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut parts: std::str::Split<'_, char> = text.trim().split('.');
    let major: u8 = parts.next()?.parse().ok()?;
    let minor: u8 = parts.next()?.parse().ok()?;
    if major != 3 {
        return None;
    }
    Some(minor)
}

fn discover_interpreters() -> Vec<OnBoxCPython> {
    let mut found: Vec<OnBoxCPython> = Vec::new();
    let mut seen: Vec<u8> = Vec::new();
    let candidates: [(&str, &[&str]); 18] = [
        ("py", &["-3.10"]),
        ("py", &["-3.11"]),
        ("py", &["-3.12"]),
        ("py", &["-3.13"]),
        ("py", &["-3.14"]),
        ("py", &["-3.15"]),
        ("python3.10", &[]),
        ("python3.11", &[]),
        ("python3.12", &[]),
        ("python3.13", &[]),
        ("python3.14", &[]),
        ("python3.15", &[]),
        ("python3.10.exe", &[]),
        ("python3.11.exe", &[]),
        ("python3.13.exe", &[]),
        ("python3.15.exe", &[]),
        ("python3", &[]),
        ("python", &[]),
    ];
    for (program, prefix) in candidates {
        let Some(minor): Option<u8> = probe_minor(program, prefix) else {
            continue;
        };
        if magic_for(PyVersion::new(3, minor)).is_none() || seen.contains(&minor) {
            continue;
        }
        seen.push(minor);
        found.push(OnBoxCPython {
            program: program.to_owned(),
            prefix_args: prefix.iter().map(|s: &&str| (*s).to_owned()).collect(),
            minor,
        });
    }
    found
}

fn compile_reference_marshal(py: &OnBoxCPython) -> Option<Vec<u8>> {
    let src: &str = REFERENCE_SOURCE;
    let name: &str = REFERENCE_FILENAME;
    let code: String = format!(
        "import marshal,sys; co=compile({src:?},{name:?},'exec'); sys.stdout.buffer.write(marshal.dumps(co))",
    );
    py.run_capture(&code)
}

fn build_real_pyz(py: &OnBoxCPython) -> Option<Vec<u8>> {
    let src: &str = PYZ_MODULE_SOURCE;
    let code: String = format!(
        "import marshal,sys,zlib,struct,importlib.util\n\
         magic=importlib.util.MAGIC_NUMBER\n\
         modules=['disrobe_alpha','disrobe_beta','disrobe_pkg']\n\
         kinds={{'disrobe_alpha':0,'disrobe_beta':0,'disrobe_pkg':1}}\n\
         header=b'PYZ\\x00'+magic+b'\\x00\\x00\\x00\\x00'\n\
         body=bytearray()\n\
         toc={{}}\n\
         for m in modules:\n\
        \x20   co=compile({src:?}, m+'.py', 'exec')\n\
        \x20   blob=zlib.compress(marshal.dumps(co),9)\n\
        \x20   pos=len(header)+len(body)\n\
        \x20   toc[m]=(kinds[m],pos,len(blob))\n\
        \x20   body+=blob\n\
         toc_bytes=marshal.dumps(toc)\n\
         toc_pos=len(header)+len(body)\n\
         out=bytearray(header); out+=body; out+=toc_bytes\n\
         out[8:12]=struct.pack('>i', toc_pos)\n\
         sys.stdout.buffer.write(bytes(out))",
    );
    py.run_capture(&code)
}

fn push_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn zlib_compress(input: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::new(9));
    enc.write_all(input).expect("zlib write");
    enc.finish().expect("zlib finish")
}

struct CArchiveEntry {
    type_byte: u8,
    name: String,
    payload: Vec<u8>,
}

fn assemble_carchive(entries: &[CArchiveEntry], pyver: u32, minor: u8) -> Vec<u8> {
    let mut data_region: Vec<u8> = Vec::new();
    let mut toc_region: Vec<u8> = Vec::new();
    for entry in entries {
        let compressed: Vec<u8> = zlib_compress(&entry.payload);
        let position: u32 = u32::try_from(data_region.len()).expect("position fits u32");
        let compressed_len: u32 = u32::try_from(compressed.len()).expect("clen fits u32");
        let uncompressed_len: u32 = u32::try_from(entry.payload.len()).expect("ulen fits u32");
        data_region.extend_from_slice(&compressed);

        let name_bytes: &[u8] = entry.name.as_bytes();
        let entry_size: u32 = 18 + u32::try_from(name_bytes.len()).expect("name fits u32");
        push_u32_be(&mut toc_region, entry_size);
        push_u32_be(&mut toc_region, position);
        push_u32_be(&mut toc_region, compressed_len);
        push_u32_be(&mut toc_region, uncompressed_len);
        toc_region.push(1u8);
        toc_region.push(entry.type_byte);
        toc_region.extend_from_slice(name_bytes);
    }

    let toc_offset: u32 = u32::try_from(data_region.len()).expect("toc_offset fits u32");
    let toc_length: u32 = u32::try_from(toc_region.len()).expect("toc_length fits u32");
    let package_len: u32 =
        toc_offset + toc_length + u32::try_from(COOKIE_LEN_V21).expect("cookie len fits u32");

    let mut archive: Vec<u8> = Vec::with_capacity(package_len as usize);
    archive.extend_from_slice(&data_region);
    archive.extend_from_slice(&toc_region);
    archive.extend_from_slice(MEI_MAGIC);
    push_u32_be(&mut archive, package_len);
    push_u32_be(&mut archive, toc_offset);
    push_u32_be(&mut archive, toc_length);
    push_u32_be(&mut archive, pyver);
    let mut libname: Vec<u8> = format!("python3{minor}.dll").into_bytes();
    libname.resize(64, 0u8);
    archive.extend_from_slice(&libname);
    archive
}

fn recovered_marshal_body(entry: &ExtractedEntry, minor: u8, expected_magic: [u8; 4]) -> &[u8] {
    let header_len: usize = PyVersion::new(3, minor).pyc_header_len();
    let data: &[u8] = &entry.data;
    assert!(
        data.len() > header_len,
        "recovered pyc for '{}' too short to carry a header + body: {} bytes",
        entry.toc.name,
        data.len()
    );
    assert_eq!(
        &data[..4],
        &expected_magic,
        "recovered pyc for '{}' must carry the real 3.{minor} magic",
        entry.toc.name,
    );
    &data[header_len..]
}

#[test]
fn every_on_box_cpython_carchive_round_trips_to_independent_recompile() {
    let interpreters: Vec<OnBoxCPython> = discover_interpreters();
    if interpreters.is_empty() {
        eprintln!(
            "SKIP: no on-box CPython 3.x with a known pyc magic located; cannot build a genuine multi-version CArchive round-trip"
        );
        return;
    }

    let mut proven: Vec<u8> = Vec::new();
    for py in &interpreters {
        let expected_magic: [u8; 4] = py.expected_magic_le();
        let pyver: u32 = 300 + u32::from(py.minor);

        let embedded_marshal: Vec<u8> = compile_reference_marshal(py)
            .unwrap_or_else(|| panic!("3.{} must marshal the reference", py.minor));
        let oracle_marshal: Vec<u8> = compile_reference_marshal(py)
            .unwrap_or_else(|| panic!("independent 3.{} recompile must succeed", py.minor));
        assert_eq!(
            embedded_marshal, oracle_marshal,
            "two 3.{} invocations must yield identical marshal (deterministic ground truth)",
            py.minor,
        );

        let entries: Vec<CArchiveEntry> = vec![
            CArchiveEntry {
                type_byte: b's',
                name: "hello".to_owned(),
                payload: embedded_marshal.clone(),
            },
            CArchiveEntry {
                type_byte: b'm',
                name: "hello_mod".to_owned(),
                payload: embedded_marshal,
            },
        ];
        let archive: Vec<u8> = assemble_carchive(&entries, pyver, py.minor);

        let cookie: Cookie = find_cookie(&archive)
            .unwrap_or_else(|_| panic!("3.{} cookie must be located", py.minor));
        assert_eq!(
            cookie.python_major, 3,
            "detected python major (3.{})",
            py.minor
        );
        assert_eq!(
            cookie.python_minor, py.minor,
            "cookie pyver {pyver} must decode to the real interpreter minor",
        );

        let toc: Vec<TocEntry> =
            walk_toc(&archive, &cookie).unwrap_or_else(|_| panic!("3.{} toc walks", py.minor));
        assert_eq!(
            toc.len(),
            2,
            "3.{} toc must enumerate both entries",
            py.minor
        );

        let output: ExtractOutput =
            extract_archive(&archive).unwrap_or_else(|_| panic!("extract 3.{} carchive", py.minor));

        let script: &ExtractedEntry = output
            .entries
            .iter()
            .find(|e: &&ExtractedEntry| e.toc.entry_type == EntryType::Script)
            .unwrap_or_else(|| panic!("3.{} script entry must survive", py.minor));
        let module: &ExtractedEntry = output
            .entries
            .iter()
            .find(|e: &&ExtractedEntry| e.toc.entry_type == EntryType::Module)
            .unwrap_or_else(|| panic!("3.{} module entry must survive", py.minor));

        let script_body: &[u8] = recovered_marshal_body(script, py.minor, expected_magic);
        let module_body: &[u8] = recovered_marshal_body(module, py.minor, expected_magic);
        assert_eq!(
            script_body,
            oracle_marshal.as_slice(),
            "recovered 3.{} SCRIPT bytecode must byte-match an INDEPENDENT recompile (non-circular)",
            py.minor,
        );
        assert_eq!(
            module_body,
            oracle_marshal.as_slice(),
            "recovered 3.{} MODULE bytecode must byte-match an INDEPENDENT recompile (non-circular)",
            py.minor,
        );

        let loaded: Object = load(script_body, PyVersion::new(3, py.minor))
            .unwrap_or_else(|_| panic!("recovered 3.{} script body must marshal-load", py.minor));
        assert!(
            matches!(loaded, Object::Code(_)),
            "recovered 3.{} script body must decode to a code object",
            py.minor,
        );

        assert!(
            script_body
                .windows(REFERENCE_TOKEN.len())
                .any(|w: &[u8]| w == REFERENCE_TOKEN.as_bytes()),
            "recovered 3.{} bytecode must carry the reference string constant",
            py.minor,
        );

        proven.push(py.minor);
    }

    eprintln!(
        "[disrobe-pyinstaller] multiversion CArchive round-trip proven for on-box CPython minors: {proven:?}"
    );
    assert!(
        !proven.is_empty(),
        "at least one present interpreter must have been graded",
    );
}

#[test]
fn every_on_box_cpython_pyz_infers_version_and_marshal_loads() {
    let interpreters: Vec<OnBoxCPython> = discover_interpreters();
    if interpreters.is_empty() {
        eprintln!(
            "SKIP: no on-box CPython 3.x located; cannot build a genuine multi-version PYZ round-trip"
        );
        return;
    }

    let mut proven: Vec<u8> = Vec::new();
    for py in &interpreters {
        let Some(pyz_blob): Option<Vec<u8>> = build_real_pyz(py) else {
            panic!("3.{} must assemble a real PYZ", py.minor);
        };

        let (version, entries): (PyVersion, Vec<PyzEntry>) = extract_pyz(&pyz_blob)
            .unwrap_or_else(|e| panic!("3.{} real PYZ must parse: {e:?}", py.minor));
        assert_eq!(
            version,
            PyVersion::new(3, py.minor),
            "recovered PYZ version must equal the real interpreter that wrote it, not a default",
        );
        assert_eq!(
            entries.len(),
            3,
            "3.{} PYZ must carve all three modules",
            py.minor,
        );

        for wanted in ["disrobe_alpha", "disrobe_beta", "disrobe_pkg"] {
            let module: &PyzEntry = entries
                .iter()
                .find(|e: &&PyzEntry| e.name == wanted)
                .unwrap_or_else(|| panic!("3.{} PYZ module '{wanted}' must be carved", py.minor));
            let loaded: Object = load(&module.bytes, version).unwrap_or_else(|_| {
                panic!(
                    "3.{} PYZ module '{wanted}' must marshal-load under the recovered version",
                    py.minor
                )
            });
            assert!(
                matches!(loaded, Object::Code(_)),
                "3.{} PYZ module '{wanted}' must decode to a code object",
                py.minor,
            );
        }

        proven.push(py.minor);
    }

    eprintln!(
        "[disrobe-pyinstaller] multiversion PYZ inference proven for on-box CPython minors: {proven:?}"
    );
    assert!(
        !proven.is_empty(),
        "at least one interpreter must be graded"
    );
}
