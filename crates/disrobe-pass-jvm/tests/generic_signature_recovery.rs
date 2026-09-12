use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_jvm::{
    Attribute, ClassFile, ConstantPoolEntry, decompile_class, decompile_class_with_inners,
    parse_classfile,
};

const GENERIC_SOURCE: &str = r"
public abstract class GenericFixture<T extends Number & Comparable<T>>
        implements java.util.function.Supplier<T> {
    public java.util.Map<String, T> values;
    public java.util.List<? extends T> upper;
    public java.util.Map<String, ? super T> lower;

    public abstract <K extends Comparable<? super K>, V>
            java.util.Map<K, V> copy(java.util.Map<? extends K, ? extends V> input)
            throws java.io.IOException;
}
";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn find_on_path(program: &str) -> Option<PathBuf> {
    let paths: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate: PathBuf = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
        if cfg!(windows) {
            let executable: PathBuf = dir.join(format!("{program}.exe"));
            if executable.is_file() {
                return Some(executable);
            }
        }
    }
    None
}

fn compile(javac: &Path, dir: &Path, source: &str) -> TestResult<ClassFile> {
    std::fs::create_dir_all(dir)?;
    let source_path: PathBuf = dir.join("GenericFixture.java");
    std::fs::write(&source_path, source)?;
    let output: std::process::Output = Command::new(javac)
        .arg("-g")
        .arg("-parameters")
        .arg("-d")
        .arg(dir)
        .arg(&source_path)
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "javac rejected source:\n{}\nsource:\n{source}",
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    let bytes: Vec<u8> = std::fs::read(dir.join("GenericFixture.class"))?;
    Ok(parse_classfile(&bytes)?)
}

fn signature_value(cf: &ClassFile, attributes: &[Attribute]) -> Option<String> {
    let matching: Vec<&Attribute> = attributes
        .iter()
        .filter(|attribute: &&Attribute| {
            cf.utf8_at(attribute.name_index)
                .is_ok_and(|name: &str| name == "Signature")
        })
        .collect();
    let [attribute]: [&Attribute; 1] = matching.try_into().ok()?;
    let [high, low]: [u8; 2] = attribute.info.as_slice().try_into().ok()?;
    cf.utf8_at(u16::from_be_bytes([high, low]))
        .ok()
        .map(str::to_string)
}

fn signature_map(cf: &ClassFile) -> TestResult<BTreeMap<String, String>> {
    let mut signatures: BTreeMap<String, String> = BTreeMap::new();
    if let Some(signature) = signature_value(cf, &cf.attributes) {
        signatures.insert("class".to_string(), signature);
    }
    for field in &cf.fields {
        let Some(signature): Option<String> = signature_value(cf, &field.attributes) else {
            continue;
        };
        let name: &str = cf.utf8_at(field.name_index)?;
        let descriptor: &str = cf.utf8_at(field.descriptor_index)?;
        signatures.insert(format!("field:{name}:{descriptor}"), signature);
    }
    for method in &cf.methods {
        let Some(signature): Option<String> = signature_value(cf, &method.attributes) else {
            continue;
        };
        let name: &str = cf.utf8_at(method.name_index)?;
        let descriptor: &str = cf.utf8_at(method.descriptor_index)?;
        signatures.insert(format!("method:{name}:{descriptor}"), signature);
    }
    Ok(signatures)
}

fn corpus_jar() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/jvm/megafile/EdgeCases-baseline.jar");
    path
}

fn corpus_classes(path: &Path) -> TestResult<Vec<(String, ClassFile)>> {
    let file: std::fs::File = std::fs::File::open(path)?;
    let mut archive: zip::ZipArchive<std::fs::File> = zip::ZipArchive::new(file)?;
    let mut classes: Vec<(String, ClassFile)> = Vec::new();
    for index in 0..archive.len() {
        let mut entry: zip::read::ZipFile<'_> = archive.by_index(index)?;
        if !Path::new(entry.name())
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("class"))
        {
            continue;
        }
        let name: String = entry.name().to_string();
        let mut bytes: Vec<u8> = Vec::new();
        entry.read_to_end(&mut bytes)?;
        classes.push((name, parse_classfile(&bytes)?));
    }
    Ok(classes)
}

#[test]
fn real_javac_generic_signatures_round_trip_exactly() -> TestResult {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; generic signature recovery not enforced");
        return Ok(());
    };
    let purpose: String = format!("disrobe_generic_signature_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose)?;
    let root: PathBuf = scratch.path().to_path_buf();
    let original_dir: PathBuf = root.join("original");
    let recovered_dir: PathBuf = root.join("recovered");
    let original: ClassFile = compile(&javac, &original_dir, GENERIC_SOURCE)?;
    let original_signatures: BTreeMap<String, String> = signature_map(&original)?;
    assert_eq!(original_signatures.len(), 5);

    let recovered_source: String = decompile_class(&original).source;
    for fragment in [
        "GenericFixture<T extends Number & Comparable<T>>",
        "implements java.util.function.Supplier<T>",
        "java.util.Map<String, T> values;",
        "java.util.List<? extends T> upper;",
        "java.util.Map<String, ? super T> lower;",
        "<K extends Comparable<? super K>, V> java.util.Map<K, V> copy(java.util.Map<? extends K, ? extends V> arg0)",
    ] {
        assert!(
            recovered_source.contains(fragment),
            "missing recovered generic fragment {fragment:?}:\n{recovered_source}"
        );
    }

    let recovered: ClassFile = compile(&javac, &recovered_dir, &recovered_source)?;
    assert_eq!(signature_map(&recovered)?, original_signatures);
    Ok(())
}

#[test]
fn malformed_signature_falls_back_atomically_to_erased_declarations() -> TestResult {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; malformed signature rejection not enforced");
        return Ok(());
    };
    let purpose: String = format!("disrobe_malformed_signature_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose)?;
    let root: PathBuf = scratch.path().to_path_buf();
    let mut class_file: ClassFile = compile(&javac, &root, GENERIC_SOURCE)?;
    let signature_indices: BTreeSet<u16> = std::iter::once(&class_file.attributes)
        .chain(class_file.fields.iter().map(|field| &field.attributes))
        .chain(class_file.methods.iter().map(|method| &method.attributes))
        .flat_map(|attributes: &Vec<Attribute>| attributes.iter())
        .filter(|attribute: &&Attribute| {
            class_file
                .utf8_at(attribute.name_index)
                .is_ok_and(|name: &str| name == "Signature")
        })
        .filter_map(|attribute: &Attribute| {
            let bytes: [u8; 2] = attribute.info.as_slice().try_into().ok()?;
            Some(u16::from_be_bytes(bytes))
        })
        .collect();
    for index in signature_indices {
        let Some(ConstantPoolEntry::Utf8(signature)) =
            class_file.constant_pool.get_mut(usize::from(index))
        else {
            return Err(std::io::Error::other("signature constant must be Utf8").into());
        };
        signature.push('!');
    }

    let recovered_source: String = decompile_class(&class_file).source;
    assert!(
        recovered_source.contains("class GenericFixture implements java.util.function.Supplier")
    );
    assert!(recovered_source.contains("java.util.Map values;"));
    assert!(recovered_source.contains("java.util.List upper;"));
    assert!(recovered_source.contains("java.util.Map lower;"));
    assert!(!recovered_source.contains("<T"));
    assert!(!recovered_source.contains("<K"));
    assert!(!recovered_source.contains('?'));
    Ok(())
}

#[test]
fn edge_cases_outer_signatures_round_trip_exactly() -> TestResult {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP: javac not on PATH; corpus generic signature recovery not enforced");
        return Ok(());
    };
    let jar: PathBuf = corpus_jar();
    let classes: Vec<(String, ClassFile)> = corpus_classes(&jar)?;
    let original: &ClassFile = classes
        .iter()
        .find_map(|(name, class_file): &(String, ClassFile)| {
            (name == "EdgeCases.class").then_some(class_file)
        })
        .ok_or_else(|| std::io::Error::other("EdgeCases.class missing from corpus jar"))?;
    let inners: BTreeMap<String, ClassFile> = classes
        .iter()
        .filter(|(name, _): &&(String, ClassFile)| name.starts_with("EdgeCases$"))
        .map(|(name, class_file): &(String, ClassFile)| (name.clone(), class_file.clone()))
        .collect();
    let original_signatures: BTreeMap<String, String> = signature_map(original)?;
    assert_eq!(original_signatures.len(), 51);

    let recovered_source: String = decompile_class_with_inners(original, &inners).source;
    let purpose: String = format!("disrobe_corpus_generic_signature_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose)?;
    let recovered_dir: PathBuf = scratch.path().to_path_buf();
    let source_path: PathBuf = recovered_dir.join("EdgeCases.java");
    std::fs::write(&source_path, &recovered_source)?;
    let output: std::process::Output = Command::new(&javac)
        .arg("-g")
        .arg("-parameters")
        .arg("-cp")
        .arg(&jar)
        .arg("-d")
        .arg(&recovered_dir)
        .arg(&source_path)
        .output()?;
    assert!(
        output.status.success(),
        "javac rejected recovered corpus source:\n{}\nsource:\n{recovered_source}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered_bytes: Vec<u8> = std::fs::read(recovered_dir.join("EdgeCases.class"))?;
    let recovered: ClassFile = parse_classfile(&recovered_bytes)?;
    assert_eq!(signature_map(&recovered)?, original_signatures);
    Ok(())
}
