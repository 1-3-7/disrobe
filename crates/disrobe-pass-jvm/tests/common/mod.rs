#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic
)]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use sha2::{Digest, Sha256};

pub const VERIFIER_SRC: &str = include_str!("V.java");

const REVIEWED_VERIFIER_MEMBER_REFERENCES: &[&str] = &[
    "V$L.<init>:(Ljava/util/Map;Z)V",
    "V$L.defineClass:(Ljava/lang/String;[BII)Ljava/lang/Class;",
    "V$L.defineRaw:(Ljava/lang/String;[B)Ljava/lang/Class;",
    "V$L.defineStub:(Ljava/lang/String;)Ljava/lang/Class;",
    "V$L.findClass:(Ljava/lang/String;)Ljava/lang/Class;",
    "V$L.findLoadedClass:(Ljava/lang/String;)Ljava/lang/Class;",
    "V$L.isStubbed:(Ljava/lang/String;)Z",
    "V$L.lambda$defineStub$0:(Ljava/lang/classfile/ClassBuilder;)V",
    "V$L.link:(Ljava/lang/Class;)V",
    "V$L.resolveClass:(Ljava/lang/Class;)V",
    "V$L.resolveTop:(Ljava/lang/String;)Ljava/lang/Class;",
    "V.carrier:(Ljava/lang/classfile/ClassModel;Ljava/lang/classfile/MethodModel;)[B",
    "V.isStub:(Ljava/lang/classfile/CodeModel;)Z",
    "V.lambda$carrier$0:(Ljava/lang/String;Ljava/lang/constant/MethodTypeDesc;Ljava/lang/classfile/MethodModel;Ljava/lang/classfile/ClassBuilder;)V",
    "V.lambda$carrier$1:(Ljava/lang/classfile/MethodModel;Ljava/lang/classfile/MethodBuilder;)V",
    "V.lambda$carrier$2:(Ljava/lang/classfile/MethodBuilder;Ljava/lang/classfile/CodeModel;)V",
    "V.lambda$carrier$3:(Ljava/lang/classfile/CodeModel;Ljava/lang/classfile/CodeBuilder;)V",
    "V.methodsWithCode:([B)I",
    "V.readJar:(Ljava/lang/String;)Ljava/util/Map;",
    "V.refsStub:(LV$L;Ljava/lang/classfile/ClassModel;Ljava/lang/classfile/MethodModel;)Z",
    "V.runBodies:(Ljava/lang/String;I)V",
    "V.runClasses:(Ljava/lang/String;I)V",
    "V.sampled:(Ljava/lang/String;I)Z",
    "V.usesInvokeSpecial:(Ljava/lang/classfile/MethodModel;)Z",
    "java/io/ByteArrayOutputStream.<init>:()V",
    "java/io/ByteArrayOutputStream.toByteArray:()[B",
    "java/io/ByteArrayOutputStream.write:([BII)V",
    "java/io/FileInputStream.<init>:(Ljava/lang/String;)V",
    "java/io/PrintStream.println:(Ljava/lang/String;)V",
    "java/lang/Class.getClassLoader:()Ljava/lang/ClassLoader;",
    "java/lang/Class.getDeclaredConstructors:()[Ljava/lang/reflect/Constructor;",
    "java/lang/Class.getDeclaredMethods:()[Ljava/lang/reflect/Method;",
    "java/lang/Class.getName:()Ljava/lang/String;",
    "java/lang/ClassLoader.<init>:(Ljava/lang/ClassLoader;)V",
    "java/lang/ClassLoader.findClass:(Ljava/lang/String;)Ljava/lang/Class;",
    "java/lang/Integer.parseInt:(Ljava/lang/String;)I",
    "java/lang/LinkageError.getMessage:()Ljava/lang/String;",
    "java/lang/Math.min:(II)I",
    "java/lang/Object.<init>:()V",
    "java/lang/Object.getClass:()Ljava/lang/Class;",
    "java/lang/String.endsWith:(Ljava/lang/String;)Z",
    "java/lang/String.equals:(Ljava/lang/Object;)Z",
    "java/lang/String.hashCode:()I",
    "java/lang/String.length:()I",
    "java/lang/String.replace:(CC)Ljava/lang/String;",
    "java/lang/String.startsWith:(Ljava/lang/String;)Z",
    "java/lang/String.substring:(II)Ljava/lang/String;",
    "java/lang/String.valueOf:(Ljava/lang/Object;)Ljava/lang/String;",
    "java/lang/System.exit:(I)V",
    "java/lang/Throwable.addSuppressed:(Ljava/lang/Throwable;)V",
    "java/lang/Throwable.getMessage:()Ljava/lang/String;",
    "java/lang/VerifyError.getMessage:()Ljava/lang/String;",
    "java/lang/classfile/AccessFlags.flagsMask:()I",
    "java/lang/classfile/ClassBuilder.withFlags:(I)Ljava/lang/classfile/ClassBuilder;",
    "java/lang/classfile/ClassBuilder.withMethod:(Ljava/lang/String;Ljava/lang/constant/MethodTypeDesc;ILjava/util/function/Consumer;)Ljava/lang/classfile/ClassBuilder;",
    "java/lang/classfile/ClassBuilder.withSuperclass:(Ljava/lang/constant/ClassDesc;)Ljava/lang/classfile/ClassBuilder;",
    "java/lang/classfile/ClassFile.build:(Ljava/lang/constant/ClassDesc;Ljava/util/function/Consumer;)[B",
    "java/lang/classfile/ClassFile.of:()Ljava/lang/classfile/ClassFile;",
    "java/lang/classfile/ClassFile.parse:([B)Ljava/lang/classfile/ClassModel;",
    "java/lang/classfile/ClassModel.constantPool:()Ljava/lang/classfile/constantpool/ConstantPool;",
    "java/lang/classfile/ClassModel.methods:()Ljava/util/List;",
    "java/lang/classfile/ClassModel.thisClass:()Ljava/lang/classfile/constantpool/ClassEntry;",
    "java/lang/classfile/CodeBuilder.with:(Ljava/lang/classfile/ClassFileElement;)Ljava/lang/classfile/ClassFileBuilder;",
    "java/lang/classfile/CodeModel.iterator:()Ljava/util/Iterator;",
    "java/lang/classfile/MethodBuilder.withCode:(Ljava/util/function/Consumer;)Ljava/lang/classfile/MethodBuilder;",
    "java/lang/classfile/MethodModel.code:()Ljava/util/Optional;",
    "java/lang/classfile/MethodModel.flags:()Ljava/lang/classfile/AccessFlags;",
    "java/lang/classfile/MethodModel.methodName:()Ljava/lang/classfile/constantpool/Utf8Entry;",
    "java/lang/classfile/MethodModel.methodType:()Ljava/lang/classfile/constantpool/Utf8Entry;",
    "java/lang/classfile/MethodModel.methodTypeSymbol:()Ljava/lang/constant/MethodTypeDesc;",
    "java/lang/classfile/constantpool/ClassEntry.asInternalName:()Ljava/lang/String;",
    "java/lang/classfile/constantpool/ClassEntry.asSymbol:()Ljava/lang/constant/ClassDesc;",
    "java/lang/classfile/constantpool/ConstantPool.iterator:()Ljava/util/Iterator;",
    "java/lang/classfile/constantpool/Utf8Entry.stringValue:()Ljava/lang/String;",
    "java/lang/classfile/instruction/InvokeInstruction.opcode:()Ljava/lang/classfile/Opcode;",
    "java/lang/constant/ClassDesc.of:(Ljava/lang/String;)Ljava/lang/constant/ClassDesc;",
    "java/lang/constant/MethodTypeDesc.of:(Ljava/lang/constant/ClassDesc;Ljava/util/List;)Ljava/lang/constant/MethodTypeDesc;",
    "java/lang/constant/MethodTypeDesc.parameterList:()Ljava/util/List;",
    "java/lang/constant/MethodTypeDesc.returnType:()Ljava/lang/constant/ClassDesc;",
    "java/lang/invoke/LambdaMetafactory.metafactory:(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
    "java/lang/invoke/StringConcatFactory.makeConcatWithConstants:(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
    "java/util/ArrayList.<init>:()V",
    "java/util/ArrayList.<init>:(Ljava/util/Collection;)V",
    "java/util/Collections.sort:(Ljava/util/List;)V",
    "java/util/HashMap.<init>:()V",
    "java/util/HashSet.<init>:()V",
    "java/util/Iterator.hasNext:()Z",
    "java/util/Iterator.next:()Ljava/lang/Object;",
    "java/util/List.add:(Ljava/lang/Object;)Z",
    "java/util/List.addAll:(Ljava/util/Collection;)Z",
    "java/util/List.iterator:()Ljava/util/Iterator;",
    "java/util/List.size:()I",
    "java/util/Map.get:(Ljava/lang/Object;)Ljava/lang/Object;",
    "java/util/Map.keySet:()Ljava/util/Set;",
    "java/util/Map.put:(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
    "java/util/Optional.get:()Ljava/lang/Object;",
    "java/util/Optional.ifPresent:(Ljava/util/function/Consumer;)V",
    "java/util/Optional.isEmpty:()Z",
    "java/util/Optional.isPresent:()Z",
    "java/util/Set.add:(Ljava/lang/Object;)Z",
    "java/util/Set.contains:(Ljava/lang/Object;)Z",
    "java/util/Set.size:()I",
    "java/util/zip/ZipEntry.getName:()Ljava/lang/String;",
    "java/util/zip/ZipInputStream.<init>:(Ljava/io/InputStream;)V",
    "java/util/zip/ZipInputStream.close:()V",
    "java/util/zip/ZipInputStream.getNextEntry:()Ljava/util/zip/ZipEntry;",
    "java/util/zip/ZipInputStream.read:([B)I",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConstantPoolEntry {
    Empty,
    Utf8(String),
    Class(u16),
    NameAndType { name: u16, descriptor: u16 },
    MemberRef { owner: u16, name_and_type: u16 },
    MethodHandle { reference: u16 },
}

struct ClassReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ClassReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8, String> {
        let value: u8 = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| "truncated class file".to_string())?;
        self.offset += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let hi: u16 = u16::from(self.u8()?);
        let lo: u16 = u16::from(self.u8()?);
        Ok((hi << 8) | lo)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let high: u32 = u32::from(self.u16()?);
        let low: u32 = u32::from(self.u16()?);
        Ok((high << 16) | low)
    }

    fn skip(&mut self, count: usize) -> Result<(), String> {
        self.offset = self
            .offset
            .checked_add(count)
            .filter(|end: &usize| *end <= self.bytes.len())
            .ok_or_else(|| "truncated class file".to_string())?;
        Ok(())
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], String> {
        let start: usize = self.offset;
        self.skip(count)?;
        Ok(&self.bytes[start..self.offset])
    }
}

fn class_member_references(class_bytes: &[u8]) -> Result<Vec<String>, String> {
    const CLASS_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
    const MAX_CLASS_BYTES: usize = 2 * 1024 * 1024;
    const MAX_CONSTANT_POOL_ENTRIES: u16 = 16_384;

    if class_bytes.len() > MAX_CLASS_BYTES {
        return Err(format!(
            "compiled verifier class exceeds {MAX_CLASS_BYTES} bytes"
        ));
    }
    let mut reader: ClassReader<'_> = ClassReader::new(class_bytes);
    if reader.bytes(4)? != CLASS_MAGIC {
        return Err("compiled verifier class has no class-file magic".to_string());
    }
    reader.skip(4)?;
    let constant_pool_count: u16 = reader.u16()?;
    if constant_pool_count > MAX_CONSTANT_POOL_ENTRIES {
        return Err(format!(
            "compiled verifier class has {constant_pool_count} constant-pool entries, above {MAX_CONSTANT_POOL_ENTRIES}"
        ));
    }
    let mut entries: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Empty];
    let mut index: u16 = 1;
    while index < constant_pool_count {
        let entry: ConstantPoolEntry = match reader.u8()? {
            1 => {
                let length: usize = usize::from(reader.u16()?);
                let raw: &[u8] = reader.bytes(length)?;
                let text: String = std::str::from_utf8(raw)
                    .map_err(|_| {
                        "compiled verifier class has non-UTF-8 constant-pool text".to_string()
                    })?
                    .to_owned();
                ConstantPoolEntry::Utf8(text)
            }
            7 => ConstantPoolEntry::Class(reader.u16()?),
            3 | 4 | 9 | 17 | 18 => {
                reader.skip(4)?;
                ConstantPoolEntry::Empty
            }
            10 | 11 => ConstantPoolEntry::MemberRef {
                owner: reader.u16()?,
                name_and_type: reader.u16()?,
            },
            12 => ConstantPoolEntry::NameAndType {
                name: reader.u16()?,
                descriptor: reader.u16()?,
            },
            5 | 6 => {
                reader.skip(8)?;
                entries.push(ConstantPoolEntry::Empty);
                index = index
                    .checked_add(1)
                    .ok_or_else(|| "constant-pool index overflow".to_string())?;
                ConstantPoolEntry::Empty
            }
            8 | 16 | 19 | 20 => {
                reader.skip(2)?;
                ConstantPoolEntry::Empty
            }
            15 => {
                reader.skip(1)?;
                ConstantPoolEntry::MethodHandle {
                    reference: reader.u16()?,
                }
            }
            tag => {
                return Err(format!(
                    "compiled verifier class has unknown constant-pool tag {tag}"
                ));
            }
        };
        entries.push(entry);
        index = index
            .checked_add(1)
            .ok_or_else(|| "constant-pool index overflow".to_string())?;
    }

    let get = |at: u16| -> Result<&ConstantPoolEntry, String> {
        entries
            .get(usize::from(at))
            .ok_or_else(|| format!("constant-pool index {at} is outside the pool"))
    };
    let utf8 = |at: u16| -> Result<&str, String> {
        match get(at)? {
            ConstantPoolEntry::Utf8(value) => Ok(value),
            _ => Err(format!("constant-pool index {at} is not UTF-8 text")),
        }
    };
    let class_name = |at: u16| -> Result<&str, String> {
        match get(at)? {
            ConstantPoolEntry::Class(name) => utf8(*name),
            _ => Err(format!("constant-pool index {at} is not a class")),
        }
    };
    let member_reference = |at: u16| -> Result<String, String> {
        let ConstantPoolEntry::MemberRef {
            owner,
            name_and_type,
        } = get(at)?
        else {
            return Err(format!(
                "constant-pool index {at} is not a member reference"
            ));
        };
        let ConstantPoolEntry::NameAndType { name, descriptor } = get(*name_and_type)? else {
            return Err(format!(
                "constant-pool index {name_and_type} is not a member name and type"
            ));
        };
        Ok(format!(
            "{}.{}:{}",
            class_name(*owner)?,
            utf8(*name)?,
            utf8(*descriptor)?
        ))
    };
    let mut references: Vec<String> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let Ok(index): Result<u16, _> = u16::try_from(index) else {
            continue;
        };
        if matches!(entry, ConstantPoolEntry::MemberRef { .. }) {
            references.push(member_reference(index)?);
        }
    }

    reader.skip(6)?;
    let interface_count: usize = usize::from(reader.u16()?);
    reader.skip(
        interface_count
            .checked_mul(2)
            .ok_or_else(|| "interface count overflow".to_string())?,
    )?;
    for section in ["field", "method"] {
        let count: usize = usize::from(reader.u16()?);
        for _ in 0..count {
            reader.skip(6)?;
            let attributes: usize = usize::from(reader.u16()?);
            for _ in 0..attributes {
                reader.skip(2)?;
                let length: usize = usize::try_from(reader.u32()?)
                    .map_err(|_| format!("{section} attribute length exceeds usize"))?;
                reader.skip(length)?;
            }
        }
    }
    let attributes: usize = usize::from(reader.u16()?);
    for _ in 0..attributes {
        let name_index: u16 = reader.u16()?;
        let length: usize = usize::try_from(reader.u32()?)
            .map_err(|_| "class attribute length exceeds usize".to_string())?;
        if utf8(name_index)? != "BootstrapMethods" {
            reader.skip(length)?;
            continue;
        }
        let attribute: &[u8] = reader.bytes(length)?;
        let mut bootstrap: ClassReader<'_> = ClassReader::new(attribute);
        let count: usize = usize::from(bootstrap.u16()?);
        for _ in 0..count {
            let handle_index: u16 = bootstrap.u16()?;
            let ConstantPoolEntry::MethodHandle { reference } = get(handle_index)? else {
                return Err(format!(
                    "bootstrap method {handle_index} is not a method handle"
                ));
            };
            references.push(member_reference(*reference)?);
            let argument_count: usize = usize::from(bootstrap.u16()?);
            bootstrap.skip(
                argument_count
                    .checked_mul(2)
                    .ok_or_else(|| "bootstrap argument count overflow".to_string())?,
            )?;
        }
        if bootstrap.offset != attribute.len() {
            return Err("BootstrapMethods attribute has trailing bytes".to_string());
        }
    }
    references.sort();
    references.dedup();
    Ok(references)
}

pub fn assert_compiled_verifier_never_initialises(directory: &Path) {
    let mut references: Vec<String> = Vec::new();
    for name in ["V.class", "V$L.class"] {
        let path: PathBuf = directory.join(name);
        let bytes: Vec<u8> = std::fs::read(&path)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", path.display()));
        references.extend(
            class_member_references(&bytes)
                .unwrap_or_else(|error: String| panic!("parse {}: {error}", path.display())),
        );
    }
    references.sort();
    references.dedup();
    assert_eq!(
        references, REVIEWED_VERIFIER_MEMBER_REFERENCES,
        "the compiled jvm verifier helper's member references changed; it defines and links \
         translations of third-party and protector bytecode, so each exact owner.name:descriptor \
         requires review before it can enter the verifier"
    );
}

pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

const KOTLIN_STDLIB_SHA256: &str =
    "4ec0293bc3751423b203f1d8493251c57c42e73eb6377a6b8560d0974ff0a6df";
const JETBRAINS_ANNOTATIONS_SHA256: &str =
    "ace2a10dc8e2d5fd34925ecac03e4988b2c0f851650c94b8cef49ba1bd111478";

fn kotlinc_lib_dir() -> PathBuf {
    let path_var: std::ffi::OsString = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path_var)
        .find(|dir: &PathBuf| dir.join("kotlinc").is_file())
        .and_then(|bin: PathBuf| bin.parent().map(|home: &Path| home.join("lib")))
        .unwrap_or_else(|| {
            panic!(
                "the Kotlin graders run kotlinc classes against kotlin-stdlib 2.4.10 and \
                 annotations 13.0: set DISROBE_KOTLIN_STDLIB_JAR and DISROBE_JETBRAINS_ANNOTATIONS_JAR \
                 (Maven Central, see tests/fixtures/shape_matrix/kotlin/PROVENANCE.txt) or put kotlinc \
                 2.4.10 on PATH"
            )
        })
}

fn kotlin_library(variable: &str, file_name: &str, sha256: &str) -> PathBuf {
    let path: PathBuf =
        std::env::var_os(variable).map_or_else(|| kotlinc_lib_dir().join(file_name), PathBuf::from);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "{variable} or kotlinc 2.4.10 must provide {file_name} at {}: {err}",
            path.display()
        )
    });
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        sha256,
        "{} is not the pinned {file_name}",
        path.display()
    );
    path
}

pub fn kotlin_runtime() -> Vec<PathBuf> {
    vec![
        kotlin_library(
            "DISROBE_KOTLIN_STDLIB_JAR",
            "kotlin-stdlib.jar",
            KOTLIN_STDLIB_SHA256,
        ),
        kotlin_library(
            "DISROBE_JETBRAINS_ANNOTATIONS_JAR",
            "annotations-13.0.jar",
            JETBRAINS_ANNOTATIONS_SHA256,
        ),
    ]
}

pub const GRADER_JDK_MAJOR: u32 = 25;

pub fn grader_jdk_tool(name: &str) -> PathBuf {
    let Some(tool): Option<PathBuf> = find_on_path(name) else {
        panic!(
            "missing prerequisite: {name} is not on PATH; the JVM graders need JDK \
             {GRADER_JDK_MAJOR} (actions/setup-java in CI, a JDK {GRADER_JDK_MAJOR} bin first on \
             PATH locally)"
        );
    };
    let major: u32 = javac_major();
    assert!(
        major >= GRADER_JDK_MAJOR,
        "missing prerequisite: the javac on PATH is JDK {major}; the JVM graders' floors were \
         measured with JDK {GRADER_JDK_MAJOR}, so an older JDK would read as a recovery \
         regression. Put a JDK {GRADER_JDK_MAJOR} bin first on PATH"
    );
    tool
}

fn javac_major() -> u32 {
    static MAJOR: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *MAJOR.get_or_init(|| {
        let Some(javac): Option<PathBuf> = find_on_path("javac") else {
            panic!("missing prerequisite: javac is not on PATH");
        };
        let output: Output = Command::new(&javac)
            .arg("-version")
            .output()
            .unwrap_or_else(|error: std::io::Error| {
                panic!(
                    "missing prerequisite: `{} -version` did not start: {error}",
                    javac.display()
                )
            });
        let text: String = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        parse_javac_major(&text)
            .unwrap_or_else(|| panic!("`javac -version` printed no version: {text:?}"))
    })
}

pub fn parse_javac_major(text: &str) -> Option<u32> {
    let version: &str = text
        .split_whitespace()
        .find(|word: &&str| word.starts_with(|ch: char| ch.is_ascii_digit()))?;
    let mut parts: std::str::Split<'_, char> = version.split('.');
    let first: u32 = parts.next()?.parse().ok()?;
    if first == 1 {
        parts.next()?.parse().ok()
    } else {
        Some(first)
    }
}

pub fn parse_metric(stdout: &str, key: &str) -> usize {
    stdout
        .split_whitespace()
        .find_map(|tok: &str| tok.strip_prefix(key))
        .and_then(|v: &str| v.parse::<usize>().ok())
        .unwrap_or(0)
}

pub fn assert_permille(stdout: &str, expected: u32) {
    let seen: Option<u32> = stdout
        .split_whitespace()
        .find_map(|tok: &str| tok.strip_prefix("permille="))
        .and_then(|value: &str| value.parse::<u32>().ok());
    assert_eq!(
        seen,
        Some(expected),
        "the jvm helper reported a body sample of {seen:?} permille but this gate's pinned counts \
         were recorded at {expected}; a caller that changes the sample rate changes the population \
         behind every figure the gate asserts"
    );
}

#[derive(Debug)]
pub struct RealApk {
    pub file: &'static str,
    pub sha256: &'static str,
    pub short: &'static str,
    pub golden: &'static str,
    pub method_total: usize,
    pub code_item_methods_pinned: usize,
    pub self_reported_bodies_pinned: usize,
    pub candidate_bodies_pinned: usize,
    pub sampled_bodies_pinned: usize,
    pub presented_bodies: usize,
    pub attested_clean_pinned: usize,
    pub attested_rejected_pinned: usize,
}

pub const REAL_APKS: &[RealApk] = &[
    RealApk {
        file: "transmissionic-ionic.apk",
        sha256: "941d6781ed72f9e819347431d2ff36406b032b12a72a62fbac50d06f9b2a0b4f",
        short: "transmissionic",
        golden: "transmissionic-ionic.txt",
        method_total: 27_805,
        code_item_methods_pinned: 26_416,
        self_reported_bodies_pinned: 26_360,
        candidate_bodies_pinned: 26_360,
        sampled_bodies_pinned: 2_688,
        presented_bodies: 989,
        attested_clean_pinned: 988,
        attested_rejected_pinned: 1,
    },
    RealApk {
        file: "rustdesk-flutter.apk",
        sha256: "56996f058b23635c33d29c6d9f2e31091da45ce5021ce8f5e614970446bc669a",
        short: "rustdesk",
        golden: "rustdesk-flutter.txt",
        method_total: 32_410,
        code_item_methods_pinned: 29_983,
        self_reported_bodies_pinned: 29_841,
        candidate_bodies_pinned: 29_810,
        sampled_bodies_pinned: 2_892,
        presented_bodies: 1223,
        attested_clean_pinned: 1217,
        attested_rejected_pinned: 6,
    },
    RealApk {
        file: "enrecipes-nativescript.apk",
        sha256: "5992f51701ec7f3c06cb353f10ce0c0cb875718775d66b6ed5aa370a0c94934b",
        short: "enrecipes",
        golden: "enrecipes-nativescript.txt",
        method_total: 29_301,
        code_item_methods_pinned: 27_544,
        self_reported_bodies_pinned: 27_461,
        candidate_bodies_pinned: 27_460,
        sampled_bodies_pinned: 2_839,
        presented_bodies: 786,
        attested_clean_pinned: 783,
        attested_rejected_pinned: 3,
    },
];

pub fn real_apk_inbox() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus");
    path.push("mobile");
    path.push("apk");
    path.push("inbox");
    path
}

pub fn real_apk_path(file: &str) -> PathBuf {
    real_apk_inbox().join(file)
}

pub fn read_real_apk(file: &str) -> Vec<u8> {
    const MAX_BYTES: usize = 64 * 1024 * 1024;

    let path: PathBuf = real_apk_path(file);
    let apk: &RealApk = REAL_APKS
        .iter()
        .find(|apk: &&RealApk| apk.file == file)
        .unwrap_or_else(|| panic!("{} has no pinned SHA-256 identity", path.display()));
    let input: File =
        File::open(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let mut reader: std::io::Take<File> =
        input.take(u64::try_from(MAX_BYTES + 1).expect("byte limit fits u64"));
    let mut bytes: Vec<u8> = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert!(
        bytes.len() <= MAX_BYTES,
        "{} exceeds the 64 MiB real-apk identity limit",
        path.display()
    );
    let actual: String = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(
        actual,
        apk.sha256,
        "{} has the wrong SHA-256 identity: expected {}, actual {}",
        path.display(),
        apk.sha256,
        actual
    );
    bytes
}

pub fn real_apks_absent() -> Vec<&'static str> {
    REAL_APKS
        .iter()
        .filter(|apk: &&RealApk| {
            if real_apk_path(apk.file).is_file() {
                drop(read_real_apk(apk.file));
                false
            } else {
                true
            }
        })
        .map(|apk: &RealApk| apk.file)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyScope {
    Classes { permille: u32 },
    Bodies { permille: u32 },
}

#[derive(Debug)]
pub struct JvmVerifier {
    java: PathBuf,
    scratch: ScratchDir,
}

impl JvmVerifier {
    pub fn prepare(purpose: &str) -> Result<Self, String> {
        let java: PathBuf =
            find_on_path("java").ok_or_else(|| "java (JDK 24+) not on PATH".to_string())?;
        let javac: PathBuf =
            find_on_path("javac").ok_or_else(|| "javac (JDK 24+) not on PATH".to_string())?;
        let scratch: ScratchDir = ScratchDir::create(purpose).map_err(|e| e.to_string())?;
        let dir: &Path = scratch.path();
        let src: PathBuf = dir.join("V.java");
        std::fs::write(&src, VERIFIER_SRC).map_err(|e| e.to_string())?;
        let compiled: Output = Command::new(&javac)
            .arg("-d")
            .arg(dir)
            .arg(&src)
            .output()
            .map_err(|e| e.to_string())?;
        if !compiled.status.success() {
            return Err(format!(
                "helper needs a JDK exposing java.lang.classfile (JDK 24+): {}",
                String::from_utf8_lossy(&compiled.stderr)
            ));
        }
        assert_compiled_verifier_never_initialises(dir);
        Ok(Self { java, scratch })
    }

    pub fn dir(&self) -> &Path {
        self.scratch.path()
    }

    pub fn write_jar(&self, label: &str, jar: &[u8]) -> PathBuf {
        let path: PathBuf = self.dir().join(format!("{label}.jar"));
        std::fs::write(&path, jar).expect("write jar for the jvm verifier");
        path
    }

    pub fn run(&self, scope: VerifyScope, jar: &Path) -> String {
        let mut cmd: Command = Command::new(&self.java);
        cmd.arg("-Xverify:all").arg("-cp").arg(self.dir()).arg("V");
        match scope {
            VerifyScope::Classes { permille } => {
                cmd.arg("classes").arg(permille.to_string()).arg(jar);
            }
            VerifyScope::Bodies { permille } => {
                cmd.arg("bodies").arg(permille.to_string()).arg(jar);
            }
        }
        let run: Output = cmd.output().expect("run the jvm bytecode verifier");
        let stdout: String = String::from_utf8_lossy(&run.stdout).into_owned();
        assert!(
            run.status.success(),
            "jvm verifier helper crashed: {}\n{stdout}",
            String::from_utf8_lossy(&run.stderr)
        );
        stdout
    }
}

pub fn lines_with_prefix(stdout: &str, prefix: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|l: &&str| l.starts_with(prefix))
        .map(|l: &str| l.to_string())
        .collect()
}
