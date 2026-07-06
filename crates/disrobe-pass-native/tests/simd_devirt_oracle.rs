#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::format_push_string
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_native::{LeafRecovery, PseudoAbi as Abi, recover_vectorized_reduction};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

const HOST_ABI: Abi = if cfg!(windows) { Abi::MsX64 } else { Abi::SysV };

const KERN_C: &str = r"#include <stdint.h>
int32_t sum_i32(const int32_t *a, int64_t n){ int32_t s=0; for(int64_t i=0;i<n;i++) s+=a[i]; return s; }
int64_t sum_i64(const int64_t *a, int64_t n){ int64_t s=0; for(int64_t i=0;i<n;i++) s+=a[i]; return s; }
uint32_t xor_u32(const uint32_t *a, int64_t n){ uint32_t x=0; for(int64_t i=0;i<n;i++) x^=a[i]; return x; }
uint32_t or_u32(const uint32_t *a, int64_t n){ uint32_t x=0; for(int64_t i=0;i<n;i++) x|=a[i]; return x; }
int16_t sum_i16(const int16_t *a, int64_t n){ int16_t s=0; for(int64_t i=0;i<n;i++) s+=a[i]; return s; }
int32_t max_i32(const int32_t *a, int64_t n){ int32_t m=a[0]; for(int64_t i=1;i<n;i++) if(a[i]>m) m=a[i]; return m; }
int32_t min_i32(const int32_t *a, int64_t n){ int32_t m=a[0]; for(int64_t i=1;i<n;i++) if(a[i]<m) m=a[i]; return m; }
void scale2_i32(uint32_t *b, const uint32_t *a, int64_t n){ for(int64_t i=0;i<n;i++) b[i]=a[i]*2; }
void shl3_i32(uint32_t *b, const uint32_t *a, int64_t n){ for(int64_t i=0;i<n;i++) b[i]=a[i]<<3; }
void xormask_u32(uint32_t *b, const uint32_t *a, int64_t n){ for(int64_t i=0;i<n;i++) b[i]=a[i]^0x5a5a5a5au; }
";

struct Kern {
    name: &'static str,
    elem_c: &'static str,
    ret_bits: u32,
}

const KERNS: &[Kern] = &[
    Kern {
        name: "sum_i32",
        elem_c: "int32_t",
        ret_bits: 32,
    },
    Kern {
        name: "sum_i64",
        elem_c: "int64_t",
        ret_bits: 64,
    },
    Kern {
        name: "xor_u32",
        elem_c: "uint32_t",
        ret_bits: 32,
    },
    Kern {
        name: "or_u32",
        elem_c: "uint32_t",
        ret_bits: 32,
    },
    Kern {
        name: "sum_i16",
        elem_c: "int16_t",
        ret_bits: 16,
    },
    Kern {
        name: "max_i32",
        elem_c: "int32_t",
        ret_bits: 32,
    },
    Kern {
        name: "min_i32",
        elem_c: "int32_t",
        ret_bits: 32,
    },
];

struct MapKern {
    name: &'static str,
    elem_c: &'static str,
}

const MAPS: &[MapKern] = &[
    MapKern {
        name: "scale2_i32",
        elem_c: "uint32_t",
    },
    MapKern {
        name: "shl3_i32",
        elem_c: "uint32_t",
    },
    MapKern {
        name: "xormask_u32",
        elem_c: "uint32_t",
    },
];

fn scratch_dir() -> PathBuf {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-simd-devirt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn host_cc() -> Option<String> {
    for cc in ["clang", "gcc", "cc"] {
        if Command::new(cc)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
        {
            return Some(cc.to_owned());
        }
    }
    None
}

fn compile_object(cc: &str, dir: &Path, opt: &str) -> Option<Vec<u8>> {
    let src: PathBuf = dir.join("kern.c");
    std::fs::write(&src, KERN_C.as_bytes()).expect("write kern.c");
    let obj: PathBuf = dir.join(format!("kern_{}.o", opt.trim_start_matches('-')));
    let out: std::process::Output = Command::new(cc)
        .args([opt, "-fno-unroll-loops", "-fno-slp-vectorize", "-c", "-o"])
        .arg(&obj)
        .arg(&src)
        .output()
        .expect("invoke cc");
    if !out.status.success() {
        let retry: std::process::Output = Command::new(cc)
            .args([opt, "-fno-unroll-loops", "-c", "-o"])
            .arg(&obj)
            .arg(&src)
            .output()
            .expect("invoke cc retry");
        if !retry.status.success() {
            eprintln!(
                "skip: cc cannot compile kernels: {}",
                String::from_utf8_lossy(&retry.stderr)
            );
            return None;
        }
    }
    Some((std::fs::read(&obj).expect("read object"), obj).0)
}

fn function_code(object_bytes: &[u8], name: &str) -> Option<(Vec<u8>, u64)> {
    let file: object::File<'_> = object::File::parse(object_bytes).ok()?;
    let candidates: [String; 2] = [name.to_owned(), format!("_{name}")];
    let sym: object::Symbol<'_, '_> = file.symbols().find(|s: &object::Symbol<'_, '_>| {
        s.name()
            .is_ok_and(|n: &str| candidates.iter().any(|c: &String| c == n))
    })?;
    let section_index: object::SectionIndex = match sym.section() {
        object::SymbolSection::Section(idx) => idx,
        _ => return None,
    };
    let section: object::Section<'_, '_> = file.section_by_index(section_index).ok()?;
    let data: &[u8] = section.data().ok()?;
    let sym_addr: u64 = sym.address();
    let start: usize = usize::try_from(sym_addr.saturating_sub(section.address())).ok()?;
    let size: usize = usize::try_from(sym.size()).ok()?;
    let end: usize = if size == 0 {
        let next_off: usize = file
            .symbols()
            .filter(|s: &object::Symbol<'_, '_>| {
                matches!(s.section(), object::SymbolSection::Section(idx) if idx == section_index)
                    && s.address() > sym_addr
                    && s.kind() == object::SymbolKind::Text
                    && s.name().is_ok_and(|n: &str| !n.is_empty())
            })
            .filter_map(|s: object::Symbol<'_, '_>| {
                usize::try_from(s.address().saturating_sub(section.address())).ok()
            })
            .min()
            .unwrap_or(data.len());
        next_off.min(data.len())
    } else {
        start.saturating_add(size).min(data.len())
    };
    let slice: &[u8] = data.get(start..end)?;
    Some((slice.to_vec(), sym_addr))
}

fn rename_recovered(source: &str, new_name: &str) -> String {
    source
        .replacen("uint64_t recovered(", &format!("uint64_t {new_name}("), 1)
        .lines()
        .filter(|l: &&str| !l.starts_with("#include"))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn ret_mask(bits: u32) -> String {
    if bits >= 64 {
        "0xFFFFFFFFFFFFFFFFULL".to_owned()
    } else {
        format!("0x{:x}ULL", (1u128 << bits) - 1)
    }
}

fn run_differential(cc: &str, opt: &str) -> bool {
    let dir: PathBuf = scratch_dir();
    let Some(obj): Option<Vec<u8>> = compile_object(cc, &dir, opt) else {
        return false;
    };

    let mut decls: String = String::new();
    let mut checks: String = String::new();
    let mut recovered: usize = 0;

    for kern in KERNS {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&obj, kern.name) else {
            eprintln!("{opt}: symbol {} not located", kern.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_vectorized_reduction(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{opt}: {} sound-rejected ({e})", kern.name);
                continue;
            }
        };
        recovered += 1;
        let rec_name: String = format!("rec_{}", kern.name);
        decls.push_str(&rename_recovered(&recovery.source, &rec_name));
        decls.push('\n');
        decls.push_str(&format!(
            "extern {} {}(const {} *, int64_t);\n",
            if kern.ret_bits >= 64 {
                "int64_t"
            } else {
                "int32_t"
            },
            kern.name,
            kern.elem_c
        ));
        let mask: String = ret_mask(kern.ret_bits);
        checks.push_str(&format!(
            "        {{ unsigned long long want=(unsigned long long){}(({} *)arr,len)&{mask}; \
             unsigned long long got={rec_name}((unsigned long long)(uintptr_t)arr,(unsigned long long)len)&{mask}; \
             if(want!=got){{printf(\"MISMATCH {} opt={opt} len=%lld want=%llu got=%llu\\n\",(long long)len,want,got);return 1;}} }}\n",
            kern.name, kern.elem_c, kern.name
        ));
    }

    for map in MAPS {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&obj, map.name) else {
            eprintln!("{opt}: symbol {} not located", map.name);
            continue;
        };
        let recovery: LeafRecovery = match recover_vectorized_reduction(&code, base, HOST_ABI) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{opt}: {} sound-rejected ({e})", map.name);
                continue;
            }
        };
        recovered += 1;
        let rec_name: String = format!("rec_{}", map.name);
        decls.push_str(&rename_recovered(&recovery.source, &rec_name));
        decls.push('\n');
        decls.push_str(&format!(
            "extern void {}({} *, const {} *, int64_t);\n",
            map.name, map.elem_c, map.elem_c
        ));
        checks.push_str(&format!(
            "        {{ {}((({} *)outa),(const {} *)arr,len); \
             {rec_name}((unsigned long long)(uintptr_t)outb,(unsigned long long)(uintptr_t)arr,(unsigned long long)len); \
             for(long long z=0;z<len;z++) if(((uint32_t *)outa)[z]!=((uint32_t *)outb)[z]){{printf(\"MISMATCH {} opt={opt} len=%lld idx=%lld\\n\",(long long)len,(long long)z);return 1;}} }}\n",
            map.name, map.elem_c, map.elem_c, map.name
        ));
    }

    if recovered == 0 {
        eprintln!("{opt}: no kernel recovered; skipping differential");
        return false;
    }

    let driver: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <stdint.h>\n{decls}\n\
         int main(void){{\n\
         \x20   static int64_t raw[300];\n\
         \x20   static uint32_t outa[400];\n\
         \x20   static uint32_t outb[400];\n\
         \x20   for(int i=0;i<300;i++){{ uint64_t v=(uint64_t)i*2654435761ull; v^=v>>17; v*=0x9E3779B1ull; raw[i]=(int64_t)(v ^ ((uint64_t)i<<40)); }}\n\
         \x20   void *arr=(void *)raw;\n\
         \x20   long long lens[]={{0,1,2,3,4,5,6,7,8,9,10,11,15,16,17,23,31,32,33,48,63,64,65,100,127,128,150}};\n\
         \x20   for(size_t k=0;k<sizeof(lens)/sizeof(lens[0]);k++){{\n\
         \x20       long long len=lens[k];\n\
         {checks}\
         \x20   }}\n\
         \x20   printf(\"OK\\n\");\n\
         \x20   return 0;\n\
         }}\n"
    );
    let driver_c: PathBuf = dir.join(format!("driver_{}.c", opt.trim_start_matches('-')));
    std::fs::write(&driver_c, driver.as_bytes()).expect("write driver");
    let obj_path: PathBuf = dir.join(format!("kern_{}.o", opt.trim_start_matches('-')));
    let exe: PathBuf = dir.join(format!(
        "harness_{}{}",
        opt.trim_start_matches('-'),
        if cfg!(windows) { ".exe" } else { "" }
    ));
    let link: std::process::Output = Command::new(cc)
        .args(["-O1", "-o"])
        .arg(&exe)
        .arg(&driver_c)
        .arg(&obj_path)
        .output()
        .expect("link harness");
    assert!(
        link.status.success(),
        "{opt}: harness link failed: {}\n--- driver ---\n{driver}",
        String::from_utf8_lossy(&link.stderr)
    );
    let run: std::process::Output = Command::new(&exe).output().expect("run harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "{opt}: execute differential FAILED ({recovered} recovered): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    println!("{opt}: execute differential PASSED for {recovered} recovered reductions");
    true
}

#[test]
fn vectorized_integer_reductions_recompile_execute_equivalent() {
    if cfg!(target_os = "macos") {
        eprintln!("skipping: host is arm64 apple-clang, x86-64 codegen/execution unavailable");
        return;
    }
    let Some(cc): Option<String> = host_cc() else {
        eprintln!("skipping: no C compiler on PATH");
        return;
    };
    let mut any: bool = false;
    for opt in ["-O2", "-O3"] {
        any |= run_differential(&cc, opt);
    }
    if !any {
        eprintln!("no optimization level produced a recoverable vectorized kernel; nothing proven");
    }
}

const FP_KERN_C: &str = "float fsum(const float *a, long long n){ float s=0; for(long long i=0;i<n;i++) s+=a[i]; return s; }\n\
     void fscale(float *b, const float *a, long long n){ for(long long i=0;i<n;i++) b[i]=a[i]*2.0f; }\n";

#[test]
fn floating_point_vectorized_loops_sound_reject() {
    if cfg!(target_os = "macos") {
        eprintln!("skipping: host is arm64 apple-clang, x86-64 codegen unavailable");
        return;
    }
    let Some(cc): Option<String> = host_cc() else {
        eprintln!("skipping: no C compiler on PATH");
        return;
    };
    let dir: PathBuf = scratch_dir();
    let src: PathBuf = dir.join("fpkern.c");
    std::fs::write(&src, FP_KERN_C.as_bytes()).expect("write fpkern.c");
    let obj: PathBuf = dir.join("fpkern.o");
    let out: std::process::Output = Command::new(&cc)
        .args(["-O3", "-ffast-math", "-fno-unroll-loops", "-c", "-o"])
        .arg(&obj)
        .arg(&src)
        .output()
        .expect("invoke cc for fp kernels");
    if !out.status.success() {
        eprintln!(
            "skip: cc cannot compile fp kernels: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let obj_bytes: Vec<u8> = std::fs::read(&obj).expect("read fp object");
    let mut checked: usize = 0;
    for name in ["fsum", "fscale"] {
        let Some((code, base)): Option<(Vec<u8>, u64)> = function_code(&obj_bytes, name) else {
            continue;
        };
        checked += 1;
        assert!(
            recover_vectorized_reduction(&code, base, HOST_ABI).is_err(),
            "{name}: floating-point reduction must sound-reject (reassociation makes it non-bit-equal), but the engine emitted a recovery"
        );
        eprintln!("{name}: floating-point vectorized loop sound-rejected as required");
    }
    assert!(checked > 0, "no fp kernel located; nothing proven");
}
