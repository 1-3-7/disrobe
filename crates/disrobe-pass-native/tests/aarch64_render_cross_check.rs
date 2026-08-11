#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use disrobe_pass_native::{LeafRecovery, PseudoScalarType as ScalarType, recover_aarch64_function};

#[path = "aarch64_grade/battery.rs"]
mod battery;

use battery::{
    CASES, FP_DRIVER_HELPERS, FpExpectation, ORACLE_FLAGS, cc, fp_expectation, run_with_watchdog,
};

const RUST_EDITION: &str = "2021";
const CROSS_ITERATIONS: usize = 600;
const fn shared_object_name() -> &'static str {
    if cfg!(windows) {
        "a64_cross_rust.dll"
    } else if cfg!(target_os = "macos") {
        "liba64_cross_rust.dylib"
    } else {
        "liba64_cross_rust.so"
    }
}

struct CrossCase {
    opt: &'static str,
    name: &'static str,
    c_symbol: String,
    rust_symbol: String,
    c_source: String,
    rust_source: String,
    params: Vec<ScalarType>,
    returns: Option<ScalarType>,
    return_width_bits: u32,
    seed: u64,
}

const fn scalar_c_type(ty: ScalarType) -> &'static str {
    match ty {
        ScalarType::Half => "uint16_t",
        ScalarType::Float => "float",
        ScalarType::Double => "double",
        ScalarType::Int => "uint64_t",
    }
}

const fn scalar_recovered_c_type(ty: ScalarType) -> &'static str {
    match ty {
        ScalarType::Half => "_Float16",
        ScalarType::Float => "float",
        ScalarType::Double => "double",
        ScalarType::Int => "uint64_t",
    }
}

const fn scalar_rust_type(ty: ScalarType) -> &'static str {
    match ty {
        ScalarType::Half => "u16",
        ScalarType::Float => "f32",
        ScalarType::Double => "f64",
        ScalarType::Int => "u64",
    }
}

fn rename_c_function(source: &str, symbol: &str) -> String {
    source.replacen("recovered(", &format!("{symbol}("), 1)
}

impl CrossCase {
    fn declarations(&self) -> String {
        let rust_params: String = if self.params.is_empty() {
            "void".to_owned()
        } else {
            self.params
                .iter()
                .map(|ty: &ScalarType| scalar_c_type(*ty).to_owned())
                .collect::<Vec<String>>()
                .join(", ")
        };
        let c_params: String = if self.params.is_empty() {
            "void".to_owned()
        } else {
            self.params
                .iter()
                .map(|ty: &ScalarType| scalar_recovered_c_type(*ty).to_owned())
                .collect::<Vec<String>>()
                .join(", ")
        };
        let rust_ret: &str = match self.returns {
            Some(ty) => scalar_c_type(ty),
            None if self.return_width_bits == 64 => "uint64_t",
            None => "uint64_t",
        };
        let c_ret: &str = self.returns.map_or("uint64_t", scalar_recovered_c_type);
        format!(
            "extern {c_ret} {}({c_params});\nextern {rust_ret} {}({rust_params});\n",
            self.c_symbol, self.rust_symbol
        )
    }

    fn rust_definition(&self, index: usize) -> String {
        let params: String = self
            .params
            .iter()
            .enumerate()
            .map(|(position, ty): (usize, &ScalarType)| {
                format!("a{position}: {}", scalar_rust_type(*ty))
            })
            .collect::<Vec<String>>()
            .join(", ");
        let args: String = (0..self.params.len())
            .map(|position: usize| format!("a{position}"))
            .collect::<Vec<String>>()
            .join(", ");
        let ret: &str = self.returns.map_or("u64", scalar_rust_type);
        let mut out: String = String::new();
        let _ = writeln!(out, "mod cross_{index} {{");
        out.push_str(&self.rust_source);
        let _ = writeln!(out, "}}");
        let _ = writeln!(out, "#[no_mangle]");
        let _ = writeln!(
            out,
            "pub extern \"C\" fn {}({params}) -> {ret} {{",
            self.rust_symbol
        );
        let _ = writeln!(out, "    cross_{index}::recovered({args})");
        let _ = writeln!(out, "}}");
        out
    }

    fn compare_block(&self) -> String {
        let mut draws: String = String::new();
        let mut c_args: Vec<String> = Vec::new();
        let mut rust_args: Vec<String> = Vec::new();
        for (position, ty) in self.params.iter().enumerate() {
            match ty {
                ScalarType::Half => {
                    let _ = writeln!(
                        draws,
                        "            uint16_t r{position} = cross_f16(&s, it, {position});"
                    );
                    let _ = writeln!(
                        draws,
                        "            _Float16 a{position} = cross_h_from_bits(r{position});"
                    );
                }
                ScalarType::Float => {
                    let _ = writeln!(
                        draws,
                        "            uint32_t r{position} = cross_f32(&s, it, {position});"
                    );
                    let _ = writeln!(
                        draws,
                        "            float a{position} = fp_f_from_bits(r{position});"
                    );
                }
                ScalarType::Double => {
                    let _ = writeln!(
                        draws,
                        "            uint64_t r{position} = cross_f64(&s, it, {position});"
                    );
                    let _ = writeln!(
                        draws,
                        "            double a{position} = fp_d_from_bits(r{position});"
                    );
                }
                ScalarType::Int => {
                    let _ = writeln!(draws, "            uint64_t a{position} = xs(&s);");
                }
            }
            c_args.push(format!("a{position}"));
            rust_args.push(if *ty == ScalarType::Half {
                format!("r{position}")
            } else {
                format!("a{position}")
            });
        }
        let exact_half: bool = self.returns == Some(ScalarType::Half);
        let nan_guard: String = if exact_half {
            String::new()
        } else {
            let terms: Vec<String> = self
                .params
                .iter()
                .enumerate()
                .filter_map(|(position, ty): (usize, &ScalarType)| match ty {
                    ScalarType::Half => Some(format!("cross_isnan16(r{position})")),
                    ScalarType::Float => Some(format!("cross_isnan32(r{position})")),
                    ScalarType::Double => Some(format!("cross_isnan64(r{position})")),
                    ScalarType::Int => None,
                })
                .collect();
            if terms.len() < 2 {
                String::new()
            } else {
                format!("            if (({}) > 1) continue;\n", terms.join(" + "))
            }
        };
        let args: String = c_args.join(", ");
        let rust_args: String = rust_args.join(", ");
        let compare: String = match self.returns {
            Some(ScalarType::Half) => format!(
                "            uint64_t left = (uint64_t)cross_h_to_bits({}({args}));\n\
                 \x20           uint64_t right = (uint64_t){}({rust_args});\n",
                self.c_symbol, self.rust_symbol
            ),
            Some(ScalarType::Float) => format!(
                "            uint64_t left = (uint64_t)fp_f_to_bits({}({args}));\n\
                 \x20           uint64_t right = (uint64_t)fp_f_to_bits({}({rust_args}));\n",
                self.c_symbol, self.rust_symbol
            ),
            Some(ScalarType::Double) => format!(
                "            uint64_t left = fp_d_to_bits({}({args}));\n\
                 \x20           uint64_t right = fp_d_to_bits({}({rust_args}));\n",
                self.c_symbol, self.rust_symbol
            ),
            Some(ScalarType::Int) | None => format!(
                "            uint64_t left = (uint64_t)({}({args}));\n\
                 \x20           uint64_t right = (uint64_t)({}({rust_args}));\n",
                self.c_symbol, self.rust_symbol
            ),
        };
        let mismatch: String = if exact_half {
            format!(
                "if (left != right) {{ printf(\"DIVERGE {} {} it=%d c=%llx rust=%llx\\n\", it, (unsigned long long)left, (unsigned long long)right); ok = 0; break; }}",
                self.opt, self.name
            )
        } else {
            let width: u32 = self.returns.map_or(0, |ty: ScalarType| match ty {
                ScalarType::Half => 16,
                ScalarType::Float => 32,
                ScalarType::Double => 64,
                ScalarType::Int => 0,
            });
            format!(
                "if (left != right) {{ if (cross_both_nan(left, right, {width})) {{ payload++; }} else {{ printf(\"DIVERGE {} {} it=%d c=%llx rust=%llx\\n\", it, (unsigned long long)left, (unsigned long long)right); ok = 0; break; }} }}",
                self.opt, self.name
            )
        };
        format!(
            "    {{\n\
             \x20       uint64_t s = 0x{:x}ULL; int ok = 1;\n\
             \x20       for (int it = 0; it < {CROSS_ITERATIONS}; it++) {{\n\
             {draws}{nan_guard}{compare}\
             \x20           {mismatch}\n\
             \x20       }}\n\
             \x20       if (ok) agreed++; else diverged++;\n\
             \x20   }}\n",
            self.seed
        )
    }
}

const CROSS_HELPERS: &str = r"
static _Float16 cross_h_from_bits(uint16_t bits) {
    _Float16 value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}
static uint16_t cross_h_to_bits(_Float16 value) {
    uint16_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}
static const uint16_t cross_specials16[] = {
    0x0000u, 0x8000u, 0x3c00u, 0xbc00u, 0x4000u, 0xc000u, 0x3800u, 0xb800u,
    0x0001u, 0x8001u, 0x03ffu, 0x0400u, 0x7bffu, 0xfbffu, 0x7c00u, 0xfc00u,
    0x7e00u, 0xfe00u, 0x7c01u, 0xfc01u, 0x6400u, 0xe400u, 0x3555u, 0xb555u
};
static const uint32_t cross_specials32[] = {
    0x00000000u, 0x80000000u, 0x3f800000u, 0xbf800000u, 0x40000000u, 0xc0000000u,
    0x3f000000u, 0xbf000000u, 0x00000001u, 0x80000001u, 0x007fffffu, 0x00800000u,
    0x7f7fffffu, 0xff7fffffu, 0x7f800000u, 0xff800000u, 0x7fc00000u, 0xffc00000u,
    0x7f800001u, 0xff800001u, 0x4b800000u, 0xcb800000u, 0x4f000000u, 0xcf000000u,
    0x5f000000u, 0xdf000000u, 0x40a00000u, 0x41200000u
};
static const uint64_t cross_specials64[] = {
    0x0000000000000000ull, 0x8000000000000000ull, 0x3ff0000000000000ull, 0xbff0000000000000ull,
    0x4000000000000000ull, 0xc000000000000000ull, 0x3fe0000000000000ull, 0xbfe0000000000000ull,
    0x0000000000000001ull, 0x8000000000000001ull, 0x000fffffffffffffull, 0x0010000000000000ull,
    0x7fefffffffffffffull, 0xffefffffffffffffull, 0x7ff0000000000000ull, 0xfff0000000000000ull,
    0x7ff8000000000000ull, 0xfff8000000000000ull, 0x7ff0000000000001ull, 0xfff0000000000001ull,
    0x4330000000000000ull, 0xc330000000000000ull, 0x41e0000000000000ull, 0xc1e0000000000000ull,
    0x43e0000000000000ull, 0xc3e0000000000000ull, 0x4024000000000000ull, 0x4028000000000000ull
};
static int cross_both_nan(uint64_t left, uint64_t right, int bits) {
    if (bits == 64) {
        return ((left & 0x7fffffffffffffffull) > 0x7ff0000000000000ull)
            && ((right & 0x7fffffffffffffffull) > 0x7ff0000000000000ull);
    }
    if (bits == 16) {
        return (((uint16_t)left & 0x7fffu) > 0x7c00u)
            && (((uint16_t)right & 0x7fffu) > 0x7c00u);
    }
    return (((uint32_t)left & 0x7fffffffu) > 0x7f800000u)
        && (((uint32_t)right & 0x7fffffffu) > 0x7f800000u);
}
static int cross_isnan16(uint16_t u) { return (u & 0x7fffu) > 0x7c00u; }
static int cross_isnan32(uint32_t u) { return (u & 0x7fffffffu) > 0x7f800000u; }
static int cross_isnan64(uint64_t u) { return (u & 0x7fffffffffffffffull) > 0x7ff0000000000000ull; }
static uint16_t cross_f16(uint64_t *state, int iteration, int lane) {
    int count = (int)(sizeof(cross_specials16) / sizeof(cross_specials16[0]));
    if (iteration < count) return cross_specials16[(iteration + lane * 7) % count];
    return (uint16_t)xs(state);
}
static uint32_t cross_f32(uint64_t *state, int iteration, int lane) {
    int count = (int)(sizeof(cross_specials32) / sizeof(cross_specials32[0]));
    if (iteration < count) return cross_specials32[(iteration + lane * 7) % count];
    return (uint32_t)xs(state);
}
static uint64_t cross_f64(uint64_t *state, int iteration, int lane) {
    int count = (int)(sizeof(cross_specials64) / sizeof(cross_specials64[0]));
    if (iteration < count) return cross_specials64[(iteration + lane * 7) % count];
    return xs(state);
}
";

fn rustc() -> Option<String> {
    Command::new("rustc")
        .arg("--version")
        .output()
        .is_ok_and(|o: std::process::Output| o.status.success())
        .then(|| "rustc".to_owned())
}

#[test]
#[ignore = "cross-checks the c rendering against the rust rendering; needs a host c compiler and rustc, so it is opt-in via --ignored"]
fn c_and_rust_renderings_agree_bit_for_bit() {
    let Some(compiler): Option<String> = cc() else {
        eprintln!("SKIP cross-check: no host C compiler on PATH");
        return;
    };
    let Some(rust_compiler): Option<String> = rustc() else {
        eprintln!("SKIP cross-check: rustc not on PATH");
        return;
    };

    let mut cases: Vec<CrossCase> = Vec::new();
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
    for (index, (opt, name, bytes)) in CASES.iter().enumerate() {
        let Some(expectation): Option<FpExpectation> = fp_expectation(name) else {
            *skipped
                .entry("not a scalar floating-point descriptor".to_owned())
                .or_default() += 1;
            continue;
        };
        if expectation
            .params
            .iter()
            .any(|ty: &ScalarType| matches!(ty, ScalarType::Int))
        {
            *skipped
                .entry("takes an integer or pointer parameter".to_owned())
                .or_default() += 1;
            continue;
        }
        let Ok(recovery): Result<LeafRecovery, _> = recover_aarch64_function(bytes, 0) else {
            *skipped
                .entry("aarch64 recovery rejected".to_owned())
                .or_default() += 1;
            continue;
        };
        if recovery.signature.parameter_types().as_slice() != expectation.params
            || recovery.returns_fp != expectation.returns
            || recovery.return_width_bits != expectation.return_width_bits
        {
            *skipped
                .entry("fp signature mismatch".to_owned())
                .or_default() += 1;
            continue;
        }
        let Some(rust_source): Option<String> = recovery.rust_source.clone() else {
            *skipped
                .entry("no rust rendering emitted".to_owned())
                .or_default() += 1;
            continue;
        };
        let c_symbol: String = format!("crossc_{opt}_{name}");
        let rust_symbol: String = format!("crossr_{opt}_{name}");
        let seed: u64 = 0x2545_F491_4F6C_DD1Du64
            ^ (index as u64)
                .wrapping_add(1)
                .wrapping_mul(0x0000_0100_0000_01B3);
        cases.push(CrossCase {
            opt,
            name,
            c_source: rename_c_function(&recovery.source, &c_symbol),
            rust_source,
            c_symbol,
            rust_symbol,
            params: expectation.params.to_vec(),
            returns: expectation.returns,
            return_width_bits: expectation.return_width_bits,
            seed: if seed == 0 {
                0xDEAD_BEEF_CAFE_F00D
            } else {
                seed
            },
        });
    }
    let half_cases: [(&str, u32, &[ScalarType]); 5] = [
        ("fadd_h", 0x1ee1_2800, &[ScalarType::Half, ScalarType::Half]),
        ("fdiv_h", 0x1ee1_1800, &[ScalarType::Half, ScalarType::Half]),
        (
            "fmadd_h",
            0x1fc1_0800,
            &[ScalarType::Half, ScalarType::Half, ScalarType::Half],
        ),
        ("fmax_h", 0x1ee1_4800, &[ScalarType::Half, ScalarType::Half]),
        ("fsqrt_h", 0x1ee1_c000, &[ScalarType::Half]),
    ];
    for (index, (name, word, params)) in half_cases.into_iter().enumerate() {
        let mut bytes: Vec<u8> = word.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        let recovery: LeafRecovery =
            recover_aarch64_function(&bytes, 0).expect("binary16 cross-check recovery");
        assert_eq!(recovery.signature.parameter_types(), params);
        assert_eq!(recovery.returns_fp, Some(ScalarType::Half));
        assert_eq!(recovery.return_width_bits, 16);
        let rust_source: String = recovery
            .rust_source
            .clone()
            .expect("binary16 Rust recovery");
        let c_symbol: String = format!("crossc_FP16_{name}");
        let rust_symbol: String = format!("crossr_FP16_{name}");
        cases.push(CrossCase {
            opt: "FP16",
            name,
            c_source: rename_c_function(&recovery.source, &c_symbol),
            rust_source,
            c_symbol,
            rust_symbol,
            params: params.to_vec(),
            returns: Some(ScalarType::Half),
            return_width_bits: 16,
            seed: 0x6A09_E667_F3BC_C909_u64 ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        });
    }
    assert_eq!(
        cases
            .iter()
            .filter(|case: &&CrossCase| case.opt == "FP16")
            .count(),
        half_cases.len()
    );

    assert!(
        !cases.is_empty(),
        "cross-check produced no case with both a c and a rust rendering"
    );

    let dir: tempfile::TempDir = tempfile::tempdir().expect("scratch dir");
    let mut unit: String = "#![allow(unused, dead_code, non_snake_case, non_camel_case_types, unused_mut, unused_parens, unused_assignments, unused_variables)]\n".to_owned();
    for (index, case) in cases.iter().enumerate() {
        unit.push_str(&case.rust_definition(index));
    }
    let unit_path: PathBuf = dir.path().join("a64_cross.rs");
    std::fs::write(&unit_path, unit.as_bytes()).expect("write cross rust unit");
    let shared_object: PathBuf = dir.path().join(shared_object_name());
    let built: std::process::Output = Command::new(&rust_compiler)
        .args([
            "--edition",
            RUST_EDITION,
            "--crate-type=cdylib",
            "-C",
            "overflow-checks=on",
            "-o",
        ])
        .arg(&shared_object)
        .arg(&unit_path)
        .output()
        .expect("invoke rustc for the cross-check unit");
    assert!(
        built.status.success(),
        "rustc rejected the cross-check unit: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let mut decls: String = String::new();
    let mut blocks: String = String::new();
    for case in &cases {
        decls.push_str(&case.declarations());
        blocks.push_str(&case.compare_block());
    }
    let driver: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         static uint64_t xs(uint64_t *st) {{ uint64_t x = *st; x ^= x << 13; x ^= x >> 7; x ^= x << 17; *st = x; return x; }}\n\
         {FP_DRIVER_HELPERS}\n\
         {CROSS_HELPERS}\n\
         static long long agreed = 0;\n\
         static long long diverged = 0;\n\
         static long long payload = 0;\n\
         {decls}\n\
         int main(void) {{\n\
         {blocks}\
         \x20   printf(\"CROSSDONE agreed=%lld diverged=%lld payload=%lld\\n\", agreed, diverged, payload);\n\
         \x20   fflush(stdout);\n\
         \x20   return 0;\n\
         }}\n"
    );
    let driver_c: PathBuf = dir.path().join("a64_cross_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write cross driver");
    let harness: PathBuf = dir
        .path()
        .join(if cfg!(windows) { "cross.exe" } else { "cross" });
    let mut objects: Vec<PathBuf> = Vec::with_capacity(cases.len());
    for (index, case) in cases.iter().enumerate() {
        let source: PathBuf = dir.path().join(format!("cross_{index}.c"));
        let object: PathBuf = dir.path().join(format!("cross_{index}.o"));
        let source_text: &str = &case.c_source;
        std::fs::write(&source, source_text.as_bytes()).expect("write recovered C unit");
        let compiled: std::process::Output = Command::new(&compiler)
            .args(ORACLE_FLAGS)
            .arg("-c")
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .expect("compile recovered C unit");
        assert!(
            compiled.status.success(),
            "recovered C case {} {} failed to compile: {}",
            case.opt,
            case.name,
            String::from_utf8_lossy(&compiled.stderr)
        );
        objects.push(object);
    }
    let rpath: String = format!("-Wl,-rpath,{}", dir.path().to_string_lossy());
    let mut link: Command = Command::new(&compiler);
    link.args(ORACLE_FLAGS).arg("-o").arg(&harness);
    if !cfg!(windows) {
        link.arg(&rpath);
    }
    let object_response: PathBuf = dir.path().join("cross_objects.rsp");
    let mut object_arguments: String = String::new();
    for object in &objects {
        let object_path: String = object.to_string_lossy().replace('\\', "/");
        writeln!(object_arguments, "\"{object_path}\"").expect("format object response");
    }
    std::fs::write(&object_response, object_arguments.as_bytes()).expect("write object response");
    let object_response_argument: String = format!("@{}", object_response.to_string_lossy());
    let linked: std::process::Output = link
        .arg(&driver_c)
        .arg(&object_response_argument)
        .arg(&shared_object)
        .output()
        .expect("invoke cc to link the cross-check harness");
    assert!(
        linked.status.success(),
        "cross-check harness failed to compile/link ({} cases): {}",
        cases.len(),
        String::from_utf8_lossy(&linked.stderr)
    );

    let Some(output): Option<std::process::Output> =
        run_with_watchdog(&harness, Duration::from_mins(5))
    else {
        panic!("cross-check harness exceeded its watchdog window");
    };
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut agreed: i64 = -1;
    let mut diverged: i64 = -1;
    let mut payload: i64 = -1;
    let mut detail: Vec<String> = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("CROSSDONE ") {
            for token in rest.split_whitespace() {
                if let Some(value) = token.strip_prefix("agreed=") {
                    agreed = value.parse().unwrap_or(-1);
                } else if let Some(value) = token.strip_prefix("diverged=") {
                    diverged = value.parse().unwrap_or(-1);
                } else if let Some(value) = token.strip_prefix("payload=") {
                    payload = value.parse().unwrap_or(-1);
                }
            }
        } else if line.starts_with("DIVERGE ") {
            detail.push(line.to_owned());
        }
    }

    eprintln!("========= AARCH64 C VERSUS RUST RENDERING CROSS-CHECK =========");
    eprintln!("paired renderings    {}", cases.len());
    eprintln!("agreed               {agreed}");
    eprintln!("diverged             {diverged}");
    eprintln!(
        "nan-payload-only     {payload}   (both renderings answered a nan; ieee-754 leaves which nan a bare arithmetic operator propagates to the implementation)"
    );
    for line in &detail {
        eprintln!("  {line}");
    }
    if !skipped.is_empty() {
        eprintln!("---- not paired ----");
        for (reason, count) in &skipped {
            eprintln!("  {count}x  {reason}");
        }
    }
    eprintln!("==============================================================");

    assert_eq!(
        i64::try_from(cases.len()).unwrap_or(-1),
        agreed.saturating_add(diverged),
        "every paired rendering must be accounted for"
    );
    assert_eq!(
        diverged, 0,
        "the c and rust renderings lower the same machine code independently; any disagreement is an unfaithful lowering in one of them"
    );
}
