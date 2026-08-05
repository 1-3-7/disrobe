#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    EvalOutcome, ObservedValue, Terminal, TraceEvent, eval_capture, eval_outcome,
    eval_outcome_bare, try_eval_outcome_with_argv,
};
use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, wait_with_output_timeout};
use disrobe_pass_js_deob::{
    DeobOptions, DeobOutput, Detection, JsObfuscator, OBFUSCATOR_IO_MAX_PASS_CEILING,
    ObfuscatorIoControl, ObfuscatorIoOptions, ObfuscatorIoOutput, deobfuscate_all, detect,
    obfuscator_io_deobfuscate,
};

const DIFFERENTIAL_FLOOR: usize = 37;
const SAMPLE_COUNT: usize = 41;
const EVAL_TIMEOUT: Duration = Duration::from_secs(12);
const HIGH_CLEAN: &str = "src/javascript/obfuscator-io-high.js";
const REQUESTED_ROOTS: &[&str] = &["js/javascript-obfuscator", "js/jsconfuser"];
const WORKER_REQUEST_ENV: &str = "DISROBE_JS_BOA_ORACLE_REQUEST";
const WORKER_RESPONSE_ENV: &str = "DISROBE_JS_BOA_ORACLE_RESPONSE";
const WORKER_CAPTURE_LIMIT: usize = 256 * 1024;
const WORKER_RESPONSE_LIMIT: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RewriterFamily {
    StringArrayDecode,
    LiteralEncoding,
    ProxyObjectInlining,
    ControlFlowFlattening,
    OpaquePredicates,
    SelfDefendingStrip,
}

const NAMED_FAMILIES: &[RewriterFamily] = &[
    RewriterFamily::ProxyObjectInlining,
    RewriterFamily::ControlFlowFlattening,
    RewriterFamily::SelfDefendingStrip,
];

const ALL_FAMILIES: &[RewriterFamily] = &[
    RewriterFamily::StringArrayDecode,
    RewriterFamily::LiteralEncoding,
    RewriterFamily::ProxyObjectInlining,
    RewriterFamily::ControlFlowFlattening,
    RewriterFamily::OpaquePredicates,
    RewriterFamily::SelfDefendingStrip,
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RewriteActivity {
    string_array_call_sites_inlined: u64,
    unminify_literal_folds: u64,
    arithmetic_folded: u64,
    string_conceal_call_sites_decoded: u64,
    string_compression_blocks_reversed: u64,
    control_flow_objects_merged: u64,
    dispatcher_calls_inlined: u64,
    calculator_calls_inlined: u64,
    variable_masking_proxies_eliminated: u64,
    control_flow_switches_unflattened: u64,
    flatten_dispatches_collapsed: u64,
    state_sum_machines_linearized: u64,
    unminify_control_flow: u64,
    opaque_predicates_folded: u64,
    unminify_protection: u64,
    integrity_loops_stripped: u64,
    lock_guards_stripped: u64,
}

impl RewriteActivity {
    const fn merge(&mut self, other: &Self) {
        self.string_array_call_sites_inlined = self
            .string_array_call_sites_inlined
            .saturating_add(other.string_array_call_sites_inlined);
        self.unminify_literal_folds = self
            .unminify_literal_folds
            .saturating_add(other.unminify_literal_folds);
        self.arithmetic_folded = self
            .arithmetic_folded
            .saturating_add(other.arithmetic_folded);
        self.string_conceal_call_sites_decoded = self
            .string_conceal_call_sites_decoded
            .saturating_add(other.string_conceal_call_sites_decoded);
        self.string_compression_blocks_reversed = self
            .string_compression_blocks_reversed
            .saturating_add(other.string_compression_blocks_reversed);
        self.control_flow_objects_merged = self
            .control_flow_objects_merged
            .saturating_add(other.control_flow_objects_merged);
        self.dispatcher_calls_inlined = self
            .dispatcher_calls_inlined
            .saturating_add(other.dispatcher_calls_inlined);
        self.calculator_calls_inlined = self
            .calculator_calls_inlined
            .saturating_add(other.calculator_calls_inlined);
        self.variable_masking_proxies_eliminated = self
            .variable_masking_proxies_eliminated
            .saturating_add(other.variable_masking_proxies_eliminated);
        self.control_flow_switches_unflattened = self
            .control_flow_switches_unflattened
            .saturating_add(other.control_flow_switches_unflattened);
        self.flatten_dispatches_collapsed = self
            .flatten_dispatches_collapsed
            .saturating_add(other.flatten_dispatches_collapsed);
        self.state_sum_machines_linearized = self
            .state_sum_machines_linearized
            .saturating_add(other.state_sum_machines_linearized);
        self.unminify_control_flow = self
            .unminify_control_flow
            .saturating_add(other.unminify_control_flow);
        self.opaque_predicates_folded = self
            .opaque_predicates_folded
            .saturating_add(other.opaque_predicates_folded);
        self.unminify_protection = self
            .unminify_protection
            .saturating_add(other.unminify_protection);
        self.integrity_loops_stripped = self
            .integrity_loops_stripped
            .saturating_add(other.integrity_loops_stripped);
        self.lock_guards_stripped = self
            .lock_guards_stripped
            .saturating_add(other.lock_guards_stripped);
    }

    fn families(&self) -> BTreeSet<RewriterFamily> {
        REGEX_REWRITERS
            .iter()
            .filter_map(|rewriter: &RegexRewriter| {
                let (family, probe): (RewriterFamily, ActivityProbe) =
                    rewriter.coverage.graded()?;
                (probe(self) != 0).then_some(family)
            })
            .collect()
    }
}

const fn activity_from_obfuscator_io(out: &ObfuscatorIoOutput) -> RewriteActivity {
    let stats: &disrobe_pass_js_deob::UnminifyStats = &out.unminify_stats;
    RewriteActivity {
        string_array_call_sites_inlined: out.string_array_call_sites_inlined as u64,
        unminify_literal_folds: (stats.bool_shorthand_reversed
            + stats.void_undefined_reversed
            + stats.double_not_reversed
            + stats.merged_string_concat
            + stats.string_split_literals_merged
            + stats.radix_literals_decimalized) as u64,
        arithmetic_folded: stats.arithmetic_folded as u64,
        string_conceal_call_sites_decoded: 0,
        string_compression_blocks_reversed: 0,
        control_flow_objects_merged: (out.control_flow_objects_merged
            + out.scope_proxy_objects_merged) as u64,
        dispatcher_calls_inlined: out.dispatcher_call_sites_inlined as u64,
        calculator_calls_inlined: 0,
        variable_masking_proxies_eliminated: 0,
        control_flow_switches_unflattened: out.control_flow_switches_unflattened as u64,
        flatten_dispatches_collapsed: out.flatten_dispatches_collapsed as u64,
        state_sum_machines_linearized: 0,
        unminify_control_flow: (stats.control_flow_blocks_unflattened
            + stats.control_flow_cases_inlined) as u64,
        opaque_predicates_folded: out.opaque_predicates_folded as u64,
        unminify_protection: (stats.debugger_loops_removed
            + stats.set_interval_watchdogs_removed
            + stats.function_debugger_removed
            + stats.self_defending_iifes_removed
            + stats.self_defending_checkers_removed
            + stats.self_defending_wrappers_removed
            + stats.debug_protection_ratchets_removed
            + stats.debug_ratchet_functions_removed) as u64,
        integrity_loops_stripped: 0,
        lock_guards_stripped: 0,
    }
}

const fn activity_from_jsconfuser(out: &DeobOutput) -> RewriteActivity {
    RewriteActivity {
        string_array_call_sites_inlined: 0,
        unminify_literal_folds: out.string_literals_decoded as u64,
        arithmetic_folded: 0,
        string_conceal_call_sites_decoded: out.string_conceal_call_sites_decoded as u64,
        string_compression_blocks_reversed: out.string_compression_blocks_reversed as u64,
        control_flow_objects_merged: 0,
        dispatcher_calls_inlined: out.dispatcher_calls_inlined as u64,
        calculator_calls_inlined: out.calculator_calls_inlined as u64,
        variable_masking_proxies_eliminated: out.variable_masking_proxies_eliminated as u64,
        control_flow_switches_unflattened: 0,
        flatten_dispatches_collapsed: (out.flatten_dispatches_collapsed
            + out.cff_generators_devirtualized) as u64,
        state_sum_machines_linearized: out.state_sum_machines_linearized as u64,
        unminify_control_flow: 0,
        opaque_predicates_folded: out.opaque_predicates_folded as u64,
        unminify_protection: 0,
        integrity_loops_stripped: (out.integrity_loops_stripped
            + out.integrity_self_checks_unwrapped) as u64,
        lock_guards_stripped: out.lock_guards_stripped as u64,
    }
}

type ActivityProbe = fn(&RewriteActivity) -> u64;

#[derive(Debug, Clone, Copy)]
enum Coverage {
    Corpus {
        family: RewriterFamily,
        probe: ActivityProbe,
    },
    Witness {
        family: RewriterFamily,
        probe: ActivityProbe,
    },
    Ungraded(&'static str),
}

impl Coverage {
    const fn graded(&self) -> Option<(RewriterFamily, ActivityProbe)> {
        match *self {
            Self::Corpus { family, probe } | Self::Witness { family, probe } => {
                Some((family, probe))
            }
            Self::Ungraded(_) => None,
        }
    }
}

#[derive(Debug)]
struct RegexRewriter {
    module: &'static str,
    coverage: Coverage,
}

const REASON_BUNDLE: &str = "bundle graph recovery rewrites module wrappers rather than obfuscated \
                             program text, and is graded by the bundler round-trip suites";
const REASON_DETECT: &str = "detection only; the module classifies input and rewrites no source";
const REASON_JSCRAMBLER: &str = "the Jscrambler chain is graded against real Jscrambler 8.5 output \
                                 by tests/jscrambler_template_all.rs";
const REASON_ESOTERIC: &str =
    "esoteric encodings are graded by tests/esoteric_recovery_graded.rs and its siblings";
const REASON_TYPESCRIPT: &str =
    "TypeScript and Closure recovery is graded by tests/ts_type_recover.rs and its siblings";
const REASON_PROTECTOR: &str =
    "commercial protector recovery is graded by tests/protectors_chain.rs and its siblings";
const REASON_JSOBFU: &str = "the jsobfu chain is graded by tests/real_jsobfu_recovery_oracle.rs";

static REGEX_REWRITERS: &[RegexRewriter] = &[
    RegexRewriter {
        module: "src/bundle/amd.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/browserify.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/bun.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/esbuild.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/parcel.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/require_rewrite.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/rolldown.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/rollup.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/systemjs.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/turbopack.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/vite.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/webpack4.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/bundle/webpack5.rs",
        coverage: Coverage::Ungraded(REASON_BUNDLE),
    },
    RegexRewriter {
        module: "src/detect.rs",
        coverage: Coverage::Ungraded(REASON_DETECT),
    },
    RegexRewriter {
        module: "src/esoteric/atob_indirection.rs",
        coverage: Coverage::Ungraded(REASON_ESOTERIC),
    },
    RegexRewriter {
        module: "src/esoteric/eval_indirection.rs",
        coverage: Coverage::Ungraded(REASON_ESOTERIC),
    },
    RegexRewriter {
        module: "src/esoteric/packer.rs",
        coverage: Coverage::Ungraded(REASON_ESOTERIC),
    },
    RegexRewriter {
        module: "src/jsconfuser/calculator.rs",
        coverage: Coverage::Ungraded(
            "calculator inlining is graded by tests/jsconfuser_calculator.rs; no requested corpus sample carries the shape",
        ),
    },
    RegexRewriter {
        module: "src/jsconfuser/dispatcher.rs",
        coverage: Coverage::Ungraded(
            "dispatcher inlining is graded by tests/jsconfuser_dispatcher.rs; no requested corpus sample carries the shape",
        ),
    },
    RegexRewriter {
        module: "src/jsconfuser/flatten.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::ControlFlowFlattening,
            probe: |activity: &RewriteActivity| activity.flatten_dispatches_collapsed,
        },
    },
    RegexRewriter {
        module: "src/jsconfuser/integrity.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::SelfDefendingStrip,
            probe: |activity: &RewriteActivity| activity.integrity_loops_stripped,
        },
    },
    RegexRewriter {
        module: "src/jsconfuser/lock.rs",
        coverage: Coverage::Ungraded(
            "environment locks are graded by tests/jsconfuser_lock.rs; no requested corpus sample carries the shape",
        ),
    },
    RegexRewriter {
        module: "src/jsconfuser/moved_declarations.rs",
        coverage: Coverage::Ungraded(
            "declaration hoisting is graded by tests/jsconfuser_moved_decls.rs",
        ),
    },
    RegexRewriter {
        module: "src/jsconfuser/opaque.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::OpaquePredicates,
            probe: |activity: &RewriteActivity| activity.opaque_predicates_folded,
        },
    },
    RegexRewriter {
        module: "src/jsconfuser/packing.rs",
        coverage: Coverage::Ungraded(
            "packed-block expansion is graded by tests/jsconfuser_packing.rs",
        ),
    },
    RegexRewriter {
        module: "src/jsconfuser/rgf.rs",
        coverage: Coverage::Ungraded(
            "runtime-generated functions are graded by tests/jsconfuser_rgf.rs",
        ),
    },
    RegexRewriter {
        module: "src/jsconfuser/rgf_eval.rs",
        coverage: Coverage::Ungraded(
            "runtime-generated eval wrappers are graded by tests/jsconfuser_rgf.rs",
        ),
    },
    RegexRewriter {
        module: "src/jsconfuser/shuffle.rs",
        coverage: Coverage::Ungraded("array shuffling is graded by tests/jsconfuser_shuffle.rs"),
    },
    RegexRewriter {
        module: "src/jsconfuser/state_sum.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::ControlFlowFlattening,
            probe: |activity: &RewriteActivity| activity.state_sum_machines_linearized,
        },
    },
    RegexRewriter {
        module: "src/jsconfuser/string_compression.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::LiteralEncoding,
            probe: |activity: &RewriteActivity| activity.string_compression_blocks_reversed,
        },
    },
    RegexRewriter {
        module: "src/jsconfuser/string_conceal.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::LiteralEncoding,
            probe: |activity: &RewriteActivity| activity.string_conceal_call_sites_decoded,
        },
    },
    RegexRewriter {
        module: "src/jsconfuser/variable_masking.rs",
        coverage: Coverage::Ungraded(
            "variable masking is graded by tests/jsconfuser_variable_masking.rs; no requested corpus sample carries the shape",
        ),
    },
    RegexRewriter {
        module: "src/jscrambler/detect.rs",
        coverage: Coverage::Ungraded(REASON_DETECT),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/anti_debugging.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/anti_monkey_patching.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/anti_tampering.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/boolean_to_anything.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/browser_lock.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/char_to_ternary.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/constant_folding.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/control_flow_flattening.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/date_lock.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/dead_code_injection.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/dead_objects.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/domain_lock.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/duplicate_literals_removal.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/extend_predicates.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/global_variable_indirection.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/identifiers_renaming.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/number_to_string.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/os_lock.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/self_defending.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/self_healing.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/string_concealing.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jscrambler/transforms/variable_masking.rs",
        coverage: Coverage::Ungraded(REASON_JSCRAMBLER),
    },
    RegexRewriter {
        module: "src/jsobfu/detect.rs",
        coverage: Coverage::Ungraded(REASON_DETECT),
    },
    RegexRewriter {
        module: "src/jsobfu/rewrite.rs",
        coverage: Coverage::Ungraded(REASON_JSOBFU),
    },
    RegexRewriter {
        module: "src/obfuscator_io/control_flow_object.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::ProxyObjectInlining,
            probe: |activity: &RewriteActivity| activity.control_flow_objects_merged,
        },
    },
    RegexRewriter {
        module: "src/obfuscator_io/control_flow_switch.rs",
        coverage: Coverage::Witness {
            family: RewriterFamily::ControlFlowFlattening,
            probe: |activity: &RewriteActivity| activity.control_flow_switches_unflattened,
        },
    },
    RegexRewriter {
        module: "src/obfuscator_io/detection.rs",
        coverage: Coverage::Ungraded(REASON_DETECT),
    },
    RegexRewriter {
        module: "src/protectors/arxan.rs",
        coverage: Coverage::Ungraded(REASON_PROTECTOR),
    },
    RegexRewriter {
        module: "src/protectors/jsdefender.rs",
        coverage: Coverage::Ungraded(REASON_PROTECTOR),
    },
    RegexRewriter {
        module: "src/protectors/pace.rs",
        coverage: Coverage::Ungraded(REASON_PROTECTOR),
    },
    RegexRewriter {
        module: "src/rename/hex_idents.rs",
        coverage: Coverage::Ungraded(
            "hexadecimal identifier renaming is graded by tests/obfuscator_io_differential_oracle.rs \
             against the clean source's identifier set",
        ),
    },
    RegexRewriter {
        module: "src/rename/scope_aware.rs",
        coverage: Coverage::Ungraded(
            "scope-aware renaming is graded by tests/mangled_usage_context_oracle.rs",
        ),
    },
    RegexRewriter {
        module: "src/string_array/detect.rs",
        coverage: Coverage::Ungraded(REASON_DETECT),
    },
    RegexRewriter {
        module: "src/string_array/inline.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::StringArrayDecode,
            probe: |activity: &RewriteActivity| activity.string_array_call_sites_inlined,
        },
    },
    RegexRewriter {
        module: "src/string_array/modern.rs",
        coverage: Coverage::Ungraded(
            "modern string-array shapes are graded by tests/obfuscator_io_modern_string_array.rs",
        ),
    },
    RegexRewriter {
        module: "src/typescript/closure_advanced.rs",
        coverage: Coverage::Ungraded(REASON_TYPESCRIPT),
    },
    RegexRewriter {
        module: "src/typescript/dts_reverse.rs",
        coverage: Coverage::Ungraded(REASON_TYPESCRIPT),
    },
    RegexRewriter {
        module: "src/unminify/arithmetic.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::LiteralEncoding,
            probe: |activity: &RewriteActivity| activity.arithmetic_folded,
        },
    },
    RegexRewriter {
        module: "src/unminify/control_flow.rs",
        coverage: Coverage::Ungraded(
            "minifier control-flow unflattening is graded by tests/full_pipeline.rs; no requested corpus sample carries the shape",
        ),
    },
    RegexRewriter {
        module: "src/unminify/globals.rs",
        coverage: Coverage::Ungraded(
            "global-call evaluation is graded by tests/full_pipeline.rs against decoded output",
        ),
    },
    RegexRewriter {
        module: "src/unminify/peepholes.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::LiteralEncoding,
            probe: |activity: &RewriteActivity| activity.unminify_literal_folds,
        },
    },
    RegexRewriter {
        module: "src/unminify/protection.rs",
        coverage: Coverage::Corpus {
            family: RewriterFamily::SelfDefendingStrip,
            probe: |activity: &RewriteActivity| activity.unminify_protection,
        },
    },
];

const REGEX_CONSTRUCTORS: &[&str] = &["Regex::new(", "RegexBuilder::new("];

fn crate_source_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn discover_regex_rewriter_modules() -> Result<BTreeSet<String>, String> {
    let root: PathBuf = crate_source_root();
    let mut discovered: BTreeSet<String> = BTreeSet::new();
    let mut pending: Vec<PathBuf> = vec![root.clone()];
    while let Some(directory) = pending.pop() {
        let entries: fs::ReadDir = fs::read_dir(&directory)
            .map_err(|error: std::io::Error| format!("{}: {error}", directory.display()))?;
        for entry_result in entries {
            let entry: fs::DirEntry = entry_result
                .map_err(|error: std::io::Error| format!("{}: {error}", directory.display()))?;
            let path: PathBuf = entry.path();
            let file_type: fs::FileType = entry
                .file_type()
                .map_err(|error: std::io::Error| format!("{}: {error}", path.display()))?;
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file()
                || path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs")
            {
                continue;
            }
            let body: String = fs::read_to_string(&path)
                .map_err(|error: std::io::Error| format!("{}: {error}", path.display()))?;
            if !REGEX_CONSTRUCTORS
                .iter()
                .any(|marker: &&str| body.contains(*marker))
            {
                continue;
            }
            let relative: &Path =
                path.strip_prefix(&root)
                    .map_err(|error: std::path::StripPrefixError| {
                        format!("{}: {error}", path.display())
                    })?;
            let normalized: String = normalize_corpus_relative(relative)?;
            discovered.insert(format!("src/{normalized}"));
        }
    }
    Ok(discovered)
}

#[derive(Clone, Copy)]
enum Reference {
    Clean(&'static str),
    Obfuscated,
}

struct Sample {
    name: &'static str,
    obf: &'static str,
    reference: Reference,
    argv_battery: &'static [&'static [&'static str]],
}

const NO_ARGS: &[&[&str]] = &[&[]];
const CLASSIFY_BATTERY: &[&[&str]] = &[
    &["150"],
    &["101"],
    &["100"],
    &["50"],
    &["11"],
    &["10"],
    &["5"],
    &["0"],
];
const INTEGRITY_BATTERY: &[&[&str]] = &[
    &["2", "3"],
    &["10", "20"],
    &["0", "0"],
    &["-5", "7"],
    &["7", "6"],
];
const RUNTIME_BATTERY: &[&[&str]] = &[
    &["10"],
    &["100"],
    &["0"],
    &["-7"],
    &["42"],
    &["1"],
    &["999"],
];
const STRINGS_BATTERY: &[&[&str]] = &[&["world"], &["planet"], &["sun"], &["a"]];
const LOOP_BATTERY: &[&[&str]] = &[
    &["10"],
    &["1"],
    &["0"],
    &["7"],
    &["100"],
    &["3"],
    &["25"],
    &["50"],
];

const SAMPLES: &[Sample] = &[
    Sample {
        name: "javascript-obfuscator/gauntlet",
        obf: "js/javascript-obfuscator/gauntlet-obfuscated.js",
        reference: Reference::Clean("js/javascript-obfuscator/gauntlet-source.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/gauntlet",
        obf: "js/jsconfuser/gauntlet-obfuscated.js",
        reference: Reference::Clean("js/jsconfuser/gauntlet-source.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/megafile-low",
        obf: "js/jsconfuser/obfuscated.megafile.low.js",
        reference: Reference::Clean("js/jsconfuser/edge_cases.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/megafile-medium",
        obf: "js/jsconfuser/obfuscated.megafile.medium.js",
        reference: Reference::Clean("js/jsconfuser/edge_cases.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/megafile-high",
        obf: "js/jsconfuser/obfuscated.megafile.high.js",
        reference: Reference::Clean("js/jsconfuser/edge_cases.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/string-conceal",
        obf: "js/jsconfuser/recovery/obf_checksum.stringconceal.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_checksum.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/string-compression",
        obf: "js/jsconfuser/recovery/obf_stringcompression.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_stringcompression.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/rgf-eval",
        obf: "js/jsconfuser/recovery/obf_tokenizer.rgf.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_tokenizer.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/statesum-real",
        obf: "js/jsconfuser/recovery/obf_statesum.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_statesum.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/statesum-spec",
        obf: "js/jsconfuser/recovery/obf_statesum.spec.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_statesum.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "jsconfuser/deadcode",
        obf: "js/jsconfuser/recovery/obf_deadcode.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_deadcode.js"),
        argv_battery: CLASSIFY_BATTERY,
    },
    Sample {
        name: "jsconfuser/deadcode-cff",
        obf: "js/jsconfuser/recovery/obf_deadcode_cff.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_deadcode.js"),
        argv_battery: CLASSIFY_BATTERY,
    },
    Sample {
        name: "jsconfuser/integrity",
        obf: "js/jsconfuser/recovery/obf_integrity.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_integrity.js"),
        argv_battery: INTEGRITY_BATTERY,
    },
    Sample {
        name: "jsconfuser/statesum-runtime",
        obf: "js/jsconfuser/recovery/obf_statesum_runtime.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_statesum_runtime.js"),
        argv_battery: RUNTIME_BATTERY,
    },
    Sample {
        name: "jsconfuser/statesum-branch",
        obf: "js/jsconfuser/recovery/obf_statesum_branch.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_statesum_branch.js"),
        argv_battery: CLASSIFY_BATTERY,
    },
    Sample {
        name: "jsconfuser/statesum-strings",
        obf: "js/jsconfuser/recovery/obf_statesum_strings.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_statesum_strings.js"),
        argv_battery: STRINGS_BATTERY,
    },
    Sample {
        name: "jsconfuser/statesum-loop",
        obf: "js/jsconfuser/recovery/obf_statesum_loop.real.js",
        reference: Reference::Clean("js/jsconfuser/recovery/src_statesum_loop.js"),
        argv_battery: LOOP_BATTERY,
    },
    Sample {
        name: "javascript-obfuscator/browser-cff",
        obf: "js/javascript-obfuscator/browser/obf_cff.js",
        reference: Reference::Clean("js/javascript-obfuscator/browser/source.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "javascript-obfuscator/browser-base64",
        obf: "js/javascript-obfuscator/browser/obf_base64.js",
        reference: Reference::Clean("js/javascript-obfuscator/browser/source.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/hello",
        obf: "js/javascript-obfuscator/obfuscated.js",
        reference: Reference::Clean("js/javascript-obfuscator/hello.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "javascript-obfuscator/megafile",
        obf: "js/javascript-obfuscator/obfuscated.megafile.js",
        reference: Reference::Clean("js/javascript-obfuscator/edge_cases.js"),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/preset/low",
        obf: "src/javascript/obfuscator-io-samples/presets/low.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/preset/medium",
        obf: "src/javascript/obfuscator-io-samples/presets/medium.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/preset/high",
        obf: "src/javascript/obfuscator-io-samples/presets/high.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/booleans",
        obf: "src/javascript/obfuscator-io-samples/controls/booleans.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/compact",
        obf: "src/javascript/obfuscator-io-samples/controls/compact.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/controlFlowFlattening",
        obf: "src/javascript/obfuscator-io-samples/controls/controlFlowFlattening.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/deadCodeInjection",
        obf: "src/javascript/obfuscator-io-samples/controls/deadCodeInjection.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/debugProtection",
        obf: "src/javascript/obfuscator-io-samples/controls/debugProtection.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/identifiersHexadecimal",
        obf: "src/javascript/obfuscator-io-samples/controls/identifiersHexadecimal.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/identifiersMangled",
        obf: "src/javascript/obfuscator-io-samples/controls/identifiersMangled.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/numbersToExpressions",
        obf: "src/javascript/obfuscator-io-samples/controls/numbersToExpressions.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/objectTransform",
        obf: "src/javascript/obfuscator-io-samples/controls/objectTransform.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/renameProperties",
        obf: "src/javascript/obfuscator-io-samples/controls/renameProperties.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/selfDefending",
        obf: "src/javascript/obfuscator-io-samples/controls/selfDefending.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/splitStrings",
        obf: "src/javascript/obfuscator-io-samples/controls/splitStrings.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/stringArrayBase64",
        obf: "src/javascript/obfuscator-io-samples/controls/stringArrayBase64.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/stringArrayRc4",
        obf: "src/javascript/obfuscator-io-samples/controls/stringArrayRc4.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/stringArrayRotate",
        obf: "src/javascript/obfuscator-io-samples/controls/stringArrayRotate.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/stringArrayShuffle",
        obf: "src/javascript/obfuscator-io-samples/controls/stringArrayShuffle.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
    Sample {
        name: "obfuscator.io/control/unicodeEscape",
        obf: "src/javascript/obfuscator-io-samples/controls/unicodeEscape.js",
        reference: Reference::Clean(HIGH_CLEAN),
        argv_battery: NO_ARGS,
    },
];

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalBatchRequest {
    program: String,
    argv_battery: Vec<Vec<String>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalBatchResponse {
    evaluations: Vec<Result<EvalOutcome, String>>,
}

enum GuardedBatch {
    Completed(Vec<Result<EvalOutcome, String>>),
    WallTimeExceeded,
    HarnessFailure(String),
}

enum Outcome {
    Passed(RewriteActivity),
    CannotExecute(String),
    Diverged(String),
    TimedOut(String),
    Truncated(String),
    HarnessFailure(String),
}

fn corpus_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(rel)
}

fn normalize_corpus_relative(path: &Path) -> Result<String, String> {
    let mut parts: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let Some(part_str): Option<&str> = part.to_str() else {
                    return Err(format!(
                        "non-UTF-8 corpus path component: {}",
                        path.display()
                    ));
                };
                parts.push(part_str.to_owned());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "corpus-relative path escapes its root: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

fn is_javascript(path: &Path) -> bool {
    let extension: Option<&str> = path.extension().and_then(std::ffi::OsStr::to_str);
    extension == Some("js")
}

fn discover_javascript_under(
    corpus_root: &Path,
    requested_root: &Path,
    discovered: &mut BTreeSet<String>,
) -> Result<(), String> {
    let mut pending: Vec<PathBuf> = vec![requested_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries: fs::ReadDir = fs::read_dir(&directory)
            .map_err(|error: std::io::Error| format!("{}: {error}", directory.display()))?;
        for entry_result in entries {
            let entry: fs::DirEntry = entry_result
                .map_err(|error: std::io::Error| format!("{}: {error}", directory.display()))?;
            let file_type: fs::FileType = entry
                .file_type()
                .map_err(|error: std::io::Error| format!("{}: {error}", entry.path().display()))?;
            let path: PathBuf = entry.path();
            if file_type.is_symlink() {
                return Err(format!(
                    "corpus census refuses symlinked entries: {}",
                    path.display()
                ));
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() || !is_javascript(&path) {
                continue;
            }
            let relative: &Path =
                path.strip_prefix(corpus_root)
                    .map_err(|error: std::path::StripPrefixError| {
                        format!("{}: {error}", path.display())
                    })?;
            let normalized: String = normalize_corpus_relative(relative)?;
            if !discovered.insert(normalized.clone()) {
                return Err(format!("duplicate discovered corpus path: {normalized}"));
            }
        }
    }
    Ok(())
}

fn discover_requested_javascript() -> Result<Option<BTreeSet<String>>, String> {
    let corpus_root: PathBuf = corpus_path("");
    let mut discovered: BTreeSet<String> = BTreeSet::new();
    for relative_root in REQUESTED_ROOTS {
        let requested_root: PathBuf = corpus_root.join(relative_root);
        if !requested_root.is_dir() {
            eprintln!(
                "requested corpus root unavailable: {}; execution differential skipped",
                requested_root.display()
            );
            return Ok(None);
        }
        discover_javascript_under(&corpus_root, &requested_root, &mut discovered)?;
    }
    Ok(Some(discovered))
}

struct RequestedManifest {
    obfuscated: BTreeSet<String>,
    references: BTreeSet<String>,
}

impl RequestedManifest {
    fn all_paths(&self) -> BTreeSet<String> {
        self.obfuscated
            .iter()
            .chain(&self.references)
            .cloned()
            .collect()
    }
}

fn path_is_requested(path: &str) -> bool {
    REQUESTED_ROOTS
        .iter()
        .any(|root: &&str| path.starts_with(&format!("{root}/")))
}

fn requested_manifest() -> Result<RequestedManifest, String> {
    let mut obfuscated: BTreeSet<String> = BTreeSet::new();
    let mut references: BTreeSet<String> = BTreeSet::new();
    for sample in SAMPLES {
        if !path_is_requested(sample.obf) {
            continue;
        }
        let normalized_obfuscated: String = normalize_corpus_relative(Path::new(sample.obf))?;
        if !obfuscated.insert(normalized_obfuscated.clone()) {
            return Err(format!(
                "duplicate requested manifest path: {normalized_obfuscated}"
            ));
        }
        if let Reference::Clean(reference) = sample.reference
            && path_is_requested(reference)
        {
            let normalized_reference: String = normalize_corpus_relative(Path::new(reference))?;
            references.insert(normalized_reference);
        }
    }
    let overlap: Option<&String> = obfuscated
        .iter()
        .find(|path: &&String| references.contains(*path));
    if let Some(overlap) = overlap {
        return Err(format!(
            "requested corpus path is both obfuscated and a clean reference: {overlap}"
        ));
    }
    Ok(RequestedManifest {
        obfuscated,
        references,
    })
}

fn try_load(rel: &str) -> Result<String, String> {
    let path: PathBuf = corpus_path(rel);
    fs::read_to_string(&path)
        .map_err(|error: std::io::Error| format!("{}: {error}", path.display()))
}

fn load(rel: &str) -> String {
    try_load(rel).unwrap_or_else(|error: String| panic!("failed to read fixture: {error}"))
}

#[test]
fn every_regex_rewriter_is_graded_or_recorded_ungraded() {
    let discovered: BTreeSet<String> =
        discover_regex_rewriter_modules().expect("crate source census must be readable");
    let recorded: BTreeSet<String> = REGEX_REWRITERS
        .iter()
        .map(|rewriter: &RegexRewriter| rewriter.module.to_owned())
        .collect();
    assert_eq!(
        recorded.len(),
        REGEX_REWRITERS.len(),
        "the regex rewriter roster must not list a module twice"
    );
    assert_eq!(
        recorded, discovered,
        "every module that builds a regular expression over source text must be recorded as graded \
         by this differential or ungraded with a reason; add the new module to REGEX_REWRITERS in \
         the same change that adds the regular expression"
    );
    let graded: Vec<&'static str> = REGEX_REWRITERS
        .iter()
        .filter(|rewriter: &&RegexRewriter| rewriter.coverage.graded().is_some())
        .map(|rewriter: &RegexRewriter| rewriter.module)
        .collect();
    eprintln!(
        "regex rewriter census: {} modules, {} graded by execution differential, {} recorded ungraded",
        REGEX_REWRITERS.len(),
        graded.len(),
        REGEX_REWRITERS.len() - graded.len()
    );
    for rewriter in REGEX_REWRITERS {
        match rewriter.coverage {
            Coverage::Corpus { family, .. } => {
                eprintln!("  graded {family:?} by corpus sample: {}", rewriter.module);
            }
            Coverage::Witness { family, .. } => {
                eprintln!("  graded {family:?} by family witness: {}", rewriter.module);
            }
            Coverage::Ungraded(reason) => {
                assert!(
                    !reason.is_empty(),
                    "{}: an ungraded rewriter must record why",
                    rewriter.module
                );
                eprintln!("  ungraded: {} ({reason})", rewriter.module);
            }
        }
    }
    for family in NAMED_FAMILIES {
        let members: Vec<&'static str> = family_modules(*family);
        assert!(
            !members.is_empty(),
            "{family:?} is named by this item and must resolve to at least one module"
        );
        eprintln!("  {family:?} resolves to {members:?}");
    }
    for family in ALL_FAMILIES {
        assert!(
            !family_modules(*family).is_empty(),
            "{family:?} has no module, so the taxonomy and the roster have drifted"
        );
    }
}

fn family_modules(family: RewriterFamily) -> Vec<&'static str> {
    REGEX_REWRITERS
        .iter()
        .filter(|rewriter: &&RegexRewriter| {
            rewriter
                .coverage
                .graded()
                .is_some_and(|(graded, _): (RewriterFamily, ActivityProbe)| graded == family)
        })
        .map(|rewriter: &RegexRewriter| rewriter.module)
        .collect()
}

#[test]
fn sample_roster_size_is_pinned_by_equality() {
    assert_eq!(
        SAMPLES.len(),
        SAMPLE_COUNT,
        "the corpus sample count is pinned by equality so growing the denominator cannot hide a \
         regression behind the pass floor"
    );
    let reachable: usize = SAMPLES.len();
    assert!(
        reachable >= DIFFERENTIAL_FLOOR,
        "the pass floor can never exceed the number of samples that could reach it"
    );
    assert_eq!(
        FAMILY_WITNESSES.len(),
        NAMED_FAMILIES.len(),
        "every named rewriter family carries exactly one faithful-and-wrong-rewrite witness"
    );
}

#[test]
fn requested_manifest_classifies_every_javascript_file() {
    let discovered: Option<BTreeSet<String>> =
        discover_requested_javascript().expect("requested corpus census must be readable");
    let Some(discovered): Option<BTreeSet<String>> = discovered else {
        eprintln!("requested corpus unavailable; execution differential coverage test skipped");
        return;
    };
    let manifest: RequestedManifest =
        requested_manifest().expect("requested manifest paths must be valid and unique");
    let classified: BTreeSet<String> = manifest.all_paths();
    assert_eq!(
        classified, discovered,
        "requested corpus manifest must classify every JavaScript file as obfuscated or a clean reference"
    );
}

fn observed(kind: &str, value: &str) -> ObservedValue {
    ObservedValue {
        kind: kind.to_owned(),
        value: value.to_owned(),
    }
}

#[test]
fn boa_observation_preserves_calls_arguments_completion_and_exceptions() {
    let completed: EvalOutcome =
        eval_outcome("console.log('a b', 7, -0, NaN); console.error('after'); 42;")
            .expect("completed observation must evaluate");
    assert_eq!(
        completed,
        EvalOutcome {
            trace: vec![
                TraceEvent {
                    call: "console.log".to_owned(),
                    arguments: vec![
                        observed("string", "a b"),
                        observed("number", "7"),
                        observed("number", "-0"),
                        observed("number", "NaN"),
                    ],
                },
                TraceEvent {
                    call: "console.error".to_owned(),
                    arguments: vec![observed("string", "after")],
                },
            ],
            terminal: Terminal::Completed(observed("number", "42")),
        }
    );

    let threw: EvalOutcome = eval_outcome("console.warn('before'); throw new TypeError('broken');")
        .expect("thrown observation must evaluate");
    assert_eq!(
        threw,
        EvalOutcome {
            trace: vec![TraceEvent {
                call: "console.warn".to_owned(),
                arguments: vec![observed("string", "before")],
            }],
            terminal: Terminal::Threw {
                kind: "TypeError".to_owned(),
                message: "broken".to_owned(),
            },
        }
    );
}

#[test]
fn thrown_exceptions_remain_comparable_observables() {
    let expected: EvalOutcome = eval_outcome("console.log('before');throw new Error('expected')")
        .expect("deliberate throw must evaluate");
    let divergent: EvalOutcome = eval_outcome("console.log('before');throw new Error('divergent')")
        .expect("divergent throw must evaluate");
    assert!(
        unsupported_reference_reason(&expected).is_none(),
        "a deliberate throw must remain eligible for comparison"
    );
    assert_ne!(expected, divergent);
    let opaque_source_one: String = ["throw ", "{", "code:1", "}"].concat();
    let opaque_one: EvalOutcome =
        eval_outcome(&opaque_source_one).expect("opaque object throw must evaluate");
    let opaque_source_two: String = ["throw ", "{", "code:2", "}"].concat();
    let opaque_two: EvalOutcome =
        eval_outcome(&opaque_source_two).expect("second opaque object throw must evaluate");
    assert!(
        unsupported_reference_reason(&opaque_one).is_some()
            && unsupported_reference_reason(&opaque_two).is_some(),
        "opaque object throws must never enter behavior comparison"
    );
    let tool_gap: EvalOutcome = eval_outcome("new FinalizationRegistry(()=>{})")
        .expect("missing Boa global must produce a terminal observation");
    assert!(
        unsupported_reference_reason(&tool_gap).is_some(),
        "a known Boa capability gap must remain out of scope"
    );
    let module_source: EvalOutcome = eval_outcome("import value from './dep.js';")
        .expect("module syntax must produce a parse observation");
    assert!(
        matches!(module_source.terminal, Terminal::ParseFailed { .. }),
        "Script-mode module syntax must be classified as a parse limit"
    );
    assert!(
        unsupported_reference_reason(&module_source).is_some(),
        "a module parse limit must remain out of scope"
    );
}

#[test]
fn boa_environment_inputs_are_fixed_and_ordered() {
    let outcome: EvalOutcome = eval_outcome(
        "console.log(Date.now(), new Date().getTime(), Math.random(), performance.now(), crypto.randomUUID(), process.env.MISSING);",
    )
    .expect("deterministic environment probe must evaluate");
    assert_eq!(
        outcome,
        EvalOutcome {
            trace: vec![
                TraceEvent {
                    call: "Date.now".to_owned(),
                    arguments: Vec::new(),
                },
                TraceEvent {
                    call: "Date.construct".to_owned(),
                    arguments: Vec::new(),
                },
                TraceEvent {
                    call: "Math.random".to_owned(),
                    arguments: Vec::new(),
                },
                TraceEvent {
                    call: "performance.now".to_owned(),
                    arguments: Vec::new(),
                },
                TraceEvent {
                    call: "crypto.randomUUID".to_owned(),
                    arguments: Vec::new(),
                },
                TraceEvent {
                    call: "console.log".to_owned(),
                    arguments: vec![
                        observed("number", "1700000000000"),
                        observed("number", "1700000000000"),
                        observed("number", "0.125"),
                        observed("number", "1234.5"),
                        observed("string", "00000000-0000-4000-8000-000000000001"),
                        observed("undefined", ""),
                    ],
                },
            ],
            terminal: Terminal::Completed(observed("undefined", "")),
        }
    );
}

#[test]
fn dom_dependent_paths_are_out_of_scope() {
    let clean: EvalOutcome =
        eval_outcome("const node=document.querySelector('#x');if(node)console.log('clean');")
            .expect("DOM-dependent clean probe must evaluate under the shim");
    let changed: EvalOutcome =
        eval_outcome("const node=document.querySelector('#x');if(node)console.log('changed');")
            .expect("DOM-dependent changed probe must evaluate under the shim");
    assert_eq!(
        clean, changed,
        "the fixed empty DOM demonstrates why selector-dependent programs cannot be compared"
    );
    assert!(
        unsupported_reference_reason(&clean).is_some()
            && unsupported_reference_reason(&changed).is_some(),
        "selector-dependent outcomes must never enter behavior comparison"
    );
}

#[test]
fn queued_promise_jobs_are_out_of_scope() {
    let clean: EvalOutcome = eval_outcome("Promise.resolve().then(()=>console.log('clean'));0")
        .expect("clean Promise probe must evaluate");
    let changed: EvalOutcome = eval_outcome("Promise.resolve().then(()=>console.log('changed'));0")
        .expect("changed Promise probe must evaluate");
    let pending: Terminal =
        Terminal::ObservationLimitExceeded("pending Promise jobs are unsupported".to_owned());
    assert_eq!(clean.terminal, pending);
    assert_eq!(changed.terminal, pending);
    assert!(
        unsupported_reference_reason(&clean).is_some()
            && unsupported_reference_reason(&changed).is_some(),
        "queued Promise jobs must never enter behavior comparison"
    );
}

#[test]
fn boa_date_timezone_is_fixed_to_utc() {
    let outcome: EvalOutcome =
        eval_outcome("console.log(new Date(2026, 0, 1).getTimezoneOffset());")
            .expect("fixed timezone probe must evaluate");
    assert_eq!(
        outcome,
        EvalOutcome {
            trace: vec![
                TraceEvent {
                    call: "Date.construct".to_owned(),
                    arguments: vec![
                        observed("number", "2026"),
                        observed("number", "0"),
                        observed("number", "1"),
                    ],
                },
                TraceEvent {
                    call: "console.log".to_owned(),
                    arguments: vec![observed("number", "0")],
                },
            ],
            terminal: Terminal::Completed(observed("undefined", "")),
        }
    );
}

#[test]
fn boa_observation_limit_is_explicit() {
    let outcome: EvalOutcome =
        eval_outcome("for (let index = 0; index < 5000; index += 1) console.log(index);")
            .expect("observation limit probe must evaluate");
    assert_eq!(
        outcome.terminal,
        Terminal::ObservationLimitExceeded("trace event limit 4096 exceeded".to_owned())
    );
    assert_eq!(outcome.trace.len(), 4096);
}

#[test]
fn boa_bigint_observation_is_magnitude_bounded() {
    let outcome: EvalOutcome = eval_outcome("console.log(1n << 4096n);")
        .expect("BigInt observation limit probe must evaluate");
    assert_eq!(
        outcome.terminal,
        Terminal::ObservationLimitExceeded(
            "observable BigInt exceeds the supported magnitude".to_owned()
        )
    );
    assert!(outcome.trace.is_empty());
}

#[test]
fn legacy_capture_preserves_primitive_javascript_rendering() {
    let captured: String =
        eval_capture("console.log(undefined, null, false, -0, 7n, 1e21, 1e-7, 1e20);")
            .expect("primitive console capture must evaluate");
    assert_eq!(
        captured,
        "undefined null false 0 7 1e+21 1e-7 100000000000000000000"
    );
    assert!(
        eval_capture("console.log({ value: 1 });").is_none(),
        "unsupported object rendering must not collapse to an empty string"
    );
}

#[test]
#[ignore = "invoked only as bounded corpus subprocess worker"]
fn boa_eval_subprocess_worker() {
    let Some(request_path): Option<PathBuf> =
        std::env::var_os(WORKER_REQUEST_ENV).map(PathBuf::from)
    else {
        eprintln!("Boa evaluation worker request unavailable; worker test skipped");
        return;
    };
    let response_path: PathBuf = std::env::var_os(WORKER_RESPONSE_ENV)
        .map(PathBuf::from)
        .expect("Boa evaluation worker response path must be set");
    let request_bytes: Vec<u8> =
        fs::read(&request_path).expect("Boa evaluation worker must read its request");
    let request: EvalBatchRequest =
        serde_json::from_slice(&request_bytes).expect("Boa evaluation worker request must decode");
    let mut evaluations: Vec<Result<EvalOutcome, String>> =
        Vec::with_capacity(request.argv_battery.len());
    for argv in &request.argv_battery {
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let evaluation: Result<EvalOutcome, String> =
            try_eval_outcome_with_argv(&request.program, &argv_refs);
        evaluations.push(evaluation);
    }
    let response: EvalBatchResponse = EvalBatchResponse { evaluations };
    let response_bytes: Vec<u8> =
        serde_json::to_vec(&response).expect("Boa evaluation worker response must encode");
    let response_limit: usize =
        usize::try_from(WORKER_RESPONSE_LIMIT).expect("worker response limit must fit usize");
    assert!(
        response_bytes.len() <= response_limit,
        "Boa evaluation worker response exceeds {WORKER_RESPONSE_LIMIT} bytes"
    );
    fs::write(&response_path, response_bytes)
        .expect("Boa evaluation worker must write its response");
}

fn worker_diagnostics(output: &CapturedOutput) -> String {
    let stdout: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    format!(
        "exit={:?}; stdout={stdout:?}; stderr={stderr:?}",
        output.exit_code
    )
}

fn read_worker_response(path: &Path) -> Result<Vec<u8>, String> {
    let metadata: fs::Metadata = fs::metadata(path)
        .map_err(|error: std::io::Error| format!("inspect Boa worker response: {error}"))?;
    if metadata.len() > WORKER_RESPONSE_LIMIT {
        return Err(format!(
            "Boa worker response is {} bytes, above the {WORKER_RESPONSE_LIMIT}-byte limit",
            metadata.len()
        ));
    }
    fs::read(path).map_err(|error: std::io::Error| format!("read Boa worker response: {error}"))
}

#[test]
fn oversized_worker_response_is_rejected_before_read() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-js-boa-response-limit").expect("scratch directory must open");
    let response_path: PathBuf = scratch.path().join("response.json");
    let response: fs::File =
        fs::File::create(&response_path).expect("response fixture must be created");
    response
        .set_len(WORKER_RESPONSE_LIMIT + 1)
        .expect("response fixture length must be set");
    let error: String =
        read_worker_response(&response_path).expect_err("oversized response must be rejected");
    assert!(
        error.contains("above the"),
        "response limit diagnostic missing: {error}"
    );
}

fn eval_batch_guarded(program: &str, argv_battery: &[&[&str]]) -> GuardedBatch {
    let scratch: ScratchDir = match ScratchDir::create("disrobe-js-boa-oracle") {
        Ok(scratch) => scratch,
        Err(error) => {
            return GuardedBatch::HarnessFailure(format!(
                "create Boa worker scratch directory: {error}"
            ));
        }
    };
    let request_path: PathBuf = scratch.path().join("request.json");
    let response_path: PathBuf = scratch.path().join("response.json");
    let argv_owned: Vec<Vec<String>> = argv_battery
        .iter()
        .map(|argv: &&[&str]| {
            argv.iter()
                .map(|argument: &&str| (*argument).to_owned())
                .collect()
        })
        .collect();
    let request: EvalBatchRequest = EvalBatchRequest {
        program: program.to_owned(),
        argv_battery: argv_owned,
    };
    let request_bytes: Vec<u8> = match serde_json::to_vec(&request) {
        Ok(bytes) => bytes,
        Err(error) => {
            return GuardedBatch::HarnessFailure(format!("encode Boa worker request: {error}"));
        }
    };
    if let Err(error) = fs::write(&request_path, request_bytes) {
        return GuardedBatch::HarnessFailure(format!("write Boa worker request: {error}"));
    }
    let executable: PathBuf = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            return GuardedBatch::HarnessFailure(format!("resolve Boa worker executable: {error}"));
        }
    };
    let child: Child = match Command::new(&executable)
        .args([
            "--ignored",
            "--exact",
            "boa_eval_subprocess_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(WORKER_REQUEST_ENV, &request_path)
        .env(WORKER_RESPONSE_ENV, &response_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return GuardedBatch::HarnessFailure(format!("spawn Boa worker: {error}"));
        }
    };
    let wait_started: Instant = Instant::now();
    let Some(output): Option<CapturedOutput> =
        wait_with_output_timeout(child, EVAL_TIMEOUT, WORKER_CAPTURE_LIMIT)
    else {
        let elapsed: Duration = wait_started.elapsed();
        if elapsed >= EVAL_TIMEOUT {
            return GuardedBatch::WallTimeExceeded;
        }
        return GuardedBatch::HarnessFailure(format!(
            "Boa worker wait or output capture failed after {elapsed:?}"
        ));
    };
    if output.exit_code != Some(0) {
        return GuardedBatch::HarnessFailure(format!(
            "Boa worker failed: {}",
            worker_diagnostics(&output)
        ));
    }
    let response_bytes: Vec<u8> = match read_worker_response(&response_path) {
        Ok(bytes) => bytes,
        Err(reason) => {
            return GuardedBatch::HarnessFailure(format!(
                "{reason}; {}",
                worker_diagnostics(&output)
            ));
        }
    };
    let response: EvalBatchResponse = match serde_json::from_slice(&response_bytes) {
        Ok(response) => response,
        Err(error) => {
            return GuardedBatch::HarnessFailure(format!(
                "decode Boa worker response: {error}; {}",
                worker_diagnostics(&output)
            ));
        }
    };
    GuardedBatch::Completed(response.evaluations)
}

#[test]
fn boa_subprocess_reports_the_engine_step_limit() {
    let evaluations: Vec<Result<EvalOutcome, String>> =
        match eval_batch_guarded("for (;;) {}", NO_ARGS) {
            GuardedBatch::Completed(evaluations) => evaluations,
            GuardedBatch::WallTimeExceeded => {
                panic!("Boa loop must hit the engine step limit before the hard wall-clock limit")
            }
            GuardedBatch::HarnessFailure(reason) => panic!("{reason}"),
        };
    let first: &Result<EvalOutcome, String> = evaluations
        .first()
        .expect("loop-limit probe must return one evaluation");
    let outcome: &EvalOutcome = first
        .as_ref()
        .unwrap_or_else(|reason: &String| panic!("{reason}"));
    assert_eq!(outcome.terminal, Terminal::ExecutionLimitExceeded);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pipeline {
    JsConfuser,
    ObfuscatorIo,
}

impl Pipeline {
    fn for_path(path: &str) -> Self {
        if path.starts_with("js/jsconfuser/") {
            Self::JsConfuser
        } else {
            Self::ObfuscatorIo
        }
    }
}

#[derive(Debug, Clone)]
struct Recovery {
    source: String,
    activity: RewriteActivity,
}

fn recover_with(pipeline: Pipeline, obf_src: &str) -> Result<Recovery, String> {
    match pipeline {
        Pipeline::JsConfuser => {
            let opts: DeobOptions = DeobOptions::all();
            let out: DeobOutput = deobfuscate_all(obf_src, &opts);
            let activity: RewriteActivity = activity_from_jsconfuser(&out);
            Ok(Recovery {
                source: out.source,
                activity,
            })
        }
        Pipeline::ObfuscatorIo => {
            let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
            let out: ObfuscatorIoOutput = obfuscator_io_deobfuscate(obf_src, &opts)
                .map_err(|error: disrobe_pass_js_deob::Error| error.to_string())?;
            let activity: RewriteActivity = activity_from_obfuscator_io(&out);
            Ok(Recovery {
                source: out.source,
                activity,
            })
        }
    }
}

const UNSUPPORTED_REFERENCE_GLOBALS: &[&str] = &[
    "Buffer",
    "FinalizationRegistry",
    "WebSocket",
    "XMLHttpRequest",
    "document",
    "exports",
    "fetch",
    "importScripts",
    "module",
    "require",
];

fn unsupported_reference_global(kind: &str, message: &str) -> Option<&'static str> {
    if kind != "ReferenceError" {
        return None;
    }
    UNSUPPORTED_REFERENCE_GLOBALS
        .iter()
        .copied()
        .find(|global: &&str| message == format!("{global} is not defined"))
}

fn unsupported_reference_reason(outcome: &EvalOutcome) -> Option<String> {
    match &outcome.terminal {
        Terminal::Completed(value)
            if matches!(value.kind.as_str(), "object" | "function" | "symbol") =>
        {
            return Some(format!(
                "script completion value has unsupported observable type {}",
                value.kind
            ));
        }
        Terminal::Threw { kind, .. }
            if matches!(
                kind.as_str(),
                "Thrownobject" | "Thrownfunction" | "Thrownsymbol"
            ) =>
        {
            return Some(format!(
                "reference source throws unsupported opaque {} value",
                kind.trim_start_matches("Thrown")
            ));
        }
        Terminal::Threw { kind, message }
            if unsupported_reference_global(kind, message).is_some() =>
        {
            let global: &str = unsupported_reference_global(kind, message)?;
            return Some(format!(
                "reference source requires unsupported Boa or host global {global}"
            ));
        }
        Terminal::Completed(_) | Terminal::Threw { .. } => {}
        Terminal::ParseFailed { kind, message } => {
            return Some(format!(
                "reference source cannot be parsed by Boa as a script: {kind}: {message}"
            ));
        }
        Terminal::ExecutionLimitExceeded => {
            return Some(format!(
                "known-completing reference source exceeded Boa's {LOOP_LIMIT_DESCRIPTION}"
            ));
        }
        Terminal::ObservationLimitExceeded(reason) => {
            return Some(format!(
                "reference source exceeded the observation limit: {reason}"
            ));
        }
    }
    for event in &outcome.trace {
        if event.call == "document.querySelector" {
            return Some(
                "reference source requires document.querySelector against a real DOM".to_owned(),
            );
        }
        if event.call.starts_with("host.unsupported.") {
            let path: &str = event
                .arguments
                .first()
                .map_or("", |argument: &ObservedValue| argument.value.as_str());
            return Some(format!(
                "reference source requires unsupported host operation {} on {path}",
                event.call
            ));
        }
        if matches!(
            event.call.as_str(),
            "setInterval" | "setTimeout" | "queueMicrotask"
        ) {
            return Some(format!(
                "reference source schedules {} but the bounded harness does not run callbacks",
                event.call
            ));
        }
        let unsupported: Option<&ObservedValue> =
            event.arguments.iter().find(|argument: &&ObservedValue| {
                matches!(argument.kind.as_str(), "object" | "function" | "symbol")
            });
        if let Some(argument) = unsupported {
            return Some(format!(
                "reference source passes unsupported {} argument to {}",
                argument.kind, event.call
            ));
        }
    }
    None
}

const LOOP_LIMIT_DESCRIPTION: &str = "2,000,000-iteration execution limit";

fn truncation_reason(outcome: &EvalOutcome) -> Option<String> {
    let Terminal::ObservationLimitExceeded(reason) = &outcome.terminal else {
        return None;
    };
    if reason.contains("exceeded") || reason.contains("exceeds") {
        return Some(reason.clone());
    }
    None
}

fn collect_reference_outcomes(
    name: &str,
    argv_battery: &[&[&str]],
    reference_kind: &str,
    evaluations: Vec<Result<EvalOutcome, String>>,
) -> Result<Vec<EvalOutcome>, Box<Outcome>> {
    if evaluations.len() != argv_battery.len() {
        return Err(Box::new(Outcome::HarnessFailure(format!(
            "{name}: Boa worker returned {} {reference_kind} evaluations for {} argument cases",
            evaluations.len(),
            argv_battery.len()
        ))));
    }
    let mut outcomes: Vec<EvalOutcome> = Vec::with_capacity(evaluations.len());
    for (index, evaluation) in evaluations.into_iter().enumerate() {
        let argv: &[&str] = argv_battery[index];
        let outcome: EvalOutcome = match evaluation {
            Ok(outcome) => outcome,
            Err(reason) => {
                return Err(Box::new(Outcome::HarnessFailure(format!(
                    "{name}: {reference_kind} evaluation harness failed for argv {argv:?}: {reason}",
                ))));
            }
        };
        if let Some(reason) = truncation_reason(&outcome) {
            return Err(Box::new(Outcome::Truncated(format!(
                "{name}: {reference_kind} observation truncated for argv {argv:?}: {reason}"
            ))));
        }
        if let Some(reason) = unsupported_reference_reason(&outcome) {
            return Err(Box::new(Outcome::CannotExecute(format!(
                "{name} for argv {argv:?}: {reason}"
            ))));
        }
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

struct DifferentialCase<'a> {
    name: &'a str,
    pipeline: Pipeline,
    reference_kind: &'a str,
    reference_src: &'a str,
    obf_src: &'a str,
    argv_battery: &'a [&'a [&'a str]],
}

fn run_differential(case: &DifferentialCase<'_>) -> Outcome {
    let name: &str = case.name;
    let reference_kind: &str = case.reference_kind;
    let reference_evaluations: Vec<Result<EvalOutcome, String>> = match eval_batch_guarded(
        case.reference_src,
        case.argv_battery,
    ) {
        GuardedBatch::Completed(evaluations) => evaluations,
        GuardedBatch::WallTimeExceeded => {
            return Outcome::TimedOut(format!(
                "{name}: {reference_kind} source exceeded the hard {EVAL_TIMEOUT:?} subprocess limit"
            ));
        }
        GuardedBatch::HarnessFailure(reason) => {
            return Outcome::HarnessFailure(format!("{name}: {reason}"));
        }
    };
    let want: Vec<EvalOutcome> = match collect_reference_outcomes(
        name,
        case.argv_battery,
        reference_kind,
        reference_evaluations,
    ) {
        Ok(outcomes) => outcomes,
        Err(outcome) => return *outcome,
    };
    let recovery: Recovery = match recover_with(case.pipeline, case.obf_src) {
        Ok(recovery) => recovery,
        Err(reason) => {
            return Outcome::Diverged(format!(
                "{name}: recovery failed before execution: {reason}"
            ));
        }
    };
    let recovered_evaluations: Vec<Result<EvalOutcome, String>> =
        match eval_batch_guarded(&recovery.source, case.argv_battery) {
            GuardedBatch::Completed(evaluations) => evaluations,
            GuardedBatch::WallTimeExceeded => {
                return Outcome::TimedOut(format!(
                    "{name}: recovered source exceeded the hard {EVAL_TIMEOUT:?} subprocess limit"
                ));
            }
            GuardedBatch::HarnessFailure(reason) => {
                return Outcome::HarnessFailure(format!("{name}: {reason}"));
            }
        };
    if recovered_evaluations.len() != case.argv_battery.len() {
        return Outcome::HarnessFailure(format!(
            "{name}: Boa worker returned {} recovered evaluations for {} argument cases",
            recovered_evaluations.len(),
            case.argv_battery.len()
        ));
    }
    for (index, evaluation) in recovered_evaluations.into_iter().enumerate() {
        let argv: &[&str] = case.argv_battery[index];
        let got: EvalOutcome = match evaluation {
            Ok(outcome) => outcome,
            Err(reason) => {
                return Outcome::HarnessFailure(format!(
                    "{name}: recovered evaluation harness failed for argv {argv:?}: {reason}"
                ));
            }
        };
        if let Some(reason) = truncation_reason(&got) {
            return Outcome::Truncated(format!(
                "{name}: recovered observation truncated for argv {argv:?}: {reason}"
            ));
        }
        let expected: &EvalOutcome = &want[index];
        if expected != &got {
            return Outcome::Diverged(format!(
                "{name}: recovered behavior diverged from {reference_kind} source for argv {argv:?}\n--reference--\n{expected:?}\n--recovered--\n{got:?}"
            ));
        }
    }
    Outcome::Passed(recovery.activity)
}

fn comparison_description(sample: &Sample) -> String {
    match sample.reference {
        Reference::Clean(reference) => {
            format!("clean {reference} vs recovered from {}", sample.obf)
        }
        Reference::Obfuscated => format!("obfuscated {} vs recovered", sample.obf),
    }
}

fn check_sample(sample: &Sample) -> Outcome {
    let obf_src: String = match try_load(sample.obf) {
        Ok(source) => source,
        Err(reason) => {
            return Outcome::CannotExecute(format!(
                "{}: obfuscated sample unavailable: {reason}",
                sample.name
            ));
        }
    };
    let clean_src: Option<String> = match sample.reference {
        Reference::Clean(reference) => match try_load(reference) {
            Ok(source) => Some(source),
            Err(reason) => {
                return Outcome::CannotExecute(format!(
                    "{}: clean source unavailable: {reason}",
                    sample.name
                ));
            }
        },
        Reference::Obfuscated => None,
    };
    let (reference_kind, reference_src): (&str, &str) = clean_src.as_deref().map_or_else(
        || ("obfuscated", obf_src.as_str()),
        |source: &str| ("clean", source),
    );
    run_differential(&DifferentialCase {
        name: sample.name,
        pipeline: Pipeline::for_path(sample.obf),
        reference_kind,
        reference_src,
        obf_src: &obf_src,
        argv_battery: sample.argv_battery,
    })
}

fn is_requested(sample: &Sample) -> bool {
    path_is_requested(sample.obf)
}

#[test]
fn corpus_wide_differential_reexec() {
    let discovered: Option<BTreeSet<String>> =
        discover_requested_javascript().expect("requested corpus census must be readable");
    let Some(discovered): Option<BTreeSet<String>> = discovered else {
        eprintln!("requested corpus unavailable; execution differential skipped");
        return;
    };
    let manifest: RequestedManifest =
        requested_manifest().expect("requested manifest paths must be valid and unique");
    let classified: BTreeSet<String> = manifest.all_paths();
    assert_eq!(
        classified, discovered,
        "requested corpus manifest must classify the execution corpus before grading"
    );

    let mut passed: Vec<&str> = Vec::new();
    let mut unexercised: Vec<String> = Vec::new();
    let mut cannot_execute: Vec<String> = Vec::new();
    let mut diverged: Vec<String> = Vec::new();
    let mut timed_out: Vec<String> = Vec::new();
    let mut truncated: Vec<String> = Vec::new();
    let mut harness_failures: Vec<String> = Vec::new();
    let mut requested_classified: usize = 0;
    let mut requested_passed: usize = 0;
    let mut aggregate: RewriteActivity = RewriteActivity::default();

    for sample in SAMPLES {
        let requested: bool = is_requested(sample);
        if requested {
            requested_classified += 1;
        }
        let comparison: String = comparison_description(sample);
        match check_sample(sample) {
            Outcome::Passed(activity) => {
                passed.push(sample.name);
                aggregate.merge(&activity);
                if requested {
                    requested_passed += 1;
                }
                let families: BTreeSet<RewriterFamily> = activity.families();
                if families.is_empty() {
                    unexercised.push(format!(
                        "{}: behavior is preserved but no tracked regex rewriter fired, so this sample grades no family [{comparison}]",
                        sample.name
                    ));
                }
                eprintln!(
                    "  pass: {} exercises {families:?} [{comparison}]",
                    sample.name
                );
            }
            Outcome::CannotExecute(reason) => {
                cannot_execute.push(format!("{reason} [{comparison}]"));
            }
            Outcome::Diverged(reason) => diverged.push(format!("{reason} [{comparison}]")),
            Outcome::TimedOut(reason) => timed_out.push(format!("{reason} [{comparison}]")),
            Outcome::Truncated(reason) => truncated.push(format!("{reason} [{comparison}]")),
            Outcome::HarnessFailure(reason) => {
                harness_failures.push(format!("{reason} [{comparison}]"));
            }
        }
    }

    eprintln!(
        "requested corpus execution differential: {requested_passed} passed of {} samples",
        manifest.obfuscated.len()
    );
    eprintln!(
        "extended execution differential total: {} passed ({} of them exercising no tracked family), {} diverged, {} timed out, {} truncated, {} cannot execute, {} harness failures (of {} samples)",
        passed.len(),
        unexercised.len(),
        diverged.len(),
        timed_out.len(),
        truncated.len(),
        cannot_execute.len(),
        harness_failures.len(),
        SAMPLES.len()
    );
    eprintln!(
        "families exercised by passing corpus samples: {:?}",
        aggregate.families()
    );
    for reason in &unexercised {
        eprintln!("  unexercised: {reason}");
    }
    for reason in &cannot_execute {
        eprintln!("  cannot execute: {reason}");
    }
    for reason in &timed_out {
        eprintln!("  timed out: {reason}");
    }
    for reason in &truncated {
        eprintln!("  truncated: {reason}");
    }
    for reason in &diverged {
        eprintln!("  diverged: {reason}");
    }
    for reason in &harness_failures {
        eprintln!("  harness failure: {reason}");
    }

    assert!(
        harness_failures.is_empty(),
        "execution differential harness failures:\n\n{}",
        harness_failures.join("\n\n")
    );
    assert!(
        diverged.is_empty(),
        "behavior divergences surfaced by corpus-wide differential re-execution:\n\n{}",
        diverged.join("\n\n")
    );
    assert!(
        timed_out.is_empty(),
        "samples that exceeded the hard subprocess limit:\n\n{}",
        timed_out.join("\n\n")
    );
    assert!(
        truncated.is_empty(),
        "samples whose observation was truncated, so their comparison graded a prefix:\n\n{}",
        truncated.join("\n\n")
    );
    assert!(
        passed.len() >= DIFFERENTIAL_FLOOR,
        "differential coverage regressed: {} samples verified < floor {DIFFERENTIAL_FLOOR}",
        passed.len()
    );
    assert_eq!(requested_classified, manifest.obfuscated.len());
    let total_classified: usize = passed.len()
        + cannot_execute.len()
        + diverged.len()
        + timed_out.len()
        + truncated.len()
        + harness_failures.len();
    assert_eq!(total_classified, SAMPLES.len());

    let corpus_graded_but_silent: Vec<&'static str> = REGEX_REWRITERS
        .iter()
        .filter_map(|rewriter: &RegexRewriter| match rewriter.coverage {
            Coverage::Corpus { probe, .. } if probe(&aggregate) == 0 => Some(rewriter.module),
            Coverage::Corpus { .. } | Coverage::Witness { .. } | Coverage::Ungraded(_) => None,
        })
        .collect();
    assert!(
        corpus_graded_but_silent.is_empty(),
        "these modules are recorded as graded by a corpus sample but no passing sample fires them; move them to a family witness or record them ungraded with a reason: {corpus_graded_but_silent:?}"
    );
}

fn assert_verified(outcome: Outcome) -> RewriteActivity {
    match outcome {
        Outcome::Passed(activity) => activity,
        Outcome::CannotExecute(reason)
        | Outcome::Diverged(reason)
        | Outcome::TimedOut(reason)
        | Outcome::Truncated(reason)
        | Outcome::HarnessFailure(reason) => panic!("{reason}"),
    }
}

fn assert_sample_verified(name: &str) {
    let sample: &Sample = SAMPLES
        .iter()
        .find(|s: &&Sample| s.name == name)
        .unwrap_or_else(|| panic!("unknown sample {name}"));
    let activity: RewriteActivity = assert_verified(check_sample(sample));
    eprintln!("  {name} exercises {:?}", activity.families());
}

#[test]
fn sample_without_clean_original_uses_obfuscated_reference() {
    let sample: Sample = Sample {
        name: "javascript-obfuscator/unpaired-browser-base64",
        obf: "js/javascript-obfuscator/browser/obf_base64.js",
        reference: Reference::Obfuscated,
        argv_battery: NO_ARGS,
    };
    assert_eq!(
        comparison_description(&sample),
        "obfuscated js/javascript-obfuscator/browser/obf_base64.js vs recovered"
    );
    assert_verified(check_sample(&sample));
}

#[test]
fn javascript_obfuscator_gauntlet_differential_reexec() {
    assert_sample_verified("javascript-obfuscator/gauntlet");
}

#[test]
fn jsconfuser_gauntlet_differential_reexec() {
    assert_sample_verified("jsconfuser/gauntlet");
}

#[test]
fn obfuscator_io_high_preset_differential_reexec() {
    assert_sample_verified("obfuscator.io/preset/high");
}

const fn routes_to_jsconfuser_full(family: JsObfuscator) -> bool {
    matches!(family, JsObfuscator::JsConfuser)
}

#[test]
fn deadcode_and_integrity_detect_as_jsconfuser_and_route_through_full() {
    const CASES: &[&str] = &[
        "js/jsconfuser/recovery/obf_deadcode.real.js",
        "js/jsconfuser/recovery/obf_deadcode_cff.real.js",
        "js/jsconfuser/recovery/obf_integrity.real.js",
    ];
    for rel in CASES {
        let src: String = load(rel);
        let det: Detection = detect(src.as_bytes());
        assert_eq!(
            det.family,
            JsObfuscator::JsConfuser,
            "{rel} must classify as JSConfuser (was misdetected as Minified), else --full misroutes it to the obfuscator.io pipeline; markers={:?}",
            det.markers
        );
        assert!(
            routes_to_jsconfuser_full(det.family),
            "{rel} must route through the JSConfuser --full pipeline (deobfuscate_all), not obfuscator.io"
        );
    }
}

#[test]
fn obfuscator_io_pipeline_is_bounded_on_integrity_trap() {
    let src: String = load("js/jsconfuser/recovery/obf_integrity.real.js");
    let controls: BTreeSet<ObfuscatorIoControl> =
        ObfuscatorIoControl::ALL.iter().copied().collect();
    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions {
        controls,
        max_passes: u32::MAX,
    };
    let out: ObfuscatorIoOutput = obfuscator_io_deobfuscate(&src, &opts)
        .expect("the obfuscator.io pipeline must not error on the integrity self-hash trap");
    assert!(
        out.passes_run <= OBFUSCATOR_IO_MAX_PASS_CEILING,
        "even under a hostile max_passes, the obfuscator.io pipeline must stay bounded by the pass ceiling {OBFUSCATOR_IO_MAX_PASS_CEILING}; ran {} passes",
        out.passes_run
    );
}

const BROWSER_SAMPLES: &[&str] = &[
    "javascript-obfuscator/browser-cff",
    "javascript-obfuscator/browser-base64",
];

#[test]
fn browser_host_samples_move_from_skipped_to_verified() {
    let mut moved: usize = 0;
    for name in BROWSER_SAMPLES {
        let sample: &Sample = SAMPLES
            .iter()
            .find(|s: &&Sample| s.name == *name)
            .unwrap_or_else(|| panic!("unknown browser sample {name}"));
        let clean_reference: &str = match sample.reference {
            Reference::Clean(reference) => reference,
            Reference::Obfuscated => panic!("{name}: browser sample must have a clean reference"),
        };
        let clean_src: String = load(clean_reference);

        let bare: Option<EvalOutcome> = eval_outcome_bare(&clean_src);
        assert!(
            !matches!(
                bare,
                Some(EvalOutcome {
                    terminal: Terminal::Completed(_),
                    ..
                })
            ),
            "{name}: the clean source reads browser globals absent from the bare boa preamble, so the pre-shim oracle would SKIP it; bare outcome was {bare:?}"
        );

        let hosted: EvalOutcome = eval_outcome(&clean_src).unwrap_or_else(|| {
            panic!("{name}: clean source must evaluate under the browser-host shim")
        });
        assert!(
            matches!(hosted.terminal, Terminal::Completed(_)),
            "{name}: the browser-host shim must let the clean source run to completion; got {hosted:?}"
        );

        assert_verified(check_sample(sample));
        moved += 1;
    }
    eprintln!("browser-host shim moved {moved} sample(s) from skipped to differential-verified");
    assert_eq!(
        moved,
        BROWSER_SAMPLES.len(),
        "every browser-targeted sample must move from skipped to differentially verified once the host shim is present"
    );
}

const WITNESS_CLEAN_PROXY: &str = r"
function calculate(op, a, b) {
  if (op === 'add') { return a + b; }
  if (op === 'sub') { return a - b; }
  return a * b;
}
console.log(calculate('add', 7, 3));
console.log(calculate('sub', 7, 3));
console.log(calculate('mul', 7, 3));
";

const WITNESS_OBF_PROXY: &str = r"
function calculate(op, a, b) {
  var _0xw1 = {
    'poLyL': function (x, y) { return x + y; },
    'FatOg': function (x, y) { return x - y; },
    'xvNoh': function (x, y) { return x * y; }
  };
  if (op === 'add') { return _0xw1['poLyL'](a, b); }
  if (op === 'sub') { return _0xw1['FatOg'](a, b); }
  return _0xw1['xvNoh'](a, b);
}
console.log(calculate('add', 7, 3));
console.log(calculate('sub', 7, 3));
console.log(calculate('mul', 7, 3));
";

const WITNESS_WRONG_PROXY: &str = r"
function calculate(op, a, b) {
  if (op === 'add') { return a - b; }
  if (op === 'sub') { return a + b; }
  return a * b;
}
console.log(calculate('add', 7, 3));
console.log(calculate('sub', 7, 3));
console.log(calculate('mul', 7, 3));
";

const WITNESS_CLEAN_DISPATCH: &str = r"
function compute() {
  var acc = 0;
  acc = acc + 5;
  acc = acc * 3;
  acc = acc - 2;
  return acc;
}
console.log(compute());
";

const WITNESS_OBF_DISPATCH: &str = r"
function compute() {
  var acc = 0;
  var order = '0|1|2'['split']('|');
  var ptr = 0;
  while (true) {
    switch (order[ptr++]) {
      case '0': acc = acc + 5; continue;
      case '1': acc = acc * 3; continue;
      case '2': acc = acc - 2; continue;
    }
    break;
  }
  return acc;
}
console.log(compute());
";

const WITNESS_WRONG_DISPATCH: &str = r"
function compute() {
  var acc = 0;
  acc = acc * 3;
  acc = acc + 5;
  acc = acc - 2;
  return acc;
}
console.log(compute());
";

const WITNESS_CLEAN_GUARD: &str = r"
function report() {
  var total = 0;
  total = total + 11;
  return total;
}
console.log(report());
";

const WITNESS_OBF_GUARD: &str = r"
function report() {
  var total = 0;
  setInterval(function () { debugger; }, 4000);
  total = total + 11;
  return total;
}
console.log(report());
";

const WITNESS_WRONG_GUARD: &str = r"
function report() {
  var total = 0;
  return total;
}
console.log(report());
";

struct FamilyWitness {
    family: RewriterFamily,
    clean: &'static str,
    obfuscated: &'static str,
    wrong_rewrite: &'static str,
    probe: ActivityProbe,
    obfuscation_is_trace_neutral: bool,
}

static FAMILY_WITNESSES: &[FamilyWitness] = &[
    FamilyWitness {
        family: RewriterFamily::ProxyObjectInlining,
        clean: WITNESS_CLEAN_PROXY,
        obfuscated: WITNESS_OBF_PROXY,
        wrong_rewrite: WITNESS_WRONG_PROXY,
        probe: |activity: &RewriteActivity| activity.control_flow_objects_merged,
        obfuscation_is_trace_neutral: true,
    },
    FamilyWitness {
        family: RewriterFamily::ControlFlowFlattening,
        clean: WITNESS_CLEAN_DISPATCH,
        obfuscated: WITNESS_OBF_DISPATCH,
        wrong_rewrite: WITNESS_WRONG_DISPATCH,
        probe: |activity: &RewriteActivity| activity.control_flow_switches_unflattened,
        obfuscation_is_trace_neutral: true,
    },
    FamilyWitness {
        family: RewriterFamily::SelfDefendingStrip,
        clean: WITNESS_CLEAN_GUARD,
        obfuscated: WITNESS_OBF_GUARD,
        wrong_rewrite: WITNESS_WRONG_GUARD,
        probe: |activity: &RewriteActivity| activity.unminify_protection,
        obfuscation_is_trace_neutral: false,
    },
];

fn single_outcome(program: &str, label: &str) -> EvalOutcome {
    match eval_batch_guarded(program, NO_ARGS) {
        GuardedBatch::Completed(mut evaluations) => {
            let evaluation: Result<EvalOutcome, String> = evaluations
                .pop()
                .unwrap_or_else(|| panic!("{label}: worker returned no evaluation"));
            evaluation.unwrap_or_else(|reason: String| panic!("{label}: {reason}"))
        }
        GuardedBatch::WallTimeExceeded => {
            panic!("{label}: exceeded the hard {EVAL_TIMEOUT:?} subprocess limit")
        }
        GuardedBatch::HarnessFailure(reason) => panic!("{label}: {reason}"),
    }
}

#[test]
fn a_wrong_rewrite_in_each_named_family_fails_the_differential() {
    assert_eq!(FAMILY_WITNESSES.len(), NAMED_FAMILIES.len());
    let mut aggregate: RewriteActivity = RewriteActivity::default();
    for witness in FAMILY_WITNESSES {
        let family: RewriterFamily = witness.family;
        assert!(
            NAMED_FAMILIES.contains(&family),
            "{family:?} is not one of the families this item names"
        );
        let want: EvalOutcome = single_outcome(witness.clean, "clean witness");
        let before: EvalOutcome = single_outcome(witness.obfuscated, "obfuscated witness");
        if witness.obfuscation_is_trace_neutral {
            assert_eq!(
                want, before,
                "{family:?}: the witness fixture must be behaviorally faithful before recovery"
            );
        } else {
            assert_ne!(
                want, before,
                "{family:?}: the guard this family strips must be visible in the trace before recovery, otherwise the strip is graded against nothing"
            );
        }
        let recovery: Recovery = recover_with(Pipeline::ObfuscatorIo, witness.obfuscated)
            .unwrap_or_else(|reason: String| panic!("{family:?}: recovery failed: {reason}"));
        aggregate.merge(&recovery.activity);
        let fired: u64 = (witness.probe)(&recovery.activity);
        assert!(
            fired > 0,
            "{family:?}: the witness must actually exercise the family, otherwise the wrong-rewrite check grades nothing"
        );
        let got: EvalOutcome = single_outcome(&recovery.source, "recovered witness");
        assert_eq!(
            want, got,
            "{family:?}: recovered behavior diverged from the clean original\n--recovered src--\n{}",
            recovery.source
        );
        let wrong: EvalOutcome = single_outcome(witness.wrong_rewrite, "wrong rewrite");
        assert_ne!(
            want, wrong,
            "{family:?}: a deliberately wrong rewrite of this family produced the original trace, so the differential cannot detect a wrong rewrite here"
        );
        eprintln!(
            "  {family:?}: faithful recovery verified, wrong rewrite rejected, probe fired {fired} time(s)"
        );
    }
    let witness_graded_but_silent: Vec<&'static str> = REGEX_REWRITERS
        .iter()
        .filter_map(|rewriter: &RegexRewriter| match rewriter.coverage {
            Coverage::Witness { probe, .. } if probe(&aggregate) == 0 => Some(rewriter.module),
            Coverage::Corpus { .. } | Coverage::Witness { .. } | Coverage::Ungraded(_) => None,
        })
        .collect();
    assert!(
        witness_graded_but_silent.is_empty(),
        "these modules are recorded as graded by a family witness but no witness fires them; record them ungraded with a reason instead: {witness_graded_but_silent:?}"
    );
}
