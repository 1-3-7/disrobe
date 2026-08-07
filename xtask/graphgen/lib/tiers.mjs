import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./data.mjs";

export const STRONG = "strong";
export const RECOMPILE_ONLY = "recompile-only";
export const PASS_GATED = "pass-gated";
export const SELF_REPORTED = "coverage-self-reported";

export const TIERS = [
  { strength: STRONG, label: "strong", tag: "strong", color: "#d8e5f4" },
  {
    strength: RECOMPILE_ONLY,
    label: "recompile-only",
    tag: "recompile",
    color: "#9fbfe0",
  },
  {
    strength: PASS_GATED,
    label: "pass-gated",
    tag: "pass-gated",
    color: "#6d8bab",
  },
  {
    strength: SELF_REPORTED,
    label: "coverage-self-reported",
    tag: "self-reported",
    color: "#4a5a6b",
  },
];

export const REPRODUCIBILITY = [
  { ci: true, tag: "CI", label: "a committed gate reproduces it on every run" },
  { ci: false, tag: "local", label: "local input, the stated command reproduces it" },
];

const BY_STRENGTH = new Map(TIERS.map((tier) => [tier.strength, tier]));

const DESCRIPTOR_DIR = join(ROOT, "evidence", "descriptors");

const UNBOUND_INSTRUMENT_TIERS = [
  {
    instrument: "crates/disrobe-pass-dotnet/tests/obfuscar_gauntlet.rs",
    strength: STRONG,
    ci: true,
    quoted:
      "requires the complete recovered method-token-to-byte map to equal the independently generated CLR runtime accessor map",
  },
  {
    instrument: "crates/disrobe-pass-dotnet/tests/smartassembly_resources.rs",
    strength: STRONG,
    ci: true,
    quoted:
      "requires exactly one [z]payload resource, byte equality with the independently compiled clean DLL, and the encrypted-resource extraction strategy",
  },
  {
    instrument: "crates/disrobe-pass-go/tests/go_published_function_name_bars.rs",
    strength: STRONG,
    ci: true,
    quoted: "against the committed `go tool nm` symbol dump beside it",
  },
];

const UNBOUND_BAR_TIERS = [
  {
    group: "Detection and routing rosters (counts)",
    bar: ".NET protectors",
    strength: SELF_REPORTED,
    ci: true,
    quoted: "This is a detection roster, not an aggregate claim",
  },
  {
    group: "Detection and routing rosters (counts)",
    bar: "Python source obfuscators",
    strength: SELF_REPORTED,
    ci: true,
    quoted: "This is a routing roster, not an aggregate source-recovery measurement",
  },
  {
    group: "Detection and routing rosters (counts)",
    bar: "JVM / Android families",
    strength: SELF_REPORTED,
    ci: true,
    quoted: "This is a routing roster, not an aggregate recovered-body measurement",
  },
  {
    group: "Detection and routing rosters (counts)",
    bar: "Shell obfuscation modes",
    strength: SELF_REPORTED,
    ci: true,
    quoted: "This is a routing roster, not a reversal rate",
  },
  {
    group: "Obfuscator and bundler family coverage (counts)",
    bar: "JS bundlers",
    strength: SELF_REPORTED,
    ci: true,
    quoted: "so 12 variants render as 11 published bundlers",
  },
  {
    group: "Obfuscator and bundler family coverage (counts)",
    bar: "Lua chain catalog entries",
    strength: SELF_REPORTED,
    ci: true,
    quoted: "obfuscator entries plus Luau and GLua dialect detectors",
  },
  {
    group: "Obfuscator and bundler family coverage (counts)",
    bar: "Lua VM-devirt on an in-house sample only (MoonSec shape, no real sample)",
    strength: SELF_REPORTED,
    ci: true,
    quoted:
      "It records shape recovery only and is not evidence that any named obfuscator's own output was reversed",
  },
  {
    group: "Obfuscator and bundler family coverage (counts)",
    bar: "WASM direct transformation helper families",
    strength: SELF_REPORTED,
    ci: true,
    quoted: "This is a source catalog count, not a measured claim",
  },
  {
    group:
      "React Native Hermes production-bundle parse scale (local non-redistributable bundle, secondary, not CI-gated)",
    bar: "functions parsed",
    strength: SELF_REPORTED,
    ci: false,
    quoted: "local-only, fixture is gitignored",
  },
  {
    group:
      "Flutter Dart AOT RAW static recovery on a real RustDesk 1.4.9 libapp.so (local fetched-by-hash sample, not CI-gated)",
    bar: "function boundaries recovered",
    strength: SELF_REPORTED,
    ci: false,
    quoted: "local-only, the APK is fetched by pinned url and sha256",
  },
];

const SECTION = /^\[([A-Za-z_][A-Za-z0-9_]*)\]$/;
const STRING_PAIR = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*)"$/;
const BOOL_PAIR = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(true|false)$/;
const INSTRUMENT = /[A-Za-z0-9_./-]+\.(?:rs|py)/g;

export function tierFor(strength) {
  const tier = BY_STRENGTH.get(strength);
  if (!tier) {
    throw new Error(
      `no chart tier is defined for grading strength "${strength}"; the four tiers are ` +
        `${[...BY_STRENGTH.keys()].join(", ")}`,
    );
  }
  return tier;
}

export function reproducibilityFor(ci) {
  const found = REPRODUCIBILITY.find((entry) => entry.ci === ci);
  if (!found) {
    throw new Error(`reproducibility must be a boolean, got ${JSON.stringify(ci)}`);
  }
  return found;
}

function barKey(heading, label) {
  return `${heading} :: ${label}`;
}

function instrumentsOf(source) {
  const found = new Set();
  for (const match of String(source).matchAll(INSTRUMENT)) found.add(match[0]);
  return found;
}

function readDescriptor(file) {
  let section = "";
  let strength = null;
  let ci = null;
  let group = null;
  let bar = null;
  for (const raw of readFileSync(join(DESCRIPTOR_DIR, file), "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    const header = line.match(SECTION);
    if (header) {
      section = header[1];
      continue;
    }
    const bool = line.match(BOOL_PAIR);
    if (bool && section === "" && bool[1] === "ci") {
      ci = bool[2] === "true";
      continue;
    }
    const pair = line.match(STRING_PAIR);
    if (!pair) continue;
    const [, key, value] = pair;
    if (section === "" && key === "oracle_strength") strength = value;
    if (section === "source" && key === "recovery_group") group = value;
    if (section === "source" && key === "recovery_bar") bar = value;
  }
  return { strength, ci, group, bar };
}

function declaredBindings() {
  const bindings = new Map();
  for (const file of readdirSync(DESCRIPTOR_DIR).sort()) {
    if (!file.endsWith(".toml")) continue;
    const { strength, ci, group, bar } = readDescriptor(file);
    if (strength === null || group === null || bar === null) continue;
    tierFor(strength);
    if (ci === null) {
      throw new Error(
        `evidence/descriptors/${file} binds a recovery chart bar but declares no ci boolean, so ` +
          "the chart cannot say whether a committed gate reproduces the number; add ci = true or " +
          "ci = false",
      );
    }
    const key = barKey(group, bar);
    const prior = bindings.get(key);
    if (prior && (prior.strength !== strength || prior.ci !== ci)) {
      throw new Error(
        `evidence/descriptors/${file} and evidence/descriptors/${prior.descriptor} both bind ` +
          `recovery.json bar "${key}" but disagree about how it is graded ` +
          `("${strength}" ci=${ci} against "${prior.strength}" ci=${prior.ci}); one of them is wrong`,
      );
    }
    bindings.set(key, { strength, ci, descriptor: file });
  }
  return bindings;
}

const LOCAL_DECLARATIONS = [
  "local-only",
  "gitignored",
  "uncommitted",
  "run locally",
  "not CI-gated",
  "No gate asserts this number",
  "CI does not run",
  "CI does not provision",
];

const CI_INSTRUMENT = /^(?:crates|benches)\/[A-Za-z0-9_.-]+\/(?:src|tests)\/[A-Za-z0-9_./-]+\.rs$/;

function addSeed(seeds, instrument, strength) {
  const seen = seeds.get(instrument);
  if (seen) {
    seen.add(strength);
    return;
  }
  seeds.set(instrument, new Set([strength]));
}

function reproducibilityOf(entry) {
  const declared = LOCAL_DECLARATIONS.find(
    (phrase) => entry.text.includes(phrase) || entry.label.includes("(local"),
  );
  if (declared !== undefined) {
    return { ci: false, why: `the bar's own text records "${declared}"` };
  }
  if (entry.gate !== null && entry.gateFunction !== null && CI_INSTRUMENT.test(entry.gate)) {
    return { ci: true, why: `the committed gate ${entry.gate}::${entry.gateFunction}` };
  }
  return {
    ci: false,
    why: "no committed gate is cited for this bar, so the chart does not claim a run reproduces it",
  };
}

function everyBar(doc) {
  const bars = [];
  for (const group of doc.groups) {
    for (const bar of group.bars) {
      const source = bar.source === undefined ? "" : String(bar.source);
      const detail = bar.detail === undefined ? "" : String(bar.detail);
      const gate =
        bar.verified_by && typeof bar.verified_by.path === "string"
          ? bar.verified_by.path
          : null;
      const gateFunction =
        bar.verified_by && typeof bar.verified_by.function === "string"
          ? bar.verified_by.function
          : null;
      bars.push({
        key: barKey(group.heading, bar.label),
        group: group.heading,
        label: bar.label,
        kind: group.kind,
        source,
        gate,
        gateFunction,
        text: `${source}\n${detail}`,
        instruments: instrumentsOf(source),
      });
    }
  }
  return bars;
}

function applyUnboundInstruments(bars, seeds) {
  for (const manual of UNBOUND_INSTRUMENT_TIERS) {
    tierFor(manual.strength);
    reproducibilityFor(manual.ci);
    const citing = bars.filter((entry) => entry.instruments.has(manual.instrument));
    if (citing.length === 0) {
      throw new Error(
        `the chart's fallback grading table still carries ${manual.instrument}, but no bar in ` +
          "recovery.json cites it any more; drop the stale entry",
      );
    }
    for (const entry of citing) {
      if (!entry.source.includes(manual.quoted)) {
        throw new Error(
          `the chart's fallback grading table calls ${manual.instrument} "${manual.strength}" on ` +
            `the strength of the phrase "${manual.quoted}", which recovery.json's bar ` +
            `"${entry.key}" no longer contains; re-read how that bar is now checked before ` +
            "restating its tier",
        );
      }
    }
    addSeed(seeds, manual.instrument, manual.strength);
  }
}

function applyUnboundBars(bars, declared, resolved) {
  const known = new Map(bars.map((entry) => [entry.key, entry]));
  for (const manual of UNBOUND_BAR_TIERS) {
    tierFor(manual.strength);
    reproducibilityFor(manual.ci);
    const key = barKey(manual.group, manual.bar);
    const entry = known.get(key);
    if (!entry) {
      throw new Error(
        `the chart's fallback grading table still tiers recovery.json bar "${key}", which the ` +
          "data file no longer carries; drop the stale entry",
      );
    }
    if (declared.has(key)) {
      throw new Error(
        `recovery.json bar "${key}" now has an evidence descriptor, so the chart's fallback ` +
          "grading table entry for it is dead and could contradict the evidence; drop it",
      );
    }
    if (!entry.source.includes(manual.quoted)) {
      throw new Error(
        `the chart's fallback grading table calls recovery.json bar "${key}" ` +
          `"${manual.strength}" on the strength of the phrase "${manual.quoted}", which that ` +
          "bar's own source text no longer contains; re-read how the bar is now checked before " +
          "restating its tier",
      );
    }
    const reproducibility = reproducibilityOf(entry);
    if (reproducibility.ci !== manual.ci) {
      throw new Error(
        `the chart's fallback grading table says recovery.json bar "${key}" is ` +
          `${manual.ci ? "CI" : "local"}, but ${reproducibility.why} makes it ` +
          `${reproducibility.ci ? "CI" : "local"}; the bar's own record wins, so correct the table`,
      );
    }
    resolved.set(key, {
      strength: manual.strength,
      ci: reproducibility.ci,
      via: `the bar's own recorded source text, ${reproducibility.why}`,
    });
  }
}

function bindingDigest(declared) {
  const hash = createHash("sha256");
  for (const key of [...declared.keys()].sort()) {
    const binding = declared.get(key);
    hash.update(`${key} ${binding.strength} ${binding.ci}\n`);
  }
  return hash.digest("hex").slice(0, 32);
}

export function barTiers(doc) {
  const declared = declaredBindings();
  const bars = everyBar(doc);

  const resolved = new Map();
  const seeds = new Map();
  for (const entry of bars) {
    const binding = declared.get(entry.key);
    if (!binding) continue;
    resolved.set(entry.key, {
      strength: binding.strength,
      ci: binding.ci,
      via: `evidence/descriptors/${binding.descriptor}`,
    });
    for (const instrument of entry.instruments) {
      addSeed(seeds, instrument, binding.strength);
    }
  }

  applyUnboundInstruments(bars, seeds);
  applyUnboundBars(bars, declared, resolved);

  for (const entry of bars) {
    if (resolved.has(entry.key)) continue;
    const strengths = new Set();
    const cited = [];
    for (const instrument of entry.instruments) {
      const seen = seeds.get(instrument);
      if (!seen) continue;
      cited.push(instrument);
      for (const strength of seen) strengths.add(strength);
    }
    if (strengths.size > 1) {
      throw new Error(
        `recovery.json bar "${entry.key}" cites instruments graded more than one way ` +
          `(${[...strengths].join(", ")} via ${cited.join(", ")}), so the chart cannot color it; ` +
          "give the bar its own evidence descriptor",
      );
    }
    if (strengths.size === 0) {
      throw new Error(
        `recovery.json bar "${entry.key}" carries no recorded grading strength: no ` +
          "evidence/descriptors/*.toml binds it through [source] recovery_group / recovery_bar, and " +
          "nothing it cites is tied to a tier. the chart refuses to draw it in the strongest color " +
          "on no evidence, because that is the defect this coloring exists to prevent. add a " +
          "descriptor with an oracle_strength of strong, recompile-only, pass-gated or " +
          "coverage-self-reported, or add the bar to UNBOUND_BAR_TIERS in " +
          "xtask/graphgen/lib/tiers.mjs quoting the bar's own source text",
      );
    }
    const reproducibility = reproducibilityOf(entry);
    resolved.set(entry.key, {
      strength: [...strengths][0],
      ci: reproducibility.ci,
      via: `the grading instrument ${cited.join(", ")}, ${reproducibility.why}`,
    });
  }

  return { key: barKey, resolved, digest: bindingDigest(declared) };
}
