import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./data.mjs";
import { C } from "./kit.mjs";

export const STRONG = "strong";
export const RECOMPILE_ONLY = "recompile-only";
export const SELF_REPORTED = "coverage-self-reported";

export const TIERS = [
  { strength: STRONG, label: "strong", color: C.accent },
  { strength: RECOMPILE_ONLY, label: "recompile-only", color: C.amber },
  { strength: SELF_REPORTED, label: "self-reported coverage", color: C.faint },
];

const BY_STRENGTH = new Map(TIERS.map((tier) => [tier.strength, tier]));

const DESCRIPTOR_DIR = join(ROOT, "evidence", "descriptors");

const UNBOUND_INSTRUMENT_TIERS = [
  {
    instrument: "crates/disrobe-pass-go/tests/go_cross_arch_va_recovery.rs",
    strength: STRONG,
    quoted: "grades every recovered name against go tool nm on the same build",
  },
];

const SECTION = /^\[([A-Za-z_][A-Za-z0-9_]*)\]$/;
const PAIR = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(.*)"$/;
const INSTRUMENT = /[A-Za-z0-9_./-]+\.(?:rs|py)/g;

export function tierFor(strength) {
  const tier = BY_STRENGTH.get(strength);
  if (!tier) {
    throw new Error(
      `no chart tier is defined for grading strength "${strength}"; the three tiers are ` +
        `${[...BY_STRENGTH.keys()].join(", ")}`,
    );
  }
  return tier;
}

function barKey(heading, label) {
  return `${heading} :: ${label}`;
}

function instrumentsOf(source) {
  const found = new Set();
  for (const match of String(source).matchAll(INSTRUMENT)) found.add(match[0]);
  return found;
}

function declaredBindings() {
  const bindings = new Map();
  for (const file of readdirSync(DESCRIPTOR_DIR)) {
    if (!file.endsWith(".toml")) continue;
    let section = "";
    let strength = null;
    let group = null;
    let bar = null;
    for (const raw of readFileSync(join(DESCRIPTOR_DIR, file), "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      const header = line.match(SECTION);
      if (header) {
        section = header[1];
        continue;
      }
      const pair = line.match(PAIR);
      if (!pair) continue;
      const [, key, value] = pair;
      if (section === "" && key === "oracle_strength") strength = value;
      if (section === "source" && key === "recovery_group") group = value;
      if (section === "source" && key === "recovery_bar") bar = value;
    }
    if (strength === null || group === null || bar === null) continue;
    tierFor(strength);
    const key = barKey(group, bar);
    const prior = bindings.get(key);
    if (prior && prior.strength !== strength) {
      throw new Error(
        `evidence/descriptors/${file} and evidence/descriptors/${prior.descriptor} both bind ` +
          `recovery.json bar "${key}" but declare different grading strengths ` +
          `("${strength}" and "${prior.strength}"); one of them is wrong`,
      );
    }
    bindings.set(key, { strength, descriptor: file });
  }
  return bindings;
}

function addSeed(seeds, instrument, strength) {
  const seen = seeds.get(instrument);
  if (seen) seen.add(strength);
  else seeds.set(instrument, new Set([strength]));
}

export function percentBarTiers(doc) {
  const declared = declaredBindings();
  const bars = [];
  for (const group of doc.groups) {
    if (group.kind !== "percent") continue;
    for (const bar of group.bars) {
      bars.push({
        key: barKey(group.heading, bar.label),
        instruments: instrumentsOf(bar.source),
        source: bar.source,
      });
    }
  }

  const resolved = new Map();
  const seeds = new Map();
  for (const entry of bars) {
    const binding = declared.get(entry.key);
    if (!binding) continue;
    resolved.set(entry.key, {
      strength: binding.strength,
      via: `evidence/descriptors/${binding.descriptor}`,
    });
    for (const instrument of entry.instruments) addSeed(seeds, instrument, binding.strength);
  }

  for (const manual of UNBOUND_INSTRUMENT_TIERS) {
    tierFor(manual.strength);
    const citing = bars.filter((entry) => entry.instruments.has(manual.instrument));
    if (citing.length === 0) {
      throw new Error(
        `the chart's fallback grading-strength table still carries ${manual.instrument}, but no ` +
          "percentage bar in recovery.json cites it any more; drop the stale entry",
      );
    }
    for (const entry of citing) {
      if (!entry.source.includes(manual.quoted)) {
        throw new Error(
          `the chart's fallback grading-strength table calls ${manual.instrument} "${manual.strength}" ` +
            `on the strength of the phrase "${manual.quoted}", which recovery.json's bar "${entry.key}" ` +
            "no longer contains; re-read how that bar is now checked before restating its tier",
        );
      }
    }
    addSeed(seeds, manual.instrument, manual.strength);
  }

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
        `recovery.json bar "${entry.key}" cites instruments of more than one grading strength ` +
          `(${[...strengths].join(", ")} via ${cited.join(", ")}), so the chart cannot color it; ` +
          "give the bar its own evidence descriptor",
      );
    }
    if (strengths.size === 0) {
      throw new Error(
        `recovery.json bar "${entry.key}" carries no recorded grading strength: no ` +
          "evidence/descriptors/*.toml binds it through [source] recovery_group / recovery_bar, and " +
          "nothing it cites is tied to a tier. the chart refuses to draw it in the strong color on " +
          "no evidence, because that is the defect this coloring exists to prevent. add a descriptor " +
          "with an oracle_strength of strong, recompile-only or coverage-self-reported, or add the bar's " +
          "grading instrument to UNBOUND_INSTRUMENT_TIERS in xtask/graphgen/lib/tiers.mjs quoting the " +
          "bar's own source text",
      );
    }
    resolved.set(entry.key, {
      strength: [...strengths][0],
      via: `the grading instrument ${cited.join(", ")}`,
    });
  }

  return { key: barKey, resolved };
}
