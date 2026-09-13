import assert from "node:assert/strict";
import test from "node:test";
import { commandGroups, publicCommands, scenes } from "./cli-plan.mjs";

const names = commandGroups.flatMap((group) => group.commands);
const help = `Usage: disrobe <COMMAND>\n\nCommands:\n${names.map((name) => `  ${name}  description`).join("\n")}\n\nOptions:\n  --help  Print help\n`;

test("the inventory refuses added and missing public commands", () => {
  assert.equal(names.length, 66);
  assert.equal(new Set(names).size, names.length);
  assert.deepEqual(publicCommands(help), names);
  assert.throws(() => publicCommands(help.replace("  native  description\n", "")), /update the command inventory/u);
  assert.throws(() => publicCommands(help.replace("\nOptions:", "\n  new-command  description\n\nOptions:")), /update the command inventory/u);
});

test("the walkthrough demonstrates capabilities and does not execute its input", () => {
  assert.equal(scenes.length, 20);
  assert.equal(new Set(scenes.map((scene) => scene.id)).size, 20);
  assert.equal(new Set(scenes.map((scene) => scene.chapter)).size, 5);
  for (const scene of scenes) {
    assert.ok(names.includes(scene.argv[0]));
    assert.equal(scene.argv.includes("--help"), false);
    assert.equal(scene.argv.includes("--allow-dynamic"), false);
  }
  assert.ok(scenes.find((scene) => scene.id === "python").argv.includes("--no-roundtrip"));
});
