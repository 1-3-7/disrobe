import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const binary = process.env.DISROBE_BIN;
assert.ok(binary, "DISROBE_BIN must name the trusted full CLI used for capture tests");

function withCheckout(version, inspect) {
  const scratch = mkdtempSync(join(root, "docs/demo/.media-test-"));
  try {
    for (const path of [
      "docs/demo/capture-cli.mjs",
      "docs/demo/media-version.mjs",
      "corpus/native/packers/upx/hello.packed.nrv2b.exe",
      "playground/public/samples/greet.luac",
      "playground/public/samples/add.wasm",
    ]) {
      mkdirSync(dirname(join(scratch, path)), { recursive: true });
      copyFileSync(join(root, path), join(scratch, path));
    }
    writeFileSync(join(scratch, "Cargo.toml"), `[workspace.package]\nversion = "${version}"\n`);
    inspect(scratch);
  } finally {
    assert.ok(resolve(scratch).startsWith(resolve(root, "docs/demo") + sep) && basename(scratch).startsWith(".media-test-") && !lstatSync(scratch).isSymbolicLink());
    rmSync(scratch, { recursive: true });
  }
}

function runCapture(scratch, ...args) {
  const result = spawnSync(process.execPath, [join(scratch, "docs/demo/capture-cli.mjs"), "--binary", resolve(binary), ...args], {
    encoding: "utf8", timeout: 120_000, maxBuffer: 128 * 1024, windowsHide: true,
  });
  if (result.error) throw result.error;
  return result;
}

function binaryVersion() {
  const result = spawnSync(resolve(binary), ["--version"], { encoding: "utf8", timeout: 15_000, maxBuffer: 4096, windowsHide: true });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  const version = result.stdout.trim().match(/^disrobe ([^\s]+)$/u)?.[1];
  assert.ok(version);
  return version;
}

test("capture rejects a workspace version mismatch without publishing a recording", () => {
  withCheckout("999.0.0", (scratch) => {
    const result = runCapture(scratch);
    assert.notEqual(result.status, 0, "capture accepted a binary from a different workspace version");
    assert.match(result.stderr, /binary version .* does not match workspace version/u);
    assert.equal(existsSync(join(scratch, "docs/demo/cli-recording.json")), false);
  });
});

test("capture rejects a release tag mismatch without publishing a recording", () => {
  withCheckout(binaryVersion(), (scratch) => {
    const result = runCapture(scratch, "--release-tag", "v999.0.0");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /release tag v999\.0\.0 does not match workspace version/u);
    assert.equal(existsSync(join(scratch, "docs/demo/cli-recording.json")), false);
  });
});

test("matching release capture records the real binary and all six static commands", () => {
  const version = binaryVersion();
  withCheckout(version, (scratch) => {
    const result = runCapture(scratch, "--release-tag", `v${version}`);
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(readFileSync(join(scratch, "docs/demo/cli-recording.json"), "utf8"));
    assert.equal(receipt.binary.version, `disrobe ${version}`);
    assert.equal(receipt.binary.sha256, createHash("sha256").update(readFileSync(resolve(binary))).digest("hex"));
    assert.equal(receipt.workspaceVersion, version);
    assert.equal(receipt.releaseTag, `v${version}`);
    assert.deepEqual(receipt.scenes.map((scene) => scene.id), ["native", "indicators", "auto", "lua", "wasm", "source"]);
    assert.equal(receipt.scenes.reduce((sum, scene) => sum + scene.durationMs, 0), 36_000);
    assert.deepEqual([receipt.presentation.width, receipt.presentation.height, receipt.presentation.fps], [1920, 1080, 60]);
    for (const scene of receipt.scenes) assert.equal(scene.exitCode, 0);
    assert.ok(receipt.artifacts.some((artifact) => artifact.name === "recovered/add.wat"));
    const source = receipt.scenes.at(-1);
    assert.equal(source.command, process.platform === "win32" ? "Get-Content -LiteralPath recovered/add.wat" : "cat recovered/add.wat");
    assert.match(source.stdout, /i32\.add/u);
  });
});
