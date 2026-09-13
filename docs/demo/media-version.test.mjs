import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { verifyMediaVersion, workspaceVersion } from "./media-version.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));

test("version agreement supports release tags, prereleases, and rolling latest", () => {
  for (const [version, tag] of [["1.2.3", "v1.2.3"], ["1.2.3-rc.1", "v1.2.3-rc.1"], ["1.2.3", "latest"], ["1.2.3", undefined]]) {
    assert.equal(verifyMediaVersion(`disrobe ${version}`, version, tag), version);
  }
});

test("development recordings accept absent or null tags while enforcing version agreement", () => {
  for (const releaseTag of [undefined, null]) {
    const recording = JSON.parse(JSON.stringify({ binary: { version: "disrobe 1.2.3" }, workspaceVersion: "1.2.3", releaseTag }));
    assert.equal(verifyMediaVersion(recording.binary.version, recording.workspaceVersion, recording.releaseTag), "1.2.3");
    assert.throws(() => verifyMediaVersion("disrobe 1.2.2", recording.workspaceVersion, recording.releaseTag), /binary version .* does not match/u);
    assert.throws(() => verifyMediaVersion("disrobe 1.2.3 extra", recording.workspaceVersion, recording.releaseTag), /exact disrobe version/u);
  }
});

test("version agreement rejects old binaries, mismatched tags, and ambiguous labels", () => {
  assert.throws(() => verifyMediaVersion("disrobe 1.2.2", "1.2.3", "v1.2.3"), /binary version .* does not match/u);
  assert.throws(() => verifyMediaVersion("disrobe 1.2.2", "1.2.3", "latest"), /binary version .* does not match/u);
  assert.throws(() => verifyMediaVersion("disrobe 1.2.3", "1.2.3", "v1.2.4"), /release tag .* does not match/u);
  assert.throws(() => verifyMediaVersion("disrobe 1.2.3 extra", "1.2.3", "v1.2.3"), /exact disrobe version/u);
  assert.throws(() => verifyMediaVersion("disrobe 1.2.3", "1.2.3", "nightly"), /release tag must be/u);
});

test("workspace version is read from its package section, not dependency versions", () => {
  const scratch = mkdtempSync(join(root, "docs/demo/.version-test-"));
  try {
    const manifest = join(scratch, "Cargo.toml");
    writeFileSync(manifest, '[package]\nversion = "8.0.0"\n[workspace.package]\nversion = "1.2.3"\n[dependencies.other]\nversion = "9.0.0"\n');
    assert.equal(workspaceVersion(manifest), "1.2.3");
    writeFileSync(manifest, '[package]\nversion = "1.2.3"\n');
    assert.throws(() => workspaceVersion(manifest), /workspace.package.version/u);
  } finally {
    assert.ok(resolve(scratch).startsWith(resolve(root, "docs/demo") + sep) && basename(scratch).startsWith(".version-test-") && !lstatSync(scratch).isSymbolicLink());
    rmSync(scratch, { recursive: true });
  }
});

test("renderer rejects a version mismatch before changing recorded media", () => {
  const manifestPath = join(root, "docs/src/assets/walkthrough/media.json");
  const names = ["media.json", "chapters.ffmetadata", ...JSON.parse(readFileSync(manifestPath, "utf8")).files.map((file) => file.name)];
  const hashes = () => names.map((name) => createHash("sha256").update(readFileSync(join(root, "docs/src/assets/walkthrough", name))).digest("hex"));
  const before = hashes();
  const result = spawnSync(process.execPath, [join(root, "docs/demo/render-media.mjs"), "--release-tag", "v999.0.0"], {
    encoding: "utf8", timeout: 15_000, maxBuffer: 128 * 1024, windowsHide: true,
  });
  if (result.error) throw result.error;
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /(?:binary version|release tag) .* does not match workspace version/u);
  assert.deepEqual(hashes(), before);
});
