import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;

export function workspaceVersion(manifestPath) {
  const manifest = readFileSync(manifestPath, "utf8");
  const section = manifest.split(/^\[/mu).find((value) => value.startsWith("workspace.package]"));
  const version = section?.match(/^version\s*=\s*"([^"]+)"\s*$/mu)?.[1];
  assert.ok(version && versionPattern.test(version), "Cargo.toml must declare workspace.package.version as a version string");
  return version;
}

export function verifyMediaVersion(binaryOutput, expectedVersion, releaseTag) {
  assert.ok(versionPattern.test(expectedVersion), "workspace version is invalid");
  const version = binaryOutput.match(/^disrobe ([^\s]+)$/u)?.[1];
  assert.ok(version && versionPattern.test(version), "binary --version must report an exact disrobe version");
  assert.equal(version, expectedVersion, `binary version ${version} does not match workspace version ${expectedVersion}`);
  if (releaseTag !== undefined && releaseTag !== "latest") {
    assert.ok(releaseTag.startsWith("v") && versionPattern.test(releaseTag.slice(1)), "release tag must be v<version> or latest");
    assert.equal(releaseTag.slice(1), expectedVersion, `release tag ${releaseTag} does not match workspace version ${expectedVersion}`);
  }
  return version;
}
