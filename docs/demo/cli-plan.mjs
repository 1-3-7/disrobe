import assert from "node:assert/strict";

export const fixtures = [
  ["corpus/native/packers/upx/hello.packed.nrv2b.exe", "hello.packed.exe"],
  ["playground/public/samples/hello.pyc", "hello.pyc"],
  ["playground/public/samples/greet.luac", "greet.luac"],
  ["playground/public/samples/webpack-bundle.js", "bundle.js"],
  ["playground/public/samples/esbuild-bundle.js.map", "bundle.js.map"],
  ["playground/public/samples/add.wasm", "add.wasm"],
  ["corpus/apk/fixture-v2v3-signed.apk", "fixture.apk"],
];

export const commandGroups = [
  { title: "Recover", commands: ["auto", "chain", "extract", "webview", "pyarmor", "pyinstaller", "pyfreeze", "nuitka"] },
  { title: "Languages and runtimes", commands: ["py", "js", "wasm", "native", "jvm", "apk", "dotnet", "hermes", "macho", "lua", "php", "shell", "ruby", "beam", "pickle", "go", "swift", "flutter", "mobile"] },
  { title: "Inspect and compare", commands: ["identify", "detect", "catalog", "scan", "ioc", "indicators", "frisk", "prowl", "strings", "behavior", "yara", "query", "capabilities", "taint", "semdiff", "vulnmatch", "diff"] },
  { title: "Evidence and reports", commands: ["envelope", "verify", "guard", "status", "context", "report", "annot", "rename"] },
  { title: "Integrate and configure", commands: ["serve", "plugin", "init", "config", "completions", "man", "doctor", "install", "install-deps", "self-update", "bug-report", "explain", "passes", "help"] },
];

export const scenes = [
  { id: "identify", chapter: "Unpack and route", title: "Recognize the packed executable", description: "Inspect the file's packer evidence before choosing a recovery path.", argv: ["identify", "hello.packed.exe"], markers: ["UPX"] },
  { id: "native", chapter: "Unpack and route", title: "Unpack the native payload", description: "Recover the UPX payload as a separate binary.", argv: ["native", "unpack", "hello.packed.exe", "--out", "recovered/hello.bin"], markers: ["upx", "recovered:"] },
  { id: "extract", chapter: "Unpack and route", title: "Open the application container", description: "Extract the APK's archive members into a directory.", argv: ["extract", "fixture.apk", "--out", "recovered/archive"], markers: ["recovered/archive"] },
  { id: "auto", chapter: "Unpack and route", title: "Let Disrobe choose the passes", description: "Keep the recovery report and each executed stage's output.", argv: ["auto", "add.wasm", "--out", "recovered/auto", "--capture-stages"], markers: ["chain.json", "recovery.json"] },
  { id: "python", chapter: "Recover readable code", title: "Recover Python from bytecode", description: "Decompile the code object without invoking Python for a round-trip check.", argv: ["py", "decompile", "hello.pyc", "--out", "recovered/python", "--no-roundtrip"], markers: ["recovered/python"], preview: { directory: "recovered/python", suffix: ".py" } },
  { id: "lua", chapter: "Recover readable code", title: "Read the Lua program", description: "Turn the compiled chunk into Lua source.", argv: ["lua", "decompile", "greet.luac", "--out", "recovered/greet.lua"], markers: ["fidelity"], preview: { path: "recovered/greet.lua" } },
  { id: "unbundle", chapter: "Recover readable code", title: "Separate the bundled modules", description: "Split the Webpack bundle into individual module files.", argv: ["js", "unbundle", "bundle.js", "--out", "recovered/modules"], markers: ["modules:", "webpack"], preview: { directory: "recovered/modules", suffix: "geometry.js.js", contains: "const PI_APPROX", lineCount: 6 } },
  { id: "sourcemap", chapter: "Recover readable code", title: "Restore the embedded originals", description: "Write the original sources retained in the source map.", argv: ["js", "sourcemap", "bundle.js.map", "--out", "recovered/sources"], markers: ["recovered/sources"], preview: { directory: "recovered/sources", suffix: "math.js" } },
  { id: "wasm", chapter: "Recover readable code", title: "Read WebAssembly instructions", description: "The WAT retains the exported add function and its i32.add instruction.", argv: ["wasm", "decompile", "add.wasm", "--target", "wat", "--out", "recovered/add.wat"], markers: ["target=wat"], preview: { path: "recovered/add.wat", contains: "(module" } },
  { id: "apk", chapter: "Inspect the evidence", title: "Decode Android resources", description: "Read the package, resource names and decoded manifest.", argv: ["apk", "fixture.apk", "--out", "recovered/android"], markers: ["com.disrobe.fixture"], outputLineCount: 9, preview: { path: "recovered/android/AndroidManifest.xml" } },
  { id: "indicators", chapter: "Inspect the evidence", title: "Extract indicators", description: "Find the URL, email address and documentation-range IP in these input bytes.", argv: ["ioc", "indicators.txt"], markers: ["https://example.org/download", "analyst@example.org", "192.0.2.42"] },
  { id: "strings", chapter: "Inspect the evidence", title: "Inspect the original strings", description: "List printable strings with decoding disabled.", argv: ["strings", "indicators.txt", "--no-decode"], markers: ["https://example.org/download", "analyst@example.org"] },
  { id: "context", chapter: "Keep the recovery evidence", title: "Review the chain's verdict", description: "Read the pass status and producer-reported recovery tiers.", argv: ["context", "--out", "recovered/auto"], markers: ["verdict:", "passes:"] },
  { id: "report", chapter: "Keep the recovery evidence", title: "Export the completed run", description: "Save a Markdown report from the existing recovery directory.", argv: ["report", "recovered/auto", "--format", "markdown"], redirect: "recovered/report.md", markers: ["#"], preview: { path: "recovered/report.md", contains: "| field | value |", lineCount: 10 } },
  { id: "envelope", chapter: "Keep the recovery evidence", title: "Package the original bytes", description: "Create a Raw-rung envelope carrying the WebAssembly input.", argv: ["envelope", "create", "add.wasm", "--out", "recovered/add.dr", "--format", "wasm", "--no-cache"], markers: ["Raw", "recovered/add.dr"] },
  { id: "verify", chapter: "Keep the recovery evidence", title: "Verify the envelope hash", description: "Check the stored payload against its BLAKE3 root hash.", argv: ["verify", "recovered/add.dr"], markers: ["verify: OK", "Raw"] },
  { id: "init", chapter: "Work with your tools", title: "Create an IDE workspace", description: "Generate the workspace and Claude integration files in this project.", argv: ["init", "--ide", "claude"], markers: ["created:", "settings.json"] },
  { id: "rename", chapter: "Work with your tools", title: "Keep a named analyst note", description: "Record the proposed symbol name separately from recovered evidence.", argv: ["rename", "func_0", "add", "--note", "two integer inputs"], markers: ["add"], preview: { path: ".disrobe/notes/renames.json", maximumRows: 11 } },
  { id: "config", chapter: "Work with your tools", title: "Write the project configuration", description: "Generate the documented configuration template.", argv: ["config", "init"], markers: [".disrobe.toml"], preview: { path: ".disrobe.toml", contains: "[output]", lineCount: 9 } },
  { id: "completions", chapter: "Work with your tools", title: "Add shell completions", description: "Generate the Bash completion script as a file.", argv: ["completions", "bash"], redirect: "recovered/disrobe.bash", markers: ["_disrobe()"], preview: { path: "recovered/disrobe.bash", contains: "if [[ \"${BASH_VERSINFO[0]}\" -eq 4" } },
].map((scene) => ({ durationMs: 6_000, ...scene }));

export const presentation = { width: 1920, height: 1080, fps: 60, openingMs: 4_000, closingMs: 8_000, timing: "Edited command entry and reading time; elapsedMs records each process separately." };
export const teaserIds = ["native", "sourcemap", "wasm", "init"];
export const commandTimeoutMs = 30_000;

export function publicCommands(help) {
  const section = help.split("Commands:\n")[1]?.split("\nOptions:")[0];
  assert.ok(section, "the CLI must expose its public command list");
  const names = [...section.matchAll(/^  ([a-z][a-z-]*)\s{2,}/gmu)].map((match) => match[1]);
  assert.ok(names.length > 0);
  assert.deepEqual([...names].sort(), commandGroups.flatMap((group) => group.commands).sort(), "update the command inventory to match this CLI build");
  return names;
}

export function validateRecording(receipt) {
  assert.equal(receipt.schema, "disrobe.cli-recording.v2");
  assert.deepEqual(receipt.presentation, presentation);
  assert.deepEqual(receipt.scenes.map((scene) => scene.id), scenes.map((scene) => scene.id));
  assert.deepEqual(receipt.catalog.commands, publicCommands(receipt.catalog.stdout));
  for (const [index, scene] of receipt.scenes.entries()) {
    assert.deepEqual(scene.argv, ["disrobe", ...scenes[index].argv]);
    assert.equal(scene.exitCode, 0);
    assert.equal(scene.durationMs, scenes[index].durationMs);
    assert.ok(Number.isFinite(scene.elapsedMs) && scene.elapsedMs >= 0 && scene.elapsedMs < commandTimeoutMs);
    for (const marker of scenes[index].markers) assert.ok((scene.stdout + scene.stderr).toLowerCase().includes(marker.toLowerCase()), `${scene.id}: missing ${marker}`);
  }
}
