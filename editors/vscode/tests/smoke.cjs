const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFile, writeFile } = require("node:fs/promises");
const { join } = require("node:path");
const vscode = require("vscode");

exports.run = async function run() {
  const binary = process.env.DISROBE_DEMO_BINARY;
  const receipt = process.env.DISROBE_DEMO_RECEIPT;
  assert(binary, "DISROBE_DEMO_BINARY must identify the tested Disrobe binary");
  assert(receipt, "DISROBE_DEMO_RECEIPT must identify the capture output");
  const settings = vscode.workspace.getConfiguration("disrobe");
  await settings.update("lsp.enable", false, vscode.ConfigurationTarget.Global);
  await settings.update("executablePath", binary, vscode.ConfigurationTarget.Global);
  const extension = vscode.extensions.getExtension("disrobe.disrobe");
  assert(extension, "Disrobe extension is not available in the extension host");
  await extension.activate();
  assert.equal(extension.isActive, true);
  const commands = await vscode.commands.getCommands(true);
  const expected = ["auto", "detect", "strings", "ioc", "behavior", "identify", "scan", "startServer", "stopServer", "showOutput"].map((name) => `disrobe.${name}`);
  for (const command of expected) assert(commands.includes(command), `${command} was not registered`);
  await vscode.commands.executeCommand("disrobe.startServer");
  await vscode.commands.executeCommand("disrobe.stopServer");
  await vscode.commands.executeCommand("disrobe.startServer");
  await vscode.commands.executeCommand("disrobe.stopServer");
  await Promise.all([
    vscode.commands.executeCommand("disrobe.startServer"),
    vscode.commands.executeCommand("disrobe.stopServer"),
  ]);
  const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
  await writeFile(receipt, JSON.stringify({
    schema: "disrobe.demo.vscode/v1", captured_at: new Date().toISOString(),
    vscode_version: vscode.version, extension_version: extension.packageJSON.version,
    binary_sha256: hash(await readFile(binary)),
    extension_sha256: hash(await readFile(join(__dirname, "../out/extension.js"))),
    registered_commands: expected, activation: "passed", start_stop_cycles: 3,
    concurrent_start_stop: "passed",
  }, null, 2) + "\n");
};
