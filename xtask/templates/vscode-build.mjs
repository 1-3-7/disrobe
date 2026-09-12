import { build, context } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";

const options = {
  entryPoints: ["src/extension.ts"], bundle: true, platform: "node", target: "node18",
  format: "cjs", external: ["vscode"], minify: true, legalComments: "linked",
  outfile: "out/extension.js",
};
mkdirSync("out", { recursive: true });
copyFileSync("node_modules/vscode-languageclient/lib/node/terminateProcess.sh", "out/terminateProcess.sh");
if (process.argv.includes("--watch")) {
  const watcher = await context(options);
  await watcher.watch();
} else {
  await build(options);
}
