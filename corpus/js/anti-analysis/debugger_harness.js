const inspector = require("node:inspector");
const path = require("node:path");

const PAUSE_LIMIT = 64;
const session = new inspector.Session();
session.connect();
let pauses = 0;
session.on("Debugger.paused", () => {
  pauses += 1;
  if (pauses >= PAUSE_LIMIT) {
    session.post("Debugger.setSkipAllPauses", { skip: true });
  }
  session.post("Debugger.resume");
});
session.post("Debugger.enable");
process.on("exit", () => {
  const suffix = pauses >= PAUSE_LIMIT ? " (limit reached)" : "";
  process.stdout.write("debugger pauses: " + pauses + suffix + "\n");
});
require(path.resolve(process.argv[2]));
