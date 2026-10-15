"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function parseArgs(argv) {
  const args = { optimize: false, viaIr: false, bytecodeHash: null, appendCbor: true, sources: [] };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = () => {
      i += 1;
      if (i >= argv.length) {
        throw new Error(`${flag} needs a value`);
      }
      return argv[i];
    };
    switch (flag) {
      case "--solc":
        args.solc = value();
        break;
      case "--out":
        args.out = value();
        break;
      case "--optimize":
        args.optimize = true;
        break;
      case "--via-ir":
        args.viaIr = true;
        break;
      case "--bytecode-hash":
        args.bytecodeHash = value();
        break;
      case "--no-cbor":
        args.appendCbor = false;
        break;
      case "--source":
        args.sources.push(value());
        break;
      default:
        throw new Error(`unknown flag ${flag}`);
    }
  }
  if (!args.solc || !args.out || args.sources.length === 0) {
    throw new Error("usage: build.cjs --solc <solc module dir> --out <dir> --source <file.sol>... [--optimize] [--via-ir] [--bytecode-hash ipfs|bzzr1|none] [--no-cbor]");
  }
  return args;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function constantGetters(ast) {
  const out = {};
  const visit = (node, contract) => {
    if (!node || typeof node !== "object") {
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((child) => visit(child, contract));
      return;
    }
    let current = contract;
    if (node.nodeType === "ContractDefinition") {
      current = node.name;
      out[current] = out[current] || [];
    }
    if (
      node.nodeType === "VariableDeclaration" &&
      node.stateVariable === true &&
      node.visibility === "public" &&
      (node.constant === true || node.mutability === "constant" || node.mutability === "immutable")
    ) {
      out[current].push(node.name);
    }
    for (const key of Object.keys(node)) {
      if (key !== "nodeType") {
        visit(node[key], current);
      }
    }
  };
  visit(ast, null);
  return out;
}

function requireMessages(ast) {
  const out = {};
  const visit = (node, contract, inConstructor) => {
    if (!node || typeof node !== "object") {
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((child) => visit(child, contract, inConstructor));
      return;
    }
    let current = contract;
    let constructor = inConstructor;
    if (node.nodeType === "ContractDefinition") {
      current = node.name;
      out[current] = out[current] || new Set();
    }
    if (node.nodeType === "FunctionDefinition") {
      constructor = node.kind === "constructor" || node.isConstructor === true;
    }
    if (
      !constructor &&
      node.nodeType === "FunctionCall" &&
      node.expression &&
      node.expression.name === "require" &&
      Array.isArray(node.arguments) &&
      node.arguments.length === 2 &&
      node.arguments[1].nodeType === "Literal" &&
      node.arguments[1].kind === "string"
    ) {
      out[current].add(node.arguments[1].value);
    }
    for (const key of Object.keys(node)) {
      if (key !== "nodeType") {
        visit(node[key], current, constructor);
      }
    }
  };
  visit(ast, null, false);
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const solc = require(path.resolve(args.solc));
  const here = __dirname;
  const sources = {};
  for (const source of args.sources) {
    sources[source] = { content: fs.readFileSync(path.join(here, "src", source), "utf8") };
  }
  const settings = {
    optimizer: { enabled: args.optimize, runs: 200 },
    outputSelection: {
      "*": {
        "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object", "evm.methodIdentifiers"],
        "": ["ast"],
      },
    },
  };
  if (args.viaIr) {
    settings.viaIR = true;
  }
  if (args.bytecodeHash !== null || !args.appendCbor) {
    settings.metadata = {};
    if (args.bytecodeHash !== null) {
      settings.metadata.bytecodeHash = args.bytecodeHash;
    }
    if (!args.appendCbor) {
      settings.metadata.appendCBOR = false;
    }
  }
  const input = { language: "Solidity", sources, settings };
  const compile = typeof solc.compileStandardWrapper === "function" ? solc.compileStandardWrapper : solc.compile;
  const output = JSON.parse(compile(JSON.stringify(input)));
  const diagnostics = output.errors || [];
  const errors = diagnostics.filter((d) => d.severity === "error");
  const warnings = diagnostics.filter((d) => d.severity !== "error");
  if (errors.length > 0) {
    for (const e of errors) {
      console.error(e.formattedMessage || e.message);
    }
    process.exit(1);
  }
  const loose = warnings.filter((w) => /can be restricted to/.test(w.message));
  if (loose.length > 0) {
    for (const w of loose) {
      console.error(w.formattedMessage || w.message);
    }
    console.error("a function is declared looser than its body needs; tighten it so the ABI mutability is the tightest one");
    process.exit(1);
  }
  fs.mkdirSync(args.out, { recursive: true });
  const reference = {
    compiler: solc.version(),
    settings: {
      optimizer: args.optimize,
      viaIR: args.viaIr,
      bytecodeHash: args.bytecodeHash,
      appendCBOR: args.appendCbor,
    },
    contracts: {},
  };
  for (const source of Object.keys(output.contracts).sort()) {
    const getters = constantGetters(output.sources[source].ast);
    const messages = requireMessages(output.sources[source].ast);
    for (const name of Object.keys(output.contracts[source]).sort()) {
      const contract = output.contracts[source][name];
      const creation = contract.evm.bytecode.object;
      const runtime = contract.evm.deployedBytecode.object;
      if (creation.length === 0 && runtime.length === 0) {
        continue;
      }
      if (creation.length === 0 || runtime.length === 0 || /[^0-9a-f]/.test(creation)) {
        throw new Error(`${name}: missing or linked bytecode`);
      }
      const file = `${name}.hex`;
      fs.writeFileSync(path.join(args.out, file), creation + "\n");
      reference.contracts[name] = {
        source,
        creation: { file, length: creation.length / 2, sha256: sha256(Buffer.from(creation, "hex")) },
        runtime: { length: runtime.length / 2, sha256: sha256(Buffer.from(runtime, "hex")) },
        methodIdentifiers: contract.evm.methodIdentifiers,
        constantGetters: (getters[name] || []).slice().sort(),
        requireMessages: Array.from(messages[name] || []).sort(),
        abi: contract.abi,
      };
    }
  }
  fs.writeFileSync(path.join(args.out, "reference.json"), JSON.stringify(reference, null, 1) + "\n");
  for (const w of warnings) {
    console.log(`warning: ${(w.formattedMessage || w.message).split("\n")[0]}`);
  }
  console.log(`${reference.compiler}: ${Object.keys(reference.contracts).length} contracts -> ${args.out}`);
}

main();
