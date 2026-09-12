import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== "--binary" || args[2] !== "--grpcurl") {
  throw new Error("usage: node docs/demo/capture-services.mjs --binary <disrobe> --grpcurl <grpcurl>");
}
const binary = resolve(args[1]);
const grpcurl = resolve(args[3]);
const wasm = await readFile(join(root, "playground/public/samples/add.wasm"));
const text = Buffer.from("Documentation: https://docs.example.com/guide Contact: help@example.com");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sessions = [];
const exchanges = [];
const maximumOutput = 256 * 1024;

function start(arguments_) {
  const process_ = spawn(binary, arguments_, { cwd: root, windowsHide: true, stdio: "pipe", env: { ...process.env, RUST_LOG: "off", NO_COLOR: "1" } });
  const exited = once(process_, "exit");
  const watchdog = setTimeout(() => process_.kill(), 45_000);
  const record = { command: ["disrobe", ...arguments_], stderr: "", exit_code: null, signal: null };
  process_.stderr.on("data", (chunk) => {
    record.stderr += chunk.toString("utf8");
    if (Buffer.byteLength(record.stderr) > maximumOutput) process_.kill();
  });
  exited.then(([code, signal]) => {
    clearTimeout(watchdog);
    record.exit_code = code;
    record.signal = signal;
  }, () => { clearTimeout(watchdog); });
  const session = { process: process_, exited, record };
  sessions.push(session);
  return session;
}

function rpc(session, framed) {
  const chunks = session.process.stdout[Symbol.asyncIterator]();
  let buffered = Buffer.alloc(0);
  let sequence = 0;
  const send = (message) => {
    const body = Buffer.from(JSON.stringify(message));
    session.process.stdin.write(framed ? Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`), body]) : Buffer.concat([body, Buffer.from("\n")]));
  };
  const receive = async () => {
    while (true) {
      if (framed) {
        const boundary = buffered.indexOf("\r\n\r\n");
        if (boundary >= 0) {
          const match = /^Content-Length: (\d+)$/imu.exec(buffered.subarray(0, boundary).toString("ascii"));
          if (match === null) throw new Error("LSP response lacks Content-Length");
          const length = Number(match[1]);
          if (length > maximumOutput) throw new Error("LSP response exceeds 256 KiB");
          const start = boundary + 4;
          if (buffered.length >= start + length) {
            const message = JSON.parse(buffered.subarray(start, start + length).toString("utf8"));
            buffered = buffered.subarray(start + length);
            return message;
          }
        }
      } else {
        const boundary = buffered.indexOf(10);
        if (boundary >= 0) {
          const message = JSON.parse(buffered.subarray(0, boundary).toString("utf8"));
          buffered = buffered.subarray(boundary + 1);
          return message;
        }
      }
      const chunk = await chunks.next();
      if (chunk.done) throw new Error("Server closed before responding");
      buffered = Buffer.concat([buffered, chunk.value]);
      if (buffered.length > maximumOutput) throw new Error("Protocol buffer exceeds 256 KiB");
    }
  };
  return {
    notify: (method, params) => send({ jsonrpc: "2.0", method, params }),
    call: async (method, params) => {
      const id = ++sequence;
      const request = { jsonrpc: "2.0", id, method, params };
      send(request);
      for (let received = 0; received < 32; received += 1) {
        const response = await receive();
        if (response.id !== id) continue;
        assert.equal(response.error, undefined, JSON.stringify(response));
        exchanges.push({ transport: framed ? "lsp" : "mcp", request, response });
        return response.result;
      }
      throw new Error("Server sent 32 unrelated messages without the requested response");
    },
  };
}

async function close(session) {
  session.process.stdin.end();
  const [code] = await session.exited;
  assert.equal(code, 0, session.record.stderr);
}

async function http(path, body) {
  const request = { method: body === undefined ? "GET" : "POST", path, ...(body === undefined ? {} : { body }) };
  const response = await fetch(`http://127.0.0.1:8850${path}`, {
    method: request.method,
    ...(body === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 200);
  const raw = await response.text();
  if (Buffer.byteLength(raw) > maximumOutput) throw new Error("HTTP response exceeds 256 KiB");
  const data = JSON.parse(raw);
  exchanges.push({ transport: "http", request, response: data });
  return data;
}

function grpc(method, body) {
  const arguments_ = ["-plaintext", "-max-time", "5", "-import-path", join(root, "crates/disrobe-cli/proto"), "-proto", "disrobe.proto", "-d", JSON.stringify(body), "127.0.0.1:8851", `disrobe.v1.Disrobe/${method}`];
  const result = spawnSync(grpcurl, arguments_, { cwd: root, windowsHide: true, timeout: 10_000, maxBuffer: maximumOutput, encoding: "utf8" });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  const response = JSON.parse(result.stdout);
  exchanges.push({ transport: "grpc", request: { method, body }, response });
  return response;
}

try {
  const mcp = start(["serve", "--mcp"]);
  const client = rpc(mcp, false);
  const initialized = await client.call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "disrobe-demo", version: "1" } });
  assert.equal(initialized.serverInfo.name, "disrobe");
  client.notify("notifications/initialized", {});
  const catalog = await client.call("tools/list", {});
  assert(catalog.tools.some((tool) => tool.name === "ioc"));
  const findings = await client.call("tools/call", { name: "ioc", arguments: { bytes_b64: text.toString("base64") } });
  assert.notEqual(findings.isError, true);
  assert.equal(findings.structuredContent.byte_len, text.length);
  assert(findings.structuredContent.indicators.some((indicator) => indicator.value === "https://docs.example.com/guide"));
  await close(mcp);

  const lsp = start(["serve", "--stdio"]);
  const language = rpc(lsp, true);
  await language.call("initialize", { processId: null, rootUri: null, capabilities: {}, clientInfo: { name: "disrobe-demo", version: "1" } });
  language.notify("initialized", {});
  const analyzed = await language.call("disrobe/analyze", { bytes_b64: wasm.toString("base64"), label: "add.wasm" });
  assert.equal(analyzed.bytes, wasm.length);
  assert.equal(analyzed.action, "Decompile { lang: Wasm }");
  await language.call("shutdown", null);
  language.notify("exit", undefined);
  await close(lsp);

  const service = start(["serve", "--bind", "127.0.0.1:8850", "--grpc"]);
  let startup = "";
  for await (const chunk of service.process.stdout.iterator({ destroyOnReturn: false })) {
    startup += chunk.toString("utf8");
    if (Buffer.byteLength(startup) > maximumOutput) throw new Error("Server startup output exceeds 256 KiB");
    if (startup.includes("listening on http://127.0.0.1:8850") && startup.includes("gRPC listening on 127.0.0.1:8851")) break;
  }
  assert(startup.includes("listening on http://127.0.0.1:8850") && startup.includes("gRPC listening on 127.0.0.1:8851"), service.record.stderr);
  service.process.stdout.resume();
  const health = await http("/v1/health");
  assert.equal(health.status, "serving");
  const httpAnalysis = await http("/v1/analyze", { bytes_b64: wasm.toString("base64") });
  assert.equal(httpAnalysis.bytes_read, wasm.length);
  assert.equal(httpAnalysis.routed_action, "Decompile { lang: Wasm }");
  assert.equal(analyzed.blake3, httpAnalysis.blake3_hash);
  const grpcHealth = grpc("Health", {});
  assert.equal(grpcHealth.status, "serving");
  const grpcAnalysis = grpc("Analyze", { bytesInline: wasm.toString("base64") });
  assert.equal(Number(grpcAnalysis.bytesRead), wasm.length);
  assert.equal(grpcAnalysis.routedAction, httpAnalysis.routed_action);
  assert.equal(grpcAnalysis.blake3Hash, httpAnalysis.blake3_hash);
  service.process.kill();
  await service.exited;
  const receipt = { schema: "disrobe.demo.services/v1", captured_at: new Date().toISOString(), binary_sha256: hash(await readFile(binary)), grpcurl_sha256: hash(await readFile(grpcurl)), inputs: [{ path: "playground/public/samples/add.wasm", bytes: wasm.length, sha256: hash(wasm) }, { text: text.toString("utf8"), bytes: text.length, sha256: hash(text) }], sessions: sessions.map((session) => session.record), exchanges };
  const encoded = JSON.stringify(receipt, null, 2) + "\n";
  if (Buffer.byteLength(encoded) > maximumOutput) throw new Error("Service receipt exceeds 256 KiB");
  await writeFile(join(root, "docs/demo/services.json"), encoded);
  process.stdout.write(`captured ${exchanges.length} exchanges across MCP, LSP, HTTP, and gRPC\n`);
} finally {
  for (const session of sessions) {
    if (session.process.exitCode === null && session.process.signalCode === null) session.process.kill();
    await session.exited;
  }
}
