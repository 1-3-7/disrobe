import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  Trace,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let lifecycle: Promise<void> = Promise.resolve();
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel("disrobe");
  context.subscriptions.push(outputChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand("disrobe.startServer", () => startLspClient(context)),
    vscode.commands.registerCommand("disrobe.stopServer", stopLspClient),
    vscode.commands.registerCommand("disrobe.showOutput", () => outputChannel.show()),
    vscode.commands.registerCommand("disrobe.auto", () => runCliOnActiveFile("auto")),
    vscode.commands.registerCommand("disrobe.detect", () => runCliOnActiveFile("detect")),
    vscode.commands.registerCommand("disrobe.strings", () => runCliOnActiveFile("strings")),
    vscode.commands.registerCommand("disrobe.ioc", () => runCliOnActiveFile("ioc")),
    vscode.commands.registerCommand("disrobe.behavior", () => runCliOnActiveFile("behavior")),
    vscode.commands.registerCommand("disrobe.identify", () => runCliOnActiveFile("identify")),
    vscode.commands.registerCommand("disrobe.scan", () => runCliOnActiveFile("scan")),
  );

  const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");
  const lspEnabled: boolean = cfg.get<boolean>("lsp.enable", true);
  if (lspEnabled) {
    startLspClient(context);
  }
}

export function deactivate(): Promise<void> {
  return stopLspClient();
}

function resolveExecutable(): string {
  const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");
  return cfg.get<string>("executablePath", "disrobe") || "disrobe";
}

function scheduleLsp(operation: () => Promise<void>): Promise<void> {
  const next: Promise<void> = lifecycle.then(operation);
  lifecycle = next.catch((error: unknown): void => {
    outputChannel.appendLine(`disrobe LSP operation failed: ${error instanceof Error ? error.message : String(error)}`);
  });
  return next;
}

function startLspClient(context: vscode.ExtensionContext): Promise<void> {
  return scheduleLsp(async (): Promise<void> => {
    if (client) {
      outputChannel.appendLine("disrobe LSP client already running.");
      return;
    }

    const exe: string = resolveExecutable();
    const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");
    const traceLevel: string = cfg.get<string>("lsp.trace", "off");

    const serverOptions: ServerOptions = {
      command: exe,
      args: ["serve"],
      transport: TransportKind.stdio,
    };

    const clientOptions: LanguageClientOptions = {
      documentSelector: [
        { scheme: "file", language: "python" },
        { scheme: "file", language: "javascript" },
        { scheme: "file", language: "typescript" },
        { scheme: "file", language: "java" },
        { scheme: "file", language: "csharp" },
        { scheme: "file", language: "go" },
        { scheme: "file", language: "lua" },
        { scheme: "file", language: "php" },
        { scheme: "file", language: "ruby" },
        { scheme: "file", language: "shellscript" },
        { scheme: "file", language: "powershell" },
      ],
      synchronize: {},
      outputChannel,
      traceOutputChannel: outputChannel,
    };

    const startedClient: LanguageClient = new LanguageClient("disrobe", "disrobe LSP", serverOptions, clientOptions);
    await startedClient.setTrace(Trace.fromString(traceLevel));

    context.subscriptions.push(startedClient);
    await startedClient.start();
    client = startedClient;
    outputChannel.appendLine(`disrobe LSP client started (${exe} serve --stdio)`);
  });
}

function stopLspClient(): Promise<void> {
  return scheduleLsp(async (): Promise<void> => {
    if (!client) return;
    await client.stop();
    client = undefined;
  });
}

function runCliOnActiveFile(subcommand: string): void {
  const editor: vscode.TextEditor | undefined = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("disrobe: no active file.");
    return;
  }

  const filePath: string = editor.document.uri.fsPath;
  if (!filePath) {
    vscode.window.showWarningMessage("disrobe: active document has no file path.");
    return;
  }

  const exe: string = resolveExecutable();
  const args: string[] = buildArgs(subcommand, filePath);
  const label: string = `disrobe ${subcommand}`;

  outputChannel.show(true);
  outputChannel.appendLine(`\n$ ${exe} ${args.join(" ")}`);

  const terminal: vscode.Terminal = vscode.window.createTerminal({
    name: label,
    shellPath: exe,
    shellArgs: args,
  });
  terminal.show(true);
}

function buildArgs(subcommand: string, filePath: string): string[] {
  const cfg: vscode.WorkspaceConfiguration = vscode.workspace.getConfiguration("disrobe");

  switch (subcommand) {
    case "auto": {
      const outDir: string = cfg.get<string>("auto.outDir", "");
      const base: string[] = ["auto", filePath];
      return outDir ? [...base, "--out", outDir] : base;
    }
    case "detect":
      return ["detect", filePath];
    case "strings":
      return ["strings", filePath];
    case "ioc":
      return ["ioc", filePath];
    case "behavior":
      return ["behavior", filePath];
    case "identify":
      return ["identify", filePath];
    case "scan":
      return ["scan", filePath];
    default:
      return [subcommand, filePath];
  }
}
