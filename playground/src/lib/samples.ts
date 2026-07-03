const encoder: TextEncoder = new TextEncoder();

export type SampleSource =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "file"; readonly file: string };

export interface Sample {
  readonly label: string;
  readonly note: string;
  readonly tone: "neutral" | "danger";
  readonly source: SampleSource;
}

export function inlineSample(
  label: string,
  note: string,
  text: string,
  tone: "neutral" | "danger" = "neutral",
): Sample {
  return { label, note, tone, source: { kind: "text", text } };
}

export function fileSample(
  label: string,
  note: string,
  file: string,
  tone: "neutral" | "danger" = "neutral",
): Sample {
  return { label, note, tone, source: { kind: "file", file } };
}

const fileCache: Map<string, Uint8Array> = new Map<string, Uint8Array>();

async function loadFile(file: string): Promise<Uint8Array> {
  const cached: Uint8Array | undefined = fileCache.get(file);
  if (cached !== undefined) {
    return cached;
  }
  const url: string = `${import.meta.env.BASE_URL}samples/${file}`;
  const response: Response = await fetch(url);
  if (!response.ok) {
    throw new Error(`failed to load sample ${file}: ${response.status}`);
  }
  const bytes: Uint8Array = new Uint8Array(await response.arrayBuffer());
  fileCache.set(file, bytes);
  return bytes;
}

export async function resolveSample(sample: Sample): Promise<Uint8Array> {
  if (sample.source.kind === "text") {
    return encoder.encode(sample.source.text);
  }
  return loadFile(sample.source.file);
}

export const PYARMOR_WRAPPER_SAMPLE: string = [
  "from pyarmor_runtime_000000 import __pyarmor__",
  "__pyarmor__(__name__, __file__, b'PY000000\\x00\\x03\\x0a...redacted-payload...')",
  "",
].join("\n");

export const PHP_EVAL_SAMPLE: string = [
  "<?php",
  "$code = base64_decode('ZWNobyAiaGVsbG8gZnJvbSBkaXNyb2JlIjs=');",
  "eval($code);",
  "?>",
].join("\n");

export const RUBY_SOURCE_SAMPLE: string = [
  "class Greeter",
  "  def initialize(name)",
  "    @name = name",
  "  end",
  "",
  "  def greet",
  '    "hello, #{@name}"',
  "  end",
  "end",
  "",
  'puts Greeter.new("world").greet',
  "",
].join("\n");

export const IOC_SAMPLE: string = [
  "configuration block",
  "endpoint: https://c2.example.com/gate.php",
  "fallback http://198.51.100.23:8080/checkin",
  "drop C:\\Users\\Public\\payload.exe",
  "wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "contact admin@drop.example.org",
  "",
].join("\n");

export const STRINGS_SAMPLE: string = [
  "loader v2 build 4471",
  "CreateRemoteThread",
  "https://cdn.example.net/stage2.bin",
  "RegSetValueExW",
  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "config key: 0123456789abcdef0123456789abcdef",
  "",
].join("\n");

export const BEHAVIOR_SAMPLE: string = [
  "VirtualAllocEx WriteProcessMemory CreateRemoteThread",
  "InternetOpenW HttpSendRequestW WinHttpConnect",
  "RegCreateKeyExW RegSetValueExW",
  "CryptEncrypt CryptGenKey BCryptEncrypt",
  "IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess",
  "",
].join("\n");

export const SECRETS_SAMPLE: string = [
  "config dump",
  "aws_access_key_id = AKIA" + "IOSFODNN7EXAMPLE",
  "github_pat = ghp_" + "1234567890abcdefghijklmnopqrstuvwx12",
  "stripe = sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc00example",
  "jwt = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysig",
  "",
].join("\n");

export const ANTI_ANALYSIS_SAMPLE: string = [
  "IsDebuggerPresent",
  "CheckRemoteDebuggerPresent",
  "NtQueryInformationProcess ProcessDebugPort",
  "GetTickCount rdtsc timing check",
  "VMware VBOX vbox virtualbox detection",
  "SbieDll.dll sandboxie probe",
  "",
].join("\n");

export const WASM_SOURCE_MAP_SAMPLE: string = JSON.stringify(
  {
    version: 3,
    file: "module.wasm",
    sourceRoot: "",
    sources: ["src/lib.rs", "src/math.rs"],
    sourcesContent: [null, null],
    names: ["add", "fibonacci", "classify", "sum_to"],
    mappings: "qBAAAA,EAAOC,EAAUC,EAAQC",
  },
  null,
  2,
);

export const YARA_SAMPLE: string = [
  "Stage2Loader",
  "https://cdn.example.net/payload",
  "RC4_INIT_KEY_8f3a2b1c",
  "this build belongs to group XYZ",
  "",
].join("\n");

export const BATCH_OBF_SAMPLE: string = [
  "@echo off",
  "set a=cal",
  "set b=c.exe",
  "set p=%a%%b%",
  "for /l %%i in (1,1,3) do echo stage %%i",
  "if 1==1 (start %p%) else (echo skip)",
  "%p%",
  "",
].join("\n");
