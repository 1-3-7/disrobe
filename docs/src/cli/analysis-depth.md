# Analysis-depth commands

A set of static-analysis primitives that make `disrobe` useful as a triage and reverse-engineering tool, not only a decompiler. Each one operates on raw bytes and (where relevant) on the strings/source a chain has already recovered, so they compose with the rest of the pipeline. None of them execute the sample.

| Command | What it does |
|---|---|
| [`disrobe scan`](#credential-scan) | Scan raw bytes for leaked credentials and secrets. |
| [`disrobe identify`](#format-identification) | Fingerprint compiler, packer, protector, and installer. |
| [`disrobe prowl`](#prowl-harvest) | Harvest URLs and IOCs from public archives and threat-intel feeds. |
| [`disrobe ioc`](#ioc-extraction) | Pull indicators of compromise out of an artifact. |
| [`disrobe indicators`](#indicator-aggregation) | Merge `frisk`, `ioc`, and `prowl` JSON into one versioned bundle. |
| [`disrobe strings`](#string-extraction) | Cross-format string extraction with single-byte XOR / base64 / ROT brute-forcing. |
| [`disrobe yara generate`](#yara-rule-generation) | Synthesize a candidate YARA rule from an artifact. |
| [`disrobe behavior`](#behavior-summary) | Summarize what a binary does, tagged with MITRE ATT&CK technique IDs. |

## Credential scan {#credential-scan}

```bash
disrobe scan firmware.bin
disrobe scan firmware.bin --json
disrobe scan firmware.bin --sarif > findings.sarif
```

`disrobe scan` scans the target's raw bytes for leaked credentials: cloud provider keys (AWS, GCP, Azure, GitHub, Stripe, and others), VCS tokens, JWTs, PEM and SSH private keys, and other high-confidence secret patterns.

Unlike `disrobe ioc`, `scan` focuses exclusively on secrets that represent an immediate credential exposure rather than general network or host indicators. Output is text (one finding per line) or SARIF 2.1.0.

## Format identification {#format-identification}

```bash
disrobe identify sample.exe
disrobe identify sample.exe --json
```

`disrobe identify` fingerprints what built or packed a PE, ELF, or Mach-O binary. It reports the compiler, linker, packer, protector, and installer if detected, with structural evidence and the `disrobe` pass that handles each detected layer. The output is the same as `disrobe native identify` but works as a top-level command without routing through the `native` subcommand tree.

## Prowl harvest

```bash
disrobe prowl example.com --subs --sources wayback,commoncrawl,urlscan --format json > prowl.json
disrobe prowl --targets-file targets.txt --proxy http://127.0.0.1:8080 --max-urls 50000
disrobe prowl --recon-input frisk.json --ioc domain,ipv4,email
disrobe prowl keyring set virustotal
```

`disrobe prowl` is the explicit network recon command. It queries Wayback, Common Crawl, OTX, urlscan, crt.sh, URLhaus, ThreatFox, and VirusTotal. Inputs can be command-line targets, a targets file, stdin, or a prior `disrobe` recon/IOC JSON report. The output schema is `disrobe.prowl/v0` and contains the requested targets, selected sources, URL records, IOC records, and per-provider status.

The source labels are `wayback`, `commoncrawl`, `otx`, `urlscan`, `crtsh`, `urlhaus`, `threatfox`, and `virustotal` (`vt` alias). API keys resolve in this order: `--api-key provider=key`, provider environment variable (`PROWL_<PROVIDER>_API_KEY` or the provider's conventional variable), OS keyring, then a permissions-checked TOML config. Required-key providers without a key are skipped with a provider status rather than failing the whole harvest.

Filters are bounded and deterministic: `--blacklist` drops extensions, `--from`/`--to` constrain Wayback dates, `--mc`/`--fc` include or exclude HTTP status codes, `--mt`/`--ft` include or exclude MIME substrings, `--ioc` keeps selected IOC classes, `--fp` collapses URLs that differ only by query values, and `--no-iocs` suppresses derived IOC extraction. `--timeout`, `--concurrency`, `--per-host-rps`, `--max-pages`, `--max-urls`, `--max-iocs`, and `--retries` cap network and memory use.

## IOC extraction

```bash
disrobe ioc suspicious.bin
disrobe ioc suspicious.bin --format json
disrobe ioc suspicious.bin --defang        # hxxp://, 1[.]2[.]3[.]4 for safe reporting
disrobe ioc malware.exe --format sarif      # GitHub code-scanning ingest
```

`disrobe ioc` scans the target's bytes and any UTF-16 / ASCII text inside it for:

- **Network**: URLs (`http`/`https`/`ftp`/`ftps`/`smb`/`file`), bare domains, IPv4, IPv6, email addresses.
- **Host artifacts**: Windows file paths, registry keys (`HKLM\...`, `HKEY_CURRENT_USER\...`), Unix paths under well-known roots (`/etc`, `/usr`, `/var`, `/Users`, ...).
- **Crypto wallets**: Bitcoin (legacy `1`/`3` and bech32 `bc1`), Ethereum (`0x...40`), Monero (`4...`).
- **Crypto constants**: AES S-box and inverse S-box, MD5 / SHA-1 / SHA-256 / SHA-512 init vectors, ChaCha20 sigma/tau, and the standard/URL base64 alphabets.

When the input is a native PE/ELF/Mach-O binary, the import table (`library!symbol`) is folded into the scan so DLL- and symbol-borne indicators surface too.

### Encoding recursion

Base64 and hex blobs in the input are decoded and re-scanned **one level deep**. An indicator found inside a decoded blob is tagged with its `encoding` (`base64` or `hex`) so you can tell a plaintext URL from one that was hidden behind a layer of encoding. The recursion is intentionally single-level to keep the scan bounded.

### Output

- Text (default): one indicator per line, `kind<TAB>encoding<TAB>@offset<TAB>value`, followed by a count.
- JSON (`--format json` or the global `--json`): the `disrobe.ioc/v0` document, `{ schema, uri, byte_len, total, indicators[] }`, each indicator carrying `kind`, `value`, `offset`, `encoding`, and an optional `context` window.
- SARIF (`--format sarif` or the global `--sarif`): SARIF 2.1.0 with one result per indicator and a `DR-IOC-<KIND>` rule id, for GitHub code scanning.

`--defang` rewrites URLs, domains, IPs, and emails into a non-clickable form (`hxxp://`, `1[.]2[.]3[.]4`, `user@host[.]tld`) in every format.

### Safety and determinism

Every pattern is bounded (explicit upper repetition counts) so adversarial input cannot trigger catastrophic regex backtracking, and the indicator set is deduplicated and offset-sorted, so the same bytes always produce the same report. The library logic lives in `disrobe_core::ioc` and is reused by the daemon and by `disrobe report`.

## Indicator aggregation

```bash
disrobe indicators frisk.json ioc.json prowl.json --format json > indicators.json
disrobe indicators frisk.json prowl.json --targets-only > targets.txt
disrobe prowl --targets-file targets.txt --format json > expanded-prowl.json
```

`disrobe indicators` ingests `disrobe.recon/v0`, `disrobe.ioc/v0`, and `disrobe.prowl/v0` JSON. It normalizes every URL, domain, IP, email, hash, ASN, path, and registry value into `disrobe.indicators/v0`, deduplicates by `(class, value)`, and preserves the source list that produced each value.

`--targets-only` prints bare domains and IPs, one per line, so an offline frisk/IOC pass can seed an explicit `prowl --targets-file` run.

## String extraction

```bash
disrobe strings sample.bin
disrobe strings sample.bin --min-len 6
disrobe strings sample.bin --no-decode      # plain ASCII / UTF-16 only
disrobe strings sample.bin --json
```

An in-house FLOSS-style extractor. It pulls printable ASCII and UTF-16LE runs at or above `--min-len` (default 4), then runs a set of deobfuscation passes and tags each result by how it was recovered:

| Tag | Meaning |
|---|---|
| `plain` / `plain:wide` | Printable ASCII run / UTF-16LE run. |
| `xor:0xKK` | Recovered by brute-forcing single-byte XOR key `KK` over a printable run; kept only when the decoded text clears a printable-ratio bar and hits at least two dictionary words. |
| `base64` | A base64 token whose decoded bytes are printable text. |
| `rot:N` | A run that, rotated by `N` (ROT13 and other ROT-`n`), becomes dictionary-rich text. |
| `stack-string` | A run reconstructed from interleaved-NUL / fragmented bytes characteristic of compiler-built stack strings. |

The XOR, ROT, and stack-string heuristics are deliberately conservative: they require dictionary hits, trading recall for precision so the output stays signal, not noise. Results are deduplicated by `(value, tag)` and offset-sorted.

Output is text (`tag<TAB>@offset<TAB>value`) or the `disrobe.strings/v0` JSON document via `--json`. The library logic lives in `disrobe_core::strings`.

## YARA rule generation

```bash
disrobe yara generate sample.bin
disrobe yara generate sample.bin --name Trojan_Foo_2026
disrobe yara generate sample.bin --sha256 <hash> --date 2026-06-10
disrobe yara generate sample.bin --json
```

Synthesizes a candidate YARA rule from an artifact. It selects high-signal strings (long, multi-character-class, non-dictionary, and any that were XOR/base64/ROT-recovered get a scoring bonus), detects the file's magic / format header, and emits a leading `$magic` hex pattern, producing a well-formed:

```yara
rule <name> : disrobe generated {
    meta:
        generated_by = "disrobe <version>"
        schema = "disrobe.yara.generated/v0"
        format = "pe"
        sha256 = "..."        // only when --sha256 is given
        date = "..."          // only when --date is given
    strings:
        $magic = { 4D 5A 90 00 ... }
        $s0 = "..." ascii
        ...
    condition:
        $magic at 0 and N of ($s*)
}
```

The condition combines an anchored magic check (when a format was recognized) with an "N of" string threshold (half the selected strings, rounded up).

### Provenance

`disrobe` has no wall clock available to its analysis core, so the rule is **not** stamped with the current date automatically. Pass `--sha256` and `--date` to embed those values in the meta block; otherwise they are omitted rather than fabricated.

### Self-verification

Every generated rule is parsed back through the in-house YARA parser (the same one behind `disrobe yara parse`) before it is returned. If the emitter ever produced something the parser could not read, generation fails loudly with `DR-YARAGEN-0001` rather than emitting a broken rule. The library logic lives in `disrobe_core::yara_gen`.

### Rule matching

Beyond generating and parsing rules, `disrobe_core::yara_match` evaluates a parsed ruleset against a byte buffer. It compiles the rule strings into an Aho-Corasick atom prefilter, then checks each rule's condition. It supports text strings (`nocase`, `fullword`, `ascii`, `wide`), hex strings (nibble wildcards, jumps, and alternation), a subset of regular expressions, and the common condition forms (`$s` at an offset or in a range, `#s` counts, `N of`, `all` / `any` / `none of`, `filesize`, and boolean and arithmetic operators). A rule that uses a feature outside that set is returned as unevaluated with a reason rather than reported as a false match or a false miss. The matcher is a library capability today with no CLI verb; it is graded by differential testing against the real `yara` command-line tool across a battery of text, hex, regex, and condition cases (`yara_match_oracle.rs`).

## Behavior summary

```bash
disrobe behavior sample.exe
disrobe behavior sample.exe --json
```

`disrobe behavior` answers "what does this binary do?" by classifying it across seven categories:

| Category | Covers |
|---|---|
| `network` | Sockets, WinHTTP/WinINet, DNS lookups, downloads. |
| `filesystem` | File create/read/write/delete, directory enumeration. |
| `process_exec` | Process / command execution, remote-thread injection. |
| `registry_persistence` | Registry writes, Run keys, scheduled tasks, services. |
| `crypto` | CryptoAPI / BCrypt / embedded crypto constants. |
| `anti_analysis` | Debugger checks, timing checks, sandbox evasion. |
| `dynamic_code` | `LoadLibrary`/`GetProcAddress`, `VirtualProtect`, `dlopen`, RWX memory. |

Signals come from three sources, each tagged in the evidence list:

- **`import`**: the native import table (PE/ELF/Mach-O), parsed when the input is a binary.
- **`string`**: API / symbol names found in the extracted strings (including XOR/base64-recovered ones), so signals survive light obfuscation.
- **`ioc`**: network/host/crypto indicators from the [IOC extractor](#ioc-extraction).

### MITRE ATT&CK mapping

Confident matches are tagged with a [MITRE ATT&CK](https://attack.mitre.org/) technique id (for example `LoadLibrary` -> `T1129`, `IsDebuggerPresent` -> `T1622`, a Run key -> `T1547.001`). The mapping is a small, hand-curated static table: only techniques that follow directly from the signal are emitted, never a probabilistic guess. The aggregate `attack_ids` list at the end of the report is the union across all categories, ready to paste into a triage ticket. The library logic lives in `disrobe_core::behavior` and is reusable by `disrobe report`.

### Scope

This is a *static* summary: `disrobe` never executes the sample. A signal means the capability is present in the binary's imports/strings, not that it necessarily fires at runtime. Treat it as a lead, not a verdict.
