# Recon, prowl, and indicators

`disrobe frisk` is `disrobe`'s built-in recon engine. Point it at any file, directory, APK, or disrobe-recovered source tree and it surfaces leaked secrets (cloud keys, SaaS/AI tokens, private keys), API endpoints and routes, cloud-storage buckets, Android manifest exposure (deep-link schemes and hosts, exported components, content-provider authorities, dangerous permissions), and IOCs (URLs, domains, IPs, emails, `.onion`, webhooks), each with its file, line, and column. Because `disrobe` recovers the real source first, frisk searches truth, not a shell grep, and it is fully encoding-safe.

## Usage

```sh
disrobe frisk app/                                  # walk a directory or recovered source tree
disrobe frisk app.apk                               # APK manifest exposure + secrets + IOCs
disrobe frisk recovered/ --format json              # text, json, or sarif
disrobe frisk recovered/ --format sarif > frisk.sarif
disrobe frisk app/ --pattern rules.txt              # custom rule pack: name=regex per line
disrobe frisk app/ --suppress example.com           # drop findings whose value contains a substring
disrobe frisk app/ --emit-baseline > baseline.json  # snapshot current findings
disrobe frisk app/ --baseline baseline.json         # report only new findings
disrobe frisk app/ --entropy                        # include high-entropy generic-secret findings
```

`frisk` is offline. Network enrichment is explicit through `prowl`, and schema merging is explicit through `indicators`.

## Decoded string layers

A secret hidden behind an encoding is still a secret, so `frisk` does not scan only the literal bytes. It peels base58, base62, base45, base91, base92, base122, Ascii85, Z85, uuencode, xxencode, yEnc, percent-encoding, HTML entities, and Punycode recursively, with decompression-bomb caps at every level, and rescans each recovered layer for the same secrets and IOCs. A finding inside a decoded layer reports the position in the file that carried it.

## Wide strings

`frisk` and `ioc` read UTF-16 text in both byte orders on every input. No flag turns wide scanning on or off, and no flag selects a byte order.

A wide run is four or more ASCII characters, each held in a two-byte code unit whose other byte is zero. Eight bytes is therefore the shortest run that can be reported. A run may start at any byte offset, odd or even. The indicator scan accepts printable ASCII, tab, line feed, and carriage return inside a run. The endpoint and `.onion` pass accepts printable ASCII only. A code unit outside the accepted set ends the run, and the scan resumes at the next position rather than stopping.

The endpoint and `.onion` pass in `disrobe frisk` reads at most 65536 wide runs per file for each byte order, and stops a single run at 65536 bytes. The indicator scan stops after 100000 indicators for one input, wide and plain findings together.

## What a wide scan reports

The indicator layer reads wide runs in both byte orders. URLs, domains, IPv4 and IPv6 addresses, emails, and wallet addresses surface from wide text in both commands. `disrobe ioc` also reports Windows paths, registry keys, and Unix paths found in wide text. `disrobe frisk` keeps those three only when the value matches a persistence indicator. The endpoint rules and the `.onion` rule run over each wide run as well.

Secret rules and `--pattern` rule packs do not read wide runs. They match the file's own bytes and its lossy UTF-8 text. A credential stored only as UTF-16 is reported only when the secret rule matches the raw bytes. `frisk` and `ioc` read UTF-16 only, and neither reads UTF-32.

`disrobe frisk` anchors every finding taken from a wide run to the file offset, line, and column where the run starts, not to a position inside the decoded text. `disrobe ioc` reports the run's file offset plus the index of the match inside the decoded run, so the offset is exact for a match at the start of a run and approximate for a match further in.

The opposite reading of the same bytes starts one byte later and produces a different value. Both readings can therefore report a finding over one run. Read the rule id suffix, or the encoding value, to see which reading produced a given finding.

## Byte order in the output

| Surface | Where the byte order appears |
|---|---|
| `disrobe frisk`, every format | The rule id gains `-UTF16LE` or `-UTF16BE`, for example `DR-RECON-ONION-UTF16BE`. |
| `disrobe ioc`, text output | The encoding column reads `utf16le` or `utf16be`. |
| `disrobe ioc --format json` | The `encoding` field reads `utf16_le` or `utf16_be`. |
| `disrobe ioc --format sarif` | The rule id comes from the indicator kind and carries no suffix. The encoding appears in the result message. |

```sh
disrobe ioc sample.bin --format json | jq '.indicators[] | select(.encoding == "utf16_be")'
disrobe frisk recovered/ --format json | jq '.findings[] | select(.rule_id | endswith("-UTF16BE"))'
```

In `disrobe frisk`, the suffix is part of the fingerprint that `--emit-baseline` and `--baseline` compare. A wide finding and its plain-text twin are two separate entries in a baseline.

## Finding categories

Every finding carries a category, a rule id, the matched value, a severity, and a `file:line:column` (or byte offset for non-text input).

| Category | What it surfaces |
|---|---|
| `secret` | Cloud keys, SaaS and AI provider tokens, private keys, webhook URLs. High-entropy generic secrets are gated behind `--entropy`. |
| `endpoint` | API endpoints, routes, and request targets recovered from source. |
| `manifest` | Android manifest exposure: deep-link schemes and hosts, exported activities/services/receivers/providers, content-provider authorities, dangerous permissions. |
| `url` | HTTP and HTTPS URLs. |
| `domain` | Bare domains. |
| `ipv4`, `ipv6` | IP-address IOCs. |
| `email` | Email addresses. |
| `onion` | Tor v2 and v3 `.onion` hidden-service addresses. |
| `custom` | Matches from a `--pattern` rule pack. |

## Flags

| Flag | Effect |
|---|---|
| `--format <text\|json\|sarif>` | Output format. SARIF 2.1.0 drops into GitHub code scanning. |
| `--pattern <FILE>` | Custom rule pack, one `name=regex` per line; `#` comments allowed. |
| `--suppress <SUBSTR>` | Drop findings whose value contains the substring. Repeatable. |
| `--emit-baseline` | Print the current findings as a baseline JSON array to snapshot. |
| `--baseline <FILE>` | Report only findings absent from the baseline array. |
| `--entropy` | Include high-entropy generic-secret findings. |

## Custom rule packs

A rule pack is one `name=regex` per line:

```text
# rules.txt
internal-host=https://[a-z0-9.-]+\.corp\.example\.com
deploy-token=DEPLOY_[A-Z0-9]{32}
```

```sh
disrobe frisk recovered/ --pattern rules.txt --format json
```

## Baselines

Snapshot the current findings, then report only new ones on later runs, so a CI gate fires only when a fresh secret or endpoint appears:

```sh
disrobe frisk app/ --emit-baseline > frisk-baseline.json
disrobe frisk app/ --baseline frisk-baseline.json --format sarif > new-findings.sarif
```

## Network harvest with prowl

```sh
disrobe prowl example.com --subs --sources wayback,commoncrawl,urlscan --format json > prowl.json
disrobe prowl --targets-file targets.txt --proxy http://127.0.0.1:8080 --timeout 20
disrobe prowl --recon-input frisk.json --ioc domain,ipv4,email
disrobe prowl keyring set virustotal
```

`disrobe prowl` queries public archives and threat-intel feeds and writes `disrobe.prowl/v0`. The source labels are:

| Source | Notes |
|---|---|
| `wayback` | Wayback capture URLs, date-filtered by `--from` and `--to`. |
| `commoncrawl` | Common Crawl index URLs. |
| `otx` | AlienVault OTX URLs and pulses; optional key. |
| `urlscan` | urlscan submissions; optional key. |
| `crtsh` | Certificate transparency names from crt.sh. |
| `urlhaus` | URLhaus URLs and payload IOCs; key-supported. |
| `threatfox` | ThreatFox IOCs; key-supported. |
| `virustotal` | VirusTotal URL/domain data; `vt` is accepted as an alias and a key is required. |

Important flags:

| Flag | Effect |
|---|---|
| `--targets-file <FILE>` | Read one domain or URL per line. |
| `--stdin` | Read targets or a prior recon/IOC JSON report from stdin. |
| `--recon-input <FILE>` | Seed targets from `frisk`, `ioc`, or `prowl` JSON. |
| `--sources <LIST>` | Comma-separated source labels; empty means every source. |
| `--subs` | Include subdomains for the target. |
| `--blacklist <EXT>` | Drop URLs with matching extensions. |
| `--mc <CODE>` / `--fc <CODE>` | Keep or drop HTTP status codes. |
| `--mt <MIME>` / `--ft <MIME>` | Keep or drop MIME substrings. |
| `--ioc <KIND>` | Keep selected IOC kinds: `subdomain`, `domain`, `ipv4`, `ipv6`, `email`, `md5`, `sha1`, `sha256`, `asn`. |
| `--fp` | Collapse URLs that differ only in query-parameter values. |
| `--no-iocs` | Keep URL records without deriving structured IOCs. |
| `--proxy <URL>` | Route requests through an HTTP(S) or SOCKS proxy. |
| `--timeout <SECS>` | Per-request timeout, default 45. |
| `--concurrency <N>` | In-flight source/target requests, default 12. |
| `--per-host-rps <RPS>` | Per-host request rate, default 4; `0` disables. |
| `--max-pages <N>` | Max paginated requests per source, default 50. |
| `--max-urls <N>` | Max retained URLs, default 1000000. |
| `--max-iocs <N>` | Max retained IOCs, default 1000000. |
| `--retries <N>` | Retries on 429/5xx, default 3. |
| `--api-key <PROVIDER=KEY>` | Provide a key for one run. Prefer env vars or keyring for normal use. |

Key resolution order is flags, provider environment variables, OS keyring, then the permissions-checked TOML config. Use `disrobe prowl keyring set|get|rm|list <provider>` to manage stored keys.

## Indicator bundles

```sh
disrobe frisk recovered/ --format json > frisk.json
disrobe ioc sample.bin --format json > ioc.json
disrobe prowl --recon-input frisk.json --format json > prowl.json
disrobe indicators frisk.json ioc.json prowl.json --format json > indicators.json
disrobe indicators frisk.json prowl.json --targets-only > targets.txt
```

`disrobe indicators` ingests `disrobe.recon/v0`, `disrobe.ioc/v0`, and `disrobe.prowl/v0`, deduplicates indicators by class and value, preserves each value's source provenance, and emits `disrobe.indicators/v0`. `--targets-only` prints network indicators ready for `prowl --targets-file`.

## String harvest from a write log

`disrobe_core::recon::string_emu` holds the wide-run reader behind the endpoint and `.onion` pass in `disrobe frisk`. It also holds two APIs that no `disrobe` command reaches: a string harvest over a write log, and a call-site argument reader. Both read state the caller already holds, a list of address and byte pairs in the first case and captured registers and stack bytes in the second. `disrobe` does not run the sample to produce either input.

The caller supplies a sandbox window of allowed address ranges alongside the write log. A write to an address outside the window is counted in `writes_outside_sandbox` and dropped, so it never reaches the harvest and never allocates host memory. A window holds at most 64 regions. A region whose base plus length passes the end of the 64-bit address space is refused with `DR-RECON-EMU-0001`, and a refused region is not recorded. A 65th region is refused with `DR-RECON-EMU-0002`.

Bytes recovered inside the window are read as UTF-8, UTF-16LE, UTF-16BE, UTF-32LE, and UTF-32BE. A narrow run that holds only ASCII carries the `ascii` label. When two readings overlap, the longer run wins. A region that the text readings do not cover is also kept as raw bytes with no text. Bytes that do not decode keep their exact values, and no reading substitutes a replacement character.

Harvest properties:

- A string overwritten in place is still harvested, together with the value that replaced it.
- Runs never join across the end of the address space. A write near the top of memory and a write at address zero stay separate.
- Results are deduplicated by address and bytes together. The same value at two addresses is two results.
- Two harvests of the same write log return the same strings.
- A truncated write log still yields the strings it contains.
- A code unit that is not a Unicode scalar value ends the run. The scan continues past it, so a run behind an unpaired surrogate is still recovered.

The harvest stops on the caller's wall-clock deadline or when it has recorded the caller's byte budget, and `bound` names which of the two stopped it. It reads at most 4194304 log entries. A caller that takes the default limits gets a 750 millisecond deadline and a 262144-byte budget. The harvest itself reports at most 4096 strings, needs four characters to start a run, and stops a single run at 65536 bytes.

## Call-site argument slots

`argument_slot` maps an argument index to a register or a stack offset. `extract_arguments` reads the values from a `CallSiteState` that carries the captured registers and the captured stack image.

| Convention | Register arguments | First stack offset | Stack step |
|---|---|---|---|
| `sysv64` | `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` | 8 | 8 |
| `win64` | `rcx`, `rdx`, `r8`, `r9` | 0x28 | 8 |
| `aapcs64` | `x0` to `x7` | 0 | 8 |
| `cdecl32` | none | 4 | 4 |
| `stdcall32` | none | 4 | 4 |
| `fastcall32` | `ecx`, `edx` | 4 | 4 |
| `thiscall32` | `ecx` | 4 | 4 |

Stack words are read little endian. `callee_cleans_stack` reports true for `stdcall32`, `fastcall32`, and `thiscall32`, and false for `cdecl32`.

Extraction refuses rather than guesses:

- An argument index of 64 or higher is refused with `DR-RECON-EMU-0003`.
- A register the call site did not capture is refused with `DR-RECON-EMU-0004`. It is never read as zero.
- A stack offset past the captured stack image is refused with `DR-RECON-EMU-0005`. The error names the convention, the argument index, the offset, and the number of bytes captured.
