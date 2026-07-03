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
