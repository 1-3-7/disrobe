# Capability map

Find commands, supported inputs and integration guides below. Use `disrobe <command> --help` for the options available in your installed build.

Recovery support varies by format, version and backend. The language guides list supported variants and limitations; chain reports identify unsupported constructs in your input.

## Command groups

| Group | Root commands | Detailed guide |
|---|---|---|
| Automatic recovery and provenance | `auto`, `chain`, `context`, `status`, `report`, `diff`, `guard` | [chain](chain.md), [reading a result](reading-a-result.md), [reports](cli/report.md) |
| Static triage and reporting | `scan`, `ioc`, `indicators`, `frisk`, `strings`, `behavior`, `identify`, `detect`, `catalog`, `capabilities`, `taint`, `vulnmatch` | [catalog](catalog.md), [Frisk](frisk.md), [forensics safety](forensics-safety.md) |
| Containers and webview assets | `extract`, `webview` | [containers](languages/containers.md), [webview](languages/webview.md) |
| Python and packaging | `py`, `pyarmor`, `pyinstaller`, `pyfreeze` (experimental), `nuitka` | [Python](languages/python.md) |
| JavaScript and WebAssembly | `js`, `wasm` | [JavaScript](languages/javascript.md), [WebAssembly](languages/wasm.md) |
| Native analysis and recovery | `native`, `macho`, `go`, `swift`, `as3`, `semdiff` | [native](languages/native.md), [decompile](languages/native-decompile.md), [unpack](languages/native-unpack.md), [Go](languages/go.md), [Swift](languages/swift.md), [AS3](languages/as3.md) |
| JVM, .NET, and mobile | `jvm`, `apk`, `dotnet`, `hermes`, `flutter`, `mobile` | [JVM and Android](languages/jvm-android.md), [.NET](languages/dotnet.md), [mobile](languages/mobile.md) |
| Script and bytecode languages | `lua`, `php`, `shell`, `ruby`, `beam`, `pickle` | [Lua](languages/lua.md), [PHP](languages/php.md), [shell](languages/shell.md), [Ruby](languages/ruby.md), [BEAM](languages/beam.md), [pickle](languages/pickle.md) |
| Structured artifacts and query | `envelope`, `verify`, `query`, `yara`, `annot`, `rename` | [envelopes](envelope.md), [query](query.md) |
| Project tooling and service | `serve`, `plugin`, `init`, `config`, `passes`, `doctor`, `install`, `install-deps`, `self-update`, `completions`, `man`, `explain`, `bug-report` | [CLI overview](cli/overview.md), [service](cli/serve.md), [config](cli/config.md), [plugins](cli/plugin.md), [LLM sidecar](llm-sidecar.md) |
| Public collection | `prowl` | [forensics safety](forensics-safety.md) |

## Public integrations

| Integration | Entry point | Detailed guide |
|---|---|---|
| Rust library | core types and the pass registry | [Library APIs](library.md) |
| Python bindings | `import disrobe` | [Python bindings](python-bindings.md) |
| MCP over stdio | `disrobe-mcp` or `disrobe serve --mcp` | [MCP](integrations/mcp.md) |
| HTTP, gRPC, and LSP | `disrobe serve` | [service](cli/serve.md) |
| GitHub Action | `action.yml` | [GitHub Action](integrations/github-action.md) |
| Editor plugins | VS Code, IDA, Ghidra, Binary Ninja | [editor plugins](integrations/editor-plugins.md) |
| Browser playground | browser UI and compiled Wasm worker | [playground](playground.md) |
| pre-commit hook | hook ID `disrobe` | [pre-commit](integrations/pre-commit.md) |
| LLM sidecar | `disrobe init --ide` | [LLM sidecar](llm-sidecar.md) |

For nested commands, see the [CLI reference](cli/reference.md). For measurements and their limits, start with the [evidence index](https://github.com/1-3-7/disrobe/blob/main/evidence/README.md).

## Run the examples

Watch the [chaptered CLI walkthrough](assets/walkthrough/watch.html) and read its [command transcript](assets/walkthrough/transcript.txt). The recording shows native unpacking, indicator extraction, automatic recovery, Lua, WebAssembly, and recovered source.

The [feature capture](https://github.com/1-3-7/disrobe/blob/main/docs/demo/features.json) records twelve commands and their output. It extracts three known indicators with their byte offsets, round-trips two ZIP members, recovers all 73,160 original code bytes from a UPX-packed greeting, decodes an APK manifest, compares a recovered Lua greeting with its baseline, and verifies an envelope before and after a one-byte payload change.

From the repository root, reproduce it with a full CLI build, Python 3.14 and Lua 5.1:

```sh
node docs/demo/capture-features.mjs --binary /path/to/disrobe --python /path/to/python --lua /path/to/lua
```

The [Wasm quickstart](https://github.com/1-3-7/disrobe/blob/main/docs/demo/quickstart.json), [Python project example](https://github.com/1-3-7/disrobe/blob/main/docs/demo/sidecar.json), and [service examples](https://github.com/1-3-7/disrobe/blob/main/docs/demo/services.json) cover automatic recovery, project briefs and the MCP, HTTP, gRPC and LSP interfaces. Each record names its inputs and binary so results can be compared across builds.

The [public-collection example](https://github.com/1-3-7/disrobe/blob/main/docs/demo/public-collection.json) retrieves four archived `example.org` URLs from the [Common Crawl index](https://index.commoncrawl.org/). It queries one archive, caps output at ten URLs, and makes no requests to the archived pages.
