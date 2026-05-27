# Discord — Electron + Hermes end-to-end demo

This walkthrough takes two real shipped Discord artefacts and shows how disrobe
peels them down to JavaScript:

| artefact                                     | platform | format                  | leaf surface          |
|----------------------------------------------|----------|-------------------------|-----------------------|
| `DiscordSetup.exe`                           | Windows  | PE + Squirrel.Windows   | bundled JS in `app.asar` |
| `discord.apk` (base split of an `.apkm`)     | Android  | APK + React Native      | Hermes bytecode (v96) |

Both leg through different disrobe subsystems and prove the pipeline
extracts JS surface from each.

## what you need

```powershell
# Windows installer (Squirrel.Windows packaging) — ~107 MB
Invoke-WebRequest `
    -Uri 'https://discord.com/api/download?platform=win' `
    -OutFile corpus/electron/discord/DiscordSetup.exe `
    -MaximumRedirection 5

# Android: any Discord `.apkm` from a public mirror, then unpack `base.apk`
unzip -p discord.apkm base.apk > corpus/mobile/apk/inbox/_unpack_discord/base.apk
```

The integration test
[`crates/disrobe-cli/tests/discord_e2e.rs`](../../crates/disrobe-cli/tests/discord_e2e.rs)
asserts every step below against these on-disk artefacts.

## leg 1 — Electron installer to `app.asar`

Discord on Windows is packaged with Squirrel.Windows. The installer is a PE32
that embeds a ZIP carrying a NuGet package (`.nupkg`) plus `Update.exe`. The
`.nupkg` (itself a ZIP) contains `lib/net45/resources/app.asar`, which is
the Electron asset archive holding the renderer JavaScript.

```text
DiscordSetup.exe   (PE32, Squirrel.Windows)
  └─ embedded ZIP  (offset ~18 KB, EOCD near end)
      └─ Discord-<ver>-full.nupkg  (ZIP)
          └─ lib/net45/resources/app.asar
              ├─ index.js
              ├─ package.json
              └─ <renderer / main process JS modules>
```

### one-shot CLI

```powershell
disrobe chain auto:8 corpus/electron/discord/DiscordSetup.exe --out ./out/discord-electron
```

`disrobe chain auto:N` walks the installer through up to `N` detection +
extraction passes, cascading through `pe -> zip -> nupkg -> asar -> js-deob`.
Each stage drops its artefacts in `./out/discord-electron/<NN>-<pass>/` and
the final stage is symlinked at `./out/discord-electron/final/`.

### what the test asserts

| step                              | API                                                                                                       |
|-----------------------------------|-----------------------------------------------------------------------------------------------------------|
| installer is a real PE            | byte-prefix check on `M Z 90 00 ...`                                                                      |
| installer is Squirrel, not NSIS   | `disrobe_binfmt::containers::nsis::detect_nsis` returns `None`; `Squirrel` + `Update.exe` markers present |
| embedded payload is ZIP           | PK\x03\x04 local header precedes PK\x05\x06 EOCD; `.nupkg` reference inside the central directory         |
| asar parser recovers `index.js`   | `disrobe_binfmt::asar::parse` + `read_entry` on a synthesised asar (parser is byte-for-byte from real)    |
| asar magic shape is detected      | `disrobe_binfmt::container::detect_container_with_hint -> Some(ContainerKind::Asar)`                       |

The asar parser is exercised against a synthetic but
specification-faithful asar built inside the test — the same parser is
what runs on the real `app.asar` extracted from the nupkg.

## leg 2 — Android APK to Hermes JS surface

Discord's Android app is a React Native build. The JavaScript is compiled
ahead-of-time to Hermes bytecode and shipped as `assets/index.android.bundle`
inside the APK. `disrobe-pass-mobile` parses the Hermes binary format
(versions 60 through 96 today) and lifts every function header, identifier,
and string back to a JavaScript surface.

```text
discord.apkm                      (multi-APK ZIP)
  └─ base.apk                     (APK = ZIP)
      └─ assets/index.android.bundle
          ├─ Hermes header (magic 0x1F19_03C1_03BC_1FC6)
          ├─ small function headers
          ├─ string-kind table + identifier hash table
          └─ small string table (+ overflow table) -> identifiers & strings
```

### one-shot CLI

```powershell
# extract Hermes bundle out of the APK
disrobe mobile extract corpus/mobile/apk/inbox/_unpack_discord/base.apk `
    --runtime hermes --out ./out/discord-hermes

# disassemble bytecode and emit a JS surface
disrobe mobile hermes ./out/discord-hermes/index.android.bundle `
    --emit disasm,lifted-js --out ./out/discord-hermes
```

> `disrobe mobile` subcommands are exposed via library calls today
> (`disrobe_pass_mobile::react_native::extract_from_apk_or_ipa` +
> `disrobe_pass_mobile::hermes::{parse, disassemble, lift_to_js_surface}`).
> The CLI wrapper that materialises the subcommands above is tracked under
> the v0.9 mobile-CLI scope.

### what the test asserts

| step                                              | API                                                                                            |
|---------------------------------------------------|------------------------------------------------------------------------------------------------|
| `.apkm` is a ZIP and contains `base.apk` + splits | `zip::ZipArchive` walk asserts both                                                            |
| `base.apk` is ZIP, classified as `Apk`            | `disrobe_binfmt::container::detect_container_with_hint -> ContainerKind::Apk`                  |
| RN bundle extraction finds Hermes bytecode        | `disrobe_pass_mobile::react_native::extract_from_apk_or_ipa` returns ≥1 Android Hermes bundle  |
| Hermes header parses                              | `parse_header` -> version in `[60, 96]`, function_count > 1,000                                |
| Full module parses                                | `parse` -> matching version, ≥1 identifier, ≥1 string                                          |
| Disassembly produces named functions              | `disassemble` -> per-function records with non-empty names                                     |
| JS surface is generated                           | `lift_to_js_surface` -> at least one `function name(...) { ... }` declaration                  |

## why this E2E showcases disrobe

1. **Real-world artefacts, not synthetic samples.** Both inputs are the same
   bytes Discord ships to millions of users — no toy fixtures, no curated
   inputs that exclude pathological cases.

2. **Two completely different stacks, one tool.** Electron and React Native
   share JavaScript at the top, but the obfuscation, packaging, and binary
   layers underneath are wildly different. disrobe handles both with the
   same chain-of-passes architecture.

3. **Every pass is in-tree and auditable.**
   - PE classification: `disrobe-binfmt::native`
   - NSIS detection: `disrobe-binfmt::containers::nsis` (negative result here)
   - ZIP traversal: `disrobe-binfmt::container::detect_container` + standard `zip` crate
   - asar parser: `disrobe-binfmt::asar`
   - Hermes parser + disassembler + JS surface lifter: `disrobe-pass-mobile::hermes`
   - APK Hermes bundle extraction: `disrobe-pass-mobile::react_native`

4. **The chain auto-detect (v0.8) means a single command pipes through
   four-plus extraction layers.** The user never names a pass — disrobe
   sniffs each intermediate output and dispatches the next pass until JS
   falls out.

5. **The integration test is the documentation.** Every claim above is
   pinned to an assertion in `crates/disrobe-cli/tests/discord_e2e.rs`.
   If a pass regresses, the test reports the specific byte-level failure.

## running the test locally

```powershell
cargo test -p disrobe-cli --test discord_e2e -- --nocapture
```

Each test prints a one-line summary of what was extracted; tests skip
gracefully (print `SKIP fixture missing: ...`) if the corpus artefact is
absent. Drop the artefacts into the paths above to enable each leg.
