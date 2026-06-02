# Mobile (Hermes / Flutter)

`disrobe` detects the runtime inside a mobile package, extracts React Native bundles, lifts Hermes bytecode to a JavaScript surface, and dumps Flutter Dart AOT layouts.

## Runtime detection and extraction

```sh
disrobe mobile detect app.apk      # React Native, Hermes, Flutter, Cordova, Capacitor, NativeScript, Xamarin
disrobe mobile extract app.apk --out bundles/   # pull React Native JS/Hermes bundles out of an apk/ipa
disrobe mobile hermes-disasm index.android.bundle --out disasm/
disrobe mobile flutter-dump libapp.so --out layout.json
```

## Hermes

```sh
disrobe hermes lift index.android.bundle --out surface/    # lift back to a JavaScript surface
disrobe hermes disasm index.android.bundle --out disasm/    # per-function summary, no JS surface
disrobe hermes info index.android.bundle                    # version, function/string/identifier counts
```

`lift` handles Hermes bytecode versions v60-v96. It is validated in CI against a live 66 MiB Discord bundle (re-downloaded fresh each run): 122,633 functions, zero errors.

## Flutter

```sh
disrobe flutter dump libapp.so --out layout.json           # Dart snapshot symbol layout
disrobe flutter decompile libapp.so --out estimate.txt      # best-effort: header + class-table estimate + strings
disrobe flutter obfmap obfuscation_map.json --out map.json   # parse obfuscation_map into a typed lookup
```

The Dart AOT snapshot parser is validated on a real `rustdesk` `libapp.so`. Where the snapshot format walls off full decompilation, `disrobe` emits a best-effort estimate and reports the boundary.
