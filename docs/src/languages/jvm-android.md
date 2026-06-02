# JVM and Android

**disrobe** decompiles JVM classfiles and Android DEX through a unified command, wrapping the best FOSS decompilers headlessly while adding obfuscator reversal, ProGuard/R8 mapping replay, and chain auto-detection.

## Decompiling

```sh
disrobe jvm decompile App.class --out src/
disrobe jvm decompile app.jar --backend vineflower --out src/
disrobe jvm decompile app.apk --backend jadx --out src/
disrobe jvm decompile classes.dex --backend jadx --out src/
```

Routes a `.class`, `.jar`, `.dex`, or `.apk` through a JVM/Android backend: CFR, Vineflower, Procyon, JADX, and others. **disrobe** validates the classfile itself (format 1.0.2-25) and recovers records, sealed types, and pattern matching where the backend supports them, plus Kotlin and Scala idioms.

## Inventory and backends

```sh
disrobe jvm extract app.apk --out classes/    # extract a .jar / .apk + dump classfile inventory
disrobe jvm backends                          # report available JVM/Android backends on PATH
```

## Obfuscator reversal

**disrobe** reverses JVM obfuscators that the raw decompilers cannot - Zelix KlassMaster, Allatori, Stringer, DashO, and DexGuard control-flow obfuscation on the Android side - and replays ProGuard/R8 mapping files to restore original names.

## Chaining

```sh
disrobe auto app.apk --out recovered/    # APK -> dex -> JADX + Smali + manifest
```
