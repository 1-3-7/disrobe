# Go

**disrobe** recovers symbols from stripped and garbled Go binaries across PE, ELF, and Mach-O, parsing the Go runtime's own metadata tables.

```sh
disrobe go recover app --out symbols.json
disrobe go report app
```

`recover` reconstructs symbols from `pclntab` (versions 1.2 through 1.26), `moduledata`, and the embedded `embed.FS` filesystem, and produces a garble-obfuscation report. `report` prints the Go build version, the pclntab version, and a stripped/garble fingerprint without doing full recovery.

Type-name resolution is validated at 557/557 on Go 1.26.3. UPX-on-Go is auto-chained: `disrobe auto` unpacks the UPX layer first, then recovers the Go symbols underneath.
