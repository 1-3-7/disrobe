# Swift / Objective-C

`disrobe` class-dumps Mach-O binaries, reverses Swift rename-obfuscation maps, and decrypts SwiftConfidential blobs.

```sh
disrobe swift classdump App.app/App --out dump.txt           # single-slice ObjC/Swift class-dump
disrobe swift unshield map.txt --out renames.json            # reverse a SwiftShield map from a .dSYM text file
disrobe swift confidential blob.bin --out strings.txt        # recover strings from a Confidential XOR blob
disrobe macho classdump App.ipa --out dump.txt               # class-dump across every fat slice
disrobe macho dump App.app/App                               # header, segments, sections, encryption-info
disrobe macho slices universal.bin                           # walk a Fat-Mach-O, report each slice
```

For fat binaries and `.ipa` containers, prefer `disrobe macho classdump`, which walks every slice. FairPlay-encrypted regions are reported (detect-only) rather than decrypted.
