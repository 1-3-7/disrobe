# Enigma Virtual Box 10.70 fixture

`x86_evb_10_70_20240522.exe` and `README_packed.txt` come from the Apache-2.0-licensed [`mos9527/evbunpack`](https://github.com/mos9527/evbunpack) repository at commit [`ee7b647acf2a46617b0c448dfa83d63132ea917b`](https://github.com/mos9527/evbunpack/commit/ee7b647acf2a46617b0c448dfa83d63132ea917b).

The upstream test notes identify the executable as an x86 fixture packed with Enigma Virtual Box 10.70. The vendor's [version history](https://enigmaprotector.com/en/downloads/changelogenigmavb.html) identifies 10.70 Build 20240522, released on 22 May 2024. The upstream `PackerProject.evb` maps `README_packed.txt` into the bundle as `README.txt`, so the 17-byte source file is the independent expected member.

| File | Upstream Git blob | SHA-256 |
| --- | --- | --- |
| `x86_evb_10_70_20240522.exe` | `6fd037f17d35070eef6722476f89780c59468148` | `bf62463cfc6832f946a14e5dea1250977ec4187b16d3a394a8d9f0ae70c83064` |
| `README_packed.txt` | `7e687fc0d4d4c9790bd2ec1a8c4d67d6ec630ba2` | `d2da67f66755dd1d0c3667b251aa0282c708ae3ae100f2bf0ea7a615d37dc190` |

This fixture establishes only the x86, built-in, uncompressed virtual-file layout emitted by Enigma Virtual Box 10.70 Build 20240522 with literal `.enigma1` and `.enigma2` section names. The parser requires those names to avoid claiming unrelated PE files that contain an `EVB` marker; it does not detect bundles whose section names were changed or obfuscated. It recognizes the directory layout structurally and does not infer a product version from it. A derived test relocates the independently graded directory and member bytes into the fixture's existing `.rsrc` range to verify placement-independent parsing; it does not establish that the vendor emits this directory in resources. The fixture does not establish compressed members, external packages, registry virtualization, executable restoration, or other layouts.
