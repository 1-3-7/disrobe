# Legal

The project's legal policy, jurisdiction-specific references, and takedown channel are in [LEGAL.md](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md). An authorization flag records the user's assertion of permission; it does not establish that a particular use satisfies the applicable law or contract.

## The authorization gate

Legally sensitive recovery paths that expose `--i-have-authorization` require the flag before they run. Passing the flag is your assertion that you are authorized to analyze the input under the statutory framing above. Use is your responsibility.

The same flag unlocks the `decryption-keys` category of the `--llm` sidecar; without it, requesting that category fails with `DR-CLI-0420`.

## What `disrobe` will not do

- It does not ship copyrighted third-party obfuscated bytecode in its public corpus. Fixtures are baked locally from known-good inputs.
- Grey-zone protectors ship recognizers first; escalation to a full peel only happens after a written legal-posture review committed to `docs/legal/<protector>-stance.md`.
- Local static analysis does not require a network service. `prowl` and optional tool installation make network requests; `serve` exposes the explicitly selected server transport. Consult each command's options before enabling it.

## Per-protector stances on file

- [Digital.ai / Arxan (JS)](https://github.com/1-3-7/disrobe/blob/main/docs/legal/digital-ai-arxan-stance.md)
- [PACE (JS)](https://github.com/1-3-7/disrobe/blob/main/docs/legal/pace-js-stance.md)
- [Jscrambler](https://github.com/1-3-7/disrobe/blob/main/docs/legal/jscrambler-stance.md)
- [PreEmptive JSDefender](https://github.com/1-3-7/disrobe/blob/main/docs/legal/jsdefender-stance.md)
- [PyArmor](https://github.com/1-3-7/disrobe/blob/main/docs/legal/pyarmor-stance.md)

## License

`disrobe` is proprietary, source-available software under the [Disrobe Source-Available License, Version 1.1](https://github.com/1-3-7/disrobe/blob/main/LICENSE), which supersedes the Elastic License 2.0 and Version 1.0 for every version as described in the [relicensing notice](https://github.com/1-3-7/disrobe/blob/main/RELICENSING-NOTICE.md). Free use is limited to individuals' own hobby projects, learning, and independent security research, nonprofit education and research, and bona fide journalism. Any use by or for a company or other for-profit organization requires a prior signed paid license; see [commercial licensing](https://github.com/1-3-7/disrobe/blob/main/COMMERCIAL.md). Redistribution, forks other than for contributing, rebranding, hosted or embedded offerings, and building competing products from exposure to Disrobe are prohibited. Every publication, report, filing, or deliverable that used Disrobe or its output must carry the credit "This work used Disrobe, created by 1-3-7: https://github.com/1-3-7/disrobe"; see the [attribution guide](https://github.com/1-3-7/disrobe/blob/main/ATTRIBUTION.md). The software is provided as is, and its author has no responsibility for how anyone uses it. Contributions require accepting the [contributor terms](https://github.com/1-3-7/disrobe/blob/main/CONTRIBUTING-LICENSE.md). The [LICENSE](https://github.com/1-3-7/disrobe/blob/main/LICENSE) and [NOTICE](https://github.com/1-3-7/disrobe/blob/main/NOTICE) govern; the [plain-language summary](https://github.com/1-3-7/disrobe/blob/main/LICENSE-SUMMARY.md) is not the license.
