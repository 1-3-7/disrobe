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

`disrobe` uses [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license). It permits use, modification, and distribution subject to its conditions, including restrictions on services that expose a substantial set of the software's features, interference with license-key functionality, and removal of notices. Distributions must include the license, and modified copies must prominently state that they were modified. See the repository's [LICENSE](https://github.com/1-3-7/disrobe/blob/main/LICENSE) and [NOTICE](https://github.com/1-3-7/disrobe/blob/main/NOTICE) for the governing terms and attribution.
