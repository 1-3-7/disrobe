# Legal

Decompilation for security research, interoperability, and recovery of your own source is permitted in most jurisdictions: US DMCA §1201(f), EU Software Directive 2009/24/EC art. 6, UK CDPA §50B/50BA, and equivalents in CA / AU / JP. The full statutory posture, with citations and a takedown channel, is in [LEGAL.md](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md).

## The authorization gate

Legally sensitive recovery paths that expose `--i-have-authorization` require the flag before they run. Passing the flag is your assertion that you are authorized to analyze the input under the statutory framing above. Use is your responsibility.

The same flag unlocks the `decryption-keys` category of the `--llm` sidecar; without it, requesting that category fails with `DR-CLI-0420`.

## What `disrobe` will not do

- It does not ship copyrighted third-party obfuscated bytecode in its public corpus. Fixtures are baked locally from known-good inputs.
- Grey-zone protectors ship recognizers first; escalation to a full peel only happens after a written legal-posture review committed to `docs/legal/<protector>-stance.md`.
- It does not phone home. The only documented network endpoint is `disrobe self-update --check-only`, and the binary is distributed source-and-release-only.

## Per-protector stances on file

- [Digital.ai / Arxan (JS)](https://github.com/1-3-7/disrobe/blob/main/docs/legal/digital-ai-arxan-stance.md)
- [PACE (JS)](https://github.com/1-3-7/disrobe/blob/main/docs/legal/pace-js-stance.md)
- [PyArmor](https://github.com/1-3-7/disrobe/blob/main/docs/legal/pyarmor-stance.md)

## License

`disrobe` is licensed under the [Elastic License 2.0](https://github.com/1-3-7/disrobe/blob/main/LICENSE). Companies and security researchers may use, copy, modify, and distribute it for free; attribution is required, so keep the author, copyright, and licensing notices intact. You may not provide `disrobe` to third parties as a hosted or managed service, and you may not remove or obscure any licensing, copyright, or other notices. The "disrobe" name and marks are reserved; the license grants no trademark rights. See [LICENSE](https://github.com/1-3-7/disrobe/blob/main/LICENSE) and [NOTICE](https://github.com/1-3-7/disrobe/blob/main/NOTICE).
