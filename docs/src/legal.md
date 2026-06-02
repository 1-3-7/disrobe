# Legal

Decompilation for security research, interoperability, and recovery of your own source is permitted in most jurisdictions — US DMCA §1201(f), EU Software Directive 2009/24/EC art. 6, UK CDPA §50B/50BA, and equivalents in CA / AU / JP. The full statutory posture, with citations and a takedown channel, is in [LEGAL.md](https://github.com/1-3-7/disrobe/blob/main/LEGAL.md).

## The authorization gate

Grey-zone commercial protectors (PyArmor paid tier, ionCube, SourceGuardian, Zend Guard, the commercial native-packer tier, and the grey-zone .NET/JVM obfuscators) are gated behind the explicit `--i-have-authorization` flag and never run otherwise. Passing the flag is your assertion that you are authorized to analyze the input under the statutory framing above. Use is your responsibility.

The same flag unlocks the `decryption-keys` category of the `--llm` sidecar; without it, requesting that category fails with `DR-CLI-0420`.

## What disrobe will not do

- It does not ship copyrighted third-party obfuscated bytecode in its public corpus. Fixtures are baked locally from known-good inputs.
- Grey-zone protectors ship recognizers first; escalation to a full peel only happens after a written legal-posture review committed to `docs/legal/<protector>-stance.md`.
- It does not phone home. The only documented network endpoint is `disrobe self-update --check-only`, and the binary is distributed source-and-release-only.

## License

disrobe is licensed under Apache-2.0. See [LICENSE-APACHE](https://github.com/1-3-7/disrobe/blob/main/LICENSE-APACHE) and [NOTICE](https://github.com/1-3-7/disrobe/blob/main/NOTICE).
