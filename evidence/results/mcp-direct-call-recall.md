# MCP direct-call edge recall on a committed stripped ELF

- id: `mcp-direct-call-recall`
- ecosystem: mcp
- claim: The MCP call_graph tool returns all 5 toolchain-derived direct-call edges for the committed stripped ELF.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: caller and callee addresses from the committed unstripped toolchain twin, compared with the MCP server's stdio response for the stripped subject
- reproduce: `cargo test -p disrobe-mcp --test mcp_protocol_roundtrip navigation_tools_round_trip_a_committed_stripped_elf_over_stdio`
- floor: 100.00 (holds)
- gate source: crates/disrobe-mcp/tests/mcp_protocol_roundtrip.rs, navigation_tools_round_trip_a_committed_stripped_elf_over_stdio; ground truth comes from the committed unstripped toolchain twin
- note: This claim covers one committed ELF pair and does not establish recall for other binaries, architectures, or toolchains.
