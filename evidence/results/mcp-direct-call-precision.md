# MCP direct-call edge precision on a committed stripped ELF

- id: `mcp-direct-call-precision`
- ecosystem: mcp
- claim: The MCP call_graph tool returns 5 direct-call edges for the committed stripped ELF, and all 5 match caller, callee, and classification evidence derived from its distinct committed unstripped toolchain twin.
- measured: 100.00%
- oracle strength: strong
- CI-attested: yes [CI]
- evidence basis: caller and callee addresses from the committed unstripped toolchain twin, compared with the MCP server's stdio response for the stripped subject
- reproduce: `cargo test -p disrobe-mcp --test mcp_protocol_roundtrip navigation_tools_round_trip_a_committed_stripped_elf_over_stdio`
- floor: 100.00 (holds)
- gate source: crates/disrobe-mcp/tests/mcp_protocol_roundtrip.rs, navigation_tools_round_trip_a_committed_stripped_elf_over_stdio; ground truth comes from the committed unstripped toolchain twin
- note: The equality assertion rejects extra edges and mismatched classifications. This claim covers one committed ELF pair and does not establish precision for other binaries, architectures, or toolchains.
