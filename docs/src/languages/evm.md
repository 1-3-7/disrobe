# EVM bytecode

`disrobe evm` reads Ethereum Virtual Machine bytecode from a file and recovers the contract interface, the control-flow graph and pseudo-Solidity. It needs no node, RPC endpoint, block explorer or compiler, and it never executes the code.

```sh
disrobe evm inspect Token.hex             # selectors, mutability, argument types, events, errors, proxy
disrobe --json evm inspect runtime.bin    # the same report as JSON
disrobe evm disasm Token.hex --blocks     # constructor, runtime and metadata sections, basic blocks
disrobe evm decompile Token.hex -o Token.sol
```

## Input

- The file holds hex text, with or without `0x` and with whitespace between digits allowed, or raw bytes. `--encoding hex` or `--encoding raw` forces one reading. Bytecode is accepted up to 1 MiB.
- Creation bytecode is split at its runtime image. disrobe follows the constructor to the `RETURN` of a memory region that a `CODECOPY` filled from the code itself, and reports the constructor length, the runtime offset and length, and the bytes after the runtime (constructor arguments). Constructors that decode their own arguments and copy the runtime to a computed address split the same way. `--layout runtime` or `--layout creation` forces one reading; a forced creation reading without a runtime image is an error.
- An EOF container (magic `0xef00`, EIP-3540) is refused by name.

## What it reports

- Disassembly of every legacy opcode through Osaka, including `PUSH0`, `TLOAD`, `TSTORE`, `MCOPY`, `BLOBHASH`, `BLOBBASEFEE` and `CLZ`. An unassigned byte prints as `UNDEFINED(0xNN)`; a `PUSH` cut short by the end of the code is marked. The report names the oldest fork whose opcode set covers the code.
- The compiler metadata trailer: for solc, the compiler version, IPFS CID (base58), `bzzr0` or `bzzr1` Swarm hash and the experimental flag from the end of the runtime; for Vyper, the compiler version from the end of the creation code.
- Basic blocks and edges. A `0x5b` byte inside `PUSH` data is not a jump destination. Jump targets resolve by constant propagation that carries return addresses through internal calls, so each internal function returns to its own caller. Each block lists its entry stack heights; unresolved jumps, jumps to non-`JUMPDEST` bytes and stack underflows are listed.
- Dispatched functions. A selector is recognised where the selector word (`SHR 224` or `DIV 2**224` of the first calldata word) is compared with `EQ`, `XOR`, `SUB` or `ISZERO` before a `JUMPI`. Linear dispatchers, `GT`/`LT` binary-search dispatchers, selectors with leading zero bytes and the all-zero selector are covered. Vyper's sparse and dense selector tables, which reduce the selector modulo a bucket count and read the bucket from a data section with `CODECOPY`, are followed through every bucket. The report states whether a fallback and a receive function exist.
- For each function: the entry offset and the state mutability. A function is `nonpayable` when a `CALLVALUE` check, alone or combined with a calldata size check, sends a non-zero value to a revert, `view` when no `SSTORE`, `TSTORE`, `LOG`, `CALL`, `CALLCODE`, `DELEGATECALL`, `CREATE`, `CREATE2` or `SELFDESTRUCT` is reachable, and `pure` when it also reads no storage, balance, block, transaction or caller value. A `STATICCALL` to a precompile (`0x01` to `0x11`) keeps a function `pure`.
- Argument count and types. The count comes from the calldata size check and the highest head word read. Each type comes from the code that validates or uses the word: an `AND` mask gives `address`, `uintN` or `bytesN`, `SIGNEXTEND` gives `intN`, a double `ISZERO` gives `bool`, signed arithmetic gives `int256`. In code that is not from solc (Vyper, or no solc prologue), a shift range check gives the same types: a word whose top bits must be zero after `SHR` is `address`, `bool` or `uintN`, and one whose low bits must be zero after `SHL` is `bytesN`. A word read as an offset is dynamic: its length multiplied by 32, or a bounded copy of 32 bytes per element, gives `T[]` with the element type read the same way, an unscaled length gives `bytes`, and an element read as an offset gives `bytes[]`. Each argument carries the basis of its type.
- Storage slots read and written, with mapping slots shown as `mapping_N[key]`, events with the topic0 signature where it is known, external calls with the callee selector, and reverts with the `Error(string)` text, the `Panic` code and its meaning, or the custom error selector.
- Known names from a built-in table of ERC-20, ERC-2612, ERC-721, ERC-1155, ERC-4626, ERC-165, ERC-1271, ERC-2981, ERC-3156, Ownable, AccessControl, Pausable and EIP-1967/ERC-1822 proxy functions, their events and the OpenZeppelin custom errors. The selectors are Keccak-256 hashes of the signatures; the inferred argument types are reported beside the table signature.
- Proxies: EIP-1167 minimal proxies and the EIP-7511 `PUSH0` variant with the implementation address, and fallbacks that `DELEGATECALL` an address loaded from the EIP-1967 implementation, beacon or admin slot, the ERC-1822 slot, another fixed slot or a constant.

`decompile` writes pseudo-Solidity for each function from its explored paths: `require` where one side of a branch reverts, `if`/`else` otherwise, and labels with `goto` where paths join or a loop repeats.

`disrobe evm decompile corpus/evm/solc/0.8.37-o1/Erc20.hex` prints, for `transferOwnership`:

```solidity
function transferOwnership(address arg0) external {
    require(msg.value == 0);
    require(!(slt(msg.data.length - 4, 32)));
    require(arg0 == address(arg0));
    require(msg.sender == address(storage[5]), error_8e4a23d6(msg.sender));
    require(address(arg0) != 0, "Ownable: new owner is the zero address");
    emit OwnershipTransferred(address(storage[5]), address(arg0));
    storage[5] = address(arg0) | bytes12(storage[5]);
    return;
}
```

## Evidence

The references are solc and Vyper. `corpus/evm/build.sh` compiles the contracts in `corpus/evm/src` with solc-js 0.8.37 and 0.8.19 (optimizer on and off, via-IR on and off) and with 0.6.12 and 0.4.26 (ABI coder v1). `corpus/evm/build_vyper.py` compiles `corpus/evm/vyper-src` with Vyper 0.4.3 in its gas and codesize modes, which emit the sparse and the dense selector table. `corpus/evm/MANIFEST.toml` records each build and the SHA-256 of every output. The contracts cover every value type width, `bytes`, `string`, dynamic arrays, payable, nonpayable, view and pure functions, events, custom errors, `require` strings, panics, AccessControl, ERC-20, ERC-721, ERC-1155 and ERC-4626 shapes, an EIP-1967 proxy with fallback and receive, a clone factory and selectors with one, two and three leading zero bytes.

`crates/disrobe-pass-evm/tests/solc_reference.rs` grades 69 compiled contracts (67 from solc, 2 from Vyper) holding 758 functions against the compilers' own output:

| Check | Result |
|---|---|
| Runtime split from creation bytecode, byte-exact against the compiler's deployed bytecode | 69 of 69 |
| Selectors against the compiler's method identifiers, with no extra selector | 758 of 758 |
| State mutability against the ABI | 758 of 758 |
| Argument types against the ABI | 876 of 947 exact, 71 in the class the code cannot separate, 0 wrong |
| Fallback and receive against the ABI | 69 of 69 |
| Metadata trailer: compiler version where the trailer holds one, hash kind, or no trailer when the build omits it | 69 of 69 |
| Events, custom errors and `require` strings against the ABI and the source | every one found, none extra |

The 71 class matches are `bytes32` arguments the code never constrains, reported as unconstrained `uint256`, and `string` arguments, reported as `bytes`. Getters of `constant` and `immutable` variables are graded as `pure`, the mutability their code has, from solc's own AST. Every jump in the compiled code resolves. Clearing the `JUMPDEST` of a function entry, or changing one `PUSH4` selector, turns the grader red. 400 randomly corrupted contracts and a set of adversarial shapes (50,000 `JUMPDEST`s, fork chains, 3,000-entry dispatchers, deep stacks) produce a report or a typed error, never a panic.

## Limits

- Fixed-size arrays and static structs in arguments are reported as their separate words, because the ABI encodes them identically.
- A word that the code never masks, sign-extends or uses in signed arithmetic is reported as `uint256`; the code does not distinguish it from `int256` or `bytes32`.
- A getter of a `constant` or `immutable` variable is reported `pure` although the ABI declares it `view`.
- Path exploration is bounded per function (steps, nodes, two forks per branch site and context, loop arrivals) and over the whole contract (40 million steps). A function that reaches a bound is marked incomplete, and its mutability and types come from the explored part.
- Selectors are found from comparisons. A dispatcher that jumps through a computed table other than a selector reduced modulo at most 256 buckets yields no selectors.
- Dispatched function names come only from the built-in table; other selectors keep their hex value.
