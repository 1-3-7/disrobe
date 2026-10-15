#!/bin/sh
# Rebuilds corpus/evm/solc from corpus/evm/src with solc-js. DISROBE_SOLCJS_ROOT holds
# solcjs-<version>/node_modules/solc for each version below (npm install --ignore-scripts solc@<version>).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=${DISROBE_SOLCJS_ROOT:?set DISROBE_SOLCJS_ROOT to the directory holding solcjs-<version>}
modern="--source AbiZoo.sol --source Erc20.sol --source Vault.sol --source Nft.sol --source Multi.sol --source Proxy.sol --source Errors.sol"
legacy="--source Legacy.sol"

build() {
    version=$1
    name=$2
    shift 2
    rm -rf "$here/solc/$name"
    # shellcheck disable=SC2068
    node "$here/build.cjs" --solc "$root/solcjs-$version/node_modules/solc" --out "$here/solc/$name" $@
}

build 0.8.37 0.8.37-o0 $modern
build 0.8.37 0.8.37-o1 --optimize $modern
build 0.8.37 0.8.37-ir-o0 --via-ir $modern
build 0.8.37 0.8.37-ir-o1 --via-ir --optimize $modern
build 0.8.19 0.8.19-o0 --bytecode-hash bzzr1 $modern
build 0.8.19 0.8.19-o1 --optimize --bytecode-hash none $modern
build 0.8.19 0.8.19-ir-o1 --via-ir --optimize --no-cbor $modern
build 0.6.12 0.6.12-o0 $legacy
build 0.6.12 0.6.12-o1 --optimize $legacy
build 0.4.26 0.4.26-o0 $legacy
build 0.4.26 0.4.26-o1 --optimize $legacy
