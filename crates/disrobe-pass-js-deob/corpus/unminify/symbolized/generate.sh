#!/bin/sh
set -eu

TERSER_VERSION=5.50.0
ESBUILD_VERSION=0.25.12

mkdir -p terser esbuild

for module in widget loader collection; do
  npx --yes "terser@${TERSER_VERSION}" "src/${module}.js" \
    --module --mangle --compress \
    --source-map "includeSources=true,url='${module}.min.js.map'" \
    --output "terser/${module}.min.js"

  npx --yes "esbuild@${ESBUILD_VERSION}" "src/${module}.js" \
    --minify --format=esm --sourcemap --sources-content=true \
    "--outfile=esbuild/${module}.min.js"
done
